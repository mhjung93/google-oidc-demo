// Mode 3 지갑 에이전트 (:5100). 스펙: docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md §3
//
// Mode 2 의 wallet_agent.js 와 나란히 두는 별도 프로세스다. 그쪽 코드를 import 하지 않는다.
// 암호학은 전부 lib/mode3_wallet.js 에 있고 여기는 상태 파일 + HTTP 만이다.
// 로그인마다 발급된다(설계 2026-09-15 §5) — 성명은 세션(r_s) 단위이고 세션 안에서만 재사용한다.
// V4(2026-09-18): 자격증명은 max_height·allowAgent, 세션은 서비스 팩토리 주소를 들고 /wallet/tx 로 온체인 실행(설계 §6.3).
// V5(2026-09-21): 자격증명 이중 구조 — 사용자 자격증명(C_u, 사용자당 하나, 폐기 리프)과 세션 자격증명(C_s, 로그인마다).
//   사용자 자격증명은 첫 로그인 때 받고, 폐기되면 다음 로그인이 알아채(트리의 리프, 또는 게시 전이면
//   세션 발급의 no_user_cred 거절) 새로 받는다.
// V6(2026-09-22): 속성은 AA(cia.js DEMO_ACCOUNTS)가 관리한다 — 지갑은 등록·로그인 때 받아 캐싱만 한다. AA 가 속성을
//   바꾸면 π_u(사용자 자격증명)가 깨지므로(/cia/user_cred 의 bad proof), ensureUserCred 가 /cia/attrs 로 재동기화하고
//   한 번 재시도한다(/wallet/attrs/sync 로 수동 재동기화도 가능 — 옛 /wallet/attrs 는 없앴다).
// Snap(2026-09-22 metamask-snap §3.3): MODE3_WALLET_SECRETS=snap 이면 등록 비밀은 Snap 이 들고, 요청마다 첨부된 witness 로
//   요청 범위 SecretSource 를 만든다. 파일에는 공개 부분만 남고, 로그인한 세션의 증인은 메모리(sessions[r_s].witness)에만 둔다.
//   트랜잭션은 /wallet/tx/prepare(calldata) → MetaMask 가 전송 → /wallet/tx/record(영수증) 로 나눈다.
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { readJson, writeJsonAtomic } from './lib/mode3_state.js';
import { createSecretSource, stripSecrets, validateWitness } from './lib/mode3_secret_source.js';
import { createRegistration, createSessionKey, buildUserCredRequest, buildIssueRequest, buildCredentialProof, signChallenge, signSessionRequest, signAttrsRequest, normalizeDisclosure, disclosureKey, ProofCache, chooseMaxHeight } from './lib/mode3_wallet.js';
import { createRevocationSync } from './lib/mode3_rcl_sync.js';
import { signPayload, proofToCalldata, parseExecuteReceipt, decodeExecuteCalldata, factoryAt, walletAt, walletInterface, FACTORY_ABI } from './lib/mode3_onchain.js';
import { pointToStrings } from './lib/mode3_issuance.js';
import { normalizeAttrs, SCALAR_MAX, ppid, randomScalar } from './lib/mode3_credential.js';
import { verifyRpCert } from './lib/mode3_rp_cert.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.MODE3_WALLET_PORT) || 5100;
const STATE_FILE = process.env.MODE3_WALLET_STATE_FILE || path.join(__dirname, 'mode3_wallet_state.json');
// 폐기 트리 체크포인트(공개 데이터만). 지우면 다음 동기화가 창세기부터 재생한다(스펙 2026-09-23 §4).
const RCL_CACHE_FILE = process.env.MODE3_WALLET_RCL_CACHE || path.join(path.dirname(STATE_FILE), 'mode3_wallet_rcl.json');
const CIA_URL = process.env.MODE3_CIA_URL || 'http://127.0.0.1:4100';
const RP_ORIGIN = process.env.MODE3_RP_ORIGIN || 'http://127.0.0.1:3100';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
// 비밀 공급원(설계 2026-09-22 metamask-snap §3.3): file 은 지금처럼 상태 파일, snap 은 요청에 실린 witness(secretSourceFor).
const SECRETS = process.env.MODE3_WALLET_SECRETS || 'file';
if (!['file', 'snap'].includes(SECRETS)) throw new Error(`MODE3_WALLET_SECRETS 는 'file' 또는 'snap' 이어야 한다: ${SECRETS}`);
const SNAP_ID = process.env.MODE3_SNAP_ID || 'local:http://localhost:8082';
const WALLET_ORIGIN = process.env.MODE3_WALLET_PUBLIC_ORIGIN || `http://127.0.0.1:${PORT}`;
// 만료는 지갑이 정한다(설계 2026-09-18 §3.2 갱신): max_height = ceil((head + TTL) / GRID) × GRID. 빈 문자열은 기본값(cia.js 의 envBig 과 같은 관례).
const envBig = (k, d) => { const v = process.env[k]; return v === undefined || v === '' ? BigInt(d) : BigInt(v); };
const TTL_BLOCKS = envBig('MODE3_TTL_BLOCKS', 300);
const HEIGHT_GRID = envBig('MODE3_HEIGHT_GRID', 100);
if (TTL_BLOCKS <= 0n || HEIGHT_GRID <= 0n) throw new Error(`MODE3_TTL_BLOCKS(${TTL_BLOCKS})·MODE3_HEIGHT_GRID(${HEIGHT_GRID}) 는 양수여야 한다`);

// 게시 직후의 로그인이 옛 root 를 보지 않도록 ethers 의 250ms 캐시를 끈다(lib/mode3_wallet.js 주석).
const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 });

// ---- 상태 ----
// registration: { uid, s_u, r_u, cm_u:{x,y}, sk_u, attrs:[4개 10진],
//                 userCred: { C_u_pt:{x,y}, Cf_u, blind_u, leaf, issuedAt } | null }   §6.1. 등록은 한 번, userCred 는 사용자당 하나
// sessions:     r_s → { arid, PPID, pk_trace:{x,y}, factoryAddress|null, attrGateAddress|null, allowAgent("0"|"1"), C_s_pt:{x,y}, blind_s,
//                       credential:{Cf_u,Cf_s,max_height,chainid,allowAgent,sigma,pk_CIA}, sessionPrivKey, pk_i, issuedAt,
//                       witness?: { s_u, blind_u, attrs, sk_u } }   ← snap 모드 전용, 메모리에만(persist 가 뺀다)
// snap 모드의 registration 은 stripSecrets 결과({ uid, cm_u, attrs, userCred:{Cf_u,leaf,issuedAt} }) 다.
// version 6 (2026-09-21): 자격증명 이중 구조(userCred·blind_u / C_s·blind_s). 옛 파일은 등록만 살리고 세션은 비운다 —
// 옛 등록에는 userCred 가 없으므로 다음 로그인이 새로 받는다.
// version 7 (2026-09-22): 속성은 AA 기록 — registration.attrs 는 지갑이 고르는 값이 아니라 AA 가 준 값이다. 옛 C_u 는
// 사용자가 고른 속성 위에서 만들어졌으므로 물리고(userCred = null) 다음 로그인이 AA 속성으로 새로 받는다.
const WALLET_STATE_VERSION = 7;
let state = readJson(STATE_FILE, { version: WALLET_STATE_VERSION, registration: null, sessions: {} });
// 세션의 witness 는 메모리에만(스펙 §3.3) — 재시작하면 사라지고 /wallet/revalidate 가 needs_consent 로 다시 동의를 받는다.
function persist() { writeJsonAtomic(STATE_FILE, JSON.parse(JSON.stringify(state, (k, v) => (k === 'witness' ? undefined : v))), 0o600); }
if (state.version !== WALLET_STATE_VERSION) {
  console.warn(`[wallet] 상태 파일 버전 ${state.version} → ${WALLET_STATE_VERSION}: 세션·credential 을 비운다(옛 형식). 등록은 유지.`);
  state = { version: WALLET_STATE_VERSION, registration: state.registration ?? null, sessions: {} };
  if (state.registration) state.registration.userCred = null;
  persist();
}
state.sessions ??= {};
if (state.registration) state.registration.userCred ??= null;
/** 만료(head > max_height)된 세션을 걷어낸다(설계 §8). 동기화 뒤 head 를 알 때 부른다. */
function pruneSessions(head) {
  let changed = false;
  for (const [k, s] of Object.entries(state.sessions)) if (BigInt(s.credential.max_height) < head) { delete state.sessions[k]; changed = true; }
  if (changed) persist();
}

const cache = new ProofCache();   // (root, r_s) → {proof, publicSignals}. 메모리만
let lastSync = null;              // { root, head, tree } — tree 는 /wallet/status 가 userCred.revoked 를 다시 동기화하지 않고 판정하는 데 쓴다

// 증분 동기화 객체. LOG_ADDRESS 가 없으면 null — 그 경우 세 라우트는 지금처럼 chain_unavailable 을 낸다.
const rcl = LOG_ADDRESS ? createRevocationSync({ provider, logAddress: LOG_ADDRESS, cacheFile: RCL_CACHE_FILE, log: (m) => console.warn(`[wallet] ${m}`) }) : null;
async function syncTree() {
  if (!rcl) throw new Error('CIA_LOG_ADDRESS not configured');
  return rcl.sync();
}

// pk_CIA — cert_s 검증용. env 가 있으면 그것, 없으면 CIA 에서 한 번 받아 고정(TOFU, RP 와 같은 규칙).
let pkCiaP = null;
function pkCia() {
  return (pkCiaP ??= (async () => {
    const { MODE3_PK_CIA_X: x, MODE3_PK_CIA_Y: y } = process.env;
    if (x && y) return { x: BigInt(x), y: BigInt(y) };
    const r = await fetch(`${CIA_URL}/cia/public_keys`);
    if (!r.ok) throw new Error(`CIA 에서 pk_CIA 를 받지 못했다 (${r.status})`);
    const k = await r.json();
    return { x: BigInt(k.pk_CIA.x), y: BigInt(k.pk_CIA.y) };
  })().catch((e) => { pkCiaP = null; throw e; }));
}

const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const isAddr = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
const json = async (r) => ({ status: r.status, body: await r.json().catch(() => null) });
const ciaPost = (p, body) => fetch(`${CIA_URL}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(json);

let chainIdCache = null;
async function chainId() {
  if (chainIdCache === null) chainIdCache = (await provider.getNetwork()).chainId;   // bigint
  return chainIdCache;
}

/** 사용자 자격증명을 바꿔 앉힌다(null 이면 버린다). 옛 자격증명의 세션은 다음 게시에 죽으므로 지금 지우고 증명 캐시도 비운다. */
function replaceUserCred(src, userCred) {
  src.setUserCred(userCred);
  state.sessions = {}; cache.clear();
  persist();
}

/** /cia/attrs 로 속성을 다시 받는다(2026-09-22 §3.3). 바뀌었으면 옛 C_u·세션을 버린다(재발급은 다음 로그인에서). */
async function syncAttrsFromCia(src) {
  const reg = src.registration();
  const nonce = randomScalar();
  const r = await ciaPost('/cia/attrs', { uid: reg.uid, nonce: nonce.toString(), sig_u: await signAttrsRequest(reg.sk_u, BigInt(reg.uid), nonce) });
  if (r.status !== 200) return { changed: false, status: r.status, body: r.body };
  const attrs = normalizeAttrs(r.body.attrs).map(String);
  const changed = JSON.stringify(attrs) !== JSON.stringify(reg.attrs);
  if (changed) { src.setAttrs(attrs); replaceUserCred(src, null); } else persist();
  return { changed, status: 200, attrs };
}

/** 사용자 자격증명 확보(설계 2026-09-21 §6.2 3단계). 없거나 폐기됐으면 새로 받는다. 돌려주는 값은 { status, body, fresh }. */
async function ensureUserCred(tree, src, { resynced = false } = {}) {
  const reg = src.registration();
  const uc = src.userCred();
  if (uc && !tree.has(BigInt(uc.leaf))) return { status: 200, fresh: false };
  const req = await buildUserCredRequest({ uid: BigInt(reg.uid), s_u: BigInt(reg.s_u), r_u: BigInt(reg.r_u), sk_u: reg.sk_u, attrs: (reg.attrs ?? []).map(BigInt) });
  const r = await ciaPost('/cia/user_cred', req.body);
  if (r.status === 201 || r.status === 200) {
    replaceUserCred(src, { C_u_pt: { x: req.C_u_pt.x.toString(), y: req.C_u_pt.y.toString() }, Cf_u: req.Cf_u.toString(), blind_u: req.secrets.blind_u.toString(), leaf: req.leaf.toString(), issuedAt: new Date().toISOString() });
    return { status: 200, body: r.body, fresh: true };
  }
  // AA 기록이 바뀌어 π_u 가 깨진 경우(2026-09-22 §3.3): 속성을 다시 받아 한 번만 재시도한다
  if (r.status === 400 && !resynced && r.body?.error === 'bad user credential proof') {
    const s = await syncAttrsFromCia(src);
    if (s.status === 200) return ensureUserCred(tree, src, { resynced: true });
  }
  return { status: r.status, body: r.body, fresh: false };
}

async function issueSession(arid, r_s, pk_trace, allowAgent, factoryAddress, attrGateAddress, head, src) {
  const reg = src.registration();
  const uc = src.userCred();
  const session = createSessionKey();
  const chainid = await chainId();
  const req = await buildIssueRequest({
    uid: BigInt(reg.uid), Cf_u: BigInt(uc.Cf_u), arid: BigInt(arid), sk_u: reg.sk_u, session, chainid, allowAgent: BigInt(allowAgent),
    max_height: chooseMaxHeight(head, { ttlBlocks: TTL_BLOCKS, grid: HEIGHT_GRID }),
  });
  const r = await ciaPost('/cia/issue', req.body);
  if (r.status === 200) {
    const PPID = await ppid({ uid: BigInt(reg.uid), arid: BigInt(arid), s_u: BigInt(reg.s_u), chainid });
    state.sessions[r_s.toString()] = {
      arid, PPID: PPID.toString(), pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }, factoryAddress, attrGateAddress, allowAgent,
      C_s_pt: { x: req.C_s_pt.x.toString(), y: req.C_s_pt.y.toString() }, blind_s: req.secrets.blind_s.toString(),
      credential: r.body, sessionPrivKey: session.wallet.privateKey, pk_i: session.pk_i.toString(), issuedAt: new Date().toISOString(),
    };
    persist();
  }
  return r;
}

/** 요청 범위 비밀 공급원. file 은 상태 파일. snap 은 증인이 어디서 오는지가 경로마다 다르다.
 *  - 세션 경로(rsKey 있음 — 재검증·tx/prepare): **세션의 메모리 증인만** 쓴다. 본문 witness 는 보지 않는다 —
 *    /wallet/revalidate 는 RP 오리진에 CORS 로 열려 있어 서비스 페이지가 엉뚱한 증인을 실어 보내면 proveSession 이
 *    revoked 로 던져 세션이 지워진다(리뷰 Ruling 4). 없으면 needs_consent(409) — 팝업이 동의를 다시 받아 채운다.
 *  - 그 밖(rsKey 없음 — 로그인·재승인·속성 동기화): 본문 witness. 호출자가 validateWitness 를 먼저 거친다. 없으면 witness_required(400). */
function secretSourceFor(req, rsKey = null) {
  if (SECRETS === 'file') return createSecretSource({ mode: 'file', state });
  let w = null;
  if (rsKey) {
    // 세션 증인은 { s_u, blind_u, attrs, sk_u } 만 든다 — 공개 부분(uid, userCred 의 Cf_u·leaf)은 파일에서 채운다. r_u 는 발급 뒤엔 필요 없다.
    const sw = state.sessions[rsKey]?.witness;
    const pub = state.registration?.userCred;
    // pub 이 없으면(상태 파일 버전을 올려 userCred 를 비운 경우 등) 증인을 재조립할 수 없다. 그대로 두면 userCred:null 로
    // 조립돼 proveSession 이 revoked 로 던지고 **세션이 지워진다** — 복구할 수 없는 손실이다. 대신 needs_consent 로 떨어뜨려
    // 팝업이 Snap 의 C_u 로 /wallet/session/witness 를 다시 채우게 한다(그 라우트가 파일의 공개 부분도 되살린다).
    if (sw && pub) w = { uid: state.registration?.uid, s_u: sw.s_u, r_u: null, sk_u: sw.sk_u, attrs: sw.attrs, userCred: { ...pub, blind_u: sw.blind_u } };
  } else w = req.body?.witness ?? null;
  if (!w) throw Object.assign(new Error(rsKey ? 'needs_consent' : 'witness_required'), { reason: rsKey ? 'needs_consent' : 'witness_required' });
  return createSecretSource({ mode: 'snap', state, witness: w });
}

/** 서비스 인증(설계 §3·§4)·팩토리 검증 — /wallet/login 과 /wallet/authorize/precheck 가 같이 쓴다. 통과면 null, 아니면 { status, body }.
 *  cert_s 가 pk_CIA 서명이어야 하고(오리진은 호출자가 대조한다), 팩토리는 인증서의 arid·pk_trace, 고정된 pk_CIA·로그 주소와 온체인 값이
 *  같아야 한다 — 임의 코드일 수 있으므로 검증 규칙이 같은 계정만 받아들인다(2026-09-18 점검 3). */
async function checkService({ arid, origin, cert_s, pk_trace, factoryAddress }) {
  // CIA 가 죽어 pk_CIA 를 못 받은 것이지 체인 문제가 아니다 — reason 목록엔 없지만 원인을 구분해 둔다.
  let pk;
  try { pk = await pkCia(); } catch (e) { return { status: 503, body: { reason: 'cia_unavailable', detail: e.message } }; }
  if (!(await verifyRpCert(pk, { arid: BigInt(arid), origin, pk_trace, cert: cert_s }))) return { status: 403, body: { reason: 'bad_rp_cert' } };
  if (factoryAddress !== null) {
    try {
      const f = factoryAt(factoryAddress, provider);
      const [fa, fl, fx, fy, tx, ty] = await Promise.all([f.arid(), f.log(), f.pkCIAX(), f.pkCIAY(), f.pkTraceX(), f.pkTraceY()]);
      if (fa !== BigInt(arid) || fl.toLowerCase() !== LOG_ADDRESS.toLowerCase() || fx !== pk.x || fy !== pk.y || tx !== BigInt(pk_trace.x) || ty !== BigInt(pk_trace.y)) {
        return { status: 409, body: { reason: 'bad_factory' } };
      }
    } catch (e) { return { status: 409, body: { reason: 'bad_factory', detail: e.shortMessage ?? e.message } }; }
  }
  return null;
}

// ---- 앱 ----
const app = express();
app.use(express.json({ limit: '1mb' }));

// RP 페이지(다른 오리진)가 부르는 것은 /wallet/revalidate·/wallet/request·/wallet/config, 그리고 file 모드의 /wallet/login 뿐이다.
// snap 모드의 /wallet/login 은 같은 오리진(지갑 페이지 팝업)만 부른다 — CORS 를 열지 않는다(스펙 §3.3). 문자열 origin 은
// cors 가 요청 Origin 과 무관하게 헤더를 붙이므로, 일치할 때만 붙이도록 함수형으로 둔다.
const loginCors = cors({ origin: (origin, cb) => cb(null, origin === RP_ORIGIN), methods: ['POST'] });
const loginMiddleware = SECRETS === 'file' ? [loginCors] : [];
if (SECRETS === 'file') app.options('/wallet/login', loginCors);
app.options('/wallet/revalidate', loginCors);
app.options('/wallet/request', loginCors);
// /wallet/config 는 GET 전용 — Snap 연동(설계 2026-09-22 metamask-snap) 전 RP 페이지가 비밀 모드·rpcUrl 등을 미리 읽는다.
const configCors = cors({ origin: (origin, cb) => cb(null, origin === RP_ORIGIN), methods: ['GET'] });

// 같은 파일이 지갑 화면과 /authorize 팝업(?authorize=1)을 겸한다 — 팝업은 쿼리로 모드만 바꾼다(metamask-snap §3.2).
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'wallet.html')));

// 비밀 없음 — RP 페이지가 로그인 전에 지갑의 비밀 모드·체인 정보를 미리 읽는다(설계 2026-09-22 metamask-snap Ruling 1).
// CIA 주소는 싣지 않는다 — 이 응답은 RP 오리진에도 나가고(configCors), 자기 폐기는 아래 프록시가 대신 낸다(Ruling 7).
app.get('/wallet/config', configCors, async (req, res) => {
  try { res.json({ secrets: SECRETS, snapId: SNAP_ID, walletOrigin: WALLET_ORIGIN, rpcUrl: RPC_URL, chainId: (await chainId()).toString() }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/wallet/status', async (req, res) => {
  let head = null;
  try { head = (await provider.getBlockNumber()).toString(); } catch { /* 체인 없음 */ }
  const sessions = {};
  for (const [r_s, e] of Object.entries(state.sessions)) {
    sessions[r_s] = { arid: e.arid, PPID: e.PPID, max_height: e.credential.max_height, chainid: e.credential.chainid, allowAgent: e.allowAgent, factoryAddress: e.factoryAddress, attrGateAddress: e.attrGateAddress ?? null, sessionAddress: new ethers.Wallet(e.sessionPrivKey).address, issuedAt: e.issuedAt, pk_trace: e.pk_trace };
  }
  // userCred.revoked 는 마지막 동기화의 트리로 판정한다(여기서 다시 동기화하지 않는다). 아직 동기화가 없으면 null.
  // 여기 쓰는 값(uid·attrs·userCred 의 Cf_u·leaf·issuedAt)은 두 모드 모두 파일의 공개 부분이다 — 비밀 공급원이 필요 없다.
  const reg = state.registration;
  const uc = reg?.userCred ?? null;
  const userCred = uc ? { Cf_u: uc.Cf_u, issuedAt: uc.issuedAt, revoked: lastSync?.tree ? lastSync.tree.has(BigInt(uc.leaf)) : null } : null;
  const st = rcl ? rcl.stats() : null;
  res.json({
    registered: Boolean(reg), uid: reg?.uid ?? null, attrs: reg?.attrs ?? null, userCred, sessions,
    head, lastRoot: lastSync?.root ?? null, logAddress: LOG_ADDRESS,
    rcl: st ? { leaves: st.leaves, lastSyncedBlock: st.lastSyncedBlock === null ? null : st.lastSyncedBlock.toString(), lastMode: st.lastMode, cacheFile: st.cacheFile } : null,
  });
});

// 2026-09-22 §3.3 — 속성은 AA(cia.js DEMO_ACCOUNTS)가 관리한다. 본문의 attrs 는 받지 않는다(있어도 무시).
// snap 모드(metamask-snap §4.1): s_u·r_u 는 Snap 이 만들고 페이지가 cm_u 만 준다. 응답의 sk_u·attrs 를 페이지가 Snap 에 저장하고,
// 파일에는 stripSecrets 결과(uid·cm_u·attrs)만 남는다. file 모드 응답에는 sk_u 가 없다(파일에 있다).
app.post('/wallet/register', async (req, res) => {
  try {
    const { uid, pwd, cm_u: cmIn } = req.body ?? {};
    if (!isDec(uid) || typeof pwd !== 'string') return res.status(400).json({ error: 'uid(10진 문자열), pwd 필요' });
    if (SECRETS === 'snap' && !(cmIn && isDec(cmIn.x) && isDec(cmIn.y))) return res.status(400).json({ error: 'snap 모드는 cm_u{x,y}(10진 문자열) 필요' });
    if (state.registration) return res.status(409).json({ reason: 'already_registered', uid: state.registration.uid });
    const reg = SECRETS === 'snap' ? null : await createRegistration();
    const cm_u = SECRETS === 'snap' ? { x: cmIn.x, y: cmIn.y } : pointToStrings(reg.cm_u);
    const r = await ciaPost('/cia/register', { uid, pwd, cm_u });
    if (r.status !== 201) {
      const status = r.status === 401 || r.status === 409 ? r.status : 502;
      return res.status(status).json({ reason: 'register_failed', cia: r.body });
    }
    const attrs = normalizeAttrs(r.body.attrs).map(String);
    if (SECRETS === 'snap') {
      state.registration = stripSecrets({ uid, cm_u, attrs, userCred: null });
      persist();
      return res.status(201).json({ uid, sk_u: r.body.sk_u, attrs });
    }
    state.registration = { uid, s_u: reg.s_u.toString(), r_u: reg.r_u.toString(), cm_u, sk_u: r.body.sk_u, attrs, userCred: null };
    persist();
    res.status(201).json({ uid, attrs });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 팝업이 Snap 동의 창을 열기 전에 인증서·팩토리를 검사한다(metamask-snap §3.3) — /wallet/login 의 같은 검사를 떼어 낸 것.
// 오리진 대조는 여기서 하지 않는다: 팝업이 postMessage 의 event.origin 으로 확인한 값을 /wallet/login 의 verifiedOrigin 으로 낸다.
app.post('/wallet/authorize/precheck', async (req, res) => {
  try {
    const { arid, origin, cert_s, pk_trace, factoryAddress = null } = req.body ?? {};
    if (!isDec(arid) || typeof origin !== 'string' || !cert_s || !pk_trace || !isDec(pk_trace.x) || !isDec(pk_trace.y)) return res.status(400).json({ error: 'arid, origin, cert_s, pk_trace{x,y} 필요' });
    if (factoryAddress !== null && !isAddr(factoryAddress)) return res.status(400).json({ error: 'factoryAddress 는 주소' });
    if (!LOG_ADDRESS) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
    const bad = await checkService({ arid, origin, cert_s, pk_trace, factoryAddress });
    if (bad) return res.status(bad.status).json(bad.body);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// snap 모드(metamask-snap §3.3): 본문 witness 필수(400 witness_required / bad_witness). 오리진은 Origin 헤더 대신 본문 verifiedOrigin
// (팝업이 postMessage 의 event.origin 으로 확인한 값)을 인증서 오리진과 대조한다. 성공하면 세션에 증인을 메모리로 남기고,
// 새 C_u·속성 변경은 응답의 userCredIssued·attrsChanged 로 페이지가 Snap 에 저장한다.
app.post('/wallet/login', ...loginMiddleware, async (req, res) => {
  try {
    const { arid, origin, cert_s, pk_trace, r_s, allowAgent = '0', factoryAddress = null, attrGateAddress = null, witness = null, verifiedOrigin = null } = req.body ?? {};
    if (!isDec(arid) || typeof origin !== 'string' || !cert_s || !pk_trace || !isDec(pk_trace.x) || !isDec(pk_trace.y) || !isDec(r_s)) return res.status(400).json({ error: 'arid, origin, cert_s, pk_trace{x,y}, r_s 필요' });
    if (allowAgent !== '0' && allowAgent !== '1') return res.status(400).json({ error: 'allowAgent 는 "0" 또는 "1"' });
    if (factoryAddress !== null && !isAddr(factoryAddress)) return res.status(400).json({ error: 'factoryAddress 는 주소' });
    // attrGateAddress 는 서비스가 알려주는 값을 세션에 실어 나를 뿐 지갑이 검증하지 않는다(스펙 §6.1) — 지갑 폼 기본값(to)으로만 쓰인다.
    if (attrGateAddress !== null && !isAddr(attrGateAddress)) return res.status(400).json({ error: 'attrGateAddress 는 주소' });
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    if (!LOG_ADDRESS) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
    const rs = BigInt(r_s);
    if (rs >= SCALAR_MAX) return res.status(400).json({ error: 'r_s 는 2^250 미만' });
    // r_s 는 세션 식별자다 — 같은 값으로 두 번 로그인할 정당한 경로가 없고, 덮어쓰면 캐시의 옛 π 와 새 세션키가 어긋난다.
    if (state.sessions[rs.toString()]) return res.status(409).json({ reason: 'duplicate_session' });
    if (SECRETS === 'snap') {
      if (!witness) return res.status(400).json({ reason: 'witness_required' });
      try { await validateWitness(witness, state.registration.uid, state.registration.cm_u); }
      catch (e) { if (e.reason === 'bad_witness') return res.status(400).json({ reason: 'bad_witness', detail: e.message }); throw e; }
    } else if (witness) console.warn('[wallet] file 모드에 witness 가 왔다 — 무시한다');

    // 서비스 인증(설계 §3·§4): cert_s 가 pk_CIA 서명이고, 요청을 보낸 오리진이 cert 의 오리진과 같아야 한다.
    // 피싱 페이지는 진짜 서비스의 (arid, cert_s) 를 그대로 보여줄 수는 있어도 그 오리진에서 요청을 보낼 수는 없다.
    // file 모드는 RP 페이지가 CORS 로 직접 부르므로 Origin 헤더, snap 모드는 같은 오리진의 팝업이 부르므로 팝업이 postMessage 의
    // event.origin 으로 확인한 verifiedOrigin 을 대조한다(같은 방어 — 피싱 페이지는 인증서의 오리진에서 메시지를 보낼 수 없다).
    // pk_trace 는 인증서가 덮는다 — 서비스가 자기만 아는 키를 주면 서비스 혼자 태그를 연다(2026-09-16 §2).
    const seenOrigin = SECRETS === 'snap' ? verifiedOrigin : req.get('Origin');
    if (seenOrigin !== origin) return res.status(403).json({ reason: 'bad_rp_cert' });
    const bad = await checkService({ arid, origin, cert_s, pk_trace, factoryAddress });
    if (bad) return res.status(bad.status).json(bad.body);

    const src = secretSourceFor(req);
    const timings = { syncMs: 0, userCredMs: 0, issueMs: 0, proveMs: 0 };
    let t = Date.now();
    let synced;
    try { synced = await syncTree(); }
    catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    timings.syncMs = Date.now() - t;
    lastSync = { root: synced.root.toString(), head: synced.head.toString(), tree: synced.tree };

    pruneSessions(synced.head);
    // 사용자 자격증명은 사용자당 하나 — 없거나 폐기됐을 때만 새로 받는다(userCredMs 는 재사용이면 0)
    t = Date.now();
    let uc = await ensureUserCred(synced.tree, src);
    timings.userCredMs = uc.fresh ? Date.now() - t : 0;
    if (uc.status === 403) return res.status(403).json({ reason: 'account_disabled', timings });
    if (uc.status !== 200) return res.status(502).json({ reason: 'user_cred_failed', cia: uc.body, timings });
    // 세션 자격증명은 로그인마다(설계 §5), 만료는 방금 읽은 head 기준
    const issue = () => issueSession(arid, rs, { x: BigInt(pk_trace.x), y: BigInt(pk_trace.y) }, allowAgent, factoryAddress ? ethers.getAddress(factoryAddress) : null, attrGateAddress ? ethers.getAddress(attrGateAddress) : null, synced.head, src);
    t = Date.now();
    let r = await issue();
    timings.issueMs = Date.now() - t;
    // no_user_cred: 지갑이 든 C_u 가 CIA 에서는 이미 물렸는데 리프가 아직 게시되지 않았다(/cia/revoke scope=credential 직후, 또는
    // 동시 로그인 경합으로 지갑이 활성이 아닌 Cf_u 를 들고 남은 경우). 트리에는 없어 ensureUserCred 가 알아채지 못하므로 여기서
    // 그 자격증명을 버리고 새로 받아 한 번만 다시 시도한다 — 게시·하트비트를 기다리지 않는다. s_u 는 같으니 PPID 는 그대로다.
    if (r.status === 403 && r.body?.reason === 'no_user_cred') {
      replaceUserCred(src, null);
      t = Date.now();
      uc = await ensureUserCred(synced.tree, src);
      timings.userCredMs += Date.now() - t;
      if (uc.status === 403) return res.status(403).json({ reason: 'account_disabled', timings });
      if (uc.status !== 200) return res.status(502).json({ reason: 'user_cred_failed', cia: uc.body, timings });
      t = Date.now();
      r = await issue();
      timings.issueMs += Date.now() - t;
    }
    // 재시도까지 no_user_cred 면 CIA 쪽에서 방금 받은 C_u 도 물린 것이다(연속 폐기·경합) — 다음 로그인이 다시 시도한다
    if (r.status === 403) return res.status(403).json({ reason: r.body?.reason === 'no_user_cred' ? 'user_cred_retired' : 'account_disabled', timings });
    if (r.status !== 200) return res.status(502).json({ reason: 'issue_failed', cia: r.body, timings });
    let out;
    try { out = await proveSession(rs.toString(), synced, timings, null, src); }
    catch (e) {
      if (e.reason === 'no_session') return res.status(409).json({ reason: 'no_session', timings });
      throw e;
    }
    if (SECRETS === 'snap') setSessionWitness(rs.toString(), src);
    // src.pending: snap 모드에서 이 로그인이 새로 받은 C_u(userCredIssued)·바뀐 속성(attrsChanged) — 페이지가 Snap 에 저장한다. file 모드는 {}.
    res.json({ ...out, issued: true, allowAgent, timings, ...src.pending });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/** snap 모드: 로그인·재승인한 세션의 증인을 메모리에만 둔다(스펙 §3.3, persist 가 뺀다). blind_u 는 지금 C_u 의 것(로그인 중 새로 받았으면 그것). */
function setSessionWitness(rsKey, src) {
  const s = state.sessions[rsKey];
  if (!s) return;
  const reg = src.registration(), uc = src.userCred();
  s.witness = { s_u: reg.s_u, blind_u: uc?.blind_u ?? null, attrs: reg.attrs, sk_u: reg.sk_u };
}

// 재시작 등으로 세션 증인이 없을 때(revalidate·tx/prepare 의 needs_consent) 팝업이 consentLogin 을 다시 받아 채운다(metamask-snap §4.3).
app.post('/wallet/session/witness', async (req, res) => {
  try {
    if (SECRETS !== 'snap') return res.status(409).json({ reason: 'not_snap_mode' });
    const { r_s, witness } = req.body ?? {};
    if (!isDec(r_s) || !witness) return res.status(400).json({ error: 'r_s, witness 필요' });
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    try { await validateWitness(witness, state.registration.uid, state.registration.cm_u); }
    catch (e) { if (e.reason === 'bad_witness') return res.status(400).json({ reason: 'bad_witness', detail: e.message }); throw e; }
    const rsKey = BigInt(r_s).toString();
    const s = state.sessions[rsKey];
    if (!s) return res.status(404).json({ reason: 'no_session' });
    // 세션은 특정 C_u 위에 발급됐다 — Snap 이 든 C_u 가 그것이 아니면(다른 기기, 지워진 상태) 이 증인으로는 증명이 안 된다
    if (!witness.userCred || witness.userCred.Cf_u !== s.credential.Cf_u) return res.status(409).json({ reason: 'user_cred_mismatch' });
    // 파일의 공개 userCred 가 비어 있으면(상태 파일 버전 올림 등) secretSourceFor 가 증인을 재조립하지 못해 계속
    // needs_consent 가 난다. 방금 세션의 Cf_u 와 일치를 확인한 C_u 의 **공개 부분만** 되살린다(비밀은 파일에 쓰지 않는다).
    if (!state.registration.userCred) {
      const u = witness.userCred;
      state.registration.userCred = { Cf_u: u.Cf_u, leaf: u.leaf, issuedAt: u.issuedAt ?? new Date().toISOString() };
      persist();
    }
    setSessionWitness(rsKey, createSecretSource({ mode: 'snap', state, witness }));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/** 세션의 성명으로 현재 root 에 대한 π 를 만든다(캐시, disclosure 별). 사용자 자격증명 리프가 트리에 있으면 throw('revoked') — 그 사용자의
 *  모든 세션이 같이 죽는다. 세션이 없으면 throw('no_session') — 호출자가 404/409 로 옮긴다(500 이 아니다). disclosure 가 없으면(mask 0) 기본 π. */
async function proveSession(rsKey, synced, timings, disclosure = null, src) {
  const s = state.sessions[rsKey];
  if (!s) throw Object.assign(new Error('no_session'), { reason: 'no_session' });
  const reg = src.registration();
  const uc = src.userCred();
  const sessionWallet = new ethers.Wallet(s.sessionPrivKey);
  const discKey = disclosure && disclosure.mask !== 0n ? disclosureKey(disclosure) : '0';
  let cached = cache.get(synced.root, rsKey, discKey);
  const cacheHit = Boolean(cached);
  if (!cached) {
    // 세션이 물린 사용자 자격증명 위에 발급된 경우(동시 로그인 경합으로 ensureUserCred 가 그 사이 새 C_u 를 받았다) — 지금 C_u 의
    // blind_u 로는 증명이 안 만들어진다(witness 실패 → 500). 그 세션은 다음 게시에 어차피 죽으므로 revoked 로 정리한다.
    if (s.credential.Cf_u !== uc?.Cf_u) throw Object.assign(new Error('revoked'), { reason: 'revoked' });
    if (synced.tree.has(BigInt(uc.leaf))) throw Object.assign(new Error('revoked'), { reason: 'revoked' });
    const t = Date.now();
    cached = await buildCredentialProof({
      uid: BigInt(reg.uid), arid: BigInt(s.arid), s_u: BigInt(reg.s_u), blind_u: BigInt(uc.blind_u), blind_s: BigInt(s.blind_s), pk_i: BigInt(s.pk_i),
      attrs: (reg.attrs ?? []).map(BigInt),
      credential: s.credential, pk_CIA: { x: BigInt(s.credential.pk_CIA.x), y: BigInt(s.credential.pk_CIA.y) },
      pk_trace: { x: BigInt(s.pk_trace.x), y: BigInt(s.pk_trace.y) }, tree: synced.tree, disclosure,
    });
    timings.proveMs = Date.now() - t;
    // 증명은 증인이 계산된 root(cached.revRoot)에 대한 것이다. 동기화와 증인 생성 사이에 다른 요청이 리프를 붙였다면
    // synced.root 보다 새 root 이고, 그 root 로 캐시해야 다음 재검증이 맞는 π 를 찾는다(스펙 §5).
    cache.set(cached.revRoot, rsKey, cached, discKey);
    if (cached.revRoot !== synced.root) cache.set(synced.root, rsKey, cached, discKey);   // 이번 sync 의 root 로 찾는 호출도 맞춰 준다
  }
  const root = (cached.revRoot ?? synced.root).toString();
  const sig = await signChallenge(sessionWallet, rsKey);
  return { proof: cached.proof, publicSignals: cached.publicSignals, sig, pk_i: s.pk_i, r_s: rsKey, root, cacheHit, allowAgent: s.allowAgent, max_height: s.credential.max_height };
}

app.post('/wallet/revalidate', loginCors, async (req, res) => {
  try {
    const { r_s, skipSync } = req.body ?? {};
    if (!isDec(r_s)) return res.status(400).json({ error: 'r_s 필요' });
    const rsKey = BigInt(r_s).toString();
    const s = state.sessions[rsKey];
    if (!s) return res.status(404).json({ reason: 'no_session' });
    if (!LOG_ADDRESS) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
    const timings = { syncMs: 0, issueMs: 0, proveMs: 0 };
    // 시연용: 동기화를 건너뛰고 마지막 root 의 π 를 그대로 재제출한다(RP 의 stale_root 거절을 보이기 위해).
    if (skipSync) {
      if (!lastSync) return res.status(409).json({ reason: 'no_cached_proof' });
      const cached = cache.get(BigInt(lastSync.root), rsKey);
      if (!cached) return res.status(409).json({ reason: 'no_cached_proof' });
      const sig = await signChallenge(new ethers.Wallet(s.sessionPrivKey), rsKey);
      return res.json({ proof: cached.proof, publicSignals: cached.publicSignals, sig, pk_i: s.pk_i, r_s: rsKey, root: lastSync.root, cacheHit: true, timings });
    }
    let t = Date.now();
    let synced;
    try { synced = await syncTree(); }
    catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    timings.syncMs = Date.now() - t;
    lastSync = { root: synced.root.toString(), head: synced.head.toString(), tree: synced.tree };
    pruneSessions(synced.head);
    if (!state.sessions[rsKey]) return res.status(410).json({ reason: 'session_expired', timings });
    try {
      // snap 모드에서 세션 증인이 없으면(재시작) needs_consent — RP 페이지가 팝업을 다시 열어 /wallet/session/witness 로 채운다(§4.3)
      const src = secretSourceFor(req, rsKey);
      const out = await proveSession(rsKey, synced, timings, null, src);
      res.json({ ...out, timings });
    } catch (e) {
      if (e.reason === 'needs_consent') return res.status(409).json({ reason: 'needs_consent', timings });
      // 그 세션만 지운다. reg.userCred 는 그대로 둔다 — 다음 로그인의 ensureUserCred 가 tree.has 로 알아채 새로 받는다.
      if (e.reason === 'revoked') { delete state.sessions[rsKey]; persist(); return res.status(403).json({ reason: 'revoked', timings }); }
      if (e.reason === 'no_session') return res.status(404).json({ reason: 'no_session', timings });
      throw e;
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2026-09-22 §3.3 — 속성은 AA 가 관리한다. 여기서는 값을 다시 받아 저장만 하고, 바뀌었으면 옛 C_u·세션을 버린다(재발급은 다음 로그인).
app.post('/wallet/attrs/sync', async (req, res) => {
  try {
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    // sk_u 로 요청에 서명한다 — snap 모드는 본문 witness 가 필요하다(없으면 400 witness_required)
    let src;
    try { src = secretSourceFor(req); }
    catch (e) { if (e.reason) return res.status(400).json({ reason: e.reason }); throw e; }
    if (SECRETS === 'snap') { try { await validateWitness(req.body.witness, state.registration.uid, state.registration.cm_u); } catch (e) { if (e.reason === 'bad_witness') return res.status(400).json({ reason: 'bad_witness', detail: e.message }); throw e; } }
    const s = await syncAttrsFromCia(src);
    if (s.status !== 200) return res.status(502).json({ reason: 'attrs_failed', cia: s.body });
    res.json({ attrs: src.registration()?.attrs ?? null, changed: s.changed, ...src.pending });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 자기 폐기 프록시(metamask-snap §4.5, Ruling 7). Snap 이 비밀번호를 묻고 지갑 페이지가 여기로 내면 에이전트가 CIA 로
// 중계한다 — cia.js 에는 CORS 가 전혀 없어 브라우저가 :5100 → :4100 으로 직접 JSON POST 를 낼 수 없기 때문이다
// (CIA 서버는 이 작업에서 바꾸지 않는다). CORS 를 붙이지 않으므로 /wallet/login 과 같이 같은 오리진만 부를 수 있다.
// 비밀번호는 중계할 뿐 로그에도 상태 파일에도 남기지 않는다(이 경로는 state 를 건드리지 않아 persist() 와 무관하다).
//
// CSRF 주의(2026-09-22 최종 리뷰 Minor 5): 이 라우트는 CORS 를 열지 않지만, **폼 전송으로는 부를 수 없다는 보장이
// `express.json()` 하나에 걸려 있다** — 브라우저 폼은 application/json 을 보낼 수 없어 preflight 가 필요하고(CORS 가 없으니 차단),
// text/plain 으로 보내면 express.json() 이 파싱하지 않아 본문이 비어 400 이 난다. 나중에 `express.urlencoded()` 를 추가하면
// 남의 페이지가 숨긴 폼으로 이 라우트(되돌릴 수 없는 자기 폐기)를 부를 수 있게 된다. 그때는 CSRF 토큰이나 Origin 검사를 함께 넣는다.
app.post('/wallet/self_revoke', async (req, res) => {
  try {
    const { uid, pwd } = req.body ?? {};
    if (!isDec(uid) || typeof pwd !== 'string') return res.status(400).json({ error: 'uid(10진 문자열), pwd 필요' });
    // 이 지갑이 들고 있는 계정만 중계한다 — 다른 경로가 validateWitness 로 등록 uid 를 대조하는 것과 같은 규칙이다.
    // 없으면 임의 uid·pwd 를 CIA 에 던져 보는 통로가 된다(Ruling 9 라운드, 리뷰 Minor 3).
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    if (uid !== state.registration.uid) return res.status(403).json({ reason: 'uid_mismatch' });
    const r = await ciaPost('/cia/account/self_revoke', { uid, pwd });
    res.status(r.status).json(r.body ?? {});
  } catch (e) { res.status(502).json({ reason: 'cia_unavailable', detail: e.message }); }
});

// 운영·시연용: 폐기 트리 체크포인트를 버린다. 다음 동기화가 창세기부터 재생한다(스펙 §8). 같은 오리진만.
// CORS 를 열지 않지만 self_revoke 와 같은 이유로 본문에 JSON `{confirm:true}` 를 요구한다 — express.json() 은
// text/plain 단순 요청(폼 전송 등)을 파싱하지 않으므로, 이 확인 없이는 다른 오리진 페이지가 폼으로 캐시를 지울 수 없다.
app.post('/wallet/rcl/reset', (req, res) => {
  if (req.body?.confirm !== true) return res.status(400).json({ error: 'confirm:true 필요' });
  if (!rcl) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
  const { deferred } = rcl.reset();
  res.json({ ok: true, deferred });
});

app.post('/wallet/request', loginCors, async (req, res) => {
  try {
    const { r_s, body } = req.body ?? {};
    if (!isDec(r_s) || typeof body !== 'string') return res.status(400).json({ error: 'r_s, body(string) 필요' });
    const s = state.sessions[BigInt(r_s).toString()];
    if (!s) return res.status(404).json({ reason: 'no_session' });
    const sig = await signSessionRequest(new ethers.Wallet(s.sessionPrivKey), BigInt(r_s), body);
    res.json({ sig, pk_i: s.pk_i });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---- 온체인 실행(설계 2026-09-18 §6.3) ----
// 세션의 성명(같은 π)을 트랜잭션마다 첨부한다 — 컨트랙트가 매번 검증한다(사용자 결정 2026-09-17). 지갑 주소는 서비스 팩토리의
// computeAddress(PPID). file 모드의 릴레이어는 hardhat 언락 계정(후원 실행 설계 2026-07-20 과 같은 방식) — 데모용이며 실제 배포의
// 번들러 자리다. snap 모드(metamask-snap §4.4)는 /wallet/tx/prepare 가 calldata 만 만들고 MetaMask(사용자 EOA)가 보낸 뒤
// /wallet/tx/record 가 영수증을 파싱한다.
const RELAYER_INDEX = Number(process.env.MODE3_RELAYER_INDEX ?? 0);
const factoryInterface = new ethers.Interface(FACTORY_ABI);
const discStrings = (d) => (d ? { mask: d.mask.toString(), lo: d.lo.map(String), hi: d.hi.map(String) } : null);

/** /wallet/tx 와 /wallet/tx/prepare 의 공통부: 검증 → 동기화 → π(캐시) → 지갑 주소·nonce → 세션키 서명 → execute 인자.
 *  실패면 { error: { status, body } } (revoked 는 그 세션을 지운 뒤). */
async function buildExecute(req) {
  const fail = (status, body) => ({ error: { status, body } });
  const { r_s, to, value = '0', data = '0x', disclose } = req.body ?? {};
  if (!isDec(r_s) || !isAddr(to) || !isDec(value) || typeof data !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(data)) {
    return fail(400, { error: 'r_s, to(주소), value(wei 10진, 선택), data(hex, 선택) 필요' });
  }
  const rsKey = BigInt(r_s).toString();
  const s = state.sessions[rsKey];
  if (!s) return fail(404, { reason: 'no_session' });
  if (!s.factoryAddress) return fail(409, { reason: 'no_factory', detail: '서비스가 로그인 때 factoryAddress 를 주지 않았다' });
  if (!LOG_ADDRESS) return fail(503, { reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
  // 2026-09-22 §4.2 선택 공개: disclose 를 회로 입력으로. 형식·범위 오류·불만족은 체인·증명 작업 전에 걸러낸다(attrs 는 두 모드 모두 파일의 공개값).
  let disclosure;
  try { disclosure = normalizeDisclosure(disclose, (state.registration.attrs ?? []).map(BigInt)); }
  catch (e) { if (e.reason) return fail(400, { reason: e.reason, detail: e.message }); throw e; }
  const timings = { syncMs: 0, issueMs: 0, proveMs: 0, txMs: 0 };
  let t = Date.now();
  let synced;
  try { synced = await syncTree(); }
  catch (e) { return fail(503, { reason: 'chain_unavailable', detail: e.message }); }
  timings.syncMs = Date.now() - t;
  lastSync = { root: synced.root.toString(), head: synced.head.toString(), tree: synced.tree };
  pruneSessions(synced.head);
  if (!state.sessions[rsKey]) return fail(409, { reason: 'session_expired', timings });
  let src;
  try { src = secretSourceFor(req, rsKey); }
  catch (e) { if (e.reason === 'needs_consent') return fail(409, { reason: 'needs_consent', timings }); throw e; }
  let proved;
  try { proved = await proveSession(rsKey, synced, timings, disclosure, src); }   // root·disclosure 가 같으면 캐시 π, 아니면 재증명
  catch (e) {
    if (e.reason === 'revoked') { delete state.sessions[rsKey]; persist(); return fail(403, { reason: 'revoked', timings }); }
    if (e.reason === 'no_session') return fail(404, { reason: 'no_session', timings });
    throw e;
  }
  const walletAddr = await factoryAt(s.factoryAddress, provider).computeAddress(BigInt(s.PPID));
  // 아직 배포 전이면 nonce 는 0(uint256 기본값) — 배포 트랜잭션을 먼저 보낸 뒤 execute 가 이 nonce 로 들어간다
  const deployNeeded = (await provider.getCode(walletAddr)) === '0x';
  const nonce = deployNeeded ? 0n : await walletAt(walletAddr, provider).nonce();
  const payload = { to: ethers.getAddress(to), value: BigInt(value), data, nonce };
  const sig = signPayload(new ethers.Wallet(s.sessionPrivKey), { chainId: await chainId(), wallet: walletAddr, ...payload, discMask: disclosure.mask, discLo: disclosure.lo, discHi: disclosure.hi });
  const { a, b, c, pub } = await proofToCalldata(proved.proof, proved.publicSignals);
  return { s, rsKey, disclosure, synced, timings, proved, walletAddr, deployNeeded, nonce, payload, args: [payload, sig, a, b, c, pub] };
}

/** execute 영수증 → 응답 공통부. disclosure = 요청값(지갑이 증명에 넣은 것), onchainDisclosure = Disclosure 이벤트에서 읽은 값(mask=0 이면 이벤트가 없어 null). */
function receiptResult(receipt, walletAddr, disclosure) {
  const parsed = parseExecuteReceipt(receipt, walletAddr);
  return {
    txHash: receipt.hash, wallet: walletAddr, status: receipt.status, ok: parsed.executed?.success ?? null, gasUsed: receipt.gasUsed.toString(),
    nonce: parsed.executed ? parsed.executed.nonceUsed.toString() : null,
    executed: parsed.executed ? { nonceUsed: parsed.executed.nonceUsed.toString(), to: parsed.executed.to, value: parsed.executed.value.toString(), success: parsed.executed.success } : null,
    disclosure: disclosure && disclosure.mask !== 0n ? discStrings(disclosure) : null,
    onchainDisclosure: discStrings(parsed.disclosure),
  };
}

// 자산 이동은 지갑 UI 에서만 시작한다(스펙 §6.3) — 서비스 오리진에는 열지 않는다. file 모드 전용(릴레이어가 보낸다).
app.post('/wallet/tx', async (req, res) => {
  try {
    if (SECRETS === 'snap') return res.status(409).json({ reason: 'use_tx_prepare' });
    const b = await buildExecute(req);
    if (b.error) return res.status(b.error.status).json(b.error.body);
    const { s, walletAddr, deployNeeded, nonce, args, timings, disclosure, proved, synced } = b;
    const relayer = await provider.getSigner(RELAYER_INDEX);
    let deployed = false;
    if (deployNeeded) { await (await factoryAt(s.factoryAddress, relayer).deploy(BigInt(s.PPID))).wait(); deployed = true; }
    const walletC = walletAt(walletAddr, relayer);
    const t = Date.now();
    let receipt;
    try { receipt = await (await walletC.execute(...args)).wait(); }
    catch (e) {
      // revert 이름(NonceMismatch·StaleRevocationRoot·RootTooOld·Expired…)을 그대로 돌려준다 — 서비스 페이지가 보여준다.
      // ethers v6 는 send()(execute 처럼 상태를 바꾸는 함수는 내부적으로 estimateGas 를 먼저 부른다)의 revert 를
      // 컨트랙트 ABI 로 자동 디코드하지 않는다 — staticCall 경로에서만 contract.interface.makeError 를 거친다.
      // 그래서 e.revert 는 항상 null 이고 e.data 에 원본 바이트만 남는다 — 직접 파싱한다.
      let name = e?.revert?.name ?? e?.reason ?? e?.shortMessage ?? e.message;
      if (e?.data) { try { name = walletC.interface.parseError(e.data)?.name ?? name; } catch { /* 알려진 커스텀 에러가 아니면 원래 메시지를 쓴다 */ } }
      return res.status(409).json({ reason: 'execute_reverted', detail: String(name), wallet: walletAddr, nonce: nonce.toString(), timings });
    }
    timings.txMs = Date.now() - t;
    res.json({ ...receiptResult(receipt, walletAddr, disclosure), nonce: nonce.toString(), deployed, cacheHit: proved.cacheHit, root: proved.root, timings });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// snap 모드(metamask-snap §4.4): 증명·서명·calldata 까지만. 페이지가 MetaMask 로 (deployCalldata 가 있으면 팩토리에 먼저) 보낸다.
// 세션에 증인이 없으면(재시작) 409 needs_consent. file 모드에서도 동작한다(상태 파일의 비밀로).
app.post('/wallet/tx/prepare', async (req, res) => {
  try {
    const b = await buildExecute(req);
    if (b.error) return res.status(b.error.status).json(b.error.body);
    const { s, walletAddr, deployNeeded, nonce, args, timings, disclosure, proved, synced } = b;
    res.json({
      walletAddr, factoryAddress: s.factoryAddress, deployNeeded,
      deployCalldata: deployNeeded ? factoryInterface.encodeFunctionData('deploy', [BigInt(s.PPID)]) : null,
      calldata: walletInterface.encodeFunctionData('execute', args),
      nonce: nonce.toString(), disclosure: disclosure.mask === 0n ? null : discStrings(disclosure),
      cacheHit: proved.cacheHit, root: proved.root, timings,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// MetaMask 가 보낸 execute 의 영수증을 파싱해 /wallet/tx 와 같은 형식으로 돌려준다. 영수증이 아직 없으면 202 { pending:true } —
// 에이전트는 기다리지 않는다(페이지가 다시 부른다). 요청값 disclosure 는 트랜잭션 calldata 의 pub[14..22] 에서 되돌린다(상태 없음).
app.post('/wallet/tx/record', async (req, res) => {
  try {
    const { r_s, txHash } = req.body ?? {};
    if (!isDec(r_s) || typeof txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) return res.status(400).json({ error: 'r_s, txHash(32바이트 hex) 필요' });
    const s = state.sessions[BigInt(r_s).toString()];
    if (!s) return res.status(404).json({ reason: 'no_session' });
    if (!s.factoryAddress) return res.status(409).json({ reason: 'no_factory' });
    const walletAddr = await factoryAt(s.factoryAddress, provider).computeAddress(BigInt(s.PPID));
    const [receipt, tx] = await Promise.all([provider.getTransactionReceipt(txHash), provider.getTransaction(txHash)]);
    if (!receipt) return res.status(202).json({ pending: true, txHash, wallet: walletAddr });
    // 이 세션의 지갑으로 간 트랜잭션만 받는다 — 배포 tx 나 남의 트랜잭션을 실행 결과로 오인하지 않는다(리뷰 Minor)
    const txTo = receipt.to ?? tx?.to ?? null;
    if (!txTo || txTo.toLowerCase() !== walletAddr.toLowerCase()) return res.status(409).json({ reason: 'not_our_tx', txHash, wallet: walletAddr });
    let disclosure = null;
    const dec = tx ? decodeExecuteCalldata(tx.data) : null;
    if (dec) { const pub = dec.pub.map(BigInt); disclosure = { mask: pub[14], lo: pub.slice(15, 19), hi: pub.slice(19, 23) }; }
    res.json(receiptResult(receipt, walletAddr, disclosure));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Mode 3 wallet agent at http://127.0.0.1:${PORT} (cia=${CIA_URL}, rp=${RP_ORIGIN}, log=${LOG_ADDRESS ?? 'none'})`);
});
