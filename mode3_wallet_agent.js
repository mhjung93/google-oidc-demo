// Mode 3 지갑 에이전트 (:5100). 스펙: docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md §3
//
// Mode 2 의 wallet_agent.js 와 나란히 두는 별도 프로세스다. 그쪽 코드를 import 하지 않는다.
// 암호학은 전부 lib/mode3_wallet.js 에 있고 여기는 상태 파일 + HTTP 만이다.
// 로그인마다 발급된다(설계 2026-09-15 §5) — 성명은 세션(r_s) 단위이고 세션 안에서만 재사용한다.
// V4(2026-09-18): 자격증명은 max_height·allowAgent, 세션은 서비스 팩토리 주소를 들고 /wallet/tx 로 온체인 실행(설계 §6.3).
// V5(2026-09-21): 자격증명 이중 구조 — 사용자 자격증명(C_u, 사용자당 하나, 폐기 리프)과 세션 자격증명(C_s, 로그인마다).
//   사용자 자격증명은 첫 로그인 또는 속성 변경(/wallet/attrs) 때 받고, 폐기되면 다음 로그인이 알아채 새로 받는다.
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { readJson, writeJsonAtomic } from './lib/mode3_state.js';
import { createRegistration, createSessionKey, buildUserCredRequest, buildIssueRequest, syncRevocationTree, buildCredentialProof, signChallenge, signSessionRequest, ProofCache, chooseMaxHeight } from './lib/mode3_wallet.js';
import { signPayload, proofToCalldata, parseExecuteReceipt, factoryAt, walletAt } from './lib/mode3_onchain.js';
import { pointToStrings } from './lib/mode3_issuance.js';
import { normalizeAttrs, SCALAR_MAX, ppid } from './lib/mode3_credential.js';
import { verifyRpCert } from './lib/mode3_rp_cert.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.MODE3_WALLET_PORT) || 5100;
const STATE_FILE = process.env.MODE3_WALLET_STATE_FILE || path.join(__dirname, 'mode3_wallet_state.json');
const CIA_URL = process.env.MODE3_CIA_URL || 'http://127.0.0.1:4100';
const RP_ORIGIN = process.env.MODE3_RP_ORIGIN || 'http://127.0.0.1:3100';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
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
// sessions:     r_s → { arid, PPID, pk_trace:{x,y}, factoryAddress|null, allowAgent("0"|"1"), C_s_pt:{x,y}, blind_s,
//                       credential:{Cf_u,Cf_s,max_height,chainid,allowAgent,sigma,pk_CIA}, sessionPrivKey, pk_i, issuedAt }
// version 6 (2026-09-21): 자격증명 이중 구조(userCred·blind_u / C_s·blind_s). 옛 파일은 등록만 살리고 세션은 비운다 —
// 옛 등록에는 userCred 가 없으므로 다음 로그인이 새로 받는다.
const WALLET_STATE_VERSION = 6;
let state = readJson(STATE_FILE, { version: WALLET_STATE_VERSION, registration: null, sessions: {} });
function persist() { writeJsonAtomic(STATE_FILE, state, 0o600); }
if (state.version !== WALLET_STATE_VERSION) {
  console.warn(`[wallet] 상태 파일 버전 ${state.version} → ${WALLET_STATE_VERSION}: 세션·credential 을 비운다(옛 형식). 등록은 유지.`);
  state = { version: WALLET_STATE_VERSION, registration: state.registration ?? null, sessions: {} };
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

/** 사용자 자격증명 확보(설계 2026-09-21 §6.2 3단계). 없거나 폐기됐으면 새로 받는다. 돌려주는 값은 { status, body, fresh }. */
async function ensureUserCred(tree) {
  const reg = state.registration;
  if (reg.userCred && !tree.has(BigInt(reg.userCred.leaf))) return { status: 200, fresh: false };
  const req = await buildUserCredRequest({ uid: BigInt(reg.uid), s_u: BigInt(reg.s_u), r_u: BigInt(reg.r_u), sk_u: reg.sk_u, attrs: (reg.attrs ?? []).map(BigInt) });
  const r = await ciaPost('/cia/user_cred', req.body);
  if (r.status === 201 || r.status === 200) {
    reg.userCred = { C_u_pt: { x: req.C_u_pt.x.toString(), y: req.C_u_pt.y.toString() }, Cf_u: req.Cf_u.toString(), blind_u: req.secrets.blind_u.toString(), leaf: req.leaf.toString(), issuedAt: new Date().toISOString() };
    // 옛 자격증명의 세션은 다음 게시에 죽는다 — 지금 지운다
    state.sessions = {}; cache.clear();
    persist();
    return { status: 200, body: r.body, fresh: true };
  }
  return { status: r.status, body: r.body, fresh: false };
}

async function issueSession(arid, r_s, pk_trace, allowAgent, factoryAddress, head) {
  const reg = state.registration;
  const session = createSessionKey();
  const chainid = await chainId();
  const req = await buildIssueRequest({
    uid: BigInt(reg.uid), Cf_u: BigInt(reg.userCred.Cf_u), arid: BigInt(arid), sk_u: reg.sk_u, session, chainid, allowAgent: BigInt(allowAgent),
    max_height: chooseMaxHeight(head, { ttlBlocks: TTL_BLOCKS, grid: HEIGHT_GRID }),
  });
  const r = await ciaPost('/cia/issue', req.body);
  if (r.status === 200) {
    const PPID = await ppid({ uid: BigInt(reg.uid), arid: BigInt(arid), s_u: BigInt(reg.s_u), chainid });
    state.sessions[r_s.toString()] = {
      arid, PPID: PPID.toString(), pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }, factoryAddress, allowAgent,
      C_s_pt: { x: req.C_s_pt.x.toString(), y: req.C_s_pt.y.toString() }, blind_s: req.secrets.blind_s.toString(),
      credential: r.body, sessionPrivKey: session.wallet.privateKey, pk_i: session.pk_i.toString(), issuedAt: new Date().toISOString(),
    };
    persist();
  }
  return r;
}

// ---- 앱 ----
const app = express();
app.use(express.json({ limit: '1mb' }));

// RP 페이지(다른 오리진)가 부르는 것은 /wallet/login·/wallet/revalidate·/wallet/request 뿐이다. 문자열 origin 은
// cors 가 요청 Origin 과 무관하게 헤더를 붙이므로, 일치할 때만 붙이도록 함수형으로 둔다.
const loginCors = cors({ origin: (origin, cb) => cb(null, origin === RP_ORIGIN), methods: ['POST'] });
app.options('/wallet/login', loginCors);
app.options('/wallet/revalidate', loginCors);
app.options('/wallet/request', loginCors);

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'wallet.html')));

app.get('/wallet/status', async (req, res) => {
  let head = null;
  try { head = (await provider.getBlockNumber()).toString(); } catch { /* 체인 없음 */ }
  const sessions = {};
  for (const [r_s, e] of Object.entries(state.sessions)) {
    sessions[r_s] = { arid: e.arid, PPID: e.PPID, max_height: e.credential.max_height, chainid: e.credential.chainid, allowAgent: e.allowAgent, factoryAddress: e.factoryAddress, sessionAddress: new ethers.Wallet(e.sessionPrivKey).address, issuedAt: e.issuedAt, pk_trace: e.pk_trace };
  }
  // userCred.revoked 는 마지막 동기화의 트리로 판정한다(여기서 다시 동기화하지 않는다). 아직 동기화가 없으면 null.
  const uc = state.registration?.userCred;
  const userCred = uc ? { Cf_u: uc.Cf_u, issuedAt: uc.issuedAt, revoked: lastSync?.tree ? lastSync.tree.has(BigInt(uc.leaf)) : null } : null;
  res.json({
    registered: Boolean(state.registration), uid: state.registration?.uid ?? null, userCred, sessions,
    head, lastRoot: lastSync?.root ?? null, logAddress: LOG_ADDRESS,
  });
});

app.post('/wallet/register', async (req, res) => {
  try {
    const { uid, pwd } = req.body ?? {};
    if (!isDec(uid) || typeof pwd !== 'string') return res.status(400).json({ error: 'uid(10진 문자열), pwd 필요' });
    let attrs;
    try { attrs = normalizeAttrs(req.body?.attrs).map(String); }
    catch (e) { return res.status(400).json({ error: `attrs: ${e.message}` }); }
    if (state.registration) return res.status(409).json({ reason: 'already_registered', uid: state.registration.uid });
    const reg = await createRegistration();
    const r = await ciaPost('/cia/register', { uid, pwd, cm_u: pointToStrings(reg.cm_u) });
    if (r.status !== 201) {
      const status = r.status === 401 || r.status === 409 ? r.status : 502;
      return res.status(status).json({ reason: 'register_failed', cia: r.body });
    }
    state.registration = { uid, s_u: reg.s_u.toString(), r_u: reg.r_u.toString(), cm_u: pointToStrings(reg.cm_u), sk_u: r.body.sk_u, attrs };
    persist();
    res.status(201).json({ uid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/wallet/login', loginCors, async (req, res) => {
  try {
    const { arid, origin, cert_s, pk_trace, r_s, allowAgent = '0', factoryAddress = null } = req.body ?? {};
    if (!isDec(arid) || typeof origin !== 'string' || !cert_s || !pk_trace || !isDec(pk_trace.x) || !isDec(pk_trace.y) || !isDec(r_s)) return res.status(400).json({ error: 'arid, origin, cert_s, pk_trace{x,y}, r_s 필요' });
    if (allowAgent !== '0' && allowAgent !== '1') return res.status(400).json({ error: 'allowAgent 는 "0" 또는 "1"' });
    if (factoryAddress !== null && !isAddr(factoryAddress)) return res.status(400).json({ error: 'factoryAddress 는 주소' });
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    if (!LOG_ADDRESS) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
    const rs = BigInt(r_s);
    if (rs >= SCALAR_MAX) return res.status(400).json({ error: 'r_s 는 2^250 미만' });
    // r_s 는 세션 식별자다 — 같은 값으로 두 번 로그인할 정당한 경로가 없고, 덮어쓰면 캐시의 옛 π 와 새 세션키가 어긋난다.
    if (state.sessions[rs.toString()]) return res.status(409).json({ reason: 'duplicate_session' });

    // 서비스 인증(설계 §3·§4): cert_s 가 pk_CIA 서명이고, 요청을 보낸 오리진이 cert 의 오리진과 같아야 한다.
    // 피싱 페이지는 진짜 서비스의 (arid, cert_s) 를 그대로 보여줄 수는 있어도 그 오리진에서 요청을 보낼 수는 없다.
    // pk_trace 는 인증서가 덮는다 — 서비스가 자기만 아는 키를 주면 서비스 혼자 태그를 연다(2026-09-16 §2).
    let pk;
    // CIA 가 죽어 pk_CIA 를 못 받은 것이지 체인 문제가 아니다 — reason 목록엔 없지만 원인을 구분해 둔다.
    try { pk = await pkCia(); } catch (e) { return res.status(503).json({ reason: 'cia_unavailable', detail: e.message }); }
    const reqOrigin = req.get('Origin');
    if (reqOrigin !== origin || !(await verifyRpCert(pk, { arid: BigInt(arid), origin, pk_trace, cert: cert_s }))) {
      return res.status(403).json({ reason: 'bad_rp_cert' });
    }
    // 팩토리는 서비스가 정하지만 임의 코드일 수 있다 — 인증서의 arid·pk_trace, 고정된 pk_CIA·로그 주소와 온체인 값을 대조해
    // 검증 규칙이 같은 계정만 받아들인다(2026-09-18 점검 3). 값이 안 맞거나 컨트랙트가 아니면 bad_factory.
    if (factoryAddress !== null) {
      try {
        const f = factoryAt(factoryAddress, provider);
        const [fa, fl, fx, fy, tx, ty] = await Promise.all([f.arid(), f.log(), f.pkCIAX(), f.pkCIAY(), f.pkTraceX(), f.pkTraceY()]);
        if (fa !== BigInt(arid) || fl.toLowerCase() !== LOG_ADDRESS.toLowerCase() || fx !== pk.x || fy !== pk.y || tx !== BigInt(pk_trace.x) || ty !== BigInt(pk_trace.y)) {
          return res.status(409).json({ reason: 'bad_factory' });
        }
      } catch (e) { return res.status(409).json({ reason: 'bad_factory', detail: e.shortMessage ?? e.message }); }
    }

    const timings = { syncMs: 0, userCredMs: 0, issueMs: 0, proveMs: 0 };
    let t = Date.now();
    let synced;
    try { synced = await syncRevocationTree(provider, LOG_ADDRESS); }
    catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    timings.syncMs = Date.now() - t;
    lastSync = { root: synced.root.toString(), head: synced.head.toString(), tree: synced.tree };

    pruneSessions(synced.head);
    // 사용자 자격증명은 사용자당 하나 — 없거나 폐기됐을 때만 새로 받는다(userCredMs 는 재사용이면 0)
    t = Date.now();
    const uc = await ensureUserCred(synced.tree);
    timings.userCredMs = uc.fresh ? Date.now() - t : 0;
    if (uc.status === 403) return res.status(403).json({ reason: 'account_disabled', timings });
    if (uc.status !== 200) return res.status(502).json({ reason: 'user_cred_failed', cia: uc.body, timings });
    t = Date.now();
    const r = await issueSession(arid, rs, { x: BigInt(pk_trace.x), y: BigInt(pk_trace.y) }, allowAgent, factoryAddress ? ethers.getAddress(factoryAddress) : null, synced.head);      // 세션 자격증명은 로그인마다(설계 §5), 만료는 방금 읽은 head 기준
    timings.issueMs = Date.now() - t;
    // no_user_cred: 방금 확보한 자격증명이 그 사이(경합) 물렸다 — 다음 로그인의 ensureUserCred 가 새로 받는다
    if (r.status === 403) return res.status(403).json({ reason: r.body?.reason === 'no_user_cred' ? 'user_cred_retired' : 'account_disabled', timings });
    if (r.status !== 200) return res.status(502).json({ reason: 'issue_failed', cia: r.body, timings });
    const out = await proveSession(rs.toString(), synced, timings);
    res.json({ ...out, issued: true, allowAgent, timings });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/** 세션의 성명으로 현재 root 에 대한 π 를 만든다(캐시). 사용자 자격증명 리프가 트리에 있으면 throw('revoked') — 그 사용자의 모든 세션이 같이 죽는다. */
async function proveSession(rsKey, synced, timings) {
  const s = state.sessions[rsKey];
  const reg = state.registration;
  const sessionWallet = new ethers.Wallet(s.sessionPrivKey);
  let cached = cache.get(synced.root, rsKey);
  const cacheHit = Boolean(cached);
  if (!cached) {
    // 세션이 물린 사용자 자격증명 위에 발급된 경우(동시 로그인 경합으로 ensureUserCred 가 그 사이 새 C_u 를 받았다) — 지금 C_u 의
    // blind_u 로는 증명이 안 만들어진다(witness 실패 → 500). 그 세션은 다음 게시에 어차피 죽으므로 revoked 로 정리한다.
    if (s.credential.Cf_u !== reg.userCred?.Cf_u) throw Object.assign(new Error('revoked'), { reason: 'revoked' });
    if (synced.tree.has(BigInt(reg.userCred.leaf))) throw Object.assign(new Error('revoked'), { reason: 'revoked' });
    const t = Date.now();
    cached = await buildCredentialProof({
      uid: BigInt(reg.uid), arid: BigInt(s.arid), s_u: BigInt(reg.s_u), blind_u: BigInt(reg.userCred.blind_u), blind_s: BigInt(s.blind_s), pk_i: BigInt(s.pk_i),
      attrs: (reg.attrs ?? []).map(BigInt),
      credential: s.credential, pk_CIA: { x: BigInt(s.credential.pk_CIA.x), y: BigInt(s.credential.pk_CIA.y) },
      pk_trace: { x: BigInt(s.pk_trace.x), y: BigInt(s.pk_trace.y) }, tree: synced.tree,
    });
    timings.proveMs = Date.now() - t;
    cache.set(synced.root, rsKey, cached);
  }
  const sig = await signChallenge(sessionWallet, rsKey);
  return { proof: cached.proof, publicSignals: cached.publicSignals, sig, pk_i: s.pk_i, r_s: rsKey, root: synced.root.toString(), cacheHit, allowAgent: s.allowAgent, max_height: s.credential.max_height };
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
    try { synced = await syncRevocationTree(provider, LOG_ADDRESS); }
    catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    timings.syncMs = Date.now() - t;
    lastSync = { root: synced.root.toString(), head: synced.head.toString(), tree: synced.tree };
    pruneSessions(synced.head);
    if (!state.sessions[rsKey]) return res.status(410).json({ reason: 'session_expired', timings });
    try {
      const out = await proveSession(rsKey, synced, timings);
      res.json({ ...out, timings });
    } catch (e) {
      // 그 세션만 지운다. reg.userCred 는 그대로 둔다 — 다음 로그인의 ensureUserCred 가 tree.has 로 알아채 새로 받는다.
      if (e.reason === 'revoked') { delete state.sessions[rsKey]; persist(); return res.status(403).json({ reason: 'revoked', timings }); }
      throw e;
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// §6.3(2026-09-21) 속성 변경: 새 사용자 자격증명을 받는다. AA 가 옛 리프를 pending 에 넣으므로 옛 세션은 다음 게시에 죽는다 — 지금 지운다.
app.post('/wallet/attrs', async (req, res) => {
  try {
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    let attrs;
    try { attrs = normalizeAttrs(req.body?.attrs).map(String); } catch (e) { return res.status(400).json({ error: `attrs: ${e.message}` }); }
    if (!LOG_ADDRESS) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
    let synced;
    try { synced = await syncRevocationTree(provider, LOG_ADDRESS); } catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    lastSync = { root: synced.root.toString(), head: synced.head.toString(), tree: synced.tree };
    pruneSessions(synced.head);   // 만료된 세션은 sessionsDropped 에 세지 않는다
    const dropped = Object.keys(state.sessions).length;
    const prev = { attrs: state.registration.attrs, userCred: state.registration.userCred };
    state.registration.attrs = attrs;
    state.registration.userCred = null;   // 강제 재발급
    const uc = await ensureUserCred(synced.tree);
    if (uc.status !== 200) {
      // CIA 가 거절하면 아무것도 바뀌지 않는다 — 옛 자격증명·속성을 되돌려 기존 세션이 그대로 쓰이게 한다(성공 전엔 persist 하지 않았다)
      Object.assign(state.registration, prev);
      if (uc.status === 403) return res.status(403).json({ reason: 'account_disabled' });
      return res.status(502).json({ reason: 'user_cred_failed', cia: uc.body });
    }
    res.json({ Cf_u: state.registration.userCred.Cf_u, leaf: state.registration.userCred.leaf, sessionsDropped: dropped });
  } catch (e) { res.status(500).json({ error: e.message }); }
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
// computeAddress(PPID). 릴레이어는 hardhat 언락 계정(후원 실행 설계 2026-07-20 과 같은 방식) — 데모용이며 실제 배포의 번들러 자리다.
const RELAYER_INDEX = Number(process.env.MODE3_RELAYER_INDEX ?? 0);
// 자산 이동은 지갑 UI 에서만 시작한다(스펙 §6.3) — 서비스 오리진에는 열지 않는다.
app.post('/wallet/tx', async (req, res) => {
  try {
    const { r_s, to, value = '0', data = '0x' } = req.body ?? {};
    if (!isDec(r_s) || !isAddr(to) || !isDec(value) || typeof data !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(data)) {
      return res.status(400).json({ error: 'r_s, to(주소), value(wei 10진, 선택), data(hex, 선택) 필요' });
    }
    const rsKey = BigInt(r_s).toString();
    const s = state.sessions[rsKey];
    if (!s) return res.status(404).json({ reason: 'no_session' });
    if (!s.factoryAddress) return res.status(409).json({ reason: 'no_factory', detail: '서비스가 로그인 때 factoryAddress 를 주지 않았다' });
    if (!LOG_ADDRESS) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
    const timings = { syncMs: 0, issueMs: 0, proveMs: 0, txMs: 0 };
    let t = Date.now();
    let synced;
    try { synced = await syncRevocationTree(provider, LOG_ADDRESS); }
    catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    timings.syncMs = Date.now() - t;
    lastSync = { root: synced.root.toString(), head: synced.head.toString(), tree: synced.tree };
    pruneSessions(synced.head);
    if (!state.sessions[rsKey]) return res.status(409).json({ reason: 'session_expired', timings });
    let proved;
    try { proved = await proveSession(rsKey, synced, timings); }   // root 가 같으면 캐시 π, 아니면 재증명
    catch (e) {
      if (e.reason === 'revoked') { delete state.sessions[rsKey]; persist(); return res.status(403).json({ reason: 'revoked', timings }); }
      throw e;
    }
    const relayer = await provider.getSigner(RELAYER_INDEX);
    const factory = factoryAt(s.factoryAddress, relayer);
    const walletAddr = await factory.computeAddress(BigInt(s.PPID));
    let deployed = false;
    if ((await provider.getCode(walletAddr)) === '0x') { await (await factory.deploy(BigInt(s.PPID))).wait(); deployed = true; }
    const walletC = walletAt(walletAddr, relayer);
    const nonce = await walletC.nonce();
    const payload = { to: ethers.getAddress(to), value: BigInt(value), data, nonce };
    const sig = signPayload(new ethers.Wallet(s.sessionPrivKey), { chainId: await chainId(), wallet: walletAddr, ...payload });
    const { a, b, c, pub } = await proofToCalldata(proved.proof, proved.publicSignals);
    t = Date.now();
    let receipt;
    try { receipt = await (await walletC.execute(payload, sig, a, b, c, pub)).wait(); }
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
    const { executed } = parseExecuteReceipt(receipt, walletAddr);
    res.json({
      txHash: receipt.hash, wallet: walletAddr, nonce: nonce.toString(), status: receipt.status, ok: executed?.success ?? null,
      gasUsed: receipt.gasUsed.toString(), deployed, cacheHit: proved.cacheHit, root: synced.root.toString(), timings,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Mode 3 wallet agent at http://127.0.0.1:${PORT} (cia=${CIA_URL}, rp=${RP_ORIGIN}, log=${LOG_ADDRESS ?? 'none'})`);
});
