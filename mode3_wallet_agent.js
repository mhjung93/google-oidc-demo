// Mode 3 지갑 에이전트 (:5100). 스펙: docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md §3
//
// Mode 2 의 wallet_agent.js 와 나란히 두는 별도 프로세스다. 그쪽 코드를 import 하지 않는다.
// 암호학은 전부 lib/mode3_wallet.js 에 있고 여기는 상태 파일 + HTTP 만이다.
// 로그인마다 발급된다(설계 2026-09-15 §5) — 성명은 세션(r_s) 단위이고 세션 안에서만 재사용한다.
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { readJson, writeJsonAtomic } from './lib/mode3_state.js';
import { createRegistration, createSessionKey, buildIssueRequest, syncRevocationTree, buildCredentialProof, signChallenge, signSessionRequest, ProofCache } from './lib/mode3_wallet.js';
import { pointToStrings } from './lib/mode3_issuance.js';
import { credLeaf } from './lib/mode3_revocation.js';
import { normalizeAttrs, SCALAR_MAX } from './lib/mode3_credential.js';
import { verifyRpCert } from './lib/mode3_rp_cert.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.MODE3_WALLET_PORT) || 5100;
const STATE_FILE = process.env.MODE3_WALLET_STATE_FILE || path.join(__dirname, 'mode3_wallet_state.json');
const CIA_URL = process.env.MODE3_CIA_URL || 'http://127.0.0.1:4100';
const RP_ORIGIN = process.env.MODE3_RP_ORIGIN || 'http://127.0.0.1:3100';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const nowSec = () => BigInt(Math.floor(Date.now() / 1000));

// 게시 직후의 로그인이 옛 root 를 보지 않도록 ethers 의 250ms 캐시를 끈다(lib/mode3_wallet.js 주석).
const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 });

// ---- 상태 ----
// registration: { uid, s_u, r_u, cm_u:{x,y}, sk_u, attrs:[4개 10진] }   §6.1. 한 번
// sessions:     r_s → { arid, credential:{C,exptime,chainid,r_s,sigma,pk_CIA}, blind, sessionPrivKey, pk_i, issuedAt }
// version 3 (2026-09-15): credentials[arid] → sessions[r_s]. 옛 파일은 등록만 살리고 세션은 비운다.
const WALLET_STATE_VERSION = 3;
let state = readJson(STATE_FILE, { version: WALLET_STATE_VERSION, registration: null, sessions: {} });
function persist() { writeJsonAtomic(STATE_FILE, state, 0o600); }
if (state.version !== WALLET_STATE_VERSION) {
  console.warn(`[wallet] 상태 파일 버전 ${state.version} → ${WALLET_STATE_VERSION}: 세션·credential 을 비운다(옛 형식). 등록은 유지.`);
  state = { version: WALLET_STATE_VERSION, registration: state.registration ?? null, sessions: {} };
  persist();
}
state.sessions ??= {};
function pruneSessions() {
  const now = nowSec();
  for (const [k, s] of Object.entries(state.sessions)) if (BigInt(s.credential.exptime) < now) delete state.sessions[k];
}
pruneSessions();   // 기동 직후 만료된 세션을 걷어낸다(설계 §8) — 로그인 때도 다시 부른다

const cache = new ProofCache();   // (root, r_s) → {proof, publicSignals}. 메모리만
let lastSync = null;              // { root, head }

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
const json = async (r) => ({ status: r.status, body: await r.json().catch(() => null) });
const ciaPost = (p, body) => fetch(`${CIA_URL}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(json);

let chainIdCache = null;
async function chainId() {
  if (chainIdCache === null) chainIdCache = (await provider.getNetwork()).chainId;   // bigint
  return chainIdCache;
}

async function issueCredential(arid, r_s) {
  const reg = state.registration;
  const session = createSessionKey();
  const req = await buildIssueRequest({
    uid: BigInt(reg.uid), arid: BigInt(arid), s_u: BigInt(reg.s_u), r_u: BigInt(reg.r_u), sk_u: reg.sk_u, session,
    chainid: await chainId(), attrs: (reg.attrs ?? []).map(BigInt), r_s,
  });
  const r = await ciaPost('/cia/issue', req.body);
  if (r.status === 200) {
    state.sessions[r_s.toString()] = {
      arid, credential: r.body, blind: req.secrets.blind.toString(),
      sessionPrivKey: session.wallet.privateKey, pk_i: session.pk_i.toString(),
      issuedAt: new Date().toISOString(),
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
    sessions[r_s] = { arid: e.arid, exptime: e.credential.exptime, chainid: e.credential.chainid, sessionAddress: new ethers.Wallet(e.sessionPrivKey).address, issuedAt: e.issuedAt };
  }
  res.json({
    registered: Boolean(state.registration), uid: state.registration?.uid ?? null, sessions,
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
    const { arid, origin, cert_s, r_s } = req.body ?? {};
    if (!isDec(arid) || typeof origin !== 'string' || !cert_s || !isDec(r_s)) return res.status(400).json({ error: 'arid, origin, cert_s, r_s 필요' });
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    if (!LOG_ADDRESS) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
    const rs = BigInt(r_s);
    if (rs >= SCALAR_MAX) return res.status(400).json({ error: 'r_s 는 2^250 미만' });
    // r_s 는 세션 식별자다 — 같은 값으로 두 번 로그인할 정당한 경로가 없고, 덮어쓰면 캐시의 옛 π 와 새 세션키가 어긋난다.
    if (state.sessions[rs.toString()]) return res.status(409).json({ reason: 'duplicate_session' });

    // 서비스 인증(설계 §3·§4): cert_s 가 pk_CIA 서명이고, 요청을 보낸 오리진이 cert 의 오리진과 같아야 한다.
    // 피싱 페이지는 진짜 서비스의 (arid, cert_s) 를 그대로 보여줄 수는 있어도 그 오리진에서 요청을 보낼 수는 없다.
    let pk;
    // CIA 가 죽어 pk_CIA 를 못 받은 것이지 체인 문제가 아니다 — reason 목록엔 없지만 원인을 구분해 둔다.
    try { pk = await pkCia(); } catch (e) { return res.status(503).json({ reason: 'cia_unavailable', detail: e.message }); }
    const reqOrigin = req.get('Origin');
    if (reqOrigin !== origin || !(await verifyRpCert(pk, { arid: BigInt(arid), origin, cert: cert_s }))) {
      return res.status(403).json({ reason: 'bad_rp_cert' });
    }

    const timings = { syncMs: 0, issueMs: 0, proveMs: 0 };
    let t = Date.now();
    let synced;
    try { synced = await syncRevocationTree(provider, LOG_ADDRESS); }
    catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    timings.syncMs = Date.now() - t;
    lastSync = { root: synced.root.toString(), head: synced.head.toString() };

    pruneSessions();
    t = Date.now();
    const r = await issueCredential(arid, rs);      // 로그인마다 발급(설계 §5)
    timings.issueMs = Date.now() - t;
    if (r.status === 403) return res.status(403).json({ reason: 'account_disabled', timings });
    if (r.status !== 200) return res.status(502).json({ reason: 'issue_failed', cia: r.body, timings });
    const out = await proveSession(rs.toString(), synced, timings);
    res.json({ ...out, issued: true, timings });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/** 세션의 성명으로 현재 root 에 대한 π 를 만든다(캐시). 폐기됐으면 throw('revoked'). */
async function proveSession(rsKey, synced, timings) {
  const s = state.sessions[rsKey];
  const reg = state.registration;
  const sessionWallet = new ethers.Wallet(s.sessionPrivKey);
  let cached = cache.get(synced.root, rsKey);
  const cacheHit = Boolean(cached);
  if (!cached) {
    if (synced.tree.has(await credLeaf(BigInt(s.credential.C)))) throw Object.assign(new Error('revoked'), { reason: 'revoked' });
    const t = Date.now();
    cached = await buildCredentialProof({
      uid: BigInt(reg.uid), arid: BigInt(s.arid), s_u: BigInt(reg.s_u), blind: BigInt(s.blind), pk_i: BigInt(s.pk_i),
      attrs: (reg.attrs ?? []).map(BigInt),
      credential: s.credential, pk_CIA: { x: BigInt(s.credential.pk_CIA.x), y: BigInt(s.credential.pk_CIA.y) }, tree: synced.tree,
    });
    timings.proveMs = Date.now() - t;
    cache.set(synced.root, rsKey, cached);
  }
  const sig = await signChallenge(sessionWallet, rsKey);
  return { proof: cached.proof, publicSignals: cached.publicSignals, sig, pk_i: s.pk_i, r_s: rsKey, root: synced.root.toString(), cacheHit };
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
    lastSync = { root: synced.root.toString(), head: synced.head.toString() };
    try {
      const out = await proveSession(rsKey, synced, timings);
      res.json({ ...out, timings });
    } catch (e) {
      if (e.reason === 'revoked') { delete state.sessions[rsKey]; persist(); return res.status(403).json({ reason: 'revoked', timings }); }
      throw e;
    }
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

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Mode 3 wallet agent at http://127.0.0.1:${PORT} (cia=${CIA_URL}, rp=${RP_ORIGIN}, log=${LOG_ADDRESS ?? 'none'})`);
});
