// Mode 3 지갑 에이전트 (:5100). 스펙: docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md §3
//
// Mode 2 의 wallet_agent.js 와 나란히 두는 별도 프로세스다. 그쪽 코드를 import 하지 않는다.
// 암호학은 전부 lib/mode3_wallet.js 에 있고 여기는 상태 파일 + HTTP 만이다.
// 발급은 로그인 안에서 필요할 때(없음·만료·폐기됨) 자동으로 일어난다(스펙 §3.3, 설계 §6.2 "세션마다").
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { readJson, writeJsonAtomic } from './lib/mode3_state.js';
import { createRegistration, createSessionKey, buildIssueRequest, syncRevocationTree, buildCredentialProof, signChallenge, ProofCache } from './lib/mode3_wallet.js';
import { pointToStrings } from './lib/mode3_issuance.js';
import { credLeaf } from './lib/mode3_revocation.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.MODE3_WALLET_PORT) || 5100;
const STATE_FILE = process.env.MODE3_WALLET_STATE_FILE || path.join(__dirname, 'mode3_wallet_state.json');
const CIA_URL = process.env.MODE3_CIA_URL || 'http://127.0.0.1:4100';
const RP_ORIGIN = process.env.MODE3_RP_ORIGIN || 'http://127.0.0.1:3100';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
// 만료 여유(블록). 지갑은 동기화 때 본 head 로 판단하지만 RP 는 증명 생성(~1초)과 두 홉 뒤의 더 높은
// head 로 같은 검사를 한다 — 여유 없이 max_height 직전 credential 을 재사용하면 RP 가 'expired' 로
// 거절하고 1회용 challenge 만 소모된다. 여유 안이면 미리 새로 발급받는다.
const EXPIRY_MARGIN_BLOCKS = 3n;

// 게시 직후의 로그인이 옛 root 를 보지 않도록 ethers 의 250ms 캐시를 끈다(lib/mode3_wallet.js 주석).
const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 });

// ---- 상태 ----
// registration: { uid, s_u, r_u, cm_u:{x,y}, sk_u }            §6.1. 한 번
// credentials:  arid → { credential:{C,max_height,sigma,pk_CIA}, blind, sessionPrivKey, pk_i, issuedAt }
// BigInt 는 전부 10진 문자열. 데모용이라 비밀이 평문으로 들어간다(0600).
let state = readJson(STATE_FILE, { version: 1, registration: null, credentials: {} });
function persist() { writeJsonAtomic(STATE_FILE, state, 0o600); }

const cache = new ProofCache();   // (root, 세션 주소) → {proof, publicSignals}. 메모리만
let lastSync = null;              // { root, head }
let lastProof = null;             // skipSync 재제출용: { arid, sessionPrivKey, pk_i, root, proof, publicSignals }

const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const json = async (r) => ({ status: r.status, body: await r.json().catch(() => null) });
const ciaPost = (p, body) => fetch(`${CIA_URL}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(json);

async function issueCredential(arid, height) {
  const reg = state.registration;
  const session = createSessionKey();
  const req = await buildIssueRequest({
    uid: BigInt(reg.uid), arid: BigInt(arid), s_u: BigInt(reg.s_u), r_u: BigInt(reg.r_u), sk_u: reg.sk_u, session, height,
  });
  const r = await ciaPost('/cia/issue', req.body);
  if (r.status === 200) {
    state.credentials[arid] = {
      credential: r.body, blind: req.secrets.blind.toString(),
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

// RP 페이지(다른 오리진)가 부르는 것은 /wallet/login 뿐이다. 문자열 origin 은 cors 가 요청 Origin 과
// 무관하게 헤더를 붙이므로, 일치할 때만 붙이도록 함수형으로 둔다.
const loginCors = cors({ origin: (origin, cb) => cb(null, origin === RP_ORIGIN), methods: ['POST'] });
app.options('/wallet/login', loginCors);

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'wallet.html')));

app.get('/wallet/status', async (req, res) => {
  let head = null;
  try { head = (await provider.getBlockNumber()).toString(); } catch { /* 체인 없음 */ }
  const credentials = {};
  for (const [arid, e] of Object.entries(state.credentials)) {
    credentials[arid] = { max_height: e.credential.max_height, sessionAddress: new ethers.Wallet(e.sessionPrivKey).address, issuedAt: e.issuedAt };
  }
  res.json({
    registered: Boolean(state.registration), uid: state.registration?.uid ?? null, credentials,
    head, lastRoot: lastSync?.root ?? null, cachedProofRoot: lastProof ? lastProof.root.toString() : null, logAddress: LOG_ADDRESS,
  });
});

app.post('/wallet/register', async (req, res) => {
  try {
    const { uid, pwd } = req.body ?? {};
    if (!isDec(uid) || typeof pwd !== 'string') return res.status(400).json({ error: 'uid(10진 문자열), pwd 필요' });
    if (state.registration) return res.status(409).json({ reason: 'already_registered', uid: state.registration.uid });
    const reg = await createRegistration();
    const r = await ciaPost('/cia/register', { uid, pwd, cm_u: pointToStrings(reg.cm_u) });
    if (r.status !== 201) {
      const status = r.status === 401 || r.status === 409 ? r.status : 502;
      return res.status(status).json({ reason: 'register_failed', cia: r.body });
    }
    state.registration = { uid, s_u: reg.s_u.toString(), r_u: reg.r_u.toString(), cm_u: pointToStrings(reg.cm_u), sk_u: r.body.sk_u };
    persist();
    res.status(201).json({ uid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/wallet/login', loginCors, async (req, res) => {
  try {
    const { arid, challenge, skipSync } = req.body ?? {};
    if (!isDec(arid) || typeof challenge !== 'string' || challenge.length === 0) return res.status(400).json({ error: 'arid(10진 문자열), challenge 필요' });
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    if (!LOG_ADDRESS) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });

    // 시연용: 동기화·발급을 건너뛰고 마지막 π 를 그대로 재제출한다(RP 의 stale_root 거절을 보이기 위해).
    if (skipSync) {
      if (!lastProof || lastProof.arid !== arid) return res.status(409).json({ reason: 'no_cached_proof' });
      const sig = await signChallenge(new ethers.Wallet(lastProof.sessionPrivKey), challenge);
      return res.json({ proof: lastProof.proof, publicSignals: lastProof.publicSignals, sig, pk_i: lastProof.pk_i, root: lastProof.root.toString(), issued: false, cacheHit: true, timings: { syncMs: 0, issueMs: 0, proveMs: 0 } });
    }

    const timings = { syncMs: 0, issueMs: 0, proveMs: 0 };
    let t = Date.now();
    let synced;
    try { synced = await syncRevocationTree(provider, LOG_ADDRESS); }
    catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    timings.syncMs = Date.now() - t;
    lastSync = { root: synced.root.toString(), head: synced.head.toString() };

    // 없거나, 만료됐거나(여유 포함), 폐기 트리에 있으면 새로 발급받는다.
    let entry = state.credentials[arid];
    let issued = false;
    const needIssue = !entry
      || synced.head + EXPIRY_MARGIN_BLOCKS > BigInt(entry.credential.max_height)
      || synced.tree.has(await credLeaf(BigInt(entry.credential.C)));
    if (needIssue) {
      t = Date.now();
      let r = await issueCredential(arid, synced.head);
      if (r.status === 400 && /stale issue request/.test(r.body?.error ?? '')) {
        // 동기화 때 본 head 가 CIA 의 창(30블록) 밖이다 — 증명 생성이 그만큼 오래 걸렸다. head 를 다시
        // 읽어 한 번만 다시 낸다.
        r = await issueCredential(arid, BigInt(await provider.getBlockNumber()));
      }
      timings.issueMs = Date.now() - t;
      if (r.status === 403) return res.status(403).json({ reason: 'account_disabled', timings });
      if (r.status !== 200) return res.status(502).json({ reason: 'issue_failed', cia: r.body, timings });
      entry = state.credentials[arid];
      issued = true;
    }

    const reg = state.registration;
    const sessionWallet = new ethers.Wallet(entry.sessionPrivKey);
    let cached = cache.get(synced.root, sessionWallet.address);
    const cacheHit = Boolean(cached);
    if (!cached) {
      t = Date.now();
      cached = await buildCredentialProof({
        uid: BigInt(reg.uid), arid: BigInt(arid), s_u: BigInt(reg.s_u), blind: BigInt(entry.blind), pk_i: BigInt(entry.pk_i),
        credential: entry.credential, pk_CIA: { x: BigInt(entry.credential.pk_CIA.x), y: BigInt(entry.credential.pk_CIA.y) }, tree: synced.tree,
      });
      timings.proveMs = Date.now() - t;
      cache.set(synced.root, sessionWallet.address, cached);
    }
    lastProof = { arid, sessionPrivKey: entry.sessionPrivKey, pk_i: entry.pk_i, root: synced.root, proof: cached.proof, publicSignals: cached.publicSignals };
    const sig = await signChallenge(sessionWallet, challenge);
    res.json({ proof: cached.proof, publicSignals: cached.publicSignals, sig, pk_i: entry.pk_i, root: synced.root.toString(), issued, cacheHit, timings });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Mode 3 wallet agent at http://127.0.0.1:${PORT} (cia=${CIA_URL}, rp=${RP_ORIGIN}, log=${LOG_ADDRESS ?? 'none'})`);
});
