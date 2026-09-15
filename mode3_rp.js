// Mode 3 RP (:3100). 스펙: docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md §4
//
// server.js(:3000, Mode 1/2)와 나란히 두는 별도 프로세스다. 그쪽 코드를 import 하지 않는다.
// 검증(설계 §6.3 7단계)은 전부 lib/mode3_rp.js 에 있고 여기는 등록·challenge 관리 + HTTP 만이다.
// 세션은 메모리 Map(r_s → PPID·pk_i·exptime·root) 뿐이고 쿠키는 없다 — 데모의 요점은 검증 결과다(스펙 §4.2).
import 'dotenv/config';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { createRpVerifier, verifySessionRequest } from './lib/mode3_rp.js';
import { VKEY_PATH } from './lib/mode3_wallet.js';
import { readJson, writeJsonAtomic } from './lib/mode3_state.js';
import { verifyRpCert } from './lib/mode3_rp_cert.js';
import { randomScalar } from './lib/mode3_credential.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.MODE3_RP_PORT) || 3100;
const CIA_URL = process.env.MODE3_CIA_URL || 'http://127.0.0.1:4100';
const WALLET_ORIGIN = process.env.MODE3_WALLET_AGENT_ORIGIN || 'http://127.0.0.1:5100';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const CHALLENGE_TTL_MS = Number(process.env.MODE3_CHALLENGE_TTL_MS) || 120_000;

if (!LOG_ADDRESS) { console.error('[rp] CIA_LOG_ADDRESS 가 없다'); process.exit(1); }

// pk_CIA 고정(설계 §5 — 유일한 위조 방어선). env 가 있으면 그것, 없으면 기동 시 CIA 에서 한 번 받아
// 프로세스 수명 동안 고정한다(TOFU, 데모 단축). 기동 후에는 CIA 에 다시 묻지 않는다(설계 §9.9).
async function resolvePkCia() {
  const { MODE3_PK_CIA_X: x, MODE3_PK_CIA_Y: y } = process.env;
  if (x && y) return { x: BigInt(x), y: BigInt(y), source: 'env' };
  const r = await fetch(`${CIA_URL}/cia/public_keys`);
  if (!r.ok) throw new Error(`CIA ${CIA_URL} 에서 pk_CIA 를 받지 못했다 (${r.status})`);
  const k = await r.json();
  console.warn(`[rp] pk_CIA 를 CIA 에서 받아 고정한다(TOFU). 운영이라면 env 로 박는다:\n  MODE3_PK_CIA_X=${k.pk_CIA.x}\n  MODE3_PK_CIA_Y=${k.pk_CIA.y}`);
  return { x: BigInt(k.pk_CIA.x), y: BigInt(k.pk_CIA.y), source: 'tofu' };
}

const pkCIA = await resolvePkCia();

// ---- 서비스 등록(설계 2026-09-15 §3) ----
// 처음 기동에서 CIA 에 (name, origin) 으로 등록해 arid 와 cert_s 를 받아 파일에 둔다. 재기동은 파일을 쓴다.
// origin 은 이 RP 페이지가 열리는 오리진 — 지갑이 요청의 Origin 헤더와 대조한다.
const REG_FILE = process.env.MODE3_RP_REGISTRATION_FILE || path.join(__dirname, 'mode3_rp_registration.json');
const PUBLIC_ORIGIN = process.env.MODE3_RP_PUBLIC_ORIGIN || `http://127.0.0.1:${PORT}`;
const RP_NAME = process.env.MODE3_RP_NAME || 'demo-rp';
async function resolveRegistration() {
  let reg = readJson(REG_FILE, null);
  if (reg && reg.origin !== PUBLIC_ORIGIN) { console.warn(`[rp] 등록 파일의 origin(${reg.origin}) 이 현재(${PUBLIC_ORIGIN}) 와 달라 다시 등록한다`); reg = null; }
  if (!reg) {
    const r = await fetch(`${CIA_URL}/cia/register_rp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: RP_NAME, origin: PUBLIC_ORIGIN }) });
    if (!r.ok) throw new Error(`CIA 등록 실패 (${r.status})`);
    const b = await r.json();
    reg = { arid: b.arid, origin: b.origin, cert_s: b.cert_s, issuedAt: new Date().toISOString() };
    writeJsonAtomic(REG_FILE, reg, 0o600);
    console.log(`[rp] CIA 에 등록: arid=${reg.arid} origin=${reg.origin} → ${REG_FILE}`);
  }
  if (!(await verifyRpCert(pkCIA, { arid: BigInt(reg.arid), origin: reg.origin, cert: reg.cert_s }))) {
    throw new Error('등록 파일의 cert_s 가 현재 pk_CIA 로 검증되지 않는다 — CIA 키가 바뀌었으면 파일을 지우고 재기동');
  }
  return reg;
}
const registration = await resolveRegistration();
const ARID = registration.arid;

const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 });
// RP 가 읽는 폐기 체인의 id. credential 의 chainid 와 같아야 한다(설계 2026-09-14 §6 c'). 기동 시 한 번 읽어 고정한다.
const chainId = (await provider.getNetwork()).chainId;
const verifier = createRpVerifier({ provider, logAddress: LOG_ADDRESS, vkey, pkCIA, arid: BigInt(ARID), chainId });

// ---- r_s: 메모리, TTL, 로그인 때 1회 소비. 소비된 r_s 는 세션 식별자가 된다(설계 §7) ----
const challenges = new Map();   // r_s(10진) → expiresAt(ms)
const sessions = new Map();     // r_s(10진) → { PPID, pk_i, exptime, root, at }
function sweepChallenges() { const now = Date.now(); for (const [c, exp] of challenges) if (exp < now) challenges.delete(c); }
function issueChallenge() {
  sweepChallenges();
  const r_s = randomScalar().toString();
  const expiresAt = Date.now() + CHALLENGE_TTL_MS;
  challenges.set(r_s, expiresAt);
  return { r_s, expiresAt };
}
function consumeChallenge(r_s) {
  const exp = challenges.get(r_s);
  if (exp === undefined) return false;
  challenges.delete(r_s);
  return Date.now() <= exp;
}

const logins = [];   // { PPID, at, root, r_s }. 메모리만
// r_s 전문은 내지 않는다 — RP 기록이 공개되면 CIA 가 used_rs 와 맞대어 uid↔PPID 를 잇는다(설계 §2).
const rsShort = (r) => r.slice(0, 8) + '…';

// ---- 앱 ----
const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'rp.html')));

app.get('/api/mode3/rp_info', (req, res) => {
  res.json({ arid: ARID, origin: registration.origin, cert_s: registration.cert_s, logAddress: LOG_ADDRESS, walletAgentOrigin: WALLET_ORIGIN, pkCiaSource: pkCIA.source, chainId: chainId.toString() });
});
app.post('/api/mode3/challenge', (req, res) => res.json(issueChallenge()));

async function verifyBody(req, res) {
  const { proof, publicSignals, sig } = req.body ?? {};
  if (!proof || !Array.isArray(publicSignals) || typeof sig !== 'string') { res.status(400).json({ ok: false, reason: 'malformed' }); return null; }
  return verifier.verifyLogin({ proof, publicSignals, sig });
}

/** publicSignals[5](r_s, 회로가 정한 순서) 를 10진 문자열로. 형식이 깨져 있으면(길이·비수치) null. */
function rsFromSignals(publicSignals) {
  try { return Array.isArray(publicSignals) && publicSignals.length === 9 ? String(BigInt(publicSignals[5])) : null; }
  catch { return null; }
}

app.post('/api/mode3/login', async (req, res) => {
  try {
    const { publicSignals } = req.body ?? {};
    const rsStr = rsFromSignals(publicSignals);
    if (!rsStr) return res.status(400).json({ ok: false, reason: 'malformed' });
    if (!consumeChallenge(rsStr)) return res.status(401).json({ ok: false, reason: 'bad_challenge' });   // 검증 전에 소비
    const v = await verifyBody(req, res); if (v === null) return;
    if (!v.ok) return res.json({ ok: false, reason: v.reason });
    sessions.set(rsStr, { PPID: v.PPID.toString(), pk_i: v.pk_i.toString(), exptime: v.exptime.toString(), root: v.root.toString(), at: new Date().toISOString() });
    logins.push({ PPID: v.PPID.toString(), at: new Date().toISOString(), root: v.root.toString(), r_s: rsShort(rsStr) });
    res.json({ ok: true, PPID: v.PPID.toString(), pk_i: v.pk_i.toString(), r_s: rsStr, root: v.root.toString() });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

app.post('/api/mode3/revalidate', async (req, res) => {
  try {
    const { publicSignals } = req.body ?? {};
    const rsStr = rsFromSignals(publicSignals);
    if (!rsStr) return res.status(400).json({ ok: false, reason: 'malformed' });
    const s = sessions.get(rsStr);
    if (!s) return res.status(401).json({ ok: false, reason: 'no_session' });
    const v = await verifyBody(req, res); if (v === null) return;
    if (!v.ok) return res.json({ ok: false, reason: v.reason });
    if (v.PPID.toString() !== s.PPID || v.pk_i.toString() !== s.pk_i) return res.status(401).json({ ok: false, reason: 'session_mismatch' });
    s.root = v.root.toString();
    res.json({ ok: true, r_s: rsStr, root: s.root });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

app.post('/api/mode3/request', async (req, res) => {
  try {
    const { r_s, body, sig } = req.body ?? {};
    if (typeof r_s !== 'string' || typeof body !== 'string' || typeof sig !== 'string') return res.status(400).json({ ok: false, reason: 'malformed' });
    const s = sessions.get(r_s);
    if (!s) return res.status(401).json({ ok: false, reason: 'no_session' });
    if (BigInt(Math.floor(Date.now() / 1000)) > BigInt(s.exptime)) { sessions.delete(r_s); return res.status(401).json({ ok: false, reason: 'expired' }); }
    // 폐기가 효력을 갖는 지점: root 가 바뀌었으면 세션은 재검증 전까지 요청을 받지 않는다.
    const view = await verifier.refreshChainView().catch(() => null);
    if (!view) return res.status(503).json({ ok: false, reason: 'chain_unavailable' });
    if (view.root.toString() !== s.root) return res.status(401).json({ ok: false, reason: 'revalidate_required' });
    if (!verifySessionRequest({ pk_i: s.pk_i, r_s, body, sig })) return res.status(401).json({ ok: false, reason: 'bad_signature' });
    res.json({ ok: true, echo: body, PPID: s.PPID });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

app.get('/api/mode3/logins', (req, res) => res.json({ logins }));
app.get('/api/mode3/sessions', (req, res) => res.json({ sessions: [...sessions.entries()].map(([r_s, s]) => ({ r_s: rsShort(r_s), PPID: s.PPID, pk_i: s.pk_i, exptime: s.exptime, root: s.root, at: s.at })) }));

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Mode 3 RP at http://127.0.0.1:${PORT} (arid=${ARID}, origin=${registration.origin}, log=${LOG_ADDRESS}, wallet=${WALLET_ORIGIN}, pk_CIA=${pkCIA.source}, chain=${chainId})`);
});
