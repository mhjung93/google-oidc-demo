// Mode 3 RP (:3100). 스펙: docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md §4
//
// server.js(:3000, Mode 1/2)와 나란히 두는 별도 프로세스다. 그쪽 코드를 import 하지 않는다.
// 검증(설계 §6.3 7단계)은 전부 lib/mode3_rp.js 에 있고 여기는 challenge 관리 + HTTP 만이다.
// 세션·쿠키는 없다 — 데모의 요점은 검증 결과다(스펙 §4.2).
import 'dotenv/config';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { createRpVerifier } from './lib/mode3_rp.js';
import { VKEY_PATH } from './lib/mode3_wallet.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.MODE3_RP_PORT) || 3100;
const ARID = process.env.MODE3_RP_ARID || '22222222222222222222';   // e2e 와 같은 값. < 2^250
const CIA_URL = process.env.MODE3_CIA_URL || 'http://127.0.0.1:4100';
const WALLET_ORIGIN = process.env.MODE3_WALLET_AGENT_ORIGIN || 'http://127.0.0.1:5100';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const CHALLENGE_TTL_MS = Number(process.env.MODE3_CHALLENGE_TTL_MS) || 120_000;

if (!LOG_ADDRESS) { console.error('[rp] CIA_LOG_ADDRESS 가 없다'); process.exit(1); }
if (!/^[0-9]+$/.test(ARID)) { console.error('[rp] MODE3_RP_ARID 는 10진 문자열이어야 한다'); process.exit(1); }

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
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 });
// RP 가 읽는 폐기 체인의 id. credential 의 chainid 와 같아야 한다(설계 2026-09-14 §6 c'). 기동 시 한 번 읽어 고정한다.
const chainId = (await provider.getNetwork()).chainId;
const verifier = createRpVerifier({ provider, logAddress: LOG_ADDRESS, vkey, pkCIA, arid: BigInt(ARID), chainId });

// ---- challenge: 메모리, TTL, 1회용 ----
const challenges = new Map();   // challenge → expiresAt(ms)
function sweepChallenges() { const now = Date.now(); for (const [c, exp] of challenges) if (exp < now) challenges.delete(c); }
function issueChallenge() {
  sweepChallenges();
  const challenge = randomBytes(32).toString('hex');
  const expiresAt = Date.now() + CHALLENGE_TTL_MS;
  challenges.set(challenge, expiresAt);
  return { challenge, expiresAt };
}
/** 있으면 지우고(1회용) 만료 여부를 돌려준다. 검증 전에 부른다 — 실패해도 재사용 못 하게. */
function consumeChallenge(challenge) {
  const exp = challenges.get(challenge);
  if (exp === undefined) return false;
  challenges.delete(challenge);
  return Date.now() <= exp;
}

const logins = [];   // { PPID, at, root }. 메모리만

// ---- 앱 ----
const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'rp.html')));

app.get('/api/mode3/rp_info', (req, res) => {
  res.json({ arid: ARID, logAddress: LOG_ADDRESS, walletAgentOrigin: WALLET_ORIGIN, pkCiaSource: pkCIA.source, chainId: chainId.toString() });
});

app.post('/api/mode3/challenge', (req, res) => res.json(issueChallenge()));

app.post('/api/mode3/login', async (req, res) => {
  try {
    const { challenge, proof, publicSignals, sig } = req.body ?? {};
    if (typeof challenge !== 'string' || !proof || !Array.isArray(publicSignals) || typeof sig !== 'string') {
      return res.status(400).json({ ok: false, reason: 'malformed' });
    }
    if (!consumeChallenge(challenge)) return res.status(401).json({ ok: false, reason: 'bad_challenge' });
    const v = await verifier.verifyLogin({ proof, publicSignals, challenge, sig });
    if (!v.ok) return res.json({ ok: false, reason: v.reason });
    const root = String(publicSignals[5]);
    logins.push({ PPID: v.PPID.toString(), at: new Date().toISOString(), root });
    res.json({ ok: true, PPID: v.PPID.toString(), pk_i: v.pk_i.toString(), root });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

app.get('/api/mode3/logins', (req, res) => res.json({ logins }));

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Mode 3 RP at http://127.0.0.1:${PORT} (arid=${ARID}, log=${LOG_ADDRESS}, wallet=${WALLET_ORIGIN}, pk_CIA=${pkCIA.source}, chain=${chainId})`);
});
