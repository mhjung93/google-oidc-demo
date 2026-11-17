// Mode 3 사용자 정적 서버(:5100, web 모드 — 설계 2026-10-15 D3, 계획 R1·R4·R11). 에이전트(mode3_wallet_agent.js) 대신 같은 포트에 띄운다.
// 비밀·세션을 받지 않는다. 내는 것: 앱(mode3/user)·공통 레이어·zk 산출물·공개 설정, 그리고 사용자 페이지가 알려 준 존재 신호(health).
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { listenMaybeTls } from './lib/mode3_tls.js';
import { checkRpcBody } from './lib/mode3_rpc_proxy.js';
import { buildWalletHealth, applyHealthHeaders, bounded, originList, allowOrigin } from './lib/mode3_health.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.MODE3_WALLET_PORT) || 5100;
const WALLET_ORIGIN = process.env.MODE3_WALLET_PUBLIC_ORIGIN || `http://127.0.0.1:${PORT}`;
const CIA_URL = process.env.MODE3_CIA_URL || 'http://127.0.0.1:4100';
const RP_ORIGINS = originList((process.env.MODE3_RP_ORIGIN || 'http://127.0.0.1:3100').split(',').map((s) => s.trim()));
if (RP_ORIGINS.length === 0) throw new Error('MODE3_RP_ORIGIN 에 유효한 origin 이 하나도 없다');
// 비밀 모드: web(기본) 또는 passkey-web(패스키 PRF 로 시드를 만드는 설치 없는 경로). passkey-web 은 WebAuthn 이 요구하는 보안 컨텍스트가 필요하다.
const SECRETS = process.env.MODE3_WALLET_SECRETS || 'web';
if (!['web', 'passkey-web'].includes(SECRETS)) { console.error(`MODE3_WALLET_SECRETS 는 web 또는 passkey-web 이어야 한다(받은 값: ${SECRETS})`); process.exit(1); }
if (SECRETS === 'passkey-web') {
  let u; try { u = new URL(WALLET_ORIGIN); } catch { console.error('passkey-web: MODE3_WALLET_PUBLIC_ORIGIN 이 URL 이 아니다'); process.exit(1); }
  const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(u.hostname) || u.hostname.includes(':');
  if (isIp || (u.protocol !== 'https:' && u.hostname !== 'localhost')) { console.error(`passkey-web: 오리진은 IP 가 아닌 호스트여야 하고 https 이거나 localhost 여야 한다(WebAuthn RP ID 제약) — ${WALLET_ORIGIN}`); process.exit(1); }
}
const HOLD_RAW = process.env.MODE3_PASSKEY_HOLD_SECONDS;
const PASSKEY_HOLD_SECONDS = HOLD_RAW === undefined || HOLD_RAW === '' ? 600 : Number(HOLD_RAW);
if (!Number.isFinite(PASSKEY_HOLD_SECONDS) || PASSKEY_HOLD_SECONDS < 0) { console.error(`MODE3_PASSKEY_HOLD_SECONDS 는 0 이상 숫자여야 한다(받은 값: ${HOLD_RAW})`); process.exit(1); }
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const REV_RPC = process.env.MODE3_REV_CHAIN_RPC || RPC_URL;
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const MIRROR_ADDRESS = process.env.MODE3_MIRROR_ADDRESS || null;
const envBig = (k, d) => { const v = process.env[k]; return v === undefined || v === '' ? String(d) : String(BigInt(v)); };
const TTL_BLOCKS = envBig('MODE3_TTL_BLOCKS', 300), HEIGHT_GRID = envBig('MODE3_HEIGHT_GRID', 100);
const PK_CIA = process.env.MODE3_PK_CIA_X && process.env.MODE3_PK_CIA_Y ? { x: process.env.MODE3_PK_CIA_X, y: process.env.MODE3_PK_CIA_Y } : null;
const RELAY_PATH = process.env.MODE3_RELAY_PATH || '/api/mode3/relay';
// 데모 세대(2026-10-21): 리셋 스크립트가 올리는 값. 사용자 페이지는 기억한 값과 다르면 이 브라우저의 옛 등록·세션을 스스로 지운다 — **데모 전용**(없으면 아무 일도 없다).
const DEMO_GENERATION = process.env.MODE3_DEMO_GENERATION || null;
const DIST = path.join(__dirname, 'mode3', 'user', 'dist');
if (!fs.existsSync(path.join(DIST, 'user.js'))) { console.error('mode3/user/dist/user.js 가 없다 — npm run user:build 먼저'); process.exit(1); }
const ZK = {
  'pi_cred.wasm': 'build/mode3/pi_cred_js/pi_cred.wasm', 'pi_cred_final.zkey': 'build/mode3/pi_cred_final.zkey', 'pi_cred_vkey.json': 'build/mode3/pi_cred_vkey.json',
  'pi_idp.wasm': 'build/mode3/pi_idp_js/pi_idp.wasm', 'pi_idp_final.zkey': 'build/mode3/pi_idp_final.zkey', 'pi_idp_vkey.json': 'build/mode3/pi_idp_vkey.json',
};
const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 });
// chainId 는 기동 때 await 로 한 번 받는다(컨트롤러 결정) — 떠다니는 promise 로 두면 /user/config·/wallet/config 가
// 기동 직후 들어온 요청에서 null 과 실제 값 사이를 오가며 경합한다.
let chainId = null;
try { chainId = (await provider.getNetwork()).chainId.toString(); } catch { chainId = null; }

// 존재 신호(계획 R4): 사용자 페이지가 같은 오리진에서 알려 주는 불리언·정수 6개. 재시작하면 초깃값.
const PRESENCE_KEYS = ['registered', 'hasCred', 'sessions', 'rpCount', 'txs', 'disclosedTxs'];
let presence = { registered: false, hasCred: false, sessions: 0, rpCount: 0, txs: 0, disclosedTxs: 0 };
function validPresence(b) {
  if (!b || typeof b !== 'object' || Array.isArray(b)) return false;
  if (Object.keys(b).some((k) => !PRESENCE_KEYS.includes(k)) || PRESENCE_KEYS.some((k) => !(k in b))) return false;
  return typeof b.registered === 'boolean' && typeof b.hasCred === 'boolean' && ['sessions', 'rpCount', 'txs', 'disclosedTxs'].every((k) => Number.isInteger(b[k]) && b[k] >= 0);
}
let ciaSeenAt = 0, pinging = null; const CIA_FRESH_MS = 10_000;
function pingCia() { if (!pinging) pinging = (async () => { const c = new AbortController(); const tm = setTimeout(() => c.abort(), 1500); try { if ((await fetch(`${CIA_URL}/cia/public_keys`, { signal: c.signal })).ok) ciaSeenAt = Date.now(); } catch { /* */ } finally { clearTimeout(tm); pinging = null; } })(); return pinging; }

const app = express();
// 같은 오리진 RPC 프록시(passkey-web 이 CORS 없이 체인을 읽게 한다): 허용 목록 읽기 메서드만 통과. ethers 배치가 16kb 를 넘으므로 전역 파서보다 앞에서 1mb 로 받는다.
function rpcProxy(target) {
  return async (req, res) => {
    const chk = checkRpcBody(req.body);
    if (!chk.ok) return res.status(chk.status).json(chk.method ? { reason: chk.reason, method: chk.method } : { reason: chk.reason });
    try {
      const up = await fetch(target, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(req.body), signal: AbortSignal.timeout(3000) });
      res.status(up.status).type(up.headers.get('content-type') || 'application/json').send(await up.text());
    } catch { res.status(502).json({ reason: 'chain_unavailable' }); }
  };
}
app.post('/rpc/app', express.json({ limit: '1mb' }), rpcProxy(RPC_URL));
app.post('/rpc/rev', express.json({ limit: '1mb' }), rpcProxy(REV_RPC));
app.all(['/rpc/app', '/rpc/rev'], (req, res) => res.status(405).set('Allow', 'POST').json({ reason: 'method_not_allowed' }));
app.use(express.json({ limit: '16kb' }));
const configCors = cors({ origin: (origin, cb) => cb(null, allowOrigin(origin, RP_ORIGINS)), methods: ['GET'] });
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'user', 'index.html')));
app.use('/dist', express.static(DIST));
app.use('/common', express.static(path.join(__dirname, 'mode3', 'common')));
// 속성 커밋먼트 도구 — 에이전트(mode3_wallet_agent.js)와 같은 경로. 이 서버의 어떤 API 도 부르지 않는 독립 정적 페이지.
app.get('/attr.html', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'attr.html')));
app.use('/attr', express.static(path.join(__dirname, 'mode3', 'attr'), { index: false }));
app.get('/zk/:name', (req, res) => {
  const rel = ZK[req.params.name];
  if (!rel) return res.status(404).json({ reason: 'not_found' });
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  res.sendFile(path.join(__dirname, rel), (err) => { if (err && !res.headersSent) res.status(err.statusCode === 404 ? 404 : 500).json({ reason: err.statusCode === 404 ? 'zk_assets_unavailable' : 'internal' }); });
});
app.get('/user/config', (req, res) => res.json({ secrets: SECRETS, passkeyHoldSeconds: PASSKEY_HOLD_SECONDS, walletOrigin: WALLET_ORIGIN, ciaUrl: CIA_URL, rpcUrl: SECRETS === 'passkey-web' ? '/rpc/app' : RPC_URL, revRpcUrl: SECRETS === 'passkey-web' ? '/rpc/rev' : REV_RPC, chainId, logAddress: LOG_ADDRESS, mirrorAddress: MIRROR_ADDRESS, ttlBlocks: TTL_BLOCKS, heightGrid: HEIGHT_GRID, rpOrigins: RP_ORIGINS, pkCia: PK_CIA, relayPath: RELAY_PATH, demoGeneration: DEMO_GENERATION }));
app.get('/wallet/config', configCors, (req, res) => res.json({ secrets: SECRETS, snapId: null, walletOrigin: WALLET_ORIGIN, rpcUrl: RPC_URL, chainId }));
const HEALTH_ALLOW = originList(RP_ORIGINS, CIA_URL);
app.get('/mode3/health', async (req, res) => {
  applyHealthHeaders(req, res, HEALTH_ALLOW);
  if (Date.now() - ciaSeenAt > CIA_FRESH_MS) pingCia();
  let chain = null;
  try { const head = await bounded(provider.getBlockNumber(), 1200); chain = { id: chainId ?? '', head: head.toString() }; } catch { /* 체인 없음 */ }
  res.json(buildWalletHealth({ now: new Date().toISOString(), chain, secrets: SECRETS, ...presence, ciaReachable: Date.now() - ciaSeenAt <= CIA_FRESH_MS, rpOrigin: RP_ORIGINS[0], rpOrigins: RP_ORIGINS, ciaUrl: CIA_URL }));
});
app.post('/wallet/presence', (req, res) => {
  if (!validPresence(req.body)) return res.status(400).json({ reason: 'malformed' });
  presence = { ...req.body };
  res.json({ ok: true });
});
// 라우트 밖으로 샌 오류의 마지막 그물(에이전트·RP 와 같은 패턴): JSON 파싱 실패 400 malformed, 그 밖 500 internal — stack 은 서버 로그에만 남긴다.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ reason: 'malformed' });
  console.error(`[user-static] 처리되지 않은 라우트 오류 ${req.method} ${req.path}: ${err?.stack ?? err}`);
  res.status(500).json({ reason: 'internal' });
});
process.on('unhandledRejection', (e) => console.error(`[user-static] unhandledRejection: ${e?.stack ?? e}`));
listenMaybeTls(app, { port: PORT, host: '127.0.0.1', onListening: (scheme) => console.log(`Mode 3 user static at ${scheme}://127.0.0.1:${PORT} (cia=${CIA_URL}, rp=${RP_ORIGINS.join(',')}, log=${LOG_ADDRESS ?? 'none'}, mirror=${MIRROR_ADDRESS ?? 'none'})`) });
