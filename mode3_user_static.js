// Mode 3 사용자 정적 서버(:5100, web 모드 — 설계 2026-10-15 D3, 계획 R1·R4·R11). 에이전트(mode3_wallet_agent.js) 대신 같은 포트에 띄운다.
// 비밀·세션을 받지 않는다. 내는 것: 앱(mode3/user)·공통 레이어·zk 산출물·공개 설정, 그리고 사용자 페이지가 알려 준 존재 신호(health).
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { buildWalletHealth, applyHealthHeaders, bounded, originList, allowOrigin } from './lib/mode3_health.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.MODE3_WALLET_PORT) || 5100;
const WALLET_ORIGIN = process.env.MODE3_WALLET_PUBLIC_ORIGIN || `http://127.0.0.1:${PORT}`;
const CIA_URL = process.env.MODE3_CIA_URL || 'http://127.0.0.1:4100';
const RP_ORIGINS = originList((process.env.MODE3_RP_ORIGIN || 'http://127.0.0.1:3100').split(',').map((s) => s.trim()));
if (RP_ORIGINS.length === 0) throw new Error('MODE3_RP_ORIGIN 에 유효한 origin 이 하나도 없다');
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const REV_RPC = process.env.MODE3_REV_CHAIN_RPC || RPC_URL;
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const MIRROR_ADDRESS = process.env.MODE3_MIRROR_ADDRESS || null;
const envBig = (k, d) => { const v = process.env[k]; return v === undefined || v === '' ? String(d) : String(BigInt(v)); };
const TTL_BLOCKS = envBig('MODE3_TTL_BLOCKS', 300), HEIGHT_GRID = envBig('MODE3_HEIGHT_GRID', 100);
const PK_CIA = process.env.MODE3_PK_CIA_X && process.env.MODE3_PK_CIA_Y ? { x: process.env.MODE3_PK_CIA_X, y: process.env.MODE3_PK_CIA_Y } : null;
const RELAY_PATH = process.env.MODE3_RELAY_PATH || '/api/mode3/relay';
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
app.use(express.json({ limit: '16kb' }));
const configCors = cors({ origin: (origin, cb) => cb(null, allowOrigin(origin, RP_ORIGINS)), methods: ['GET'] });
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'user', 'index.html')));
app.use('/dist', express.static(DIST));
app.use('/common', express.static(path.join(__dirname, 'mode3', 'common')));
app.get('/zk/:name', (req, res) => {
  const rel = ZK[req.params.name];
  if (!rel) return res.status(404).json({ reason: 'not_found' });
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  res.sendFile(path.join(__dirname, rel), (err) => { if (err && !res.headersSent) res.status(err.statusCode === 404 ? 404 : 500).json({ reason: err.statusCode === 404 ? 'zk_assets_unavailable' : 'internal' }); });
});
app.get('/user/config', (req, res) => res.json({ secrets: 'web', walletOrigin: WALLET_ORIGIN, ciaUrl: CIA_URL, rpcUrl: RPC_URL, revRpcUrl: REV_RPC, chainId, logAddress: LOG_ADDRESS, mirrorAddress: MIRROR_ADDRESS, ttlBlocks: TTL_BLOCKS, heightGrid: HEIGHT_GRID, rpOrigins: RP_ORIGINS, pkCia: PK_CIA, relayPath: RELAY_PATH }));
app.get('/wallet/config', configCors, (req, res) => res.json({ secrets: 'web', snapId: null, walletOrigin: WALLET_ORIGIN, rpcUrl: RPC_URL, chainId }));
const HEALTH_ALLOW = originList(RP_ORIGINS, CIA_URL);
app.get('/mode3/health', async (req, res) => {
  applyHealthHeaders(req, res, HEALTH_ALLOW);
  if (Date.now() - ciaSeenAt > CIA_FRESH_MS) pingCia();
  let chain = null;
  try { const head = await bounded(provider.getBlockNumber(), 1200); chain = { id: chainId ?? '', head: head.toString() }; } catch { /* 체인 없음 */ }
  res.json(buildWalletHealth({ now: new Date().toISOString(), chain, secrets: 'web', ...presence, ciaReachable: Date.now() - ciaSeenAt <= CIA_FRESH_MS, rpOrigin: RP_ORIGINS[0], rpOrigins: RP_ORIGINS, ciaUrl: CIA_URL }));
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
app.listen(PORT, '127.0.0.1', () => console.log(`Mode 3 user static at http://127.0.0.1:${PORT} (cia=${CIA_URL}, rp=${RP_ORIGINS.join(',')}, log=${LOG_ADDRESS ?? 'none'}, mirror=${MIRROR_ADDRESS ?? 'none'})`));
