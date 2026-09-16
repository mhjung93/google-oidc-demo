// Mode 3 CIA (Credential Issuing Authority).
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §3, §6
//
// Mode 2 의 custom_idp.js 와 나란히 두는 별도 서버다(:4100). 그쪽 코드를 import 하지 않는다.
// 하는 일 넷: 등록(§6.1), 발급(§6.2), 폐기(§6.5), root 게시(§6.5). 로그인 검증은 하지 않는다 —
// 그것은 RP 의 일이고(§6.3) CIA 는 조회 경로에 있어서는 안 된다(§9.9).
import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { readJson, writeJsonAtomic } from './lib/mode3_state.js';
import { credMessage, compressPoint, SCALAR_MAX, randomScalar } from './lib/mode3_credential.js';
import { credLeaf, createRevocationTree } from './lib/mode3_revocation.js';
import { verifyIssuance, isValidPoint, pointFromStrings, parseProof, issueRequestMessage } from './lib/mode3_issuance.js';
import { LOG_ABI, rootToBytes32, signRootPublication } from './lib/mode3_log.js';
import { signRpCert } from './lib/mode3_rp_cert.js';
import { isTracePoint, createShare, combinePublicKey, partialDecrypt, combineDecrypt } from './lib/mode3_trace.js';
import { openRequestMessage, openResultMessage, recoverSigner, isFreshTs } from './lib/mode3_opening.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.CIA_PORT) || 4100;
const STATE_FILE = process.env.CIA_STATE_FILE || path.join(__dirname, 'cia_state.json');
const KEYS_FILE = process.env.CIA_KEYS_FILE || path.join(__dirname, 'cia_keys.json');
const VKEY_PATH = process.env.MODE3_VKEY_PATH || path.join(__dirname, 'build', 'mode3', 'pi_cred_vkey.json');
const ADMIN_SECRET = process.env.CIA_ADMIN_SECRET;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const TTL_SECONDS = Number(process.env.CIA_TTL_SECONDS) || 3600;   // exptime = now + TTL (Unix 초). 옛 300블록×12초에 상응
if (!(TTL_SECONDS > 0)) throw new Error(`CIA_TTL_SECONDS(${process.env.CIA_TTL_SECONDS}) 는 양수여야 한다`);
// 발급 기록을 만료 뒤에도 이만큼(초) 더 들고 있다가 걷어낸다. RP 시계가 CIA 보다 뒤처지면 RP 는 만료된
// credential 을 그 차이만큼 더 받아들이는데, 그때 CIA 가 기록을 이미 버렸으면 계정 폐기가 그 리프를 넣지
// 못한다(설계 2026-09-14 §8.3). 여유만큼 늦게 버리면 폐기 대상이 어떤 RP 가 받아들일 집합의 상위집합이 된다 —
// 트리는 append-only 라 여분 리프는 무해하다.
const REVOKE_SKEW_SECONDS = Number(process.env.CIA_REVOKE_SKEW_SECONDS ?? 300);
if (!(REVOKE_SKEW_SECONDS >= 0)) throw new Error(`CIA_REVOKE_SKEW_SECONDS(${process.env.CIA_REVOKE_SKEW_SECONDS}) 는 0 이상이어야 한다`);
// 발급을 허용하는 폐기 체인 id 목록(쉼표 구분). 미설정이면 기동 시 RPC 의 chainId 하나. 사용자가 요청에 넣은
// chainid 가 이 목록에 없으면 400 — 다른 체인 기준 credential 을 이 CIA 가 서명하지 않는다(설계 2026-09-14 §4).
// BigInt(s) 가 실패하면(숫자가 아니면) 기동 시 거부 — 허용 목록에 비교 불가능한 값이 섞이는 것보다 낫다.
let CHAIN_IDS = (process.env.CIA_CHAIN_IDS || '').split(',').map((s) => s.trim()).filter(Boolean).map((s) => {
  try { return BigInt(s).toString(); }
  catch { throw new Error(`CIA_CHAIN_IDS 의 값 "${s}" 은 정수가 아니다`); }
});

// 데모 계정. Mode 2 의 testuser 관례를 따른 프로토타입이다 — 실제 계정 체계가 아니다.
const DEMO_ACCOUNTS = {
  testuser: { password: 'password123', uid: '12345' },
  alice: { password: 'alicepw', uid: '67890' },
};

// ---- 키 ----
// EdDSA-Poseidon(credential 서명)과 secp256k1(root 게시) 둘. 파일은 0600.
let eddsa, poseidon, F;
let ciaPrv;        // Buffer 32 — signPoseidon 이 요구하는 형식
let ciaPub;        // [Ax, Ay]
let ethWallet;     // ethers.Wallet

function loadOrCreateKeys() {
  let keys = readJson(KEYS_FILE, null);
  if (!keys) {
    keys = { eddsaPrv: randomBytes(32).toString('hex'), ethPrv: ethers.Wallet.createRandom().privateKey };
    writeJsonAtomic(KEYS_FILE, keys, 0o600);
  }
  ciaPrv = Buffer.from(keys.eddsaPrv, 'hex');
  ciaPub = eddsa.prv2pub(ciaPrv);
  const ethPrv = process.env.CIA_ETH_PRIVATE_KEY || keys.ethPrv;   // 테스트는 배포한 로그와 맞는 키를 주입한다
  // ethers 의 250ms eth_blockNumber 캐시를 끈다(RP·지갑과 같이). /cia/state 가 항상 최신 head 를 보여주게
  // 하고, race 테스트의 eth_blockNumber 게이트가 결정적으로 걸리게(캐시가 있으면 chainAlive() 의 조회가
  // 캐시에 합류해 게이트를 건너뛸 수 있다) 하는 데만 쓰인다 — 발급 경로는 더 이상 head 값 자체를 보지 않는다.
  ethWallet = new ethers.Wallet(ethPrv, new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 }));
}

// ---- 상태 ----
// accounts:  uid → { pk_u:{x,y}, cm_u:{x,y}, disabled }
// issued:    uid → [ { leaf(10진), C(10진), exptime(10진 Unix 초) } ]
// rps:       arid → { name, origin, pk_service(체크섬 주소)|null, X_svc:{x,y}|null, x_AA|null, pk_trace:{x,y}|null,
//                     status: pending|approved|denied, requestedAt, decidedAt|null }   서비스 등록(2026-09-16 §3)
//            x_AA 는 CIA 조각 — 밖으로 나가지 않는다. 잃으면 그 서비스의 과거 태그는 영원히 열 수 없다(§8 4번)
// openings:  [ { id, arid, r_s, PPID, c1:{x,y}, c2, D_svc:{x,y}, status: pending|approved|denied|failed, requestedAt,
//                decidedAt|null, uid? } ]   영구 감사 기록(§6). uid 는 approved 에만
// revoked / pending / epoch
// version 4 (2026-09-16): used_rs 삭제(CIA 는 로그인당 기록이 없다 — §4.4), rps 에 키·상태, openings 추가.
// v3 는 마이그레이션한다(사용자 쪽 서명 형식이 안 바뀌었다). v2 이하는 옛 서명 형식이라 읽지 않는다.
const STATE_VERSION = 4;
let state;
let tree;            // 전체 폐기 트리(게시 여부 무관) — 서명해 올리는 root 의 출처
let publishedTree;   // 온체인에 이벤트로 나간 리프만 — 게시 직전 온체인 root 와 대조하는 기준
function defaultState() { return { version: STATE_VERSION, accounts: {}, issued: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 }; }
function persist() { writeJsonAtomic(STATE_FILE, state, 0o600); }

// pending 은 revoked 의 접미사다 — /cia/revoke 가 둘 다에 push 하고 /cia/publish 가 pending 의
// 앞부분만 지운다. 따라서 "게시된 리프" = revoked 의 앞 (revoked.length - pending.length) 개.
async function buildPublishedTree() {
  const t = await createRevocationTree();
  const published = state.revoked.length - state.pending.length;
  for (const l of state.revoked.slice(0, published)) await t.insert(BigInt(l));
  return t;
}
async function readChain() {
  const log = new ethers.Contract(LOG_ADDRESS, LOG_ABI, ethWallet);
  const [root, epoch] = await Promise.all([log.root(), log.epoch()]);
  return { onchainRoot: BigInt(root), onchainEpoch: Number(epoch) };
}
// 로컬 게시 기록을 온체인 (root, epoch) 과 대조한다. 어긋난 채로 게시하면 서명 root 와 지갑이
// 이벤트로 재구성한 root 가 달라져 전원이 fail-closed 되고, 로그 재배포 말고는 복구가 없다.
//   - 게시 tx 는 성공했는데 persist() 전에 죽은 경우: 그 tx 에 실렸던 pending 앞부분이 이미
//     체인에 있다. publishedTree 에 pending 을 하나씩 더해 가며 온체인 root 와 같아지는 지점을
//     찾고, 그 앞부분은 pending 에서 걷어낸다(다시 올리면 리프 이벤트가 중복될 뿐 무해하지만,
//     걷어내는 쪽이 정확하다). epoch 도 컨트랙트를 진실로 삼아 따라잡는다.
//   - 어느 접두사도 맞지 않으면 false(로그 재배포, 상태 파일 유실·옛 백업 복원). 이때
//     publishedTree 는 걷다 만 상태라 호출자가 다시 만들거나 종료해야 한다.
// 기동 시와 게시 직전 둘 다 이 함수를 쓴다 — 기동 때 RPC 가 죽어 대조를 건너뛰었거나 CIA 가 켜진
// 채로 로그가 재배포된 경우를 게시 직전 대조가 잡는다(2026-09-12 리뷰 반영).
async function reconcileWithChain({ onchainRoot, onchainEpoch }) {
  let k = 0;
  while (publishedTree.getRoot() !== onchainRoot && k < state.pending.length) { await publishedTree.insert(BigInt(state.pending[k])); k++; }
  if (publishedTree.getRoot() !== onchainRoot) return false;
  let changed = false;
  if (k > 0) {
    console.warn(`[cia] 크래시 복구: pending ${k}개는 이미 체인에 게시돼 있어 걷어낸다`);
    state.pending = state.pending.slice(k);
    changed = true;
  }
  if (onchainEpoch > state.epoch) {
    console.warn(`[cia] 상태 파일 epoch(${state.epoch})가 체인 epoch(${onchainEpoch})보다 뒤처져 있어 맞춘다`);
    state.epoch = onchainEpoch;
    changed = true;
  }
  if (changed) persist();
  return true;
}

async function loadState() {
  state = readJson(STATE_FILE, defaultState());
  if (state.version === 3) {
    console.warn('[cia] 상태 파일 v3 → v4 마이그레이션: used_rs 버림, 기존 서비스 등록은 approved(조각 없음)로 둔다');
    delete state.used_rs;
    for (const e of Object.values(state.rps ?? {})) {
      e.pk_service ??= null; e.X_svc ??= null; e.x_AA ??= null; e.pk_trace ??= null;
      e.status ??= 'approved'; e.requestedAt ??= e.at ?? new Date().toISOString(); e.decidedAt ??= e.requestedAt;
    }
    state.openings ??= [];
    state.version = STATE_VERSION;
    persist();
  }
  if (state.version !== STATE_VERSION) {
    console.error(`[cia] 기동 거부: 상태 파일 버전 ${state.version} (기대 ${STATE_VERSION}). v2 이하는 옛 credential 형식이라 ` +
      `새 회로에서 검증되지 않으므로 마이그레이션하지 않는다 — 재시연 세트(로그 재배포 → 상태 파일 삭제)로 새로 시작할 것.`);
    process.exit(1);
  }
  state.rps ??= {}; state.openings ??= [];
  publishedTree = await buildPublishedTree();
  // 기동 시 대조. RPC 가 아직 안 떠 있으면 대조 없이 기동한다 — 발급은 chainAlive() 가 503 을 내거나
  // (CIA_CHAIN_IDS 도 없어 허용 목록이 비어 있으면) chainid 허용 목록 검사에서 503 을 내고,
  // 게시는 게시 직전 대조에서 다시 확인된다.
  if (LOG_ADDRESS) {
    let chain = null;
    try { chain = await readChain(); }
    catch (e) { console.warn(`[cia] 기동 시 체인 확인 실패, root 대조 없이 계속 진행: ${e.message}`); }
    if (chain && !(await reconcileWithChain(chain))) {
      console.error(`[cia] 기동 거부: 로컬 폐기 트리와 온체인 root 불일치 (로그 ${LOG_ADDRESS}, 온체인 epoch ${chain.onchainEpoch}, ` +
        `로컬 revoked ${state.revoked.length}개 / pending ${state.pending.length}개). 로그를 재배포했거나 상태 파일이 ` +
        `유실·복원됐다. 이대로 게시하면 지갑의 이벤트 재구성이 전부 실패한다 — CIA_STATE_FILE 과 CIA_LOG_ADDRESS 를 확인할 것.`);
      process.exit(1);
    }
  }
  tree = await createRevocationTree();
  for (const l of state.revoked) await tree.insert(BigInt(l));
  if (CHAIN_IDS.length === 0) {
    try { CHAIN_IDS = [(await ethWallet.provider.getNetwork()).chainId.toString()]; }
    catch (e) { console.warn(`[cia] 기동 시 chainId 를 읽지 못했다 — CIA_CHAIN_IDS 가 없으면 발급은 503: ${e.message}`); }
  }
}

// ---- 유틸 ----
const S = (o) => ({ x: F.toObject(o[0]).toString(), y: F.toObject(o[1]).toString() });
const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const isPt = (p) => p && isDec(p.x) && isDec(p.y);
function secretMatches(a, b) {
  const A = Buffer.from(a), B = Buffer.from(b);
  return A.length === B.length && timingSafeEqual(A, B);
}
function requireAdmin(req, res, next) {
  if (!ADMIN_SECRET) return res.status(503).json({ error: 'admin endpoints disabled: CIA_ADMIN_SECRET is not configured' });
  const p = req.get('X-CIA-Admin-Secret');
  if (typeof p !== 'string' || !secretMatches(p, ADMIN_SECRET)) return res.status(401).json({ error: 'unauthorized' });
  next();
}
async function headHeight() {
  if (!LOG_ADDRESS) throw Object.assign(new Error('CIA_LOG_ADDRESS not configured'), { status: 503 });
  try {
    return BigInt(await ethWallet.provider.getBlockNumber());
  } catch {
    // RPC 가 안 뜬 상태면 fail-closed — CIA_LOG_ADDRESS 미설정과 같은 취급(503)으로 통일한다.
    throw Object.assign(new Error('chain unavailable'), { status: 503 });
  }
}
const nowSec = () => BigInt(Math.floor(Date.now() / 1000));
/**
 * 만료(exptime + REVOKE_SKEW_SECONDS < now)된 발급 기록을 걷어내고 남은 것을 돌려준다. 체인이 필요 없다 —
 * 만료는 벽시계다. 실제 만료(exptime)보다 여유만큼 늦게 지우는 이유는 위 REVOKE_SKEW_SECONDS 주석 참고.
 */
function pruneExpired(uid) {
  const list = state.issued[uid] ?? [];
  const now = nowSec();
  state.issued[uid] = list.filter((e) => BigInt(e.exptime) + BigInt(REVOKE_SKEW_SECONDS) >= now);
  return state.issued[uid];
}
/** 발급 직전의 체인 가용성 확인(fail-closed, 기반 설계 §2.1). 값은 쓰지 않는다 — 살아 있는지만 본다. */
async function chainAlive() {
  if (!LOG_ADDRESS) throw Object.assign(new Error('CIA_LOG_ADDRESS not configured'), { status: 503 });
  try { await ethWallet.provider.getBlockNumber(); }
  catch { throw Object.assign(new Error('chain unavailable'), { status: 503 }); }
}

// ---- 앱 ----
const app = express();
app.use(express.json({ limit: '256kb' }));

// 관리자 패널(스펙 §5). 페이지 하나만 허용 목록으로 내보낸다 — express.static 은 쓰지 않는다.
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'cia_admin.html')));

// 사용자 페이지(§6.5.1). 잃어버린 지갑이 아니라 어느 장치에서든 열 수 있어야 하므로 CIA 가 직접 낸다.
app.get('/account', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'cia_account.html')));

app.get('/cia/public_keys', (req, res) => {
  res.json({ pk_CIA: S(ciaPub), ethAddress: ethWallet.address, ttlSeconds: TTL_SECONDS, chainIds: CHAIN_IDS, logAddress: LOG_ADDRESS });
});

// §3(2026-09-16) 서비스 등록 — pending 으로 받고 운영자가 승인하면 CIA 조각을 만들어 조합 키 pk_trace 와 cert_s(V2)를
// 낸다. 같은 origin·같은 키의 재호출은 현재 상태를 돌려준다(상태 조회를 겸한다). arid 는 요청 시점에 배정한다.
const isAddr = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
app.post('/cia/register_rp', async (req, res) => {
  try {
    const { name, origin, pk_service, X_svc } = req.body ?? {};
    if (typeof name !== 'string' || name.length === 0 || typeof origin !== 'string' || !/^https?:\/\/[^/\s]+$/.test(origin) || !isAddr(pk_service) || !isPt(X_svc)) {
      return res.status(400).json({ error: 'name, origin(http(s)://host[:port], 경로 없음), pk_service(주소), X_svc{x,y} required' });
    }
    const addr = ethers.getAddress(pk_service);
    const Xs = pointFromStrings(X_svc);
    // 항등원·부분군 밖은 거절 — 항등원 X_svc 면 pk_trace 가 CIA 조각만으로 열린다(§2).
    if (!(await isTracePoint(Xs))) return res.status(400).json({ error: 'X_svc is not a valid subgroup point' });
    const Xn = { x: Xs.x.toString(), y: Xs.y.toString() };   // 정규 인코딩으로 저장·대조 — 비정규 입력이 다른 값으로 오인되지 않게
    let arid = Object.keys(state.rps).find((a) => state.rps[a].origin === origin);
    let e = arid ? state.rps[arid] : null;
    if (e && e.pk_service === null) {
      // v3 에서 넘어온 등록(키 없음): 키를 처음 내면 pending 으로 돌려 운영자 승인을 다시 받게 한다 —
      // 그러지 않으면 첫 호출자가 승인 없이 조합 키를 얻어 진짜 서비스가 잠긴다(§3).
      e.pk_service = addr; e.X_svc = Xn;
      e.status = 'pending'; e.requestedAt = new Date().toISOString(); e.decidedAt = null;
      e.x_AA = null; e.pk_trace = null;
      persist();
    }
    if (e && (e.pk_service !== addr || e.X_svc.x !== Xn.x || e.X_svc.y !== Xn.y)) {
      return res.status(409).json({ error: 'service_key_mismatch' });
    }
    if (!e) {
      arid = randomScalar().toString();
      e = state.rps[arid] = { name, origin, pk_service: addr, X_svc: Xn, x_AA: null, pk_trace: null, status: 'pending', requestedAt: new Date().toISOString(), decidedAt: null };
      persist();
    }
    if (e.status === 'denied') return res.status(403).json({ arid, status: 'denied' });
    if (e.status === 'pending') return res.status(202).json({ arid, status: 'pending' });
    const cert_s = await signRpCert(ciaPrv, { arid: BigInt(arid), origin, pk_trace: e.pk_trace });
    res.json({ arid, name: e.name, origin, pk_trace: e.pk_trace, cert_s });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/** CIA 조각을 만들어 조합 키를 채운다. 승인 때 한 번 — await 사이 다른 요청이 먼저 채웠으면 덮어쓰지 않는다. */
async function makeShare(arid) {
  const e = state.rps[arid];
  if (e.pk_trace) return;
  const share = await createShare();
  if (e.pk_trace) return;
  const pk = await combinePublicKey(pointFromStrings(e.X_svc), share.X);
  if (e.pk_trace) return;
  e.x_AA = share.x.toString();
  e.pk_trace = { x: pk.x.toString(), y: pk.y.toString() };
  persist();
}

const rpView = (arid, e) => ({ arid, name: e.name, origin: e.origin, pk_service: e.pk_service, X_svc: e.X_svc, pk_trace: e.pk_trace, status: e.status, requestedAt: e.requestedAt, decidedAt: e.decidedAt });
app.get('/cia/rps', requireAdmin, (req, res) => res.json({ rps: Object.entries(state.rps).map(([a, e]) => rpView(a, e)) }));
app.post('/cia/rps/:arid/approve', requireAdmin, async (req, res) => {
  try {
    const e = state.rps[req.params.arid];
    if (!e) return res.status(404).json({ error: 'unknown service' });
    if (e.status !== 'pending') return res.status(409).json({ error: `already ${e.status}` });
    if (!e.X_svc) return res.status(409).json({ error: 'no service key registered' });
    e.status = 'approved'; e.decidedAt = new Date().toISOString();
    await makeShare(req.params.arid);
    res.json({ arid: req.params.arid, status: e.status });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/cia/rps/:arid/deny', requireAdmin, (req, res) => {
  const e = state.rps[req.params.arid];
  if (!e) return res.status(404).json({ error: 'unknown service' });
  if (e.status !== 'pending') return res.status(409).json({ error: `already ${e.status}` });
  e.status = 'denied'; e.decidedAt = new Date().toISOString(); persist();
  res.json({ arid: req.params.arid, status: e.status });
});

// §6.1 등록. CIA 가 장기키를 만들어 주고 sk_u 는 기억하지 않는다(응답에 한 번 실어 보내고 버린다).
app.post('/cia/register', async (req, res) => {
  const { uid, pwd, cm_u } = req.body ?? {};
  if (!isDec(uid) || typeof pwd !== 'string' || !isPt(cm_u)) return res.status(400).json({ error: 'uid, pwd, cm_u{x,y} required' });
  const acct = Object.values(DEMO_ACCOUNTS).find((a) => a.uid === uid);
  if (!acct || acct.password !== pwd) return res.status(401).json({ error: 'invalid credentials' });
  if (state.accounts[uid]) return res.status(409).json({ error: 'already registered' });
  // 등록은 한 번뿐이다. 곡선·부분군 밖이거나 비정규 인코딩이면 이후 모든 발급이 400 이 되고
  // 재등록은 409 라 uid 가 영구히 잠기므로 여기서 거절한다.
  if (!(await isValidPoint(pointFromStrings(cm_u)))) return res.status(400).json({ error: 'cm_u is not a valid subgroup point' });
  // 위 await 동안 같은 uid 의 등록이 먼저 끝났을 수 있다(기동 직후 첫 요청은 babyjub WASM 빌드로 길다).
  // 여기서 다시 확인하지 않으면 뒤의 것이 덮어써 먼저 등록한 지갑의 sk_u·cm_u 가 영구히 맞지 않게 된다.
  if (state.accounts[uid]) return res.status(409).json({ error: 'already registered' });
  const prv = randomBytes(32);
  const pub = eddsa.prv2pub(prv);
  state.accounts[uid] = { pk_u: S(pub), cm_u: { x: cm_u.x, y: cm_u.y }, disabled: false };
  persist();
  res.status(201).json({ pk_u: S(pub), sk_u: prv.toString('hex') });
});

// §5(2026-09-15) 발급. C 는 받지 않는다 — C_pt 에서 스스로 유도한다. 검사 순서: 형식 → disabled → chainid 허용 →
// 사용자 서명 → π_issue → 같은 C → 체인 가용성 → disabled 재확인 → 서명·기록.
app.post('/cia/issue', async (req, res) => {
  try {
    const { uid, C_pt, proof, sig_u, chainid, r_s } = req.body ?? {};
    if (!isDec(uid) || !isPt(C_pt) || !proof || !sig_u || !isDec(chainid) || !isDec(r_s)) {
      return res.status(400).json({ error: 'uid, C_pt, proof, sig_u, chainid, r_s required' });
    }
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });

    const chainStr = BigInt(chainid).toString();
    if (CHAIN_IDS.length === 0) return res.status(503).json({ error: 'chain id unknown: CIA_CHAIN_IDS not configured and RPC unreachable at startup' });
    if (!CHAIN_IDS.includes(chainStr)) return res.status(400).json({ error: `bad chainid ${chainStr}: allowed ${CHAIN_IDS.join(',')}` });

    const rsBig = BigInt(r_s);
    if (rsBig >= SCALAR_MAX) return res.status(400).json({ error: 'r_s must be < 2^250' });
    const rsStr = rsBig.toString();

    const cpt = pointFromStrings(C_pt);
    // 사용자 인증: 등록된 pk_u 로 (C_pt, chainid, r_s) 에 대한 EdDSA-Poseidon 서명 검증
    let sigOk = false;
    try {
      const m = F.e(await issueRequestMessage(cpt, BigInt(chainStr), rsBig));
      const sig = { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) };
      const pub = [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))];
      sigOk = eddsa.verifyPoseidon(m, sig, pub);
    } catch { sigOk = false; }
    if (!sigOk) return res.status(400).json({ error: 'bad user signature' });

    // π_issue: 이 C_pt 가 내 uid 의 것이고 s_u 가 등록된 cm_u 와 같다. 속성 슬롯은 검증하지 않는다(설계 §2).
    let proofOk = false;
    try { proofOk = await verifyIssuance({ uid: BigInt(uid), C_pt: cpt, cm_u: pointFromStrings(acct.cm_u), proof: parseProof(proof) }); }
    catch { proofOk = false; }
    if (!proofOk) return res.status(400).json({ error: 'bad issuance proof' });

    const C = await compressPoint(cpt);
    const Cstr = C.toString();
    // 같은 C_pt 재발급 거절 — r_s 와 별개로, 같은 커밋에 서명이 두 번 붙지 않게.
    if (pruneExpired(uid).some((e) => e.C === Cstr)) return res.status(409).json({ error: 'credential already issued for this C_pt' });

    await chainAlive();   // fail-closed: 체인이 죽어 있으면 발급하지 않는다(게시도 불가하므로 폐기가 닿지 않는 credential 이 된다)

    const exptime = nowSec() + BigInt(TTL_SECONDS);
    const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessage(C, exptime, BigInt(chainStr), rsBig)));
    const leaf = await credLeaf(C);
    // 위 await 들 사이에 /cia/revoke·self_revoke 나 같은 (C_pt, 다른 r_s) 의 동시 요청이 끼어들 수 있다 —
    // 폐기 직후의 발급이 살아남으면 트리에 없는 새 credential 이 TTL 동안 유효하고, 같은 C 가 두 번 서명되면
    // 서로 다른 σ_CIA 두 개가 credential 하나를 가리킨다. 마지막 await 뒤, 기록 직전에 disabled·같은 C
    // 둘을 다시 확인한다. 끼어든 revoke 의 pruneExpired 가 목록 배열을 새로 만들었을 수 있어
    // state.issued[uid] 에 넣는다. r_s 는 기록하지 않는다(2026-09-16 §4.4) — 재생은 RP 의 소비가 막는다.
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });
    if (pruneExpired(uid).some((e) => e.C === Cstr)) return res.status(409).json({ error: 'credential already issued for this C_pt' });
    (state.issued[uid] ??= []).push({ leaf: leaf.toString(), C: Cstr, exptime: exptime.toString() });
    persist();
    res.json({
      C: Cstr, exptime: exptime.toString(), chainid: chainStr, r_s: rsStr,
      sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() },
      pk_CIA: S(ciaPub),
    });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

// §6.5 계정 전체 폐기: 그 uid 의 미만료 리프 전부 삽입 + disabled. 관리자 폐기(/cia/revoke scope=account)와
// 사용자 자기 폐기(/cia/account/self_revoke, §6.5.1)가 같은 처리를 탄다 — 다른 것은 "누가 개시하느냐"뿐이다.
// tree.insert 는 이미 있는 리프에 false 를 돌려주므로 두 번 불러도 새 리프가 들어가지 않는다(멱등).
async function revokeAccount(uid) {
  const acct = state.accounts[uid];
  if (!acct) throw Object.assign(new Error('unknown account'), { status: 404 });
  const targets = pruneExpired(uid).map((e) => e.leaf);
  acct.disabled = true;
  const inserted = [];
  for (const l of targets) {
    if (await tree.insert(BigInt(l))) { state.revoked.push(l); state.pending.push(l); inserted.push(l); }
  }
  persist();
  return { inserted, root: tree.getRoot().toString(), pending: state.pending.length };
}

// §6.5 폐기. account = 그 uid 의 미만료 리프 전부 + disabled. credential = 리프 하나.
app.post('/cia/revoke', requireAdmin, async (req, res) => {
  try {
    const { uid, scope, leaf, C } = req.body ?? {};
    if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
    if (scope === 'account') return res.json(await revokeAccount(uid));
    if (scope !== 'credential') return res.status(400).json({ error: "scope must be 'account' or 'credential'" });
    // 그 uid 의 미만료 발급 목록에 있는 리프만 받는다 — 폐기는 append-only 라 잘못 넣은 리프가
    // 영구히 남고, 범위 밖 값은 트리가 throw 한다. leaf 대신 C 를 주면 서버가 리프를 유도한다.
    // 발급 기록은 {leaf, C} 쌍이라 다시 해시하지 않고 기록에서 찾는다. isDec 은 앞자리 0 을 허용하므로
    // BigInt 로 정규화한 뒤 비교한다.
    const issued = pruneExpired(uid);
    let entry;
    if (isDec(C)) entry = issued.find((e) => e.C === BigInt(C).toString());
    else if (isDec(leaf)) entry = issued.find((e) => e.leaf === BigInt(leaf).toString());
    else return res.status(400).json({ error: 'leaf or C required' });
    if (!entry) return res.status(404).json({ error: 'leaf not issued to this uid (or expired)' });
    const inserted = [];
    if (await tree.insert(BigInt(entry.leaf))) { state.revoked.push(entry.leaf); state.pending.push(entry.leaf); inserted.push(entry.leaf); }
    persist();
    res.json({ inserted, root: tree.getRoot().toString(), pending: state.pending.length });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// §6.5 게시. 서명이 리프 배열까지 덮는다 — 릴레이어의 calldata 오염 방지. 로그 주소도 덮는다 —
// 같은 CIA 키로 재배포한 다른 로그에 옛 게시를 재생하지 못하게(재생되면 root 가 옛 트리로 바뀐다).
// digest 계산은 lib/mode3_log.js 하나다(컨트랙트의 digestFor 와 바이트 단위로 같다).
//
// 게시는 한 번에 하나만 돈다. 둘이 겹치면 각자 pending 을 자기 개수만큼 앞에서 잘라, 그 사이 들어온
// revoke 의 리프가 pending 에서만 사라진다 — 트리·서명 root 에는 남아 지갑 재구성이 영구히 실패한다.
// 관리자 페이지의 게시 버튼을 두 번 누르는 것이 그 경로다.
let publishing = false;
app.post('/cia/publish', requireAdmin, async (req, res) => {
  if (publishing) return res.status(409).json({ error: 'publish already in progress' });
  publishing = true;
  try {
    if (!LOG_ADDRESS) return res.status(503).json({ error: 'CIA_LOG_ADDRESS not configured' });
    // 게시 직전 대조(기동 시와 같은 규칙). 온체인 root 가 우리가 아는 어느 접두사와도 다르면 올리지 않는다 —
    // 체인에 이벤트로 나간 적 없는 리프를 품은 root 를 서명하면 전원의 재구성이 영구히 실패한다.
    let chain;
    try { chain = await readChain(); }
    catch (e) { return res.status(503).json({ error: `chain unavailable: ${e.message}` }); }
    if (!(await reconcileWithChain(chain))) {
      publishedTree = await buildPublishedTree();   // 걷다 만 트리를 되돌린다
      return res.status(503).json({ error: `onchain root ${chain.onchainRoot} 가 로컬 게시 기록의 어느 접두사와도 다르다 — ` +
        `로그를 재배포했거나 상태 파일이 유실·복원됐다. CIA_STATE_FILE 과 CIA_LOG_ADDRESS 를 확인할 것` });
    }
    if (state.pending.length === 0) return res.json({ published: false, epoch: state.epoch, root: tree.getRoot().toString() });
    const log = new ethers.Contract(LOG_ADDRESS, LOG_ABI, ethWallet);
    const leaves = state.pending.map(rootToBytes32);
    const root = rootToBytes32(tree.getRoot());
    // reconcileWithChain 이 state.epoch 를 온체인과 맞췄다 — 로컬만 보고 이미 온체인에 있는 epoch 를 또
    // 보내면 EpochNotIncreasing 으로 영원히 막힌다.
    const epoch = state.epoch + 1;
    const sig = await signRootPublication(ethWallet, { logAddress: LOG_ADDRESS, root, epoch, leaves });
    const tx = await log.publishRoot(root, epoch, leaves, sig);
    await tx.wait();
    state.epoch = epoch;
    // 위 await 들 사이에 /cia/revoke 가 pending 뒤에 붙인 리프는 이번 tx 에 실리지 않았다 —
    // 이번에 실은 앞부분만 지운다. 통째로 비우면 그 리프는 온체인 이벤트로 영영 나가지 않으면서
    // 이후 모든 서명 root 에는 들어 있어, 지갑의 이벤트 재구성이 전부 fail-closed 된다.
    for (const l of state.pending.slice(0, leaves.length)) await publishedTree.insert(BigInt(l));
    state.pending = state.pending.slice(leaves.length);
    persist();
    res.json({ published: true, epoch, root: tree.getRoot().toString(), txHash: tx.hash, leaves });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
  finally { publishing = false; }
});

app.post('/cia/account/set_disabled', requireAdmin, (req, res) => {
  const { uid, disabled } = req.body ?? {};
  if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
  state.accounts[uid].disabled = Boolean(disabled);
  persist();
  res.json({ uid, disabled: state.accounts[uid].disabled });
});

// §6.5.1 사용자 개시 폐기. 인증은 계정 비밀번호다 — 지갑 키가 아니다. 장치를 잃은 사용자에게 sk_u 는 없고
// 공격자에게는 있으므로, 인증 수단은 장치 밖에 있어야 한다. 처리는 관리자의 계정 폐기와 같다.
// 형식 → 비밀번호 → 등록 상태 순으로 검사한다. 비밀번호가 틀리면 등록 여부를 알려주지 않는다.
app.post('/cia/account/self_revoke', async (req, res) => {
  try {
    const { uid, pwd } = req.body ?? {};
    if (!isDec(uid) || typeof pwd !== 'string') return res.status(400).json({ error: 'uid, pwd required' });
    const acct = Object.values(DEMO_ACCOUNTS).find((a) => a.uid === uid);
    if (!acct || !secretMatches(pwd, acct.password)) return res.status(401).json({ error: 'invalid credentials' });
    if (!state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
    // disabled 는 인증만 통과하면 즉시 건다(설계 §6.5.1) — 재발급 차단은 트리·게시와 분리된 별개의 효력이다.
    state.accounts[uid].disabled = true;
    persist();
    // 만료 판정이 벽시계라(2026-09-14 설계 §7) 리프 삽입에도 체인이 필요 없다 — 체인이 죽어 있어도 전부 걸린다.
    const out = await revokeAccount(uid);
    res.json({ ...out, disabled: true });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// ---- §6(2026-09-16) 승인된 개봉 ----
// 요청: 서비스가 트랜스크립트(공개 입력 14개 + π)와 자기 부분 복호 D_svc 를 서비스 서명키로 서명해 낸다. CIA 는 서명·신선도·
// arid·pk_trace·Groth16 을 검증하고 pending 으로 둔다 — 트랜스크립트 검증이 없으면 서비스가 임의 암호문을 내 CIA 를 복호
// 오라클로 쓸 수 있고, arid 대조가 없으면 유출된 남의 로그로 연다. 승인 시점에야 CIA 조각을 더해 uid 를 계산한다.
let vkeyP = null;
function loadVkey() {
  return (vkeyP ??= (async () => JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8')))().catch((e) => { vkeyP = null; throw e; }));
}
const findOpening = (id) => state.openings.find((o) => o.id === id);
app.post('/cia/open/request', async (req, res) => {
  try {
    const { arid, publicSignals, proof, D_svc, ts, sig } = req.body ?? {};
    if (!isDec(arid) || !Array.isArray(publicSignals) || publicSignals.length !== 14 || !publicSignals.every(isDec) || !proof || !isPt(D_svc) || !isDec(ts) || typeof sig !== 'string') {
      return res.status(400).json({ error: 'arid, publicSignals[14], proof, D_svc{x,y}, ts, sig required' });
    }
    if (!(await isTracePoint(pointFromStrings(D_svc)))) return res.status(400).json({ error: 'D_svc is not a valid subgroup point' });
    const e = state.rps[arid];
    if (!e) return res.status(404).json({ error: 'unknown_service' });
    if (e.status !== 'approved' || !e.pk_service || !e.pk_trace) return res.status(403).json({ error: 'not_approved' });
    if (!isFreshTs(ts)) return res.status(401).json({ error: 'stale' });
    const [PPID, aridIn, , , , r_s, , ciaX, ciaY, traceX, traceY, c1x, c1y, c2] = publicSignals;
    if (recoverSigner(openRequestMessage({ arid, r_s, PPID, D_svc, ts }), sig) !== e.pk_service) return res.status(401).json({ error: 'bad_signature' });
    if (aridIn !== arid) return res.status(403).json({ error: 'wrong_arid' });
    const pk = S(ciaPub);
    if (ciaX !== pk.x || ciaY !== pk.y) return res.status(403).json({ error: 'untrusted_cia' });
    if (traceX !== e.pk_trace.x || traceY !== e.pk_trace.y) return res.status(403).json({ error: 'wrong_trace_key' });
    let vkey;
    try { vkey = await loadVkey(); } catch (err) { return res.status(503).json({ error: `vkey unavailable: ${err.message}` }); }
    let ok = false;
    try { ok = await snarkjs.groth16.verify(vkey, publicSignals, proof); }
    catch (err) { console.warn('[cia] 개봉 요청의 증명 검증 예외 — vkey/회로 불일치일 수 있다: ' + err.message); ok = false; }
    if (!ok) return res.status(403).json({ error: 'bad_proof' });
    // pending·approved 는 같은 세션의 결정이 이미 있거나 진행 중이라 그 id 를 돌려주고, failed·denied 는
    // 새 요청을 허용한다 — 틀린 D_svc 를 고치거나 거절된 세션을 다시 심사에 올릴 길이 있어야 한다.
    const dup = state.openings.find((o) => o.arid === arid && o.r_s === r_s && (o.status === 'pending' || o.status === 'approved'));
    if (dup) return res.status(200).json({ id: dup.id, status: dup.status });
    const id = randomBytes(32).toString('hex');
    state.openings.push({ id, arid, r_s, PPID, c1: { x: c1x, y: c1y }, c2, D_svc: { x: D_svc.x, y: D_svc.y }, status: 'pending', requestedAt: new Date().toISOString(), decidedAt: null });
    persist();
    res.status(202).json({ id, status: 'pending' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/cia/openings', requireAdmin, (req, res) => res.json({ openings: state.openings }));
app.post('/cia/openings/:id/approve', requireAdmin, async (req, res) => {
  try {
    const o = findOpening(req.params.id);
    if (!o) return res.status(404).json({ error: 'unknown opening' });
    if (o.status !== 'pending') return res.status(409).json({ error: `already ${o.status}` });
    const e = state.rps[o.arid];
    const D_aa = await partialDecrypt(BigInt(e.x_AA), pointFromStrings(o.c1));
    const uid = (await combineDecrypt(BigInt(o.c2), pointFromStrings(o.D_svc), D_aa)).toString();
    o.decidedAt = new Date().toISOString();
    if (state.accounts[uid]) { o.status = 'approved'; o.uid = uid; }
    else { o.status = 'failed'; }   // D_svc 가 틀렸다 — 서비스 자신의 요청만 망친다(§6)
    persist();
    res.json({ id: o.id, status: o.status });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/cia/openings/:id/deny', requireAdmin, (req, res) => {
  const o = findOpening(req.params.id);
  if (!o) return res.status(404).json({ error: 'unknown opening' });
  if (o.status !== 'pending') return res.status(409).json({ error: `already ${o.status}` });
  o.status = 'denied'; o.decidedAt = new Date().toISOString(); persist();
  res.json({ id: o.id, status: o.status });
});
app.get('/cia/open/:id', (req, res) => {
  const { ts, sig } = req.query ?? {};
  const o = findOpening(req.params.id);
  if (!o) return res.status(404).json({ error: 'unknown opening' });
  if (!isDec(ts) || typeof sig !== 'string') return res.status(400).json({ error: 'ts, sig required' });
  if (!isFreshTs(ts)) return res.status(401).json({ error: 'stale' });
  const e = state.rps[o.arid];
  if (recoverSigner(openResultMessage(o.id, ts), sig) !== e.pk_service) return res.status(401).json({ error: 'bad_signature' });
  if (o.status === 'pending') return res.status(202).json({ id: o.id, status: o.status });
  if (o.status !== 'approved') return res.status(403).json({ id: o.id, status: o.status });
  res.json({ id: o.id, status: o.status, uid: o.uid, PPID: o.PPID, r_s: o.r_s, decidedAt: o.decidedAt });
});

app.get('/cia/state', async (req, res) => {
  let head = null;
  try { head = (await headHeight()).toString(); } catch { /* 체인 없음 */ }
  res.json({ root: tree.getRoot().toString(), epoch: state.epoch, pendingCount: state.pending.length, leafCount: state.revoked.length, head });
});

// ---- 기동 ----
eddsa = await buildEddsa();
poseidon = await buildPoseidon();
F = poseidon.F;
loadOrCreateKeys();
await loadState();
// RP·지갑 에이전트와 같이 루프백에만 묶는다 — 관리자·사용자 페이지와 발급 경로를 LAN 에 노출하지 않는다.
app.listen(PORT, '127.0.0.1', () => {
  console.log(`Mode 3 CIA running at http://127.0.0.1:${PORT} (log=${LOG_ADDRESS ?? 'none'}, ttl=${TTL_SECONDS}s, chains=${CHAIN_IDS.join(',') || 'none'}, vkey=${fs.existsSync(VKEY_PATH) ? 'ok' : 'missing'})`);
});
