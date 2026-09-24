// Mode 3 CIA (Credential Issuing Authority).
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §3, §6
//
// Mode 2 의 custom_idp.js 와 나란히 두는 별도 서버다(:4100). 그쪽 코드를 import 하지 않는다.
// 하는 일 넷: 등록(§6.1), 발급(§6.2), 폐기(§6.5), root 게시(§6.5). 로그인 검증은 하지 않는다 —
// 그것은 RP 의 일이고(§6.3) CIA 는 조회 경로에 있어서는 안 된다(§9.9).
// V4(2026-09-18): 만료는 블록 높이(max_height), allowAgent, 체인 헤드 조회, 하트비트 게시, 개봉 평문 역조회 — 설계 2026-09-18-mode3-onchain-execution-design.md §4·§6.
// V5(2026-09-21): 자격증명 이중 구조 — 사용자 자격증명(/cia/user_cred, π_u)과 세션 발급(/cia/issue, ZKP 없음)을 나눈다. 폐기 리프는 Cf_u 에서
//   나오므로 세션 기록(issued)이 없다 — 설계 2026-09-21-mode3-two-tier-credential §3·§4.
// V8(2026-09-24): 세션 단위 폐기 — 발급이 accounts[uid].sessions 에 기록을 남기고, /cia/revoke scope=session 이 sessionLeaf(Cf_s) 를
//   트리에 넣는다. 만료된 기록은 하트비트에서 지운다(리프는 남는다) — 설계 2026-09-24-mode3-session-revocation §2.2·§6.
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
import { credMessageV5, compressPoint, randomScalar, normalizeAttrs, ATTR_SLOTS } from './lib/mode3_credential.js';
import { userLeaf, sessionLeaf, createRevocationTree } from './lib/mode3_revocation.js';
import { isValidPoint, pointFromStrings, verifyUserCred, parseUserCredProof, userCredRequestMessage, issueRequestMessageV4, attrsRequestMessage, revokeSessionMessage } from './lib/mode3_issuance.js';
import { LOG_ABI, rootToBytes32, signRootPublication } from './lib/mode3_log.js';
import { signRpCert } from './lib/mode3_rp_cert.js';
import { isTracePoint, createShare, combinePublicKey, partialDecrypt, combineDecrypt, resolveTagPlaintext, proveShare } from './lib/mode3_trace.js';
import { openRequestMessage, openResultMessage, recoverSigner, isFreshTs } from './lib/mode3_opening.js';
import { CIA_STATE_VERSION, defaultCiaState, migrateCiaState } from './lib/mode3_cia_state.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.CIA_PORT) || 4100;
const STATE_FILE = process.env.CIA_STATE_FILE || path.join(__dirname, 'cia_state.json');
const KEYS_FILE = process.env.CIA_KEYS_FILE || path.join(__dirname, 'cia_keys.json');
const VKEY_PATH = process.env.MODE3_VKEY_PATH || path.join(__dirname, 'build', 'mode3', 'pi_cred_vkey.json');
const ADMIN_SECRET = process.env.CIA_ADMIN_SECRET;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
// dotenv 는 이미 있는 키를 덮지 않으므로 격리 테스트 하네스는 "기본값 사용"을 빈 문자열로 표시한다(isolated_cia.mjs).
// `||` 는 빈 문자열을 falsy 로 봐 기본값으로 떨어지지만 `??` 는 아니라서 `BigInt('') === 0n` 이 그대로 상수가 돼
// 버린다 — 하트비트가 경고 없이 꺼지는 등 조용한 오설정으로 이어진다. 미설정·빈 문자열만 "기본값"으로 다룬다:
// 하트비트를 끄려면 명시적으로 '0' 이어야 한다.
const envBig = (k, d) => { const v = process.env[k]; return v === undefined || v === '' ? BigInt(d) : BigInt(v); };
// 만료 max_height 는 지갑이 정하고 CIA 는 그대로 서명한다(설계 2026-09-18 §3.2 갱신, zkLogin 의 max_epoch 와 같은 구조).
// 상한은 검증자(서비스·컨트랙트)가 head + L 로 강제한다. CIA 는 발급 때 헤드를 읽지 않는다 — 체인 가용성만 확인한다.
// 하트비트(설계 §4.5): 마지막 게시에서 이만큼 블록이 지나면 같은 root 를 새 epoch 로 재게시한다. 지갑 컨트랙트의
// MAX_ROOT_AGE(기본 100) 보다 작아야 한다. 0 이면 끈다(테스트) — envBig 은 빈 문자열을 기본값으로 보므로 끄려면
// 명시적으로 '0' 을 줘야 한다(격리 하네스가 그렇게 한다).
const HEARTBEAT_BLOCKS = envBig('CIA_HEARTBEAT_BLOCKS', 50);
const HEARTBEAT_POLL_MS = Number(process.env.CIA_HEARTBEAT_POLL_MS) || 5000;
for (const k of ['CIA_TTL_SECONDS', 'CIA_REVOKE_SKEW_SECONDS', 'CIA_CHAIN_IDS', 'CIA_TTL_BLOCKS', 'CIA_HEIGHT_GRID', 'CIA_REVOKE_SKEW_BLOCKS']) {
  if (process.env[k]) console.warn(`[cia] ${k} 는 더 이상 읽지 않는다(2026-09-18: 블록 높이·CIA_CHAIN_RPCS, 2026-09-21: 세션 기록 없음) — 무시`);
}
// 발급을 허용하는 체인과 그 헤드를 읽을 RPC(설계 §4.2). "chainid=url,chainid=url". 비어 있으면 기동 시 자기 provider 의
// chainId 하나를 RPC_URL 로 등록한다. 요청의 chainid 가 여기 없으면 400.
const CHAIN_RPCS = new Map();
for (const item of (process.env.CIA_CHAIN_RPCS || '').split(',').map((s) => s.trim()).filter(Boolean)) {
  const i = item.indexOf('=');
  if (i <= 0) throw new Error(`CIA_CHAIN_RPCS 항목 "${item}" 은 chainid=url 형식이어야 한다`);
  let id;
  try { id = BigInt(item.slice(0, i).trim()).toString(); } catch { throw new Error(`CIA_CHAIN_RPCS 의 chainid "${item.slice(0, i)}" 은 정수가 아니다`); }
  CHAIN_RPCS.set(id, item.slice(i + 1).trim());
}
const chainProviders = new Map();   // chainid → JsonRpcProvider (재사용)

// 데모 계정. Mode 2 의 testuser 관례를 따른 프로토타입이다 — 실제 계정 체계가 아니다.
const DEMO_ACCOUNTS = {
  testuser: { password: 'password123', uid: '12345', attrs: ['1990', '410', '2', '0'] },   // a₀ 출생연도, a₁ 국가(ISO 3166 numeric), a₂ 등급, a₃ 예비
  alice: { password: 'alicepw', uid: '67890', attrs: ['2005', '840', '1', '0'] },
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
  // ethers 의 250ms eth_blockNumber 캐시를 끈다(RP·지갑과 같이). /cia/state·readChain 이 항상 최신 값을 보게
  // 한다. headOf() 가 쓰는 체인별 provider(providerFor)도 같은 옵션으로 만든다 — 그래야 race 테스트의
  // eth_blockNumber 게이트가 결정적으로 걸린다(캐시가 있으면 조회가 캐시에 합류해 게이트를 건너뛸 수 있다).
  ethWallet = new ethers.Wallet(ethPrv, new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 }));
}

// ---- 상태 ----
// accounts:  uid → { pk_u:{x,y}, cm_u:{x,y}, disabled, creds: [ { Cf_u(10진), C_u_pt:{x,y}, leaf(10진), issuedAt, revoked } ] }
//            creds 중 revoked:false 는 하나뿐(사용자당 활성 자격증명 하나, 2026-09-21 §3.1). 세션 발급은 기록하지 않는다.
// rps:       arid → { name, origin, pk_service, X_svc, x_AA, pk_trace, status, requestedAt, decidedAt }   (2026-09-16 §3)
// openings:  [ { id, arid, PPID, c1:{x,y}, c2, D_svc:{x,y}, allowAgent, max_height, chainid, status, requestedAt, decidedAt,
//                uid|null, resolved } ]   영구 감사 기록(§6). uid·resolved 는 approved 에만 의미 있다
// revoked / pending / epoch
// 버전·이행은 lib/mode3_cia_state.js (v6, 2026-09-21).
const STATE_VERSION = CIA_STATE_VERSION;
let state;
let tree;            // 전체 폐기 트리(게시 여부 무관) — 서명해 올리는 root 의 출처
let publishedTree;   // 온체인에 이벤트로 나간 리프만 — 게시 직전 온체인 root 와 대조하는 기준
function defaultState() { return defaultCiaState(); }
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
  let migrated;
  try { migrated = migrateCiaState(state, { demoAttrs: (uid) => Object.values(DEMO_ACCOUNTS).find((a) => a.uid === uid)?.attrs ?? null }); }
  catch (e) {
    console.error(`[cia] 기동 거부: ${e.message}. v2 이하는 옛 credential 형식이라 새 회로에서 검증되지 않으므로 마이그레이션하지 않는다 — ` +
      `재시연 세트(로그 재배포 → 상태 파일 삭제)로 새로 시작할 것.`);
    process.exit(1);
  }
  state = migrated.state;
  if (migrated.notes.length) { for (const n of migrated.notes) console.warn(`[cia] 상태 파일 이행 ${n}`); persist(); }
  publishedTree = await buildPublishedTree();
  // 기동 시 대조. RPC 가 아직 안 떠 있으면 대조 없이 기동한다 — 발급은 headOf() 가 503 을 내거나
  // (CIA_CHAIN_RPCS 도 없어 허용 목록이 비어 있으면) chainid 허용 목록 검사에서 503 을 내고,
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
  if (CHAIN_RPCS.size === 0) {
    try { CHAIN_RPCS.set((await ethWallet.provider.getNetwork()).chainId.toString(), RPC_URL); }
    catch (e) { console.warn(`[cia] 기동 시 chainId 를 읽지 못했다 — CIA_CHAIN_RPCS 가 없으면 발급은 503: ${e.message}`); }
  }
  // 이행(v6→v7 등)이 pending 리프를 남겼으면 게시를 한 번 자동으로 시도한다 — 그러지 않으면 다음 하트비트까지
  // 옛(보증되지 않은) C_u 로도 여전히 π 가 만들어져 세션 발급이 통과한다(2026-09-22 최종 리뷰 Important, Ruling 8).
  // RPC 가 아직 없으면(또는 다른 이유로 게시가 실패하면) 경고만 남긴다 — 기동 자체는 막지 않는다.
  if (migrated.notes.length && state.pending.length > 0) {
    try {
      const r = await publishNow();
      console.log(`[cia] 이행 뒤 자동 게시: epoch ${r.epoch}, 리프 ${r.leaves?.length ?? 0}개`);
    } catch (e) {
      console.warn(`[cia] 이행 뒤 자동 게시 실패(${e.message}) — pending ${state.pending.length}개가 남아 있다. ` +
        `체인이 준비되면 /cia/publish 를 수동으로 호출할 것.`);
    }
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
function providerFor(chainStr) {
  if (!chainProviders.has(chainStr)) chainProviders.set(chainStr, new ethers.JsonRpcProvider(CHAIN_RPCS.get(chainStr), undefined, { cacheTimeout: -1 }));
  return chainProviders.get(chainStr);
}
/** 그 체인의 헤드. 발급 직전의 체인 가용성 확인(fail-closed, 기반 설계 §2.1)을 겸한다 — 못 읽으면 503. */
async function headOf(chainStr) {
  if (!LOG_ADDRESS) throw Object.assign(new Error('CIA_LOG_ADDRESS not configured'), { status: 503 });
  if (!CHAIN_RPCS.has(chainStr)) throw Object.assign(new Error(`bad chainid ${chainStr}: allowed ${[...CHAIN_RPCS.keys()].join(',')}`), { status: 400 });
  try { return BigInt(await providerFor(chainStr).getBlockNumber()); }
  catch { throw Object.assign(new Error('chain head unavailable'), { status: 503 }); }
}
/** 발급 직전의 체인 가용성 확인(fail-closed, 기반 설계 §2.1). 값은 쓰지 않는다 — 살아 있는지만 본다. 발급은 head 를 쓰지 않는다. */
async function chainAlive(chainStr) { await headOf(chainStr); }
/** 사용자당 활성 자격증명 하나(설계 §3.1). 없으면 null. */
function activeCred(uid) {
  return (state.accounts[uid]?.creds ?? []).find((c) => !c.revoked) ?? null;
}
/** 활성 자격증명을 revoked 로 돌리고 리프를 트리·pending 에 넣는다. 돌려주는 값은 새로 들어간 리프 목록(멱등). */
async function retireActiveCred(uid) {
  const inserted = [];
  for (const c of state.accounts[uid]?.creds ?? []) {
    if (c.revoked) continue;
    c.revoked = true;
    if (await tree.insert(BigInt(c.leaf))) { state.revoked.push(c.leaf); state.pending.push(c.leaf); inserted.push(c.leaf); }
  }
  return inserted;
}

// ---- 앱 ----
const app = express();
app.use(express.json({ limit: '256kb' }));

// 관리자 패널(스펙 §5). 페이지 하나만 허용 목록으로 내보낸다 — express.static 은 쓰지 않는다.
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'cia_admin.html')));

// 사용자 페이지(§6.5.1). 잃어버린 지갑이 아니라 어느 장치에서든 열 수 있어야 하므로 CIA 가 직접 낸다.
app.get('/account', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'cia_account.html')));

app.get('/cia/public_keys', (req, res) => {
  res.json({ pk_CIA: S(ciaPub), ethAddress: ethWallet.address, heartbeatBlocks: Number(HEARTBEAT_BLOCKS), chainIds: [...CHAIN_RPCS.keys()], logAddress: LOG_ADDRESS });
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
    // CIA 조각 X_AA 와 그 지식 증명(2026-09-21, rogue key 방지). 저장하지 않고 x_AA 로 매번 새로 낸다 — 옛 상태 파일의 승인 항목에도 그대로 나간다.
    // 서비스는 pk_trace = X_svc + X_AA 와 PoK 를 확인한다(mode3_rp.js). 지갑은 cert_s 만 본다 — 인증서 형식은 그대로다.
    const pok = await proveShare(BigInt(e.x_AA), { arid: BigInt(arid), X_svc: pointFromStrings(e.X_svc) });
    const S = (o) => ({ x: o.x.toString(), y: o.y.toString() });
    res.json({ arid, name: e.name, origin, pk_trace: e.pk_trace, cert_s, X_AA: S(pok.X), share_pok: { T: S(pok.T), c: pok.c.toString(), z: pok.z.toString() } });
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
  state.accounts[uid] = { pk_u: S(pub), cm_u: { x: cm_u.x, y: cm_u.y }, disabled: false, creds: [], attrs: [...acct.attrs] };
  persist();
  res.status(201).json({ pk_u: S(pub), sk_u: prv.toString('hex'), attrs: state.accounts[uid].attrs });
});

// §4.1(2026-09-21) 사용자 자격증명 발급. 세션과 무관 — 속성이 바뀔 때만 다시 온다. AA 서명은 없다(세션 서명이 Cf_u 를 덮는다).
// 검사 순서: 형식 → 계정·disabled → C_u_pt 부분군 → sig_u → π_u → 기록. 이미 활성 자격증명이 있으면 그것을 물리고(리프 → pending) 새 것을 활성으로.
app.post('/cia/user_cred', async (req, res) => {
  try {
    const { uid, C_u_pt, proof, sig_u } = req.body ?? {};
    if (!isDec(uid) || !isPt(C_u_pt) || !proof || !sig_u) return res.status(400).json({ error: 'uid, C_u_pt, proof, sig_u required' });
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });
    const cpt = pointFromStrings(C_u_pt);
    if (!(await isValidPoint(cpt))) return res.status(400).json({ error: 'C_u_pt is not a valid subgroup point' });
    let sigOk = false;
    try {
      const m = F.e(await userCredRequestMessage(cpt));
      sigOk = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) }, [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))]);
    } catch { sigOk = false; }
    if (!sigOk) return res.status(400).json({ error: 'bad user signature' });
    let proofOk = false;
    // 속성은 AA 기록(acct.attrs) — 요청의 값은 받지 않는다(2026-09-22 §3.4).
    try { proofOk = await verifyUserCred({ uid: BigInt(uid), attrs: acct.attrs.map(BigInt), C_u_pt: cpt, cm_u: pointFromStrings(acct.cm_u), proof: parseUserCredProof(proof) }); }
    catch { proofOk = false; }
    if (!proofOk) return res.status(400).json({ error: 'bad user credential proof' });
    const Cf_u = (await compressPoint(cpt)).toString();
    const leaf = (await userLeaf(BigInt(Cf_u))).toString();
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });   // await 사이에 폐기가 끼어들 수 있다
    acct.creds ??= [];
    if (acct.creds.some((c) => c.Cf_u === Cf_u && c.revoked)) return res.status(409).json({ error: 'this user credential was revoked; make a new one' });
    // 활성 자격증명을 물리고 새 것을 활성으로. retireActiveCred 안의 await(리프 삽입) 동안 같은 uid 의 다른 user_cred 가
    // 먼저 push 했거나 /cia/revoke·self_revoke 가 disabled 를 걸었을 수 있다 — 활성이 없어질 때까지 반복하고, 마지막 await
    // 뒤(아래는 전부 동기)에 disabled 와 같은 Cf_u 의 폐기 여부를 다시 본다. 어느 순서로 끼어들어도 활성은 정확히 하나고,
    // disabled 계정에 활성 자격증명이 남지 않는다.
    for (;;) {
      const cur = activeCred(uid);
      if (cur && cur.Cf_u === Cf_u) return res.json({ Cf_u, leaf });   // 멱등 — 동시에 온 같은 Cf_u 가 먼저 기록된 경우 포함
      if (!cur) break;
      await retireActiveCred(uid);
    }
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });   // 위 await 동안 폐기가 끼어들었다
    if (acct.creds.some((c) => c.Cf_u === Cf_u)) return res.status(409).json({ error: 'this user credential was revoked; make a new one' });   // 여기 오면 같은 Cf_u 는 전부 revoked
    acct.creds.push({ Cf_u, C_u_pt: { x: cpt.x.toString(), y: cpt.y.toString() }, leaf, issuedAt: new Date().toISOString(), revoked: false });
    persist();
    res.status(201).json({ Cf_u, leaf });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// 2026-09-22 §3.3 지갑이 자기 속성을 다시 받는다 — user_cred 가 bad proof 로 거절됐을 때(AA 기록이 바뀜). sk_u 서명으로 인증.
app.post('/cia/attrs', async (req, res) => {
  try {
    const { uid, nonce, sig_u } = req.body ?? {};
    if (!isDec(uid) || !isDec(nonce) || !sig_u) return res.status(400).json({ error: 'uid, nonce, sig_u required' });
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    let ok = false;
    try {
      const m = F.e(await attrsRequestMessage(BigInt(uid), BigInt(nonce)));
      ok = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) }, [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))]);
    } catch { ok = false; }
    if (!ok) return res.status(400).json({ error: 'bad user signature' });
    res.json({ attrs: acct.attrs });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// 2026-09-22 §3.3 관리자가 속성을 바꾼다. 활성 자격증명은 옛 속성이라 물린다(리프 → 다음 게시). 지갑은 다음 발급에서 재동기화한다.
app.post('/cia/accounts/:uid/attrs', requireAdmin, async (req, res) => {
  try {
    const uid = req.params.uid;
    const acct = state.accounts[uid];
    if (!isDec(uid) || !acct) return res.status(404).json({ error: 'unknown account' });
    // 관리자 변경은 길이 4 배열만 받는다 — normalizeAttrs 의 0 패딩(발급 경로엔 필요)이 여기서는 "본문 없는 호출 한 번에
    // 속성 4칸이 0" 이 되고 옛 C_u 리프가 append-only 트리에 들어가 되돌릴 수 없다(2026-09-23 점검 A-I2).
    const raw = req.body?.attrs;
    if (!Array.isArray(raw) || raw.length !== ATTR_SLOTS) return res.status(400).json({ error: `attrs 는 길이 ${ATTR_SLOTS} 배열이어야 한다` });
    // 길이만 보면 빈 칸이 통과한다 — BigInt('') === 0n 이라 관리자 UI(mode3/cia_admin.html 의 `i.value.trim()`)가 보낸
    // 빈 슬롯이 조용히 0 이 되고, 바로 아래 retireActiveCred 가 옛 C_u 리프를 append-only 트리에 게시해 되돌릴 수 없다
    // (2026-09-23 최종 리뷰 M2 — 점검 A-I2 의 현실적 트리거).
    if (!raw.every((v) => /^[0-9]+$/.test(String(v)))) return res.status(400).json({ error: 'attrs 원소는 10진 문자열' });
    let attrs;
    try { attrs = normalizeAttrs(raw).map(String); } catch (e) { return res.status(400).json({ error: `attrs: ${e.message}` }); }
    acct.attrs = attrs;
    const inserted = await retireActiveCred(uid);
    persist();
    res.json({ uid, attrs, inserted });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// §4.2(2026-09-21) 세션 발급 V5. ZKP 없음 — uid·s_u 는 사용자 자격증명 발급 때 π_u 로 이미 증명됐다.
// 검사 순서: 형식 → max_height 범위 → 계정·disabled → chainid 허용 → sig_u → 활성 Cf_u 조회 → C_s_pt 부분군 → 체인 생존(fail-closed) →
// disabled·활성 재확인 → 서명. 기록하지 않는다.
app.post('/cia/issue', async (req, res) => {
  try {
    const { uid, Cf_u, C_s_pt, sig_u, chainid, allowAgent, max_height } = req.body ?? {};
    if (!isDec(uid) || !isDec(Cf_u) || !isPt(C_s_pt) || !sig_u || !isDec(chainid) || (allowAgent !== '0' && allowAgent !== '1') || !isDec(max_height)) {
      return res.status(400).json({ error: 'uid, Cf_u, C_s_pt, sig_u, chainid, allowAgent("0"|"1"), max_height required' });
    }
    const mh = BigInt(max_height);
    if (mh >= (1n << 64n)) return res.status(400).json({ error: 'max_height must be < 2^64' });
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    if (acct.disabled) return res.status(403).json({ error: 'account disabled', reason: 'account_disabled' });
    const chainStr = BigInt(chainid).toString();
    if (CHAIN_RPCS.size === 0) return res.status(503).json({ error: 'chain id unknown: CIA_CHAIN_RPCS not configured and RPC unreachable at startup' });
    if (!CHAIN_RPCS.has(chainStr)) return res.status(400).json({ error: `bad chainid ${chainStr}: allowed ${[...CHAIN_RPCS.keys()].join(',')}` });
    const agent = BigInt(allowAgent);
    const cfu = BigInt(Cf_u);
    const cspt = pointFromStrings(C_s_pt);
    let sigOk = false;
    try {
      const m = F.e(await issueRequestMessageV4(cfu, cspt, BigInt(chainStr), agent, mh));
      sigOk = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) }, [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))]);
    } catch { sigOk = false; }
    if (!sigOk) return res.status(400).json({ error: 'bad user signature' });
    const cred = activeCred(uid);
    if (!cred || cred.Cf_u !== cfu.toString()) return res.status(403).json({ error: 'no active user credential for this Cf_u', reason: 'no_user_cred' });
    if (!(await isValidPoint(cspt))) return res.status(400).json({ error: 'C_s_pt is not a valid subgroup point' });
    const Cf_s = await compressPoint(cspt);
    await chainAlive(chainStr);   // fail-closed: 체인이 죽어 있으면 발급하지 않는다(게시도 불가하므로 폐기가 닿지 않는 세션이 된다)
    if (acct.disabled || activeCred(uid)?.Cf_u !== cfu.toString()) return res.status(403).json({ error: 'account disabled or credential retired', reason: 'no_user_cred' });   // await 사이의 폐기
    const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessageV5(cfu, Cf_s, mh, BigInt(chainStr), agent)));
    // V8(2026-09-24 §2.1): 세션 단위 폐기를 하려면 CIA 가 Cf_s 를 알아야 한다. 기록은 만료 뒤 하트비트가 지운다.
    acct.sessions ??= [];
    acct.sessions.push({ Cf_s: Cf_s.toString(), max_height: mh.toString(), chainid: chainStr, allowAgent: agent.toString(), issuedAt: new Date().toISOString(), revokedAt: null });
    persist();
    res.json({
      Cf_u: cfu.toString(), Cf_s: Cf_s.toString(), max_height: mh.toString(), chainid: chainStr, allowAgent: agent.toString(),
      sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() },
      pk_CIA: S(ciaPub),
    });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// §6.5 계정 전체 폐기: 활성 사용자 자격증명의 리프 삽입 + disabled. 관리자 폐기(/cia/revoke scope=account)와
// 사용자 자기 폐기(/cia/account/self_revoke, §6.5.1)가 같은 처리를 탄다 — 다른 것은 "누가 개시하느냐"뿐이다.
// 리프는 Cf_u 하나에서 나오므로(2026-09-21 §3.6) 체인 헤드를 읽지 않고, tree.insert 의 멱등성으로 두 번 불러도 새 리프가 없다.
async function revokeAccount(uid) {
  const acct = state.accounts[uid];
  if (!acct) throw Object.assign(new Error('unknown account'), { status: 404 });
  acct.disabled = true;
  const inserted = await retireActiveCred(uid);
  persist();
  return { inserted, root: tree.getRoot().toString(), pending: state.pending.length };
}

// §4.3(2026-09-21) 폐기. account = 활성 사용자 자격증명 리프 + disabled. credential = 리프만(계정은 살아 있어 새 user_cred 를 받아야 한다).
// 리프는 사용자당 하나라 leaf/C 인자를 받지 않는다(있어도 무시). 트리 삽입은 멱등(이미 있으면 false).
// V8(2026-09-24 §2.2) session = 세션 하나만 — 사용자는 sk_u 서명으로, 운영자는 관리자 시크릿으로. 그래서 requireAdmin 을 미들웨어로
// 걸지 않고 안에서 분기한다. 관리자 헤더가 틀리게 오면 isAdmin=false 라 scope=session 은 서명 경로로 흐르고 account/credential 은 401 이다.
app.post('/cia/revoke', async (req, res) => {
  try {
    const { uid, scope, Cf_s, sig_u, nonce } = req.body ?? {};
    const hdr = req.get('X-CIA-Admin-Secret');
    const isAdmin = Boolean(ADMIN_SECRET) && typeof hdr === 'string' && secretMatches(hdr, ADMIN_SECRET);
    if (scope !== 'session') {   // requireAdmin 과 같은 응답을 그대로 유지한다(시크릿 미설정 503, 틀린 시크릿 401)
      if (!ADMIN_SECRET) return res.status(503).json({ error: 'admin endpoints disabled: CIA_ADMIN_SECRET is not configured' });
      if (!isAdmin) return res.status(401).json({ error: 'unauthorized' });
    }
    if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
    if (scope === 'account') return res.json(await revokeAccount(uid));
    if (scope === 'credential') {
      const inserted = await retireActiveCred(uid);
      persist();
      return res.json({ inserted, root: tree.getRoot().toString(), pending: state.pending.length });
    }
    if (scope !== 'session') return res.status(400).json({ error: "scope must be 'account', 'credential' or 'session'" });
    if (!isDec(Cf_s)) return res.status(400).json({ error: 'Cf_s required' });
    const acct = state.accounts[uid];
    const rec = (acct.sessions ?? []).find((s) => s.Cf_s === BigInt(Cf_s).toString());
    // 서명은 기록 조회보다 먼저 본다 — 서명 없이 "그 Cf_s 가 이 계정에 있는지" 를 알아내지 못하게.
    if (!isAdmin) {
      if (!sig_u || !isDec(nonce)) return res.status(401).json({ error: 'sig_u and nonce required without admin secret' });
      let ok = false;
      try {
        const m = F.e(await revokeSessionMessage(BigInt(uid), BigInt(Cf_s), BigInt(nonce)));
        ok = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) }, [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))]);
      } catch { ok = false; }
      if (!ok) return res.status(400).json({ error: 'bad user signature' });
    }
    if (!rec) return res.status(404).json({ error: 'unknown session', reason: 'unknown_session' });
    if (rec.revokedAt) return res.json({ inserted: false, root: tree.getRoot().toString(), pending: state.pending.length });
    // 만료된 세션은 리프를 넣지 않는다 — append-only 트리를 이미 죽은 세션으로 불리는 일이다(설계 §6).
    if ((await headOf(rec.chainid)) >= BigInt(rec.max_height)) return res.status(409).json({ error: 'session expired', reason: 'expired' });
    const leaf = (await sessionLeaf(BigInt(Cf_s))).toString();
    // 위 await 들 사이에 하트비트의 pruneExpiredSessions() 가 acct.sessions 를 통째로 갈아끼울 수 있다 — 그러면 rec 은 버려진
    // 객체라 revokedAt 이 아무 데도 안 남고, 그 사이 만료된 세션에 리프만 들어간다. 삽입 직전에 다시 찾는다.
    const cur = (acct.sessions ?? []).find((s) => s.Cf_s === BigInt(Cf_s).toString());
    if (!cur) return res.status(409).json({ error: 'session expired', reason: 'expired' });
    const inserted = await tree.insert(BigInt(leaf));
    if (inserted) { state.revoked.push(leaf); state.pending.push(leaf); }
    cur.revokedAt = new Date().toISOString();
    persist();
    res.json({ inserted, leaf, root: tree.getRoot().toString(), pending: state.pending.length });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// V8(2026-09-24 §2.3) 관리자 세션 목록. expired 는 그 체인 헤드로 계산하고, 못 읽으면 null(모름)이다.
app.get('/cia/admin/sessions', requireAdmin, async (req, res) => {
  const uid = String(req.query.uid ?? '');
  if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
  const heads = {};
  const out = [];
  for (const s of state.accounts[uid].sessions ?? []) {
    if (heads[s.chainid] === undefined) { try { heads[s.chainid] = await headOf(s.chainid); } catch { heads[s.chainid] = null; } }
    out.push({ ...s, expired: heads[s.chainid] === null ? null : heads[s.chainid] >= BigInt(s.max_height) });
  }
  res.json({ sessions: out });
});

// §6.5 게시. 서명이 리프 배열까지 덮는다 — 릴레이어의 calldata 오염 방지. 로그 주소도 덮는다 —
// 같은 CIA 키로 재배포한 다른 로그에 옛 게시를 재생하지 못하게(재생되면 root 가 옛 트리로 바뀐다).
// digest 계산은 lib/mode3_log.js 하나다(컨트랙트의 digestFor 와 바이트 단위로 같다).
//
// 게시는 한 번에 하나만 돈다. 둘이 겹치면 각자 pending 을 자기 개수만큼 앞에서 잘라, 그 사이 들어온
// revoke 의 리프가 pending 에서만 사라진다 — 트리·서명 root 에는 남아 지갑 재구성이 영구히 실패한다.
// 관리자 페이지의 게시 버튼을 두 번 누르는 것이 그 경로다.
let publishing = false;
/**
 * root 게시. heartbeat=true 면 pending 이 비어 있어도 같은 root 를 새 epoch 로 올린다(설계 §4.5) — 컨트랙트 조건은 epoch
 * 증가뿐이라 그대로다. 한 번에 하나만 돈다: 둘이 겹치면 각자 pending 을 자기 개수만큼 앞에서 잘라 그 사이 들어온 revoke 의
 * 리프가 pending 에서만 사라진다(트리·서명 root 에는 남아 지갑 재구성이 영구히 실패).
 */
async function publishNow({ heartbeat = false } = {}) {
  if (publishing) throw Object.assign(new Error('publish already in progress'), { status: 409 });
  publishing = true;
  try {
    if (!LOG_ADDRESS) throw Object.assign(new Error('CIA_LOG_ADDRESS not configured'), { status: 503 });
    // 게시 직전 대조(기동 시와 같은 규칙). 온체인 root 가 우리가 아는 어느 접두사와도 다르면 올리지 않는다.
    let chain;
    try { chain = await readChain(); }
    catch (e) { throw Object.assign(new Error(`chain unavailable: ${e.message}`), { status: 503 }); }
    if (!(await reconcileWithChain(chain))) {
      publishedTree = await buildPublishedTree();   // 걷다 만 트리를 되돌린다
      throw Object.assign(new Error(`onchain root ${chain.onchainRoot} 가 로컬 게시 기록의 어느 접두사와도 다르다 — ` +
        `로그를 재배포했거나 상태 파일이 유실·복원됐다. CIA_STATE_FILE 과 CIA_LOG_ADDRESS 를 확인할 것`), { status: 503 });
    }
    if (state.pending.length === 0 && !heartbeat) return { published: false, heartbeat: false, epoch: state.epoch, root: tree.getRoot().toString() };
    const log = new ethers.Contract(LOG_ADDRESS, LOG_ABI, ethWallet);
    const leaves = state.pending.map(rootToBytes32);
    const root = rootToBytes32(tree.getRoot());
    const epoch = state.epoch + 1;   // reconcileWithChain 이 state.epoch 를 온체인과 맞췄다
    const sig = await signRootPublication(ethWallet, { logAddress: LOG_ADDRESS, root, epoch, leaves });
    const tx = await log.publishRoot(root, epoch, leaves, sig);
    await tx.wait();
    state.epoch = epoch;
    // 위 await 들 사이에 pending 뒤에 붙은 리프는 이번 tx 에 실리지 않았다 — 이번에 실은 앞부분만 지운다.
    for (const l of state.pending.slice(0, leaves.length)) await publishedTree.insert(BigInt(l));
    state.pending = state.pending.slice(leaves.length);
    persist();
    return { published: true, heartbeat: leaves.length === 0, epoch, root: tree.getRoot().toString(), txHash: tx.hash, leaves };
  } finally { publishing = false; }
}
app.post('/cia/publish', requireAdmin, async (req, res) => {
  try { res.json(await publishNow()); }
  catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});
/** 하트비트 틱(설계 §4.5): 마지막 게시에서 HEARTBEAT_BLOCKS 이상 지났으면 재게시. pending 이 있으면 그것도 같이 나간다. */
async function heartbeatTick() {
  if (publishing || !LOG_ADDRESS) return;
  try {
    await pruneExpiredSessions();   // try 안에 둔다 — setInterval 콜백이라 여기서 던지면 unhandled rejection 이다
    const log = new ethers.Contract(LOG_ADDRESS, LOG_ABI, ethWallet);
    const [head, last] = await Promise.all([ethWallet.provider.getBlockNumber(), log.lastPublishedBlock()]);
    if (BigInt(head) - BigInt(last) < HEARTBEAT_BLOCKS) return;
    const r = await publishNow({ heartbeat: true });
    console.log(`[cia] 하트비트 게시: epoch ${r.epoch}, 리프 ${r.leaves.length}개, head ${head}`);
  } catch (e) { console.warn(`[cia] 하트비트 실패: ${e.message}`); }
}

/** V8: 만료된 세션 기록 삭제(리프는 남는다 — 설계 §6). 체인별 head 는 한 번만 읽는다. */
async function pruneExpiredSessions() {
  const heads = {};
  let dropped = 0;
  for (const acct of Object.values(state.accounts)) {
    if (!acct.sessions?.length) continue;
    const keep = [];
    for (const s of acct.sessions) {
      if (heads[s.chainid] === undefined) { try { heads[s.chainid] = await headOf(s.chainid); } catch { heads[s.chainid] = null; } }
      if (heads[s.chainid] !== null && heads[s.chainid] >= BigInt(s.max_height)) dropped++; else keep.push(s);
    }
    acct.sessions = keep;
  }
  if (dropped) persist();
}

app.post('/cia/account/set_disabled', requireAdmin, (req, res) => {
  const { uid, disabled } = req.body ?? {};
  if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
  state.accounts[uid].disabled = Boolean(disabled);
  persist();
  res.json({ uid, disabled: state.accounts[uid].disabled });
});

// 관리자 계정 목록(관리 페이지의 속성 편집용). activeCred 는 위의 기존 헬퍼(사용자당 활성 자격증명 하나).
app.get('/cia/accounts', requireAdmin, (req, res) => res.json({
  accounts: Object.entries(state.accounts).map(([uid, a]) => ({ uid, disabled: a.disabled, attrs: a.attrs, activeCf_u: activeCred(uid)?.Cf_u ?? null })),
}));

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
    // 리프는 활성 사용자 자격증명 하나에서 나오고 체인을 읽지 않으므로(2026-09-21 §3.6) 체인이 죽어 있어도 걸린다.
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
    // V7(2026-09-23): 공개 입력 25개 — 태그 위치([11..13])는 그대로라 개봉 로직은 바뀌지 않는다.
    if (!isDec(arid) || !Array.isArray(publicSignals) || publicSignals.length !== 25 || !publicSignals.every(isDec) || !proof || !isPt(D_svc) || !isDec(ts) || typeof sig !== 'string') {
      return res.status(400).json({ error: 'arid, publicSignals[25], proof, D_svc{x,y}, ts, sig required' });
    }
    if (!(await isTracePoint(pointFromStrings(D_svc)))) return res.status(400).json({ error: 'D_svc is not a valid subgroup point' });
    const e = state.rps[arid];
    if (!e) return res.status(404).json({ error: 'unknown_service' });
    if (e.status !== 'approved' || !e.pk_service || !e.pk_trace) return res.status(403).json({ error: 'not_approved' });
    if (!isFreshTs(ts)) return res.status(401).json({ error: 'stale' });
    // 정규 10진으로 맞춘다(앞자리 0 허용 입력 대비 — 서명 메시지·문자열 비교·저장 전부 정규형 위에서, 2026-09-18 점검 1).
    const ps = publicSignals.map((v) => BigInt(v).toString());
    const [PPID, aridIn, , max_height, chainIn, allowAgent, , ciaX, ciaY, traceX, traceY, c1x, c1y, c2] = ps;
    if (recoverSigner(openRequestMessage({ arid, PPID, c1: { x: c1x, y: c1y }, D_svc, ts }), sig) !== e.pk_service) return res.status(401).json({ error: 'bad_signature' });
    if (aridIn !== arid) return res.status(403).json({ error: 'wrong_arid' });
    const pk = S(ciaPub);
    if (ciaX !== pk.x || ciaY !== pk.y) return res.status(403).json({ error: 'untrusted_cia' });
    if (traceX !== e.pk_trace.x || traceY !== e.pk_trace.y) return res.status(403).json({ error: 'wrong_trace_key' });
    if (!CHAIN_RPCS.has(BigInt(chainIn).toString())) return res.status(403).json({ error: 'wrong_chain' });
    if (BigInt(allowAgent) > 1n) return res.status(403).json({ error: 'bad_allow_agent' });
    if (c1x === '0' && c1y === '1') return res.status(403).json({ error: 'bad_tag' });   // r = 0 — 서비스·컨트랙트와 같은 규칙(심층 방어)
    let vkey;
    try { vkey = await loadVkey(); } catch (err) { return res.status(503).json({ error: `vkey unavailable: ${err.message}` }); }
    let ok = false;
    try { ok = await snarkjs.groth16.verify(vkey, ps, proof); }
    catch (err) { console.warn('[cia] 개봉 요청의 증명 검증 예외 — vkey/회로 불일치일 수 있다: ' + err.message); ok = false; }
    if (!ok) return res.status(403).json({ error: 'bad_proof' });
    // pending 이거나, approved 지만 uid 를 찾은(resolved:true) 경우는 같은 (arid, c1) 의 결정이 이미 있거나
    // 진행 중이라 그 id 를 돌려준다. denied 와 approved+resolved:false(틀린 D_svc — 서비스 자신의 요청만 망친다,
    // §6.2)는 새 요청을 허용한다 — 거절된 세션을 다시 심사에 올리거나 서비스가 D_svc 를 고쳐 다시 낼 길이
    // 있어야 한다. arid 대조가 없으면 유출된 남의 로그로 연다.
    // dup 키는 (arid, c1, c2, PPID) — c1 = r·B8 은 사용자와 무관해 두 사용자가 같은 r 을 쓰면 겹친다(2026-09-23 점검 A-I1).
    // c2·PPID 까지 같아야 "같은 트랜스크립트"다. 아니면 뒤 요청이 앞 사용자의 승인 항목을 받아 uid 가 오귀속된다.
    const dup = state.openings.find((o) => o.arid === arid && o.c1.x === c1x && o.c1.y === c1y && o.c2 === c2 && o.PPID === PPID
      && (o.status === 'pending' || (o.status === 'approved' && o.resolved !== false)));
    if (dup) return res.status(200).json({ id: dup.id, status: dup.status });
    const id = randomBytes(32).toString('hex');
    state.openings.push({ id, arid, PPID, c1: { x: c1x, y: c1y }, c2, D_svc: { x: D_svc.x, y: D_svc.y }, allowAgent, max_height, chainid: chainIn, status: 'pending', requestedAt: new Date().toISOString(), decidedAt: null, uid: null, resolved: null });
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
    const h = await combineDecrypt(BigInt(o.c2), pointFromStrings(o.D_svc), D_aa);
    // 평문은 Poseidon(uid, arid)(2026-09-18 §3.4) — 등록부의 uid 마다 계산해 되찾는다. 못 찾으면 D_svc 가 틀렸거나(서비스 자신의
    // 요청만 망친다) 계정이 등록부에 없는 것이다. 어느 쪽이든 approved 로 기록하되 resolved=false 로 남긴다(§6.2).
    const uid = await resolveTagPlaintext(h, BigInt(o.arid), Object.keys(state.accounts));
    o.decidedAt = new Date().toISOString();
    o.status = 'approved'; o.uid = uid; o.resolved = uid !== null;
    persist();
    res.json({ id: o.id, status: o.status, resolved: o.resolved });
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
  res.json({ id: o.id, status: o.status, uid: o.uid, resolved: o.resolved, PPID: o.PPID, allowAgent: o.allowAgent, max_height: o.max_height, chainid: o.chainid, decidedAt: o.decidedAt });
});

app.get('/cia/state', async (req, res) => {
  let head = null;
  try { head = (await headHeight()).toString(); } catch { /* 체인 없음 */ }
  const credCount = Object.values(state.accounts).reduce((n, a) => n + (a.creds ?? []).filter((c) => !c.revoked).length, 0);
  res.json({ root: tree.getRoot().toString(), epoch: state.epoch, pendingCount: state.pending.length, leafCount: state.revoked.length, credCount, head });
});

// ---- 기동 ----
eddsa = await buildEddsa();
poseidon = await buildPoseidon();
F = poseidon.F;
loadOrCreateKeys();
await loadState();
if (HEARTBEAT_BLOCKS > 0n) {
  const hb = setInterval(heartbeatTick, HEARTBEAT_POLL_MS);
  hb.unref();
}
// RP·지갑 에이전트와 같이 루프백에만 묶는다 — 관리자·사용자 페이지와 발급 경로를 LAN 에 노출하지 않는다.
app.listen(PORT, '127.0.0.1', () => {
  console.log(`Mode 3 CIA running at http://127.0.0.1:${PORT} (log=${LOG_ADDRESS ?? 'none'}, heartbeat=${HEARTBEAT_BLOCKS}, chains=${[...CHAIN_RPCS.keys()].join(',') || 'none'}, vkey=${fs.existsSync(VKEY_PATH) ? 'ok' : 'missing'})`);
});
