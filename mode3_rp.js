// Mode 3 RP (:3100). 스펙: docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md §4
//
// server.js(:3000, Mode 1/2)와 나란히 두는 별도 프로세스다. 그쪽 코드를 import 하지 않는다.
// 검증(설계 §6.3 7단계)은 전부 lib/mode3_rp.js 에 있고 여기는 등록·challenge 관리 + HTTP 만이다.
// 세션은 메모리 Map(r_s → PPID·pk_i·max_height·allowAgent·root) 뿐이고 쿠키는 없다 — 데모의 요점은 검증 결과다(스펙 §4.2).
// V4(2026-09-18): 팩토리 배포(§6.1), 로그인 V4(max_height·allowAgent, σ 는 서버 챌린지 위), 트랜잭션 해시 개봉(§6.2).
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
import { createShare, partialDecrypt, combinePublicKey, verifyShare } from './lib/mode3_trace.js';
import { signOpenRequest, signOpenResult } from './lib/mode3_opening.js';
import { deployVerifier, deployFactory, deployAttrGate, decodeExecuteCalldata, parseExecuteReceipt, FACTORY_ABI, MAX_ROOT_AGE_DEFAULT, MAX_LIFETIME_DEFAULT } from './lib/mode3_onchain.js';

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
// CIA 가 알려 준 하트비트 주기(블록). 아래 TOFU 경로에서만 받는다 — pk_CIA 를 env 로 박으면 CIA 에 묻지 않으므로 null 이고,
// 그때는 maxRootAge 와 대조할 수 없다(경고를 위해 새 RPC·HTTP 호출을 만들지는 않는다. 2026-09-23 최종 리뷰 M4).
let ciaHeartbeatBlocks = null;
async function resolvePkCia() {
  const { MODE3_PK_CIA_X: x, MODE3_PK_CIA_Y: y } = process.env;
  if (x && y) return { x: BigInt(x), y: BigInt(y), source: 'env' };
  const r = await fetch(`${CIA_URL}/cia/public_keys`);
  if (!r.ok) throw new Error(`CIA ${CIA_URL} 에서 pk_CIA 를 받지 못했다 (${r.status})`);
  const k = await r.json();
  if (Number.isFinite(k.heartbeatBlocks)) ciaHeartbeatBlocks = BigInt(k.heartbeatBlocks);
  console.warn(`[rp] pk_CIA 를 CIA 에서 받아 고정한다(TOFU). 운영이라면 env 로 박는다:\n  MODE3_PK_CIA_X=${k.pk_CIA.x}\n  MODE3_PK_CIA_Y=${k.pk_CIA.y}`);
  return { x: BigInt(k.pk_CIA.x), y: BigInt(k.pk_CIA.y), source: 'tofu' };
}

const pkCIA = await resolvePkCia();

// ---- 서비스 등록(설계 2026-09-16 §3) ----
// 키 둘: secp256k1 서명키(pk_service, 개봉 요청)와 Baby Jubjub 조각(x_svc, 태그). 첫 기동에서 만들어 파일에 두고 CIA 에
// 등록한다. CIA 는 pending 으로 받고 운영자가 승인하면 조합 키 pk_trace 와 cert_s 를 준다 — 그때까지는 대기 상태로 뜬다.
const REG_FILE = process.env.MODE3_RP_REGISTRATION_FILE || path.join(__dirname, 'mode3_rp_registration.json');
const REG_VERSION = 3;
const PUBLIC_ORIGIN = process.env.MODE3_RP_PUBLIC_ORIGIN || `http://127.0.0.1:${PORT}`;
const RP_NAME = process.env.MODE3_RP_NAME || 'demo-rp';
const POLL_MS = Number(process.env.MODE3_RP_REGISTRATION_POLL_MS) || 5000;
const LOGIN_LOG = process.env.MODE3_RP_LOGIN_LOG || path.join(__dirname, 'mode3_rp_logins.jsonl');
if (fs.existsSync(LOGIN_LOG)) fs.chmodSync(LOGIN_LOG, 0o600);   // 옛 실행이 남긴 파일의 권한도 조인다

let reg = readJson(REG_FILE, null);
// v2 → v3(2026-09-18): 팩토리·검증자 주소 필드. 조각(x_svc)은 그대로 — 버리면 이전 로그인 로그의 태그를 열 수 없다.
if (reg && reg.version === 2) { reg = { ...reg, version: 3, factoryAddress: null, verifierAddress: null }; writeJsonAtomic(REG_FILE, reg, 0o600); }
if (reg && (reg.version !== REG_VERSION || reg.origin !== PUBLIC_ORIGIN)) {
  console.warn(`[rp] 등록 파일이 옛 형식이거나 origin(${reg.origin}) 이 현재(${PUBLIC_ORIGIN}) 와 달라 새로 등록한다` +
    ` — 옛 서비스 조각(x_svc)도 버려지므로 이전 로그인 로그의 태그는 더 이상 열 수 없다`);
  reg = null;
}
if (!reg) {
  const w = ethers.Wallet.createRandom();
  const share = await createShare();
  // attrGateAddress: 배포된 AttrGate 주소. attrGateFactory: 그 배포에 실제로 쓰인 factoryAddress — 팩토리가
  // 바뀌면(재배포로 factoryAddress 가 달라지면) ensureAttrGate() 가 이 값과 비교해 다시 배포할지 정한다(2026-09-22 리뷰).
  reg = { version: REG_VERSION, origin: PUBLIC_ORIGIN, pk_service: w.address, sk_service: w.privateKey, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() }, x_svc: share.x.toString(), status: 'pending', arid: null, pk_trace: null, cert_s: null, issuedAt: null, factoryAddress: null, verifierAddress: null, attrGateAddress: null, attrGateFactory: null };
  writeJsonAtomic(REG_FILE, reg, 0o600);
}
const serviceWallet = new ethers.Wallet(reg.sk_service);

/** pk_trace == X_svc + X_AA 이고 X_AA 의 Schnorr PoK 가 (arid, X_svc) 에 대해 검증되는가. 형식이 깨지면 false. */
async function verifyCiaShare(arid, pk_trace, X_AA, share_pok) {
  try {
    const P = (o) => ({ x: BigInt(o.x), y: BigInt(o.y) });
    const X_svc = P(reg.X_svc), Xaa = P(X_AA), pt = P(pk_trace);
    const pok = { T: P(share_pok.T), c: BigInt(share_pok.c), z: BigInt(share_pok.z) };
    if (!(await verifyShare(Xaa, pok, { arid: BigInt(arid), X_svc }))) return false;
    const sum = await combinePublicKey(X_svc, Xaa);
    return sum.x === pt.x && sum.y === pt.y;
  } catch { return false; }
}

/** CIA 에 등록/조회. 200 이면 파일을 채우고 true. 202 면 false. 403 이면 throw. */
async function registerOnce() {
  const r = await fetch(`${CIA_URL}/cia/register_rp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: RP_NAME, origin: PUBLIC_ORIGIN, pk_service: reg.pk_service, X_svc: reg.X_svc }) });
  const b = await r.json().catch(() => ({}));
  if (r.status === 202) { reg.arid = b.arid; reg.status = 'pending'; writeJsonAtomic(REG_FILE, reg, 0o600); return false; }
  // 403(거절)은 영구 상태로 기록한다. 408·429 를 뺀 나머지 4xx(예: 409 service_key_mismatch, 400 형식 오류)도
  // 재시도해 봤자 같은 응답이 반복될 뿐이라 영구 실패다 — CIA 가 죽었거나 네트워크가 끊긴 것(5xx·예외)만 일시적이라 계속 재시도한다.
  if (r.status === 403) { reg.arid = b.arid; reg.status = 'denied'; writeJsonAtomic(REG_FILE, reg, 0o600); throw Object.assign(new Error(`CIA 가 등록을 거절했다 (arid=${b.arid})`), { permanent: true }); }
  if (r.status >= 400 && r.status < 500 && r.status !== 408 && r.status !== 429) {
    throw Object.assign(new Error(`CIA 등록 실패 (${r.status}) ${JSON.stringify(b)}`), { permanent: true });
  }
  if (r.status !== 200) throw new Error(`CIA 등록 실패 (${r.status}) ${JSON.stringify(b)}`);
  const pk_trace = { x: BigInt(b.pk_trace.x), y: BigInt(b.pk_trace.y) };
  if (!(await verifyRpCert(pkCIA, { arid: BigInt(b.arid), origin: PUBLIC_ORIGIN, pk_trace, cert: b.cert_s }))) throw Object.assign(new Error('CIA 가 준 cert_s 가 pk_CIA 로 검증되지 않는다'), { permanent: true });
  // CIA 조각 검사(2026-09-21, rogue key 방지): pk_trace 가 정말 "내 조각 + CIA 가 이산로그를 아는 조각"인지.
  // CIA 가 X_AA = X′ − X_svc 로 골라 조합 키 전체를 혼자 알게 되는 것을 막는다 — 스펙 2026-09-16 §2.
  if (!(await verifyCiaShare(b.arid, b.pk_trace, b.X_AA, b.share_pok))) throw Object.assign(new Error('CIA 조각 X_AA 의 지식 증명이 검증되지 않거나 pk_trace ≠ X_svc + X_AA — rogue key 의심'), { permanent: true });
  reg = { ...reg, arid: b.arid, status: 'approved', pk_trace: b.pk_trace, cert_s: b.cert_s, X_AA: b.X_AA, share_pok: b.share_pok, issuedAt: new Date().toISOString() };
  writeJsonAtomic(REG_FILE, reg, 0o600);
  console.log(`[rp] CIA 등록 승인됨: arid=${reg.arid} origin=${reg.origin} → ${REG_FILE}`);
  return true;
}

const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 });
const chainId = (await provider.getNetwork()).chainId;
let verifier = null;   // 승인 뒤에만 만든다 — arid 와 pk_trace 가 있어야 한다

// ---- 팩토리(설계 2026-09-18 §6.1): 승인 뒤 한 번 배포. env 가 있으면 그것. 배포자·가스는 hardhat 언락 계정(개인키 없음). ----
const RELAYER_INDEX = Number(process.env.MODE3_RELAYER_INDEX ?? 0);
// PINNED_ENV(tests/helpers/isolated_mode3_stack.mjs)가 빈 문자열로 고정한다 — 다른 CIA_* env 와 같은 관례로
// 빈 문자열도 "기본값 사용"이어야 한다(?? 는 빈 문자열을 값으로 본다 — cia.js 의 envBig 과 같은 이유로 || 를 쓴다).
const MAX_ROOT_AGE = BigInt(process.env.MODE3_MAX_ROOT_AGE || MAX_ROOT_AGE_DEFAULT);
// 지갑이 정한 max_height 의 상한 L(설계 2026-09-18 §3.2 갱신): head ≤ max_height ≤ head + L. 서비스·컨트랙트가 같은 값을 쓴다.
const MAX_LIFETIME = BigInt(process.env.MODE3_MAX_LIFETIME_BLOCKS || MAX_LIFETIME_DEFAULT);
async function ensureFactory() {
  if (process.env.MODE3_RP_FACTORY_ADDRESS) { reg.factoryAddress = ethers.getAddress(process.env.MODE3_RP_FACTORY_ADDRESS); return; }
  if (reg.factoryAddress) return;
  const signer = await provider.getSigner(RELAYER_INDEX);
  const verifierAddress = process.env.MODE3_VERIFIER_ADDRESS || reg.verifierAddress || await deployVerifier(signer);
  const factoryAddress = await deployFactory(signer, { verifierAddress, arid: reg.arid, pkCIA, pkTrace: { x: BigInt(reg.pk_trace.x), y: BigInt(reg.pk_trace.y) }, logAddress: LOG_ADDRESS, maxRootAge: MAX_ROOT_AGE, maxLifetime: MAX_LIFETIME });
  reg = { ...reg, verifierAddress, factoryAddress };
  writeJsonAtomic(REG_FILE, reg, 0o600);
  console.log(`[rp] 팩토리 배포: ${factoryAddress} (verifier ${verifierAddress}, maxRootAge ${MAX_ROOT_AGE}, maxLifetime ${MAX_LIFETIME}) → ${REG_FILE}`);
}
// 팩토리가 이미 있으면 그 immutable(maxRootAge·maxLifetime)이 진실이다 — env 를 나중에 바꿔도 온체인은 안 바뀌므로
// 오프체인 검증기는 온체인 값을 채택하고 경고한다(2026-09-23 점검 D-I2). 바꾸려면 팩토리를 재배포한다(문서 "처음 한 번" 6).
let EFFECTIVE_MAX_ROOT_AGE = MAX_ROOT_AGE, EFFECTIVE_MAX_LIFETIME = MAX_LIFETIME;
async function adoptFactoryConstants() {
  const f = new ethers.Contract(reg.factoryAddress, FACTORY_ABI, provider);
  const [ra, ml] = await Promise.all([f.maxRootAge(), f.maxLifetime()]);
  EFFECTIVE_MAX_ROOT_AGE = BigInt(ra); EFFECTIVE_MAX_LIFETIME = BigInt(ml);
  if (EFFECTIVE_MAX_ROOT_AGE !== MAX_ROOT_AGE || EFFECTIVE_MAX_LIFETIME !== MAX_LIFETIME) {
    console.warn(`[rp] 팩토리 ${reg.factoryAddress} 의 maxRootAge=${EFFECTIVE_MAX_ROOT_AGE}·maxLifetime=${EFFECTIVE_MAX_LIFETIME} 가 env(${MAX_ROOT_AGE}·${MAX_LIFETIME})와 다르다 — 온체인 값을 쓴다. 바꾸려면 팩토리를 재배포한다`);
  }
}
// 팩토리는 있는데 상수 조회만 실패하는 경우(RPC 일시 오류·팩토리가 아닌 주소·ABI 불일치) env 값으로 되돌아가면
// D-I2 가 그대로 재발한다 — 온체인은 100/400 인데 오프체인만 env 값으로 계속 서비스하게 된다(2026-09-23 리뷰 I-1).
// 그래서 검증기를 아예 만들지 않고(fail-closed) 주기적으로 다시 시도한다. 그 동안 로그인·재검증·세션 요청은
// 503 factory_constants_unavailable 이다(등록 대기와 구분한다).
const FACTORY_CONSTANTS_RETRY_MS = Number(process.env.MODE3_FACTORY_CONSTANTS_RETRY_MS) || 5000;
let factoryConstantsFailed = false;
let constantsRetryTimer = null;
let syncingConstants = false;
/** 검증기가 없을 때 돌려줄 사유. 팩토리 상수를 못 읽은 것과 등록 대기를 구분한다. */
const inactiveReason = () => (factoryConstantsFailed ? 'factory_constants_unavailable' : 'registration_pending');
/** 팩토리 상수를 채택한 뒤에만 검증기를 만든다. 조회에 실패하면 검증기를 비우고 재시도를 건다. */
async function syncFactoryConstantsAndVerifier() {
  if (syncingConstants) return;
  syncingConstants = true;
  try {
    if (reg.factoryAddress) {
      try { await adoptFactoryConstants(); }
      catch (e) {
        factoryConstantsFailed = true;
        verifier = null;
        console.warn(`[rp] 팩토리 ${reg.factoryAddress} 의 maxRootAge/maxLifetime 조회 실패 — 검증기를 만들지 않는다(fail-closed): ${e.message}`);
        startFactoryConstantsRetry();
        return;
      }
    }
    factoryConstantsFailed = false;
    verifier = createRpVerifier({ provider, logAddress: LOG_ADDRESS, vkey, pkCIA, arid: BigInt(reg.arid), chainId, pkTrace: { x: BigInt(reg.pk_trace.x), y: BigInt(reg.pk_trace.y) }, maxLifetimeBlocks: EFFECTIVE_MAX_LIFETIME, maxRootAge: EFFECTIVE_MAX_ROOT_AGE });
    // 하트비트 주기가 상한 이상이면 폐기가 없어도 root 나이가 상한을 넘는 창이 생겨 **전원**이 root_too_old(온체인 RootTooOld)로
    // 막힌다. 두 값은 서로 다른 프로세스의 env 라 아무도 대조하지 않는다(2026-09-23 최종 리뷰 M4).
    if (ciaHeartbeatBlocks !== null && ciaHeartbeatBlocks > 0n && ciaHeartbeatBlocks >= EFFECTIVE_MAX_ROOT_AGE) {
      console.warn(`[rp] CIA 하트비트 주기 ${ciaHeartbeatBlocks} 블록 ≥ maxRootAge ${EFFECTIVE_MAX_ROOT_AGE} — 정상 운영에서도 root_too_old 가 난다. CIA 의 CIA_HEARTBEAT_BLOCKS 를 낮추거나 더 큰 maxRootAge 로 팩토리를 재배포한다`);
    }
  } finally { syncingConstants = false; }
}
function startFactoryConstantsRetry() {
  if (constantsRetryTimer) return;
  constantsRetryTimer = setInterval(async () => {
    await syncFactoryConstantsAndVerifier();
    if (!factoryConstantsFailed) {
      clearInterval(constantsRetryTimer); constantsRetryTimer = null;
      console.log(`[rp] 팩토리 상수 조회 성공 — 검증기 활성화(maxRootAge ${EFFECTIVE_MAX_ROOT_AGE}, maxLifetime ${EFFECTIVE_MAX_LIFETIME})`);
    }
  }, FACTORY_CONSTANTS_RETRY_MS);
  constantsRetryTimer.unref();
}
// AttrGate(설계 2026-09-22 §5.3): 팩토리 다음에 한 번 배포하는 데모 대상. 정책은 국가=410, 출생연도≤2007 고정(데모).
// reg.attrGateFactory(그 배포가 물린 팩토리)가 지금의 reg.factoryAddress 와 다르면 다시 배포한다 — factoryAddress 가
// 파일에 없는 채 env(MODE3_RP_FACTORY_ADDRESS)로만 매번 정해지는 경로에서도, factoryAddress 자체는 안 바뀌었는데
// attrGateAddress 유무만으로 리셋하던 옛 방식(재기동마다 불필요하게 재배포)과 달리 실제로 팩토리가 바뀐 경우에만 걸린다.
async function ensureAttrGate() {
  if (!reg.factoryAddress) { console.warn('[rp] 팩토리가 없어 AttrGate 배포를 건너뛴다'); return; }
  if (reg.attrGateAddress && reg.attrGateFactory === reg.factoryAddress) return;
  const signer = await provider.getSigner(RELAYER_INDEX);
  const attrGateAddress = await deployAttrGate(signer, { factoryAddress: reg.factoryAddress });
  reg = { ...reg, attrGateAddress, attrGateFactory: reg.factoryAddress };
  writeJsonAtomic(REG_FILE, reg, 0o600);
  console.log(`[rp] AttrGate 배포: ${attrGateAddress} (factory ${reg.factoryAddress}) → ${REG_FILE}`);
}
async function activate() {
  // 팩토리를 먼저 본다(2026-09-23 점검 D-I2): 이미 배포된 팩토리가 있으면 그 immutable 이 오프체인 검증기의 상한이 된다.
  // 팩토리를 **배포하지 못한** 경우(주소 자체가 없다)는 오프체인 로그인만 된다 — 대조할 온체인 상수가 없으니
  // env 값이 곧 상한이고 /wallet/tx 만 no_factory 가 된다. 팩토리는 있는데 상수를 못 읽는 경우는 다르다(아래 fail-closed).
  try { await ensureFactory(); } catch (e) { console.warn(`[rp] 팩토리 배포 실패(오프체인 로그인만 가능): ${e.message}`); }
  await syncFactoryConstantsAndVerifier();
  try { await ensureAttrGate(); } catch (e) { console.warn(`[rp] AttrGate 배포 실패: ${e.message}`); }
}
if (reg.status === 'approved' && reg.cert_s) {
  if (!(await verifyRpCert(pkCIA, { arid: BigInt(reg.arid), origin: reg.origin, pk_trace: { x: BigInt(reg.pk_trace.x), y: BigInt(reg.pk_trace.y) }, cert: reg.cert_s }))) {
    throw new Error('등록 파일의 cert_s 가 현재 pk_CIA 로 검증되지 않는다 — CIA 키가 바뀌었으면 파일을 지우고 재기동');
  }
  // 2026-09-21 이전에 승인된 등록 파일에는 X_AA·share_pok 가 없다. 등록을 다시 받으면 x_svc 가 바뀌어 옛 태그를 못 열므로
  // 강제하지 않고 경고만 남긴다 — 조각 검사를 원하면 파일을 지우고 재등록한다.
  if (reg.X_AA && reg.share_pok) {
    if (!(await verifyCiaShare(reg.arid, reg.pk_trace, reg.X_AA, reg.share_pok))) throw new Error('등록 파일의 CIA 조각 증명(share_pok)이 검증되지 않는다 — 파일이 손상됐거나 pk_trace ≠ X_svc + X_AA');
  } else {
    console.warn('[rp] 등록 파일에 CIA 조각 증명(X_AA·share_pok)이 없다(2026-09-21 이전 승인) — rogue key 검사를 건너뛴다');
  }
  await activate();
} else {
  if (await registerOnce()) await activate();
  else {
    console.log(`[rp] 등록 대기 (arid=${reg.arid}) — CIA 관리자 페이지에서 승인하면 ${POLL_MS} ms 안에 활성화된다`);
    // 한 틱이 끝나기 전에(특히 activate() 의 팩토리 배포는 느리다) 다음 틱이 시작하지 않도록 재진입을 막는다 —
    // clearInterval 만으로는 부족하다: 두 틱이 거의 동시에 registerOnce() 를 시작해 버리면 clearInterval 이
    // 걸리기 전에 이미 둘 다 진행 중이라 팩토리가 중복 배포되고 reg.factoryAddress 가 경합으로 덮어써진다.
    let activating = false;
    const timer = setInterval(async () => {
      if (activating) return;
      activating = true;
      try { if (await registerOnce()) { clearInterval(timer); await activate(); } }
      catch (e) {
        // 거절·인증서 검증 실패는 영구 상태라 멈춘다. 그 외(CIA 일시 장애·네트워크 오류)는 계속 재시도한다.
        if (e.permanent) { console.error(`[rp] ${e.message}`); clearInterval(timer); }
        else console.warn(`[rp] 등록 조회 실패, 다시 시도: ${e.message}`);
      } finally { activating = false; }
    }, POLL_MS);
    timer.unref();
  }
}

// ---- r_s: 메모리, TTL, 로그인 때 1회 소비. 소비된 r_s 는 세션 식별자가 된다(설계 §7) ----
const challenges = new Map();   // r_s(10진) → expiresAt(ms)
const sessions = new Map();     // r_s(10진) → { PPID, pk_i, max_height, allowAgent, root, at }
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
// r_s 전문은 내지 않는다 — (PPID, 시각) 과 함께 서비스의 사용자 활동 기록이다(설계 2026-09-16 §5).
const rsShort = (r) => r.slice(0, 8) + '…';
// 선택 공개(2026-09-22 §6.2) — verifyLogin 이 돌려주는 bigint 조각을 세션·로그인 로그·조회 API 에 쓸 문자열로.
const discOf = (d) => ({ mask: d.mask.toString(), lo: d.lo.map(String), hi: d.hi.map(String) });

// ---- 앱 ----
const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'rp.html')));

app.get('/api/mode3/rp_info', (req, res) => {
  res.json({ status: reg.status, arid: reg.arid, origin: reg.origin, cert_s: reg.cert_s, pk_trace: reg.pk_trace, logAddress: LOG_ADDRESS, walletAgentOrigin: WALLET_ORIGIN, pkCiaSource: pkCIA.source, chainId: chainId.toString(), active: Boolean(verifier), factoryAddress: reg.factoryAddress ?? null, verifierAddress: reg.verifierAddress ?? null, attrGateAddress: reg.attrGateAddress ?? null });
});
app.post('/api/mode3/challenge', (req, res) => {
  // 봉투를 다른 라우트와 같은 { ok, reason } 으로 맞춘다 — 페이지가 상태 코드가 아니라 본문으로 사유를 읽는다(2026-09-23 최종 리뷰 M3).
  if (!verifier) return res.status(503).json({ ok: false, reason: inactiveReason() });
  res.json({ ok: true, ...issueChallenge(), factoryAddress: reg.factoryAddress ?? null, attrGateAddress: reg.attrGateAddress ?? null });
});

async function verifyBody(req, res, r_s) {
  const { proof, publicSignals, sig } = req.body ?? {};
  if (!proof || !Array.isArray(publicSignals) || typeof sig !== 'string') { res.status(400).json({ ok: false, reason: 'malformed' }); return null; }
  return verifier.verifyLogin({ proof, publicSignals, sig, r_s });
}

app.post('/api/mode3/login', async (req, res) => {
  try {
    if (!verifier) return res.status(503).json({ ok: false, reason: inactiveReason() });
    const { r_s } = req.body ?? {};
    if (typeof r_s !== 'string' || !/^[0-9]+$/.test(r_s)) return res.status(400).json({ ok: false, reason: 'malformed' });
    const rsStr = BigInt(r_s).toString();
    if (!consumeChallenge(rsStr)) return res.status(401).json({ ok: false, reason: 'bad_challenge' });   // 검증 전에 소비
    const v = await verifyBody(req, res, BigInt(rsStr)); if (v === null) return;
    if (!v.ok) return res.json({ ok: false, reason: v.reason });
    const at = new Date().toISOString();
    const disclosure = discOf(v.disclosure);
    sessions.set(rsStr, { PPID: v.PPID.toString(), pk_i: v.pk_i.toString(), max_height: v.max_height.toString(), allowAgent: v.allowAgent.toString(), root: v.root.toString(), disclosure, at });
    logins.push({ PPID: v.PPID.toString(), at, root: v.root.toString(), r_s: rsShort(rsStr), allowAgent: v.allowAgent.toString(), disclosure });
    // §5 로그인 로그 — 전체 r_s 와 트랜스크립트(태그 포함). 개봉 요청의 재료다. 조회 API 로는 내지 않는다.
    fs.appendFileSync(LOGIN_LOG, JSON.stringify({ at, PPID: v.PPID.toString(), r_s: rsStr, pk_i: v.pk_i.toString(), max_height: v.max_height.toString(), allowAgent: v.allowAgent.toString(), root: v.root.toString(), disclosure, publicSignals: v.publicSignals, proof: req.body.proof }) + '\n', { mode: 0o600 });
    res.json({ ok: true, PPID: v.PPID.toString(), pk_i: v.pk_i.toString(), r_s: rsStr, root: v.root.toString(), allowAgent: v.allowAgent.toString(), disclosure });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

app.post('/api/mode3/revalidate', async (req, res) => {
  try {
    if (!verifier) return res.status(503).json({ ok: false, reason: inactiveReason() });
    const { r_s } = req.body ?? {};
    if (typeof r_s !== 'string' || !/^[0-9]+$/.test(r_s)) return res.status(400).json({ ok: false, reason: 'malformed' });
    const rsStr = BigInt(r_s).toString();
    const s = sessions.get(rsStr);
    if (!s) return res.status(401).json({ ok: false, reason: 'no_session' });
    const v = await verifyBody(req, res, BigInt(rsStr)); if (v === null) return;
    if (!v.ok) return res.json({ ok: false, reason: v.reason });
    if (v.PPID.toString() !== s.PPID || v.pk_i.toString() !== s.pk_i) return res.status(401).json({ ok: false, reason: 'session_mismatch' });
    s.root = v.root.toString();
    s.disclosure = discOf(v.disclosure);
    res.json({ ok: true, r_s: rsStr, root: s.root });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

app.post('/api/mode3/request', async (req, res) => {
  try {
    if (!verifier) return res.status(503).json({ ok: false, reason: inactiveReason() });
    const { r_s, body, sig } = req.body ?? {};
    if (typeof r_s !== 'string' || !/^[0-9]+$/.test(r_s) || typeof body !== 'string' || typeof sig !== 'string') return res.status(400).json({ ok: false, reason: 'malformed' });
    const rsKey = BigInt(r_s).toString();   // login·revalidate 와 같은 정규 키(2026-09-18 점검 9)
    const s = sessions.get(rsKey);
    if (!s) return res.status(401).json({ ok: false, reason: 'no_session' });
    // 폐기가 효력을 갖는 지점: root 가 바뀌었으면 세션은 재검증 전까지 요청을 받지 않는다.
    const view = await verifier.refreshChainView().catch(() => null);
    if (!view) return res.status(503).json({ ok: false, reason: 'chain_unavailable' });
    if (view.head > BigInt(s.max_height)) { sessions.delete(rsKey); return res.status(401).json({ ok: false, reason: 'expired' }); }
    if (view.root.toString() !== s.root) return res.status(401).json({ ok: false, reason: 'revalidate_required' });
    // b′ — root 게시 나이(2026-09-23 점검 C-1, 리뷰 Ruling 1). verifyLogin 의 b′ 와 같은 상한·같은 위치(root 일치 뒤).
    // CIA 게시가 멈추면 새 로그인뿐 아니라 이미 있는 세션의 요청도 함께 멈춘다. 세션 상태가 아니라 게시 생존의
    // 문제이므로 chain_unavailable 과 같은 503 이다.
    if (view.head - view.lastPublishedBlock > EFFECTIVE_MAX_ROOT_AGE) return res.status(503).json({ ok: false, reason: 'root_too_old' });
    if (!verifySessionRequest({ pk_i: s.pk_i, r_s: rsKey, body, sig })) return res.status(401).json({ ok: false, reason: 'bad_signature' });
    res.json({ ok: true, echo: body, PPID: s.PPID });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

// ---- §6 개봉(데모용, 인증 없음) ----
function lastTranscriptOf(PPID) {
  if (!fs.existsSync(LOGIN_LOG)) return null;
  // 마지막 줄이 쓰다 만 채로 잘려 있을 수 있다 — 파싱 안 되는 줄만 건너뛰고 나머지는 그대로 쓴다.
  let dropped = 0;
  const lines = fs.readFileSync(LOGIN_LOG, 'utf8').split('\n').filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { dropped++; return null; } }).filter(Boolean);
  if (dropped > 0) console.warn(`[rp] 로그인 로그 손상 줄 ${dropped}개 건너뜀`);
  return lines.reverse().find((l) => l.PPID === PPID) ?? null;
}
/** 트랜잭션 해시에서 개봉 재료(§6.2): calldata 의 (a, b, c, pub) 을 snarkjs 증명 형식으로 되돌린다. 성공한 execute 만 받는다. */
async function transcriptFromTx(txHash) {
  const tx = await provider.getTransaction(txHash);
  if (!tx) return { error: 'no_tx' };
  const d = decodeExecuteCalldata(tx.data);
  if (!d) return { error: 'not_execute' };
  const receipt = await provider.getTransactionReceipt(txHash);
  if (!receipt || receipt.status !== 1 || !parseExecuteReceipt(receipt, tx.to).auth) return { error: 'tx_failed' };
  // exportSolidityCallData 는 b 의 각 행을 (y, x) 로 뒤집는다 — 되돌린다.
  const proof = {
    pi_a: [d.a[0], d.a[1], '1'],
    pi_b: [[d.b[0][1], d.b[0][0]], [d.b[1][1], d.b[1][0]], ['1', '0']],
    pi_c: [d.c[0], d.c[1], '1'],
    protocol: 'groth16', curve: 'bn128',
  };
  return { publicSignals: d.pub, proof, PPID: d.pub[0] };
}
app.post('/api/mode3/open', async (req, res) => {
  try {
    if (!verifier) return res.status(503).json({ ok: false, reason: inactiveReason() });
    const { PPID, txHash } = req.body ?? {};
    let T;
    if (typeof txHash === 'string') {
      if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) return res.status(400).json({ ok: false, reason: 'malformed' });
      T = await transcriptFromTx(txHash);
      if (T.error) return res.status(404).json({ ok: false, reason: T.error });
    } else if (typeof PPID === 'string') {
      T = lastTranscriptOf(PPID);
      if (!T) return res.status(404).json({ ok: false, reason: 'no_transcript' });
    } else return res.status(400).json({ ok: false, reason: 'malformed' });
    const c1 = { x: BigInt(T.publicSignals[11]), y: BigInt(T.publicSignals[12]) };
    const D = await partialDecrypt(BigInt(reg.x_svc), c1);
    const D_svc = { x: D.x.toString(), y: D.y.toString() };
    const ts = Math.floor(Date.now() / 1000).toString();
    const sig = await signOpenRequest(serviceWallet, { arid: reg.arid, PPID: T.PPID, c1: { x: c1.x.toString(), y: c1.y.toString() }, D_svc, ts });
    const r = await fetch(`${CIA_URL}/cia/open/request`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ arid: reg.arid, publicSignals: T.publicSignals, proof: T.proof, D_svc, ts, sig }) });
    res.status(r.status).json(await r.json().catch(() => ({})));
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});
app.get('/api/mode3/open/:id', async (req, res) => {
  try {
    const ts = Math.floor(Date.now() / 1000).toString();
    const sig = await signOpenResult(serviceWallet, req.params.id, ts);
    const r = await fetch(`${CIA_URL}/cia/open/${encodeURIComponent(req.params.id)}?ts=${ts}&sig=${encodeURIComponent(sig)}`);
    res.status(r.status).json(await r.json().catch(() => ({})));
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

app.get('/api/mode3/logins', (req, res) => res.json({ logins }));
app.get('/api/mode3/sessions', (req, res) => res.json({ sessions: [...sessions.entries()].map(([r_s, s]) => ({ r_s: rsShort(r_s), PPID: s.PPID, pk_i: s.pk_i, max_height: s.max_height, allowAgent: s.allowAgent, root: s.root, disclosure: s.disclosure, at: s.at })) }));

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Mode 3 RP at http://127.0.0.1:${PORT} (arid=${reg.arid ?? '-'} status=${reg.status}, origin=${reg.origin}, log=${LOG_ADDRESS}, wallet=${WALLET_ORIGIN}, pk_CIA=${pkCIA.source}, chain=${chainId})`);
});
