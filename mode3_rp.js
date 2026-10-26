// Mode 3 RP (:3100). 스펙: docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md §4
//
// server.js(:3000, Mode 1/2)와 나란히 두는 별도 프로세스다. 그쪽 코드를 import 하지 않는다.
// 검증(설계 §6.3 7단계)은 전부 lib/mode3_rp.js 에 있고 여기는 등록·challenge 관리 + HTTP 만이다.
// 세션은 메모리 Map(r_s → PPID·pk_i·max_height·allowAgent·root·auid_s·arid_s·r_rp) 뿐이고 쿠키는 없다 — 데모의 요점은 검증 결과다(스펙 §4.2).
// V4(2026-09-18): 팩토리 배포(§6.1), 로그인 V4(max_height·allowAgent, σ 는 서버 챌린지 위), 트랜잭션 해시 개봉(§6.2).
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { createRpVerifier, verifySessionRequest, canonicalProof, proofFromCalldata, verifyCalldataProof, uniqueMembers } from './lib/mode3_rp.js';
import { VKEY_PATH } from './lib/mode3_wallet.js';
import { readJson, writeJsonAtomic } from './lib/mode3_state.js';
import { verifyRpCert } from './lib/mode3_rp_cert.js';
import { randomScalar } from './lib/mode3_credential.js';
import { createShare, partialDecrypt, combinePublicKey, verifyShare } from './lib/mode3_trace.js';
import { signOpenRequest, signOpenResult } from './lib/mode3_opening.js';
import { deployVerifier, deployFactory, deployAttrGate, decodeExecuteCalldata, parseExecuteReceipt, walletInterface, FACTORY_ABI, MAX_ROOT_AGE_DEFAULT, MAX_LIFETIME_DEFAULT, ROOT_WINDOW_DEFAULT, ALLOWED_COUNTRIES_DEFAULT, MIN_AGE_DEFAULT, PUB_INDEX } from './lib/mode3_onchain.js';
import { setRoot } from './lib/mode3_set_tree.js';
import { buildRpHealth, applyHealthHeaders, bounded, originList } from './lib/mode3_health.js';
import { DEFAULT_ATTR_SCHEMA, loadSchema, slotIndexOf, encodeMembers, schemaInfo } from './lib/mode3_attr_schema.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.MODE3_RP_PORT) || 3100;
// 수신 주소(2026-10-20, VM 분리 데모): 기본은 지금처럼 127.0.0.1. 다른 기계에서 붙게 하려면 MODE3_BIND_HOST=0.0.0.0.
const BIND_HOST = process.env.MODE3_BIND_HOST || '127.0.0.1';
const CIA_URL = process.env.MODE3_CIA_URL || 'http://127.0.0.1:4100';
const WALLET_ORIGIN = process.env.MODE3_WALLET_AGENT_ORIGIN || 'http://127.0.0.1:5100';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;   // 캐노니컬 표시용(/api/mode3/rp_info) — 검증기는 이 주소를 읽지 않는다(V10)
const MIRROR_ADDRESS = process.env.MODE3_MIRROR_ADDRESS || null;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const CHALLENGE_TTL_MS = Number(process.env.MODE3_CHALLENGE_TTL_MS) || 120_000;

if (!LOG_ADDRESS) { console.error('[rp] CIA_LOG_ADDRESS 가 없다'); process.exit(1); }
// V10: RP 는 폐기 체인의 캐노니컬 Mode3Log 를 직접 읽지 않고 자기 체인의 거울(Mode3Mirror)만 읽는다(설계 §2·§5).
if (!MIRROR_ADDRESS) { console.error('[rp] MODE3_MIRROR_ADDRESS 가 없다 — 이 체인의 Mode3Mirror 주소(V10)'); process.exit(1); }

// pk_CIA 고정(설계 §5 — 유일한 위조 방어선). env 가 있으면 그것, 없으면 기동 시 IdP 에서 한 번 받아
// 프로세스 수명 동안 고정한다(TOFU, 데모 단축). 기동 후에는 IdP 에 다시 묻지 않는다(설계 §9.9).
// IdP 가 알려 준 하트비트 주기(블록). 아래 TOFU 경로에서만 받는다 — pk_CIA 를 env 로 박으면 IdP 에 묻지 않으므로 null 이고,
// 그때는 maxRootAge 와 대조할 수 없다(경고를 위해 새 RPC·HTTP 호출을 만들지는 않는다. 2026-09-23 최종 리뷰 M4).
let ciaHeartbeatBlocks = null;
// oidc(스펙 2026-10-16 §2): IdP 가 Google 등록을 켰는지 — 같은 응답에서 함께 받아 rp_info 로 페이지에 중계한다(모달의 Google 버튼 활성).
// env 경로는 IdP 를 부르지 않으므로 알 수 없다 — 꺼진 것으로 본다(버튼은 지금처럼 "데모 미지원" 안내).
async function resolvePkCia() {
  const { MODE3_PK_CIA_X: x, MODE3_PK_CIA_Y: y } = process.env;
  if (x && y) return { x: BigInt(x), y: BigInt(y), source: 'env', oidc: { enabled: false } };
  const r = await fetch(`${CIA_URL}/cia/public_keys`);
  if (!r.ok) throw new Error(`IdP ${CIA_URL} 에서 pk_CIA 를 받지 못했다 (${r.status})`);
  const k = await r.json();
  if (Number.isFinite(k.heartbeatBlocks)) ciaHeartbeatBlocks = BigInt(k.heartbeatBlocks);
  console.warn(`[rp] pk_CIA 를 IdP 에서 받아 고정한다(TOFU). 운영이라면 env 로 박는다:\n  MODE3_PK_CIA_X=${k.pk_CIA.x}\n  MODE3_PK_CIA_Y=${k.pk_CIA.y}`);
  return { x: BigInt(k.pk_CIA.x), y: BigInt(k.pk_CIA.y), source: 'tofu', oidc: k.oidc ?? { enabled: false } };
}

const pkCIA = await resolvePkCia();

// 속성 스키마(스펙 2 §5.4): IdP 가 공개하는 것을 기동 때 한 번 받는다(pk_CIA 와 같은 TOFU 성격). 못 받으면(HTTP 오류·네트워크) 공유 모듈
// 기본 스키마 + 경고 — 프로세스 수명 동안 그대로다. 받았는데 검증에 실패하면 기동 거부(스펙 §7 첫 행, 최종 리뷰 I4) — 연결 실패와 구분한다.
async function resolveAttrSchema() {
  let b;
  try {
    const r = await fetch(`${CIA_URL}/cia/attr_schema`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    b = await r.json();
  } catch (e) {
    console.warn(`[rp] 속성 스키마를 IdP 에서 받지 못해 기본 스키마를 쓴다: ${e.message}`);
    return { ...loadSchema(DEFAULT_ATTR_SCHEMA), source: 'default' };
  }
  try { return { ...loadSchema(b?.schema), source: 'cia' }; }
  catch (e) { console.error(`[rp] 기동 거부: IdP 의 속성 스키마가 검증에 실패했다 — ${e.message}`); process.exit(1); }
}
const ATTR_SCHEMA = await resolveAttrSchema();
const COUNTRY_SLOT = slotIndexOf(ATTR_SCHEMA.schema, 'country');     // -1 이면 국가 술어를 요구할 수 없다(predicate_unavailable)
const BIRTH_SLOT = slotIndexOf(ATTR_SCHEMA.schema, 'birthYear');

// ---- RP 등록(설계 2026-09-16 §3) ----
// 키 둘: secp256k1 서명키(pk_service, 개봉 요청)와 Baby Jubjub 조각(x_svc, 태그). 첫 기동에서 만들어 파일에 두고 IdP 에
// 등록한다. IdP 는 pending 으로 받고 운영자가 승인하면 조합 키 pk_trace 와 cert_s 를 준다 — 그때까지는 대기 상태로 뜬다.
const REG_FILE = process.env.MODE3_RP_REGISTRATION_FILE || path.join(__dirname, 'mode3_rp_registration.json');
const REG_VERSION = 3;
const PUBLIC_ORIGIN = process.env.MODE3_RP_PUBLIC_ORIGIN || `http://127.0.0.1:${PORT}`;
const RP_NAME = process.env.MODE3_RP_NAME || 'demo-rp';
// 운영자가 IdP RP 페이지(Task 11, 스펙 §3.3·§6)에서 만든 RP 슬롯에 등록을 묶는 비밀. 없으면(zkONE·zkTWO 의 기동 자동
// 등록처럼) 지금과 같은 키 없는 등록이다.
const RP_KEY = process.env.MODE3_RP_KEY || null;
const POLL_MS = Number(process.env.MODE3_RP_REGISTRATION_POLL_MS) || 5000;
const LOGIN_LOG = process.env.MODE3_RP_LOGIN_LOG || path.join(__dirname, 'mode3_rp_logins.jsonl');
if (fs.existsSync(LOGIN_LOG)) fs.chmodSync(LOGIN_LOG, 0o600);   // 옛 실행이 남긴 파일의 권한도 조인다

let reg = readJson(REG_FILE, null);
// v2 → v3(2026-09-18): 팩토리·검증자 주소 필드. 조각(x_svc)은 그대로 — 버리면 이전 로그인 로그의 태그를 열 수 없다.
if (reg && reg.version === 2) { reg = { ...reg, version: 3, factoryAddress: null, verifierAddress: null }; writeJsonAtomic(REG_FILE, reg, 0o600); }
if (reg && (reg.version !== REG_VERSION || reg.origin !== PUBLIC_ORIGIN)) {
  console.warn(`[rp] 등록 파일이 옛 형식이거나 origin(${reg.origin}) 이 현재(${PUBLIC_ORIGIN}) 와 달라 새로 등록한다` +
    ` — 옛 RP 조각(x_svc)도 버려지므로 이전 로그인 로그의 태그는 더 이상 열 수 없다`);
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

/** IdP 에 등록/조회. 200 이면 파일을 채우고 true. 202 면 false. 403 이면 throw. */
async function registerOnce() {
  const r = await fetch(`${CIA_URL}/cia/register_rp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: RP_NAME, origin: PUBLIC_ORIGIN, pk_service: reg.pk_service, X_svc: reg.X_svc, ...(RP_KEY ? { rp_key: RP_KEY } : {}) }) });
  const b = await r.json().catch(() => ({}));
  if (r.status === 202) { reg.arid = b.arid; reg.status = 'pending'; writeJsonAtomic(REG_FILE, reg, 0o600); return false; }
  // 403(거절)은 영구 상태로 기록한다. 408·429 를 뺀 나머지 4xx(예: 409 service_key_mismatch, 400 형식 오류)도
  // 재시도해 봤자 같은 응답이 반복될 뿐이라 영구 실패다 — IdP 가 죽었거나 네트워크가 끊긴 것(5xx·예외)만 일시적이라 계속 재시도한다.
  if (r.status === 403) { reg.arid = b.arid; reg.status = 'denied'; writeJsonAtomic(REG_FILE, reg, 0o600); throw Object.assign(new Error(`IdP 가 등록을 거절했다 (arid=${b.arid})`), { permanent: true }); }
  if (r.status >= 400 && r.status < 500 && r.status !== 408 && r.status !== 429) {
    throw Object.assign(new Error(`IdP 등록 실패 (${r.status}) ${JSON.stringify(b)}`), { permanent: true });
  }
  if (r.status !== 200) throw new Error(`IdP 등록 실패 (${r.status}) ${JSON.stringify(b)}`);
  const pk_trace = { x: BigInt(b.pk_trace.x), y: BigInt(b.pk_trace.y) };
  if (!(await verifyRpCert(pkCIA, { arid: BigInt(b.arid), origin: PUBLIC_ORIGIN, pk_trace, cert: b.cert_s }))) throw Object.assign(new Error('IdP 가 준 cert_s 가 pk_CIA 로 검증되지 않는다'), { permanent: true });
  // IdP 조각 검사(2026-09-21, rogue key 방지): pk_trace 가 정말 "내 조각 + IdP 가 이산로그를 아는 조각"인지.
  // IdP 가 X_AA = X′ − X_svc 로 골라 조합 키 전체를 혼자 알게 되는 것을 막는다 — 스펙 2026-09-16 §2.
  if (!(await verifyCiaShare(b.arid, b.pk_trace, b.X_AA, b.share_pok))) throw Object.assign(new Error('IdP 조각 X_AA 의 지식 증명이 검증되지 않거나 pk_trace ≠ X_svc + X_AA — rogue key 의심'), { permanent: true });
  reg = { ...reg, arid: b.arid, status: 'approved', pk_trace: b.pk_trace, cert_s: b.cert_s, X_AA: b.X_AA, share_pok: b.share_pok, issuedAt: new Date().toISOString() };
  writeJsonAtomic(REG_FILE, reg, 0o600);
  console.log(`[rp] IdP 등록 승인됨: arid=${reg.arid} origin=${reg.origin} → ${REG_FILE}`);
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
// 지갑이 정한 max_height 의 상한 L(설계 2026-09-18 §3.2 갱신): head ≤ max_height ≤ head + L. RP·컨트랙트가 같은 값을 쓴다.
const MAX_LIFETIME = BigInt(process.env.MODE3_MAX_LIFETIME_BLOCKS || MAX_LIFETIME_DEFAULT);
// 2026-10-25 root 유효 창 §6: 계정 컨트랙트가 대체된 root 를 더 받는 블록 수 G. 팩토리 immutable 이라 바꾸려면 팩토리를 재배포한다.
const ROOT_WINDOW = BigInt(process.env.MODE3_ROOT_WINDOW || ROOT_WINDOW_DEFAULT);
// V7 술어 정책(설계 2026-09-23 §4.3·§6): AttrGate 배포와 오프체인 로그인 정책이 같은 값을 쓴다.
// 스펙 2: MODE3_ALLOWED_COUNTRIES 는 이름(KR,JP)과 코드(410,392)를 모두 받아 country 슬롯의 인코더로 바꾼다. 표에 없으면 기동 실패.
const ALLOWED_COUNTRY_TOKENS = (process.env.MODE3_ALLOWED_COUNTRIES ?? '').split(',').map((s) => s.trim()).filter(Boolean);
let ALLOWED_COUNTRIES = [];
if (ALLOWED_COUNTRY_TOKENS.length) {
  if (COUNTRY_SLOT < 0) { console.error('[rp] 속성 스키마에 country 슬롯이 없어 MODE3_ALLOWED_COUNTRIES 를 해석할 수 없다'); process.exit(1); }
  // 이름·코드가 겹치면("KR,410") 같은 값이 둘 — 지갑이 중복 원소를 거절하므로(리뷰 D1) 첫 순서로 하나만 남긴다.
  try { ALLOWED_COUNTRIES = uniqueMembers(await encodeMembers(ATTR_SCHEMA.schema, COUNTRY_SLOT, ALLOWED_COUNTRY_TOKENS)); }
  catch (e) { console.error(`[rp] MODE3_ALLOWED_COUNTRIES 해석 실패: ${e.message}`); process.exit(1); }
}
const ALLOWED_COUNTRIES_EFFECTIVE = ALLOWED_COUNTRIES.length ? ALLOWED_COUNTRIES : [...ALLOWED_COUNTRIES_DEFAULT];
const countryName = (code) => { const s = COUNTRY_SLOT >= 0 ? ATTR_SCHEMA.schema.slots[COUNTRY_SLOT] : null; const hit = s ? Object.entries(s.values).find(([, c]) => BigInt(c) === code) : null; return hit ? hit[0] : `#${code}`; };
const ALLOWED_COUNTRY_NAMES = ALLOWED_COUNTRIES_EFFECTIVE.map(countryName);
const MIN_AGE = BigInt(process.env.MODE3_MIN_AGE || MIN_AGE_DEFAULT);
const ALLOWED_COUNTRIES_ROOT = await setRoot(ALLOWED_COUNTRIES_EFFECTIVE);
async function ensureFactory() {
  if (process.env.MODE3_RP_FACTORY_ADDRESS) { reg.factoryAddress = ethers.getAddress(process.env.MODE3_RP_FACTORY_ADDRESS); return; }
  if (reg.factoryAddress) return;
  const signer = await provider.getSigner(RELAYER_INDEX);
  const verifierAddress = process.env.MODE3_VERIFIER_ADDRESS || reg.verifierAddress || await deployVerifier(signer);
  // V10: 팩토리가 온체인 지갑에 물려주는 root 소스도 거울이다 — 온체인·오프체인 검증기가 같은 체인을 본다.
  const factoryAddress = await deployFactory(signer, { verifierAddress, arid: reg.arid, pkCIA, pkTrace: { x: BigInt(reg.pk_trace.x), y: BigInt(reg.pk_trace.y) }, logAddress: MIRROR_ADDRESS, maxRootAge: MAX_ROOT_AGE, maxLifetime: MAX_LIFETIME, rootWindow: ROOT_WINDOW });
  reg = { ...reg, verifierAddress, factoryAddress };
  writeJsonAtomic(REG_FILE, reg, 0o600);
  console.log(`[rp] 팩토리 배포: ${factoryAddress} (verifier ${verifierAddress}, maxRootAge ${MAX_ROOT_AGE}, maxLifetime ${MAX_LIFETIME}, rootWindow ${ROOT_WINDOW}) → ${REG_FILE}`);
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
    // policySetRoot: 집합 술어를 실은 성명은 **이 RP 의 정책 집합**이어야 한다(2026-09-25 리뷰 I-2).
    // 회로는 "어떤 트리에 속한다" 만 증명하므로, 대조하지 않으면 자기 국가만 든 집합의 root 로 "허용 집합 소속" 을
    // 주장할 수 있다. AttrGate(온체인)는 이미 같은 대조를 한다 — 로그인·재검증에도 같은 선을 긋는다.
    // V10: 검증기는 캐노니컬(LOG_ADDRESS)이 아니라 이 체인의 거울(MIRROR_ADDRESS)을 읽는다(설계 §2·§5).
    verifier = createRpVerifier({ provider, logAddress: MIRROR_ADDRESS, vkey, pkCIA, arid: BigInt(reg.arid), chainId, pkTrace: { x: BigInt(reg.pk_trace.x), y: BigInt(reg.pk_trace.y) }, maxLifetimeBlocks: EFFECTIVE_MAX_LIFETIME, maxRootAge: EFFECTIVE_MAX_ROOT_AGE, policySetRoot: ALLOWED_COUNTRIES_ROOT });
    // 하트비트 주기가 상한 이상이면 폐기가 없어도 root 나이가 상한을 넘는 창이 생겨 **전원**이 root_too_old(온체인 RootTooOld)로
    // 막힌다. 두 값은 서로 다른 프로세스의 env 라 아무도 대조하지 않는다(2026-09-23 최종 리뷰 M4).
    if (ciaHeartbeatBlocks !== null && ciaHeartbeatBlocks > 0n && ciaHeartbeatBlocks >= EFFECTIVE_MAX_ROOT_AGE) {
      console.warn(`[rp] IdP 하트비트 주기 ${ciaHeartbeatBlocks} 블록 ≥ maxRootAge ${EFFECTIVE_MAX_ROOT_AGE} — 정상 운영에서도 root_too_old 가 난다. IdP 의 CIA_HEARTBEAT_BLOCKS 를 낮추거나 더 큰 maxRootAge 로 팩토리를 재배포한다`);
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
// AttrGate(설계 2026-09-22 §5.3): 팩토리 다음에 한 번 배포하는 데모 대상. 정책은 국가 ∈ MODE3_ALLOWED_COUNTRIES, 올해 − 출생연도 ≥ MODE3_MIN_AGE.
// reg.attrGateFactory(그 배포가 물린 팩토리)가 지금의 reg.factoryAddress 와 다르면 다시 배포한다 — factoryAddress 가
// 파일에 없는 채 env(MODE3_RP_FACTORY_ADDRESS)로만 매번 정해지는 경로에서도, factoryAddress 자체는 안 바뀌었는데
// attrGateAddress 유무만으로 리셋하던 옛 방식(재기동마다 불필요하게 재배포)과 달리 실제로 팩토리가 바뀐 경우에만 걸린다.
// 정책(root·minAge)이 바뀌어도 다시 배포한다 — AttrGate 는 immutable 이라 env 를 바꾼 뒤 재기동만으로는 온체인이 안 바뀐다.
async function ensureAttrGate() {
  // AttrGate(불변)는 "출생연도 = 슬롯 0, 국가 = set_sel 2(슬롯 1)" 을 코드에 박고 있다(스펙 2 §3.2) — 스키마가 다르면 배포하지 않는다.
  if (BIRTH_SLOT !== 0 || COUNTRY_SLOT !== 1) { console.warn(`[rp] 속성 스키마의 birthYear(${BIRTH_SLOT})·country(${COUNTRY_SLOT}) 슬롯이 AttrGate 의 전제(0·1)와 달라 AttrGate 배포를 건너뛴다`); return; }
  if (!reg.factoryAddress) { console.warn('[rp] 팩토리가 없어 AttrGate 배포를 건너뛴다'); return; }
  if (reg.attrGateAddress && reg.attrGateFactory === reg.factoryAddress && reg.attrGatePolicy?.root === ALLOWED_COUNTRIES_ROOT.toString() && reg.attrGatePolicy?.minAge === MIN_AGE.toString()) return;
  const signer = await provider.getSigner(RELAYER_INDEX);
  const attrGateAddress = await deployAttrGate(signer, { factoryAddress: reg.factoryAddress, allowedCountries: ALLOWED_COUNTRIES_EFFECTIVE, minAge: MIN_AGE });
  reg = { ...reg, attrGateAddress, attrGateFactory: reg.factoryAddress, attrGatePolicy: { root: ALLOWED_COUNTRIES_ROOT.toString(), minAge: MIN_AGE.toString() } };
  writeJsonAtomic(REG_FILE, reg, 0o600);
  console.log(`[rp] AttrGate 배포: ${attrGateAddress} (factory ${reg.factoryAddress}, 국가∈{${ALLOWED_COUNTRY_NAMES.join(',')}}, minAge ${MIN_AGE}) → ${REG_FILE}`);
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
    throw new Error('등록 파일의 cert_s 가 현재 pk_CIA 로 검증되지 않는다 — IdP 키가 바뀌었으면 파일을 지우고 재기동');
  }
  // 2026-09-21 이전에 승인된 등록 파일에는 X_AA·share_pok 가 없다. 등록을 다시 받으면 x_svc 가 바뀌어 옛 태그를 못 열므로
  // 강제하지 않고 경고만 남긴다 — 조각 검사를 원하면 파일을 지우고 재등록한다.
  if (reg.X_AA && reg.share_pok) {
    if (!(await verifyCiaShare(reg.arid, reg.pk_trace, reg.X_AA, reg.share_pok))) throw new Error('등록 파일의 IdP 조각 증명(share_pok)이 검증되지 않는다 — 파일이 손상됐거나 pk_trace ≠ X_svc + X_AA');
  } else {
    console.warn('[rp] 등록 파일에 IdP 조각 증명(X_AA·share_pok)이 없다(2026-09-21 이전 승인) — rogue key 검사를 건너뛴다');
  }
  await activate();
} else {
  if (await registerOnce()) await activate();
  else {
    console.log(`[rp] 등록 대기 (arid=${reg.arid}) — IdP 관리자 페이지에서 승인하면 ${POLL_MS} ms 안에 활성화된다`);
    // 한 틱이 끝나기 전에(특히 activate() 의 팩토리 배포는 느리다) 다음 틱이 시작하지 않도록 재진입을 막는다 —
    // clearInterval 만으로는 부족하다: 두 틱이 거의 동시에 registerOnce() 를 시작해 버리면 clearInterval 이
    // 걸리기 전에 이미 둘 다 진행 중이라 팩토리가 중복 배포되고 reg.factoryAddress 가 경합으로 덮어써진다.
    let activating = false;
    const timer = setInterval(async () => {
      if (activating) return;
      activating = true;
      try { if (await registerOnce()) { clearInterval(timer); await activate(); } }
      catch (e) {
        // 거절·인증서 검증 실패는 영구 상태라 멈춘다. 그 외(IdP 일시 장애·네트워크 오류)는 계속 재시도한다.
        if (e.permanent) { console.error(`[rp] ${e.message}`); clearInterval(timer); }
        else console.warn(`[rp] 등록 조회 실패, 다시 시도: ${e.message}`);
      } finally { activating = false; }
    }, POLL_MS);
    timer.unref();
  }
}

// ---- r_s·r_rp: 메모리, TTL, 로그인 때 1회 소비. 소비된 r_s 는 세션 식별자가 된다(설계 §7). r_rp 는 세션 가명·C_s 블라인딩의 재료(V11 §3.2) — IdP 에 보내지 않는다 ----
const challenges = new Map();   // r_s(10진) → { expiresAt(ms), r_rp(10진) }
// 2026-10-16: 이 RP 가 지운 세션의 묘비(r_s). 사용자 페이지의 세션 확인(/api/mode3/sessions/check)이 "지운 것"과 "아직 모르는 것"(로그인 결과가
// 제출되기 전)을 가르는 데 쓴다 — 모르는 것은 null 로 답해 지갑이 방금 만든 세션을 지우지 않게 한다. 최근 1000개만 남긴다.
const removedSessions = new Set();
// 2026-10-21: 모르는 세션(RP 재시작 뒤 등)의 로그아웃도 묘비를 남긴다 — 그 세션은 어차피 이 RP 에서 못 쓰므로, 사용자 페이지가 목록에서 지우게 둔다.
const forgetSession = (k) => { const had = sessions.delete(k); removedSessions.add(k); if (removedSessions.size > 1000) removedSessions.delete(removedSessions.values().next().value); return had; };
const sessions = new Map();     // r_s(10진) → { PPID, pk_i, max_height, allowAgent, root, regRoot, disclosure, auid_s, arid_s, r_rp, at }
function sweepChallenges() { const now = Date.now(); for (const [c, e] of challenges) if (e.expiresAt < now) challenges.delete(c); }
function issueChallenge() {
  sweepChallenges();
  const r_s = randomScalar().toString(), r_rp = randomScalar().toString();
  const expiresAt = Date.now() + CHALLENGE_TTL_MS;
  challenges.set(r_s, { expiresAt, r_rp });
  return { r_s, r_rp, expiresAt };
}
/** 소비. 모르거나 만료면 null, 아니면 그 챌린지의 r_rp(10진). */
function consumeChallenge(r_s) {
  const e = challenges.get(r_s);
  if (e === undefined) return null;
  challenges.delete(r_s);
  return Date.now() <= e.expiresAt ? e.r_rp : null;
}

// 마지막으로 본 head − lastPublishedBlock(health 표시용, 설계 2026-09-25 §1.1 "RP 가 마지막으로 본 값").
// 체인 조회를 새로 하지 않는다 — 세션 요청이 이미 읽은 view 에서만 기록하므로 아직 본 적이 없으면 null 이다.
let lastRootAge = null;
// 체험 모드의 4·5단계 판정용 프로세스 안 카운터(설계 §3.2 — 관리자·계정 페이지에는 페이지 메모리가 없다).
// 개수만 health 에 싣고, 서버를 다시 띄우면 0 부터다.
let requestCount = 0;          // 받아들인 세션 요청(/api/mode3/request)
let disclosedLoginCount = 0;   // 공개 조건을 실은 로그인(mask ≠ 0 이거나 집합 공개)

const logins = [];   // { PPID, at, root, r_s }. 메모리만
// 릴레이가 보낸 트랜잭션 기록(2026-10-21, RP 관리자 페이지) — 로그인 기록과 같이 메모리만. RP 가 원래 아는 것(계정·PPID·calldata 의 받는 주소·금액)만 담는다.
const relayedTxs = [];   // { at, txHash, account, PPID, kind, target, value, deployTxHash, status, blockNumber }
// r_s 전문은 내지 않는다 — (PPID, 시각) 과 함께 RP 의 사용자 활동 기록이다(설계 2026-09-16 §5).
const rsShort = (r) => r.slice(0, 8) + '…';
// 선택 공개(2026-09-22 §6.2) — verifyLogin 이 돌려주는 bigint 조각을 세션·로그인 로그·조회 API 에 쓸 문자열로.
const discOf = (d) => ({ mask: d.mask.toString(), lo: d.lo.map(String), hi: d.hi.map(String), set: d.sel !== 0n ? { sel: d.sel.toString(), root: d.root.toString() } : null });

// ---- 앱 ----
const app = express();
// 본문 상한은 IdP(cia.js) 와 같은 256kb(2026-10-26 리뷰 E1). 정상 로그인 본문은 수 KB, 릴레이 calldata 도 수십 KB 안이다.
// 더 크면 기록해 둔 트랜스크립트가 개봉 요청에서 IdP 상한에 걸리는 비대칭이 생긴다(기록은 정규 proof 로만 하지만 이중 방어).
app.use(express.json({ limit: '256kb' }));

// 데모 공통 레이어(설계 2026-09-24-mode3-demo-ux §1.2) — mode3/common 만 정적으로 낸다.
app.use('/common', express.static(path.join(__dirname, 'mode3', 'common')));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'rp.html')));
// 2026-10-16: 운영자 화면(로그인 기록·승인 개봉) — 고객 페이지에서 떼어냈다. 같은 서버·같은 API, 페이지만 다르다.
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'rp_admin.html')));

// rp_info 와 health(§1.1)가 같은 정책 값을 쓴다 — 한 곳에서만 만든다.
// birthYearMin(최종 리뷰 I1): 나이 술어의 lo 하한 = 스키마의 출생연도 min. 페이지가 lo 로 보내고 로그인 검사가 lo ≥ 이 값을 요구한다.
const BIRTH_MIN = BIRTH_SLOT >= 0 ? BigInt(ATTR_SCHEMA.schema.slots[BIRTH_SLOT].min ?? 0) : null;
const currentPredicates = () => ({ allowedCountries: ALLOWED_COUNTRIES_EFFECTIVE.map(String), allowedCountryNames: ALLOWED_COUNTRY_NAMES, allowedCountriesRoot: ALLOWED_COUNTRIES_ROOT.toString(), minAge: MIN_AGE.toString(), birthYearMin: BIRTH_MIN === null ? null : BIRTH_MIN.toString(), attrSchema: schemaInfo(ATTR_SCHEMA.schema, ATTR_SCHEMA.hash) });

// 2026-10-21: MODE3_REQUIRE_DISCLOSURE=1(데모의 zkTWO)이면 로그인 때 국가 집합·나이 술어를 **서버가** 요구한다 — 페이지의 체크박스와 무관. 기본은 끔(zkONE: 누구나).
const REQUIRE_DISCLOSURE = process.env.MODE3_REQUIRE_DISCLOSURE === '1';
app.get('/api/mode3/rp_info', (req, res) => {
  res.json({ name: RP_NAME, requireDisclosure: REQUIRE_DISCLOSURE,   // 2026-10-15: 페이지 브랜드(zkONE/zkTWO) 표기용
       status: reg.status, arid: reg.arid, origin: reg.origin, cert_s: reg.cert_s, pk_trace: reg.pk_trace, logAddress: LOG_ADDRESS, mirrorAddress: MIRROR_ADDRESS, walletAgentOrigin: WALLET_ORIGIN, ciaUrl: CIA_URL, pkCiaSource: pkCIA.source, chainId: chainId.toString(), active: Boolean(verifier), factoryAddress: reg.factoryAddress ?? null, verifierAddress: reg.verifierAddress ?? null, attrGateAddress: reg.attrGateAddress ?? null, predicates: currentPredicates(),
       oidc: pkCIA.oidc });   // 2026-10-16: IdP 의 public_keys.oidc 중계 — 페이지는 enabled·provider 만 본다
});

// 상태 엔드포인트(설계 2026-09-25 §1) — 민감정보 없음, 지갑·AA 오리진에만 CORS.
// 허용 오리진은 설정값에서 origin 만 남겨 만든다 — MODE3_CIA_URL 끝의 '/' 같은 것이 CORS 를 조용히 깨뜨리지 않게.
const HEALTH_ALLOW = originList(WALLET_ORIGIN, CIA_URL);
app.get('/mode3/health', async (req, res) => {
  applyHealthHeaders(req, res, HEALTH_ALLOW);
  let chain = null;
  // 체인 조회 예산은 1.2초 — 페이지의 요청 예산(3초)보다 넉넉히 짧게 둔다(설계 §1.3).
  try { chain = { id: chainId.toString(), head: (await bounded(provider.getBlockNumber(), 1200)).toString() }; } catch { /* 체인 없음·응답 없음 */ }
  const p = currentPredicates();
  res.json(buildRpHealth({ now: new Date().toISOString(), chain, status: reg.status, active: !!verifier, inactiveReason: verifier ? null : inactiveReason(), maxRootAge: Number(EFFECTIVE_MAX_ROOT_AGE), rootAge: lastRootAge,
    sessions: sessions.size, requests: requestCount, disclosures: disclosedLoginCount,
    predicates: { countries: p.allowedCountries.length, minAge: Number(p.minAge) }, walletAgentOrigin: WALLET_ORIGIN, ciaUrl: CIA_URL }));
});
app.post('/api/mode3/challenge', (req, res) => {
  // 봉투를 다른 라우트와 같은 { ok, reason } 으로 맞춘다 — 페이지가 상태 코드가 아니라 본문으로 사유를 읽는다(2026-09-23 최종 리뷰 M3).
  if (!verifier) return res.status(503).json({ ok: false, reason: inactiveReason() });
  res.json({ ok: true, ...issueChallenge(), factoryAddress: reg.factoryAddress ?? null, attrGateAddress: reg.attrGateAddress ?? null });
});

async function verifyBody(req, res, r_s, r_rp) {
  const { proof, publicSignals, sig } = req.body ?? {};
  if (!proof || !Array.isArray(publicSignals) || typeof sig !== 'string') { res.status(400).json({ ok: false, reason: 'malformed' }); return null; }
  // proof 정규형(2026-10-26 리뷰 E1): 비정규 숫자·덧붙인 원소·필드 밖 좌표는 형식 오류(400)다. verifyLogin 도 같은 검사를 하고 정규형을 돌려준다.
  const canon = canonicalProof(proof);
  if (!canon) { res.status(400).json({ ok: false, reason: 'malformed', detail: 'proof' }); return null; }
  return verifier.verifyLogin({ proof: canon, publicSignals, sig, r_s, r_rp });
}

app.post('/api/mode3/login', async (req, res) => {
  try {
    if (!verifier) return res.status(503).json({ ok: false, reason: inactiveReason() });
    const { r_s } = req.body ?? {};
    if (typeof r_s !== 'string' || !/^[0-9]+$/.test(r_s)) return res.status(400).json({ ok: false, reason: 'malformed' });
    // V7 술어 요구(스펙 §6, Ruling 항목 5): 요구는 페이지가 `require` 로 싣는다 — 서버 정책 게이트가 아니다(데모 의미).
    // 운영이라면 서버가 강제해야 한다. 여기서는 형식만 검사한다 — plain object 가 아니면(배열 등) 조용히 무시하지 않고 막는다.
    let requireP = req.body.require ?? null;
    if (requireP !== null && (typeof requireP !== 'object' || Array.isArray(requireP))) return res.status(400).json({ ok: false, reason: 'malformed' });
    // 2026-10-21: 서버 정책 게이트 — MODE3_REQUIRE_DISCLOSURE=1 이면 페이지가 뭘 보내든 국가 집합·나이 술어를 요구한다(없으면 아래서 predicate_unmet).
    if (REQUIRE_DISCLOSURE) requireP = { ...(requireP ?? {}), countrySet: true, minAge: true };
    const rsStr = BigInt(r_s).toString();
    const r_rp = consumeChallenge(rsStr);   // 검증 전에 소비
    if (r_rp === null) return res.status(401).json({ ok: false, reason: 'bad_challenge' });
    const v = await verifyBody(req, res, BigInt(rsStr), BigInt(r_rp)); if (v === null) return;
    if (!v.ok) return res.json({ ok: false, reason: v.reason });
    if (requireP) {
      const d = v.disclosure;
      // 슬롯 번호는 스키마에서 찾는다(스펙 2 §5.4). 슬롯이 없으면 그 조건은 요구할 수 없다 — predicate_unavailable.
      if (requireP.countrySet) {
        if (COUNTRY_SLOT < 0) return res.json({ ok: false, reason: 'predicate_unavailable' });
        if (!(d.sel === BigInt(COUNTRY_SLOT) + 1n && d.root === ALLOWED_COUNTRIES_ROOT)) return res.json({ ok: false, reason: 'predicate_unmet' });
      }
      if (requireP.minAge) {
        if (BIRTH_SLOT < 0) return res.json({ ok: false, reason: 'predicate_unavailable' });
        // lo ≥ 스키마 min(최종 리뷰 I1): 출생연도 0 은 "값 없음"인데 hi 만 보면 [0, 올해 − minAge] 가 통과한다. 지갑이 lo ≤ a₀ 를
        // 강제하므로 0 인 계정은 이 술어를 만들 수 없다. 온체인 AttrGate(불변)는 hi 만 본다 — 런북 "수용한 한계".
        if (!(((d.mask >> BigInt(BIRTH_SLOT)) & 1n) === 1n && d.lo[BIRTH_SLOT] >= BIRTH_MIN && d.hi[BIRTH_SLOT] + MIN_AGE <= BigInt(new Date().getUTCFullYear()))) return res.json({ ok: false, reason: 'predicate_unmet' });
      }
    }
    const at = new Date().toISOString();
    const disclosure = discOf(v.disclosure);
    sessions.set(rsStr, { PPID: v.PPID.toString(), pk_i: v.pk_i.toString(), max_height: v.max_height.toString(), allowAgent: v.allowAgent.toString(), root: v.root.toString(), regRoot: v.regRoot.toString(), disclosure, auid_s: v.auid_s.toString(), arid_s: v.arid_s.toString(), r_rp, at });
    // 2026-10-16: 같은 계정(PPID)의 이전 세션은 새 로그인이 대체한다 — "RP 당 활성 세션 하나". IdP 폐기 트리는 건드리지 않는다(강한 무효화는 V8 세션 폐기).
    for (const [k, s] of sessions) if (k !== rsStr && s.PPID === v.PPID.toString()) forgetSession(k);
    if (disclosure.mask !== '0' || disclosure.set) disclosedLoginCount++;
    logins.push({ PPID: v.PPID.toString(), at, root: v.root.toString(), r_s: rsShort(rsStr), allowAgent: v.allowAgent.toString(), disclosure });
    // §5 로그인 로그 — 전체 r_s 와 트랜스크립트(태그 포함). 개봉 요청의 재료다. 조회 API 로는 내지 않는다.
    fs.appendFileSync(LOGIN_LOG, JSON.stringify({ at, PPID: v.PPID.toString(), r_s: rsStr, pk_i: v.pk_i.toString(), max_height: v.max_height.toString(), allowAgent: v.allowAgent.toString(), root: v.root.toString(), disclosure, auid_s: v.auid_s.toString(), arid_s: v.arid_s.toString(), publicSignals: v.publicSignals, proof: v.proof }) + '\n', { mode: 0o600 });
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
    const v = await verifyBody(req, res, BigInt(rsStr), BigInt(s.r_rp)); if (v === null) return;
    if (!v.ok) return res.json({ ok: false, reason: v.reason });
    if (v.PPID.toString() !== s.PPID || v.pk_i.toString() !== s.pk_i) return res.status(401).json({ ok: false, reason: 'session_mismatch' });
    // 재검증은 세션을 **마지막 증명에 다시 묶는다**(2026-09-25 리뷰 C-4). root·disclosure 만 갱신하면
    // allowAgent=1 로 만든 세션이 allowAgent=0 인 성명으로 재검증된 뒤에도 1 로 남아, 세션 상태가 실제로
    // 보증된 것보다 넓어진다(만료 max_height 도 같다 — /api/mode3/request 의 만료 판정이 그 값을 쓴다).
    s.root = v.root.toString();
    s.regRoot = v.regRoot.toString();
    s.disclosure = discOf(v.disclosure);
    s.max_height = v.max_height.toString();
    s.allowAgent = v.allowAgent.toString();
    res.json({ ok: true, r_s: rsStr, root: s.root });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

// 2026-10-21: RP 페이지의 "현재 잔액 확인" — 세션 서명 검증 뒤 돌려주는 거래소 꾸밈의 시연용 잔액(실제 장부 없음, rp.html 의 내 자산 목록과 같은 값).
const DEMO_LEDGER = { KRW: '1,000,000', BTC: '0.02', ETH: '0.5' };
app.post('/api/mode3/request', async (req, res) => {
  try {
    if (!verifier) return res.status(503).json({ ok: false, reason: inactiveReason() });
    const { r_s, body, sig } = req.body ?? {};
    if (typeof r_s !== 'string' || !/^[0-9]+$/.test(r_s) || typeof body !== 'string' || typeof sig !== 'string') return res.status(400).json({ ok: false, reason: 'malformed' });
    const rsKey = BigInt(r_s).toString();   // login·revalidate 와 같은 정규 키(2026-09-18 점검 9)
    const s = sessions.get(rsKey);
    if (!s) return res.status(401).json({ ok: false, reason: 'no_session' });
    // 폐기가 효력을 갖는 지점: root 가 바뀌었으면 세션은 재검증 전까지 요청을 받지 않는다.
    // V9 에서는 계정·자격증명 폐기가 등록부 root(regRoot)만 바꾸므로 두 root 를 함께 본다.
    const view = await verifier.refreshChainView().catch(() => null);
    if (view) lastRootAge = Number(view.head - view.lastPublishedBlock);   // health 표시용(§1.1)
    if (!view) return res.status(503).json({ ok: false, reason: 'chain_unavailable' });
    if (view.head > BigInt(s.max_height)) { forgetSession(rsKey); return res.status(401).json({ ok: false, reason: 'expired' }); }
    if (view.root.toString() !== s.root || view.regRoot.toString() !== s.regRoot) return res.status(401).json({ ok: false, reason: 'revalidate_required' });
    // b′ — root 게시 나이(2026-09-23 점검 C-1, 리뷰 Ruling 1). verifyLogin 의 b′ 와 같은 상한·같은 위치(root 일치 뒤).
    // IdP 게시가 멈추면 새 로그인뿐 아니라 이미 있는 세션의 요청도 함께 멈춘다. 세션 상태가 아니라 게시 생존의
    // 문제이므로 chain_unavailable 과 같은 503 이다.
    if (view.head - view.lastPublishedBlock > EFFECTIVE_MAX_ROOT_AGE) return res.status(503).json({ ok: false, reason: 'root_too_old' });
    if (!verifySessionRequest({ pk_i: s.pk_i, r_s: rsKey, body, sig })) return res.status(401).json({ ok: false, reason: 'bad_signature' });
    requestCount++;
    // 'balance'(2026-10-21): 거래 없이 세션으로 RP 와 상호작용하는 예 — 시연용 장부를 돌려준다.
    if (body === 'balance') return res.json({ ok: true, echo: body, PPID: s.PPID, balance: { ledger: DEMO_LEDGER } });   // 온체인 계정 잔액은 내지 않는다(사용자 요청 2026-10-21)
    res.json({ ok: true, echo: body, PPID: s.PPID });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

// ---- 릴레이(설계 2026-10-15 §5.1, 계획 R6): 브라우저 사용자 페이지의 execute 를 RP 의 릴레이어 계정이 대신 보낸다 ----
// 릴레이어는 서명만 한다 — 사용자 비밀을 보지 않는다. 검열(거부·지연) 가능성은 런북의 한계에 적는다.
// 검사 순서: 활성 → 본문 형식(value 0 고정) → execute 셀렉터·pub 34(2026-10-22 §6.5 counter 추가)·pub[1]=arid → to = computeAddress(pub[0])
//   → Groth16 오프체인 확인(2026-10-26 리뷰 E2) → 속도 제한 → (코드 없으면 deploy) → estimateGas ≤ cap → 전송.
// 증명 확인이 배포보다 앞이어야 한다 — arid 는 공개이고 to 는 PPID 로 맞출 수 있어, 없으면 PPID 만 바꿔 가며 릴레이어 가스로
// 빈 계정을 끝없이 배포시킬 수 있다(속도 제한은 대상별이라 매번 새 키). 속도 제한보다도 앞에 둬 틀린 증명이 남의 몫을 깎지 않게 한다.
const RELAY_GAS_CAP = BigInt(process.env.MODE3_RELAY_GAS_CAP || 1_200_000);
const RELAY_RATE = Number(process.env.MODE3_RELAY_RATE || 10);     // 계정당 분당
const relayCors = cors({ origin: (origin, cb) => cb(null, origin === WALLET_ORIGIN), methods: ['POST', 'GET'], allowedHeaders: ['Content-Type'] });
app.options('/api/mode3/relay', relayCors);
const relayHits = new Map();   // to(소문자) → [ms, …] 지난 60초
const isAddr = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
const revertName = (e) => { try { const n = e?.data ? walletInterface.parseError(e.data)?.name : null; if (n) return n; } catch { /* 모르는 에러 */ } return e?.revert?.name ?? e?.shortMessage ?? e?.message ?? 'revert'; };
app.post('/api/mode3/relay', relayCors, async (req, res) => {
  try {
    if (!verifier || !reg.factoryAddress) return res.status(503).json({ ok: false, reason: 'relay_inactive', detail: verifier ? 'no_factory' : inactiveReason() });
    const { to, data, value } = req.body ?? {};
    if (value !== undefined && String(value) !== '0') return res.status(400).json({ ok: false, reason: 'relay_bad_calldata', detail: 'value' });
    if (!isAddr(to) || typeof data !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(data)) return res.status(400).json({ ok: false, reason: 'relay_bad_calldata', detail: 'format' });
    const dec = decodeExecuteCalldata(data);
    if (!dec || dec.pub.length !== PUB_INDEX.COUNT) return res.status(400).json({ ok: false, reason: 'relay_bad_calldata', detail: 'selector' });
    if (dec.pub[PUB_INDEX.ARID] !== String(reg.arid)) return res.status(400).json({ ok: false, reason: 'relay_bad_calldata', detail: 'arid' });
    const factory = new ethers.Contract(reg.factoryAddress, FACTORY_ABI, provider);
    const ppid = BigInt(dec.pub[PUB_INDEX.PPID]);
    const expected = await factory.computeAddress(ppid);
    if (expected.toLowerCase() !== to.toLowerCase()) return res.status(400).json({ ok: false, reason: 'relay_bad_target' });
    if (!(await verifyCalldataProof({ vkey, a: dec.a, b: dec.b, c: dec.c, pub: dec.pub }))) return res.status(400).json({ ok: false, reason: 'relay_bad_proof' });
    const key = to.toLowerCase(), now = Date.now();
    const hits = (relayHits.get(key) ?? []).filter((t) => now - t < 60_000);
    if (hits.length >= RELAY_RATE) { relayHits.set(key, hits); return res.status(429).json({ ok: false, reason: 'relay_rate_limited' }); }
    hits.push(now); relayHits.set(key, hits);
    const relayer = await provider.getSigner(RELAYER_INDEX);
    let deployTxHash = null;
    if ((await provider.getCode(to)) === '0x') { const dtx = await factory.connect(relayer).deploy(ppid); await dtx.wait(); deployTxHash = dtx.hash; }
    let gas;
    try { gas = await provider.estimateGas({ from: await relayer.getAddress(), to, data }); }
    catch (e) { return res.status(400).json({ ok: false, reason: 'relay_gas', detail: revertName(e) }); }
    if (gas > RELAY_GAS_CAP) return res.status(400).json({ ok: false, reason: 'relay_gas', detail: `gas ${gas} > cap ${RELAY_GAS_CAP}` });
    const gasLimit = (gas * 12n) / 10n > RELAY_GAS_CAP ? RELAY_GAS_CAP : (gas * 12n) / 10n;
    const tx = await relayer.sendTransaction({ to, data, gasLimit });
    const gate = reg.attrGateAddress ? String(reg.attrGateAddress).toLowerCase() : null;
    const rec = { at: new Date().toISOString(), txHash: tx.hash, account: to, PPID: ppid.toString(), kind: gate && String(dec.payload.to).toLowerCase() === gate ? 'claim' : 'transfer',
      target: dec.payload.to, value: dec.payload.value.toString(), deployTxHash, status: 'pending', blockNumber: null };
    relayedTxs.push(rec);
    // 영수증이 오면 상태를 채운다. 계정 안 호출이 실패했으면(Executed.success=false) 트랜잭션이 들어갔어도 실패로 본다.
    tx.wait().then((rc) => { rec.blockNumber = rc?.blockNumber ?? null; rec.status = rc?.status === 1 && parseExecuteReceipt(rc, to).executed?.success !== false ? 'success' : 'failed'; },
      () => { rec.status = 'failed'; });
    res.json({ ok: true, txHash: tx.hash, deployed: Boolean(deployTxHash), deployTxHash });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});
app.get('/api/mode3/relay/:txHash', relayCors, async (req, res) => {
  try {
    const { txHash } = req.params;
    if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) return res.status(400).json({ ok: false, reason: 'malformed' });
    const rc = await provider.getTransactionReceipt(txHash);
    if (!rc) return res.json({ ok: true, pending: true });
    res.json({ ok: true, pending: false, status: rc.status, blockNumber: rc.blockNumber, gasUsed: rc.gasUsed.toString(), to: rc.to });
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
  // exportSolidityCallData 는 b 의 각 행을 (y, x) 로 뒤집는다 — proofFromCalldata 가 되돌린다(릴레이의 증명 확인과 같은 변환).
  return { publicSignals: d.pub, proof: proofFromCalldata(d), PPID: d.pub[0] };
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
    const c1 = { x: BigInt(T.publicSignals[PUB_INDEX.TAG_C1_X]), y: BigInt(T.publicSignals[PUB_INDEX.TAG_C1_Y]) };
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
    // 다른 라우트와 같이 fail-closed(2026-09-25 리뷰 C-5) — 검증기가 없는 RP 가 IdP 로 서명한 조회를 중계하지 않는다.
    if (!verifier) return res.status(503).json({ ok: false, reason: inactiveReason() });
    const ts = Math.floor(Date.now() / 1000).toString();
    const sig = await signOpenResult(serviceWallet, req.params.id, ts);
    const r = await fetch(`${CIA_URL}/cia/open/${encodeURIComponent(req.params.id)}?ts=${ts}&sig=${encodeURIComponent(sig)}`);
    res.status(r.status).json(await r.json().catch(() => ({})));
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

app.get('/api/mode3/logins', (req, res) => res.json({ logins }));
app.get('/api/mode3/txs', (req, res) => res.json({ txs: relayedTxs }));   // 개봉 경로와 같이 데모용, 인증 없음(관리자 페이지가 읽는다)
// 2026-10-16 로그아웃: 이 RP 가 세션을 잊는다(세션키 서명은 요구하지 않는다 — 피해가 없는 동작). 그 r_s 는 이후 unknown_session.
// 2026-10-21: 사용자 페이지(지갑 오리진)도 부른다 — 세션 폐기 뒤 이 RP 에 알려 RP 페이지가 바로 로그아웃 상태가 되게(최선 노력, 폐기 자체는 체인 root 로 효력).
app.options('/api/mode3/logout', relayCors);
app.post('/api/mode3/logout', relayCors, (req, res) => {
  const { r_s } = req.body ?? {};
  if (typeof r_s !== 'string' || !/^[0-9]+$/.test(r_s)) return res.status(400).json({ ok: false, reason: 'malformed' });
  const key = BigInt(r_s).toString();
  const removed = forgetSession(key);
  res.json({ ok: true, removed });
});
// 2026-10-16 세션 확인(사용자 페이지용, 지갑 오리진 CORS): 지갑이 자기 세션들이 이 RP 에 아직 있는지 묻고 없는 것을 목록에서 정리한다.
// RP 가 이미 아는 r_s 만 오간다(새로 새는 정보 없음). 최대 50개.
app.options('/api/mode3/sessions/check', relayCors);
app.post('/api/mode3/sessions/check', relayCors, (req, res) => {
  const list = Array.isArray(req.body?.r_s) ? req.body.r_s.filter((x) => typeof x === 'string' && /^[0-9]+$/.test(x)).slice(0, 50) : null;
  if (!list) return res.status(400).json({ reason: 'malformed' });
  // true=있다, false=이 RP 가 지웠다(로그아웃·대체·만료), null=모른다(아직 제출 전이거나 RP 재시작) — 지갑은 false 만 정리한다.
  const alive = {}; for (const x of list) { const k = BigInt(x).toString(); alive[x] = sessions.has(k) ? true : (removedSessions.has(k) ? false : null); }
  res.json({ alive });
});
app.get('/api/mode3/sessions', (req, res) => res.json({ sessions: [...sessions.entries()].map(([r_s, s]) => ({ r_s: rsShort(r_s), PPID: s.PPID, pk_i: s.pk_i, max_height: s.max_height, allowAgent: s.allowAgent, root: s.root, disclosure: s.disclosure, auid_s: rsShort(s.auid_s), arid_s: rsShort(s.arid_s), at: s.at })) }));

// 라우트 밖으로 샌 오류의 마지막 그물(2026-10-11): JSON 파싱 실패 400 malformed, 그 밖 500 internal — 다른 라우트와 같은 { ok, reason } 봉투.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ ok: false, reason: 'malformed' });
  console.error(`[rp] 처리되지 않은 라우트 오류 ${req.method} ${req.path}: ${err?.stack ?? err}`);
  res.status(500).json({ ok: false, reason: 'internal', detail: err?.message });
});
process.on('unhandledRejection', (e) => console.error(`[rp] unhandledRejection: ${e?.stack ?? e}`));
app.listen(PORT, BIND_HOST, () => {
  console.log(`Mode 3 RP at http://${BIND_HOST}:${PORT} (arid=${reg.arid ?? '-'} status=${reg.status}, origin=${reg.origin}, log=${LOG_ADDRESS}, wallet=${WALLET_ORIGIN}, pk_CIA=${pkCIA.source}, chain=${chainId})`);
});
