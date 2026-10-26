// Mode 3 지갑 에이전트 (:5100). 스펙: docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md §3
//
// Mode 2 의 wallet_agent.js 와 나란히 두는 별도 프로세스다. 그쪽 코드를 import 하지 않는다.
// 암호학은 전부 lib/mode3_wallet.js 에 있고 여기는 상태 파일 + HTTP 만이다.
// 로그인마다 발급된다(설계 2026-09-15 §5) — 성명은 세션(r_s) 단위이고 세션 안에서만 재사용한다.
// V4(2026-09-18): 자격증명은 max_height·allowAgent, 세션은 RP 팩토리 주소를 들고 /wallet/tx 로 온체인 실행(설계 §6.3).
// V5(2026-09-21): 자격증명 이중 구조 — 사용자 자격증명(C_u, 사용자당 하나, 폐기 리프)과 세션 자격증명(C_s, 로그인마다).
//   사용자 자격증명은 첫 로그인 때 받고, 폐기되면 다음 로그인이 등록부로 알아채 새로 받는다 — 경합으로 IdP 가 그 자리에서
//   "이미 물렸다"(409 cred_revoked)고 거절하면 한 번만 다시 시도한다(/wallet/login 의 cred_revoked 재시도).
// V11(2026-10-12): 속성은 사용자가 지갑에 넣는다(profile → attrs, D15, PUT /wallet/profile), 발급마다 π_IdP, RP 챌린지 r_rp, 상태 v9.
// Snap(2026-09-22 metamask-snap §3.3): MODE3_WALLET_SECRETS=snap 이면 등록 비밀은 Snap 이 들고, 요청마다 첨부된 witness 로
//   요청 범위 SecretSource 를 만든다. 파일에는 공개 부분만 남고, 로그인한 세션의 증인은 메모리(sessions[r_s].witness)에만 둔다.
//   트랜잭션은 /wallet/tx/prepare(calldata) → MetaMask 가 전송 → /wallet/tx/record(영수증) 로 나눈다.
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeJwt } from 'jose';
import { ethers } from 'ethers';
import { readJson, writeJsonAtomic } from './lib/mode3_state.js';
import { createSecretSource, stripSecrets, validateWitness } from './lib/mode3_secret_source.js';
import { DEFAULT_ATTR_SCHEMA, loadSchema, assertPredicateTypes, decodeAttrs, schemaInfo, encodeProfile, normalizeProfile } from './lib/mode3_attr_schema.js';
import { createRegistration, createSessionKey, buildIssueRequest, buildCredentialProof, signChallenge, signSessionRequest, signSlotRequest, signRevokeSession, signRegistration, eddsaPubOf, normalizeDisclosure, normalizeSet, disclosureKey, hasPredicate, ProofCache, chooseMaxHeight, syncRegistryTree } from './lib/mode3_wallet.js';
import { sessionLeafRange, SESSION_BOUND_MAX, signRevokeBind } from './lib/mode3_revocation.js';
import { createRevocationSync } from './lib/mode3_rcl_sync.js';
import { registryLeaf } from './lib/mode3_registry.js';
import { signPayload, statementDigestFields, proofToCalldata, parseExecuteReceipt, decodeExecuteCalldata, factoryAt, walletAt, walletInterface, FACTORY_ABI, verifyReferenceCode, FACTORY_MAX_ROOT_AGE_BAND, FACTORY_MAX_LIFETIME_BAND, FACTORY_ROOT_WINDOW_BAND, PUB_INDEX, LOGIN_COUNTER } from './lib/mode3_onchain.js';
import { SCALAR_MAX, ppid, randomScalar, auidOf, aridSOf } from './lib/mode3_credential.js';
import { uidOf, regNonce, issueNonce, newRevokeNonce } from './lib/mode3_oidc_nonce.js';
import { verifyRpCert } from './lib/mode3_rp_cert.js';
import { MODE3_ROOTS_ABI } from './lib/mode3_log.js';
import { buildWalletHealth, applyHealthHeaders, bounded, originList, allowOrigin } from './lib/mode3_health.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.MODE3_WALLET_PORT) || 5100;
const STATE_FILE = process.env.MODE3_WALLET_STATE_FILE || path.join(__dirname, 'mode3_wallet_state.json');
// 폐기 트리 체크포인트(공개 데이터만). 지우면 다음 동기화가 창세기부터 재생한다(스펙 2026-09-23 §4).
const RCL_CACHE_FILE = process.env.MODE3_WALLET_RCL_CACHE || path.join(path.dirname(STATE_FILE), 'mode3_wallet_rcl.json');
const CIA_URL = process.env.MODE3_CIA_URL || 'http://127.0.0.1:4100';
// RP 오리진 허용 목록(2026-09-30): 쉼표로 여럿 — 지갑 하나가 RP 여럿에 로그인한다(같은 사용자, RP 마다 다른 PPID).
// 끝의 '/' 나 경로가 붙어도 origin 만 남기고, 주소가 아닌 항목은 버린다(originList). 비교는 정확히 같은 origin 만(allowOrigin).
const RP_ORIGINS_ENV = originList((process.env.MODE3_RP_ORIGIN || 'http://127.0.0.1:3100').split(',').map((s) => s.trim()));
if (RP_ORIGINS_ENV.length === 0) throw new Error('MODE3_RP_ORIGIN 에 유효한 origin 이 하나도 없다');
const RP_ORIGIN = RP_ORIGINS_ENV[0];                   // 첫 RP — 로그·health 의 기존 필드(rpOrigin) 표기용(env 기준, 폴링 무관)
// 동적 RP 허용 목록(Task 13, 설계 §5.4): env ∪ IdP GET /cia/rp_origins. isRpOrigin·CORS(loginCors·configCors)·health 의
// 허용 목록이 모두 이 하나의 변수(rpOrigins)를 본다 — 계산은 pollRpOrigins() 한 곳뿐이다(addendum 판정). IdP 가 안 닿으면
// (네트워크 오류·4xx/5xx) 마지막으로 받은 목록을 그대로 둔다 — 허용 목록을 비워 기존 RP 까지 막지 않는다.
let rpOrigins = RP_ORIGINS_ENV;
const isRpOrigin = (o) => allowOrigin(o, rpOrigins);
let pollingRpOrigins = false;   // M7(2026-10-23): 느린 IdP 라도 겹쳐 돌지 않게 — 실행 중이면 이번 주기는 건너뛴다
async function pollRpOrigins() {
  if (pollingRpOrigins) return;
  pollingRpOrigins = true;
  try {
    // M7: IdP 가 응답하지 않으면(네트워크 끊김 등) fetch 가 기본적으로 끝없이 기다릴 수 있다 — 3초로 끊는다.
    const r = await fetch(`${CIA_URL}/cia/rp_origins`, { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      const { origins } = await r.json();
      // originList 는 중복을 거르지 않는다 — env 에 이미 있는 RP 가 IdP 에도 승인돼 있으면(흔한 경우) 그대로 합치면
      // 같은 origin 이 두 번 남는다. isRpOrigin·CORS 는 중복이 있어도 맞게 동작하지만 health 의 rpOrigins 는 화면·테스트가
      // 정확한 목록으로 본다 — Set 으로 걷어낸다(순서는 env 먼저, 그 뒤 IdP 가 더한 새 origin 유지).
      rpOrigins = [...new Set(originList(RP_ORIGINS_ENV, origins))];
    }
  } catch { /* IdP 미응답(네트워크 오류·타임아웃) — 마지막 목록 유지 */ }
  finally { pollingRpOrigins = false; }
}
pollRpOrigins();                       // 기동 직후 1회 즉시(결과를 기다리지 않는다 — 서버 기동을 막지 않는다)
setInterval(pollRpOrigins, 10_000).unref();
// V10(2026-10-02 설계 §5 결정 3): 두 체인. 캐노니컬 Mode3Log(CIA_LOG_ADDRESS)는 폐기 전용 체인(MODE3_REV_CHAIN_RPC, 기본은
// CIA_RPC_URL)에 있고, 지갑이 증명·실행하는 대상 체인(CIA_RPC_URL)에는 그 체인의 거울(MODE3_MIRROR_ADDRESS)이 있다. RP 와
// 계정 컨트랙트는 거울만 읽으므로 π 는 거울의 (revRoot, regRoot) 로 만든다 — 트리는 캐노니컬 이벤트를 거울 epoch 까지 재생해 얻는다.
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const MIRROR_ADDRESS = process.env.MODE3_MIRROR_ADDRESS || null;
const REV_RPC = process.env.MODE3_REV_CHAIN_RPC || RPC_URL;
// 비밀 공급원(설계 2026-09-22 metamask-snap §3.3): file 은 지금처럼 상태 파일, snap 은 요청에 실린 witness(secretSourceFor).
const SECRETS = process.env.MODE3_WALLET_SECRETS || 'file';
if (!['file', 'snap'].includes(SECRETS)) throw new Error(`MODE3_WALLET_SECRETS 는 'file' 또는 'snap' 이어야 한다: ${SECRETS}`);
const SNAP_ID = process.env.MODE3_SNAP_ID || 'local:http://localhost:8082';
const WALLET_ORIGIN = process.env.MODE3_WALLET_PUBLIC_ORIGIN || `http://127.0.0.1:${PORT}`;
// 만료는 지갑이 정한다(설계 2026-09-18 §3.2 갱신): max_height = ceil((head + TTL) / GRID) × GRID. 빈 문자열은 기본값(cia.js 의 envBig 과 같은 관례).
const envBig = (k, d) => { const v = process.env[k]; return v === undefined || v === '' ? BigInt(d) : BigInt(v); };
const TTL_BLOCKS = envBig('MODE3_TTL_BLOCKS', 300);
const HEIGHT_GRID = envBig('MODE3_HEIGHT_GRID', 100);
if (TTL_BLOCKS <= 0n || HEIGHT_GRID <= 0n) throw new Error(`MODE3_TTL_BLOCKS(${TTL_BLOCKS})·MODE3_HEIGHT_GRID(${HEIGHT_GRID}) 는 양수여야 한다`);

// 게시 직후의 로그인이 옛 root 를 보지 않도록 ethers 의 250ms 캐시를 끈다(lib/mode3_wallet.js 주석).
const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 });
// 캐노니컬 체인 읽기 전용(이벤트 재생·캐노니컬 최신 root). 같은 RPC 여도 따로 둔다 — 대상 체인과 다를 수 있다.
const canonProvider = new ethers.JsonRpcProvider(REV_RPC, undefined, { cacheTimeout: -1 });
const mirror = MIRROR_ADDRESS ? new ethers.Contract(MIRROR_ADDRESS, MODE3_ROOTS_ABI, provider) : null;
/** 세 체인 라우트(login·revalidate·tx)의 설정 검사. 문제가 없으면 null, 있으면 503 chain_unavailable 의 detail. */
const chainConfigMissing = () => (!LOG_ADDRESS ? 'CIA_LOG_ADDRESS not configured' : !MIRROR_ADDRESS ? 'MODE3_MIRROR_ADDRESS not configured' : null);

// ---- 상태 ----
// registration: { uid, s_u, sk_u, pk_u:{x,y}, auid(10진), slot, profile:{스키마 이름→값}, attrs:[6개 10진], userCred: { C_u_pt:{x,y}, Cf_u, blind_u, issuedAt } | null }
// sessions:     r_s → { arid, origin, PPID, pk_trace:{x,y}, factoryAddress|null, attrGateAddress|null, allowAgent("0"|"1"), r_rp, auid_s, arid_s,
//                       credential:{Cf_u,Cf_s,max_height,chainid,allowAgent,sigma,pk_CIA,slot,regRoot,epoch,published}, sessionPrivKey, pk_i, issuedAt,
//                       witness?: { s_u, blind_u, attrs, sk_u } }   ← snap 모드 전용, 메모리에만(persist 가 뺀다)
// snap 모드의 registration 은 stripSecrets 결과({ uid, auid, pk_u, slot, profile, attrs, provider, userCred:{Cf_u,issuedAt} }) 다.
// version 9 (2026-10-12, V11): r_u·cm_u 삭제, auid(= Poseidon(T_AUID, uid, s_u))·profile(사용자 입력, D15) 추가; 세션에 r_rp·auid_s·arid_s.
//   옛 파일은 등록만 유지하고(file 모드 — auid 를 s_u 로 재계산; snap 모드는 비밀이 없어 재계산할 수 없으므로 등록을 비운다) 세션·userCred 를 비운다.
// version 10 (2026-10-22): pendingBounds(세션키별 체인 반영 대기 중인 setSessionBound 요청) 추가 — 옛 파일은 빈 배열로 시작한다.
const WALLET_STATE_VERSION = 10;
const DEFAULT_PROFILE = Object.freeze({ birthYear: '1990', country: 'KR' });   // 데모 testuser 기본값(스펙 §7). 사용자가 등록 폼에서 바꿀 수 있다.
let state = readJson(STATE_FILE, { version: WALLET_STATE_VERSION, registration: null, sessions: {}, pendingBounds: [] });
// 세션의 witness 는 메모리에만(스펙 §3.3) — 재시작하면 사라지고 /wallet/revalidate 가 needs_consent 로 다시 동의를 받는다.
function persist() { writeJsonAtomic(STATE_FILE, JSON.parse(JSON.stringify(state, (k, v) => (k === 'witness' ? undefined : v))), 0o600); }
// 2026-10-01 최종 리뷰 A1: 길이 4 짜리 옛 attrs 가 들어오면 화면이 undefined 를 보이고 회로가 500 으로 죽는다 — 매 기동 6칸으로 맞춘다.
function padAttrs6(attrs) { return [...(Array.isArray(attrs) ? attrs : []), '0', '0', '0', '0', '0', '0'].slice(0, 6).map(String); }
if (state.version !== WALLET_STATE_VERSION) {
  console.warn(`[wallet] 상태 파일 버전 ${state.version} → ${WALLET_STATE_VERSION}: 세션·credential 을 비운다(옛 형식). 등록은 file 모드에서만 유지(auid 재계산).`);
  const reg = state.registration ?? null;
  let kept = null;
  if (reg && typeof reg.s_u === 'string' && /^[0-9]+$/.test(reg.s_u) && typeof reg.uid === 'string') {
    kept = { uid: reg.uid, s_u: reg.s_u, sk_u: reg.sk_u, pk_u: reg.pk_u ?? null, auid: (await auidOf({ uid: BigInt(reg.uid), s_u: BigInt(reg.s_u) })).toString(), slot: reg.slot ?? null, profile: reg.profile ?? { ...DEFAULT_PROFILE }, attrs: padAttrs6(reg.attrs), userCred: null };
  } else if (reg) console.warn('[wallet] snap 모드 등록(파일에 비밀 없음)은 auid 를 재계산할 수 없어 등록을 비운다 — 다시 등록한다(Snap 쪽 "초기화" 도 함께)');
  state = { version: WALLET_STATE_VERSION, registration: kept, sessions: {}, pendingBounds: [] };
  persist();
}
state.sessions ??= {};
state.pendingBounds ??= [];
if (state.registration) {
  state.registration.userCred ??= null;
  // 버전은 이미 8이지만 attrs 길이가 6이 아닌 경우(손으로 고친 상태 파일 등) 방어 — 위 이행 분기와 별개로 매번 건다.
  if (!Array.isArray(state.registration.attrs) || state.registration.attrs.length !== 6) {
    console.warn('[wallet] registration.attrs 길이가 6이 아니다 — 6칸으로 맞춘다(상태 파일이 손상됐거나 손으로 고쳤을 수 있다).');
    state.registration.attrs = padAttrs6(state.registration.attrs);
    persist();
  }
}
const cache = new ProofCache();   // (root, r_s) → {proof, publicSignals}. 메모리만
let lastSync = null;              // { root, regRoot, epoch, head, chainId, lastPublishedBlock, canonicalEpoch, tree, registry } — 거울 뷰(V10). V9: userCred.revoked 판정은 lastRegistry(registryCheck 결과)가 대신한다

/** 만료(head > max_height)된 세션을 걷어낸다(설계 §8). 동기화 뒤 head 를 알 때 부른다.
 *  세션의 π 캐시도 같이 버린다 — 남겨 두면 같은 r_s 로 다시 로그인했을 때(root 가 그대로면) 옛 세션의 π 가
 *  히트해 새 pk_i·sig 와 어긋난다(2026-09-23 점검 M-1). */
function pruneSessions(head) {
  let changed = false;
  for (const [k, s] of Object.entries(state.sessions)) if (BigInt(s.credential.max_height) < head) { delete state.sessions[k]; cache.deleteSession(k); changed = true; }
  if (changed) persist();
}

// 증분 동기화 객체. LOG_ADDRESS 가 없으면 null — 그 경우 세 라우트는 지금처럼 chain_unavailable 을 낸다.
// V10: 캐노니컬 로그를 읽으므로 canonProvider 다(대상 체인 provider 가 아니다).
const rcl = LOG_ADDRESS ? createRevocationSync({ provider: canonProvider, logAddress: LOG_ADDRESS, cacheFile: RCL_CACHE_FILE, log: (m) => console.warn(`[wallet] ${m}`) }) : null;
/** 대상 체인 거울의 네 값을 한 블록(head)에서 읽는다 — 서로 다른 블록의 revRoot·regRoot 를 짝짓지 않게. */
async function mirrorView() {
  const head = BigInt(await provider.getBlockNumber());
  const blockTag = Number(head);
  const [revRoot, regRoot, epoch, last] = await Promise.all([mirror.revRoot({ blockTag }), mirror.regRoot({ blockTag }), mirror.epoch({ blockTag }), mirror.lastPublishedBlock({ blockTag })]);
  return { root: BigInt(revRoot), regRoot: BigInt(regRoot), epoch: BigInt(epoch), head, lastPublishedBlock: BigInt(last) };
}
/** 폐기 트리·등록부를 함께 동기화한다(V9). 둘을 그냥 병렬로(Promise.all) 동기화하면 그 사이 IdP 의 게시가 끼어들어
 *  서로 다른 head 의 (revRoot, regRoot) 쌍을 만들 수 있다 — 그 쌍은 한 번도 온체인에 같이 존재한 적이 없어 RP·온체인
 *  검증기가 stale_*로 fail-closed 거절한다. 순차로 동기화해 head 가 같아질 때까지 최대 3 번 재시도한다.
 *  V10(2026-10-02 §5 결정 3): 돌려주는 root·regRoot·epoch·tree·registry 는 **거울 뷰**다 — RP 와 계정 컨트랙트가 거울만
 *  읽으므로 캐노니컬 최신으로 만든 π 는 거울이 따라잡기 전까지 stale 로 거절된다. 캐노니컬 최신 (root, regRoot) 가 거울과 같으면
 *  그 트리를 그대로 쓰고, 다르면(거울이 뒤처짐) 캐노니컬 이벤트를 거울 epoch 까지만 재생해 거울 root 와 대조한다(fail-closed).
 *  canonical 은 캐노니컬 최신 — 내 슬롯 확인(registryCheck)·세션 폐기 사전 확인은 이것으로 해 은퇴·폐기를 거울보다 빨리 안다. */
async function syncAll() {
  const missing = chainConfigMissing();
  if (missing) throw new Error(missing);
  const mv = await mirrorView();
  let rev = null, reg = null;
  for (let i = 0; i < 3; i++) {
    rev = await rcl.sync();
    reg = await syncRegistryTree(canonProvider, LOG_ADDRESS);
    if (BigInt(rev.head) === BigInt(reg.head)) break;
    rev = null;
  }
  if (!rev) throw Object.assign(new Error('sync_unstable'), { reason: 'sync_unstable' });
  const canonical = { root: rev.root, regRoot: reg.root, epoch: reg.epoch, tree: rev.tree, registry: reg.tree };
  // 거울이 캐노니컬보다 앞설 수는 없다(거울은 캐노니컬에 게시된 서명만 받는다) — 그렇게 보이면 두 RPC 가 서로 다른 캐노니컬
  // 로그를 보고 있다는 뜻이므로 증명하지 않는다.
  if (mv.epoch > canonical.epoch) throw Object.assign(new Error(`sync_unstable: 거울 epoch(${mv.epoch}) 가 캐노니컬 epoch(${canonical.epoch}) 보다 앞서 있다`), { reason: 'sync_unstable' });
  // 같으면 rcl 의 공유 메모리 트리를 그대로 넘긴다 — 다른 요청의 sync() 가 그 사이 델타를 붙일 수 있으므로 proveSession 이
  // 증명의 root 를 거울 쌍과 대조하고, 어긋나면 격리 트리(syncAt)로 다시 증명한다(Task 9 수정).
  let tree = rev.tree, registry = reg.tree;
  if (rev.root !== mv.root || reg.root !== mv.regRoot) {
    // 거울이 뒤처져 있다 — 거울 epoch 시점의 트리로 되감는다. syncAt 은 rcl 의 체크포인트(메모리 트리·캐시 파일)를 건드리지 않는다.
    tree = (await rcl.syncAt({ untilEpoch: mv.epoch, expectRoot: mv.root })).tree;
    registry = (await syncRegistryTree(canonProvider, LOG_ADDRESS, { untilEpoch: mv.epoch, expectRoot: mv.regRoot })).tree;
  }
  return { root: mv.root, regRoot: mv.regRoot, epoch: mv.epoch, head: mv.head, tree, registry, chainId: await chainId(), mirror: { lastPublishedBlock: mv.lastPublishedBlock }, canonical };
}
/** registryCheck 에 넘길 캐노니컬 최신 뷰(V10 — 컨트롤러 결정 2: 내 슬롯 확인은 캐노니컬 최신으로). */
const canonicalView = (synced) => ({ registry: synced.canonical.registry, regRoot: synced.canonical.regRoot, regEpoch: synced.canonical.epoch });
/** lastSync(재검증의 skipSync 시연·/wallet/status)에 남길 거울 뷰. */
const syncSnapshot = (synced) => ({ root: synced.root.toString(), regRoot: synced.regRoot.toString(), epoch: synced.epoch.toString(), head: synced.head.toString(), chainId: synced.chainId.toString(),
  lastPublishedBlock: synced.mirror.lastPublishedBlock.toString(), canonicalEpoch: synced.canonical.epoch.toString(), tree: synced.tree, registry: synced.registry });

// pk_CIA — cert_s 검증용. env 가 있으면 그것, 없으면 IdP 에서 한 번 받아 고정(TOFU, RP 와 같은 규칙).
let pkCiaP = null;
function pkCia() {
  return (pkCiaP ??= (async () => {
    const { MODE3_PK_CIA_X: x, MODE3_PK_CIA_Y: y } = process.env;
    if (x && y) return { x: BigInt(x), y: BigInt(y) };
    const r = await fetch(`${CIA_URL}/cia/public_keys`);
    if (!r.ok) throw new Error(`IdP 에서 pk_CIA 를 받지 못했다 (${r.status})`);
    const k = await r.json();
    return { x: BigInt(k.pk_CIA.x), y: BigInt(k.pk_CIA.y) };
  })().catch((e) => { pkCiaP = null; throw e; }));
}

// OIDC 래퍼(2026-10-26 Snap OIDC 래퍼 §3): IdP 가 공개하는 oidc 설정(enabled·provider·clientId·issuer). 지갑 페이지가 Google 버튼을 그리고(clientId),
// 에이전트가 토큰의 sub 로 uid 를 미리 계산하는 데(provider) 쓴다. 받으면 고정, 실패는 캐시하지 않는다(pkCia() 와 같은 메모이즈).
const OIDC_OFF = { enabled: false, provider: null, clientId: null, issuer: null };
let oidcCfgP = null;
function oidcConfig() {
  return (oidcCfgP ??= (async () => {
    const r = await fetch(`${CIA_URL}/cia/public_keys`, { signal: AbortSignal.timeout(2000) });
    if (!r.ok) throw new Error(`IdP 에서 oidc 설정을 받지 못했다 (${r.status})`);
    const o = (await r.json()).oidc;
    return o?.enabled ? { enabled: true, provider: o.provider, clientId: o.clientId, issuer: o.issuer } : OIDC_OFF;
  })().catch((e) => { oidcCfgP = null; throw e; }));
}
/** 토큰의 sub 로 uid 를 계산한다 — 서명은 검증하지 않는다(판정은 IdP 몫, 스펙 §5). 못 읽으면 null. */
function oidcUidOf(provider, idToken) {
  try { const { sub } = decodeJwt(idToken); return typeof sub === 'string' && sub ? uidOf(provider, sub) : null; }
  catch { return null; }
}

// 속성 스키마(스펙 2 §5.3): IdP 가 공개하는 것을 받아 둔다. 못 받으면(HTTP 오류·네트워크·2초 타임아웃) 공유 모듈의 기본 스키마로 간다(경고) —
// 술어 타입 검사는 기본 스키마 기준이 되고, IdP 가 다른 스키마를 쓰면 응답의 schemaHash 불일치로 드러나 그때 다시 받는다.
// 받았는데 검증에 실패하면(최종 리뷰 I4) 보관 스키마를 바꾸지 않고 기록만 한다 — 술어 요청은 503 schema_invalid(연결 실패와 구분).
// 최종 리뷰 M4: 진행 중 요청은 하나로 합치고(pkCia() 와 같은 메모이즈), 기본 스키마인 동안의 재시도는 요청 경로가 아니라 백그라운드에서
// 60초 간격으로 한다(받으면 멈춘다) — IdP 가 죽어 있을 때 로그인·tx 마다 IdP 를 부르지 않는다.
const ATTR_SCHEMA_RETRY_MS = 60_000;
const ATTR_SCHEMA_TIMEOUT_MS = 2000;
let attrSchema = null;          // { schema, hash, source: 'cia' | 'default' }
let attrSchemaInvalid = null;   // 마지막으로 받은 스키마의 검증 실패 메시지(받아서 통과하면 null)
let attrSchemaP = null;         // 진행 중인 수신
function fetchAttrSchema() {
  return (attrSchemaP ??= (async () => {
    const c = new AbortController();
    const tm = setTimeout(() => c.abort(), ATTR_SCHEMA_TIMEOUT_MS);
    let b;
    try {
      const r = await fetch(`${CIA_URL}/cia/attr_schema`, { signal: c.signal });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      b = await r.json();
    } catch (e) {
      if (!attrSchema && !attrSchemaInvalid) { attrSchema = { ...loadSchema(DEFAULT_ATTR_SCHEMA), source: 'default' }; console.warn(`[wallet] 속성 스키마를 IdP 에서 받지 못해 기본 스키마를 쓴다: ${e.message}`); }
      return attrSchema;
    } finally { clearTimeout(tm); }
    let loaded;
    try { loaded = loadSchema(b?.schema); }
    catch (e) { attrSchemaInvalid = e.message; console.error(`[wallet] IdP 의 속성 스키마가 검증에 실패했다 — 보관 스키마를 바꾸지 않는다, 술어 요청은 schema_invalid: ${e.message}`); return attrSchema; }
    if (b.hash && b.hash !== loaded.hash) console.warn(`[wallet] IdP 가 알린 스키마 해시(${b.hash})와 계산값(${loaded.hash})이 다르다 — 계산값을 쓴다`);
    attrSchema = { schema: loaded.schema, hash: loaded.hash, source: 'cia' }; attrSchemaInvalid = null;
    return attrSchema;
  })().finally(() => { attrSchemaP = null; }));
}
/** 보관 스키마. 기동 수신이 아직 진행 중이면 그것을 기다린다. hashHint(IdP 응답의 schemaHash — IdP 를 새로 부르지 않고 얻은 값)가
 *  보관 해시와 다를 때만 즉시 다시 받고, 그래도 다르면 경고만(스펙 §7 — 지갑은 IdP 를 바꿀 수 없다). 검증 실패 상태면
 *  Error{ reason:'schema_invalid' } — 술어가 있는 요청만 부르므로 술어 없는 로그인·tx 는 막지 않는다. */
async function schemaFor(hashHint = null) {
  if (attrSchemaP && !attrSchema) await attrSchemaP;
  if (hashHint && hashHint !== attrSchema?.hash) await fetchAttrSchema();
  if (attrSchemaInvalid) throw Object.assign(new Error(`IdP 의 속성 스키마가 검증에 실패했다: ${attrSchemaInvalid}`), { reason: 'schema_invalid' });
  if (hashHint && attrSchema.hash !== hashHint) console.warn(`[wallet] IdP 응답의 schemaHash(${hashHint})가 보관 스키마(${attrSchema.hash})와 다르다`);
  return attrSchema;
}
/** 등록·재동기화 응답의 schemaHash 로 보관 스키마를 맞춰 본다. 검증 실패는 이미 기록됐고 등록·재동기화 자체는 막지 않는다. */
const noteSchemaHint = (hashHint) => schemaFor(hashHint).catch((e) => { if (e.reason !== 'schema_invalid') throw e; });
// 기동 때 한 번. 못 받았거나 검증에 실패했으면 백그라운드로 다시 받아 본다(받으면 멈춘다). 실패는 안에서 경고로 삼킨다 — 기동을 막지 않는다.
fetchAttrSchema().then(() => {
  if (attrSchema?.source === 'cia' && !attrSchemaInvalid) return;
  const retry = setInterval(() => { fetchAttrSchema().then(() => { if (attrSchema?.source === 'cia' && !attrSchemaInvalid) clearInterval(retry); }); }, ATTR_SCHEMA_RETRY_MS);
  retry.unref();
});

const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const isAddr = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
const json = async (r) => ({ status: r.status, body: await r.json().catch(() => null) });
const ciaPost = (p, body) => fetch(`${CIA_URL}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(json);

let chainIdCache = null;
async function chainId() {
  if (chainIdCache === null) chainIdCache = (await provider.getNetwork()).chainId;   // bigint
  return chainIdCache;
}

/** 사용자 자격증명을 바꿔 앉힌다(null 이면 버린다). 옛 자격증명의 세션은 다음 게시에 죽으므로 지금 지우고 증명 캐시도 비운다. */
function replaceUserCred(src, userCred) {
  src.setUserCred(userCred);
  state.sessions = {}; cache.clear();
  persist();
}

/** 등록부 확인(설계 §8.2): 내 슬롯의 리프 == Poseidon(auid, Cf_u). 자격증명이 없으면 null.
 *  view 는 { registry, regRoot, regEpoch } — V10 부터 호출자는 캐노니컬 최신(canonicalView(synced))을 넘긴다. */
async function registryCheck(view, reg, uc) {
  if (!reg || !Number.isInteger(reg.slot)) return null;
  const leaf = view.registry.leafAt(reg.slot);
  const expected = uc ? await registryLeaf(BigInt(reg.auid), BigInt(uc.Cf_u)) : 0n;
  const r = { slot: reg.slot, leaf: leaf.toString(), expected: expected.toString(), match: uc ? leaf === expected : null, regRoot: view.regRoot.toString(), epoch: view.regEpoch.toString(), checkedAt: new Date().toISOString() };
  lastRegistry = r;
  return r;
}
let lastRegistry = null;
/** V10(§5): 거울 뷰 등록부의 내 슬롯이 내 자격증명인가. 캐노니컬에는 게시됐어도 거울이 아직 못 따라왔으면 false —
 *  그 상태로는 거울 뷰 트리에서 등록부 증인이 안 만들어진다(회로 실패 → 분류 안 된 500). 자격증명·슬롯이 없으면 판정 대상이 아니다(true). */
async function mirrorLeafMatches(synced, reg, uc) {
  if (!uc || !reg || !Number.isInteger(reg.slot)) return true;
  return synced.registry.leafAt(reg.slot) === await registryLeaf(BigInt(reg.auid), BigInt(uc.Cf_u));
}

/** 사용자 자격증명 선택(V11 — 옛 ensureUserCred). 들고 있는 C_u 가 등록부에서 내 슬롯에 살아 있으면 재사용(blind_u 그대로), 없거나 은퇴(슬롯 0)면 새 blind_u.
 *  남의 리프면 registry_mismatch — IdP 의 부정(또는 내가 모르는 재발급). 돌려주는 값: { blind_u, fresh } 또는 { status:403, reason, registry? }. */
async function chooseUserCred(synced, src) {
  const reg = src.registration();
  const uc = src.userCred();
  if (!uc) return { blind_u: randomScalar(), fresh: true };
  // 리뷰 S3(2026-10-13): snap 모드에서는 파일의 공개 Cf_u 가 정본이다(Task 9 판정과 같은 원칙). Snap 이 든 C_u 가 그것과 다르면 — 발급 뒤 실패한
  // 로그인의 새 C_u 를 페이지가 Snap 에 반영하지 못한 경우 등 — Snap 쪽이 낡았다. 등록부로 판정하면 내 슬롯에 새 리프가 있어 registry_mismatch 로
  // 막히므로(Snap 을 초기화하기 전까지) 새 C_u 를 받는다.
  if (SECRETS === 'snap' && uc.Cf_u !== state.registration?.userCred?.Cf_u) return { blind_u: randomScalar(), fresh: true };
  const chk = await registryCheck(canonicalView(synced), reg, uc);   // V10: 캐노니컬 최신 — 은퇴·바꿔치기를 거울보다 먼저 안다
  if (!chk) return { status: 403, reason: 'registry_slot_unknown' };
  if (chk.match) return { blind_u: BigInt(uc.blind_u), fresh: false };
  if (chk.leaf !== '0') return { status: 403, reason: 'registry_mismatch', registry: chk };
  return { blind_u: randomScalar(), fresh: true };   // 슬롯 0: 은퇴됐다 — 새로 받는다
}

/** 세션 발급(V11 §5.2): C_u(blind_u)·C_s·π_IdP 를 한 요청으로. 200 이면 세션을 저장하고, 새 C_u 였으면 사용자 자격증명도 바꿔 앉힌다(옛 세션은 함께 버린다).
 *  id_token: Google 계정의 발급 토큰(issue:H(pk_u|arid_s) nonce) — 그대로 /cia/issue 본문에 얹는다.
 *  auth_code(Task 13): IdP 가 CIA_ISSUE_AUTH=code 로 떠 있을 때만 보는 1회용 코드 — 그대로 /cia/issue 본문에 얹는다(로그에 찍지 않는다). */
async function issueSession({ arid, r_s, r_rp, pk_trace, allowAgent, factoryAddress, attrGateAddress, head, src, blind_u, auth_code = null, id_token = null }) {
  const reg = src.registration();
  const session = createSessionKey();
  const chainid = await chainId();
  const ov = takeOverride('issue');   // 시연(설계 §8.3): 이번 발급의 s_u·uid 를 한 번만 덮어쓴다 — 가짜 auid 로 증명돼 IdP 가 bad_idp_proof 를 낸다
  const req = await buildIssueRequest({
    uid: BigInt(ov?.uid ?? reg.uid), s_u: BigInt(ov?.s_u ?? reg.s_u), blind_u, attrs: (reg.attrs ?? []).map(BigInt), arid: BigInt(arid), r_rp, r_s,
    sk_u: reg.sk_u, session, chainid, allowAgent: BigInt(allowAgent), max_height: chooseMaxHeight(head, { ttlBlocks: TTL_BLOCKS, grid: HEIGHT_GRID }),
  });
  if (ov?.uid) req.body.uid = reg.uid;   // 요청 본문의 uid 는 진짜 — C_u·π_IdP 안의 uid 만 바뀐다(스펙 §8.3)
  if (auth_code) req.body.auth_code = auth_code;
  if (id_token) req.body.id_token = id_token;   // OIDC 래퍼(2026-10-26): Google 계정은 발급마다 토큰 — 로그에 찍지 않는다
  const r = await ciaPost('/cia/issue', req.body);
  if (r.status !== 200) return { r, demo: ov ? 'override:issue' : undefined };
  // V10(§4.5): 계정 폐기로 슬롯이 은퇴된 뒤 되살아난 계정의 재발급은 새 슬롯을 받는다 — 응답의 슬롯을 따른다.
  if (Number.isInteger(r.body?.slot) && r.body.slot >= 0 && r.body.slot !== state.registration.slot) state.registration.slot = r.body.slot;
  const uc = src.userCred();
  if (!uc || uc.Cf_u !== req.Cf_u.toString()) replaceUserCred(src, { C_u_pt: { x: req.C_u_pt.x.toString(), y: req.C_u_pt.y.toString() }, Cf_u: req.Cf_u.toString(), blind_u: blind_u.toString(), issuedAt: new Date().toISOString() });
  const PPID = await ppid({ uid: BigInt(reg.uid), s_u: BigInt(reg.s_u), arid: BigInt(arid), chainid });
  state.sessions[r_s.toString()] = {
    arid, PPID: PPID.toString(), pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }, factoryAddress, attrGateAddress, allowAgent,
    r_rp: r_rp.toString(), auid_s: req.auid_s.toString(), arid_s: req.arid_s.toString(),
    credential: r.body, sessionPrivKey: session.wallet.privateKey, pk_i: session.pk_i.toString(), issuedAt: new Date().toISOString(),
  };
  persist();
  return { r, demo: ov ? 'override:issue' : undefined };
}

/** 요청 범위 비밀 공급원. file 은 상태 파일. snap 은 증인이 어디서 오는지가 경로마다 다르다.
 *  - 세션 경로(rsKey 있음 — 재검증·tx/prepare): **세션의 메모리 증인만** 쓴다. 본문 witness 는 보지 않는다 —
 *    /wallet/revalidate 는 RP 오리진에 CORS 로 열려 있어 RP 페이지가 엉뚱한 증인을 실어 보내면 proveSession 이
 *    revoked 로 던져 세션이 지워진다(리뷰 Ruling 4). 없으면 needs_consent(409) — 팝업이 동의를 다시 받아 채운다.
 *  - 그 밖(rsKey 없음 — 로그인): 본문 witness. 호출자가 validateWitness 를 먼저 거친다. 없으면 witness_required(400). */
function secretSourceFor(req, rsKey = null) {
  if (SECRETS === 'file') return createSecretSource({ mode: 'file', state });
  let w = null;
  if (rsKey) {
    // 세션 증인은 { s_u, blind_u, attrs, sk_u } 를 든다 — 공개 부분(uid, userCred 의 Cf_u)은 파일에서 채운다.
    const sw = state.sessions[rsKey]?.witness;
    const pub = state.registration?.userCred;
    // pub 이 없으면(상태 파일 버전을 올려 userCred 를 비운 경우 등) 증인을 재조립할 수 없다. 그대로 두면 userCred:null 로
    // 조립돼 proveSession 이 revoked 로 던지고 **세션이 지워진다** — 복구할 수 없는 손실이다. 대신 needs_consent 로 떨어뜨려
    // 팝업이 Snap 의 C_u 로 /wallet/session/witness 를 다시 채우게 한다(그 라우트가 파일의 공개 부분도 되살린다).
    if (sw && pub) w = { uid: state.registration?.uid, s_u: sw.s_u, sk_u: sw.sk_u, attrs: sw.attrs, userCred: { ...pub, blind_u: sw.blind_u } };
  } else w = req.body?.witness ?? null;
  if (!w) throw Object.assign(new Error(rsKey ? 'needs_consent' : 'witness_required'), { reason: rsKey ? 'needs_consent' : 'witness_required' });
  return createSecretSource({ mode: 'snap', state, witness: w });
}

/** RP 인증(설계 §3·§4)·팩토리 검증 — /wallet/login 과 /wallet/authorize/precheck 가 같이 쓴다. 통과면 null, 아니면 { status, body }.
 *  cert_s 가 pk_CIA 서명이어야 하고(오리진은 호출자가 대조한다), 팩토리는 인증서의 arid·pk_trace, 고정된 pk_CIA·로그 주소와 온체인 값이
 *  같아야 하고(2026-09-18 점검 3), 팩토리·검증자 코드가 지갑의 참조 빌드와 같아야 한다(2026-09-23 참조 코드 대조). */
async function checkService({ arid, origin, cert_s, pk_trace, factoryAddress }) {
  // IdP 가 죽어 pk_CIA 를 못 받은 것이지 체인 문제가 아니다 — reason 목록엔 없지만 원인을 구분해 둔다.
  let pk;
  try { pk = await pkCia(); } catch (e) { return { status: 503, body: { reason: 'cia_unavailable', detail: e.message } }; }
  if (!(await verifyRpCert(pk, { arid: BigInt(arid), origin, pk_trace, cert: cert_s }))) return { status: 403, body: { reason: 'bad_rp_cert' } };
  if (factoryAddress !== null) {
    try {
      const f = factoryAt(factoryAddress, provider);
      const [fa, fl, fx, fy, tx, ty, fra, flt, frw] = await Promise.all([f.arid(), f.log(), f.pkCIAX(), f.pkCIAY(), f.pkTraceX(), f.pkTraceY(), f.maxRootAge(), f.maxLifetime(), f.rootWindow()]);
      // V10(2026-10-02 §5): 계정 컨트랙트는 대상 체인의 거울을 읽는다 — 팩토리의 log() 는 캐노니컬이 아니라 거울이어야 한다.
      if (fa !== BigInt(arid) || fl.toLowerCase() !== MIRROR_ADDRESS.toLowerCase() || fx !== pk.x || fy !== pk.y || tx !== BigInt(pk_trace.x) || ty !== BigInt(pk_trace.y)) {
        return { status: 409, body: { reason: 'bad_factory' } };
      }
      // 상한 두 개도 본다(2026-09-25 리뷰 I-3): 참조 코드 대조는 immutable 을 0 으로 지우고 비교하므로 이 둘을 못 잡는다.
      // 너무 크면 AA 가 게시를 멈춰도 온체인 실행이 계속되고(폐기 신선도 상실), 0 이면 그 계정의 모든 execute 가 revert 해
      // 이미 넣은 자산이 영구 동결된다(주소가 이 인자들로 결정돼 다른 값으로 재배포할 수 없다).
      if (BigInt(fra) < FACTORY_MAX_ROOT_AGE_BAND.min || BigInt(fra) > FACTORY_MAX_ROOT_AGE_BAND.max) return { status: 409, body: { reason: 'bad_factory', detail: 'maxRootAge out of band' } };
      if (BigInt(flt) < FACTORY_MAX_LIFETIME_BAND.min || BigInt(flt) > FACTORY_MAX_LIFETIME_BAND.max) return { status: 409, body: { reason: 'bad_factory', detail: 'maxLifetime out of band' } };
      // 2026-10-25 root 유효 창 §3: 창이 너무 크면 은퇴한 자격증명의 옛 π 가 그만큼 오래 통과한다(§7 한계 2). 0 은 옛 동작(최신만)이라 허용.
      // rootWindow() 가 없는 옛 팩토리는 호출이 revert 해 아래 catch 의 bad_factory 로 떨어진다 — 재배포가 필요하다.
      if (BigInt(frw) < FACTORY_ROOT_WINDOW_BAND.min || BigInt(frw) > FACTORY_ROOT_WINDOW_BAND.max) return { status: 409, body: { reason: 'bad_factory', detail: 'rootWindow out of band' } };
      // 값이 맞아도 코드가 가짜일 수 있다(2026-09-23): 무엇이든 통과시키는 검증자를 가리키는 팩토리면 공개 입력을 고르는 쪽이
      // pk_i 를 제 키로 넣어 계정을 비운다. 팩토리·검증자 코드를 지갑의 참조 빌드(artifacts/)와 대조한다 — lib/mode3_onchain.js.
      const code = await verifyReferenceCode(provider, factoryAddress);
      if (!code.ok) return { status: 409, body: { reason: 'bad_factory', detail: code.reason } };
    } catch (e) { return { status: 409, body: { reason: 'bad_factory', detail: e.shortMessage ?? e.message } }; }
  }
  return null;
}

/** 세션 라우트(/wallet/revalidate·/wallet/request)의 RP 대조(2026-09-25 리뷰 D-4). 남의 RP 세션은 "없는 것"과
 *  같이 다룬다(새 사유를 만들지 않는다). 지금은 loginCors 가 오리진 하나만 허용해 브라우저에서는 실현되지 않지만
 *  CORS 는 브라우저에만 걸리고, RP 를 둘 이상 열면 그 순간 교차 RP 인증이 된다.
 *  **있는 단서는 전부 본다**(최종 리뷰 F-1): 요청 오리진과 세션 오리진이 둘 다 있으면 같아야 하고, 본문 arid 가
 *  있으면 세션 arid 와 같아야 한다. 본문 arid 는 precheck 의 r_s 분기와 달리 cert_s 로 인증된 값이 아니고 공개돼
 *  있으므로(GET /api/mode3/rp_info 가 그대로 싣는다), 그것을 실었다는 이유로 오리진 대조를 끄면 막으려던 교차
 *  RP 사용이 그대로 통과한다. 둘 다 없을 때만(브라우저 밖 호출, 또는 origin 을 적기 전에 만들어진 옛 세션)
 *  지금처럼 r_s 만으로 판정한다. */
function sessionMatchesRequester(req, s, arid) {
  const origin = req.get('Origin');
  if (origin && s.origin && origin !== s.origin) return false;
  if (arid !== undefined && arid !== null) return String(arid) === String(s.arid);
  return true;
}

// ---- 앱 ----
const app = express();
app.use(express.json({ limit: '1mb' }));

// RP 페이지(다른 오리진)가 부르는 것은 /wallet/revalidate·/wallet/request·/wallet/config, 그리고 file 모드의 /wallet/login 뿐이다.
// snap 모드의 /wallet/login 은 같은 오리진(지갑 페이지 팝업)만 부른다 — CORS 를 열지 않는다(스펙 §3.3). 문자열 origin 은
// cors 가 요청 Origin 과 무관하게 헤더를 붙이므로, 일치할 때만 붙이도록 함수형으로 둔다.
const loginCors = cors({ origin: (origin, cb) => cb(null, isRpOrigin(origin)), methods: ['POST'] });
const loginMiddleware = SECRETS === 'file' ? [loginCors] : [];
if (SECRETS === 'file') app.options('/wallet/login', loginCors);
app.options('/wallet/revalidate', loginCors);
app.options('/wallet/request', loginCors);
// /wallet/config 는 GET 전용 — Snap 연동(설계 2026-09-22 metamask-snap) 전 RP 페이지가 비밀 모드·rpcUrl 등을 미리 읽는다.
const configCors = cors({ origin: (origin, cb) => cb(null, isRpOrigin(origin)), methods: ['GET'] });

// 데모 공통 레이어(설계 2026-09-24-mode3-demo-ux §1.2) — 같은 오리진 페이지만 읽는다(CORS 를 열지 않는다).
app.use('/common', express.static(path.join(__dirname, 'mode3', 'common')));

// 같은 파일이 지갑 화면과 /authorize 팝업(?authorize=1)을 겸한다 — 팝업은 쿼리로 모드만 바꾼다(metamask-snap §3.2).
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'wallet.html')));

// 비밀 없음 — RP 페이지가 로그인 전에 지갑의 비밀 모드·체인 정보를 미리 읽는다(설계 2026-09-22 metamask-snap Ruling 1).
// ciaUrl(Task 13, 2026-10-23): 지갑 페이지(Task 14)가 IdP 쪽 페이지(인증 창·코드 등록)로 안내하려면 필요하다 — 당시 Ruling 7
// 의 "IdP 주소는 싣지 않는다"를 번복한다(어차피 /mode3/health 가 RP 오리진에도 ciaUrl 을 낸다 — 공개 정보로 재분류).
app.get('/wallet/config', configCors, async (req, res) => {
  try {
    let oidc = OIDC_OFF;
    try { oidc = await oidcConfig(); } catch { /* IdP 를 못 읽으면 꺼진 것으로 보인다 — 다음 요청이 다시 읽는다 */ }
    res.json({ secrets: SECRETS, snapId: SNAP_ID, walletOrigin: WALLET_ORIGIN, rpcUrl: RPC_URL, chainId: (await chainId()).toString(), ciaUrl: CIA_URL, oidc });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 지갑 페이지(같은 오리진)가 사용자에게 salt(s_u)를 보여 주는 라우트(Task 13/14, 컨트롤러 addendum 2026-10-23): file 모드에서만
// — 에이전트가 s_u 를 직접 들고 있는 유일한 모드다. snap 모드는 Snap 이 들고 있다(showSalt()) — 에이전트는 몰라 409 로
// "Snap 이 보관"을 알린다. CORS 를 열지 않는다(RP 오리진에는 절대 노출하지 않는다) — s_u 는 로그에도 찍지 않는다.
app.get('/wallet/secrets/salt', (req, res) => {
  // M8(2026-10-23): 다른 사이트의 <img>·fetch 가 CORS 없이도 same-site 가 아닌 GET 을 이 라우트로 보낼 수 있다 —
  // Sec-Fetch-Site 가 있으면 same-origin 만 받는다(헤더가 없는 구형 클라이언트는 거부하지 않고 그냥 통과시킨다).
  const fetchSite = req.get('Sec-Fetch-Site');
  if (fetchSite && fetchSite !== 'same-origin') return res.status(403).json({ reason: 'cross_site' });
  if (SECRETS !== 'file') return res.status(409).json({ reason: 'snap_mode' });
  if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
  res.json({ s_u: state.registration.s_u });
});

// 상태 엔드포인트(설계 2026-09-25 §1) — 민감정보 없음, RP·IdP 오리진에만 CORS(cors 미들웨어가 아니라 같은 헤더 헬퍼).
let ciaSeenAt = 0;    // 마지막으로 IdP 가 200 을 준 시각(ms) — health 의 ciaReachable
let pinging = null;   // 동시에 여러 health 요청이 와도 ping 은 한 번만(느린 IdP 에 요청을 쌓지 않는다)
const CIA_FRESH_MS = 10_000;   // 이 동안의 결과는 그대로 쓴다 — health 는 캐시로만 답하고 ping 은 뒤에서 돈다
// 체험 모드의 4·5단계 판정용 프로세스 안 카운터(설계 §3.2). 개수만 싣고 다시 띄우면 0 부터다.
let txCount = 0, disclosedTxCount = 0;
const countedTxHashes = new Set();   // /wallet/tx/record 는 페이지가 여러 번 부를 수 있다 — 같은 해시는 한 번만 센다
function countTx(d) {
  txCount++;
  const mask = d && d.mask !== undefined && d.mask !== null ? BigInt(d.mask) : 0n;
  const sel = d ? BigInt(d.sel ?? d.setSel ?? 0) : 0n;
  if (mask !== 0n || sel !== 0n) disclosedTxCount++;
}
async function doPingCia() {
  const c = new AbortController();
  const tm = setTimeout(() => c.abort(), 1500);
  try { if ((await fetch(`${CIA_URL}/cia/public_keys`, { signal: c.signal })).ok) ciaSeenAt = Date.now(); }
  catch { /* 못 닿음 */ }
  finally { clearTimeout(tm); }
}
function pingCia() {
  if (!pinging) pinging = doPingCia().finally(() => { pinging = null; });
  return pinging;
}
app.get('/mode3/health', async (req, res) => {
  // 허용 오리진은 매 요청 rpOrigins(폴링으로 바뀐다) 에서 다시 만든다 — 끝의 '/' 같은 것이 CORS 를 조용히 깨뜨리지 않게.
  applyHealthHeaders(req, res, originList(rpOrigins, CIA_URL));
  // ping 은 기다리지 않는다(설계 §1.3) — 이 응답은 캐시(ciaSeenAt)로만 답하고, 결과는 다음 폴링이 본다.
  // 그래서 IdP 가 느리거나 죽어 있어도 health 응답 시간은 체인 예산(1.2초)만큼만이다.
  if (Date.now() - ciaSeenAt > CIA_FRESH_MS) pingCia();
  let chain = null;
  try { const [id, head] = await bounded(Promise.all([chainId(), provider.getBlockNumber()]), 1200); chain = { id: id.toString(), head: head.toString() }; } catch { /* 체인 없음·응답 없음 */ }
  // rpCount(U6, 체험 모드 login2 단계 — 두 번째 RP 로그인): 세션에 남은 서로 다른 arid 수. 세션이 지워지면(만료·폐기)
  // 함께 준다 — "지금 몇 RP 에 로그인 상태인가"다(누적이 아니다).
  const rpCount = new Set(Object.values(state.sessions).map((s) => String(s.arid))).size;
  res.json(buildWalletHealth({ now: new Date().toISOString(), chain, secrets: SECRETS, registered: !!state.registration, hasCred: !!state.registration?.userCred, sessions: Object.keys(state.sessions).length,
    txs: txCount, disclosedTxs: disclosedTxCount, rpCount, ciaReachable: Date.now() - ciaSeenAt <= CIA_FRESH_MS, rpOrigin: RP_ORIGIN, rpOrigins, ciaUrl: CIA_URL }));
});

/** PPID 계정 주소(팩토리 computeAddress) — 상태 조회마다 RPC 를 치지 않게 (factory, PPID) 별로 캐시한다. RPC 실패면 null(표기만 비운다). */
const accountAddrCache = new Map();
async function accountAddressOf(factoryAddress, PPID) {
  const key = `${factoryAddress}:${PPID}`;
  if (accountAddrCache.has(key)) return accountAddrCache.get(key);
  try { const a = await factoryAt(factoryAddress, provider).computeAddress(BigInt(PPID)); accountAddrCache.set(key, a); return a; }
  catch { return null; }
}
/** 계정의 배포 여부·nonce(2026-10-23 리뷰 3-5 — getCode→nonce 패턴 3곳을 하나로). 미배포면 { deployNeeded:true, nonce:0n },
 *  배포돼 있으면 { deployNeeded:false, nonce: Mode3Wallet.nonce() }. 실패하면 그대로 던진다(호출자가 처리). */
async function accountNonceOf(account) {
  const deployNeeded = (await provider.getCode(account)) === '0x';
  const nonce = deployNeeded ? 0n : await walletAt(account, provider).nonce();
  return { deployNeeded, nonce };
}
app.get('/wallet/status', async (req, res) => {
  let head = null;
  try { head = (await provider.getBlockNumber()).toString(); } catch { /* 체인 없음 */ }
  // 새로고침 버튼(?sync=1, V9 §8.2): 관리자가 등록부를 바꿔치기한 뒤처럼, 이 페이지가 강제로 다시 동기화해
  // 등록부 확인 줄(lastRegistry)을 갱신하고 싶을 때 쓴다. 실패해도(체인 없음 등) 응답은 지금까지의 값으로 낸다.
  if (req.query.sync === '1' && rcl && state.registration) {
    try { const synced = await syncAll(); await registryCheck(canonicalView(synced), state.registration, state.registration.userCred); } catch { /* 체인 없음 */ }
  }
  // V10(§5): 대상 체인 거울과 캐노니컬 로그의 지금 값. 읽지 못하면 null(체인 없음·주소 미설정) — 상태 응답 자체는 그대로 낸다.
  let mirrorStatus = { address: MIRROR_ADDRESS, epoch: null, lastPublishedBlock: null };
  if (mirror) { try { const [e, l] = await bounded(Promise.all([mirror.epoch(), mirror.lastPublishedBlock()]), 1200); mirrorStatus = { address: MIRROR_ADDRESS, epoch: e.toString(), lastPublishedBlock: l.toString() }; } catch { /* 못 읽음 */ } }
  let canonicalEpoch = null;
  if (LOG_ADDRESS) { try { canonicalEpoch = (await bounded(new ethers.Contract(LOG_ADDRESS, MODE3_ROOTS_ABI, canonProvider).epoch(), 1200)).toString(); } catch { /* 못 읽음 */ } }
  const sessions = {};
  for (const [r_s, e] of Object.entries(state.sessions)) {
    // 2026-10-14: 세션의 PPID 계정 주소(팩토리 computeAddress(PPID), CREATE2 라 배포 전에도 정해진다)를 화면 표기용으로 싣는다. 결과는 캐시한다.
    const account = e.factoryAddress ? await accountAddressOf(e.factoryAddress, e.PPID) : null;
    // 2026-10-22: 이 계정의 체인 nonce — 거래 π 의 counter 가 된다(브리프 §6.5). 미배포면 '0', 못 읽으면 null(화면 표기용, 실패해도 상태 응답 자체는 낸다).
    let nonce = null;
    if (account) {
      try { nonce = (await accountNonceOf(account)).nonce.toString(); }
      catch { nonce = null; }
    }
    sessions[r_s] = { account, nonce, arid: e.arid, PPID: e.PPID, max_height: e.credential.max_height, chainid: e.credential.chainid, allowAgent: e.allowAgent, factoryAddress: e.factoryAddress, attrGateAddress: e.attrGateAddress ?? null, sessionAddress: new ethers.Wallet(e.sessionPrivKey).address, issuedAt: e.issuedAt, pk_trace: e.pk_trace };
  }
  // 2026-10-22: 체인에 아직 반영되지 않은 setSessionBound 대기 항목. applicableSession 은 같은 account(= 같은 PPID·팩토리) 를 가진
  // 살아 있는 세션의 r_s — 그 세션으로 /wallet/bounds/apply 를 바로 부를 수 있다. 없으면 null(새로 로그인해야 반영할 수 있다).
  const pendingBounds = (state.pendingBounds ?? []).map((p) => ({
    ...p,
    applicableSession: Object.entries(sessions).find(([, e]) => e.account && e.account.toLowerCase() === p.account.toLowerCase())?.[0] ?? null,
  }));
  // userCred.revoked 는 마지막 등록부 확인(lastRegistry)으로 판정한다(여기서 다시 확인하지 않는다, V9 §8.2). 아직 확인이 없으면 null.
  // 여기 쓰는 값(uid·attrs·userCred 의 Cf_u·issuedAt)은 두 모드 모두 파일의 공개 부분이다 — 비밀 공급원이 필요 없다.
  const reg = state.registration;
  const uc = reg?.userCred ?? null;
  const userCred = uc ? { Cf_u: uc.Cf_u, issuedAt: uc.issuedAt, revoked: lastRegistry ? !lastRegistry.match : null } : null;
  const st = rcl ? rcl.stats() : null;
  res.json({
    registered: Boolean(reg), uid: reg?.uid ?? null, provider: reg ? (reg.provider ?? 'demo') : null, auid: reg?.auid ?? null, slot: reg?.slot ?? null, attrs: reg?.attrs ?? null, userCred, sessions, pendingBounds,
    profile: reg?.profile ?? null, attrSchema: attrSchema ? schemaInfo(attrSchema.schema, attrSchema.hash) : null,
    attrsView: reg && attrSchema ? decodeAttrs(attrSchema.schema, reg.attrs, reg.profile ?? null) : null,
    registry: lastRegistry, demoOverride: demoOverride ? { scope: demoOverride.scope, fields: Object.keys(demoOverride).filter((k) => k !== 'scope') } : null,
    head, lastRoot: lastSync?.root ?? null, lastRegRoot: lastSync?.regRoot ?? null, logAddress: LOG_ADDRESS, ciaUrl: CIA_URL,
    mirror: mirrorStatus, canonical: { rpc: REV_RPC, logAddress: LOG_ADDRESS, epoch: canonicalEpoch },
    rcl: st ? { leaves: st.leaves, lastSyncedBlock: st.lastSyncedBlock === null ? null : st.lastSyncedBlock.toString(), lastMode: st.lastMode, cacheFile: st.cacheFile } : null,
  });
});

// 지갑 페이지(같은 오리진)가 이름 ↔ 코드를 바꾸는 데 쓰는 전체 스키마(스펙 2 §5.6). 에이전트가 IdP 에서 받아 보관한 것.
app.get('/wallet/attr_schema', async (req, res) => {
  try { const s = await schemaFor(); res.json({ schema: s.schema, hash: s.hash, source: s.source }); }
  catch (e) { if (e.reason === 'schema_invalid') return res.status(503).json({ reason: 'schema_invalid', detail: e.message }); res.status(500).json({ error: e.message }); }
});

// 시연(설계 §8.3, 2026-10-14 확장): 다음 발급/증명/서명을 메모리에서만 덮어쓴다. 한 번 쓰면 사라진다. 전문가 보기 전용 카드가 부른다.
//   issue·prove: s_u·uid 를 바꿔친다(가짜 auid 로는 발급·증명 자체가 안 된다 — IdP bad_idp_proof·지갑 demo_proof_failed).
//   fake_proof·fake_sig: s_u·uid 는 그대로다. 발급·증명은 정상으로 끝내고, **보내는 복사본**만 바꿔친다(아래 proveSession·buildExecute) —
//   형식은 유효해 보이지만 RP·체인이 거절하는 장면(가짜 증명·가짜 서명)을 보이기 위함이다(사용자 요청 2026-10-14).
let demoOverride = null;   // { scope: 'issue'|'prove'|'fake_proof'|'fake_sig', s_u?: string, uid?: string }
function takeOverride(scope) { if (!demoOverride || demoOverride.scope !== scope) return null; const ov = demoOverride; demoOverride = null; return ov; }
app.post('/wallet/demo/override', (req, res) => {
  const { s_u = null, uid: uidIn = null, scope = null, clear = false } = req.body ?? {};
  if (clear) { demoOverride = null; return res.json({ ok: true, override: null }); }
  if (!['issue', 'prove', 'fake_proof', 'fake_sig'].includes(scope)) return res.status(400).json({ error: "scope 는 'issue'·'prove'·'fake_proof'·'fake_sig' 중 하나" });
  // fake_proof·fake_sig 는 s_u·uid 가 필요 없다 — 발급은 정상으로 끝내고 다음 증명·서명의 보내는 복사본만 바꿔친다.
  if (scope === 'fake_proof' || scope === 'fake_sig') { demoOverride = { scope }; return res.json({ ok: true, override: { scope, fields: [] } }); }
  if ((s_u !== null && (!isDec(s_u) || BigInt(s_u) >= SCALAR_MAX)) || (uidIn !== null && (!isDec(uidIn) || BigInt(uidIn) >= SCALAR_MAX))) return res.status(400).json({ error: 's_u·uid 는 10진, 2^250 미만' });
  if (s_u === null && uidIn === null) return res.status(400).json({ error: 's_u 또는 uid 가 필요하다' });
  demoOverride = { scope, ...(s_u !== null ? { s_u } : {}), ...(uidIn !== null ? { uid: uidIn } : {}) };
  res.json({ ok: true, override: { scope, fields: Object.keys(demoOverride).filter((k) => k !== 'scope') } });
});

// OIDC 래퍼 nonce(2026-10-26 Snap OIDC 래퍼 §2): 지갑 페이지가 Google 버튼에 넣을 nonce 를 계산한다 — 비밀을 내지 않는다(pk_u·arid_s 의 해시).
// register 는 sk_u 를 받지만 pk_u 계산에만 쓰고 저장·로그하지 않는다(바로 다음 /wallet/register 가 같은 sk_u 를 보낸다). CORS 없음(같은 오리진 전용).
app.post('/wallet/oidc/nonce', async (req, res) => {
  try {
    const { purpose, sk_u, arid, r_rp } = req.body ?? {};
    if (purpose === 'register') {
      if (typeof sk_u !== 'string' || !/^[0-9a-fA-F]{64}$/.test(sk_u)) return res.status(400).json({ error: 'sk_u(hex 64자) 필요' });
      return res.json({ nonce: regNonce(await eddsaPubOf(sk_u)) });
    }
    if (purpose === 'issue') {
      if (!isDec(arid) || !isDec(r_rp)) return res.status(400).json({ error: 'arid, r_rp(10진 문자열) 필요' });
      if (!state.registration?.pk_u) return res.status(409).json({ reason: 'not_registered' });
      return res.json({ nonce: issueNonce(state.registration.pk_u, await aridSOf({ arid: BigInt(arid), r_rp: BigInt(r_rp) })) });
    }
    if (purpose === 'revoke') return res.json({ nonce: newRevokeNonce() });
    res.status(400).json({ reason: 'bad_purpose', detail: 'purpose 는 register·issue·revoke' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// V11 §3.1·§3.3 — 등록 키(sk_u/pk_u)·salt(s_u) 는 지갑이 만들고 auid = Poseidon(T_AUID, uid, s_u) 를 IdP 에 낸다. 속성은 **사용자가 넣는다**(D15):
// 본문 profile(스키마 이름→값, 기본 DEFAULT_PROFILE)을 공개 스키마로 인코딩해 attrs 를 만든다 — IdP 는 받지 않는다.
// snap 모드(metamask-snap §4.1): s_u·sk_u 는 Snap 이 만들고 페이지가 한 번 넘긴다(로그인 증인과 같은 모델). 파일에는 stripSecrets 결과만 남는다.
// Task 13(2026-10-23): pwd 대신 code(가입 계정이 /cia/user/register_code 로 받은 1회용 코드, 세션 필요)도 받는다 —
// snap 모드는 Snap 의 register(uid)가 더 이상 비밀번호를 받지 않으므로(Task 15) 지갑 페이지가 pwd 대신 code 를 싣는다.
// 둘 다 왔으면 code 를 우선한다(IdP /cia/register 의 같은 우선순위와 맞춘다) — IdP 본문에는 받은 쪽 하나만 싣는다.
// 2026-10-26: id_token(Google 등록) — uid 는 토큰의 sub 로 계산하고 IdP 에는 uid 없이 { id_token, auid, pk_u, sig_reg } 를 낸다.
app.post('/wallet/register', async (req, res) => {
  try {
    const { uid: uidIn, pwd, code, id_token, profile: profileIn = null, s_u: suIn, sk_u: skIn } = req.body ?? {};
    let uid = uidIn, oidcProvider = null;
    if (id_token !== undefined) {
      if (uidIn !== undefined || pwd !== undefined || code !== undefined) return res.status(400).json({ error: 'id_token 과 uid·pwd·code 는 함께 줄 수 없다' });
      if (typeof id_token !== 'string') return res.status(400).json({ error: 'id_token 은 문자열' });
      if (SECRETS !== 'snap') return res.status(400).json({ reason: 'not_snap_mode', detail: 'id_token 등록은 snap 모드만(스펙 §7)' });
      let oc;
      try { oc = await oidcConfig(); } catch (e) { return res.status(502).json({ reason: 'cia_unavailable', detail: e.message }); }
      if (!oc.enabled) return res.status(503).json({ reason: 'oidc_disabled' });
      uid = oidcUidOf(oc.provider, id_token);
      if (!uid) return res.status(400).json({ reason: 'bad_id_token', detail: '토큰의 sub 를 읽지 못했다' });
      oidcProvider = oc.provider;
    } else {
      if (!isDec(uid)) return res.status(400).json({ error: 'uid(10진 문자열) 필요' });
      if (typeof pwd !== 'string' && typeof code !== 'string') return res.status(400).json({ error: 'pwd 또는 code 필요' });
    }
    if (BigInt(uid) >= SCALAR_MAX) return res.status(400).json({ error: 'uid 는 2^250 미만' });
    if (SECRETS === 'snap' && !(isDec(suIn) && BigInt(suIn) < SCALAR_MAX && typeof skIn === 'string' && /^[0-9a-fA-F]{64}$/.test(skIn))) return res.status(400).json({ error: 'snap 모드는 s_u(10진, 2^250 미만)·sk_u(hex) 필요' });
    if (profileIn !== null && (typeof profileIn !== 'object' || Array.isArray(profileIn))) return res.status(400).json({ reason: 'bad_attr', detail: 'profile_required' });
    if (state.registration) return res.status(409).json({ reason: 'already_registered', uid: state.registration.uid });
    let schema;
    try { schema = (await schemaFor()).schema; } catch (e) { if (e.reason === 'schema_invalid') return res.status(503).json({ reason: 'schema_invalid', detail: e.message }); throw e; }
    // profile 을 안 보냈을 때만 DEFAULT_PROFILE 을 스키마의 슬롯 이름으로 거른다 — IdP 가 country 같은 이름을 빼면
    // encodeProfile 이 그 키를 unknown_field 로 거절하므로(스펙 2), 기본값은 "그 스키마가 아는 이름"만 남긴다.
    // 사용자가 직접 보낸 profile 은 그대로 둔다(모르는 필드는 여전히 400 bad_attr).
    const profile = profileIn ?? Object.fromEntries(Object.entries(DEFAULT_PROFILE).filter(([k]) => schema.slots.some((s) => s.type !== 'unused' && s.name === k)));
    let attrs;
    try { attrs = await encodeProfile(schema, profile, { allowEmptyRequired: false }); }
    catch (e) { if (e.reason === 'bad_attr') return res.status(400).json({ reason: 'bad_attr', slot: e.slot, field: e.field, detail: e.detail, message: e.message }); throw e; }
    const normalized = normalizeProfile(schema, profile);
    const reg = SECRETS === 'snap' ? { s_u: BigInt(suIn), sk_u: skIn, auid: await auidOf({ uid: BigInt(uid), s_u: BigInt(suIn) }), pk_u: await eddsaPubOf(skIn) } : await createRegistration(BigInt(uid));
    const pub = { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() };
    const idBody = oidcProvider ? { id_token } : typeof code === 'string' ? { code, uid } : { pwd, uid };
    const r = await ciaPost('/cia/register', { ...idBody, auid: reg.auid.toString(), pk_u: pub, sig_reg: await signRegistration(reg.sk_u, BigInt(uid), reg.auid) });
    if (r.status !== 201) {
      const status = r.status === 401 || r.status === 409 ? r.status : 502;
      return res.status(status).json({ reason: 'register_failed', cia: r.body });
    }
    if (oidcProvider && r.body.uid !== uid) return res.status(502).json({ reason: 'uid_mismatch', detail: 'IdP 가 정한 uid 가 토큰의 sub 로 계산한 값과 다르다' });
    const provider = r.body.provider ?? oidcProvider ?? 'demo';
    await noteSchemaHint(r.body.schemaHash ?? null);
    const full = { uid, s_u: reg.s_u.toString(), sk_u: reg.sk_u, pk_u: pub, auid: reg.auid.toString(), slot: r.body.slot, profile: normalized, attrs, provider, userCred: null };
    state.registration = SECRETS === 'snap' ? stripSecrets(full) : full;
    persist();
    res.status(201).json({ uid, slot: r.body.slot, auid: reg.auid.toString(), attrs, profile: normalized, provider });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 반쯤 된 Google 등록 복구(2026-10-26): IdP 등록·에이전트 저장은 끝났는데 Snap 이 보류 등록으로 남은 경우(Snap storeRegistration 실패,
// /user 타이머가 /wallet/register 도중 팝업을 닫음) 지갑 페이지가 Snap 의 보류 비밀(s_u·sk_u)을 보내 에이전트 등록과 맞는지 묻는다.
// 판정을 에이전트가 하는 이유: 페이지에는 Poseidon(auid)·EdDSA(pk_u) 계산이 없다. IdP 를 부르지 않는 이유: 등록은 이미 끝났다 —
// 맞으면 Snap 이 저장할 값(register 201 과 같은 필드)만 돌려주고 상태를 바꾸지 않는다. s_u·sk_u 는 비교에만 쓰고 저장·로그하지 않는다. CORS 없음(같은 오리진 전용).
app.post('/wallet/register/resume', async (req, res) => {
  try {
    if (SECRETS !== 'snap') return res.status(400).json({ reason: 'not_snap_mode' });
    const { s_u, sk_u } = req.body ?? {};
    if (!(isDec(s_u) && BigInt(s_u) < SCALAR_MAX && typeof sk_u === 'string' && /^[0-9a-fA-F]{64}$/.test(sk_u))) return res.status(400).json({ error: 's_u(10진, 2^250 미만)·sk_u(hex 64자) 필요' });
    const reg = state.registration;
    if (!reg) return res.status(409).json({ reason: 'not_registered' });
    const pk = await eddsaPubOf(sk_u);
    const auid = await auidOf({ uid: BigInt(reg.uid), s_u: BigInt(s_u) });
    if (pk.x.toString() !== String(reg.pk_u?.x) || pk.y.toString() !== String(reg.pk_u?.y) || auid.toString() !== String(reg.auid)) {
      return res.status(409).json({ reason: 'secrets_mismatch', detail: '이 Snap 의 보류 비밀이 에이전트 등록과 다르다' });
    }
    res.json({ uid: reg.uid, slot: reg.slot, auid: reg.auid, attrs: reg.attrs, profile: reg.profile, provider: reg.provider ?? 'demo' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// V11 §3.3 — 사용자가 속성을 바꾼다. 스키마 검증 → attrs 재인코딩 → 바뀌었으면 옛 C_u·세션·π 캐시를 버린다(다음 로그인이 새 C_u 를 발급받는다 — PPID 는 그대로).
// snap 모드는 응답의 attrsChanged 를 페이지가 Snap 의 syncAttrs 에 전달한다(Snap 이 자기 userCred 를 버린다). 비밀이 필요 없어 증인은 받지 않는다.
app.put('/wallet/profile', async (req, res) => {
  try {
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    const profile = req.body?.profile;
    if (!profile || typeof profile !== 'object' || Array.isArray(profile)) return res.status(400).json({ reason: 'bad_attr', detail: 'profile_required' });
    let schema;
    try { schema = (await schemaFor()).schema; } catch (e) { if (e.reason === 'schema_invalid') return res.status(503).json({ reason: 'schema_invalid', detail: e.message }); throw e; }
    let attrs;
    try { attrs = await encodeProfile(schema, profile, { allowEmptyRequired: false }); }
    catch (e) { if (e.reason === 'bad_attr') return res.status(400).json({ reason: 'bad_attr', slot: e.slot, field: e.field, detail: e.detail, message: e.message }); throw e; }
    const normalized = normalizeProfile(schema, profile);
    const changed = JSON.stringify(attrs) !== JSON.stringify(state.registration.attrs ?? []);
    state.registration.profile = normalized;
    if (changed) { state.registration.attrs = attrs; state.registration.userCred = null; state.sessions = {}; cache.clear(); }
    persist();
    res.json({ attrs, profile: normalized, changed, ...(SECRETS === 'snap' && changed ? { attrsChanged: attrs } : {}) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 팝업이 Snap 동의 창을 열기 전에 인증서·팩토리를 검사한다(metamask-snap §3.3) — /wallet/login 의 같은 검사를 떼어 낸 것.
// 오리진 대조는 여기서 하지 않는다: 팝업이 postMessage 의 event.origin 으로 확인한 값을 /wallet/login 의 verifiedOrigin 으로 낸다.
app.post('/wallet/authorize/precheck', async (req, res) => {
  try {
    const { arid, origin, cert_s, pk_trace, factoryAddress = null, r_s = null } = req.body ?? {};
    if (!isDec(arid) || typeof origin !== 'string' || !cert_s || !pk_trace || !isDec(pk_trace.x) || !isDec(pk_trace.y)) return res.status(400).json({ error: 'arid, origin, cert_s, pk_trace{x,y} 필요' });
    if (factoryAddress !== null && !isAddr(factoryAddress)) return res.status(400).json({ error: 'factoryAddress 는 주소' });
    if (chainConfigMissing()) return res.status(503).json({ reason: 'chain_unavailable', detail: chainConfigMissing() });
    const bad = await checkService({ arid, origin, cert_s, pk_trace, factoryAddress });
    if (bad) return res.status(bad.status).json(bad.body);
    // 재승인(r_s 있음): 동의 창의 "AI 에이전트 허용" 은 RP 가 보낸 값이 아니라 **이 세션의 실제 값**이어야 한다(2026-09-23 점검 B-I1).
    // 인증서 검사를 통과한 뒤에만 답한다 — 남의 오리진이 세션의 allowAgent 를 물어볼 수 없다.
    if (r_s !== null) {
      if (!isDec(r_s)) return res.status(400).json({ error: 'r_s 는 10진 문자열' });
      const s = state.sessions[BigInt(r_s).toString()];
      // 남의 RP 세션은 없는 것과 같이 다룬다 — 유효한 인증서를 가진 RP A 가 RP B 세션의 r_s 로
      // A 의 이름이 적힌 동의 창을 띄우지 못하게 한다(리뷰 Minor 3). 새 사유는 만들지 않는다.
      if (!s || String(s.arid) !== String(arid)) return res.status(404).json({ reason: 'no_session' });
      return res.json({ ok: true, sessionAllowAgent: String(s.allowAgent) });
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// snap 모드(metamask-snap §3.3): 본문 witness 필수(400 witness_required / bad_witness). 오리진은 Origin 헤더 대신 본문 verifiedOrigin
// (팝업이 postMessage 의 event.origin 으로 확인한 값)을 인증서 오리진과 대조한다. 성공하면 세션에 증인을 메모리로 남기고,
// 새 C_u 는 응답의 userCredIssued 로 페이지가 Snap 에 저장한다. attrsChanged 는 보통은 안 실린다 — 증인의 attrs 가 지갑 파일과
// 다를 때만(V11(D15) 자가 치유, 아래) 실려 페이지가 Snap 의 attrs 를 파일 값으로 맞추게 한다.
app.post('/wallet/login', ...loginMiddleware, async (req, res) => {
  let src = null;   // 바깥 catch 도 src.pending 을 싣도록 try 밖에 둔다(리뷰 S3)
  try {
    const { arid, origin, cert_s, pk_trace, r_s, r_rp, allowAgent = '0', factoryAddress = null, attrGateAddress = null, witness = null, verifiedOrigin = null, disclose = null, set = null, auth_code = null, id_token = null } = req.body ?? {};
    if (!isDec(arid) || typeof origin !== 'string' || !cert_s || !pk_trace || !isDec(pk_trace.x) || !isDec(pk_trace.y) || !isDec(r_s) || !isDec(r_rp)) return res.status(400).json({ error: 'arid, origin, cert_s, pk_trace{x,y}, r_s, r_rp 필요' });
    if (allowAgent !== '0' && allowAgent !== '1') return res.status(400).json({ error: 'allowAgent 는 "0" 또는 "1"' });
    if (id_token !== null && typeof id_token !== 'string') return res.status(400).json({ error: 'id_token 은 문자열' });
    if (factoryAddress !== null && !isAddr(factoryAddress)) return res.status(400).json({ error: 'factoryAddress 는 주소' });
    // attrGateAddress 는 RP 가 알려주는 값을 세션에 실어 나를 뿐 지갑이 검증하지 않는다(스펙 §6.1) — 지갑 폼 기본값(to)으로만 쓰인다.
    if (attrGateAddress !== null && !isAddr(attrGateAddress)) return res.status(400).json({ error: 'attrGateAddress 는 주소' });
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    // Google 계정: 이 지갑이 든 계정의 토큰만 IdP 로 보낸다(/wallet/self_revoke 와 같은 규칙, 최종 리뷰 I1). IdP 의 403 uid_mismatch 를
    // account_disabled 로 오진하지 않도록 체인 작업 전에 여기서 끝낸다. 서명 검증은 IdP 몫이다.
    if (id_token !== null) {
      let oc;
      try { oc = await oidcConfig(); } catch (e) { return res.status(502).json({ reason: 'cia_unavailable', detail: e.message }); }
      if (!oc.enabled) return res.status(503).json({ reason: 'oidc_disabled' });
      const tokUid = oidcUidOf(oc.provider, id_token);
      if (!tokUid) return res.status(400).json({ reason: 'bad_id_token' });
      if (tokUid !== state.registration.uid) return res.status(403).json({ reason: 'uid_mismatch' });
    }
    if (chainConfigMissing()) return res.status(503).json({ reason: 'chain_unavailable', detail: chainConfigMissing() });
    const rs = BigInt(r_s), rrp = BigInt(r_rp);
    if (rs >= SCALAR_MAX || rrp >= SCALAR_MAX) return res.status(400).json({ error: 'r_s·r_rp 는 2^250 미만' });
    // r_s 는 세션 식별자다 — 같은 값으로 두 번 로그인할 정당한 경로가 없고, 덮어쓰면 캐시의 옛 π 와 새 세션키가 어긋난다.
    if (state.sessions[rs.toString()]) return res.status(409).json({ reason: 'duplicate_session' });
    // V7: 로그인 성명에도 술어를 실을 수 있다(스펙 §6). 형식·불만족은 체인 작업 전에 걸러낸다.
    let disclosure = null;
    if (disclose || set) {
      try { assertPredicateTypes((await schemaFor()).schema, disclose, set); }
      catch (e) {
        if (e.reason === 'schema_invalid') return res.status(503).json({ reason: 'schema_invalid', detail: e.message });
        if (e.reason === 'predicate_type') return res.status(400).json({ reason: 'predicate_type', detail: e.message });
        throw e;
      }
      try { const attrs = (state.registration.attrs ?? []).map(BigInt); disclosure = { ...normalizeDisclosure(disclose, attrs), ...(await normalizeSet(set, attrs)) }; }
      catch (e) { if (e.reason) return res.status(400).json({ reason: e.reason, detail: e.message }); throw e; }
    }
    if (SECRETS === 'snap') {
      if (!witness) return res.status(400).json({ reason: 'witness_required' });
      try { await validateWitness(witness, state.registration.uid, state.registration.auid); }
      catch (e) { if (e.reason === 'bad_witness') return res.status(400).json({ reason: 'bad_witness', detail: e.message }); throw e; }
    } else if (witness) console.warn('[wallet] file 모드에 witness 가 왔다 — 무시한다');

    // RP 인증(설계 §3·§4): cert_s 가 pk_CIA 서명이고, 요청을 보낸 오리진이 cert 의 오리진과 같아야 한다.
    // 피싱 페이지는 진짜 RP 의 (arid, cert_s) 를 그대로 보여줄 수는 있어도 그 오리진에서 요청을 보낼 수는 없다.
    // file 모드는 RP 페이지가 CORS 로 직접 부르므로 Origin 헤더, snap 모드는 같은 오리진의 팝업이 부르므로 팝업이 postMessage 의
    // event.origin 으로 확인한 verifiedOrigin 을 대조한다(같은 방어 — 피싱 페이지는 인증서의 오리진에서 메시지를 보낼 수 없다).
    // pk_trace 는 인증서가 덮는다 — RP 가 자기만 아는 키를 주면 RP 혼자 태그를 연다(2026-09-16 §2).
    const seenOrigin = SECRETS === 'snap' ? verifiedOrigin : req.get('Origin');
    if (seenOrigin !== origin) return res.status(403).json({ reason: 'bad_rp_cert' });
    const bad = await checkService({ arid, origin, cert_s, pk_trace, factoryAddress });
    if (bad) return res.status(bad.status).json(bad.body);

    src = secretSourceFor(req);
    // V11(D15): 지갑 파일의 attrs 가 정본이다. PUT /wallet/profile 뒤 페이지가 Snap 의 syncAttrs 전달에 실패했으면 증인의 attrs 가 옛 값이다 —
    // 그대로 두면 옛 C_u 를 재사용하면서 술어는 새 attrs 로 판정한다. 파일 값으로 맞추고(pending.attrsChanged → 페이지가 Snap 에 반영) 증인의
    // C_u 는 버려 새 C_u 를 받게 한다(응답의 userCredIssued 도 함께 간다 — applyPendingToSnap 이 syncAttrs → updateUserCred 순으로 저장한다).
    if (SECRETS === 'snap' && JSON.stringify(witness.attrs.map(String)) !== JSON.stringify((state.registration.attrs ?? []).map(String))) {
      src.setAttrs([...state.registration.attrs]);
      if (witness.userCred) witness.userCred = null;
      console.warn('[wallet] snap 증인의 attrs 가 지갑 파일과 다르다 — 파일 값으로 맞추고 새 C_u 를 받는다(페이지가 attrsChanged 를 Snap 에 반영해야 한다)');
    }
    // V9: 옛 상태 파일(슬롯 없음)은 IdP 의 /cia/slot 으로 되찾는다 — 상태 파일 버전을 올릴 때는 아직 네트워크를 쓸 수 없어 미뤄 둔 일이다.
    const reg = src.registration();
    if (reg.slot === null || reg.slot === undefined) {
      const nonce = randomScalar();
      const r0 = await ciaPost('/cia/slot', { uid: reg.uid, nonce: nonce.toString(), sig_u: await signSlotRequest(reg.sk_u, BigInt(reg.uid), nonce) });
      // 슬롯은 음이 아닌 정수여야 한다(리뷰 Minor 1) — IdP 가 망가진 값을 주면 state.registration.slot 에 그대로 박혀
      // registryCheck 가 영구히 null 을 돌려주게 된다. 여기서 막으면 그 상태로 persist() 되는 일이 없다.
      if (r0.status !== 200 || !Number.isInteger(r0.body?.slot) || r0.body.slot < 0) return res.status(502).json({ reason: 'slot_failed', cia: r0.body });
      state.registration.slot = r0.body.slot;
      persist();
    }
    const timings = { syncMs: 0, userCredMs: 0, issueMs: 0, proveMs: 0 };
    let t = Date.now();
    let synced;
    try { synced = await syncAll(); }
    catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    timings.syncMs = Date.now() - t;
    lastSync = syncSnapshot(synced);

    pruneSessions(synced.head);
    // V11: 사용자 자격증명은 발급 요청에 함께 실려 간다 — 들고 있는 C_u 를 재사용할지(등록부에 살아 있음) 새로 만들지(없음·은퇴)를 먼저 정한다.
    const pick = await chooseUserCred(synced, src);
    if (pick.status === 403) return res.status(403).json({ reason: pick.reason, ...(pick.registry ? { registry: pick.registry } : {}), timings });
    t = Date.now();
    const issued = await issueSession({ arid, r_s: rs, r_rp: rrp, pk_trace: { x: BigInt(pk_trace.x), y: BigInt(pk_trace.y) }, allowAgent, factoryAddress: factoryAddress ? ethers.getAddress(factoryAddress) : null, attrGateAddress: attrGateAddress ? ethers.getAddress(attrGateAddress) : null, head: synced.head, src, blind_u: pick.blind_u, auth_code, id_token });
    timings.issueMs = Date.now() - t;
    timings.userCredMs = pick.fresh ? timings.issueMs : 0;   // 새 C_u 를 받은 로그인만 0 이 아니다(옛 의미 유지 — 테스트·화면이 본다)
    let r = issued.r, demo = issued.demo;
    // V10 no_user_cred 재시도의 V11 등가물: IdP 가 "이미 물린 C_u" 라며 거절하면(경합 등) 버리고 새 C_u 로 한 번만 다시 시도한다.
    if (r.status === 409 && r.body?.reason === 'cred_revoked') {
      replaceUserCred(src, null);
      t = Date.now();
      // auth_code 는 1회용이라 첫 시도에서 이미 소비됐을 수 있다(IdP 는 sig_u·π_IdP 검증 뒤에 소비한다 — cred_revoked 는 그 뒤에만
      // 난다) — 재시도가 같은 코드를 다시 쓰면 bad_code 로 막힐 수 있다. 코드 재발급은 이 흐름 밖(인증 창)이라 여기서는
      // 그대로 한 번 더 건네는 것 이상은 하지 않는다(알려진 한계 — 보고서에 남긴다).
      const retried = await issueSession({ arid, r_s: rs, r_rp: rrp, pk_trace: { x: BigInt(pk_trace.x), y: BigInt(pk_trace.y) }, allowAgent, factoryAddress: factoryAddress ? ethers.getAddress(factoryAddress) : null, attrGateAddress: attrGateAddress ? ethers.getAddress(attrGateAddress) : null, head: synced.head, src, blind_u: randomScalar(), auth_code, id_token });
      const retryMs = Date.now() - t;
      timings.issueMs += retryMs;
      timings.userCredMs = retryMs;
      r = retried.r; demo = retried.demo;
    }
    // 리뷰 S3(2026-10-13): 여기부터의 오류 응답에는 src.pending 을 싣는다 — snap 모드에서 발급이 성공한 뒤(게시 대기·증명) 실패해도 새 C_u
    // (userCredIssued)가 페이지를 거쳐 Snap 에 저장돼야 한다. 안 실으면 파일엔 새 Cf_u·Snap 엔 옛 C_u 가 남는다. cred_revoked 재시도로 C_u 를
    // 버린 경우는 userCredIssued:null(= Snap 도 버려라)이 실린다. file 모드는 {}.
    // IdP 의 403 은 사유가 둘 이상이다(account_disabled · uid_mismatch · …) — 사유가 없거나 account_disabled 일 때만 계정 비활성으로 본다(최종 리뷰 I1).
    if (r.status === 403) {
      const why = r.body?.reason;
      if (!why || why === 'account_disabled') return res.status(403).json({ reason: 'account_disabled', timings, ...src.pending });
      return res.status(403).json({ reason: why, cia: r.body, timings, ...src.pending });
    }
    if (r.status === 400 && r.body?.reason === 'bad_idp_proof') return res.status(502).json({ reason: 'user_cred_failed', cia: r.body, demo, timings, ...src.pending });
    // Task 13: CIA_ISSUE_AUTH=code 일 때 IdP 의 401(auth_code_required·bad_code)을 그대로 넘긴다 — /wallet/register 가
    // IdP 의 401·409 를 그대로 넘기는 것과 같은 모양이다. r.body.reason 은 IdP 의 모든 401 에 항상 실린다(cia.js).
    if (r.status === 401) return res.status(401).json({ reason: r.body?.reason ?? 'unauthorized', cia: r.body, demo, timings, ...src.pending });
    if (r.status !== 200) return res.status(502).json({ reason: 'issue_failed', cia: r.body, demo, timings, ...src.pending });
    // 이 세션이 어느 RP 오리진의 것인지 남긴다(2026-09-25 리뷰 D-4) — 세션 라우트가 요청 오리진과 대조한다.
    // origin 은 바로 위에서 인증서(cert_s)와 대조를 마친 값이다.
    state.sessions[rs.toString()].origin = origin;
    persist();
    // 방금 새 사용자 자격증명을 받았으면(fresh) 그 슬롯이 등록부에 게시될 때까지 기다린다 — 안 그러면 바로 이어지는
    // proveSession 이 아직 옛(또는 빈) 슬롯을 보고 registry_mismatch/registry_empty 로 죽는다(2026-10-01 §8.3).
    // V10(2026-10-02 §5): 캐노니컬 게시만으로는 부족하다 — π 는 거울 뷰로 만들고 RP 도 거울을 읽으므로, **거울의 regRoot 가
    // 내 리프를 담을 때까지**(IdP 의 릴레이가 거울을 올릴 때까지) 기다린다. 마감·폴링 간격은 그대로다. fresh 가 아니어도
    // 거울 뷰에 내 리프가 없으면(관리자 바꿔치기를 되돌린 직후 등 — 캐노니컬만 고쳐졌다) 같은 이유로 기다린다.
    if (pick.fresh || !(await mirrorLeafMatches(synced, src.registration(), src.userCred()))) {
      const deadline = Date.now() + 30_000;
      for (;;) {
        // 다른 세 syncAll() 호출부(로그인 첫 동기화·재검증·buildExecute)와 같은 모양으로 감싼다(리뷰 Important) — 안 그러면
        // 일시적 RPC 오류나 sync_unstable 이 바깥 catch 로 새어나가 이미 세션이 저장된 뒤에 분류 안 된 500 이 된다.
        try { synced = await syncAll(); }
        catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message, ...src.pending }); }
        lastSync = syncSnapshot(synced);
        const chk = await registryCheck(canonicalView(synced), src.registration(), src.userCred());
        if (!chk) return res.status(403).json({ reason: 'registry_slot_unknown', timings, ...src.pending });   // 리뷰 Minor 1 — null 을 그대로 읽으면 TypeError
        if (chk.match && synced.registry.leafAt(chk.slot).toString() === chk.expected) break;   // 캐노니컬에 있고 거울 뷰에도 반영됐다
        if (Date.now() > deadline) return res.status(503).json({ reason: 'registry_unpublished', registry: chk, timings, ...src.pending });
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
    let out;
    try { out = await proveSession(rs.toString(), synced, timings, disclosure, src); }
    catch (e) {
      if (e.reason === 'no_session') return res.status(409).json({ reason: 'no_session', timings, ...src.pending });
      if (e.reason === 'demo_proof_failed') return res.status(409).json({ reason: e.reason, detail: e.detail, demo: 'override:prove', timings, ...src.pending });
      if (e.reason === 'registry_slot_unknown') return res.status(403).json({ reason: 'registry_slot_unknown', timings, ...src.pending });
      if (e.reason === 'registry_unpublished') return res.status(503).json({ reason: 'registry_unpublished', timings, ...src.pending });
      if (e.reason === 'sync_unstable') return res.status(503).json({ reason: 'chain_unavailable', detail: e.message, timings, ...src.pending });
      throw e;
    }
    // 시연(가짜 서명, 사용자 요청 2026-10-14): 세션키 대신 매번 새로 뽑는 임의 키로 서명한다 — RP 의 verifyLogin 이
    // ethers.verifyMessage 로 복원한 주소가 pk_i 와 달라 bad_signature 로 거절한다. proveSession 의 sig 는 여기서만 버린다
    // (buildExecute 는 이 sig 를 쓰지 않으므로 /wallet/tx 경로는 아래의 signPayload 호출부에서 따로 takeOverride 한다).
    const fakeSig = takeOverride('fake_sig');
    if (fakeSig) out = { ...out, sig: await signChallenge(ethers.Wallet.createRandom(), rs.toString()), demo: 'override:fake_sig' };
    if (SECRETS === 'snap') setSessionWitness(rs.toString(), src);
    // src.pending: snap 모드에서 이 로그인이 새로 받은 C_u(userCredIssued) — 페이지가 Snap 에 저장한다. attrsChanged 는 증인의 attrs 가
    // 지갑 파일과 달라 자가 치유(위 V11(D15))가 걸렸을 때만 실린다 — 평소 로그인은 attrs 를 바꾸지 않는다. file 모드는 {}.
    res.json({ ...out, issued: true, allowAgent, timings, disclosure: hasPredicate(disclosure) ? discStrings(disclosure) : null, ...src.pending });
  } catch (e) { res.status(500).json({ error: e.message, ...(src?.pending ?? {}) }); }
});

/** snap 모드: 로그인·재승인한 세션의 증인을 메모리에만 둔다(스펙 §3.3, persist 가 뺀다). blind_u 는 지금 C_u 의 것(로그인 중 새로 받았으면 그것). */
function setSessionWitness(rsKey, src) {
  const s = state.sessions[rsKey];
  if (!s) return;
  const reg = src.registration(), uc = src.userCred();
  s.witness = { s_u: reg.s_u, blind_u: uc?.blind_u ?? null, attrs: reg.attrs, sk_u: reg.sk_u };
}

// 재시작 등으로 세션 증인이 없을 때(revalidate·tx/prepare 의 needs_consent) 팝업이 consentLogin 을 다시 받아 채운다(metamask-snap §4.3).
app.post('/wallet/session/witness', async (req, res) => {
  try {
    if (SECRETS !== 'snap') return res.status(409).json({ reason: 'not_snap_mode' });
    const { r_s, witness, allowAgent = null } = req.body ?? {};
    if (!isDec(r_s) || !witness) return res.status(400).json({ error: 'r_s, witness 필요' });
    // allowAgent 는 팝업이 동의 창에 실제로 쓴 값이다 — 필수로 받아야 "문구와 세션이 어긋났는지" 를 판정할 수 있다(리뷰 Ruling 5).
    if (allowAgent !== '0' && allowAgent !== '1') return res.status(400).json({ error: 'allowAgent 필요' });
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    try { await validateWitness(witness, state.registration.uid, state.registration.auid); }
    catch (e) { if (e.reason === 'bad_witness') return res.status(400).json({ reason: 'bad_witness', detail: e.message }); throw e; }
    const rsKey = BigInt(r_s).toString();
    const s = state.sessions[rsKey];
    if (!s) return res.status(404).json({ reason: 'no_session' });
    // 세션의 실제 값과 다르면 사용자가 읽은 문구가 세션 권한과 어긋난 것이므로 증인을 채우지 않는다(2026-09-23 점검 B-I1).
    if (allowAgent !== String(s.allowAgent)) return res.status(409).json({ reason: 'allow_agent_mismatch' });
    // 세션은 특정 C_u 위에 발급됐다 — Snap 이 든 C_u 가 그것이 아니면(다른 기기, 지워진 상태) 이 증인으로는 증명이 안 된다
    if (!witness.userCred || witness.userCred.Cf_u !== s.credential.Cf_u) return res.status(409).json({ reason: 'user_cred_mismatch' });
    // 파일의 공개 userCred 가 비어 있으면(상태 파일 버전 올림 등) secretSourceFor 가 증인을 재조립하지 못해 계속
    // needs_consent 가 난다. 방금 세션의 Cf_u 와 일치를 확인한 C_u 의 **공개 부분만** 되살린다(비밀은 파일에 쓰지 않는다).
    if (!state.registration.userCred) {
      const u = witness.userCred;
      state.registration.userCred = { Cf_u: u.Cf_u, issuedAt: u.issuedAt ?? new Date().toISOString() };
      persist();
    }
    setSessionWitness(rsKey, createSecretSource({ mode: 'snap', state, witness }));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/** 세션의 성명으로 현재 (revRoot, regRoot) 에 대한 π 를 만든다(캐시, disclosure 별). V9(설계 §8.2): 사용자 자격증명의
 *  활성 여부는 등록부로 본다 — 내 슬롯이 내 자격증명이 아니면(은퇴·바꿔치기) throw('revoked') — 그 사용자의 모든 세션이
 *  같이 죽는다. V8(2026-09-24 §4): 세션 리프가 (옛) 폐기 트리에 있으면 throw('revoked_session') — 그 세션 하나만 죽고
 *  자격증명은 그대로다. 세션이 없으면 throw('no_session') — 호출자가 404/409 로 옮긴다(500 이 아니다).
 *  시연 덮어쓰기(scope='prove')가 걸려 있으면 증명이 실패할 때 throw('demo_proof_failed') — 500 이 아니라 호출자가 409 로 보여준다.
 *  disclosure 가 없으면(mask 0) 기본 π. */
async function proveSession(rsKey, synced, timings, disclosure = null, src, counter = LOGIN_COUNTER) {
  const s = state.sessions[rsKey];
  if (!s) throw Object.assign(new Error('no_session'), { reason: 'no_session' });
  const reg = src.registration();
  const uc = src.userCred();
  const sessionWallet = new ethers.Wallet(s.sessionPrivKey);
  // counter(2026-10-22 §6.5): 거래마다 새 π 가 필요하다(counter = 그 거래의 nonce) — 캐시는 로그인·재검증(LOGIN_COUNTER)과
  // 거래(counter=nonce)를 같은 (root, r_s) 아래 섞지 않도록 counter 를 discKey 뒤에 덧붙인다.
  const baseDiscKey = hasPredicate(disclosure) ? disclosureKey(disclosure) : '0';
  const discKey = counter === LOGIN_COUNTER ? baseDiscKey : `${baseDiscKey}#n${counter}`;
  // V10(2026-10-02): 폐기 사전 확인은 캐시 히트여도 한다. 캐시 키는 거울 뷰 (root, regRoot) 인데, 거울이 뒤처진 동안 캐노니컬에서
  // 폐기·은퇴가 일어나면 키가 그대로라 히트가 나고, 예전처럼 미스일 때만 보면 지갑이 이미 아는 폐기를 놓친 채 옛 π 를 계속 낸다.
  // 확인은 해시 두어 번이라 싸다.
  // 세션이 물린 사용자 자격증명 위에 발급된 경우(동시 로그인 경합으로 issueSession 이 그 사이 새 C_u 를 받았다) — 지금 C_u 의
  // blind_u 로는 증명이 안 만들어진다(witness 실패 → 500). 그 세션은 다음 게시에 어차피 죽으므로 revoked 로 정리한다.
  if (s.credential.Cf_u !== uc?.Cf_u) throw Object.assign(new Error('revoked'), { reason: 'revoked' });
  // V9: 폐기 리프 대신 등록부 — 내 슬롯의 리프가 내 자격증명이 아니면(은퇴돼 0 이거나 바꿔치기) 죽는다(설계 §8.2).
  const chk = await registryCheck(canonicalView(synced), reg, uc);   // V10: 캐노니컬 최신으로(결정 2) — π 는 아래에서 거울 뷰 트리로 만든다
  // reg.slot 이 정수가 아니면 registryCheck 가 null 이다 — !chk.match 를 그대로 읽으면 TypeError(리뷰 Minor 1).
  if (!chk) throw Object.assign(new Error('registry_slot_unknown'), { reason: 'registry_slot_unknown' });
  if (!chk.match) throw Object.assign(new Error('revoked'), { reason: 'revoked', registry: chk });
  // V8: 세션 리프(설계 2026-09-24 §4). 사용자 쪽을 먼저 본다 — 둘 다 폐기됐으면 자격증명 쪽이 더 넓은 사유다.
  // V10: 캐노니컬 최신 트리로 본다 — 거울이 아직 그 폐기를 싣지 않았어도 폐기된 세션을 더 쓰지 않는다(registryCheck 와 같은 규칙).
  // 2026-10-22 §6.5: 리프 하나가 아니라 구간([lo, lo+counter])에 폐기 리프가 있는지를 본다 — 상한(bound) 이 counter 이하인
  // 폐기가 하나라도 있으면 이 거래(또는 로그인·재검증, counter=LOGIN_COUNTER)는 더 쓸 수 없다.
  {
    const { lo, hi } = await sessionLeafRange(BigInt(s.credential.Cf_s), counter);
    try { await synced.canonical.tree.getRangeNonMembershipWitness(lo, hi); }
    catch (e) {
      // 2026-10-23 리뷰 3-6: "is a member" 일 때만 revoked_session 으로 바꾼다(:851 의 prove() 안 같은 규칙) — 그 밖의 오류
      // (범위 오류 등 버그)를 삼키면 호출자가 세션을 지워 버려 되돌릴 수 없다.
      if (/is a member/.test(e.message ?? '')) throw Object.assign(new Error('revoked_session'), { reason: 'revoked_session' });
      throw e;
    }
  }
  let cached = cache.get(ProofCache.rootKey(synced.chainId, synced.root, synced.regRoot), rsKey, discKey);
  const cacheHit = Boolean(cached);
  if (!cached) {
    // V10: 캐노니컬에서는 내 슬롯이 맞지만 거울이 아직 못 따라왔다 — 거울 뷰로는 증명이 안 된다. 세션은 그대로 두고 503 으로(릴레이 뒤 다시).
    if (!(await mirrorLeafMatches(synced, reg, uc))) throw Object.assign(new Error('registry_unpublished'), { reason: 'registry_unpublished' });
    const t = Date.now();
    const ov = takeOverride('prove');   // 시연(설계 §8.3): 다음 증명의 s_u·uid 를 한 번만 바꿔치기
    const prove = async (tree, registry) => {
      try {
        return await buildCredentialProof({
          uid: BigInt(ov?.uid ?? reg.uid), arid: BigInt(s.arid), s_u: BigInt(ov?.s_u ?? reg.s_u), auid: BigInt(reg.auid), blind_u: BigInt(uc.blind_u),
          r_rp: BigInt(s.r_rp), r_s: BigInt(rsKey), pk_i: BigInt(s.pk_i), attrs: (reg.attrs ?? []).map(BigInt),
          credential: s.credential, pk_CIA: { x: BigInt(s.credential.pk_CIA.x), y: BigInt(s.credential.pk_CIA.y) },
          pk_trace: { x: BigInt(s.pk_trace.x), y: BigInt(s.pk_trace.y) }, tree, registry, slot: reg.slot, disclosure, counter,
        });
      } catch (e) {
        // 시연 덮어쓰기가 걸려 있었다면 원인은 거의 항상 그것이다(가짜 s_u·uid 로는 witness 가 안 만들어진다) — 500 대신
        // 호출자가 409 로 보여줄 수 있게 구분한다.
        if (ov) throw Object.assign(new Error('demo_proof_failed'), { reason: 'demo_proof_failed', detail: e.message });
        // 위 사전 검사와 증인 생성 사이에 다른 요청의 sync() 가 내 세션 리프 구간([lo,hi])을 붙이면
        // getRangeNonMembershipWitness 가 "… is a member …" 로 던진다(lib/imt_v2.js, 2026-10-22 §6.5 부터 구간
        // 비멤버십). 테스트가 못 박은 계약은 이 부분 문구다. V9: 폐기 트리에는 세션 리프만 남으므로(사용자 쪽은
        // 등록부로 옮겨갔다) 이 문구는 늘 revoked_session 이다.
        if (/is a member/.test(e.message ?? '')) throw Object.assign(new Error('revoked_session'), { reason: 'revoked_session' });
        throw e;
      }
    };
    cached = await prove(synced.tree, synced.registry);
    // V10(2026-10-02 Task 9 수정): π 는 반드시 거울의 (revRoot, regRoot) 를 실어야 한다 — RP·계정 컨트랙트는 거울만 읽는다.
    // 거울과 캐노니컬 root 가 같으면 syncAll 은 rcl 의 **공유** 메모리 트리를 그대로 넘기므로, 동기화와 증인 생성 사이에 다른
    // 요청의 rcl.sync() 가 델타를 붙이면 거울에 아직 없는 캐노니컬 root 로 증명된다(RP stale_root / StaleRevocationRoot).
    // 그때는 거울 epoch 시점의 격리 트리(syncAt·untilEpoch 재생 — 공유 상태를 건드리지 않는다)로 한 번만 다시 증명하고,
    // 그래도 다르면 sync_unstable 로 끝낸다. V9 의 "새 쌍으로 캐시하고 이번 sync 키로도 별칭" 규칙은 두 root 가 다 게시돼
    // 있어야 성립하므로 V10 에서는 버렸다 — 캐시는 π 가 실은 쌍(= 거울 쌍) 하나로만 한다.
    if (cached.revRoot !== synced.root || cached.regRoot !== synced.regRoot) {
      try {
        const [rev, regT] = await Promise.all([
          rcl.syncAt({ untilEpoch: synced.epoch, expectRoot: synced.root }),
          syncRegistryTree(canonProvider, LOG_ADDRESS, { untilEpoch: synced.epoch, expectRoot: synced.regRoot }),
        ]);
        cached = await prove(rev.tree, regT.tree);
      } catch (e) {
        // 재생 root 불일치는 미태그 Error 라 그대로 두면 호출자의 503 매핑을 빠져나가 500 이 된다 — 사유가 없는 오류만 sync_unstable 로 태그한다.
        if (e.reason) throw e;
        throw Object.assign(new Error('sync_unstable'), { reason: 'sync_unstable', detail: e.message });
      }
      if (cached.revRoot !== synced.root || cached.regRoot !== synced.regRoot) throw Object.assign(new Error('sync_unstable'), { reason: 'sync_unstable' });
    }
    timings.proveMs = Date.now() - t;
    cache.set(ProofCache.rootKey(synced.chainId, cached.revRoot, cached.regRoot), rsKey, cached, discKey);
  }
  const root = (cached.revRoot ?? synced.root).toString();
  const regRoot = (cached.regRoot ?? synced.regRoot).toString();
  const sig = await signChallenge(sessionWallet, rsKey);
  // 시연(가짜 증명, 사용자 요청 2026-10-14): pi_a·pi_c 를 바꿔친다 — 둘 다 유효한 G1 점(같은 [x,y,1] 모양)이라 형식은 그대로지만
  // 페어링이 깨져 RP(verifyLogin → bad_proof)·체인(PiCredVerifier.verifyProof → InvalidProof) 모두 거절한다. 여기서 쓰는 proveSession 은
  // /wallet/login·/wallet/revalidate·buildExecute(/wallet/tx, /wallet/tx/prepare) 가 공유하므로 한 곳에서 다음 1회만 바꾸면 된다.
  // cached.proof(캐시가 쥔 원본)는 손대지 않는다 — 복사본(얕은 복제) 쪽의 pi_a·pi_c 만 맞바꾼다. 그대로 cached.proof 를 고치면
  // 캐시가 더럽혀져 이 세션의 다음(정상) 요청까지 가짜 증명을 받는다.
  const fakeProof = takeOverride('fake_proof');
  const proof = fakeProof ? { ...cached.proof, pi_a: cached.proof.pi_c, pi_c: cached.proof.pi_a } : cached.proof;
  return { proof, publicSignals: cached.publicSignals, sig, pk_i: s.pk_i, r_s: rsKey, root, regRoot, cacheHit, allowAgent: s.allowAgent, max_height: s.credential.max_height, ...(fakeProof ? { demo: 'override:fake_proof' } : {}) };
}

app.post('/wallet/revalidate', loginCors, async (req, res) => {
  try {
    const { r_s, skipSync, arid = null } = req.body ?? {};
    if (!isDec(r_s)) return res.status(400).json({ error: 'r_s 필요' });
    const rsKey = BigInt(r_s).toString();
    const s = state.sessions[rsKey];
    if (!s || !sessionMatchesRequester(req, s, arid)) return res.status(404).json({ reason: 'no_session' });
    if (chainConfigMissing()) return res.status(503).json({ reason: 'chain_unavailable', detail: chainConfigMissing() });
    const timings = { syncMs: 0, issueMs: 0, proveMs: 0 };
    // 시연용: 동기화를 건너뛰고 마지막 (root, regRoot) 의 π 를 그대로 재제출한다(RP 의 stale_root/stale_registry_root 거절을 보이기 위해).
    if (skipSync) {
      if (!lastSync) return res.status(409).json({ reason: 'no_cached_proof' });
      const cached = cache.get(ProofCache.rootKey(BigInt(lastSync.chainId), BigInt(lastSync.root), BigInt(lastSync.regRoot)), rsKey);
      if (!cached) return res.status(409).json({ reason: 'no_cached_proof' });
      const sig = await signChallenge(new ethers.Wallet(s.sessionPrivKey), rsKey);
      return res.json({ proof: cached.proof, publicSignals: cached.publicSignals, sig, pk_i: s.pk_i, r_s: rsKey, root: lastSync.root, regRoot: lastSync.regRoot, cacheHit: true, timings });
    }
    let t = Date.now();
    let synced;
    try { synced = await syncAll(); }
    catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    timings.syncMs = Date.now() - t;
    lastSync = syncSnapshot(synced);
    pruneSessions(synced.head);
    if (!state.sessions[rsKey]) return res.status(410).json({ reason: 'session_expired', timings });   // 캐시는 바로 위 pruneSessions 가 이미 지웠다
    try {
      // snap 모드에서 세션 증인이 없으면(재시작) needs_consent — RP 페이지가 팝업을 다시 열어 /wallet/session/witness 로 채운다(§4.3)
      const src = secretSourceFor(req, rsKey);
      let out = await proveSession(rsKey, synced, timings, null, src);
      // 시연(가짜 서명): /wallet/login 과 같다 — 다음 1회만 임의 키로 서명한다.
      const fakeSig = takeOverride('fake_sig');
      if (fakeSig) out = { ...out, sig: await signChallenge(ethers.Wallet.createRandom(), rsKey), demo: 'override:fake_sig' };
      res.json({ ...out, timings });
    } catch (e) {
      if (e.reason === 'needs_consent') return res.status(409).json({ reason: 'needs_consent', timings });
      // 그 세션만 지운다. reg.userCred 는 그대로 둔다 — 다음 로그인의 chooseUserCred 가 등록부로 알아채 새로 받는다.
      if (e.reason === 'revoked') { delete state.sessions[rsKey]; cache.deleteSession(rsKey); persist(); return res.status(403).json({ reason: 'revoked', registry: e.registry, timings }); }
      // V8: 이 세션 하나만 폐기됐다 — 지우는 범위는 같지만(그 세션) 사유가 다르다. 다른 세션·자격증명은 그대로 쓴다.
      if (e.reason === 'revoked_session') { delete state.sessions[rsKey]; cache.deleteSession(rsKey); persist(); return res.status(403).json({ reason: 'revoked_session', timings }); }
      if (e.reason === 'demo_proof_failed') return res.status(409).json({ reason: e.reason, detail: e.detail, demo: 'override:prove', timings });
      if (e.reason === 'registry_slot_unknown') return res.status(403).json({ reason: 'registry_slot_unknown', timings });
      if (e.reason === 'registry_unpublished') return res.status(503).json({ reason: 'registry_unpublished', timings });
      if (e.reason === 'sync_unstable') return res.status(503).json({ reason: 'chain_unavailable', detail: e.message, timings });
      if (e.reason === 'no_session') return res.status(404).json({ reason: 'no_session', timings });
      throw e;
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 자기 폐기 프록시(metamask-snap §4.5, Ruling 7). Snap 이 비밀번호를 묻고 지갑 페이지가 여기로 내면 에이전트가 IdP 로
// 중계한다 — cia.js 에는 CORS 가 전혀 없어 브라우저가 :5100 → :4100 으로 직접 JSON POST 를 낼 수 없기 때문이다
// (IdP 서버는 이 작업에서 바꾸지 않는다). CORS 를 붙이지 않으므로 /wallet/login 과 같이 같은 오리진만 부를 수 있다.
// 비밀번호는 중계할 뿐 로그에도 상태 파일에도 남기지 않는다(이 경로는 state 를 건드리지 않아 persist() 와 무관하다).
//
// CSRF 주의(2026-09-22 최종 리뷰 Minor 5): 이 라우트는 CORS 를 열지 않지만, **폼 전송으로는 부를 수 없다는 보장이
// `express.json()` 하나에 걸려 있다** — 브라우저 폼은 application/json 을 보낼 수 없어 preflight 가 필요하고(CORS 가 없으니 차단),
// text/plain 으로 보내면 express.json() 이 파싱하지 않아 본문이 비어 400 이 난다. 나중에 `express.urlencoded()` 를 추가하면
// 남의 페이지가 숨긴 폼으로 이 라우트(되돌릴 수 없는 자기 폐기)를 부를 수 있게 된다. 그때는 CSRF 토큰이나 Origin 검사를 함께 넣는다.
app.post('/wallet/self_revoke', async (req, res) => {
  try {
    const { uid, pwd, id_token } = req.body ?? {};
    // Google 계정(2026-10-26 Snap OIDC 래퍼 §2.3): 비밀번호 대신 revoke: nonce 의 id_token. 이 지갑이 든 계정의 토큰만 중계한다
    // (토큰의 sub 로 계산한 uid 를 등록 uid 와 대조 — 서명 검증은 IdP 몫).
    if (id_token !== undefined) {
      if (typeof id_token !== 'string' || uid !== undefined || pwd !== undefined) return res.status(400).json({ error: 'id_token(문자열)만 — uid·pwd 와 함께 줄 수 없다' });
      if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
      let oc;
      try { oc = await oidcConfig(); } catch (e) { return res.status(502).json({ reason: 'cia_unavailable', detail: e.message }); }
      if (!oc.enabled) return res.status(503).json({ reason: 'oidc_disabled' });
      const tokUid = oidcUidOf(oc.provider, id_token);
      if (!tokUid) return res.status(400).json({ reason: 'bad_id_token' });
      if (tokUid !== state.registration.uid) return res.status(403).json({ reason: 'uid_mismatch' });
      const r = await ciaPost('/cia/account/self_revoke', { id_token });
      return res.status(r.status).json(r.body ?? {});
    }
    if (!isDec(uid) || typeof pwd !== 'string') return res.status(400).json({ error: 'uid(10진 문자열), pwd 필요' });
    // 이 지갑이 들고 있는 계정만 중계한다 — 다른 경로가 validateWitness 로 등록 uid 를 대조하는 것과 같은 규칙이다.
    // 없으면 임의 uid·pwd 를 IdP 에 던져 보는 통로가 된다(Ruling 9 라운드, 리뷰 Minor 3).
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    if (uid !== state.registration.uid) return res.status(403).json({ reason: 'uid_mismatch' });
    const r = await ciaPost('/cia/account/self_revoke', { uid, pwd });
    res.status(r.status).json(r.body ?? {});
  } catch (e) { res.status(502).json({ reason: 'cia_unavailable', detail: e.message }); }
});

// V8 세션 폐기(설계 2026-09-24 §4, 2026-10-22 §3 bound 추가): 이 지갑의 세션 하나를 AA 에 폐기 요청한다. 서명은 sk_u — file 모드는 상태 파일,
// snap 모드는 세션의 메모리 증인(로그인·재승인 때 채워진다). 증인이 없으면 409 needs_consent 로 떨어뜨려 페이지가
// 팝업으로 동의를 다시 받게 한다. self_revoke 와 같이 CORS 를 열지 않는다(지갑 페이지, 같은 오리진 전용).
// bound(본문, 선택) — 생략하면 계정의 현재 체인 nonce(팩토리 없으면 0). AA 가 받아들이면 account 가 있는 한 pendingBounds 에
// "체인에 아직 반영되지 않은 setSessionBound" 항목을 남긴다 — /wallet/bounds/apply 가 나중에 그 반영을 보낸다.
app.post('/wallet/session/revoke', async (req, res) => {
  try {
    const { r_s, bound: boundIn } = req.body ?? {};
    if (!isDec(r_s)) return res.status(400).json({ error: 'r_s 필요' });
    const rsKey = BigInt(r_s).toString();
    const s = state.sessions[rsKey];
    if (!s) return res.status(404).json({ reason: 'no_session' });
    // self_revoke 와 같은 규칙 — 등록이 없으면 여기서 끝낸다. 없으면 file 모드가 snap 전용 사유인 needs_consent 를 내게 된다.
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    const sk_u = SECRETS === 'snap' ? s.witness?.sk_u : state.registration.sk_u;
    if (!sk_u) return res.status(409).json({ reason: 'needs_consent' });
    // bound 형식·범위 검사(2026-10-23 리뷰 3-2): 체인을 읽기 **전**에 먼저 끝낸다 — bound 를 명시한 요청은 체인을 전혀 읽지 않는다.
    if (boundIn !== undefined && boundIn !== null && !isDec(boundIn)) return res.status(400).json({ error: 'bound 는 10진 문자열' });
    let bound = boundIn !== undefined && boundIn !== null ? BigInt(boundIn) : null;
    if (bound !== null && (bound < 0n || bound >= SESSION_BOUND_MAX)) return res.status(400).json({ error: 'bound 는 [0, 2^32)' });
    // account: 팩토리가 있으면 캐시된 computeAddress(:accountAddressOf, 실패해도 던지지 않고 null) — bound 기본값·pendingBounds 기록에 쓴다.
    const account = s.factoryAddress ? await accountAddressOf(s.factoryAddress, s.PPID) : null;
    if (bound === null) {
      // 기본값 = 계정의 현재 nonce(미배포·팩토리 없음은 0) — 지금까지의 거래는 살리고 그 뒤를 막는다.
      // 이 체인 읽기만 bounded 로 감싼다(F3: 지역 오류가 아니라 체인 문제이므로 503, 500 internal 로 뭉개지 않는다).
      if (account) {
        try { bound = (await bounded(accountNonceOf(account), 1200)).nonce; }
        catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
      } else bound = 0n;
    }
    const nonce = randomScalar();   // lib/mode3_credential.js — 다른 요청과 같은 난수원. 신선도는 IdP 가 보지 않는다(재생 = 같은 세션 재폐기, 멱등)
    const sig_u = await signRevokeSession(sk_u, BigInt(state.registration.uid), BigInt(s.credential.Cf_s), bound, nonce);
    // 2026-10-25 root 유효 창 §4: 세션키 pk_i 를 세션키 서명으로 묶어 함께 낸다 — IdP 가 다음 게시에 (pk_i, bound) 를 실어 거울이 창 안에서도 즉시 막는다.
    const sig_i = await signRevokeBind(s.sessionPrivKey, { uid: state.registration.uid, Cf_s: s.credential.Cf_s, bound, nonce });
    // 502 cia_unavailable 은 **IdP 호출 실패만** 가리킨다(최종 리뷰 F3). 서명·BigInt 같은 지역 오류는 아래 500 internal 로 간다 —
    // 둘을 뭉치면 운영자가 "AA 가 죽었나" 를 잘못 쫓는다.
    let r;
    try { r = await ciaPost('/cia/revoke', { uid: state.registration.uid, scope: 'session', Cf_s: s.credential.Cf_s, bound: bound.toString(), sig_u, nonce: nonce.toString(), pk_i: s.pk_i, sig_i }); }
    catch (e) { return res.status(502).json({ reason: 'cia_unavailable', detail: e.message }); }
    if (r.status !== 200) return res.status(r.status).json(r.body ?? {});
    // AA 가 받아들인 순간부터 이 지갑은 그 세션을 더 쓰지 않는다 — 게시 전이라도(게시 뒤에는 어차피 π 가 안 만들어진다).
    delete state.sessions[rsKey]; cache.deleteSession(rsKey);
    // IdP 가 실제로 적용한 bound(2026-10-23 리뷰 3-3) — 멱등 분기(이미 더 낮은 bound 가 있으면 그 값을 그대로 돌려준다)를 반영한다.
    const appliedBound = r.body.bound ?? bound.toString();
    // account 가 없으면(팩토리 없는 세션) 체인 상한을 올릴 곳이 없다 — 대기 항목을 넣지 않는다.
    let pendingBoundId = null;
    if (account) {
      pendingBoundId = randomScalar().toString().slice(0, 16);
      state.pendingBounds.push({ id: pendingBoundId, account, chainid: s.credential.chainid, arid: s.arid, pk_i: s.pk_i, bound: appliedBound, revokedAt: new Date().toISOString() });
    }
    persist();
    res.json({ revoked: true, inserted: r.body.inserted, pending: r.body.pending, bound: appliedBound, pendingBoundId, mirrorBound: r.body.mirrorBound === true });
  } catch (e) { res.status(500).json({ reason: 'internal', detail: e.message }); }
});

// 운영·시연용: 폐기 트리 체크포인트를 버린다. 다음 동기화가 창세기부터 재생한다(스펙 §8). 같은 오리진만.
// CORS 를 열지 않지만 self_revoke 와 같은 이유로 본문에 JSON `{confirm:true}` 를 요구한다 — express.json() 은
// text/plain 단순 요청(폼 전송 등)을 파싱하지 않으므로, 이 확인 없이는 다른 오리진 페이지가 폼으로 캐시를 지울 수 없다.
app.post('/wallet/rcl/reset', (req, res) => {
  if (req.body?.confirm !== true) return res.status(400).json({ error: 'confirm:true 필요' });
  if (!rcl) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
  const { deferred } = rcl.reset();
  res.json({ ok: true, deferred });
});

app.post('/wallet/request', loginCors, async (req, res) => {
  try {
    const { r_s, body, arid = null } = req.body ?? {};
    if (!isDec(r_s) || typeof body !== 'string') return res.status(400).json({ error: 'r_s, body(string) 필요' });
    const s = state.sessions[BigInt(r_s).toString()];
    if (!s || !sessionMatchesRequester(req, s, arid)) return res.status(404).json({ reason: 'no_session' });
    const sig = await signSessionRequest(new ethers.Wallet(s.sessionPrivKey), BigInt(r_s), body);
    res.json({ sig, pk_i: s.pk_i });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---- 온체인 실행(설계 2026-09-18 §6.3) ----
// 세션의 성명(같은 π)을 트랜잭션마다 첨부한다 — 컨트랙트가 매번 검증한다(사용자 결정 2026-09-17). 지갑 주소는 RP 팩토리의
// computeAddress(PPID). file 모드의 릴레이어는 hardhat 언락 계정(후원 실행 설계 2026-07-20 과 같은 방식) — 데모용이며 실제 배포의
// 번들러 자리다. snap 모드(metamask-snap §4.4)는 /wallet/tx/prepare 가 calldata 만 만들고 MetaMask(사용자 EOA)가 보낸 뒤
// /wallet/tx/record 가 영수증을 파싱한다.
const RELAYER_INDEX = Number(process.env.MODE3_RELAYER_INDEX ?? 0);
const factoryInterface = new ethers.Interface(FACTORY_ABI);
// d.sel ?? d.setSel: 지갑이 계산한 disclosure 는 {sel,root}, parseExecuteReceipt 가 읽은 온체인 값은 {setSel,setRoot} — 둘 다 받는다.
// sel 이 우선이다(0n 은 nullish 가 아니라 ?? 로는 걸러지지 않으므로, sel 이 있으면 항상 sel 을 쓰고 setSel 은 sel 이 없을 때만 본다).
const discStrings = (d) => (d ? { mask: d.mask.toString(), lo: d.lo.map(String), hi: d.hi.map(String), set: (d.sel ?? d.setSel ?? 0n) !== 0n ? { sel: (d.sel ?? d.setSel).toString(), root: (d.root ?? d.setRoot).toString() } : null } : null);

/** /wallet/tx 와 /wallet/tx/prepare 의 공통부: 검증 → 동기화 → π(캐시) → 지갑 주소·nonce → 세션키 서명 → execute 인자.
 *  실패면 { error: { status, body } } (revoked 는 그 세션을 지운 뒤). */
async function buildExecute(req) {
  const fail = (status, body) => ({ error: { status, body } });
  const { r_s, to, value = '0', data = '0x', disclose, set = null } = req.body ?? {};
  if (!isDec(r_s) || !isAddr(to) || !isDec(value) || typeof data !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(data)) {
    return fail(400, { error: 'r_s, to(주소), value(wei 10진, 선택), data(hex, 선택) 필요' });
  }
  const rsKey = BigInt(r_s).toString();
  const s = state.sessions[rsKey];
  if (!s) return fail(404, { reason: 'no_session' });
  if (!s.factoryAddress) return fail(409, { reason: 'no_factory', detail: '서비스가 로그인 때 factoryAddress 를 주지 않았다' });
  if (chainConfigMissing()) return fail(503, { reason: 'chain_unavailable', detail: chainConfigMissing() });
  // 2026-09-22 §4.2 선택 공개: disclose 를 회로 입력으로. 형식·범위 오류·불만족은 체인·증명 작업 전에 걸러낸다(attrs 는 두 모드 모두 파일의 공개값).
  let disclosure;
  try {
    // 스키마는 술어가 있을 때만 필요하다 — 술어 없는 tx 는 스키마 상태(schema_invalid)와 무관하게 간다(최종 리뷰 I4).
    if (disclose || set) {
      try { assertPredicateTypes((await schemaFor()).schema, disclose, set); }
      catch (e) {
        if (e.reason === 'schema_invalid') return fail(503, { reason: 'schema_invalid', detail: e.message });
        if (e.reason === 'predicate_type') return fail(400, { reason: 'predicate_type', detail: e.message });
        throw e;
      }
    }
    const attrs = (state.registration.attrs ?? []).map(BigInt);
    disclosure = { ...normalizeDisclosure(disclose, attrs), ...(await normalizeSet(set, attrs)) };   // V7: 범위 + 집합
  } catch (e) { if (e.reason) return fail(400, { reason: e.reason, detail: e.message }); throw e; }
  const timings = { syncMs: 0, issueMs: 0, proveMs: 0, txMs: 0 };
  let t = Date.now();
  let synced;
  try { synced = await syncAll(); }
  catch (e) { return fail(503, { reason: 'chain_unavailable', detail: e.message }); }
  timings.syncMs = Date.now() - t;
  lastSync = syncSnapshot(synced);
  pruneSessions(synced.head);
  if (!state.sessions[rsKey]) return fail(409, { reason: 'session_expired', timings });   // 캐시는 바로 위 pruneSessions 가 이미 지웠다
  let src;
  try { src = secretSourceFor(req, rsKey); }
  catch (e) { if (e.reason === 'needs_consent') return fail(409, { reason: 'needs_consent', timings }); throw e; }
  // 2026-10-22: 거래 π 는 counter = nonce 를 공개 입력으로 싣는다(컨트랙트가 pub[33]==payload.nonce 를 검사한다) — proveSession
  // 보다 먼저 nonce 를 읽어야 한다(브리프 Step 3-3).
  const walletAddr = await factoryAt(s.factoryAddress, provider).computeAddress(BigInt(s.PPID));
  // 아직 배포 전이면 nonce 는 0(uint256 기본값) — 배포 트랜잭션을 먼저 보낸 뒤 execute 가 이 nonce 로 들어간다
  const { deployNeeded, nonce } = await accountNonceOf(walletAddr);
  let proved;
  try { proved = await proveSession(rsKey, synced, timings, disclosure, src, nonce); }   // root·disclosure·counter(=nonce) 가 같으면 캐시 π, 아니면 재증명
  catch (e) {
    if (e.reason === 'revoked') { delete state.sessions[rsKey]; cache.deleteSession(rsKey); persist(); return fail(403, { reason: 'revoked', registry: e.registry, timings }); }
    // V8: 이 세션만 폐기됐다(/wallet/tx 와 /wallet/tx/prepare 가 함께 탄다).
    if (e.reason === 'revoked_session') { delete state.sessions[rsKey]; cache.deleteSession(rsKey); persist(); return fail(403, { reason: 'revoked_session', timings }); }
    if (e.reason === 'demo_proof_failed') return fail(409, { reason: e.reason, detail: e.detail, demo: 'override:prove', timings });
    if (e.reason === 'registry_slot_unknown') return fail(403, { reason: 'registry_slot_unknown', timings });
    if (e.reason === 'registry_unpublished') return fail(503, { reason: 'registry_unpublished', timings });
    if (e.reason === 'sync_unstable') return fail(503, { reason: 'chain_unavailable', detail: e.message, timings });
    if (e.reason === 'no_session') return fail(404, { reason: 'no_session', timings });
    throw e;
  }
  // 받는 주소(2026-10-16): 대소문자 체크섬이 안 맞는 입력도 받는다(소문자로 내려 정규형) — 사용자 페이지 코어와 같은 규칙.
  const payload = { to: (() => { try { return ethers.getAddress(to); } catch { return ethers.getAddress(String(to).toLowerCase()); } })(), value: BigInt(value), data, nonce };
  // 시연(가짜 서명, 사용자 요청 2026-10-14): 세션키 대신 매번 새로 뽑는 임의 키로 서명한다 — 컨트랙트의 _recover 가 복원한 주소가
  // pub[2](pk_i)와 달라 BadSignature 로 거절한다. proveSession 의 signChallenge 가 아니라 여기서 따로 take 하는 이유는
  // proveSession 이 /wallet/login·revalidate 와 공유되는데 그쪽 sig(세션 챌린지 서명)는 이 경로에서 쓰지 않기 때문이다 —
  // 거기서 소비되면 실제로 보내는 이 서명은 멀쩡한 채로 나간다.
  const fakeSig = takeOverride('fake_sig');
  const signer = fakeSig ? ethers.Wallet.createRandom() : new ethers.Wallet(s.sessionPrivKey);
  // 다이제스트의 성명 쪽 다섯 필드(max_height·allowAgent·태그)는 이번에 붙일 π 의 공개 입력에서 그대로 가져온다
  // (2026-09-25 리뷰 A-2). 세션 기록의 값으로 조립하면 캐시된 π 와 어긋난 σ 가 나올 수 있다.
  const sig = signPayload(signer, { chainId: await chainId(), wallet: walletAddr, ...payload, discMask: disclosure.mask, discLo: disclosure.lo, discHi: disclosure.hi, setSel: disclosure.sel, setRoot: disclosure.root, ...statementDigestFields(proved.publicSignals) });
  const { a, b, c, pub } = await proofToCalldata(proved.proof, proved.publicSignals);
  // demo: fake_proof 는 proveSession 이 이미 proved.demo 로 알려줬고, fake_sig 는 여기서 막 소비했다 — 둘은 같은 요청에서 동시에
  // 일어날 수 없다(takeOverride 가 scope 하나만 들고 있다).
  const demo = proved.demo ?? (fakeSig ? 'override:fake_sig' : undefined);
  return { s, rsKey, disclosure, timings, proved, walletAddr, deployNeeded, nonce, payload, args: [payload, sig, a, b, c, pub], demo };
}

/** execute 영수증 → 응답 공통부. disclosure = 요청값(지갑이 증명에 넣은 것), onchainDisclosure = Disclosure 이벤트에서 읽은 값(mask=0 이면 이벤트가 없어 null). */
function receiptResult(receipt, walletAddr, disclosure) {
  const parsed = parseExecuteReceipt(receipt, walletAddr);
  return {
    txHash: receipt.hash, wallet: walletAddr, status: receipt.status, ok: parsed.executed?.success ?? null, gasUsed: receipt.gasUsed.toString(),
    nonce: parsed.executed ? parsed.executed.nonceUsed.toString() : null,
    executed: parsed.executed ? { nonceUsed: parsed.executed.nonceUsed.toString(), to: parsed.executed.to, value: parsed.executed.value.toString(), success: parsed.executed.success } : null,
    disclosure: hasPredicate(disclosure) ? discStrings(disclosure) : null,
    onchainDisclosure: discStrings(parsed.disclosure),
  };
}

/** execute 전송 공통부(2026-10-23 리뷰 3-5) — /wallet/tx 와 /wallet/bounds/apply(file 모드)가 함께 쓴다. 배포가 필요하면
 *  먼저 배포하고 execute 를 보내 영수증을 기다린다. revert 하면 Error{ reason:'execute_reverted', detail } 를 던진다
 *  (호출자가 409 로 보여준다 — NonceMismatch·StaleRevocationRoot·RootTooOld·Expired·BoundNotLowered·OnlySelf 등). */
async function sendExecute({ s, walletAddr, deployNeeded, args }) {
  const relayer = await provider.getSigner(RELAYER_INDEX);
  let deployed = false;
  if (deployNeeded) { await (await factoryAt(s.factoryAddress, relayer).deploy(BigInt(s.PPID))).wait(); deployed = true; }
  const walletC = walletAt(walletAddr, relayer);
  let receipt;
  try { receipt = await (await walletC.execute(...args)).wait(); }
  catch (e) {
    // ethers v6 는 send()(execute 처럼 상태를 바꾸는 함수는 내부적으로 estimateGas 를 먼저 부른다)의 revert 를 컨트랙트
    // ABI 로 자동 디코드하지 않는다 — staticCall 경로에서만 contract.interface.makeError 를 거친다. 그래서 e.revert 는
    // 항상 null 이고 e.data 에 원본 바이트만 남는다 — 직접 파싱한다.
    let name = e?.revert?.name ?? e?.reason ?? e?.shortMessage ?? e.message;
    if (e?.data) { try { name = walletC.interface.parseError(e.data)?.name ?? name; } catch { /* 알려진 커스텀 에러가 아니면 원래 메시지를 쓴다 */ } }
    throw Object.assign(new Error('execute_reverted'), { reason: 'execute_reverted', detail: String(name) });
  }
  return { receipt, deployed };
}

/** snap 모드 "증명·서명·calldata 까지만" 응답 공통부(2026-10-23 리뷰 3-5) — /wallet/tx/prepare 와 /wallet/bounds/apply(snap 모드)가 함께 쓴다. */
function prepareResponse({ s, walletAddr, deployNeeded, nonce, args, disclosure, proved, timings, demo }, extra = {}) {
  return {
    walletAddr, factoryAddress: s.factoryAddress, deployNeeded,
    deployCalldata: deployNeeded ? factoryInterface.encodeFunctionData('deploy', [BigInt(s.PPID)]) : null,
    calldata: walletInterface.encodeFunctionData('execute', args),
    nonce: nonce.toString(), disclosure: hasPredicate(disclosure) ? discStrings(disclosure) : null,
    cacheHit: proved.cacheHit, root: proved.root, regRoot: proved.regRoot, timings, ...(demo ? { demo } : {}),
    ...extra,
  };
}

/** 영수증의 SessionBound(pk_i, bound) 로그(2026-10-23 리뷰 3-4: walletAddr 발신만 — 임의 to 로 보낸 execute 의 영수증에서
 *  외부 컨트랙트가 같은 시그니처를 내도 안 지워지게)로 확인되는 pendingBounds 항목을 지운다. /wallet/bounds/apply(file 모드)
 *  와 /wallet/tx/record 가 함께 쓴다(리뷰 3-5). 지워진 (pk_i, bound) 쌍을 돌려준다. */
function clearAppliedBounds(receipt, walletAddr) {
  const found = [];
  for (const l of receipt.logs ?? []) {
    if (l.address?.toLowerCase() !== walletAddr.toLowerCase()) continue;
    let parsed = null;
    try { parsed = walletInterface.parseLog({ topics: [...l.topics], data: l.data }); } catch { continue; }
    if (parsed?.name === 'SessionBound') found.push({ pk_i: parsed.args.pk_i.toString(), bound: parsed.args.bound.toString() });
  }
  if (found.length) {
    const before = state.pendingBounds?.length ?? 0;
    state.pendingBounds = (state.pendingBounds ?? []).filter((x) => !found.some((f) => f.pk_i === x.pk_i && f.bound === x.bound));
    if (state.pendingBounds.length !== before) persist();
  }
  return found;
}

/**
 * "지금 반영" 판정 공통부(F-14, 2026-10-23) — 영수증 하나와 대기 항목(pendingBounds 의 한 원소 p)을 받아
 * applied/alreadyLower/bound_not_applied 를 결정한다. Mode3Wallet.execute 는 내부 호출이 실패해도 트랜잭션 자체를
 * revert 하지 않으므로(Executed.success 만 false, contracts/Mode3Wallet.sol) — 영수증이 성공(status=1)이어도
 * setSessionBound 가 BoundNotLowered·OnlySelf 로 실패했을 수 있다. 로그 기반 정리(clearAppliedBounds)와 별개로
 * Executed.success·온체인 sessionBound(pk_i) 를 둘 다 다시 읽어 확인해야 "반영됨" 이라 말할 수 있다(2026-10-23 리뷰 §1).
 * /wallet/bounds/apply(file 모드, 보내고 바로 판정)와 /wallet/tx/record(snap 모드, pendingBoundId 로 나중에 판정)가
 * 함께 쓴다 — state.pendingBounds 에서 p 를 지우는 것은 호출자가 한다(applied 일 때만, M6: 판정 "뒤"에 지운다).
 */
async function boundApplyVerdict(receipt, walletAddr, p) {
  const success = parseExecuteReceipt(receipt, walletAddr).executed?.success ?? false;
  let onchainBound = null;
  try { const v = await walletAt(walletAddr, provider).sessionBound(BigInt(p.pk_i)); onchainBound = v === 0n ? null : v - 1n; }
  catch { /* 못 읽으면 null — 아래 bound_not_applied 로 떨어진다(에러가 아니라 상태) */ }
  const reqBound = BigInt(p.bound);
  if (success && onchainBound === reqBound) return { applied: true, onchainBound: onchainBound.toString() };
  if (onchainBound !== null && onchainBound <= reqBound) {
    // 누가 먼저 더 낮거나 같게 반영해 둔 상태 — 이 tx 는 BoundNotLowered 로 실패했을 수 있지만 목적은 이미 달성됐다.
    return { applied: true, alreadyLower: true, onchainBound: onchainBound.toString() };
  }
  // 반영되지 않았다 — 에러가 아니라 상태다. 호출자는 pending 항목을 그대로 남겨 다시 시도할 수 있게 한다.
  return { applied: false, reason: 'bound_not_applied', onchainBound: onchainBound === null ? null : onchainBound.toString() };
}

// 자산 이동은 지갑 UI 에서만 시작한다(스펙 §6.3) — RP 오리진에는 열지 않는다. file 모드 전용(릴레이어가 보낸다).
app.post('/wallet/tx', async (req, res) => {
  try {
    if (SECRETS === 'snap') return res.status(409).json({ reason: 'use_tx_prepare' });
    const b = await buildExecute(req);
    if (b.error) return res.status(b.error.status).json(b.error.body);
    const { s, walletAddr, deployNeeded, nonce, args, timings, disclosure, proved, demo } = b;
    const t = Date.now();
    let receipt, deployed;
    try { ({ receipt, deployed } = await sendExecute({ s, walletAddr, deployNeeded, args })); }
    catch (e) {
      if (e.reason !== 'execute_reverted') throw e;
      // 시연(가짜 증명·서명): fake_proof 는 InvalidProof, fake_sig 는 BadSignature 가 여기 detail 에 실린다 — demo 플래그를
      // 함께 보내 페이지가 "[시연 모드]" 로 표시할 수 있게 한다.
      return res.status(409).json({ reason: 'execute_reverted', detail: e.detail, wallet: walletAddr, nonce: nonce.toString(), timings, ...(demo ? { demo } : {}) });
    }
    timings.txMs = Date.now() - t;
    countTx(disclosure);
    res.json({ ...receiptResult(receipt, walletAddr, disclosure), nonce: nonce.toString(), deployed, cacheHit: proved.cacheHit, root: proved.root, regRoot: proved.regRoot, timings, ...(demo ? { demo } : {}) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// snap 모드(metamask-snap §4.4): 증명·서명·calldata 까지만. 페이지가 MetaMask 로 (deployCalldata 가 있으면 팩토리에 먼저) 보낸다.
// 세션에 증인이 없으면(재시작) 409 needs_consent. file 모드에서도 동작한다(상태 파일의 비밀로).
app.post('/wallet/tx/prepare', async (req, res) => {
  try {
    const b = await buildExecute(req);
    if (b.error) return res.status(b.error.status).json(b.error.body);
    res.json(prepareResponse(b));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 체인 반영 대기(설계 2026-10-22 §3·§7): /wallet/session/revoke 가 남긴 pendingBounds 항목 하나를 지금 세션(r_s, 같은 account)으로
// setSessionBound 거래로 보낸다. file 모드는 여기서 바로 전송·영수증까지 받는다(/wallet/tx 와 같은 전송부). snap 모드는
// calldata 만 만들어 돌려준다(/wallet/tx/prepare 와 같은 모양) — 페이지가 MetaMask 로 보낸 뒤 /wallet/tx/record 가 받는다.
app.post('/wallet/bounds/apply', async (req, res) => {
  try {
    const { id, r_s } = req.body ?? {};
    if (typeof id !== 'string' || !id || !isDec(r_s)) return res.status(400).json({ error: 'id, r_s 필요' });
    const p = (state.pendingBounds ?? []).find((x) => x.id === id);
    if (!p) return res.status(404).json({ reason: 'no_pending_bound' });
    const rsKey = BigInt(r_s).toString();
    const s = state.sessions[rsKey];
    if (!s) return res.status(404).json({ reason: 'no_session' });
    if (!s.factoryAddress) return res.status(409).json({ reason: 'no_factory' });
    // 세션의 account 가 대기 항목의 account 와 같아야 한다 — 다른 계정으로 보내면 setSessionBound 가 남의 pk_i 상한을 건드리게 된다.
    const account = await factoryAt(s.factoryAddress, provider).computeAddress(BigInt(s.PPID));
    if (account.toLowerCase() !== p.account.toLowerCase()) return res.status(409).json({ reason: 'bound_wrong_account' });
    const data = walletInterface.encodeFunctionData('setSessionBound', [BigInt(p.pk_i), Number(p.bound)]);
    const b = await buildExecute({ body: { r_s, to: p.account, value: '0', data } });
    if (b.error) return res.status(b.error.status).json(b.error.body);
    const { walletAddr, deployNeeded, nonce, args, timings, disclosure, proved, demo } = b;
    if (SECRETS === 'snap') return res.json(prepareResponse(b, { pendingBoundId: p.id }));
    const t = Date.now();
    let receipt, deployed;
    try { ({ receipt, deployed } = await sendExecute({ s, walletAddr, deployNeeded, args })); }
    catch (e) {
      if (e.reason !== 'execute_reverted') throw e;
      // /wallet/tx 와 같은 revert 이름 — BoundNotLowered(이미 더 낮은 상한이 걸려 있다)·OnlySelf 등을 그대로 돌려준다.
      return res.status(409).json({ reason: 'execute_reverted', detail: e.detail, wallet: walletAddr, nonce: nonce.toString(), timings, ...(demo ? { demo } : {}) });
    }
    timings.txMs = Date.now() - t;
    // F-14(2026-10-23): 판정은 공통 헬퍼(boundApplyVerdict, /wallet/tx/record 의 pendingBoundId 경로와 같다)로 뽑았다.
    // M6: 로그 기반 정리(clearAppliedBounds, 3-4 주소 필터 포함)는 그 판정 "뒤"에 돌린다 — 판정이 끝나기 전에는
    // pending 상태를 건드리지 않는다는 불변식을 지킨다(clearAppliedBounds 는 이 receipt 의 SessionBound 이벤트 전체를
    // 넓게 보므로, p 와 무관한 다른 pending 항목도 지울 수 있다 — 그 정리 자체는 이 판정과 순서가 바뀌어도 결과가
    // 같지만, "판정 전에는 지우지 않는다"는 원칙을 고정해 둔다).
    const verdict = await boundApplyVerdict(receipt, walletAddr, p);
    clearAppliedBounds(receipt, walletAddr);
    if (verdict.applied) {
      if ((state.pendingBounds ?? []).some((x) => x.id === p.id)) { state.pendingBounds = state.pendingBounds.filter((x) => x.id !== p.id); persist(); }
      return res.json({ ...receiptResult(receipt, walletAddr, disclosure), nonce: nonce.toString(), deployed, cacheHit: proved.cacheHit, root: proved.root, regRoot: proved.regRoot, timings, applied: true, ...(verdict.alreadyLower ? { alreadyLower: true } : {}), bound: p.bound, wallet: walletAddr, ...(demo ? { demo } : {}) });
    }
    // 반영되지 않았다 — 에러가 아니라 상태로 200 을 낸다(브리프 §1). pending 항목은 그대로 남겨 다시 시도할 수 있게 한다.
    return res.json({ applied: false, reason: verdict.reason, txHash: receipt.hash, onchainBound: verdict.onchainBound, wallet: walletAddr, nonce: nonce.toString(), timings, ...(demo ? { demo } : {}) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// MetaMask 가 보낸 execute 의 영수증을 파싱해 /wallet/tx 와 같은 형식으로 돌려준다. 영수증이 아직 없으면 202 { pending:true } —
// 에이전트는 기다리지 않는다(페이지가 다시 부른다). 요청값 disclosure 는 트랜잭션 calldata 의 pub(PUB_INDEX.DISC_MASK..SET_ROOT)에서 되돌린다(상태 없음).
app.post('/wallet/tx/record', async (req, res) => {
  try {
    const { r_s, txHash, pendingBoundId } = req.body ?? {};
    if (!isDec(r_s) || typeof txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) return res.status(400).json({ error: 'r_s, txHash(32바이트 hex) 필요' });
    const s = state.sessions[BigInt(r_s).toString()];
    if (!s) return res.status(404).json({ reason: 'no_session' });
    if (!s.factoryAddress) return res.status(409).json({ reason: 'no_factory' });
    const walletAddr = await factoryAt(s.factoryAddress, provider).computeAddress(BigInt(s.PPID));
    const [receipt, tx] = await Promise.all([provider.getTransactionReceipt(txHash), provider.getTransaction(txHash)]);
    if (!receipt) return res.status(202).json({ pending: true, txHash, wallet: walletAddr });
    // 이 세션의 지갑으로 간 트랜잭션만 받는다 — 배포 tx 나 남의 트랜잭션을 실행 결과로 오인하지 않는다(리뷰 Minor)
    const txTo = receipt.to ?? tx?.to ?? null;
    if (!txTo || txTo.toLowerCase() !== walletAddr.toLowerCase()) return res.status(409).json({ reason: 'not_our_tx', txHash, wallet: walletAddr });
    let disclosure = null;
    const dec = tx ? decodeExecuteCalldata(tx.data) : null;
    if (dec) { const pub = dec.pub.map(BigInt); disclosure = { mask: pub[PUB_INDEX.DISC_MASK], lo: pub.slice(PUB_INDEX.DISC_LO, PUB_INDEX.DISC_HI), hi: pub.slice(PUB_INDEX.DISC_HI, PUB_INDEX.SET_SEL), sel: pub[PUB_INDEX.SET_SEL], root: pub[PUB_INDEX.SET_ROOT] }; }
    // F-14(2026-10-23): snap 모드의 "지금 반영" — pendingBoundId 가 있으면 /wallet/bounds/apply(file 모드)와 같은
    // 판정 헬퍼(boundApplyVerdict)로 applied/alreadyLower/bound_not_applied 를 매겨 응답에 싣는다. M6: 일반 로그
    // 정리(clearAppliedBounds, 이 영수증의 SessionBound 이벤트 전체를 넓게 본다)는 이 판정 "뒤"에 돌린다.
    let boundResult = {};
    if (typeof pendingBoundId === 'string' && pendingBoundId) {
      const p = (state.pendingBounds ?? []).find((x) => x.id === pendingBoundId);
      if (!p) boundResult = { applied: false, reason: 'no_pending_bound' };
      else {
        const verdict = await boundApplyVerdict(receipt, walletAddr, p);
        // pending 은 applied(alreadyLower 포함)일 때만 지운다 — bound_not_applied 면 다시 시도할 수 있게 남긴다.
        if (verdict.applied && (state.pendingBounds ?? []).some((x) => x.id === p.id)) {
          state.pendingBounds = state.pendingBounds.filter((x) => x.id !== p.id);
          persist();
        }
        boundResult = verdict;
      }
    }
    // 대기 중인 다른 setSessionBound 거래가 같은 영수증에 반영되면 그 항목도 지운다(snap 모드: /wallet/bounds/apply 는
    // calldata 만 돌려주고, 실제 전송·영수증은 MetaMask 를 거쳐 이 라우트로 들어온다). 로그 자체가 나왔다는 것은
    // inner call 이 성공했다는 뜻이다.
    clearAppliedBounds(receipt, walletAddr);
    if (!countedTxHashes.has(txHash)) { countedTxHashes.add(txHash); countTx(disclosure); }
    res.json({ ...receiptResult(receipt, walletAddr, disclosure), ...boundResult });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 라우트 밖으로 샌 오류의 마지막 그물(2026-10-11): JSON 파싱 실패 400 malformed, 그 밖 500 internal — 페이지는 reason 으로 사유를 읽는다.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ reason: 'malformed' });
  console.error(`[wallet] 처리되지 않은 라우트 오류 ${req.method} ${req.path}: ${err?.stack ?? err}`);
  res.status(500).json({ reason: 'internal', detail: err?.message });
});
process.on('unhandledRejection', (e) => console.error(`[wallet] unhandledRejection: ${e?.stack ?? e}`));
app.listen(PORT, '127.0.0.1', () => {
  console.log(`Mode 3 wallet agent at http://127.0.0.1:${PORT} (cia=${CIA_URL}, rp=${rpOrigins.join(',')}, log=${LOG_ADDRESS ?? 'none'}@${REV_RPC}, mirror=${MIRROR_ADDRESS ?? 'none'})`);
});
