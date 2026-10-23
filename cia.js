// Mode 3 IdP (Credential Issuing Authority).
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §3, §6
//
// Mode 2 의 custom_idp.js 와 나란히 두는 별도 서버다(:4100). 그쪽 코드를 import 하지 않는다.
// 하는 일 넷: 등록(§6.1), 발급(§6.2), 폐기(§6.5), root 게시(§6.5). 로그인 검증은 하지 않는다 —
// 그것은 RP 의 일이고(§6.3) IdP 는 조회 경로에 있어서는 안 된다(§9.9).
// V4(2026-09-18): 만료는 블록 높이(max_height), allowAgent, 체인 헤드 조회, 하트비트 게시, 개봉 평문 역조회 — 설계 2026-09-18-mode3-onchain-execution-design.md §4·§6.
// V5(2026-09-21): 자격증명 이중 구조 — 사용자 자격증명(/cia/user_cred, π_u — V11 에서 삭제)과 세션 발급(/cia/issue, ZKP 없음)을 나눈다. 폐기 리프는 Cf_u 에서
//   나오므로 세션 기록(issued)이 없다 — 설계 2026-09-21-mode3-two-tier-credential §3·§4.
// V8(2026-09-24): 세션 단위 폐기 — 발급이 accounts[uid].sessions 에 기록을 남기고, /cia/revoke scope=session 이 sessionLeaf(Cf_s) 를
//   트리에 넣는다. 만료된 기록은 하트비트에서 지운다(리프는 남는다) — 설계 2026-09-24-mode3-session-revocation §2.2·§6.
// V10(2026-10-02): 게시 서명은 V3 다이제스트(캐노니컬 chainid·로그 주소). 계정·자격증명 폐기는 IdP 서명 접수증을 돌려주고,
//   게시는 로그의 접수증 대기열(pendingSlots)을 먼저 따른다(슬롯 0·영구 은퇴 → 재발급은 새 슬롯) — 설계
//   2026-10-02-mode3-revocation-chain-design §4.
// V11(2026-10-12): auid·π_IdP 도입 — /cia/issue 가 /cia/user_cred 를 흡수해(세션마다 π_IdP 검증) 사용자·세션 자격증명을 한 요청으로
//   낸다. 상태는 v12(cm_u·attrs 삭제, auid 필수) — 설계 2026-10-12-mode3-v11-figure-protocol-design.md §5.2·§7.
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import session from 'express-session';
import path from 'node:path';
import fs from 'node:fs';
import { randomBytes, timingSafeEqual, createHash, scryptSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { readJson, writeJsonAtomic } from './lib/mode3_state.js';
import { credMessageV11, compressPoint, randomScalar } from './lib/mode3_credential.js';
import { DEFAULT_ATTR_SCHEMA, loadSchema, schemaInfo } from './lib/mode3_attr_schema.js';
import { sessionLeaf, createRevocationTree, SESSION_BOUND_MAX } from './lib/mode3_revocation.js';
import { isValidPoint, pointFromStrings, issueRequestMessageV11, slotRequestMessage, revokeSessionMessage, registerMessage } from './lib/mode3_issuance.js';
import { PUB_INDEX } from './lib/mode3_onchain.js';
import { loadIdpVkey, idpPublicSignals, verifyIdp, IDP_VKEY_PATH } from './lib/mode3_idp_proof.js';
import { MODE3_LOG_ABI, MODE3_MIRROR_ABI, rootToBytes32, signPublicationV3, entryHashes, signReceipt } from './lib/mode3_log.js';
import { createRegistryTree, registryLeaf } from './lib/mode3_registry.js';
import { signRpCert } from './lib/mode3_rp_cert.js';
import { isTracePoint, createShare, combinePublicKey, partialDecrypt, combineDecrypt, resolveTagPlaintext, proveShare } from './lib/mode3_trace.js';
import { openRequestMessage, openResultMessage, recoverSigner, isFreshTs } from './lib/mode3_opening.js';
import { CIA_STATE_VERSION, defaultCiaState, migrateCiaState } from './lib/mode3_cia_state.js';
import { buildAaHealth, applyHealthHeaders, bounded, originList } from './lib/mode3_health.js';
import { createOidcVerifier, GOOGLE_DEFAULTS } from './lib/mode3_oidc.js';
import { uidOf, regNonce, issueNonce, isRevokeNonce, REG_PREFIX, REVOKE_PREFIX, ISSUE_PREFIX } from './lib/mode3_oidc_nonce.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.CIA_PORT) || 4100;
// 수신 주소(2026-10-20, VM 분리 데모): 기본은 지금처럼 127.0.0.1. 다른 기계에서 붙게 하려면 MODE3_BIND_HOST=0.0.0.0.
const BIND_HOST = process.env.MODE3_BIND_HOST || '127.0.0.1';
const STATE_FILE = process.env.CIA_STATE_FILE || path.join(__dirname, 'cia_state.json');
const KEYS_FILE = process.env.CIA_KEYS_FILE || path.join(__dirname, 'cia_keys.json');
const IDP_VKEY = process.env.MODE3_IDP_VKEY_PATH || IDP_VKEY_PATH;
const VKEY_PATH = process.env.MODE3_VKEY_PATH || path.join(__dirname, 'build', 'mode3', 'pi_cred_vkey.json');
// 속성 매핑 계층(스펙 2, 2026-10-07): 스키마는 공유 모듈의 기본값이고 CIA_ATTR_SCHEMA_FILE(JSON)로 바꿀 수 있다. 검증 실패는 기동 거부.
const ATTR_SCHEMA_FILE = process.env.CIA_ATTR_SCHEMA_FILE || null;
let ATTR_SCHEMA, ATTR_SCHEMA_HASH;
try {
  ({ schema: ATTR_SCHEMA, hash: ATTR_SCHEMA_HASH } = loadSchema(ATTR_SCHEMA_FILE ? JSON.parse(fs.readFileSync(ATTR_SCHEMA_FILE, 'utf8')) : DEFAULT_ATTR_SCHEMA));
} catch (e) {
  console.error(`[cia] 기동 거부: 속성 스키마 오류(${ATTR_SCHEMA_FILE ?? '기본 스키마'}) — ${e.message}`);
  process.exit(1);
}
const ADMIN_SECRET = process.env.CIA_ADMIN_SECRET;
// 데모 설정(2026-10-21, 사용자 요청): CIA_ADMIN_OPEN=1 이면 관리자 경로가 시크릿을 묻지 않는다(관리자 페이지는 입력칸을 숨긴다).
// 이 IdP 에 닿는 누구나 RP 승인·폐기·개봉 승인을 할 수 있으므로 데모 전용이다. 기본은 꺼짐(지금처럼 시크릿 필요).
const ADMIN_OPEN = process.env.CIA_ADMIN_OPEN === '1';
// 사용자 오리진(web 모드 사용자 페이지 또는 에이전트, 스펙 2026-10-15 §5.3). health 의 허용 목록과 아래 userCors 가 같은 값을 쓴다.
const WALLET_AGENT_ORIGIN = process.env.MODE3_WALLET_AGENT_ORIGIN || 'http://127.0.0.1:5100';
// OIDC 래퍼(스펙 2026-10-16): Google ID 토큰을 체인 밖에서 검증해 계정을 만든다. 클라이언트 ID 가 없으면 꺼진다(데모 계정만).
const envStr = (k, d) => (process.env[k] === undefined || process.env[k] === '' ? d : process.env[k]);
const OIDC_PROVIDER = envStr('MODE3_OIDC_PROVIDER', GOOGLE_DEFAULTS.provider), OIDC_ISSUER = envStr('MODE3_OIDC_ISSUER', GOOGLE_DEFAULTS.issuer), OIDC_JWKS_URL = envStr('MODE3_OIDC_JWKS_URL', GOOGLE_DEFAULTS.jwksUrl), OIDC_CLIENT_ID = envStr('MODE3_OIDC_CLIENT_ID', envStr('GOOGLE_CLIENT_ID', null));
const OIDC = { enabled: Boolean(OIDC_CLIENT_ID), provider: OIDC_PROVIDER, issuer: OIDC_ISSUER, jwksUrl: OIDC_JWKS_URL, clientId: OIDC_CLIENT_ID ?? null, verifier: OIDC_CLIENT_ID ? createOidcVerifier({ issuer: OIDC_ISSUER, jwksUrl: OIDC_JWKS_URL, clientId: OIDC_CLIENT_ID }) : null };
const OIDC_STATUS = { oidc_invalid: 401, oidc_nonce_mismatch: 400, oidc_unavailable: 502 };
// 공유 클라이언트 ID 경고(2026-10-16 최종 리뷰 I2): GOOGLE_CLIENT_ID 폴백으로 켜지면 Mode 1 과 aud 가 같다. Mode 1 server.js 의
// /login?custom_nonce= 는 고른 nonce 로 같은 aud 의 토큰을 받게 해 주므로 reg:·revoke: nonce 의 결속(D4)이 무력해진다. 폴백은 두고(스펙 D3·§6) 알리기만 한다.
if (OIDC.enabled) {
  console.log(`[cia] OIDC 래퍼 켜짐: provider=${OIDC.provider}, issuer=${OIDC.issuer}`);
  if (envStr('MODE3_OIDC_CLIENT_ID', null) === null) console.warn('[cia] 경고: OIDC 래퍼가 Mode 1 의 클라이언트 ID(GOOGLE_CLIENT_ID)를 함께 쓴다 — 같은 aud 로 토큰을 받는 흐름(Mode 1 의 /login?custom_nonce=)이 등록·폐기 nonce(reg:·revoke:)를 고른 토큰을 만들 수 있다. MODE3_OIDC_CLIENT_ID 로 Mode 3 전용 클라이언트를 쓰기를 권한다.');
}
/** id_token 을 검증해 { uid, sub, nonce } 를 돌려준다. 실패는 { status, body } 로(라우트가 그대로 낸다). */
async function oidcUid(idToken, noncePrefix) {
  if (!OIDC.enabled) return { error: { status: 503, body: { error: 'oidc_disabled', reason: 'oidc_disabled' } } };
  try { const v = await OIDC.verifier.verify(idToken, { noncePrefix }); return { uid: uidOf(OIDC.provider, v.sub), sub: v.sub, nonce: v.nonce }; }
  catch (e) { const status = OIDC_STATUS[e.reason]; if (!status) throw e; return { error: { status, body: { error: e.reason, reason: e.reason, detail: e.detail } } }; }
}
// 사용자 페이지가 브라우저에서 직접 부르는 라우트에만 연다(계획 2026-10-15 Task 6). 관리자 헤더는 허용 목록에 없다 —
// 교차 오리진에서 관리자 경로를 부를 수 없다(관리자 페이지는 같은 오리진 /admin 이다). 문자열이 아니라 함수형 origin 이어야
// 일치할 때만 헤더가 붙는다(에이전트의 loginCors 와 같은 이유).
const userCors = cors({ origin: (origin, cb) => cb(null, origin === WALLET_AGENT_ORIGIN), methods: ['GET', 'POST'], allowedHeaders: ['Content-Type'] });
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
// dotenv 는 이미 있는 키를 덮지 않으므로 격리 테스트 하네스는 "기본값 사용"을 빈 문자열로 표시한다(isolated_cia.mjs).
// `||` 는 빈 문자열을 falsy 로 봐 기본값으로 떨어지지만 `??` 는 아니라서 `BigInt('') === 0n` 이 그대로 상수가 돼
// 버린다 — 하트비트가 경고 없이 꺼지는 등 조용한 오설정으로 이어진다. 미설정·빈 문자열만 "기본값"으로 다룬다:
// 하트비트를 끄려면 명시적으로 '0' 이어야 한다.
const envBig = (k, d) => { const v = process.env[k]; return v === undefined || v === '' ? BigInt(d) : BigInt(v); };
// 만료 max_height 는 지갑이 정하고 IdP 는 그대로 서명한다(설계 2026-09-18 §3.2 갱신, zkLogin 의 max_epoch 와 같은 구조).
// 상한은 검증자(RP·컨트랙트)가 head + L 로 강제한다. IdP 는 발급 때 헤드를 읽지 않는다 — 체인 가용성만 확인한다.
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
// V10(2026-10-02 설계 §5 결정 3) 거울 릴레이. "chainid=mirrorAddress,…". 각 chainid 의 RPC 는 CIA_CHAIN_RPCS 에서 찾는다 —
// 거울 주소만 있고 그 체인을 읽을 길이 없으면 거울이 늙어 그 체인이 전원 Stale 로 멈추므로 기동부터 막는다.
// 주기 H_X(CIA_MIRROR_HEARTBEAT_BLOCKS)는 거울 체인 X 의 블록 기준이다(기본 50, '0' = 끔 — 격리 하네스 기본값).
const MIRROR_HEARTBEAT_BLOCKS = envBig('CIA_MIRROR_HEARTBEAT_BLOCKS', 50);
const MIRROR_POLL_MS = Number(process.env.CIA_MIRROR_POLL_MS) || 5000;
// 2026-10-05(전체 코드 리뷰 3번): 캐노니컬 게시가 성공하면 곧바로 뒤처진 거울에 중계한다 — 등록부 변경이 다음 주기(H 블록)까지
// 거울에 안 실려 첫 로그인이 지갑의 30초 대기(registry_unpublished)를 넘기고, 폐기 반영에도 시간 상한이 없던 문제. 주기 틱은 안전망
// (실패 재시도·behindSince 상한·불일치 복구)으로 남는다. '0' 이면 예전처럼 주기 틱만 — 거울 지연을 눈으로 보이는 시연용.
// 릴레이 자체가 꺼져 있으면(CIA_MIRROR_HEARTBEAT_BLOCKS=0, 격리 하네스 기본값) 이것도 꺼진다.
const MIRROR_RELAY_ON_PUBLISH = (process.env.CIA_MIRROR_RELAY_ON_PUBLISH ?? '1').trim() !== '0';
const MIRROR_SPECS = [];   // [{ chainStr, address }] — provider·서명자는 키를 읽은 뒤 initMirrors() 가 붙인다
for (const item of (process.env.CIA_MIRRORS || '').split(',').map((s) => s.trim()).filter(Boolean)) {
  const i = item.indexOf('=');
  if (i <= 0) throw new Error(`CIA_MIRRORS 항목 "${item}" 은 chainid=address 형식이어야 한다`);
  let chainStr;
  try { chainStr = BigInt(item.slice(0, i).trim()).toString(); } catch { throw new Error(`CIA_MIRRORS 의 chainid "${item.slice(0, i)}" 은 정수가 아니다`); }
  const address = ethers.getAddress(item.slice(i + 1).trim());
  if (!CHAIN_RPCS.has(chainStr)) throw new Error(`CIA_MIRRORS 의 chainid ${chainStr} 에 대한 RPC 가 CIA_CHAIN_RPCS 에 없다`);
  MIRROR_SPECS.push({ chainStr, address });
}
// 자기 provider(RPC_URL)의 chainId — health 의 chain.id. head 를 읽는 provider 와 같은 체인이어야 하므로
// CHAIN_RPCS 의 첫 키를 쓰지 않는다(여러 체인이 설정돼 있으면 어긋난다). 기동 시 한 번 읽는다.
let selfChainId = null;

// 데모 계정 — 비밀번호·uid 만(D15: 속성은 지갑이 들고 IdP 는 모른다. 옛 profile·attrs 필드는 2026-10-12 에 지웠다).
const DEMO_ACCOUNTS = {
  testuser: { password: 'password123', uid: '12345' },
  alice: { password: 'alicepw', uid: '67890' },
};
// Task 10(B1, 2026-10-22 스펙 §3.1~3.3): 발급 인증 정책 — key(기본·테스트) = /cia/issue 는 sig_u 만. code(데모) = provider 'demo' 계정은
// /cia/auth/code 로 받은 1회용 코드(auth_code)가 추가로 필요하다. DEMO_SEED 는 기동 때 DEMO_ACCOUNTS(testuser·alice)를 상태에 심는다 —
// 옛 흐름·기존 테스트 호환용이고, 가입(POST /cia/signup)만 쓰는 데모에서는 꺼 둔다(CIA_DEMO_ACCOUNTS 미설정).
const ISSUE_AUTH = process.env.CIA_ISSUE_AUTH === 'code' ? 'code' : 'key';
const DEMO_SEED = process.env.CIA_DEMO_ACCOUNTS === '1';
const CODE_TTL_MS = Number(process.env.CIA_CODE_TTL_MS) || 5 * 60_000;

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
// accounts:  uid → { pk_u:{x,y}, auid(10진 — Poseidon(T_AUID, uid, s_u), V11 D4), disabled, slot, tampered, creds, sessions, receipt, slotRetired }   (attrs·profile 없음 — D15)
//            creds 중 revoked:false 는 하나뿐(사용자당 활성 자격증명 하나, 2026-09-21 §3.1).
// rps:       arid → { name, origin, pk_service, X_svc, x_AA, pk_trace, status, requestedAt, decidedAt }   (2026-09-16 §3)
// openings:  [ { id, arid, PPID, tagKey, c1:{x,y}, c2, D_svc:{x,y}, allowAgent, max_height, chainid, status, requestedAt, decidedAt,
//                uid|null, resolved } ]   영구 감사 기록(§6). uid·resolved 는 approved 에만 의미 있다.
//            결정(승인·거절)이 끝나면 복호 재료 c1·c2·D_svc 는 지운다(2026-09-25 리뷰 B-4) — 재요청 대조는 tagKey 가 맡는다
// registry:  { depth, next, leaves: {"<index>": "<leaf>"(10진)}, pendingSlots: [{index, leaf}] }   사용자 자격증명 등록부(V9, 2026-10-01 §3)
// V10(2026-10-02): accounts[uid].receipt(마지막 폐기 접수증 또는 null)·slotRetired(대기열로 영구 은퇴된 슬롯이면 true),
//            lastPublication = { revRoot, regRoot, epoch, hLeaves, hIdx, hSlots, sig, txHash } (마지막 성공 게시 — 거울 릴레이용)
//            signedEpochMax = 서명한 가장 큰 epoch(게시 성공 여부 무관, 2026-10-02 최종 리뷰 I-2) — 다음 게시는 이보다 큰 epoch 를 쓴다
// revoked / pending / epoch
// 버전·이행은 lib/mode3_cia_state.js (v6, 2026-09-21).
const STATE_VERSION = CIA_STATE_VERSION;
let state;
let tree;            // 전체 폐기 트리(게시 여부 무관) — 서명해 올리는 root 의 출처
let publishedTree;   // 온체인에 이벤트로 나간 리프만 — 게시 직전 온체인 root 와 대조하는 기준
let registry;        // 등록부(설계 2026-10-01 §3) — state.registry.leaves 에서 복원
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
  const log = new ethers.Contract(LOG_ADDRESS, MODE3_LOG_ABI, ethWallet);
  const [root, regRoot, epoch] = await Promise.all([log.revRoot(), log.regRoot(), log.epoch()]);
  return { onchainRoot: BigInt(root), onchainRegRoot: BigInt(regRoot), onchainEpoch: Number(epoch) };
}
// 로컬 게시 기록을 온체인 (root, epoch) 과 대조한다. 어긋난 채로 게시하면 서명 root 와 지갑이
// 이벤트로 재구성한 root 가 달라져 전원이 fail-closed 되고, 로그 재배포 말고는 복구가 없다.
//   - 게시 tx 는 성공했는데 persist() 전에 죽은 경우: 그 tx 에 실렸던 pending 앞부분이 이미
//     체인에 있다. publishedTree 에 pending 을 하나씩 더해 가며 온체인 root 와 같아지는 지점을
//     찾고, 그 앞부분은 pending 에서 걷어낸다(다시 올리면 리프 이벤트가 중복될 뿐 무해하지만,
//     걷어내는 쪽이 정확하다). epoch 도 컨트랙트를 진실로 삼아 따라잡는다.
//   - 어느 접두사도 맞지 않으면 false(로그 재배포, 상태 파일 유실·옛 백업 복원). 이때
//     publishedTree 는 걷다 만 상태라 호출자가 다시 만들거나 종료해야 한다.
// 기동 시와 게시 직전 둘 다 이 함수를 쓴다 — 기동 때 RPC 가 죽어 대조를 건너뛰었거나 IdP 가 켜진
// 채로 로그가 재배포된 경우를 게시 직전 대조가 잡는다(2026-09-12 리뷰 반영).
//
// 등록부(V9) 쪽 대조(fullRegistryRebuild). registry.root() 는 폐기 쪽 publishedTree 와 달리 "아직 게시 안 된
// pendingSlots 까지 포함한" 전체 현재 상태라서, 게시 직전(publishNow 안)에는 onchainRegRoot 와 다른 것이
// **정상**이다 — 로컬이 pendingSlots 만큼만 앞서 있을 뿐이다. 그때는 손대지 않는다: pendingSlots 가 이미
// 정확히 그 칸들이다(2026-10-01 리뷰 2차) — 여기서 "지금 non-zero 인 칸 전부" 를 섞으면(1차 수정의 실수)
// 사용자가 N 명이면 매 게시마다 N 칸이 전부 실려 가스·SlotUpdated 양이 가입자 수에 비례해 버린다. IdP 키만
// 게시할 수 있으므로 런타임에 "로컬 − pendingSlots" 와 체인이 달라지는 경우는 보통 기동 호출
// (fullRegistryRebuild: true)이 잡지만, RPC 가 안 떠 기동 대조 자체를 건너뛰었거나(아래 loadState 의
// chain === null 분기) IdP 가 켜진 채로 로그가 같은 주소로 재배포된 경우는 기동 호출을 거치지 않으므로
// pendingSlots 가 그 순간 비어 있지 않으면 놓칠 수 있다 — epochDiverged 를 추가 신호로 쓰는 이유다(2026-10-01
// 리뷰 3차, 아래). pendingSlots 가 비어 있는데도 불일치하면(기동이든 런타임이든) 설명할 길이 없는 진짜
// 어긋남이므로 마찬가지로 0..next-1 전부(설계 §3.4, 비어 있어 0 인 칸 포함)를 다시 내보낸다 — 지갑은
// SlotUpdated 를 순서대로 재생해 root 를 맞추므로 중복은 무해하다.
async function reconcileWithChain({ onchainRoot, onchainRegRoot, onchainEpoch }, { fullRegistryRebuild = false } = {}) {
  let k = 0;
  while (publishedTree.getRoot() !== onchainRoot && k < state.pending.length) { await publishedTree.insert(BigInt(state.pending[k])); k++; }
  if (publishedTree.getRoot() !== onchainRoot) return false;
  let changed = false;
  if (k > 0) {
    console.warn(`[cia] 크래시 복구: pending ${k}개는 이미 체인에 게시돼 있어 걷어낸다`);
    state.pending = state.pending.slice(k);
    changed = true;
  }
  // epoch 은 이 함수의 따라잡기 줄(바로 아래)과 publishNow() 의 tx.wait() 뒤에서만 바뀐다 — 정상 런타임이면
  // 항상 state.epoch === onchainEpoch 다. 어긋나면(재배포는 <, 옛 백업 복원은 >) 등록부 쪽도 진짜 어긋났다는
  // 신호로 쓴다(2026-10-01 리뷰 3차) — 드문 경우라 비용은 전 칸 재발행 한 번뿐이다.
  const epochDiverged = onchainEpoch !== state.epoch;
  if (onchainEpoch > state.epoch) {
    console.warn(`[cia] 상태 파일 epoch(${state.epoch})가 체인 epoch(${onchainEpoch})보다 뒤처져 있어 맞춘다`);
    state.epoch = onchainEpoch;
    changed = true;
  }
  if (registry.root() === onchainRegRoot) {
    if (state.registry.pendingSlots.length) { state.registry.pendingSlots = []; changed = true; }
  } else if (fullRegistryRebuild || epochDiverged || state.registry.pendingSlots.length === 0) {
    state.registry.pendingSlots = Array.from({ length: state.registry.next }, (_, i) => ({ index: i, leaf: registry.leafAt(i).toString() }));
    changed = true;
  } else {
    // 로컬이 pendingSlots 만큼만 앞서 있다 — 게시 직전의 정상 상태. 할 일 없음(이미 정확히 그 칸들이다).
  }
  if (changed) persist();
  return true;
}

async function loadState() {
  state = readJson(STATE_FILE, defaultState());
  let migrated;
  try { migrated = migrateCiaState(state); }
  catch (e) {
    console.error(`[cia] 기동 거부: ${e.message}. V11(2026-10-12)은 옛 상태를 이행하지 않는다 — 재시연 세트(로그·거울 재배포 → 상태 파일 새로)로 새로 시작할 것.`);
    process.exit(1);
  }
  state = migrated.state;
  for (const n of migrated.notes) console.warn(`[cia] 상태 파일 이행 ${n}`);
  // 최종 리뷰 I4: 스키마는 지갑이 C_u 에 넣는 속성의 공통 인코딩 규칙이라, 바뀌면 이미 발급된 C_u 의 의미가 달라진다 —
  // 그래서 바뀐 스키마로는 뜨지 않는다(다시 인코딩할 길이 없다 — 지갑 쪽 상태). 해시가 없는 파일(이 필드 이전 또는
  // v10 이행)은 지금 스키마를 기록한다.
  let schemaHashRecorded = false;
  if (state.attrSchemaHash === null) { state.attrSchemaHash = ATTR_SCHEMA_HASH; schemaHashRecorded = true; }
  else if (state.attrSchemaHash !== ATTR_SCHEMA_HASH) {
    console.error(`[cia] 기동 거부: 속성 스키마가 바뀌었다(저장 ${state.attrSchemaHash} ≠ 현재 ${ATTR_SCHEMA_HASH}) — 다시 인코딩할 길이 없다(지갑 쪽 상태). ` +
      `스키마를 되돌리거나(CIA_ATTR_SCHEMA_FILE) 상태 파일을 새로 시작할 것.`);
    process.exit(1);
  }
  // 데모 시드(Task 10, 2026-10-22): CIA_DEMO_ACCOUNTS=1 일 때만 기동 때 DEMO_ACCOUNTS(testuser·alice)를 상태에 넣는다 — 가입 전용
  // 데모(§8 리셋 스크립트)에서는 꺼 둔다. 이미 있으면(재시작) 건드리지 않는다 — pwHash 를 매번 새로 만들지 않는다.
  let seeded = false;
  if (DEMO_SEED) {
    for (const a of Object.values(DEMO_ACCOUNTS)) {
      if (state.accounts[a.uid]) continue;
      state.accounts[a.uid] = { ...newPw(a.password), createdAt: new Date().toISOString(), pk_u: null, auid: null, slot: null, provider: 'demo', tampered: false, disabled: false, creds: [], sessions: [], receipt: null, slotRetired: false };
      seeded = true;
    }
  }
  publishedTree = await buildPublishedTree();
  tree = await createRevocationTree();
  for (const l of state.revoked) await tree.insert(BigInt(l));
  registry = await createRegistryTree(state.registry.depth);
  for (const [i, leaf] of Object.entries(state.registry.leaves)) registry.set(Number(i), BigInt(leaf));
  if (migrated.notes.length || schemaHashRecorded || seeded) persist();
  // 손으로 만든 상태 파일 방어(리프 비어 있는 슬롯 채움): 활성 자격증명의 리프를 채운다 — Poseidon 이 비동기라 이행 함수가 못 한다.
  let filled = 0;
  for (const [uid, acct] of Object.entries(state.accounts)) {
    const cur = activeCred(uid);
    if (!cur || !Number.isInteger(acct.slot) || state.registry.leaves[acct.slot] !== undefined) continue;
    const leaf = await registryLeaf(BigInt(acct.auid), BigInt(cur.Cf_u));
    setSlot(uid, leaf); filled++;
  }
  if (filled) { console.warn(`[cia] 등록부: 활성 자격증명 ${filled}개의 슬롯을 채웠다 — 다음 게시에 나간다`); persist(); }
  // 기동 시 대조. RPC 가 아직 안 떠 있으면 대조 없이 기동한다 — 발급은 headOf() 가 503 을 내거나
  // (CIA_CHAIN_RPCS 도 없어 허용 목록이 비어 있으면) chainid 허용 목록 검사에서 503 을 내고,
  // 게시는 게시 직전 대조에서 다시 확인된다.
  if (LOG_ADDRESS) {
    let chain = null;
    try { chain = await readChain(); }
    catch (e) { console.warn(`[cia] 기동 시 체인 확인 실패, root 대조 없이 계속 진행: ${e.message}`); }
    if (chain && !(await reconcileWithChain(chain, { fullRegistryRebuild: true }))) {
      console.error(`[cia] 기동 거부: 로컬 폐기 트리와 온체인 root 불일치 (로그 ${LOG_ADDRESS}, 온체인 epoch ${chain.onchainEpoch}, ` +
        `로컬 revoked ${state.revoked.length}개 / pending ${state.pending.length}개). 로그를 재배포했거나 상태 파일이 ` +
        `유실·복원됐다. 이대로 게시하면 지갑의 이벤트 재구성이 전부 실패한다 — CIA_STATE_FILE 과 CIA_LOG_ADDRESS 를 확인할 것.`);
      process.exit(1);
    }
  }
  try { selfChainId = (await ethWallet.provider.getNetwork()).chainId.toString(); }
  catch (e) { console.warn(`[cia] 기동 시 chainId 를 읽지 못했다 — health 의 chain.id 가 비고, CIA_CHAIN_RPCS 가 없으면 발급은 503: ${e.message}`); }
  if (CHAIN_RPCS.size === 0 && selfChainId) CHAIN_RPCS.set(selfChainId, RPC_URL);
  // 백로그(폐기 pending 또는 등록부 pendingSlots)가 남아 있으면 게시를 한 번 자동으로 시도한다 — 이행이나 리프 채움이
  // 없었어도 마찬가지다: setSlot+persist() 뒤 게시가 성공하기 전에 죽으면 리프는 이미 저장돼 있어 migrated.notes·filled
  // 가 둘 다 0 이지만 pendingSlots 는 남는다(2026-10-01 리뷰 Important 1) — 이행만 조건으로 두면 그 백로그가 다음
  // 하트비트까지(꺼져 있으면 영영) 게시되지 않아, 폐기된 자격증명이 체인에서는 계속 유효한 것으로 보인다.
  // RPC 가 아직 없으면(또는 다른 이유로 게시가 실패하면) 경고만 남긴다 — 기동 자체는 막지 않는다.
  if (state.registry.pendingSlots.length > 0 || state.pending.length > 0 || migrated.notes.length || filled) {
    try {
      const r = await publishNow();
      if (r.published) console.log(`[cia] 이행 뒤 자동 게시: epoch ${r.epoch}, 리프 ${r.leaves?.length ?? 0}개, 슬롯 ${r.slots ?? 0}개`);
      else console.log('[cia] 이행 뒤 자동 게시: 게시할 것이 없어 건너뜀');
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
// 서명 필드 파서(2026-10-13 리뷰 S1). BigInt(sig.S) 를 그대로 쓰면 '-1' 같은 값이 통과하는데, circomlibjs verifyPoseidon 은 S ≥ subOrder 만
// 거르므로 mulPointEscalar(-1n) 가 끝나지 않는다(-1n >> 1n === -1n) — IdP 프로세스 전체(하트비트·릴레이·전 라우트)가 멈춘다.
// 세 필드가 10진이고 R8x·R8y < p, S < 부분군 차수일 때만 verifyPoseidon 이 받는 { R8, S } 를, 아니면 null 을 돌려준다 — 호출자는 null 을
// 서명 불일치(400)로 다룬다. 네 라우트(/cia/register·/cia/slot·/cia/issue·/cia/revoke scope=session)가 함께 쓴다. 값은 로그에 남기지 않는다.
function parseEddsaSig(sig) {
  if (!sig || typeof sig !== 'object' || !isDec(sig.R8x) || !isDec(sig.R8y) || !isDec(sig.S)) return null;
  const r8x = BigInt(sig.R8x), r8y = BigInt(sig.R8y), sc = BigInt(sig.S);
  if (r8x >= F.p || r8y >= F.p || sc >= eddsa.babyJub.subOrder) return null;
  return { R8: [F.e(r8x), F.e(r8y)], S: sc };
}
function secretMatches(a, b) {
  const A = Buffer.from(a), B = Buffer.from(b);
  return A.length === B.length && timingSafeEqual(A, B);
}
// 계정 비밀번호(Task 10, 스펙 §3.1). scrypt(N=16384, r=8, p=1) — 보안 리뷰(2026-10-23)로 브리프·스펙의 sha256(salt‖pwd) 대신
// Node 내장 KDF 로 바꿨다(별도 의존성 없음). pwAlgo 를 계정에 같이 적어 두어 나중에 다른 알고리즘으로 옮길 길을 남긴다.
// 비밀번호·salt·해시는 로그에 남기지 않는다.
const hashPw = (saltHex, pwd) => scryptSync(String(pwd), Buffer.from(saltHex, 'hex'), 32, { N: 16384, r: 8, p: 1 }).toString('hex');
const newPw = (pwd) => { const pwSalt = randomBytes(16).toString('hex'); return { pwSalt, pwHash: hashPw(pwSalt, pwd), pwAlgo: 'scrypt' }; };
const pwOk = (acct, pwd) => {
  if (!acct?.pwHash || !acct?.pwSalt || typeof pwd !== 'string') return false;
  const a = Buffer.from(acct.pwHash, 'hex'), b = Buffer.from(hashPw(acct.pwSalt, pwd), 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
};
function requireAdmin(req, res, next) {
  if (ADMIN_OPEN) return next();
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
/** 사용자당 활성 자격증명 하나(설계 §3.1). 없으면 null. */
function activeCred(uid) {
  return (state.accounts[uid]?.creds ?? []).find((c) => !c.revoked) ?? null;
}
/** 등록부 슬롯 갱신(설계 2026-10-01 §3.2). leaf 0 = 비움. 다음 게시(pendingSlots)에 실린다 — 호출자가 persist·publish 한다. */
function setSlot(uid, leaf) {
  const acct = state.accounts[uid];
  if (!Number.isInteger(acct?.slot)) throw new Error(`setSlot: ${uid} 에 슬롯이 없다`);
  const v = BigInt(leaf);
  registry.set(acct.slot, v);
  if (v === 0n) delete state.registry.leaves[acct.slot]; else state.registry.leaves[acct.slot] = v.toString();
  state.registry.pendingSlots.push({ index: acct.slot, leaf: v.toString() });
}
/** 등록부가 바뀐 직후의 즉시 게시. 실패해도 상태는 유지하고 pendingSlots 가 남아 하트비트가 재시도한다(§3.3).
 *  이미 다른 게시가 진행 중이면(publishing) 그 promise 를 먼저 기다린 뒤 한 번 더 시도한다(2026-10-01 최종 리뷰
 *  A2) — publishNow 를 바로 불러 409 를 맞고 그대로 { published: false } 를 돌려주면, 그 사이 들어온 이 호출의
 *  슬롯·폐기 변경은 (먼저 끝난 게시의 스냅샷에 이미 끼어 있지 않은 한) pendingSlots/pending 에만 남아 다음
 *  하트비트 — 꺼져 있으면 사실상 다음 변경 — 까지 게시되지 않는다. 기다렸다 다시 부르면 그 백로그를 이 호출이
 *  그대로 집어간다. */
async function publishSafely() {
  try { return await publishNow({ wait: true }); }
  catch (e) { console.warn(`[cia] 즉시 게시 실패(다음 하트비트가 재시도): ${e.message}`); return { published: false, error: e.message }; }
}
/** 활성 자격증명을 revoked 로 돌린다(V9: 폐기 트리에 넣지 않는다 — 슬롯을 0 으로 두는 것이 호출자의 몫). 돌려주는 값은 물린 개수. */
function retireActiveCred(uid) {
  let n = 0;
  for (const c of state.accounts[uid]?.creds ?? []) if (!c.revoked) { c.revoked = true; n++; }
  return n;
}
// V10(2026-10-02 §4) 캐노니컬 = 이 IdP 가 게시하는 로그(RPC_URL 의 체인, LOG_ADDRESS). 게시 서명·접수증 둘 다 이 값을 덮는다.
// chainId 는 처음 필요할 때 한 번 읽어 둔다 — 읽기에 실패하면 캐시하지 않아 다음 호출이 다시 시도한다.
let canonical = null;
async function canonicalParams() {
  if (!LOG_ADDRESS) throw Object.assign(new Error('CIA_LOG_ADDRESS not configured'), { status: 503 });
  return (canonical ??= { canonicalChainId: (await ethWallet.provider.getNetwork()).chainId, canonicalLogAddress: LOG_ADDRESS });
}
/** 폐기 접수증(설계 §4.1) — "이 슬롯은 비어 있어야 한다" 는 IdP 의 약속. uid 는 넣지 않는다(슬롯은 SlotUpdated 로 어차피 공개). */
async function makeReceipt(slot) {
  const c = await canonicalParams();
  const params = { ...c, slot, epochAtRequest: BigInt(state.epoch), requestedAt: BigInt(Math.floor(Date.now() / 1000)) };
  const sig = await signReceipt(ethWallet, params);
  return { slot, epochAtRequest: params.epochAtRequest.toString(), requestedAt: params.requestedAt.toString(), sig, canonicalChainId: c.canonicalChainId.toString(), canonicalLogAddress: c.canonicalLogAddress };
}
/** 계정 폐기의 접수증. 같은 슬롯의 것이 이미 있으면 그대로(멱등 재요청), 슬롯이 바뀌었으면(은퇴 뒤 새 슬롯) 새로 낸다.
 *  만들지 못하면(로그 미설정·체인 chainId 를 못 읽음) null — 폐기 자체(disabled·슬롯 0)는 체인과 무관하게 이미 걸려 있어야
 *  하므로(§6.5.1) 접수증 실패로 폐기를 실패시키지 않는다. 저장하지 않으니 다음 재요청이 다시 시도한다. 호출자가 persist 한다. */
async function receiptFor(uid) {
  const acct = state.accounts[uid];
  if (acct.receipt && acct.receipt.slot === acct.slot) return acct.receipt;
  try { acct.receipt = await makeReceipt(acct.slot); }
  catch (e) { console.warn(`[cia] 폐기 접수증을 만들지 못했다(slot ${acct.slot}): ${e.message}`); return null; }
  return acct.receipt;
}

// ---- 1회용 코드(Task 10, 스펙 §3.3) ----
// state.codes 에 저장한다(메모리가 아니다) — 재시작 뒤에도 expiresAt 검사로 일관되게 만료된다. 32B hex, uid·purpose·auid 에 묶여
// 다른 계정·다른 목적(register vs issue)에는 못 쓴다. 발급마다 만료분을 함께 쓸어 상태 파일이 자라지 않게 한다.
function issueCode({ uid, purpose, auid = null }) {
  const code = randomBytes(32).toString('hex');
  state.codes[code] = { uid, purpose, auid, expiresAt: Date.now() + CODE_TTL_MS };
  for (const [k, v] of Object.entries(state.codes)) if (v.expiresAt < Date.now()) delete state.codes[k];
  persist();
  return { code, expiresAt: state.codes[code].expiresAt };
}
/** 1회용 코드 소비 — 있든 맞든 틀리든 조회된 코드는 지운다(브루트포스 재시도 방지). 맞으면 true. */
function consumeCode(code, { uid, purpose, auid = null }) {
  const c = typeof code === 'string' ? state.codes[code] : null;
  if (!c) return false;
  delete state.codes[code];
  persist();
  return c.expiresAt >= Date.now() && c.uid === uid && c.purpose === purpose && (auid === null || c.auid === auid);
}

// ---- 앱 ----
const app = express();
app.use(express.json({ limit: '256kb' }));
// 사용자 세션(Task 10, 스펙 §3.2): 메모리 저장소, 쿠키 cia.sid. 재기동하면 로그인이 풀린다(데모 수용) —
// CIA_SESSION_SECRET 이 없으면 기동마다 난수를 쓴다.
app.use(session({ name: 'cia.sid', secret: process.env.CIA_SESSION_SECRET || randomBytes(32).toString('hex'), resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: 'lax' } }));

// 사용자 오리진이 브라우저에서 직접 부르는 5 개 POST 라우트의 프리플라이트(계획 2026-10-15 Task 6).
for (const p of ['/cia/register', '/cia/issue', '/cia/slot', '/cia/revoke', '/cia/account/self_revoke']) app.options(p, userCors);

// 데모 공통 레이어(설계 2026-09-24-mode3-demo-ux §1.2) — mode3/common 만 정적으로 낸다.
app.use('/common', express.static(path.join(__dirname, 'mode3', 'common')));

// 관리자 패널(스펙 §5). 페이지 하나만 허용 목록으로 내보낸다 — express.static 은 쓰지 않는다.
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'cia_admin.html')));

// 사용자 페이지(§6.5.1). 잃어버린 지갑이 아니라 어느 장치에서든 열 수 있어야 하므로 IdP 가 직접 낸다.
app.get('/account', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'cia_account.html')));

app.get('/cia/public_keys', userCors, (req, res) => {
  // V10: canonicalChainId = 게시 로그가 있는 체인(selfChainId 와 같은 provider). mirrors = CIA_MIRRORS(릴레이 대상 거울, 2026-10-02 Task 6).
  res.json({ pk_CIA: S(ciaPub), ethAddress: ethWallet.address, heartbeatBlocks: Number(HEARTBEAT_BLOCKS), chainIds: [...CHAIN_RPCS.keys()], logAddress: LOG_ADDRESS,
    canonicalChainId: selfChainId, mirrors: MIRRORS.map(({ chainStr, address }) => ({ chainId: chainStr, address })),
    oidc: { enabled: OIDC.enabled, provider: OIDC.provider, clientId: OIDC.clientId, issuer: OIDC.issuer } });
});

// 속성 스키마 공개(스펙 2 §5.2, 인증 없음). 지갑·RP 가 기동 때 받아 술어 타입·정책 이름을 해석하고, 화면이 이름값을 그린다.
app.get('/cia/attr_schema', userCors, (req, res) => res.json({ schema: ATTR_SCHEMA, hash: ATTR_SCHEMA_HASH }));

// 상태 엔드포인트(설계 2026-09-25 §1) — 민감정보 없음, 승인된 RP·지갑 오리진에만 CORS.
app.get('/mode3/health', async (req, res) => {
  const rpOrigins = Object.values(state.rps).filter((r) => r.status === 'approved').map((r) => r.origin);
  // 허용 오리진은 origin 으로 정규화한다 — 설정값 끝의 '/' 같은 것이 CORS 를 조용히 깨뜨리지 않게.
  applyHealthHeaders(req, res, originList(rpOrigins, WALLET_AGENT_ORIGIN));
  let chain = null, last = null;
  // 두 조회를 함께 돌리고 한 예산(1.2초)만 씌운다 — 직렬로 1.5초씩 걸면 페이지의 요청 예산을 넘길 수 있다(설계 §1.3).
  try {
    const log = LOG_ADDRESS ? new ethers.Contract(LOG_ADDRESS, MODE3_LOG_ABI, ethWallet) : null;
    const [head, lastPub] = await bounded(Promise.all([headHeight(), log ? log.lastPublishedBlock().catch(() => null) : null]), 1200);
    chain = { id: selfChainId ?? '', head: head.toString() };
    last = lastPub === null || lastPub === undefined ? null : lastPub.toString();
  } catch { /* 체인 없음·응답 없음 */ }
  const mirrors = await readMirrorsHealth();   // 거울마다 따로 1.2초 예산(병렬) — 실패는 null 항목
  res.json(buildAaHealth({ now: new Date().toISOString(), chain, root: tree.getRoot().toString(), epoch: state.epoch, lastPublishedBlock: last, heartbeatBlocks: Number(HEARTBEAT_BLOCKS),
    pendingLeaves: state.pending.length, pendingRps: Object.values(state.rps).filter((r) => r.status === 'pending').length, pendingOpenings: state.openings.filter((o) => o.status === 'pending').length,
    accounts: Object.keys(state.accounts).length, walletOrigin: WALLET_AGENT_ORIGIN, rpOrigins, mirrors, attrSchema: schemaInfo(ATTR_SCHEMA, ATTR_SCHEMA_HASH) }));
});

// §3(2026-09-16) RP 등록 — pending 으로 받고 운영자가 승인하면 IdP 조각을 만들어 조합 키 pk_trace 와 cert_s(V2)를
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
    // 항등원·부분군 밖은 거절 — 항등원 X_svc 면 pk_trace 가 IdP 조각만으로 열린다(§2).
    if (!(await isTracePoint(Xs))) return res.status(400).json({ error: 'X_svc is not a valid subgroup point' });
    const Xn = { x: Xs.x.toString(), y: Xs.y.toString() };   // 정규 인코딩으로 저장·대조 — 비정규 입력이 다른 값으로 오인되지 않게
    let arid = Object.keys(state.rps).find((a) => state.rps[a].origin === origin);
    let e = arid ? state.rps[arid] : null;
    if (e && e.pk_service === null) {
      // v3 에서 넘어온 등록(키 없음): 키를 처음 내면 pending 으로 돌려 운영자 승인을 다시 받게 한다 —
      // 그러지 않으면 첫 호출자가 승인 없이 조합 키를 얻어 진짜 RP 가 잠긴다(§3).
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
    // IdP 조각 X_AA 와 그 지식 증명(2026-09-21, rogue key 방지). 저장하지 않고 x_AA 로 매번 새로 낸다 — 옛 상태 파일의 승인 항목에도 그대로 나간다.
    // RP 는 pk_trace = X_svc + X_AA 와 PoK 를 확인한다(mode3_rp.js). 지갑은 cert_s 만 본다 — 인증서 형식은 그대로다.
    const pok = await proveShare(BigInt(e.x_AA), { arid: BigInt(arid), X_svc: pointFromStrings(e.X_svc) });
    const S = (o) => ({ x: o.x.toString(), y: o.y.toString() });
    res.json({ arid, name: e.name, origin, pk_trace: e.pk_trace, cert_s, X_AA: S(pok.X), share_pok: { T: S(pok.T), c: pok.c.toString(), z: pok.z.toString() } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/** IdP 조각을 만들어 조합 키를 채운다. 승인 때 한 번 — await 사이 다른 요청이 먼저 채웠으면 덮어쓰지 않는다. */
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
    // 조각을 먼저 만들고, 성공한 **뒤에** status 를 바꾼다(2026-09-25 리뷰 B-6). 순서가 반대면 makeShare 가 던졌을 때
    // pk_trace = null 인 approved 로 굳는다 — 재승인은 409(already approved)고, 재등록도 status 가 pending 이 아니라
    // 조각을 다시 만들지 않는다. 그 RP 는 영영 조합 키를 못 받는다.
    await makeShare(req.params.arid);
    e.status = 'approved'; e.decidedAt = new Date().toISOString();
    persist();   // makeShare 의 persist 는 status 변경 전이다(이미 조각이 있어 일찍 반환한 경우 아예 안 쓴다)
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

// ---- Task 10(B1, 2026-10-22 스펙 §3.1~3.3): 사용자 계정·세션·1회용 코드 ----
// 모두 같은 오리진(IdP 자신의 /user·/login 페이지)에서만 부른다 — CORS 를 열지 않는다(스펙 §3.3).
const requireUser = (req, res, next) => { if (!req.session?.uid || !state.accounts[req.session.uid]) return res.status(401).json({ error: 'login required' }); next(); };
/** 사용자당 활성 자격증명의 Cf_u(없으면 null) — /cia/user/me·/cia/accounts 가 같이 쓴다. */
function activeCfU(a) { return (a.creds ?? []).find((c) => !c.revoked)?.Cf_u ?? null; }

app.post('/cia/signup', (req, res) => {
  const { pwd } = req.body ?? {};
  if (typeof pwd !== 'string' || pwd.length < 8) return res.status(400).json({ error: 'pwd 는 8자 이상', reason: 'signup_failed' });
  const uid = String(state.nextUid++);
  state.accounts[uid] = { ...newPw(pwd), createdAt: new Date().toISOString(), pk_u: null, auid: null, slot: null, provider: 'demo', tampered: false, disabled: false, creds: [], sessions: [], receipt: null, slotRetired: false };
  persist();
  res.status(201).json({ uid });
});
app.post('/cia/user/login', (req, res) => {
  const { uid, pwd } = req.body ?? {};
  if (!isDec(uid) || !pwOk(state.accounts[uid], pwd)) return res.status(401).json({ error: 'invalid credentials' });
  // 세션 고정 방지(보안 리뷰 2026-10-23): 로그인마다 세션 id 를 새로 받는다 — 로그인 전에 심어 둔 sid 로 로그인 뒤 들어오지 못하게.
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'session' });
    req.session.uid = uid;
    req.session.save((e2) => (e2 ? res.status(500).json({ error: 'session' }) : res.json({ uid })));
  });
});
app.post('/cia/user/logout', (req, res) => {
  req.session.destroy(() => { res.clearCookie('cia.sid'); res.json({ ok: true }); });
});
app.get('/cia/user/me', requireUser, (req, res) => {
  const uid = req.session.uid, a = state.accounts[uid];
  res.json({ uid, registered: Boolean(a.pk_u), auid: a.auid, slot: a.slot, provider: a.provider, disabled: a.disabled, activeCf_u: activeCfU(a), registryLeaf: a.slot === null ? null : registry.leafAt(a.slot).toString() });
});
app.post('/cia/user/register_code', requireUser, (req, res) => {
  const a = state.accounts[req.session.uid];
  if (a.pk_u) return res.status(409).json({ error: 'already registered', reason: 'already_registered' });
  res.json(issueCode({ uid: req.session.uid, purpose: 'register' }));
});
// 인증 창(§4)이 부른다 — 세션 없이도 된다. pwd 검사 → 등록 상태 → auid 일치 순으로 본다(틀린 비밀번호에는 등록 여부를 알려주지 않는다).
app.post('/cia/auth/code', (req, res) => {
  const { uid, pwd, auid } = req.body ?? {};
  const a = isDec(uid) ? state.accounts[uid] : null;
  if (!pwOk(a, pwd)) return res.status(401).json({ error: 'invalid credentials', reason: 'invalid_credentials' });
  if (!a.pk_u) return res.status(409).json({ error: 'not registered', reason: 'not_registered' });
  if (!isDec(auid) || BigInt(auid).toString() !== a.auid) return res.status(403).json({ error: 'auid mismatch', reason: 'auid_mismatch' });
  res.json(issueCode({ uid, purpose: 'issue', auid: a.auid }));
});

// V11 §3.1 등록. 지갑이 auid = Poseidon(T_AUID, uid, s_u) 와 등록 키 pk_u 를 낸다 — IdP 는 소유 증명 서명만 보고 슬롯 번호를 배정한다. 속성은 받지 않는다(D15).
// 신원은 데모 계정 {uid, pwd} 또는 Google ID 토큰 {id_token}(OIDC 래퍼 2026-10-16 — uid 는 IdP 가 검증한 sub 로 유도, nonce 는 pk_u 에 묶임) 중 하나로 확인한다.
app.post('/cia/register', userCors, async (req, res) => {
  const { uid: uidIn, pwd, code, id_token, auid, pk_u, sig_reg } = req.body ?? {};
  if (!isDec(auid) || !isPt(pk_u) || !sig_reg) return res.status(400).json({ error: 'auid, pk_u{x,y}, sig_reg required' });
  const demoPath = uidIn !== undefined, oidcPath = id_token !== undefined;
  if (demoPath === oidcPath) return res.status(400).json({ error: '{uid, pwd 또는 code} 또는 {id_token} 중 하나만' });   // 둘 다 없거나 둘 다 있음
  let uid, provider;
  if (oidcPath) {
    if (typeof id_token !== 'string') return res.status(400).json({ error: 'id_token 은 문자열' });
    const o = await oidcUid(id_token, REG_PREFIX); if (o.error) return res.status(o.error.status).json(o.error.body);
    // 토큰은 이 pk_u 에 묶여 있어야 한다(D4) — 가로챈 토큰으로 다른 키를 등록하지 못하게. auid 는 sig_reg 가 결속한다.
    if (o.nonce !== regNonce(pk_u)) return res.status(400).json({ error: 'oidc_nonce_mismatch', reason: 'oidc_nonce_mismatch', detail: 'nonce 가 요청의 pk_u 와 다르다' });
    uid = o.uid; provider = OIDC.provider;
  } else {
    if (!isDec(uidIn)) return res.status(400).json({ error: 'uid, (pwd 또는 code), auid, pk_u{x,y}, sig_reg required' });
    // 가입 계정(§3.1): POST /cia/user/register_code 로 받은 1회용 코드(purpose register), 또는(API·옛 흐름 호환) 가입 비밀번호.
    if (code !== undefined) {
      if (!consumeCode(code, { uid: uidIn, purpose: 'register' })) return res.status(401).json({ error: 'bad_code', reason: 'bad_code' });
    } else {
      if (typeof pwd !== 'string') return res.status(400).json({ error: 'uid, (pwd 또는 code), auid, pk_u{x,y}, sig_reg required' });
      if (!pwOk(state.accounts[uidIn], pwd)) return res.status(401).json({ error: 'invalid credentials' });
    }
    uid = uidIn; provider = 'demo';
  }
  const made = await registerAccount({ uid, provider, auid, pk_u, sig_reg });
  if (made.error) return res.status(made.error.status).json(made.error.body);
  res.status(201).json({ slot: made.slot, schemaHash: ATTR_SCHEMA_HASH, uid, provider });
});
/** 계정 등록의 공통 부분(/cia/register 와 /cia/issue 의 id_token 암묵 등록이 같이 쓴다, 2026-10-16): 409·auid 범위·pk_u 점·sig_reg 검증·슬롯 배정.
 *  성공 { slot }, 실패 { error: { status, body } }. */
async function registerAccount({ uid, provider, auid, pk_u, sig_reg }) {
  const fail = (status, body) => ({ error: { status, body } });
  if (!isDec(auid) || !isPt(pk_u) || !sig_reg) return fail(400, { error: 'auid, pk_u{x,y}, sig_reg required' });
  // Task 10(B1): 가입만 하고 등록 전인 계정(pk_u:null)은 막지 않는다 — "이미 등록됨" 은 pk_u 가 채워져 있을 때뿐이다.
  if (state.accounts[uid]?.pk_u) return fail(409, { error: 'already registered' });
  if (BigInt(auid) >= F.p) return fail(400, { error: 'auid is not a field element' });   // Poseidon 출력 범위 — 비정규 값은 등록부 리프·π 와 어긋난다
  if (!(await isValidPoint(pointFromStrings(pk_u)))) return fail(400, { error: 'pk_u is not a valid subgroup point' });
  let ok = false;
  const sigReg = parseEddsaSig(sig_reg);   // 리뷰 S1: 비정규·범위 밖 서명은 verifyPoseidon 에 넣지 않는다
  try {
    const m = F.e(await registerMessage(BigInt(uid), BigInt(auid)));
    ok = sigReg !== null && eddsa.verifyPoseidon(m, sigReg, [F.e(BigInt(pk_u.x)), F.e(BigInt(pk_u.y))]);
  } catch { ok = false; }
  if (!ok) return fail(400, { error: 'bad_registration_signature' });
  if (state.accounts[uid]?.pk_u) return fail(409, { error: 'already registered' });   // await 사이 경합
  const slot = state.registry.next++;
  // 가입 때 만든 레코드(pwSalt·pwHash·createdAt)가 있으면 그 자리를 채운다 — 새 객체로 덮어 비밀번호를 잃지 않는다(Task 10).
  const acct = state.accounts[uid] ??= { pwSalt: null, pwHash: null, pwAlgo: null, createdAt: new Date().toISOString(), tampered: false, disabled: false, creds: [], sessions: [], receipt: null, slotRetired: false };
  Object.assign(acct, { pk_u: { x: BigInt(pk_u.x).toString(), y: BigInt(pk_u.y).toString() }, auid: BigInt(auid).toString(), slot, provider });
  persist();
  return { slot };
}

// V9: 옛 지갑 상태 파일(슬롯 없음)이 자기 슬롯 번호를 되찾는다. sk_u 서명 인증, 메시지는 Poseidon(D_SLOTREQ, uid, nonce).
app.post('/cia/slot', userCors, async (req, res) => {
  try {
    const { uid, nonce, sig_u } = req.body ?? {};
    if (!isDec(uid) || !isDec(nonce) || !sig_u) return res.status(400).json({ error: 'uid, nonce, sig_u required' });
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    let ok = false;
    const sigU = parseEddsaSig(sig_u);   // 리뷰 S1
    try {
      const m = F.e(await slotRequestMessage(BigInt(uid), BigInt(nonce)));
      ok = sigU !== null && eddsa.verifyPoseidon(m, sigU, [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))]);
    } catch { ok = false; }
    if (!ok) return res.status(400).json({ error: 'bad user signature' });
    res.json({ slot: acct.slot });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// V11(스펙 2026-10-12 §5.2, 그림 3 "DA request") 세션 발급 = (C_u, C_s, π_IdP, sig_u) 한 요청. 옛 /cia/user_cred 를 흡수했다 — 요청의 C_u 가
// 활성 자격증명과 다르면(첫 로그인·사용자의 속성 변경) 등록부 슬롯을 갱신·게시한 뒤 토큰을 낸다. 속성 값은 받지 않는다(D15).
// 검사 순서: 형식 → max_height 범위 → 계정·disabled → chainid 허용 → C_u·C_s 부분군 → sig_u → π_IdP → 체인 생존(fail-closed) → disabled 재확인 →
// (C_u 교체: 은퇴 → creds 추가 → setSlot → persist → 즉시 게시) → 토큰 서명 → 세션 기록. auid_s·arid_s 는 서명·토큰에만 쓰고 저장하지 않는다(D1).
// /cia/issue — 데모 계정은 sig_u 만, 래퍼(Google) 계정은 sig_u + id_token(+첫 로그인이면 registration). 2026-10-16.
app.post('/cia/issue', userCors, async (req, res) => {
  try {
    const { uid, auid_s, arid_s, C_u_pt, C_s_pt, chainid, allowAgent, max_height, proof_idp, sig_u, id_token, registration, auth_code } = req.body ?? {};
    if (!isDec(uid) || !isDec(auid_s) || !isDec(arid_s) || !isPt(C_u_pt) || !isPt(C_s_pt) || !isDec(chainid) || (allowAgent !== '0' && allowAgent !== '1') || !isDec(max_height) || !proof_idp || typeof proof_idp !== 'object' || !sig_u) {
      return res.status(400).json({ error: 'uid, auid_s, arid_s, C_u_pt{x,y}, C_s_pt{x,y}, chainid, allowAgent("0"|"1"), max_height, proof_idp, sig_u required' });
    }
    const mh = BigInt(max_height);
    if (mh >= (1n << 64n)) return res.status(400).json({ error: 'max_height must be < 2^64' });
    // 리뷰 L5(2026-10-13): auid_s·arid_s 도 /cia/register 의 auid 처럼 필드 원소(< p)여야 한다 — arid_s = A + p 는 Poseidon 안에서 A 와 같아져
    // 서명·토큰은 그대로 통과하지만 정규형이 아닌 별칭이다(auid_s 는 snarkjs 가 거절하지만 같은 자리에서 먼저 막는다).
    if (BigInt(auid_s) >= F.p || BigInt(arid_s) >= F.p) return res.status(400).json({ error: 'auid_s and arid_s must be field elements (< p)' });
    // OIDC 래퍼 — RP 로그인 흐름(2026-10-16): Google 로 로그인한 사용자는 발급마다 ID 토큰을 함께 낸다. 래퍼가 토큰을 검증해 계정(uid=H(provider|sub))을
    // 정하고, 계정이 아직 없으면 요청에 실린 등록 재료(auid·pk_u·sig_reg)로 그 자리에서 등록한 뒤 발급한다 — 사용자에게 보이는 등록 단계가 없다.
    // 토큰은 이 지갑의 공개키와 이 로그인(arid_s)에 nonce 로 묶여 있어 가로채도 다른 키·다른 로그인에 못 쓴다. 데모 계정(uid/pwd 등록)은 id_token 없이 지금처럼.
    let oidcClaims = null;
    if (id_token !== undefined) {
      if (typeof id_token !== 'string') return res.status(400).json({ error: 'id_token 은 문자열' });
      const o = await oidcUid(id_token, ISSUE_PREFIX); if (o.error) return res.status(o.error.status).json(o.error.body);
      if (o.uid !== uid) return res.status(403).json({ error: 'uid_mismatch', reason: 'uid_mismatch', detail: '토큰의 계정이 요청의 uid 와 다르다' });
      oidcClaims = o;
      if (!state.accounts[uid]) {
        if (!registration || typeof registration !== 'object') return res.status(404).json({ error: 'unknown account', reason: 'not_registered', detail: '첫 로그인이면 registration{auid,pk_u,sig_reg} 을 함께 보낸다' });
        const made = await registerAccount({ uid, provider: OIDC.provider, auid: registration.auid, pk_u: registration.pk_u, sig_reg: registration.sig_reg });
        if (made.error) return res.status(made.error.status).json(made.error.body);
      }
    }
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    if (acct.disabled) return res.status(403).json({ error: 'account disabled', reason: 'account_disabled' });
    // 래퍼 계정(provider 가 demo 가 아님)은 발급마다 토큰이 있어야 한다 — Google 이 매 로그인을 확인한다는 의미다.
    if (acct.provider && acct.provider !== 'demo' && !oidcClaims) return res.status(401).json({ error: 'oidc_required', reason: 'oidc_required' });
    if (oidcClaims && oidcClaims.nonce !== issueNonce(acct.pk_u, arid_s)) return res.status(400).json({ error: 'oidc_nonce_mismatch', reason: 'oidc_nonce_mismatch', detail: 'nonce 가 이 지갑·이 로그인(arid_s)과 다르다' });
    // 발급 인증 정책(CIA_ISSUE_AUTH=code, Task 10 B1, 2026-10-22): demo 계정은 §4 의 인증 창이 낸 1회용 코드가 있어야 발급한다.
    if (ISSUE_AUTH === 'code' && acct.provider === 'demo') {
      if (typeof auth_code !== 'string') return res.status(401).json({ error: 'auth_code required', reason: 'auth_code_required' });
      if (!consumeCode(auth_code, { uid, purpose: 'issue', auid: acct.auid })) return res.status(401).json({ error: 'bad_code', reason: 'bad_code' });
    }
    const chainStr = BigInt(chainid).toString();
    if (CHAIN_RPCS.size === 0) return res.status(503).json({ error: 'chain id unknown: CIA_CHAIN_RPCS not configured and RPC unreachable at startup' });
    if (!CHAIN_RPCS.has(chainStr)) return res.status(400).json({ error: `bad chainid ${chainStr}: allowed ${[...CHAIN_RPCS.keys()].join(',')}` });
    const agent = BigInt(allowAgent);
    const cupt = pointFromStrings(C_u_pt), cspt = pointFromStrings(C_s_pt);
    if (!(await isValidPoint(cupt))) return res.status(400).json({ error: 'C_u_pt is not a valid subgroup point' });
    if (!(await isValidPoint(cspt))) return res.status(400).json({ error: 'C_s_pt is not a valid subgroup point' });
    // Cf_u·Cf_s 는 IdP 가 점에서 스스로 유도한다(설계 §6.2) — 사용자가 보낸 Cf 를 서명하면 증명된 점과 무관한 값에 서명이 붙는다.
    const Cf_u = await compressPoint(cupt), Cf_s = await compressPoint(cspt);
    const auidS = BigInt(auid_s), aridS = BigInt(arid_s);
    let sigOk = false;
    const sigU = parseEddsaSig(sig_u);   // 리뷰 S1
    try {
      const m = F.e(await issueRequestMessageV11(auidS, aridS, Cf_u, Cf_s, BigInt(chainStr), agent, mh));
      sigOk = sigU !== null && eddsa.verifyPoseidon(m, sigU, [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))]);
    } catch { sigOk = false; }
    if (!sigOk) return res.status(400).json({ error: 'bad user signature' });
    // π_IdP — 공개 입력은 IdP 가 스스로 조립한다(uid 는 요청·계정, auid 는 DB 값): 지갑이 보낸 값을 그대로 넣으면 아무 auid 에 대한 증명이 통과한다.
    let vkIdp;
    // 리뷰 S4: 응답에는 고정 사유만 — 절대경로·ENOENT 는 지갑을 거쳐 페이지까지 가므로 서버 로그에만 남긴다.
    try { vkIdp = await loadIdpVkey(IDP_VKEY); } catch (e) { console.error(`[cia] π_IdP vkey 를 읽지 못했다: ${e.message}`); return res.status(503).json({ error: 'idp_vkey_unavailable', reason: 'idp_vkey_unavailable' }); }
    const pubIdp = idpPublicSignals({ uid: BigInt(uid), auid: BigInt(acct.auid), auid_s: auidS, C_u_pt: cupt, C_s_pt: cspt, max_height: mh });
    if (!(await verifyIdp(vkIdp, pubIdp, proof_idp))) return res.status(400).json({ error: 'bad idp proof', reason: 'bad_idp_proof' });
    const head = await headOf(chainStr);   // fail-closed: 체인이 죽어 있으면 발급하지 않는다(게시도 불가하므로 폐기가 닿지 않는 세션이 된다)
    const cfu = Cf_u.toString();
    // 이 await 를 끝으로 아래 물리기→push→setSlot→persist 구간은 동기다(2026-10-01 리뷰 Important 2 와 같은 이유).
    const newLeaf = await registryLeaf(BigInt(acct.auid), Cf_u);
    if (acct.disabled) return res.status(403).json({ error: 'account disabled', reason: 'account_disabled' });   // await 사이의 폐기
    acct.creds ??= [];
    const cur = activeCred(uid);
    let published = false;
    if (!cur || cur.Cf_u !== cfu) {
      // 물린 적 있는 C_u 는 다시 받지 않는다 — 은퇴·폐기의 되감기를 막는다.
      if (acct.creds.some((c) => c.Cf_u === cfu)) return res.status(409).json({ error: 'this user credential was revoked; make a new one', reason: 'cred_revoked' });
      retireActiveCred(uid);
      // V10(§4.5): 대기열로 영구 은퇴된 슬롯에는 0 아닌 리프를 쓸 수 없다(컨트랙트 SlotIsRetired) — 새 슬롯을 받는다. PPID 는 (uid, s_u, arid, chainid) 에만 걸려 있어 슬롯이 바뀌어도 그대로다.
      if (acct.slotRetired) { acct.slot = state.registry.next++; acct.slotRetired = false; }
      acct.creds.push({ Cf_u: cfu, C_u_pt: { x: cupt.x.toString(), y: cupt.y.toString() }, issuedAt: new Date().toISOString(), revoked: false });
      setSlot(uid, newLeaf);
      persist();
      published = Boolean((await publishSafely()).published);
      if (acct.disabled) return res.status(403).json({ error: 'account disabled', reason: 'account_disabled' });   // 게시 await 사이의 폐기
      // 리뷰 S2(2026-10-13): 게시 await 사이에 이 C_u 가 물렸으면(같은 uid 의 다른 새 C_u 발급, 관리자 scope=credential) 토큰을 내지 않는다 —
      // 은퇴된 Cf_u 위의 토큰은 등록부에 없어 쓸 수 없고, 지갑이 그 C_u 를 보관하면 다음 로그인이 registry_mismatch 에서 못 빠져나온다.
      // 지갑은 cred_revoked 에 새 C_u 로 한 번만 다시 시도한다(mode3_wallet_agent.js /wallet/login).
      if (activeCred(uid)?.Cf_u !== cfu) return res.status(409).json({ error: 'this user credential was retired while publishing; make a new one', reason: 'cred_revoked' });
    }
    const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessageV11(auidS, aridS, Cf_u, Cf_s, BigInt(chainStr), agent)));
    // V8(2026-09-24 §2.1): 세션 단위 폐기를 하려면 IdP 가 Cf_s 를 알아야 한다. 정리는 하트비트뿐 아니라 여기서도(최종 리뷰 F2). auid_s·arid_s 는 적지 않는다(D1).
    acct.sessions = (acct.sessions ?? []).filter((r) => r.chainid !== chainStr || BigInt(r.max_height) >= head);
    acct.sessions.push({ Cf_s: Cf_s.toString(), max_height: mh.toString(), chainid: chainStr, allowAgent: agent.toString(), issuedAt: new Date().toISOString(), revokedAt: null });
    persist();
    res.json({
      Cf_u: cfu, Cf_s: Cf_s.toString(), max_height: mh.toString(), chainid: chainStr, allowAgent: agent.toString(),
      sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() },
      pk_CIA: S(ciaPub), slot: acct.slot, regRoot: registry.root().toString(), epoch: state.epoch, published,
    });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// §6.5 계정 전체 폐기: 활성 사용자 자격증명의 슬롯을 0 으로 비우고 즉시 게시 + disabled. 관리자 폐기(/cia/revoke scope=account)와
// 사용자 자기 폐기(/cia/account/self_revoke, §6.5.1)가 같은 처리를 탄다 — 다른 것은 "누가 개시하느냐"뿐이다.
// 슬롯은 Cf_u 하나에서 나오므로(2026-09-21 §3.6) 체인 헤드를 읽지 않고, setSlot(uid, 0n) 은 멱등(이미 0 이면 값이 그대로)이다.
async function revokeAccount(uid) {
  const acct = state.accounts[uid];
  if (!acct) throw Object.assign(new Error('unknown account'), { status: 404 });
  acct.disabled = true;
  const retired = retireActiveCred(uid);
  if (retired) setSlot(uid, 0n);   // 물린 게 없으면 슬롯은 건드리지 않는다 — disabled 는 그대로 건다
  // V10(2026-10-02 수정): 계정 폐기는 슬롯을 로컬에서도 영구 은퇴시킨다 — 관리자가 되살린 뒤의 재발급은 새 슬롯을 받는다.
  // 그래야 이 폐기의 접수증이 가리키는 슬롯은 영원히 0 이고, 누가 나중에 올려도 다시 채운 슬롯을 강제 은퇴시키지 못한다.
  acct.slotRetired = true;
  persist();   // disabled·(물렸다면) 슬롯 변경을 게시 시도 전에 먼저 저장한다 — 게시 중 죽어도 다음 기동이 백로그를 본다
  // V10 접수증(§4.1): 계정 폐기에만 낸다. 물린 게 없어도(retired 0) 낸다 — 약속은 "이 슬롯은 비어 있어야 한다" 이다. 체인 조회가 끼므로 위 저장 뒤에 만든다.
  const receipt = await receiptFor(uid);
  if (receipt) persist();
  const pub = retired ? await publishSafely() : { published: false };
  return { retired, disabled: true, slot: acct.slot, regRoot: registry.root().toString(), published: Boolean(pub.published), pending: state.pending.length, receipt };
}

// §4.3(2026-09-21) 폐기. account = 활성 사용자 자격증명의 슬롯을 0 으로 비움 + disabled. credential = 슬롯만 비움(계정은 살아 있어 새 C_u 로 /cia/issue 를 다시 받아야 한다).
// 슬롯은 사용자당 하나라 leaf/C 인자를 받지 않는다(있어도 무시). setSlot(uid, 0n) 은 멱등(이미 0 이면 값이 그대로)이다.
// V8(2026-09-24 §2.2) session = 세션 하나만 — 사용자는 sk_u 서명으로, 운영자는 관리자 시크릿으로. 그래서 requireAdmin 을 미들웨어로
// 걸지 않고 안에서 분기한다. 관리자 헤더가 틀리게 오면 isAdmin=false 라 scope=session 은 서명 경로로 흐르고 account/credential 은 401 이다.
app.post('/cia/revoke', userCors, async (req, res) => {
  try {
    const { uid, scope, Cf_s, sig_u, nonce, bound: boundIn } = req.body ?? {};
    const hdr = req.get('X-CIA-Admin-Secret');
    // CIA_ADMIN_OPEN 이면 헤더가 있는 요청(관리자 페이지)만 관리자로 본다 — 헤더 없는 사용자 본인 서명 요청은 그대로 서명 경로로 간다.
    const isAdmin = ADMIN_OPEN ? typeof hdr === 'string' : Boolean(ADMIN_SECRET) && typeof hdr === 'string' && secretMatches(hdr, ADMIN_SECRET);
    if (scope !== 'session') {   // requireAdmin 과 같은 응답을 그대로 유지한다(시크릿 미설정 503, 틀린 시크릿 401)
      if (!ADMIN_OPEN && !ADMIN_SECRET) return res.status(503).json({ error: 'admin endpoints disabled: CIA_ADMIN_SECRET is not configured' });
      if (!isAdmin) return res.status(401).json({ error: 'unauthorized' });
    }
    if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
    if (scope === 'account') return res.json(await revokeAccount(uid));
    if (scope === 'credential') {
      const retired = retireActiveCred(uid);
      if (retired) { setSlot(uid, 0n); persist(); }   // 물린 게 없으면 슬롯·게시·persist 모두 건드리지 않는다
      // V10(2026-10-02 수정): 접수증을 내지 않는다(응답에 receipt 필드 없음). 자격증명 은퇴는 IdP 가 개시한 것이라(속성 변경 등)
      // 사용자가 강제할 요청이 없고, 접수증이 있으면 같은 슬롯을 다시 채운 뒤에도 누구든 그 슬롯을 강제 은퇴시킬 수 있다.
      const pub = retired ? await publishSafely() : { published: false };
      return res.json({ retired, slot: state.accounts[uid].slot, regRoot: registry.root().toString(), published: Boolean(pub.published), pending: state.pending.length });
    }
    if (scope !== 'session') return res.status(400).json({ error: "scope must be 'account', 'credential' or 'session'" });
    if (!isDec(Cf_s)) return res.status(400).json({ error: 'Cf_s required' });
    // 허용 거래 수 bound ∈ [0, 2^32)(설계 2026-10-22 §3): nonce < bound 인 거래만 유효, 0 = 세션 전부 차단. 관리자 경로는
    // 생략하면 0(전부 차단)이고, 사용자 서명 경로는 서명이 bound 를 덮으므로 생략할 수 없다(아래에서 isDec 이 걸러낸다).
    const bound = isAdmin ? (boundIn ?? '0') : boundIn;
    if (!isDec(bound) || BigInt(bound) >= SESSION_BOUND_MAX) return res.status(400).json({ error: 'bound 는 [0, 2^32)' });
    const acct = state.accounts[uid];
    const rec = (acct.sessions ?? []).find((s) => s.Cf_s === BigInt(Cf_s).toString());
    // 서명은 기록 조회보다 먼저 본다 — 서명 없이 "그 Cf_s 가 이 계정에 있는지" 를 알아내지 못하게.
    if (!isAdmin) {
      if (!sig_u || !isDec(nonce)) return res.status(401).json({ error: 'sig_u and nonce required without admin secret' });
      let ok = false;
      const sigU = parseEddsaSig(sig_u);   // 리뷰 S1
      try {
        const m = F.e(await revokeSessionMessage(BigInt(uid), BigInt(Cf_s), BigInt(bound), BigInt(nonce)));
        ok = sigU !== null && eddsa.verifyPoseidon(m, sigU, [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))]);
      } catch { ok = false; }
      if (!ok) return res.status(400).json({ error: 'bad user signature' });
    }
    if (!rec) return res.status(404).json({ error: 'unknown session', reason: 'unknown_session' });
    // 이미 폐기된 세션의 재폐기: bound 를 기존보다 낮추는 요청만 새 리프를 넣는다(낮추기, 설계 §3) — 같거나 올리는 요청은 멱등 응답.
    if (rec.revokedAt && BigInt(bound) >= BigInt(rec.bound ?? '0')) {
      return res.json({ inserted: false, bound: rec.bound ?? '0', root: tree.getRoot().toString(), pending: state.pending.length });
    }
    // 만료된 세션은 리프를 넣지 않는다 — append-only 트리를 이미 죽은 세션으로 불리는 일이다(설계 §6).
    // 만료 기준은 head > max_height 다 — 컨트랙트(Mode3Wallet.sol `block.number > pub[3]`)·RP(lib/mode3_rp.js)와 같은 부등호를
    // 쓴다. head == max_height 는 아직 살아 있는 세션이라 폐기할 수 있어야 한다(최종 리뷰 F1).
    if ((await headOf(rec.chainid)) > BigInt(rec.max_height)) return res.status(409).json({ error: 'session expired', reason: 'expired' });
    const leaf = (await sessionLeaf(BigInt(Cf_s), BigInt(bound))).toString();
    // 위 await 들 사이에 하트비트의 pruneExpiredSessions() 가 acct.sessions 를 통째로 갈아끼울 수 있다 — 그러면 rec 은 버려진
    // 객체라 revokedAt 이 아무 데도 안 남고, 그 사이 만료된 세션에 리프만 들어간다. 삽입 직전에 다시 찾는다.
    const cur = (acct.sessions ?? []).find((s) => s.Cf_s === BigInt(Cf_s).toString());
    if (!cur) return res.status(409).json({ error: 'session expired', reason: 'expired' });
    const inserted = await tree.insert(BigInt(leaf));
    if (inserted) { state.revoked.push(leaf); state.pending.push(leaf); }
    cur.revokedAt = new Date().toISOString();
    cur.bound = BigInt(bound).toString();
    persist();
    res.json({ inserted, leaf, bound: cur.bound, root: tree.getRoot().toString(), pending: state.pending.length });
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
    out.push({ ...s, expired: heads[s.chainid] === null ? null : heads[s.chainid] > BigInt(s.max_height) });
  }
  res.json({ sessions: out });
});

// §6.5 게시. 서명이 리프 배열까지 덮는다 — 릴레이어의 calldata 오염 방지. 로그 주소도 덮는다 —
// 같은 IdP 키로 재배포한 다른 로그에 옛 게시를 재생하지 못하게(재생되면 root 가 옛 트리로 바뀐다).
// digest 계산은 lib/mode3_log.js 하나다(컨트랙트의 digestFor 와 바이트 단위로 같다).
//
// 게시는 한 번에 하나만 돈다. 둘이 겹치면 각자 pending 을 자기 개수만큼 앞에서 잘라, 그 사이 들어온
// revoke 의 리프가 pending 에서만 사라진다 — 트리·서명 root 에는 남아 지갑 재구성이 영구히 실패한다.
// 관리자 페이지의 게시 버튼을 두 번 누르는 것이 그 경로다.
// publishing 은 "진행 중 여부"가 아니라 **진행 중인 게시의 promise** 다(2026-10-01 최종 리뷰 A2). publishNow 를
// 그대로 다시 부르면(관리자의 /cia/publish 이중 클릭 등) 여전히 409 로 막지만, publishSafely·heartbeatTick 같은
// 내부 호출자는 이 promise 를 기다렸다가 끝난 뒤 자기 몫을 다시 시도한다 — 예전에는 409 를 캐치하고 그냥
// { published: false } 를 돌려줘, 그 사이 들어온 슬롯·폐기 변경이 다음 하트비트(또는 그 다음 변경)까지, 하트비트가
// 꺼져 있으면 사실상 영영 게시되지 않을 수 있었다(조용한 로컬 체인에서 폐기된 자격증명이 계속 유효하게 남는다).
let publishing = null;
/** 게시 잠금 획득(2026-10-02 Task 6 리뷰 C1). 잠금을 잡는 곳은 여기 하나다 — publishNow 와 같은 체인 거울 tx(sendMirrorTx).
 *  - 원자성: 마지막 `publishing === null` 확인과 `publishing = mine` 대입 사이에 await 가 없다(같은 동기 구간). 예전처럼
 *    `await waitPublishing()` 뒤 호출자가 대입하면, 같은 promise 를 기다리던 대기자들이 같은 마이크로태스크 회차에 깨어나
 *    둘 다 null 을 보고 둘 다 잡았다 — 게시 tx 와 거울 tx 가 같은 키로 동시에 나가(nonce 경합) 게시 둘이 겹칠 수 있었다.
 *  - 소유자 해제: 내 promise 일 때만 null 로 되돌린다. 무조건 null 로 두면 내가 끝난 뒤 이미 잡은 남의 잠금을 풀어 버린다.
 *  - wait=false 는 진행 중이면 즉시 409(관리자 /cia/publish 이중 클릭), wait=true 는 끝날 때까지 기다려 잡는다
 *    (publishSafely·heartbeatTick·릴레이 — 409 를 맞고 { published:false } 로 끝나면 A2 리뷰의 유실이 되살아난다).
 *  - factory 는 동기 구간 안에서 불려 promise 를 돌려줘야 한다(async 함수 호출이면 된다). 먼저 가던 쪽의 실패는 그쪽 책임 — 삼킨다. */
async function withPublishLock(factory, { wait }) {
  if (publishing && !wait) throw Object.assign(new Error('publish already in progress'), { status: 409 });
  while (publishing) { try { await publishing; } catch { /* 그쪽 catch 가 이미 경고를 냈다 */ } }
  const mine = factory();
  publishing = mine;
  try { return await mine; } finally { if (publishing === mine) publishing = null; }
}
/** 진행 중인 잠금이 풀릴 때까지 기다리기만 한다(잡지 않는다). **최적화 용도로만** 쓴다 — 기다린 뒤 "아직 필요한지" 다시 재서
 *  불필요한 하트비트를 줄이는 것. 이 뒤의 실제 게시는 반드시 publishNow({ wait: true }) 로 잡으므로 여기서 다른 대기자가 먼저
 *  잡아도 안전하다(겹치지 않고 그 뒤에 줄을 선다 — 최악은 하트비트 한 번 더). */
async function waitPublishing() {
  while (publishing) { try { await publishing; } catch { /* */ } }
}
/**
 * root 게시. heartbeat=true 면 pending 이 비어 있어도 같은 root 를 새 epoch 로 올린다(설계 §4.5) — 컨트랙트 조건은 epoch
 * 증가뿐이라 그대로다. 한 번에 하나만 돈다: 둘이 겹치면 각자 pending 을 자기 개수만큼 앞에서 잘라 그 사이 들어온 revoke 의
 * 리프가 pending 에서만 사라진다(트리·서명 root 에는 남아 지갑 재구성이 영구히 실패). 진짜 동시 호출(수동 게시 버튼 이중
 * 클릭 등)은 여전히 409(wait=false 기본). 내부 호출자(publishSafely·heartbeatTick·릴레이)는 wait=true 로 불러 끝날 때까지
 * 기다렸다 잠금을 원자적으로 잡는다(withPublishLock, 2026-10-02 Task 6 리뷰 C1).
 */
async function publishNow({ heartbeat = false, wait = false } = {}) {
  const r = await withPublishLock(async () => {
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
    const log = new ethers.Contract(LOG_ADDRESS, MODE3_LOG_ABI, ethWallet);
    // V10(§4.3·§4.4) 접수증 대기열 따르기. 로그는 pending 슬롯마다 이번 slotIdx 의 그 슬롯 항목이 **전부** 0 이고 하나 이상
    // 있어야 publish 를 받는다(아니면 PendingRevocationNotApplied — 하트비트까지 막혀 root 가 늙는다). 그래서 스냅샷 전에
    // 읽어 (a) 그 슬롯의 계정을 폐기·은퇴로 돌리고(재발급은 새 슬롯) (b) 백로그에서 그 슬롯의 항목을 걷어 (slot, 0) 하나로
    // 바꾼다 — 앞서 쌓인 0 아닌 항목이 섞여 있으면 거절되기 때문이다. 같은 칸의 중간값은 아직 게시 전이라 최종값 0 만
    // 내도 지갑의 재생 결과가 같다. 계정이 없는 슬롯(정직한 IdP 에선 안 생기지만 체인이 강제한다)도 로컬 트리를 0 으로 맞춰
    // 서명 regRoot 가 실린 항목과 어긋나지 않게 한다.
    const pendingOnChain = (await log.pendingSlots()).map(Number);
    for (const slot of pendingOnChain) {
      const entry = Object.entries(state.accounts).find(([, a]) => a.slot === slot);
      // 2026-10-02 V10 최종 리뷰 I-3: 계정이 이미 slotRetired 면 이 접수증은 지난 계정 폐기의 것이다 — 그 뒤 관리자가 되살렸어도
      // 재발급 전이라 acct.slot 이 아직 옛 슬롯이어서 여기서 찾힌다. 계정은 건드리지 않는다(복구를 조용히 뒤집지 않는다).
      // 로컬 트리 0·(slot, 0) 싣기는 아래에서 그대로 한다 — 체인이 요구하는 것은 그것뿐이고, 재발급은 어차피 새 슬롯이다.
      if (entry && !entry[1].slotRetired) {
        const [uid, a] = entry;
        a.disabled = true; retireActiveCred(uid); a.slotRetired = true;
      }
      registry.set(slot, 0n); delete state.registry.leaves[slot];
      state.registry.pendingSlots = state.registry.pendingSlots.filter((e) => e.index !== slot);
      state.registry.pendingSlots.push({ index: slot, leaf: '0' });
    }
    if (pendingOnChain.length) { console.warn(`[cia] 접수증 대기열 슬롯 ${pendingOnChain.join(',')} 을 0 으로 싣고 은퇴시킨다`); persist(); }
    // V10(2026-10-02 Task 6, Task 5 리뷰 이월) 은퇴 슬롯 방어. 로그는 isRetired 슬롯에 0 아닌 리프를 실으면 SlotIsRetired 로
    // 거절한다 — 그 항목이 백로그에 남아 있는 한 하트비트까지 매번 막혀 root 가 늙는다. 정직한 런타임에선 은퇴 슬롯을 다시
    // 쓰지 않지만(계정 폐기가 로컬에서도 슬롯을 은퇴시킨다) 옛 백업 복원은 은퇴 전의 0 아닌 리프를 되살리고, 기동 대조가 그것을
    // pendingSlots 로 다시 싣는다. 그래서 이번 묶음의 0 아닌 슬롯만(묶음은 작다 — 슬롯당 한 번) isRetired 를 읽어, 은퇴했으면
    // 대기열 따르기와 똑같이 처리한다: 계정 폐기·은퇴 표시, 로컬 트리 0, 그 슬롯 항목을 (slot, 0) 하나로. 은퇴는 접수증(계정
    // 폐기)에서만 생기므로 계정을 폐기 상태로 돌리는 것이 체인과 맞는다.
    const nonZeroSlots = [...new Set(state.registry.pendingSlots.filter((e) => BigInt(e.leaf) !== 0n).map((e) => e.index))];
    const retiredOnChain = [];
    for (const slot of nonZeroSlots) if (await log.isRetired(slot)) retiredOnChain.push(slot);
    for (const slot of retiredOnChain) {
      const entry = Object.entries(state.accounts).find(([, a]) => a.slot === slot);
      if (entry) { const [uid, a] = entry; a.disabled = true; retireActiveCred(uid); a.slotRetired = true; }
      registry.set(slot, 0n); delete state.registry.leaves[slot];
      state.registry.pendingSlots = state.registry.pendingSlots.filter((e) => e.index !== slot);
      state.registry.pendingSlots.push({ index: slot, leaf: '0' });
    }
    if (retiredOnChain.length) { console.warn(`[cia] 체인에서 이미 은퇴한 슬롯 ${retiredOnChain.join(',')} 에 0 아닌 리프가 실려 있어 0 으로 바꿔 싣는다(옛 백업 복원?)`); persist(); }
    const noRev = state.pending.length === 0, noSlots = state.registry.pendingSlots.length === 0;
    if (noRev && noSlots && !heartbeat) return { published: false, heartbeat: false, epoch: state.epoch, root: tree.getRoot().toString(), regRoot: registry.root().toString() };
    const leaves = state.pending.map(rootToBytes32);
    const slots = state.registry.pendingSlots.slice();   // 이번 tx 에 실을 갱신(순서 유지 — 같은 칸의 set→0 도 순서대로 재생돼야 한다)
    const slotIdx = slots.map((s) => s.index), slotLeaves = slots.map((s) => rootToBytes32(s.leaf));
    const revRoot = rootToBytes32(tree.getRoot()), regRoot = rootToBytes32(registry.root());
    // 2026-10-02 V10 최종 리뷰 I-2(a): 서명한 epoch 는 다시 쓰지 않는다. 서명 뒤 게시가 실패하면(채굴 전에 접수증이 끼어
    // PendingRevocationNotApplied 로 revert 등) 그 calldata 의 epoch E 서명이 이미 공개돼 있다 — state.epoch 가 안 올랐다고 E 를
    // 다른 내용으로 다시 서명하면, 누군가 revert 된 쪽을 거울에 먼저 올려 같은 epoch 다른 root 가 된다. 그래서 서명 **전에**
    // signedEpochMax 를 저장하고 그보다 큰 epoch 를 고른다. 컨트랙트는 epoch 증가만 보므로 건너뜀은 허용된다.
    const epoch = Math.max(state.epoch, state.signedEpochMax ?? 0) + 1;
    state.signedEpochMax = epoch;
    persist();
    const sig = await signPublicationV3(ethWallet, { ...(await canonicalParams()), revRoot, regRoot, epoch, revLeaves: leaves, slotIdx, slotLeaves });
    const tx = await log.publish(revRoot, regRoot, epoch, leaves, slotIdx, slotLeaves, sig);
    await tx.wait();
    state.epoch = epoch;
    // V10: 거울 릴레이(Task 6)가 같은 서명을 그대로 올린다 — 거울은 배열 대신 해시 세 개를 받는다.
    state.lastPublication = { revRoot, regRoot, epoch: String(epoch), ...entryHashes({ revLeaves: leaves, slotIdx, slotLeaves }), sig, txHash: tx.hash };
    for (const l of state.pending.slice(0, leaves.length)) await publishedTree.insert(BigInt(l));
    state.pending = state.pending.slice(leaves.length);
    state.registry.pendingSlots = state.registry.pendingSlots.slice(slots.length);
    persist();
    return { published: true, heartbeat: leaves.length === 0 && slots.length === 0, epoch, root: tree.getRoot().toString(), regRoot: registry.root().toString(), txHash: tx.hash, leaves, slots: slots.length };
  }, { wait });
  if (r.published) scheduleRelayAfterPublish();
  return r;
}
/** 2026-10-05 전체 코드 리뷰 3번: 게시 직후 거울 중계. 게시 잠금 **밖에서**(같은 체인 거울 tx 가 그 잠금을 빌리므로 안에서 부르면
 *  교착) 다음 틱에 돌리고 기다리지 않는다 — 발급·폐기 응답을 거울 체인 tx 만큼 늦추지 않게. 뒤처진 거울만 보낸다(behindOnly —
 *  따라잡은 거울을 위해 캐노니컬 하트비트를 새로 만들지 않는다, 9번). 실패는 경고만 — 주기 틱이 다시 본다. */
function scheduleRelayAfterPublish() {
  if (!MIRROR_RELAY_ON_PUBLISH || MIRROR_HEARTBEAT_BLOCKS === 0n || MIRRORS.length === 0) return;
  setImmediate(() => { relayAll({ behindOnly: true }).catch((e) => console.warn(`[cia] 게시 직후 거울 중계 실패(주기 틱이 다시 본다): ${e.message}`)); });
}
app.post('/cia/publish', requireAdmin, async (req, res) => {
  try { res.json(await publishNow()); }
  catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});
/** 하트비트 틱(설계 §4.5): 마지막 게시에서 HEARTBEAT_BLOCKS 이상 지났으면 재게시. pending 이 있으면 그것도 같이 나간다. */
async function heartbeatTick() {
  // 정리는 게시 게이트보다 **앞**이다(최종 리뷰 F2): 게시 중이거나 LOG_ADDRESS 가 없어도 만료 기록은 지워야 한다.
  // 자체 try 로 감싼다 — setInterval 콜백이라 여기서 던지면 unhandled rejection 이다.
  try { await pruneExpiredSessions(); } catch (e) { console.warn(`[cia] 세션 기록 정리 실패: ${e.message}`); }
  if (!LOG_ADDRESS) return;
  // 게시 중이면(publishing) 그냥 return 하지 않는다(2026-10-01 최종 리뷰 A2) — 끝날 때까지 기다린 뒤 아래에서
  // head-last 를 다시 재서 하트비트가 여전히 필요한지 다시 판단한다. 예전에는 여기서 바로 돌아가, 그 사이 끝난
  // 게시가 이미 비운 pending 을 모르고 다음 HEARTBEAT_POLL_MS 를 통째로 날렸다(틱 자체가 막힌 건 아니지만, 한
  // 틱만큼 재게시가 늦어질 수 있었다 — publishSafely 쪽의 진짜 유실과는 결이 다르지만 같은 변수를 쓰므로 함께 고친다).
  await waitPublishing();
  try {
    const log = new ethers.Contract(LOG_ADDRESS, MODE3_LOG_ABI, ethWallet);
    const [head, last] = await Promise.all([ethWallet.provider.getBlockNumber(), log.lastPublishedBlock()]);
    if (BigInt(head) - BigInt(last) < HEARTBEAT_BLOCKS) return;
    const r = await publishNow({ heartbeat: true, wait: true });
    console.log(`[cia] 하트비트 게시: epoch ${r.epoch}, 리프 ${r.leaves.length}개, head ${head}`);
  } catch (e) { console.warn(`[cia] 하트비트 실패: ${e.message}`); }
}

// ---- V10 거울 릴레이(2026-10-02 설계 §5 결정 3) ----
// 거울은 캐노니컬의 마지막 게시(서명 포함)를 그대로 받는다 — 서명이 V3 다이제스트라 같은 서명이 거울에도 유효하다.
// 2026-10-05(전체 코드 리뷰 3·9번): 캐노니컬 게시 직후 뒤처진 거울에 바로 옮기고(scheduleRelayAfterPublish), 주기 틱(H_X 블록,
// 거울 체인 X 기준)은 안전망이다. 거울이 따라잡은 상태면 아무것도 하지 않는다 — 예전에는 H 가 지나면 캐노니컬 하트비트를 새로
// 만들어 옮겨, 캐노니컬 게시가 거울 수·짧은 H 에 비례해 늘었다(데모에서 15초마다 epoch +1). 거울의 신선도는 이제 캐노니컬 정규
// 하트비트(CIA_HEARTBEAT_BLOCKS)가 정한다 — 그 주기(폐기 체인 시간)가 각 응용 체인 MAX_ROOT_AGE(시간)보다 짧아야 한다(스펙 §5).
// 거울은 epoch 단조 증가만 받으므로 새 epoch 가 꼭 필요한 경우(불일치 복구·관리자 강제·게시 기록 없음)에만 하트비트를 만든다.
let MIRRORS = [];   // [{ chainStr, address, provider, contract, sameChain }]
/** 키를 읽고 loadState 가 selfChainId 를 정한 뒤에 부른다. 서명자는 ethWallet 과 같은 키를 거울 체인 provider 에 붙인 것이다.
 *  거울 체인이 캐노니컬 체인과 같으면(데모·테스트의 :8545) provider·서명자를 그대로 쓰고 sameChain 으로 표시한다 —
 *  같은 키·같은 체인이라 게시 tx 와 nonce 가 겹치지 않게 sendMirrorTx 가 publishing 잠금을 빌린다. */
function initMirrors() {
  MIRRORS = MIRROR_SPECS.map(({ chainStr, address }) => {
    const sameChain = chainStr === selfChainId || CHAIN_RPCS.get(chainStr) === RPC_URL;
    const signer = sameChain ? ethWallet : new ethers.Wallet(ethWallet.privateKey, providerFor(chainStr));
    return { chainStr, address, provider: signer.provider, contract: new ethers.Contract(address, MODE3_MIRROR_ABI, signer), sameChain };
  });
}
/** 거울 publish 의 revert 가 EpochNotIncreasing(누군가 이미 같은·더 새 epoch 를 올렸다)인지. ethers v6 가 붙이는 위치가 경우마다
 *  달라(e.revert, e.data, 메시지) 셋 다 본다. */
function isEpochNotIncreasing(m, e) {
  if (e?.revert?.name === 'EpochNotIncreasing') return true;
  try { if (e?.data && m.contract.interface.parseError(e.data)?.name === 'EpochNotIncreasing') return true; } catch { /* 다른 에러 데이터 */ }
  return /EpochNotIncreasing/.test(String(e?.shortMessage ?? '') + ' ' + String(e?.message ?? e));
}
async function sendMirrorTx(m, lp) {
  const send = async () => {
    const tx = await m.contract.publish(lp.revRoot, lp.regRoot, lp.epoch, lp.hLeaves, lp.hIdx, lp.hSlots, lp.sig);
    await tx.wait();
    return tx.hash;
  };
  if (!m.sameChain) return send();
  // 같은 체인·같은 키: 동시에 나간 게시 tx 와 같은 nonce 를 집지 않게 게시 잠금을 잠깐 빌린다(원자 획득·소유자 해제는 withPublishLock).
  return withPublishLock(send, { wait: true });
}
/** 2026-10-02 V10 최종 리뷰 I-2(b): 거울의 (epoch, revRoot, regRoot) 가 IdP 의 게시 기록과 어긋나는가. 거울은 캐노니컬을 앞설 수
 *  없고(IdP 는 서명한 epoch 를 재사용하지 않는다), 같은 epoch 면 root 둘이 같아야 한다. 캐노니컬(체인에서 직접 읽은 값)과
 *  state.lastPublication 둘 다와 대조한다. 거울이 캐노니컬보다 **뒤**인데 root 가 다른 경우(건너뛴 epoch 의 서명)는 기록이 없어
 *  여기서 잡지 못한다 — 그 경우는 '뒤처짐'으로 behindSince 트리거가 H 안에 덮는다. */
function mirrorMismatch(mv, canon) {
  if (mv.epoch > canon.epoch) return true;
  if (mv.epoch === canon.epoch && (mv.revRoot !== canon.revRoot || mv.regRoot !== canon.regRoot)) return true;
  const lp = state.lastPublication;
  return Boolean(lp && BigInt(lp.epoch) === mv.epoch && (BigInt(lp.revRoot) !== mv.revRoot || BigInt(lp.regRoot) !== mv.regRoot));
}
/** 거울 하나와 캐노니컬을 같이 읽는다(릴레이·건강 정보 공용). 값은 전부 bigint. 캐노니컬을 못 읽으면(LOG_ADDRESS 없음·RPC 실패)
 *  canon·mismatch 가 null 이다 — 건강 정보는 거울 값만이라도 내고, 릴레이는 그때 던진다. */
async function readMirrorView(m) {
  const [head, epoch, last, revRoot, regRoot, chain] = await Promise.all([m.provider.getBlockNumber(), m.contract.epoch(), m.contract.lastPublishedBlock(),
    m.contract.revRoot(), m.contract.regRoot(), LOG_ADDRESS ? readChain().catch(() => null) : null]);
  const mv = { head: BigInt(head), epoch: BigInt(epoch), last: BigInt(last), revRoot: BigInt(revRoot), regRoot: BigInt(regRoot) };
  const canon = chain && { epoch: BigInt(chain.onchainEpoch), revRoot: chain.onchainRoot, regRoot: chain.onchainRegRoot };
  return { mv, canon, mismatch: canon ? mirrorMismatch(mv, canon) : null };
}
async function relayMirror(m, { force = false, behindOnly = false } = {}) {
  const { mv, canon, mismatch } = await readMirrorView(m);
  if (!canon) throw new Error('캐노니컬 로그를 읽지 못했다 — 거울 대조 없이 릴레이하지 않는다');
  const out = (epoch, txHash, skipped) => ({ chainId: m.chainStr, epoch: String(epoch), txHash, skipped });
  // 2026-10-02 V10 최종 리뷰 I-1: mv.last(lastPublishedBlock)는 누구나 캐노니컬에 공개된 중간 epoch 서명을 올려 갱신할 수 있다 —
  // 그것만 보면 IdP 릴레이 직전마다 중간 epoch 를 하나씩 올려 폐기 반영을 (중간 epoch 수 + 1)·H 로 늘릴 수 있었다. 그래서 거울마다
  // behindSince(거울이 캐노니컬보다 뒤처진 것을 처음 관측한 거울 체인 블록, 메모리)를 두고, 뒤처져 있으면 그 블록부터 H 가 지나면
  // 갱신한다. 따라잡으면 null. 뒤처지지 않았으면 기존대로 head − last ≥ H 일 때 하트비트(§5 '변화 없어도 주기마다'). 기동 직후처럼
  // 오래 뒤처져 있던 거울은 head − last 쪽이 먼저 걸린다(OR — 그쪽을 리셋해도 behindSince 쪽 상한은 그대로다).
  // I-2(b): 어긋남(mismatch)이면 주기와 무관하게 즉시 덮는다.
  const behind = mv.epoch < canon.epoch;
  if (!behind) m.behindSince = null;
  else m.behindSince ??= mv.head;
  // 2026-10-05(9번): 따라잡은 거울(behind=false)은 주기가 지나도 건드리지 않는다 — 옮길 새 epoch 가 없고, 그것을 만들려고 캐노니컬
  // 하트비트를 올리는 것이 증폭의 원인이었다. 뒤처진 거울은 게시 직후 중계(behindOnly)면 즉시, 주기 틱이면 위 두 상한 중 먼저 오는 쪽.
  const due = force || mismatch || (behind && (behindOnly || mv.head - mv.last >= MIRROR_HEARTBEAT_BLOCKS || mv.head - m.behindSince >= MIRROR_HEARTBEAT_BLOCKS));
  if (!due) return out(mv.epoch, null, true);
  // 거울 epoch 는 IdP 키 서명으로만 오른다 — 거울이 앞서 있으면 그 epoch 는 이미 서명된(소비된) 것이다. 다음 하트비트가 그보다 커야
  // 거울이 받으므로 signedEpochMax 를 끌어올린다(상태 파일이 옛 백업이라 그 서명을 기억하지 못하는 경우까지 덮는다).
  if (mismatch && mv.epoch > BigInt(state.signedEpochMax ?? 0)) { state.signedEpochMax = Number(mv.epoch); persist(); }
  // 올릴 새 epoch 가 없으면(첫 기동·크래시로 lastPublication 이 없음, 거울이 이미 따라잡음, 옛 백업이라 마지막 게시 기록이
  // 체인 epoch 보다 뒤처짐, 거울이 어긋난 서명으로 같거나 앞선 epoch 에 있음) 캐노니컬 하트비트를 먼저 올린다. 진행 중인 게시가
  // 끝나면 다시 판단한다 — 그 게시가 새 epoch 를 줬을 수 있다.
  const stale = () => !state.lastPublication || BigInt(state.lastPublication.epoch) <= mv.epoch || Number(state.lastPublication.epoch) !== state.epoch;
  if (stale()) {
    await waitPublishing();   // 최적화: 진행 중인 게시가 새 epoch 를 줬으면 하트비트를 건너뛴다(획득은 아래 wait:true 가 원자적으로)
    if (stale()) await publishNow({ heartbeat: true, wait: true });
  }
  const lp = state.lastPublication;
  try {
    const txHash = await sendMirrorTx(m, lp);
    m.behindSince = null;
    return out(lp.epoch, txHash, false);
  } catch (e) {
    if (isEpochNotIncreasing(m, e)) return out(lp.epoch, null, true);   // 다른 릴레이어가 먼저 올렸다 — 이미 갱신됨(§5). 어긋났다면 다음 틱이 다시 본다
    throw e;
  }
}
// 릴레이는 한 번에 하나(틱끼리, 틱과 관리자 relay 사이) — 같은 거울에 같은 epoch 를 두 번 보내지 않게.
let relaying = null;
async function relayAll({ force = false, behindOnly = false } = {}) {
  while (relaying) { try { await relaying; } catch { /* */ } }
  relaying = (async () => {
    const res = [];
    for (const m of MIRRORS) {
      try { res.push(await relayMirror(m, { force, behindOnly })); }
      catch (e) {
        console.warn(`[cia] 거울 ${m.chainStr}(${m.address}) 릴레이 실패: ${e.message}`);
        res.push({ chainId: m.chainStr, epoch: null, txHash: null, skipped: false, error: e.message });
      }
    }
    return res;
  })();
  try { return await relaying; } finally { relaying = null; }
}
/** 주기 틱 — setInterval 콜백이라 절대 던지지 않는다. 앞 틱(또는 관리자 relay)이 아직 돌면 이번 틱은 건너뛴다. */
async function relayTick() {
  if (!LOG_ADDRESS || MIRRORS.length === 0 || relaying) return;
  try { await relayAll(); } catch (e) { console.warn(`[cia] 거울 릴레이 틱 실패: ${e.message}`); }
}
// 테스트·데모용: 주기를 무시하고 모든 거울을 지금 갱신한다. 거울 하나라도 실패하면 502(나머지 결과는 그대로 싣는다).
// 주의: 거울이 이미 캐노니컬 epoch 를 따라잡았으면 force 는 캐노니컬 하트비트를 하나 더 올린다 — 캐노니컬 체인의 블록·epoch
// 하나와 가스를 쓴다(거울은 같은 epoch 를 두 번 받지 않으므로). 운영 경로가 아니라 데모·관리자용이다.
app.post('/cia/admin/relay', requireAdmin, async (req, res) => {
  if (!LOG_ADDRESS) return res.status(503).json({ error: 'CIA_LOG_ADDRESS not configured' });
  try {
    const mirrors = await relayAll({ force: true });
    res.status(mirrors.some((m) => m.error) ? 502 : 200).json({ mirrors });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});
/** 건강 정보용 거울 읽기. 실패한 거울은 빼지 않고 null 로 낸다 — "거울이 안 보인다" 자체가 알려야 할 상태다. */
async function readMirrorsHealth() {
  return Promise.all(MIRRORS.map(async (m) => {
    try {
      const { mv, mismatch } = await bounded(readMirrorView(m), 1200);   // mismatch: 2026-10-02 V10 최종 리뷰 I-2(b)
      return { chainId: m.chainStr, address: m.address, epoch: mv.epoch.toString(), lastPublishedBlock: mv.last.toString(), rootAge: Number(mv.head - mv.last), behind: state.epoch - Number(mv.epoch), mismatch };
    } catch {
      return { chainId: m.chainStr, address: m.address, epoch: null, lastPublishedBlock: null, rootAge: null, behind: null, mismatch: null };
    }
  }));
}

/** V8: 만료된 세션 기록 삭제(리프는 남는다 — 설계 §6). 체인별 head 는 한 번만 읽는다.
 *  head 는 계정 순회 **전에** 모두 읽는다(2026-09-25 리뷰 I-1): 순회 안에서 await 하면 그 사이 /cia/issue 가
 *  acct.sessions 를 새 배열로 갈아끼우고, 재개한 정리가 옛 배열로 만든 keep 을 대입해 방금 발급된 기록을 덮어썼다.
 *  그러면 그 세션은 404 unknown_session 이라 개별 폐기가 영영 안 된다. 아래 순회는 await 이 하나도 없어 원자적이다. */
async function pruneExpiredSessions() {
  const chainIds = new Set();
  for (const acct of Object.values(state.accounts)) for (const s of acct.sessions ?? []) chainIds.add(s.chainid);
  if (chainIds.size === 0) return;
  const heads = {};
  for (const id of chainIds) { try { heads[id] = await headOf(id); } catch { heads[id] = null; } }
  // ↓ 여기부터 await 없음 — 이벤트 루프가 끼어들지 못한다. 그 사이 새로 생긴 체인의 기록은 heads 에 없어(undefined) 그대로 남는다.
  let dropped = 0;
  for (const acct of Object.values(state.accounts)) {
    if (!acct.sessions?.length) continue;
    const keep = acct.sessions.filter((s) => {
      const h = heads[s.chainid];
      const gone = h !== null && h !== undefined && h > BigInt(s.max_height);
      if (gone) dropped++;
      return !gone;
    });
    if (keep.length !== acct.sessions.length) acct.sessions = keep;
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

// 관리자 계정 목록(관리 페이지의 계정 목록용). activeCred 는 위의 기존 헬퍼(사용자당 활성 자격증명 하나).
app.get('/cia/accounts', requireAdmin, (req, res) => res.json({
  accounts: Object.entries(state.accounts).map(([uid, a]) => ({ uid, disabled: a.disabled, activeCf_u: activeCfU(a), slot: a.slot, tampered: Boolean(a.tampered), registryLeaf: state.registry.leaves[a.slot] ?? '0', provider: a.provider ?? 'demo' })),
}));

// ---- V9 등록부 관리(설계 2026-10-01 §9) ----
app.get('/cia/admin/registry', requireAdmin, (req, res) => {
  const byIndex = new Map(Object.entries(state.accounts).map(([uid, a]) => [a.slot, { uid, a }]));
  const pendingIdx = new Set(state.registry.pendingSlots.map((e) => e.index));
  const slots = registry.entries().map(([index, leaf]) => {
    const e = byIndex.get(index);
    const cred = e ? activeCred(e.uid) : null;
    // 관리자 화면 "사용자 자격증명 활성 목록"(2026-10-14): 활성 C_u 의 Cf_u·발급 시각·disabled·게시 대기 여부를 함께 준다. 값은 모두 공개 부분이다.
    return { index, uid: e?.uid ?? null, leaf: leaf.toString(), tampered: Boolean(e?.a.tampered), active: Boolean(cred),
      Cf_u: cred?.Cf_u ?? null, issuedAt: cred?.issuedAt ?? null, disabled: Boolean(e?.a.disabled), pending: pendingIdx.has(index) };
  });
  res.json({ depth: registry.depth, next: state.registry.next, regRoot: registry.root().toString(), epoch: state.epoch, pendingSlots: state.registry.pendingSlots.length, slots });
});
/** 관리자 화면 "세션 폐기 목록"(2026-10-14): 폐기된(revokedAt 있는) 세션만 계정 전체에서 모은다. 세션 리프 Poseidon(5, Cf_s) 와
 *  게시 여부(pending = 아직 체인에 안 올라감)를 함께 준다. auid_s·arid_s 는 기록에 없으므로(D1) 여기에도 없다. */
app.get('/cia/admin/revoked_sessions', requireAdmin, async (req, res) => {
  const pendingLeaves = new Set(state.pending);
  const out = [];
  for (const [uid, a] of Object.entries(state.accounts)) {
    for (const s of a.sessions ?? []) {
      if (!s.revokedAt) continue;
      const bound = s.bound ?? '0';   // 하위호환: bound 가 없는 옛 레코드는 0(전부 차단)으로 본다
      const leaf = (await sessionLeaf(BigInt(s.Cf_s), BigInt(bound))).toString();
      out.push({ uid, Cf_s: s.Cf_s, chainid: s.chainid, max_height: s.max_height, allowAgent: s.allowAgent, issuedAt: s.issuedAt, revokedAt: s.revokedAt, bound, leaf, pending: pendingLeaves.has(leaf) });
    }
  }
  out.sort((x, y) => String(y.revokedAt).localeCompare(String(x.revokedAt)));
  res.json({ sessions: out, pendingCount: state.pending.length, leafCount: state.revoked.length });
});
/** 시연: "장부를 속이는 AA" — 활성 자격증명은 그대로 두고 슬롯에 가짜 리프를 게시한다. 지갑의 등록부 확인이 ✗ 가 되고 로그인이 막힌다. */
app.post('/cia/admin/registry/tamper', requireAdmin, async (req, res) => {
  try {
    const { uid } = req.body ?? {};
    const acct = state.accounts[uid];
    if (!isDec(uid) || !acct) return res.status(404).json({ error: 'unknown account' });
    if (!activeCred(uid)) return res.status(409).json({ error: 'no_active_credential' });
    const fake = (await registryLeaf(BigInt(acct.auid), randomScalar())).toString();
    setSlot(uid, fake); acct.tampered = true; persist();
    const pub = await publishSafely();
    res.json({ slot: acct.slot, leaf: fake, regRoot: registry.root().toString(), published: Boolean(pub.published) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/cia/admin/registry/restore', requireAdmin, async (req, res) => {
  try {
    const { uid } = req.body ?? {};
    const acct = state.accounts[uid];
    if (!isDec(uid) || !acct) return res.status(404).json({ error: 'unknown account' });
    const cur = activeCred(uid);
    const leaf = cur ? (await registryLeaf(BigInt(acct.auid), BigInt(cur.Cf_u))).toString() : '0';
    setSlot(uid, leaf); acct.tampered = false; persist();
    const pub = await publishSafely();
    res.json({ slot: acct.slot, leaf, regRoot: registry.root().toString(), published: Boolean(pub.published) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// §6.5.1 사용자 개시 폐기. 인증은 계정 비밀번호다 — 지갑 키가 아니다. 장치를 잃은 사용자에게 sk_u 는 없고
// 공격자에게는 있으므로, 인증 수단은 장치 밖에 있어야 한다. 처리는 관리자의 계정 폐기와 같다.
// 형식 → 비밀번호 → 등록 상태 순으로 검사한다. 비밀번호가 틀리면 등록 여부를 알려주지 않는다.
// Google 계정은 비밀번호 대신 폐기용 nonce("revoke:…")의 id_token 으로 인증한다(OIDC 래퍼 2026-10-16) — 검증된 토큰 보유자에게는 미등록이면 404 로 알린다.
app.post('/cia/account/self_revoke', userCors, async (req, res) => {
  try {
    const { uid: uidIn, pwd, id_token } = req.body ?? {};
    let uid;
    if (id_token !== undefined) {
      if (typeof id_token !== 'string') return res.status(400).json({ error: 'id_token 은 문자열' });
      const o = await oidcUid(id_token, REVOKE_PREFIX); if (o.error) return res.status(o.error.status).json(o.error.body);
      if (!isRevokeNonce(o.nonce)) return res.status(400).json({ error: 'oidc_nonce_mismatch', reason: 'oidc_nonce_mismatch', detail: 'nonce 가 폐기용이 아니다' });
      uid = o.uid;
    } else {
      if (!isDec(uidIn) || typeof pwd !== 'string') return res.status(400).json({ error: 'uid, pwd required' });
      if (!pwOk(state.accounts[uidIn], pwd)) return res.status(401).json({ error: 'invalid credentials' });
      uid = uidIn;
    }
    // Task 10(B1): 가입만 하고 등록 전인 계정(pk_u:null)도 "미등록" — self_revoke 는 등록된 자격증명이 있어야 뜻이 있다
    // (registerAccount 의 "이미 등록됨" 판정과 같은 기준).
    if (!state.accounts[uid]?.pk_u) return res.status(404).json({ error: 'unknown account' });
    // revokeAccount 안에서 disabled 가 동기적으로(await 전에) 걸린다(설계 §6.5.1) — 재발급 차단은 트리·게시와 분리된
    // 별개의 효력이다. 슬롯은 체인을 읽지 않고 활성 사용자 자격증명 하나에서 나오므로(2026-09-21 §3.6) 체인이 죽어 있어도 걸린다.
    const r = await revokeAccount(uid);
    res.json(r);
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// ---- §6(2026-09-16) 승인된 개봉 ----
// 요청: RP 가 트랜스크립트(공개 입력 14개 + π)와 자기 부분 복호 D_svc 를 RP 서명키로 서명해 낸다. IdP 는 서명·신선도·
// arid·pk_trace·Groth16 을 검증하고 pending 으로 둔다 — 트랜스크립트 검증이 없으면 RP 가 임의 암호문을 내 IdP 를 복호
// 오라클로 쓸 수 있고, arid 대조가 없으면 유출된 남의 로그로 연다. 승인 시점에야 IdP 조각을 더해 uid 를 계산한다.
let vkeyP = null;
function loadVkey() {
  return (vkeyP ??= (async () => JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8')))().catch((e) => { vkeyP = null; throw e; }));
}
const findOpening = (id) => state.openings.find((o) => o.id === id);
/** 같은 트랜스크립트의 재요청을 알아보는 열쇠 — (arid, c1, c2, PPID) 의 해시. 복호 재료를 지운 뒤에도 남길 수 있다(§6 감사 기록). */
const openingTagKey = (arid, c1x, c1y, c2, PPID) => createHash('sha256').update([arid, c1x, c1y, c2, PPID].join('|')).digest('hex');
/** 결정이 끝난 항목에서 복호 재료를 지운다(2026-09-25 리뷰 B-4): D_svc·c1·c2 는 결정 뒤 쓸 일이 없는데 x_AA 와 같은
 *  파일에 남아 있으면 거절한 요청까지 나중에 열 수 있는 재료가 된다. 감사 기록(arid·PPID·uid·resolved·시각·allowAgent·
 *  max_height·chainid)과 대조용 tagKey 는 남긴다. */
function forgetOpeningShards(o) { delete o.D_svc; delete o.c1; delete o.c2; }
app.post('/cia/open/request', async (req, res) => {
  try {
    const { arid, publicSignals, proof, D_svc, ts, sig } = req.body ?? {};
    // V11: 공개 입력 34(COUNTER 포함, 2026-10-22) — 태그는 [12..14] 그대로
    if (!isDec(arid) || !Array.isArray(publicSignals) || publicSignals.length !== PUB_INDEX.COUNT || !publicSignals.every(isDec) || !proof || !isPt(D_svc) || !isDec(ts) || typeof sig !== 'string') {
      return res.status(400).json({ error: `arid, publicSignals[${PUB_INDEX.COUNT}], proof, D_svc{x,y}, ts, sig required` });
    }
    if (!(await isTracePoint(pointFromStrings(D_svc)))) return res.status(400).json({ error: 'D_svc is not a valid subgroup point' });
    const e = state.rps[arid];
    if (!e) return res.status(404).json({ error: 'unknown_service' });
    if (e.status !== 'approved' || !e.pk_service || !e.pk_trace) return res.status(403).json({ error: 'not_approved' });
    if (!isFreshTs(ts)) return res.status(401).json({ error: 'stale' });
    // 정규 10진으로 맞춘다(앞자리 0 허용 입력 대비 — 서명 메시지·문자열 비교·저장 전부 정규형 위에서, 2026-09-18 점검 1).
    const ps = publicSignals.map((v) => BigInt(v).toString());
    const [PPID, aridIn, , max_height, chainIn, allowAgent, , , ciaX, ciaY, traceX, traceY, c1x, c1y, c2] = ps;
    if (recoverSigner(openRequestMessage({ arid, PPID, c1: { x: c1x, y: c1y }, D_svc, ts }), sig) !== e.pk_service) return res.status(401).json({ error: 'bad_signature' });
    if (aridIn !== arid) return res.status(403).json({ error: 'wrong_arid' });
    const pk = S(ciaPub);
    if (ciaX !== pk.x || ciaY !== pk.y) return res.status(403).json({ error: 'untrusted_cia' });
    if (traceX !== e.pk_trace.x || traceY !== e.pk_trace.y) return res.status(403).json({ error: 'wrong_trace_key' });
    if (!CHAIN_RPCS.has(BigInt(chainIn).toString())) return res.status(403).json({ error: 'wrong_chain' });
    if (BigInt(allowAgent) > 1n) return res.status(403).json({ error: 'bad_allow_agent' });
    if (c1x === '0' && c1y === '1') return res.status(403).json({ error: 'bad_tag' });   // r = 0 — RP·컨트랙트와 같은 규칙(심층 방어)
    let vkey;
    try { vkey = await loadVkey(); } catch (err) { console.error(`[cia] pi_cred vkey 를 읽지 못했다: ${err.message}`); return res.status(503).json({ error: 'vkey unavailable', reason: 'vkey_unavailable' }); }   // 경로·errno 는 로그에만(리뷰 S4 와 같은 원칙)
    let ok = false;
    try { ok = await snarkjs.groth16.verify(vkey, ps, proof); }
    catch (err) { console.warn('[cia] 개봉 요청의 증명 검증 예외 — vkey/회로 불일치일 수 있다: ' + err.message); ok = false; }
    if (!ok) return res.status(403).json({ error: 'bad_proof' });
    // pending 이거나, approved 지만 uid 를 찾은(resolved:true) 경우는 같은 (arid, c1) 의 결정이 이미 있거나
    // 진행 중이라 그 id 를 돌려준다. denied 와 approved+resolved:false(틀린 D_svc — RP 자신의 요청만 망친다,
    // §6.2)는 새 요청을 허용한다 — 거절된 세션을 다시 심사에 올리거나 RP 가 D_svc 를 고쳐 다시 낼 길이
    // 있어야 한다. arid 대조가 없으면 유출된 남의 로그로 연다.
    // dup 키는 (arid, c1, c2, PPID) — c1 = r·B8 은 사용자와 무관해 두 사용자가 같은 r 을 쓰면 겹친다(2026-09-23 점검 A-I1).
    // c2·PPID 까지 같아야 "같은 트랜스크립트"다. 아니면 뒤 요청이 앞 사용자의 승인 항목을 받아 uid 가 오귀속된다.
    // 결정된 항목에서는 c1·c2 를 지우므로(2026-09-25 리뷰 B-4) 대조는 요청 때 박아 둔 tagKey(그 넷의 해시)로 한다.
    // tagKey 는 복호에 쓸 수 없다. tagKey 가 없는 옛 항목은 예전처럼 원본 값으로 본다.
    const tagKey = openingTagKey(arid, c1x, c1y, c2, PPID);
    const dup = state.openings.find((o) => (o.tagKey ? o.tagKey === tagKey
      : (o.arid === arid && o.c1?.x === c1x && o.c1?.y === c1y && o.c2 === c2 && o.PPID === PPID))
      && (o.status === 'pending' || (o.status === 'approved' && o.resolved !== false)));
    if (dup) return res.status(200).json({ id: dup.id, status: dup.status });
    const id = randomBytes(32).toString('hex');
    state.openings.push({ id, arid, PPID, tagKey, c1: { x: c1x, y: c1y }, c2, D_svc: { x: D_svc.x, y: D_svc.y }, allowAgent, max_height, chainid: chainIn, status: 'pending', requestedAt: new Date().toISOString(), decidedAt: null, uid: null, resolved: null });
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
    // 평문은 Poseidon(uid, arid)(2026-09-18 §3.4) — 등록부의 uid 마다 계산해 되찾는다. 못 찾으면 D_svc 가 틀렸거나(RP 자신의
    // 요청만 망친다) 계정이 등록부에 없는 것이다. 어느 쪽이든 approved 로 기록하되 resolved=false 로 남긴다(§6.2).
    const uid = await resolveTagPlaintext(h, BigInt(o.arid), Object.keys(state.accounts));
    o.decidedAt = new Date().toISOString();
    o.status = 'approved'; o.uid = uid; o.resolved = uid !== null;
    forgetOpeningShards(o);
    persist();
    res.json({ id: o.id, status: o.status, resolved: o.resolved });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/cia/openings/:id/deny', requireAdmin, (req, res) => {
  const o = findOpening(req.params.id);
  if (!o) return res.status(404).json({ error: 'unknown opening' });
  if (o.status !== 'pending') return res.status(409).json({ error: `already ${o.status}` });
  o.status = 'denied'; o.decidedAt = new Date().toISOString(); forgetOpeningShards(o); persist();
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
  res.json({ root: tree.getRoot().toString(), epoch: state.epoch, pendingCount: state.pending.length, leafCount: state.revoked.length, credCount, head,
    regRoot: registry.root().toString(), registrySlots: registry.entries().length, pendingSlots: state.registry.pendingSlots.length });
});

// ---- 기동 ----
eddsa = await buildEddsa();
poseidon = await buildPoseidon();
F = poseidon.F;
loadOrCreateKeys();
await loadState();
initMirrors();
if (HEARTBEAT_BLOCKS > 0n) {
  const hb = setInterval(heartbeatTick, HEARTBEAT_POLL_MS);
  hb.unref();
}
if (MIRRORS.length && MIRROR_HEARTBEAT_BLOCKS > 0n) setInterval(relayTick, MIRROR_POLL_MS).unref();
scheduleRelayAfterPublish();   // 기동 게시(loadState 의 대조·자동 게시)는 initMirrors 전이라 중계되지 않았다 — 뒤처졌으면 지금 옮긴다
// RP·지갑 에이전트와 같이 루프백에만 묶는다 — 관리자·사용자 페이지와 발급 경로를 LAN 에 노출하지 않는다.
// 라우트 밖으로 샌 오류의 마지막 그물(2026-10-11): 본문 JSON 파싱 실패는 400, 그 밖은 500 — HTML 기본 페이지 대신 다른 라우트와 같은
// { error } 봉투. 처리되지 않은 rejection(백그라운드 루프 등)은 기록만 하고 프로세스를 살려 둔다 — 하트비트·중계가 멈추는 쪽이 더 나쁘다.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: 'malformed' });
  console.error(`[cia] 처리되지 않은 라우트 오류 ${req.method} ${req.path}: ${err?.stack ?? err}`);
  res.status(500).json({ error: 'internal' });
});
process.on('unhandledRejection', (e) => console.error(`[cia] unhandledRejection: ${e?.stack ?? e}`));
app.listen(PORT, BIND_HOST, () => {
  if (ADMIN_OPEN) console.warn('[cia] CIA_ADMIN_OPEN=1 — 관리자 인증이 꺼져 있다(데모 전용). 이 IdP 에 닿는 누구나 RP 승인·폐기·개봉 승인을 할 수 있다.');
  console.log(`Mode 3 IdP running at http://${BIND_HOST}:${PORT} (log=${LOG_ADDRESS ?? 'none'}, heartbeat=${HEARTBEAT_BLOCKS}, mirrors=${MIRRORS.map((m) => m.chainStr).join(',') || 'none'}(H=${MIRROR_HEARTBEAT_BLOCKS}, relayOnPublish=${MIRROR_RELAY_ON_PUBLISH && MIRROR_HEARTBEAT_BLOCKS > 0n}), chains=${[...CHAIN_RPCS.keys()].join(',') || 'none'}, vkey=${fs.existsSync(VKEY_PATH) ? 'ok' : 'missing'}, idpVkey=${fs.existsSync(IDP_VKEY) ? 'ok' : 'missing'}, registry=${registry.entries().length})`);
});
