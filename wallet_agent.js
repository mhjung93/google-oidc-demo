import express from 'express';
import cors from 'cors';
import * as snarkjs from 'snarkjs';
import { buildPoseidon, buildEddsa } from 'circomlibjs';
import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { webcrypto, createHash, randomBytes } from 'crypto';
import http from 'http';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256, AbiCoder, Interface } from 'ethers';
import { createIMT, leafValue, TAG_SESSION, TAG_ACCOUNT } from './lib/imt.js';

const { subtle } = webcrypto;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.WALLET_AGENT_PORT || 5001;
const RP_ORIGIN = process.env.RP_ORIGIN || 'http://127.0.0.1:3000';
const IDP_ORIGIN = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';
const MODE2_ETH_RPC_URL = process.env.MODE2_ETH_RPC_URL || process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';
// B1 트랜잭션 제출(post-login) 대상 PPIDWalletFactory 주소. 지금까지는 이 정보를 아는
// 컴포넌트가 없었다(검증 스크립트가 임시로 수동 배포/전달했음) — 실제 온체인 제출을
// 하려면 이 값이 반드시 필요하다.
const PPID_WALLET_FACTORY_ADDRESS = process.env.PPID_WALLET_FACTORY_ADDRESS;
// 지갑이 증명에 쓰려는 폐기 root가 실제로 온체인에 게시돼 있는지 직접 확인하기 위한
// RevocationRegistry 주소. 이게 없으면 지갑은 게시 여부를 알 수 없어, 아직 게시되지
// 않은 root로 증명했다가 PPIDWallet.execute()에서 정체불명의 StaleRevocationRoot
// revert를 맞는다(무고한 사용자 포함).
const REVOCATION_REGISTRY_ADDRESS = process.env.REVOCATION_REGISTRY_ADDRESS;

const PPID_WALLET_FACTORY_ABI = [
  'function computeAddress(uint256 ppid) view returns (address)',
  'function deploy(uint256 ppid) returns (address)',
];
const PPID_WALLET_ABI = [
  'function execute((address to, uint256 value, bytes data, uint256 nonce) payload, bytes sig, uint[2] proofA, uint[2][2] proofB, uint[2] proofC, uint256 pk_i, uint256 pk_IdP_x, uint256 pk_IdP_y, uint256 max_height, bytes32 revocationRoot) returns (bool ok)',
  'function nonce() view returns (uint256)',
];
const REVOCATION_REGISTRY_ABI = [
  'function isRecentRoot(bytes32 root) view returns (bool)',
  'function filled() view returns (uint256)',
];
const factoryInterface = new Interface(PPID_WALLET_FACTORY_ABI);
const walletInterface = new Interface(PPID_WALLET_ABI);
const registryInterface = new Interface(REVOCATION_REGISTRY_ABI);
const STATE_FILE = path.join(__dirname, 'wallet_state.json');
let poseidon = null;
let eddsa = null;
async function ensureEdDSA() {
  if (!eddsa) eddsa = await buildEddsa();
  return eddsa;
}

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const TOKEN_VALIDITY_SECONDS = 3600n;
const ETHEREUM_SLOT_SECONDS = 12n;
// Demo-only fixture for the prior verified Wallet-IdP account binding.
// Production deployments must populate this value through an authenticated enrollment flow.
const DEMO_BOUND_UID = '12345';

// client.js의 valueToField()/bytesToHex()와 동일한 필드 축소 규칙.
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function valueToField(value) {
  if (typeof value === 'bigint') return value % FIELD_PRIME;
  if (typeof value === 'number') return BigInt(value) % FIELD_PRIME;
  const str = String(value);
  if (str.startsWith('0x')) return BigInt(str) % FIELD_PRIME;
  if (/^[0-9]+$/.test(str)) return BigInt(str) % FIELD_PRIME;
  const bytes = new TextEncoder().encode(str);
  const hex = bytesToHex(bytes);
  return BigInt(`0x${hex || '0'}`) % FIELD_PRIME;
}

function validityWindowBlocks() {
  return (TOKEN_VALIDITY_SECONDS + ETHEREUM_SLOT_SECONDS - 1n) / ETHEREUM_SLOT_SECONDS;
}

// pi_pk_i 증명의 첫 생성은 BN128 커브 WASM 초기화 + V8 JIT 웜업 비용 때문에 느리다
// (실측 ~700ms, warm 상태 대비 3배 이상). 파일 I/O는 원인이 아님을 별도로 확인했다
// (OS 페이지 캐시를 미리 채워도 1회차는 여전히 느림). 한 번만 워밍업하면 V8 JIT이
// 완전히 최적화되기 전이라 그다음 2~3회까지도 다소 느린 게 실측으로 확인돼서,
// WARMUP_RUNS번 반복 실행해서 완전히 안정화(~230ms대)된 뒤에 서버가 리슨을
// 시작하게 한다. Poseidon/EdDSA를 기동 시점에 미리 빌드해두는 것과 같은 이유/같은
// 패턴이다.
const PI_PK_I_WARMUP_RUNS = 4;

// 회로가 Task 7 이전 버전(pi_pk_i 13-field)에서 revocation non-membership
// 검증(uid/rid/salt + sess_*/acct_* witness)을 추가한 버전으로 바뀌면서, 웜업
// 입력도 새 회로 시그니처에 맞춰야 한다 — 빈 IMT(20)에 대한 witness는 두 target
// 모두 자명하게 비멤버이므로 웜업용으로 충분하다(실제 폐기 상태를 반영할 필요 없음).
async function buildWarmupPiPkIInput(index) {
  const F = eddsa.F;
  const sk_dummy = webcrypto.getRandomValues(new Uint8Array(32));
  const pk_dummy = eddsa.prv2pub(sk_dummy);

  const rp_nonce = valueToField(`warmup-rp-nonce-${index}`);
  const rid = valueToField('warmup-rid');
  const uid = valueToField('warmup-uid');
  const salt = valueToField('warmup-salt');
  const pk_i = valueToField(`0x04deadbeef${index}`);
  const max_height = valueToField('1000');
  const chain_id = valueToField('1337');

  const PPID = poseidon.F.toObject(poseidon([uid, rid, salt]));
  const arid_i = (rid * rp_nonce) % FIELD_PRIME;
  const auid_i = (PPID * rp_nonce) % FIELD_PRIME;
  const r_token = poseidon.F.toObject(poseidon([pk_i, max_height, rp_nonce]));
  const auid = poseidon.F.toObject(poseidon([uid, salt]));

  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const msg = poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id]);
  const sig = eddsa.signPoseidon(sk_dummy, msg);

  const tree = await createIMT(20);
  const sessTarget = await leafValue(TAG_SESSION, r_token.toString());
  const acctTarget = await leafValue(TAG_ACCOUNT, auid.toString());
  const sessWitness = await tree.getNonMembershipWitness(sessTarget);
  const acctWitness = await tree.getNonMembershipWitness(acctTarget);

  return {
    rp_nonce: rp_nonce.toString(),
    arid_i: arid_i.toString(),
    auid_i: auid_i.toString(),
    r_token: r_token.toString(),
    chain_id: chain_id.toString(),
    S: sig.S.toString(),
    R8x: F.toObject(sig.R8[0]).toString(),
    R8y: F.toObject(sig.R8[1]).toString(),
    uid: uid.toString(),
    rid: rid.toString(),
    salt: salt.toString(),
    sess_lowValue: sessWitness.lowValue,
    sess_lowNextValue: sessWitness.lowNextValue,
    sess_pathElements: sessWitness.pathElements,
    sess_pathIndices: sessWitness.pathIndices,
    acct_lowValue: acctWitness.lowValue,
    acct_lowNextValue: acctWitness.lowNextValue,
    acct_pathElements: acctWitness.pathElements,
    acct_pathIndices: acctWitness.pathIndices,
    pk_i: pk_i.toString(),
    pk_IdP_x: F.toObject(pk_dummy[0]).toString(),
    pk_IdP_y: F.toObject(pk_dummy[1]).toString(),
    PPID: PPID.toString(),
    max_height: max_height.toString(),
    revocationRoot: sessWitness.root,
  };
}

async function warmUpPiPkI() {
  for (let i = 0; i < PI_PK_I_WARMUP_RUNS; i++) {
    const runStart = now();
    await snarkjs.groth16.fullProve(
      await buildWarmupPiPkIInput(i),
      'build/mode2/pi_pk_i_js/pi_pk_i.wasm',
      'build/mode2/pi_pk_i_final.zkey',
    );
    console.log(`[WalletAgent] pi_pk_i warm-up run ${i + 1}/${PI_PK_I_WARMUP_RUNS}: ${now() - runStart}ms`);
  }
}

async function rpcCall(method, params = []) {
  const response = await fetch(MODE2_ETH_RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method,
      params,
    }),
  });

  if (!response.ok) {
    throw new Error(`${method} RPC failed with status ${response.status}`);
  }

  const data = await response.json();
  if (data.error || typeof data.result !== 'string') {
    throw new Error(data.error?.message || `${method} RPC returned no result`);
  }
  return data.result;
}

// rpcCall()과 같은 패턴이지만, eth_getBlockByNumber(전체 트랜잭션 포함)처럼 결과가
// 문자열이 아닌 객체인 RPC 메서드도 다뤄야 해서 결과 타입을 강제하지 않는다.
async function rpcCallGeneric(method, params = []) {
  const response = await fetch(MODE2_ETH_RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (!response.ok) {
    throw new Error(`${method} RPC failed with status ${response.status}`);
  }
  const data = await response.json();
  if (data.error) {
    throw new Error(data.error.message || `${method} RPC returned an error`);
  }
  return data.result;
}

async function getMaxHeight() {
  const chainIdHex = await rpcCall('eth_chainId');
  const blockHex = await rpcCall('eth_blockNumber');
  const currentBlock = BigInt(blockHex);
  return {
    chainId: BigInt(chainIdHex).toString(),
    currentBlock,
    maxHeight: currentBlock + validityWindowBlocks(),
    source: MODE2_ETH_RPC_URL,
  };
}

// custom_idp.js의 psSign() / server.js의 PS 서명 검증식과 동일하다.
// wallet_agent.js가 RP로부터 받은 rid가 정말 이 IdP가 EdDSA-Poseidon으로
// Poseidon(['RP_REG', rid, origin])에 서명해서 발급한 값인지 확인한다(예전엔 PS
// 서명이었으나, pi_arid_i 회로 안에서 같은 서명을 검증해야 해서 EdDSA-Poseidon으로
// 전환 — PS는 페어링 연산이라 circom 회로 안에서 검증하기엔 너무 무거움).
// origin이 서명 대상에 포함돼 있으므로, 서명 검증을 통과했다면 "이 rid는 이
// origin 것"이라는 것까지 IdP가 보증한 것이다. verifyRpCredential이 이어서 그
// 서명된 origin을 wallet_agent.js 자신의 신뢰 앵커인 RP_ORIGIN과 대조해서, RP
// FE(client.js)가 다른(피해자) RP의 정상 발급 rid를 몰래 끼워 넣는 것(A7,
// blind-message attack)을 막는다.
let idpPublicKeysCache = null;
async function getIdpPublicKeys() {
  if (idpPublicKeysCache) return idpPublicKeysCache;
  const response = await fetch(`${IDP_ORIGIN}/ps_public_keys`);
  if (!response.ok) throw new Error(`Failed to fetch IdP public keys (${response.status})`);
  idpPublicKeysCache = await response.json();
  return idpPublicKeysCache;
}

// IdP가 공개한 폐기 목록으로 로컬 트리를 재구성해 자기 witness를 계산한다.
// 리프가 해시라 목록을 받아도 남의 값을 알 수 없다.
async function fetchRevocationWitnesses(rTokenField, auidField) {
  const res = await fetch(`${IDP_ORIGIN}/idp/revocation_state`);
  if (!res.ok) throw new Error(`revocation_state failed: ${res.status}`);
  const { root, revokedLeaves } = await res.json();

  const tree = await createIMT(20);
  for (const leaf of revokedLeaves) await tree.insert(BigInt(leaf));

  const localRoot = tree.getRoot().toString();
  if (localRoot !== root) {
    throw new Error(`local revocation tree root ${localRoot} != IdP root ${root}`);
  }

  const sessTarget = await leafValue(TAG_SESSION, rTokenField);
  const acctTarget = await leafValue(TAG_ACCOUNT, auidField);
  return {
    root,
    sess: await tree.getNonMembershipWitness(sessTarget),
    acct: await tree.getNonMembershipWitness(acctTarget),
  };
}

// PPIDWallet.execute()의 revocationRoot 파라미터와 RevocationRegistry는 bytes32를
// 쓰고, 회로/IdP 쪽 root는 필드 요소(10진 문자열)다. 경계에서만 변환한다.
function revocationRootToBytes32(root) {
  return '0x' + BigInt(root).toString(16).padStart(64, '0');
}

// 이 root가 레지스트리 윈도우 안에 살아있는지 온체인에 직접 물어본다.
// IdP가 아니라 체인에 묻는다는 점이 중요하다 — IdP에 요청을 보내면 그 자체가
// 타이밍 상관 신호가 된다(아래 /submitTransaction 주석 참고).
async function isRevocationRootPublished(root) {
  if (!REVOCATION_REGISTRY_ADDRESS) throw new Error('REVOCATION_REGISTRY_ADDRESS not configured');
  const data = registryInterface.encodeFunctionData('isRecentRoot', [revocationRootToBytes32(root)]);
  const result = await rpcCall('eth_call', [{ to: REVOCATION_REGISTRY_ADDRESS, data }, 'latest']);
  const [isRecent] = registryInterface.decodeFunctionResult('isRecentRoot', result);
  return Boolean(isRecent);
}

// isRevocationRootPublished()가 false를 돌려줬을 때, 운영자가 원인을 구분할 수 있도록
// filled()를 추가로 조회한다. filled()==0이면 레지스트리가 (재)배포된 직후 아직
// 아무 root도 게시되지 않은 것이고(부트스트랩 미실행), filled()>0인데 이 root가 안
// 보이면 grace window(GRACE_BLOCKS)가 지나 만료됐거나 애초에 게시된 적 없는
// root라는 뜻이다. 두 경우는 운영자가 취할 조치가 다르므로(전자는 최초
// push_revocation_root 실행, 후자는 재게시/재조회) 구분해서 알려준다.
async function describeUnpublishedRoot() {
  const data = registryInterface.encodeFunctionData('filled', []);
  const result = await rpcCall('eth_call', [{ to: REVOCATION_REGISTRY_ADDRESS, data }, 'latest']);
  const [filled] = registryInterface.decodeFunctionResult('filled', result);
  if (BigInt(filled) === 0n) {
    return 'RevocationRegistry에 아직 어떤 root도 게시되지 않았습니다(재배포 직후 부트스트랩 미실행일 수 있습니다).';
  }
  return 'RevocationRegistry에 이 root가 없거나 grace window(GRACE_BLOCKS)가 지나 만료되었습니다.';
}

async function verifyRpCredential(rpCredential) {
  await ensureEdDSA();
  if (!poseidon) throw new Error('Poseidon not initialized yet');
  const idpPublicKeys = await getIdpPublicKeys();
  const pkIdPRaw = idpPublicKeys?.pk_IdP;
  if (!pkIdPRaw || pkIdPRaw.length !== 2) throw new Error('IdP EdDSA public key not available');

  const DOMAIN_RP_REG = valueToField('RP_REG');
  const msg = poseidon([DOMAIN_RP_REG, valueToField(rpCredential.rid), valueToField(rpCredential.origin)]);
  const pkIdP = [eddsa.F.e(BigInt(pkIdPRaw[0])), eddsa.F.e(BigInt(pkIdPRaw[1]))];
  const sig = rpCredential.signature ?? {};
  if (!Array.isArray(sig.R8) || sig.R8.length !== 2 || !sig.S) {
    throw new Error('RP credential signature is missing or malformed');
  }
  const sigForVerify = {
    R8: [eddsa.F.e(BigInt(sig.R8[0])), eddsa.F.e(BigInt(sig.R8[1]))],
    S: BigInt(sig.S),
  };
  const isValid = eddsa.verifyPoseidon(msg, sigForVerify, pkIdP);
  if (!isValid) {
    throw new Error('RP credential signature verification failed: this rid/origin pair was not issued by the trusted IdP');
  }
  if (rpCredential.origin !== RP_ORIGIN) {
    throw new Error(
      `RP credential origin mismatch: credential is bound to ${rpCredential.origin}, but this wallet only trusts ${RP_ORIGIN}`,
    );
  }
}

// snap/src/index.js의 assertTokenMatchesWalletSubmission()을 그대로 이식 — Step 12가
// Snap에서 여기로 옮겨오면서, 토큰 필드가 Step 8에서 지갑이 실제로 제출한 값과
// 일치하는지 대조하는 로직도 같이 옮겨온다.
function assertTokenMatchesWalletSubmission(token, walletSubmission, business) {
  const checks = {
    aridOk: String(token.arid_i) === String(walletSubmission?.arid_i ?? business?.arid_i),
    auidOk: String(token.auid_i) === String(walletSubmission?.auid_i ?? business?.auid_i),
    tokenNonceOk: String(token.r_token) === String(walletSubmission?.r_token ?? business?.r_token ?? business?.tokenNonce),
    maxHeightOk: String(token.max_height) === String(business?.maxHeight ?? business?.max_height),
    chainIdOk: String(token.chain_id) === String(business?.chain_id ?? business?.chainId),
  };
  const success = checks.aridOk && checks.auidOk && checks.tokenNonceOk && checks.maxHeightOk && checks.chainIdOk;
  return { success, checks };
}

function now() { return Date.now(); }
function cursor() { return { last: now() }; }
function ms(c) {
  const t = now();
  const delta = t - c.last;
  c.last = t;
  return `${delta.toFixed(0)} ms`;
}
function preview(value, maxChars = 40) {
  if (value === undefined || value === null) return 'n/a';
  const str = typeof value === 'string' ? value : JSON.stringify(value);
  return str.length > maxChars ? `${str.slice(0, maxChars)}...` : str;
}

function readState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  } catch {
    return {};
  }
}

// state 파일에는 지갑 salt와 인증 토큰이 들어있으므로 소유자만 읽고 쓸 수 있게 한다.
function writeState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
  try {
    fs.chmodSync(STATE_FILE, 0o600);
  } catch {
    // best-effort; writeFileSync's mode already covers the common case.
  }
}

// 지갑 salt: 이 로컬 프로세스만 접근 가능한 파일에 보관하고, 최초 1회 생성 후 재사용한다.
function getOrCreateWalletSalt() {
  const state = readState();
  if (!state.mode2WalletSalt) {
    const bytes = webcrypto.getRandomValues(new Uint8Array(32));
    state.mode2WalletSalt = `0x${bytesToHex(bytes)}`;
    writeState(state);
  }
  return state.mode2WalletSalt;
}

// pk_i의 이더리움 주소 계산 — 65바이트(0x04 prefix) 비압축 공개키에서 프리픽스를 떼고
// keccak256(X||Y)의 마지막 20바이트를 취한다. 표준 이더리움 주소 유도 공식.
function ethAddressFromSecp256k1Pubkey(pubKeyUncompressed65) {
  const xy = pubKeyUncompressed65.slice(1);
  const hash = keccak256(xy);
  return '0x' + hash.slice(-40);
}

// 세션 서명키(pk_i/sk_i): P-256 대신 secp256k1을 쓴다 — 이유는 PPIDWallet 컨트랙트가
// payload 서명을 회로 밖에서 ecrecover로 직접 검증하기 때문(온체인 ecrecover는
// secp256k1 전용). WebCrypto의 SubtleCrypto는 secp256k1을 지원하지 않으므로
// @noble/curves를 쓴다.
//
// 이 키는 로그인(Step 8)마다 새로 생성해서 메모리에만 둔다 — pk_i는 IdP/RP 양쪽
// 증명의 평문 public input이자 온체인 pi_pk_i에도 노출되므로, 고정된 값을 계속
// 재사용하면 IdP가 세션 간 상관관계를 추적하거나 서로 다른 RP/온체인 관찰자가
// pk_i만으로 같은 지갑임을 알아낼 수 있다(논문 Property 5, cross-service
// unlinkability가 막으려는 바로 그 속성). 같은 방문(로그인→트랜잭션 제출) 안에서는
// 이 프로세스가 계속 떠 있는 동안 메모리 값이 유지되므로 일관성 문제는 없다.
let currentSessionKey = null;

// pi_pk_i의 계정 바인딩(PPID === Poseidon(uid, rid, salt))과 auid 계산에 필요하다.
// 세션 키와 수명을 같이 하며, HTTP로 나가지 않는다.
let currentAccountSecrets = null; // { uid, salt, rid } — 전부 bigint

// pi_pk_i는 세션 크레덴셜이라 같은 세션·같은 root면 증명을 재사용할 수 있다.
let cachedPiPkI = null; // { sessionKeyId, root, proofA, proofB, proofC }

// 캐시된 pi_pk_i 증명을 재사용해도 되는지 판정한다.
// 세션 키가 같고 폐기 root도 같을 때만 재사용할 수 있다 — root가 바뀌었다면
// 그 사이에 누군가 폐기됐을 수 있으므로 다시 증명해야 한다.
// 테스트에서 직접 호출하므로 export 한다.
export function shouldReuseProof(cache, currentRoot, sessionKeyId) {
  if (!cache) return false;
  if (cache.sessionKeyId !== sessionKeyId) return false;
  if (cache.root !== currentRoot) return false;
  return true;
}

function generateNewSessionKey() {
  const sk_i = secp256k1.utils.randomPrivateKey();
  const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
  const address = ethAddressFromSecp256k1Pubkey(pubUncompressed);
  currentSessionKey = { sk_i, pk_i: BigInt(address), address, publicKeyHex: `0x${bytesToHex(pubUncompressed)}` };
  currentAccountSecrets = null;
  cachedPiPkI = null;
  return currentSessionKey;
}

function getCurrentSessionKey() {
  if (!currentSessionKey) {
    throw new Error('No active session key — call /generateStep8Proofs (login) first');
  }
  return currentSessionKey;
}

function getCurrentAccountSecrets() {
  if (!currentAccountSecrets) {
    throw new Error('No account secrets — call /generateStep8Proofs (login) first');
  }
  return currentAccountSecrets;
}

// 인증 토큰: RP_ORIGIN 자신(server.js)만 이 파일을 직접 읽어서 브라우저 페이지에
// 전달할 수 있다 — CORS는 브라우저가 아닌 호출자(curl, 다른 로컬 프로세스, LAN의
// 다른 머신)를 막지 못하므로, 토큰 없이는 /generateStep8Proofs를 아무도 호출하지
// 못하게 해서 salt 추출(uid=1, rid=1 등으로 ppid=salt를 뽑아내는 것)을 막는다.
function getOrCreateAgentToken() {
  const state = readState();
  if (!state.agentToken) {
    const bytes = webcrypto.getRandomValues(new Uint8Array(32));
    state.agentToken = bytesToHex(bytes);
    writeState(state);
  }
  return state.agentToken;
}

const app = express();
app.use(cors({ origin: RP_ORIGIN }));
app.use(express.json());

// RP 페이지가 숨겨진 iframe으로 이 정적 relay 페이지를 임베드한다(설계 문서:
// docs/superpowers/specs/2026-07-21-wallet-relay-idp-popup-design.md). iframe의
// src 요청은 브라우저가 커스텀 헤더를 못 실어 보내므로, 아래 두 라우트는 반드시
// X-Wallet-Agent-Token 검사 미들웨어보다 앞에 둔다. frame-ancestors CSP로 이
// relay를 설정된 RP_ORIGIN 외의 페이지가 iframe으로 못 담게 막는다.
function setRelayCsp(res) {
  res.setHeader('Content-Security-Policy', `frame-ancestors ${RP_ORIGIN}`);
}
app.get('/relay', (req, res) => {
  setRelayCsp(res);
  res.sendFile(path.join(__dirname, 'wallet', 'relay.html'));
});
// express.static의 setHeaders로도 같은 CSP를 붙인다 — 안 그러면 relay.html이
// /wallet/relay.html 경로로도 그대로 노출돼서 위 /relay 라우트의 CSP를 우회할 수 있다.
app.use('/wallet', express.static(path.join(__dirname, 'wallet'), {
  setHeaders: setRelayCsp,
}));

app.use((req, res, next) => {
  const provided = req.get('X-Wallet-Agent-Token');
  if (!provided || provided !== getOrCreateAgentToken()) {
    console.warn(`[WalletAgent] Rejected request to ${req.path}: missing or invalid X-Wallet-Agent-Token`);
    return res.status(401).json({ error: 'Missing or invalid wallet agent token' });
  }
  next();
});

async function generateStep8ProofsData(rpCredential, r_i, rpNonce) {
  const requestStart = now();
  const start = cursor();
  console.log(`--- [WalletAgent][Step 8] generateStep8Proofs request received ---`);
  console.log(`[WalletAgent][Step 8] rid: ${preview(rpCredential?.rid)}, r_i: ${preview(r_i)}`);

  if (!rpCredential?.rid) throw new Error('rpCredential.rid is required');
  if (!rpCredential?.signature) throw new Error('rpCredential.signature is required');
  if (!r_i) throw new Error('r_i is required');
  if (!rpNonce) throw new Error('rpNonce is required');

  await verifyRpCredential(rpCredential);
  console.log(`[WalletAgent][Step 8] RP credential signature verified ${ms(start)}`);

  const heightInfo = await getMaxHeight();
  const maxHeight = heightInfo.maxHeight;
  console.log(`[WalletAgent][Step 8] chain_id/max_height computed: chainId=${heightInfo.chainId}, currentBlock=${heightInfo.currentBlock.toString()}, maxHeight=${maxHeight.toString()} ${ms(start)}`);

  const walletSalt = getOrCreateWalletSalt();
  const uidField = valueToField(DEMO_BOUND_UID);
  const saltField = valueToField(walletSalt);
  const rid = BigInt(rpCredential.rid);
  const rpNonceField = valueToField(rpNonce);

  // ppid = Poseidon(uid, rid, salt), arid_i = rid * rp_nonce, auid_i = ppid * rp_nonce
  const ppid = poseidon.F.toObject(poseidon([uidField, rid, saltField]));
  const arid_i = (rid * rpNonceField) % FIELD_PRIME;
  const auid_i = (ppid * rpNonceField) % FIELD_PRIME;
  // auid = Poseidon(uid, salt) — fixed per account, lets the IdP detect a
  // wallet reusing a different salt across logins for the same uid.
  const auid = poseidon.F.toObject(poseidon([uidField, saltField]));
  console.log(`[WalletAgent][Step 8] PPID/arid_i/auid_i/auid computed ${ms(start)}`);

  // 세션 서명키: secp256k1, 로그인마다 새로 생성됨 (generateNewSessionKey 참고).
  // pk_i는 이제 공개키 블롭의 해시가 아니라 그 공개키의 이더리움 주소 자체다.
  const { sk_i, pk_i: pkField, address, publicKeyHex } = generateNewSessionKey();
  // generateNewSessionKey()가 currentAccountSecrets를 비우므로 반드시 그 뒤에 채운다.
  // 앞에 두면 방금 넣은 값이 곧바로 지워져 /submitTransaction이 항상 실패한다.
  currentAccountSecrets = { uid: uidField, salt: saltField, rid };
  console.log(`[WalletAgent][Step 8] session key ready. address(pk_i): ${preview(publicKeyHex, 34)} ${ms(start)}`);

  const maxHeightField = valueToField(maxHeight);

  const tokenNonce = poseidon.F.toObject(poseidon([pkField, maxHeightField, rpNonceField]));
  console.log(`[WalletAgent][Step 8] token nonce (Poseidon) generated ${ms(start)}`);

  // verifyRpCredential() above already checked this signature locally; here we
  // feed the same signature into pi_arid_i so the IdP can confirm (without
  // learning rid/origin) that a valid RP_REG credential was actually used.
  const idpPublicKeysForCircuit = await getIdpPublicKeys();
  const [pkIdPXForCircuit, pkIdPYForCircuit] = idpPublicKeysForCircuit.pk_IdP;

  const aridInputs = {
    rp_nonce: rpNonceField.toString(),
    salt: saltField.toString(),
    rid: rid.toString(),
    pk_i: pkField.toString(),
    origin: valueToField(rpCredential.origin).toString(),
    rp_reg_S: rpCredential.signature.S,
    rp_reg_R8x: rpCredential.signature.R8[0],
    rp_reg_R8y: rpCredential.signature.R8[1],
    uid: uidField.toString(),
    arid_i: arid_i.toString(),
    auid_i: auid_i.toString(),
    max_height: maxHeightField.toString(),
    token_nonce: tokenNonce.toString(),
    auid: auid.toString(),
    pk_IdP_x: pkIdPXForCircuit,
    pk_IdP_y: pkIdPYForCircuit,
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    aridInputs,
    'build/mode2/pi_arid_i_js/pi_arid_i.wasm',
    'build/mode2/pi_arid_i_final.zkey',
  );
  console.log(`[WalletAgent][Step 8] pi_i (pi_arid_i) proof generated ${ms(start)}`);

  const ppidInputs = {
    uid: uidField.toString(),
    salt: saltField.toString(),
    rid: rid.toString(),
    ppid: ppid.toString(),
  };
  const { proof: ppidProof, publicSignals: ppidPublicSignals } = await snarkjs.groth16.fullProve(
    ppidInputs,
    'build/mode2/pi_ppid_js/pi_ppid.wasm',
    'build/mode2/pi_ppid_final.zkey',
  );
  console.log(`[WalletAgent][Step 8] pi_PPID proof generated ${ms(start)}`);

  const durationMs = now() - requestStart;
  console.log(`✅ [WalletAgent][Step 8] All proofs ready ${ms(start)}`);

  return {
    rid: rid.toString(),
    ppid: ppid.toString(),
    rpNonceField: rpNonceField.toString(),
    arid_i: arid_i.toString(),
    auid_i: auid_i.toString(),
    currentBlock: heightInfo.currentBlock.toString(),
    chain_id: heightInfo.chainId,
    heightSource: heightInfo.source,
    maxHeight: maxHeightField.toString(),
    tokenNonce: tokenNonce.toString(),
    pk_i: pkField.toString(),
    publicKeyHex,
    zkpProof: proof,
    // pi_arid_i public signals are [uid, arid_i, auid_i, max_height, token_nonce, auid, pk_IdP_x, pk_IdP_y].
    // The IdP reconstructs uid from the authenticated account, so never expose it to RP FE.
    zkpPublicSignals: publicSignals.slice(1),
    pi_PPID: {
      type: 'pi_PPID',
      proof: ppidProof,
      publicSignals: ppidPublicSignals, // [rid, ppid], per circuit's public [rid, ppid]
      r_token: tokenNonce.toString(),
      generatedAt: new Date().toISOString(),
    },
    walletSubmission: {
      auid_i: auid_i.toString(),
      arid_i: arid_i.toString(),
      r_token: tokenNonce.toString(),
      pi_i: proof,
      r_i,
    },
    business: {
      ppid: ppid.toString(),
      arid_i: arid_i.toString(),
      auid_i: auid_i.toString(),
      r_i,
      r_token: tokenNonce.toString(),
      tokenNonce: tokenNonce.toString(),
      maxHeight: maxHeightField.toString(),
      chain_id: heightInfo.chainId,
    },
    durationMs,
    // Internal only — captured at the exact moment this job's session key was
    // generated, so later async steps (loopback /par signing) use THIS job's
    // key even if a concurrent /startLogin call overwrites the shared global
    // currentSessionKey in the meantime. Never sent over HTTP — the
    // /generateStep8Proofs route below strips this before responding.
    sessionKey: { sk_i, address },
  };
}

// Step 8을 대신 수행한다: PPID/arid_i/auid_i 계산, 세션 서명키 생성, Poseidon
// 토큰 논스, pi_i/pi_PPID Groth16 증명 생성. 이 프로세스는 사용자 로컬 머신에서만
// 돌고 RP_ORIGIN에서만 접근 가능하다 — RP 페이지(client.js)의 JS 컨텍스트와는
// 별도의 OS 프로세스라서, uid와 salt가 RP 페이지에 직접 노출되지 않는다.
app.post('/generateStep8Proofs', async (req, res) => {
  try {
    const { rpCredential, r_i, rpNonce } = req.body ?? {};
    if (Object.prototype.hasOwnProperty.call(req.body ?? {}, 'uid')) {
      throw new Error('uid must not be supplied by the RP frontend');
    }
    const result = await generateStep8ProofsData(rpCredential, r_i, rpNonce);
    const { sessionKey, ...publicResult } = result; // never expose the raw session key over HTTP
    res.json(publicResult);
  } catch (err) {
    console.error(`❌ [WalletAgent][Step 8] generateStep8Proofs error: ${err.message}`);
    res.status(400).json({ error: err.message });
  }
});

// Wallet-driven login job store: jobId -> { status, expiresAt, step8?, error?,
// result? }. Memory-only, same pattern as this project's other in-memory
// stores (e.g. custom_idp.js's pushedRequests/authorizationCodes) — lost on
// restart, intentional demo limitation.
const loginJobs = new Map();
const LOGIN_JOB_TTL_MS = 10 * 60 * 1000; // generous — covers proof gen + human login/consent time

function pruneExpiredJobs() {
  const now = Date.now();
  for (const [jobId, job] of loginJobs) {
    if (job.expiresAt <= now) loginJobs.delete(jobId);
  }
}

// Step 8을 백그라운드로 돌리고 즉시 jobId만 응답한다 — 이후 단계(Snap 승인,
// 시스템 브라우저 로그인)가 사람 개입으로 수십 초~수 분 걸릴 수 있어서, RP FE가
// 하나의 HTTP 요청으로 계속 기다리게 하지 않는다. 대신 /loginStatus를 폴링한다.
app.post('/startLogin', async (req, res) => {
  const { rpCredential, r_i, rpNonce } = req.body ?? {};
  if (Object.prototype.hasOwnProperty.call(req.body ?? {}, 'uid')) {
    return res.status(400).json({ error: 'uid must not be supplied by the RP frontend' });
  }
  if (!rpCredential?.rid) return res.status(400).json({ error: 'rpCredential.rid is required' });
  if (!rpCredential?.signature) return res.status(400).json({ error: 'rpCredential.signature is required' });
  if (!r_i) return res.status(400).json({ error: 'r_i is required' });
  if (!rpNonce) return res.status(400).json({ error: 'rpNonce is required' });

  pruneExpiredJobs();
  const jobId = webcrypto.randomUUID();
  loginJobs.set(jobId, { status: 'generating_proof', expiresAt: Date.now() + LOGIN_JOB_TTL_MS });
  res.status(202).json({ jobId });

  try {
    const step8 = await generateStep8ProofsData(rpCredential, r_i, rpNonce);
    const job = loginJobs.get(jobId);
    if (!job) return; // expired/pruned while proof was generating
    job.status = 'awaiting_wallet_approval';
    job.step8 = step8;
    console.log(`[WalletAgent][startLogin] job ${jobId} awaiting_wallet_approval`);
  } catch (err) {
    const job = loginJobs.get(jobId);
    if (job) {
      job.status = 'failed';
      job.error = err.message;
    }
    console.error(`[WalletAgent][startLogin] job ${jobId} failed during proof generation: ${err.message}`);
  }
});

app.get('/loginStatus', (req, res) => {
  pruneExpiredJobs();
  const { jobId } = req.query ?? {};
  const job = loginJobs.get(jobId);
  if (!job) return res.status(404).json({ error: 'Unknown or expired jobId' });

  if (job.status === 'done') {
    return res.json({ status: 'done', ...job.result });
  }
  if (job.status === 'failed') {
    return res.json({ status: 'failed', error: job.error });
  }
  if (job.status === 'awaiting_browser_login') {
    return res.json({ status: 'awaiting_browser_login', requestUri: job.requestUri });
  }
  res.json({ status: job.status });
});

// client.js가 Snap confirmLogin 다이얼로그 결과를 보고하는 엔드포인트.
// wallet_agent.js는 Node 프로세스라 window.ethereum에 직접 접근할 수 없어서,
// Snap 호출 자체는 client.js가 대신 하고 그 결과만 여기로 보고받는다. 승인이면
// loopback 리스너를 열고 /par를 호출해서 시스템 브라우저 단계로 넘어간다.
app.post('/confirmLoginResult', async (req, res) => {
  const { jobId, approved } = req.body ?? {};
  const job = loginJobs.get(jobId);
  if (!job) return res.status(404).json({ error: 'Unknown or expired jobId' });
  if (job.status !== 'awaiting_wallet_approval') {
    return res.status(400).json({ error: `job is not awaiting approval (current status: ${job.status})` });
  }

  if (!approved) {
    job.status = 'denied';
    console.log(`[WalletAgent][confirmLoginResult] job ${jobId} denied at Snap approval`);
    return res.json({ success: true });
  }

  res.json({ success: true });
  startLoopbackLogin(jobId).catch((err) => {
    const j = loginJobs.get(jobId);
    if (j) {
      j.status = 'failed';
      j.error = err.message;
    }
    console.error(`[WalletAgent][confirmLoginResult] job ${jobId} failed: ${err.message}`);
  });
});

const LOOPBACK_TIMEOUT_MS = 90 * 1000; // /par's request_uri TTL (60s) plus margin

async function startLoopbackLogin(jobId) {
  const job = loginJobs.get(jobId);
  if (!job) return;
  const step8 = job.step8;

  const state = webcrypto.randomUUID();
  const nonce = webcrypto.randomUUID();
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

  const { sk_i, address } = step8.sessionKey;
  const bindingHash = keccak256(
    AbiCoder.defaultAbiCoder().encode(['string', 'string', 'string'], [state, nonce, codeChallenge]),
  );
  const sigRaw = secp256k1.sign(bindingHash.slice(2), sk_i);
  const requestBindingSignature =
    '0x' +
    sigRaw.r.toString(16).padStart(64, '0') +
    sigRaw.s.toString(16).padStart(64, '0') +
    (27 + sigRaw.recovery).toString(16).padStart(2, '0');

  const server = http.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const redirectUri = `http://127.0.0.1:${port}/oidc/callback`;

  const timeoutHandle = setTimeout(() => {
    server.close();
    const j = loginJobs.get(jobId);
    if (j && j.status === 'awaiting_browser_login') {
      j.status = 'failed';
      j.error = 'Timed out waiting for the browser login/consent to complete';
      console.error(`[WalletAgent][loopback] job ${jobId} timed out waiting for callback`);
    }
  }, LOOPBACK_TIMEOUT_MS);

  server.on('request', (req, res) => {
    handleLoopbackCallback(jobId, req, res, { server, timeoutHandle, redirectUri, codeVerifier, state });
  });

  const parRes = await fetch(`${IDP_ORIGIN}/par`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: 'pairct-wallet',
      redirect_uri: redirectUri,
      response_type: 'code',
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      zkpProof: step8.zkpProof,
      zkpPublicSignals: step8.zkpPublicSignals,
      chain_id: step8.chain_id,
      requestBinding: { pk_i: address, signature: requestBindingSignature },
    }),
  });
  const parBody = await parRes.json();
  if (!parRes.ok || !parBody.request_uri) {
    clearTimeout(timeoutHandle);
    server.close();
    throw new Error(parBody.error_description || parBody.error || '/par failed');
  }

  job.status = 'awaiting_browser_login';
  job.requestUri = parBody.request_uri;
  console.log(`[WalletAgent][loopback] job ${jobId} pushed to IdP, request_uri=${parBody.request_uri}, redirect_uri=${redirectUri}`);
  // 브라우저를 여는 건 이제 RP FE의 몫이다 — RP FE가 사용자 클릭 시점에 미리
  // 열어둔 빈 창을 이 request_uri로 이동시킨다(팝업 차단 회피). Wallet은 IdP에
  // ZKP 증명을 담아 /par만 보내고, 그 결과인 request_uri(그 자체로는 아무
  // 의미 없는 참조값)만 RP FE에 넘겨준다.
}

function handleLoopbackCallback(jobId, req, res, ctx) {
  const { server, timeoutHandle, redirectUri, codeVerifier, state } = ctx;
  const requestUrl = new URL(req.url, 'http://127.0.0.1');
  if (requestUrl.pathname !== '/oidc/callback') {
    res.writeHead(404).end();
    return;
  }

  clearTimeout(timeoutHandle);
  const returnedState = requestUrl.searchParams.get('state');
  const code = requestUrl.searchParams.get('code');
  const error = requestUrl.searchParams.get('error');

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<html><body><p>Login complete. You can close this tab and return to the app.</p></body></html>');
  server.close();

  const job = loginJobs.get(jobId);
  if (!job) return;

  if (returnedState !== state) {
    job.status = 'failed';
    job.error = 'state mismatch on loopback callback (possible CSRF)';
    console.error(`[WalletAgent][loopback] job ${jobId}: state mismatch on callback`);
    return;
  }
  if (error) {
    job.status = 'denied';
    console.log(`[WalletAgent][loopback] job ${jobId} denied at IdP consent: ${error}`);
    return;
  }
  if (!code) {
    job.status = 'failed';
    job.error = 'loopback callback had neither code nor error';
    return;
  }

  job.status = 'exchanging_token';
  exchangeToken(jobId, code, redirectUri, codeVerifier).catch((err) => {
    const j = loginJobs.get(jobId);
    if (j) {
      j.status = 'failed';
      j.error = err.message;
    }
    console.error(`[WalletAgent][loopback] job ${jobId} token exchange failed: ${err.message}`);
  });
}

async function exchangeToken(jobId, code, redirectUri, codeVerifier) {
  const job = loginJobs.get(jobId);
  if (!job) return;

  const tokenRes = await fetch(`${IDP_ORIGIN}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: 'pairct-wallet',
      code_verifier: codeVerifier,
    }),
  });
  const statement = await tokenRes.json();
  if (!tokenRes.ok || !statement.signature) {
    throw new Error(statement.error_description || statement.error || '/token failed');
  }

  const step8 = job.step8;
  // /token 응답에는 새 9-field statement 필드와 옛 6-field idpToken(온체인 tx
  // 제출 전용, /submitTransaction이 소비)이 함께 실려 온다. statement 전체를
  // 그대로 job.result.statement에 복사하면 idpToken이 그 안에 중첩되어 남으므로,
  // 구조 분해로 분리해서 둘을 독립된 필드로 둔다.
  const { idpToken, ...statementFields } = statement;
  job.status = 'done';
  job.result = {
    ppid: step8.ppid,
    arid_i: step8.arid_i,
    auid_i: step8.auid_i,
    pk_i: step8.pk_i,
    publicKeyHex: step8.publicKeyHex,
    pi_PPID: step8.pi_PPID,
    statement: statementFields,
    idpToken,
  };
  console.log(`[WalletAgent][loopback] job ${jobId} done`);
}

app.post('/verifyIdPAuthToken', async (req, res) => {
  const start = cursor();
  const verifyStart = now();
  try {
    const { idpToken, walletSubmission, business } = req.body ?? {};
    if (!idpToken) throw new Error('idpToken is required');

    await ensureEdDSA();
    if (!poseidon) throw new Error('Poseidon not initialized yet');

    const idpPublicKeys = await getIdpPublicKeys();
    const pkIdPRaw = idpPublicKeys?.pk_IdP;
    if (!pkIdPRaw || pkIdPRaw.length !== 2) throw new Error('IdP EdDSA public key not available');

    const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
    const msgFields = [
      DOMAIN_IDP_TOKEN,
      valueToField(idpToken.arid_i),
      valueToField(idpToken.auid_i),
      valueToField(idpToken.r_token),
      valueToField(idpToken.max_height),
      valueToField(idpToken.chain_id),
    ];
    const msg = poseidon(msgFields);
    const pkIdP = [eddsa.F.e(BigInt(pkIdPRaw[0])), eddsa.F.e(BigInt(pkIdPRaw[1]))];
    const sig = idpToken.signature ?? {};
    if (!Array.isArray(sig.R8) || sig.R8.length !== 2 || !sig.S) {
      throw new Error('idpToken.signature is missing or malformed');
    }
    const sigForVerify = {
      R8: [eddsa.F.e(BigInt(sig.R8[0])), eddsa.F.e(BigInt(sig.R8[1]))],
      S: BigInt(sig.S),
    };

    let accepted = eddsa.verifyPoseidon(msg, sigForVerify, pkIdP);
    const binding = assertTokenMatchesWalletSubmission(idpToken, walletSubmission, business);
    accepted = accepted && binding.success;
    const message = accepted
      ? 'EdDSA-Poseidon signature and Wallet bindings verified'
      : 'EdDSA-Poseidon signature or Wallet binding verification failed';

    console.log(`[WalletAgent][Step 12] verifyIdPAuthToken: ${accepted ? 'PASS' : 'FAIL'} ${ms(start)}`);
    res.json({ success: accepted, message, checks: binding.checks, durationMs: now() - verifyStart });
  } catch (err) {
    console.error(`[WalletAgent][Step 12] verifyIdPAuthToken error: ${err.message} ${ms(start)}`);
    res.status(400).json({ success: false, message: err.message, checks: {}, durationMs: now() - verifyStart });
  }
});

// B1(PPID 트랜잭션 제출): payload에 세션키(pk_i/sk_i)로 서명하고, Step 12에서 검증했던
// EdDSA-Poseidon 인증 토큰 서명을 회로 안에서 다시 검증하는 pi_pk_i 증명을 생성한다.
// payloadHash는 PPIDWallet.sol의 execute()가 계산하는
// keccak256(abi.encode(to, value, data, nonce))와 정확히 같은 방식으로 계산해야
// 컨트랙트의 ecrecover가 세션키 주소(pk_i)를 그대로 복구할 수 있다.
app.post('/submitTransaction', async (req, res) => {
  const start = cursor();
  try {
    const { to, value, data, business, rpNonce } = req.body ?? {};
    if (!to) throw new Error('to is required');
    if (value === undefined) throw new Error('value is required');
    if (!business?.arid_i || !business?.auid_i) throw new Error('business.arid_i/auid_i are required');
    if (business?.PPID === undefined && business?.ppid === undefined) throw new Error('business.PPID/ppid is required');
    if (!rpNonce) throw new Error('rpNonce is required');
    if (!PPID_WALLET_FACTORY_ADDRESS) throw new Error('PPID_WALLET_FACTORY_ADDRESS not configured');
    if (!REVOCATION_REGISTRY_ADDRESS) throw new Error('REVOCATION_REGISTRY_ADDRESS not configured');

    await ensureEdDSA();
    if (!poseidon) throw new Error('Poseidon not initialized yet');

    const idpPublicKeys = await getIdpPublicKeys();
    const pkIdPRaw = idpPublicKeys?.pk_IdP;
    if (!pkIdPRaw || pkIdPRaw.length !== 2) throw new Error('IdP EdDSA public key not available');

    // sigma_i (인증 토큰 자체의 EdDSA-Poseidon 서명)도 요청 본문에서 받는다 —
    // 클라이언트는 walletReceivedIdPToken.signature.{R8,S}로 이미 갖고 있다.
    // circuitInput 조립보다 먼저 검사해서, S/R8x/R8y가 빈 값인 채로
    // snarkjs.groth16.fullProve가 호출되지 않도록 한다.
    const idpTokenSig = req.body?.idpToken?.signature;
    if (!idpTokenSig?.R8 || !idpTokenSig?.S) throw new Error('idpToken.signature is required');

    const { sk_i, pk_i } = getCurrentSessionKey();

    const ppidField = valueToField(business.PPID ?? business.ppid);

    // 대상 PPIDWallet의 CREATE2 주소를 factory에 직접 조회한다 — client.js는
    // 이 주소를 몰라도 된다.
    const computeAddressCalldata = factoryInterface.encodeFunctionData('computeAddress', [ppidField]);
    const computeAddressResult = await rpcCall('eth_call', [
      { to: PPID_WALLET_FACTORY_ADDRESS, data: computeAddressCalldata },
      'latest',
    ]);
    const [walletAddress] = factoryInterface.decodeFunctionResult('computeAddress', computeAddressResult);

    // PPIDWallet은 CREATE2로 지연 배포되므로, 아직 배포 안 됐을 수 있다(코드 없음).
    // 배포 안 됐으면 nonce는 0으로 간주하고, 응답에 배포 트랜잭션도 같이 실어보낸다 —
    // wallet_agent.js는 가스비를 낼 서명 키가 없어서(sk_i는 payload 서명 전용) 배포도
    // execute()와 마찬가지로 브라우저의 MetaMask가 보내야 한다.
    const walletCode = await rpcCall('eth_getCode', [walletAddress, 'latest']);
    const isDeployed = Boolean(walletCode) && walletCode !== '0x';

    let currentNonce = 0n;
    if (isDeployed) {
      const nonceCalldata = walletInterface.encodeFunctionData('nonce', []);
      const nonceResult = await rpcCall('eth_call', [{ to: walletAddress, data: nonceCalldata }, 'latest']);
      [currentNonce] = walletInterface.decodeFunctionResult('nonce', nonceResult);
    }

    const payloadData = data ?? '0x';
    const payload = { to, value: value.toString(), data: payloadData, nonce: currentNonce.toString() };

    const payloadHash = keccak256(
      AbiCoder.defaultAbiCoder().encode(
        ['address', 'uint256', 'bytes', 'uint256'],
        [payload.to, payload.value, payload.data, payload.nonce],
      ),
    );
    const sigRaw = secp256k1.sign(payloadHash.slice(2), sk_i);
    const sig =
      '0x' +
      sigRaw.r.toString(16).padStart(64, '0') +
      sigRaw.s.toString(16).padStart(64, '0') +
      (27 + sigRaw.recovery).toString(16).padStart(2, '0');

    const rp_nonce = valueToField(rpNonce);
    const arid_i = valueToField(business.arid_i);
    const auid_i = valueToField(business.auid_i);
    const r_token = valueToField(business.r_token ?? business.tokenNonce);
    const chain_id = valueToField(business.chain_id ?? business.chainId);
    const maxHeightField = valueToField(business.maxHeight ?? business.max_height);

    const pkIdP_x = BigInt(pkIdPRaw[0]);
    const pkIdP_y = BigInt(pkIdPRaw[1]);

    const { uid: uidField, salt: saltField, rid: ridField } = getCurrentAccountSecrets();
    const auidField = poseidon.F.toObject(poseidon([uidField, saltField]));

    const sessionKeyId = pk_i.toString();

    // 이 트랜잭션에 쓸 폐기 root를 먼저 정한다. 캐시된 증명의 root가 아직 레지스트리
    // 윈도우 안에 살아있으면 그것을 그대로 쓰고, IdP에는 아무 요청도 보내지 않는다.
    //
    // 예전에는 fetchRevocationWitnesses()가 캐시 판정보다 앞에 있어서, 증명을
    // 재사용하는 경우에도 트랜잭션마다 IdP로 요청이 나갔다. IdP는 로그인 시점에 uid와
    // 그 클라이언트의 네트워크 신원을 알고 있으므로, IdP 로그와 체인을 함께 보면
    // "t에 세션 X가 폐기 목록을 조회 → t+Δ에 지갑 W에서 tx" 상관으로 지갑↔uid가
    // 몇 건 만에 확정된다. spec §3.4가 r_token을 public으로 올리는 안을 기각한
    // 바로 그 이유(IdP 로그와 온체인 지갑을 잇는 다리)를 접근 패턴으로 재도입한
    // 셈이라, 조회를 캐시 미스 경로로 옮긴다.
    //
    // 이렇게 하면 폐기가 방금 일어났더라도 캐시된 root가 만료되기 전까지(최대
    // GRACE_BLOCKS) 옛 증명이 쓰일 수 있다. 그건 C2에서 레지스트리에 못 박은
    // 신선도 정책이 의도적으로 허용하는 창이며, 그 창이 지나면 isRecentRoot가
    // false를 돌려주므로 자동으로 IdP 재조회 경로를 탄다.
    let rev = null;
    let txRevocationRoot;
    if (cachedPiPkI?.sessionKeyId === sessionKeyId && (await isRevocationRootPublished(cachedPiPkI.root))) {
      txRevocationRoot = cachedPiPkI.root;
    } else {
      rev = await fetchRevocationWitnesses(r_token.toString(), auidField.toString());
      txRevocationRoot = rev.root;
      // 지갑은 IdP의 '현재' 리프 집합으로만 witness를 만들 수 있는데, 온체인 게시는
      // 운영자가 돌리는 별도 단계다. 그래서 폐기 발생 후 push 전까지는 무고한
      // 사용자까지 전원이 execute()에서 StaleRevocationRoot로 revert한다. 여기서
      // 미리 걸러 원인을 알 수 있는 에러로 바꿔준다(옛 root로 증명하는 기능은 IdP가
      // 과거 리프 집합을 노출해야 하므로 이번 범위 밖).
      if (!(await isRevocationRootPublished(txRevocationRoot))) {
        const detail = await describeUnpublishedRoot();
        throw new Error(
          '폐기 목록이 아직 온체인에 반영되지 않았습니다: IdP의 현재 revocation root가 ' +
          `RevocationRegistry에 게시돼 있지 않습니다. ${detail} 운영자가 push_revocation_root를 ` +
          '실행해 root를 게시한 뒤 다시 시도하세요.',
        );
      }
    }

    let proofA, proofB, proofC;
    if (shouldReuseProof(cachedPiPkI, txRevocationRoot, sessionKeyId)) {
      ({ proofA, proofB, proofC } = cachedPiPkI);
      console.log('[WalletAgent][submitTransaction] reusing cached pi_pk_i proof (no IdP round-trip)');
    } else {
      // 여기 도달했다는 것은 캐시 재사용이 불가능했다는 뜻이고, 그 경우는 위에서
      // 반드시 IdP 조회 경로를 타므로 rev(=witness)가 채워져 있다. 이 불변식은
      // shouldReuseProof의 현재 조건 3개(캐시 존재/세션 일치/root 일치)에 기대고
      // 있을 뿐 강제되지 않으므로, 조건이 늘어나 깨지더라도 rev.sess에서 조용히
      // TypeError가 나지 않도록 여기서 명시적으로 확인한다.
      if (!rev) {
        throw new Error(
          'internal error: proof cache was not reused but no revocation witness was fetched (rev is null)',
        );
      }
      const circuitInput = {
        rp_nonce: rp_nonce.toString(),
        arid_i: arid_i.toString(),
        auid_i: auid_i.toString(),
        r_token: r_token.toString(),
        chain_id: chain_id.toString(),
        S: idpTokenSig.S,
        R8x: idpTokenSig.R8[0],
        R8y: idpTokenSig.R8[1],
        uid: uidField.toString(),
        rid: ridField.toString(),
        salt: saltField.toString(),
        sess_lowValue: rev.sess.lowValue,
        sess_lowNextValue: rev.sess.lowNextValue,
        sess_pathElements: rev.sess.pathElements,
        sess_pathIndices: rev.sess.pathIndices,
        acct_lowValue: rev.acct.lowValue,
        acct_lowNextValue: rev.acct.lowNextValue,
        acct_pathElements: rev.acct.pathElements,
        acct_pathIndices: rev.acct.pathIndices,
        pk_i: pk_i.toString(),
        pk_IdP_x: pkIdP_x.toString(),
        pk_IdP_y: pkIdP_y.toString(),
        PPID: ppidField.toString(),
        max_height: maxHeightField.toString(),
        revocationRoot: rev.root,
      };
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInput,
        'build/mode2/pi_pk_i_js/pi_pk_i.wasm',
        'build/mode2/pi_pk_i_final.zkey',
      );
      const calldata = JSON.parse(`[${await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)}]`);
      [proofA, proofB, proofC] = calldata;
      cachedPiPkI = { sessionKeyId, root: txRevocationRoot, proofA, proofB, proofC };
    }

    // PPIDWallet.execute()의 revocationRoot 파라미터는 bytes32다(field element를
    // 32바이트 hex로 표현). root는 스낙js·캐시 비교용 10진수 문자열이라서
    // ABI 인코딩 직전에만 hex로 변환한다.
    const revocationRootBytes32 = revocationRootToBytes32(txRevocationRoot);

    const executeCalldata = walletInterface.encodeFunctionData('execute', [
      { to: payload.to, value: payload.value, data: payload.data, nonce: payload.nonce },
      sig,
      proofA,
      proofB,
      proofC,
      pk_i.toString(),
      pkIdP_x.toString(),
      pkIdP_y.toString(),
      maxHeightField.toString(),
      revocationRootBytes32,
    ]);

    const deploy = isDeployed
      ? null
      : {
          to: PPID_WALLET_FACTORY_ADDRESS,
          data: factoryInterface.encodeFunctionData('deploy', [ppidField]),
        };

    console.log(`[WalletAgent][submitTransaction] proof + calldata generated ${ms(start)}`);
    res.json({ deploy, to: walletAddress, data: executeCalldata });
  } catch (err) {
    console.error(`[WalletAgent][submitTransaction] error: ${err.message} ${ms(start)}`);
    res.status(400).json({ error: err.message });
  }
});

// server.js가 ppid만 갖고 있을 때(로그인 검증 시점) 그 ppid의 PPIDWallet 주소를
// 알아내기 위해 쓰는 단독 엔드포인트. /submitTransaction 안에 있던 computeAddress
// 조회 로직과 동일하다 — server.js는 factory ABI/RPC를 몰라도 되게 한다.
app.post('/computeWalletAddress', async (req, res) => {
  const start = cursor();
  try {
    const { ppid } = req.body ?? {};
    if (ppid === undefined) throw new Error('ppid is required');
    if (!PPID_WALLET_FACTORY_ADDRESS) throw new Error('PPID_WALLET_FACTORY_ADDRESS not configured');

    const ppidField = valueToField(ppid);
    const computeAddressCalldata = factoryInterface.encodeFunctionData('computeAddress', [ppidField]);
    const computeAddressResult = await rpcCall('eth_call', [
      { to: PPID_WALLET_FACTORY_ADDRESS, data: computeAddressCalldata },
      'latest',
    ]);
    const [walletAddress] = factoryInterface.decodeFunctionResult('computeAddress', computeAddressResult);

    res.json({ walletAddress });
  } catch (err) {
    console.error(`[WalletAgent][computeWalletAddress] error: ${err.message} ${ms(start)}`);
    res.status(400).json({ error: err.message });
  }
});

// Trace UI(= authorized opening)가 "어느 트랜잭션을 추적할지" 고를 수 있게, 체인
// 전체에서 execute() 호출로 디코딩되는 트랜잭션을 전부 찾아 pk_i/max_height 목록을
// 돌려준다. 일부러 "지금 로그인한 PPID의 지갑" 하나로 안 좁힌다 — authorized
// opening은 원래 "지금 로그인한 내 트랜잭션"이 아니라 "분쟁이 생긴 임의의 과거
// 세션"을 추적하는 것이므로, 조사자가 아무 PPIDWallet의 트랜잭션이나 골라서
// 추적할 수 있어야 한다. pk_i/max_height는 execute() calldata에 이미 평문으로
// 들어가는 공개 온체인 데이터라서(누구나 체인을 보면 알 수 있음), 서버의 private
// sessionLog는 전혀 안 건드린다. 데모용 로컬 체인이라 블록 0부터 전부 스캔하고,
// `to`가 특정 주소와 같은지는 안 보고 calldata가 execute()로 디코딩되는지만 본다
// — 블록/트랜잭션 수가 많은 실제 체인에서는 이 전체 스캔 방식이 느려지므로 그대로
// 쓰면 안 된다.
app.post('/transactionHistory', async (req, res) => {
  const start = cursor();
  try {
    const latestHex = await rpcCall('eth_blockNumber', []);
    const latestBlock = Number(BigInt(latestHex));

    const history = [];
    for (let i = 0; i <= latestBlock; i++) {
      const block = await rpcCallGeneric('eth_getBlockByNumber', [`0x${i.toString(16)}`, true]);
      if (!block?.transactions?.length) continue;
      for (const tx of block.transactions) {
        const calldata = tx.data ?? tx.input;
        if (!tx.to || !calldata || calldata === '0x') continue;
        try {
          const decoded = walletInterface.decodeFunctionData('execute', calldata);
          history.push({
            txHash: tx.hash,
            blockNumber: i,
            to: tx.to,
            pk_i: decoded.pk_i.toString(),
            max_height: decoded.max_height.toString(),
          });
        } catch (err) {
          // execute()로 디코딩 안 되는 트랜잭션(PPIDWallet 배포, 무관한 트랜잭션 등)은 건너뜀.
        }
      }
    }

    console.log(`[WalletAgent][transactionHistory] found ${history.length} execute() call(s) across the chain ${ms(start)}`);
    res.json({ history });
  } catch (err) {
    console.error(`[WalletAgent][transactionHistory] error: ${err.message} ${ms(start)}`);
    res.status(400).json({ error: err.message });
  }
});

// 토큰은 첫 요청을 기다리지 않고 기동 시점에 바로 만들어둔다 — server.js의
// /api/mode2/wallet_agent_token이 이 프로세스에 요청이 오기 전에도 파일을
// 읽을 수 있어야 하기 때문이다 (닭이 먼저냐 달걀이 먼저냐 문제 방지).
getOrCreateAgentToken();

// 이 모듈을 직접 실행할 때만(= `node wallet_agent.js`) 참이 된다. 다른 파일이
// shouldReuseProof 등을 쓰려고 import만 해도 warm-up(수 초)과 app.listen(포트
// 점유)이라는 부작용이 따라오는 것을 막기 위한 가드.
const isDirectRun = process.argv[1] !== undefined
  && import.meta.url === pathToFileURL(process.argv[1]).href;

// REVOCATION_REGISTRY_ADDRESS가 없으면 프로세스는 정상 기동하지만 모든
// /submitTransaction이 나중에 400으로 실패한다(isRevocationRootPublished가 매
// 요청마다 던짐). 운영자가 기동 로그만 보고 정상이라 여기지 않도록, 서버를 실제로
// 띄우는 경우(isDirectRun)에는 여기서 즉시 검사해 못 박는다. import만 하는 테스트
// (예: tests/test_wallet_revocation_cache.js)는 isDirectRun이 false라 이 검사를
// 타지 않는다.
if (isDirectRun && !REVOCATION_REGISTRY_ADDRESS) {
  console.error('[WalletAgent] REVOCATION_REGISTRY_ADDRESS is not configured — every /submitTransaction would fail at request time. Refusing to start.');
  process.exit(1);
}

try {
  console.log('[WalletAgent] Initializing Poseidon...');
  poseidon = await buildPoseidon();
  console.log('[WalletAgent] Poseidon initialized.');

  // custom_idp.js/server.js처럼 기동 시점에 미리 만들어둔다 — 안 그러면 첫
  // Step 12 요청이 buildEddsa()의 무거운 WASM 초기화(Poseidon 외에도
  // pedersenHash/mimc7/mimcSponge까지 같이 빌드됨) 비용을 그대로 떠안는다.
  console.log('[WalletAgent] Initializing EdDSA-Poseidon...');
  await ensureEdDSA();
  console.log('[WalletAgent] EdDSA-Poseidon initialized.');

  if (isDirectRun) {
    console.log('[WalletAgent] Warming up pi_pk_i proof generation...');
    const warmupStart = now();
    await warmUpPiPkI();
    console.log(`[WalletAgent] pi_pk_i warm-up complete (${(now() - warmupStart).toFixed(0)}ms).`);

    app.listen(PORT, '127.0.0.1', () => {
      console.log(`[WalletAgent] Local wallet-side Step 8 agent listening on http://127.0.0.1:${PORT}`);
      console.log(`[WalletAgent] Accepting requests only from RP origin: ${RP_ORIGIN}`);
      console.log(`[WalletAgent] Requires X-Wallet-Agent-Token header (see wallet_state.json).`);
    });
  }
} catch (err) {
  console.error(`[WalletAgent] Failed to initialize Poseidon/EdDSA: ${err.message}`);
  process.exit(1);
}
