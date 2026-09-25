// Mode 3 온체인 실행 유틸 — 설계 2026-09-18 §5·§6. 지갑 에이전트(서명·제출), 서비스(팩토리 배포·calldata 디코드),
// 컨트랙트 테스트가 전부 여기 하나를 쓴다. 컨트랙트와 바이트 단위로 맞아야 하는 것(payload digest, ABI)만 둔다.
// 테스트 헬퍼 tests/helpers/mode3_chain.mjs(:8545 노드용) 와는 별개다.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import * as snarkjs from 'snarkjs';
import { setRoot } from './mode3_set_tree.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));

/** 스펙 §5.3: root 게시 뒤 이만큼 블록이 지나면 지갑이 RootTooOld 로 멈춘다. CIA 하트비트 간격(50)보다 넉넉히. */
export const MAX_ROOT_AGE_DEFAULT = 100n;
/** 스펙 §3.2(갱신): 지갑이 정한 max_height 의 상한 — 검증자는 head ≤ max_height ≤ head + L 을 요구한다. 지갑 기본 TTL 300 + 그리드 100 = 400. */
export const MAX_LIFETIME_DEFAULT = 400n;

/** 지갑이 서비스 팩토리에서 받아들이는 두 상한의 범위(2026-09-25 리뷰 I-3). 참조 코드 대조(verifyReferenceCode)는
 *  immutable 자리를 0 으로 지우고 비교하므로 이 두 생성자 인자는 코드로 잡히지 않는다 — 값으로 직접 본다.
 *  위쪽은 기본값의 2배·4배까지(서비스가 운영 사정에 맞춰 고를 여지는 남긴다), 아래쪽은 0 을 막는다:
 *  maxRootAge 가 크면 AA 가 게시를 멈춰도 온체인 실행이 계속되고(폐기 신선도 상실), 0 이면 그 팩토리로 만든 계정의
 *  모든 execute 가 revert 한다(주소가 이 인자들로 결정돼 다른 값으로 재배포할 수 없어 보낸 자산이 영구 동결된다). */
export const FACTORY_MAX_ROOT_AGE_BAND = Object.freeze({ min: 1n, max: 2n * MAX_ROOT_AGE_DEFAULT });     // 1..200 블록
export const FACTORY_MAX_LIFETIME_BAND = Object.freeze({ min: 1n, max: 4n * MAX_LIFETIME_DEFAULT });     // 1..1600 블록

export const WALLET_ABI = [
  'function ppid() view returns (uint256)',
  'function arid() view returns (uint256)',
  'function nonce() view returns (uint256)',
  'function maxRootAge() view returns (uint64)',
  'function maxLifetime() view returns (uint64)',
  'function execute((address to,uint256 value,bytes data,uint256 nonce) payload, bytes sig, uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[25] pub) returns (bool)',
  'event Executed(uint256 indexed nonceUsed, address indexed to, uint256 value, bool success)',
  'event Mode3Auth(uint256 indexed nonceUsed, uint256 pk_i, uint256 maxHeight, uint256 allowAgent, uint256 tagC1X, uint256 tagC1Y, uint256 tagC2)',
  'event Disclosure(uint256 indexed nonceUsed, uint256 mask, uint256[4] lo, uint256[4] hi, uint256 setSel, uint256 setRoot)',
  'error NonceMismatch(uint256 expected, uint256 got)',
  'error BadSignature()',
  'error WrongWallet()',
  'error UntrustedKeys()',
  'error BadAllowAgent()',
  'error BadTag()',
  'error StaleRevocationRoot(bytes32 root)',
  'error RootTooOld(uint256 lastPublished, uint256 current)',
  'error Expired(uint256 currentBlock, uint256 maxHeight)',
  'error TooFarExpiry(uint256 currentBlock, uint256 maxHeight)',
  'error InvalidProof()',
  'error BadDisclosure()',
];
export const FACTORY_ABI = [
  'function computeAddress(uint256 ppid) view returns (address)',
  'function deploy(uint256 ppid) returns (address)',
  'function arid() view returns (uint256)',
  'function verifier() view returns (address)',
  'function log() view returns (address)',
  'function pkCIAX() view returns (uint256)',
  'function pkCIAY() view returns (uint256)',
  'function pkTraceX() view returns (uint256)',
  'function pkTraceY() view returns (uint256)',
  'function maxRootAge() view returns (uint64)',
  'function maxLifetime() view returns (uint64)',
  'function isWallet(address) view returns (bool)',
];
export const ATTR_GATE_ABI = [
  'function claim()',
  'function claimed(address) view returns (bool)',
  'function factory() view returns (address)',
  'function allowedCountriesRoot() view returns (uint256)',
  'function minAge() view returns (uint64)',
  'function yearOf(uint256) pure returns (uint256)',
  'event Claimed(address indexed wallet, uint64 birthYearHi, uint256 setRoot)',
];
export const walletInterface = new ethers.Interface(WALLET_ABI);

/**
 * Mode3Wallet.execute 의 서명 digest:
 * keccak256(abi.encode(chainid, wallet, to, value, data, nonce, discMask, discLo, discHi, setSel, setRoot,
 *                      maxHeight, allowAgent, tagC1X, tagC1Y, tagC2)).
 * discMask/discLo/discHi/setSel/setRoot 는 π 의 pub[14]·pub[15..18]·pub[19..22]·pub[23]·pub[24]
 * (2026-09-22 §5.1, V7 §4.2) — 다이제스트가 공개 값 11워드 전부를 덮어야 같은 세션키·같은 mask/sel 의 π 를
 * 다른 대상용 lo/hi/setRoot 로 바꿔 끼우지 못한다(리뷰 수정 1).
 * maxHeight/allowAgent/tagC1X/tagC1Y/tagC2 는 π 의 pub[3]·pub[5]·pub[11..13] 이다(2026-09-25 리뷰 A-2):
 * 이것들이 빠져 있으면 릴레이어가 σ 는 그대로 두고 같은 사용자·같은 세션키의 다른 π 로 바꿔 끼워, 지갑이 내는
 * Mode3Auth 가 이번 실행을 인가하지 않은 만료·에이전트 허용·개봉 태그를 남기게 된다.
 * 이 다섯에는 **기본값을 두지 않는다** — 안 넘긴 호출부가 조용히 (0 으로 서명한) 틀린 σ 를 만들면 그 실패는
 * 검증 시점에 BadSignature 로만 보여 원인을 찾기 어렵다. 넘겨야 할 값은 언제나 그 π 의 공개 입력 그대로다.
 */
export function payloadDigest({ chainId, wallet, to, value, data, nonce, discMask = 0n, discLo = [0n, 0n, 0n, 0n], discHi = [0n, 0n, 0n, 0n], setSel = 0n, setRoot = 0n, maxHeight, allowAgent, tagC1X, tagC1Y, tagC2 }) {
  for (const [k, v] of [['maxHeight', maxHeight], ['allowAgent', allowAgent], ['tagC1X', tagC1X], ['tagC1Y', tagC1Y], ['tagC2', tagC2]]) {
    if (v === undefined || v === null) throw new Error(`payloadDigest: ${k} 필수 — π 의 공개 입력(pub[3]·pub[5]·pub[11..13])을 그대로 넘겨라`);
  }
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['uint256', 'address', 'address', 'uint256', 'bytes', 'uint256', 'uint256', 'uint256[4]', 'uint256[4]', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256'],
    [chainId, wallet, to, value, data, nonce, discMask, discLo, discHi, setSel, setRoot, maxHeight, allowAgent, tagC1X, tagC1Y, tagC2],
  ));
}

/** π 의 공개 입력에서 다이제스트의 성명 쪽 다섯 필드를 뽑는다(2026-09-25 리뷰 A-2). 서명하는 쪽은 언제나 이것을 그대로 쓴다 —
 *  요청이나 세션 기록에서 따로 조립하면 이번에 붙일 π 와 어긋난 σ 가 나온다. pub 은 10진 문자열 25개(snarkjs publicSignals)
 *  또는 hex/bigint 배열(proofToCalldata 의 pub) 둘 다 된다. 색인은 여기 한 곳에만 둔다. */
export const statementDigestFields = (pub) => ({
  maxHeight: BigInt(pub[3]), allowAgent: BigInt(pub[5]),
  tagC1X: BigInt(pub[11]), tagC1Y: BigInt(pub[12]), tagC2: BigInt(pub[13]),
});

/** 세션키(ethers.Wallet)로 raw digest 에 secp256k1 서명. EIP-191 없음 — 컨트랙트가 ecrecover(hash) 를 그대로 쓴다. v ∈ {27, 28}. */
export function signPayload(sessionWallet, fields) {
  return ethers.Signature.from(sessionWallet.signingKey.sign(payloadDigest(fields))).serialized;
}

/** snarkjs 증명을 execute 인자(a, b, c, pub) 로. pub 은 hex 문자열 25개 — ethers 가 uint256 으로 받는다. */
export async function proofToCalldata(proof, publicSignals) {
  const [a, b, c, pub] = JSON.parse('[' + (await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)) + ']');
  return { a, b, c, pub };
}

/** execute 트랜잭션의 calldata 를 되돌린다. 서비스가 트랜잭션 해시로 개봉 재료를 꺼낼 때 쓴다(§6.2). execute 가 아니면 null. */
export function decodeExecuteCalldata(data) {
  let parsed;
  try { parsed = walletInterface.parseTransaction({ data }); } catch { return null; }
  if (!parsed || parsed.name !== 'execute') return null;
  const [payload, sig, a, b, c, pub] = parsed.args;
  return {
    payload: { to: payload.to, value: payload.value, data: payload.data, nonce: payload.nonce },
    sig,
    a: a.map((v) => BigInt(v).toString()),
    b: b.map((row) => row.map((v) => BigInt(v).toString())),
    c: c.map((v) => BigInt(v).toString()),
    pub: pub.map((v) => BigInt(v).toString()),
  };
}

/**
 * 영수증에서 Executed·Mode3Auth 를 뽑는다. 없으면 각각 null.
 * payload.to 가 악의적 컨트랙트면 내부 호출 중 같은 topic0 의 가짜 Mode3Auth 를 낼 수 있어,
 * 발신 주소로 거른다(지갑은 이벤트를 내부 호출 뒤에 내지만, 그 순서에만 기대지 않는다).
 * walletAddress 를 주면 그 주소의 로그만, 안 주면 receipt.to(트랜잭션 수신 주소) 를 기준으로
 * 거른다 — 둘 다 없을 때만 전부 본다.
 */
export function parseExecuteReceipt(receipt, walletAddress = null) {
  const target = (walletAddress ?? receipt.to ?? null)?.toLowerCase() ?? null;
  let executed = null, auth = null, disclosure = null;
  for (const l of receipt.logs ?? []) {
    if (target && l.address?.toLowerCase() !== target) continue;
    let p = null;
    try { p = walletInterface.parseLog({ topics: [...l.topics], data: l.data }); } catch { continue; }
    if (!p) continue;
    if (p.name === 'Executed') executed = { nonceUsed: p.args.nonceUsed, to: p.args.to, value: p.args.value, success: p.args.success };
    if (p.name === 'Mode3Auth') auth = { nonceUsed: p.args.nonceUsed, pk_i: p.args.pk_i, maxHeight: p.args.maxHeight, allowAgent: p.args.allowAgent, tag: { c1x: p.args.tagC1X, c1y: p.args.tagC1Y, c2: p.args.tagC2 } };
    if (p.name === 'Disclosure') disclosure = { mask: p.args.mask, lo: [...p.args.lo], hi: [...p.args.hi], setSel: p.args.setSel, setRoot: p.args.setRoot };
  }
  return { executed, auth, disclosure };
}

/** hardhat 아티팩트. 없으면 컴파일부터 하라고 알린다 — 조용히 hardhat 을 부르지 않는다(서버 기동 중 컴파일은 느리고 놀랍다). */
export function readArtifact(name) {
  const p = path.join(ROOT_DIR, 'artifacts', 'contracts', `${name}.sol`, `${name}.json`);
  if (!fs.existsSync(p)) throw new Error(`${p} 가 없다 — 먼저 npx hardhat compile`);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

/**
 * 참조 코드 대조(2026-09-23 — 슬라이드 "검증자 주소를 cert_s 에" 공백의 해결책 B). 지갑은 팩토리의 immutable 값만 getter 로 대조했고
 * 팩토리가 가리키는 Groth16 검증자와 팩토리 코드 자체는 보지 않았다 — "무엇이든 통과시키는 검증자"를 가리키는 팩토리를 주면
 * 공개 입력을 증명자가 고르므로 공격자가 pk_i 를 자기 키로 넣어 그 계정을 비울 수 있다. 여기서는 지갑이 이미 신뢰하는 자기 빌드
 * (artifacts/ — zkey·vkey 와 같은 근거)의 deployedBytecode 와 온체인 코드를 비교한다. 검증자는 immutable 이 없어 정확 일치,
 * 팩토리는 build-info 의 immutableReferences 자리를 0 으로 지운 뒤 비교한다(생성자 값은 checkService 가 getter 로 대조).
 * 계정 컨트랙트 코드는 팩토리 안에 박혀 있어 팩토리가 진짜면 자동으로 보증된다.
 */
let referenceCodeP = null;
function loadReferenceCode() {
  return (referenceCodeP ??= Promise.resolve().then(() => {
    const masked = (name) => {
      const artifact = readArtifact(name);
      const dbgPath = path.join(ROOT_DIR, 'artifacts', 'contracts', `${name}.sol`, `${name}.dbg.json`);
      const dbg = JSON.parse(fs.readFileSync(dbgPath, 'utf8'));
      const buildInfo = JSON.parse(fs.readFileSync(path.resolve(path.dirname(dbgPath), dbg.buildInfo), 'utf8'));
      const refs = buildInfo.output.contracts[`contracts/${name}.sol`][name].evm.deployedBytecode.immutableReferences ?? {};
      const slots = Object.values(refs).flat().map(({ start, length }) => [start, length]);
      const code = maskSlots(ethers.getBytes(artifact.deployedBytecode), slots);
      return { hash: ethers.keccak256(code), length: code.length, slots };
    };
    return { factory: masked('Mode3WalletFactory'), verifier: masked('PiCredVerifier') };
  }));
}
function maskSlots(bytes, slots) {
  const out = Uint8Array.from(bytes);
  for (const [start, length] of slots) out.fill(0, start, start + length);
  return out;
}
/** 팩토리와 그 검증자의 온체인 코드를 참조 빌드와 대조한다. { ok:true } | { ok:false, reason: 'no_code' | 'factory_code_mismatch' | 'verifier_code_mismatch' }. */
export async function verifyReferenceCode(provider, factoryAddress) {
  const ref = await loadReferenceCode();
  const factoryCode = ethers.getBytes(await provider.getCode(factoryAddress));
  if (factoryCode.length === 0) return { ok: false, reason: 'no_code' };
  if (factoryCode.length !== ref.factory.length || ethers.keccak256(maskSlots(factoryCode, ref.factory.slots)) !== ref.factory.hash) {
    return { ok: false, reason: 'factory_code_mismatch' };
  }
  const verifierAddress = await factoryAt(factoryAddress, provider).verifier();
  const verifierCode = await provider.getCode(verifierAddress);
  if (ethers.keccak256(verifierCode) !== ref.verifier.hash) return { ok: false, reason: 'verifier_code_mismatch' };
  return { ok: true };
}

export async function deployVerifier(signer) {
  const { abi, bytecode } = readArtifact('PiCredVerifier');
  const c = await new ethers.ContractFactory(abi, bytecode, signer).deploy();
  await c.waitForDeployment();
  return c.getAddress();
}

/** 서비스가 자기 팩토리를 배포한다(§6.1). pkCIA·pkTrace 는 {x, y} bigint. */
export async function deployFactory(signer, { verifierAddress, arid, pkCIA, pkTrace, logAddress, maxRootAge = MAX_ROOT_AGE_DEFAULT, maxLifetime = MAX_LIFETIME_DEFAULT }) {
  const { abi, bytecode } = readArtifact('Mode3WalletFactory');
  const c = await new ethers.ContractFactory(abi, bytecode, signer).deploy(
    verifierAddress, BigInt(arid), BigInt(pkCIA.x), BigInt(pkCIA.y), BigInt(pkTrace.x), BigInt(pkTrace.y), logAddress, BigInt(maxRootAge), BigInt(maxLifetime),
  );
  await c.waitForDeployment();
  return c.getAddress();
}

export const factoryAt = (address, runner) => new ethers.Contract(address, FACTORY_ABI, runner);
export const walletAt = (address, runner) => new ethers.Contract(address, WALLET_ABI, runner);

export const ALLOWED_COUNTRIES_DEFAULT = Object.freeze([410n, 392n, 840n, 276n, 250n]);   // KR·JP·US·DE·FR (ISO 3166 numeric)
export const MIN_AGE_DEFAULT = 19n;
/** 데모 대상 v2(§4.2). root 는 여기서 계산한다 — 하드코딩 금지(lib/mode3_set_tree.js 가 유일한 정의). */
export async function deployAttrGate(signer, { factoryAddress, allowedCountries = ALLOWED_COUNTRIES_DEFAULT, minAge = MIN_AGE_DEFAULT }) {
  const { abi, bytecode } = readArtifact('AttrGate');
  const c = await new ethers.ContractFactory(abi, bytecode, signer).deploy(factoryAddress, await setRoot(allowedCountries), BigInt(minAge));
  await c.waitForDeployment();
  return c.getAddress();
}
export const attrGateAt = (address, runner) => new ethers.Contract(address, ATTR_GATE_ABI, runner);
