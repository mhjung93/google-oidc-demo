// Mode 3 온체인 실행 유틸 — 설계 2026-09-18 §5·§6. 지갑 에이전트(서명·제출), 서비스(팩토리 배포·calldata 디코드),
// 컨트랙트 테스트가 전부 여기 하나를 쓴다. 컨트랙트와 바이트 단위로 맞아야 하는 것(payload digest, ABI)만 둔다.
// 테스트 헬퍼 tests/helpers/mode3_chain.mjs(:8545 노드용) 와는 별개다.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import * as snarkjs from 'snarkjs';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));

/** 스펙 §5.3: root 게시 뒤 이만큼 블록이 지나면 지갑이 RootTooOld 로 멈춘다. CIA 하트비트 간격(50)보다 넉넉히. */
export const MAX_ROOT_AGE_DEFAULT = 100n;

export const WALLET_ABI = [
  'function ppid() view returns (uint256)',
  'function arid() view returns (uint256)',
  'function nonce() view returns (uint256)',
  'function maxRootAge() view returns (uint64)',
  'function execute((address to,uint256 value,bytes data,uint256 nonce) payload, bytes sig, uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[14] pub) returns (bool)',
  'event Executed(uint256 indexed nonceUsed, address indexed to, uint256 value, bool success)',
  'event Mode3Auth(uint256 indexed nonceUsed, uint256 pk_i, uint256 maxHeight, uint256 allowAgent, uint256 tagC1X, uint256 tagC1Y, uint256 tagC2)',
  'error NonceMismatch(uint256 expected, uint256 got)',
  'error BadSignature()',
  'error WrongWallet()',
  'error UntrustedKeys()',
  'error BadAllowAgent()',
  'error BadTag()',
  'error StaleRevocationRoot(bytes32 root)',
  'error RootTooOld(uint256 lastPublished, uint256 current)',
  'error Expired(uint256 currentBlock, uint256 maxHeight)',
  'error InvalidProof()',
];
export const FACTORY_ABI = [
  'function computeAddress(uint256 ppid) view returns (address)',
  'function deploy(uint256 ppid) returns (address)',
  'function arid() view returns (uint256)',
  'function verifier() view returns (address)',
  'function log() view returns (address)',
];
export const walletInterface = new ethers.Interface(WALLET_ABI);

/** Mode3Wallet.execute 의 서명 digest: keccak256(abi.encode(chainid, wallet, to, value, data, nonce)). */
export function payloadDigest({ chainId, wallet, to, value, data, nonce }) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['uint256', 'address', 'address', 'uint256', 'bytes', 'uint256'],
    [chainId, wallet, to, value, data, nonce],
  ));
}

/** 세션키(ethers.Wallet)로 raw digest 에 secp256k1 서명. EIP-191 없음 — 컨트랙트가 ecrecover(hash) 를 그대로 쓴다. v ∈ {27, 28}. */
export function signPayload(sessionWallet, fields) {
  return ethers.Signature.from(sessionWallet.signingKey.sign(payloadDigest(fields))).serialized;
}

/** snarkjs 증명을 execute 인자(a, b, c, pub) 로. pub 은 hex 문자열 14개 — ethers 가 uint256 으로 받는다. */
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
  let executed = null, auth = null;
  for (const l of receipt.logs ?? []) {
    if (target && l.address?.toLowerCase() !== target) continue;
    let p = null;
    try { p = walletInterface.parseLog({ topics: [...l.topics], data: l.data }); } catch { continue; }
    if (!p) continue;
    if (p.name === 'Executed') executed = { nonceUsed: p.args.nonceUsed, to: p.args.to, value: p.args.value, success: p.args.success };
    if (p.name === 'Mode3Auth') auth = { nonceUsed: p.args.nonceUsed, pk_i: p.args.pk_i, maxHeight: p.args.maxHeight, allowAgent: p.args.allowAgent, tag: { c1x: p.args.tagC1X, c1y: p.args.tagC1Y, c2: p.args.tagC2 } };
  }
  return { executed, auth };
}

/** hardhat 아티팩트. 없으면 컴파일부터 하라고 알린다 — 조용히 hardhat 을 부르지 않는다(서버 기동 중 컴파일은 느리고 놀랍다). */
export function readArtifact(name) {
  const p = path.join(ROOT_DIR, 'artifacts', 'contracts', `${name}.sol`, `${name}.json`);
  if (!fs.existsSync(p)) throw new Error(`${p} 가 없다 — 먼저 npx hardhat compile`);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

export async function deployVerifier(signer) {
  const { abi, bytecode } = readArtifact('PiCredVerifier');
  const c = await new ethers.ContractFactory(abi, bytecode, signer).deploy();
  await c.waitForDeployment();
  return c.getAddress();
}

/** 서비스가 자기 팩토리를 배포한다(§6.1). pkCIA·pkTrace 는 {x, y} bigint. */
export async function deployFactory(signer, { verifierAddress, arid, pkCIA, pkTrace, logAddress, maxRootAge = MAX_ROOT_AGE_DEFAULT }) {
  const { abi, bytecode } = readArtifact('Mode3WalletFactory');
  const c = await new ethers.ContractFactory(abi, bytecode, signer).deploy(
    verifierAddress, BigInt(arid), BigInt(pkCIA.x), BigInt(pkCIA.y), BigInt(pkTrace.x), BigInt(pkTrace.y), logAddress, BigInt(maxRootAge),
  );
  await c.waitForDeployment();
  return c.getAddress();
}

export const factoryAt = (address, runner) => new ethers.Contract(address, FACTORY_ABI, runner);
export const walletAt = (address, runner) => new ethers.Contract(address, WALLET_ABI, runner);
