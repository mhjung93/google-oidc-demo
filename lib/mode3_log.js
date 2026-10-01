// Mode 3 로그 컨트랙트와 JS 쪽이 바이트 단위로 맞춰야 하는 것만 모은다: ABI 조각, root 게시 digest, bytes32
// 변환. CIA(cia.js)·RP·지갑 라이브러리·테스트 헬퍼·컨트랙트 테스트가 전부 여기 하나를 쓴다 — 예전에는 cia.js,
// tests/helpers/mode3_chain.mjs, test/RevocationLog.test.mjs 에 같은 계산이 세 벌 있어 digest 에 로그 주소를
// 넣을 때 셋을 다 고쳐야 했고, 드리프트는 테스트가 못 잡고 실배포의 BadSignature 로만 드러났다(2026-09-12
// 리뷰 반영). V1(contracts/RevocationLog.sol, 폐기 전용)은 Mode 2·test/RevocationLog.test.mjs 가 그대로
// 쓰고, V9 등록부 이후의 Mode 3 는 아래 V2(contracts/Mode3Log.sol, 폐기+등록부 겸용)를 쓴다(2026-10-01).
import { ethers } from 'ethers';

export const DOMAIN_ROOT = ethers.keccak256(ethers.toUtf8Bytes('MODE3_REVOCATION_ROOT_V1'));

export const LOG_ABI = [
  'function root() view returns (bytes32)',
  'function epoch() view returns (uint64)',
  'function lastPublishedBlock() view returns (uint64)',
  'function publishRoot(bytes32 newRoot, uint64 newEpoch, bytes32[] leaves, bytes sig)',
  'event Revoked(uint64 indexed epoch, bytes32 root, bytes32[] leaves)',
];

export const rootToBytes32 = (n) => ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32);

/**
 * RevocationLog.digestFor() 와 같은 내부 digest: keccak(abi.encode(DOMAIN, address(log), root, epoch,
 * keccak(leaves))). leaves 는 bytes32 hex 배열. 서명이 리프 배열까지 덮어 릴레이어의 calldata 오염을
 * 막고, 로그 주소를 덮어 같은 CIA 키로 재배포한 다른 로그에 옛 게시를 재생하지 못하게 한다.
 * chainid 는 넣지 않는다(설계 §6.5).
 */
export function publicationDigest({ logAddress, root, epoch, leaves }) {
  if (!logAddress) throw new Error('publicationDigest: logAddress 가 필요하다 (digest 가 로그 주소를 덮는다)');
  const leavesHash = ethers.keccak256(ethers.solidityPacked(leaves.map(() => 'bytes32'), leaves));
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'address', 'bytes32', 'uint64', 'bytes32'], [DOMAIN_ROOT, logAddress, root, epoch, leavesHash]));
}

/** 위 digest 에 EIP-191 personal_sign. 컨트랙트는 recover 결과를 cia 주소와 대조한다. */
export function signRootPublication(wallet, params) {
  return wallet.signMessage(ethers.getBytes(publicationDigest(params)));
}

// ---- V2 (Mode3Log, 2026-10-01 등록부) — 옛 V1 상수·함수는 RevocationLog.test·Mode 2 가 쓰므로 남긴다 ----
export const DOMAIN_LOG_V2 = ethers.keccak256(ethers.toUtf8Bytes('MODE3_LOG_V2'));
export const MODE3_LOG_ABI = [
  'function cia() view returns (address)',
  'function revRoot() view returns (bytes32)',
  'function regRoot() view returns (bytes32)',
  'function epoch() view returns (uint64)',
  'function lastPublishedBlock() view returns (uint64)',
  'function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] revLeaves, uint32[] slotIdx, bytes32[] slotLeaves) view returns (bytes32)',
  'function publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] revLeaves, uint32[] slotIdx, bytes32[] slotLeaves, bytes sig)',
  'event Revoked(uint64 indexed epoch, bytes32 root, bytes32[] leaves)',
  'event SlotUpdated(uint64 indexed epoch, uint32 index, bytes32 leaf)',
];
/**
 * Mode3Log.digestFor() 와 같은 내부 digest. revLeaves·slotLeaves 는 bytes32 hex 배열, slotIdx 는 정수 배열.
 * slotIdx 는 uint32 값이지만 32바이트로 패킹한다 — Solidity 의 `abi.encodePacked(uint32[] calldata)` 는
 * (일반 scalar 인자와 달리) 배열 원소를 타입 폭대로 빡빡하게 패킹하지 않고 32바이트로 패딩한다("array elements
 * are padded, but still encoded in-place", Solidity ABI spec Non-standard Packed Mode). 처음에 ethers 의
 * solidityPacked 로 'uint32' 를 써서 4바이트로 좁혀 패킹했더니 digestFor 와 어긋났다(test/Mode3Log.test.mjs
 * 로 발견, 2026-10-01) — bytes32 는 이미 32바이트라 revLeaves·slotLeaves 는 이 함정에 걸리지 않는다.
 */
export function publicationDigestV2({ logAddress, revRoot, regRoot, epoch, revLeaves, slotIdx, slotLeaves }) {
  if (!logAddress) throw new Error('publicationDigestV2: logAddress 가 필요하다');
  if (slotIdx.length !== slotLeaves.length) throw new Error('publicationDigestV2: slotIdx 와 slotLeaves 길이가 다르다');
  const packed = (types, vals) => ethers.keccak256(vals.length ? ethers.solidityPacked(types, vals) : '0x');
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'address', 'bytes32', 'bytes32', 'uint64', 'bytes32', 'bytes32', 'bytes32'],
    [DOMAIN_LOG_V2, logAddress, revRoot, regRoot, epoch, packed(revLeaves.map(() => 'bytes32'), revLeaves), packed(slotIdx.map(() => 'uint256'), slotIdx), packed(slotLeaves.map(() => 'bytes32'), slotLeaves)],
  ));
}
export function signPublicationV2(wallet, params) {
  return wallet.signMessage(ethers.getBytes(publicationDigestV2(params)));
}
