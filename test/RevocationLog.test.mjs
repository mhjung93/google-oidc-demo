// RevocationLog — 폐기 체인 컨트랙트. hardhat 인프로세스 체인. (contract 그룹)
import { expect } from 'chai';
import hre from 'hardhat';
import { createRevocationTree } from '../lib/mode3_revocation.js';

const { ethers } = hre;
const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes('MODE3_REVOCATION_ROOT_V1'));
const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(n), 32);

async function signPub(wallet, root, epoch, leaves) {
  const leavesHash = ethers.keccak256(ethers.solidityPacked(leaves.map(() => 'bytes32'), leaves));
  const inner = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'bytes32', 'uint64', 'bytes32'], [DOMAIN, root, epoch, leavesHash]));
  return wallet.signMessage(ethers.getBytes(inner));
}

describe('RevocationLog', () => {
  let log, cia, relayer, stranger, emptyRoot;
  beforeEach(async () => {
    [, cia, relayer, stranger] = await ethers.getSigners();
    emptyRoot = b32((await createRevocationTree()).getRoot());
    const F = await ethers.getContractFactory('RevocationLog');
    log = await F.deploy(cia.address, emptyRoot);
  });

  it('초기 상태: 빈 트리 root, epoch 0', async () => {
    expect(await log.root()).to.equal(emptyRoot);
    expect(await log.epoch()).to.equal(0n);
    expect(await log.cia()).to.equal(cia.address);
  });

  it('CIA 서명 게시: root·epoch 갱신, 리프 이벤트', async () => {
    const leaves = [b32(111n), b32(222n)];
    const newRoot = b32(999n);
    const sig = await signPub(cia, newRoot, 1n, leaves);
    await expect(log.connect(relayer).publishRoot(newRoot, 1n, leaves, sig))
      .to.emit(log, 'Revoked').withArgs(1n, newRoot, leaves);
    expect(await log.root()).to.equal(newRoot);
    expect(await log.epoch()).to.equal(1n);
  });

  it('제출자는 아무나여도 된다 (권한은 서명에 있다)', async () => {
    const sig = await signPub(cia, b32(1n), 1n, []);
    await log.connect(stranger).publishRoot(b32(1n), 1n, [], sig);
    expect(await log.epoch()).to.equal(1n);
  });

  it('CIA 가 아닌 키의 서명은 거절된다', async () => {
    const sig = await signPub(stranger, b32(1n), 1n, []);
    await expect(log.publishRoot(b32(1n), 1n, [], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
  });

  it('epoch 가 오르지 않으면 거절된다 (재생 방지)', async () => {
    await log.publishRoot(b32(1n), 1n, [], await signPub(cia, b32(1n), 1n, []));
    await expect(log.publishRoot(b32(2n), 1n, [], await signPub(cia, b32(2n), 1n, [])))
      .to.be.revertedWithCustomError(log, 'EpochNotIncreasing');
    await expect(log.publishRoot(b32(2n), 0n, [], await signPub(cia, b32(2n), 0n, [])))
      .to.be.revertedWithCustomError(log, 'EpochNotIncreasing');
  });

  it('서명된 것과 다른 리프 배열을 붙이면 거절된다 (calldata 오염 방지)', async () => {
    const sig = await signPub(cia, b32(5n), 1n, [b32(1n)]);
    await expect(log.publishRoot(b32(5n), 1n, [b32(2n)], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
    await expect(log.publishRoot(b32(5n), 1n, [], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
  });

  it('digestFor 가 JS 와 같은 digest 를 준다', async () => {
    const leaves = [b32(7n)];
    const leavesHash = ethers.keccak256(ethers.solidityPacked(['bytes32'], leaves));
    const inner = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ['bytes32', 'bytes32', 'uint64', 'bytes32'], [DOMAIN, b32(9n), 3n, leavesHash]));
    expect(await log.digestFor(b32(9n), 3n, leaves)).to.equal(inner);
  });
});
