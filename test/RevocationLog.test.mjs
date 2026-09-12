// RevocationLog — 폐기 체인 컨트랙트. hardhat 인프로세스 체인. (contract 그룹)
import { expect } from 'chai';
import hre from 'hardhat';
import { createRevocationTree } from '../lib/mode3_revocation.js';
import { signRootPublication, publicationDigest } from '../lib/mode3_log.js';

const { ethers } = hre;
const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(n), 32);

// digest 계산은 lib/mode3_log.js 하나만 쓴다(CIA 가 실제로 쓰는 코드) — 여기 사본을 두면 lib 이
// 드리프트해도 이 테스트가 잡지 못한다.
const signPubFor = async (target, wallet, root, epoch, leaves) =>
  signRootPublication(wallet, { logAddress: await target.getAddress(), root, epoch, leaves });

describe('RevocationLog', () => {
  let log, cia, relayer, stranger, emptyRoot;
  const signPub = (wallet, root, epoch, leaves) => signPubFor(log, wallet, root, epoch, leaves);
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

  it('같은 CIA 키로 배포한 다른 로그의 게시를 재생하면 거절된다 (digest 가 로그 주소를 덮는다)', async () => {
    // CIA 이더 키를 유지한 채 로그를 재배포하면 옛 로그의 공개 calldata (root, epoch, leaves, sig) 를
    // 새 로그에 그대로 제출할 수 있었다. 그러면 새 로그의 root 가 옛 트리로 바뀌어 지갑 재구성이 전부 막힌다.
    const F = await ethers.getContractFactory('RevocationLog');
    const other = await F.deploy(cia.address, emptyRoot);
    const leaves = [b32(111n)];
    const sigForLog = await signPub(cia, b32(5n), 1n, leaves);
    await log.publishRoot(b32(5n), 1n, leaves, sigForLog);
    await expect(other.publishRoot(b32(5n), 1n, leaves, sigForLog)).to.be.revertedWithCustomError(other, 'BadSignature');
    // 그 로그를 위해 새로 서명하면 된다
    await other.publishRoot(b32(5n), 1n, leaves, await signPubFor(other, cia, b32(5n), 1n, leaves));
    expect(await other.epoch()).to.equal(1n);
  });

  it('digestFor 가 JS(lib/mode3_log.js) 와 같은 digest 를 준다', async () => {
    const leaves = [b32(7n)];
    const inner = publicationDigest({ logAddress: await log.getAddress(), root: b32(9n), epoch: 3n, leaves });
    expect(await log.digestFor(b32(9n), 3n, leaves)).to.equal(inner);
  });
});
