import hre from 'hardhat';
import { expect } from 'chai';

const { ethers } = hre;

describe('RevocationRegistry', function () {
  const R = (n) => ethers.zeroPadValue(ethers.toBeHex(n), 32);

  async function deploy() {
    const [idp, other] = await ethers.getSigners();
    const F = await ethers.getContractFactory('RevocationRegistry');
    const reg = await F.deploy(idp.address);
    return { reg, idp, other };
  }

  it('accepts a root from the IdP and reports it as current', async function () {
    const { reg } = await deploy();
    await reg.pushRoot(R(1));
    expect(await reg.isCurrentRoot(R(1))).to.equal(true);
    expect(await reg.latestRoot()).to.equal(R(1));
  });

  it('rejects pushRoot from a non-IdP caller', async function () {
    const { reg, other } = await deploy();
    await expect(reg.connect(other).pushRoot(R(1))).to.be.revertedWithCustomError(reg, 'NotIdP');
  });

  // 핵심 변경: grace window와 K개 순환 버퍼가 사라졌으므로, root가 바뀌면 직전 root는
  // 그 즉시(같은 블록에서) 무효가 된다 — 더 이상 "아직 유효한 옛 root"라는 개념이 없다.
  it('invalidates the previous root the instant a new root is pushed', async function () {
    const { reg } = await deploy();
    await reg.pushRoot(R(1));
    expect(await reg.isCurrentRoot(R(1))).to.equal(true);

    await reg.pushRoot(R(2));
    expect(await reg.isCurrentRoot(R(1))).to.equal(false, 'previous root must be invalid immediately');
    expect(await reg.isCurrentRoot(R(2))).to.equal(true);
    expect(await reg.latestRoot()).to.equal(R(2));
  });

  it('reports an unknown root as not current', async function () {
    const { reg } = await deploy();
    await reg.pushRoot(R(1));
    expect(await reg.isCurrentRoot(R(42))).to.equal(false);
  });

  // 부트스트랩 전(latestRoot == 0)에는 0 root로도 통과해서는 안 된다 — 그렇지 않으면
  // 배포 직후 아무 root도 게시하지 않은 상태에서 revocationRoot=0으로 만든 증명이
  // 통과하는 구멍이 생긴다.
  it('treats every root as not current before any root has been published, including the zero root', async function () {
    const { reg } = await deploy();
    expect(await reg.latestRoot()).to.equal(R(0));
    expect(await reg.isCurrentRoot(R(0))).to.equal(false);
    expect(await reg.isCurrentRoot(R(1))).to.equal(false);
  });

  it('republishing the same root is a harmless no-op', async function () {
    const { reg } = await deploy();
    await reg.pushRoot(R(1));
    await reg.pushRoot(R(1));
    expect(await reg.isCurrentRoot(R(1))).to.equal(true);
    expect(await reg.latestRoot()).to.equal(R(1));
  });
});
