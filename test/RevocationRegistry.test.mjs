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

  it('accepts a root from the IdP and reports it as recent', async function () {
    const { reg } = await deploy();
    await reg.pushRoot(R(1));
    expect(await reg.isRecentRoot(R(1))).to.equal(true);
    expect(await reg.latestRoot()).to.equal(R(1));
  });

  it('rejects pushRoot from a non-IdP caller', async function () {
    const { reg, other } = await deploy();
    await expect(reg.connect(other).pushRoot(R(1))).to.be.revertedWithCustomError(reg, 'NotIdP');
  });

  it('keeps the most recent K roots and evicts older ones', async function () {
    const { reg } = await deploy();
    for (let i = 1; i <= 8; i++) await reg.pushRoot(R(i));
    expect(await reg.isRecentRoot(R(1))).to.equal(true);
    await reg.pushRoot(R(9));
    expect(await reg.isRecentRoot(R(1))).to.equal(false, 'oldest root must be evicted');
    expect(await reg.isRecentRoot(R(9))).to.equal(true);
    expect(await reg.isRecentRoot(R(2))).to.equal(true);
  });

  it('reports an unknown root as not recent', async function () {
    const { reg } = await deploy();
    await reg.pushRoot(R(1));
    expect(await reg.isRecentRoot(R(42))).to.equal(false);
  });
});
