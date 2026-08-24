import hre from 'hardhat';
import { expect } from 'chai';

const { ethers } = hre;

describe('PPIDWallet revocation root check', function () {
  it('reverts when the proof root is not in the registry window', async function () {
    const [idp] = await ethers.getSigners();

    const Reg = await ethers.getContractFactory('RevocationRegistry');
    const reg = await Reg.deploy(idp.address);
    await reg.pushRoot(ethers.zeroPadValue(ethers.toBeHex(1), 32));

    const Verifier = await ethers.getContractFactory('PiPkIVerifier');
    const verifier = await Verifier.deploy();

    const Wallet = await ethers.getContractFactory('PPIDWallet');
    const wallet = await Wallet.deploy(123n, await verifier.getAddress(), 1n, 2n, await reg.getAddress());

    const payload = { to: idp.address, value: 0, data: '0x', nonce: 0 };
    const staleRoot = ethers.zeroPadValue(ethers.toBeHex(999), 32);

    await expect(
      wallet.execute(
        payload,
        '0x' + '00'.repeat(65),
        [0, 0], [[0, 0], [0, 0]], [0, 0],
        0, 1n, 2n, 999999n,
        staleRoot,
      ),
    ).to.be.revertedWithCustomError(wallet, 'StaleRevocationRoot');
  });
});
