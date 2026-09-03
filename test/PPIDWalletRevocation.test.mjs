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

    // 예전에는 pk_i = 0 + all-zero 서명으로 서명 검사를 건너뛰고 폐기 검사에 도달했다.
    // 그 경로는 2026-09-04에 막혔다(ecrecover의 address(0)이 address(uint160(0))과 같아
    // 서명 검사가 공허하게 통과하던 구멍). 이제는 진짜 세션 키로 서명해서 폐기 검사까지
    // 도달해야 한다 — 이 테스트가 보려는 것은 stale root 거부이지 서명 검사가 아니다.
    const sessionKey = ethers.Wallet.createRandom();
    const pk_i = BigInt(sessionKey.address);
    const { chainId } = await ethers.provider.getNetwork();
    const payloadHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ['uint256', 'address', 'address', 'uint256', 'bytes', 'uint256'],
        [chainId, await wallet.getAddress(), payload.to, payload.value, payload.data, payload.nonce],
      ),
    );
    const sig = sessionKey.signingKey.sign(payloadHash).serialized;

    await expect(
      wallet.execute(
        payload,
        sig,
        [0, 0], [[0, 0], [0, 0]], [0, 0],
        pk_i, 1n, 2n, 999999n,
        staleRoot,
      ),
    ).to.be.revertedWithCustomError(wallet, 'StaleRevocationRoot');
  });
});
