// 지갑의 참조 코드 대조(2026-09-23, 슬라이드 "검증자 주소를 cert_s 에" 공백의 해결책 B) — verifyReferenceCode 가 진짜 검증자·팩토리는
// 받고, 무엇이든 통과시키는 검증자를 가리키는 팩토리·팩토리 자리의 다른 컨트랙트·코드 없는 주소는 거절한다. hardhat 인프로세스 체인(contract 그룹).
import assert from 'node:assert';
import hre from 'hardhat';
import { verifyReferenceCode } from '../lib/mode3_onchain.js';

const { ethers } = hre;

describe('verifyReferenceCode', function () {
  this.timeout(60_000);
  let deployer, log;
  const ARGS = (verifier, logAddr) => [verifier, 1n, 2n, 3n, 4n, 5n, logAddr, 100n, 400n];

  before(async () => {
    [deployer] = await ethers.getSigners();
    log = await (await ethers.getContractFactory('RevocationLog')).deploy(deployer.address, ethers.ZeroHash);
  });

  it('진짜 PiCredVerifier 를 가리키는 진짜 팩토리는 ok', async () => {
    const verifier = await (await ethers.getContractFactory('PiCredVerifier')).deploy();
    const factory = await (await ethers.getContractFactory('Mode3WalletFactory')).deploy(...ARGS(await verifier.getAddress(), await log.getAddress()));
    assert.deepEqual(await verifyReferenceCode(ethers.provider, await factory.getAddress()), { ok: true });
  });

  it('immutable 값이 달라도(다른 arid·키·상한) 팩토리 코드 자체는 같으므로 ok — 값 대조는 checkService 의 몫', async () => {
    const verifier = await (await ethers.getContractFactory('PiCredVerifier')).deploy();
    const factory = await (await ethers.getContractFactory('Mode3WalletFactory')).deploy(await verifier.getAddress(), 99n, 98n, 97n, 96n, 95n, await log.getAddress(), 7n, 8n);
    assert.deepEqual(await verifyReferenceCode(ethers.provider, await factory.getAddress()), { ok: true });
  });

  it('무엇이든 통과시키는 검증자를 가리키는 팩토리는 verifier_code_mismatch', async () => {
    const fake = await (await ethers.getContractFactory('AcceptAllPiCredVerifier')).deploy();
    const factory = await (await ethers.getContractFactory('Mode3WalletFactory')).deploy(...ARGS(await fake.getAddress(), await log.getAddress()));
    assert.deepEqual(await verifyReferenceCode(ethers.provider, await factory.getAddress()), { ok: false, reason: 'verifier_code_mismatch' });
  });

  it('팩토리 자리에 다른 컨트랙트(검증자)가 있으면 factory_code_mismatch', async () => {
    const verifier = await (await ethers.getContractFactory('PiCredVerifier')).deploy();
    assert.deepEqual(await verifyReferenceCode(ethers.provider, await verifier.getAddress()), { ok: false, reason: 'factory_code_mismatch' });
  });

  it('코드 없는 주소는 no_code', async () => {
    assert.deepEqual(await verifyReferenceCode(ethers.provider, ethers.Wallet.createRandom().address), { ok: false, reason: 'no_code' });
  });
});
