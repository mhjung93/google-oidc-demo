// AttrGate v2 — 설계 2026-09-23 §4.2: 집합 root + block.timestamp 기반 나이. hardhat 인프로세스 체인(contract 그룹).
import { expect } from 'chai';
import assert from 'node:assert';
import hre from 'hardhat';
import { setRoot } from '../lib/mode3_set_tree.js';

const { ethers } = hre;

describe('AttrGate v2', function () {
  this.timeout(60_000);
  let gate;
  before(async () => {
    const [deployer] = await ethers.getSigners();
    // isWallet 은 view 함수라 EOA(코드 없는 주소)를 넘기면 Solidity 의 자동 extcodesize 검사가
    // require 의 메시지보다 먼저 빈 데이터로 revert 한다 — "not a mode3 wallet" 를 실제로 관찰하려면
    // isWallet(address) 를 실제로 구현한 컨트랙트가 필요하다. 이 팩토리는 실제로 지갑을 배포하지
    // 않으므로 verifier·log 는 아무 주소나 된다.
    const Factory = await ethers.getContractFactory('Mode3WalletFactory');
    const factory = await Factory.deploy(ethers.ZeroAddress, 0n, 0n, 0n, 0n, 0n, ethers.ZeroAddress, 100n, 400n);
    const Gate = await ethers.getContractFactory('AttrGate');
    gate = await Gate.deploy(await factory.getAddress(), await setRoot([410, 392, 840, 276, 250]), 19n);
  });

  it('yearOf: UTC 연도 경계 — 1970-01-01, 2000-02-29, 2026-12-31 23:59:59, 2027-01-01 00:00:00, 2100-03-01', async () => {
    const cases = [0, Date.UTC(2000, 1, 29) / 1000, Date.UTC(2026, 11, 31, 23, 59, 59) / 1000, Date.UTC(2027, 0, 1) / 1000, Date.UTC(2100, 2, 1) / 1000, Date.UTC(1999, 11, 31, 23, 59, 59) / 1000];
    for (const ts of cases) assert.equal(await gate.yearOf(ts), BigInt(new Date(ts * 1000).getUTCFullYear()), `ts=${ts}`);
  });

  it('생성자 값이 immutable 로 남는다', async () => {
    assert.equal(await gate.allowedCountriesRoot(), await setRoot([250, 276, 392, 410, 840]));
    assert.equal(await gate.minAge(), 19n);
  });

  it('claim: 팩토리가 배포한 지갑이 아니면 revert', async () => {
    await expect(gate.claim()).to.be.revertedWith('not a mode3 wallet');
  });
});
