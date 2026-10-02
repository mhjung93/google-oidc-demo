// Mode3Log — 폐기 root + 등록부 root 를 한 트랜잭션에 게시(V9, 설계 2026-10-01 §4). hardhat 인프로세스 체인(contract 그룹).
import { expect } from 'chai';
import hre from 'hardhat';
import { createRevocationTree } from '../lib/mode3_revocation.js';
import { createRegistryTree } from '../lib/mode3_registry.js';
import { signPublicationV3, publicationDigestV3, rootToBytes32 } from '../lib/mode3_log.js';

const { ethers } = hre;
const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(n), 32);

describe('Mode3Log', () => {
  let log, cia, relayer, stranger, emptyRev, emptyReg;
  const canon = async () => ({ canonicalChainId: (await ethers.provider.getNetwork()).chainId, canonicalLogAddress: await log.getAddress() });
  const sign = async (wallet, p) => signPublicationV3(wallet, { ...(await canon()), ...p });
  beforeEach(async () => {
    [, cia, relayer, stranger] = await ethers.getSigners();
    emptyRev = rootToBytes32((await createRevocationTree()).getRoot());
    emptyReg = rootToBytes32((await createRegistryTree()).root());
    log = await (await ethers.getContractFactory('Mode3Log')).deploy(cia.address, emptyRev, emptyReg);
  });

  it('초기 상태: 빈 root 둘, epoch 0, lastPublishedBlock = 배포 블록', async () => {
    expect(await log.revRoot()).to.equal(emptyRev);
    expect(await log.regRoot()).to.equal(emptyReg);
    expect(await log.epoch()).to.equal(0n);
    expect(await log.lastPublishedBlock()).to.equal(BigInt(await ethers.provider.getBlockNumber()));
  });
  it('게시: 두 root 갱신, Revoked 1건 + SlotUpdated n건, 제출자는 아무나', async () => {
    const p = { revRoot: b32(9n), regRoot: b32(8n), epoch: 1n, revLeaves: [b32(1n)], slotIdx: [7, 9], slotLeaves: [b32(70n), b32(90n)] };
    const sig = await sign(cia, p);
    const tx = log.connect(relayer).publish(p.revRoot, p.regRoot, p.epoch, p.revLeaves, p.slotIdx, p.slotLeaves, sig);
    await expect(tx).to.emit(log, 'Revoked').withArgs(1n, p.revRoot, p.revLeaves);
    await expect(tx).to.emit(log, 'SlotUpdated').withArgs(1n, 7, b32(70n));
    await expect(tx).to.emit(log, 'SlotUpdated').withArgs(1n, 9, b32(90n));
    expect(await log.revRoot()).to.equal(p.revRoot); expect(await log.regRoot()).to.equal(p.regRoot); expect(await log.epoch()).to.equal(1n);
    expect(await log.lastPublishedBlock()).to.equal(BigInt(await ethers.provider.getBlockNumber()));
  });
  it('하트비트: 리프·슬롯 없이 같은 root 를 새 epoch 로 재게시하면 lastPublishedBlock 만 바뀐다', async () => {
    await ethers.provider.send('hardhat_mine', ['0x5']);
    const p = { revRoot: emptyRev, regRoot: emptyReg, epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [] };
    await log.publish(p.revRoot, p.regRoot, p.epoch, [], [], [], await sign(cia, p));
    expect(await log.lastPublishedBlock()).to.equal(BigInt(await ethers.provider.getBlockNumber()));
  });
  it('CIA 가 아닌 서명·epoch 미증가·길이 불일치·서명과 다른 인자는 거절', async () => {
    const p = { revRoot: b32(1n), regRoot: b32(2n), epoch: 1n, revLeaves: [], slotIdx: [1], slotLeaves: [b32(5n)] };
    await expect(log.publish(p.revRoot, p.regRoot, 1n, [], [1], [b32(5n)], await sign(stranger, p))).to.be.revertedWithCustomError(log, 'BadSignature');
    await expect(log.publish(p.revRoot, p.regRoot, 0n, [], [1], [b32(5n)], await sign(cia, { ...p, epoch: 0n }))).to.be.revertedWithCustomError(log, 'EpochNotIncreasing');
    await expect(log.publish(p.revRoot, p.regRoot, 1n, [], [1, 2], [b32(5n)], await sign(cia, p))).to.be.revertedWithCustomError(log, 'LengthMismatch');
    const sig = await sign(cia, p);
    await expect(log.publish(p.revRoot, b32(3n), 1n, [], [1], [b32(5n)], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
    await expect(log.publish(p.revRoot, p.regRoot, 1n, [], [2], [b32(5n)], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
    await expect(log.publish(p.revRoot, p.regRoot, 1n, [], [1], [b32(6n)], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
  });
  it('다른 로그의 게시를 재생하면 거절 (digest 가 주소를 덮는다)', async () => {
    const other = await (await ethers.getContractFactory('Mode3Log')).deploy(cia.address, emptyRev, emptyReg);
    const p = { revRoot: b32(1n), regRoot: b32(2n), epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [] };
    const sig = await sign(cia, p);
    await log.publish(p.revRoot, p.regRoot, 1n, [], [], [], sig);
    await expect(other.publish(p.revRoot, p.regRoot, 1n, [], [], [], sig)).to.be.revertedWithCustomError(other, 'BadSignature');
  });
  it('digestFor 가 JS publicationDigestV3 와 같다 (chainid·주소를 덮는다)', async () => {
    const p = { revRoot: b32(9n), regRoot: b32(8n), epoch: 3n, revLeaves: [b32(7n)], slotIdx: [4], slotLeaves: [b32(44n)] };
    expect(await log.digestFor(p.revRoot, p.regRoot, p.epoch, p.revLeaves, p.slotIdx, p.slotLeaves)).to.equal(publicationDigestV3({ ...(await canon()), ...p }));
    expect(await log.DOMAIN()).to.equal(ethers.keccak256(ethers.toUtf8Bytes('MODE3_LOG_V3')));
  });
});
