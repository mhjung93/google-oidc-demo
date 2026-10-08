// Mode3Log — 폐기 root + 등록부 root 를 한 트랜잭션에 게시(V9, 설계 2026-10-01 §4). hardhat 인프로세스 체인(contract 그룹).
import { expect } from 'chai';
import hre from 'hardhat';
import { createRevocationTree } from '../lib/mode3_revocation.js';
import { createRegistryTree } from '../lib/mode3_registry.js';
import { signPublicationV3, publicationDigestV3, rootToBytes32, signReceipt, receiptDigest } from '../lib/mode3_log.js';

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

  // 접수증 대기열 (V10 §4): IdP(cia)가 서명한 폐기 접수증을 누구나 올릴 수 있고, 다음 publish 는 그 슬롯을
  // 0 으로 실어야 통과한다. 통과하면 슬롯은 영구 은퇴돼 다시는 0 이 아닌 값을 받지 않는다.
  const receipt = async (wallet, slot, epochAtRequest, requestedAt) => signReceipt(wallet, { ...(await canon()), slot, epochAtRequest, requestedAt });
  it('접수증: CIA 서명만 받고 pendingSlots 에 적는다, 중복은 무해', async () => {
    const sig = await receipt(cia, 7, 0n, 1000n);
    await expect(log.connect(stranger).requestRevocation(7, 0n, 1000n, sig)).to.emit(log, 'RevocationRequested').withArgs(7, 0n);
    expect(await log.pendingSlots()).to.deep.equal([7n]);
    await log.requestRevocation(7, 0n, 1000n, sig);   // 두 번째는 no-op
    expect(await log.pendingSlots()).to.deep.equal([7n]);
    await expect(log.requestRevocation(8, 0n, 1000n, await receipt(stranger, 8, 0n, 1000n))).to.be.revertedWithCustomError(log, 'BadSignature');
    expect(await log.receiptDigestFor(7, 0n, 1000n)).to.equal(receiptDigest({ ...(await canon()), slot: 7, epochAtRequest: 0n, requestedAt: 1000n }));
  });
  it('강제: pending 슬롯이 0 으로 실리지 않은 publish 는 거절, 실리면 통과하고 슬롯은 은퇴', async () => {
    await log.requestRevocation(7, 0n, 1000n, await receipt(cia, 7, 0n, 1000n));
    const bad = { revRoot: b32(1n), regRoot: b32(2n), epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [] };
    await expect(log.publish(bad.revRoot, bad.regRoot, 1n, [], [], [], await sign(cia, bad))).to.be.revertedWithCustomError(log, 'PendingRevocationNotApplied').withArgs(7);
    const bad2 = { ...bad, slotIdx: [7], slotLeaves: [b32(5n)] };   // 0 이 아닌 값으로는 안 된다
    await expect(log.publish(bad2.revRoot, bad2.regRoot, 1n, [], [7], [b32(5n)], await sign(cia, bad2))).to.be.revertedWithCustomError(log, 'PendingRevocationNotApplied').withArgs(7);
    const ok = { ...bad, slotIdx: [7], slotLeaves: [b32(0n)] };
    await expect(log.publish(ok.revRoot, ok.regRoot, 1n, [], [7], [b32(0n)], await sign(cia, ok))).to.emit(log, 'SlotRetired').withArgs(7, 1n);
    expect(await log.pendingSlots()).to.deep.equal([]);
    expect(await log.isRetired(7)).to.equal(true);
    const reuse = { ...bad, epoch: 2n, slotIdx: [7], slotLeaves: [b32(9n)] };
    await expect(log.publish(reuse.revRoot, reuse.regRoot, 2n, [], [7], [b32(9n)], await sign(cia, reuse))).to.be.revertedWithCustomError(log, 'SlotIsRetired').withArgs(7);
    const zeroAgain = { ...bad, epoch: 2n, slotIdx: [7], slotLeaves: [b32(0n)] };   // 0 으로 다시 쓰는 건 허용(멱등)
    await log.publish(zeroAgain.revRoot, zeroAgain.regRoot, 2n, [], [7], [b32(0n)], await sign(cia, zeroAgain));
  });
  it('강제: pending 슬롯이 slotIdx 에 여러 번 실리면 전부 0 이어야 한다(중복 항목으로 우회 불가, 2026-10-02 수정)', async () => {
    await log.requestRevocation(7, 0n, 1000n, await receipt(cia, 7, 0n, 1000n));
    const decoy = { revRoot: b32(1n), regRoot: b32(2n), epoch: 1n, revLeaves: [], slotIdx: [7, 7], slotLeaves: [b32(0n), b32(42n)] };   // 0 짜리를 먼저 넣고 진짜 값을 뒤에 넣는 미끼
    await expect(log.publish(decoy.revRoot, decoy.regRoot, 1n, [], [7, 7], [b32(0n), b32(42n)], await sign(cia, decoy))).to.be.revertedWithCustomError(log, 'PendingRevocationNotApplied').withArgs(7);
    const dup = { ...decoy, slotLeaves: [b32(0n), b32(0n)] };   // 중복이라도 전부 0 이면 통과(멱등)
    await expect(log.publish(dup.revRoot, dup.regRoot, 1n, [], [7, 7], [b32(0n), b32(0n)], await sign(cia, dup))).to.emit(log, 'SlotRetired').withArgs(7, 1n);
    expect(await log.isRetired(7)).to.equal(true);
  });
  it('은퇴된 슬롯에 대한 접수증은 no-op', async () => {
    await log.requestRevocation(7, 0n, 1000n, await receipt(cia, 7, 0n, 1000n));
    const ok = { revRoot: b32(1n), regRoot: b32(2n), epoch: 1n, revLeaves: [], slotIdx: [7], slotLeaves: [b32(0n)] };
    await log.publish(ok.revRoot, ok.regRoot, 1n, [], [7], [b32(0n)], await sign(cia, ok));
    expect(await log.isRetired(7)).to.equal(true);
    await expect(log.requestRevocation(7, 1n, 2000n, await receipt(cia, 7, 1n, 2000n))).to.not.emit(log, 'RevocationRequested');
    expect(await log.pendingSlots()).to.deep.equal([]);
  });
});
