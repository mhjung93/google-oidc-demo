// Mode3Mirror — 응용 체인에서 폐기 체인의 캐노니컬 Mode3Log 를 거울처럼 비추는 컨트랙트(V10 설계 §2·§3·§5).
// hardhat 인프로세스 체인(contract 그룹). 신뢰 근거는 IdP(cia) 서명뿐 — 제출자는 아무나.
import { expect } from 'chai';
import hre from 'hardhat';
import { createRevocationTree } from '../lib/mode3_revocation.js';
import { createRegistryTree } from '../lib/mode3_registry.js';
import { signPublicationV3, entryHashes, rootToBytes32 } from '../lib/mode3_log.js';
const { ethers } = hre;
const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(n), 32);
describe('Mode3Mirror', () => {
  let log, mirror, cia, relayer, stranger, emptyRev, emptyReg, canon;
  beforeEach(async () => {
    [, cia, relayer, stranger] = await ethers.getSigners();
    emptyRev = rootToBytes32((await createRevocationTree()).getRoot()); emptyReg = rootToBytes32((await createRegistryTree()).root());
    log = await (await ethers.getContractFactory('Mode3Log')).deploy(cia.address, emptyRev, emptyReg);
    canon = { canonicalChainId: (await ethers.provider.getNetwork()).chainId, canonicalLogAddress: await log.getAddress() };
    mirror = await (await ethers.getContractFactory('Mode3Mirror')).deploy(cia.address, canon.canonicalChainId, canon.canonicalLogAddress, emptyRev, emptyReg);
  });
  it('캐노니컬에 올린 서명을 그대로 거울에 올리면 같은 root·epoch 가 적힌다(제출자는 아무나)', async () => {
    const p = { revRoot: b32(9n), regRoot: b32(8n), epoch: 1n, revLeaves: [b32(1n)], slotIdx: [7], slotLeaves: [b32(70n)] };
    const sig = await signPublicationV3(cia, { ...canon, ...p });
    await log.publish(p.revRoot, p.regRoot, p.epoch, p.revLeaves, p.slotIdx, p.slotLeaves, [], [], sig);
    const h = entryHashes(p);
    await expect(mirror.connect(relayer).publish(p.revRoot, p.regRoot, p.epoch, h.hLeaves, h.hIdx, h.hSlots, [], [], sig)).to.emit(mirror, 'Mirrored').withArgs(1n, p.revRoot, p.regRoot);
    expect(await mirror.revRoot()).to.equal(p.revRoot); expect(await mirror.regRoot()).to.equal(p.regRoot); expect(await mirror.epoch()).to.equal(1n);
    expect(await mirror.lastPublishedBlock()).to.equal(BigInt(await ethers.provider.getBlockNumber()));
    expect(await mirror.digestFor(p.revRoot, p.regRoot, p.epoch, h.hLeaves, h.hIdx, h.hSlots, h.hBoundKeys, h.hBoundValues)).to.equal(await log.digestFor(p.revRoot, p.regRoot, p.epoch, p.revLeaves, p.slotIdx, p.slotLeaves, [], []));
  });
  it('epoch 미증가·남의 서명·다른 캐노니컬(주소)의 서명은 거절', async () => {
    const p = { revRoot: b32(1n), regRoot: b32(2n), epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [] };
    const h = entryHashes(p);
    await expect(mirror.publish(p.revRoot, p.regRoot, 0n, h.hLeaves, h.hIdx, h.hSlots, [], [], await signPublicationV3(cia, { ...canon, ...p, epoch: 0n }))).to.be.revertedWithCustomError(mirror, 'EpochNotIncreasing');
    await expect(mirror.publish(p.revRoot, p.regRoot, 1n, h.hLeaves, h.hIdx, h.hSlots, [], [], await signPublicationV3(stranger, { ...canon, ...p }))).to.be.revertedWithCustomError(mirror, 'BadSignature');
    await expect(mirror.publish(p.revRoot, p.regRoot, 1n, h.hLeaves, h.hIdx, h.hSlots, [], [], await signPublicationV3(cia, { ...canon, canonicalLogAddress: stranger.address, ...p }))).to.be.revertedWithCustomError(mirror, 'BadSignature');
  });
  it('건너뛴 epoch 도 받는다(거울은 뒤처질 수 있다)', async () => {
    const p = { revRoot: b32(1n), regRoot: b32(2n), epoch: 5n, revLeaves: [], slotIdx: [], slotLeaves: [] };
    const h = entryHashes(p);
    await mirror.publish(p.revRoot, p.regRoot, 5n, h.hLeaves, h.hIdx, h.hSlots, [], [], await signPublicationV3(cia, { ...canon, ...p }));
    expect(await mirror.epoch()).to.equal(5n);
  });
  it('bound 배열은 거울도 그대로 받아 sessionBoundOf 에 적고(c+1), 다이제스트가 캐노니컬과 같다; 서명 뒤 바꾸면 BadSignature', async () => {
    const p = { revRoot: b32(9n), regRoot: b32(8n), epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [], boundKeys: [0xaaan, 0xbbbn], boundValues: [2, 0] };
    const sig = await signPublicationV3(cia, { ...canon, ...p });
    const h = entryHashes(p);
    expect(await mirror.digestFor(p.revRoot, p.regRoot, p.epoch, h.hLeaves, h.hIdx, h.hSlots, h.hBoundKeys, h.hBoundValues)).to.equal(await log.digestFor(p.revRoot, p.regRoot, p.epoch, [], [], [], p.boundKeys, p.boundValues));
    await expect(mirror.publish(p.revRoot, p.regRoot, 1n, h.hLeaves, h.hIdx, h.hSlots, p.boundKeys, [2, 1], sig)).to.be.revertedWithCustomError(mirror, 'BadSignature');
    const tx = mirror.connect(relayer).publish(p.revRoot, p.regRoot, 1n, h.hLeaves, h.hIdx, h.hSlots, p.boundKeys, p.boundValues, sig);
    await expect(tx).to.emit(mirror, 'SessionBoundPublished').withArgs(0xaaan, 2, 1n);
    expect(await mirror.sessionBoundOf(0xaaan)).to.equal(3n); expect(await mirror.sessionBoundOf(0xbbbn)).to.equal(1n);
    expect(await mirror.revSupersededAt(emptyRev)).to.equal(BigInt(await ethers.provider.getBlockNumber()));
    expect(await mirror.isAcceptableRevRoot(emptyRev, 5)).to.equal(true);
  });
  it('epoch 을 건너뛴 중계에도 그 페이로드의 bound 가 실린다(IdP 가 누적해 다시 보낸다 — 건너뛴 게시의 값은 여기서 유실되지 않는다)', async () => {
    const p = { revRoot: b32(1n), regRoot: b32(2n), epoch: 5n, revLeaves: [], slotIdx: [], slotLeaves: [], boundKeys: [7n], boundValues: [4] };
    const h = entryHashes(p);
    await mirror.publish(p.revRoot, p.regRoot, 5n, h.hLeaves, h.hIdx, h.hSlots, p.boundKeys, p.boundValues, await signPublicationV3(cia, { ...canon, ...p }));
    expect(await mirror.epoch()).to.equal(5n);
    expect(await mirror.sessionBoundOf(7n)).to.equal(5n);
  });
});
