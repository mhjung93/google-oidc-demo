// TraceRegistry — PPID 마다 한 번 남기는 추적 기록과 개봉 요청(스펙 2026-11-26 ppid-account-trace §4.3·§5). hardhat 인프로세스 체인(contract 그룹).
// 실제 π_trace 를 만든다 — build/mode3/ 의 pi_trace zkey·wasm 이 필요하다(bash scripts/build_mode3_circuit.sh pi_trace).
import { expect } from 'chai';
import hre from 'hardhat';
import fs from 'node:fs';
import * as snarkjs from 'snarkjs';
import { dealAuditorKey, traceWitness, partialDecryptTrace, verifyPartial, combineTrace } from '../lib/mode3_trace_record.js';
import { proofToCalldata } from '../lib/mode3_onchain.js';
import { randomScalar } from '../lib/mode3_credential.js';
const { ethers } = hre;
const WASM = 'build/mode3/pi_trace_js/pi_trace.wasm', ZKEY = 'build/mode3/pi_trace_final.zkey';

describe('TraceRegistry', function () {
  this.timeout(120_000);
  let reg, key, a1, a2, a3, service, stranger, chainid;
  const ARID = 4242n;
  /** 한 사용자의 기록 재료: 증명·호출 인자. over 로 회로 입력의 키·체인을 바꾼다(다른 키·다른 체인으로 만든 증명). */
  async function material({ s_u = randomScalar(), arid = ARID, pk = key.pk, chain = chainid } = {}) {
    const w = await traceWitness({ s_u, arid, chainid: chain, pk_aud: pk });
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(w.input, WASM, ZKEY);
    const { a, b, c } = await proofToCalldata(proof, publicSignals);
    return { w, a, b, c, args: [w.PPID, arid, w.c1.x, w.c1.y, w.c2, a, b, c] };
  }
  before(function () { if (!fs.existsSync(ZKEY) || !fs.existsSync(WASM)) { console.log('    BLOCKED: build/mode3/pi_trace_* 가 없다 — bash scripts/build_mode3_circuit.sh pi_trace'); this.skip(); } });
  beforeEach(async () => {
    [, a1, a2, a3, service, stranger] = await ethers.getSigners();
    key = await dealAuditorKey();
    chainid = (await ethers.provider.getNetwork()).chainId;
    const verifier = await (await ethers.getContractFactory('TraceVerifier')).deploy();
    reg = await (await ethers.getContractFactory('TraceRegistry')).deploy(await verifier.getAddress(), key.pk.x, key.pk.y, [a1.address, a2.address, a3.address]);
  });

  it('올바른 증명이면 기록이 남고(제출자는 아무나), 같은 PPID 는 두 번 남기지 못한다', async () => {
    const m = await material();
    expect(await reg.has(m.w.PPID)).to.equal(false);
    await expect(reg.connect(stranger).register(...m.args)).to.emit(reg, 'TraceRegistered').withArgs(m.w.PPID, ARID);
    expect(await reg.has(m.w.PPID)).to.equal(true);
    const r = await reg.recordOf(m.w.PPID);
    expect([r.arid, r.c1x, r.c1y, r.c2]).to.deep.equal([ARID, m.w.c1.x, m.w.c1.y, m.w.c2]);
    expect(r.registeredAt).to.equal(BigInt(await ethers.provider.getBlockNumber()));
    await expect(reg.register(...m.args)).to.be.revertedWithCustomError(reg, 'AlreadyRegistered').withArgs(m.w.PPID);
  });
  it('암호문·PPID·arid 를 바꾸면 InvalidProof — 남의 증명에 자기 PPID 를 붙이지 못한다', async () => {
    const m = await material(), other = await material();
    const swap = (i, v) => { const x = [...m.args]; x[i] = v; return x; };
    for (const args of [swap(4, m.w.c2 + 1n), swap(2, other.w.c1.x), swap(1, ARID + 1n), swap(0, other.w.PPID)]) await expect(reg.register(...args)).to.be.revertedWithCustomError(reg, 'InvalidProof');
    expect(await reg.has(m.w.PPID)).to.equal(false); expect(await reg.has(other.w.PPID)).to.equal(false);
  });
  it('다른 감사자 키로 잠근 암호문·다른 체인을 위한 증명은 InvalidProof(공개 입력의 키·체인은 컨트랙트가 넣는다)', async () => {
    const otherKey = await dealAuditorKey();
    await expect(reg.register(...(await material({ pk: otherKey.pk })).args)).to.be.revertedWithCustomError(reg, 'InvalidProof');
    await expect(reg.register(...(await material({ chain: chainid + 1n })).args)).to.be.revertedWithCustomError(reg, 'InvalidProof');
  });
  it('개봉 요청: 기록이 있어야 하고, 이벤트에 요청자·사유 해시가 남는다 — 번호는 0부터', async () => {
    const m = await material(), reason = ethers.id('사유 1');
    await expect(reg.connect(service).requestOpen(m.w.PPID, reason)).to.be.revertedWithCustomError(reg, 'NotRegistered').withArgs(m.w.PPID);
    await reg.register(...m.args);
    await expect(reg.connect(service).requestOpen(m.w.PPID, reason)).to.emit(reg, 'OpenRequested').withArgs(0n, m.w.PPID, service.address, reason);
    await expect(reg.connect(stranger).requestOpen(m.w.PPID, ethers.id('사유 2'))).to.emit(reg, 'OpenRequested').withArgs(1n, m.w.PPID, stranger.address, ethers.id('사유 2'));
    expect(await reg.requestCount()).to.equal(2n);
    const q = await reg.requestOf(0n);
    expect([q.ppid, q.requester, q.reasonHash, q.shareBits]).to.deep.equal([m.w.PPID, service.address, reason, 0n]);
    await expect(reg.requestOf(2n)).to.be.revertedWithCustomError(reg, 'UnknownRequest');
    // 사용자 화면이 하는 일: 이벤트 전체를 받아 자기 PPID 로 거른다
    const logs = await reg.queryFilter(reg.filters.OpenRequested());
    expect(logs.filter((l) => l.args.ppid === m.w.PPID).length).to.equal(2);
  });
  it('조각을 냈다는 표시: 감사자만, 요청마다 한 번 — 순서가 조각의 번호다', async () => {
    const m = await material(); await reg.register(...m.args); await reg.connect(service).requestOpen(m.w.PPID, ethers.ZeroHash);
    const h = ethers.id('share');
    await expect(reg.connect(stranger).noteShare(0n, h)).to.be.revertedWithCustomError(reg, 'NotAuditor');
    await expect(reg.connect(a2).noteShare(5n, h)).to.be.revertedWithCustomError(reg, 'UnknownRequest');
    await expect(reg.connect(a2).noteShare(0n, h)).to.emit(reg, 'ShareSubmitted').withArgs(0n, 2, h);
    await expect(reg.connect(a2).noteShare(0n, h)).to.be.revertedWithCustomError(reg, 'AlreadySubmitted').withArgs(0n, 2);
    await expect(reg.connect(a3).noteShare(0n, h)).to.emit(reg, 'ShareSubmitted').withArgs(0n, 3, h);
    expect((await reg.requestOf(0n)).shareBits).to.equal(6n);   // 2번·3번
  });
  it('체인의 기록을 읽어 감사자 둘의 부분 복호로 그 사용자의 auid 가 나온다 — 하나로는 안 된다', async () => {
    const m = await material(); await reg.register(...m.args);
    const r = await reg.recordOf(m.w.PPID), c1 = { x: r.c1x, y: r.c1y };
    const p1 = await partialDecryptTrace(key.shares[0], c1), p3 = await partialDecryptTrace(key.shares[2], c1);
    expect(await verifyPartial(key.shares[0].X, c1, p1)).to.equal(true); expect(await verifyPartial(key.shares[2].X, c1, p3)).to.equal(true);
    expect(await combineTrace(r.c2, p1, p3)).to.equal(m.w.auid);
    let threw = false; try { await combineTrace(r.c2, p1, p1); } catch { threw = true; } expect(threw).to.equal(true);
  });
  it('감사자 주소가 비었거나 겹치면 배포되지 않는다', async () => {
    const v = await reg.verifier(), F = await ethers.getContractFactory('TraceRegistry');
    for (const list of [[a1.address, a1.address, a3.address], [a1.address, a2.address, ethers.ZeroAddress]]) await expect(F.deploy(v, key.pk.x, key.pk.y, list)).to.be.revertedWithCustomError(reg, 'BadAuditors');
  });
});
