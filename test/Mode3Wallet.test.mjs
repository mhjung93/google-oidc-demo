// Mode3Wallet / Mode3WalletFactory — 설계 2026-09-18 §5. hardhat 인프로세스 체인(contract 그룹).
// 증명은 tests/helpers/mode3_fixture.mjs 의 픽스처로 실제로 만든다(build/mode3 산출물 필요).
import { expect } from 'chai';
import assert from 'node:assert';
import hre from 'hardhat';
import fs from 'node:fs';
import * as snarkjs from 'snarkjs';
import { buildValidInput } from '../tests/helpers/mode3_fixture.mjs';
import { signRootPublication, rootToBytes32 } from '../lib/mode3_log.js';
import { signPayload, proofToCalldata, decodeExecuteCalldata, parseExecuteReceipt, MAX_ROOT_AGE_DEFAULT, MAX_LIFETIME_DEFAULT } from '../lib/mode3_onchain.js';

const { ethers } = hre;
const WASM = 'build/mode3/pi_cred_js/pi_cred.wasm', ZKEY = 'build/mode3/pi_cred_final.zkey';

describe('Mode3Wallet', function () {
  this.timeout(180_000);
  before(() => { if (!fs.existsSync(ZKEY)) throw new Error(`${ZKEY} 없음 — bash scripts/build_mode3_circuit.sh`); });

  const chainId = () => ethers.provider.getNetwork().then((n) => n.chainId);

  /** 세션키 + 픽스처 증명. 옵션은 픽스처로 전달. */
  async function statement(opts = {}) {
    const session = ethers.Wallet.createRandom();
    // 만료는 지갑이 정한다 — 컨트랙트가 head + maxLifetime 상한을 강제하므로 현재 블록 기준으로 정한다
    const maxHeight = opts.maxHeight ?? BigInt(await ethers.provider.getBlockNumber()) + 300n;
    const fx = await buildValidInput({ pk_i: BigInt(session.address), chainid: await chainId(), ...opts, maxHeight });
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(fx.input, WASM, ZKEY);
    const cd = await proofToCalldata(proof, publicSignals);
    return { session, fx, proof, publicSignals, ...cd };
  }

  /** 픽스처의 root 로 RevocationLog 를 배포하고(초기 root = 픽스처 트리), 검증자·팩토리·지갑까지. */
  async function deployStack(st, { arid = st.fx.arid, maxRootAge = MAX_ROOT_AGE_DEFAULT, maxLifetime = MAX_LIFETIME_DEFAULT } = {}) {
    const [deployer, cia] = await ethers.getSigners();
    const Log = await ethers.getContractFactory('RevocationLog');
    const log = await Log.deploy(cia.address, rootToBytes32(BigInt(st.input().revRoot)));
    const Verifier = await ethers.getContractFactory('PiCredVerifier');
    const verifier = await Verifier.deploy();
    const Factory = await ethers.getContractFactory('Mode3WalletFactory');
    const factory = await Factory.deploy(await verifier.getAddress(), arid, st.fx.ciaPub.x, st.fx.ciaPub.y, st.fx.pk_trace.x, st.fx.pk_trace.y, await log.getAddress(), maxRootAge, maxLifetime);
    const ppid = BigInt(st.input().PPID);
    const walletAddr = await factory.computeAddress(ppid);
    await (await deployer.sendTransaction({ to: walletAddr, value: ethers.parseEther('1') })).wait();
    await (await factory.deploy(ppid)).wait();
    const wallet = await ethers.getContractAt('Mode3Wallet', walletAddr);
    return { deployer, cia, log, verifier, factory, wallet, walletAddr, ppid };
  }
  const withInput = (st) => ({ ...st, input: () => st.fx.input });

  async function signedPayload(st, wallet, { to = ethers.Wallet.createRandom().address, value = 0n, data = '0x', discMask = 0n, discLo = [0n, 0n, 0n, 0n], discHi = [0n, 0n, 0n, 0n] } = {}) {
    const nonce = await wallet.nonce();
    const payload = { to, value, data, nonce };
    const sig = signPayload(st.session, { chainId: await chainId(), wallet: wallet.target, ...payload, discMask, discLo, discHi });
    return { payload, sig };
  }

  let ST;   // 공통 성명 — 증명 생성이 1초쯤이라 케이스 간 공유한다(체인은 케이스마다 새로 배포)
  before(async () => { ST = withInput(await statement()); });

  it('정상 실행: 값 전송, nonce 증가, Executed·Mode3Auth 이벤트, gas 기록', async () => {
    const { wallet } = await deployStack(ST);
    const recipient = ethers.Wallet.createRandom().address;
    const { payload, sig } = await signedPayload(ST, wallet, { to: recipient, value: ethers.parseEther('0.1') });
    const tx = await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub);
    const receipt = await tx.wait();
    expect(await ethers.provider.getBalance(recipient)).to.equal(ethers.parseEther('0.1'));
    expect(await wallet.nonce()).to.equal(1n);
    const { executed, auth } = parseExecuteReceipt(receipt);
    expect(executed.success).to.equal(true);
    expect(auth.pk_i).to.equal(BigInt(ST.session.address));
    expect(auth.maxHeight).to.equal(BigInt(ST.fx.input.max_height));
    expect(auth.allowAgent).to.equal(0n);
    expect(auth.tag.c2).to.equal(ST.fx.tag.c2);
    console.log(`      execute() gas: ${receipt.gasUsed}`);
    // 발신 주소 필터: 지갑 주소를 명시해도 같은 결과, 엉뚱한 주소를 주면 아무것도 안 찾는다
    // (payload.to 가 악의적이면 내부 호출 중 같은 이름의 가짜 이벤트를 낼 수 있다).
    const filtered = parseExecuteReceipt(receipt, wallet.target);
    expect(filtered.executed.success).to.equal(true);
    expect(filtered.auth.tag.c2).to.equal(ST.fx.tag.c2);
    const wrongTarget = parseExecuteReceipt(receipt, ethers.Wallet.createRandom().address);
    expect(wrongTarget).to.deep.equal({ executed: null, auth: null, disclosure: null });
  });

  it('allowAgent = 1 성명은 이벤트에 1 로 남는다', async () => {
    const st = withInput(await statement({ allowAgent: 1n }));
    const { wallet } = await deployStack(st);
    const { payload, sig } = await signedPayload(st, wallet);
    const receipt = await (await wallet.execute(payload, sig, st.a, st.b, st.c, st.pub)).wait();
    expect(parseExecuteReceipt(receipt).auth.allowAgent).to.equal(1n);
  });

  it('같은 π 로 두 번째 트랜잭션도 된다(세션 안 재사용) — nonce 만 다르다', async () => {
    const { wallet } = await deployStack(ST);
    for (let i = 0; i < 2; i++) {
      const { payload, sig } = await signedPayload(ST, wallet);
      await (await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).wait();
    }
    expect(await wallet.nonce()).to.equal(2n);
  });

  it('nonce 재사용은 NonceMismatch', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    await (await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).wait();
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'NonceMismatch');
  });

  it('다른 키의 서명·손상된 서명은 BadSignature', async () => {
    const { wallet } = await deployStack(ST);
    const { payload } = await signedPayload(ST, wallet);
    const other = ethers.Wallet.createRandom();
    const wrong = signPayload(other, { chainId: await chainId(), wallet: wallet.target, ...payload });
    await expect(wallet.execute(payload, wrong, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
    await expect(wallet.execute(payload, '0x' + '11'.repeat(64) + '00', ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
  });

  it('가변 서명(malleated: s → n-s, v 뒤집기)은 BadSignature (RevocationLog 와 같은 기준)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
    const r = sig.slice(0, 66);
    const s = BigInt('0x' + sig.slice(66, 130));
    const v = parseInt(sig.slice(130, 132), 16);
    const flippedS = (N - s).toString(16).padStart(64, '0');
    const flippedV = (v === 27 ? 28 : 27).toString(16).padStart(2, '0');
    const malleated = r + flippedS + flippedV;
    await expect(wallet.execute(payload, malleated, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
  });

  it('다른 지갑 주소로 서명한 payload 는 BadSignature (도메인 분리)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload } = await signedPayload(ST, wallet);
    const sig = signPayload(ST.session, { chainId: await chainId(), wallet: ethers.Wallet.createRandom().address, ...payload });
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
  });

  it('공개 입력의 PPID·arid·chainid 가 지갑과 다르면 WrongWallet (다른 계정·다른 서비스·다른 체인의 성명 재생)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const otherPpid = [...ST.pub]; otherPpid[0] = '0x1';
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, otherPpid)).to.be.revertedWithCustomError(wallet, 'WrongWallet');
    const otherArid = [...ST.pub]; otherArid[1] = '0x1';
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, otherArid)).to.be.revertedWithCustomError(wallet, 'WrongWallet');
    const otherChain = [...ST.pub]; otherChain[4] = '0x1';
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, otherChain)).to.be.revertedWithCustomError(wallet, 'WrongWallet');
  });

  it('다른 arid 로 배포한 팩토리의 지갑에는 이 성명이 들어가지 않는다 (WrongWallet)', async () => {
    const { wallet } = await deployStack(ST, { arid: 5n });
    const { payload, sig } = await signedPayload(ST, wallet);
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'WrongWallet');
  });

  it('pk_CIA·pk_trace 가 다르면 UntrustedKeys', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const p = [...ST.pub]; p[9] = '0x1';
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, p)).to.be.revertedWithCustomError(wallet, 'UntrustedKeys');
  });

  it('allowAgent = 2 는 BadAllowAgent (증명 검증 전에 걸린다)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const p = [...ST.pub]; p[5] = '0x2';
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, p)).to.be.revertedWithCustomError(wallet, 'BadAllowAgent');
  });

  it('c1 이 항등원(r = 0)이면 BadTag (증명 검증 전에 걸린다)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const p = [...ST.pub]; p[11] = '0x0'; p[12] = '0x1';
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, p)).to.be.revertedWithCustomError(wallet, 'BadTag');
  });

  it('root 가 게시로 바뀌면 옛 π 는 StaleRevocationRoot', async () => {
    const { wallet, log, cia } = await deployStack(ST);
    const newRoot = rootToBytes32(12345n);
    const sig = await signRootPublication(cia, { logAddress: await log.getAddress(), root: newRoot, epoch: 1n, leaves: [] });
    await (await log.publishRoot(newRoot, 1n, [], sig)).wait();
    const sp = await signedPayload(ST, wallet);
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'StaleRevocationRoot');
  });

  it('root 게시가 maxRootAge 블록보다 오래되면 RootTooOld, 하트비트(같은 root 재게시) 뒤엔 다시 된다', async () => {
    const { wallet, log, cia } = await deployStack(ST, { maxRootAge: 10n });
    await ethers.provider.send('hardhat_mine', ['0xb']);   // 11 블록
    const sp = await signedPayload(ST, wallet);
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'RootTooOld');
    const root = await log.root();
    const sig = await signRootPublication(cia, { logAddress: await log.getAddress(), root, epoch: 1n, leaves: [] });
    await (await log.publishRoot(root, 1n, [], sig)).wait();
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.not.be.reverted;
  });

  it('max_height 가 block.number + maxLifetime 을 넘으면 TooFarExpiry (지갑이 정한 만료의 상한)', async () => {
    const st = withInput(await statement({ maxHeight: BigInt(await ethers.provider.getBlockNumber()) + 10_000n }));
    const { wallet } = await deployStack(st);
    const { payload, sig } = await signedPayload(st, wallet);
    await expect(wallet.execute(payload, sig, st.a, st.b, st.c, st.pub)).to.be.revertedWithCustomError(wallet, 'TooFarExpiry');
  });

  it('block.number > max_height 면 Expired', async () => {
    const st = withInput(await statement({ maxHeight: BigInt(await ethers.provider.getBlockNumber()) }));
    const { wallet } = await deployStack(st);   // 배포로 블록이 지나 이미 만료
    const { payload, sig } = await signedPayload(st, wallet);
    await expect(wallet.execute(payload, sig, st.a, st.b, st.c, st.pub)).to.be.revertedWithCustomError(wallet, 'Expired');
  });

  it('증명을 손상하면 InvalidProof', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const a = [ST.a[1], ST.a[0]];
    await expect(wallet.execute(payload, sig, a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'InvalidProof');
  });

  it('내부 호출이 실패해도 revert 하지 않고 nonce 를 소모하며 Executed(success=false)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet, { value: ethers.parseEther('1000') });
    const receipt = await (await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).wait();
    expect(parseExecuteReceipt(receipt).executed.success).to.equal(false);
    expect(await wallet.nonce()).to.equal(1n);
  });

  it('decodeExecuteCalldata 가 제출한 인자를 그대로 되돌린다 (서비스의 해시 기반 개봉 재료)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const tx = await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub);
    await tx.wait();
    const d = decodeExecuteCalldata((await ethers.provider.getTransaction(tx.hash)).data);
    expect(d.pub).to.deep.equal(ST.publicSignals);
    expect(d.payload.nonce).to.equal(payload.nonce);
    expect(d.sig).to.equal(sig);
  });

  it('computeAddress 는 배포 전후 같고, deploy 는 멱등이다', async () => {
    const { factory, walletAddr, ppid } = await deployStack(ST);
    expect(await factory.computeAddress(ppid)).to.equal(walletAddr);
    await (await factory.deploy(ppid)).wait();
    expect(await ethers.provider.getCode(walletAddr)).to.not.equal('0x');
    expect(await factory.isWallet(walletAddr)).to.equal(true);
  });

  it('V6: pub 은 23개이고 mask = 0 이면 꼬리는 항상 붙지만 Disclosure 이벤트는 없음', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const rc = await (await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).wait();
    assert.equal(ST.pub.length, 23);
    const { disclosure } = parseExecuteReceipt(rc, wallet.target);
    assert.equal(disclosure, null);
  });

  // 최종 리뷰 Critical(2026-09-22, Ruling 7) — reviewer PoC(scratchpad/poc_tail_forgery.test.mjs) 를 회귀 테스트로 옮긴 것.
  // 캐시된 mask = 0 의 π 로 payload.data 안에 직접 위조한 꼬리(mask=3, lo/hi)를 실어 AttrGate.claim 을 속일 수 있는지 확인한다.
  // 꼬리를 mask 와 무관하게 항상 붙이면(고정 후) 지갑이 실제로 계산한 (mask=0, 0×9) 꼬리가 위조 꼬리 뒤에 또 붙어
  // calldata 끝 288바이트는 항상 0 이 되므로 AttrGate 가 "need slot0,1" 로 거절해야 한다.
  it('V6(회귀): mask = 0 π + payload.data 안의 위조 꼬리로는 AttrGate.claim 을 속일 수 없다; 진짜 mask = 3 π 는 여전히 통과', async () => {
    const { wallet, factory } = await deployStack(ST);
    const Gate = await ethers.getContractFactory('AttrGate');
    const gate = await Gate.deploy(await factory.getAddress(), 840n, 2007n);   // 정책이 ST 의 실제 국가(410)와 다르게 잡혀 있다 — 위조 없이는 통과 못 한다
    // 위조 꼬리: mask=3, lo=[0,840,0,0], hi=[2007,840,0,0] — 실제로는 mask=0 π 라 회로가 이런 값을 검증하지 않았다.
    const fakeTail = ethers.AbiCoder.defaultAbiCoder().encode(['uint256', 'uint256[4]', 'uint256[4]'], [3n, [0n, 840n, 0n, 0n], [2007n, 840n, 0n, 0n]]);
    const data = gate.interface.encodeFunctionData('claim') + fakeTail.slice(2);
    const { payload, sig } = await signedPayload(ST, wallet, { to: await gate.getAddress(), data });   // discMask 0 — 진짜 π 와 일치
    const rc = await (await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).wait();
    const { executed, disclosure } = parseExecuteReceipt(rc, wallet.target);
    assert.equal(executed.success, false, '위조 꼬리가 통과하면 안 된다');
    assert.equal(disclosure, null);
    assert.equal(await gate.claimed(wallet.target), false, 'claim 이 통과했다 = 위조 성공(회귀)');

    // 대조: 실제 속성(국가 410)에 맞는 정책의 게이트에 진짜 mask=3 π(국가 410 공개)로 보내면 통과한다.
    const DS = withInput(await statement({ disclosure: { mask: 0b0011n, lo: [0n, 410n, 0n, 0n], hi: [2007n, 410n, 0n, 0n] } }));
    const { wallet: wallet2, factory: factory2 } = await deployStack(DS);
    const gate2 = await Gate.deploy(await factory2.getAddress(), 410n, 2007n);
    const data2 = gate2.interface.encodeFunctionData('claim');
    const real = await signedPayload(DS, wallet2, { to: await gate2.getAddress(), data: data2, discMask: 0b0011n, discLo: DS.fx.disclosure.lo, discHi: DS.fx.disclosure.hi });
    const rc2 = await (await wallet2.execute(real.payload, real.sig, DS.a, DS.b, DS.c, DS.pub)).wait();
    assert.equal(parseExecuteReceipt(rc2, wallet2.target).executed.success, true, '진짜 mask=3 π 는 여전히 통과해야 한다');
    assert.equal(await gate2.claimed(wallet2.target), true);
  });

  it('V6: mask ≠ 0 이면 대상이 꼬리 9워드를 읽고 AttrGate.claim 이 통과한다; Disclosure 이벤트; 두 번째 claim 은 already claimed', async () => {
    const DS = withInput(await statement({ disclosure: { mask: 0b0011n, lo: [0n, 410n, 0n, 0n], hi: [2007n, 410n, 0n, 0n] } }));
    const { wallet, factory } = await deployStack(DS);
    const Gate = await ethers.getContractFactory('AttrGate');
    const gate = await Gate.deploy(await factory.getAddress(), 410n, 2007n);
    const data = gate.interface.encodeFunctionData('claim');
    const { payload, sig } = await signedPayload(DS, wallet, { to: await gate.getAddress(), data, discMask: 0b0011n, discLo: DS.fx.disclosure.lo, discHi: DS.fx.disclosure.hi });
    const rc = await (await wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub)).wait();
    const { executed, disclosure } = parseExecuteReceipt(rc, wallet.target);
    assert.equal(executed.success, true);
    assert.equal(disclosure.mask, 3n); assert.equal(disclosure.hi[0], 2007n); assert.equal(disclosure.lo[1], 410n);
    assert.equal(await gate.claimed(wallet.target), true);
    const again = await signedPayload(DS, wallet, { to: await gate.getAddress(), data, discMask: 0b0011n, discLo: DS.fx.disclosure.lo, discHi: DS.fx.disclosure.hi });
    const rc2 = await (await wallet.execute(again.payload, again.sig, DS.a, DS.b, DS.c, DS.pub)).wait();
    assert.equal(parseExecuteReceipt(rc2, wallet.target).executed.success, false, 'already claimed → 내부 호출 실패, nonce 는 소모');
  });

  it('V6: 공개 구간이 정책보다 넓으면(hi[0] > birthYearMax) claim 이 실패(success=false)', async () => {
    // 픽스처 속성은 [1990, 410, 2, 0] 이라 a₁ = 840 등식은 증명 자체가 안 만들어진다(회로가 거절) →
    // 국가 불일치 케이스는 alice 형 속성의 픽스처가 없어 이 테스트에서 시험하지 않는다(데모 스택 단계에서 시험).
    // 대신 "정책보다 넓은 구간" 으로 시험한다: hi[0] = 2010 (> birthYearMax 2007) 는 증명은 되지만 게이트가 거절한다.
    const wide = withInput(await statement({ disclosure: { mask: 0b0011n, lo: [0n, 410n, 0n, 0n], hi: [2010n, 410n, 0n, 0n] } }));
    const { wallet, factory } = await deployStack(wide);
    const Gate = await ethers.getContractFactory('AttrGate');
    const gate = await Gate.deploy(await factory.getAddress(), 410n, 2007n);
    const data = gate.interface.encodeFunctionData('claim');
    const { payload, sig } = await signedPayload(wide, wallet, { to: await gate.getAddress(), data, discMask: 0b0011n, discLo: wide.fx.disclosure.lo, discHi: wide.fx.disclosure.hi });
    const rc = await (await wallet.execute(payload, sig, wide.a, wide.b, wide.c, wide.pub)).wait();
    assert.equal(parseExecuteReceipt(rc, wallet.target).executed.success, false);
    assert.equal(await gate.claimed(wallet.target), false);
  });

  it('V6: EOA 가 꼬리를 흉내 내 AttrGate.claim 을 직접 부르면 not a mode3 wallet', async () => {
    const { factory } = await deployStack(ST);
    const Gate = await ethers.getContractFactory('AttrGate');
    const gate = await Gate.deploy(await factory.getAddress(), 410n, 2007n);
    const [eoa] = await ethers.getSigners();
    const tail = ethers.AbiCoder.defaultAbiCoder().encode(['uint256', 'uint256[4]', 'uint256[4]'], [3n, [0n, 410n, 0n, 0n], [2007n, 410n, 0n, 0n]]);
    await assert.rejects(eoa.sendTransaction({ to: await gate.getAddress(), data: gate.interface.encodeFunctionData('claim') + tail.slice(2) }), /not a mode3 wallet/);
  });

  it('V6: 다이제스트가 mask 를 덮는다 — mask 0 으로 서명한 σ 로 mask 3 의 π 를 붙이면 BadSignature', async () => {
    const DS = withInput(await statement({ disclosure: { mask: 0b0011n, lo: [0n, 410n, 0n, 0n], hi: [2007n, 410n, 0n, 0n] } }));
    const { wallet } = await deployStack(DS);
    const { payload, sig } = await signedPayload(DS, wallet, { discMask: 0n });
    await assert.rejects(wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub), /BadSignature/);
  });

  it('V6: 다이제스트가 lo/hi 를 덮는다 — 같은 mask 로 서명하되 hi[0] 만 다르게 서명한 σ 는 BadSignature', async () => {
    const DS = withInput(await statement({ disclosure: { mask: 0b0011n, lo: [0n, 410n, 0n, 0n], hi: [2007n, 410n, 0n, 0n] } }));
    const { wallet } = await deployStack(DS);
    const wrongHi = [9999n, ...DS.fx.disclosure.hi.slice(1)];
    const { payload, sig } = await signedPayload(DS, wallet, { discMask: 0b0011n, discLo: DS.fx.disclosure.lo, discHi: wrongHi });
    await assert.rejects(wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub), /BadSignature/);
  });

  it('V6: pub[14] ≥ 16 은 BadDisclosure (증명 검증 전에 걸린다)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet, { discMask: 16n });
    const pub = [...ST.pub]; pub[14] = 16n;
    await assert.rejects(wallet.execute(payload, sig, ST.a, ST.b, ST.c, pub), /BadDisclosure/);
  });

  it('V6: factory.isWallet 은 배포한 지갑만 true', async () => {
    const { factory, walletAddr } = await deployStack(ST);
    assert.equal(await factory.isWallet(walletAddr), true);
    assert.equal(await factory.isWallet(ethers.Wallet.createRandom().address), false);
  });
});
