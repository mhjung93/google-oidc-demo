// Mode3Wallet / Mode3WalletFactory — 설계 2026-09-18 §5. hardhat 인프로세스 체인(contract 그룹).
// 증명은 tests/helpers/mode3_fixture.mjs 의 픽스처로 실제로 만든다(build/mode3 산출물 필요).
import { expect } from 'chai';
import assert from 'node:assert';
import hre from 'hardhat';
import fs from 'node:fs';
import * as snarkjs from 'snarkjs';
import { buildValidInput } from '../tests/helpers/mode3_fixture.mjs';
import { signPublicationV3, rootToBytes32, entryHashes } from '../lib/mode3_log.js';
import { signPayload, payloadDigest, statementDigestFields, proofToCalldata, decodeExecuteCalldata, parseExecuteReceipt, MAX_ROOT_AGE_DEFAULT, MAX_LIFETIME_DEFAULT } from '../lib/mode3_onchain.js';
import { setRoot } from '../lib/mode3_set_tree.js';

const { ethers } = hre;
const WASM = 'build/mode3/pi_cred_js/pi_cred.wasm', ZKEY = 'build/mode3/pi_cred_final.zkey';

describe('Mode3Wallet', function () {
  this.timeout(180_000);
  before(() => { if (!fs.existsSync(ZKEY)) throw new Error(`${ZKEY} 없음 — bash scripts/build_mode3_circuit.sh`); });

  const chainId = () => ethers.provider.getNetwork().then((n) => n.chainId);

  /** 세션키 + 픽스처 증명. 옵션은 픽스처로 전달. session 을 주면 그 세션키를 재사용한다(같은 pk_i 의 다른 성명 두 개를 만들 때). */
  async function statement({ session: reuse = null, ...opts } = {}) {
    const session = reuse ?? ethers.Wallet.createRandom();
    // 만료는 지갑이 정한다 — 컨트랙트가 head + maxLifetime 상한을 강제하므로 현재 블록 기준으로 정한다
    const maxHeight = opts.maxHeight ?? BigInt(await ethers.provider.getBlockNumber()) + 300n;
    const fx = await buildValidInput({ pk_i: BigInt(session.address), chainid: await chainId(), ...opts, maxHeight });
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(fx.input, WASM, ZKEY);
    const cd = await proofToCalldata(proof, publicSignals);
    return { session, fx, proof, publicSignals, ...cd };
  }

  /** 픽스처의 두 root 로 Mode3Log 를 배포하고(초기 root = 픽스처 트리), 검증자·팩토리·지갑까지. */
  async function deployStack(st, { arid = st.fx.arid, maxRootAge = MAX_ROOT_AGE_DEFAULT, maxLifetime = MAX_LIFETIME_DEFAULT } = {}) {
    const [deployer, cia] = await ethers.getSigners();
    const Log = await ethers.getContractFactory('Mode3Log');
    const log = await Log.deploy(cia.address, rootToBytes32(BigInt(st.input().revRoot)), rootToBytes32(BigInt(st.input().regRoot)));
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

  /** 다이제스트의 성명 쪽 다섯 필드(2026-09-25 리뷰 A-2) 기본값 — π 의 공개 입력 그대로. 음성 테스트는 opts 로 덮어쓴다. */
  const stmtFields = (st) => statementDigestFields(st.publicSignals);
  const STMT_KEYS = ['maxHeight', 'allowAgent', 'tagC1X', 'tagC1Y', 'tagC2'];

  async function signedPayload(st, wallet, opts = {}) {
    const { to = ethers.Wallet.createRandom().address, value = 0n, data = '0x', discMask = 0n, discLo = [0n, 0n, 0n, 0n, 0n, 0n], discHi = [0n, 0n, 0n, 0n, 0n, 0n], setSel = 0n, setRoot = 0n } = opts;
    const stmt = stmtFields(st);
    for (const k of STMT_KEYS) if (opts[k] !== undefined) stmt[k] = opts[k];
    const nonce = await wallet.nonce();
    const payload = { to, value, data, nonce };
    const sig = signPayload(st.session, { chainId: await chainId(), wallet: wallet.target, ...payload, discMask, discLo, discHi, setSel, setRoot, ...stmt });
    return { payload, sig };
  }

  let ST;   // 공통 성명 — 증명 생성이 1초쯤이라 케이스 간 공유한다(체인은 케이스마다 새로 배포)
  // counter: 0n — 이 성명을 쓰는 케이스는 모두 각자 새로 배포한 지갑에서 "첫 실행"(nonce 0)으로만 쓴다
  // (2026-10-22 설계 §6.5: π 의 counter 가 그 실행의 nonce 와 같아야 한다, 기본값은 로그인용 LOGIN_COUNTER).
  // maxHeight 여유는 기본(head + 300)보다 넉넉히 둔다(head + 395, TooFarExpiry 상한인 head + maxLifetime(400)
  // 안) — 2026-10-22 수정 라운드 1 로 ST 를 쓰는 케이스 앞에 트랜잭션(블록)이 더 늘어, 300 여유로는 스위트
  // 뒤쪽(E-1 등)에서 전체 블록 소비가 누적돼 ST 의 π 가 먼저 Expired 로 꺼지는 일이 있었다.
  before(async () => {
    const head = BigInt(await ethers.provider.getBlockNumber());
    ST = withInput(await statement({ counter: 0n, maxHeight: head + 395n }));
  });

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
    const st = withInput(await statement({ allowAgent: 1n, counter: 0n }));
    const { wallet } = await deployStack(st);
    const { payload, sig } = await signedPayload(st, wallet);
    const receipt = await (await wallet.execute(payload, sig, st.a, st.b, st.c, st.pub)).wait();
    expect(parseExecuteReceipt(receipt).auth.allowAgent).to.equal(1n);
  });

  it('같은 세션키의 다른 nonce 성명 두 개 — 같은 π 는 재사용할 수 없다(counter 가 nonce 와 같아야 한다, 2026-10-22 §6.5) — 증명자가 counter 를 낮춰 고르는 것을 막는다', async () => {
    const s0 = withInput(await statement({ counter: 0n }));
    const { wallet } = await deployStack(s0);
    const p0 = await signedPayload(s0, wallet);
    await (await wallet.execute(p0.payload, p0.sig, s0.a, s0.b, s0.c, s0.pub)).wait();
    // nonce 는 이제 1. 같은 π(counter 0 그대로)를 재사용하면 — counter 가 nonce 보다 **작은** 방향도
    // CounterMismatch 여야 한다(그냥 `!=` 가 아니라 `>` 로 바뀌어도 통과해버리는 변이를 여기서 잡는다).
    const reused = await signedPayload(s0, wallet);
    await expect(wallet.execute(reused.payload, reused.sig, s0.a, s0.b, s0.c, s0.pub))
      .to.be.revertedWithCustomError(wallet, 'CounterMismatch').withArgs(1n, 0n);
    const s1 = withInput(await statement({ session: s0.session, counter: 1n }));
    const p1 = await signedPayload(s1, wallet);
    await (await wallet.execute(p1.payload, p1.sig, s1.a, s1.b, s1.c, s1.pub)).wait();
    expect(await wallet.nonce()).to.equal(2n);
  });

  it('pub[33](counter) 를 바꿔 신선한 nonce 에 맞춰도 InvalidProof — counter 는 π 가 묶는다(다이제스트가 아니라)', async () => {
    const s0 = withInput(await statement({ counter: 0n }));
    const { wallet } = await deployStack(s0);
    const p0 = await signedPayload(s0, wallet);
    await (await wallet.execute(p0.payload, p0.sig, s0.a, s0.b, s0.c, s0.pub)).wait();   // nonce: 0 → 1
    // 다이제스트는 pub[33](counter)를 덮지 않으므로(payloadDigest 의 15워드 + A-2 다섯에 counter 는 없다),
    // nonce=1 로 다시 서명한 σ 는 여전히 유효하다. 그 σ 에 π0(counter=0)의 pub 을 pub[33]=1 로만 바꿔 붙이면
    // NonceMismatch·CounterMismatch·BadSignature 는 전부 통과하지만(바뀐 자리는 다이제스트 밖), 그 pub 전체가
    // 실제로 검증받은 증명(π0)이 만든 값과 더 이상 같지 않아 verifyProof 가 거부한다 — counter 를 체인에
    // 묶어 두는 것은 결국 Groth16 바인딩이고, 서명이 그걸 대신하지 않는다는 뜻이다.
    const reused = await signedPayload(s0, wallet);
    const tamperedPub = [...s0.pub]; tamperedPub[33] = '0x1';
    await expect(wallet.execute(reused.payload, reused.sig, s0.a, s0.b, s0.c, tamperedPub))
      .to.be.revertedWithCustomError(wallet, 'InvalidProof');
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
    const wrong = signPayload(other, { chainId: await chainId(), wallet: wallet.target, ...payload, ...stmtFields(ST) });
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
    const sig = signPayload(ST.session, { chainId: await chainId(), wallet: ethers.Wallet.createRandom().address, ...payload, ...stmtFields(ST) });
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
  });

  it('공개 입력의 PPID·arid·chainid 가 지갑과 다르면 WrongWallet (다른 계정·다른 RP·다른 체인의 성명 재생)', async () => {
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
    const p = [...ST.pub]; p[10] = '0x1';
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, p)).to.be.revertedWithCustomError(wallet, 'UntrustedKeys');
  });

  it('allowAgent = 2 는 BadAllowAgent (증명 검증 전에 걸린다)', async () => {
    const { wallet } = await deployStack(ST);
    // 다이제스트가 allowAgent 를 덮으므로(2026-09-25 A-2) 그 값으로 서명해야 _checkStatement 까지 간다 —
    // 즉 세션키를 쥔 악의적 지갑이 스스로 2 를 실은 경우다. 남이 바꿔 끼우는 것은 이제 BadSignature 로 먼저 막힌다.
    const { payload, sig } = await signedPayload(ST, wallet, { allowAgent: 2n });
    const p = [...ST.pub]; p[5] = '0x2';
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, p)).to.be.revertedWithCustomError(wallet, 'BadAllowAgent');
  });

  it('c1 이 항등원(r = 0)이면 BadTag (증명 검증 전에 걸린다)', async () => {
    const { wallet } = await deployStack(ST);
    // 위와 같은 이유(A-2): 태그도 다이제스트가 덮으므로 그 태그로 서명한 경우를 본다.
    const { payload, sig } = await signedPayload(ST, wallet, { tagC1X: 0n, tagC1Y: 1n });
    const p = [...ST.pub]; p[12] = '0x0'; p[13] = '0x1';
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, p)).to.be.revertedWithCustomError(wallet, 'BadTag');
  });

  it('root 가 게시로 바뀌면 옛 π 는 StaleRevocationRoot', async () => {
    const { wallet, log, cia } = await deployStack(ST);
    const newRoot = rootToBytes32(12345n);
    const sig = await signPublicationV3(cia, { canonicalChainId: await chainId(), canonicalLogAddress: await log.getAddress(), revRoot: newRoot, regRoot: await log.regRoot(), epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [] });
    await (await log.publish(newRoot, await log.regRoot(), 1n, [], [], [], sig)).wait();
    const sp = await signedPayload(ST, wallet);
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'StaleRevocationRoot');
  });

  it('root 게시가 maxRootAge 블록보다 오래되면 RootTooOld, 하트비트(같은 root 재게시) 뒤엔 다시 된다', async () => {
    const { wallet, log, cia } = await deployStack(ST, { maxRootAge: 10n });
    await ethers.provider.send('hardhat_mine', ['0xb']);   // 11 블록
    const sp = await signedPayload(ST, wallet);
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'RootTooOld');
    const revRoot = await log.revRoot();
    const regRoot = await log.regRoot();
    const sig = await signPublicationV3(cia, { canonicalChainId: await chainId(), canonicalLogAddress: await log.getAddress(), revRoot, regRoot, epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [] });
    await (await log.publish(revRoot, regRoot, 1n, [], [], [], sig)).wait();
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.not.be.reverted;
  });

  it('V9: 등록부 root 가 바뀌면(슬롯 바꿔치기·은퇴) 옛 π 는 StaleRegistryRoot — 폐기 root 검사 다음에 걸린다', async () => {
    const { wallet, log, cia } = await deployStack(ST);
    const rev = await log.revRoot();
    const newReg = rootToBytes32(777n);
    const sig = await signPublicationV3(cia, { canonicalChainId: await chainId(), canonicalLogAddress: await log.getAddress(), revRoot: rev, regRoot: newReg, epoch: 1n, revLeaves: [], slotIdx: [7], slotLeaves: [rootToBytes32(424242n)] });
    await (await log.publish(rev, newReg, 1n, [], [7], [rootToBytes32(424242n)], sig)).wait();
    const sp = await signedPayload(ST, wallet);
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'StaleRegistryRoot');
  });

  // V10 거울(Mode3Mirror, 설계 §2·§3·§5): 지갑의 IMode3Roots 는 캐노니컬 Mode3Log 대신 거울을 가리킬 수 있다.
  // 지갑은 거울의 root 만 보므로, 캐노니컬이 앞서가도(거울이 뒤처져도) 영향이 없고, 거울 자체가 전진해야
  // 거기 안 실린 옛 π 가 거절된다. 같은 IdP 서명이 캐노니컬 publish 와 거울 publish 양쪽에 유효한지도 같이 본다.
  it('V10: 거울 위의 지갑 — 거울 root 와 같은 π 는 통과, 캐노니컬만 전진해도 거울이 그대로면 영향 없음, 거울이 전진하면 옛 π 는 StaleRevocationRoot', async () => {
    const [deployer, cia] = await ethers.getSigners();
    const initRev = rootToBytes32(BigInt(ST.input().revRoot));
    const initReg = rootToBytes32(BigInt(ST.input().regRoot));
    const log = await (await ethers.getContractFactory('Mode3Log')).deploy(cia.address, initRev, initReg);
    const canonicalChainId = await chainId();
    const canonicalLogAddress = await log.getAddress();
    const mirror = await (await ethers.getContractFactory('Mode3Mirror')).deploy(cia.address, canonicalChainId, canonicalLogAddress, initRev, initReg);
    const verifier = await (await ethers.getContractFactory('PiCredVerifier')).deploy();
    const factory = await (await ethers.getContractFactory('Mode3WalletFactory')).deploy(
      await verifier.getAddress(), ST.fx.arid, ST.fx.ciaPub.x, ST.fx.ciaPub.y, ST.fx.pk_trace.x, ST.fx.pk_trace.y,
      await mirror.getAddress(), MAX_ROOT_AGE_DEFAULT, MAX_LIFETIME_DEFAULT);
    const ppid = BigInt(ST.input().PPID);
    const walletAddr = await factory.computeAddress(ppid);
    await (await deployer.sendTransaction({ to: walletAddr, value: ethers.parseEther('1') })).wait();
    await (await factory.deploy(ppid)).wait();
    const wallet = await ethers.getContractAt('Mode3Wallet', walletAddr);

    // (a) 거울의 초기 root 는 캐노니컬의 초기 root 와 같다(생성자에 같은 값을 넣었다) — 기존 π 가 통과한다.
    const sp1 = await signedPayload(ST, wallet);
    await expect(wallet.execute(sp1.payload, sp1.sig, ST.a, ST.b, ST.c, ST.pub)).to.not.be.reverted;

    // 캐노니컬 로그만 새 epoch 로 전진시킨다(거울에는 아직 중계하지 않는다) — 거울은 여전히 옛 root 이므로
    // 지갑은 영향받지 않는다(거울이 뒤처져도 검증에는 영향 없다, V10 §3).
    // nonce 가 이미 1 이므로 새 π 가 필요하다(counter: 1n) — revRoot 는 statement() 기본값이라 ST 와 같다(initRev).
    const newRoot = rootToBytes32(12345n);
    const sigCanon = await signPublicationV3(cia, { canonicalChainId, canonicalLogAddress, revRoot: newRoot, regRoot: initReg, epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [] });
    await (await log.publish(newRoot, initReg, 1n, [], [], [], sigCanon)).wait();
    const st2 = withInput(await statement({ session: ST.session, counter: 1n }));
    const sp2 = await signedPayload(st2, wallet);
    await expect(wallet.execute(sp2.payload, sp2.sig, st2.a, st2.b, st2.c, st2.pub)).to.not.be.reverted;

    // 그 캐노니컬 게시를 거울로 중계한다(같은 서명이 거울에도 유효하다) — 거울의 root 가 바뀌었으므로,
    // 그 root 를 담지 않은 옛 π 는 이제 거절된다. 지갑은 캐노니컬이 아니라 거울만 본다는 확인.
    // nonce 가 이미 2 이므로 또 새 π(counter: 2n) — 여전히 옛 revRoot(initRev) 를 담아야 거절 사유를 확인할 수 있다.
    const h = entryHashes({ revLeaves: [], slotIdx: [], slotLeaves: [] });
    await (await mirror.publish(newRoot, initReg, 1n, h.hLeaves, h.hIdx, h.hSlots, sigCanon)).wait();
    const st3 = withInput(await statement({ session: ST.session, counter: 2n }));
    const sp3 = await signedPayload(st3, wallet);
    await expect(wallet.execute(sp3.payload, sp3.sig, st3.a, st3.b, st3.c, st3.pub)).to.be.revertedWithCustomError(wallet, 'StaleRevocationRoot');
  });

  it('V9: 마스크 6비트·set_sel ≤ 6 — mask 64, set_sel 7 은 BadDisclosure', async () => {
    const { wallet } = await deployStack(ST);
    const a = await signedPayload(ST, wallet, { discMask: 64n });
    const p = [...ST.pub]; p[15] = '0x40';
    await expect(wallet.execute(a.payload, a.sig, ST.a, ST.b, ST.c, p)).to.be.revertedWithCustomError(wallet, 'BadDisclosure');
    const b = await signedPayload(ST, wallet, { setSel: 7n });
    const q = [...ST.pub]; q[28] = '0x7';
    await expect(wallet.execute(b.payload, b.sig, ST.a, ST.b, ST.c, q)).to.be.revertedWithCustomError(wallet, 'BadDisclosure');
  });

  it('max_height 가 block.number + maxLifetime 을 넘으면 TooFarExpiry (지갑이 정한 만료의 상한)', async () => {
    const st = withInput(await statement({ maxHeight: BigInt(await ethers.provider.getBlockNumber()) + 10_000n, counter: 0n }));
    const { wallet } = await deployStack(st);
    const { payload, sig } = await signedPayload(st, wallet);
    await expect(wallet.execute(payload, sig, st.a, st.b, st.c, st.pub)).to.be.revertedWithCustomError(wallet, 'TooFarExpiry');
  });

  it('block.number > max_height 면 Expired', async () => {
    const st = withInput(await statement({ maxHeight: BigInt(await ethers.provider.getBlockNumber()), counter: 0n }));
    const { wallet } = await deployStack(st);   // 배포로 블록이 지나 이미 만료
    const { payload, sig } = await signedPayload(st, wallet);
    await expect(wallet.execute(payload, sig, st.a, st.b, st.c, st.pub)).to.be.revertedWithCustomError(wallet, 'Expired');
  });

  // 2026-09-25 리뷰 E-6: 위 케이스는 "한참 지난" 만료만 본다. 부등호가 `>=` 로 바뀌어도(= 마지막 한 블록을
  // 잃어도) 빨개지지 않는다. 경계 두 칸을 같은 지갑·같은 max_height 의 새 π 로 붙여서 본다 — IdP(cia.js)·
  // RP(lib/mode3_rp.js)가 쓰는 부등호와 같아야 한다: head == max_height 는 아직 산 성명이다.
  it('E-6 만료 경계: block.number == max_height 는 유효, 그 다음 블록부터 Expired', async () => {
    const st = withInput(await statement({ maxHeight: BigInt(await ethers.provider.getBlockNumber()) + 30n, counter: 0n }));
    const { wallet } = await deployStack(st);
    const maxHeight = BigInt(st.fx.input.max_height);
    // execute 는 "지금 head + 1" 블록에 들어간다. 그 블록이 정확히 max_height 가 되게 채운다.
    const gap = maxHeight - 1n - BigInt(await ethers.provider.getBlockNumber());
    assert.ok(gap >= 0n, `배포가 경계를 넘겨 버렸다(gap=${gap}) — maxHeight 여유를 늘려야 한다`);
    if (gap > 0n) await ethers.provider.send('hardhat_mine', ['0x' + gap.toString(16)]);
    const a = await signedPayload(st, wallet);
    const receipt = await (await wallet.execute(a.payload, a.sig, st.a, st.b, st.c, st.pub)).wait();
    expect(BigInt(receipt.blockNumber)).to.equal(maxHeight, '경계 블록에서 실행돼야 이 케이스가 의미가 있다');
    // 한 블록만 더 가면(= head == max_height 인 상태에서 보낸 다음 트랜잭션) 같은 max_height 의 새 π 가 만료된다.
    // nonce 가 이미 1 이므로 새 π 는 counter: 1n(같은 max_height) — 아니면 Expired 전에 CounterMismatch 로 막힌다.
    const st2 = withInput(await statement({ maxHeight, session: st.session, counter: 1n }));
    const b = await signedPayload(st2, wallet);
    await expect(wallet.execute(b.payload, b.sig, st2.a, st2.b, st2.c, st2.pub)).to.be.revertedWithCustomError(wallet, 'Expired');
  });

  it('증명을 손상하면 InvalidProof', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const a = [ST.a[1], ST.a[0]];
    await expect(wallet.execute(payload, sig, a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'InvalidProof');
  });

  it('pub[30]/[31]/[32](auid_s·arid_s·r_s) 를 하나씩 바꾸면 InvalidProof — 다이제스트가 덮지 않아 σ 는 그대로지만 증명이 그 공개 입력과 안 맞는다', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    for (const i of [30, 31, 32]) {
      const p = [...ST.pub];
      p[i] = '0x' + (BigInt(ST.pub[i]) + 1n).toString(16);
      await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, p)).to.be.revertedWithCustomError(wallet, 'InvalidProof');
    }
  });

  it('내부 호출이 실패해도 revert 하지 않고 nonce 를 소모하며 Executed(success=false)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet, { value: ethers.parseEther('1000') });
    const receipt = await (await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).wait();
    expect(parseExecuteReceipt(receipt).executed.success).to.equal(false);
    expect(await wallet.nonce()).to.equal(1n);
  });

  it('decodeExecuteCalldata 가 제출한 인자를 그대로 되돌린다 (RP 의 해시 기반 개봉 재료)', async () => {
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

  it('V11: pub 은 34개이고 mask = 0 이고 set_sel = 0 이면 꼬리는 항상 붙지만 Disclosure 이벤트는 없음', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const rc = await (await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).wait();
    assert.equal(ST.pub.length, 34);
    const { disclosure } = parseExecuteReceipt(rc, wallet.target);
    assert.equal(disclosure, null);
  });

  // 최종 리뷰 Critical(2026-09-22, Ruling 7) — reviewer PoC(scratchpad/poc_tail_forgery.test.mjs) 를 회귀 테스트로 옮긴 것.
  // 캐시된 mask = 0, set_sel = 0 의 π 로 payload.data 안에 직접 위조한 꼬리(mask=3, lo/hi, set_sel, set_root)를 실어
  // AttrGate.claim 을 속일 수 있는지 확인한다. 꼬리를 mask·set_sel 과 무관하게 항상 붙이면(고정 후) 지갑이 실제로 계산한
  // (mask=0, 0×12, set_sel=0, set_root=0) 꼬리가 위조 꼬리 뒤에 또 붙어 calldata 끝 480바이트는 항상 0 이 되므로
  // AttrGate 가 "need slot0"(또는 "country")로 거절해야 한다.
  it('V7(회귀): mask=0·set_sel=0 π + payload.data 안의 위조 꼬리로는 AttrGate.claim 을 속일 수 없다; 진짜 π 는 여전히 통과', async () => {
    const { wallet, factory } = await deployStack(ST);
    const Gate = await ethers.getContractFactory('AttrGate');
    const gate = await Gate.deploy(await factory.getAddress(), await setRoot([840n]), 19n);   // 정책 = 미국(840)만 허용 → ST(국가 410) 는 위조 없이는 통과 못 한다
    // 위조 꼬리: mask=3, lo=[0,840,0,0,0,0], hi=[2007,840,0,0,0,0], set_sel=2, set_root=FAKE_ROOT — 실제로는 mask=0,set_sel=0 π 라 회로가 이런 값을 검증하지 않았다.
    const FAKE_ROOT = await setRoot([840n]);
    const fakeTail = ethers.AbiCoder.defaultAbiCoder().encode(['uint256', 'uint256[6]', 'uint256[6]', 'uint256', 'uint256'], [3n, [0n, 840n, 0n, 0n, 0n, 0n], [2007n, 840n, 0n, 0n, 0n, 0n], 2n, FAKE_ROOT]);
    const data = gate.interface.encodeFunctionData('claim') + fakeTail.slice(2);
    const { payload, sig } = await signedPayload(ST, wallet, { to: await gate.getAddress(), data });   // discMask 0, setSel 0 — 진짜 π 와 일치
    const rc = await (await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).wait();
    const { executed, disclosure } = parseExecuteReceipt(rc, wallet.target);
    assert.equal(executed.success, false, '위조 꼬리가 통과하면 안 된다');
    assert.equal(disclosure, null);
    assert.equal(await gate.claimed(wallet.target), false, 'claim 이 통과했다 = 위조 성공(회귀)');

    // 대조: 실제 속성(생년 1990, 국가 410 ∈ 허용집합)에 맞는 정책의 게이트에 진짜 π(슬롯0 공개 + 집합 소속)로 보내면 통과한다.
    const DS = withInput(await statement({ disclosure: { mask: 0b0001n, lo: [0n, 0n, 0n, 0n, 0n, 0n], hi: [1990n, 0n, 0n, 0n, 0n, 0n] }, set: { slot: 1, members: [410, 392, 840, 276, 250] }, counter: 0n }));
    const { wallet: wallet2, factory: factory2 } = await deployStack(DS);
    const gate2 = await Gate.deploy(await factory2.getAddress(), await setRoot([410, 392, 840, 276, 250]), 19n);
    const data2 = gate2.interface.encodeFunctionData('claim');
    const real = await signedPayload(DS, wallet2, { to: await gate2.getAddress(), data: data2, discMask: 1n, discLo: DS.fx.disclosure.lo, discHi: DS.fx.disclosure.hi, setSel: 2n, setRoot: DS.fx.set.root });
    const rc2 = await (await wallet2.execute(real.payload, real.sig, DS.a, DS.b, DS.c, DS.pub)).wait();
    assert.equal(parseExecuteReceipt(rc2, wallet2.target).executed.success, true, '진짜 π 는 여전히 통과해야 한다');
    assert.equal(await gate2.claimed(wallet2.target), true);
  });

  // 2026-09-22 사용자 결정(Ruling 10): data 가 비어 있고 mask = 0 이면 꼬리를 붙이지 않는다 — receive() 만 있는 컨트랙트로의
  // 단순 송금이 살아야 한다. 다른 Mode3Wallet(receive() 만 있음)을 수신자로 써서 확인한다. 위조 방어는 위 회귀 테스트가 그대로 지킨다.
  it('V6: payload.data 가 비어 있고 mask = 0 이면 꼬리 없이 보내 receive()-only 컨트랙트(다른 Mode3Wallet)로 송금이 된다', async () => {
    const { wallet, factory, deployer } = await deployStack(ST);
    const other = await factory.computeAddress(BigInt(ST.input().PPID) + 1n);
    await (await factory.deploy(BigInt(ST.input().PPID) + 1n)).wait();
    assert.equal(await deployer.provider.getCode(other) !== '0x', true);
    const before = await deployer.provider.getBalance(other);
    const { payload, sig } = await signedPayload(ST, wallet, { to: other, value: ethers.parseEther('0.1'), data: '0x' });
    const rc = await (await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).wait();
    assert.equal(parseExecuteReceipt(rc, wallet.target).executed.success, true, 'receive()-only 대상 송금은 성공해야 한다');
    assert.equal(await deployer.provider.getBalance(other) - before, ethers.parseEther('0.1'));
    // 같은 대상에 data 가 비어 있지 않으면(꼬리가 붙어) receive() 가 실행되지 않아 실패한다 — 예외의 경계 확인
    // 첫 execute 로 nonce 가 이미 1 이므로 새 π 가 필요하다(counter: 1n).
    const stNext = withInput(await statement({ session: ST.session, counter: 1n }));
    const withData = await signedPayload(stNext, wallet, { to: other, value: 0n, data: '0x01' });
    const rc2 = await (await wallet.execute(withData.payload, withData.sig, stNext.a, stNext.b, stNext.c, stNext.pub)).wait();
    assert.equal(parseExecuteReceipt(rc2, wallet.target).executed.success, false);
  });

  it('V7: mask ≠ 0 이면 대상이 꼬리 15워드를 읽고 AttrGate.claim 이 통과한다; Disclosure 이벤트; 두 번째 claim 은 already claimed', async () => {
    const discOpts = { mask: 0b0001n, lo: [0n, 0n, 0n, 0n, 0n, 0n], hi: [1990n, 0n, 0n, 0n, 0n, 0n] };
    const setOpts = { slot: 1, members: [410, 392, 840, 276, 250] };
    const DS = withInput(await statement({ disclosure: discOpts, set: setOpts, counter: 0n }));
    const { wallet, factory } = await deployStack(DS);
    const Gate = await ethers.getContractFactory('AttrGate');
    const gate = await Gate.deploy(await factory.getAddress(), await setRoot([410, 392, 840, 276, 250]), 19n);
    const data = gate.interface.encodeFunctionData('claim');
    const { payload, sig } = await signedPayload(DS, wallet, { to: await gate.getAddress(), data, discMask: 1n, discLo: DS.fx.disclosure.lo, discHi: DS.fx.disclosure.hi, setSel: 2n, setRoot: DS.fx.set.root });
    const rc = await (await wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub)).wait();
    const { executed, disclosure } = parseExecuteReceipt(rc, wallet.target);
    assert.equal(executed.success, true);
    assert.equal(disclosure.mask, 1n); assert.equal(disclosure.hi[0], 1990n);
    assert.equal(disclosure.setSel, 2n); assert.equal(disclosure.setRoot, DS.fx.set.root);
    assert.equal(await gate.claimed(wallet.target), true);
    // 첫 claim 으로 nonce 가 이미 1 이므로 두 번째 시도는 새 π(counter: 1n, 같은 disclosure/set)가 필요하다.
    const DS2 = withInput(await statement({ disclosure: discOpts, set: setOpts, session: DS.session, counter: 1n }));
    const again = await signedPayload(DS2, wallet, { to: await gate.getAddress(), data, discMask: 1n, discLo: DS2.fx.disclosure.lo, discHi: DS2.fx.disclosure.hi, setSel: 2n, setRoot: DS2.fx.set.root });
    const rc2 = await (await wallet.execute(again.payload, again.sig, DS2.a, DS2.b, DS2.c, DS2.pub)).wait();
    assert.equal(parseExecuteReceipt(rc2, wallet.target).executed.success, false, 'already claimed → 내부 호출 실패, nonce 는 소모');
  });

  it('V7: 나이가 정책(minAge)보다 어리면 claim 이 실패(success=false)', async () => {
    // 픽스처 속성은 [1990, 410, 2, 0] 이다. minAge 를 200 으로 잡으면 1990 + 200 은 어떤 현재 연도보다도 크므로
    // 나이 조건(hi[0] + minAge ≤ yearOf(now))이 성립하지 않는다.
    const wide = withInput(await statement({ disclosure: { mask: 1n, lo: [0n, 0n, 0n, 0n, 0n, 0n], hi: [1990n, 0n, 0n, 0n, 0n, 0n] }, set: { slot: 1, members: [410, 392, 840, 276, 250] }, counter: 0n }));
    const { wallet, factory } = await deployStack(wide);
    const Gate = await ethers.getContractFactory('AttrGate');
    const gate = await Gate.deploy(await factory.getAddress(), await setRoot([410, 392, 840, 276, 250]), 200n);
    const data = gate.interface.encodeFunctionData('claim');
    const { payload, sig } = await signedPayload(wide, wallet, { to: await gate.getAddress(), data, discMask: 1n, discLo: wide.fx.disclosure.lo, discHi: wide.fx.disclosure.hi, setSel: 2n, setRoot: wide.fx.set.root });
    const rc = await (await wallet.execute(payload, sig, wide.a, wide.b, wide.c, wide.pub)).wait();
    assert.equal(parseExecuteReceipt(rc, wallet.target).executed.success, false);
    assert.equal(await gate.claimed(wallet.target), false);
  });

  it('V7: EOA 가 꼬리를 흉내 내 AttrGate.claim 을 직접 부르면 not a mode3 wallet', async () => {
    const { factory } = await deployStack(ST);
    const Gate = await ethers.getContractFactory('AttrGate');
    const gate = await Gate.deploy(await factory.getAddress(), await setRoot([410, 392, 840, 276, 250]), 19n);
    const [eoa] = await ethers.getSigners();
    const tail = ethers.AbiCoder.defaultAbiCoder().encode(['uint256', 'uint256[6]', 'uint256[6]', 'uint256', 'uint256'], [1n, [0n, 0n, 0n, 0n, 0n, 0n], [1990n, 0n, 0n, 0n, 0n, 0n], 2n, await setRoot([410, 392, 840, 276, 250])]);
    await expect(eoa.sendTransaction({ to: await gate.getAddress(), data: gate.interface.encodeFunctionData('claim') + tail.slice(2) })).to.be.revertedWith('not a mode3 wallet');
  });

  it('V6: 다이제스트가 mask 를 덮는다 — mask 0 으로 서명한 σ 로 mask 3 의 π 를 붙이면 BadSignature', async () => {
    const DS = withInput(await statement({ disclosure: { mask: 0b0011n, lo: [0n, 410n, 0n, 0n, 0n, 0n], hi: [2007n, 410n, 0n, 0n, 0n, 0n] }, counter: 0n }));
    const { wallet } = await deployStack(DS);
    const { payload, sig } = await signedPayload(DS, wallet, { discMask: 0n });
    await assert.rejects(wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub), /BadSignature/);
  });

  it('V6: 다이제스트가 lo/hi 를 덮는다 — 같은 mask 로 서명하되 hi[0] 만 다르게 서명한 σ 는 BadSignature', async () => {
    const DS = withInput(await statement({ disclosure: { mask: 0b0011n, lo: [0n, 410n, 0n, 0n, 0n, 0n], hi: [2007n, 410n, 0n, 0n, 0n, 0n] }, counter: 0n }));
    const { wallet } = await deployStack(DS);
    const wrongHi = [9999n, ...DS.fx.disclosure.hi.slice(1)];
    const { payload, sig } = await signedPayload(DS, wallet, { discMask: 0b0011n, discLo: DS.fx.disclosure.lo, discHi: wrongHi });
    await assert.rejects(wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub), /BadSignature/);
  });

  it('V6: pub[15] ≥ 64 는 BadDisclosure (증명 검증 전에 걸린다)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet, { discMask: 64n });
    const pub = [...ST.pub]; pub[15] = 64n;
    await assert.rejects(wallet.execute(payload, sig, ST.a, ST.b, ST.c, pub), /BadDisclosure/);
  });

  it('V6: factory.isWallet 은 배포한 지갑만 true', async () => {
    const { factory, walletAddr } = await deployStack(ST);
    assert.equal(await factory.isWallet(walletAddr), true);
    assert.equal(await factory.isWallet(ethers.Wallet.createRandom().address), false);
  });

  it('V7: 다이제스트가 set_sel·set_root 를 덮는다 — 서명은 sel 0 인데 π 는 sel 2 면 BadSignature', async () => {
    const DS = withInput(await statement({ set: { slot: 1, members: [410, 392, 840, 276, 250] }, counter: 0n }));
    const { wallet } = await deployStack(DS);
    const { payload, sig } = await signedPayload(DS, wallet);   // setSel 0, setRoot 0 으로 서명
    await expect(wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
  });
  it('V7: 단순 송금 예외는 mask = 0 이고 set_sel = 0 일 때만 — set_sel ≠ 0 이면 data 가 비어도 꼬리가 붙어 receive()-only 대상은 실패', async () => {
    const DS = withInput(await statement({ set: { slot: 1, members: [410, 392, 840, 276, 250] }, counter: 0n }));
    const { wallet, factory } = await deployStack(DS);
    const other = await factory.computeAddress(BigInt(DS.input().PPID) + 1n);
    await (await factory.deploy(BigInt(DS.input().PPID) + 1n)).wait();
    const { payload, sig } = await signedPayload(DS, wallet, { to: other, value: 0n, data: '0x', setSel: 2n, setRoot: DS.fx.set.root });
    const rc = await (await wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub)).wait();
    assert.equal(parseExecuteReceipt(rc, wallet.target).executed.success, false);
  });

  // ── 2026-09-25 리뷰 ────────────────────────────────────────────────────────────────────────────

  it('E-1: 서명한 payload 와 다른 payload 를 제출하면 BadSignature (다이제스트가 to·value·data 를 덮는다)', async () => {
    const { wallet } = await deployStack(ST);
    const recipientA = ethers.Wallet.createRandom().address;
    const { payload, sig } = await signedPayload(ST, wallet, { to: recipientA, value: 1n, data: '0x1234' });
    for (const tampered of [
      { ...payload, to: ethers.Wallet.createRandom().address },
      { ...payload, value: payload.value + 1n },
      { ...payload, data: payload.data + 'ff' },
    ]) {
      await expect(wallet.execute(tampered, sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
    }
    // 대조: 서명한 그대로면 통과한다 — 위 셋이 "아무 payload 나 막는다" 로 공허하게 통과하지 않게 한다.
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).to.not.be.reverted;
  });

  it('I-4: 마스크 비트가 0 인 슬롯의 lo/hi 가 0 이 아니면 BadDisclosure (회로가 제약하지 않는 값이라 꼬리·이벤트로 내보내지 않는다)', async () => {
    // mask = 0b0001 이라 회로가 검사하는 것은 슬롯 0 뿐이다(0 ≤ 1990 ≤ 2007). 슬롯 1 의 hi 에 1990 을 실어도
    // 회로는 64비트 범위 말고 아무 제약도 걸지 않아 π 는 정상적으로 만들어진다 — 즉 증명자가 고른 값이다.
    const DS = withInput(await statement({ disclosure: { mask: 0b0001n, lo: [0n, 0n, 0n, 0n, 0n, 0n], hi: [2007n, 1990n, 0n, 0n, 0n, 0n] }, counter: 0n }));
    assert.equal(DS.publicSignals[23], '1990', '픽스처가 마스크 밖 슬롯(pub[23] = disc_hi[1])에 값을 싣지 못했다 — 전제가 깨졌다');
    const { wallet } = await deployStack(DS);
    const { payload, sig } = await signedPayload(DS, wallet, { discMask: 0b0001n, discLo: [0n, 0n, 0n, 0n, 0n, 0n], discHi: [2007n, 1990n, 0n, 0n, 0n, 0n] });
    await expect(wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub)).to.be.revertedWithCustomError(wallet, 'BadDisclosure');
  });

  it('I-4: 마스크 밖 슬롯이 0 이면 그대로 통과한다 (정직한 지갑 normalizeDisclosure 의 출력)', async () => {
    const DS = withInput(await statement({ disclosure: { mask: 0b0001n, lo: [0n, 0n, 0n, 0n, 0n, 0n], hi: [2007n, 0n, 0n, 0n, 0n, 0n] }, counter: 0n }));
    const { wallet } = await deployStack(DS);
    const { payload, sig } = await signedPayload(DS, wallet, { discMask: 0b0001n, discLo: [0n, 0n, 0n, 0n, 0n, 0n], discHi: [2007n, 0n, 0n, 0n, 0n, 0n] });
    await expect(wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub)).to.not.be.reverted;
  });

  it('A-2: 다이제스트가 allowAgent 를 덮는다 — 같은 사용자·같은 세션키의 다른 π 로 바꿔 끼우면 BadSignature', async () => {
    const S0 = withInput(await statement({ allowAgent: 0n, counter: 0n }));
    const { wallet } = await deployStack(S0);
    // 같은 pk_i·같은 max_height 인데 allowAgent 만 1 인 두 번째 성명. PPID 가 같으니 같은 지갑에 들어간다.
    const S1 = withInput(await statement({ allowAgent: 1n, session: S0.session, maxHeight: BigInt(S0.fx.input.max_height), counter: 0n }));
    assert.equal(S1.publicSignals[0], S0.publicSignals[0], '같은 지갑이어야 바꿔 끼우기가 성립한다');
    assert.equal(S1.publicSignals[5], '1');
    assert.equal(S0.publicSignals[5], '0');
    const { payload, sig } = await signedPayload(S0, wallet);
    // 릴레이어가 σ 는 그대로 두고 π 만 바꾼다 — Mode3Auth 가 허가받지 않은 allowAgent = 1 을 남기게 된다.
    await expect(wallet.execute(payload, sig, S1.a, S1.b, S1.c, S1.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
    // 대조: 서명한 그 π 는 같은 σ 로 통과한다(바뀐 것이 π 뿐임을 못 박는다).
    await expect(wallet.execute(payload, sig, S0.a, S0.b, S0.c, S0.pub)).to.not.be.reverted;
  });

  it('A-2: 다이제스트가 max_height·allowAgent·태그 세 워드를 각각 덮는다 — pub 한 워드만 바꿔도 BadSignature', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    for (const i of [3, 5, 12, 13, 14]) {
      const p = [...ST.pub];
      p[i] = '0x' + (BigInt(ST.pub[i]) + 1n).toString(16);
      await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, p)).to.be.revertedWithCustomError(wallet, 'BadSignature');
    }
  });

  it('A-2: payloadDigest 는 성명 다섯 필드를 기본값으로 채우지 않는다 — 빠뜨리면 던진다(조용히 틀린 σ 방지)', () => {
    const base = {
      chainId: 31337n, wallet: ethers.ZeroAddress, to: ethers.ZeroAddress, value: 0n, data: '0x', nonce: 0n,
      maxHeight: 1n, allowAgent: 0n, tagC1X: 1n, tagC1Y: 2n, tagC2: 3n,
    };
    expect(() => payloadDigest(base)).to.not.throw();
    for (const k of STMT_KEYS) {
      const missing = { ...base };
      delete missing[k];
      expect(() => payloadDigest(missing), k).to.throw(new RegExp(k));
    }
  });

  // ── 2026-10-22 설계 §6.5: counter == nonce, 세션키별 온체인 상한(setSessionBound) ──────────────────

  it('counter 는 로그인 값(2^32−1)이 아니라 nonce 와 같아야 한다 — 다르면 CounterMismatch', async () => {
    const st = withInput(await statement());                       // 기본 counter = LOGIN_COUNTER
    const { wallet } = await deployStack(st);
    const { payload, sig } = await signedPayload(st, wallet);
    await expect(wallet.execute(payload, sig, st.a, st.b, st.c, st.pub)).to.be.revertedWithCustomError(wallet, 'CounterMismatch');
    const st0 = withInput(await statement({ session: st.session, counter: 0n }));
    const ok = await signedPayload(st0, wallet);
    await (await wallet.execute(ok.payload, ok.sig, st0.a, st0.b, st0.c, st0.pub)).wait();
    expect(await wallet.nonce()).to.equal(1n);
  });
  it('setSessionBound 는 자기 호출(execute 경유)로만, 낮추기만; 설정 뒤 그 세션키의 nonce ≥ bound 는 SessionBounded', async () => {
    const s1 = ethers.Wallet.createRandom(), s2 = ethers.Wallet.createRandom();
    const A0 = withInput(await statement({ session: s1, counter: 0n }));
    const { wallet, walletAddr } = await deployStack(A0);
    await expect(wallet.setSessionBound(BigInt(s1.address), 1)).to.be.revertedWithCustomError(wallet, 'OnlySelf');
    // s1 로 nonce 0 실행(허용) → s2 가 자기 호출로 s1 의 상한 1 설정 → s1 의 nonce 2 는 거절, 다른 키(s2) 는 무관
    let p = await signedPayload(A0, wallet); await (await wallet.execute(p.payload, p.sig, A0.a, A0.b, A0.c, A0.pub)).wait();
    const B1 = withInput(await statement({ session: s2, counter: 1n }));
    const data = wallet.interface.encodeFunctionData('setSessionBound', [BigInt(s1.address), 1]);
    p = await signedPayload(B1, wallet, { to: walletAddr, data });
    const rc = await (await wallet.execute(p.payload, p.sig, B1.a, B1.b, B1.c, B1.pub)).wait();
    expect(rc.logs.some((l) => { try { return wallet.interface.parseLog(l)?.name === 'SessionBound'; } catch { return false; } })).to.equal(true);
    expect(await wallet.sessionBound(BigInt(s1.address))).to.equal(2n);   // 저장값 = bound + 1
    const A2 = withInput(await statement({ session: s1, counter: 2n }));
    p = await signedPayload(A2, wallet);
    await expect(wallet.execute(p.payload, p.sig, A2.a, A2.b, A2.c, A2.pub)).to.be.revertedWithCustomError(wallet, 'SessionBounded');
    // 올리기(2) 는 BoundNotLowered, 낮추기(0) 는 된다
    const B2 = withInput(await statement({ session: s2, counter: 2n }));
    p = await signedPayload(B2, wallet, { to: walletAddr, data: wallet.interface.encodeFunctionData('setSessionBound', [BigInt(s1.address), 2]) });
    const rc2 = await (await wallet.execute(p.payload, p.sig, B2.a, B2.b, B2.c, B2.pub)).wait();   // execute 자체는 성공, 내부 호출이 실패(Executed.success=false)
    expect(parseExecuteReceipt(rc2, walletAddr).executed.success).to.equal(false);
    expect(await wallet.sessionBound(BigInt(s1.address))).to.equal(2n);

    // "낮추기(0) 는 된다" 를 실제로 실행: 새 세션키 s3 에 counter 3 성명(authorizer s2)으로 bound 3 을
    // 설정한 뒤(처음 설정이라 cur == 0 이라 통과) 0 으로 낮추고, sessionBound == 1n(= 0 + 1) 과
    // SessionBound 이벤트 인자 (pk_i, 0) 을 확인한다.
    const s3 = ethers.Wallet.createRandom();
    const B3 = withInput(await statement({ session: s2, counter: 3n }));
    p = await signedPayload(B3, wallet, { to: walletAddr, data: wallet.interface.encodeFunctionData('setSessionBound', [BigInt(s3.address), 3]) });
    const rc3 = await (await wallet.execute(p.payload, p.sig, B3.a, B3.b, B3.c, B3.pub)).wait();
    expect(parseExecuteReceipt(rc3, walletAddr).executed.success).to.equal(true);
    expect(await wallet.sessionBound(BigInt(s3.address))).to.equal(4n);   // bound 3 + 1
    const B4 = withInput(await statement({ session: s2, counter: 4n }));
    p = await signedPayload(B4, wallet, { to: walletAddr, data: wallet.interface.encodeFunctionData('setSessionBound', [BigInt(s3.address), 0]) });
    const rc4 = await (await wallet.execute(p.payload, p.sig, B4.a, B4.b, B4.c, B4.pub)).wait();
    expect(parseExecuteReceipt(rc4, walletAddr).executed.success).to.equal(true);
    const lowered = rc4.logs.map((l) => { try { return wallet.interface.parseLog(l); } catch { return null; } }).find((l) => l?.name === 'SessionBound');
    expect(lowered?.args.pk_i).to.equal(BigInt(s3.address));
    expect(lowered?.args.bound).to.equal(0n);
    expect(await wallet.sessionBound(BigInt(s3.address))).to.equal(1n);   // 저장값 = 0 + 1

    // BoundNotLowered·OnlySelf 를 이름으로 직접 단언 — π 없이 setSessionBound 자체 로직만 본다.
    // 지갑 주소를 가장(impersonate)해 msg.sender == address(this) 를 만들어 OnlySelf 를 지나간다
    // (deployStack 이 이미 walletAddr 에 1 ETH 를 보냈으므로 가스는 충분해 hardhat_setBalance 는 필요 없다).
    await ethers.provider.send('hardhat_impersonateAccount', [walletAddr]);
    const asWallet = wallet.connect(await ethers.getSigner(walletAddr));
    await expect(asWallet.setSessionBound(BigInt(s3.address), 5)).to.be.revertedWithCustomError(wallet, 'BoundNotLowered');   // (a) 더 큰 값(올리기)
    await expect(asWallet.setSessionBound(BigInt(s3.address), 0)).to.be.revertedWithCustomError(wallet, 'BoundNotLowered');   // (b) 같은 값(현재도 bound 0)
    await ethers.provider.send('hardhat_stopImpersonatingAccount', [walletAddr]);
    // 가장을 풀어도 외부 EOA 의 직접 호출은 여전히 OnlySelf.
    await expect(wallet.setSessionBound(BigInt(s3.address), 0)).to.be.revertedWithCustomError(wallet, 'OnlySelf');
  });
});
