// Mode3Wallet / Mode3WalletFactory — 설계 2026-09-18 §5. hardhat 인프로세스 체인(contract 그룹).
// 증명은 tests/helpers/mode3_fixture.mjs 의 픽스처로 실제로 만든다(build/mode3 산출물 필요).
import { expect } from 'chai';
import hre from 'hardhat';
import fs from 'node:fs';
import * as snarkjs from 'snarkjs';
import { buildValidInput } from '../tests/helpers/mode3_fixture.mjs';
import { signRootPublication, rootToBytes32 } from '../lib/mode3_log.js';
import { signPayload, proofToCalldata, decodeExecuteCalldata, parseExecuteReceipt, MAX_ROOT_AGE_DEFAULT } from '../lib/mode3_onchain.js';

const { ethers } = hre;
const WASM = 'build/mode3/pi_cred_js/pi_cred.wasm', ZKEY = 'build/mode3/pi_cred_final.zkey';

describe('Mode3Wallet', function () {
  this.timeout(180_000);
  before(() => { if (!fs.existsSync(ZKEY)) throw new Error(`${ZKEY} 없음 — bash scripts/build_mode3_circuit.sh`); });

  const chainId = () => ethers.provider.getNetwork().then((n) => n.chainId);

  /** 세션키 + 픽스처 증명. 옵션은 픽스처로 전달. */
  async function statement(opts = {}) {
    const session = ethers.Wallet.createRandom();
    const fx = await buildValidInput({ pk_i: BigInt(session.address), chainid: await chainId(), ...opts });
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(fx.input, WASM, ZKEY);
    const cd = await proofToCalldata(proof, publicSignals);
    return { session, fx, proof, publicSignals, ...cd };
  }

  /** 픽스처의 root 로 RevocationLog 를 배포하고(초기 root = 픽스처 트리), 검증자·팩토리·지갑까지. */
  async function deployStack(st, { arid = st.fx.arid, maxRootAge = MAX_ROOT_AGE_DEFAULT } = {}) {
    const [deployer, cia] = await ethers.getSigners();
    const Log = await ethers.getContractFactory('RevocationLog');
    const log = await Log.deploy(cia.address, rootToBytes32(BigInt(st.input().revRoot)));
    const Verifier = await ethers.getContractFactory('PiCredVerifier');
    const verifier = await Verifier.deploy();
    const Factory = await ethers.getContractFactory('Mode3WalletFactory');
    const factory = await Factory.deploy(await verifier.getAddress(), arid, st.fx.ciaPub.x, st.fx.ciaPub.y, st.fx.pk_trace.x, st.fx.pk_trace.y, await log.getAddress(), maxRootAge);
    const ppid = BigInt(st.input().PPID);
    const walletAddr = await factory.computeAddress(ppid);
    await (await deployer.sendTransaction({ to: walletAddr, value: ethers.parseEther('1') })).wait();
    await (await factory.deploy(ppid)).wait();
    const wallet = await ethers.getContractAt('Mode3Wallet', walletAddr);
    return { deployer, cia, log, verifier, factory, wallet, walletAddr, ppid };
  }
  const withInput = (st) => ({ ...st, input: () => st.fx.input });

  async function signedPayload(st, wallet, { to = ethers.Wallet.createRandom().address, value = 0n, data = '0x' } = {}) {
    const nonce = await wallet.nonce();
    const payload = { to, value, data, nonce };
    const sig = signPayload(st.session, { chainId: await chainId(), wallet: wallet.target, ...payload });
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
    expect(wrongTarget).to.deep.equal({ executed: null, auth: null });
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
  });
});
