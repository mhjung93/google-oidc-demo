// 로컬 Blockscout 자동 검증의 순수 함수(lib/blockscout_verify.mjs) — 스펙 docs/superpowers/specs/2026-11-18-blockscout-auto-verify-design.md §3.
// 체인도 Blockscout 도 쓰지 않는다. hardhat 컴파일 산출물(artifacts/ — git 에는 없다)만 읽는다: 없으면 BLOCKED 로 끝난다(npx hardhat compile).
//   node tests/test_blockscout_verify.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { TARGETS, loadArtifacts, matchRuntime, ctorArgsFromCreation, walletCtorArgs, DEPLOY_SELECTOR } from '../lib/blockscout_verify.mjs';

if (!fs.existsSync(new URL('../artifacts/build-info', import.meta.url))) { console.log('BLOCKED: artifacts/ 가 없다 — npx hardhat compile'); process.exit(1); }

let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

const arts = loadArtifacts();
const by = Object.fromEntries(arts.map((a) => [a.name, a]));
/** immutable 자리에 0 이 아닌 값을 채운 런타임 코드 — 체인에 올라간 모습을 흉내 낸다. */
const filled = (a, byte = 0xab) => { const b = Buffer.from(a.deployedBytecode.slice(2), 'hex'); for (const { start, length } of a.immutableRefs) b.fill(byte, start, start + length); return '0x' + b.toString('hex'); };

t('대상 여섯 개를 모두 읽는다(2026-11-25: 폐기 체인의 Mode3Log)', () => {
  assert.deepEqual(arts.map((a) => a.name), TARGETS);
  assert.deepEqual(TARGETS, ['Mode3Mirror', 'PiCredVerifier', 'Mode3WalletFactory', 'AttrGate', 'Mode3Wallet', 'Mode3Log']);
  for (const a of arts) { assert.match(a.solcLongVersion, /^0\.8\.24\+commit\./, a.name); assert.ok(a.standardInput.sources[a.sourceName], `${a.name}: 표준 입력에 자기 소스`); }
});

// §2: build-info 는 <이름>.dbg.json 이 가리키는 파일 하나다 — PiCredVerifier 는 build-info 여럿에 들어 있고 대부분 배포되는 것과 다른 코드를 낸다.
t('고른 build-info 의 런타임 코드가 artifact 와 같다(여섯 대상 모두)', () => {
  for (const a of arts) {
    const bi = JSON.parse(fs.readFileSync(a.buildInfoPath, 'utf8'));
    assert.equal('0x' + bi.output.contracts[a.sourceName][a.name].evm.deployedBytecode.object, a.deployedBytecode, a.name);
  }
});

t('immutable 자리를 채운 런타임 코드가 자기 이름으로 판별되고 다른 이름과 섞이지 않는다', () => {
  for (const a of arts) { assert.equal(matchRuntime(filled(a), arts), a.name); assert.equal(matchRuntime(a.deployedBytecode, arts), a.name); }
  assert.equal(matchRuntime('0x', arts), null);
  assert.equal(matchRuntime('0x6080604052', arts), null);
});

t('immutable 가림은 그 자리만 가린다 — 다른 바이트가 바뀌면 판별되지 않는다', () => {
  assert.equal(by.Mode3Wallet.immutableRefs.length > 0 && by.Mode3WalletFactory.immutableRefs.length > 0 && by.AttrGate.immutableRefs.length > 0 && by.Mode3Mirror.immutableRefs.length > 0, true);
  assert.equal(by.PiCredVerifier.immutableRefs.length, 0, 'PiCredVerifier 는 immutable 이 없다');
  for (const a of arts) {
    const masked = new Set(); for (const { start, length } of a.immutableRefs) for (let i = start; i < start + length; i++) masked.add(i);
    const b = Buffer.from(filled(a).slice(2), 'hex');
    let i = 0; while (masked.has(i)) i++;   // 가려지지 않는 첫 바이트
    b[i] ^= 0xff;
    assert.equal(matchRuntime('0x' + b.toString('hex'), arts), null, a.name);
  }
});

t('ctorArgsFromCreation: 생성 tx 입력에서 생성자 인자를 되돌린다', () => {
  const args = ethers.AbiCoder.defaultAbiCoder().encode(['address', 'uint256', 'uint256'], ['0x' + '11'.repeat(20), 7n, 19n]);
  assert.equal(ctorArgsFromCreation(by.AttrGate.bytecode + args.slice(2), by.AttrGate), args.slice(2));
  assert.equal(ctorArgsFromCreation(by.PiCredVerifier.bytecode, by.PiCredVerifier), '', '인자 없는 생성자');
  // 폐기 체인의 로그: constructor(address cia, bytes32 emptyRevRoot, bytes32 emptyRegRoot)
  const la = ethers.AbiCoder.defaultAbiCoder().encode(by.Mode3Log.abi.find((x) => x.type === 'constructor').inputs.map((i) => i.type), ['0x' + '11'.repeat(20), '0x' + '22'.repeat(32), '0x' + '33'.repeat(32)]);
  assert.equal(ctorArgsFromCreation(by.Mode3Log.bytecode + la.slice(2), by.Mode3Log), la.slice(2)); assert.equal(ctorArgsFromCreation(by.Mode3Log.bytecode + la.slice(2), by.Mode3Mirror), null, '거울과 섞이지 않는다');
  assert.equal(ctorArgsFromCreation('0x6080' + args.slice(2), by.AttrGate), null, '이 artifact 의 생성 코드가 아니다');
});

t('walletCtorArgs: Mode3Wallet 생성자 ABI 로 풀면 순서가 맞다(ppid 가 맨 앞, 나머지는 팩토리 값)', () => {
  const f = { arid: 2n, pkCIAX: 3n, pkCIAY: 4n, pkTraceX: 5n, pkTraceY: 6n, verifier: '0x' + '22'.repeat(20), log: '0x' + '33'.repeat(20), maxRootAge: 100n, maxLifetime: 400n, rootWindow: 20n };
  const hex = walletCtorArgs(f, 1n);
  const ctor = by.Mode3Wallet.abi.find((x) => x.type === 'constructor');
  assert.deepEqual(ctor.inputs.map((i) => i.name), ['_ppid', '_arid', '_pkCIAX', '_pkCIAY', '_pkTraceX', '_pkTraceY', '_verifier', '_log', '_maxRootAge', '_maxLifetime', '_rootWindow']);
  const d = ethers.AbiCoder.defaultAbiCoder().decode(ctor.inputs.map((i) => i.type), '0x' + hex);
  assert.deepEqual(d.map((v) => (typeof v === 'string' ? v.toLowerCase() : v)), [1n, 2n, 3n, 4n, 5n, 6n, f.verifier, f.log, 100n, 400n, 20n]);
});

t('DEPLOY_SELECTOR 는 팩토리의 deploy(uint256)', () => {
  assert.equal(DEPLOY_SELECTOR, new ethers.Interface(by.Mode3WalletFactory.abi).getFunction('deploy').selector);
});

console.log(fails ? `\n${fails} FAILED` : '\nall ok');
process.exit(fails ? 1 : 0);
