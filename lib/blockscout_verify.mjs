// 로컬 Blockscout 컨트랙트 자동 검증의 순수 함수 — 스펙 docs/superpowers/specs/2026-11-18-blockscout-auto-verify-design.md §2.
// 감시자(scripts/blockscout_verify_watch.mjs)가 쓴다. 체인도 Blockscout 도 부르지 않는다 — hardhat 산출물(artifacts/)만 읽는다.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'artifacts');
/** 응용 체인에 올라오는 컨트랙트(스펙 §0)와 폐기(RCL) 체인의 캐노니컬 로그 Mode3Log(2026-11-25) — 감시자 둘이 같은 목록을 쓴다(체인에 없는 것은 나타나지 않을 뿐이다). */
export const TARGETS = ['Mode3Mirror', 'PiCredVerifier', 'Mode3WalletFactory', 'AttrGate', 'Mode3Wallet', 'Mode3Log'];
/** Mode3WalletFactory.deploy(uint256) — 지갑은 이 호출로만 생긴다(팩토리는 이벤트를 내지 않는다, B6). */
export const DEPLOY_SELECTOR = ethers.id('deploy(uint256)').slice(0, 10);
/** Mode3Wallet 생성자 인자의 타입(contracts/Mode3Wallet.sol) — ppid 뒤는 팩토리의 public immutable 게터와 같은 순서다. */
const WALLET_CTOR_TYPES = ['uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'address', 'address', 'uint64', 'uint64', 'uint64'];
export const FACTORY_GETTERS = ['arid', 'pkCIAX', 'pkCIAY', 'pkTraceX', 'pkTraceY', 'verifier', 'log', 'maxRootAge', 'maxLifetime', 'rootWindow'];

/** 대상 artifact 와 그 컴파일 job(build-info)을 읽는다. build-info 는 **<이름>.dbg.json 이 가리키는 파일 하나**다 — 같은 소스를 담은 다른 build-info 는
 *  설정(viaIR)이 달라 배포되는 것과 다른 코드를 낼 수 있다(PiCredVerifier). immutable 위치는 artifact 에 없고 build-info 의 output 에만 있다(B4). */
export function loadArtifacts(names = TARGETS, root = ROOT) {
  return names.map((name) => {
    const dir = path.join(root, 'contracts', `${name}.sol`);
    const art = JSON.parse(fs.readFileSync(path.join(dir, `${name}.json`), 'utf8'));
    const buildInfoPath = path.resolve(dir, JSON.parse(fs.readFileSync(path.join(dir, `${name}.dbg.json`), 'utf8')).buildInfo);
    const bi = JSON.parse(fs.readFileSync(buildInfoPath, 'utf8'));
    const refs = bi.output.contracts[art.sourceName][name].evm.deployedBytecode.immutableReferences ?? {};
    return { name, sourceName: art.sourceName, abi: art.abi, bytecode: art.bytecode, deployedBytecode: art.deployedBytecode,
      immutableRefs: Object.values(refs).flat().map(({ start, length }) => ({ start, length })), buildInfoPath, solcLongVersion: bi.solcLongVersion, standardInput: bi.input };
  });
}

const maskedHex = (hex, refs) => { const b = Buffer.from(hex.slice(2), 'hex'); for (const { start, length } of refs) b.fill(0, start, start + length); return b.toString('hex'); };
/** 체인의 런타임 코드가 어느 대상의 것인지 — immutable 자리를 0 으로 가리고 견준다. 맞는 것이 없으면 null(테스트·벤치 컨트랙트는 건너뛴다). */
export function matchRuntime(code, artifacts) {
  if (typeof code !== 'string' || code.length <= 2) return null;
  for (const a of artifacts) {
    if (code.length !== a.deployedBytecode.length) continue;
    if (maskedHex(code.toLowerCase(), a.immutableRefs) === maskedHex(a.deployedBytecode.toLowerCase(), a.immutableRefs)) return a.name;
  }
  return null;
}

/** 직접 배포 tx 의 입력에서 생성자 인자(hex, 0x 없음)를 뗀다 — 입력이 이 artifact 의 생성 코드로 시작하지 않으면 null(B5). */
export function ctorArgsFromCreation(input, artifact) {
  const code = artifact.bytecode.toLowerCase(), data = String(input).toLowerCase();
  return data.startsWith(code) ? data.slice(code.length) : null;
}

/** 팩토리가 만든 지갑의 생성자 인자(hex, 0x 없음) — factoryValues 는 팩토리 게터(FACTORY_GETTERS)로 읽은 값(B6). */
export function walletCtorArgs(factoryValues, ppid) {
  return ethers.AbiCoder.defaultAbiCoder().encode(WALLET_CTOR_TYPES, [ppid, ...FACTORY_GETTERS.map((k) => factoryValues[k])]).slice(2);
}
