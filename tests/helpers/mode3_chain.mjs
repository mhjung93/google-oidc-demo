// :8545 hardhat 노드용 헬퍼 (chain 그룹). 컨트랙트 테스트(test/*.test.mjs)는 이걸 쓰지
// 않는다 — 그쪽은 hardhat 인프로세스 체인이다.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { createRevocationTree } from '../../lib/mode3_revocation.js';
import { createRegistryTree } from '../../lib/mode3_registry.js';
// digest·bytes32 변환은 lib/mode3_log.js 하나다 — 여기는 이름만 다시 내보낸다(이 파일 안에서도 쓴다).
import { DOMAIN_ROOT, rootToBytes32, signRootPublication, signPublicationV3, entryHashes } from '../../lib/mode3_log.js';
export { DOMAIN_ROOT as DOMAIN, rootToBytes32, signRootPublication };

const ROOT_DIR = fileURLToPath(new URL('../..', import.meta.url));
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const ARTIFACT = path.join(ROOT_DIR, 'artifacts', 'contracts', 'RevocationLog.sol', 'RevocationLog.json');
const ARTIFACT_V2 = path.join(ROOT_DIR, 'artifacts', 'contracts', 'Mode3Log.sol', 'Mode3Log.json');
const ARTIFACT_MIRROR = path.join(ROOT_DIR, 'artifacts', 'contracts', 'Mode3Mirror.sol', 'Mode3Mirror.json');

function artifact() {
  if (!fs.existsSync(ARTIFACT)) {
    execFileSync('npx', ['hardhat', 'compile', '--quiet'], { cwd: ROOT_DIR, stdio: 'inherit' });
  }
  return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
}
export const logAbi = () => artifact().abi;

function artifactV2() {
  if (!fs.existsSync(ARTIFACT_V2)) execFileSync('npx', ['hardhat', 'compile', '--quiet'], { cwd: ROOT_DIR, stdio: 'inherit' });
  return JSON.parse(fs.readFileSync(ARTIFACT_V2, 'utf8'));
}

function artifactMirror() {
  if (!fs.existsSync(ARTIFACT_MIRROR)) execFileSync('npx', ['hardhat', 'compile', '--quiet'], { cwd: ROOT_DIR, stdio: 'inherit' });
  return JSON.parse(fs.readFileSync(ARTIFACT_MIRROR, 'utf8'));
}

// 테스트는 게시 직후 수 ms 안에 동기화하므로 provider 레벨 250ms 캐시를 끈다.
export function getProvider() { return new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 }); }
export async function getFunder(provider = getProvider()) { return provider.getSigner(0); }

export async function fundAddress(addr, eth = '1', provider = getProvider()) {
  const funder = await getFunder(provider);
  await (await funder.sendTransaction({ to: addr, value: ethers.parseEther(eth) })).wait();
}

export async function deployRevocationLog(ciaAddress, provider = getProvider()) {
  const { abi, bytecode } = artifact();
  const emptyRoot = rootToBytes32((await createRevocationTree()).getRoot());
  const factory = new ethers.ContractFactory(abi, bytecode, await getFunder(provider));
  const contract = await factory.deploy(ciaAddress, emptyRoot);
  await contract.waitForDeployment();
  return { address: await contract.getAddress(), contract };
}

/** V9: Mode3Log 배포 — 빈 폐기 root + 빈 등록부 root. */
export async function deployMode3Log(ciaAddress, provider = getProvider()) {
  const { abi, bytecode } = artifactV2();
  const emptyRev = rootToBytes32((await createRevocationTree()).getRoot());
  const emptyReg = rootToBytes32((await createRegistryTree()).root());
  const factory = new ethers.ContractFactory(abi, bytecode, await getFunder(provider));
  const contract = await factory.deploy(ciaAddress, emptyRev, emptyReg);
  await contract.waitForDeployment();
  return { address: await contract.getAddress(), contract };
}

export async function mineBlocks(n, provider = getProvider()) {
  await provider.send('hardhat_mine', ['0x' + n.toString(16)]);
}

/** V10: 캐노니컬 Mode3Log 의 chainid·주소를 digest 에 묶는 두 값. */
export async function canonOf(log, provider = getProvider()) {
  return { canonicalChainId: (await provider.getNetwork()).chainId, canonicalLogAddress: await log.getAddress() };
}

/** V10: Mode3Mirror 배포 — 캐노니컬 로그와 같은 빈 root 로 시작한다. */
export async function deployMode3Mirror(ciaAddress, canonicalLogAddress, provider = getProvider()) {
  const { abi, bytecode } = artifactMirror();
  const emptyRev = rootToBytes32((await createRevocationTree()).getRoot());
  const emptyReg = rootToBytes32((await createRegistryTree()).root());
  const factory = new ethers.ContractFactory(abi, bytecode, await getFunder(provider));
  const contract = await factory.deploy(ciaAddress, (await provider.getNetwork()).chainId, canonicalLogAddress, emptyRev, emptyReg);
  await contract.waitForDeployment();
  return { address: await contract.getAddress(), contract };
}

/** V10 게시 헬퍼 — 테스트가 CIA 없이 캐노니컬 Mode3Log 에 두 root 를 올린다. 인자는 bigint, 서명은 ciaWallet. */
export async function publishV3(log, ciaWallet, { revRoot, regRoot, epoch, revLeaves = [], slotIdx = [], slotLeaves = [] }) {
  const b = rootToBytes32;
  const p = { revRoot: b(revRoot), regRoot: b(regRoot), epoch, revLeaves: revLeaves.map(b), slotIdx, slotLeaves: slotLeaves.map(b) };
  const sig = await signPublicationV3(ciaWallet, { ...(await canonOf(log, ciaWallet.provider)), ...p });
  await (await log.connect(ciaWallet).publish(p.revRoot, p.regRoot, epoch, p.revLeaves, slotIdx, p.slotLeaves, sig)).wait();
  return { sig, p };
}

/** V10: 캐노니컬에 이미 올라간 게시(p, sig)를 거울에 중계한다 — 같은 서명이 거울에도 그대로 유효하다. */
export async function relayToMirror(mirror, signer, { p, sig }) {
  const h = entryHashes(p);
  await (await mirror.connect(signer).publish(p.revRoot, p.regRoot, p.epoch, h.hLeaves, h.hIdx, h.hSlots, sig)).wait();
}
