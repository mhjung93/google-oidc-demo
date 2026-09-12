// :8545 hardhat 노드용 헬퍼 (chain 그룹). 컨트랙트 테스트(test/*.test.mjs)는 이걸 쓰지
// 않는다 — 그쪽은 hardhat 인프로세스 체인이다.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { createRevocationTree } from '../../lib/mode3_revocation.js';

const ROOT_DIR = fileURLToPath(new URL('../..', import.meta.url));
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const ARTIFACT = path.join(ROOT_DIR, 'artifacts', 'contracts', 'RevocationLog.sol', 'RevocationLog.json');

export const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes('MODE3_REVOCATION_ROOT_V1'));
export const rootToBytes32 = (n) => ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32);

function artifact() {
  if (!fs.existsSync(ARTIFACT)) {
    execFileSync('npx', ['hardhat', 'compile', '--quiet'], { cwd: ROOT_DIR, stdio: 'inherit' });
  }
  return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
}
export const logAbi = () => artifact().abi;

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

export async function mineBlocks(n, provider = getProvider()) {
  await provider.send('hardhat_mine', ['0x' + n.toString(16)]);
}

/**
 * 컨트랙트 digestFor 와 같은 내부 digest 에 EIP-191 서명. leaves 는 bytes32 hex 배열.
 * logAddress 는 필수다 — digest 가 로그 주소를 덮어, 같은 CIA 키로 재배포한 다른 로그에
 * 옛 게시를 재생할 수 없게 한다. cia.js 의 /cia/publish 와 바이트 단위로 같아야 한다.
 */
export async function signRootPublication(wallet, { logAddress, root, epoch, leaves }) {
  if (!logAddress) throw new Error('signRootPublication: logAddress 가 필요하다 (digest 가 로그 주소를 덮는다)');
  const leavesHash = ethers.keccak256(ethers.solidityPacked(leaves.map(() => 'bytes32'), leaves));
  const inner = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'address', 'bytes32', 'uint64', 'bytes32'], [DOMAIN, logAddress, root, epoch, leavesHash]));
  return wallet.signMessage(ethers.getBytes(inner));
}
