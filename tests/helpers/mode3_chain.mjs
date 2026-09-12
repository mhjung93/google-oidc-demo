// :8545 hardhat 노드용 헬퍼 (chain 그룹). 컨트랙트 테스트(test/*.test.mjs)는 이걸 쓰지
// 않는다 — 그쪽은 hardhat 인프로세스 체인이다.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { createRevocationTree } from '../../lib/mode3_revocation.js';
// digest·bytes32 변환은 lib/mode3_log.js 하나다 — 여기는 이름만 다시 내보낸다(이 파일 안에서도 쓴다).
import { DOMAIN_ROOT, rootToBytes32, signRootPublication } from '../../lib/mode3_log.js';
export { DOMAIN_ROOT as DOMAIN, rootToBytes32, signRootPublication };

const ROOT_DIR = fileURLToPath(new URL('../..', import.meta.url));
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const ARTIFACT = path.join(ROOT_DIR, 'artifacts', 'contracts', 'RevocationLog.sol', 'RevocationLog.json');

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
