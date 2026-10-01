// Mode 3 지갑의 등록부 동기화(설계 2026-10-01 §8.1) — Mode3Log 의 SlotUpdated 이벤트를 창세기부터 순서대로 재생해 트리를 만들고
// 같은 head 의 regRoot 와 대조한다(fail-closed). 캐시·증분은 두지 않는다(데모 규모; 후속 과제).
import { ethers } from 'ethers';
import { MODE3_LOG_ABI } from './mode3_log.js';
import { createRegistryTree } from './mode3_registry.js';

export async function syncRegistryTree(provider, logAddress) {
  const log = new ethers.Contract(logAddress, MODE3_LOG_ABI, provider);
  const head = BigInt(await provider.getBlockNumber());
  const blockTag = Number(head);
  const [events, onchainRoot, epoch] = await Promise.all([log.queryFilter(log.filters.SlotUpdated(), 0, blockTag), log.regRoot({ blockTag }), log.epoch({ blockTag })]);
  const tree = await createRegistryTree();
  // 이벤트 순서 = 블록·로그 인덱스 순. 같은 칸의 set → 0 이 순서대로 적용돼야 root 가 맞는다.
  events.sort((a, b) => (a.blockNumber - b.blockNumber) || (a.index - b.index));
  for (const e of events) tree.set(Number(e.args.index), BigInt(e.args.leaf));
  const root = tree.root();
  if (root !== BigInt(onchainRoot)) throw new Error(`등록부 재생 root(${root}) 가 컨트랙트 regRoot(${BigInt(onchainRoot)}) 와 다르다 — 이벤트 규약 불일치 또는 calldata 오염`);
  return { tree, root, epoch: BigInt(epoch), head };
}

export function createRegistrySync({ provider, logAddress }) {
  if (!logAddress) throw new Error('createRegistrySync: logAddress 가 필요하다');
  return { sync: () => syncRegistryTree(provider, logAddress) };
}
