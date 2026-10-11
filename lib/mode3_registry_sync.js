// Mode 3 지갑의 등록부 동기화(설계 2026-10-01 §8.1) — Mode3Log 의 SlotUpdated 이벤트를 창세기부터 순서대로 재생해 트리를 만들고
// 같은 head 의 regRoot 와 대조한다(fail-closed). 캐시·증분은 두지 않는다(데모 규모; 후속 과제).
import { ethers } from 'ethers';
import { MODE3_LOG_ABI } from './mode3_log.js';
import { createRegistryTree } from './mode3_registry.js';

/**
 * V10(2026-10-02 §7/§9) — untilEpoch·expectRoot: lib/mode3_wallet.js syncRevocationTree 와 같은 규칙이다.
 * 거울의 (regRoot, epoch) 시점까지만 재생해야 할 때(Task 9) untilEpoch 보다 큰 args.epoch 의 SlotUpdated 는
 * 건너뛰고, expectRoot(거울의 regRoot)와 대조한다 — null 이면 대조를 생략한다. untilEpoch 가 없으면 현행 그대로.
 */
export async function syncRegistryTree(provider, logAddress, { untilEpoch = null, expectRoot = null } = {}) {
  const log = new ethers.Contract(logAddress, MODE3_LOG_ABI, provider);
  const head = BigInt(await provider.getBlockNumber());
  const blockTag = Number(head);
  const [events, onchainRoot, onchainEpoch] = await Promise.all([log.queryFilter(log.filters.SlotUpdated(), 0, blockTag), log.regRoot({ blockTag }), log.epoch({ blockTag })]);
  const tree = await createRegistryTree();
  // 이벤트 순서 = 블록·로그 인덱스 순. 같은 칸의 set → 0 이 순서대로 적용돼야 root 가 맞는다.
  // 정렬 키의 a.index/b.index 는 ethers v6 Log 객체의 블록 내 로그 위치(log index)다 — 바로 아래
  // e.args.index(등록부 슬롯 번호, SlotUpdated 의 두 번째 인자)와 이름만 같을 뿐 다른 값이니 혼동하지 말 것.
  events.sort((a, b) => (a.blockNumber - b.blockNumber) || (a.index - b.index));
  for (const e of events) {
    if (untilEpoch !== null && BigInt(e.args.epoch) > BigInt(untilEpoch)) continue;
    tree.set(Number(e.args.index), BigInt(e.args.leaf));
  }
  const root = tree.root();
  if (untilEpoch === null) {
    if (root !== BigInt(onchainRoot)) throw new Error(`등록부 재생 root(${root}) 가 컨트랙트 regRoot(${BigInt(onchainRoot)}) 와 다르다 — 이벤트 규약 불일치 또는 calldata 오염`);
    return { tree, root, epoch: BigInt(onchainEpoch), head };
  }
  const epoch = BigInt(untilEpoch);
  if (expectRoot !== null && root !== BigInt(expectRoot)) throw new Error(`등록부 재생 root(${root}) 가 거울 regRoot(${BigInt(expectRoot)}) 와 다르다 — epoch ${epoch} 까지`);
  return { tree, root, epoch, head };
}

export function createRegistrySync({ provider, logAddress }) {
  if (!logAddress) throw new Error('createRegistrySync: logAddress 가 필요하다');
  return { sync: () => syncRegistryTree(provider, logAddress) };
}
