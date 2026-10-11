// Mode 3 등록부 — 사용자 자격증명 슬롯 트리(설계 2026-10-01-mode3-v9-registry-design.md §3).
// 깊이 20 증분 머클 트리. 리프 = Poseidon(cm_u.x, cm_u.y, Cf_u), 빈 칸·은퇴 = 0. 내부 노드 = Poseidon(left, right).
// 경로 규약은 회로 circuits/lib/merkle_inclusion.circom 과 같다: pathIndices[i] = ⌊index / 2^i⌋ mod 2, 0 이면 현재 노드가 왼쪽.
// JS 비트연산은 32비트 부호 있는 정수로 변환되므로 depth 32 에서 index ≥ 2^31 이 틀어진다; lib/imt_v2.js 와 같은 산술 연산을 쓴다.
// CIA 가 관리하고(cia.js), 지갑은 Mode3Log 의 SlotUpdated 이벤트로 같은 트리를 복원한다(lib/mode3_registry_sync.js).
import { buildPoseidon } from 'circomlibjs';

export const REG_DEPTH = 20;

let poseidonP = null;
const getPoseidon = () => (poseidonP ??= buildPoseidon());
const big = (v) => (typeof v === 'bigint' ? v : BigInt(v));

/** L_reg(cm_u, Cf_u) = Poseidon(cm_u.x, cm_u.y, Cf_u). cm_u 는 {x, y}(bigint 또는 10진 문자열). */
export async function registryLeaf(cm_u, Cf_u) {
  const ps = await getPoseidon();
  return ps.F.toObject(ps([big(cm_u.x), big(cm_u.y), big(Cf_u)]));
}

/** 경로로 root 를 다시 계산한다 — 지갑이 "내 슬롯 = 내 자격증명" 을 체인 root 와 대조할 때 쓴다. */
export async function computeRoot(leaf, pathElements, pathIndices) {
  const ps = await getPoseidon();
  let cur = big(leaf);
  for (let i = 0; i < pathElements.length; i++) {
    const sib = big(pathElements[i]);
    cur = ps.F.toObject(Number(pathIndices[i]) ? ps([sib, cur]) : ps([cur, sib]));
  }
  return cur;
}

export async function createRegistryTree(depth = REG_DEPTH) {
  if (!Number.isInteger(depth) || depth < 1 || depth > 32) throw new Error('createRegistryTree: depth 는 1..32');
  const ps = await getPoseidon();
  const H = (a, b) => ps.F.toObject(ps([a, b]));
  const zeros = [0n];
  for (let i = 0; i < depth; i++) zeros.push(H(zeros[i], zeros[i]));
  const nodes = Array.from({ length: depth + 1 }, () => new Map());   // level → (index → value); 없으면 zeros[level]
  const get = (lvl, idx) => nodes[lvl].get(idx) ?? zeros[lvl];
  const max = 2 ** depth;
  const checkIndex = (index) => { if (!Number.isInteger(index) || index < 0 || index >= max) throw new Error(`registry: index 범위 밖 ${index} (0..${max - 1})`); };
  return {
    depth,
    set(index, leaf) {
      checkIndex(index);
      const v = big(leaf);
      if (v < 0n) throw new Error('registry: leaf 는 음이 아닌 정수');
      if (v === 0n) nodes[0].delete(index); else nodes[0].set(index, v);
      let idx = index;
      for (let lvl = 0; lvl < depth; lvl++) {
        const parent = Math.floor(idx / 2);
        const h = H(get(lvl, parent * 2), get(lvl, parent * 2 + 1));
        if (h === zeros[lvl + 1]) nodes[lvl + 1].delete(parent); else nodes[lvl + 1].set(parent, h);
        idx = parent;
      }
    },
    leafAt(index) { checkIndex(index); return get(0, index); },
    root() { return get(depth, 0); },
    path(index) {
      checkIndex(index);
      const pathElements = [], pathIndices = [];
      let idx = index;
      for (let lvl = 0; lvl < depth; lvl++) { const bit = idx % 2; pathElements.push(get(lvl, bit ? idx - 1 : idx + 1)); pathIndices.push(bit); idx = Math.floor(idx / 2); }
      return { pathElements, pathIndices };
    },
    entries() { return [...nodes[0].entries()].sort((a, b) => a[0] - b[0]); },
  };
}
