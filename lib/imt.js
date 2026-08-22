// Indexed Merkle Tree — 폐기 집합의 비멤버십 증명용.
//
// 리프는 값 오름차순으로 정렬돼 있고 각 리프가 (value, nextValue)를 담는다.
// nextValue == 0 은 "가장 큰 값"이라는 sentinel이다.
// circuits/lib/imt_nonmembership.circom 과 리프 해시 형식이 일치해야 한다.
import { buildPoseidon } from 'circomlibjs';

export const TAG_SESSION = 1n;
export const TAG_ACCOUNT = 2n;

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

// 리프 값은 하위 252비트로 정규화한다. 회로의 LessThan(252)이 입력이
// [0, 2^252) 임을 전제하는데 Poseidon 출력은 필드 전역에 분포하므로,
// 정규화하지 않으면 비교가 wrap-around로 뒤집힌다.
// circuits/lib/imt_nonmembership.circom 의 targetMasked 계산과 일치해야 한다.
const MASK_252 = (1n << 252n) - 1n;

export async function leafValue(tag, raw) {
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([tag, BigInt(raw)])) & MASK_252;
}

export async function createIMT(depth) {
  const poseidon = await getPoseidon();
  const F = poseidon.F;
  const H = (a, b) => F.toObject(poseidon([a, b]));

  // 정렬 상태를 유지하는 값 목록. 0은 sentinel 이므로 실제 값으로 쓰지 않는다.
  const values = [];

  function nextOf(i) {
    return i + 1 < values.length ? values[i + 1] : 0n;
  }

  // 리프 i의 해시
  function leafHash(i) {
    return H(values[i], nextOf(i));
  }

  // 전체 트리를 다시 쌓아 root와 각 리프의 경로를 만든다.
  // 폐기 집합은 작으므로(수천~수만) 매번 재구성해도 충분하다.
  function build() {
    let level = values.map((_, i) => leafHash(i));
    if (level.length === 0) level = [0n];
    const levels = [level];
    for (let d = 0; d < depth; d++) {
      const prev = levels[levels.length - 1];
      const next = [];
      for (let i = 0; i < prev.length; i += 2) {
        const l = prev[i];
        const r = i + 1 < prev.length ? prev[i + 1] : 0n;
        next.push(H(l, r));
      }
      levels.push(next.length ? next : [H(0n, 0n)]);
    }
    return levels;
  }

  function pathFor(levels, leafIndex) {
    const pathElements = [];
    const pathIndices = [];
    let idx = leafIndex;
    for (let d = 0; d < depth; d++) {
      const level = levels[d];
      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;
      pathElements.push(siblingIdx < level.length ? level[siblingIdx] : 0n);
      pathIndices.push(isRight ? 1 : 0);
      idx = Math.floor(idx / 2);
    }
    return { pathElements, pathIndices };
  }

  return {
    async insert(value) {
      const v = BigInt(value);
      if (v === 0n) throw new Error('0 is reserved as the sentinel and cannot be inserted');
      if (values.some((x) => x === v)) return; // 이미 폐기됨
      values.push(v);
      values.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    },

    getRoot() {
      const levels = build();
      return levels[levels.length - 1][0];
    },

    async getNonMembershipWitness(target) {
      const t = BigInt(target);
      if (values.some((x) => x === t)) {
        throw new Error(`${t} is a member of the revocation set`);
      }
      const levels = build();
      const root = levels[levels.length - 1][0];

      if (values.length === 0) {
        // 빈 트리: 리프가 (0, 0) 하나뿐이므로 어떤 target 이든 상한 검사가 면제된다.
        const { pathElements, pathIndices } = pathFor(levels, 0);
        return {
          lowValue: '0',
          lowNextValue: '0',
          pathElements: pathElements.map(String),
          pathIndices: pathIndices.map(String),
          root: root.toString(),
        };
      }

      // t 보다 작은 값 중 가장 큰 것을 찾는다.
      let lowIdx = -1;
      for (let i = 0; i < values.length; i++) {
        if (values[i] < t) lowIdx = i;
        else break;
      }
      if (lowIdx === -1) {
        throw new Error('target is smaller than every revoked value; insert a 0-anchor leaf first');
      }
      const { pathElements, pathIndices } = pathFor(levels, lowIdx);
      return {
        lowValue: values[lowIdx].toString(),
        lowNextValue: nextOf(lowIdx).toString(),
        pathElements: pathElements.map(String),
        pathIndices: pathIndices.map(String),
        root: root.toString(),
      };
    },
  };
}
