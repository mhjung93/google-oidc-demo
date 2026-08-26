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

  // 0은 항상 존재하는 anchor 리프다. 모든 리프 값은 Poseidon 출력을 마스킹한
  // 것이라 0이 될 확률은 무시할 수 있으므로, 0을 "모든 값보다 작은 하한"으로
  // 두면 어떤 target이든 자기보다 작은 리프를 항상 찾을 수 있다.
  //
  // anchor 없이 빈 트리를 특수 분기로 처리하면 두 가지가 깨진다:
  //  (1) 회로는 Poseidon(lowValue, lowNextValue) = Poseidon(0,0) 에서 경로를
  //      시작하는데 라이브러리가 리터럴 0에서 시작하면 root가 어긋난다.
  //  (2) 값이 하나라도 들어간 뒤에는 최솟값보다 작은 target의 low 리프를
  //      찾을 수 없게 된다.
  const values = [0n];

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
    // values 는 anchor 때문에 항상 최소 1개다.
    const levels = [values.map((_, i) => leafHash(i))];
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
      if (v === 0n) throw new Error('0 is the anchor leaf and cannot be revoked');
      // 회로가 lowValue/lowNextValue 를 Num2Bits(252) 로 range-check 하므로,
      // 마스킹되지 않은 값이 트리에 들어가면 그 리프 주변의 증명이 불가능해진다.
      // leafValue() 를 거치지 않은 원시 Poseidon 다이제스트를 막는다.
      if (v < 0n || v >= (1n << 252n)) {
        throw new Error(`${v} is outside [0, 2^252); pass leafValue() output, not a raw digest`);
      }
      if (values.some((x) => x === v)) return; // 이미 폐기됨
      values.push(v);
      values.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    },

    getRoot() {
      const levels = build();
      return levels[levels.length - 1][0];
    },

    async getNonMembershipWitness(target) {
      // 회로는 target을 내부에서 하위 252비트로 정규화하므로, low 리프를 고를 때도
      // 같은 정규화를 거친 값으로 비교해야 한다. leafValue() 출력은 이미 마스킹돼
      // 있어 이 연산이 무해하고(idempotent), 원시 Poseidon 다이제스트를 그대로
      // 넘긴 경우에도 회로와 같은 값을 보게 된다.
      const t = BigInt(target) & MASK_252;
      if (values.some((x) => x === t)) {
        throw new Error(`${t} is a member of the revocation set`);
      }
      const levels = build();
      const root = levels[levels.length - 1][0];

      // t 보다 작은 값 중 가장 큰 것을 찾는다. anchor(0) 가 항상 있으므로
      // t > 0 인 한 반드시 하나는 찾는다.
      let lowIdx = -1;
      for (let i = 0; i < values.length; i++) {
        if (values[i] < t) lowIdx = i;
        else break;
      }
      if (lowIdx === -1) {
        throw new Error(`target ${t} must be greater than 0 (the anchor leaf)`);
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
