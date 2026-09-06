// 정석(proper) Indexed Merkle Tree — 폐기 집합의 비멤버십 증명용. v2.
//
// lib/imt.js(v1)와의 차이는 "다음 리프"를 어디서 얻느냐 하나다.
//
//   v1: 정렬된 배열을 그대로 리프 배열로 쓰고 next를 **물리적 인접성**에서
//       유도한다(nextOf(i) = values[i+1]). 그래서 중간에 값이 하나 들어가면
//       그 뒤 모든 리프의 인덱스가 밀려 트리 전체를 다시 쌓아야 한다 — O(n).
//   v2: next를 리프에 **명시적으로 저장**하고(nextIndex/nextValue) 물리 위치는
//       삽입 순서대로 append한다. 정렬 순서는 연결 리스트로만 표현되므로
//       삽입 한 번이 바꾸는 리프는 둘(low 리프와 새 리프)뿐이다 — O(log n).
//
//   leaf[i] = Poseidon(value_i, nextIndex_i, nextValue_i)
//
// circuits/lib/imt_nonmembership_v2.circom 과 리프 해시 형식이 일치해야 한다.
//
// 이 모듈은 v1을 대체하지 않는다. 리프 해시가 달라 root가 전부 바뀌므로,
// 실제 전환은 zkey 재생성/재배포와 함께 별도로 진행한다.
//
// 설계 근거: docs/superpowers/specs/2026-08-30-proper-imt-design.md
import { buildPoseidon } from 'circomlibjs';

// 리프 값 규약(도메인 태그 + 252비트 마스킹)은 v1과 **완전히 동일**해야 하므로
// 재정의하지 않고 그대로 재수출한다.
export { leafValue, TAG_SESSION, TAG_ACCOUNT } from './imt.js';

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

// 회로의 LessThan(252)이 입력이 [0, 2^252)임을 전제한다. lib/imt.js와 동일.
const MASK_252 = (1n << 252n) - 1n;
const TWO_252 = 1n << 252n;

/**
 * 빈 트리를 만든다. 리프 슬롯은 2^depth개인 **고정 용량** 트리다.
 *
 * 물리 인덱스 0은 anchor 리프 (0, 0, 0)이고 절대 제거·재사용되지 않는다.
 * anchor가 있어야 최솟값보다 작은 target도 low 리프를 찾을 수 있다.
 */
export async function createIMTv2(depth) {
  if (!Number.isInteger(depth) || depth < 1 || depth > 32) {
    throw new Error(`depth must be an integer in [1, 32], got ${depth}`);
  }
  const poseidon = await getPoseidon();
  const F = poseidon.F;
  const H2 = (a, b) => F.toObject(poseidon([a, b]));
  const H3 = (a, b, c) => F.toObject(poseidon([a, b, c]));

  const capacity = 2 ** depth;

  // 레벨별 "빈 서브트리" 해시. 이게 없으면 고정 용량이 성립하지 않는다 —
  // 깊이 20이면 매번 1,048,576개 슬롯을 해싱해야 하기 때문이다.
  //
  // zeros[0](빈 리프)을 리터럴 0으로 둔 것이 중요하다. 빈 슬롯을 (0, 0, 0)으로
  // 두면 Poseidon(0,0,0)이 되어 anchor와 **모양이 같아지고**, 그 슬롯을 low
  // 리프로 제시하면 lowValue=0 / lowNextValue=0(sentinel)이라 t > 0인 모든
  // 값에 대해 거짓 비멤버십이 통과한다(설계 문서 3.2절). 리터럴 0은 Poseidon
  // 출력이 될 확률이 무시할 만하므로 아무도 preimage를 제시할 수 없다.
  const zeros = [0n];
  for (let k = 1; k <= depth; k++) zeros.push(H2(zeros[k - 1], zeros[k - 1]));

  // 물리 순서(삽입 순서) 리프 배열. leaves[0]은 anchor.
  const leaves = [{ value: 0n, nextIndex: 0, nextValue: 0n }];

  // 값 오름차순으로 정렬된 **물리 인덱스** 목록. predecessor 탐색 전용이며
  // 트리 밖 자료구조라 해시 계산이 전혀 없다(설계 문서 6.2절).
  const order = [0];

  // 레벨 해시 캐시. levels[0]은 리프 해시, levels[depth]는 root 하나.
  // levels[k][i]는 i < levels[k].length 인 구간만 유효하고, 그 밖은 zeros[k]다
  // (리프를 0번부터 빈틈없이 append하므로 뒤쪽은 전부 빈 서브트리).
  //
  // null이면 아직 물질화되지 않은 상태다. 빈 트리에 대량 삽입을 할 때
  // 삽입마다 경로를 갱신하는 O(n log n) 대신 마지막에 한 번 O(n)으로 쌓기
  // 위한 것이다. getRoot()/witness 요청 시 필요하면 자동으로 쌓는다.
  let levels = null;

  function leafHash(i) {
    const leaf = leaves[i];
    return H3(leaf.value, BigInt(leaf.nextIndex), leaf.nextValue);
  }

  function nodeAt(level, idx) {
    const arr = levels[level];
    return idx < arr.length ? arr[idx] : zeros[level];
  }

  function writeNode(level, idx, val) {
    const arr = levels[level];
    if (idx < arr.length) arr[idx] = val;
    else if (idx === arr.length) arr.push(val);
    else throw new Error(`internal: non-contiguous write at level ${level} index ${idx}`);
  }

  // 전체 재구성 — O(n) 해시. 리프가 없는 구간은 zeros[k]로 접는다.
  function rebuildLevels() {
    const lv = [leaves.map((_, i) => leafHash(i))];
    for (let k = 0; k < depth; k++) {
      const prev = lv[k];
      const next = [];
      for (let i = 0; i < prev.length; i += 2) {
        const l = prev[i];
        const r = i + 1 < prev.length ? prev[i + 1] : zeros[k];
        next.push(H2(l, r));
      }
      lv.push(next);
    }
    levels = lv;
  }

  function ensureLevels() {
    if (!levels) rebuildLevels();
  }

  // 리프 하나가 바뀌었을 때 그 경로만 다시 계산한다 — O(depth) 해시.
  function updateLeaf(i) {
    writeNode(0, i, leafHash(i));
    let idx = i;
    for (let k = 0; k < depth; k++) {
      const parent = Math.floor(idx / 2);
      const l = nodeAt(k, parent * 2);
      const r = nodeAt(k, parent * 2 + 1);
      writeNode(k + 1, parent, H2(l, r));
      idx = parent;
    }
  }

  function pathFor(leafIndex) {
    const pathElements = [];
    const pathIndices = [];
    let idx = leafIndex;
    for (let k = 0; k < depth; k++) {
      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;
      pathElements.push(nodeAt(k, siblingIdx));
      pathIndices.push(isRight ? 1 : 0);
      idx = Math.floor(idx / 2);
    }
    return { pathElements, pathIndices };
  }

  // order 안에서 값이 v 이상인 첫 위치 (이진 탐색).
  function lowerBound(v) {
    let lo = 0;
    let hi = order.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (leaves[order[mid]].value < v) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  function findExact(v) {
    const p = lowerBound(v);
    return p < order.length && leaves[order[p]].value === v ? order[p] : -1;
  }

  function validateValue(v) {
    if (v === 0n) throw new Error('0 is the anchor leaf and cannot be revoked');
    // 회로가 lowValue/lowNextValue를 Num2Bits(252)로 range-check하므로,
    // 마스킹되지 않은 값이 트리에 들어가면 그 리프 주변의 증명이 불가능해진다.
    if (v < 0n || v >= TWO_252) {
      throw new Error(`${v} is outside [0, 2^252); pass leafValue() output, not a raw digest`);
    }
  }

  const tree = {
    depth,
    capacity,

    /** 사용 중인 리프 슬롯 수 (anchor 포함). */
    size() {
      return leaves.length;
    },

    /** 슬롯 사용률. 소진이 임박하면 재기준화가 필요하다(설계 문서 3.3절). */
    usage() {
      return { used: leaves.length, capacity, ratio: leaves.length / capacity };
    },

    /**
     * 값 v를 폐기 집합에 넣는다. O(log n).
     *
     * 1) v보다 작은 값 중 가장 큰 것을 담은 리프 L(인덱스 i)을 찾는다
     * 2) 다음 빈 인덱스 n에 새 리프 (v, L.nextIndex, L.nextValue)를 쓴다
     * 3) L을 (L.value, n, v)로 갱신한다
     *
     * 바뀌는 리프는 i와 n 둘뿐이므로 경로도 둘만 다시 계산한다.
     * 이미 있는 값이면 false, 새로 넣었으면 true를 반환한다.
     */
    async insert(value) {
      const v = BigInt(value);
      validateValue(v);
      if (findExact(v) !== -1) return false; // 이미 폐기됨

      if (leaves.length >= capacity) {
        // 조용히 잘못된 root를 만드는 것보다 거부가 낫다.
        throw new Error(
          `IMT capacity exhausted: all ${capacity} leaf slots of depth ${depth} are used; ` +
            'rebaseline() with the live value set is required before inserting again',
        );
      }

      const lowPos = lowerBound(v) - 1; // v보다 작은 값 중 마지막. anchor(0)가 있어 항상 >= 0
      const lowIdx = order[lowPos];
      const low = leaves[lowIdx];

      const newIdx = leaves.length;
      leaves.push({ value: v, nextIndex: low.nextIndex, nextValue: low.nextValue });
      low.nextIndex = newIdx;
      low.nextValue = v;
      order.splice(lowPos + 1, 0, newIdx);

      if (levels) {
        // 새 리프를 먼저 쓴다. 그래야 low 리프 경로를 갱신할 때 레벨 배열이
        // 이미 확장돼 있어 공유 조상이 새 값으로 다시 계산된다.
        updateLeaf(newIdx);
        updateLeaf(lowIdx);
      }
      return true;
    },

    /**
     * insert()와 같은 삽입을 하되, **회로가 검증할 수 있는 전이 기록**을 함께 돌려준다
     * (설계 문서 13.2절, circuits/lib/imt_insert_batch.circom).
     *
     * 회로가 요구하는 세 상태의 증거를 모아야 한다:
     *   old  — low 리프가 들어 있는 현재 트리
     *   mid  — low 리프만 갱신한 트리. 여기서 새 슬롯이 비어 있음을 보인다.
     *   new  — 새 리프까지 쓴 트리
     *
     * mid의 경로는 증분 갱신 기계로는 얻기 어렵다(insert()는 성능을 위해 새 리프를 **먼저**
     * 쓴다 — 그 순서가 아니면 공유 조상이 낡은 값으로 남기 때문이다). 그래서 여기서는
     * 단계마다 레벨을 통째로 다시 쌓는다. O(n) 해시를 세 번 하는 셈인데, 서브트리가
     * 256~1,024리프라 무시할 만하고 이 경로는 게시 회차당 한 번만 돈다(로그인 경로가 아니다).
     *
     * 이미 있는 값이면 null을 돌려준다.
     */
    async insertWithTranscript(value) {
      const v = BigInt(value);
      validateValue(v);
      if (findExact(v) !== -1) return null;
      if (leaves.length >= capacity) {
        throw new Error(
          `IMT capacity exhausted: all ${capacity} leaf slots of depth ${depth} are used; ` +
            'rebaseline() with the live value set is required before inserting again',
        );
      }

      ensureLevels();
      const oldRoot = levels[depth][0];

      const lowPos = lowerBound(v) - 1;
      const lowIdx = order[lowPos];
      const low = leaves[lowIdx];
      const lowValue = low.value;
      const lowNextIndex = low.nextIndex;
      const lowNextValue = low.nextValue;
      const lowPath = pathFor(lowIdx);
      const newIdx = leaves.length;

      // mid — low 리프만 갱신한다. 새 슬롯은 아직 배열 밖이라 nodeAt()이 zeros를 준다.
      low.nextIndex = newIdx;
      low.nextValue = v;
      levels = null;
      ensureLevels();
      const newSlotPath = pathFor(newIdx);

      // new — 새 리프를 쓴다.
      leaves.push({ value: v, nextIndex: lowNextIndex, nextValue: lowNextValue });
      order.splice(lowPos + 1, 0, newIdx);
      levels = null;
      ensureLevels();
      const newRoot = levels[depth][0];

      return {
        oldRoot: oldRoot.toString(),
        newRoot: newRoot.toString(),
        newValue: v.toString(),
        lowValue: lowValue.toString(),
        lowNextIndex: String(lowNextIndex),
        lowNextValue: lowNextValue.toString(),
        lowPathIndices: lowPath.pathIndices.map(String),
        lowSiblings: lowPath.pathElements.map(String),
        newIndex: String(newIdx),
        newPathIndices: newSlotPath.pathIndices.map(String),
        newSiblings: newSlotPath.pathElements.map(String),
      };
    },

    // remove()는 의도적으로 없다.
    //
    // 언링크(앞 리프의 next가 건너뛰게 고치는 것)는 건전하지 않다. 언링크된
    // 리프는 여전히 Merkle 멤버라 low 리프로 제시할 수 있고, 그 낡은 구간
    // (v, w) 안에 나중에 삽입된 값에 대해 거짓 비멤버십 증명이 만들어진다.
    // 리프를 0으로 지우는 건 더 나쁘다 — anchor와 모양이 같아져 모든 t > 0을
    // 통과시킨다. 회수는 rebaseline()으로만 한다(설계 문서 3.2/3.3절).

    getRoot() {
      ensureLevels();
      return levels[depth][0];
    },

    /**
     * 살아있는 값만으로 트리를 새로 쌓아 반환한다. 이 트리는 그대로 둔다.
     *
     * 값을 오름차순으로 정렬해 넣으므로 결과 root는 입력 순서와 무관한
     * **살아있는 집합의 순수 함수**다. IdP와 지갑이 같은 집합에서 독립적으로
     * 같은 트리를 얻을 수 있어야 하기 때문이다.
     */
    async rebaseline(liveValues) {
      const uniq = [...new Set([...liveValues].map((x) => BigInt(x)))];
      uniq.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      return buildIMTv2(depth, uniq);
    },

    /**
     * target이 폐기 집합에 없음을 보이는 witness.
     * lowNextIndex가 v1 대비 추가된 필드다.
     */
    async getNonMembershipWitness(target) {
      // 회로는 target을 내부에서 하위 252비트로 정규화하므로, low 리프를 고를
      // 때도 같은 정규화를 거친 값으로 비교해야 한다.
      const t = BigInt(target) & MASK_252;
      if (findExact(t) !== -1) {
        throw new Error(`${t} is a member of the revocation set`);
      }
      const lowPos = lowerBound(t) - 1;
      if (lowPos < 0) {
        // t === 0 은 anchor 값과 같아 위에서 이미 걸리므로 도달 불가능하지만,
        // 불변식이 깨진 채로 잘못된 witness를 내보내지 않도록 남겨둔다.
        throw new Error(`target ${t} must be greater than 0 (the anchor leaf)`);
      }
      ensureLevels();
      const lowIdx = order[lowPos];
      const low = leaves[lowIdx];
      const { pathElements, pathIndices } = pathFor(lowIdx);
      return {
        lowValue: low.value.toString(),
        lowNextIndex: low.nextIndex.toString(),
        lowNextValue: low.nextValue.toString(),
        pathElements: pathElements.map(String),
        pathIndices: pathIndices.map(String),
        root: levels[depth][0].toString(),
      };
    },

    /** 값이 폐기 집합에 있는지. O(log n). */
    has(value) {
      const v = BigInt(value) & MASK_252;
      return findExact(v) !== -1;
    },

    /** 물리 순서 리프 배열의 복사본. 변경 로그/직렬화용. */
    getLeaves() {
      return leaves.map((l) => ({ ...l }));
    },

    /** 물리 인덱스 i의 리프 해시. 변경 로그 항목을 만들 때 쓴다. */
    getLeafHash(i) {
      if (!Number.isInteger(i) || i < 0 || i >= leaves.length) {
        throw new Error(`leaf index ${i} out of range [0, ${leaves.length})`);
      }
      return leafHash(i);
    },
  };

  return tree;
}

/**
 * 값 목록을 순서대로 삽입한 트리를 한 번에 쌓는다.
 *
 * 레벨 캐시를 마지막에 딱 한 번 만들므로 O(n) 해시다. 삽입마다 경로를
 * 갱신하는 O(n log n)보다 초기 구성에 유리하다. 연결 리스트 갱신 로직은
 * insert()와 완전히 동일하므로, 같은 순서로 넣으면 증분 삽입과 **같은 root**가
 * 나와야 한다(단위 테스트가 이걸 검증한다).
 *
 * 주의: 물리 배치가 삽입 순서에 따라 달라지므로 root는 순서에 의존한다.
 * 순서와 무관한 결정적 트리가 필요하면 rebaseline()을 쓴다.
 */
export async function buildIMTv2(depth, values) {
  const tree = await createIMTv2(depth);
  for (const v of values) await tree.insert(v);
  tree.getRoot(); // 레벨 캐시를 여기서 한 번에 만든다
  return tree;
}
