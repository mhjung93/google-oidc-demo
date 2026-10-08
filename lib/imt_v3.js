// 샤드 포레스트 — 폐기 트리 이중 구조. v3.
//
// 설계: docs/superpowers/specs/2026-09-05-revocation-dual-tree-design.md
//
// v2(lib/imt_v2.js)와의 차이는 트리를 하나가 아니라 여럿으로 나눈다는 것뿐이다.
// 서브트리 하나하나는 v2 그대로이고(정석 IMT, append-only, 리프 Poseidon(3)), 여기서
// 더하는 것은 (a) 어느 서브트리에 넣을지 정하는 규칙과 (b) 서브트리 루트들을 묶는
// 상위 트리다.
//
//   상위 트리  keccak256   — 컨트랙트가 Solidity에서 검증한다. 회로에 안 들어간다.
//   하위 서브트리  Poseidon — 회로가 비멤버십을 증명한다.
//
// 왜 상위가 keccak인가. 상위 트리는 회로에 들어가지 않으므로 SNARK 친화적일 필요가
// 없다. EVM에는 keccak precompile이 있고 Poseidon은 없으므로, 밖으로 뺀 구간은
// keccak이 압도적으로 싸다.
//
// **샤드는 호출자가 지정할 수 없다.** insert/witness 모두 리프(+메타)에서 샤드를 스스로
// 계산한다. 설계 문서 4절 조건 4("IdP는 반드시 f(leaf) 샤드에만 삽입한다")를 규율이 아니라
// 구조로 강제하기 위한 것이다 — 엉뚱한 샤드에 넣으면 그 폐기는 증명에 보이지 않아
// 조용히 무효가 되는데, 그건 아무 데서도 드러나지 않는 종류의 실패다.
import { keccak256, concat, zeroPadValue, toBeHex } from 'ethers';
import { createIMTv2, buildIMTv2 } from './imt_v2.js';

export { leafValue, TAG_SESSION, TAG_ACCOUNT } from './imt.js';

// ============================================================================
// 층별 파라미터 — circuits/pi_pk_i_v3.circom 과 반드시 일치해야 한다
// ============================================================================

// 세션 층. 샤드 = (max_height mod SESSION_RING) * 2^SESSION_VALUE_BITS + 리프 하위 비트.
//
// 만료 축을 쓸 수 있는 이유: 세션 리프의 만료가 곧 max_height이고, 그건 이미 public
// signal이라 증명자가 자기 샤드를 안다(설계 문서 3.2절).
//
// 값 축이 왜 필요한가: max_height만 쓰면 칸을 512개 잡아도 실효는 332칸이다.
// assertMaxHeightWithinBound가 max_height <= 현재 + 300 + 32를 강제하므로 어느 시점에나
// 살아있는 max_height 값이 332개뿐이기 때문이다. 값 축 3비트를 곱해 실효 2,656칸으로 늘린다.
export const SESSION_RING = 512n;
export const SESSION_VALUE_BITS = 3;
export const SESSION_SHARD_COUNT = Number(SESSION_RING) * (1 << SESSION_VALUE_BITS); // 4096
export const SESSION_SUBTREE_DEPTH = 8;

// 계정 층. 샤드 = 리프 하위 8비트.
//
// 만료로 나눌 수 없다 — 계정 폐기의 만료는 "접수 시점 + 332"인데 증명자는 자기 계정이
// 언제 폐기됐는지(혹은 폐기됐는지 자체를) 모른다. 모르는 것이 이 층의 요점이다.
//
// 칸을 256개로 작게 잡은 이유는 성능이 아니라 **프라이버시**다. acct_shard는 public
// signal이고 auid는 rid와 무관하므로, 같은 사용자의 서로 다른 RP 지갑이 같은 값을
// 온체인에 공개한다. 칸이 많을수록 그 신호가 강해진다(설계 문서 5절). 계정 폐기는
// 드물어서 칸이 적어도 무효화 빈도가 충분히 낮다 — 두 목표가 같은 방향이다.
// 2026-09-07: 256 -> 4,096. 근거는 scripts/exp_account_shard_count.mjs 실측이다 —
// 1억 DAU·폐기율 0.1%에서 256이면 **모든 세션이 반드시 무효화**되고 평균 18회 재증명하는데
// (트랜잭션당 캐시 미스 41.9%), 4,096이면 1.1회 / 3.3%가 된다. 대가는 상위 트리가 깊어지는
// execute() +1.37%(실측 단계당 1,141 gas)뿐이다. 지갑 응답은 형제 경로 검증으로 바꿔서
// 샤드 수와 무관하게 상수가 됐다.
export const ACCOUNT_SHARD_BITS = 12;
export const ACCOUNT_SHARD_COUNT = 1 << ACCOUNT_SHARD_BITS; // 4096
export const ACCOUNT_SUBTREE_DEPTH = 10;

/**
 * 세션 리프의 샤드. maxHeight는 그 크레덴셜의 max_height다.
 *
 * 회로는 값 축(하위 3비트)만 고정하고, 만료 축은 컨트랙트가 max_height % 512로 직접
 * 계산한다. 둘 다 있어야 샤드가 확정된다(설계 문서 4절 조건 2·3).
 */
export function sessionShardOf(leaf, maxHeight) {
  const ring = BigInt(maxHeight) % SESSION_RING;
  const low = BigInt(leaf) & ((1n << BigInt(SESSION_VALUE_BITS)) - 1n);
  return Number(ring * (1n << BigInt(SESSION_VALUE_BITS)) + low);
}

/** 세션 리프의 값 축(회로가 sess_shard_low로 받는 값). */
export function sessionShardLowOf(leaf) {
  return Number(BigInt(leaf) & ((1n << BigInt(SESSION_VALUE_BITS)) - 1n));
}

/** 계정 리프의 샤드. 회로의 IMTNonMembershipV3(10, 8) shardIndex와 같은 식이어야 한다. */
export function accountShardOf(leaf) {
  return Number(BigInt(leaf) & (BigInt(ACCOUNT_SHARD_COUNT) - 1n));
}

// ============================================================================
// 상위 트리 (keccak256)
// ============================================================================
//
// 리프는 서브트리 루트(필드 원소)를 bytes32로 편 값이다. 노드는
// keccak256(left ‖ right)로, Solidity의 keccak256(abi.encodePacked(bytes32, bytes32))와
// 바이트 단위로 같다. 컨트랙트가 같은 계산을 해야 하므로 정렬(sorted pair) 같은 변형을
// 쓰지 않는다 — 인덱스로 좌우가 정해진다.

/** 필드 원소(10진 문자열/BigInt) -> bytes32 hex. wallet_agent.js의 변환과 동일하다. */
export function rootToBytes32(root) {
  return zeroPadValue(toBeHex(BigInt(root)), 32);
}

function hashPair(left, right) {
  return keccak256(concat([left, right]));
}

function assertPowerOfTwo(n, label) {
  if (!Number.isInteger(n) || n < 1 || (n & (n - 1)) !== 0) {
    throw new Error(`${label} must be a power of two, got ${n}`);
  }
}

/**
 * 서브트리 루트 배열에서 상위 root를 계산한다. 길이는 2의 거듭제곱이어야 한다.
 *
 * 지갑이 IdP에서 루트 목록만 받아 스스로 계산할 수 있도록 포레스트 인스턴스와 무관한
 * 순수 함수로 둔다.
 */
/**
 * 지금 이 세션 샤드를 통째로 비울 수 있는가.
 *
 * **RevocationRegistryV4._requireSessionShardExpired와 반드시 같은 식이어야 한다.**
 * IdP가 이 판정 없이 비우면(자기 만료 기록만 보고) 그 리셋 전이를 컨트랙트가
 * SessionShardNotExpired로 거부해 그 회차 전체가 막힌다 — 2026-09-07에 실제로 그랬다.
 *
 * 판정: d = (k - B) mod RING > span, k = shard / VALUE_SPAN.
 * 뜻은 "이 링 칸에 살아있을 수 있는 크레덴셜이 아예 없다"이다. 컨트랙트는 IdP의 만료
 * 기록을 볼 수 없으므로 링 위치만으로 판정할 수 있는 이 충분조건을 쓴다.
 *
 * 창은 만료 직후 (RING - span - 1)블록이고, 다음 세대가 발급되기 시작하는 지점에서 닫힌다.
 */
export function sessionShardResettable(shard, currentBlock, maxCredentialSpan) {
  const k = BigInt(Math.floor(shard / (1 << SESSION_VALUE_BITS)));
  const d = (k + SESSION_RING - (BigInt(currentBlock) % SESSION_RING)) % SESSION_RING;
  return d > BigInt(maxCredentialSpan);
}

export function computeTopRoot(subtreeRoots) {
  assertPowerOfTwo(subtreeRoots.length, 'subtreeRoots.length');
  let level = subtreeRoots.map(rootToBytes32);
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(hashPair(level[i], level[i + 1]));
    level = next;
  }
  return level[0];
}

/**
 * 샤드 s의 상위 경로(형제 해시들). 컨트랙트가 이걸로 top root를 재계산한다.
 *
 * pathIndices는 돌려주지 않는다 — 샤드 인덱스 s의 비트가 곧 방향이고, 컨트랙트는 자기가
 * 계산하거나 검증한 s를 써야 하기 때문이다(설계 문서 4절 조건 2). 호출자가 방향을
 * 따로 넘길 수 있게 두면 그 제약이 무의미해진다.
 */
export function computeTopPath(subtreeRoots, shard) {
  assertPowerOfTwo(subtreeRoots.length, 'subtreeRoots.length');
  if (!Number.isInteger(shard) || shard < 0 || shard >= subtreeRoots.length) {
    throw new Error(`shard ${shard} out of range [0, ${subtreeRoots.length})`);
  }
  const siblings = [];
  let level = subtreeRoots.map(rootToBytes32);
  let idx = shard;
  while (level.length > 1) {
    siblings.push(level[idx ^ 1]);
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(hashPair(level[i], level[i + 1]));
    level = next;
    idx >>= 1;
  }
  return siblings;
}

/**
 * 세션 층과 계정 층의 상위 root를 하나로 묶는다. 온체인 레지스트리는 root를 하나만
 * 들고 있으므로, 두 층을 2-리프 keccak 트리로 합쳐 그 값을 게시한다.
 *
 * 컨트랙트는 두 층의 상위 경로를 각각 올라간 뒤 이 함수와 같은 계산으로 합쳐
 * 레지스트리의 허용 root와 대조한다. 그래서 두 층이 **한 트랜잭션 안에서 원자적으로**
 * 같은 시점의 상태에 묶인다 — 한쪽만 낡은 상태로 통과하는 경로가 없다.
 */
export function combineTopRoots(sessionTopRoot, accountTopRoot) {
  return hashPair(sessionTopRoot, accountTopRoot);
}

/** 상위 경로를 재검증한다. 컨트랙트가 할 계산과 같다 — 테스트/지갑의 자체 확인용. */
export function verifyTopPath(subtreeRoot, shard, siblings, topRoot) {
  return computeTopFromPath(subtreeRoot, shard, siblings) === topRoot;
}

/**
 * 서브트리 root와 형제 경로만으로 상위 root를 **계산한다**(대조가 아니라 산출).
 *
 * 지갑이 이걸 쓴다. 예전에는 비어 있지 않은 모든 샤드의 root 목록을 받아 상위 트리를
 * 통째로 다시 쌓았는데(computeTopRoot), 그러면 응답이 샤드 수에 비례해 커진다 — 계정
 * 샤드를 256에서 4,096으로 늘리면 22 KB에서 233 KB가 된다(실측:
 * scripts/exp_account_shard_count.mjs).
 *
 * 그럴 필요가 없다. 지갑이 알아야 하는 것은 "내 서브트리 root가 이 상위 root 안에 있다"
 * 뿐이고, 그건 형제 경로로 접어 올리면 나온다 — **컨트랙트가 하는 계산과 정확히 같다**
 * (PPIDWalletV3._climbAcct). 다른 샤드의 내용은 지갑에게 필요가 없다.
 *
 * 서빙된 상위 root를 믿지 않으려고 boolean이 아니라 계산 결과를 돌려준다. 호출자는 이
 * 값으로 combined root를 만들어 온체인 레지스트리와 대조한다 — 거기가 진짜 기준점이다.
 */
export function computeTopFromPath(subtreeRoot, shard, siblings) {
  if (!Number.isInteger(shard) || shard < 0) {
    throw new Error(`shard ${shard} must be a non-negative integer`);
  }
  if (!Array.isArray(siblings)) throw new Error('siblings must be an array');
  if (shard >= 2 ** siblings.length) {
    // 경로가 짧으면 접어 올린 값이 실제 상위 root와 다르게 나오는데, 그 어긋남은 온체인
    // 대조에서야 드러난다. 여기서 형태로 먼저 막는다.
    throw new Error(`siblings length ${siblings.length} is too short for shard ${shard}`);
  }
  let node = rootToBytes32(subtreeRoot);
  let idx = shard;
  for (const sib of siblings) {
    node = (idx & 1) === 0 ? hashPair(node, sib) : hashPair(sib, node);
    idx >>= 1;
  }
  return node;
}

// ============================================================================
// 포레스트
// ============================================================================

// 빈 서브트리(anchor 리프 하나뿐)의 root. 깊이마다 상수이고, 한 번만 계산해 재사용한다.
// 쓰이지 않은 샤드의 상위 트리 리프가 이 값이다 — 0이 아니라는 점이 중요하다.
const emptyRootCache = new Map();
async function emptySubtreeRoot(depth) {
  if (!emptyRootCache.has(depth)) {
    const t = await createIMTv2(depth);
    emptyRootCache.set(depth, t.getRoot().toString());
  }
  return emptyRootCache.get(depth);
}

/**
 * 샤드 포레스트를 만든다.
 *
 * 서브트리는 **지연 생성**한다. 세션 층은 샤드가 4,096개인데 전부 미리 만들면
 * Poseidon 수만 번이 기동 시점에 들어간다(circomlibjs 기준 수십 초). 실제로 리프가
 * 들어간 샤드만 만들고, 나머지는 빈 서브트리 상수로 취급한다.
 *
 * 상위 트리는 keccak이라 싸므로 전부 물질화한다(4,096칸 = keccak 4,095회, 수 ms).
 *
 * @param shardOf (leaf, meta) => number — 리프에서 샤드를 정하는 규칙. 호출자가 샤드를
 *                직접 지정할 수 없게 하려고 규칙만 받는다.
 */
export async function createShardForest({ shardCount, depth, shardOf, leafBelongsToShard }) {
  assertPowerOfTwo(shardCount, 'shardCount');
  if (typeof shardOf !== 'function') throw new Error('shardOf must be a function');

  const emptyRoot = await emptySubtreeRoot(depth);
  const subtrees = new Map();          // shard -> IMT v2 인스턴스 (지연 생성)
  const rootStr = new Array(shardCount).fill(emptyRoot);
  let topLevels = null;                // keccak 레벨 캐시

  function rebuildTop() {
    const lv = [rootStr.map(rootToBytes32)];
    while (lv[lv.length - 1].length > 1) {
      const prev = lv[lv.length - 1];
      const next = [];
      for (let i = 0; i < prev.length; i += 2) next.push(hashPair(prev[i], prev[i + 1]));
      lv.push(next);
    }
    topLevels = lv;
  }

  function ensureTop() {
    if (!topLevels) rebuildTop();
  }

  // 샤드 하나가 바뀌었을 때 그 경로만 다시 계산한다 — keccak log2(shardCount)회.
  //
  // **상위 트리가 아직 없으면 여기서 만들지 않는다.** 예전에는 ensureTop()을 불러 통째로
  // 쌓았는데(4,095 keccak, 약 80 ms), 지갑은 그 트리를 쓰지 않는다 — 자기 형제 경로를
  // computeTopFromPath로 접을 뿐이다(0.17 ms). 그런데 갱신마다 포레스트를 새로 만드니
  // 매번 그 80 ms를 냈다. 계정 샤드가 256 -> 4,096이 되면서 16배로 커졌다.
  //
  // 호출자마다 다른 함수를 부르게 하는 대신 **필요할 때까지 미룬다.** 모든 호출부가
  // updateTop 직전에 rootStr[shard]를 갱신하므로, 나중에 ensureTop()이 rootStr에서
  // 통째로 쌓으면 결과가 같다. 실제로 상위 트리를 쓰는 쪽(IdP)은 getTopRoot()에서 한 번
  // 쌓고 그 뒤로는 여기 증분 경로를 타므로 손해가 없다.
  function updateTop(shard) {
    if (!topLevels) return;
    topLevels[0][shard] = rootToBytes32(rootStr[shard]);
    let idx = shard;
    for (let k = 0; k + 1 < topLevels.length; k++) {
      const parent = idx >> 1;
      topLevels[k + 1][parent] = hashPair(topLevels[k][parent * 2], topLevels[k][parent * 2 + 1]);
      idx = parent;
    }
  }

  async function ensureSubtree(shard) {
    if (!subtrees.has(shard)) subtrees.set(shard, await createIMTv2(depth));
    return subtrees.get(shard);
  }

  function checkShard(shard) {
    if (!Number.isInteger(shard) || shard < 0 || shard >= shardCount) {
      throw new Error(`shardOf returned ${shard}, outside [0, ${shardCount})`);
    }
    return shard;
  }

  return {
    shardCount,
    depth,
    emptyRoot,

    /** 이 리프가 속하는 샤드. 라우팅 규칙을 밖에서도 확인할 수 있게 노출한다. */
    shardFor(leaf, meta) {
      return checkShard(shardOf(leaf, meta));
    },

    /**
     * 리프를 넣는다. 샤드는 규칙이 정하며 호출자가 지정할 수 없다(설계 문서 조건 4).
     * 이미 있으면 false, 새로 넣었으면 true.
     */
    async insert(leaf, meta) {
      const shard = checkShard(shardOf(leaf, meta));
      const tree = await ensureSubtree(shard);
      const added = await tree.insert(BigInt(leaf));
      if (added) {
        rootStr[shard] = tree.getRoot().toString();
        updateTop(shard);
      }
      return added;
    },

    /**
     * insert()와 같지만 **전이 증명용 기록**을 함께 돌려준다(설계 문서 13.2절).
     * 이미 있으면 null.
     *
     * 반환: { shard, transcript } — transcript는 lib/imt_v2.js의 insertWithTranscript()
     * 형식 그대로다. 같은 샤드에 연달아 넣으면 기록이 root로 이어지므로, 그대로 모아
     * lib/transition_proof.js에 넘기면 증명 하나가 된다.
     */
    async insertWithTranscript(leaf, meta) {
      const shard = checkShard(shardOf(leaf, meta));
      const tree = await ensureSubtree(shard);
      const transcript = await tree.insertWithTranscript(BigInt(leaf));
      if (transcript === null) return null;
      rootStr[shard] = tree.getRoot().toString();
      updateTop(shard);
      return { shard, transcript };
    },

    /**
     * 상위 트리에서 이 샤드까지의 형제 경로. 컨트랙트가 접어 올리는 데 쓴다.
     *
     * getTopPath와 **같은 값**이라 그쪽에 위임한다. 원래는 computeTopPath(rootStr, shard)로
     * 따로 계산했는데, 그건 매번 상위 트리를 통째로 접어 O(shardCount)다. IdP가 전이
     * 서술자마다 부르므로 그대로 두면 계정 샤드 4,096에서 호출당 4,095 keccak이 된다.
     * 캐시된 레벨을 쓰면 O(log shardCount)다.
     */
    topPathFor(shard) {
      return this.getTopPath(shard);
    },

    /**
     * 서브트리를 통째로 비운다. 세션 층에서 만료된 샤드를 회수하는 경로다 —
     * 샤드 인덱스의 만료 축이 곧 그 안에 든 리프들의 만료이므로, 그 블록이 지나면
     * 샤드 전체가 죽은 것이라 재기준화 없이 그냥 버리면 된다(설계 문서 3.2절).
     */
    resetShard(shard) {
      checkShard(shard);
      if (!subtrees.has(shard) && rootStr[shard] === emptyRoot) return false;
      subtrees.delete(shard);
      rootStr[shard] = emptyRoot;
      updateTop(shard);
      return true;
    },

    /**
     * 지갑이 받은 리프 배열로 샤드 하나를 재구성한다. 물리 순서를 그대로 넣어야 한다.
     *
     * 값이 정말 그 샤드에 속하는지 검사한다. lib/wallet_revocation_v3.js가 "받은 것을
     * 스스로 재구성해 대조한다"는 원칙으로 쓰였는데 이 축만 비어 있었다 — IdP 라우팅
     * 버그(설계 문서 조건 4)를 지갑이 잡아줄 수 있는 유일한 지점이다.
     *
     * 세션 층은 만료 축을 리프만으로 알 수 없으므로 **값 축만** 검사한다. 그것만으로도
     * "다른 값 버킷의 리프가 섞여 들어오는" 경우는 걸린다.
     */
    async loadShard(shard, values) {
      checkShard(shard);
      if (typeof leafBelongsToShard === 'function') {
        for (const v of values) {
          if (!leafBelongsToShard(BigInt(v), shard)) {
            throw new Error(`leaf ${v} does not belong to shard ${shard}`);
          }
        }
      }
      const tree = await buildIMTv2(depth, values.map((v) => BigInt(v)));
      subtrees.set(shard, tree);
      rootStr[shard] = tree.getRoot().toString();
      updateTop(shard);
      return rootStr[shard];
    },

    /** 샤드의 서브트리 root(10진 문자열). 비어 있으면 빈 서브트리 상수. */
    getSubtreeRoot(shard) {
      checkShard(shard);
      return rootStr[shard];
    },

    /** 서브트리 루트 전체 목록. 지갑이 상위 경로를 스스로 만들 때 받아가는 값이다. */
    getSubtreeRoots() {
      return rootStr.slice();
    },

    /** 상위 root (bytes32). 온체인에 게시되는 값이다. */
    getTopRoot() {
      ensureTop();
      return topLevels[topLevels.length - 1][0];
    },

    /** 샤드 s의 상위 경로(형제 해시들). */
    getTopPath(shard) {
      checkShard(shard);
      ensureTop();
      const siblings = [];
      let idx = shard;
      for (let k = 0; k + 1 < topLevels.length; k++) {
        siblings.push(topLevels[k][idx ^ 1]);
        idx >>= 1;
      }
      return siblings;
    },

    /**
     * 비멤버십 witness. 샤드는 규칙이 정한다 — 호출자가 다른 샤드를 골라
     * 빈 서브트리의 witness를 받아갈 수 없다.
     */
    async getNonMembershipWitness(leaf, meta) {
      const shard = checkShard(shardOf(leaf, meta));
      const tree = await ensureSubtree(shard);
      const w = await tree.getNonMembershipWitness(BigInt(leaf));
      return { ...w, shard };
    },

    /** 값이 폐기 집합에 있는지. 자기 샤드만 보면 된다. */
    async has(leaf, meta) {
      const shard = checkShard(shardOf(leaf, meta));
      if (!subtrees.has(shard)) return false;
      return subtrees.get(shard).has(BigInt(leaf));
    },

    /** 샤드의 물리 순서 리프 값 배열(anchor 제외). 직렬화/서빙용. */
    getShardLeafValues(shard) {
      checkShard(shard);
      if (!subtrees.has(shard)) return [];
      return subtrees.get(shard).getLeaves().slice(1).map((l) => l.value.toString());
    },

    /** 비어 있지 않은 샤드 번호들. */
    activeShards() {
      return [...subtrees.keys()].filter((s) => rootStr[s] !== emptyRoot).sort((a, b) => a - b);
    },

    /** 사용률. 서브트리 단위로 본다 — 한 샤드만 먼저 차는 상황을 봐야 하기 때문이다. */
    usage() {
      const capacity = 2 ** depth;
      let maxUsed = 0;
      let total = 0;
      for (const [, t] of subtrees) {
        const u = t.size();
        total += u - 1; // anchor 제외
        if (u > maxUsed) maxUsed = u;
      }
      return {
        shardCount,
        activeShards: subtrees.size,
        totalLeaves: total,
        maxShardUsed: maxUsed,
        perShardCapacity: capacity,
        maxShardRatio: maxUsed / capacity,
      };
    },
  };
}

/** 세션 층 포레스트. meta로 { maxHeight }를 받는다. */
export function createSessionForest() {
  return createShardForest({
    shardCount: SESSION_SHARD_COUNT,
    depth: SESSION_SUBTREE_DEPTH,
    shardOf: (leaf, meta) => {
      if (meta?.maxHeight === undefined || meta?.maxHeight === null) {
        throw new Error('session shard requires meta.maxHeight');
      }
      return sessionShardOf(leaf, meta.maxHeight);
    },
    // 만료 축은 리프만으로 알 수 없으므로 값 축(하위 3비트)만 본다.
    leafBelongsToShard: (leaf, shard) =>
      sessionShardLowOf(leaf) === shard % (1 << SESSION_VALUE_BITS),
  });
}

/** 계정 층 포레스트. meta가 필요 없다. */
export function createAccountForest() {
  return createShardForest({
    shardCount: ACCOUNT_SHARD_COUNT,
    depth: ACCOUNT_SUBTREE_DEPTH,
    shardOf: (leaf) => accountShardOf(leaf),
    leafBelongsToShard: (leaf, shard) => accountShardOf(leaf) === shard,
  });
}
