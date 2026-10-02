// lib/imt_v2.js 단위 테스트 — 외부 산출물 없이 단독 실행된다.
//   node tests/test_imt_v2_lib.js
//
// 핵심은 "증분 갱신이 전체 재구성과 같은 root를 낸다"는 것이다. v2의 위험은
// 전부 여기 몰려 있다 — 레벨 캐시를 부분만 고쳐 쓰기 때문이다.
import assert from 'node:assert/strict';
import { buildPoseidon } from 'circomlibjs';
import { createIMTv2, buildIMTv2, leafValue, TAG_SESSION, TAG_ACCOUNT } from '../lib/imt_v2.js';

const DEPTH = 20;

// 재현 가능한 의사난수 (mulberry32). 순서 셔플에 seed를 고정해 두면 실패를
// 다시 만들 수 있다.
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffled(arr, seed) {
  const out = [...arr];
  const rand = rng(seed);
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

// 라이브러리와 **독립적인** 참조 root 계산. 레벨 캐시도 증분 갱신도 쓰지 않고
// 재귀로 내려가며, 리프가 하나도 없는 서브트리는 zeros[level]로 접는다.
function makeRefRoot(poseidon, depth) {
  const F = poseidon.F;
  const H2 = (a, b) => F.toObject(poseidon([a, b]));
  const H3 = (a, b, c) => F.toObject(poseidon([a, b, c]));
  const zeros = [0n];
  for (let k = 1; k <= depth; k++) zeros.push(H2(zeros[k - 1], zeros[k - 1]));

  return function refRoot(leaves) {
    const n = leaves.length;
    function node(level, idx) {
      if (idx * 2 ** level >= n) return zeros[level]; // 통째로 빈 서브트리
      if (level === 0) {
        const l = leaves[idx];
        return H3(l.value, BigInt(l.nextIndex), l.nextValue);
      }
      return H2(node(level - 1, idx * 2), node(level - 1, idx * 2 + 1));
    }
    return node(depth, 0);
  };
}

// anchor에서 next를 따라가면 값이 엄격히 증가하며 모든 리프를 정확히 한 번
// 방문해야 한다. 5절의 건전성이 통째로 이 불변식에 기대고 있다.
function assertSortedLinkedList(leaves, label) {
  const seen = new Set();
  let idx = 0;
  let prev = -1n;
  let count = 0;
  for (;;) {
    assert.ok(!seen.has(idx), `${label}: linked list has a cycle at leaf ${idx}`);
    seen.add(idx);
    const leaf = leaves[idx];
    assert.ok(leaf.value > prev, `${label}: values must strictly increase along the list`);
    prev = leaf.value;
    count += 1;
    if (leaf.nextValue === 0n) break; // sentinel: 가장 큰 값
    assert.equal(
      leaves[leaf.nextIndex].value,
      leaf.nextValue,
      `${label}: nextValue must equal the value of the leaf at nextIndex`,
    );
    idx = leaf.nextIndex;
  }
  assert.equal(count, leaves.length, `${label}: every leaf must appear on the list exactly once`);
}

async function main() {
  const poseidon = await buildPoseidon();
  const refRoot = makeRefRoot(poseidon, DEPTH);

  // ---------------------------------------------------------------------
  // 1) 증분 갱신의 정확성 — 이 테스트가 v2의 존재 이유다.
  //    레벨 캐시를 먼저 물질화한 뒤 한 건씩 넣어 경로만 갱신한 트리와,
  //    같은 순서로 넣고 마지막에 한 번 전체를 쌓은 트리의 root가 같아야 한다.
  // ---------------------------------------------------------------------
  {
    const values = [];
    for (let i = 1; i <= 200; i++) values.push(BigInt(i) * 1_000_003n);

    const incremental = await createIMTv2(DEPTH);
    incremental.getRoot(); // 캐시를 미리 물질화해 증분 경로를 강제한다
    for (const v of values) await incremental.insert(v);

    const scratch = await buildIMTv2(DEPTH, values);

    assert.equal(
      incremental.getRoot().toString(),
      scratch.getRoot().toString(),
      'incremental path updates must match a from-scratch rebuild',
    );
    console.log('OK: incremental insert root == from-scratch rebuild root (200 leaves)');

    assert.equal(
      incremental.getRoot().toString(),
      refRoot(incremental.getLeaves()).toString(),
      'root must match an independent reference implementation',
    );
    console.log('OK: root matches an independent recursive reference implementation');

    assertSortedLinkedList(incremental.getLeaves(), 'ascending insert');
  }

  // ---------------------------------------------------------------------
  // 2) 삽입 순서를 무작위로 섞어도 증분 갱신이 정확한가.
  //    이게 물리 순서와 정렬 순서의 분리를 실제로 때리는 케이스다 — low 리프가
  //    물리적으로 어디에 있든(마지막이 아니라 중간이든) 경로 갱신이 맞아야 한다.
  // ---------------------------------------------------------------------
  {
    const values = [];
    for (let i = 1; i <= 300; i++) values.push(BigInt(i) * 7_777_777n);
    const order = shuffled(values, 20260830);

    const incremental = await createIMTv2(DEPTH);
    incremental.getRoot();
    for (const v of order) await incremental.insert(v);

    const scratch = await buildIMTv2(DEPTH, order);
    assert.equal(
      incremental.getRoot().toString(),
      scratch.getRoot().toString(),
      'random-order incremental updates must match a from-scratch rebuild',
    );
    assert.equal(incremental.getRoot().toString(), refRoot(incremental.getLeaves()).toString());
    assertSortedLinkedList(incremental.getLeaves(), 'random insert');
    console.log('OK: random insertion order — incremental root == rebuild root == reference root');

    // 주의: append-only IMT에서 root는 삽입 **순서에 의존한다.** 같은 집합이라도
    // 물리 배치가 달라지기 때문이다. 이건 버그가 아니라 정석 IMT의 성질이다.
    // 순서와 무관한 결정적 트리가 필요하면 rebaseline()을 쓴다(테스트 7).
    const ascending = await buildIMTv2(DEPTH, values);
    assert.notEqual(
      ascending.getRoot().toString(),
      incremental.getRoot().toString(),
      'different insertion orders place leaves differently, so roots differ by design',
    );
    console.log('OK: root depends on insertion order (append-only physical layout, by design)');

    // 순서가 달라도 **비멤버십 의미**는 같아야 한다: 같은 집합이면 같은 값들이
    // 멤버이고 같은 값들이 witness를 얻는다.
    for (const v of [values[0], values[42], values[299]]) {
      assert.equal(ascending.has(v), true);
      assert.equal(incremental.has(v), true);
      await assert.rejects(() => ascending.getNonMembershipWitness(v), /is a member/);
      await assert.rejects(() => incremental.getNonMembershipWitness(v), /is a member/);
    }
    for (const v of [1n, 7_777_776n, 300n * 7_777_777n + 1n]) {
      assert.equal(ascending.has(v), false);
      assert.equal(incremental.has(v), false);
      const wa = await ascending.getNonMembershipWitness(v);
      const wi = await incremental.getNonMembershipWitness(v);
      // 같은 구간을 증언하지만 물리 위치·경로는 다르다
      assert.equal(wa.lowValue, wi.lowValue);
      assert.equal(wa.lowNextValue, wi.lowNextValue);
    }
    console.log('OK: insertion order changes the layout but not the membership semantics');
  }

  // ---------------------------------------------------------------------
  // 3) 폐기된 값에 대해 witness를 얻을 수 없다 / 비멤버는 얻을 수 있다.
  // ---------------------------------------------------------------------
  {
    const tree = await createIMTv2(DEPTH);
    const rootEmpty = tree.getRoot();

    const a = await leafValue(TAG_ACCOUNT, 777n);
    const s = await leafValue(TAG_SESSION, 777n);
    assert.notEqual(a.toString(), s.toString(), 'domain tags must separate identical raw values');

    // 빈 트리에서도 witness가 나온다 (anchor가 low 리프 역할을 한다)
    const w0 = await tree.getNonMembershipWitness(12345n);
    assert.equal(w0.lowValue, '0');
    assert.equal(w0.lowNextIndex, '0');
    assert.equal(w0.lowNextValue, '0');
    assert.equal(w0.root, rootEmpty.toString());
    assert.equal(w0.pathElements.length, DEPTH);
    assert.equal(w0.pathIndices.length, DEPTH);
    console.log('OK: empty tree still yields a witness anchored at leaf 0');

    assert.equal(await tree.insert(a), true);
    const rootAfter = tree.getRoot();
    assert.notEqual(rootAfter.toString(), rootEmpty.toString(), 'insert must change the root');

    await assert.rejects(() => tree.getNonMembershipWitness(a), /is a member/);
    console.log('OK: a revoked value yields no non-membership witness');

    const w1 = await tree.getNonMembershipWitness(s);
    assert.equal(w1.root, rootAfter.toString());
    console.log('OK: a non-revoked value still yields a witness');

    // 같은 값을 또 넣어도 no-op이고 root가 변하지 않는다
    assert.equal(await tree.insert(a), false, 'duplicate insert must be a no-op');
    assert.equal(tree.getRoot().toString(), rootAfter.toString(), 'duplicate insert must not change the root');
    console.log('OK: duplicate insert is a no-op that leaves the root untouched');

    // 원시(마스킹되지 않은) target도 회로와 같은 마스킹을 거쳐 처리된다
    const raw = (BigInt(w1.lowValue) + 1n) + (1n << 252n);
    if (BigInt(w1.lowNextValue) === 0n || raw - (1n << 252n) < BigInt(w1.lowNextValue)) {
      const wRaw = await tree.getNonMembershipWitness(raw);
      assert.equal(wRaw.lowValue, w1.lowValue);
      console.log('OK: an unmasked target is normalised to its low 252 bits');
    }
  }

  // ---------------------------------------------------------------------
  // 4) anchor 리프 보호 / 값 범위 / remove 부재.
  // ---------------------------------------------------------------------
  {
    const tree = await createIMTv2(DEPTH);
    await assert.rejects(() => tree.insert(0n), /anchor leaf and cannot be revoked/);
    console.log('OK: insert() rejects the anchor value 0');

    await assert.rejects(() => tree.insert(-5n), /outside/);
    console.log('OK: insert() rejects negative values');

    await assert.rejects(() => tree.insert(1n << 252n), /outside/);
    console.log('OK: insert() rejects unmasked values >= 2^252');

    assert.equal(typeof tree.remove, 'undefined', 'v2 must not expose remove(); unlinking is unsound');
    console.log('OK: remove() is absent (unlinking is unsound — design doc 3.2)');

    // anchor는 삽입을 아무리 해도 물리 인덱스 0에 남고 값이 0이다
    for (let i = 1; i <= 20; i++) await tree.insert(BigInt(i) * 13n);
    const leaves = tree.getLeaves();
    assert.equal(leaves[0].value, 0n, 'the anchor leaf must keep value 0 forever');
    assert.equal(leaves[0].nextValue, 13n, 'the anchor must link to the smallest inserted value');
    assertSortedLinkedList(leaves, 'anchor protection');
    console.log('OK: the anchor leaf stays at physical index 0 with value 0');
  }

  // ---------------------------------------------------------------------
  // 5) 고정 용량 — 슬롯이 다 차면 조용히 잘못된 root를 만들지 않고 거부한다.
  // ---------------------------------------------------------------------
  {
    const small = await createIMTv2(3); // 2^3 = 8 슬롯, anchor 포함
    assert.equal(small.capacity, 8);
    for (let i = 1; i <= 7; i++) assert.equal(await small.insert(BigInt(i)), true);
    assert.equal(small.size(), 8);
    assert.equal(small.usage().ratio, 1);

    const rootFull = small.getRoot().toString();
    await assert.rejects(() => small.insert(8n), /capacity exhausted/);
    assert.equal(small.getRoot().toString(), rootFull, 'a rejected insert must not mutate the tree');
    console.log('OK: insert() rejects once all 2^depth slots are used, leaving the tree intact');

    // 이미 있는 값은 가득 찬 트리에서도 no-op이어야 한다 (용량 검사보다 먼저 걸린다)
    assert.equal(await small.insert(3n), false);
    console.log('OK: a duplicate insert into a full tree is still a no-op');
  }

  // ---------------------------------------------------------------------
  // 6) 빈 서브트리 해시 — 고정 용량이 성립하는지.
  //    깊이가 달라도 리프 배치가 같으면 하위 구조가 같아야 하고, 무엇보다
  //    2^20 슬롯을 다 해싱하지 않고도 root가 참조 구현과 일치해야 한다.
  //    (테스트 1에서 이미 확인했지만 여기서 깊이를 바꿔 한 번 더 본다)
  // ---------------------------------------------------------------------
  {
    for (const d of [4, 10, 20]) {
      const refRootD = makeRefRoot(poseidon, d);
      const t = await buildIMTv2(d, [5n, 9n, 2n, 7n]);
      assert.equal(t.getRoot().toString(), refRootD(t.getLeaves()).toString(), `depth ${d} root mismatch`);
    }
    console.log('OK: precomputed empty-subtree hashes give the correct fixed-capacity root at depth 4/10/20');
  }

  // ---------------------------------------------------------------------
  // 7) rebaseline — 살아있는 값만으로 새 트리를 쌓는다.
  // ---------------------------------------------------------------------
  {
    const live = [11n, 22n, 33n];
    const dead = [44n, 55n];
    const tree = await buildIMTv2(DEPTH, shuffled([...live, ...dead], 7));
    for (const v of [...live, ...dead]) assert.equal(tree.has(v), true);

    const rebased = await tree.rebaseline(live);

    // 원본은 그대로다 (재기준화는 후보 트리를 만들 뿐이다 — 설계 문서 3.3절)
    assert.equal(tree.size(), 6, 'rebaseline() must not mutate the source tree');
    for (const v of dead) assert.equal(tree.has(v), true);

    assert.equal(rebased.size(), live.length + 1, 'rebased tree holds the anchor plus the live values');
    for (const v of live) assert.equal(rebased.has(v), true);
    for (const v of dead) assert.equal(rebased.has(v), false);
    assertSortedLinkedList(rebased.getLeaves(), 'rebaseline');
    assert.equal(rebased.getRoot().toString(), refRoot(rebased.getLeaves()).toString());
    console.log('OK: rebaseline() builds a tree over the live set only, without touching the source');

    // 재기준화한 뒤에는 죽은 값이 다시 비멤버가 된다 — 회수가 여기서 일어난다
    for (const v of dead) {
      const w = await rebased.getNonMembershipWitness(v);
      assert.ok(BigInt(w.lowValue) < v, 'low < target');
      assert.ok(BigInt(w.lowNextValue) === 0n || v < BigInt(w.lowNextValue), 'target < next (or sentinel)');
    }
    console.log('OK: values dropped by rebaseline() are non-members again');

    // rebaseline()의 root는 입력 순서와 무관한 살아있는 집합의 순수 함수다
    const rebasedShuffled = await tree.rebaseline(shuffled(live, 99));
    assert.equal(
      rebased.getRoot().toString(),
      rebasedShuffled.getRoot().toString(),
      'rebaseline() must be a pure function of the live set, independent of input order',
    );
    console.log('OK: rebaseline() root is order-independent (sorted layout)');

    // 중복이 섞여 들어와도 한 번만 들어간다
    const withDupes = await tree.rebaseline([...live, ...live]);
    assert.equal(withDupes.getRoot().toString(), rebased.getRoot().toString());
    console.log('OK: rebaseline() de-duplicates its input');
  }

  // ---------------------------------------------------------------------
  // 8) witness의 lowNextIndex가 실제로 low 리프가 가리키는 물리 인덱스인가.
  //    회로는 이 값을 리프 해시에만 쓰므로, 틀리면 경로 검증에서 걸린다.
  // ---------------------------------------------------------------------
  {
    const tree = await buildIMTv2(DEPTH, [100n, 300n, 200n, 50n]);
    const leaves = tree.getLeaves();
    const w = await tree.getNonMembershipWitness(250n);
    assert.equal(w.lowValue, '200');
    assert.equal(w.lowNextValue, '300');
    const lowIdx = leaves.findIndex((l) => l.value === 200n);
    assert.equal(w.lowNextIndex, leaves[lowIdx].nextIndex.toString());
    assert.equal(leaves[Number(w.lowNextIndex)].value.toString(), w.lowNextValue);
    console.log('OK: witness.lowNextIndex points at the physical leaf holding lowNextValue');

    // 가장 큰 값보다 큰 target은 sentinel 리프를 low로 받는다
    const wMax = await tree.getNonMembershipWitness(999n);
    assert.equal(wMax.lowValue, '300');
    assert.equal(wMax.lowNextValue, '0');
    console.log('OK: a target above the maximum lands on the sentinel leaf');
  }

  console.log('PASS: proper IMT (v2) inserts in O(log n), matches full rebuilds, and refuses unsound operations.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
