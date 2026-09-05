// lib/imt_v3.js 단위 테스트 — 외부 산출물 없이 단독 실행된다.
//   node tests/test_imt_v3_lib.js
//
// v3의 위험은 v2와 다른 데 있다. v2는 "증분 갱신이 전체 재구성과 같은 root를 내는가"가
// 전부였고, 그건 서브트리 안에서 이미 v2 테스트가 고정한다. v3에서 새로 생기는 위험은
// 셋이다.
//
//   ① 라우팅 — 리프가 규칙이 정한 샤드로만 들어가는가. 엉뚱한 샤드에 들어가면 그 폐기는
//      증명에 보이지 않아 **조용히 무효**가 된다(설계 문서 4절 조건 4). 그래서
//      호출자가 샤드를 지정할 수 있는 경로가 아예 없어야 한다.
//   ② 상위 트리 — 포레스트가 들고 있는 root와 지갑이 루트 목록만으로 계산한 root가
//      같은가. 다르면 온체인 검증이 통째로 어긋난다.
//   ③ 격리 — 다른 샤드의 폐기가 내 서브트리 root를 건드리지 않는가. 이게 이 설계의
//      목적 그 자체다(설계 문서 1절 Case 2).
//
// 회로와의 일치(shardOf === IMTNonMembershipV3의 shardIndex)는 여기서 다루지 않는다.
// tests/test_pi_pk_i_v3_shard.mjs 가 이 모듈의 함수를 그대로 import해 회로에 먹이므로
// 그 테스트가 통과하는 것 자체가 일치의 증거다.
import assert from 'node:assert/strict';
import {
  createSessionForest,
  createAccountForest,
  createShardForest,
  computeTopRoot,
  computeTopPath,
  verifyTopPath,
  rootToBytes32,
  sessionShardOf,
  sessionShardLowOf,
  accountShardOf,
  leafValue,
  TAG_SESSION,
  TAG_ACCOUNT,
  SESSION_SHARD_COUNT,
  SESSION_RING,
  ACCOUNT_SHARD_COUNT,
  ACCOUNT_SUBTREE_DEPTH,
} from '../lib/imt_v3.js';

async function main() {
  // ── 1) 샤드 규칙 ──────────────────────────────────────────────────────
  {
    // 계정: 리프 하위 8비트
    for (const v of [0n, 1n, 255n, 256n, 257n, 123456789012345678901234567890n]) {
      assert.equal(accountShardOf(v), Number(v & 255n));
    }
    assert.equal(ACCOUNT_SHARD_COUNT, 256);

    // 세션: (max_height mod 512) * 8 + 리프 하위 3비트
    assert.equal(sessionShardOf(0n, 0n), 0);
    assert.equal(sessionShardOf(5n, 0n), 5);
    assert.equal(sessionShardOf(0n, 1n), 8);
    assert.equal(sessionShardOf(7n, 3n), 3 * 8 + 7);
    // 링이 한 바퀴 돌면 같은 칸으로 돌아온다
    assert.equal(sessionShardOf(2n, 5n), sessionShardOf(2n, 5n + SESSION_RING));
    assert.equal(sessionShardLowOf(13n), 5);
    assert.equal(SESSION_SHARD_COUNT, 4096);
    console.log('OK: 1) 샤드 규칙 — 계정은 하위 8비트, 세션은 (max_height mod 512)*8 + 하위 3비트');
  }

  // ── 2) 상위 트리 ──────────────────────────────────────────────────────
  // 작은 포레스트로 시작해 keccak 경로 계산이 서로 맞물리는지 본다.
  {
    const f = await createShardForest({
      shardCount: 8,
      depth: 4,
      shardOf: (leaf) => Number(BigInt(leaf) & 7n),
    });

    // 빈 상태: 모든 샤드가 빈 서브트리 상수
    const roots0 = f.getSubtreeRoots();
    assert.equal(roots0.length, 8);
    assert.ok(roots0.every((r) => r === f.emptyRoot), '빈 포레스트의 루트가 상수가 아니다');
    assert.equal(f.getTopRoot(), computeTopRoot(roots0), '빈 상태의 top root 불일치');

    // 리프를 몇 개 넣고, 매번 포레스트의 top root와 순수 함수 계산이 같은지 확인
    for (const v of [9n, 17n, 3n, 42n, 100n]) {
      await f.insert(v);
      const roots = f.getSubtreeRoots();
      assert.equal(f.getTopRoot(), computeTopRoot(roots), `top root 불일치 (leaf ${v})`);
    }

    // 상위 경로: 포레스트가 준 것과 순수 함수가 준 것이 같고, 둘 다 재검증을 통과해야 한다
    for (let s = 0; s < 8; s++) {
      const roots = f.getSubtreeRoots();
      const a = f.getTopPath(s);
      const b = computeTopPath(roots, s);
      assert.deepEqual(a, b, `샤드 ${s}의 상위 경로가 순수 함수 계산과 다르다`);
      assert.ok(
        verifyTopPath(f.getSubtreeRoot(s), s, a, f.getTopRoot()),
        `샤드 ${s}의 상위 경로가 재검증을 통과하지 못했다`,
      );
    }

    // 가짜 root로는 통과하지 못한다 (컨트랙트가 막을 지점의 라이브러리 쪽 대응물)
    assert.ok(
      !verifyTopPath(f.emptyRoot, 1, f.getTopPath(1), f.getTopRoot()) || f.getSubtreeRoot(1) === f.emptyRoot,
      '가짜 root가 상위 경로 검증을 통과했다',
    );
    console.log('OK: 2) 상위 트리 — 포레스트 top root와 루트 목록 기반 계산이 일치하고 경로가 재검증된다');
  }

  // ── 3) 라우팅 — 호출자가 샤드를 고를 수 없다 ─────────────────────────
  {
    const acct = await createAccountForest();
    const leaf = await leafValue(TAG_ACCOUNT, 987654321n);
    const shard = accountShardOf(leaf);

    await acct.insert(leaf);
    assert.equal(acct.shardFor(leaf), shard);
    assert.ok(await acct.has(leaf), '삽입한 리프를 자기 샤드에서 찾지 못한다');

    // 규칙이 정한 샤드에만 들어갔다
    assert.deepEqual(acct.activeShards(), [shard]);
    for (let s = 0; s < ACCOUNT_SHARD_COUNT; s++) {
      if (s === shard) continue;
      assert.equal(acct.getSubtreeRoot(s), acct.emptyRoot, `샤드 ${s}가 오염됐다`);
    }

    // insert/witness 어디에도 샤드를 지정하는 인자가 없다 — 규칙만 받는다.
    // 폐기된 리프는 자기 샤드에서 witness가 나오지 않아야 한다(Case 1).
    await assert.rejects(
      () => acct.getNonMembershipWitness(leaf),
      /is a member of the revocation set/,
      '폐기된 계정 리프에 대해 witness가 만들어졌다',
    );
    console.log('OK: 3) 라우팅 — 규칙이 정한 샤드에만 들어가고, 폐기된 리프는 witness가 나오지 않는다');
  }

  // ── 4) 격리 — 다른 샤드의 폐기는 내 서브트리를 건드리지 않는다 (Case 2) ─
  {
    const acct = await createAccountForest();
    const mine = await leafValue(TAG_ACCOUNT, 111111n);
    const myShard = accountShardOf(mine);

    const w0 = await acct.getNonMembershipWitness(mine);
    const myRoot0 = acct.getSubtreeRoot(myShard);
    const top0 = acct.getTopRoot();

    // 내 샤드가 아닌 곳에 떨어지는 남의 리프를 찾아 넣는다
    let other = null;
    for (let i = 1; i < 500; i++) {
      const cand = await leafValue(TAG_ACCOUNT, 111111n + BigInt(i));
      if (accountShardOf(cand) !== myShard) { other = cand; break; }
    }
    assert.ok(other !== null, '다른 샤드에 떨어지는 리프를 찾지 못했다');
    await acct.insert(other);

    const w1 = await acct.getNonMembershipWitness(mine);
    assert.equal(acct.getSubtreeRoot(myShard), myRoot0, '타인 폐기가 내 서브트리 root를 바꿨다');
    assert.deepEqual(w1, w0, '타인 폐기가 내 witness를 바꿨다');
    assert.notEqual(acct.getTopRoot(), top0, 'top root는 바뀌어야 한다 (상위 형제 갱신이 필요하다는 뜻)');
    console.log('OK: 4) 격리 — 타인 폐기에 내 서브트리 root와 witness가 불변, top root만 바뀐다');
  }

  // ── 5) 세션 층 만료 리셋 ──────────────────────────────────────────────
  // 샤드 인덱스의 만료 축이 곧 그 안의 리프들의 만료이므로, 재기준화 없이 통째로 버린다.
  {
    const sess = await createSessionForest();
    const maxHeight = 1000n;
    const leaf = await leafValue(TAG_SESSION, 555n);
    const shard = sessionShardOf(leaf, maxHeight);

    await sess.insert(leaf, { maxHeight });
    assert.ok(await sess.has(leaf, { maxHeight }));
    const withLeaf = sess.getSubtreeRoot(shard);
    assert.notEqual(withLeaf, sess.emptyRoot);

    // maxHeight가 없으면 라우팅이 불가능하므로 거부해야 한다
    await assert.rejects(() => sess.insert(leaf), /requires meta.maxHeight/);

    // 만료 리셋: 그 샤드가 빈 상태로 돌아가고 top root도 원래대로
    const topBefore = sess.getTopRoot();
    assert.equal(sess.resetShard(shard), true);
    assert.equal(sess.getSubtreeRoot(shard), sess.emptyRoot);
    assert.equal(await sess.has(leaf, { maxHeight }), false);
    assert.notEqual(sess.getTopRoot(), topBefore);
    assert.equal(sess.resetShard(shard), false, '이미 빈 샤드를 리셋했는데 true를 돌려줬다');

    // 링이 한 바퀴 돈 뒤 같은 칸을 다시 쓴다
    const later = maxHeight + SESSION_RING;
    assert.equal(sessionShardOf(leaf, later), shard);
    console.log('OK: 5) 세션 층 — 만료 샤드를 통째로 리셋하고 링이 재사용된다');
  }

  // ── 6) loadShard — 지갑 재구성이 같은 root를 낸다 ─────────────────────
  {
    // 샤드 8개짜리 작은 포레스트를 쓴다 — 같은 샤드에 떨어지는 리프를 찾는 비용이
    // 계정 포레스트(256칸)에서는 리프 수백 개를 해싱해야 해서 느리다. 검증하려는 것은
    // loadShard/getShardLeafValues의 왕복이지 샤드 개수가 아니다.
    const SMALL = 8;
    const idp = await createShardForest({
      shardCount: SMALL,
      depth: ACCOUNT_SUBTREE_DEPTH,
      shardOf: (leaf) => Number(BigInt(leaf) & BigInt(SMALL - 1)),
    });
    const values = [];
    let shard = null;
    for (let i = 0; i < 200 && values.length < 3; i++) {
      const cand = await leafValue(TAG_ACCOUNT, 7000000n + BigInt(i));
      const s = Number(cand & BigInt(SMALL - 1));
      if (shard === null) shard = s;
      if (s === shard) values.push(cand.toString());
    }
    assert.equal(values.length, 3, '같은 샤드에 떨어지는 리프 3개를 찾지 못했다');
    for (const v of values) await idp.insert(BigInt(v));

    // 지갑: 그 샤드의 물리 순서 리프 배열만 받아 재구성한다
    const served = idp.getShardLeafValues(shard);
    assert.deepEqual(served, values, '서빙되는 리프 배열이 물리 순서가 아니다');

    const wallet = await createShardForest({
      shardCount: SMALL,
      depth: ACCOUNT_SUBTREE_DEPTH,
      shardOf: (leaf) => Number(BigInt(leaf) & BigInt(SMALL - 1)),
    });
    const rebuilt = await wallet.loadShard(shard, served);
    assert.equal(rebuilt, idp.getSubtreeRoot(shard), '지갑 재구성 root가 IdP와 다르다');

    // 지갑은 루트 목록만 더 받으면 상위 경로까지 스스로 만든다
    const roots = idp.getSubtreeRoots();
    const siblings = computeTopPath(roots, shard);
    assert.ok(
      verifyTopPath(rebuilt, shard, siblings, idp.getTopRoot()),
      '지갑이 만든 상위 경로가 IdP의 top root로 이어지지 않는다',
    );
    console.log('OK: 6) loadShard — 지갑이 샤드 하나 + 루트 목록만으로 top root까지 재현한다');
  }

  // ── 7) 사용률은 샤드별로 본다 ─────────────────────────────────────────
  {
    const f = await createShardForest({
      shardCount: 4,
      depth: 2,                       // 슬롯 4개(anchor 포함)
      shardOf: () => 1,               // 일부러 한 샤드로 몰아넣는다
    });
    await f.insert(10n);
    await f.insert(20n);
    await f.insert(30n);
    const u = f.usage();
    assert.equal(u.activeShards, 1);
    assert.equal(u.maxShardUsed, 4);
    assert.equal(u.maxShardRatio, 1);
    // 한 샤드만 꽉 차도 전역 평균으로는 25%다 — 그래서 샤드별로 봐야 한다
    await assert.rejects(() => f.insert(40n), /capacity exhausted/);
    console.log('OK: 7) 사용률 — 한 샤드만 먼저 차는 상황이 드러나고, 넘치면 거부한다');
  }

  // ── 8) rootToBytes32 ─────────────────────────────────────────────────
  {
    assert.equal(rootToBytes32(0n), '0x' + '0'.repeat(64));
    assert.equal(rootToBytes32(1n), '0x' + '0'.repeat(63) + '1');
    assert.equal(rootToBytes32('255'), '0x' + '0'.repeat(62) + 'ff');
    console.log('OK: 8) rootToBytes32 — 필드 원소를 bytes32로 왼쪽 0채움');
  }

  console.log(`\nPASS: 샤드 포레스트(v3) — 라우팅·상위 트리·격리·만료 리셋·지갑 재구성 (계정 깊이 ${ACCOUNT_SUBTREE_DEPTH})`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
