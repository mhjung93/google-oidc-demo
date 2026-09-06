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

  // ── 9) 계정 층 샤드 단위 재기준화 ─────────────────────────────────────
  {
    const { createIdPRevocationV3, LAYER_ACCOUNT } = await import('../lib/idp_revocation_v3.js');
    const v3 = await createIdPRevocationV3();

    // 같은 샤드에 만료/생존 리프를 하나씩 넣는다
    let expired = null;
    let liveLeaf = null;
    let shard = null;
    for (let i = 0; i < 600 && (expired === null || liveLeaf === null); i++) {
      const leaf = (await leafValue(TAG_ACCOUNT, 900000n + BigInt(i))).toString();
      const s2 = accountShardOf(leaf);
      if (shard === null) shard = s2;
      if (s2 !== shard) continue;
      if (expired === null) expired = leaf;
      else if (liveLeaf === null) liveLeaf = leaf;
    }
    assert.ok(expired && liveLeaf, '같은 샤드의 리프 2개를 찾지 못했다');

    v3.record(expired, LAYER_ACCOUNT, { expiry: 100n });   // 블록 100에 만료
    v3.record(liveLeaf, LAYER_ACCOUNT, { expiry: 9999n }); // 아직 살아있음
    await v3.applyCommit([expired, liveLeaf]);
    const before = v3.combinedRoot();

    // 만료 전에는 아무것도 회수되지 않는다
    assert.deepEqual(await v3.rebaselineExpiredAccountShards(50n), { shardsRebaselined: 0, leavesReclaimed: 0 });
    assert.equal(v3.combinedRoot(), before, '만료 전인데 root가 바뀌었다');

    // 만료 후: 그 샤드만 재기준화되고 살아있는 리프는 남는다
    const r = await v3.rebaselineExpiredAccountShards(500n);
    assert.deepEqual(r, { shardsRebaselined: 1, leavesReclaimed: 1 });
    assert.notEqual(v3.combinedRoot(), before);
    const snap = v3.snapshot({ accountShard: shard });
    assert.deepEqual(snap.accountShardLeaves, [liveLeaf], '살아있는 리프가 남지 않았다');
    console.log('OK: 9) 계정 층 — 만료 리프만 샤드 단위로 회수되고 생존 리프는 남는다');
  }

  // ── 10) 리뷰 회귀: 라우팅 키·부분 적용·샤드 검증 ───────────────────────
  // 2026-09-06 리뷰에서 나온 세 결함을 고정한다. 셋 다 공통점이 있다 — 실패해도
  // 아무 데서도 드러나지 않고, 폐기가 조용히 무효가 된다.
  {
    const { createIdPRevocationV3, LAYER_SESSION, LAYER_ACCOUNT } =
      await import('../lib/idp_revocation_v3.js');

    // (a) 세션 라우팅 키는 만료가 아니라 max_height다.
    //     같은 리프에 더 늦은 만료가 들어와도 샤드는 max_height가 정해야 한다.
    {
      const v3 = await createIdPRevocationV3();
      const leaf = (await leafValue(TAG_SESSION, 4001n)).toString();
      v3.record(leaf, LAYER_SESSION, { expiry: 2000n, maxHeight: 1000n });
      await v3.applyCommit([leaf]);
      const shards = Object.keys(v3.snapshot().sessionRootOverrides).map(Number);
      assert.deepEqual(
        shards, [sessionShardOf(leaf, 1000n)],
        '세션 리프가 max_height가 아니라 만료로 라우팅됐다 — 그 폐기는 증명에 보이지 않는다',
      );
      // max_height 없이 세션을 기록하려 하면 거부해야 한다(조용히 만료를 쓰지 않도록)
      assert.throws(() => v3.record(leaf, LAYER_SESSION, { expiry: 1000n }), /requires maxHeight/);
      console.log('OK: 10-a) 세션 샤드는 만료가 아니라 max_height로 정해진다');
    }

    // (b) 층 미기록 리프 하나가 배치 나머지를 버리면 안 된다.
    {
      const v3 = await createIdPRevocationV3();
      const g1 = (await leafValue(TAG_ACCOUNT, 5001n)).toString();
      const orphan = (await leafValue(TAG_ACCOUNT, 5002n)).toString(); // 층 미기록
      const g2 = (await leafValue(TAG_ACCOUNT, 5003n)).toString();
      v3.record(g1, LAYER_ACCOUNT, { expiry: 9999n });
      v3.record(g2, LAYER_ACCOUNT, { expiry: 9999n });
      const r = await v3.applyCommit([g1, orphan, g2]);
      assert.equal(r.accountAdded, 2, '층 미기록 리프 때문에 배치 나머지가 유실됐다');
      assert.equal(r.failed.length, 1);
      assert.equal(r.failed[0].leaf, orphan);
      assert.match(r.failed[0].reason, /no recorded layer/);
      assert.equal(v3.needsBackfill, true, '반영 실패가 있었는데 backfill 플래그가 서지 않았다');
      console.log('OK: 10-b) 층 미기록 리프는 건너뛰되 배치 나머지는 반영되고, 실패 목록이 보고된다');
    }

    // (c) loadShard는 다른 샤드의 리프를 거부해야 한다.
    {
      const f = await createAccountForest();
      const mine = (await leafValue(TAG_ACCOUNT, 6001n)).toString();
      const myShard = accountShardOf(mine);
      let foreign = null;
      for (let i = 0; i < 500; i++) {
        const c = (await leafValue(TAG_ACCOUNT, 7000n + BigInt(i))).toString();
        if (accountShardOf(c) !== myShard) { foreign = c; break; }
      }
      assert.ok(foreign, '다른 샤드 리프를 찾지 못했다');
      await assert.rejects(
        () => f.loadShard(myShard, [foreign]),
        /does not belong to shard/,
        '다른 샤드의 리프를 검증 없이 적재했다',
      );
      await f.loadShard(myShard, [mine]); // 올바른 것은 통과
      console.log('OK: 10-c) loadShard가 다른 샤드의 리프를 거부한다');
    }
  }

  // ── 11) 2차 리뷰 회귀: 링 재사용·메타데이터 누적·재구축 ────────────────
  {
    const { createIdPRevocationV3, LAYER_SESSION, LAYER_ACCOUNT } =
      await import('../lib/idp_revocation_v3.js');
    const { sessionShardLowOf } = await import('../lib/imt_v3.js');

    // (a) 정리 창을 놓쳐도 링 재사용 시 낡은 리프가 섞이지 않는다.
    //     예전에는 "링 슬롯이 지금 살아있는가"로 판정해, 36분 창을 놓치면 만료된 리프가
    //     다음 주기의 새 크레덴셜과 같은 샤드에 남았다.
    {
      const v3 = await createIdPRevocationV3();
      let a = null, b = null;
      for (let i = 0n; i < 400n && (a === null || b === null); i++) {
        const l = (await leafValue(TAG_SESSION, 1000n + i)).toString();
        if (a === null) a = l;
        else if (sessionShardLowOf(l) === sessionShardLowOf(a)) b = l;
      }
      assert.ok(a && b, '값 버킷이 같은 리프 2개를 찾지 못했다');
      const M1 = 100n, M2 = 100n + SESSION_RING;   // 링 한 바퀴 뒤 = 같은 샤드
      v3.record(a, LAYER_SESSION, { expiry: M1, maxHeight: M1 });
      await v3.applyCommit([a]);
      const shard = sessionShardOf(a, M1);
      assert.equal(sessionShardOf(b, M2), shard, '두 리프가 같은 샤드여야 이 테스트가 의미 있다');

      // 정리 창(블록 100~279)을 통째로 놓친다
      for (const blk of [300n, 400n, 500n, 600n]) v3.resetExpiredSessionShards(blk);

      // 링이 재사용되는 새 크레덴셜이 들어온다
      v3.record(b, LAYER_SESSION, { expiry: M2, maxHeight: M2 });
      await v3.applyCommit([b]);
      const leaves = v3._forests().session.getShardLeafValues(shard);
      assert.deepEqual(
        leaves, [b],
        '링 재사용 시 만료된 옛 리프가 새 크레덴셜과 같은 샤드에 남았다 (샤드 용량 잠식)',
      );
      console.log('OK: 11-a) 정리 창을 놓쳐도 링 재사용이 자가 치유된다');
    }

    // (b) 게시되지 않은 접수분의 메타데이터가 만료 후 정리된다.
    {
      const v3 = await createIdPRevocationV3();
      for (let i = 0; i < 5; i++) {
        v3.record((await leafValue(TAG_SESSION, 2000n + BigInt(i))).toString(),
                  LAYER_SESSION, { expiry: 10n, maxHeight: 10n });
        v3.record((await leafValue(TAG_ACCOUNT, 3000n + BigInt(i))).toString(),
                  LAYER_ACCOUNT, { expiry: 10n });
      }
      const before = v3.serialize();
      assert.equal(Object.keys(before.layer).length, 10);
      const pruned = v3.pruneExpiredMetadata(1000n);
      const after = v3.serialize();
      assert.equal(pruned, 10);
      assert.equal(Object.keys(after.layer).length, 0, '만료된 메타데이터가 정리되지 않았다');
      assert.equal(Object.keys(after.sessionMaxHeight).length, 0);
      assert.equal(Object.keys(after.accountExpiry).length, 0);
      console.log('OK: 11-b) 게시되지 않은 접수분의 만료 메타데이터가 정리된다');
    }

    // (c) v2에만 있는 리프를 preimage로 되찾는다 (backfill).
    //     /idp/revoke 재접수로는 안 되는 경로다 — 그래서 별도 관리자 경로를 뒀다.
    {
      const v3 = await createIdPRevocationV3();
      const auid = 424242n;
      const leaf = (await leafValue(TAG_ACCOUNT, auid)).toString();
      const published = new Set([leaf]);           // v2에는 있고 v3에는 없는 상태
      assert.equal(await v3.hasLeaf(leaf), false);

      // 잘못된 후보는 v2 게시 집합과 대조돼 들어가지 않는다
      const wrong = (await leafValue(TAG_ACCOUNT, 999999n)).toString();
      let r = await v3.rebuildFromCandidates(
        { account: [{ leaf: wrong, expiry: 9999n }] }, published, 100n);
      assert.equal(r.routed.account, 0);
      assert.match(r.skipped[0].reason, /not in the published v2 set/);

      // 만료된 후보도 건너뛴다
      r = await v3.rebuildFromCandidates(
        { account: [{ leaf, expiry: 50n }] }, published, 100n);
      assert.equal(r.routed.account, 0);
      assert.match(r.skipped[0].reason, /already expired/);

      // 올바른 후보는 되찾아진다
      r = await v3.rebuildFromCandidates(
        { account: [{ leaf, expiry: 9999n }] }, published, 100n);
      assert.equal(r.routed.account, 1);
      assert.equal(await v3.hasLeaf(leaf), true, 'backfill로 v3에 반영되지 않았다');
      assert.equal(accountShardOf(leaf), Number(Object.keys(v3.snapshot().accountRootOverrides)[0]));

      // 두 번 돌려도 중복되지 않는다(멱등)
      r = await v3.rebuildFromCandidates(
        { account: [{ leaf, expiry: 9999n }] }, published, 100n);
      assert.equal(r.routed.account, 0);
      assert.match(r.skipped[0].reason, /already in v3/);
      console.log('OK: 11-c) v2에만 있는 리프를 preimage 대조로 되찾고, 오입력·만료·중복을 거른다');
    }
  }

  // ── 12) 3차 리뷰 회귀: shardMaxHeight 없는 옛 스냅샷 복원 ──────────────
  {
    const { createIdPRevocationV3, LAYER_SESSION } = await import('../lib/idp_revocation_v3.js');
    const v3 = await createIdPRevocationV3();
    const leaf = (await leafValue(TAG_SESSION, 777n)).toString();
    const M = 100n;
    v3.record(leaf, LAYER_SESSION, { expiry: M, maxHeight: M });
    await v3.applyCommit([leaf]);
    const shard = sessionShardOf(leaf, M);

    // 이 맵이 생기기 전에 쓰인 v5 파일을 흉내 낸다
    const oldSnapshot = { ...v3.serialize() };
    delete oldSnapshot.shardMaxHeight;

    const restored = await createIdPRevocationV3();
    await restored.restore(oldSnapshot);
    assert.equal(
      restored._forests().session.getShardLeafValues(shard).length, 1,
      '복원 자체가 실패했다',
    );
    // 메타데이터로 재구성했으므로 만료 회수가 동작해야 한다
    assert.equal(
      restored.resetExpiredSessionShards(100000n), 1,
      'shardMaxHeight를 재구성하지 못해 세션 샤드가 영영 회수되지 않는다',
    );
    assert.equal(restored._forests().session.getShardLeafValues(shard).length, 0);

    // 메타데이터까지 없으면 근거가 없으므로 비운다(영구 누적 방지)
    const noMeta = { ...v3.serialize() };
    delete noMeta.shardMaxHeight;
    delete noMeta.sessionMaxHeight;
    const restored2 = await createIdPRevocationV3();
    await restored2.restore(noMeta);
    assert.equal(
      restored2._forests().session.getShardLeafValues(shard).length, 0,
      '회수 근거가 전혀 없는 세션 샤드를 그대로 남겼다',
    );
    console.log('OK: 12) shardMaxHeight 없는 옛 스냅샷을 메타데이터로 재구성한다');
  }

  // ── 13) publishedLeafSet — v2 집합과의 차이가 설계대로인가 ─────────────
  {
    const { createIdPRevocationV3, LAYER_SESSION, LAYER_ACCOUNT } =
      await import('../lib/idp_revocation_v3.js');
    const v3 = await createIdPRevocationV3();
    const sLeaf = (await leafValue(TAG_SESSION, 8001n)).toString();
    const aLeaf = (await leafValue(TAG_ACCOUNT, 8002n)).toString();
    v3.record(sLeaf, LAYER_SESSION, { expiry: 100n, maxHeight: 100n });
    v3.record(aLeaf, LAYER_ACCOUNT, { expiry: 100n });
    await v3.applyCommit([sLeaf, aLeaf]);
    assert.deepEqual([...v3.publishedLeafSet()].sort(), [sLeaf, aLeaf].sort(),
      '두 층의 리프가 합집합에 안 들어왔다');

    // 만료 회수 후에는 v3에서 빠진다 — v2였다면 재기준화 전까지 남아 있었을 것이다.
    v3.resetExpiredSessionShards(1000n);
    await v3.rebaselineExpiredAccountShards(1000n);
    assert.equal(v3.publishedLeafSet().size, 0,
      '만료 리프가 회수됐는데도 합집합에 남아 있다');
    console.log('OK: 13) publishedLeafSet — 두 층 합집합이고, 만료 회수가 반영된다');
  }

  console.log(`\nPASS: 샤드 포레스트(v3) — 라우팅·상위 트리·격리·만료 리셋·지갑 재구성 (계정 깊이 ${ACCOUNT_SUBTREE_DEPTH})`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
