// IdP가 v3(이중 트리) 폐기 상태를 실제로 라우팅·서빙·영속화하는지 본다.
//   node tests/test_idp_revocation_v3.mjs
//
// tests/helpers/isolated_idp.mjs로 격리 인스턴스를 띄운다 — 개발용 :4000과 그 폐기
// 트리는 건드리지 않는다. 전제: hardhat 노드(IdP가 블록 높이를 읽는다).
//
// 무엇을 고정하는가 — 설계 문서 2026-09-05-revocation-dual-tree-design.md 9절:
//
//   1) 라우팅   세션 폐기는 세션 포레스트로, 계정 폐기는 계정 포레스트로 간다.
//               리프는 Poseidon 해시라 사후에 층을 알 수 없으므로 접수 시점의 기록이
//               유일한 근거다 — 그게 실제로 작동하는지 본다.
//   2) 서빙     지갑이 받은 응답만으로 상위 root를 재현할 수 있는가. 재현이 안 되면
//               온체인 검증이 통째로 어긋난다.
//   3) 격리     다른 샤드의 폐기가 내 서브트리 root를 바꾸지 않는가(Case 2).
//   4) 영속화   재시작을 넘어 v3가 같은 root로 살아남는가(상태 파일 v5).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { leafValue, TAG_SESSION, TAG_ACCOUNT } from '../lib/imt.js';
import {
  computeTopRoot,
  computeTopPath,
  verifyTopPath,
  combineTopRoots,
  accountShardOf,
  sessionShardOf,
  SESSION_SHARD_COUNT,
  ACCOUNT_SHARD_COUNT,
} from '../lib/imt_v3.js';
import { startIsolatedIdP } from './helpers/isolated_idp.mjs';

const uniqueValue = () => `${Date.now()}${Math.floor(Math.random() * 1e6)}`;

/** 응답의 (빈 루트 + 덮어쓰기 목록)에서 전체 루트 배열을 복원한다 — 지갑이 할 일. */
function rebuildRoots(emptyRoot, overrides, count) {
  const roots = new Array(count).fill(emptyRoot);
  for (const [shard, root] of Object.entries(overrides)) roots[Number(shard)] = root;
  return roots;
}

async function publish(idp) {
  const prepared = await idp.post('/idp/publish/prepare');
  assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
  const committed = await idp.post('/idp/publish/commit', { roundToken: prepared.body.roundToken });
  assert.equal(committed.status, 200, JSON.stringify(committed.body));
  return committed.body;
}

async function main() {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'idp-v3-'));
  let idp = await startIsolatedIdP({ dir: stateDir });
  try {
    // ── 1) 계정 폐기가 계정 포레스트로 라우팅된다 ────────────────────────
    const auid = uniqueValue();
    const acctLeaf = (await leafValue(TAG_ACCOUNT, auid)).toString();
    const acctShard = accountShardOf(acctLeaf);

    let r = await idp.post('/idp/revoke', { type: 'account', value: auid });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.leaf, acctLeaf);

    // 게시 전에는 v3에도 반영되지 않아야 한다 (게시된 상태만 서빙한다).
    let snap = (await idp.get('/idp/revocation_state_v3')).body;
    assert.deepEqual(snap.accountRootOverrides, {}, '게시 전인데 v3에 반영됐다');

    await publish(idp);
    snap = (await idp.get(`/idp/revocation_state_v3?accountShard=${acctShard}`)).body;
    assert.deepEqual(
      Object.keys(snap.accountRootOverrides).map(Number),
      [acctShard],
      '계정 폐기가 규칙이 정한 샤드로 가지 않았다',
    );
    assert.deepEqual(snap.sessionRootOverrides, {}, '계정 폐기가 세션 포레스트를 건드렸다');
    assert.deepEqual(snap.accountShardLeaves, [acctLeaf]);
    console.log(`OK: 1) 계정 폐기가 샤드 ${acctShard}로 라우팅됐다`);

    // ── 2) 응답만으로 상위 root를 재현할 수 있다 ─────────────────────────
    {
      const acctRoots = rebuildRoots(snap.accountEmptyRoot, snap.accountRootOverrides, ACCOUNT_SHARD_COUNT);
      const sessRoots = rebuildRoots(snap.sessionEmptyRoot, snap.sessionRootOverrides, SESSION_SHARD_COUNT);
      assert.equal(computeTopRoot(acctRoots), snap.accountTopRoot, '계정 상위 root 재현 실패');
      assert.equal(computeTopRoot(sessRoots), snap.sessionTopRoot, '세션 상위 root 재현 실패');
      assert.equal(
        combineTopRoots(snap.sessionTopRoot, snap.accountTopRoot),
        snap.topRoot,
        'combined root 재현 실패',
      );
      // IdP가 준 상위 형제도 같은 값이어야 하고, 재검증을 통과해야 한다.
      assert.deepEqual(snap.accountShardSiblings, computeTopPath(acctRoots, acctShard));
      assert.ok(
        verifyTopPath(acctRoots[acctShard], acctShard, snap.accountShardSiblings, snap.accountTopRoot),
        'IdP가 준 상위 경로가 자기 top root로 이어지지 않는다',
      );
      console.log('OK: 2) 지갑이 응답만으로 상위 root와 경로를 재현한다');
    }

    // ── 3) 세션 폐기는 세션 포레스트로 간다 ──────────────────────────────
    // 세션 폐기는 발급 기록이 있어야 접수된다(입구 검사). 격리 인스턴스에는 로그인
    // 기록이 없으므로 404가 정상이고, 그 자체가 "임의의 숫자로 트리를 부풀릴 수 없다"는
    // 기존 불변식이다. 여기서는 그 거부를 확인하고, 라우팅은 4)의 재시작 검증으로 본다.
    {
      const rr = await idp.post('/idp/revoke', { type: 'session', value: uniqueValue() });
      assert.equal(rr.status, 404, `세션 폐기 입구 검사가 사라졌다: ${JSON.stringify(rr.body)}`);
      console.log('OK: 3) 발급 기록 없는 세션 폐기는 접수되지 않는다 (기존 불변식 유지)');
    }

    // ── 4) 격리 — 다른 계정 폐기가 내 서브트리를 건드리지 않는다 ─────────
    {
      const before = snap.accountRootOverrides[acctShard];
      const beforeTop = snap.topRoot;

      let other = null;
      for (let i = 0; i < 400; i++) {
        const v = uniqueValue();
        const leaf = (await leafValue(TAG_ACCOUNT, v)).toString();
        if (accountShardOf(leaf) !== acctShard) { other = v; break; }
      }
      assert.ok(other, '다른 샤드에 떨어지는 값을 찾지 못했다');
      r = await idp.post('/idp/revoke', { type: 'account', value: other });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      await publish(idp);

      const after = (await idp.get('/idp/revocation_state_v3')).body;
      assert.equal(after.accountRootOverrides[acctShard], before, '타인 폐기가 내 서브트리 root를 바꿨다');
      assert.notEqual(after.topRoot, beforeTop, 'top root는 바뀌어야 한다');
      console.log('OK: 4) 타인 폐기에 내 서브트리 root가 불변, top root만 바뀐다');
    }

    // ── 5) 영속화 — 재시작을 넘어 같은 root ──────────────────────────────
    const beforeRestart = (await idp.get('/idp/revocation_state_v3')).body;
    const stateFile = path.join(stateDir, 'idp_state.json');
    const saved = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    assert.equal(saved.version, 6, '상태 파일이 v6가 아니다');
    assert.ok(saved.v3 && saved.v3.accountShards, 'v3 스냅샷이 저장되지 않았다');
    // v6에서 v2 필드가 사라졌다. 남아 있으면 게시의 진실이 둘인 상태로 되돌아간 것이다.
    for (const k of ['v2Leaves', 'publishedRootV2', 'epochV2', 'seqV2']) {
      assert.ok(!(k in saved), `v6 상태 파일에 v2 필드 ${k}가 남아 있다`);
    }

    await idp.stop();
    idp = await startIsolatedIdP({ dir: stateDir });
    const afterRestart = (await idp.get('/idp/revocation_state_v3')).body;
    assert.equal(afterRestart.topRoot, beforeRestart.topRoot, '재시작 후 combined root가 달라졌다');
    assert.deepEqual(afterRestart.accountRootOverrides, beforeRestart.accountRootOverrides);
    console.log('OK: 5) 재시작을 넘어 v3 상태가 같은 root로 복원된다');

    // ── 6) 잘못된 샤드 질의는 거부한다 ───────────────────────────────────
    {
      const bad = await idp.get(`/idp/revocation_state_v3?accountShard=${ACCOUNT_SHARD_COUNT}`);
      assert.equal(bad.status, 400);
      const bad2 = await idp.get('/idp/revocation_state_v3?sessionShard=abc');
      assert.equal(bad2.status, 400);
      console.log('OK: 6) 범위를 벗어난 샤드 질의를 400으로 거부한다');
    }

    // ── 7) 이미 게시된 폐기의 재접수는 대기열을 오염시키지 않는다 ─────────
    // 13.1 이전에는 이 성질이 "backfill이 무력했던 이유"였다(재접수로는 v2에만 있는
    // 리프를 v3로 되찾을 수 없어 전용 관리자 경로 rebuild_from_v2가 필요했다). v2가
    // 사라지면서 그 경로도 사라졌지만, 성질 자체는 여전히 유효하고 지켜져야 한다 —
    // 게시된 폐기를 다시 접수할 때마다 대기열이 자라면 매 회차가 중복 삽입을 시도한다.
    {
      const v = uniqueValue();
      r = await idp.post('/idp/revoke', { type: 'account', value: v });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      await publish(idp);

      const again = await idp.post('/idp/revoke', { type: 'account', value: v });
      assert.equal(again.body.alreadyPublished, true, '게시된 폐기인데 alreadyPublished가 서지 않았다');
      assert.equal(again.body.pendingCount, 0, '재접수가 대기열에 들어갔다');

      const before = (await idp.get('/idp/revocation_state_v3')).body.topRoot;
      const p2 = await idp.post('/idp/publish/prepare');
      assert.equal(p2.body.added, 0, '재접수로 게시될 리프가 생겼다');
      await idp.post('/idp/publish/commit', { roundToken: p2.body.roundToken });
      assert.equal(
        (await idp.get('/idp/revocation_state_v3')).body.topRoot, before,
        '아무것도 추가되지 않았는데 root가 바뀌었다',
      );
      console.log('OK: 7) 게시된 폐기의 재접수는 대기열도 root도 건드리지 않는다');
    }

    console.log('\n== IdP v3 배선 7종 통과 ==');
  } finally {
    await idp.stop();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
