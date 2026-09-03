// 게시(prepare/commit)·재기준화·만료의 **동작** 테스트.
//   node tests/test_idp_publish_behavior.mjs
//
// tests/helpers/isolated_idp.mjs로 매 케이스마다 격리된 IdP를 띄운다 — 개발자가 띄워 둔
// :4000 인스턴스와 그 폐기 트리는 건드리지 않으며, 관리자 시크릿도 테스트가 스스로 만든다.
// 그래서 여기서는 **실패 경로와 소진 경로를 실제로 돌릴 수 있다**(소스 텍스트 검사가 아니다).
//
// 전제: hardhat 노드(ETH_RPC_URL, 기본 127.0.0.1:8545). IdP가 블록 높이를 읽는다.
// 주의: 만료를 확인하는 케이스는 그 체인의 블록을 CREDENTIAL_LIFETIME_BLOCKS(300)만큼
// 진행시킨다. 데모 체인에서는 무해하다(tests/test_mode2_e2e_onchain.js도 매 실행마다
// 블록을 진행시킨다).
import assert from 'node:assert/strict';
import { startIsolatedIdP, revokeAndPublish } from './helpers/isolated_idp.mjs';

const RPC = process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';
const CAPACITY = 2 ** 20; // 깊이 20
const CREDENTIAL_LIFETIME_BLOCKS = 300;

async function rpc(method, params = []) {
  const r = await fetch(RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const j = await r.json();
  if (j.error) throw new Error(`${method}: ${j.error.message}`);
  return j.result;
}

// 임계치를 리프 개수로 지정한다. usage().used는 anchor를 포함하므로 그 기준 그대로다.
const forceRatioForLeaves = (n) => String(n / CAPACITY);

const uniqueValue = () => `${Date.now()}${Math.floor(Math.random() * 1e6)}`;

// ---------------------------------------------------------------------------
// 1. 회수할 것이 없는데 슬롯이 임계치를 넘으면, 재기준화를 반복하지 않고 거부해야 한다.
//
// 현재는 사용률만 보고 재기준화를 강제한다. 살아있는 리프로 가득 차 있으면 재기준화해도
// 크기가 그대로라 다음 게시에서 또 강제되고, 그때마다 epoch가 올라 **모든 지갑이 매번
// 전체 재다운로드**를 한다. 회수되는 슬롯은 0인데 증분 설계만 무력화된다.
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP({ env: { IDP_REBASELINE_FORCE_RATIO: forceRatioForLeaves(4) } });
  try {
    await revokeAndPublish(idp, uniqueValue()); // used: anchor+1 = 2
    await revokeAndPublish(idp, uniqueValue()); // used: 3
    const beforeState = (await idp.get('/idp/revocation_state_v2')).body;
    assert.equal(beforeState.leaves.length, 3, '준비: anchor 포함 리프 3개');

    // 하나 더 넣으면 projected 4 >= 임계치 4. 만료된 리프는 하나도 없다.
    const queued = await idp.post('/idp/revoke', { type: 'account', value: uniqueValue() });
    assert.equal(queued.status, 200);

    const prepared = await idp.post('/idp/publish/prepare');
    assert.notEqual(
      prepared.status,
      200,
      '회수할 것이 없는데 임계치를 넘으면 prepare가 성공해서는 안 된다(재기준화 반복)',
    );
    assert.match(
      JSON.stringify(prepared.body),
      /capacity|slot|소진|용량/i,
      '거부 사유가 슬롯 소진임을 알 수 있어야 한다',
    );

    const afterState = (await idp.get('/idp/revocation_state_v2')).body;
    assert.equal(afterState.epoch, beforeState.epoch, '거부된 prepare는 epoch를 올리면 안 된다');
    assert.equal(afterState.root, beforeState.root, '거부된 prepare는 트리를 바꾸면 안 된다');
    console.log('OK (1): 회수 불가 + 임계치 초과 -> 재기준화 반복 대신 거부, 상태 불변');
  } finally {
    await idp.stop();
  }
}

// ---------------------------------------------------------------------------
// 2. 회수할 것이 있으면 재기준화로 실제로 회수한다(epoch 상승은 이때만).
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP({ env: { IDP_REBASELINE_FORCE_RATIO: forceRatioForLeaves(4) } });
  try {
    await revokeAndPublish(idp, uniqueValue());
    await revokeAndPublish(idp, uniqueValue());
    const before = (await idp.get('/idp/revocation_state_v2')).body;
    assert.equal(before.leaves.length, 3);

    // 게시된 두 리프를 만료시킨다.
    await rpc('hardhat_mine', [`0x${(CREDENTIAL_LIFETIME_BLOCKS + 1).toString(16)}`]);

    await idp.post('/idp/revoke', { type: 'account', value: uniqueValue() });
    const prepared = await idp.post('/idp/publish/prepare');
    assert.equal(prepared.status, 200, '회수할 만료 리프가 있으면 게시가 진행돼야 한다');
    assert.equal(prepared.body.v2.rebaselineForced, true, '임계치를 넘었으므로 재기준화 회차여야 한다');
    const committed = await idp.post('/idp/publish/commit', { root: prepared.body.expectedRoot });
    assert.equal(committed.status, 200);

    const after = (await idp.get('/idp/revocation_state_v2')).body;
    assert.equal(after.epoch, before.epoch + 1, '재기준화는 epoch를 올린다');
    assert.ok(
      after.leaves.length < before.leaves.length + 1,
      `재기준화가 만료 슬롯을 실제로 회수해야 한다 (before ${before.leaves.length}, after ${after.leaves.length})`,
    );
    console.log(`OK (2): 만료가 있을 때만 재기준화 — 리프 ${before.leaves.length} -> ${after.leaves.length}, epoch +1`);
  } finally {
    await idp.stop();
  }
}

// ---------------------------------------------------------------------------
// 3. 이미 만료된 대기 리프는 게시하지 않는다.
//
// append-only라 한 번 들어간 리프는 재기준화 전까지 슬롯을 물고 있는다. 게시 시점에
// 이미 만료인 줄 알면서 넣을 이유가 없다. (게시 주기가 300블록을 넘길 때 발생한다.)
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP();
  try {
    const before = (await idp.get('/idp/revocation_state_v2')).body;
    const staleValue = uniqueValue();
    const queued = await idp.post('/idp/revoke', { type: 'account', value: staleValue });
    assert.equal(queued.status, 200);

    // 게시 전에 만료시킨다.
    await rpc('hardhat_mine', [`0x${(CREDENTIAL_LIFETIME_BLOCKS + 1).toString(16)}`]);

    const prepared = await idp.post('/idp/publish/prepare');
    assert.equal(prepared.status, 200);
    assert.equal(prepared.body.added, 0, '이미 만료된 대기 리프는 게시 대상이 아니어야 한다');
    const committed = await idp.post('/idp/publish/commit', { root: prepared.body.expectedRoot });
    assert.equal(committed.status, 200);

    const after = (await idp.get('/idp/revocation_state_v2')).body;
    assert.equal(
      after.leaves.length,
      before.leaves.length,
      '만료된 대기 리프가 슬롯을 차지하면 안 된다',
    );
    assert.equal(committed.body.pendingCount, 0, '만료된 대기 항목은 대기열에서도 정리돼야 한다');
    console.log('OK (3): 이미 만료된 대기 리프는 게시되지 않고 대기열에서 정리된다');
  } finally {
    await idp.stop();
  }
}

// ---------------------------------------------------------------------------
// 4. 변경 로그 절단 -> tooOld (test_imt_v2_wiring.js가 SKIP하던 3b 경로).
//
// 로그 상한을 낮춘 인스턴스를 직접 띄워 실제로 절단시킨다. 절단됐는데 조용히 부분
// 결과를 주면 지갑의 트리가 root와 어긋나 모든 증명이 실패한다.
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP({ env: { IDP_MUTATION_LOG_MAX: '2' } });
  try {
    for (let i = 0; i < 4; i++) await revokeAndPublish(idp, uniqueValue());
    const state = (await idp.get('/idp/revocation_state_v2')).body;
    assert.ok(state.seq > 3, `준비: seq가 충분히 진행돼야 한다 (seq ${state.seq})`);

    const stale = (await idp.get('/idp/revocation_state_v2?since=0')).body;
    assert.equal(stale.tooOld, true, '절단된 구간을 요청하면 tooOld로 전체 재조회를 안내해야 한다');
    assert.ok(Array.isArray(stale.mutations) === false, 'tooOld 응답은 부분 mutations를 주면 안 된다');

    const fresh = (await idp.get(`/idp/revocation_state_v2?since=${state.seq}`)).body;
    assert.equal(fresh.tooOld, undefined, '최신 커서는 절단과 무관하다');
    console.log('OK (4): 로그 절단이 tooOld로 드러난다 (wiring 3b SKIP 해소)');
  } finally {
    await idp.stop();
  }
}

// ---------------------------------------------------------------------------
// 5. 재기준화는 미결 prepare를 무효화한다(회귀 방지).
//
// 그대로 두면 뒤늦은 commit이 새 트리에 리프를 삽입하고서야 불일치를 발견해 500을 내고,
// 트리는 되돌릴 수 없게 전진한 채 재시도가 영원히 500이 된다.
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP();
  try {
    await idp.post('/idp/revoke', { type: 'account', value: uniqueValue() });
    const prepared = await idp.post('/idp/publish/prepare');
    assert.equal(prepared.status, 200);

    const rebaselined = await idp.post('/idp/rebaseline_v2');
    assert.equal(rebaselined.status, 200);
    assert.equal(rebaselined.body.discardedPreparedPublish, true, '재기준화는 미결 prepare를 버렸다고 알려야 한다');

    const rootAfterRebaseline = (await idp.get('/idp/revocation_state_v2')).body.root;
    const late = await idp.post('/idp/publish/commit', { root: prepared.body.expectedRoot });
    assert.equal(late.status, 409, '무효가 된 prepare의 commit은 409로 거절돼야 한다');
    assert.equal(
      (await idp.get('/idp/revocation_state_v2')).body.root,
      rootAfterRebaseline,
      '거절된 commit이 트리를 건드리면 안 된다',
    );
    console.log('OK (5): 재기준화가 미결 prepare를 무효화하고, 뒤늦은 commit이 트리를 건드리지 못한다');
  } finally {
    await idp.stop();
  }
}

console.log('PASS: 게시·재기준화·만료 동작 — 소진 시 거부, 회수 시에만 재기준화, 만료 대기 리프 미게시, 절단 신호, prepare 무효화.');
