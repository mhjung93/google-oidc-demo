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
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { leafValue, TAG_ACCOUNT } from '../lib/imt.js';
import { startIsolatedIdP, revokeAndPublish } from './helpers/isolated_idp.mjs';

const RPC = process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';
const CAPACITY = 2 ** 20; // 깊이 20
const CREDENTIAL_LIFETIME_BLOCKS = 300;
// custom_idp.js의 MAX_HEIGHT_SLACK_BLOCKS와 같아야 한다. 계정 폐기 리프의 만료가
// lifetime + slack이므로, 만료를 유발하려면 그만큼 채굴해야 한다.
const MAX_HEIGHT_SLACK_BLOCKS = 32;
const BLOCKS_TO_EXPIRE = CREDENTIAL_LIFETIME_BLOCKS + MAX_HEIGHT_SLACK_BLOCKS + 1;

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
// 1. 회수할 것이 없는데 임계치를 넘으면: 재기준화하지 않고, **거부도 하지 않고**, 경고한다.
//
// 두 가지를 동시에 고정한다.
//  (a) 회수 0인 재기준화를 반복하면 매 회차 epoch가 올라 모든 지갑이 전체 재다운로드를
//      한다 — 회수되는 슬롯은 0인데 증분 설계만 무력화된다. 그러니 재기준화하면 안 된다.
//  (b) 그렇다고 게시를 거부하면 폐기 자체가 멈춘다. 임계치는 위생 경고선이지 실제 한계
//      (2^20)가 아니라 삽입은 여전히 가능하다. 보안 조작을 용량 위생 때문에 막는 것은
//      교환이 맞지 않는다. 대신 capacityExhausted로 크게 알린다.
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
    assert.equal(prepared.status, 200, '임계치를 넘어도 게시를 거부하면 안 된다(폐기가 멈춘다)');
    assert.equal(prepared.body.v2.capacityExhausted, true, '소진 상태를 응답으로 알려야 한다');
    assert.equal(prepared.body.v2.rebaselineForced, false, '회수할 것이 없으면 재기준화하면 안 된다');
    assert.equal(prepared.body.added, 1, '접수된 폐기는 그대로 게시된다');

    const committed = await idp.post('/idp/publish/commit', { root: prepared.body.expectedRoot });
    assert.equal(committed.status, 200);

    const afterState = (await idp.get('/idp/revocation_state_v2')).body;
    assert.equal(afterState.epoch, beforeState.epoch, '회수 0인데 epoch가 오르면 전 지갑이 헛되이 재다운로드한다');
    assert.equal(afterState.leaves.length, beforeState.leaves.length + 1, '폐기 리프는 실제로 들어간다');
    console.log('OK (1): 회수 불가 + 임계치 초과 -> 재기준화 없이 경고하고 게시는 계속한다');
  } finally {
    await idp.stop();
  }
}

// ---------------------------------------------------------------------------
// 1-c. 회수량이 적으면 재기준화하지 않는다 — "만료 리프가 1개라도 있으면 재기준화"는
//      thrash를 못 막는다. 사용률이 임계치 근처인 정상 운영에서 사이클마다 하나씩
//      만료되면 매 게시가 재기준화가 되어, 없애려던 현상이 그대로 재현된다.
//      재기준화는 **회수 후 사용률이 경고선 아래로 내려갈 때만** 할 가치가 있다.
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP({
    env: {
      IDP_REBASELINE_WARN_RATIO: forceRatioForLeaves(2),
      IDP_REBASELINE_FORCE_RATIO: forceRatioForLeaves(4),
    },
  });
  try {
    await revokeAndPublish(idp, uniqueValue()); // used 2 — 이 리프만 만료시킬 것이다
    await rpc('hardhat_mine', [`0x${BLOCKS_TO_EXPIRE.toString(16)}`]);
    await revokeAndPublish(idp, uniqueValue()); // used 3 (방금 폐기라 살아있다)

    const before = (await idp.get('/idp/revocation_state_v2')).body;
    await idp.post('/idp/revoke', { type: 'account', value: uniqueValue() });

    // projected 4 >= FORCE 4. 만료는 1개뿐이라 회수해도 3 > WARN 2 — 헤드룸이 안 생긴다.
    const prepared = await idp.post('/idp/publish/prepare');
    assert.equal(prepared.status, 200);
    assert.equal(prepared.body.expiredPublished, 1, '준비: 회수 가능한 만료 리프가 1개다');
    assert.equal(
      prepared.body.v2.rebaselineForced,
      false,
      '회수해도 경고선 아래로 못 내려가면 재기준화하지 않는다(그러지 않으면 매 회차 반복된다)',
    );
    const committed = await idp.post('/idp/publish/commit', { root: prepared.body.expectedRoot });
    assert.equal(committed.status, 200);
    const after = (await idp.get('/idp/revocation_state_v2')).body;
    assert.equal(after.epoch, before.epoch, '회수량이 적으면 epoch를 올리지 않는다');
    console.log('OK (1-c): 회수량이 헤드룸을 못 만들면 재기준화하지 않는다 (thrash 방지)');
  } finally {
    await idp.stop();
  }
}

// ---------------------------------------------------------------------------
// 1-b. 임계치를 넘긴 상태에서의 no-op 재게시(heartbeat)도 정상 동작해야 한다.
//
// scripts/revocation_sweep.cjs의 데몬 모드는 대기열이 비어도 주기적으로 prepare -> pushRoot
// -> commit을 돈다. prepare가 여기서 실패하면 사이클이 pushRoot 전에 중단돼 root 재게시가
// 통째로 멈춘다. 임계치를 넘긴 상태에서도 이 경로가 살아 있는지 고정한다.
// ---------------------------------------------------------------------------
// 이 상태는 신선한 트리에서는 만들어지지 않는다(used가 임계치에 닿기 전에 멈춘다).
// 도달하는 경로는 **운영자가 임계치를 낮춰 재기동하는 것**이다 — 이미 쌓인 상태가 새
// 임계치를 넘는 상태로 뜬다. 그래서 같은 상태 디렉터리로 두 번 띄운다.
{
  // 두 인스턴스가 같은 상태를 쓰도록 디렉터리를 테스트가 소유한다(하네스가 만든
  // 디렉터리는 그 인스턴스의 stop()이 지운다).
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'idp-behavior-'));
  try {
    const first = await startIsolatedIdP({
      dir: stateDir,
      env: { IDP_REBASELINE_FORCE_RATIO: forceRatioForLeaves(4) },
    });
    // 여기서 던지면 first가 살아남아 포트를 물고, 바깥 finally가 그 인스턴스의 상태
    // 디렉터리를 지워 버린다. 반드시 감싼다.
    try {
      await revokeAndPublish(first, uniqueValue());
      await revokeAndPublish(first, uniqueValue()); // used: anchor+2 = 3 (임계치 4 미만)
    } finally {
      await first.stop();
    }

    // 임계치를 3으로 낮춰 재기동 — 기존 used 3이 곧바로 임계치에 걸린다.
    const idp = await startIsolatedIdP({
      dir: stateDir,
      env: { IDP_REBASELINE_FORCE_RATIO: forceRatioForLeaves(3) },
    });
    try {
      const before = (await idp.get('/idp/revocation_state_v2')).body;
      const prepared = await idp.post('/idp/publish/prepare'); // 대기열이 비어 있다
      assert.equal(prepared.status, 200, '넣을 리프가 없는 재게시는 임계치와 무관하게 통과해야 한다');
      assert.equal(prepared.body.added, 0);
      assert.equal(prepared.body.expectedRoot, before.root, 'no-op 재게시는 root를 바꾸지 않는다');

      const committed = await idp.post('/idp/publish/commit', { root: prepared.body.expectedRoot });
      assert.equal(committed.status, 200);
      const after = (await idp.get('/idp/revocation_state_v2')).body;
      assert.equal(after.epoch, before.epoch, 'no-op 재게시가 epoch를 올리면 안 된다');
      console.log('OK (1-b): 넣을 것이 없는 재게시(heartbeat)는 소진 임계치에 막히지 않는다');
    } finally {
      await idp.stop();
    }
  } finally {
    fs.rmSync(stateDir, { recursive: true, force: true });
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
    await rpc('hardhat_mine', [`0x${BLOCKS_TO_EXPIRE.toString(16)}`]);

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
// 3. 접수된 폐기는 게시가 늦어도 사라지지 않는다.
//
// "이미 만료된 대기 리프는 슬롯만 먹으니 게시하지 말자"는 최적화는 **계정 폐기에서
// 건전하지 않다.** 계정 폐기의 만료는 접수 시점 + CREDENTIAL_LIFETIME_BLOCKS로 고정되고
// (세션 폐기와 달리 실제 크레덴셜의 max_height가 아니다), 계정 폐기는 disabled를 세우지
// 않으므로 그 계정은 재로그인해 **더 늦은 max_height**를 가진 크레덴셜을 받을 수 있다.
// 게시가 지연돼 접수 리프가 "만료"로 판정돼 버려지면, 그 늦은 크레덴셜을 막을 것이
// 아무것도 남지 않는다 — 폐기가 조용히 사라지는 방향의 실패다.
//
// 슬롯 낭비는 재기준화가 회수한다. 회수 가능한 낭비와 놓친 폐기는 교환 대상이 아니다.
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP();
  try {
    const before = (await idp.get('/idp/revocation_state_v2')).body;
    const staleValue = uniqueValue();
    const queued = await idp.post('/idp/revoke', { type: 'account', value: staleValue });
    assert.equal(queued.status, 200);

    // 게시가 지연되는 동안 접수 리프의 명목 만료가 지나간다.
    await rpc('hardhat_mine', [`0x${BLOCKS_TO_EXPIRE.toString(16)}`]);

    const prepared = await idp.post('/idp/publish/prepare');
    assert.equal(prepared.status, 200);
    assert.equal(prepared.body.added, 1, '접수된 폐기는 게시가 늦어도 게시 대상에서 빠지면 안 된다');
    const committed = await idp.post('/idp/publish/commit', { root: prepared.body.expectedRoot });
    assert.equal(committed.status, 200);

    const after = (await idp.get('/idp/revocation_state_v2')).body;
    assert.equal(
      after.leaves.length,
      before.leaves.length + 1,
      '접수된 폐기 리프가 트리에 실제로 들어가야 한다',
    );
    assert.equal(committed.body.pendingCount, 0, '게시된 항목은 대기열에서 정리된다');
    console.log('OK (3): 접수된 폐기는 게시가 지연돼도 사라지지 않고 트리에 들어간다');
  } finally {
    await idp.stop();
  }
}

// ---------------------------------------------------------------------------
// 3-b. **재기준화 회차에서도** 접수된 폐기는 사라지지 않는다.
//
// 케이스 3은 일반 append 회차만 본다. 재기준화 회차는 "살아있는 값만으로 다시 쌓는"
// 경로라, 거기서 만료 필터를 접수 리프에까지 적용하면 같은 폐기 소실이 재현된다 —
// 트리에 한 번도 안 들어가고 commit의 대기열 정리가 지워 버린다. 회수 대상은 **이미
// 게시된** 만료 리프뿐이어야 한다.
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP({ env: { IDP_REBASELINE_FORCE_RATIO: forceRatioForLeaves(4) } });
  try {
    await revokeAndPublish(idp, uniqueValue()); // used 2
    await revokeAndPublish(idp, uniqueValue()); // used 3
    await rpc('hardhat_mine', [`0x${BLOCKS_TO_EXPIRE.toString(16)}`]); // 둘 다 만료

    // 접수한 뒤 게시 전에 이 리프까지 만료시킨다(게시 지연 상황).
    const delayed = uniqueValue();
    assert.equal((await idp.post('/idp/revoke', { type: 'account', value: delayed })).status, 200);
    await rpc('hardhat_mine', [`0x${BLOCKS_TO_EXPIRE.toString(16)}`]);
    const delayedLeaf = (await leafValue(TAG_ACCOUNT, delayed)).toString();

    const prepared = await idp.post('/idp/publish/prepare');
    assert.equal(prepared.status, 200);
    assert.equal(prepared.body.v2.rebaselineForced, true, '준비: 이번 회차는 재기준화여야 한다');
    const committed = await idp.post('/idp/publish/commit', { root: prepared.body.expectedRoot });
    assert.equal(committed.status, 200);

    const after = (await idp.get('/idp/revocation_state_v2')).body;
    const members = after.leaves.slice(1).map((l) => l.value);
    assert.ok(
      members.includes(delayedLeaf),
      '재기준화 회차에서도 접수된 폐기는 트리에 들어가야 한다(게시 지연으로 사라지면 안 된다)',
    );
    assert.equal(committed.body.pendingCount, 0, '게시됐으므로 대기열은 비어야 한다');
    console.log('OK (3-b): 재기준화 회차에서도 접수된 폐기가 보존된다');
  } finally {
    await idp.stop();
  }
}

// ---------------------------------------------------------------------------
// 3-c. 실제 한계 근처에서는 회수량이 적어도 재기준화한다.
//
// "회수 후 경고선 아래로" 조건만 두면, 만료분이 (1-WARN)×capacity에 못 미치는 동안
// 재기준화를 영영 안 하고 append만 하다가 트리가 꽉 차 insert()가 던진다 — 폐기 게시가
// 통째로 멈춘다. 한계 근처에서는 전 지갑 재다운로드가 게시 정지보다 낫다.
// ---------------------------------------------------------------------------
{
  const CAP = CAPACITY;
  const idp = await startIsolatedIdP({
    env: {
      IDP_REBASELINE_WARN_RATIO: forceRatioForLeaves(2), // 회수해도 경고선 아래로 못 감
      IDP_REBASELINE_FORCE_RATIO: forceRatioForLeaves(4),
      IDP_HARD_LIMIT_MARGIN: String(CAP - 4), // projectedUsed >= 4 면 '한계 근처'로 본다
    },
  });
  try {
    await revokeAndPublish(idp, uniqueValue()); // used 2 — 이것만 만료시킨다
    await rpc('hardhat_mine', [`0x${BLOCKS_TO_EXPIRE.toString(16)}`]);
    await revokeAndPublish(idp, uniqueValue()); // used 3 (살아있음)

    const before = (await idp.get('/idp/revocation_state_v2')).body;
    await idp.post('/idp/revoke', { type: 'account', value: uniqueValue() });

    const prepared = await idp.post('/idp/publish/prepare');
    assert.equal(prepared.status, 200);
    assert.equal(
      prepared.body.v2.rebaselineForced,
      true,
      '한계 근처에서는 회수량이 적어도 재기준화해야 한다(안 그러면 트리가 꽉 차 게시가 멈춘다)',
    );
    const committed = await idp.post('/idp/publish/commit', { root: prepared.body.expectedRoot });
    assert.equal(committed.status, 200);
    const after = (await idp.get('/idp/revocation_state_v2')).body;
    assert.equal(after.epoch, before.epoch + 1, '재기준화했으므로 epoch가 오른다');
    console.log('OK (3-c): 실제 한계 근처에서는 회수량이 적어도 재기준화한다');
  } finally {
    await idp.stop();
  }
}

// ---------------------------------------------------------------------------
// 3-d. 이미 게시됐지만 만료된 리프를 **재폐기**하면, 그 재폐기가 재기준화에 먹히면 안 된다.
//
// /idp/revoke는 이미 게시된 리프면 대기열에 넣지 않고 만료만 연장한다. 그런데 prepare가
// 그 리프를 "만료"로 보고 재기준화 집합에서 빼 둔 뒤에 재폐기가 들어오면, commit이 동결된
// 집합으로 재기준화하면서 리프를 지운다 — 방금 접수한 재폐기가 트리에서 사라지고 만료
// 메타데이터 고아 정리까지 흔적을 지운다. 재폐기는 200을 받았는데 아무 효과가 없다.
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP({ env: { IDP_REBASELINE_FORCE_RATIO: forceRatioForLeaves(4) } });
  try {
    const victim = uniqueValue();
    const victimLeaf = (await leafValue(TAG_ACCOUNT, victim)).toString();
    await revokeAndPublish(idp, victim); // used 2
    await revokeAndPublish(idp, uniqueValue()); // used 3
    await rpc('hardhat_mine', [`0x${BLOCKS_TO_EXPIRE.toString(16)}`]); // 둘 다 만료

    // 재기준화 회차를 만든다(projected 4 >= 임계치 4).
    await idp.post('/idp/revoke', { type: 'account', value: uniqueValue() });
    const prepared = await idp.post('/idp/publish/prepare');
    assert.equal(prepared.status, 200);
    assert.equal(prepared.body.v2.rebaselineForced, true, '준비: 이번 회차는 재기준화여야 한다');

    // prepare와 commit 사이에 victim을 **재폐기**한다(운영자가 push를 기다리는 동안).
    const rerevoked = await idp.post('/idp/revoke', { type: 'account', value: victim });
    assert.equal(rerevoked.status, 200, '재폐기는 접수돼야 한다');

    const committed = await idp.post('/idp/publish/commit', { root: prepared.body.expectedRoot });
    assert.equal(committed.status, 200);

    // 이 회차에서 빠지는 것 자체는 정상(집합이 동결됐다). 하지만 **다음 회차에 반드시
    // 다시 들어가야 한다** — 재폐기가 조용히 사라지면 안 된다.
    const afterRebaseline = (await idp.get('/idp/revocation_state_v2')).body;
    const next = await idp.post('/idp/publish/prepare');
    assert.equal(next.status, 200);
    const nextCommitted = await idp.post('/idp/publish/commit', { root: next.body.expectedRoot });
    assert.equal(nextCommitted.status, 200);

    const final = (await idp.get('/idp/revocation_state_v2')).body;
    const members = final.leaves.slice(1).map((l) => l.value);
    assert.ok(
      members.includes(victimLeaf),
      `재폐기된 계정은 다음 게시에서 반드시 트리에 있어야 한다 ` +
        `(재기준화 직후 ${afterRebaseline.leaves.length}개 -> 최종 ${final.leaves.length}개)`,
    );
    console.log('OK (3-d): 게시·만료된 리프의 재폐기가 재기준화에 먹히지 않는다');
  } finally {
    await idp.stop();
  }
}

// ---------------------------------------------------------------------------
// 3-e. 계정 폐기 리프의 만료는 max_height 상한의 **여유(slack)까지** 덮어야 한다.
//
// IdP는 max_height <= currentBlock + CREDENTIAL_LIFETIME_BLOCKS + MAX_HEIGHT_SLACK_BLOCKS를
// 허용한다(지갑이 값을 계산한 시점과 IdP가 블록을 읽는 시점의 간격 흡수). 그런데 계정
// 폐기 리프의 만료가 여유 없이 +CREDENTIAL_LIFETIME_BLOCKS라면, 그 차이만큼 구간이 열린다:
// 리프는 만료로 회수되는데 크레덴셜은 아직 살아 있어 계정 비멤버십을 다시 통과한다.
// 상한을 넓힌 것과 같은 폭만큼 폐기 창도 넓혀야 한다.
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP();
  try {
    const before = BigInt(await rpc('eth_blockNumber', []));
    const revoked = await idp.post('/idp/revoke', { type: 'account', value: uniqueValue() });
    assert.equal(revoked.status, 200);
    const expiry = BigInt(revoked.body.expiryBlock);
    const lifetime = BigInt(CREDENTIAL_LIFETIME_BLOCKS);
    const slack = BigInt(MAX_HEIGHT_SLACK_BLOCKS);
    assert.ok(
      expiry >= before + lifetime + slack,
      `계정 폐기 리프의 만료가 max_height 상한을 덮지 못한다 ` +
        `(블록 ${before}, 만료 ${expiry}, 필요 최소 ${before + lifetime + slack})`,
    );
    console.log(`OK (3-e): 폐기 리프 만료가 max_height 상한의 여유까지 덮는다 (${expiry} >= ${before + lifetime + slack})`);
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

console.log('PASS: 게시·재기준화·만료 동작 — 소진 시 경고하되 게시는 계속, 헤드룸을 되찾을 때만 재기준화, 접수된 폐기 보존, 절단 신호, prepare 무효화.');
