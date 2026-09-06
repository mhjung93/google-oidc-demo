// 게시(prepare/commit)·만료 회수의 **동작** 테스트.
//   node tests/test_idp_publish_behavior.mjs
//
// tests/helpers/isolated_idp.mjs로 매 케이스마다 격리된 IdP를 띄운다 — 개발자가 띄워 둔
// :4000 인스턴스와 그 폐기 트리는 건드리지 않으며, 관리자 시크릿도 테스트가 스스로 만든다.
// 그래서 여기서는 **실패 경로를 실제로 돌릴 수 있다**(소스 텍스트 검사가 아니다).
//
// 전제: hardhat 노드(ETH_RPC_URL, 기본 127.0.0.1:8545). IdP가 블록 높이를 읽는다.
// 주의: 만료를 확인하는 케이스는 그 체인의 블록을 CREDENTIAL_LIFETIME_BLOCKS(300)만큼
// 진행시킨다. 데모 체인에서는 무해하다(tests/test_mode2_e2e_onchain.js도 매 실행마다
// 블록을 진행시킨다).
//
// == 13.1에서 사라진 케이스들 ==
// 이 파일은 원래 v2의 전역 용량 임계치(80%/95%)·강제 재기준화·epoch 상승·변경 로그
// 절단(tooOld)·"재기준화가 미결 prepare의 예측 root를 무효화한다"를 고정했다. v2를
// 걷어내면서 그 기계가 전부 사라졌다(설계 문서 13.1절):
//   - 전역 용량이 없다. 샤드마다 독립적인 작은 트리(256/1,024리프)라 "트리가 몇 % 찼는가"
//     라는 질문 자체가 성립하지 않는다.
//   - 전 지갑 재다운로드를 부르는 전역 재기준화가 없다. 세션 층은 샤드 리셋, 계정 층은
//     샤드 단위 재기준화로 회수한다 — 둘 다 그 샤드를 쓰는 지갑에만 영향이 있다.
//   - 증분 동기화가 없으니 epoch·seq·변경 로그·tooOld도 없다.
//   - prepare가 root를 예측하지 않으니 그 예측을 무효화할 일도 없다.
// 그 케이스들을 v3로 "옮길" 수는 없다 — 대응물이 없기 때문이다. 대신 그 자리를 물려받은
// 성질(만료 회수, 회차 토큰)을 아래 4·5번이 고정한다.
import assert from 'node:assert/strict';
import { leafValue, TAG_ACCOUNT } from '../lib/imt.js';
import { accountShardOf } from '../lib/imt_v3.js';
import { startIsolatedIdP, revokeAndPublish } from './helpers/isolated_idp.mjs';

const RPC = process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';
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

const uniqueValue = () => `${Date.now()}${Math.floor(Math.random() * 1e6)}`;

/** 계정 값 하나의 리프와 그 샤드. */
async function acctLeafOf(value) {
  const leaf = (await leafValue(TAG_ACCOUNT, value)).toString();
  return { leaf, shard: accountShardOf(leaf) };
}

/** 그 리프가 지금 게시된 트리 안에 있는가. */
async function isPublished(idp, value) {
  const { leaf, shard } = await acctLeafOf(value);
  const res = await idp.get(`/idp/revocation_state_v3?accountShard=${shard}`);
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return (res.body.accountShardLeaves ?? []).includes(leaf);
}

/** 게시된 리프 총 개수. prepare가 부수효과 없이 알려준다. */
async function publishedCount(idp) {
  const p = await idp.get('/idp/revocation_state_v3');
  assert.equal(p.status, 200);
  // 샤드별 리프를 세려면 샤드마다 물어야 하므로, 총계는 prepare의 leafCount를 쓴다.
  // prepare는 게시 상태를 바꾸지 않는다(회차 토큰만 새로 발급된다).
  const prepared = await idp.post('/idp/publish/prepare');
  assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
  return prepared.body.leafCount;
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
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP();
  try {
    const staleValue = uniqueValue();
    const queued = await idp.post('/idp/revoke', { type: 'account', value: staleValue });
    assert.equal(queued.status, 200);

    // 게시가 지연되는 동안 접수 리프의 명목 만료가 지나간다.
    await rpc('hardhat_mine', [`0x${BLOCKS_TO_EXPIRE.toString(16)}`]);

    const prepared = await idp.post('/idp/publish/prepare');
    assert.equal(prepared.status, 200);
    assert.equal(prepared.body.added, 1, '접수된 폐기는 게시가 늦어도 게시 대상에서 빠지면 안 된다');
    const committed = await idp.post('/idp/publish/commit', { roundToken: prepared.body.roundToken });
    assert.equal(committed.status, 200, JSON.stringify(committed.body));

    assert.ok(await isPublished(idp, staleValue), '접수된 폐기 리프가 트리에 실제로 들어가야 한다');
    assert.equal(committed.body.pendingCount, 0, '게시된 항목은 대기열에서 정리된다');
    console.log('OK (3): 접수된 폐기는 게시가 지연돼도 사라지지 않고 트리에 들어간다');
  } finally {
    await idp.stop();
  }
}

// ---------------------------------------------------------------------------
// 3-d. 이미 게시됐지만 만료된 리프를 **재폐기**하면, 그 재폐기가 회수에 먹히면 안 된다.
//
// 시나리오: prepare가 회차를 동결한 뒤 commit 전에 재폐기가 들어온다. 그 회차의 commit은
// 만료 회수를 수행하는데, 재폐기가 만료를 미래로 연장했으므로 이 리프는 회수 대상이 아니다.
// 리프가 트리에 그대로 남은 채 만료만 연장되는 것이 올바른 최종 상태다.
//
// 대조군을 함께 둔다: 재폐기하지 **않은** 만료 리프는 실제로 회수돼야 한다. 그게 없으면
// "남아 있다"가 단지 회수가 고장났다는 뜻일 수도 있어 테스트가 무의미해진다.
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP();
  try {
    const victim = uniqueValue();   // 재폐기할 대상
    const control = uniqueValue();  // 그대로 두어 회수돼야 할 대조군
    await revokeAndPublish(idp, victim);
    await revokeAndPublish(idp, control);
    assert.ok(await isPublished(idp, victim));
    assert.ok(await isPublished(idp, control));

    await rpc('hardhat_mine', [`0x${BLOCKS_TO_EXPIRE.toString(16)}`]); // 둘 다 만료

    const prepared = await idp.post('/idp/publish/prepare');
    assert.equal(prepared.status, 200);
    assert.equal(prepared.body.expiredPublished, 2, '게시된 두 리프가 모두 만료로 보여야 한다');

    // prepare와 commit 사이에 victim을 **재폐기**한다(운영자가 다음 단계를 밟는 동안).
    const rerevoked = await idp.post('/idp/revoke', { type: 'account', value: victim });
    assert.equal(rerevoked.status, 200, '재폐기는 접수돼야 한다');
    assert.equal(rerevoked.body.alreadyPublished, true);

    const committed = await idp.post('/idp/publish/commit', { roundToken: prepared.body.roundToken });
    assert.equal(committed.status, 200, JSON.stringify(committed.body));

    assert.ok(
      await isPublished(idp, victim),
      '재폐기로 만료가 연장된 리프가 회수돼 버렸다 — 방금 접수한 폐기가 사라진다',
    );
    assert.ok(
      !(await isPublished(idp, control)),
      '만료된 대조군이 회수되지 않았다 — 회수 자체가 동작하지 않으면 위 단언이 무의미하다',
    );

    // 다음 회차에서도 그대로 남아 있어야 한다(한 회차만 버티는 것이 아니다).
    const next = await idp.post('/idp/publish/prepare');
    const nextCommitted = await idp.post('/idp/publish/commit', { roundToken: next.body.roundToken });
    assert.equal(nextCommitted.status, 200, JSON.stringify(nextCommitted.body));
    assert.ok(await isPublished(idp, victim), '다음 회차에서 재폐기된 리프가 사라졌다');

    console.log('OK (3-d): 게시·만료된 리프의 재폐기가 만료 회수에 먹히지 않는다 (대조군은 회수된다)');
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
// 4. 회차 합의는 회차 토큰으로 이뤄진다 (13.1에서 root 예측을 대체했다).
//
// 이 가드가 없으면 운영자가 A 회차를 push한다고 믿는 동안 B 회차가 반영된다. 게시 순서가
// prepare -> commit -> push라 commit이 돌려주는 root가 곧 push 대상이므로, 회차가 어긋나면
// 온체인 root와 IdP 상태가 갈라진다.
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP();
  try {
    // (a) prepare 없이 commit -> 409
    const noPrepare = await idp.post('/idp/publish/commit', { roundToken: 'deadbeef' });
    assert.equal(noPrepare.status, 409, JSON.stringify(noPrepare.body));

    // (b) 토큰 없이 commit -> 400 (형식 오류이지 회차 충돌이 아니다)
    await idp.post('/idp/revoke', { type: 'account', value: uniqueValue() });
    const p1 = await idp.post('/idp/publish/prepare');
    assert.equal(p1.status, 200);
    assert.ok(p1.body.roundToken, 'prepare가 회차 토큰을 주지 않았다');
    assert.equal(p1.body.expectedRoot, undefined, 'prepare가 root를 예측하면 안 된다');
    const noToken = await idp.post('/idp/publish/commit', {});
    assert.equal(noToken.status, 400, JSON.stringify(noToken.body));

    // (c) 다른 회차의 토큰 -> 409. prepare를 다시 부르면 옛 토큰은 무효가 된다.
    const p2 = await idp.post('/idp/publish/prepare');
    assert.notEqual(p2.body.roundToken, p1.body.roundToken, '회차 토큰이 재사용됐다');
    const stale = await idp.post('/idp/publish/commit', { roundToken: p1.body.roundToken });
    assert.equal(stale.status, 409, JSON.stringify(stale.body));

    // (d) 맞는 토큰은 통과하고, 같은 토큰의 재사용은 409다(회차는 한 번만 소비된다).
    const ok = await idp.post('/idp/publish/commit', { roundToken: p2.body.roundToken });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.match(String(ok.body.root), /^0x[0-9a-f]{64}$/, 'commit이 push할 bytes32 root를 돌려줘야 한다');
    const replay = await idp.post('/idp/publish/commit', { roundToken: p2.body.roundToken });
    assert.equal(replay.status, 409, JSON.stringify(replay.body));

    console.log('OK (4): 회차 토큰이 회차를 고정하고, 어긋난/재사용된 토큰은 409로 막힌다');
  } finally {
    await idp.stop();
  }
}

// ---------------------------------------------------------------------------
// 5. 만료 회수가 실제로 슬롯을 되찾는다.
//
// v2에서 이 자리는 "전역 재기준화가 임계치를 넘었을 때만 일어난다"였다. v3에서는 회수가
// 임계치와 무관하게 **매 회차** 일어나고, 전 지갑 재다운로드를 부르지 않는다. 그래서
// 고정할 것이 달라졌다: 만료된 것은 회수되고, 만료되지 않은 것은 그대로 남는가.
// ---------------------------------------------------------------------------
{
  const idp = await startIsolatedIdP();
  try {
    const old1 = uniqueValue();
    const old2 = uniqueValue();
    await revokeAndPublish(idp, old1);
    await revokeAndPublish(idp, old2);
    assert.equal(await publishedCount(idp), 2);

    await rpc('hardhat_mine', [`0x${BLOCKS_TO_EXPIRE.toString(16)}`]);

    // 아직 회수되지 않았다 — 회수는 commit에서 일어난다.
    const beforeCommit = await idp.post('/idp/publish/prepare');
    assert.equal(beforeCommit.body.leafCount, 2, '회수는 commit 시점에 일어나야 한다');
    assert.equal(beforeCommit.body.expiredPublished, 2);

    // 만료되지 않은 새 폐기를 같은 회차에 섞는다 — 회수가 이것까지 쓸어가면 안 된다.
    const fresh = uniqueValue();
    await idp.post('/idp/revoke', { type: 'account', value: fresh });
    const p = await idp.post('/idp/publish/prepare');
    const c = await idp.post('/idp/publish/commit', { roundToken: p.body.roundToken });
    assert.equal(c.status, 200, JSON.stringify(c.body));

    assert.ok(!(await isPublished(idp, old1)), '만료된 리프가 회수되지 않았다');
    assert.ok(!(await isPublished(idp, old2)), '만료된 리프가 회수되지 않았다');
    assert.ok(await isPublished(idp, fresh), '만료되지 않은 새 폐기가 회수에 함께 쓸려갔다');
    assert.equal(c.body.leafCount, 1, `회수 후 리프가 1개여야 한다 (실제 ${c.body.leafCount})`);

    console.log('OK (5): 만료 회수가 만료분만 되찾고 살아있는 폐기는 남긴다');
  } finally {
    await idp.stop();
  }
}

console.log('\n== 게시 동작 5종 통과 ==');
