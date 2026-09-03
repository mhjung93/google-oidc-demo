// 정석 IMT(v2) 배선 단위 테스트 — 살아있는 IdP(:4000)의 v2 대역을 검증한다.
// Stage B: v2가 회로에 배선되고 v1이 제거됐다. 이 테스트는 IdP의 v2 조회 엔드포인트와
// 지갑의 증분 적용 규칙만 본다(회로/온체인은 다른 테스트가 덮는다).
//
//   IDP_ADMIN_SECRET=<value> node tests/test_imt_v2_wiring.js
//   (secret은 실행 중인 custom_idp.js와 같은 값이어야 한다)
//
// 검증 항목:
//  1) v2 자체 정합성 — 전체 조회 재구성이 IdP root와 일치하고 멤버십 판정이 올바른가
//     (v1이 제거돼 "v1과 같은 판정"은 성립하지 않으므로 v2 단독 정합성으로 재정의)
//  2) 증분 조회가 서로 다른 since로 물어도 올바르게 따라잡는가(여러 클라이언트)
//  3) epoch 불일치 / 로그 절단에서 tooOld로 전체 재조회를 안내하는가
//  4) 재기준화가 epoch를 올리고 로그를 비우며 살아있는 멤버 집합을 보존하는가
import assert from 'node:assert/strict';
import { leafValue, TAG_ACCOUNT } from '../lib/imt.js';
import { buildIMTv2 } from '../lib/imt_v2.js';

const BASE = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';
const ADMIN_SECRET = process.env.IDP_ADMIN_SECRET;
if (!ADMIN_SECRET) {
  console.error('IDP_ADMIN_SECRET is required (must match the running custom_idp.js).');
  process.exit(1);
}
const adminHeaders = { 'Content-Type': 'application/json', 'X-IdP-Admin-Secret': ADMIN_SECRET };
const DEPTH = 20;

const getJSON = async (url) => {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} -> ${r.status}`);
  return r.json();
};

// 지갑이 하는 것과 동일한 증분 적용: append 항목(index === 현재 크기)의 값을 insert한다.
// low 갱신 항목은 insert가 처리하므로 건너뛴다(설계 문서 3.1/3.4절, wallet_agent.js와 동일).
async function applyMutations(tree, mutations) {
  for (const m of mutations) {
    if (m.index === tree.size()) await tree.insert(BigInt(m.leaf.value));
  }
}
const buildFromFull = (body) => buildIMTv2(DEPTH, body.leaves.slice(1).map((l) => BigInt(l.value)));

async function revokeAccount(value) {
  const r = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST', headers: adminHeaders, body: JSON.stringify({ type: 'account', value }),
  });
  assert.equal(r.status, 200, `revoke ${value} must succeed`);
}
async function publish() {
  const prepared = await (await fetch(`${BASE}/idp/publish/prepare`, { method: 'POST', headers: adminHeaders, body: '{}' })).json();
  const commit = await fetch(`${BASE}/idp/publish/commit`, {
    method: 'POST', headers: adminHeaders, body: JSON.stringify({ root: prepared.expectedRoot }),
  });
  assert.equal(commit.status, 200, 'commit must succeed');
  return prepared;
}

async function main() {
  // === 1) v2 자체 정합성 — 게시된 폐기 집합의 멤버십 판정 ==================
  // 새 계정을 폐기·게시한 뒤, 지갑이 하듯 v2 전체 조회의 물리 순서 리프로 트리를
  // 재구성해 root가 IdP와 일치하고 멤버십 판정이 올바른지 본다.
  const victim = `55501${Date.now()}`;
  const victimLeaf = (await leafValue(TAG_ACCOUNT, victim)).toString();
  await revokeAccount(victim);
  await publish();

  const v2full = await getJSON(`${BASE}/idp/revocation_state_v2`);
  const v2tree = await buildFromFull(v2full);
  assert.equal(v2tree.getRoot().toString(), v2full.root, 'local v2 tree must match IdP v2 root (full fetch, physical order)');

  const publishedValues = v2full.leaves.slice(1).map((l) => l.value);
  // 방금 폐기한 리프는 멤버여야 한다.
  assert.ok(publishedValues.includes(victimLeaf), 'the freshly revoked leaf must be published in v2');
  assert.equal(v2tree.has(BigInt(victimLeaf)), true, 'v2 must contain the freshly revoked leaf');
  // 게시된 모든 리프는 멤버여야 한다(비멤버십 witness 거부).
  for (const l of publishedValues) {
    assert.equal(v2tree.has(BigInt(l)), true, `every published leaf must be a v2 member (${l})`);
    await assert.rejects(() => v2tree.getNonMembershipWitness(BigInt(l)), /is a member/);
  }
  // 한 번도 폐기된 적 없는 값은 비멤버(witness 획득 가능)여야 한다.
  const fresh = await leafValue(TAG_ACCOUNT, `9990001${Date.now()}`);
  await v2tree.getNonMembershipWitness(fresh);
  console.log('OK (1): v2 self-consistency — full rebuild matches IdP root; members and non-members judged correctly');

  // === 2) 여러 클라이언트가 서로 다른 since로 증분 동기화 ================
  // 주의: seq는 "빈 트리부터의 오프셋"이 아니다. seq=0 시점의 트리는 대량 구축된
  // base(마이그레이션/재기준화 결과)이고, 그 base는 변경 로그에 없다. 그래서 신규
  // 지갑은 반드시 **전체 조회를 먼저** 해서 base를 잡은 뒤 증분으로 따라잡아야 한다
  // (wallet_agent.js가 v2RevTree===null이면 전체 조회 경로를 타는 이유). 여기서는
  // 서로 다른 시점에 base를 잡은 두 클라이언트가 각자 증분으로 현재까지 따라잡는지 본다.

  // 클라이언트 A: 이른 시점(cursor c0)에 전체를 받아 둔다.
  const snap0 = await getJSON(`${BASE}/idp/revocation_state_v2`);
  const treeA = await buildFromFull(snap0);

  await revokeAccount(`5550201${Date.now()}`);
  await publish();

  // 클라이언트 B: 그보다 늦은 시점(cursor c1)에 전체를 받아 둔다.
  const snap1 = await getJSON(`${BASE}/idp/revocation_state_v2`);
  const treeB = await buildFromFull(snap1);
  assert.ok(snap1.seq > snap0.seq, 'a publish must advance seq (distinct cursors)');

  await revokeAccount(`5550202${Date.now()}`);
  await publish();

  // A(옛 커서)와 B(늦은 커서)가 각자 자기 since로 증분만 받아 따라잡는다.
  const incA = await getJSON(`${BASE}/idp/revocation_state_v2?since=${snap0.seq}&epoch=${snap0.epoch}`);
  assert.ok(!incA.tooOld, 'A incremental must not be tooOld (same epoch, within log)');
  assert.ok(incA.mutations.length >= 4, 'two publishes of one new leaf each -> >=4 mutation entries for A');
  await applyMutations(treeA, incA.mutations);

  const incB = await getJSON(`${BASE}/idp/revocation_state_v2?since=${snap1.seq}&epoch=${snap1.epoch}`);
  assert.ok(!incB.tooOld, 'B incremental must not be tooOld');
  assert.ok(incB.mutations.length >= 2, 'one publish after B -> >=2 mutation entries for B');
  await applyMutations(treeB, incB.mutations);

  // 클라이언트 C: 지금 막 접속한 지갑 — 전체를 받는다.
  const snapNow = await getJSON(`${BASE}/idp/revocation_state_v2`);
  const treeC = await buildFromFull(snapNow);

  // 세 클라이언트가 모두 같은 최종 root로 수렴해야 한다.
  assert.equal(incA.root, snapNow.root, 'A incremental response root must equal the current IdP root');
  assert.equal(incB.root, snapNow.root, 'B incremental response root must equal the current IdP root');
  assert.equal(treeA.getRoot().toString(), snapNow.root, 'A (early cursor + incremental) must converge');
  assert.equal(treeB.getRoot().toString(), snapNow.root, 'B (later cursor + incremental) must converge');
  assert.equal(treeC.getRoot().toString(), snapNow.root, 'C (fresh full fetch) must equal the current IdP root');
  console.log('OK (2): clients at different cursors converge to the same root via incremental catch-up');

  // === 3) tooOld — epoch 불일치 / 로그 절단 ==============================
  const mismatch = await getJSON(`${BASE}/idp/revocation_state_v2?since=0&epoch=999999`);
  assert.equal(mismatch.tooOld, true, 'an epoch mismatch must return tooOld (full fetch required)');
  console.log('OK (3a): epoch mismatch -> tooOld');

  // 로그 절단 tooOld는 서버가 작은 상한으로 떠 있을 때만 강제할 수 있다. 상한 값을
  // 테스트와 서버가 공유하는 IDP_MUTATION_LOG_MAX로 알려주면 그 경로도 확인한다.
  const cap = Number(process.env.IDP_MUTATION_LOG_MAX);
  if (Number.isInteger(cap) && cap > 0 && cap <= 64) {
    // 상한을 넘길 만큼 게시를 반복한 뒤 since=0을 요청하면 절단으로 tooOld여야 한다.
    const needed = cap + 4;
    for (let i = 0; i * 2 <= needed; i++) { await revokeAccount(`55503${i}${Date.now()}`); await publish(); }
    const truncated = await getJSON(`${BASE}/idp/revocation_state_v2?since=0&epoch=${(await getJSON(`${BASE}/idp/revocation_state_v2`)).epoch}`);
    assert.equal(truncated.tooOld, true, 'a since older than the truncated log must return tooOld');
    console.log(`OK (3b): log truncation (cap=${cap}) -> tooOld for an old since`);
  } else {
    // 이 파일은 개발자가 띄워 둔 IdP를 상대로 돌기 때문에 로그 상한을 바꿀 수 없다.
    // 절단 경로는 tests/test_idp_publish_behavior.mjs가 상한을 낮춘 **격리 인스턴스**를
    // 직접 띄워 검증한다 — 여기서 건너뛴다고 미검증 상태인 것은 아니다.
    console.log(
      'SKIP (3b): 절단 경로는 tests/test_idp_publish_behavior.mjs(격리 IdP)가 검증한다. ' +
        '이 파일에서 함께 보려면 IDP_MUTATION_LOG_MAX<=64로 서버를 띄워야 한다',
    );
  }

  // === 4) 재기준화 — epoch↑, 로그 비움, 살아있는 멤버 보존 =================
  // v1이 제거돼 rebaseline은 이제 게시된 v2 root를 정당하게 바꾼다(물리 순서 정렬 +
  // 만료 회수). 따라서 "게시 root 불변"은 성립하지 않는다 — 대신 epoch↑, seq 0,
  // 살아있는 멤버 전원 보존, 재기준화 전 epoch 클라이언트의 tooOld를 본다.
  // 갓 폐기·게시한 리프를 하나 심어 둔다. 만료까지 CREDENTIAL_LIFETIME_BLOCKS가 남아
  // 있으므로 재기준화가 **반드시** 보존해야 한다.
  //
  // 예전에는 "게시된 리프 전부가 보존된다"로 단언했는데, 재기준화는 만료 리프를 정당하게
  // 회수하므로(바로 위 주석이 말하는 그 동작) 체인이 충분히 진행된 환경에서는 틀린 단언이다.
  // 실제로 블록이 600 넘게 진행된 뒤 이 단언이 깨졌다. 살아있는 리프의 보존과 "없던 리프가
  // 생기지 않음"으로 나눠서 본다.
  const survivor = `5550401${Date.now()}`;
  const survivorLeaf = (await leafValue(TAG_ACCOUNT, survivor)).toString();
  await revokeAccount(survivor);
  await publish();

  const beforeV2 = await getJSON(`${BASE}/idp/revocation_state_v2`);
  const membersBefore = new Set(beforeV2.leaves.slice(1).map((l) => l.value));
  const rebase = await fetch(`${BASE}/idp/rebaseline_v2`, { method: 'POST', headers: adminHeaders, body: '{}' });
  assert.equal(rebase.status, 200, `rebaseline must succeed (got ${rebase.status})`);
  const rebaseBody = await rebase.json();
  assert.equal(rebaseBody.epoch, beforeV2.epoch + 1, 'rebaseline must bump epoch by 1');

  const afterV2 = await getJSON(`${BASE}/idp/revocation_state_v2`);
  assert.equal(afterV2.epoch, beforeV2.epoch + 1, 'v2 epoch must have advanced');
  assert.equal(afterV2.seq, 0, 'rebaseline must reset seq to 0 (log cleared)');

  // 재기준화 전 epoch를 든 클라이언트는 반드시 전체 재조회로 떨어져야 한다.
  const stale = await getJSON(`${BASE}/idp/revocation_state_v2?since=${beforeV2.seq}&epoch=${beforeV2.epoch}`);
  assert.equal(stale.tooOld, true, 'a client on the pre-rebaseline epoch must be told to full-fetch');

  // 재기준화 후에도 (만료되지 않은) 살아있는 멤버는 전원 보존돼야 한다.
  const v2after = await buildFromFull(afterV2);
  assert.equal(v2after.getRoot().toString(), afterV2.root, 'rebased v2 tree rebuilds to the reported root');
  assert.equal(
    v2after.has(BigInt(survivorLeaf)),
    true,
    'a leaf published moments ago (nowhere near expiry) must survive the rebaseline',
  );
  for (const l of afterV2.leaves.slice(1).map((x) => x.value)) {
    assert.equal(membersBefore.has(l), true, 'rebaseline must not invent leaves that were not published before');
  }
  console.log('OK (4): rebaseline bumps epoch, clears the log, preserves live members (and invents none)');

  console.log('PASS: IMT v2 wiring — self-consistency, incremental multi-client sync, tooOld signalling, and rebaseline.');
}

main().catch((err) => { console.error(err); process.exit(1); });
