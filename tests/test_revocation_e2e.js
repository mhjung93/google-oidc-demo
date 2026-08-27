import assert from 'node:assert/strict';
import { createIMT, leafValue, TAG_ACCOUNT } from '../lib/imt.js';

const IDP = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';

// /idp/revoke는 운영자 전용이라 IdP 프로세스와 같은 IDP_ADMIN_SECRET이 필요하다.
//   IDP_ADMIN_SECRET=<value> node tests/test_revocation_e2e.js
const ADMIN_SECRET = process.env.IDP_ADMIN_SECRET;
if (!ADMIN_SECRET) {
  console.error('IDP_ADMIN_SECRET is required to run this test (must match the value custom_idp.js was started with)');
  process.exit(1);
}

// 폐기 전후로 witness 생성 가능 여부가 뒤집히는지 확인한다. 이 파일은 IdP 레벨
// (폐기 → non-membership witness 발급 가능 여부)만 검증한다.
// 회로가 폐기된 세션/계정을 거부하는지는 tests/test_pi_pk_i_revocation.mjs가,
// 온체인 지갑/레지스트리가 등록되지 않은 root를 거부하는지는
// test/PPIDWalletRevocation.test.mjs, test/RevocationRegistry.test.mjs가 각각 담당한다.
// 이 세 조각을 합성해 살아있는 wallet_agent.js가 만든 실제 증명이 배포된
// PPIDWallet에서 실제로 거부되는 전 구간을 도는 테스트는 아직 없다.
async function main() {
  // 살아있는 IdP의 인메모리 폐기 트리는 IdP 재시작 전까지 유지된다. victim에 고정값을
  // 쓰면 두 번째 실행에서는 이미 폐기된 계정이라 첫 단언("폐기 전에는 비멤버십 witness가
  // 나온다")부터 실패한다 — IdP 결함이 아니라 테스트 자체의 비멱등성이다. 실행마다 새
  // 계정을 써서 재실행 가능하게 만든다.
  const victim = `987654321${Date.now()}`;
  const leaf = await leafValue(TAG_ACCOUNT, victim);

  const before = await (await fetch(`${IDP}/idp/revocation_state`)).json();
  const t1 = await createIMT(20);
  for (const l of before.revokedLeaves) await t1.insert(BigInt(l));
  const w = await t1.getNonMembershipWitness(leaf);
  assert.equal(w.root, before.root, 'local tree must match IdP root before revocation');
  console.log('OK: unrevoked account has a non-membership witness');

  const res = await fetch(`${IDP}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-IdP-Admin-Secret': ADMIN_SECRET },
    body: JSON.stringify({ type: 'account', value: victim }),
  });
  assert.equal(res.status, 200);

  // 배칭: 폐기는 대기열에 들어갈 뿐이고, 게시 전까지 지갑이 보는 상태는 그대로다.
  const queued = await (await fetch(`${IDP}/idp/revocation_state`)).json();
  assert.equal(queued.root, before.root, 'queued revocation must not change the published root');
  console.log('OK: 폐기 접수만으로는 게시 상태가 바뀌지 않는다 (배칭)');

  // 게시(prepare -> commit). 이 테스트는 **온체인 push 없이 IdP 단계만** 돌린다.
  //
  // 근거: 이 파일의 검증 대상은 "폐기가 비멤버십 witness 발급 가능 여부를 뒤집는가"
  // 라는 IdP 레벨 성질 하나뿐이고(파일 상단 주석 참고), 지금까지 custom_idp.js
  // 하나에만 의존하는 자기완결형 테스트였다. 온체인 push를 넣으려면 hardhat 노드와
  // 배포된 RevocationRegistry 주소, 운영자 키까지 전제로 끌어와야 해서 이 테스트의
  // 성격이 바뀐다. push까지 포함한 전체 게시 경로(prepare -> pushRoot -> commit)는
  // scripts/revocation_sweep.cjs와 tests/test_mode2_e2e_onchain.js가 이미 덮는다.
  //
  // 대가: 이 테스트를 돌리면 IdP의 게시 상태가 온체인 root보다 앞서게 된다.
  // 그 상태로 온체인 테스트를 이어서 돌리려면 root를 먼저 게시해야 하는데,
  // tests/test_mode2_e2e_onchain.js가 시작 시 자기 전제조건을 스스로 세우므로
  // (isRecentRoot 확인 후 필요하면 게시) 실무상 문제가 되지 않는다.
  const adminHeaders = { 'Content-Type': 'application/json', 'X-IdP-Admin-Secret': ADMIN_SECRET };
  const prepared = await (await fetch(`${IDP}/idp/publish/prepare`, { method: 'POST', headers: adminHeaders, body: '{}' })).json();
  assert.ok(prepared.expectedRoot, 'prepare must return an expected root');
  assert.equal(prepared.currentRoot, before.root, 'prepare must not move the published root');
  const commitRes = await fetch(`${IDP}/idp/publish/commit`, {
    method: 'POST',
    headers: adminHeaders,
    body: JSON.stringify({ root: prepared.expectedRoot }),
  });
  assert.equal(commitRes.status, 200, 'commit must succeed with the prepared root');

  const after = await (await fetch(`${IDP}/idp/revocation_state`)).json();
  assert.notEqual(after.root, before.root, 'root must change after publishing the revocation');
  assert.equal(after.root, prepared.expectedRoot, 'published root must equal the prepared root');

  const t2 = await createIMT(20);
  for (const l of after.revokedLeaves) await t2.insert(BigInt(l));
  await assert.rejects(() => t2.getNonMembershipWitness(leaf), /is a member/);
  console.log('OK: revoked account can no longer obtain a witness');

  console.log('PASS: revocation flips witness availability end to end (only after publication).');
}

main();
