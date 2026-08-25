import assert from 'node:assert/strict';
import { createIMT, leafValue, TAG_ACCOUNT } from '../lib/imt.js';

const IDP = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';

// 폐기 전후로 witness 생성 가능 여부가 뒤집히는지 확인한다. 이 파일은 IdP 레벨
// (폐기 → non-membership witness 발급 가능 여부)만 검증한다.
// 회로가 폐기된 세션/계정을 거부하는지는 tests/test_pi_pk_i_revocation.mjs가,
// 온체인 지갑/레지스트리가 등록되지 않은 root를 거부하는지는
// test/PPIDWalletRevocation.test.mjs, test/RevocationRegistry.test.mjs가 각각 담당한다.
// 이 세 조각을 합성해 살아있는 wallet_agent.js가 만든 실제 증명이 배포된
// PPIDWallet에서 실제로 거부되는 전 구간을 도는 테스트는 아직 없다.
async function main() {
  const victim = '987654321';
  const leaf = await leafValue(TAG_ACCOUNT, victim);

  const before = await (await fetch(`${IDP}/idp/revocation_state`)).json();
  const t1 = await createIMT(20);
  for (const l of before.revokedLeaves) await t1.insert(BigInt(l));
  const w = await t1.getNonMembershipWitness(leaf);
  assert.equal(w.root, before.root, 'local tree must match IdP root before revocation');
  console.log('OK: unrevoked account has a non-membership witness');

  const res = await fetch(`${IDP}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'account', value: victim }),
  });
  assert.equal(res.status, 200);

  const after = await (await fetch(`${IDP}/idp/revocation_state`)).json();
  assert.notEqual(after.root, before.root, 'root must change after revocation');

  const t2 = await createIMT(20);
  for (const l of after.revokedLeaves) await t2.insert(BigInt(l));
  await assert.rejects(() => t2.getNonMembershipWitness(leaf), /is a member/);
  console.log('OK: revoked account can no longer obtain a witness');

  console.log('PASS: revocation flips witness availability end to end.');
}

main();
