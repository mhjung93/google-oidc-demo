import assert from 'node:assert/strict';
import { createIMT, leafValue, TAG_ACCOUNT } from '../lib/imt.js';

const IDP = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';

// 폐기 전후로 witness 생성 가능 여부가 뒤집히는지 확인한다.
// 회로·온체인 검증까지 도는 전체 흐름은 test_mode2_integration.js가 담당하며,
// 여기서는 폐기가 실제로 반영되는지만 본다.
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
