// Mode 3 폐기 트리 헬퍼. 리프 유도와 트리 동작을 확인한다.
//   node tests/test_mode3_revocation_tree.js
//
// 트리 본체는 lib/imt_v2.js를 그대로 쓰므로 여기서는 재검증하지 않는다.
// 확인하는 것은 Mode 3이 얹는 부분 — 리프 유도가 결정적이고, 회로가 쓰는
// 252비트 범위 안에 들어오며, Mode 2의 태그와 충돌하지 않는다는 것이다.
import assert from 'node:assert/strict';
import {
  MODE3_TREE_DEPTH,
  TAG_MODE3_USER,
  userLeaf,
  createRevocationTree,
} from '../lib/mode3_revocation.js';
import { TAG_SESSION, TAG_ACCOUNT } from '../lib/imt_v2.js';

const TWO_252 = 1n << 252n;
let failed = 0;

async function t(name, fn) {
  try {
    await fn();
    console.log(`ok   ${name}`);
  } catch (e) {
    failed++;
    console.error(`FAIL ${name}\n     ${e.message}`);
  }
}

await t('깊이는 32다', () => {
  assert.equal(MODE3_TREE_DEPTH, 32);
});

await t('태그는 4 — Mode 2(1·2)·V4 세션 리프(3)와 충돌하지 않는다', () => {
  assert.equal(TAG_MODE3_USER, 4n);
  assert.notEqual(TAG_MODE3_USER, TAG_SESSION);
  assert.notEqual(TAG_MODE3_USER, TAG_ACCOUNT);
});

await t('userLeaf는 결정적이고 252비트 안에 들어온다', async () => {
  const Cf_u = 123456789012345678901234567890n;
  const a = await userLeaf(Cf_u);
  const b = await userLeaf(Cf_u);
  assert.equal(a, b, '같은 Cf_u 는 같은 리프를 준다');
  assert.ok(a < TWO_252, `리프가 2^252 미만이어야 한다: ${a}`);
  assert.ok(a > 0n, '리프가 0이면 anchor와 충돌한다');
});

await t('다른 Cf_u 는 다른 리프를 준다', async () => {
  const a = await userLeaf(1n);
  const b = await userLeaf(2n);
  assert.notEqual(a, b);
});

await t('폐기 전에는 비멤버십 witness가 나오고 폐기 후에는 안 나온다', async () => {
  const tree = await createRevocationTree();
  const leaf = await userLeaf(42n);

  const before = await tree.getNonMembershipWitness(leaf);
  assert.ok(before, '폐기 전에는 witness가 나와야 한다');
  assert.equal(before.pathElements.length, MODE3_TREE_DEPTH);

  const rootBefore = tree.getRoot();
  assert.equal(await tree.insert(leaf), true);
  assert.notEqual(tree.getRoot().toString(), rootBefore.toString(),
    '삽입하면 root가 바뀌어야 한다');

  await assert.rejects(() => tree.getNonMembershipWitness(leaf), /is a member/);
});

await t('다른 사용자 자격증명은 남의 폐기에 영향받지 않는다', async () => {
  const tree = await createRevocationTree();
  const mine = await userLeaf(7n);
  await tree.insert(await userLeaf(8n));
  const w = await tree.getNonMembershipWitness(mine);
  assert.ok(w, '내 리프는 여전히 비멤버십이어야 한다');
});

await t('제거 기능이 없다 (append-only)', async () => {
  const tree = await createRevocationTree();
  assert.equal(typeof tree.remove, 'undefined');
});

process.exit(failed === 0 ? 0 : 1);
