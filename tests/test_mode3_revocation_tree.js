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
  TAG_MODE3_SESSION,
  userLeaf,
  sessionLeaf,
  sessionLeafRange,
  SESSION_BOUND_MAX,
  createRevocationTree,
  revokeBindMessage,
  signRevokeBind,
  verifyRevokeBind,
} from '../lib/mode3_revocation.js';
import { ethers } from 'ethers';
import { TAG_SESSION, TAG_ACCOUNT, leafValue } from '../lib/imt_v2.js';

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

await t('세션 리프 태그는 5 — 같은 Cf 라도 userLeaf 와 sessionLeaf 는 다르다', async () => {
  assert.equal(TAG_MODE3_SESSION, 5n);
  const a = await userLeaf(123n), b = await sessionLeaf(123n, 0n);
  assert.notEqual(a, b);
  assert.ok(b < (1n << 252n));
  assert.equal(b, await sessionLeaf(123n, 0n));
});

await t('revokeSessionMessage: 도메인은 ASCII MODE3REVOKESESS, 입력이 하나라도 다르면 값이 다르다(2026-10-22: uid, Cf_s, bound, nonce)', async () => {
  const { DOMAIN_MODE3_REVOKESESS, revokeSessionMessage } = await import('../lib/mode3_issuance.js');
  assert.equal(Buffer.from(DOMAIN_MODE3_REVOKESESS.toString(16), 'hex').toString(), 'MODE3REVOKESESS');
  const m = await revokeSessionMessage(1n, 2n, 3n, 4n);
  assert.notEqual(m, await revokeSessionMessage(1n, 2n, 3n, 5n));
  assert.notEqual(m, await revokeSessionMessage(1n, 2n, 9n, 4n));
  assert.notEqual(m, await revokeSessionMessage(1n, 5n, 3n, 4n));
});

await t('sessionLeaf(Cf_s, bound) = (Poseidon(5,Cf_s) mod 2^220)·2^32 + bound, 2^252 미만', async () => {
  const Cf_s = 123456789n;
  const hp = (await leafValue(TAG_MODE3_SESSION, Cf_s)) & ((1n << 220n) - 1n);
  assert.equal(await sessionLeaf(Cf_s, 0n), hp << 32n);
  assert.equal(await sessionLeaf(Cf_s, 7n), (hp << 32n) + 7n);
  assert.ok((await sessionLeaf(Cf_s, SESSION_BOUND_MAX - 1n)) < (1n << 252n));
  await assert.rejects(() => sessionLeaf(Cf_s, SESSION_BOUND_MAX), /bound/);
  await assert.rejects(() => sessionLeaf(Cf_s, -1n), /bound/);
});
await t('sessionLeafRange(Cf_s, counter) = [H′·2^32, H′·2^32 + counter]', async () => {
  const Cf_s = 42n;
  const base = await sessionLeaf(Cf_s, 0n);
  assert.deepEqual(await sessionLeafRange(Cf_s, 0n), { lo: base, hi: base });
  assert.deepEqual(await sessionLeafRange(Cf_s, 5n), { lo: base, hi: base + 5n });
  assert.deepEqual(await sessionLeafRange(Cf_s, SESSION_BOUND_MAX - 1n), { lo: base, hi: base + SESSION_BOUND_MAX - 1n });
});
await t('구간 비멤버십 증인: 상한 c 리프가 있을 때 counter < c 는 증인, counter ≥ c 는 "is a member"', async () => {
  const tree = await createRevocationTree(8);
  const Cf_s = 777n;
  await tree.insert(await sessionLeaf(Cf_s, 3n));            // 허용 거래 수 3 → nonce 0,1,2 만
  for (const k of [0n, 1n, 2n]) { const { lo, hi } = await sessionLeafRange(Cf_s, k); const w = await tree.getRangeNonMembershipWitness(lo, hi); assert.ok(w.pathElements.length === 8); }
  for (const k of [3n, 4n, SESSION_BOUND_MAX - 1n]) { const { lo, hi } = await sessionLeafRange(Cf_s, k); await assert.rejects(() => tree.getRangeNonMembershipWitness(lo, hi), /is a member/); }
  const other = await sessionLeafRange(778n, SESSION_BOUND_MAX - 1n);   // 다른 세션은 영향 없음
  assert.ok(await tree.getRangeNonMembershipWitness(other.lo, other.hi));
});

// 2026-10-25 root 유효 창 §4: 세션키 결속 서명 — 폐기 요청의 pk_i 가 그 요청(uid·Cf_s·bound·nonce)의 것임을 sk_i 로 묶는다.
{
  const w = ethers.Wallet.createRandom();
  const f = { uid: 12345n, Cf_s: 777n, bound: 2n, nonce: 999n };
  assert.equal(revokeBindMessage(f), 'MODE3_REVOKE_BIND_V1|12345|777|2|999');
  assert.equal(revokeBindMessage({ uid: '12345', Cf_s: '777', bound: '2', nonce: '999' }), revokeBindMessage(f), '10진 문자열도 같은 메시지');
  const sig = await signRevokeBind(w.privateKey, f);
  const pk_i = BigInt(w.address).toString();
  assert.equal(verifyRevokeBind(pk_i, f, sig), true);
  assert.equal(verifyRevokeBind(BigInt(ethers.Wallet.createRandom().address).toString(), f, sig), false, '다른 pk_i');
  assert.equal(verifyRevokeBind(pk_i, { ...f, bound: 3n }, sig), false, '다른 bound');
  assert.equal(verifyRevokeBind(pk_i, { ...f, nonce: 1n }, sig), false, '다른 nonce');
  assert.equal(verifyRevokeBind(pk_i, f, '0xdead'), false, '깨진 서명은 false(throw 아님)');
  assert.equal(verifyRevokeBind('not-a-number', f, sig), false, '깨진 pk_i 도 false');
  console.log('ok   revokeBind 결속 서명');
}

process.exit(failed === 0 ? 0 : 1);
