// tests/test_mode3_vault_hold.mjs — 금고의 10분 passkey salt 보관(passkey-web). (unit)  node tests/test_mode3_vault_hold.mjs
import assert from 'node:assert/strict';
import { createVault, PASSKEY_HOLD_MS } from '../mode3/user/core/vault.js';
import { createMemKv } from '../mode3/user/core/kv_mem.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

const S = '123456789012345678901234567890123456789';
const MIN = 60_000;
let tm = 1_000_000;
const now = () => tm;
async function fresh(opts = {}) { tm = 1_000_000; const kv = createMemKv(); const vault = createVault(kv, { now, ...opts }); await vault.setup(null); return { kv, vault }; }

await t('상수: 10분', () => assert.equal(PASSKEY_HOLD_MS, 10 * MIN));
await t('보관·읽기: 읽힌다, kv 에 salt 평문이 없다', async () => {
  const { kv, vault } = await fresh();
  assert.equal(await vault.holdSalt(S), true);
  assert.equal(await vault.heldSalt(), S);
  assert.equal(await vault.heldUntil(), tm + PASSKEY_HOLD_MS);
  const dump = {}; for (const k of await kv.keys()) { const v = await kv.get(k); dump[k] = v?.box ? { ...v, box: JSON.stringify(v.box) } : v?.key ? '(key)' : v; }
  assert.ok(!JSON.stringify(dump).includes(S));
});
await t('만료: null 이고 kv 키가 지워진다', async () => {
  const { kv, vault } = await fresh();
  await vault.holdSalt(S); tm += PASSKEY_HOLD_MS + 1;
  assert.equal(await vault.heldSalt(), null);
  assert.equal(await kv.get('passkeyHold'), undefined);
});
await t('늘리지 않음: 읽어도 until 이 그대로', async () => {
  const { vault } = await fresh();
  await vault.holdSalt(S); tm += 9 * MIN;
  assert.equal(await vault.heldSalt(), S);
  tm += MIN + 1;
  assert.equal(await vault.heldSalt(), null);
});
await t('다른 탭: 같은 kv 의 두 번째 금고가 읽는다', async () => {
  const { kv, vault } = await fresh();
  await vault.holdSalt(S);
  assert.equal(await createVault(kv, { now }).heldSalt(), S);
});
await t('끔: holdMs 0 이면 false, kv 에 키 없음', async () => {
  const { kv, vault } = await fresh({ holdMs: 0 });
  assert.equal(await vault.holdSalt(S), false);
  assert.equal(await kv.get('passkeyHold'), undefined);
});
await t('지우기: clearHold 뒤 null', async () => {
  const { vault } = await fresh();
  await vault.holdSalt(S); await vault.clearHold();
  assert.equal(await vault.heldSalt(), null); assert.equal(await vault.heldUntil(), null);
});
await t('덮어쓰기: 새 until', async () => {
  const { vault } = await fresh();
  await vault.holdSalt(S); tm += 5 * MIN; await vault.holdSalt('42');
  assert.equal(await vault.heldSalt(), '42'); assert.equal(await vault.heldUntil(), tm + PASSKEY_HOLD_MS);
});
await t('바깥 until 조작: 안쪽과 달라 null, 키 삭제', async () => {
  const { kv, vault } = await fresh();
  await vault.holdSalt(S);
  const h = await kv.get('passkeyHold'); await kv.set('passkeyHold', { ...h, until: h.until + 10 * MIN });
  assert.equal(await vault.heldSalt(), null);
  assert.equal(await kv.get('passkeyHold'), undefined);
});
await t('잠김: 금고 없으면 holdSalt locked, heldSalt null', async () => {
  const vault = createVault(createMemKv(), { now });
  await assert.rejects(vault.holdSalt(S), (e) => e.reason === 'locked');
  assert.equal(await vault.heldSalt(), null); assert.equal(await vault.heldUntil(), null);
});
await t('형식: 0·abc·2^250 이상은 reject', async () => {
  const { vault } = await fresh();
  for (const bad of ['0', 'abc', '', (2n ** 250n).toString(), 5, null]) await assert.rejects(vault.holdSalt(bad), `거부돼야 함: ${bad}`);
});
process.exit(fails ? 1 : 0);
