// 패스키 모드 salt 유도식(스펙 2026-11-17-mode3-passkey-mode §1 P2). 전역 스크립트라 vm 으로 window 를 흉내 내 읽는다.
//   node tests/test_mode3_passkey_salt.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createHash } from 'node:crypto';

globalThis.window = {};
vm.runInThisContext(fs.readFileSync(new URL('../mode3/common/passkey_store.js', import.meta.url), 'utf8'));
const P = globalThis.window.Mode3Passkey;

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

const utf8 = (s) => new TextEncoder().encode(s);
const expected = (prf) => (BigInt('0x' + createHash('sha256').update(Buffer.concat([Buffer.from('zkd-passkey-s_u-v1', 'utf8'), Buffer.from(prf)])).digest('hex')) >> 6n).toString();

await t('전역 Mode3Passkey 가 있다', () => { assert.equal(typeof P?.saltFromPrf, 'function'); });
await t('PRF 입력은 utf8("zkd-s_u-v1"), 도메인은 zkd-passkey-s_u-v1', () => {
  assert.deepEqual([...P.PRF_INPUT], [...utf8('zkd-s_u-v1')]);
  assert.equal(P.SALT_DOMAIN, 'zkd-passkey-s_u-v1');
});
await t('0 바이트 32개 → SHA-256(도메인 ‖ prf) >> 6', async () => {
  const prf = new Uint8Array(32);
  assert.equal(await P.saltFromPrf(prf), expected(prf));
});
await t('ArrayBuffer 도 받는다, 결과는 [1, 2^250)', async () => {
  const prf = new Uint8Array(32).map((_, i) => i * 7 + 1);
  const s = await P.saltFromPrf(prf.buffer);
  assert.equal(s, expected(prf));
  assert.ok(BigInt(s) >= 1n && BigInt(s) < (1n << 250n));
});
await t('같은 입력은 같은 값, 첫 바이트가 다르면 다른 값', async () => {
  const a = new Uint8Array(32).fill(9); const b = new Uint8Array(32).fill(9); b[0] = 10;
  assert.equal(await P.saltFromPrf(a), await P.saltFromPrf(new Uint8Array(a)));
  assert.notEqual(await P.saltFromPrf(a), await P.saltFromPrf(b));
});
await t('32바이트가 아니면 passkey_prf_unsupported', async () => {
  await assert.rejects(P.saltFromPrf(new Uint8Array(31)), (e) => e.reason === 'passkey_prf_unsupported');
  await assert.rejects(P.saltFromPrf(null), (e) => e.reason === 'passkey_prf_unsupported');
});

if (fails) { console.log(`\n${fails} failed`); process.exit(1); }
console.log('\nall passed');
