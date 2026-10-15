// tests/test_secret_box.mjs — PBKDF2/AES-GCM 금고 원시 연산(스펙 D1). Node 22 WebCrypto 로 돈다. (unit)  node tests/test_secret_box.mjs
import assert from 'node:assert/strict';
import { KDF_ITERATIONS, SALT_BYTES, randomSaltHex, deriveKey, encryptJson, decryptJson, makeCheck, verifyCheck, createMeta, openMeta } from '../lib/browser/secret_box.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

await t('상수: 310,000회·salt 16바이트, randomSaltHex 는 32자 hex 이고 매번 다르다', () => {
  assert.equal(KDF_ITERATIONS, 310000); assert.equal(SALT_BYTES, 16);
  const a = randomSaltHex(), b = randomSaltHex();
  assert.match(a, /^[0-9a-f]{32}$/); assert.notEqual(a, b);
});
await t('deriveKey: 기본은 추출 불가 AES-GCM 256, 같은 (pw, salt) 는 같은 암복호 키, 다른 salt·다른 pw 는 다른 키', async () => {
  const salt = randomSaltHex();
  const k1 = await deriveKey('pw-1', salt, 1000), k2 = await deriveKey('pw-1', salt, 1000);
  assert.equal(k1.extractable, false); assert.equal(k1.algorithm.name, 'AES-GCM'); assert.equal(k1.algorithm.length, 256);
  const box = await encryptJson(k1, { s_u: '123', sk_u: 'ab'.repeat(32) });
  assert.deepEqual(await decryptJson(k2, box), { s_u: '123', sk_u: 'ab'.repeat(32) });
  for (const k of [await deriveKey('pw-2', salt, 1000), await deriveKey('pw-1', randomSaltHex(), 1000)]) {
    await assert.rejects(() => decryptJson(k, box), (e) => e.reason === 'bad_password');
  }
  const ex = await deriveKey('pw-1', salt, 1000, { extractable: true });
  assert.equal(ex.extractable, true);
});
await t('encryptJson: iv 12바이트(hex 24자), 같은 평문도 iv 가 달라 암호문이 다르다, 손상된 ct 는 bad_password', async () => {
  const k = await deriveKey('pw', randomSaltHex(), 1000);
  const a = await encryptJson(k, { x: 1 }), b = await encryptJson(k, { x: 1 });
  assert.match(a.iv, /^[0-9a-f]{24}$/); assert.notEqual(a.iv, b.iv); assert.notEqual(a.ct, b.ct);
  const broken = { iv: a.iv, ct: a.ct.slice(0, -2) + (a.ct.endsWith('00') ? '01' : '00') };
  await assert.rejects(() => decryptJson(k, broken), (e) => e.reason === 'bad_password');
});
await t('makeCheck/verifyCheck: 맞는 키 true, 다른 키 false(throw 하지 않는다)', async () => {
  const salt = randomSaltHex();
  const k = await deriveKey('pw', salt, 1000), other = await deriveKey('no', salt, 1000);
  const check = await makeCheck(k);
  assert.equal(await verifyCheck(k, check), true);
  assert.equal(await verifyCheck(other, check), false);
});
await t('createMeta/openMeta: 메타 모양, 맞는 비밀번호는 키·틀리면 null, iterations 를 메타가 정한다', async () => {
  const { meta, key } = await createMeta('demo-pw');
  assert.equal(meta.version, 1); assert.ok(Date.parse(meta.createdAt) > 0);
  assert.match(meta.kdf.salt, /^[0-9a-f]{32}$/); assert.equal(meta.kdf.iterations, KDF_ITERATIONS);
  assert.ok(meta.check.iv && meta.check.ct);
  const box = await encryptJson(key, { hello: 'world' });
  const reopened = await openMeta('demo-pw', meta);
  assert.ok(reopened); assert.deepEqual(await decryptJson(reopened, box), { hello: 'world' });
  assert.equal(await openMeta('wrong', meta), null);
  const fast = { ...meta, kdf: { ...meta.kdf, iterations: 1000 } };
  assert.equal(await openMeta('demo-pw', fast), null, 'iterations 가 다르면 다른 키');
});
process.exit(fails ? 1 : 0);
