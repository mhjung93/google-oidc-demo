// salt 봉투 라이브러리(lib/mode3_salt_envelope.js) 단위 테스트. 외부 의존 없음.
//   node tests/test_mode3_salt_envelope.mjs
import assert from 'node:assert/strict';
import {
  BACKUP_LIMIT, DEVICE_LIMIT, ENV_KINDS, envKeyFromPrf, envKeyFromCode, newRecoveryCode, parseRecoveryCode,
  newEnvelopeId, sealSalt, openSalt, isEnvelope, auidCheckOf,
} from '../lib/mode3_salt_envelope.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.log(`FAIL ${name}\n     ${e.stack || e}`); }
}
const rejectsWith = async (fn, reason) => {
  try { await fn(); } catch (e) { assert.equal(e.reason, reason, `reason=${e.reason}`); return; }
  assert.fail(`${reason} 로 던져야 한다`);
};
const prf = (b) => new Uint8Array(32).fill(b);
const SALT = '123456789012345678901234567890';
const base = { s_u: SALT, uid: 'uid-1', id: '0123456789abcdef0123456789abcdef', kind: 'passkey', credentialId: 'cred_A-b' };
const sealOpen = async (key, over = {}) => {
  const ct = await sealSalt({ key, ...base });
  return openSalt({ key, ct, ...base, ...over });
};

await t('상수', () => {
  assert.equal(BACKUP_LIMIT, 5); assert.equal(DEVICE_LIMIT, 10);
  assert.deepEqual(ENV_KINDS, ['passkey', 'code', 'device']);
});
await t('왕복: 같은 s_u', async () => {
  const key = await envKeyFromPrf(prf(1));
  assert.equal(await sealOpen(key), SALT);
});
await t('uid·id·kind·credentialId 중 하나라도 바꾸면 envelope_open_failed', async () => {
  const key = await envKeyFromPrf(prf(1));
  for (const over of [{ uid: 'uid-2' }, { id: 'f'.repeat(32) }, { kind: 'device' }, { credentialId: 'cred_B' }, { credentialId: null }]) {
    await rejectsWith(() => sealOpen(key, over), 'envelope_open_failed');
  }
});
await t('ct 한 바이트 변조 -> envelope_open_failed', async () => {
  const key = await envKeyFromPrf(prf(1));
  const ct = await sealSalt({ key, ...base });
  const i = 20, c = ct[i] === 'A' ? 'B' : 'A';
  await rejectsWith(() => openSalt({ key, ct: ct.slice(0, i) + c + ct.slice(i + 1), ...base }), 'envelope_open_failed');
});
await t('다른 PRF -> envelope_open_failed', async () => {
  const ct = await sealSalt({ key: await envKeyFromPrf(prf(1)), ...base });
  await rejectsWith(async () => openSalt({ key: await envKeyFromPrf(prf(2)), ct, ...base }), 'envelope_open_failed');
});
await t('열쇠는 추출 불가, IV 는 매번 다르다', async () => {
  const key = await envKeyFromPrf(prf(1));
  assert.equal(key.extractable, false);
  assert.notEqual(await sealSalt({ key, ...base }), await sealSalt({ key, ...base }));
});
await t('복구 코드: 형식·왕복', async () => {
  const code = newRecoveryCode();
  assert.match(code, /^([0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]{3}$/);
  assert.equal(code.replace(/-/g, '').length, 27);
  assert.equal(parseRecoveryCode(code).length, 16);
  assert.deepEqual(parseRecoveryCode(code), parseRecoveryCode(code.toLowerCase().replace(/-/g, ' ')));
  const key = await envKeyFromCode(code);
  const kc = { ...base, kind: 'code', credentialId: null };
  const ct = await sealSalt({ key, ...kc });
  assert.equal(await openSalt({ key, ct, ...kc }), SALT);
});
await t('복구 코드: I/L/O 정규화', () => {
  const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const sym = (s) => [...s].reduce((n, c) => n + A.indexOf(c), 0) % 32;
  const body = '1100000000000000000000000'.padEnd(26, '0');
  const mk = (b) => b + A[sym(b)];
  assert.deepEqual(parseRecoveryCode(mk(body)), parseRecoveryCode(mk(body).replace(/1/g, 'I').replace(/0/g, 'O')));
  assert.deepEqual(parseRecoveryCode(mk(body)), parseRecoveryCode(mk(body).replace(/1/g, 'l')));
});
await t('복구 코드: 한 글자 틀림 -> recovery_code_typo', async () => {
  const code = newRecoveryCode().replace(/-/g, '');
  const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const i = 3, bad = code.slice(0, i) + A[(A.indexOf(code[i]) + 1) % 32] + code.slice(i + 1);
  assert.throws(() => parseRecoveryCode(bad), (e) => e.reason === 'recovery_code_typo');
  await rejectsWith(() => envKeyFromCode(bad), 'recovery_code_typo');
});
await t('복구 코드: 길이·문자·남는 비트 -> recovery_code_format', async () => {
  const code = newRecoveryCode().replace(/-/g, '');
  for (const bad of ['', code.slice(1), code + '0', code.slice(0, 5) + 'U' + code.slice(6), code.slice(0, 5) + '!' + code.slice(6), 12345]) {
    assert.throws(() => parseRecoveryCode(bad), (e) => e.reason === 'recovery_code_format', String(bad));
  }
  await rejectsWith(() => envKeyFromCode('abc'), 'recovery_code_format');
  // 26번째 자리의 남는 2비트가 0 이 아니면 검사 문자가 맞아도 형식 오류
  const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const body = '0'.repeat(25) + '1';
  const chk = A[1];
  assert.throws(() => parseRecoveryCode(body + chk), (e) => e.reason === 'recovery_code_format');
});
await t('틀린(검사 문자까지 맞춘) 코드로 열면 envelope_open_failed', async () => {
  const kc = { ...base, kind: 'code', credentialId: null };
  const ct = await sealSalt({ key: await envKeyFromCode(newRecoveryCode()), ...kc });
  await rejectsWith(async () => openSalt({ key: await envKeyFromCode(newRecoveryCode()), ct, ...kc }), 'envelope_open_failed');
});
await t('newEnvelopeId: 16진 32자', () => {
  assert.match(newEnvelopeId(), /^[0-9a-f]{32}$/);
  assert.notEqual(newEnvelopeId(), newEnvelopeId());
});
await t('isEnvelope 경계', () => {
  const id = 'a'.repeat(32);
  assert.equal(isEnvelope({ id, kind: 'passkey', credentialId: 'abc_-', ct: 'x'.repeat(256) }), true);
  assert.equal(isEnvelope({ id, kind: 'passkey', credentialId: 'abc', ct: 'x'.repeat(257) }), false);
  assert.equal(isEnvelope({ id, kind: 'code', credentialId: null, ct: 'abc' }), true);
  assert.equal(isEnvelope({ id, kind: 'code', credentialId: 'abc', ct: 'abc' }), false);
  assert.equal(isEnvelope({ id, kind: 'device', ct: 'abc' }), false);
  assert.equal(isEnvelope({ id, kind: 'device', credentialId: null, ct: 'abc' }), false);
  assert.equal(isEnvelope({ id, kind: 'passkey', credentialId: 'a'.repeat(1025), ct: 'abc' }), false);
  assert.equal(isEnvelope({ id, kind: 'passkey', credentialId: 'a'.repeat(1024), ct: 'abc' }), true);
  assert.equal(isEnvelope({ id: 'A'.repeat(32), kind: 'passkey', credentialId: 'abc', ct: 'abc' }), false);
  assert.equal(isEnvelope({ id, kind: 'other', credentialId: 'abc', ct: 'abc' }), false);
  assert.equal(isEnvelope({ id, kind: 'passkey', credentialId: 'a+b', ct: 'abc' }), false);
  assert.equal(isEnvelope({ id, kind: 'passkey', credentialId: 'abc', ct: '' }), false);
  assert.equal(isEnvelope(null), false);
});
await t('auidCheckOf 고정 값', async () => {
  assert.equal(await auidCheckOf('uid-1', 'auid-1'), '84d4d4e09e2242153a197fe9269650848ca18dd0790b879527199e83f2770a7e');
});

if (failed) { console.log(`\n${failed} 실패`); process.exit(1); }
console.log('\n전부 통과');
