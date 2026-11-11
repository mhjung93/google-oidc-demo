// tests/test_attr_backup.mjs — 속성 도구 암호화 백업(2026-11-11, 사용자 결정: 자동 백업·백업 비밀번호). Node 22 WebCrypto 로 돈다. (unit)  node tests/test_attr_backup.mjs
import assert from 'node:assert/strict';
import { BACKUP_FORMAT, BACKUP_MIN_PASSWORD, backupKey, sealBackup, openBackup, isSealedBackup } from '../lib/browser/attr_backup.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

const REC = { version: 2, uid: '100001', s_u: '98765432109876543210', profile: { birthYear: '1990', country: 'KR' }, attrs: ['1990', '410', '0', '0', '0', '0'], blind: '7777777777777777777777', commit: '1234567890123456789012', createdAt: '2026-11-11T00:00:00.000Z' };

await t('봉인: 형식 표시·kdf(salt·횟수)·암호문만 — uid·s_u·속성·blind 는 평문으로 없다', async () => {
  const { key, kdf } = await backupKey('correct horse', undefined, 1000);
  assert.equal(key.extractable, false, '키는 추출 불가(IndexedDB 에 CryptoKey 로 둔다)');
  const sealed = await sealBackup(key, kdf, REC);
  assert.equal(sealed.format, BACKUP_FORMAT); assert.equal(sealed.version, 1); assert.equal(isSealedBackup(sealed), true);
  assert.match(sealed.kdf.salt, /^[0-9a-f]{32}$/); assert.equal(sealed.kdf.iterations, 1000);
  const text = JSON.stringify(sealed);
  // 암호문은 16진이라 짧은 숫자는 우연히 겹칠 수 있다 — 긴 값과 16진에 나올 수 없는 키 이름·문자로 본다.
  for (const v of [REC.s_u, REC.blind, REC.commit, 'birthYear', 'profile', 's_u', 'uid', 'KR']) assert.equal(text.includes(v), false, `평문 ${v} 가 없다`);
});
await t('열기: 같은 비밀번호면 기록 그대로, 틀린 비밀번호는 bad_password, 손상된 암호문도 bad_password', async () => {
  const { key, kdf } = await backupKey('correct horse', undefined, 1000);
  const sealed = await sealBackup(key, kdf, REC);
  assert.deepEqual(await openBackup('correct horse', sealed), REC);
  await assert.rejects(() => openBackup('wrong horse', sealed), (e) => e.reason === 'bad_password');
  const bad = { ...sealed, box: { ...sealed.box, ct: sealed.box.ct.replace(/^../, (h) => (h === '00' ? '01' : '00')) } };
  await assert.rejects(() => openBackup('correct horse', bad), (e) => e.reason === 'bad_password');
});
await t('형식: 평문 기록·다른 형식은 봉인 백업이 아니다; openBackup 은 형식이 다르면 bad_backup', async () => {
  assert.equal(isSealedBackup(REC), false); assert.equal(isSealedBackup(null), false); assert.equal(isSealedBackup({ format: 'other' }), false);
  await assert.rejects(() => openBackup('x'.repeat(8), { format: BACKUP_FORMAT, version: 9 }), (e) => e.reason === 'bad_backup');
});
await t('비밀번호: 8자 미만이면 키를 만들지 않는다(bad_backup_password); 기본 횟수는 310,000', async () => {
  assert.equal(BACKUP_MIN_PASSWORD, 8);
  await assert.rejects(() => backupKey('short'), (e) => e.reason === 'bad_backup_password');
  const { kdf } = await backupKey('long enough pw');
  assert.equal(kdf.iterations, 310000);
});

process.exit(fails ? 1 : 0);
