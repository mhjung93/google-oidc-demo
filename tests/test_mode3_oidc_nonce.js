// tests/test_mode3_oidc_nonce.js — OIDC 래퍼의 순수 유도 함수(스펙 2026-10-16 D3·D4). 외부 의존 없음. (unit)  node tests/test_mode3_oidc_nonce.js
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { REG_PREFIX, REVOKE_PREFIX, uidOf, regNonce, newRevokeNonce, isRevokeNonce, isRegNonce } from '../lib/mode3_oidc_nonce.js';
import { SCALAR_MAX } from '../lib/mode3_credential.js';

let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }
const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

t('uidOf: SHA-256(provider|sub) mod 2^250, 10진, 결정적, provider·sub 가 다르면 다르다', () => {
  const u = uidOf('google', '1234567890');
  assert.match(u, /^(0|[1-9][0-9]*)$/); assert.ok(BigInt(u) < SCALAR_MAX);
  assert.equal(u, (BigInt('0x' + sha('google|1234567890')) & (SCALAR_MAX - 1n)).toString());
  assert.equal(uidOf('google', '1234567890'), u);
  assert.notEqual(uidOf('google', '1234567891'), u); assert.notEqual(uidOf('naver', '1234567890'), u);
  assert.throws(() => uidOf('', 'x'), /provider/); assert.throws(() => uidOf('google', ''), /sub/); assert.throws(() => uidOf('google', 5), /sub/);
});
t('regNonce: "reg:" + sha256(x|y) — 10진·bigint 입력이 같은 값, 비정규(앞자리 0)도 정규화된다', () => {
  const n = regNonce({ x: '45', y: '67' });
  assert.equal(n, REG_PREFIX + sha('45|67')); assert.match(n, /^reg:[0-9a-f]{64}$/);
  assert.equal(regNonce({ x: 45n, y: 67n }), n);
  assert.equal(regNonce({ x: '045', y: '67' }), n);
  assert.notEqual(regNonce({ x: '46', y: '67' }), n);
  assert.throws(() => regNonce({ x: 'abc', y: '2' })); assert.throws(() => regNonce({ x: '1' })); assert.throws(() => regNonce(null));
  assert.equal(isRegNonce(n), true); assert.equal(isRegNonce('revoke:' + 'a'.repeat(64)), false);
});
t('newRevokeNonce: "revoke:" + 64 hex, 매번 다르다; isRevokeNonce 는 형식만 본다', () => {
  const a = newRevokeNonce(), b = newRevokeNonce();
  assert.match(a, /^revoke:[0-9a-f]{64}$/); assert.notEqual(a, b);
  assert.equal(isRevokeNonce(a), true); assert.equal(isRevokeNonce('revoke:' + 'g'.repeat(64)), false); assert.equal(isRevokeNonce(REG_PREFIX + 'a'.repeat(64)), false); assert.equal(isRevokeNonce(REVOKE_PREFIX), false);
});
process.exit(fails ? 1 : 0);
