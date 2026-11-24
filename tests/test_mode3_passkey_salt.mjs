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


// ---- 휴대폰 패스키(스펙 2026-11-19 login-flow-and-phone-passkey P1·P2): 힌트·transports 가 WebAuthn 옵션에 실리고, 인증기의 공개 정보를 돌려준다 ----
{
  const RP = 'wallet.zkd.test';
  globalThis.location = { hostname: RP };
  globalThis.window.PublicKeyCredential = function () {};
  globalThis.window.isSecureContext = true;
  const calls = [];
  const prfOut = new Uint8Array(32).fill(5).buffer;
  const authData = (flags) => { const b = new Uint8Array(37); b[32] = flags; return b.buffer; };
  const fake = {
    create: async ({ publicKey }) => { calls.push(['create', publicKey]); return { rawId: new Uint8Array([1, 2, 3]).buffer, authenticatorAttachment: 'cross-platform',
      response: { getTransports: () => ['hybrid', 'internal'], getAuthenticatorData: () => authData(0x01 | 0x04 | 0x08 | 0x10) }, getClientExtensionResults: () => ({ prf: { enabled: true } }) }; },
    get: async ({ publicKey }) => { calls.push(['get', publicKey]); return { rawId: new Uint8Array([1, 2, 3]).buffer, authenticatorAttachment: 'cross-platform',
      response: { authenticatorData: authData(0x01 | 0x04 | 0x08) }, getClientExtensionResults: () => ({ prf: { results: { first: prfOut } } }) }; },
  };
  Object.defineProperty(globalThis, 'navigator', { value: { credentials: fake }, configurable: true });

  await t('derivePrf: hints·transports 를 주면 옵션에 실린다', async () => {
    calls.length = 0;
    const d = await P.derivePrf({ credentialId: 'AQID', rpId: RP, hints: ['hybrid'], transports: ['hybrid', 'internal'] });
    const [, pk] = calls[0];
    assert.deepEqual(pk.hints, ['hybrid']);
    assert.deepEqual(pk.allowCredentials[0].transports, ['hybrid', 'internal']);
    assert.equal(d.credentialId, 'AQID');
    assert.deepEqual(d.info, { attachment: 'cross-platform', transports: null, backupEligible: true, backedUp: false });
  });
  await t('derivePrf: 안 주면 옵션에 hints·transports 키가 없다(지금까지와 같다)', async () => {
    calls.length = 0;
    await P.derivePrf({ credentialId: 'AQID', rpId: RP });
    const [, pk] = calls[0];
    assert.equal('hints' in pk, false);
    assert.equal('transports' in pk.allowCredentials[0], false);
  });
  await t('createPasskey: hints 가 만들기와 뒤따르는 확인 계산 둘 다에 실리고, 공개 정보(붙는 방식·transports·동기화 표시)를 돌려준다', async () => {
    calls.length = 0;
    const c = await P.createPasskey({ rpId: RP, rpName: 'zk 지갑', hints: ['hybrid'] });
    assert.deepEqual(calls.map((x) => x[0]), ['create', 'get']);
    assert.deepEqual(calls[0][1].hints, ['hybrid']);
    assert.deepEqual(calls[1][1].hints, ['hybrid']);
    assert.deepEqual(calls[1][1].allowCredentials[0].transports, ['hybrid', 'internal']);
    assert.deepEqual(c.info, { attachment: 'cross-platform', transports: ['hybrid', 'internal'], backupEligible: true, backedUp: true });
    assert.equal(typeof c.s_u, 'string');
  });
  await t('모르는 힌트·transports 는 거른다', async () => {
    calls.length = 0;
    await P.derivePrf({ credentialId: 'AQID', rpId: RP, hints: ['hybrid', 'evil', 7], transports: ['usb', '<x>', 'hybrid'] });
    assert.deepEqual(calls[0][1].hints, ['hybrid']);
    assert.deepEqual(calls[0][1].allowCredentials[0].transports, ['usb', 'hybrid']);
  });
}

// ---- 패스키 봉투 열쇠(envKey)·excludeCredentials (2026-11-24 salt 봉투 Task 3) ----
{
  const { envKeyFromPrf, sealSalt, openSalt } = await import('../lib/mode3_salt_envelope.js');
  const RP = 'wallet.zkd.test';
  globalThis.location = { hostname: RP };
  const prfOut = new Uint8Array(32).map((_, i) => i * 3 + 2);
  const calls = [];
  let createError = null;
  const fake = {
    create: async ({ publicKey }) => { calls.push(['create', publicKey]); if (createError) throw createError; return { rawId: new Uint8Array([9, 8, 7]).buffer, authenticatorAttachment: 'platform', response: {}, getClientExtensionResults: () => ({ prf: { enabled: true } }) }; },
    get: async ({ publicKey }) => { calls.push(['get', publicKey]); return { rawId: new Uint8Array([9, 8, 7]).buffer, authenticatorAttachment: 'platform', response: {}, getClientExtensionResults: () => ({ prf: { results: { first: prfOut.buffer.slice(0) } } }) }; },
  };
  Object.defineProperty(globalThis, 'navigator', { value: { credentials: fake }, configurable: true });
  const sealArgs = { s_u: '12345', uid: 'u1', id: 'e1', kind: 'passkey', credentialId: 'CQgH' };

  await t('derivePrf 의 envKey 는 추출 불가 AES-GCM 키고, Task 1 envKeyFromPrf 로 같은 PRF 에서 만든 열쇠로 봉투가 열린다', async () => {
    const d = await P.derivePrf({ credentialId: 'CQgH', rpId: RP });
    assert.equal(d.envKey.extractable, false);
    assert.equal(d.envKey.algorithm.name, 'AES-GCM');
    const ct = await sealSalt({ key: d.envKey, ...sealArgs });
    assert.equal(await openSalt({ key: await envKeyFromPrf(new Uint8Array(prfOut)), ct, ...sealArgs }), '12345');
  });
  await t('salt 유도는 그대로(s_u 기대값)', async () => {
    const d = await P.derivePrf({ credentialId: 'CQgH', rpId: RP });
    assert.equal(d.s_u, expected(prfOut));
  });
  await t('createPasskey 도 envKey 를 돌려주고 새 credential 의 PRF 에서 나온다', async () => {
    const c = await P.createPasskey({ rpId: RP });
    const ct = await sealSalt({ key: await envKeyFromPrf(new Uint8Array(prfOut)), ...sealArgs });
    assert.equal(await openSalt({ key: c.envKey, ct, ...sealArgs }), '12345');
  });
  await t('excludeCredentialIds 는 excludeCredentials 로 가고, 안 주면 키가 없다', async () => {
    calls.length = 0;
    await P.createPasskey({ rpId: RP, excludeCredentialIds: ['AQID', 'CQgH'] });
    assert.deepEqual(calls[0][1].excludeCredentials.map((x) => [x.type, [...x.id]]), [['public-key', [1, 2, 3]], ['public-key', [9, 8, 7]]]);
    calls.length = 0;
    await P.createPasskey({ rpId: RP });
    assert.equal('excludeCredentials' in calls[0][1], false);
  });
  await t('인증기가 InvalidStateError 로 거절하면 passkey_already_registered', async () => {
    createError = Object.assign(new Error('dup'), { name: 'InvalidStateError' });
    try { await assert.rejects(P.createPasskey({ rpId: RP, excludeCredentialIds: ['CQgH'] }), (e) => e.reason === 'passkey_already_registered'); }
    finally { createError = null; }
  });
}

if (fails) { console.log(`\n${fails} failed`); process.exit(1); }
console.log('\nall passed');
