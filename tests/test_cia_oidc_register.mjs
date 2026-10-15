// tests/test_cia_oidc_register.mjs — IdP 의 OIDC 래퍼 경로(스펙 2026-10-16 §3.1·§3.3). 격리 IdP + 발급자 스텁. :8545 필요(로그 배포). (chain)
import assert from 'node:assert/strict';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { createRegistration, signRegistration } from '../lib/mode3_wallet.js';
import { uidOf, regNonce, newRevokeNonce } from '../lib/mode3_oidc_nonce.js';

const cia = await startIsolatedCia({ oidc: true });
const stub = cia.oidc;
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const j = (o) => JSON.stringify(o);
/** 지갑이 하는 일을 흉내: 재료 → sub 에서 uid 선계산 → 등록 토큰(nonce = regNonce) → 서명. */
async function makeReg(sub, { nonce = null, aud, iss, expSeconds } = {}) {
  const reg = await createRegistration(0n);   // s_u·sk_u·pk_u 만 쓴다 — auid 는 진짜 uid 로 다시 만든다
  const uid = uidOf(stub.provider, sub);
  const { auidOf } = await import('../lib/mode3_credential.js');
  const auid = await auidOf({ uid: BigInt(uid), s_u: reg.s_u });
  const pk_u = { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() };
  const id_token = await stub.mint({ sub, nonce: nonce ?? regNonce(pk_u), ...(aud ? { aud } : {}), ...(iss ? { iss } : {}), ...(expSeconds ? { expSeconds } : {}) });
  return { uid, auid: auid.toString(), pk_u, sig_reg: await signRegistration(reg.sk_u, BigInt(uid), auid), id_token, sk_u: reg.sk_u };
}
try {
  await t('public_keys.oidc 가 스텁 발급자 설정을 공개한다(enabled·provider·clientId·issuer)', async () => {
    const k = (await cia.get('/cia/public_keys')).body;
    assert.deepEqual(k.oidc, { enabled: true, provider: stub.provider, clientId: stub.clientId, issuer: stub.issuer });
  });
  let first;
  await t('Google 경로 등록: 201, uid = uidOf(provider, sub), provider 기록, 데모 계정 경로와 같은 슬롯 배정', async () => {
    first = await makeReg('google-sub-1');
    const r = await cia.post('/cia/register', { id_token: first.id_token, auid: first.auid, pk_u: first.pk_u, sig_reg: first.sig_reg });
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.uid, first.uid); assert.equal(r.body.provider, stub.provider); assert.equal(typeof r.body.slot, 'number'); assert.ok(r.body.schemaHash);
    const acc = (await cia.adminGet('/cia/accounts')).body;
    const mine = (acc.accounts ?? acc).find((a) => String(a.uid) === first.uid); assert.ok(mine, j(acc).slice(0, 200)); assert.equal(mine.provider, stub.provider);
  });
  await t('같은 sub 의 재등록은 409 already registered(토큰·키 재료가 새것이어도)', async () => {
    const again = await makeReg('google-sub-1');
    const r = await cia.post('/cia/register', { id_token: again.id_token, auid: again.auid, pk_u: again.pk_u, sig_reg: again.sig_reg });
    assert.equal(r.status, 409);
  });
  await t('nonce 가 요청의 pk_u 와 다르면 400 oidc_nonce_mismatch — 가로챈 토큰을 다른 키로 쓰는 재사용 차단', async () => {
    const a = await makeReg('google-sub-2');
    const b = await makeReg('google-sub-2');   // 다른 키 재료
    const r = await cia.post('/cia/register', { id_token: a.id_token, auid: b.auid, pk_u: b.pk_u, sig_reg: b.sig_reg });
    assert.equal(r.status, 400); assert.equal(r.body.reason, 'oidc_nonce_mismatch');
  });
  await t('폐기 토큰(revoke:)으로 등록 → 400 oidc_nonce_mismatch; 다른 aud → 401 oidc_invalid; 만료 → 401 oidc_invalid', async () => {
    const x = await makeReg('google-sub-3', { nonce: newRevokeNonce() });
    let r = await cia.post('/cia/register', { id_token: x.id_token, auid: x.auid, pk_u: x.pk_u, sig_reg: x.sig_reg }); assert.equal(r.status, 400); assert.equal(r.body.reason, 'oidc_nonce_mismatch');
    const y = await makeReg('google-sub-3', { aud: 'someone-else' });
    r = await cia.post('/cia/register', { id_token: y.id_token, auid: y.auid, pk_u: y.pk_u, sig_reg: y.sig_reg }); assert.equal(r.status, 401); assert.equal(r.body.reason, 'oidc_invalid');
    const z = await makeReg('google-sub-3', { expSeconds: -600 });
    r = await cia.post('/cia/register', { id_token: z.id_token, auid: z.auid, pk_u: z.pk_u, sig_reg: z.sig_reg }); assert.equal(r.status, 401); assert.equal(r.body.reason, 'oidc_invalid');
  });
  await t('지갑이 uid 를 잘못 선계산해 서명했으면 400 bad_registration_signature', async () => {
    const w = await makeReg('google-sub-4');
    const { signRegistration: sr } = await import('../lib/mode3_wallet.js');
    const wrongSig = await sr(w.sk_u, BigInt(w.uid) + 1n, BigInt(w.auid));
    const r = await cia.post('/cia/register', { id_token: w.id_token, auid: w.auid, pk_u: w.pk_u, sig_reg: wrongSig });
    assert.equal(r.status, 400); assert.equal(r.body.error, 'bad_registration_signature');
  });
  await t('자기 폐기(id_token): revoke 토큰 → 200, 계정 disabled; 등록 토큰으로 폐기 → 400; 모르는 sub → 404', async () => {
    const tok = await stub.mint({ sub: 'google-sub-1', nonce: newRevokeNonce() });
    const r = await cia.post('/cia/account/self_revoke', { id_token: tok }); assert.equal(r.status, 200, j(r.body));
    const acc = (await cia.adminGet('/cia/accounts')).body; const mine = (acc.accounts ?? acc).find((a) => String(a.uid) === first.uid); assert.equal(mine.disabled, true);
    const regTok = await stub.mint({ sub: 'google-sub-1', nonce: regNonce(first.pk_u) });
    assert.equal((await cia.post('/cia/account/self_revoke', { id_token: regTok })).status, 400);
    assert.equal((await cia.post('/cia/account/self_revoke', { id_token: await stub.mint({ sub: 'never-registered', nonce: newRevokeNonce() }) })).status, 404);
  });
  await t('데모 계정 경로는 그대로(uid·pwd 등록 201 + 응답에 uid·provider demo; 비밀번호 틀리면 401)', async () => {
    const reg = await createRegistration(12345n);
    const r = await cia.post('/cia/register', { uid: '12345', pwd: 'password123', auid: reg.auid.toString(), pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() }, sig_reg: await signRegistration(reg.sk_u, 12345n, reg.auid) });
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.uid, '12345'); assert.equal(r.body.provider, 'demo');
    const reg2 = await createRegistration(67890n);
    assert.equal((await cia.post('/cia/register', { uid: '67890', pwd: 'wrong', auid: reg2.auid.toString(), pk_u: { x: reg2.pk_u.x.toString(), y: reg2.pk_u.y.toString() }, sig_reg: await signRegistration(reg2.sk_u, 67890n, reg2.auid) })).status, 401);
  });
  await t('형식: id_token 과 uid/pwd 가 둘 다 없으면 400; 둘 다 있으면 id_token 을 우선하지 않고 400(모호)', async () => {
    assert.equal((await cia.post('/cia/register', { auid: '1', pk_u: { x: '1', y: '1' }, sig_reg: { R8x: '1', R8y: '1', S: '1' } })).status, 400);
    const w = await makeReg('google-sub-5');
    assert.equal((await cia.post('/cia/register', { id_token: w.id_token, uid: '12345', pwd: 'password123', auid: w.auid, pk_u: w.pk_u, sig_reg: w.sig_reg })).status, 400);
  });
} finally { await cia.stop(); }
// oidc 를 끈 IdP: id_token 경로는 503 oidc_disabled, public_keys.oidc.enabled=false
const off = await startIsolatedCia();
try {
  await t('OIDC 설정이 없는 IdP: public_keys.oidc.enabled=false, id_token 등록·폐기는 503 oidc_disabled', async () => {
    const k = (await off.get('/cia/public_keys')).body; assert.equal(k.oidc.enabled, false); assert.equal(k.oidc.clientId, null);
    const r = await off.post('/cia/register', { id_token: 'a.b.c', auid: '1', pk_u: { x: '1', y: '1' }, sig_reg: { R8x: '1', R8y: '1', S: '1' } }); assert.equal(r.status, 503); assert.equal(r.body.reason, 'oidc_disabled');
    assert.equal((await off.post('/cia/account/self_revoke', { id_token: 'a.b.c' })).status, 503);
  });
} finally { await off.stop(); }
process.exit(fails ? 1 : 0);
