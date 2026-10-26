// tests/test_cia_oidc_register.mjs — IdP 의 OIDC 래퍼 경로(스펙 2026-10-16 §3.1·§3.3). 격리 IdP + 발급자 스텁. :8545 필요(로그 배포). (chain)
import assert from 'node:assert/strict';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { createRegistration, signRegistration } from '../lib/mode3_wallet.js';
import { uidOf, regNonce, issueNonce, newRevokeNonce } from '../lib/mode3_oidc_nonce.js';
import { aridSOf, randomScalar } from '../lib/mode3_credential.js';
import { getProvider } from './helpers/mode3_chain.mjs';
import { issueV11, TESTUSER_ATTRS } from './helpers/mode3_flow.mjs';

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
  // 리뷰 C1(2026-10-26): /cia/issue 의 암묵 등록(계정 없는 Google 사용자의 첫 로그인)은 토큰 nonce 가 registration.pk_u 에 묶였는지
  // 등록 **전에** 본다. 그러지 않으면 가로챈 issue 토큰 + 공격자 registration 으로 피해자 uid 가 공격자 키로 영구 등록된다.
  const provider = getProvider();
  const ISSUE_ARID = 33333333333333333333n;
  /** 피해자 쪽 재료: 그 uid 의 등록 재료와, 그 pk_u·이 로그인(arid_s)에 묶인 issue 토큰. */
  async function issueMaterial(sub) {
    const uid = uidOf(stub.provider, sub);
    const reg = await createRegistration(BigInt(uid));
    const pk_u = { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() };
    const r_rp = randomScalar();
    const arid_s = await aridSOf({ arid: ISSUE_ARID, r_rp });
    const id_token = await stub.mint({ sub, nonce: issueNonce(pk_u, arid_s) });
    const registration = { auid: reg.auid.toString(), pk_u, sig_reg: await signRegistration(reg.sk_u, BigInt(uid), reg.auid) };
    const user = { uid: BigInt(uid), s_u: reg.s_u, auid: reg.auid, sk_u: reg.sk_u, attrs: [...TESTUSER_ATTRS] };
    return { uid, reg, pk_u, r_rp, id_token, registration, user };
  }
  await t('암묵 등록(issue 토큰 + registration, pk 일치) → 200, 계정이 provider 로 생긴다', async () => {
    const v = await issueMaterial('google-sub-implicit-ok');
    const { r } = await issueV11(cia, v.user, { arid: ISSUE_ARID, r_rp: v.r_rp, provider, overrides: { id_token: v.id_token, registration: v.registration } });
    assert.equal(r.status, 200, j(r.body));
    const acc = (await cia.adminGet('/cia/accounts')).body;
    const mine = (acc.accounts ?? acc).find((a) => String(a.uid) === v.uid); assert.ok(mine, '계정이 생겨야 한다'); assert.equal(mine.provider, stub.provider);
  });
  await t('가로챈 issue 토큰 + 공격자 registration(pk_A) → 400 oidc_nonce_mismatch, 계정이 생기지 않고 피해자는 reg: 토큰으로 201 등록', async () => {
    const SUB = 'google-sub-squat';
    const v = await issueMaterial(SUB);
    const a = await createRegistration(BigInt(v.uid));   // 공격자: 피해자 uid 로 자기 키(sk_A) 서명 — sig_reg 는 자기 키라 통과한다
    const regA = { auid: a.auid.toString(), pk_u: { x: a.pk_u.x.toString(), y: a.pk_u.y.toString() }, sig_reg: await signRegistration(a.sk_u, BigInt(v.uid), a.auid) };
    const attacker = { uid: BigInt(v.uid), s_u: a.s_u, auid: a.auid, sk_u: a.sk_u, attrs: [...TESTUSER_ATTRS] };
    const { r } = await issueV11(cia, attacker, { arid: ISSUE_ARID, r_rp: v.r_rp, provider, overrides: { id_token: v.id_token, registration: regA } });
    assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, 'oidc_nonce_mismatch');
    const acc = (await cia.adminGet('/cia/accounts')).body;
    assert.equal((acc.accounts ?? acc).find((a2) => String(a2.uid) === v.uid), undefined, '공격자 키로 계정이 생기면 안 된다');
    // 형식이 틀린 registration.pk_u 는 nonce 대조 전에 400(상태 변경 없음)
    const bad = await issueV11(cia, attacker, { arid: ISSUE_ARID, r_rp: v.r_rp, provider, overrides: { id_token: v.id_token, registration: { ...regA, pk_u: { x: 'nope' } } } });
    assert.equal(bad.r.status, 400, j(bad.r.body));
    // 피해자는 여전히 자기 키로 등록할 수 있다(uid 선점 안 됨)
    const regTok = await stub.mint({ sub: SUB, nonce: regNonce(v.pk_u) });
    const ok = await cia.post('/cia/register', { id_token: regTok, ...v.registration });
    assert.equal(ok.status, 201, j(ok.body)); assert.equal(ok.body.uid, v.uid);
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
