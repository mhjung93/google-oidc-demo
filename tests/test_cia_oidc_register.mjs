// tests/test_cia_oidc_register.mjs — IdP 의 OIDC 래퍼 경로(스펙 2026-10-16 §3.1·§3.3). 격리 IdP + 발급자 스텁. :8545 필요(로그 배포). (chain)
import assert from 'node:assert/strict';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { createRegistration } from '../lib/mode3_wallet.js';
import { uidOf, regNonce, issueNonce, newRevokeNonce } from '../lib/mode3_oidc_nonce.js';
import { aridSOf, randomScalar, registerCtx, issueCtx, tagOf } from '../lib/mode3_credential.js';
import { getProvider } from './helpers/mode3_chain.mjs';
import { issueV11, regBody, TESTUSER_ATTRS } from './helpers/mode3_flow.mjs';

const cia = await startIsolatedCia({ oidc: true });
const stub = cia.oidc;
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const j = (o) => JSON.stringify(o);
/** 지갑이 하는 일을 흉내: 재료 → sub 에서 uid 선계산 → n 을 뽑아 tag 계산 → 등록 토큰(nonce = regNonce(tag)) → 등록용 π_IdP.
 *  (2026-11-13 스펙 no-pk-u §3.3: 토큰은 등록 키가 아니라 이 요청의 tag 에 묶인다.) body 는 /cia/register 본문의 지갑 쪽 부분. */
async function makeReg(sub, { nonce = null, aud, iss, expSeconds } = {}) {
  const uid = uidOf(stub.provider, sub);
  const reg = await createRegistration(BigInt(uid));
  const n = randomScalar();
  const tag = await tagOf({ s_u: reg.s_u, ctx: await registerCtx({ n }) });
  const id_token = await stub.mint({ sub, nonce: nonce ?? regNonce(tag), ...(aud ? { aud } : {}), ...(iss ? { iss } : {}), ...(expSeconds ? { expSeconds } : {}) });
  return { uid, reg, n, tag, id_token, body: await regBody(reg, uid, { n }) };
}
/** 발급 요청의 tag — 지갑이 Google 로 가기 전에 계산해 토큰 nonce(issueNonce) 에 넣는 값. issueV11 의 기본값(chainid 31337, allowAgent 0)과 맞춘다.
 *  n 은 지갑이 그때 뽑는 난수 — 발급 요청(issueV11 의 n)에 같은 값을 실어야 tag 가 맞는다. */
const issueTag = async (s_u, arid, r_rp, n) => tagOf({ s_u, ctx: await issueCtx({ arid_s: await aridSOf({ arid, r_rp }), chainid: 31337n, allowAgent: 0n, n }) });
try {
  await t('public_keys.oidc 가 스텁 발급자 설정을 공개한다(enabled·provider·clientId·issuer)', async () => {
    const k = (await cia.get('/cia/public_keys')).body;
    assert.deepEqual(k.oidc, { enabled: true, provider: stub.provider, clientId: stub.clientId, issuer: stub.issuer });
    assert.equal('providers' in k.oidc, false, '2026-11-10: zkID 쪽 연결(providers)은 없앴다 — RP 가 직접 받는다');
  });
  let first;
  await t('Google 경로 등록: 201, uid = uidOf(provider, sub), provider 기록, 데모 계정 경로와 같은 슬롯 배정', async () => {
    first = await makeReg('google-sub-1');
    const r = await cia.post('/cia/register', { id_token: first.id_token, ...first.body });
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.uid, first.uid); assert.equal(r.body.provider, stub.provider); assert.equal(typeof r.body.slot, 'number'); assert.ok(r.body.schemaHash);
    const acc = (await cia.adminGet('/cia/accounts')).body;
    const mine = (acc.accounts ?? acc).find((a) => String(a.uid) === first.uid); assert.ok(mine, j(acc).slice(0, 200)); assert.equal(mine.provider, stub.provider);
  });
  await t('같은 sub 의 재등록은 409 already registered(토큰·지갑 비밀이 새것이어도)', async () => {
    const again = await makeReg('google-sub-1');
    const r = await cia.post('/cia/register', { id_token: again.id_token, ...again.body });
    assert.equal(r.status, 409);
  });
  await t('nonce 가 요청의 tag 와 다르면 400 oidc_nonce_mismatch — 가로챈 토큰을 다른 지갑(s_u)으로 쓰는 재사용 차단, 계정은 생기지 않는다', async () => {
    const a = await makeReg('google-sub-2');
    const b = await makeReg('google-sub-2');   // 같은 uid, 다른 s_u — b 의 증명은 b 의 auid 로 유효하지만 토큰은 a 의 tag 에 묶였다
    const r = await cia.post('/cia/register', { id_token: a.id_token, ...b.body });
    assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, 'oidc_nonce_mismatch');
    const acc = (await cia.adminGet('/cia/accounts')).body;
    assert.equal((acc.accounts ?? acc).find((x) => String(x.uid) === a.uid), undefined, '거절된 등록은 계정을 만들지 않는다');
  });
  await t('폐기 토큰(revoke:)으로 등록 → 400 oidc_nonce_mismatch; 다른 aud → 401 oidc_invalid; 만료 → 401 oidc_invalid', async () => {
    const x = await makeReg('google-sub-3', { nonce: newRevokeNonce() });
    let r = await cia.post('/cia/register', { id_token: x.id_token, ...x.body }); assert.equal(r.status, 400); assert.equal(r.body.reason, 'oidc_nonce_mismatch');
    const y = await makeReg('google-sub-3', { aud: 'someone-else' });
    r = await cia.post('/cia/register', { id_token: y.id_token, ...y.body }); assert.equal(r.status, 401); assert.equal(r.body.reason, 'oidc_invalid');
    const z = await makeReg('google-sub-3', { expSeconds: -600 });
    r = await cia.post('/cia/register', { id_token: z.id_token, ...z.body }); assert.equal(r.status, 401); assert.equal(r.body.reason, 'oidc_invalid');
  });
  await t('지갑이 uid 를 잘못 선계산해 증명했으면 400 bad_idp_proof — IdP 는 토큰의 uid 로 공개 입력을 조립한다', async () => {
    const w = await makeReg('google-sub-4');
    const wrongUid = (BigInt(w.uid) + 1n).toString();
    const wrong = await regBody(await createRegistration(BigInt(wrongUid)), wrongUid, { n: w.n });   // uid+1 로 만든 auid·증명
    const r = await cia.post('/cia/register', { id_token: w.id_token, ...wrong });
    assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, 'bad_idp_proof');
  });
  // 리뷰 C1(2026-10-26): /cia/issue 의 암묵 등록(계정 없는 Google 사용자의 첫 로그인)은 **검증이 끝난 뒤에** 등록한다(2026-11-13 스펙 no-pk-u §3.2):
  // 발급 증명을 registration.auid 로 검증하고 토큰 nonce 를 그 tag 에 대조한 다음이다. 그러지 않으면 가로챈 issue 토큰 + 공격자의 auid 로 피해자 uid 가 선점된다.
  const provider = getProvider();
  const ISSUE_ARID = 33333333333333333333n;
  const accountOf = async (uid) => { const acc = (await cia.adminGet('/cia/accounts')).body; return (acc.accounts ?? acc).find((a) => String(a.uid) === uid); };
  /** 피해자 쪽 재료: 그 uid 의 등록 재료와, 이 지갑(s_u)·이 로그인(arid_s)의 tag 에 묶인 issue 토큰. */
  async function issueMaterial(sub) {
    const uid = uidOf(stub.provider, sub);
    const reg = await createRegistration(BigInt(uid));
    const r_rp = randomScalar(), n = randomScalar();
    const id_token = await stub.mint({ sub, nonce: issueNonce(await issueTag(reg.s_u, ISSUE_ARID, r_rp, n)) });
    const registration = { auid: reg.auid.toString() };
    const user = { uid: BigInt(uid), s_u: reg.s_u, auid: reg.auid, attrs: [...TESTUSER_ATTRS] };
    return { uid, reg, r_rp, n, id_token, registration, user };
  }
  await t('암묵 등록(issue 토큰 + registration{auid}, 발급 증명이 그 auid 로 맞음) → 200, 계정이 provider 로 생긴다', async () => {
    const v = await issueMaterial('google-sub-implicit-ok');
    const { r } = await issueV11(cia, v.user, { arid: ISSUE_ARID, r_rp: v.r_rp, n: v.n, provider, overrides: { id_token: v.id_token, registration: v.registration } });
    assert.equal(r.status, 200, j(r.body));
    const mine = await accountOf(v.uid); assert.ok(mine, '계정이 생겨야 한다'); assert.equal(mine.provider, stub.provider); assert.equal(mine.auid, v.reg.auid.toString());
  });
  await t('가로챈 issue 토큰 + 공격자의 auid·증명 → 400 oidc_nonce_mismatch; 피해자의 auid 를 대고 공격자 증명 → 400 bad_idp_proof — 어느 쪽도 계정을 만들지 않고, 피해자는 reg: 토큰으로 201 등록', async () => {
    const SUB = 'google-sub-squat';
    const v = await issueMaterial(SUB);
    const a = await createRegistration(BigInt(v.uid));   // 공격자: 피해자 uid 로 자기 s_u — 자기 auid 에 대한 발급 증명은 유효하다
    const attacker = { uid: BigInt(v.uid), s_u: a.s_u, auid: a.auid, attrs: [...TESTUSER_ATTRS] };
    // 공격자는 피해자의 r_rp·n 까지 그대로 쓴다(요청 본문에서 볼 수 있는 값이다) — 그래도 s_u 가 달라 tag 가 다르다
    const { r } = await issueV11(cia, attacker, { arid: ISSUE_ARID, r_rp: v.r_rp, n: v.n, provider, overrides: { id_token: v.id_token, registration: { auid: a.auid.toString() } } });
    assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, 'oidc_nonce_mismatch');   // 증명은 맞지만 tag 가 피해자 토큰의 것과 다르다
    assert.equal(await accountOf(v.uid), undefined, '공격자의 auid 로 계정이 생기면 안 된다');
    // 피해자의 auid 를 대면 공격자의 증명(다른 s_u)이 그 auid 로 검증되지 않는다 — nonce 대조까지 가지도 못한다
    const forged = await issueV11(cia, attacker, { arid: ISSUE_ARID, r_rp: v.r_rp, n: v.n, provider, overrides: { id_token: v.id_token, registration: v.registration } });
    assert.equal(forged.r.status, 400, j(forged.r.body)); assert.equal(forged.r.body.reason, 'bad_idp_proof');
    assert.equal(await accountOf(v.uid), undefined, '증명이 틀린 요청은 계정을 만들지 않는다');
    // 형식이 틀린 registration.auid 는 증명 검증 전에 400(상태 변경 없음)
    const bad = await issueV11(cia, attacker, { arid: ISSUE_ARID, r_rp: v.r_rp, n: v.n, provider, overrides: { id_token: v.id_token, registration: { auid: 'nope' } } });
    assert.equal(bad.r.status, 400, j(bad.r.body));
    assert.equal(await accountOf(v.uid), undefined);
    // 피해자는 여전히 자기 지갑으로 등록할 수 있다(uid 선점 안 됨)
    const n = randomScalar();
    const regTok = await stub.mint({ sub: SUB, nonce: regNonce(await tagOf({ s_u: v.reg.s_u, ctx: await registerCtx({ n }) })) });
    const ok = await cia.post('/cia/register', { id_token: regTok, ...(await regBody(v.reg, v.uid, { n })) });
    assert.equal(ok.status, 201, j(ok.body)); assert.equal(ok.body.uid, v.uid);
    assert.equal((await accountOf(v.uid)).auid, v.reg.auid.toString(), '등록된 것은 피해자의 auid 다');
  });
  await t('자기 폐기(id_token): revoke 토큰 → 200, 계정 disabled; 등록 토큰으로 폐기 → 400; 모르는 sub → 404', async () => {
    const tok = await stub.mint({ sub: 'google-sub-1', nonce: newRevokeNonce() });
    const r = await cia.post('/cia/account/self_revoke', { id_token: tok }); assert.equal(r.status, 200, j(r.body));
    const acc = (await cia.adminGet('/cia/accounts')).body; const mine = (acc.accounts ?? acc).find((a) => String(a.uid) === first.uid); assert.equal(mine.disabled, true);
    const regTok = await stub.mint({ sub: 'google-sub-1', nonce: regNonce(first.tag) });
    assert.equal((await cia.post('/cia/account/self_revoke', { id_token: regTok })).status, 400);
    assert.equal((await cia.post('/cia/account/self_revoke', { id_token: await stub.mint({ sub: 'never-registered', nonce: newRevokeNonce() }) })).status, 404);
  });
  await t('데모 계정 경로는 그대로(uid·pwd 등록 201 + 응답에 uid·provider demo; 비밀번호 틀리면 401)', async () => {
    const reg = await createRegistration(12345n);
    const r = await cia.post('/cia/register', { uid: '12345', pwd: 'password123', ...(await regBody(reg, '12345')) });
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.uid, '12345'); assert.equal(r.body.provider, 'demo');
    const reg2 = await createRegistration(67890n);
    assert.equal((await cia.post('/cia/register', { uid: '67890', pwd: 'wrong', ...(await regBody(reg2, '67890')) })).status, 401);
  });
  // 2026-11-09(연결 로그인 L5): 2026-11-06 의 "발급 중 첫 번에 자동 연결" 은 없앴다 — 연결은 /user, 로그인은 인증 창(tests/test_cia_linked_logins.mjs).
  await t('아이디(demo) 계정의 발급에 다른 sub 의 issue 토큰 → 400 use_auth_window(연결되지 않는다, 같은 sub 다시 해도 400); 없는 uid 는 uid_mismatch 그대로', async () => {
    const uid = 67890n;   // 시드 데모 계정(password123) — 위 '데모 계정 경로' 케이스는 이 uid 를 등록하지 않는다
    const reg = await createRegistration(uid);
    const r0 = await cia.post('/cia/register', { uid: uid.toString(), pwd: 'alicepw', ...(await regBody(reg, uid.toString())) });   // alice(67890) 의 비밀번호
    assert.equal(r0.status, 201, j(r0.body));
    const user = { uid, s_u: reg.s_u, auid: reg.auid, attrs: [...TESTUSER_ATTRS] };
    const issueWith = async (sub) => { const r_rp = randomScalar(), n = randomScalar(); const id_token = await stub.mint({ sub, nonce: issueNonce(await issueTag(reg.s_u, ISSUE_ARID, r_rp, n)) }); return issueV11(cia, user, { arid: ISSUE_ARID, r_rp, n, provider, overrides: { id_token } }); };
    const { r: first } = await issueWith('google-link-A');
    assert.equal(first.status, 400, j(first.body)); assert.equal(first.body.reason, 'use_auth_window');
    const acc = (await cia.adminGet('/cia/accounts')).body; const mine = (acc.accounts ?? acc).find((a) => String(a.uid) === uid.toString());
    assert.equal(mine.provider, 'demo', '계정 종류는 그대로 demo');
    const { r: again } = await issueWith('google-link-A'); assert.equal(again.status, 400, j(again.body), '자동 연결이 없으므로 두 번째도 400');
    const ghost = await createRegistration(55556n);
    const r_rp = randomScalar(), nG = randomScalar();
    const { r: g } = await issueV11(cia, { uid: 55556n, s_u: ghost.s_u, auid: ghost.auid, attrs: [...TESTUSER_ATTRS] }, { arid: ISSUE_ARID, r_rp, n: nG, provider, overrides: { id_token: await stub.mint({ sub: 'google-link-C', nonce: issueNonce(await issueTag(ghost.s_u, ISSUE_ARID, r_rp, nG)) }) } });
    assert.equal(g.status, 403, j(g.body)); assert.equal(g.body.reason, 'uid_mismatch');
  });

  await t('형식: id_token 과 uid/pwd 가 둘 다 없으면 400; 둘 다 있으면 id_token 을 우선하지 않고 400(모호)', async () => {
    assert.equal((await cia.post('/cia/register', { auid: '1' })).status, 400);
    const w = await makeReg('google-sub-5');
    assert.equal((await cia.post('/cia/register', { id_token: w.id_token, uid: '12345', pwd: 'password123', ...w.body })).status, 400);
  });
} finally { await cia.stop(); }
// oidc 를 끈 IdP: id_token 경로는 503 oidc_disabled, public_keys.oidc.enabled=false
const off = await startIsolatedCia();
try {
  await t('OIDC 설정이 없는 IdP: public_keys.oidc.enabled=false, id_token 등록·폐기는 503 oidc_disabled', async () => {
    const k = (await off.get('/cia/public_keys')).body; assert.equal(k.oidc.enabled, false); assert.equal(k.oidc.clientId, null);
    const r = await off.post('/cia/register', { id_token: 'a.b.c', auid: '1' }); assert.equal(r.status, 503); assert.equal(r.body.reason, 'oidc_disabled');
    assert.equal((await off.post('/cia/account/self_revoke', { id_token: 'a.b.c' })).status, 503);
  });
} finally { await off.stop(); }
process.exit(fails ? 1 : 0);
