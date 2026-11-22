// tests/test_cia_passkey_signup.mjs — "패스키로 로그인" 이 계정을 스스로 만드는 길의 zkIdP 쪽(스펙 2026-11-20 passkey-google-signup §3).
// uid 예약(POST /cia/signup/reserve) → Google 토큰(대역 발급자)·π_IdP 로 가입+등록(POST /cia/register signup:true). 격리 IdP + 발급자 스텁. :8545 필요(로그 배포). (chain)
import assert from 'node:assert/strict';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { createRegistration } from '../lib/mode3_wallet.js';
import { regNonce } from '../lib/mode3_oidc_nonce.js';
import { randomScalar, registerCtx, tagOf } from '../lib/mode3_credential.js';
import { regBody } from './helpers/mode3_flow.mjs';

const RELAY = 'https://127.0.0.1:5100/google-relay';
const cia = await startIsolatedCia({ oidc: true, env: { MODE3_OIDC_REDIRECT_URI: RELAY, MODE3_RP_GOOGLE_CLIENT_ID_DENY: 'rp-only-client-a, rp-only-client-b' } });   // 서비스 ID 목록에 zkIdP 의 ID 가 없으면 가입은 열린다
const stub = cia.oidc;
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const j = (o) => JSON.stringify(o);
const accounts = async () => { const a = (await cia.adminGet('/cia/accounts')).body; return a.accounts ?? a; };
const reserve = async () => { const r = await cia.post('/cia/signup/reserve', {}); assert.equal(r.status, 200, j(r.body)); assert.match(String(r.body.uid), /^[1-9][0-9]*$/); return String(r.body.uid); };
/** 지갑이 하는 일: (예약받은 uid) → 재료 s_u → n → 등록 증명 → 그 tag 에 묶인 Google 토큰. seed(hex)를 주면 그 패스키로(복구·다른 요청), 안 주면 새 패스키. */
async function makeSignup({ uid, sub, email = `${sub}@example.com`, verified = true, seed = null, claims = null }) {
  const reg = seed === null ? await createRegistration(BigInt(uid)) : await createRegistration(BigInt(uid), Buffer.from(seed, 'hex'));
  const n = randomScalar();
  const tag = await tagOf({ s_u: reg.s_u, ctx: await registerCtx({ n }) });
  const id_token = await stub.mint({ sub, nonce: regNonce(tag), extra: claims ?? { email, email_verified: verified } });
  return { uid, reg, n, id_token, email, body: { signup: true, uid, id_token, ...(await regBody(reg, uid, { n })) } };
}
try {
  await t('public_keys.oidc.signup 이 Google 로 갈 주소와 돌아올 주소를 공개한다', async () => {
    const k = (await cia.get('/cia/public_keys')).body;
    assert.equal(k.issueAuth, 'key');
    assert.deepEqual(k.oidc.signup, { authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth', redirectUri: RELAY });
  });
  await t('예약: uid 를 순번으로 내준다 — 계정은 아직 없다', async () => {
    const before = (await accounts()).length;
    const a = await reserve(), b = await reserve();
    assert.equal(BigInt(b), BigInt(a) + 1n);
    assert.equal((await accounts()).length, before, '예약만으로 계정이 생기지 않는다');
  });
  let first;
  await t('가입: 201 — 아이디는 확인된 이메일, 등록까지 끝난다, 비밀번호 로그인은 안 된다', async () => {
    first = await makeSignup({ uid: await reserve(), sub: 'g-sub-1', email: 'Jihoo.Kim@Example.com' });
    const r = await cia.post('/cia/register', first.body);
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.uid, first.uid); assert.equal(r.body.provider, 'demo'); assert.equal(r.body.email, 'Jihoo.Kim@Example.com'); assert.equal(typeof r.body.slot, 'number');
    const mine = (await accounts()).find((a) => String(a.uid) === first.uid);
    assert.ok(mine, '계정이 없다'); assert.equal(mine.id, 'Jihoo.Kim@Example.com'); assert.equal(mine.auid, first.reg.auid.toString()); assert.equal(mine.provider, 'demo');
    const lg = await cia.post('/cia/user/login', { id: 'Jihoo.Kim@Example.com', pwd: 'whatever-pass' });
    assert.equal(lg.status, 401, j(lg.body));
  });
  await t('같은 예약을 두 번 쓰지 못한다 — 다른 Google 계정이 그 uid 로 오면 409 signup_reservation_invalid', async () => {
    const x = await makeSignup({ uid: first.uid, sub: 'g-sub-other' });
    const r = await cia.post('/cia/register', x.body);
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'signup_reservation_invalid');
  });
  await t('예약하지 않은 uid 는 409 signup_reservation_invalid — 계정이 생기지 않는다', async () => {
    const x = await makeSignup({ uid: '987654321', sub: 'g-sub-noreserve' });
    const r = await cia.post('/cia/register', x.body);
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'signup_reservation_invalid');
    assert.equal((await accounts()).find((a) => String(a.uid) === '987654321'), undefined);
  });
  await t('확인되지 않은 이메일·이메일 없는 토큰은 403 signup_email_unverified', async () => {
    const uid = await reserve();
    let r = await cia.post('/cia/register', (await makeSignup({ uid, sub: 'g-sub-unv', verified: false })).body);
    assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.reason, 'signup_email_unverified');
    r = await cia.post('/cia/register', (await makeSignup({ uid, sub: 'g-sub-unv', claims: {} })).body);
    assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.reason, 'signup_email_unverified');
    assert.equal((await accounts()).find((a) => String(a.uid) === uid), undefined);
  });
  await t('토큰이 다른 패스키의 요청에 묶여 있으면 400 oidc_nonce_mismatch — 계정이 생기지 않고, 예약은 남아 같은 uid 로 다시 가입할 수 있다', async () => {
    const uid = await reserve();
    const a = await makeSignup({ uid, sub: 'g-sub-2' }), b = await makeSignup({ uid, sub: 'g-sub-2' });   // 같은 uid·같은 Google 계정, 다른 패스키
    let r = await cia.post('/cia/register', { ...b.body, id_token: a.id_token });
    assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, 'oidc_nonce_mismatch');
    assert.equal((await accounts()).find((x) => String(x.uid) === uid), undefined);
    r = await cia.post('/cia/register', a.body);
    assert.equal(r.status, 201, j(r.body));
  });
  await t('같은 Google 계정의 두 번째 가입: 409 signup_exists 와 기존 uid — 새 계정을 만들지 않는다', async () => {
    const uid = await reserve();
    const again = await makeSignup({ uid, sub: 'g-sub-1', seed: first.reg.seed });
    const r = await cia.post('/cia/register', again.body);
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'signup_exists'); assert.equal(r.body.uid, first.uid);
    assert.equal((await accounts()).find((a) => String(a.uid) === uid), undefined);
  });
  await t('복구: 같은 Google 계정 + 같은 패스키가 기존 uid 로 오면 201 restored — 슬롯은 그대로', async () => {
    const slot0 = (await accounts()).find((a) => String(a.uid) === first.uid).slot;
    const back = await makeSignup({ uid: first.uid, sub: 'g-sub-1', seed: first.reg.seed });
    const r = await cia.post('/cia/register', back.body);
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.restored, true); assert.equal(r.body.slot, slot0); assert.equal(r.body.uid, first.uid);
  });
  await t('같은 Google 계정 + 다른 패스키가 기존 uid 로 오면 409 signup_other_passkey', async () => {
    const other = await makeSignup({ uid: first.uid, sub: 'g-sub-1' });
    const r = await cia.post('/cia/register', other.body);
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'signup_other_passkey');
  });
  await t('signup 표시가 문자열 "true" 등 다른 값이면 받지 않는다(400) · uid 가 10진이 아니면 400', async () => {
    const x = await makeSignup({ uid: await reserve(), sub: 'g-sub-3' });
    let r = await cia.post('/cia/register', { ...x.body, signup: 'true' }); assert.equal(r.status, 400, j(r.body));
    r = await cia.post('/cia/register', { ...x.body, uid: 'abc' }); assert.equal(r.status, 400, j(r.body));
  });
} finally { await cia.stop(); }
// 꺼진 구성: 돌아올 주소가 없거나 발급 정책이 code 면 이 길은 없다.
// C2(2026-11-22): zkIdP 의 Google 클라이언트 ID 가 서비스의 ID(MODE3_RP_GOOGLE_CLIENT_ID_DENY)나 Mode 1 공유 ID(GOOGLE_CLIENT_ID)와 같아도 닫는다 —
// 같은 aud 면 악의적 서비스가 자기가 고른 nonce(=공격자 패스키의 tag)로 피해자의 토큰을 받아 피해자 Google 계정의 zkIdP 계정을 선점한다. 스텁의 ID 는 mode3-test-client.
for (const [name, opts] of [['돌아올 주소 없음', { oidc: true }], ['발급 정책 code', { oidc: true, env: { MODE3_OIDC_REDIRECT_URI: RELAY, CIA_ISSUE_AUTH: 'code' } }],
  ['서비스와 같은 클라이언트 ID', { oidc: true, env: { MODE3_OIDC_REDIRECT_URI: RELAY, MODE3_RP_GOOGLE_CLIENT_ID_DENY: 'rp-only-client-a, mode3-test-client' } }],
  ['Mode 1 공유 ID 와 같은 클라이언트 ID', { oidc: true, env: { MODE3_OIDC_REDIRECT_URI: RELAY, GOOGLE_CLIENT_ID: 'mode3-test-client' } }]]) {
  const off = await startIsolatedCia(opts);
  try {
    await t(`꺼진 구성(${name}): public_keys 에 signup 이 없고 예약·가입은 403 signup_disabled`, async () => {
      const k = (await off.get('/cia/public_keys')).body; assert.equal('signup' in k.oidc, false, j(k.oidc));
      let r = await off.post('/cia/signup/reserve', {}); assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.reason, 'signup_disabled');
      const reg = await createRegistration(100001n); const n = randomScalar();
      const id_token = await off.oidc.mint({ sub: 'x', nonce: regNonce(await tagOf({ s_u: reg.s_u, ctx: await registerCtx({ n }) })), extra: { email: 'x@example.com', email_verified: true } });
      r = await off.post('/cia/register', { signup: true, uid: '100001', id_token, ...(await regBody(reg, '100001', { n })) });
      assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.reason, 'signup_disabled');
    });
  } finally { await off.stop(); }
}
console.log(fails ? `\n${fails} 실패` : '\n모두 통과');
process.exit(fails ? 1 : 0);   // 증명 라이브러리의 워커가 남아 있어 스스로 끝나지 않는다
