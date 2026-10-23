// Task 10(B1, 스펙 2026-10-22-mode3-idp-pages-design.md §3.1~3.3): 가입·세션·1회용 코드(등록/발급)·발급 정책 CIA_ISSUE_AUTH,
// 시드 계정(12345·67890) opt-in(CIA_DEMO_ACCOUNTS). 격리 IdP + :8545 Mode3Log. (chain)  node tests/test_cia_accounts.mjs
import assert from 'node:assert/strict';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createRegistration, signRegistration } from '../lib/mode3_wallet.js';
import { pointToStrings } from '../lib/mode3_issuance.js';
import { issueV11, userOf, TESTUSER_ATTRS, ALICE_ATTRS } from './helpers/mode3_flow.mjs';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

// 쿠키 세션: fetch 가 쿠키를 자동으로 보내지 않으므로 Set-Cookie 를 Cookie 헤더로 되돌리는 jar 를 둔다. 로그인은 세션을
// regenerate 하므로(세션 고정 방지) 매 응답의 Set-Cookie 를 따라간다 — 첫 응답의 것만 고정하지 않는다.
function makeJar(base) {
  const jar = {};
  return async (p, init = {}) => {
    const r = await fetch(`${base}${p}`, { ...init, headers: { 'Content-Type': 'application/json', ...(jar.cookie ? { Cookie: jar.cookie } : {}), ...(init.headers ?? {}) } });
    const sc = r.headers.get('set-cookie');
    if (sc) jar.cookie = sc.split(';')[0];
    return { status: r.status, body: await r.json().catch(() => null) };
  };
}

const provider = getProvider();
const arid = 22222222222222222222n;
const cia = await startIsolatedCia();   // isolated_cia.mjs 가 CIA_DEMO_ACCOUNTS='1', CIA_ISSUE_AUTH='' 를 고정한다
try {
  await t('signup: pwd 8자 이상, uid 는 100001 부터 배정, 계정은 등록 전 상태', async () => {
    const withJar = makeJar(cia.base);
    assert.equal((await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'short' }) })).status, 400);
    const a = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'password-1' }) });
    assert.equal(a.status, 201, j(a.body)); assert.equal(a.body.uid, '100001');
    const b = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'password-2' }) });
    assert.equal(b.status, 201, j(b.body)); assert.equal(b.body.uid, '100002');
  });

  await t('user login/me/logout: 세션 쿠키, 틀린 pwd 401, 로그아웃 뒤 me 401', async () => {
    const withJar = makeJar(cia.base);
    const su = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'password-3' }) });
    const uid = su.body.uid;
    assert.equal((await withJar('/cia/user/me')).status, 401, '로그인 전');
    assert.equal((await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid, pwd: 'wrong-pwd' }) })).status, 401);
    const li = await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid, pwd: 'password-3' }) });
    assert.equal(li.status, 200, j(li.body)); assert.equal(li.body.uid, uid);
    const me = await withJar('/cia/user/me');
    assert.equal(me.status, 200, j(me.body));
    assert.equal(me.body.uid, uid); assert.equal(me.body.registered, false);
    assert.equal(me.body.auid, null); assert.equal(me.body.slot, null); assert.equal(me.body.registryLeaf, null);
    const lo = await withJar('/cia/user/logout', { method: 'POST', body: JSON.stringify({}) });
    assert.equal(lo.status, 200, j(lo.body));
    assert.equal((await withJar('/cia/user/me')).status, 401, '로그아웃 뒤');
  });

  let regUid;
  await t('register_code → /cia/register {uid, code}: 코드로 등록되고 코드는 1회용, 등록 뒤 register_code 는 409', async () => {
    const withJar = makeJar(cia.base);
    const su = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'password-4' }) });
    regUid = su.body.uid;
    assert.equal((await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid: regUid, pwd: 'password-4' }) })).status, 200);
    const rc = await withJar('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
    assert.equal(rc.status, 200, j(rc.body));
    assert.ok(typeof rc.body.code === 'string' && rc.body.code.length >= 32, '코드는 32B hex 이상');
    assert.ok(typeof rc.body.expiresAt === 'number' && rc.body.expiresAt > Date.now());
    const reg = await createRegistration(BigInt(regUid));
    const sig_reg = await signRegistration(reg.sk_u, BigInt(regUid), reg.auid);
    const r1 = await cia.post('/cia/register', { uid: regUid, code: rc.body.code, auid: reg.auid.toString(), pk_u: pointToStrings(reg.pk_u), sig_reg });
    assert.equal(r1.status, 201, j(r1.body));
    const r2 = await cia.post('/cia/register', { uid: regUid, code: rc.body.code, auid: reg.auid.toString(), pk_u: pointToStrings(reg.pk_u), sig_reg });
    assert.equal(r2.status, 401, j(r2.body)); assert.equal(r2.body.error, 'bad_code', '코드는 1회용');
    const again = await withJar('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
    assert.equal(again.status, 409, j(again.body)); assert.equal(again.body.reason, 'already_registered');
    const me = await withJar('/cia/user/me');
    assert.equal(me.body.registered, true); assert.equal(me.body.auid, reg.auid.toString());
    assert.equal(me.body.slot, 0); assert.equal(me.body.registryLeaf, '0', '아직 자격증명(C_u) 발급 전이라 슬롯 리프는 비어 있다');
  });

  let authUid, authReg;
  const authPwd = 'password-5';
  await t('auth/code: pwd·auid 검사 — auid 틀리면 403 auid_mismatch, 등록 전 계정은 409 not_registered', async () => {
    const withJar = makeJar(cia.base);
    const su = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: authPwd }) });
    authUid = su.body.uid;
    assert.equal((await cia.post('/cia/auth/code', { uid: authUid, pwd: 'wrong', auid: '1' })).status, 401, '틀린 비밀번호');
    const notReg = await cia.post('/cia/auth/code', { uid: authUid, pwd: authPwd, auid: '1' });
    assert.equal(notReg.status, 409, j(notReg.body)); assert.equal(notReg.body.reason, 'not_registered', '등록 전 계정');
    await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid: authUid, pwd: authPwd }) });
    const rc = await withJar('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
    authReg = await createRegistration(BigInt(authUid));
    const sig_reg = await signRegistration(authReg.sk_u, BigInt(authUid), authReg.auid);
    const rr = await cia.post('/cia/register', { uid: authUid, code: rc.body.code, auid: authReg.auid.toString(), pk_u: pointToStrings(authReg.pk_u), sig_reg });
    assert.equal(rr.status, 201, j(rr.body));
    const mism = await cia.post('/cia/auth/code', { uid: authUid, pwd: authPwd, auid: (authReg.auid + 1n).toString() });
    assert.equal(mism.status, 403, j(mism.body)); assert.equal(mism.body.reason, 'auid_mismatch');
    const ok = await cia.post('/cia/auth/code', { uid: authUid, pwd: authPwd, auid: authReg.auid.toString() });
    assert.equal(ok.status, 200, j(ok.body));
    assert.ok(typeof ok.body.code === 'string' && typeof ok.body.expiresAt === 'number');
  });

  await t('auth/code: 코드는 TTL 뒤 만료(두 번째 IdP, CIA_CODE_TTL_MS=50)', async () => {
    const cia2 = await startIsolatedCia({ env: { CIA_CODE_TTL_MS: '50' } });
    try {
      const withJar2 = makeJar(cia2.base);
      const su = await withJar2('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'password-6' }) });
      const uid2 = su.body.uid;
      await withJar2('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid: uid2, pwd: 'password-6' }) });
      const rc = await withJar2('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
      const reg2 = await createRegistration(BigInt(uid2));
      const sig_reg2 = await signRegistration(reg2.sk_u, BigInt(uid2), reg2.auid);
      await new Promise((r) => setTimeout(r, 150));
      const r1 = await cia2.post('/cia/register', { uid: uid2, code: rc.body.code, auid: reg2.auid.toString(), pk_u: pointToStrings(reg2.pk_u), sig_reg: sig_reg2 });
      assert.equal(r1.status, 401, j(r1.body)); assert.equal(r1.body.error, 'bad_code', '만료된 코드');
    } finally { await cia2.stop(); }
  });

  await t('CIA_ISSUE_AUTH=code: demo 계정 발급은 auth_code 필수(401 auth_code_required), 맞는 코드면 200, 다른 사용자의 코드면 401 bad_code', async () => {
    const cia3 = await startIsolatedCia({ env: { CIA_ISSUE_AUTH: 'code' } });
    try {
      const u = userOf(await cia3.registerUser('12345', 'password123'), '12345', TESTUSER_ATTRS);
      const alice = userOf(await cia3.registerUser('67890', 'alicepw'), '67890', ALICE_ATTRS);
      const noCode = await issueV11(cia3, u, { arid, provider });
      assert.equal(noCode.r.status, 401, j(noCode.r.body)); assert.equal(noCode.r.body.reason, 'auth_code_required');
      const authResp = await cia3.post('/cia/auth/code', { uid: '12345', pwd: 'password123', auid: u.auid.toString() });
      assert.equal(authResp.status, 200, j(authResp.body));
      const ok = await issueV11(cia3, u, { arid, provider, overrides: { auth_code: authResp.body.code } });
      assert.equal(ok.r.status, 200, j(ok.r.body));
      const reuse = await issueV11(cia3, u, { arid, provider, blind_u: ok.blind_u, overrides: { auth_code: authResp.body.code } });
      assert.equal(reuse.r.status, 401, j(reuse.r.body)); assert.equal(reuse.r.body.reason, 'bad_code', '코드는 1회용');
      const authA = await cia3.post('/cia/auth/code', { uid: '67890', pwd: 'alicepw', auid: alice.auid.toString() });
      assert.equal(authA.status, 200, j(authA.body));
      const bad = await issueV11(cia3, u, { arid, provider, overrides: { auth_code: authA.body.code } });
      assert.equal(bad.r.status, 401, j(bad.r.body)); assert.equal(bad.r.body.reason, 'bad_code', '다른 사용자의 코드');
    } finally { await cia3.stop(); }
  });

  await t('CIA_DEMO_ACCOUNTS 미설정이면 12345/67890 이 없고(/cia/register 401), 설정이면(기본 격리 IdP) 있다', async () => {
    const ciaOff = await startIsolatedCia({ env: { CIA_DEMO_ACCOUNTS: '' } });
    try {
      const reg = await createRegistration(12345n);
      const sig_reg = await signRegistration(reg.sk_u, 12345n, reg.auid);
      const r = await ciaOff.post('/cia/register', { uid: '12345', pwd: 'password123', auid: reg.auid.toString(), pk_u: pointToStrings(reg.pk_u), sig_reg });
      assert.equal(r.status, 401, j(r.body));
      const su = await ciaOff.post('/cia/signup', { pwd: 'password-off-1' });
      assert.equal(su.status, 201, j(su.body), '가입으로는 여전히 계정을 만들 수 있다');
    } finally { await ciaOff.stop(); }
    const reg2 = await createRegistration(12345n);
    const sig_reg2 = await signRegistration(reg2.sk_u, 12345n, reg2.auid);
    const r2 = await cia.post('/cia/register', { uid: '12345', pwd: 'password123', auid: reg2.auid.toString(), pk_u: pointToStrings(reg2.pk_u), sig_reg: sig_reg2 });
    assert.equal(r2.status, 201, j(r2.body));
  });

  // ---- 수정 라운드 1(리뷰 97158aa) ----
  await t('가입만 한(등록 전) uid 는 /cia/issue·/cia/slot·관리자 /cia/revoke scope=account 모두 404 unknown account(레코드는 있지만 pk_u 없음)', async () => {
    const withJar = makeJar(cia.base);
    const su = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'password-7' }) });
    const uid = su.body.uid;
    const head = await provider.getBlockNumber();
    const dummyPt = { x: '1', y: '1' }, dummySig = { R8x: '1', R8y: '1', S: '1' };
    const issueRes = await cia.post('/cia/issue', {
      uid, auid_s: '1', arid_s: '1', C_u_pt: dummyPt, C_s_pt: dummyPt, chainid: '31337', allowAgent: '0', max_height: String(head + 300), proof_idp: {}, sig_u: dummySig,
    });
    assert.equal(issueRes.status, 404, j(issueRes.body)); assert.equal(issueRes.body.error, 'unknown account');
    const slotRes = await cia.post('/cia/slot', { uid, nonce: '1', sig_u: dummySig });
    assert.equal(slotRes.status, 404, j(slotRes.body)); assert.equal(slotRes.body.error, 'unknown account');
    const revokeRes = await cia.adminPost('/cia/revoke', { uid, scope: 'account' });
    assert.equal(revokeRes.status, 404, j(revokeRes.body)); assert.equal(revokeRes.body.error, 'unknown account');
  });

  await t('register 코드: 잘못된 서명으로 등록이 실패해도 코드는 타지 않는다 — 같은 코드로 재시도하면 성공(스펙 "성공 시 소진")', async () => {
    const withJar = makeJar(cia.base);
    const su = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'password-8' }) });
    const uid = su.body.uid;
    await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid, pwd: 'password-8' }) });
    const rc = await withJar('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
    const reg = await createRegistration(BigInt(uid));
    const badSig = { R8x: '1', R8y: '1', S: '1' };
    const bad = await cia.post('/cia/register', { uid, code: rc.body.code, auid: reg.auid.toString(), pk_u: pointToStrings(reg.pk_u), sig_reg: badSig });
    assert.equal(bad.status, 400, j(bad.body)); assert.equal(bad.body.error, 'bad_registration_signature');
    const sig_reg = await signRegistration(reg.sk_u, BigInt(uid), reg.auid);
    const ok = await cia.post('/cia/register', { uid, code: rc.body.code, auid: reg.auid.toString(), pk_u: pointToStrings(reg.pk_u), sig_reg });
    assert.equal(ok.status, 201, j(ok.body), '서명이 틀렸던 시도가 코드를 태우지 않았어야 한다');
  });

  await t('로그인은 세션 id 를 새로 받는다(세션 고정 방지) — 옛 sid 는 로그인 뒤에도 폐기, 세션 없이 register_code 는 401', async () => {
    const su = await fetch(`${cia.base}/cia/signup`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pwd: 'password-9' }) }).then((r) => r.json());
    const uid = su.uid;
    const login1 = await fetch(`${cia.base}/cia/user/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ uid, pwd: 'password-9' }) });
    assert.equal(login1.status, 200);
    const sid1 = login1.headers.get('set-cookie').split(';')[0];
    const login2 = await fetch(`${cia.base}/cia/user/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: sid1 }, body: JSON.stringify({ uid, pwd: 'password-9' }) });
    assert.equal(login2.status, 200);
    const sid2 = login2.headers.get('set-cookie').split(';')[0];
    assert.notEqual(sid1, sid2, '로그인마다 세션 id 가 바뀐다(regenerate)');
    const meOld = await fetch(`${cia.base}/cia/user/me`, { headers: { Cookie: sid1 } });
    assert.equal(meOld.status, 401, '옛 sid 는 로그인 뒤에도 폐기돼 있어야 한다');
    const meNew = await fetch(`${cia.base}/cia/user/me`, { headers: { Cookie: sid2 } });
    assert.equal(meNew.status, 200, j(await meNew.json().catch(() => null)));
    const noSession = await cia.post('/cia/user/register_code', {});
    assert.equal(noSession.status, 401, j(noSession.body)); assert.equal(noSession.body.reason, 'login_required');
  });

  await t('다른 uid 의 register 코드로 등록하면 bad_code', async () => {
    const withJarA = makeJar(cia.base), withJarB = makeJar(cia.base);
    const suA = await withJarA('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'password-a1' }) });
    const suB = await withJarB('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'password-b1' }) });
    await withJarA('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid: suA.body.uid, pwd: 'password-a1' }) });
    const rcA = await withJarA('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
    const regB = await createRegistration(BigInt(suB.body.uid));
    const sig_regB = await signRegistration(regB.sk_u, BigInt(suB.body.uid), regB.auid);
    const r = await cia.post('/cia/register', { uid: suB.body.uid, code: rcA.body.code, auid: regB.auid.toString(), pk_u: pointToStrings(regB.pk_u), sig_reg: sig_regB });
    assert.equal(r.status, 401, j(r.body)); assert.equal(r.body.error, 'bad_code', 'A 의 코드로 B 를 등록할 수 없다');
  });

  await t('모호성 복원: uid 없이 pwd 와 id_token 이 함께 오면 400(id_token 을 우선하지 않는다)', async () => {
    const r = await cia.post('/cia/register', { pwd: 'whatever1', id_token: 'x', auid: '1', pk_u: { x: '1', y: '1' }, sig_reg: { R8x: '1', R8y: '1', S: '1' } });
    assert.equal(r.status, 400, j(r.body));
  });

  await t('목적 교차 사용: register 코드를 /cia/issue 의 auth_code 로, issue 코드를 /cia/register 의 code 로 쓰면 둘 다 bad_code', async () => {
    const cia5 = await startIsolatedCia({ env: { CIA_ISSUE_AUTH: 'code' } });
    try {
      const withJar5 = makeJar(cia5.base);
      const u = userOf(await cia5.registerUser('12345', 'password123'), '12345', TESTUSER_ATTRS);
      const issueCodeResp = await cia5.post('/cia/auth/code', { uid: '12345', pwd: 'password123', auid: u.auid.toString() });
      assert.equal(issueCodeResp.status, 200, j(issueCodeResp.body));
      const su5 = await withJar5('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'password-x' }) });
      const uid2 = su5.body.uid;
      const reg2 = await createRegistration(BigInt(uid2));
      const sig_reg2 = await signRegistration(reg2.sk_u, BigInt(uid2), reg2.auid);
      const regAttempt = await cia5.post('/cia/register', { uid: uid2, code: issueCodeResp.body.code, auid: reg2.auid.toString(), pk_u: pointToStrings(reg2.pk_u), sig_reg: sig_reg2 });
      assert.equal(regAttempt.status, 401, j(regAttempt.body)); assert.equal(regAttempt.body.error, 'bad_code', 'issue 코드는 register 에 못 쓴다');
      await withJar5('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid: uid2, pwd: 'password-x' }) });
      const registerCodeResp = await withJar5('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
      const issueAttempt = await issueV11(cia5, u, { arid, provider, overrides: { auth_code: registerCodeResp.body.code } });
      assert.equal(issueAttempt.r.status, 401, j(issueAttempt.r.body)); assert.equal(issueAttempt.r.body.reason, 'bad_code', 'register 코드는 issue 에 못 쓴다');
    } finally { await cia5.stop(); }
  });
} finally { await cia.stop(); }

provider.destroy();
process.exit(failed === 0 ? 0 : 1);
