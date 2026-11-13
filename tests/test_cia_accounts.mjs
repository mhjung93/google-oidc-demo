// Task 10(B1, 스펙 2026-10-22-mode3-idp-pages-design.md §3.1~3.3): 가입·세션·1회용 코드(등록/발급)·발급 정책 CIA_ISSUE_AUTH,
// 시드 계정(12345·67890) opt-in(CIA_DEMO_ACCOUNTS). 격리 IdP + :8545 Mode3Log. (chain)  node tests/test_cia_accounts.mjs
// Task 11(B2, 같은 스펙 §3.3): RP 운영자 계정·RP 슬롯(rp_key)·공개 rp_origins 도 여기서 같이 본다.
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createRegistration } from '../lib/mode3_wallet.js';
import { createShare } from '../lib/mode3_trace.js';
import { issueV11, userOf, regBody, TESTUSER_ATTRS, ALICE_ATTRS } from './helpers/mode3_flow.mjs';
import { jwtVerify, createLocalJWKSet } from 'jose';
import { attrCommit } from '../lib/mode3_attr_commit.js';
import { DEFAULT_ATTR_SCHEMA, encodeProfile } from '../lib/mode3_attr_schema.js';

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
  await t('signup(2026-11-03 아이디 가입): id 형식·pwd 8자 이상, 중복 id 는 409 id_taken(대소문자 무시), uid 는 100001 부터 배정, 계정은 등록 전 상태', async () => {
    const withJar = makeJar(cia.base);
    assert.equal((await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'user-1', pwd: 'short' }) })).status, 400, 'pwd 8자 미만');
    const noId = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'password-1' }) });
    assert.equal(noId.status, 400, 'id 없음'); assert.equal(noId.body.reason, 'bad_id');
    assert.equal((await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'ab', pwd: 'password-1' }) })).body.reason, 'bad_id', '2자');
    assert.equal((await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'bad id!', pwd: 'password-1' }) })).body.reason, 'bad_id', '허용 밖 문자');
    assert.equal((await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: '12345', pwd: 'password-1' }) })).body.reason, 'bad_id', '숫자만인 아이디는 uid 와 겹쳐 금지(리뷰 I-1)');
    const a = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'user-1', pwd: 'password-1' }) });
    assert.equal(a.status, 201, j(a.body)); assert.equal(a.body.uid, '100001'); assert.equal(a.body.id, 'user-1');
    const dup = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'USER-1', pwd: 'password-9' }) });
    assert.equal(dup.status, 409, j(dup.body)); assert.equal(dup.body.reason, 'id_taken');
    const b = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'user_2', pwd: 'password-2' }) });
    assert.equal(b.status, 201, j(b.body)); assert.equal(b.body.uid, '100002');
  });

  await t('user login/me/logout: 아이디로 로그인(대소문자 무시), uid 로도 로그인(시드·옛 경로), 세션 쿠키, 틀린 pwd·모르는 id 401, 로그아웃 뒤 me 401', async () => {
    const withJar = makeJar(cia.base);
    const su = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'User.3', pwd: 'password-3' }) });
    const uid = su.body.uid;
    assert.equal((await withJar('/cia/user/me')).status, 401, '로그인 전');
    assert.equal((await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ id: 'user.3', pwd: 'wrong-pwd' }) })).status, 401, '틀린 pwd');
    assert.equal((await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ id: 'nobody', pwd: 'password-3' }) })).status, 401, '모르는 id');
    const li = await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ id: 'USER.3', pwd: 'password-3' }) });
    assert.equal(li.status, 200, j(li.body)); assert.equal(li.body.uid, uid); assert.equal(li.body.id, 'User.3');
    const byUid = await makeJar(cia.base)('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid, pwd: 'password-3' }) });
    assert.equal(byUid.status, 200, j(byUid.body), 'uid 로그인(옛 경로)도 그대로');
    const byUidAsId = await makeJar(cia.base)('/cia/user/login', { method: 'POST', body: JSON.stringify({ id: uid, pwd: 'password-3' }) });
    assert.equal(byUidAsId.status, 200, j(byUidAsId.body), '아이디 칸에 uid 를 넣어도 된다(리뷰 I-2: 아이디 없는 계정의 /user 로그인)');
    const seedById = await makeJar(cia.base)('/cia/user/login', { method: 'POST', body: JSON.stringify({ id: 'TestUser', pwd: 'password123' }) });
    assert.equal(seedById.status, 200, j(seedById.body)); assert.equal(seedById.body.uid, '12345', '시드 계정은 이름이 아이디(대소문자 무시)');
    const me = await withJar('/cia/user/me');
    assert.equal(me.status, 200, j(me.body));
    assert.equal(me.body.uid, uid); assert.equal(me.body.id, 'User.3'); assert.equal(me.body.registered, false);
    assert.equal(me.body.auid, null); assert.equal(me.body.slot, null); assert.equal(me.body.registryLeaf, null);
    const lo = await withJar('/cia/user/logout', { method: 'POST', body: JSON.stringify({}) });
    assert.equal(lo.status, 200, j(lo.body));
    assert.equal((await withJar('/cia/user/me')).status, 401, '로그아웃 뒤');
  });

  let regUid;
  await t('register_code → /cia/register {uid, code}: 코드로 등록되고 코드는 1회용, 등록 뒤 register_code 는 409', async () => {
    const withJar = makeJar(cia.base);
    const su = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'user-4', pwd: 'password-4' }) });
    regUid = su.body.uid;
    assert.equal((await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid: regUid, pwd: 'password-4' }) })).status, 200);
    const rc = await withJar('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
    assert.equal(rc.status, 200, j(rc.body));
    assert.ok(typeof rc.body.code === 'string' && rc.body.code.length >= 32, '코드는 32B hex 이상');
    assert.ok(typeof rc.body.expiresAt === 'number' && rc.body.expiresAt > Date.now());
    const reg = await createRegistration(BigInt(regUid));
    const r1 = await cia.post('/cia/register', { uid: regUid, code: rc.body.code, ...(await regBody(reg, regUid)) });
    assert.equal(r1.status, 201, j(r1.body));
    const r2 = await cia.post('/cia/register', { uid: regUid, code: rc.body.code, ...(await regBody(reg, regUid)) });
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
    const su = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'user-5', pwd: authPwd }) });
    authUid = su.body.uid;
    assert.equal((await cia.post('/cia/auth/code', { uid: authUid, pwd: 'wrong', auid: '1' })).status, 401, '틀린 비밀번호');
    const notReg = await cia.post('/cia/auth/code', { uid: authUid, pwd: authPwd, auid: '1' });
    assert.equal(notReg.status, 409, j(notReg.body)); assert.equal(notReg.body.reason, 'not_registered', '등록 전 계정');
    await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid: authUid, pwd: authPwd }) });
    const rc = await withJar('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
    authReg = await createRegistration(BigInt(authUid));
    const rr = await cia.post('/cia/register', { uid: authUid, code: rc.body.code, ...(await regBody(authReg, authUid)) });
    assert.equal(rr.status, 201, j(rr.body));
    const mism = await cia.post('/cia/auth/code', { uid: authUid, pwd: authPwd, auid: (authReg.auid + 1n).toString() });
    assert.equal(mism.status, 403, j(mism.body)); assert.equal(mism.body.reason, 'auid_mismatch');
    const ok = await cia.post('/cia/auth/code', { uid: authUid, pwd: authPwd, auid: authReg.auid.toString() });
    assert.equal(ok.status, 200, j(ok.body));
    assert.equal((await cia.post('/cia/auth/code', { id: 'USER-5', pwd: authPwd, auid: authReg.auid.toString() })).status, 200, '인증 창의 아이디 경로');
    assert.equal((await cia.post('/cia/auth/code', { id: authUid, pwd: authPwd, auid: authReg.auid.toString() })).status, 200, '아이디 칸에 10진 uid 를 넣어도 된다');
    assert.equal((await cia.post('/cia/auth/code', { id: 'nobody', pwd: authPwd, auid: authReg.auid.toString() })).status, 401, '모르는 아이디');
    assert.ok(typeof ok.body.code === 'string' && typeof ok.body.expiresAt === 'number');
  });

  await t('auth/code: 코드는 TTL 뒤 만료(두 번째 IdP, CIA_CODE_TTL_MS=50)', async () => {
    const cia2 = await startIsolatedCia({ env: { CIA_CODE_TTL_MS: '50' } });
    try {
      const withJar2 = makeJar(cia2.base);
      const su = await withJar2('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'user-6', pwd: 'password-6' }) });
      const uid2 = su.body.uid;
      await withJar2('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid: uid2, pwd: 'password-6' }) });
      const rc = await withJar2('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
      const reg2 = await createRegistration(BigInt(uid2));
      await new Promise((r) => setTimeout(r, 150));
      const r1 = await cia2.post('/cia/register', { uid: uid2, code: rc.body.code, ...(await regBody(reg2, uid2)) });
      assert.equal(r1.status, 401, j(r1.body)); assert.equal(r1.body.error, 'bad_code', '만료된 코드');
    } finally { await cia2.stop(); }
  });

  // 2026-11-09(사용자 결정): 지갑 등록은 서비스 첫 로그인 중 — 인증 창이 purpose=register 로 등록 코드·uid 를 내고, 그 코드로 등록하면 발급 코드가 함께 온다.
  await t('auth/code purpose=register: 비밀번호·auid 로 등록 코드·uid(auid 는 코드에 묶임 — 다르면 register_auid_mismatch), 이미 등록이면 409; 그 코드로 /cia/register 하면 issue_code 가 함께 오고 /cia/issue(code 모드)에 바로 쓰인다; bad_purpose 400', async () => {
    const cia8 = await startIsolatedCia({ env: { CIA_ISSUE_AUTH: 'code' } });
    try {
      const su = await cia8.post('/cia/signup', { id: 'reg-at-login', pwd: 'password-r1' });
      assert.equal(su.status, 201, j(su.body)); const uid8 = su.body.uid;
      assert.equal((await cia8.post('/cia/auth/code', { id: 'reg-at-login', pwd: 'password-r1', purpose: 'bogus' })).body.reason, 'bad_purpose');
      assert.equal((await cia8.post('/cia/auth/code', { id: 'reg-at-login', pwd: 'wrong', purpose: 'register' })).status, 401);
      // 2026-11-11(사용자 결정): 첫 등록에도 auid 를 받는다 — 속성 도구가 uid·salt 로 계산해 보여 준 값을 붙여 넣는다. 코드에 묶이고, /cia/register 의 auid 와 다르면 거절.
      const reg = await createRegistration(BigInt(uid8));
      const noAuid = await cia8.post('/cia/auth/code', { id: 'reg-at-login', pwd: 'password-r1', purpose: 'register' });
      assert.equal(noAuid.status, 400, j(noAuid.body)); assert.equal(noAuid.body.reason, 'bad_auid');
      const rc = await cia8.post('/cia/auth/code', { id: 'reg-at-login', pwd: 'password-r1', purpose: 'register', auid: reg.auid.toString() });
      assert.equal(rc.status, 200, j(rc.body)); assert.equal(rc.body.uid, uid8); assert.equal(rc.body.purpose, 'register'); assert.match(rc.body.code, /^[0-9a-f]{64}$/);
      const other = await createRegistration(BigInt(uid8));   // 다른 salt — 커밋먼트와 다른 salt 로 등록하려는 경우
      const wrong = await cia8.post('/cia/register', { uid: uid8, code: rc.body.code, ...(await regBody(other, uid8)) });
      assert.equal(wrong.status, 403, j(wrong.body)); assert.equal(wrong.body.reason, 'register_auid_mismatch');
      const r1 = await cia8.post('/cia/register', { uid: uid8, code: rc.body.code, ...(await regBody(reg, uid8)) });
      assert.equal(r1.status, 201, j(r1.body)); assert.match(r1.body.issue_code, /^[0-9a-f]{64}$/, '등록 코드 경로는 발급 코드를 함께 준다');
      // 2026-11-12(스펙 snap-derived-secrets S3): 이미 등록된 계정도 같은 auid 면 등록 코드를 준다(복구 — 같은 비밀로 다시 등록). 다른 auid 면 409.
      const again = await cia8.post('/cia/auth/code', { id: 'reg-at-login', pwd: 'password-r1', purpose: 'register', auid: reg.auid.toString() });
      assert.equal(again.status, 200, j(again.body)); assert.equal(again.body.purpose, 'register');
      const diff = await cia8.post('/cia/auth/code', { id: 'reg-at-login', pwd: 'password-r1', purpose: 'register', auid: other.auid.toString() });
      assert.equal(diff.status, 409, j(diff.body)); assert.equal(diff.body.reason, 'already_registered');
      const rr = await cia8.post('/cia/register', { uid: uid8, code: again.body.code, ...(await regBody(reg, uid8)) });
      assert.equal(rr.status, 201, j(rr.body)); assert.equal(rr.body.restored, true); assert.equal(rr.body.slot, r1.body.slot);
      assert.match(rr.body.issue_code, /^[0-9a-f]{64}$/, '복구도 등록 코드 경로면 발급 코드를 준다');
      const u8 = userOf({ ...reg, slot: r1.body.slot }, uid8, TESTUSER_ATTRS);
      const ok = await issueV11(cia8, u8, { arid, provider, overrides: { auth_code: r1.body.issue_code } });
      assert.equal(ok.r.status, 200, j(ok.r.body), '등록 응답의 발급 코드로 바로 발급된다');
      const reuse = await issueV11(cia8, u8, { arid, provider, blind_u: ok.blind_u, overrides: { auth_code: r1.body.issue_code } });
      assert.equal(reuse.r.status, 401, '발급 코드도 1회용');
      // 비밀번호 경로(code 없음)의 등록 응답에는 issue_code 가 없다
      const su2 = await cia8.post('/cia/signup', { id: 'reg-by-pwd', pwd: 'password-r2' }); const uid9 = su2.body.uid;
      const reg2 = await createRegistration(BigInt(uid9));
      const r2 = await cia8.post('/cia/register', { uid: uid9, pwd: 'password-r2', ...(await regBody(reg2, uid9)) });
      assert.equal(r2.status, 201, j(r2.body)); assert.equal(r2.body.issue_code, undefined);
    } finally { await cia8.stop(); }
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

  await t('F-7: 발급 코드 소비는 π_IdP 검증 뒤 — 맞는 코드 + 틀린 tag 는 400 이고 코드는 타지 않아, 같은 코드로 재시도하면 200', async () => {
    const cia6 = await startIsolatedCia({ env: { CIA_ISSUE_AUTH: 'code' } });
    try {
      const u = userOf(await cia6.registerUser('12345', 'password123'), '12345', TESTUSER_ATTRS);
      const authResp = await cia6.post('/cia/auth/code', { uid: '12345', pwd: 'password123', auid: u.auid.toString() });
      assert.equal(authResp.status, 200, j(authResp.body));
      const bad = await issueV11(cia6, u, { arid, provider, overrides: { auth_code: authResp.body.code, tag: '1' } });
      assert.equal(bad.r.status, 400, j(bad.r.body)); assert.equal(bad.r.body.reason, 'bad_idp_proof');
      const ok = await issueV11(cia6, u, { arid, provider, overrides: { auth_code: authResp.body.code } });
      assert.equal(ok.r.status, 200, j(ok.r.body), '틀린 증명 시도가 코드를 태우지 않았어야 한다');
    } finally { await cia6.stop(); }
  });

  await t('CIA_DEMO_ACCOUNTS 미설정이면 12345/67890 이 없고(/cia/register 401), 설정이면(기본 격리 IdP) 있다', async () => {
    const ciaOff = await startIsolatedCia({ env: { CIA_DEMO_ACCOUNTS: '' } });
    try {
      const reg = await createRegistration(12345n);
      const r = await ciaOff.post('/cia/register', { uid: '12345', pwd: 'password123', ...(await regBody(reg, '12345')) });
      assert.equal(r.status, 401, j(r.body));
      const su = await ciaOff.post('/cia/signup', { id: 'user-off-1', pwd: 'password-off-1' });
      assert.equal(su.status, 201, j(su.body), '가입으로는 여전히 계정을 만들 수 있다');
    } finally { await ciaOff.stop(); }
    const reg2 = await createRegistration(12345n);
    const r2 = await cia.post('/cia/register', { uid: '12345', pwd: 'password123', ...(await regBody(reg2, '12345')) });
    assert.equal(r2.status, 201, j(r2.body));
  });

  // ---- 수정 라운드 1(리뷰 97158aa) ----
  await t('가입만 한(등록 전) uid 는 /cia/issue·/cia/slot·관리자 /cia/revoke scope=account 모두 404 unknown account(레코드는 있지만 auid 없음)', async () => {
    const withJar = makeJar(cia.base);
    const su = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'user-7', pwd: 'password-7' }) });
    const uid = su.body.uid;
    const head = await provider.getBlockNumber();
    const dummyPt = { x: '1', y: '1' };
    const issueRes = await cia.post('/cia/issue', {
      uid, auid_s: '1', arid_s: '1', C_u_pt: dummyPt, C_s_pt: dummyPt, chainid: '31337', allowAgent: '0', max_height: String(head + 300), proof_idp: {}, tag: '1', n: '1',
    });
    assert.equal(issueRes.status, 404, j(issueRes.body)); assert.equal(issueRes.body.error, 'unknown account');
    const slotRes = await cia.post('/cia/slot', { uid, nonce: '1' });
    assert.equal(slotRes.status, 404, j(slotRes.body)); assert.equal(slotRes.body.error, 'unknown account');
    const revokeRes = await cia.adminPost('/cia/revoke', { uid, scope: 'account' });
    assert.equal(revokeRes.status, 404, j(revokeRes.body)); assert.equal(revokeRes.body.error, 'unknown account');
  });

  await t('register 코드: 잘못된 증명으로 등록이 실패해도 코드는 타지 않는다 — 같은 코드로 재시도하면 성공(스펙 "성공 시 소진")', async () => {
    const withJar = makeJar(cia.base);
    const su = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'user-8', pwd: 'password-8' }) });
    const uid = su.body.uid;
    await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid, pwd: 'password-8' }) });
    const rc = await withJar('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
    const reg = await createRegistration(BigInt(uid));
    const bad = await cia.post('/cia/register', { uid, code: rc.body.code, ...(await regBody(reg, uid)), tag: '1' });
    assert.equal(bad.status, 400, j(bad.body)); assert.equal(bad.body.reason, 'bad_idp_proof');
    const ok = await cia.post('/cia/register', { uid, code: rc.body.code, ...(await regBody(reg, uid)) });
    assert.equal(ok.status, 201, j(ok.body), '증명이 틀렸던 시도가 코드를 태우지 않았어야 한다');
  });

  await t('로그인은 세션 id 를 새로 받는다(세션 고정 방지) — 옛 sid 는 로그인 뒤에도 폐기, 세션 없이 register_code 는 401', async () => {
    const su = await fetch(`${cia.base}/cia/signup`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: 'user-9', pwd: 'password-9' }) }).then((r) => r.json());
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
    const suA = await withJarA('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'user-a1', pwd: 'password-a1' }) });
    const suB = await withJarB('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'user-b1', pwd: 'password-b1' }) });
    await withJarA('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid: suA.body.uid, pwd: 'password-a1' }) });
    const rcA = await withJarA('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
    const regB = await createRegistration(BigInt(suB.body.uid));
    const r = await cia.post('/cia/register', { uid: suB.body.uid, code: rcA.body.code, ...(await regBody(regB, suB.body.uid)) });
    assert.equal(r.status, 401, j(r.body)); assert.equal(r.body.error, 'bad_code', 'A 의 코드로 B 를 등록할 수 없다');
  });

  await t('모호성 복원: uid 없이 pwd 와 id_token 이 함께 오면 400(id_token 을 우선하지 않는다)', async () => {
    const r = await cia.post('/cia/register', { pwd: 'whatever1', id_token: 'x', auid: '1' });
    assert.equal(r.status, 400, j(r.body));
  });

  await t('목적 교차 사용: register 코드를 /cia/issue 의 auth_code 로, issue 코드를 /cia/register 의 code 로 쓰면 둘 다 bad_code', async () => {
    const cia5 = await startIsolatedCia({ env: { CIA_ISSUE_AUTH: 'code' } });
    try {
      const withJar5 = makeJar(cia5.base);
      const u = userOf(await cia5.registerUser('12345', 'password123'), '12345', TESTUSER_ATTRS);
      const issueCodeResp = await cia5.post('/cia/auth/code', { uid: '12345', pwd: 'password123', auid: u.auid.toString() });
      assert.equal(issueCodeResp.status, 200, j(issueCodeResp.body));
      const su5 = await withJar5('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'user-x', pwd: 'password-x' }) });
      const uid2 = su5.body.uid;
      const reg2 = await createRegistration(BigInt(uid2));
      const regAttempt = await cia5.post('/cia/register', { uid: uid2, code: issueCodeResp.body.code, ...(await regBody(reg2, uid2)) });
      assert.equal(regAttempt.status, 401, j(regAttempt.body)); assert.equal(regAttempt.body.error, 'bad_code', 'issue 코드는 register 에 못 쓴다');
      await withJar5('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid: uid2, pwd: 'password-x' }) });
      const registerCodeResp = await withJar5('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
      const issueAttempt = await issueV11(cia5, u, { arid, provider, overrides: { auth_code: registerCodeResp.body.code } });
      assert.equal(issueAttempt.r.status, 401, j(issueAttempt.r.body)); assert.equal(issueAttempt.r.body.reason, 'bad_code', 'register 코드는 issue 에 못 쓴다');
    } finally { await cia5.stop(); }
  });

  // ---- Task 11(B2, 2026-10-22): RP 운영자·RP 슬롯(rp_key)·공개 rp_origins ----
  /** register_rp 본문(서비스 키는 매번 새로 — 재등록 검사(service_key_mismatch)에 걸리지 않게). */
  async function rpRegBody(name, origin) {
    const serviceWallet = ethers.Wallet.createRandom();
    const share = await createShare();
    return { name, origin, pk_service: serviceWallet.address, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() } };
  }

  await t('rp signup/login/create: 키·명령 발급, 이름 규칙, 같은 운영자 안 중복 409', async () => {
    const withJar = makeJar(cia.base);
    const su = await withJar('/cia/rp/signup', { method: 'POST', body: JSON.stringify({ id: 'op-eleven', pwd: 'operator-pw-1' }) });
    assert.equal(su.status, 201, j(su.body)); assert.equal(su.body.id, 'op-eleven');
    const dupId = await withJar('/cia/rp/signup', { method: 'POST', body: JSON.stringify({ id: 'op-eleven', pwd: 'another-pw' }) });
    assert.equal(dupId.status, 409, j(dupId.body), '같은 id 로 재가입은 안 된다');
    assert.equal(dupId.body.error, 'id_taken'); assert.equal(dupId.body.reason, 'id_taken');
    assert.equal((await withJar('/cia/rp/login', { method: 'POST', body: JSON.stringify({ id: 'op-eleven', pwd: 'wrong' }) })).status, 401);
    const li = await withJar('/cia/rp/login', { method: 'POST', body: JSON.stringify({ id: 'op-eleven', pwd: 'operator-pw-1' }) });
    assert.equal(li.status, 200, j(li.body)); assert.equal(li.body.id, 'op-eleven');
    const bad = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'bad name', origin: 'http://127.0.0.1:39990' }) });
    assert.equal(bad.status, 400, j(bad.body)); assert.equal(bad.body.reason, 'bad_name', '수정 라운드 1: 형식 오류는 bad_name');
    // 2026-11-06: 서비스 주소가 필수 — 없거나 경로가 있으면 bad_origin.
    for (const origin of [undefined, 'not a url', 'http://127.0.0.1:39990/path', 'http://LocalHost:39990', 'http://[::1]:39990', 'http://127.0.0.1:80']) {   // 정규형만(소문자·기본 포트 생략·IPv6 불가)
      const bo = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkTHREE', origin }) });
      assert.equal(bo.status, 400, j(bo.body)); assert.equal(bo.body.reason, 'bad_origin', `주소 ${origin}`);
    }
    const create = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkTHREE', origin: ' http://127.0.0.1:39990/ ' }) });
    assert.equal(create.status, 201, j(create.body));
    assert.equal(create.body.name, 'zkTHREE'); assert.equal(create.body.origin, 'http://127.0.0.1:39990', '공백·끝 슬래시는 정규화');
    assert.equal(create.body.status, 'created'); assert.equal(create.body.arid, null);
    assert.ok(/^[0-9a-f]{64}$/.test(create.body.key), `키는 64자 hex: ${create.body.key}`);
    assert.equal(create.body.command, `bash scripts/new_rp.sh zkTHREE 39990 ${create.body.key} --public-origin http://127.0.0.1:39990`, '127.0.0.1 은 new_rp.sh 기본(localhost)과 달라 --public-origin 을 붙인다(리뷰 HIGH-1)');
    // 2026-11-11(사용자 지적): 스킴을 빼고 "localhost:3100" 처럼 넣으면 http:// 를 붙여 받는다 — 대문자·경로·IPv6 는 위처럼 여전히 거절
    const noScheme = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkNOSCH', origin: 'localhost:39987' }) });
    assert.equal(noScheme.status, 201, j(noScheme.body)); assert.equal(noScheme.body.origin, 'http://localhost:39987', '스킴 없으면 http://');
    assert.equal(noScheme.body.command, `bash scripts/new_rp.sh zkNOSCH 39987 ${noScheme.body.key}`);
    for (const origin of ['LocalHost:39986', 'localhost:39986/path', 'ftp://localhost:39986']) {
      const bo = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkNOSCHB', origin }) });
      assert.equal(bo.status, 400, j(bo.body)); assert.equal(bo.body.reason, 'bad_origin', `주소 ${origin}`);
    }
    const local = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkLOCAL', origin: 'http://localhost:39988' }) });
    assert.equal(local.body.command, `bash scripts/new_rp.sh zkLOCAL 39988 ${local.body.key}`, 'localhost 면 new_rp.sh 기본과 같아 포트만');
    const tls = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkTLS', origin: 'https://rp.example.com' }) });
    assert.equal(tls.body.command, `bash scripts/new_rp.sh zkTLS 443 ${tls.body.key} --host rp.example.com --public-origin https://rp.example.com`, 'https·기본 포트는 --host 와 --public-origin 둘 다');
    const dup = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkTHREE', origin: 'http://127.0.0.1:39989' }) });
    assert.equal(dup.status, 409, j(dup.body), '같은 운영자 안에서 같은 이름 중복');
    assert.equal(dup.body.error, 'name_taken'); assert.equal(dup.body.reason, 'name_taken');
    const dupOrigin = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkTHREEB', origin: 'http://127.0.0.1:39990' }) });
    assert.equal(dupOrigin.status, 409, j(dupOrigin.body), '같은 주소로 두 번째 슬롯은 안 된다'); assert.equal(dupOrigin.body.reason, 'origin_taken');
    const remote = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkREMOTE', origin: 'http://192.168.226.13:3102' }) });
    assert.equal(remote.status, 201, j(remote.body));
    assert.equal(remote.body.command, `bash scripts/new_rp.sh zkREMOTE 3102 ${remote.body.key} --host 192.168.226.13`, 'VM 주소면 --host 를 채운다');
    const me = await withJar('/cia/rp/me');
    assert.equal(me.body.rps.find((r) => r.name === 'zkTHREE').origin, 'http://127.0.0.1:39990', '묶이기 전에도 슬롯의 주소가 보인다');
    const lo = await withJar('/cia/rp/logout', { method: 'POST', body: JSON.stringify({}) });
    assert.equal(lo.status, 200, j(lo.body));
    assert.equal((await withJar('/cia/rp/me')).status, 401, '로그아웃 뒤');
  });

  await t('register_rp with rp_key: 운영자에 연결(/cia/rp/me 에 arid·pending), 틀린 키 400 bad_rp_key, 이름 다르면 400; 키 없는 등록은 지금처럼 허용', async () => {
    const withJar = makeJar(cia.base);
    await withJar('/cia/rp/signup', { method: 'POST', body: JSON.stringify({ id: 'op-twelve', pwd: 'operator-pw-2' }) });
    await withJar('/cia/rp/login', { method: 'POST', body: JSON.stringify({ id: 'op-twelve', pwd: 'operator-pw-2' }) });
    const origin = 'http://127.0.0.1:39991';
    const create = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkFOUR', origin }) });
    assert.equal(create.status, 201, j(create.body));
    const { key } = create.body;

    const badKey = await cia.post('/cia/register_rp', { ...(await rpRegBody('zkFOUR', origin)), rp_key: 'f'.repeat(64) });
    assert.equal(badKey.status, 400, j(badKey.body)); assert.equal(badKey.body.error, 'bad_rp_key', '틀린 키');
    // 2026-11-06: 키·이름은 맞지만 슬롯에 적은 서비스 주소와 다른 origin 으로 등록하면 origin_mismatch.
    const badOrigin = await cia.post('/cia/register_rp', { ...(await rpRegBody('zkFOUR', 'http://127.0.0.1:39999')), rp_key: key });
    assert.equal(badOrigin.status, 400, j(badOrigin.body)); assert.equal(badOrigin.body.error, 'origin_mismatch', '슬롯 주소와 다르다');

    const badName = await cia.post('/cia/register_rp', { ...(await rpRegBody('zkWRONGNAME', 'http://127.0.0.1:39992')), rp_key: key });
    assert.equal(badName.status, 400, j(badName.body)); assert.equal(badName.body.error, 'bad_rp_key', '키는 맞지만 이름이 다르다');

    // 실제 RP(mode3_rp.js)는 등록 파일에 자기 서비스 키를 고정해 두고 매 폴링마다 같은 본문을 다시 보낸다 — 여기서도
    // 같은 본문을 재사용한다(새 pk_service 를 또 생성하면 같은 origin 에 다른 키라 service_key_mismatch(409)로 깨진다).
    const okBody = { ...(await rpRegBody('zkFOUR', origin)), rp_key: key };
    const ok = await cia.post('/cia/register_rp', okBody);
    assert.equal(ok.status, 202, j(ok.body), '키가 맞으면 평소처럼 pending');

    const me = await withJar('/cia/rp/me');
    assert.equal(me.status, 200, j(me.body));
    const mine = me.body.rps.find((r) => r.name === 'zkFOUR');
    assert.ok(mine, 'rp/me 에 zkFOUR 가 보여야 한다');
    assert.equal(mine.status, 'pending'); assert.equal(mine.arid, ok.body.arid);
    // 수정 라운드 1: 묶인 뒤의 requestedAt 은 등록 요청 시각(e.requestedAt) 이고, createdAt(슬롯 생성 시각)은 따로 남는다 —
    // 슬롯은 register_rp 로 묶이기 전에 먼저 만들어지므로 requestedAt 은 createdAt 과 같거나 그 뒤다.
    assert.ok(typeof mine.requestedAt === 'string' && typeof mine.createdAt === 'string');
    assert.ok(new Date(mine.requestedAt) >= new Date(mine.createdAt), 'requestedAt(등록 요청) 은 createdAt(슬롯 생성) 과 같거나 그 뒤');

    const adminRps = await cia.adminGet('/cia/rps');
    const adminEntry = adminRps.body.rps.find((r) => r.arid === ok.body.arid);
    assert.equal(adminEntry.operator, 'op-twelve', '관리자 RP 목록에 운영자가 보인다');

    // 재시도(같은 키·같은 본문으로 다시 register_rp) 는 지금처럼 같은 상태를 돌려준다(폴링 호환) — bad_rp_key 로 깨지지 않는다.
    const retry = await cia.post('/cia/register_rp', okBody);
    assert.equal(retry.status, 202, j(retry.body), '같은 origin 재호출은 이미 있는 arid 로 pending 상태 조회');

    // 리뷰 A-I2(2026-11-03): 승인 전(pending·denied) 항목은 운영자 키로 다시 등록해 선점을 되돌릴 수 있다 — 키 없이·다른 키는 여전히 409.
    const denied = await cia.adminPost(`/cia/rps/${ok.body.arid}/deny`);
    assert.equal(denied.status, 200, j(denied.body));
    const squat = await cia.post('/cia/register_rp', await rpRegBody('zkFOUR', origin));
    assert.equal(squat.status, 409, j(squat.body), '다른 키·rp_key 없음은 409');
    const wrongName = await cia.post('/cia/register_rp', { ...(await rpRegBody('zkOTHER', origin)), rp_key: key });
    assert.equal(wrongName.status, 400, j(wrongName.body), '키는 맞지만 이름이 다르면 bad_rp_key');
    const reclaim = await cia.post('/cia/register_rp', { ...(await rpRegBody('zkFOUR', origin)), rp_key: key });
    assert.equal(reclaim.status, 202, j(reclaim.body), '운영자 키로 다시 등록하면 pending');
    assert.equal(reclaim.body.arid, ok.body.arid, '같은 arid 를 유지한다');
    const after = (await cia.adminGet('/cia/rps')).body.rps.find((r) => r.arid === ok.body.arid);
    assert.equal(after.status, 'pending'); assert.equal(after.operator, 'op-twelve');

    // 키 없는 등록(zkONE·zkTWO 의 기동 자동 등록과 같은 경로)은 지금처럼 허용하고 운영자 없음으로 남는다.
    const keylessOrigin = 'http://127.0.0.1:39993';
    const keyless = await cia.post('/cia/register_rp', await rpRegBody('zkLEGACY', keylessOrigin));
    assert.equal(keyless.status, 202, j(keyless.body), '키 없는 등록은 여전히 허용');
    const keylessEntry = (await cia.adminGet('/cia/rps')).body.rps.find((r) => r.arid === keyless.body.arid);
    assert.equal(keylessEntry.operator, null, '키 없는 등록은 운영자 없음');
  });

  await t('운영자 인증서 발급 요청(2026-11-06): 키 없는 등록을 같은 이름·주소의 슬롯에 묶고 /cia/rp/request_cert 가 요청을 적으면 관리자 승인 뒤 발급; 미등록 409, 이름 불일치 409, 승인 뒤 재요청 409', async () => {
    const withJar = makeJar(cia.base);
    await withJar('/cia/rp/signup', { method: 'POST', body: JSON.stringify({ id: 'op-thirteen', pwd: 'operator-pw-3' }) });
    await withJar('/cia/rp/login', { method: 'POST', body: JSON.stringify({ id: 'op-thirteen', pwd: 'operator-pw-3' }) });
    const unknown = await withJar('/cia/rp/request_cert', { method: 'POST', body: JSON.stringify({ name: 'zkNOBODY' }) });
    assert.equal(unknown.status, 404, j(unknown.body)); assert.equal(unknown.body.reason, 'unknown_rp');

    // (1) 등록이 먼저(zkONE·zkTWO 처럼 키 없이 기동) → 뒤에 운영자가 같은 이름·주소로 만들면 그 등록에 묶인다.
    const origin1 = 'http://127.0.0.1:39995';
    const body1 = await rpRegBody('zkSEVEN', origin1);
    const reg1 = await cia.post('/cia/register_rp', body1);
    assert.equal(reg1.status, 202, j(reg1.body));
    const wrongName = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkSEVENX', origin: origin1 }) });
    assert.equal(wrongName.status, 409, j(wrongName.body)); assert.equal(wrongName.body.reason, 'origin_name_mismatch'); assert.equal(wrongName.body.registeredName, 'zkSEVEN');
    const c1 = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkSEVEN', origin: origin1 }) });
    assert.equal(c1.status, 201, j(c1.body)); assert.equal(c1.body.status, 'pending', '이미 들어온 등록에 묶여 바로 발급 대기'); assert.equal(c1.body.arid, reg1.body.arid);
    assert.equal((await cia.adminGet('/cia/rps')).body.rps.find((r) => r.arid === reg1.body.arid).operator, 'op-thirteen', '묶이면 관리자 목록에 운영자가 보인다');
    const withJar2 = makeJar(cia.base);
    await withJar2('/cia/rp/signup', { method: 'POST', body: JSON.stringify({ id: 'op-fourteen', pwd: 'operator-pw-4' }) });
    await withJar2('/cia/rp/login', { method: 'POST', body: JSON.stringify({ id: 'op-fourteen', pwd: 'operator-pw-4' }) });
    const taken = await withJar2('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkSEVEN', origin: origin1 }) });
    assert.equal(taken.status, 409, j(taken.body)); assert.equal(taken.body.reason, 'origin_taken', '다른 운영자는 같은 주소를 못 가져간다');
    const notMine = await withJar2('/cia/rp/request_cert', { method: 'POST', body: JSON.stringify({ name: 'zkSEVEN' }) });
    assert.equal(notMine.status, 404, j(notMine.body), '다른 운영자의 RP 에는 발급할 수 없다');
    assert.ok(!(await cia.get('/cia/rp_origins')).body.origins.includes(origin1), '발급 전에는 공개 목록에 없다');
    const req1 = await withJar('/cia/rp/request_cert', { method: 'POST', body: JSON.stringify({ name: 'zkSEVEN' }) });
    assert.equal(req1.status, 200, j(req1.body)); assert.equal(req1.body.requested, true); assert.equal(req1.body.status, 'pending', '요청은 승인이 아니다'); assert.equal(req1.body.arid, reg1.body.arid);
    assert.equal((await cia.post('/cia/register_rp', body1)).status, 202, '요청만으로는 RP 폴링이 아직 pending');
    assert.ok((await cia.adminGet('/cia/rps')).body.rps.find((r) => r.arid === reg1.body.arid).certRequestedAt, '관리자 목록에 요청 시각이 보인다');
    assert.equal((await withJar('/cia/rp/me')).body.rps.find((r) => r.name === 'zkSEVEN').certRequestedAt, req1.body.certRequestedAt, '운영자 표에도 요청 상태');
    const req1b = await withJar('/cia/rp/request_cert', { method: 'POST', body: JSON.stringify({ name: 'zkSEVEN' }) });
    assert.equal(req1b.body.certRequestedAt, req1.body.certRequestedAt, '재요청은 멱등');
    assert.equal((await cia.adminPost(`/cia/rps/${reg1.body.arid}/approve`)).status, 200, '관리자가 승인한다');
    const poll1 = await cia.post('/cia/register_rp', body1);
    assert.equal(poll1.status, 200, j(poll1.body), 'RP 서버의 다음 폴링이 인증서를 받는다'); assert.ok(poll1.body.cert_s && poll1.body.pk_trace, '인증서·조합 키');
    assert.ok((await cia.get('/cia/rp_origins')).body.origins.includes(origin1), '발급 뒤 공개 목록에 있다');
    const again = await withJar('/cia/rp/request_cert', { method: 'POST', body: JSON.stringify({ name: 'zkSEVEN' }) });
    assert.equal(again.status, 409, j(again.body)); assert.equal(again.body.reason, 'already_issued');
    assert.equal((await withJar('/cia/rp/me')).body.rps.find((r) => r.name === 'zkSEVEN').status, 'approved');
    // 2026-11-06: 관리자 인증서 회수 → 다시 pending(조합 키 유지) → RP 폴링 202 → 운영자 재요청 → 승인 → 폴링 200, 같은 arid·pk_trace.
    const pkBefore = poll1.body.pk_trace;
    const rev = await cia.adminPost(`/cia/rps/${reg1.body.arid}/revoke_cert`);
    assert.equal(rev.status, 200, j(rev.body)); assert.equal(rev.body.status, 'pending');
    assert.equal((await cia.adminPost(`/cia/rps/${reg1.body.arid}/revoke_cert`)).status, 409, '이미 pending 이면 409');
    assert.equal((await cia.post('/cia/register_rp', body1)).status, 202, '회수 뒤 RP 폴링은 다시 202');
    assert.ok(!(await cia.get('/cia/rp_origins')).body.origins.includes(origin1), '회수 뒤 공개 목록에서 빠진다');
    const mineRev = (await withJar('/cia/rp/me')).body.rps.find((r) => r.name === 'zkSEVEN');
    assert.equal(mineRev.status, 'pending'); assert.equal(mineRev.certRequestedAt, null, '요청 표시도 지워져 다시 요청할 수 있다');
    assert.equal((await withJar('/cia/rp/request_cert', { method: 'POST', body: JSON.stringify({ name: 'zkSEVEN' }) })).status, 200);
    assert.equal((await cia.adminPost(`/cia/rps/${reg1.body.arid}/approve`)).status, 200);
    const poll1b = await cia.post('/cia/register_rp', body1);
    assert.equal(poll1b.status, 200, j(poll1b.body)); assert.equal(poll1b.body.arid, reg1.body.arid);
    assert.deepEqual(poll1b.body.pk_trace, pkBefore, '재승인은 조합 키를 바꾸지 않는다(팩토리·계정 주소 유지)');

    // (2) 슬롯이 먼저 → 키 없는 등록은 같은 이름·주소라도 묶이지 않는다(리뷰 HIGH-2: 키로 쓸 슬롯을 가짜가 차지하지 못하게). 등록 전 발급은 409.
    const origin2 = 'http://127.0.0.1:39996';
    const c2 = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkEIGHT', origin: origin2 }) });
    assert.equal(c2.status, 201, j(c2.body)); assert.equal(c2.body.status, 'created');
    const early = await withJar('/cia/rp/request_cert', { method: 'POST', body: JSON.stringify({ name: 'zkEIGHT' }) });
    assert.equal(early.status, 409, j(early.body)); assert.equal(early.body.reason, 'rp_not_registered');
    const squatBody = await rpRegBody('zkEIGHT', origin2);
    const squat2 = await cia.post('/cia/register_rp', squatBody);
    assert.equal(squat2.status, 202, j(squat2.body), '같은 이름·주소의 키 없는 등록은 받되 운영자 없는 등록으로 남는다');
    assert.equal((await cia.adminGet('/cia/rps')).body.rps.find((r) => r.arid === squat2.body.arid).operator, null);
    assert.equal((await withJar('/cia/rp/me')).body.rps.find((r) => r.name === 'zkEIGHT').status, 'created', '슬롯은 그대로 만들어짐 — 발급 버튼이 생기지 않는다');
    assert.equal((await withJar('/cia/rp/request_cert', { method: 'POST', body: JSON.stringify({ name: 'zkEIGHT' }) })).body.reason, 'rp_not_registered');
    // 진짜 RP 가 이 슬롯의 키로 등록하면 가짜(pending) 등록을 되찾아 슬롯에 묶인다; 주소가 슬롯과 다르면 되찾기 분기에서도 origin_mismatch.
    const realBody = { ...(await rpRegBody('zkEIGHT', origin2)), rp_key: c2.body.key };
    const wrongOriginReclaim = await cia.post('/cia/register_rp', { ...(await rpRegBody('zkEIGHT', 'http://127.0.0.1:39986')), rp_key: c2.body.key });
    assert.equal(wrongOriginReclaim.status, 400, j(wrongOriginReclaim.body)); assert.equal(wrongOriginReclaim.body.error, 'origin_mismatch');
    const real2 = await cia.post('/cia/register_rp', realBody);
    assert.equal(real2.status, 202, j(real2.body)); assert.equal(real2.body.arid, squat2.body.arid, '같은 arid 를 유지하며 키가 바뀐다');
    const mine2 = (await withJar('/cia/rp/me')).body.rps.find((r) => r.name === 'zkEIGHT');
    assert.equal(mine2.status, 'pending'); assert.equal(mine2.arid, squat2.body.arid);
    const req2 = await withJar('/cia/rp/request_cert', { method: 'POST', body: JSON.stringify({ name: 'zkEIGHT' }) });
    assert.equal(req2.status, 200, j(req2.body));
    assert.equal((await cia.adminPost(`/cia/rps/${squat2.body.arid}/approve`)).status, 200);
    assert.equal((await cia.post('/cia/register_rp', realBody)).status, 200, '진짜 RP 의 폴링이 인증서를 받는다');
    assert.equal((await cia.post('/cia/register_rp', squatBody)).status, 409, '가짜(옛 키)는 service_key_mismatch');
    // 키 등록(선점 없음)이 슬롯에 묶이는 평범한 경로 + 관리자 승인 뒤 issue 는 already_issued.
    const origin3 = 'http://127.0.0.1:39997';
    const c3 = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkNINE', origin: origin3 }) });
    assert.equal(c3.status, 201, j(c3.body));
    const body3 = { ...(await rpRegBody('zkNINE', origin3)), rp_key: c3.body.key };
    const reg3 = await cia.post('/cia/register_rp', body3);
    assert.equal(reg3.status, 202, j(reg3.body));
    const mine3 = (await withJar('/cia/rp/me')).body.rps.find((r) => r.name === 'zkNINE');
    assert.equal(mine3.status, 'pending'); assert.equal(mine3.arid, reg3.body.arid, '키 등록이 슬롯에 묶였다');
    assert.equal((await cia.adminPost(`/cia/rps/${reg3.body.arid}/approve`)).status, 200, '관리자 승인은 그대로 된다');
    const afterAdmin = await withJar('/cia/rp/request_cert', { method: 'POST', body: JSON.stringify({ name: 'zkNINE' }) });
    assert.equal(afterAdmin.status, 409, j(afterAdmin.body)); assert.equal(afterAdmin.body.reason, 'already_issued');
    assert.equal((await cia.post('/cia/register_rp', body3)).status, 200, '승인 뒤 폴링은 200');
    // 이미 승인된 키 없는 등록(AUTO_APPROVE 경로)에 뒤늦게 슬롯을 만들면 'approved' 로 묶인다.
    const origin5 = 'http://127.0.0.1:39985';
    const reg5 = await cia.post('/cia/register_rp', await rpRegBody('zkELEVEN', origin5));
    assert.equal((await cia.adminPost(`/cia/rps/${reg5.body.arid}/approve`)).status, 200);
    const c5 = await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkELEVEN', origin: origin5 }) });
    assert.equal(c5.status, 201, j(c5.body)); assert.equal(c5.body.status, 'approved'); assert.equal(c5.body.arid, reg5.body.arid);
    // 거부된 등록은 발급할 수 없다(관리자 거절은 그대로 남는다).
    const origin4 = 'http://127.0.0.1:39998';
    const body4 = await rpRegBody('zkTEN', origin4);
    const reg4 = await cia.post('/cia/register_rp', body4);
    assert.equal((await withJar('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkTEN', origin: origin4 }) })).status, 201);
    assert.equal((await cia.adminPost(`/cia/rps/${reg4.body.arid}/deny`)).status, 200);
    const deniedIssue = await withJar('/cia/rp/request_cert', { method: 'POST', body: JSON.stringify({ name: 'zkTEN' }) });
    assert.equal(deniedIssue.status, 409, j(deniedIssue.body)); assert.equal(deniedIssue.body.reason, 'rp_denied');
    // 2026-11-06: 관리자 reopen — 거절 → 다시 pending(키 그대로) → RP 폴링 202 → 요청·승인 가능. approved 항목에는 409.
    assert.equal((await cia.adminPost(`/cia/rps/${reg4.body.arid}/reopen`)).body.status, 'pending');
    assert.equal((await cia.adminPost(`/cia/rps/${reg4.body.arid}/reopen`)).status, 409, '이미 pending 이면 409');
    assert.equal((await cia.post('/cia/register_rp', body4)).status, 202, 'reopen 뒤 같은 키의 RP 폴링은 202');
    assert.equal((await withJar('/cia/rp/request_cert', { method: 'POST', body: JSON.stringify({ name: 'zkTEN' }) })).status, 200, 'reopen 뒤 운영자 요청 가능');
    assert.equal((await cia.adminPost(`/cia/rps/${reg4.body.arid}/deny`)).status, 200, '다시 거절(아래 넘겨받기 케이스가 거부 상태를 전제한다)');
    // 거부된 주소는 다른 운영자가 넘겨받을 수 있고, 그러면 옛 슬롯은 은퇴한다(리뷰 MEDIUM-2) — 옛 키로는 더 되찾지 못한다.
    const take = await withJar2('/cia/rp/create', { method: 'POST', body: JSON.stringify({ name: 'zkTEN', origin: origin4 }) });
    assert.equal(take.status, 201, j(take.body)); assert.equal(take.body.status, 'created', '거부된 항목에는 묶지 않는다');
    assert.equal((await withJar('/cia/rp/me')).body.rps.find((r) => r.name === 'zkTEN').status, 'retired', '옛 슬롯은 은퇴');
    const newOwner = { ...(await rpRegBody('zkTEN', origin4)), rp_key: take.body.key };
    const reclaimNew = await cia.post('/cia/register_rp', newOwner);
    assert.equal(reclaimNew.status, 202, j(reclaimNew.body), '새 운영자의 키는 거부된 항목을 되찾아 pending');
    assert.equal((await withJar2('/cia/rp/me')).body.rps.find((r) => r.name === 'zkTEN').status, 'pending');
  });

  await t('지갑 연결 해제(2026-11-06): 등록된 계정에서 auid 를 풀고 활성 자격증명을 은퇴·게시(disabled 아님) → me.registered=false → 같은 계정에 새 지갑을 다시 등록(새 슬롯); 비밀번호 틀리면 401, 미등록이면 409', async () => {
    const withJar = makeJar(cia.base);
    const su = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'unlink-1', pwd: 'password-u1' }) });
    await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ id: 'unlink-1', pwd: 'password-u1' }) });
    assert.equal((await withJar('/cia/user/unlink_wallet', { method: 'POST', body: JSON.stringify({ pwd: 'password-u1' }) })).status, 409, '등록 전엔 풀 것이 없다');
    const reg1 = async () => {
      const rc = await withJar('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
      const reg = await createRegistration(BigInt(su.body.uid));
      const rr = await cia.post('/cia/register', { uid: su.body.uid, code: rc.body.code, ...(await regBody(reg, su.body.uid)) });
      assert.equal(rr.status, 201, j(rr.body)); return { ...rr.body, reg };
    };
    const first = await reg1();
    const me1 = (await withJar('/cia/user/me')).body; assert.equal(me1.registered, true);
    // R11·P7(2026-11-13 스펙 random-salt): 같은 스냅(같은 salt → 같은 auid)으로 다른 계정을 등록하면 auid_taken — 연결을 풀면 그 스냅을 다른 계정에 쓸 수 있다(아래).
    const jar2 = makeJar(cia.base);
    const su2 = await jar2('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'unlink-2', pwd: 'password-u2' }) });
    await jar2('/cia/user/login', { method: 'POST', body: JSON.stringify({ id: 'unlink-2', pwd: 'password-u2' }) });
    const regSameSnap = async () => {
      const rc = await jar2('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
      const reg = await createRegistration(BigInt(su2.body.uid), Buffer.from(first.reg.seed, 'hex'));
      assert.equal(reg.auid, first.reg.auid, '같은 salt → 같은 auid');
      return cia.post('/cia/register', { uid: su2.body.uid, code: rc.body.code, ...(await regBody(reg, su2.body.uid)) });
    };
    const taken = await regSameSnap();
    assert.equal(taken.status, 409, j(taken.body)); assert.equal(taken.body.reason, 'auid_taken');
    assert.equal((await jar2('/cia/user/me')).body.registered, false);
    assert.equal((await withJar('/cia/user/unlink_wallet', { method: 'POST', body: JSON.stringify({ pwd: 'wrong' }) })).status, 401);
    const un = await withJar('/cia/user/unlink_wallet', { method: 'POST', body: JSON.stringify({ pwd: 'password-u1' }) });
    assert.equal(un.status, 200, j(un.body)); assert.equal(un.body.unlinked, true); assert.equal(un.body.retired, 0, '발급 전이라 은퇴할 자격증명은 없다');
    const me2 = (await withJar('/cia/user/me')).body; assert.equal(me2.registered, false, '지갑 연결이 풀렸다'); assert.equal(me2.disabled, false, '계정은 폐기되지 않았다');
    assert.equal((await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === su.body.uid).auid, null, '연결을 풀면 auid 가 비고(등록됨의 표지), 옛 슬롯 번호는 남는다');
    assert.equal((await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ id: 'unlink-1', pwd: 'password-u1' }) })).status, 200, '같은 아이디로 계속 로그인된다');
    const freed = await regSameSnap();
    assert.equal(freed.status, 201, j(freed.body) + ' — 연결을 푼 계정의 auid 는 다른 계정이 쓸 수 있다(P7)');
    const second = await reg1();
    assert.notEqual(second.slot, first.slot, '다시 등록하면 새 슬롯');
    assert.equal((await withJar('/cia/user/me')).body.registered, true);
    // 2026-11-12(사용자 결정): 계정의 최신 auid_s(lastAuidS)는 옛 auid 에서 나온 값이라 연결을 풀면 함께 지운다.
    const lastOf = async () => (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === su.body.uid).lastAuidS;
    assert.equal(await lastOf(), null, '발급 전에는 없다');
    const is = await issueV11(cia, userOf({ ...second.reg, slot: second.slot }, su.body.uid, TESTUSER_ATTRS), { arid, provider });
    assert.equal(is.r.status, 200, j(is.r.body)); assert.equal((await lastOf())?.value, is.req.auid_s.toString());
    assert.equal((await withJar('/cia/user/unlink_wallet', { method: 'POST', body: JSON.stringify({ pwd: 'password-u1' }) })).status, 200);
    assert.equal(await lastOf(), null, '연결을 풀면 최신 auid_s 도 지운다');
  });

  await t('계정 삭제(2026-11-06, 관리자): 가입만 한 계정은 레코드·아이디 색인이 지워져 같은 아이디로 재가입; 등록된 계정은 먼저 폐기(슬롯 0)되고 지워진다; 모르는 uid 404; 시크릿 없이 401', async () => {
    const withJar = makeJar(cia.base);
    const su = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'del-1', pwd: 'password-d1' }) });
    assert.equal(su.status, 201, j(su.body));
    assert.equal((await cia.post('/cia/account/delete', { uid: su.body.uid })).status, 401, '관리자 시크릿 없이는 안 된다');
    assert.equal((await cia.adminPost('/cia/account/delete', { uid: '424242' })).status, 404, '모르는 uid');
    const d1 = await cia.adminPost('/cia/account/delete', { uid: su.body.uid });
    assert.equal(d1.status, 200, j(d1.body)); assert.equal(d1.body.deleted, true); assert.equal(d1.body.id, 'del-1'); assert.equal(d1.body.revoked, null, '등록 전 계정은 폐기 단계가 없다');
    assert.equal((await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ id: 'del-1', pwd: 'password-d1' }) })).status, 401, '지운 계정으로는 로그인할 수 없다');
    assert.ok(!(await cia.adminGet('/cia/accounts')).body.accounts.some((a) => a.uid === su.body.uid), '관리자 목록에서 사라진다');
    const su2 = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'del-1', pwd: 'password-d1b' }) });
    assert.equal(su2.status, 201, j(su2.body), '같은 아이디로 다시 가입할 수 있다'); assert.notEqual(su2.body.uid, su.body.uid, 'uid 는 새로 받는다');
    // 등록된 계정: 가입 → 로그인 → register_code → 등록 → 삭제. 슬롯은 0 으로 비워지고(폐기) 레코드가 사라진다.
    const withJar2 = makeJar(cia.base);
    const su3 = await withJar2('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'del-2', pwd: 'password-d2' }) });
    await withJar2('/cia/user/login', { method: 'POST', body: JSON.stringify({ id: 'del-2', pwd: 'password-d2' }) });
    const rc = await withJar2('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
    const reg = await createRegistration(BigInt(su3.body.uid));
    const rr = await cia.post('/cia/register', { uid: su3.body.uid, code: rc.body.code, ...(await regBody(reg, su3.body.uid)) });
    assert.equal(rr.status, 201, j(rr.body));
    const before = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === su3.body.uid);
    assert.ok(Number.isInteger(before.slot), '등록된 계정은 슬롯이 있다');
    const d2 = await cia.adminPost('/cia/account/delete', { uid: su3.body.uid });
    assert.equal(d2.status, 200, j(d2.body)); assert.equal(d2.body.deleted, true);
    assert.ok(d2.body.revoked && d2.body.revoked.disabled === true && d2.body.revoked.slot === before.slot, '등록된 계정은 먼저 폐기된다');
    assert.ok(!(await cia.adminGet('/cia/accounts')).body.accounts.some((a) => a.uid === su3.body.uid), '레코드가 사라진다');
    // 등록만 하고 발급 전인 슬롯은 리프가 없어 등록부 목록에 아예 안 나온다(entries 는 채워진 칸만). 나오더라도 uid 없는 빈 칸(leaf 0)이어야 한다.
    const regView = (await cia.adminGet('/cia/admin/registry')).body.slots.find((sl) => sl.index === before.slot);
    assert.ok(!regView || (regView.uid === null && regView.leaf === '0'), `등록부 슬롯은 uid 없는 빈 칸으로 남고 재사용되지 않는다: ${j(regView)}`);
    assert.ok((await cia.adminGet('/cia/admin/registry')).body.next > before.slot, '슬롯 번호는 되돌리지 않는다');
    assert.equal((await withJar2('/cia/user/me')).status, 401, '그 계정의 세션은 더 쓸 수 없다');
    assert.equal((await withJar2('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'del-2', pwd: 'password-d2' }) })).status, 201, '같은 아이디로 재가입');
  });

  await t('rp_origins: 승인 전 빈 목록, 관리자 승인 뒤 origin 포함(공개, 세션 불필요)', async () => {
    const origin = 'http://127.0.0.1:39994';
    const r1 = await cia.post('/cia/register_rp', await rpRegBody('zkSIX', origin));
    assert.equal(r1.status, 202, j(r1.body));
    const before = await cia.get('/cia/rp_origins');
    assert.equal(before.status, 200, j(before.body));
    assert.ok(!before.body.origins.includes(origin), '승인 전에는 목록에 없다');
    const approve = await cia.adminPost(`/cia/rps/${r1.body.arid}/approve`);
    assert.equal(approve.status, 200, j(approve.body));
    const after = await cia.get('/cia/rp_origins');
    assert.equal(after.status, 200, j(after.body));
    assert.ok(after.body.origins.includes(origin), '승인 뒤에는 목록에 있다');
    assert.ok(!('arid' in after.body) && !('rps' in after.body), '공개 응답은 origin 외에 다른 필드를 내지 않는다');
  });

  await t('수정 라운드 1(스펙 §3.2): 사용자·운영자 세션은 같은 쿠키에 공존 — 한쪽 로그아웃이 다른 쪽을 지우지 않는다', async () => {
    const jar = {};
    const call = async (p, body) => {
      const r = await fetch(`${cia.base}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(jar.cookie ? { Cookie: jar.cookie } : {}) }, body: JSON.stringify(body ?? {}) });
      const sc = r.headers.get('set-cookie');
      if (sc) jar.cookie = sc.split(';')[0];
      return { status: r.status, body: await r.json().catch(() => null), setCookie: sc };
    };
    const get = async (p) => {
      const r = await fetch(`${cia.base}${p}`, { headers: jar.cookie ? { Cookie: jar.cookie } : {} });
      return { status: r.status, body: await r.json().catch(() => null) };
    };

    const su = await call('/cia/signup', { id: 'coexist-1', pwd: 'coexist-pw-1' });
    assert.equal(su.status, 201, j(su.body));
    const uid = su.body.uid;
    const opSignup = await call('/cia/rp/signup', { id: 'op-coexist', pwd: 'coexist-pw-2' });
    assert.equal(opSignup.status, 201, j(opSignup.body));

    const userLogin = await call('/cia/user/login', { uid, pwd: 'coexist-pw-1' });
    assert.equal(userLogin.status, 200, j(userLogin.body));
    const sidAfterUser = jar.cookie;

    const opLogin = await call('/cia/rp/login', { id: 'op-coexist', pwd: 'coexist-pw-2' });
    assert.equal(opLogin.status, 200, j(opLogin.body));
    const sidAfterOp = jar.cookie;
    assert.notEqual(sidAfterOp, sidAfterUser, '운영자 로그인도 세션 고정 방지로 sid 를 회전한다');

    assert.equal((await get('/cia/user/me')).status, 200, '운영자 로그인 뒤에도 사용자 세션이 살아있다(공존)');
    assert.equal((await get('/cia/rp/me')).status, 200);

    const opLogout = await call('/cia/rp/logout', {});
    assert.equal(opLogout.status, 200, j(opLogout.body)); assert.equal(opLogout.body.ok, true);
    const sidAfterOpLogout = jar.cookie;
    assert.notEqual(sidAfterOpLogout, sidAfterOp, '운영자 로그아웃도(다른 역할이 남아 있어) sid 를 회전한다');
    assert.equal((await get('/cia/rp/me')).status, 401, '운영자 로그아웃 뒤 운영자 세션만 지워진다');
    assert.equal((await get('/cia/user/me')).status, 200, '사용자 세션은 그대로 보존된다');

    const userLogout = await call('/cia/user/logout', {});
    assert.equal(userLogout.status, 200, j(userLogout.body)); assert.equal(userLogout.body.ok, true);
    assert.ok(userLogout.setCookie && /cia\.sid=;/.test(userLogout.setCookie) && /expires=/i.test(userLogout.setCookie),
      '다른 역할이 남아 있지 않으면 지금처럼 clearCookie 로 쿠키를 만료시킨다');
    assert.equal((await get('/cia/user/me')).status, 401);
    assert.equal((await get('/cia/rp/me')).status, 401);
  });
  // 2026-11-09 Phase 1: 프로필 name(속성 커밋먼트) + OIDC 모양 ID 토큰. 별도 IdP 로 돈다(이 파일의 기본 IdP 는 앞 케이스들이 12345 를 쓴다).
  await t('프로필(/cia/user/profile): 세션 필수(401), 형식 검사(400 bad_profile), 저장 → /me.profile, 빈 값이면 지움; discovery·JWKS 공개; 발급 응답 id_token(ES256) 은 JWKS 로 검증되고 sub=auid_s·aud=arid_s·name=프로필·exp 10분', async () => {
    const cia7 = await startIsolatedCia();
    try {
      const attrs = await encodeProfile(DEFAULT_ATTR_SCHEMA, { birthYear: '1990', country: 'KR' });
      const C = await attrCommit({ s_u: '2', attrs });
      assert.equal((await cia7.post('/cia/user/profile', { name: C })).status, 401, '세션 없음');
      const withJar = makeJar(cia7.base);
      const li = await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid: '12345', pwd: 'password123' }) });
      assert.equal(li.status, 200, j(li.body));
      assert.equal((await withJar('/cia/user/me')).body.profile, null, '처음엔 프로필 없음');
      for (const name of ['a\nb', 'x'.repeat(257), 123, null]) {
        const bad = await withJar('/cia/user/profile', { method: 'POST', body: JSON.stringify({ name }) });
        assert.equal(bad.status, 400, `bad_profile: ${JSON.stringify(name)?.slice(0, 20)}`); assert.equal(bad.body.reason, 'bad_profile');
      }
      const ok = await withJar('/cia/user/profile', { method: 'POST', body: JSON.stringify({ name: `  ${C} ` }) });
      assert.equal(ok.status, 200, j(ok.body)); assert.equal(ok.body.profile.name, C, '앞뒤 공백 제거');
      assert.equal((await withJar('/cia/user/me')).body.profile.name, C);
      // discovery·JWKS — 공개, 개인키 d 없음
      const disc = await cia7.get('/.well-known/openid-configuration');
      assert.equal(disc.status, 200); assert.equal(disc.body.issuer, cia7.base); assert.equal(disc.body.jwks_uri, `${cia7.base}/.well-known/jwks.json`);
      assert.deepEqual(disc.body.id_token_signing_alg_values_supported, ['ES256']);
      const jwks = await cia7.get('/.well-known/jwks.json');
      assert.equal(jwks.status, 200); assert.equal(jwks.body.keys.length, 1);
      const k = jwks.body.keys[0];
      assert.equal(k.kty, 'EC'); assert.equal(k.crv, 'P-256'); assert.equal(k.alg, 'ES256'); assert.equal(k.use, 'sig'); assert.ok(k.kid && k.x && k.y); assert.equal(k.d, undefined, '개인키가 새면 안 된다');
      // 발급 → id_token
      const u = userOf(await cia7.registerUser('12345', 'password123'), '12345', TESTUSER_ATTRS);
      const iss = await issueV11(cia7, u, { arid, provider });
      assert.equal(iss.r.status, 200, j(iss.r.body));
      assert.equal(typeof iss.cred.id_token, 'string');
      const keyset = createLocalJWKSet(jwks.body);
      const { payload, protectedHeader } = await jwtVerify(iss.cred.id_token, keyset, { issuer: cia7.base, audience: iss.req.arid_s.toString(), algorithms: ['ES256'] });
      assert.equal(protectedHeader.kid, k.kid);
      assert.equal(payload.sub, iss.req.auid_s.toString(), 'sub = auid_s');
      assert.equal(payload.aud, iss.req.arid_s.toString(), 'aud = arid_s');
      assert.equal(payload.name, undefined, '2026-11-11: 프로필 커밋먼트(C_attr)는 RP 로 가는 ID 토큰에 싣지 않는다 — RP 마다 같은 값이라 RP 간 연결이 된다');
      assert.equal(payload.exp - payload.iat, 600);
      for (const key of ['uid', 'auid', 'arid', 'email']) assert.equal(payload[key], undefined, `${key} 는 토큰에 없다`);
      await assert.rejects(jwtVerify(iss.cred.id_token, keyset, { issuer: cia7.base, audience: '1', algorithms: ['ES256'] }), /aud/, '다른 aud 는 거절');
      // 프로필을 비우면 name 클레임이 빠진다(토큰은 여전히 나온다)
      const cleared = await withJar('/cia/user/profile', { method: 'POST', body: JSON.stringify({ name: '' }) });
      assert.equal(cleared.status, 200); assert.equal(cleared.body.profile, null);
      const iss2 = await issueV11(cia7, u, { arid, provider, blind_u: iss.blind_u });
      assert.equal(iss2.r.status, 200, j(iss2.r.body));
      const { payload: p2 } = await jwtVerify(iss2.cred.id_token, keyset, { issuer: cia7.base, audience: iss2.req.arid_s.toString() });
      assert.equal(p2.name, undefined); assert.equal(p2.sub, iss2.req.auid_s.toString());
    } finally { await cia7.stop(); }
  });
  // 2026-11-11(사용자 결정): 속성 변경 = 내 정보의 커밋먼트를 **다른 값으로** 바꿔 저장. IdP 는 속성 값을 모르므로(D15) 이 저장을 신호로 본다.
  await t('속성 변경(/cia/user/profile 다른 값 저장): 활성 C_u 은퇴·슬롯 0, 살아 있는 세션 폐기 트리 삽입(revokedSessions), 첫 저장·같은 값·비우기는 그대로, 다음 발급이 슬롯을 다시 채운다', async () => {
    const cia8 = await startIsolatedCia();
    try {
      const withJar = makeJar(cia8.base);
      assert.equal((await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid: '12345', pwd: 'password123' }) })).status, 200);
      const u = userOf(await cia8.registerUser('12345', 'password123'), '12345', TESTUSER_ATTRS);
      const iss = await issueV11(cia8, u, { arid, provider });
      assert.equal(iss.r.status, 200, j(iss.r.body));
      const save = (name) => withJar('/cia/user/profile', { method: 'POST', body: JSON.stringify({ name }) });
      const leaves0 = (await cia8.get('/cia/state')).body.leafCount;
      const first = await save('C1');
      assert.equal(first.status, 200, j(first.body)); assert.equal(first.body.revokedSessions, 0, '첫 저장은 변경이 아니다'); assert.equal(first.body.retired, 0);
      assert.ok((await withJar('/cia/user/me')).body.activeCf_u, '첫 저장 뒤에도 C_u 활성');
      const same = await save('C1');
      assert.equal(same.body.revokedSessions, 0, '같은 값'); assert.equal(same.body.retired, 0);
      const ch = await save('C2');
      assert.equal(ch.status, 200, j(ch.body)); assert.equal(ch.body.revokedSessions, 1, j(ch.body)); assert.equal(ch.body.retired, 1);
      const me = (await withJar('/cia/user/me')).body;
      assert.equal(me.activeCf_u, null, '활성 C_u 은퇴'); assert.equal(me.registryLeaf, '0', '슬롯 비움');
      assert.equal((await cia8.get('/cia/state')).body.leafCount, leaves0 + 1, '세션 리프 하나가 폐기 트리에');
      const again = await save('C3');
      assert.equal(again.body.revokedSessions, 0, '이미 폐기된 세션은 다시 넣지 않는다'); assert.equal(again.body.retired, 0);
      const cleared = await save('');
      assert.equal(cleared.status, 200); assert.equal(cleared.body.revokedSessions, 0);
      const iss2 = await issueV11(cia8, u, { arid, provider });
      assert.equal(iss2.r.status, 200, j(iss2.r.body));
      const me2 = (await withJar('/cia/user/me')).body;
      assert.ok(me2.activeCf_u, '다음 발급이 새 C_u'); assert.notEqual(me2.registryLeaf, '0', '슬롯을 다시 채운다');
    } finally { await cia8.stop(); }
  });
} finally { await cia.stop(); }

provider.destroy();
process.exit(failed === 0 ? 0 : 1);
