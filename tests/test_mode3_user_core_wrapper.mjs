// tests/test_mode3_user_core_wrapper.mjs — 웹 코어의 래퍼 로그인(스펙 2026-11-20 zkwrapper §2.2, 계획 Task 3)을 Node 에서(메모리 kv·진짜 snarkjs) 격리 발급 서버(CIA_WRAPPER)·
// Google 대역·RP 에 대고 돌린다. 패스키는 대역(derive 호출 수를 센다). wrapperBegin(요청 키) → Google 토큰 → wrapperLogin(패스키 한 번 → 발급 → π_RP) → 서비스 검증. :8545·build/mode3 필요. (chain)
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createMemKv } from '../mode3/user/core/kv_mem.js';
import { createUserCore } from '../mode3/user/core/user_core.js';
import { randomScalar, auidOf } from '../lib/mode3_credential.js';
import { uidOf } from '../lib/mode3_oidc_nonce.js';
import { wrapperNonce } from '../lib/mode3_wrapper_auth.js';
import { PUB_INDEX } from '../lib/mode3_onchain.js';
import * as snarkjs from 'snarkjs';

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });   // 정적 서버는 dist 가 없으면 기동을 거부한다
const stack = await startIsolatedMode3Stack({ userMode: 'web', walletHost: 'localhost', walletEnv: { MODE3_WALLET_SECRETS: 'passkey-web' }, wrapper: true, autoRelay: true });
const { wallet, rp, cia } = stack;
const stub = stack.oidc;
const provider = getProvider();
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
try {
  const config = { ...(await wallet.get('/user/config')).body, wrapper: true };
  assert.equal(config.secrets, 'passkey-web');
  const fullProve = { idp: () => { throw new Error('래퍼 방식은 π_IdP 를 만들지 않는다'); }, cred: (input, w, z) => snarkjs.groth16.fullProve(input, w, z) };
  /** 브라우저 하나 = kv 하나 + 패스키 하나(salt). sent 에 발급 서버로 간 요청 본문을 모은다. */
  const browser = (salt = randomScalar().toString(), cid = 'Y2lkLWE', now = Date.now) => {
    const kv = createMemKv(), b = { kv, salt, cid, calls: 0, sent: [] };
    const passkey = { derive: async () => { b.calls++; return { credentialId: cid, s_u: salt }; } };
    const fetchSpy = async (url, init) => { if (String(url).includes('/cia/') && init?.body) b.sent.push({ url: String(url), body: JSON.parse(init.body) }); return globalThis.fetch(url, init); };
    b.core = createUserCore({ kv, config, provider, canonProvider: provider, fullProve, passkey, fetch: fetchSpy, now });
    b.dump = async () => { const all = {}; for (const k of await kv.keys()) all[k] = await kv.get(k); return j(all); };
    return b;
  };
  let info = (await rp.get('/api/mode3/rp_info')).body;
  for (let i = 0; i < 50 && !info.attrGateAddress; i++) { await sleep(200); info = (await rp.get('/api/mode3/rp_info')).body; }
  const loginBody = (ch) => ({ arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, allowAgent: '0', factoryAddress: info.factoryAddress, attrGateAddress: info.attrGateAddress });
  const challenge = async () => (await rp.post('/api/mode3/challenge')).body;
  const mint = (sub, nonce) => stub.mint({ sub, nonce, extra: { email: `${sub}@example.com`, email_verified: true } });
  /** 창이 하는 일: wrapperBegin → Google(대역)에서 그 nonce 의 토큰 → wrapperLogin → 서비스 검증. */
  const wlogin = async (b, sub) => {
    const bg = await b.core.wrapperBegin(); assert.equal(bg.status, 200, j(bg.body));
    const idToken = await mint(sub, bg.body.googleNonce);
    const ch = await challenge();
    const r = await b.core.wrapperLogin(loginBody(ch), { idToken, verifiedOrigin: info.origin, googleMs: 1234 });
    if (r.status !== 200) return { r, ch, idToken };
    const v = await rp.post('/api/mode3/login', { proof: r.body.proof, publicSignals: r.body.publicSignals, sig: r.body.sig, r_s: ch.r_s });
    return { r, ch, v, idToken, PPID: r.body.publicSignals[PUB_INDEX.PPID] };
  };
  const accounts = async () => (await cia.adminGet('/cia/accounts')).body.accounts;
  const A = browser(); const UID_A = uidOf(stub.provider, 'g-anna');
  let first;

  await t('패스키 연결 전: wrapperLogin 은 409 passkey_setup_required — 계정·로컬 등록이 생기지 않는다', async () => {
    const out = await wlogin(A, 'g-anna');
    assert.equal(out.r.status, 409, j(out.r.body)); assert.equal(out.r.body.reason, 'passkey_setup_required');
    assert.equal(await A.kv.get('registration'), undefined); assert.equal((await accounts()).some((a) => a.uid === UID_A), false);
  });
  await t('wrapperBegin: 패스키를 묻지 않는다(derive 0회), googleNonce 는 그 요청 키의 "wrap:"…, 개인키는 꺼낼 수 없다', async () => {
    assert.equal((await A.core.passkeyConnect({ credentialId: A.cid, s_u: A.salt })).status, 200);
    const calls0 = A.calls;
    const bg = await A.core.wrapperBegin(); assert.equal(bg.status, 200, j(bg.body));
    assert.ok(bg.body.googleNonce.startsWith('wrap:')); assert.equal(bg.body.googleNonce, await wrapperNonce(bg.body.pkE));
    const wk = await A.kv.get('wrapperKey'); assert.equal(wk.privateKey.extractable, false); assert.deepEqual(wk.pkE, bg.body.pkE);
    assert.equal(A.calls, calls0);
    const again = await A.core.wrapperBegin(); assert.notEqual(again.body.googleNonce, bg.body.googleNonce, '부를 때마다 새 요청 키');
  });
  await t('wrapperLogin(처음): derive 1회, 계정·로컬 등록이 생기고 서비스 검증 통과 — 발급 요청에 uid·n·tag·proof_idp 가 없다', async () => {
    const calls0 = A.calls; A.sent.length = 0;
    first = await wlogin(A, 'g-anna');
    assert.equal(first.r.status, 200, j(first.r.body)); assert.equal(first.v.status, 200, j(first.v.body));
    assert.equal(A.calls - calls0, 1, '패스키는 한 번');
    const issue = A.sent.filter((x) => x.url.endsWith('/cia/issue')); assert.equal(issue.length, 1);
    for (const k of ['uid', 'n', 'tag', 'proof_idp', 'registration', 'auth_code']) assert.equal(k in issue[0].body, false, `발급 요청에 ${k}`);
    for (const k of ['id_token', 'pk_e', 'sig', 'auid', 'auid_s', 'arid_s', 'C_u_pt', 'C_s_pt']) assert.ok(k in issue[0].body, `발급 요청에 ${k} 가 없다`);
    assert.equal(A.sent.some((x) => /\/cia\/(register|slot|signup)/.test(x.url)), false, '등록·슬롯 경로를 부르지 않는다');
    const reg = await A.kv.get('registration');
    assert.equal(reg.uid, UID_A); assert.equal(reg.auid, (await auidOf({ s_u: BigInt(A.salt) })).toString()); assert.equal(Number.isInteger(reg.slot), true); assert.ok(!reg.pendingIdp); assert.equal(reg.wrapper, true);
    const acct = (await accounts()).find((a) => a.uid === UID_A); assert.equal(acct.auid, reg.auid); assert.equal(acct.id, 'g-anna@example.com');
  });
  await t('끝난 뒤 kv 에 요청 키·salt·Google 토큰이 없다', async () => {
    assert.equal(await A.kv.get('wrapperKey'), undefined);
    const d = await A.dump(); assert.ok(!d.includes(A.salt), 'salt 가 남았다'); assert.ok(!d.includes(first.idToken), 'Google 토큰이 남았다');
  });
  await t('loginFlow 기록: prove_idp 가 없고 google·passkey·issue·prove_session 이 있다', async () => {
    const f = (await A.core.loginFlow()).body.flow; const keys = f.steps.map((s) => s.key);
    assert.equal(keys.includes('prove_idp'), false, j(keys));
    for (const k of ['google', 'passkey', 'issue', 'prove_session']) assert.ok(keys.includes(k), `${k} 없음: ${j(keys)}`);
    assert.equal(f.steps.find((s) => s.key === 'google').ms, 1234); assert.equal(f.values.uid, UID_A);
  });
  await t('wrapperLogin(두 번째): derive 1회, 같은 PPID', async () => {
    const calls0 = A.calls;
    const second = await wlogin(A, 'g-anna');
    assert.equal(second.r.status, 200, j(second.r.body)); assert.equal(second.v.status, 200, j(second.v.body));
    assert.equal(A.calls - calls0, 1); assert.equal(second.PPID, first.PPID);
  });
  await t('wrapperBegin 없이 wrapperLogin: 409 wrapper_key_missing — 패스키를 묻지 않는다', async () => {
    const calls0 = A.calls; const ch = await challenge();
    const r = await A.core.wrapperLogin(loginBody(ch), { idToken: await mint('g-anna', 'wrap:' + '0'.repeat(64)), verifiedOrigin: info.origin });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'wrapper_key_missing'); assert.equal(A.calls, calls0);
  });
  await t('토큰이 지금의 요청 키의 것이 아니면(그 사이 wrapperBegin 을 다시 불렀다) 409 wrapper_key_missing', async () => {
    const bg1 = await A.core.wrapperBegin(); const stale = await mint('g-anna', bg1.body.googleNonce);
    await A.core.wrapperBegin();
    const r = await A.core.wrapperLogin(loginBody(await challenge()), { idToken: stale, verifiedOrigin: info.origin });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'wrapper_key_missing');
  });
  await t('요청 키에는 수명이 있다(최종 검토 M-8): wrapperBegin 뒤 10분이 지나면 409 wrapper_key_missing — 패스키를 묻지 않고 키를 지운다', async () => {
    let clock = Date.now();
    const C = browser(undefined, undefined, () => clock);
    const bg = await C.core.wrapperBegin(); assert.equal(bg.status, 200, j(bg.body));
    const idToken = await mint('g-late', bg.body.googleNonce);
    clock += 10 * 60_000 + 1;
    const r = await C.core.wrapperLogin(loginBody(await challenge()), { idToken, verifiedOrigin: info.origin });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'wrapper_key_missing'); assert.equal(C.calls, 0);
    assert.equal(await C.kv.get('wrapperKey'), undefined, '오래된 요청 키는 남기지 않는다');
  });
  await t('다른 패스키(다른 salt)로 같은 Google 계정: 409 auid_pinned, 로컬 등록이 생기지 않는다', async () => {
    const B = browser(undefined, 'Y2lkLWI'); await B.core.passkeyConnect({ credentialId: B.cid, s_u: B.salt });
    const out = await wlogin(B, 'g-anna');
    assert.equal(out.r.status, 409, j(out.r.body)); assert.equal(out.r.body.reason, 'auid_pinned');
    assert.equal(await B.kv.get('registration'), undefined); assert.equal(await B.kv.get('wrapperKey'), undefined);
  });
  // 2026-11-24(사용자 결정): 처음 받은 C_u 의 첫 교체는 기다리지 않는다 — 그다음 교체부터 10분에 한 번
  await t('같은 패스키·같은 Google 계정을 새 브라우저에서(새 C_u): 첫 교체는 되고, 10분 안의 두 번째 교체는 429 cred_change_too_soon 이 그대로 온다 — 그때는 로컬 등록을 남기지 않는다', async () => {
    const C = browser(A.salt, A.cid); await C.core.passkeyConnect({ credentialId: C.cid, s_u: C.salt });
    const first = await wlogin(C, 'g-anna');
    assert.equal(first.r.status, 200, j(first.r.body));
    const D = browser(A.salt, A.cid); await D.core.passkeyConnect({ credentialId: D.cid, s_u: D.salt });
    const out = await wlogin(D, 'g-anna');
    assert.equal(out.r.status, 429, j(out.r.body)); assert.equal(out.r.body.reason, 'cred_change_too_soon');
    assert.equal(await D.kv.get('registration'), undefined);
  });
  await t('이 브라우저가 다른 Google 계정에 묶여 있으면 409 wrapper_account_mismatch — 발급 서버로 가지 않는다', async () => {
    A.sent.length = 0;
    const out = await wlogin(A, 'g-other');
    assert.equal(out.r.status, 409, j(out.r.body)); assert.equal(out.r.body.reason, 'wrapper_account_mismatch');
    assert.equal(A.sent.some((x) => x.url.endsWith('/cia/issue')), false); assert.equal((await A.kv.get('registration')).uid, UID_A);
  });
  await t('예전 방식의 로컬 등록(wrapper 표시 없음)은 래퍼 로그인이 새 등록으로 바꾼다', async () => {
    const D = browser(undefined, 'Y2lkLWQ'); await D.core.passkeyConnect({ credentialId: D.cid, s_u: D.salt });
    const auid = (await auidOf({ s_u: BigInt(D.salt) })).toString();
    await D.kv.set('registration', { uid: '777', auid, slot: 3, provider: 'demo', profile: {}, attrs: ['0', '0', '0', '0', '0', '0'], userCred: null });
    const out = await wlogin(D, 'g-dora');
    assert.equal(out.r.status, 200, j(out.r.body)); assert.equal(out.v.status, 200, j(out.v.body));
    const reg = await D.kv.get('registration'); assert.equal(reg.uid, uidOf(stub.provider, 'g-dora')); assert.equal(reg.wrapper, true);
  });
  await t('방금 만든 패스키의 값(salt)을 주면 그 로그인에 바로 쓴다(derive 0회) — 속성 도구 기록은 이 패스키의 것일 때만 쓰고, 아니면 409 attr_record_salt_mismatch', async () => {
    const E = browser(undefined, 'Y2lkLWU'); await E.core.passkeyConnect({ credentialId: E.cid, s_u: E.salt });
    const auidE = (await auidOf({ s_u: BigInt(E.salt) })).toString();
    const go = async (extra) => { const bg = await E.core.wrapperBegin(); const ch = await challenge(); return { ch, r: await E.core.wrapperLogin(loginBody(ch), { idToken: await mint('g-ella', bg.body.googleNonce), verifiedOrigin: info.origin, salt: E.salt, ...extra }) }; };
    const bad = await go({ profile: { birthYear: '2001', country: 'KR' }, recordAuid: '12345' });
    assert.equal(bad.r.status, 409, j(bad.r.body)); assert.equal(bad.r.body.reason, 'attr_record_salt_mismatch'); assert.equal(await E.kv.get('registration'), undefined);
    const ok = await go({ profile: { birthYear: '2001', country: 'KR' }, recordAuid: auidE });
    assert.equal(ok.r.status, 200, j(ok.r.body)); assert.equal(E.calls, 0, '방금 만든 값으로 — 패스키를 다시 묻지 않는다');
    assert.equal((await E.kv.get('registration')).profile.birthYear, '2001'); assert.ok(!(await E.dump()).includes(E.salt));
    assert.equal((await go({ salt: 'not-a-number' })).r.body.reason, 'passkey_bad_salt');
  });
  await t('래퍼 설정이 아닌 코어에서는 wrapperBegin·wrapperLogin 이 409 not_wrapper_mode', async () => {
    const kv = createMemKv();
    const core = createUserCore({ kv, config: { ...config, wrapper: false }, provider, canonProvider: provider, fullProve, passkey: { derive: async () => ({}) } });
    assert.equal((await core.wrapperBegin()).body.reason, 'not_wrapper_mode');
    assert.equal((await core.wrapperLogin({}, { idToken: 'a.b.c' })).body.reason, 'not_wrapper_mode');
  });
} finally { await stack.stop(); }
console.log(fails ? `\n${fails} 실패` : '\n모두 통과');
process.exit(fails ? 1 : 0);
