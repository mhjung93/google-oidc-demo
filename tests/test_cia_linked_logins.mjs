// tests/test_cia_linked_logins.mjs — zkID 계정에 Google·네이버 로그인 연결(스펙 2026-11-09-mode3-linked-logins). 격리 IdP + 발급자 스텁 둘
// (Google 역할 = oidc 스텁, 네이버 = 인가 코드·PKCE 흉내). :8545 필요(로그 배포). (chain)
import assert from 'node:assert/strict';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { createRegistration, signRegistration } from '../lib/mode3_wallet.js';
import { uidOf, regNonce } from '../lib/mode3_oidc_nonce.js';
import { auidOf } from '../lib/mode3_credential.js';

const cia = await startIsolatedCia({ oidc: true, naver: true });
const g = cia.oidc, nv = cia.naver;
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const j = (o) => JSON.stringify(o);

/** 쿠키(cia.sid)를 들고 다니는 브라우저 흉내. 리다이렉트는 따라가지 않는다(Location 을 본다). */
function browser() {
  let cookie = '';
  async function req(method, p, body) {
    const url = p.startsWith('http') ? p : `${cia.base}${p}`;
    const sameHost = url.startsWith(cia.base);
    const r = await fetch(url, { method, redirect: 'manual', headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(cookie && sameHost ? { Cookie: cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
    if (sameHost) for (const c of r.headers.getSetCookie?.() ?? []) if (c.startsWith('cia.sid=')) cookie = c.split(';')[0];
    return { status: r.status, location: r.headers.get('location'), body: await r.json().catch(() => null) };
  }
  return { get: (p) => req('GET', p), post: (p, b) => req('POST', p, b ?? {}) };
}
/** 가입 → (선택) 지갑 등록 → 로그인한 브라우저. */
async function account(id, { register = true } = {}) {
  const pwd = 'pw-' + id + '-12345';
  const s = await cia.post('/cia/signup', { id, pwd }); assert.equal(s.status, 201, j(s.body));
  const uid = s.body.uid;
  const reg = register ? await cia.registerUser(uid, pwd) : null;
  const b = browser();
  const l = await b.post('/cia/user/login', { id, pwd }); assert.equal(l.status, 200, j(l.body));
  return { id, pwd, uid, reg, b };
}
async function linkGoogle(acc, sub) {
  const n = await acc.b.post('/cia/oidc/nonce', { purpose: 'link' }); assert.equal(n.status, 200, j(n.body));
  const id_token = await g.mint({ sub, nonce: n.body.nonce });
  return { r: await acc.b.post('/cia/user/link', { provider: 'google', id_token }), id_token };
}
/** 네이버 연결·인증 왕복: start → (스텁 인가) → callback. 마지막 Location 을 돌려준다. */
async function naverRound(b, startPath, sub) {
  nv.setNextSub(sub);
  const s = await b.get(startPath); assert.equal(s.status, 302, j(s));
  if (!s.location.startsWith(nv.base)) return s.location;   // 시작에서 바로 되돌아온 경우(꺼짐·로그인 필요)
  const a = await b.get(s.location); assert.equal(a.status, 302);
  const c = await b.get(a.location); assert.equal(c.status, 302, j(c));
  return c.location;
}
async function authGoogle(sub, body) {
  const n = await cia.post('/cia/oidc/nonce', { purpose: 'auth' }); assert.equal(n.status, 200);
  const id_token = await g.mint({ sub, nonce: n.body.nonce });
  return { r: await cia.post('/cia/auth/code', { method: 'google', id_token, ...body }), id_token };
}

try {
  let alice, bob;
  await t('public_keys.oidc.providers: google(clientId 포함)·naver 둘 다 켜짐, 옛 oidc 필드는 그대로', async () => {
    const k = (await cia.get('/cia/public_keys')).body.oidc;
    assert.deepEqual(k.providers, { google: { enabled: true, clientId: g.clientId }, naver: { enabled: true } });
    assert.equal(k.enabled, true); assert.equal(k.clientId, g.clientId);
  });
  await t('연결용 nonce 는 로그인 세션이 있어야 받는다(401), 잘못된 purpose 는 400', async () => {
    assert.equal((await cia.post('/cia/oidc/nonce', { purpose: 'link' })).status, 401);
    assert.equal((await cia.post('/cia/oidc/nonce', { purpose: 'x' })).status, 400);
  });
  await t('Google 연결: 200, /cia/user/me 에 linked.google.linkedAt — sub 는 응답에 없다', async () => {
    alice = await account('alice1');
    const { r } = await linkGoogle(alice, 'g-alice');
    assert.equal(r.status, 200, j(r.body)); assert.ok(r.body.linked.google.linkedAt); assert.equal(r.body.linked.naver, null);
    const me = await alice.b.get('/cia/user/me');
    assert.ok(me.body.linked.google.linkedAt); assert.equal(j(me.body).includes('g-alice'), false); assert.equal('linkedOidc' in me.body, false);
  });
  await t('같은 연결 토큰 재사용 → 400 oidc_nonce_mismatch(nonce 1회용)', async () => {
    const n = await alice.b.post('/cia/oidc/nonce', { purpose: 'link' });
    const id_token = await g.mint({ sub: 'g-alice', nonce: n.body.nonce });
    assert.equal((await alice.b.post('/cia/user/link', { provider: 'google', id_token })).status, 200, '같은 sub 재연결은 멱등');
    const again = await alice.b.post('/cia/user/link', { provider: 'google', id_token });
    assert.equal(again.status, 400); assert.equal(again.body.reason, 'oidc_nonce_mismatch');
  });
  await t('남의 세션이 받은 nonce 로 만든 토큰 → 400(세션 uid 결속), 인증용(auth:) nonce 토큰으로 연결 → 400', async () => {
    bob = await account('bob1');
    const n = await alice.b.post('/cia/oidc/nonce', { purpose: 'link' });
    const tok = await g.mint({ sub: 'g-bob', nonce: n.body.nonce });
    const r = await bob.b.post('/cia/user/link', { provider: 'google', id_token: tok });
    assert.equal(r.status, 400); assert.equal(r.body.reason, 'oidc_nonce_mismatch');
    const an = await cia.post('/cia/oidc/nonce', { purpose: 'auth' });
    const r2 = await bob.b.post('/cia/user/link', { provider: 'google', id_token: await g.mint({ sub: 'g-bob', nonce: an.body.nonce }) });
    assert.equal(r2.status, 400);
  });
  await t('이미 다른 계정에 연결된 Google → 409 oidc_linked_elsewhere; 이 계정에 다른 Google 이 있으면 409 oidc_already_linked', async () => {
    const r = (await linkGoogle(bob, 'g-alice')).r; assert.equal(r.status, 409); assert.equal(r.body.reason, 'oidc_linked_elsewhere');
    const r2 = (await linkGoogle(alice, 'g-other')).r; assert.equal(r2.status, 409); assert.equal(r2.body.reason, 'oidc_already_linked');
  });
  await t('Google 래퍼 계정(Google 로 가입)의 sub 는 연결할 수 없다 → 409 oidc_has_own_account', async () => {
    const sub = 'g-wrapper';
    const reg = await createRegistration(0n), uid = uidOf(g.provider, sub);
    const auid = await auidOf({ uid: BigInt(uid), s_u: reg.s_u });
    const pk_u = { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() };
    const w = await cia.post('/cia/register', { id_token: await g.mint({ sub, nonce: regNonce(pk_u) }), auid: auid.toString(), pk_u, sig_reg: await signRegistration(reg.sk_u, BigInt(uid), auid) });
    assert.equal(w.status, 201, j(w.body));
    const r = (await linkGoogle(bob, sub)).r; assert.equal(r.status, 409); assert.equal(r.body.reason, 'oidc_has_own_account');
  });
  await t('리뷰 I-1: 아이디 계정에 연결된 Google 로 래퍼 계정을 따로 만들 수 없다 → /cia/register 409 oidc_linked_elsewhere', async () => {
    const sub = 'g-alice';
    const reg = await createRegistration(0n), uid = uidOf(g.provider, sub);
    const auid = await auidOf({ uid: BigInt(uid), s_u: reg.s_u });
    const pk_u = { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() };
    const w = await cia.post('/cia/register', { id_token: await g.mint({ sub, nonce: regNonce(pk_u) }), auid: auid.toString(), pk_u, sig_reg: await signRegistration(reg.sk_u, BigInt(uid), auid) });
    assert.equal(w.status, 409, j(w.body)); assert.equal(w.body.reason, 'oidc_linked_elsewhere');
  });
  await t('네이버 연결: start → 인가 → callback → /user?linked=naver, me 에 linked.naver', async () => {
    const loc = await naverRound(alice.b, '/cia/oidc/naver/start?purpose=link', 'n-alice');
    assert.equal(loc, '/user?linked=naver');
    assert.ok((await alice.b.get('/cia/user/me')).body.linked.naver.linkedAt);
  });
  await t('네이버 연결: 로그인 없이 start → /user?link_error=login_required; 다른 계정의 네이버 → link_error=oidc_linked_elsewhere; 모르는 state → naver_state_invalid', async () => {
    const anon = browser();
    assert.equal((await anon.get('/cia/oidc/naver/start?purpose=link')).location, '/user?link_error=login_required');
    assert.equal(await naverRound(bob.b, '/cia/oidc/naver/start?purpose=link', 'n-alice'), '/user?link_error=oidc_linked_elsewhere');
    assert.equal((await bob.b.get('/cia/oidc/naver/callback?code=x&state=nope')).location, '/user?link_error=naver_state_invalid');
    assert.equal((await bob.b.get('/cia/oidc/naver/callback?code=x&state=auth-nope')).location, '/login?auth_error=naver_state_invalid', '인증 창 쪽 state 는 인증 창으로');
  });
  await t('네이버 연결: 시작한 세션과 다른 세션으로 콜백이 오면(남의 인가 코드 끼워 넣기) → link_error=login_required, 연결되지 않는다', async () => {
    nv.setNextSub('n-injected');
    const s = await bob.b.get('/cia/oidc/naver/start?purpose=link');
    const a = await bob.b.get(s.location);                    // bob 의 네이버 인가 → 콜백 주소(code·state)
    const c = await alice.b.get(a.location);                  // 그 주소를 alice 의 브라우저가 연다
    assert.equal(c.location, '/user?link_error=login_required');
    const me = (await bob.b.get('/cia/user/me')).body; assert.equal(me.linked.naver, null);
  });
  await t('인증 창 Google(발급): 연결 계정의 코드; auid 를 틀리면 403 이고 같은 토큰으로 다시 하면 200, 그 뒤 재사용은 400', async () => {
    const n = await cia.post('/cia/oidc/nonce', { purpose: 'auth' });
    const id_token = await g.mint({ sub: 'g-alice', nonce: n.body.nonce });
    const bad = await cia.post('/cia/auth/code', { method: 'google', id_token, auid: '1' });
    assert.equal(bad.status, 403); assert.equal(bad.body.reason, 'auid_mismatch');
    const ok = await cia.post('/cia/auth/code', { method: 'google', id_token, auid: alice.reg.auid.toString() });
    assert.equal(ok.status, 200, j(ok.body)); assert.match(ok.body.code, /^[0-9a-f]{64}$/);
    const again = await cia.post('/cia/auth/code', { method: 'google', id_token, auid: alice.reg.auid.toString() });
    assert.equal(again.status, 400); assert.equal(again.body.reason, 'oidc_nonce_mismatch');
  });
  await t('인증 창 Google: 연결 안 된 Google → 404 oidc_not_linked; 연결용(link:) nonce 토큰 → 400 oidc_nonce_mismatch', async () => {
    const r = (await authGoogle('g-nobody', { auid: '1' })).r; assert.equal(r.status, 404); assert.equal(r.body.reason, 'oidc_not_linked');
    const n = await alice.b.post('/cia/oidc/nonce', { purpose: 'link' });
    const r2 = await cia.post('/cia/auth/code', { method: 'google', id_token: await g.mint({ sub: 'g-alice', nonce: n.body.nonce }), auid: alice.reg.auid.toString() });
    assert.equal(r2.status, 400); assert.equal(r2.body.reason, 'oidc_nonce_mismatch');
  });
  await t('인증 창 네이버(발급): callback 이 맡긴 쿼리만(허용 키) 되돌리고 ticket 을 붙인다 → 코드 200, ticket 재사용 401', async () => {
    const ctx = new URLSearchParams({ nonce: 'abc', wallet: 'http://localhost:5100', return: '1', purpose: 'issue', method: 'naver', evil: 'x' }).toString();
    const loc = await naverRound(browser(), `/cia/oidc/naver/start?purpose=auth&ctx=${encodeURIComponent(ctx)}`, 'n-alice');
    const u = new URL(loc, cia.base);
    assert.equal(u.pathname, '/login'); assert.equal(u.searchParams.get('nonce'), 'abc'); assert.equal(u.searchParams.get('wallet'), 'http://localhost:5100');
    assert.equal(u.searchParams.get('method'), 'naver'); assert.equal(u.searchParams.get('evil'), null);
    const ticket = u.searchParams.get('ticket'); assert.match(ticket, /^[0-9a-f]{64}$/);
    const ok = await cia.post('/cia/auth/code', { method: 'naver', ticket, auid: alice.reg.auid.toString() });
    assert.equal(ok.status, 200, j(ok.body));
    const again = await cia.post('/cia/auth/code', { method: 'naver', ticket, auid: alice.reg.auid.toString() });
    assert.equal(again.status, 401); assert.equal(again.body.reason, 'bad_ticket');
  });
  await t('리뷰 Minor 2: 발급용(purpose=issue) 인증 창에서 받은 ticket 을 등록 코드에 쓰면 401 bad_ticket', async () => {
    const loc = await naverRound(browser(), `/cia/oidc/naver/start?purpose=auth&ctx=${encodeURIComponent('nonce=n2&purpose=issue')}`, 'n-alice');
    const ticket = new URL(loc, cia.base).searchParams.get('ticket');
    const r = await cia.post('/cia/auth/code', { method: 'naver', ticket, purpose: 'register' });
    assert.equal(r.status, 401); assert.equal(r.body.reason, 'bad_ticket');
    assert.equal((await cia.post('/cia/auth/code', { method: 'naver', ticket, auid: alice.reg.auid.toString() })).status, 200, '맞는 용도로는 그대로 쓴다');
  });
  await t('인증 창 네이버: 연결 안 된 네이버 → ticket 은 나오지만 코드는 404 oidc_not_linked', async () => {
    const loc = await naverRound(browser(), `/cia/oidc/naver/start?purpose=auth&ctx=${encodeURIComponent('nonce=n1')}`, 'n-nobody');
    const ticket = new URL(loc, cia.base).searchParams.get('ticket');
    const r = await cia.post('/cia/auth/code', { method: 'naver', ticket, auid: '1' });
    assert.equal(r.status, 404); assert.equal(r.body.reason, 'oidc_not_linked');
  });
  await t('등록 모드: 미등록 아이디 계정에 연결한 Google 로 등록 코드 + uid; 이미 등록된 계정은 409', async () => {
    const carol = await account('carol1', { register: false });
    assert.equal((await linkGoogle(carol, 'g-carol')).r.status, 200);
    const r = (await authGoogle('g-carol', { purpose: 'register' })).r;
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.uid, carol.uid); assert.equal(r.body.purpose, 'register');
    const r2 = (await authGoogle('g-alice', { purpose: 'register' })).r; assert.equal(r2.status, 409); assert.equal(r2.body.reason, 'already_registered');
  });
  await t('잘못된 method → 400 bad_method', async () => {
    const r = await cia.post('/cia/auth/code', { method: 'kakao' }); assert.equal(r.status, 400); assert.equal(r.body.reason, 'bad_method');
  });
  await t('지갑 연결 해제(unlink_wallet)는 외부 연결을 남긴다(L4)', async () => {
    const r = await alice.b.post('/cia/user/unlink_wallet', { pwd: alice.pwd }); assert.equal(r.status, 200, j(r.body));
    const me = (await alice.b.get('/cia/user/me')).body;
    assert.equal(me.registered, false); assert.ok(me.linked.google); assert.ok(me.linked.naver);
  });
  await t('연결 해제: google 해제 뒤 그 Google 로 인증 → 404, 없는 연결 해제 → 409, 모르는 공급자 → 400', async () => {
    const r = await alice.b.post('/cia/user/unlink', { provider: 'google' });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.linked.google, null); assert.ok(r.body.linked.naver);
    assert.equal((await authGoogle('g-alice', { purpose: 'register' })).r.status, 404);
    assert.equal((await alice.b.post('/cia/user/unlink', { provider: 'google' })).status, 409);
    assert.equal((await alice.b.post('/cia/user/unlink', { provider: 'kakao' })).status, 400);
    assert.equal((await linkGoogle(bob, 'g-alice')).r.status, 200, '해제된 Google 은 다른 계정에 연결할 수 있다');
  });
  await t('/cia/issue: 아이디 계정에 Google 토큰을 직접 들고 오면 400 use_auth_window(2026-11-06 자동 연결은 없다)', async () => {
    const id_token = await g.mint({ sub: 'g-bob-direct', nonce: 'issue:' + '0'.repeat(64) });
    const r = await cia.post('/cia/issue', { uid: bob.uid, auid_s: '1', arid_s: '1', C_u_pt: { x: '1', y: '2' }, C_s_pt: { x: '1', y: '2' }, chainid: '31337', allowAgent: '0', max_height: '10', proof_idp: {}, sig_u: 'x', id_token });
    assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, 'use_auth_window');
  });
} finally {
  await cia.stop();
}
console.log(fails ? `\n${fails} FAIL` : '\nall ok');
process.exit(fails ? 1 : 0);
