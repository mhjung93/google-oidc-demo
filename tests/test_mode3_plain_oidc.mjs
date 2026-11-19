// OIDC 와 zk-Delegation 비교(스펙 2026-11-19-mode3-oidc-comparison) — zkIdP 의 일반 OIDC(인가 코드 + PKCE, sub = uid·aud = rid)와 서비스의 zkoidc 로그인,
// 그리고 각자가 본 식별자의 기록(zkIdP: lastOidc·lastAridS, 서비스: /api/rp/me 의 seen). 브라우저 없이 요청과 쿠키만으로 돈다.
// 격리 IdP(CIA_PLAIN_OIDC=1)·RP(MODE3_RP_ZKOIDC=1) + :8545. (chain)   node tests/test_mode3_plain_oidc.mjs
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { decodeJwt } from 'jose';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); } }
const b64u = (buf) => buf.toString('base64url');
const pkce = () => { const verifier = b64u(randomBytes(32)); return { verifier, challenge: b64u(createHash('sha256').update(verifier).digest()) }; };
/** 쿠키를 따라가는 호출기(리디렉션은 따라가지 않는다 — Location 을 본다). */
function makeJar(base) {
  const jar = new Map();
  return async (p, init = {}) => {
    const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    const r = await fetch(p.startsWith('http') ? p : `${base}${p}`, { redirect: 'manual', ...init, headers: { ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: cookie } : {}), ...(init.headers ?? {}) } });
    for (const sc of r.headers.getSetCookie()) { const first = sc.split(';')[0], i = first.indexOf('='), k = first.slice(0, i), v = first.slice(i + 1); if (v === '' || /expires=Thu, 01 Jan 1970/i.test(sc)) jar.delete(k); else jar.set(k, v); }
    return { status: r.status, location: r.headers.get('location'), body: await r.json().catch(() => null) };
  };
}
const form = (o) => ({ method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(o).toString() });

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });   // 정적 서버는 dist 가 없으면 기동을 거부한다
const stack = await startIsolatedMode3Stack({ userMode: 'web', walletHost: 'localhost', walletEnv: { MODE3_WALLET_SECRETS: 'passkey-web' }, ciaEnv: { CIA_PLAIN_OIDC: '1', MODE3_WALLET_KIND: 'passkey-web' }, rpEnv: { MODE3_RP_ZKOIDC: '1', MODE3_WALLET_KIND: 'passkey-web' }, autoRelay: true });
const { cia, rp } = stack;
try {
  let info = (await rp.get('/api/mode3/rp_info')).body;
  for (let i = 0; i < 50 && !info.arid; i++) { await new Promise((r) => setTimeout(r, 200)); info = (await rp.get('/api/mode3/rp_info')).body; }
  const RID = String(info.arid), REDIRECT = `${rp.base}/api/rp/zkoidc/callback`;
  const PWD = 'oidc-pass-1';
  const idp = makeJar(cia.base);
  const su = await idp('/cia/signup', { method: 'POST', body: JSON.stringify({ id: 'oidc-user', pwd: PWD }) });
  assert.equal(su.status, 201, j(su.body));
  const UID = su.body.uid;
  const reqOf = (over = {}) => { const p = pkce(); return { p, q: { response_type: 'code', client_id: RID, redirect_uri: REDIRECT, scope: 'openid', state: 'st-' + b64u(randomBytes(6)), nonce: 'n-' + b64u(randomBytes(6)), code_challenge: p.challenge, code_challenge_method: 'S256', ...over } }; };
  const infoOf = (jar, q) => jar(`/oidc/authorize/info?${new URLSearchParams(q)}`);
  const decide = (jar, q, approve = true) => jar('/oidc/authorize/decision', { method: 'POST', body: JSON.stringify({ ...q, approve }) });
  const login = (jar) => jar('/cia/user/login', { method: 'POST', body: JSON.stringify({ id: 'oidc-user', pwd: PWD }) });
  const tokenOf = (o) => fetch(`${cia.base}/oidc/token`, form(o)).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));

  await t('discovery: 일반 OIDC 가 켜지면 인가·토큰 엔드포인트와 public 주체 유형을 알린다', async () => {
    const d = (await cia.get('/.well-known/openid-configuration')).body;
    assert.equal(d.authorization_endpoint, `${d.issuer}/oidc/authorize`); assert.equal(d.token_endpoint, `${d.issuer}/oidc/token`);
    assert.deepEqual(d.subject_types_supported, ['pairwise', 'public']); assert.ok(d.response_types_supported.includes('code'));
    assert.equal((await rp.get('/api/mode3/rp_info')).body.social.zkoidc.enabled, true);
  });

  await t('꺼진 zkIdP(기본): 인가·토큰 경로가 없다(404 plain_oidc_disabled), discovery 는 지금 그대로', async () => {
    const c = await startIsolatedCia();
    try {
      const a = await c.get(`/oidc/authorize/info?${new URLSearchParams(reqOf().q)}`); assert.equal(a.status, 404, j(a.body)); assert.equal(a.body.reason, 'plain_oidc_disabled');
      const page = await fetch(`${c.base}/oidc/authorize`); assert.equal(page.status, 404);
      const tk = await fetch(`${c.base}/oidc/token`, form({ grant_type: 'authorization_code', code: 'x' })); assert.equal(tk.status, 404);
      const d = (await c.get('/.well-known/openid-configuration')).body;
      assert.equal(d.authorization_endpoint, undefined); assert.deepEqual(d.subject_types_supported, ['pairwise']);
    } finally { await c.stop(); }
  });

  await t('인가 요청 검사: 모르는 client·다른 redirect·PKCE 없음·response_type 은 화면 오류다(돌려보낼 주소를 주지 않는다)', async () => {
    const page = await fetch(`${cia.base}/oidc/authorize?${new URLSearchParams(reqOf().q)}`);
    assert.equal(page.status, 200); assert.match(page.headers.get('content-type'), /text\/html/);
    const ok = await infoOf(idp, reqOf().q);
    assert.equal(ok.status, 200, j(ok.body)); assert.equal(ok.body.client.rid, RID); assert.equal(ok.body.client.name, info.name); assert.equal(ok.body.client.origin, rp.base); assert.equal(ok.body.user, null, '로그인 전');
    for (const [over, reason] of [[{ client_id: '999' }, 'oidc_client_unknown'], [{ client_id: 'abc' }, 'oidc_client_unknown'], [{ redirect_uri: `${rp.base}/elsewhere` }, 'oidc_redirect_mismatch'],
      [{ redirect_uri: 'https://evil.example/api/rp/zkoidc/callback' }, 'oidc_redirect_mismatch'], [{ code_challenge: '' }, 'oidc_request_invalid'], [{ code_challenge_method: 'plain' }, 'oidc_request_invalid'],
      [{ response_type: 'id_token' }, 'oidc_request_invalid'], [{ scope: 'profile' }, 'oidc_request_invalid'], [{ state: '' }, 'oidc_request_invalid'], [{ nonce: '' }, 'oidc_request_invalid']]) {
      const r = await infoOf(idp, reqOf(over).q);
      assert.equal(r.status, 400, `${j(over)}: ${j(r.body)}`); assert.equal(r.body.reason, reason, j(over)); assert.equal(r.body.redirect, undefined);
      const d = await decide(idp, reqOf(over).q); assert.notEqual(d.status, 200, `결정도 거절: ${j(over)}`);
    }
  });

  await t('결정은 로그인 세션이 있어야 한다 — 없으면 401, JSON 이 아닌 POST 는 415', async () => {
    const anon = makeJar(cia.base);
    const r = await decide(anon, reqOf().q); assert.equal(r.status, 401, j(r.body)); assert.equal(r.body.reason, 'login_required');
    const f = await fetch(`${cia.base}/oidc/authorize/decision`, form({ approve: 'true' })); assert.equal(f.status, 415);
  });

  await t('흐름: 로그인 → 동의 → 코드 → 토큰. sub = uid, aud = rid(서비스의 arid), nonce 그대로 — zkIdP 는 어느 서비스인지 적는다(lastOidc)', async () => {
    assert.equal((await login(idp)).status, 200);
    const { p, q } = reqOf();
    const i = await infoOf(idp, q); assert.equal(i.body.user.uid, UID); assert.equal(i.body.user.id, 'oidc-user');
    const d = await decide(idp, q); assert.equal(d.status, 200, j(d.body));
    const back = new URL(d.body.redirect);
    assert.equal(back.origin + back.pathname, REDIRECT); assert.equal(back.searchParams.get('state'), q.state);
    const code = back.searchParams.get('code'); assert.match(code, /^[0-9a-f]{64}$/);
    const tk = await tokenOf({ grant_type: 'authorization_code', code, client_id: RID, redirect_uri: REDIRECT, code_verifier: p.verifier });
    assert.equal(tk.status, 200, j(tk.body)); assert.equal(tk.body.token_type, 'Bearer');
    const c = decodeJwt(tk.body.id_token);
    assert.equal(c.sub, UID); assert.equal(c.aud, RID); assert.equal(c.nonce, q.nonce); assert.equal(c.zkid_plain, true);
    assert.equal(c.iss, (await cia.get('/.well-known/openid-configuration')).body.issuer);
    const again = await tokenOf({ grant_type: 'authorization_code', code, client_id: RID, redirect_uri: REDIRECT, code_verifier: p.verifier });
    assert.equal(again.status, 400, j(again.body)); assert.equal(again.body.error, 'invalid_grant', '코드는 1회용');
    const acct = (await fetch(`${cia.base}/cia/accounts`, { headers: cia.adminHeaders }).then((r) => r.json())).accounts.find((a) => a.uid === UID);
    assert.equal(acct.lastOidc.rid, RID); assert.equal(acct.lastOidc.name, info.name); assert.ok(Date.parse(acct.lastOidc.at) > 0);
    assert.equal(acct.lastAridS, null, 'zk-Delegation 발급은 아직 없다');
  });

  await t('토큰 거절: 틀린 verifier·다른 client·다른 redirect·없는 코드·grant_type 은 invalid_grant/unsupported — 틀린 시도도 코드를 태운다', async () => {
    const fresh = async () => { const { p, q } = reqOf(); const d = await decide(idp, q); return { p, code: new URL(d.body.redirect).searchParams.get('code') }; };
    const base = (x) => ({ grant_type: 'authorization_code', code: x.code, client_id: RID, redirect_uri: REDIRECT, code_verifier: x.p.verifier });
    const a = await fresh();
    const badV = await tokenOf({ ...base(a), code_verifier: pkce().verifier }); assert.equal(badV.status, 400); assert.equal(badV.body.error, 'invalid_grant');
    const retry = await tokenOf(base(a)); assert.equal(retry.body.error, 'invalid_grant', '실패한 시도 뒤 같은 코드');
    const b = await fresh(); assert.equal((await tokenOf({ ...base(b), client_id: '999' })).body.error, 'invalid_grant');
    const c = await fresh(); assert.equal((await tokenOf({ ...base(c), redirect_uri: `${rp.base}/x` })).body.error, 'invalid_grant');
    assert.equal((await tokenOf({ ...base(await fresh()), code: 'ff'.repeat(32) })).body.error, 'invalid_grant');
    assert.equal((await tokenOf({ ...base(await fresh()), grant_type: 'password' })).body.error, 'unsupported_grant_type');
  });

  await t('취소: error=access_denied 와 state 로 돌려보낸다 — 코드는 없다', async () => {
    const { q } = reqOf();
    const d = await decide(idp, q, false); assert.equal(d.status, 200, j(d.body));
    const back = new URL(d.body.redirect);
    assert.equal(back.searchParams.get('error'), 'access_denied'); assert.equal(back.searchParams.get('state'), q.state); assert.equal(back.searchParams.get('code'), null);
  });

  // ---- 서비스 쪽: start → (zkIdP) → callback → 계정·seen ----
  const user = makeJar(rp.base);
  /** 서비스의 start 를 따라 zkIdP 인가 주소를 받고, zkIdP 에서 결정해 콜백 주소를 만든다. */
  const startAt = async (jar) => { const s = await jar('/api/rp/zkoidc/start?purpose=login'); assert.equal(s.status, 302, j(s.body)); return new URL(s.location); };
  await t('서비스 로그인: start 가 zkIdP 인가 주소로 보내고(client_id = 자기 arid·PKCE·state·nonce), 콜백 뒤 /api/rp/me 의 seen 이 uid 다', async () => {
    const auth = await startAt(user);
    assert.equal(auth.origin + auth.pathname, `${cia.base}/oidc/authorize`);
    const q = Object.fromEntries(auth.searchParams);
    assert.equal(q.client_id, RID); assert.equal(q.redirect_uri, REDIRECT); assert.equal(q.response_type, 'code'); assert.equal(q.code_challenge_method, 'S256'); assert.ok(q.state && q.nonce && q.code_challenge);
    const d = await decide(idp, q); assert.equal(d.status, 200, j(d.body));
    const cb = await user(d.body.redirect); assert.equal(cb.status, 302, j(cb.body));
    const home = new URL(cb.location, rp.base);
    assert.equal(home.searchParams.get('social'), 'ok', cb.location); assert.equal(home.searchParams.get('via'), 'zkoidc');
    const me = await user('/api/rp/me'); assert.equal(me.status, 200, j(me.body));
    assert.equal(me.body.via, 'zkoidc'); assert.equal(me.body.seen.protocol, 'oidc'); assert.equal(me.body.seen.uid, UID); assert.equal(me.body.seen.rid, RID);
    // 시나리오(2026-11-19): 서비스가 받은 JWT 에 uid(sub)·rid(aud)가 그대로 있다 — 화면이 그 본문을 보인다. 서명은 싣지 않는다.
    assert.equal(me.body.seen.jwt.payload.sub, UID); assert.equal(me.body.seen.jwt.payload.aud, RID); assert.equal(me.body.seen.jwt.header.alg, 'ES256'); assert.deepEqual(Object.keys(me.body.seen.jwt).sort(), ['header', 'payload']);
    assert.ok(me.body.methods.zkoidc?.linkedAt); assert.equal(me.body.methods.zkid, null);
    // 같은 uid 로 다시 로그인하면 같은 서비스 계정이다
    const user2 = makeJar(rp.base); const q2 = Object.fromEntries((await startAt(user2)).searchParams);
    await user2((await decide(idp, q2)).body.redirect);
    assert.equal((await user2('/api/rp/me')).body.account, me.body.account);
  });

  await t('서비스 콜백 거절: 남의 브라우저의 state·취소·이미 쓴 코드 — 폐기된 계정은 받아 둔 코드도 새 동의도 못 쓴다', async () => {
    const a = makeJar(rp.base), b = makeJar(rp.base);
    const qa = Object.fromEntries((await startAt(a)).searchParams);
    const da = await decide(idp, qa);
    const stolen = await b(da.body.redirect); assert.equal(new URL(stolen.location, rp.base).searchParams.get('social_error'), 'zkoidc_state_invalid', '다른 브라우저가 연 콜백');
    assert.equal((await b('/api/rp/me')).status, 401);
    const c = makeJar(rp.base); const qc = Object.fromEntries((await startAt(c)).searchParams);
    const denied = await c((await decide(idp, qc, false)).body.redirect); assert.equal(new URL(denied.location, rp.base).searchParams.get('social_error'), 'zkoidc_denied');
    const d = makeJar(rp.base); const qd = Object.fromEntries((await startAt(d)).searchParams);
    const url = (await decide(idp, qd)).body.redirect;
    assert.equal(new URL((await d(url)).location, rp.base).searchParams.get('social'), 'ok');
    const d2 = makeJar(rp.base); await startAt(d2);
    assert.ok(new URL((await d2(url)).location, rp.base).searchParams.get('social_error'), '쓴 콜백 주소를 다시');
    // 리뷰 2026-11-19(OIDC M-1): 코드를 받은 뒤 계정이 폐기되면 토큰 교환이 거절되고(서비스에 로그인되지 않는다), 폐기된 계정의 새 동의도 거절된다
    const e = makeJar(rp.base); const qe = Object.fromEntries((await startAt(e)).searchParams);
    const de = await decide(idp, qe); assert.equal(de.status, 200, j(de.body));
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: UID, disabled: true })).body.disabled, true);
    assert.ok(new URL((await e(de.body.redirect)).location, rp.base).searchParams.get('social_error'), '폐기 뒤에 낸 코드');
    assert.equal((await e('/api/rp/me')).status, 401);
    const f = makeJar(rp.base); const qf = Object.fromEntries((await startAt(f)).searchParams);
    const df = await decide(idp, qf); assert.ok([401, 403].includes(df.status), j(df));
  });
} finally { await stack.stop(); }
console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed === 0 ? 0 : 1);
