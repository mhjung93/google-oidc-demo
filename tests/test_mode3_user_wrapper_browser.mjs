// zkWrapper 의 서비스 로그인(스펙 2026-11-20-mode3-zkwrapper §2.2, 계획 Task 4) — 승인 창이 zkIdP 인증 창 대신 Google 을 다녀온다:
//   · 패스키도 계정도 없는 브라우저: 서비스의 "zk 로그인" → Google(대역 발급자) → 중계 화면 → 지갑 창 → 패스키 만들기 한 번 → 로그인 성공(발급 서버에 그 Google 계정이 생긴다)
//   · 두 번째부터: Google 계정 선택 한 번 + 패스키 한 번
//   · 다른 서비스(zkTWO)는 다른 PPID·조건 증명
// 정적 서버(MODE3_WALLET_SECRETS=passkey-web, MODE3_WRAPPER=1) + 격리 발급 서버(CIA_WRAPPER, Google 대역)·RP 둘 + 결정적 WebAuthn 스텁. hardhat :8545, build/mode3, Chrome 필요(browser 그룹).
//   node tests/test_mode3_user_wrapper_browser.mjs   (MODE3_BROWSER_DEBUG=1 이면 콘솔 출력)
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { buildWebAuthnStub } from './helpers/webauthn_stub.js';
import { uidOf } from '../lib/mode3_oidc_nonce.js';

const DEBUG = process.env.MODE3_BROWSER_DEBUG === '1';
const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); } }
async function launchBrowser() {
  const tried = [];
  for (const opts of [{ channel: 'chrome' }, {}]) { try { return await chromium.launch(opts); } catch (e) { tried.push(`${j(opts)}: ${e.message.split('\n')[0]}`); } }
  throw new Error(`BLOCKED: 브라우저를 띄우지 못했다.\n  ${tried.join('\n  ')}`);
}
/** 스텁 패스키의 salt — 페이지와 같은 식(PRF 입력 zkd-s_u-v1, 도메인 zkd-passkey-s_u-v1). */
function stubSalt(secretHex) {
  const salt = createHash('sha256').update(Buffer.concat([Buffer.from('WebAuthn PRF\0'), Buffer.from('zkd-s_u-v1')])).digest();
  const prf = createHmac('sha256', Buffer.from(secretHex, 'hex')).update(salt).digest();
  return (BigInt('0x' + createHash('sha256').update(Buffer.concat([Buffer.from('zkd-passkey-s_u-v1'), prf])).digest('hex')) >> 6n).toString();
}
execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
const browser = await launchBrowser();
const stack = await startIsolatedMode3Stack({ userMode: 'web', walletHost: 'localhost', wrapper: true, autoRelay: true,
  walletEnv: { MODE3_WALLET_SECRETS: 'passkey-web', MODE3_WRAPPER: '1' }, rpEnv: { MODE3_WALLET_KIND: 'passkey-web' },
  ciaEnv: { MODE3_WALLET_KIND: 'passkey-web', MODE3_OIDC_REDIRECT_URI: '{walletOrigin}/google-relay' },
  extraRps: [{ name: 'zkTWO', env: { MODE3_WALLET_KIND: 'passkey-web', MODE3_ALLOWED_COUNTRIES: 'KR,JP', MODE3_REQUIRE_DISCLOSURE: '1' } }] });
const { cia, wallet, rp } = stack;
const rp2 = stack.rps[1], google = stack.oidc;
const SECRET_A = 'a7'.repeat(32), SALT_A = stubSalt(SECRET_A);
const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
async function waitText(page, sel, needle, timeout = 30_000) {
  try { await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout }); }
  catch { throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`); }
}
const idbDump = (page) => page.evaluate(async () => { const open = indexedDB.open('mode3-user', 1); open.onupgradeneeded = () => { if (!open.result.objectStoreNames.contains('kv')) open.result.createObjectStore('kv'); }; const db = await new Promise((r, x) => { open.onsuccess = () => r(open.result); open.onerror = () => x(open.error); }); const st = db.transaction('kv', 'readonly').objectStore('kv'); const keys = await new Promise((r) => { const q = st.getAllKeys(); q.onsuccess = () => r(q.result); }); const out = {}; for (const k of keys) out[k] = await new Promise((r) => { const q = st.get(k); q.onsuccess = () => r(q.result); }); db.close(); return JSON.parse(JSON.stringify(out, (k, v) => (v instanceof CryptoKey ? '[CryptoKey]' : v))); });
const accounts = async () => (await cia.adminGet('/cia/accounts')).body.accounts.filter((x) => typeof x.id === 'string' && x.id.includes('@'));
// 창이 거친 주소 — 대역 발급자는 인가 요청에 곧바로 302 를 준다(화면이 없다). 문서 이동 요청도 함께 적는다.
const trackNav = (popup) => {
  const visited = [popup.url()];
  popup.on('request', (r) => { try { if (r.isNavigationRequest() && r.frame() === popup.mainFrame()) visited.push(r.url()); } catch { /* 닫힌 창 */ } });
  popup.on('framenavigated', (f) => { if (f === popup.mainFrame()) visited.push(f.url()); });
  return visited;
};
const went = (visited, base) => visited.some((u) => u.startsWith(base));
async function newBrowserWith(secretHex) {
  const hits = { create: 0, get: 0 };
  const ctx = await browser.newContext();
  await ctx.exposeFunction('__webauthnHit', (k) => { hits[k] = (hits[k] ?? 0) + 1; });
  await ctx.addInitScript({ content: buildWebAuthnStub({ secretHex }) });
  ctx.on('dialog', (d) => d.accept());
  ctx.on('page', (p) => { if (DEBUG) { p.on('console', (m) => console.log(`    [${new URL(p.url()).port}] ${m.type()}: ${m.text()}`)); p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`)); } });
  return { ctx, hits };
}
/** 서비스 페이지를 연다 — 이 브라우저가 그 서비스에 이미 로그인돼 있으면(쿠키 세션) 로그아웃해 로그인 버튼이 보이게 한다. */
async function openRp(ctx, svc) {
  const rpPage = await ctx.newPage(); await rpPage.goto(`${svc.base}/`);
  await rpPage.waitForFunction(() => { const a = document.getElementById('loginBtn'), b = document.getElementById('logoutBtn'); return (a && !a.hidden) || (b && b.offsetParent !== null); }, null, { timeout: 15_000 });
  if (await rpPage.$eval('#loginBtn', (b) => b.hidden)) { await rpPage.click('#logoutBtn'); await rpPage.waitForSelector('#loginBtn:not([hidden])'); }
  return rpPage;
}
/** 서비스 페이지에서 "zk 로그인" 을 눌러 승인 창을 연다. */
async function startLogin(ctx, svc) {
  const rpPage = await openRp(ctx, svc);
  await rpPage.click('#loginBtn');
  const [popup] = await Promise.all([ctx.waitForEvent('page'), rpPage.click('#idpLoginBtn')]);
  return { rpPage, popup, visited: trackNav(popup) };
}
const ppidOf = (dump, svcArid) => Object.values(dump.sessions ?? {}).filter((s) => String(s.arid) === String(svcArid)).map((s) => s.PPID);
try {
  const info1 = (await rp.get('/api/mode3/rp_info')).body, info2 = (await rp2.get('/api/mode3/rp_info')).body;
  const A = await newBrowserWith(SECRET_A);
  const UID_A = uidOf(google.provider, 'google-user-A');
  let ppid1 = null;
  await t('설정: 지갑 서버가 래퍼 방식을 알린다(/user/config.wrapper), 발급 서버의 돌아올 주소는 지갑의 /google-relay', async () => {
    assert.equal((await wallet.get('/user/config')).body.wrapper, true);
    const k = (await cia.get('/cia/public_keys')).body; assert.equal(k.wrapper, true); assert.equal(k.oidc.redirectUri, `${wallet.base}/google-relay`); assert.equal(k.oidc.authorizeUrl, google.authorizeUrl);
  });
  await t('빈 브라우저: 서비스 "zk 로그인" → Google → 패스키 만들기 한 번 → 로그인 성공 — zkIdP 인증 창(/login)으로 가지 않고, 발급 서버의 계정 표에 Google 계정이 생긴다', async () => {
    google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
    assert.equal((await accounts()).length, 0);
    const { rpPage, popup, visited } = await startLogin(A.ctx, rp);
    await popup.waitForSelector('#authWrapPasskeyBtn', { timeout: 30_000 });
    assert.ok(went(visited, google.authorizeUrl), `Google 로 가지 않았다: ${j(visited.map((u) => u.slice(0, 70)))}`);
    assert.ok(went(visited, `${wallet.base}/google-relay`), '중계 화면을 거치지 않았다');
    const authUrl = new URL(visited.find((u) => u.startsWith(google.authorizeUrl)));
    assert.equal(authUrl.searchParams.get('prompt'), 'select_account'); assert.ok(authUrl.searchParams.get('nonce').startsWith('wrap:'), authUrl.searchParams.get('nonce'));
    const intro = await text(popup, '#authStatus'); assert.ok(intro.includes('패스키'), intro);
    assert.equal((await accounts()).length, 0, '패스키를 만들기 전에는 계정이 생기지 않는다');
    assert.ok(!(await popup.evaluate(() => location.href)).includes('id_token'), '토큰이 주소창에 남았다');
    await popup.click('#authWrapPasskeyBtn');
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    assert.ok(!visited.some((u) => u.startsWith(`${cia.base}/login`)), 'zkIdP 인증 창(아이디·비밀번호)으로 가면 안 된다');
    const acc = await accounts(); assert.equal(acc.length, 1, j(acc.map((a) => a.id)));
    assert.equal(acc[0].id, 'jihoo@example.com'); assert.equal(String(acc[0].uid), UID_A); assert.ok(acc[0].auid, '첫 발급이 곧 등록이다');
    assert.equal(A.hits.create, 1); assert.equal(A.hits.get, 1, `패스키 확인은 만들 때의 한 번뿐이어야 한다: ${j(A.hits)}`);
    await rpPage.close();
  });
  const userPage = await A.ctx.newPage();
  await t('저장소에 salt·ID 토큰·대기분이 남지 않는다(localStorage·sessionStorage·IndexedDB 의 값 전부)', async () => {
    await userPage.goto(`${wallet.base}/`); await userPage.waitForSelector('#mainView:not([hidden])');
    const d = await idbDump(userPage);
    assert.equal(String(d.registration.uid), UID_A); assert.equal(d.registration.wrapper, true); assert.equal(d.wrapperKey, undefined, '요청 키가 남았다');
    const stores = await userPage.evaluate(() => ({ ss: Object.entries(sessionStorage).map(([k, v]) => `${k}=${v}`), ls: Object.entries(localStorage).map(([k, v]) => `${k}=${v}`) }));
    const all = j(d) + j(stores);
    assert.ok(!all.includes(SALT_A), 'salt 가 저장소에 있다'); assert.ok(!/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}/.test(j(stores)), 'Google 토큰 모양이 웹 저장소에 있다');
    assert.ok(!stores.ss.some((e) => e.startsWith('mode3.wrapper.pending')), j(stores.ss));
    // IndexedDB 에 있어도 되는 토큰은 서비스에 넘기는 세션 토큰(sub = auid_s — 공개값)뿐이다. Google 토큰(sub = Google 계정)은 없어야 한다.
    for (const tok of j(d).match(/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}/g) ?? []) {
      const pl = JSON.parse(Buffer.from(tok.split('.')[1], 'base64url').toString('utf8'));
      assert.ok(pl.sub !== 'google-user-A' && !('email' in pl), `Google 토큰이 IndexedDB 에 있다: ${j(Object.keys(pl))}`);
    }
    ppid1 = ppidOf(d, info1.arid)[0]; assert.ok(ppid1);
  });
  await t('두 번째 로그인: Google 계정 선택을 한 번 거치고 패스키 1회 — 같은 PPID', async () => {
    google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
    const g0 = A.hits.get;
    const { rpPage, visited } = await startLogin(A.ctx, rp);
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    assert.equal(visited.filter((u) => u.startsWith(google.authorizeUrl)).length >= 1, true); assert.ok(!visited.some((u) => u.startsWith(`${cia.base}/login`)));
    assert.equal(A.hits.get - g0, 1, j(A.hits)); assert.equal(A.hits.create, 1);
    const ps = ppidOf(await idbDump(userPage), info1.arid); assert.ok(ps.length >= 1 && ps.every((p) => p === ppid1), j(ps));
    assert.equal((await accounts()).length, 1);
    await rpPage.close();
  });
  await t('zkTWO 로그인: PPID 가 zkONE 과 다르고 조건 증명이 통과한다', async () => {
    google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
    const { rpPage } = await startLogin(A.ctx, rp2);
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    const s2 = (await rp2.get('/api/mode3/sessions')).body.sessions; assert.ok(s2.length >= 1 && s2[0].disclosure?.set, `zkTWO 세션에 공개 집합이 없다: ${j(s2)}`);
    const p2 = ppidOf(await idbDump(userPage), info2.arid)[0]; assert.ok(p2); assert.notEqual(p2, ppid1);
    await rpPage.close();
  });
  await t('Google 에서 돌아온 조각을 다른 창에 붙여도(이 창이 시작한 로그인이 아니다) 발급되지 않는다', async () => {
    const before = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => String(a.uid) === UID_A).lastAuidS?.value;
    const token = await google.mint({ sub: 'google-user-A', nonce: 'wrap:' + 'ab'.repeat(32), extra: { email: 'jihoo@example.com', email_verified: true } });
    const page = await A.ctx.newPage(); const calls = [];
    page.on('request', (r) => { if (r.url().includes('/cia/issue')) calls.push(r.url()); });
    await page.goto(`${wallet.base}/?authorize=1#google_back=1&state=forged.state&id_token=${token}`);
    await waitText(page, '#authHint', '이어받지 못했습니다', 15_000);
    assert.equal(calls.length, 0, '발급 서버로 갔다'); assert.ok(!(await page.evaluate(() => location.href)).includes('id_token'), '토큰이 주소창에 남았다');
    assert.equal((await cia.adminGet('/cia/accounts')).body.accounts.find((a) => String(a.uid) === UID_A).lastAuidS?.value, before);
    await page.close();
  });
  await t('Google 에서 취소하면(토큰 없음) 서비스에 실패로 알리고 발급하지 않는다', async () => {
    const g0 = A.hits.get;
    const rpPage = await openRp(A.ctx, rp); await rpPage.click('#loginBtn');
    // 대역 발급자가 토큰 대신 오류를 돌려주게: 인가 요청을 가로채 중계 화면으로 error 조각을 보낸다
    await A.ctx.route(`${google.authorizeUrl}**`, async (route) => { const u = new URL(route.request().url()); await route.fulfill({ status: 302, headers: { location: `${u.searchParams.get('redirect_uri')}#error=access_denied&state=${encodeURIComponent(u.searchParams.get('state'))}` } }); });
    try {
      const [popup] = await Promise.all([A.ctx.waitForEvent('page'), rpPage.click('#idpLoginBtn')]);
      await waitText(rpPage, '#verdict', 'Google', 60_000);
      assert.ok(!(await text(rpPage, '#verdict')).includes('로그인 성공')); assert.equal(A.hits.get, g0, '패스키를 묻지 않는다');
      await popup.close().catch(() => {});
    } finally { await A.ctx.unroute(`${google.authorizeUrl}**`); }
    await rpPage.close();
  });
  await A.ctx.close();
} finally {
  await browser.close().catch(() => {});
  await stack.stop();
}
console.log(failed ? `\n${failed} 실패` : '\n모두 통과');
process.exit(failed ? 1 : 0);
