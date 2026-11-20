// passkey-web 의 패스키 가입(스펙 2026-11-20-mode3-passkey-google-signup) — zkIdP 페이지의 "패스키로 로그인" 이 미등록 브라우저에서 Google 로 확인한 이메일로 계정을 만든다:
//   · 패스키도 계정도 없는 브라우저: 버튼 한 번(패스키 만들기) → Google(대역 발급자) → 중계 화면 → 지갑 창 → zkIdP 에 로그인된 채로 끝난다
//   · 그 뒤 서비스 로그인·zkIdP 재로그인은 Google 없이 패스키만
//   · 같은 Google 계정 + 같은 패스키(저장소가 빈 다른 브라우저)는 기존 계정으로 복구, 다른 패스키는 거절
// 정적 서버(MODE3_WALLET_SECRETS=passkey-web) + 격리 IdP(key 정책, Google 대역 발급자)·RP + 결정적 WebAuthn 스텁. hardhat :8545, build/mode3, Chrome 필요(browser 그룹).
//   node tests/test_mode3_user_passkey_web_signup.mjs   (MODE3_BROWSER_DEBUG=1 이면 콘솔 출력)
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { buildWebAuthnStub } from './helpers/webauthn_stub.js';
import { startOidcIssuerStub } from './helpers/oidc_issuer_stub.mjs';

const DEBUG = process.env.MODE3_BROWSER_DEBUG === '1';
const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); } }
async function launchBrowser() {
  const tried = [];
  for (const opts of [{ channel: 'chrome' }, {}]) { try { return await chromium.launch(opts); } catch (e) { tried.push(`${j(opts)}: ${e.message.split('\n')[0]}`); } }
  throw new Error(`BLOCKED: 브라우저를 띄우지 못했다.\n  ${tried.join('\n  ')}`);
}
execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
const browser = await launchBrowser();
// zkIdP 의 Google 자리: 대역 발급자. 돌아올 주소는 지갑 정적 서버의 /google-relay 다(실제 데모에서는 https://127.0.0.1:5100/google-relay) — 포트는 스택이 정하므로 {walletOrigin} 으로 적는다.
const google = await startOidcIssuerStub({ clientId: 'idp-google-client', provider: 'google' });
const stack = await startIsolatedMode3Stack({ userMode: 'web', walletHost: 'localhost', walletEnv: { MODE3_WALLET_SECRETS: 'passkey-web' }, rpEnv: { MODE3_WALLET_KIND: 'passkey-web' }, autoRelay: true,
  ciaEnv: { MODE3_WALLET_KIND: 'passkey-web', MODE3_OIDC_CLIENT_ID: google.clientId, MODE3_OIDC_ISSUER: google.issuer, MODE3_OIDC_JWKS_URL: google.jwksUrl, MODE3_OIDC_PROVIDER: 'google',
    MODE3_OIDC_AUTHORIZE_URL: google.authorizeUrl, MODE3_OIDC_REDIRECT_URI: '{walletOrigin}/google-relay' } });
const { cia, wallet, rp } = stack;
const SECRET_A = 'a7'.repeat(32), SECRET_B = 'b8'.repeat(32);
const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
async function waitText(page, sel, needle, timeout = 30_000) {
  try { await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout }); }
  catch { throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`); }
}
const idbGet = (page, key) => page.evaluate(async (k) => { const open = indexedDB.open('mode3-user', 1); const db = await new Promise((r, x) => { open.onsuccess = () => r(open.result); open.onerror = () => x(open.error); }); const v = await new Promise((r, x) => { const q = db.transaction('kv').objectStore('kv').get(k); q.onsuccess = () => r(q.result); q.onerror = () => x(q.error); }); db.close(); return v; }, key);
// 격리 IdP 는 데모 계정을 심어 둔 채 뜬다 — 이 테스트는 가입으로 생긴 계정(아이디가 이메일)만 센다
const accounts = async () => { const a = (await cia.adminGet('/cia/accounts')).body; return (a.accounts ?? a).filter((x) => typeof x.id === 'string' && x.id.includes('@')); };
// 창이 거친 주소 — 대역 발급자는 인가 요청에 곧바로 302 를 주므로(화면이 없다) 문서로 뜬 주소(framenavigated)만 보면 빠진다. 문서 이동 요청도 함께 적는다.
const trackNav = (popup) => {
  const visited = [popup.url()];
  popup.on('request', (r) => { try { if (r.isNavigationRequest() && r.frame() === popup.mainFrame()) visited.push(r.url()); } catch { /* 닫힌 창 */ } });
  popup.on('framenavigated', (f) => { if (f === popup.mainFrame()) visited.push(f.url()); });
  return visited;
};
const went = (visited, base) => visited.some((u) => u.startsWith(base));
/** 가짜 패스키 하나를 가진 새 브라우저(저장소가 비어 있다). hits 는 그 브라우저의 WebAuthn 호출 수. */
async function newBrowserWith(secretHex) {
  const hits = { create: 0, get: 0 };
  const ctx = await browser.newContext();
  await ctx.exposeFunction('__webauthnHit', (k) => { hits[k] = (hits[k] ?? 0) + 1; });
  await ctx.addInitScript({ content: buildWebAuthnStub({ secretHex }) });
  ctx.on('dialog', (d) => d.accept());
  ctx.on('page', (p) => { if (DEBUG) { p.on('console', (m) => console.log(`    [${new URL(p.url()).port}] ${m.type()}: ${m.text()}`)); p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`)); } });
  return { ctx, hits };
}
/** zkIdP 페이지에서 "패스키로 로그인" 을 누르고 지갑 창을 돌려준다. */
async function clickPasskeyLogin(ctx, idpPage) {
  await idpPage.waitForSelector('#passkeyLoginBtn', { state: 'visible', timeout: 15_000 });
  const [popup] = await Promise.all([ctx.waitForEvent('page'), idpPage.click('#passkeyLoginBtn')]);
  return popup;
}
try {
  await t('zkIdP 가 패스키 가입을 열어 두었다(public_keys.oidc.signup) — 돌아올 주소는 지갑의 /google-relay', async () => {
    const k = (await cia.get('/cia/public_keys')).body;
    assert.equal(k.issueAuth, 'key'); assert.deepEqual(k.oidc.signup, { authorizeUrl: google.authorizeUrl, redirectUri: `${wallet.base}/google-relay` });
  });
  const A = await newBrowserWith(SECRET_A);
  const idpPage = await A.ctx.newPage();
  let uidA = null;
  await t('패스키도 계정도 없는 브라우저: "패스키로 로그인" → 패스키 만들기 한 번 → Google → zkIdP 에 로그인된 채로 끝난다 — 아이디는 Google 이 확인한 이메일', async () => {
    google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
    assert.equal((await accounts()).length, 0);
    await idpPage.goto(`${cia.base}/user`);
    await idpPage.waitForSelector('#passkeyLoginBtn', { state: 'visible', timeout: 15_000 });
    const note = await text(idpPage, '#passkeyLoginRow small');
    assert.ok(note.includes('Google') && !note.includes('아이디·비밀번호로 로그인하세요'), `패스키 가입이 켜져 있으면 안내문은 그 한 가지만: ${note}`);
    const popup = await clickPasskeyLogin(A.ctx, idpPage); const visited = trackNav(popup);
    await popup.waitForSelector('#authSignupPasskeyBtn', { timeout: 20_000 });
    // 가입 창은 가입이라고 말한다 — 제목과, 버튼 위의 설명(패스키 → Google 이메일). 경고 색의 안내 상자(#authHint)가 아니라 진행 줄(#authStatus)이다
    assert.ok((await text(popup, '#authTitle')).includes('계정 만들기'), await text(popup, '#authTitle'));
    const intro = await text(popup, '#authStatus'); assert.ok(intro.includes('Google') && intro.includes('패스키'), intro);
    assert.equal(await popup.$eval('#authHint', (e) => e.hidden), true, '안내 상자는 쓰지 않는다');
    assert.equal((await accounts()).length, 0, '버튼을 누르기 전에는 아무것도 만들지 않는다');
    await popup.click('#authSignupPasskeyBtn');
    await idpPage.waitForSelector('#meCard:not([hidden])', { timeout: 90_000 });
    assert.ok(went(visited, google.authorizeUrl), `Google 로 가지 않았다: ${j(visited.map((u) => u.slice(0, 70)))}`);
    assert.ok(went(visited, `${wallet.base}/google-relay`), '중계 화면을 거치지 않았다');
    assert.ok(!visited.some((u) => u.startsWith(`${cia.base}/login`)), 'zkIdP 인증 창(아이디·비밀번호)으로 가면 안 된다');
    assert.ok((await text(idpPage, '#meInfo')).includes('jihoo@example.com'), await text(idpPage, '#meInfo'));
    const acc = await accounts(); assert.equal(acc.length, 1, j(acc.map((a) => a.id)));
    assert.equal(acc[0].id, 'jihoo@example.com'); assert.ok(acc[0].auid, '등록까지 끝났다'); assert.equal(acc[0].provider, 'demo');
    uidA = String(acc[0].uid);
    // 이 계정에 맞지 않는 카드는 보이지 않는다 — 비밀번호가 없고(연결 해제·계정 폐기), 속성 도구를 거치지 않았다(프로필)
    assert.equal(await idpPage.$eval('#profileCard', (e) => e.hidden), true, '프로필 카드'); assert.equal(await idpPage.$eval('#revokeCard', (e) => e.hidden), true, '연결 해제·계정 폐기 카드');
    const infoPage = await A.ctx.newPage();
    try { await infoPage.goto(`${cia.base}/user/info`); await infoPage.waitForFunction(() => (document.getElementById('infoMethod')?.textContent ?? '-') !== '-', null, { timeout: 15_000 }); const m = await text(infoPage, '#infoMethod'); assert.ok(m.includes('Google') && m.includes('패스키'), `가입 방식: ${m}`); }
    finally { await infoPage.close(); }
    assert.equal(A.hits.create, 1); assert.equal(A.hits.get, 1, `패스키 확인은 만들 때의 한 번뿐이어야 한다(가입 준비는 그 값을 쓴다): ${j(A.hits)}`);
  });
  const userPage = await A.ctx.newPage();
  await t('지갑에는 등록(공개값)만 남는다 — salt·Google 토큰·가입 대기분은 어디에도 없다', async () => {
    await userPage.goto(`${wallet.base}/`); await userPage.waitForSelector('#mainView:not([hidden])');
    const reg = await idbGet(userPage, 'registration');
    assert.equal(String(reg.uid), uidA); assert.equal(reg.provider, 'demo'); assert.deepEqual(reg.profile, { birthYear: '1990', country: 'KR' }, j(reg.profile));
    assert.equal(await idbGet(userPage, 'passkeyHold'), undefined);
    const stores = await userPage.evaluate(() => ({ ss: Object.keys(sessionStorage), ls: Object.entries(localStorage).map(([k, v]) => `${k}=${v}`) }));
    assert.ok(!stores.ss.includes('mode3.signup.pending'), j(stores.ss));
    assert.ok(!stores.ls.some((e) => /eyJ[A-Za-z0-9_-]{10,}\./.test(e)), 'localStorage 에 토큰 모양이 있다');
  });
  await t('서비스 로그인은 Google·인증 창 없이 패스키 한 번 — 속성 도구를 거치지 않았어도 된다', async () => {
    const rpPage = await A.ctx.newPage(); await rpPage.goto(rp.base);
    await rpPage.click('#loginBtn'); const g0 = A.hits.get;
    const [popup] = await Promise.all([A.ctx.waitForEvent('page'), rpPage.click('#idpLoginBtn')]); const visited = trackNav(popup);
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    assert.ok(!went(visited, google.authorizeUrl) && !went(visited, `${cia.base}/login`), j(visited.map((u) => u.slice(0, 70))));
    assert.equal(A.hits.get - g0, 1);
    await rpPage.close();
  });
  await t('zkIdP 다시 로그인: 로그아웃 뒤 "패스키로 로그인" 은 Google 없이 패스키 한 번', async () => {
    await idpPage.click('#logoutBtn'); await idpPage.waitForSelector('#meCard', { state: 'hidden' });
    const g0 = A.hits.get;
    const popup = await clickPasskeyLogin(A.ctx, idpPage); const visited = trackNav(popup);
    await idpPage.waitForSelector('#meCard:not([hidden])', { timeout: 60_000 });
    assert.ok(!went(visited, google.authorizeUrl), 'Google 로 가면 안 된다'); assert.equal(A.hits.get - g0, 1);
    assert.equal((await accounts()).length, 1);
  });
  await t('복구: 저장소가 빈 다른 브라우저의 같은 패스키 + 같은 Google 계정 → 새 계정을 만들지 않고 기존 계정으로 들어간다(패스키를 한 번 더 묻는다)', async () => {
    const A2 = await newBrowserWith(SECRET_A);
    try {
      const w = await A2.ctx.newPage(); await w.goto(`${wallet.base}/`); await w.waitForSelector('#pkSetupCard:not([hidden])');
      await w.click('#pkExistingBtn'); await waitText(w, '#pkSetupVerdict', '패스키를 연결했습니다');
      google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
      const page = await A2.ctx.newPage(); await page.goto(`${cia.base}/user`);
      const g0 = A2.hits.get;
      const popup = await clickPasskeyLogin(A2.ctx, page); const visited = trackNav(popup);
      await page.waitForSelector('#meCard:not([hidden])', { timeout: 90_000 });
      assert.ok(went(visited, google.authorizeUrl));
      assert.ok((await text(page, '#meInfo')).includes('jihoo@example.com'));
      const acc = await accounts(); assert.equal(acc.length, 1, '계정이 늘면 안 된다'); assert.equal(String(acc[0].uid), uidA);
      assert.equal(String((await idbGet(w, 'registration')).uid), uidA);
      assert.equal(A2.hits.get - g0, 2, `가입 준비 한 번 + 복구 한 번: ${j(A2.hits)}`); assert.equal(A2.hits.create, 0);
    } finally { await A2.ctx.close(); }
  });
  await t('같은 Google 계정 + 다른 패스키는 거절한다 — zkIdP 페이지에 사유가 보이고 계정·등록이 생기지 않는다', async () => {
    const B = await newBrowserWith(SECRET_B);
    try {
      google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
      const page = await B.ctx.newPage(); await page.goto(`${cia.base}/user`);
      const popup = await clickPasskeyLogin(B.ctx, page);
      await popup.waitForSelector('#authSignupPasskeyBtn', { timeout: 20_000 }); await popup.click('#authSignupPasskeyBtn');
      await waitText(page, '#userVerdict', '다른 패스키', 90_000);
      assert.equal(await page.$eval('#meCard', (e) => e.hidden), true);
      assert.equal((await accounts()).length, 1);
      const w = await B.ctx.newPage(); await w.goto(`${wallet.base}/`); await w.waitForSelector('#mainView:not([hidden])');
      assert.equal(await idbGet(w, 'registration'), undefined);
    } finally { await B.ctx.close(); }
  });
  await t('확인되지 않은 이메일의 Google 계정은 가입하지 못한다', async () => {
    const C = await newBrowserWith('c9'.repeat(32));
    try {
      google.setNextSub('google-user-C'); google.setNextClaims({ email: 'c@example.com', email_verified: false });
      const page = await C.ctx.newPage(); await page.goto(`${cia.base}/user`);
      const popup = await clickPasskeyLogin(C.ctx, page);
      await popup.waitForSelector('#authSignupPasskeyBtn', { timeout: 20_000 }); await popup.click('#authSignupPasskeyBtn');
      await waitText(page, '#userVerdict', '확인한 이메일이 없습니다', 90_000);
      assert.equal((await accounts()).length, 1);
    } finally { await C.ctx.close(); }
  });
} finally {
  await browser.close().catch(() => {});
  await stack.stop();
  await google.stop?.();
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed === 0 ? 0 : 1);
