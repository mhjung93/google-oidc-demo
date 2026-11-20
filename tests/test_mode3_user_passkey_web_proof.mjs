// passkey-web 의 증명 로그인(스펙 2026-11-19-mode3-passkey-proof-login) — IdP 의 발급 정책이 key 일 때:
//   · 등록된 지갑의 서비스 로그인은 zkIdP 인증 창(아이디·비밀번호)을 거치지 않고 패스키 증명만으로 끝난다(L1·L2)
//   · 로그인마다 패스키를 한 번 묻는다(L4). 재검증도 창마다 한 번 — salt 를 저장하지 않는다(2026-11-20: 10분 보관 제거)
//   · zkIdP 페이지의 "패스키로 로그인"(L5·L7·L9) — 지갑 창은 IdP 오리진이 연 창에만 증명을 돌려준다(L8)
// code 정책의 passkey-web(지금까지의 동작)은 tests/test_mode3_user_passkey_web.mjs 가 본다.
// 정적 서버(MODE3_WALLET_SECRETS=passkey-web) + 격리 IdP(CIA_ISSUE_AUTH 기본 = key)·RP + 결정적 WebAuthn 스텁. hardhat :8545, build/mode3, Chrome 필요(browser 그룹).
//   node tests/test_mode3_user_passkey_web_proof.mjs   (MODE3_BROWSER_DEBUG=1 이면 콘솔 출력)
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { buildWebAuthnStub } from './helpers/webauthn_stub.js';
import { startOidcIssuerStub } from './helpers/oidc_issuer_stub.mjs';
import { auidOf } from '../lib/mode3_credential.js';

const DEBUG = process.env.MODE3_BROWSER_DEBUG === '1';
const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); }
}
async function launchBrowser() {
  const tried = [];
  for (const opts of [{ channel: 'chrome' }, {}]) {
    try { return await chromium.launch(opts); }
    catch (e) { tried.push(`${j(opts)}: ${e.message.split('\n')[0]}`); }
  }
  throw new Error(`BLOCKED: 브라우저를 띄우지 못했다.\n  ${tried.join('\n  ')}`);
}
/** 스텁 패스키의 salt·credential ID — tests/test_mode3_user_passkey_web.mjs 와 같은 식. */
function stubSalt(secretHex) {
  const salt = createHash('sha256').update(Buffer.concat([Buffer.from('WebAuthn PRF\0'), Buffer.from('zkd-s_u-v1')])).digest();
  const prf = createHmac('sha256', Buffer.from(secretHex, 'hex')).update(salt).digest();
  return (BigInt('0x' + createHash('sha256').update(Buffer.concat([Buffer.from('zkd-passkey-s_u-v1'), prf])).digest('hex')) >> 6n).toString();
}
const stubCredId = (secretHex) => createHash('sha256').update(Buffer.from(secretHex, 'hex')).digest().subarray(0, 16).toString('base64url');

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
execFileSync('node', ['scripts/build_attr_tool.mjs'], { stdio: 'inherit' });
const browser = await launchBrowser();
// CIA_ISSUE_AUTH 를 주지 않는다 — 격리 IdP 의 기본(key). MODE3_WALLET_KIND: 분리 데모 스크립트가 IdP·서비스에 넘기는 값(문구와 "패스키로 로그인" 버튼).
const stack = await startIsolatedMode3Stack({ userMode: 'web', walletHost: 'localhost', walletEnv: { MODE3_WALLET_SECRETS: 'passkey-web' }, ciaEnv: { MODE3_WALLET_KIND: 'passkey-web', CIA_PLAIN_OIDC: '1' }, rpEnv: { MODE3_WALLET_KIND: 'passkey-web', MODE3_RP_ZKOIDC: '1' }, autoRelay: true });   // CIA_PLAIN_OIDC·MODE3_RP_ZKOIDC: 일반 OIDC(비교용) — 스크립트가 passkey-web 에서 기본으로 켠다
const { cia, wallet, rp } = stack;
const WALLET_ORIGIN = new URL(wallet.base).origin;
// Google 대역 발급자(2026-11-19 시나리오 3·4 — 실제 Google 자리): 서비스는 리디렉션식으로 다녀오고, 돌아올 주소는 지갑 정적 서버의 /google-relay 다(실제 데모에서는 https://127.0.0.1:5100/google-relay).
const google = await startOidcIssuerStub({ clientId: 'rp-google-client', provider: 'google' });
await stack.restartRp({ MODE3_RP_GOOGLE_CLIENT_ID: google.clientId, MODE3_RP_GOOGLE_ISSUER: google.issuer, MODE3_RP_GOOGLE_JWKS_URL: google.jwksUrl, MODE3_RP_GOOGLE_AUTHORIZE_URL: google.authorizeUrl, MODE3_RP_GOOGLE_REDIRECT_URI: `${wallet.base}/google-relay` });
const SECRET = 'e5'.repeat(32), SALT = stubSalt(SECRET);
const AUID = (await auidOf({ s_u: BigInt(SALT) })).toString();
const PWD = 'demo-pass-9';
const hits = { create: 0, get: 0, rpIds: [] };
const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
/** 화면 확인용 캡처(검사 아님) — MODE3_SHOT_DIR 이 있을 때만 그 요소를 PNG 로 남긴다. */
const shot = async (page, sel, name) => { if (!process.env.MODE3_SHOT_DIR) return; try { await page.setViewportSize({ width: 1280, height: 1400 }); await (await page.$(sel)).screenshot({ path: `${process.env.MODE3_SHOT_DIR}/${name}.png` }); } catch (e) { console.log(`shot ${name}: ${e.message}`); } };
async function waitText(page, sel, needle, timeout = 30_000) {
  try { await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout }); }
  catch { throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`); }
}
const visible = (page, sel) => page.$eval(sel, (el) => getComputedStyle(el).display !== 'none' && !el.hidden);
const putPasskey = (page, credentialId) => page.evaluate(async (cid) => { const open = indexedDB.open('mode3-user', 1); open.onupgradeneeded = () => { if (!open.result.objectStoreNames.contains('kv')) open.result.createObjectStore('kv'); }; const db = await new Promise((r, x) => { open.onsuccess = () => r(open.result); open.onerror = () => x(open.error); }); await new Promise((r, x) => { const q = db.transaction('kv', 'readwrite').objectStore('kv').put({ credentialId: cid, createdAt: Date.now() }, 'passkey'); q.onsuccess = () => r(); q.onerror = () => x(q.error); }); db.close(); }, credentialId);
const idbGet = (page, key) => page.evaluate(async (k) => { const open = indexedDB.open('mode3-user', 1); const db = await new Promise((r, x) => { open.onsuccess = () => r(open.result); open.onerror = () => x(open.error); }); const v = await new Promise((r, x) => { const q = db.transaction('kv').objectStore('kv').get(k); q.onsuccess = () => r(q.result); q.onerror = () => x(q.error); }); db.close(); return v; }, key);
// 2026-11-20: 속성 도구의 기록은 version 6 — salt 없이 그 salt 의 auid(공개값)만 있다. 이 파일은 새 모양으로 넣는다(옛 version 5 는 tests/test_mode3_user_passkey_web.mjs 가 본다).
const putAttrRecord = (page, auid) => page.evaluate(async (r) => {
  try { const x = await fetch('/attr/dist/reset.json', { cache: 'no-store' }); if (x.ok) localStorage.setItem('mode3_attr_tool_reset', String((await x.json()).epoch ?? '')); } catch { /* 없으면 그대로 */ }
  localStorage.setItem('mode3_attr_tool_v1', JSON.stringify(r));
}, { version: 6, auid, profile: { birthYear: '1990', country: 'KR' } });
const rpLoginClick = async (page) => { if (await page.$eval('#loginBtn', (b) => b.hidden)) { await page.click('#logoutBtn'); await page.waitForSelector('#loginBtn:not([hidden])'); } await page.click('#loginBtn'); await page.click('#idpLoginBtn'); };
/** 팝업이 거친 주소를 모은다 — 인증 창(IdP 오리진)으로 갔는지 본다. */
const trackNav = (popup) => { const visited = [popup.url()]; popup.on('framenavigated', (f) => { if (f === popup.mainFrame()) visited.push(f.url()); }); return visited; };
const wentToIdp = (visited) => visited.some((u) => { try { return new URL(u).origin === cia.base; } catch { return false; } });
/** 아무 페이지에서나 지갑 창을 열어 mode3-idp-login 을 보내고 결과를 받는다(피싱 각본). originField = 요청에 적는 origin. */
const askIdpLogin = (page, originField, nonce) => page.evaluate(([walletOrigin, origin, n]) => new Promise((resolve) => {
  const popup = window.open(`${walletOrigin}/?authorize=1`, 'phish', 'width=460,height=640');
  const timer = setTimeout(() => resolve({ timeout: true }), 60_000);
  window.addEventListener('message', function on(ev) {
    if (ev.origin !== walletOrigin || ev.source !== popup || !ev.data) return;
    if (ev.data.type === 'mode3-authorize-ready') { popup.postMessage({ type: 'mode3-idp-login', origin, nonce: n }, walletOrigin); return; }
    if (ev.data.type !== 'mode3-idp-login-result') return;
    clearTimeout(timer); window.removeEventListener('message', on); resolve(ev.data.result);
  });
}), [WALLET_ORIGIN, originField, nonce]);

try {
  assert.equal((await wallet.get('/user/config')).body.secrets, 'passkey-web');
  assert.equal((await cia.get('/cia/public_keys')).body.issueAuth, 'key', '이 테스트는 key 정책의 IdP 를 본다');
  const ctx = await browser.newContext();
  await ctx.exposeFunction('__webauthnHit', (k, rpId) => { hits[k] = (hits[k] ?? 0) + 1; hits.rpIds.push(rpId); });
  await ctx.addInitScript({ content: buildWebAuthnStub({ secretHex: SECRET }) });
  ctx.on('dialog', (d) => d.accept());
  ctx.on('page', (p) => { if (DEBUG) { p.on('console', (m) => console.log(`    [${new URL(p.url()).port}] ${m.type()}: ${m.text()}`)); p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`)); } });

  // zkIdP 가입(아이디·비밀번호 — L3: 가입은 그대로) → 로그아웃 상태의 zkIdP 페이지를 열어 둔다
  const idpPage = await ctx.newPage(); await idpPage.goto(`${cia.base}/user`);
  await idpPage.click('#showSignupBtn'); await idpPage.fill('#signupId', 'pk-proof'); await idpPage.fill('#signupPwd', PWD); await idpPage.fill('#signupPwd2', PWD); await idpPage.click('#signupBtn');
  await waitText(idpPage, '#userVerdict', '가입했습니다');
  const userPage = await ctx.newPage(); await userPage.goto(`${wallet.base}/`); await userPage.waitForSelector('#mainView:not([hidden])');
  await putPasskey(userPage, stubCredId(SECRET));
  await putAttrRecord(userPage, AUID);
  const rpPage = await ctx.newPage(); await rpPage.goto(rp.base);
  const curSession = () => rpPage.evaluate(() => (typeof currentSession === 'undefined' ? null : currentSession));

  await t('zkIdP 페이지: key 정책 + passkey-web 이면 "패스키로 로그인" 이 보인다 — 아이디·비밀번호 폼도 그대로', async () => {
    await idpPage.waitForFunction(() => { const r = document.getElementById('passkeyLoginRow'); return r && !r.hidden && getComputedStyle(r).display !== 'none'; }, null, { timeout: 15_000 });
    assert.equal((await text(idpPage, '#passkeyLoginBtn')).trim(), '패스키로 로그인');
    assert.equal(await visible(idpPage, '#loginForm'), true);
  });

  await t('zkIdP 페이지: 등록 전에는 패스키 로그인이 not_registered 로 끝난다 — 패스키를 묻지 않는다', async () => {
    const before = hits.get;
    const [popup] = await Promise.all([ctx.waitForEvent('page'), idpPage.click('#passkeyLoginBtn')]);
    await waitText(idpPage, '#userVerdict', '로그인 실패', 30_000);
    assert.ok((await text(idpPage, '#userVerdict')).includes('등록되지 않았습니다'), await text(idpPage, '#userVerdict'));
    if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 20_000 }).catch(() => {});
    assert.equal(hits.get - before, 0);
    assert.equal(await visible(idpPage, '#loginView'), true, '로그인되지 않았다');
  });

  await t('첫 로그인 = 등록(L3 그대로): 인증 창(등록 모드, 아이디·비밀번호·auid) → 등록·로그인 성공, 패스키 한 번', async () => {
    const before = hits.get;
    const [popup] = await Promise.all([ctx.waitForEvent('page'), rpLoginClick(rpPage)]);
    await popup.waitForURL((x) => x.origin === cia.base && x.pathname === '/login', { timeout: 60_000 });
    assert.equal(new URL(popup.url()).searchParams.get('purpose'), 'register');
    await popup.fill('#authUid', 'pk-proof'); await popup.fill('#authPwd', PWD); await popup.fill('#authAuid', AUID); await popup.click('#authGo');
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    assert.equal(hits.get - before, 1, `패스키 ${hits.get - before}번`);
    assert.equal(String((await idbGet(userPage, 'registration'))?.auid), AUID);
  });

  await t('두 번째 로그인(L1·L2·L4): zkIdP 인증 창으로 가지 않는다 — 패스키 한 번, 로그인 성공. salt 보관분은 없다', async () => {
    assert.equal(await idbGet(userPage, 'passkeyHold'), undefined, 'IndexedDB 에 salt 보관분이 있다');
    const prev = await curSession(), before = hits.get;
    const [popup] = await Promise.all([ctx.waitForEvent('page'), rpLoginClick(rpPage)]);
    const visited = trackNav(popup);
    await rpPage.waitForFunction((p) => typeof currentSession !== 'undefined' && currentSession && currentSession !== p, prev, { timeout: 180_000 });
    await waitText(rpPage, '#verdict', '로그인 성공', 60_000);
    assert.equal(wentToIdp(visited), false, `팝업이 zkIdP 로 갔다: ${j(visited)}`);
    assert.equal(hits.get - before, 1, `패스키 ${hits.get - before}번 — 로그인마다 한 번이어야 한다`);
    assert.equal(await idbGet(userPage, 'passkeyHold'), undefined, '로그인 뒤 IndexedDB 에 salt 보관분이 있다');
  });

  await t('재검증도 패스키를 한 번 묻는다 — 저장해 둔 salt 가 없다', async () => {
    const before = hits.get;
    const [popup, rv] = await Promise.all([ctx.waitForEvent('page'), rpPage.evaluate(() => popupCall('mode3-revalidate', { arid: info.arid, origin: info.origin, r_s: currentSession }))]);
    assert.equal(rv.ok, true, j(rv));
    if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 15_000 }).catch(() => {});
    assert.equal(hits.get - before, 1, `패스키 ${hits.get - before}번`);
  });

  await t('피싱(L8): zkIdP 가 아닌 페이지가 지갑 창에 로그인 증명을 청하면 origin_mismatch — 요청의 origin 을 zkIdP 로 속여도 같다, 패스키도 묻지 않는다', async () => {
    const before = hits.get;
    const ch = await idpPage.evaluate(() => fetch('/cia/user/login_challenge', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then((r) => r.json()));
    const [phishPopup, honest] = await Promise.all([ctx.waitForEvent('page'), askIdpLogin(rpPage, rp.base, ch.nonce)]);
    assert.equal(honest.ok, false, j(honest)); assert.equal(honest.reason, 'origin_mismatch');
    // 리뷰 M5: 거절된 요청의 창에 "zkIdP 로그인" 제목·주소 줄을 그리지 않는다(남의 사이트가 지갑 창을 zkIdP 로그인 화면처럼 보이게 하지 못한다)
    assert.equal((await text(phishPopup, '#authTitle')).includes('zkIdP 로그인'), false, await text(phishPopup, '#authTitle'));
    assert.equal((await text(phishPopup, '#authSummary')).trim(), '', await text(phishPopup, '#authSummary'));
    await rpPage.waitForTimeout(3500);   // 실패한 창은 3초 뒤에 닫힌다 — 같은 이름의 창을 다시 열기 전에 기다린다
    const spoofed = await askIdpLogin(rpPage, cia.base, ch.nonce);
    assert.equal(spoofed.ok, false, j(spoofed)); assert.equal(spoofed.reason, 'origin_mismatch');
    assert.equal(j(honest).includes('proof_idp') || j(spoofed).includes('proof_idp'), false, '증명이 새어 나갔다');
    assert.equal(hits.get - before, 0);
  });

  await t('zkIdP 페이지: "패스키로 로그인" → 지갑 창이 패스키로 증명 → 로그인된다(비밀번호 없이). 패스키 한 번, 증명 기록의 용도는 idp_login', async () => {
    const before = hits.get;
    assert.equal((await idpPage.evaluate(() => fetch('/cia/user/me').then((r) => r.status))), 401, '로그인 전');
    const [popup] = await Promise.all([ctx.waitForEvent('page'), idpPage.click('#passkeyLoginBtn')]);
    const visited = trackNav(popup);
    await idpPage.waitForFunction(() => getComputedStyle(document.getElementById('loginView')).display === 'none' || document.getElementById('loginView').hidden, null, { timeout: 120_000 }).catch(async () => { throw new Error(`로그인되지 않았다: ${await text(idpPage, '#userVerdict')}`); });
    const me = await idpPage.evaluate(() => fetch('/cia/user/me').then((r) => r.json()));
    assert.equal(me.id, 'pk-proof', j(me)); assert.equal(String(me.auid), AUID);
    assert.equal(hits.get - before, 1, `패스키 ${hits.get - before}번`);
    assert.equal(wentToIdp(visited), false, '지갑 창은 zkIdP 로 이동하지 않는다');
    const proofs = (await idbGet(userPage, 'proofs')) ?? [];
    assert.equal(proofs.at(-1)?.purpose, 'idp_login', j(proofs.map((p) => p.purpose)));
  });

  // 리뷰 M4: zkIdP 로그인의 "패스키 한 번" 은 정책 읽기에 기대지 않는다 — 지갑 창이 public_keys 를 못 읽어도(정책을 code 로 보게 돼도) 패스키를 건너뛰지 않는다.
  await t('zkIdP 페이지: 지갑 창이 IdP 정책을 못 읽어도 패스키 로그인은 패스키를 한 번 묻는다', async () => {
    await idpPage.click('#logoutBtn');
    await idpPage.waitForFunction(() => !document.getElementById('loginView').hidden, null, { timeout: 15_000 });
    const block = (route) => (new URL(route.request().url()).pathname === '/cia/public_keys' && route.request().headers().origin === WALLET_ORIGIN ? route.abort() : route.continue());
    await ctx.route(`${cia.base}/cia/public_keys`, block);
    try {
      const before = hits.get;
      await Promise.all([ctx.waitForEvent('page'), idpPage.click('#passkeyLoginBtn')]);
      await idpPage.waitForFunction(() => document.getElementById('loginView').hidden || getComputedStyle(document.getElementById('loginView')).display === 'none', null, { timeout: 120_000 }).catch(async () => { throw new Error(`로그인되지 않았다: ${await text(idpPage, '#userVerdict')}`); });
      assert.equal(hits.get - before, 1, `패스키 ${hits.get - before}번`);
    } finally { await ctx.unroute(`${cia.base}/cia/public_keys`, block); }
  });

  await t('zkIdP 페이지: 로그아웃 뒤 아이디·비밀번호 로그인도 그대로 된다(L3)', async () => {
    await idpPage.click('#logoutBtn');
    await idpPage.waitForFunction(() => !document.getElementById('loginView').hidden, null, { timeout: 15_000 });
    await idpPage.fill('#loginId', 'pk-proof'); await idpPage.fill('#loginPwd', PWD); await idpPage.click('#loginBtn');
    await idpPage.waitForFunction(() => fetch('/cia/user/me').then((r) => r.status === 200), null, { timeout: 15_000 });
  });

  // ---- OIDC 와 zk-Delegation 비교(스펙 2026-11-19-mode3-oidc-comparison, 2026-11-19 데모 시나리오) ----
  // 서비스는 받은 ID 토큰의 sub·aud 를 보인다: zk-Delegation 은 auid_s·arid_s(가려진 값), 일반 OIDC 는 uid·rid 그대로. zkIdP 는 계정마다 "본 서비스" 를 하나씩 남긴다.
  const seenTitle = (page, k) => page.$eval(`#seenBody [data-seen="${k}"]`, (el) => el.title);
  const idpAccount = async () => (await fetch(`${cia.base}/cia/accounts`, { headers: cia.adminHeaders }).then((r) => r.json())).accounts.find((a) => a.id === 'pk-proof');
  const rpInfo = await rpPage.evaluate(() => fetch('/api/mode3/rp_info').then((r) => r.json()));
  let zkSeen = null;
  await t('zk-Delegation 로그인: 서비스가 받은 토큰의 sub = auid_s·aud = arid_s(+ PPID) — uid·rid 가 아니다. zkIdP 가 본 것도 같은 arid_s 뿐이다', async () => {
    const prev = await curSession();
    const [popup] = await Promise.all([ctx.waitForEvent('page'), rpLoginClick(rpPage)]);
    await rpPage.waitForFunction((p) => typeof currentSession !== 'undefined' && currentSession && currentSession !== p, prev, { timeout: 180_000 });
    await rpPage.waitForSelector('#seenBox[data-protocol="zk"]:not([hidden])', { timeout: 30_000 });
    zkSeen = { auid_s: await seenTitle(rpPage, 'auid_s'), arid_s: await seenTitle(rpPage, 'arid_s'), PPID: await seenTitle(rpPage, 'PPID') };
    for (const v of Object.values(zkSeen)) assert.match(v, /^[0-9]{20,}$/, j(zkSeen));
    const acct = await idpAccount();
    assert.notEqual(zkSeen.auid_s, acct.uid); assert.notEqual(zkSeen.arid_s, String(rpInfo.arid), 'arid 자체가 아니다');
    const jwt = JSON.parse(await rpPage.$eval('#seenJwt', (el) => el.textContent));
    assert.equal(jwt.sub, zkSeen.auid_s); assert.equal(jwt.aud, zkSeen.arid_s); assert.equal(jwt.zkid_plain, undefined);
    assert.equal(acct.lastAridS.value, zkSeen.arid_s, 'zkIdP 가 남긴 arid_s 가 서비스가 받은 aud 와 같다'); assert.equal(acct.lastAuidS.value, zkSeen.auid_s);
    // 2026-11-20(사용자 요청): iss 줄(토큰 본문의 값 그대로)과, aud 는 앞 17자만(전체는 title) — 제목에 iss·sub·aud
    assert.equal(await text(rpPage, '#seenBody [data-seen="iss"]'), jwt.iss); assert.ok(jwt.iss.startsWith('http'), jwt.iss);
    assert.equal(await text(rpPage, '#seenBody [data-seen="arid_s"]'), `${zkSeen.arid_s.slice(0, 17)}…`);
    assert.equal(await text(rpPage, '#seenFigureBody [data-flow="arid_s"]'), `${zkSeen.arid_s.slice(0, 17)}…`, '그림의 aud 도 앞 17자');
    assert.ok((await text(rpPage, '#seenFigureBody')).includes('π_RP') && !(await text(rpPage, '#seenFigureBody')).includes('π_session'), '증명의 화면 이름은 π_RP');
    assert.ok((await text(rpPage, '#seenTitle')).includes('iss·sub·aud'), await text(rpPage, '#seenTitle'));
    // 데모 시나리오 7(2026-11-19): 서비스가 받은 것·검증한 것·알 수 없는 것의 그림 — 값은 이 로그인의 실제 값이다
    const fig = await rpPage.evaluate(() => ({ n: document.querySelectorAll('#seenFigureBody .flow-fig').length, ppid: document.querySelector('#seenFigureBody [data-flow="PPID"]')?.title, arid: document.querySelector('#seenFigureBody [data-flow="arid"]')?.title,
      checks: [...document.querySelectorAll('#seenFigureBody .flow-check li')].map((x) => x.textContent), unknown: [...document.querySelectorAll('#seenFigureBody .flow-unknown li')].map((x) => x.textContent), all: document.getElementById('seenFigureBody').textContent }));
    assert.equal(fig.n, 1); assert.equal(fig.ppid, zkSeen.PPID); assert.equal(fig.arid, String(rpInfo.arid));
    assert.ok(fig.checks.length >= 6 && fig.checks.some((x) => x.includes('폐기')) && fig.checks.some((x) => x.includes('ID 토큰')), j(fig.checks));
    assert.ok(fig.unknown.some((x) => x.includes('uid')), j(fig.unknown)); assert.equal(/\bflow_[a-z0-9_]+\b/.test(fig.all), false, '사전에 없는 키가 그대로 보인다');
    // 2026-11-19(화면 셀프 리뷰): "알려 준 것" 은 오른쪽 좁은 칸이 아니라 시세표 아래의 넓은 카드다 — 그림이 가로 세 칸으로 펴진다
    const box = await rpPage.evaluate(() => ({ w: document.getElementById('seenBox').getBoundingClientRect().width, inAssets: Boolean(document.getElementById('seenBox').closest('#assets')), cols: getComputedStyle(document.querySelector('#seenFigureBody .flow-fig')).gridTemplateColumns.split(' ').length,
      below: document.getElementById('seenBox').getBoundingClientRect().top >= document.getElementById('market').getBoundingClientRect().bottom, overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth }));
    assert.ok(box.w >= 600 && !box.inAssets && box.below, j(box)); assert.equal(box.cols, 3, j(box)); assert.ok(box.overflow <= 1, j(box));
    await shot(rpPage, '#seenBox', 'rp_seen_zk');
  });

  // ---- trace tag 없는 개봉(스펙 2026-11-19-mode3-trace-without-tag, 데모 시나리오 9·10) ----
  await t('개봉: 서비스가 그 PPID 의 가장 최신 로그인(auid_s)을 zkIdP 에 내고, zkIdP 관리자가 승인하면 발급 기록에서 uid 가 나온다 — 증명의 공개 입력은 29개(태그 없음)', async () => {
    const acct = await idpAccount();
    const req = await rp.post('/api/mode3/open', { PPID: zkSeen.PPID }, rp.adminHeaders);
    assert.equal(req.status, 202, j(req.body)); assert.equal(req.body.status, 'pending');
    const pending = (await fetch(`${cia.base}/cia/openings`, { headers: cia.adminHeaders }).then((r) => r.json())).openings.find((o) => o.id === req.body.id);
    assert.equal(pending.auid_s, zkSeen.auid_s, 'zkIdP 가 받은 것은 그 로그인의 auid_s 다'); assert.equal(pending.uid, null);
    for (const k of ['c1', 'c2', 'D_svc']) assert.equal(k in pending, false, `${k}(태그·조각)는 없다`);
    assert.equal((await rp.get(`/api/mode3/open/${req.body.id}`, rp.adminHeaders)).status, 202, '승인 전');
    const ap = await fetch(`${cia.base}/cia/openings/${req.body.id}/approve`, { method: 'POST', headers: cia.adminHeaders }).then((r) => r.json());
    assert.equal(ap.resolved, true, j(ap));
    const res = await rp.get(`/api/mode3/open/${req.body.id}`, rp.adminHeaders);
    assert.equal(res.status, 200, j(res.body)); assert.equal(res.body.uid, acct.uid); assert.equal(res.body.PPID, zkSeen.PPID);
    const proofs = (await idbGet(userPage, 'proofs')) ?? [];
    assert.equal(proofs.filter((x) => x.kind === 'pi_cred').at(-1).publicSignals.length, 29);
  });

  await t('일반 OIDC 로그인(비교용): zkIdP 동의 화면이 서비스·rid·uid 를 보이고, "계속" 뒤 서비스가 받은 토큰의 sub = uid·aud = rid — zkIdP 는 어느 서비스인지 적는다', async () => {
    const acct0 = await idpAccount();
    await rpPage.click('#logoutBtn'); await rpPage.waitForSelector('#loginBtn:not([hidden])');
    await rpPage.click('#loginBtn'); await rpPage.waitForSelector('#zkoidcLoginBtn:not([hidden])');
    assert.ok((await text(rpPage, '#zkoidcLoginBtn')).includes('비교용'));
    await rpPage.click('#zkoidcLoginBtn');
    await rpPage.waitForURL((x) => x.origin === cia.base && x.pathname === '/oidc/authorize', { timeout: 30_000 });
    await rpPage.waitForSelector('#oidcConsent:not([hidden])', { timeout: 15_000 });   // zkIdP 에 이미 로그인돼 있다(앞 케이스의 비밀번호 로그인)
    assert.ok((await text(rpPage, '#oidcClient')).includes(rpInfo.name), await text(rpPage, '#oidcClient'));
    assert.equal(await rpPage.$eval('#oidcRid', (e) => e.title), String(rpInfo.arid)); assert.ok((await text(rpPage, '#oidcRid')).length <= 24, 'rid 는 줄여 보인다(전체는 title)'); assert.ok((await text(rpPage, '#oidcUid')).includes(acct0.uid));
    await shot(rpPage, '#oidcCard', 'idp_oidc_consent');
    await rpPage.click('#oidcContinueBtn');
    await rpPage.waitForURL((x) => x.origin === rp.base && x.pathname === '/', { timeout: 30_000 });
    await rpPage.waitForSelector('#seenBox[data-protocol="oidc"]:not([hidden])', { timeout: 30_000 });
    assert.equal(await seenTitle(rpPage, 'uid'), acct0.uid); assert.equal(await seenTitle(rpPage, 'rid'), String(rpInfo.arid));
    const jwt = JSON.parse(await rpPage.$eval('#seenJwt', (el) => el.textContent));
    assert.equal(jwt.sub, acct0.uid); assert.equal(jwt.aud, String(rpInfo.arid)); assert.equal(jwt.zkid_plain, true);
    await waitText(rpPage, '#verdict', '로그인했습니다');
    const acct = await idpAccount();
    assert.equal(acct.lastOidc.rid, String(rpInfo.arid)); assert.equal(acct.lastOidc.name, rpInfo.name);
    assert.equal(acct.lastAridS.value, zkSeen.arid_s, 'zk 쪽 기록은 그대로다');
    // 기존 OIDC 의 그림: 받은 것은 ID 토큰(sub = uid·aud = rid), "알게 되는 것" 에 uid 가 있다
    const fig = await rpPage.evaluate(() => ({ sub: document.querySelector('#seenFigureBody [data-flow="sub"]')?.title, aud: document.querySelector('#seenFigureBody [data-flow="aud"]')?.title, learn: [...document.querySelectorAll('#seenFigureBody .flow-learn li')].map((x) => x.textContent), unknown: document.querySelectorAll('#seenFigureBody .flow-unknown li').length }));
    assert.equal(fig.sub, acct0.uid); assert.equal(fig.aud, String(rpInfo.arid)); assert.ok(fig.learn.some((x) => x.includes('uid')), j(fig.learn)); assert.equal(fig.unknown, 0);
    // 2026-11-19(화면 셀프 리뷰): 그림의 받는 쪽 이름은 서비스 이름이고('RP' 가 아니다), OIDC 로그인에는 PPID 계정 주소 줄·상단 배지의 주소가 없다
    await rpPage.waitForFunction((n) => document.querySelector('#seenFigureBody .flow-to strong')?.textContent === n, rpInfo.name, { timeout: 10_000 });
    assert.deepEqual(await rpPage.evaluate(() => [document.getElementById('accountKv').hidden, document.getElementById('accountAddr').hidden, document.getElementById('copyPpidNavBtn').hidden]), [true, true, true]);
    await shot(rpPage, '#seenBox', 'rp_seen_plain_oidc');
  });

  await t('zkIdP 관리자 표: 그 계정 줄에 "일반 OIDC 에서 본 서비스"(이름·rid)와 "zk-Delegation 에서 본 서비스"(arid_s — 어느 서비스인지 모름)가 나란히 있다', async () => {
    const p = await ctx.newPage();
    try {
      await p.goto(`${cia.base}/admin`);
      await p.waitForSelector('#adminGate:not([hidden])');
      await p.fill('#adminGate .gate-pwd', cia.adminSecret); await p.click('#adminGate .gate-form button[type=submit]');
      await p.waitForSelector('#auidMap td[data-seen="oidc"]', { timeout: 20_000 });
      const row = await p.evaluate(() => { const tr = [...document.querySelectorAll('#auidMap tbody tr')].find((r) => r.textContent.includes('pk-proof')); return { oidc: tr.querySelector('td[data-seen="oidc"]').textContent, oidcFull: tr.querySelector('td[data-seen="oidc"] code').title, zk: tr.querySelector('td[data-seen="zk"]').textContent, zkFull: tr.querySelector('td[data-seen="zk"] code').title }; });
      assert.ok(row.oidc.includes(rpInfo.name) && row.oidc.includes('rid '), row.oidc); assert.equal(row.oidcFull, String(rpInfo.arid), 'rid 는 줄여 보이고 전체는 title 에 있다');
      assert.ok(row.zk.includes('arid_s') && row.zk.includes('어느 서비스인지 모름'), row.zk); assert.equal(row.zkFull, zkSeen.arid_s);
      assert.equal(row.zk.includes(rpInfo.name), false, 'zk 쪽에는 서비스 이름이 없다');
      // 데모 시나리오 6(2026-11-19): 그 줄의 "그림" — zkIdP 가 가장 최근 발급에서 받은 것·검증한 것·알 수 없는 것
      const uid = (await idpAccount()).uid;
      assert.equal(await p.$$eval('#auidMap button[data-figure-uid]', (l) => l.length), 1, '"그림" 버튼은 로그인(발급)한 계정에만 있다');
      await p.click(`#auidMap button[data-figure-uid="${uid}"]`); await p.waitForSelector('#issueFigure:not([hidden]) .flow-fig');
      const fig = await p.evaluate(() => ({ auid_s: document.querySelector('#issueFigureBody [data-flow="auid_s"]')?.title, arid_s: document.querySelector('#issueFigureBody [data-flow="arid_s"]')?.title, uid: document.querySelector('#issueFigureBody [data-flow="uid"]')?.title,
        checks: [...document.querySelectorAll('#issueFigureBody .flow-check li')].map((x) => x.textContent), unknown: [...document.querySelectorAll('#issueFigureBody .flow-unknown li')].map((x) => x.textContent), all: document.getElementById('issueFigure').textContent }));
      assert.equal(fig.uid, uid); assert.equal(fig.auid_s, zkSeen.auid_s); assert.equal(fig.arid_s, zkSeen.arid_s);
      assert.ok(fig.checks.some((x) => x.includes('π_IdP')) && fig.unknown.some((x) => x.includes('어느 서비스')), j([fig.checks, fig.unknown]));
      await shot(p, '#issueFigure', 'idp_issue_figure'); await shot(p, '#auidMap', 'idp_auid_table');
      // 2026-11-19(화면 셀프 리뷰): "본 서비스" 두 열이 생긴 뒤에도 표가 카드·화면 밖으로 넘치지 않는다
      const fit = await p.evaluate(() => { const t = document.querySelector('#auidMap table').getBoundingClientRect(), c = document.getElementById('auidMap').closest('.card').getBoundingClientRect(); return { page: document.documentElement.scrollWidth - document.documentElement.clientWidth, table: t.right - c.right }; });
      assert.ok(fit.page <= 1 && fit.table <= 1, `표가 넘친다: ${j(fit)}`);
      // 개봉 요청 표(스펙 trace-without-tag T10): 서비스가 낸 auid_s 가 보인다 — 앞 케이스에서 승인한 요청
      await p.click('#openingsBtn');
      await p.waitForSelector('#openings td[data-open="auid_s"] code', { timeout: 15_000 });
      assert.equal(await p.$eval('#openings td[data-open="auid_s"] code', (x) => x.title), zkSeen.auid_s);
      assert.ok((await p.$eval('#openings table', (x) => x.textContent)).includes('서비스가 낸 auid_s'));
      assert.equal(fig.all.includes(rpInfo.name), false, 'zkIdP 의 그림에 서비스 이름이 없다'); assert.equal(/\bflow_[a-z0-9_]+\b/.test(fig.all), false, '사전에 없는 키가 그대로 보인다');
    } finally { await p.close(); }
  });

  await t('일반 OIDC 동의 화면에서도 패스키로 로그인할 수 있다(zkIdP 로그아웃 상태) — 패스키 한 번', async () => {
    await idpPage.click('#logoutBtn'); await idpPage.waitForFunction(() => !document.getElementById('loginView').hidden, null, { timeout: 15_000 });
    await rpPage.click('#logoutBtn'); await rpPage.waitForSelector('#loginBtn:not([hidden])');
    await rpPage.click('#loginBtn'); await rpPage.click('#zkoidcLoginBtn');
    await rpPage.waitForSelector('#oidcLogin:not([hidden])', { timeout: 30_000 });
    await rpPage.waitForFunction(() => { const r = document.getElementById('oidcPasskeyRow'); return !r.hidden && getComputedStyle(r).display !== 'none'; }, null, { timeout: 15_000 });
    const before = hits.get;
    await Promise.all([ctx.waitForEvent('page'), rpPage.click('#oidcPasskeyBtn')]);
    await rpPage.waitForSelector('#oidcConsent:not([hidden])', { timeout: 120_000 });
    assert.equal(hits.get - before, 1);
    await rpPage.click('#oidcContinueBtn');
    await rpPage.waitForSelector('#seenBox[data-protocol="oidc"]:not([hidden])', { timeout: 30_000 });
  });

  // ---- 실제 Google OIDC 의 자리(2026-11-19 데모 시나리오 3·4) — 발급자는 대역, 흐름은 실제와 같다: 서비스 → Google(암묵 흐름) → 지갑 정적 서버의 /google-relay → 서비스 ----
  await t('Google 로 로그인(리디렉션식): 중계 화면을 거쳐 서비스로 돌아오고, 받은 ID 토큰의 sub(uid)·aud(rid)가 그대로 보인다 — 주소창에 토큰이 남지 않는다', async () => {
    google.setNextSub('google-user-1');
    await rpPage.click('#logoutBtn'); await rpPage.waitForSelector('#loginBtn:not([hidden])');
    await rpPage.click('#loginBtn');
    await rpPage.waitForFunction(() => { const b = document.getElementById('googleLoginBtn'); return getComputedStyle(b).display !== 'none'; }, null, { timeout: 15_000 });
    assert.ok((await text(rpPage, '#googleLoginBtn')).includes('일반 OIDC'), `리디렉션식 Google 이 켜져 있으면 그 버튼이 "일반 OIDC" 다(2026-11-20): ${await text(rpPage, '#googleLoginBtn')}`);
    const visited = trackNav(rpPage);
    await rpPage.click('#googleLoginBtn');
    await rpPage.waitForSelector('#seenBox[data-issuer="google"]:not([hidden])', { timeout: 30_000 });
    assert.ok(visited.some((u) => u.startsWith(`${wallet.base}/google-relay`)), `중계 화면을 거치지 않았다: ${j(visited.map((u) => u.slice(0, 60)))}`);
    assert.equal(await seenTitle(rpPage, 'uid'), 'google-user-1'); assert.equal(await seenTitle(rpPage, 'rid'), google.clientId);
    const jwt = JSON.parse(await rpPage.$eval('#seenJwt', (el) => el.textContent));
    assert.equal(jwt.sub, 'google-user-1'); assert.equal(jwt.aud, google.clientId); assert.equal(jwt.iss, google.issuer);
    assert.equal(await text(rpPage, '#seenBody [data-seen="iss"]'), google.issuer, 'iss 는 줄이지 않고 보인다(2026-11-20)');
    assert.equal(await text(rpPage, '#seenBody [data-seen="rid"]'), google.clientId.length > 17 ? `${google.clientId.slice(0, 17)}…` : google.clientId, 'aud 는 앞 17자');
    assert.ok((await text(rpPage, '#seenTitle')).includes('Google'), await text(rpPage, '#seenTitle'));
    assert.equal(new URL(rpPage.url()).hash, '', '주소창에 토큰 조각이 남았다');
    const me = await rpPage.evaluate(() => fetch('/api/rp/me').then((r) => r.json()));
    assert.equal(me.via, 'google'); assert.equal(me.seen.issuer, 'google');
    await shot(rpPage, '#seenBox', 'rp_seen_google');
  });

  await t('Google 돌아온 길 위조: 이 브라우저가 시작하지 않은 조각(#google_back)은 받지 않는다 — 로그인되지 않는다', async () => {
    const p = await ctx.newPage();
    try {
      await p.goto(`${cia.base}/user`);   // 다른 오리진의 빈 맥락에서 시작(서비스의 sessionStorage 에 대기분이 없다)
      const nonce = (await p.evaluate((base) => fetch(`${base}/api/rp/oidc/nonce`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"purpose":"login"}' }).then((r) => r.json()).catch(() => null), rp.base))?.nonce ?? 'rplogin:forged';
      const tok = await google.mint({ sub: 'attacker', nonce });
      const fresh = await browser.newContext(); const q = await fresh.newPage();
      try {
        await q.goto(`${rp.base}/#google_back=1&state=forged.1&id_token=${tok}`);
        await waitText(q, '#verdict', 'Google 로그인 요청을 찾지 못했습니다', 20_000);
        assert.equal(await q.evaluate(() => fetch('/api/rp/me').then((r) => r.status)), 401);
      } finally { await fresh.close(); }
    } finally { await p.close(); }
  });

  await t('중계 화면: 이 서버가 모르는 서비스 오리진으로는 토큰을 넘기지 않는다', async () => {
    const p = await ctx.newPage();
    try {
      const state = `${Buffer.from('https://evil.example').toString('base64url')}.x`;
      await p.goto(`${wallet.base}/google-relay#state=${state}&id_token=abc`);
      await waitText(p, '#msg', '돌아갈 서비스를 알 수 없습니다', 15_000);
      assert.equal(new URL(p.url()).origin, WALLET_ORIGIN); assert.equal(new URL(p.url()).hash, '', '조각을 지운다');
    } finally { await p.close(); }
  });
  // 참고 출력(검사 아님): 이 실행에서 브라우저가 만든 증명별 생성 시간 — 로그인 단계 시간을 물을 때 본다(MODE3_BROWSER_TIMINGS=1).
  if (process.env.MODE3_BROWSER_TIMINGS === '1') console.log('TIMINGS ' + j(((await idbGet(userPage, 'proofs')) ?? []).map((x) => ({ kind: x.kind, purpose: x.purpose, ms: x.ms }))));
} finally {
  await browser.close().catch(() => {});
  await stack.stop();
  await google.stop?.();
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed === 0 ? 0 : 1);
