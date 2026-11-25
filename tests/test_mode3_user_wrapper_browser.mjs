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
import { startOidcIssuerStub } from './helpers/oidc_issuer_stub.mjs';
import { uidOf } from '../lib/mode3_oidc_nonce.js';
import { ethers } from 'ethers';
import { walletInterface } from '../lib/mode3_onchain.js';

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
// 지갑 자리와 발급 서버가 한 서버(mode3_zkwrapper.js)다 — 기본. MODE3_TEST_SPLIT=1 이면 Task 4 의 배치(지갑 정적 서버 + 따로 뜬 발급 서버)로 같은 사례를 돈다.
const SPLIT = process.env.MODE3_TEST_SPLIT === '1';
const KIND = 'zkwrapper';   // 서비스가 아는 지갑 종류 — 데모 스크립트처럼 래퍼 방식이면 배치와 관계없이 zkwrapper(서비스 페이지가 지갑 서버를 부르지 않는다)
const stack = await startIsolatedMode3Stack({ userMode: SPLIT ? 'web' : 'zkwrapper', walletHost: 'localhost', wrapper: true, autoRelay: true,
  walletEnv: { MODE3_WALLET_SECRETS: 'passkey-web', MODE3_WRAPPER: '1', MODE3_WRAPPER_CLIENT_ID: 'mode3-test-client' }, rpEnv: { MODE3_WALLET_KIND: KIND, MODE3_RELAY_DEMO_REVERT: '1' },
  ciaEnv: { MODE3_WALLET_KIND: 'passkey-web', MODE3_OIDC_REDIRECT_URI: '{walletOrigin}/google-relay' },
  extraRps: [{ name: 'zkTWO', env: { MODE3_WALLET_KIND: KIND, MODE3_ALLOWED_COUNTRIES: 'KR,JP', MODE3_REQUIRE_DISCLOSURE: '1' } }] });
const { cia, wallet, rp } = stack;
const rp2 = stack.rps[1], google = stack.oidc;
const SECRET_A = 'a7'.repeat(32), SALT_A = stubSalt(SECRET_A);
const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
const shot = async (page, name) => { if (process.env.MODE3_SHOT_DIR) await page.screenshot({ path: `${process.env.MODE3_SHOT_DIR}/${name}.png`, fullPage: true }); };   // 눈으로 볼 때만
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
async function newBrowserWith(secretHex, extraSecrets = []) {
  const hits = { create: 0, get: 0 };
  const ctx = await browser.newContext();
  await ctx.exposeFunction('__webauthnHit', (k) => { hits[k] = (hits[k] ?? 0) + 1; });
  await ctx.addInitScript({ content: buildWebAuthnStub({ secretHex, extraSecrets }) });
  const dialogs = [];   // 확인 창 문구(2026-11-23: 세션 끝내기 확인 창이 서비스 이름을 말하는지 본다)
  ctx.on('dialog', (d) => { dialogs.push(d.message()); d.accept(); });
  // 이 브라우저에서 나간 모든 요청 — 어느 페이지가(pageOrigin) 어디로(url) 무엇을(body·referer·origin) 보냈는지. Task 5 의 "서버가 무엇을 보는가" 사례가 본다.
  const reqs = [];
  ctx.on('request', (r) => { try { let from = null; try { from = new URL(r.frame().url()).origin; } catch { from = null; } reqs.push({ url: r.url(), method: r.method(), body: r.postData() ?? '', referer: r.headers().referer ?? '', origin: r.headers().origin ?? '', from, nav: r.isNavigationRequest() }); } catch { /* 닫힌 창 */ } });
  ctx.on('page', (p) => { if (DEBUG) { p.on('console', (m) => console.log(`    [${new URL(p.url()).port}] ${m.type()}: ${m.text()}`)); p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`)); } });
  return { ctx, hits, reqs, dialogs };
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
const seenSessions = new Map();   // r_s → 세션 레코드(로그인마다 모은다 — 뒤의 "서버가 무엇을 보는가" 사례가 쓴다)
const noteSessions = (dump) => { for (const [k, v] of Object.entries(dump.sessions ?? {})) seenSessions.set(k, v); return dump; };
// 래퍼 방식의 화면에 남으면 안 되는 낱말(계획 Task 6) — 별도 IdP·인증 창·π_IdP·비밀번호가 없다.
const BANNED = ['zkIdP', '인증 창', 'π_IdP', '비밀번호'], BANNED_STAFF = ['zkIdP', '인증 창', 'π_IdP'];
const visibleText = (page) => page.evaluate(() => document.body.innerText);
// 운영자·관리자 화면의 "비밀번호" 는 그 사람들 자신의 로그인(운영자 계정·관리자 시크릿)이라 남는다 — 그 두 화면은 나머지 셋만 본다(장부의 Task 6 Ruling).
const bannedIn = (txt, words = BANNED) => words.filter((w) => txt.includes(w)).map((w) => { const i = txt.indexOf(w); return `${w}: …${txt.slice(Math.max(0, i - 30), i + 30).replace(/\s+/g, ' ')}…`; });
const chainRead = new ethers.JsonRpcProvider('http://127.0.0.1:8545');
const accountAddr = (factory, PPID) => new ethers.Contract(factory, ['function computeAddress(uint256) view returns (address)'], chainRead).computeAddress(BigInt(PPID));
const ppidOf = (dump, svcArid) => Object.values(dump.sessions ?? {}).filter((s) => String(s.arid) === String(svcArid)).map((s) => s.PPID);
try {
  const info1 = (await rp.get('/api/mode3/rp_info')).body, info2 = (await rp2.get('/api/mode3/rp_info')).body;
  const A = await newBrowserWith(SECRET_A);
  /** 2026-11-24(사용자 요청): 세션 관리는 /user — 처음에는 잠겨 있고 패스키로 연다(이 탭에서 10분 동안 아무 동작이 없으면 다시 잠긴다). 이미 열려 있으면 패스키를 묻지 않는다. */
  const openUser = async (page, q = '') => {
    await page.goto(`${wallet.base}/user${q}`); await page.waitForSelector('#mainView:not([hidden])');
    await page.waitForFunction(() => ['userLockCard', 'sessionsCard'].some((id) => document.getElementById(id)?.checkVisibility() === true), null, { timeout: 15_000 });
    if (await page.evaluate(() => document.getElementById('userLockCard')?.checkVisibility() === true)) await page.click('#userUnlockBtn');
    await page.waitForSelector('#sessionsCard', { state: 'visible', timeout: 15_000 });
    return page;
  };
  const UID_A = uidOf(google.provider, 'google-user-A');
  let ppid1 = null, popupBanned = null, ppid2 = null, acct2 = null, replayHash = null;
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
    popupBanned = bannedIn(await visibleText(popup));   // 문구 검사(Task 6)는 아래 사례에서 본다 — 여기서는 창이 떠 있는 동안 글자만 모은다
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
    const d = noteSessions(await idbDump(userPage));
    assert.equal(String(d.registration.uid), UID_A); assert.equal(d.registration.wrapper, true); assert.equal(d.wrapperKey, undefined, '요청 키가 남았다');
    // 2026-11-24(사용자 결정): 속성 기본값(1990·KR)이 없다 — 속성 도구를 쓰지 않은 첫 등록은 모든 칸이 "값 없음"(0)
    assert.ok((d.registration.attrs ?? []).length === 6 && d.registration.attrs.every((a) => String(a) === '0'), j(d.registration.attrs)); assert.deepEqual(d.registration.profile ?? {}, {});
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
    const ps = ppidOf(noteSessions(await idbDump(userPage)), info1.arid); assert.ok(ps.length >= 1 && ps.every((p) => p === ppid1), j(ps));
    assert.equal((await accounts()).length, 1);
    await rpPage.close();
  });
  // 2026-11-24(사용자 결정): 속성이 비어 있으면 속성을 요구하는 서비스(zkTWO — 국가 KR·JP)만 막는다 — Google 로 가기 전에 멈추고 속성 도구로 안내한다
  await t('zkTWO(속성 조건 있음): 속성 커밋먼트가 없으면 Google 로 가기 전에 멈추고 속성 도구로 안내한다(패스키도 묻지 않는다)', async () => {
    const g0 = A.hits.get;
    const { rpPage, popup, visited } = await startLogin(A.ctx, rp2);
    await popup.waitForSelector('#authHint a', { timeout: 30_000 });
    assert.equal(await popup.$eval('#authHint a', (a) => a.href), `${new URL(wallet.base).origin}/attr.html`);
    await waitText(rpPage, '#verdict', '속성 커밋먼트', 30_000);
    assert.ok(!went(visited, google.authorizeUrl), `Google 로 갔다: ${j(visited.map((u) => u.slice(0, 70)))}`);
    assert.equal(A.hits.get, g0, `패스키를 물었다: ${j(A.hits)}`);
    await popup.close().catch(() => {}); await rpPage.close();
  });
  await t('zkTWO 로그인(속성 도구 기록을 넣은 뒤): PPID 가 zkONE 과 다르고 조건 증명이 통과한다', async () => {
    // 속성 도구의 기록(version 6 — salt 없이 이 패스키의 auid 와 속성) — 데모 리셋 표시는 본 것으로 맞춰 둔다(readAttrRecord 가 지우지 않게)
    const reg = (await idbDump(userPage)).registration;
    await userPage.evaluate(async (r) => {
      try { const x = await fetch('/attr/dist/reset.json', { cache: 'no-store' }); if (x.ok) localStorage.setItem('mode3_attr_tool_reset', String((await x.json()).epoch ?? '')); } catch { /* 없으면 그대로 */ }
      localStorage.setItem('mode3_attr_tool_v1', JSON.stringify(r));
    }, { version: 6, auid: String(reg.auid), profile: { birthYear: '1990', country: 'KR' } });
    google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
    const { rpPage } = await startLogin(A.ctx, rp2);
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    // 2026-11-24(구조 점검 3번): 속성은 사용자가 스스로 넣은 값이다 — 서비스 화면이 그것을 확인된 사실처럼 말하지 않는다
    await waitText(rpPage, '#loginProof', '보증하지 않습니다', 15_000);
    assert.ok((await text(rpPage, '#loginPolicy')).includes('스스로 넣은'), await text(rpPage, '#loginPolicy'));
    const s2 = (await rp2.get('/api/mode3/sessions')).body.sessions; assert.ok(s2.length >= 1 && s2[0].disclosure?.set, `zkTWO 세션에 공개 집합이 없다: ${j(s2)}`);
    const p2 = ppidOf(noteSessions(await idbDump(userPage)), info2.arid)[0]; assert.ok(p2); assert.notEqual(p2, ppid1);
    // 2026-11-23(사용자 요청): 로그인 직후부터 "내 계정 주소" 는 0x 스마트 계정 주소다 — 잔액 조회 전에도. 그전에는 web 방식에서 잔액을 자동으로 읽지 않아 PPID 10진수로 남았다.
    ppid2 = p2; acct2 = await accountAddr(info2.factoryAddress, p2);
    await rpPage.waitForFunction(() => /^0x/.test(document.getElementById('accountPPID')?.title ?? ''), null, { timeout: 10_000 }).catch(() => {});
    const shown = await rpPage.$eval('#accountPPID', (e) => e.title);
    assert.equal(shown.toLowerCase(), acct2.toLowerCase(), `zkTWO 의 내 계정 주소가 스마트 계정 주소가 아니다: ${shown.slice(0, 24)}`);
    await rpPage.close();
  });
  await t('zk 클라이언트 세션 카드: "PPID" 줄은 PPID 숫자, "PPID 스마트 계정 주소" 줄은 서비스 화면과 같은 0x 주소(2026-11-23)', async () => {
    await openUser(userPage);
    await userPage.waitForFunction((pp) => [...document.querySelectorAll('#sessionActions dd code')].some((e) => e.title === pp), ppid2, { timeout: 15_000 });
    const cards = await userPage.$$eval('#sessionActions dl', (dls) => dls.map((dl) => Object.fromEntries([...dl.querySelectorAll('dt')].map((dt) => [dt.textContent.trim(), dt.nextElementSibling.querySelector('code')?.title ?? dt.nextElementSibling.textContent.trim()]))));
    const c2 = cards.find((o) => o.PPID === ppid2);
    assert.ok(c2, `PPID 줄이 PPID 값을 보이지 않는다: ${j(cards.map((o) => Object.keys(o)))}`);
    assert.equal(String(c2['PPID 스마트 계정 주소'] ?? '').toLowerCase(), acct2.toLowerCase(), j(c2));
    // 2026-11-24(화면 점검 3번): 세션마다 테두리 상자, 맨 위에 서비스 이름, 만료는 "블록 N까지 · M블록 남음", 버튼은 "이 세션 끝내기"
    const box = await userPage.evaluate((pp) => {
      const b = [...document.querySelectorAll('#sessionActions > div')].find((x) => [...x.querySelectorAll('dd code')].some((e) => e.title === pp));
      const dts = [...b.querySelectorAll('dt')]; const exp = dts.find((d) => d.textContent.trim() === '만료');
      return { cls: b.className, head: b.querySelector('.session-head')?.textContent.trim() ?? '', rows: dts.map((d) => d.textContent.trim()), exp: exp?.nextElementSibling.textContent.trim() ?? '', btn: b.querySelector('button.danger')?.textContent.trim() ?? '' };
    }, ppid2);
    assert.match(box.cls, /\bsession-box\b/, j(box));
    assert.ok(box.head.startsWith('zkTWO'), j(box));
    assert.ok(!box.rows.includes('서비스'), j(box));
    assert.match(box.exp, /^블록 \d+까지 · \d+블록 남음$/, j(box));
    assert.equal(box.btn, '이 세션 끝내기', j(box));
  });
  await t('관리자 화면: zkWrapper 의 긴 uid 는 앞자리만 보이고(전체는 title) 표가 화면 밖으로 넘치지 않는다(2026-11-23)', async () => {
    assert.ok(UID_A.length > 40, `대역 Google 계정의 uid 가 짧다: ${UID_A.length}`);
    const c = (await wallet.get('/user/config')).body;
    const p = await A.ctx.newPage(); await p.goto(`${c.ciaUrl}/admin`);
    await p.fill('#adminGate .gate-pwd', cia.adminSecret); await p.click('#adminGate .gate-form button[type=submit]');
    await p.waitForFunction((head) => [...document.querySelectorAll('td')].some((td) => td.textContent.includes(head)), UID_A.slice(0, 12), { timeout: 15_000 });
    const cells = await p.$$eval('td', (tds, head) => tds.filter((td) => td.textContent.includes(head)).map((td) => ({ text: td.textContent.trim(), title: td.querySelector('code')?.title ?? null })), UID_A.slice(0, 12));
    assert.ok(cells.length >= 1);
    for (const x of cells) assert.ok(x.text.length <= 14 && x.title === UID_A, `uid 칸: ${j({ len: x.text.length, title: x.title?.slice(0, 16) ?? null })}`);
    const over = await p.evaluate(() => [...document.querySelectorAll('table')].filter((tb) => tb.offsetParent !== null && tb.scrollWidth > tb.parentElement.clientWidth + 1).map((tb) => `${tb.scrollWidth}>${tb.parentElement.clientWidth}`));
    assert.deepEqual(over, []);
    await p.close();
  });
  // 2026-11-23(사용자 요청): "출금 출처" 선택칸을 없앴다 — 출처는 세션 종류로 정한다(zk 로그인 = 내 계정, 소셜 로그인 = 거래소 보관).
  await t('서비스 화면에 "출금 출처" 선택칸이 없다', async () => {
    const page = await openRp(A.ctx, rp);
    assert.equal(await page.$$eval('#txSource', (l) => l.length), 0); assert.ok(!(await visibleText(page)).includes('출금 출처'));
    await page.close();
  });
  // 2026-11-23(사용자 요청, 시연 2차): root 가 바뀐 경우만 보인다 — ① 지금의 root·nonce 로 증명을 만들어 두고(보내지 않는다) ② root 가 바뀐 뒤 그 증명에
  // 지금 root 만 붙여 보낸다. nonce 는 ① 때 그대로라 nonce 검사는 통과하고 계정 컨트랙트의 증명 검증(InvalidProof)에서만 되돌려진다.
  // ① 뒤에 nonce 가 바뀌었으면(그사이 출금) 보내기 전에 거절한다 — nonce 검사 장면은 다음 버전에서 따로 보인다.
  let replayPage = null;
  // 승인 창은 앞 요청의 창을 다시 쓸 수 있다(새 창 이벤트가 없을 수 있다) — 누르기만 하고 결과는 #txVerdict 로 본다.
  const clickTx = async (page, sel) => { await page.click(sel); };
  await t('옛 증명 시연: ① 없이 ② 를 누르면 지금 nonce 로 만들어 둔 증명이 없어 보내지 않는다(블록 그대로)', async () => {
    google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
    const { rpPage } = await startLogin(A.ctx, rp);
    replayPage = rpPage;
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    await rpPage.waitForSelector('#txHoldBtn:not([hidden])', { timeout: 10_000 }); await rpPage.waitForSelector('#txReplayBtn:not([hidden])');
    const h0 = await chainRead.getBlockNumber();
    await clickTx(rpPage, '#txReplayBtn');
    await waitText(rpPage, '#txVerdict', '만들어 둔 증명이 없습니다', 120_000);
    assert.equal(await chainRead.getBlockNumber(), h0, '거절했는데 블록이 늘었다'); assert.equal(await rpPage.$eval('#txHashRow', (e) => e.hidden), true);
  });
  await t('옛 증명 시연 ①: 증명만 만들어 두고 거래는 보내지 않는다 — root 가 그대로면 ② 는 거절(블록 그대로)', async () => {
    const h0 = await chainRead.getBlockNumber(), g0 = A.hits.get;
    await clickTx(replayPage, '#txHoldBtn');
    await waitText(replayPage, '#txVerdict', '증명을 만들어 두었습니다', 120_000);
    // 2026-11-23(화면 점검): root 바꾸는 길은 홈의 "세션 끝내기" → 게시다 — 옛 안내("관리자 화면에서 폐기·게시")를 쓰지 않는다
    assert.ok((await text(replayPage, '#txVerdict')).includes('내 세션 관리'), await text(replayPage, '#txVerdict'));
    assert.equal(await chainRead.getBlockNumber(), h0, '① 이 거래를 보냈다'); assert.equal(A.hits.get - g0, 1, `패스키는 한 번: ${j(A.hits)}`);
    await clickTx(replayPage, '#txReplayBtn');
    await waitText(replayPage, '#txVerdict', 'root 가 아직 바뀌지 않았습니다', 120_000);
    assert.ok((await text(replayPage, '#txVerdict')).includes('내 세션 관리'), await text(replayPage, '#txVerdict'));
    assert.equal(await chainRead.getBlockNumber(), h0, '거절했는데 블록이 늘었다');
  });
  // 2026-11-23(사용자 요청): zkWrapper 의 관리자 화면에는 폐기할 곳이 없었다(계정 카드는 11-11 에 숨겼다) — zkWrapper 일 때만 계정 카드를 다시 보인다.
  await t('관리자 화면(zkWrapper): 계정 카드·메뉴가 보이고, 세션 표의 "폐기" → 게시로 root 가 바뀐다', async () => {
    const root0 = (await cia.get('/mode3/health')).body.root;
    const c = (await wallet.get('/user/config')).body;
    const p = await A.ctx.newPage(); await p.goto(`${c.ciaUrl}/admin`);
    await p.fill('#adminGate .gate-pwd', cia.adminSecret); await p.click('#adminGate .gate-form button[type=submit]');
    await p.waitForFunction(() => document.getElementById('secAccounts')?.offsetParent !== null, null, { timeout: 15_000 });
    assert.equal(await p.$$eval('.section-menu a[href="#secAccounts"]', (l) => l.length), 1, '메뉴에 계정 항목이 없다');
    await p.waitForFunction((head) => [...document.querySelectorAll('#accounts tr')].some((tr) => tr.textContent.includes(head)), UID_A.slice(0, 12), { timeout: 15_000 });
    await p.evaluate((head) => [...document.querySelectorAll('#accounts tr')].find((tr) => tr.textContent.includes(head)).querySelector('button').click(), UID_A.slice(0, 12));
    await p.waitForFunction(() => [...document.querySelectorAll('#accounts button')].some((b) => b.textContent.trim() === '폐기'), null, { timeout: 15_000 })
      .catch(async () => { throw new Error(`세션 폐기 버튼이 없다: ${(await text(p, '#accounts')).replace(/\s+/g, ' ').slice(0, 400)}`); });
    // 가장 먼저 발급된(첫 로그인) 세션을 폐기한다 — 지금 시연 중인 zkONE 세션은 남긴다. bound 는 기본값 0 그대로.
    await p.evaluate(() => { window.prompt = (_m, d) => d; [...document.querySelectorAll('#accounts button')].find((b) => b.textContent.trim() === '폐기').click(); });
    await waitText(p, '#adminVerdict', '폐기', 15_000);
    await p.click('#publishBtn');
    await p.waitForFunction(() => (document.getElementById('publishVerdict')?.textContent ?? '').length > 0, null, { timeout: 30_000 });
    const root1 = (await cia.get('/mode3/health')).body.root;
    assert.notEqual(root1, root0, '게시했는데 root 가 그대로다');
    await p.close();
  });
  await t('옛 증명 시연 ②(root 가 바뀐 뒤): 거래는 블록에 실리고 InvalidProof — nonce 는 ① 때 그대로, root 두 줄은 서로 다르다', async () => {
    const g0 = A.hits.get;
    await clickTx(replayPage, '#txReplayBtn');
    await waitText(replayPage, '#txVerdict', '증명 검증', 120_000);
    const v = await text(replayPage, '#txVerdict'); assert.ok(v.includes('InvalidProof'), v.slice(0, 200));
    const hash = await replayPage.$eval('#txHashCode', (e) => e.title); assert.match(hash, /^0x[0-9a-f]{64}$/);
    replayHash = hash;
    const rc = await chainRead.getTransactionReceipt(hash); assert.ok(rc, '거래가 블록에 없다'); assert.equal(rc.status, 0, '되돌려져야 한다');
    const addr = await accountAddr(info1.factoryAddress, ppid1);
    assert.equal(rc.to.toLowerCase(), addr.toLowerCase(), '내 계정으로 간 거래가 아니다');
    const args = walletInterface.decodeFunctionData('execute', (await chainRead.getTransaction(hash)).data);
    const nonceNow = await new ethers.Contract(addr, ['function nonce() view returns (uint256)'], chainRead).nonce();
    assert.equal(BigInt(args[5][28]), nonceNow, '증명의 counter 가 지금 nonce 와 다르다(nonce 때문에 실패하면 안 된다)');
    assert.equal(BigInt(args[0].nonce), nonceNow);
    assert.equal(await replayPage.$eval('#raceRoots', (e) => e.hidden), false, 'root 두 줄이 없다');
    const built = await text(replayPage, '#raceRootBuilt'), now = await text(replayPage, '#raceRootNow');
    assert.ok(built.length > 10 && now.length > 10); assert.notEqual(built, now, 'root 가 바뀌지 않은 것으로 보인다');
    assert.equal(A.hits.get - g0, 1, `패스키는 한 번: ${j(A.hits)}`);
  });
  await t('옛 증명 시연: ① 뒤 일반 출금으로 nonce 가 바뀌면 ② 는 보내지 않는다(블록 그대로)', async () => {
    await clickTx(replayPage, '#txHoldBtn');
    await waitText(replayPage, '#txVerdict', '증명을 만들어 두었습니다', 120_000);
    await replayPage.fill('#txValue', '0');
    await clickTx(replayPage, '#txBtn');
    await waitText(replayPage, '#txVerdict', '보냈습니다', 120_000);
    const h0 = await chainRead.getBlockNumber();
    await clickTx(replayPage, '#txReplayBtn');
    await waitText(replayPage, '#txVerdict', '만들어 둔 증명이 없습니다', 120_000);
    assert.equal(await chainRead.getBlockNumber(), h0, '거절했는데 블록이 늘었다');
    await replayPage.close();
  });
  await t('옛 증명 시연 경로는 이 서비스에 로그인해 있는 세션의 거래만 보낸다 — r_s 를 바꾼 호출 데이터는 블록 없이 403(2026-11-23 리뷰)', async () => {
    assert.ok(replayHash, '앞 사례의 거래가 없다');
    const tx = await chainRead.getTransaction(replayHash);
    const args = walletInterface.decodeFunctionData('execute', tx.data);
    const pub = [...args[5]]; pub[27] = 123456789n;
    const data = walletInterface.encodeFunctionData('execute', [args[0], args[1], args[2], args[3], args[4], pub]);
    const h0 = await chainRead.getBlockNumber();
    const r = await rp.post('/api/mode3/relay', { to: tx.to, data, demo: 'replay_old_proof' });
    assert.equal(r.status, 403, j(r)); assert.equal(r.body?.reason, 'relay_demo_no_session');
    assert.equal(await chainRead.getBlockNumber(), h0, '거절했는데 블록이 늘었다');
  });
  await t('옛 증명으로 보내기는 서비스가 켜 둔 때만(MODE3_RELAY_DEMO_REVERT=1) — 꺼진 zkTWO 는 버튼이 없고 릴레이가 거절한다', async () => {
    const r = await rp2.post('/api/mode3/relay', { to: '0x' + '11'.repeat(20), data: '0x', demo: 'replay_old_proof' });
    assert.equal(r.status, 403, j(r)); assert.equal(r.body?.reason, 'relay_demo_off');
    // openRp 는 로그인돼 있으면 로그아웃한다 — 뒤 사례(홈의 세션 안내)가 쓰는 zkTWO 세션을 남기려고 페이지만 연다
    const page = await A.ctx.newPage(); await page.goto(`${rp2.base}/`);
    await page.waitForFunction(() => { const b = document.getElementById('logoutBtn'); return b && b.offsetParent !== null; }, null, { timeout: 15_000 });
    await page.waitForTimeout(1000);
    assert.equal(await page.$eval('#txReplayBtn', (b) => b.hidden), true, '로그인 중인 zkTWO 에 버튼이 보인다');
    await page.close();
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
  // ---- Task 6: 홈페이지·화면 문구 ----
  await t('홈: 사용자용 세 단계·운영자용 세 단계·전체 플로우 링크가 있고, 링크가 맞다', async () => {
    const page = await A.ctx.newPage(); await page.goto(`${wallet.base}/`); await page.waitForSelector('#homeGuide:not([hidden])', { timeout: 15_000 });
    const c = (await wallet.get('/user/config')).body;
    assert.equal(await page.$$eval('#homeUserSteps li', (l) => l.length), 3); assert.equal(await page.$$eval('#homeOpSteps li', (l) => l.length), 3);
    const hrefs = await page.$$eval('#homeGuide a', (as) => as.map((a) => a.href));
    for (const want of [`${new URL(wallet.base).origin}/common/flow.html`, `${c.ciaUrl}/rp`, `${c.ciaUrl}/admin`]) assert.ok(hrefs.includes(want), `${want} 링크가 없다: ${j(hrefs)}`);
    for (const h of hrefs) { const r = await fetch(h); assert.equal(r.status, 200, `${h} → ${r.status}`); }
    assert.ok((await text(page, '#homeGuide')).includes('Google'), '사용자 단계에 Google 이 없다');
    // 2026-11-24(사용자 요청): 홈에는 "zk-Delegation 쓰는 법" 만 — 세션 관리는 /user(링크가 있다)
    assert.ok(hrefs.includes(`${new URL(wallet.base).origin}/user`), `/user 링크가 없다: ${j(hrefs)}`);
    // 스펙 home-and-account-recovery 1.2a — H2: 사용자 1단계 뒤에 서비스 링크(설정의 rpServices — 승인된 서비스의 이름·주소), H5: 탭 제목
    const svc = await page.$$eval('#homeSvcLinks a', (as) => as.map((a) => ({ name: a.textContent.trim(), href: a.href })));
    assert.deepEqual(svc.map((x) => x.name).sort(), [info1.name, info2.name].sort(), j(svc));
    assert.deepEqual(svc.map((x) => new URL(x.href).origin).sort(), [new URL(rp.base).origin, new URL(rp2.base).origin].sort(), j(svc));
    assert.equal(await page.title(), 'zkWrapper 홈');
    await page.waitForTimeout(1500);
    const shown = await page.evaluate(() => [...document.querySelectorAll('#mainView > section')].filter((e) => e.checkVisibility()).map((e) => e.id));
    assert.deepEqual(shown, ['homeGuide'], j(shown));
    await page.close();
  });
  await t('/user: 처음에는 잠겨 있고 패스키로 연다 — 새로고침은 열린 채, 잠그기·10분 동안 아무 동작이 없으면 다시 잠긴다', async () => {
    const page = await A.ctx.newPage(); await page.goto(`${wallet.base}/user`);
    await page.waitForSelector('#userLockCard', { state: 'visible', timeout: 15_000 });
    const shown = () => page.evaluate(() => [...document.querySelectorAll('#mainView > section')].filter((e) => e.checkVisibility()).map((e) => e.id));
    assert.deepEqual(await shown(), ['userLockCard'], '잠긴 화면에 다른 카드가 보인다');
    const g0 = A.hits.get; await page.click('#userUnlockBtn');
    await page.waitForSelector('#sessionsCard', { state: 'visible', timeout: 15_000 }); assert.equal(A.hits.get - g0, 1, j(A.hits));
    { const s = await shown(); assert.ok(!s.includes('userLockCard') && !s.includes('homeGuide') && s.includes('identityCard') && s.includes('userBar'), j(s));
      assert.ok(!s.includes('demoCard'), `시연 카드는 ?demo=1 일 때만: ${j(s)}`); }   // H3
    assert.equal(await page.title(), 'zkWrapper — 내 세션 관리');   // H5
    assert.equal(await page.evaluate(() => document.getElementById('attr4')?.checkVisibility() === true || document.getElementById('attr5')?.checkVisibility() === true), false, '"미사용" 칸이 보인다');   // H4
    await page.reload(); await page.waitForSelector('#sessionsCard', { state: 'visible', timeout: 15_000 }); assert.equal(A.hits.get - g0, 1, '새로고침에 패스키를 다시 물었다');
    await page.goto(`${wallet.base}/user?demo=1`); await page.waitForSelector('#demoCard', { state: 'visible', timeout: 15_000 });   // H3: ?demo=1 이면 시연 카드
    await page.click('#userLockBtn'); await page.waitForSelector('#userLockCard', { state: 'visible', timeout: 5_000 }); assert.deepEqual(await shown(), ['userLockCard']);
    await page.click('#userUnlockBtn'); await page.waitForSelector('#sessionsCard', { state: 'visible', timeout: 15_000 });
    await page.evaluate(() => sessionStorage.setItem('mode3_user_unlock_until', String(Date.now() - 1)));   // 10분이 지난 것처럼
    await page.waitForSelector('#userLockCard', { state: 'visible', timeout: 5_000 }); assert.deepEqual(await shown(), ['userLockCard']);
    await page.close();
  });
  await t('래퍼 방식의 화면 어디에도 "zkIdP"·"인증 창"·"π_IdP"·"비밀번호" 가 없다(홈·승인 창·서비스·운영자·관리자·전체 플로우)', async () => {
    const c = (await wallet.get('/user/config')).body; const hits = [];
    assert.ok(Array.isArray(popupBanned), '승인 창의 글자를 모으지 못했다'); for (const h of popupBanned) hits.push(`승인 창 ${h}`);
    for (const [name, url] of [['홈', `${wallet.base}/`], ['내 세션 관리', `${wallet.base}/user`], ['서비스', `${rp.base}/`], ['zkTWO', `${rp2.base}/`], ['운영자', `${c.ciaUrl}/rp`], ['관리자', `${c.ciaUrl}/admin`], ['전체 플로우', `${wallet.base}/common/flow.html`]]) {
      const page = await A.ctx.newPage(); await page.goto(url); await page.waitForLoadState('networkidle').catch(() => {}); await page.waitForTimeout(800);
      // 화면의 래퍼 표기는 서버 상태(/mode3/health 의 wrapper)를 읽은 뒤 켜진다 — 그 표시가 붙을 때까지 기다린다(서비스 페이지는 자기 서버의 상태를 읽으므로 붙지 않는다)
      if (name !== '서비스' && name !== 'zkTWO') await page.waitForFunction(() => document.documentElement.dataset.wrapper === '1', null, { timeout: 15_000 }).catch(() => {});
      for (const h of bannedIn(await visibleText(page), name === '운영자' || name === '관리자' ? BANNED_STAFF : BANNED)) hits.push(`${name} ${h}`);
      if (name === '운영자' || name === '관리자') {
        const nav = await page.evaluate(() => ({ url: location.href, wr: document.documentElement.dataset.wrapper ?? null, user: [...document.querySelectorAll('.idp-nav a[href="/user"]')].map((a) => getComputedStyle(a).display) }));
        if (nav.user.some((d) => d !== 'none')) hits.push(`${name} 상단 바에 /user 링크가 보인다 ${JSON.stringify(nav)}`);
      }
      await page.close();
    }
    assert.deepEqual(hits, []);
  });
  // 2026-11-23(사용자 요청, C): 세션 끝내기는 Google 확인(1회용 요청 키에 묶인 토큰 + 그 키의 서명)으로 동작한다 — 세션마다 버튼이 있다.
  // 계정 자기 폐기(π_IdP·비밀번호를 쓴다)는 여전히 없고 안내만 있다(최종 검토 I-1).
  // 2026-11-24(스펙 home-and-account-recovery 2부): 비밀번호를 묻는 옛 "계정 자기 폐기" 버튼은 없고, 그 자리에 Google 확인으로 하는 "내 계정 폐기" 가 있다
  await t('래퍼 방식의 /user: 세션마다 "이 세션 끝내기" 버튼이 있고, 비밀번호를 묻는 옛 계정 폐기 버튼 대신 "내 계정 폐기" 가 있다', async () => {
    const page = await openUser(await A.ctx.newPage());
    await page.waitForFunction(() => document.querySelectorAll('#sessionActions button.danger').length > 0, null, { timeout: 15_000 }).catch(() => {});
    const st = await page.evaluate(() => ({ cards: document.querySelectorAll('#sessionActions dl').length,
      endBtns: [...document.querySelectorAll('#sessionActions button')].filter((b) => b.offsetParent !== null && /세션 끝내기/.test(b.textContent)).length,
      selfRevoke: document.getElementById('selfRevokeBtn')?.offsetParent !== null, notes: document.getElementById('wrapRevokeAccountBtn')?.checkVisibility() === true ? 1 : 0,
      sessionNotes: [...document.querySelectorAll('#sessionActions .wrap-revoke-note')].filter((e) => e.offsetParent !== null).length }));
    assert.ok(st.cards >= 1, '세션이 그려지지 않았다: ' + j(st));
    assert.equal(st.endBtns, st.cards, j(st)); assert.equal(st.sessionNotes, 0, j(st));
    assert.equal(st.selfRevoke, false, j(st)); assert.ok(st.notes >= 1, j(st));
    await page.close();
  });
  // 2026-11-24(화면 점검 5번): 홈이 길다 — 영지식 증명 표·시연 버튼·공개할 속성 조건은 처음에 접어 두고, 편 상태만 이 브라우저에 기억한다.
  await t('래퍼 방식의 홈: 영지식 증명 표·시연 버튼·공개할 속성 조건은 처음에 접혀 있고, 편 상태는 새로고침해도 남는다', async () => {
    const KEYS = ['mode3_proofs_open', 'mode3_demo_open', 'mode3_disclose_open'];
    const page = await openUser(await A.ctx.newPage(), '?demo=1');
    await page.evaluate((ks) => { for (const k of ks) localStorage.removeItem(k); }, KEYS);
    await page.reload(); await page.waitForSelector('#sessionsCard', { state: 'visible', timeout: 15_000 });
    await page.waitForFunction(() => /\d+개/.test(document.querySelector('#proofsFold > summary')?.textContent ?? ''), null, { timeout: 15_000 });
    const st = await page.evaluate(() => { const vis = (id) => document.getElementById(id)?.checkVisibility() === true;   // 닫힌 <details> 안도 offsetParent 는 있다(Chrome) — checkVisibility 로 본다
      return { proofs: document.getElementById('proofsFold').open, demo: document.getElementById('demoFold').open, disc: document.getElementById('discloseBox').open,
        list: vis('proofsList'), fake: vis('demoFakeProofBtn'), lo: vis('discLo0') }; });
    assert.deepEqual(st, { proofs: false, demo: false, disc: false, list: false, fake: false, lo: false }, j(st));
    await page.click('#proofsFold > summary'); await page.click('#demoFold > summary');
    // toggle 이벤트는 비동기라 클릭 직후 새로고침하면 저장 전일 수 있다 — 기억된 뒤에 새로고침한다
    await page.waitForFunction(() => localStorage.getItem('mode3_proofs_open') === '1' && localStorage.getItem('mode3_demo_open') === '1', null, { timeout: 5_000 });
    await page.reload(); await page.waitForSelector('#sessionsCard', { state: 'visible', timeout: 15_000 });
    await page.waitForFunction(() => document.getElementById('demoFakeProofBtn')?.checkVisibility() === true && document.querySelector('#proofsList .proof-view')?.checkVisibility() === true, null, { timeout: 15_000 })
      .catch(async (e) => { const d = await page.evaluate(() => ({ proofs: document.getElementById('proofsFold')?.open, demo: document.getElementById('demoFold')?.open, ls: [localStorage.getItem('mode3_proofs_open'), localStorage.getItem('mode3_demo_open')], sum: document.querySelector('#proofsFold > summary')?.textContent, list: document.getElementById('proofsList')?.textContent.slice(0, 80) })); throw new Error(`${e.message} ${j(d)}`); });
    await page.evaluate((ks) => { for (const k of ks) localStorage.removeItem(k); }, KEYS);
    await page.close();
  });
  // 홈의 "이 세션 끝내기(폐기)" — 이 탭이 Google 을 다녀와(패스키는 묻지 않는다) 그 세션 하나만 폐기를 요청한다. 옛 증명 시연의 root 바꾸기도 이 길로 한다:
  // zkONE ① → 홈에서 zkTWO 세션 끝내기 → 게시 → zkONE ② = InvalidProof.
  const adminSessions = async () => (await cia.adminGet(`/cia/admin/sessions?uid=${UID_A}`)).body.sessions;
  const endSessionOnHome = async (page, arid) => {
    await openUser(page);
    const d = await idbDump(page);
    const [r_s, s] = Object.entries(d.sessions ?? {}).find(([, v]) => String(v.arid) === String(arid)) ?? [];
    assert.ok(r_s, `홈에 그 서비스의 세션이 없다: ${j(Object.values(d.sessions ?? {}).map((v) => v.arid))}`);
    await page.waitForFunction((pp) => [...document.querySelectorAll('#sessionActions dd code')].some((e) => e.title === pp), s.PPID, { timeout: 15_000 });
    await page.evaluate((pp) => { const box = [...document.querySelectorAll('#sessionActions > div')].find((b) => [...b.querySelectorAll('dd code')].some((e) => e.title === pp)); [...box.querySelectorAll('button')].find((b) => /세션 끝내기/.test(b.textContent)).click(); }, s.PPID);
    return { r_s, Cf_s: String(s.credential.Cf_s) };
  };
  await t('홈의 세션 끝내기: 다른 Google 계정으로 돌아오면 폐기되지 않는다(세션은 그대로)', async () => {
    const page = await A.ctx.newPage();
    google.setNextSub('google-user-B'); google.setNextClaims({ email: 'other@example.com', email_verified: true });
    const { Cf_s } = await endSessionOnHome(page, info2.arid);
    await page.waitForURL((u) => u.origin === new URL(wallet.base).origin && u.pathname === '/user' && !u.search.includes('authorize'), { timeout: 60_000 });
    await waitText(page, '#sessionVerdict', '실패', 30_000);
    const rec = (await adminSessions()).find((x) => x.Cf_s === Cf_s); assert.ok(rec, '서버에 그 세션이 없다'); assert.equal(rec.revokedAt, null, '다른 계정으로 폐기됐다');
    assert.ok(Object.values((await idbDump(page)).sessions ?? {}).some((v) => String(v.arid) === String(info2.arid)), '실패했는데 지갑에서 세션이 지워졌다');
    await page.close();
  });
  await t('홈의 세션 끝내기 → 게시 → 옛 증명 시연 ② 는 InvalidProof: 그 세션 하나만 폐기되고, 패스키는 묻지 않는다', async () => {
    // 앞 사례들(openRp)이 zkONE 에서 로그아웃했다 — 다시 로그인한다
    google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
    const { rpPage } = await startLogin(A.ctx, rp);
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    await rpPage.waitForSelector('#txHoldBtn:not([hidden])', { timeout: 15_000 });
    await rpPage.click('#txHoldBtn'); await waitText(rpPage, '#txVerdict', '증명을 만들어 두었습니다', 120_000);
    const before = await adminSessions(), root0 = (await cia.get('/mode3/health')).body.root;
    const page = await openUser(await A.ctx.newPage()), g0 = A.hits.get;   // /user 를 여는 패스키 한 번은 세지 않는다
    google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
    const { Cf_s } = await endSessionOnHome(page, info2.arid);
    await page.waitForURL((u) => u.origin === new URL(wallet.base).origin && u.pathname === '/user' && !u.search.includes('authorize'), { timeout: 60_000 });
    // 2026-11-23(화면 점검): 확인 창은 어느 서비스를 끝내는지 말하고, 결과는 서비스 이름으로 말한다 — H(C_s)·관리자 화면은 사용자 문구에 없다
    assert.ok(A.dialogs.at(-1)?.includes('zkTWO'), `확인 창: ${A.dialogs.at(-1)}`);
    await waitText(page, '#sessionVerdict', 'zkTWO 세션을 끝냈습니다', 30_000);
    { const v = await text(page, '#sessionVerdict'); assert.ok(!v.includes('H(C_s)') && !v.includes('관리자'), v); }
    assert.equal(A.hits.get - g0, 0, `패스키를 물었다: ${j(A.hits)}`);
    const after = await adminSessions();
    assert.ok(after.find((x) => x.Cf_s === Cf_s)?.revokedAt, '그 세션이 폐기되지 않았다');
    const newlyRevoked = after.filter((x) => x.revokedAt && !before.find((y) => y.Cf_s === x.Cf_s)?.revokedAt).map((x) => x.Cf_s);
    assert.deepEqual(newlyRevoked, [Cf_s], '다른 세션까지 폐기됐다');
    assert.ok(!Object.values((await idbDump(page)).sessions ?? {}).some((v) => String(v.arid) === String(info2.arid)), '지갑에 폐기한 세션이 남았다');
    // 2026-11-24(구조 점검 4번): 세션 끝내기는 바로 게시된다 — 관리자 게시 없이 root 가 바뀌었고, 결과 문구도 "바로" 라고 말한다
    assert.notEqual((await cia.get('/mode3/health')).body.root, root0, '세션을 끝냈는데 root 가 바로 바뀌지 않았다');
    assert.ok((await text(page, '#sessionVerdict')).includes('바로'), await text(page, '#sessionVerdict'));
    await rpPage.click('#txReplayBtn');
    await waitText(rpPage, '#txVerdict', '증명 검증', 120_000);
    assert.ok((await text(rpPage, '#txVerdict')).includes('InvalidProof'));
    // 2026-11-23(화면 점검): 끝낸 서비스(zkTWO)를 다시 열면 말없이 로그아웃 화면이 아니라 "세션이 끝났다" 를 말한다
    const p2 = await A.ctx.newPage(); await p2.goto(`${rp2.base}/`);
    await waitText(p2, '#verdict', '세션이 끝났습니다', 15_000);
    assert.ok(await p2.$eval('#loginBtn', (b) => !b.hidden), 'zkTWO 가 아직 로그인 상태다');
    assert.ok(await p2.$eval('#sessionBar', (b) => !b.hidden), '상단 바가 없다');
    await p2.close();
    await page.close(); await rpPage.close();
  });
  // 2026-11-24(스펙 home-and-account-recovery T1, §6 Q1): 누구에게 로그인하는지 밝히는 이름 — "Google 로 로그인" 처럼
  await t('서비스의 로그인 버튼은 "zkWrapper 로 로그인" 이다', async () => {
    const page = await openRp(A.ctx, rp); await page.click('#loginBtn');
    assert.equal((await text(page, '#idpLoginBtn')).trim(), 'zkWrapper 로 로그인'); await page.close();
  });
  await t('전체 플로우 한 장: 아랫줄에 Google 이 있고 π_IdP 가 없다 — 실제 값이 채워진다', async () => {
    const page = await A.ctx.newPage(); const asked = []; page.on('request', (r) => asked.push(new URL(r.url()).pathname));
    await page.goto(`${wallet.base}/common/flow.html`);
    await page.waitForFunction(() => (document.getElementById('zkAuidS')?.textContent ?? '').length > 'auid_s'.length, null, { timeout: 15_000 });
    const seq = await page.$eval('#seqZk', (e) => e.textContent);
    assert.ok(seq.includes('Google'), seq.slice(0, 200)); assert.ok(!seq.includes('π_IdP'), 'π_IdP 가 남았다'); assert.ok(seq.includes('zkWrapper'), 'zkWrapper 가 없다');
    await page.click('#seqZk .st[data-step="3"]'); const det = await text(page, '#detailZk'); assert.ok(det.includes('Google') && !det.includes('π_IdP'), det);
    // 2026-11-24(flow.html 점검): 펴서 보는 설명(①~⑥)에도 zkIdP 가 없다 · ③ 에 커밋먼트·가명 시간 · ④ 이름은 그림과 설명이 같다 · uid 는 줄여서(전체는 title)
    // · ② 패스키는 사용자 대기(인증기 창)와 salt 계산을 나눠 보인다
    const dets = [];
    for (let k = 1; k <= 6; k++) { await page.click(`#seqZk .st[data-step="${k}"]`); dets.push(await text(page, '#detailZk')); }
    assert.deepEqual(dets.filter((d) => /zk-?IdP/.test(d)), [], 'zkIdP 가 남은 설명');
    assert.ok(dets[2].includes('커밋먼트 C_u · C_s 만들기') && dets[2].includes('가명 auid_s · arid_s 만들기'), dets[2]);
    assert.ok(dets[1].includes('사용자 대기') && dets[1].includes('salt 계산'), dets[1]);
    const lbl4 = await page.$eval('#seqZk .st[data-step="4"] .lbl', (e) => e.textContent.trim());
    assert.ok(lbl4.startsWith('④ 세션 토큰') && dets[3].startsWith('④ 세션 토큰'), `${lbl4} / ${dets[3].slice(0, 40)}`);
    // T1: 펼친 설명·그림·머리말 어디에도 옛 이름("zk 클라이언트"·"zk 로그인")이 없다 — 계산하는 주체는 "브라우저"
    { const all = `${dets.join(' ')} ${await visibleText(page)}`; assert.ok(!/zk 클라이언트|zk 로그인/.test(all), all.match(/.{0,30}(zk 클라이언트|zk 로그인).{0,30}/)?.[0]); }
    // 2026-11-25(사용자 지적): 세션 토큰에는 arid_s 가 있다 — "서비스 이름 없음" 이 아니라 가명으로만. 서명하는 여섯 값과 r_rp 를 아는 쪽
    // ③·④ 의 글자가 두 세로선(x 170~578) 사이에, ③ 은 초록 상자(186~564) 안에 들어간다
    const box = (k) => page.$eval(`#seqZk .st[data-step="${k}"] .lbl`, (e) => { const b = e.getBBox(); return [b.x, b.x + b.width]; });
    for (const [k, l, r] of [[3, 186, 564], [4, 170, 578]]) { const [a, b] = await box(k); assert.ok(a >= l && b <= r, `${k} 단계 글자 ${a.toFixed(1)}~${b.toFixed(1)} 가 ${l}~${r} 밖`); }
    assert.ok(lbl4.includes('(서비스는 가명 arid_s 로만)'), lbl4); assert.ok(!seq.includes('서비스 이름 없음') && !dets[3].includes('서비스 이름'), dets[3]);
    for (const w of ['auid_s · arid_s · Cf_u · Cf_s 와 chainid · allowAgent', 'Poseidon(arid, r_rp)', '서비스와 사용자의 브라우저만']) assert.ok(dets[3].includes(w), `없음: ${w} — ${dets[3]}`);
    const uid = await page.$eval('#zkUid', (e) => ({ t: e.textContent, title: e.title }));
    assert.ok(uid.t.length < 30 && uid.title.length > 40, j(uid));
    // 2026-11-25(사용자 요청): ③ Google 토큰 · ④ 세션 토큰을 누르면 그 로그인의 실제 본문이 보인다 — 서명은 없다. 다른 단계에는 토큰 표가 없다
    const flow = (await idbDump(page)).loginFlow, claims = () => page.$$eval('#detailZk table.tok code', (l) => Object.fromEntries(l.map((c) => [c.dataset.claim, c.textContent])));
    const open = async (k) => { if (await page.$eval('#detailZk', (d) => d.hidden) || !(await text(page, '#detailZk')).startsWith('①②③④⑤⑥'[k - 1])) await page.click(`#seqZk .st[data-step="${k}"]`); };
    await open(3); { const c = await claims(); assert.equal(c.sub, 'google-user-A'); assert.equal(c.email, 'jihoo@example.com'); assert.equal(c.aud, google.clientId); assert.equal(c.nonce, flow.values.tokens.google.payload.nonce); assert.equal(c.alg, 'RS256'); }
    await shot(page, 'flow_wallet_google_token');
    await open(4); { const c = await claims(); assert.equal(c.alg, 'ES256'); assert.equal(c.sub, flow.values.auid_s); assert.equal(c.aud, flow.values.arid_s); assert.equal(c.C_u, flow.values.Cf_u);
      const t4 = await text(page, '#detailZk'); for (const v of ['google-user-A', 'jihoo@example.com', UID_A]) assert.ok(!t4.includes(v), `세션 토큰 설명에 ${v}`); }
    await shot(page, 'flow_wallet_session_token');
    for (const k of [1, 2, 5, 6]) { await open(k); assert.equal(await page.$$eval('#detailZk table.tok', (l) => l.length), 0, `${k} 단계에 토큰 표`); }
    // 사실 맞추기: zkWrapper 는 sub·이메일을 받는다, "모른다" 는 로그인 때, 카드 링크는 /user
    const know = `${await text(page, '#kIdpWho')} ${await text(page, '#kIdpSvc')} ${await text(page, '#footOpen')}`;
    for (const s of ['sub 와 이메일', 'sub 의 해시', '로그인 때는', '온체인 거래']) assert.ok(know.includes(s), `없음: ${s} — ${know}`);
    assert.equal(await page.$eval('#flowCardLink', (a) => a.getAttribute('href')), '/user#flowCard');
    // 지갑 오리진은 서비스 API 를 부르지 않고, 서비스용 칸은 비어 있다
    assert.deepEqual(asked.filter((p) => p.startsWith('/api/')), []);
    assert.deepEqual(await page.evaluate(() => [document.getElementById('recentOidc').hidden, ...['oidcClientId', 'oidcSub', 'oidcAud'].map((id) => document.getElementById(id).textContent)]), [true, '', '', '']);
    await page.close();
    // 홈의 "로그인 전체 플로우" 카드도 패스키를 사용자 대기·salt 계산으로 나눠 적는다
    const home = await openUser(await A.ctx.newPage());
    await home.waitForFunction(() => (document.getElementById('flowSummary')?.textContent ?? '').includes('가장 최근'), null, { timeout: 15_000 });
    const fl = await home.evaluate(() => ({ sum: document.getElementById('flowSummary').textContent, fig: document.getElementById('flowFigure').textContent }));
    assert.ok(fl.sum.includes('사용자 대기') && fl.fig.includes('사용자 대기') && fl.fig.includes('salt 계산'), j({ sum: fl.sum, fig: fl.fig.slice(0, 300) }));
    await home.close();
  });

  // ---- Task 5: zkWrapper 서버가 보는 것(스펙 §5) — 한 서버 배치에서만 ----
  if (!SPLIT) {
    const WO = new URL(wallet.base).origin;
    const toWrapper = () => A.reqs.filter((r) => { try { return new URL(r.url).origin === WO; } catch { return false; } });
    await t('체인 읽기는 설정의 chainRpcUrl 로 간다 — zkWrapper 서버에는 /rpc 요청이 없다', async () => {
      const c = (await wallet.get('/user/config')).body; assert.equal(c.wrapper, true); assert.ok(/^http:\/\/127\.0\.0\.1:8545/.test(c.chainRpcUrl), c.chainRpcUrl);
      assert.ok(A.reqs.some((r) => r.from === WO && r.method === 'POST' && r.url.startsWith(c.chainRpcUrl) && r.body.includes('eth_')), '지갑 페이지가 체인 노드를 직접 부르지 않았다');
      assert.equal(toWrapper().filter((r) => new URL(r.url).pathname.startsWith('/rpc')).length, 0);
    });
    await t('로그인 여러 번 동안 zkWrapper 서버로 간 모든 요청의 주소·본문·머리말에 서비스의 arid·오리진·팩토리 주소·PPID·계정 주소가 없다', async () => {
      noteSessions(await idbDump(userPage)); const sess = [...seenSessions.values()];
      assert.ok(sess.length >= 3 && new Set(sess.map((x) => String(x.arid))).size === 2, `두 서비스의 세션이 모여 있어야 한다: ${sess.length}`);
      const secrets = new Set();
      for (const svc of [info1, info2]) for (const v of [svc.arid, svc.origin, svc.factoryAddress, svc.attrGateAddress]) if (v) secrets.add(String(v));
      for (const x of sess) for (const v of [x.PPID, x.account, x.sessionAddress]) if (v) secrets.add(String(v));
      const seen = toWrapper(); assert.ok(seen.some((r) => new URL(r.url).pathname === '/cia/issue'), '발급 요청이 기록되지 않았다');
      for (const r of seen) for (const v of secrets) {
        const hay = `${r.url}\n${r.body}\n${r.referer}\n${r.origin}`.toLowerCase();
        assert.ok(!hay.includes(v.toLowerCase()), `zkWrapper 로 간 요청에 서비스 쪽 값이 있다(${v.slice(0, 24)}…): ${r.method} ${r.url.slice(0, 90)}`);
      }
      assert.equal(seen.filter((r) => new URL(r.url).pathname === '/wallet/presence').length, 0, '존재 신호를 보내면 안 된다');
    });
    await t('서비스 페이지에서 zkWrapper 서버로 가는 것은 승인 창을 여는 것뿐이다(fetch 0건)', async () => {
      const rpOrigins = [new URL(rp.base).origin, new URL(rp2.base).origin];
      const bad = toWrapper().filter((r) => rpOrigins.includes(r.from) && !r.nav);
      assert.equal(bad.length, 0, j(bad.map((r) => `${r.from} → ${r.method} ${r.url}`)));
    });
    await t('Google 중계: 래퍼 전용 클라이언트 ID 로 받은 토큰은 서비스 페이지로 넘기지 않는다 — 다른 ID 의 토큰은 넘긴다', async () => {
      const state = `${Buffer.from(new URL(rp.base).origin).toString('base64url')}.abc`;
      const mine = await google.mint({ sub: 'google-user-A', nonce: 'wrap:' + 'cd'.repeat(32) });
      const page = await A.ctx.newPage();
      await page.goto(`${wallet.base}/google-relay#state=${state}&id_token=${mine}`);
      await waitText(page, '#msg', '넘길 수 없습니다', 15_000);
      assert.equal(new URL(page.url()).origin, WO, '서비스로 넘어갔다');
      const other = await google.mint({ sub: 'google-user-A', nonce: 'n-1', aud: 'some-service-client' });
      await page.close();
      const page2 = await A.ctx.newPage();   // 같은 주소에 조각(#)만 바꿔 다시 열면 브라우저가 페이지를 다시 실행하지 않는다 — 새 창에서
      await page2.goto(`${wallet.base}/google-relay#state=${state}&id_token=${other}`);
      await page2.waitForURL((u) => u.origin === new URL(rp.base).origin, { timeout: 15_000 });
      await page2.close();
    });
  }
  // ---- salt 봉투(계획 2026-11-24 salt-envelope Task 5): /user 의 백업 카드 → 패스키₁ 이 없는 새 브라우저가 백업으로 같은 계정(같은 PPID)을 되찾는다 ----
  // 새 브라우저들도 Google 계정 A 로 로그인한다 — 계정이 새로 생기지 않는다(뒤 사례는 계정이 A 하나뿐이라고 본다). 기기 봉투는 마지막 사례의 관리자 삭제가 계정과 함께 지운다.
  const SECRET_BK = 'b8'.repeat(32);   // 백업 패스키(다른 인증기) — A 의 브라우저에서 만들고, 복구하는 브라우저에도 꽂혀 있다(보안 키처럼)
  const WO_ = new URL(wallet.base).origin;
  const toUserPage = (page) => page.waitForURL((u) => u.origin === WO_ && u.pathname === '/user' && !u.search.includes('authorize'), { timeout: 60_000 });
  const backupCount = (page) => page.$$eval('#backupList li', (l) => l.length);
  const storesOf = async (page) => j(await idbDump(page)) + j(await page.evaluate(() => [Object.entries(sessionStorage), Object.entries(localStorage)]));
  const asA = () => { google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true }); };
  let recoveryCode = null;
  await t('/user 백업 카드: 백업 패스키 더하기 → Google → ① 지금 패스키 ② 백업 패스키 만들기(같은 인증기면 거절하고 그 자리에서 다시) → 목록 1', async () => {
    await A.ctx.addInitScript({ content: buildWebAuthnStub({ secretHex: SECRET_A, extraSecrets: [SECRET_BK] }) });   // 이제부터 A 의 페이지에는 인증기가 둘(0번 = 패스키₁)
    const page = await openUser(await A.ctx.newPage());
    await page.waitForSelector('#backupCard', { state: 'visible', timeout: 15_000 });
    assert.equal(await backupCount(page), 0);
    { const d = await text(page, '#backupCard'); for (const w of ['다른 기기', '보안 키', '동기화', '안전한 곳', '끊기지 않습니다']) assert.ok(d.includes(w), `안내에 "${w}" 가 없다: ${d.slice(0, 300)}`); }
    asA(); const h0 = { ...A.hits };
    await page.click('#backupPasskeyBtn');
    await page.waitForSelector('#authBackupConfirmBtn', { timeout: 60_000 });
    assert.ok(A.dialogs.at(-1)?.includes('보안 키'), `확인 창: ${A.dialogs.at(-1)}`);
    assert.ok(!page.url().includes('id_token'), '토큰이 주소창에 남았다');
    assert.equal(A.hits.get - h0.get, 0, 'Google 에서 돌아오자마자 패스키를 물었다(클릭 한 번에 한 번)');
    await page.click('#authBackupConfirmBtn');
    await page.waitForSelector('#authBackupCreateBtn', { timeout: 30_000 });
    assert.equal(A.hits.get - h0.get, 1, j(A.hits)); assert.equal(A.hits.create - h0.create, 0, '① 에서 패스키를 만들었다');
    // 같은 인증기(패스키₁)에 만들려 하면 excludeCredentials 로 거절된다 — 요청 키가 남아 같은 화면에서 다시 만든다
    await page.evaluate(() => { window.__webauthnCreateIndex = 0; });
    await page.click('#authBackupCreateBtn');
    await waitText(page, '#authStatus', '이미 패스키가 있습니다', 30_000);
    await page.evaluate(() => { window.__webauthnCreateIndex = 1; });
    await page.click('#authBackupCreateBtn');
    await toUserPage(page);
    await waitText(page, '#backupVerdict', '백업을 더했습니다', 30_000);
    await page.waitForFunction(() => document.querySelectorAll('#backupList li').length === 1, null, { timeout: 15_000 });
    assert.ok((await text(page, '#backupList')).includes('백업 패스키'), await text(page, '#backupList'));
    assert.equal(A.hits.create - h0.create, 2, `거절된 만들기 1 + 만든 것 1: ${j(A.hits)}`);
    // ② 는 ① 의 salt 메모를 쓴다 — get 은 ① 1 + 백업 패스키를 만든 뒤의 재계산 1(거절된 만들기는 재계산하지 않는다)
    assert.equal(A.hits.get - h0.get, 2, `① 1 + 만들기의 재계산 1: ${j(A.hits)}`);
    assert.ok(!(await storesOf(page)).includes(SALT_A), 'salt 가 저장소에 있다');
    await page.close();
  });
  await t('복구 코드 만들기: Google 을 다녀온 귀로 화면에서 코드를 보이고 다시 입력받는다(다르면 저장하지 않는다) → 목록 2 — 저장소·화면에 코드·salt 가 남지 않는다', async () => {
    const page = await openUser(await A.ctx.newPage());
    await page.waitForFunction(() => document.querySelectorAll('#backupList li').length === 1, null, { timeout: 15_000 });
    asA();
    await page.click('#backupCodeBtn');
    await page.waitForSelector('#authBackupCode', { timeout: 60_000 });
    const code = (await text(page, '#authBackupCode')).trim();
    assert.match(code, /^([0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]{3}$/, code);
    { const st = await storesOf(page); assert.ok(!st.includes(code) && !st.includes(code.replace(/-/g, '')), '코드가 저장소에 있다'); }
    const g0 = A.hits.get;
    await page.click('#authBackupCodeWrittenBtn');
    await page.waitForSelector('#authBackupCodeInput', { timeout: 10_000 });
    assert.ok(!(await visibleText(page)).includes(code), '다시 입력받는 동안 코드가 화면에 보인다');
    // 다르게 넣으면 저장하지 않는다(패스키도 묻지 않는다)
    const other = (code[0] === '0' ? '1' : '0') + code.slice(1);
    await page.fill('#authBackupCodeInput', other); await page.click('#authBackupCodeSaveBtn');
    await waitText(page, '#authStatus', '다릅니다', 10_000);
    assert.equal(A.hits.get, g0, '다른 코드인데 패스키를 물었다');
    await page.fill('#authBackupCodeInput', code.toLowerCase().replace(/-/g, ' ')); await page.click('#authBackupCodeSaveBtn');
    await toUserPage(page);
    await waitText(page, '#backupVerdict', '백업을 더했습니다', 30_000);
    await page.waitForFunction(() => document.querySelectorAll('#backupList li').length === 2, null, { timeout: 15_000 });
    assert.ok((await text(page, '#backupList')).includes('복구 코드'));
    assert.equal(A.hits.get - g0, 1, `저장할 때 패스키 한 번: ${j(A.hits)}`);
    const st = await storesOf(page);
    assert.ok(!st.includes(code) && !st.includes(code.replace(/-/g, '')) && !st.includes(code.replace(/-/g, '').toLowerCase()), '코드가 저장소에 있다');
    assert.ok(!st.includes(SALT_A), 'salt 가 저장소에 있다');
    assert.ok(!(await page.evaluate(() => document.documentElement.outerHTML)).includes(code.replace(/-/g, '').slice(0, 12)), '코드가 화면(DOM)에 남았다');
    recoveryCode = code;
    await page.close();
  });
  await t('패스키₁ 이 없는 새 브라우저(다른 패스키 + 백업 패스키): "zkWrapper 로 로그인" → 패스키 만들기 → 복구 화면 → "백업 패스키로 복구" → 로그인 성공, PPID 가 A 와 같다 — create 1 + get 2', async () => {
    const R1 = await newBrowserWith('d4'.repeat(32), [SECRET_BK]);
    try {
      asA();
      const { rpPage, popup } = await startLogin(R1.ctx, rp);
      await popup.waitForSelector('#authWrapPasskeyBtn', { timeout: 30_000 }); await popup.click('#authWrapPasskeyBtn');
      await popup.waitForSelector('#authRecoverList button', { timeout: 120_000 });
      const btns = await popup.$$eval('#authRecoverList button', (bs) => bs.map((b) => `${b.dataset.kind}:${b.textContent.trim()}`));
      assert.ok(btns.some((b) => b.startsWith('passkey:') && b.includes('백업 패스키')) && btns.some((b) => b.startsWith('code:') && b.includes('복구 코드')), j(btns));
      assert.ok(!(await text(rpPage, '#verdict')).includes('로그인 성공'));
      assert.equal(R1.hits.get, 1, `복구 화면 전에는 만들기의 확인 한 번뿐: ${j(R1.hits)}`);
      await popup.click('#authRecoverList button[data-kind="passkey"]');
      await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
      assert.equal(R1.hits.create, 1, j(R1.hits)); assert.equal(R1.hits.get, 2, j(R1.hits));
      const p = await R1.ctx.newPage(); await p.goto(`${wallet.base}/`); await p.waitForSelector('#mainView:not([hidden])');
      const d = await idbDump(p);
      assert.deepEqual(ppidOf(d, info1.arid), [ppid1], 'PPID 가 A 와 다르다'); assert.equal(d.passkey.via, 'envelope');
      assert.ok(!j(d).includes(SALT_A), 'salt 가 저장소에 있다');
      await p.close(); await rpPage.close();
    } finally { await R1.ctx.close(); }
  });
  await t('새 브라우저에서 복구 코드로: 한 글자 틀리면 "한 글자가 틀렸습니다"(그 자리에서 다시), 고치면 로그인 성공·같은 PPID — create 1 + get 1', async () => {
    assert.ok(recoveryCode, '앞 사례의 코드가 없다');
    const R2 = await newBrowserWith('e5'.repeat(32));
    try {
      asA();
      const { rpPage, popup } = await startLogin(R2.ctx, rp);
      await popup.waitForSelector('#authWrapPasskeyBtn', { timeout: 30_000 }); await popup.click('#authWrapPasskeyBtn');
      await popup.waitForSelector('#authRecoverList button[data-kind="code"]', { timeout: 120_000 });
      await popup.click('#authRecoverList button[data-kind="code"]');
      await popup.waitForSelector('#authRecoverCode', { state: 'visible', timeout: 10_000 });
      const typo = (recoveryCode[0] === '0' ? '1' : '0') + recoveryCode.slice(1);
      await popup.fill('#authRecoverCode', typo); await popup.click('#authRecoverCodeBtn');
      await waitText(popup, '#authStatus', '한 글자가 틀렸습니다', 30_000);
      assert.ok(!(await text(rpPage, '#verdict')).includes('로그인 성공'));
      await popup.fill('#authRecoverCode', recoveryCode); await popup.click('#authRecoverCodeBtn');
      await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
      assert.equal(R2.hits.create, 1, j(R2.hits)); assert.equal(R2.hits.get, 1, j(R2.hits));
      const p = await R2.ctx.newPage(); await p.goto(`${wallet.base}/`); await p.waitForSelector('#mainView:not([hidden])');
      const d = await idbDump(p);
      assert.deepEqual(ppidOf(d, info1.arid), [ppid1], 'PPID 가 A 와 다르다');
      const st = j(d); assert.ok(!st.includes(SALT_A) && !st.includes(recoveryCode.replace(/-/g, '')), '저장소에 salt·코드가 있다');
      await p.close(); await rpPage.close();
    } finally { await R2.ctx.close(); }
  });
  // 2026-11-24 최종 검토 I-1: 지우기도 계정의 auid 를 싣는다 — 돌아온 화면의 버튼을 누를 때 지금 패스키를 한 번 묻는다(클릭 한 번에 한 번).
  await t('백업 지우기: "지우기" → Google → 돌아온 화면의 "지금 패스키로 확인하고 지우기"(패스키 한 번) → 목록 1 — 확인 창이 "이미 복구한 기기는 끊기지 않습니다" 를 말한다', async () => {
    const page = await openUser(await A.ctx.newPage());
    await page.waitForFunction(() => document.querySelectorAll('#backupList li').length === 2, null, { timeout: 15_000 });
    asA(); const g0 = A.hits.get;
    await page.click('#backupList li[data-kind="code"] button');
    await page.waitForSelector('#authBackupRemoveBtn', { timeout: 60_000 });
    assert.ok(A.dialogs.at(-1)?.includes('끊기지 않습니다') && A.dialogs.at(-1)?.includes('패스키'), `확인 창: ${A.dialogs.at(-1)}`);
    assert.equal(A.hits.get - g0, 0, `Google 에서 돌아오자마자 패스키를 물었다: ${j(A.hits)}`);
    await page.click('#authBackupRemoveBtn');
    await toUserPage(page);
    await waitText(page, '#backupVerdict', '백업을 지웠습니다', 30_000);
    await page.waitForFunction(() => document.querySelectorAll('#backupList li').length === 1, null, { timeout: 15_000 });
    assert.ok(!(await text(page, '#backupList')).includes('복구 코드'));
    assert.equal(A.hits.get - g0, 1, `지우기는 패스키 한 번: ${j(A.hits)}`);
    await page.close();
  });
  // 2026-11-21(셀프 피드백 — 테스트 구멍): 폐기된 계정도 패스키를 쥔다(R11). 래퍼 화면의 안내는 "관리자가 삭제해야 한다" 까지만 말한다 — 삭제 뒤 실제로 같은 패스키로 돌아오는지 본다.
  // 2026-11-24(스펙 home-and-account-recovery 2부): 계정 자기 폐기 — /user 의 "내 계정 폐기" → Google(같은 계정만) → 폐기. 패스키는 묻지 않는다(A2).
  await t('/user 의 "내 계정 폐기": 다른 Google 계정으로 돌아오면 서버로 보내지 않고, 같은 계정이면 폐기된다 — 패스키는 묻지 않고, 그 뒤 로그인은 폐기된 계정으로 거절된다', async () => {
    const C = await newBrowserWith('c3'.repeat(32));
    try {
      google.setNextSub('google-user-C'); google.setNextClaims({ email: 'cee@example.com', email_verified: true });
      { const { rpPage, popup } = await startLogin(C.ctx, rp); await popup.waitForSelector('#authWrapPasskeyBtn', { timeout: 30_000 }); await popup.click('#authWrapPasskeyBtn'); await waitText(rpPage, '#verdict', '로그인 성공', 120_000); await rpPage.close(); }
      const page = await openUser(await C.ctx.newPage()); const g0 = C.hits.get;
      await page.waitForSelector('#attrEmptyNote', { state: 'visible', timeout: 15_000 });   // H4: 속성이 하나도 없으면 한 줄 안내
      const toUser = () => page.waitForURL((u) => u.origin === new URL(wallet.base).origin && u.pathname === '/user' && !u.search.includes('authorize'), { timeout: 60_000 });
      // 다른 Google 계정으로 돌아오면: 서버로 보내지 않는다(그 계정을 폐기하지 않는다)
      google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
      C.reqs.length = 0;
      await page.click('#wrapRevokeAccountBtn'); await toUser();
      await waitText(page, '#storageVerdict', '폐기하지 못했습니다', 30_000);
      assert.ok(!C.reqs.some((r) => r.url.includes('/cia/account/self_revoke')), '다른 계정의 토큰을 서버로 보냈다');
      assert.ok(C.dialogs.at(-1)?.includes('되돌릴 수 없습니다'), `확인 창: ${C.dialogs.at(-1)}`);
      // 같은 계정이면 폐기된다
      google.setNextSub('google-user-C'); google.setNextClaims({ email: 'cee@example.com', email_verified: true });
      await page.click('#wrapRevokeAccountBtn'); await toUser();
      await waitText(page, '#storageVerdict', '계정을 폐기했습니다', 30_000);
      assert.equal(C.hits.get - g0, 0, `패스키를 물었다: ${j(C.hits)}`);
      assert.deepEqual(Object.keys((await idbDump(page)).sessions ?? {}), [], '이 브라우저의 세션이 남았다');
      await page.close();
      // 그 뒤 로그인은 폐기된 계정으로 거절된다
      google.setNextSub('google-user-C'); google.setNextClaims({ email: 'cee@example.com', email_verified: true });
      const { rpPage, popup } = await startLogin(C.ctx, rp);
      const deadline = Date.now() + 120_000; let seen = '';
      while (Date.now() < deadline) {
        const v = await text(rpPage, '#verdict').catch(() => '');
        seen = `${v} | ${popup.isClosed() ? '' : await visibleText(popup).catch(() => '')}`;
        if (/폐기된 계정/.test(seen)) break;
        assert.ok(!v.includes('로그인 성공'), '폐기된 계정이 로그인됐다');
        if (!popup.isClosed()) { const b = await popup.$('#authWrapPasskeyBtn:not([hidden])').catch(() => null); if (b) await b.click().catch(() => {}); }
        await new Promise((r) => setTimeout(r, 500));
      }
      assert.match(seen, /폐기된 계정/, seen.slice(0, 300));
      await popup.close().catch(() => {}); await rpPage.close();
    } finally {
      await C.ctx.close();
      // 뒤 사례(관리자 폐기·삭제)는 Google 계정이 A 하나뿐이라고 본다 — 이 사례의 계정 C 는 관리자 삭제로 정리한다
      await cia.adminPost('/cia/account/delete', { uid: uidOf(google.provider, 'google-user-C') }).catch(() => {});
    }
  });
  await t('관리자 폐기 → "zk 로그인" 은 폐기된 계정으로 거절된다 — 관리자 삭제 뒤 같은 브라우저(같은 패스키)·같은 Google 계정으로 다시 하면 성공하고 PPID 가 같다', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid: UID_A, scope: 'account' })).status, 200);
    google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
    const first = await startLogin(A.ctx, rp);
    const deadline = Date.now() + 120_000; let seen = '';
    while (Date.now() < deadline) {
      const v = await text(first.rpPage, '#verdict').catch(() => '');
      const p = first.popup.isClosed() ? '' : await visibleText(first.popup).catch(() => '');
      seen = `${v} | ${p}`;
      if (/폐기된 계정/.test(seen)) break;
      assert.ok(!v.includes('로그인 성공'), '폐기된 계정이 로그인됐다');
      if (!p) { const b = await first.popup.$('#authWrapPasskeyBtn').catch(() => null); if (b) await b.click().catch(() => {}); }
      await new Promise((r) => setTimeout(r, 500));
    }
    assert.match(seen, /폐기된 계정/, seen.slice(0, 300));
    assert.match(seen, /관리자가 이 계정을 삭제/, '래퍼 문구(ko_wr)가 보여야 한다: ' + seen.slice(0, 300));
    await first.popup.close().catch(() => {}); await first.rpPage.close();
    assert.equal((await cia.adminPost('/cia/account/delete', { uid: UID_A })).status, 200);
    assert.equal((await accounts()).length, 0);
    google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
    const again = await startLogin(A.ctx, rp);
    await waitText(again.rpPage, '#verdict', '로그인 성공', 120_000);
    const acc = await accounts(); assert.equal(acc.length, 1, '지운 뒤 다시 하면 새 계정이 하나 생긴다'); assert.equal(String(acc[0].uid), UID_A);
    const ps = ppidOf(noteSessions(await idbDump(userPage)), info1.arid); assert.ok(ps.length >= 1 && ps.every((p) => p === ppid1), j(ps));
    await again.rpPage.close();
  });
  // 2026-11-25(사용자 요청): 속성 도구의 래퍼 문구 — 붙여 넣을 곳(zkIdP 프로필·인증 창)이 없다. 기록은 로그인 창이 같은 오리진에서 읽는다. 새 맥락에서 홈을 거쳐 도구를 연다
  // (홈이 /mode3/health 로 래퍼 방식을 알아 localStorage 에 남기고, 도구는 그 값으로 그린다). 이 사례는 A 의 기록을 건드리지 않는다.
  await t('속성 도구(zkWrapper): "만들기" 뒤 문구가 "이 브라우저에 저장·zkWrapper 로 로그인하면 됨" 이고 붙여 넣기·zkIdP·인증 창 안내와 복사 버튼이 없다', async () => {
    const ctx = await browser.newContext();
    try {
      const p = await ctx.newPage();
      // 도구는 /attr/dist/reset.json 의 walletKind 로 모드를 다시 정한다 — 데모 스크립트가 래퍼에서 쓰는 값을 준다(작업 트리에 남은 옛 파일에 기대지 않는다).
      await p.route('**/attr/dist/reset.json', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ epoch: 'test-wrapper', walletKind: 'zkwrapper' }) }));
      await p.goto(`${wallet.base}/`);
      await p.waitForFunction(() => document.documentElement.dataset.wrapper === '1', null, { timeout: 15_000 });
      await p.goto(`${wallet.base}/attr.html`);
      await p.waitForFunction(() => document.documentElement.dataset.wrapper === '1' && document.querySelectorAll('#country option').length > 1, null, { timeout: 15_000 });
      await p.fill('#birthYear', '1990'); await p.selectOption('#country', 'KR'); await p.fill('#salt', SALT_A);
      await p.click('#makeBtn');
      await waitText(p, '#formVerdict', '이제 서비스에서 zkWrapper 로 로그인하면 됩니다', 30_000);
      const body = await visibleText(p);
      for (const s of ['zkWrapper 로 로그인할 때부터 반영', '다른 서비스의 열린 세션은 닫히고', '참고용 공개값입니다', '자동으로 씁니다']) assert.ok(body.includes(s), `없음: ${s}`);
      for (const w of ['zkIdP', '인증 창', '프로필', '붙여 넣으세요']) assert.ok(!body.includes(w), `남음: ${w} — ${body.slice(Math.max(0, body.indexOf(w) - 40), body.indexOf(w) + 40)}`);
      assert.equal(await p.$eval('#copyBtn', (el) => el.checkVisibility()), false, '래퍼에서는 커밋먼트 복사 버튼이 할 일이 없다');
    } finally { await ctx.close(); }
  });
  // 2026-11-25(사용자 결정): 서비스의 "Google 로 로그인"(일반 OIDC)은 서비스가 보관하는 계정이다 — 키를 새로 맡지 않고 화면만 정리한다.
  // 주소 줄 대신 계정 번호와 "서비스가 보관" 을, 잔액은 보관 ETH 한 줄만, 그 아래 zkWrapper 로 로그인하면 내가 쥐는 계정을 받는다는 안내를 보인다.
  // 서비스를 Google 설정으로 다시 띄우므로 이 파일의 마지막 사례로 둔다.
  await t('서비스에서 Google 로 로그인: 계정 번호·"서비스가 보관"·보관 잔액 한 줄·zkWrapper 안내가 보이고 PPID 주소 줄은 없다', async () => {
    // 서비스는 래퍼와 다른 Google 클라이언트 ID 를 쓴다(데모 스크립트와 같다) — 같으면 중계 화면이 래퍼용 토큰이라 서비스로 넘기지 않는다(스펙 zkwrapper §10 C2).
    const rpGoogle = await startOidcIssuerStub({ clientId: 'rp-google-client', provider: 'google' });
    try {
    await stack.restartRp({ MODE3_RP_GOOGLE_CLIENT_ID: rpGoogle.clientId, MODE3_RP_GOOGLE_ISSUER: rpGoogle.issuer, MODE3_RP_GOOGLE_JWKS_URL: rpGoogle.jwksUrl, MODE3_RP_GOOGLE_AUTHORIZE_URL: rpGoogle.authorizeUrl, MODE3_RP_GOOGLE_REDIRECT_URI: `${wallet.base}/google-relay`, MODE3_EXPLORER_URL: 'http://127.0.0.1:4000/' });
    rpGoogle.setNextSub('google-rp-only-user');
    const page = await openRp(A.ctx, rp);
    await page.click('#loginBtn');
    await page.waitForFunction(() => { const b = document.getElementById('googleLoginBtn'); return b && getComputedStyle(b).display !== 'none'; }, null, { timeout: 15_000 });
    await page.click('#googleLoginBtn');
    await page.waitForSelector('#seenBox[data-issuer="google"]:not([hidden])', { timeout: 30_000 });
    await page.waitForSelector('#custodyIdRow:not([hidden])', { timeout: 15_000 });
    const me = await page.evaluate(() => fetch('/api/rp/me').then((r) => r.json()));
    assert.equal(me.via, 'google');
    const vis = (sel) => page.$eval(sel, (el) => el.checkVisibility());
    assert.equal(await text(page, '#custodyAccountId'), me.account, '계정 번호는 서비스 계정 ID 다');
    assert.ok((await text(page, '#custodyIdRow')).includes('서비스가 보관하는 계정'), await text(page, '#custodyIdRow'));
    assert.equal(await vis('#ppidAddrRow'), false, 'PPID 주소 줄은 보이지 않는다');
    assert.equal(await vis('.balance-list li[data-asset="ETH"]'), false, '체인 잔액 줄(주소 없음)은 숨긴다');
    assert.equal(await vis('.balance-list li[data-asset="ETH_CUSTODY"]'), true);
    assert.ok((await text(page, '.balance-list li[data-asset="ETH_CUSTODY"] .bal-label')).includes('내 계정 — 서비스 보관'));
    // 그림(스펙 2026-11-25 service-flow-figure): 서비스에서 열면 지금 로그인한 방식의 줄만 서비스가 받은 값으로 채운다
    const figVal = (p, id) => p.$eval(`#${id}`, (e) => e.querySelector('title')?.textContent ?? '');
    const openFigure = async () => { const [f] = await Promise.all([A.ctx.waitForEvent('page'), page.click('#flowFigureLink')]); await f.waitForFunction(() => document.getElementById('recentOidc') && !document.getElementById('recentOidc').hidden && document.getElementById('recent').textContent.includes('이 서비스에 zkWrapper 로'), null, { timeout: 15_000 }); return f; };
    let gFigSub = null;
    {
      const f = await openFigure();
      await f.waitForFunction(() => (document.getElementById('oidcSub').textContent ?? '') !== '', null, { timeout: 15_000 });
      assert.equal(await figVal(f, 'oidcSub'), me.seen.uid); assert.equal(await figVal(f, 'oidcAud'), me.seen.rid); assert.equal(await figVal(f, 'oidcClientId'), me.seen.rid); gFigSub = me.seen.uid;
      assert.equal(gFigSub, 'google-rp-only-user');
      for (const id of ['zkAuidS', 'zkAridS', 'zkPpid']) assert.equal(await figVal(f, id), '', `Google 로그인인데 ${id} 가 채워졌다`);
      const all = await visibleText(f); assert.ok(!/zk-?IdP|zk 클라이언트|zk 로그인/.test(all), all.match(/.{0,30}(zk-?IdP|zk 클라이언트|zk 로그인).{0,30}/)?.[0]); assert.ok(!/zkTWO/.test(all), '"zkTWO 도 같은 값" 이 남았다');
      await shot(f, 'flow_service_google'); assert.ok(!(await visibleText(f)).includes('걸린 시간이 펴집니다'), '서비스에는 시간이 없다'); await f.close();
    }
    const hint = await text(page, '#custodyHint');
    assert.equal(await vis('#custodyHint'), true);
    assert.ok(hint.includes('키는 서비스가 보관') && hint.includes('zkWrapper 로 로그인하면') && hint.includes('세션키와 증명'), `누가 키를 쥐는지 안내: ${hint}`);
    // 보관 주소(스펙 2026-11-25 rp-custody-address): 주소·복사·탐색기 링크·보낼 수 있는 최대, 보내기 설명
    await page.waitForSelector('#custodyAddrRow:not([hidden])', { timeout: 15_000 });
    const cAddr = (await page.evaluate((b) => fetch('/api/rp/ledger', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ body: b }) }).then((x) => x.json()), 'balance')).balance.custodyAddress;
    assert.match(cAddr, /^0x[0-9a-fA-F]{40}$/); assert.equal(await text(page, '#custodyAddr'), cAddr); assert.equal(await vis('#copyCustodyBtn'), true);
    assert.equal(await page.$eval('#custodyExplorerLink', (a) => (a.checkVisibility() ? a.getAttribute('href') : null)), `http://127.0.0.1:4000/address/${cAddr}`);
    assert.ok((await text(page, '#custodyMax')).includes('최대 0 ETH'), await text(page, '#custodyMax')); assert.ok((await text(page, '#txDesc')).includes('서비스가 대신 서명'), await text(page, '#txDesc'));
    assert.ok(!(await visibleText(page)).includes('거래소 보관'), '옛 "거래소 보관" 문구가 남았다');
    // 보관 잔액(0)보다 많이 출금하면 래퍼 문구의 잔고 부족(insufficient_custody ko_wr)
    await page.fill('#txTo', '0x' + '11'.repeat(20)); await page.fill('#txValue', '1');
    await page.click('#txBtn');
    await waitText(page, '#txVerdict', '내 계정 잔고가 부족합니다', 20_000);
    // 표시 버그(2026-11-25): Google 계정에 KRW·보관 ETH 가 생긴 탭에서 이어서 zkWrapper 로 로그인하면 그 숫자가 남았다 — 잔액 칸의 처음 값을 페이지 시작 때 적어 두어 0 으로 돌아간다.
    // 서버의 zk 계정은 Google 계정과 따로라 KRW·보관 0, PPID 계정의 체인 잔액도 0 이다(zkWrapper 세션은 자동 조회를 하지 않으므로 화면이 처음 값 그대로여야 맞다).
    const amt = (a) => text(page, `.balance-list li[data-asset="${a}"] .bal-amt`);
    await page.click('#depositBtn');
    await page.waitForFunction(() => document.querySelector('.balance-list li[data-asset="KRW"] .bal-amt').textContent !== '0', null, { timeout: 20_000 });
    await page.fill('#buyAmount', '0.01'); await page.click('#buyBtn');
    await page.waitForFunction(() => document.querySelector('.balance-list li[data-asset="ETH_CUSTODY"] .bal-amt').textContent !== '0', null, { timeout: 20_000 });
    assert.notEqual(await amt('KRW'), '0');
    // 구매는 체인의 내 주소로 들어오고, 보내면 from 이 그 주소다. 가스 부족이면 사유
    assert.equal(await chainRead.getBalance(cAddr), 10n ** 16n, '산 ETH 가 내 주소에 없다'); await page.waitForFunction(() => /최대 0\.0099/.test(document.getElementById('custodyMax').textContent), null, { timeout: 10_000 });
    await page.fill('#txValue', '0.01'); await page.click('#txBtn'); await waitText(page, '#txVerdict', '가스로 쓸 ETH 가 모자랍니다', 20_000);
    await page.fill('#txValue', '0.005'); await page.click('#txBtn'); await waitText(page, '#txVerdict', '서비스가 보관한 키로 대신 서명', 20_000);
    { const h = await page.$eval('#txHashCode', (e) => e.title); const tx = await chainRead.getTransaction(h); assert.equal(tx.from, cAddr, 'from 이 내 주소가 아니다'); assert.equal(tx.to.toLowerCase(), '0x' + '11'.repeat(20)); }
    await page.click('#logoutBtn'); await page.waitForSelector('#loginBtn:not([hidden])');
    google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
    await page.click('#loginBtn');
    const [zkPopup] = await Promise.all([A.ctx.waitForEvent('page'), page.click('#idpLoginBtn')]);
    await waitText(page, '#verdict', '로그인 성공', 120_000);
    await zkPopup.close().catch(() => {});
    assert.deepEqual([await amt('KRW'), await amt('ETH')], ['0', '0'], 'Google 계정의 KRW·ETH 가 zk 로그인 뒤에 남았다');
    assert.equal(await vis('.balance-list li[data-asset="ETH_CUSTODY"]'), false, 'zk 로그인에는 보관 잔액이 없어 그 줄을 숨긴다');
    assert.equal(await vis('#custodyIdRow'), false); assert.equal(await vis('#custodyAddrRow'), false); assert.equal(await vis('#custodyMax'), false);
    assert.ok(!(await page.content()).includes(cAddr), '앞 로그인의 보관 주소가 남았다'); assert.ok(!(await text(page, '#txDesc')).includes('서비스가 대신 서명'));
    {
      const zme = await page.evaluate(() => fetch('/api/rp/me').then((r) => r.json())); assert.equal(zme.via, 'zkid', j(zme.via));
      const f = await openFigure();
      await f.waitForFunction(() => (document.getElementById('zkPpid').textContent ?? '') !== '', null, { timeout: 15_000 });
      assert.equal(await figVal(f, 'zkAuidS'), String(zme.seen.auid_s)); assert.equal(await figVal(f, 'zkAridS'), String(zme.seen.arid_s)); assert.equal(await figVal(f, 'zkPpid'), String(zme.seen.PPID));
      for (const id of ['oidcClientId', 'oidcSub', 'oidcAud']) assert.equal(await text(f, `#${id}`), '', `zk 로그인인데 ${id} 가 채워졌다`);
      assert.ok(!(await f.content()).includes(gFigSub), '앞 로그인의 Google sub 가 그림에 남았다');
      assert.ok((await text(f, '#kIdpWho')).includes('이 서비스는 모름')); assert.ok((await text(f, '#zkSaltNote')).includes('모름'));
      // 같은 서비스의 앞 로그인들과: auid_s 는 다르고 PPID 는 같다
      const prev = [...seenSessions.values()].filter((x) => String(x.arid) === String(info1.arid));
      assert.ok(prev.length >= 1 && prev.every((x) => String(x.auid_s) !== String(zme.seen.auid_s)), 'auid_s 가 앞 로그인과 같다'); assert.ok(prev.every((x) => String(x.PPID) === String(zme.seen.PPID)), 'PPID 가 앞 로그인과 다르다');
      // 시간·토큰 표가 없고, 어디에도 저장하지 않는다
      for (let k = 1; k <= 6; k++) { await f.click(`#seqZk .st[data-step="${k}"]`); assert.equal(await f.$$eval('#detailZk table', (l) => l.length), 0, `${k} 단계에 표`); }
      const st = await f.evaluate(async () => ({ dbs: (await indexedDB.databases()).map((d) => d.name), ls: JSON.stringify(Object.entries(localStorage)), ss: JSON.stringify(Object.entries(sessionStorage)) }));
      assert.ok(!st.dbs.includes('mode3-user'), j(st.dbs)); assert.ok(!st.ss.includes(gFigSub) && !st.ls.includes(gFigSub), '저장소에 Google sub');
      await shot(f, 'flow_service_zk');
      // 로그아웃(서버 쿠키가 사라짐) 뒤 탭으로 돌아오면 값이 지워진다
      await f.route('**/api/rp/me', (r) => r.fulfill({ status: 401, contentType: 'application/json', body: '{"ok":false}' }));
      await f.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
      await f.waitForFunction(() => document.getElementById('zkPpid').textContent === '', null, { timeout: 10_000 });
      assert.ok(!(await f.content()).includes(String(zme.seen.PPID)), '401 뒤에도 PPID 가 남았다');
      await f.close();
    }
    // "세션 복구" 실패(2026-11-25): 로그인된 상태에서는 로그인 카드(#verdict)가 숨어 있다 — 실패 사유가 배너 안(#sessionBarVerdict)에 보여야 한다.
    // 세션이 끝난 배너를 띄우고(페이지 전역 noteSessionReason), 복구 로그인의 챌린지를 503 으로 실패시킨다.
    await page.evaluate(() => noteSessionReason('revoked'));
    await page.waitForSelector('#sessionBar:not([hidden])', { timeout: 5_000 });
    await page.route('**/api/mode3/challenge', (r) => r.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ ok: false, reason: 'registration_pending' }) }));
    await page.click('#sessionBarBtn');
    await waitText(page, '#sessionBarVerdict', '로그인 실패', 20_000);
    assert.equal(await vis('#sessionBarVerdict'), true, '배너 안의 실패 사유가 보이지 않는다');
    assert.equal(await vis('#verdict'), false, '이 사례의 전제: 로그인 카드의 결과 칸은 숨어 있다');
    assert.equal(await vis('#sessionBar'), true, '실패면 배너는 남는다');
    await page.unroute('**/api/mode3/challenge');
    await page.click('#logoutBtn'); await page.waitForSelector('#loginBtn:not([hidden])');
    await page.close();
    } finally { await rpGoogle.stop(); }
  });
  // 2026-11-25(사용자 요청): /user 잠금 화면 — 이 브라우저에 패스키가 없으면 서비스에 로그인하라고 하지 않고 여기서 만든다(Google 을 거치지 않고 연결만). 등록이 없어도 패스키로 열린다.
  await t('/user 잠금: 패스키 없음 → 안내·버튼 둘, 취소하면 사유가 잠금 카드에 → "패스키 만들기" → "패스키로 열기" 로 열린다(등록 없음) → 그 패스키로 서비스 첫 로그인', async () => {
    const before = (await accounts()).length;
    const B = await newBrowserWith('d4'.repeat(32));
    try {
      const page = await B.ctx.newPage(); await page.goto(`${wallet.base}/user`);
      const vis = (sel) => page.$eval(sel, (el) => el.checkVisibility());
      await page.waitForSelector('#userNoPk', { state: 'visible', timeout: 15_000 });
      const shown = await page.evaluate(() => [...document.querySelectorAll('#mainView > section')].filter((e) => e.checkVisibility()).map((e) => e.id)); assert.deepEqual(shown, ['userLockCard']);
      assert.equal(await vis('#userUnlockBtn'), false, '패스키가 없는데 "패스키로 열기" 가 보인다');
      const card = await page.$eval('#userLockCard', (e) => e.innerText);
      assert.ok(card.includes('패스키를 만들면 이 화면을 열 수 있습니다'), card); assert.ok(!/로그인한 서비스가 없습니다|서비스에서/.test(card), `서비스에 로그인하라는 문장이 남았다: ${card}`);
      // 취소: 사유가 잠금 카드에 보이고 다시 누를 수 있다(연결은 되지 않는다)
      await page.evaluate(() => { const c = navigator.credentials, orig = c.create; Object.defineProperty(c, 'create', { configurable: true, value: () => { Object.defineProperty(c, 'create', { configurable: true, value: orig }); return Promise.reject(new DOMException('cancelled', 'NotAllowedError')); } }); });
      await page.click('#lockPkNewBtn'); await page.waitForFunction(() => document.getElementById('userLockVerdict').classList.contains('bad'), null, { timeout: 10_000 });
      assert.equal(await vis('#userLockVerdict'), true); assert.equal((await idbDump(page)).passkey, undefined); assert.equal(await vis('#lockPkNewBtn'), true);
      // 만들기 → 연결 → "패스키로 열기"
      await page.reload(); await page.waitForSelector('#userNoPk', { state: 'visible', timeout: 15_000 });
      await page.click('#lockPkNewBtn'); await page.waitForSelector('#userUnlockBtn', { state: 'visible', timeout: 15_000 });
      await waitText(page, '#userLockVerdict', '패스키를 연결했습니다'); assert.equal(await vis('#userLockVerdict'), true); assert.equal(await vis('#userNoPk'), false); assert.equal(B.hits.create, 1, j(B.hits));
      assert.deepEqual(await page.evaluate(() => [...document.querySelectorAll('#mainView > section')].filter((e) => e.checkVisibility()).map((e) => e.id)), ['userLockCard'], '연결만으로 열리지 않는다');
      const g0 = B.hits.get; await page.click('#userUnlockBtn'); await page.waitForSelector('#sessionsCard', { state: 'visible', timeout: 15_000 }); assert.equal(B.hits.get - g0, 1, j(B.hits));
      assert.equal((await idbDump(page)).registration, undefined, '등록 없이 열렸다'); assert.equal((await accounts()).length, before, '서버 계정이 생겼다');
      assert.ok(!B.reqs.some((r) => r.url.startsWith(google.issuer)), 'Google 로 갔다');
      await page.click('#userLockBtn'); await page.waitForSelector('#userUnlockBtn', { state: 'visible', timeout: 5_000 }); assert.equal(await vis('#userNoPk'), false);
      await page.close();
      // 그 패스키로 서비스 첫 로그인 — 패스키를 새로 만들지 않는다
      google.setNextSub('google-user-lock'); google.setNextClaims({ email: 'lock@example.com', email_verified: true });
      const { rpPage } = await startLogin(B.ctx, rp); await waitText(rpPage, '#verdict', '로그인 성공', 120_000); assert.equal(B.hits.create, 1, '로그인 때 패스키를 또 만들었다');
      assert.equal((await accounts()).length, before + 1); await rpPage.close();
    } finally { await B.ctx.close(); await cia.adminPost('/cia/account/delete', { uid: uidOf(google.provider, 'google-user-lock') }).catch(() => {}); }
  });
  await t('/user 잠금: "이미 있는 패스키 쓰기" → 만들지 않고 연결된다', async () => {
    const C = await newBrowserWith(SECRET_A);
    try {
      const page = await C.ctx.newPage(); await page.goto(`${wallet.base}/user`); await page.waitForSelector('#userNoPk', { state: 'visible', timeout: 15_000 });
      await page.click('#lockPkExistingBtn'); await page.waitForSelector('#userUnlockBtn', { state: 'visible', timeout: 15_000 });
      assert.equal(C.hits.create, 0, j(C.hits)); assert.ok(C.hits.get >= 1, j(C.hits));
      await page.click('#userUnlockBtn'); await page.waitForSelector('#sessionsCard', { state: 'visible', timeout: 15_000 });
    } finally { await C.ctx.close(); }
  });
  await A.ctx.close();
} finally {
  await browser.close().catch(() => {});
  await stack.stop();
}
console.log(failed ? `\n${failed} 실패` : '\n모두 통과');
process.exit(failed ? 1 : 0);
