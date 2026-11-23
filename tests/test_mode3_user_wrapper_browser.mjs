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
  // 이 브라우저에서 나간 모든 요청 — 어느 페이지가(pageOrigin) 어디로(url) 무엇을(body·referer·origin) 보냈는지. Task 5 의 "서버가 무엇을 보는가" 사례가 본다.
  const reqs = [];
  ctx.on('request', (r) => { try { let from = null; try { from = new URL(r.frame().url()).origin; } catch { from = null; } reqs.push({ url: r.url(), method: r.method(), body: r.postData() ?? '', referer: r.headers().referer ?? '', origin: r.headers().origin ?? '', from, nav: r.isNavigationRequest() }); } catch { /* 닫힌 창 */ } });
  ctx.on('page', (p) => { if (DEBUG) { p.on('console', (m) => console.log(`    [${new URL(p.url()).port}] ${m.type()}: ${m.text()}`)); p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`)); } });
  return { ctx, hits, reqs };
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
  await t('zkTWO 로그인: PPID 가 zkONE 과 다르고 조건 증명이 통과한다', async () => {
    google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
    const { rpPage } = await startLogin(A.ctx, rp2);
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
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
    await userPage.goto(`${wallet.base}/`); await userPage.waitForSelector('#mainView:not([hidden])');
    await userPage.waitForFunction((pp) => [...document.querySelectorAll('#sessionActions dd code')].some((e) => e.title === pp), ppid2, { timeout: 15_000 });
    const cards = await userPage.$$eval('#sessionActions dl', (dls) => dls.map((dl) => Object.fromEntries([...dl.querySelectorAll('dt')].map((dt) => [dt.textContent.trim(), dt.nextElementSibling.querySelector('code')?.title ?? dt.nextElementSibling.textContent.trim()]))));
    const c2 = cards.find((o) => o.PPID === ppid2);
    assert.ok(c2, `PPID 줄이 PPID 값을 보이지 않는다: ${j(cards.map((o) => Object.keys(o)))}`);
    assert.equal(String(c2['PPID 스마트 계정 주소'] ?? '').toLowerCase(), acct2.toLowerCase(), j(c2));
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
    assert.equal(await chainRead.getBlockNumber(), h0, '① 이 거래를 보냈다'); assert.equal(A.hits.get - g0, 1, `패스키는 한 번: ${j(A.hits)}`);
    await clickTx(replayPage, '#txReplayBtn');
    await waitText(replayPage, '#txVerdict', 'root 가 아직 바뀌지 않았습니다', 120_000);
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
    await page.close();
  });
  await t('래퍼 방식의 화면 어디에도 "zkIdP"·"인증 창"·"π_IdP"·"비밀번호" 가 없다(홈·승인 창·서비스·운영자·관리자·전체 플로우)', async () => {
    const c = (await wallet.get('/user/config')).body; const hits = [];
    assert.ok(Array.isArray(popupBanned), '승인 창의 글자를 모으지 못했다'); for (const h of popupBanned) hits.push(`승인 창 ${h}`);
    for (const [name, url] of [['홈', `${wallet.base}/`], ['서비스', `${rp.base}/`], ['zkTWO', `${rp2.base}/`], ['운영자', `${c.ciaUrl}/rp`], ['관리자', `${c.ciaUrl}/admin`], ['전체 플로우', `${wallet.base}/common/flow.html`]]) {
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
  await t('래퍼 방식의 홈: 세션마다 "이 세션 끝내기(폐기)" 버튼이 있고, 계정 자기 폐기 버튼은 없고 안내가 있다', async () => {
    const page = await A.ctx.newPage(); await page.goto(`${wallet.base}/`); await page.waitForSelector('#homeGuide:not([hidden])', { timeout: 15_000 });
    await page.waitForFunction(() => document.querySelectorAll('#sessionActions button.danger').length > 0, null, { timeout: 15_000 }).catch(() => {});
    const st = await page.evaluate(() => ({ cards: document.querySelectorAll('#sessionActions dl').length,
      endBtns: [...document.querySelectorAll('#sessionActions button')].filter((b) => b.offsetParent !== null && /세션 끝내기/.test(b.textContent)).length,
      selfRevoke: document.getElementById('selfRevokeBtn')?.offsetParent !== null, notes: [...document.querySelectorAll('.wrap-revoke-note')].filter((e) => e.offsetParent !== null).length,
      sessionNotes: [...document.querySelectorAll('#sessionActions .wrap-revoke-note')].filter((e) => e.offsetParent !== null).length }));
    assert.ok(st.cards >= 1, '세션이 그려지지 않았다: ' + j(st));
    assert.equal(st.endBtns, st.cards, j(st)); assert.equal(st.sessionNotes, 0, j(st));
    assert.equal(st.selfRevoke, false, j(st)); assert.ok(st.notes >= 1, j(st));
    await page.close();
  });
  // 홈의 "이 세션 끝내기(폐기)" — 이 탭이 Google 을 다녀와(패스키는 묻지 않는다) 그 세션 하나만 폐기를 요청한다. 옛 증명 시연의 root 바꾸기도 이 길로 한다:
  // zkONE ① → 홈에서 zkTWO 세션 끝내기 → 게시 → zkONE ② = InvalidProof.
  const adminSessions = async () => (await cia.adminGet(`/cia/admin/sessions?uid=${UID_A}`)).body.sessions;
  const endSessionOnHome = async (page, arid) => {
    await page.goto(`${wallet.base}/`); await page.waitForSelector('#mainView:not([hidden])');
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
    await page.waitForURL((u) => u.origin === new URL(wallet.base).origin && u.pathname === '/' && !u.search.includes('authorize'), { timeout: 60_000 });
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
    const page = await A.ctx.newPage(), g0 = A.hits.get;
    google.setNextSub('google-user-A'); google.setNextClaims({ email: 'jihoo@example.com', email_verified: true });
    const { Cf_s } = await endSessionOnHome(page, info2.arid);
    await page.waitForURL((u) => u.origin === new URL(wallet.base).origin && u.pathname === '/' && !u.search.includes('authorize'), { timeout: 60_000 });
    await waitText(page, '#sessionVerdict', '폐기를 요청했습니다', 30_000);
    assert.equal(A.hits.get - g0, 0, `패스키를 물었다: ${j(A.hits)}`);
    const after = await adminSessions();
    assert.ok(after.find((x) => x.Cf_s === Cf_s)?.revokedAt, '그 세션이 폐기되지 않았다');
    const newlyRevoked = after.filter((x) => x.revokedAt && !before.find((y) => y.Cf_s === x.Cf_s)?.revokedAt).map((x) => x.Cf_s);
    assert.deepEqual(newlyRevoked, [Cf_s], '다른 세션까지 폐기됐다');
    assert.ok(!Object.values((await idbDump(page)).sessions ?? {}).some((v) => String(v.arid) === String(info2.arid)), '지갑에 폐기한 세션이 남았다');
    assert.equal((await cia.adminPost('/cia/publish', {})).status, 200);
    assert.notEqual((await cia.get('/mode3/health')).body.root, root0, '게시했는데 root 가 그대로다');
    await rpPage.click('#txReplayBtn');
    await waitText(rpPage, '#txVerdict', '증명 검증', 120_000);
    assert.ok((await text(rpPage, '#txVerdict')).includes('InvalidProof'));
    await page.close(); await rpPage.close();
  });
  await t('서비스의 로그인 버튼은 "zk 로그인" 이다', async () => {
    const page = await openRp(A.ctx, rp); await page.click('#loginBtn');
    assert.equal((await text(page, '#idpLoginBtn')).trim(), 'zk 로그인'); await page.close();
  });
  await t('전체 플로우 한 장: 아랫줄에 Google 이 있고 π_IdP 가 없다 — 실제 값이 채워진다', async () => {
    const page = await A.ctx.newPage(); await page.goto(`${wallet.base}/common/flow.html`);
    await page.waitForFunction(() => (document.getElementById('zkAuidS')?.textContent ?? '').length > 'auid_s'.length, null, { timeout: 15_000 });
    const seq = await page.$eval('#seqZk', (e) => e.textContent);
    assert.ok(seq.includes('Google'), seq.slice(0, 200)); assert.ok(!seq.includes('π_IdP'), 'π_IdP 가 남았다'); assert.ok(seq.includes('zkWrapper'), 'zkWrapper 가 없다');
    await page.click('#seqZk .st[data-step="3"]'); const det = await text(page, '#detailZk'); assert.ok(det.includes('Google') && !det.includes('π_IdP'), det);
    await page.close();
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
  // 2026-11-21(셀프 피드백 — 테스트 구멍): 폐기된 계정도 패스키를 쥔다(R11). 래퍼 화면의 안내는 "관리자가 삭제해야 한다" 까지만 말한다 — 삭제 뒤 실제로 같은 패스키로 돌아오는지 본다.
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
  await A.ctx.close();
} finally {
  await browser.close().catch(() => {});
  await stack.stop();
}
console.log(failed ? `\n${failed} 실패` : '\n모두 통과');
process.exit(failed ? 1 : 0);
