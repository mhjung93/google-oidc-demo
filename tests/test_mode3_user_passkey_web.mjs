// passkey-web(스펙 2026-11-17-mode3-passkey-web) — 웹 모드 사용자 페이지의 승인 팝업이 IdP 인증 창을 다녀오고 salt 를 패스키(10분 보관분)에서 받는다.
// 정적 서버(MODE3_WALLET_SECRETS=passkey-web) + 격리 IdP(CIA_ISSUE_AUTH=code)·RP(릴레이) + 결정적 WebAuthn 스텁(tests/helpers/webauthn_stub.js).
// hardhat :8545, build/mode3 산출물, Chrome 이 필요하다(browser 그룹). 번들(사용자 앱·속성 도구)은 여기서 만든다.
//   node tests/test_mode3_user_passkey_web.mjs   (MODE3_BROWSER_DEBUG=1 이면 콘솔 출력)
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { buildWebAuthnStub } from './helpers/webauthn_stub.js';
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
/** 스텁 패스키의 salt — 페이지와 같은 식(PRF 입력 zkd-s_u-v1, 도메인 zkd-passkey-s_u-v1). */
function stubSalt(secretHex) {
  const salt = createHash('sha256').update(Buffer.concat([Buffer.from('WebAuthn PRF\0'), Buffer.from('zkd-s_u-v1')])).digest();
  const prf = createHmac('sha256', Buffer.from(secretHex, 'hex')).update(salt).digest();
  return (BigInt('0x' + createHash('sha256').update(Buffer.concat([Buffer.from('zkd-passkey-s_u-v1'), prf])).digest('hex')) >> 6n).toString();
}
/** 스텁 패스키의 credential ID — 스텁의 rawId(SHA-256(secret) 앞 16바이트)를 base64url 로(passkey_store.b64url 과 같다). */
const stubCredId = (secretHex) => createHash('sha256').update(Buffer.from(secretHex, 'hex')).digest().subarray(0, 16).toString('base64url');

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
execFileSync('node', ['scripts/build_attr_tool.mjs'], { stdio: 'inherit' });   // 속성 도구 번들 — reset.json 을 사용자 페이지가 같은 오리진에서 읽는다
const browser = await launchBrowser();
const stack = await startIsolatedMode3Stack({ userMode: 'web', walletHost: 'localhost', walletEnv: { MODE3_WALLET_SECRETS: 'passkey-web' }, ciaEnv: { CIA_ISSUE_AUTH: 'code' }, autoRelay: true });
const { cia, wallet, rp } = stack;
const WALLET_ORIGIN = new URL(wallet.base).origin;
const SECRET_A = 'a1'.repeat(32), SECRET_C = 'c3'.repeat(32);
const SALT_A = stubSalt(SECRET_A), SALT_C = stubSalt(SECRET_C);
const AUID_A = (await auidOf({ s_u: BigInt(SALT_A) })).toString();
const DEMO_PWD = 'demo-pass-9';
const hits = { create: 0, get: 0, rpIds: [] };
const writes = [];        // 지갑 오리진의 localStorage·sessionStorage 쓰기 전부(키·값)
const consoleLines = [];  // 모든 페이지의 콘솔 출력
const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
async function waitText(page, sel, needle, timeout = 30_000) {
  try { await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout }); }
  catch { throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`); }
}
/** 스텁 컨텍스트 — 모든 페이지(팝업·IdP 포함)에 같은 패스키. 호출 수·RP ID 는 하네스(hits)가, 저장소 쓰기는 writes 가 센다. */
async function stubContext(opts) {
  const ctx = await browser.newContext();
  await ctx.exposeFunction('__webauthnHit', (k, rpId) => { hits[k] = (hits[k] ?? 0) + 1; hits.rpIds.push(rpId); });
  await ctx.exposeFunction('__storageHit', (origin, kind, k, v) => { if (origin === WALLET_ORIGIN) writes.push({ kind, k, v }); });
  await ctx.addInitScript({ content: buildWebAuthnStub(opts) });
  await ctx.addInitScript(() => {
    const orig = Storage.prototype.setItem;
    Storage.prototype.setItem = function (k, v) {
      try { window.__storageHit?.(location.origin, this === window.sessionStorage ? 'session' : 'local', String(k), String(v)); } catch { /* 하네스 없음 */ }
      return orig.call(this, k, v);
    };
  });
  ctx.on('dialog', (d) => d.accept());
  ctx.on('page', (p) => {
    p.on('console', (m) => { consoleLines.push(m.text()); if (DEBUG) console.log(`    [${new URL(p.url()).port}] ${m.type()}: ${m.text()}`); });
    if (DEBUG) p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`));
  });
  return ctx;
}
const idbDump = (page) => page.evaluate(async () => { const open = indexedDB.open('mode3-user', 1); open.onupgradeneeded = () => { if (!open.result.objectStoreNames.contains('kv')) open.result.createObjectStore('kv'); }; const db = await new Promise((r, x) => { open.onsuccess = () => r(open.result); open.onerror = () => x(open.error); }); const st = db.transaction('kv', 'readonly').objectStore('kv'); const keys = await new Promise((r) => { const q = st.getAllKeys(); q.onsuccess = () => r(q.result); }); const out = {}; for (const k of keys) out[k] = await new Promise((r) => { const q = st.get(k); q.onsuccess = () => r(q.result); }); db.close(); return JSON.parse(JSON.stringify(out, (k, v) => (v instanceof CryptoKey ? '[CryptoKey]' : v))); });
/** 패스키 연결을 IndexedDB 에 직접 둔다(설정 카드는 Task 7) — kv `passkey` 는 공개값(credential ID)이다. */
const putPasskey = (page, credentialId) => page.evaluate(async (cid) => { const open = indexedDB.open('mode3-user', 1); open.onupgradeneeded = () => { if (!open.result.objectStoreNames.contains('kv')) open.result.createObjectStore('kv'); }; const db = await new Promise((r, x) => { open.onsuccess = () => r(open.result); open.onerror = () => x(open.error); }); await new Promise((r, x) => { const q = db.transaction('kv', 'readwrite').objectStore('kv').put({ credentialId: cid, createdAt: Date.now() }, 'passkey'); q.onsuccess = () => r(); q.onerror = () => x(q.error); }); db.close(); }, credentialId);
/** 속성 도구가 남기는 기록 — 데모 리셋 표시(reset.json)의 epoch 를 본 것으로 맞춰 둔다(readAttrRecord 가 지우지 않게). */
const putAttrRecord = (page, s_u) => page.evaluate(async (r) => {
  try { const x = await fetch('/attr/dist/reset.json', { cache: 'no-store' }); if (x.ok) localStorage.setItem('mode3_attr_tool_reset', String((await x.json()).epoch ?? '')); } catch { /* 없으면 그대로 */ }
  localStorage.setItem('mode3_attr_tool_v1', JSON.stringify(r));
}, { version: 5, s_u, profile: { birthYear: '1990', country: 'KR' } });
const openUserPage = async (ctx) => { const p = await ctx.newPage(); await p.goto(`${wallet.base}/`); await p.waitForSelector('#mainView:not([hidden])'); return p; };
const idpLogin = async (page) => { if (await page.$eval('#loginBtn', (b) => b.hidden)) { await page.click('#logoutBtn'); await page.waitForSelector('#loginBtn:not([hidden])'); } await page.click('#loginBtn'); await page.click('#idpLoginBtn'); };
const approve = async (popup) => { await popup.waitForSelector('#authApproveBtn:not([hidden])', { timeout: 60_000 }); await popup.click('#authApproveBtn'); };
const atIdpLogin = (popup) => popup.waitForURL((x) => x.origin === cia.base && x.pathname === '/login' && x.searchParams.get('return') === '1', { timeout: 60_000 });
const backAtWallet = (popup) => popup.waitForURL((x) => x.origin === WALLET_ORIGIN && x.searchParams.get('authorize') === '1', { timeout: 30_000 });
const fillIdp = async (popup) => { await popup.fill('#authUid', 'pk-user'); await popup.fill('#authPwd', DEMO_PWD); await popup.fill('#authAuid', AUID_A); await popup.click('#authGo'); };
/** RP 페이지가 사용자 오리진에서 받은 메시지 전부(postMessage 에 salt 가 실리지 않는지 본다). */
const recordWalletMessages = (page) => page.evaluate((origin) => { window.__walletMsgs = []; window.__readyCount = 0; window.addEventListener('message', (ev) => { if (ev.origin !== origin) return; window.__walletMsgs.push(JSON.stringify(ev.data)); if (ev.data?.type === 'mode3-authorize-ready') window.__readyCount++; }); }, WALLET_ORIGIN);

try {
  assert.equal((await wallet.get('/user/config')).body.secrets, 'passkey-web');
  const ctxA = await stubContext({ secretHex: SECRET_A });
  // zkID 가입(아이디·비밀번호) — 지갑과 무관하다(IdP /user 화면)
  {
    const u = await ctxA.newPage(); await u.goto(`${cia.base}/user`);
    await u.click('#showSignupBtn'); await u.fill('#signupId', 'pk-user'); await u.fill('#signupPwd', DEMO_PWD); await u.fill('#signupPwd2', DEMO_PWD); await u.click('#signupBtn');
    await waitText(u, '#userVerdict', '가입했습니다'); await u.close();
  }
  const userPage = await openUserPage(ctxA);
  await putPasskey(userPage, stubCredId(SECRET_A));
  const rpPage = await ctxA.newPage();
  await rpPage.goto(rp.base);
  await recordWalletMessages(rpPage);
  const curSession = () => rpPage.evaluate(() => (typeof currentSession === 'undefined' ? null : currentSession));

  await t('rp 배지: passkey-web 은 브라우저(패스키)', async () => {
    await waitText(rpPage, '#walletMode', '패스키');
    assert.ok((await text(rpPage, '#walletMode')).includes('브라우저'), await text(rpPage, '#walletMode'));
  });

  await t('속성 도구 기록이 없으면 IdP 로 가지 않는다', async () => {
    const before = hits.get;
    const [popup] = await Promise.all([ctxA.waitForEvent('page'), idpLogin(rpPage)]);
    const visited = [];
    popup.on('framenavigated', (f) => { if (f === popup.mainFrame()) visited.push(f.url()); });
    await approve(popup);
    await waitText(rpPage, '#verdict', '속성 커밋먼트 기록이 없습니다', 30_000);
    assert.equal(await popup.$eval('#authHint a', (a) => a.href), `${WALLET_ORIGIN}/attr.html`, '안내 링크는 같은 오리진의 속성 도구');
    if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 20_000 });
    assert.equal(visited.some((u) => new URL(u).origin === cia.base), false, `팝업이 IdP 로 갔다: ${j(visited)}`);
    assert.equal(hits.get - before, 0, '패스키를 묻지 않았다');
    assert.equal((await idbDump(userPage)).registration, undefined);
  });

  await t('첫 로그인 = 등록: 승인 → 인증 창(등록) → 등록·로그인 성공, 패스키 한 번, rpId localhost', async () => {
    await putAttrRecord(userPage, SALT_A);
    const before = hits.get, rpIdsFrom = hits.rpIds.length;
    const [popup] = await Promise.all([ctxA.waitForEvent('page'), idpLogin(rpPage)]);
    await approve(popup);
    await atIdpLogin(popup);
    assert.equal(new URL(popup.url()).searchParams.get('purpose'), 'register', '미등록이면 등록 모드 인증 창');
    await fillIdp(popup);
    await backAtWallet(popup);
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    assert.equal(hits.get - before, 1, `패스키 계산 ${hits.get - before}번 — 팝업 하나에 한 번이어야 한다`);
    assert.deepEqual(hits.rpIds.slice(rpIdsFrom), ['localhost']);
    const d = await idbDump(userPage);
    assert.equal(String(d.registration?.auid), AUID_A, '패스키 salt 로 등록됐다');
    assert.equal(j(d).includes(SALT_A), false, 'IndexedDB 에 평문 salt 가 있다');
    const stores = await userPage.evaluate(() => { const ls = {}; for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (k !== 'mode3_attr_tool_v1') ls[k] = localStorage.getItem(k); } return JSON.stringify(ls) + JSON.stringify(sessionStorage); });
    assert.equal(stores.includes(SALT_A), false, '브라우저 저장소에 salt 가 있다');
    const leaked = writes.filter((w) => w.k !== 'mode3_attr_tool_v1' && w.v.includes(SALT_A));
    assert.deepEqual(leaked, [], '저장소 쓰기(대기 저장분 포함)에 salt 가 있다');
    assert.ok(writes.some((w) => w.kind === 'session' && w.k === 'mode3.authorize.pending'), '팝업이 IdP 대기 저장분을 남겼다');
    assert.equal((await rpPage.evaluate(() => window.__walletMsgs.join('\n'))).includes(SALT_A), false, 'postMessage 에 salt 가 있다');
    assert.equal(consoleLines.some((l) => l.includes(SALT_A)), false, '콘솔 로그에 salt 가 있다');
  });

  await t('두 번째 로그인: 인증 창(발급) → 패스키 0번(보관분) → 성공', async () => {
    const prev = await curSession();
    const before = hits.get;
    const [popup] = await Promise.all([ctxA.waitForEvent('page'), idpLogin(rpPage)]);
    await approve(popup);
    await atIdpLogin(popup);
    assert.equal(new URL(popup.url()).searchParams.get('purpose'), null, '등록된 브라우저는 발급 인증 창');
    await fillIdp(popup);
    await rpPage.waitForFunction((p) => typeof currentSession !== 'undefined' && currentSession && currentSession !== p, prev, { timeout: 180_000 });
    await waitText(rpPage, '#verdict', '로그인 성공', 60_000);
    assert.equal(hits.get - before, 0, '10분 보관분으로 패스키를 묻지 않는다');
  });

  await t('재검증·잔액 확인·출금: 보관분으로 패스키 없이 성공', async () => {
    const before = hits.get;
    const [rvPopup, rv] = await Promise.all([ctxA.waitForEvent('page'), rpPage.evaluate(() => popupCall('mode3-revalidate', { arid: info.arid, origin: info.origin, r_s: currentSession }))]);
    assert.equal(rv.ok, true, j(rv));
    if (!rvPopup.isClosed()) await rvPopup.waitForEvent('close', { timeout: 15_000 }).catch(() => {});
    const [balPopup] = await Promise.all([ctxA.waitForEvent('page'), rpPage.click('#balanceBtn')]);
    await approve(balPopup);
    await waitText(rpPage, '#ledgerVerdict', '세션 요청 성공', 60_000);
    await rpPage.fill('#txTo', '0x000000000000000000000000000000000000dEaD'); await rpPage.fill('#txValue', '0');
    const [txPopup] = await Promise.all([ctxA.waitForEvent('page'), rpPage.click('#txBtn')]);
    await approve(txPopup);
    await waitText(rpPage, '#txVerdict', '전송 성공', 180_000);
    assert.ok((await text(rpPage, '#txLog')).includes('txHash='), await text(rpPage, '#txLog'));
    assert.equal(hits.get - before, 0, '보관분으로 패스키 없이');
  });

  // ---- 새 컨텍스트·미등록 ----
  const ctxC = await stubContext({ secretHex: SECRET_C });
  const userC = await openUserPage(ctxC);
  const rpC = await ctxC.newPage(); await rpC.goto(rp.base);
  await t('패스키 연결이 없으면 IdP 로 가지 않는다(passkey_setup_required)', async () => {
    const before = hits.get;
    const [popup] = await Promise.all([ctxC.waitForEvent('page'), idpLogin(rpC)]);
    const visited = [];
    popup.on('framenavigated', (f) => { if (f === popup.mainFrame()) visited.push(f.url()); });
    await approve(popup);
    await waitText(rpC, '#verdict', '패스키를 먼저 설정해야 합니다', 30_000);
    if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 20_000 });
    assert.equal(visited.some((u) => new URL(u).origin === cia.base), false, `팝업이 IdP 로 갔다: ${j(visited)}`);
    assert.equal(hits.get - before, 0);
  });

  await t('돌아온 길 nonce 불일치: 이어받지 않고 ready 를 다시 보내지 않는다', async () => {
    await putPasskey(userC, stubCredId(SECRET_C));
    await putAttrRecord(userC, SALT_C);
    await recordWalletMessages(rpC);
    const [popup] = await Promise.all([ctxC.waitForEvent('page'), idpLogin(rpC)]);
    await approve(popup);
    await atIdpLogin(popup);
    assert.equal(await rpC.evaluate(() => window.__readyCount), 1);
    await popup.goto(`${wallet.base}/?authorize=1&idp_nonce=bad&idp_code=bad&idp_purpose=register&idp_uid=1`);
    await waitText(popup, '#authStep', '이어받지 못했습니다', 30_000);
    assert.equal(new URL(popup.url()).search, '?authorize=1', '1회용 코드가 주소창에 남지 않는다');
    await popup.waitForTimeout(1500);
    assert.equal(await rpC.evaluate(() => window.__readyCount), 1, '돌아온 팝업이 ready 를 다시 보냈다');
    assert.equal(await popup.isHidden('#authApproveBtn'), true, '승인 버튼을 다시 띄우지 않는다');
    assert.equal((await idbDump(userC)).registration, undefined, '등록되지 않았다');
    const pending = await popup.evaluate(() => sessionStorage.getItem('mode3.authorize.pending'));
    assert.equal(pending, null, '대기 저장분은 지워졌다');
    await popup.close();
  });
  await ctxC.close();

  await t('데모 세대가 바뀌면 등록은 지우고 패스키 연결은 남긴다', async () => {
    const cid = stubCredId(SECRET_A);
    assert.ok((await idbDump(userPage)).registration, '앞 케이스의 등록이 있다');
    await stack.restartWallet({ MODE3_DEMO_GENERATION: 'g1' });
    await userPage.reload(); await userPage.waitForSelector('#mainView:not([hidden])');
    await userPage.waitForFunction(async () => { const open = indexedDB.open('mode3-user', 1); const db = await new Promise((r) => { open.onsuccess = () => r(open.result); }); const v = await new Promise((r) => { const q = db.transaction('kv', 'readonly').objectStore('kv').get('demoGeneration'); q.onsuccess = () => r(q.result); }); db.close(); return v === 'g1'; }, undefined, { timeout: 15_000, polling: 300 });
    assert.ok((await idbDump(userPage)).registration, '처음 본 번호로는 지우지 않는다');
    await stack.restartWallet({ MODE3_DEMO_GENERATION: 'g2' });
    await userPage.reload(); await userPage.waitForSelector('#mainView:not([hidden])');
    await userPage.waitForFunction(async () => { const open = indexedDB.open('mode3-user', 1); const db = await new Promise((r) => { open.onsuccess = () => r(open.result); }); const v = await new Promise((r) => { const q = db.transaction('kv', 'readonly').objectStore('kv').get('demoGeneration'); q.onsuccess = () => r(q.result); }); db.close(); return v === 'g2'; }, undefined, { timeout: 15_000, polling: 300 });
    const d = await idbDump(userPage);
    assert.equal(d.registration, undefined, '등록은 지웠다');
    assert.equal(d.passkey?.credentialId, cid, '패스키 연결은 남는다');
  });
} finally {
  await browser.close().catch(() => {});
  await stack.stop();
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed === 0 ? 0 : 1);
