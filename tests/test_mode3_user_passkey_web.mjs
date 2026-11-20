// passkey-web(스펙 2026-11-17-mode3-passkey-web) — 웹 모드 사용자 페이지의 승인 팝업이 IdP 인증 창을 다녀오고 salt 를 패스키에서 받는다(저장하지 않는다 — 2026-11-20: 10분 보관 제거).
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
const stack = await startIsolatedMode3Stack({ userMode: 'web', walletHost: 'localhost', walletEnv: { MODE3_WALLET_SECRETS: 'passkey-web', MODE3_EXPLORER_URL: 'http://127.0.0.1:4000' }, ciaEnv: { CIA_ISSUE_AUTH: 'code', MODE3_WALLET_KIND: 'passkey-web' }, rpEnv: { MODE3_WALLET_KIND: 'passkey-web' }, autoRelay: true });   // MODE3_WALLET_KIND: 분리 데모 스크립트가 IdP·서비스에 넘기는 값(화면 문구용)
const { cia, wallet, rp } = stack;
const WALLET_ORIGIN = new URL(wallet.base).origin;
const SECRET_A = 'a1'.repeat(32), SECRET_C = 'c3'.repeat(32), SECRET_D = 'd4'.repeat(32), SECRET_P = 'e5'.repeat(32);
const SALT_A = stubSalt(SECRET_A), SALT_C = stubSalt(SECRET_C), SALT_D = stubSalt(SECRET_D);
const AUID_A = (await auidOf({ s_u: BigInt(SALT_A) })).toString();
const DEMO_PWD = 'demo-pass-9';
const hits = { create: 0, get: 0, rpIds: [], opts: [] };
const writes = [];        // 지갑 오리진의 localStorage·sessionStorage 쓰기 전부(키·값)
const consoleLines = [];  // 모든 페이지의 콘솔 출력
const cspHits = [];       // 지갑 오리진 문서의 CSP 위반(securitypolicyviolation) 전부 — 정상 흐름에서는 0건이어야 한다(마지막 케이스)
/** CSP 위반 기록기 — 문서가 위반을 알리면 하네스로 보낸다. 지갑 오리진만 모은다. */
async function recordCsp(ctx) {
  await ctx.exposeFunction('__cspHit', (origin, directive, blocked, sample) => { if (origin === WALLET_ORIGIN) cspHits.push({ directive, blocked, sample }); });
  await ctx.addInitScript(() => { document.addEventListener('securitypolicyviolation', (e) => { try { window.__cspHit?.(location.origin, e.effectiveDirective, e.blockedURI, e.sample); } catch { /* 하네스 없음 */ } }); });
}
const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
async function waitText(page, sel, needle, timeout = 30_000) {
  try { await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout }); }
  catch { throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`); }
}
/** 스텁 컨텍스트 — 모든 페이지(팝업·IdP 포함)에 같은 패스키. 호출 수·RP ID 는 하네스(hits)가, 저장소 쓰기는 writes 가 센다. */
async function stubContext(opts) {
  const ctx = await browser.newContext();
  await ctx.exposeFunction('__webauthnHit', (k, rpId, o) => { hits[k] = (hits[k] ?? 0) + 1; hits.rpIds.push(rpId); hits.opts.push(o ?? null); });
  await ctx.exposeFunction('__storageHit', (origin, kind, k, v) => { if (origin === WALLET_ORIGIN) writes.push({ kind, k, v }); });
  await recordCsp(ctx);
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
/** 패스키 연결을 IndexedDB 에 직접 둔다(설정 카드를 거치지 않는 케이스용 — 설정 카드는 아래 Task 7 케이스가 본다). kv `passkey` 는 공개값(credential ID)이다. */
const putPasskey = (page, credentialId) => page.evaluate(async (cid) => { const open = indexedDB.open('mode3-user', 1); open.onupgradeneeded = () => { if (!open.result.objectStoreNames.contains('kv')) open.result.createObjectStore('kv'); }; const db = await new Promise((r, x) => { open.onsuccess = () => r(open.result); open.onerror = () => x(open.error); }); await new Promise((r, x) => { const q = db.transaction('kv', 'readwrite').objectStore('kv').put({ credentialId: cid, createdAt: Date.now() }, 'passkey'); q.onsuccess = () => r(); q.onerror = () => x(q.error); }); db.close(); }, credentialId);
/** 속성 도구가 남기는 기록 — 데모 리셋 표시(reset.json)의 epoch 를 본 것으로 맞춰 둔다(readAttrRecord 가 지우지 않게). */
const putAttrRecord = (page, s_u) => page.evaluate(async (r) => {
  try { const x = await fetch('/attr/dist/reset.json', { cache: 'no-store' }); if (x.ok) localStorage.setItem('mode3_attr_tool_reset', String((await x.json()).epoch ?? '')); } catch { /* 없으면 그대로 */ }
  localStorage.setItem('mode3_attr_tool_v1', JSON.stringify(r));
}, { version: 5, s_u, profile: { birthYear: '1990', country: 'KR' } });
/** 예전 버전이 남긴 10분 보관분(kv passkeyHold) 모양의 레코드를 심는다 — 새 코어가 읽지 않고 지우는지 본다(2026-11-20: 보관 제거). */
const putOldHold = (page) => page.evaluate(async () => { const open = indexedDB.open('mode3-user', 1); const db = await new Promise((r, x) => { open.onsuccess = () => r(open.result); open.onerror = () => x(open.error); }); await new Promise((r, x) => { const q = db.transaction('kv', 'readwrite').objectStore('kv').put({ until: Date.now() + 600_000, box: { iv: 'AAAA', ct: 'AAAA' } }, 'passkeyHold'); q.onsuccess = () => r(); q.onerror = () => x(q.error); }); db.close(); });
const openUserPage = async (ctx) => { const p = await ctx.newPage(); await p.goto(`${wallet.base}/`); await p.waitForSelector('#mainView:not([hidden])'); return p; };
const idpLogin = async (page) => { if (await page.$eval('#loginBtn', (b) => b.hidden)) { await page.click('#logoutBtn'); await page.waitForSelector('#loginBtn:not([hidden])'); } await page.click('#loginBtn'); await page.click('#idpLoginBtn'); };
// 2026-11-18(사용자 요청): passkey-web 의 승인 창은 승인·거절 단계가 없다(/user/config popupConsent false) — 아래 각본은 아무도 승인 버튼을 누르지 않고 끝까지 간다.
const atIdpLogin = (popup) => popup.waitForURL((x) => x.origin === cia.base && x.pathname === '/login' && x.searchParams.get('return') === '1', { timeout: 60_000 });
const backAtWallet = (popup) => popup.waitForURL((x) => x.origin === WALLET_ORIGIN && x.searchParams.get('authorize') === '1', { timeout: 30_000 });
const fillIdp = async (popup) => { await popup.fill('#authUid', 'pk-user'); await popup.fill('#authPwd', DEMO_PWD); await popup.fill('#authAuid', AUID_A); await popup.click('#authGo'); };
/** RP 페이지가 사용자 오리진에서 받은 메시지 전부(postMessage 에 salt 가 실리지 않는지 본다). */
const recordWalletMessages = (page) => page.evaluate((origin) => { window.__walletMsgs = []; window.__readyCount = 0; window.addEventListener('message', (ev) => { if (ev.origin !== origin) return; window.__walletMsgs.push(JSON.stringify(ev.data)); if (ev.data?.type === 'mode3-authorize-ready') window.__readyCount++; }); }, WALLET_ORIGIN);

try {
  assert.equal((await wallet.get('/user/config')).body.secrets, 'passkey-web');
  const ctxA = await stubContext({ secretHex: SECRET_A });
  // zkIdP 가입(아이디·비밀번호) — 지갑과 무관하다(IdP /user 화면)
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

  // 2026-11-17: 지갑 오리진 CSP — 페이지에 끼워 넣은 인라인 스크립트·인라인 처리기·남의 오리진 스크립트는 돌지 않고 위반 이벤트가 난다.
  // (page.evaluate·addInitScript 는 DevTools 경로라 CSP 와 무관하다 — 그래서 하네스는 그대로 돈다.)
  await t('CSP: 끼워 넣은 인라인·남의 오리진 스크립트는 돌지 않는다(위반 이벤트)', async () => {
    const before = cspHits.length;
    const r = await userPage.evaluate(async (foreign) => {
      const seen = [];
      const done = new Promise((resolve) => { document.addEventListener('securitypolicyviolation', (e) => { seen.push(e.effectiveDirective); if (seen.length >= 3) resolve(); }); setTimeout(resolve, 5000); });
      const s1 = document.createElement('script'); s1.textContent = 'window.__injected = "inline";'; document.body.appendChild(s1);
      const img = document.createElement('img'); img.setAttribute('onerror', 'window.__injected2 = "attr";'); img.src = 'data:,x'; document.body.appendChild(img);
      const s2 = document.createElement('script'); s2.src = `${foreign}/common/demo.js`; document.body.appendChild(s2);
      await done;
      return { seen: seen.sort(), inline: window.__injected ?? null, attr: window.__injected2 ?? null };
    }, cia.base);
    assert.equal(r.inline, null, '인라인 <script> 가 돌았다'); assert.equal(r.attr, null, '인라인 처리기가 돌았다');
    assert.deepEqual(r.seen, ['script-src-attr', 'script-src-elem', 'script-src-elem'], j(r));
    cspHits.length = before;   // 이 케이스가 일부러 낸 위반은 마지막 "위반 0건" 검사에서 뺀다
  });

  await t('속성 도구 기록이 없으면 IdP 로 가지 않는다', async () => {
    const before = hits.get;
    const [popup] = await Promise.all([ctxA.waitForEvent('page'), idpLogin(rpPage)]);
    const visited = [];
    popup.on('framenavigated', (f) => { if (f === popup.mainFrame()) visited.push(f.url()); });
    await waitText(rpPage, '#verdict', '속성 커밋먼트 기록이 없습니다', 30_000);
    assert.equal(await popup.$eval('#authHint a', (a) => a.href), `${WALLET_ORIGIN}/attr.html`, '안내 링크는 같은 오리진의 속성 도구');
    if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 20_000 });
    assert.equal(visited.some((u) => new URL(u).origin === cia.base), false, `팝업이 IdP 로 갔다: ${j(visited)}`);
    assert.equal(hits.get - before, 0, '패스키를 묻지 않았다');
    assert.equal((await idbDump(userPage)).registration, undefined);
  });

  // ---- 로그인 전체 플로우 카드(스펙 2026-11-19 login-flow-and-phone-passkey F6) ----
  const FLOW_KEYS = ['request', 'check_service', 'passkey', 'sync', 'random', 'session_key', 'commit', 'pseudonym', 'prove_idp', 'issue', 'publish_wait', 'prove_session', 'sign', 'respond'];
  await t('로그인 전체 플로우 카드: 로그인 전에는 단계의 의미만 — 시간·값이 없고, 단계를 누르면 설명이 펴진다', async () => {
    // 기본은 접혀 있다(요약만) — 단계가 열넷이라 펴 두면 아래 카드가 밀린다. 펴면 그 상태를 기억한다.
    await userPage.waitForSelector('#flowFigure .seq-step[data-step="prove_session"]', { state: 'attached', timeout: 15_000 });
    assert.equal(await userPage.$eval('#flowDetails', (x) => x.open), false, '기본은 접힘');
    assert.ok(await userPage.$eval('#flowCard', (x) => x.getBoundingClientRect().height) < 260, '접힌 카드는 낮다');
    await userPage.click('#flowDetails > summary');
    await userPage.waitForSelector('#flowFigure .seq-step[data-step="prove_session"]', { timeout: 15_000 });
    await userPage.waitForFunction(() => localStorage.getItem('mode3_flow_open') === '1', null, { timeout: 5000 });   // toggle 이벤트는 다음 틱에 온다
    assert.deepEqual(await userPage.$$eval('#flowFigure .seq-step', (l) => l.map((x) => x.dataset.step)), FLOW_KEYS);
    assert.equal(await userPage.$$eval('#flowFigure .seq-time', (l) => l.length), 0, '시간이 없다');
    await waitText(userPage, '#flowSummary', '로그인한 적이 없습니다');
    assert.deepEqual(await userPage.$$eval('#flowFigure .seq-lane strong', (l) => l.map((x) => x.textContent)), ['서비스', 'zk 클라이언트', 'zkIdP']);
    assert.equal(await userPage.$eval('#flowFigure .seq-step[data-step="issue"]', (x) => x.dataset.kind), 'arrow');
    assert.equal(await userPage.$eval('#flowFigure .seq-step[data-step="commit"]', (x) => x.dataset.kind), 'self');
    // 화살표는 보내는 쪽 세로선(줄의 가운데)에서 받는 쪽 세로선까지다(2026-11-19 화면 셀프 리뷰)
    const geo = await userPage.evaluate(() => {
      const mid = (k) => { const r = document.querySelector(`#flowFigure .seq-lane[data-lane="${k}"]`).getBoundingClientRect(); return r.left + r.width / 2; };
      const ends = (k) => { const r = document.querySelector(`#flowFigure .seq-step[data-step="${k}"] .seq-box`).getBoundingClientRect(); return [r.left, r.right]; };
      return { rp: mid('rp'), user: mid('user'), idp: mid('idp'), request: ends('request'), issue: ends('issue'), respond: ends('respond') };
    });
    const near = (a, b) => Math.abs(a - b) <= 3;
    assert.ok(near(geo.request[0], geo.rp) && near(geo.request[1], geo.user) && near(geo.respond[0], geo.rp) && near(geo.respond[1], geo.user), j(geo));
    assert.ok(near(geo.issue[0], geo.user) && near(geo.issue[1], geo.idp), j(geo));
    await userPage.click('#flowFigure .seq-step[data-step="pseudonym"] summary');
    await waitText(userPage, '#flowFigure .seq-step[data-step="pseudonym"] .seq-body', 'zkIdP 는 arid_s 만 보므로');
    assert.equal(await userPage.$$eval('#flowFigure .seq-step[data-step="pseudonym"] .flow-items dt', (l) => l.length), 0, '값이 없다');
  });

  await t('첫 로그인 = 등록: 승인 단계 없이 인증 창(등록) → 등록·로그인 성공, 패스키 한 번, rpId localhost', async () => {
    await putAttrRecord(userPage, SALT_A);
    const before = hits.get, rpIdsFrom = hits.rpIds.length;
    const [popup] = await Promise.all([ctxA.waitForEvent('page'), idpLogin(rpPage)]);
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
    // 리뷰 2026-11-19 I-1: 첫 로그인의 패스키는 등록하면서(로그인 함수 전에) 물었다 — 플로우 카드가 그 시간을 "전체" 의 일부처럼 말하지 않는다
    const pk = (await idbDump(userPage)).loginFlow.steps.find((x) => x.key === 'passkey');
    assert.equal(pk.before, true, j(pk)); assert.equal(pk.held, false);
    await userPage.bringToFront();
    await waitText(userPage, '#flowSummary', '패스키는 로그인 전에 확인', 20_000);
    await waitText(userPage, '#flowFigure .seq-step[data-step="passkey"]', '전체 시간에는 넣지 않습니다');
    assert.equal(await userPage.$$eval('#flowFigure .seq-step[data-step="passkey"] .seq-bar', (l) => l.length), 0, '전체 대비 막대를 그리지 않는다');
    await rpPage.bringToFront();
  });

  await t('두 번째 로그인: 인증 창(발급) → 패스키 한 번(저장해 둔 salt 가 없다) → 성공', async () => {
    const prev = await curSession();
    const before = hits.get;
    const [popup] = await Promise.all([ctxA.waitForEvent('page'), idpLogin(rpPage)]);
    await atIdpLogin(popup);
    assert.equal(new URL(popup.url()).searchParams.get('purpose'), null, '등록된 브라우저는 발급 인증 창');
    await fillIdp(popup);
    await rpPage.waitForFunction((p) => typeof currentSession !== 'undefined' && currentSession && currentSession !== p, prev, { timeout: 180_000 });
    await waitText(rpPage, '#verdict', '로그인 성공', 60_000);
    assert.equal(hits.get - before, 1, `패스키 계산 ${hits.get - before}번 — 로그인마다 한 번이어야 한다`);
    assert.equal((await idbDump(userPage)).passkeyHold, undefined, 'IndexedDB 에 salt 보관분이 있다');
  });

  await t('로그인 전체 플로우 카드: 로그인 뒤에는 가장 최근 로그인의 시간·실제 값 — 저장된 세션의 가명과 같고, 펴 둔 단계는 그대로, salt 는 없다', async () => {
    await userPage.bringToFront();
    await waitText(userPage, '#flowSummary', '가장 최근 로그인', 20_000);
    const d = await idbDump(userPage);
    const f = d.loginFlow; assert.ok(f, 'kv loginFlow');
    assert.equal(f.values.r_s, String(await curSession()), '기록은 방금(두 번째) 로그인의 것이다');
    // 카드는 2초마다 다시 읽는다 — 첫 로그인의 그림이 아니라 이 기록을 그릴 때까지 기다린다
    await userPage.waitForFunction((at) => document.querySelector('#flowSummary')?.dataset.flowAt === String(at), f.at, { timeout: 20_000 });
    assert.equal(j(f).includes(SALT_A), false, '기록에 salt 가 있다');
    const s = d.sessions[f.values.r_s]; assert.ok(s, '기록의 r_s 가 저장된 세션이다');
    for (const k of ['prove_idp', 'prove_session', 'issue', 'pseudonym', 'session_key', 'commit', 'sync', 'check_service', 'sign']) {
      assert.match(await userPage.$eval(`#flowFigure [data-seq-time="${k}"]`, (x) => x.textContent), /^<?[\d.]+(ms|s)$/, k);
    }
    assert.equal(await userPage.$$eval('#flowFigure [data-seq-time="request"], #flowFigure [data-seq-time="respond"]', (l) => l.length), 0, '서비스 쪽 단계는 재지 않는다');
    // 게시 대기는 기다렸을 때만 기록된다(새 C_u 가 아니어도 거울 중계가 늦으면 잠깐 기다린다) — 기록이 없으면 흐리게 "없었습니다", 있으면 시간
    const waited = f.steps.some((x) => x.key === 'publish_wait');
    assert.equal(await userPage.$eval('#flowFigure .seq-step[data-step="publish_wait"]', (x) => x.classList.contains('seq-dim')), !waited);
    if (waited) assert.equal(await userPage.$$eval('#flowFigure [data-seq-time="publish_wait"]', (l) => l.length), 1);
    else await waitText(userPage, '#flowFigure .seq-step[data-step="publish_wait"]', '이번 로그인에는 없었습니다');
    // 두 번째 로그인의 패스키는 로그인 안에서 물었다 — 시간이 보이고 "보관분 사용"·"로그인 전에 확인" 같은 덧말이 없다
    assert.match(await userPage.$eval('#flowFigure [data-seq-time="passkey"]', (x) => x.textContent), /^<?[\d.]+(ms|s)$/, 'passkey');
    assert.equal(/보관분|전체 시간에는 넣지 않습니다/.test(await text(userPage, '#flowFigure .seq-step[data-step="passkey"]')), false, await text(userPage, '#flowFigure .seq-step[data-step="passkey"]'));
    const pk2 = f.steps.find((x) => x.key === 'passkey'); assert.equal(pk2.held, false, j(pk2)); assert.equal(pk2.before, undefined, j(pk2));
    // 앞 케이스에서 펴 둔 단계가 다시 그려도 펴져 있고, 이제 실제 값이 있다
    assert.equal(await userPage.$eval('#flowFigure .seq-step[data-step="pseudonym"] details', (x) => x.open), true);
    assert.equal(await userPage.$eval('#flowFigure .seq-step[data-step="pseudonym"] code[data-flow="auid_s"]', (x) => x.title), String(s.auid_s));
    assert.equal(await userPage.$eval('#flowFigure .seq-step[data-step="pseudonym"] code[data-flow="arid_s"]', (x) => x.title), String(s.arid_s));
    await userPage.click('#flowFigure .seq-step[data-step="respond"] summary');
    assert.equal(await userPage.$eval('#flowFigure .seq-step[data-step="respond"] code[data-flow="PPID"]', (x) => x.title), String(s.PPID));
    // 발급(왕복) 단계는 보낸 것과 돌려받은 것을 나눠 적는다 — 보낸 쪽에 uid·가명·봉투, 받은 쪽에 자격증명
    await userPage.click('#flowFigure .seq-step[data-step="issue"] summary');
    assert.deepEqual(await userPage.$$eval('#flowFigure .seq-step[data-step="issue"] .seq-body .flow-sub', (l) => l.map((x) => x.textContent)), ['zkIdP 에 보낸 것 →', '← zkIdP 가 돌려준 것']);
    assert.deepEqual(await userPage.$$eval('#flowFigure .seq-step[data-step="issue"] .seq-body .flow-items', (l) => l.map((dl) => [...dl.querySelectorAll('dt')].map((x) => x.textContent))),
      [['uid', 'auid_s', 'arid_s', 'C_u', 'C_s', 'max_height', 'π_IdP'], ['자격증명', 'zkIdP ID 토큰']]);
    assert.equal(await userPage.$eval('#flowFigure .seq-step[data-step="issue"] code[data-flow="auid_s"]', (x) => x.title), String(s.auid_s));
    // π_IdP 줄의 "증명 보기" 는 그 로그인의 π_IdP 를 증명 창으로 연다(공개 입력에 이 로그인의 auid_s)
    await userPage.click('#flowFigure .seq-step[data-step="issue"] button[data-flow-action="pi_idp"]');
    await userPage.waitForSelector('#proofModal:not([hidden])', { timeout: 10_000 });
    assert.ok((await userPage.$eval('#proofModal', (x) => x.textContent)).includes('π_IdP'), '연 것은 π_IdP 다');
    assert.ok((await idbDump(userPage)).proofs.some((x) => x.kind === 'pi_idp' && x.publicSignals.includes(String(s.auid_s))), '그 로그인의 π_IdP 기록이 있다');
    await userPage.click('#proofCloseBtn'); await userPage.waitForSelector('#proofModal', { state: 'hidden' });
    // 카드는 "보낸 트랜잭션" 위에 있다(시연에서 로그인 직후 바로 보이게)
    assert.equal(await userPage.evaluate(() => Boolean(document.querySelector('#flowCard').compareDocumentPosition(document.querySelector('#txsCard')) & Node.DOCUMENT_POSITION_FOLLOWING)), true);
    assert.equal((await userPage.$eval('#flowCard', (x) => x.textContent)).includes(SALT_A), false, '카드에 salt 가 있다');
    await waitText(userPage, '#flowSummary', '영지식 증명');
  });

  await t('재검증·잔액 확인·출금: 재검증·출금은 창마다 패스키 한 번, 잔액 확인(세션키 서명)은 묻지 않는다', async () => {
    let before = hits.get;
    const [rvPopup, rv] = await Promise.all([ctxA.waitForEvent('page'), rpPage.evaluate(() => popupCall('mode3-revalidate', { arid: info.arid, origin: info.origin, r_s: currentSession }))]);
    assert.equal(rv.ok, true, j(rv));
    if (!rvPopup.isClosed()) await rvPopup.waitForEvent('close', { timeout: 15_000 }).catch(() => {});
    assert.equal(hits.get - before, 1, `재검증: 패스키 ${hits.get - before}번`);
    before = hits.get;
    const [balPopup] = await Promise.all([ctxA.waitForEvent('page'), rpPage.click('#balanceBtn')]);
    await waitText(rpPage, '#ledgerVerdict', '세션 요청 성공', 60_000);
    assert.equal(hits.get - before, 0, '잔액 확인은 salt 가 필요 없다 — 패스키를 묻지 않는다');
    await rpPage.fill('#txTo', '0x000000000000000000000000000000000000dEaD'); await rpPage.fill('#txValue', '0');
    const [txPopup] = await Promise.all([ctxA.waitForEvent('page'), rpPage.click('#txBtn')]);
    await waitText(rpPage, '#txVerdict', '전송 성공', 180_000);
    assert.ok((await text(rpPage, '#txLog')).includes('txHash='), await text(rpPage, '#txLog'));
    assert.equal(hits.get - before, 1, `출금: 패스키 ${hits.get - before}번`);
    assert.equal((await idbDump(userPage)).passkeyHold, undefined, 'IndexedDB 에 salt 보관분이 있다');
  });

  // 2026-11-18(사용자 요청, 화면을 보고): passkey-web 에 없는 것은 화면에서 숨긴다 — Race (2) 시연(에이전트 전용)·allowAgent 줄(에이전트 대리 전송).
  await t('이 모드에 없는 것은 숨긴다: 서비스의 Race (2) 시연 체크박스, 사용자 페이지의 allowAgent 줄; 출금 설명은 "확인하면" 이 아니다', async () => {
    await rpPage.bringToFront();
    await rpPage.waitForFunction(() => document.documentElement.dataset.walletKind === 'passkey-web', null, { timeout: 15_000 });
    assert.equal(await rpPage.isVisible('#txBtn'), true, '출금 버튼은 보인다(로그인한 상태)');
    assert.equal(await rpPage.isVisible('#raceHold'), false, 'Race (2) 체크박스가 보인다');
    assert.equal(await rpPage.isVisible('#raceToggleBtn'), false, '"시연 숨기기" 버튼이 보인다');
    assert.equal((await rpPage.evaluate(() => document.body.innerText)).includes('Race (2)'), false, 'Race (2) 글자가 보인다');
    // 체크가 남아 있어도(다른 모드에서 켜 둔 값) 이 모드에서는 "멈춤" 을 보내지 않는다
    assert.equal(await rpPage.evaluate(() => { document.getElementById('raceHold').checked = true; const on = raceHoldOn(); document.getElementById('raceHold').checked = false; return on; }), false);
    const desc = await rpPage.evaluate(() => window.Demo.t('rp_tx_desc'));
    assert.ok(!desc.includes('확인하면') && desc.includes('zk 클라이언트'), desc);
    await userPage.bringToFront();
    await userPage.waitForSelector('#sessionsCard dl', { timeout: 15_000 });
    assert.equal((await userPage.$eval('#sessionsCard', (el) => el.innerText)).includes('allowAgent'), false, '연결된 서비스에 allowAgent 줄이 보인다');
    assert.ok(!(await userPage.$eval('#storagePanel', (el) => el.innerText)).includes('복구 코드'), '보관 상태 설명이 이 모드에 없는 복구 코드를 말한다');
    // 서비스 로그인 창: 이 모드에서 동작하지 않는 Google·네이버 버튼은 보이지 않고 "zkIdP 로 로그인" 만 남는다(새 브라우저 — 로그인 전 화면)
    const ctx = await browser.newContext();
    try {
      const p = await ctx.newPage(); await p.goto(rp.base);
      await p.waitForFunction(() => document.documentElement.dataset.walletKind === 'passkey-web', null, { timeout: 15_000 });
      await p.click('#loginBtn'); await p.waitForSelector('#loginModal:not([hidden])', { timeout: 10_000 });
      assert.equal(await p.isVisible('#idpLoginBtn'), true, '"zkIdP 로 로그인" 은 보인다');
      assert.equal(await p.isVisible('#googleLoginBtn'), false, 'Google 버튼이 보인다');
      assert.equal(await p.isVisible('#naverLoginBtn'), false, '네이버 버튼이 보인다');
      const txt = await p.$eval('#loginModal', (el) => el.innerText); assert.ok(!/Google|네이버/.test(txt), txt);
    } finally { await ctx.close(); }
  });

  // 2026-11-18(사용자 요청 "각 zkp 를 확인할 수 있게"): 사용자 페이지의 "영지식 증명" 카드 — 승인 창(다른 창)에서 만든 증명이 같은 저장소라 여기 보인다.
  await t('영지식 증명 카드: 기본은 π_RP 만·번호 1~7 만 — 전체 보기 29개, 검증 ✓, 값을 바꾸면 ✗, 출금 증명에는 거래 링크, 버튼을 누르면 π_IdP 도', async () => {
    await userPage.bringToFront();
    await userPage.waitForSelector('#proofsList tr[data-proof-purpose="tx"]', { timeout: 30_000 });
    const rows = await userPage.$$eval('#proofsList tbody tr', (rs) => rs.map((r) => [r.dataset.proofKind, r.dataset.proofPurpose, r.cells[1].textContent]));
    assert.ok(rows.length >= 2 && rows.every(([k]) => k === 'pi_cred'), `기본은 π_RP 만: ${j(rows)}`);
    assert.ok(rows.some(([, p]) => p === 'login'), j(rows)); assert.equal(rows[0][2], 'π_RP', '화면 이름은 π_RP(2026-11-20 — 전에는 π_RP)');
    // 보기(로그인 증명): 기본은 번호 1~7(arid … regRoot)
    await userPage.locator('#proofsList tr[data-proof-purpose="login"] .proof-view').first().click();
    await userPage.waitForSelector('#proofModal:not([hidden])');
    const names = () => userPage.$$eval('#proofInputs tbody tr', (rs) => rs.map((r) => r.dataset.pub));
    assert.deepEqual(await names(), ['arid', 'pk_i', 'max_height', 'chainid', 'allowAgent', 'revRoot', 'regRoot']);
    assert.ok((await text(userPage, '#proofInputsTitle')).includes('7/29'), await text(userPage, '#proofInputsTitle'));
    assert.equal(await userPage.isHidden('#proofTxRow'), true, '로그인 증명에는 거래가 없다');
    await userPage.click('#proofMoreBtn');
    assert.equal((await names()).length, 18, '묶음 18줄(2026-11-19 — pk_trace·tag 묶음이 없다)'); assert.equal(await userPage.locator('#proofInputs td.pv code').count(), 29, '값 29개');
    assert.equal((await names()).some((n) => n === 'tag' || n === 'pk_trace'), false, '태그·추적 키 줄이 없다');
    assert.equal((await names())[0], 'PPID');
    await userPage.click('#proofMoreBtn'); assert.equal((await names()).length, 7, '다시 기본만');
    // 검증 ✓ → 값 하나를 바꾸면 ✗ → 원래대로 ✓
    await userPage.click('#proofVerifyBtn'); await waitText(userPage, '#proofVerdict', '유효한 증명입니다', 60_000);
    await userPage.click('#proofEditBtn');
    const cell = '#proofInputs input[data-pub-index="1"]';
    await userPage.fill(cell, (BigInt(await userPage.inputValue(cell)) + 1n).toString());
    await userPage.click('#proofVerifyBtn'); await waitText(userPage, '#proofVerdict', '검증에 실패했습니다', 60_000);
    assert.ok((await text(userPage, '#proofVerdict')).includes('1칸'), await text(userPage, '#proofVerdict'));
    await userPage.fill(cell, '숫자가 아니다');
    await userPage.click('#proofVerifyBtn'); await waitText(userPage, '#proofVerdict', '검증에 실패했습니다', 60_000);
    await userPage.click('#proofResetBtn');
    assert.equal(await userPage.locator('#proofInputs input').count(), 0, '원래대로 — 고치는 칸이 닫힌다');
    await userPage.click('#proofVerifyBtn'); await waitText(userPage, '#proofVerdict', '유효한 증명입니다', 60_000);
    await userPage.click('#proofCloseBtn'); assert.equal(await userPage.isHidden('#proofModal'), true);
    // 출금 증명: 그 증명이 실린 거래의 해시와 탐색기 링크
    {
      const d = await idbDump(userPage);
      const txProofs = (d.proofs ?? []).filter((x) => x.purpose === 'tx').map((x) => ({ txHash: x.txHash ?? null, counter: x.publicSignals[28], r_s: x.r_s }));
      assert.ok(txProofs.some((x) => x.txHash), `저장소의 거래 증명에 해시가 없다: ${j(txProofs)} / txs ${j((d.txs ?? []).map((x) => ({ txHash: x.txHash, nonce: x.nonce })))}`);
    }
    await userPage.locator('#proofsList tr[data-proof-purpose="tx"] .proof-view').first().click();
    await userPage.waitForSelector('#proofTxRow:not([hidden])', { timeout: 15_000 }).catch(async (e) => {
      const d = await idbDump(userPage);
      const st = await userPage.evaluate(() => ({ modalHidden: document.getElementById('proofModal').hidden, title: document.getElementById('proofTitle').textContent, rowHidden: document.getElementById('proofTxRow').hidden, hash: document.getElementById('proofTxHash').textContent, rows: [...document.querySelectorAll('#proofsList tbody tr')].map((r) => r.dataset.proofPurpose) }));
      throw new Error(`${e.message.split('\n')[0]} — 화면 ${j(st)} / 저장소 ${j((d.proofs ?? []).map((x) => [x.kind, x.purpose, x.txHash ? 'tx' : '-', x.at]))}`);
    });
    const txHash = await text(userPage, '#proofTxHash'); assert.match(txHash, /^0x[0-9a-f]{64}$/);
    assert.ok((await text(rpPage, '#txLog')).includes(txHash), '서비스 화면의 그 거래다');
    assert.equal(await userPage.getAttribute('#proofTxLink', 'href'), `http://127.0.0.1:4000/tx/${txHash}`);
    await userPage.click('#proofVerifyBtn'); await waitText(userPage, '#proofVerdict', '유효한 증명입니다', 60_000);
    await userPage.click('#proofCloseBtn');
    // π_IdP 도 보기: 등록·세션 발급 증명이 더 보이고, 공개 입력 10개(묶음 8줄)가 전부 보인다
    await userPage.click('#proofsKindBtn');
    const all = await userPage.$$eval('#proofsList tbody tr', (rs) => rs.map((r) => [r.dataset.proofKind, r.dataset.proofPurpose]));
    assert.ok(all.some(([k, p]) => k === 'pi_idp' && p === 'register') && all.some(([k, p]) => k === 'pi_idp' && p === 'issue'), j(all));
    await userPage.locator('#proofsList tr[data-proof-kind="pi_idp"] .proof-view').first().click();
    await waitText(userPage, '#proofTitle', 'π_IdP', 15_000);   // 창은 기록을 다시 읽은 뒤에 열린다
    assert.deepEqual(await names(), ['uid', 'auid', 'auid_s', 'C_u', 'C_s', 'max_height', 'ctx', 'tag']);
    assert.equal(await userPage.isHidden('#proofMoreBtn'), true, 'π_IdP 는 전부 보인다');
    await userPage.click('#proofVerifyBtn'); await waitText(userPage, '#proofVerdict', '유효한 증명입니다', 60_000);
    await userPage.click('#proofCloseBtn');
    await userPage.click('#proofsKindBtn');
    assert.ok((await userPage.$$eval('#proofsList tbody tr', (rs) => rs.map((r) => r.dataset.proofKind))).every((k) => k === 'pi_cred'), '다시 π_RP 만');
    // 기록에는 salt 가 없다
    assert.equal(j((await idbDump(userPage)).proofs ?? []).includes(SALT_A), false, '증명 기록에 salt 가 있다');
  });

  // 2026-11-17(미뤄 둔 Minor, Task 6): Google 경로는 승인을 누르기 전에 거절한다 — 승인 뒤에야 passkey_mode 로 막으면 헛클릭 한 번이다.
  // 승인 버튼을 띄웠다면 팝업이 결정을 기다리느라 회신하지 않아 아래 waitText 가 시간 초과로 실패한다.
  await t('Google 로 로그인은 승인 전에 passkey_mode — 승인 버튼 없이, IdP·패스키로 가지 않는다', async () => {
    const before = hits.get + hits.create;
    const title = await rpPage.evaluate(() => window.DemoStrings.reasons.passkey_mode.ko.title);
    const [popup] = await Promise.all([ctxA.waitForEvent('page'), rpPage.evaluate(() => { startIdpLogin({ provider: 'google' }); })]);
    try {
      const visited = [];
      popup.on('framenavigated', (f) => { if (f === popup.mainFrame()) visited.push(f.url()); });
      // 판별자는 이 waitText 다 — 승인 버튼을 띄웠다면 팝업은 결정을 기다리며 회신하지 않아 RP 판정이 나오지 않고 여기서 시간 초과로 실패한다.
      // 아래 isHidden 은 보조일 뿐이다: 팝업은 회신 뒤 곧 닫히므로 이미 닫혔으면 아무것도 보지 않는다(Minor B 리뷰 잔여).
      await waitText(rpPage, '#verdict', title, 30_000);
      if (!popup.isClosed()) assert.equal(await popup.isHidden('#authApproveBtn'), true, '승인 버튼이 보인다');
      assert.equal(visited.some((u) => new URL(u).origin === cia.base), false, `팝업이 IdP 로 갔다: ${j(visited)}`);
      assert.equal(hits.get + hits.create - before, 0, '패스키를 묻지 않는다');
    } finally { if (!popup.isClosed()) await popup.close(); }   // 실패해도 팝업을 닫는다 — 남으면 RP 가 다음 로그인 클릭을 무시한다
  });

  // 계획 R-8 + 2026-11-20(사용자 요청 — salt 를 IndexedDB 에 두지 않는다): 팝업 하나(요청 하나)에 패스키는 한 번(withSalt 메모)이고, 끝난 뒤 남는 것이 없다.
  // 예전 버전이 남긴 보관분(kv passkeyHold)이 있어도 새 창의 코어가 읽지 않고 지운다. 설정의 보관 시간(passkeyHoldSeconds)도 없다.
  await t('팝업마다 패스키 정확히 한 번(R-8): 로그인·출금 — 예전 보관분은 쓰지 않고 지우며, 새로 남기지 않는다', async () => {
    assert.equal('passkeyHoldSeconds' in (await wallet.get('/user/config')).body, false);
    await putOldHold(userPage);
    assert.ok((await idbDump(userPage)).passkeyHold, '심은 옛 보관분이 있다');
    const prev = await curSession();
    let before = hits.get;
    const [popup] = await Promise.all([ctxA.waitForEvent('page'), idpLogin(rpPage)]);
    await atIdpLogin(popup);
    await fillIdp(popup);
    await rpPage.waitForFunction((p) => typeof currentSession !== 'undefined' && currentSession && currentSession !== p, prev, { timeout: 180_000 });
    await waitText(rpPage, '#verdict', '로그인 성공', 60_000);
    assert.equal(hits.get - before, 1, `로그인: 패스키 ${hits.get - before}번`);
    assert.equal((await idbDump(userPage)).passkeyHold, undefined, '옛 보관분이 남아 있다');
    before = hits.get;
    const [txPopup] = await Promise.all([ctxA.waitForEvent('page'), rpPage.click('#txBtn')]);
    await waitText(rpPage, '#txVerdict', '전송 성공', 180_000);
    assert.equal(hits.get - before, 1, `출금: 패스키 ${hits.get - before}번`);
    const d = await idbDump(userPage);
    assert.equal(d.passkeyHold, undefined); assert.equal(j(d).includes(SALT_A), false, 'IndexedDB 에 평문 salt 가 있다');
  });

  // 2026-11-17(미뤄 둔 Minor, Task 6): 팝업이 상태(core.status)를 못 읽으면 등록된 것으로 보고 발급 인증 창으로 간다(IdP·코어가 다시 거른다).
  // 미등록·속성 도구 기록 없음인 브라우저라, 상태를 읽었다면 attr_record_missing 으로 IdP 에 가지 않았을 것이다 — 발급 창에 닿으면 그 분기다.
  // 실패는 승인 팝업에서만 kv 'demo' 읽기(status 만 읽는다)를 던지게 해 만든다.
  await t('상태를 못 읽으면 발급 인증 창으로 간다(등록 창·패스키 없이)', async () => {
    const ctx = await stubContext({ secretHex: SECRET_D });
    try {
      await ctx.addInitScript(() => {
        if (new URLSearchParams(location.search).get('authorize') !== '1') return;
        const get = IDBObjectStore.prototype.get;
        IDBObjectStore.prototype.get = function (k) { if (k === 'demo') throw new DOMException('시험: 상태 읽기 실패', 'UnknownError'); return get.call(this, k); };
      });
      const u = await openUserPage(ctx);
      await putPasskey(u, stubCredId(SECRET_D));
      const rpS = await ctx.newPage(); await rpS.goto(rp.base);
      const before = hits.get + hits.create;
      const [popup] = await Promise.all([ctx.waitForEvent('page'), idpLogin(rpS)]);
      await atIdpLogin(popup);
      assert.equal(new URL(popup.url()).searchParams.get('purpose'), null, '상태를 못 읽으면 발급 인증 창');
      assert.equal(hits.get + hits.create - before, 0, 'IdP 로 가기 전에 패스키를 묻지 않는다');
      assert.equal((await idbDump(u)).registration, undefined);
      await popup.close();
    } finally { await ctx.close(); }
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

  // ---- 사용자 페이지 화면(계획 Task 7): 패스키 설정·salt 보기·연결 끊기·계정 복구. 각 케이스는 새 스텁 컨텍스트(새 IndexedDB). ----
  const reasonTitle = (page, code) => page.evaluate((c) => window.DemoStrings.reasons[c].ko.title, code);
  /** 설정 카드에서 패스키를 연결한다(btn = #pkNewBtn 또는 #pkExistingBtn). */
  const connectPasskey = async (page, btn) => {
    await page.waitForSelector('#pkSetupCard:not([hidden])', { timeout: 15_000 });
    await page.click(btn);
    await waitText(page, '#pkSetupVerdict', '패스키를 연결했습니다');
  };
  const storagesOf = (page) => page.evaluate(() => { const ls = {}; for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); ls[k] = localStorage.getItem(k); } return JSON.stringify(ls) + JSON.stringify(sessionStorage); });

  await t('설정 카드: 패스키 만들기 → 연결, 카드 숨김, 패스키 줄 — salt 보관 표시·보관분이 없다', async () => {
    const ctx = await stubContext({ secretHex: SECRET_D });
    try {
      const p = await openUserPage(ctx);
      const before = hits.create;
      await connectPasskey(p, '#pkNewBtn');
      assert.equal(hits.create - before, 1, '패스키를 한 번 만들었다');
      assert.equal((await idbDump(p)).passkey?.credentialId, stubCredId(SECRET_D));
      await p.waitForSelector('#pkSetupCard', { state: 'hidden', timeout: 15_000 });
      await p.waitForSelector('#pkInfo', { state: 'visible', timeout: 15_000 });
      await waitText(p, '#pkInfo', stubCredId(SECRET_D).slice(0, 12));
      assert.equal(/보관|분 남음/.test(await text(p, '#pkInfo')), false, await text(p, '#pkInfo'));
      const d = await idbDump(p); assert.equal(d.passkeyHold, undefined, 'IndexedDB 에 salt 보관분이 있다'); assert.equal(j(d).includes(SALT_D), false, 'IndexedDB 에 평문 salt 가 있다');
      assert.equal(/10분|IndexedDB\)에 10/.test(await p.evaluate(() => document.body.innerText)), false, '화면에 salt 10분 보관 문구가 있다');
      // 2026-11-19: 기본("이 기기")은 힌트를 싣지 않고, 패스키 줄에 이 기기의 패스키라고 보인다
      assert.deepEqual(hits.opts.slice(-2).map((o) => [o.kind, o.hints]), [['create', null], ['get', null]]);
      await waitText(p, '#pkInfo', '이 기기의 패스키');
    } finally { await ctx.close(); }
  });
  // 2026-11-20(사용자 결정): "패스키를 둘 곳"(이 기기 / 휴대폰 QR) 선택지를 화면에서 뺐다 — 시연 머신에 블루투스가 없다. 만들 때도 확인할 때도 힌트를 싣지 않고,
  // 화면에 "휴대폰"·"QR"·"블루투스" 라는 말이 없다. (코어·passkey_store 의 힌트 처리는 남아 있다 — tests/test_mode3_passkey_salt.mjs·test_mode3_user_core_passkey.mjs 가 본다.)
  await t('패스키 설정: "패스키를 둘 곳"(휴대폰 QR) 선택지가 없다 — 힌트 없이 만들고 화면에 휴대폰 표기가 없다', async () => {
    const ctx = await stubContext({ secretHex: SECRET_P });
    try {
      const p = await openUserPage(ctx);
      await p.waitForSelector('#pkSetupCard:not([hidden])', { timeout: 15_000 });
      for (const sel of ['#pkPlaceRow', '#pkPlaceHint', 'input[name="pkPlace"]']) assert.equal(await p.$(sel), null, `${sel} 는 없다`);
      const noPhone = async (where) => { const m = (await p.evaluate(() => document.body.innerText)).match(/.{0,20}(휴대폰|QR|블루투스).{0,20}/); assert.equal(m, null, `${where}: ${m?.[0]}`); };
      await noPhone('설정 화면');
      const from = hits.opts.length;
      await connectPasskey(p, '#pkNewBtn');
      const o = hits.opts.slice(from);
      assert.deepEqual(o.map((x) => x.kind), ['create', 'get']);
      assert.equal(o[0].hints, null, '만들 때 힌트를 싣지 않는다'); assert.equal(o[1].hints, null, '확인 계산에도 싣지 않는다');
      await waitText(p, '#pkInfo', '이 기기의 패스키');
      const info = (await idbDump(p)).passkey.info;
      assert.equal(info.attachment, 'platform', j(info)); assert.equal(info.hint, null, j(info));
      await noPhone('연결한 뒤의 화면');
      // 다음 확인(salt 보기)도 힌트 없이
      const from2 = hits.opts.length;
      await p.click('#pkShowSaltBtn');
      for (let i = 0; i < 100 && hits.opts.length === from2; i++) await new Promise((r) => setTimeout(r, 100));
      const again = hits.opts.slice(from2);
      assert.equal(again.length, 1); assert.equal(again[0].kind, 'get'); assert.equal(again[0].hints, null);
    } finally { await ctx.close(); }
  });

  await t('127.0.0.1 로 열면 WebAuthn 을 부르지 않는다', async () => {
    const ctx = await stubContext({ secretHex: SECRET_D });
    try {
      const before = { create: hits.create, get: hits.get };
      const p = await ctx.newPage();
      await p.goto(`${wallet.base.replace('//localhost', '//127.0.0.1')}/`);
      await p.waitForSelector('#pkSetupCard:not([hidden])', { timeout: 15_000 });
      await waitText(p, '#pkSetupVerdict', await reasonTitle(p, 'passkey_wrong_origin'));
      assert.equal(await p.$eval('#pkNewBtn', (b) => b.disabled), true);
      assert.equal(await p.$eval('#pkExistingBtn', (b) => b.disabled), true);
      assert.equal(await p.$eval('#pkOriginLink', (a) => a.href), `${WALLET_ORIGIN}/`);
      await p.waitForTimeout(500);
      assert.equal(hits.create - before.create, 0); assert.equal(hits.get - before.get, 0);
    } finally { await ctx.close(); }
  });

  await t('PRF 없는 인증기는 연결하지 않는다', async () => {
    const ctx = await stubContext({ secretHex: SECRET_D, prf: false });
    try {
      const p = await openUserPage(ctx);
      await p.waitForSelector('#pkSetupCard:not([hidden])', { timeout: 15_000 });
      await p.click('#pkNewBtn');
      await waitText(p, '#pkSetupVerdict', await reasonTitle(p, 'passkey_prf_unsupported'));
      assert.equal((await idbDump(p)).passkey, undefined);
      assert.equal(await p.isVisible('#pkSetupCard'), true, '설정 카드가 그대로 보인다');
    } finally { await ctx.close(); }
  });

  // 2026-11-17(미뤄 둔 Minor, Task 7): 사유가 붙지 않은 오류(WebAuthn 오류는 passkey_store 가 사유를 붙인다)는 internal — passkey_unsupported 로 뭉뚱그리지 않는다.
  // 인증기 응답의 getClientExtensionResults 가 던지게 해 만든다(passkey_store 의 mapError 밖에서 난다).
  await t('패스키 연결 중 사유 없는 오류는 internal 로 보인다', async () => {
    const ctx = await stubContext({ secretHex: SECRET_D });
    try {
      await ctx.addInitScript(() => { navigator.credentials.create = async () => ({ rawId: new ArrayBuffer(16), getClientExtensionResults() { throw new Error('시험: 확장 결과를 읽지 못했다'); } }); });
      const p = await openUserPage(ctx);
      await p.waitForSelector('#pkSetupCard:not([hidden])', { timeout: 15_000 });
      await p.click('#pkNewBtn');
      await waitText(p, '#pkSetupVerdict', await reasonTitle(p, 'internal'));
      assert.equal((await text(p, '#pkSetupVerdict')).includes(await reasonTitle(p, 'passkey_unsupported')), false);
      assert.equal((await idbDump(p)).passkey, undefined);
    } finally { await ctx.close(); }
  });

  await t('salt 보기: 누를 때마다 패스키 한 번, 닫으면 지워진다, 저장소에 평문 없음', async () => {
    const ctx = await stubContext({ secretHex: SECRET_D });
    try {
      const p = await openUserPage(ctx);
      await connectPasskey(p, '#pkExistingBtn');
      const before = hits.get + hits.create;
      await p.click('#pkShowSaltBtn');
      await p.waitForSelector('#pkSaltModal:not([hidden])', { timeout: 15_000 });
      assert.equal(await text(p, '#pkSaltText'), SALT_D);
      assert.equal(hits.get + hits.create - before, 1, '패스키를 한 번 묻는다');
      await p.click('#pkSaltClose');
      assert.equal(await p.isHidden('#pkSaltModal'), true);
      assert.equal(await text(p, '#pkSaltText'), '', '닫으면 화면에서 지운다');
      await p.click('#pkShowSaltBtn');
      await p.waitForSelector('#pkSaltModal:not([hidden])', { timeout: 15_000 });
      assert.equal(await text(p, '#pkSaltText'), SALT_D);
      assert.equal(hits.get + hits.create - before, 2, '다시 누르면 다시 묻는다 — 앞에서 얻은 salt 를 들고 있지 않다');
      await p.click('#pkSaltClose');
      assert.equal((await idbDump(p)).passkeyHold, undefined, 'IndexedDB 에 salt 보관분이 있다');
      assert.equal(j(await idbDump(p)).includes(SALT_D), false, 'IndexedDB 에 평문 salt 가 있다');
      assert.equal((await storagesOf(p)).includes(SALT_D), false, '브라우저 저장소에 salt 가 있다');
      assert.deepEqual(writes.filter((w) => w.v.includes(SALT_D)), [], '저장소 쓰기에 salt 가 있다');
      assert.equal(consoleLines.some((l) => l.includes(SALT_D)), false, '콘솔 로그에 salt 가 있다');
    } finally { await ctx.close(); }
  });

  await t('등록 폼·복구 코드 버튼이 없다', async () => {
    const ctx = await stubContext({ secretHex: SECRET_D });
    try {
      const p = await openUserPage(ctx);
      await p.waitForSelector('#pkSetupCard:not([hidden])', { timeout: 15_000 });
      for (const sel of ['#fileRegFields', '#registerBtn', '#profileSaveBtn', '#recoveryCodeBtn', '#recoverBtn']) assert.equal(await p.isHidden(sel), true, `${sel} 이 보인다`);
      assert.equal(await p.$eval('#pkAttrNote a', (a) => a.href), `${WALLET_ORIGIN}/attr.html`, '속성 안내에 속성 도구 링크');
      assert.equal(await p.isVisible('#pkAttrNote'), true);
      // 속성 저장이 없으므로 신원 카드의 속성 칸은 읽기 전용(최종 리뷰) — 스키마로 다시 그린 뒤(국가 = 선택 목록)에 본다
      await p.waitForFunction(() => document.querySelector('#attr1')?.tagName === 'SELECT', null, { timeout: 15_000 });
      const editable = await p.$$eval('[id^="attr"]', (els) => els.filter((e) => /^attr[0-5]$/.test(e.id) && !(e.tagName === 'SELECT' ? e.disabled : e.readOnly)).map((e) => e.id));
      assert.deepEqual(editable, [], `편집 가능한 속성 칸: ${editable}`);
    } finally { await ctx.close(); }
  });

  // 순서 의존(2026-11-17 미뤄 둔 Minor C): 아래 세 케이스(연결 끊기·계정 복구·데모 세대)의 앞 절반은 위 "첫 로그인 = 등록"·"두 번째 로그인" 케이스가 만든
  // ctxA 상태(userPage 의 등록·세션 PPID)를 쓴다 — 그 케이스가 실패하면 여기서는 아래 '앞 케이스' 단언이 먼저 실패한다(원인은 앞 케이스다).
  // 새 브라우저 쪽(ctx)은 각 케이스가 스스로 만든다.
  await t('연결 끊기는 미등록일 때만', async () => {
    // 등록된 브라우저(앞 케이스들의 ctxA): 끊기 버튼 비활성
    assert.ok((await idbDump(userPage)).registration, '앞 케이스(ctxA 첫 로그인 = 등록)의 등록이 있어야 한다');
    await userPage.waitForSelector('#pkInfo', { state: 'visible', timeout: 15_000 });
    await userPage.waitForFunction(() => document.querySelector('#pkDisconnectBtn')?.disabled === true, undefined, { timeout: 15_000 });
    // 미등록 브라우저: 끊으면 연결이 지워지고 설정 카드가 다시 뜬다
    const ctx = await stubContext({ secretHex: SECRET_D });
    try {
      const p = await openUserPage(ctx);
      await connectPasskey(p, '#pkExistingBtn');
      await p.waitForSelector('#pkDisconnectBtn:not([disabled])', { state: 'visible', timeout: 15_000 });
      await p.click('#pkDisconnectBtn');
      await p.waitForSelector('#pkSetupCard:not([hidden])', { timeout: 15_000 });
      assert.equal((await idbDump(p)).passkey, undefined, '연결이 지워졌다');
      assert.equal(await p.isHidden('#pkInfo'), true);
    } finally { await ctx.close(); }
  });

  await t('계정 복구: 저장소를 비운 브라우저에서 같은 패스키로 같은 등록·같은 PPID', async () => {
    // 앞 케이스(ctxA 의 등록·로그인)에 기댄다: 비교할 PPID 는 ctxA 의 세션에서, IdP 계정 pk-user 는 이미 AUID_A 로 등록돼 있어야 복구(restored)가 된다.
    const firstPPID = Object.values((await idbDump(userPage)).sessions ?? {})[0]?.PPID;
    assert.ok(firstPPID, '앞 케이스(ctxA)의 세션 PPID');
    const ctx = await stubContext({ secretHex: SECRET_A });
    try {
      const p = await openUserPage(ctx);
      await connectPasskey(p, '#pkExistingBtn');
      await p.waitForSelector('#pkRecoverCard:not([hidden])', { timeout: 15_000 });
      await p.waitForSelector('#pkRecoverAttrs [data-slot="birthYear"]');
      assert.equal(await p.$eval('#pkRecoverAttrs [data-slot="birthYear"]', (e) => e.value), '1990');
      assert.equal(await p.$eval('#pkRecoverAttrs [data-slot="country"]', (e) => e.value), 'KR');
      assert.equal(await p.$$eval('#pkRecoverAttrs [data-slot]', (els) => els.some((e) => /^extra|^unused/.test(e.dataset.slot))), false, '예비·미사용 슬롯은 없다');
      await p.click('#pkRecoverAuidBtn');
      await waitText(p, '#pkRecoverAuid', AUID_A);
      await p.click('#pkRecoverGoBtn');
      await p.waitForURL((x) => x.origin === cia.base && x.pathname === '/login' && x.searchParams.get('purpose') === 'register', { timeout: 30_000 });
      await fillIdp(p);
      await p.waitForURL((x) => x.origin === WALLET_ORIGIN && x.pathname === '/' && x.search === '', { timeout: 180_000 });
      await p.waitForSelector('#mainView:not([hidden])');
      await waitText(p, '#pkRecoverVerdict', '계정을 되찾았습니다', 60_000);
      assert.equal(await p.evaluate(() => sessionStorage.getItem('mode3_recover_result')), null, '복구 결과는 한 번 보이고 지운다');
      assert.equal(String((await idbDump(p)).registration?.auid), AUID_A);
      await p.waitForSelector('#pkRecoverCard', { state: 'hidden', timeout: 15_000 });
      // 서비스 로그인 — 같은 PPID
      const rpR = await ctx.newPage(); await rpR.goto(rp.base);
      const [popup] = await Promise.all([ctx.waitForEvent('page'), idpLogin(rpR)]);
      await atIdpLogin(popup);
      assert.equal(new URL(popup.url()).searchParams.get('purpose'), null, '복구된 브라우저는 발급 인증 창');
      await fillIdp(popup);
      await waitText(rpR, '#verdict', '로그인 성공', 180_000);
      const ppids = Object.values((await idbDump(p)).sessions ?? {}).map((s) => s.PPID);
      assert.deepEqual(ppids, [firstPPID], '복구 뒤 같은 PPID');
    } finally { await ctx.close(); }
  });

  await t('복구에서 다른 auid 를 넣으면 등록되지 않는다', async () => {
    const ctx = await stubContext({ secretHex: SECRET_A });
    try {
      const p = await openUserPage(ctx);
      await connectPasskey(p, '#pkExistingBtn');
      await p.waitForSelector('#pkRecoverCard:not([hidden])', { timeout: 15_000 });
      await p.click('#pkRecoverGoBtn');
      await p.waitForURL((x) => x.origin === cia.base && x.pathname === '/login' && x.searchParams.get('purpose') === 'register', { timeout: 30_000 });
      // 실제 경로(2026-11-17 미뤄 둔 Minor C — 전에는 두 경로 중 어느 쪽이든 받았다): pk-user 는 앞 케이스에서 AUID_A 로 이미 등록돼 있으므로 IdP 의
      // /cia/auth/code(purpose register)가 다른 auid 에 409 already_registered 를 주고 인증 창에 머문다 — 지갑으로 돌아가지 않고 등록 코드도 나오지 않는다.
      const badAuid = AUID_A.slice(0, -1) + (AUID_A.endsWith('1') ? '2' : '1');
      await p.fill('#authUid', 'pk-user'); await p.fill('#authPwd', DEMO_PWD); await p.fill('#authAuid', badAuid);
      const [resp] = await Promise.all([p.waitForResponse((r) => new URL(r.url()).pathname === '/cia/auth/code' && r.request().method() === 'POST', { timeout: 30_000 }), p.click('#authGo')]);
      assert.equal(resp.status(), 409, 'IdP 가 다른 auid 의 등록 코드를 409 로 거절한다');
      assert.equal((await resp.json()).reason, 'already_registered');
      await p.waitForSelector('#authVerdict.bad', { timeout: 30_000 });
      assert.equal(new URL(p.url()).origin, cia.base, '인증 창에 머문다(지갑으로 돌아가지 않는다)');
      const u = await openUserPage(ctx);
      assert.equal((await idbDump(u)).registration, undefined, '등록되지 않았다');
    } finally { await ctx.close(); }
  });

  // 2026-11-18(사용자 요청): 데모 리셋은 패스키 연결도 끊는다 — 리셋 뒤에는 패스키 설정 카드부터 다시 시작한다(그전에는 연결을 남겼다).
  await t('데모 세대가 바뀌면 등록을 지우고 패스키 연결도 끊는다 — 설정 카드가 다시 보인다', async () => {
    const cid = stubCredId(SECRET_A);
    assert.ok((await idbDump(userPage)).registration, '앞 케이스(ctxA 첫 로그인 = 등록)의 등록이 있다');   // 순서 의존 — 위 주석
    await stack.restartWallet({ MODE3_DEMO_GENERATION: 'g1' });
    await userPage.reload(); await userPage.waitForSelector('#mainView:not([hidden])');
    await userPage.waitForFunction(async () => { const open = indexedDB.open('mode3-user', 1); const db = await new Promise((r) => { open.onsuccess = () => r(open.result); }); const v = await new Promise((r) => { const q = db.transaction('kv', 'readonly').objectStore('kv').get('demoGeneration'); q.onsuccess = () => r(q.result); }); db.close(); return v === 'g1'; }, undefined, { timeout: 15_000, polling: 300 });
    assert.ok((await idbDump(userPage)).registration, '처음 본 번호로는 지우지 않는다');
    assert.equal((await idbDump(userPage)).passkey?.credentialId, cid, '처음 본 번호로는 연결도 그대로다');
    await stack.restartWallet({ MODE3_DEMO_GENERATION: 'g2' });
    await userPage.reload(); await userPage.waitForSelector('#mainView:not([hidden])');
    await userPage.waitForFunction(async () => { const open = indexedDB.open('mode3-user', 1); const db = await new Promise((r) => { open.onsuccess = () => r(open.result); }); const v = await new Promise((r) => { const q = db.transaction('kv', 'readonly').objectStore('kv').get('demoGeneration'); q.onsuccess = () => r(q.result); }); db.close(); return v === 'g2'; }, undefined, { timeout: 15_000, polling: 300 });
    const d = await idbDump(userPage);
    assert.equal(d.registration, undefined, '등록은 지웠다');
    assert.equal(d.passkey, undefined, '패스키 연결도 끊었다');
    assert.equal(d.passkeyHold, undefined, '보관분도 없다');
    await userPage.waitForSelector('#pkSetupCard:not([hidden])', { timeout: 15_000 });
    assert.equal(await userPage.isHidden('#pkPanel'), true, '연결된 패스키 줄이 없다');
    await waitText(userPage, '#storageVerdict', '패스키 연결', 15_000);   // 안내가 연결을 끊었다고 알린다
  });

  // 2026-11-17: 속성 도구(/attr.html)도 같은 CSP 아래에서 커밋먼트를 만든다(인라인이던 페이지 스크립트는 /attr/attr_page.js). 새 컨텍스트 — 앞 케이스의 기록과 섞이지 않게.
  await t('CSP: 속성 도구가 커밋먼트를 만든다(위반 없이)', async () => {
    const ctx = await browser.newContext();
    try {
      await recordCsp(ctx);
      const p = await ctx.newPage(); await p.goto(`${wallet.base}/attr.html`);
      await p.fill('#birthYear', '1990'); await p.selectOption('#country', 'KR'); await p.fill('#salt', SALT_D);
      await p.click('#makeBtn');
      await p.waitForSelector('#commitBox:not([hidden])', { timeout: 30_000 });
      assert.match(await text(p, '#commitBox'), /^[0-9]+$/);
      // 2026-11-20(사용자 결정): salt 는 계산 직후 사라진다 — 기록(localStorage)·세션 저장소·입력 칸·화면 어디에도 없다. 기록에는 그 salt 의 auid(공개값)만 남는다.
      const rec = JSON.parse(await p.evaluate(() => localStorage.getItem('mode3_attr_tool_v1')));
      assert.equal(rec.version, 6); assert.equal('s_u' in rec, false); assert.equal(rec.auid, (await auidOf({ s_u: BigInt(SALT_D) })).toString());
      assert.equal(await p.evaluate((salt) => [...Object.values(localStorage), ...Object.values(sessionStorage)].some((v) => String(v).includes(salt)), SALT_D), false, '저장소에 salt 평문이 있다');
      assert.equal(await p.inputValue('#salt'), '', 'salt 칸을 비운다');
      await p.click('#inputsFold > summary');
      assert.equal((await p.evaluate(() => document.body.innerText)).includes(SALT_D), false, '화면에 salt 가 있다');
      assert.equal(await text(p, '#auidShown'), rec.auid);
      // 옛 기록(version 5 — salt 평문)은 도구를 열 때 auid 로 바뀌고 salt 가 지워진다
      await p.evaluate((r) => localStorage.setItem('mode3_attr_tool_v1', JSON.stringify(r)), { ...rec, version: 5, s_u: SALT_D, auid: undefined });
      await p.reload(); await p.waitForSelector('#commitBox:not([hidden])', { timeout: 30_000 });
      const moved = JSON.parse(await p.evaluate(() => localStorage.getItem('mode3_attr_tool_v1')));
      assert.equal(moved.version, 6); assert.equal('s_u' in moved, false); assert.equal(moved.auid, rec.auid); assert.equal(moved.commit, rec.commit);
    } finally { await ctx.close(); }
  });

  // 2026-11-18(사용자 요청): passkey-web 에는 스냅이 없다 — 화면에 "스냅" 이 보이지 않고 지갑 자리는 "zk 클라이언트" 다.
  const noSnap = async (page, label) => {
    await page.waitForFunction(() => window.DemoStrings?.noSnap === true, null, { timeout: 15_000 });
    const m = (await page.evaluate(() => document.body.innerText)).match(/.{0,30}(스냅|\bsnap\b).{0,30}/i);
    assert.equal(m, null, `${label} 에 "스냅" 이 보인다: ${m?.[0]}`);
  };
  await t('표기: 속성 도구 상단 바는 "zk 클라이언트" 이고 "스냅" 메뉴가 없다', async () => {
    const p = await ctxA.newPage();
    try {
      await p.goto(`${wallet.base}/attr.html`);
      await p.waitForFunction(() => document.documentElement.dataset.walletKind === 'passkey-web', null, { timeout: 15_000 });
      assert.equal((await text(p, '.wallet-nav .brand')).trim(), 'zk 클라이언트');
      assert.equal(await p.isVisible('.nav-link[data-i18n="wallet_nav_snap"]'), false, '"스냅" 메뉴가 보인다');
      assert.equal(await p.isVisible('.nav-link[data-i18n="wallet_nav_attr"]'), true, '"속성 도구" 메뉴는 남는다');
      await noSnap(p, '속성 도구');
    } finally { await p.close(); }
  });
  await t('표기: 처음 여는 브라우저의 속성 도구도 리셋 표시 파일의 walletKind 로 "zk 클라이언트" — 상태 조회는 부르지 않는다', async () => {
    const ctx = await browser.newContext();
    try {
      const p = await ctx.newPage(); const reqs = [];
      p.on('request', (r) => reqs.push(new URL(r.url()).pathname));
      await p.route('**/attr/dist/reset.json', (route) => route.fulfill({ json: { epoch: 'test-kind', walletKind: 'passkey-web' } }));   // 실제 파일은 쓰지 않는다(라이브 데모가 읽는다)
      await p.goto(`${wallet.base}/attr.html`);
      await p.waitForFunction(() => document.documentElement.dataset.walletKind === 'passkey-web', null, { timeout: 15_000 });
      assert.equal((await text(p, '.wallet-nav .brand')).trim(), 'zk 클라이언트');
      await noSnap(p, '속성 도구(처음 여는 브라우저)');
      assert.equal(reqs.includes('/mode3/health'), false, `속성 도구가 상태 조회를 불렀다: ${j(reqs)}`);
    } finally { await ctx.close(); }
  });
  await t('표기: 사용자 페이지·승인 창·zkIdP 페이지·서비스 페이지에 "스냅" 이 보이지 않는다', async () => {
    // 승인 창: 사전에 없는 키가 글자 그대로 보이면 안 된다(전에는 wallet_auth_note 가 그대로 보였다)
    { const p = await ctxA.newPage(); try { await p.goto(`${wallet.base}/?authorize=1`); await p.waitForSelector('#authorizeView:not([hidden])'); const m = (await p.evaluate(() => document.body.innerText)).match(/\b[a-z]+(_[a-z0-9]+){2,}\b/); assert.equal(m, null, `승인 창에 키 이름이 보인다: ${m?.[0]}`); } finally { await p.close(); } }
    const pages = [[wallet.base, '/'], [wallet.base, '/?authorize=1'],
      ...['/user', '/user/info', '/rp', '/admin', '/account', '/login', `/login?nonce=x&wallet=${encodeURIComponent(WALLET_ORIGIN)}`, `/login?nonce=x&purpose=register&wallet=${encodeURIComponent(WALLET_ORIGIN)}`].map((x) => [cia.base, x]),
      [rp.base, '/'], [rp.base, '/admin']];
    for (const [base, path] of pages) {
      const p = await ctxA.newPage();
      try { await p.goto(`${base}${path}`); await noSnap(p, `${new URL(base).port}${path}`); } finally { await p.close(); }
    }
  });

  // 2026-11-19(스펙 passkey-proof-login §2.4): 이 스택은 code 정책이다 — 위 각본처럼 로그인마다 인증 창을 거치고, zkIdP 페이지에 증명 로그인 버튼이 없다.
  // key 정책의 동작(인증 창 생략·"패스키로 로그인")은 tests/test_mode3_user_passkey_web_proof.mjs 가 본다.
  await t('code 정책: zkIdP 페이지에 "패스키로 로그인" 이 보이지 않는다', async () => {
    const p = await ctxA.newPage();
    try {
      const keys = p.waitForResponse((r) => new URL(r.url()).pathname === '/cia/public_keys');
      await p.goto(`${cia.base}/user`);
      assert.equal((await (await keys).json()).issueAuth, 'code');
      await p.waitForFunction(() => document.documentElement.dataset.walletKind === 'passkey-web', null, { timeout: 15_000 });
      assert.equal(await p.$eval('#passkeyLoginRow', (el) => el.hidden), true);
    } finally { await p.close(); }
  });

  // 2026-11-19(스펙 oidc-comparison C1·C7): 이 스택은 일반 OIDC(비교용)를 켜지 않았다 — 버튼이 없고 zkIdP 의 인가 경로도 없다.
  await t('일반 OIDC 꺼짐(기본): 서비스 로그인 창에 "일반 OIDC · 비교용" 버튼이 없고 zkIdP 는 /oidc/authorize 를 받지 않는다', async () => {
    const p = await ctxA.newPage();
    try {
      await p.goto(rp.base); await p.waitForFunction(() => typeof info !== 'undefined' && info && info.social);
      assert.equal(await p.$eval('#zkoidcLoginBtn', (el) => el.hidden), true);
      assert.equal((await fetch(`${cia.base}/oidc/authorize?client_id=1`)).status, 404);
    } finally { await p.close(); }
  });

  await t('CSP: 위 정상 흐름 전체(증명 워커·wasm·IdP 왕복·복구·속성 도구)에서 지갑 오리진 위반 0건', async () => {
    assert.deepEqual(cspHits, []);
  });
} finally {
  await browser.close().catch(() => {});
  await stack.stop();
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed === 0 ? 0 : 1);
