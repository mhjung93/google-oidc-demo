// 패스키 모드(MODE3_WALLET_SECRETS=passkey, 스펙 2026-11-17-mode3-passkey-mode) — zk 스냅 화면·승인 팝업·서비스 페이지를 실제 Chrome 으로 돌린다.
// 흐름 시험은 결정적 WebAuthn 스텁(tests/helpers/webauthn_stub.js, 계획 R-A), 실제 Chrome WebAuthn 경로는 CDP 가상 인증기로 따로 본다.
// hardhat :8545 와 build/mode3 산출물, Chrome 이 필요하다(browser 그룹).   node tests/test_mode3_passkey_browser.mjs   (MODE3_BROWSER_DEBUG=1 이면 콘솔 출력)
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash, createHmac } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { buildWebAuthnStub } from './helpers/webauthn_stub.js';
import { VKEY_PATH } from '../lib/mode3_wallet.js';
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

assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);
execFileSync('node', ['scripts/build_attr_tool.mjs'], { stdio: 'inherit' });   // 속성 도구 번들 — zk 스냅 화면이 같은 오리진에서 읽는다
const browser = await launchBrowser();
const stack = await startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'passkey', MODE3_PASSKEY_HOLD_SECONDS: '0' }, walletHost: 'localhost', ciaEnv: { CIA_ISSUE_AUTH: 'code' }, autoRelay: true });
const { cia, wallet, rp } = stack;
const SECRET_A = 'a1'.repeat(32), SECRET_B = 'b2'.repeat(32);
const SALT_A = stubSalt(SECRET_A);
const DEMO_PWD = 'demo-pass-9';
const hits = { create: 0, get: 0 };
const walletUrl = (host = 'localhost') => `http://${host}:${new URL(wallet.base).port}/`;
const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
async function waitText(page, sel, needle, timeout = 30_000) {
  try { await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout }); }
  catch { throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`); }
}
/** 스텁 컨텍스트 — 모든 페이지(팝업·IdP 포함)에 같은 패스키. 호출 수는 하네스(hits)가 센다. */
async function stubContext(opts) {
  const ctx = await browser.newContext();
  await ctx.exposeFunction('__webauthnHit', (k) => { hits[k] = (hits[k] ?? 0) + 1; });
  await ctx.addInitScript({ content: buildWebAuthnStub(opts) });
  ctx.on('dialog', (d) => d.accept());
  if (DEBUG) ctx.on('page', (p) => { p.on('console', (m) => console.log(`    [${new URL(p.url()).port}] ${m.type()}: ${m.text()}`)); p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`)); });
  return ctx;
}
const pkState = async () => (await wallet.get('/wallet/passkey/state', { 'Sec-Fetch-Site': 'same-origin' })).body;
const delCredential = () => wallet.raw('/wallet/passkey/credential', { method: 'DELETE', headers: { 'Sec-Fetch-Site': 'same-origin' } });

try {
  assert.equal((await wallet.get('/wallet/config')).body.secrets, 'passkey');

  await t('실제 Chrome WebAuthn(CDP 가상 인증기): 패스키 만들기 → 연결, 두 번 계산해도 같은 salt; PRF 없는 인증기는 passkey_prf_unsupported', async () => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const opts = { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true };
    let { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { ...opts, hasPrf: true } });
    await page.goto(walletUrl());
    await page.waitForSelector('#setupPasskeyNewBtn:not([hidden])', { state: 'visible', timeout: 15_000 });
    await page.click('#setupPasskeyNewBtn');
    await waitText(page, '#setupNotice', '패스키를 연결했습니다');
    const cid = (await pkState()).passkey?.credentialId;
    assert.match(String(cid), /^[A-Za-z0-9_-]+$/);
    const [a, b] = [await page.evaluate((c) => window.Mode3Passkey.derivePrf({ credentialId: c }), cid), await page.evaluate((c) => window.Mode3Passkey.derivePrf({ credentialId: c }), cid)];
    assert.equal(a.s_u, b.s_u); assert.equal(a.credentialId, cid);
    assert.ok(BigInt(a.s_u) > 0n && BigInt(a.s_u) < (1n << 250n));
    assert.equal((await delCredential()).status, 200, '등록 전이라 연결을 끊을 수 있다');
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
    ({ authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { ...opts, hasPrf: false } }));
    await page.reload();
    await page.waitForSelector('#setupPasskeyNewBtn:not([hidden])', { state: 'visible', timeout: 15_000 });
    await page.click('#setupPasskeyNewBtn');
    await waitText(page, '#setupVerdict', '이 패스키는 PRF 를 지원하지 않습니다');
    assert.equal((await pkState()).passkey, null, 'PRF 없는 패스키는 연결하지 않는다');
    await ctx.close();
  });

  const ctxA = await stubContext({ secretHex: SECRET_A });

  await t('127.0.0.1 로 열면 패스키를 부르지 않고 localhost 안내만', async () => {
    const before = { ...hits };
    const p = await ctxA.newPage(); await p.goto(walletUrl('127.0.0.1'));
    await p.waitForSelector('#passkeyOriginCard:not([hidden])', { timeout: 15_000 });
    assert.equal(await p.isHidden('#setupCard'), true); assert.equal(await p.isHidden('#connectCard'), true);
    assert.equal(await p.getAttribute('#passkeyOriginLink', 'href'), walletUrl());
    assert.deepEqual(hits, before, 'WebAuthn 을 부르지 않았다');
    await p.close();
  });

  await t('PRF 없는 인증기(스텁)는 거절 — 연결하지 않는다', async () => {
    const ctx = await stubContext({ secretHex: SECRET_B, prf: false });
    const p = await ctx.newPage(); await p.goto(walletUrl());
    await p.click('#setupPasskeyNewBtn');
    await waitText(p, '#setupVerdict', '이 패스키는 PRF 를 지원하지 않습니다');
    assert.equal((await pkState()).passkey, null);
    await ctx.close();
  });

  // 2026-11-17(미뤄 둔 Minor): 사유가 붙지 않은 오류는 internal — passkey_unsupported 로 뭉뚱그리지 않는다(인증기 응답의 확장 결과 읽기가 던지게 해 만든다).
  await t('패스키 연결 중 사유 없는 오류는 internal 로 보인다', async () => {
    const ctx = await stubContext({ secretHex: SECRET_B });
    await ctx.addInitScript(() => { navigator.credentials.create = async () => ({ rawId: new ArrayBuffer(16), getClientExtensionResults() { throw new Error('시험: 확장 결과를 읽지 못했다'); } }); });
    const p = await ctx.newPage(); await p.goto(walletUrl());
    await p.click('#setupPasskeyNewBtn');
    const titles = await p.evaluate(() => [window.DemoStrings.reasons.internal.ko.title, window.DemoStrings.reasons.passkey_unsupported.ko.title]);
    await waitText(p, '#setupVerdict', titles[0]);
    assert.equal((await text(p, '#setupVerdict')).includes(titles[1]), false);
    assert.equal((await pkState()).passkey, null);
    await ctx.close();
  });

  const walletPage = await ctxA.newPage();
  await t('설정 카드: 패스키 만들기 → 연결되고 탭이 열린다(MetaMask 연결 카드 없음)', async () => {
    await walletPage.goto(walletUrl());
    await walletPage.waitForSelector('#setupPasskeyNewBtn:not([hidden])', { state: 'visible', timeout: 15_000 });
    assert.equal(await walletPage.isHidden('#connectCard'), true); assert.equal(await walletPage.isHidden('#setupChoice'), true, '백업 파일 버튼은 없다');
    await walletPage.click('#setupPasskeyNewBtn');
    await waitText(walletPage, '#setupNotice', '패스키를 연결했습니다');
    assert.ok((await pkState()).passkey?.credentialId);
    assert.equal(await walletPage.isHidden('#setupCard'), true); assert.equal(await walletPage.isVisible('#walletTabs'), true);
  });

  // zkID 가입(아이디·비밀번호) — 지갑과 무관하다(tests/test_mode3_browser.mjs 의 가입 케이스와 같은 화면)
  {
    const u = await ctxA.newPage(); await u.goto(`${cia.base}/user`);
    await u.click('#showSignupBtn'); await u.fill('#signupId', 'pk-user'); await u.fill('#signupPwd', DEMO_PWD); await u.fill('#signupPwd2', DEMO_PWD); await u.click('#signupBtn');
    await waitText(u, '#userVerdict', '가입했습니다'); await u.close();
  }
  const rpPage = await ctxA.newPage();
  await rpPage.goto(rp.base);
  const idpLogin = async (page) => { if (await page.$eval('#loginBtn', (b) => b.hidden)) { await page.click('#logoutBtn'); await page.waitForSelector('#loginBtn:not([hidden])'); } await page.click('#loginBtn'); await page.click('#idpLoginBtn'); };
  const atIdpLogin = (popup) => popup.waitForURL((x) => x.origin === cia.base && x.pathname === '/login' && x.searchParams.get('return') === '1', { timeout: 60_000 });
  const backAtWallet = (popup) => popup.waitForURL((x) => x.origin === new URL(wallet.base).origin && x.searchParams.get('authorize') === '1', { timeout: 30_000 });
  const AUID_A = (await auidOf({ s_u: BigInt(SALT_A) })).toString();

  await t('첫 로그인 = 등록 + 로그인: 승인 팝업 하나에 패스키 한 번, 서비스에 로그인 성공', async () => {
    // 속성 도구가 남기는 기록 — 첫 등록은 이 기록의 salt 가 지금 salt(패스키)와 같아야 한다
    // 데모 리셋 표시(/attr/dist/reset.json)가 있으면 화면이 그 epoch 를 처음 볼 때 기록을 지운다(readAttrRecord) — 지금 epoch 를 본 것으로 맞춰 둔다
    await walletPage.evaluate(async (r) => {
      try { const x = await fetch('/attr/dist/reset.json', { cache: 'no-store' }); if (x.ok) localStorage.setItem('mode3_attr_tool_reset', String((await x.json()).epoch ?? '')); } catch {}
      localStorage.setItem('mode3_attr_tool_v1', JSON.stringify(r));
    }, { version: 5, s_u: SALT_A, profile: { birthYear: '1990', country: 'KR' } });   // 2026-11-17: 기록에 uid 가 없다
    const before = hits.get;
    const [popup] = await Promise.all([ctxA.waitForEvent('page'), idpLogin(rpPage)]);
    await atIdpLogin(popup);
    await popup.fill('#authUid', 'pk-user'); await popup.fill('#authPwd', DEMO_PWD); await popup.fill('#authAuid', AUID_A); await popup.click('#authGo');
    await backAtWallet(popup);
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    assert.equal(hits.get - before, 1, `패스키 계산 ${hits.get - before}번 — 팝업 하나에 한 번이어야 한다`);
    const st = (await wallet.get('/wallet/status')).body;
    assert.equal(st.registered, true); assert.equal(String(st.auid), AUID_A, '패스키 salt 로 등록됐다');
    assert.equal(fs.readFileSync(stack.walletStateFile, 'utf8').includes(SALT_A), false, 's_u 가 상태 파일에 없다');
  });

  await t('다른 패스키는 passkey_mismatch — 서비스에 로그인되지 않는다', async () => {
    const ctxB = await stubContext({ secretHex: SECRET_B });
    const rpB = await ctxB.newPage(); await rpB.goto(rp.base);
    const [popup] = await Promise.all([ctxB.waitForEvent('page'), idpLogin(rpB)]);
    // 등록된 지갑이라 발급 인증 창(IdP)을 다녀온다 — 아이디·비밀번호·auid 를 넣으면 돌아와 패스키를 부른다
    await atIdpLogin(popup);
    await popup.fill('#authUid', 'pk-user'); await popup.fill('#authPwd', DEMO_PWD); await popup.fill('#authAuid', AUID_A); await popup.click('#authGo');
    await waitText(rpB, '#verdict', '다른 패스키입니다', 120_000);
    await ctxB.close();
  });

  // ---- Task 4: 세션 복구(스펙 P9)·salt 보기·데모 리셋·연결 끊기 ----
  const curSession = () => rpPage.evaluate(() => (typeof currentSession === 'undefined' ? null : currentSession));
  const servicesTab = async () => { await walletPage.click('#walletTabs [data-tab="services"]'); };
  const loginAgain = async () => {
    const prev = await curSession();
    const [popup] = await Promise.all([ctxA.waitForEvent('page'), idpLogin(rpPage)]);
    await atIdpLogin(popup);
    await popup.fill('#authUid', 'pk-user'); await popup.fill('#authPwd', DEMO_PWD); await popup.fill('#authAuid', AUID_A); await popup.click('#authGo');
    await rpPage.waitForFunction((p) => typeof currentSession !== 'undefined' && currentSession && currentSession !== p, prev, { timeout: 180_000 });
    if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 15_000 }).catch(() => {});
    return curSession();
  };

  await t('에이전트 재시작 → 서비스 출금은 세션 복구 안내 → zk 스냅 화면 "세션 복구"(패스키 한 번) → 재검증 200', async () => {
    const rs = await curSession(); assert.match(String(rs), /^[0-9]+$/);
    await stack.restartWallet();
    const [popup] = await Promise.all([ctxA.waitForEvent('page'), rpPage.click('#txBtn')]);
    await waitText(rpPage, '#txVerdict', '세션 복구가 필요합니다', 120_000);
    assert.ok((await text(rpPage, '#txVerdict')).includes('세션 복구'), '조치가 zk 스냅 화면의 세션 복구를 말한다');
    if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 15_000 }).catch(() => {});
    await walletPage.reload(); await servicesTab();
    await walletPage.waitForSelector('#restoreCard:not([hidden])', { timeout: 15_000 });
    assert.equal(await walletPage.$$eval('#restoreList li', (l) => l.length), 1);
    const before = hits.get;
    await walletPage.click('#restoreBtn');
    await walletPage.waitForFunction(() => document.querySelector('#restoreList li')?.dataset.result === 'ok', undefined, { timeout: 120_000 });
    assert.equal(hits.get - before, 1, '세션 복구는 패스키 한 번');
    assert.equal((await wallet.get('/wallet/status')).body.sessions[rs].hasWitness, true);
    const rv = await wallet.post('/wallet/revalidate', { r_s: rs }, { Origin: rp.origin });
    assert.equal(rv.status, 200, j(rv.body));
    await walletPage.reload(); await servicesTab();
    await walletPage.waitForSelector('#restoreCard', { state: 'hidden', timeout: 15_000 });
  });

  await t('복구는 세션별 결과 — 한 세션이 거절돼도 다른 세션은 복구된다', async () => {
    const rs2 = await loginAgain();
    await stack.restartWallet();
    const st = (await wallet.get('/wallet/status')).body;
    const lacking = Object.entries(st.sessions).filter(([, e]) => !e.hasWitness).map(([k]) => k);
    assert.ok(lacking.length >= 2, `증인 없는 세션 ${lacking.length}개: ${j(Object.keys(st.sessions))}`);
    const victim = lacking.find((k) => k !== rs2);
    await walletPage.route('**/wallet/session/witness', async (route) => {
      const body = JSON.parse(route.request().postData() ?? '{}');
      if (body.r_s === victim) return route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ reason: 'user_cred_mismatch' }) });
      return route.continue();
    });
    await walletPage.reload(); await servicesTab();
    await walletPage.waitForSelector('#restoreCard:not([hidden])', { timeout: 15_000 });
    await walletPage.click('#restoreBtn');
    await walletPage.waitForFunction((v) => document.querySelector(`#restoreList li[data-rs="${v}"]`)?.dataset.result === 'fail', victim, { timeout: 120_000 });
    assert.equal(await walletPage.$eval(`#restoreList li[data-rs="${rs2}"]`, (li) => li.dataset.result), 'ok');
    await walletPage.unroute('**/wallet/session/witness');
    const after = (await wallet.get('/wallet/status')).body.sessions;
    assert.equal(after[rs2].hasWitness, true); assert.equal(after[victim].hasWitness, false);
  });

  await t('salt 보기는 패스키 한 번 — 화면에는 보이지만 브라우저 저장소·상태 파일에는 s_u 가 없다', async () => {
    await walletPage.click('#walletTabs [data-tab="me"]');
    const before = hits.get;
    await walletPage.click('#passkeyShowSaltBtn');
    await waitText(walletPage, '#passkeySaltOut', SALT_A);
    assert.equal(hits.get - before, 1);
    const stores = await walletPage.evaluate(() => {
      const ls = {}; for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (k !== 'mode3_attr_tool_v1') ls[k] = localStorage.getItem(k); }   // 속성 도구 기록은 salt 를 평문으로 드는 의도된 예외(런북)
      return JSON.stringify(ls) + JSON.stringify(sessionStorage);
    });
    assert.equal(stores.includes(SALT_A), false, '브라우저 저장소에 s_u 가 있다');
    assert.equal(fs.readFileSync(stack.walletStateFile, 'utf8').includes(SALT_A), false, '상태 파일에 s_u 가 있다');
  });

  await t('등록이 있으면 패스키 연결 끊기 버튼은 꺼져 있다; 초기화 뒤 같은 패스키로 다시 로그인하면 같은 PPID, 그 뒤 연결 끊기 → 설정 카드', async () => {
    assert.equal(await walletPage.$eval('#passkeyDisconnectBtn', (b) => b.disabled), true);
    const ppids = async () => new Set((await rp.get('/api/mode3/logins', rp.adminHeaders)).body.logins.filter((l) => l.PPID).map((l) => l.PPID));
    const beforeP = await ppids(); assert.equal(beforeP.size, 1);
    await walletPage.click('#snapResetBtn');
    await waitText(walletPage, '#snapResetVerdict', '초기화', 30_000);
    assert.equal((await wallet.get('/wallet/status')).body.registered, false);
    assert.ok((await pkState()).passkey?.credentialId, '패스키 연결은 남는다');
    await loginAgain();
    const afterP = await ppids(); assert.deepEqual([...afterP], [...beforeP], '같은 패스키 → 같은 salt → 같은 PPID');
    await walletPage.click('#walletTabs [data-tab="me"]');
    await walletPage.click('#snapResetBtn');
    await waitText(walletPage, '#snapResetVerdict', '초기화', 30_000);
    await walletPage.waitForFunction(() => !document.querySelector('#passkeyDisconnectBtn')?.disabled, undefined, { timeout: 15_000 });
    await walletPage.click('#passkeyDisconnectBtn');
    await walletPage.waitForSelector('#setupPasskeyNewBtn:not([hidden])', { state: 'visible', timeout: 15_000 });
    assert.equal((await pkState()).passkey, null);
  });

  // ---- 계정 복구(스펙 §10 P11~P15): 에이전트 파일을 잃어도 zk 스냅 화면에서 같은 등록을 되찾는다 ----
  /** 에이전트 상태 파일 분실 흉내 — 빈 파일로 덮고 재시작한 뒤 화면에서 같은 패스키를 다시 연결한다(이미 있는 패스키 쓰기). */
  const loseAgentFile = async () => {
    fs.writeFileSync(stack.walletStateFile, '{}');
    await stack.restartWallet();
    await walletPage.goto(walletUrl());
    await walletPage.waitForSelector('#setupPasskeyExistingBtn:not([hidden])', { state: 'visible', timeout: 15_000 });
    await walletPage.click('#setupPasskeyExistingBtn');
    await walletPage.waitForSelector('#recoverCard:not([hidden])', { timeout: 15_000 });
  };

  await t('에이전트 파일을 잃어도 계정 복구로 같은 등록·같은 PPID — 패스키 두 번, salt 는 저장소에 없다', async () => {
    const ppidsBefore = new Set((await rp.get('/api/mode3/logins', rp.adminHeaders)).body.logins.filter((l) => l.PPID).map((l) => l.PPID));
    assert.equal(ppidsBefore.size, 1);
    await loseAgentFile();
    assert.equal((await wallet.get('/wallet/status')).body.registered, false);
    assert.ok(await walletPage.$('#recoverAttrs [data-slot]'), '속성 칸이 있다');
    const before = hits.get;
    await walletPage.click('#recoverAuidBtn');
    await waitText(walletPage, '#recoverAuid', AUID_A);
    await walletPage.click('#recoverGoBtn');
    await atIdpLogin(walletPage);
    await walletPage.fill('#authUid', 'pk-user'); await walletPage.fill('#authPwd', DEMO_PWD); await walletPage.fill('#authAuid', AUID_A); await walletPage.click('#authGo');
    await walletPage.waitForURL((x) => x.origin === new URL(wallet.base).origin && x.pathname === '/' && !x.searchParams.get('authorize'), { timeout: 120_000 });
    await waitText(walletPage, '#recoverVerdict', '계정을 되찾았습니다', 60_000);
    assert.equal(hits.get - before, 2, `복구 동안 패스키 계산 ${hits.get - before}번 — auid 표시·돌아온 뒤 두 번`);
    const st = (await wallet.get('/wallet/status')).body;
    assert.equal(st.registered, true); assert.equal(String(st.auid), AUID_A);
    const dump = await walletPage.evaluate(() => {
      const ls = {}; for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (k !== 'mode3_attr_tool_v1') ls[k] = localStorage.getItem(k); }
      return { all: JSON.stringify(ls) + JSON.stringify(sessionStorage), result: sessionStorage.getItem('mode3_recover_result') };
    });
    assert.equal(dump.result, null, '복구 결과는 한 번 보인 뒤 지운다');
    assert.equal(dump.all.includes(SALT_A), false, '브라우저 저장소에 s_u 가 있다');
    assert.equal(fs.readFileSync(stack.walletStateFile, 'utf8').includes(SALT_A), false, '상태 파일에 s_u 가 있다');
    await walletPage.reload(); await walletPage.waitForTimeout(1000);
    assert.equal((await text(walletPage, '#recoverVerdict').catch(() => '')).includes('되찾았습니다'), false, '새로 고치면 결과가 다시 뜨지 않는다');
    await loginAgain();
    const ppidsAfter = new Set((await rp.get('/api/mode3/logins', rp.adminHeaders)).body.logins.filter((l) => l.PPID).map((l) => l.PPID));
    assert.deepEqual([...ppidsAfter], [...ppidsBefore], '복구한 등록으로 로그인해도 같은 PPID');
  });

  // 리뷰(복구) I-1: 두 경로를 따로 본다 — (1) 이미 다른 auid 로 등록된 계정이면 IdP 인증 창이 거기서 막고, (2) 등록 없는 계정에 틀린 auid 를 넣으면
  // IdP 가 그 auid 에 묶인 코드를 주고 화면으로 돌아온다 — 그때 finishRecover 의 auid 대조(또는 IdP 의 코드 대조)가 register_auid_mismatch 로 멈춘다.
  const wrongAuid = AUID_A.slice(0, -1) + (AUID_A.endsWith('1') ? '2' : '1');
  await t('이미 다른 auid 로 등록된 계정에 틀린 auid 를 넣으면 IdP 인증 창이 already_registered 로 막는다 — 등록되지 않는다', async () => {
    await loseAgentFile();
    await walletPage.click('#recoverGoBtn');
    await atIdpLogin(walletPage);
    await walletPage.fill('#authUid', 'pk-user'); await walletPage.fill('#authPwd', DEMO_PWD); await walletPage.fill('#authAuid', wrongAuid); await walletPage.click('#authGo');
    await waitText(walletPage, '#authVerdict', '이미 등록', 30_000);
    assert.equal(new URL(walletPage.url()).origin, cia.base, '지갑으로 돌아가지 않는다');
    assert.equal((await wallet.get('/wallet/status')).body.registered, false);
  });

  await t('등록 없는 계정에 이 패스키와 다른 auid 를 넣으면 돌아와 register_auid_mismatch — 등록되지 않는다', async () => {
    const u = await ctxA.newPage(); await u.goto(`${cia.base}/user`);
    await u.click('#showSignupBtn'); await u.fill('#signupId', 'pk-user2'); await u.fill('#signupPwd', DEMO_PWD); await u.fill('#signupPwd2', DEMO_PWD); await u.click('#signupBtn');
    await waitText(u, '#userVerdict', '가입했습니다'); await u.close();
    await loseAgentFile();
    await walletPage.click('#recoverGoBtn');
    await atIdpLogin(walletPage);
    await walletPage.fill('#authUid', 'pk-user2'); await walletPage.fill('#authPwd', DEMO_PWD); await walletPage.fill('#authAuid', wrongAuid); await walletPage.click('#authGo');
    await walletPage.waitForURL((x) => x.origin === new URL(wallet.base).origin && x.pathname === '/' && !x.searchParams.get('authorize'), { timeout: 120_000 });
    await waitText(walletPage, '#recoverVerdict', '넣은 auid 가', 60_000);
    assert.equal((await wallet.get('/wallet/status')).body.registered, false, '다른 auid 로는 등록되지 않는다');
    const acct = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.id === 'pk-user2');
    assert.ok(!acct?.auid, `IdP 의 pk-user2 에도 등록이 없다: ${j(acct)}`);
  });

  // 스펙 §11 P16(10분 보관): 보관을 켜면 패스키를 누른 뒤 10분 안의 로그인은 패스키를 묻지 않는다.
  await t('salt 10분 보관: 첫 로그인은 패스키 한 번, 곧이은 로그인은 패스키 없이; 상태 파일에는 salt 가 없다', async () => {
    // 앞 케이스들이 에이전트를 비웠다 — 같은 계정·같은 auid 로 다시 등록(restored)해 둔다(화면 흐름은 앞 케이스가 이미 본다)
    const acc = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.id === 'pk-user');
    const ac = await fetch(`${cia.base}/cia/auth/code`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ uid: acc.uid, pwd: DEMO_PWD, auid: AUID_A, purpose: 'register' }) });
    const code = (await ac.json()).code;
    const reg = await wallet.post('/wallet/register', { uid: String(acc.uid), code, s_u: SALT_A });
    assert.equal(reg.status, 201, j(reg.body));
    await stack.restartWallet({ MODE3_PASSKEY_HOLD_SECONDS: '600' });
    const g0 = hits.get; await loginAgain(); assert.equal(hits.get - g0, 1, '보관 전 첫 로그인은 패스키 한 번');
    const g1 = hits.get; await loginAgain(); assert.equal(hits.get - g1, 0, '10분 안의 로그인은 패스키 없이');
    assert.equal(fs.readFileSync(stack.walletStateFile, 'utf8').includes(SALT_A), false, '보관은 메모리에만');
    await stack.restartWallet({ MODE3_PASSKEY_HOLD_SECONDS: '0' });
  });

  // 2026-11-17(사용자 요청): 세션이 끝나면(만료·로그아웃·폐기) 서비스 상단 바에 "현재 세션이 만료됐습니다" — "세션 복구" 를 누르면 새 zkID 로그인으로 새 세션을 맺는다
  await t('서비스 상단 바: 세션이 끝나면 "현재 세션이 만료됐습니다" → "세션 복구" 로 새 세션', async () => {
    const old = await curSession(); assert.match(String(old), /^[0-9]+$/);
    assert.equal(await rpPage.isHidden('#sessionBar'), true, '살아 있는 세션에는 바가 없다');
    assert.equal((await rp.post('/api/mode3/logout', { r_s: String(old) })).body.removed, true);   // 서버 쪽에서 세션이 끝났다(만료와 같은 길 — forgetSession)
    await rpPage.waitForSelector('#sessionBar:not([hidden])', { timeout: 15_000 });
    assert.ok((await text(rpPage, '#sessionBar')).includes('현재 세션이 만료됐습니다'), await text(rpPage, '#sessionBar'));
    const [popup] = await Promise.all([ctxA.waitForEvent('page'), rpPage.click('#sessionBarBtn')]);
    await atIdpLogin(popup);
    await popup.fill('#authUid', 'pk-user'); await popup.fill('#authPwd', DEMO_PWD); await popup.fill('#authAuid', AUID_A); await popup.click('#authGo');
    await rpPage.waitForFunction((p) => typeof currentSession !== 'undefined' && currentSession && currentSession !== p, String(old), { timeout: 180_000 });
    await waitText(rpPage, '#verdict', '로그인 성공', 60_000);
    await rpPage.waitForSelector('#sessionBar', { state: 'hidden', timeout: 10_000 });
  });
} finally {
  await browser.close().catch(() => {});
  await stack.stop();
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed === 0 ? 0 : 1);
