// snap 모드 지갑 + Google(OIDC 래퍼) 브라우저 각본(스펙 2026-10-26 Snap OIDC 래퍼 §6). Snap 은 진짜 snap-mode3/src/index.js(ethereum_stub),
// Google 은 GIS 스텁 + 발급자 스텁. 지갑 오리진은 localhost(GSI 는 localhost 에서만 버튼을 그린다). (browser 그룹)
// hardhat :8545 와 build/mode3 의 pi_cred zkey·vkey, 그리고 Chrome(또는 Chromium)이 필요하다.
//   node tests/test_mode3_wallet_snap_oidc_browser.mjs
//   MODE3_BROWSER_DEBUG=1 로 브라우저 콘솔·페이지 오류를 그대로 흘려 본다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { buildInitScript } from './helpers/ethereum_stub.js';
import { VKEY_PATH } from '../lib/mode3_wallet.js';
import { uidOf } from '../lib/mode3_oidc_nonce.js';
import { startOidcIssuerStub } from './helpers/oidc_issuer_stub.mjs';

const DEBUG = process.env.MODE3_BROWSER_DEBUG === '1';
const j = (o) => JSON.stringify(o);
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); }
}
// 진짜 GIS 대신: initialize 가 준 nonce 로 발급자 스텁 /mint 에서 토큰을 받아 callback 을 부르는 버튼. sub 는 window.__gsiSub.
const GSI_STUB = (mintUrl) => `window.__gsiMintUrl = ${j(mintUrl)}; window.__gsiSub = window.__gsiSub ?? 'g-user-1';
window.google = { accounts: { id: { _cfg: null, initialize(cfg) { this._cfg = cfg; },
  renderButton(el, opts) { const b = document.createElement('button'); b.type = 'button'; b.className = 'gsi-stub'; b.textContent = 'Google(stub:' + (opts?.text ?? '') + ')';
    b.addEventListener('click', async () => { const r = await fetch(window.__gsiMintUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sub: window.__gsiSub, nonce: this._cfg.nonce }) }); const { id_token } = await r.json(); this._cfg.callback({ credential: id_token }); });
    el.replaceChildren(b); } } } };`;

assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);

/** 설치된 Chrome 을 먼저 쓴다 — Playwright 의 번들 chromium 은 Ubuntu 20.04 에 내려받을 수 없다(2026-09-22 실측). */
async function launchBrowser() {
  const tried = [];
  for (const opts of [{ channel: 'chrome' }, {}]) {
    try { return await chromium.launch(opts); }
    catch (e) { tried.push(`${j(opts)}: ${e.message.split('\n')[0]}`); }
  }
  throw new Error(`BLOCKED: 브라우저를 띄우지 못했다.\n  ${tried.join('\n  ')}`);
}

const browser = await launchBrowser();
const provider = getProvider();
// ciaHost 'localhost': IdP 페이지(/user·/account)도 localhost 오리진이라 GIS(스텁)가 그려진다 — 분리 데모의 SSH 터널과 같은 모양.
// RP 소셜(2026-11-10): RP 가 직접 쓰는 Google·네이버 흉내 — IdP 래퍼용 stub 과 따로. RP 는 localhost 오리진(rpHost)이라 GIS 가 그려지고 네이버 콜백 쿠키가 맞는다.
const rpGoogle = await startOidcIssuerStub({ clientId: 'rp-google-client', provider: 'google' });
const rpNaver = await startOidcIssuerStub({ clientId: 'rp-naver-client', provider: 'naver', clientSecret: 'rp-naver-secret' });
const rpSocialEnv = {
  MODE3_RP_GOOGLE_CLIENT_ID: rpGoogle.clientId, MODE3_RP_GOOGLE_ISSUER: rpGoogle.issuer, MODE3_RP_GOOGLE_JWKS_URL: rpGoogle.jwksUrl,
  MODE3_RP_NAVER_CLIENT_ID: rpNaver.clientId, MODE3_RP_NAVER_CLIENT_SECRET: rpNaver.clientSecret, MODE3_RP_NAVER_ISSUER: rpNaver.issuer, MODE3_RP_NAVER_JWKS_URL: rpNaver.jwksUrl,
  MODE3_RP_NAVER_AUTHORIZE_URL: rpNaver.authorizeUrl, MODE3_RP_NAVER_TOKEN_URL: rpNaver.tokenUrl,
};
const stack = await startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'snap' }, ciaEnv: { CIA_ISSUE_AUTH: 'code' }, rpEnv: rpSocialEnv, autoRelay: true, oidc: true, walletHost: 'localhost', ciaHost: 'localhost', rpHost: 'localhost' });
const { cia, wallet, rp, oidc: stub, ciaUiBase: ciaUi } = stack;
const SUB = 'g-browser-1';

// ---- 하네스가 맡는 것: Snap 저장소, 대화상자, 체인 전송 (test_mode3_browser.mjs 와 같다) ----
// 2026-11-13(스냅 0.5.0, 스펙 random-salt): salt 는 무작위이고 백업을 확인해야 쓸 수 있다 — 하네스가 "설정이 끝난 스냅" 의 저장 상태를 직접 채운다(설정 화면 자체는 test_mode3_browser.mjs 가 본다).
// 같은 IdP 에서 한 스냅(salt)의 계정은 하나라(R11), 다른 Google 계정으로 새로 가입하는 케이스는 다른 salt 의 스냅을 쓴다.
const readySnap = (s_u) => ({ version: 2, salt: { s_u: String(s_u), createdAt: new Date().toISOString(), source: 'import', backedUp: true, backedUpAt: new Date().toISOString() }, registration: null, userCred: null, consents: {} });
const SALT_A = '111111111111111111111111111111', SALT_B = '222222222222222222222222222222';
let snapState = readySnap(SALT_A);
const dialogs = [];        // 사용자에게 보인 대화상자(문구 검사용)
const answers = [];        // 다음 대화상자들이 돌려줄 값

try {
  const eoa = await provider.getSigner(1);       // MetaMask 의 사용자 계정 역할(가스를 낸다)
  const account = await eoa.getAddress();
  const cfg = (await wallet.get('/wallet/config')).body;
  assert.equal(cfg.secrets, 'snap', `지갑이 snap 모드여야 한다: ${j(cfg)}`);
  assert.equal(cfg.oidc?.enabled, true, `지갑 config.oidc.enabled: ${j(cfg.oidc)}`);

  const context = await browser.newContext();
  await context.exposeFunction('__snapState', (op, newState) => {
    if (op === 'get') return snapState;
    if (op === 'update') { snapState = newState; return null; }
    if (op === 'clear') { snapState = null; return null; }
    throw new Error(`하네스: 모르는 snap_manageState operation ${op}`);
  });
  await context.exposeFunction('__snapDialog', async (params) => {
    dialogs.push(params);
    if (!answers.length) throw new Error(`하네스: 대화상자 응답 큐가 비었다 — ${j(params).slice(0, 200)}`);
    return answers.shift();
  });
  await context.exposeFunction('__sendTx', async (tx) => {
    const sent = await eoa.sendTransaction({ to: tx.to, data: tx.data ?? '0x', value: tx.value ?? 0 });
    return sent.hash;
  });
  await context.exposeFunction('__getReceipt', async (hash) => {
    const r = await provider.getTransactionReceipt(hash);
    return r ? { transactionHash: r.hash, status: Number(r.status), blockNumber: r.blockNumber } : null;
  });
  await context.addInitScript({ content: buildInitScript({ snapId: cfg.snapId, account, chainId: cfg.chainId }) });
  await context.addInitScript(GSI_STUB(`${stub.base}/mint`));
  await context.addInitScript(`window.__gsiSub = ${JSON.stringify(SUB)};`);
  context.on('page', (p) => p.on('dialog', (d) => d.accept()));   // Demo.confirmDanger(자기 폐기 확인)
  if (DEBUG) {
    context.on('page', (p) => {
      p.on('console', (m) => console.log(`    [${new URL(p.url()).port}] ${m.type()}: ${m.text()}`));
      p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`));
    });
  }

  const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
  // 로그인 모달(2026-10-15): #loginBtn 은 모달을 열기만 하고, 실제 zk 로그인은 모달의 #idpLoginBtn 이 한다.
  // 2026-10-21: 로그인 상태에서는 로그인 버튼이 숨으므로, 이미 로그인돼 있으면 먼저 로그아웃한다.
  const idpLogin = async (page) => { if (await page.$eval('#loginBtn', (b) => b.hidden)) { await page.click('#logoutBtn'); await page.waitForSelector('#loginBtn:not([hidden])'); } await page.click('#loginBtn'); await page.click('#idpLoginBtn'); };
  /** sel 의 텍스트가 needle 을 담을 때까지 기다린다. 실패하면 지금 보이는 텍스트를 붙여 던진다. */
  async function waitText(page, sel, needle, timeout = 30_000) {
    try {
      await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout });
    } catch (e) {
      throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`);
    }
  }

  const walletPage = await context.newPage();
  await walletPage.goto(`${wallet.base}/`);
  await t('지갑 페이지(localhost): MetaMask·Snap 연결', async () => {
    await walletPage.click('#connectBtn');
    await waitText(walletPage, '#mmStatus', 'MetaMask 0x');   // 2026-11-05: 배지는 "MetaMask 0x…"(Snap id 는 보이지 않는다)
  });

  await t('/user: "Google 로 등록" → 지갑 팝업 → Snap 보류 등록(확인 창 없음, 2026-11-05) → 팝업의 Google 버튼 → 등록됨(provider·uid=H(provider|sub)); IdP 로그인 없이', async () => {
    const u = await context.newPage(); await u.goto(`${ciaUi}/user?google=1`);   // 2026-11-06: Google 등록 버튼은 ?google=1 일 때만 보인다
    await u.waitForSelector('#registerGoogleBtn:not([hidden])', { timeout: 15_000 });
    const dBefore = dialogs.length;
    const [popup] = await Promise.all([context.waitForEvent('page'), u.click('#registerGoogleBtn')]);
    await popup.waitForSelector('#gsiBox .gsi-stub', { timeout: 30_000 });
    assert.equal(dialogs.length, dBefore, 'Snap 등록 확인 창은 없다(2026-11-05 중복 확인 제거)');
    await popup.click('#gsiBox .gsi-stub');
    await waitText(u, '#userVerdict', '등록됨', 60_000);   // 2026-11-05: uid 는 화면에 보이지 않는다 — 지갑 상태로 본다
    const st = (await wallet.get('/wallet/status')).body;
    assert.equal(st.provider, stub.provider); assert.equal(st.uid, uidOf(stub.provider, SUB));
    assert.equal(JSON.parse(JSON.stringify(snapState)).registration.uid, st.uid, 'Snap 보류 등록에 uid 가 채워졌다');
    await u.close();
  });

  await t('반쯤 된 등록 복구: Snap 을 보류로 되돌리고 "Google 로 등록" 다시 → Google 버튼 없이 Snap 저장을 마저 한다(uid 복원)', async () => {
    const full = JSON.parse(JSON.stringify(snapState.registration));
    assert.ok(full.uid && snapState.salt?.s_u, 'Snap 에 완성된 등록과 salt 가 있어야 한다');
    const saltBefore = snapState.salt.s_u;
    // IdP 등록·에이전트 저장은 끝났는데 Snap storeRegistration 이 안 된 상태 — 보류 등록만 남긴다(0.5.0: 비밀은 등록이 아니라 salt 에 있다)
    for (const k of ['uid', 'auid', 'slot', 'attrs', 'provider']) snapState.registration[k] = null;
    const u = await context.newPage(); await u.goto(`${ciaUi}/user?google=1`);   // 2026-11-06: Google 등록 버튼은 ?google=1 일 때만 보인다
    await u.waitForSelector('#registerGoogleBtn:not([hidden])', { timeout: 15_000 });
    const [popup] = await Promise.all([context.waitForEvent('page'), u.click('#registerGoogleBtn')]);   // prepareRegister 는 확인 창 없이 같은 비밀을 돌려준다
    await waitText(u, '#userVerdict', '등록됨', 60_000);   // 2026-11-05: 결과 문구에 uid 는 없다 — 복원된 uid 는 아래 Snap 상태로 본다
    assert.equal(await popup.$('#gsiBox .gsi-stub'), null, '복구는 Google 로그인을 다시 하지 않는다');
    const back = JSON.parse(JSON.stringify(snapState.registration));
    for (const k of ['uid', 'auid', 'slot', 'provider']) assert.equal(back[k], full[k], `복구된 Snap 등록.${k}`);
    assert.deepEqual(back.attrs, full.attrs);
    assert.equal(snapState.salt.s_u, saltBefore, 'salt 는 그대로다');
    await u.close();
  });

  // 2026-11-12(스펙 snap-derived-secrets §4.3): 예전엔 "등록이 반만 됐다" 로 멈췄다 — 이제 로그인 팝업이 보류 등록을 시드 유도 비밀로 마저 채우고(에이전트 resume) 로그인을 이어 간다.
  await t('반쯤 된 등록 + RP 로그인: 팝업이 보류 등록을 에이전트 등록으로 마저 채우고(Google 재로그인 없이 복구) 발급용 Google 버튼으로 로그인 성공', async () => {
    const full = JSON.parse(JSON.stringify(snapState.registration));
    for (const k of ['uid', 'auid', 'slot', 'attrs', 'provider']) snapState.registration[k] = null;
    try {
      const rpPage = await context.newPage(); await rpPage.goto(rp.base);
      const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
      await popup.waitForSelector('#gsiBox .gsi-stub', { timeout: 60_000 });   // 복구 뒤 발급용 Google 버튼
      const back = JSON.parse(JSON.stringify(snapState.registration));
      for (const k of ['uid', 'auid', 'slot', 'provider', 's_u']) assert.equal(back[k], full[k], `복구된 Snap 등록.${k}`);
      await popup.click('#gsiBox .gsi-stub');
      await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
      await rpPage.close();
    } finally { if (!snapState.registration?.uid) snapState.registration = full; }
  });

  await t('RP 로그인: IdP 로그인 페이지로 가지 않고 팝업의 Google 버튼 → 로그인 성공(CIA_ISSUE_AUTH=code 인데 코드 없음; 2026-11-05 부터 Snap 동의 창도 없다)', async () => {
    const rpPage = await context.newPage(); await rpPage.goto(rp.base);
    const dBefore = dialogs.length;
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await popup.waitForSelector('#gsiBox .gsi-stub', { timeout: 60_000 });
    assert.ok(popup.url().includes('authorize=1') && !popup.url().includes('/login'), `Google 계정은 IdP 로그인 페이지로 가지 않는다: ${popup.url()}`);
    assert.equal(dialogs.length, dBefore, 'Snap 로그인 동의 창은 없다(2026-11-05)');
    await popup.click('#gsiBox .gsi-stub');
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    await rpPage.close();
  });

  // 2026-11-11(사용자 지적): zkID 로 로그인한 상태에서 Google·네이버로 로그인하면 화면이 이전 zkID 세션(r_s)을 버리지 않아 새 소셜 계정에 그 PPID·자산이
  // 섞여 보였다("zkID 연결이 자동으로 됐다"). 소셜 로그인은 로그인 전체를 바꾼다 — 남은 zkID 세션은 끝낸다(RP 에서도).
  // 2026-11-11(사용자 결정): RP 의 Google 버튼은 zkID 래퍼가 됐다(그 자체가 zkID 세션) — 소셜 로그인의 세션 정리는 네이버로 본다.
  await t('zkID 로그인 상태에서 네이버로 로그인하면 이전 zkID 세션이 정리된다(PPID·r_s 가 새 계정에 섞이지 않는다)', async () => {
    const page = await context.newPage(); await page.goto(`${rp.base}/`);
    await page.waitForFunction(() => typeof currentSession !== 'undefined' && currentSession, undefined, { timeout: 15_000 });   // 앞 케이스의 zkID 세션이 복원돼 있다
    const oldRs = await page.evaluate(() => currentSession);
    // 네이버로 돌아오는 길(페이지 새로 열림)은 저장해 둔 zkID 세션을 되살리지 않고 RP 에서도 끝낸다
    rpNaver.setNextSub('rp-n-mix');
    await page.evaluate(() => openLoginModal()); await page.click('#naverLoginBtn');   // 로그인 상태라 상단 버튼은 숨어 있다 — 열린 다른 탭 등에서 연 것과 같다
    await page.waitForFunction(() => (document.querySelector('#viaBadge')?.textContent ?? '').includes('네이버'), undefined, { timeout: 30_000 });
    assert.equal(await page.evaluate(() => currentSession), null, '화면의 zkID 세션은 끝났다');
    assert.equal((await text(page, '#accountPPID')).trim(), '-', '새 네이버 계정에는 PPID 가 없다');
    const me = await page.evaluate(() => fetch('/api/rp/me').then((r) => r.json()));
    assert.equal(me.methods.zkid, null, j(me));
    const sess = await page.evaluate(() => fetch('/api/mode3/sessions').then((r) => r.json()));
    assert.equal(sess.sessions.some((x) => x.r_s === `${oldRs.slice(0, 8)}…`), false, 'RP 에서도 옛 zkID 세션이 끝났다');
    assert.equal(await page.evaluate(() => localStorage.getItem('mode3.rp.session')), null, '저장된 zkID 세션도 지웠다');
    await page.click('#logoutBtn'); await page.waitForSelector('#assetsLoggedOut:not([hidden])');
    await page.close();
  });

  // 2026-11-11: zk 스냅 화면의 설정 탭(스냅 자기 폐기)은 없앴다 — 계정 폐기는 zkID 내 계정·관리자에서 한다.

  // 2026-11-11(사용자 결정): 로그인 창의 Google 버튼은 zkID 래퍼다 — RP 직접 Google 은 내 계정의 "연결"에만 남는다.
  await t('RP 소셜(2026-11-10): 로그인 창 네이버 → 새 RP 계정·via 네이버 배지 → 내 계정에서 Google 연결(GIS 흉내, RP 직접) → 자산에 거래소 보관 ETH·출금 출처; 로그아웃하면 /api/rp/me 401', async () => {
    const page = await context.newPage(); await page.goto(`${rp.base}/`);
    if (await page.$eval('#loginBtn', (b) => b.hidden)) { await page.click('#logoutBtn'); await page.waitForSelector('#loginBtn:not([hidden])'); }
    await page.click('#loginBtn'); assert.equal(await page.isVisible('#googleLoginBtn'), true, '로그인 창의 Google 버튼은 래퍼 버튼 그대로 보인다(GIS 를 바로 그리지 않는다)');
    rpNaver.setNextSub('rp-n-user');
    await page.click('#naverLoginBtn');
    await page.waitForSelector('#assetsLoggedIn:not([hidden])', { timeout: 30_000 });
    assert.match(await text(page, '#viaBadge'), /네이버/);
    await page.click('#navAccount'); await page.waitForSelector('#account:not([hidden])');
    assert.match(await text(page, '#mState_naver'), /연결됨/); assert.match(await text(page, '#mState_google'), /연결 안 됨/);
    await page.evaluate((u) => { window.__gsiMintUrl = u; window.__gsiSub = 'rp-g-user'; }, `${rpGoogle.base}/mint`);   // 이 페이지의 GIS 흉내는 RP 용 Google 스텁으로
    await page.click('#mLink_google');
    await page.waitForSelector('#linkGsiSlot .gsi-stub', { timeout: 30_000 }); await page.click('#linkGsiSlot .gsi-stub');
    await waitText(page, '#accountVerdict', 'Google');
    assert.match(await text(page, '#mState_google'), /연결됨/);
    assert.equal(await page.isVisible('#mUnlink_google'), true);
    assert.equal(await page.$eval('li[data-asset="ETH_CUSTODY"]', (el) => !el.hidden), true);
    assert.equal(await page.$eval('#txSource option[value="account"]', (o) => o.disabled), true, 'zkID 세션이 아니면 내 계정 출금 불가');
    await page.click('#logoutBtn'); await page.waitForSelector('#assetsLoggedOut:not([hidden])');
    assert.equal(await page.evaluate(() => fetch('/api/rp/me').then((r) => r.status)), 401);
    await page.close();
  });

  // 2026-11-11(사용자 결정): RP 의 "Google 계정으로 로그인" = OIDC 래퍼 — 미등록 스냅이면 팝업에서 Google 로 등록(uid = H(google, sub))하고 이어서
  // zkID 와 같은 발급·증명으로 PPID 세션을 만든다. 등록·발급의 nonce 가 달라 팝업의 Google 버튼을 두 번 누른다.
  await t('Google 래퍼: 미등록 스냅에서 RP 의 Google 버튼 → 팝업 Google(등록) → 팝업 Google(발급) → zkID 로그인 성공·PPID; IdP 로그인 페이지로 가지 않는다', async () => {
    assert.equal((await wallet.post('/wallet/reset', { confirm: true })).status, 200);
    snapState = readySnap(SALT_B);                                      // 새로 설치해 설정을 끝낸 스냅(다른 salt — 앞 계정과 다른 스냅)
    const SUB2 = 'g-browser-2';
    const rpPage = await context.newPage(); await rpPage.goto(rp.base);
    if (await rpPage.$eval('#loginBtn', (b) => b.hidden)) { await rpPage.click('#logoutBtn'); await rpPage.waitForSelector('#loginBtn:not([hidden])'); }
    await rpPage.click('#loginBtn');
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#googleLoginBtn')]);
    await popup.waitForSelector('#gsiBox .gsi-stub', { timeout: 60_000 });
    await popup.evaluate((s) => { window.__gsiSub = s; }, SUB2);        // 로드된 뒤에 — 흉내 버튼은 누를 때 이 값을 읽는다
    assert.ok(popup.url().includes('authorize=1') && !popup.url().includes('/login'), `IdP 로그인 페이지로 가지 않는다: ${popup.url()}`);
    await popup.click('#gsiBox .gsi-stub');                             // 등록용 토큰
    await popup.waitForSelector('#gsiBox .gsi-stub', { state: 'detached', timeout: 60_000 });   // 첫 버튼이 치워진 뒤에 다음 버튼을 기다린다
    await popup.waitForSelector('#gsiBox .gsi-stub', { timeout: 120_000 });
    await popup.click('#gsiBox .gsi-stub');                             // 발급용 토큰
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    const st = (await wallet.get('/wallet/status')).body;
    assert.equal(st.registered, true); assert.equal(st.provider, stub.provider); assert.equal(st.uid, uidOf(stub.provider, SUB2), 'Google 계정마다 별도 zkID 계정');
    assert.equal(snapState.registration.uid, st.uid, '스냅에도 등록됐다');
    assert.ok(await rpPage.evaluate(() => currentSession), 'zkID 세션이 잡혔다');
    assert.notEqual((await text(rpPage, '#accountPPID')).trim(), '-', 'PPID 가 있다');
    await rpPage.close();
  });

  // 2026-11-13(스펙 random-salt): 스냅을 다시 깐 뒤 백업에서 같은 salt 를 불러오면 Google 계정도 재설치(R1)·새 PC(R2) 뒤 같은 PPID 로 돌아온다.
  // 앞 케이스("Google 래퍼")가 SUB2 계정으로 등록·로그인한 상태에서 이어 간다.
  const googleLogin = async (clicks) => {
    const rpPage = await context.newPage(); await rpPage.goto(rp.base);
    if (await rpPage.$eval('#loginBtn', (b) => b.hidden)) { await rpPage.click('#logoutBtn'); await rpPage.waitForSelector('#loginBtn:not([hidden])'); }
    await rpPage.click('#loginBtn');
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#googleLoginBtn')]);
    for (let i = 0; i < clicks; i++) {
      if (i > 0) await popup.waitForSelector('#gsiBox .gsi-stub', { state: 'detached', timeout: 60_000 });
      await popup.waitForSelector('#gsiBox .gsi-stub', { timeout: 120_000 });
      await popup.evaluate((sub) => { window.__gsiSub = sub; }, 'g-browser-2');
      await popup.click('#gsiBox .gsi-stub');
    }
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    const ppid = (await text(rpPage, '#accountPPID')).trim();
    await rpPage.close();
    return ppid;
  };
  let googlePPID = null;
  await t('복구 R1(Google): 스냅을 다시 깔고 백업에서 같은 salt 를 불러오면 RP "Google 계정으로 로그인" 이 스냅 등록을 되살리고 같은 PPID(Google 버튼은 발급용 한 번)', async () => {
    const st0 = (await wallet.get('/wallet/status')).body;
    assert.equal(st0.provider, stub.provider, '앞 케이스의 Google 계정 등록이 있어야 한다');
    googlePPID = await googleLogin(1);   // 기준 PPID(스냅 그대로)
    assert.notEqual(googlePPID, '-');
    snapState = readySnap(SALT_B);   // 스냅 재설치 + 백업에서 salt 불러오기(등록은 비었다)
    assert.equal(await googleLogin(1), googlePPID, '같은 PPID');
    assert.equal(snapState.registration?.uid, st0.uid); assert.equal(snapState.registration?.provider, stub.provider);
  });
  await t('복구 R2(Google): 스냅·에이전트 둘 다 잃으면 Google 등록이 IdP 복구(같은 uid·slot)로 이어져 같은 PPID(Google 버튼은 등록·발급 두 번)', async () => {
    const st0 = (await wallet.get('/wallet/status')).body;
    assert.equal((await wallet.post('/wallet/reset', { confirm: true })).status, 200);
    snapState = readySnap(SALT_B);
    assert.equal(await googleLogin(2), googlePPID, '같은 PPID');
    const st = (await wallet.get('/wallet/status')).body;
    assert.equal(st.uid, st0.uid); assert.equal(st.slot, st0.slot, 'IdP 가 같은 슬롯을 돌려줬다(새 등록이 아니다)');
  });
  await t('하네스: 준비한 대화상자 응답이 남지 않았다(기대한 동의 창이 다 떴다)', async () => {
    assert.equal(answers.length, 0, `쓰이지 않은 응답이 남았다: ${j(answers)}`);
  });
} finally {
  await browser.close();
  await stack.stop();
  await rpGoogle.stop(); await rpNaver.stop();
  provider.destroy();
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed === 0 ? 0 : 1);
