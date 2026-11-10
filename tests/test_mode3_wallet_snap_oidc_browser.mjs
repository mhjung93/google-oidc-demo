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
// ciaHost 'localhost'(2026-11-09 연결 로그인): 인증 창·/user 도 localhost 오리진이라 GIS(스텁)가 그려진다 — 분리 데모의 SSH 터널과 같은 모양. naver: 네이버 흉내.
// RP 소셜(2026-11-10): RP 가 직접 쓰는 Google·네이버 흉내 — IdP 래퍼용 stub 과 따로. RP 는 localhost 오리진(rpHost)이라 GIS 가 그려지고 네이버 콜백 쿠키가 맞는다.
const rpGoogle = await startOidcIssuerStub({ clientId: 'rp-google-client', provider: 'google' });
const rpNaver = await startOidcIssuerStub({ clientId: 'rp-naver-client', provider: 'naver', clientSecret: 'rp-naver-secret' });
const rpSocialEnv = {
  MODE3_RP_GOOGLE_CLIENT_ID: rpGoogle.clientId, MODE3_RP_GOOGLE_ISSUER: rpGoogle.issuer, MODE3_RP_GOOGLE_JWKS_URL: rpGoogle.jwksUrl,
  MODE3_RP_NAVER_CLIENT_ID: rpNaver.clientId, MODE3_RP_NAVER_CLIENT_SECRET: rpNaver.clientSecret, MODE3_RP_NAVER_ISSUER: rpNaver.issuer, MODE3_RP_NAVER_JWKS_URL: rpNaver.jwksUrl,
  MODE3_RP_NAVER_AUTHORIZE_URL: rpNaver.authorizeUrl, MODE3_RP_NAVER_TOKEN_URL: rpNaver.tokenUrl,
};
const stack = await startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'snap' }, ciaEnv: { CIA_ISSUE_AUTH: 'code' }, rpEnv: rpSocialEnv, autoRelay: true, oidc: true, naver: true, walletHost: 'localhost', ciaHost: 'localhost', rpHost: 'localhost' });
const { cia, wallet, rp, oidc: stub, naver: naverStub, ciaUiBase: ciaUi } = stack;
const SUB = 'g-browser-1';

// ---- 하네스가 맡는 것: Snap 저장소, 대화상자, 체인 전송 (test_mode3_browser.mjs 와 같다) ----
let snapState = null;
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
    assert.ok(full.uid && full.sk_u && full.s_u, 'Snap 에 완성된 등록이 있어야 한다');
    // IdP 등록·에이전트 저장은 끝났는데 Snap storeRegistration 이 안 된 상태 — s_u·sk_u 만 남긴다
    for (const k of ['uid', 'auid', 'slot', 'attrs', 'provider']) snapState.registration[k] = null;
    const u = await context.newPage(); await u.goto(`${ciaUi}/user?google=1`);   // 2026-11-06: Google 등록 버튼은 ?google=1 일 때만 보인다
    await u.waitForSelector('#registerGoogleBtn:not([hidden])', { timeout: 15_000 });
    const [popup] = await Promise.all([context.waitForEvent('page'), u.click('#registerGoogleBtn')]);   // prepareRegister 는 확인 창 없이 같은 비밀을 돌려준다
    await waitText(u, '#userVerdict', '등록됨', 60_000);   // 2026-11-05: 결과 문구에 uid 는 없다 — 복원된 uid 는 아래 Snap 상태로 본다
    assert.equal(await popup.$('#gsiBox .gsi-stub'), null, '복구는 Google 로그인을 다시 하지 않는다');
    const back = JSON.parse(JSON.stringify(snapState.registration));
    for (const k of ['uid', 'auid', 'slot', 'provider', 's_u', 'sk_u']) assert.equal(back[k], full[k], `복구된 Snap 등록.${k}`);
    assert.deepEqual(back.attrs, full.attrs);
    await u.close();
  });

  await t('반쯤 된 등록 + RP 로그인: 동의 창 없이 "등록이 반만 됐다" 안내(reason=registration_incomplete), Snap 복원 뒤에는 다시 정상', async () => {
    const full = JSON.parse(JSON.stringify(snapState.registration));
    for (const k of ['uid', 'auid', 'slot', 'attrs', 'provider']) snapState.registration[k] = null;
    try {
      const rpPage = await context.newPage(); await rpPage.goto(rp.base);
      const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
      await waitText(popup, '#authStep', '등록이 반만 됐다', 60_000);
      assert.ok((await text(popup, '#authStep')).includes("'Google 로 등록'"), '다시 등록하라는 안내');
      await rpPage.close();
    } finally { snapState.registration = full; }
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

  await t('자기 폐기: 지갑 페이지의 Google 버튼(비밀번호 프롬프트 없음) → IdP 계정 disabled', async () => {
    const before = dialogs.length;
    await walletPage.click('#walletTabs [data-tab="settings"]');   // 자기 폐기는 설정 탭(2026-11-03)
    await walletPage.click('#selfRevokeBtn');
    await walletPage.waitForSelector('#gsiBox .gsi-stub', { timeout: 15_000 });
    await walletPage.click('#gsiBox .gsi-stub');
    await waitText(walletPage, '#snapVerdict', '폐기를 zkID 에 요청', 60_000);   // 2026-11-05: 결과 문구에 uid 는 없다
    assert.equal(dialogs.length, before, 'Snap 비밀번호 프롬프트를 띄우지 않는다');
    const a = (await cia.adminGet('/cia/accounts')).body.accounts.find((x) => String(x.uid) === uidOf(stub.provider, SUB));
    assert.equal(a?.disabled, true);
  });

  // 2026-11-09 연결 로그인(스펙 linked-logins L1·L2·L6): 아이디 계정에 /user 에서 Google·네이버를 연결 → 미등록 지갑 + RP 의 Google 버튼 → 인증 창이
  // 연결된 Google 로 본인 확인(등록 모드) → 등록·발급 → 로그인. 지갑은 아이디 계정(provider demo)이고 Google 래퍼 가입은 일어나지 않는다(2026-11-06 흐름 대체).
  const LINK_ID = 'linkuser1', LINK_PWD = 'linkpw-12345', LINK_GSUB = 'g-linked-1', LINK_NSUB = 'n-linked-1';
  let linkUid = null;
  await t('/user: 아이디 계정에 Google·네이버 연결("연결된 로그인" 카드 — Google 은 GIS, 네이버는 IdP 를 거쳐 다녀온다)', async () => {
    const s = await cia.post('/cia/signup', { id: LINK_ID, pwd: LINK_PWD }); assert.equal(s.status, 201, j(s.body)); linkUid = s.body.uid;
    const u = await context.newPage(); await u.goto(`${ciaUi}/user`);
    await u.fill('#loginId', LINK_ID); await u.fill('#loginPwd', LINK_PWD); await u.click('#loginBtn');
    await u.waitForSelector('#linksCard:not([hidden])');
    await u.evaluate((sub) => { window.__gsiSub = sub; }, LINK_GSUB);
    await u.click('#linkGoogleBtn');
    await u.waitForSelector('#linkGsiSlot .gsi-stub'); await u.click('#linkGsiSlot .gsi-stub');
    await waitText(u, '#linksVerdict', 'Google 계정을 연결했습니다');
    naverStub.setNextSub(LINK_NSUB);
    await u.click('#linkNaverBtn');   // IdP → 네이버 흉내(바로 code) → 콜백 → /user?linked=naver
    await waitText(u, '#linksVerdict', '네이버 계정을 연결했습니다');
    assert.match(await text(u, '#linkGoogleState'), /연결됨/); assert.match(await text(u, '#linkNaverState'), /연결됨/);
    assert.equal(new URL(u.url()).searchParams.has('linked'), false, '돌아온 주소의 ?linked 는 지운다');
    await u.close();
  });

  await t('RP 소셜(2026-11-10): 로그인 창 Google(GIS 흉내) → 새 RP 계정·via google 배지 → 내 계정에서 네이버 연결 → 자산에 거래소 보관 ETH·출금 출처; 로그아웃하면 /api/rp/me 401', async () => {
    const page = await context.newPage(); await page.goto(`${rp.base}/`);
    if (await page.$eval('#loginBtn', (b) => b.hidden)) { await page.click('#logoutBtn'); await page.waitForSelector('#loginBtn:not([hidden])'); }
    await page.evaluate((u) => { window.__gsiMintUrl = u; window.__gsiSub = 'rp-g-user'; }, `${rpGoogle.base}/mint`);   // 이 페이지의 GIS 흉내는 RP 용 Google 스텁으로
    await page.click('#loginBtn'); await page.click('#googleLoginBtn');
    await page.waitForSelector('#loginGsiSlot .gsi-stub', { timeout: 30_000 });
    await page.click('#loginGsiSlot .gsi-stub');
    await page.waitForSelector('#assetsLoggedIn:not([hidden])', { timeout: 30_000 });
    assert.match(await text(page, '#viaBadge'), /Google/);
    await page.click('#navAccount'); await page.waitForSelector('#account:not([hidden])');
    assert.match(await text(page, '#mState_google'), /연결됨/); assert.match(await text(page, '#mState_naver'), /연결 안 됨/);
    assert.equal(await page.isVisible('#mUnlink_google'), true);
    rpNaver.setNextSub('rp-n-user');
    await page.click('#mLink_naver');                                   // 네이버 흉내를 다녀와 /?linked=naver#account 로 돌아온다
    await page.waitForURL((u) => u.hash === '#account' && !u.search, { timeout: 30_000 });
    await waitText(page, '#accountVerdict', '네이버');
    assert.match(await text(page, '#mState_naver'), /연결됨/);
    assert.equal(await page.$eval('li[data-asset="ETH_CUSTODY"]', (el) => !el.hidden), true);
    assert.equal(await page.$eval('#txSource option[value="account"]', (o) => o.disabled), true, 'zkID 세션이 아니면 내 계정 출금 불가');
    await page.click('#logoutBtn'); await page.waitForSelector('#assetsLoggedOut:not([hidden])');
    assert.equal(await page.evaluate(() => fetch('/api/rp/me').then((r) => r.status)), 401);
    await page.close();
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
