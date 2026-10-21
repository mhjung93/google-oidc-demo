// tests/test_mode3_user_web_oidc.mjs — OIDC 래퍼의 **남은 화면 경로**(2026-10-16 사용자 요청으로 사용자 페이지의 Google 등록·폐기 UI 는 뺐다 — 백엔드는 그대로).
// (1) 사용자 페이지에 Google 행·금고 비밀번호 칸이 없다 (2) RP 모달 Google 버튼은 안내만 (3) IdP 계정 페이지(localhost)에서 Google 로 자기 폐기 — 계정은 Node 에서
// IdP API + 발급자 스텁으로 만든다 (4) 사전에 사유 6개가 있다. hardhat :8545, build/mode3, Chrome 필요. (browser)   node tests/test_mode3_user_web_oidc.mjs
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { createRegistration, signRegistration } from '../lib/mode3_wallet.js';
import { auidOf } from '../lib/mode3_credential.js';
import { uidOf, regNonce } from '../lib/mode3_oidc_nonce.js';

const DEBUG = process.env.MODE3_BROWSER_DEBUG === '1';
const j = (o) => JSON.stringify(o);
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); } }
async function launchBrowser() { const tried = []; for (const opts of [{ channel: 'chrome' }, {}]) { try { return await chromium.launch(opts); } catch (e) { tried.push(`${j(opts)}: ${e.message.split('\n')[0]}`); } } throw new Error(`BLOCKED: 브라우저를 띄우지 못했다.\n  ${tried.join('\n  ')}`); }
// 진짜 GIS 대신: initialize 가 준 nonce 로 발급자 스텁 /mint 에서 토큰을 받아 callback 을 부르는 버튼. sub 는 window.__gsiSub.
const GSI_STUB = (mintUrl) => `window.__gsiMintUrl = ${j(mintUrl)}; window.__gsiSub = window.__gsiSub ?? 'g-user-1';
window.google = { accounts: { id: { _cfg: null, initialize(cfg) { this._cfg = cfg; },
  renderButton(el, opts) { const b = document.createElement('button'); b.type = 'button'; b.className = 'gsi-stub'; b.textContent = 'Google(stub:' + (opts?.text ?? '') + ')';
    b.addEventListener('click', async () => { const r = await fetch(window.__gsiMintUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sub: window.__gsiSub, nonce: this._cfg.nonce }) }); const { id_token } = await r.json(); this._cfg.callback({ credential: id_token }); });
    el.replaceChildren(b); } } } };`;

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
const browser = await launchBrowser();
const stack = await startIsolatedMode3Stack({ userMode: 'web', autoRelay: true, oidc: true, walletHost: 'localhost' });
const { wallet, rp, cia, oidc: stub } = stack;
const SUB = 'g-user-1';
try {
  const context = await browser.newContext();
  await context.addInitScript(GSI_STUB(`${stub.base}/mint`));
  if (DEBUG) context.on('page', (p) => { p.on('console', (m) => console.log(`    [${new URL(p.url()).host}] ${m.type()}: ${m.text()}`)); p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`)); });
  const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
  async function waitText(page, sel, needle, timeout = 60_000) {
    try { await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout }); }
    catch { throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`); }
  }

  await t('(1) 사용자 페이지: Google 등록 행·금고 비밀번호 칸이 없다, 데모 계정 등록 폼은 있다', async () => {
    const p = await context.newPage(); await p.goto(`${wallet.base}/`); await p.waitForSelector('#mainView:not([hidden])');
    assert.equal((await p.$('#googleRegRow')) === null, true); assert.equal((await p.$('#googleRevokeRow')) === null, true); assert.equal((await p.$('#vaultPw')) === null, true);
    assert.ok(await p.$('#registerBtn')); assert.ok(await p.$('#uid')); await p.close();
  });
  await t('(2) RP "Google 로 로그인"(RP 로그인 흐름, 2026-10-16): 미등록 브라우저 → 승인 창 → 승인 → 창 안의 Google(stub) → 암묵 등록 + 발급 → 로그인 성공; 사용자 페이지는 등록됨(provider)', async () => {
    const rpPage = await context.newPage(); await rpPage.goto(`${rp.base}/`); await waitText(rpPage, '#walletMode', '사용자 비밀=브라우저');
    assert.equal((await (await fetch(`${rp.base}/api/mode3/rp_info`)).json()).oidc?.enabled, true, 'rp_info.oidc.enabled');
    await rpPage.click('#loginBtn');
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#googleLoginBtn')]);
    await popup.waitForSelector('#authorizeView:not([hidden])');
    await popup.waitForSelector('#authApproveBtn:not([hidden])', { timeout: 60_000 }); await popup.click('#authApproveBtn');
    await popup.waitForSelector('#authGoogleSlot .gsi-stub', { timeout: 30_000 });
    await popup.evaluate((s) => { window.__gsiSub = s; }, SUB);
    await popup.click('#authGoogleSlot .gsi-stub');
    await waitText(rpPage, '#verdict', '로그인 성공', 150_000);
    const userPage = await context.newPage(); await userPage.goto(`${wallet.base}/`); await userPage.waitForSelector('#mainView:not([hidden])');
    await waitText(userPage, '#regBadge', '등록', 20_000); await waitText(userPage, '#regInfo', stub.provider, 20_000);
    await userPage.close(); await rpPage.close();
  });
  await t('(3) 계정 페이지(localhost): Google 로 등록한 계정을 Google 재로그인으로 폐기 → 200, disabled', async () => {
    // 계정은 Node 에서 IdP 의 id_token 경로로 만든다(지갑 흉내: 재료 → sub 로 uid 선계산 → 등록 토큰 → sig_reg).
    const reg = await createRegistration(0n); const uid = uidOf(stub.provider, SUB); const auid = await auidOf({ uid: BigInt(uid), s_u: reg.s_u });
    const pk_u = { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() };
    const id_token = await stub.mint({ sub: SUB, nonce: regNonce(pk_u) });
    const r = await cia.post('/cia/register', { id_token, auid: auid.toString(), pk_u, sig_reg: await signRegistration(reg.sk_u, BigInt(uid), auid) });
    assert.ok(r.status === 201 || r.status === 409, j(r.body));   // (2) 가 이미 암묵 등록했으면 409 — 그 계정을 폐기한다
    const acct = await context.newPage(); await acct.goto(`${cia.base.replace('127.0.0.1', 'localhost')}/account`);
    await acct.waitForSelector('#googleRevokeRow:not([hidden])'); await acct.waitForSelector('#googleRevokeSlot .gsi-stub', { timeout: 30_000 });
    assert.ok(await acct.$('#revokeBtn'), '데모 uid/pwd 폼은 그대로');
    await acct.evaluate((s) => { window.__gsiSub = s; }, SUB);
    acct.once('dialog', (d) => d.accept());
    await acct.click('#googleRevokeSlot .gsi-stub');
    await waitText(acct, '#out', '→ 200', 30_000);
    const a = (await cia.adminGet('/cia/accounts')).body.accounts.find((x) => String(x.uid) === uid); assert.equal(a?.disabled, true); assert.equal(a?.provider, stub.provider);
    await acct.close();
  });
  await t('(4) 사전: OIDC 사유 6개와 계정 페이지 Google 키가 ko·en 으로 있다', async () => {
    const src = readFileSync('mode3/common/strings.js', 'utf8');
    for (const k of ['oidc_disabled', 'oidc_invalid', 'oidc_nonce_mismatch', 'oidc_unavailable', 'gsi_unavailable', 'gsi_origin', 'account_google_revoke_label', 'uid_mismatch']) assert.ok(src.includes(`${k}:`), k);
  });
} finally { await browser.close(); await stack.stop(); }
process.exit(failed ? 1 : 0);
