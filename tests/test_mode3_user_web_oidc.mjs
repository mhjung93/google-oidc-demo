// tests/test_mode3_user_web_oidc.mjs — Google(OIDC 래퍼) 경로를 실제 Chrome 에서(스펙 2026-10-16 §7). GIS 는 addInitScript 스텁(발급자 스텁에서 토큰), 사용자 오리진은 localhost(D6).
// hardhat :8545, build/mode3, Chrome 필요. 번들은 여기서 만든다. (browser)   node tests/test_mode3_user_web_oidc.mjs   MODE3_BROWSER_DEBUG=1 로 콘솔.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { uidOf } from '../lib/mode3_oidc_nonce.js';

const DEBUG = process.env.MODE3_BROWSER_DEBUG === '1';
const j = (o) => JSON.stringify(o);
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); } }
async function launchBrowser() { const tried = []; for (const opts of [{ channel: 'chrome' }, {}]) { try { return await chromium.launch(opts); } catch (e) { tried.push(`${j(opts)}: ${e.message.split('\n')[0]}`); } } throw new Error(`BLOCKED: 브라우저를 띄우지 못했다.\n  ${tried.join('\n  ')}`); }
const GSI_STUB = (mintUrl) => `window.__gsiMintUrl = ${j(mintUrl)}; window.__gsiSub = window.__gsiSub ?? 'g-user-1';
window.google = { accounts: { id: { _cfg: null, initialize(cfg) { this._cfg = cfg; },
  renderButton(el, opts) { const b = document.createElement('button'); b.type = 'button'; b.className = 'gsi-stub'; b.textContent = 'Google(stub:' + (opts?.text ?? '') + ')';
    b.addEventListener('click', async () => { const r = await fetch(window.__gsiMintUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sub: window.__gsiSub, nonce: this._cfg.nonce }) }); const { id_token } = await r.json(); this._cfg.callback({ credential: id_token }); });
    el.replaceChildren(b); } } } };`;

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
const browser = await launchBrowser();
const stack = await startIsolatedMode3Stack({ userMode: 'web', autoRelay: true, oidc: true, walletHost: 'localhost' });
const { wallet, rp, cia, oidc: stub } = stack;
const PW = 'oidc-vault-pw';
const SUB1 = 'g-user-1', SUB2 = 'g-user-2', SUB3 = 'g-user-3';
try {
  const context = await browser.newContext();
  await context.addInitScript(GSI_STUB(`${stub.base}/mint`));
  if (DEBUG) context.on('page', (p) => { p.on('console', (m) => console.log(`    [${new URL(p.url()).host}] ${m.type()}: ${m.text()}`)); p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`)); });
  const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
  async function waitText(page, sel, needle, timeout = 60_000) {
    try { await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout }); }
    catch { throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`); }
  }
  const idbDump = (page) => page.evaluate(async () => { const open = indexedDB.open('mode3-user', 1); const db = await new Promise((r, x) => { open.onsuccess = () => r(open.result); open.onerror = () => x(open.error); }); const st = db.transaction('kv', 'readonly').objectStore('kv'); const keys = await new Promise((r) => { const q = st.getAllKeys(); q.onsuccess = () => r(q.result); }); const out = {}; for (const k of keys) out[k] = await new Promise((r) => { const q = st.get(k); q.onsuccess = () => r(q.result); }); return JSON.parse(JSON.stringify(out, (k, v) => (v instanceof CryptoKey ? '[CryptoKey]' : v))); });
  async function viaPopup(trigger, fn) { const [popup] = await Promise.all([context.waitForEvent('page'), trigger()]); await popup.waitForSelector('#authorizeView:not([hidden])'); await fn(popup); if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 120_000 }); }
  const approve = async (popup) => { await popup.waitForSelector('#authApproveBtn:not([hidden])', { timeout: 60_000 }); await popup.click('#authApproveBtn'); };
  const setSub = (page, sub) => page.evaluate((s) => { window.__gsiSub = s; }, sub);

  assert.match(wallet.base, /^http:\/\/localhost:/, 'walletHost 옵션으로 사용자 오리진이 localhost 다');
  const userPage = await context.newPage();
  await userPage.goto(`${wallet.base}/`);
  await userPage.waitForSelector('#mainView:not([hidden])');
  const rpPage = await context.newPage();
  await rpPage.goto(`${rp.base}/`);
  await waitText(rpPage, '#walletMode', '사용자 비밀=브라우저');

  await t('G1 미등록 + RP 모달 Google 버튼 → 팝업이 등록 안내와 사용자 페이지 링크를 보이고 not_registered 로 끝난다', async () => {
    await rpPage.click('#loginBtn');
    assert.equal(await rpPage.getAttribute('#googleLoginBtn', 'data-oidc'), '1', 'rp_info.oidc.enabled 로 Google 버튼이 활성');
    let hint = '', href = '';
    await viaPopup(() => rpPage.click('#googleLoginBtn'), async (popup) => { await popup.waitForSelector('#authHint:not([hidden])', { timeout: 60_000 }); hint = await text(popup, '#authHint'); href = await popup.getAttribute('#authHint a', 'href'); });
    assert.ok(hint.includes('Google'), hint); assert.equal(href, `${wallet.base}/`);
    await waitText(rpPage, '#verdict', 'not_registered', 30_000);
  });
  await t('G2 사용자 페이지: Google 행이 보이고(stub 버튼) 금고 비밀번호 + Google → 등록됨; registration.provider = 스텁 provider, uid = uidOf(provider, sub)', async () => {
    await userPage.waitForSelector('#googleRegRow:not([hidden])');
    await userPage.waitForSelector('#googleRegSlot .gsi-stub', { timeout: 30_000 });
    await setSub(userPage, SUB1);
    await userPage.fill('#vaultPw', PW); await userPage.fill('#vaultPw2', PW);
    await userPage.click('#googleRegSlot .gsi-stub');
    await waitText(userPage, '#registerResult', '등록됨', 90_000);
    const d = await idbDump(userPage);
    assert.equal(d.registration.provider, stub.provider); assert.equal(d.registration.uid, uidOf(stub.provider, SUB1)); assert.ok(!('s_u' in d.registration));
    await waitText(userPage, '#regInfo', stub.provider);
    assert.equal(await userPage.isHidden('#googleRegRow'), true, '등록 뒤 Google 등록 행은 숨는다');
  });
  await t('G3 RP 모달 Google 버튼 → 팝업 요약에 신원 줄(provider) → 승인 → 로그인 성공', async () => {
    await rpPage.click('#loginBtn');
    await viaPopup(() => rpPage.click('#googleLoginBtn'), async (popup) => { await waitText(popup, '#authSummary', stub.provider); await approve(popup); });
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
  });
  await t('G4 계정 페이지(localhost): Google 폐기 행 → stub 버튼 → 200 revoked; 데모 uid/pwd 폼은 그대로 있다', async () => {
    const acct = await context.newPage();
    await acct.goto(`${cia.base.replace('127.0.0.1', 'localhost')}/account`);
    await acct.waitForSelector('#googleRevokeRow:not([hidden])'); await acct.waitForSelector('#googleRevokeSlot .gsi-stub', { timeout: 30_000 });
    assert.ok(await acct.$('#revokeBtn'), '데모 폼 유지');
    await setSub(acct, SUB1);
    acct.once('dialog', (d) => d.accept());
    await acct.click('#googleRevokeSlot .gsi-stub');
    await waitText(acct, '#out', '→ 200', 30_000);
    await acct.close();
  });
  await t('G5 폐기 뒤 RP Google 로그인은 account_disabled', async () => {
    await rpPage.click('#loginBtn');
    await viaPopup(() => rpPage.click('#googleLoginBtn'), async (popup) => { await approve(popup); });
    await waitText(rpPage, '#verdict', 'account_disabled', 120_000);
  });
  await t('G6 모두 지우기 → 두 번째 Google 계정으로 등록 → 사용자 페이지의 Google 폐기 행(폐기 버튼 대신)으로 자기 폐기 → revoked', async () => {
    userPage.once('dialog', (d) => d.accept());
    await userPage.click('#wipeBtn');
    await waitText(userPage, '#storageVerdict', '지웠습니다', 30_000);
    await userPage.waitForSelector('#googleRegSlot .gsi-stub', { timeout: 30_000 });
    await setSub(userPage, SUB2);
    await userPage.fill('#vaultPw', PW); await userPage.fill('#vaultPw2', PW);
    await userPage.click('#googleRegSlot .gsi-stub');
    await waitText(userPage, '#registerResult', '등록됨', 90_000);
    await userPage.waitForSelector('#googleRevokeRow:not([hidden])'); await userPage.waitForSelector('#googleRevokeSlot .gsi-stub', { timeout: 30_000 });
    assert.equal(await userPage.isHidden('#selfRevokeBtn'), true, 'Google 계정에는 비밀번호 폐기 버튼이 없다');
    userPage.once('dialog', (d) => d.accept());
    await userPage.click('#googleRevokeSlot .gsi-stub');
    await waitText(userPage, '#storageVerdict', '폐기', 60_000);
    const r = await cia.adminGet('/cia/accounts'); const acc = (r.body.accounts ?? r.body).find((a) => String(a.uid) === uidOf(stub.provider, SUB2)); assert.equal(acc?.disabled, true);
  });
  await t('G7 127.0.0.1 로 연 사용자 페이지: Google 행 대신 localhost 안내(gsi_origin)와 링크', async () => {
    const p = await context.newPage();
    await p.goto(`${wallet.base.replace('localhost', '127.0.0.1')}/`);
    await p.waitForSelector('#mainView:not([hidden])');
    await p.waitForSelector('#googleRegNote:not([hidden])');
    assert.ok((await text(p, '#googleRegNote')).includes('localhost')); assert.equal(await p.getAttribute('#googleRegNote a', 'href'), `${wallet.base}/`);
    assert.equal(await p.isHidden('#googleRegRow'), true);
    await p.close();
  });
  await t('G8 GIS 스크립트를 못 받으면(스텁 없음 + 네트워크 차단) gsi_unavailable 안내 — 데모 계정 등록 폼은 그대로', async () => {
    const ctx2 = await browser.newContext();
    await ctx2.route('https://accounts.google.com/**', (r) => r.abort());
    const p = await ctx2.newPage();
    await p.goto(`${wallet.base}/`); await p.waitForSelector('#mainView:not([hidden])');
    await p.waitForSelector('#googleRegNote:not([hidden])', { timeout: 20_000 });
    assert.ok((await text(p, '#googleRegNote')).includes('Google'), await text(p, '#googleRegNote'));
    assert.ok(await p.$('#registerBtn'));
    await ctx2.close();
  });
  await t('G9 사전: 새 사유 6개와 ui 키가 ko·en 으로 있다(strings.js 를 페이지가 아니라 파일로)', async () => {
    const src = readFileSync('mode3/common/strings.js', 'utf8');
    for (const k of ['oidc_disabled', 'oidc_invalid', 'oidc_nonce_mismatch', 'oidc_unavailable', 'gsi_unavailable', 'gsi_origin', 'user_register_hint_google', 'user_auth_identity', 'account_google_revoke_label', 'rp_google_login_note']) assert.ok(src.includes(`${k}:`), k);
  });
  // 수정 라운드 1(Important 1): wipe 는 코어의 보류 등록 재료를 지운다 — 미등록 상태에서 지운 뒤에도 Google 버튼이 새 nonce 로 다시 걸려야 한다
  // (G6 은 폐기 버튼이 걸린 뒤에 지워서 이 경로를 피해 갔다). 새 컨텍스트 = 빈 IndexedDB, 처음 보는 sub.
  await t('G10 미등록 상태에서 모두 지우기 → 바로 Google 등록이 된다(버려진 nonce 의 버튼이 남지 않는다)', async () => {
    const ctx3 = await browser.newContext();
    await ctx3.addInitScript(GSI_STUB(`${stub.base}/mint`));
    try {
      const p = await ctx3.newPage();
      await p.goto(`${wallet.base}/`); await p.waitForSelector('#mainView:not([hidden])');
      await p.waitForSelector('#googleRegSlot .gsi-stub', { timeout: 30_000 });
      p.once('dialog', (d) => d.accept());
      await p.click('#wipeBtn');
      await waitText(p, '#storageVerdict', '지웠습니다', 30_000);
      await p.waitForSelector('#googleRegSlot .gsi-stub', { timeout: 30_000 });
      await setSub(p, SUB3);
      await p.fill('#vaultPw', PW); await p.fill('#vaultPw2', PW);
      await p.click('#googleRegSlot .gsi-stub');
      await waitText(p, '#registerResult', '등록됨', 90_000);
      const d = await idbDump(p);
      assert.equal(d.registration.provider, stub.provider); assert.equal(d.registration.uid, uidOf(stub.provider, SUB3));
    } finally { await ctx3.close(); }
  });
} finally { await browser.close(); await stack.stop(); }
process.exit(failed ? 1 : 0);
