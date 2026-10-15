// tests/test_mode3_user_web.mjs — 브라우저 전용 사용자 페이지(web 모드)를 실제 Chrome 에서. 정적 서버 + 격리 IdP·RP(릴레이). 비밀은 IndexedDB 암호문에만.
// hardhat :8545, build/mode3, Chrome 필요. 번들은 여기서 만든다. (browser)   node tests/test_mode3_user_web.mjs   MODE3_BROWSER_DEBUG=1 로 콘솔을 본다.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { attrGateAt } from '../lib/mode3_onchain.js';

const DEBUG = process.env.MODE3_BROWSER_DEBUG === '1';
const j = (o) => JSON.stringify(o);
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); } }
async function launchBrowser() { const tried = []; for (const opts of [{ channel: 'chrome' }, {}]) { try { return await chromium.launch(opts); } catch (e) { tried.push(`${j(opts)}: ${e.message.split('\n')[0]}`); } } throw new Error(`BLOCKED: 브라우저를 띄우지 못했다.\n  ${tried.join('\n  ')}`); }

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
const browser = await launchBrowser();
const provider = getProvider();
const stack = await startIsolatedMode3Stack({ userMode: 'web', autoRelay: true });
const { wallet, rp } = stack;
const PW = 'demo-vault-pw';
try {
  const context = await browser.newContext();
  if (DEBUG) context.on('page', (p) => { p.on('console', (m) => console.log(`    [${new URL(p.url()).port}] ${m.type()}: ${m.text()}`)); p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`)); });
  const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
  async function waitText(page, sel, needle, timeout = 60_000) {
    try { await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout }); }
    catch { throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`); }
  }
  const idbDump = (page) => page.evaluate(async () => { const open = indexedDB.open('mode3-user', 1); const db = await new Promise((r, x) => { open.onsuccess = () => r(open.result); open.onerror = () => x(open.error); }); const st = db.transaction('kv', 'readonly').objectStore('kv'); const keys = await new Promise((r) => { const q = st.getAllKeys(); q.onsuccess = () => r(q.result); }); const out = {}; for (const k of keys) out[k] = await new Promise((r) => { const q = st.get(k); q.onsuccess = () => r(q.result); }); return JSON.parse(JSON.stringify(out, (k, v) => (v instanceof CryptoKey ? '[CryptoKey]' : v))); });
  const pageDump = (page) => page.evaluate(() => [document.documentElement.outerHTML, [...document.querySelectorAll('input,textarea,select')].map((e) => `${e.id}=${e.value}`).join('\n'), (() => { try { return JSON.stringify(localStorage) + JSON.stringify(sessionStorage); } catch { return ''; } })()].join('\n'));
  /** RP 페이지 동작이 여는 팝업을 잡아 fn(popup) 으로 조작하고, RP 쪽 결과를 기다린다. */
  async function viaPopup(trigger, fn) { const [popup] = await Promise.all([context.waitForEvent('page'), trigger()]); await popup.waitForSelector('#authorizeView:not([hidden])'); await fn(popup); if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 120_000 }); }
  const approve = async (popup) => { await popup.waitForSelector('#authApproveBtn:not([hidden])', { timeout: 60_000 }); await popup.click('#authApproveBtn'); };

  const userPage = await context.newPage();
  await userPage.goto(`${wallet.base}/`);
  await userPage.waitForSelector('#mainView:not([hidden])');
  const rpPage = await context.newPage();
  await rpPage.goto(`${rp.base}/`);
  await waitText(rpPage, '#walletMode', '사용자 비밀=브라우저');
  let account = null;

  await t('A1 등록: 금고 비밀번호를 정하고 IdP 에 등록 — 등록됨, IndexedDB 에 registration(공개)·secrets(암호문)·meta·unlock(CryptoKey) 만, 비밀 평문 없음', async () => {
    await userPage.fill('#vaultPw', PW); await userPage.fill('#vaultPw2', PW);
    await userPage.click('#registerBtn');
    await waitText(userPage, '#registerResult', '등록됨', 90_000);
    const d = await idbDump(userPage);
    assert.deepEqual(Object.keys(d).sort(), ['meta', 'registration', 'secrets', 'sessions', 'unlock'].filter((k) => k in d).sort());
    assert.equal(d.registration.uid, '12345'); assert.ok(!('s_u' in d.registration) && !('sk_u' in d.registration));
    assert.ok(d.secrets.iv && d.secrets.ct); assert.equal(d.unlock.key, '[CryptoKey]');
    const dump = await pageDump(userPage); assert.ok(!dump.includes(d.secrets.ct), '암호문도 DOM 에 없다'); assert.ok(!dump.includes(PW), '비밀번호가 DOM 에 남지 않는다');
    await waitText(userPage, '#vaultBadge', '해제');
  });
  await t('A2 로그인: RP 로그인 → 사용자 팝업(승인 버튼) → 로그인 성공; 팝업 DOM 에 비밀 없음', async () => {
    let popupDump = null;
    await viaPopup(async () => { await rpPage.click('#loginBtn'); await rpPage.click('#idpLoginBtn'); }, async (popup) => { await waitText(popup, '#authSummary', rp.origin); await approve(popup); popupDump = await pageDump(popup).catch(() => ''); });
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    const d = await idbDump(userPage); const s = Object.values(d.sessions)[0]; assert.ok(s?.proofCache?.proof, '증명 캐시가 저장됐다'); assert.ok(!('sessionPrivKey' in s)); account = s.account;
    assert.ok(popupDump !== null && !popupDump.includes('"s_u"') && !popupDump.includes('sessionPrivKey'));
    await rpPage.click('#connectWalletBtn'); await waitText(rpPage, '#walletPillText', '브라우저');
  });
  await t('A3 재검증: 팝업이 캐시 히트로 바로 끝난다(승인 버튼 없음) → 재검증 성공', async () => {
    await viaPopup(() => rpPage.click('#revalidateBtn'), async (popup) => { assert.equal(await popup.$('#authApproveBtn:not([hidden])'), null, '캐시 히트는 동의 화면이 없다'); });
    await waitText(rpPage, '#sessionVerdict', '재검증 성공');
  });
  await t('A4 세션 요청: 팝업 승인 → 세션 요청 성공', async () => {
    await viaPopup(() => rpPage.click('#requestBtn'), async (popup) => { await waitText(popup, '#authSummary', 'hello'); await approve(popup); });
    await waitText(rpPage, '#sessionVerdict', '세션 요청 성공');
  });
  await t('A5 트랜잭션: 사용자 페이지에서 보내기 → RP 릴레이가 배포·전송 → 전송 성공, 체인에 Executed', async () => {
    await userPage.click('#refreshBtn'); await userPage.waitForFunction(() => document.querySelector('#txSession')?.options.length > 0);
    await userPage.click('#txBtn');
    await waitText(userPage, '#txVerdict', '전송 성공', 120_000);
    assert.ok((await text(userPage, '#txLog')).includes('txHash='));
    assert.notEqual(await provider.getCode(account), '0x', '계정이 배포됐다');
  });
  await t('A6 Selective disclosure proof: 버튼으로 AttrGate 조건을 채우고 보내기 → 전송 성공, claimed(account)=true', async () => {
    await userPage.click('#claimBtn'); await userPage.click('#txBtn');
    await waitText(userPage, '#txVerdict', '전송 성공', 120_000);
    const info = (await rp.get('/api/mode3/rp_info')).body;
    assert.equal(await attrGateAt(info.attrGateAddress, provider).claimed(account), true);
    assert.equal((await wallet.get('/mode3/health')).body.disclosedTxs, 1, '존재 신호가 health 에 반영된다');
  });
  await t('A7 세션 폐기: 확인창 승인 → 폐기 요청 접수, 세션 목록이 빈다', async () => {
    userPage.once('dialog', (d) => d.accept());
    await userPage.click('#sessionActions button.danger');
    await waitText(userPage, '#sessionVerdict', '폐기 요청 접수');
    await waitText(userPage, '#sessionActions', '로그인 세션이 없습니다', 15_000);
  });
} finally { await browser.close(); await stack.stop(); }
process.exit(failed ? 1 : 0);
