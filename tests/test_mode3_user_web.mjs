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
const stack = await startIsolatedMode3Stack({ userMode: 'web', autoRelay: true, extraRps: [{ name: 'zkTWO', env: { MODE3_ALLOWED_COUNTRIES: 'KR,JP' } }] });
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
  // ---- 각본 B ----
  const rp2 = stack.rps[1];
  await t('B1 잠금: 잠그기 뒤 트랜잭션은 모달을 띄운다 — 틀린 비밀번호는 bad_password, 맞으면 진행해 전송 성공', async () => {
    // 새 세션이 필요하다(A7 에서 폐기했다)
    await viaPopup(async () => { await rpPage.click('#loginBtn'); await rpPage.click('#idpLoginBtn'); }, approve);
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    await userPage.click('#lockBtn'); await waitText(userPage, '#vaultBadge', '잠김');
    assert.equal((await idbDump(userPage)).unlock, undefined, 'unlock 레코드가 지워졌다');
    await userPage.click('#refreshBtn'); await userPage.waitForFunction(() => document.querySelector('#txSession')?.options.length > 0);
    // 전제: A6 의 claim 버튼이 채운 AttrGate claim() 폼이 그대로 남아 있다. 이 RP 의 계정(PPID 는 RP 마다 하나)은 A6 에서 이미 claim 했으므로
    // 그대로 보내면 계정 안의 호출이 "already claimed" 로 실패한다 — 잠금 각본은 기본 송금(HTML 기본값)으로 되돌려 보낸다.
    await userPage.fill('#txTo', '0x000000000000000000000000000000000000dEaD'); await userPage.fill('#txData', '0x');
    await userPage.click('#txBtn');
    await userPage.waitForSelector('#unlockModal:not([hidden])');
    await userPage.fill('#unlockPw', 'wrong'); await userPage.click('#unlockGo');
    await waitText(userPage, '#unlockVerdict', '비밀번호', 10_000);
    await userPage.fill('#unlockPw', PW); await userPage.click('#unlockGo');
    await waitText(userPage, '#txVerdict', '전송 성공', 120_000);
    await waitText(userPage, '#vaultBadge', '해제');
  });
  await t('B2 잠긴 상태의 팝업: 재검증 팝업이 비밀번호를 묻고, 취소하면 RP 에 user_denied', async () => {
    await userPage.click('#lockBtn'); await waitText(userPage, '#vaultBadge', '잠김');
    await viaPopup(() => rpPage.click('#revalidateBtn'), async (popup) => { await popup.waitForSelector('#unlockModal:not([hidden])'); await popup.click('#unlockCancel'); });
    await waitText(rpPage, '#sessionVerdict', 'user_denied');
    await viaPopup(() => rpPage.click('#revalidateBtn'), async (popup) => { await popup.waitForSelector('#unlockModal:not([hidden])'); await popup.fill('#unlockPw', PW); await popup.click('#unlockGo'); });
    await waitText(rpPage, '#sessionVerdict', '재검증 성공');
    await waitText(userPage, '#vaultBadge', '해제', 10_000);   // 팝업의 해제가 IndexedDB 를 거쳐 메인 탭에도 보인다(R3)
  });
  await t('B3 시연 가짜 증명: 다음 로그인이 RP 에서 bad_proof 로 거절되고 [시연 모드] 표기; 가짜 서명: 다음 트랜잭션이 relay_gas(BadSignature)', async () => {
    await userPage.evaluate(() => Demo.setExpert(true)); await userPage.waitForSelector('#demoCard', { state: 'visible' });
    await userPage.click('#demoFakeProofBtn'); await waitText(userPage, '#demoVerdict', '적용', 10_000);
    await viaPopup(async () => { await rpPage.click('#loginBtn'); await rpPage.click('#idpLoginBtn'); }, approve);
    await waitText(rpPage, '#verdict', 'bad_proof', 120_000);
    assert.ok((await text(rpPage, '#verdict')).includes('[시연 모드]'));
    await userPage.click('#demoFakeSigBtn'); await waitText(userPage, '#demoVerdict', '적용', 10_000);
    await userPage.click('#refreshBtn'); await userPage.click('#txBtn');
    await waitText(userPage, '#txVerdict', 'relay_gas', 120_000);
    assert.match(await text(userPage, '#txVerdict'), /\[시연 모드\]|BadSignature/);
    await userPage.evaluate(() => Demo.setExpert(false));
  });
  await t('B4 오리진 위조: 다른 오리진에서 보낸 mode3-authorize 는 origin_mismatch; 세션 주인이 아닌 RP 의 mode3-revalidate 는 no_session; mode3-config 는 RP 오리진에만', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const sessionsBefore = Object.keys((await idbDump(userPage)).sessions);
    const forged = async (fromPage, type, request) => {
      await fromPage.evaluate(({ walletOrigin, type: ty, request: req }) => {
        document.getElementById('forgedBtn')?.remove();
        window.__forged = new Promise((resolve) => { window.__forgedResolve = resolve; });
        const btn = document.createElement('button'); btn.id = 'forgedBtn';
        btn.addEventListener('click', () => {
          const popup = window.open(`${walletOrigin}/?authorize=1`, `forged-${ty}-${Math.random()}`, 'width=480,height=680');
          window.addEventListener('message', (ev) => { if (ev.origin !== walletOrigin || ev.source !== popup || !ev.data) return; if (ev.data.type === 'mode3-authorize-ready') { popup.postMessage({ type: ty, ...req }, walletOrigin); return; } if (ev.data.type === `${ty}-result`) window.__forgedResolve(ev.data.result); });
        });
        document.body.appendChild(btn);
      }, { walletOrigin: wallet.base, type, request });
      const [popup] = await Promise.all([context.waitForEvent('page'), fromPage.click('#forgedBtn')]);
      const result = await fromPage.evaluate(() => Promise.race([window.__forged, new Promise((r) => setTimeout(() => r({ timeout: true }), 60_000))]));
      if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 15_000 }).catch(() => {});
      return result;
    };
    // (a) rp2 페이지가 rp1 의 인증서를 들고 로그인 요청 — 메시지 오리진(rp2) ≠ 인증서 오리진(rp1)
    const rp2Page = await context.newPage(); await rp2Page.goto(`${rp2.base}/`); await waitText(rp2Page, '#walletMode', '사용자 비밀=브라우저');
    const a = await forged(rp2Page, 'mode3-authorize', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: '11', r_rp: '12', serviceName: 'x' });
    assert.equal(a.reason, 'origin_mismatch', j(a));
    // (b) rp2 가 rp1 세션의 r_s 로 재검증 — 세션 오리진이 다르다
    const info2 = (await rp2.get('/api/mode3/rp_info')).body;
    const b = await forged(rp2Page, 'mode3-revalidate', { arid: info2.arid, origin: info2.origin, r_s: sessionsBefore[0] });
    assert.equal(b.reason, 'no_session', j(b));
    // (c) mode3-config 는 RP 오리진이면 registered·rpCount·sessions 만(uid 없음)
    const c = await forged(rp2Page, 'mode3-config', { origin: info2.origin });
    assert.equal(c.ok, true); assert.equal(c.registered, true); assert.equal(typeof c.rpCount, 'number'); assert.ok(!('uid' in c), j(c));
    await rp2Page.close();
  });
  await t('B5 두 번째 RP(zkTWO) 로그인: 다른 계정 주소, health.rpCount=2, RP 페이지 브랜드 zkTWO', async () => {
    const rp2Page = await context.newPage(); await rp2Page.goto(`${rp2.base}/`); await waitText(rp2Page, '#walletMode', '사용자 비밀=브라우저');
    assert.equal(await rp2Page.evaluate(() => document.body.dataset.brand), 'zkTWO');
    await viaPopup(async () => { await rp2Page.click('#loginBtn'); await rp2Page.click('#idpLoginBtn'); }, approve);
    await waitText(rp2Page, '#verdict', '로그인 성공', 120_000);
    const sessions = Object.values((await idbDump(userPage)).sessions);
    const accounts = new Set(sessions.map((s) => s.account)); assert.ok(accounts.size >= 2, 'RP 마다 다른 계정 주소');
    await userPage.click('#refreshBtn');
    await userPage.waitForFunction(async () => (await (await fetch('/mode3/health')).json()).rpCount >= 2, undefined, { timeout: 15_000 });
    await rp2Page.close();
  });
  await t('B6 증명 키 캐시: 새 탭에서 페이지를 열면 /zk/*.zkey 를 다시 받지 않는다(Cache API 히트)', async () => {
    const p2 = await context.newPage(); const zkFetches = [];
    p2.on('request', (r) => { if (r.url().includes('/zk/') && r.url().endsWith('.zkey')) zkFetches.push(r.url()); });
    await p2.goto(`${wallet.base}/`); await p2.waitForSelector('#mainView:not([hidden])'); await waitText(p2, '#zkProgress', '준비', 60_000);
    assert.equal(zkFetches.length, 0, `네트워크로 다시 받았다: ${j(zkFetches)}`);
    await p2.close();
  });
  await t('B7 모두 지우기: 확인 → IndexedDB 가 비고 미등록·금고 없음으로 돌아간다, 재등록은 IdP 가 409(already registered) 로 막는다(재시연 세트 필요)', async () => {
    userPage.once('dialog', (d) => d.accept());
    await userPage.click('#wipeBtn');
    await waitText(userPage, '#vaultBadge', '없음', 10_000);
    assert.deepEqual(await idbDump(userPage), {});
    await userPage.fill('#vaultPw', PW); await userPage.fill('#vaultPw2', PW); await userPage.click('#registerBtn');
    await waitText(userPage, '#registerResult', 'register_failed', 60_000);
  });
} finally { await browser.close(); await stack.stop(); }
process.exit(failed ? 1 : 0);
