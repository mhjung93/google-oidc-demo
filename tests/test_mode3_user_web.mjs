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
const stack = await startIsolatedMode3Stack({ userMode: 'web', autoRelay: true, extraRps: [{ name: 'zkTWO', env: { MODE3_ALLOWED_COUNTRIES: 'KR,JP', MODE3_REQUIRE_DISCLOSURE: '1' } }] });   // 2026-10-21: zkTWO 는 로그인 때 조건 증명 강제
const { wallet, rp } = stack;
const PW = 'demo-vault-pw';
let recoveryCode = null;   // A1 에서 받아 B9 복구에 쓴다(2026-10-21)
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

  await t('A1 등록: 비밀번호 없이 IdP 에 등록(자동 금고, 2026-10-16) — 등록됨, IndexedDB 에 registration(공개)·secrets(암호문)·meta·unlock(CryptoKey) 만, 비밀 평문 없음', async () => {
    await userPage.click('#registerBtn');
    await waitText(userPage, '#registerResult', '등록됨', 90_000);
    // 2026-10-21: 복구 코드 보기 — 모달에 zkd1.코드, 닫으면 화면에서 지워진다
    await userPage.click('#recoveryCodeBtn'); await userPage.waitForSelector('#recoveryCodeModal:not([hidden])');
    recoveryCode = await text(userPage, '#recoveryCodeText'); assert.match(recoveryCode, /^zkd1\.[A-Za-z0-9_-]{43}$/);
    await userPage.click('#recoveryCodeClose'); assert.equal(await text(userPage, '#recoveryCodeText'), '');
    const d = await idbDump(userPage);
    assert.deepEqual(Object.keys(d).sort(), ['meta', 'registration', 'secrets', 'sessions', 'unlock'].filter((k) => k in d).sort());
    assert.equal(d.registration.uid, '12345'); assert.ok(!('s_u' in d.registration) && !('sk_u' in d.registration));
    assert.ok(d.secrets.iv && d.secrets.ct); assert.equal(d.unlock.key, '[CryptoKey]'); assert.equal(d.meta.mode, 'auto'); assert.equal(d.unlock.expiresAt, null);
    const dump = await pageDump(userPage); assert.ok(!dump.includes(d.secrets.ct), '암호문도 DOM 에 없다');
    assert.equal((await userPage.$('#vaultPw')) === null, true, '금고 비밀번호 칸이 없다'); assert.equal((await userPage.$('#googleRegRow')) === null, true, 'Google 등록 행이 없다');
  });
  await t('A2 로그인: RP 로그인 → 사용자 팝업(승인 버튼) → 로그인 성공; 팝업 DOM 에 비밀 없음', async () => {
    let popupDump = null;
    await rpPage.click('#connectWalletBtn'); await waitText(rpPage, '#walletPillText', 'MetaMask');   // 2026-10-16: 지갑 연결 = MetaMask 계정 연결(헤드리스엔 확장이 없어 '없습니다' 류 문구) — 2026-10-21: 로그인 전에(로그인 뒤엔 버튼이 숨는다)
    await viaPopup(async () => { await rpPage.click('#loginBtn'); await rpPage.click('#idpLoginBtn'); }, async (popup) => { await waitText(popup, '#authSummary', rp.origin); await approve(popup); popupDump = await pageDump(popup).catch(() => ''); });
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    const d = await idbDump(userPage); const s = Object.values(d.sessions)[0]; assert.ok(s?.proofCache?.proof, '증명 캐시가 저장됐다'); assert.ok(!('sessionPrivKey' in s)); account = s.account;
    assert.ok(popupDump !== null && !popupDump.includes('"s_u"') && !popupDump.includes('sessionPrivKey'));
    assert.equal(await rpPage.$eval('#loginBtn', (b) => b.hidden), true, '로그인 뒤 로그인 버튼 숨김'); assert.equal(await rpPage.$eval('#connectWalletBtn', (b) => b.hidden), true, '로그인 뒤 지갑 연결 버튼 숨김');   // 2026-10-21
  });
  await t('A3 재검증: 팝업이 캐시 히트로 바로 끝난다(승인 버튼 없음) → 재검증 성공', async () => {
    await viaPopup(() => rpPage.click('#revalidateBtn'), async (popup) => { assert.equal(await popup.$('#authApproveBtn:not([hidden])'), null, '캐시 히트는 동의 화면이 없다'); });
    await waitText(rpPage, '#sessionVerdict', '재검증 성공');
  });
  await t('A4 현재 잔액 확인(2026-10-21, 옛 세션 요청): 팝업 승인 → 세션 요청 성공, 온체인 계정 잔액 줄이 보인다', async () => {
    await viaPopup(() => rpPage.click('#balanceBtn'), async (popup) => { await waitText(popup, '#authSummary', '잔액 확인'); await approve(popup); });
    await waitText(rpPage, '#sessionVerdict', '세션 요청 성공');
    assert.match(await text(rpPage, '#sessionVerdict'), /KRW 1,000,000/);
  });
  await t('A4b 로그아웃(2026-10-16): RP 로그아웃 → 사용자 페이지 세션 목록이 곧 빈다(2초 새로고침) → 다시 로그인하면 세션 하나', async () => {
    await rpPage.click('#logoutBtn');
    await userPage.waitForFunction(() => (document.querySelector('#sessionActions')?.textContent ?? '').includes('로그인 세션이 없습니다'), undefined, { timeout: 15_000 });
    assert.equal(await rpPage.$eval('#loginBtn', (b) => b.hidden), false, '로그아웃 뒤 로그인 버튼 복귀'); assert.equal((await text(rpPage, '#sessionVerdict')).trim(), '', '로그아웃하면 이전 세션 결과가 비워진다(2026-10-21)');
    await viaPopup(async () => { await rpPage.click('#loginBtn'); await rpPage.click('#idpLoginBtn'); }, approve);
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    await userPage.waitForFunction(() => document.querySelectorAll('#sessionActions dl').length === 1, undefined, { timeout: 15_000 });
    const d = await idbDump(userPage); account = Object.values(d.sessions)[0].account;
  });
  await t('A5 트랜잭션: 사용자 페이지에서 보내기 → RP 릴레이가 배포·전송 → 전송 성공, 체인에 Executed', async () => {
    await userPage.click('#refreshBtn'); await userPage.waitForFunction(() => document.querySelector('#txSession')?.options.length > 0);
    await userPage.click('#txBtn');
    await waitText(userPage, '#txVerdict', '전송 성공', 120_000);
    assert.ok((await text(userPage, '#txLog')).includes('txHash='));
    assert.notEqual(await provider.getCode(account), '0x', '계정이 배포됐다');
  });
  await t('A5b RP 페이지 온체인 출금(2026-10-16): 출금 버튼 → 사용자 승인 창(받는 주소·금액) → 승인 → 전송 성공(txHash)', async () => {
    await rpPage.fill('#txTo', '0x000000000000000000000000000000000000dEaD'); await rpPage.fill('#txValue', '0');
    await viaPopup(() => rpPage.click('#txBtn'), async (popup) => { await waitText(popup, '#authSummary', '0x000000000000000000000000000000000000dEaD'); await approve(popup); });
    await waitText(rpPage, '#txVerdict', '전송 성공', 120_000);
    assert.ok((await text(rpPage, '#txLog')).includes('txHash='));
    // 2026-10-21: 결과 아래에 해시 줄과 복사 버튼이 보인다
    assert.equal(await rpPage.$eval('#txHashRow', (e) => e.hidden), false, '해시 줄이 보인다');
    assert.match(await rpPage.$eval('#txHashCode', (e) => e.title), /^0x[0-9a-f]{64}$/);
    assert.ok(await rpPage.$('#copyTxHashBtn'));
  });
  await t('A5c RP 관리자 페이지(/admin): 로그인 기록 표와 승인 개봉 카드가 있고, 고객 페이지에는 둘 다 없다', async () => {
    const adminPage = await context.newPage(); await adminPage.goto(`${rp.base}/admin`);
    await adminPage.waitForSelector('#openBtn'); await adminPage.waitForFunction(() => document.querySelectorAll('#logins table tbody tr').length > 0, undefined, { timeout: 20_000 });
    assert.ok(await adminPage.$('#openPollBtn'));
    // 2026-10-21: 트랜잭션 기록 — A5(사용자 페이지)·A5b(RP 페이지) 두 건이 이 RP 의 릴레이로 나갔다. 해시 옆 ⧉ 가 실제로 클립보드에 복사한다.
    await adminPage.waitForFunction(() => document.querySelectorAll('#txs table tbody tr').length >= 2, undefined, { timeout: 20_000 });
    assert.equal(await adminPage.$$eval('#txs table tbody tr button.copy-btn', (b) => b.length) >= 2, true, '행마다 복사 버튼');
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: rp.base });
    const firstHash = await adminPage.$eval('#txs table tbody tr button.copy-btn', (b) => b.parentElement.querySelector('code').title);   // 복사 버튼과 같은 칸의 해시
    assert.match(firstHash, /^0x[0-9a-f]{64}$/);
    await adminPage.click('#txs table tbody tr button.copy-btn');
    assert.equal(await adminPage.evaluate(() => navigator.clipboard.readText()), firstHash);
    await adminPage.close();
    assert.equal((await rpPage.$('#openBtn')) === null, true, '고객 페이지에 개봉 카드가 없다'); assert.equal((await rpPage.$('#logins')) === null, true, '고객 페이지에 로그인 기록이 없다');
    assert.ok(await rpPage.$('#rpAdminLink'));
    // 2026-10-16: 세션 표기는 "zkONE(8674…)" 꼴, 보낸 트랜잭션 목록에 A5·A5b 의 두 건이 보인다
    await userPage.click('#refreshBtn');
    await userPage.waitForFunction(() => document.querySelectorAll('#txsList table tbody tr').length >= 2, undefined, { timeout: 20_000 });
    assert.match(await text(userPage, '#sessionActions'), /zkONE\([0-9]{4}…\)/);
    assert.ok((await text(userPage, '#txsList')).includes('zkONE('));
    assert.equal(await userPage.$$eval('#txsList table tbody tr button.copy-btn', (b) => b.length) >= 2, true, '사용자 페이지 거래 목록에도 복사 버튼');
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
    // 세션 목록은 2초 새로고침마다 통째로 다시 그려진다 — page.click 의 '안정' 대기가 계속 어긋나 시간 초과가 났다(2026-10-21, 세 번 중 두 번). DOM 에서 바로 누른다.
    await userPage.waitForSelector('#sessionActions button.danger');
    await userPage.$eval('#sessionActions button.danger', (b) => b.click());
    await waitText(userPage, '#sessionVerdict', '폐기 요청 접수');
    await waitText(userPage, '#sessionActions', '로그인 세션이 없습니다', 15_000);
    // 2026-10-21: 폐기하면 사용자 페이지가 RP 에 로그아웃을 알리고, RP 페이지는 2초 확인에서 로그아웃 상태가 된다
    await waitText(rpPage, '#verdict', '로그아웃됨', 10_000);
    assert.equal(await rpPage.$eval('#accountPill', (e) => e.hidden), true, 'RP 페이지 계정 표시가 사라진다');
  });
  // ---- 각본 B ----
  const rp2 = stack.rps[1];
  // B1·B2(잠금·잠긴 팝업 각본)는 2026-10-16 자동 금고 전환으로 뺐다 — 비밀번호 금고 동작은 tests/test_mode3_user_core.mjs 가 본다.
  await t('B3 시연 가짜 증명: 다음 로그인이 RP 에서 bad_proof 로 거절되고 [시연 모드] 표기; 가짜 서명: 다음 트랜잭션이 relay_gas(BadSignature)', async () => {
    await userPage.evaluate(() => Demo.setExpert(true)); await userPage.waitForSelector('#demoCard', { state: 'visible' });
    await userPage.click('#demoFakeProofBtn'); await waitText(userPage, '#demoVerdict', '적용', 10_000);
    await viaPopup(async () => { await rpPage.click('#loginBtn'); await rpPage.click('#idpLoginBtn'); }, approve);
    await waitText(rpPage, '#verdict', 'bad_proof', 120_000);
    assert.ok((await text(rpPage, '#verdict')).includes('[시연 모드]'));
    await userPage.click('#demoFakeSigBtn'); await waitText(userPage, '#demoVerdict', '가짜 서명', 10_000);
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
    // 2026-10-21: zkTWO 는 로그인 조건 강제 — 페이지가 술어를 자동으로 싣고 서버가 요구한다. 세션에 국가 집합 공개가 실린다. zkONE 은 "누구나".
    const s2 = (await rp2.get('/api/mode3/sessions')).body.sessions; assert.ok(s2.length >= 1 && s2[0].disclosure?.set, `zkTWO 세션에 공개 집합이 없다: ${j(s2)}`);
    assert.match(await text(rp2Page, '#loginPolicy'), /조건 증명/); assert.match(await text(rpPage, '#loginPolicy'), /누구나/);
    assert.equal(await rp2Page.$eval('#requirePred', (e) => e.closest('label').style.display), 'none', 'zkTWO 는 체크박스를 숨긴다');
    const sessions = Object.values((await idbDump(userPage)).sessions);
    const accounts = new Set(sessions.map((s) => s.account)); assert.ok(accounts.size >= 2, 'RP 마다 다른 계정 주소');
    await userPage.click('#refreshBtn');
    await userPage.waitForFunction(async () => (await (await fetch('/mode3/health')).json()).rpCount >= 2, undefined, { timeout: 15_000 });
    await rp2Page.close();
  });
  await t('B5b zkTWO 세션의 selective disclosure proof(2026-10-16): claim 버튼이 zkTWO 정책(KR,JP)으로 채우고 → 전송 성공(계정 안 호출 성공)', async () => {
    await userPage.click('#refreshBtn');
    await userPage.waitForFunction(() => [...document.querySelectorAll('#txSession option')].some((o) => o.textContent.includes('zkTWO')), undefined, { timeout: 20_000 });
    await userPage.selectOption('#txSession', { label: await userPage.$eval('#txSession', (sel) => [...sel.options].find((o) => o.textContent.includes('zkTWO')).label) });
    await userPage.click('#claimBtn');
    assert.equal(await userPage.inputValue('#setMembers'), 'KR,JP', '허용 국가가 zkTWO 정책(KR,JP)으로 채워진다');
    await userPage.click('#txBtn');
    await waitText(userPage, '#txVerdict', '전송 성공', 120_000);
    assert.ok(!(await text(userPage, '#txVerdict')).includes('실패'));
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
    await userPage.waitForFunction(() => (document.querySelector('#regBadge')?.textContent ?? '').includes('미등록'), undefined, { timeout: 10_000 });
    assert.deepEqual(await idbDump(userPage), {});
    await userPage.click('#registerBtn');
    await waitText(userPage, '#registerResult', 'register_failed', 60_000);
  });
  await t('B8 데모 세대(2026-10-21): 사용자 페이지 서버를 새 MODE3_DEMO_GENERATION 으로 다시 띄우면 처음 본 번호는 기억만 하고, 다음 번호에서 옛 등록·세션을 스스로 지우고 알린다', async () => {
    await stack.restartWallet({ MODE3_DEMO_GENERATION: 'gen-1' });
    await userPage.reload(); await userPage.waitForSelector('#mainView:not([hidden])');
    await userPage.waitForFunction(() => document.querySelector('#regBadge')?.textContent, undefined, { timeout: 15_000 });
    assert.equal((await idbDump(userPage)).demoGeneration, 'gen-1', '처음 본 번호는 기억한다');
    assert.ok(!(await text(userPage, '#storagePanel')).includes('데모가 초기화됨'), '처음 본 번호로는 지우지 않는다');
    await stack.restartWallet({ MODE3_DEMO_GENERATION: 'gen-2' });
    await userPage.reload(); await userPage.waitForSelector('#mainView:not([hidden])');
    await waitText(userPage, '#storagePanel', '데모가 초기화됨', 15_000);
    assert.deepEqual(await idbDump(userPage), { demoGeneration: 'gen-2' }, '옛 상태는 지우고 새 번호만 남는다');
  });
  await t('B9 복구(2026-10-21): 지워진 브라우저에서 uid + 복구 코드 → 복구됨(등록·비밀 복원, IdP 슬롯 그대로) → 같은 계정 주소로 다시 로그인', async () => {
    await userPage.click('#recoverBtn'); await userPage.waitForSelector('#recoverModal:not([hidden])');
    await userPage.fill('#recoverUid', '12345'); await userPage.fill('#recoverCode', recoveryCode); await userPage.click('#recoverGo');
    await waitText(userPage, '#storagePanel', '복구됨', 30_000);
    const d = await idbDump(userPage); assert.ok(d.registration && d.secrets, '등록·비밀이 다시 생겼다'); assert.ok(Number.isInteger(d.registration.slot));
    if (await rpPage.$eval('#loginBtn', (b) => b.hidden)) { await rpPage.click('#logoutBtn'); await rpPage.waitForSelector('#loginBtn:not([hidden])'); }
    await viaPopup(async () => { await rpPage.click('#loginBtn'); await rpPage.click('#idpLoginBtn'); }, approve);
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    assert.equal(Object.values((await idbDump(userPage)).sessions)[0].account, account, '복구 뒤에도 같은 계정 주소(PPID)');
  });
} finally { await browser.close(); await stack.stop(); }
process.exit(failed ? 1 : 0);
