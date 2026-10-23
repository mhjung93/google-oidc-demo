// Mode 3 체험 모드(Demo.tour) + 상태 점(Demo.stack) 의 브라우저 경로 — 설계 2026-09-25-mode3-demo-ux-phase2 §4.
// 격리 스택(file 모드)을 임시 포트로 띄우고 실제 Chrome 으로 서비스·지갑 페이지를 함께 연다. 보는 것은 네 가지다.
//   (a) 서비스를 ?tour=1 로 열면 지갑이 등록 전이라 로그인 버튼이 잠기고 사유 배지가 붙는다(쿼리는 주소창에서 지워진다)
//   (b) 지갑에서 등록하면 다음 폴링에 서비스 잠금이 풀리고 말풍선이 4단계(로그인)를 가리킨다
//   (c) 로그인에 성공하면 말풍선이 5단계(이용·재검증)로 옮겨 가고 상태 점이 초록이 된다
//   (d) 신원 기관(CIA) 프로세스를 내리면 신원 기관 점이 빨강, 지갑 점이 노랑(신원 기관에 못 닿음)이 된다
// Task 17(B8, 2026-10-23): rp_create(1단계, idp_rp 의 #rpCreateBtn)·register(3단계, idp_user 의 #registerBtn 로 이동)는
// 이 각본이 직접 누르지 않는다 — 격리 스택이 RP 생성·승인을 미리 해 두고(startIsolatedMode3Stack), 등록은 file 모드인
// wallet.html 자신의 #registerBtn 으로 한다(둘 다 서버 사실로 done 판정되므로 어느 UI 로 했는지는 상관없다).
// hardhat :8545 와 build/mode3 의 pi_cred zkey·vkey, 그리고 Chrome(또는 Chromium)이 필요하다. (browser 그룹)
//   node tests/test_mode3_tour.mjs
//   MODE3_BROWSER_DEBUG=1 로 브라우저 콘솔·페이지 오류를 그대로 흘려 본다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { VKEY_PATH } from '../lib/mode3_wallet.js';

const DEBUG = process.env.MODE3_BROWSER_DEBUG === '1';
const j = (o) => JSON.stringify(o);
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); }
}

// 무거운 것을 띄우기 전에 전제를 확인한다 — 실패해도 자식 프로세스를 고아로 남기지 않는다.
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
// 스택은 try 안에서 띄운다 — 기동이 실패해도 finally 가 브라우저를 닫는다(안 그러면 Chrome 이 남는다).
let stack = null;
let ciaStopped = false;

try {
  stack = await startIsolatedMode3Stack({ autoRelay: true });          // file 모드(MetaMask·Snap 없이 도는 데모 경로). V10: 거울 릴레이는 헬퍼가 대신 돈다
  const { wallet, rp } = stack;
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  // 파괴적 조작의 확인창(2026-09-24 UX §4.5) — 자동화는 모두 승인한다.
  context.on('page', (p) => p.on('dialog', (d) => d.accept().catch(() => {})));
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
    } catch {
      throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`);
    }
  }
  /** 지금 화면의 점 클래스 — 실패 메시지에 붙여 무엇이 무슨 색이었는지 남긴다. */
  const dotClasses = (page) => page.evaluate(() => [...document.querySelectorAll('.stack-dots .dot')].map((d) => d.className));

  const rpPage = await context.newPage();
  const walletPage = await context.newPage();

  await t('체험 모드: 서비스 로그인은 지갑 등록 전 잠긴다(?tour=1 은 저장되고 주소창에서 지워진다)', async () => {
    await rpPage.goto(`${rp.base}/?tour=1`);
    // 2026-10-16: 잠금은 사유 배지만 — 버튼은 비활성화되지 않는다(모든 버튼 늘 활성).
    await rpPage.waitForSelector('.tour-lock', { timeout: 30_000 });
    assert.equal(await rpPage.$eval('#loginBtn', (b) => b.disabled), false, '잠겨도 버튼은 활성이다');
    const badge = await rpPage.$('.tour-lock');
    assert.ok(badge, '잠금 사유 배지(.tour-lock)가 있어야 한다');
    assert.equal(await badge.getAttribute('data-for'), 'loginBtn');
    assert.ok((await badge.textContent()).includes('사용자'), `배지 문구: ${j(await badge.textContent())}`);
    assert.equal(new URL(rpPage.url()).search, '', `주소창에 ?tour 가 남았다: ${rpPage.url()}`);
    assert.equal(await rpPage.evaluate(() => localStorage.getItem('mode3.tour')), '1');
    assert.equal(await rpPage.evaluate(() => document.querySelector('#tourToggle')?.checked), true, '스위치가 켜진 채로 보인다');
  });

  await t('지갑에서 등록하면 서비스 잠금이 풀리고 말풍선이 로그인 버튼을 가리킨다', async () => {
    await walletPage.goto(`${wallet.base}/?tour=1`);
    await walletPage.waitForSelector('#mainView:not([hidden])', { timeout: 30_000 });
    // 서비스는 격리 헬퍼가 이미 승인해 두었으므로 3단계(등록)는 잠기지 않는다.
    await walletPage.waitForFunction(() => document.querySelector('#registerBtn') && !document.querySelector('#registerBtn').disabled, undefined, { timeout: 30_000 });
    assert.equal((await walletPage.$('.tour-lock')) === null, true, '승인된 서비스가 있으면 등록 버튼은 잠기지 않는다');
    await walletPage.click('#registerBtn');
    await waitText(walletPage, '#registerResult', '등록됨', 60_000);
    // 서비스 페이지는 5초마다 지갑 health 를 읽는다 — 다음 폴링에 잠금이 풀려야 한다.
    // 2026-10-16: 버튼은 늘 활성이라 disabled 로는 풀림을 알 수 없다 — 배지가 사라지기를 기다린다(RP 가 다음 폴링에 지갑 등록을 본다).
    await rpPage.waitForSelector('.tour-lock', { state: 'detached', timeout: 30_000 });
    assert.equal(await rpPage.$eval('#loginBtn', (b) => b.disabled), false, '잠금이 풀린 뒤에도 버튼은 활성');
    await rpPage.waitForFunction(() => (document.querySelector('.tour-bubble')?.textContent ?? '').includes('로그인'), undefined, { timeout: 30_000 });
  });

  // U6(2026-10-14): login2(두 번째 RP 로그인, unlinkability 시연)가 4단계(로그인) 뒤에 끼었다. 이 격리 스택은 RP 가
  // 하나뿐이라(startIsolatedMode3Stack 기본값) login2 는 절대 끝낼 수 없다 — 말풍선 대신 "다른 창에서" 카드로 뜨고
  // (두 번째 RP 를 모르니 링크 없이 문구만), 그 뒤 단계(이용 등)의 완료 여부 자체는 막지 않는다(상태 점은 독립 판정).
  await t('로그인 뒤 카드가 5단계(두 번째 RP 로그인)로 옮겨 가 "다른 창에서"로 뜨고 상태 점 셋 이상이 초록', async () => {
    await idpLogin(rpPage);
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    await rpPage.waitForFunction(() => (document.querySelector('#tourCard')?.textContent ?? '').includes('두 번째'), undefined, { timeout: 30_000 });
    assert.equal((await rpPage.$('.tour-bubble')) === null, true, 'RP 가 하나뿐이면 두 번째 RP 를 가리킬 수 없다 — 말풍선이 아니라 카드만 남는다');
    await rpPage.waitForFunction(() => [...document.querySelectorAll('.stack-dots .dot')].filter((d) => d.classList.contains('ok')).length >= 3, undefined, { timeout: 30_000 })
      .catch(async () => { throw new Error(`초록 점이 셋 미만이다: ${j(await dotClasses(rpPage))}`); });
  });

  await t('V9 등록부 줄: 로그인 뒤 ✓, 관리자 바꿔치기 뒤 다음 폴링에 ✗, 되돌리기 뒤 ✓', async () => {
    await walletPage.waitForFunction(() => document.querySelector('#registryBadge')?.classList.contains('ok'), undefined, { timeout: 30_000 });
    assert.equal((await stack.cia.adminPost('/cia/admin/registry/tamper', { uid: '12345' })).status, 200);
    // 2026-10-01 리뷰 Important 1 회귀 확인: 바꿔치기 뒤 로그인은 403 registry_mismatch 로 거절되고, 서비스 페이지의
    // 판정 제목 줄(.summary, demo.js 의 renderVerdict 가 쓰는 클래스)이 빈 줄이 아니라 사유 사전의 제목을 그대로
    // 보여야 한다 — summary 를 섣불리 ''로 채우면 demo.js 의 `summary ?? r.title` 폴백이 깨져 이 줄이 비어 버린다.
    await idpLogin(rpPage);
    const mismatchTitle = await rpPage.evaluate(() => window.DemoStrings?.reasons?.registry_mismatch?.ko?.title ?? '');
    await rpPage.waitForFunction((needle) => (document.querySelector('#verdict .summary')?.textContent ?? '').includes(needle), mismatchTitle, { timeout: 60_000 });
    assert.equal(await rpPage.$eval('#verdict .summary', (el) => el.textContent), mismatchTitle, '회귀: 제목 줄이 비면 안 된다');
    await walletPage.click('#refreshBtn');
    await walletPage.waitForFunction(() => document.querySelector('#registryBadge')?.classList.contains('bad'), undefined, { timeout: 30_000 });
    assert.ok((await text(walletPage, '#registryInfo')).includes('바뀌'), '✗ 문구');
    assert.equal((await stack.cia.adminPost('/cia/admin/registry/restore', { uid: '12345' })).status, 200);
    await walletPage.click('#refreshBtn');
    await walletPage.waitForFunction(() => document.querySelector('#registryBadge')?.classList.contains('ok'), undefined, { timeout: 30_000 });
  });
  // 2026-10-12 V11: CIA 는 /cia/user_cred 가 아니라 /cia/issue 를 쓰고 거절 사유도 바뀌었다(bad_idp_proof) — 아래 waitText 는
  // 그 raw 문구("bad user credential proof")가 아니라 모든 시연 실패가 공통으로 붙이는 "[시연 모드] " 접두사를 기다린다
  // (제목 자체는 바로 뒤 동적 비교가 strings.js 의 user_cred_failed.ko.title 과 대조한다).
  await t('V9 시연 카드(전문가 보기): salt 를 바꾸고 다음 발급 → 서비스 로그인 결과에 [시연 모드] 접두의 π_IdP 거절', async () => {
    await walletPage.evaluate(() => Demo.setExpert(true));
    await walletPage.waitForSelector('#demoCard', { state: 'visible' });
    assert.equal((await stack.cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' })).status, 200);   // 다음 로그인이 새로 받게
    await walletPage.click('#demoNewSalt'); await walletPage.selectOption('#demoScope', 'issue'); await walletPage.click('#demoApplyBtn');
    await waitText(walletPage, '#demoVerdict', '적용', 10_000);
    await idpLogin(rpPage);
    await waitText(rpPage, '#verdict', '[시연 모드]', 120_000);
    // 2026-10-01 리뷰 Important 1 + round 2: 시연 모드 실패는 제목 줄 앞에 "[시연 모드] " 를 붙이고, 그 뒤에
    // 사유 사전의 제목(이 시나리오의 사유는 user_cred_failed)이 **비지 않고** 그대로 와야 한다. round 1 때는
    // 이 사유가 사전에 없어 "포함" 검사가 빈 문자열을 상대로 공허하게 통과했다 — round 2 가 사전에 그 코드를
    // 추가했으므로, 접두 뒤 나머지가 비어 있지 않은지까지 확인해야 실제로 변별력이 있다.
    const ucFailedTitle = await rpPage.evaluate(() => window.DemoStrings?.reasons?.user_cred_failed?.ko?.title ?? '');
    const demoSummary = await rpPage.$eval('#verdict .summary', (el) => el.textContent);
    assert.ok(demoSummary.startsWith('[시연 모드] '), `시연 접두가 없다: ${demoSummary}`);
    const demoRemainder = demoSummary.slice('[시연 모드] '.length);
    assert.notEqual(demoRemainder, '', `사유 제목이 비어 있다(공허한 통과를 막는 검사): ${demoSummary}`);
    assert.equal(demoRemainder, ucFailedTitle, `사유 제목이 사전과 다르다: ${demoSummary}`);
    await idpLogin(rpPage);
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);   // 덮어쓰기는 한 번만 — 그다음은 정상
    await walletPage.evaluate(() => Demo.setExpert(false));
  });

  await t('신원 기관을 내리면 신원 기관 점이 빨강·지갑 점이 노랑이 된다', async () => {
    await stack.cia.stop();          // 격리 CIA 프로세스만 내린다(스택 전체 stop 은 마지막에)
    ciaStopped = true;
    await rpPage.waitForFunction(() => document.querySelector('.stack-dots .dot.aa')?.classList.contains('bad'), undefined, { timeout: 30_000 })
      .catch(async () => { throw new Error(`신원 기관 점이 빨강이 되지 않았다: ${j(await dotClasses(rpPage))}`); });
    // 지갑은 health 를 줄 때마다 CIA 를 뒤에서 찔러 보고(1.5초 예산, 응답은 기다리지 않는다) 결과를 10초 동안 쓴다 —
    // 그래서 CIA 를 내리면 ciaReachable 은 10초 안팎 뒤의 폴링부터 false 가 된다(아래 30초 여유 안에 든다).
    await rpPage.waitForFunction(() => document.querySelector('.stack-dots .dot.wallet')?.classList.contains('warn'), undefined, { timeout: 30_000 })
      .catch(async () => { throw new Error(`지갑 점이 노랑이 되지 않았다: ${j(await dotClasses(rpPage))}`); });
    assert.ok((await rpPage.$eval('.stack-dots .dot.wallet', (d) => d.getAttribute('aria-label'))).includes('IdP'), '지갑 점의 사유가 IdP 쪽임을 말한다');
  });
} finally {
  await browser.close().catch(() => {});
  if (ciaStopped) console.log('(CIA 는 테스트가 이미 내렸다 — 스택 stop 은 나머지를 정리한다)');
  await stack?.stop().catch((e) => console.error(`스택 정리 실패: ${e.message}`));
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
// 다른 Mode 3 테스트와 같은 관례 — 남는 핸들 때문에 저절로 끝나지 않는다
process.exit(failed === 0 ? 0 : 1);
