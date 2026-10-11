// Mode 3 체험 모드(Demo.tour) + 상태 점(Demo.stack) 의 브라우저 경로 — 설계 2026-09-25-mode3-demo-ux-phase2 §4.
// 격리 스택(file 모드)을 임시 포트로 띄우고 실제 Chrome 으로 서비스·지갑 페이지를 함께 연다. 보는 것은 네 가지다.
//   (a) 서비스를 ?tour=1 로 열면 지갑이 등록 전이라 로그인 버튼이 잠기고 사유 배지가 붙는다(쿼리는 주소창에서 지워진다)
//   (b) 지갑에서 등록하면 다음 폴링에 서비스 잠금이 풀리고 말풍선이 3단계(로그인)를 가리킨다
//   (c) 로그인에 성공하면 말풍선이 4단계(이용·재검증)로 옮겨 가고 상태 점이 초록이 된다
//   (d) 신원 기관(CIA) 프로세스를 내리면 신원 기관 점이 빨강, 지갑 점이 노랑(신원 기관에 못 닿음)이 된다
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
    await rpPage.waitForFunction(() => document.querySelector('#loginBtn')?.disabled === true, undefined, { timeout: 30_000 });
    const badge = await rpPage.$('.tour-lock');
    assert.ok(badge, '잠금 사유 배지(.tour-lock)가 있어야 한다');
    assert.equal(await badge.getAttribute('data-for'), 'loginBtn');
    assert.ok((await badge.textContent()).includes('지갑'), `배지 문구: ${j(await badge.textContent())}`);
    assert.equal(new URL(rpPage.url()).search, '', `주소창에 ?tour 가 남았다: ${rpPage.url()}`);
    assert.equal(await rpPage.evaluate(() => localStorage.getItem('mode3.tour')), '1');
    assert.equal(await rpPage.evaluate(() => document.querySelector('#tourToggle')?.checked), true, '스위치가 켜진 채로 보인다');
  });

  await t('지갑에서 등록하면 서비스 잠금이 풀리고 말풍선이 로그인 버튼을 가리킨다', async () => {
    await walletPage.goto(`${wallet.base}/?tour=1`);
    await walletPage.waitForSelector('#mainView:not([hidden])', { timeout: 30_000 });
    // 서비스는 격리 헬퍼가 이미 승인해 두었으므로 2단계(등록)는 잠기지 않는다.
    await walletPage.waitForFunction(() => document.querySelector('#registerBtn') && !document.querySelector('#registerBtn').disabled, undefined, { timeout: 30_000 });
    assert.equal(await walletPage.$('.tour-lock'), null, '승인된 서비스가 있으면 등록 버튼은 잠기지 않는다');
    await walletPage.click('#registerBtn');
    await waitText(walletPage, '#registerResult', '등록됨', 60_000);
    // 서비스 페이지는 5초마다 지갑 health 를 읽는다 — 다음 폴링에 잠금이 풀려야 한다.
    await rpPage.waitForFunction(() => document.querySelector('#loginBtn')?.disabled === false, undefined, { timeout: 30_000 });
    assert.equal(await rpPage.$('.tour-lock'), null, '잠금이 풀리면 배지도 사라진다');
    await rpPage.waitForFunction(() => (document.querySelector('.tour-bubble')?.textContent ?? '').includes('로그인'), undefined, { timeout: 30_000 });
  });

  await t('로그인 뒤 말풍선이 4단계(이용)로 옮겨 가고 상태 점 셋 이상이 초록', async () => {
    await rpPage.click('#loginBtn');
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    await rpPage.waitForFunction(() => (document.querySelector('.tour-bubble')?.textContent ?? '').includes('재검증'), undefined, { timeout: 30_000 });
    await rpPage.waitForFunction(() => [...document.querySelectorAll('.stack-dots .dot')].filter((d) => d.classList.contains('ok')).length >= 3, undefined, { timeout: 30_000 })
      .catch(async () => { throw new Error(`초록 점이 셋 미만이다: ${j(await dotClasses(rpPage))}`); });
  });

  await t('V9 등록부 줄: 로그인 뒤 ✓, 관리자 바꿔치기 뒤 다음 폴링에 ✗, 되돌리기 뒤 ✓', async () => {
    await walletPage.waitForFunction(() => document.querySelector('#registryBadge')?.classList.contains('ok'), undefined, { timeout: 30_000 });
    assert.equal((await stack.cia.adminPost('/cia/admin/registry/tamper', { uid: '12345' })).status, 200);
    // 2026-10-01 리뷰 Important 1 회귀 확인: 바꿔치기 뒤 로그인은 403 registry_mismatch 로 거절되고, 서비스 페이지의
    // 판정 제목 줄(.summary, demo.js 의 renderVerdict 가 쓰는 클래스)이 빈 줄이 아니라 사유 사전의 제목을 그대로
    // 보여야 한다 — summary 를 섣불리 ''로 채우면 demo.js 의 `summary ?? r.title` 폴백이 깨져 이 줄이 비어 버린다.
    await rpPage.click('#loginBtn');
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
  await t('V9 시연 카드(전문가 보기): salt 를 바꾸고 다음 발급 → 서비스 로그인 결과에 bad user credential proof', async () => {
    await walletPage.evaluate(() => Demo.setExpert(true));
    await walletPage.waitForSelector('#demoCard', { state: 'visible' });
    assert.equal((await stack.cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' })).status, 200);   // 다음 로그인이 새로 받게
    await walletPage.click('#demoNewSalt'); await walletPage.selectOption('#demoScope', 'issue'); await walletPage.click('#demoApplyBtn');
    await waitText(walletPage, '#demoVerdict', '적용', 10_000);
    await rpPage.click('#loginBtn');
    await waitText(rpPage, '#verdict', 'bad user credential proof', 120_000);
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
    await rpPage.click('#loginBtn');
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
    assert.ok((await rpPage.$eval('.stack-dots .dot.wallet', (d) => d.getAttribute('aria-label'))).includes('신원 기관'), '지갑 점의 사유가 신원 기관 쪽임을 말한다');
  });
} finally {
  await browser.close().catch(() => {});
  if (ciaStopped) console.log('(CIA 는 테스트가 이미 내렸다 — 스택 stop 은 나머지를 정리한다)');
  await stack?.stop().catch((e) => console.error(`스택 정리 실패: ${e.message}`));
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
// 다른 Mode 3 테스트와 같은 관례 — 남는 핸들 때문에 저절로 끝나지 않는다
process.exit(failed === 0 ? 0 : 1);
