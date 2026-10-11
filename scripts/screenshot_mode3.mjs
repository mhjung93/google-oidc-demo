// Mode 3 데모 페이지 스크린샷 — 설계 2026-09-24-mode3-demo-ux-design.md §6.
//
// 격리 스택(tests/helpers/isolated_mode3_stack.mjs, file 모드)을 임시 포트로 띄우고 실제 Chrome 으로
// 네 페이지(서비스·지갑·관리자·내 계정)를 ko·en·전문가 세 상태로 fullPage 캡처한다. 서비스·지갑은
// 좁은 창(400px) 한 장을 더 찍는다. 개발용 :3100/:4100/:5100 은 건드리지 않는다.
//
// --tour 를 주면 대신 **체험 모드**(설계 2026-09-25 §3)의 네 장면을 찍는다 — 서비스 잠김·지갑 말풍선·
// 잠금이 풀린 서비스 말풍선·상태 패널 펼침. 기본 저장 위치도 results/mode3_ux_20260925/ 로 바뀐다.
//
//   node scripts/screenshot_mode3.mjs                       # results/mode3_ux_20260924/ 에 저장
//   node scripts/screenshot_mode3.mjs --out results/foo      # 다른 디렉터리에 저장
//   node scripts/screenshot_mode3.mjs --tour                 # results/mode3_ux_20260925/ 에 체험 모드 4장
//
// 전제: hardhat 노드(:8545), build/mode3 의 pi_cred zkey·vkey, 설치된 Chrome(또는 Chromium).
// 끝나면 스택과 브라우저를 모두 내린다 — 포트를 남기지 않는다.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from '../tests/helpers/isolated_mode3_stack.mjs';
import { VKEY_PATH } from '../lib/mode3_wallet.js';

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

// ---- 인자 ----
const argv = process.argv.slice(2);
let TOUR = false;
let outArg = null;                  // --out 이 없으면 모드에 따라 아래에서 기본값을 고른다
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--tour') { TOUR = true; continue; }
  if (argv[i] === '--out') { outArg = argv[++i] ?? outArg; continue; }
  if (argv[i].startsWith('--out=')) { outArg = argv[i].slice('--out='.length); continue; }
  if (argv[i] === '--help' || argv[i] === '-h') {
    console.log('사용법: node scripts/screenshot_mode3.mjs [--tour] [--out <디렉터리>]');
    process.exit(0);
  }
  console.error(`알 수 없는 인자: ${argv[i]}`);
  process.exit(2);
}
outArg ??= TOUR ? 'results/mode3_ux_20260925' : 'results/mode3_ux_20260924';
const OUT_DIR = path.isAbsolute(outArg) ? outArg : path.join(REPO_ROOT, outArg);

// 무거운 것을 띄우기 전에 전제를 확인한다 — 실패해도 자식 프로세스를 고아로 남기지 않는다.
if (!fs.existsSync(VKEY_PATH)) {
  console.error(`pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);
  process.exit(1);
}
fs.mkdirSync(OUT_DIR, { recursive: true });

/** 설치된 Chrome 을 먼저 쓴다 — Playwright 의 번들 chromium 은 Ubuntu 20.04 에 내려받을 수 없다(2026-09-22 실측). */
async function launchBrowser() {
  const tried = [];
  for (const opts of [{ channel: 'chrome' }, {}]) {
    try { return await chromium.launch(opts); }
    catch (e) { tried.push(`${JSON.stringify(opts)}: ${e.message.split('\n')[0]}`); }
  }
  throw new Error(`BLOCKED: 브라우저를 띄우지 못했다.\n  ${tried.join('\n  ')}`);
}

const WIDE = { width: 1280, height: 900 };
const NARROW = { width: 400, height: 900 };
const shots = [];

async function shot(page, name) {
  const file = path.join(OUT_DIR, `${name}.png`);
  // 안내 바는 position:sticky 다 — 스크롤된 채로 fullPage 를 찍으면 바가 페이지 한가운데에 박혀 카드를 가린다.
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(100);
  await page.screenshot({ path: file, fullPage: true });
  shots.push(name);
  console.log(`  찍음 ${path.relative(REPO_ROOT, file)}`);
}

/** 언어·전문가 보기를 바꾸고 다시 그려질 틈을 준다(모두 동기 렌더지만 폰트·레이아웃을 한 틱 기다린다). */
async function setState(page, lang, expert) {
  await page.evaluate(([l, e]) => { window.Demo.setLang(l); window.Demo.setExpert(e); }, [lang, expert]);
  await page.waitForTimeout(200);
}

/** 한 페이지의 ko·en·전문가(+좁은 창) 세트. 끝나면 ko·전문가 꺼짐·넓은 창으로 되돌린다. */
async function captureStates(page, name, { narrow = false } = {}) {
  await setState(page, 'ko', false); await shot(page, `${name}-ko`);
  await setState(page, 'en', false); await shot(page, `${name}-en`);
  await setState(page, 'ko', true); await shot(page, `${name}-expert`);
  await setState(page, 'ko', false);
  if (narrow) {
    await page.setViewportSize(NARROW);
    await page.waitForTimeout(200);
    await shot(page, `${name}-narrow`);
    await page.setViewportSize(WIDE);
    await page.waitForTimeout(200);
  }
}

/** sel 의 텍스트가 needle 을 담을 때까지 기다린다. 실패하면 지금 보이는 텍스트를 붙여 던진다. */
async function waitText(page, sel, needle, timeout = 180_000) {
  try {
    await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout });
  } catch {
    const now = await page.$eval(sel, (el) => el.textContent ?? '').catch(() => '?');
    throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${JSON.stringify(now)}`);
  }
}

/** 기본 세트: 네 페이지를 조작이 끝난 상태로 만들고 ko·en·전문가(+좁은 창)를 찍는다. */
async function captureAll(context, stack) {
  const { cia, wallet, rp } = stack;

  // ---- 지갑: 등록 ----
  const walletPage = await context.newPage();
  await walletPage.goto(wallet.base);
  await walletPage.waitForSelector('#mainView:not([hidden])');
  console.log('지갑 등록…');
  await walletPage.click('#registerBtn');
  await waitText(walletPage, '#registerResult', '등록됨', 60_000);

  // ---- 서비스: 로그인 한 번 + 재검증 한 번 ----
  const rpPage = await context.newPage();
  await rpPage.goto(rp.base);
  await waitText(rpPage, '#rpStatusBadge', '활성', 60_000);
  console.log('로그인…');
  await rpPage.click('#loginBtn');
  await waitText(rpPage, '#verdict', '로그인 성공');
  console.log('재검증…');
  await rpPage.click('#revalidateBtn');
  await waitText(rpPage, '#sessionVerdict', '재검증 성공');
  await rpPage.click('#refreshLogins');
  await rpPage.waitForTimeout(500);

  // ---- 지갑: 트랜잭션 한 건 — 폼 기본값은 AttrGate.claim() 이라 공개 조건(나이·국가 집합)을 채워야 내부 호출이
  // 성공한다(안 채우면 최종 리뷰 M2 뒤로는 "전송 실패(내부 호출 실패)" 카드가 뜬다). 나이 프리셋 + 국가 집합 슬롯.
  console.log('트랜잭션…');
  await walletPage.click('#refreshBtn');
  await walletPage.waitForFunction(() => !document.querySelector('#txBtn').disabled, undefined, { timeout: 30_000 });
  await walletPage.click('#ageBtn');
  await walletPage.selectOption('#setSlot', '1');
  await walletPage.click('#txBtn');
  await waitText(walletPage, '#txVerdict', '전송 성공');

  // ---- 관리자: 시크릿을 넣고 목록을 불러온다 ----
  const adminPage = await context.newPage();
  await adminPage.goto(`${cia.base}/admin`);
  await adminPage.fill('#secret', cia.adminSecret);
  await adminPage.click('#reloadBtn');
  await adminPage.waitForSelector('#accounts table.list', { timeout: 30_000 });
  await adminPage.waitForSelector('#rps table.list', { timeout: 30_000 });
  await adminPage.waitForTimeout(800);

  // ---- 내 계정: 조작 없이 첫 화면 ----
  const accountPage = await context.newPage();
  await accountPage.goto(`${cia.base}/account`);
  await accountPage.waitForSelector('#revokeBtn');

  console.log(`캡처 → ${path.relative(REPO_ROOT, OUT_DIR)}`);
  await captureStates(rpPage, 'rp', { narrow: true });
  await captureStates(walletPage, 'wallet', { narrow: true });
  await captureStates(adminPage, 'admin');
  await captureStates(accountPage, 'account');
}

/**
 * 체험 모드 세트(설계 2026-09-25 §3). 두 창을 ?tour=1 로 열어 잠김 → 등록 → 잠금 해제 → 로그인 → 상태 패널
 * 순서로 네 장을 찍는다. 체험 모드는 오리진마다 localStorage 에 새겨지므로 각 창을 한 번씩 ?tour=1 로 연다.
 */
async function captureTour(context, stack) {
  const { wallet, rp } = stack;

  // ---- 서비스: 지갑 등록 전이라 로그인 버튼이 잠긴 화면 ----
  const rpPage = await context.newPage();
  await rpPage.goto(`${rp.base}/?tour=1`);
  await rpPage.waitForFunction(() => document.querySelector('#loginBtn')?.disabled === true, undefined, { timeout: 30_000 });
  await rpPage.waitForSelector('.tour-lock', { timeout: 30_000 });
  await rpPage.waitForTimeout(300);
  await shot(rpPage, 'rp-tour-locked');

  // ---- 지갑: 말풍선이 등록 버튼을 가리키는 화면(누르기 전) ----
  const walletPage = await context.newPage();
  await walletPage.goto(`${wallet.base}/?tour=1`);
  await walletPage.waitForSelector('#mainView:not([hidden])', { timeout: 30_000 });
  await walletPage.waitForSelector('.tour-bubble', { timeout: 30_000 });
  await walletPage.waitForTimeout(300);
  await shot(walletPage, 'wallet-tour');

  // ---- 등록 → 다음 폴링에 서비스 잠금이 풀리고 말풍선이 로그인 버튼으로 ----
  console.log('지갑 등록…');
  await walletPage.click('#registerBtn');
  await waitText(walletPage, '#registerResult', '등록됨', 60_000);
  await rpPage.waitForFunction(() => document.querySelector('#loginBtn')?.disabled === false, undefined, { timeout: 30_000 });
  await rpPage.waitForFunction(() => (document.querySelector('.tour-bubble')?.textContent ?? '').includes('로그인'), undefined, { timeout: 30_000 });
  await rpPage.waitForTimeout(300);
  await shot(rpPage, 'rp-tour-bubble');

  // ---- 로그인 뒤 점을 눌러 상태 패널을 펼친 화면 ----
  console.log('로그인…');
  await rpPage.click('#loginBtn');
  await waitText(rpPage, '#verdict', '로그인 성공');
  await rpPage.click('.stack-dots .dot.aa');
  await rpPage.waitForSelector('#stackPanel:not([hidden])', { timeout: 10_000 });
  await rpPage.waitForTimeout(300);
  await shot(rpPage, 'rp-stack-panel');
}

const browser = await launchBrowser();
let stack = null;
try {
  console.log('격리 스택 기동(file 모드)…');
  stack = await startIsolatedMode3Stack();          // 헬퍼가 RP 등록 승인·활성화까지 기다린다
  const { cia, wallet, rp } = stack;
  console.log(`  CIA ${cia.base} · 지갑 ${wallet.base} · 서비스 ${rp.base}`);

  const context = await browser.newContext({ viewport: WIDE });
  // 파괴적 조작의 확인창(설계 §4.5) — 자동화는 모두 승인한다.
  context.on('page', (p) => p.on('dialog', (d) => d.accept().catch(() => {})));

  if (TOUR) await captureTour(context, stack);
  else await captureAll(context, stack);

  console.log(`\n${shots.length}장 저장: ${OUT_DIR}`);
} finally {
  await browser.close().catch(() => {});
  if (stack) await stack.stop().catch(() => {});
}
