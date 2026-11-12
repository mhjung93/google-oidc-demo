// Mode 3 브라우저 경로 — 실제 Chrome 에서 지갑 페이지·승인 팝업·RP 페이지를 돌린다(스펙 2026-09-22 metamask-snap §7).
// MetaMask 는 tests/helpers/ethereum_stub.js 가 대신하고, Snap 은 **진짜 snap-mode3/src/index.js 의 onRpcRequest** 가 답한다
// (Task 5 Ruling 5 — 시뮬레이터가 아니다). 대화상자 답과 체인 전송만 이 하네스가 맡는다.
// Task 14(B5, 2026-10-23): 이 스택은 ciaEnv: { CIA_ISSUE_AUTH: 'code' } 로 뜬다 — 그래서 신규 로그인(비-reauth)마다
// 지갑 팝업 창이 갔다가 돌아오는 IdP 로그인 페이지(완료는 completeIdpAuth())를 거쳐야 한다. 재승인(reauth)·precheck 실패·거절로 끝나는
// 케이스는 /cia/issue 를 타지 않아 그대로다.
// hardhat :8545 와 build/mode3 의 pi_cred zkey·vkey, 그리고 Chrome(또는 Chromium)이 필요하다. (browser 그룹)
//   node tests/test_mode3_browser.mjs
//   MODE3_BROWSER_DEBUG=1 로 브라우저 콘솔·페이지 오류를 그대로 흘려 본다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { buildInitScript, STUB_SRP } from './helpers/ethereum_stub.js';
import { derivedSecrets } from './helpers/snap_sim.mjs';
import { VKEY_PATH } from '../lib/mode3_wallet.js';
import { attrGateAt } from '../lib/mode3_onchain.js';
import { execFileSync } from 'node:child_process';
import { DEFAULT_ATTR_SCHEMA, encodeSlotValue } from '../lib/mode3_attr_schema.js';
import { encodeProfile } from '../lib/mode3_attr_schema.js';
import { attrCommit } from '../lib/mode3_attr_commit.js';
import { auidOf } from '../lib/mode3_credential.js';
import { openBackup, isSealedBackup } from '../lib/browser/attr_backup.js';

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

// 속성 커밋먼트 도구 번들(2026-11-09 Phase 1) — /attr.html 케이스가 쓴다. user_static 테스트와 같은 방식으로 여기서 만든다.
execFileSync('node', ['scripts/build_attr_tool.mjs'], { stdio: 'inherit' });
const browser = await launchBrowser();
const provider = getProvider();
// Task 14(B5): CIA_ISSUE_AUTH=code — 신규 로그인마다 IdP 인증 창의 1회용 코드(auth_code)가 필요하다(completeIdpAuth 참고).
const stack = await startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'snap', MODE3_DEMO_RACE: '1' }, ciaEnv: { CIA_ISSUE_AUTH: 'code', CIA_REVOKE_PUBLISH_AFTER_BLOCKS: '3' }, autoRelay: true });   // 2026-11-12: Race (2) 시연 — 폐기 뒤 3블록에 IdP 가 게시   // V10: 거울 릴레이는 헬퍼가 대신 돈다(페이지 안 로그인)
const { cia, wallet, rp } = stack;

// ---- 하네스가 맡는 것: Snap 저장소, 대화상자, 체인 전송 ----
// MetaMask 의 암호화 저장소는 확장에 있다 — 지갑 페이지와 팝업(다른 JS 컨텍스트)이 같은 등록을 봐야 하므로 여기 둔다.
let snapState = null;
const dialogs = [];        // 사용자에게 보인 대화상자(문구 검사용)
const answers = [];        // 다음 대화상자들이 돌려줄 값
const sentTxs = [];        // 스텁이 실제로 보낸 트랜잭션
// 설정하면 대화상자가 여기서 멈춘다 — "팝업이 동의를 기다리는 중"인 순간을 붙잡아야 하는 테스트가 쓴다.
let dialogGate = null;

try {
  const eoa = await provider.getSigner(1);       // MetaMask 의 사용자 계정 역할(가스를 낸다)
  const account = await eoa.getAddress();
  // Task 14(B5): 등록 케이스(아래 "등록(2026-10-22): …")가 채운다 — IdP 가입이 배정한 uid, 지갑이 낸 auid.
  // 이후의 모든 로그인(completeIdpAuth 의 기본값)과 Task 12 "IdP 인증 창" 케이스가 재사용한다.
  let uid = null, AUID = null;
  // 2026-11-12(스펙 snap-derived-secrets): salt 는 스냅이 시드에서 유도한다 — 스텁 SRP(STUB_SRP)의 유도값이 곧 이 사용자의 salt 다.
  const USER_SALT = derivedSecrets(STUB_SRP).s_u;
  const DEMO_PWD = 'demo-pass-9';   // IdP /user 가입 비밀번호(등록 케이스가 쓴다) — Snap 은 비밀번호를 받지 않는다(Task 15).
  const cfg = (await wallet.get('/wallet/config')).body;
  assert.equal(cfg.secrets, 'snap', `지갑이 snap 모드여야 한다: ${j(cfg)}`);

  const context = await browser.newContext();
  await context.exposeFunction('__snapState', (op, newState) => {
    if (op === 'get') return snapState;
    if (op === 'update') { snapState = newState; return null; }
    if (op === 'clear') { snapState = null; return null; }
    throw new Error(`하네스: 모르는 snap_manageState operation ${op}`);
  });
  await context.exposeFunction('__snapDialog', async (params) => {
    dialogs.push(params);
    if (dialogGate) await dialogGate;
    if (!answers.length) throw new Error(`하네스: 대화상자 응답 큐가 비었다 — ${j(params).slice(0, 200)}`);
    return answers.shift();
  });
  await context.exposeFunction('__sendTx', async (tx) => {
    const sent = await eoa.sendTransaction({ to: tx.to, data: tx.data ?? '0x', value: tx.value ?? 0 });
    sentTxs.push(sent.hash);
    return sent.hash;
  });
  await context.exposeFunction('__getReceipt', async (hash) => {
    const r = await provider.getTransactionReceipt(hash);
    return r ? { transactionHash: r.hash, status: Number(r.status), blockNumber: r.blockNumber } : null;
  });
  await context.addInitScript({ content: buildInitScript({ snapId: cfg.snapId, account, chainId: cfg.chainId }) });
  if (DEBUG) {
    context.on('page', (p) => {
      p.on('console', (m) => console.log(`    [${new URL(p.url()).port}] ${m.type()}: ${m.text()}`));
      p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`));
    });
  }

  const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
  // 2026-11-03: 지갑 페이지는 탭(계정·연결된 서비스·보내기·설정) 하나씩만 보인다 — 가려진 요소를 만지기 전에 그 탭을 누른다.
  const walletTab = (page, name) => page.click(`#walletTabs [data-tab="${name}"]`);
  // 로그인 모달(2026-10-15): #loginBtn 은 모달을 열기만 하고, 실제 zk 로그인은 모달의 #idpLoginBtn 이 한다.
  // 2026-10-21: 로그인 상태에서는 로그인 버튼이 숨으므로, 이미 로그인돼 있으면 먼저 로그아웃한다.
  const idpLogin = async (page) => { if (await page.$eval('#loginBtn', (b) => b.hidden)) { await page.click('#logoutBtn'); await page.waitForSelector('#loginBtn:not([hidden])'); } await page.click('#loginBtn'); await page.click('#idpLoginBtn'); };
  /**
   * Task 14(B5): CIA_ISSUE_AUTH=code 라 신규 로그인(비-reauth)마다 지갑 팝업이 여는 IdP 인증 창을 완성해야 한다
   * (재승인·precheck 실패·동의 거절로 끝나는 케이스는 /cia/issue 를 타지 않아 이 창을 열지 않는다 — 호출할 필요가 없다).
   * popup 은 지갑의 mode3-authorize 팝업(이미 consentLogin 동의를 통과해 이 창을 연 상태). 창이 스스로 닫힐 때까지
   * 기다린다(cia_login.html 이 성공 시 300ms 뒤 닫는다) — 호출자는 이어서 원래 팝업·RP 의 성공 신호를 기다리면 된다.
   */
  async function completeIdpAuth(popup, { authUid = uid, pwd = DEMO_PWD } = {}) {
    // 2026-11-05: 별도 창·"IdP 인증 창 열기" 버튼 대신 팝업 창 자체가 IdP 로그인 페이지(/login?return=1)로 간다(mode3/wallet.html goIdpAuth).
    // 2026-11-09(사용자 결정): auid 는 더 이상 쿼리로 넘기지 않는다 — uid·비밀번호·auid 를 모두 직접 넣어야 지갑 /?authorize=1 로 돌아와 로그인을 이어 간다.
    await atIdpLogin(popup);
    assert.equal(await popup.isVisible('#authAuidRow'), true, 'auid 칸은 늘 보인다');
    assert.equal(await popup.inputValue('#authAuid'), '', 'auid 는 미리 채우지 않는다');
    await popup.fill('#authUid', String(authUid));
    await popup.fill('#authPwd', pwd);
    await popup.fill('#authAuid', String(AUID));
    await popup.click('#authGo');
    await backAtWallet(popup);
  }
  /** 팝업이 IdP 로그인 페이지(return=1)에 와 있을 때까지. */
  const atIdpLogin = (popup) => popup.waitForURL((u) => u.origin === cia.base && u.pathname === '/login' && u.searchParams.get('return') === '1', { timeout: 60_000 });
  /** 팝업이 IdP 에서 지갑 /?authorize=1 로 돌아올 때까지. */
  const backAtWallet = (popup) => popup.waitForURL((u) => u.origin === wallet.base && u.searchParams.get('authorize') === '1', { timeout: 30_000 });
  /** sel 의 텍스트가 needle 을 담을 때까지 기다린다. 실패하면 지금 보이는 텍스트를 붙여 던진다. */
  async function waitText(page, sel, needle, timeout = 30_000) {
    try {
      await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout });
    } catch (e) {
      throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`);
    }
  }
  const lastDialog = () => j(dialogs[dialogs.length - 1] ?? null);
  /** 팝업이 닫힐 때까지 기다린다. 창 이름은 `mode3-authorize-${r_s}` 라 같은 세션(로그인 뒤 재승인)이면 이름이 같고,
   *  아직 살아 있으면 다음 window.open 이 새 창을 만들지 않고 그 창을 재사용한다 — 그러면 다음 테스트의 'page' 이벤트가 오지 않는다. */
  const awaitPopupClosed = async (popup) => { if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 15_000 }); };
  /** 하네스 쪽 조건을 기다린다(대화상자가 떴는지 등 — 페이지 밖에서 일어나는 일). */
  async function waitFor(cond, what, timeout = 60_000) {
    const deadline = Date.now() + timeout;
    while (!cond() && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
    assert.ok(cond(), `${what} 를 기다리다 시간이 지났다 (${timeout}ms)`);
  }
  /** 페이지가 밖으로 드러내는 모든 문자열 — DOM, 입력값, localStorage·sessionStorage. */
  const pageDump = (page) => page.evaluate(() => {
    const inputs = [...document.querySelectorAll('input,textarea,select')].map((e) => `${e.id}=${e.value}`).join('\n');
    const store = (s) => { try { return JSON.stringify(s); } catch { return ''; } };
    // 2026-11-11: 속성 커밋먼트 도구의 기록(mode3_attr_tool_v1)은 salt 를 평문으로 든다 — 첫 등록이 그 salt 를 쓰므로(사용자 결정) 의도된 예외다
    // (런북 "도구의 비밀은 localStorage 평문" 한계). 이 검사는 스냅·에이전트 쪽 비밀이 새지 않는지만 본다.
    const ls = {}; for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (k !== 'mode3_attr_tool_v1') ls[k] = localStorage.getItem(k); }
    return [document.documentElement.outerHTML, inputs, store(ls), store(sessionStorage)].join('\n');
  });

  /** RP 페이지가 들고 있는 서비스 정보(진짜 arid·origin·cert_s·pk_trace). */
  const rpRequestBase = () => rpPage.evaluate(() => ({ arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace }));
  /**
   * 정상 흐름을 타지 않고 승인 팝업에 **임의의 요청 본문**을 직접 보낸다(피싱 페이지 흉내).
   * 팝업은 사용자 제스처로만 열리므로 버튼을 하나 만들어 Playwright 가 실제로 누른다.
   * 돌려주는 것은 { popup, result } — result 는 팝업이 postMessage 로 보낸 mode3-authorize-result 의 result.
   */
  async function forgeAuthorize(name, request) {
    await rpPage.evaluate(({ walletOrigin, request: req, name: winName }) => {
      document.getElementById('forgedBtn')?.remove();
      window.__forged = new Promise((resolve) => { window.__forgedResolve = resolve; });
      const btn = document.createElement('button');
      btn.id = 'forgedBtn';
      btn.addEventListener('click', () => {
        const popup = window.open(`${walletOrigin}/?authorize=1`, winName, 'width=480,height=680');
        window.addEventListener('message', (ev) => {
          if (ev.origin !== walletOrigin || ev.source !== popup || !ev.data) return;
          if (ev.data.type === 'mode3-authorize-ready') { popup.postMessage({ type: 'mode3-authorize', ...req }, walletOrigin); return; }
          if (ev.data.type === 'mode3-authorize-result') window.__forgedResolve(ev.data.result);
        });
      });
      document.body.appendChild(btn);
    }, { walletOrigin: wallet.base, request, name });
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#forgedBtn')]);
    const result = await rpPage.evaluate(() => Promise.race([
      window.__forged,
      new Promise((_, rej) => setTimeout(() => rej(new Error('위조 요청의 결과가 60초 안에 오지 않았다')), 60_000)),
    ]));
    return { popup, result };
  }

  /**
   * F-1(2026-10-23): forgeAuthorize 와 같은 패턴으로 지갑 팝업(?authorize=1)을 열고, 준비 신호를 받은 뒤 **RP 오리진에서**
   * mode3-register 를 보낸다(진짜 등록 흐름은 IdP 오리진의 /user 페이지가 연다 — mode3/wallet.html:446 의 수신 가드가
   * 이 가짜 발신 오리진을 걸러내야 한다). 돌려주는 것은 { popup, result } — result 는 mode3-register-result 의 result.
   */
  async function forgeRegister(name, request) {
    await rpPage.evaluate(({ walletOrigin, request: req, name: winName }) => {
      document.getElementById('forgedRegBtn')?.remove();
      window.__forgedReg = new Promise((resolve) => { window.__forgedRegResolve = resolve; });
      const btn = document.createElement('button');
      btn.id = 'forgedRegBtn';
      btn.addEventListener('click', () => {
        const popup = window.open(`${walletOrigin}/?authorize=1`, winName, 'width=480,height=680');
        window.addEventListener('message', (ev) => {
          if (ev.origin !== walletOrigin || ev.source !== popup || !ev.data) return;
          if (ev.data.type === 'mode3-authorize-ready') { popup.postMessage({ type: 'mode3-register', ...req }, walletOrigin); return; }
          if (ev.data.type === 'mode3-register-result') window.__forgedRegResolve(ev.data.result);
        });
      });
      document.body.appendChild(btn);
    }, { walletOrigin: wallet.base, request, name });
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#forgedRegBtn')]);
    const result = await rpPage.evaluate(() => Promise.race([
      window.__forgedReg,
      new Promise((_, rej) => setTimeout(() => rej(new Error('위조 등록 요청의 결과가 10초 안에 오지 않았다')), 10_000)),
    ]));
    return { popup, result };
  }

  const walletPage = await context.newPage();
  await walletPage.goto(wallet.base);

  await t('지갑 페이지: snap 모드 화면이 켜지고 MetaMask 연결이 된다', async () => {
    await walletPage.waitForSelector('#connectCard:not([hidden])', { timeout: 15_000 });   // snap 모드는 연결 전에 연결 카드만 보인다(2026-11-03)
    assert.equal(await walletPage.$eval('#fileRegFields', (el) => el.hidden), true, 'snap 모드는 uid·pwd 폼을 숨긴다(게이트와 무관하게 요소 자체의 hidden 으로 본다)');
    await walletPage.click('#connectBtn');
    await waitText(walletPage, '#mmStatus', account);
    assert.ok((await text(walletPage, '#mmStatus')).startsWith('MetaMask'), '배지는 "MetaMask 0x…"(2026-11-05 — Snap id 는 보이지 않는다)');
  });

  // "내 계정"(2026-11-12 사용자 요청): 스냅이 저장한 값 전부를 보여 주는 탭. 값이 든 칸은 data-store-path(상태 안의 경로)로 찾는다.
  const storeCell = (path) => `#meCard [data-store-path="${path}"]`;
  await t('내 계정: 등록 전에는 "저장된 등록 없음" 과 다음 가입 번호만 보인다', async () => {
    await walletTab(walletPage, 'me');
    await walletPage.waitForSelector('#meStoreEmpty:not([hidden])', { timeout: 15_000 });
    await waitText(walletPage, storeCell('nextIndex'), '0');
    assert.equal(await walletPage.$(storeCell('registration.uid')), null, '등록 줄은 없다');
    await walletTab(walletPage, 'services');
  });

  // 2026-11-09(사용자 결정): zkID 가입에는 지갑이 끼지 않는다 — /user 에는 지갑 등록 버튼이 없고, 지갑 등록은 아래 RP 로그인 케이스에서
  // 팝업 → zkID 인증 창(등록 모드) → 돌아와 등록 → 발급으로 처음 한 번 일어난다. (Task 14 의 "/user 가 mode3-register 팝업을 연다" 는 Google 등록(?google=1)에만 남았다.)
  await t('zkID 가입(2026-11-09): 아이디·비밀번호로 가입 → 자동 로그인(등록 상태 배지는 없다, 2026-11-10); 지갑 등록 버튼·카드는 없고 프로필 카드만 보인다', async () => {
    const u = await context.newPage(); await u.goto(`${cia.base}/user`);
    await u.click('#showSignupBtn'); await u.fill('#signupId', 'demo-user'); await u.fill('#signupPwd', DEMO_PWD); await u.fill('#signupPwd2', DEMO_PWD); await u.click('#signupBtn');
    await waitText(u, '#profileVerdict', '가입했습니다');   // 안내는 프로필 카드에 — "지갑 등록은 서비스에서 zkID 로 로그인할 때"
    await waitText(u, '#meInfo', 'demo-user'); assert.equal(await u.isHidden('#loginView'), true, '가입 직후 자동 로그인');
    assert.equal(await u.$('#meBadge'), null, '아이디 옆 등록 상태 배지는 없다(2026-11-10)');
    assert.equal(await u.$('#registerBtn'), null, '지갑 등록 버튼이 없다'); assert.equal(await u.$('#registerCard'), null, '지갑 등록 카드가 없다');
    assert.equal(await u.isVisible('#profileCard'), true, '프로필 카드는 등록과 무관하게 보인다');
    assert.equal(await u.isHidden('#revokeCard'), true, '등록 전에는 계정 관리(지갑 연결 해제) 카드가 없다');
    assert.equal((await wallet.get('/wallet/status')).body.registered, false, '지갑은 아직 미등록');
    await u.close();
  });

  await t('Snap 오리진 검사: 지갑 오리진이 아니면 거절한다(진짜 Snap 코드가 돈다는 증거)', async () => {
    const msg = await walletPage.evaluate(() => window.__snapOnRpcRequest({ origin: 'http://evil.example', request: { method: 'getPublicInfo' } }).then(() => 'RESOLVED', (e) => e.message));
    assert.match(msg, /unauthorized_origin/);
  });

  // ---- RP 페이지: 팝업 로그인 ----
  const rpPage = await context.newPage();
  await rpPage.goto(rp.base);
  let sessionRs = null;

  await t('RP 페이지: /wallet/config 를 CORS 로 읽어 snap 모드임을 안다', async () => {
    await waitText(rpPage, '#walletMode', '스냅 비밀=snap', 15_000);
    assert.ok((await text(rpPage, '#walletMode')).includes(cfg.snapId));
  });

  // 2026-11-11(사용자 결정): 첫 등록은 속성 도구 기록의 salt 를 쓴다(스냅 팝업의 salt 칸은 없다) — 인증 창(등록 모드)에 속성 도구가 보여 준 auid 를 붙여 넣는다.
  await t('첫 로그인 전에 속성 도구 기록이 없으면 등록하지 않고 안내한다(attr_record_missing) — 코드·Snap 은 쓰지 않는다', async () => {
    const demoUid = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.id === 'demo-user').uid;
    const demoAuid = (await auidOf({ uid: BigInt(demoUid), s_u: BigInt(USER_SALT) })).toString();
    await walletPage.evaluate(() => localStorage.removeItem('mode3_attr_tool_v1'));
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await atIdpLogin(popup);
    await popup.fill('#authUid', 'demo-user'); await popup.fill('#authPwd', DEMO_PWD); await popup.fill('#authAuid', demoAuid); await popup.click('#authGo');
    await backAtWallet(popup);
    await waitText(rpPage, '#verdict', '속성 커밋먼트 기록이 없습니다', 120_000);
    assert.equal((await wallet.get('/wallet/status')).body.registered, false, '등록하지 않았다');
    assert.equal(snapState?.registration, undefined, 'Snap 에도 아무것도 없다');
    await awaitPopupClosed(popup);
  });

  await t('리뷰 I-2(2026-11-12): 직접 넣은 salt(시드 유도 전)로 만든 속성 기록이면 첫 등록을 멈추고 "스냅에서 가져오기" 로 다시 만들라고 안내한다(attr_record_salt_not_derived)', async () => {
    const OLD_SALT = '123456789012345678901234567890';   // 11-10·11-11 의 직접 입력 salt — 스냅 유도값이 아니다
    assert.notEqual(OLD_SALT, USER_SALT);
    const demoUid = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.id === 'demo-user').uid;
    const oldAuid = (await auidOf({ uid: BigInt(demoUid), s_u: BigInt(OLD_SALT) })).toString();
    await walletPage.evaluate((r) => localStorage.setItem('mode3_attr_tool_v1', JSON.stringify(r)), { version: 2, uid: String(demoUid), s_u: OLD_SALT, profile: { birthYear: '1990', country: 'JP' } });
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await atIdpLogin(popup);
    await popup.fill('#authUid', 'demo-user'); await popup.fill('#authPwd', DEMO_PWD); await popup.fill('#authAuid', oldAuid); await popup.click('#authGo');
    await backAtWallet(popup);
    await waitText(rpPage, '#verdict', '속성 도구 기록의 salt 가 스냅과 다릅니다', 120_000);
    assert.equal((await wallet.get('/wallet/status')).body.registered, false, '등록하지 않았다');
    assert.equal(snapState?.registration, undefined, 'Snap 에도 아무것도 없다');
    await awaitPopupClosed(popup);
  });

  await t('첫 로그인 = 지갑 등록(2026-11-09): 팝업이 MetaMask 를 연결하고 zkID 인증 창(등록 모드, 2026-11-11 부터 auid 칸 있음)으로 갔다가 돌아와 속성 도구 기록의 salt 로 등록 → 발급 → RP 세션; Snap 확인 창 없음', async () => {
    const before = dialogs.length;
    const demoUid = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.id === 'demo-user').uid;
    const demoAuid = (await auidOf({ uid: BigInt(demoUid), s_u: BigInt(USER_SALT) })).toString();
    await walletPage.evaluate((r) => localStorage.setItem('mode3_attr_tool_v1', JSON.stringify(r)), { version: 2, uid: String(demoUid), s_u: USER_SALT, index: 0, profile: { birthYear: '1990', country: 'JP' } });   // 속성 도구가 남기는 기록(필요한 칸만) — 2026-11-11(가): 속성도 여기서
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    assert.ok(popup.url().includes('authorize=1'), `팝업 URL: ${popup.url()}`);
    await atIdpLogin(popup);
    assert.equal(new URL(popup.url()).searchParams.get('purpose'), 'register', '미등록 지갑은 등록 모드로 간다');
    assert.equal(await popup.isVisible('#authAuidRow'), true, '2026-11-11: 등록 모드에도 auid 칸이 있다');
    await waitText(popup, '#authTitle', '스냅 등록');
    await popup.fill('#authUid', 'demo-user'); await popup.fill('#authPwd', DEMO_PWD); await popup.fill('#authAuid', demoAuid); await popup.click('#authGo');
    await backAtWallet(popup);
    assert.equal(await popup.$('#saltAsk'), null, '스냅 팝업에 salt 칸은 없다(2026-11-11)');
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    assert.equal(dialogs.length, before, '등록·로그인에 Snap 확인 창이 없다(2026-11-05 중복 확인 제거)');
    const st = (await wallet.get('/wallet/status')).body;
    assert.equal(st.registered, true, '첫 로그인이 지갑을 등록했다'); assert.match(String(st.uid), /^[0-9]+$/); uid = st.uid; AUID = st.auid;
    assert.equal(snapState.registration?.uid, uid, 'Snap 에도 등록이 저장됐다');
    assert.equal(snapState.registration?.index, 0, '기록의 계정 번호로 등록했다(2026-11-12 스펙 snap-account-index)');
    assert.equal(snapState.nextIndex, 1, '등록을 저장하면 다음 가입 번호가 오른다'); assert.equal(st.index, 0, '에이전트 기록에도 번호');
    assert.equal(snapState.registration?.s_u, USER_SALT, '속성 도구 기록의 salt 가 s_u 로 저장됐다'); assert.deepEqual(st.profile, { birthYear: '1990', country: 'JP' }, '속성 도구 기록의 속성으로 등록됐다(가)'); assert.equal(String(AUID), demoAuid, '붙여 넣은 auid 로 등록됐다');
    assert.ok((await text(rpPage, '#log')).includes('allowAgent=0'), 'AI 에이전트 체크박스를 없앴으므로 늘 0(2026-11-05)');
    await awaitPopupClosed(popup);
    assert.ok((await text(rpPage, '#log')).includes('3. RP 검증'), 'RP 페이지가 /api/mode3/login 까지 냈다');
    assert.ok(await rpPage.evaluate(() => currentSession), '세션이 잡혔다');
    await waitText(walletPage, '#sessionActions', 'zkID · ', 30_000);   // 2026-11-11: 연결된 서비스 줄에 발급 IdP(zkID · 주소)
    // 팝업 결과에는 지갑 안 정보가 실리지 않는다(스펙 §3.2) — 그래도 Snap 에는 새 C_u 가 저장돼 있어야 한다.
    assert.ok(snapState.userCred?.blind_u, '팝업이 userCredIssued 를 Snap 에 저장했다');
    assert.equal((await rp.get('/api/mode3/logins', rp.adminHeaders)).body.logins.length, 1);
    // 목록의 r_s 는 잘라 보여 주는 값이라, 전체 r_s 는 RP 페이지가 들고 있는 것을 그대로 읽는다(전역 스크립트라 이름이 보인다).
    sessionRs = await rpPage.evaluate(() => (typeof currentSession === 'undefined' ? null : currentSession));
    assert.match(String(sessionRs), /^[0-9]+$/, 'RP 페이지가 세션 r_s 를 들고 있다');
  });

  await t('비밀은 Snap 에만: 에이전트 응답·양쪽 페이지 DOM·브라우저 저장소 어디에도 s_u·sk_u·blind_u 가 없다', async () => {
    const secrets = {
      s_u: snapState.registration.s_u,
      sk_u: snapState.registration.sk_u, blind_u: snapState.userCred.blind_u,
    };
    for (const [k, v] of Object.entries(secrets)) assert.ok(typeof v === 'string' && v.length >= 16, `${k} 가 Snap 상태에 있어야 한다: ${v}`);
    // 에이전트가 HTTP 로 내보내는 것(파일은 열지 않는다 — 공개 표면만 본다) + RP 가 기록·노출하는 것
    const surfaces = {
      'wallet/status': j((await wallet.get('/wallet/status')).body),
      'wallet/config': j((await wallet.get('/wallet/config')).body),
      'rp/logins': j((await rp.get('/api/mode3/logins', rp.adminHeaders)).body),
      'rp/sessions': j((await rp.get('/api/mode3/sessions')).body),
      'wallet page': await pageDump(walletPage),
      'rp page': await pageDump(rpPage),
    };
    for (const [where, dump] of Object.entries(surfaces)) {
      for (const [k, v] of Object.entries(secrets)) assert.equal(dump.includes(v), false, `${where} 에 ${k} 가 있다`);
    }
    // 한편 공개 부분(Cf_u)은 에이전트가 정상으로 들고 있어야 한다 — 위 검사가 "아무것도 안 봤다"로 지나가지 않게.
    assert.equal((await wallet.get('/wallet/status')).body.userCred.Cf_u, snapState.userCred.Cf_u);
  });

  // 2026-11-09: salt 를 화면에 보이는 이 케이스는 "비밀은 Snap 에만" 검사(페이지 DOM 에 s_u 가 없어야 한다) 뒤에 둔다 — 등록이 첫 로그인으로 옮겨가 AUID 를 로그인 뒤에야 안다.
  // 2026-11-11(사용자 결정): zk 스냅 화면은 "연결된 서비스" 하나 — 계정·보내기·설정 탭은 없다(속성·salt 는 속성 도구에서 첫 등록 때).
  // 2026-11-12(사용자 요청): "내 계정" 탭이 생겼다 — 스냅이 저장한 값 전부.
  await t('zk 스냅 화면: 제목 "zk 스냅", 탭은 연결된 서비스·내 계정(계정·보내기·설정 없음)', async () => {
    assert.equal(await walletPage.title(), 'zk 스냅');
    const tabs = await walletPage.$$eval('#walletTabs [data-tab]', (bs) => bs.map((b) => b.dataset.tab));
    assert.deepEqual(tabs, ['services', 'me']);
    assert.equal(await walletPage.isHidden('#meCard'), true, '내 계정 카드는 그 탭에서만 보인다');
    assert.equal(await walletPage.isVisible('#sessionsCard'), true);
    for (const id of ['#identityCard', '#txCard', '#snapPanel']) assert.equal(await walletPage.isHidden(id), true, `${id} 는 보이지 않는다`);
  });

  await t('zk 스냅 화면 계정 번호(2026-11-12 스펙 snap-account-index §3.4): "연결된 서비스" 아래 접는 칸에 이 계정 번호·다음 가입 번호, 바꾸기는 스냅 setNextIndex', async () => {
    await walletPage.click('#indexFold > summary');
    await waitText(walletPage, '#meIndex', '0'); await waitText(walletPage, '#meNextIndex', '1');
    await walletPage.fill('#nextIndexInput', '7'); await walletPage.click('#nextIndexBtn');
    await waitText(walletPage, '#meNextIndex', '7'); assert.equal(snapState.nextIndex, 7);
    await walletPage.fill('#nextIndexInput', '-1'); await walletPage.click('#nextIndexBtn');
    await waitText(walletPage, '#indexVerdict', '계정 번호'); assert.equal(snapState.nextIndex, 7, '잘못된 번호는 바꾸지 않는다');
    await walletPage.fill('#nextIndexInput', '1'); await walletPage.click('#nextIndexBtn');
    await waitText(walletPage, '#meNextIndex', '1'); assert.equal(snapState.nextIndex, 1);
    await walletPage.click('#indexFold > summary');
  });

  await t('내 계정: 스냅이 저장한 값 전부(등록·자격증명·동의 기록·다음 가입 번호)가 보인다 — 비밀(s_u·sk_u·blind_u)은 가려 있고 "비밀 값 보기" 로만 열리며, 탭을 떠나면 다시 가린다', async () => {
    const cell = (path) => text(walletPage, storeCell(path));
    await walletTab(walletPage, 'me');
    await waitText(walletPage, storeCell('registration.uid'), uid);
    assert.equal(await walletPage.isHidden('#meStoreEmpty'), true);
    const reg = snapState.registration, uc = snapState.userCred;
    for (const [path, want] of [
      ['registration.uid', reg.uid], ['registration.auid', reg.auid], ['registration.index', String(reg.index)], ['registration.slot', String(reg.slot)], ['registration.registeredAt', reg.registeredAt],
      ['registration.attrs[0]', reg.attrs[0]], ['registration.attrs[5]', reg.attrs[5]],
      ['userCred.C_u_pt.x', uc.C_u_pt.x], ['userCred.C_u_pt.y', uc.C_u_pt.y], ['userCred.Cf_u', uc.Cf_u], ['userCred.issuedAt', uc.issuedAt],
      ['nextIndex', String(snapState.nextIndex)], ['version', '1'],
    ]) assert.equal(await cell(path), want, path);
    const rpOrigin = Object.keys(snapState.consents)[0];
    assert.ok(rpOrigin, '동의 기록이 있다');
    assert.equal(await cell(`consents.${rpOrigin}.grantedAt`), snapState.consents[rpOrigin].grantedAt);
    assert.equal(await cell(`consents.${rpOrigin}.allowAgent`), snapState.consents[rpOrigin].allowAgent);
    // 비밀은 기본 가림 — 칸은 있지만 값은 DOM 어디에도 없다
    const secrets = { 'registration.s_u': reg.s_u, 'registration.sk_u': reg.sk_u, 'userCred.blind_u': uc.blind_u };
    const masked = await pageDump(walletPage);
    for (const [path, v] of Object.entries(secrets)) {
      assert.ok((await cell(path)).length > 0, `${path} 칸이 있다`);
      assert.equal(masked.includes(v), false, `${path} 는 누르기 전에 화면에 없다`);
    }
    await walletPage.click('#meRevealBtn');
    for (const [path, v] of Object.entries(secrets)) assert.equal(await cell(path), v, `${path} 가 열린다`);
    // 탭을 떠났다 돌아오면 다시 가린다
    await walletTab(walletPage, 'services'); await walletTab(walletPage, 'me');
    await waitText(walletPage, storeCell('registration.uid'), uid);
    const again = await pageDump(walletPage);
    for (const [path, v] of Object.entries(secrets)) assert.equal(again.includes(v), false, `탭을 떠났다 오면 ${path} 는 다시 가려진다`);
    await walletTab(walletPage, 'services');
    assert.equal((await pageDump(walletPage)).includes(reg.s_u), false, '탭을 떠난 뒤 화면에 비밀이 남지 않는다');
  });


  // 2026-11-11: zk 스냅 화면의 "보내기" 탭(평범한·공개 트랜잭션)은 없앴다 — 거래는 RP 의 온체인 출금으로만.
  const info = (await rp.get('/api/mode3/rp_info')).body;

  // ---- RP 페이지의 잔액(2026-11-05 B안): KRW 는 RP 장부, ETH 는 세션 계정의 실제 체인 잔액 — 입금(시연) → 구매 → (아래) 온체인 출금 ----
  const balText = (asset) => rpPage.$eval(`.balance-list li[data-asset="${asset}"] .bal-amt`, (e) => e.textContent.trim());
  let sessionAccount = null;
  await t('RP 잔액(B안): 로그인 직후 KRW 0·ETH 0 → "입금(시연)" → "ETH 구매" 하면 KRW 가 깎이고 세션 계정에 실제 ETH 가 들어온다', async () => {
    assert.equal(await rpPage.$('.balance-list li[data-asset="BTC"]'), null, 'BTC 는 잔액 목록에서 뺐다');
    await rpPage.click('#balanceBtn'); await waitText(rpPage, '#ledgerVerdict', '세션 요청 성공', 60_000);
    assert.equal(await balText('KRW'), '0'); assert.equal(await balText('ETH'), '0');
    await rpPage.click('#depositBtn'); await waitText(rpPage, '#ledgerVerdict', '입금 완료', 60_000);
    assert.equal(await balText('KRW'), '1,000,000');
    await rpPage.fill('#buyAmount', '0.05'); await rpPage.click('#buyBtn'); await waitText(rpPage, '#ledgerVerdict', '구매 완료', 120_000);
    assert.equal(await balText('KRW'), '789,500', '1,000,000 − 0.05 × 4,210,000');
    assert.equal(await balText('ETH'), '0.05');
    const buyTx = (await rp.get('/api/mode3/txs', rp.adminHeaders)).body.txs.at(-1);
    assert.equal(buyTx.kind, 'buy'); sessionAccount = buyTx.account;
    assert.equal((await provider.getBalance(sessionAccount)).toString(), '50000000000000000', '세션 계정(CREATE2 주소)에 실제로 0.05 ETH 가 있다');
    // 같은 서명 본문의 재전송은 막힌다(입금·구매 되풀이 방지)
    const sig = (await wallet.post('/wallet/request', { r_s: sessionRs, body: `deposit:${Date.now()}` }, { Origin: rp.origin })).body;
    const body = `deposit:${Date.now()}`;
    const sig2 = (await wallet.post('/wallet/request', { r_s: sessionRs, body }, { Origin: rp.origin })).body.sig;
    assert.equal((await rp.post('/api/mode3/request', { r_s: sessionRs, body, sig: sig2 })).status, 200);
    assert.equal((await rp.post('/api/mode3/request', { r_s: sessionRs, body, sig: sig2 })).body.reason, 'request_replayed');
    assert.ok(sig.sig, '지갑이 서명을 돌려준다');
  });

  // ---- RP 페이지의 "온체인 출금"(2026-11-04): snap 모드도 지갑 팝업(mode3-tx)이 받는다 — Snap 동의 창 → prepare → RP 릴레이 → 영수증 ----
  await t('RP "온체인 출금": 지갑 팝업(mode3-tx) → Snap 동의(RP 오리진·대상·금액) → RP 릴레이 전송 → RP 결과에 txHash, 잔액이 준다', async () => {
    const txsBefore = (await rp.get('/api/mode3/txs', rp.adminHeaders)).body.txs.length;
    assert.equal(await rpPage.inputValue('#txValue'), '0.01', '금액 단위는 ETH(기본 0.01)');
    answers.push(true);                        // consentDisclosure(relay) 확인 — 대상 주소·금액
    const before = dialogs.length;
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#txBtn')]);
    assert.ok(popup.url().includes('authorize=1'), `팝업 URL: ${popup.url()}`);
    await waitText(rpPage, '#txVerdict', '전송 성공', 180_000);
    assert.equal(dialogs.length, before + 1, '동의 대화상자 한 번');
    assert.ok(lastDialog().includes(rp.origin), `동의 창이 RP 오리진을 보여 준다: ${lastDialog().slice(0, 300)}`);
    assert.ok(lastDialog().includes('0x000000000000000000000000000000000000dEaD'), '동의 창이 받는 주소를 보여 준다');
    assert.ok(lastDialog().includes('0.01 ETH'), `동의 창이 금액을 ETH 로 보여 준다: ${lastDialog().slice(0, 400)}`);
    await awaitPopupClosed(popup);
    const rpLog = await text(rpPage, '#txLog');
    assert.match(rpLog, /txHash=0x[0-9a-fA-F]{64}/, `RP 로그에 txHash: ${rpLog}`);
    assert.equal((await rpPage.$eval('#txVerdict', (el) => [...el.querySelectorAll('strong, p')].map((e) => e.textContent).join(' '))).match(/0x[0-9a-fA-F]{10,}/g), null, '결과 카드의 제목·요약에는 해시가 없다(접힌 상세 JSON 제외) — 아래 해시 줄 한 곳에만(2026-11-05)');
    assert.equal(await rpPage.isHidden('#txHashRow'), false);
    const txs = (await rp.get('/api/mode3/txs', rp.adminHeaders)).body.txs;
    assert.equal(txs.length, txsBefore + 1, 'RP 릴레이가 보낸 거래가 RP 거래 기록에 남는다(= 지갑 EOA 가 아니라 릴레이어가 보냈다)');
    assert.equal(txs.at(-1).kind, 'transfer'); assert.equal(txs.at(-1).value, '10000000000000000');
    await rpPage.waitForFunction(() => document.querySelector('.balance-list li[data-asset="ETH"] .bal-amt')?.textContent.trim() === '0.04', undefined, { timeout: 30_000 });
    assert.equal((await provider.getBalance(sessionAccount)).toString(), '40000000000000000', '0.05 − 0.01');
  });

  // ---- 재승인(§4.3): RP 의 "지금 확인"(재검증) 버튼으로 하던 화면 케이스 둘은 2026-11-11 카드 제거와 함께 뺐다 — 팝업 쪽 가드는 아래 위조 요청 케이스가 본다 ----


  // 2026-09-23 점검 B-I1: 재승인의 allowAgent 를 서비스가 정하면 안 된다. 세션은 allowAgent='0'(2026-11-05 부터 체크박스 없음) 인데 요청에 '1' 을
  // 실어 보내도, 팝업은 precheck 이 돌려준 세션 값을 /wallet/session/witness 에 실으므로 성공한다(요청 값을 썼다면 409 allow_agent_mismatch 로 실패한다).
  await t('재승인 allowAgent 바인딩: 요청이 1 이라도 팝업은 세션의 실제 값(0)으로 재승인한다', async () => {
    const before = dialogs.length;
    const { popup, result } = await forgeAuthorize('mode3-authorize-forged-allowagent', {
      ...(await rpRequestBase()), reauth: true, r_s: sessionRs, allowAgent: '1', serviceName: '○○은행',
    });
    assert.equal(result.ok, true, j(result));
    assert.equal(dialogs.length, before, '동의 창 없음');
    await awaitPopupClosed(popup);
  });

  // 리뷰 I-1: 세션 값을 못 받으면(reauth 만 넣고 r_s 를 뺀 요청) precheck 이 r_s 분기를 타지 않아 sessionAllowAgent 가 없다.
  // 그대로 진행하면 정규화가 undefined 를 '0' 으로 만들어 "AI 에이전트 허용: 아니오" 동의 창이 떠 버린다 — 그 전에 멈춰야 한다.
  await t('재승인 가드(지갑): r_s 없는 reauth 요청은 동의 창 없이 no_session 이다', async () => {
    const before = dialogs.length;
    const { popup, result } = await forgeAuthorize('mode3-authorize-forged-nors', {
      ...(await rpRequestBase()), reauth: true, allowAgent: '1', serviceName: '○○은행',
    });
    assert.equal(result.ok, false, j(result));
    assert.equal(result.reason, 'no_session', j(result));
    assert.equal(dialogs.length, before, '동의 창을 띄우지 않는다');
    await awaitPopupClosed(popup);
  });

  // 팝업의 오리진 검사(최종 리뷰 Minor 7) — 지금까지 RP 쪽 필터만 테스트가 있었다.
  await t('팝업 오리진 검사: 메시지 오리진과 요청의 origin 이 다르면 동의 창 없이 origin_mismatch', async () => {
    const before = dialogs.length;
    const { popup, result } = await forgeAuthorize('mode3-authorize-forged-origin', {
      ...(await rpRequestBase()), origin: 'http://evil.example', r_s: '424243', allowAgent: '1', serviceName: '○○은행',
    });
    assert.equal(result.ok, false, j(result));
    assert.equal(result.reason, 'origin_mismatch', j(result));
    assert.equal(dialogs.length, before, '동의 창을 띄우지 않는다');
    await awaitPopupClosed(popup);
  });

  // 최종 리뷰 Important 1: reauth 분기가 precheck 을 건너뛰면 임의 페이지가 자기 오리진·자기가 쓴 서비스 이름으로
  // Snap 로그인 동의 창을 띄울 수 있었다. 오리진은 자기일치(RP 페이지가 보내니 ev.origin === req.origin)지만
  // arid 가 인증서와 맞지 않으므로 precheck 이 403 bad_rp_cert 로 막아야 하고, 동의 창은 뜨지 않아야 한다.
  await t('재승인 위조: 인증서가 맞지 않는 reauth 요청은 precheck 에서 막히고 동의 창이 뜨지 않는다', async () => {
    const before = dialogs.length;
    const { popup, result } = await forgeAuthorize('mode3-authorize-forged-reauth', {
      ...(await rpRequestBase()), arid: '999', reauth: true, r_s: sessionRs, allowAgent: '1', serviceName: '○○은행',
    });
    assert.equal(result.ok, false, j(result));
    assert.equal(result.reason, 'bad_rp_cert', j(result));
    assert.equal(dialogs.length, before, 'precheck 을 통과하기 전에는 Snap 동의 창을 띄우지 않는다');
    await awaitPopupClosed(popup);
  });

  await t('팝업 차단: window.open 이 null 이면 안내만 하고 로그인 버튼이 다시 살아난다', async () => {
    await rpPage.evaluate(() => { window.__realOpen = window.open; window.open = () => null; });
    try {
      await idpLogin(rpPage);
      await waitText(rpPage, '#verdict', '팝업이 차단됐다', 30_000);
      await rpPage.waitForFunction(() => !document.querySelector('#loginBtn').disabled, undefined, { timeout: 10_000 });
    } finally {
      await rpPage.evaluate(() => { window.open = window.__realOpen; });
    }
  });

  await t('RP 오리진·r_s 필터: 다른 창이 보낸 결과와 r_s 가 다른 결과는 무시하고 진짜 결과만 받는다', async () => {
    // 이번 로그인의 r_s 를 가로챈다 — (1) 검사가 "오리진 때문에" 거절됐음을 확인하려면 r_s 는 맞아야 한다.
    let challengeRs = null;
    const onResp = async (resp) => {
      if (!resp.url().endsWith('/api/mode3/challenge')) return;
      try { challengeRs = (await resp.json()).r_s; } catch { /* 본문을 못 읽으면 넘어간다 */ }
    };
    rpPage.on('response', onResp);
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    // 2026-11-05: 동의 창 대신, 팝업이 IdP 로그인 페이지에 머무는 동안(사용자 입력 대기)이 "진짜 결과 전" 순간이다.
    await atIdpLogin(popup);
    assert.ok(challengeRs, '챌린지 r_s 를 가로챘다');
    // (1) r_s 는 맞지만 지갑 오리진이 아닌 창(RP 페이지 자신)이 보낸 결과
    await rpPage.evaluate((rs) => window.postMessage({ type: 'mode3-authorize-result', r_s: rs, result: { ok: false, reason: 'forged_from_rp_origin' } }, '*'), challengeRs);
    // (2) 우리가 연 그 창이지만 지금은 IdP 오리진에 있다 — r_s 가 맞아도 지갑 오리진이 아니라 무시된다.
    await popup.evaluate((rs) => window.opener.postMessage({ type: 'mode3-authorize-result', r_s: rs, result: { ok: false, reason: 'forged_from_idp_origin' } }, '*'), challengeRs);
    await rpPage.waitForTimeout(500);
    assert.equal((await text(rpPage, '#verdict')).includes('forged'), false, `위조 결과가 받아들여졌다: ${await text(rpPage, '#verdict')}`);
    assert.equal((await text(rpPage, '#log')).includes('3. RP 검증'), false, '아직 진짜 결과가 오지 않았다');
    await completeIdpAuth(popup);               // 지갑 /?authorize=1 로 돌아온다 — 증명 생성 몇 초 동안 팝업이 지갑 오리진에 살아 있다
    // (3) 지갑 오리진(팝업)이 보냈지만 r_s 가 다른 결과 — 진짜 결과보다 먼저 보낸다(이미 닫혔으면 건너뛴다).
    await popup.evaluate(() => window.opener.postMessage({ type: 'mode3-authorize-result', r_s: '424242', result: { ok: false, reason: 'forged_wrong_rs' } }, '*')).catch(() => {});
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    assert.equal((await text(rpPage, '#log')).includes('forged'), false);
    assert.equal((await text(rpPage, '#verdict')).includes('forged'), false);
    rpPage.off('response', onResp);
    await awaitPopupClosed(popup);
  });

  // 2026-11-05: 로그인 동의 창은 없어졌다 — 남은 Snap 동의 창은 RP 릴레이 출금(받는 주소·금액)뿐이라 그 거절 경로를 본다.
  await t('동의 거절: RP "온체인 출금" 의 Snap 동의 창에서 거절하면 RP 에 user_denied 가 돌아오고 거래는 보내지 않는다', async () => {
    const before = (await rp.get('/api/mode3/txs', rp.adminHeaders)).body.txs.length;
    answers.push(false);                       // consentDisclosure(relay) 거절
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#txBtn')]);
    await waitText(rpPage, '#txVerdict', '요청을 거절했습니다', 120_000);   // user_denied 제목(코드는 화면에 없다, 2026-11-05)
    await awaitPopupClosed(popup);
    assert.equal((await rp.get('/api/mode3/txs', rp.adminHeaders)).body.txs.length, before, '거절은 거래를 남기지 않는다');
  });
  // V11(D15): 속성은 사용자가 지갑에 넣는다 — 관리자 페이지가 아니라 지갑 페이지의 "속성 저장"(PUT /wallet/profile)이 바꾼다.
  // 바뀌면 에이전트가 옛 C_u·세션을 지우고, 페이지는 응답의 attrsChanged 를 Snap 의 syncAttrs 로 전달해 Snap 도 옛 C_u 를 버린다
  // (Snap 의 syncAttrs 는 changed 면 attrs 와 함께 저장된 C_u 도 지운다). 다음 로그인이 새 C_u 를 받는다.
  // 2026-10-15 W5: extra1(#attr2)은 화면에서 숨긴 예비 슬롯이라 더는 채울 수 없다 — 출생연도(#attr0)로 같은 의도(속성
  // 변경 → 새 C_u)를 보인다.

  // 리뷰 round 1 Minor 7 — 지난 삭제된 테스트가 지키던 "syncAttrs → updateUserCred" 순서 회귀 가드를 다시 둔다.
  // 이번에는 바로 위 테스트(페이지를 거쳐 속성을 바꾼 경우)와 다르게, **에이전트 API 를 페이지 없이 직접 불러**
  // Snap 을 일부러 못 따라오게 만든다 — 그래야 다음 로그인이 자가 치유(attrsChanged + userCredIssued 동시 응답)를
  // 실제로 타고, 팝업의 applyPendingToSnap 이 그 둘을 올바른 순서로 반영하는지(새 C_u 가 살아남는지)를 본다.
  // 2026-11-12(스펙 snap-derived-secrets §4): 같은 SRP 로 MetaMask 를 다시 깔면 스냅이 같은 비밀을 유도한다 — 등록이 돌아오고 PPID 가 같다.
  const ppids = async () => (await rp.get('/api/mode3/logins', rp.adminHeaders)).body.logins.filter((l) => l.PPID).map((l) => l.PPID);
  await t('복구 R1: 스냅 상태만 잃음(MetaMask 재설치) → RP 로그인이 유도 비밀로 스냅 등록을 되살리고 같은 PPID 로 로그인', async () => {
    const before = await ppids(); const known = new Set(before);
    assert.ok(before.length > 0, '앞 케이스의 로그인 기록이 있어야 비교할 수 있다');
    snapState = null;   // MetaMask 재설치 — 확장의 암호화 저장소가 비었다
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await completeIdpAuth(popup);
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    await awaitPopupClosed(popup);
    assert.equal(snapState.registration?.uid, uid, '스냅 등록이 돌아왔다'); assert.equal(snapState.registration?.s_u, USER_SALT);
    assert.equal(snapState.registration?.auid, AUID);
    const after = await ppids();
    assert.equal(after.length, before.length + 1, '로그인 한 번이 더 기록됐다');
    assert.deepEqual(new Set(after), known, '새 PPID 가 생기지 않았다 — 같은 PPID');
  });
  await t('복구 R2: 스냅·에이전트 상태 둘 다 잃음(새 PC) → 등록 모드 인증 창 → IdP 가 같은 비밀 재등록을 복구로 받아 같은 PPID', async () => {
    const before = await ppids(); const known = new Set(before);
    snapState = null;
    assert.equal((await wallet.post('/wallet/reset', { confirm: true })).status, 200);
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await atIdpLogin(popup);
    assert.equal(new URL(popup.url()).searchParams.get('purpose'), 'register', '에이전트가 비어 등록 모드로 간다');
    const loginId = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === String(uid))?.id ?? String(uid);
    await popup.fill('#authUid', loginId); await popup.fill('#authPwd', DEMO_PWD); await popup.fill('#authAuid', String(AUID)); await popup.click('#authGo');
    await backAtWallet(popup);
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    await awaitPopupClosed(popup);
    const st = (await wallet.get('/wallet/status')).body;
    assert.equal(st.registered, true); assert.equal(String(st.uid), String(uid)); assert.equal(st.auid, AUID);
    assert.equal(snapState.registration?.uid, uid); assert.equal(snapState.registration?.s_u, USER_SALT);
    const after = await ppids();
    assert.equal(after.length, before.length + 1); assert.deepEqual(new Set(after), known, '같은 PPID');
  });
  await t('다른 SRP 의 스냅으로는 복구하지 않는다 — 스냅이 비었고 에이전트 등록과 비밀이 다르면 snap_restore_mismatch 로 멈춘다', async () => {
    const saved = snapState;
    snapState = null;
    await context.addInitScript({ content: 'window.__srpOverride = "other-srp";' });   // 이 컨텍스트의 새 페이지부터 — 다른 시드의 MetaMask
    try {
      const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
      await completeIdpAuth(popup);
      await waitText(rpPage, '#verdict', '이 스냅의 비밀이 등록과 다릅니다', 120_000);
      assert.ok((await text(rpPage, '#verdict')).includes('재시연 세트'), '리뷰 I-1: 시드 유도 전 등록은 되찾을 수 없다는 실행 가능한 안내');
      assert.equal((await text(rpPage, '#verdict')).includes('백업의 salt 로만'), false, '되찾을 수 없는 길을 안내하지 않는다');
      await awaitPopupClosed(popup);
      assert.notEqual(snapState?.registration?.uid, uid, '다른 계정 등록을 만들지 않았다');
    } finally {
      await context.addInitScript({ content: 'window.__srpOverride = null;' });   // addInitScript 는 누적된다 — 뒤에 실행되는 이 줄이 되돌린다
      snapState = saved;
    }
  });

  await t('에이전트에서 직접 속성을 바꾸면(Snap 모름) 다음 로그인이 attrsChanged·새 C_u 를 함께 반영한다', async () => {
    const beforeCf = snapState.userCred?.Cf_u ?? null;
    assert.ok(beforeCf, '시작 시 Snap 에 C_u 가 있다');
    const beforeAttrs = [...snapState.registration.attrs];
    const status0 = (await wallet.get('/wallet/status')).body;
    // 2026-10-15 W5: extra2 대신 출생연도를 바꿔 같은 의도(페이지 없이 바로 바꿔 Snap 이 모르게 만든다)를 유지한다.
    const newProfile = { ...status0.profile, birthYear: String(Number(status0.profile.birthYear) + 1) };
    const chg = await wallet.put('/wallet/profile', { profile: newProfile });
    assert.equal(chg.status, 200, j(chg.body));
    assert.equal(chg.body.changed, true, '페이지를 거치지 않은 PUT 도 에이전트 파일의 attrs 를 바꾼다');
    // 2026-11-11: 로그인 팝업은 속성 도구 기록을 기준으로 속성을 맞춘다 — 기록도 같은 값으로 두어야 이 케이스(Snap 만 모르는 상태)가 그대로 남는다.
    await walletPage.evaluate((p) => { const r = JSON.parse(localStorage.getItem('mode3_attr_tool_v1')); localStorage.setItem('mode3_attr_tool_v1', JSON.stringify({ ...r, profile: p })); }, newProfile);
    // Snap 은 이 변경을 전혀 모른다 — syncAttrs 를 부른 적이 없으니 그대로 옛 attrs·C_u 를 들고 있다.
    assert.deepEqual(snapState.registration.attrs, beforeAttrs, 'Snap 은 아직 옛 속성을 들고 있다(일부러 어긋낸 상태)');
    assert.ok(snapState.userCred, 'Snap 은 아직 옛 C_u 도 그대로 들고 있다');
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await completeIdpAuth(popup);               // Task 14: IdP 인증(CIA_ISSUE_AUTH=code)
    await waitText(rpPage, '#verdict', '로그인 성공', 240_000);
    await awaitPopupClosed(popup);
    assert.deepEqual(snapState.registration.attrs, chg.body.attrs, '팝업이 attrsChanged 를 Snap 의 syncAttrs 로 반영해 파일과 같아졌다');
    assert.ok(snapState.userCred, '새 C_u 가 Snap 에 남아 있다(syncAttrs 를 updateUserCred 보다 나중에 하면 지워진다)');
    assert.notEqual(snapState.userCred.Cf_u, beforeCf, '옛 C_u 가 아니라 새로 받은 것이다');
    assert.equal((await wallet.get('/wallet/status')).body.userCred.Cf_u, snapState.userCred.Cf_u, '에이전트의 공개 Cf_u 와 같다');
  });

  // 2026-11-11(사용자 보고: 속성 도구에서 바꿔도 반영되지 않았다): 로그인 팝업이 속성 도구 기록의 속성을 에이전트·Snap 에 먼저 맞추고 새 C_u 를 받는다.
  await t('속성 도구 기록의 salt 가 등록과 다르면 속성을 맞추지 않고 멈춘다(attr_record_salt_mismatch) — 에이전트 속성은 그대로', async () => {
    const status0 = (await wallet.get('/wallet/status')).body;
    const rec = JSON.parse(await walletPage.evaluate(() => localStorage.getItem('mode3_attr_tool_v1')));
    await walletPage.evaluate((r) => localStorage.setItem('mode3_attr_tool_v1', JSON.stringify(r)), { ...rec, s_u: '12345', profile: { ...status0.profile, country: 'US' } });
    try {
      const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
      await completeIdpAuth(popup);
      await waitText(rpPage, '#verdict', '속성 도구 기록의 salt 가 등록과 다릅니다', 120_000);
      await awaitPopupClosed(popup);
      assert.deepEqual((await wallet.get('/wallet/status')).body.profile, status0.profile, '에이전트 속성은 바뀌지 않았다');
    } finally { await walletPage.evaluate((r) => localStorage.setItem('mode3_attr_tool_v1', JSON.stringify(r)), rec); }
  });

  await t('속성 도구에서 속성을 바꾸면 다음 로그인 팝업이 에이전트·Snap 속성을 기록 값으로 맞추고 새 C_u 를 받는다', async () => {
    const beforeCf = snapState.userCred?.Cf_u ?? null;
    assert.ok(beforeCf, '시작 시 Snap 에 C_u 가 있다');
    const status0 = (await wallet.get('/wallet/status')).body;
    const newProfile = { ...status0.profile, country: status0.profile.country === 'KR' ? 'JP' : 'KR' };
    await walletPage.evaluate((p) => { const r = JSON.parse(localStorage.getItem('mode3_attr_tool_v1')); localStorage.setItem('mode3_attr_tool_v1', JSON.stringify({ ...r, profile: p })); }, newProfile);
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await completeIdpAuth(popup);
    await waitText(rpPage, '#verdict', '로그인 성공', 240_000);
    await awaitPopupClosed(popup);
    const st = (await wallet.get('/wallet/status')).body;
    assert.deepEqual(st.profile, newProfile, '에이전트 속성이 속성 도구 기록 값이 됐다');
    assert.deepEqual(snapState.registration.attrs, st.attrs, 'Snap 속성도 같다');
    assert.ok(snapState.userCred, '새 C_u 가 Snap 에 있다');
    assert.notEqual(snapState.userCred.Cf_u, beforeCf, '옛 C_u 가 아니라 새 속성으로 받은 것이다');
  });

  await t('폐기 상한(2026-10-22): 세션 카드에 nonce, 폐기 때 허용 수 입력(Snap 동의 창 없음) → 체인 반영 대기 행 → 재로그인 뒤 "지금 반영" → 행 사라짐', async () => {
    await walletTab(walletPage, 'services');
    await walletPage.waitForFunction(() => /nonce\s*\d+/.test(document.querySelector('#sessionActions')?.textContent ?? ''), undefined, { timeout: 15_000 });
    await walletPage.fill('#sessionActions input.bound', '1');
    const dBefore = dialogs.length;                                       // 2026-11-05: Snap 의 consentRevokeSession 동의 창은 없다 — 페이지의 confirm 만
    walletPage.once('dialog', (d) => d.accept());                         // confirm_revoke
    await walletPage.click('#sessionActions button.danger');
    await waitText(walletPage, '#sessionVerdict', '폐기 요청 접수');
    assert.equal(dialogs.length, dBefore, '세션 폐기에 Snap 동의 창이 없다');
    await waitText(walletPage, '#boundsList', '반영 대기', 10_000);
    // 다시 로그인(같은 RP) → IdP 인증 창(Task 14, CIA_ISSUE_AUTH=code) → 지금 반영 → MetaMask 스텁이 보낸다 → 행 사라짐
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await completeIdpAuth(popup);
    await popup.waitForEvent('close');
    // F-14 Z(2026-10-23): snap 모드 "지금 반영"은 record 요청에 pendingBoundId 를 실어야 하고, 응답은 applied:true 여야
    // 행이 사라져야 한다(2xx 만으로는 부족하다 — boundApplyVerdict 가 실제 온체인 상한을 다시 읽어 판정한다).
    const recordResp = walletPage.waitForResponse(async (r) => {
      if (!r.url().endsWith('/wallet/tx/record') || r.request().method() !== 'POST') return false;
      return r.status() !== 202;                                    // 202 pending 은 최종 응답이 아니다 — 계속 기다린다
    });
    await walletPage.click('#boundsList button.apply');
    const recordRes = await recordResp;
    const recordReqBody = JSON.parse(recordRes.request().postData() ?? '{}');
    const recordResBody = await recordRes.json();
    assert.ok(typeof recordReqBody.pendingBoundId === 'string' && recordReqBody.pendingBoundId.length > 0, `record 요청에 pendingBoundId 가 있어야 한다: ${j(recordReqBody)}`);
    assert.equal(recordResBody.applied, true, `record 응답이 applied:true 여야 한다: ${j(recordResBody)}`);
    await walletPage.waitForFunction(() => !/반영 대기/.test(document.querySelector('#boundsList')?.textContent ?? ''), undefined, { timeout: 60_000 });
  });

  // 2026-11-12 시연 Race (2): RP 출금 카드의 "보내기 전에 멈춤" → 팝업이 증명·서명 뒤 멈춘다 → "N블록 뒤 보내기" 가 그 세션을 폐기하고
  // 블록을 N 개 진행한 뒤 보낸다. IdP 는 폐기 뒤 3블록에 게시·중계하므로(CIA_REVOKE_PUBLISH_AFTER_BLOCKS=3) 2블록은 통과, 5블록은 SessionBounded.
  const reloginRp = async () => {
    const [p] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await completeIdpAuth(p);
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    await awaitPopupClosed(p);
  };
  const raceSend = async (btn) => {
    await rpPage.fill('#txValue', '0');
    if (!(await rpPage.isChecked('#raceHold', { timeout: 5000 }))) await rpPage.check('#raceHold', { timeout: 5000 });
    answers.push(true);                        // consentDisclosure(relay) 확인
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#txBtn')]);
    await popup.waitForSelector(btn, { state: 'visible', timeout: 180_000 });
    assert.equal((await text(rpPage, '#txVerdict')).includes('영지식'), false, 'RP 는 기다리는 동안 "영지식 증명 생성 중" 을 띄우지 않는다');
    await popup.click(btn);
    return popup;
  };
  await t('시연 Race (2) 2블록: 멈춘 출금을 "2블록 뒤 보내기" → 세션 폐기 → 2블록 뒤 전송 → 거울 반영 전이라 통과', async () => {
    assert.equal(await rpPage.isVisible('#raceHold'), true, '시연 체크박스는 평소 화면에 보인다');
    await rpPage.click('#raceToggleBtn', { timeout: 5000 }); assert.equal(await rpPage.isVisible('#raceHold'), false, '숨기기');
    await rpPage.click('#raceToggleBtn', { timeout: 5000 }); assert.equal(await rpPage.isVisible('#raceHold'), true, '다시 보이기');
    const popup = await raceSend('#race2Btn');
    await waitText(rpPage, '#txVerdict', '거울 반영 전이라 통과했습니다', 120_000);
    await awaitPopupClosed(popup);
  });
  await t('시연 Race (2) 5블록: 같은 순서를 "5블록 뒤 보내기" 로 하면 거울이 상한을 받은 뒤라 session_bounded 로 막힌다', async () => {
    await reloginRp();
    const popup = await raceSend('#race5Btn');
    await waitText(rpPage, '#txVerdict', '폐기된 세션의 거래가 막혔습니다', 120_000);
    assert.match(await text(rpPage, '#txVerdict'), /SessionBounded/, '자세히의 detail 에 컨트랙트 오류 이름');
    await awaitPopupClosed(popup);
    await rpPage.uncheck('#raceHold', { timeout: 5000 });
    await reloginRp();   // 뒤 케이스를 위해 살아 있는 세션으로 돌려 둔다
  });

  // 2026-09-23 최종 리뷰 M3: 검증기가 없는 동안 /challenge 는 503 { ok:false, reason } 이다. 예전 페이지는 본문을 바로
  // 구조분해해 r_s.slice 에서 죽었고, 화면에는 "Cannot read properties of undefined" 만 남아 사유가 묻혔다.
  await t('챌린지 503: 페이지가 사유(factory_constants_unavailable)를 보여 주고 멈춘다 — TypeError 가 아니다', async () => {
    const before = dialogs.length;
    await rpPage.route('**/api/mode3/challenge', (route) => route.fulfill({
      status: 503, contentType: 'application/json', body: j({ ok: false, reason: 'factory_constants_unavailable' }),
    }));
    try {
      await idpLogin(rpPage);
      await waitText(rpPage, '#verdict', 'RP 가 체인 설정을 읽지 못했습니다', 30_000);   // factory_constants_unavailable 제목
      assert.equal((await text(rpPage, '#verdict')).includes('Cannot read'), false, `TypeError 가 아니라 사유가 보여야 한다: ${await text(rpPage, '#verdict')}`);
      await rpPage.waitForFunction(() => !document.querySelector('#loginBtn').disabled, undefined, { timeout: 10_000 });
      assert.equal(dialogs.length, before, '챌린지 단계에서 멈추므로 지갑 팝업·동의 창까지 가지 않는다');
    } finally {
      await rpPage.unroute('**/api/mode3/challenge');
    }
  });

  // ---- Task 12(B3, 2026-10-22): IdP 사용자·RP·인증 창 페이지(/user·/rp·/login) ----
  // 가입·로그인·RP 만들기는 Snap 대화상자를 쓰지 않는다 — 새 계정(가입으로 받은 uid·새 운영자 id)을 쓴다.
  await t('IdP 사용자 페이지(2026-11-03): 계정 만들기(아이디·비밀번호·확인, 불일치는 pwd_mismatch, 중복 아이디는 id_taken) → 가입 직후 자동 로그인(2026-11-06) → 로그아웃 → 아이디로 로그인 → 로그아웃하면 로그인 화면', async () => {
    const p = await context.newPage(); await p.goto(`${cia.base}/user`);
    // 같은 브라우저 컨텍스트라 앞의 등록 케이스가 로그인해 둔 세션 쿠키가 남아 있을 수 있다 — 내 계정 화면이면 먼저 로그아웃한다.
    await p.waitForSelector('#loginView:not([hidden]), #meCard:not([hidden])');
    if (await p.isVisible('#meCard')) { await p.click('#logoutBtn'); await p.waitForSelector('#loginView:not([hidden])'); }
    assert.equal(await p.$('#registerCard'), null, '지갑 등록 카드는 없다(2026-11-09)'); assert.equal(await p.isHidden('#revokeCard'), true);
    await p.click('#showSignupBtn'); await p.waitForSelector('#signupView:not([hidden])');
    await p.fill('#signupId', 'demo-user-2'); await p.fill('#signupPwd', 'demo-pass-1'); await p.fill('#signupPwd2', 'demo-pass-X'); await p.click('#signupBtn');
    await waitText(p, '#signupVerdict', '비밀번호 확인이 일치하지 않습니다');   // pwd_mismatch 제목
    await p.fill('#signupPwd2', 'demo-pass-1'); await p.click('#signupBtn');
    // 2026-11-06(8차): 가입 직후 자동 로그인 — 등록 카드에 안내가 뜨고 상태는 등록 전. 로그인 화면으로 돌아가지 않는다.
    await waitText(p, '#profileVerdict', '가입했습니다'); await waitText(p, '#meInfo', 'demo-user-2');
    assert.equal(await p.isHidden('#loginView'), true);
    await p.click('#logoutBtn'); await p.waitForSelector('#loginView:not([hidden])');
    // 같은 아이디(대소문자만 다른)로 다시 가입하면 409 id_taken.
    await p.click('#showSignupBtn'); await p.fill('#signupId', 'DEMO-USER-2'); await p.fill('#signupPwd', 'demo-pass-1'); await p.fill('#signupPwd2', 'demo-pass-1'); await p.click('#signupBtn');
    await waitText(p, '#signupVerdict', '그 아이디는 이미 쓰고 있습니다'); await p.click('#showLoginBtn');   // id_taken 제목
    await p.fill('#loginId', 'demo-user-2'); await p.fill('#loginPwd', 'wrong-pass-1'); await p.click('#loginBtn'); await waitText(p, '#userVerdict', '아이디 또는 비밀번호가 맞지 않습니다');   // invalid_credentials 제목
    await p.fill('#loginPwd', 'demo-pass-1'); await p.click('#loginBtn');
    await waitText(p, '#meInfo', 'demo-user-2'); assert.equal(await p.isVisible('#profileCard'), true);
    await p.click('#logoutBtn'); await p.waitForSelector('#loginView:not([hidden])'); assert.equal(await p.isHidden('#meCard'), true); await p.close();
  });
  // 2026-11-09 Phase 1: 속성 커밋먼트 도구(지갑 오리진 /attr.html — 독립 정적 페이지) + zkID 프로필 카드.
  let toolCommit = null;
  await t('속성 도구(/attr.html): 정적 자원과 스냅 설정(/wallet/config) 말고는 요청 없이 커밋먼트를 만들고, localStorage 의 attrs·blind 로 Node 가 다시 계산한 값과 같다; 지우기·백업 불러오기', async () => {
    const p = await context.newPage();
    const reqs = []; p.on('request', (r) => reqs.push(r.url()));
    await p.goto(`${wallet.base}/attr.html`);
    await p.waitForSelector('#noCommit:not([hidden])');
    // 2026-11-10(B+b1): uid·salt 를 묶는다 — 비우면 만들지 않는다(required).
    // 2026-11-12(스펙 snap-derived-secrets S2): salt 는 직접 넣지 않는다 — "스냅에서 가져오기" 가 시드 유도 salt 를 채운다.
    assert.equal(await p.$('#saltGenBtn'), null, '"salt 새로 뽑기" 는 없다');
    assert.equal(await p.getAttribute('#salt', 'readonly'), '', 'salt 칸은 읽기 전용');
    await p.fill('#uid', String(uid)); await p.click('#saltFromSnapBtn');
    await p.waitForFunction(() => document.getElementById('salt').value !== '');
    assert.equal(await p.inputValue('#salt'), USER_SALT, '스냅이 유도한 salt(지갑 등록 때와 같은 값)');
    assert.equal(await p.inputValue('#acctIndex'), '0', '번호 칸이 비어 있으면 스냅 기본 — 등록된 계정의 번호(Ruling P1)');
    await p.fill('#birthYear', '1990'); await p.selectOption('#country', 'KR'); await p.fill('#extra1', 'hello');
    await p.click('#makeBtn');
    await p.waitForSelector('#commitBox:not([hidden])');
    await waitText(p, '#formVerdict', '커밋먼트 생성 완료');
    const shown = (await p.textContent('#commitBox')).trim();
    const rec = JSON.parse(await p.evaluate(() => localStorage.getItem('mode3_attr_tool_v1')));
    assert.equal(rec.commit, shown); assert.match(shown, /^[0-9]+$/);
    const attrs = await encodeProfile(DEFAULT_ATTR_SCHEMA, { birthYear: '1990', country: 'KR', extra1: 'hello' });
    assert.deepEqual(rec.attrs, attrs);
    assert.equal(rec.version, 2); assert.equal(rec.uid, String(uid)); assert.equal(rec.s_u, USER_SALT);
    assert.equal(rec.index, 0, '기록에 계정 번호');
    assert.equal(await attrCommit({ uid: rec.uid, s_u: rec.s_u, attrs, blind: rec.blind }), rec.commit, 'Node 재계산과 일치');
    // 재료를 모두 숨기지 않고 보인다 — uid·salt·blind·인코딩 값
    assert.equal((await p.textContent('#uidShown')).trim(), rec.uid); assert.equal((await p.textContent('#saltShown')).trim(), USER_SALT);
    assert.equal((await p.textContent('#blindShown')).trim(), rec.blind);
    // 2026-11-11: 같은 uid·salt 로 계산한 auid 도 보인다 — 첫 RP 로그인 인증 창에 붙여 넣는 값
    assert.equal((await p.textContent('#auidShown')).trim(), (await auidOf({ uid: BigInt(rec.uid), s_u: BigInt(rec.s_u) })).toString());
    for (let i = 0; i < 4; i++) assert.ok((await p.textContent(`#attrShown${i}`)).includes(rec.attrs[i]), `attr${i} 인코딩 값 표시`);
    // 2026-11-11(사용자 결정): 입력할 수 없는 미사용 슬롯(attr₄·attr₅, 늘 0)은 보이지 않는다 — 해시에는 그대로 0 이 들어간다
    assert.equal(await p.locator('#attrShown4, #attrShown5').count(), 0, '미사용 슬롯 행 없음');
    assert.ok((await p.textContent('#attrShown0')).includes('1990'), '입력값도 함께');
    assert.deepEqual(rec.profile, { birthYear: '1990', country: 'KR', extra1: 'hello' });
    const okReq = (u) => /\/attr\.html|\/attr\/dist\/|\/common\/|\/wallet\/config$/.test(u);   // 2026-11-12: 가져오기가 snapId 를 읽는다
    assert.ok(reqs.every(okReq), `정적 자원 외 요청: ${reqs.filter((u) => !okReq(u)).join(', ')}`);
    // 범위 밖 값(출생연도 1800 < min 1900)은 인코더가 거절한다 — 저장값은 그대로(빈 칸은 폼의 required 가 먼저 막아 요청 자체가 없다)
    await p.fill('#birthYear', '1800'); await p.click('#makeBtn'); await waitText(p, '#formVerdict', '커밋먼트를 만들지 못했습니다');
    assert.equal(JSON.parse(await p.evaluate(() => localStorage.getItem('mode3_attr_tool_v1'))).commit, rec.commit);
    // 지우기(confirm 수락) → 없음; 백업 불러오기 → 같은 커밋먼트 복원
    p.once('dialog', (d) => d.accept());
    await p.click('#clearBtn'); await p.waitForSelector('#noCommit:not([hidden])');
    assert.equal(await p.evaluate(() => localStorage.getItem('mode3_attr_tool_v1')), null);
    for (const id of ['#uid', '#salt', '#acctIndex']) assert.equal(await p.inputValue(id), '', `지우기는 ${id} 칸도 비운다(최종 리뷰 I-1 — 다음 계정이 앞 계정 값으로 만들지 않게)`);
    await p.setInputFiles('#importFile', { name: 'backup.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(rec)) });
    await waitText(p, '#resultVerdict', '백업 불러오기 완료');
    assert.equal((await p.textContent('#commitBox')).trim(), rec.commit);
    // 옛 형식(version 1, uid·salt 없음) 백업은 거절하고, 저장소에 옛 기록이 있으면 "다시 만드세요" 를 보인다.
    const { uid: _u, s_u: _s, ...v1 } = rec;
    await p.setInputFiles('#importFile', { name: 'v1.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ ...v1, version: 1 })) });
    await waitText(p, '#resultVerdict', '백업을 불러오지 못했습니다');
    const broken = { ...rec, commit: '1' };
    await p.setInputFiles('#importFile', { name: 'bad.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(broken)) });
    await waitText(p, '#resultVerdict', '백업을 불러오지 못했습니다');
    toolCommit = rec.commit;
    // 2026-11-11: 데모 리셋(scripts/demo_split_start.sh 가 /attr/dist/reset.json 에 리셋 시각을 쓴다) — 도구가 처음 보는 값이면 이 브라우저의 기록을 비운다.
    await p.setInputFiles('#importFile', { name: 'backup.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(rec)) });
    await waitText(p, '#resultVerdict', '백업 불러오기 완료');
    const resetFile = new URL('../mode3/attr/dist/reset.json', import.meta.url);
    fs.writeFileSync(resetFile, JSON.stringify({ epoch: 'test-reset-1' }));
    try {
      await p.reload(); await p.waitForSelector('#resetCleared:not([hidden])', { timeout: 15_000 });
      assert.equal(await p.evaluate(() => localStorage.getItem('mode3_attr_tool_v1')), null, '리셋 뒤 기록이 비었다');
      assert.equal(await p.isVisible('#noCommit'), true);
      await p.reload(); await p.waitForTimeout(500);
      assert.equal(await p.isHidden('#resetCleared'), true, '같은 리셋 값이면 다시 비우지 않는다(안내도 없다)');
    } finally { fs.rmSync(resetFile, { force: true }); }
    await p.close();
  });
  // 2026-11-11(사용자 결정, 스펙 D20): 자동 암호화 백업 — 백업 비밀번호와 한 번 고른 파일. 기록이 바뀔 때마다 그 파일을 암호문으로 덮어쓴다(평문 내려받기는 없다).
  await t('속성 도구 계정 번호: 번호를 바꾸면 salt 칸이 비고, 1번으로 가져오면 다른 salt(같은 시드라도) — 0번으로 되돌리면 등록 salt', async () => {
    const p = await context.newPage(); await p.goto(`${wallet.base}/attr.html`);
    try {
      await p.fill('#acctIndex', '1');
      assert.equal(await p.inputValue('#salt'), '', '번호를 바꾸면 salt 를 다시 가져와야 한다');
      await p.click('#saltFromSnapBtn'); await p.waitForFunction(() => document.getElementById('salt').value !== '');
      assert.equal(await p.inputValue('#salt'), derivedSecrets(STUB_SRP, 1).s_u); assert.notEqual(await p.inputValue('#salt'), USER_SALT);
      await p.fill('#acctIndex', '0'); await p.click('#saltFromSnapBtn');
      await p.waitForFunction((v) => document.getElementById('salt').value === v, USER_SALT);
    } finally { await p.close(); }
  });
  await t('속성 도구 자동 백업: 비밀번호·파일을 한 번 정하면 기록을 만들 때마다 그 파일을 암호문으로 덮어쓴다(평문 없음)·새로고침 뒤에도 이어진다·내려받기도 암호문; 불러오기는 틀린 비밀번호면 실패, 맞으면 복원', async () => {
    const PW = 'backup-pw-1234';
    const p = await context.newPage();
    // 파일 선택 창 대신 브라우저 내부 파일(OPFS)의 실제 파일 핸들 — 진짜 핸들이라 IndexedDB 에 그대로 저장된다
    await p.addInitScript(() => { window.showSaveFilePicker = async () => (await navigator.storage.getDirectory()).getFileHandle('zkd-attr-backup.json', { create: true }); });
    const readBackup = async () => JSON.parse(await p.evaluate(async () => (await (await (await navigator.storage.getDirectory()).getFileHandle('zkd-attr-backup.json')).getFile()).text()));
    const make = async (birthYear) => {
      await p.fill('#uid', String(uid)); await p.click('#saltFromSnapBtn'); await p.waitForFunction(() => document.getElementById('salt').value !== ''); await p.fill('#birthYear', birthYear); await p.selectOption('#country', 'KR');
      await p.click('#makeBtn'); await waitText(p, '#formVerdict', '커밋먼트 생성 완료');
    };
    const record = async () => JSON.parse(await p.evaluate(() => localStorage.getItem('mode3_attr_tool_v1')));
    await p.goto(`${wallet.base}/attr.html`);
    await make('1990');
    assert.match(await text(p, '#backupStatus'), /꺼짐/, '설정 전에는 꺼짐');
    await p.fill('#backupPw', 'short'); await p.fill('#backupPw2', 'short'); await p.click('#backupSetupBtn');
    await waitText(p, '#backupVerdict', '8자');
    await p.fill('#backupPw', PW); await p.fill('#backupPw2', `${PW}x`); await p.click('#backupSetupBtn');
    await waitText(p, '#backupVerdict', '일치하지');
    await p.fill('#backupPw', PW); await p.fill('#backupPw2', PW); await p.click('#backupSetupBtn');
    await waitText(p, '#backupStatus', '마지막 백업', 60_000);
    assert.equal(await p.inputValue('#backupPw'), '', '비밀번호 칸은 비운다');
    const rec1 = await record();
    const b1 = await readBackup();
    assert.equal(isSealedBackup(b1), true, '봉인 백업 형식');
    const raw1 = JSON.stringify(b1);
    for (const v of [USER_SALT, rec1.blind, rec1.commit, 'birthYear', 's_u']) assert.equal(raw1.includes(v), false, `백업 파일에 평문 ${v.slice(0, 12)} 가 없다`);
    assert.deepEqual(await openBackup(PW, b1), rec1, '비밀번호로 풀면 기록과 같다');
    // 새로고침 뒤 기록을 다시 만들면 자동으로 덮어쓴다(핸들·키는 IndexedDB)
    await p.reload(); await make('1991');
    const rec2 = await record();
    let b2 = b1;
    for (let i = 0; i < 120 && b2.savedAt === b1.savedAt; i++) { await new Promise((r) => setTimeout(r, 250)); b2 = await readBackup(); }
    assert.equal((await openBackup(PW, b2)).commit, rec2.commit, '새 기록으로 덮어썼다');
    // 내려받기도 암호문
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#exportBtn')]);
    assert.equal(isSealedBackup(JSON.parse(fs.readFileSync(await dl.path(), 'utf8'))), true, '내려받기도 암호화 백업');
    // 불러오기: 지우기 → 틀린 비밀번호는 실패 → 맞는 비밀번호는 복원
    p.once('dialog', (d) => d.accept()); await p.click('#clearBtn'); await p.waitForSelector('#noCommit:not([hidden])');
    const file = { name: 'zkd-attr-backup.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(b2)) };
    p.once('dialog', (d) => d.accept('wrong-password')); await p.setInputFiles('#importFile', file);
    await waitText(p, '#resultVerdict', '백업을 불러오지 못했습니다');
    assert.equal(await p.evaluate(() => localStorage.getItem('mode3_attr_tool_v1')), null, '틀린 비밀번호로는 아무것도 들어오지 않는다');
    p.once('dialog', (d) => d.accept(PW)); await p.setInputFiles('#importFile', file);
    await waitText(p, '#resultVerdict', '백업 불러오기 완료');
    assert.equal((await p.textContent('#commitBox')).trim(), rec2.commit);
    await p.close();
  });

  await t('속성 도구: MetaMask 가 없으면 salt 를 못 가져오고 사유를 보이며 salt 칸을 바꾸지 않는다; 옛 기록의 salt 가 스냅 salt 와 다르면 경고', async () => {
    const p = await context.newPage();
    await p.addInitScript(() => { delete window.ethereum; });
    await p.goto(`${wallet.base}/attr.html`);
    const shownBefore = await p.inputValue('#salt');   // 앞 케이스의 기록이 있으면 그 salt 가 보인다(기록 표시) — 가져오기 실패는 이 값을 바꾸지 않는다
    await p.fill('#uid', String(uid)); await p.click('#saltFromSnapBtn');
    await waitText(p, '#formVerdict', 'MetaMask');
    assert.equal(await p.inputValue('#salt'), shownBefore, '가져오기에 실패하면 salt 칸을 바꾸지 않는다');
    await p.close();
    const q = await context.newPage();
    await q.goto(`${wallet.base}/attr.html`);
    const orig = await q.evaluate(() => localStorage.getItem('mode3_attr_tool_v1'));
    assert.ok(orig, '앞 케이스가 남긴 기록이 있어야 한다');
    try {
      await q.evaluate((r) => localStorage.setItem('mode3_attr_tool_v1', r), JSON.stringify({ ...JSON.parse(orig), s_u: '987654321' }));
      await q.reload();
      assert.equal(await q.isHidden('#saltWarn'), true, '가져오기 전에는 경고가 없다(MetaMask 를 스스로 부르지 않는다)');
      await q.click('#saltFromSnapBtn');
      await q.waitForSelector('#saltWarn:not([hidden])');
      assert.ok((await q.textContent('#saltWarn')).includes('시드로 복구할 수 없는'));
    } finally { await q.evaluate((r) => localStorage.setItem('mode3_attr_tool_v1', r), orig); await q.close(); }
  });

  await t('리뷰 M-3(2026-11-12): 옛 스냅(0.1.0, getSalt 없음)이면 속성 도구가 "스냅이 옛 버전" 으로 안내한다(snap_outdated)', async () => {
    const p = await context.newPage();
    await p.addInitScript(() => { window.__snapOutdated = true; });
    await p.goto(`${wallet.base}/attr.html`);
    const before = await p.inputValue('#salt');
    await p.click('#saltFromSnapBtn');
    await waitText(p, '#formVerdict', '스냅이 옛 버전입니다');
    assert.equal(await p.inputValue('#salt'), before);
    await p.close();
  });

  await t('zkID 사용자 페이지 프로필 카드: 로그인만 하면 보인다(지갑 등록과 무관) → 커밋먼트 저장 → 현재 값 표시 → /me.profile; 비우면 없음', async () => {
    const p = await context.newPage(); await p.goto(`${cia.base}/user`);
    await p.waitForSelector('#loginView:not([hidden]), #meCard:not([hidden])');
    if (await p.isVisible('#meCard')) { await p.click('#logoutBtn'); await p.waitForSelector('#loginView:not([hidden])'); }
    assert.equal(await p.isHidden('#profileCard'), true, '로그인 전엔 숨김');
    await p.fill('#loginId', 'demo-user-2'); await p.fill('#loginPwd', 'demo-pass-1'); await p.click('#loginBtn');   // 앞 케이스가 만든 미등록 계정
    await waitText(p, '#meInfo', 'demo-user-2');
    await p.waitForSelector('#profileCard:not([hidden])');
    assert.equal((await p.textContent('#profileCurrent')).trim(), '없음');
    assert.ok((await p.getAttribute('#attrToolLink', 'href')).endsWith('/attr.html'), '속성 도구 링크는 지갑 오리진 /attr.html');
    await p.fill('#profileName', toolCommit); await p.click('#profileSaveBtn');
    await waitText(p, '#profileVerdict', '프로필 저장 완료');
    assert.equal((await p.textContent('#profileCurrent')).trim(), toolCommit);
    const me = await p.evaluate(() => fetch('/cia/user/me', { credentials: 'same-origin' }).then((r) => r.json()));
    assert.equal(me.profile?.name, toolCommit);
    // 2026-11-10: "내 계정" 하위 메뉴 "내 정보"(/user/info) — 저장한 커밋먼트·저장 시각·지갑 등록 여부를 읽기 전용으로 보인다.
    await p.click('.sub-nav a[href="/user/info"]'); await p.waitForSelector('#infoView:not([hidden])');
    assert.equal(await p.getAttribute('.sub-nav a[href="/user/info"]', 'aria-current'), 'page');
    assert.equal((await p.textContent('#infoId')).trim(), 'demo-user-2');
    assert.equal((await p.textContent('#infoUid')).trim(), String(me.uid), 'uid 를 보인다(2026-11-10 — 속성 커밋먼트 도구에 넣는 값)');
    assert.equal((await p.textContent('#infoMethod')).trim(), '아이디·비밀번호');
    assert.match(await p.textContent('#infoWallet'), /아직 없음/, '미등록 계정');
    // 2026-11-11: auid·슬롯 — 지갑 등록 전에는 auid 가 없고 복사 버튼도 숨는다
    assert.equal((await p.textContent('#infoAuid')).trim(), '아직 없음(스냅 등록 전)'); assert.equal(await p.isHidden('#copyAuidBtn'), true);
    assert.equal((await p.textContent('#infoSlot')).trim(), '-');
    assert.equal((await p.textContent('#infoAttr')).trim(), toolCommit);
    assert.match((await p.textContent('#infoAttrAt')).trim(), /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/);
    assert.equal(await p.getAttribute('#infoAttrAt', 'title'), me.profile.updatedAt, '원본 시각은 title 에');
    await p.click('.sub-nav a[href="/user"]'); await p.waitForSelector('#profileCard:not([hidden])');
    await p.fill('#profileName', ''); await p.click('#profileSaveBtn'); await waitText(p, '#profileVerdict', '프로필을 비웠습니다');   // 제목은 앞 저장과 같아 요약으로 기다린다
    assert.equal((await p.textContent('#profileCurrent')).trim(), '없음');
    await p.goto(`${cia.base}/user/info`); await p.waitForSelector('#infoView:not([hidden])');
    assert.equal((await p.textContent('#infoAttr')).trim(), '저장된 값 없음'); assert.equal((await p.textContent('#infoAttrAt')).trim(), '-');
    await p.goto(`${cia.base}/user`); await p.waitForSelector('#meCard:not([hidden])');
    await p.click('#logoutBtn'); await p.waitForSelector('#loginView:not([hidden])');
    await p.goto(`${cia.base}/user/info`); await p.waitForSelector('#loginNeeded:not([hidden])');   // 로그아웃 상태에서는 로그인 안내만
    assert.equal(await p.isHidden('#infoView'), true); await p.close();
  });
  await t('IdP RP 페이지: 운영자 가입·로그인 → zkTHREE 만들기 → 키·명령 표시', async () => {
    const p = await context.newPage(); await p.goto(`${cia.base}/rp`);
    // 2026-11-03: /rp 도 /user 처럼 로그인 화면 → "운영자 계정 만들기"(아이디·비밀번호·확인) → 로그인 화면으로 돌아와 비밀번호 → 로그인 뒤에만 RP 만들기.
    await p.waitForSelector('#opLoginView:not([hidden])');   // 초기 /cia/rp/me 조회가 끝나 로그인 화면이 선 뒤에 누른다(간헐 실패 2026-11-06·09)
    await p.click('#showOpSignupBtn'); await p.waitForSelector('#opSignupView:not([hidden])');
    await p.fill('#opSignupId', 'op1'); await p.fill('#opSignupPwd', 'operator-1'); await p.fill('#opSignupPwd2', 'operator-1'); await p.click('#opSignupBtn');
    try { await waitText(p, '#opVerdict', 'op1'); } catch (e) { throw new Error(`${e.message}\n  opSignupVerdict=${await text(p, '#opSignupVerdict')}`); } assert.equal(await p.inputValue('#opId'), 'op1', '가입 뒤 로그인 화면에 아이디가 채워진다'); assert.equal(await p.isHidden('#rpCreateCard'), true, '로그인 전에는 RP 만들기가 없다');
    await p.fill('#opPwd', 'operator-1'); await p.click('#opLoginBtn'); await p.waitForSelector('#rpCreateCard:not([hidden])');
    await p.fill('#rpName', 'zkTHREE'); await p.fill('#rpOrigin', 'http://localhost:3999'); await p.click('#rpCreateBtn');   // 2026-11-06: 서비스 주소도 넣는다 — 명령의 포트가 채워진다
    await waitText(p, '#rpList', 'zkTHREE'); assert.match(await text(p, '#rpList'), /new_rp\.sh zkTHREE 3999 [0-9a-f]{64}/);
    assert.ok((await text(p, '#rpList')).includes('RP 서버 기동 전'), '서버가 등록 전이라 인증서 열은 짧은 안내만(2026-11-06)'); await p.close();
  });
  await t('IdP 인증 창: wallet 쿼리가 지갑 오리진과 다르면 폼을 막는다; 맞으면 uid·pwd·auid 로 코드를 받아 opener 에 postMessage', async () => {
    const bad = await context.newPage(); await bad.goto(`${cia.base}/login?nonce=abc&wallet=http://evil.example`); await waitText(bad, '#authVerdict', '스냅 오리진'); await bad.close();
    // 등록된 계정(맨 위 "등록(2026-10-22): …" 케이스가 IdP 가입으로 만든 uid·AUID)으로: opener 를 흉내 내는 페이지가
    // window.open 으로 연다. 그 등록 케이스가 실패해 uid 가 null 로 남으면 /cia/auth/code 가 not_registered 로 막아
    // 아래가 시간 초과로 실패한다 — /login 페이지·/cia/auth/code 자체의 결함이 아니라 그 실패가 이어진 것이다.
    const opener = await context.newPage(); await opener.goto(`${wallet.base}/`);
    const [win] = await Promise.all([context.waitForEvent('page'), opener.evaluate((u) => { window.__got = null; window.addEventListener('message', (ev) => { window.__got = { origin: ev.origin, data: ev.data }; }); window.open(u); }, `${cia.base}/login?nonce=n1&wallet=${wallet.base}`)]);
    await win.fill('#authUid', uid); await win.fill('#authPwd', DEMO_PWD); await win.fill('#authAuid', String(AUID)); await win.click('#authGo');
    await opener.waitForFunction(() => window.__got !== null, undefined, { timeout: 10_000 });
    const got = await opener.evaluate(() => window.__got);
    assert.equal(got.origin, cia.base); assert.equal(got.data.type, 'mode3-idp-auth'); assert.equal(got.data.nonce, 'n1'); assert.match(got.data.code, /^[0-9a-f]{64}$/);
    await opener.close();
  });

  // Task 14(B5): 위 케이스들은 completeIdpAuth() 로 IdP 로그인을 "그냥 통과"시켰다 — 이 케이스는 그 페이지를 직접 다뤄
  // (숨겨진) auid 가 틀리면 auid_mismatch 로 막히고(페이지에 머문다), 고치면 지갑으로 돌아가 발급까지 간다는 것을 보인다.
  await t('로그인(2026-10-22): 팝업이 IdP 로그인 페이지로 가 uid·비밀번호·auid 를 넣어야 발급된다(2026-11-09 auid 직접 입력); auid 가 틀리면 auid_mismatch', async () => {
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await atIdpLogin(popup);
    assert.equal(await popup.isVisible('#authAuidRow'), true, '2026-11-09: auid 칸은 늘 보인다(직접 입력)');
    assert.equal(await popup.inputValue('#authAuid'), '', 'auid 는 미리 채우지 않는다');
    await popup.fill('#authUid', uid); await popup.fill('#authPwd', DEMO_PWD);
    await popup.evaluate(() => { document.querySelector('#authAuid').value = '123'; }); await popup.click('#authGo');
    await waitText(popup, '#authVerdict', '다른 zkID 계정');                                          // auid_mismatch 사유, 페이지에 머문다
    assert.ok(popup.url().includes('/login'), `실패하면 IdP 페이지에 머문다: ${popup.url()}`);
    // cia_login.html 의 #authGo 핸들러는 성공·실패 모두에서 clearPwd() 로 비밀번호 칸을 비운다(§4) — 다시 채워야 한다.
    await popup.fill('#authPwd', DEMO_PWD); await popup.evaluate((a) => { document.querySelector('#authAuid').value = a; }, String(AUID)); await popup.click('#authGo');
    await backAtWallet(popup);
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    await awaitPopupClosed(popup);
  });

  // F-1(2026-10-23): 두 postMessage 채널(mode3-idp-auth, mode3-register)의 음성 테스트 — 지갑 팝업의 수신 가드가
  // 깨지는 회귀를 잡는다("팝업 오리진 검사" 패턴 재사용). idpLogin(rpPage) 이 rpPage 의 currentSession 을 새 세션으로
  // 덮어쓰므로, 그 값에 의존하는 앞쪽 테스트(sessionRs·지갑 재시작 재검증 등)를 건드리지 않게 파일 끝(하네스 점검 바로
  // 앞)에 둔다.
  // 2026-11-05: IdP 인증 결과는 postMessage 가 아니라 돌아오는 URL(idp_nonce·idp_code)로 온다 — 팝업은 저장해 둔 pending 의 nonce 와 맞을 때만 이어 간다.
  await t('돌아오는 길 음성: 저장된 요청(pending) 없이 idp_code 를 들고 온 창은 결과를 내지 않고 안내만 한다', async () => {
    const before = (await rp.get('/api/mode3/logins', rp.adminHeaders)).body.logins.length;
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.evaluate((u) => { window.open(u, 'forged-return', 'width=400,height=400'); }, `${wallet.base}/?authorize=1&idp_nonce=deadbeef&idp_code=${'0'.repeat(64)}`)]);
    await waitText(popup, '#authStep', '이어받지 못했습니다', 15_000);
    await popup.waitForTimeout(500);
    assert.equal(popup.isClosed(), false, '결과를 내고 닫히면 안 된다');
    assert.equal(popup.url().includes('idp_code'), false, '1회용 코드는 주소창에서 지운다');
    assert.equal((await rp.get('/api/mode3/logins', rp.adminHeaders)).body.logins.length, before, '로그인이 생기지 않는다');
    await popup.close();
  });

  await t('postMessage 음성(F-1): 지갑 팝업의 mode3-register 수신은 RP 오리진 같은 가짜 발신을 origin_mismatch 로 무시한다', async () => {
    const { popup, result } = await forgeRegister('mode3-register-forged', { uid: '1', code: 'forged' });
    assert.equal(result.ok, false, j(result));
    assert.equal(result.reason, 'origin_mismatch', j(result));
    await awaitPopupClosed(popup);
  });

  await t('관리자 비밀번호(2026-11-05): RP /admin 은 비밀번호 화면이 먼저 — 틀리면 "비밀번호가 맞지 않습니다", 맞으면 기록이 열리고 새로고침은 넘기며 로그아웃은 다시 잠근다; API 는 헤더 없이 401', async () => {
    assert.equal((await rp.get('/api/mode3/logins')).status, 401, '헤더 없는 로그인 기록 GET');
    assert.equal((await rp.post('/api/mode3/open', { PPID: '1' })).status, 401, '헤더 없는 개봉 요청');
    const p = await context.newPage(); await p.goto(`${rp.base}/admin`);
    await p.waitForSelector('#adminGate:not([hidden])');
    assert.equal(await p.$eval('#loginsCard', (el) => getComputedStyle(el).display), 'none', '잠긴 동안 기록 카드는 숨는다');
    await p.fill('#adminGate .gate-pwd', 'wrong'); await p.click('#adminGate .gate-form button[type=submit]');
    await waitText(p, '#adminGate .gate-verdict', '비밀번호가 맞지 않습니다');
    await p.fill('#adminGate .gate-pwd', rp.adminHeaders['X-RP-Admin-Secret']); await p.click('#adminGate .gate-form button[type=submit]');
    await p.waitForFunction(() => document.querySelectorAll('#logins table tbody tr').length > 0, undefined, { timeout: 20_000 });
    assert.equal(await p.$eval('#adminGate', (el) => el.hidden), true);
    // 2026-11-11: "auid_s ↔ PPID" 표 — zkID 로그인 줄마다 auid_s·PPID 를 자르지 않고 보인다
    const lg = (await rp.get('/api/mode3/logins', rp.adminHeaders)).body.logins.filter((l) => l.PPID);
    const auidRows = await p.$$eval('#auids table tbody tr', (trs) => trs.map((tr) => [tr.cells[1].textContent, tr.cells[2].textContent]));
    assert.equal(auidRows.length, lg.length);
    for (const l of lg) assert.ok(auidRows.some(([a, pp]) => a === l.auid_s && pp === l.PPID), `auid_s ${l.auid_s} ↔ PPID ${l.PPID}`);
    await p.reload({ waitUntil: 'load' });
    await p.waitForFunction(() => document.querySelectorAll('#logins table tbody tr').length > 0, undefined, { timeout: 20_000 });   // sessionStorage 로 넘어간다
    await p.click('#gateLogoutBtn'); await p.waitForSelector('#adminGate:not([hidden])');
    assert.equal(await p.$eval('#loginsCard', (el) => getComputedStyle(el).display), 'none');
    await p.close();
  });
  await t('관리자 비밀번호(2026-11-05): IdP /admin 도 비밀번호 화면 — 맞으면 계정 목록이 열린다', async () => {
    const p = await context.newPage(); await p.goto(`${cia.base}/admin`);
    await p.waitForSelector('#adminGate:not([hidden])');
    await p.fill('#adminGate .gate-pwd', 'wrong'); await p.click('#adminGate .gate-form button[type=submit]');
    await waitText(p, '#adminGate .gate-verdict', '비밀번호가 맞지 않습니다');
    await p.fill('#adminGate .gate-pwd', cia.adminSecret); await p.click('#adminGate .gate-form button[type=submit]');
    await p.waitForFunction(() => document.querySelectorAll('#accounts table tbody tr').length > 0, undefined, { timeout: 20_000 });
    assert.equal(await p.$eval('#adminGate', (el) => el.hidden), true);
    // 2026-11-11: "uid ↔ auid 대응" 표는 계정마다 한 줄, auid 는 자르지 않고 보인다. "등록부 DB" 는 regRoot 전체와 슬롯별 리프를 보인다.
    const accts = await p.evaluate((sec) => fetch('/cia/accounts', { headers: { 'X-CIA-Admin-Secret': sec } }).then((r) => r.json()), cia.adminSecret);
    // 2026-11-11(사용자 결정): 계정 카드는 화면에서 뺐다 — 메뉴에도 없다. 목록은 "uid ↔ auid 대응"·"등록부 DB" 로 본다.
    assert.equal(await p.isVisible('#secAccounts'), false, '계정 카드는 보이지 않는다');
    assert.equal(await p.$('.section-menu a[href="#secAccounts"]'), null, '메뉴에 계정이 없다');
    await p.waitForFunction((n) => document.querySelectorAll('#auidMap table tbody tr').length === n, accts.accounts.length, { timeout: 20_000 });
    const mapRows = await p.$$eval('#auidMap table tbody tr', (trs) => trs.map((tr) => [...tr.cells].map((c) => c.querySelector('code')?.textContent ?? c.textContent.trim())));
    for (const a of accts.accounts) {
      const row = mapRows.find((r) => r[0] === a.uid);
      assert.ok(row, `uid ${a.uid} 줄이 있다`);
      assert.equal(row[2], a.auid ?? '(없음)', `uid ${a.uid} 의 auid 전체`);
      assert.equal(row[3], a.lastAuidS?.value ?? '(없음)', `uid ${a.uid} 의 최신 auid_s 전체(2026-11-12)`);
    }
    assert.ok(accts.accounts.some((a) => a.auid), '등록된 계정이 하나는 있다(대응 표가 실제 auid 를 보이는지 확인하려면)');
    assert.ok(accts.accounts.some((a) => a.lastAuidS?.value), '발급받은 계정이 하나는 있다(최신 auid_s 열이 실제 값을 보이는지 확인하려면)');
    assert.deepEqual(await p.$$eval('#auidMap table thead th', (ths) => ths.map((th) => th.textContent.trim())), ['uid', '아이디', 'auid', '최신 auid_s', '슬롯']);
    const st = await p.evaluate(() => fetch('/cia/state').then((r) => r.json()));
    await p.waitForFunction((root) => [...document.querySelectorAll('#regDbKv code')].some((c) => c.textContent === root), st.regRoot, { timeout: 20_000 });
    const reg = await p.evaluate((sec) => fetch('/cia/admin/registry', { headers: { 'X-CIA-Admin-Secret': sec } }).then((r) => r.json()), cia.adminSecret);
    const leaves = await p.$$eval('#regDb table tbody tr', (trs) => trs.map((tr) => tr.cells[4].querySelector('code').textContent));
    assert.deepEqual(leaves, reg.slots.filter((x) => x.uid !== null).map((x) => x.leaf), '등록부 DB 의 리프는 API 와 같은 전체 값');
    await p.close();
  });

  await t('I-3(2026-11-12 스펙 snap-account-index): 같은 시드의 스냅을 초기화하고 다른 계정을 가입하면 계정 번호가 올라 sk_u·salt 가 다르다 — IdP 는 새 계정으로 받는다', async () => {
    const skA = snapState.registration.sk_u, saltA = snapState.registration.s_u;
    assert.equal((await cia.post('/cia/signup', { id: 'demo-user-b', pwd: DEMO_PWD })).status, 201, '계정 B 가입');
    const uidB = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.id === 'demo-user-b').uid;
    // "스냅 초기화" 의 결과(등록·동의를 지우고 nextIndex 만 남긴다 — 스냅 RPC 테스트가 reset 자체를 본다) + 에이전트 비우기
    snapState = { version: 1, registration: null, userCred: null, consents: {}, nextIndex: snapState.nextIndex };
    assert.equal((await wallet.post('/wallet/reset', { confirm: true })).status, 200);
    const saltB = derivedSecrets(STUB_SRP, 1).s_u;
    const auidB = (await auidOf({ uid: BigInt(uidB), s_u: BigInt(saltB) })).toString();
    // 최종 리뷰 I-1: 속성 도구 화면을 거친다 — 앞 계정 A 의 기록이 칸을 채운 채 열리고, uid 만 B 로 바꾸면 번호·salt 가 비어야 한다(그대로면 B 도 0번 = A 의 pk_u).
    const a = await context.newPage(); await a.goto(`${wallet.base}/attr.html`);
    try {
      await a.waitForFunction(() => document.getElementById('acctIndex').value === '0');   // A 의 기록(0번)으로 열린다
      await a.fill('#uid', String(uidB));
      assert.equal(await a.inputValue('#acctIndex'), '', 'uid 를 바꾸면 번호 칸이 빈다'); assert.equal(await a.inputValue('#salt'), '', 'salt 칸도 빈다');
      await a.click('#saltFromSnapBtn'); await a.waitForFunction(() => document.getElementById('salt').value !== '');
      assert.equal(await a.inputValue('#acctIndex'), '1', '등록이 없는 스냅의 기본은 다음 가입 번호'); assert.equal(await a.inputValue('#salt'), saltB);
      await a.fill('#birthYear', '1990'); await a.selectOption('#country', 'KR'); await a.click('#makeBtn');
      await waitText(a, '#formVerdict', '커밋먼트 생성 완료');
      const recB = JSON.parse(await a.evaluate(() => localStorage.getItem('mode3_attr_tool_v1')));
      assert.equal(recB.uid, String(uidB)); assert.equal(recB.index, 1); assert.equal(recB.s_u, saltB);
    } finally { await a.close(); }
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await atIdpLogin(popup);
    await popup.fill('#authUid', 'demo-user-b'); await popup.fill('#authPwd', DEMO_PWD); await popup.fill('#authAuid', auidB); await popup.click('#authGo');
    await backAtWallet(popup);
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    await awaitPopupClosed(popup);
    assert.equal(snapState.registration?.index, 1); assert.equal(snapState.registration?.uid, String(uidB));
    assert.notEqual(snapState.registration.sk_u, skA, '다른 계정은 다른 서명키 — IdP 가 pk_u 로 묶지 못한다');
    assert.notEqual(snapState.registration.s_u, saltA);
    const st = (await wallet.get('/wallet/status')).body; assert.equal(st.index, 1); assert.equal(String(st.uid), String(uidB));
  });

  await t('하네스: 준비한 대화상자 응답이 남지 않았다(기대한 동의 창이 다 떴다)', async () => {
    assert.equal(answers.length, 0, `쓰이지 않은 응답이 남았다: ${j(answers)}`);
  });
} finally {
  await browser.close();
  await stack.stop();
  provider.destroy();
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
// 다른 Mode 3 테스트와 같은 관례 — 남는 핸들 때문에 저절로 끝나지 않는다
process.exit(failed === 0 ? 0 : 1);
