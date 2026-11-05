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
import { buildInitScript } from './helpers/ethereum_stub.js';
import { VKEY_PATH } from '../lib/mode3_wallet.js';
import { attrGateAt } from '../lib/mode3_onchain.js';
import { DEFAULT_ATTR_SCHEMA, encodeSlotValue } from '../lib/mode3_attr_schema.js';

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
const provider = getProvider();
// Task 14(B5): CIA_ISSUE_AUTH=code — 신규 로그인마다 IdP 인증 창의 1회용 코드(auth_code)가 필요하다(completeIdpAuth 참고).
const stack = await startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'snap' }, ciaEnv: { CIA_ISSUE_AUTH: 'code' }, autoRelay: true });   // V10: 거울 릴레이는 헬퍼가 대신 돈다(페이지 안 로그인)
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
    // 2026-11-05: 별도 창·"IdP 인증 창 열기" 버튼 대신 팝업 창 자체가 IdP 로그인 페이지(/login?return=1&auid=…)로 간다(mode3/wallet.html goIdpAuth).
    // auid 는 쿼리로 넘어와 칸이 숨겨지고, 아이디·비밀번호만 넣으면 지갑 /?authorize=1 로 돌아와 로그인을 이어 간다.
    await atIdpLogin(popup);
    assert.equal(await popup.isHidden('#authAuidRow'), true, 'auid 칸은 숨겨진다(쿼리로 받았다)');
    assert.equal(await popup.inputValue('#authAuid'), String(AUID), 'auid 가 자동으로 채워진다');
    await popup.fill('#authUid', String(authUid));
    await popup.fill('#authPwd', pwd);
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
    return [document.documentElement.outerHTML, inputs, store(localStorage), store(sessionStorage)].join('\n');
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

  // Task 14(B5, 2026-10-23): 등록은 이제 IdP /user 페이지가 지갑 팝업(?authorize=1)을 열고 mode3-register 를 보낸다 —
  // Snap 의 register({uid})(Task 15)는 더 이상 비밀번호를 묻지 않는다(확인 창 하나, uid 만 보인다). IdP 는 auid·pk_u·sig_reg
  // 만 받는다(cia.js 의 /cia/register) — uid·비밀번호를 직접 프롬프트하던 옛 Snap RPC 는 이제 없다.
  await t('등록(2026-10-22): IdP 사용자 페이지 가입·로그인 → "지갑으로 커밋먼트 등록" → 지갑 팝업 → Snap 확인 창(uid·비밀번호 프롬프트 없음) → 등록됨; IdP 는 auid·pk_u·sig_reg 만 받았다', async () => {
    const u = await context.newPage(); await u.goto(`${cia.base}/user`);
    // 2026-11-03 재구성: 로그인 화면 → "계정 만들기" → 아이디·비밀번호·확인 → 가입되면 로그인 화면으로 돌아오고 아이디가 채워져 있다.
    assert.equal(await u.isHidden('#registerBtn'), true, '로그인 전에는 등록 카드가 없다');
    await u.click('#showSignupBtn'); await u.fill('#signupId', 'demo-user'); await u.fill('#signupPwd', DEMO_PWD); await u.fill('#signupPwd2', DEMO_PWD); await u.click('#signupBtn');
    await waitText(u, '#userVerdict', '가입했습니다');   // 2026-11-05: 가입 문구에 uid 는 없다 — uid 는 등록 뒤 지갑 상태에서 받는다
    assert.equal(await u.inputValue('#loginId'), 'demo-user', '가입한 아이디가 로그인 폼에 채워진다');
    await u.fill('#loginPwd', DEMO_PWD); await u.click('#loginBtn'); await waitText(u, '#meBadge', '등록 전');
    assert.equal(await u.isHidden('#revokeCard'), true, '등록 전에는 폐기 카드가 없다');
    const dBefore = dialogs.length;                                                        // 2026-11-05: Snap 등록 확인 창은 없다(중복 확인 제거)
    const [popup] = await Promise.all([context.waitForEvent('page'), u.click('#registerBtn')]);
    await waitText(u, '#meBadge', '등록됨', 60_000);
    assert.equal(await u.isVisible('#revokeCard'), true, '등록 뒤에는 폐기 카드가 보인다'); assert.equal(await u.isHidden('#registerBtn'), true, '등록 뒤에는 등록 버튼이 없다');
    assert.equal(dialogs.length, dBefore, '등록에 Snap 확인 창이 뜨지 않는다');
    const st = (await wallet.get('/wallet/status')).body; assert.match(String(st.uid), /^[0-9]+$/); uid = st.uid; AUID = st.auid; await u.close();
    await awaitPopupClosed(popup);
  });
  await t('지갑 페이지 제목은 "지갑", 신원 카드에 auid·salt 와 복사 버튼', async () => {
    assert.equal(await walletPage.title(), '지갑');   // 새로고침 버튼은 없다(2026-11-05) — 화면이 5초마다 스스로 갱신한다
    await walletTab(walletPage, 'account'); await walletPage.click('#identityDetails summary');   // auid·salt 는 '상세' 접힘 안(2026-11-03)
    await waitText(walletPage, '#meAuid', AUID.slice(0, 10));                           // showSalt 확인 창은 없다(2026-11-05)
    await walletPage.click('#showSaltBtn'); await walletPage.waitForFunction(() => /^[0-9]{10,}$/.test(document.querySelector('#meSalt')?.textContent ?? ''), undefined, { timeout: 10_000 });
    assert.ok(await walletPage.$('#copyAuidBtn')); assert.ok(await walletPage.$('#copySaltBtn'));
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
    await waitText(rpPage, '#walletMode', '지갑 비밀=snap', 15_000);
    assert.ok((await text(rpPage, '#walletMode')).includes(cfg.snapId));
  });

  await t('로그인: 팝업이 IdP 로그인 페이지로 갔다가 돌아와 Snap 동의 창 없이 결과를 postMessage 로 돌려준다 → RP 세션', async () => {
    const before = dialogs.length;
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    assert.ok(popup.url().includes('authorize=1'), `팝업 URL: ${popup.url()}`);
    await completeIdpAuth(popup);               // Task 14: IdP 인증(CIA_ISSUE_AUTH=code) — 2026-11-05 부터 팝업 창 자체가 갔다 온다
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    assert.equal(dialogs.length, before, '로그인에 Snap 동의 창이 없다(2026-11-05 중복 확인 제거)');
    assert.ok((await text(rpPage, '#log')).includes('allowAgent=0'), 'AI 에이전트 체크박스를 없앴으므로 늘 0(2026-11-05)');
    await awaitPopupClosed(popup);
    assert.ok((await text(rpPage, '#log')).includes('3. RP 검증'), 'RP 페이지가 /api/mode3/login 까지 냈다');
    assert.equal((await text(rpPage, '#sessionId')).includes('(없음)'), false, '세션이 잡혔다');
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

  await t('재검증: /wallet/revalidate 는 RP 오리진에 CORS 로 열려 있어 팝업 없이 된다', async () => {
    const before = dialogs.length;
    await rpPage.click('#revalidateBtn');
    await waitText(rpPage, '#sessionVerdict', '재검증 성공', 120_000);
    assert.equal(dialogs.length, before, '세션 안 재검증은 동의를 다시 묻지 않는다');
  });

  // ---- 평범한 트랜잭션 + 공개 트랜잭션: MetaMask(스텁)가 배포·execute 를 보낸다 ----
  const info = (await rp.get('/api/mode3/rp_info')).body;

  // U4(2026-10-14): 세션을 골라도 더는 AttrGate 로 자동 재배선하지 않는다 — 기본 대상(사망 주소)·조건 없음인
  // 평범한 트랜잭션은 늘 성공해야 한다(사용자가 실제로 겪은 문제: 예전에는 모든 기본 tx 가 AttrGate.claim 으로
  // 가 조건 미공개로 늘 revert 됐다).
  await t('평범한 트랜잭션: 기본 대상·조건 없이 보내도 늘 성공한다(U4)', async () => {
    await walletTab(walletPage, 'send');
    await walletPage.waitForFunction(() => !document.querySelector('#txBtn').disabled, undefined, { timeout: 15_000 });
    assert.equal(await walletPage.inputValue('#txTo'), '0x000000000000000000000000000000000000dEaD', '기본 대상을 AttrGate 로 재배선하지 않는다');
    assert.equal(await walletPage.inputValue('#txData'), '0x');
    const before = dialogs.length;             // 2026-11-05: 지갑 "보내기" 는 Snap 동의 창 없이 MetaMask 확인 창(스텁)만 거친다
    await walletPage.click('#txBtn');
    await waitText(walletPage, '#txVerdict', '전송 성공', 180_000);
    assert.equal(dialogs.length, before, 'Snap 동의 창이 없다');
    const log = await text(walletPage, '#txLog');
    assert.match(log, /ok\(실행 성공\)=true/, `평범한 트랜잭션은 ok=true 여야 한다: ${log}`);
  });

  await t('공개 트랜잭션: "AttrGate 에 자격 증명(claim)" 버튼이 조건을 자동으로 채우고 claim 이 성공한다', async () => {
    assert.ok(info.attrGateAddress, 'AttrGate 가 배포돼 있어야 한다');
    await walletTab(walletPage, 'send'); await walletPage.click('#claimBtn');
    assert.equal(await walletPage.inputValue('#txTo'), info.attrGateAddress, 'claim 버튼이 받는 주소를 AttrGate 로 채운다');
    assert.equal(await walletPage.inputValue('#txData'), '0x4e71d92d', 'claim 버튼이 데이터를 claim() 셀렉터로 채운다');
    assert.equal(await walletPage.isChecked('#dk0'), true, 'claim 버튼이 출생연도 조건을 자동으로 채운다');
    assert.equal(await walletPage.inputValue('#setSlot'), '1', 'claim 버튼이 국가 집합 조건(슬롯 1)을 채운다');
    const before = dialogs.length;
    await walletPage.click('#txBtn');
    await waitText(walletPage, '#txVerdict', '전송 성공', 180_000);
    assert.equal(dialogs.length, before, '공개 트랜잭션도 Snap 동의 창 없이(MetaMask 확인 창만) 간다(2026-11-05)');
    const log = await text(walletPage, '#txLog');
    assert.ok(log.includes('온체인 공개(Disclosure 이벤트)'), '영수증 파싱 결과가 표시된다');
    const walletAddr = /지갑 주소=(0x[0-9a-fA-F]{40})/.exec(log)?.[1];
    assert.ok(walletAddr, `지갑 주소를 로그에서 못 찾았다:\n${log}`);
    assert.equal(await attrGateAt(info.attrGateAddress, provider).claimed(walletAddr), true, '온체인에서 claim 됐다');
  });

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

  // ---- 재승인(§4.3): 지갑이 재시작해 세션 증인이 사라진 경우 ----
  await t('지갑 재시작 뒤 재검증: 409 needs_consent → 같은 팝업을 reauth 로 열고 한 번 재시도한다', async () => {
    await stack.restartWallet();
    assert.equal((await wallet.get('/wallet/config')).body.secrets, 'snap');
    assert.equal((await wallet.post('/wallet/revalidate', { r_s: sessionRs }, { Origin: rp.origin })).status, 409, '재시작 뒤엔 증인이 없다');
    const before = dialogs.length;
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#revalidateBtn')]);
    assert.ok(popup.url().includes('authorize=1'));
    await waitText(rpPage, '#sessionVerdict', '재검증 성공', 180_000);
    assert.equal(dialogs.length, before, '재승인도 Snap 동의 창 없이 끝난다(2026-11-05)');
    const log = await text(rpPage, '#sessionLog');
    assert.ok(log.includes('재승인 팝업을 연다'), log);
    assert.ok(log.includes('재승인 완료'), log);
    await awaitPopupClosed(popup);
  });

  await t('재승인 가드: 세션의 allowAgent 를 모르면 팝업을 열지 않고 다시 로그인하라고 안내한다', async () => {
    await stack.restartWallet();
    await rpPage.evaluate(() => { currentSessionAllowAgent = null; });
    const before = dialogs.length;
    await rpPage.click('#revalidateBtn');
    await waitText(rpPage, '#sessionVerdict', '재승인 불가', 60_000);
    assert.equal(dialogs.length, before, '동의 창을 띄우지 않는다');
  });

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
  await t('지갑에서 속성 저장(출생연도) → Snap 의 속성 갱신·C_u 폐기 → 다음 로그인이 새 C_u', async () => {
    const beforeCf = snapState.userCred?.Cf_u ?? null;
    assert.ok(beforeCf, '시작 시 Snap 에 C_u 가 있다');
    assert.deepEqual(snapState.registration.attrs, ['1990', '410', '0', '0', '0', '0']);
    await walletTab(walletPage, 'account'); await walletPage.fill('#attr0', '1991');
    await walletPage.click('#profileSaveBtn');
    // '속성 저장 완료'(성공)까지 — 실패 문구('속성 저장 실패'·'속성 값이 스키마에 맞지 않습니다')에도 '속성'이 들어가
    // 그냥 '속성'만 찾으면 실패도 통과해 버린다.
    await waitText(walletPage, '#registerResult', '속성 저장 완료', 15_000);
    assert.deepEqual(snapState.registration.attrs, [await encodeSlotValue(DEFAULT_ATTR_SCHEMA, 0, '1991'), '410', '0', '0', '0', '0'], 'syncAttrs 가 Snap 의 속성을 갱신했다');
    assert.equal(snapState.userCred, null, '속성이 바뀌면 Snap 의 syncAttrs 가 옛 C_u 를 함께 버린다');
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await completeIdpAuth(popup);               // Task 14: IdP 인증(CIA_ISSUE_AUTH=code)
    await waitText(rpPage, '#verdict', '로그인 성공', 240_000);
    await awaitPopupClosed(popup);
    assert.ok(snapState.userCred, '새 C_u 가 Snap 에 남아 있다');
    assert.notEqual(snapState.userCred.Cf_u, beforeCf, '옛 C_u 가 아니라 새로 받은 것이다');
    assert.equal((await wallet.get('/wallet/status')).body.userCred.Cf_u, snapState.userCred.Cf_u, '에이전트의 공개 Cf_u 와 같다');
  });

  // 리뷰 round 1 Minor 7 — 지난 삭제된 테스트가 지키던 "syncAttrs → updateUserCred" 순서 회귀 가드를 다시 둔다.
  // 이번에는 바로 위 테스트(페이지를 거쳐 속성을 바꾼 경우)와 다르게, **에이전트 API 를 페이지 없이 직접 불러**
  // Snap 을 일부러 못 따라오게 만든다 — 그래야 다음 로그인이 자가 치유(attrsChanged + userCredIssued 동시 응답)를
  // 실제로 타고, 팝업의 applyPendingToSnap 이 그 둘을 올바른 순서로 반영하는지(새 C_u 가 살아남는지)를 본다.
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
  await t('IdP 사용자 페이지(2026-11-03): 계정 만들기(아이디·비밀번호·확인, 불일치는 pwd_mismatch, 중복 아이디는 id_taken) → 아이디로 로그인 → 상태(등록 전) → 로그아웃하면 로그인 화면', async () => {
    const p = await context.newPage(); await p.goto(`${cia.base}/user`);
    // 같은 브라우저 컨텍스트라 앞의 등록 케이스가 로그인해 둔 세션 쿠키가 남아 있을 수 있다 — 내 계정 화면이면 먼저 로그아웃한다.
    await p.waitForSelector('#loginView:not([hidden]), #meCard:not([hidden])');
    if (await p.isVisible('#meCard')) { await p.click('#logoutBtn'); await p.waitForSelector('#loginView:not([hidden])'); }
    assert.equal(await p.isHidden('#registerCard'), true); assert.equal(await p.isHidden('#revokeCard'), true);
    await p.click('#showSignupBtn'); await p.waitForSelector('#signupView:not([hidden])');
    await p.fill('#signupId', 'demo-user-2'); await p.fill('#signupPwd', 'demo-pass-1'); await p.fill('#signupPwd2', 'demo-pass-X'); await p.click('#signupBtn');
    await waitText(p, '#signupVerdict', '비밀번호 확인이 일치하지 않습니다');   // pwd_mismatch 제목
    await p.fill('#signupPwd2', 'demo-pass-1'); await p.click('#signupBtn');
    await waitText(p, '#userVerdict', '가입했습니다'); assert.equal(await p.inputValue('#loginId'), 'demo-user-2');
    // 같은 아이디(대소문자만 다른)로 다시 가입하면 409 id_taken.
    await p.click('#showSignupBtn'); await p.fill('#signupId', 'DEMO-USER-2'); await p.fill('#signupPwd', 'demo-pass-1'); await p.fill('#signupPwd2', 'demo-pass-1'); await p.click('#signupBtn');
    await waitText(p, '#signupVerdict', '그 아이디는 이미 쓰고 있습니다'); await p.click('#showLoginBtn');   // id_taken 제목
    await p.fill('#loginId', 'demo-user-2'); await p.fill('#loginPwd', 'wrong-pass-1'); await p.click('#loginBtn'); await waitText(p, '#userVerdict', '아이디 또는 비밀번호가 맞지 않습니다');   // invalid_credentials 제목
    await p.fill('#loginPwd', 'demo-pass-1'); await p.click('#loginBtn');
    await waitText(p, '#meBadge', '등록 전'); await waitText(p, '#meInfo', 'demo-user-2'); assert.equal(await p.isVisible('#registerBtn'), true);
    await p.click('#logoutBtn'); await p.waitForSelector('#loginView:not([hidden])'); assert.equal(await p.isHidden('#meCard'), true); await p.close();
  });
  await t('IdP RP 페이지: 운영자 가입·로그인 → zkTHREE 만들기 → 키·명령 표시', async () => {
    const p = await context.newPage(); await p.goto(`${cia.base}/rp`);
    // 2026-11-03: /rp 도 /user 처럼 로그인 화면 → "운영자 계정 만들기"(아이디·비밀번호·확인) → 로그인 화면으로 돌아와 비밀번호 → 로그인 뒤에만 RP 만들기.
    await p.click('#showOpSignupBtn'); await p.fill('#opSignupId', 'op1'); await p.fill('#opSignupPwd', 'operator-1'); await p.fill('#opSignupPwd2', 'operator-1'); await p.click('#opSignupBtn');
    await waitText(p, '#opVerdict', 'op1'); assert.equal(await p.inputValue('#opId'), 'op1', '가입 뒤 로그인 화면에 아이디가 채워진다'); assert.equal(await p.isHidden('#rpCreateCard'), true, '로그인 전에는 RP 만들기가 없다');
    await p.fill('#opPwd', 'operator-1'); await p.click('#opLoginBtn'); await p.waitForSelector('#rpCreateCard:not([hidden])');
    await p.fill('#rpName', 'zkTHREE'); await p.click('#rpCreateBtn');
    await waitText(p, '#rpList', 'zkTHREE'); assert.match(await text(p, '#rpList'), /new_rp\.sh zkTHREE <port> [0-9a-f]{64}/); await p.close();
  });
  await t('IdP 인증 창: wallet 쿼리가 지갑 오리진과 다르면 폼을 막는다; 맞으면 uid·pwd·auid 로 코드를 받아 opener 에 postMessage', async () => {
    const bad = await context.newPage(); await bad.goto(`${cia.base}/login?nonce=abc&wallet=http://evil.example`); await waitText(bad, '#authVerdict', '지갑 오리진'); await bad.close();
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
  await t('로그인(2026-10-22): 팝업이 IdP 로그인 페이지로 가 아이디·비밀번호를 넣어야 발급된다; (숨겨진) auid 가 틀리면 auid_mismatch', async () => {
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await atIdpLogin(popup);
    assert.equal(await popup.isHidden('#authAuidRow'), true, 'auid 칸은 숨겨져 있다');
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
    await p.close();
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
