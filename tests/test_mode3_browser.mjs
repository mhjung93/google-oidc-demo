// Mode 3 브라우저 경로 — 실제 Chrome 에서 지갑 페이지·승인 팝업·RP 페이지를 돌린다(스펙 2026-09-22 metamask-snap §7).
// MetaMask 는 tests/helpers/ethereum_stub.js 가 대신하고, Snap 은 **진짜 snap-mode3/src/index.js 의 onRpcRequest** 가 답한다
// (Task 5 Ruling 5 — 시뮬레이터가 아니다). 대화상자 답과 체인 전송만 이 하네스가 맡는다.
// '폐기 상한(2026-10-22): …' 케이스(Task 9)는 Snap 의 consentRevokeSession 이 아직 bound 를 보여 주지 않아
// "동의 창에 상한" 단언에서 일부러 실패한다 — Task 15 뒤 통과(그 태스크가 Snap 쪽을 고친다).
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
const stack = await startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'snap' }, autoRelay: true });   // V10: 거울 릴레이는 헬퍼가 대신 돈다(페이지 안 로그인)
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
  // 로그인 모달(2026-10-15): #loginBtn 은 모달을 열기만 하고, 실제 zk 로그인은 모달의 #idpLoginBtn 이 한다.
  // 2026-10-21: 로그인 상태에서는 로그인 버튼이 숨으므로, 이미 로그인돼 있으면 먼저 로그아웃한다.
  const idpLogin = async (page) => { if (await page.$eval('#loginBtn', (b) => b.hidden)) { await page.click('#logoutBtn'); await page.waitForSelector('#loginBtn:not([hidden])'); } await page.click('#loginBtn'); await page.click('#idpLoginBtn'); };
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

  const walletPage = await context.newPage();
  await walletPage.goto(wallet.base);

  await t('지갑 페이지: snap 모드 화면이 켜지고 MetaMask 연결이 된다', async () => {
    await walletPage.waitForSelector('#snapPanel:not([hidden])', { timeout: 15_000 });
    assert.equal(await walletPage.isHidden('#fileRegFields'), true, 'snap 모드는 uid·pwd 폼을 숨긴다');
    await walletPage.click('#connectBtn');
    await waitText(walletPage, '#mmStatus', account);
    assert.ok((await text(walletPage, '#mmStatus')).includes(cfg.snapId), 'Snap 연결 표시');
  });

  await t('등록: Snap 대화상자가 uid·비밀번호를 묻고, 비밀은 Snap 상태에만 남는다', async () => {
    answers.push('12345', 'password123');
    await walletPage.click('#registerBtn');
    await waitText(walletPage, '#registerResult', '등록됨', 30_000);
    assert.ok((await text(walletPage, '#registerResult')).includes('1990'), 'AA 속성이 화면에 온다');
    assert.equal(dialogs.length, 2, '대화상자 두 번(uid·비밀번호)');
    assert.ok(snapState?.registration?.s_u, '등록 비밀 s_u 는 Snap 상태에 있다');
    assert.ok(snapState.registration.sk_u, 'register 가 sk_u 를 만들었다');
    assert.equal(snapState.registration.uid, '12345');
    assert.equal('pwd' in snapState.registration, false, '비밀번호는 Snap 에 저장되지 않는다');
    const s = (await wallet.get('/wallet/status')).body;
    assert.equal(s.registered, true); assert.equal(s.uid, '12345');
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

  await t('로그인: 팝업이 열려 Snap 동의를 받고 결과를 postMessage 로 돌려준다 → RP 세션', async () => {
    await rpPage.check('#allowAgent');          // allowAgent='1' — 재승인 동의 창이 같은 값을 보여야 한다(§4.3)
    answers.push(true);                        // consentLogin 확인
    const before = dialogs.length;
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    assert.ok(popup.url().includes('authorize=1'), `팝업 URL: ${popup.url()}`);
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    assert.equal(dialogs.length, before + 1, '로그인 동의 대화상자 한 번');
    assert.ok(lastDialog().includes(rp.origin), `동의 창이 서비스 오리진을 보여 준다: ${lastDialog().slice(0, 300)}`);
    assert.ok(lastDialog().includes('AI 에이전트 허용: 예'), `동의 창이 allowAgent=1 을 보여 준다: ${lastDialog().slice(0, 400)}`);
    assert.ok((await text(rpPage, '#log')).includes('allowAgent=1'), 'RP 검증 결과의 allowAgent 가 1');
    await awaitPopupClosed(popup);
    assert.ok((await text(rpPage, '#log')).includes('3. RP 검증'), 'RP 페이지가 /api/mode3/login 까지 냈다');
    assert.equal((await text(rpPage, '#sessionId')).includes('(없음)'), false, '세션이 잡혔다');
    // 팝업 결과에는 지갑 안 정보가 실리지 않는다(스펙 §3.2) — 그래도 Snap 에는 새 C_u 가 저장돼 있어야 한다.
    assert.ok(snapState.userCred?.blind_u, '팝업이 userCredIssued 를 Snap 에 저장했다');
    assert.equal((await rp.get('/api/mode3/logins')).body.logins.length, 1);
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
      'rp/logins': j((await rp.get('/api/mode3/logins')).body),
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
    await walletPage.click('#refreshBtn');
    await walletPage.waitForFunction(() => !document.querySelector('#txBtn').disabled, undefined, { timeout: 15_000 });
    assert.equal(await walletPage.inputValue('#txTo'), '0x000000000000000000000000000000000000dEaD', '기본 대상을 AttrGate 로 재배선하지 않는다');
    assert.equal(await walletPage.inputValue('#txData'), '0x');
    answers.push(true);                        // consentDisclosure 확인 — snap 모드는 조건이 없어도 매번 동의를 묻는다
    await walletPage.click('#txBtn');
    await waitText(walletPage, '#txVerdict', '전송 성공', 180_000);
    const log = await text(walletPage, '#txLog');
    assert.match(log, /ok\(실행 성공\)=true/, `평범한 트랜잭션은 ok=true 여야 한다: ${log}`);
  });

  await t('공개 트랜잭션: "AttrGate 에 자격 증명(claim)" 버튼이 조건을 자동으로 채우고 claim 이 성공한다', async () => {
    assert.ok(info.attrGateAddress, 'AttrGate 가 배포돼 있어야 한다');
    await walletPage.click('#claimBtn');
    assert.equal(await walletPage.inputValue('#txTo'), info.attrGateAddress, 'claim 버튼이 받는 주소를 AttrGate 로 채운다');
    assert.equal(await walletPage.inputValue('#txData'), '0x4e71d92d', 'claim 버튼이 데이터를 claim() 셀렉터로 채운다');
    assert.equal(await walletPage.isChecked('#dk0'), true, 'claim 버튼이 출생연도 조건을 자동으로 채운다');
    assert.equal(await walletPage.inputValue('#setSlot'), '1', 'claim 버튼이 국가 집합 조건(슬롯 1)을 채운다');
    answers.push(true);                        // consentDisclosure 확인
    const before = dialogs.length;
    await walletPage.click('#txBtn');
    await waitText(walletPage, '#txVerdict', '전송 성공', 180_000);
    assert.equal(dialogs.length, before + 1, '공개 동의 대화상자 한 번');
    assert.ok(lastDialog().includes('∈ {'), `동의 창이 집합 소속 줄을 보여 준다: ${lastDialog().slice(0, 300)}`);
    const log = await text(walletPage, '#txLog');
    assert.ok(log.includes('온체인 공개(Disclosure 이벤트)'), '영수증 파싱 결과가 표시된다');
    const walletAddr = /지갑 주소=(0x[0-9a-fA-F]{40})/.exec(log)?.[1];
    assert.ok(walletAddr, `지갑 주소를 로그에서 못 찾았다:\n${log}`);
    assert.equal(await attrGateAt(info.attrGateAddress, provider).claimed(walletAddr), true, '온체인에서 claim 됐다');
  });

  // ---- 재승인(§4.3): 지갑이 재시작해 세션 증인이 사라진 경우 ----
  await t('지갑 재시작 뒤 재검증: 409 needs_consent → 같은 팝업을 reauth 로 열고 한 번 재시도한다', async () => {
    await stack.restartWallet();
    assert.equal((await wallet.get('/wallet/config')).body.secrets, 'snap');
    assert.equal((await wallet.post('/wallet/revalidate', { r_s: sessionRs }, { Origin: rp.origin })).status, 409, '재시작 뒤엔 증인이 없다');
    answers.push(true);                        // 재승인 consentLogin
    const before = dialogs.length;
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#revalidateBtn')]);
    assert.ok(popup.url().includes('authorize=1'));
    await waitText(rpPage, '#sessionVerdict', '재검증 성공', 180_000);
    assert.equal(dialogs.length, before + 1, '재승인 동의 대화상자 한 번');
    // 세션은 allowAgent='1' 로 만들어졌고 /wallet/session/witness 는 그 값을 바꾸지 않는다 — 동의 창도 '예' 여야 한다.
    assert.ok(lastDialog().includes('AI 에이전트 허용: 예'), `재승인 동의 창이 세션의 allowAgent 를 보여 준다: ${lastDialog().slice(0, 400)}`);
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

  // 2026-09-23 점검 B-I1: 재승인 동의 창의 allowAgent 를 서비스가 정하면 안 된다. 세션은 allowAgent='1' 인데
  // 요청에 '0' 을 실어 보내도, 팝업은 precheck 이 돌려준 세션 값을 쓰므로 문구는 '예' 여야 한다.
  await t('재승인 allowAgent 바인딩: 요청이 0 이라도 동의 창은 세션의 실제 값(예)을 보여 준다', async () => {
    const before = dialogs.length;
    answers.push(true);                        // 재승인 consentLogin
    const { popup, result } = await forgeAuthorize('mode3-authorize-forged-allowagent', {
      ...(await rpRequestBase()), reauth: true, r_s: sessionRs, allowAgent: '0', serviceName: '○○은행',
    });
    assert.equal(result.ok, true, j(result));
    assert.equal(dialogs.length, before + 1, '재승인 동의 대화상자 한 번');
    assert.ok(lastDialog().includes('AI 에이전트 허용: 예'), `요청의 allowAgent 가 아니라 세션 값을 보여야 한다: ${lastDialog().slice(0, 400)}`);
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
    let release = null;
    dialogGate = new Promise((r) => { release = r; });
    answers.push(true);
    const before = dialogs.length;
    let popup = null;
    try {
      [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
      await waitFor(() => dialogs.length > before, '팝업이 동의 창까지 오는 것');
      assert.ok(challengeRs, '챌린지 r_s 를 가로챘다');
      // (1) r_s 는 맞지만 지갑 오리진이 아닌 창(RP 페이지 자신)이 보낸 결과
      await rpPage.evaluate((rs) => window.postMessage({ type: 'mode3-authorize-result', r_s: rs, result: { ok: false, reason: 'forged_from_rp_origin' } }, '*'), challengeRs);
      // (2) 지갑 오리진(팝업)이 보냈지만 r_s 가 다른 결과
      await popup.evaluate(() => window.opener.postMessage({ type: 'mode3-authorize-result', r_s: '424242', result: { ok: false, reason: 'forged_wrong_rs' } }, '*'));
      await rpPage.waitForTimeout(500);
      assert.equal((await text(rpPage, '#verdict')).includes('forged'), false, `위조 결과가 받아들여졌다: ${await text(rpPage, '#verdict')}`);
      assert.equal((await text(rpPage, '#log')).includes('3. RP 검증'), false, '아직 진짜 결과가 오지 않았다');
    } finally {
      release(); dialogGate = null;
    }
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    assert.equal((await text(rpPage, '#log')).includes('forged'), false);
    rpPage.off('response', onResp);
    await awaitPopupClosed(popup);
  });

  await t('동의 거절: Snap 이 denied 를 주면 RP 에 user_denied 가 돌아오고 새 세션은 생기지 않는다', async () => {
    const before = (await rp.get('/api/mode3/logins')).body.logins.length;
    answers.push(false);                       // consentLogin 거절
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await waitText(rpPage, '#verdict', 'user_denied', 120_000);
    await awaitPopupClosed(popup);
    assert.equal((await rp.get('/api/mode3/logins')).body.logins.length, before, '거절은 로그인을 남기지 않는다');
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
    await walletPage.fill('#attr0', '1991');
    await walletPage.click('#profileSaveBtn');
    // '속성 저장 완료'(성공)까지 — 실패 문구('속성 저장 실패'·'속성 값이 스키마에 맞지 않습니다')에도 '속성'이 들어가
    // 그냥 '속성'만 찾으면 실패도 통과해 버린다.
    await waitText(walletPage, '#registerResult', '속성 저장 완료', 15_000);
    assert.deepEqual(snapState.registration.attrs, [await encodeSlotValue(DEFAULT_ATTR_SCHEMA, 0, '1991'), '410', '0', '0', '0', '0'], 'syncAttrs 가 Snap 의 속성을 갱신했다');
    assert.equal(snapState.userCred, null, '속성이 바뀌면 Snap 의 syncAttrs 가 옛 C_u 를 함께 버린다');
    answers.push(true);                        // 로그인 동의
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
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
    answers.push(true);                        // 로그인 동의
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    await waitText(rpPage, '#verdict', '로그인 성공', 240_000);
    await awaitPopupClosed(popup);
    assert.deepEqual(snapState.registration.attrs, chg.body.attrs, '팝업이 attrsChanged 를 Snap 의 syncAttrs 로 반영해 파일과 같아졌다');
    assert.ok(snapState.userCred, '새 C_u 가 Snap 에 남아 있다(syncAttrs 를 updateUserCred 보다 나중에 하면 지워진다)');
    assert.notEqual(snapState.userCred.Cf_u, beforeCf, '옛 C_u 가 아니라 새로 받은 것이다');
    assert.equal((await wallet.get('/wallet/status')).body.userCred.Cf_u, snapState.userCred.Cf_u, '에이전트의 공개 Cf_u 와 같다');
  });

  await t('폐기 상한(2026-10-22): 세션 카드에 nonce, 폐기 때 허용 수 입력 → Snap 동의 창에 "허용 거래 수" → 체인 반영 대기 행 → 재로그인 뒤 "지금 반영" → 행 사라짐', async () => {
    await walletPage.click('#refreshBtn');
    await walletPage.waitForFunction(() => /nonce\s*\d+/.test(document.querySelector('#sessionActions')?.textContent ?? ''), undefined, { timeout: 15_000 });
    await walletPage.fill('#sessionActions input.bound', '1');
    answers.push(true);                                                   // consentRevokeSession
    walletPage.once('dialog', (d) => d.accept());                         // confirm_revoke
    await walletPage.click('#sessionActions button.danger');
    await waitText(walletPage, '#sessionVerdict', '폐기 요청 접수');
    assert.ok(dialogs.at(-1).content.children.some((c) => /허용 거래 수: 1/.test(c.value ?? '')), '동의 창에 상한');
    await waitText(walletPage, '#boundsList', '반영 대기', 10_000);
    // 다시 로그인(같은 RP) → 지금 반영 → MetaMask 스텁이 보낸다 → 행 사라짐
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]); answers.push(true); await popup.waitForEvent('close');
    await walletPage.click('#boundsList button.apply');
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
      await waitText(rpPage, '#verdict', 'factory_constants_unavailable', 30_000);
      assert.equal((await text(rpPage, '#verdict')).includes('Cannot read'), false, `TypeError 가 아니라 사유가 보여야 한다: ${await text(rpPage, '#verdict')}`);
      await rpPage.waitForFunction(() => !document.querySelector('#loginBtn').disabled, undefined, { timeout: 10_000 });
      assert.equal(dialogs.length, before, '챌린지 단계에서 멈추므로 지갑 팝업·동의 창까지 가지 않는다');
    } finally {
      await rpPage.unroute('**/api/mode3/challenge');
    }
  });

  // ---- Task 12(B3, 2026-10-22): IdP 사용자·RP·인증 창 페이지(/user·/rp·/login) ----
  // 가입·로그인·RP 만들기는 Snap 대화상자를 쓰지 않는다 — 새 계정(가입으로 받은 uid·새 운영자 id)을 써서 위의
  // "등록: Snap 대화상자가…" 실패(Task 13 이후 Snap 이 register({uid})를 요구하는데 Task 14 전 지갑 페이지는 여전히
  // 옛 방식으로 불러 생기는 실패)와 아래 "폐기 상한" 케이스에 영향받지 않는다(컨트롤러 판정 2026-10-23).
  await t('IdP 사용자 페이지: 가입 → uid 배정 → 로그인 → 상태(등록 전) → 로그아웃', async () => {
    const p = await context.newPage(); await p.goto(`${cia.base}/user`);
    await p.fill('#signupPwd', 'demo-pass-1'); await p.click('#signupBtn');
    await waitText(p, '#userVerdict', 'uid'); const uid = await p.$eval('#userVerdict', (e) => e.textContent.match(/uid\s*(\d+)/)[1]);
    await p.fill('#loginUid', uid); await p.fill('#loginPwd', 'demo-pass-1'); await p.click('#loginBtn');
    await waitText(p, '#meBadge', '등록 전'); await p.click('#logoutBtn'); await waitText(p, '#meBadge', '로그아웃'); await p.close();
  });
  await t('IdP RP 페이지: 운영자 가입·로그인 → zkTHREE 만들기 → 키·명령 표시', async () => {
    const p = await context.newPage(); await p.goto(`${cia.base}/rp`);
    await p.fill('#opId', 'op1'); await p.fill('#opPwd', 'operator-1'); await p.click('#opSignupBtn'); await waitText(p, '#rpVerdict', 'op1');
    await p.click('#opLoginBtn'); await p.fill('#rpName', 'zkTHREE'); await p.click('#rpCreateBtn');
    await waitText(p, '#rpList', 'zkTHREE'); assert.match(await text(p, '#rpList'), /new_rp\.sh zkTHREE <port> [0-9a-f]{64}/); await p.close();
  });
  await t('IdP 인증 창: wallet 쿼리가 지갑 오리진과 다르면 폼을 막는다; 맞으면 uid·pwd·auid 로 코드를 받아 opener 에 postMessage', async () => {
    const bad = await context.newPage(); await bad.goto(`${cia.base}/login?nonce=abc&wallet=http://evil.example`); await waitText(bad, '#authVerdict', '지갑 오리진'); await bad.close();
    // 등록된 계정(앞의 "등록: Snap 대화상자가…" 케이스가 만든 12345 — 시드)으로: opener 를 흉내 내는 페이지가 window.open 으로 연다.
    // 그 케이스가 실패해 12345 가 미등록으로 남으면(위 주석) /cia/auth/code 가 not_registered 로 막아 아래가 시간 초과로
    // 실패한다 — /login 페이지·/cia/auth/code 자체의 결함이 아니라 그 실패가 이어진 것이다(보고서에 기록).
    const status = (await wallet.get('/wallet/status')).body;
    const AUID_12345 = status?.registered ? status.auid : null;
    const opener = await context.newPage(); await opener.goto(`${wallet.base}/`);
    const [win] = await Promise.all([context.waitForEvent('page'), opener.evaluate((u) => { window.__got = null; window.addEventListener('message', (ev) => { window.__got = { origin: ev.origin, data: ev.data }; }); window.open(u); }, `${cia.base}/login?nonce=n1&wallet=${wallet.base}`)]);
    await win.fill('#authUid', '12345'); await win.fill('#authPwd', 'password123'); await win.fill('#authAuid', String(AUID_12345)); await win.click('#authGo');
    await opener.waitForFunction(() => window.__got !== null, undefined, { timeout: 10_000 });
    const got = await opener.evaluate(() => window.__got);
    assert.equal(got.origin, cia.base); assert.equal(got.data.type, 'mode3-idp-auth'); assert.equal(got.data.nonce, 'n1'); assert.match(got.data.code, /^[0-9a-f]{64}$/);
    await opener.close();
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
