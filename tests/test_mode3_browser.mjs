// Mode 3 브라우저 경로 — 실제 Chrome 에서 지갑 페이지·승인 팝업·RP 페이지를 돌린다(스펙 2026-09-22 metamask-snap §7).
// MetaMask 는 tests/helpers/ethereum_stub.js 가 대신하고, Snap 은 **진짜 snap-mode3/src/index.js 의 onRpcRequest** 가 답한다
// (Task 5 Ruling 5 — 시뮬레이터가 아니다). 대화상자 답과 체인 전송만 이 하네스가 맡는다.
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
const stack = await startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'snap' } });
const { wallet, rp } = stack;

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
    assert.ok(snapState.registration.sk_u, 'storeRegistration 이 sk_u 를 넣었다');
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
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#loginBtn')]);
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

  await t('비밀은 Snap 에만: 에이전트 응답·양쪽 페이지 DOM·브라우저 저장소 어디에도 s_u·r_u·sk_u·blind_u 가 없다', async () => {
    const secrets = {
      s_u: snapState.registration.s_u, r_u: snapState.registration.r_u,
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

  // ---- 공개 트랜잭션: MetaMask(스텁)가 배포·execute 를 보낸다 ----
  const info = (await rp.get('/api/mode3/rp_info')).body;
  await t('공개 트랜잭션: 슬롯 0·1 공개(mask 3) 로 AttrGate.claim 이 성공한다', async () => {
    assert.ok(info.attrGateAddress, 'AttrGate 가 배포돼 있어야 한다');
    await walletPage.click('#refreshBtn');
    await walletPage.waitForFunction(() => !document.querySelector('#txBtn').disabled, undefined, { timeout: 15_000 });
    await walletPage.fill('#txTo', info.attrGateAddress);
    await walletPage.fill('#txData', '0x4e71d92d');
    await walletPage.check('#dk0'); await walletPage.fill('#discLo0', '0'); await walletPage.fill('#discHi0', '2007');
    await walletPage.check('#dk1'); await walletPage.fill('#discLo1', '410'); await walletPage.fill('#discHi1', '410');
    answers.push(true);                        // consentDisclosure 확인
    const before = dialogs.length;
    await walletPage.click('#txBtn');
    await waitText(walletPage, '#txVerdict', '전송 성공', 180_000);
    assert.equal(dialogs.length, before + 1, '공개 동의 대화상자 한 번');
    assert.ok(lastDialog().includes('410'), `동의 창이 공개 구간을 보여 준다: ${lastDialog().slice(0, 300)}`);
    const log = await text(walletPage, '#txLog');
    assert.ok(log.includes('배포 txHash='), '첫 트랜잭션은 CREATE2 배포를 먼저 보낸다');
    assert.ok(log.includes('온체인 공개(Disclosure 이벤트)'), '영수증 파싱 결과가 표시된다');
    assert.equal(sentTxs.length, 2, `스텁이 배포+execute 두 건을 보냈다: ${j(sentTxs)}`);
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
      await rpPage.click('#loginBtn');
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
      [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#loginBtn')]);
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
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#loginBtn')]);
    await waitText(rpPage, '#verdict', 'user_denied', 120_000);
    await awaitPopupClosed(popup);
    assert.equal((await rp.get('/api/mode3/logins')).body.logins.length, before, '거절은 로그인을 남기지 않는다');
  });
  // 최종 리뷰 Important 2: AA 가 속성을 바꾸면 다음 로그인 응답에 attrsChanged 와 **새** userCredIssued 가 함께 실린다.
  // 지갑 페이지의 applyPendingToSnap 은 syncAttrs 를 먼저 하고(속성이 바뀌면 Snap 이 옛 C_u 를 함께 버린다) 새 C_u 를
  // 그 뒤에 저장해야 한다 — 순서를 뒤집으면 갓 저장한 C_u 가 지워져 아래 "C_u 가 남아 있다" 단언이 깨진다.
  await t('AA 속성 변경 뒤 로그인: Snap 의 속성이 갱신되고 새 C_u 가 남는다(syncAttrs → updateUserCred 순서)', async () => {
    const beforeCf = snapState.userCred?.Cf_u ?? null;
    assert.ok(beforeCf, '시작 시 Snap 에 C_u 가 있다');
    assert.deepEqual(snapState.registration.attrs, ['1990', '410', '2', '0']);
    assert.equal((await stack.cia.adminPost('/cia/accounts/12345/attrs', { attrs: ['1990', '410', '3', '0'] })).status, 200);
    assert.equal((await stack.cia.adminPost('/cia/publish')).body.published, true);
    answers.push(true);                        // 로그인 동의
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#loginBtn')]);
    await waitText(rpPage, '#verdict', '로그인 성공', 240_000);
    await awaitPopupClosed(popup);
    assert.deepEqual(snapState.registration.attrs, ['1990', '410', '3', '0'], 'syncAttrs 가 Snap 의 속성을 갱신했다');
    assert.ok(snapState.userCred, '새 C_u 가 Snap 에 남아 있어야 한다(syncAttrs 를 나중에 하면 지워진다)');
    assert.notEqual(snapState.userCred.Cf_u, beforeCf, '옛 C_u 가 아니라 새로 받은 것이다');
    assert.equal((await wallet.get('/wallet/status')).body.userCred.Cf_u, snapState.userCred.Cf_u, '에이전트의 공개 Cf_u 와 같다');
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
