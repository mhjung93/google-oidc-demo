// Mode 3 브라우저 경로 — 실제 Chrome 에서 지갑 페이지·승인 팝업·RP 페이지를 돌린다(스펙 2026-09-22 metamask-snap §7).
// MetaMask 는 tests/helpers/ethereum_stub.js 가 대신하고, Snap 은 **진짜 snap-mode3/src/index.js 의 onRpcRequest** 가 답한다
// (Task 5 Ruling 5 — 시뮬레이터가 아니다). 대화상자 답과 체인 전송만 이 하네스가 맡는다.
// hardhat :8545 와 build/mode3 의 pi_cred zkey·vkey 필요. (chain 그룹)
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
  await context.exposeFunction('__snapDialog', (params) => {
    dialogs.push(params);
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
    answers.push(true);                        // consentLogin 확인
    const before = dialogs.length;
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#loginBtn')]);
    assert.ok(popup.url().includes('authorize=1'), `팝업 URL: ${popup.url()}`);
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
    assert.equal(dialogs.length, before + 1, '로그인 동의 대화상자 한 번');
    assert.ok(lastDialog().includes(rp.origin), `동의 창이 서비스 오리진을 보여 준다: ${lastDialog().slice(0, 300)}`);
    if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 10_000 });
    assert.ok((await text(rpPage, '#log')).includes('3. RP 검증'), 'RP 페이지가 /api/mode3/login 까지 냈다');
    assert.equal((await text(rpPage, '#sessionId')).includes('(없음)'), false, '세션이 잡혔다');
    // 팝업 결과에는 지갑 안 정보가 실리지 않는다(스펙 §3.2) — 그래도 Snap 에는 새 C_u 가 저장돼 있어야 한다.
    assert.ok(snapState.userCred?.blind_u, '팝업이 userCredIssued 를 Snap 에 저장했다');
    assert.equal((await rp.get('/api/mode3/logins')).body.logins.length, 1);
    // 목록의 r_s 는 잘라 보여 주는 값이라, 전체 r_s 는 RP 페이지가 들고 있는 것을 그대로 읽는다(전역 스크립트라 이름이 보인다).
    sessionRs = await rpPage.evaluate(() => (typeof currentSession === 'undefined' ? null : currentSession));
    assert.match(String(sessionRs), /^[0-9]+$/, 'RP 페이지가 세션 r_s 를 들고 있다');
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
    const log = await text(rpPage, '#sessionLog');
    assert.ok(log.includes('재승인 팝업을 연다'), log);
    assert.ok(log.includes('재승인 완료'), log);
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

  await t('동의 거절: Snap 이 denied 를 주면 RP 에 user_denied 가 돌아오고 새 세션은 생기지 않는다', async () => {
    const before = (await rp.get('/api/mode3/logins')).body.logins.length;
    answers.push(false);                       // consentLogin 거절
    const [popup] = await Promise.all([context.waitForEvent('page'), rpPage.click('#loginBtn')]);
    await waitText(rpPage, '#verdict', 'user_denied', 120_000);
    if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 10_000 });
    assert.equal((await rp.get('/api/mode3/logins')).body.logins.length, before, '거절은 로그인을 남기지 않는다');
  });
} finally {
  await browser.close();
  await stack.stop();
  provider.destroy();
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
// 다른 Mode 3 테스트와 같은 관례 — 남는 핸들 때문에 저절로 끝나지 않는다
process.exit(failed === 0 ? 0 : 1);
