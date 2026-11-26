// 추적 기록의 화면 흐름(스펙 2026-11-26 ppid-account-trace) — zkWrapper 방식. 첫 로그인이 기록을 남기고(실제 π_trace 가 로그인 요청에 실려 가고, 서비스가 로그인을 확인한 뒤 올린다), 서비스 관리자의 개봉 요청(체인의 거래)이
// /user 의 "개봉 알림" 에 뜨고, 감사자 둘의 응답 뒤 zkWrapper 관리자가 열면 그 Google 계정이 나온다. 기록이 없으면 서비스가 로그인을 받지 않는다.
// :8545 · build/mode3(pi_cred·pi_trace) · Chrome 필요. (browser)
//   node tests/test_mode3_trace_browser.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { chromium } from '@playwright/test';
import { ethers } from 'ethers';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { buildWebAuthnStub } from './helpers/webauthn_stub.js';
import { uidOf } from '../lib/mode3_oidc_nonce.js';
import { traceRegistryAt, registryPk } from '../lib/mode3_trace_chain.js';

const j = (o) => JSON.stringify(o);
let fails = 0; async function t(n, f) { try { await f(); console.log('ok  ', n); } catch (e) { fails++; console.log('FAIL', n, '\n    ', e.stack ?? e.message); } }
if (!fs.existsSync('build/mode3/pi_trace_final.zkey')) { console.log('BLOCKED: build/mode3/pi_trace_* 가 없다 — bash scripts/build_mode3_circuit.sh pi_trace'); process.exit(1); }
execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
const RPC = 'http://127.0.0.1:8545', AUD_PORT = '5393';
const AUD_TOKEN = 'test-auditor-token-fedcba9876543210fedcba9876543210';   // 테스트 고정값
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkd-aud-b-'));
const setup = execFileSync('node', ['scripts/mode3_trace_setup.mjs'], { env: { ...process.env, RPC, MODE3_AUDITOR_DIR: dir }, encoding: 'utf8' });
const REG = /MODE3_TRACE_REGISTRY=(0x[0-9a-fA-F]{40})/.exec(setup)[1];
const auditors = spawn('node', ['mode3_auditors.js'], { env: { ...process.env, MODE3_AUDITOR_DIR: dir, MODE3_AUDITOR_RPC: RPC, MODE3_TRACE_REGISTRY: REG, MODE3_AUDITOR_PORT: AUD_PORT, MODE3_AUDITOR_POLL_MS: '500', MODE3_AUDITOR_TOKEN: AUD_TOKEN }, stdio: 'ignore' });
const TRACE_ENV = { MODE3_TRACE_REGISTRY: REG, MODE3_AUDITOR_URL: `http://127.0.0.1:${AUD_PORT}`, MODE3_AUDITOR_TOKEN: AUD_TOKEN };
let browser = null, stack = null;
try {
  for (const opts of [{ channel: 'chrome' }, {}]) { try { browser = await chromium.launch(opts); break; } catch { browser = null; } }
  if (!browser) throw new Error('BLOCKED: 브라우저를 띄우지 못했다');
  stack = await startIsolatedMode3Stack({ userMode: 'zkwrapper', walletHost: 'localhost', wrapper: true, autoRelay: true,
    walletEnv: { MODE3_WALLET_SECRETS: 'passkey-web', MODE3_WRAPPER: '1', MODE3_WRAPPER_CLIENT_ID: 'mode3-test-client', ...TRACE_ENV }, rpEnv: { MODE3_WALLET_KIND: 'zkwrapper', ...TRACE_ENV },
    ciaEnv: { MODE3_WALLET_KIND: 'passkey-web', MODE3_OIDC_REDIRECT_URI: '{walletOrigin}/google-relay', ...TRACE_ENV },
    extraRps: [{ name: 'zkTWO', env: { MODE3_WALLET_KIND: 'zkwrapper', ...TRACE_ENV } }] });
  const { cia, wallet, rp } = stack, google = stack.oidc;
  const registry = traceRegistryAt(REG, new ethers.JsonRpcProvider(RPC));
  const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
  const waitText = async (page, sel, needle, timeout = 30_000) => page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout }).catch(async () => { throw new Error(`${sel} 에 "${needle}" 없음: ${(await text(page, sel).catch(() => '?')).slice(0, 300)}`); });
  async function newBrowser(secretHex) {
    const ctx = await browser.newContext(), reqs = [];
    await ctx.route('**/attr/dist/reset.json', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"epoch":"test-epoch","walletKind":"zkwrapper"}' }));
    await ctx.exposeFunction('__webauthnHit', () => {});
    await ctx.addInitScript({ content: buildWebAuthnStub({ secretHex }) });
    ctx.on('dialog', (d) => d.accept());
    ctx.on('request', (r) => reqs.push({ url: r.url(), method: r.method(), body: r.method() === 'POST' && r.url().endsWith('/api/mode3/login') ? r.postData() : null }));
    return { ctx, reqs };
  }
  /** 서비스에서 zk 로그인 — 결과 칸의 글자를 돌려준다(성공·실패 모두). first: 이 브라우저에 패스키가 없어 만드는 로그인. */
  async function login(B, sub, email, { first = false } = {}) {
    google.setNextSub(sub); google.setNextClaims({ email, email_verified: true });
    const page = await B.ctx.newPage(); await page.goto(`${rp.base}/`);
    await page.waitForFunction(() => { const a = document.getElementById('loginBtn'), b = document.getElementById('logoutBtn'); return (a && !a.hidden) || (b && b.offsetParent !== null); }, null, { timeout: 20_000 });
    if (await page.$eval('#loginBtn', (b) => b.hidden)) { await page.click('#logoutBtn'); await page.waitForSelector('#loginBtn:not([hidden])'); }
    await page.click('#loginBtn');
    const [popup] = await Promise.all([B.ctx.waitForEvent('page'), page.click('#idpLoginBtn')]);
    if (first) { await popup.waitForSelector('#authWrapPasskeyBtn', { timeout: 30_000 }); await popup.click('#authWrapPasskeyBtn'); }
    await page.waitForFunction(() => /로그인 성공|로그인 실패|없습니다|못했습니다|않습니다/.test(document.getElementById('verdict')?.textContent ?? ''), null, { timeout: 120_000 });
    const verdict = await text(page, '#verdict');
    const me = await page.evaluate(() => fetch('/api/rp/me').then((r) => (r.ok ? r.json() : null)).catch(() => null));
    await page.close();
    return { verdict, PPID: me?.seen?.PPID ? String(me.seen.PPID) : null };
  }
  const openUser = async (B) => {
    const page = await B.ctx.newPage(); await page.goto(`${wallet.base}/user`); await page.waitForSelector('#mainView:not([hidden])');
    await page.waitForFunction(() => ['userLockCard', 'sessionsCard'].some((id) => document.getElementById(id)?.checkVisibility() === true), null, { timeout: 15_000 });
    if (await page.evaluate(() => document.getElementById('userLockCard')?.checkVisibility() === true)) await page.click('#userUnlockBtn');
    await page.waitForSelector('#sessionsCard', { state: 'visible', timeout: 15_000 });
    return page;
  };
  const A = await newBrowser('a1'.repeat(32));
  let ppidA = null;

  await t('설정: 지갑 설정과 서비스 정보가 같은 등록부 주소를 알리고, 지갑 설정에는 감사자 키가 고정돼 있다(zkWrapper 서버가 자기 노드에서 읽은 값 — 검토 I-2)', async () => {
    const cfg = await (async () => { for (let i = 0; i < 20; i++) { const c = (await wallet.get('/user/config')).body.trace; if (c?.pk) return c; await new Promise((r) => setTimeout(r, 500)); } return (await wallet.get('/user/config')).body.trace; })();
    assert.equal(cfg?.registry, REG); assert.equal((await rp.get('/api/mode3/rp_info')).body.trace?.registry, REG);
    const pk = await registryPk(registry); assert.deepEqual(cfg.pk, { x: pk.x.toString(), y: pk.y.toString() });
  });
  await t('첫 로그인이 추적 기록을 남긴다 — 기록이 로그인 요청에 실려 가고(따로 열린 등록 길은 없다), 체인에 그 PPID 의 기록이 생긴다; 다음 로그인은 싣지 않는다', async () => {
    const logins = () => A.reqs.filter((x) => x.body !== null && x.url === `${rp.base}/api/mode3/login`).map((x) => JSON.parse(x.body));
    const r1 = await login(A, 'google-user-T', 'tee@example.com', { first: true });
    assert.ok(r1.verdict.includes('로그인 성공'), r1.verdict); ppidA = r1.PPID; assert.ok(ppidA, 'PPID');
    assert.equal(await registry.has(ppidA), true, '체인에 기록이 없다');
    assert.equal(logins().length, 1); assert.equal(logins()[0].trace?.ppid, ppidA, '첫 로그인에 기록이 실리지 않았다');
    assert.equal((await rp.post('/api/mode3/trace/register', {})).status, 404, '따로 열린 등록 길이 남아 있다');
    assert.ok(!A.reqs.some((x) => x.url.includes('/trace/register')));
    const r2 = await login(A, 'google-user-T', 'tee@example.com');
    assert.ok(r2.verdict.includes('로그인 성공'), r2.verdict); assert.equal(r2.PPID, ppidA);
    const r3 = await login(A, 'google-user-T', 'tee@example.com');
    assert.ok(r3.verdict.includes('로그인 성공'), r3.verdict);
    assert.equal(logins().length, 3); assert.equal(logins()[2].trace, undefined, '체인에서 기록을 확인한 뒤에도 다시 실었다');
    const rec = await registry.recordOf(ppidA); assert.equal(rec.arid.toString(), String((await rp.get('/api/mode3/rp_info')).body.arid));
  });
  let userPage = null;
  await t('/user "개봉 알림": 요청이 없을 때는 없다고 말하고 지켜보는 계정 수를 보인다', async () => {
    userPage = await openUser(A);
    await userPage.waitForSelector('#traceCard:not([hidden])', { timeout: 20_000 });
    assert.equal(await userPage.$eval('#traceEmpty', (e) => e.hidden), false); assert.ok((await text(userPage, '#traceState')).includes('1개'), await text(userPage, '#traceState'));
  });
  await t('서비스 관리자의 개봉 요청은 체인의 거래다 — 관리자 비밀번호가 없으면 401, 기록 없는 PPID 는 404, 맞으면 요청 번호가 나온다', async () => {
    assert.equal((await rp.post('/api/mode3/trace/open', { PPID: ppidA, reason: '테스트' })).status, 401);
    assert.equal((await rp.post('/api/mode3/trace/open', { PPID: '12345', reason: '테스트' }, rp.adminHeaders)).body.reason, 'trace_not_registered');
    for (const reason of [undefined, '', '   ', 'x'.repeat(201)]) assert.equal((await rp.post('/api/mode3/trace/open', { PPID: ppidA, reason }, rp.adminHeaders)).body.reason, 'trace_bad_request', `사유 ${JSON.stringify(reason)?.slice(0, 12)}`);
    assert.equal(Number(await registry.requestCount()), 0, '사유 없는 요청이 체인에 나갔다');
    const r = await rp.post('/api/mode3/trace/open', { PPID: ppidA, reason: '테스트' }, rp.adminHeaders);
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.id, 0);
    assert.equal((await registry.requestOf(0)).ppid.toString(), ppidA);
  });
  await t('사용자 화면에 알림이 뜬다 — 서비스 이름·요청 번호, 감사자 둘이 응답하면 2/3', async () => {
    await userPage.waitForFunction(() => document.querySelectorAll('#traceList li').length === 1, null, { timeout: 30_000 });
    const li = await text(userPage, '#traceList li'); assert.ok(li.includes('zkONE') && li.includes('#0'), li);
    await userPage.waitForFunction(() => (document.querySelector('#traceList li')?.textContent ?? '').includes('2/3'), null, { timeout: 40_000 });
    assert.equal(await userPage.$eval('#traceEmpty', (e) => e.hidden), true);
  });
  await t('zkWrapper 관리자가 연다: 감사자 둘의 부분 복호를 합쳐 그 Google 계정이 나온다 — 화면의 목록에도 열림으로 보인다', async () => {
    const list = await cia.adminGet('/cia/admin/trace/requests'); assert.equal(list.status, 200, j(list.body));
    assert.equal(list.body.enabled, true); assert.equal(list.body.requests.length, 1); assert.deepEqual(list.body.requests[0].shares, [1, 2]);
    const svcName = list.body.requests[0].service; assert.ok(typeof svcName === 'string' && svcName.length > 0, '서비스 이름(발급 서버에 등록된 이름)이 없다');
    assert.equal((await cia.post('/cia/admin/trace/0/open', {})).status, 401, '관리자 인증 없이 열렸다');
    assert.equal((await fetch(`http://127.0.0.1:${AUD_PORT}/shares/0`)).status, 401, '감사자가 토큰 없이 조각을 내줬다');
    const o = await cia.adminPost('/cia/admin/trace/0/open'); assert.equal(o.status, 200, j(o.body));
    assert.equal(o.body.resolved, true); assert.equal(o.body.uid, uidOf(google.provider, 'google-user-T')); assert.equal(o.body.logins[0].email, 'tee@example.com'); assert.deepEqual(o.body.used.sort(), [1, 2]);
    assert.equal((await cia.adminPost('/cia/admin/trace/7/open')).body.reason, 'trace_unknown_request');
    const p = await A.ctx.newPage(); await p.goto(`${wallet.base}/admin`);
    await p.fill('#adminGate .gate-pwd', cia.adminSecret); await p.click('#adminGate .gate-form button[type=submit]');
    await p.click('#openingsBtn');
    await p.waitForFunction(() => (document.querySelector('#traceReqs li')?.textContent ?? '').includes('tee@example.com'), null, { timeout: 20_000 });
    assert.ok((await text(p, '#traceReqs li')).includes(svcName), await text(p, '#traceReqs li')); await p.close();
  });
  await t('기록 없이는 로그인되지 않는다 — 로그인 요청에서 기록을 떼면 trace_required, 기록을 바꾸면 컨트랙트가 거절(trace_bad_proof), 그대로 보내면 로그인된다', async () => {
    const B = await newBrowser('b2'.repeat(32));
    try {
      const tamper = (fn) => B.ctx.route('**/api/mode3/login', (route) => { const b = JSON.parse(route.request().postData()); fn(b); return route.continue({ postData: JSON.stringify(b) }); });
      await tamper((b) => { delete b.trace; });
      const r1 = await login(B, 'google-user-U', 'you@example.com', { first: true });
      assert.ok(!r1.verdict.includes('로그인 성공') && r1.verdict.includes('추적 기록이 없습니다'), r1.verdict);
      await B.ctx.unroute('**/api/mode3/login');
      await tamper((b) => { b.trace.c2 = (BigInt(b.trace.c2) + 1n).toString(); });
      const r2 = await login(B, 'google-user-U', 'you@example.com');
      assert.ok(!r2.verdict.includes('로그인 성공') && r2.verdict.includes('증명이 맞지 않습니다'), r2.verdict);
      await B.ctx.unroute('**/api/mode3/login');
      const r3 = await login(B, 'google-user-U', 'you@example.com');
      assert.ok(r3.verdict.includes('로그인 성공'), r3.verdict); assert.equal(await registry.has(r3.PPID), true);
    } finally { await B.ctx.close(); }
  });
  await t('남의 서비스의 계정은 요청하지 못한다(trace_not_mine) — 서비스는 자기 arid 의 기록만 개봉을 요청한다', async () => {
    const other = stack.rps[1];
    const n0 = Number(await registry.requestCount());
    assert.equal((await other.post('/api/mode3/trace/open', { PPID: ppidA, reason: '테스트' }, other.adminHeaders)).body.reason, 'trace_not_mine');
    assert.equal(Number(await registry.requestCount()), n0, '남의 계정의 요청이 체인에 나갔다');
  });
  if (userPage) await userPage.close();
  await A.ctx.close();
} catch (e) { fails++; console.log('FAIL (준비)', e.stack ?? e.message); } finally {
  if (stack) await stack.stop().catch(() => {});
  if (browser) await browser.close().catch(() => {});
  auditors.kill(); fs.rmSync(dir, { recursive: true, force: true });
}
console.log(fails ? `\n${fails} 실패` : '\n모두 통과');
process.exit(fails ? 1 : 0);
