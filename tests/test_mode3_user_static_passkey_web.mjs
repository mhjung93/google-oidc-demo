// tests/test_mode3_user_static_passkey_web.mjs — 정적 서버의 passkey-web 설정·RPC 프록시·속성 도구·기동 거부. :8545 필요. (chain)
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { freePort } from './helpers/isolated_cia.mjs';
import { spawnServer, stopChild, PINNED_ENV } from './helpers/isolated_mode3_stack.mjs';

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
execFileSync('node', ['scripts/build_attr_tool.mjs'], { stdio: 'inherit' });
const CHAIN = 'http://127.0.0.1:8545';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'm3-static-pw-'));
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const rpc = (url, body) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const rq = (method, id = 1) => ({ jsonrpc: '2.0', id, method, params: [] });
// 서비스 오리진(CORS 허용 목록)도 고정한다 — 셸의 MODE3_RP_ORIGIN 이 새지 않게, CORS 단언이 이 값을 허용 오리진으로 쓴다.
// IdP 주소도 고정한다(CSP connect-src 단언이 이 값을 쓴다) — .env 의 MODE3_CIA_URL 이 새지 않게. 아무것도 듣지 않는 주소라 health 의 IdP 확인은 조용히 실패한다.
const RP_ORIGIN = 'http://127.0.0.1:3999', FOREIGN = 'http://evil.example', CIA = 'http://127.0.0.1:3998';
const base = (port, extra = {}) => ({ MODE3_WALLET_PORT: String(port), MODE3_WALLET_PUBLIC_ORIGIN: `http://localhost:${port}`, MODE3_RP_ORIGIN: RP_ORIGIN, MODE3_CIA_URL: CIA, CIA_RPC_URL: CHAIN, MODE3_REV_CHAIN_RPC: CHAIN, ...extra });
/** CSP 헤더를 지시어 → 값 목록으로. 헤더가 없으면 null. */
const cspOf = (res) => { const h = res.headers.get('content-security-policy'); return h === null ? null : Object.fromEntries(h.split(';').map((d) => d.trim()).filter(Boolean).map((d) => { const [k, ...v] = d.split(/\s+/); return [k, v]; })); };
/** 인라인(src 없는) <script> 의 수 — 주석 안의 글자는 세지 않는다. */
const inlineScripts = (html) => [...html.replace(/<!--[\s\S]*?-->/g, '').matchAll(/<script\b([^>]*)>/gi)].filter((m) => !/\bsrc\s*=/.test(m[1])).length;
const start = async (name, env) => { const port = await freePort(); const child = await spawnServer('mode3_user_static.js', { env: base(port, env), readyUrl: `http://127.0.0.1:${port}/user/config`, logFile: path.join(tmp, `${name}.log`) }); return { port, child, url: `http://127.0.0.1:${port}` }; };
// 기동 거부: 10초 안에 종료 코드 ≠ 0 이어야 한다. 포트는 빈 포트를 받는다(고정 포트가 사용 중이면 EADDRINUSE 로 "거부된 것처럼" 보인다 —
// 그래서 각 경우의 stderr 도 그 경우의 사유 문구와 대조한다). spawn 실패('error')도 reject 로 — 멈추지 않는다.
const refuses = (env) => new Promise((resolve, reject) => {
  freePort().then((port) => {
    const c = spawn('node', ['mode3_user_static.js'], { env: { ...process.env, ...PINNED_ENV, ...base(port), ...env.set }, stdio: ['ignore', 'pipe', 'pipe'] });
    let err = ''; c.stderr.on('data', (d) => { err += d; }); c.stdout.on('data', () => {});
    const tm = setTimeout(() => { c.kill('SIGKILL'); reject(new Error('10초 안에 종료하지 않았다')); }, 10_000);
    c.on('error', (e) => { clearTimeout(tm); reject(e); });
    c.on('exit', (code) => { clearTimeout(tm); resolve({ code, err }); });
  }, reject);
});

const pw = await start('pw', { MODE3_WALLET_SECRETS: 'passkey-web' });
try {
  await t('config', async () => {
    const c = await (await fetch(`${pw.url}/user/config`)).json();
    assert.equal(c.secrets, 'passkey-web'); assert.equal(c.rpcUrl, '/rpc/app'); assert.equal(c.revRpcUrl, '/rpc/rev');
    assert.equal('passkeyHoldSeconds' in c, false, 'salt 보관 시간 설정은 없다(2026-11-20: 10분 보관 제거)');
    assert.equal((await (await fetch(`${pw.url}/wallet/config`)).json()).secrets, 'passkey-web');
    assert.equal((await (await fetch(`${pw.url}/mode3/health`)).json()).secrets, 'passkey-web');
  });
  // 2026-11-18(사용자 요청): passkey-web 의 승인 창은 승인·거절 단계를 두지 않는다(기본). MODE3_POPUP_CONSENT=1 이면 다시 켠다.
  await t('승인 단계 설정 — passkey-web 기본은 끔, MODE3_POPUP_CONSENT=1 이면 켬', async () => {
    assert.equal((await (await fetch(`${pw.url}/user/config`)).json()).popupConsent, false);
    // 2026-11-18: 탐색기 주소(증명 기록의 거래 링크) — 안 주면 null, 주면 끝의 / 를 떼고 그대로.
    assert.equal((await (await fetch(`${pw.url}/user/config`)).json()).explorerUrl, null);
    const on = await start('pw-consent', { MODE3_WALLET_SECRETS: 'passkey-web', MODE3_POPUP_CONSENT: '1', MODE3_EXPLORER_URL: 'http://127.0.0.1:4000/' });
    try { const c = await (await fetch(`${on.url}/user/config`)).json(); assert.equal(c.popupConsent, true); assert.equal(c.explorerUrl, 'http://127.0.0.1:4000'); } finally { await stopChild(on.child); }
  });
  await t('프록시 eth_chainId = 직접 호출', async () => {
    const a = await (await rpc(`${pw.url}/rpc/app`, rq('eth_chainId'))).json();
    const b = await (await rpc(`${pw.url}/rpc/rev`, rq('eth_chainId'))).json();
    const d = await (await rpc(CHAIN, rq('eth_chainId'))).json();
    assert.equal(a.result, d.result); assert.equal(b.result, d.result);
  });
  await t('배치 100건(16kb 넘는 본문)', async () => {
    // 전역 파서(16kb)보다 큰 본문이 /rpc 에서는 통과하는지 — 배치 상한(100) 안에서 eth_call 데이터로 크기를 채운다.
    const call = (i) => ({ jsonrpc: '2.0', id: i, method: 'eth_call', params: [{ to: '0x' + '00'.repeat(20), data: '0x' + 'ab'.repeat(120) }, 'latest'] });
    const body = Array.from({ length: 100 }, (_, i) => call(i));
    assert.ok(JSON.stringify(body).length > 16 * 1024);
    const r = await rpc(`${pw.url}/rpc/app`, body);
    assert.equal(r.status, 200); assert.equal((await r.json()).length, 100);
  });
  // 2026-11-17(미뤄 둔 Minor C): 상류 부하 상한 — 100건을 넘는 배치는 체인에 보내지 않고 400 rpc_batch_too_large.
  await t('배치 101건은 400 rpc_batch_too_large', async () => {
    const r = await rpc(`${pw.url}/rpc/app`, Array.from({ length: 101 }, (_, i) => rq('eth_blockNumber', i)));
    assert.equal(r.status, 400); assert.equal((await r.json()).reason, 'rpc_batch_too_large');
  });
  // 2026-11-17(미뤄 둔 Minor C): 1mb 를 넘는 본문은 500 internal 이 아니라 413 payload_too_large(전역 16kb 파서도 같은 처리).
  await t('1mb 넘는 본문은 413 payload_too_large', async () => {
    const r = await rpc(`${pw.url}/rpc/app`, { jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: ['x'.repeat(1_100_000)] });
    assert.equal(r.status, 413); assert.equal((await r.json()).reason, 'payload_too_large');
    const p = await fetch(`${pw.url}/wallet/presence`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pad: 'x'.repeat(20_000) }) });
    assert.equal(p.status, 413); assert.equal((await p.json()).reason, 'payload_too_large');
  });
  await t('막힌 메서드', async () => {
    const r = await rpc(`${pw.url}/rpc/app`, rq('eth_sendTransaction'));
    assert.equal(r.status, 403); assert.equal((await r.json()).reason, 'rpc_method_blocked');
    const before = (await (await rpc(CHAIN, rq('eth_blockNumber'))).json()).result;
    const r2 = await rpc(`${pw.url}/rpc/app`, [rq('eth_blockNumber', 1), rq('evm_mine', 2)]);
    assert.equal(r2.status, 403);
    const after = (await (await rpc(CHAIN, rq('eth_blockNumber'))).json()).result;
    assert.equal(before, after);
  });
  await t('형식·메서드', async () => {
    assert.equal((await fetch(`${pw.url}/rpc/app`)).status, 405);
    const r = await rpc(`${pw.url}/rpc/app`, {});
    assert.equal(r.status, 400); assert.equal((await r.json()).reason, 'malformed');
  });
  // 2026-11-17(미뤄 둔 Minor C): CORS 단언에 실제 Origin 을 싣는다 — Origin 없는 요청에는 어차피 ACAO 가 없어 전에는 아무것도 보지 않았다.
  // 대조군: 같은 서버의 /wallet/config 는 허용 오리진(서비스)에 ACAO 를 준다(이 단언이 헤더를 제대로 보는지). /rpc 는 같은 오리진 전용이라 허용 오리진에도 주지 않는다.
  await t('CORS: /rpc 는 허용·남의 오리진 모두 ACAO 없음(대조: /wallet/config 는 허용 오리진에 준다)', async () => {
    const cfgOk = await fetch(`${pw.url}/wallet/config`, { headers: { Origin: RP_ORIGIN } });
    assert.equal(cfgOk.headers.get('access-control-allow-origin'), RP_ORIGIN, '대조군: 허용 오리진에 ACAO');
    const cfgNo = await fetch(`${pw.url}/wallet/config`, { headers: { Origin: FOREIGN } });
    assert.equal(cfgNo.headers.get('access-control-allow-origin'), null, '대조군: 남의 오리진에는 ACAO 없음');
    for (const origin of [RP_ORIGIN, FOREIGN]) {
      const r = await fetch(`${pw.url}/rpc/app`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify(rq('eth_chainId')) });
      assert.equal(r.status, 200, origin); assert.equal(r.headers.get('access-control-allow-origin'), null, `POST ${origin}`);
      const pre = await fetch(`${pw.url}/rpc/app`, { method: 'OPTIONS', headers: { Origin: origin, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' } });
      assert.equal(pre.headers.get('access-control-allow-origin'), null, `OPTIONS ${origin}`);
    }
  });
  await t('상류 실패 502', async () => {
    const dead = await start('dead', { MODE3_WALLET_SECRETS: 'passkey-web', CIA_RPC_URL: `http://127.0.0.1:${await freePort()}`, MODE3_REV_CHAIN_RPC: '' });
    try { const r = await rpc(`${dead.url}/rpc/app`, rq('eth_chainId')); assert.equal(r.status, 502); assert.equal((await r.json()).reason, 'chain_unavailable'); } finally { await stopChild(dead.child); }
  });
  await t('속성 도구', async () => {
    const h = await fetch(`${pw.url}/attr.html`); assert.equal(h.status, 200); assert.match(h.headers.get('content-type'), /text\/html/);
    assert.equal((await fetch(`${pw.url}/attr/dist/attr.js`)).status, 200);
  });
  // 2026-11-17: passkey-web 의 salt 는 지갑 오리진의 JS 메모리에 있다(2026-11-20 부터 IndexedDB 에는 두지 않는다) — 그 오리진에서 남의 스크립트가 돌지 못하게 CSP 를 건다.
  await t('CSP: 페이지·워커·속성 도구 응답에 같은 정책 — 인라인·남의 스크립트 없음, 연결은 자기·IdP·서비스만', async () => {
    const want = {
      'default-src': ["'self'"], 'script-src': ["'self'", "'wasm-unsafe-eval'"], 'worker-src': ["'self'", 'blob:'],
      'connect-src': ["'self'", CIA, RP_ORIGIN], 'img-src': ["'self'", 'data:'], 'style-src': ["'self'", "'unsafe-inline'"],
      'object-src': ["'none'"], 'base-uri': ["'none'"], 'frame-ancestors': ["'none'"], 'form-action': ["'none'"],
    };
    for (const p of ['/', '/attr.html', '/dist/prover_worker.js', '/dist/user.js', '/user/config']) {
      const r = await fetch(`${pw.url}${p}`); assert.equal(r.status, 200, p);
      assert.deepEqual(cspOf(r), want, p);
    }
  });
  await t('CSP: 지갑 오리진의 HTML 에 인라인 <script> 가 없다(속성 도구 스크립트는 /attr/attr_page.js)', async () => {
    for (const p of ['/', '/attr.html']) assert.equal(inlineScripts(await (await fetch(`${pw.url}${p}`)).text()), 0, p);
    const js = await fetch(`${pw.url}/attr/attr_page.js`); assert.equal(js.status, 200); assert.match(js.headers.get('content-type'), /javascript/);
  });
  // 2026-11-19: Google 로그인 중계 — Google 이 돌아올 주소로 받는 것은 공개 도메인·localhost 뿐이라 이 서버의 /google-relay 가 토큰 조각을 서비스 페이지로 넘긴다.
  await t('Google 중계 화면: /google-relay(HTML, 인라인 스크립트 없음)·/google-relay.js 를 내고 CSP 가 붙는다 — 넘길 곳은 /user/config 의 rpOrigins', async () => {
    const h = await fetch(`${pw.url}/google-relay`); assert.equal(h.status, 200); assert.match(h.headers.get('content-type'), /text\/html/);
    const html = await h.text(); assert.equal(inlineScripts(html), 0); assert.ok(html.includes('src="/google-relay.js"'));
    assert.ok(h.headers.get('content-security-policy'), 'CSP 헤더');
    const js = await fetch(`${pw.url}/google-relay.js`); assert.equal(js.status, 200); assert.match(js.headers.get('content-type'), /javascript/);
    const src = await js.text(); assert.ok(src.includes('rpOrigins') && src.includes('allowed.includes(target)'), '아는 서비스 오리진으로만 넘긴다');
    assert.ok(Array.isArray((await (await fetch(`${pw.url}/user/config`)).json()).rpOrigins));
  });
} finally { await stopChild(pw.child); }

await t('기동 거부', async () => {
  const cases = [
    { set: { MODE3_WALLET_SECRETS: 'passkey-web', MODE3_WALLET_PUBLIC_ORIGIN: 'https://127.0.0.1:5199' }, err: /passkey-web: 오리진은 IP 가 아닌 호스트/ },
    { set: { MODE3_WALLET_SECRETS: 'passkey-web', MODE3_WALLET_PUBLIC_ORIGIN: 'http://wallet.zkd.test:5199' }, err: /passkey-web: 오리진은 IP 가 아닌 호스트/ },
    { set: { MODE3_WALLET_SECRETS: 'bogus' }, err: /MODE3_WALLET_SECRETS 는 web 또는 passkey-web.*bogus/ },
  ];
  for (const c of cases) {
    const r = await refuses(c);
    assert.notEqual(r.code, 0, JSON.stringify(c.set));
    assert.match(r.err, c.err, `${JSON.stringify(c.set)} — 그 경우의 사유로 거부해야 한다(포트 충돌 등 다른 이유가 아니라)`);
  }
});

const web = await start('web', {});
try {
  await t('web 회귀', async () => {
    const c = await (await fetch(`${web.url}/user/config`)).json();
    assert.equal(c.secrets, 'web'); assert.match(c.rpcUrl, /^http:\/\//);
    assert.equal(c.popupConsent, true, 'web 모드는 승인 단계를 그대로 둔다');
  });
  await t('web 모드에는 CSP 헤더가 없다(passkey-web 전용)', async () => {
    for (const p of ['/', '/attr.html', '/dist/prover_worker.js', '/user/config']) assert.equal((await fetch(`${web.url}${p}`)).headers.get('content-security-policy'), null, p);
  });
} finally { await stopChild(web.child); }
fs.rmSync(tmp, { recursive: true, force: true });
if (fails) { console.log(`\n${fails} FAILED`); process.exit(1); }
console.log('\nall ok');
