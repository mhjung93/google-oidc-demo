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
const base = (port, extra = {}) => ({ MODE3_WALLET_PORT: String(port), MODE3_WALLET_PUBLIC_ORIGIN: `http://localhost:${port}`, CIA_RPC_URL: CHAIN, MODE3_REV_CHAIN_RPC: CHAIN, ...extra });
const start = async (name, env) => { const port = await freePort(); const child = await spawnServer('mode3_user_static.js', { env: base(port, env), readyUrl: `http://127.0.0.1:${port}/user/config`, logFile: path.join(tmp, `${name}.log`) }); return { port, child, url: `http://127.0.0.1:${port}` }; };
// 기동 거부: 10초 안에 종료 코드 ≠ 0 이어야 한다.
const refuses = (env) => new Promise((resolve, reject) => {
  const c = spawn('node', ['mode3_user_static.js'], { env: { ...process.env, ...PINNED_ENV, ...base(env.port ?? 5199), ...env.set }, stdio: ['ignore', 'pipe', 'pipe'] });
  let err = ''; c.stderr.on('data', (d) => { err += d; }); c.stdout.on('data', () => {});
  const tm = setTimeout(() => { c.kill('SIGKILL'); reject(new Error('10초 안에 종료하지 않았다')); }, 10_000);
  c.on('exit', (code) => { clearTimeout(tm); resolve({ code, err }); });
});

const pw = await start('pw', { MODE3_WALLET_SECRETS: 'passkey-web' });
try {
  await t('config', async () => {
    const c = await (await fetch(`${pw.url}/user/config`)).json();
    assert.equal(c.secrets, 'passkey-web'); assert.equal(c.rpcUrl, '/rpc/app'); assert.equal(c.revRpcUrl, '/rpc/rev'); assert.equal(c.passkeyHoldSeconds, 600);
    assert.equal((await (await fetch(`${pw.url}/wallet/config`)).json()).secrets, 'passkey-web');
    assert.equal((await (await fetch(`${pw.url}/mode3/health`)).json()).secrets, 'passkey-web');
  });
  await t('프록시 eth_chainId = 직접 호출', async () => {
    const a = await (await rpc(`${pw.url}/rpc/app`, rq('eth_chainId'))).json();
    const b = await (await rpc(`${pw.url}/rpc/rev`, rq('eth_chainId'))).json();
    const d = await (await rpc(CHAIN, rq('eth_chainId'))).json();
    assert.equal(a.result, d.result); assert.equal(b.result, d.result);
  });
  await t('배치 300건', async () => {
    const body = Array.from({ length: 300 }, (_, i) => rq('eth_blockNumber', i));
    assert.ok(JSON.stringify(body).length > 16 * 1024);
    const r = await rpc(`${pw.url}/rpc/app`, body);
    assert.equal(r.status, 200); assert.equal((await r.json()).length, 300);
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
    assert.equal(r.headers.get('access-control-allow-origin'), null);
  });
  await t('상류 실패 502', async () => {
    const dead = await start('dead', { MODE3_WALLET_SECRETS: 'passkey-web', CIA_RPC_URL: `http://127.0.0.1:${await freePort()}`, MODE3_REV_CHAIN_RPC: '' });
    try { const r = await rpc(`${dead.url}/rpc/app`, rq('eth_chainId')); assert.equal(r.status, 502); assert.equal((await r.json()).reason, 'chain_unavailable'); } finally { await stopChild(dead.child); }
  });
  await t('속성 도구', async () => {
    const h = await fetch(`${pw.url}/attr.html`); assert.equal(h.status, 200); assert.match(h.headers.get('content-type'), /text\/html/);
    assert.equal((await fetch(`${pw.url}/attr/dist/attr.js`)).status, 200);
  });
} finally { await stopChild(pw.child); }

await t('기동 거부', async () => {
  const cases = [
    { set: { MODE3_WALLET_SECRETS: 'passkey-web', MODE3_WALLET_PUBLIC_ORIGIN: 'https://127.0.0.1:5199' }, err: 'passkey-web' },
    { set: { MODE3_WALLET_SECRETS: 'passkey-web', MODE3_WALLET_PUBLIC_ORIGIN: 'http://wallet.zkd.test:5199' }, err: 'passkey-web' },
    { set: { MODE3_WALLET_SECRETS: 'bogus' } },
    { set: { MODE3_PASSKEY_HOLD_SECONDS: '-1' } },
  ];
  for (const c of cases) {
    const r = await refuses(c);
    assert.notEqual(r.code, 0, JSON.stringify(c.set));
    if (c.err) assert.match(r.err, new RegExp(c.err), JSON.stringify(c.set));
  }
});

const web = await start('web', {});
try {
  await t('web 회귀', async () => {
    const c = await (await fetch(`${web.url}/user/config`)).json();
    assert.equal(c.secrets, 'web'); assert.match(c.rpcUrl, /^http:\/\//);
  });
} finally { await stopChild(web.child); }
fs.rmSync(tmp, { recursive: true, force: true });
if (fails) { console.log(`\n${fails} FAILED`); process.exit(1); }
console.log('\nall ok');
