// tests/test_mode3_user_static.mjs — 사용자 정적 서버(web 모드)의 라우트·CORS·존재 신호. :8545 필요(health 의 chain 조회), 번들은 여기서 만든다. (chain)
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
const stack = await startIsolatedMode3Stack({ userMode: 'web' });
const { wallet, rp, cia } = stack;
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.message); } }
const hdr = (r, k) => r.headers.get(k);
try {
  await t('/ 와 /?authorize=1 은 index.html(data-page="wallet"), /dist/user.js·/dist/prover_worker.js·/common/demo.js 가 200', async () => {
    for (const p of ['/', '/?authorize=1']) { const r = await wallet.raw(p); assert.equal(r.status, 200); assert.ok((await r.text()).includes('data-page="wallet"'), p); }
    for (const p of ['/dist/user.js', '/dist/prover_worker.js', '/common/demo.js', '/common/strings.js']) assert.equal((await wallet.raw(p)).status, 200, p);
  });
  await t('/zk/* 는 허용 이름 6개만 — vkey 는 JSON, 그 밖은 404, immutable 캐시 헤더', async () => {
    for (const n of ['pi_cred.wasm', 'pi_cred_final.zkey', 'pi_cred_vkey.json', 'pi_idp.wasm', 'pi_idp_final.zkey', 'pi_idp_vkey.json']) {
      const r = await wallet.raw(`/zk/${n}`, { method: 'HEAD' });
      assert.equal(r.status, 200, n); assert.match(hdr(r, 'cache-control') ?? '', /immutable/);
    }
    const v = await (await wallet.raw('/zk/pi_cred_vkey.json')).json(); assert.equal(v.protocol, 'groth16');
    for (const n of ['pi_cred.r1cs', '../package.json', 'x.zkey']) assert.equal((await wallet.raw(`/zk/${encodeURIComponent(n)}`)).status, 404, n);
  });
  await t('/user/config 는 같은 오리진 전용(CORS 없음)이고 공개 설정만 싣는다', async () => {
    const r = await wallet.raw('/user/config', { headers: { Origin: rp.origin } });
    const b = await r.json();
    assert.equal(r.status, 200); assert.equal(hdr(r, 'access-control-allow-origin'), null);
    assert.equal(b.secrets, 'web'); assert.equal(b.ciaUrl, cia.base); assert.equal(b.logAddress, cia.logAddress); assert.equal(b.mirrorAddress, cia.mirrorAddress);
    assert.deepEqual(b.rpOrigins, [rp.origin]); assert.equal(b.ttlBlocks, '300'); assert.equal(b.heightGrid, '100'); assert.equal(b.relayPath, '/api/mode3/relay');
    assert.match(b.chainId, /^[0-9]+$/);
    for (const k of ['s_u', 'sk_u', 'uid', 'secret']) assert.ok(!JSON.stringify(b).includes(`"${k}"`), k);
  });
  await t('/wallet/config 는 에이전트와 같은 키, RP 오리진에만 CORS', async () => {
    const ok = await wallet.raw('/wallet/config', { headers: { Origin: rp.origin } });
    assert.equal(hdr(ok, 'access-control-allow-origin'), rp.origin);
    assert.deepEqual(Object.keys(await ok.json()).sort(), ['chainId', 'rpcUrl', 'secrets', 'snapId', 'walletOrigin']);
    assert.equal((await wallet.get('/wallet/config')).body.secrets, 'web');
    assert.equal(hdr(await wallet.raw('/wallet/config', { headers: { Origin: 'http://evil.example' } }), 'access-control-allow-origin'), null);
  });
  await t('/mode3/health: role wallet·secrets web·기본 false/0, RP·IdP 오리진에만 CORS, 민감 키 없음', async () => {
    const r = await wallet.raw('/mode3/health', { headers: { Origin: rp.origin } });
    const h = await r.json();
    assert.equal(hdr(r, 'access-control-allow-origin'), rp.origin); assert.equal(hdr(r, 'cache-control'), 'no-store');
    assert.equal(h.role, 'wallet'); assert.equal(h.secrets, 'web'); assert.equal(h.registered, false); assert.equal(h.sessions, 0); assert.equal(h.rpCount, 0); assert.ok(h.chain?.head);
    assert.equal(hdr(await wallet.raw('/mode3/health', { headers: { Origin: cia.base } }), 'access-control-allow-origin'), cia.base);
    assert.equal(hdr(await wallet.raw('/mode3/health', { headers: { Origin: 'http://evil.example' } }), 'access-control-allow-origin'), null);
    for (const k of ['uid', 'PPID', 'sk_u', 'pk_u', 'arid', 'r_s']) assert.ok(!JSON.stringify(h).includes(`"${k}"`), k);
  });
  await t('/wallet/presence: 형식 검사 400, 반영된 값이 health 에 나온다, CORS 없음', async () => {
    assert.equal((await wallet.post('/wallet/presence', { registered: 'yes' })).status, 400);
    assert.equal((await wallet.post('/wallet/presence', { registered: true, hasCred: true, sessions: 2, rpCount: 1, txs: 3, disclosedTxs: 1, uid: '12345' })).status, 400, '모르는 키도 400');
    const ok = await wallet.post('/wallet/presence', { registered: true, hasCred: true, sessions: 2, rpCount: 2, txs: 3, disclosedTxs: 1 });
    assert.equal(ok.status, 200);
    const h = (await wallet.get('/mode3/health')).body;
    assert.equal(h.registered, true); assert.equal(h.hasCred, true); assert.equal(h.sessions, 2); assert.equal(h.rpCount, 2); assert.equal(h.txs, 3); assert.equal(h.disclosedTxs, 1);
    const pre = await wallet.raw('/wallet/presence', { method: 'OPTIONS', headers: { Origin: rp.origin, 'Access-Control-Request-Method': 'POST' } });
    assert.equal(hdr(pre, 'access-control-allow-origin'), null);
  });
  await t('restartWallet() 뒤에도 web 모드이고 presence 는 초기화된다', async () => {
    await stack.restartWallet();
    assert.equal((await wallet.get('/wallet/config')).body.secrets, 'web');
    assert.equal((await wallet.get('/mode3/health')).body.registered, false);
  });
} finally { await stack.stop(); }
process.exit(fails ? 1 : 0);
