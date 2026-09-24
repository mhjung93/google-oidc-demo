// GET /mode3/health 실제 응답·CORS. :8545 필요. node tests/test_mode3_health.mjs
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { createShare } from '../lib/mode3_trace.js';
const stack = await startIsolatedMode3Stack();
const { cia, rp, wallet } = stack;
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.message); } }
const get = (base, origin) => fetch(`${base}/mode3/health`, { headers: origin ? { Origin: origin } : {} });
await t('세 서버가 role·ok·chain 을 준다', async () => {
  for (const [b, role] of [[cia.base, 'aa'], [rp.base, 'rp'], [wallet.base, 'wallet']]) { const r = await get(b); const j = await r.json(); assert.equal(r.status, 200); assert.equal(j.role, role); assert.equal(j.ok, true); assert.ok(j.chain?.head, `${role} chain`); assert.equal(r.headers.get('cache-control'), 'no-store'); }
});
await t('민감 키 없음(전 깊이)', async () => {
  const bad = ['uid', 'PPID', 'secret', 'sk_u', 'pk_u', 'pk_CIA', 'arid', 'r_s'];
  for (const b of [cia.base, rp.base, wallet.base]) { const s = JSON.stringify(await (await get(b)).json()); for (const k of bad) assert.ok(!s.includes(`"${k}"`), `${b} has ${k}`); }
});
await t('CORS: 허용 오리진에만 헤더', async () => {
  assert.equal((await get(rp.base, wallet.origin)).headers.get('access-control-allow-origin'), wallet.origin);
  assert.equal((await get(rp.base, 'http://evil.example')).headers.get('access-control-allow-origin'), null);
  assert.equal((await get(wallet.base, rp.origin)).headers.get('access-control-allow-origin'), rp.origin);
  assert.equal((await get(cia.base, wallet.origin)).headers.get('access-control-allow-origin'), wallet.origin);   // MODE3_WALLET_AGENT_ORIGIN
  assert.equal((await get(cia.base, rp.origin)).headers.get('access-control-allow-origin'), rp.origin);           // 승인된 서비스
  assert.equal((await get(cia.base, 'http://evil.example')).headers.get('access-control-allow-origin'), null);
});
await t('RP: approved·active, 지갑: 미등록·ciaReachable', async () => {
  const r = await (await get(rp.base)).json(); assert.equal(r.status, 'approved'); assert.equal(r.active, true); assert.equal(typeof r.maxRootAge, 'number');
  const w = await (await get(wallet.base)).json(); assert.equal(w.registered, false); assert.equal(w.ciaReachable, true);
});
// 헬퍼는 자기 RP 를 승인해 둔다 — 승인 전 상태는 CIA 에 직접 등록한 두 번째 서비스로 본다(승인 전에는 허용 목록에 없다).
await t('AA CORS: 승인 전 서비스 오리진은 거부, 승인 뒤 허용', async () => {
  const pendingOrigin = 'http://127.0.0.1:59999';
  const share = await createShare();
  const reg = await cia.post('/cia/register_rp', { name: 'pending-rp', origin: pendingOrigin, pk_service: ethers.Wallet.createRandom().address, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() } });
  assert.equal(reg.status, 202, JSON.stringify(reg.body));
  const before = await get(cia.base, pendingOrigin);
  assert.equal(before.headers.get('access-control-allow-origin'), null, '승인 전에는 CORS 헤더가 없어야 한다');
  const bj = await before.json();
  assert.ok(bj.pendingRps >= 1, `pendingRps ${bj.pendingRps}`);
  assert.ok(!bj.rpOrigins.includes(pendingOrigin), 'rpOrigins 에 승인 전 서비스가 들어가면 안 된다');
  const ap = await cia.adminPost(`/cia/rps/${reg.body.arid}/approve`);
  assert.equal(ap.status, 200, JSON.stringify(ap.body));
  const after = await get(cia.base, pendingOrigin);
  assert.equal(after.headers.get('access-control-allow-origin'), pendingOrigin);
  assert.ok((await after.json()).rpOrigins.includes(pendingOrigin));
});
await t('Vary: Origin 은 허용·거절 모두에 붙는다(중간 캐시가 응답을 섞지 않게)', async () => {
  const has = (r) => (r.headers.get('vary') ?? '').toLowerCase().split(',').map((v) => v.trim()).includes('origin');
  assert.ok(has(await get(rp.base, wallet.origin)), '허용 경로');
  assert.ok(has(await get(rp.base, 'http://evil.example')), '거절 경로');
  assert.ok(has(await get(wallet.base, rp.origin)) && has(await get(cia.base, wallet.origin)), '지갑·AA 허용 경로');
});
await stack.stop();
if (fails) { console.log(`\n${fails} FAIL`); process.exit(1); } console.log('\nall ok');
