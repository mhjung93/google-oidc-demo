// GET /mode3/health 실제 응답·CORS. :8545 필요. node tests/test_mode3_health.mjs
import assert from 'node:assert/strict';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
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
await stack.stop();
if (fails) { console.log(`\n${fails} FAIL`); process.exit(1); } console.log('\nall ok');
