// tests/test_mode3_zk_assets.mjs — 회로 파일(wasm·zkey·vkey) 받기와 Cache API 캐시(lib/browser/zk_assets.js). 외부 의존 없음(unit) — caches·fetch 는 대역.
// 2026-11-20: 회로를 다시 만든 뒤에도 브라우저에 남은 옛 zkey·wasm 으로 증명해 로그인이 "예상치 못한 오류" 로 끝났다(캐시 키가 주소 이름뿐이었다).
// 세트의 버전(= 서버에서 매번 새로 받는 vkey 의 해시)을 캐시 키에 넣어, 회로가 바뀌면 새로 받고 옛 항목은 지운다.
import assert from 'node:assert/strict';
import { loadSet, ZK_CACHE_NAME } from '../lib/browser/zk_assets.js';

let failed = 0;
const t = async (name, fn) => { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.log(`FAIL ${name}\n     ${e.stack ?? e}`); } };
const enc = (s) => new TextEncoder().encode(s), dec = (b) => new TextDecoder().decode(b);
const BASE = 'https://wallet.test';
const abs = (u) => new URL(typeof u === 'string' ? u : u.url, BASE).href;
// Cache API 대역 — 키는 절대 주소(브라우저와 같다), 값은 바이트
function fakeCaches() {
  const stores = new Map();
  return { stores, async open(name) {
    if (!stores.has(name)) stores.set(name, new Map());
    const m = stores.get(name);
    return {
      async match(u) { const v = m.get(abs(u)); return v ? new Response(v) : undefined; },
      async put(u, res) { m.set(abs(u), new Uint8Array(await res.arrayBuffer())); },
      async delete(u) { return m.delete(abs(u)); },
      async keys() { return [...m.keys()].map((url) => ({ url })); },
    };
  } };
}
// 서버 대역 — files: 경로 → 내용. 받은 요청(쿼리 포함)을 적는다
function fakeServer(files) {
  const hits = [];
  const fetch = async (u, init) => { const url = new URL(u, BASE); hits.push({ path: url.pathname, search: url.search, cache: init?.cache ?? null }); const body = files[url.pathname]; return body === undefined ? new Response('no', { status: 404 }) : new Response(enc(body), { status: 200 }); };
  return { fetch, hits, files };
}
const SET = { wasm: '/zk/pi_cred.wasm', zkey: '/zk/pi_cred_final.zkey', vkey: '/zk/pi_cred_vkey.json' };
const install = (server, caches) => { globalThis.fetch = server.fetch; globalThis.caches = caches; globalThis.location = { href: `${BASE}/dist/prover_worker.js` }; };

await t('처음에는 셋 다 받고, 다음에는 vkey 만 새로 받는다(wasm·zkey 는 캐시)', async () => {
  const server = fakeServer({ [SET.wasm]: 'WASM-1', [SET.zkey]: 'ZKEY-1', [SET.vkey]: '{"protocol":"groth16","n":1}' }), caches = fakeCaches(); install(server, caches);
  const a = await loadSet(SET);
  assert.equal(dec(a.wasm), 'WASM-1'); assert.equal(dec(a.zkey), 'ZKEY-1'); assert.deepEqual(a.vkey, { protocol: 'groth16', n: 1 });
  assert.match(a.version, /^[0-9a-f]{16}$/);
  assert.deepEqual(server.hits.map((h) => h.path).sort(), [SET.vkey, SET.wasm, SET.zkey].sort());
  assert.ok(server.hits.every((h) => h.cache === 'no-store'), '브라우저 HTTP 캐시를 거치지 않는다');
  server.hits.length = 0;
  const b = await loadSet(SET);
  assert.equal(dec(b.zkey), 'ZKEY-1'); assert.equal(b.version, a.version);
  assert.deepEqual(server.hits.map((h) => h.path), [SET.vkey], 'vkey 는 매번, wasm·zkey 는 다시 받지 않는다');
});
await t('회로가 바뀌면(vkey 가 다르면) 캐시에 옛 파일이 있어도 새로 받고, 옛 항목은 지운다', async () => {
  const server = fakeServer({ [SET.wasm]: 'WASM-1', [SET.zkey]: 'ZKEY-1', [SET.vkey]: '{"n":1}' }), caches = fakeCaches(); install(server, caches);
  const a = await loadSet(SET);
  Object.assign(server.files, { [SET.wasm]: 'WASM-2', [SET.zkey]: 'ZKEY-2', [SET.vkey]: '{"n":2}' }); server.hits.length = 0;
  const b = await loadSet(SET);
  assert.equal(dec(b.wasm), 'WASM-2'); assert.equal(dec(b.zkey), 'ZKEY-2'); assert.deepEqual(b.vkey, { n: 2 }); assert.notEqual(b.version, a.version);
  const keys = [...caches.stores.get(ZK_CACHE_NAME).keys()];
  assert.equal(keys.length, 2, `옛 항목이 남았다: ${keys.join(' ')}`);
  assert.ok(keys.every((k) => k.endsWith(`?v=${b.version}`)), keys.join(' '));
});
await t('옛 앱이 이름만으로 넣어 둔 항목(버전 없음)은 쓰지 않고 지운다', async () => {
  const server = fakeServer({ [SET.wasm]: 'WASM-NEW', [SET.zkey]: 'ZKEY-NEW', [SET.vkey]: '{"n":"new"}' }), caches = fakeCaches(); install(server, caches);
  const c = await caches.open(ZK_CACHE_NAME);
  for (const [u, v] of [[SET.wasm, 'WASM-OLD'], [SET.zkey, 'ZKEY-OLD'], [SET.vkey, '{"n":"old"}']]) await c.put(u, new Response(enc(v)));
  const a = await loadSet(SET);
  assert.equal(dec(a.wasm), 'WASM-NEW'); assert.equal(dec(a.zkey), 'ZKEY-NEW'); assert.deepEqual(a.vkey, { n: 'new' });
  const keys = [...caches.stores.get(ZK_CACHE_NAME).keys()];
  assert.ok(!keys.some((k) => !k.includes('?v=')), `버전 없는 옛 항목이 남았다: ${keys.join(' ')}`);
});
await t('다른 종류(pi_idp)의 캐시는 건드리지 않는다', async () => {
  const IDP = { wasm: '/zk/pi_idp.wasm', zkey: '/zk/pi_idp_final.zkey', vkey: '/zk/pi_idp_vkey.json' };
  const server = fakeServer({ [SET.wasm]: 'W', [SET.zkey]: 'Z', [SET.vkey]: '{"k":"cred"}', [IDP.wasm]: 'IW', [IDP.zkey]: 'IZ', [IDP.vkey]: '{"k":"idp"}' }), caches = fakeCaches(); install(server, caches);
  await loadSet(IDP); await loadSet(SET); server.hits.length = 0;
  const again = await loadSet(IDP);
  assert.equal(dec(again.zkey), 'IZ'); assert.deepEqual(server.hits.map((h) => h.path), [IDP.vkey]);
});
await t('Cache API 가 없어도 받는다 · 서버가 404 면 zk_assets_unavailable', async () => {
  const server = fakeServer({ [SET.wasm]: 'W', [SET.zkey]: 'Z', [SET.vkey]: '{"n":1}' }); install(server, undefined);
  assert.equal(dec((await loadSet(SET)).zkey), 'Z');
  delete server.files[SET.zkey];
  await assert.rejects(loadSet(SET), (e) => e.reason === 'zk_assets_unavailable');
});
if (failed) { console.log(`\n${failed} 실패`); process.exit(1); }
console.log('\n모두 통과');
