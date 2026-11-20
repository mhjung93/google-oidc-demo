// lib/browser/zk_assets.js — zk 산출물(wasm·zkey·vkey) 받기 + Cache API(스펙 2026-10-15 §6 워커). 진행률은 Content-Length 가 있을 때만 total 이 있다.
// 2026-11-20: 캐시 키에 세트의 버전을 넣는다. 전에는 키가 주소 이름뿐이라, 회로를 다시 만든 뒤에도 브라우저가 옛 zkey·wasm 으로 증명해
// 로그인이 "예상치 못한 오류" 로 끝났다("모두 지우기" 를 눌러야만 새로 받았다). 버전은 서버에서 **매번 새로 받는 vkey 의 해시**다 — vkey 는 작고(수 KB)
// zkey 가 바뀌면 함께 바뀐다. 서버·번들에 버전 값을 따로 두지 않으므로 회로만 다시 만들어도 다음 로드가 스스로 알아챈다.
export const ZK_CACHE_NAME = 'mode3-zk-v1';
const fail = (msg) => Object.assign(new Error(msg), { reason: 'zk_assets_unavailable' });
async function cacheOpen() { try { return typeof caches !== 'undefined' ? await caches.open(ZK_CACHE_NAME) : null; } catch { return null; } }
const here = () => globalThis.location?.href ?? 'http://localhost/';
const pathOf = (u) => new URL(u, here()).pathname;
/** 서버에서 바로 받는다. 서버는 /zk/* 를 immutable 로 내므로 기본 fetch 는 브라우저 HTTP 캐시의 옛 파일을 돌려줄 수 있다 — 늘 HTTP 캐시를 우회한다. */
async function fetchBytes(url, { onProgress = () => {} } = {}) {
  let r; try { r = await fetch(url, { cache: 'no-store' }); } catch (e) { throw fail(`${url}: ${e.message}`); }
  if (!r.ok || !r.body) throw fail(`${url}: HTTP ${r.status}`);
  const total = Number(r.headers.get('content-length')) || null;
  const reader = r.body.getReader(); const chunks = []; let loaded = 0;
  for (;;) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); loaded += value.length; onProgress({ url, loaded, total }); }
  const out = new Uint8Array(loaded); let o = 0; for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}
/** 같은 파일의 다른 버전(버전 없는 옛 항목 포함)을 캐시에서 지운다 — 수십 MB 짜리 옛 zkey 가 쌓이지 않게. 실패해도 넘어간다. */
async function pruneOthers(cache, url, key) {
  try {
    const keep = new URL(key, here()).href, path = pathOf(url);
    for (const req of await cache.keys()) { const u = new URL(req.url, here()); if (u.pathname === path && u.href !== keep) await cache.delete(req.url); }
  } catch { /* 정리 실패는 동작에 영향이 없다 */ }
}
/** 파일 하나. version 을 주면 캐시 키·요청 주소에 ?v=version 을 붙이고(서버는 쿼리를 보지 않는다) 같은 파일의 다른 버전을 지운다. version 이 없으면 캐시를 쓰지 않는다. */
export async function loadAsset(url, { onProgress = () => {}, version = null } = {}) {
  if (!version) return fetchBytes(url, { onProgress });
  const key = `${url}?v=${version}`;
  const cache = await cacheOpen();
  const hit = cache ? await cache.match(key) : null;
  if (hit) return new Uint8Array(await hit.arrayBuffer());
  const out = await fetchBytes(key, { onProgress });
  if (cache) {
    try { await cache.put(key, new Response(out, { headers: { 'Content-Type': 'application/octet-stream' } })); } catch { /* 저장 공간 부족 등 — 다음에 다시 받는다 */ }
    await pruneOthers(cache, url, key);
  }
  return out;
}
/** JSON 하나(vkey) — 늘 서버에서 새로 받는다(캐시하지 않는다). */
export async function loadJson(url) { return JSON.parse(new TextDecoder().decode(await fetchBytes(url))); }
/** 한 회로의 산출물 세트 { wasm, zkey, vkey(주소) } → { wasm, zkey(바이트), vkey(객체), version }. vkey 를 먼저 새로 받아 그 SHA-256 앞 16자를 세트의 버전으로 쓴다. */
export async function loadSet({ wasm, zkey, vkey }, { onProgress = () => {} } = {}) {
  const vk = await fetchBytes(vkey);
  const version = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', vk)), (b) => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
  const [w, z] = await Promise.all([loadAsset(wasm, { onProgress, version }), loadAsset(zkey, { onProgress, version })]);
  const cache = await cacheOpen();
  if (cache) { try { await cache.delete(vkey); } catch { /* 옛 앱이 넣어 둔 vkey 항목 — 못 지워도 쓰지 않는다 */ } }
  return { wasm: w, zkey: z, vkey: JSON.parse(new TextDecoder().decode(vk)), version };
}
