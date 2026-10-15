// lib/browser/zk_assets.js — zk 산출물(wasm·zkey·vkey) 받기 + Cache API(스펙 2026-10-15 §6 워커). 진행률은 Content-Length 가 있을 때만 total 이 있다.
export const ZK_CACHE_NAME = 'mode3-zk-v1';
const fail = (msg) => Object.assign(new Error(msg), { reason: 'zk_assets_unavailable' });
async function cacheOpen() { try { return typeof caches !== 'undefined' ? await caches.open(ZK_CACHE_NAME) : null; } catch { return null; } }
export async function loadAsset(url, { onProgress = () => {} } = {}) {
  const cache = await cacheOpen();
  const hit = cache ? await cache.match(url) : null;
  if (hit) return new Uint8Array(await hit.arrayBuffer());
  // 서버는 /zk/* 를 immutable 로 내므로 기본 fetch 는 브라우저 HTTP 캐시의 옛 파일을 돌려줄 수 있다 — 앱 캐시는 Cache API(mode3-zk-v1)
  // 하나만 쓰고 HTTP 캐시는 우회한다(산출물 재생성 뒤 "모두 지우기" 가 실제로 새 파일을 받게).
  let r; try { r = await fetch(url, { cache: 'no-store' }); } catch (e) { throw fail(`${url}: ${e.message}`); }
  if (!r.ok || !r.body) throw fail(`${url}: HTTP ${r.status}`);
  const total = Number(r.headers.get('content-length')) || null;
  const reader = r.body.getReader(); const chunks = []; let loaded = 0;
  for (;;) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); loaded += value.length; onProgress({ url, loaded, total }); }
  const out = new Uint8Array(loaded); let o = 0; for (const c of chunks) { out.set(c, o); o += c.length; }
  if (cache) { try { await cache.put(url, new Response(out, { headers: { 'Content-Type': 'application/octet-stream' } })); } catch { /* 저장 공간 부족 등 — 다음에 다시 받는다 */ } }
  return out;
}
export async function loadJson(url) { return JSON.parse(new TextDecoder().decode(await loadAsset(url))); }
