// lib/browser/zk_assets.js — zk 산출물(wasm·zkey·vkey) 받기 + Cache API(스펙 2026-10-15 §6 워커). 진행률은 Content-Length 가 있을 때만 total 이 있다.
const CACHE = 'mode3-zk-v1';
const fail = (msg) => Object.assign(new Error(msg), { reason: 'zk_assets_unavailable' });
async function cacheOpen() { try { return typeof caches !== 'undefined' ? await caches.open(CACHE) : null; } catch { return null; } }
export async function loadAsset(url, { onProgress = () => {} } = {}) {
  const cache = await cacheOpen();
  const hit = cache ? await cache.match(url) : null;
  if (hit) return new Uint8Array(await hit.arrayBuffer());
  let r; try { r = await fetch(url); } catch (e) { throw fail(`${url}: ${e.message}`); }
  if (!r.ok || !r.body) throw fail(`${url}: HTTP ${r.status}`);
  const total = Number(r.headers.get('content-length')) || null;
  const reader = r.body.getReader(); const chunks = []; let loaded = 0;
  for (;;) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); loaded += value.length; onProgress({ url, loaded, total }); }
  const out = new Uint8Array(loaded); let o = 0; for (const c of chunks) { out.set(c, o); o += c.length; }
  if (cache) { try { await cache.put(url, new Response(out, { headers: { 'Content-Type': 'application/octet-stream' } })); } catch { /* 저장 공간 부족 등 — 다음에 다시 받는다 */ } }
  return out;
}
export async function loadJson(url) { return JSON.parse(new TextDecoder().decode(await loadAsset(url))); }
