// mode3/user/core/kv_idb.js — IndexedDB `mode3-user`(v1) 의 객체 저장소 `kv` 하나에 { key, value } 를 둔다(스펙 2026-10-15 §3). CryptoKey(추출 불가)도 그대로 저장된다(계획 R3).
const req = (r) => new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
export async function openIdbKv(name = 'mode3-user', version = 1) {
  if (typeof indexedDB === 'undefined') throw Object.assign(new Error('IndexedDB 없음'), { reason: 'storage_unavailable' });
  let db;
  try {
    const open = indexedDB.open(name, version);
    open.onupgradeneeded = () => { if (!open.result.objectStoreNames.contains('kv')) open.result.createObjectStore('kv'); };
    db = await req(open);
  } catch (e) { throw Object.assign(new Error(`IndexedDB 열기 실패: ${e?.message ?? e}`), { reason: 'storage_unavailable' }); }
  const tx = (mode) => db.transaction('kv', mode).objectStore('kv');
  return {
    get: (k) => req(tx('readonly').get(k)),
    set: (k, v) => req(tx('readwrite').put(v, k)).then(() => {}),
    del: (k) => req(tx('readwrite').delete(k)).then(() => {}),
    clear: () => req(tx('readwrite').clear()).then(() => {}),
    keys: () => req(tx('readonly').getAllKeys()),
  };
}
