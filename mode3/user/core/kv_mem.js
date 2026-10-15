// mode3/user/core/kv_mem.js — 메모리 키-값(테스트·IndexedDB 없는 환경의 대체). kv 계약: get/set/del/clear/keys 전부 Promise.
export function createMemKv() {
  const m = new Map();
  return { async get(k) { return m.get(k); }, async set(k, v) { m.set(k, v); }, async del(k) { m.delete(k); }, async clear() { m.clear(); }, async keys() { return [...m.keys()]; } };
}
