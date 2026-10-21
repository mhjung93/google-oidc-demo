// mode3/user/core/vault.js — 비밀 금고(스펙 D1·§3, 계획 R3). meta(공개)·secrets(암호문)·unlock(추출 불가 CryptoKey + 만료) 세 레코드.
// 2026-10-16: **자동 금고(mode:'auto')** — 비밀번호 없이 setup(null) 하면 추출 불가 AES-GCM 키를 만들어 unlock 레코드에 만료 없이 둔다.
// 비밀은 여전히 암호문으로만 저장되지만, 보호 경계는 비밀번호가 아니라 브라우저의 오리진 격리다(데모 단순화 — 사용자 요청). 잠그기·비밀번호 변경은 없다.
// 비밀번호 금고(옛 등록)는 그대로 동작한다.
import { createMeta, openMeta, deriveKey, randomSaltHex, makeCheck, encryptJson, decryptJson, KDF_ITERATIONS } from '../../../lib/browser/secret_box.js';
export const UNLOCK_TTL_MS = 30 * 60_000;
const EMPTY_SECRETS = () => ({ s_u: null, sk_u: null, blind_u: null, sessionKeys: {} });
const locked = () => Object.assign(new Error('locked'), { reason: 'locked' });
export function createVault(kv, { now = Date.now, ttlMs = UNLOCK_TTL_MS } = {}) {
  // meta 는 kv 에서 읽어 메모리에 둔다(공개값). unlock 은 **매번 kv 에서** 읽는다 — 팝업·다른 탭이 지우거나 바꾼 것을 바로 보기 위해(R3).
  // hasVault()·isUnlocked() 는 동기다(화면 배지·테스트가 await 없이 읽는다) — 마지막으로 kv 에서 본 값의 메모리 사본으로 답한다.
  // 권위 있는 판정은 key()(async)이고, key()·refresh() 가 사본을 맞춘다. 다른 탭의 변화를 화면에 보이려면 refresh() 를 먼저 부른다
  // (user_core.status() 가 부른다).
  let meta = null;          // null = 아직 안 읽음, false = 금고 없음, 객체 = meta
  let unlockedUntil = 0;    // 마지막으로 본 unlock 레코드의 만료(ms). 0 = 잠김
  const load = async (force = false) => { if (meta === null || force) meta = (await kv.get('meta')) ?? false; return meta || null; };
  const v = {
    hasVault() { return Boolean(meta); },
    isUnlocked() { return unlockedUntil > now(); },
    /** kv 를 다시 읽어 동기 사본을 맞춘다 — 다른 탭(팝업)이 금고를 만들거나 잠그거나 지운 것을 반영한다. */
    async refresh() { await load(true); await v.key(); return { hasVault: v.hasVault(), isUnlocked: v.isUnlocked() }; },
    /** 자동 금고인가(비밀번호 없음). meta 를 읽은 뒤에만 답할 수 있다. */
    isAuto() { return Boolean(meta && meta.mode === 'auto'); },
    async key() {
      const u = (await kv.get('unlock')) ?? null;
      if (!u) { unlockedUntil = 0; return null; }
      if (u.expiresAt !== null && !(u.expiresAt > now())) { await kv.del('unlock'); unlockedUntil = 0; return null; }
      unlockedUntil = u.expiresAt === null ? Infinity : u.expiresAt;
      return u.key;
    },
    async setup(password) {
      if (await load(true)) throw new Error('이미 금고가 있다');
      if (password === null || password === undefined || password === '') {
        // 자동 금고: 키는 추출 불가로 만들어 IndexedDB 에만 둔다(비밀번호 유도 없음, 만료 없음).
        const key = await globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        const m = { v: 1, mode: 'auto', createdAt: now() };
        await kv.set('meta', m); meta = m;
        await kv.set('secrets', await encryptJson(key, EMPTY_SECRETS()));
        await kv.set('unlock', { key, expiresAt: null }); unlockedUntil = Infinity;
        return true;
      }
      const { meta: m, key } = await createMeta(password);
      await kv.set('meta', m); meta = m;
      await kv.set('secrets', await encryptJson(key, EMPTY_SECRETS()));
      await v._remember(key);
      return true;
    },
    async unlock(password) {
      // meta 는 다시 읽는다 — 다른 탭이 비밀번호를 바꿨으면 옛 meta 로는 새 비밀번호가 안 맞는다.
      const m = await load(true); if (!m) return false;
      if (m.mode === 'auto') return Boolean(await v.key());   // 자동 금고는 비밀번호가 없다 — 키가 있으면 늘 열려 있다
      const key = await openMeta(password, m); if (!key) return false;
      await v._remember(key); return true;
    },
    async _remember(key) { const expiresAt = now() + ttlMs; await kv.set('unlock', { key, expiresAt }); unlockedUntil = expiresAt; },
    async lock() { if ((await load())?.mode === 'auto') return false; await kv.del('unlock'); unlockedUntil = 0; return true; },   // 자동 금고는 잠그면 키를 잃으므로 잠그지 않는다
    async readSecrets() { const key = await v.key(); if (!key) throw locked(); const box = await kv.get('secrets'); return box ? await decryptJson(key, box) : EMPTY_SECRETS(); },
    async writeSecrets(obj) { const key = await v.key(); if (!key) throw locked(); await kv.set('secrets', await encryptJson(key, obj)); },
    async changePassword(oldPw, newPw) {
      const m = await load(true); if (!m || m.mode === 'auto') return false;   // 자동 금고에는 비밀번호가 없다
      const oldKey = await openMeta(oldPw, m); if (!oldKey) return false;
      const plain = await decryptJson(oldKey, (await kv.get('secrets')) ?? await encryptJson(oldKey, EMPTY_SECRETS()));
      const salt = randomSaltHex(); const key = await deriveKey(newPw, salt);
      const nm = { ...m, kdf: { salt, iterations: KDF_ITERATIONS }, check: await makeCheck(key) };
      await kv.set('secrets', await encryptJson(key, plain)); await kv.set('meta', nm); meta = nm;
      await v._remember(key); return true;
    },
    /** wipe 뒤 메모리도 비운다 — user_core.wipe() 가 부른다. */
    reset() { meta = null; unlockedUntil = 0; },
  };
  return v;
}
