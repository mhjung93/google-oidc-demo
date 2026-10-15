// mode3/user/core/vault.js — 비밀 금고(스펙 D1·§3, 계획 R3). meta(공개)·secrets(암호문)·unlock(추출 불가 CryptoKey + 만료) 세 레코드.
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
    async key() {
      const u = (await kv.get('unlock')) ?? null;
      if (!u) { unlockedUntil = 0; return null; }
      if (!(u.expiresAt > now())) { await kv.del('unlock'); unlockedUntil = 0; return null; }
      unlockedUntil = u.expiresAt;
      return u.key;
    },
    async setup(password) {
      if (await load(true)) throw new Error('이미 금고가 있다');
      const { meta: m, key } = await createMeta(password);
      await kv.set('meta', m); meta = m;
      await kv.set('secrets', await encryptJson(key, EMPTY_SECRETS()));
      await v._remember(key);
      return true;
    },
    async unlock(password) {
      // meta 는 다시 읽는다 — 다른 탭이 비밀번호를 바꿨으면 옛 meta 로는 새 비밀번호가 안 맞는다.
      const m = await load(true); if (!m) return false;
      const key = await openMeta(password, m); if (!key) return false;
      await v._remember(key); return true;
    },
    async _remember(key) { const expiresAt = now() + ttlMs; await kv.set('unlock', { key, expiresAt }); unlockedUntil = expiresAt; },
    async lock() { await kv.del('unlock'); unlockedUntil = 0; },
    async readSecrets() { const key = await v.key(); if (!key) throw locked(); const box = await kv.get('secrets'); return box ? await decryptJson(key, box) : EMPTY_SECRETS(); },
    async writeSecrets(obj) { const key = await v.key(); if (!key) throw locked(); await kv.set('secrets', await encryptJson(key, obj)); },
    async changePassword(oldPw, newPw) {
      const m = await load(true); if (!m) return false;
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
