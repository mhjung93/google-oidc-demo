// lib/browser/secret_box.js — 사용자 페이지의 비밀 금고 원시 연산(스펙 2026-10-15 D1·§3). WebCrypto 만 쓴다(브라우저·Node 22 공통).
//   비밀번호 → PBKDF2(SHA-256, 310,000회, salt 16B) → AES-GCM-256 키(기본 추출 불가 — 계획 R3: IndexedDB 에 CryptoKey 로 보관해도
//   원시 키 바이트는 꺼낼 수 없다). 비밀 JSON 은 iv 12B 와 함께 암호화한다. meta.check 는 'mode3-user' 의 암호문 — 비밀번호 검증용.
export const KDF_ITERATIONS = 310000;
export const SALT_BYTES = 16;
export const CHECK_PLAINTEXT = 'mode3-user';
const subtle = () => globalThis.crypto.subtle;
const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const badPassword = (msg = 'bad_password') => Object.assign(new Error(msg), { reason: 'bad_password' });

export function randomSaltHex() { const s = new Uint8Array(SALT_BYTES); globalThis.crypto.getRandomValues(s); return toHex(s); }

export async function deriveKey(password, saltHex, iterations = KDF_ITERATIONS, { extractable = false } = {}) {
  if (typeof password !== 'string' || !password) throw new Error('deriveKey: 비밀번호 문자열이 필요하다');
  if (!/^[0-9a-f]{32}$/.test(saltHex)) throw new Error('deriveKey: salt 는 16바이트 hex');
  const base = await subtle().importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return subtle().deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(saltHex), iterations }, base, { name: 'AES-GCM', length: 256 }, extractable, ['encrypt', 'decrypt']);
}
export async function encryptJson(key, obj) {
  const iv = new Uint8Array(12); globalThis.crypto.getRandomValues(iv);
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj)));
  return { iv: toHex(iv), ct: toHex(new Uint8Array(ct)) };
}
export async function decryptJson(key, box) {
  if (!box || typeof box.iv !== 'string' || typeof box.ct !== 'string') throw badPassword('secret box 형식');
  let pt;
  try { pt = await subtle().decrypt({ name: 'AES-GCM', iv: fromHex(box.iv) }, key, fromHex(box.ct)); }
  catch { throw badPassword(); }   // WebCrypto 는 키 불일치·손상을 모두 OperationError 로 낸다 — 구분하지 않는다
  return JSON.parse(new TextDecoder().decode(pt));
}
export const makeCheck = (key) => encryptJson(key, CHECK_PLAINTEXT);
export async function verifyCheck(key, box) {
  try { return (await decryptJson(key, box)) === CHECK_PLAINTEXT; } catch { return false; }
}
export async function createMeta(password) {
  const salt = randomSaltHex();
  const key = await deriveKey(password, salt);
  return { meta: { version: 1, createdAt: new Date().toISOString(), kdf: { salt, iterations: KDF_ITERATIONS }, check: await makeCheck(key) }, key };
}
export async function openMeta(password, meta) {
  if (!meta || meta.version !== 1 || !meta.kdf?.salt) throw new Error('openMeta: meta 형식');
  let key;
  try { key = await deriveKey(password, meta.kdf.salt, meta.kdf.iterations); } catch { return null; }
  return (await verifyCheck(key, meta.check)) ? key : null;
}
