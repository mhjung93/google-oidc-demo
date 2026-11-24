// lib/mode3_salt_envelope.js — zkWrapper 의 salt 봉투(계획 2026-11-24 zkwrapper salt-envelope, Global Constraints). 서버(cia.js)·테스트(Node 22)·브라우저 번들이 같이 쓴다.
// WebCrypto(globalThis.crypto)만 쓴다 — node:crypto 도 새 의존성도 없다.
//
// 봉투 = AES-GCM-256(K, utf8(s_u 10진), AAD = "zkd-env-v1|uid|id|kind|credentialId") — 서버는 암호문만 가지고, 열쇠 K 는 패스키 PRF 또는 복구 코드에서만 나온다.
// AAD 에 uid·id·kind·credentialId 를 넣어, 다른 계정·다른 봉투·다른 종류의 암호문을 끼워 넣으면 열리지 않게 한다.
export const BACKUP_LIMIT = 5;
export const DEVICE_LIMIT = 10;
export const ENV_KINDS = ['passkey', 'code', 'device'];

const subtle = globalThis.crypto.subtle;
const enc = (s) => new TextEncoder().encode(s);
const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
const b64url = (buf) => { let s = ''; for (const b of new Uint8Array(buf)) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const fromB64url = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));
const fail = (reason, msg) => Object.assign(new Error(msg || reason), { reason });
const B64URL = /^[A-Za-z0-9_-]+$/;

async function hkdfKey(ikm, info) {
  const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc(info) }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
/** 백업 패스키·기기 봉투의 열쇠 — PRF(입력 "zkd-s_u-v1") 32바이트에서. */
export async function envKeyFromPrf(prf) {
  if (!(prf instanceof Uint8Array) || prf.length !== 32) throw fail('malformed', 'PRF 는 32바이트여야 한다');
  return hkdfKey(prf, 'zkd-env-key-v1');
}
/** 복구 코드 봉투의 열쇠. 형식·검사 문자가 틀리면 열쇠를 만들기 전에 던진다. */
export async function envKeyFromCode(code) {
  return hkdfKey(parseRecoveryCode(code), 'zkd-env-code-v1');
}

// 복구 코드 — 무작위 16바이트(128비트)를 Crockford base32 26자(130비트, 마지막 자리의 남는 2비트는 0) + 검사 문자 1자(26자 값의 합 mod 32).
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const symSum = (s) => [...s].reduce((n, c) => n + ALPHABET.indexOf(c), 0) % 32;
export function newRecoveryCode() {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  bits += '00';
  let body = '';
  for (let i = 0; i < 130; i += 5) body += ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  return (body + ALPHABET[symSum(body)]).match(/.{1,4}/g).join('-');
}
/** 사용자가 친 코드 → 16바이트. 대소문자·'-'·공백은 무시하고 I/L→1, O→0. */
export function parseRecoveryCode(input) {
  if (typeof input !== 'string') throw fail('recovery_code_format');
  const s = input.toUpperCase().replace(/[-\s]/g, '').replace(/[IL]/g, '1').replace(/O/g, '0');
  if (s.length !== 27 || [...s].some((c) => ALPHABET.indexOf(c) < 0)) throw fail('recovery_code_format');
  const body = s.slice(0, 26);
  if ((ALPHABET.indexOf(body[25]) & 3) !== 0) throw fail('recovery_code_format');
  if (ALPHABET.indexOf(s[26]) !== symSum(body)) throw fail('recovery_code_typo');
  let bits = '';
  for (const c of body) bits += ALPHABET.indexOf(c).toString(2).padStart(5, '0');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return out;
}

/** 봉투 id — 16진 32자(무작위 16바이트). */
export function newEnvelopeId() {
  return hex(globalThis.crypto.getRandomValues(new Uint8Array(16)));
}

const aadOf = ({ uid, id, kind, credentialId }) => enc(`zkd-env-v1|${uid}|${id}|${kind}|${credentialId ?? '-'}`);
/** s_u(10진 문자열)를 봉투로 — ct = b64url(IV 12바이트 ‖ 암호문+태그). */
export async function sealSalt({ key, s_u, uid, id, kind, credentialId }) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const body = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aadOf({ uid, id, kind, credentialId }) }, key, enc(String(s_u))));
  const out = new Uint8Array(12 + body.length);
  out.set(iv, 0); out.set(body, 12);
  return b64url(out);
}
/** 봉투를 열어 s_u 를 돌려준다. 열쇠·AAD·암호문 어느 하나라도 맞지 않으면 envelope_open_failed. */
export async function openSalt({ key, ct, uid, id, kind, credentialId }) {
  try {
    const raw = fromB64url(ct);
    if (raw.length < 12 + 16) throw new Error('짧다');
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12), additionalData: aadOf({ uid, id, kind, credentialId }) }, key, raw.slice(12));
    return new TextDecoder().decode(plain);
  } catch {
    throw fail('envelope_open_failed');
  }
}

/** 서버가 저장·응답하는 봉투의 모양 검사. */
export function isEnvelope(e) {
  if (!e || typeof e !== 'object') return false;
  if (typeof e.id !== 'string' || !/^[0-9a-f]{32}$/.test(e.id)) return false;
  if (!ENV_KINDS.includes(e.kind)) return false;
  if (typeof e.ct !== 'string' || e.ct.length === 0 || e.ct.length > 256 || !B64URL.test(e.ct)) return false;
  if (e.kind === 'code') return e.credentialId === null;
  return typeof e.credentialId === 'string' && e.credentialId.length > 0 && e.credentialId.length <= 1024 && B64URL.test(e.credentialId);
}

/** 서버가 auid 를 내주지 않고 이 값만 주면, 브라우저가 연 salt 로 같은 값을 계산해 대조한다. */
export async function auidCheckOf(uid, auid) {
  return hex(await subtle.digest('SHA-256', enc(`zkd-auid-check-v1|${uid}|${auid}`)));
}
