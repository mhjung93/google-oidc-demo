// lib/mode3_profile_vault.js — zkWrapper 의 "보관 사본"(스펙 2026-11-26 profile-vault). 발급 서버(cia.js)와 브라우저 코어가 같이 쓴다.
// WebCrypto(globalThis.crypto.subtle)만 쓴다 — Node 22 와 브라우저에서 같은 코드가 돈다.
//
// 같은 패스키(같은 salt)로 다른 브라우저·기기에서 로그인하면 계정 주소(PPID)는 같지만, 속성과 사용자 자격증명의 재료(blind_u)는 그 브라우저에만 있었다 —
// 새 브라우저는 빈 속성으로 새 C_u 를 받아 조건을 거는 서비스에 못 들어가고, 다른 기기의 세션은 폐기됐다. 그래서 그 재료를 salt 에서 유도한 키로 잠가 서버에 둔다:
//   · 키 = AES-256-GCM, 키 재료 SHA-256("zkwrapper-vault-v1|" + salt). 저장하지 않는다 — 패스키로 salt 를 만든 자리에서만 생긴다.
//   · 평문 = { v:1, uid(C_u 안의 uid), profile, attrs[6], blind_u }. 암호문은 계정의 auid 에 묶인다(추가 인증 데이터).
//   · 브라우저는 발급 요청마다 지금의 사본을 싣고(vault), 서버는 발급이 받아들여지면 그 계정의 것으로 덮어쓴다. 서버는 열지 못한다(속성 값은 서버가 모른다는 D15 그대로).
//   · 새 브라우저는 첫 로그인에서 Google 확인·패스키 뒤 POST /cia/wrapper/vault 로 암호문을 받아 연다.
// 세션키·거래 기록·증명 기록은 싣지 않는다(세션은 브라우저마다 따로 만든다).
const DOMAIN = 'zkwrapper-vault-v1|';
export const VAULT_MAX = 4096;   // base64url 글자 수 상한 — 평문은 1KB 안팎이다
const enc = (s) => new TextEncoder().encode(s);
const b64url = (buf) => { let s = ''; for (const b of new Uint8Array(buf)) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const fromB64url = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));
const DEC = /^[0-9]{1,80}$/;

export const isVaultCt = (v) => typeof v === 'string' && v.length >= 40 && v.length <= VAULT_MAX && /^[A-Za-z0-9_-]+$/.test(v);
async function keyOf(s_u) {
  const s = BigInt(s_u); if (s <= 0n) throw new Error('salt');
  return crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', enc(DOMAIN + s.toString())), 'AES-GCM', false, ['encrypt', 'decrypt']);
}
const aadOf = (auid) => { if (!DEC.test(String(auid))) throw new Error('auid'); return enc(DOMAIN + String(auid)); };

/** 사본을 잠근다 → base64url(iv(12) || 암호문). data 는 JSON 으로 옮길 수 있는 값. */
export async function sealVault({ s_u, auid, data }) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aadOf(auid) }, await keyOf(s_u), enc(JSON.stringify(data))));
  const out = new Uint8Array(12 + ct.length); out.set(iv, 0); out.set(ct, 12);
  const s = b64url(out);
  if (!isVaultCt(s)) throw new Error('vault too large');
  return s;
}
/** 사본을 연다 — 모양이 맞는 { v:1, uid, profile, attrs[6], blind_u } 또는 null(다른 salt·다른 auid·손상·모양 오류. 던지지 않는다). */
export async function openVault({ s_u, auid, ct }) {
  try {
    if (!isVaultCt(ct)) return null;
    const raw = fromB64url(ct);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12), additionalData: aadOf(auid) }, await keyOf(s_u), raw.slice(12));
    const d = JSON.parse(new TextDecoder().decode(pt));
    if (d?.v !== 1 || !DEC.test(String(d.uid)) || !DEC.test(String(d.blind_u)) || !Array.isArray(d.attrs) || d.attrs.length !== 6 || !d.attrs.every((a) => DEC.test(String(a)))) return null;
    if (d.profile !== null && (typeof d.profile !== 'object' || Array.isArray(d.profile))) return null;
    return { v: 1, uid: String(d.uid), profile: d.profile, attrs: d.attrs.map(String), blind_u: String(d.blind_u) };
  } catch { return null; }
}
/** 사본을 달라는 요청에서 요청 키가 서명하는 글 — 계정의 auid 와 서버 주소를 덮는다. */
export function vaultDigest(req, aud) {
  if (typeof aud !== 'string' || !/^[^|\u0000-\u001f\u007f]+$/.test(aud) || !DEC.test(String(req?.auid))) throw Object.assign(new Error('vault request'), { reason: 'malformed' });
  return enc(['zkwrapper', 'vault', aud, 'get', String(req.auid)].join('|'));
}
