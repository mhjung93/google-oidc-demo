// lib/mode3_wrapper_auth.js — zkWrapper 의 요청 결속(스펙 2026-11-20 zkwrapper §2.2·§3·§10). 발급 서버(cia.js, CIA_WRAPPER)와 브라우저 코어가 같이 쓴다.
// WebCrypto(globalThis.crypto.subtle)만 쓴다 — Node 22 와 브라우저에서 같은 코드가 돈다(번들 shim 이 필요 없다).
//
// π_IdP 가 없으면 "이 요청은 이 Google 계정의 것" 을 Google ID 토큰이 말해 준다. 그 토큰을 가로채거나 남이 받아 내도 못 쓰게, 토큰을 **1회용 요청 키** 에 묶는다:
//   · 브라우저가 요청 키 쌍(pk_e — P-256, 개인키는 꺼낼 수 없다)을 만들고, Google 인가 요청의 nonce 를 "wrap:" + SHA-256(pk_e.x || pk_e.y) 로 낸다.
//   · 발급·폐기 요청의 본문에 그 키로 서명한다. 서버는 토큰의 nonce 가 본문에 실린 pk_e 의 해시인지, 서명이 그 pk_e 의 것인지 본다.
//   · 서명하는 글에는 목적(issue·revoke_session·revoke_account·envelope)과 서버의 공개 주소(aud)가 들어간다 — 한 목적의 서명을 다른 목적·다른 서버에 쓰지 못한다.
// 본문 필드를 요청 본문이 아니라 키에 묶는 까닭: 본문(가명·커밋먼트)은 salt 가 있어야 만드는데 Google 을 다녀오면 창이 새로 떠 salt 가 사라진다 — 키로 묶으면 패스키를 돌아온 뒤 한 번만 묻는다.
export const WRAPPER_PREFIX = 'wrap:';
const HEX64 = /^[0-9a-f]{64}$/;
const ALG = { name: 'ECDSA', namedCurve: 'P-256' }, SIGN = { name: 'ECDSA', hash: 'SHA-256' };
const malformed = (msg) => Object.assign(new Error(msg), { reason: 'malformed' });
const enc = (s) => new TextEncoder().encode(s);
const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
const b64url = (buf) => { let s = ''; for (const b of new Uint8Array(buf)) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
function fromB64url(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) throw malformed('base64url 이 아니다');
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
/** 공개키 JWK 의 x·y(32바이트씩). P-256 공개키 모양이 아니면 던진다. */
function pkBytes(pkE) {
  if (!pkE || typeof pkE !== 'object' || pkE.kty !== 'EC' || pkE.crv !== 'P-256') throw malformed('pk_e 는 P-256 공개키(JWK)여야 한다');
  const x = fromB64url(pkE.x), y = fromB64url(pkE.y);
  if (x.length !== 32 || y.length !== 32) throw malformed('pk_e 의 좌표 길이');
  return { x, y };
}

/** 1회용 요청 키 쌍. 개인키는 추출 불가(extractable:false) — 브라우저는 IndexedDB 에 CryptoKey 그대로 두고, 값은 어디에도 나오지 않는다. */
export async function generateRequestKey() {
  const pair = await crypto.subtle.generateKey(ALG, false, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { privateKey: pair.privateKey, pkE: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } };
}
/** Google 인가 요청의 nonce — 토큰을 이 요청 키에 묶는다. */
export async function wrapperNonce(pkE) {
  const { x, y } = pkBytes(pkE);
  const both = new Uint8Array(64); both.set(x, 0); both.set(y, 32);
  return WRAPPER_PREFIX + hex(await crypto.subtle.digest('SHA-256', both));
}
export const isWrapperNonce = (s) => typeof s === 'string' && s.startsWith(WRAPPER_PREFIX) && HEX64.test(s.slice(WRAPPER_PREFIX.length));

// 서명하는 글의 한 칸 — 문자열이어야 하고 구분자(|)·제어 문자가 없어야 한다(칸의 경계가 흐려지지 않게).
const field = (v, name) => { if (typeof v !== 'string' || v === '' || /[|\u0000-\u001f\u007f]/.test(v)) throw malformed(`${name}: 문자열 필드가 필요하다`); return v; };
const audOf = (aud) => field(aud, 'aud');
/** 발급 요청에서 서명하는 글. 필드 순서는 고정이다 — 서버와 브라우저가 같은 순서로 잇는다. */
export function issueDigest(body, aud) {
  if (!body || typeof body !== 'object') throw malformed('body');
  const pt = (p, name) => { if (!p || typeof p !== 'object') throw malformed(name); return [field(p.x, `${name}.x`), field(p.y, `${name}.y`)]; };
  const parts = ['zkwrapper', 'issue', audOf(aud), field(body.auid, 'auid'), field(body.auid_s, 'auid_s'), field(body.arid_s, 'arid_s'), ...pt(body.C_u_pt, 'C_u_pt'), ...pt(body.C_s_pt, 'C_s_pt'),
    field(body.chainid, 'chainid'), field(body.allowAgent, 'allowAgent'), field(body.max_height, 'max_height')];
  // salt 봉투(계획 2026-11-24 salt-envelope [I6]): 복구 발급에 실린 기기 봉투도 서명이 덮는다 — 끝에 덧붙인다. 봉투가 없으면 글은 바이트까지 예전과 같다.
  // 연결 열쇠(2026-11-26 스펙 identity-multi-login M3 — lib/mode3_link_key.js): 본문에 있으면 서명이 덮는다. 없으면 글은 바이트까지 예전과 같다.
  if (body.link_key !== undefined) parts.push('link_key', field(body.link_key, 'link_key'));
  // 보관 사본(2026-11-26 스펙 profile-vault — lib/mode3_profile_vault.js): 본문에 있으면 서명이 덮는다(base64url 이라 구분자가 들어갈 수 없다).
  if (body.vault !== undefined) parts.push('vault', field(body.vault, 'vault'));
  if (body.envelope !== undefined) parts.push('envelope', ...envelopeFields(body.envelope));
  return enc(parts.join('|'));
}
// 봉투의 서명 칸 — id·kind·credentialId(복구 코드면 '-')·ct. ct 를 해시하지 않고 그대로 넣는다: 브라우저의 WebCrypto 에는 동기 SHA-256 이 없고,
// ct 는 base64url(≤ 256자)이라 구분자가 들어갈 수 없다. 모양(길이·종류)은 서버가 isEnvelope 로 따로 본다 — 여기서는 칸의 경계만 지킨다.
function envelopeFields(e) {
  if (!e || typeof e !== 'object') throw malformed('envelope');
  return [field(e.id, 'envelope.id'), field(e.kind, 'envelope.kind'), e.credentialId === null ? '-' : field(e.credentialId, 'envelope.credentialId'), field(e.ct, 'envelope.ct')];
}
/** 봉투 추가·삭제 요청에서 서명하는 글. add 는 봉투 전체, remove 는 그 id 만 덮는다.
 *  auid(최종 검토 2026-11-24 I-1): 계정의 auid 도 덮는다 — 서버는 계정에 고정된 auid 와 같을 때만 받는다. auid 는 salt 를 아는 사람(패스키·백업)만 계산하므로,
 *  Google 계정만 가진 사람은 409 auid_pinned 로 봉투 id 를 알아도 백업을 지우거나 한도를 채우지 못한다. */
export function envelopeDigest(req, aud) {
  if (!req || typeof req !== 'object') throw malformed('envelope request');
  if (req.op === 'add') return enc(['zkwrapper', 'envelope', audOf(aud), 'add', field(req.auid, 'auid'), ...envelopeFields(req.envelope)].join('|'));
  if (req.op === 'remove') return enc(['zkwrapper', 'envelope', audOf(aud), 'remove', field(req.auid, 'auid'), field(req.id, 'id')].join('|'));
  throw malformed('op 는 add 또는 remove');
}
/** 폐기 요청에서 서명하는 글. scope 'session' 은 그 세션의 Cf_s, 'account' 는 대상이 계정 자신이다. */
export function revokeDigest(req, aud) {
  if (!req || typeof req !== 'object') throw malformed('revoke');
  if (req.scope === 'session') return enc(['zkwrapper', 'revoke_session', audOf(aud), field(req.Cf_s, 'Cf_s')].join('|'));
  if (req.scope === 'account') return enc(['zkwrapper', 'revoke_account', audOf(aud)].join('|'));
  throw malformed('scope 는 session 또는 account');
}
/** 로그인 계정 연결·떼기 요청에서 서명하는 글(스펙 2026-11-26 identity-multi-login M3·M5).
 *  begin: 지금 계정의 요청 키가 계정의 auid(salt 를 안다는 증거)와 **다음 요청 키의 해시**(next — 더할 계정의 토큰이 묶일 nonce 의 16진 64자)를 덮는다.
 *  finish: 그 다음 요청 키가 "연결을 끝낸다" 만 덮는다 — 어느 신원에 붙는지는 begin 이 정했다. remove: auid 와 뗄 uid. */
export function linkDigest(req, aud) {
  if (!req || typeof req !== 'object') throw malformed('link request');
  if (req.op === 'begin') { if (!HEX64.test(String(req.next))) throw malformed('next 는 16진 64자'); return enc(['zkwrapper', 'link', audOf(aud), 'begin', field(req.auid, 'auid'), field(req.next, 'next')].join('|')); }
  if (req.op === 'finish') return enc(['zkwrapper', 'link', audOf(aud), 'finish'].join('|'));
  if (req.op === 'remove') return enc(['zkwrapper', 'link', audOf(aud), 'remove', field(req.auid, 'auid'), field(req.uid, 'uid')].join('|'));
  throw malformed('op 는 begin·finish·remove');
}
/** 요청 키로 서명 — base64url(IEEE P1363, 64바이트). */
export async function signDigest(privateKey, digestBytes) { return b64url(await crypto.subtle.sign(SIGN, privateKey, digestBytes)); }
/** 서명 확인. 키·서명의 형식이 틀리면 false(던지지 않는다 — 서버는 한 가지 사유로 거절한다). */
export async function verifyDigest(pkE, digestBytes, sig) {
  try {
    pkBytes(pkE);
    const raw = fromB64url(sig);
    if (raw.length !== 64) return false;
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: pkE.x, y: pkE.y }, ALG, false, ['verify']);
    return await crypto.subtle.verify(SIGN, key, raw, digestBytes);
  } catch { return false; }
}
export const signIssue = (privateKey, body, aud) => signDigest(privateKey, issueDigest(body, aud));
export async function verifyIssue(pkE, body, sig, aud) { let d; try { d = issueDigest(body, aud); } catch { return false; } return verifyDigest(pkE, d, sig); }
