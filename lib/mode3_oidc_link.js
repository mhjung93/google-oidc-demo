// lib/mode3_oidc_link.js — zkID 계정에 외부 로그인(Google·네이버) 연결(스펙 2026-11-09-mode3-linked-logins). IdP(cia.js)만 쓴다.
//   - 1회용 저장소: 연결·인증용 nonce, 네이버 state, 네이버 ticket. 메모리(재시작하면 진행 중인 연결만 다시 하면 된다), 만료·개수 상한.
//   - 네이버 OIDC: 인가 코드 + PKCE(S256). 네이버는 response_type=code 만 지원한다(nid.naver.com/.well-known/openid-configuration).
import { createHash, randomBytes } from 'node:crypto';

export const LINK_PREFIX = 'link:';
export const AUTH_PREFIX = 'auth:';
export const NAVER_DEFAULTS = Object.freeze({
  provider: 'naver', issuer: 'https://nid.naver.com', jwksUrl: 'https://nid.naver.com/oauth2/jwks',
  authorizeUrl: 'https://nid.naver.com/oauth2/authorize', tokenUrl: 'https://nid.naver.com/oauth2/token',
});
export const LINK_SLOTS = Object.freeze(['google', 'naver']);

const b64u = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const randomHex = () => randomBytes(32).toString('hex');

/** 만료(ttlMs)와 개수 상한(max)이 있는 1회용 맵. 상한을 넘으면 가장 오래된 것부터 버린다(무인증 nonce 요청으로 메모리가 자라지 않게). */
export function createOnceStore({ ttlMs = 5 * 60_000, max = 5000, now = () => Date.now() } = {}) {
  const m = new Map();
  const sweep = () => { const t = now(); for (const [k, v] of m) if (v.exp < t) m.delete(k); };
  return {
    put(key, data) {
      sweep();
      while (m.size >= max) m.delete(m.keys().next().value);
      m.set(key, { data, exp: now() + ttlMs });
    },
    /** 지우지 않고 본다 — 만료면 null. */
    peek(key) { const v = typeof key === 'string' ? m.get(key) : undefined; if (!v) return null; if (v.exp < now()) { m.delete(key); return null; } return v.data; },
    /** 보고 지운다. */
    take(key) { const d = this.peek(key); if (d !== null) m.delete(key); return d; },
    get size() { return m.size; },
  };
}

/** PKCE(RFC 7636) S256 쌍. */
export function pkcePair() {
  const verifier = b64u(randomBytes(32));
  return { verifier, challenge: b64u(createHash('sha256').update(verifier).digest()) };
}

export function naverAuthorizeUrl(cfg, { state, nonce, challenge }) {
  const u = new URL(cfg.authorizeUrl);
  for (const [k, v] of Object.entries({ response_type: 'code', client_id: cfg.clientId, redirect_uri: cfg.redirectUri, scope: 'openid', state, nonce, code_challenge: challenge, code_challenge_method: 'S256' })) u.searchParams.set(k, v);
  return u.toString();
}

/** 인가 코드 → id_token. 실패는 reason 이 붙은 Error(naver_token_failed). 응답 본문·비밀은 오류 메시지에 넣지 않는다. */
export async function exchangeNaverCode(cfg, { code, state, verifier, fetchImpl = fetch, timeoutMs = 8000 }) {
  const body = new URLSearchParams({ grant_type: 'authorization_code', client_id: cfg.clientId, client_secret: cfg.clientSecret, code, state, redirect_uri: cfg.redirectUri, code_verifier: verifier });
  let r;
  try { r = await fetchImpl(cfg.tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body, signal: AbortSignal.timeout(timeoutMs) }); }
  catch (e) { throw Object.assign(new Error(`naver_token_failed: ${e?.name ?? 'network'}`), { reason: 'naver_token_failed' }); }
  const j = await r.json().catch(() => null);
  if (!r.ok || typeof j?.id_token !== 'string') throw Object.assign(new Error(`naver_token_failed: HTTP ${r.status}${j?.error ? ` ${j.error}` : ''}`), { reason: 'naver_token_failed' });
  return j.id_token;
}

/** 인증 창이 맡기는 쿼리(네이버를 다녀온 뒤 되돌려 줄 것) — 허용한 키만, 값은 짧은 문자열만 남긴다. */
const CTX_KEYS = ['nonce', 'wallet', 'return', 'purpose', 'method'];
export function sanitizeAuthCtx(raw) {
  const q = new URLSearchParams(typeof raw === 'string' ? raw : '');
  const out = new URLSearchParams();
  for (const k of CTX_KEYS) { const v = q.get(k); if (typeof v === 'string' && v.length <= 256) out.set(k, v); }
  return out.toString();
}
