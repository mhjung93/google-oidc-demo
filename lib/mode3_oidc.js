// lib/mode3_oidc.js — OIDC 래퍼의 토큰 검증기(스펙 2026-10-16 §2). Node 전용(jose). IdP(cia.js)만 쓴다 — Google ID 토큰(RS256)을 체인 밖에서 검증하고
// sub·nonce 만 돌려준다. uid 유도·nonce 계산은 lib/mode3_oidc_nonce.js(브라우저도 쓰는 순수 함수)에 있다.
import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from 'jose';

export const GOOGLE_DEFAULTS = Object.freeze({ issuer: 'https://accounts.google.com', jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs', provider: 'google' });
const tagged = (reason, detail) => Object.assign(new Error(`${reason}: ${detail}`), { reason, detail });
const isJwtShape = (t) => typeof t === 'string' && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(t);

export function createOidcVerifier({ issuer, jwksUrl, clientId, jwks = null, clockToleranceSec = 60 }) {
  if (typeof issuer !== 'string' || !issuer) throw new Error('createOidcVerifier: issuer 가 필요하다');
  if (typeof clientId !== 'string' || !clientId) throw new Error('createOidcVerifier: clientId 가 필요하다');
  if (!jwks && (typeof jwksUrl !== 'string' || !jwksUrl)) throw new Error('createOidcVerifier: jwksUrl 또는 jwks 가 필요하다');
  const keySet = jwks ?? createRemoteJWKSet(new URL(jwksUrl));
  // Google 은 iss 를 "https://accounts.google.com" 또는 "accounts.google.com" 으로 낸다 — 둘 다 받는다(uid 유도에는 iss 를 쓰지 않는다, D3).
  const issuers = [...new Set([issuer, issuer.replace(/^https:\/\//, '')])];
  return {
    issuer, clientId,
    async verify(idToken, { noncePrefix }) {
      if (typeof noncePrefix !== 'string' || !noncePrefix) throw new Error('verify: noncePrefix 가 필요하다');
      if (!isJwtShape(idToken)) throw tagged('oidc_invalid', 'format');
      let payload;
      try {
        ({ payload } = await jwtVerify(idToken, keySet, { algorithms: ['RS256'], issuer: issuers, audience: clientId, clockTolerance: clockToleranceSec }));
      } catch (e) {
        // JWKSNoMatchingKey 는 여기서 빼낸다 — jose 의 createRemoteJWKSet 은 모르는 kid 를 만나면 JWKS 를
        // 한 번 다시 받아본 뒤에야 이 오류를 낸다. 즉 발급자에게 최신 키 목록을 확인한 뒤의 결론이므로,
        // "발급자가 공개하지 않은 키로 서명된 토큰" = 무효(oidc_invalid)다. oidc_unavailable(502)로 보고하면
        // 호출자가 재시도하게 되는데, 위조 토큰은 다시 받아도 유효해지지 않는다(R2).
        if (e instanceof joseErrors.JWKSTimeout || e instanceof joseErrors.JWKSMultipleMatchingKeys || e instanceof TypeError || e?.code === 'ECONNREFUSED' || e?.cause?.code === 'ECONNREFUSED') {
          throw tagged('oidc_unavailable', e.code ?? e.name ?? 'fetch_failed');
        }
        throw tagged('oidc_invalid', e.code ?? e.name);   // 만료·서명·aud·iss·alg·형식·모르는 kid(JWKSNoMatchingKey)
      }
      if (typeof payload.sub !== 'string' || !payload.sub) throw tagged('oidc_invalid', 'sub 없음');
      if (typeof payload.nonce !== 'string' || !payload.nonce.startsWith(noncePrefix)) throw tagged('oidc_nonce_mismatch', `nonce 접두어 ${noncePrefix} 아님`);
      return { sub: payload.sub, nonce: payload.nonce, iss: payload.iss };
    },
  };
}
