// lib/mode3_oidc.js — OIDC 래퍼의 토큰 검증기(스펙 2026-10-16 §2). Node 전용(jose). IdP(cia.js)만 쓴다 — Google ID 토큰(RS256)을 체인 밖에서 검증하고
// sub·nonce 만 돌려준다. uid 유도·nonce 계산은 lib/mode3_oidc_nonce.js(브라우저도 쓰는 순수 함수)에 있다.
import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from 'jose';

export const GOOGLE_DEFAULTS = Object.freeze({ issuer: 'https://accounts.google.com', jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs', provider: 'google' });
const tagged = (reason, detail) => Object.assign(new Error(`${reason}: ${detail}`), { reason, detail });
const isJwtShape = (t) => typeof t === 'string' && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(t);
// 토큰 자체의 검증 실패 — 만료·클레임(iss·aud·exp·iat·sub)·서명·형식·alg·지원 안 되는 헤더, 그리고 모르는 kid(JWKSNoMatchingKey, 아래 R2).
// 이 목록에 있는 것만 oidc_invalid 다. 나머지는 전부 oidc_unavailable(2026-10-16 최종 리뷰 I3).
const TOKEN_FAILURES = [joseErrors.JWTExpired, joseErrors.JWTClaimValidationFailed, joseErrors.JWSSignatureVerificationFailed, joseErrors.JWSInvalid,
  joseErrors.JWTInvalid, joseErrors.JOSEAlgNotAllowed, joseErrors.JOSENotSupported, joseErrors.JWKSNoMatchingKey];

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
        ({ payload } = await jwtVerify(idToken, keySet, { algorithms: ['RS256'], issuer: issuers, audience: clientId, clockTolerance: clockToleranceSec, requiredClaims: ['exp', 'iat', 'sub'] }));
      } catch (e) {
        // 분류 규칙: 토큰 자체의 검증 실패(TOKEN_FAILURES)만 oidc_invalid(401), 그 밖은 전부 oidc_unavailable(502)다.
        // IdP 가 토큰을 확인하지 못한 것(JWKS 를 못 받음 — 타임아웃·연결 거부·DNS(EAI_AGAIN·ENOTFOUND)·연결 끊김, JWKS 응답이 200 이
        // 아님(일반 JOSEError)·JSON 이 아님, 키 집합 모양이 틀림(JWKSInvalid)·같은 kid 가 여럿(JWKSMultipleMatchingKeys), TypeError,
        // 모르는 오류)은 "토큰이 무효"가 아니다 — 사용자에게 다시 로그인하라고 해도 풀리지 않는다. Node 판 jose 는 JWKS 를 http(s).get 으로
        // 받아 네트워크 실패가 원시 시스템 오류로 오므로, 실패 목록이 아니라 검증 실패 목록을 정해 두고 나머지를 unavailable 로 보낸다.
        // JWKSNoMatchingKey 는 invalid 쪽이다 — jose 의 createRemoteJWKSet 은 모르는 kid 를 만나면 JWKS 를 한 번 다시 받아본 뒤에야
        // 이 오류를 낸다. 즉 발급자에게 최신 키 목록을 확인한 뒤의 결론이므로 "발급자가 공개하지 않은 키로 서명된 토큰" = 무효다.
        // unavailable(502)로 보고하면 호출자가 재시도하게 되는데, 위조 토큰은 다시 받아도 유효해지지 않는다(R2).
        // detail 은 코드명·클래스명만 — e.message 는 넣지 않는다(토큰·클레임이 응답에 되돌아가지 않게).
        const reason = TOKEN_FAILURES.some((C) => e instanceof C) ? 'oidc_invalid' : 'oidc_unavailable';
        throw tagged(reason, e?.code ?? e?.name ?? 'unknown');
      }
      if (typeof payload.sub !== 'string' || !payload.sub) throw tagged('oidc_invalid', 'sub 없음');
      if (typeof payload.nonce !== 'string' || !payload.nonce.startsWith(noncePrefix)) throw tagged('oidc_nonce_mismatch', `nonce 접두어 ${noncePrefix} 아님`);
      return { sub: payload.sub, nonce: payload.nonce, iss: payload.iss };
    },
  };
}
