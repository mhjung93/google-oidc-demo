// tests/test_mode3_oidc_verifier.mjs — OIDC 검증기(스펙 2026-10-16 §2 lib/mode3_oidc.js) + RS256 발급자 스텁. localhost HTTP 만 쓴다. (unit)
import assert from 'node:assert/strict';
import http from 'node:http';
import { SignJWT, generateKeyPair, exportJWK, createLocalJWKSet } from 'jose';
import { createOidcVerifier, GOOGLE_DEFAULTS } from '../lib/mode3_oidc.js';
import { startOidcIssuerStub } from './helpers/oidc_issuer_stub.mjs';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.stack ?? e.message); } }
const expectReason = async (p, reason, detailRe = null) => { try { await p; assert.fail(`${reason} 를 기대했는데 통과했다`); } catch (e) { assert.equal(e.reason, reason, `reason: ${e.reason} (${e.detail ?? e.message})`); if (detailRe) assert.match(String(e.detail), detailRe); } };

const stub = await startOidcIssuerStub({ clientId: 'cid-1' });
try {
  await t('GOOGLE_DEFAULTS 는 Google 의 iss·JWKS URL·provider 다', () => {
    assert.deepEqual(GOOGLE_DEFAULTS, { issuer: 'https://accounts.google.com', jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs', provider: 'google' });
  });
  await t('스텁: JWKS 를 내고(CORS *), mint 한 토큰을 원격 JWKS 로 검증한다 — sub·nonce·iss 를 돌려준다', async () => {
    const r = await fetch(stub.jwksUrl); assert.equal(r.status, 200); assert.equal(r.headers.get('access-control-allow-origin'), '*');
    const jwks = await r.json(); assert.equal(jwks.keys.length, 1); assert.equal(jwks.keys[0].alg, 'RS256'); assert.ok(jwks.keys[0].kid);
    const v = createOidcVerifier({ issuer: stub.issuer, jwksUrl: stub.jwksUrl, clientId: 'cid-1' });
    const token = await stub.mint({ sub: 'user-1', nonce: 'reg:' + 'a'.repeat(64) });
    const out = await v.verify(token, { noncePrefix: 'reg:' });
    assert.deepEqual(out, { sub: 'user-1', nonce: 'reg:' + 'a'.repeat(64), iss: stub.issuer });
    const viaHttp = await (await fetch(`${stub.base}/mint`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sub: 'user-2', nonce: 'revoke:' + 'b'.repeat(64) }) })).json();
    assert.deepEqual(await v.verify(viaHttp.id_token, { noncePrefix: 'revoke:' }), { sub: 'user-2', nonce: 'revoke:' + 'b'.repeat(64), iss: stub.issuer });
  });
  await t('iss 두 형태: https:// 를 뗀 iss 도 통과한다(Google 호환)', async () => {
    const v = createOidcVerifier({ issuer: 'https://accounts.example', jwksUrl: stub.jwksUrl, clientId: 'cid-1' });
    const ok1 = await stub.mint({ sub: 's', nonce: 'reg:' + 'c'.repeat(64), iss: 'https://accounts.example' });
    const ok2 = await stub.mint({ sub: 's', nonce: 'reg:' + 'c'.repeat(64), iss: 'accounts.example' });
    assert.equal((await v.verify(ok1, { noncePrefix: 'reg:' })).iss, 'https://accounts.example');
    assert.equal((await v.verify(ok2, { noncePrefix: 'reg:' })).iss, 'accounts.example');
    await expectReason(v.verify(await stub.mint({ sub: 's', nonce: 'reg:x', iss: 'https://other.example' }), { noncePrefix: 'reg:' }), 'oidc_invalid', /ERR_JWT_CLAIM_VALIDATION_FAILED/);
  });
  await t('거절: 다른 aud·만료·서명 위조·형식 → oidc_invalid(detail 에 jose 코드), nonce 접두어 불일치·nonce 없음 → oidc_nonce_mismatch', async () => {
    const v = createOidcVerifier({ issuer: stub.issuer, jwksUrl: stub.jwksUrl, clientId: 'cid-1' });
    await expectReason(v.verify(await stub.mint({ sub: 's', nonce: 'reg:n', aud: 'cid-2' }), { noncePrefix: 'reg:' }), 'oidc_invalid', /ERR_JWT_CLAIM_VALIDATION_FAILED/);
    await expectReason(v.verify(await stub.mint({ sub: 's', nonce: 'reg:n', expSeconds: -120 }), { noncePrefix: 'reg:' }), 'oidc_invalid', /ERR_JWT_EXPIRED/);
    const { privateKey } = await generateKeyPair('RS256');
    const forged = await new SignJWT({ sub: 's', nonce: 'reg:n' }).setProtectedHeader({ alg: 'RS256', kid: 'other' }).setIssuer(stub.issuer).setAudience('cid-1').setIssuedAt().setExpirationTime('5m').sign(privateKey);
    await expectReason(v.verify(forged, { noncePrefix: 'reg:' }), 'oidc_invalid');   // JWKS 에 그 kid 가 없다 — JWKSNoMatchingKey(jose 가 JWKS 를 다시 받아본 뒤) = 발급자가 공개하지 않은 키 → 무효(R2)
    await expectReason(v.verify('not-a-jwt', { noncePrefix: 'reg:' }), 'oidc_invalid', /format/);
    await expectReason(v.verify(12, { noncePrefix: 'reg:' }), 'oidc_invalid', /format/);
    await expectReason(v.verify(await stub.mint({ sub: 's', nonce: 'revoke:' + 'd'.repeat(64) }), { noncePrefix: 'reg:' }), 'oidc_nonce_mismatch');
    await expectReason(v.verify(await stub.mint({ sub: 's', nonce: undefined }), { noncePrefix: 'reg:' }), 'oidc_nonce_mismatch');
    await expectReason(v.verify(await stub.mint({ sub: '', nonce: 'reg:n' }), { noncePrefix: 'reg:' }), 'oidc_invalid', /sub/);
  });
  await t('로컬 JWKS 주입(jwks 인자)과 JWKS 서버 불가(oidc_unavailable)', async () => {
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
    const v = createOidcVerifier({ issuer: 'https://accounts.google.com', jwksUrl: 'https://127.0.0.1:1/never', clientId: 'cid-1', jwks: createLocalJWKSet({ keys: [jwk] }) });
    const token = await new SignJWT({ sub: 'g-1', nonce: 'reg:' + 'e'.repeat(64) }).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer('accounts.google.com').setAudience('cid-1').setIssuedAt().setExpirationTime('5m').sign(privateKey);
    assert.equal((await v.verify(token, { noncePrefix: 'reg:' })).sub, 'g-1');
    const down = createOidcVerifier({ issuer: stub.issuer, jwksUrl: 'http://127.0.0.1:1/jwks', clientId: 'cid-1' });
    await expectReason(down.verify(await stub.mint({ sub: 's', nonce: 'reg:n' }), { noncePrefix: 'reg:' }), 'oidc_unavailable', /^[A-Za-z_]+$/);   // detail 은 코드명/클래스명만(e.message 금지)
  });
  // 2026-10-16 최종 리뷰 I3·M1 — 토큰을 확인하지 못한 경우(JWKS 획득 실패)는 "무효"가 아니라 oidc_unavailable 이다.
  await t('JWKS 서버가 500 → oidc_unavailable(detail 은 코드명)', async () => {
    const srv = http.createServer((req, res) => { res.writeHead(req.url === '/.well-known/jwks.json' ? 500 : 404); res.end(); });
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    try {
      const v = createOidcVerifier({ issuer: stub.issuer, jwksUrl: `http://127.0.0.1:${srv.address().port}/.well-known/jwks.json`, clientId: 'cid-1' });
      await expectReason(v.verify(await stub.mint({ sub: 's', nonce: 'reg:n' }), { noncePrefix: 'reg:' }), 'oidc_unavailable', /^[A-Za-z_]+$/);
    } finally { await new Promise((r) => srv.close(() => r())); }
  });
  await t('DNS 가 풀리지 않는 호스트 → oidc_unavailable', async () => {
    const v = createOidcVerifier({ issuer: stub.issuer, jwksUrl: 'http://nonexistent.invalid/jwks', clientId: 'cid-1' });   // .invalid 는 절대 풀리지 않는다(RFC 6761)
    await expectReason(v.verify(await stub.mint({ sub: 's', nonce: 'reg:n' }), { noncePrefix: 'reg:' }), 'oidc_unavailable', /^E[A-Z_]+$/);   // EAI_AGAIN·ENOTFOUND
  });
  await t('exp·iat 없는 토큰 → oidc_invalid(requiredClaims)', async () => {
    const v = createOidcVerifier({ issuer: stub.issuer, jwksUrl: stub.jwksUrl, clientId: 'cid-1' });
    await expectReason(v.verify(await stub.mint({ sub: 's', nonce: 'reg:n', omitClaims: ['exp'] }), { noncePrefix: 'reg:' }), 'oidc_invalid', /ERR_JWT_CLAIM_VALIDATION_FAILED/);
    await expectReason(v.verify(await stub.mint({ sub: 's', nonce: 'reg:n', omitClaims: ['iat'] }), { noncePrefix: 'reg:' }), 'oidc_invalid', /ERR_JWT_CLAIM_VALIDATION_FAILED/);
  });
  await t('alg HS256 토큰 → oidc_invalid(alg 혼동 차단)', async () => {
    const v = createOidcVerifier({ issuer: stub.issuer, jwksUrl: stub.jwksUrl, clientId: 'cid-1' });
    const hmac = crypto.getRandomValues(new Uint8Array(32));
    const hs = await new SignJWT({ sub: 's', nonce: 'reg:n' }).setProtectedHeader({ alg: 'HS256' }).setIssuer(stub.issuer).setAudience('cid-1').setIssuedAt().setExpirationTime('5m').sign(hmac);
    await expectReason(v.verify(hs, { noncePrefix: 'reg:' }), 'oidc_invalid', /ERR_JOSE_ALG_NOT_ALLOWED/);
  });
} finally { await stub.stop(); }
process.exit(fails ? 1 : 0);
