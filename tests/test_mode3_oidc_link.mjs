// lib/mode3_oidc_link.js — 1회용 저장소·PKCE·네이버 인가 주소·인증 창 쿼리 정리(스펙 2026-11-09-mode3-linked-logins). 외부 의존 없음(unit).
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createOnceStore, pkcePair, naverAuthorizeUrl, sanitizeAuthCtx, exchangeNaverCode, NAVER_DEFAULTS } from '../lib/mode3_oidc_link.js';
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

await t('once store: peek 은 남기고 take 는 지운다, 만료는 null, 상한을 넘으면 오래된 것부터 버린다', () => {
  let now = 0;
  const s = createOnceStore({ ttlMs: 100, max: 2, now: () => now });
  s.put('a', { v: 1 });
  assert.deepEqual(s.peek('a'), { v: 1 }); assert.deepEqual(s.take('a'), { v: 1 }); assert.equal(s.take('a'), null);
  s.put('b', 1); now = 101; assert.equal(s.peek('b'), null, '만료');
  now = 200; s.put('c', 1); s.put('d', 2); s.put('e', 3);
  assert.equal(s.peek('c'), null, '상한 2 — 가장 오래된 c 를 버린다'); assert.equal(s.peek('e'), 3); assert.equal(s.size, 2);
  assert.equal(s.peek(undefined), null);
});
await t('PKCE: challenge = base64url(SHA-256(verifier)), 패딩 없음', () => {
  const { verifier, challenge } = pkcePair();
  assert.match(verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(challenge, createHash('sha256').update(verifier).digest('base64url'));
});
await t('네이버 인가 주소: code·openid·state·nonce·S256', () => {
  const u = new URL(naverAuthorizeUrl({ ...NAVER_DEFAULTS, clientId: 'cid', redirectUri: 'http://localhost:4100/cia/oidc/naver/callback' }, { state: 's1', nonce: 'auth:x', challenge: 'c1' }));
  assert.equal(u.origin + u.pathname, NAVER_DEFAULTS.authorizeUrl);
  for (const [k, v] of Object.entries({ response_type: 'code', client_id: 'cid', scope: 'openid', state: 's1', nonce: 'auth:x', code_challenge: 'c1', code_challenge_method: 'S256', redirect_uri: 'http://localhost:4100/cia/oidc/naver/callback' })) assert.equal(u.searchParams.get(k), v, k);
});
await t('인증 창 쿼리 정리: 허용 키만, 긴 값은 버린다', () => {
  const q = new URLSearchParams(sanitizeAuthCtx(`nonce=n&wallet=http%3A%2F%2Flocalhost%3A5100&return=1&purpose=register&method=naver&ticket=t&evil=1&x=${'a'.repeat(10)}`));
  assert.deepEqual([...q.keys()].sort(), ['method', 'nonce', 'purpose', 'return', 'wallet']);
  assert.equal(new URLSearchParams(sanitizeAuthCtx(`nonce=${'a'.repeat(300)}`)).has('nonce'), false);
  assert.equal(sanitizeAuthCtx(undefined), '');
});
await t('토큰 교환: 성공은 id_token, HTTP 오류·id_token 없음·네트워크 오류는 naver_token_failed(비밀은 메시지에 없다)', async () => {
  const cfg = { ...NAVER_DEFAULTS, clientId: 'cid', clientSecret: 'SECRET-XYZ', redirectUri: 'http://localhost/cb' };
  let sent = null;
  const ok = await exchangeNaverCode(cfg, { code: 'c', state: 's', verifier: 'v', fetchImpl: async (url, init) => { sent = Object.fromEntries(new URLSearchParams(init.body)); return { ok: true, status: 200, json: async () => ({ id_token: 'a.b.c' }) }; } });
  assert.equal(ok, 'a.b.c'); assert.equal(sent.code_verifier, 'v'); assert.equal(sent.grant_type, 'authorization_code');
  for (const f of [async () => ({ ok: false, status: 400, json: async () => ({ error: 'invalid_grant' }) }), async () => ({ ok: true, status: 200, json: async () => ({}) }), async () => { throw new TypeError('fetch failed'); }]) {
    await assert.rejects(exchangeNaverCode(cfg, { code: 'c', state: 's', verifier: 'v', fetchImpl: f }), (e) => e.reason === 'naver_token_failed' && !e.message.includes('SECRET-XYZ'));
  }
});
process.exit(failed === 0 ? 0 : 1);
