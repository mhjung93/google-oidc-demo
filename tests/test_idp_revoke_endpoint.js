import assert from 'node:assert/strict';

const BASE = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';

// /idp/revoke는 운영자 전용 엔드포인트라 공유 시크릿 헤더를 요구한다.
// 시크릿은 IdP 프로세스와 이 테스트가 같은 값을 환경변수로 받아야 한다:
//   IDP_ADMIN_SECRET=<value> node custom_idp.js
//   IDP_ADMIN_SECRET=<value> node tests/test_idp_revoke_endpoint.js
const ADMIN_SECRET = process.env.IDP_ADMIN_SECRET;
if (!ADMIN_SECRET) {
  console.error('IDP_ADMIN_SECRET is required to run this test (must match the value custom_idp.js was started with)');
  process.exit(1);
}
const adminHeaders = { 'X-IdP-Admin-Secret': ADMIN_SECRET };

// Stage A(트리 수명 관리) 범위 노트: "실제 발급된 r_token으로 세션 폐기가 성공한다"는
// 케이스는 의도적으로 여기서 다루지 않는다. issuanceLog에 r_token을 남기려면
// /par → /authorize/login → /authorize/consent → /token(또는 구 플로우인
// /sso_with_credentials → /consent_result) 전체 로그인을 돌아야 하는데, 그러려면
// server.js(:3000)/wallet_agent.js(:5001)까지 함께 떠 있어야 한다(이 파일은 지금까지
// custom_idp.js 하나에만 의존하는 자기완결형 테스트였다). 그 전체 흐름은 이미
// tests/test_par_authorize_token_e2e.js의 testNewFlow()가 덮고 있으므로, 여기서는
// "발급 기록이 없으면 거부"(입구 검사의 핵심 동작)만 확인하고 실제 발급 성공 케이스는
// 생략한다.
async function main() {
  const before = await (await fetch(`${BASE}/idp/revocation_state`)).json();
  assert.ok(typeof before.root === 'string', 'revocation_state must expose a root');
  assert.ok(Array.isArray(before.revokedLeaves), 'revocation_state must expose revokedLeaves');

  // 계정 폐기는 발급 기록이 없어도 항상 통과해야 한다(Stage A 입구 검사는
  // type === 'session'에만 적용된다) — 계정 층 폐기는 "이미 발급된 크레덴셜의
  // 무효화"가 아니라 그 auid 자체를 더 이상 신뢰하지 않겠다는 선언이기 때문이다.
  const res = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...adminHeaders },
    body: JSON.stringify({ type: 'account', value: '424242' }),
  });
  assert.equal(res.status, 200, 'account revocation must succeed without any issuance record');
  const body = await res.json();
  assert.ok(typeof body.root === 'string');
  assert.notEqual(body.root, before.root, 'revoking must change the root');

  const after = await (await fetch(`${BASE}/idp/revocation_state`)).json();
  assert.equal(after.revokedLeaves.length, before.revokedLeaves.length + 1);

  // --- Stage A: 세션 폐기 입구 검사 ---
  // 발급 기록이 없는 r_token으로 세션 폐기를 시도하면 거부돼야 한다. 이 검사가
  // 없으면 임의의 숫자를 세션으로 폐기 신청해 트리를 무한정 부풀릴 수 있다.
  // 실제로 issuanceLog에 기록되는 r_token은 로그인 전체를 거쳐야 발급되므로,
  // 이 값은 IdP가 절대 발급하지 않았을 합성값이다.
  const stateBeforeUnissuedSession = await (await fetch(`${BASE}/idp/revocation_state`)).json();
  const unissuedSession = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...adminHeaders },
    body: JSON.stringify({ type: 'session', value: '999888777666555' }),
  });
  assert.equal(unissuedSession.status, 404, 'revoking a session with no issuance record must be rejected');
  const unissuedSessionBody = await unissuedSession.json();
  assert.ok(unissuedSessionBody.error, 'error field must be present');
  const stateAfterUnissuedSession = await (await fetch(`${BASE}/idp/revocation_state`)).json();
  assert.equal(
    stateAfterUnissuedSession.root,
    stateBeforeUnissuedSession.root,
    'a rejected session revocation must not change the revocation root',
  );

  const bad = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...adminHeaders },
    body: JSON.stringify({ type: 'nonsense', value: '1' }),
  });
  assert.equal(bad.status, 400, 'unknown revocation type must be rejected');

  // Test: non-numeric value must be rejected with 400
  const nonNumeric = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...adminHeaders },
    body: JSON.stringify({ type: 'account', value: 'abc' }),
  });
  assert.equal(nonNumeric.status, 400, 'non-numeric value must be rejected');
  const nonNumericBody = await nonNumeric.json();
  assert.ok(nonNumericBody.error, 'error field must be present');

  // Test: empty string must be rejected with 400
  const emptyString = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...adminHeaders },
    body: JSON.stringify({ type: 'account', value: '' }),
  });
  assert.equal(emptyString.status, 400, 'empty string value must be rejected');
  const emptyStringBody = await emptyString.json();
  assert.ok(emptyStringBody.error, 'error field must be present');

  // Test: value at the BN254 field prime p must be rejected with 400.
  // 상한은 p이지 2^252가 아니다 — leafValue()가 Poseidon '출력'을 252비트로
  // 정규화하므로 입력은 [0, p) 전체가 유효하다.
  const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const oversized = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...adminHeaders },
    body: JSON.stringify({ type: 'account', value: FIELD_PRIME.toString() }),
  });
  assert.equal(oversized.status, 400, 'value >= FIELD_PRIME must be rejected');
  const oversizedBody = await oversized.json();
  assert.ok(oversizedBody.error, 'error field must be present');

  // 회귀 방지 핵심: 2^252 < value < p 인 값은 정상 수락돼야 한다.
  // 예전 구현은 상한이 2^252라서 Poseidon 출력의 약 67%가 여기서 400으로 막혔고,
  // 폐기가 조용히 실패했다(fail-open).
  const aboveOldCap = (2n ** 253n).toString();
  assert.ok(2n ** 253n > 2n ** 252n && 2n ** 253n < FIELD_PRIME, 'test fixture must sit between 2^252 and p');
  const beforeAboveCap = await (await fetch(`${BASE}/idp/revocation_state`)).json();
  const aboveCap = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...adminHeaders },
    body: JSON.stringify({ type: 'account', value: aboveOldCap }),
  });
  assert.equal(aboveCap.status, 200, 'value between 2^252 and p must be accepted');
  const aboveCapBody = await aboveCap.json();
  assert.notEqual(aboveCapBody.root, beforeAboveCap.root, 'accepting the value must insert a leaf');

  // --- 관리자 인증 (I3) ---
  const stateBeforeAuthChecks = await (await fetch(`${BASE}/idp/revocation_state`)).json();

  // 시크릿 헤더 없이 호출하면 401이어야 한다.
  const noAuth = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'account', value: '111222333' }),
  });
  assert.equal(noAuth.status, 401, 'missing admin secret must be rejected with 401');

  // 잘못된 시크릿도 401이어야 한다.
  const wrongAuth = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-IdP-Admin-Secret': `${ADMIN_SECRET}-wrong` },
    body: JSON.stringify({ type: 'account', value: '111222333' }),
  });
  assert.equal(wrongAuth.status, 401, 'wrong admin secret must be rejected with 401');

  // 브라우저에서 온 요청(Origin 헤더가 붙은 요청)은 시크릿이 맞아도 거부돼야 한다.
  // 악성 페이지가 전역 cors() 뒤에 숨어 폐기를 유발하는 경로를 막는다.
  const browserOrigin = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...adminHeaders, Origin: 'http://evil.example' },
    body: JSON.stringify({ type: 'account', value: '111222333' }),
  });
  assert.equal(browserOrigin.status, 403, 'browser-originated revoke must be rejected with 403');

  // 위 세 번의 거부가 트리를 건드리지 않았는지 확인한다.
  const stateAfterAuthChecks = await (await fetch(`${BASE}/idp/revocation_state`)).json();
  assert.equal(
    stateAfterAuthChecks.root,
    stateBeforeAuthChecks.root,
    'rejected revoke attempts must not change the revocation root',
  );

  console.log('PASS: IdP revoke endpoint updates the tree, enforces admin auth and the session issuance-record entry check, and exposes state.');
}

main();
