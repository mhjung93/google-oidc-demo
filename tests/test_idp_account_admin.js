// custom_idp.js는 모듈 최상위 부수효과가 있어 안전하게 import할 수 없다(다른 테스트와
// 동일한 제약 — tests/test_uid_wallet_boundary.js, tests/test_idp_state_persistence.js
// 참고). 이 파일은 두 종류를 섞는다:
//   1. 소스 정적 검사 — "disabled 검사가 증명 검증보다 먼저 있는가" 같은 순서 규칙.
//   2. 살아있는 IdP(:4000)에 대한 실제 HTTP 호출 — /idp/account/set_disabled,
//      /idp/account/unpin_auid의 인증·검증·에러 처리.
//
// 실제 로그인 흐름을 거쳐 "disabled 계정이 로그인 자체를 거부당하는지", "고정 해제 후
// 다른 salt로 로그인이 성공하는지"까지 확인하는 것은 server.js(:3000)/wallet_agent.js
// (:5001)까지 함께 띄운 전체 플로우가 필요해 이 자기완결형 테스트의 범위 밖이다 —
// tests/test_par_authorize_token_e2e.js와 같은 이유. 그 부분은 수동 검증(보고서 참고)으로
// 확인했다.
import assert from 'node:assert/strict';
import fs from 'node:fs';

const idpSource = fs.readFileSync('custom_idp.js', 'utf8');

// ---------------------------------------------------------------------------
// 1. 정적 검사: users 데모 계정에 disabled 필드가 있다.
// ---------------------------------------------------------------------------
assert.match(
  idpSource,
  /'testuser':\s*\{[^}]*disabled:\s*false[^}]*\}/,
  'testuser demo account must default to disabled: false',
);
assert.match(
  idpSource,
  /'alice':\s*\{[^}]*disabled:\s*false[^}]*\}/,
  'alice demo account must default to disabled: false',
);

// ---------------------------------------------------------------------------
// 2. 정적 검사: 두 로그인 경로 모두 disabled 계정을 거부하고, 그 검사가 증명 검증
//    (snarkjs.groth16.verify — 비싼 연산)보다 앞서 있다. 한쪽에만 있으면 계정
//    비활성화가 우회된다 — pinAuidToAccount가 한쪽에만 있어 폐기가 우회됐던 전례와
//    같은 실수를 반복하지 않기 위한 검사다.
// ---------------------------------------------------------------------------
function bodyOf(source, startMarker) {
  const start = source.indexOf(startMarker);
  assert.notEqual(start, -1, `custom_idp.js must still contain ${startMarker}`);
  const rest = source.slice(start + startMarker.length);
  const end = rest.search(/\n(?:app\.(?:post|get|use)\(|(?:async )?function )/);
  return end === -1 ? rest : rest.slice(0, end);
}

for (const marker of ["app.post('/authorize/login'", 'async function verifyPiIAndIssueToken']) {
  const body = bodyOf(idpSource, marker);
  assert.match(
    body,
    /if \(user\.disabled\)/,
    `${marker} must check user.disabled — otherwise account disablement is bypassable from that login path`,
  );
  const disabledCheckIdx = body.search(/if \(user\.disabled\)/);
  // 실제 호출부만 잡는다("await snarkjs.groth16.verify(") — 이 파일의 disabled 검사
  // 옆 주석 자체가 설명을 위해 "snarkjs.groth16.verify"라는 문구를 언급하므로, 느슨한
  // 부분 문자열 검색은 그 주석에 먼저 걸려 순서 판정이 항상 거짓 통과하게 된다.
  const proofVerifyIdx = body.indexOf('await snarkjs.groth16.verify(');
  assert.ok(disabledCheckIdx !== -1 && proofVerifyIdx !== -1, `${marker} must contain both the disabled check and the proof verification call`);
  assert.ok(
    disabledCheckIdx < proofVerifyIdx,
    `${marker} must check user.disabled before verifying the zk proof (cheap check first)`,
  );
}

console.log('PASS (static): disabled check is present and ordered before proof verification on both login paths.');

// ---------------------------------------------------------------------------
// 3. 살아있는 IdP에 대한 HTTP 검사. IDP_ADMIN_SECRET/IDP_AUDITOR_SECRET이 IdP
//    프로세스와 같아야 한다.
// ---------------------------------------------------------------------------
const BASE = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';
const ADMIN_SECRET = process.env.IDP_ADMIN_SECRET;
const AUDITOR_SECRET = process.env.IDP_AUDITOR_SECRET;
if (!ADMIN_SECRET) {
  console.error('IDP_ADMIN_SECRET is required to run this test (must match the value custom_idp.js was started with)');
  process.exit(1);
}
if (!AUDITOR_SECRET) {
  console.error('IDP_AUDITOR_SECRET is required to run this test (used to confirm admin/auditor separation on the new endpoints)');
  process.exit(1);
}
const adminHeaders = { 'Content-Type': 'application/json', 'X-IdP-Admin-Secret': ADMIN_SECRET };
const auditorHeaders = { 'Content-Type': 'application/json', 'X-IdP-Auditor-Secret': AUDITOR_SECRET };

async function main() {
  // --- 인증 매트릭스: 두 엔드포인트 모두 무인증 401, 감사자 시크릿으로도 401,
  //     브라우저 Origin이 붙으면 403이어야 한다(requireIdPAdmin과 동일 정책). ---
  for (const path of ['/idp/account/set_disabled', '/idp/account/unpin_auid']) {
    const body = JSON.stringify({ username: 'alice', disabled: true });

    const noAuth = await fetch(`${BASE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
    assert.equal(noAuth.status, 401, `${path}: missing admin secret must be rejected with 401`);

    // 감사자 시크릿(추적 권한)으로 관리자 엔드포인트(폐기와 같은 등급의 조작)를
    // 통과할 수 있으면 권한 분리가 이름뿐인 것이 된다 — 반드시 401이어야 한다.
    const auditorAuth = await fetch(`${BASE}${path}`, { method: 'POST', headers: auditorHeaders, body });
    assert.equal(auditorAuth.status, 401, `${path}: auditor secret must NOT be accepted (admin/auditor separation)`);

    const wrongAuth = await fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-IdP-Admin-Secret': `${ADMIN_SECRET}-wrong` },
      body,
    });
    assert.equal(wrongAuth.status, 401, `${path}: wrong admin secret must be rejected with 401`);

    const browserOrigin = await fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { ...adminHeaders, Origin: 'http://evil.example' },
      body,
    });
    assert.equal(browserOrigin.status, 403, `${path}: browser-originated request must be rejected with 403`);
  }
  console.log('PASS: both account-admin endpoints enforce admin auth and reject auditor secret / browser origin.');

  // --- 입력 검증 ---
  const missingUsername = await fetch(`${BASE}/idp/account/set_disabled`, {
    method: 'POST', headers: adminHeaders, body: JSON.stringify({ disabled: true }),
  });
  assert.equal(missingUsername.status, 400, 'set_disabled: missing username must be 400');

  const nonBooleanDisabled = await fetch(`${BASE}/idp/account/set_disabled`, {
    method: 'POST', headers: adminHeaders, body: JSON.stringify({ username: 'alice', disabled: 'yes' }),
  });
  assert.equal(nonBooleanDisabled.status, 400, 'set_disabled: non-boolean disabled must be 400');

  const missingUsernameUnpin = await fetch(`${BASE}/idp/account/unpin_auid`, {
    method: 'POST', headers: adminHeaders, body: JSON.stringify({}),
  });
  assert.equal(missingUsernameUnpin.status, 400, 'unpin_auid: missing username must be 400');
  console.log('PASS: input validation rejects missing username / non-boolean disabled with 400.');

  // --- 존재하지 않는 계정 ---
  const unknownAccount = 'no-such-account-xyz';
  const setDisabledUnknown = await fetch(`${BASE}/idp/account/set_disabled`, {
    method: 'POST', headers: adminHeaders, body: JSON.stringify({ username: unknownAccount, disabled: true }),
  });
  assert.equal(setDisabledUnknown.status, 404, 'set_disabled: unknown account must be 404');

  const unpinUnknown = await fetch(`${BASE}/idp/account/unpin_auid`, {
    method: 'POST', headers: adminHeaders, body: JSON.stringify({ username: unknownAccount }),
  });
  assert.equal(unpinUnknown.status, 404, 'unpin_auid: unknown account must be 404');
  console.log('PASS: requests for a non-existent account are rejected with 404 on both endpoints.');

  // --- disabled 계정에 대한 unpin 거부, 그리고 set_disabled 왕복(테스트가 끝나면
  //     alice를 원래 상태(disabled: false)로 되돌린다). ---
  const disableAlice = await fetch(`${BASE}/idp/account/set_disabled`, {
    method: 'POST', headers: adminHeaders, body: JSON.stringify({ username: 'alice', disabled: true }),
  });
  assert.equal(disableAlice.status, 200, 'set_disabled: disabling alice must succeed');
  const disableBody = await disableAlice.json();
  assert.equal(disableBody.disabled, true, 'set_disabled response must reflect the new disabled state');

  const unpinDisabled = await fetch(`${BASE}/idp/account/unpin_auid`, {
    method: 'POST', headers: adminHeaders, body: JSON.stringify({ username: 'alice' }),
  });
  assert.equal(unpinDisabled.status, 409, 'unpin_auid: a disabled account must refuse unpin with 409');

  const reenableAlice = await fetch(`${BASE}/idp/account/set_disabled`, {
    method: 'POST', headers: adminHeaders, body: JSON.stringify({ username: 'alice', disabled: false }),
  });
  assert.equal(reenableAlice.status, 200, 're-enabling alice must succeed');
  const reenableBody = await reenableAlice.json();
  assert.equal(reenableBody.disabled, false, 're-enable response must reflect disabled: false');
  console.log('PASS: unpin_auid refuses a disabled account with 409; set_disabled round-trip works and restores state.');

  console.log('ALL PASS: /idp/account/set_disabled and /idp/account/unpin_auid behave as designed.');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
