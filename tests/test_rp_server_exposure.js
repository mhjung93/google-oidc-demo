// RP 백엔드(server.js)의 노출면 검사.
//   node tests/test_rp_server_exposure.js      (server.js가 :3000에 떠 있어야 한다)
//
// 왜 이 파일이 생겼나. 2026-09-04 전체 코드 리뷰에서 `app.use(express.static(__dirname))`가
// 저장소 루트를 통째로 서빙한다는 것이 드러났다. 영속화 작업(ac30011)이 IdP 개인키
// (idp_keys.json)와 r_token->uid 매핑(idp_state.json)을 그 루트에 놓으면서, 둘의 조합으로
// **개인키와 프라이버시 매핑이 HTTP로 다운로드되는** 상태가 됐다(실측: 200, 665B / 15,671B).
// 각각의 코드는 문제가 없었고 조합이 구멍이었다 — 그래서 "새 파일이 생겨도 안전한" 방식,
// 즉 허용 목록을 강제한다.
import assert from 'node:assert/strict';

const BASE = process.env.RP_SERVER_BASE_URL || 'http://127.0.0.1:3000';

async function status(path, init) {
  const res = await fetch(`${BASE}${path}`, init);
  return res.status;
}

// --- 1. 민감 파일이 서빙되면 안 된다 ------------------------------------------
// 루트에 있고 앞으로도 생길 수 있는 것들. 새 파일이 추가돼도 기본이 "차단"이어야 한다.
for (const path of [
  '/idp_keys.json', // IdP EdDSA 개인키 + PS 비밀키
  '/idp_state.json', // r_token -> uid 매핑 (PairCT가 지키려는 바로 그 연결)
  '/wallet_state.json', // 지갑 에이전트 토큰
  '/auditor_keys.json',
  '/rp_registration.json',
  '/bip32_out.json',
  '/package.json',
  '/custom_idp.js', // 서버 소스
  '/server.js',
]) {
  const code = await status(path);
  assert.notEqual(code, 200, `${path} 는 서빙되면 안 된다 (받은 코드 ${code})`);
}
console.log('OK (1): 민감 파일·서버 소스가 서빙되지 않는다');

// --- 2. 데모에 필요한 자산은 그대로 서빙돼야 한다 -------------------------------
for (const path of ['/', '/index.html', '/client.js']) {
  assert.equal(await status(path), 200, `${path} 는 계속 서빙돼야 한다(데모가 깨진다)`);
}
console.log('OK (2): index.html·client.js는 정상 서빙된다');

// --- 3. B2 추적은 감사자 자격 없이 호출되면 안 된다 -----------------------------
// server.js가 자기 IDP_AUDITOR_SECRET을 대신 붙여주면, 감사자/관리자 권한 분리(12c161b)가
// 이 프록시 하나로 무력화된다 — RP가 단독으로 사용자를 추적할 수 있게 된다.
const traceNoAuth = await status('/api/mode2/trace_transaction', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ auid_i: '1' }),
});
assert.ok(
  traceNoAuth === 401 || traceNoAuth === 403,
  `추적은 감사자 자격 없이 거부돼야 한다 (받은 코드 ${traceNoAuth})`,
);
console.log('OK (3): B2 추적이 감사자 자격 없이는 거부된다');

// --- 4. 인증 없는 릴레이 엔드포인트가 없어야 한다 -------------------------------
// /api/mode2/relay_transaction은 인증 없이 임의의 to/data를 노드의 unlocked 계정으로
// 보냈고, 저장소 어디서도 호출하지 않았다.
const relay = await status('/api/mode2/relay_transaction', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ to: '0x0000000000000000000000000000000000000001', data: '0x' }),
});
assert.ok(
  relay === 404 || relay === 401 || relay === 403,
  `인증 없는 임의 트랜잭션 릴레이가 살아 있으면 안 된다 (받은 코드 ${relay})`,
);
console.log('OK (4): 인증 없는 릴레이 엔드포인트가 없다');

console.log('PASS: RP 백엔드 노출면 — 민감 파일 비공개, 추적 권한 분리, 열린 릴레이 없음.');
