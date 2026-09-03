// 게시(prepare/commit)와 재기준화 사이의 불변식 검사.
//   node tests/test_idp_publish_invariants.js
//
// custom_idp.js는 모듈 최상위 부수효과(포트 바인딩, RPC, 파일 IO)가 있어 안전하게
// import할 수 없다. tests/test_idp_state_persistence.js의 선례를 따라 소스를 텍스트로
// 읽어 검사한다 — "그 자리에 있어야 할 코드가 실제로 있는지"만 잡는 방식이다.
//
// 이 파일을 behavioral 테스트로 쓸 수 없는 이유를 분명히 해 둔다: 아래 시나리오를
// 살아있는 IdP에 실제로 돌리면 v2 트리가 되돌릴 수 없게 전진한 채 저장되지 않고
// preparedPublish가 고착돼, 그 IdP가 이후 모든 커밋에서 500을 내는 상태가 된다.
// 격리 실행(PORT/IDP_STATE_FILE 환경변수화)이 생기기 전까지는 소스 검사가 최선이다.
import assert from 'node:assert/strict';
import fs from 'fs';

const src = fs.readFileSync('custom_idp.js', 'utf8');

function section(startMarker, endMarker, label) {
  const start = src.indexOf(startMarker);
  assert(start !== -1, `could not find start marker for ${label}: ${startMarker}`);
  const end = src.indexOf(endMarker, start);
  assert(end !== -1, `could not find end marker for ${label}: ${endMarker}`);
  return src.slice(start, end);
}

// ---------------------------------------------------------------------------
// 재기준화는 prepare가 예측해 둔 root를 무효로 만든다.
//
// commit 핸들러는 "prepare와 commit 사이에 v2를 바꾸는 경로는 없으므로(admin 직렬)"를
// 전제로 적혀 있는데, /idp/rebaseline_v2가 정확히 그 경로다(같은 관리자 인증).
// prepare(root R) -> 온체인 push -> rebaseline -> commit{root: R} 순서면, 최초 비교는
// prepared.root와 하므로 통과하고, 리프를 **새 트리에** 삽입한 뒤에야 root 불일치를
// 발견해 500을 낸다. 그 시점엔 트리가 이미 전진했고(append-only, 되돌릴 수 없음)
// preparedPublish를 비우기 전에 리턴하므로 재시도는 영원히 500이다.
//
// 그러므로 재기준화는 미결 prepare를 스스로 무효화해야 한다.
// ---------------------------------------------------------------------------
const rebaselineHandlerSrc = section(
  "app.post('/idp/rebaseline_v2', requireIdPAdmin, serializeAdminMutation(async (req, res) => {",
  '\n});',
  '/idp/rebaseline_v2 handler',
);
assert.match(
  rebaselineHandlerSrc,
  /preparedPublish = null;/,
  '/idp/rebaseline_v2 must invalidate any outstanding prepared publish — its root no longer applies',
);

console.log('PASS: 재기준화가 미결 prepare를 무효화한다.');
