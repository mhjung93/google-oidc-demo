// 게시(prepare/commit) 회차 합의의 불변식 검사.
//   node tests/test_idp_publish_invariants.js
//
// custom_idp.js는 모듈 최상위 부수효과(포트 바인딩, RPC, 파일 IO)가 있어 안전하게
// import할 수 없다. tests/test_idp_state_persistence.js의 선례를 따라 소스를 텍스트로
// 읽어 검사한다 — "그 자리에 있어야 할 코드가 실제로 있는지"만 잡는 방식이다.
//
// 동작 테스트는 tests/test_idp_publish_behavior.mjs가 격리 IdP를 띄워서 한다. 여기서는
// "그 자리에 있어야 할 가드가 실제로 있는지"만 소스에서 확인한다 — 동작 테스트가 통과하는
// 경로만으로는 가드가 사라졌는지 알 수 없기 때문이다(정상 경로에서는 어차피 토큰이 맞다).
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
// 회차 합의는 root가 아니라 **회차 토큰**으로 한다.
//
// v2 시절 이 자리에는 다른 불변식이 있었다: /idp/rebaseline_v2가 prepare가 예측해 둔
// root를 무효로 만들 수 있으므로 그 핸들러가 preparedPublish를 비워야 한다는 것. 13.1에서
// 그 엔드포인트도, root 예측 자체도 사라져 위험 자체가 없어졌다(설계 문서 13.1절).
//
// 남은 불변식은 그 후임이다. commit은 "이 커밋이 그 prepare의 것인가"를 확인해야 하고,
// 그 확인이 없으면 운영자가 A 회차를 push한다고 믿는 동안 B 회차가 반영된다.
// ---------------------------------------------------------------------------
const commitHandlerSrc = section(
  "app.post('/idp/publish/commit', requireIdPAdmin, serializeAdminMutation(async (req, res) => {",
  '\n}));',
  '/idp/publish/commit handler',
);
assert.match(
  commitHandlerSrc,
  /roundToken !== preparedPublish\.roundToken/,
  'publish/commit must verify the round token against the prepared publish',
);
assert.match(
  commitHandlerSrc,
  /res\.status\(409\)/,
  'a mismatched round token must be refused with 409, not silently applied',
);

const prepareHandlerSrc = section(
  "app.post('/idp/publish/prepare', requireIdPAdmin, serializeAdminMutation(async (req, res) => {",
  '\n}));',
  '/idp/publish/prepare handler',
);
// prepare가 root를 다시 예측하기 시작하면 순서(prepare -> commit -> push)가 조용히
// 되돌아간다. 그 root는 commit이 만료를 회수하기 **전** 값이라 온체인에 올리면 어긋난다.
assert.doesNotMatch(
  prepareHandlerSrc,
  /expectedRoot/,
  'publish/prepare must not predict a root — the publishable root is only fixed after commit',
);
assert.match(
  prepareHandlerSrc,
  /roundToken/,
  'publish/prepare must issue a round token',
);

// commit이 실패한 회차를 200으로 보고하면 운영자가 그 root를 push하고 빠진 폐기는
// 조용히 사라진다. v2와 나란히 돌던 시절에는 5xx를 낼 수 없어 backfill 플래그로 미뤘지만,
// 이제 push 이전이라 실패한 회차는 그냥 실패시킬 수 있다.
assert.match(
  commitHandlerSrc,
  /applied\.failed\.length > 0[\s\S]*?res\.status\(500\)/,
  'publish/commit must fail the round when some leaves could not be applied',
);

console.log('PASS: 회차 합의가 회차 토큰으로 이뤄지고, 부분 실패가 회차를 무른다.');
