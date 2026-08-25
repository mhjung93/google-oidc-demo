import assert from 'node:assert/strict';
import fs from 'node:fs';
import { shouldReuseProof } from '../wallet_agent.js';

// wallet_agent.js가 실제로 쓰는 판정 함수를 그대로 불러 검증한다.
// (증명 생성 자체는 느리므로 여기서는 재사용 판정 규칙만 본다.)
assert.equal(shouldReuseProof(null, 'r1', 's1'), false, 'no cache -> must prove');
assert.equal(shouldReuseProof({ root: 'r1', sessionKeyId: 's1' }, 'r1', 's1'), true, 'same root and session -> reuse');
assert.equal(shouldReuseProof({ root: 'r1', sessionKeyId: 's1' }, 'r2', 's1'), false, 'root changed -> reprove');
assert.equal(shouldReuseProof({ root: 'r1', sessionKeyId: 's1' }, 'r1', 's2'), false, 'new session key -> reprove');

console.log('PASS: proof cache is reused only for the same session key and root.');

// --- currentAccountSecrets 대입 순서 회귀 테스트 ---
// generateNewSessionKey()는 새 세션 시작 시 옛 currentAccountSecrets를 비운다
// (의도된 동작). 따라서 currentAccountSecrets를 채우는 대입문은 반드시 그
// 호출 뒤에 와야 한다. 앞에 두면 방금 채운 값이 같은 동기 호출 안에서 곧바로
// 지워져 /submitTransaction이 항상 실패한다 — wallet_agent.js를 import하면
// 최상위에서 app.listen(5001)이 실행되므로(사용자 프로세스와 충돌), 여기서는
// 이미 로드된 모듈을 다시 import하지 않고 소스 텍스트만 읽어 순서를 검사한다.
const walletAgentSourceForOrderCheck = fs.readFileSync('wallet_agent.js', 'utf8');

// 'generateNewSessionKey()'만으로 찾으면 함수 정의 자체
// ('function generateNewSessionKey() {')가 먼저 걸려 늘 통과하는 무의미한
// 검사가 되므로, 실제 호출부에만 있는 '= generateNewSessionKey();' 패턴으로 찾는다.
const sessionKeyCallIndex = walletAgentSourceForOrderCheck.indexOf('= generateNewSessionKey();');
const secretsAssignIndex = walletAgentSourceForOrderCheck.indexOf('currentAccountSecrets = {');

assert.notEqual(sessionKeyCallIndex, -1, 'generateNewSessionKey() call not found in wallet_agent.js');
assert.notEqual(secretsAssignIndex, -1, 'currentAccountSecrets = { ... } assignment not found in wallet_agent.js');
assert(
  sessionKeyCallIndex < secretsAssignIndex,
  'currentAccountSecrets must be assigned AFTER generateNewSessionKey() runs — ' +
    'generateNewSessionKey() clears currentAccountSecrets to null, so assigning before it ' +
    'means the value is wiped immediately and /submitTransaction always fails',
);

console.log('PASS: currentAccountSecrets is assigned after generateNewSessionKey() clears it.');
