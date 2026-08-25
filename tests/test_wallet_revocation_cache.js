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

// --- 폐기 목록 조회가 캐시 판정보다 뒤에 오는지 회귀 테스트 ---
// fetchRevocationWitnesses()가 캐시 판정보다 앞에 있으면, 증명을 재사용하는
// 경우에도 트랜잭션마다 IdP로 요청이 나간다. IdP는 로그인 시점에 uid와 클라이언트의
// 네트워크 신원을 알고 있으므로, IdP 로그와 체인을 함께 보면 "조회 → Δ 후 지갑 W에서
// tx" 타이밍 상관으로 지갑↔uid가 연결된다. 캐시 적중 경로에서는 IdP가 아니라
// 레지스트리(온체인)에만 물어봐야 한다.
const cacheHitCheckIndex = walletAgentSourceForOrderCheck.indexOf(
  'cachedPiPkI?.sessionKeyId === sessionKeyId',
);
const fetchWitnessCallIndex = walletAgentSourceForOrderCheck.indexOf(
  'rev = await fetchRevocationWitnesses(',
);

assert.notEqual(cacheHitCheckIndex, -1, 'cache-hit check not found in wallet_agent.js');
assert.notEqual(fetchWitnessCallIndex, -1, 'fetchRevocationWitnesses() call site not found in wallet_agent.js');
assert(
  cacheHitCheckIndex < fetchWitnessCallIndex,
  'the cached-proof check must come BEFORE fetchRevocationWitnesses() — otherwise every ' +
    'transaction pings the IdP even when the cached proof is reused, and IdP logs correlate ' +
    'with on-chain transactions to link the wallet to the uid',
);

// 캐시 적중 여부는 IdP가 아니라 레지스트리에 물어봐야 한다.
assert(
  walletAgentSourceForOrderCheck.includes('isRevocationRootPublished(cachedPiPkI.root)'),
  'the cached root must be validated against the on-chain registry, not by re-fetching from the IdP',
);

console.log('PASS: the IdP revocation lookup only happens on a cache miss.');
