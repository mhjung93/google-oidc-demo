import assert from 'node:assert/strict';
import { shouldReuseProof } from '../wallet_agent.js';

// wallet_agent.js가 실제로 쓰는 판정 함수를 그대로 불러 검증한다.
// (증명 생성 자체는 느리므로 여기서는 재사용 판정 규칙만 본다.)
assert.equal(shouldReuseProof(null, 'r1', 's1'), false, 'no cache -> must prove');
assert.equal(shouldReuseProof({ root: 'r1', sessionKeyId: 's1' }, 'r1', 's1'), true, 'same root and session -> reuse');
assert.equal(shouldReuseProof({ root: 'r1', sessionKeyId: 's1' }, 'r2', 's1'), false, 'root changed -> reprove');
assert.equal(shouldReuseProof({ root: 'r1', sessionKeyId: 's1' }, 'r1', 's2'), false, 'new session key -> reprove');

console.log('PASS: proof cache is reused only for the same session key and root.');
