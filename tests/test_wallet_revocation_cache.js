// wallet_agent.js의 pi_pk_i 증명 재사용 판정.
//   node tests/test_wallet_revocation_cache.js
//
// v3(이중 트리)에서 판정 기준이 바뀌었다. v2에서는 폐기 root 하나였지만, 이제는
// **서브트리 root 두 개**다 — 이게 이중 트리 설계의 요점이다.
//
// 다른 샤드에서 폐기가 나면 통합 topRoot는 바뀌지만 내 서브트리 root는 그대로다.
// 그때 증명을 재생성하면 설계의 이득(500ms짜리 SNARK가 타인 폐기에 살아남는 것)이
// 통째로 사라진다. 그래서 topRoot로 판정하지 않는다는 것을 여기서 고정한다.
import assert from 'node:assert/strict';
import { shouldReuseProof } from '../wallet_agent.js';

const cache = { sessRoot: 'S1', acctRoot: 'A1', sessionKeyId: 's1' };

assert.equal(shouldReuseProof(null, 'S1', 'A1', 's1'), false, '캐시 없음 -> 증명해야 한다');
assert.equal(shouldReuseProof(cache, 'S1', 'A1', 's1'), true, '두 서브트리 root와 세션이 같으면 재사용');
assert.equal(shouldReuseProof(cache, 'S2', 'A1', 's1'), false, '세션 서브트리가 바뀌면 재증명');
assert.equal(shouldReuseProof(cache, 'S1', 'A2', 's1'), false, '계정 서브트리가 바뀌면 재증명');
assert.equal(shouldReuseProof(cache, 'S1', 'A1', 's2'), false, '세션 키가 바뀌면 재증명');

// 핵심: 판정에 topRoot가 끼어들면 안 된다. 캐시에 낡은 topRoot가 들어 있어도
// 서브트리 root가 같으면 재사용해야 한다(타인 폐기 경로).
const staleTop = { ...cache, topRoot: '0xdeadbeef' };
assert.equal(
  shouldReuseProof(staleTop, 'S1', 'A1', 's1'),
  true,
  'topRoot가 낡았어도 서브트리 root가 같으면 재사용해야 한다 — 이게 이중 트리의 이득이다',
);

console.log('PASS: 증명 재사용 판정은 서브트리 root 두 개로만 한다 (topRoot는 온체인 대조용)');
