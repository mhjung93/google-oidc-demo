// tests/test_mode3_rpc_proxy.mjs — 허용 목록 RPC 프록시의 본문 검사(lib/mode3_rpc_proxy.js). 외부 의존 없음. (unit)
import assert from 'node:assert/strict';
import { RPC_ALLOW, MAX_BATCH, checkRpcBody } from '../lib/mode3_rpc_proxy.js';

let fails = 0; const t = (n, f) => { try { f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.message); } };
const rq = (method, id = 1) => ({ jsonrpc: '2.0', id, method, params: [] });

t('허용 메서드 12개', () => assert.equal(RPC_ALLOW.length, 12));
t('eth_call 통과', () => assert.deepEqual(checkRpcBody(rq('eth_call')), { ok: true }));
for (const m of ['eth_sendTransaction', 'hardhat_mine', 'evm_mine', 'personal_unlockAccount', 'eth_accounts', 'eth_sign']) {
  t(`${m} 403`, () => assert.deepEqual(checkRpcBody(rq(m)), { ok: false, status: 403, reason: 'rpc_method_blocked', method: m }));
}
t('배치 안의 막힌 메서드 → 전체 403', () => assert.deepEqual(checkRpcBody([rq('eth_call'), rq('evm_mine', 2)]), { ok: false, status: 403, reason: 'rpc_method_blocked', method: 'evm_mine' }));
t('허용만 든 배치 통과', () => assert.deepEqual(checkRpcBody([rq('eth_call'), rq('eth_chainId', 2)]), { ok: true }));
t('빈 배열 400', () => assert.deepEqual(checkRpcBody([]), { ok: false, status: 400, reason: 'malformed' }));
// 2026-11-17(미뤄 둔 Minor C): 상류 부하 상한 — 배치는 MAX_BATCH(=ethers JsonRpcProvider 기본 batchMaxCount 100)개까지. 넘으면 400 rpc_batch_too_large.
t('MAX_BATCH 는 100(ethers 기본 batchMaxCount)', () => assert.equal(MAX_BATCH, 100));
t('101개 400 rpc_batch_too_large', () => assert.deepEqual(checkRpcBody(Array.from({ length: 101 }, (_, i) => rq('eth_call', i))), { ok: false, status: 400, reason: 'rpc_batch_too_large' }));
t('500개도 400 rpc_batch_too_large(옛 상한)', () => assert.equal(checkRpcBody(Array.from({ length: 500 }, (_, i) => rq('eth_call', i))).reason, 'rpc_batch_too_large'));
t('100개 통과', () => assert.deepEqual(checkRpcBody(Array.from({ length: 100 }, (_, i) => rq('eth_call', i))), { ok: true }));
t('{} 400', () => assert.equal(checkRpcBody({}).reason, 'malformed'));
t('method 가 숫자면 400', () => assert.equal(checkRpcBody({ jsonrpc: '2.0', id: 1, method: 5 }).reason, 'malformed'));
t('jsonrpc 없으면 400', () => assert.equal(checkRpcBody({ id: 1, method: 'eth_call' }).reason, 'malformed'));
t('null·문자열 400', () => { assert.equal(checkRpcBody(null).reason, 'malformed'); assert.equal(checkRpcBody('x').reason, 'malformed'); });
if (fails) { console.log(`\n${fails} FAILED`); process.exit(1); }
console.log('\nall ok');
