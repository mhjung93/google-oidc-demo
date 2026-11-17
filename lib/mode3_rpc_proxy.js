// 사용자 정적 서버(passkey-web)의 같은 오리진 JSON-RPC 프록시가 쓰는 본문 검사. 읽기 메서드만 통과시킨다 — 사용자 페이지가 체인에 쓰거나 노드를 조작하는 요청은 막는다.
export const RPC_ALLOW = Object.freeze([
  'eth_chainId', 'net_version', 'eth_blockNumber', 'eth_call', 'eth_getLogs', 'eth_getCode', 'eth_getBalance',
  'eth_getBlockByNumber', 'eth_getBlockByHash', 'eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getTransactionCount',
]);
// 상류 부하 상한(2026-11-17 미뤄 둔 Minor C): 요청 하나가 체인 노드에 거는 호출 수를 묶는다(eth_getLogs·eth_call 수백 건 배치 방지).
// 100 은 ethers JsonRpcProvider 의 기본 batchMaxCount 다 — 사용자 페이지(mode3/user/user.js)의 provider 는 그보다 큰 배치를 만들지 않으므로 정상 흐름은 걸리지 않는다.
export const MAX_BATCH = 100;
const MALFORMED = Object.freeze({ ok: false, status: 400, reason: 'malformed' });

/** 객체 하나 또는 1~MAX_BATCH 개 배열. 원소마다 jsonrpc:'2.0'·문자열 method 여야 하고, 하나라도 허용 목록 밖이면 전체가 403 이다. 상한을 넘으면 400 rpc_batch_too_large. */
export function checkRpcBody(body) {
  const items = Array.isArray(body) ? body : [body];
  if (items.length < 1) return { ...MALFORMED };
  if (items.length > MAX_BATCH) return { ok: false, status: 400, reason: 'rpc_batch_too_large' };
  for (const it of items) {
    if (!it || typeof it !== 'object' || Array.isArray(it) || it.jsonrpc !== '2.0' || typeof it.method !== 'string') return { ...MALFORMED };
  }
  for (const it of items) {
    if (!RPC_ALLOW.includes(it.method)) return { ok: false, status: 403, reason: 'rpc_method_blocked', method: it.method };
  }
  return { ok: true };
}
