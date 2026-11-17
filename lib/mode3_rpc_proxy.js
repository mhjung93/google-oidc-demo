// 사용자 정적 서버(passkey-web)의 같은 오리진 JSON-RPC 프록시가 쓰는 본문 검사. 읽기 메서드만 통과시킨다 — 사용자 페이지가 체인에 쓰거나 노드를 조작하는 요청은 막는다.
export const RPC_ALLOW = Object.freeze([
  'eth_chainId', 'net_version', 'eth_blockNumber', 'eth_call', 'eth_getLogs', 'eth_getCode', 'eth_getBalance',
  'eth_getBlockByNumber', 'eth_getBlockByHash', 'eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getTransactionCount',
]);
const MAX_BATCH = 500;
const MALFORMED = Object.freeze({ ok: false, status: 400, reason: 'malformed' });

/** 객체 하나 또는 1~500개 배열. 원소마다 jsonrpc:'2.0'·문자열 method 여야 하고, 하나라도 허용 목록 밖이면 전체가 403 이다. */
export function checkRpcBody(body) {
  const items = Array.isArray(body) ? body : [body];
  if (items.length < 1 || items.length > MAX_BATCH) return { ...MALFORMED };
  for (const it of items) {
    if (!it || typeof it !== 'object' || Array.isArray(it) || it.jsonrpc !== '2.0' || typeof it.method !== 'string') return { ...MALFORMED };
  }
  for (const it of items) {
    if (!RPC_ALLOW.includes(it.method)) return { ok: false, status: 403, reason: 'rpc_method_blocked', method: it.method };
  }
  return { ok: true };
}
