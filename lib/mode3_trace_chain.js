// lib/mode3_trace_chain.js — 추적 기록 등록부(contracts/TraceRegistry.sol)의 ABI·배포·감사자 키 파일(스펙 2026-11-26 ppid-account-trace). Node 전용(파일·배포).
// 브라우저는 ABI(TRACE_REGISTRY_ABI)만 쓴다 — 그 부분은 파일 시스템을 만지지 않는다.
import { ethers } from 'ethers';

export const TRACE_REGISTRY_ABI = [
  'function pkAudX() view returns (uint256)',
  'function pkAudY() view returns (uint256)',
  'function auditors(uint256) view returns (address)',
  'function has(uint256 ppid) view returns (bool)',
  'function recordOf(uint256 ppid) view returns (uint256 arid, uint256 c1x, uint256 c1y, uint256 c2, uint64 registeredAt)',
  'function register(uint256 ppid, uint256 arid, uint256 c1x, uint256 c1y, uint256 c2, uint256[2] a, uint256[2][2] b, uint256[2] c)',
  'function requestOpen(uint256 ppid, bytes32 reasonHash) returns (uint256 id)',
  'function noteShare(uint256 id, bytes32 shareHash)',
  'function requestCount() view returns (uint256)',
  'function requestOf(uint256 id) view returns (uint256 ppid, address requester, bytes32 reasonHash, uint64 requestedAt, uint8 shareBits)',
  'event TraceRegistered(uint256 indexed ppid, uint256 indexed arid)',
  'event OpenRequested(uint256 indexed id, uint256 indexed ppid, address indexed requester, bytes32 reasonHash)',
  'event ShareSubmitted(uint256 indexed id, uint8 indexed auditorIndex, bytes32 shareHash)',
  'error AlreadyRegistered(uint256 ppid)', 'error InvalidProof()', 'error NotRegistered(uint256 ppid)', 'error UnknownRequest(uint256 id)', 'error NotAuditor()', 'error AlreadySubmitted(uint256 id, uint8 auditorIndex)', 'error BadAuditors()',
];
export const traceRegistryAt = (address, runner) => new ethers.Contract(address, TRACE_REGISTRY_ABI, runner);
export const isAddress = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
/** 등록부에 고정된 감사자 공개키. */
export async function registryPk(registry) { return { x: await registry.pkAudX(), y: await registry.pkAudY() }; }
/** 부분 복호가 답하는 요청의 문맥(DLEQ 에 묶는다) — 체인·등록부 주소·요청 번호의 해시(필드에 들어가게 248비트). */
export const traceCtx = ({ chainId, registry, id }) => BigInt(ethers.solidityPackedKeccak256(['uint256', 'address', 'uint256'], [BigInt(chainId), registry, BigInt(id)])) >> 8n;
/** 등록부의 개봉 요청(번호순, 가장 최근 max 건) — { id, ppid, requester, reasonHash, requestedAt, shares:[index] }. 하나씩 읽으므로 상한을 둔다(요청은 아무나 낼 수 있다 — 2026-11-26 검토 M-2). */
export async function listOpenRequests(registry, { max = 200 } = {}) {
  const n = Number(await registry.requestCount()), out = [];
  for (let id = Math.max(0, n - max); id < n; id++) {
    const q = await registry.requestOf(id);
    out.push({ id, ppid: q.ppid.toString(), requester: q.requester, reasonHash: q.reasonHash, requestedAt: Number(q.requestedAt), shares: [1, 2, 3].filter((i) => (Number(q.shareBits) >> (i - 1)) & 1) });
  }
  return out;
}
