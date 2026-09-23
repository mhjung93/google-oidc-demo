// Mode 3 집합 소속 술어의 집합 트리 — 설계 2026-09-23-mode3-predicates-design.md §2.
// 회로(circuits/pi_cred.circom ⑦)·지갑(lib/mode3_wallet.js normalizeSet)·서비스(AttrGate 배포, 오프체인 정책)·테스트가 전부 이 정의를 쓴다.
// 리프 = 원소 값 그대로, 빈 자리 = SET_PAD(2^64) — 속성은 회로에서 64비트로 잘려 있어 어떤 속성도 패딩과 같을 수 없다.
import { buildPoseidon } from 'circomlibjs';

export const SET_DEPTH = 8;
export const SET_SIZE = 1 << SET_DEPTH;   // 256
export const SET_PAD = 1n << 64n;
const ATTR_MAX = 1n << 64n;
/** 집합 술어 없음 — 회로 입력 set_sel = 0, set_root = 0 (path·index 는 아무 값이나 되지만 0 으로 둔다). */
export const NO_SET = Object.freeze({ sel: 0n, root: 0n, index: 0, path: Object.freeze(Array(SET_DEPTH).fill(0n)) });

let poseidonPromise = null;
const getPoseidon = () => (poseidonPromise ??= buildPoseidon());
const fail = (reason, msg) => Object.assign(new Error(msg), { reason });

/** 형식 검사 + 오름차순 정렬 + 중복 제거. 오류는 bad_disclosure. */
export function normalizeMembers(members) {
  if (!Array.isArray(members) || members.length === 0) throw fail('bad_disclosure', 'set.members 는 비어 있지 않은 배열');
  const seen = new Set();
  for (const m of members) {
    if (typeof m !== 'string' && typeof m !== 'number' && typeof m !== 'bigint') throw fail('bad_disclosure', `set.members 원소가 정수가 아니다: ${String(m)}`);
    let v;
    try { v = BigInt(m); } catch { throw fail('bad_disclosure', `set.members 원소가 정수가 아니다: ${String(m)}`); }
    if (v < 0n || v >= ATTR_MAX) throw fail('bad_disclosure', `set.members 원소는 0 ≤ v < 2^64: ${String(m)}`);
    seen.add(v);
  }
  const sorted = [...seen].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (sorted.length > SET_SIZE) throw fail('bad_disclosure', `set.members 는 중복 제거 뒤 최대 ${SET_SIZE}개`);
  return sorted;
}

/** 리프층부터 root 까지 층별 노드. levels[0] = 리프 256개, levels[SET_DEPTH] = [root]. */
async function levels(sorted) {
  const poseidon = await getPoseidon();
  const H = (a, b) => poseidon.F.toObject(poseidon([a, b]));
  let layer = Array.from({ length: SET_SIZE }, (_, i) => (i < sorted.length ? sorted[i] : SET_PAD));
  const out = [layer];
  for (let d = 0; d < SET_DEPTH; d++) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) next.push(H(layer[i], layer[i + 1]));
    out.push(next); layer = next;
  }
  return out;
}

export async function setRoot(members) {
  const L = await levels(normalizeMembers(members));
  return L[SET_DEPTH][0];
}

/** value 의 멤버십 경로. path[i] 는 i 층의 형제, index 비트 i 가 1 이면 value 쪽이 오른쪽 자식이다(회로 ⑦ 의 MultiMux1 과 같은 규약). */
export async function setPath(members, value) {
  const sorted = normalizeMembers(members);
  const v = BigInt(value);
  const index = sorted.indexOf(v);
  if (index < 0) throw fail('disclosure_unsatisfiable', `값 ${v} 이 집합에 없다`);
  const L = await levels(sorted);
  const path = [];
  let idx = index;
  for (let d = 0; d < SET_DEPTH; d++) { path.push(L[d][idx ^ 1]); idx >>= 1; }
  return { index, path, root: L[SET_DEPTH][0] };
}
