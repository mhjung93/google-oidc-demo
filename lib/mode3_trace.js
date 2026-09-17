// 2-of-2 트레이스 태그 — 설계 2026-09-16 §4.1.
//   pk_trace = (x_svc + x_AA)·B8          서비스 조각 + CIA 조각. 승인 때 CIA 가 만들어 cert_s 에 싣는다
//   c1 = r·B8,  K = r·pk_trace,  c2 = Poseidon(uid, arid) + Poseidon(K.x, K.y)  (평문 h — 2026-09-18 §3.4)      지갑이 로그인마다 새 r 로
//   복호: K = x_svc·c1 + x_AA·c1 — 두 부분 복호를 더해야 K 가 나온다. 어느 조각 하나로는 안 된다
// 해시 ElGamal 인 이유: uid 를 점으로 인코딩하면 복호 뒤 이산로그가 필요하고 회로에 점 덧셈이 더 든다.
// 회로 판은 circuits/lib/mode3_trace_tag.circom — 같은 B8, 같은 Poseidon(2), 같은 250비트 상한.
import { randomBytes } from 'node:crypto';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import { SCALAR_MAX } from './mode3_credential.js';

/** circomlib eddsaposeidon.circom 의 BASE8 = circomlibjs Base8. pk_CIA 와 같은 부분군의 생성원. */
export const B8 = Object.freeze([
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
]);

let bjP = null, psP = null;
const getBj = () => (bjP ??= buildBabyjub());
const getPs = () => (psP ??= buildPoseidon());
const toObj = (bj, P) => ({ x: bj.F.toObject(P[0]), y: bj.F.toObject(P[1]) });
const fromObj = (bj, o) => [bj.F.e(o.x), bj.F.e(o.y)];

function checkScalar(v, name) {
  if (typeof v !== 'bigint' || v < 0n || v >= SCALAR_MAX) throw new Error(`${name} 는 [0, 2^250) bigint`);
}

/** 정규 인코딩·곡선 위·소수 위수 부분군·항등원 아님. 항등원 X_svc 를 받으면 pk_trace 가 CIA 조각만으로 열린다. */
export async function isTracePoint(o) {
  const bj = await getBj();
  if (typeof o?.x !== 'bigint' || typeof o?.y !== 'bigint') return false;
  const p = bj.F.p;
  if (o.x < 0n || o.x >= p || o.y < 0n || o.y >= p) return false;
  if (o.x === 0n && o.y === 1n) return false;
  const P = fromObj(bj, o);
  return bj.inCurve(P) && bj.inSubgroup(P);
}

/** [1, 2^250) 균일. 0 은 다시 뽑는다 — c1 이 항등원이면 태그가 uid 를 그대로 드러낸다. */
export function randomTraceScalar() {
  for (;;) {
    let v = 0n;
    for (const b of randomBytes(32)) v = (v << 8n) | BigInt(b);
    v &= SCALAR_MAX - 1n;
    if (v !== 0n) return v;
  }
}

/** 조각 하나: 비밀 x 와 공개 X = x·B8. 서비스(x_svc)와 CIA(x_AA,s)가 각자 만든다. */
export async function createShare() {
  const bj = await getBj();
  const x = randomTraceScalar();
  return { x, X: toObj(bj, bj.mulPointEscalar(bj.Base8, x)) };
}

export async function combinePublicKey(A, B) {
  const bj = await getBj();
  return toObj(bj, bj.addPoint(fromObj(bj, A), fromObj(bj, B)));
}

async function maskOf(K) {
  const ps = await getPs();
  return ps.F.toObject(ps([K.x, K.y]));
}

/** 태그 평문 h = Poseidon(uid, arid) — 설계 2026-09-18 §3.4. 회로 TraceTag 와 같은 계산. 복호해도 uid 원문이 아니라 서비스별 값이 나온다. */
export async function tagPlaintext(uid, arid) {
  checkScalar(uid, 'uid'); checkScalar(arid, 'arid');
  const ps = await getPs();
  return ps.F.toObject(ps([uid, arid]));
}

export async function encryptTag(pk_trace, uid, arid, r = randomTraceScalar()) {
  const h = await tagPlaintext(uid, arid);
  if (typeof r !== 'bigint' || r <= 0n || r >= SCALAR_MAX) throw new Error('r 는 [1, 2^250) bigint');
  const bj = await getBj();
  const c1 = toObj(bj, bj.mulPointEscalar(bj.Base8, r));
  const K = toObj(bj, bj.mulPointEscalar(fromObj(bj, pk_trace), r));
  const c2 = (h + await maskOf(K)) % bj.F.p;
  return { c1, c2, r, h };
}

/** 복호 결과 h 를 등록부의 uid(10진 문자열 배열)로 되돌린다. 없으면 null. 데모 등록부는 작아 단순 반복한다 — 호출자가 arid 별로 캐시해도 된다. */
export async function resolveTagPlaintext(h, arid, uids) {
  for (const u of uids) if ((await tagPlaintext(BigInt(u), arid)) === h) return u;
  return null;
}

/** 조각 x 로 c1 을 곱한다. 서비스는 D_svc = x_svc·c1 을 개봉 요청에 싣고, CIA 는 승인 때 x_AA·c1 을 더한다. */
export async function partialDecrypt(x, c1) {
  checkScalar(x, 'x');
  const bj = await getBj();
  return toObj(bj, bj.mulPointEscalar(fromObj(bj, c1), x));
}

export async function combineDecrypt(c2, D_a, D_b) {
  const bj = await getBj();
  const K = toObj(bj, bj.addPoint(fromObj(bj, D_a), fromObj(bj, D_b)));
  const p = bj.F.p;
  return (((c2 - await maskOf(K)) % p) + p) % p;
}
