// lib/mode3_trace_record.js — PPID 계정에 한 번 남기는 추적 기록(스펙 2026-11-26 ppid-account-trace). 브라우저(암호화·증명 입력), 감사자(부분 복호), 조합자(zkWrapper)가 같이 쓴다.
//
//   감사자 키   x = f(0),  f(z) = a0 + a1·z (mod L)   조각 x_i = f(i), i = 1..3 (2-of-3 Shamir, L = Baby Jubjub 부분군의 위수)
//               pk_aud = x·B8,  조각의 공개키 X_i = x_i·B8
//   암호문      c1 = rho·B8,  K = rho·pk_aud,  c2 = auid + Poseidon(K.x, K.y)        (회로 circuits/pi_trace.circom 과 같은 식)
//   부분 복호   D_i = x_i·c1  +  DLEQ 증명(log_B8 X_i = log_c1 D_i) — 조각을 드러내지 않고 "이 D_i 는 내 조각으로 만든 것" 을 보인다
//   조합        K = λ_i·D_i + λ_j·D_j (라그랑주 계수, z = 0),  auid = c2 − Poseidon(K.x, K.y)
//
// 조각 하나로는 K 가 나오지 않는다. 틀린 D_i 는 DLEQ 가 걸러 낸다(틀린 조각으로 엉뚱한 auid 가 나오지 않게).
// 데모의 키 생성은 딜러 한 번이다(조각을 만들어 나눠 주고 비밀 x 는 버린다) — 운영이라면 분산 키 생성이 필요하다(스펙 §3).
import { randomBytes } from 'node:crypto';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import { SCALAR_MAX, auidOf, ppid } from './mode3_credential.js';

/** π_trace 의 공개 입력 순서(circuits/pi_trace.circom·contracts/TraceRegistry.sol 과 함께 바꾼다). */
export const TRACE_PUB_INDEX = Object.freeze({ PPID: 0, ARID: 1, CHAINID: 2, PK_AUD_X: 3, PK_AUD_Y: 4, C1_X: 5, C1_Y: 6, C2: 7, COUNT: 8 });
export const DOMAIN_MODE3_TRACE_DLEQ = 0x4d4f44453354524143454451n;   // ASCII "MODE3TRACEDQ"
export const AUDITORS = 3, THRESHOLD = 2;

let bjP = null, psP = null;
const getBj = () => (bjP ??= buildBabyjub());
const getPs = () => (psP ??= buildPoseidon());
const toObj = (bj, P) => ({ x: bj.F.toObject(P[0]), y: bj.F.toObject(P[1]) });
const fromObj = (bj, o) => [bj.F.e(o.x), bj.F.e(o.y)];
const big = (v, name) => { if (typeof v !== 'bigint') throw new Error(`${name} 는 bigint`); return v; };
const mod = (a, n) => ((a % n) + n) % n;
/** n 은 소수다(부분군의 위수) — 역원은 페르마의 소정리로. */
function inv(a, n) { let r = 1n, b = mod(a, n), e = n - 2n; while (e > 0n) { if (e & 1n) r = (r * b) % n; b = (b * b) % n; e >>= 1n; } return r; }
async function randomZr(bj) { for (;;) { const v = BigInt('0x' + randomBytes(64).toString('hex')) % bj.subOrder; if (v !== 0n) return v; } }
/** 곡선 위·소수 위수 부분군·항등원 아님. */
export async function isSubgroupPoint(o) {
  try {
    const bj = await getBj();
    if (typeof o?.x !== 'bigint' || typeof o?.y !== 'bigint' || o.x < 0n || o.y < 0n || o.x >= bj.F.p || o.y >= bj.F.p) return false;
    const P = fromObj(bj, o);
    return bj.inCurve(P) && bj.inSubgroup(P) && !(o.x === 0n && o.y === 1n);
  } catch { return false; }
}
const sameSet = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

/** 딜러의 키 생성(데모): { pk, shares: [{ index, x, X }] }. 비밀 x 는 돌려주지 않는다. */
export async function dealAuditorKey() {
  const bj = await getBj(), L = bj.subOrder;
  const a0 = await randomZr(bj), a1 = await randomZr(bj);
  const shares = [];
  for (let i = 1; i <= AUDITORS; i++) {
    const x = mod(a0 + a1 * BigInt(i), L);
    if (x === 0n) return dealAuditorKey();   // 일어나지 않지만(확률 2^-251) 조각이 0 이면 다시 뽑는다
    shares.push({ index: i, x, X: toObj(bj, bj.mulPointEscalar(bj.Base8, x)) });
  }
  return { pk: toObj(bj, bj.mulPointEscalar(bj.Base8, a0)), shares };
}
/** 조각의 공개키 X = x·B8. */
export async function sharePublic(x) { const bj = await getBj(); return toObj(bj, bj.mulPointEscalar(bj.Base8, big(x, 'x'))); }
/** 조각 공개키 둘(서로 다른 index)에서 pk_aud 를 다시 계산한다 — 감사자들이 올린 X_i 가 컨트랙트의 pk_aud 와 맞는지 볼 때 쓴다. */
export async function pkFromShares(a, b) {
  const bj = await getBj(), L = bj.subOrder;
  const [la, lb] = lagrange(a.index, b.index, L);
  return toObj(bj, bj.addPoint(bj.mulPointEscalar(fromObj(bj, a.X), la), bj.mulPointEscalar(fromObj(bj, b.X), lb)));
}
function lagrange(i, j, L) {
  if (!Number.isInteger(i) || !Number.isInteger(j) || i === j || i < 1 || j < 1 || i > AUDITORS || j > AUDITORS) throw new Error('조각의 index 는 1..3 의 서로 다른 둘');
  const I = BigInt(i), J = BigInt(j);
  return [mod(J * inv(J - I, L), L), mod(I * inv(I - J, L), L)];
}

async function maskOf(K) { const ps = await getPs(); return ps.F.toObject(ps([K.x, K.y])); }

/** auid 를 pk_aud 로 암호화한다 → { c1, c2, rho }. rho 는 [1, 2^250)(회로의 Num2Bits(250)). */
export async function encryptTrace(pk_aud, auid, rho = null) {
  const bj = await getBj();
  if (!(await isSubgroupPoint(pk_aud))) throw new Error('pk_aud 가 부분군의 점이 아니다');
  big(auid, 'auid'); if (auid < 0n || auid >= bj.F.p) throw new Error('auid 는 필드 원소');
  let r = rho;
  if (r === null) { do { r = BigInt('0x' + randomBytes(32).toString('hex')) % SCALAR_MAX; } while (r === 0n); }
  if (typeof r !== 'bigint' || r <= 0n || r >= SCALAR_MAX) throw new Error('rho 는 [1, 2^250) bigint');
  const c1 = toObj(bj, bj.mulPointEscalar(bj.Base8, r));
  const K = toObj(bj, bj.mulPointEscalar(fromObj(bj, pk_aud), r));
  return { c1, c2: (auid + await maskOf(K)) % bj.F.p, rho: r };
}

// ctx: 이 부분 복호가 답하는 개봉 요청(체인·등록부·요청 번호 — lib/mode3_trace_chain.js traceCtx). 다른 요청에 낸 조각을 이 요청의 것으로 내지 못한다(2026-11-26 검토 M-3).
async function dleqChallenge(X, c1, D, A, B, ctx) {
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_TRACE_DLEQ, X.x, X.y, c1.x, c1.y, D.x, D.y, A.x, A.y, B.x, B.y, ctx])) & (SCALAR_MAX - 1n);
}
const ctxOf = async (ctx) => { const bj = await getBj(); if (typeof ctx !== 'bigint' || ctx < 0n || ctx >= bj.F.p) throw new Error('ctx 는 필드 원소(bigint)'); return ctx; };
/** 감사자의 부분 복호: 조각 { index, x } 로 D = x·c1 과 DLEQ 증명을 낸다 → { index, D, proof: { A, B, z } }. ctx 는 답하는 요청(기본 0 — 요청 없이 쓰는 테스트). */
export async function partialDecryptTrace(share, c1, ctx = 0n) {
  await ctxOf(ctx);
  const bj = await getBj(), L = bj.subOrder;
  const x = big(share?.x, 'share.x');
  if (x <= 0n || x >= L) throw new Error('조각은 [1, L)');
  if (!(await isSubgroupPoint(c1))) throw new Error('c1 이 부분군의 점이 아니다');
  const C = fromObj(bj, c1);
  const X = toObj(bj, bj.mulPointEscalar(bj.Base8, x)), D = toObj(bj, bj.mulPointEscalar(C, x));
  const k = await randomZr(bj);
  const A = toObj(bj, bj.mulPointEscalar(bj.Base8, k)), B = toObj(bj, bj.mulPointEscalar(C, k));
  const e = await dleqChallenge(X, c1, D, A, B, ctx);
  return { index: share.index, D, proof: { A, B, z: mod(k + e * x, L) } };
}
/** 부분 복호의 확인: X(그 감사자의 조각 공개키)에 대해 z·B8 = A + e·X 이고 z·c1 = B + e·D. 형식이 깨져도 false. */
export async function verifyPartial(X, c1, part, ctx = 0n) {
  try {
    await ctxOf(ctx);
    const bj = await getBj();
    const { D, proof } = part ?? {};
    for (const P of [X, c1, D]) if (!(await isSubgroupPoint(P))) return false;
    const { A, B, z } = proof ?? {};
    for (const P of [A, B]) { if (typeof P?.x !== 'bigint' || typeof P?.y !== 'bigint') return false; const Q = fromObj(bj, P); if (!bj.inCurve(Q) || !bj.inSubgroup(Q)) return false; }
    if (typeof z !== 'bigint' || z < 0n || z >= bj.subOrder) return false;
    const e = await dleqChallenge(X, c1, D, A, B, ctx);
    const eq = (P, Q) => bj.F.eq(P[0], Q[0]) && bj.F.eq(P[1], Q[1]);
    return eq(bj.mulPointEscalar(bj.Base8, z), bj.addPoint(fromObj(bj, A), bj.mulPointEscalar(fromObj(bj, X), e)))
      && eq(bj.mulPointEscalar(fromObj(bj, c1), z), bj.addPoint(fromObj(bj, B), bj.mulPointEscalar(fromObj(bj, D), e)));
  } catch { return false; }
}
/** 부분 복호 둘(서로 다른 index)을 합쳐 auid 를 얻는다. 호출자가 먼저 verifyPartial 로 둘을 확인한다. */
export async function combineTrace(c2, a, b) {
  const bj = await getBj(), L = bj.subOrder, p = bj.F.p;
  const [la, lb] = lagrange(a.index, b.index, L);
  const K = toObj(bj, bj.addPoint(bj.mulPointEscalar(fromObj(bj, a.D), la), bj.mulPointEscalar(fromObj(bj, b.D), lb)));
  return mod(big(c2, 'c2') - await maskOf(K), p);
}

/** 조합자(zkWrapper)가 하는 일 전부: 감사자들이 낸 부분 복호(parts — 둘 이상)를 확인하고 합쳐 auid 를 얻는다.
 *  pk: 등록부 컨트랙트에 고정된 pk_aud. shareXs: { [index]: X_i }(감사자들이 공개한 조각 공개키). 검사: 고른 두 조각의 X 로 다시 계산한 키가 pk 와 같고(다른 키의 조각을 섞지 못한다),
 *  두 부분 복호의 DLEQ 가 맞는다(ctx — 그 요청에 낸 것). DLEQ 를 통과한 것들 가운데 키가 맞는 첫 쌍을 쓴다. 성공 { auid, used: [i, j] }, 실패는 던진다(reason: trace_shares_short | trace_share_bad | trace_key_mismatch). */
export async function openFromParts({ pk, shareXs, c1, c2, parts, ctx = 0n }) {
  const fail = (reason) => Object.assign(new Error(reason), { reason });
  const good = [];
  for (const part of Array.isArray(parts) ? parts : []) {
    const X = shareXs?.[part?.index];
    if (!X || good.some((g) => g.index === part.index)) continue;
    if (await verifyPartial(X, c1, part, ctx)) good.push(part);
  }
  if (!Array.isArray(parts) || parts.length < THRESHOLD) throw fail('trace_shares_short');
  if (good.length < THRESHOLD) throw fail('trace_share_bad');
  for (let i = 0; i < good.length; i++) for (let j = i + 1; j < good.length; j++) {
    const a = good[i], b = good[j];
    const again = await pkFromShares({ index: a.index, X: shareXs[a.index] }, { index: b.index, X: shareXs[b.index] });
    if (again.x === pk.x && again.y === pk.y) return { auid: await combineTrace(c2, a, b), used: [a.index, b.index] };
  }
  throw fail('trace_key_mismatch');
}

/** π_trace 의 회로 입력과 공개 입력(10진 문자열 8개) — 브라우저가 증명을 만들기 전에 조립한다. */
export async function traceWitness({ s_u, arid, chainid, pk_aud, rho = null }) {
  const auid = await auidOf({ s_u: big(s_u, 's_u') });
  const PPID = await ppid({ s_u, arid: big(arid, 'arid'), chainid: big(chainid, 'chainid') });
  const { c1, c2, rho: r } = await encryptTrace(pk_aud, auid, rho);
  const pub = [PPID, arid, chainid, pk_aud.x, pk_aud.y, c1.x, c1.y, c2].map(String);
  const input = { s_u: s_u.toString(), rho: r.toString(), PPID: pub[0], arid: pub[1], chainid: pub[2], pk_aud_x: pub[3], pk_aud_y: pub[4], c1_x: pub[5], c1_y: pub[6], c2: pub[7] };
  return { input, publicSignals: pub, PPID, auid, c1, c2 };
}
/** 증명이 낸 공개 입력이 조립한 것과 같은가(순서까지). */
export const samePublicSignals = (a, b) => Array.isArray(a) && Array.isArray(b) && sameSet(a.map(String), b.map(String));

// 점·조각의 JSON 모양(10진 문자열) — 파일·HTTP 로 옮길 때.
export const ptToJson = (P) => ({ x: P.x.toString(), y: P.y.toString() });
export const ptFromJson = (o) => { if (!/^[0-9]+$/.test(String(o?.x)) || !/^[0-9]+$/.test(String(o?.y))) throw new Error('점의 모양'); return { x: BigInt(o.x), y: BigInt(o.y) }; };
export const partToJson = (part) => ({ index: part.index, D: ptToJson(part.D), proof: { A: ptToJson(part.proof.A), B: ptToJson(part.proof.B), z: part.proof.z.toString() } });
export const partFromJson = (o) => ({ index: Number(o.index), D: ptFromJson(o.D), proof: { A: ptFromJson(o.proof?.A), B: ptFromJson(o.proof?.B), z: BigInt(String(o.proof?.z)) } });
