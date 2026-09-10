// 발급 PoK — 시그마 프로토콜. 설계 §6.2.
//
// CIA 는 uid 를 알고 arid·pk_i·blind 를 몰라야 한다. C_pt 에서 uid·G₁ 을 빼고
// 나머지 네 항의 표현(representation)을 아는지, 그리고 그 s_u 가 등록 때 낸 cm_u 의
// s_u 와 같은지를 한 증명으로 보인다. SNARK 가 아니라 회로·셋업이 없다 — 이것이
// 커밋을 Pedersen 으로 둔 이유다(§11).
//
// 시그마 프로토콜은 Z_r 상의 표현 지식만 증명하고 범위는 증명하지 않는다. 2^250 상한을
// 실제로 강제하는 것은 show 회로의 Num2Bits(250) 이다(§6.1) — 여기서 s_u < 2^250 을
// 검사하지 않으며, 검사할 방법도 없다.
import { randomBytes } from 'node:crypto';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import { PEDERSEN_GENERATORS } from './mode3_credential.js';

export const DOMAIN_MODE3_ISSUE = 365084431357343731766597n;   // ASCII "MODE3ISSUE"

const MASK_250 = (1n << 250n) - 1n;

let bjP = null, psP = null;
const getBj = () => (bjP ??= buildBabyjub());
const getPs = () => (psP ??= buildPoseidon());

function G(bj, name) {
  const g = PEDERSEN_GENERATORS[name];
  return [bj.F.e(g[0]), bj.F.e(g[1])];
}
const toObj = (bj, P) => ({ x: bj.F.toObject(P[0]), y: bj.F.toObject(P[1]) });
const fromObj = (bj, o) => [bj.F.e(o.x), bj.F.e(o.y)];
const eqPt = (bj, A, B) => bj.F.eq(A[0], B[0]) && bj.F.eq(A[1], B[1]);
const negPt = (bj, P) => [bj.F.neg(P[0]), P[1]];

/** Z_r 균일. 512비트를 뽑아 mod r — 편향 2^-260. 256비트 mod r 은 편향이 2^-5 라 못 쓴다. */
export async function randomZr() {
  const bj = await getBj();
  return BigInt('0x' + randomBytes(64).toString('hex')) % bj.subOrder;
}

function msm(bj, terms) {
  // terms: [[scalar, point], ...] — 곱해서 전부 더한다
  let acc = null;
  for (const [e, P] of terms) {
    const Q = bj.mulPointEscalar(P, e);
    acc = acc === null ? Q : bj.addPoint(acc, Q);
  }
  return acc;
}

/** cm_u = s_u·G₃ + r_u·H. 등록 시 사용자가 만들어 CIA 에 낸다(§6.1). */
export async function registrationCommit(s_u, r_u) {
  const bj = await getBj();
  return toObj(bj, msm(bj, [[s_u, G(bj, 's_u')], [r_u, G(bj, 'blind')]]));
}

async function challenge(bj, uid, C_pt, cm_u, T1, T2) {
  const ps = await getPs();
  const h = ps.F.toObject(ps([
    DOMAIN_MODE3_ISSUE, uid,
    C_pt.x, C_pt.y, cm_u.x, cm_u.y, T1.x, T1.y, T2.x, T2.y,
  ]));
  return h & MASK_250;
}

export async function proveIssuance({ uid, arid, s_u, blind, pk_i, r_u }) {
  const bj = await getBj();
  const r = bj.subOrder;
  const [G1, G2, G3, G4, H] = ['uid', 'arid', 's_u', 'pk_i', 'blind'].map((n) => G(bj, n));

  const C_ptP = msm(bj, [[uid, G1], [arid, G2], [s_u, G3], [pk_i, G4], [blind, H]]);
  const cm_uP = msm(bj, [[s_u, G3], [r_u, H]]);
  const C_pt = toObj(bj, C_ptP);
  const cm_u = toObj(bj, cm_uP);

  const a = {};
  for (const k of ['arid', 'su', 'pki', 'blind', 'ru']) a[k] = await randomZr();
  const T1 = toObj(bj, msm(bj, [[a.arid, G2], [a.su, G3], [a.pki, G4], [a.blind, H]]));
  const T2 = toObj(bj, msm(bj, [[a.su, G3], [a.ru, H]]));

  const c = await challenge(bj, uid, C_pt, cm_u, T1, T2);
  const z = (ax, x) => (ax + c * x) % r;
  const proof = {
    T1, T2, c,
    z_arid: z(a.arid, arid), z_su: z(a.su, s_u), z_pki: z(a.pki, pk_i),
    z_blind: z(a.blind, blind), z_ru: z(a.ru, r_u),
  };
  return { C_pt, cm_u, proof };
}

function validPoint(bj, o) {
  if (typeof o?.x !== 'bigint' || typeof o?.y !== 'bigint') return false;
  const P = fromObj(bj, o);
  return bj.inCurve(P) && bj.inSubgroup(P);
}

export async function verifyIssuance({ uid, C_pt, cm_u, proof }) {
  const bj = await getBj();
  const r = bj.subOrder;
  const { T1, T2, c, z_arid, z_su, z_pki, z_blind, z_ru } = proof ?? {};
  // 1) 형식·군 검사. 부분군 밖의 점은 작은 위수 성분으로 등식을 만족시킬 수 있어 거절한다.
  for (const P of [C_pt, cm_u, T1, T2]) if (!validPoint(bj, P)) return false;
  for (const z of [c, z_arid, z_su, z_pki, z_blind, z_ru]) {
    if (typeof z !== 'bigint' || z < 0n || z >= r) return false;
  }
  if (typeof uid !== 'bigint' || uid < 0n) return false;
  // 2) 챌린지 재계산
  if ((await challenge(bj, uid, C_pt, cm_u, T1, T2)) !== c) return false;
  // 3) 두 등식
  const [G1, G2, G3, G4, H] = ['uid', 'arid', 's_u', 'pk_i', 'blind'].map((n) => G(bj, n));
  const Y1 = bj.addPoint(fromObj(bj, C_pt), negPt(bj, bj.mulPointEscalar(G1, uid)));
  const lhs1 = msm(bj, [[z_arid, G2], [z_su, G3], [z_pki, G4], [z_blind, H]]);
  const rhs1 = bj.addPoint(fromObj(bj, T1), bj.mulPointEscalar(Y1, c));
  if (!eqPt(bj, lhs1, rhs1)) return false;
  const lhs2 = msm(bj, [[z_su, G3], [z_ru, H]]);
  const rhs2 = bj.addPoint(fromObj(bj, T2), bj.mulPointEscalar(fromObj(bj, cm_u), c));
  return eqPt(bj, lhs2, rhs2);
}

// ---- 직렬화 (HTTP 는 bigint 를 못 실으니 10진 문자열) ----
export const pointToStrings = (p) => ({ x: p.x.toString(), y: p.y.toString() });
export const pointFromStrings = (o) => ({ x: BigInt(o.x), y: BigInt(o.y) });
export function serializeProof(p) {
  return {
    T1: pointToStrings(p.T1), T2: pointToStrings(p.T2), c: p.c.toString(),
    z_arid: p.z_arid.toString(), z_su: p.z_su.toString(), z_pki: p.z_pki.toString(),
    z_blind: p.z_blind.toString(), z_ru: p.z_ru.toString(),
  };
}
export function parseProof(o) {
  const B = (v) => { if (typeof v !== 'string' || !/^[0-9]+$/.test(v)) throw new Error('bad scalar'); return BigInt(v); };
  return {
    T1: pointFromStrings(o.T1), T2: pointFromStrings(o.T2), c: B(o.c),
    z_arid: B(o.z_arid), z_su: B(o.z_su), z_pki: B(o.z_pki), z_blind: B(o.z_blind), z_ru: B(o.z_ru),
  };
}
