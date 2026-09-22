// 발급 PoK — 시그마 프로토콜. 설계 §6.2, 2026-09-21 자격증명 이중 구조 §3.5.
//
// CIA 는 uid 를 알고 s_u·속성·blind_u 를 몰라야 한다. C_u_pt 에서 uid·G₁ 을 빼고
// 나머지 항의 표현(representation)을 아는지, 그리고 그 s_u 가 등록 때 낸 cm_u 의
// s_u 와 같은지를 한 증명(π_u)으로 보인다. SNARK 가 아니라 회로·셋업이 없다 — 이것이
// 커밋을 Pedersen 으로 둔 이유다(§11). 세션 발급(/cia/issue)에는 ZKP 가 없다 — Cf_u 조회 + sig_u 만.
//
// 시그마 프로토콜은 Z_r 상의 표현 지식만 증명하고 범위는 증명하지 않는다. 2^250 상한을
// 실제로 강제하는 것은 show 회로의 Num2Bits(250) 이다(§6.1) — 여기서 s_u < 2^250 을
// 검사하지 않으며, 검사할 방법도 없다. 다만 양쪽이 평문으로 아는 uid(CIA·지갑)는 여기서
// 검사한다 — 상한을 넘긴 채 발급되면 CIA 가 서명까지 하지만 show 회로가 열 수 없는 credential 이 된다.
// 2026-09-14: 속성 4슬롯이 witness 로 더해졌다(설계 2026-09-14 §4). CIA 는 attr 값을 모른다.
// 2026-09-22: 속성은 AA 기록. AA 가 uid·G_UID + Σa_k·G_ATTR 을 빼고 (s_u, blind_u) 만 PoK.
import { randomBytes } from 'node:crypto';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import { PEDERSEN_GENERATORS, SCALAR_MAX, normalizeAttrs } from './mode3_credential.js';

// 2026-09-21 자격증명 이중 구조(설계 §3.4·§3.5). 세션 발급에는 ZKP 가 없고 사용자 자격증명 발급에만 π_u 가 있다.
export const DOMAIN_MODE3_USERCRED_V2 = 1568025692958769574353059516335154n;   // ASCII "MODE3USERCRED2" — π_u V2 FS 도메인(속성 공개)
export const DOMAIN_MODE3_ATTRSREQ    = 6125100363118752795903799739729n;      // ASCII "MODE3ATTRSREQ"  — /cia/attrs 요청 서명
export const DOMAIN_MODE3_USERCREDREQ = 102762131813745922824802108462542767441n;   // ASCII "MODE3USERCREDREQ" — /cia/user_cred 요청 서명
export const DOMAIN_MODE3_ISSUEREQ_V4 = 401414577397388343646241740924474932n;      // ASCII "MODE3ISSUEREQV4" — /cia/issue V5 요청 서명(Cf_u 를 덮는다)

const MAX_HEIGHT_MAX = 1n << 64n;

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

/** 등록 시 cm_u 검사용 — 등록은 되돌릴 수 없어 여기서 걸러내지 않으면 uid 가 영구히 잠긴다. */
export async function isValidPoint(o) {
  return validPoint(await getBj(), o);
}

function validPoint(bj, o) {
  if (typeof o?.x !== 'bigint' || typeof o?.y !== 'bigint') return false;
  const p = bj.F.p;
  if (o.x < 0n || o.x >= p || o.y < 0n || o.y >= p) return false; // 비정규(non-canonical) 인코딩 거절
  const P = fromObj(bj, o);
  return bj.inCurve(P) && bj.inSubgroup(P);
}

// ---- π_u V2: 사용자 자격증명 증명 (스펙 2026-09-22 §3.4). 속성은 AA 기록값(공개) — AA 가
// uid·G_UID + Σaₖ·G_ATTR 을 스스로 빼고, PoK 는 (s_u, blind_u, r_u) 만 남는다. arid·pk_i 는 세션 커밋에 있다 ----
async function challengeU(bj, uid, attrs, C_u_pt, cm_u, T1, T2) {
  const ps = await getPs();
  const h = ps.F.toObject(ps([DOMAIN_MODE3_USERCRED_V2, uid, ...attrs, C_u_pt.x, C_u_pt.y, cm_u.x, cm_u.y, T1.x, T1.y, T2.x, T2.y]));
  return h & MASK_250;
}

/**
 * PoK{ (s_u, blind_u, r_u) : C_u − uid·G_UID − Σaₖ·G_ATTR = s_u·G_SU + blind_u·H  ∧  cm_u = s_u·G_SU + r_u·H }.
 * 공개 uid, a₀..a₃, C_u_pt, cm_u. 속성은 AA 기록이므로 AA 가 빼고 검증한다(스펙 2026-09-22 §3.4).
 */
export async function proveUserCred({ uid, s_u, blind_u, r_u, attrs }) {
  if (typeof uid !== 'bigint' || uid < 0n || uid >= SCALAR_MAX) throw new Error(`uid 는 [0, 2^250) 이어야 한다: ${uid}`);
  const a4 = normalizeAttrs(attrs);
  const bj = await getBj();
  const r = bj.subOrder;
  const [G1, G3, H] = ['uid', 's_u', 'blind'].map((n) => G(bj, n));
  const GA = [0, 1, 2, 3].map((i) => G(bj, `attr${i}`));
  const C_u_pt = toObj(bj, msm(bj, [[uid, G1], [s_u, G3], ...a4.map((v, i) => [v, GA[i]]), [blind_u, H]]));
  const cm_u = toObj(bj, msm(bj, [[s_u, G3], [r_u, H]]));
  const a = { su: await randomZr(), blind: await randomZr(), ru: await randomZr() };
  const T1 = toObj(bj, msm(bj, [[a.su, G3], [a.blind, H]]));
  const T2 = toObj(bj, msm(bj, [[a.su, G3], [a.ru, H]]));
  const c = await challengeU(bj, uid, a4, C_u_pt, cm_u, T1, T2);
  const z = (ax, x) => (ax + c * x) % r;
  return { C_u_pt, cm_u, proof: { T1, T2, c, z_su: z(a.su, s_u), z_blind: z(a.blind, blind_u), z_ru: z(a.ru, r_u) } };
}

/** attrs 는 검증자(AA)의 기록값 — 지갑이 무엇을 보내든 AA 는 자기 DB 값으로 검증한다. */
export async function verifyUserCred({ uid, attrs, C_u_pt, cm_u, proof }) {
  if (typeof uid !== 'bigint' || uid < 0n || uid >= SCALAR_MAX) return false;
  let a4; try { a4 = normalizeAttrs(attrs); } catch { return false; }
  const bj = await getBj();
  const r = bj.subOrder;
  const { T1, T2, c, z_su, z_blind, z_ru } = proof ?? {};
  for (const P of [C_u_pt, cm_u, T1, T2]) if (!validPoint(bj, P)) return false;
  for (const z of [c, z_su, z_blind, z_ru]) if (typeof z !== 'bigint' || z < 0n || z >= r) return false;
  if ((await challengeU(bj, uid, a4, C_u_pt, cm_u, T1, T2)) !== c) return false;
  const [G1, G3, H] = ['uid', 's_u', 'blind'].map((n) => G(bj, n));
  const GA = [0, 1, 2, 3].map((i) => G(bj, `attr${i}`));
  // Y1 = C_u − uid·G_UID − Σaₖ·G_ATTR — AA 가 아는 항을 전부 뺀다
  const known = msm(bj, [[uid, G1], ...a4.map((v, i) => [v, GA[i]])]);
  const Y1 = bj.addPoint(fromObj(bj, C_u_pt), negPt(bj, known));
  const lhs1 = msm(bj, [[z_su, G3], [z_blind, H]]);
  const rhs1 = bj.addPoint(fromObj(bj, T1), bj.mulPointEscalar(Y1, c));
  if (!eqPt(bj, lhs1, rhs1)) return false;
  const lhs2 = msm(bj, [[z_su, G3], [z_ru, H]]);
  const rhs2 = bj.addPoint(fromObj(bj, T2), bj.mulPointEscalar(fromObj(bj, cm_u), c));
  return eqPt(bj, lhs2, rhs2);
}

/** /cia/attrs 요청의 사용자 서명 메시지 = Poseidon(D_ATTRSREQ, uid, nonce). nonce 는 지갑이 뽑는 난수 — AA 는 신선도를 검사하지 않는다(스펙 §3.3). */
export async function attrsRequestMessage(uid, nonce) {
  if (typeof uid !== 'bigint' || uid < 0n || uid >= SCALAR_MAX) throw new Error('attrsRequestMessage: uid 는 [0, 2^250) bigint');
  if (typeof nonce !== 'bigint' || nonce < 0n || nonce >= SCALAR_MAX) throw new Error('attrsRequestMessage: nonce 는 [0, 2^250) bigint');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_ATTRSREQ, uid, nonce]));
}

/** /cia/user_cred 요청의 사용자 서명 메시지 = Poseidon(D_USERCREDREQ, C_u_pt.x, C_u_pt.y). */
export async function userCredRequestMessage(C_u_pt) {
  if (typeof C_u_pt?.x !== 'bigint' || typeof C_u_pt?.y !== 'bigint') throw new Error('userCredRequestMessage: C_u_pt{x,y}(bigint) 가 필요하다');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_USERCREDREQ, C_u_pt.x, C_u_pt.y]));
}

/**
 * /cia/issue V5 요청의 사용자 서명 메시지 = Poseidon(D_ISSUEREQ_V4, Cf_u, C_s_pt.x, C_s_pt.y, chainid, allowAgent, max_height).
 * Cf_u 를 덮으므로 제3자가 남의 C_u 에 자기 C_s 를 붙여 달라고 할 수 없다(설계 §3.4).
 */
export async function issueRequestMessageV4(Cf_u, C_s_pt, chainid, allowAgent, max_height) {
  if (typeof Cf_u !== 'bigint' || Cf_u < 0n) throw new Error('issueRequestMessageV4: Cf_u 는 음이 아닌 bigint 여야 한다');
  if (typeof C_s_pt?.x !== 'bigint' || typeof C_s_pt?.y !== 'bigint') throw new Error('issueRequestMessageV4: C_s_pt{x,y}(bigint) 가 필요하다');
  for (const [k, v] of [['chainid', chainid], ['allowAgent', allowAgent], ['max_height', max_height]]) {
    if (typeof v !== 'bigint' || v < 0n) throw new Error(`issueRequestMessageV4: ${k} 는 음이 아닌 bigint 여야 한다`);
  }
  if (allowAgent > 1n) throw new Error('issueRequestMessageV4: allowAgent 는 0 또는 1 이어야 한다');
  if (max_height >= MAX_HEIGHT_MAX) throw new Error('issueRequestMessageV4: max_height 는 2^64 미만이어야 한다');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_ISSUEREQ_V4, Cf_u, C_s_pt.x, C_s_pt.y, chainid, allowAgent, max_height]));
}

export function serializeUserCredProof(p) {
  return { T1: pointToStrings(p.T1), T2: pointToStrings(p.T2), c: p.c.toString(), z_su: p.z_su.toString(), z_blind: p.z_blind.toString(), z_ru: p.z_ru.toString() };
}
export function parseUserCredProof(o) {
  const B = (v) => { if (typeof v !== 'string' || !/^[0-9]+$/.test(v)) throw new Error('bad scalar'); return BigInt(v); };
  return { T1: pointFromStrings(o.T1), T2: pointFromStrings(o.T2), c: B(o.c), z_su: B(o.z_su), z_blind: B(o.z_blind), z_ru: B(o.z_ru) };
}

// ---- 직렬화 (HTTP 는 bigint 를 못 실으니 10진 문자열) ----
export const pointToStrings = (p) => ({ x: p.x.toString(), y: p.y.toString() });
export const pointFromStrings = (o) => ({ x: BigInt(o.x), y: BigInt(o.y) });
