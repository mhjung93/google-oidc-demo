// 발급·등록 요청의 서명 메시지와 점 검사 — V11(스펙 2026-10-12 §3.1·§5.2).
//
// V10 까지 여기 있던 π_u(시그마 프로토콜)·registrationCommit(cm_u) 는 지웠다: V11 은 등록 때 auid = Poseidon(T_AUID, uid, s_u) 를
// 내고(D4), 세션마다 Groth16 회로 π_IdP(circuits/pi_idp.circom, lib/mode3_idp_proof.js)로 uid·salt 관계와 세션 바인딩을 보인다(D10).
// 메시지 인자 **순서**는 회로·IdP·지갑이 공유하는 계약이다 — Poseidon 은 순서가 바뀌면 다른 해시다.
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import { SCALAR_MAX, MAX_HEIGHT_MAX } from './mode3_credential.js';

const be = (s) => BigInt('0x' + Buffer.from(s).toString('hex'));
export const DOMAIN_MODE3_ISSUEREQ_V11 = 102762131813731415973437885676665581873n;   // ASCII "MODE3ISSUEREQV11" — /cia/issue V11 요청 서명
export const DOMAIN_MODE3_REGISTER_V2 = 1568025692958713225867644958495282n;         // ASCII "MODE3REGISTER2" — /cia/register 소유 증명(uid, auid)
export const DOMAIN_MODE3_SLOTREQ = 23926173293437685841045636433n;                  // ASCII "MODE3SLOTREQ" — /cia/slot 요청 서명(옛 MODE3ATTRSREQ 대체)
export const DOMAIN_MODE3_REVOKESESS = be('MODE3REVOKESESS');                        // /cia/revoke scope=session 사용자 서명(불변)

let bjP = null, psP = null, fieldPrimeP = null;
const getBj = () => (bjP ??= buildBabyjub());
const getPs = () => (psP ??= buildPoseidon());
// BN254 스칼라 필드 소수 p(= circomlibjs buildPoseidon().F.p 와 같은 값) — 값을 다시 타이핑하지 않고 getBj() 에서 얻는다.
const getFieldPrime = () => (fieldPrimeP ??= getBj().then((bj) => bj.F.p));

const isScalar = (v) => typeof v === 'bigint' && v >= 0n && v < SCALAR_MAX;
/** Poseidon 입력으로 쓸 수 있는 값인가(= BN254 스칼라 필드 원소 [0, p)). 상한이 없으면 p 이상 값이 모듈러로 다시 줄어들어
 *  호출자가 의도한 값과 다른 해시가 나갈 수 있다. */
const isField = async (v) => typeof v === 'bigint' && v >= 0n && v < (await getFieldPrime());

/** 점이 정규 인코딩이고 곡선 위·소수 부분군 안인가. 등록·발급은 되돌릴 수 없어 여기서 걸러낸다(§6.1). */
export async function isValidPoint(o) {
  const bj = await getBj();
  if (typeof o?.x !== 'bigint' || typeof o?.y !== 'bigint') return false;
  const p = bj.F.p;
  if (o.x < 0n || o.x >= p || o.y < 0n || o.y >= p) return false;   // 비정규(non-canonical) 인코딩 거절
  const P = [bj.F.e(o.x), bj.F.e(o.y)];
  return bj.inCurve(P) && bj.inSubgroup(P);
}

/**
 * /cia/issue V11 요청의 사용자 서명 메시지 = Poseidon(D_ISSUEREQ_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height).
 * Cf_u·Cf_s 를 덮으므로 제3자가 남의 C_u 에 자기 C_s 를 붙여 달라고 할 수 없고, auid_s·arid_s 를 덮으므로 다른 세션의 바인딩으로 바꿔 끼울 수 없다.
 */
export async function issueRequestMessageV11(auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height) {
  for (const [k, v] of [['auid_s', auid_s], ['arid_s', arid_s], ['Cf_u', Cf_u], ['Cf_s', Cf_s], ['chainid', chainid], ['allowAgent', allowAgent], ['max_height', max_height]]) {
    if (!(await isField(v))) throw new Error(`issueRequestMessageV11: ${k} 는 [0, p) 범위의 bigint 여야 한다(BN254 스칼라 필드)`);
  }
  if (allowAgent > 1n) throw new Error('issueRequestMessageV11: allowAgent 는 0 또는 1 이어야 한다');
  if (max_height >= MAX_HEIGHT_MAX) throw new Error('issueRequestMessageV11: max_height 는 2^64 미만이어야 한다');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_ISSUEREQ_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height]));
}

/** /cia/register 의 소유 증명 메시지 = Poseidon(D_REGISTER_V2, uid, auid). 지갑이 만든 sk_u 로 서명한다 — IdP 는 sk_u 를 만들지 않는다. */
export async function registerMessage(uid, auid) {
  if (!isScalar(uid)) throw new Error('registerMessage: uid 는 [0, 2^250) bigint');
  if (!(await isField(auid))) throw new Error('registerMessage: auid 는 [0, p) 범위의 bigint 여야 한다(BN254 스칼라 필드)');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_REGISTER_V2, uid, auid]));
}

/** /cia/slot 요청의 사용자 서명 메시지 = Poseidon(D_SLOTREQ, uid, nonce). nonce 는 지갑이 뽑는 난수 — IdP 는 신선도를 검사하지 않는다(응답은 공개 슬롯 번호). */
export async function slotRequestMessage(uid, nonce) {
  if (!isScalar(uid)) throw new Error('slotRequestMessage: uid 는 [0, 2^250) bigint');
  if (!isScalar(nonce)) throw new Error('slotRequestMessage: nonce 는 [0, 2^250) bigint');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_SLOTREQ, uid, nonce]));
}

/** 세션 폐기 요청의 사용자 서명 메시지 = Poseidon(D_REVOKESESS, uid, Cf_s, nonce). nonce 신선도는 검사하지 않는다(재생 = 같은 세션을 다시 폐기, 멱등). */
export async function revokeSessionMessage(uid, Cf_s, nonce) {
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_REVOKESESS, uid, Cf_s, nonce]));
}

// ---- 직렬화 (HTTP 는 bigint 를 못 실으니 10진 문자열) ----
export const pointToStrings = (p) => ({ x: p.x.toString(), y: p.y.toString() });
export const pointFromStrings = (o) => ({ x: BigInt(o.x), y: BigInt(o.y) });
