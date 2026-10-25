// Mode 3 폐기 트리.
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §7.1
//
// 단일 IMT, 깊이 32, 샤딩 없음, append-only. 리프는 **폐기가 일어날 때만** 생긴다
// (발급 때가 아니다). 그래서 트리가 작고 Mode 2의 샤딩·상위 트리·리셋 보조정리가
// 전부 필요 없다.
//
// 트리 본체는 lib/imt_v2.js를 그대로 쓴다 — Mode 3이 얹는 것은 리프 유도뿐이다.
// v2는 remove()를 노출하지 않으므로 append-only가 자료구조 수준에서 강제된다.
import { createIMTv2, leafValue } from './imt_v2.js';
import { ethers } from 'ethers';

export const MODE3_TREE_DEPTH = 32;

// TAG_SESSION=1, TAG_ACCOUNT=2는 Mode 2가 쓰고 있다(circuits/pi_pk_i_v3.circom). 3 은 V4 세션 리프가 쓰던 값이다(2026-09-21 폐기).
// 같은 트리를 쓰지는 않지만, 리프 유도 함수를 공유하므로 값을 갈라 둔다.
export const TAG_MODE3_USER = 4n;

/** 세션 리프 태그(2026-09-24 세션 폐기). 사용자 리프(4)와 같은 트리에 들어가므로 값을 가른다. */
export const TAG_MODE3_SESSION = 5n;

/** 세션 폐기 리프의 상한 c ∈ [0, 2^32). c = 허용하는 거래 수(nonce < c 만 유효). 2026-10-22 설계 §3. */
export const SESSION_BOUND_MAX = 1n << 32n;
const H_PRIME_MASK = (1n << 220n) - 1n;   // Poseidon(5, Cf_s) 의 하위 220비트 — V = H'·2^32 + c < 2^252(leafValue 마스크·회로 LessThan(252) 범위)

/** 세션 폐기 리프 = (Poseidon(5, Cf_s) mod 2^220)·2^32 + bound. 같은 세션의 리프가 트리에서 연속 구간 [H'·2^32, H'·2^32 + 2^32 − 1] 에 놓인다. */
export async function sessionLeaf(Cf_s, bound) {
  if (typeof bound !== 'bigint' || bound < 0n || bound >= SESSION_BOUND_MAX) throw new Error('sessionLeaf: bound 는 [0, 2^32) bigint');
  const hp = (await leafValue(TAG_MODE3_SESSION, Cf_s)) & H_PRIME_MASK;
  return (hp << 32n) + bound;
}
/** nonce = counter 인 거래가 걸리는 리프 구간 [H'·2^32, H'·2^32 + counter] — 상한 c ≤ counter 인 리프 전부. 로그인은 counter = 2^32 − 1(리프 하나라도 있으면 실패). */
export async function sessionLeafRange(Cf_s, counter) {
  if (typeof counter !== 'bigint' || counter < 0n || counter >= SESSION_BOUND_MAX) throw new Error('sessionLeafRange: counter 는 [0, 2^32) bigint');
  const lo = await sessionLeaf(Cf_s, 0n);
  return { lo, hi: lo + counter };
}

/**
 * 폐기 트리에 들어가는 리프 값. 2026-09-21 자격증명 이중 구조(설계 §3.6): 리프는 세션이 아니라
 * **사용자 자격증명** Cf_u 에서 뽑는다. 사용자당 하나 — 리프 하나로 그 사용자의 모든 세션이 함께 죽는다.
 *
 * 설계 문서 §4.3: 리프를 커밋 **으로부터 유도**하는 것이 핵심이다. 커밋 안의 속성으로
 * 두면 사용자가 값을 골라 아무 난수나 제시할 수 있어 발급 시 정합성 ZKP가
 * 필요해진다. 유도하면 회로가 비공개 입력 C_u 에서 직접 계산하므로 다른 리프를
 * 들이밀 방법이 없다.
 *
 * leafValue()가 하위 252비트로 마스킹한다 — 회로의 LessThan(252)이 그 범위를
 * 전제하기 때문이다(circuits/lib/imt_nonmembership_v2.circom 주석 참조).
 */
export async function userLeaf(Cf_u) {
  return leafValue(TAG_MODE3_USER, Cf_u);
}

export async function createRevocationTree(depth = MODE3_TREE_DEPTH) {
  return createIMTv2(depth);
}

// ---- 2026-10-25 root 유효 창 §4: 세션키 결속 서명 ----
// IdP 는 발급 때 pk_i 를 모른다(C_s 안에만 있다, D1). 폐기 때 지갑이 pk_i 를 알려 주되, 그 pk_i 가 **이 요청의** 것임을 세션키
// (secp256k1 sk_i) 서명으로 묶는다 — 묶지 않으면 sig_u 만 가진 사용자가 남의 pk_i 를 넣어 그 세션의 거울 counter 를 낮출 수 있다
// (낮추기만이라 되돌릴 수 없다). 메시지는 EIP-191 personal_sign 문자열, 값은 sk_u 서명(revokeSessionMessage)과 같은 것을 10진으로.
export const REVOKE_BIND_PREFIX = 'MODE3_REVOKE_BIND_V1';
export function revokeBindMessage({ uid, Cf_s, bound, nonce }) {
  return `${REVOKE_BIND_PREFIX}|${BigInt(uid)}|${BigInt(Cf_s)}|${BigInt(bound)}|${BigInt(nonce)}`;
}
/** 세션키(0x 개인키)로 결속 서명. */
export function signRevokeBind(sessionPrivKey, fields) {
  return new ethers.Wallet(sessionPrivKey).signMessage(revokeBindMessage(fields));
}
/** pk_i(10진, 160비트 주소) 가 sig_i 의 서명자인가. 형식이 깨졌으면 false(throw 하지 않는다). */
export function verifyRevokeBind(pk_i, fields, sig_i) {
  try {
    const addr = ethers.getAddress(ethers.toBeHex(BigInt(pk_i), 20));
    return ethers.verifyMessage(revokeBindMessage(fields), sig_i).toLowerCase() === addr.toLowerCase();
  } catch { return false; }
}
