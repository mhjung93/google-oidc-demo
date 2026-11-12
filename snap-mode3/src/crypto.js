// 등록 비밀 생성 — lib/mode3_credential.js 의 randomScalar 를 Snap 번들에 맞게 옮겨 적은 것(스펙 2026-09-22 metamask-snap §3.1, V11 갱신).
// V11(2026-10-12): 등록 비밀은 { s_u, sk_u } 둘이다. 등록 커밋 cm_u(Baby Jubjub 스칼라곱)는 없어졌고, 등록 가명 auid = Poseidon(T_AUID, uid, s_u) 는
// Snap 에 Poseidon 이 없어(WASM 권한 없음) 에이전트가 계산한다 — 그래서 register 는 s_u 를 sk_u 와 함께 **한 번** 페이지로 넘긴다(로그인 증인과 같은 모델).
// 2026-11-12(스펙 snap-derived-secrets): s_u·sk_u 는 무작위가 아니라 snap_getEntropy(SRP·스냅 ID 로 결정적)에서 유도한다 — 같은 시드면 같은 PPID 로 복구된다.
// 2026-11-12(스펙 snap-account-index): 계정 번호 k 마다 따로 유도한다 — salt 끝에 10진 k(규칙 v2). 같은 시드의 여러 IdP 계정이 서로 다른 비밀을 갖는다.
export const SCALAR_MAX = 1n << 250n;   // 회로 Num2Bits(250) 과 같은 상한
// 속성 상한 — lib/mode3_credential.js 의 ATTR_MAX 와 같다(회로 Num2Bits(64)). Snap 번들에는 lib import 가 없어 여기 상수가 정본이다
// (리뷰 2026-10-13 U2: storeRegistration 이 attrs 원소의 상한을 검사하지 않고 있었다).
export const ATTR_MAX = 1n << 64n;

export const ENTROPY_SALT_S_U = 'zkd/mode3/s_u/v2/';    // 끝에 10진 계정 번호를 붙인다(v2, 2026-11-12 스펙 snap-account-index)
export const ENTROPY_SALT_SK_U = 'zkd/mode3/sk_u/v2/';
export const INDEX_MAX = 2 ** 31 - 1;
export const isIndex = (v) => Number.isInteger(v) && v >= 0 && v <= INDEX_MAX;
const entropyBig = (hex) => {
  if (typeof hex !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(hex)) throw new Error('bad_entropy: snap_getEntropy 결과는 0x + 64자 16진이어야 한다');
  return BigInt(hex);
};
/** 엔트로피 → s_u ∈ [1, 2^250 − 1](10진 문자열). 0 은 쓰지 않는다(register 의 기존 범위 검사와 같다). */
export function saltFromEntropy(hex) { return (1n + (entropyBig(hex) % (SCALAR_MAX - 1n))).toString(); }
/** 엔트로피 → sk_u(소문자 64자 16진, 지금 형식과 같다 — EdDSA-Poseidon 은 아무 32바이트나 받는다). */
export function skFromEntropy(hex) { entropyBig(hex); return hex.slice(2).toLowerCase(); }
/** 계정 번호 index 의 등록 한 벌 — 같은 SRP·같은 스냅 ID·같은 번호면 언제나 같은 값. salt 의 v2 는 유도 규칙의 버전이다(번호 없는 v1 을 대체). */
export async function deriveRegistrationSecrets(index) {
  if (!isIndex(index)) throw new Error('bad_index: 계정 번호는 0 이상 2^31−1 이하의 정수');
  const get = (salt) => snap.request({ method: 'snap_getEntropy', params: { version: 1, salt: `${salt}${index}` } });
  return { s_u: saltFromEntropy(await get(ENTROPY_SALT_S_U)), sk_u: skFromEntropy(await get(ENTROPY_SALT_SK_U)) };
}
