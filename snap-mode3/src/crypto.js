// 등록 비밀 생성 — lib/mode3_credential.js 의 randomScalar 를 Snap 번들에 맞게 옮겨 적은 것(스펙 2026-09-22 metamask-snap §3.1, V11 갱신).
// V11(2026-10-12): 등록 비밀은 { s_u, sk_u } 둘이다. 등록 커밋 cm_u(Baby Jubjub 스칼라곱)는 없어졌고, 등록 가명 auid = Poseidon(T_AUID, uid, s_u) 는
// Snap 에 Poseidon 이 없어(WASM 권한 없음) 에이전트가 계산한다 — 그래서 register 는 s_u 를 sk_u 와 함께 **한 번** 페이지로 넘긴다(로그인 증인과 같은 모델).
export const SCALAR_MAX = 1n << 250n;   // 회로 Num2Bits(250) 과 같은 상한
// 속성 상한 — lib/mode3_credential.js 의 ATTR_MAX 와 같다(회로 Num2Bits(64)). Snap 번들에는 lib import 가 없어 여기 상수가 정본이다
// (리뷰 2026-10-13 U2: storeRegistration 이 attrs 원소의 상한을 검사하지 않고 있었다).
export const ATTR_MAX = 1n << 64n;

/** lib/mode3_credential.js 의 randomScalar — 32바이트를 250비트로 자른다. */
export function randomScalar() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v & (SCALAR_MAX - 1n);
}

/** 등록 한 벌 — s_u·sk_u 는 Snap 상태에 남고 register 응답으로 한 번 나간다. sk_u 는 32바이트 16진(250비트로 자르지 않는다). */
export function createRegistrationSecrets() {
  const sk = new Uint8Array(32);
  crypto.getRandomValues(sk);
  return { s_u: randomScalar().toString(), sk_u: [...sk].map((b) => b.toString(16).padStart(2, '0')).join('') };
}
