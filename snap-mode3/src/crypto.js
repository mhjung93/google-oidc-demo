// 등록 비밀 생성 — lib/mode3_credential.js 의 randomScalar 를 Snap 번들에 맞게 옮겨 적은 것(스펙 2026-09-22 metamask-snap §3.1, V11 갱신).
// V11(2026-10-12): 등록 비밀은 s_u 다(0.4.0 부터 — 전에는 sk_u 도 있었다). 등록 커밋 cm_u(Baby Jubjub 스칼라곱)는 없어졌고, 등록 가명 auid = Poseidon(T_AUID, uid, s_u) 는
// Snap 에 Poseidon 이 없어(WASM 권한 없음) 에이전트가 계산한다 — 그래서 register 는 s_u 를 **한 번** 페이지로 넘긴다(로그인 증인과 같은 모델).
// 2026-11-12(스펙 snap-derived-secrets): s_u 는 무작위가 아니라 snap_getEntropy(SRP·스냅 ID 로 결정적)에서 유도한다 — 같은 시드면 같은 PPID 로 복구된다.
// 2026-11-12(스펙 snap-account-index): 계정 번호 k 마다 따로 유도한다 — salt 끝에 10진 k(규칙 v2). 같은 시드의 여러 IdP 계정이 서로 다른 비밀을 갖는다.
// 2026-11-13(스펙 2026-11-12 no-pk-u §4.1): 등록 키 sk_u 는 없어졌다 — 비밀은 s_u 하나다.
// 2026-11-13(스펙 2026-11-13 random-salt R1·R2, 0.5.0): 시드 유도(snap_getEntropy)와 계정 번호를 버렸다 — 스냅 하나에 salt(s_u) 하나, 스냅 안에서 무작위로 만든다.
// 되찾는 길은 사용자의 암호화 백업 파일뿐이다(zk 스냅 화면이 설치 직후 만든다). auid = Poseidon(T_AUID2, s_u) 도 uid 없이 salt 에서만 나온다.
export const SCALAR_MAX = 1n << 250n;   // 회로 Num2Bits(250) 과 같은 상한
// 속성 상한 — lib/mode3_credential.js 의 ATTR_MAX 와 같다(회로 Num2Bits(64)). Snap 번들에는 lib import 가 없어 여기 상수가 정본이다
// (리뷰 2026-10-13 U2: storeRegistration 이 attrs 원소의 상한을 검사하지 않고 있었다).
export const ATTR_MAX = 1n << 64n;

/** salt(s_u) 를 스냅 안에서 무작위로 만든다 — [1, 2^250 − 1] 의 10진 문자열. 0 은 쓰지 않는다. 32바이트를 2^250 − 1 로 나눈 나머지라 편향은 2^-6 미만의 상대 오차로 무시한다. */
export function randomSalt() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return (1n + (v % (SCALAR_MAX - 1n))).toString();
}
/** salt 로 받을 수 있는 값인가 — 10진 문자열, [1, 2^250 − 1]. */
export const isSalt = (v) => typeof v === 'string' && /^[0-9]+$/.test(v) && BigInt(v) >= 1n && BigInt(v) < SCALAR_MAX;
