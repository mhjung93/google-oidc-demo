// 등록 비밀 생성 — lib/mode3_credential.js 의 randomScalar·PEDERSEN_GENERATORS 와 lib/mode3_issuance.js 의
// registrationCommit 을 Snap 번들에 맞게 옮겨 적은 것이다(스펙 2026-09-22 metamask-snap §3.1, Task 3 브리프).
//
// 왜 circomlibjs 를 그대로 쓰지 않는가: circomlibjs 의 buildBabyjub 은 ffjavascript 의 WASM 곡선(wasmcurves)을 올린다.
// WebAssembly 를 지운 채 buildBabyjub 을 부르면 "Cannot read properties of undefined (reading 'Memory')" 로 죽는다(2026-09-22 실측).
// 이 Snap 의 manifest 에는 `endowment:webassembly` 가 없으므로(스펙 §3.1 이 요구하는 권한 세 개뿐) WASM 을 쓸 수 없다.
// 그래서 Baby Jubjub 의 트위스티드 에드워즈 덧셈·스칼라곱만 BigInt 로 적는다 — 결과가 루트 lib 와 같은 점인지는
// test/rpc.test.mjs 가 registrationCommit(s_u, r_u) 와 대조해 고정한다. cm_u 계산은 그대로 Snap 안에 남는다(스펙 §9(c) 대안 불필요).

// Baby Jubjub: a·x² + y² = 1 + d·x²y² (mod p), p = bn128 스칼라 필드.
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const A = 168700n;
const D = 168696n;

// 회로·루트 lib 와 글자 단위로 같아야 하는 생성원 — lib/mode3_credential.js 의 PEDERSEN_GENERATORS 중 등록 커밋이 쓰는 둘.
const G_SU = [5802099305472655231388284418920769829666717045250560929368476121199858275951n,
  5980429700218124965372158798884772646841287887664001482443826541541529227896n];
const H_BLIND = [20265828622013100949498132415626198973119240347465898028410217039057588424236n,
  1160461593266035632937973507065134938065359936056410650153315956301179689506n];

export const SCALAR_MAX = 1n << 250n;   // 회로 Num2Bits(250) 과 같은 상한

const mod = (v) => ((v % P) + P) % P;

/** 확장 유클리드 역원 — P 는 소수라 gcd 는 항상 1 이다. */
function inv(v) {
  let [r0, r1] = [mod(v), P];
  let [t0, t1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [t0, t1] = [t1, t0 - q * t1];
  }
  if (r0 !== 1n) throw new Error('crypto: 역원이 없다');
  return mod(t0);
}

/** circomlibjs babyjub.addPoint 와 같은 식. */
export function addPoint(p1, p2) {
  const [x1, y1] = p1, [x2, y2] = p2;
  const beta = mod(x1 * y2);
  const gamma = mod(y1 * x2);
  const tau = mod(beta * gamma);
  const dtau = mod(D * tau);
  const x3 = mod(mod(beta + gamma) * inv(mod(1n + dtau)));
  const y3 = mod(mod(mod(y1 * y2) - mod(A * mod(x1 * x2))) * inv(mod(1n - dtau)));
  return [x3, y3];
}

/** circomlibjs babyjub.mulPointEscalar 와 같은 이진 double-and-add. */
export function mulPointEscalar(base, e) {
  let res = [0n, 1n];      // 항등원
  let exp = base;
  let rem = e;
  while (rem > 0n) {
    if (rem & 1n) res = addPoint(res, exp);
    exp = addPoint(exp, exp);
    rem >>= 1n;
  }
  return res;
}

/** lib/mode3_credential.js 의 randomScalar — 32바이트를 250비트로 자른다. */
export function randomScalar() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v & (SCALAR_MAX - 1n);
}

/** cm_u = s_u·G_SU + r_u·H_BLIND (lib/mode3_issuance.js registrationCommit 과 같은 값). */
export function registrationCommit(s_u, r_u) {
  const [x, y] = addPoint(mulPointEscalar(G_SU, s_u), mulPointEscalar(H_BLIND, r_u));
  return { x: x.toString(), y: y.toString() };
}

/** 등록 한 벌 — s_u·r_u 는 Snap 상태에만 남고 cm_u 만 밖으로 나간다(스펙 §4.1). */
export function createRegistrationSecrets() {
  const s_u = randomScalar(), r_u = randomScalar();
  return { s_u: s_u.toString(), r_u: r_u.toString(), cm_u: registrationCommit(s_u, r_u) };
}
