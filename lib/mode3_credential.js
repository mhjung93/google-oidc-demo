// Mode 3 credential 프로토콜 유도값 — circuits/pi_cred.circom 과 JS 쪽이 반드시
// 일치해야 하는 계산만 모은다(커밋 C, 서명 메시지, PPID). 단일 책임: 이 세
// 함수 밖의 어떤 프로토콜 로직도 여기 두지 않는다.
//
// 인자 **순서**는 회로 배선의 일부다 — Poseidon은 인자 순서가 바뀌면 다른
// 해시가 나오므로, 여기서 순서를 바꾸면 회로와 어긋난다.
import { randomBytes } from 'node:crypto';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';

export const DOMAIN_MODE3_CRED = 1426111059989523219780n; // ASCII "MODE3CRED" 빅엔디언

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

// Poseidon 커밋 판 (2026-09-10 이전 기존 credCommit 을 개명). C = Poseidon(uid, arid, s_u,
// blind, pk_i) 하나의 필드 원소다. 현재는 안 쓰이지만, 발급 경로를 시그마 프로토콜에서
// π_issue SNARK 로 전환할 때 되돌아올 기준선이라 남겨 둔다 (§11 결정, 2026-09-10).
export async function credCommitPoseidon({ uid, arid, s_u, blind, pk_i }) {
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([uid, arid, s_u, blind, pk_i]));
}

// ---- 교과서 Pedersen 커밋 (2026-09-10 부터 현행) ----
// circuits/lib/mode3_commit.circom 의 CommitPedersen 과 정확히 같은 생성원·순서·상한.

export const SCALAR_BITS = 250;
export const SCALAR_MAX = 1n << 250n;   // 회로의 Num2Bits(250). r(≈2^251.4) 미만이라 binding 이 유지된다

// circomlib pedersen.circom BASE[0..4]. 회로 파일의 G_UID/G_ARID/G_SU/G_PKI/H_BLIND 와 글자 단위로 같아야 한다.
// 안쪽 [x, y] 배열까지 얼려 둔다 — 바깥 객체만 freeze 하면
// PEDERSEN_GENERATORS.uid[0] = 0n 같은 변형이 조용히 통과해 회로와 어긋난다.
export const PEDERSEN_GENERATORS = Object.freeze({
  uid:   Object.freeze([10457101036533406547632367118273992217979173478358440826365724437999023779287n,
          19824078218392094440610104313265183977899662750282163392862422243483260492317n]),
  arid:  Object.freeze([2671756056509184035029146175565761955751135805354291559563293617232983272177n,
          2663205510731142763556352975002641716101654201788071096152948830924149045094n]),
  s_u:   Object.freeze([5802099305472655231388284418920769829666717045250560929368476121199858275951n,
          5980429700218124965372158798884772646841287887664001482443826541541529227896n]),
  pk_i:  Object.freeze([7107336197374528537877327281242680114152313102022415488494307685842428166594n,
          2857869773864086953506483169737724679646433914307247183624878062391496185654n]),
  blind: Object.freeze([20265828622013100949498132415626198973119240347465898028410217039057588424236n,
          1160461593266035632937973507065134938065359936056410650153315956301179689506n]),
});

// s_u, blind, r_u 등 커밋 스칼라를 뽑는 표준 샘플러. crypto.randomBytes(32)로 256비트를
// 얻은 뒤 250비트로 마스킹한다 — 전체 필드 난수를 그대로 쓰면 credCommit()의 2^250
// 상한을 92% 확률로 넘어 거부된다.
export function randomScalar() {
  const bytes = randomBytes(32);
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v & (SCALAR_MAX - 1n);
}

let babyjubP = null;
function getBabyjub() {
  if (!babyjubP) babyjubP = buildBabyjub();
  return babyjubP;
}

/**
 * C = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + blind·H  (baby jubjub 점).
 * Cf = Poseidon(Cx, Cy) — 서명 메시지와 폐기 리프에 들어가는 압축값.
 *
 * 상한 검사는 회로의 Num2Bits(250) 과 같은 규약이다. CIA 가 발급 시 이 함수를 쓰므로
 * 사용자가 s_u·blind 를 2^250 이상으로 고르는 경로가 여기서 막힌다.
 */
export async function credCommit({ uid, arid, s_u, blind, pk_i }) {
  const fields = { uid, arid, s_u, pk_i, blind };
  for (const [k, v] of Object.entries(fields)) {
    if (typeof v !== 'bigint' || v < 0n || v >= SCALAR_MAX) {
      throw new Error(`${k} 는 [0, 2^250) 범위의 bigint 여야 한다 (회로 Num2Bits(250) 과 같은 상한): ${v}`);
    }
  }
  const bj = await getBabyjub();
  const mul = (g, e) => bj.mulPointEscalar([bj.F.e(g[0]), bj.F.e(g[1])], e);
  let acc = mul(PEDERSEN_GENERATORS.uid, uid);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.arid, arid));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.s_u, s_u));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.pk_i, pk_i));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, blind));
  const Cx = bj.F.toObject(acc[0]);
  const Cy = bj.F.toObject(acc[1]);
  const poseidon = await getPoseidon();
  const Cf = poseidon.F.toObject(poseidon([Cx, Cy]));
  return { Cx, Cy, Cf };
}

// circuits/pi_cred.circom 의 msgHasher(DOMAIN_MODE3_CRED, C, max_height 순서)와
// 일치해야 한다.
export async function credMessage(C, max_height) {
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_CRED, C, max_height]));
}

// circuits/pi_cred.circom 의 ppidHasher(uid, arid, s_u 순서)와 일치해야 한다.
export async function ppid({ uid, arid, s_u }) {
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([uid, arid, s_u]));
}
