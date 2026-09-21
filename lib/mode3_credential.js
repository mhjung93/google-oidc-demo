// Mode 3 credential 프로토콜 유도값 — circuits/pi_cred.circom 과 JS 쪽이 반드시
// 일치해야 하는 계산만 모은다(커밋 C_u·C_s, 서명 메시지, PPID). 단일 책임: 이 세
// 함수 밖의 어떤 프로토콜 로직도 여기 두지 않는다.
//
// 인자 **순서**는 회로 배선의 일부다 — Poseidon은 인자 순서가 바뀌면 다른
// 해시가 나오므로, 여기서 순서를 바꾸면 회로와 어긋난다.
// 2026-09-14: 속성 4슬롯(attr0..3)과 (max_height, chainid, allowAgent) 서명 메시지 — 2026-09-18 설계 §3.
import { randomBytes } from 'node:crypto';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';

// 서명 도메인(MODE3CRED 계열) 이력: "MODE3CRED"(2026-09-09) → V2 속성 4슬롯(09-14) → V3 세션 성명(09-15) → V4 max_height·allowAgent(09-18)
// → V5(2026-09-21) 부터 커밋 둘. 옛 상수는 지웠다 — 서명 도메인이 달라 옛 자격증명은 V5 회로에서 재생되지 않는다.
// 2026-09-21 자격증명 이중 구조(설계 §3.3): Sign(D_V5, Cf_u, Cf_s, max_height, chainid, allowAgent). 인자 6개.
export const DOMAIN_MODE3_CRED_V5 = 93461614427473393731524149n; // ASCII "MODE3CREDV5" 빅엔디언
export const MAX_HEIGHT_MAX = 1n << 64n;   // 회로 Num2Bits(64) 와 같은 상한
export const ATTR_SLOTS = 4;

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

// ---- 교과서 Pedersen 커밋 (2026-09-10 부터 현행) ----
// circuits/lib/mode3_commit.circom 의 CommitUser·CommitSession 과 정확히 같은 생성원·순서·상한.

export const SCALAR_BITS = 250;
export const SCALAR_MAX = 1n << 250n;   // 회로의 Num2Bits(250). r(≈2^251.4) 미만이라 binding 이 유지된다

// circomlib pedersen.circom BASE[0..8]. 회로 파일의 G_UID/G_ARID/G_SU/G_PKI/G_ATTR[0..3]/H_BLIND 와 글자 단위로 같아야 한다.
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
  attr0: Object.freeze([1487999857809287756929114517587739322941449154962237464737694709326309567994n,
          14017256862867289575056460215526364897734808720610101650676790868051368668003n]),
  attr1: Object.freeze([14618644331049802168996997831720384953259095788558646464435263343433563860015n,
          13115243279999696210147231297848654998887864576952244320558158620692603342236n]),
  attr2: Object.freeze([6814338563135591367010655964669793483652536871717891893032616415581401894627n,
          13660303521961041205824633772157003587453809761793065294055279768121314853695n]),
  attr3: Object.freeze([3571615583211663069428808372184817973703476260057504149923239576077102575715n,
          11981351099832644138306422070127357074117642951423551606012551622164230222506n]),
  blind: Object.freeze([20265828622013100949498132415626198973119240347465898028410217039057588424236n,
          1160461593266035632937973507065134938065359936056410650153315956301179689506n]),
});

// s_u, blind, r_u 등 커밋 스칼라를 뽑는 표준 샘플러. crypto.randomBytes(32)로 256비트를
// 얻은 뒤 250비트로 마스킹한다 — 전체 필드 난수를 그대로 쓰면 userCommit()·sessionCommit() 의 2^250
// 상한을 92% 확률로 넘어 거부된다.
export function randomScalar() {
  const bytes = randomBytes(32);
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v & (SCALAR_MAX - 1n);
}

/** attrs 를 길이 4 의 bigint 배열로 정규화한다. 생략·짧은 배열은 0 으로 채우고, 상한 밖이면 throw. */
export function normalizeAttrs(attrs) {
  if (attrs !== undefined && attrs !== null && !Array.isArray(attrs)) throw new Error('attrs 는 배열이어야 한다');
  if (Array.isArray(attrs) && attrs.length > ATTR_SLOTS) throw new Error(`attrs 는 최대 ${ATTR_SLOTS}개다`);
  const out = [];
  for (let i = 0; i < ATTR_SLOTS; i++) {
    const raw = attrs?.[i] ?? 0n;
    const v = typeof raw === 'bigint' ? raw : BigInt(raw);
    if (v < 0n || v >= SCALAR_MAX) throw new Error(`attr${i} 는 [0, 2^250) 범위여야 한다: ${v}`);
    out.push(v);
  }
  return out;
}

let babyjubP = null;
function getBabyjub() {
  if (!babyjubP) babyjubP = buildBabyjub();
  return babyjubP;
}

function checkScalars(fields) {
  for (const [k, v] of Object.entries(fields)) {
    if (typeof v !== 'bigint' || v < 0n || v >= SCALAR_MAX) {
      throw new Error(`${k} 는 [0, 2^250) 범위의 bigint 여야 한다 (회로 Num2Bits(250) 과 같은 상한): ${v}`);
    }
  }
}
async function finishCommit(acc) {
  const bj = await getBabyjub();
  const Cx = bj.F.toObject(acc[0]);
  const Cy = bj.F.toObject(acc[1]);
  const poseidon = await getPoseidon();
  return { Cx, Cy, Cf: poseidon.F.toObject(poseidon([Cx, Cy])) };
}

/**
 * 사용자 자격증명 커밋(설계 2026-09-21 §3.1). 사용자당 하나, 오래 산다.
 *   C_u = uid·G_UID + s_u·G_SU + attr₀·G_ATTR0 + … + attr₃·G_ATTR3 + blind_u·H
 * circuits/lib/mode3_commit.circom 의 CommitUser 와 생성원·덧셈 순서가 같다. arid·pk_i 항이 없다 — 그 둘은 sessionCommit 에.
 */
export async function userCommit({ uid, s_u, blind_u, attrs }) {
  checkScalars({ uid, s_u, blind_u });
  const a = normalizeAttrs(attrs);
  const bj = await getBabyjub();
  const mul = (g, e) => bj.mulPointEscalar([bj.F.e(g[0]), bj.F.e(g[1])], e);
  let acc = mul(PEDERSEN_GENERATORS.uid, uid);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.s_u, s_u));
  for (let i = 0; i < ATTR_SLOTS; i++) acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS[`attr${i}`], a[i]));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, blind_u));
  return finishCommit(acc);
}

/**
 * 세션 커밋(설계 2026-09-21 §3.2). 로그인마다 새 blind_s.
 *   C_s = arid·G_ARID + pk_i·G_PKI + blind_s·H
 * arid 를 넣는 이유: 같은 세션키를 두 서비스에 쓰면 pk_i 로 이어지므로 세션 자격증명을 서비스에 묶는다(§2).
 * AA 는 이 커밋을 열지 못한다 — pk_i 를 평문으로 보면 온체인 pk_i 로 트랜잭션 ↔ uid 가 이어진다.
 */
export async function sessionCommit({ arid, pk_i, blind_s }) {
  checkScalars({ arid, pk_i, blind_s });
  const bj = await getBabyjub();
  const mul = (g, e) => bj.mulPointEscalar([bj.F.e(g[0]), bj.F.e(g[1])], e);
  let acc = mul(PEDERSEN_GENERATORS.arid, arid);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.pk_i, pk_i));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, blind_s));
  return finishCommit(acc);
}

// circuits/pi_cred.circom V5 의 msgHasher(DOMAIN_MODE3_CRED_V5, Cf_u, Cf_s, max_height, chainid, allowAgent) 와 순서가 같아야 한다.
export async function credMessageV5(Cf_u, Cf_s, max_height, chainid, allowAgent) {
  for (const [k, v] of [['Cf_u', Cf_u], ['Cf_s', Cf_s], ['max_height', max_height], ['chainid', chainid], ['allowAgent', allowAgent]]) {
    if (typeof v !== 'bigint' || v < 0n) throw new Error(`credMessageV5: ${k} 는 음이 아닌 bigint 여야 한다`);
  }
  if (max_height >= MAX_HEIGHT_MAX) throw new Error('credMessageV5: max_height 는 2^64 미만이어야 한다 (회로 Num2Bits(64))');
  if (allowAgent > 1n) throw new Error('credMessageV5: allowAgent 는 0 또는 1 이어야 한다');
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_CRED_V5, Cf_u, Cf_s, max_height, chainid, allowAgent]));
}

// circuits/pi_cred.circom 의 ppidHasher(uid, s_u, chainid, arid 순서)와 일치해야 한다.
// 2026-09-15: chainid 를 넣었다 — 같은 사용자·같은 RP 라도 체인이 다르면 가명이 달라야 한다(체인 간
// unlinkability). 순서는 발표 자료의 H(ID, salt, chain, rid) 를 글자 단위로 따른다. Mode 2 의
// Poseidon(uid, rid, salt) 와는 더 이상 같은 구조가 아니다.
export async function ppid({ uid, arid, s_u, chainid }) {
  if (typeof chainid !== 'bigint') throw new Error('ppid: chainid(bigint) 가 필요하다');
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([uid, s_u, chainid, arid]));
}

/**
 * Cf = Poseidon(pt.x, pt.y). CIA 가 π_u 의 공개 입력 C_u_pt, 세션 발급 요청의 C_s_pt 에서 Cf_u·Cf_s 를
 * **스스로** 유도할 때 쓴다(설계 §6.2 — 사용자가 보낸 Cf 를 서명하면 증명된 점과
 * 무관한 값에 서명이 붙는다). userCommit·sessionCommit 이 돌려주는 Cf 와 같은 계산이다.
 */
export async function compressPoint({ x, y }) {
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([x, y]));
}
