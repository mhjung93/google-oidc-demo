// Mode 3 credential 프로토콜 유도값 — circuits/pi_cred.circom 과 JS 쪽이 반드시
// 일치해야 하는 계산만 모은다(커밋 C_u·C_s, 서명 메시지, PPID). 단일 책임: 이 세
// 함수 밖의 어떤 프로토콜 로직도 여기 두지 않는다.
//
// 인자 **순서**는 회로 배선의 일부다 — Poseidon은 인자 순서가 바뀌면 다른
// 해시가 나오므로, 여기서 순서를 바꾸면 회로와 어긋난다.
// 2026-09-14: 속성 4슬롯(attr0..3)과 (max_height, chainid, allowAgent) 서명 메시지 — 2026-09-18 설계 §3.
// 2026-10-12 V11: C_s 재정의(pk_i·max_height·r_s·r_rp), 토큰 7인자, auid·auid_s·arid_s, PPID 순서 — 스펙 2026-10-12 §2.
import { randomBytes } from 'node:crypto';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';

// 서명 도메인(MODE3CRED 계열) 이력: "MODE3CRED"(2026-09-09) → V2 속성 4슬롯(09-14) → V3 세션 성명(09-15) → V4 max_height·allowAgent(09-18)
// → V5(2026-09-21) 커밋 둘 → **V11(2026-10-12, 그림 261012)**: Sign(D_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent). 인자 7개.
// max_height 는 토큰 메시지에서 빠지고 C_s 안에 들어간다(D5). 옛 상수는 지웠다 — 도메인이 달라 옛 자격증명은 V11 회로에서 재생되지 않는다.
export const DOMAIN_MODE3_CRED_V11 = 23926173293433188795270181169n;   // ASCII "MODE3CREDV11" 빅엔디언
// 가명 유도 태그(스펙 2026-10-12 §2). 세 해시가 서로 다른 태그를 쓰므로 한 값이 다른 자리에서 재해석되지 않는다.
export const DOMAIN_MODE3_AUID  = 1426111059989489862980n;      // "MODE3AUID"  — auid   = Poseidon(T, uid, s_u)
export const DOMAIN_MODE3_AUIDS = 365084431357309404922963n;    // "MODE3AUIDS" — auid_s = Poseidon(T, auid, arid, r_rp)  (D7: arid 포함)
export const DOMAIN_MODE3_ARIDS = 365084431357309354591315n;    // "MODE3ARIDS" — arid_s = Poseidon(T, arid, r_rp)
export const MAX_HEIGHT_MAX = 1n << 64n;   // 회로 Num2Bits(64) 와 같은 상한
export const PK_I_MAX = 1n << 160n;        // pk_i 는 이더리움 주소 — 회로 Num2Bits(160)
export const ATTR_SLOTS = 6;
export const ATTR_MAX = 1n << 64n;   // 속성은 64비트 정수(스펙 2026-09-22 §4.1) — 회로 Num2Bits(64)·LessEqThan(64) 과 같은 상한

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

// ---- 교과서 Pedersen 커밋 (2026-09-10 부터 현행) ----
// circuits/lib/mode3_commit.circom 의 CommitUser·CommitSessionV11 과 정확히 같은 생성원·순서·상한.

export const SCALAR_BITS = 250;
export const SCALAR_MAX = 1n << 250n;   // 회로의 Num2Bits(250). r(≈2^251.4) 미만이라 binding 이 유지된다

// circomlib pedersen.circom BASE[0..12]. 회로 파일의 G_UID/G_ARID/G_SU/G_PKI/G_ATTR[0..5]/H_BLIND/G_EXP/G_RS 와 글자 단위로 같아야 한다.
// circomlib 표는 index 0..9 까지라, index 10(attr5) 이후는 circomlib 표에는 없고 circomlibjs getBasePoint('blake', i) 로 계산한 값이다.
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
  attr4: Object.freeze([18597552580465440374022635246985743886550544261632147935254624835147509493269n,
          6753322320275422086923032033899357299485124665258735666995435957890214041481n]),
  attr5: Object.freeze([16246587114701919230396141881596483298016809673932703125119295166936827150109n,
          2008259283001433748666303325888612438000671916354550248296035439458960131795n]),
  blind: Object.freeze([20265828622013100949498132415626198973119240347465898028410217039057588424236n,
          1160461593266035632937973507065134938065359936056410650153315956301179689506n]),
  // V11(2026-10-12 §2): C_s 의 max_height·r_s 항. circomlibjs getBasePoint('blake', 11)·(12) — attr5(10) 선례. 2026-10-12 inCurve·inSubgroup 확인.
  exp:   Object.freeze([15213743939064641260146023541489016041952046087348720940641996397552589095764n,
          12626463709848357735089296069583194130598330177778437327210365765201604869873n]),
  rs:    Object.freeze([3794846596710804728427490183747125272829051653079153052879417268450674798099n,
          21842435477255044883863745269531290629657425422620774125328061317110773122799n]),
});

// s_u, blind_u, r_s·r_rp 등 커밋 스칼라를 뽑는 표준 샘플러. crypto.randomBytes(32)로 256비트를
// 얻은 뒤 250비트로 마스킹한다 — 전체 필드 난수를 그대로 쓰면 userCommit()·sessionCommit() 의 2^250
// 상한을 92% 확률로 넘어 거부된다.
export function randomScalar() {
  const bytes = randomBytes(32);
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v & (SCALAR_MAX - 1n);
}

/** attrs 를 길이 6 의 bigint 배열로 정규화한다. 생략·짧은 배열은 0 으로 채우고, 상한 밖이면 throw. */
export function normalizeAttrs(attrs) {
  if (attrs !== undefined && attrs !== null && !Array.isArray(attrs)) throw new Error('attrs 는 배열이어야 한다');
  if (Array.isArray(attrs) && attrs.length > ATTR_SLOTS) throw new Error(`attrs 는 최대 ${ATTR_SLOTS}개다`);
  const out = [];
  for (let i = 0; i < ATTR_SLOTS; i++) {
    const raw = attrs?.[i] ?? 0n;
    const v = typeof raw === 'bigint' ? raw : BigInt(raw);
    if (v < 0n || v >= ATTR_MAX) throw new Error(`attr${i} 는 [0, 2^64) 범위여야 한다: ${v}`);
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
 *   C_u = uid·G_UID + s_u·G_SU + attr₀·G_ATTR0 + … + attr₅·G_ATTR5 + blind_u·H
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
 * 세션 커밋 V11(스펙 2026-10-12 D5·§3.2). 로그인마다.
 *   C_s = pk_i·G_PK + max_height·G_EXP + r_s·G_RS + r_rp·H
 * arid 는 빠졌다 — RP 바인딩은 토큰의 arid_s·auid_s(둘 다 r_rp 로 묶인다)가 맡는다. 블라인딩은 RP 가 준 r_rp 다:
 * RP 는 C_s 의 열림값을 모두 알고(심층 방어), IdP 는 r_rp 를 몰라 C_s 를 열지 못한다(pk_i 가 IdP 에 평문으로 가지 않는다).
 * circuits/lib/mode3_commit.circom 의 CommitSessionV11 과 생성원·덧셈 순서·비트 폭(pk_i 160, max_height 64, r_s·r_rp 250)이 같다.
 */
export async function sessionCommit({ pk_i, max_height, r_s, r_rp }) {
  if (typeof pk_i !== 'bigint' || pk_i < 0n || pk_i >= PK_I_MAX) throw new Error(`pk_i 는 [0, 2^160) 범위의 bigint 여야 한다 (회로 Num2Bits(160)): ${pk_i}`);
  if (typeof max_height !== 'bigint' || max_height < 0n || max_height >= MAX_HEIGHT_MAX) throw new Error(`max_height 는 [0, 2^64) 범위의 bigint 여야 한다 (회로 Num2Bits(64)): ${max_height}`);
  checkScalars({ r_s, r_rp });
  const bj = await getBabyjub();
  const mul = (g, e) => bj.mulPointEscalar([bj.F.e(g[0]), bj.F.e(g[1])], e);
  let acc = mul(PEDERSEN_GENERATORS.pk_i, pk_i);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.exp, max_height));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.rs, r_s));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, r_rp));
  return finishCommit(acc);
}

// circuits/pi_cred.circom V11 의 msgHasher(DOMAIN_MODE3_CRED_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent) 와 순서가 같아야 한다.
// max_height 는 여기 없다 — C_s(Cf_s) 안에 있다(D5). IdP 는 auid_s·arid_s 를 서명하되 저장하지 않는다(D1·D3).
export async function credMessageV11(auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent) {
  const poseidon = await getPoseidon();
  for (const [k, v] of [['auid_s', auid_s], ['arid_s', arid_s], ['Cf_u', Cf_u], ['Cf_s', Cf_s], ['chainid', chainid], ['allowAgent', allowAgent]]) {
    if (typeof v !== 'bigint' || v < 0n || v >= poseidon.F.p) throw new Error(`credMessageV11: ${k} 는 [0, p) 범위의 bigint 여야 한다(BN254 스칼라 필드)`);
  }
  if (allowAgent > 1n) throw new Error('credMessageV11: allowAgent 는 0 또는 1 이어야 한다');
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_CRED_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent]));
}

/** auid = Poseidon(T_AUID, uid, s_u) — 등록 때 지갑이 IdP 에 내는 사용자 가명(D4). 등록부 리프 Poseidon(auid, Cf_u) 의 재료. */
export async function auidOf({ uid, s_u }) {
  checkScalars({ uid, s_u });
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_AUID, uid, s_u]));
}
/** auid_s = Poseidon(T_AUIDS, auid, arid, r_rp) — 세션 가명(D7: arid 가 들어가 두 RP 가 같은 r_rp 를 써도 RP 간에 다르다). */
export async function auidSOf({ auid, arid, r_rp }) {
  if (typeof auid !== 'bigint' || auid < 0n) throw new Error('auidSOf: auid(bigint) 가 필요하다');
  checkScalars({ arid, r_rp });
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_AUIDS, auid, arid, r_rp]));
}
/** arid_s = Poseidon(T_ARIDS, arid, r_rp) — 세션용 RP 가명. RP 가 자기 r_rp 로 재계산해 토큰이 이 세션용인지 확인한다. */
export async function aridSOf({ arid, r_rp }) {
  checkScalars({ arid, r_rp });
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_ARIDS, arid, r_rp]));
}

// circuits/pi_cred.circom V11 의 ppidHasher(uid, s_u, arid, chainid) 와 일치해야 한다 — 덱 3장 H(uid, salt, rid, chain_id) 순서(D13).
// V10 의 (uid, s_u, chainid, arid) 에서 순서만 바뀌었다 — 모든 계정 주소가 바뀐다(팩토리 재배포와 함께).
export async function ppid({ uid, s_u, arid, chainid }) {
  if (typeof chainid !== 'bigint') throw new Error('ppid: chainid(bigint) 가 필요하다');
  checkScalars({ uid, s_u, arid });
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([uid, s_u, arid, chainid]));
}

/**
 * Cf = Poseidon(pt.x, pt.y). IdP 가 π_IdP·π_RP 의 공개 입력 C_u_pt, 세션 발급 요청의 C_s_pt 에서 Cf_u·Cf_s 를
 * **스스로** 유도할 때 쓴다(설계 §6.2 — 사용자가 보낸 Cf 를 서명하면 증명된 점과
 * 무관한 값에 서명이 붙는다). userCommit·sessionCommit 이 돌려주는 Cf 와 같은 계산이다.
 */
export async function compressPoint({ x, y }) {
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([x, y]));
}
