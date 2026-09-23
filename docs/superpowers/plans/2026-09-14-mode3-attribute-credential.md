# Mode 3 속성 credential 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mode 3 credential 을 `C_pt`(속성 4슬롯 포함) + `σ_CIA(C, exptime, chainid, nonce)` 형식으로 바꾸고, 회로·CIA·지갑·RP·테스트·문서를 그 형식으로 옮긴다.

**Architecture:** 커밋·서명 메시지의 단일 진실은 `lib/mode3_credential.js` 와 `circuits/lib/mode3_commit.circom`·`circuits/pi_cred.circom` 이다. 발급 PoK(`lib/mode3_issuance.js`)는 생성원 9개 표현 증명으로 늘어나고, CIA 는 height 창 대신 `(uid, nonce)` 집합으로 재생을 막으며 만료를 Unix 초로 기록한다. RP 는 `exptime`·`chainid` 를 검사한다. 컨트랙트·폐기 트리·게시 경로는 손대지 않는다.

**Tech Stack:** circom 2.1.9 + circomlib(Pedersen NUMS 생성원, Poseidon, EdDSAPoseidon), snarkjs Groth16, circomlibjs, Node.js ESM, express, ethers 6, hardhat 로컬 노드(:8545).

**Spec:** `docs/superpowers/specs/2026-09-14-mode3-attribute-credential-design.md` (§3 credential, §4 발급, §5 증명, §6 RP, §7 상태·만료). 기반: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md`.

## Global Constraints

- 주석·문서·오류 문구는 한글, 기존 파일 문체(짧은 단정문, `—` 대시). 새 의존성 없음.
- **Task 사이에는 chain 그룹이 깨진 상태가 정상이다** — credential 형식이 한꺼번에 바뀌므로 각 Task 는 자기 테스트만 통과시키고, chain 그룹 전체는 Task 6 끝에서 다시 12/12 를 확인한다. unit·circuit 그룹은 각 Task 끝에 해당 파일만 돌린다.
- 상수(스펙에서 그대로): `ATTR_SLOTS = 4`; 속성 생성원 = circomlib `BASE[5..8]`(아래 Task 1 의 리터럴); `DOMAIN_MODE3_CRED_V2 = 93461614427473393731524146n` (ASCII "MODE3CREDV2" 빅엔디언); 서명 메시지 `Poseidon(DOMAIN_MODE3_CRED_V2, C, exptime, chainid, nonce)`; 사용자 서명 메시지 `Poseidon(C_pt.x, C_pt.y, chainid, nonce)`; 회로 공개 입력 순서 `[PPID, arid, pk_i, exptime, chainid, revRoot, pk_CIA_x, pk_CIA_y]`(8개); 모든 커밋 스칼라·nonce 는 `[0, 2²⁵⁰)`; `CIA_TTL_SECONDS` 기본 3600; `CIA_CHAIN_IDS` 기본 = RPC 의 chainId; 지갑 만료 여유 `EXPIRY_MARGIN_SECONDS = 30`; CIA 상태 파일 `version: 2`, 옛 버전은 기동 거부.
- HTTP 바디의 bigint 는 10진 문자열. `attrs` 는 길이 4 의 10진 문자열 배열, 생략 시 `["0","0","0","0"]`.
- `build/mode3` 산출물 재생성은 Task 3 에서만, `pot21_final.ptau` 로. `npm run zk:*` 스크립트는 쓰지 않는다(Mode 1 대상).
- :8545 hardhat 노드, :4100/:5100/:3100 데모 서버는 사용자 프로세스다 — 켜져 있으면 쓰고, 끄거나 재시작하지 않는다. :8545 가 없으면 `npx hardhat node` 를 직접 띄우고 끝나면 종료한다.
- `.env`, `*_keys.json`, `*_state.json` 은 읽지 않는다. 격리 헬퍼(`tests/helpers/isolated_*.mjs`)가 임시 디렉터리를 쓴다.
- 커밋은 사용자 승인 후에만 한다. 각 Task 의 커밋 단계는 "제안 후 승인 시 실행".

---

### Task 1: 커밋 형식 — 속성 4슬롯, 새 도메인, 새 서명 메시지 (JS + 커밋 회로)

**Files:**
- Modify: `lib/mode3_credential.js`
- Modify: `circuits/lib/mode3_commit.circom` (`CommitPedersen` 만; `CommitPoseidon` 은 그대로)
- Test: `tests/test_mode3_commit_scheme.mjs` (circuit 그룹)

**Interfaces:**
- Consumes: circomlib `pedersen.circom` `BASE[5..8]`.
- Produces: `ATTR_SLOTS = 4`; `PEDERSEN_GENERATORS.attr0..attr3`; `credCommit({ uid, arid, s_u, blind, pk_i, attrs = [0n,0n,0n,0n] }) → { Cx, Cy, Cf }`; `DOMAIN_MODE3_CRED_V2`; `credMessage(C, exptime, chainid, nonce)`; `normalizeAttrs(attrs) → bigint[4]`(문자열/bigint 배열을 길이 4 bigint 배열로, 범위 검사); circom `CommitPedersen` 입력 `attrs[4]` 추가. Task 2·3·4·5 가 이 시그니처를 쓴다.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_mode3_commit_scheme.mjs` 의 `INPUT` 을 아래로 바꾸고, 생성원 수·속성 케이스를 더한다.

```js
const INPUT = {
  uid: '11111111111111111111',
  arid: '22222222222222222222',
  s_u: '33333333333333333333',
  blind: '44444444444444444444',
  pk_i: '1234567890123456789012345678901234567890', // 160비트 주소 범위
  attrs: ['19', '410', '0', '0'],                   // 예: 나이·국가코드, 빈 슬롯은 0
};
```

`'Pedersen 판: 회로의 (Cx, Cy) 가 JS credCommit 과 일치한다'` 케이스의 `credCommit` 호출에 `attrs: INPUT.attrs.map(BigInt)` 를 더한다. `'Pedersen 판: 생성원 5개가 …'` 케이스 이름을 `'Pedersen 판: 생성원 9개가 곡선 위·소수 부분군 안에 있다'` 로 바꾸고 아래 한 줄을 루프 앞에 넣는다.

```js
  assert.equal(Object.keys(PEDERSEN_GENERATORS).length, 9, 'uid, arid, s_u, pk_i, attr0..3, blind');
```

케이스 두 개를 파일 끝(제약 수 표 출력 앞)에 추가한다.

```js
await t('Pedersen 판: attr 하나만 바꿔도 C 가 바뀐다 (속성이 커밋에 실린다)', async () => {
  const a = await witness('pedersen', INPUT);
  const b = await witness('pedersen', { ...INPUT, attrs: ['20', '410', '0', '0'] });
  assert.notEqual(a[1].toString(), b[1].toString());
});

await t('Pedersen 판: attrs 를 생략한 JS credCommit 은 전부 0 과 같다', async () => {
  const withZero = await credCommit({ uid: 1n, arid: 2n, s_u: 3n, blind: 4n, pk_i: 5n, attrs: [0n, 0n, 0n, 0n] });
  const omitted = await credCommit({ uid: 1n, arid: 2n, s_u: 3n, blind: 4n, pk_i: 5n });
  assert.equal(withZero.Cf, omitted.Cf);
});

await t('DOMAIN_MODE3_CRED_V2 는 "MODE3CREDV2" 빅엔디언이고 옛 태그와 다르다', () => {
  assert.equal(DOMAIN_MODE3_CRED_V2, BigInt('0x' + Buffer.from('MODE3CREDV2').toString('hex')));
  assert.notEqual(DOMAIN_MODE3_CRED_V2, DOMAIN_MODE3_CRED);
});
```

import 줄을 `import { credCommit, SCALAR_MAX, PEDERSEN_GENERATORS, DOMAIN_MODE3_CRED, DOMAIN_MODE3_CRED_V2 } from '../lib/mode3_credential.js';` 로 바꾼다.

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_commit_scheme.mjs 2>&1 | grep -E "^(ok|FAIL)"`
Expected: `FAIL pedersen: 컴파일되고 witness가 계산된다`(회로에 `attrs` 입력이 없어 witness 계산이 `Signal not found` 로 실패) 또는 import 단계에서 `DOMAIN_MODE3_CRED_V2` 미정의 SyntaxError. 어느 쪽이든 실패.

- [ ] **Step 3: `lib/mode3_credential.js` 수정**

`DOMAIN_MODE3_CRED` 아래에 추가:

```js
// 속성 credential(2026-09-14 설계 §3). 옛 태그와 다른 값이라 두 형식의 서명이 서로 재생되지 않는다.
export const DOMAIN_MODE3_CRED_V2 = 93461614427473393731524146n; // ASCII "MODE3CREDV2" 빅엔디언
export const ATTR_SLOTS = 4;
```

`PEDERSEN_GENERATORS` 를 아래로 교체한다(기존 5개는 글자 단위로 같고, `attr0..3` 은 circomlib `BASE[5..8]`).

```js
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
```

`randomScalar` 아래에 추가:

```js
/** attrs 를 길이 4 의 bigint 배열로 정규화한다. 생략·짧은 배열은 0 으로 채우고, 상한 밖이면 throw. */
export function normalizeAttrs(attrs) {
  const out = [];
  for (let i = 0; i < ATTR_SLOTS; i++) {
    const raw = attrs?.[i] ?? 0n;
    const v = typeof raw === 'bigint' ? raw : BigInt(raw);
    if (v < 0n || v >= SCALAR_MAX) throw new Error(`attr${i} 는 [0, 2^250) 범위여야 한다: ${v}`);
    out.push(v);
  }
  if (Array.isArray(attrs) && attrs.length > ATTR_SLOTS) throw new Error(`attrs 는 최대 ${ATTR_SLOTS}개다`);
  return out;
}
```

`credCommit` 을 아래로 교체:

```js
/**
 * C = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + attr₀·G₅ + … + attr₃·G₈ + blind·H  (baby jubjub 점).
 * Cf = Poseidon(Cx, Cy) — 서명 메시지와 폐기 리프에 들어가는 압축값.
 *
 * 2^250 상한을 실제로 강제하는 것은 show 회로의 Num2Bits(250) 이다(설계 §6.1). 이
 * throw 는 지갑·테스트가 규약을 어긴 것을 일찍 잡기 위한 것이다. attrs 는 생략하면 전부 0.
 */
export async function credCommit({ uid, arid, s_u, blind, pk_i, attrs }) {
  const fields = { uid, arid, s_u, pk_i, blind };
  for (const [k, v] of Object.entries(fields)) {
    if (typeof v !== 'bigint' || v < 0n || v >= SCALAR_MAX) {
      throw new Error(`${k} 는 [0, 2^250) 범위의 bigint 여야 한다 (회로 Num2Bits(250) 과 같은 상한): ${v}`);
    }
  }
  const a = normalizeAttrs(attrs);
  const bj = await getBabyjub();
  const mul = (g, e) => bj.mulPointEscalar([bj.F.e(g[0]), bj.F.e(g[1])], e);
  let acc = mul(PEDERSEN_GENERATORS.uid, uid);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.arid, arid));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.s_u, s_u));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.pk_i, pk_i));
  for (let i = 0; i < ATTR_SLOTS; i++) acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS[`attr${i}`], a[i]));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, blind));
  const Cx = bj.F.toObject(acc[0]);
  const Cy = bj.F.toObject(acc[1]);
  const poseidon = await getPoseidon();
  const Cf = poseidon.F.toObject(poseidon([Cx, Cy]));
  return { Cx, Cy, Cf };
}
```

`credMessage` 를 아래로 교체:

```js
// circuits/pi_cred.circom 의 msgHasher(DOMAIN_MODE3_CRED_V2, C, exptime, chainid, nonce 순서)와
// 일치해야 한다. exptime 은 Unix 초, chainid 는 폐기 체인 id, nonce 는 사용자 무작위(설계 §3).
export async function credMessage(C, exptime, chainid, nonce) {
  for (const [k, v] of [['exptime', exptime], ['chainid', chainid], ['nonce', nonce]]) {
    if (typeof v !== 'bigint' || v < 0n) throw new Error(`credMessage: ${k} 는 음이 아닌 bigint 여야 한다`);
  }
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_CRED_V2, C, exptime, chainid, nonce]));
}
```

파일 머리 주석의 "인자 순서" 문단 아래에 한 줄을 더한다: `// 2026-09-14: 속성 4슬롯(attr0..3)과 (exptime, chainid, nonce) 서명 메시지 — 설계 2026-09-14-mode3-attribute-credential-design.md §3.`

- [ ] **Step 4: `circuits/lib/mode3_commit.circom` 의 `CommitPedersen` 수정**

주석 블록의 수식 줄을 `//   C = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + attr₀·G₅ + attr₁·G₆ + attr₂·G₇ + attr₃·G₈ + blind·H` 로, 마지막 문장을 `// 생성원은 circomlib pedersen.circom 의 NUMS 점 BASE[0..8]. 서로의 이산로그를 아무도 모른다.` 로 바꾼다. 템플릿 본문을 아래로 교체한다.

```circom
template CommitPedersen() {
    signal input uid;
    signal input arid;
    signal input s_u;
    signal input blind;
    signal input pk_i;
    signal input attrs[4];   // 속성 4슬롯(설계 2026-09-14 §3). 빈 슬롯은 0. CIA 는 값을 모른다
    signal output Cx;
    signal output Cy;

    var N = 250;

    var G_UID[2]   = [10457101036533406547632367118273992217979173478358440826365724437999023779287,
                      19824078218392094440610104313265183977899662750282163392862422243483260492317];
    var G_ARID[2]  = [2671756056509184035029146175565761955751135805354291559563293617232983272177,
                      2663205510731142763556352975002641716101654201788071096152948830924149045094];
    var G_SU[2]    = [5802099305472655231388284418920769829666717045250560929368476121199858275951,
                      5980429700218124965372158798884772646841287887664001482443826541541529227896];
    var G_PKI[2]   = [7107336197374528537877327281242680114152313102022415488494307685842428166594,
                      2857869773864086953506483169737724679646433914307247183624878062391496185654];
    var G_ATTR[4][2] = [
        [1487999857809287756929114517587739322941449154962237464737694709326309567994,
         14017256862867289575056460215526364897734808720610101650676790868051368668003],
        [14618644331049802168996997831720384953259095788558646464435263343433563860015,
         13115243279999696210147231297848654998887864576952244320558158620692603342236],
        [6814338563135591367010655964669793483652536871717891893032616415581401894627,
         13660303521961041205824633772157003587453809761793065294055279768121314853695],
        [3571615583211663069428808372184817973703476260057504149923239576077102575715,
         11981351099832644138306422070127357074117642951423551606012551622164230222506]
    ];
    var H_BLIND[2] = [20265828622013100949498132415626198973119240347465898028410217039057588424236,
                      1160461593266035632937973507065134938065359936056410650153315956301179689506];

    component bUid   = Num2Bits(N);  bUid.in   <== uid;
    component bArid  = Num2Bits(N);  bArid.in  <== arid;
    component bSu    = Num2Bits(N);  bSu.in    <== s_u;
    component bPki   = Num2Bits(N);  bPki.in   <== pk_i;
    component bBlind = Num2Bits(N);  bBlind.in <== blind;
    component bAttr[4];
    for (var j = 0; j < 4; j++) { bAttr[j] = Num2Bits(N); bAttr[j].in <== attrs[j]; }

    component mUid   = EscalarMulFix(N, G_UID);
    component mArid  = EscalarMulFix(N, G_ARID);
    component mSu    = EscalarMulFix(N, G_SU);
    component mPki   = EscalarMulFix(N, G_PKI);
    component mBlind = EscalarMulFix(N, H_BLIND);
    component mAttr[4];
    for (var j = 0; j < 4; j++) mAttr[j] = EscalarMulFix(N, G_ATTR[j]);
    for (var i = 0; i < N; i++) {
        mUid.e[i]   <== bUid.out[i];
        mArid.e[i]  <== bArid.out[i];
        mSu.e[i]    <== bSu.out[i];
        mPki.e[i]   <== bPki.out[i];
        mBlind.e[i] <== bBlind.out[i];
        for (var j = 0; j < 4; j++) mAttr[j].e[i] <== bAttr[j].out[i];
    }

    // 덧셈 순서: uid + arid + s_u + pk_i + attr0..3 + blind. JS 와 같은 순서 (결과는 순서와 무관하지만
    // 읽는 사람이 대조하기 쉽도록 맞춘다).
    component a1 = BabyAdd();
    a1.x1 <== mUid.out[0];   a1.y1 <== mUid.out[1];
    a1.x2 <== mArid.out[0];  a1.y2 <== mArid.out[1];
    component a2 = BabyAdd();
    a2.x1 <== a1.xout;       a2.y1 <== a1.yout;
    a2.x2 <== mSu.out[0];    a2.y2 <== mSu.out[1];
    component a3 = BabyAdd();
    a3.x1 <== a2.xout;       a3.y1 <== a2.yout;
    a3.x2 <== mPki.out[0];   a3.y2 <== mPki.out[1];
    component aAttr[4];
    for (var j = 0; j < 4; j++) {
        aAttr[j] = BabyAdd();
        if (j == 0) { aAttr[j].x1 <== a3.xout; aAttr[j].y1 <== a3.yout; }
        else        { aAttr[j].x1 <== aAttr[j-1].xout; aAttr[j].y1 <== aAttr[j-1].yout; }
        aAttr[j].x2 <== mAttr[j].out[0]; aAttr[j].y2 <== mAttr[j].out[1];
    }
    component a4 = BabyAdd();
    a4.x1 <== aAttr[3].xout; a4.y1 <== aAttr[3].yout;
    a4.x2 <== mBlind.out[0]; a4.y2 <== mBlind.out[1];

    Cx <== a4.xout;
    Cy <== a4.yout;
}
```

- [ ] **Step 5: 통과 확인**

Run: `node tests/test_mode3_commit_scheme.mjs 2>&1 | grep -E "^(ok|FAIL)|Pedersen 판 \|"`
Expected: 전부 `ok`. Pedersen 제약 수가 이전(18,786 근처)보다 약 4/5 만큼 늘어난 값으로 찍힌다(속성 스칼라곱 4개).

- [ ] **Step 6: 커밋 (사용자 승인 후)**

```bash
git add lib/mode3_credential.js circuits/lib/mode3_commit.circom tests/test_mode3_commit_scheme.mjs
git commit -m "feat(mode3): 커밋에 속성 4슬롯(BASE[5..8]), 서명 메시지 (C, exptime, chainid, nonce), DOMAIN_MODE3_CRED_V2"
```

---

### Task 2: 발급 PoK — 생성원 9개 표현 증명, 사용자 서명 메시지 `(C_pt, chainid, nonce)`

**Files:**
- Modify: `lib/mode3_issuance.js`
- Test: `tests/test_mode3_issuance.js` (unit 그룹)

**Interfaces:**
- Consumes: Task 1 의 `PEDERSEN_GENERATORS.attr0..3`, `normalizeAttrs`, `ATTR_SLOTS`.
- Produces: `proveIssuance({ uid, arid, s_u, blind, pk_i, r_u, attrs }) → { C_pt, cm_u, proof }`, `proof` 에 `z_attr: bigint[4]` 추가; `verifyIssuance({ uid, C_pt, cm_u, proof })` 시그니처 불변; `serializeProof`/`parseProof` 가 `z_attr` 문자열 배열을 다룸; `issueRequestMessage(C_pt, chainid, nonce)`.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_mode3_issuance.js` 에서:
- `freshUser()` 가 `attrs: [19n, 410n, 0n, 0n]` 도 돌려주게 하고, 파일의 모든 `proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u })` 호출에 `attrs: u.attrs` 를 더한다(`forgeMismatchedSu` 내부는 아래에서 따로 고친다).
- `'C_pt 는 credCommit 과 같은 점이다'` 케이스의 `credCommit` 호출에 `attrs: u.attrs` 를 더한다.
- `forgeMismatchedSu` 에서 `[G1, G2, G3, G4, H]` 줄 아래에 `const GA = ['attr0', 'attr1', 'attr2', 'attr3'].map(G);` 를 두고, `C_pt` 계산에 `...u.attrs.map((v, i) => [v, GA[i]])` 를 `[pk_i, G4]` 뒤에 펼쳐 넣는다. `a` 에 `attr0..attr3` 키를 더하고(`for (const k of ['arid', 'su', 'pki', 'blind', 'ru', 'attr0', 'attr1', 'attr2', 'attr3'])`), `T1` 계산에 `[a.attr0, GA[0]], …, [a.attr3, GA[3]]` 를 더하며, `proof` 에 `z_attr: u.attrs.map((v, i) => z(a[`attr${i}`], v))` 를 더한다. 같은 케이스의 eq1 재계산(`lhs1`)에도 `mulP(GA[i], proof.z_attr[i])` 네 항을 더한다.
- 새 케이스 셋을 `'직렬화 왕복이 값을 보존한다'` 앞에 추가한다.

```js
await t('음성: attr 하나를 바꿔 만든 C_pt 에 원래 증명을 붙이면 거절된다 (속성이 표현에 묶인다)', async () => {
  const u = await freshUser();
  const { cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u, attrs: u.attrs });
  const other = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u, attrs: [20n, 410n, 0n, 0n] });
  assert.equal(await verifyIssuance({ uid, C_pt: other.C_pt, cm_u, proof }), false);
});

await t('음성: z_attr 하나를 바꾸면 거절된다', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u, attrs: u.attrs });
  const bad = { ...proof, z_attr: proof.z_attr.map((z, i) => (i === 2 ? z + 1n : z)) };
  assert.equal(await verifyIssuance({ uid, C_pt, cm_u, proof: bad }), false);
});

await t('issueRequestMessage 는 (C_pt, chainid, nonce) 를 덮는다 — 하나라도 다르면 다른 메시지', async () => {
  const C_pt = { x: 1n, y: 2n };
  const m = await issueRequestMessage(C_pt, 31337n, 7n);
  assert.notEqual(m, await issueRequestMessage(C_pt, 1n, 7n));
  assert.notEqual(m, await issueRequestMessage(C_pt, 31337n, 8n));
  assert.notEqual(m, await issueRequestMessage({ x: 1n, y: 3n }, 31337n, 7n));
});
```

import 에 `issueRequestMessage` 를 더한다. 직렬화 왕복 케이스는 그대로 두되 `proveIssuance` 에 `attrs: u.attrs` 를 더한다.

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_issuance.js 2>&1 | grep -E "^(ok|FAIL)"`
Expected: `FAIL 양성: 올바른 witness 의 증명이 검증된다`(JS `credCommit` 은 attrs 를 반영하지만 `proveIssuance` 는 무시하므로 `C_pt` 비교 케이스가 실패) 및 새 케이스 3건 FAIL(`z_attr` 미정의, `issueRequestMessage` 인자 수).

- [ ] **Step 3: `lib/mode3_issuance.js` 수정**

import 를 `import { PEDERSEN_GENERATORS, SCALAR_MAX, normalizeAttrs, ATTR_SLOTS } from './mode3_credential.js';` 로 바꾼다. 파일 머리 주석의 첫 문단 끝에 `// 2026-09-14: 속성 4슬롯이 witness 로 더해졌다(설계 2026-09-14 §4). CIA 는 attr 값을 모른다.` 를 더한다.

`proveIssuance` 를 교체:

```js
export async function proveIssuance({ uid, arid, s_u, blind, pk_i, r_u, attrs }) {
  for (const [n, v] of [['uid', uid], ['arid', arid]]) {
    if (typeof v !== 'bigint' || v < 0n || v >= SCALAR_MAX) throw new Error(`${n} 는 [0, 2^250) 이어야 한다: ${v}`);
  }
  const a4 = normalizeAttrs(attrs);
  const bj = await getBj();
  const r = bj.subOrder;
  const [G1, G2, G3, G4, H] = ['uid', 'arid', 's_u', 'pk_i', 'blind'].map((n) => G(bj, n));
  const GA = [0, 1, 2, 3].map((i) => G(bj, `attr${i}`));

  const C_ptP = msm(bj, [[uid, G1], [arid, G2], [s_u, G3], [pk_i, G4], ...a4.map((v, i) => [v, GA[i]]), [blind, H]]);
  const cm_uP = msm(bj, [[s_u, G3], [r_u, H]]);
  const C_pt = toObj(bj, C_ptP);
  const cm_u = toObj(bj, cm_uP);

  const a = {};
  for (const k of ['arid', 'su', 'pki', 'blind', 'ru']) a[k] = await randomZr();
  const aAttr = [];
  for (let i = 0; i < ATTR_SLOTS; i++) aAttr.push(await randomZr());
  const T1 = toObj(bj, msm(bj, [[a.arid, G2], [a.su, G3], [a.pki, G4], ...aAttr.map((v, i) => [v, GA[i]]), [a.blind, H]]));
  const T2 = toObj(bj, msm(bj, [[a.su, G3], [a.ru, H]]));

  const c = await challenge(bj, uid, C_pt, cm_u, T1, T2);
  const z = (ax, x) => (ax + c * x) % r;
  const proof = {
    T1, T2, c,
    z_arid: z(a.arid, arid), z_su: z(a.su, s_u), z_pki: z(a.pki, pk_i),
    z_blind: z(a.blind, blind), z_ru: z(a.ru, r_u),
    z_attr: a4.map((v, i) => z(aAttr[i], v)),
  };
  return { C_pt, cm_u, proof };
}
```

`verifyIssuance` 를 교체:

```js
export async function verifyIssuance({ uid, C_pt, cm_u, proof }) {
  if (typeof uid !== 'bigint' || uid < 0n || uid >= SCALAR_MAX) return false;
  const bj = await getBj();
  const r = bj.subOrder;
  const { T1, T2, c, z_arid, z_su, z_pki, z_blind, z_ru, z_attr } = proof ?? {};
  // 1) 형식·군 검사. 부분군 밖의 점은 작은 위수 성분으로 등식을 만족시킬 수 있어 거절한다.
  for (const P of [C_pt, cm_u, T1, T2]) if (!validPoint(bj, P)) return false;
  if (!Array.isArray(z_attr) || z_attr.length !== ATTR_SLOTS) return false;
  for (const z of [c, z_arid, z_su, z_pki, z_blind, z_ru, ...z_attr]) {
    if (typeof z !== 'bigint' || z < 0n || z >= r) return false;
  }
  // 2) 챌린지 재계산
  if ((await challenge(bj, uid, C_pt, cm_u, T1, T2)) !== c) return false;
  // 3) 두 등식
  const [G1, G2, G3, G4, H] = ['uid', 'arid', 's_u', 'pk_i', 'blind'].map((n) => G(bj, n));
  const GA = [0, 1, 2, 3].map((i) => G(bj, `attr${i}`));
  const Y1 = bj.addPoint(fromObj(bj, C_pt), negPt(bj, bj.mulPointEscalar(G1, uid)));
  const lhs1 = msm(bj, [[z_arid, G2], [z_su, G3], [z_pki, G4], ...z_attr.map((z, i) => [z, GA[i]]), [z_blind, H]]);
  const rhs1 = bj.addPoint(fromObj(bj, T1), bj.mulPointEscalar(Y1, c));
  if (!eqPt(bj, lhs1, rhs1)) return false;
  const lhs2 = msm(bj, [[z_su, G3], [z_ru, H]]);
  const rhs2 = bj.addPoint(fromObj(bj, T2), bj.mulPointEscalar(fromObj(bj, cm_u), c));
  return eqPt(bj, lhs2, rhs2);
}
```

`issueRequestMessage` 를 교체:

```js
/**
 * 발급 요청의 사용자 서명 메시지 = Poseidon(C_pt.x, C_pt.y, chainid, nonce) (설계 2026-09-14 §4 단계 2).
 * 지갑의 signUserRequest 와 CIA 의 검증이 이 함수 하나를 공유한다 — 회로에는 들어가지 않는다.
 * exptime 은 CIA 가 정하므로 여기 없다.
 */
export async function issueRequestMessage(C_pt, chainid, nonce) {
  for (const [k, v] of [['chainid', chainid], ['nonce', nonce]]) {
    if (typeof v !== 'bigint' || v < 0n) throw new Error(`issueRequestMessage: ${k} 는 음이 아닌 bigint 여야 한다`);
  }
  const ps = await getPs();
  return ps.F.toObject(ps([C_pt.x, C_pt.y, chainid, nonce]));
}
```

직렬화 두 함수에 `z_attr` 를 더한다.

```js
export function serializeProof(p) {
  return {
    T1: pointToStrings(p.T1), T2: pointToStrings(p.T2), c: p.c.toString(),
    z_arid: p.z_arid.toString(), z_su: p.z_su.toString(), z_pki: p.z_pki.toString(),
    z_blind: p.z_blind.toString(), z_ru: p.z_ru.toString(),
    z_attr: p.z_attr.map((z) => z.toString()),
  };
}
export function parseProof(o) {
  const B = (v) => { if (typeof v !== 'string' || !/^[0-9]+$/.test(v)) throw new Error('bad scalar'); return BigInt(v); };
  if (!Array.isArray(o?.z_attr) || o.z_attr.length !== ATTR_SLOTS) throw new Error('bad z_attr');
  return {
    T1: pointFromStrings(o.T1), T2: pointFromStrings(o.T2), c: B(o.c),
    z_arid: B(o.z_arid), z_su: B(o.z_su), z_pki: B(o.z_pki), z_blind: B(o.z_blind), z_ru: B(o.z_ru),
    z_attr: o.z_attr.map(B),
  };
}
```

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_issuance.js 2>&1 | grep -E "^(ok|FAIL)"`
Expected: 전부 `ok`.

- [ ] **Step 5: 커밋 (사용자 승인 후)**

```bash
git add lib/mode3_issuance.js tests/test_mode3_issuance.js
git commit -m "feat(mode3): 발급 PoK 를 생성원 9개 표현 증명으로, 사용자 서명 메시지는 (C_pt, chainid, nonce)"
```

---

### Task 3: 회로 `pi_cred` — 속성·nonce witness, `(C, exptime, chainid, nonce)` 서명 검증, 공개 입력 8개, 산출물 재생성

**Files:**
- Modify: `circuits/pi_cred.circom`
- Modify: `tests/helpers/mode3_fixture.mjs`
- Modify: `tests/test_pi_cred_witness.mjs` (circuit 그룹)
- Create: `scripts/build_mode3_circuit.sh` (컴파일 + zkey. 그동안 없어서 사람이 명령을 기억해야 했다)
- Modify: `scripts/bench_pi_cred.mjs` (zkey 가 있으면 건너뛰는 부분은 그대로, 사용법 주석에 새 스크립트 언급)

**Interfaces:**
- Consumes: Task 1 의 `CommitPedersen`(`attrs[4]`), `credCommit`, `credMessage(C, exptime, chainid, nonce)`.
- Produces: 회로 입력 `attrs[4]`, `nonce`(비공개), `exptime`, `chainid`(공개); `component main {public [PPID, arid, pk_i, exptime, chainid, revRoot, pk_CIA_x, pk_CIA_y]}`; `buildValidInput()` 이 새 입력 모양을 돌려줌; `build/mode3/{pi_cred.r1cs, pi_cred_js/pi_cred.wasm, pi_cred_final.zkey, pi_cred_vkey.json}` 재생성.

- [ ] **Step 1: 픽스처와 실패하는 테스트 작성**

`tests/helpers/mode3_fixture.mjs` 의 `buildValidInput` 을 아래로 교체한다.

```js
export async function buildValidInput() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const eddsa = await buildEddsa();

  const uid   = 11111111111111111111n;
  const arid  = 22222222222222222222n;
  const s_u   = 33333333333333333333n;
  const blind = 44444444444444444444n;
  const pk_i  = 0x1234567890123456789012345678901234567890n; // 160비트
  const attrs = [19n, 410n, 0n, 0n];
  const exptime = 1789000000n;   // Unix 초. 값 자체는 회로에 무관 — 서명 메시지에만 들어간다
  const chainid = 31337n;
  const nonce = 55555555555555555555n;

  // s_u, blind, attrs, nonce 등 스칼라는 2^250 미만이어야 한다 (회로 Num2Bits(250)
  // 과 같은 상한, lib/mode3_credential.js 의 SCALAR_MAX). 새 난수가 필요하면
  // randomScalar()를 쓴다 — 전체 필드 난수는 92% 확률로 이 상한을 넘어 거부된다.
  const { Cf: C } = await credCommit({ uid, arid, s_u, blind, pk_i, attrs });
  const PPID = await computePpid({ uid, arid, s_u });
  const msg = await credMessage(C, exptime, chainid, nonce);

  // CIA 서명키. 테스트 고정값이며 실제 키가 아니다.
  const prv = Buffer.from('0001020304050607080900010203040506070809000102030405060708090001', 'hex');
  const pub = eddsa.prv2pub(prv);
  const sig = eddsa.signPoseidon(prv, F.e(msg));

  // 폐기 트리에 남의 폐기를 하나 넣어 둔다 — 내 비멤버십은 여전히 성립해야 한다.
  const tree = await createRevocationTree();
  await tree.insert(await credLeaf(999n));
  const w = await tree.getNonMembershipWitness(await credLeaf(C));

  const input = {
    uid: uid.toString(),
    s_u: s_u.toString(),
    blind: blind.toString(),
    attrs: attrs.map(String),
    nonce: nonce.toString(),
    S: sig.S.toString(),
    R8x: F.toObject(sig.R8[0]).toString(),
    R8y: F.toObject(sig.R8[1]).toString(),
    lowValue: w.lowValue.toString(),
    lowNextIndex: w.lowNextIndex.toString(),
    lowNextValue: w.lowNextValue.toString(),
    pathElements: w.pathElements.map(String),
    pathIndices: w.pathIndices.map(String),
    PPID: PPID.toString(),
    arid: arid.toString(),
    pk_i: pk_i.toString(),
    exptime: exptime.toString(),
    chainid: chainid.toString(),
    revRoot: tree.getRoot().toString(),
    pk_CIA_x: F.toObject(pub[0]).toString(),
    pk_CIA_y: F.toObject(pub[1]).toString(),
  };

  return { input, C };
}
```

`tests/test_pi_cred_witness.mjs` 에서 `'음성: 서명이 다른 max_height에 대한 것이면 거부된다'` 케이스를 아래 네 케이스로 교체한다.

```js
await t('음성: exptime 을 바꾸면 거부된다 (서명이 exptime 을 덮는다)', async () => {
  await assert.rejects(() => witness({ ...valid, exptime: (BigInt(valid.exptime) + 1n).toString() }), /Assert Failed/);
});

await t('음성: chainid 를 바꾸면 거부된다 (서명이 chainid 를 덮는다)', async () => {
  await assert.rejects(() => witness({ ...valid, chainid: '1' }), /Assert Failed/);
});

await t('음성: nonce 를 바꾸면 거부된다 (서명이 nonce 를 덮는다)', async () => {
  await assert.rejects(() => witness({ ...valid, nonce: (BigInt(valid.nonce) + 1n).toString() }), /Assert Failed/);
});

await t('음성: attr 하나를 바꾸면 거부된다 (C 가 달라져 서명이 안 맞는다)', async () => {
  const attrs = [...valid.attrs]; attrs[0] = '20';
  await assert.rejects(() => witness({ ...valid, attrs }), /Assert Failed/);
});
```

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_pi_cred_witness.mjs 2>&1 | grep -E "^(ok|FAIL)"`
Expected: 컴파일은 되지만(회로는 아직 옛 입력) `양성` 케이스가 `Signal not found`(attrs/nonce/exptime/chainid) 로 FAIL. 이후 케이스도 FAIL.

- [ ] **Step 3: `circuits/pi_cred.circom` 수정**

머리 주석의 `①` 줄을 `//   ① CIA가 (C, exptime, chainid, nonce)에 서명했다 — 없으면 아무나 credential을 만든다` 로 바꾸고 `④` 아래에 두 줄을 더한다.

```
//   attrs[4] 는 커밋에만 실린다 — CIA 는 값을 모르고(설계 2026-09-14 §2) 이 회로는 술어를 검증하지 않는다.
//   nonce 는 비공개다 — 공개하면 RP 로그와 CIA 의 (uid, nonce) 기록이 맞물려 uid↔RP 가 이어진다(§5).
```

템플릿의 입력 선언과 서명 검증 블록을 아래로 바꾼다(그 외 블록은 그대로).

```circom
    // ---- Private ----
    signal input uid;
    signal input s_u;
    signal input blind;
    signal input attrs[4];
    signal input nonce;

    // CIA EdDSA-Poseidon 서명
    signal input S;
    signal input R8x;
    signal input R8y;

    // 폐기 비멤버십 witness
    signal input lowValue;
    signal input lowNextIndex;
    signal input lowNextValue;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // ---- Public ----
    signal input PPID;
    signal input arid;
    signal input pk_i;
    signal input exptime;
    signal input chainid;
    signal input revRoot;
    signal input pk_CIA_x;
    signal input pk_CIA_y;

    var DOMAIN_MODE3_CRED_V2 = 93461614427473393731524146;  // ASCII "MODE3CREDV2"
    var TAG_MODE3_CRED = 3;                                  // TAG_SESSION=1, TAG_ACCOUNT=2 와 갈라 둔다
```

`commit` 컴포넌트 배선에 `for (var j = 0; j < 4; j++) commit.attrs[j] <== attrs[j];` 를 더한다. `msgHasher` 블록을 교체한다.

```circom
    // ---- ① CIA 서명 검증 ----
    // nonce 는 비공개 witness 로 메시지에만 들어간다. 스칼라 상한은 서명 메시지 안에서는 필요 없지만
    // JS 쪽(credMessage·CIA)이 2^250 미만으로 강제하므로 여기서도 같은 검사를 둔다 — 두 값이 r 을
    // 넘나들어 같은 해시를 내는 일이 없게.
    component nonceRange = Num2Bits(250);
    nonceRange.in <== nonce;
    component msgHasher = Poseidon(5);
    msgHasher.inputs[0] <== DOMAIN_MODE3_CRED_V2;
    msgHasher.inputs[1] <== Cf;
    msgHasher.inputs[2] <== exptime;
    msgHasher.inputs[3] <== chainid;
    msgHasher.inputs[4] <== nonce;
```

파일 끝의 `component main` 을 교체한다.

```circom
// 공개 입력의 순서는 lib/mode3_wallet.js·lib/mode3_rp.js 가 의존한다. 바꾸지 말 것.
// pk_CIA_x/y 는 공개 입력이다. 검증자는 반드시 이 값을 고정된 CIA 키와 비교해야 한다 (설계 §5).
component main {public [
    PPID, arid, pk_i, exptime, chainid, revRoot, pk_CIA_x, pk_CIA_y
]} = PiCred(32);
```

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_pi_cred_witness.mjs 2>&1 | grep -E "^(ok|FAIL)|비선형 제약"`
Expected: 전부 `ok`. 제약 수는 이전(18,786 근처)보다 약 4/5 늘어난 값.

- [ ] **Step 5: 빌드 스크립트 작성**

`scripts/build_mode3_circuit.sh` 를 만든다(실행 권한 `chmod +x`).

```bash
#!/usr/bin/env bash
# Mode 3 pi_cred 회로 컴파일 + Groth16 셋업. 산출물은 전부 build/mode3/ 아래.
#
#   bash scripts/build_mode3_circuit.sh [pot21_final.ptau]
#
# 그동안 이 절차는 tests/test_pi_cred_witness.mjs(컴파일, 단 witness_test/ 하위)와
# scripts/bench_pi_cred.mjs(zkey)에 나뉘어 있어 사람이 순서를 기억해야 했다. 회로를 바꾸면
# 반드시 이 스크립트로 zkey·vkey·wasm 을 한 세트로 다시 만든다 — 셋이 어긋나면 지갑의
# 로그인이 전부 bad_proof 가 된다.
#
# == 신뢰 설정에 관한 경고 ==
# contribute 는 고정 엔트로피 문자열을 쓴다(재현 가능한 데모 설정). 운영이라면 ceremony 가 필요하다.
set -euo pipefail
cd "$(dirname "$0")/.."

PTAU="${1:-pot21_final.ptau}"
if [ ! -f "$PTAU" ]; then
  echo "$PTAU 가 없습니다. pi_cred 는 2^14 를 넘어 pot21_final.ptau(2^21) 가 필요합니다." >&2
  exit 1
fi

OUT=build/mode3
mkdir -p "$OUT"
rm -f "$OUT/pi_cred_0000.zkey" "$OUT/pi_cred_final.zkey" "$OUT/pi_cred_vkey.json"

echo "=== compile ==="
circom circuits/pi_cred.circom --r1cs --wasm --sym -o "$OUT" \
  -l circuits -l circuits/lib -l node_modules/circomlib/circuits

echo "=== groth16 setup ==="
npx snarkjs groth16 setup "$OUT/pi_cred.r1cs" "$PTAU" "$OUT/pi_cred_0000.zkey"
npx snarkjs zkey contribute "$OUT/pi_cred_0000.zkey" "$OUT/pi_cred_final.zkey" --name=mode3 -v -e=mode3-bench
npx snarkjs zkey export verificationkey "$OUT/pi_cred_final.zkey" "$OUT/pi_cred_vkey.json"

echo "완료: $OUT/pi_cred_final.zkey, $OUT/pi_cred_vkey.json, $OUT/pi_cred_js/pi_cred.wasm"
```

`scripts/bench_pi_cred.mjs` 의 머리 주석 두 번째 줄 아래에 `//   (zkey 가 없으면 여기서 만들지만, 회로를 바꾼 뒤에는 scripts/build_mode3_circuit.sh 로 한 세트를 다시 만들 것)` 를 더한다.

- [ ] **Step 6: 산출물 재생성**

Run: `bash scripts/build_mode3_circuit.sh pot21_final.ptau 2>&1 | tail -3`
Expected: `완료: build/mode3/pi_cred_final.zkey, …`. 수 분 걸린다. 이후 `node -e 'const v=require("./build/mode3/pi_cred_vkey.json");console.log(v.nPublic)'` 가 `8` 을 찍는다.

- [ ] **Step 7: 커밋 (사용자 승인 후)**

```bash
git add circuits/pi_cred.circom tests/helpers/mode3_fixture.mjs tests/test_pi_cred_witness.mjs scripts/build_mode3_circuit.sh scripts/bench_pi_cred.mjs
git commit -m "feat(mode3): pi_cred 가 (C, exptime, chainid, nonce) 서명을 검증하고 속성·nonce 를 witness 로 받는다 — 빌드 스크립트 추가"
```

---

### Task 4: 지갑·RP 라이브러리 — 요청 형식, 증명 입력, `exptime`·`chainid` 검사

**Files:**
- Modify: `lib/mode3_wallet.js`
- Modify: `lib/mode3_rp.js`
- Test: `tests/test_mode3_wallet.mjs`, `tests/test_mode3_rp.mjs` (chain 그룹, :8545 + Task 3 산출물)

**Interfaces:**
- Consumes: Task 1~3.
- Produces: `signUserRequest(sk_uHex, C_pt, chainid, nonce)`; `buildIssueRequest({ uid, arid, s_u, r_u, sk_u, session, chainid, attrs }) → { body: { uid, C_pt, proof, sig_u, chainid, nonce }, secrets: { blind, nonce } }`; `buildCredentialProof({ …, attrs, credential })` 가 `credential.{C, exptime, chainid, nonce, sigma}` 를 읽음, `publicSignals` 8개; `createRpVerifier({ …, chainId })` 와 `verifyLogin` 의 실패 사유 `'expired'`(벽시계), `'wrong_chain'`(신규). `credential` 객체 형태: `{ C, exptime, chainid, nonce, sigma:{R8x,R8y,S}, pk_CIA? }`.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_mode3_wallet.mjs`:
- `localIssue(C_pt, head)` 를 `localIssue(C_pt, chainid, nonce, ttlSec = 3600n)` 로 바꾼다.

```js
async function localIssue(C_pt, chainid, nonce, ttlSec = 3600n) {
  const C = await compressPoint(C_pt);
  const exptime = BigInt(Math.floor(Date.now() / 1000)) + ttlSec;
  const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessage(C, exptime, chainid, nonce)));
  return { C: C.toString(), exptime: exptime.toString(), chainid: chainid.toString(), nonce: nonce.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
```

- `'발급 요청 → 로컬 CIA 서명 → 증명 생성 → vkey 로 검증된다'` 케이스에서 `buildIssueRequest` 호출을 `buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n, attrs: [19n, 410n, 0n, 0n] })` 로, `cred = await localIssue(pointFromStrings(req.body.C_pt), 31337n, req.secrets.nonce);` 로 바꾸고, `buildCredentialProof` 호출에 `attrs: [19n, 410n, 0n, 0n]` 을 더한다. 단언을 `assert.equal(publicSignals.length, 8); assert.equal(BigInt(publicSignals[2]), session.pk_i); assert.equal(BigInt(publicSignals[3]), BigInt(cred.exptime)); assert.equal(BigInt(publicSignals[4]), 31337n); assert.equal(BigInt(publicSignals[5]), tree0.getRoot());` 로 바꾼다. `head` 변수는 지운다.
- `'내 credential 이 폐기되면 …'` 케이스의 `buildCredentialProof` 에도 `attrs: [19n, 410n, 0n, 0n]` 을 더한다.
- 새 케이스를 `'챌린지 서명은 …'` 앞에 추가한다.

```js
await t('buildIssueRequest 는 요청마다 새 nonce 를 뽑고 본문에 chainid·nonce 를 싣는다', async () => {
  const sk_u = Buffer.alloc(32, 3).toString('hex');
  const a = await buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n });
  const b = await buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n });
  assert.equal(a.body.chainid, '31337');
  assert.equal(a.body.nonce, a.secrets.nonce.toString());
  assert.notEqual(a.body.nonce, b.body.nonce);
  assert.equal(a.body.height, undefined, 'height 는 더 이상 보내지 않는다');
  assert.equal(a.body.proof.z_attr.length, 4);
});
```

`tests/test_mode3_rp.mjs`:
- `issueWith(key, C_pt, ttl = 300n)` 을 아래로 교체한다.

```js
async function issueWith(key, C_pt, nonce, ttlSec = 3600n, chainid = 31337n) {
  const C = await compressPoint(C_pt);
  const exptime = BigInt(Math.floor(Date.now() / 1000)) + ttlSec;
  const s = eddsa.signPoseidon(key.prv, F.e(await credMessage(C, exptime, chainid, nonce)));
  return { C: C.toString(), exptime: exptime.toString(), chainid: chainid.toString(), nonce: nonce.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
```

- `makeLogin` 을 아래로 교체한다.

```js
async function makeLogin({ key = CIA, useArid = arid, ttlSec = 3600n, chainid = 31337n } = {}) {
  const reg = await createRegistration();
  const session = createSessionKey();
  const attrs = [19n, 410n, 0n, 0n];
  const req = await buildIssueRequest({ uid, arid: useArid, s_u: reg.s_u, r_u: reg.r_u, sk_u: Buffer.alloc(32, 3).toString('hex'), session, chainid, attrs });
  const cred = await issueWith(key, pointFromStrings(req.body.C_pt), req.secrets.nonce, ttlSec, chainid);
  const { tree } = await syncRevocationTree(provider, logAddress);
  const { proof, publicSignals } = await buildCredentialProof({ uid, arid: useArid, s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, attrs, credential: cred, pk_CIA: key.pub, tree });
  const challenge = 'rp-challenge-' + Math.random();
  return { proof, publicSignals, challenge, sig: await signChallenge(session.wallet, challenge), session, cred, reg };
}
```

- 검증기 생성 세 곳(`rp`, 두 개의 `rp2`)에 `chainId: 31337n` 을 더한다.
- `'음성 c: max_height 를 지나면 expired'` 를 아래로 교체한다(블록 진행이 아니라 시간).

```js
await t('음성 c: exptime 이 지나면 expired (벽시계)', async () => {
  const L = await makeLogin({ ttlSec: -5n });
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'expired' });
});

await t("음성 c': 다른 chainid 로 발급된 credential 은 wrong_chain", async () => {
  const L = await makeLogin({ chainid: 1n });
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'wrong_chain' });
});
```

`mineBlocks` import 는 더 이상 쓰지 않으면 지운다.

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_wallet.mjs 2>&1 | grep -E "^(ok|FAIL)"` 와 `node tests/test_mode3_rp.mjs 2>&1 | grep -E "^(ok|FAIL)"`
Expected: 발급·증명 케이스가 FAIL(`signUserRequest` 가 height 를 요구, `buildCredentialProof` 가 `max_height` 를 읽음).

- [ ] **Step 3: `lib/mode3_wallet.js` 수정**

`signUserRequest`·`buildIssueRequest`·`buildCredentialProof` 를 교체한다. import 에 `normalizeAttrs` 를 더한다(`import { randomScalar, ppid, normalizeAttrs } from './mode3_credential.js';`).

```js
/**
 * Sign(sk_u, (C_pt, chainid, nonce)): 등록된 장기키로 서명 (설계 2026-09-14 §4 단계 2). 메시지는 issueRequestMessage().
 * nonce 는 요청마다 새로 뽑고 CIA 가 (uid, nonce) 재사용을 거절한다 — 만료된 요청 본문을 그대로 다시 내서
 * 새 σ_CIA 를 받는 것(TTL 연장)을 막는다. 옛 height 창 검사의 자리다.
 */
export async function signUserRequest(sk_uHex, C_pt, chainid, nonce) {
  if (typeof chainid !== 'bigint' || typeof nonce !== 'bigint') throw new Error('signUserRequest: chainid·nonce(bigint) 가 필요하다');
  const eddsa = await getEddsa();
  const F = eddsa.F;
  const s = eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), F.e(await issueRequestMessage(C_pt, chainid, nonce)));
  return { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() };
}

/** §4 단계 1~2. blind·nonce 는 여기서 새로 뽑고 secrets 로 돌려준다 — 증명 생성 때 필요하다. attrs 는 생략하면 전부 0. */
export async function buildIssueRequest({ uid, arid, s_u, r_u, sk_u, session, chainid, attrs }) {
  if (typeof chainid !== 'bigint') throw new Error('buildIssueRequest: chainid(bigint) 가 필요하다');
  const blind = randomScalar();
  const nonce = randomScalar();
  const a4 = normalizeAttrs(attrs);
  const { C_pt, proof } = await proveIssuance({ uid, arid, s_u, blind, pk_i: session.pk_i, r_u, attrs: a4 });
  const body = {
    uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof),
    sig_u: await signUserRequest(sk_u, C_pt, chainid, nonce), chainid: chainid.toString(), nonce: nonce.toString(),
  };
  return { body, secrets: { blind, nonce } };
}
```

```js
/** §5 — 공개 입력 순서 [PPID, arid, pk_i, exptime, chainid, revRoot, pk_CIA_x, pk_CIA_y] 는 회로가 정한다. */
export async function buildCredentialProof({ uid, arid, s_u, blind, pk_i, attrs, credential, pk_CIA, tree, wasmPath = WASM_PATH, zkeyPath = ZKEY_PATH }) {
  const PPID = await ppid({ uid, arid, s_u });
  const C = BigInt(credential.C);
  const a4 = normalizeAttrs(attrs);
  const w = await tree.getNonMembershipWitness(await credLeaf(C));   // 폐기됐으면 여기서 throw ("is a member")
  const input = {
    uid: uid.toString(), s_u: s_u.toString(), blind: blind.toString(),
    attrs: a4.map(String), nonce: BigInt(credential.nonce).toString(),
    S: credential.sigma.S, R8x: credential.sigma.R8x, R8y: credential.sigma.R8y,
    lowValue: String(w.lowValue), lowNextIndex: String(w.lowNextIndex), lowNextValue: String(w.lowNextValue),
    pathElements: w.pathElements.map(String), pathIndices: w.pathIndices.map(String),
    PPID: PPID.toString(), arid: arid.toString(), pk_i: pk_i.toString(),
    exptime: BigInt(credential.exptime).toString(), chainid: BigInt(credential.chainid).toString(), revRoot: tree.getRoot().toString(),
    pk_CIA_x: pk_CIA.x.toString(), pk_CIA_y: pk_CIA.y.toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  return { proof, publicSignals, revRoot: tree.getRoot() };
}
```

- [ ] **Step 4: `lib/mode3_rp.js` 수정**

머리 주석의 `c.` 줄을 `//   c. 만료             ← now ≤ exptime (Unix 초, 벽시계). 2026-09-14 설계 §6` 로 바꾸고 그 아래 `//   c'. chainid         ← credential 의 폐기 체인이 RP 가 읽는 체인과 같은가 (신규)` 를 더한다. `createRpVerifier` 시그니처와 `verifyLogin` 을 교체한다.

```js
export function createRpVerifier({ provider, logAddress, vkey, pkCIA, arid, chainId, headMaxAgeMs = 10 * 60_000, now = Date.now }) {
  if (typeof chainId !== 'bigint') throw new Error('createRpVerifier: chainId(bigint) 가 필요하다 — RP 가 읽는 폐기 체인의 id');
```

```js
  async function verifyLogin({ proof, publicSignals, challenge, sig }) {
    if (!Array.isArray(publicSignals) || publicSignals.length !== 8 || !proof || typeof challenge !== 'string' || typeof sig !== 'string') {
      return { ok: false, reason: 'malformed' };
    }
    let ps;
    try { ps = publicSignals.map((s) => BigInt(s)); } catch { return { ok: false, reason: 'malformed' }; }
    const [PPID, aridIn, pk_i, exptime, chainIn, revRoot, ciaX, ciaY] = ps;

    const v = await chainView();                                   // a
    if (!v) return { ok: false, reason: 'chain_unavailable' };
    if (revRoot !== v.root) return { ok: false, reason: 'stale_root' };       // b
    if (BigInt(Math.floor(now() / 1000)) > exptime) return { ok: false, reason: 'expired' };   // c (벽시계)
    if (chainIn !== chainId) return { ok: false, reason: 'wrong_chain' };     // c'
    if (ciaX !== BigInt(pkCIA.x) || ciaY !== BigInt(pkCIA.y)) return { ok: false, reason: 'untrusted_cia' };   // d
    if (aridIn !== BigInt(arid)) return { ok: false, reason: 'wrong_arid' };
```

이하(e·f·g)는 그대로.

- [ ] **Step 5: 통과 확인**

Run: `node tests/test_mode3_wallet.mjs 2>&1 | grep -E "^(ok|FAIL)"; node tests/test_mode3_rp.mjs 2>&1 | grep -E "^(ok|FAIL)"`
Expected: 두 파일 모두 전부 `ok`.

- [ ] **Step 6: 커밋 (사용자 승인 후)**

```bash
git add lib/mode3_wallet.js lib/mode3_rp.js tests/test_mode3_wallet.mjs tests/test_mode3_rp.mjs
git commit -m "feat(mode3): 지갑이 chainid·nonce·attrs 로 발급 요청·증명을 만들고 RP 가 exptime(벽시계)·chainid 를 검사한다"
```

---

### Task 5: CIA — nonce 집합, 허용 chainid, TTL 초, 상태 v2, 폐기 대상 선별을 시간 기준으로

**Files:**
- Modify: `cia.js`
- Modify: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` (§6.5.1 의 "체인이 닿지 않아도" 문단 한 줄 보정)
- Test: `tests/test_cia_register_issue.mjs`, `tests/test_cia_startup.mjs`, `tests/test_cia_issue_race.mjs` (chain 그룹)

**Interfaces:**
- Consumes: Task 1·2 (`credMessage`, `issueRequestMessage`, `parseProof`, `verifyIssuance`), Task 4 의 `signUserRequest(sk, C_pt, chainid, nonce)`.
- Produces: `POST /cia/issue` 본문 `{ uid, C_pt, proof, sig_u, chainid, nonce }` → 200 `{ C, exptime, chainid, nonce, sigma, pk_CIA }`; 400 `bad chainid`(허용 목록 밖) / `bad user signature` / `bad issuance proof` / 형식; 409 `nonce already used` / `credential already issued for this C_pt`; `GET /cia/public_keys` → `{ pk_CIA, ethAddress, ttlSeconds, chainIds: string[], logAddress }`; 상태 파일 `{ version: 2, accounts, issued: uid → [{leaf, C, exptime}], nonces: uid → [nonce], revoked, pending, epoch }`; `revokeAccount(uid)`(head 불필요); `self_revoke` 응답에서 `treeUpdated` 제거.

**설계 보정(스펙 §7 에서 따름):** 발급 기록 정리가 벽시계 기준이 되므로 계정 폐기가 체인 head 를 읽을 이유가 없다. 따라서 `/cia/revoke`·`self_revoke` 모두 체인 없이 리프를 넣는다. 기반 설계 §6.5.1 의 "체인이 닿지 않아도 `disabled` 는 걸린다" 문단은 "체인이 닿지 않아도 폐기가 전부 걸린다" 로 바뀐다(아래 Step 5).

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_cia_register_issue.mjs`:
- 상단 `signUser` 와 `issueRequest` 를 교체한다.

```js
// 사용자 서명은 (C_pt, chainid, nonce) 를 덮는다 — 만료된 요청 본문을 그대로 다시 내서 새 σ_CIA 를 받는
// 것(TTL 연장)은 CIA 의 (uid, nonce) 영구 집합이 막는다(설계 2026-09-14 §4).
const CHAIN_ID = 31337n;
const signUser = (prvBuf, C_pt, chainid, nonce) => signUserRequest(prvBuf.toString('hex'), C_pt, chainid, nonce);

async function issueRequest(u, overrides = {}, { chainid = CHAIN_ID, nonce = randomScalar(), attrs = [19n, 410n, 0n, 0n] } = {}) {
  const blind = randomScalar();
  const { C_pt, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind, pk_i, r_u: u.r_u, attrs });
  return { body: { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u: await signUser(u.sk_u, C_pt, chainid, nonce), chainid: chainid.toString(), nonce: nonce.toString(), ...overrides }, C_pt, blind, nonce };
}
```

- `public_keys` 케이스의 `assert.equal(r.body.ttlBlocks, 300);` 을 `assert.equal(r.body.ttlSeconds, 3600); assert.deepEqual(r.body.chainIds, ['31337']);` 로.
- 발급 양성 케이스의 서명 검증·만료 단언을 교체한다.

```js
    // σ_CIA 가 credMessage(C, exptime, chainid, nonce) 에 대한 pk_CIA 서명인지
    const msg = F.e(await credMessage(BigInt(cred.C), BigInt(cred.exptime), BigInt(cred.chainid), BigInt(cred.nonce)));
    const sig = { R8: [F.e(BigInt(cred.sigma.R8x)), F.e(BigInt(cred.sigma.R8y))], S: BigInt(cred.sigma.S) };
    const pub = [F.e(BigInt(cred.pk_CIA.x)), F.e(BigInt(cred.pk_CIA.y))];
    assert.ok(eddsa.verifyPoseidon(msg, sig, pub));
    // exptime = now + 3600 (±5초), chainid·nonce 는 요청값 그대로
    const nowSec = Math.floor(Date.now() / 1000);
    assert.ok(Number(cred.exptime) >= nowSec + 3595 && Number(cred.exptime) <= nowSec + 3605, cred.exptime);
    assert.equal(cred.chainid, '31337');
    assert.equal(cred.nonce, body.nonce);
```

- `'issue: 사용자 서명이 다른 키면 400'` 의 서명 줄을 `body.sig_u = await signUser(Buffer.alloc(32, 7), C_pt, CHAIN_ID, BigInt(body.nonce));` 로.
- `'issue: 서명한 height 가 너무 오래됐거나 미래면 400 …'` 케이스를 아래로 교체한다.

```js
  await t('issue: 같은 nonce 재사용은 409, 허용 목록 밖 chainid 는 400, 값만 바꿔 끼우면 서명 불일치 400, 누락은 400', async () => {
    const first = await issueRequest(user);
    assert.equal((await cia.post('/cia/issue', first.body)).status, 200);
    // 같은 nonce 로 다른 C_pt 를 내도 409 — (uid, nonce) 는 영구 집합이다
    const replay = await issueRequest(user, {}, { nonce: first.nonce });
    const r1 = await cia.post('/cia/issue', replay.body);
    assert.equal(r1.status, 409, JSON.stringify(r1.body));
    assert.match(r1.body.error, /nonce/);
    // 허용 목록(31337) 밖
    const wrongChain = await issueRequest(user, {}, { chainid: 1n });
    const r2 = await cia.post('/cia/issue', wrongChain.body);
    assert.equal(r2.status, 400, JSON.stringify(r2.body));
    assert.match(r2.body.error, /chainid/);
    // nonce 만 바꿔 끼우면 서명이 안 맞아 400
    const tampered = await issueRequest(user);
    tampered.body.nonce = (BigInt(tampered.body.nonce) + 1n).toString();
    assert.equal((await cia.post('/cia/issue', tampered.body)).status, 400);
    // nonce 없이 보내면 400
    const missing = await issueRequest(user);
    delete missing.body.nonce;
    assert.equal((await cia.post('/cia/issue', missing.body)).status, 400);
  });
```

- 형식 오류 케이스(`height: '0'` 이 들어 있는 곳, 원래 239행 부근)의 본문에서 `height: '0'` 을 `chainid: '31337', nonce: '1'` 로 바꾼다.
- `'self_revoke: 체인 RPC 가 죽어도 …'`(dead RPC 인스턴스) 케이스의 단언을 바꾼다: `treeUpdated` 단언을 지우고, `assert.equal(r.body.disabled, true); assert.ok(r.body.inserted.length >= 1, '체인 없이도 미만료 리프가 들어간다 — 만료 판정이 벽시계라 head 가 필요 없다');` 로. 그 케이스의 발급은 dead 인스턴스에서 `issue` 가 503 을 내므로(chainid 목록을 기동 시 RPC 에서 못 읽음) 발급 없이 `inserted.length === 0` 이 될 수 있다 — 그러면 단언을 `assert.deepEqual(r.body.inserted, [])` 로 두고 주석에 "dead 인스턴스는 발급이 안 되므로 넣을 리프가 없다" 고 적는다. **어느 쪽이 맞는지는 Step 3 의 구현(기동 시 chainId 조회 실패 처리)에 따라 정해진다 — 구현 뒤 실제 응답을 보고 둘 중 하나를 고르고 주석으로 이유를 남긴다.**
- `'publish 도중 들어온 revoke …'` 등 나머지 케이스는 `issueRequest(user)` 호출 형태가 같으므로 그대로 둔다. 다만 `mineBlocks` 를 더 이상 쓰지 않으면 import 에서 지운다.

`tests/test_cia_startup.mjs` 의 `registerAndIssueLeaf` 발급 부분을 아래로 바꾼다.

```js
  const blind = randomScalar(), nonce = randomScalar();
  const { C_pt, proof } = await proveIssuance({ uid, arid, s_u: user.s_u, blind, pk_i, r_u: user.r_u, attrs: [0n, 0n, 0n, 0n] });
  const sig_u = await signUserRequest(user.sk_u, C_pt, 31337n, nonce);
  const r = await cia.post('/cia/issue', { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u, chainid: '31337', nonce: nonce.toString() });
```

`tests/test_cia_issue_race.mjs` 의 `issueBody` 를 아래로 바꾼다.

```js
  async function issueBody() {
    const blind = randomScalar(), nonce = randomScalar();
    const { C_pt, proof } = await proveIssuance({ uid, arid, s_u, blind, pk_i, r_u, attrs: [0n, 0n, 0n, 0n] });
    return { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u: await signUserRequest(sk_u, C_pt, 31337n, nonce), chainid: '31337', nonce: nonce.toString() };
  }
```

race 테스트의 첫 케이스 이름 `'issue 가 head 를 읽는 동안 …'` 은 게이트 프록시가 `eth_blockNumber` 를 잡는 방식이다. Step 3 에서 `issue` 가 더 이상 `headHeight()` 를 부르지 않으면 이 게이트가 걸리지 않는다 — **`issue` 핸들러는 발급 기록 직전에 `headHeight()` 를 한 번 부르지 않는다. 대신 프록시가 잡을 수 있도록 `await ethWallet.provider.getBlockNumber()` 를 발급 핸들러의 검증 뒤·기록 앞에 "체인 가용성 확인"으로 남긴다**(아래 Step 3 의 `chainAlive()`; 503 fail-closed 유지, 스펙 §4 의 "CIA 는 발급 경로에서 체인 가용성을 본다"는 기반 설계 §2.1 과 같다). 케이스 이름은 `'issue 가 체인 가용성을 확인하는 동안 계정이 폐기되면 발급하지 않는다 (403, 기록도 남지 않는다)'` 로 바꾼다.

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_cia_register_issue.mjs 2>&1 | grep -E "^(ok|FAIL)" | head -30`
Expected: `public_keys` 케이스부터 FAIL(`ttlSeconds` 없음), 발급 케이스 FAIL(`height required` 400).

- [ ] **Step 3: `cia.js` 수정**

상수 블록(`TTL_BLOCKS`·`ISSUE_HEIGHT_WINDOW`·그 검사)을 아래로 교체한다.

```js
const TTL_SECONDS = Number(process.env.CIA_TTL_SECONDS) || 3600;   // exptime = now + TTL (Unix 초). 옛 300블록×12초에 상응
// 발급을 허용하는 폐기 체인 id 목록(쉼표 구분). 미설정이면 기동 시 RPC 의 chainId 하나. 사용자가 요청에 넣은
// chainid 가 이 목록에 없으면 400 — 다른 체인 기준 credential 을 이 CIA 가 서명하지 않는다(설계 2026-09-14 §4).
let CHAIN_IDS = (process.env.CIA_CHAIN_IDS || '').split(',').map((s) => s.trim()).filter(Boolean);
```

`// ---- 상태 ----` 주석과 `defaultState` 를 교체한다.

```js
// ---- 상태 ----
// accounts:  uid → { pk_u:{x,y}, cm_u:{x,y}, disabled }
// issued:    uid → [ { leaf(10진), C(10진), exptime(10진 Unix 초) } ]   폐기 시 열거·재전송 거절용. 만료되면 걷어낸다
// nonces:    uid → [ nonce(10진) ]   발급 요청 재생 방지. **정리하지 않는다** — 만료 뒤 지우면 옛 본문 재생으로 TTL 연장이 된다
// revoked:   [leaf(10진)]                              지금까지 트리에 넣은 전부 — 재기동 시 재구성
// pending:   [leaf(10진)]                              아직 게시 안 한 것
// epoch
// version 2 (2026-09-14): issued 항목이 max_height 대신 exptime, nonces 추가. v1 은 옛 credential 형식이라 읽지 않는다.
const STATE_VERSION = 2;
function defaultState() { return { version: STATE_VERSION, accounts: {}, issued: {}, nonces: {}, revoked: [], pending: [], epoch: 0 }; }
```

`loadState` 첫 줄 뒤에 버전 검사를 넣는다.

```js
  state = readJson(STATE_FILE, defaultState());
  if (state.version !== STATE_VERSION) {
    console.error(`[cia] 기동 거부: 상태 파일 버전 ${state.version} (기대 ${STATE_VERSION}). 옛 credential 형식(max_height)의 상태는 ` +
      `새 회로에서 어차피 검증되지 않으므로 마이그레이션하지 않는다 — 재시연 세트(로그 재배포 → 상태 파일 삭제)로 새로 시작할 것.`);
    process.exit(1);
  }
  state.nonces ??= {};
```

`loadState` 끝(트리 재구성 뒤)에 chainId 확정을 더한다.

```js
  if (CHAIN_IDS.length === 0) {
    try { CHAIN_IDS = [(await ethWallet.provider.getNetwork()).chainId.toString()]; }
    catch (e) { console.warn(`[cia] 기동 시 chainId 를 읽지 못했다 — CIA_CHAIN_IDS 가 없으면 발급은 503: ${e.message}`); }
  }
```

`pruneExpired` 와 `headHeight` 사이를 아래로 바꾼다(`headHeight` 는 `/cia/state`·게시 경로가 계속 쓴다).

```js
const nowSec = () => BigInt(Math.floor(Date.now() / 1000));
/** 만료(exptime < now)된 발급 기록을 걷어내고 남은 것을 돌려준다. 체인이 필요 없다 — 만료는 벽시계다. */
function pruneExpired(uid) {
  const list = state.issued[uid] ?? [];
  const now = nowSec();
  state.issued[uid] = list.filter((e) => BigInt(e.exptime) >= now);
  return state.issued[uid];
}
/** 발급 직전의 체인 가용성 확인(fail-closed, 기반 설계 §2.1). 값은 쓰지 않는다 — 살아 있는지만 본다. */
async function chainAlive() {
  if (!LOG_ADDRESS) throw Object.assign(new Error('CIA_LOG_ADDRESS not configured'), { status: 503 });
  try { await ethWallet.provider.getBlockNumber(); }
  catch { throw Object.assign(new Error('chain unavailable'), { status: 503 }); }
}
```

`/cia/public_keys` 응답을 `res.json({ pk_CIA: S(ciaPub), ethAddress: ethWallet.address, ttlSeconds: TTL_SECONDS, chainIds: CHAIN_IDS, logAddress: LOG_ADDRESS });` 로.

`/cia/issue` 핸들러를 통째로 교체한다.

```js
// §4(2026-09-14) 발급. C 는 받지 않는다 — C_pt 에서 스스로 유도한다. 검사 순서: 형식 → disabled → chainid 허용 →
// (uid, nonce) 미사용 → 사용자 서명 → π_issue → 같은 C → 체인 가용성 → disabled 재확인 → 서명·기록.
app.post('/cia/issue', async (req, res) => {
  try {
    const { uid, C_pt, proof, sig_u, chainid, nonce } = req.body ?? {};
    if (!isDec(uid) || !isPt(C_pt) || !proof || !sig_u || !isDec(chainid) || !isDec(nonce)) {
      return res.status(400).json({ error: 'uid, C_pt, proof, sig_u, chainid, nonce required' });
    }
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });

    const chainStr = BigInt(chainid).toString();
    if (CHAIN_IDS.length === 0) return res.status(503).json({ error: 'chain id unknown: CIA_CHAIN_IDS not configured and RPC unreachable at startup' });
    if (!CHAIN_IDS.includes(chainStr)) return res.status(400).json({ error: `bad chainid ${chainStr}: allowed ${CHAIN_IDS.join(',')}` });

    const nonceBig = BigInt(nonce);
    if (nonceBig >= SCALAR_MAX) return res.status(400).json({ error: 'nonce must be < 2^250' });
    const nonceStr = nonceBig.toString();
    const used = (state.nonces[uid] ??= []);
    // 서명·증명 검증(~170ms) 앞에 둔다 — 재생 본문이 매번 검증을 태우지 않게.
    if (used.includes(nonceStr)) return res.status(409).json({ error: 'nonce already used' });

    const cpt = pointFromStrings(C_pt);
    // 사용자 인증: 등록된 pk_u 로 (C_pt, chainid, nonce) 에 대한 EdDSA-Poseidon 서명 검증
    let sigOk = false;
    try {
      const m = F.e(await issueRequestMessage(cpt, BigInt(chainStr), nonceBig));
      const sig = { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) };
      const pub = [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))];
      sigOk = eddsa.verifyPoseidon(m, sig, pub);
    } catch { sigOk = false; }
    if (!sigOk) return res.status(400).json({ error: 'bad user signature' });

    // π_issue: 이 C_pt 가 내 uid 의 것이고 s_u 가 등록된 cm_u 와 같다. 속성 슬롯은 검증하지 않는다(설계 §2).
    let proofOk = false;
    try { proofOk = await verifyIssuance({ uid: BigInt(uid), C_pt: cpt, cm_u: pointFromStrings(acct.cm_u), proof: parseProof(proof) }); }
    catch { proofOk = false; }
    if (!proofOk) return res.status(400).json({ error: 'bad issuance proof' });

    const C = await compressPoint(cpt);
    const Cstr = C.toString();
    // 같은 C_pt 재발급 거절 — nonce 와 별개로, 같은 커밋에 서명이 두 번 붙지 않게.
    if (pruneExpired(uid).some((e) => e.C === Cstr)) return res.status(409).json({ error: 'credential already issued for this C_pt' });

    await chainAlive();   // fail-closed: 체인이 죽어 있으면 발급하지 않는다(게시도 불가하므로 폐기가 닿지 않는 credential 이 된다)

    const exptime = nowSec() + BigInt(TTL_SECONDS);
    const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessage(C, exptime, BigInt(chainStr), nonceBig)));
    const leaf = await credLeaf(C);
    // 위 await 들 사이에 /cia/revoke·self_revoke 가 끼어들 수 있다 — 폐기 직후의 발급이 살아남으면 트리에 없는
    // 새 credential 이 TTL 동안 유효하다. 마지막 await 뒤, 기록 직전에 다시 확인한다. 끼어든 revoke 의 pruneExpired 가
    // 목록 배열을 새로 만들었을 수 있어 state.issued[uid] 에 넣는다. nonce 는 성공했을 때만 기록한다 — 실패한 요청의
    // nonce 를 태우면 지갑이 재시도할 때마다 새 nonce 를 써야 하고, 실패 응답을 재생 방지에 쓸 이유도 없다.
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });
    if ((state.nonces[uid] ??= []).includes(nonceStr)) return res.status(409).json({ error: 'nonce already used' });
    (state.issued[uid] ??= []).push({ leaf: leaf.toString(), C: Cstr, exptime: exptime.toString() });
    state.nonces[uid].push(nonceStr);
    persist();
    res.json({
      C: Cstr, exptime: exptime.toString(), chainid: chainStr, nonce: nonceStr,
      sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() },
      pk_CIA: S(ciaPub),
    });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});
```

import 줄에 `SCALAR_MAX` 를 더한다: `import { credMessage, compressPoint, SCALAR_MAX } from './lib/mode3_credential.js';`

`revokeAccount(uid, head)` → `revokeAccount(uid)` 로, 안의 `pruneExpired(uid, head)` → `pruneExpired(uid)`. `/cia/revoke` 에서 `const head = await headHeight();` 줄을 지우고 `revokeAccount(uid)`·`pruneExpired(uid)` 로 바꾼다(credential 분기 포함). `self_revoke` 의 `disabled` 저장 뒤 블록을 아래로 교체한다.

```js
    // disabled 는 인증만 통과하면 즉시 건다(설계 §6.5.1) — 재발급 차단은 트리·게시와 분리된 별개의 효력이다.
    state.accounts[uid].disabled = true;
    persist();
    // 만료 판정이 벽시계라(2026-09-14 설계 §7) 리프 삽입에도 체인이 필요 없다 — 체인이 죽어 있어도 전부 걸린다.
    const out = await revokeAccount(uid);
    res.json({ ...out, disabled: true });
```

`/cia/state` 는 그대로(`headHeight` 사용). 기동 로그의 `ttl=${TTL_BLOCKS}` 를 `ttl=${TTL_SECONDS}s, chains=${CHAIN_IDS.join(',') || 'none'}` 로.

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_cia_register_issue.mjs 2>&1 | grep -E "^(ok|FAIL)"; node tests/test_cia_startup.mjs 2>&1 | grep -E "^(ok|FAIL)"; node tests/test_cia_issue_race.mjs 2>&1 | grep -E "^(ok|FAIL)"`
Expected: 세 파일 모두 전부 `ok`. dead-RPC self_revoke 케이스는 Step 1 의 지시대로 실제 동작에 맞춘 단언과 주석이 들어가 있어야 한다.

- [ ] **Step 5: 기반 설계 §6.5.1 문단 보정**

`docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` 의 문단 `**체인이 닿지 않아도 \`disabled\` 는 걸린다.** …` 전체를 아래로 교체한다.

```
**체인이 닿지 않아도 폐기가 전부 걸린다(2026-09-14 개정).** 만료 판정이 벽시계(`exptime`)가 되면서 계정 폐기가
체인 head 를 읽을 이유가 없어졌다 — 자기 폐기는 인증 직후 `disabled` 를 저장하고 그대로 미만료 리프를 넣는다.
그동안 게시는 체인이 돌아온 뒤에 한다. (그 전 판의 `treeUpdated:false` 부분 성공 응답은 이 개정으로 사라졌다.)
관리자 폐기(`/cia/revoke`)도 같다.
```

- [ ] **Step 6: 커밋 (사용자 승인 후)**

```bash
git add cia.js tests/test_cia_register_issue.mjs tests/test_cia_startup.mjs tests/test_cia_issue_race.mjs docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md
git commit -m "feat(mode3): CIA 가 (C, exptime, chainid, nonce) 에 서명한다 — nonce 영구 집합, chainid 허용 목록, TTL 초, 상태 v2, 폐기가 체인 없이 동작"
```

---

### Task 6: 서버·페이지·격리 테스트 — 지갑 에이전트(attrs·chainid), RP(chainId), 지갑 페이지, e2e·데모 스택

**Files:**
- Modify: `mode3_wallet_agent.js`, `mode3_rp.js`, `mode3/wallet.html`
- Test: `tests/test_mode3_e2e.mjs`, `tests/test_mode3_wallet_agent.mjs`, `tests/test_mode3_demo_stack.mjs` (chain 그룹)

**Interfaces:**
- Consumes: Task 4·5.
- Produces: `POST /wallet/register { uid, pwd, attrs? }`; 지갑 상태 `credentials[arid] = { credential:{C,exptime,chainid,nonce,sigma,pk_CIA}, blind, sessionPrivKey, pk_i, issuedAt }`, `registration.attrs: string[4]`; `GET /wallet/status` 의 credential 항목이 `exptime` 을 보여줌; RP 가 기동 시 `chainId` 를 읽어 검증기에 넘김; `/api/mode3/login` 이 root 를 `publicSignals[5]` 에서 읽음.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_mode3_e2e.mjs`: `createRpVerifier({ …, chainId: 31337n })`; `newSessionAndIssue` 의 `buildIssueRequest` 호출을 `buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n, attrs: ATTRS })` 로, 파일 상단에 `const ATTRS = [19n, 410n, 0n, 0n];` 을 두고 모든 `buildCredentialProof` 호출에 `attrs: ATTRS` 를 더한다. `provider.getBlockNumber()` 를 height 용으로 쓰던 자리는 지운다.

`tests/test_mode3_wallet_agent.mjs`: 검증기 생성에 `chainId: 31337n` 을 더한다. 등록 케이스(`'등록'` 또는 45행 부근)의 본문을 `{ uid, pwd: 'password123', attrs: ['19', '410', '0', '0'] }` 로 바꾸고, 첫 로그인 케이스에 `assert.equal(r.body.publicSignals.length, 8); assert.equal(r.body.publicSignals[4], '31337');` 를 더한다. 새 케이스를 추가한다.

```js
  await t('status: credential 이 exptime(Unix 초)을 보여주고 max_height 는 없다', async () => {
    const s = await wallet.get('/wallet/status');
    const [, c] = Object.entries(s.body.credentials)[0];
    assert.match(String(c.exptime), /^[0-9]+$/);
    assert.equal(c.max_height, undefined);
    assert.ok(Number(c.exptime) > Math.floor(Date.now() / 1000));
  });

  await t('register: attrs 가 4개를 넘거나 10진이 아니면 400', async () => {
    // 이미 등록된 상태에서는 409 가 먼저이므로 형식 검사는 등록 앞에 있어야 한다 — 새 인스턴스 없이 확인하려면
    // 400 이 409 보다 먼저 나오는지를 본다.
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['1', '2', '3', '4', '5'] })).status, 400);
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['x'] })).status, 400);
  });
```

`tests/test_mode3_demo_stack.mjs`: `'1. 등록'` 의 본문에 `attrs: ['19', '410', '0', '0']` 을 더한다. 로그인 검증은 RP 서버가 하므로 다른 변경은 없다.

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_e2e.mjs 2>&1 | grep -E "^(ok|FAIL)" | head; node tests/test_mode3_wallet_agent.mjs 2>&1 | grep -E "^(ok|FAIL)" | head`
Expected: e2e 는 Task 4·5 가 끝났으면 통과할 수도 있다(라이브러리만 쓴다) — 통과하면 그대로 둔다. wallet_agent 는 로그인 케이스 FAIL(에이전트가 옛 요청 형식·`max_height` 를 씀).

- [ ] **Step 3: `mode3_wallet_agent.js` 수정**

- `EXPIRY_MARGIN_BLOCKS = 3n` 을 아래로 교체.

```js
// 만료 여유(초). 지갑은 지금 시각으로 판단하지만 RP 는 증명 생성(~1초)과 두 홉 뒤에 같은 검사를 한다 — 여유 없이
// exptime 직전 credential 을 재사용하면 RP 가 'expired' 로 거절하고 1회용 challenge 만 소모된다. 여유 안이면 미리 새로 발급받는다.
const EXPIRY_MARGIN_SECONDS = 30n;
const nowSec = () => BigInt(Math.floor(Date.now() / 1000));
```

- import 에 `normalizeAttrs` 를 더한다: `import { normalizeAttrs } from './lib/mode3_credential.js';`
- 상태 주석의 `registration` 줄을 `// registration: { uid, s_u, r_u, cm_u:{x,y}, sk_u, attrs:[4개 10진] }   §6.1. 한 번. attrs 는 사용자가 고른 속성(CIA 는 모른다)` 로, `credentials` 줄의 `credential:{C,max_height,…}` 를 `credential:{C,exptime,chainid,nonce,sigma,pk_CIA}` 로.
- chainId 를 한 번 읽어 캐시하는 헬퍼를 `ciaPost` 아래에 둔다.

```js
let chainIdCache = null;
async function chainId() {
  if (chainIdCache === null) chainIdCache = (await provider.getNetwork()).chainId;   // bigint
  return chainIdCache;
}
```

- `issueCredential(arid, height)` 를 교체.

```js
async function issueCredential(arid) {
  const reg = state.registration;
  const session = createSessionKey();
  const req = await buildIssueRequest({
    uid: BigInt(reg.uid), arid: BigInt(arid), s_u: BigInt(reg.s_u), r_u: BigInt(reg.r_u), sk_u: reg.sk_u, session,
    chainid: await chainId(), attrs: (reg.attrs ?? []).map(BigInt),
  });
  const r = await ciaPost('/cia/issue', req.body);
  if (r.status === 200) {
    state.credentials[arid] = {
      credential: r.body, blind: req.secrets.blind.toString(),
      sessionPrivKey: session.wallet.privateKey, pk_i: session.pk_i.toString(),
      issuedAt: new Date().toISOString(),
    };
    persist();
  }
  return r;
}
```

- `/wallet/status` 의 credential 요약을 `credentials[arid] = { exptime: e.credential.exptime, chainid: e.credential.chainid, sessionAddress: …, issuedAt: e.issuedAt };` 로.
- `/wallet/register` 의 형식 검사 뒤(409 검사 앞)에 attrs 검사를 넣고 등록 상태에 저장한다.

```js
    let attrs;
    try { attrs = normalizeAttrs(req.body?.attrs).map(String); }
    catch (e) { return res.status(400).json({ error: `attrs: ${e.message}` }); }
    if (state.registration) return res.status(409).json({ reason: 'already_registered', uid: state.registration.uid });
```

`state.registration = { uid, s_u: …, r_u: …, cm_u: …, sk_u: r.body.sk_u, attrs };`

- `/wallet/login` 의 발급 판단과 재시도를 교체.

```js
    let entry = state.credentials[arid];
    let issued = false;
    const needIssue = !entry
      || nowSec() + EXPIRY_MARGIN_SECONDS > BigInt(entry.credential.exptime)
      || synced.tree.has(await credLeaf(BigInt(entry.credential.C)));
    if (needIssue) {
      t = Date.now();
      const r = await issueCredential(arid);
      timings.issueMs = Date.now() - t;
      if (r.status === 403) return res.status(403).json({ reason: 'account_disabled', timings });
      if (r.status !== 200) return res.status(502).json({ reason: 'issue_failed', cia: r.body, timings });
      entry = state.credentials[arid];
      issued = true;
    }
```

`buildCredentialProof` 호출에 `attrs: (reg.attrs ?? []).map(BigInt),` 를 더한다.

- [ ] **Step 4: `mode3_rp.js`·`mode3/wallet.html` 수정**

`mode3_rp.js`: `const verifier = createRpVerifier(…)` 앞에 아래를 두고 `chainId` 를 넘긴다.

```js
// RP 가 읽는 폐기 체인의 id. credential 의 chainid 와 같아야 한다(설계 2026-09-14 §6 c'). 기동 시 한 번 읽어 고정한다.
const chainId = (await provider.getNetwork()).chainId;
const verifier = createRpVerifier({ provider, logAddress: LOG_ADDRESS, vkey, pkCIA, arid: BigInt(ARID), chainId });
```

`/api/mode3/login` 의 `const root = String(publicSignals[4]);` 를 `publicSignals[5]` 로. `/api/mode3/rp_info` 응답에 `chainId: chainId.toString()` 을 더한다. 기동 로그에 `chain=${chainId}` 를 더한다.

`mode3/wallet.html`: 등록 fieldset 의 `pwd` 입력 뒤에 아래를 넣는다.

```html
    <br />
    <label class="muted">속성(선택, 10진 4개 — CIA 는 값을 모른다. 설계 2026-09-14 §2)</label>
    <input id="attr0" value="19" size="6" title="attr0" />
    <input id="attr1" value="410" size="6" title="attr1" />
    <input id="attr2" value="0" size="6" title="attr2" />
    <input id="attr3" value="0" size="6" title="attr3" />
```

등록 fetch 의 body 를 `JSON.stringify({ uid: $('uid').value.trim(), pwd: $('pwd').value, attrs: ['attr0', 'attr1', 'attr2', 'attr3'].map((id) => $(id).value.trim() || '0') })` 로. 상태 표시의 `max_height=${c.max_height}` 를 `exptime=${c.exptime}(${new Date(Number(c.exptime) * 1000).toLocaleTimeString()})  chainid=${c.chainid}` 로.

- [ ] **Step 5: 통과 확인 + chain 그룹 전체**

Run: `node tests/test_mode3_wallet_agent.mjs 2>&1 | grep -E "^(ok|FAIL)"; node tests/test_mode3_e2e.mjs 2>&1 | grep -E "^(ok|FAIL)"; node tests/test_mode3_demo_stack.mjs 2>&1 | grep -E "^(ok|FAIL)"`
Expected: 전부 `ok`.

Run: `bash scripts/run_tests.sh chain 2>&1 | tail -4`
Expected: `== 통과 12 / 실패 0 ==`

Run: `npm test 2>&1 | tail -3`
Expected: `== 통과 21 / 실패 0 ==` (unit + circuit).

- [ ] **Step 6: 커밋 (사용자 승인 후)**

```bash
git add mode3_wallet_agent.js mode3_rp.js mode3/wallet.html tests/test_mode3_e2e.mjs tests/test_mode3_wallet_agent.mjs tests/test_mode3_demo_stack.mjs
git commit -m "feat(mode3): 지갑 에이전트가 속성·chainid·nonce 로 발급받고 RP 가 chainId 를 고정한다 — 데모 스택 전 구간 새 형식"
```

---

### Task 7: 데모 문서

**Files:**
- Modify: `docs/MODE3_DEMO.md`

**Interfaces:** Task 3(빌드 스크립트), Task 5(env), Task 6(페이지).

- [ ] **Step 1: "처음 한 번" 절에 회로 산출물 단계를 앞에 추가**

`## 처음 한 번: 배포와 \`.env\`` 목록의 1번 앞에 0번을 넣는다.

```markdown
0. `bash scripts/build_mode3_circuit.sh pot21_final.ptau` — `build/mode3/` 의 zkey·vkey·wasm 을 한 세트로 만든다(수 분).
   회로를 바꾼 뒤에는 반드시 다시 돌린다. 다른 기계에 `build/` 를 복사해 뒀다면 그것도 다시 옮긴다.
```

- [ ] **Step 2: env 설명과 각본 갱신**

4번 항목 뒤에 한 줄을 더한다.

```markdown
   선택 env: `CIA_TTL_SECONDS`(credential 만료, 기본 3600), `CIA_CHAIN_IDS`(발급을 허용할 폐기 체인 id 목록, 기본은 RPC 의 chainId).
```

시연 각본 1번 행을 `| 1 | 지갑 | 등록 (\`12345\` / \`password123\`, 속성 4칸은 기본값 그대로) | \`등록됨\` |` 로 바꾸고, 표 아래 문단에 한 문장을 더한다: `속성 4칸은 사용자가 고르는 값이고 CIA 는 보지 못한다(설계 2026-09-14 §2). credential 은 발급 시각 + 1시간에 만료되며, 지갑 상태 페이지에 \`exptime\` 으로 보인다.`

"하지 말 것" 목록에 한 줄을 더한다.

```markdown
- **옛 상태 파일(`version: 1`, `max_height`)을 새 CIA 에 물리지 않는다.** CIA 가 기동을 거부한다 — 재시연 세트로 새로 시작한다.
```

- [ ] **Step 3: 확인**

Run: `grep -n "build_mode3_circuit\|CIA_TTL_SECONDS\|version: 1\|속성 4칸" docs/MODE3_DEMO.md`
Expected: 네 항목이 각각 보인다.

- [ ] **Step 4: 커밋 (사용자 승인 후)**

```bash
git add docs/MODE3_DEMO.md
git commit -m "docs(mode3): 데모 문서에 회로 빌드 스크립트, TTL·chainid env, 속성 입력, 상태 파일 v2 주의"
```

---

## 자체 점검

- **스펙 대응:** §3 커밋·서명·도메인 → Task 1; §4 발급(PoK 9생성원, 사용자 서명 메시지, CIA 검사 순서, nonce 영구, chainid 허용 목록, exptime=now+TTL) → Task 2·5; §5 회로(공개 입력 8, nonce·attrs 비공개) → Task 3; §6 RP(c 벽시계, c' chainid) → Task 4; §7 지갑 여유 30초·CIA 상태 v2·기동 거부·TTL 3600 → Task 5·6; §8-5 산출물 재생성 → Task 3; 문서 → Task 7. 기반 설계 §6.5.1 의 체인 불가 문단 보정 → Task 5 Step 5.
- **이름 일관성:** `credMessage(C, exptime, chainid, nonce)`, `issueRequestMessage(C_pt, chainid, nonce)`, `signUserRequest(sk, C_pt, chainid, nonce)`, `buildIssueRequest({…, chainid, attrs})`, `buildCredentialProof({…, attrs, credential})`, `createRpVerifier({…, chainId})`, credential 필드 `{C, exptime, chainid, nonce, sigma, pk_CIA}`, 공개 입력 인덱스(exptime 3, chainid 4, revRoot 5)가 Task 3·4·5·6 에서 동일.
- **테스트 순서 영향:** Task 5 의 nonce 409 케이스는 `first` 발급이 성공한 뒤 같은 nonce 를 재사용한다 — 뒤 케이스들은 매번 새 nonce 를 뽑으므로 영향 없음. Task 5 dead-RPC 케이스는 구현 결과에 맞춰 두 단언 중 하나를 고르도록 명시했다.
- **미정 항목:** 없음. Task 5 Step 1 의 dead-RPC 단언 선택은 구현 사실에 따라 결정되는 것으로, 두 선택지와 판정 기준을 적어 두었다.
