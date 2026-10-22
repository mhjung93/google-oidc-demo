# Mode 3 IdP 페이지 + 세션 폐기 상한 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** (A) 세션 폐기에 허용 거래 수 c 를 넣어 RCL 리프·회로·계정 컨트랙트가 `nonce < c` 만 통과시키고(즉시 차단용 온체인 상한 포함), (B) 사용자·RP 운영자가 IdP 페이지에서 계정을 만들고 등록하며 RP 로그인 때 IdP 인증 창(uid·비밀번호·auid)을 거치게 한다. Snap 모드 기준, web 모드(`mode3/user`, `mode3_user_static.js`)는 손대지 않는다.

**Architecture:** 폐기 리프 값을 `H'·2^32 + c`(H' = Poseidon(5, Cf_s) 하위 220비트)로 바꾸고 회로 ⑥ 을 구간 비멤버십으로, 공개 입력에 `counter`(34번째)를 더한다. 계정 컨트랙트는 `counter == nonce` 와 세션키별 온체인 상한(`sessionBound`, 자기 호출로만 설정)을 검사한다. IdP 는 계정(가입·비밀번호 해시·세션 쿠키)·1회용 코드(등록/발급)·운영자·RP 슬롯·공개 RP 주소 목록을 갖고, 새 페이지 셋(`/user`·`/rp`·`/login`)을 낸다. 지갑 팝업은 `mode3-register`(IdP 페이지 발) 요청과 발급 전 IdP 인증 창을 처리하며 에이전트는 RP 허용 목록을 IdP 에서 동적으로 받는다.

**Tech Stack:** circom 2 + snarkjs 0.7(Groth16, pot21), Solidity 0.8.24/hardhat, Node 22 ESM(express, express-session, ethers v6, circomlibjs), MetaMask Snap(@metamask/snaps-sdk), Playwright(Chrome), 저장소 테스트 러너 `scripts/run_tests.sh`.

**Spec:** `docs/superpowers/specs/2026-10-22-mode3-revocation-counter-bound-design.md`(A) · `docs/superpowers/specs/2026-10-22-mode3-idp-pages-design.md`(B)

## Global Constraints

- 모든 응답·주석·문구는 한국어(영문 문구는 `strings.js` 의 `en` 칸). 커밋은 사용자 승인 뒤에만(계획의 커밋 단계는 "제안"이며 실행은 컨트롤러가 승인받는다). 푸시·PR 없음.
- 회로 산출물 재생성(`bash scripts/build_mode3_circuit.sh pot21_final.ptau`)은 **사용자 승인 C3** 가 있다 — Task A3 에서만 실행하고, 그 밖의 태스크는 `build/mode3` 를 건드리지 않는다. `npm run zk:*` 는 쓰지 않는다(Mode 1/2 산출물).
- 공개 입력 수 **34**, `PUB_INDEX.COUNTER = 33`, `COUNT = 34`, `LOGIN_COUNTER = 2^32 − 1`(로그인·재검증·세션 요청), 거래는 `counter = payload.nonce`. 폐기 리프 `V = H'·2^32 + c`, `H' = Poseidon(5, Cf_s) mod 2^220`, `c ∈ [0, 2^32)`. 구간 `[lo, hi] = [H'·2^32, H'·2^32 + counter]`.
- `maxRootAge` 는 생존 검사다(최신 root 만 받는다) — 바꾸지 않는다.
- web 모드 파일(`mode3/user/**`, `mode3_user_static.js`, `tests/test_mode3_user_*`)은 **Task A7b(거래 증명 counter 호환) 외에는** 수정하지 않는다. `buildCredentialProof` 의 `counter` 기본값은 LOGIN_COUNTER.
- 민감 파일(`.env`, `cia_state.json`, `cia_keys.json`, `mode3_wallet_state.json`, `mode3_rp_registration*.json`, `idp_state.json`)은 읽지도 커밋하지도 않는다. 새 상태 파일 이름은 `.gitignore` 에 먼저 넣는다.
- 새 의존성 없음(`express-session` 은 이미 `dependencies`).
- Snap 번들은 **Task B6 에서 한 번만** 재빌드한다(A 의 Snap 변경도 거기서).
- 에이전트 모드는 OIDC(Google) 래퍼를 지원하지 않는다 — IdP 인증 창의 Google 버튼은 web 모드 복귀 때 붙인다(이 계획에서 `/login` 은 uid·비밀번호·auid 만).
- 테스트 실행 전제: `chain` 그룹은 :8545 hardhat 노드(없으면 컨트롤러가 `npx hardhat node` 를 띄우고 끝나면 내린다), `browser` 는 Chrome, `snap` 은 `snap-mode3/node_modules`. 라이브·분리 데모 프로세스(:3100/:3101/:4100/:5100/:8082/:8547/:8548)는 건드리지 않는다.

---

## 파일 지도

| 파일 | 책임 | 태스크 |
|---|---|---|
| `lib/mode3_revocation.js` | `sessionLeaf(Cf_s, bound)`, `sessionLeafRange(Cf_s, counter)`, `SESSION_BOUND_MAX` | A1 |
| `lib/imt_v2.js` | `getRangeNonMembershipWitness(lo, hi)` | A1 |
| `circuits/lib/imt_range_nonmembership_v2.circom` (새) | 구간 비멤버십 가젯 | A2 |
| `circuits/pi_cred.circom` | `counter` 공개 입력, ⑥ 구간 비멤버십 | A2 |
| `tests/test_imt_v2_range_circuit.mjs` (새), `tests/test_mode3_artifacts.mjs` | 가젯 테스트, 산출물 공개 입력 34 | A2 |
| `scripts/build_mode3_circuit.sh`, `build/mode3/**`, `contracts/PiCredVerifier.sol` | 빌드(34 검사) | A3 |
| `lib/mode3_onchain.js` | `PUB_INDEX`·`LOGIN_COUNTER`·ABI(34, setSessionBound) | A4 |
| `contracts/Mode3Wallet.sol`, `contracts/test/AcceptAllPiCredVerifier.sol`, `test/Mode3Wallet.test.mjs`, `tests/helpers/mode3_fixture.mjs` | 카운터·온체인 상한 | A4 |
| `lib/mode3_wallet.js`, `lib/mode3_issuance.js`, `lib/mode3_rp.js`, `tests/test_mode3_rp.mjs`, `tests/test_mode3_wallet_lib.js` | 증명 입력 `counter`, 폐기 서명 `bound`, RP `bad_counter` | A5 |
| `cia.js`, `mode3/cia_admin.html`, `tests/test_cia_revoke_bound.mjs` (새) | `/cia/revoke` bound, 관리자 표 bound 열 | A6 |
| `mode3_wallet_agent.js`, `tests/test_mode3_wallet_agent.mjs` | counter·pendingBounds·`/wallet/bounds` | A7 |
| `mode3/user/core/user_core.js` | web 코어 거래 counter=nonce·폐기 bound 자동(호환) | A7b |
| `mode3/wallet.html`, `tests/test_mode3_browser.mjs` | 세션 nonce·상한 입력·체인 반영 대기 | A8 |
| `cia.js`, `tests/test_cia_accounts.mjs` (새), `tests/helpers/isolated_cia.mjs` | 계정·세션·코드·발급 정책 | B1 |
| `cia.js`, `mode3/cia_admin.html`, `mode3_rp.js` | 운영자·RP 슬롯·`rp_key`·`rp_origins` | B2 |
| `mode3/cia_user.html`, `mode3/cia_rp.html`, `mode3/cia_login.html` (새), `mode3/common/strings.js` | IdP 페이지 셋 | B3 |
| `mode3_wallet_agent.js` | 동적 RP 목록, `auth_code`, `/wallet/register {code}` | B4 |
| `mode3/wallet.html`, `tests/test_mode3_browser.mjs` | 제목, auid·salt 복사, 팝업 `mode3-register`, IdP 인증 창 | B5 |
| `snap-mode3/src/index.js`, `snap-mode3/test/rpc.test.mjs`, `tests/helpers/snap_sim.mjs`, `tests/helpers/ethereum_stub.js` | `register({uid})`, `consentRevokeSession({bound})`, 재빌드 | B6 |
| `scripts/new_rp.sh` (새), `.gitignore` | 새 RP 기동 명령 | B7 |
| `mode3/common/strings.js`, `mode3/common/demo.js`, `tests/test_mode3_demo_strings.js`, `tests/test_mode3_tour.mjs` | 체험 모드 단계·페이지 | B8 |
| `scripts/demo_web_reset.sh`, `scripts/demo_split_start.sh`, `docs/MODE3_DEMO.md`, 벤치 `results/` | 리셋·런북·벤치·E2E | B9 |

---

# Part A — 세션 폐기 상한

### Task A1: 폐기 리프 값·구간 증인 (라이브러리)

**Files:**
- Modify: `lib/mode3_revocation.js:20-23` (`sessionLeaf`)
- Modify: `lib/imt_v2.js` (`getNonMembershipWitness` 아래에 `getRangeNonMembershipWitness` 추가)
- Test: `tests/test_mode3_revocation_tree.js`, `tests/test_imt_v2_lib.js`

**Interfaces:**
- Produces: `export const SESSION_BOUND_MAX = 1n << 32n;` `export async function sessionLeaf(Cf_s, bound)` → `bigint` (`V`), `export async function sessionLeafRange(Cf_s, counter)` → `{ lo: bigint, hi: bigint }`, `tree.getRangeNonMembershipWitness(lo, hi)` → `{ lowValue, lowNextIndex, lowNextValue, pathElements, pathIndices, root }`(문자열, 기존 증인과 같은 모양).
- Consumes: `leafValue(tag, raw)`(252비트 마스크), `lowerBound`·`findExact`·`order`·`leaves`·`pathFor`·`ensureLevels`(imt_v2 내부).

- [ ] **Step 1: 실패하는 단위 테스트**

`tests/test_mode3_revocation_tree.js` 끝에 추가(기존 파일의 `t(name, fn)` 패턴 사용):

```js
import { sessionLeaf, sessionLeafRange, SESSION_BOUND_MAX, createRevocationTree, TAG_MODE3_SESSION } from '../lib/mode3_revocation.js';
import { leafValue } from '../lib/imt_v2.js';

await t('sessionLeaf(Cf_s, bound) = (Poseidon(5,Cf_s) mod 2^220)·2^32 + bound, 2^252 미만', async () => {
  const Cf_s = 123456789n;
  const hp = (await leafValue(TAG_MODE3_SESSION, Cf_s)) & ((1n << 220n) - 1n);
  assert.equal(await sessionLeaf(Cf_s, 0n), hp << 32n);
  assert.equal(await sessionLeaf(Cf_s, 7n), (hp << 32n) + 7n);
  assert.ok((await sessionLeaf(Cf_s, SESSION_BOUND_MAX - 1n)) < (1n << 252n));
  await assert.rejects(() => sessionLeaf(Cf_s, SESSION_BOUND_MAX), /bound/);
  await assert.rejects(() => sessionLeaf(Cf_s, -1n), /bound/);
});
await t('sessionLeafRange(Cf_s, counter) = [H′·2^32, H′·2^32 + counter]', async () => {
  const Cf_s = 42n;
  const base = await sessionLeaf(Cf_s, 0n);
  assert.deepEqual(await sessionLeafRange(Cf_s, 0n), { lo: base, hi: base });
  assert.deepEqual(await sessionLeafRange(Cf_s, 5n), { lo: base, hi: base + 5n });
  assert.deepEqual(await sessionLeafRange(Cf_s, SESSION_BOUND_MAX - 1n), { lo: base, hi: base + SESSION_BOUND_MAX - 1n });
});
await t('구간 비멤버십 증인: 상한 c 리프가 있을 때 counter < c 는 증인, counter ≥ c 는 "is a member"', async () => {
  const tree = await createRevocationTree(8);
  const Cf_s = 777n;
  await tree.insert(await sessionLeaf(Cf_s, 3n));            // 허용 거래 수 3 → nonce 0,1,2 만
  for (const k of [0n, 1n, 2n]) { const { lo, hi } = await sessionLeafRange(Cf_s, k); const w = await tree.getRangeNonMembershipWitness(lo, hi); assert.ok(w.pathElements.length === 8); }
  for (const k of [3n, 4n, SESSION_BOUND_MAX - 1n]) { const { lo, hi } = await sessionLeafRange(Cf_s, k); await assert.rejects(() => tree.getRangeNonMembershipWitness(lo, hi), /is a member/); }
  const other = await sessionLeafRange(778n, SESSION_BOUND_MAX - 1n);   // 다른 세션은 영향 없음
  assert.ok(await tree.getRangeNonMembershipWitness(other.lo, other.hi));
});
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_revocation_tree.js` → `sessionLeafRange is not a function` 류로 FAIL.

- [ ] **Step 3: 구현**

`lib/mode3_revocation.js` 의 `sessionLeaf` 를 바꾼다:

```js
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
```

`lib/imt_v2.js` 의 `getNonMembershipWitness` 바로 아래에:

```js
    /**
     * 구간 [lo, hi] 안에 리프가 하나도 없음을 보이는 증인(2026-10-22 세션 폐기 상한). low 리프 = value < lo 인 가장 큰 리프,
     * low.nextValue > hi 또는 0(끝)이어야 한다. 구간 안에 리프가 있으면 getNonMembershipWitness 와 같은 "is a member" 문구로 던진다.
     */
    async getRangeNonMembershipWitness(lo, hi) {
      const l = BigInt(lo) & MASK_252, h = BigInt(hi) & MASK_252;
      if (l > h) throw new Error(`range lo ${l} > hi ${h}`);
      const lowPos = lowerBound(l) - 1;
      if (lowPos < 0) throw new Error(`range lo ${l} must be greater than 0 (the anchor leaf)`);
      ensureLevels();
      const lowIdx = order[lowPos];
      const low = leaves[lowIdx];
      if (low.nextValue !== 0n && low.nextValue <= h) throw new Error(`${low.nextValue} is a member of the revocation set (range [${l}, ${h}])`);
      const { pathElements, pathIndices } = pathFor(lowIdx);
      return { lowValue: low.value.toString(), lowNextIndex: low.nextIndex.toString(), lowNextValue: low.nextValue.toString(), pathElements: pathElements.map(String), pathIndices: pathIndices.map(String), root: levels[depth][0].toString() };
    },
```

(`lowerBound(v)` 는 `value ≥ v` 인 첫 정렬 위치를 돌려주는 기존 내부 함수다 — `getNonMembershipWitness` 가 쓰는 것과 같다. low 의 value 가 l 과 같은 경우는 lowerBound 가 그 위치를 돌려 `-1` 로 그 앞 리프를 고르므로 "value < lo" 가 성립한다.)

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_revocation_tree.js && node tests/test_imt_v2_lib.js` → all ok. 기존 `sessionLeaf(Cf_s)` 한 인자 호출이 남은 곳은 `grep -rn "sessionLeaf(" --include=*.js --include=*.mjs lib cia.js mode3_wallet_agent.js mode3/user/core tests` 로 찾아 A5·A6·A7 에서 고친다(이 태스크에서는 lib 안만).

- [ ] **Step 5: 커밋 제안** — `feat(mode3): 세션 폐기 리프에 허용 거래 수(bound) — H'·2^32+c, 구간 비멤버십 증인`

### Task A2: 회로 — 구간 비멤버십 가젯 + `counter` 공개 입력

**Files:**
- Create: `circuits/lib/imt_range_nonmembership_v2.circom`
- Modify: `circuits/pi_cred.circom:43-48`(증인 입력 그대로), `:81-82`(공개 입력 `counter` 추가), `:145-157`(⑥), `:233-238`(`public [...]`)
- Create: `tests/test_imt_v2_range_circuit.mjs` (하네스는 `tests/test_imt_v2_nonmembership_circuit.mjs:20-70` 을 그대로 복사해 가젯 이름만 바꾼다)
- Modify: `tests/test_mode3_artifacts.mjs`(공개 입력 수 34)

**Interfaces:**
- Produces: `template IMTRangeNonMembershipV2(depth)` 입력 `lo, hi, lowValue, lowNextIndex, lowNextValue, pathElements[depth], pathIndices[depth], root`. `pi_cred` 공개 입력 순서 `…, auid_s, arid_s, r_s, counter`(색인 33).
- Consumes: A1 의 증인 모양(필드 이름 같음).

- [ ] **Step 1: 가젯 테스트(실패)** — `tests/test_imt_v2_range_circuit.mjs`: 하네스 복사(`CIRCUIT_NAME = 'imt_v2_range_only'`, `WRAPPER_SRC` 는 `include "lib/imt_range_nonmembership_v2.circom"; component main {public [root, lo, hi]} = IMTRangeNonMembershipV2(20);`, `stale` 판정의 mtime 비교 파일을 새 가젯으로). 케이스:

```js
// 트리: 값 100·200 삽입. 구간 [101,199] → 통과(low=100, next=200). [100,150] → 실패(100 이 구간 안: low 는 anchor 0 이고 next=100 ≤ hi).
// [150,200] → 실패(next=200 ≤ hi). [201, 2^252−1] → 통과(low=200, next=0 끝). lo>hi 는 JS 증인이 막는다(회로는 hi<lo 면 next>hi 가 더 쉽게 성립하므로 호출자가 보장).
const tree = await createIMTv2(20); await tree.insert(100n); await tree.insert(200n);
const w = (lo, hi) => tree.getRangeNonMembershipWitness(lo, hi).then((x) => ({ ...x, lo: String(lo), hi: String(hi) }));
await accepts(await w(101n, 199n));
await rejects({ ...(await w(101n, 199n)), hi: '200' }, 'hi 를 next 까지 늘리면 실패');
await rejects({ ...(await w(101n, 199n)), lo: '100' }, 'lo 를 low.value 까지 내리면 실패');
await accepts(await w(201n, (1n << 252n) - 1n));
await assert.rejects(() => tree.getRangeNonMembershipWitness(150n, 200n), /is a member/);
```

- [ ] **Step 2: 실패 확인** — `node tests/test_imt_v2_range_circuit.mjs` → circom include 실패로 FAIL.

- [ ] **Step 3: 가젯 구현** — `circuits/lib/imt_range_nonmembership_v2.circom`:

```circom
pragma circom 2.0.0;
include "poseidon.circom";
include "comparators.circom";
include "mux1.circom";
include "bitify.circom";

// 구간 비멤버십(2026-10-22 세션 폐기 상한): [lo, hi] 안에 리프가 없다 ⇔ lowValue < lo 이고 (lowNextValue > hi 또는 lowNextValue == 0).
// 리프 해시·Merkle 경로·252비트 정규화는 imt_nonmembership_v2.circom 과 같다. lo·hi 는 호출자(pi_cred)가 H'·2^32 + counter 로
// 만들어 2^252 미만이 보장되지만 여기서도 범위를 검사한다. lib/imt_v2.js getRangeNonMembershipWitness 와 짝.
template IMTRangeNonMembershipV2(depth) {
    signal input lo;
    signal input hi;
    signal input lowValue;
    signal input lowNextIndex;
    signal input lowNextValue;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input root;

    component leafHash = Poseidon(3);
    leafHash.inputs[0] <== lowValue;
    leafHash.inputs[1] <== lowNextIndex;
    leafHash.inputs[2] <== lowNextValue;

    component h[depth];
    component muxL[depth];
    component muxR[depth];
    signal cur[depth + 1];
    cur[0] <== leafHash.out;
    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;
        muxL[i] = Mux1(); muxL[i].c[0] <== cur[i]; muxL[i].c[1] <== pathElements[i]; muxL[i].s <== pathIndices[i];
        muxR[i] = Mux1(); muxR[i].c[0] <== pathElements[i]; muxR[i].c[1] <== cur[i]; muxR[i].s <== pathIndices[i];
        h[i] = Poseidon(2); h[i].inputs[0] <== muxL[i].out; h[i].inputs[1] <== muxR[i].out;
        cur[i + 1] <== h[i].out;
    }
    root === cur[depth];

    component loRange = Num2Bits(252);  loRange.in <== lo;
    component hiRange = Num2Bits(252);  hiRange.in <== hi;
    component lowRange = Num2Bits(252); lowRange.in <== lowValue;
    component nextRange = Num2Bits(252); nextRange.in <== lowNextValue;

    // lowValue < lo
    component ltLow = LessThan(252);
    ltLow.in[0] <== lowValue; ltLow.in[1] <== lo;
    ltLow.out === 1;

    // hi < lowNextValue, 단 lowNextValue == 0 이면 통과
    component isLast = IsZero();
    isLast.in <== lowNextValue;
    component ltHigh = LessThan(252);
    ltHigh.in[0] <== hi; ltHigh.in[1] <== lowNextValue;
    component pick = Mux1();
    pick.c[0] <== ltHigh.out; pick.c[1] <== 1; pick.s <== isLast.out;
    pick.out === 1;
}
```

- [ ] **Step 4: 가젯 테스트 통과** — `node tests/test_imt_v2_range_circuit.mjs` → OK, 출력된 제약 수를 메모(보고용).

- [ ] **Step 5: pi_cred 수정**

`include "lib/imt_nonmembership_v2.circom";` 아래에 `include "lib/imt_range_nonmembership_v2.circom";`. 공개 입력 블록(`signal input r_s; // V11 [32]` 다음)에:

```circom
    signal input counter;    // 2026-10-22 [33] — 거래는 payload.nonce, 로그인·재검증은 2^32 − 1. 32비트.
```

⑥ 세션 비멤버십 블록을 통째로 바꾼다:

```circom
    // ---- ⑥ 세션 구간 비멤버십 (폐기 트리, 2026-10-22 상한) ----
    // 리프 V = H'·2^32 + c (H' = Poseidon(5, Cf_s) 하위 220비트, c = 허용 거래 수). [H'·2^32, H'·2^32 + counter] 에 리프가 없다
    // ⇔ 상한 c ≤ counter 인 폐기가 없다 ⇔ 이 counter(=nonce) 의 거래가 허용된다. 로그인은 counter = 2^32−1 로 "리프 없음" 을 뜻한다.
    component ctrBits = Num2Bits(32);
    ctrBits.in <== counter;
    component sLeaf = Poseidon(2);
    sLeaf.inputs[0] <== TAG_MODE3_SESSION;
    sLeaf.inputs[1] <== Cf_s;
    component sBits = Num2Bits_strict();
    sBits.in <== sLeaf.out;
    var hp = 0;
    for (var i = 0; i < 220; i++) hp += sBits.out[i] * (1 << i);
    signal sLo;
    sLo <== hp * 4294967296;          // H'·2^32
    signal sHi;
    sHi <== sLo + counter;
    component nmS = IMTRangeNonMembershipV2(depth);
    nmS.lo <== sLo;
    nmS.hi <== sHi;
    nmS.lowValue <== s_lowValue;
    nmS.lowNextIndex <== s_lowNextIndex;
    nmS.lowNextValue <== s_lowNextValue;
    for (var i = 0; i < depth; i++) {
        nmS.pathElements[i] <== s_pathElements[i];
        nmS.pathIndices[i] <== s_pathIndices[i];
    }
    nmS.root <== revRoot;
```

(`(1 << i)` 는 circom 에서 i ≥ 64 에 안전하지 않으므로 `var pow = 1;` 로 누적한다: `for (var i = 0; i < 220; i++) { hp += sBits.out[i] * pow; pow = pow * 2; }`. 이 형태로 쓴다.)

`component main {public [...]}` 끝을 `auid_s, arid_s, r_s, counter` 로. 파일 머리 주석의 `[32] r_s` 뒤에 `[33] counter` 를 적는다.

- [ ] **Step 6: 산출물 테스트 갱신** — `tests/test_mode3_artifacts.mjs` 의 pi_cred 공개 입력 수 기대값 33 → 34(`PUB_INDEX.COUNT` 를 쓰면 A4 뒤 자동). 이 테스트는 A3 빌드 뒤에야 통과한다 — 지금은 실패가 정상임을 보고에 적는다.

- [ ] **Step 7: 컴파일 확인(빌드 아님)** — `circom circuits/pi_cred.circom --r1cs -o /tmp/pi_cred_check -l circuits -l circuits/lib -l node_modules/circomlib/circuits` 가 성공하고 "non-linear constraints" 가 33,909 보다 약 +800 인지 메모. `/tmp/pi_cred_check` 는 지운다.

- [ ] **Step 8: 커밋 제안** — `feat(circuit): pi_cred 공개 입력 counter(34번째)·세션 구간 비멤버십(IMTRangeNonMembershipV2)`

### Task A3: 회로 빌드·검증기 재생성 (사용자 승인 C3 — 컨트롤러가 실행 직전 알린다)

**Files:**
- Modify: `scripts/build_mode3_circuit.sh:45` (`uint\[33\]` → `uint\[34\]`)
- Regenerate: `build/mode3/pi_cred*`, `build/mode3/pi_idp*`, `contracts/PiCredVerifier.sol`, `build/mode3/MANIFEST.sha256`

- [ ] **Step 1:** `sed -i 's/uint\\\\\\[33\\\\\\] calldata _pubSignals/uint\\\\\\[34\\\\\\] calldata _pubSignals/; s/공개 입력이 33개가 아니다/공개 입력이 34개가 아니다/' scripts/build_mode3_circuit.sh` (실제로는 편집기로 그 두 문자열만 바꾼다).
- [ ] **Step 2:** `bash scripts/build_mode3_circuit.sh pot21_final.ptau` (10~30분. 로그를 파일로 받는다. Ethernal 무관.)
- [ ] **Step 3:** `grep -c 'uint\[34\] calldata _pubSignals' contracts/PiCredVerifier.sol` → 1. `npx hardhat compile`.
- [ ] **Step 4:** `bash scripts/pack_mode3_build.sh /tmp/mode3_build_check.tar.gz && rm /tmp/mode3_build_check.tar.gz` (MANIFEST 갱신). `node tests/test_mode3_artifacts.mjs` → OK(34).
- [ ] **Step 5:** `node scripts/bench_pi_cred.mjs pot21_final.ptau` 의 제약 수·증명 시간을 `results/pi_cred_counter_20261022.md` 에 적는다(이전: 33,909 제약 / 지난 측정값은 `results/baselines_20261013.md` 참조).
- [ ] **Step 6: 커밋 제안** — `build(mode3): counter 포함 pi_cred 산출물·PiCredVerifier(34) 재생성`(zkey 등 build/ 는 .gitignore — 커밋은 PiCredVerifier.sol·스크립트·results 만)

### Task A4: 계정 컨트랙트 — `counter == nonce`, 세션키별 온체인 상한

**Files:**
- Modify: `lib/mode3_onchain.js:14-15`(PUB_INDEX), `:33-50`(WALLET_ABI)
- Modify: `contracts/Mode3Wallet.sol`, `contracts/test/AcceptAllPiCredVerifier.sol`(`uint[34]`)
- Modify: `tests/helpers/mode3_fixture.mjs`(`counter` 옵션), `test/Mode3Wallet.test.mjs`

**Interfaces:**
- Produces: `PUB_INDEX.COUNTER = 33`, `PUB_INDEX.COUNT = 34`, `export const LOGIN_COUNTER = (1n << 32n) - 1n;` ABI: `execute(..., uint256[34] pub)`, `function setSessionBound(uint256 pk_i, uint32 bound)`, `function sessionBound(uint256 pk_i) view returns (uint256)`, `event SessionBound(uint256 indexed pk_i, uint256 bound)`, errors `CounterMismatch(uint256 expected, uint256 got)`, `SessionBounded(uint256 pk_i, uint256 bound)`, `BoundNotLowered(uint256 current, uint256 proposed)`, `OnlySelf()`.
- Consumes: A3 의 `PiCredVerifier(uint[34])`.

- [ ] **Step 1: 픽스처에 counter** — `tests/helpers/mode3_fixture.mjs buildValidInput` 옵션에 `counter = LOGIN_COUNTER`(import from `../../lib/mode3_onchain.js`) 를 더하고, 세션 증인을 `tree.getRangeNonMembershipWitness(...(await sessionLeafRange(Cf_s, counter)))` 로, `revokedSessions` 옵션의 리프는 `sessionLeaf(Cf_s, bound)` 로(옵션 모양을 `revokedSessions: [{ Cf_s, bound }]` 로 바꾼다 — 기존 호출처 `grep -rn revokedSessions tests test` 를 함께 고친다). `input.counter = counter.toString()`.

- [ ] **Step 2: 실패하는 컨트랙트 테스트** — `test/Mode3Wallet.test.mjs` 에 추가:

```js
  it('counter 는 로그인 값(2^32−1)이 아니라 nonce 와 같아야 한다 — 다르면 CounterMismatch', async () => {
    const st = withInput(await statement());                       // 기본 counter = LOGIN_COUNTER
    const { wallet } = await deployStack(st);
    const { payload, sig } = await signedPayload(st, wallet);
    await expect(wallet.execute(payload, sig, st.a, st.b, st.c, st.pub)).to.be.revertedWithCustomError(wallet, 'CounterMismatch');
    const st0 = withInput(await statement({ session: st.session, counter: 0n }));
    const ok = await signedPayload(st0, wallet);
    await (await wallet.execute(ok.payload, ok.sig, st0.a, st0.b, st0.c, st0.pub)).wait();
    expect(await wallet.nonce()).to.equal(1n);
  });
  it('setSessionBound 는 자기 호출(execute 경유)로만, 낮추기만; 설정 뒤 그 세션키의 nonce ≥ bound 는 SessionBounded', async () => {
    const s1 = ethers.Wallet.createRandom(), s2 = ethers.Wallet.createRandom();
    const A0 = withInput(await statement({ session: s1, counter: 0n }));
    const { wallet, walletAddr } = await deployStack(A0);
    await expect(wallet.setSessionBound(BigInt(s1.address), 1)).to.be.revertedWithCustomError(wallet, 'OnlySelf');
    // s1 로 nonce 0 실행(허용) → s2 가 자기 호출로 s1 의 상한 1 설정 → s1 의 nonce 2 는 거절, 다른 키(s2) 는 무관
    let p = await signedPayload(A0, wallet); await (await wallet.execute(p.payload, p.sig, A0.a, A0.b, A0.c, A0.pub)).wait();
    const B1 = withInput(await statement({ session: s2, counter: 1n }));
    const data = wallet.interface.encodeFunctionData('setSessionBound', [BigInt(s1.address), 1]);
    p = await signedPayload(B1, wallet, { to: walletAddr, data });
    const rc = await (await wallet.execute(p.payload, p.sig, B1.a, B1.b, B1.c, B1.pub)).wait();
    expect(rc.logs.some((l) => { try { return wallet.interface.parseLog(l)?.name === 'SessionBound'; } catch { return false; } })).to.equal(true);
    expect(await wallet.sessionBound(BigInt(s1.address))).to.equal(2n);   // 저장값 = bound + 1
    const A2 = withInput(await statement({ session: s1, counter: 2n }));
    p = await signedPayload(A2, wallet);
    await expect(wallet.execute(p.payload, p.sig, A2.a, A2.b, A2.c, A2.pub)).to.be.revertedWithCustomError(wallet, 'SessionBounded');
    // 올리기(2) 는 BoundNotLowered, 낮추기(0) 는 된다
    const B2 = withInput(await statement({ session: s2, counter: 2n }));
    p = await signedPayload(B2, wallet, { to: walletAddr, data: wallet.interface.encodeFunctionData('setSessionBound', [BigInt(s1.address), 2]) });
    const rc2 = await (await wallet.execute(p.payload, p.sig, B2.a, B2.b, B2.c, B2.pub)).wait();   // execute 자체는 성공, 내부 호출이 실패(Executed.success=false)
    expect(parseExecuteReceipt(rc2, walletAddr).executed.success).to.equal(false);
    expect(await wallet.sessionBound(BigInt(s1.address))).to.equal(2n);
  });
```

(`statement()` 는 `opts` 를 픽스처로 넘기므로 `counter` 옵션이 그대로 전달된다. `nonce` 는 `signedPayload` 가 체인에서 읽는다 — `counter` 와 같게 케이스를 짠다.)

- [ ] **Step 3: 실패 확인** — `npx hardhat test test/Mode3Wallet.test.mjs` → `CounterMismatch` 없음 등으로 FAIL.

- [ ] **Step 4: 구현**

`lib/mode3_onchain.js`: `PUB_INDEX` 에 `COUNTER: 33`, `COUNT: 34`; `export const LOGIN_COUNTER = (1n << 32n) - 1n;   // 로그인·재검증·세션 요청의 counter — "이 세션의 폐기 리프가 하나도 없다"`; `WALLET_ABI` 의 `uint256[33] pub` → `uint256[34] pub`, 그리고 추가:

```js
  'function setSessionBound(uint256 pk_i, uint32 bound)',
  'function sessionBound(uint256 pk_i) view returns (uint256)',
  'event SessionBound(uint256 indexed pk_i, uint256 bound)',
  'error CounterMismatch(uint256 expected, uint256 got)',
  'error SessionBounded(uint256 pk_i, uint256 bound)',
  'error BoundNotLowered(uint256 current, uint256 proposed)',
  'error OnlySelf()',
```

`proofToCalldata`·`decodeExecuteCalldata`·`statementDigestFields` 가 `33`/`PUB_INDEX.COUNT` 를 하드코딩한 곳은 `grep -n "33" lib/mode3_onchain.js` 로 찾아 `PUB_INDEX.COUNT` 로.

`contracts/Mode3Wallet.sol`:

```solidity
    /// @notice 세션키별 온체인 상한(2026-10-22 설계 §6.5): 저장값 = 허용 거래 수 c + 1 (0 = 없음). nonce < c 만 통과.
    mapping(uint256 => uint256) public sessionBound;
    event SessionBound(uint256 indexed pk_i, uint256 bound);
    error CounterMismatch(uint256 expected, uint256 got);
    error SessionBounded(uint256 pk_i, uint256 bound);
    error BoundNotLowered(uint256 current, uint256 proposed);
    error OnlySelf();

    /// @notice 자기 호출(execute 의 payload.to == address(this))로만 — 다른 세션(S2)의 π 가 계정 소유를 증명한다. 낮추기만 된다.
    function setSessionBound(uint256 pk_i, uint32 bound) external {
        if (msg.sender != address(this)) revert OnlySelf();
        uint256 cur = sessionBound[pk_i];
        if (cur != 0 && uint256(bound) + 1 >= cur) revert BoundNotLowered(cur - 1, bound);
        sessionBound[pk_i] = uint256(bound) + 1;
        emit SessionBound(pk_i, bound);
    }
```

`execute` 서명을 `uint[34] calldata pub` 로, `payload.nonce != nonce` 검사 바로 뒤에:

```solidity
        if (pub[33] != payload.nonce) revert CounterMismatch(payload.nonce, pub[33]);   // 2026-10-22: π 의 구간 [H'·2^32, +counter] 가 이 nonce 의 것이어야 한다
        uint256 b = sessionBound[pub[2]];
        if (b != 0 && payload.nonce + 1 >= b) revert SessionBounded(pub[2], b - 1);     // 온체인 상한(즉시 차단) — nonce < c 만
```

`_checkStatement(uint[33] …)` → `uint[34]`. 꼬리 15워드·다이제스트는 그대로(색인 15~29). 주석의 "33개" → "34개 … [33] counter". `contracts/test/AcceptAllPiCredVerifier.sol` 의 `uint[33]` → `uint[34]`.

- [ ] **Step 5: 통과 확인** — `npx hardhat test test/Mode3Wallet.test.mjs` 전체 PASS(기존 케이스는 픽스처 기본 `counter = LOGIN_COUNTER` 라 `CounterMismatch` 로 깨진다 — 기존 케이스의 `statement()` 호출에 `counter: 0n`(첫 실행)·`counter: 1n`(두 번째) 등 nonce 와 같은 값을 넣어 고친다. "같은 π 로 두 번째 트랜잭션" 케이스는 이제 **같은 π 를 재사용할 수 없다**(counter 가 다르다) — 케이스 제목·내용을 "같은 세션키의 다른 nonce 성명 두 개" 로 바꾼다.)

- [ ] **Step 6: 커밋 제안** — `feat(contracts): Mode3Wallet counter==nonce 검사·세션키별 온체인 상한(setSessionBound)`

### Task A5: 증명 입력 `counter`·폐기 서명 `bound`·RP `bad_counter`

**Files:**
- Modify: `lib/mode3_wallet.js:85-89`(signRevokeSession), `buildCredentialProof`
- Modify: `lib/mode3_issuance.js:66-70`(revokeSessionMessage)
- Modify: `lib/mode3_rp.js:62-63, 76-78`(verifyLogin)
- Test: `tests/test_mode3_rp.mjs`, `tests/test_mode3_wallet_lib.js`

**Interfaces:**
- Produces: `buildCredentialProof({ …, counter = LOGIN_COUNTER })`; `signRevokeSession(sk_uHex, uid, Cf_s, bound, nonce)`; `revokeSessionMessage(uid, Cf_s, bound, nonce)`; `verifyLogin` 은 `publicSignals.length === 34` 와 `counter === LOGIN_COUNTER`(아니면 `{ ok:false, reason:'bad_counter' }`).

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_rp.mjs` 의 `makeLogin` 이 `buildCredentialProof` 를 쓰므로 옵션 `counter` 를 통과시키게 하고 케이스 추가:

```js
await t('음성(2026-10-22): counter 가 LOGIN_COUNTER 가 아닌 π(거래용 counter=0)는 bad_counter', async () => {
  const L = await makeLogin({ counter: 0n });
  const r = await rp.verifyLogin(L);
  assert.equal(r.ok, false); assert.equal(r.reason, 'bad_counter');
});
await t('공개 입력이 34개가 아니면 malformed', async () => {
  const L = await makeLogin(); L.publicSignals = L.publicSignals.slice(0, 33);
  assert.equal((await rp.verifyLogin(L)).reason, 'malformed');
});
```

`tests/test_mode3_wallet_lib.js` 에: `signRevokeSession(sk, uid, Cf_s, 3n, nonce)` 가 `revokeSessionMessage(uid, Cf_s, 3n, nonce)` 로 검증되고, `bound` 가 다르면(2n) 검증 실패.

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_rp.mjs` → FAIL(bad_counter 없음).

- [ ] **Step 3: 구현**

`lib/mode3_issuance.js`:
```js
/** 세션 폐기 요청의 사용자 서명 메시지 = Poseidon(D_REVOKESESS, uid, Cf_s, bound, nonce) — 2026-10-22: 허용 거래 수 bound 가 서명에 든다(옛 3인자 서명과 호환되지 않음). */
export async function revokeSessionMessage(uid, Cf_s, bound, nonce) {
  if (typeof bound !== 'bigint' || bound < 0n || bound >= (1n << 32n)) throw new Error('revokeSessionMessage: bound 는 [0, 2^32) bigint');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_REVOKESESS, uid, Cf_s, bound, nonce]));
}
```
`lib/mode3_wallet.js`: `signRevokeSession(sk_uHex, uid, Cf_s, bound, nonce)` 가 그 메시지를 서명. `buildCredentialProof` 의 인자에 `counter = LOGIN_COUNTER` 를 더하고(import `LOGIN_COUNTER` from `./mode3_onchain.js`, `sessionLeafRange` from `./mode3_revocation.js`), 세션 증인을
```js
  if (typeof counter !== 'bigint' || counter < 0n || counter >= (1n << 32n)) throw new Error('buildCredentialProof: counter 는 [0, 2^32) bigint');
  const { lo, hi } = await sessionLeafRange(BigInt(credential.Cf_s), counter);
  const ws = await tree.getRangeNonMembershipWitness(lo, hi);   // 구간 안에 리프가 있으면 "is a member" 로 던진다(폐기됨)
```
로, `input` 에 `counter: counter.toString()`. `lib/mode3_rp.js verifyLogin`: 길이 34, 구조분해에 `const counter = rest[17];` 추가, `if (rsIn !== r_s)` 검사 뒤에 `if (counter !== LOGIN_COUNTER) return { ok: false, reason: 'bad_counter' };`(import `LOGIN_COUNTER`).

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_rp.mjs && node tests/test_mode3_wallet_lib.js && node tests/test_mode3_rp_cert.js`. `grep -rn "sessionLeaf(" lib tests` 에서 한 인자 호출이 남은 테스트(`tests/test_cia_register_issue.mjs:11` 등)는 A6 에서 고친다.

- [ ] **Step 5: 커밋 제안** — `feat(lib): π_RP counter 입력·구간 증인, 폐기 서명에 bound, RP bad_counter`

### Task A6: IdP — 폐기 요청에 `bound`, 관리자 표

**Files:**
- Modify: `cia.js`(`/cia/revoke` scope=session 블록: 서명·리프·레코드), `/cia/admin/sessions`(응답에 `bound`), `/cia/admin/revoked_sessions`
- Modify: `mode3/cia_admin.html:313-337`(bound 열·관리자 폐기 상한 입력), `mode3/common/strings.js`(`admin_col_bound`, `admin_revoke_bound_prompt`)
- Create: `tests/test_cia_revoke_bound.mjs`; Modify: `tests/test_cia_register_issue.mjs`(`sessionLeaf` 두 인자·`signRevokeSession` 5인자), `scripts/run_tests.sh`(CHAIN 에 새 파일)

**Interfaces:**
- Produces: `POST /cia/revoke { uid, scope:'session', Cf_s, bound, nonce, sig_u }`(관리자 헤더면 `sig_u`·`nonce` 없이 `bound` 만, 기본 0) → `{ inserted, leaf, bound, root, pending }`. 세션 레코드 `bound` 필드. `/cia/admin/sessions` 항목에 `bound`.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_cia_revoke_bound.mjs`(`startIsolatedCia` + 기존 `test_cia_register_issue.mjs` 의 등록·발급 헬퍼를 복사: 등록 → 세션 발급 → Cf_s 확보):

```js
await t('세션 폐기(bound): 서명이 bound 를 덮고, 리프 = sessionLeaf(Cf_s, bound), 레코드·관리자 목록에 bound', async () => {
  const bound = 3n, nonce = randomScalar();
  const sig_u = await signRevokeSession(user.sk_u, BigInt(user.uid), BigInt(Cf_s), bound, nonce);
  const r = await cia.post('/cia/revoke', { uid: user.uid, scope: 'session', Cf_s, bound: bound.toString(), nonce: nonce.toString(), sig_u });
  assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.inserted, true); assert.equal(r.body.bound, '3');
  assert.equal(r.body.leaf, (await sessionLeaf(BigInt(Cf_s), bound)).toString());
  const list = (await cia.adminGet(`/cia/admin/sessions?uid=${user.uid}`)).body.sessions;
  assert.equal(list.find((s) => s.Cf_s === Cf_s).bound, '3');
});
await t('bound 가 없거나 범위 밖(2^32)이면 400; 서명의 bound 와 본문 bound 가 다르면 400 bad user signature', async () => { /* 세 요청 */ });
await t('관리자 폐기는 bound 기본 0(전부 차단), bound 를 주면 그 값', async () => { /* adminPost 두 번(다른 세션) */ });
```

- [ ] **Step 2: 실패 확인** — `node tests/test_cia_revoke_bound.mjs`.

- [ ] **Step 3: 구현** — `cia.js /cia/revoke`: 본문 `bound` 를 `scope === 'session'` 에서 읽는다 — 관리자면 `bound ?? '0'`, 아니면 필수. `if (!isDec(bound) || BigInt(bound) >= SESSION_BOUND_MAX) return 400 { error: 'bound 는 [0, 2^32)' }`. 서명 메시지 `revokeSessionMessage(uid, Cf_s, BigInt(bound), nonce)`. `const leaf = (await sessionLeaf(BigInt(Cf_s), BigInt(bound))).toString();` `cur.revokedAt = …; cur.bound = BigInt(bound).toString();` 응답에 `bound`. 이미 폐기된 세션의 재폐기: `bound` 가 기존보다 작으면 새 리프를 넣는다(낮추기), 아니면 `{ inserted:false, bound: 기존 }`. `/cia/admin/sessions`·`/cia/admin/revoked_sessions` 응답은 `...s` 스프레드라 `bound` 가 따라온다. 관리자 페이지: `renderSessions` 표에 `['admin_col_bound', true]` 열(`s.bound ?? '-'`), 관리자 폐기 버튼은 `window.prompt(Demo.t('admin_revoke_bound_prompt'), '0')` 로 bound 를 받아 본문에 싣는다. 문구 `admin_col_bound: { ko: '허용 거래 수', en: 'Allowed txs' }`, `admin_revoke_bound_prompt: { ko: '허용 거래 수 c (nonce < c 만 유효, 0 = 전부 차단)', en: 'Allowed tx count c (only nonce < c stays valid; 0 = block all)' }`.

- [ ] **Step 4: 통과 확인** — `node tests/test_cia_revoke_bound.mjs && node tests/test_cia_register_issue.mjs && node tests/test_cia_registry.mjs`(기존 폐기 케이스의 서명 호출을 5인자로 고친다).

- [ ] **Step 5: 커밋 제안** — `feat(cia): 세션 폐기 요청의 허용 거래 수(bound) — 서명·리프·관리자 표`

### Task A7: 지갑 에이전트 — counter·체인 반영 대기·`/wallet/bounds`

**Files:**
- Modify: `mode3_wallet_agent.js`: `proveSession`(783-), `buildExecute`(prepareTx 순서), `/wallet/login`·`/wallet/revalidate`·`/wallet/request`(LOGIN_COUNTER), `/wallet/session/revoke`(bound), `/wallet/status`(세션 `nonce`·`pendingBounds`), 새 `/wallet/bounds/apply`, `/wallet/tx/record`(대기 항목 정리), 상태 버전 10(`pendingBounds: []`)
- Test: `tests/test_mode3_wallet_agent.mjs`

**Interfaces:**
- Produces: `POST /wallet/session/revoke { r_s, bound? }` → `{ revoked, inserted, pending, bound, pendingBoundId }`(bound 기본 = 계정 nonce; 팩토리 없으면 0). `GET /wallet/status` 의 `sessions[r_s].nonce`(문자열, 미배포 0, 못 읽으면 null)와 `pendingBounds: [{ id, account, chainid, arid, pk_i, bound, revokedAt, applicableSession: r_s|null }]`. `POST /wallet/bounds/apply { id, r_s }` → file 모드: 전송 결과(`/wallet/tx` 와 같은 모양 + `applied:true`), snap 모드: `/wallet/tx/prepare` 와 같은 모양 + `pendingBoundId`. `/wallet/tx/record` 가 setSessionBound 셀렉터 거래를 보면 그 대기 항목을 지운다.
- Consumes: A4·A5.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_wallet_agent.mjs` 끝(`'V8 세션 폐기'` 케이스 뒤)에:

```js
  await t('폐기 상한(2026-10-22): nonce 0·1 실행 → bound 3 폐기·게시 → nonce 2 성공, nonce 3 은 revoked_session, 재검증은 revoked_session', async () => {
    const a = await loginOnce();                                             // 팩토리 있는 세션(기존 tx 케이스와 같은 loginOnce 옵션)
    for (const _ of [0, 1]) assert.equal((await wallet.post('/wallet/tx', { r_s: a.r_s, to: ethers.ZeroAddress, value: '0' })).status, 200);
    const r = await wallet.post('/wallet/session/revoke', { r_s: a.r_s, bound: '3' });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.bound, '3'); assert.ok(r.body.pendingBoundId);
    await publishOnce();
    // 지갑은 폐기한 세션을 버렸으므로, 같은 세션키로 "공격자" 가 보내는 상황은 리프 기준으로 직접 확인한다:
    const st = (await wallet.get('/wallet/status')).body;
    assert.ok(st.pendingBounds.some((p) => p.id === r.body.pendingBoundId && p.bound === '3' && p.applicableSession === null));
    // 같은 계정의 새 세션으로 "지금 반영" → setSessionBound 거래 → 영수증 SessionBound 이벤트
    const b = await loginOnce();
    const ap = await wallet.post('/wallet/bounds/apply', { id: r.body.pendingBoundId, r_s: b.r_s });
    assert.equal(ap.status, 200, j(ap.body)); assert.equal(ap.body.applied, true);
    assert.equal((await wallet.get('/wallet/status')).body.pendingBounds.length, 0);
    const acct = walletAt(ap.body.wallet, provider);
    assert.equal(await acct.sessionBound(BigInt(a.sessionAddress)), 4n);   // 저장값 = 3 + 1 (a.sessionAddress 는 loginOnce 가 돌려주는 세션 주소)
  });
```

(`loginOnce`·`publishOnce`·`walletAt`·`provider` 는 이 테스트 파일에 이미 있다. 폐기한 세션으로 `nonce 3` 를 내 보는 직접 시험은 지갑이 세션을 버리므로 에이전트 API 로는 못 한다 — 컨트랙트 테스트(A4)가 `SessionBounded`, lib 테스트(A1)가 "is a member" 를 각각 보인다.)

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_wallet_agent.mjs`(:8545 필요).

- [ ] **Step 3: 구현**

1. 상태: `WALLET_STATE_VERSION = 10`; 마이그레이션 블록이 `pendingBounds` 를 비우고, 기동 뒤 `state.pendingBounds ??= [];`.
2. `proveSession(rsKey, synced, timings, disclosure = null, src, counter = LOGIN_COUNTER)`: 캐시 키 `discKey` 를 `counter === LOGIN_COUNTER ? discKey : `${discKey}#n${counter}`` 로; `buildCredentialProof({ …, counter })`; 사전 확인 `synced.canonical.tree.has(await sessionLeaf(...))` 는 구간 확인으로: `const { lo, hi } = await sessionLeafRange(Cf_s, counter); try { await synced.canonical.tree.getRangeNonMembershipWitness(lo, hi); } catch { throw revoked_session }`.
3. `buildExecute`: `walletAddr`·`deployNeeded`·`nonce` 계산을 `proveSession` **앞**으로 옮기고 `proveSession(rsKey, synced, timings, disclosure, src, nonce)` 로 부른다(`nonce` 는 bigint).
4. `/wallet/session/revoke`: `bound` 본문(선택). 없으면 계산: `s.factoryAddress` 가 있으면 `account = computeAddress(PPID)`, 코드가 있으면 `nonce()`, 아니면 `0n`; `bound = BigInt(bodyBound ?? nonce)`. 범위 검사. `signRevokeSession(sk_u, uid, Cf_s, bound, nonce)`; IdP 본문에 `bound: bound.toString()`. 성공 뒤 `state.pendingBounds.push({ id: randomScalar().toString().slice(0, 16), account: account ?? null, chainid: s.credential.chainid, arid: s.arid, pk_i: s.pk_i, bound: bound.toString(), revokedAt: new Date().toISOString() })`(account 가 없으면 체인 상한을 올릴 곳이 없다 — 항목을 넣지 않는다). 응답에 `bound`, `pendingBoundId`.
5. `/wallet/status`: 세션마다 `nonce`(`account` 가 있고 코드가 있으면 `walletAt(account).nonce()` 문자열, 미배포 `'0'`, 실패 null); `pendingBounds` 는 각 항목에 `applicableSession`: `Object.entries(state.sessions).find(([, e]) => e.factoryAddress && e.PPID === … )` — 같은 `account`(= 같은 PPID·팩토리) 를 가진 살아 있는 세션의 `r_s` 또는 null.
6. `/wallet/bounds/apply { id, r_s }`: 항목·세션 확인(세션의 account 가 항목의 account 와 같아야 409 `bound_wrong_account`). `data = walletInterface.encodeFunctionData('setSessionBound', [BigInt(p.pk_i), Number(p.bound)])`; `const b = await buildExecute({ body: { r_s, to: p.account, value: '0', data } })`; file 모드: `/wallet/tx` 와 같이 전송하고 영수증에서 `SessionBound` 이벤트(`walletInterface.parseLog`)가 있으면 항목 삭제·persist → 응답 `{ ...receiptResult(...), applied: true, wallet: walletAddr }`; snap 모드: `/wallet/tx/prepare` 응답 모양 + `pendingBoundId: p.id`.
7. `/wallet/tx/record`: 영수증 로그에 `SessionBound(pk_i, bound)` 가 있으면 `state.pendingBounds` 에서 같은 `pk_i`·`bound` 항목을 지운다.
8. `/wallet/login`·`/wallet/revalidate`·`/wallet/request` 의 `proveSession` 호출은 기본값(LOGIN_COUNTER).

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_wallet_agent.mjs`(전체), `node tests/test_mode3_rp_relay.mjs`(web 릴레이는 그대로), `node tests/test_mode3_demo_stack.mjs`(큰 묶음 — 깨지는 케이스는 `sessionLeaf`·서명 인자 변경에 맞춰 고친다).

- [ ] **Step 5: 커밋 제안** — `feat(agent): 거래 π counter=nonce, 폐기 bound·체인 반영 대기(pendingBounds)·/wallet/bounds/apply`

### Task A7b: web 모드 코어 — 거래 증명의 counter = nonce (호환 유지, 사용자 결정 2026-10-23)

**Files:**
- Modify: `mode3/user/core/user_core.js`(`proveSession`, `prepareTx`)
- Test: `tests/test_mode3_user_core.mjs`(기존 거래 케이스가 그대로 통과해야 한다), `tests/test_mode3_user_web.mjs`·`tests/test_mode3_rp_relay.mjs`(변경 없음 — 통과 확인만)

**Interfaces:**
- Consumes: A5 의 `buildCredentialProof({ …, counter })`·`LOGIN_COUNTER`.
- Produces: web 코어의 `proveSession(rsKey, synced, timings, disclosure, src, counter = LOGIN_COUNTER)`; `prepareTx` 는 계정 주소·배포 여부·nonce 를 **증명 전에** 읽고 `counter = nonce` 로 증명한다(에이전트 A7 과 같은 순서). 캐시 키는 `counter === LOGIN_COUNTER ? discKey : `${discKey}#n${counter}``. 그 밖의 web 모드 동작(폐기 bound 입력·체인 반영 대기)은 이번 범위 밖 — web 코어의 `revokeSession` 은 `bound` 를 **현재 nonce**(팩토리·계정이 있으면 체인에서, 없으면 0)로 자동으로 넣어 IdP 의 새 서명 형식을 만족시킨다(UI 없음).

- [ ] **Step 1: 실패 확인** — A5 뒤 `node tests/test_mode3_user_core.mjs` 의 거래 케이스(`A5`·claim)가 `CounterMismatch`/`execute_reverted` 로 FAIL, 폐기 케이스가 IdP 400(bound 없음)으로 FAIL.
- [ ] **Step 2: 구현** — `user_core.js` 의 `proveSession` 시그니처에 `counter = LOGIN_COUNTER`, 캐시 키·`buildCredentialProof` 호출에 `counter` 전달. `prepareTx`: `walletAddr`·`deployNeeded`·`nonce` 계산 블록을 `proveSession` 호출 앞으로 옮기고 `proveSession(rsKey, synced, timings, disclosure, src, nonce)`. `revokeSession`: 세션 `s.factoryAddress` 가 있으면 `account = factory.computeAddress(PPID)`, 코드가 있으면 `nonce()`, 아니면 `0n` → `signRevokeSession(sk_u, uid, Cf_s, bound, nonce)`·IdP 본문 `bound`. web 모드 거래 증명은 nonce 마다 새로 만든다(캐시 미스) — 동작 변화는 그뿐이다.
- [ ] **Step 3: 통과 확인** — `node tests/test_mode3_user_core.mjs`, `node tests/test_mode3_user_web.mjs`, `node tests/test_mode3_rp_relay.mjs`.
- [ ] **Step 4: 커밋 제안** — `fix(user-core): 거래 증명 counter=nonce·폐기 bound 자동(회로 변경 호환)`

### Task A8: 지갑 페이지 — nonce 표시·상한 입력·체인 반영 대기 카드

**Files:**
- Modify: `mode3/wallet.html`(세션 카드 `renderSessions`, `revokeSession`, 새 카드 `#boundsCard`), `mode3/common/strings.js`
- Test: `tests/test_mode3_browser.mjs`

- [ ] **Step 1: 실패하는 브라우저 테스트** — 기존 `'V8 세션 폐기'` 류 케이스 뒤에:

```js
  await t('폐기 상한(2026-10-22): 세션 카드에 nonce, 폐기 때 허용 수 입력 → Snap 동의 창에 "허용 거래 수" → 체인 반영 대기 행 → 재로그인 뒤 "지금 반영" → 행 사라짐', async () => {
    await walletPage.click('#refreshBtn');
    await walletPage.waitForFunction(() => /nonce\s*\d+/.test(document.querySelector('#sessionActions')?.textContent ?? ''), undefined, { timeout: 15_000 });
    await walletPage.fill('#sessionActions input.bound', '1');
    answers.push(true);                                                   // consentRevokeSession
    walletPage.once('dialog', (d) => d.accept());                         // confirm_revoke
    await walletPage.click('#sessionActions button.danger');
    await waitText(walletPage, '#sessionVerdict', '폐기 요청 접수');
    assert.ok(dialogs.at(-1).content.children.some((c) => /허용 거래 수: 1/.test(c.value ?? '')), '동의 창에 상한');
    await waitText(walletPage, '#boundsList', '반영 대기', 10_000);
    // 다시 로그인(같은 RP) → 지금 반영 → MetaMask 스텁이 보낸다 → 행 사라짐
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]); answers.push(true); await popup.waitForEvent('close');
    await walletPage.click('#boundsList button.apply');
    await walletPage.waitForFunction(() => !/반영 대기/.test(document.querySelector('#boundsList')?.textContent ?? ''), undefined, { timeout: 60_000 });
  });
```

(`dialogs`/`answers`/`idpLogin`/`rpPage`/`walletPage`/`waitText` 는 이 파일의 하네스 변수. 이 케이스는 **B6(Snap 동의 창에 상한 표시) 뒤에야** 통과한다 — 컨트롤러는 A8 을 B6 뒤에 검증한다.)

- [ ] **Step 2: 구현**

`renderSessions`: 세션 `dl` 에 `kvRow(dl, tt('wallet_session_nonce') || 'nonce', String(c.nonce ?? '-'))`; 폐기 버튼 앞에 `<input type="number" class="bound" min="0" value="${c.nonce ?? 0}">`(라벨 `wallet_bound_label` "허용 거래 수"). `revokeSession(r_s, c, btn)`: `const bound = box.querySelector('input.bound').value.trim() || '0';` Snap 동의에 `bound` 를 넘기고(`invokeSnap('consentRevokeSession', { …, bound })`), `postJson('/wallet/session/revoke', { r_s, bound })`. 결과 문구에 `bound`.

새 카드(세션 카드 아래):
```html
    <section class="card" id="boundsCard">
      <h3 data-i18n="wallet_bounds_title">체인 반영 대기</h3>
      <p class="desc" data-i18n="wallet_bounds_desc">폐기한 세션의 허용 거래 수를 응용 체인의 계정에도 올립니다(즉시 차단). 같은 RP 에 다시 로그인하면 반영할 수 있습니다.</p>
      <div id="boundsList"></div>
      <div id="boundsVerdict"></div>
    </section>
```
`renderBounds()`(status 의 `pendingBounds`): 항목마다 `account 앞자리 · pk_i 앞자리 · 허용 수 c · 반영 대기`, `applicableSession` 이 있으면 `<button class="apply">지금 반영</button>`(없으면 muted 문구 `wallet_bounds_need_login`). 클릭 → `postJson('/wallet/bounds/apply', { id, r_s })` → snap 모드면 응답의 `calldata`·`walletAddr`·`deployCalldata` 를 **txBtn 핸들러가 쓰는 MetaMask 전송 함수**로 보낸다(그 코드를 `async function submitPrepared(prep, rsKey)` 로 추출해 둘 다 쓴다) → 영수증 뒤 `/wallet/tx/record` 호출(기존 흐름) → `refresh()`. 문구: `wallet_session_nonce`, `wallet_bound_label`, `wallet_bounds_title`, `wallet_bounds_desc`, `wallet_bounds_pending`("반영 대기"), `wallet_bounds_apply`("지금 반영"), `wallet_bounds_need_login`, `wallet_bounds_applied`.

- [ ] **Step 3: 검증** — B6 뒤 `node tests/test_mode3_browser.mjs`.
- [ ] **Step 4: 커밋 제안** — `feat(wallet-page): 세션 nonce·폐기 허용 수 입력·체인 반영 대기 카드`

---

# Part B — IdP 페이지

### Task B1: IdP 계정·세션·1회용 코드·발급 정책

**Files:**
- Modify: `cia.js`(상수 블록 `:60-70` 근처, `/cia/register:555-580`, `/cia/issue` 데모 계정 분기, 상태 `defaultState()`·기동 시드, 새 라우트)
- Modify: `tests/helpers/isolated_cia.mjs`(`CIA_DEMO_ACCOUNTS: '1'`, `CIA_ISSUE_AUTH: ''`), `scripts/run_tests.sh`(CHAIN 에 `tests/test_cia_accounts.mjs`)
- Create: `tests/test_cia_accounts.mjs`

**Interfaces:**
- Produces(스펙 B §3.3): `POST /cia/signup {pwd}`→201`{uid}`; `POST /cia/user/login {uid,pwd}`; `POST /cia/user/logout`; `GET /cia/user/me`; `POST /cia/user/register_code`→`{code, expiresAt}`; `POST /cia/auth/code {uid,pwd,auid}`→`{code, expiresAt}`(403 `auid_mismatch`, 401 `invalid credentials`, 409 `not_registered`); `/cia/register` 의 `{uid, code}` 경로(401 `bad_code`); `/cia/issue` 의 `auth_code`(정책 `CIA_ISSUE_AUTH=code` 일 때 demo 계정 필수 — 401 `auth_code_required`·`bad_code`). 계정 필드 `pwSalt`·`pwHash`·`createdAt`, 상태 `nextUid`(시작 100001), `codes: {}`.
- 내부: `hashPw(salt, pwd) = sha256(salt + pwd) hex`, `issueCode({uid, purpose, auid})`, `consumeCode(code, {uid, purpose, auid})`.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_cia_accounts.mjs`(`startIsolatedCia({ env: { CIA_ISSUE_AUTH: 'code' } })` 와 `startIsolatedCia({ env: { CIA_DEMO_ACCOUNTS: '' } })` 둘):

```js
// 쿠키 세션: fetch 가 쿠키를 자동으로 보내지 않으므로 Set-Cookie 를 잡아 Cookie 헤더로 되돌리는 jar 를 둔다.
const jar = {}; const withJar = async (p, init = {}) => { const r = await fetch(`${cia.base}${p}`, { ...init, headers: { 'Content-Type': 'application/json', ...(jar.cookie ? { Cookie: jar.cookie } : {}), ...(init.headers ?? {}) } }); const sc = r.headers.get('set-cookie'); if (sc) jar.cookie = sc.split(';')[0]; return { status: r.status, body: await r.json().catch(() => null) }; };
await t('signup: pwd 8자 이상, uid 는 100001 부터 배정, 계정은 등록 전 상태', async () => {
  assert.equal((await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'short' }) })).status, 400);
  const a = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'password-1' }) }); assert.equal(a.status, 201); assert.equal(a.body.uid, '100001');
  const b = await withJar('/cia/signup', { method: 'POST', body: JSON.stringify({ pwd: 'password-2' }) }); assert.equal(b.body.uid, '100002');
});
await t('user login/me/logout: 세션 쿠키, 틀린 pwd 401, 로그아웃 뒤 me 401', async () => { /* … */ });
await t('register_code → /cia/register {uid, code}: 코드로 등록되고 코드는 1회용, 등록 뒤 register_code 는 409', async () => {
  // login(100001) → register_code → createRegistration → POST /cia/register {uid, code, auid, pk_u, sig_reg} → 201; 같은 코드 재사용 401 bad_code
});
await t('auth/code: pwd·auid 검사 — auid 틀리면 403 auid_mismatch, 등록 전 계정은 409 not_registered, 5분 뒤 만료(시계 주입 없이: 서버의 TTL 상수를 env CIA_CODE_TTL_MS=50 으로 띄운 두 번째 IdP 로 확인)', async () => { /* … */ });
await t('CIA_ISSUE_AUTH=code: demo 계정 발급은 auth_code 필수(401 auth_code_required), 맞는 코드면 200, 다른 auid 의 코드면 401 bad_code', async () => { /* 기존 test_cia_register_issue 의 issue 헬퍼를 복사해 auth_code 를 싣는다 */ });
await t('CIA_DEMO_ACCOUNTS 미설정이면 12345/67890 이 없고(/cia/register 401), 설정이면 있다', async () => { /* … */ });
```

- [ ] **Step 2: 실패 확인** — `node tests/test_cia_accounts.mjs`.

- [ ] **Step 3: 구현(cia.js)**

```js
import session from 'express-session';
import { createHash, randomBytes } from 'node:crypto';
const ISSUE_AUTH = process.env.CIA_ISSUE_AUTH === 'code' ? 'code' : 'key';   // 발급 인증 정책(2026-10-22): key = sig_u 만(기본·테스트), code = demo 계정에 1회용 코드 필수(데모)
const DEMO_SEED = process.env.CIA_DEMO_ACCOUNTS === '1';                      // 시드 계정(12345·67890)은 테스트·옛 흐름에서만
const CODE_TTL_MS = Number(process.env.CIA_CODE_TTL_MS) || 5 * 60_000;
const hashPw = (salt, pwd) => createHash('sha256').update(salt + pwd).digest('hex');
const newPw = (pwd) => { const pwSalt = randomBytes(16).toString('hex'); return { pwSalt, pwHash: hashPw(pwSalt, pwd) }; };
const pwOk = (acct, pwd) => Boolean(acct?.pwHash) && typeof pwd === 'string' && secretMatches(hashPw(acct.pwSalt, pwd), acct.pwHash);
app.use(session({ name: 'cia.sid', secret: process.env.CIA_SESSION_SECRET || randomBytes(32).toString('hex'), resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: 'lax' } }));
```
`defaultState()` 에 `nextUid: 100001, codes: {}`(기동 뒤 `state.nextUid ??= 100001; state.codes ??= {};`). 기동 시드: `if (DEMO_SEED) for (const a of Object.values(DEMO_ACCOUNTS)) if (!state.accounts[a.uid]) state.accounts[a.uid] = { ...newPw(a.password), createdAt: new Date().toISOString(), pk_u: null, auid: null, slot: null, provider: 'demo', tampered: false, disabled: false, creds: [], sessions: [] };` — **주의**: 기존 코드는 `state.accounts[uid]` 가 있으면 `registerAccount` 가 409 를 낸다. "등록 전 계정"을 구분하도록 `registerAccount` 의 409 조건을 `state.accounts[uid]?.pk_u` 로 바꾸고, 등록 때는 기존 레코드에 `pk_u·auid·slot·provider` 를 **채운다**(새 객체로 덮지 않는다 — pwHash 보존). `/cia/register` 데모 경로: `DEMO_ACCOUNTS` 조회 대신 `const acct = state.accounts[uidIn]; if (code !== undefined) { if (!consumeCode(code, { uid: uidIn, purpose: 'register' })) return 401 { error: 'bad_code', reason: 'bad_code' }; } else if (!pwOk(acct, pwd)) return 401 invalid credentials;`. 그 밖의 `DEMO_ACCOUNTS` 사용처(`:1195` self_revoke 의 비밀번호 검사)도 `pwOk` 로.

코드 저장소:
```js
function issueCode({ uid, purpose, auid = null }) { const code = randomBytes(32).toString('hex'); state.codes[code] = { uid, purpose, auid, expiresAt: Date.now() + CODE_TTL_MS }; for (const [k, v] of Object.entries(state.codes)) if (v.expiresAt < Date.now()) delete state.codes[k]; persist(); return { code, expiresAt: state.codes[code].expiresAt }; }
function consumeCode(code, { uid, purpose, auid = null }) { const c = typeof code === 'string' ? state.codes[code] : null; if (!c) return false; delete state.codes[code]; persist(); return c.expiresAt >= Date.now() && c.uid === uid && c.purpose === purpose && (auid === null || c.auid === auid); }
```
라우트:
```js
app.post('/cia/signup', (req, res) => { const { pwd } = req.body ?? {}; if (typeof pwd !== 'string' || pwd.length < 8) return res.status(400).json({ error: 'pwd 는 8자 이상', reason: 'signup_failed' }); const uid = String(state.nextUid++); state.accounts[uid] = { ...newPw(pwd), createdAt: new Date().toISOString(), pk_u: null, auid: null, slot: null, provider: 'demo', tampered: false, disabled: false, creds: [], sessions: [] }; persist(); res.status(201).json({ uid }); });
app.post('/cia/user/login', (req, res) => { const { uid, pwd } = req.body ?? {}; if (!isDec(uid) || !pwOk(state.accounts[uid], pwd)) return res.status(401).json({ error: 'invalid credentials' }); req.session.uid = uid; res.json({ uid }); });
app.post('/cia/user/logout', (req, res) => { req.session.uid = undefined; res.json({ ok: true }); });
const requireUser = (req, res, next) => { if (!req.session?.uid || !state.accounts[req.session.uid]) return res.status(401).json({ error: 'login required' }); next(); };
app.get('/cia/user/me', requireUser, async (req, res) => { const uid = req.session.uid, a = state.accounts[uid]; res.json({ uid, registered: Boolean(a.pk_u), auid: a.auid, slot: a.slot, provider: a.provider, disabled: a.disabled, activeCf_u: activeCfU(a) ?? null, registryLeaf: a.slot === null ? null : registry.leafAt(a.slot).toString() }); });
app.post('/cia/user/register_code', requireUser, (req, res) => { const a = state.accounts[req.session.uid]; if (a.pk_u) return res.status(409).json({ error: 'already registered', reason: 'already_registered' }); res.json(issueCode({ uid: req.session.uid, purpose: 'register' })); });
app.post('/cia/auth/code', (req, res) => { const { uid, pwd, auid } = req.body ?? {}; const a = isDec(uid) ? state.accounts[uid] : null; if (!pwOk(a, pwd)) return res.status(401).json({ error: 'invalid credentials', reason: 'invalid_credentials' }); if (!a.pk_u) return res.status(409).json({ error: 'not registered', reason: 'not_registered' }); if (!isDec(auid) || BigInt(auid).toString() !== a.auid) return res.status(403).json({ error: 'auid mismatch', reason: 'auid_mismatch' }); res.json(issueCode({ uid, purpose: 'issue', auid: a.auid })); });
```
(`activeCfU(a)` 는 기존 `/cia/accounts` 가 쓰는 "활성 자격증명 해시" 계산을 함수로 뽑아 쓴다.) `/cia/issue`: demo 계정 분기(`acct.provider === 'demo'`)에서 `if (ISSUE_AUTH === 'code') { if (typeof auth_code !== 'string') return 401 { error: 'auth_code required', reason: 'auth_code_required' }; if (!consumeCode(auth_code, { uid, purpose: 'issue', auid: acct.auid })) return 401 { error: 'bad_code', reason: 'bad_code' }; }`(본문 구조분해에 `auth_code` 추가).

- [ ] **Step 4: 통과 확인** — `node tests/test_cia_accounts.mjs`, 그리고 기존 `node tests/test_cia_register_issue.mjs tests/test_cia_startup.mjs tests/test_cia_oidc_register.mjs tests/test_cia_registry.mjs`(도우미가 시드를 켜므로 그대로). `/cia/accounts` 응답이 등록 전 계정(`pk_u:null`)을 만나 깨지지 않게 `registryLeaf` 계산을 `slot === null` 가드.

- [ ] **Step 5: 커밋 제안** — `feat(cia): 가입·세션·1회용 코드(등록/발급)·발급 정책 CIA_ISSUE_AUTH, 시드 계정 opt-in`

### Task B2: IdP RP 운영자·RP 슬롯·`rp_key`·공개 RP 주소 목록

**Files:**
- Modify: `cia.js`(`/cia/register_rp:471-505`, 새 라우트), `mode3/cia_admin.html:388-420`(operator 열), `mode3/common/strings.js`(`admin_col_operator`)
- Modify: `mode3_rp.js:121-123`(`rp_key`), `.env` 읽기 상수 `MODE3_RP_KEY`
- Test: `tests/test_cia_accounts.mjs`(케이스 추가), `tests/test_mode3_rp.mjs`(선택: `MODE3_RP_KEY` 전달은 격리 스택의 `rpEnv` 로)

**Interfaces:**
- Produces: `POST /cia/rp/signup {id,pwd}`(id `^[a-z0-9_-]{3,32}$`)→201; `POST /cia/rp/login`·`/cia/rp/logout`; `GET /cia/rp/me`→`{id, rps:[{name, key, status, origin, arid, requestedAt}]}`; `POST /cia/rp/create {name}`→201`{name, key, command}`(name `^zk[A-Za-z0-9]{1,15}$`, 운영자 안 유일); `/cia/register_rp` 본문 `rp_key?`(400 `bad_rp_key`); `GET /cia/rp_origins`→`{origins:[…]}`(승인된 RP 의 origin). 상태 `operators: {}`, `rpSlots: {}`, `state.rps[arid].operator`.
- `command` 문자열: `bash scripts/new_rp.sh <name> <port> <key> [--host <rp-vm-ip>]`.

- [ ] **Step 1: 실패하는 테스트**(`tests/test_cia_accounts.mjs` 에 추가):

```js
await t('rp signup/login/create: 키·명령 발급, 이름 규칙, 같은 운영자 안 중복 409', async () => { /* zkTHREE 생성 → key 64자 hex, command 에 key·name 포함; 'bad name' 400; 재생성 409 */ });
await t('register_rp with rp_key: 운영자에 연결(/cia/rp/me 에 arid·pending), 틀린 키 400 bad_rp_key, 이름 다르면 400; 키 없는 등록은 지금처럼 허용', async () => { /* … */ });
await t('rp_origins: 승인 전 빈 목록, 관리자 승인 뒤 origin 포함(공개, 세션 불필요)', async () => { /* adminPost approve → GET /cia/rp_origins */ });
```

- [ ] **Step 2: 실패 확인.**
- [ ] **Step 3: 구현** — `state.operators ??= {}; state.rpSlots ??= {};` 라우트는 B1 의 `newPw`/`pwOk` 재사용(운영자 레코드 `{ pwSalt, pwHash, createdAt }`), `requireOperator`(세션 `opId`). `/cia/rp/create`: `key = randomBytes(32).toString('hex')`, `state.rpSlots[key] = { opId, name, status: 'created', createdAt, arid: null }`, `command: `bash scripts/new_rp.sh ${name} <port> ${key} [--host <rp-vm-ip>]``. `/cia/register_rp`: `rp_key` 가 있으면 `const slot = state.rpSlots[rp_key]; if (!slot || slot.status !== 'created' || slot.name !== name) return 400 { error: 'bad_rp_key', reason: 'bad_rp_key' };` 등록 생성 뒤 `e.operator = slot.opId; slot.status = 'pending'; slot.arid = arid;`. `/cia/rp/me`: 운영자의 슬롯마다 `state.rps[slot.arid]` 의 `status·origin` 을 합쳐 낸다(`key` 는 `status === 'created'` 일 때만). `/cia/rp_origins`: `Object.values(state.rps).filter((e) => e.status === 'approved').map((e) => e.origin)`. 관리자 `/cia/rps` 응답에 `operator`, 관리자 페이지 표에 `['admin_col_operator']` 열(`e.operator ?? '-'`). `mode3_rp.js`: `const RP_KEY = process.env.MODE3_RP_KEY || null;` 등록 본문에 `...(RP_KEY ? { rp_key: RP_KEY } : {})`.
- [ ] **Step 4: 통과 확인** — `node tests/test_cia_accounts.mjs`.
- [ ] **Step 5: 커밋 제안** — `feat(cia): RP 운영자 계정·RP 슬롯 키(rp_key)·공개 rp_origins; rp 서버 MODE3_RP_KEY`

### Task B3: IdP 페이지 셋 — `/user`, `/rp`, `/login`

**Files:**
- Create: `mode3/cia_user.html`, `mode3/cia_rp.html`, `mode3/cia_login.html`
- Modify: `cia.js`(라우트: `/user`, `/rp`, `/login`, `/account` → 302 `/user`), `mode3/common/strings.js`(ui 키), `mode3/cia_admin.html`(상단 링크에 `/user`·`/rp`)
- Test: `tests/test_mode3_browser.mjs`(페이지 로드·가입·로그인·RP 만들기 — Snap 팝업 등록은 B5)

**Interfaces:**
- `/user`: 요소 `#signupPwd`·`#signupBtn`·`#loginUid`·`#loginPwd`·`#loginBtn`·`#logoutBtn`·`#meBadge`·`#meInfo`·`#registerBtn`(커밋먼트 등록 — B5 가 팝업을 연다)·`#userVerdict`·`#revokeBtn`(계정 폐기, 세션으로 — `/cia/account/self_revoke` 에 `{uid, pwd}` 대신 세션: 새 경로 `POST /cia/user/self_revoke {pwd}` 를 B3 에서 더한다).
- `/rp`: `#opId`·`#opPwd`·`#opSignupBtn`·`#opLoginBtn`·`#opLogoutBtn`·`#rpName`·`#rpCreateBtn`·`#rpList`(표: 이름·상태·주소·키·명령 + 복사 버튼)·`#rpVerdict`.
- `/login`: 쿼리 `nonce`·`wallet`. 요소 `#authUid`·`#authPwd`·`#authAuid`·`#authGo`·`#authVerdict`. 성공 시 `window.opener.postMessage({ type:'mode3-idp-auth', nonce, code }, allowedWalletOrigin)` 후 `window.close()`. `allowedWalletOrigin` 은 `/mode3/health` 의 `walletOrigin` 이며 쿼리 `wallet` 과 같아야 한다(다르면 `#authVerdict` 에 `idp_auth_bad_wallet` 사유, 폼 비활성).
- 모든 페이지: `/common/strings.js`·`/common/demo.js`·`/common/demo.css`, `Demo.init({ page: 'idp_user' | 'idp_rp' })`(login 은 `Demo` 없이), 상태 패널 `Demo.stack?.({ self:'aa', urls:{} })`.

- [ ] **Step 1: 실패하는 브라우저 테스트**(`tests/test_mode3_browser.mjs`, 스택 `cia.base` 사용):

```js
  await t('IdP 사용자 페이지: 가입 → uid 배정 → 로그인 → 상태(등록 전) → 로그아웃', async () => {
    const p = await context.newPage(); await p.goto(`${cia.base}/user`);
    await p.fill('#signupPwd', 'demo-pass-1'); await p.click('#signupBtn');
    await waitText(p, '#userVerdict', 'uid'); const uid = await p.$eval('#userVerdict', (e) => e.textContent.match(/uid\s*(\d+)/)[1]);
    await p.fill('#loginUid', uid); await p.fill('#loginPwd', 'demo-pass-1'); await p.click('#loginBtn');
    await waitText(p, '#meBadge', '등록 전'); await p.click('#logoutBtn'); await waitText(p, '#meBadge', '로그아웃'); await p.close();
  });
  await t('IdP RP 페이지: 운영자 가입·로그인 → zkTHREE 만들기 → 키·명령 표시', async () => {
    const p = await context.newPage(); await p.goto(`${cia.base}/rp`);
    await p.fill('#opId', 'op1'); await p.fill('#opPwd', 'operator-1'); await p.click('#opSignupBtn'); await waitText(p, '#rpVerdict', 'op1');
    await p.click('#opLoginBtn'); await p.fill('#rpName', 'zkTHREE'); await p.click('#rpCreateBtn');
    await waitText(p, '#rpList', 'zkTHREE'); assert.match(await text(p, '#rpList'), /new_rp\.sh zkTHREE <port> [0-9a-f]{64}/); await p.close();
  });
  await t('IdP 인증 창: wallet 쿼리가 지갑 오리진과 다르면 폼을 막는다; 맞으면 uid·pwd·auid 로 코드를 받아 opener 에 postMessage', async () => {
    const bad = await context.newPage(); await bad.goto(`${cia.base}/login?nonce=abc&wallet=http://evil.example`); await waitText(bad, '#authVerdict', '지갑 오리진'); await bad.close();
    // 등록된 계정(앞 케이스들이 만든 12345 — 시드) 으로: opener 를 흉내 내는 페이지가 window.open 으로 연다
    const opener = await context.newPage(); await opener.goto(`${wallet.base}/`);
    const [win] = await Promise.all([context.waitForEvent('page'), opener.evaluate((u) => { window.__got = null; window.addEventListener('message', (ev) => { window.__got = { origin: ev.origin, data: ev.data }; }); window.open(u); }, `${cia.base}/login?nonce=n1&wallet=${wallet.base}`)]);
    await win.fill('#authUid', '12345'); await win.fill('#authPwd', 'password123'); await win.fill('#authAuid', AUID_12345); await win.click('#authGo');
    await opener.waitForFunction(() => window.__got !== null, undefined, { timeout: 10_000 });
    const got = await opener.evaluate(() => window.__got); assert.equal(got.origin, cia.base); assert.equal(got.data.type, 'mode3-idp-auth'); assert.equal(got.data.nonce, 'n1'); assert.match(got.data.code, /^[0-9a-f]{64}$/);
    await opener.close();
  });
```
(`AUID_12345` 는 등록 케이스에서 `/wallet/status` 의 `auid` 로 받아 둔 값.)

- [ ] **Step 2: 실패 확인** — 404.

- [ ] **Step 3: 구현** — 세 페이지(아래 골격; 스타일은 `demo.css` 의 `.card`·`.kv`·`.badge`·`.verdict`·`.copy-btn` 재사용, 문구는 `data-i18n` + `Demo.t`). `cia_user.html`:

```html
<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>IdP — 사용자</title><link rel="stylesheet" href="/common/demo.css" /><script src="/common/strings.js"></script><script src="/common/demo.js"></script></head>
<body data-page="idp_user"><header id="demoBar"></header><main class="cards">
  <section class="card" id="signupCard"><h3 data-i18n="idp_signup_title">계정 만들기</h3><p class="desc" data-i18n="idp_signup_desc">비밀번호만 정하면 IdP 가 uid 를 배정합니다. 속성은 IdP 에 보내지 않습니다.</p>
    <p><label><span data-i18n="idp_pwd_label">비밀번호</span> <input id="signupPwd" type="password" autocomplete="new-password" /></label> <button id="signupBtn" data-i18n="idp_signup_btn">가입</button></p></section>
  <section class="card" id="loginCard"><h3 data-i18n="idp_login_title">로그인</h3>
    <p><label>uid <input id="loginUid" size="8" /></label> <label><span data-i18n="idp_pwd_label">비밀번호</span> <input id="loginPwd" type="password" autocomplete="current-password" /></label> <button id="loginBtn" data-i18n="idp_login_btn">로그인</button> <button id="logoutBtn" class="btn-ghost" data-i18n="idp_logout_btn">로그아웃</button></p>
    <p><span id="meBadge" class="badge muted">로그아웃</span> <span id="meInfo" class="muted"></span></p></section>
  <section class="card" id="registerCard"><h3 data-i18n="idp_register_title">커밋먼트 등록</h3><p class="desc" data-i18n="idp_register_desc">지갑(MetaMask Snap)이 비밀을 만들고 커밋먼트와 공개키만 IdP 에 등록합니다. 속성은 지갑에만 남습니다.</p>
    <p><button id="registerBtn" data-i18n="idp_register_btn">지갑으로 커밋먼트 등록</button> <a id="walletLink" class="btn-ghost" target="_blank" data-i18n="idp_wallet_link">지갑 페이지 열기</a></p>
    <dl class="kv"><dt data-term="auid">auid</dt><dd><code id="meAuid">-</code> <button type="button" id="copyAuidBtn" class="copy-btn" hidden>⧉</button></dd><dt data-i18n="idp_slot_label">등록부 슬롯</dt><dd id="meSlot">-</dd></dl>
    <div id="userVerdict"></div></section>
  <section class="card" id="revokeCard"><h3 data-i18n="account_revoke_btn">내 계정 폐기</h3><p><label><span data-i18n="idp_pwd_label">비밀번호</span> <input id="revokePwd" type="password" /></label> <button id="revokeBtn" class="danger" data-i18n="account_revoke_btn">내 계정 폐기</button></p><div id="revokeVerdict"></div></section>
</main><script>
  const $ = (id) => document.getElementById(id);
  const post = (url, body) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body ?? {}) }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));
  const tt = (k, v) => { const s = Demo.t(k, v); return s === k ? '' : s; };
  const verdict = (el, ok, title, extra) => Demo.verdict(el, () => ({ ok, title: window.DemoStrings?.verdicts?.[title] ? title : Demo.t(title), ...(typeof extra === 'function' ? extra() : extra) }));
  let walletOrigin = null, me = null;
  async function refreshMe() {
    const r = await fetch('/cia/user/me'); me = r.status === 200 ? await r.json() : null;
    $('meBadge').className = `badge ${!me ? 'muted' : me.registered ? 'ok' : 'warn'}`;
    $('meBadge').textContent = !me ? (tt('idp_me_out') || '로그아웃') : me.registered ? (tt('idp_me_registered') || '등록됨') : (tt('idp_me_unregistered') || '등록 전');
    $('meInfo').textContent = me ? `uid ${me.uid}` : ''; $('meAuid').textContent = me?.auid ?? '-'; $('copyAuidBtn').hidden = !me?.auid; $('meSlot').textContent = me?.slot ?? '-';
  }
  $('signupBtn').addEventListener('click', async () => { const r = await post('/cia/signup', { pwd: $('signupPwd').value }); if (r.status === 201) { $('loginUid').value = r.body.uid; verdict($('userVerdict'), true, 'idp_signup_ok_title', () => ({ summary: tt('idp_signup_ok', { uid: r.body.uid }) || `가입됨 — uid ${r.body.uid}. 이 uid 로 로그인하세요.` })); } else verdict($('userVerdict'), false, 'idp_signup_failed', { reason: r.body?.reason ?? `HTTP ${r.status}`, detail: r.body }); });
  $('loginBtn').addEventListener('click', async () => { const r = await post('/cia/user/login', { uid: $('loginUid').value.trim(), pwd: $('loginPwd').value }); $('loginPwd').value = ''; if (r.status !== 200) verdict($('userVerdict'), false, 'idp_login_failed', { reason: r.body?.reason ?? `HTTP ${r.status}` }); await refreshMe(); });
  $('logoutBtn').addEventListener('click', async () => { await post('/cia/user/logout'); await refreshMe(); });
  $('copyAuidBtn').addEventListener('click', async () => { try { await navigator.clipboard.writeText(me.auid); } catch { const ta = document.createElement('textarea'); ta.value = me.auid; document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); } finally { ta.remove(); } } });
  $('revokeBtn').addEventListener('click', async () => { if (!me) return; if (!Demo.confirmDanger('confirm_account_revoke')) return; const r = await post('/cia/user/self_revoke', { pwd: $('revokePwd').value }); $('revokePwd').value = ''; verdict($('revokeVerdict'), r.status === 200, r.status === 200 ? 'revoked_ok' : 'account_revoke_failed', { reason: r.body?.reason, detail: r.body }); await refreshMe(); });
  // 커밋먼트 등록(B5): 세션으로 등록 코드 → 지갑 팝업(?authorize=1) 에 mode3-register. walletOrigin 은 /mode3/health 가 준다.
  $('registerBtn').addEventListener('click', async () => {
    if (!me) return verdict($('userVerdict'), false, 'idp_register_failed', { reason: 'login_required' });
    const c = await post('/cia/user/register_code'); if (c.status !== 200) return verdict($('userVerdict'), false, 'idp_register_failed', { reason: c.body?.reason ?? `HTTP ${c.status}` });
    const popup = window.open(`${walletOrigin}/?authorize=1`, 'mode3-register', 'width=460,height=640');
    if (!popup) return verdict($('userVerdict'), false, 'idp_register_failed', { reason: 'popup_blocked' });
    Demo.verdict($('userVerdict'), { pending: true, title: tt('working') || '처리 중' });
    const onMsg = (ev) => {
      if (ev.origin !== walletOrigin) return;
      if (ev.data?.type === 'mode3-authorize-ready') popup.postMessage({ type: 'mode3-register', uid: me.uid, code: c.body.code, ciaUrl: location.origin }, walletOrigin);
      if (ev.data?.type === 'mode3-register-result') { window.removeEventListener('message', onMsg); const r = ev.data.result; verdict($('userVerdict'), Boolean(r.ok), r.ok ? 'idp_register_ok_title' : 'idp_register_failed', r.ok ? () => ({ summary: tt('idp_register_ok', { slot: r.slot }) || `등록됨 — 슬롯 #${r.slot}` }) : { reason: r.reason, detail: r.detail }); refreshMe(); }
    };
    window.addEventListener('message', onMsg);
  });
  (async () => { try { const h = await (await fetch('/mode3/health')).json(); walletOrigin = h.walletOrigin; $('walletLink').href = `${walletOrigin}/`; } catch { /* */ } Demo.init({ page: 'idp_user' }); Demo.stack?.({ self: 'aa', urls: { wallet: walletOrigin } }); await refreshMe(); })();
</script></body></html>
```

`cia_rp.html`(같은 틀; 운영자 가입·로그인·`rpName`·만들기·`rpList` 표 — 행: name, status badge, origin, key(`created` 만, 복사 버튼), command(`<code>` + 복사 버튼)). `cia_login.html`(데모 바 없음, 좁은 창): 로드 때 `nonce`·`wallet` 쿼리와 `/mode3/health.walletOrigin` 대조 → 폼; `#authGo` → `POST /cia/auth/code {uid, pwd, auid}` → 200 이면 `window.opener?.postMessage({ type: 'mode3-idp-auth', nonce, code: body.code }, walletOrigin); setTimeout(() => window.close(), 300);` 실패면 사유(`invalid_credentials`·`not_registered`·`auid_mismatch`). `cia.js`: `app.get('/user', …cia_user.html)`, `/rp`, `/login`, `app.get('/account', (req, res) => res.redirect(302, '/user'))`; `POST /cia/user/self_revoke {pwd}`(세션 uid + `pwOk` → 기존 `revokeAccount(uid)`). `/cia/account/self_revoke` 는 그대로 둔다(web 모드). 문구 키(ko·en): `idp_signup_title/desc/btn`, `idp_pwd_label`, `idp_login_title/btn`, `idp_logout_btn`, `idp_me_out/registered/unregistered`, `idp_register_title/desc/btn`, `idp_wallet_link`, `idp_slot_label`, `idp_signup_ok_title/ok/failed`, `idp_login_failed`, `idp_register_ok_title/ok/failed`, `idp_rp_*`(운영자 가입/로그인/만들기/표 열/복사), `idp_auth_title/desc/go`, `idp_auth_bad_wallet`, `account_revoke_failed`, `confirm_account_revoke`; 사유: `invalid_credentials`, `signup_failed`, `login_required`, `bad_code`, `auth_code_required`, `auid_mismatch`, `idp_auth_cancelled`, `idp_auth_bad_wallet`, `bad_rp_key`, `operator_login_failed`(`where:'aa'`, ko/en title·cause·action).

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_browser.mjs`(새 케이스 셋), `node tests/test_mode3_demo_strings.js`(새 키는 ko·en 둘 다).
- [ ] **Step 5: 커밋 제안** — `feat(cia): IdP 사용자·RP·인증 창 페이지`

### Task B4: 에이전트 — 동적 RP 허용 목록·`auth_code`·코드 등록

**Files:**
- Modify: `mode3_wallet_agent.js`(`RP_ORIGINS`·`isRpOrigin`·CORS, `/wallet/login`, `/wallet/register`, `/wallet/config`)
- Test: `tests/test_mode3_wallet_agent.mjs`

**Interfaces:**
- Produces: `GET /wallet/config` 에 `ciaUrl`. RP 허용 목록 = env ∪ IdP `/cia/rp_origins`(10초 폴링, 실패 시 유지; `pollRpOrigins()`). `POST /wallet/login { …, auth_code? }` → `/cia/issue` 본문에 `auth_code`. `POST /wallet/register { uid, code | pwd, s_u?, sk_u?, profile? }` → `/cia/register { uid, code | pwd, … }`.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_wallet_agent.mjs` 에:
```js
  await t('동적 RP 허용 목록: IdP 가 승인한 새 RP 오리진에 10초 안에 CORS 가 열린다', async () => { /* cia.adminPost 로 새 RP 등록·승인(테스트가 /cia/register_rp 를 직접 부른다: origin http://127.0.0.1:3999) → 최대 12초 폴링하며 OPTIONS /wallet/login Origin:3999 의 ACAO 확인 */ });
  await t('/wallet/login 의 auth_code 가 /cia/issue 로 전달된다(IdP 를 CIA_ISSUE_AUTH=code 로 띄운 스택에서: 코드 없으면 401 auth_code_required, 있으면 200)', async () => { /* 별도 스택 startIsolatedMode3Stack({ ciaEnv: { CIA_ISSUE_AUTH: 'code' } }) */ });
  await t('/wallet/register { uid, code }: register_code 로 받은 코드로 등록된다(pwd 없이)', async () => { /* 세션 jar 로 /cia/user/login(시드 12345) → register_code → wallet.post('/wallet/register', { uid:'12345', code }) → 201 */ });
```
- [ ] **Step 2: 실패 확인.**
- [ ] **Step 3: 구현** — `let rpOrigins = originList(envList);` `const isRpOrigin = (o) => allowOrigin(o, rpOrigins);` `loginCors`·`HEALTH_ALLOW` 가 함수형으로 `rpOrigins` 를 매번 본다(cors 의 `origin: (o, cb) => cb(null, isRpOrigin(o))`). `async function pollRpOrigins() { try { const r = await fetch(`${CIA_URL}/cia/rp_origins`); if (r.ok) { const { origins } = await r.json(); rpOrigins = originList(envList, ...origins); } } catch { /* 유지 */ } }` 기동 때 한 번 + `setInterval(pollRpOrigins, 10_000).unref()`. `/wallet/login` 본문에 `auth_code = null` 추가 → `issueSession` 호출에 전달 → `/cia/issue` 본문 `...(auth_code ? { auth_code } : {})`. `/wallet/register`: `pwd` 또는 `code` 중 하나(둘 다 없으면 400); IdP 본문에 해당 키만. `/wallet/config` 에 `ciaUrl: CIA_URL`.
- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_wallet_agent.mjs`.
- [ ] **Step 5: 커밋 제안** — `feat(agent): IdP rp_origins 동적 허용 목록, auth_code 전달, 코드 등록`

### Task B5: 지갑 페이지 — 제목·auid/salt 복사·`mode3-register` 팝업·IdP 인증 창

**Files:**
- Modify: `mode3/wallet.html`(`<title>`, 신원 카드, 팝업 `onMessage`, 등록 버튼), `mode3/common/strings.js`
- Test: `tests/test_mode3_browser.mjs`

**Interfaces:**
- 팝업 메시지 `mode3-register { uid, code, ciaUrl }`(발신 오리진 == `new URL(cfg.ciaUrl).origin` 만) → `mode3-register-result { result: { ok, slot?, auid?, reason?, detail? } }`.
- 로그인 흐름: precheck → Snap consentLogin → **IdP 인증 창** `window.open(`${cfg.ciaUrl}/login?nonce=${n}&wallet=${location.origin}`)` → `mode3-idp-auth { nonce, code }`(발신 오리진 == IdP 오리진, nonce 일치) → `/wallet/login { …, auth_code }`. 60초 안 응답 없음·창 닫힘 → `reply({ ok:false, reason:'idp_auth_cancelled' })`.
- 신원 카드: `#meAuid`(전체 auid + 복사), `#meSalt`(전체 s_u + 복사, 라벨 "비밀 — 시연용 표시"). Snap 모드는 `invokeSnap('getRegistrationSecretsForDisplay')` 대신 **기존 `consentLogin` 류의 비밀 반출은 쓰지 않고** `/wallet/status` 의 `auid` 와, salt 는 Snap 의 `getPublicInfo` 가 비밀을 내지 않으므로 새 Snap RPC `showSalt`(확인 창 "salt 를 화면에 표시합니다" 뒤 `{ s_u }` 반환, B6) 로 받는다. file 모드는 `/wallet/status` 에 `s_u` 를 싣지 않으므로 새 에이전트 경로 `GET /wallet/secrets/salt`(file 모드 전용, 같은 오리진)를 B4 에서 더한다 → 이 태스크에서 호출.
- Snap 모드 등록 버튼: 신원 카드의 `#registerBtn` 은 Snap 모드에서 숨기고 `#registerHint`("IdP 사용자 페이지에서 가입·등록하세요" + 링크 `${cfg.ciaUrl}/user`)를 보인다. file 모드는 그대로.

- [ ] **Step 1: 실패하는 브라우저 테스트**(기존 '등록' 케이스를 IdP 페이지 경유로 바꾼다):

```js
  await t('등록(2026-10-22): IdP 사용자 페이지 가입·로그인 → "지갑으로 커밋먼트 등록" → 지갑 팝업 → Snap 확인 창(uid·비밀번호 프롬프트 없음) → 등록됨; IdP 는 auid·pk_u·sig_reg 만 받았다', async () => {
    const u = await context.newPage(); await u.goto(`${cia.base}/user`);
    await u.fill('#signupPwd', 'demo-pass-9'); await u.click('#signupBtn'); await waitText(u, '#userVerdict', 'uid');
    const uid = await u.$eval('#userVerdict', (e) => e.textContent.match(/uid\s*(\d+)/)[1]); await u.fill('#loginUid', uid); await u.fill('#loginPwd', 'demo-pass-9'); await u.click('#loginBtn'); await waitText(u, '#meBadge', '등록 전');
    answers.push(true);                                                                    // Snap 등록 확인 창
    const [popup] = await Promise.all([context.waitForEvent('page'), u.click('#registerBtn')]);
    await waitText(u, '#meBadge', '등록됨', 60_000);
    assert.ok(dialogs.at(-1).content.children.some((c) => new RegExp(`uid ${uid}`).test(c.value ?? '')), '확인 창에 uid');
    assert.ok(!dialogs.at(-1).content.children.some((c) => /비밀번호/.test(c.value ?? '')), '비밀번호를 묻지 않는다');
    const st = (await wallet.get('/wallet/status')).body; assert.equal(st.uid, uid); AUID = st.auid; await u.close();
  });
  await t('지갑 페이지 제목은 "지갑", 신원 카드에 auid·salt 와 복사 버튼', async () => {
    assert.equal(await walletPage.title(), '지갑'); await walletPage.click('#refreshBtn');
    await waitText(walletPage, '#meAuid', AUID.slice(0, 10)); answers.push(true);        // showSalt 확인 창
    await walletPage.click('#showSaltBtn'); await walletPage.waitForFunction(() => /^[0-9]{10,}$/.test(document.querySelector('#meSalt')?.textContent ?? ''), undefined, { timeout: 10_000 });
    assert.ok(await walletPage.$('#copyAuidBtn')); assert.ok(await walletPage.$('#copySaltBtn'));
  });
  await t('로그인(2026-10-22): Snap 동의 뒤 IdP 인증 창이 뜨고 uid·비밀번호·auid 를 넣어야 발급된다; auid 가 틀리면 auid_mismatch', async () => {
    answers.push(true);                                                                     // consentLogin
    const [popup] = await Promise.all([context.waitForEvent('page'), idpLogin(rpPage)]);
    const [auth] = await Promise.all([context.waitForEvent('page'), popup.waitForSelector('#authStep')]);   // 팝업이 연 IdP 창
    await auth.fill('#authUid', uid); await auth.fill('#authPwd', 'demo-pass-9'); await auth.fill('#authAuid', '123'); await auth.click('#authGo');
    await waitText(auth, '#authVerdict', 'auid');                                           // auid_mismatch 사유, 창은 열려 있다
    await auth.fill('#authAuid', AUID); await auth.click('#authGo');
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
  });
```
(이 스택은 `ciaEnv: { CIA_ISSUE_AUTH: 'code' }` 로 띄운다 — 파일 머리의 `startIsolatedMode3Stack` 옵션에 추가. `uid` 는 등록 케이스가 바깥 변수에 둔다.)

- [ ] **Step 2: 실패 확인.**
- [ ] **Step 3: 구현** — `wallet.html`: `<title>지갑</title>`, `#identityCard h3` 문구 `wallet_identity_title` → "내 신원"; `dl.kv` 에
```html
        <dt data-term="auid">auid</dt><dd><code id="meAuid">-</code> <button type="button" id="copyAuidBtn" class="copy-btn" hidden title="복사">⧉</button></dd>
        <dt><span data-i18n="wallet_salt_label">salt(s_u)</span> <span class="badge warn" data-i18n="wallet_salt_warn">비밀 — 시연용 표시</span></dt><dd><code id="meSalt">-</code> <button type="button" id="showSaltBtn" class="btn-ghost" data-i18n="wallet_salt_show">보기</button> <button type="button" id="copySaltBtn" class="copy-btn" hidden title="복사">⧉</button></dd>
```
`renderIdentity` 가 `#meAuid` 를 `s.auid` 로 채우고 `#copyAuidBtn.hidden = !s.auid`; `#showSaltBtn` → Snap 모드 `invokeSnap('showSalt')` / file 모드 `fetch('/wallet/secrets/salt')` → `#meSalt` 에 표시·복사 버튼 표시. Snap 모드에서 `#registerBtn.hidden = true`, `#registerHint`(링크 `${cfg.ciaUrl}/user`) 표시(`cfg.ciaUrl` 은 B4 의 `/wallet/config`). 팝업 `onMessage`: `req.type === 'mode3-register'` 분기(오리진 == `new URL(cfg.ciaUrl).origin` 아니면 `origin_mismatch`): `connectMetaMask()` → `invokeSnap('register', { uid: req.uid })`(B6: 확인 창 하나, 반환 `{ uid, s_u, sk_u }` 또는 `{ denied }`) → `postJson('/wallet/register', { uid: req.uid, code: req.code, s_u, sk_u })` → 201 이면 `invokeSnap('storeRegistration', { attrs: b.attrs, slot: b.slot, auid: b.auid })` → `reply({ ok:true, slot: b.slot, auid: b.auid })`(reply 는 `mode3-register-result` 로, `req.ciaUrl` 오리진에). 로그인 분기: `consentLogin` 뒤에
```js
          step('IdP 인증 창에서 uid·비밀번호·auid 를 입력하세요.');
          const authCode = await idpAuth();   // null 이면 취소
          if (!authCode) { step('IdP 인증 취소'); return reply({ ok: false, reason: 'idp_auth_cancelled' }); }
```
```js
    function idpAuth() {
      return new Promise((resolve) => {
        const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
        const ciaOrigin = new URL(cfg.ciaUrl).origin;
        const win = window.open(`${cfg.ciaUrl}/login?nonce=${nonce}&wallet=${encodeURIComponent(location.origin)}`, 'mode3-idp-auth', 'width=420,height=520');
        if (!win) return resolve(null);
        const done = (v) => { clearInterval(tick); clearTimeout(timer); window.removeEventListener('message', onMsg); resolve(v); };
        const onMsg = (ev) => { if (ev.origin !== ciaOrigin || ev.data?.type !== 'mode3-idp-auth' || ev.data.nonce !== nonce) return; done(ev.data.code || null); };
        window.addEventListener('message', onMsg);
        const tick = setInterval(() => { if (win.closed) done(null); }, 500);
        const timer = setTimeout(() => { try { win.close(); } catch { /* */ } done(null); }, 60_000);
      });
    }
```
`/wallet/login` 본문에 `auth_code: authCode`. 문구: `wallet_identity_title`("내 신원"), `wallet_salt_label/warn/show`, `wallet_register_hint`("IdP 사용자 페이지에서 가입하고 커밋먼트를 등록하세요"), `user_auth_idp_step`.

- [ ] **Step 4: 통과 확인** — B6 뒤 `node tests/test_mode3_browser.mjs`.
- [ ] **Step 5: 커밋 제안** — `feat(wallet-page): 제목 "지갑", auid·salt 복사, IdP 페이지 등록 팝업(mode3-register), 발급 전 IdP 인증 창`

### Task B6: Snap — `register({uid})`·`consentRevokeSession({bound})`·`showSalt`, 시뮬레이터, 재빌드

**Files:**
- Modify: `snap-mode3/src/index.js`(`register`, `consentRevokeSession`, 새 `showSalt`), `snap-mode3/test/rpc.test.mjs`, `tests/helpers/snap_sim.mjs`, `tests/helpers/ethereum_stub.js`(변경 없을 가능성 — `wallet_invokeSnap` 라우팅은 메서드 불문)
- Regenerate: `snap-mode3/dist/bundle.js`, `snap-mode3/snap.manifest.json`(`npm run snap:build`)

**Interfaces:**
- `register({ uid })`: 확인 창 하나("IdP 등록 — uid N. 비밀 s_u·sk_u 를 만들어 이 Snap 에 보관합니다. 속성은 지갑에만 남습니다.") → `{ uid, s_u, sk_u }` 또는 `{ denied:true }`. uid 는 10진 문자열 필수(`bad_uid`). 비밀번호 프롬프트 없음.
- `consentRevokeSession({ arid, issuedAt, maxHeight, bound })`: 창에 `허용 거래 수: ${bound} (nonce < ${bound} 만 유효)` 줄.
- `showSalt()`: 확인 창("salt(s_u)를 지갑 페이지에 표시합니다 — 시연용. 화면 밖으로 보내지 마세요.") → `{ s_u }` 또는 `{ denied:true }`.
- 시뮬레이터 `register({ uid })`(pwd 없음), `consentRevokeSession({ bound })`, `showSalt()`.

- [ ] **Step 1: 단위 테스트(실패)** — `snap-mode3/test/rpc.test.mjs` 의 등록 케이스를 `register({ uid:'100001' })` 로(프롬프트 응답 큐 대신 `answers.push(true)` 하나), 대화상자 내용에 `uid 100001` 포함·`비밀번호` 미포함 단언; `consentRevokeSession({ …, bound: '3' })` 창에 `허용 거래 수: 3`; `showSalt` 거절/승인.
- [ ] **Step 2: 실패 확인** — `node snap-mode3/test/rpc.test.mjs`.
- [ ] **Step 3: 구현** — `index.js`:
```js
    case 'register': {
      if (state.registration) fail('already_registered: 이미 등록돼 있다 (초기화하려면 reset)');
      const uid = String(params.uid ?? '').trim();
      if (!isDec(uid)) fail('bad_uid: uid 는 10진 숫자 문자열이어야 한다');
      const ok = await confirm('IdP 등록', [`uid: ${uid}`, null, '등록 비밀(s_u·sk_u)을 만들어 이 Snap 에 보관합니다.', '속성은 지갑에만 남고 IdP 에는 커밋먼트와 공개키만 갑니다.']);
      if (!ok) return { denied: true };
      const secrets = createRegistrationSecrets();
      state.registration = { uid, s_u: secrets.s_u, auid: null, sk_u: secrets.sk_u, slot: null, attrs: null, registeredAt: new Date().toISOString() };
      state.userCred = null; await setState(state);
      return { uid, s_u: secrets.s_u, sk_u: secrets.sk_u };
    }
    case 'showSalt': {
      const reg = requireRegistered(state);
      const ok = await confirm('salt 표시', ['salt(s_u)를 지갑 페이지에 표시합니다 — 시연용입니다.', '화면 밖으로 보내지 마세요.']);
      return ok ? { s_u: reg.s_u } : { denied: true };
    }
```
`consentRevokeSession` 의 줄에 `` `허용 거래 수: ${String(params.bound ?? '0')} (nonce < ${String(params.bound ?? '0')} 만 유효)` ``. 시뮬레이터도 같은 입출력. `cd snap-mode3 && npm run build` → `dist/bundle.js`·`snap.manifest.json` 갱신(체크섬 바뀜 — MetaMask 재설치 안내는 B9 런북).
- [ ] **Step 4: 통과 확인** — `node snap-mode3/test/rpc.test.mjs`, 그리고 A8·B5 의 브라우저 케이스: `node tests/test_mode3_browser.mjs` 전체.
- [ ] **Step 5: 커밋 제안** — `feat(snap): register(uid) 확인 창만, 폐기 동의에 허용 거래 수, showSalt; 번들 재빌드`

### Task B7: 새 RP 기동 명령 `scripts/new_rp.sh`

**Files:**
- Create: `scripts/new_rp.sh`
- Modify: `.gitignore`(`mode3_rp_*`, `*.bak-*`), `mode3_rp.js`(없음 — B2 에서 `MODE3_RP_KEY`)
- Test: 수동(`bash scripts/new_rp.sh zkTHREE 3102 <key>` 를 한 머신 Snap 데모에서; B9 E2E 가 돈다)

**Interfaces:** `bash scripts/new_rp.sh NAME PORT KEY [--host IP] [--relayer N] [--countries 410,392] [--min-age 19] [--require-disclosure] [--stop]`

- [ ] **Step 1: 스크립트**

```bash
#!/usr/bin/env bash
# 새 RP 서버 한 줄 기동(2026-10-22 설계 B §6). IdP RP 페이지가 보여 주는 명령이다. 로컬(한 머신 데모) 또는 --host 로 RP VM 에 ssh.
#   bash scripts/new_rp.sh zkTHREE 3102 <rp_key> [--host 192.168.226.11] [--relayer 3] [--countries 410,392] [--min-age 19] [--require-disclosure] [--stop]
# 공통 env 는 로컬이면 $DEMO_LOG_DIR/demo_env.txt(demo_web_reset.sh 가 쓴 로그·거울 주소)와 그 스크립트의 오리진 규칙, VM 이면 ~/zkd-demo/role.env(rp1 의 것) 위에 덮는다.
set -euo pipefail
cd "$(dirname "$0")/.."
NAME="${1:?NAME}"; PORT="${2:?PORT}"; KEY="${3:?KEY}"; shift 3
HOST=""; RELAYER=""; COUNTRIES=""; MIN_AGE=""; REQ=""; STOP=0
while [ $# -gt 0 ]; do case "$1" in --host) HOST="$2"; shift 2;; --relayer) RELAYER="$2"; shift 2;; --countries) COUNTRIES="$2"; shift 2;; --min-age) MIN_AGE="$2"; shift 2;; --require-disclosure) REQ=1; shift;; --stop) STOP=1; shift;; *) echo "모르는 옵션 $1" >&2; exit 1;; esac; done
[[ "$NAME" =~ ^zk[A-Za-z0-9]{1,15}$ ]] || { echo "NAME 은 zk 로 시작하는 영숫자(최대 16자)" >&2; exit 1; }
LOGS="${DEMO_LOG_DIR:-/tmp/mode3-demo}"
if [ -z "$HOST" ]; then
  # 로컬: 기존 RP 수로 릴레이어 인덱스 기본값(0·1 = zkONE·zkTWO, 2 = Snap 에이전트)
  N=$(pgrep -fc '^node mode3_rp.js$' || true); RELAYER="${RELAYER:-$((3 + N))}"
  if [ "$STOP" = 1 ]; then for pid in $(ss -ltnp 2>/dev/null | grep ":$PORT " | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u); do kill "$pid" && echo "stop :$PORT ($pid)"; done; exit 0; fi
  [ -s "$LOGS/demo_env.txt" ] || { echo "$LOGS/demo_env.txt 가 없다 — 먼저 demo_web_reset.sh / demo_snap_reset.sh 로 데모를 띄울 것" >&2; exit 1; }
  set -a; . "$LOGS/demo_env.txt"; set +a
  export CIA_ADMIN_OPEN="${CIA_ADMIN_OPEN:-1}" MODE3_VERIFIER_ADDRESS="" MODE3_RP_FACTORY_ADDRESS="" MODE3_WALLET_AGENT_ORIGIN="http://localhost:5100" MODE3_CIA_URL="http://localhost:4100" CIA_RPC_URL="http://127.0.0.1:8545"
  export MODE3_RP_NAME="$NAME" MODE3_RP_PORT="$PORT" MODE3_RP_PUBLIC_ORIGIN="http://localhost:$PORT" MODE3_RP_KEY="$KEY" MODE3_RELAYER_INDEX="$RELAYER" MODE3_RP_REGISTRATION_FILE="mode3_rp_${NAME}_registration.json" MODE3_RP_LOGIN_LOG="mode3_rp_${NAME}_logins.jsonl"
  [ -n "$COUNTRIES" ] && export MODE3_ALLOWED_COUNTRIES="$COUNTRIES"; [ -n "$MIN_AGE" ] && export MODE3_MIN_AGE="$MIN_AGE"; [ -n "$REQ" ] && export MODE3_REQUIRE_DISCLOSURE=1
  setsid nohup node mode3_rp.js > "$LOGS/rp_${NAME}.log" 2>&1 < /dev/null &
  timeout 40 bash -c "until ss -ltn | grep -q ':$PORT '; do sleep 1; done" && echo "$NAME up at http://localhost:$PORT (등록 요청 보냄 — IdP 관리자 승인 대기)" || { echo "$NAME failed — $LOGS/rp_${NAME}.log"; exit 1; }
else
  U="${SPLIT_SSH_USER:-zkd}"
  if [ "$STOP" = 1 ]; then ssh -o BatchMode=yes "$U@$HOST" "pkill -f '[z]kd-demo/bin/node mode3_rp.js.*rp_${NAME}' || true"; exit 0; fi
  RELAYER="${RELAYER:-3}"
  ssh -o BatchMode=yes "$U@$HOST" "cd ~/zkd-demo && { grep -vE '^(MODE3_RP_PORT|MODE3_RP_NAME|MODE3_RP_PUBLIC_ORIGIN|MODE3_RELAYER_INDEX|MODE3_ALLOWED_COUNTRIES|MODE3_MIN_AGE|MODE3_REQUIRE_DISCLOSURE|MODE3_RP_REGISTRATION_FILE|MODE3_RP_LOGIN_LOG|MODE3_RP_KEY)=' role.env; echo MODE3_RP_PORT=$PORT; echo MODE3_RP_NAME=$NAME; echo MODE3_RP_PUBLIC_ORIGIN=http://$HOST:$PORT; echo MODE3_RELAYER_INDEX=$RELAYER; echo MODE3_RP_KEY=$KEY; echo MODE3_RP_REGISTRATION_FILE=mode3_rp_${NAME}_registration.json; echo MODE3_RP_LOGIN_LOG=mode3_rp_${NAME}_logins.jsonl; ${COUNTRIES:+echo MODE3_ALLOWED_COUNTRIES=$COUNTRIES;} ${MIN_AGE:+echo MODE3_MIN_AGE=$MIN_AGE;} ${REQ:+echo MODE3_REQUIRE_DISCLOSURE=1;} } > rp_${NAME}.env && chmod 600 rp_${NAME}.env"
  ssh -o BatchMode=yes "$U@$HOST" "cd ~/zkd-demo && set -a && . ./rp_${NAME}.env && set +a && { setsid nohup \$HOME/zkd-demo/bin/node mode3_rp.js > logs/rp_${NAME}.log 2>&1 < /dev/null & }"
  for i in $(seq 1 40); do curl -s -m 2 -o /dev/null "http://$HOST:$PORT/mode3/health" && { echo "$NAME up at http://$HOST:$PORT (승인 대기)"; exit 0; }; sleep 1; done
  echo "$NAME failed — $HOST 의 ~/zkd-demo/logs/rp_${NAME}.log" >&2; exit 1
fi
```
(`mode3_rp.js` 의 프로세스 식별에 `rp_${NAME}` 가 명령줄에 없으므로 VM `--stop` 은 포트로: `ssh … "pid=\$(ss -ltnp | grep ':$PORT ' | grep -oE 'pid=[0-9]+' | cut -d= -f2); [ -n \"\$pid\" ] && kill \$pid"` 로 쓴다.)

- [ ] **Step 2:** `chmod +x`, `bash -n`. `.gitignore` 에 `mode3_rp_*` 와 `*.bak-*`.
- [ ] **Step 3:** 수동 검증은 B9.
- [ ] **Step 4: 커밋 제안** — `feat(scripts): new_rp.sh — RP 페이지 키로 새 RP 서버 한 줄 기동(로컬·VM)`

### Task B8: 체험 모드 단계·페이지 id

**Files:**
- Modify: `mode3/common/strings.js`(steps: `rp_create` 추가, `register` where/target 변경, `revoke` where `account`→`idp_user`), `mode3/common/demo.js`(페이지 집합에 `idp_user`·`idp_rp`; `account` 제거), `tests/test_mode3_demo_strings.js:70`(`TOUR_PAGES`), `tests/test_mode3_tour.mjs`

- [ ] **Step 1:** `TOUR_PAGES = ['rp', 'rp_admin', 'wallet', 'admin', 'idp_user', 'idp_rp']`; steps:
```js
    { key: 'rp_create', where: ['idp_rp'], target: { idp_rp: 'rpCreateBtn' }, ko: { title: 'RP 만들기', hint: 'RP 운영자가 IdP 에서 RP 계정을 만들고 서버를 띄웁니다.' }, en: { title: 'Create an RP', hint: 'The RP operator creates an RP at the IdP and starts the server.' },
      tour: { ko: { title: '1. RP 를 만드세요', body: 'RP 운영자 계정으로 로그인해 "새 RP 만들기" 를 누르면 키와 실행 명령이 나옵니다. 그 명령으로 RP 서버를 띄우면 등록 요청이 IdP 로 갑니다.' }, en: { … } } },
```
`approve` 의 tour 제목 번호를 2 로, `register` 를 `{ key:'register', where:['idp_user'], target:{ idp_user:'registerBtn' }, …tour '3. 가입하고 커밋먼트를 등록하세요' }`, 이후 번호 +1(login 4, login2 5, use 6, disclose 7, revoke 8, open 9). `revoke.where` 의 `account` → `idp_user`, `target.idp_user: 'revokeBtn'`. `demo.js` 에서 페이지별 분기(`D.page === 'account'`)를 `idp_user` 로. 체험 모드 조건(`cond: 'rp_approved'` 등)은 그대로.
- [ ] **Step 2:** `node tests/test_mode3_demo_strings.js`, `node tests/test_mode3_tour.mjs`(단계 번호·페이지 기대값 갱신).
- [ ] **Step 3: 커밋 제안** — `feat(tour): RP 만들기 단계, 등록 단계를 IdP 사용자 페이지로`

### Task B9: 리셋 스크립트·런북·메모리·E2E

**Files:**
- Modify: `scripts/demo_web_reset.sh`, `scripts/demo_split_start.sh`(IdP env `CIA_ISSUE_AUTH=code`, `CIA_DEMO_ACCOUNTS` 미설정; 요약 출력에 `/user`·`/rp`·`new_rp.sh` 안내; Snap 재설치 안내), `docs/MODE3_DEMO.md`(시연 순서 §8, 복구 코드 절 아래에 "IdP 페이지·폐기 상한" 절), `results/`(A3)
- 메모리: 컨트롤러가 `project_mode3_split_vm_demo.md`·새 메모리 `project_mode3_idp_pages_revocation_bound.md` 에 기록

- [ ] **Step 1:** 두 스크립트 IdP env 에 `CIA_ISSUE_AUTH=code` 추가(`ISSUE_AUTH=key` 옵션으로 끌 수 있게 `"${ISSUE_AUTH:-code}"`). 요약 줄에 `사용자 http://…:4100/user · RP 운영자 http://…:4100/rp · 새 RP: bash scripts/new_rp.sh <name> <port> <key> [--host IP]`.
- [ ] **Step 2: 런북** — "시연 순서(2026-10-22)" 절: ① `/rp` 운영자 가입 → zkTHREE 만들기 → 명령 실행 ② `/admin` 승인 ③ `/user` 가입 → 커밋먼트 등록(지갑 팝업·Snap 확인) ④ 지갑 페이지에서 auid 복사 ⑤ zkONE 로그인 → Snap 동의 → IdP 인증 창(uid·비밀번호·auid) → 성공 ⑥ 거래 2건 → 세션 폐기(허용 수 = 현재 nonce) → 같은 RP 재로그인 → "지금 반영" ⑦ 이후 기존 단계. Snap 재설치(체크섬 변경), `CIA_ISSUE_AUTH`, `MODE3_RP_KEY`, 한계(에이전트 모드 Google 없음, 전파 지연, 피싱 창).
- [ ] **Step 3: E2E(한 머신 Snap)** — 컨트롤러가 라이브 포트 사용 여부를 확인한 뒤 `AUTO_APPROVE=1 bash scripts/demo_snap_reset.sh` → 브라우저 테스트 하네스 대신 `tests/test_mode3_browser.mjs` 가 격리 스택으로 같은 흐름을 이미 덮는다. 추가로 `bash scripts/new_rp.sh zkTHREE 3102 <key>`(키는 `curl -c jar -b jar` 로 `/cia/rp/signup`·`/cia/rp/login`·`/cia/rp/create` 를 불러 얻는다) → `/cia/rps` 에 zkTHREE pending → `/cia/rps/<arid>/approve` → `GET /cia/rp_origins` 에 `http://localhost:3102` → 에이전트 `OPTIONS /wallet/login`(Origin 3102) ACAO 확인.
- [ ] **Step 4: 전 묶음** — `npm test`(unit+circuit), `bash scripts/run_tests.sh chain`, `contract`, `browser`, `snap` 전부 통과.
- [ ] **Step 5: 분리 데모 반영** — `SYNC=1 bash scripts/demo_split_snap_reset.sh`(VM 에 `build/mode3`·코드 재전송: SYNC 의 FILES 에 `build/mode3/pi_cred_vkey.json` 등은 이미 있다 — 새 vkey·검증기가 간다) → 승인 → 지갑 페이지 MetaMask Snap 재설치 → ①~⑥ 수동 확인.
- [ ] **Step 6: 커밋 제안** — `docs/scripts(mode3): 데모 리셋에 발급 코드 정책·IdP 페이지 안내, 런북 시연 순서 갱신`

---

## 자체 검토 메모

- 스펙 A §3~§8 ↔ A1~A8·A3·B9(벤치); 스펙 B §3 ↔ B1·B2·B3, §4 ↔ B5(+B3 `/login`), §5 ↔ B4·B5·B6, §6 ↔ B2·B7, §7 ↔ B8, §8 ↔ B9, §9 ↔ 각 태스크 테스트. 스펙 B §4 의 Google 버튼은 Global Constraints 대로 web 모드 복귀 때(계획 밖).
- 이름 일관성: `sessionLeaf(Cf_s, bound)`·`sessionLeafRange(Cf_s, counter)`·`getRangeNonMembershipWitness(lo, hi)`·`LOGIN_COUNTER`·`PUB_INDEX.COUNTER`·`setSessionBound(pk_i, bound)`·`sessionBound(pk_i)`(저장값 c+1)·`/wallet/session/revoke {r_s, bound}`·`pendingBounds[].id`·`/wallet/bounds/apply {id, r_s}`·`mode3-register`·`mode3-register-result`·`mode3-idp-auth {nonce, code}`·`auth_code`·`rp_key`·`/cia/rp_origins`.
- 순서 의존: A3(빌드) 뒤에야 A4·A5·A7 의 실제 π 테스트가 통과한다. B6(Snap)은 A8·B5 의 브라우저 케이스를 통과시키는 마지막 조각이다 — 컨트롤러는 A8·B5 의 "통과 확인" 을 B6 뒤로 미루고 B6 뒤에 `tests/test_mode3_browser.mjs` 를 한 번에 돈다.
- web 모드 코어의 거래 호환은 Task A7b 가 맡는다(사용자 결정 2026-10-23) — web 테스트 묶음도 초록을 유지한다.
