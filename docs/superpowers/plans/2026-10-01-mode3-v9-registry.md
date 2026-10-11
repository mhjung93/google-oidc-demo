# Mode 3 V9 등록부·등록 키·속성 6슬롯·시연 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 사용자 자격증명의 활성 여부를 공개 등록부(사용자별 슬롯, 키 cm_u → 활성 H(C_u))로 옮기고, π_RP 가 "내 슬롯에 내 자격증명이 있다 + salt 가 등록 커밋먼트와 같다"를 증명하게 하며, 폐기 트리는 세션 리프만 남긴다. 같은 회로 판(V9)에 속성 슬롯 4 → 6, 등록 키 지갑 생성, 시연용 관리자 슬롯 바꿔치기·지갑 salt/uid 덮어쓰기를 넣는다.

**Architecture:** 등록부 = 깊이 20 증분 머클 트리(CIA 가 관리, `cia_state.json` 저장), 로그 컨트랙트 V2 `Mode3Log` 가 폐기 root 와 등록부 root 를 같은 트랜잭션에 게시하고 `SlotUpdated` 이벤트를 낸다. 회로 V9 는 사용자 리프 비멤버십을 빼고 조건 9(cm_u 재계산 + 20단 포함)를 넣으며 공개 입력이 30개가 된다. 지갑은 두 트리를 체인 이벤트에서 복원하고, 자기 슬롯이 자기 자격증명인지 확인해 표시한다.

**Tech Stack:** Node 22 ESM, circom 2 + circomlib + snarkjs(Groth16, pot21_final.ptau), Solidity 0.8.24 + hardhat, ethers v6, express, circomlibjs(Poseidon·Baby Jubjub·EdDSA), Playwright(Chrome).

**Spec:** `docs/superpowers/specs/2026-10-01-mode3-v9-registry-design.md` (근거 메모 `2026-10-01-mode3-credential-registry-memo.md`)

## Global Constraints

- 공개 입력 30개 순서(스펙 §5.1, 글자 그대로): `[0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot [7] regRoot [8] pk_CIA_x [9] pk_CIA_y [10] pk_trace_x [11] pk_trace_y [12] tag_c1_x [13] tag_c1_y [14] tag_c2 [15] disc_mask [16..21] disc_lo[6] [22..27] disc_hi[6] [28] set_sel [29] set_root`.
- 등록부 리프 `L_reg(cm_u, Cf_u) = Poseidon(cm_u.x, cm_u.y, Cf_u)`, 빈 칸·은퇴 = 0, 깊이 `REG_DEPTH = 20`, 내부 노드 `Poseidon(left, right)`, 영리프 0.
- 세션 폐기 리프 `Poseidon(5, Cf_s)` 그대로. **사용자 리프 `Poseidon(4, Cf_u)` 는 V9 회로가 보지 않고 CIA 도 더 이상 넣지 않는다.**
- 속성 슬롯 6개, 값은 64비트 정수(`ATTR_SLOTS = 6`, `ATTR_MAX = 2^64`). 제너레이터 `attr4`·`attr5` 는 circomlibjs `pedersenHash.getBasePoint(9)`·`getBasePoint(10)` 의 좌표를 JS 와 회로에 같은 글자로 둔다.
- 등록 메시지 `registerMessage(uid, cm_u) = Poseidon(D_REG, uid, cm_u.x, cm_u.y)`, `D_REG = BigInt('0x' + Buffer.from('MODE3REGISTER').toString('hex'))`. CIA 는 sk_u 를 더 이상 만들지도 내려주지도 않는다.
- 로그 V2 다이제스트 `keccak256(abi.encode(DOMAIN, address(this), revRoot, regRoot, epoch, keccak(abi.encodePacked(revLeaves)), keccak(abi.encodePacked(slotIdx)), keccak(abi.encodePacked(slotLeaves))))`, `DOMAIN = keccak256("MODE3_LOG_V2")`.
- σ_tx 다이제스트 = 현행 필드에서 lo/hi 가 `uint256[6]` 이 되고 태그 인덱스가 `pub[12..14]`, 성명 필드가 `pub[3], pub[5], pub[12], pub[13], pub[14]` 로 옮겨간 것. 꼬리 = `pub[15..29]` 15워드(480바이트).
- 데모 계정 속성(cia.js `DEMO_ACCOUNTS`): testuser `['1990','410','2','0','0','0']`, alice `['2005','840','1','0','0','0']`. 모든 테스트의 4슬롯 상수는 6슬롯으로 바꾼다.
- CLAUDE.md: `cia_state.json`·`idp_state.json` 삭제 금지. 회로 산출물 재생성(`bash scripts/build_mode3_circuit.sh pot21_final.ptau`)은 스펙 §5.5 로 허가됨 — Task 4 에서만 돌린다. git push 는 하지 않는다(커밋만). 모든 커밋 메시지는 한글, 끝에 `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` 과 `Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN`.
- 테스트는 `node <file>` 로 직접 돌린다. `chain` 그룹은 :8545 hardhat 노드가 필요하다 — 없으면 `npx hardhat node` 를 백그라운드로 띄우고 작업 끝에 내린다(이미 떠 있는 노드는 건드리지 않는다). 상태 파일·포트 :4100/:5100/:3100 은 건드리지 않는다(격리 헬퍼만 쓴다).

---

## 파일 구조 (한눈에)

| 파일 | 역할 | Task |
|---|---|---|
| `lib/mode3_credential.js` | `ATTR_SLOTS = 6`, 제너레이터 attr4·attr5 | 1 |
| `circuits/lib/mode3_commit.circom` | `CommitUser` 슬롯 6, 새 `RegistrationCommit` | 1 |
| `lib/mode3_registry.js` (새) | 깊이 20 슬롯 트리, `registryLeaf` | 2 |
| `lib/mode3_issuance.js`, `lib/mode3_wallet.js` | `registerMessage`, 등록 키 생성·서명 | 3 |
| `circuits/lib/merkle_inclusion.circom` (새), `circuits/pi_cred.circom` | V9 회로 | 4 |
| `tests/helpers/mode3_fixture.mjs`, `tests/test_pi_cred_witness.mjs`, `build/mode3/*`, `contracts/PiCredVerifier.sol` | 픽스처·회로 테스트·산출물 | 4 |
| `contracts/Mode3Log.sol` (새), `lib/mode3_log.js`, `tests/helpers/mode3_chain.mjs`, `scripts/deploy_mode3_log.cjs`, `test/Mode3Log.test.mjs` (새) | 로그 V2 | 5 |
| `contracts/Mode3Wallet.sol`, `Mode3WalletFactory.sol`, `AttrGate.sol`, `lib/mode3_onchain.js`, `test/Mode3Wallet.test.mjs`, `test/AttrGate.test.mjs`, `test/Mode3ReferenceCode.test.mjs` | 계정 컨트랙트 30 입력 | 6 |
| `lib/mode3_cia_state.js`, `cia.js`, `tests/test_mode3_cia_state_v9.js` (새), `tests/test_cia_registry.mjs` (새), `tests/test_cia_register_issue.mjs` | CIA 등록부·등록·발급·폐기·게시 | 7, 8 |
| `cia.js`, `mode3/cia_admin.html`, `mode3/common/strings.js` | 관리자 tamper/restore·속성 6 | 9 |
| `lib/mode3_registry_sync.js` (새), `lib/mode3_wallet.js`, `lib/mode3_rcl_sync.js`, `lib/mode3_rp.js`, `mode3_rp.js`, `tests/test_mode3_e2e.mjs` | 지갑 라이브러리·RP 검증기 | 10 |
| `tests/helpers/mode3_chain.mjs`(`publishV2`), `tests/test_mode3_wallet.mjs`, `tests/test_mode3_rp.mjs`, `tests/test_mode3_rcl_sync.mjs`, `tests/test_cia_opening.mjs` | 라이브러리 체인 테스트 이전 | 11 |
| `mode3_wallet_agent.js`, `lib/mode3_secret_source.js`, `cia.js`(`/cia/slot`), `tests/test_mode3_wallet_agent.mjs` | 지갑 에이전트 | 12 |
| `snap-mode3/src/index.js`, `snap-mode3/src/crypto.js`, `tests/helpers/snap_sim.mjs`, `snap-mode3/test/rpc.test.mjs`, `tests/test_mode3_wallet_snap.mjs`, `mode3/wallet.html`(등록 흐름) | Snap 등록 키 | 13 |
| `mode3/wallet.html`, `mode3/rp.html`, `mode3/common/strings.js`, `tests/test_mode3_browser.mjs`, `tests/test_mode3_tour.mjs` | 화면: 속성 6행, 등록부 줄, 시연 카드 | 14 |
| `tests/test_mode3_demo_stack.mjs`, `scripts/run_tests.sh`, `docs/MODE3_DEMO.md` | 전 구간·문서 | 15 |
| `scripts/bench_mode3_onchain.mjs`, `results/mode3_v9_registry_<날짜>.md` | 벤치 | 16 |

Task 순서는 의존 순서다: 1 → 2 → 3 → 4(산출물 재생성) → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16. Task 4 가 끝나기 전에는 `build/mode3` 의 zkey 가 옛 회로라 chain·contract 그룹이 깨진다 — Task 1~3 은 unit·circuit 테스트만 돌린다.

---

### Task 1: 속성 6슬롯 — 제너레이터 2개와 `ATTR_SLOTS`

**Files:**
- Modify: `lib/mode3_credential.js:16-17`(ATTR_SLOTS), `lib/mode3_credential.js:34-52`(PEDERSEN_GENERATORS), `lib/mode3_credential.js:102-116`(userCommit 주석)
- Modify: `lib/mode3_issuance.js:91-103, 107-127`(`[0, 1, 2, 3]` → 슬롯 수)
- Modify: `circuits/lib/mode3_commit.circom:39-100`(CommitUser), 끝에 `RegistrationCommit` 추가
- Modify: `tests/test_mode3_commit_scheme.mjs`(입력 attrs 6개)
- Create: `tests/test_mode3_v9_lib.js`
- Modify: `scripts/run_tests.sh`(UNIT 배열에 `tests/test_mode3_v9_lib.js`)

**Interfaces:**
- Produces: `PEDERSEN_GENERATORS.attr4`, `.attr5` (bigint[2]), `ATTR_SLOTS === 6`, `normalizeAttrs(attrs)` → 길이 6 bigint[]. 회로 `CommitUser()` 의 `attrs[6]`; 새 템플릿 `RegistrationCommit()` — `signal input s_u, r_u; signal output Cx, Cy` (cm_u = s_u·G_SU + r_u·H_BLIND, 250비트 스칼라).

- [ ] **Step 1: 두 점의 좌표를 계산한다**

Run:
```bash
node -e "
import('circomlibjs').then(async ({ buildPedersenHash }) => {
  const ph = await buildPedersenHash();
  for (const i of [9, 10]) { const P = ph.getBasePoint(i); console.log(i, ph.babyJub.F.toObject(P[0]).toString(), ph.babyJub.F.toObject(P[1]).toString()); }
});"
```
Expected: 두 줄, 각각 인덱스와 x·y 10진. (아래 테스트가 같은 계산으로 대조하므로 값을 베껴 쓸 때 한 자라도 틀리면 테스트가 잡는다.) circomlib `pedersen.circom` 의 `BASE[9]` 가 `getBasePoint(9)` 와 같은지도 눈으로 확인한다(`grep -n "BASE\[9\]" -A2 circuits/lib/pedersen.circom` 은 없음 — 표는 `var BASE[10][2] = [...]` 한 덩어리다. 10번째 항목이 index 9).

- [ ] **Step 2: 실패하는 단위 테스트를 쓴다**

`tests/test_mode3_v9_lib.js`:
```js
// V9 라이브러리 단위 테스트 — 제너레이터 6개, 속성 6슬롯. (unit 그룹)  node tests/test_mode3_v9_lib.js
import assert from 'node:assert/strict';
import { buildPedersenHash } from 'circomlibjs';
import { PEDERSEN_GENERATORS, ATTR_SLOTS, normalizeAttrs, userCommit } from '../lib/mode3_credential.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

await t('ATTR_SLOTS = 6, normalizeAttrs 는 길이 6 으로 0 패딩', () => {
  assert.equal(ATTR_SLOTS, 6);
  assert.deepEqual(normalizeAttrs(['1990', '410', '2']), [1990n, 410n, 2n, 0n, 0n, 0n]);
  assert.throws(() => normalizeAttrs([1n, 2n, 3n, 4n, 5n, 6n, 7n]), /최대 6개/);
  assert.throws(() => normalizeAttrs([1n << 64n]), /2\^64/);
});
await t('attr4·attr5 = circomlibjs getBasePoint(9)·(10) (회로 상수와 같은 글자)', async () => {
  const ph = await buildPedersenHash();
  const F = ph.babyJub.F;
  for (const [name, i] of [['attr4', 9], ['attr5', 10]]) {
    const P = ph.getBasePoint(i);
    assert.deepEqual([...PEDERSEN_GENERATORS[name]], [F.toObject(P[0]), F.toObject(P[1])], name);
  }
  // 기존 9개도 getBasePoint(0..8) 과 같다 — 표를 옮겨 적다 생긴 오타를 잡는다
  const names = ['uid', 'arid', 's_u', 'pk_i', 'attr0', 'attr1', 'attr2', 'attr3', 'blind'];
  names.forEach((n, i) => { const P = ph.getBasePoint(i); assert.deepEqual([...PEDERSEN_GENERATORS[n]], [F.toObject(P[0]), F.toObject(P[1])], n); });
});
await t('userCommit 은 슬롯 6개를 쓴다 — 5번째 슬롯이 다르면 커밋이 다르다', async () => {
  const base = { uid: 1n, s_u: 2n, blind_u: 3n };
  const a = await userCommit({ ...base, attrs: [1990n, 410n, 2n, 0n, 0n, 0n] });
  const b = await userCommit({ ...base, attrs: [1990n, 410n, 2n, 0n, 7n, 0n] });
  const c = await userCommit({ ...base, attrs: [1990n, 410n, 2n, 0n, 0n, 7n] });
  assert.notEqual(a.Cf, b.Cf); assert.notEqual(a.Cf, c.Cf); assert.notEqual(b.Cf, c.Cf);
});
process.exit(fails ? 1 : 0);
```

- [ ] **Step 3: 실패를 확인한다**

Run: `node tests/test_mode3_v9_lib.js`
Expected: `FAIL - ATTR_SLOTS = 6 ...`(4 !== 6), `FAIL - attr4·attr5 ...`(undefined).

- [ ] **Step 4: `lib/mode3_credential.js` 를 고친다**

`ATTR_SLOTS = 4` → `6`. `PEDERSEN_GENERATORS` 의 `attr3` 다음에 두 항목을 넣는다(Step 1 의 값):
```js
  attr4: Object.freeze([<getBasePoint(9).x>n, <getBasePoint(9).y>n]),
  attr5: Object.freeze([<getBasePoint(10).x>n, <getBasePoint(10).y>n]),
```
주석 `BASE[0..8]` → `BASE[0..10]`(circomlib 표는 0..9 까지라 index 10 은 circomlibjs 로 계산한 값). `userCommit` 의 주석 `attr₀ … attr₃` → `attr₀ … attr₅`.

`lib/mode3_issuance.js` 의 `proveUserCred`·`verifyUserCred` 안 `const GA = [0, 1, 2, 3].map((i) => G(bj, \`attr${i}\`));` 두 곳을 `const GA = Array.from({ length: ATTR_SLOTS }, (_, i) => G(bj, \`attr${i}\`));` 로 바꾸고 import 에 `ATTR_SLOTS` 를 더한다(`import { PEDERSEN_GENERATORS, SCALAR_MAX, normalizeAttrs, ATTR_SLOTS } from './mode3_credential.js';`). 주석의 `a₀..a₃` → `a₀..a₅`.

- [ ] **Step 5: 회로 커밋 가젯을 6슬롯으로, 등록 커밋 템플릿을 추가한다**

`circuits/lib/mode3_commit.circom` 의 `CommitUser`: `signal input attrs[4];` → `attrs[6]`, `var G_ATTR[4][2] = [...]` → `var G_ATTR[6][2]` 에 두 점 추가(Step 1 값, JS 와 같은 순서), `component bAttr[4]`·`mAttr[4]`·`aAttr[4]` 와 네 `for (var j = 0; j < 4; j++)` 루프를 전부 6 으로, `a2.x1 <== aAttr[3].xout; a2.y1 <== aAttr[3].yout;` → `aAttr[5]`. 파일 머리 주석의 `attr₀ … attr₃` 와 `BASE[0..8]` 설명을 갱신한다.

파일 끝에 추가:
```
// V9(2026-10-01 등록부 §5.2 조건 9): 등록 커밋 cm_u = s_u·G_SU + r_u·H — lib/mode3_issuance.js registrationCommit 과 같은 생성원·순서.
// π_RP 가 "C_u 의 s_u 가 등록 때 낸 cm_u 의 s_u 와 같다" 를 보이려고 회로 안에서 다시 계산한다.
template RegistrationCommit() {
    signal input s_u;
    signal input r_u;
    signal output Cx;
    signal output Cy;

    var N = 250;
    var G_SU[2]    = [5802099305472655231388284418920769829666717045250560929368476121199858275951,
                      5980429700218124965372158798884772646841287887664001482443826541541529227896];
    var H_BLIND[2] = [20265828622013100949498132415626198973119240347465898028410217039057588424236,
                      1160461593266035632937973507065134938065359936056410650153315956301179689506];

    component bSu = Num2Bits(N);  bSu.in <== s_u;
    component bRu = Num2Bits(N);  bRu.in <== r_u;
    component mSu = EscalarMulFix(N, G_SU);
    component mRu = EscalarMulFix(N, H_BLIND);
    for (var i = 0; i < N; i++) { mSu.e[i] <== bSu.out[i]; mRu.e[i] <== bRu.out[i]; }
    component a = BabyAdd();
    a.x1 <== mSu.out[0]; a.y1 <== mSu.out[1];
    a.x2 <== mRu.out[0]; a.y2 <== mRu.out[1];
    Cx <== a.xout;
    Cy <== a.yout;
}
```

- [ ] **Step 6: 커밋 회로 테스트를 6슬롯·등록 커밋으로 넓힌다**

`tests/test_mode3_commit_scheme.mjs` 에서 `USER_INPUT` 의 `attrs: ['19', '410', '0', '0']` 을 `['19', '410', '0', '0', '0', '0']` 으로, 아래 `attr 하나만 바꿔도` 케이스의 `['20', '410', '0', '0']` 을 `['20', '410', '0', '0', '0', '0']` 으로, `attrs: [0n, 0n, 0n, 0n]` 을 `[0n, 0n, 0n, 0n, 0n, 0n]` 으로, `생성원 9개` 케이스의 `assert.equal(Object.keys(PEDERSEN_GENERATORS).length, 9, 'uid, arid, s_u, pk_i, attr0..3, blind')` 을 `11, 'uid, arid, s_u, pk_i, attr0..5, blind'` 로(제목도 `생성원 11개`) 바꾸고, `SRC` 에 세 번째 회로를 더한다:
```js
  registration: `pragma circom 2.0.0;
include "lib/mode3_commit.circom";
component main = RegistrationCommit();`,
```
파일 끝 테스트 블록에 추가:
```js
await t('RegistrationCommit 회로 = JS registrationCommit(s_u, r_u)', async () => {
  const { registrationCommit } = await import('../lib/mode3_issuance.js');
  const n = compile('registration', SRC.registration);
  console.log(`   RegistrationCommit 비선형 제약: ${n.toLocaleString()}`);
  const s_u = 123456789n, r_u = 987654321n;
  const cm = await registrationCommit(s_u, r_u);
  const w = await witness('registration', { s_u: s_u.toString(), r_u: r_u.toString() });
  // main.Cx, main.Cy 는 출력 신호 1·2 번(출력은 witness 의 앞에 온다)
  assert.equal(BigInt(w[1]), cm.x); assert.equal(BigInt(w[2]), cm.y);
});
```
(기존 테스트가 `userCommit` 과 회로 출력을 어떻게 대조하는지 그 파일의 패턴(`w[1]`, `w[2]`)을 그대로 따른다.)

- [ ] **Step 7: 테스트를 돌린다**

Run: `node tests/test_mode3_v9_lib.js && node tests/test_mode3_commit_scheme.mjs`
Expected: 둘 다 전부 ok. (`test_mode3_commit_scheme` 는 circom 컴파일을 하므로 1분쯤.)

- [ ] **Step 8: run_tests.sh 에 넣고 커밋**

`scripts/run_tests.sh` 의 `UNIT=(` 배열 끝에 `tests/test_mode3_v9_lib.js` 를 추가.
```bash
git add lib/mode3_credential.js lib/mode3_issuance.js circuits/lib/mode3_commit.circom tests/test_mode3_commit_scheme.mjs tests/test_mode3_v9_lib.js scripts/run_tests.sh
git commit -m "feat(mode3): 속성 6슬롯 — 제너레이터 attr4·attr5, CommitUser 6, RegistrationCommit 가젯 (V9 1/16)"
```

---

### Task 2: 등록부 트리 모듈 `lib/mode3_registry.js`

**Files:**
- Create: `lib/mode3_registry.js`
- Create: `tests/test_mode3_registry.js`
- Modify: `scripts/run_tests.sh`(UNIT 에 추가)

**Interfaces:**
- Produces: `REG_DEPTH = 20`; `registryLeaf(cm_u, Cf_u)` → bigint (`cm_u` 는 `{x, y}` bigint 또는 10진 문자열, `Cf_u` bigint 또는 10진); `createRegistryTree(depth = 20)` → `{ depth, set(index, leaf), leafAt(index), root(), path(index) → { pathElements: bigint[depth], pathIndices: number[depth] }, entries() → [index, leaf][] (0 이 아닌 것만, index 오름차순) }`. 메서드는 동기(생성만 비동기). `verifyPath(leaf, pathElements, pathIndices)` → root 계산(지갑 확인용).

- [ ] **Step 1: 실패하는 테스트**

`tests/test_mode3_registry.js`:
```js
// 등록부 슬롯 트리(스펙 2026-10-01 §3.1). (unit 그룹)  node tests/test_mode3_registry.js
import assert from 'node:assert/strict';
import { buildPoseidon } from 'circomlibjs';
import { REG_DEPTH, registryLeaf, createRegistryTree, computeRoot } from '../lib/mode3_registry.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

await t('빈 트리 root = 영해시 체인, 깊이 20', async () => {
  const ps = await buildPoseidon(); const H = (a, b) => ps.F.toObject(ps([a, b]));
  let z = 0n; for (let i = 0; i < 20; i++) z = H(z, z);
  const tree = await createRegistryTree();
  assert.equal(tree.depth, REG_DEPTH); assert.equal(REG_DEPTH, 20);
  assert.equal(tree.root(), z);
});
await t('registryLeaf = Poseidon(cm.x, cm.y, Cf_u); 문자열 입력도 같다', async () => {
  const ps = await buildPoseidon();
  const a = await registryLeaf({ x: 11n, y: 22n }, 33n);
  assert.equal(a, ps.F.toObject(ps([11n, 22n, 33n])));
  assert.equal(await registryLeaf({ x: '11', y: '22' }, '33'), a);
});
await t('set/leafAt/path: 경로로 root 가 재계산되고, 덮어쓰기·0 으로 비우기가 된다', async () => {
  const tree = await createRegistryTree();
  tree.set(0, 101n); tree.set(5, 505n); tree.set(1023, 7n);
  assert.equal(tree.leafAt(5), 505n); assert.equal(tree.leafAt(6), 0n);
  const { pathElements, pathIndices } = tree.path(5);
  assert.equal(pathElements.length, 20); assert.equal(pathIndices.length, 20);
  assert.deepEqual(pathIndices.slice(0, 4), [1, 0, 1, 0]);   // 5 = 0b101
  assert.equal(await computeRoot(505n, pathElements, pathIndices), tree.root());
  const before = tree.root();
  tree.set(5, 506n); assert.notEqual(tree.root(), before);
  assert.equal(await computeRoot(506n, tree.path(5).pathElements, tree.path(5).pathIndices), tree.root());
  tree.set(5, 0n); tree.set(1023, 0n); tree.set(0, 0n);
  const empty = await createRegistryTree();
  assert.equal(tree.root(), empty.root(), '전부 비우면 빈 트리 root');
  assert.deepEqual(empty.entries(), []);
});
await t('entries 는 0 이 아닌 (index, leaf) 를 index 순으로', async () => {
  const tree = await createRegistryTree();
  tree.set(9, 1n); tree.set(2, 2n); tree.set(9, 0n); tree.set(4, 4n);
  assert.deepEqual(tree.entries(), [[2, 2n], [4, 4n]]);
});
await t('범위 밖 index·음수 리프는 throw', async () => {
  const tree = await createRegistryTree(4);
  assert.throws(() => tree.set(16, 1n), /index/); assert.throws(() => tree.set(-1, 1n), /index/);
  assert.throws(() => tree.set(1, -1n), /leaf/);
});
process.exit(fails ? 1 : 0);
```

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_registry.js` → `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: 구현**

`lib/mode3_registry.js`:
```js
// Mode 3 등록부 — 사용자 자격증명 슬롯 트리(설계 2026-10-01-mode3-v9-registry-design.md §3).
// 깊이 20 증분 머클 트리. 리프 = Poseidon(cm_u.x, cm_u.y, Cf_u), 빈 칸·은퇴 = 0. 내부 노드 = Poseidon(left, right).
// 경로 규약은 회로 circuits/lib/merkle_inclusion.circom 과 같다: pathIndices[i] = (index >> i) & 1, 0 이면 현재 노드가 왼쪽.
// CIA 가 관리하고(cia.js), 지갑은 Mode3Log 의 SlotUpdated 이벤트로 같은 트리를 복원한다(lib/mode3_registry_sync.js).
import { buildPoseidon } from 'circomlibjs';

export const REG_DEPTH = 20;

let poseidonP = null;
const getPoseidon = () => (poseidonP ??= buildPoseidon());
const big = (v) => (typeof v === 'bigint' ? v : BigInt(v));

/** L_reg(cm_u, Cf_u) = Poseidon(cm_u.x, cm_u.y, Cf_u). cm_u 는 {x, y}(bigint 또는 10진 문자열). */
export async function registryLeaf(cm_u, Cf_u) {
  const ps = await getPoseidon();
  return ps.F.toObject(ps([big(cm_u.x), big(cm_u.y), big(Cf_u)]));
}

/** 경로로 root 를 다시 계산한다 — 지갑이 "내 슬롯 = 내 자격증명" 을 체인 root 와 대조할 때 쓴다. */
export async function computeRoot(leaf, pathElements, pathIndices) {
  const ps = await getPoseidon();
  let cur = big(leaf);
  for (let i = 0; i < pathElements.length; i++) {
    const sib = big(pathElements[i]);
    cur = ps.F.toObject(Number(pathIndices[i]) ? ps([sib, cur]) : ps([cur, sib]));
  }
  return cur;
}

export async function createRegistryTree(depth = REG_DEPTH) {
  if (!Number.isInteger(depth) || depth < 1 || depth > 32) throw new Error('createRegistryTree: depth 는 1..32');
  const ps = await getPoseidon();
  const H = (a, b) => ps.F.toObject(ps([a, b]));
  const zeros = [0n];
  for (let i = 0; i < depth; i++) zeros.push(H(zeros[i], zeros[i]));
  const nodes = Array.from({ length: depth + 1 }, () => new Map());   // level → (index → value); 없으면 zeros[level]
  const get = (lvl, idx) => nodes[lvl].get(idx) ?? zeros[lvl];
  const max = 2 ** depth;
  const checkIndex = (index) => { if (!Number.isInteger(index) || index < 0 || index >= max) throw new Error(`registry: index 범위 밖 ${index} (0..${max - 1})`); };
  return {
    depth,
    set(index, leaf) {
      checkIndex(index);
      const v = big(leaf);
      if (v < 0n) throw new Error('registry: leaf 는 음이 아닌 정수');
      if (v === 0n) nodes[0].delete(index); else nodes[0].set(index, v);
      let idx = index;
      for (let lvl = 0; lvl < depth; lvl++) {
        const parent = idx >> 1;
        const h = H(get(lvl, parent * 2), get(lvl, parent * 2 + 1));
        if (h === zeros[lvl + 1]) nodes[lvl + 1].delete(parent); else nodes[lvl + 1].set(parent, h);
        idx = parent;
      }
    },
    leafAt(index) { checkIndex(index); return get(0, index); },
    root() { return get(depth, 0); },
    path(index) {
      checkIndex(index);
      const pathElements = [], pathIndices = [];
      let idx = index;
      for (let lvl = 0; lvl < depth; lvl++) { pathElements.push(get(lvl, idx ^ 1)); pathIndices.push(idx & 1); idx >>= 1; }
      return { pathElements, pathIndices };
    },
    entries() { return [...nodes[0].entries()].sort((a, b) => a[0] - b[0]); },
  };
}
```

- [ ] **Step 4: 통과 확인, 그룹 등록, 커밋**

Run: `node tests/test_mode3_registry.js` → 전부 ok. `scripts/run_tests.sh` UNIT 에 `tests/test_mode3_registry.js` 추가.
```bash
git add lib/mode3_registry.js tests/test_mode3_registry.js scripts/run_tests.sh
git commit -m "feat(mode3): 등록부 슬롯 트리 lib/mode3_registry.js — 깊이 20, 리프 Poseidon(cm_u, Cf_u) (V9 2/16)"
```

---

### Task 3: 등록 키를 지갑이 만든다 — 메시지·서명·키 생성

**Files:**
- Modify: `lib/mode3_issuance.js`(도메인 상수·`registerMessage`)
- Modify: `lib/mode3_wallet.js:30-34`(`createRegistration`), 서명 함수 추가
- Modify: `tests/test_mode3_v9_lib.js`(테스트 추가)

**Interfaces:**
- Produces: `DOMAIN_MODE3_REGISTER`, `registerMessage(uid, cm_u)` → bigint (`lib/mode3_issuance.js`); `createRegistration()` → `{ s_u, r_u, cm_u:{x,y}, sk_u(hex 64), pk_u:{x:bigint,y:bigint} }`; `signRegistration(sk_uHex, uid, cm_u)` → `{R8x, R8y, S}` 10진 문자열; `eddsaPubOf(sk_uHex)` → `{x, y}` bigint (`lib/mode3_wallet.js`).

- [ ] **Step 1: 테스트 추가** (`tests/test_mode3_v9_lib.js` 끝, `process.exit` 앞)

```js
await t('등록 메시지·서명: registerMessage = Poseidon(D_REG, uid, cm.x, cm.y), 지갑 키로 서명·검증', async () => {
  const { registerMessage, DOMAIN_MODE3_REGISTER } = await import('../lib/mode3_issuance.js');
  const { createRegistration, signRegistration, eddsaPubOf } = await import('../lib/mode3_wallet.js');
  const { buildEddsa, buildPoseidon } = await import('circomlibjs');
  assert.equal(DOMAIN_MODE3_REGISTER, BigInt('0x' + Buffer.from('MODE3REGISTER').toString('hex')));
  const ps = await buildPoseidon();
  assert.equal(await registerMessage(12345n, { x: 1n, y: 2n }), ps.F.toObject(ps([DOMAIN_MODE3_REGISTER, 12345n, 1n, 2n])));
  const reg = await createRegistration();
  assert.match(reg.sk_u, /^[0-9a-f]{64}$/); assert.equal(typeof reg.pk_u.x, 'bigint');
  assert.deepEqual(await eddsaPubOf(reg.sk_u), reg.pk_u);
  const sig = await signRegistration(reg.sk_u, 12345n, reg.cm_u);
  const eddsa = await buildEddsa(); const F = eddsa.F;
  const m = F.e(await registerMessage(12345n, reg.cm_u));
  const ok = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig.R8x)), F.e(BigInt(sig.R8y))], S: BigInt(sig.S) }, [F.e(reg.pk_u.x), F.e(reg.pk_u.y)]);
  assert.equal(ok, true);
  const other = await createRegistration();
  assert.equal(eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig.R8x)), F.e(BigInt(sig.R8y))], S: BigInt(sig.S) }, [F.e(other.pk_u.x), F.e(other.pk_u.y)]), false);
});
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_v9_lib.js` → 마지막 케이스 FAIL(export 없음).

- [ ] **Step 3: 구현**

`lib/mode3_issuance.js` — `DOMAIN_MODE3_REVOKESESS` 줄 아래:
```js
export const DOMAIN_MODE3_REGISTER = BigInt('0x' + Buffer.from('MODE3REGISTER').toString('hex'));   // /cia/register 소유 증명 서명(V9, 2026-10-01 §7.1)
```
`revokeSessionMessage` 아래:
```js
/** /cia/register 의 소유 증명 메시지 = Poseidon(D_REGISTER, uid, cm_u.x, cm_u.y). 지갑이 만든 sk_u 로 서명한다 — CIA 는 sk_u 를 만들지 않는다(V9). */
export async function registerMessage(uid, cm_u) {
  if (typeof uid !== 'bigint' || uid < 0n || uid >= SCALAR_MAX) throw new Error('registerMessage: uid 는 [0, 2^250) bigint');
  if (typeof cm_u?.x !== 'bigint' || typeof cm_u?.y !== 'bigint') throw new Error('registerMessage: cm_u{x,y}(bigint) 가 필요하다');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_REGISTER, uid, cm_u.x, cm_u.y]));
}
```
`lib/mode3_wallet.js` — import 에 `registerMessage` 추가, `createRegistration` 교체:
```js
import { randomBytes } from 'node:crypto';
...
/** EdDSA-Poseidon 공개키 (circomlibjs eddsa.prv2pub). sk_u 는 32바이트 hex. */
export async function eddsaPubOf(sk_uHex) {
  const eddsa = await getEddsa();
  const pub = eddsa.prv2pub(Buffer.from(sk_uHex, 'hex'));
  return { x: eddsa.F.toObject(pub[0]), y: eddsa.F.toObject(pub[1]) };
}
/** §6.1 + V9 §7.1 — s_u, r_u 는 randomScalar(2^250 미만), cm_u 를 CIA 에 낸다. 등록 키 (sk_u, pk_u) 도 여기서 만든다 — CIA 는 pk_u 만 받는다. */
export async function createRegistration() {
  const s_u = randomScalar(), r_u = randomScalar();
  const sk_u = randomBytes(32).toString('hex');
  return { s_u, r_u, cm_u: await registrationCommit(s_u, r_u), sk_u, pk_u: await eddsaPubOf(sk_u) };
}
/** /cia/register 소유 증명 = Sign(sk_u, Poseidon(D_REGISTER, uid, cm_u.x, cm_u.y)). */
export async function signRegistration(sk_uHex, uid, cm_u) {
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await registerMessage(uid, cm_u))));
}
```
(`sigStrings` 는 파일에 이미 있다 — `createRegistration` 보다 아래에 정의돼 있으니 함수 선언 호이스팅으로 쓸 수 있지만 `const` 라면 안 된다. 파일의 `const sigStrings = ...` 는 호출 시점에 정의돼 있으면 되므로 `signRegistration` 이 그 아래에 오도록 둔다.)

- [ ] **Step 4: 통과·커밋**

Run: `node tests/test_mode3_v9_lib.js` → 전부 ok.
```bash
git add lib/mode3_issuance.js lib/mode3_wallet.js tests/test_mode3_v9_lib.js
git commit -m "feat(mode3): 등록 키를 지갑이 생성 — registerMessage·signRegistration·eddsaPubOf (V9 3/16)"
```

---

### Task 4: 회로 V9 — 포함 가젯, 조건 9, 공개 입력 30, 산출물 재생성

**Files:**
- Create: `circuits/lib/merkle_inclusion.circom`
- Modify: `circuits/pi_cred.circom` (전체 교체 — 아래 코드)
- Modify: `tests/helpers/mode3_fixture.mjs` (전체 교체)
- Modify: `tests/test_pi_cred_witness.mjs`
- Regenerate: `build/mode3/*`, `contracts/PiCredVerifier.sol` (`bash scripts/build_mode3_circuit.sh pot21_final.ptau`, 그 뒤 `npx hardhat compile`)

**Interfaces:**
- Consumes: Task 1 `CommitUser`(attrs[6])·`RegistrationCommit`, Task 2 `createRegistryTree`·`registryLeaf`.
- Produces: 회로 입력 이름 — 비공개 `uid, s_u, r_u, blind_u, blind_s, attrs[6], r, S, R8x, R8y, s_lowValue, s_lowNextIndex, s_lowNextValue, s_pathElements[32], s_pathIndices[32], reg_pathElements[20], reg_pathIndices[20], set_index, set_path[8]`; 공개 30개(Global Constraints 순서). `buildValidInput(opts)` → `{ input, Cf_u, Cf_s, pk_trace, shares, tag, ciaPub, arid, uid, tree(폐기), registry(등록부 트리), slot, cm_u, attrs, disclosure, set }` — `opts.disclosure.lo/hi` 는 길이 6, `opts.set.slot` 0..5, 새 옵션 `registrySlot`(기본 7)·`registryLeafOverride`(리프 강제, 음성용).

- [ ] **Step 1: 포함 가젯**

`circuits/lib/merkle_inclusion.circom`:
```
pragma circom 2.0.0;

include "poseidon.circom";
include "mux1.circom";

// 깊이 depth 머클 포함 증명(V9 등록부, 설계 2026-10-01 §5.2 조건 9). lib/mode3_registry.js 와 같은 규약:
//   내부 노드 = Poseidon(left, right), pathIndices[i] = (index >> i) & 1, 0 이면 현재 노드가 왼쪽 자식.
// pi_cred 의 집합 소속 경로(깊이 8)와 같은 MultiMux1 배선을 매개변수화한 것이다.
template MerkleInclusion(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    component mux[depth];
    component hash[depth];
    signal cur[depth + 1];
    cur[0] <== leaf;
    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;
        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== cur[i];            mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];   mux[i].c[1][1] <== cur[i];
        mux[i].s <== pathIndices[i];
        hash[i] = Poseidon(2);
        hash[i].inputs[0] <== mux[i].out[0];
        hash[i].inputs[1] <== mux[i].out[1];
        cur[i + 1] <== hash[i].out;
    }
    root <== cur[depth];
}
```

- [ ] **Step 2: 회로 V9** — `circuits/pi_cred.circom` 전체를 아래로 교체한다(머리 주석은 기존 것을 유지하고 V9 줄을 더한다).

```
pragma circom 2.0.0;

include "lib/eddsaposeidon.circom";
include "lib/poseidon.circom";
include "lib/imt_nonmembership_v2.circom";
include "lib/merkle_inclusion.circom";
include "lib/bitify.circom";
include "lib/comparators.circom";
include "lib/mux1.circom";
include "lib/mode3_commit.circom";
include "lib/mode3_trace_tag.circom";

// (기존 머리 주석 V4~V8 유지)
// V9(2026-10-01): 등록부 — 사용자 리프 비멤버십(④)을 빼고 조건 ⑨ "cm_u = s_u·G_SU + r_u·H 를 다시 만들어 리프 Poseidon(cm.x, cm.y, Cf_u) 가
//   깊이 20 등록부(regRoot)에 있다" 를 넣는다. 속성 6슬롯, 공개 입력 30. 설계 docs/superpowers/specs/2026-10-01-mode3-v9-registry-design.md §5
template PiCred(depth, regDepth) {
    // ---- Private ----
    signal input uid;
    signal input s_u;
    signal input r_u;        // V9: 등록 커밋 cm_u 의 블라인딩 — 조건 ⑨
    signal input blind_u;
    signal input blind_s;
    signal input attrs[6];
    signal input r;

    signal input S;
    signal input R8x;
    signal input R8y;

    // V8 세션 리프 비멤버십 증인(폐기 트리). V9 에서 사용자 리프 증인은 없다.
    signal input s_lowValue;
    signal input s_lowNextIndex;
    signal input s_lowNextValue;
    signal input s_pathElements[depth];
    signal input s_pathIndices[depth];

    // V9 등록부 경로(비공개). 슬롯 번호는 pathIndices 비트에만 있다 — 공개되지 않는다.
    signal input reg_pathElements[regDepth];
    signal input reg_pathIndices[regDepth];

    // V7 집합 소속 경로(비공개)
    signal input set_index;
    signal input set_path[8];

    // ---- Public (순서 = lib/mode3_wallet.js·lib/mode3_rp.js·contracts/Mode3Wallet.sol 의 계약) ----
    signal input PPID;
    signal input arid;
    signal input pk_i;
    signal input max_height;
    signal input chainid;
    signal input allowAgent;
    signal input revRoot;
    signal input regRoot;
    signal input pk_CIA_x;
    signal input pk_CIA_y;
    signal input pk_trace_x;
    signal input pk_trace_y;
    signal input tag_c1_x;
    signal input tag_c1_y;
    signal input tag_c2;
    signal input disc_mask;
    signal input disc_lo[6];
    signal input disc_hi[6];
    signal input set_sel;
    signal input set_root;

    var DOMAIN_MODE3_CRED_V5 = 93461614427473393731524149;  // ASCII "MODE3CREDV5" — 서명 도메인은 V9 에서도 그대로(메시지 모양 불변)
    var TAG_MODE3_SESSION = 5;

    component pkIRange = Num2Bits(160);
    pkIRange.in <== pk_i;

    // ---- ② 커밋 둘 ----
    component cu = CommitUser();
    cu.uid <== uid;  cu.s_u <== s_u;  cu.blind_u <== blind_u;
    for (var j = 0; j < 6; j++) cu.attrs[j] <== attrs[j];
    component cfu = Poseidon(2);
    cfu.inputs[0] <== cu.Cx;  cfu.inputs[1] <== cu.Cy;
    signal Cf_u;
    Cf_u <== cfu.out;
    component cs = CommitSession();
    cs.arid <== arid;  cs.pk_i <== pk_i;  cs.blind_s <== blind_s;
    component cfs = Poseidon(2);
    cfs.inputs[0] <== cs.Cx;  cfs.inputs[1] <== cs.Cy;
    signal Cf_s;
    Cf_s <== cfs.out;

    // ---- ① CIA 서명 ----
    component mhRange = Num2Bits(64);
    mhRange.in <== max_height;
    allowAgent * (allowAgent - 1) === 0;
    component msgHasher = Poseidon(6);
    msgHasher.inputs[0] <== DOMAIN_MODE3_CRED_V5;
    msgHasher.inputs[1] <== Cf_u;
    msgHasher.inputs[2] <== Cf_s;
    msgHasher.inputs[3] <== max_height;
    msgHasher.inputs[4] <== chainid;
    msgHasher.inputs[5] <== allowAgent;
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== pk_CIA_x;
    sigVerifier.Ay <== pk_CIA_y;
    sigVerifier.S <== S;
    sigVerifier.R8x <== R8x;
    sigVerifier.R8y <== R8y;
    sigVerifier.M <== msgHasher.out;

    // ---- ③ PPID ----
    component ppidHasher = Poseidon(4);
    ppidHasher.inputs[0] <== uid;
    ppidHasher.inputs[1] <== s_u;
    ppidHasher.inputs[2] <== chainid;
    ppidHasher.inputs[3] <== arid;
    PPID === ppidHasher.out;

    // ---- ④′ 세션 비멤버십 (폐기 트리) ----
    component sLeaf = Poseidon(2);
    sLeaf.inputs[0] <== TAG_MODE3_SESSION;
    sLeaf.inputs[1] <== Cf_s;
    component nmS = IMTNonMembershipV2(depth);
    nmS.target <== sLeaf.out;
    nmS.lowValue <== s_lowValue;
    nmS.lowNextIndex <== s_lowNextIndex;
    nmS.lowNextValue <== s_lowNextValue;
    for (var i = 0; i < depth; i++) {
        nmS.pathElements[i] <== s_pathElements[i];
        nmS.pathIndices[i] <== s_pathIndices[i];
    }
    nmS.root <== revRoot;

    // ---- ⑨ 등록부 멤버십 (V9) ----
    // cm_u 를 s_u·r_u 로 다시 만든다. s_u 는 ②·③ 과 같은 신호 — 등록 때 낸 salt 와 지금 PPID 의 salt 가 같다는 뜻이다.
    component rc = RegistrationCommit();
    rc.s_u <== s_u;  rc.r_u <== r_u;
    component regLeaf = Poseidon(3);
    regLeaf.inputs[0] <== rc.Cx;  regLeaf.inputs[1] <== rc.Cy;  regLeaf.inputs[2] <== Cf_u;
    component inc = MerkleInclusion(regDepth);
    inc.leaf <== regLeaf.out;
    for (var i = 0; i < regDepth; i++) {
        inc.pathElements[i] <== reg_pathElements[i];
        inc.pathIndices[i] <== reg_pathIndices[i];
    }
    inc.root === regRoot;

    // ---- ⑤ 트레이스 태그 ----
    component rNZ = IsZero();
    rNZ.in <== r;
    rNZ.out === 0;
    component tag = TraceTag();
    tag.r <== r;
    tag.uid <== uid;
    tag.arid <== arid;
    tag.pk_trace_x <== pk_trace_x;
    tag.pk_trace_y <== pk_trace_y;
    tag_c1_x === tag.c1x;
    tag_c1_y === tag.c1y;
    tag_c2 === tag.c2;

    // ---- ⑥ 선택 공개 (슬롯 6) ----
    component maskBits = Num2Bits(6);
    maskBits.in <== disc_mask;
    component loBits[6]; component hiBits[6]; component ge[6]; component le[6];
    signal discOk[6];
    for (var k = 0; k < 6; k++) {
        loBits[k] = Num2Bits(64); loBits[k].in <== disc_lo[k];
        hiBits[k] = Num2Bits(64); hiBits[k].in <== disc_hi[k];
        ge[k] = LessEqThan(64); ge[k].in[0] <== disc_lo[k]; ge[k].in[1] <== attrs[k];
        le[k] = LessEqThan(64); le[k].in[0] <== attrs[k];   le[k].in[1] <== disc_hi[k];
        discOk[k] <== ge[k].out * le[k].out;
        maskBits.out[k] * (1 - discOk[k]) === 0;
    }

    // ---- ⑦ 집합 소속 (set_sel ∈ {0..6}) ----
    component selIs[7];
    var selSum = 0;
    for (var j = 0; j < 7; j++) {
        selIs[j] = IsEqual();
        selIs[j].in[0] <== set_sel;
        selIs[j].in[1] <== j;
        selSum += selIs[j].out;
    }
    selSum === 1;
    signal selTerm[6];
    for (var k = 0; k < 6; k++) selTerm[k] <== selIs[k + 1].out * attrs[k];
    signal setVal;
    setVal <== selTerm[0] + selTerm[1] + selTerm[2] + selTerm[3] + selTerm[4] + selTerm[5];
    component setInc = MerkleInclusion(8);
    setInc.leaf <== setVal;
    component setIdxBits = Num2Bits(8);
    setIdxBits.in <== set_index;
    for (var i = 0; i < 8; i++) {
        setInc.pathElements[i] <== set_path[i];
        setInc.pathIndices[i] <== setIdxBits.out[i];
    }
    (1 - selIs[0].out) * (setInc.root - set_root) === 0;
    selIs[0].out * set_root === 0;
}

// [0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot [7] regRoot [8,9] pk_CIA [10,11] pk_trace
// [12..14] tag [15] disc_mask [16..21] disc_lo [22..27] disc_hi [28] set_sel [29] set_root
component main {public [
    PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, regRoot, pk_CIA_x, pk_CIA_y,
    pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2,
    disc_mask, disc_lo, disc_hi, set_sel, set_root
]} = PiCred(32, 20);
```
집합 경로를 `MerkleInclusion(8)` 로 바꾼 것은 같은 배선(MultiMux1 + Poseidon(2), 비트 i = 오른쪽)이라 `lib/mode3_set_tree.js setPath` 와 그대로 맞는다.

- [ ] **Step 3: 픽스처 교체** — `tests/helpers/mode3_fixture.mjs` 전체:

```js
// pi_cred 회로용 공유 입력 픽스처 (V9 — 설계 2026-10-01 §5).
// tests/test_pi_cred_witness.mjs, scripts/bench_pi_cred.mjs, test/Mode3Wallet.test.mjs 가 같은 입력 생성기를 쓴다.
import { buildPoseidon, buildEddsa, buildBabyjub } from 'circomlibjs';
import { sessionLeaf, createRevocationTree } from '../../lib/mode3_revocation.js';
import { userCommit, sessionCommit, credMessageV5, ppid as computePpid } from '../../lib/mode3_credential.js';
import { registrationCommit } from '../../lib/mode3_issuance.js';
import { createRegistryTree, registryLeaf } from '../../lib/mode3_registry.js';
import { combinePublicKey, encryptTag } from '../../lib/mode3_trace.js';
import { setPath, NO_SET } from '../../lib/mode3_set_tree.js';

export const ZERO6 = Object.freeze([0n, 0n, 0n, 0n, 0n, 0n]);
export const FIXTURE_ATTRS = Object.freeze([1990n, 410n, 2n, 0n, 0n, 0n]);   // 데모 testuser 와 같은 값(cia.js DEMO_ACCOUNTS)

/** 정상 입력 하나. 옵션: pk_i(실제 세션키 주소), maxHeight, allowAgent, chainid, disclosure{mask, lo[6], hi[6]}, set{slot 0..5, members},
 *  revokedSessions(남의 세션 리프), registrySlot(기본 7), registryLeafOverride(음성용 — 슬롯에 넣을 리프를 강제). */
export async function buildValidInput({ pk_i: pkIOpt, maxHeight = 1789000000n, allowAgent = 0n, chainid = 31337n, disclosure = null, set = null, revokedSessions = [], registrySlot = 7, registryLeafOverride = null } = {}) {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const eddsa = await buildEddsa();

  const uid     = 11111111111111111111n;
  const arid    = 22222222222222222222n;
  const s_u     = 33333333333333333333n;
  const r_u     = 99999999999999999999n;   // V9: 등록 커밋 블라인딩
  const blind_u = 44444444444444444444n;
  const blind_s = 55555555555555555555n;
  const pk_i    = pkIOpt ?? 0x1234567890123456789012345678901234567890n;
  const attrs   = [...FIXTURE_ATTRS];
  const max_height = maxHeight;

  const bj = await buildBabyjub();
  const shareOf = (x) => ({ x, X: { x: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[0]), y: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[1]) } });
  const shares = { svc: shareOf(66666666666666666666n), aa: shareOf(77777777777777777777n) };
  const pk_trace = await combinePublicKey(shares.svc.X, shares.aa.X);
  const tag = await encryptTag(pk_trace, uid, arid, 88888888888888888888n);

  const { Cf: Cf_u } = await userCommit({ uid, s_u, blind_u, attrs });
  const { Cf: Cf_s } = await sessionCommit({ arid, pk_i, blind_s });
  const PPID = await computePpid({ uid, arid, s_u, chainid });
  const msg = await credMessageV5(Cf_u, Cf_s, max_height, chainid, allowAgent);

  const prv = Buffer.from('0001020304050607080900010203040506070809000102030405060708090001', 'hex');
  const pub = eddsa.prv2pub(prv);
  const sig = eddsa.signPoseidon(prv, F.e(msg));
  const ciaPub = { x: F.toObject(pub[0]), y: F.toObject(pub[1]) };

  // 폐기 트리: 남의 세션 폐기 리프만(V9 — 사용자 리프 없음). 내 세션 비멤버십은 성립해야 한다.
  const tree = await createRevocationTree();
  await tree.insert(await sessionLeaf(999n));
  for (const c of revokedSessions) await tree.insert(await sessionLeaf(BigInt(c)));
  const ws = await tree.getNonMembershipWitness(await sessionLeaf(Cf_s));

  // 등록부: 남의 슬롯 둘 + 내 슬롯(registrySlot). 리프 = Poseidon(cm_u.x, cm_u.y, Cf_u).
  const cm_u = await registrationCommit(s_u, r_u);
  const registry = await createRegistryTree();
  registry.set(0, 12345n);
  registry.set(3, 67890n);
  const myLeaf = registryLeafOverride ?? await registryLeaf(cm_u, Cf_u);
  registry.set(registrySlot, myLeaf);
  const rp = registry.path(registrySlot);

  const disc = disclosure ?? { mask: 0n, lo: [...ZERO6], hi: [...ZERO6] };
  let st = NO_SET;
  if (set) {
    const { index, path, root } = await setPath(set.members, attrs[set.slot]);
    st = { sel: BigInt(set.slot) + 1n, root, index, path };
  }

  const input = {
    uid: uid.toString(), s_u: s_u.toString(), r_u: r_u.toString(), blind_u: blind_u.toString(), blind_s: blind_s.toString(), attrs: attrs.map(String),
    S: sig.S.toString(), R8x: F.toObject(sig.R8[0]).toString(), R8y: F.toObject(sig.R8[1]).toString(),
    s_lowValue: ws.lowValue.toString(), s_lowNextIndex: ws.lowNextIndex.toString(), s_lowNextValue: ws.lowNextValue.toString(),
    s_pathElements: ws.pathElements.map(String), s_pathIndices: ws.pathIndices.map(String),
    reg_pathElements: rp.pathElements.map(String), reg_pathIndices: rp.pathIndices.map(String),
    r: tag.r.toString(),
    PPID: PPID.toString(), arid: arid.toString(), pk_i: pk_i.toString(),
    max_height: max_height.toString(), chainid: chainid.toString(), allowAgent: allowAgent.toString(),
    revRoot: tree.getRoot().toString(), regRoot: registry.root().toString(),
    pk_CIA_x: ciaPub.x.toString(), pk_CIA_y: ciaPub.y.toString(),
    pk_trace_x: pk_trace.x.toString(), pk_trace_y: pk_trace.y.toString(),
    tag_c1_x: tag.c1.x.toString(), tag_c1_y: tag.c1.y.toString(), tag_c2: tag.c2.toString(),
    disc_mask: disc.mask.toString(), disc_lo: disc.lo.map(String), disc_hi: disc.hi.map(String),
    set_sel: st.sel.toString(), set_root: st.root.toString(), set_index: String(st.index), set_path: st.path.map(String),
  };

  return { input, Cf_u, Cf_s, pk_trace, shares, tag, ciaPub, arid, uid, tree, registry, slot: registrySlot, cm_u, attrs, disclosure: disc, set: st };
}
```

- [ ] **Step 4: 회로 테스트 갱신** — `tests/test_pi_cred_witness.mjs`

1. import 를 `import { sessionLeaf, createRevocationTree, MODE3_TREE_DEPTH } from '../lib/mode3_revocation.js';` 로(`userLeaf` 제거), `import { registryLeaf } from '../lib/mode3_registry.js';` 추가.
2. 양성 첫 케이스의 `assert.equal(valid.pathElements.length, MODE3_TREE_DEPTH);` → `assert.equal(valid.s_pathElements.length, MODE3_TREE_DEPTH); assert.equal(valid.reg_pathElements.length, 20);`.
3. 삭제: `V5 음성: 폐기 트리에 내 userLeaf 가 들어 있으면 비멤버십이 거부된다`, `음성: 폐기 전에 만든 witness는 폐기 후 root에서 거부된다 (낡은 증명)`, `JS userLeaf 와 회로의 리프 계산이 일치한다`, `V8 대조군: …`, `V8 음성: 세션 폐기 후 사용자 증인을 세션 증인 자리에 넣어도 거부 …` (사용자 증인이 없어졌다).
4. 4슬롯 상수 교체: `attrs[0] = '20'` 케이스는 그대로(배열 복사). `['1990', '410', '2', '0']` 이 들어간 자리는 전부 6개(`'0','0'` 추가). `disclosure: { mask, lo: [...4], hi: [...4] }` 는 전부 길이 6 으로(0 두 개 추가). `mask ≥ 16` 케이스는 `disc_mask: '64'` 로(6비트). `set_sel = 5 는 거부` → `set_sel = 7 은 거부`(`'7'`). `set: { slot: 3, members: [0] }` 케이스는 그대로 두되 attrs 배열을 6개로.
5. 추가(파일 끝, `console.log('')` 앞):
```js
await t('V9 양성: 등록부에 내 슬롯(7)이 있으면 통과; 다른 슬롯 번호를 써도 그 슬롯에 같은 리프가 있으면 통과', async () => {
  const fx = await buildValidInput({ registrySlot: 2 ** 20 - 1 });   // 마지막 슬롯
  await witness(fx.input);
});
await t('V9 음성: r_u 가 다르면 cm_u 가 달라 등록부 포함이 깨진다', async () => {
  await assert.rejects(() => witness({ ...valid, r_u: (BigInt(valid.r_u) + 1n).toString() }), /Assert Failed/);
});
await t('V9 음성: 슬롯이 비어 있으면(리프 0) 거부 — 게시 전 자격증명', async () => {
  const fx = await buildValidInput({ registryLeafOverride: 0n });
  await assert.rejects(() => witness(fx.input), /Assert Failed/);
});
await t('V9 음성: 슬롯이 다른 자격증명(C′)으로 바뀌면 거부 — 관리자 바꿔치기 시연의 회로 쪽', async () => {
  const fx = await buildValidInput({ registryLeafOverride: 424242n });
  await assert.rejects(() => witness(fx.input), /Assert Failed/);
});
await t('V9 음성: 경로를 바꾸면 거부, regRoot 를 바꾸면 거부', async () => {
  const els = [...valid.reg_pathElements]; els[0] = (BigInt(els[0]) + 1n).toString();
  await assert.rejects(() => witness({ ...valid, reg_pathElements: els }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, regRoot: (BigInt(valid.regRoot) + 1n).toString() }), /Assert Failed/);
});
await t('V9 음성: salt(s_u) 를 바꾸면 PPID·C_u·등록부가 모두 어긋난다(지갑 시연 "prove" 경로)', async () => {
  await assert.rejects(() => witness({ ...valid, s_u: (BigInt(valid.s_u) + 1n).toString() }), /Assert Failed/);
});
await t('V9: JS registryLeaf 와 회로의 리프 계산이 일치한다 (main.regLeaf.out)', async () => {
  const sym = fs.readFileSync(path.join(OUT_DIR, `${NAME}.sym`), 'utf8');
  const line = sym.split('\n').find((l) => l.split(',')[3] === 'main.regLeaf.out');
  assert.ok(line, 'pi_cred.sym 에서 main.regLeaf.out 을 찾지 못했다');
  const idx = Number(line.split(',')[1]);
  const w = await witness(valid);
  const fx = await buildValidInput();
  assert.equal(BigInt(w[idx]), await registryLeaf(fx.cm_u, fx.Cf_u));
});
await t('V9 양성: 6번째 슬롯 범위·집합 — attrs[5] = 0 ∈ [0, 0], set_sel = 6', async () => {
  const fx = await buildValidInput({ disclosure: { mask: 0b100000n, lo: [0n, 0n, 0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n, 0n, 0n] }, set: { slot: 5, members: [0, 1, 2] } });
  assert.equal(fx.input.set_sel, '6');
  await witness(fx.input);
});
```
6. 파일 끝의 제약 수 출력에 `console.log('   (V8 2026-09-24: 37,130)');` 를 더한다.

- [ ] **Step 5: 회로 테스트 실행** — `node tests/test_pi_cred_witness.mjs`
Expected: 전부 ok, 마지막 줄 `## pi_cred 비선형 제약: N` — N 을 적어 둔다(스펙 추정 37,130 ± 1천; 벗어나면 보고만 하고 진행).

- [ ] **Step 6: 산출물 재생성** (스펙 §5.5 허가)

Run: `ls -la pot21_final.ptau && bash scripts/build_mode3_circuit.sh pot21_final.ptau && npx hardhat compile`
Expected: `완료: build/mode3/pi_cred_final.zkey, …, contracts/PiCredVerifier.sol`, 그 뒤 hardhat 컴파일 성공(`Mode3Wallet.sol` 은 아직 `uint[25]` 라 PiCredVerifier 의 `uint[30]` 과 안 맞아 **컴파일 에러가 날 수 있다** — 그러면 이 단계에서는 `npx hardhat compile` 을 생략하고 Task 6 Step 5 에서 한다). 걸리는 시간: 수 분.
그 다음 `node tests/test_mode3_artifacts.mjs` → ok(산출물이 지금 회로의 것).

- [ ] **Step 7: 커밋** (`build/` 는 .gitignore 라 올라가지 않는다. `contracts/PiCredVerifier.sol` 은 올린다.)
```bash
git add circuits/lib/merkle_inclusion.circom circuits/pi_cred.circom tests/helpers/mode3_fixture.mjs tests/test_pi_cred_witness.mjs contracts/PiCredVerifier.sol
git commit -m "feat(mode3): 회로 V9 — 등록부 멤버십(조건 9)·사용자 비멤버십 제거·속성 6슬롯·공개 입력 30, 검증자 재생성 (V9 4/16)"
```

---

### Task 5: 로그 컨트랙트 V2 `Mode3Log` 와 JS 보조

**Files:**
- Create: `contracts/Mode3Log.sol`
- Modify: `lib/mode3_log.js` (V2 추가 — 옛 상수·함수는 남긴다, `RevocationLog.test.mjs`·Mode 2 가 쓴다)
- Modify: `tests/helpers/mode3_chain.mjs` (`deployMode3Log`)
- Modify: `scripts/deploy_mode3_log.cjs` (`Mode3Log` 배포)
- Create: `test/Mode3Log.test.mjs`
- Modify: `scripts/run_tests.sh` 의 CONTRACT 배열(파일에서 `test/RevocationLog.test.mjs` 가 있는 줄 근처)에 `test/Mode3Log.test.mjs`

**Interfaces:**
- Produces: `MODE3_LOG_ABI`(ethers 사람 읽기 ABI: `revRoot()`, `regRoot()`, `epoch()`, `lastPublishedBlock()`, `cia()`, `publish(bytes32,bytes32,uint64,bytes32[],uint32[],bytes32[],bytes)`, `event Revoked(uint64 indexed epoch, bytes32 root, bytes32[] leaves)`, `event SlotUpdated(uint64 indexed epoch, uint32 index, bytes32 leaf)`), `DOMAIN_LOG_V2`, `publicationDigestV2({logAddress, revRoot, regRoot, epoch, revLeaves, slotIdx, slotLeaves})`, `signPublicationV2(wallet, params)`, `deployMode3Log(ciaAddress, provider)` → `{ address, contract }` (빈 root 둘은 JS 로 계산).

- [ ] **Step 1: 컨트랙트 테스트** — `test/Mode3Log.test.mjs`:
```js
// Mode3Log — 폐기 root + 등록부 root 를 한 트랜잭션에 게시(V9, 설계 2026-10-01 §4). hardhat 인프로세스 체인(contract 그룹).
import { expect } from 'chai';
import hre from 'hardhat';
import { createRevocationTree } from '../lib/mode3_revocation.js';
import { createRegistryTree } from '../lib/mode3_registry.js';
import { signPublicationV2, publicationDigestV2, rootToBytes32 } from '../lib/mode3_log.js';

const { ethers } = hre;
const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(n), 32);

describe('Mode3Log', () => {
  let log, cia, relayer, stranger, emptyRev, emptyReg;
  const sign = (wallet, target, p) => signPublicationV2(wallet, { logAddress: target, ...p });
  beforeEach(async () => {
    [, cia, relayer, stranger] = await ethers.getSigners();
    emptyRev = rootToBytes32((await createRevocationTree()).getRoot());
    emptyReg = rootToBytes32((await createRegistryTree()).root());
    log = await (await ethers.getContractFactory('Mode3Log')).deploy(cia.address, emptyRev, emptyReg);
  });
  const addr = () => log.getAddress();

  it('초기 상태: 빈 root 둘, epoch 0, lastPublishedBlock = 배포 블록', async () => {
    expect(await log.revRoot()).to.equal(emptyRev);
    expect(await log.regRoot()).to.equal(emptyReg);
    expect(await log.epoch()).to.equal(0n);
    expect(await log.lastPublishedBlock()).to.equal(BigInt(await ethers.provider.getBlockNumber()));
  });
  it('게시: 두 root 갱신, Revoked 1건 + SlotUpdated n건, 제출자는 아무나', async () => {
    const p = { revRoot: b32(9n), regRoot: b32(8n), epoch: 1n, revLeaves: [b32(1n)], slotIdx: [7, 9], slotLeaves: [b32(70n), b32(90n)] };
    const sig = await sign(cia, await addr(), p);
    const tx = log.connect(relayer).publish(p.revRoot, p.regRoot, p.epoch, p.revLeaves, p.slotIdx, p.slotLeaves, sig);
    await expect(tx).to.emit(log, 'Revoked').withArgs(1n, p.revRoot, p.revLeaves);
    await expect(tx).to.emit(log, 'SlotUpdated').withArgs(1n, 7, b32(70n));
    await expect(tx).to.emit(log, 'SlotUpdated').withArgs(1n, 9, b32(90n));
    expect(await log.revRoot()).to.equal(p.revRoot); expect(await log.regRoot()).to.equal(p.regRoot); expect(await log.epoch()).to.equal(1n);
    expect(await log.lastPublishedBlock()).to.equal(BigInt(await ethers.provider.getBlockNumber()));
  });
  it('하트비트: 리프·슬롯 없이 같은 root 를 새 epoch 로 재게시하면 lastPublishedBlock 만 바뀐다', async () => {
    await ethers.provider.send('hardhat_mine', ['0x5']);
    const p = { revRoot: emptyRev, regRoot: emptyReg, epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [] };
    await log.publish(p.revRoot, p.regRoot, p.epoch, [], [], [], await sign(cia, await addr(), p));
    expect(await log.lastPublishedBlock()).to.equal(BigInt(await ethers.provider.getBlockNumber()));
  });
  it('CIA 가 아닌 서명·epoch 미증가·길이 불일치·서명과 다른 인자는 거절', async () => {
    const p = { revRoot: b32(1n), regRoot: b32(2n), epoch: 1n, revLeaves: [], slotIdx: [1], slotLeaves: [b32(5n)] };
    await expect(log.publish(p.revRoot, p.regRoot, 1n, [], [1], [b32(5n)], await sign(stranger, await addr(), p))).to.be.revertedWithCustomError(log, 'BadSignature');
    await expect(log.publish(p.revRoot, p.regRoot, 0n, [], [1], [b32(5n)], await sign(cia, await addr(), { ...p, epoch: 0n }))).to.be.revertedWithCustomError(log, 'EpochNotIncreasing');
    await expect(log.publish(p.revRoot, p.regRoot, 1n, [], [1, 2], [b32(5n)], await sign(cia, await addr(), p))).to.be.revertedWithCustomError(log, 'LengthMismatch');
    const sig = await sign(cia, await addr(), p);
    await expect(log.publish(p.revRoot, b32(3n), 1n, [], [1], [b32(5n)], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
    await expect(log.publish(p.revRoot, p.regRoot, 1n, [], [2], [b32(5n)], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
    await expect(log.publish(p.revRoot, p.regRoot, 1n, [], [1], [b32(6n)], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
  });
  it('다른 로그의 게시를 재생하면 거절 (digest 가 주소를 덮는다)', async () => {
    const other = await (await ethers.getContractFactory('Mode3Log')).deploy(cia.address, emptyRev, emptyReg);
    const p = { revRoot: b32(1n), regRoot: b32(2n), epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [] };
    const sig = await sign(cia, await addr(), p);
    await log.publish(p.revRoot, p.regRoot, 1n, [], [], [], sig);
    await expect(other.publish(p.revRoot, p.regRoot, 1n, [], [], [], sig)).to.be.revertedWithCustomError(other, 'BadSignature');
  });
  it('digestFor 가 JS publicationDigestV2 와 같다', async () => {
    const p = { revRoot: b32(9n), regRoot: b32(8n), epoch: 3n, revLeaves: [b32(7n)], slotIdx: [4], slotLeaves: [b32(44n)] };
    expect(await log.digestFor(p.revRoot, p.regRoot, p.epoch, p.revLeaves, p.slotIdx, p.slotLeaves)).to.equal(publicationDigestV2({ logAddress: await addr(), ...p }));
  });
});
```

- [ ] **Step 2: 실패 확인** — `npx hardhat test test/Mode3Log.test.mjs` → 컨트랙트 없음 에러.

- [ ] **Step 3: 컨트랙트** — `contracts/Mode3Log.sol`:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Mode 3 로그 V2 — 폐기 트리 root 와 사용자 자격증명 등록부 root 를 한 트랜잭션에 게시한다(설계 2026-10-01 §4).
/// @notice RevocationLog(V1)과 같은 서명 규칙(EIP-191, CIA 키, low-s)·epoch 증가 규칙. 두 root 가 같은 블록에 게시되므로
///   root 나이(lastPublishedBlock)는 하나다. 지갑은 Revoked 이벤트로 폐기 트리를, SlotUpdated 이벤트로 등록부를 복원한다.
contract Mode3Log {
    bytes32 public constant DOMAIN = keccak256("MODE3_LOG_V2");

    address public immutable cia;
    bytes32 public revRoot;
    bytes32 public regRoot;
    uint64 public epoch;
    uint64 public lastPublishedBlock;

    event Revoked(uint64 indexed epoch, bytes32 root, bytes32[] leaves);
    event SlotUpdated(uint64 indexed epoch, uint32 index, bytes32 leaf);

    error EpochNotIncreasing(uint64 got, uint64 have);
    error BadSignature();
    error LengthMismatch();

    constructor(address cia_, bytes32 emptyRevRoot, bytes32 emptyRegRoot) {
        cia = cia_;
        revRoot = emptyRevRoot;
        regRoot = emptyRegRoot;
        lastPublishedBlock = uint64(block.number);
    }

    /// @dev EIP-191 을 적용하기 전의 내부 digest. lib/mode3_log.js publicationDigestV2 와 바이트 단위로 같다.
    function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] calldata revLeaves, uint32[] calldata slotIdx, bytes32[] calldata slotLeaves)
        public view returns (bytes32)
    {
        return keccak256(abi.encode(
            DOMAIN, address(this), newRev, newReg, newEpoch,
            keccak256(abi.encodePacked(revLeaves)), keccak256(abi.encodePacked(slotIdx)), keccak256(abi.encodePacked(slotLeaves))
        ));
    }

    function publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] calldata revLeaves, uint32[] calldata slotIdx, bytes32[] calldata slotLeaves, bytes calldata sig)
        external
    {
        if (newEpoch <= epoch) revert EpochNotIncreasing(newEpoch, epoch);
        if (slotIdx.length != slotLeaves.length) revert LengthMismatch();
        bytes32 inner = digestFor(newRev, newReg, newEpoch, revLeaves, slotIdx, slotLeaves);
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        if (_recover(ethDigest, sig) != cia) revert BadSignature();
        revRoot = newRev;
        regRoot = newReg;
        epoch = newEpoch;
        lastPublishedBlock = uint64(block.number);
        emit Revoked(newEpoch, newRev, revLeaves);
        for (uint256 i = 0; i < slotIdx.length; i++) emit SlotUpdated(newEpoch, slotIdx[i], slotLeaves[i]);
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert BadSignature();
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert BadSignature();
        if (v != 27 && v != 28) revert BadSignature();
        address a = ecrecover(digest, v, r, s);
        if (a == address(0)) revert BadSignature();
        return a;
    }
}
```

- [ ] **Step 4: JS 보조** — `lib/mode3_log.js` 끝에 추가:
```js
// ---- V2 (Mode3Log, 2026-10-01 등록부) — 옛 V1 상수·함수는 RevocationLog.test·Mode 2 가 쓰므로 남긴다 ----
export const DOMAIN_LOG_V2 = ethers.keccak256(ethers.toUtf8Bytes('MODE3_LOG_V2'));
export const MODE3_LOG_ABI = [
  'function cia() view returns (address)',
  'function revRoot() view returns (bytes32)',
  'function regRoot() view returns (bytes32)',
  'function epoch() view returns (uint64)',
  'function lastPublishedBlock() view returns (uint64)',
  'function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] revLeaves, uint32[] slotIdx, bytes32[] slotLeaves) view returns (bytes32)',
  'function publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] revLeaves, uint32[] slotIdx, bytes32[] slotLeaves, bytes sig)',
  'event Revoked(uint64 indexed epoch, bytes32 root, bytes32[] leaves)',
  'event SlotUpdated(uint64 indexed epoch, uint32 index, bytes32 leaf)',
];
/** Mode3Log.digestFor() 와 같은 내부 digest. revLeaves·slotLeaves 는 bytes32 hex 배열, slotIdx 는 정수 배열. */
export function publicationDigestV2({ logAddress, revRoot, regRoot, epoch, revLeaves, slotIdx, slotLeaves }) {
  if (!logAddress) throw new Error('publicationDigestV2: logAddress 가 필요하다');
  if (slotIdx.length !== slotLeaves.length) throw new Error('publicationDigestV2: slotIdx 와 slotLeaves 길이가 다르다');
  const packed = (types, vals) => ethers.keccak256(vals.length ? ethers.solidityPacked(types, vals) : '0x');
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'address', 'bytes32', 'bytes32', 'uint64', 'bytes32', 'bytes32', 'bytes32'],
    [DOMAIN_LOG_V2, logAddress, revRoot, regRoot, epoch, packed(revLeaves.map(() => 'bytes32'), revLeaves), packed(slotIdx.map(() => 'uint32'), slotIdx), packed(slotLeaves.map(() => 'bytes32'), slotLeaves)],
  ));
}
export function signPublicationV2(wallet, params) {
  return wallet.signMessage(ethers.getBytes(publicationDigestV2(params)));
}
```
(`abi.encodePacked` 의 빈 배열은 빈 바이트열이므로 `keccak256('0x')` 와 같다 — `packed` 가 그 경우를 다룬다.)

`tests/helpers/mode3_chain.mjs` 에 추가:
```js
import { createRegistryTree } from '../../lib/mode3_registry.js';
const ARTIFACT_V2 = path.join(ROOT_DIR, 'artifacts', 'contracts', 'Mode3Log.sol', 'Mode3Log.json');
function artifactV2() {
  if (!fs.existsSync(ARTIFACT_V2)) execFileSync('npx', ['hardhat', 'compile', '--quiet'], { cwd: ROOT_DIR, stdio: 'inherit' });
  return JSON.parse(fs.readFileSync(ARTIFACT_V2, 'utf8'));
}
/** V9: Mode3Log 배포 — 빈 폐기 root + 빈 등록부 root. */
export async function deployMode3Log(ciaAddress, provider = getProvider()) {
  const { abi, bytecode } = artifactV2();
  const emptyRev = rootToBytes32((await createRevocationTree()).getRoot());
  const emptyReg = rootToBytes32((await createRegistryTree()).root());
  const factory = new ethers.ContractFactory(abi, bytecode, await getFunder(provider));
  const contract = await factory.deploy(ciaAddress, emptyRev, emptyReg);
  await contract.waitForDeployment();
  return { address: await contract.getAddress(), contract };
}
```
`scripts/deploy_mode3_log.cjs`: `createRevocationTree` 옆에 `const { createRegistryTree } = await import("../lib/mode3_registry.js");`, `emptyReg` 를 같은 식으로 계산, `getContractFactory("Mode3Log")`, `F.deploy(cia, emptyRoot, emptyReg)`, 출력 문구 `Mode3Log: …`. 머리 주석을 "Mode 3 로그 V2(폐기 root + 등록부 root)" 로.

- [ ] **Step 5: 통과·커밋** — `npx hardhat test test/Mode3Log.test.mjs` → 6 passing. `scripts/run_tests.sh` CONTRACT 배열에 `test/Mode3Log.test.mjs` 추가.
```bash
git add contracts/Mode3Log.sol lib/mode3_log.js tests/helpers/mode3_chain.mjs scripts/deploy_mode3_log.cjs test/Mode3Log.test.mjs scripts/run_tests.sh
git commit -m "feat(mode3): Mode3Log V2 — 폐기 root + 등록부 root 한 트랜잭션 게시, SlotUpdated 이벤트 (V9 5/16)"
```

---

### Task 6: 계정 컨트랙트·팩토리·AttrGate 를 공개 입력 30 으로, on-chain 유틸 갱신

**Files:**
- Modify: `contracts/Mode3Wallet.sol`, `contracts/Mode3WalletFactory.sol`, `contracts/AttrGate.sol`
- Modify: `lib/mode3_onchain.js`
- Modify: `test/Mode3Wallet.test.mjs`, `test/AttrGate.test.mjs`, `test/Mode3ReferenceCode.test.mjs`

**Interfaces:**
- Consumes: Task 4 `PiCredVerifier.sol`(uint[30]), Task 5 `Mode3Log`.
- Produces: `Mode3Wallet.execute(payload, sig, a, b, c, uint[30] pub)`; 새 에러 `StaleRegistryRoot(bytes32)`; `Disclosure(nonceUsed, mask, uint256[6] lo, uint256[6] hi, setSel, setRoot)`; `AttrGate._disclosure()` → `(mask, lo[6], hi[6], setSel, setRoot)`; JS `payloadDigest({..., discLo:[6], discHi:[6], ...})`, `statementDigestFields(pub)` → `{maxHeight: pub[3], allowAgent: pub[5], tagC1X: pub[12], tagC1Y: pub[13], tagC2: pub[14]}`, `PUB_INDEX` 상수 객체, `deployFactory` 는 인자 불변(로그 주소에 Mode3Log).

- [ ] **Step 1: 컨트랙트 테스트를 먼저 고친다** — `test/Mode3Wallet.test.mjs`
  - `deployStack`: `RevocationLog` → `Mode3Log`, `Log.deploy(cia.address, rootToBytes32(BigInt(st.input().revRoot)), rootToBytes32(BigInt(st.input().regRoot)))`.
  - `signedPayload` 기본값 `discLo = [0n×6]`, `discHi = [0n×6]`.
  - 인덱스: `p[9] = '0x1'`(UntrustedKeys) 는 `p[10]`(pk_trace_x), BadTag 는 `p[12] = '0x0'; p[13] = '0x1'`, `V7: pub 은 25개` → `assert.equal(ST.pub.length, 30)` 와 제목 `V9: pub 은 30개`.
  - `root 가 게시로 바뀌면 옛 π 는 StaleRevocationRoot`: `signPublicationV2(cia, { logAddress, revRoot: newRoot, regRoot: await log.regRoot(), epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [] })` 로 서명해 `log.publish(newRoot, await log.regRoot(), 1n, [], [], [], sig)`.
  - 하트비트 케이스도 `publish(revRoot, regRoot, 1n, [], [], [], sig)` 로.
  - 새 케이스:
```js
  it('V9: 등록부 root 가 바뀌면(슬롯 바꿔치기·은퇴) 옛 π 는 StaleRegistryRoot — 폐기 root 검사 다음에 걸린다', async () => {
    const { wallet, log, cia } = await deployStack(ST);
    const rev = await log.revRoot();
    const newReg = rootToBytes32(777n);
    const sig = await signPublicationV2(cia, { logAddress: await log.getAddress(), revRoot: rev, regRoot: newReg, epoch: 1n, revLeaves: [], slotIdx: [7], slotLeaves: [rootToBytes32(424242n)] });
    await (await log.publish(rev, newReg, 1n, [], [7], [rootToBytes32(424242n)], sig)).wait();
    const sp = await signedPayload(ST, wallet);
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'StaleRegistryRoot');
  });
  it('V9: 마스크 6비트·set_sel ≤ 6 — mask 64, set_sel 7 은 BadDisclosure', async () => {
    const { wallet } = await deployStack(ST);
    const a = await signedPayload(ST, wallet, { discMask: 64n });
    const p = [...ST.pub]; p[15] = '0x40';
    await expect(wallet.execute(a.payload, a.sig, ST.a, ST.b, ST.c, p)).to.be.revertedWithCustomError(wallet, 'BadDisclosure');
    const b = await signedPayload(ST, wallet, { setSel: 7n });
    const q = [...ST.pub]; q[28] = '0x7';
    await expect(wallet.execute(b.payload, b.sig, ST.a, ST.b, ST.c, q)).to.be.revertedWithCustomError(wallet, 'BadDisclosure');
  });
```
  - 위조 꼬리 회귀 케이스: `fakeTail` 인코딩을 `['uint256', 'uint256[6]', 'uint256[6]', 'uint256', 'uint256']` 와 길이 6 배열로, 진짜 π 케이스의 `disclosure: { mask: 0b0001n, lo: [0n×6], hi: [1990n, 0n×5] }`, `discLo: DS.fx.disclosure.lo` 는 이미 길이 6.
  - import 에 `signPublicationV2` 추가(`signRootPublication` 는 더 쓰지 않으면 지운다).
  - `test/AttrGate.test.mjs`: 팩토리 배포 인자 그대로(로그 주소는 아무 주소). 변경 없음이지만 Task 6 끝에 같이 돌린다.
  - `test/Mode3ReferenceCode.test.mjs`: `log = await (await ethers.getContractFactory('Mode3Log')).deploy(deployer.address, ethers.ZeroHash, ethers.ZeroHash);`.

- [ ] **Step 2: 실패 확인** — `npx hardhat test test/Mode3Wallet.test.mjs` → 컴파일 에러(uint[25] vs uint[30]) 또는 실패.

- [ ] **Step 3: `contracts/Mode3Wallet.sol`**
  - `import "./RevocationLog.sol";` → `import "./Mode3Log.sol";`, `RevocationLog public immutable log;` → `Mode3Log public immutable log;`, 생성자 `log = Mode3Log(_log);`.
  - 에러 추가 `error StaleRegistryRoot(bytes32 root);`.
  - `Disclosure` 이벤트 배열 `uint256[6] lo, uint256[6] hi`.
  - `execute` 의 `uint[25] calldata pub` → `uint[30]`, 주석의 인덱스 표를 Global Constraints 로 교체. `payloadHash`:
```solidity
        bytes32 payloadHash = keccak256(
            abi.encode(
                block.chainid, address(this), payload.to, payload.value, payload.data, payload.nonce,
                pub[15], [pub[16], pub[17], pub[18], pub[19], pub[20], pub[21]], [pub[22], pub[23], pub[24], pub[25], pub[26], pub[27]], pub[28], pub[29],
                pub[3], pub[5], pub[12], pub[13], pub[14]
            )
        );
```
  - 꼬리: `(payload.data.length == 0 && pub[15] == 0 && pub[28] == 0) ? payload.data : abi.encodePacked(payload.data, pub[15], pub[16], …, pub[29])` (15워드 전부 나열). 주석의 "11워드(352바이트)" → "15워드(480바이트)".
  - 이벤트: `emit Mode3Auth(payload.nonce, pub[2], pub[3], pub[5], pub[12], pub[13], pub[14]);`, `if (pub[15] != 0 || pub[28] != 0) emit Disclosure(payload.nonce, pub[15], [pub[16..21]], [pub[22..27]], pub[28], pub[29]);`.
  - `_checkStatement(uint[30] calldata pub)`:
```solidity
        if (pub[0] != ppid || pub[1] != arid || pub[4] != block.chainid) revert WrongWallet();
        if (pub[8] != pkCIAX || pub[9] != pkCIAY || pub[10] != pkTraceX || pub[11] != pkTraceY) revert UntrustedKeys();
        if (pub[5] > 1) revert BadAllowAgent();
        if (pub[12] == 0 && pub[13] == 1) revert BadTag();
        if (pub[15] >= 64) revert BadDisclosure();
        if (pub[28] > 6 || (pub[28] == 0 && pub[29] != 0)) revert BadDisclosure();
        for (uint256 k = 0; k < 6; k++) {
            if (((pub[15] >> k) & 1) == 0 && (pub[16 + k] != 0 || pub[22 + k] != 0)) revert BadDisclosure();
        }
        bytes32 root = bytes32(pub[6]);
        if (root != log.revRoot()) revert StaleRevocationRoot(root);
        bytes32 reg = bytes32(pub[7]);
        if (reg != log.regRoot()) revert StaleRegistryRoot(reg);
        uint256 last = log.lastPublishedBlock();
        if (block.number - last > maxRootAge) revert RootTooOld(last, block.number);
        if (block.number > pub[3]) revert Expired(block.number, pub[3]);
        if (pub[3] > block.number + maxLifetime) revert TooFarExpiry(block.number, pub[3]);
```
  - `Mode3WalletFactory.sol`: 변경 없음(`address log` 를 그대로 넘긴다) — 주석만 "Mode3Log".
  - `AttrGate.sol`: `TAIL = 15 * 32`; `_disclosure()` 가 `uint256[6] memory lo, uint256[6] memory hi` 를 돌려주고 루프 `k < 6`, `pl = base + 32 * (1 + k)`, `ph = base + 32 * (7 + k)`, `ps = base + 32 * 13`, `pr = base + 32 * 14`; `claim()` 의 구조 분해 `(uint256 mask, , uint256[6] memory hi, uint256 setSel, uint256 setRoot)`. 머리 주석의 "11워드" → "15워드".

- [ ] **Step 4: `lib/mode3_onchain.js`**
  - `WALLET_ABI`: `uint256[30] pub`, `Disclosure(... uint256[6] lo, uint256[6] hi ...)`, 에러 목록에 `'error StaleRegistryRoot(bytes32 root)'`.
  - 새 상수(파일 위쪽):
```js
/** 공개 입력 색인(V9, circuits/pi_cred.circom) — 다른 파일은 숫자 대신 이것을 쓴다. */
export const PUB_INDEX = Object.freeze({ PPID: 0, ARID: 1, PK_I: 2, MAX_HEIGHT: 3, CHAINID: 4, ALLOW_AGENT: 5, REV_ROOT: 6, REG_ROOT: 7, PK_CIA_X: 8, PK_CIA_Y: 9, PK_TRACE_X: 10, PK_TRACE_Y: 11, TAG_C1_X: 12, TAG_C1_Y: 13, TAG_C2: 14, DISC_MASK: 15, DISC_LO: 16, DISC_HI: 22, SET_SEL: 28, SET_ROOT: 29, COUNT: 30 });
export const ATTR_SLOTS = 6;
export const ZERO_SLOTS = Object.freeze([0n, 0n, 0n, 0n, 0n, 0n]);
```
  - `payloadDigest`: 기본값 `discLo = [...ZERO_SLOTS], discHi = [...ZERO_SLOTS]`, 타입 `'uint256[6]', 'uint256[6]'`, 주석의 pub 색인 갱신.
  - `statementDigestFields = (pub) => ({ maxHeight: BigInt(pub[3]), allowAgent: BigInt(pub[5]), tagC1X: BigInt(pub[12]), tagC1Y: BigInt(pub[13]), tagC2: BigInt(pub[14]) })`.
  - 새 함수 `export function deployMode3Log` 는 테스트 헬퍼에 있으므로 여기엔 두지 않는다. `readArtifact('Mode3Log')` 를 쓰는 `deployLog(signer, ciaAddress, emptyRev, emptyReg)` 를 추가한다(RP·스크립트가 아니라 벤치가 쓸 수 있게):
```js
export async function deployLog(signer, { ciaAddress, emptyRevRoot, emptyRegRoot }) {
  const { abi, bytecode } = readArtifact('Mode3Log');
  const c = await new ethers.ContractFactory(abi, bytecode, signer).deploy(ciaAddress, emptyRevRoot, emptyRegRoot);
  await c.waitForDeployment();
  return c.getAddress();
}
```
  - 주석의 "11워드" 들을 "15워드" 로.

- [ ] **Step 5: 컴파일·테스트** — `npx hardhat compile && npx hardhat test test/Mode3Log.test.mjs test/Mode3Wallet.test.mjs test/AttrGate.test.mjs test/Mode3ReferenceCode.test.mjs`
Expected: 전부 passing. `execute() gas:` 줄의 값을 적어 둔다(벤치 보고용).

- [ ] **Step 6: 커밋**
```bash
git add contracts/Mode3Wallet.sol contracts/Mode3WalletFactory.sol contracts/AttrGate.sol lib/mode3_onchain.js test/Mode3Wallet.test.mjs test/AttrGate.test.mjs test/Mode3ReferenceCode.test.mjs
git commit -m "feat(mode3): Mode3Wallet·AttrGate 공개 입력 30 — regRoot 검사(StaleRegistryRoot), 마스크 6비트, 꼬리 15워드 (V9 6/16)"
```

---

### Task 7: CIA 등록부 — 상태 v9, 등록(pk_u·sig_reg·슬롯), 게시 V2, 발급·은퇴·폐기의 슬롯 갱신

**Files:**
- Modify: `lib/mode3_cia_state.js`
- Create: `tests/test_mode3_cia_state_v9.js` (unit)
- Modify: `cia.js` (아래 번호 순서대로)
- Modify: `tests/helpers/isolated_cia.mjs` (`deployMode3Log`, `registerUser`)
- Create: `tests/test_cia_registry.mjs` (chain)
- Modify: `scripts/run_tests.sh` (UNIT 에 `tests/test_mode3_cia_state_v9.js`, CHAIN 에 `tests/test_cia_registry.mjs`)

**Interfaces:**
- Consumes: Task 2 `createRegistryTree`·`registryLeaf`, Task 3 `registerMessage`·`createRegistration`·`signRegistration`, Task 5 `MODE3_LOG_ABI`·`signPublicationV2`·`deployMode3Log`.
- Produces (HTTP):
  - `POST /cia/register {uid, pwd, cm_u:{x,y}, pk_u:{x,y}, sig_reg:{R8x,R8y,S}}` → 201 `{ slot, attrs }` (sk_u 없음); 400 `bad_registration_signature` / `pk_u is not a valid subgroup point`.
  - `POST /cia/user_cred` → 201|200 `{ Cf_u, slot, regRoot, epoch, published }`.
  - `POST /cia/revoke {scope:'credential'|'account'}` → 200 `{ retired:<수>, slot, regRoot, published, disabled? }`; `scope:'session'` 현행.
  - `POST /cia/publish` → `{ published, heartbeat, epoch, root, regRoot, txHash, leaves, slots }`.
  - `GET /cia/state` → `+ regRoot, registrySlots, pendingSlots`. `GET /cia/accounts`(admin) 항목 `+ slot, tampered, registryLeaf`.
  - 상태 파일: `state.registry = { depth: 20, next, leaves: {"<index>": "<leaf>"}, pendingSlots: [{index, leaf}] }`, `accounts[uid].slot`, `accounts[uid].tampered`.
- 테스트 헬퍼: `cia.registerUser(uid, pwd)` → `{ s_u, r_u, cm_u, sk_u, pk_u, slot, attrs, body }`.

- [ ] **Step 1: 상태 v9 이행 단위 테스트** — `tests/test_mode3_cia_state_v9.js`:
```js
// CIA 상태 v8 → v9 이행(등록부·슬롯). (unit)  node tests/test_mode3_cia_state_v9.js
import assert from 'node:assert/strict';
import { CIA_STATE_VERSION, defaultCiaState, migrateCiaState } from '../lib/mode3_cia_state.js';
let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }
const v8 = () => ({ version: 8, accounts: {
  '67890': { pk_u: { x: '1', y: '2' }, cm_u: { x: '3', y: '4' }, disabled: false, creds: [], attrs: ['2005', '840', '1', '0'], sessions: [] },
  '12345': { pk_u: { x: '5', y: '6' }, cm_u: { x: '7', y: '8' }, disabled: false, creds: [{ Cf_u: '99', C_u_pt: { x: '1', y: '1' }, leaf: '0', issuedAt: 'x', revoked: false }], attrs: ['1990', '410', '2', '0'], sessions: [] },
}, rps: {}, openings: [], revoked: [], pending: [], epoch: 3 });
t('CIA_STATE_VERSION = 9, defaultCiaState 에 registry', () => {
  assert.equal(CIA_STATE_VERSION, 9);
  assert.deepEqual(defaultCiaState().registry, { depth: 20, next: 0, leaves: {}, pendingSlots: [] });
});
t('v8 → v9: 슬롯은 uid 오름차순(12345 → 0, 67890 → 1), registry.next = 2, 속성은 6칸으로 0 패딩, tampered:false', () => {
  const { state, notes } = migrateCiaState(v8());
  assert.equal(state.version, 9);
  assert.equal(state.accounts['12345'].slot, 0); assert.equal(state.accounts['67890'].slot, 1);
  assert.equal(state.registry.next, 2); assert.deepEqual(state.registry.leaves, {}); assert.deepEqual(state.registry.pendingSlots, []);
  assert.deepEqual(state.accounts['12345'].attrs, ['1990', '410', '2', '0', '0', '0']);
  assert.equal(state.accounts['12345'].tampered, false);
  assert.ok(notes.some((n) => n.startsWith('v8→v9')), notes.join('|'));
  assert.equal(state.epoch, 3, '게시 epoch 는 그대로');
});
t('v9 는 그대로 통과하고 slot 이 있는 계정은 다시 배정하지 않는다', () => {
  const { state: s1 } = migrateCiaState(v8());
  const { state: s2, notes } = migrateCiaState(JSON.parse(JSON.stringify(s1)));
  assert.deepEqual(notes, []); assert.equal(s2.accounts['67890'].slot, 1); assert.equal(s2.registry.next, 2);
});
process.exit(fails ? 1 : 0);
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_cia_state_v9.js` → FAIL(버전 8).

- [ ] **Step 3: `lib/mode3_cia_state.js`**
  - 머리 주석에 `// version 9 (2026-10-01): 등록부 — state.registry {depth, next, leaves, pendingSlots}, accounts[uid].slot(uid 오름차순 배정)·tampered. 속성 6슬롯(0 패딩). 활성 자격증명의 리프는 cia.js 기동이 계산해 넣고 게시한다(Poseidon 은 비동기).`
  - `CIA_STATE_VERSION = 9`; `defaultCiaState()` 에 `registry: { depth: 20, next: 0, leaves: {}, pendingSlots: [] }`.
  - `if (state.version === 7) {…}` 블록 뒤에:
```js
  if (state.version === 8) {
    state.registry ??= { depth: 20, next: 0, leaves: {}, pendingSlots: [] };
    const uids = Object.keys(state.accounts ?? {}).sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0));
    let assigned = 0;
    for (const uid of uids) {
      const a = state.accounts[uid];
      if (!Number.isInteger(a.slot)) { a.slot = state.registry.next++; assigned++; }
      a.tampered ??= false;
      a.attrs = [...(a.attrs ?? []), '0', '0', '0', '0', '0', '0'].slice(0, 6);
    }
    state.version = 9;
    notes.push(`v8→v9: 등록부 생성, 계정 ${assigned}개에 슬롯 배정(uid 오름차순), 속성 6칸 — 활성 자격증명 리프는 기동 뒤 채워 게시한다`);
  }
```
  - 마지막 기본값 줄에 `state.registry ??= { depth: 20, next: 0, leaves: {}, pendingSlots: [] };` 와 계정 루프에 `a.tampered ??= false;`.

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_cia_state_v9.js` → ok. 기존 `node tests/test_mode3_cia_state.js` 도 ok 여야 한다(v5 이행이 v9 까지 이어진다 — 그 테스트가 `version === 8` 을 단언하면 9 로 고친다).

- [ ] **Step 5: 테스트 헬퍼** — `tests/helpers/isolated_cia.mjs`
  - `import { getProvider, fundAddress, deployMode3Log } from './mode3_chain.mjs';`, `const { address: logAddress } = await deployMode3Log(ethWallet.address, provider);`
  - `import { createRegistration, signRegistration } from '../../lib/mode3_wallet.js'; import { pointToStrings } from '../../lib/mode3_issuance.js';`
  - 반환 객체에 추가:
```js
    /** V9 등록(설계 2026-10-01 §7.1): 지갑 키·등록 커밋을 만들어 /cia/register 를 부른다. { s_u, r_u, cm_u, sk_u, pk_u, slot, attrs, body } */
    async registerUser(uid, pwd) {
      const reg = await createRegistration();
      const r = await this.post('/cia/register', { uid, pwd, cm_u: pointToStrings(reg.cm_u), pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() }, sig_reg: await signRegistration(reg.sk_u, BigInt(uid), reg.cm_u) });
      if (r.status !== 201) throw new Error(`register 실패(${r.status}): ${JSON.stringify(r.body)}`);
      return { ...reg, slot: r.body.slot, attrs: r.body.attrs, body: r.body };
    },
```

- [ ] **Step 6: 체인 테스트** — `tests/test_cia_registry.mjs`:
```js
// CIA 등록부(V9) — 등록 키·슬롯·즉시 게시·은퇴·마이그레이션. 격리 CIA + :8545 Mode3Log. (chain)  node tests/test_cia_registry.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createRegistration, signRegistration, buildUserCredRequest, buildIssueRequest, createSessionKey, signRevokeSession } from '../lib/mode3_wallet.js';
import { pointToStrings, registrationCommit } from '../lib/mode3_issuance.js';
import { userCommit, randomScalar } from '../lib/mode3_credential.js';
import { registryLeaf, createRegistryTree } from '../lib/mode3_registry.js';
import { MODE3_LOG_ABI } from '../lib/mode3_log.js';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }
const provider = getProvider();
const cia = await startIsolatedCia();
const log = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
const ATTRS = [1990n, 410n, 2n, 0n, 0n, 0n];
const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32);
let u;   // registerUser 결과
try {
  await t('등록: pk_u·sig_reg 필수, 틀린 서명 400, 정상 201 { slot 0, attrs 6 }, sk_u 없음, 두 번째 계정은 슬롯 1', async () => {
    const reg = await createRegistration();
    const base = { uid: '12345', pwd: 'password123', cm_u: pointToStrings(reg.cm_u), pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() } };
    assert.equal((await cia.post('/cia/register', { ...base, pk_u: undefined, sig_reg: await signRegistration(reg.sk_u, 12345n, reg.cm_u) })).status, 400);
    const other = await createRegistration();
    const bad = await cia.post('/cia/register', { ...base, sig_reg: await signRegistration(other.sk_u, 12345n, reg.cm_u) });
    assert.equal(bad.status, 400); assert.equal(bad.body.error, 'bad_registration_signature');
    u = await cia.registerUser('12345', 'password123');
    assert.equal(u.slot, 0); assert.deepEqual(u.attrs, ['1990', '410', '2', '0', '0', '0']); assert.equal(u.body.sk_u, undefined);
    const a = await cia.registerUser('67890', 'alicepw');
    assert.equal(a.slot, 1);
  });
  let cred;
  await t('발급: 201 { Cf_u, slot, regRoot, epoch, published:true } — 체인 regRoot·SlotUpdated(0, L_reg) 가 같이 간다', async () => {
    cred = await buildUserCredRequest({ uid: 12345n, s_u: u.s_u, r_u: u.r_u, sk_u: u.sk_u, attrs: ATTRS });
    const r = await cia.post('/cia/user_cred', cred.body);
    assert.equal(r.status, 201, j(r.body));
    assert.equal(r.body.slot, 0); assert.equal(r.body.published, true); assert.equal(r.body.leaf, undefined, 'V9: 사용자 리프는 없다');
    assert.equal(b32(r.body.regRoot), await log.regRoot());
    const ev = await log.queryFilter(log.filters.SlotUpdated(), 0, 'latest');
    assert.equal(ev.length, 1); assert.equal(Number(ev[0].args.index), 0);
    assert.equal(BigInt(ev[0].args.leaf), await registryLeaf(u.cm_u, cred.Cf_u));
    const same = await cia.post('/cia/user_cred', cred.body);   // 멱등
    assert.equal(same.status, 200); assert.equal(same.body.published, false);
  });
  await t('교체: 새 C_u 를 받으면 슬롯 리프가 바뀌고 게시된다; 옛 Cf_u 로 세션 발급은 403 no_user_cred', async () => {
    const cred2 = await buildUserCredRequest({ uid: 12345n, s_u: u.s_u, r_u: u.r_u, sk_u: u.sk_u, attrs: ATTRS });
    const r = await cia.post('/cia/user_cred', cred2.body);
    assert.equal(r.status, 201); assert.equal(r.body.published, true);
    const ev = await log.queryFilter(log.filters.SlotUpdated(), 0, 'latest');
    assert.equal(BigInt(ev.at(-1).args.leaf), await registryLeaf(u.cm_u, cred2.Cf_u));
    const iss = await buildIssueRequest({ uid: 12345n, Cf_u: cred.Cf_u, arid: 22222222222222222222n, sk_u: u.sk_u, session: createSessionKey(), chainid: 31337n, max_height: BigInt(await provider.getBlockNumber()) + 300n });
    const rs = await cia.post('/cia/issue', iss.body);
    assert.equal(rs.status, 403); assert.equal(rs.body.reason, 'no_user_cred');
    cred = cred2;
  });
  await t('은퇴(scope=credential): 슬롯 0 게시, 폐기 트리 리프 수는 불변', async () => {
    const before = (await cia.get('/cia/state')).body.leafCount;
    const r = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.retired, 1); assert.equal(r.body.published, true);
    const ev = await log.queryFilter(log.filters.SlotUpdated(), 0, 'latest');
    assert.equal(BigInt(ev.at(-1).args.leaf), 0n);
    assert.equal((await cia.get('/cia/state')).body.leafCount, before, '사용자 리프를 폐기 트리에 넣지 않는다');
    const again = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' });
    assert.equal(again.body.retired, 0);
  });
  await t('계정 폐기(scope=account): disabled + 슬롯 0; 세션 폐기는 여전히 폐기 트리 리프(pending → publish 로 Revoked)', async () => {
    const c3 = await buildUserCredRequest({ uid: 12345n, s_u: u.s_u, r_u: u.r_u, sk_u: u.sk_u, attrs: ATTRS });
    assert.equal((await cia.post('/cia/user_cred', c3.body)).status, 201);
    const iss = await buildIssueRequest({ uid: 12345n, Cf_u: c3.Cf_u, arid: 22222222222222222222n, sk_u: u.sk_u, session: createSessionKey(), chainid: 31337n, max_height: BigInt(await provider.getBlockNumber()) + 300n });
    const issued = await cia.post('/cia/issue', iss.body);
    assert.equal(issued.status, 200, j(issued.body));
    const nonce = randomScalar();
    const rv = await cia.post('/cia/revoke', { uid: '12345', scope: 'session', Cf_s: issued.body.Cf_s, sig_u: await signRevokeSession(u.sk_u, 12345n, BigInt(issued.body.Cf_s), nonce), nonce: nonce.toString() });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.inserted, true);
    assert.equal((await cia.get('/cia/state')).body.pendingCount, 1);
    const ra = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' });
    assert.equal(ra.status, 200, j(ra.body)); assert.equal(ra.body.disabled, true); assert.equal(ra.body.published, true);
    assert.equal((await cia.get('/cia/state')).body.pendingCount, 0, '계정 폐기 게시에 세션 리프도 함께 나갔다');
    const rev = await log.queryFilter(log.filters.Revoked(), 0, 'latest');
    assert.equal(rev.at(-1).args.leaves.length, 1);
  });
  await t('/cia/state·/cia/accounts: regRoot·슬롯 정보', async () => {
    const s = (await cia.get('/cia/state')).body;
    assert.equal(b32(s.regRoot), await log.regRoot()); assert.equal(s.pendingSlots, 0);
    const a = (await cia.adminGet('/cia/accounts')).body.accounts.find((x) => x.uid === '12345');
    assert.equal(a.slot, 0); assert.equal(a.tampered, false); assert.equal(a.registryLeaf, '0');
  });
} finally { await cia.stop(); }

// ---- 마이그레이션: v8 상태 파일로 기동하면 슬롯을 배정하고 활성 자격증명 리프를 채워 게시한다 ----
await t('v8 상태 파일 → 기동 시 등록부 생성·게시', async () => {
  const reg = await createRegistration();
  const blind_u = randomScalar();
  const { Cx, Cy, Cf } = await userCommit({ uid: 12345n, s_u: reg.s_u, blind_u, attrs: ATTRS });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-v8-'));
  const stateFile = path.join(dir, 'cia_state.json');
  fs.writeFileSync(stateFile, JSON.stringify({ version: 8, accounts: { '12345': { pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() }, cm_u: pointToStrings(reg.cm_u), disabled: false, creds: [{ Cf_u: Cf.toString(), C_u_pt: { x: Cx.toString(), y: Cy.toString() }, leaf: '0', issuedAt: 'x', revoked: false }], attrs: ['1990', '410', '2', '0'], sessions: [] } }, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 }));
  const cia2 = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile } });
  try {
    const log2 = new ethers.Contract(cia2.logAddress, MODE3_LOG_ABI, provider);
    const expected = await registryLeaf(reg.cm_u, Cf);
    const tree = await createRegistryTree(); tree.set(0, expected);
    assert.equal(await log2.regRoot(), b32(tree.root()), '기동 자동 게시로 체인 regRoot 가 슬롯 0 하나짜리 트리');
    const ev = await log2.queryFilter(log2.filters.SlotUpdated(), 0, 'latest');
    assert.equal(ev.length, 1); assert.equal(BigInt(ev[0].args.leaf), expected);
    const a = (await cia2.adminGet('/cia/accounts')).body.accounts[0];
    assert.equal(a.slot, 0); assert.deepEqual(a.attrs, ['1990', '410', '2', '0', '0', '0']);
    assert.equal(a.registryLeaf, expected.toString());
  } finally { await cia2.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
});
provider.destroy();
process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 7: 실패 확인** — `node tests/test_cia_registry.mjs` (hardhat :8545 필요) → 등록 400(pk_u 모름) 등으로 FAIL.

- [ ] **Step 8: `cia.js`** — 번호 순서로.

1. import: `userLeaf` 제거(`import { sessionLeaf, createRevocationTree } from './lib/mode3_revocation.js';`), `registerMessage` 를 `./lib/mode3_issuance.js` import 에 추가, `import { MODE3_LOG_ABI, rootToBytes32, signPublicationV2 } from './lib/mode3_log.js';`(`LOG_ABI`·`signRootPublication` 제거), `import { createRegistryTree, registryLeaf } from './lib/mode3_registry.js';`.
2. `DEMO_ACCOUNTS`: testuser `['1990', '410', '2', '0', '0', '0']`, alice `['2005', '840', '1', '0', '0', '0']`; 주석에 `a₄·a₅ 예비`.
3. 상태 주석에 `slot`·`tampered`·`registry` 설명(Interfaces 의 모양). `let tree; let publishedTree;` 옆에 `let registry;   // 등록부(설계 2026-10-01 §3) — state.registry.leaves 에서 복원`.
4. `readChain()` 교체:
```js
async function readChain() {
  const log = new ethers.Contract(LOG_ADDRESS, MODE3_LOG_ABI, ethWallet);
  const [root, regRoot, epoch] = await Promise.all([log.revRoot(), log.regRoot(), log.epoch()]);
  return { onchainRoot: BigInt(root), onchainRegRoot: BigInt(regRoot), onchainEpoch: Number(epoch) };
}
```
5. `reconcileWithChain` 의 `if (onchainEpoch > state.epoch)` 블록 뒤, `if (changed) persist();` 앞에 등록부 대조를 넣는다(인자에 `onchainRegRoot` 를 받는다: `async function reconcileWithChain({ onchainRoot, onchainRegRoot, onchainEpoch })`):
```js
  // 등록부(V9): 갱신형이라 접두사 대조가 없다. 체인과 같으면 미게시 갱신이 없는 것이고, 다르면 지금 트리의 모든 칸(미게시 0 포함)을
  // 다음 게시에 전부 다시 내보낸다 — 지갑은 SlotUpdated 를 순서대로 재생해 root 를 맞추므로 중복 이벤트는 무해하다.
  if (registry.root() === onchainRegRoot) {
    if (state.registry.pendingSlots.length) { state.registry.pendingSlots = []; changed = true; }
  } else {
    const idx = new Set([...state.registry.pendingSlots.map((p) => p.index), ...registry.entries().map(([i]) => i)]);
    state.registry.pendingSlots = [...idx].sort((a, b) => a - b).map((i) => ({ index: i, leaf: registry.leafAt(i).toString() }));
    changed = true;
  }
```
6. `loadState()`: `tree = await createRevocationTree(); for (...) tree.insert(...)` 다음에:
```js
  registry = await createRegistryTree(state.registry.depth);
  for (const [i, leaf] of Object.entries(state.registry.leaves)) registry.set(Number(i), BigInt(leaf));
  // v9 이행 뒤(또는 리프가 비어 있는 슬롯): 활성 자격증명의 리프를 채운다 — Poseidon 이 비동기라 이행 함수가 못 한다.
  let filled = 0;
  for (const [uid, acct] of Object.entries(state.accounts)) {
    const cur = activeCred(uid);
    if (!cur || !Number.isInteger(acct.slot) || state.registry.leaves[acct.slot] !== undefined) continue;
    const leaf = await registryLeaf(acct.cm_u, cur.Cf_u);
    setSlot(uid, leaf); filled++;
  }
  if (filled) { console.warn(`[cia] 등록부: 활성 자격증명 ${filled}개의 슬롯을 채웠다 — 다음 게시에 나간다`); persist(); }
```
   그리고 **등록부 대조는 트리 생성 뒤에** 돌아야 하므로, `publishedTree = await buildPublishedTree();` 와 `if (LOG_ADDRESS) { … reconcileWithChain(chain) … }` 블록을 위 등록부 생성 코드 **뒤로** 옮긴다(순서: 이행 → publishedTree → tree → registry 채움 → 체인 대조 → selfChainId → 자동 게시). 자동 게시 조건을 `if ((migrated.notes.length || filled) && (state.pending.length > 0 || state.registry.pendingSlots.length > 0))` 로 넓히고 로그에 `슬롯 ${r.slots ?? 0}개` 를 더한다.
7. 유틸(`activeCred` 옆):
```js
/** 등록부 슬롯 갱신(설계 2026-10-01 §3.2). leaf 0 = 비움. 다음 게시(pendingSlots)에 실린다 — 호출자가 persist·publish 한다. */
function setSlot(uid, leaf) {
  const acct = state.accounts[uid];
  if (!Number.isInteger(acct?.slot)) throw new Error(`setSlot: ${uid} 에 슬롯이 없다`);
  const v = BigInt(leaf);
  registry.set(acct.slot, v);
  if (v === 0n) delete state.registry.leaves[acct.slot]; else state.registry.leaves[acct.slot] = v.toString();
  state.registry.pendingSlots.push({ index: acct.slot, leaf: v.toString() });
}
/** 등록부가 바뀐 직후의 즉시 게시. 실패해도 상태는 유지하고 pendingSlots 가 남아 하트비트가 재시도한다(§3.3). */
async function publishSafely() {
  try { return await publishNow(); }
  catch (e) { console.warn(`[cia] 즉시 게시 실패(다음 하트비트가 재시도): ${e.message}`); return { published: false, error: e.message }; }
}
```
8. `retireActiveCred(uid)` 교체 — 폐기 트리에 넣지 않는다:
```js
/** 활성 자격증명을 revoked 로 돌린다(V9: 폐기 트리에 넣지 않는다 — 슬롯을 0 으로 두는 것이 호출자의 몫). 돌려주는 값은 물린 개수. */
function retireActiveCred(uid) {
  let n = 0;
  for (const c of state.accounts[uid]?.creds ?? []) if (!c.revoked) { c.revoked = true; n++; }
  return n;
}
```
   호출부 전부(`/cia/user_cred` 의 루프, `revokeAccount`, `/cia/revoke scope=credential`, `/cia/accounts/:uid/attrs`)를 아래대로 고친다. `await retireActiveCred` 는 동기 호출로.
9. `/cia/register` 교체:
```js
// §6.1 + V9 §7.1 등록. 키는 지갑이 만든다 — CIA 는 pk_u 와 소유 증명 서명만 받고 슬롯 번호를 배정한다.
app.post('/cia/register', async (req, res) => {
  const { uid, pwd, cm_u, pk_u, sig_reg } = req.body ?? {};
  if (!isDec(uid) || typeof pwd !== 'string' || !isPt(cm_u) || !isPt(pk_u) || !sig_reg) return res.status(400).json({ error: 'uid, pwd, cm_u{x,y}, pk_u{x,y}, sig_reg required' });
  const acct = Object.values(DEMO_ACCOUNTS).find((a) => a.uid === uid);
  if (!acct || acct.password !== pwd) return res.status(401).json({ error: 'invalid credentials' });
  if (state.accounts[uid]) return res.status(409).json({ error: 'already registered' });
  if (!(await isValidPoint(pointFromStrings(cm_u)))) return res.status(400).json({ error: 'cm_u is not a valid subgroup point' });
  if (!(await isValidPoint(pointFromStrings(pk_u)))) return res.status(400).json({ error: 'pk_u is not a valid subgroup point' });
  let ok = false;
  try {
    const m = F.e(await registerMessage(BigInt(uid), pointFromStrings(cm_u)));
    ok = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig_reg.R8x)), F.e(BigInt(sig_reg.R8y))], S: BigInt(sig_reg.S) }, [F.e(BigInt(pk_u.x)), F.e(BigInt(pk_u.y))]);
  } catch { ok = false; }
  if (!ok) return res.status(400).json({ error: 'bad_registration_signature' });
  if (state.accounts[uid]) return res.status(409).json({ error: 'already registered' });   // await 사이 경합
  const slot = state.registry.next++;
  state.accounts[uid] = { pk_u: { x: BigInt(pk_u.x).toString(), y: BigInt(pk_u.y).toString() }, cm_u: { x: cm_u.x, y: cm_u.y }, slot, tampered: false, disabled: false, creds: [], attrs: [...acct.attrs], sessions: [] };
  persist();
  res.status(201).json({ slot, attrs: state.accounts[uid].attrs });
});
```
10. `/cia/user_cred`: `const leaf = (await userLeaf(BigInt(Cf_u))).toString();` 줄 삭제. 멱등 반환 `return res.json({ Cf_u, leaf })` → `return res.json({ Cf_u, slot: acct.slot, regRoot: registry.root().toString(), epoch: state.epoch, published: false })` (앞의 `if (retired) persist()` 는 `retired` 변수가 더 이상 비동기 은퇴를 뜻하지 않으므로 아래처럼 단순화). 루프를
```js
    const retired = retireActiveCred(uid);
    if (acct.disabled) { if (retired) { setSlot(uid, 0n); persist(); await publishSafely(); } return res.status(403).json({ error: 'account disabled' }); }
    if (acct.creds.some((c) => c.Cf_u === Cf_u)) return res.status(409).json({ error: 'this user credential was revoked; make a new one' });
    acct.creds.push({ Cf_u, C_u_pt: { x: cpt.x.toString(), y: cpt.y.toString() }, issuedAt: new Date().toISOString(), revoked: false });
    setSlot(uid, await registryLeaf(acct.cm_u, BigInt(Cf_u)));
    persist();
    const pub = await publishSafely();
    res.status(201).json({ Cf_u, slot: acct.slot, regRoot: registry.root().toString(), epoch: state.epoch, published: Boolean(pub.published) });
```
   (`for (;;)` 루프와 그 위 긴 주석은 지운다 — 은퇴가 동기라 끼어들기가 없다. 멱등 분기 `if (cur && cur.Cf_u === Cf_u)` 는 루프 앞에 그대로 둔다.)
11. `revokeAccount(uid)`:
```js
async function revokeAccount(uid) {
  const acct = state.accounts[uid];
  if (!acct) throw Object.assign(new Error('unknown account'), { status: 404 });
  acct.disabled = true;
  const retired = retireActiveCred(uid);
  setSlot(uid, 0n);
  persist();
  const pub = await publishSafely();
  return { retired, disabled: true, slot: acct.slot, regRoot: registry.root().toString(), published: Boolean(pub.published), pending: state.pending.length };
}
```
   `scope === 'credential'` 분기:
```js
    if (scope === 'credential') {
      const retired = retireActiveCred(uid);
      setSlot(uid, 0n); persist();
      const pub = await publishSafely();
      return res.json({ retired, slot: state.accounts[uid].slot, regRoot: registry.root().toString(), published: Boolean(pub.published), pending: state.pending.length });
    }
```
   `/cia/account/self_revoke` 안의 `disabled = true` + 은퇴 코드는 `const r = await revokeAccount(uid); return res.json(r);` 로.
12. `/cia/accounts/:uid/attrs`: `const inserted = await retireActiveCred(uid);` → `const retired = retireActiveCred(uid); setSlot(uid, 0n); persist(); const pub = await publishSafely();` 그리고 응답에 `retired, published` (옛 `inserted` 키는 지운다). 주석의 "리프 → 다음 게시" 를 "슬롯 0 → 즉시 게시" 로.
13. `publishNow` 교체(함수 본문의 `if (state.pending.length === 0 && !heartbeat)` 부터 return 까지):
```js
    const noRev = state.pending.length === 0, noSlots = state.registry.pendingSlots.length === 0;
    if (noRev && noSlots && !heartbeat) return { published: false, heartbeat: false, epoch: state.epoch, root: tree.getRoot().toString(), regRoot: registry.root().toString() };
    const log = new ethers.Contract(LOG_ADDRESS, MODE3_LOG_ABI, ethWallet);
    const leaves = state.pending.map(rootToBytes32);
    const slots = state.registry.pendingSlots.slice();   // 이번 tx 에 실을 갱신(순서 유지 — 같은 칸의 set→0 도 순서대로 재생돼야 한다)
    const slotIdx = slots.map((s) => s.index), slotLeaves = slots.map((s) => rootToBytes32(s.leaf));
    const revRoot = rootToBytes32(tree.getRoot()), regRoot = rootToBytes32(registry.root());
    const epoch = state.epoch + 1;
    const sig = await signPublicationV2(ethWallet, { logAddress: LOG_ADDRESS, revRoot, regRoot, epoch, revLeaves: leaves, slotIdx, slotLeaves });
    const tx = await log.publish(revRoot, regRoot, epoch, leaves, slotIdx, slotLeaves, sig);
    await tx.wait();
    state.epoch = epoch;
    for (const l of state.pending.slice(0, leaves.length)) await publishedTree.insert(BigInt(l));
    state.pending = state.pending.slice(leaves.length);
    state.registry.pendingSlots = state.registry.pendingSlots.slice(slots.length);
    persist();
    return { published: true, heartbeat: leaves.length === 0 && slots.length === 0, epoch, root: tree.getRoot().toString(), regRoot: registry.root().toString(), txHash: tx.hash, leaves, slots: slots.length };
```
    `heartbeatTick` 의 `new ethers.Contract(LOG_ADDRESS, LOG_ABI, …)` → `MODE3_LOG_ABI`; `/mode3/health` 의 `new ethers.Contract(LOG_ADDRESS, LOG_ABI, ethWallet)` 도 같이.
14. `/cia/state` 응답에 `regRoot: registry.root().toString(), registrySlots: registry.entries().length, pendingSlots: state.registry.pendingSlots.length`.
15. `/cia/accounts`: 항목에 `slot: a.slot, tampered: Boolean(a.tampered), registryLeaf: state.registry.leaves[a.slot] ?? '0'`.
16. `/cia/open/request`: `publicSignals.length !== 30`, 오류 문구 `publicSignals[30]`, 구조 분해 `const [PPID, aridIn, , max_height, chainIn, allowAgent, , , ciaX, ciaY, traceX, traceY, c1x, c1y, c2] = ps;`, 주석 `V9: 공개 입력 30 — [7] regRoot 가 끼어 태그는 [12..14]`.
17. 기동 로그 `console.log` 에 `registry=${registry.entries().length}` 를 더한다.

- [ ] **Step 9: 통과·커밋** — `node tests/test_cia_registry.mjs` → 전부 ok(두 격리 CIA 가 뜬다). `node tests/test_mode3_cia_state_v9.js` ok.
```bash
git add lib/mode3_cia_state.js cia.js tests/helpers/isolated_cia.mjs tests/test_mode3_cia_state_v9.js tests/test_cia_registry.mjs scripts/run_tests.sh
git commit -m "feat(mode3): CIA 등록부 — 상태 v9·슬롯 배정·등록 키 검증·즉시 게시 V2·은퇴 = 슬롯 0 (V9 7/16)"
```

---

### Task 8: 기존 CIA·라이브러리 테스트를 V9 API 로 옮긴다

**Files:**
- Modify: `tests/test_cia_register_issue.mjs`, `tests/test_cia_opening.mjs`, `tests/test_cia_startup.mjs`, `tests/test_cia_issue_race.mjs`, `tests/test_mode3_session_revoke.mjs`, `tests/test_mode3_health.mjs`

**Interfaces:** Consumes Task 7 의 HTTP 모양과 `cia.registerUser`.

- [ ] **Step 1: 한 번에 찾기**

Run: `grep -n "cia/register'\|\.sk_u\|inserted\|userLeaf\|\.leaf\b\|'1990', '410', '2', '0'\]\|\[1990n, 410n, 2n, 0n\]\|\[2005n, 840n, 1n, 0n\]\|length !== 25\|publicSignals\[11\]\|\[11\]" tests/test_cia_register_issue.mjs tests/test_cia_opening.mjs tests/test_cia_startup.mjs tests/test_cia_issue_race.mjs tests/test_mode3_session_revoke.mjs tests/test_mode3_health.mjs`
각 줄을 아래 규칙으로 고친다.

- [ ] **Step 2: 규칙**
  1. `cia.post('/cia/register', { uid, pwd, cm_u })` + `r.body.sk_u` → `const u = await cia.registerUser(uid, pwd);` 로 바꾸고 `u.s_u, u.r_u, u.cm_u, u.sk_u(hex), u.pk_u` 를 쓴다. `Buffer.from(r.body.sk_u, 'hex')` 가 필요하던 곳은 `Buffer.from(u.sk_u, 'hex')`.
  2. 4슬롯 상수 → 6슬롯(`'0','0'` 또는 `0n, 0n` 두 개 추가). `TESTUSER_ATTRS = [1990n, 410n, 2n, 0n, 0n, 0n]`, `ALICE_ATTRS = [2005n, 840n, 1n, 0n, 0n, 0n]`.
  3. `/cia/user_cred` 응답: `r.body.leaf` 단언은 `r.body.slot`(testuser 0, 첫 등록 순) 과 `r.body.published === true` 로.
  4. `/cia/revoke scope=credential|account` 응답: `inserted: [leaf]` → `retired: 1`, `inserted: []` → `retired: 0`; "체인이 죽어도 활성 자격증명의 리프는 들어간다"(`test_cia_register_issue.mjs` 380~395) → "체인이 죽어도 슬롯은 0 이 되고 `published:false`, `/cia/state` 의 `pendingSlots ≥ 1`".
  5. `revokedLeaf()`(`test_cia_register_issue.mjs` 84~91)를 **세션 리프**로: 활성 자격증명으로 세션을 하나 발급(`issueRequest`)하고 관리자 `/cia/revoke { uid, scope: 'session', Cf_s }` 로 폐기해 `r.body.leaf` 를 돌려준다. 이 함수에 기대던 "pending 에 리프 하나" 의 뜻은 그대로다. 그것을 쓰는 케이스(287~290, 322~327, 457~470)의 `cred.leaf` 비교는 돌려받은 세션 리프로.
  6. `test_cia_register_issue.mjs` 166~170(`돌려준 sk_u 가 pk_u 와 맞아야 한다`) → `eddsaPubOf(u.sk_u)` 가 `/cia/accounts` 의 `pk_u` 와 같은지로(관리자 조회가 pk_u 를 안 싣고 있으면 그 단언은 지운다 — 등록 서명 검증이 이미 Task 7 테스트에 있다).
  7. 관리자 속성 변경(549~568): `['1990', '410', '3', '0']` → 6칸, `r.body.inserted.length === 1` → `r.body.retired === 1 && r.body.published === true`, 길이 검사 `['1990', '410']` 400 은 그대로.
  8. `test_cia_opening.mjs`: `publicSignals` 길이 25 → 30 이 들어간 자리, 태그 색인 `[11]..[13]` → `[12]..[14]`. 트랜스크립트는 `buildCredentialProof` 로 만들 텐데 그 함수는 Task 10 에서 V9 로 바뀐다 — **이 파일은 Task 10 뒤에 다시 돌린다**(여기서는 색인·상수만 고친다).
  9. `test_mode3_session_revoke.mjs`: 등록 1·속성 2 규칙만. `inserted:true`·`leaf` 단언(세션 폐기)은 그대로다.
  10. `test_mode3_health.mjs`: 등록 1·속성 2 규칙. 민감 "값" 목록에 `pk_u` 가 있으면 그대로(응답에 안 실린다).
  11. `test_cia_startup.mjs`·`test_cia_issue_race.mjs`: 등록 1 규칙, `inserted` 4 규칙. startup 테스트가 로그 재배포·상태 불일치를 보면 `deployRevocationLog` → `deployMode3Log`.

- [ ] **Step 3: 실행** — `node tests/test_cia_register_issue.mjs && node tests/test_cia_startup.mjs && node tests/test_cia_issue_race.mjs && node tests/test_mode3_session_revoke.mjs && node tests/test_mode3_health.mjs`
Expected: 전부 ok. (`test_cia_opening.mjs` 는 Task 10 뒤.)

- [ ] **Step 4: 커밋**
```bash
git add tests/test_cia_register_issue.mjs tests/test_cia_opening.mjs tests/test_cia_startup.mjs tests/test_cia_issue_race.mjs tests/test_mode3_session_revoke.mjs tests/test_mode3_health.mjs
git commit -m "test(mode3): CIA 테스트를 V9 로 — registerUser 헬퍼, 슬롯·retired 응답, 속성 6칸, 공개 입력 30 (V9 8/16)"
```

---

### Task 9: 관리자 — 슬롯 바꿔치기·되돌리기, 등록부 조회, 속성 6칸 화면

**Files:**
- Modify: `cia.js` (엔드포인트 셋), `mode3/cia_admin.html`, `mode3/common/strings.js`
- Modify: `tests/test_cia_registry.mjs` (케이스 추가)

**Interfaces:**
- Produces: `POST /cia/admin/registry/tamper {uid}` (requireAdmin) → 200 `{ slot, leaf, regRoot, published }`, 409 `no_active_credential`; `POST /cia/admin/registry/restore {uid}` → 200 `{ slot, leaf, regRoot, published }`; `GET /cia/admin/registry` → `{ depth, next, regRoot, epoch, pendingSlots, slots: [{ index, uid, leaf, tampered, active }] }`.
- 화면: 계정 표에 "등록부" 열(슬롯 번호 + 상태 배지: 활성/비어 있음/바꿔치기됨), 작업 열에 "슬롯 바꿔치기(시연)"·"되돌리기" 버튼. strings 키 `admin_col_registry, admin_tamper_btn, admin_restore_btn, admin_tamper_title, admin_tamper_summary, admin_restore_title, admin_restore_summary, admin_tamper_failed, admin_restore_failed, admin_reg_active, admin_reg_empty, admin_reg_tampered, confirm_tamper`; `admin_accounts_attrs_note`·`admin_col_attrs` 를 6칸 문구로; `attr4`·`attr5` 용어(`속성 5`·`속성 6`, en `Attribute 5/6`, expert `attrs[4] (a₅)`·`attrs[5] (a₆)`).

- [ ] **Step 1: 테스트 추가** — `tests/test_cia_registry.mjs` 의 첫 `try` 블록 안, `/cia/state·/cia/accounts` 케이스 뒤:
```js
  await t('관리자 바꿔치기: 슬롯에 가짜 리프를 게시하면 regRoot 가 바뀌고 tampered:true; 되돌리기로 진짜 리프·false', async () => {
    const c4 = await buildUserCredRequest({ uid: 67890n, s_u: alice.s_u, r_u: alice.r_u, sk_u: alice.sk_u, attrs: [2005n, 840n, 1n, 0n, 0n, 0n] });
    assert.equal((await cia.post('/cia/user_cred', c4.body)).status, 201);
    const real = await registryLeaf(alice.cm_u, c4.Cf_u);
    const before = await log.regRoot();
    const tp = await cia.adminPost('/cia/admin/registry/tamper', { uid: '67890' });
    assert.equal(tp.status, 200, j(tp.body)); assert.equal(tp.body.slot, 1); assert.notEqual(BigInt(tp.body.leaf), real); assert.equal(tp.body.published, true);
    assert.notEqual(await log.regRoot(), before);
    const reg = (await cia.adminGet('/cia/admin/registry')).body;
    const s = reg.slots.find((x) => x.index === 1);
    assert.equal(s.uid, '67890'); assert.equal(s.tampered, true); assert.equal(s.leaf, tp.body.leaf);
    const rs = await cia.adminPost('/cia/admin/registry/restore', { uid: '67890' });
    assert.equal(rs.status, 200, j(rs.body)); assert.equal(BigInt(rs.body.leaf), real);
    assert.equal((await cia.adminGet('/cia/admin/registry')).body.slots.find((x) => x.index === 1).tampered, false);
    assert.equal((await cia.adminPost('/cia/admin/registry/tamper', { uid: '12345' })).status, 409, '활성 자격증명 없음(폐기된 계정)');
  });
```
(`alice` 는 첫 케이스에서 `const a = await cia.registerUser('67890', 'alicepw')` 로 받은 값을 `let alice` 에 담아 둔다.)

- [ ] **Step 2: 실패 확인** — 404.

- [ ] **Step 3: `cia.js`** — `/cia/accounts` 아래에:
```js
// ---- V9 등록부 관리(설계 2026-10-01 §9) ----
app.get('/cia/admin/registry', requireAdmin, (req, res) => {
  const byIndex = new Map(Object.entries(state.accounts).map(([uid, a]) => [a.slot, { uid, a }]));
  const slots = registry.entries().map(([index, leaf]) => {
    const e = byIndex.get(index);
    return { index, uid: e?.uid ?? null, leaf: leaf.toString(), tampered: Boolean(e?.a.tampered), active: e ? Boolean(activeCred(e.uid)) : false };
  });
  res.json({ depth: registry.depth, next: state.registry.next, regRoot: registry.root().toString(), epoch: state.epoch, pendingSlots: state.registry.pendingSlots.length, slots });
});
/** 시연: "장부를 속이는 AA" — 활성 자격증명은 그대로 두고 슬롯에 가짜 리프를 게시한다. 지갑의 등록부 확인이 ✗ 가 되고 로그인이 막힌다. */
app.post('/cia/admin/registry/tamper', requireAdmin, async (req, res) => {
  try {
    const { uid } = req.body ?? {};
    const acct = state.accounts[uid];
    if (!isDec(uid) || !acct) return res.status(404).json({ error: 'unknown account' });
    if (!activeCred(uid)) return res.status(409).json({ error: 'no_active_credential' });
    const fake = (await registryLeaf(acct.cm_u, randomScalar())).toString();
    setSlot(uid, fake); acct.tampered = true; persist();
    const pub = await publishSafely();
    res.json({ slot: acct.slot, leaf: fake, regRoot: registry.root().toString(), published: Boolean(pub.published) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/cia/admin/registry/restore', requireAdmin, async (req, res) => {
  try {
    const { uid } = req.body ?? {};
    const acct = state.accounts[uid];
    if (!isDec(uid) || !acct) return res.status(404).json({ error: 'unknown account' });
    const cur = activeCred(uid);
    const leaf = cur ? (await registryLeaf(acct.cm_u, BigInt(cur.Cf_u))).toString() : '0';
    setSlot(uid, leaf); acct.tampered = false; persist();
    const pub = await publishSafely();
    res.json({ slot: acct.slot, leaf, regRoot: registry.root().toString(), published: Boolean(pub.published) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
```

- [ ] **Step 4: 관리자 페이지** — `mode3/cia_admin.html`
  - 안내 문구 `admin_accounts_attrs_note` 의 ko/en 을 "속성 6슬롯을 바꾸면 활성 자격증명이 물리고 등록부 슬롯이 0 으로 즉시 게시됩니다 — 지갑은 다음 발급에서 다시 받습니다." 로(`strings.js`).
  - `renderAccounts`: 표 머리 `[['admin_col_uid'], ['admin_col_status'], ['admin_col_registry'], ['admin_col_attrs'], ['admin_col_action']]`; 상태 셀 뒤에 등록부 셀: `cell(row, badge(a.tampered ? 'admin_reg_tampered' : a.registryLeaf !== '0' ? 'admin_reg_active' : 'admin_reg_empty', a.tampered ? 'bad' : a.registryLeaf !== '0' ? 'ok' : 'muted'))` 와 그 앞에 `#${a.slot}` 텍스트. 세션 하위 행의 `colSpan = 5`.
  - 작업 셀에 두 버튼 추가:
```js
        act.appendChild(document.createTextNode(' '));
        act.appendChild(button('admin_tamper_btn', 'danger', () => { if (!Demo.confirmDanger('confirm_tamper')) return; run('admin_tamper_failed', () => call('POST', '/cia/admin/registry/tamper', { uid: a.uid }), ({ body }) => { setVerdict($('adminVerdict'), true, 'admin_tamper_title', () => ({ summary: Demo.t('admin_tamper_summary', { uid: a.uid, slot: body.slot }), detail: safeDetail(body) })); loadAccounts(); loadState(); }); }));
        act.appendChild(document.createTextNode(' '));
        act.appendChild(button('admin_restore_btn', 'btn-ghost', () => run('admin_restore_failed', () => call('POST', '/cia/admin/registry/restore', { uid: a.uid }), ({ body }) => { setVerdict($('adminVerdict'), true, 'admin_restore_title', () => ({ summary: Demo.t('admin_restore_summary', { uid: a.uid, slot: body.slot }), detail: safeDetail(body) })); loadAccounts(); loadState(); })));
```
  - 속성 입력칸은 `a.attrs` 길이(6)만큼 자동으로 생긴다(`inputs` 가 배열을 따른다) — `input.size = 4` 그대로.
  - `strings.js` 에 키 추가(ko/en):
```js
    admin_col_registry: { ko: '등록부', en: 'Registry' },
    admin_reg_active: { ko: '활성', en: 'active' }, admin_reg_empty: { ko: '비어 있음', en: 'empty' }, admin_reg_tampered: { ko: '바꿔치기됨', en: 'tampered' },
    admin_tamper_btn: { ko: '슬롯 바꿔치기(시연)', en: 'Tamper slot (demo)' }, admin_restore_btn: { ko: '되돌리기', en: 'Restore' },
    admin_tamper_title: { ko: '슬롯을 바꿔치기했습니다(시연)', en: 'Slot tampered (demo)' },
    admin_tamper_summary: { ko: 'uid {uid} 의 등록부 슬롯 #{slot} 에 가짜 자격증명을 게시했습니다. 지갑 페이지의 등록부 확인이 ✗ 가 되고 로그인이 막힙니다.', en: 'Published a fake credential into registry slot #{slot} of uid {uid}. The wallet page now flags the registry and logins fail.' },
    admin_restore_title: { ko: '슬롯을 되돌렸습니다', en: 'Slot restored' },
    admin_restore_summary: { ko: 'uid {uid} 의 슬롯 #{slot} 에 진짜 자격증명을 다시 게시했습니다.', en: 'Republished the genuine credential into slot #{slot} of uid {uid}.' },
    admin_tamper_failed: { ko: '바꿔치기 실패', en: 'Tampering failed' }, admin_restore_failed: { ko: '되돌리기 실패', en: 'Restore failed' },
    confirm_tamper: { ko: '시연용입니다 — 이 계정의 등록부 슬롯에 가짜 자격증명을 게시합니다. 계속할까요?', en: 'Demo only — publish a fake credential into this account’s registry slot. Continue?' },
    admin_col_attrs: { ko: '속성(출생연도 · 국가 · 등급 · 예비 · 속성5 · 속성6)', en: 'Attributes (birth year · country · tier · spare · attr 5 · attr 6)' },
    attr4: { ko: '속성 5', en: 'Attribute 5', expert: 'attrs[4] (a₅), 64-bit' },
    attr5: { ko: '속성 6', en: 'Attribute 6', expert: 'attrs[5] (a₆), 64-bit' },
```
  (`confirm_*` 키가 `Demo.confirmDanger` 의 사전에 있어야 한다 — 기존 `confirm_revoke` 가 있는 자리에 같은 모양으로.)

- [ ] **Step 5: 통과·커밋** — `node tests/test_cia_registry.mjs` 전부 ok. 관리자 페이지는 Task 13 의 브라우저 테스트가 본다.
```bash
git add cia.js mode3/cia_admin.html mode3/common/strings.js tests/test_cia_registry.mjs
git commit -m "feat(mode3): 관리자 등록부 조회·슬롯 바꿔치기/되돌리기 시연, 속성 6칸 (V9 9/16)"
```

---

### Task 10: 지갑 라이브러리·등록부 동기화·RP 검증기 — V9 증인·30 입력·regRoot 검사, 라이브러리 e2e

**Files:**
- Create: `lib/mode3_registry_sync.js`
- Modify: `lib/mode3_wallet.js` (`buildUserCredRequest`, `buildCredentialProof`, `normalizeDisclosure`, `normalizeSet`, `syncRevocationTree`)
- Modify: `lib/mode3_rcl_sync.js` (`LOG_ABI` → `MODE3_LOG_ABI`, `contract.root(` → `contract.revRoot(`)
- Modify: `lib/mode3_rp.js` (30 입력, regRoot, 6슬롯)
- Modify: `mode3_rp.js:446` (`publicSignals[11]`/`[12]` → `[12]`/`[13]`)
- Modify: `tests/test_mode3_e2e.mjs` (전체 교체)

**Interfaces:**
- Produces:
  - `createRegistrySync({ provider, logAddress })` → `{ sync() → { tree, root, epoch, head } }`; `syncRegistryTree(provider, logAddress)` (한 번 재생 — 테스트·간단 호출용) — 같은 반환.
  - `buildUserCredRequest({ uid, s_u, r_u, sk_u, attrs })` → `{ body, secrets:{blind_u}, C_u_pt, Cf_u }` (`leaf` 없음).
  - `buildCredentialProof({ uid, arid, s_u, r_u, blind_u, blind_s, pk_i, attrs, credential, pk_CIA, pk_trace, tree, registry, slot, cm_u, disclosure, tagR })` → `{ proof, publicSignals(30), revRoot, regRoot, tag }`. 슬롯 리프가 기대값과 다르면 throw: 0 이면 `reason:'registry_empty'`, 아니면 `reason:'registry_mismatch'`.
  - `normalizeDisclosure(disclose, attrs)`: `disclose` 길이 1..6(모자라면 null 로 채움) → `{ mask, lo[6], hi[6] }`; `normalizeSet`: `slot` 0..5.
  - `createRpVerifier(...)`: `verifyLogin` 이 30개를 요구하고 `stale_registry_root` 를 낸다; 반환의 `root` 는 revRoot, `+ regRoot`; `maskDisclosure` 는 길이 6.
  - `createRegistrationSecrets` 등 Snap 쪽은 Task 13.

- [ ] **Step 1: e2e 테스트를 V9 로 다시 쓴다** — `tests/test_mode3_e2e.mjs` 전체:
```js
// Mode 3 전 구간(V9): 등록(지갑 키) → 사용자 자격증명(π_u, 슬롯 게시) → 세션 발급 → 로그인 → 은퇴(슬롯 0) → 거절 → 재발급 → 로그인
//  → 관리자 바꿔치기 → registry_mismatch → 되돌리기. 격리 CIA + :8545 Mode3Log + 지갑 라이브러리 + RP 검증기. (chain 그룹)
//   node tests/test_mode3_e2e.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createSessionKey, buildUserCredRequest, buildIssueRequest, syncRevocationTree, syncRegistryTree, buildCredentialProof, signChallenge, ProofCache, VKEY_PATH } from '../lib/mode3_wallet.js';
import { createRpVerifier } from '../lib/mode3_rp.js';
import { randomScalar } from '../lib/mode3_credential.js';
import { createShare, combinePublicKey } from '../lib/mode3_trace.js';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
const ATTRS = [1990n, 410n, 2n, 0n, 0n, 0n];   // cia.js DEMO_ACCOUNTS.testuser
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH}`);
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = getProvider();
const cia = await startIsolatedCia();
const uid = 12345n;
try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  const { arid: aridStr } = await cia.registerRp('http://127.0.0.1:1');
  const arid = BigInt(aridStr);
  const pk_trace = await combinePublicKey((await createShare()).X, (await createShare()).X);
  const rp = createRpVerifier({ provider, logAddress: cia.logAddress, vkey, pkCIA: pk_CIA, arid, chainId: 31337n, pkTrace: pk_trace });
  const cache = new ProofCache();
  let u, session, userCred, blind_u, blind_s, cred, sessionRs;

  async function trees() {
    const rev = await syncRevocationTree(provider, cia.logAddress);
    const reg = await syncRegistryTree(provider, cia.logAddress);
    return { tree: rev.tree, revRoot: rev.root, registry: reg.tree, regRoot: reg.root };
  }
  async function loginRound() {
    const { tree, revRoot, registry, regRoot } = await trees();
    const key = ProofCache.rootKey(revRoot, regRoot);
    let cached = cache.get(key, session.wallet.address);
    if (!cached) {
      cached = await buildCredentialProof({ uid, arid, s_u: u.s_u, r_u: u.r_u, blind_u, blind_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree, registry, slot: u.slot, cm_u: u.cm_u });
      cache.set(key, session.wallet.address, cached);
    }
    return submit(cached);
  }
  const submit = async (cached) => rp.verifyLogin({ proof: cached.proof, publicSignals: cached.publicSignals, sig: await signChallenge(session.wallet, sessionRs.toString()), r_s: sessionRs });
  async function ensureUserCred() {
    if (userCred) return;
    const uc = await buildUserCredRequest({ uid, s_u: u.s_u, r_u: u.r_u, sk_u: u.sk_u, attrs: ATTRS });
    const r = await cia.post('/cia/user_cred', uc.body);
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.slot, u.slot); assert.equal(r.body.published, true);
    userCred = uc; blind_u = uc.secrets.blind_u;
  }
  async function newSessionAndIssue() {
    await ensureUserCred();
    session = createSessionKey();
    const req = await buildIssueRequest({ uid, Cf_u: userCred.Cf_u, arid, sk_u: u.sk_u, session, chainid: 31337n, max_height: BigInt(await provider.getBlockNumber()) + 300n });
    blind_s = req.secrets.blind_s; sessionRs = randomScalar();
    return cia.post('/cia/issue', req.body);
  }

  await t('등록(지갑 키): 슬롯 0, sk_u 는 지갑에만', async () => {
    u = await cia.registerUser('12345', 'password123');
    assert.equal(u.slot, 0); assert.equal(u.body.sk_u, undefined);
  });
  await t('발급 → 슬롯 게시 → 로그인 성공 (공개 입력 30, [7] = regRoot)', async () => {
    const r = await newSessionAndIssue();
    assert.equal(r.status, 200, j(r.body)); cred = r.body;
    const v = await loginRound();
    assert.equal(v.ok, true, j(v));
    const { regRoot } = await trees();
    const cached = cache.get(ProofCache.rootKey(v.root, regRoot), session.wallet.address);
    assert.equal(cached.publicSignals.length, 30); assert.equal(BigInt(cached.publicSignals[7]), regRoot); assert.equal(v.regRoot, regRoot);
  });
  let PPID1, staleProof;
  await t('같은 root 둘이면 캐시 π 재사용', async () => {
    const tr = await trees();
    const before = cache.get(ProofCache.rootKey(tr.revRoot, tr.regRoot), session.wallet.address);
    const v = await loginRound(); assert.equal(v.ok, true, j(v));
    PPID1 = v.PPID; staleProof = before;
  });
  await t('은퇴(scope=credential): 슬롯 0 게시 → 옛 π 는 stale_registry_root, 새 π 는 registry_empty; 재발급 뒤 PPID 는 그대로', async () => {
    const rv = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.retired, 1); assert.equal(rv.body.published, true);
    const v = await submit(staleProof);
    assert.equal(v.ok, false); assert.equal(v.reason, 'stale_registry_root', j(v));
    const { tree, registry } = await trees();
    await assert.rejects(() => buildCredentialProof({ uid, arid, s_u: u.s_u, r_u: u.r_u, blind_u, blind_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree, registry, slot: u.slot, cm_u: u.cm_u }), (e) => e.reason === 'registry_empty');
    userCred = null;
    const r2 = await newSessionAndIssue(); assert.equal(r2.status, 200, j(r2.body)); cred = r2.body;
    const v2 = await loginRound(); assert.equal(v2.ok, true, j(v2)); assert.equal(v2.PPID, PPID1, 'PPID 는 salt 에서 나오므로 그대로');
  });
  await t('관리자 바꿔치기: 슬롯에 가짜 리프 → 지갑은 registry_mismatch 로 증명을 만들지 않는다; 되돌리기 뒤 다시 로그인', async () => {
    assert.equal((await cia.adminPost('/cia/admin/registry/tamper', { uid: '12345' })).status, 200);
    const { tree, registry } = await trees();
    await assert.rejects(() => buildCredentialProof({ uid, arid, s_u: u.s_u, r_u: u.r_u, blind_u, blind_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree, registry, slot: u.slot, cm_u: u.cm_u }), (e) => e.reason === 'registry_mismatch');
    assert.equal((await cia.adminPost('/cia/admin/registry/restore', { uid: '12345' })).status, 200);
    const v = await loginRound(); assert.equal(v.ok, true, j(v));
  });
  await t('V6: 공개 mask ≠ 0(6슬롯) 로그인도 받는다', async () => {
    const { tree, registry } = await trees();
    const disclosure = { mask: 3n, lo: [0n, 410n, 0n, 0n, 0n, 0n], hi: [2007n, 410n, 0n, 0n, 0n, 0n] };
    const piD = await buildCredentialProof({ uid, arid, s_u: u.s_u, r_u: u.r_u, blind_u, blind_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree, registry, slot: u.slot, cm_u: u.cm_u, disclosure });
    const v = await rp.verifyLogin({ proof: piD.proof, publicSignals: piD.publicSignals, sig: await signChallenge(session.wallet, sessionRs.toString()), r_s: sessionRs });
    assert.equal(v.ok, true, j(v)); assert.equal(v.disclosure.mask, 3n); assert.deepEqual(v.disclosure.hi.map(String), ['2007', '410', '0', '0', '0', '0']);
  });
  await t('세션 폐기(폐기 트리)는 그대로: 리프 게시 뒤 옛 π 는 stale_root, 새 π 는 is a member', async () => {
    const nonce = randomScalar();
    const { signRevokeSession } = await import('../lib/mode3_wallet.js');
    const rv = await cia.post('/cia/revoke', { uid: '12345', scope: 'session', Cf_s: cred.Cf_s, sig_u: await signRevokeSession(u.sk_u, uid, BigInt(cred.Cf_s), nonce), nonce: nonce.toString() });
    assert.equal(rv.status, 200, j(rv.body));
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const { tree, registry } = await trees();
    await assert.rejects(() => buildCredentialProof({ uid, arid, s_u: u.s_u, r_u: u.r_u, blind_u, blind_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree, registry, slot: u.slot, cm_u: u.cm_u }), /is a member/);
  });
  await t('계정 폐기 → disabled 재발급 거절(403) → 복구 → 새 자격증명 → 로그인, PPID 유지', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' })).status, 200);
    userCred = null;
    const r = await newSessionAndIssue(); assert.equal(r.status, 403, j(r.body));
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: '12345', disabled: false })).status, 200);
    const r2 = await newSessionAndIssue(); assert.equal(r2.status, 200, j(r2.body)); cred = r2.body;
    const v = await loginRound(); assert.equal(v.ok, true, j(v)); assert.equal(v.PPID, PPID1);
  });
} finally { await cia.stop(); provider.destroy(); }
process.exit(failed === 0 ? 0 : 1);
```
(`ensureUserCred` 가 403 을 받으면 `assert.equal(r.status, 201)` 에서 던진다 — "계정 폐기" 케이스는 `newSessionAndIssue` 가 그 단언으로 실패하므로, 그 케이스에서는 `ensureUserCred` 대신 직접 `cia.post('/cia/user_cred', …)` 로 403 을 확인하도록 한 줄 바꾼다: `const uc = await buildUserCredRequest({...}); assert.equal((await cia.post('/cia/user_cred', uc.body)).status, 403);`.)

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_e2e.mjs` → `syncRegistryTree` 없음 등.

- [ ] **Step 3: 등록부 동기화** — `lib/mode3_registry_sync.js`:
```js
// Mode 3 지갑의 등록부 동기화(설계 2026-10-01 §8.1) — Mode3Log 의 SlotUpdated 이벤트를 창세기부터 순서대로 재생해 트리를 만들고
// 같은 head 의 regRoot 와 대조한다(fail-closed). 캐시·증분은 두지 않는다(데모 규모; 후속 과제).
import { ethers } from 'ethers';
import { MODE3_LOG_ABI } from './mode3_log.js';
import { createRegistryTree } from './mode3_registry.js';

export async function syncRegistryTree(provider, logAddress) {
  const log = new ethers.Contract(logAddress, MODE3_LOG_ABI, provider);
  const head = BigInt(await provider.getBlockNumber());
  const blockTag = Number(head);
  const [events, onchainRoot, epoch] = await Promise.all([log.queryFilter(log.filters.SlotUpdated(), 0, blockTag), log.regRoot({ blockTag }), log.epoch({ blockTag })]);
  const tree = await createRegistryTree();
  // 이벤트 순서 = 블록·로그 인덱스 순. 같은 칸의 set → 0 이 순서대로 적용돼야 root 가 맞는다.
  events.sort((a, b) => (a.blockNumber - b.blockNumber) || (a.index - b.index));
  for (const e of events) tree.set(Number(e.args.index), BigInt(e.args.leaf));
  const root = tree.root();
  if (root !== BigInt(onchainRoot)) throw new Error(`등록부 재생 root(${root}) 가 컨트랙트 regRoot(${BigInt(onchainRoot)}) 와 다르다 — 이벤트 규약 불일치 또는 calldata 오염`);
  return { tree, root, epoch: BigInt(epoch), head };
}

export function createRegistrySync({ provider, logAddress }) {
  if (!logAddress) throw new Error('createRegistrySync: logAddress 가 필요하다');
  return { sync: () => syncRegistryTree(provider, logAddress) };
}
```

- [ ] **Step 4: `lib/mode3_wallet.js`**
  - import: `userLeaf` 제거(`sessionLeaf, createRevocationTree, MODE3_TREE_DEPTH` 만), `import { MODE3_LOG_ABI } from './mode3_log.js';`(`LOG_ABI` 대신), `import { registryLeaf } from './mode3_registry.js';`, `export { syncRegistryTree } from './mode3_registry_sync.js';`, `import { ATTR_SLOTS } from './mode3_credential.js'` 추가.
  - `normalizeDisclosure`: `if (!Array.isArray(disclose) || disclose.length === 0 || disclose.length > ATTR_SLOTS) throw fail('bad_disclosure', 'disclose 는 길이 1..6 배열');` 로, `lo = Array(ATTR_SLOTS).fill(0n)`, `hi = …`; 기본 반환도 길이 6. 주석 "길이 4" 갱신.
  - `normalizeSet`: `slot > 3` → `slot >= ATTR_SLOTS`, 문구 `0..5`.
  - `buildUserCredRequest`: `leaf` 계산·반환 제거 → `return { body, secrets: { blind_u }, C_u_pt, Cf_u };`.
  - `syncRevocationTree`: `new ethers.Contract(logAddress, MODE3_LOG_ABI, provider)`, `log.root({ blockTag })` → `log.revRoot({ blockTag })`.
  - `buildCredentialProof` 시그니처에 `r_u, registry, slot, cm_u` 추가, 본문:
```js
  if (typeof r_u !== 'bigint') throw new Error('buildCredentialProof: r_u(bigint) 가 필요하다 — 등록 커밋 cm_u 의 블라인딩(V9 조건 9)');
  if (!registry || !Number.isInteger(slot) || typeof cm_u?.x !== 'bigint') throw new Error('buildCredentialProof: registry·slot·cm_u{x,y}(bigint) 가 필요하다');
  const expectedLeaf = await registryLeaf(cm_u, BigInt(credential.Cf_u));
  const onSlot = registry.leafAt(slot);
  if (onSlot !== expectedLeaf) throw Object.assign(new Error(onSlot === 0n ? 'registry_empty' : 'registry_mismatch'), { reason: onSlot === 0n ? 'registry_empty' : 'registry_mismatch', slot, expected: expectedLeaf.toString(), actual: onSlot.toString() });
  const regPath = registry.path(slot);
  const regRoot = registry.root();
```
    사용자 리프 증인(`uLeaf`, `w`, root 비교)을 지우고 `const ws = await tree.getNonMembershipWitness(await sessionLeaf(BigInt(credential.Cf_s))); const revRoot = BigInt(ws.root);`. 입력에서 `lowValue, lowNextIndex, lowNextValue, pathElements, pathIndices` 를 빼고 `r_u: r_u.toString(), reg_pathElements: regPath.pathElements.map(String), reg_pathIndices: regPath.pathIndices.map(String), regRoot: regRoot.toString()` 추가. `disc` 기본값 길이 6(`ZERO6`). 반환 `{ proof, publicSignals, revRoot, regRoot, tag: {...} }`. 머리 주석의 공개 입력 목록을 Global Constraints 로.
  - `ProofCache` 는 키가 문자열이라 그대로다 — 호출자가 `${revRoot}:${regRoot}` 를 root 자리에 넣는다. `deleteSession` 의 `k.split(':')[1]` 은 두 번째 필드가 sessionId 라는 전제이므로 키 모양을 `${revRoot}:${regRoot}:${sessionId}:${discKey}` 로 바꾸면 깨진다 → 호출자는 root 자리에 `revRoot + '/' + regRoot` 처럼 ':' 이 아닌 구분자를 쓴다(`ProofCache.join(revRoot, regRoot)` 정적 헬퍼를 추가: `static rootKey(rev, reg) { return \`${rev}/${reg}\`; }`).
  - `lib/mode3_rcl_sync.js`: import 를 `MODE3_LOG_ABI` 로, `contract.root({ blockTag })` → `contract.revRoot({ blockTag })`.

- [ ] **Step 5: `lib/mode3_rp.js`**
  - `refreshChainView`: `const [root, regRoot, lastPublishedBlock] = await Promise.all([log.revRoot({ blockTag }), log.regRoot({ blockTag }), log.lastPublishedBlock({ blockTag })]); view = { root: BigInt(root), regRoot: BigInt(regRoot), head, lastPublishedBlock: …, readAt }`. `new ethers.Contract(logAddress, MODE3_LOG_ABI, provider)`.
  - `verifyLogin`: `publicSignals.length !== 30`; 구조 분해 `const [PPID, aridIn, pk_i, max_height, chainIn, allowAgent, revRoot, regRoot, ciaX, ciaY, traceX, traceY, c1x, c1y, c2, discMask, ...rest] = ps; const lo = rest.slice(0, 6), hi = rest.slice(6, 12), setSel = rest[12], setRoot = rest[13];`; `maskDisclosure({ mask: discMask, lo, hi, sel: setSel, root: setRoot })`; b 뒤에 `if (regRoot !== v.regRoot) return { ok: false, reason: 'stale_registry_root' };`; `discMask >= 64n`; `setSel > 6n`; 반환에 `regRoot`.
  - `maskDisclosure`: 길이 6 요구.
  - 머리 주석 b 항목에 "b‴ 등록부 root 일치(V9) — stale_registry_root" 추가.
  - `mode3_rp.js:446`: `const c1 = { x: BigInt(T.publicSignals[12]), y: BigInt(T.publicSignals[13]) };`.

- [ ] **Step 6: 통과·커밋** — `node tests/test_mode3_e2e.mjs` → 전부 ok.
```bash
git add lib/mode3_registry_sync.js lib/mode3_wallet.js lib/mode3_rcl_sync.js lib/mode3_rp.js mode3_rp.js tests/test_mode3_e2e.mjs
git commit -m "feat(mode3): 지갑 라이브러리 V9 — 등록부 동기화·조건 9 증인·30 입력, RP 검증기 stale_registry_root (V9 10/16)"
```

---

### Task 11: 라이브러리 수준 체인 테스트 이전 — wallet·rp·rcl_sync·opening

**Files:**
- Modify: `tests/helpers/mode3_chain.mjs` (`publishV2` 헬퍼)
- Modify: `tests/test_mode3_wallet.mjs`, `tests/test_mode3_rp.mjs`, `tests/test_mode3_rcl_sync.mjs`, `tests/test_cia_opening.mjs`

**Interfaces:**
- Produces: `publishV2(log, ciaWallet, { revRoot, regRoot, epoch, revLeaves = [], slotIdx = [], slotLeaves = [] })` (bigint 들을 받아 bytes32 로 바꾸고 서명·전송·wait) — 세 테스트가 자기 `publish()` 대신 쓴다.

- [ ] **Step 1: 헬퍼** — `tests/helpers/mode3_chain.mjs` 끝에:
```js
import { signPublicationV2 } from '../../lib/mode3_log.js';
/** V9 게시 헬퍼 — 테스트가 CIA 없이 Mode3Log 에 두 root 를 올린다. 인자는 bigint, 서명은 ciaWallet. */
export async function publishV2(log, ciaWallet, { revRoot, regRoot, epoch, revLeaves = [], slotIdx = [], slotLeaves = [] }) {
  const b = rootToBytes32;
  const p = { logAddress: await log.getAddress(), revRoot: b(revRoot), regRoot: b(regRoot), epoch, revLeaves: revLeaves.map(b), slotIdx, slotLeaves: slotLeaves.map(b) };
  const sig = await signPublicationV2(ciaWallet, p);
  await (await log.connect(ciaWallet).publish(p.revRoot, p.regRoot, epoch, p.revLeaves, slotIdx, p.slotLeaves, sig)).wait();
}
```
(import 는 파일 머리의 import 묶음에 합친다.)

- [ ] **Step 2: 공통 규칙** — 세 파일(`test_mode3_wallet.mjs`, `test_mode3_rp.mjs`, `test_mode3_rcl_sync.mjs`):
  1. `deployRevocationLog` → `deployMode3Log`; `signRootPublication`·`rootToBytes32` import 는 `publishV2` 로 대체.
  2. 각 파일의 `async function publish(leavesBig)` 를 "폐기 리프를 넣고 두 root 를 올린다" 로: 트리에 `insert` 한 뒤 `publishV2(log, ciaEth, { revRoot: tree.getRoot(), regRoot: registry.root(), epoch: ++epoch, revLeaves: leavesBig })`. 파일에 `const registry = await createRegistryTree();` 를 두고, **첫 로그인 전에** 사용자 슬롯을 채워 게시한다: `registry.set(SLOT, await registryLeaf(reg.cm_u, uc.Cf_u)); await publishV2(log, ciaEth, { revRoot: tree.getRoot(), regRoot: registry.root(), epoch: ++epoch, slotIdx: [SLOT], slotLeaves: [registry.leafAt(SLOT)] });` (SLOT = 0).
  3. `createRegistration()` 이 이제 `sk_u` 를 주므로 `Buffer.alloc(32, 3).toString('hex')` 같은 고정 sk_u 는 `reg.sk_u` 로.
  4. `buildUserCredRequest` 의 `leaf` 단언(`test_mode3_wallet.mjs:103`) 삭제. `buildCredentialProof` 호출에 `r_u: reg.r_u, registry, slot: SLOT, cm_u: reg.cm_u` 추가. `syncRevocationTree` 로 받은 `tree` 와 함께 `const { tree: registry } = await syncRegistryTree(provider, logAddress)` 를 쓰는 것이 "지갑이 체인에서 복원" 의 뜻에 맞다(동기화 테스트는 그것을 쓴다; 단순 케이스는 로컬 `registry` 객체를 넘겨도 된다).
  5. 사용자 리프 폐기 시나리오(`publish([await userLeaf(Cf_u)])`, `test_mode3_wallet.mjs:140`, `test_mode3_rp.mjs:262`) → 슬롯 비우기: `registry.set(SLOT, 0n); await publishV2(…, { slotIdx: [SLOT], slotLeaves: [0n] })`. 기대: `buildCredentialProof` 가 `reason === 'registry_empty'` 로 던지고(동기화한 registry 로), RP 는 옛 π 에 `stale_registry_root`.
  6. 속성 4 → 6, `disclosure` 배열 6, `publicSignals.length` 25 → 30, 색인 `[11..13]` → `[12..14]`, `publicSignals[4]`(chainid) 는 그대로.
  7. `test_mode3_rcl_sync.mjs` 는 폐기 트리만 본다 — `publish` 를 `publishV2(…, { regRoot: registry.root() })`(빈 등록부) 로 바꾸고 `syncRevocationTree`·`createRevocationSync` 의 단언은 그대로.
  8. `test_cia_opening.mjs`: 등록 `cia.registerUser`, 속성 6, 트랜스크립트 생성에 `r_u, registry(syncRegistryTree), slot, cm_u`, `publicSignals` 길이 30·색인.

- [ ] **Step 3: 실행** — `node tests/test_mode3_wallet.mjs && node tests/test_mode3_rp.mjs && node tests/test_mode3_rcl_sync.mjs && node tests/test_cia_opening.mjs` → 전부 ok.

- [ ] **Step 4: 커밋**
```bash
git add tests/helpers/mode3_chain.mjs tests/test_mode3_wallet.mjs tests/test_mode3_rp.mjs tests/test_mode3_rcl_sync.mjs tests/test_cia_opening.mjs
git commit -m "test(mode3): 라이브러리 체인 테스트를 V9 로 — publishV2 헬퍼, 등록부 슬롯 게시, 30 입력 (V9 11/16)"
```

---

### Task 12: 지갑 에이전트 — 등록 키·등록부 동기화·확인·시연 덮어쓰기·30 입력

**Files:**
- Modify: `mode3_wallet_agent.js`, `lib/mode3_secret_source.js`
- Modify: `tests/test_mode3_wallet_agent.mjs`

**Interfaces:**
- Consumes: Task 10 `syncRegistryTree`·`buildCredentialProof(r_u, registry, slot, cm_u)`·`ProofCache.rootKey`, Task 7 CIA API.
- Produces (HTTP, 지갑 에이전트):
  - `POST /wallet/register` — file 모드 `{uid, pwd}` → 지갑이 키·커밋을 만들어 CIA 에 등록, 201 `{ uid, slot, attrs }`; snap 모드 `{uid, pwd, cm_u, sk_u}`(Snap 이 만든 sk_u 를 한 번 넘긴다 — 로그인 증인과 같은 모델) → 201 `{ uid, slot, attrs }` (응답에 sk_u 없음).
  - `GET /wallet/status` — `+ slot`, `registry: null | { slot, leaf, expected, match, regRoot, epoch, checkedAt }`, `demoOverride: null | { scope, fields: string[] }`, `publicSignals` 길이 30.
  - 로그인 거절 사유 `registry_unpublished`(발급 뒤 30 s 안에 슬롯이 안 올라옴), `registry_mismatch`(✗).
  - `POST /wallet/demo/override { s_u?, uid?, scope: 'issue'|'prove' }` → 200 `{ ok, override }`; `{ clear: true }` → 200 `{ ok, override: null }`. 메모리만.
  - 상태 파일 `registration` 에 `slot`, `pk_u`; `userCred` 에 `leaf` 없음(`WALLET_STATE_VERSION = 8`: 옛 파일은 세션·userCred 를 비우고 등록만 유지 — 옛 등록에는 `slot` 이 없으므로 다음 로그인 때 `/cia/accounts` 가 아니라 **CIA 의 `/cia/slot`** 로 묻는다 → 그 엔드포인트도 이 Task 에서 CIA 에 추가: `POST /cia/slot {uid, nonce, sig_u}` → `{ slot }`).

- [ ] **Step 1: 테스트** — `tests/test_mode3_wallet_agent.mjs`
  1. 4슬롯 상수·`publicSignals.length` 25 → 30 과 그 제목(`V9: 기존 15 + 선택 공개 6+6 + 집합 2`), `disclose: [...]` 길이 4 는 그대로 둬도 된다(길이 1..6 허용) — 단 길이 6 케이스를 하나 둔다.
  2. 등록 케이스: 응답 `{ uid, slot: 0, attrs: 6칸 }`, `status.body.slot === 0`, `status.body.registry === null`(아직 동기화 전).
  3. 첫 로그인 뒤: `status.body.registry.match === true`, `registry.slot === 0`, `registry.leaf === registry.expected`.
  4. 새 케이스들(파일 끝, 세션 폐기 케이스 뒤에):
```js
  await t('V9 등록부 확인: 관리자 바꿔치기 → status.registry.match=false, 로그인 403 registry_mismatch; 되돌리기 → 로그인 ok', async () => {
    assert.equal((await cia.adminPost('/cia/admin/registry/tamper', { uid })).status, 200);
    const r = await login();
    assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.reason, 'registry_mismatch');
    const s = await wallet.get('/wallet/status');
    assert.equal(s.body.registry.match, false);
    assert.equal((await cia.adminPost('/cia/admin/registry/restore', { uid })).status, 200);
    const ok = await login(); assert.equal(ok.status, 200, j(ok.body));
    assert.equal((await wallet.get('/wallet/status')).body.registry.match, true);
  });
  await t('V9 은퇴(scope=credential): 다음 로그인이 슬롯 0 을 보고 새 자격증명을 받아(userCredMs>0) 성공, PPID 유지', async () => {
    const before = (await wallet.get('/wallet/status')).body;
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'credential' })).status, 200);
    const r = await login(); assert.equal(r.status, 200, j(r.body)); assert.ok(r.body.timings.userCredMs > 0);
    const v = await verify(r.body, r.body.r_s); assert.equal(v.ok, true, j(v));
    assert.equal(v.PPID.toString(), Object.values(before.sessions)[0].PPID);
  });
  await t('시연 덮어쓰기(issue): salt 를 바꾸면 AA 가 bad user credential proof 로 거절; uid 를 바꿔도 같다; 자동 해제', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'credential' })).status, 200);   // 다음 로그인이 user_cred 를 새로 받게
    assert.equal((await wallet.post('/wallet/demo/override', { s_u: randomScalar().toString(), scope: 'issue' })).status, 200);
    assert.deepEqual((await wallet.get('/wallet/status')).body.demoOverride, { scope: 'issue', fields: ['s_u'] });
    const r = await login();
    assert.equal(r.status, 502, j(r.body)); assert.equal(r.body.reason, 'user_cred_failed'); assert.equal(r.body.cia.error, 'bad user credential proof'); assert.equal(r.body.demo, 'override:issue');
    assert.equal((await wallet.get('/wallet/status')).body.demoOverride, null, '한 번 쓰면 해제');
    assert.equal((await wallet.post('/wallet/demo/override', { uid: '99999', scope: 'issue' })).status, 200);
    const r2 = await login();
    assert.equal(r2.status, 502, j(r2.body)); assert.equal(r2.body.cia.error, 'bad user credential proof');
    const ok = await login(); assert.equal(ok.status, 200, j(ok.body));   // 덮어쓰기 없이 다시 — 새 자격증명 발급 성공
  });
  await t('시연 덮어쓰기(prove): salt 를 바꾸면 증명 생성이 실패한다(500 아님 — 409 demo_proof_failed)', async () => {
    assert.equal((await wallet.post('/wallet/demo/override', { s_u: randomScalar().toString(), scope: 'prove' })).status, 200);
    const r = await login();
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'demo_proof_failed'); assert.equal(r.body.demo, 'override:prove');
    assert.equal((await wallet.get('/wallet/status')).body.demoOverride, null);
    assert.equal((await wallet.post('/wallet/demo/override', { clear: true })).status, 200);
  });
```
  5. `/wallet/tx disclose` 케이스의 `disclose: [{lo,hi}, null, null, null]` 은 그대로 두고, 집합 케이스 `set: { slot: 1, … }` 그대로. 폐기 트리 케이스(`rv.body.inserted.length === 1`, 239행 — scope=credential 가 리프를 넣는다는 단언)는 `rv.body.retired === 1 && rv.body.published === true` 로 바꾸고 그 뒤 기대(세션이 revoked 로 죽는가)는 **`stale_registry_root` 가 아니라 지갑 쪽에서 `revoked`** 로 끝나야 한다 — proveSession 이 "슬롯 0(등록부에 내 자격증명 없음)" 을 `revoked` 로 올리므로 그대로 둔다.

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_wallet_agent.mjs` → 등록 400(CIA 가 pk_u 요구).

- [ ] **Step 3: CIA 에 `/cia/slot`** — `cia.js` 의 `/cia/attrs` 바로 아래(같은 서명 모양):
```js
// V9: 옛 지갑 상태 파일(슬롯 없음)이 자기 슬롯 번호를 되찾는다. sk_u 서명 인증, 메시지는 /cia/attrs 와 같은 Poseidon(D_ATTRSREQ, uid, nonce).
app.post('/cia/slot', async (req, res) => {
  try {
    const { uid, nonce, sig_u } = req.body ?? {};
    if (!isDec(uid) || !isDec(nonce) || !sig_u) return res.status(400).json({ error: 'uid, nonce, sig_u required' });
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    let ok = false;
    try {
      const m = F.e(await attrsRequestMessage(BigInt(uid), BigInt(nonce)));
      ok = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) }, [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))]);
    } catch { ok = false; }
    if (!ok) return res.status(400).json({ error: 'bad user signature' });
    res.json({ slot: acct.slot });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
```

- [ ] **Step 4: `lib/mode3_secret_source.js`**
  - `stripSecrets`: `{ uid, cm_u, pk_u, slot, attrs, userCred: userCred ? { Cf_u, issuedAt } : null }` (leaf 제거, pk_u·slot 추가).
  - `validateWitness`: `attrs.length !== 4` → `!== 6`; `userCred` 형식에서 `!isDec(u.leaf)` 제거.
  - `createSecretSource` 의 `registration()` 반환에 `slot: state.registration.slot, pk_u: state.registration.pk_u` 추가(두 모드).

- [ ] **Step 5: `mode3_wallet_agent.js`**
  1. import: `createRegistration, createSessionKey, buildUserCredRequest, buildIssueRequest, buildCredentialProof, signChallenge, signSessionRequest, signAttrsRequest, signRevokeSession, signRegistration, eddsaPubOf, normalizeDisclosure, normalizeSet, disclosureKey, hasPredicate, ProofCache, chooseMaxHeight, syncRegistryTree` (`lib/mode3_wallet.js`); `import { registryLeaf } from './lib/mode3_registry.js';`; `import { pointToStrings } from './lib/mode3_issuance.js';` 그대로; `statementDigestFields, PUB_INDEX` 등 on-chain 유틸 그대로.
  2. 상태: `WALLET_STATE_VERSION = 8`; 주석에 `registration: { uid, s_u, r_u, cm_u, sk_u, pk_u:{x,y}, slot, attrs:[6], userCred: { C_u_pt, Cf_u, blind_u, issuedAt } | null }`. 버전 올림 분기에서 `state.registration.slot ??= null; state.registration.pk_u ??= null;`.
  3. 등록부 동기화: `const reg = LOG_ADDRESS ? createRegistrySync({ provider, logAddress: LOG_ADDRESS }) : null;` 는 쓰지 않고 `syncRegistryTree(provider, LOG_ADDRESS)` 를 직접 부른다. `syncTree()` 를 둘 다 돌리는 `syncAll()` 로:
```js
async function syncAll() {
  if (!rcl) throw new Error('CIA_LOG_ADDRESS not configured');
  const [rev, reg] = await Promise.all([rcl.sync(), syncRegistryTree(provider, LOG_ADDRESS)]);
  return { ...rev, registry: reg.tree, regRoot: reg.root, regEpoch: reg.epoch };
}
```
     `syncTree()` 호출부(로그인·재검증·buildExecute) 를 `syncAll()` 로, `lastSync = { root, regRoot, head, tree, registry }`.
  4. 등록부 확인 함수:
```js
/** 등록부 확인(설계 §8.2): 내 슬롯의 리프 == Poseidon(cm_u, Cf_u). 자격증명이 없으면 null. */
async function registryCheck(synced, reg, uc) {
  if (!reg || !Number.isInteger(reg.slot)) return null;
  const leaf = synced.registry.leafAt(reg.slot);
  const expected = uc ? await registryLeaf({ x: BigInt(reg.cm_u.x), y: BigInt(reg.cm_u.y) }, BigInt(uc.Cf_u)) : 0n;
  const r = { slot: reg.slot, leaf: leaf.toString(), expected: expected.toString(), match: uc ? leaf === expected : null, regRoot: synced.regRoot.toString(), epoch: synced.regEpoch.toString(), checkedAt: new Date().toISOString() };
  lastRegistry = r;
  return r;
}
let lastRegistry = null;
```
  5. 슬롯 보완(옛 등록): 로그인 시작 시 `if (reg.slot === null || reg.slot === undefined) { const nonce = randomScalar(); const r = await ciaPost('/cia/slot', { uid: reg.uid, nonce: nonce.toString(), sig_u: await signAttrsRequest(reg.sk_u, BigInt(reg.uid), nonce) }); if (r.status !== 200) return res.status(502).json({ reason: 'slot_failed', cia: r.body }); state.registration.slot = r.body.slot; persist(); }` (file 모드; snap 모드는 `state.registration.slot` 도 같은 공개 필드).
  6. `ensureUserCred(synced, src, { resynced })` 교체 — 폐기 트리 `tree.has(leaf)` 대신 등록부:
```js
async function ensureUserCred(synced, src, { resynced = false } = {}) {
  const reg = src.registration();
  const uc = src.userCred();
  if (uc) {
    const chk = await registryCheck(synced, reg, uc);
    if (chk.match) return { status: 200, fresh: false };
    if (chk.leaf !== '0') return { status: 403, reason: 'registry_mismatch', registry: chk };   // 내 슬롯에 남의 자격증명 — 신원 기관의 부정(또는 내가 모르는 재발급)
    // 슬롯 0: 은퇴됐다 — 새로 받는다
  }
  const ov = takeOverride('issue');
  const req = await buildUserCredRequest({ uid: BigInt(ov?.uid ?? reg.uid), s_u: BigInt(ov?.s_u ?? reg.s_u), r_u: BigInt(reg.r_u), sk_u: reg.sk_u, attrs: (reg.attrs ?? []).map(BigInt) });
  if (ov?.uid) req.body.uid = reg.uid;   // 요청 본문의 uid 는 진짜 — C_u 안의 uid 만 바뀐다(스펙 §8.3)
  const r = await ciaPost('/cia/user_cred', req.body);
  if (r.status === 201 || r.status === 200) {
    replaceUserCred(src, { C_u_pt: { x: req.C_u_pt.x.toString(), y: req.C_u_pt.y.toString() }, Cf_u: req.Cf_u.toString(), blind_u: req.secrets.blind_u.toString(), issuedAt: new Date().toISOString() });
    return { status: 200, body: r.body, fresh: true, published: r.body.published };
  }
  if (r.status === 400 && !resynced && !ov && r.body?.error === 'bad user credential proof') {
    const s = await syncAttrsFromCia(src);
    if (s.status === 200) return ensureUserCred(synced, src, { resynced: true });
  }
  return { status: r.status, body: r.body, fresh: false, demo: ov ? 'override:issue' : undefined };
}
```
     로그인 라우트에서 `uc.status === 403 && uc.reason === 'registry_mismatch'` → `403 { reason: 'registry_mismatch', registry: uc.registry, timings }`; `uc.status !== 200` → `502 { reason: 'user_cred_failed', cia: uc.body, demo: uc.demo, timings }` (기존 줄에 `demo` 추가). 새 자격증명을 받았으면(`fresh`) **게시된 슬롯이 보일 때까지** 재동기화한다:
```js
    if (uc.fresh) {
      const deadline = Date.now() + 30_000;
      for (;;) {
        synced = await syncAll(); lastSync = { root: synced.root.toString(), regRoot: synced.regRoot.toString(), head: synced.head.toString(), tree: synced.tree, registry: synced.registry };
        const chk = await registryCheck(synced, src.registration(), src.userCred());
        if (chk.match) break;
        if (Date.now() > deadline) return res.status(503).json({ reason: 'registry_unpublished', registry: chk, timings });
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
```
  7. `proveSession(rsKey, synced, timings, disclosure, src)`: 사용자 리프 검사 두 줄(`s.credential.Cf_u !== uc?.Cf_u` 는 유지; `synced.tree.has(BigInt(uc.leaf))` 는 삭제)을 등록부 검사로: `const chk = await registryCheck(synced, reg, uc); if (!chk.match) throw Object.assign(new Error('revoked'), { reason: 'revoked', registry: chk });`. `buildCredentialProof` 호출에 `r_u: BigInt(reg.r_u), registry: synced.registry, slot: reg.slot, cm_u: { x: BigInt(reg.cm_u.x), y: BigInt(reg.cm_u.y) }` 와 시연 덮어쓰기 `const ov = takeOverride('prove'); s_u: BigInt(ov?.s_u ?? reg.s_u), uid: BigInt(ov?.uid ?? reg.uid)` — 그리고 catch 에 `if (ov) throw Object.assign(new Error('demo_proof_failed'), { reason: 'demo_proof_failed', detail: e.message });`. 캐시 키 root 자리에 `ProofCache.rootKey(cached.revRoot, cached.regRoot)` / `ProofCache.rootKey(synced.root, synced.regRoot)`. 반환에 `regRoot: cached.regRoot.toString()`. `/is a member/` 분기는 세션 리프만 남으므로 `revoked_session` 으로.
     라우트들의 `e.reason === 'demo_proof_failed'` → `409 { reason, detail, demo: 'override:prove', timings }`; `registry` 가 붙은 `revoked` 는 그대로 403.
  8. 시연 덮어쓰기:
```js
// 시연(설계 §8.3): 다음 발급/증명의 s_u·uid 를 메모리에서만 덮어쓴다. 한 번 쓰면 사라진다. 전문가 보기 전용 카드가 부른다.
let demoOverride = null;   // { scope: 'issue'|'prove', s_u?: string, uid?: string }
function takeOverride(scope) { if (!demoOverride || demoOverride.scope !== scope) return null; const ov = demoOverride; demoOverride = null; return ov; }
app.post('/wallet/demo/override', (req, res) => {
  const { s_u = null, uid: uidIn = null, scope = null, clear = false } = req.body ?? {};
  if (clear) { demoOverride = null; return res.json({ ok: true, override: null }); }
  if (scope !== 'issue' && scope !== 'prove') return res.status(400).json({ error: "scope 는 'issue' 또는 'prove'" });
  if ((s_u !== null && (!isDec(s_u) || BigInt(s_u) >= SCALAR_MAX)) || (uidIn !== null && (!isDec(uidIn) || BigInt(uidIn) >= SCALAR_MAX))) return res.status(400).json({ error: 's_u·uid 는 10진, 2^250 미만' });
  if (s_u === null && uidIn === null) return res.status(400).json({ error: 's_u 또는 uid 가 필요하다' });
  demoOverride = { scope, ...(s_u !== null ? { s_u } : {}), ...(uidIn !== null ? { uid: uidIn } : {}) };
  res.json({ ok: true, override: { scope, fields: Object.keys(demoOverride).filter((k) => k !== 'scope') } });
});
```
     (`takeOverride('issue')` 는 `ensureUserCred` 가 실제로 요청을 만들 때만 부른다 — 자격증명이 멀쩡하면 덮어쓰기가 남아 있다가 다음 발급에 쓰인다. 테스트는 그래서 먼저 은퇴시킨다.)
  9. 등록 라우트:
```js
app.post('/wallet/register', async (req, res) => {
  try {
    const { uid, pwd, cm_u: cmIn, sk_u: skIn } = req.body ?? {};
    if (!isDec(uid) || typeof pwd !== 'string') return res.status(400).json({ error: 'uid(10진 문자열), pwd 필요' });
    if (SECRETS === 'snap' && !(cmIn && isDec(cmIn.x) && isDec(cmIn.y) && typeof skIn === 'string' && /^[0-9a-fA-F]{64}$/.test(skIn))) return res.status(400).json({ error: 'snap 모드는 cm_u{x,y}(10진 문자열)·sk_u(hex) 필요' });
    if (state.registration) return res.status(409).json({ reason: 'already_registered', uid: state.registration.uid });
    const reg = SECRETS === 'snap' ? null : await createRegistration();
    const cm_u = SECRETS === 'snap' ? { x: BigInt(cmIn.x), y: BigInt(cmIn.y) } : reg.cm_u;
    const sk_u = SECRETS === 'snap' ? skIn : reg.sk_u;
    const pk_u = await eddsaPubOf(sk_u);
    const r = await ciaPost('/cia/register', { uid, pwd, cm_u: pointToStrings(cm_u), pk_u: { x: pk_u.x.toString(), y: pk_u.y.toString() }, sig_reg: await signRegistration(sk_u, BigInt(uid), cm_u) });
    if (r.status !== 201) {
      const status = r.status === 401 || r.status === 409 ? r.status : 502;
      return res.status(status).json({ reason: 'register_failed', cia: r.body });
    }
    const attrs = normalizeAttrs(r.body.attrs).map(String);
    const pub = { x: pk_u.x.toString(), y: pk_u.y.toString() };
    if (SECRETS === 'snap') {
      state.registration = stripSecrets({ uid, cm_u: pointToStrings(cm_u), pk_u: pub, slot: r.body.slot, attrs, userCred: null });
      persist();
      return res.status(201).json({ uid, slot: r.body.slot, attrs });
    }
    state.registration = { uid, s_u: reg.s_u.toString(), r_u: reg.r_u.toString(), cm_u: pointToStrings(cm_u), sk_u, pk_u: pub, slot: r.body.slot, attrs, userCred: null };
    persist();
    res.status(201).json({ uid, slot: r.body.slot, attrs });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
```
  10. `/wallet/status`: `userCred` 의 `revoked` 판정을 `lastRegistry` 로(`revoked: lastRegistry ? !lastRegistry.match : null`), 응답에 `slot: reg?.slot ?? null, registry: lastRegistry, demoOverride: demoOverride ? { scope: demoOverride.scope, fields: Object.keys(demoOverride).filter((k) => k !== 'scope') } : null, lastRegRoot: lastSync?.regRoot ?? null`.
  11. `/wallet/tx/record`: `disclosure = { mask: pub[15], lo: pub.slice(16, 22), hi: pub.slice(22, 28), sel: pub[28], root: pub[29] }` — `PUB_INDEX` 로 쓴다. `buildExecute` 의 `disclosure` 는 길이 6. `discStrings` 그대로(배열 길이 따라감).
  12. `/wallet/session/witness`·`setSessionWitness`: `userCred` 모양에서 `leaf` 제거.
  13. 기동 로그에 `registry` 표시 불필요.

- [ ] **Step 6: 통과·커밋** — `node tests/test_mode3_wallet_agent.mjs` 전부 ok; `node tests/test_mode3_health_shape.js` ok.
```bash
git add mode3_wallet_agent.js lib/mode3_secret_source.js cia.js tests/test_mode3_wallet_agent.mjs
git commit -m "feat(mode3): 지갑 에이전트 V9 — 등록 키 생성·등록부 확인(registry_mismatch/unpublished)·시연 덮어쓰기·30 입력 (V9 12/16)"
```

---

### Task 13: Snap — 등록 키 생성, storeRegistration 모양, 속성 6칸

**Files:**
- Modify: `snap-mode3/src/index.js`, `snap-mode3/src/crypto.js`, `tests/helpers/snap_sim.mjs`, `snap-mode3/test/rpc.test.mjs`, `tests/test_mode3_wallet_snap.mjs`, `mode3/wallet.html`(등록 흐름 두 줄)

**Interfaces:**
- Produces: Snap RPC `register` → `{ uid, pwd, cm_u, sk_u }` (sk_u 는 Snap 이 `crypto.getRandomValues` 32바이트로 만들어 저장하고 이 응답에만 한 번 싣는다 — 로그인 증인과 같은 모델); `storeRegistration { attrs(6), slot }` → `{ ok }` (sk_u 는 받지 않는다); `getPublicInfo` 에 `slot`; `syncAttrs` 는 길이 6; `buildWitness` 의 `userCred` 에 `leaf` 없음; `SLOT_LABELS` 6개(`'속성 5'`, `'속성 6'`), `SLOT_NAMES` `a₀..a₅`, `predicateLines` 루프 6·`set.slot <= 5`. 시뮬레이터 `snap_sim.mjs` 도 같은 모양.

- [ ] **Step 1: 테스트 먼저**
  - `snap-mode3/test/rpc.test.mjs`: `register` 가 `sk_u`(hex 64) 를 돌려주고 상태에 저장함, `storeRegistration({ attrs:[6], slot })` 가 `sk_u` 없이 통과하고 `getPublicInfo().slot` 이 값, `attrs` 길이 4 는 `bad_attrs`, `buildWitness` 결과에 `sk_u` 가 register 때 만든 것과 같음. 기존 `storeRegistration({ sk_u, attrs })` 호출을 바꾼다.
  - `tests/test_mode3_wallet_snap.mjs`: `sim.register` 결과의 `sk_u` 를 `/wallet/register` 본문에 싣고(`{ uid, pwd, cm_u, sk_u }`), 응답 `{ uid, slot, attrs(6) }`(sk_u 없음), `sim.storeRegistration({ attrs: r.body.attrs, slot: r.body.slot })`, 파일에 `"sk_u"`·`"s_u"`·`"r_u"`·`"blind_u"` 없음 단언 유지, 속성 상수 6칸, `syncAttrs` 6칸, `disclose` 길이 4 는 유지해도 된다.

- [ ] **Step 2: `snap-mode3/src/crypto.js`** — `createRegistrationSecrets()` 가 `sk_u` 도 만든다: `const sk = new Uint8Array(32); crypto.getRandomValues(sk); sk_u = [...sk].map((b) => b.toString(16).padStart(2, '0')).join('')`. (Snap 런타임은 WebCrypto `crypto.getRandomValues` 가 있다 — 기존 `randomScalar` 가 같은 것을 쓴다면 그 함수를 재사용.) 반환 `{ s_u, r_u, cm_u, sk_u }`.

- [ ] **Step 3: `snap-mode3/src/index.js`**
  - `SLOT_LABELS = ['출생연도', '국가', '등급', '예비', '속성 5', '속성 6']`, `SLOT_NAMES = ['a₀','a₁','a₂','a₃','a₄','a₅']`, `predicateLines`: `i < 6`, `set.slot <= 5`.
  - `register`: `state.registration = { uid, s_u, r_u, cm_u, sk_u: secrets.sk_u, slot: null, attrs: null, registeredAt }`; 반환 `{ uid, pwd, cm_u, sk_u: secrets.sk_u }`.
  - `storeRegistration`: `const { attrs, slot } = params; if (!Array.isArray(attrs) || attrs.length !== 6 || …) fail('bad_attrs: attrs 는 10진 문자열 6개'); if (!Number.isInteger(slot) || slot < 0) fail('bad_slot'); reg.attrs = attrs.map(String); reg.slot = slot;`.
  - `getPublicInfo`: `slot: r?.slot ?? null`.
  - `buildWitness`: `sk_u` 가 string 인지(이미 있음), `userCred` 복사 그대로(leaf 가 없어도 된다). `unwrapUserCred`: `leaf` 검사 제거.
  - `syncAttrs`: 길이 6.
- [ ] **Step 4: `tests/helpers/snap_sim.mjs`** — 같은 모양: `register` 가 `createRegistration()` 의 `sk_u` 를 저장·반환, `storeRegistration({ attrs, slot })`, `getPublicInfo` 에 `slot`, `syncAttrs` 6.
- [ ] **Step 5: `mode3/wallet.html` 등록 흐름** — snap 분기 `body = { uid: reg.uid, pwd: reg.pwd, cm_u: reg.cm_u, sk_u: reg.sk_u }`; 성공 뒤 `invokeSnap('storeRegistration', { attrs: b.attrs, slot: b.slot })`. `safeDetail` 은 이미 `sk_u` 를 뺀다. 주석의 "응답의 sk_u(snap 모드)" 문구를 "요청의 sk_u 는 Snap 이 준 값으로 한 번만 지나간다" 로.
- [ ] **Step 6: 실행·커밋** — `node snap-mode3/test/rpc.test.mjs && node tests/test_mode3_wallet_snap.mjs` 전부 ok.
```bash
git add snap-mode3/src/index.js snap-mode3/src/crypto.js tests/helpers/snap_sim.mjs snap-mode3/test/rpc.test.mjs tests/test_mode3_wallet_snap.mjs mode3/wallet.html
git commit -m "feat(mode3): Snap 등록 키 생성 — register 가 sk_u 를 만들고 storeRegistration 은 slot·attrs(6) (V9 13/16)"
```

---

### Task 14: 화면 — 속성 6행, 등록부 확인 줄, 시연 카드, RP 페이지 6슬롯, 브라우저 테스트

**Files:**
- Modify: `mode3/wallet.html`, `mode3/rp.html`, `mode3/common/strings.js`
- Modify: `tests/test_mode3_browser.mjs`, `tests/test_mode3_tour.mjs`

**Interfaces:**
- 지갑 페이지 요소 id: `attr4`, `attr5`(속성 표시), `dk4`, `dk5`, `discLo4`, `discHi4`, `discLo5`, `discHi5`, `setSlot` 옵션 `4`,`5`; 신원 카드 `registryInfo`(한 줄, 상태 배지 `registryBadge`); 시연 카드 `demoCard`(class `expert`) 안에 `demoSalt`(input), `demoNewSalt`(button), `demoUid`(input), `demoScope`(select issue|prove), `demoApplyBtn`, `demoClearBtn`, `demoVerdict`.
- strings 키: `wallet_registry_ok, wallet_registry_empty, wallet_registry_mismatch, wallet_registry_unknown, wallet_demo_title, wallet_demo_desc, wallet_demo_apply, wallet_demo_clear, wallet_demo_new_salt, wallet_demo_scope_issue, wallet_demo_scope_prove, wallet_demo_set, wallet_demo_cleared, wallet_demo_failed` + 사유 사전 `registry_mismatch, registry_unpublished, demo_proof_failed, slot_failed`(where: wallet) — `strings.js` 의 reason 사전 모양(`{ where, ko:{title,cause,action}, en:{…} }`)을 따른다.

- [ ] **Step 1: 브라우저 테스트** — `tests/test_mode3_browser.mjs`·`tests/test_mode3_tour.mjs`
  - 속성 상수 6칸(`['1990','410','2','0','0','0']`, `['1990','410','3','0','0','0']`), `snapState.registration.sk_u` 단언은 그대로(Snap 이 만든 값), `storeRegistration 이 sk_u 를 넣었다` 문구를 `register 가 sk_u 를 만들었다` 로.
  - 새 케이스(`test_mode3_tour.mjs` 의 로그인 케이스 뒤, CIA 를 내리는 케이스 **앞**):
```js
  await t('V9 등록부 줄: 로그인 뒤 ✓, 관리자 바꿔치기 뒤 다음 폴링에 ✗, 되돌리기 뒤 ✓', async () => {
    await walletPage.waitForFunction(() => document.querySelector('#registryBadge')?.classList.contains('ok'), undefined, { timeout: 30_000 });
    assert.equal((await stack.cia.adminPost('/cia/admin/registry/tamper', { uid: '12345' })).status, 200);
    await walletPage.click('#refreshBtn');
    await walletPage.waitForFunction(() => document.querySelector('#registryBadge')?.classList.contains('bad'), undefined, { timeout: 30_000 });
    assert.ok((await text(walletPage, '#registryInfo')).includes('바뀌'), '✗ 문구');
    assert.equal((await stack.cia.adminPost('/cia/admin/registry/restore', { uid: '12345' })).status, 200);
    await walletPage.click('#refreshBtn');
    await walletPage.waitForFunction(() => document.querySelector('#registryBadge')?.classList.contains('ok'), undefined, { timeout: 30_000 });
  });
  await t('V9 시연 카드(전문가 보기): salt 를 바꾸고 다음 발급 → 서비스 로그인 결과에 bad user credential proof', async () => {
    await walletPage.evaluate(() => Demo.setExpert(true));
    await walletPage.waitForSelector('#demoCard', { state: 'visible' });
    assert.equal((await stack.cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' })).status, 200);   // 다음 로그인이 새로 받게
    await walletPage.click('#demoNewSalt'); await walletPage.selectOption('#demoScope', 'issue'); await walletPage.click('#demoApplyBtn');
    await waitText(walletPage, '#demoVerdict', '적용', 10_000);
    await rpPage.click('#loginBtn');
    await waitText(rpPage, '#verdict', 'bad user credential proof', 120_000);
    await rpPage.click('#loginBtn');
    await waitText(rpPage, '#verdict', '로그인 성공', 180_000);   // 덮어쓰기는 한 번만 — 그다음은 정상
    await walletPage.evaluate(() => Demo.setExpert(false));
  });
```
    (`refreshBtn` 은 지갑 페이지의 새로고침 버튼. 등록부 줄은 `/wallet/status` 의 `registry` 를 그리므로 로그인 뒤 동기화 결과가 있어야 ✓ 가 된다 — 지갑 페이지는 로그인 뒤 `refresh()` 를 부른다. 바꿔치기 뒤에는 에이전트가 다시 동기화해야 하므로 `#refreshBtn` 이 `/wallet/status?sync=1` 을 부르게 한다 — Step 3.)

- [ ] **Step 2: `mode3/wallet.html`**
  - 속성 표시 `attrsView` 에 `attr4`·`attr5` 두 줄(`data-term="attr4"`, `"attr5"`), 공개 조건 `discloseRows` 에 `dk4/discLo4/discHi4`, `dk5/…` 두 블록, `setSlot` 에 `<option value="4" data-term="attr4">`, `<option value="5" data-term="attr5">`. JS 의 `for (let k = 0; k < 4; k++)` 들(속성 채우기 `renderIdentity`, `readDisclose`, `discExactBtn`, `ageBtn` 은 그대로) 을 6 으로.
  - 신원 카드 `<dl class="kv">` 에 `<dt data-term="registry">등록부</dt><dd><span id="registryBadge" class="badge muted">-</span> <span id="registryInfo"></span></dd>` 추가; `renderIdentity` 에:
```js
      const rg = s?.registry ?? null;
      const rb = $('registryBadge');
      const key = !rg ? 'wallet_registry_unknown' : rg.match === true ? 'wallet_registry_ok' : rg.leaf === '0' ? 'wallet_registry_empty' : 'wallet_registry_mismatch';
      rb.className = `badge ${!rg ? 'muted' : rg.match === true ? 'ok' : rg.leaf === '0' ? 'warn' : 'bad'}`;
      tte(rb, key);
      $('registryInfo').textContent = rg ? tt('wallet_registry_info', { slot: rg.slot, epoch: rg.epoch }) || `슬롯 ${rg.slot} · epoch ${rg.epoch}` : '';
```
  - 새로고침 버튼: `$('refreshBtn').addEventListener('click', () => refresh(true));` 로 바꾸고 `refresh(sync = false)` 가 `fetch(sync ? '/wallet/status?sync=1' : '/wallet/status')`. 에이전트 `/wallet/status` 는 `req.query.sync === '1'` 이면 `syncAll()` 을 돌려 `lastRegistry` 를 갱신한 뒤 답한다(Task 12 의 라우트에 한 줄: `if (req.query.sync === '1' && rcl && state.registration) { try { const synced = await syncAll(); await registryCheck(synced, state.registration, state.registration.userCred); } catch { /* 체인 없음 */ } }`).
  - 시연 카드(전문가 보기 전용) — `txCard` 아래:
```html
    <section class="card expert" id="demoCard">
      <h3 data-i18n="wallet_demo_title">시연: 비밀 바꾸기</h3>
      <p class="desc" data-i18n="wallet_demo_desc">다음 발급(또는 다음 증명)에 쓸 salt·uid 를 메모리에서만 바꿉니다. 지갑 자체 검사를 건너뛰고 프로토콜이 거절하는 장면을 보입니다. 한 번 쓰면 풀립니다.</p>
      <p><label>salt <input id="demoSalt" size="24" /></label> <button id="demoNewSalt" type="button" class="btn-ghost" data-i18n="wallet_demo_new_salt">새 난수</button>
         <label>uid <input id="demoUid" size="8" /></label>
         <select id="demoScope"><option value="issue" data-i18n="wallet_demo_scope_issue">다음 발급</option><option value="prove" data-i18n="wallet_demo_scope_prove">다음 증명</option></select>
         <button id="demoApplyBtn" class="danger" data-i18n="wallet_demo_apply">적용</button> <button id="demoClearBtn" class="btn-ghost" data-i18n="wallet_demo_clear">원래대로</button></p>
      <div id="demoVerdict"></div>
    </section>
```
    JS:
```js
    $('demoNewSalt').addEventListener('click', () => { const b = new Uint8Array(32); crypto.getRandomValues(b); b[0] &= 0x03; $('demoSalt').value = BigInt('0x' + [...b].map((x) => x.toString(16).padStart(2, '0')).join('')).toString(); });   // 2^250 미만
    $('demoApplyBtn').addEventListener('click', async () => {
      const body = { scope: $('demoScope').value };
      if ($('demoSalt').value.trim()) body.s_u = $('demoSalt').value.trim();
      if ($('demoUid').value.trim()) body.uid = $('demoUid').value.trim();
      const { status, body: b } = await postJson('/wallet/demo/override', body);
      if (status !== 200) { setVerdict($('demoVerdict'), false, 'wallet_demo_failed', { reason: b.error ?? `HTTP ${status}` }); return; }
      setVerdict($('demoVerdict'), true, 'wallet_demo_set', () => ({ summary: tt('wallet_demo_set_summary', { scope: b.override.scope, fields: b.override.fields.join(', ') }) || `적용: ${b.override.scope} (${b.override.fields.join(', ')})` }));
      refresh();
    });
    $('demoClearBtn').addEventListener('click', async () => { await postJson('/wallet/demo/override', { clear: true }); setVerdict($('demoVerdict'), true, 'wallet_demo_cleared', () => ({ summary: tt('wallet_demo_cleared') || '원래대로' })); refresh(); });
```
    로그인 결과 카드(서비스 페이지)는 에이전트 응답의 `demo` 필드가 있으면 요약 앞에 "시연 모드" 를 붙인다 — `rp.html` 의 로그인 결과 생성기에서 `lg.body.demo ? '[시연 모드] ' : ''` 를 summary 앞에.
  - `strings.js`: 위 키들 ko/en, 용어 `registry: { ko: '등록부', en: 'Registry', expert: 'regRoot · 슬롯 리프 Poseidon(cm_u, Cf_u)' }`, 사유 사전 네 개:
```js
    registry_mismatch: { where: 'wallet', ko: { title: '등록부의 내 자격증명이 바뀌었습니다', cause: '체인에 게시된 내 슬롯의 자격증명이 지갑이 든 것과 다릅니다. 내가 요청한 재발급이 아니라면 신원 기관의 부정입니다.', action: '관리자 페이지에서 되돌리거나 신원 기관에 문의하세요. 지갑은 로그인을 시도하지 않습니다.' }, en: { title: 'The registry holds a different credential for me', cause: 'The credential published in my registry slot differs from the one this wallet holds. Unless I requested a re-issuance, the authority misbehaved.', action: 'Restore it from the admin page or contact the authority. The wallet will not attempt a login.' } },
    registry_unpublished: { where: 'wallet', ko: { title: '등록부 게시 대기', cause: '새 자격증명이 아직 체인 등록부에 오르지 않았습니다(30초 기다렸습니다).', action: '신원 기관의 게시(하트비트)를 확인하고 다시 로그인하세요.' }, en: { title: 'Waiting for registry publication', cause: 'The new credential has not appeared in the on-chain registry (waited 30 s).', action: 'Check the authority’s publication and log in again.' } },
    demo_proof_failed: { where: 'wallet', ko: { title: '증명 생성 실패(시연)', cause: '서명된 자격증명과 증인이 다릅니다 — C_u 재계산·등록부 리프가 어긋나 회로가 거절했습니다.', action: '"원래대로" 로 덮어쓰기를 풀고 다시 시도하세요.' }, en: { title: 'Proof generation failed (demo)', cause: 'The witness no longer matches the signed credential — the recomputed C_u and registry leaf disagree, so the circuit rejected it.', action: 'Clear the override and try again.' } },
    slot_failed: { where: 'wallet', ko: { title: '슬롯 번호를 받지 못했습니다', cause: '옛 등록에 슬롯이 없어 신원 기관에 물었지만 실패했습니다.', action: '신원 기관 상태를 확인하세요.' }, en: { title: 'Could not fetch the slot number', cause: 'This older registration has no slot and the authority did not answer.', action: 'Check the authority.' } },
```
  - `mode3/rp.html`: 공개 조건 표시가 `lo[4]/hi[4]` 를 가정한 곳(로그인 기록 표의 `공개한 조건`)을 길이에 따르게 — `d.lo.length` 로 루프. 세션 카드 등도 같다.

- [ ] **Step 3: 실행** — `node tests/test_mode3_tour.mjs && node tests/test_mode3_browser.mjs` (Chrome 필요). 전부 ok.

- [ ] **Step 4: 커밋**
```bash
git add mode3/wallet.html mode3/rp.html mode3/common/strings.js mode3_wallet_agent.js tests/test_mode3_browser.mjs tests/test_mode3_tour.mjs
git commit -m "feat(mode3): 지갑 화면 — 속성 6행, 등록부 확인 줄(✓/대기/✗), 시연 카드(salt·uid 덮어쓰기) (V9 14/16)"
```

---

### Task 15: 전 구간(HTTP) 테스트·테스트 그룹·런북

**Files:**
- Modify: `tests/test_mode3_demo_stack.mjs`, `scripts/run_tests.sh`, `docs/MODE3_DEMO.md`

- [ ] **Step 1: `tests/test_mode3_demo_stack.mjs`** — Task 8 규칙(등록 헬퍼: alice 는 `cia.registerUser('67890', 'alicepw')`, 속성 6칸, `disclosure` 길이 6, `rev.body.inserted` 는 세션 폐기 케이스 그대로), `makeAliceAgent` 의 `buildCredentialProof` 에 `r_u: reg.r_u, registry: (await syncRegistryTree(provider, cia.logAddress)).tree, slot: a.slot, cm_u: reg.cm_u`, 각본 4(계정 폐기 → 게시)는 "슬롯 0 즉시 게시" 라 관리자 "게시" 호출이 `published:false` 일 수 있다 — 단언을 `published === false && pending === 0` 또는 상태의 `regRoot` 변화로. 새 각본 두 줄:
```js
await t('각본 10(V9): 관리자 바꿔치기 → 지갑 로그인 403 registry_mismatch → 되돌리기 → 로그인 ok', async () => {
  assert.equal((await cia.adminPost('/cia/admin/registry/tamper', { uid })).status, 200);
  const bad = await loginViaRp(); assert.equal(bad.walletStatus, 403); assert.equal(bad.wallet.reason, 'registry_mismatch');
  assert.equal((await cia.adminPost('/cia/admin/registry/restore', { uid })).status, 200);
  const ok = await loginViaRp(); assert.equal(ok.walletStatus, 200, j(ok.wallet)); assert.equal(ok.rp.ok, true, j(ok.rp));
});
await t('각본 11(V9): 두 사용자의 슬롯은 다르고(0·1) 각자 PPID 로 로그인된다', async () => {
  const accts = (await cia.adminGet('/cia/accounts')).body.accounts;
  assert.deepEqual(accts.map((a) => [a.uid, a.slot]).sort(), [['12345', 0], ['67890', 1]]);
});
```
  (alice 등록이 testuser 뒤라면 슬롯 1 — 이 파일에서 `ensureAlice` 가 처음 불리는 순서를 확인해 기대값을 맞춘다.)
- [ ] **Step 2: `scripts/run_tests.sh`** — UNIT: `tests/test_mode3_v9_lib.js`, `tests/test_mode3_registry.js`, `tests/test_mode3_cia_state_v9.js`(앞 Task 들이 넣었는지 확인); CHAIN: `tests/test_cia_registry.mjs`; CONTRACT: `test/Mode3Log.test.mjs`. 주석의 "25개"·"4슬롯" 문구가 있으면 갱신.
- [ ] **Step 3: `docs/MODE3_DEMO.md`**
  - "처음 한 번" 0 항목에 V9 문단: 회로 V9(2026-10-01, 등록부·속성 6슬롯·공개 입력 30) — 순서 (1) `bash scripts/build_mode3_circuit.sh …` (2) `npx hardhat compile` (3) **로그 재배포 필수**: `CIA_ETH_ADDRESS=… npx hardhat run scripts/deploy_mode3_log.cjs --network localhost` 가 `Mode3Log` 를 배포 → `.env` 의 `CIA_LOG_ADDRESS` 교체 (4) `cia_state.json` 은 지우지 않는다 — v9 로 자동 이행(슬롯 배정, 활성 자격증명 리프 게시). 단 로그를 새로 배포했으므로 폐기 트리의 옛 `revoked` 가 체인과 어긋나면 기동 거부 → 그때는 **옛 폐기 리프를 유지한 채 로그 주소만 바꾼 상태 파일을 쓸 수 없다**: 재시연 세트(상태 파일 백업 뒤 새 파일)로 간다(기존 "재시연 세트" 절 참조) (5) `mode3_rp_registration.json` 의 `verifierAddress`·`factoryAddress`·`attrGateAddress` 셋 삭제 → RP 재시작(계정 주소 변경) (6) 지갑 상태 v8 자동 이행(세션·userCred 비움, 등록 유지; 옛 등록은 첫 로그인 때 `/cia/slot` 로 슬롯을 받는다).
  - "프로세스와 포트" 표 아래 한 줄: 로그 컨트랙트가 `Mode3Log`(root 둘).
  - "시연 각본" 표에 각본 10(바꿔치기/되돌리기)·11(시연 카드: salt 바꾸기 → `bad user credential proof`, uid 바꾸기 → 같음, 다음 증명 → `demo_proof_failed`)·12(두 사용자 슬롯) 추가; 4 의 기대에 "슬롯 0 즉시 게시" 추가; 2 의 기대에 "지갑 신원 카드 등록부 ✓(슬롯 N)".
  - "속성과 선택 공개" 절: 슬롯 6(이름은 매핑 스펙 전까지 `속성 5·6`), 64비트.
  - "세션 폐기(V8)" 절 끝에 "V9: 사용자 리프는 더 이상 폐기 트리에 넣지 않는다 — 자격증명 은퇴·계정 폐기 = 등록부 슬롯 0".
  - "테스트" 절에 `tests/test_cia_registry.mjs`, `test/Mode3Log.test.mjs`, 단위 셋.
- [ ] **Step 4: 실행·커밋** — `node tests/test_mode3_demo_stack.mjs` ok; `bash scripts/run_tests.sh unit` ok.
```bash
git add tests/test_mode3_demo_stack.mjs scripts/run_tests.sh docs/MODE3_DEMO.md
git commit -m "test+docs(mode3): 전 구간 각본 10~12(V9), 테스트 그룹, 런북 V9 절차·각본 (V9 15/16)"
```

---

### Task 16: 벤치 재측정과 결과 파일

**Files:**
- Modify: `scripts/bench_mode3_onchain.mjs` (6슬롯·30 입력·Mode3Log 게시 gas)
- Create: `results/mode3_v9_registry_<YYYYMMDD>.md`

- [ ] **Step 1: 벤치 스크립트** — `disclose`/`set` 인자는 그대로(길이 1..6 허용), `publicSignals` 길이 단언이 있으면 30, 로그 게시 gas 항목에 "슬롯 1개 게시(SlotUpdated 1건)" 추가: 격리 CIA 에서 `user_cred` 발급이 즉시 게시하므로 그 tx 의 영수증(`cia.get('/cia/state')` 로는 해시를 모른다 → `log.queryFilter(SlotUpdated)` 의 마지막 이벤트 `getTransactionReceipt`) 에서 `gasUsed` 를 읽는다. 하트비트 gas 는 현행 방식.
- [ ] **Step 2: 실행** — `node scripts/bench_pi_cred.mjs pot21_final.ptau`(zkey 있음 — 증명·검증 시간만), `npx snarkjs r1cs info build/mode3/pi_cred.r1cs`(제약 수), `node scripts/bench_mode3_onchain.mjs 10`(hardhat 필요).
- [ ] **Step 3: 결과 파일** — `results/mode3_v9_registry_<날짜>.md` 에 표: 제약(V8 37,130 → V9 N), 증명/검증 ms(N=10 중앙값), 공개 입력 25 → 30, execute gas(mask 0 캐시 / 범위 / 집합 / 범위+집합+claim) V8 값(417,533 / 422,366 / 422,982 / 456,439) 과 나란히, 계정 배포, 팩토리·검증자·Mode3Log 배포, 게시 gas(리프 1 / 슬롯 1 / 하트비트), 로그인 왕복(첫 로그인에 등록부 게시 대기 포함). 측정 조건(CPU, Node, 커밋 해시) 명기.
- [ ] **Step 4: 커밋**
```bash
git add scripts/bench_mode3_onchain.mjs results/mode3_v9_registry_*.md
git commit -m "bench(mode3): V9 등록부 실측 — 제약·증명 시간·실행/게시 gas·로그인 지연 (V9 16/16)"
```

---

## 실행 뒤 남는 것 (이 계획 밖)
- 형식 문서 `security_formal.md` 에 G12·(A10) 완화·조건 9 반영, 논문 §V·§VII·Fig. 1, 스펙 2(속성 매핑 계층).
- `docs/superpowers/specs/2026-10-01-mode3-v9-registry-design.md` §5.5 의 제약 추정을 실측으로 갱신(Task 16 결과).
