# Mode 3 속성 술어 확장(V7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** π_rp 에 집합 소속 술어(`a_sel ∈ S`, root 하나를 공개 입력으로)를 더하고, 시각 상대 술어("나이 ≥ N")는 회로를 바꾸지 않고 검증자(AttrGate·RP)가 자기 시계로 판정하게 한다.

**Architecture:** 회로 V7 은 공개 입력 25개(`set_sel`[23], `set_root`[24]); 집합은 정렬·중복 제거·2^64 패딩·깊이 8 Poseidon(2) 트리이고 그 정의는 `lib/mode3_set_tree.js` 하나에 있다(지갑·RP·테스트 공유). `Mode3Wallet.execute` 는 꼬리 11워드·다이제스트 11워드, `AttrGate` v2 는 `allowedCountriesRoot`·`minAge` 와 `block.timestamp` 로 판정한다. 지갑 요청은 `disclose` 옆에 `set: {slot, members}` 를 받고, 에이전트가 root 를 스스로 계산한다. CIA 는 개봉 API 의 공개 입력 길이 검사(23 → 25)만 바뀐다.

**Tech Stack:** circom 2.1.9 + circomlib(Poseidon, MultiMux1, IsEqual), snarkjs Groth16(pot21), Solidity 0.8.24 + hardhat, Node ESM(ethers v6, circomlibjs), MetaMask Snap(snaps-sdk), node:test 스타일 `t()` 러너.

**Spec:** `docs/superpowers/specs/2026-09-23-mode3-predicates-design.md` (V6 spec `2026-09-22-mode3-selective-disclosure-design.md` 를 잇는다)

## Global Constraints

- 공개 입력 순서(불변): `[0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot [7,8] pk_CIA [9,10] pk_trace [11,12] tag_c1 [13] tag_c2 [14] disc_mask [15..18] disc_lo [19..22] disc_hi [23] set_sel [24] set_root` — 25개.
- 집합 트리: 원소 `0 ≤ s < 2^64`, 오름차순 정렬·중복 제거, `1 ≤ |S| ≤ 256`, 깊이 `SET_DEPTH = 8`, 패딩 `SET_PAD = 2^64`, 노드 `Poseidon(2)(left, right)`, 리프 = 원소 값 그대로.
- `set_sel ∈ {0,1,2,3,4}`: 0 = 집합 술어 없음, k = 슬롯 k−1. `set_sel = 0 → set_root = 0` (회로·컨트랙트·RP 모두 강제).
- `execute` 꼬리 = 11워드(352 B) `mask, lo[4], hi[4], set_sel, set_root`, mask·sel 과 무관하게 항상 붙인다. 단순 송금 예외는 `payload.data` 가 비고 `mask = 0` **이고** `set_sel = 0` 일 때만.
- σ 다이제스트 = `abi.encode(chainid, wallet, to, value, data, nonce, mask, lo[4], hi[4], set_sel, set_root)`.
- AttrGate v2 정책: `mask & 1 == 1`, `set_sel == 2 && set_root == allowedCountriesRoot`, `hi[0] + minAge ≤ yearOf(block.timestamp)`. 기본 허용 국가 `[410, 392, 840, 276, 250]`(KR·JP·US·DE·FR, ISO 3166 numeric), 기본 `minAge = 19`. RP env `MODE3_ALLOWED_COUNTRIES`(쉼표 구분)·`MODE3_MIN_AGE`.
- 나이는 연 단위("올해 − 출생연도 ≥ N"). 오프체인 RP 는 `new Date().getUTCFullYear()`.
- 오류 사유 문자열: 형식 오류 `bad_disclosure`, 불만족 `disclosure_unsatisfiable`, RP 로그인 정책 미충족 `predicate_unmet`.
- 회로 산출물은 `bash scripts/build_mode3_circuit.sh pot21_final.ptau` 로만 만든다(zkey·vkey·wasm·`contracts/PiCredVerifier.sol` 한 세트). `npm run zk:*` 는 쓰지 않는다.
- 새 테스트 파일은 `scripts/run_tests.sh` 의 해당 그룹에 넣는다. 커밋 메시지는 한글, 저장소 관례(`feat(mode3): …`, `test(mode3): …`) 를 따르고 트레일러는 세션 규칙대로.
- `idp_state.json`·`cia_state.json`·`mode3_wallet_state.json`·`.env`·`*_keys.json` 은 읽거나 지우지 않는다.

---

## 파일 구조

| 파일 | 책임 | 작업 |
|---|---|---|
| `lib/mode3_set_tree.js` (신규) | 집합 트리 정의 하나: `normalizeMembers`, `setRoot`, `setPath`, `SET_DEPTH`, `SET_PAD`, `NO_SET` | T1 |
| `tests/test_mode3_set_tree.mjs` (신규) | 위 단위 테스트 | T1 |
| `circuits/pi_cred.circom` | V7: `set_sel`·`set_root`·`set_index`·`set_path[8]`, ⑦ 집합 소속 | T2 |
| `tests/helpers/mode3_fixture.mjs` | `buildValidInput({ set })` | T2 |
| `tests/test_pi_cred_witness.mjs` | V7 양성·음성 | T2 |
| `contracts/Mode3Wallet.sol`, `contracts/AttrGate.sol`, `contracts/PiCredVerifier.sol`(생성) | pub[25]·꼬리 11워드·이벤트, AttrGate v2(`yearOf`) | T3 |
| `lib/mode3_onchain.js` | ABI·`payloadDigest`·`parseExecuteReceipt`·`deployAttrGate` | T3 |
| `test/Mode3Wallet.test.mjs`, `test/AttrGate.test.mjs` (신규) | 컨트랙트 테스트 | T3 |
| `lib/mode3_wallet.js` | `normalizeSet`, `disclosureKey`, `buildCredentialProof` set 입력 | T4 |
| `tests/test_mode3_wallet.mjs` | 단위 테스트 | T4 |
| `mode3_wallet_agent.js`, `mode3/wallet.html`, `snap-mode3/src/index.js`(+dist) | 트랜잭션 경로의 `set`, 동의 창, 폼 | T5 |
| `snap-mode3/test/rpc.test.mjs`, `tests/test_mode3_wallet_agent.mjs` | 테스트 | T5 |
| `lib/mode3_rp.js`, `mode3_rp.js`, `mode3/rp.html`, `cia.js` | 25개 파싱, 정책 env, AttrGate v2 배포, `predicates`, 개봉 길이 | T6 |
| `tests/test_mode3_rp.mjs` | 테스트 | T6 |
| `mode3_wallet_agent.js`(login), `mode3/wallet.html`(팝업), `snap-mode3/src/index.js`(consentLogin), `mode3/rp.html`, `mode3_rp.js` | 로그인 경로 술어 | T7 |
| `tests/test_mode3_demo_stack.mjs`, `tests/helpers/isolated_mode3_stack.mjs`, `scripts/bench_mode3_onchain.mjs` | V7 시나리오·벤치 | T8 |
| `docs/MODE3_DEMO.md`, `results/mode3_predicates_20260923.md`, spec 정정 | 문서·측정 | T9 |

---

### Task 1: 집합 트리 라이브러리 `lib/mode3_set_tree.js`

**Files:**
- Create: `lib/mode3_set_tree.js`
- Create: `tests/test_mode3_set_tree.mjs`
- Modify: `scripts/run_tests.sh` (UNIT 배열에 파일 추가)

**Interfaces:**
- Consumes: `circomlibjs.buildPoseidon` (lib/imt.js 와 같은 방식).
- Produces:
  - `export const SET_DEPTH = 8`, `export const SET_SIZE = 256`, `export const SET_PAD = 1n << 64n`
  - `export const NO_SET = Object.freeze({ sel: 0n, root: 0n, index: 0, path: Object.freeze(Array(8).fill(0n)) })`
  - `export function normalizeMembers(members) → bigint[]` (정렬·중복 제거; 오류는 `Error` + `.reason = 'bad_disclosure'`)
  - `export async function setRoot(members) → bigint`
  - `export async function setPath(members, value) → { index: number, path: bigint[8], root: bigint }` (없으면 `.reason = 'disclosure_unsatisfiable'`)

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_mode3_set_tree.mjs`:

```js
// 집합 트리(V7 spec §2) — 회로·지갑·RP 가 공유하는 정의. node tests/test_mode3_set_tree.mjs
import assert from 'node:assert/strict';
import { buildPoseidon } from 'circomlibjs';
import { normalizeMembers, setRoot, setPath, SET_DEPTH, SET_SIZE, SET_PAD, NO_SET } from '../lib/mode3_set_tree.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

await t('상수: 깊이 8, 리프 256, 패딩 2^64, NO_SET 은 sel 0·root 0·path 0×8', () => {
  assert.equal(SET_DEPTH, 8); assert.equal(SET_SIZE, 256); assert.equal(SET_PAD, 1n << 64n);
  assert.deepEqual({ ...NO_SET, path: [...NO_SET.path] }, { sel: 0n, root: 0n, index: 0, path: Array(8).fill(0n) });
});

await t('normalizeMembers: 정렬·중복 제거, 문자열·숫자·bigint 혼용 허용', () => {
  assert.deepEqual(normalizeMembers(['840', 410, 392n, '410']), [392n, 410n, 840n]);
});

await t('normalizeMembers: 빈 배열·배열 아님·비정수·음수·≥2^64·257개(중복 제거 후) 는 bad_disclosure', () => {
  for (const bad of [[], 'x', null, ['abc'], [-1], [(1n << 64n).toString()], Array.from({ length: 257 }, (_, i) => i)]) {
    assert.throws(() => normalizeMembers(bad), (e) => e.reason === 'bad_disclosure', `허용되면 안 됨: ${JSON.stringify(bad)?.slice(0, 40)}`);
  }
  assert.equal(normalizeMembers(Array.from({ length: 300 }, (_, i) => i % 256)).length, 256);   // 중복 제거 뒤 256 이면 허용
});

await t('setRoot: 순서·중복과 무관하게 같은 root, 원소가 다르면 다른 root', async () => {
  const a = await setRoot([410, 392, 840, 276, 250]);
  const b = await setRoot(['250', '276', '392', '410', '840', '410']);
  assert.equal(a, b);
  assert.notEqual(a, await setRoot([410, 392, 840, 276]));
});

await t('setRoot: 손으로 계산한 깊이 8 트리(리프 = 값, 빈 자리 = 2^64, Poseidon(2))와 같다', async () => {
  const poseidon = await buildPoseidon();
  const H = (x, y) => poseidon.F.toObject(poseidon([x, y]));
  let layer = Array.from({ length: 256 }, (_, i) => (i < 3 ? [7n, 9n, 11n][i] : SET_PAD));
  for (let d = 0; d < 8; d++) { const n = []; for (let i = 0; i < layer.length; i += 2) n.push(H(layer[i], layer[i + 1])); layer = n; }
  assert.equal(await setRoot([11, 7, 9]), layer[0]);
});

await t('setPath: 경로로 root 를 재구성할 수 있고 index 는 정렬 뒤 위치', async () => {
  const members = [410, 392, 840, 276, 250];
  const { index, path, root } = await setPath(members, 410);
  assert.equal(index, 3);   // 정렬 [250, 276, 392, 410, 840]
  assert.equal(path.length, 8);
  const poseidon = await buildPoseidon();
  const H = (x, y) => poseidon.F.toObject(poseidon([x, y]));
  let cur = 410n, idx = index;
  for (let i = 0; i < 8; i++) { cur = (idx & 1) ? H(path[i], cur) : H(cur, path[i]); idx >>= 1; }
  assert.equal(cur, root);
  assert.equal(root, await setRoot(members));
});

await t('setPath: 없는 값은 disclosure_unsatisfiable, 형식 오류는 bad_disclosure', async () => {
  await assert.rejects(() => setPath([410, 392], 840), (e) => e.reason === 'disclosure_unsatisfiable');
  await assert.rejects(() => setPath([], 840), (e) => e.reason === 'bad_disclosure');
});

if (failed) { console.error(`${failed} failed`); process.exit(1); }
console.log('all passed');
```

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_set_tree.mjs`
Expected: `ERR_MODULE_NOT_FOUND` (lib/mode3_set_tree.js 없음)

- [ ] **Step 3: 구현**

`lib/mode3_set_tree.js`:

```js
// Mode 3 집합 소속 술어의 집합 트리 — 설계 2026-09-23-mode3-predicates-design.md §2.
// 회로(circuits/pi_cred.circom ⑦)·지갑(lib/mode3_wallet.js normalizeSet)·서비스(AttrGate 배포, 오프체인 정책)·테스트가 전부 이 정의를 쓴다.
// 리프 = 원소 값 그대로, 빈 자리 = SET_PAD(2^64) — 속성은 회로에서 64비트로 잘려 있어 어떤 속성도 패딩과 같을 수 없다.
import { buildPoseidon } from 'circomlibjs';

export const SET_DEPTH = 8;
export const SET_SIZE = 1 << SET_DEPTH;   // 256
export const SET_PAD = 1n << 64n;
const ATTR_MAX = 1n << 64n;
/** 집합 술어 없음 — 회로 입력 set_sel = 0, set_root = 0 (path·index 는 아무 값이나 되지만 0 으로 둔다). */
export const NO_SET = Object.freeze({ sel: 0n, root: 0n, index: 0, path: Object.freeze(Array(SET_DEPTH).fill(0n)) });

let poseidonPromise = null;
const getPoseidon = () => (poseidonPromise ??= buildPoseidon());
const fail = (reason, msg) => Object.assign(new Error(msg), { reason });

/** 형식 검사 + 오름차순 정렬 + 중복 제거. 오류는 bad_disclosure. */
export function normalizeMembers(members) {
  if (!Array.isArray(members) || members.length === 0) throw fail('bad_disclosure', 'set.members 는 비어 있지 않은 배열');
  const seen = new Set();
  for (const m of members) {
    if (typeof m !== 'string' && typeof m !== 'number' && typeof m !== 'bigint') throw fail('bad_disclosure', `set.members 원소가 정수가 아니다: ${String(m)}`);
    let v;
    try { v = BigInt(m); } catch { throw fail('bad_disclosure', `set.members 원소가 정수가 아니다: ${String(m)}`); }
    if (v < 0n || v >= ATTR_MAX) throw fail('bad_disclosure', `set.members 원소는 0 ≤ v < 2^64: ${String(m)}`);
    seen.add(v);
  }
  const sorted = [...seen].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (sorted.length > SET_SIZE) throw fail('bad_disclosure', `set.members 는 중복 제거 뒤 최대 ${SET_SIZE}개`);
  return sorted;
}

/** 리프층부터 root 까지 층별 노드. levels[0] = 리프 256개, levels[SET_DEPTH] = [root]. */
async function levels(sorted) {
  const poseidon = await getPoseidon();
  const H = (a, b) => poseidon.F.toObject(poseidon([a, b]));
  let layer = Array.from({ length: SET_SIZE }, (_, i) => (i < sorted.length ? sorted[i] : SET_PAD));
  const out = [layer];
  for (let d = 0; d < SET_DEPTH; d++) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) next.push(H(layer[i], layer[i + 1]));
    out.push(next); layer = next;
  }
  return out;
}

export async function setRoot(members) {
  const L = await levels(normalizeMembers(members));
  return L[SET_DEPTH][0];
}

/** value 의 멤버십 경로. path[i] 는 i 층의 형제, index 비트 i 가 1 이면 value 쪽이 오른쪽 자식이다(회로 ⑦ 의 MultiMux1 과 같은 규약). */
export async function setPath(members, value) {
  const sorted = normalizeMembers(members);
  const v = BigInt(value);
  const index = sorted.indexOf(v);
  if (index < 0) throw fail('disclosure_unsatisfiable', `값 ${v} 이 집합에 없다`);
  const L = await levels(sorted);
  const path = [];
  let idx = index;
  for (let d = 0; d < SET_DEPTH; d++) { path.push(L[d][idx ^ 1]); idx >>= 1; }
  return { index, path, root: L[SET_DEPTH][0] };
}
```

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_set_tree.mjs`
Expected: 7 ok, `all passed`

- [ ] **Step 5: 러너 등록**

`scripts/run_tests.sh` 의 `UNIT=(` 배열에서 `tests/test_mode3_commit_scheme.mjs` 가 있는 줄 **앞**에 `tests/test_mode3_set_tree.mjs` 한 줄 추가(UNIT 배열은 `tests/test_mode3_secret_source.js` 근처 — 파일을 열어 `UNIT=(` 블록을 찾는다).

Run: `bash scripts/run_tests.sh unit 2>&1 | tail -3`
Expected: 새 파일 포함 전부 ok

- [ ] **Step 6: Commit**

```bash
git add lib/mode3_set_tree.js tests/test_mode3_set_tree.mjs scripts/run_tests.sh
git commit -m "feat(mode3): 집합 소속 술어의 집합 트리(lib/mode3_set_tree.js) — 정렬·중복 제거·2^64 패딩·깊이 8 Poseidon(2), 단위 테스트"
```

---

### Task 2: 회로 V7 — 집합 소속 ⑦

**Files:**
- Modify: `circuits/pi_cred.circom` (입력 선언 §Private/§Public, ⑥ 뒤에 ⑦, `component main` 공개 목록, 머리 주석)
- Modify: `tests/helpers/mode3_fixture.mjs:10-70` (`set` 옵션)
- Modify: `tests/test_pi_cred_witness.mjs` (V7 케이스 추가)

**Interfaces:**
- Consumes: Task 1 의 `setPath(members, value)`, `NO_SET`.
- Produces: 회로 입력 `set_sel, set_root`(공개 [23],[24]), `set_index, set_path[8]`(비공개). 픽스처 `buildValidInput({ set: { slot, members } })` 가 `input.set_*` 를 채우고 `fx.set = { sel, root, index, path }` 를 돌려준다.

- [ ] **Step 1: 픽스처에 `set` 옵션**

`tests/helpers/mode3_fixture.mjs`: import 추가 `import { setPath, NO_SET } from '../../lib/mode3_set_tree.js';`. 시그니처를 `buildValidInput({ pk_i: pkIOpt, maxHeight = 1789000000n, allowAgent = 0n, chainid = 31337n, disclosure = null, set = null } = {})` 로. `const disc = …` 다음에:

```js
  // V7 집합 소속(spec §3): set = { slot: 0..3, members: [...] } 이면 attrs[slot] 의 경로를 만든다. 없으면 NO_SET.
  let st = NO_SET;
  if (set) {
    const { index, path, root } = await setPath(set.members, attrs[set.slot]);
    st = { sel: BigInt(set.slot) + 1n, root, index, path };
  }
```

`input` 객체 끝(disc_hi 다음)에:

```js
    set_sel: st.sel.toString(), set_root: st.root.toString(), set_index: String(st.index), set_path: st.path.map(String),
```

반환에 `set: st` 추가: `return { input, Cf_u, Cf_s, pk_trace, shares, tag, ciaPub, arid, uid, tree, attrs, disclosure: disc, set: st };`

- [ ] **Step 2: 실패하는 회로 테스트 추가**

`tests/test_pi_cred_witness.mjs` 끝(`V6 음성: mask ≥ 16 …` 케이스 뒤, 요약 출력 앞)에:

```js
const COUNTRIES = [410, 392, 840, 276, 250];
await t('V7 양성: set_sel = 0, set_root = 0 (집합 술어 없음) — 기존 입력 그대로 통과, 공개 입력에 set_sel·set_root 가 있다', async () => {
  const fx = await buildValidInput();
  assert.equal(fx.input.set_sel, '0'); assert.equal(fx.input.set_root, '0');
  await witness(fx.input);
});
await t('V7 양성: 국가(a₁ = 410) ∈ {410,392,840,276,250} — set_sel = 2 통과', async () => {
  const fx = await buildValidInput({ set: { slot: 1, members: COUNTRIES } });
  assert.equal(fx.input.set_sel, '2');
  await witness(fx.input);
});
await t('V7 양성: 범위 + 집합 동시(슬롯 0 범위, 슬롯 1 집합)', async () => {
  const fx = await buildValidInput({ disclosure: { mask: 0b0001n, lo: [0n, 0n, 0n, 0n], hi: [2007n, 0n, 0n, 0n] }, set: { slot: 1, members: COUNTRIES } });
  await witness(fx.input);
});
await t('V7 음성: root 를 바꾸면 거부', async () => {
  const fx = await buildValidInput({ set: { slot: 1, members: COUNTRIES } });
  await assert.rejects(() => witness({ ...fx.input, set_root: (BigInt(fx.input.set_root) + 1n).toString() }), /Assert Failed/);
});
await t('V7 음성: 다른 슬롯을 가리키면(set_sel = 1, a₀ = 1990 ∉ S) 거부', async () => {
  const fx = await buildValidInput({ set: { slot: 1, members: COUNTRIES } });
  await assert.rejects(() => witness({ ...fx.input, set_sel: '1' }), /Assert Failed/);
});
await t('V7 음성: 경로 index 를 바꾸면 거부', async () => {
  const fx = await buildValidInput({ set: { slot: 1, members: COUNTRIES } });
  await assert.rejects(() => witness({ ...fx.input, set_index: String((Number(fx.input.set_index) + 1) % 256) }), /Assert Failed/);
});
await t('V7 음성: set_sel = 0 인데 set_root ≠ 0 은 거부(검증자가 무시하는 값에 쓰레기를 실을 수 없다)', async () => {
  const fx = await buildValidInput();
  await assert.rejects(() => witness({ ...fx.input, set_root: '1' }), /Assert Failed/);
});
await t('V7 음성: set_sel = 5 는 거부', async () => {
  const fx = await buildValidInput({ set: { slot: 1, members: COUNTRIES } });
  await assert.rejects(() => witness({ ...fx.input, set_sel: '5' }), /Assert Failed/);
});
await t('V7 양성: set_sel = 0 이면 set_index·set_path 는 무시된다', async () => {
  const fx = await buildValidInput();
  await witness({ ...fx.input, set_index: '77', set_path: Array(8).fill('123456789') });
});
await t('V7: 패딩 리프(2^64)는 어떤 속성으로도 못 맞춘다 — 속성이 64비트라 2^64 자체가 거부된다', async () => {
  // 집합에 원소 하나만 두면 index 1..255 는 전부 패딩. 속성 값을 2^64 로 바꿔 패딩 자리에 맞추려 해도 C_u 의 Num2Bits(64) 가 먼저 막는다.
  const fx = await buildValidInput({ set: { slot: 3, members: [0] } });   // a₃ = 0 ∈ {0}
  await witness(fx.input);
  await assert.rejects(() => witness({ ...fx.input, attrs: ['1990', '410', '2', (1n << 64n).toString()], set_index: '1' }), /Assert Failed/);
});
```

- [ ] **Step 3: 실패 확인**

Run: `node tests/test_pi_cred_witness.mjs 2>&1 | tail -15`
Expected: 컴파일은 되나 V7 케이스들이 FAIL(회로에 `set_sel` 입력이 없어 witness 계산기가 거부하거나 unknown signal).

- [ ] **Step 4: 회로 구현**

`circuits/pi_cred.circom`:

(a) include 에 `include "lib/mux1.circom";` 추가(`circuits/lib/mux1.circom` 에 `MultiMux1` 이 있다).

(b) 머리 주석에 한 줄: `// V7(2026-09-23): 집합 소속 set_sel/set_root(공개)·set_index/set_path(비공개). 설계 2026-09-23-mode3-predicates-design.md §3`.

(c) `// ---- Private ----` 블록의 `signal input pathIndices[depth];` 뒤:

```
    // V7 집합 소속 경로(비공개). set_sel = 0 이면 무시된다(지갑은 0 을 넣는다).
    signal input set_index;        // 리프 인덱스 0..255
    signal input set_path[8];      // 형제 노드, 리프에서 root 쪽으로
```

(d) `// ---- Public ----` 블록의 `signal input disc_hi[4];` 뒤:

```
    // V7 집합 소속(2026-09-23 §3): set_sel ∈ {0..4}, 0 = 없음, k = 슬롯 k−1 이 set_root 의 집합에 속한다. sel = 0 이면 root = 0 이어야 한다.
    signal input set_sel;
    signal input set_root;
```

(e) ⑥ 블록(`for (var k = 0; k < 4; k++) { … }` 닫는 `}`) 뒤, 템플릿 닫는 `}` 앞에:

```
    // ---- ⑦ 집합 소속 (2026-09-23 V7 §3.2) ----
    // sel 을 원핫 5개로 풀고 합이 1 이어야 한다 — sel ∉ {0..4} 는 여기서 죽는다.
    component selIs[5];
    var selSum = 0;
    for (var j = 0; j < 5; j++) {
        selIs[j] = IsEqual();
        selIs[j].in[0] <== set_sel;
        selIs[j].in[1] <== j;
        selSum += selIs[j].out;
    }
    selSum === 1;
    // 선택된 속성 값(sel = 0 이면 0). 곱 하나당 신호 하나 — 사차 항 여러 개를 한 제약에 못 둔다.
    signal selTerm[4];
    for (var k = 0; k < 4; k++) selTerm[k] <== selIs[k + 1].out * attrs[k];
    signal setVal;
    setVal <== selTerm[0] + selTerm[1] + selTerm[2] + selTerm[3];
    // 깊이 8 경로. index 비트가 0 이면 현재 노드가 왼쪽(lib/mode3_set_tree.js setPath 와 같은 규약).
    component setIdxBits = Num2Bits(8);
    setIdxBits.in <== set_index;
    component setMux[8];
    component setHash[8];
    signal setCur[9];
    setCur[0] <== setVal;
    for (var i = 0; i < 8; i++) {
        setMux[i] = MultiMux1(2);
        setMux[i].c[0][0] <== setCur[i];     setMux[i].c[0][1] <== set_path[i];
        setMux[i].c[1][0] <== set_path[i];   setMux[i].c[1][1] <== setCur[i];
        setMux[i].s <== setIdxBits.out[i];
        setHash[i] = Poseidon(2);
        setHash[i].inputs[0] <== setMux[i].out[0];
        setHash[i].inputs[1] <== setMux[i].out[1];
        setCur[i + 1] <== setHash[i].out;
    }
    // sel ≠ 0 → 계산한 root == set_root;  sel = 0 → set_root == 0.
    (1 - selIs[0].out) * (setCur[8] - set_root) === 0;
    selIs[0].out * set_root === 0;
```

(f) 꼬리 주석·공개 목록:

```
// [14] disc_mask [15..18] disc_lo [19..22] disc_hi [23] set_sel [24] set_root
component main {public [
    PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, pk_CIA_x, pk_CIA_y,
    pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2,
    disc_mask, disc_lo, disc_hi, set_sel, set_root
]} = PiCred(32);
```

- [ ] **Step 5: 통과 확인**

Run: `node tests/test_pi_cred_witness.mjs 2>&1 | tail -16`
Expected: 첫 줄 `OK: 컴파일됨, 비선형 제약 N개` 에서 N ≈ 27,400(V6 25,369 + ≈2k; 정확값을 보고서에 적는다), V6·V7 전부 ok. `build/mode3/witness_test/` 에만 컴파일된다(`build/mode3/` 의 zkey·wasm 은 건드리지 않는다 — Task 3 에서 세트로 재생성).

- [ ] **Step 6: Commit**

```bash
git add circuits/pi_cred.circom tests/helpers/mode3_fixture.mjs tests/test_pi_cred_witness.mjs
git commit -m "feat(mode3): 회로 V7 — 집합 소속 술어(set_sel·set_root 공개, 깊이 8 Poseidon 경로), 공개 입력 25개; 픽스처 set 옵션·witness 테스트 10건"
```

---

### Task 3: 온체인 V7 — `Mode3Wallet` pub[25]·꼬리 11워드, `AttrGate` v2, 산출물 재생성

**Files:**
- Run: `bash scripts/build_mode3_circuit.sh pot21_final.ptau` (→ `build/mode3/*`, `contracts/PiCredVerifier.sol`)
- Modify: `contracts/Mode3Wallet.sol`
- Rewrite: `contracts/AttrGate.sol`
- Modify: `lib/mode3_onchain.js` (`WALLET_ABI`, `ATTR_GATE_ABI`, `payloadDigest`, `parseExecuteReceipt`, `deployAttrGate`)
- Modify: `test/Mode3Wallet.test.mjs`
- Create: `test/AttrGate.test.mjs`

**Interfaces:**
- Consumes: Task 1 `setRoot`; Task 2 픽스처 `buildValidInput({ set })`.
- Produces:
  - `execute(payload, sig, a, b, c, uint[25] pub)`; `event Disclosure(uint256 indexed nonceUsed, uint256 mask, uint256[4] lo, uint256[4] hi, uint256 setSel, uint256 setRoot)`.
  - `payloadDigest({ chainId, wallet, to, value, data, nonce, discMask = 0n, discLo = [0n×4], discHi = [0n×4], setSel = 0n, setRoot = 0n })`.
  - `parseExecuteReceipt(...)` 의 `disclosure = { mask, lo, hi, setSel, setRoot } | null`.
  - `deployAttrGate(signer, { factoryAddress, allowedCountries = [410n, 392n, 840n, 276n, 250n], minAge = 19n }) → address`; `ATTR_GATE_ABI` 에 `allowedCountriesRoot() view returns (uint256)`, `minAge() view returns (uint64)`, `yearOf(uint256) pure returns (uint256)`, `event Claimed(address indexed wallet, uint64 birthYearHi, uint256 setRoot)`.

- [ ] **Step 1: 산출물 재생성(수 분)**

Run: `bash scripts/build_mode3_circuit.sh pot21_final.ptau 2>&1 | tail -5`
Expected: `build/mode3/pi_cred_final.zkey`·`pi_cred_vkey.json`·`pi_cred_js/pi_cred.wasm` 새로 생성, `contracts/PiCredVerifier.sol` 의 `verifyProof(..., uint[25] calldata _pubSignals)`. 확인: `grep -c "uint\[25\]" contracts/PiCredVerifier.sol` → ≥ 1.

- [ ] **Step 2: 실패하는 컨트랙트 테스트**

`test/Mode3Wallet.test.mjs`:
- `signedPayload` 시그니처에 `setSel = 0n, setRoot = 0n` 추가하고 `signPayload(…, { …, discMask, discLo, discHi, setSel, setRoot })`.
- `V6: pub 은 23개…` 케이스의 `assert.equal(ST.pub.length, 23)` → `25`, 이름을 `V7: pub 은 25개이고 …` 로.
- 위조 꼬리 회귀 케이스: `fakeTail` 인코딩을 `encode(['uint256','uint256[4]','uint256[4]','uint256','uint256'], [3n, [0n,840n,0n,0n], [2007n,840n,0n,0n], 2n, FAKE_ROOT])` 로(`const FAKE_ROOT = await setRoot([840n]);`, 파일 상단 `import { setRoot } from '../lib/mode3_set_tree.js';`). 게이트 배포는 `Gate.deploy(factory, await setRoot([840n]), 19n)` 로(정책 = 미국만 허용 → ST(410) 는 위조 없이는 통과 못 한다). "진짜 π" 대조 부분은 `statement({ disclosure: { mask: 0b0001n, lo: [0n×4], hi: [1990n, 0n, 0n, 0n] }, set: { slot: 1, members: [410, 392, 840, 276, 250] } })` 로 만들고 `gate2 = Gate.deploy(factory2, await setRoot([410, 392, 840, 276, 250]), 19n)`, `signedPayload(DS, wallet2, { …, discMask: 1n, discLo: DS.fx.disclosure.lo, discHi: DS.fx.disclosure.hi, setSel: 2n, setRoot: DS.fx.set.root })`.
- `V6: mask ≠ 0 이면 대상이 꼬리 9워드…` 케이스를 V7 로: 위와 같은 DS/gate, 단언에 `assert.equal(disclosure.setSel, 2n); assert.equal(disclosure.setRoot, DS.fx.set.root);` 추가.
- `V6: 공개 구간이 정책보다 넓으면…` 케이스: `hi[0] = 2010` 대신 **나이 정책**으로 — `wide = statement({ disclosure: { mask: 1n, …, hi: [1990n,…] }, set: {slot:1, members: COUNTRIES} })`, `gate = Gate.deploy(factory, root, 200n)` (minAge 200 → 1990 + 200 > 올해) → `success=false`.
- 새 케이스 둘:

```js
  it('V7: 다이제스트가 set_sel·set_root 를 덮는다 — 서명은 sel 0 인데 π 는 sel 2 면 BadSignature', async () => {
    const DS = withInput(await statement({ set: { slot: 1, members: [410, 392, 840, 276, 250] } }));
    const { wallet } = await deployStack(DS);
    const { payload, sig } = await signedPayload(DS, wallet);   // setSel 0, setRoot 0 으로 서명
    await expect(wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
  });
  it('V7: 단순 송금 예외는 mask = 0 이고 set_sel = 0 일 때만 — set_sel ≠ 0 이면 data 가 비어도 꼬리가 붙어 receive()-only 대상은 실패', async () => {
    const DS = withInput(await statement({ set: { slot: 1, members: [410, 392, 840, 276, 250] } }));
    const { wallet, factory } = await deployStack(DS);
    const other = await factory.computeAddress(BigInt(DS.input().PPID) + 1n);
    await (await factory.deploy(BigInt(DS.input().PPID) + 1n)).wait();
    const { payload, sig } = await signedPayload(DS, wallet, { to: other, value: 0n, data: '0x', setSel: 2n, setRoot: DS.fx.set.root });
    const rc = await (await wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub)).wait();
    assert.equal(parseExecuteReceipt(rc, wallet.target).executed.success, false);
  });
```

`test/AttrGate.test.mjs`(신규):

```js
// AttrGate v2 — 설계 2026-09-23 §4.2: 집합 root + block.timestamp 기반 나이. hardhat 인프로세스 체인(contract 그룹).
import { expect } from 'chai';
import assert from 'node:assert';
import hre from 'hardhat';
import { setRoot } from '../lib/mode3_set_tree.js';

const { ethers } = hre;

describe('AttrGate v2', function () {
  this.timeout(60_000);
  let gate;
  before(async () => {
    const [deployer] = await ethers.getSigners();
    // 팩토리 주소는 isWallet 검사에만 쓰인다 — yearOf 는 pure 라 아무 주소나 된다.
    const Gate = await ethers.getContractFactory('AttrGate');
    gate = await Gate.deploy(deployer.address, await setRoot([410, 392, 840, 276, 250]), 19n);
  });

  it('yearOf: UTC 연도 경계 — 1970-01-01, 2000-02-29, 2026-12-31 23:59:59, 2027-01-01 00:00:00, 2100-03-01', async () => {
    const cases = [0, Date.UTC(2000, 1, 29) / 1000, Date.UTC(2026, 11, 31, 23, 59, 59) / 1000, Date.UTC(2027, 0, 1) / 1000, Date.UTC(2100, 2, 1) / 1000, Date.UTC(1999, 11, 31, 23, 59, 59) / 1000];
    for (const ts of cases) assert.equal(await gate.yearOf(ts), BigInt(new Date(ts * 1000).getUTCFullYear()), `ts=${ts}`);
  });

  it('생성자 값이 immutable 로 남는다', async () => {
    assert.equal(await gate.allowedCountriesRoot(), await setRoot([250, 276, 392, 410, 840]));
    assert.equal(await gate.minAge(), 19n);
  });

  it('claim: 팩토리가 배포한 지갑이 아니면 revert', async () => {
    await expect(gate.claim()).to.be.revertedWith('not a mode3 wallet');
  });
});
```

(claim 의 성공·country·age 분기는 진짜 π 가 필요해 `test/Mode3Wallet.test.mjs` 쪽 케이스가 맡는다 — 위 V7 케이스들.)

- [ ] **Step 3: 실패 확인**

Run: `npx hardhat test test/AttrGate.test.mjs 2>&1 | tail -12`
Expected: `yearOf is not a function` 류로 FAIL (AttrGate 는 아직 v1).

- [ ] **Step 4: 컨트랙트 구현**

`contracts/Mode3Wallet.sol`:
- 문서 주석 `@param pub 공개 입력 23개` → `25개`, 순서 줄에 `[23] set_sel [24] set_root` 추가.
- `uint[23] calldata pub` → `uint[25] calldata pub` (execute 와 `_checkStatement` 둘 다).
- `event Disclosure(uint256 indexed nonceUsed, uint256 mask, uint256[4] lo, uint256[4] hi, uint256 setSel, uint256 setRoot);`
- 다이제스트:

```solidity
        bytes32 payloadHash = keccak256(
            abi.encode(
                block.chainid, address(this), payload.to, payload.value, payload.data, payload.nonce,
                pub[14], [pub[15], pub[16], pub[17], pub[18]], [pub[19], pub[20], pub[21], pub[22]], pub[23], pub[24]
            )
        );
```

- 꼬리(주석의 "9워드(288바이트)" → "11워드(352바이트: mask, lo[4], hi[4], set_sel, set_root)", 예외 조건에 set_sel 추가):

```solidity
        bytes memory data = (payload.data.length == 0 && pub[14] == 0 && pub[23] == 0)
            ? payload.data
            : abi.encodePacked(payload.data, pub[14], pub[15], pub[16], pub[17], pub[18], pub[19], pub[20], pub[21], pub[22], pub[23], pub[24]);
```

- 이벤트: `if (pub[14] != 0 || pub[23] != 0) { emit Disclosure(payload.nonce, pub[14], [pub[15], pub[16], pub[17], pub[18]], [pub[19], pub[20], pub[21], pub[22]], pub[23], pub[24]); }`
- `_checkStatement` 의 `if (pub[14] >= 16) revert BadDisclosure();` 뒤에:

```solidity
        // V7: set_sel ∈ {0..4}, sel = 0 이면 root = 0 — 회로도 막지만 꼬리·이벤트·다이제스트에 남는 값이라 한 번 더
        if (pub[23] > 4 || (pub[23] == 0 && pub[24] != 0)) revert BadDisclosure();
```

`contracts/AttrGate.sol` 전체 교체:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Mode3WalletFactory.sol";

/// @title 데모 대상 v2 — 집합 소속 + 시각 상대 술어 (설계 2026-09-23-mode3-predicates-design.md §4.2)
/// @notice Mode3Wallet.execute 가 π 검증 뒤 호출 데이터 꼬리에 붙인 (mask, lo[4], hi[4], set_sel, set_root) 11워드를 읽는다.
///   꼬리는 mask·sel 값과 무관하게 항상 붙는다(둘 다 0 이면 전부 0) — 그래야 payload.data 안의 위조 꼬리가 그 앞에 묻힌다
///   (2026-09-22 최종 리뷰 Critical). 예외는 payload.data 가 비고 mask = 0, set_sel = 0 인 단순 송금뿐(셀렉터가 없어 아무도 못 읽는다).
///   정책: 국가(a₁) ∈ S(allowedCountriesRoot), 올해(block.timestamp, UTC) − 출생연도(a₀) ≥ minAge. 나이는 연 단위다.
///   "올해" 를 체인 시계로 계산하므로 증명자가 시각을 고를 수 없다 — 회로는 그대로다(범위 술어 hi[0] 만 쓴다).
contract AttrGate {
    Mode3WalletFactory public immutable factory;
    uint256 public immutable allowedCountriesRoot;   // lib/mode3_set_tree.js setRoot(허용 국가) — 원소는 서비스가 게시한다
    uint64 public immutable minAge;
    mapping(address => bool) public claimed;

    event Claimed(address indexed wallet, uint64 birthYearHi, uint256 setRoot);

    uint256 private constant TAIL = 11 * 32;

    constructor(address _factory, uint256 _allowedCountriesRoot, uint64 _minAge) {
        factory = Mode3WalletFactory(_factory); allowedCountriesRoot = _allowedCountriesRoot; minAge = _minAge;
    }

    /// @dev calldata 끝 352바이트 = mask, lo[0..3], hi[0..3], set_sel, set_root (각 32바이트 워드).
    function _disclosure() internal pure returns (uint256 mask, uint256[4] memory lo, uint256[4] memory hi, uint256 setSel, uint256 setRoot) {
        require(msg.data.length >= 4 + TAIL, "no disclosure");
        uint256 base = msg.data.length - TAIL;
        assembly { mask := calldataload(base) }
        for (uint256 k = 0; k < 4; k++) {
            uint256 l; uint256 h;
            uint256 pl = base + 32 * (1 + k); uint256 ph = base + 32 * (5 + k);
            assembly { l := calldataload(pl) h := calldataload(ph) }
            lo[k] = l; hi[k] = h;
        }
        uint256 ps = base + 32 * 9; uint256 pr = base + 32 * 10;
        assembly { setSel := calldataload(ps) setRoot := calldataload(pr) }
    }

    /// @notice UNIX 초 → 그레고리력 연도(UTC). Howard Hinnant 의 civil_from_days — 윤년 규칙(4·100·400) 포함.
    function yearOf(uint256 ts) public pure returns (uint256) {
        uint256 z = ts / 86400 + 719468;
        uint256 era = z / 146097;
        uint256 doe = z - era * 146097;                                   // [0, 146096]
        uint256 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        uint256 y = yoe + era * 400;
        uint256 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);             // [0, 365]
        uint256 mp = (5 * doy + 2) / 153;                                  // [0, 11], 0 = 3월
        return y + (mp < 10 ? 0 : 1);                                      // 1·2월(mp 10·11)은 다음 해
    }

    function claim() external {
        require(factory.isWallet(msg.sender), "not a mode3 wallet");
        require(!claimed[msg.sender], "already claimed");
        (uint256 mask, , uint256[4] memory hi, uint256 setSel, uint256 setRoot) = _disclosure();
        require(mask & 0x1 == 0x1, "need slot0");
        require(setSel == 2 && setRoot == allowedCountriesRoot, "country");
        require(hi[0] + minAge <= yearOf(block.timestamp), "age");
        claimed[msg.sender] = true;
        emit Claimed(msg.sender, uint64(hi[0]), setRoot);
    }
}
```

`lib/mode3_onchain.js`:
- `WALLET_ABI`: execute 의 `uint256[23] pub` → `uint256[25] pub`; `'event Disclosure(uint256 indexed nonceUsed, uint256 mask, uint256[4] lo, uint256[4] hi, uint256 setSel, uint256 setRoot)'`.
- `ATTR_GATE_ABI`: `countryEq`·`birthYearMax` 줄을 `'function allowedCountriesRoot() view returns (uint256)'`, `'function minAge() view returns (uint64)'`, `'function yearOf(uint256) pure returns (uint256)'` 로, 이벤트를 `'event Claimed(address indexed wallet, uint64 birthYearHi, uint256 setRoot)'` 로.
- `payloadDigest`: 인자에 `setSel = 0n, setRoot = 0n`, 타입 배열 끝에 `'uint256', 'uint256'`, 값 끝에 `setSel, setRoot`. 주석에 "11워드".
- `parseExecuteReceipt`: `disclosure = { mask: p.args.mask, lo: [...p.args.lo], hi: [...p.args.hi], setSel: p.args.setSel, setRoot: p.args.setRoot }`.
- `deployAttrGate`: 

```js
import { setRoot } from './mode3_set_tree.js';
export const ALLOWED_COUNTRIES_DEFAULT = Object.freeze([410n, 392n, 840n, 276n, 250n]);   // KR·JP·US·DE·FR (ISO 3166 numeric)
export const MIN_AGE_DEFAULT = 19n;
/** 데모 대상 v2(§4.2). root 는 여기서 계산한다 — 하드코딩 금지(lib/mode3_set_tree.js 가 유일한 정의). */
export async function deployAttrGate(signer, { factoryAddress, allowedCountries = ALLOWED_COUNTRIES_DEFAULT, minAge = MIN_AGE_DEFAULT }) {
  const { abi, bytecode } = readArtifact('AttrGate');
  const c = await new ethers.ContractFactory(abi, bytecode, signer).deploy(factoryAddress, await setRoot(allowedCountries), BigInt(minAge));
  await c.waitForDeployment();
  return c.getAddress();
}
```

- [ ] **Step 5: 컴파일·테스트 통과**

Run: `npx hardhat compile 2>&1 | tail -2 && bash scripts/run_tests.sh contract 2>&1 | tail -20`
Expected: 컴파일 성공, `Mode3Wallet`(V7 케이스 포함)·`AttrGate v2`·기존 컨트랙트 테스트 전부 passing. (`test/Mode3Wallet.test.mjs` 의 gas 기록 출력값을 보고서에 적는다 — Task 9 측정에 쓴다.)

- [ ] **Step 6: Commit**

```bash
git add contracts/Mode3Wallet.sol contracts/AttrGate.sol contracts/PiCredVerifier.sol lib/mode3_onchain.js test/Mode3Wallet.test.mjs test/AttrGate.test.mjs
git commit -m "feat(mode3): 온체인 V7 — execute pub[25]·꼬리 11워드·Disclosure(setSel,setRoot), AttrGate v2(집합 root + block.timestamp 나이, yearOf), 검증자 재생성"
```

`build/mode3/` 는 git 밖(.gitignore) — 커밋하지 않는다. 다른 기계는 Task 9 의 문서대로 다시 만든다.

---

### Task 4: 지갑 라이브러리 — `normalizeSet`·`disclosureKey`·`buildCredentialProof`

**Files:**
- Modify: `lib/mode3_wallet.js` (`normalizeDisclosure` 근처, `disclosureKey`, `buildCredentialProof`)
- Modify: `tests/test_mode3_wallet.mjs`

**Interfaces:**
- Consumes: Task 1 `setPath`, `NO_SET`.
- Produces:
  - `export async function normalizeSet(set, attrs) → { sel: bigint, root: bigint, index: number, path: bigint[8] }` — `set` 이 `null/undefined` 면 `NO_SET`.
  - `disclosureKey(d)` = `` `${d.mask}:${d.lo.join(',')}:${d.hi.join(',')}:${d.sel ?? 0n}:${d.root ?? 0n}` ``.
  - `export const hasPredicate = (d) => Boolean(d) && (d.mask !== 0n || (d.sel ?? 0n) !== 0n)`.
  - `buildCredentialProof({ …, disclosure })` 의 `disclosure` 는 `{ mask, lo, hi, sel?, root?, index?, path? }` — set 필드가 없으면 `NO_SET` 로 채운다. 회로 입력에 `set_sel, set_root, set_index, set_path` 를 넣는다. `publicSignals` 25개.

- [ ] **Step 1: 실패하는 테스트**

`tests/test_mode3_wallet.mjs` 의 import 에 `normalizeSet, hasPredicate` 추가(`disclosureKey` 가 없으면 같이). `normalizeDisclosure` 케이스 뒤에:

```js
await t('V7 normalizeSet: 없음 → NO_SET; 소속이면 sel = slot+1·root·경로; 비소속은 disclosure_unsatisfiable; 형식 오류는 bad_disclosure', async () => {
  const attrs = [1990n, 410n, 2n, 0n];
  const none = await normalizeSet(null, attrs);
  assert.deepEqual({ sel: none.sel, root: none.root, index: none.index, path: [...none.path] }, { sel: 0n, root: 0n, index: 0, path: Array(8).fill(0n) });
  const s = await normalizeSet({ slot: 1, members: [410, 392, 840, 276, 250] }, attrs);
  assert.equal(s.sel, 2n); assert.equal(s.index, 3); assert.equal(s.path.length, 8); assert.notEqual(s.root, 0n);
  await assert.rejects(() => normalizeSet({ slot: 1, members: [392, 840] }, attrs), (e) => e.reason === 'disclosure_unsatisfiable');
  for (const bad of [{ slot: 4, members: [1] }, { slot: -1, members: [1] }, { slot: '1', members: [1] }, { slot: 1, members: [] }, { slot: 1 }, { members: [1] }, 'x']) {
    await assert.rejects(() => normalizeSet(bad, attrs), (e) => e.reason === 'bad_disclosure', `허용되면 안 됨: ${JSON.stringify(bad)}`);
  }
});
await t('V7 disclosureKey·hasPredicate: set 이 키에 들어가고, mask 0 이라도 sel ≠ 0 이면 술어가 있다', async () => {
  const attrs = [1990n, 410n, 2n, 0n];
  const base = normalizeDisclosure(null, attrs);
  const withSet = { ...base, ...(await normalizeSet({ slot: 1, members: [410] }, attrs)) };
  assert.notEqual(disclosureKey(base), disclosureKey(withSet));
  assert.equal(hasPredicate(base), false); assert.equal(hasPredicate(withSet), true);
  assert.equal(hasPredicate(normalizeDisclosure([{ lo: '0', hi: '2007' }, null, null, null], attrs)), true);
});
```

그리고 기존 `buildCredentialProof` 를 부르는 케이스(파일에서 `publicSignals.length` 를 단언하는 곳이 있으면 23 → 25) 뒤에:

```js
await t('V7 buildCredentialProof: set 을 주면 publicSignals[23] = sel, [24] = root; 안 주면 0·0 — 25개', async () => {
  // 이 파일의 기존 증명 픽스처(등록·C_u·세션 발급을 거쳐 buildCredentialProof 를 부르는 헬퍼)를 그대로 쓰되 disclosure 에 set 을 섞는다.
  const attrs = [1990n, 410n, 2n, 0n];
  const st = await normalizeSet({ slot: 1, members: [410, 392] }, attrs);
  const built = await proveWith({ mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n], ...st });   // proveWith = 이 파일의 증명 헬퍼(없으면 기존 케이스의 buildCredentialProof 호출을 함수로 뽑는다)
  assert.equal(built.publicSignals.length, 25);
  assert.equal(built.publicSignals[23], '2'); assert.equal(built.publicSignals[24], st.root.toString());
  const plain = await proveWith(null);
  assert.equal(plain.publicSignals[23], '0'); assert.equal(plain.publicSignals[24], '0');
});
```

(`proveWith(disclosure)` 는 파일 안에서 이미 `buildCredentialProof` 를 부르는 케이스의 준비 코드를 함수로 추출해 만든다 — 픽스처 값은 그 케이스 것을 그대로 쓴다.)

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_wallet.mjs 2>&1 | grep -E "FAIL|SyntaxError" | head`
Expected: `normalizeSet` 없음으로 실패.

- [ ] **Step 3: 구현**

`lib/mode3_wallet.js`:
- import 추가: `import { setPath, NO_SET } from './mode3_set_tree.js';`
- `normalizeDisclosure` 뒤에:

```js
/**
 * V7(2026-09-23 §5.1) — 요청의 set({ slot, members }) 를 회로 입력 { sel, root, index, path } 로. root 는 여기서 members 로부터 계산한다 —
 * 서비스가 준 root 를 믿지 않는다(증명하는 사실은 항상 "내 속성 ∈ 내가 받은 members"). 없으면 NO_SET.
 */
export async function normalizeSet(set, attrs) {
  const fail = (reason, msg) => Object.assign(new Error(msg ?? reason), { reason });
  if (set === undefined || set === null) return NO_SET;
  if (typeof set !== 'object' || Array.isArray(set)) throw fail('bad_disclosure', 'set 은 { slot, members } 객체');
  const { slot, members } = set;
  if (!Number.isInteger(slot) || slot < 0 || slot > 3) throw fail('bad_disclosure', 'set.slot 은 정수 0..3');
  const { index, path, root } = await setPath(members, attrs[slot]);   // bad_disclosure / disclosure_unsatisfiable 를 그대로 올린다
  return { sel: BigInt(slot) + 1n, root, index, path };
}

/** 술어가 하나라도 있으면(범위 또는 집합) 캐시 π 를 못 쓰고 새로 증명한다. */
export const hasPredicate = (d) => Boolean(d) && (d.mask !== 0n || (d.sel ?? 0n) !== 0n);
```

- `disclosureKey`: `export const disclosureKey = (d) => \`${d.mask}:${d.lo.join(',')}:${d.hi.join(',')}:${d.sel ?? 0n}:${d.root ?? 0n}\`;`
- `buildCredentialProof`: 주석의 "(23개…)" → "(25개, V7 §3.3: [23] set_sel [24] set_root)". `const disc = …` 뒤에 `const st = { sel: disc.sel ?? NO_SET.sel, root: disc.root ?? NO_SET.root, index: disc.index ?? 0, path: disc.path ?? NO_SET.path };` 그리고 input 끝에 `set_sel: st.sel.toString(), set_root: st.root.toString(), set_index: String(st.index), set_path: [...st.path].map(String),`.

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_wallet.mjs 2>&1 | tail -6`
Expected: 전부 ok (이 파일은 `chain` 그룹 — :8545 노드가 필요하면 `npx hardhat node` 를 백그라운드로 띄우고 끝나면 내린다).

- [ ] **Step 5: Commit**

```bash
git add lib/mode3_wallet.js tests/test_mode3_wallet.mjs
git commit -m "feat(mode3): 지갑 라이브러리 V7 — normalizeSet(에이전트가 root 계산), hasPredicate, 캐시 키·회로 입력에 set"
```

---

### Task 5: 트랜잭션 경로 — 에이전트 `set`, Snap 동의 창, 지갑 폼

**Files:**
- Modify: `mode3_wallet_agent.js` (`buildExecute`, `discStrings`, `proveSession` 의 discKey 조건, `/wallet/tx/record` 의 pub 재구성)
- Modify: `snap-mode3/src/index.js` (`consentDisclosure`), 빌드 `snap-mode3/dist/*`·`snap-mode3/snap.manifest.json`
- Modify: `mode3/wallet.html` (폼·`readDisclose`·`txForm`·결과 표시)
- Modify: `snap-mode3/test/rpc.test.mjs`, `tests/test_mode3_wallet_agent.mjs`

**Interfaces:**
- Consumes: Task 4 `normalizeSet`, `hasPredicate`, `disclosureKey`; Task 3 `payloadDigest(setSel, setRoot)`, `parseExecuteReceipt`.
- Produces:
  - `POST /wallet/tx`·`/wallet/tx/prepare` 본문에 선택 필드 `set: { slot, members }`. 응답 `disclosure`·`onchainDisclosure` 는 `{ mask, lo, hi, set: { sel, root } | null } | null`.
  - Snap `consentDisclosure` params 에 `set: { slot, members } | null`.

- [ ] **Step 1: 실패하는 테스트**

`snap-mode3/test/rpc.test.mjs` 의 `consentDisclosure` 케이스 뒤에:

```js
await t('consentDisclosure(V7): set 이 있으면 "a₁(국가) ∈ {…} (N개)" 줄, 33개 이상이면 앞 8개 + "외 N개"', async () => {
  answers.push(true);
  const base = { arid: '777', origin: RP_ORIGIN, disclose: [null, null, null, null], to: '0x1111111111111111111111111111111111111111', value: '0' };
  assert.deepEqual(await call('consentDisclosure', { ...base, set: { slot: 1, members: [410, 392, 840, 276, 250] } }), { ok: true });
  let d = lastDialogText();
  for (const part of ['a₁', '국가', '∈', '410', '250', '(5개)']) assert.ok(d.includes(part), `대화상자에 ${part} 가 없다`);
  answers.push(true);
  await call('consentDisclosure', { ...base, set: { slot: 2, members: Array.from({ length: 40 }, (_, i) => i + 1) } });
  d = lastDialogText();
  assert.ok(d.includes('… 외 32개') && d.includes('a₂') && !d.includes(' 40,') , d);
});
```

`tests/test_mode3_wallet_agent.mjs`: 이 파일의 `/wallet/tx` 케이스(선택 공개를 보내는 것) 옆에 다음을 추가 — 로그인 헬퍼·세션 r_s 는 파일의 기존 케이스와 같은 것을 쓴다:

```js
await t('V7 /wallet/tx: set 으로 국가 ∈ 집합을 증명하면 onchainDisclosure.set 이 sel 2·root 로 남는다; 비소속 집합은 400 disclosure_unsatisfiable; slot 4 는 bad_disclosure', async () => {
  const { r_s } = await loginTestuser();   // 파일의 기존 로그인 헬퍼 이름으로 맞춘다
  const members = [410, 392, 840, 276, 250];
  const ok = await wallet.post('/wallet/tx', { r_s, to: '0x000000000000000000000000000000000000dEaD', disclose: [null, null, null, null], set: { slot: 1, members } }, { Origin: rpOrigin });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(ok.body.onchainDisclosure.mask, '0');
  assert.equal(ok.body.onchainDisclosure.set.sel, '2');
  assert.equal(ok.body.onchainDisclosure.set.root, (await setRoot(members)).toString());
  const miss = await wallet.post('/wallet/tx', { r_s, to: '0x000000000000000000000000000000000000dEaD', set: { slot: 1, members: [392, 840] } }, { Origin: rpOrigin });
  assert.equal(miss.status, 400); assert.equal(miss.body.reason, 'disclosure_unsatisfiable');
  const bad = await wallet.post('/wallet/tx', { r_s, to: '0x000000000000000000000000000000000000dEaD', set: { slot: 4, members } }, { Origin: rpOrigin });
  assert.equal(bad.status, 400); assert.equal(bad.body.reason, 'bad_disclosure');
});
```

(`import { setRoot } from '../lib/mode3_set_tree.js';` 추가. `/wallet/tx/record` 를 시험하는 케이스가 있으면 재구성된 disclosure 에 `set` 이 있는지 한 줄 단언 추가.)

- [ ] **Step 2: 실패 확인**

Run: `cd snap-mode3 && npm test 2>&1 | grep -E "FAIL|ok " | tail -4; cd ..`
Expected: V7 consentDisclosure 케이스 FAIL.

- [ ] **Step 3: 에이전트 구현**

`mode3_wallet_agent.js`:
- import 에 `normalizeSet, hasPredicate` 추가(`lib/mode3_wallet.js`).
- `buildExecute`: `const { r_s, to, value = '0', data = '0x', disclose, set = null } = req.body ?? {};` 그리고

```js
  let disclosure;
  try {
    const attrs = (state.registration.attrs ?? []).map(BigInt);
    disclosure = { ...normalizeDisclosure(disclose, attrs), ...(await normalizeSet(set, attrs)) };   // V7: 범위 + 집합
  } catch (e) { if (e.reason) return fail(400, { reason: e.reason, detail: e.message }); throw e; }
```

  `signPayload(…, { …, discMask: disclosure.mask, discLo: disclosure.lo, discHi: disclosure.hi, setSel: disclosure.sel, setRoot: disclosure.root })`.
- `proveSession`: `const discKey = hasPredicate(disclosure) ? disclosureKey(disclosure) : '0';`
- `discStrings`: `const discStrings = (d) => (d ? { mask: d.mask.toString(), lo: d.lo.map(String), hi: d.hi.map(String), set: (d.sel ?? d.setSel ?? 0n) !== 0n ? { sel: (d.sel ?? d.setSel).toString(), root: (d.root ?? d.setRoot).toString() } : null } : null);`
- `receiptResult`·`/wallet/tx/prepare` 의 `disclosure.mask !== 0n ? … : null` → `hasPredicate(disclosure) ? discStrings(disclosure) : null`.
- `/wallet/tx/record` 의 재구성: `disclosure = { mask: pub[14], lo: pub.slice(15, 19), hi: pub.slice(19, 23), sel: pub[23], root: pub[24] };`

`snap-mode3/src/index.js` `consentDisclosure`:

```js
      const { arid, origin: rpOrigin, disclose, to, value, set } = params;
      …(기존 lines 루프)…
      // V7 집합 소속: 에이전트가 members 로부터 root 를 계산해 증명에 넣는다 — 여기서는 사용자에게 원소를 보여 준다(root 검산은 에이전트 몫, 스펙 §5.2).
      if (set && Number.isInteger(set.slot) && set.slot >= 0 && set.slot <= 3 && Array.isArray(set.members)) {
        const ms = set.members.map(String);
        const shown = ms.length > 32 ? `${ms.slice(0, 8).join(', ')} … 외 ${ms.length - 8}개` : ms.join(', ');
        lines.push(`${SLOT_NAMES[set.slot]}(${SLOT_LABELS[set.slot]}) ∈ {${shown}} (${ms.length}개)`);
      }
```

`if (lines.length === 0) …` 는 그 뒤에 그대로.

빌드: `cd snap-mode3 && npm run build && cd ..` → `dist/bundle.js`·`snap.manifest.json`(shasum) 갱신.

`mode3/wallet.html`:
- `discloseRows` 아래에 추가:

```html
    <div id="setRow">
      집합 소속(V7): 슬롯 <select id="setSlot"><option value="">없음</option><option value="0">슬롯0</option><option value="1" selected>슬롯1(국가)</option><option value="2">슬롯2</option><option value="3">슬롯3</option></select>
      원소 <input id="setMembers" value="410,392,840,276,250" size="28" />
      <button id="ageBtn" type="button">나이 ≥ <input id="minAgeIn" value="19" size="3" /> 증명(슬롯0 hi = 올해 − N)</button>
    </div>
```

- 스크립트: `readSet = () => { const s = $('setSlot').value; if (s === '') return null; return { slot: Number(s), members: $('setMembers').value.split(',').map((x) => x.trim()).filter(Boolean) }; }`, `txForm` 에 `set: readSet()` 추가. `ageBtn` 클릭: `$('dk0').checked = true; $('discLo0').value = '0'; $('discHi0').value = String(new Date().getUTCFullYear() - Number($('minAgeIn').value || 19));`. Snap 경로 `invokeSnap('consentDisclosure', { …, set: f.set })`. `showTxResult` 는 이미 JSON 전체를 찍으므로 그대로.
- 안내 문단(`선택 공개(2026-09-22 §4.2)…`)에 한 문장: "집합 소속(V7)은 슬롯 하나만 — 지갑이 원소 목록으로 root 를 계산해 증명에 넣는다. 나이는 연 단위(올해 − 출생연도)."

- [ ] **Step 4: 통과 확인**

Run: `cd snap-mode3 && npm test 2>&1 | tail -3; cd .. && node tests/test_mode3_wallet_agent.mjs 2>&1 | tail -5`
Expected: 둘 다 전부 ok(에이전트 테스트는 chain 그룹 — :8545 필요).

- [ ] **Step 5: Commit**

```bash
git add mode3_wallet_agent.js mode3/wallet.html snap-mode3/src/index.js snap-mode3/dist snap-mode3/snap.manifest.json snap-mode3/test/rpc.test.mjs tests/test_mode3_wallet_agent.mjs
git commit -m "feat(mode3): 트랜잭션 경로 V7 — /wallet/tx·prepare 의 set(에이전트가 root 계산), Snap 동의 창에 집합 원소, 지갑 폼(집합·나이 ≥ N 버튼)"
```

---

### Task 6: 서비스(RP)·CIA — 25개 파싱, 정책 env, AttrGate v2 배포, `predicates`

**Files:**
- Modify: `lib/mode3_rp.js` (`verifyLogin`, `maskDisclosure`)
- Modify: `mode3_rp.js` (env, `ensureAttrGate`, `discOf`, `rp_info`)
- Modify: `mode3/rp.html:90-92` (정책 문구), `mode3/rp.html:117` (`discOf` 표시)
- Modify: `cia.js:612-613` (길이 25)
- Modify: `tests/test_mode3_rp.mjs`

**Interfaces:**
- Consumes: Task 3 `deployAttrGate({ allowedCountries, minAge })`, `ALLOWED_COUNTRIES_DEFAULT`, `MIN_AGE_DEFAULT`; Task 1 `setRoot`.
- Produces:
  - `verifyLogin` 의 `disclosure = { mask, lo, hi, sel, root }`(bigint); 사유 `bad_disclosure` 에 `sel > 4`, `sel = 0 ∧ root ≠ 0` 추가.
  - `maskDisclosure({ mask, lo, hi, sel = 0n, root = 0n })` → `sel = 0` 이면 `root = 0`.
  - `GET /api/mode3/rp_info` 에 `predicates: { allowedCountries: string[], allowedCountriesRoot: string, minAge: string }`.
  - RP env `MODE3_ALLOWED_COUNTRIES`, `MODE3_MIN_AGE`; 등록 파일 `reg.attrGatePolicy = { root, minAge }`.

- [ ] **Step 1: 실패하는 테스트**

`tests/test_mode3_rp.mjs` 의 `V6: publicSignals 가 14개면 malformed…` 케이스를 V7 로 고친다(`23` → `25`, `slice(0, 14)` 그대로, 이름 `V7: … 25개면 통과 …`). 그 뒤에:

```js
await t('V7: set_sel/set_root 가 disclosure 에 실린다; sel 5·(sel 0, root ≠ 0) 은 bad_disclosure; maskDisclosure 는 sel 0 이면 root 를 지운다', async () => {
  const members = [410, 392, 840, 276, 250];
  const st = await normalizeSet({ slot: 1, members }, attrs);   // attrs = 이 파일의 testuser 속성 [1990n, 410n, 2n, 0n]
  const good = await login({ mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n], ...st });   // login(disclosure) = 파일의 로그인 픽스처 헬퍼
  const v = await rp.verifyLogin(good);
  assert.equal(v.ok, true, v.reason);
  assert.equal(v.disclosure.sel, 2n); assert.equal(v.disclosure.root, await setRoot(members));
  const ps = [...good.publicSignals]; ps[23] = '5';
  assert.equal((await rp.verifyLogin({ ...good, publicSignals: ps })).reason, 'bad_disclosure');
  const plain = await login(null);
  const ps2 = [...plain.publicSignals]; ps2[24] = '7';
  assert.equal((await rp.verifyLogin({ ...plain, publicSignals: ps2 })).reason, 'bad_disclosure');
  assert.deepEqual(maskDisclosure({ mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n], sel: 0n, root: 9n }).root, 0n);
  assert.deepEqual(maskDisclosure({ mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n] }), { mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n], sel: 0n, root: 0n });
});
```

(`import { normalizeSet } from '../lib/mode3_wallet.js'; import { setRoot } from '../lib/mode3_set_tree.js';` 추가.)

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_rp.mjs 2>&1 | grep -E "FAIL|ok " | tail -5`
Expected: V7 케이스 FAIL(`malformed` — 25개를 거절).

- [ ] **Step 3: 구현**

`lib/mode3_rp.js` `verifyLogin`:
- 길이 검사 `!== 23` → `!== 25`.
- 구조 분해: `const [PPID, aridIn, pk_i, max_height, chainIn, allowAgent, revRoot, ciaX, ciaY, traceX, traceY, c1x, c1y, c2, discMask, lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3, setSel, setRoot] = ps;` `const disclosure = maskDisclosure({ mask: discMask, lo: [lo0, lo1, lo2, lo3], hi: [hi0, hi1, hi2, hi3], sel: setSel, root: setRoot });`
- `if (discMask >= 16n) …` 뒤: `if (setSel > 4n || (setSel === 0n && setRoot !== 0n)) return { ok: false, reason: 'bad_disclosure' };   // V7 — 회로도 막지만 세션·로그에 남는 값이라 한 번 더`

`maskDisclosure`:

```js
export function maskDisclosure({ mask, lo, hi, sel = 0n, root = 0n }) {
  … (기존 검사·keep) …
  const s = BigInt(sel);
  return { mask: m, lo: keep(lo), hi: keep(hi), sel: s, root: s === 0n ? 0n : BigInt(root) };   // V7: sel 0 이면 root 는 무시되는 값 — 지운다
}
```

`mode3_rp.js`:
- import 에 `ALLOWED_COUNTRIES_DEFAULT, MIN_AGE_DEFAULT` (`./lib/mode3_onchain.js`), `setRoot` (`./lib/mode3_set_tree.js`).
- env(`MAX_LIFETIME` 줄 근처):

```js
// V7 술어 정책(설계 2026-09-23 §4.3·§6): AttrGate 배포와 오프체인 로그인 정책이 같은 값을 쓴다.
const ALLOWED_COUNTRIES = (process.env.MODE3_ALLOWED_COUNTRIES ?? '').split(',').map((s) => s.trim()).filter(Boolean).map(BigInt);
const ALLOWED_COUNTRIES_EFFECTIVE = ALLOWED_COUNTRIES.length ? ALLOWED_COUNTRIES : [...ALLOWED_COUNTRIES_DEFAULT];
const MIN_AGE = BigInt(process.env.MODE3_MIN_AGE || MIN_AGE_DEFAULT);
const ALLOWED_COUNTRIES_ROOT = await setRoot(ALLOWED_COUNTRIES_EFFECTIVE);
```

- `ensureAttrGate`: 재배포 판정을 `if (reg.attrGateAddress && reg.attrGateFactory === reg.factoryAddress && reg.attrGatePolicy?.root === ALLOWED_COUNTRIES_ROOT.toString() && reg.attrGatePolicy?.minAge === MIN_AGE.toString()) return;` 로, 배포를 `deployAttrGate(signer, { factoryAddress: reg.factoryAddress, allowedCountries: ALLOWED_COUNTRIES_EFFECTIVE, minAge: MIN_AGE })`, 저장을 `reg = { ...reg, attrGateAddress, attrGateFactory: reg.factoryAddress, attrGatePolicy: { root: ALLOWED_COUNTRIES_ROOT.toString(), minAge: MIN_AGE.toString() } };`. 주석의 "국가=410, 출생연도≤2007 고정" → "국가 ∈ MODE3_ALLOWED_COUNTRIES, 올해 − 출생연도 ≥ MODE3_MIN_AGE".
- `discOf`: `const discOf = (d) => ({ mask: d.mask.toString(), lo: d.lo.map(String), hi: d.hi.map(String), set: d.sel !== 0n ? { sel: d.sel.toString(), root: d.root.toString() } : null });`
- `rp_info` 응답에 `predicates: { allowedCountries: ALLOWED_COUNTRIES_EFFECTIVE.map(String), allowedCountriesRoot: ALLOWED_COUNTRIES_ROOT.toString(), minAge: MIN_AGE.toString() }`.

`mode3/rp.html:91`: `` `AttrGate=${info.attrGateAddress}   정책: 국가(a₁) ∈ {${info.predicates.allowedCountries.join(', ')}}, 올해 − 출생연도(a₀) ≥ ${info.predicates.minAge}` ``. `:117` 의 `discOf` 표시에 `${l.disclosure.set ? ` set(sel=${l.disclosure.set.sel}, root=${l.disclosure.set.root.slice(0, 10)}…)` : ''}` 를 덧붙이고, 조건을 `l.disclosure && (l.disclosure.mask !== '0' || l.disclosure.set)` 로.

`cia.js:612-613`: `publicSignals.length !== 23` → `25`, 오류 문자열 `publicSignals[23]` → `publicSignals[25]`. 주석 한 줄: `// V7(2026-09-23): 공개 입력 25개 — 태그 위치([11..13])는 그대로라 개봉 로직은 바뀌지 않는다.`

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_rp.mjs 2>&1 | tail -5`
Expected: 전부 ok.

- [ ] **Step 5: Commit**

```bash
git add lib/mode3_rp.js mode3_rp.js mode3/rp.html cia.js tests/test_mode3_rp.mjs
git commit -m "feat(mode3): 서비스 V7 — verifyLogin 25개·set 파싱, 정책 env(MODE3_ALLOWED_COUNTRIES·MODE3_MIN_AGE)로 AttrGate v2 배포, rp_info.predicates; CIA 개봉 길이 25"
```

---

### Task 7: 로그인 경로 술어 — 지갑 `/wallet/login` 의 `disclose`·`set`, 팝업·Snap 동의, RP 요구

**Files:**
- Modify: `mode3_wallet_agent.js` (`/wallet/login` 본문·`proveSession` 호출)
- Modify: `mode3/wallet.html` (팝업 `onMessage` 의 `/wallet/login` 본문, `consentLogin(req)` 인자)
- Modify: `snap-mode3/src/index.js` (`consentLogin` 에 술어 줄), 빌드 dist
- Modify: `mode3/rp.html` (체크박스, `authorizeRequest`/`/wallet/login` 본문, `/api/mode3/login` 본문)
- Modify: `mode3_rp.js` (`/api/mode3/login` 의 `require` 검사)
- Modify: `tests/test_mode3_demo_stack.mjs` (새 케이스), `snap-mode3/test/rpc.test.mjs`

**Interfaces:**
- Consumes: Task 4·5·6.
- Produces:
  - `POST /wallet/login` 선택 필드 `disclose`(길이 4)·`set`; 응답의 `disclosure` 는 `/wallet/tx` 와 같은 형식.
  - Snap `consentLogin` params 에 `disclose`, `set`(선택) — 대화상자에 `consentDisclosure` 와 같은 줄.
  - `POST /api/mode3/login` 본문 선택 필드 `require: { countrySet?: boolean, minAge?: boolean }` — 미충족이면 `{ ok: false, reason: 'predicate_unmet' }`.

- [ ] **Step 1: 실패하는 테스트**

`tests/test_mode3_demo_stack.mjs` 의 `12. …` 케이스 앞에(번호는 파일 흐름에 맞춘다):

```js
  await t('V7 로그인 술어: require.countrySet+minAge 를 만족하는 로그인은 ok·세션에 set; 술어 없이 보내면 predicate_unmet', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const year = new Date().getUTCFullYear();
    const disclose = [{ lo: '0', hi: String(year - Number(info.predicates.minAge)) }, null, null, null];
    const set = { slot: 1, members: info.predicates.allowedCountries };
    const ch = (await rp.post('/api/mode3/challenge')).body;
    const w = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, allowAgent: '0', factoryAddress: ch.factoryAddress, attrGateAddress: ch.attrGateAddress, disclose, set }, { Origin: rp.origin });
    assert.equal(w.status, 200, j(w.body));
    assert.equal(w.body.disclosure.set.sel, '2');
    const r = await rp.post('/api/mode3/login', { r_s: ch.r_s, proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, require: { countrySet: true, minAge: true } });
    assert.equal(r.body.ok, true, j(r.body));
    assert.equal(r.body.disclosure.set.root, info.predicates.allowedCountriesRoot);
    // 술어 없는 성명 + require → predicate_unmet
    const ch2 = (await rp.post('/api/mode3/challenge')).body;
    const w2 = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch2.r_s, allowAgent: '0', factoryAddress: ch2.factoryAddress, attrGateAddress: ch2.attrGateAddress }, { Origin: rp.origin });
    assert.equal(w2.status, 200, j(w2.body));
    const r2 = await rp.post('/api/mode3/login', { r_s: ch2.r_s, proof: w2.body.proof, publicSignals: w2.body.publicSignals, sig: w2.body.sig, require: { countrySet: true } });
    assert.deepEqual(r2.body, { ok: false, reason: 'predicate_unmet' });
  });
```

(응답 필드명 `proof`·`publicSignals`·`sig` 는 파일의 `loginViaRp` 헬퍼가 쓰는 이름과 맞춘다.)

`snap-mode3/test/rpc.test.mjs` `consentLogin` 케이스 옆에:

```js
await t('consentLogin(V7): disclose·set 이 있으면 공개 줄이 보인다', async () => {
  answers.push(true);
  await call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '0', serviceName: '데모 RP', disclose: [{ lo: '0', hi: '2007' }, null, null, null], set: { slot: 1, members: [410, 392] } });
  const d = lastDialogText();
  for (const part of ['a₀', '2007', 'a₁', '∈', '410', '(2개)']) assert.ok(d.includes(part), `대화상자에 ${part} 가 없다`);
});
```

- [ ] **Step 2: 실패 확인**

Run: `cd snap-mode3 && npm test 2>&1 | grep FAIL; cd ..`
Expected: consentLogin(V7) FAIL(줄이 없다).

- [ ] **Step 3: 구현**

`snap-mode3/src/index.js`: 술어 줄 생성을 함수로 뽑는다(파일 상단 헬퍼 영역):

```js
/** 공개 술어를 대화상자 줄로(V6 범위 + V7 집합). consentLogin·consentDisclosure 가 같이 쓴다. */
function predicateLines(disclose, set) {
  const lines = [];
  const slots = Array.isArray(disclose) ? disclose : [];
  for (let i = 0; i < 4; i++) { const d = slots[i]; if (d) lines.push(`${SLOT_NAMES[i]}(${SLOT_LABELS[i]}) ∈ [${d.lo}, ${d.hi}]`); }
  if (set && Number.isInteger(set.slot) && set.slot >= 0 && set.slot <= 3 && Array.isArray(set.members)) {
    const ms = set.members.map(String);
    const shown = ms.length > 32 ? `${ms.slice(0, 8).join(', ')} … 외 ${ms.length - 8}개` : ms.join(', ');
    lines.push(`${SLOT_NAMES[set.slot]}(${SLOT_LABELS[set.slot]}) ∈ {${shown}} (${ms.length}개)`);
  }
  return lines;
}
```

`consentDisclosure` 는 이 함수를 쓰도록 바꾸고(Task 5 의 인라인 코드 대체), `consentLogin` 은 `const { origin: rpOrigin, arid, allowAgent, serviceName, disclose, set } = params;` 와 `const pred = predicateLines(disclose, set);` 뒤 대화상자 배열의 `AI 에이전트 허용` 줄 다음에 `...(pred.length ? [null, '공개할 속성:', ...pred] : [])`. 빌드 `cd snap-mode3 && npm run build`.

`mode3_wallet_agent.js` `/wallet/login`: 본문에 `disclose = null, set = null` 추가. `if (state.sessions[rs.toString()]) …` 뒤에

```js
    // V7: 로그인 성명에도 술어를 실을 수 있다(스펙 §6). 형식·불만족은 체인 작업 전에 걸러낸다.
    let disclosure = null;
    if (disclose || set) {
      try { const attrs = (state.registration.attrs ?? []).map(BigInt); disclosure = { ...normalizeDisclosure(disclose, attrs), ...(await normalizeSet(set, attrs)) }; }
      catch (e) { if (e.reason) return res.status(400).json({ reason: e.reason, detail: e.message }); throw e; }
    }
```

`proveSession(rs.toString(), synced, timings, disclosure, src)`. 응답에 `disclosure: hasPredicate(disclosure) ? discStrings(disclosure) : null` 추가(`out` 에 같은 키가 없으면).

`mode3/wallet.html` 팝업: `consentLogin(req)` 가 `req.disclose`·`req.set` 을 Snap 에 넘기도록(`consentLogin` 헬퍼의 params 조립에 `disclose: req.disclose ?? null, set: req.set ?? null`), `/wallet/login` 본문에 `disclose: req.disclose ?? null, set: req.set ?? null`.

`mode3/rp.html`: `allowAgent` 체크박스 아래에 `<label><input type="checkbox" id="requirePred" /> 속성 술어 요구(V7): 국가 ∈ 허용 집합, 올해 − 출생연도 ≥ minAge</label><br />`. 로그인 흐름에서:

```js
        const pred = $('requirePred').checked ? {
          disclose: [{ lo: '0', hi: String(new Date().getUTCFullYear() - Number(info.predicates.minAge)) }, null, null, null],
          set: { slot: 1, members: info.predicates.allowedCountries },
          require: { countrySet: true, minAge: true },
        } : null;
```

file 모드 `/wallet/login` 본문과 `authorizeRequest({ …, disclose: pred?.disclose ?? null, set: pred?.set ?? null })` 에 전달하고, `/api/mode3/login` 본문에 `require: pred?.require ?? null`.

`mode3_rp.js` `/api/mode3/login`: `if (!v.ok) return …` 뒤에

```js
    // V7 술어 요구(스펙 §6): 페이지가 요구한 술어를 성명이 만족하는지. 오프체인 나이는 UTC 연 단위.
    const requireP = req.body.require ?? null;
    if (requireP && typeof requireP === 'object') {
      const d = v.disclosure;
      if (requireP.countrySet && !(d.sel === 2n && d.root === ALLOWED_COUNTRIES_ROOT)) return res.json({ ok: false, reason: 'predicate_unmet' });
      if (requireP.minAge && !(((d.mask & 1n) === 1n) && d.hi[0] + MIN_AGE <= BigInt(new Date().getUTCFullYear()))) return res.json({ ok: false, reason: 'predicate_unmet' });
    }
```

- [ ] **Step 4: 통과 확인**

Run: `cd snap-mode3 && npm test 2>&1 | tail -2; cd .. && node tests/test_mode3_demo_stack.mjs 2>&1 | tail -8`
Expected: 전부 ok(데모 스택 테스트는 격리 스택 — :8545 필요; 기존 10·11 케이스는 Task 8 에서 V7 로 바뀌기 전까지 실패할 수 있다 — 이 Task 에서는 새 케이스와 Snap 테스트만 통과하면 된다. 10·11 이 실패하면 보고서에 적는다).

- [ ] **Step 5: Commit**

```bash
git add mode3_wallet_agent.js mode3/wallet.html mode3/rp.html mode3_rp.js snap-mode3/src/index.js snap-mode3/dist snap-mode3/snap.manifest.json snap-mode3/test/rpc.test.mjs tests/test_mode3_demo_stack.mjs
git commit -m "feat(mode3): 로그인 경로 술어(V7) — /wallet/login 의 disclose·set, Snap consentLogin 공개 줄, RP 페이지 요구 체크박스와 /api/mode3/login require(predicate_unmet)"
```

---

### Task 8: 데모 스택·E2E·벤치 V7 시나리오

**Files:**
- Modify: `tests/test_mode3_demo_stack.mjs` (케이스 10·11, alice `tx` 헬퍼)
- Modify: `tests/helpers/isolated_mode3_stack.mjs:17-20` (`PINNED_ENV` 에 `MODE3_ALLOWED_COUNTRIES: '', MODE3_MIN_AGE: ''`)
- Modify: `tests/test_mode3_e2e.mjs` (execute 를 직접 만드는 곳이 있으면 `signPayload` 의 setSel/setRoot 기본값으로 충분 — 25개 단언이 있으면 갱신)
- Modify: `scripts/bench_mode3_onchain.mjs` (5번 항목 + 집합 항목)

- [ ] **Step 1: 테스트 갱신(먼저 실패)**

`tests/test_mode3_demo_stack.mjs`:
- alice `tx(to, data, disclose, set = null)`: `disclosure = { ...normalizeDisclosure(disclose, attrs), ...(await normalizeSet(set, attrs)) }`(import `normalizeSet`), `signPayload(…, { …, setSel: disclosure.sel, setRoot: disclosure.root })`, 반환 `onchainDisclosure` 에 `set` 포함(`discStrings` 와 같은 형식).
- 케이스 10 을 V7 로: 

```js
    const year = new Date().getUTCFullYear();
    const disclose = [{ lo: '0', hi: String(year - Number(info.predicates.minAge)) }, null, null, null];
    const set = { slot: 1, members: info.predicates.allowedCountries };
    const tx = await wallet.post('/wallet/tx', { r_s: s.r_s, to: info.attrGateAddress, data: '0x4e71d92d', disclose, set }, { Origin: rp.origin });
    assert.equal(tx.body.ok, true, j(tx.body));
    assert.equal(tx.body.onchainDisclosure.mask, '1');
    assert.equal(tx.body.onchainDisclosure.set.root, info.predicates.allowedCountriesRoot);
```

  (제목: `10. V7 술어: testuser 가 나이 ≥ minAge(올해 − 출생연도) + 국가 ∈ 허용 집합으로 AttrGate.claim → Claimed; 두 번째는 already claimed`.)
- 케이스 11 을 V7 로: alice(2005, 840) — 840 은 허용 집합 안이라 **root 불일치**로 시험한다: `alice.tx(gate, claim, disclose, { slot: 1, members: [840, 392] })` → `ok === false`(country revert); 허용 집합에서 840 을 뺀 `{ slot: 1, members: info.predicates.allowedCountries.filter((c) => c !== '840') }` → 400 `disclosure_unsatisfiable`; 나이: `[{ lo: '0', hi: String(year - 19) }, …]` 는 2005 ≤ year−19 이면 통과, `minAge` 를 못 맞추는 케이스는 `hi[0] = String(year - 5)`(정책보다 넓은 구간) 로 보내 `ok === false`(age revert).

`scripts/bench_mode3_onchain.mjs`: 5번 루프의 `disclose` 를 `[{ lo: '0', hi: String(1990 + i) }, null, null, null]` 로, 요청에 `set: { slot: 1, members: [410, 392, 840, 276, 250] }` 추가, `deployAttrGate(signer, { factoryAddress })`(기본 정책 = 같은 집합·19). 결과 표에 항목 이름 `/wallet/tx 왕복(mask=1 + set, 새 π + AttrGate.claim, N회)`. 추가로 **집합만**(mask 0, set 만, to = dEaD, 캐시 없음) 한 항목을 6번으로 넣어 gas 를 잰다(V6 대비 공개 입력 +2 의 비용).

- [ ] **Step 2: 실행**

Run(:8545 노드 필요 — 없으면 `npx hardhat node` 를 백그라운드로 띄우고 끝나면 내린다): `node tests/test_mode3_demo_stack.mjs 2>&1 | tail -12 && node tests/test_mode3_e2e.mjs 2>&1 | tail -4`
Expected: 전부 ok.

- [ ] **Step 3: Commit**

```bash
git add tests/test_mode3_demo_stack.mjs tests/helpers/isolated_mode3_stack.mjs tests/test_mode3_e2e.mjs scripts/bench_mode3_onchain.mjs
git commit -m "test(mode3): 데모 스택·벤치를 V7 술어 시나리오로(나이 ≥ minAge + 국가 ∈ 집합, root 불일치·비소속·나이 미달), 격리 스택 env"
```

---

### Task 9: 측정·문서·spec 정정

**Files:**
- Create: `results/mode3_predicates_20260923.md`
- Modify: `docs/MODE3_DEMO.md` (0단계 V7 주의, env 두 줄, "트랜잭션의 선택 공개"·"AttrGate" 문단, 엔드포인트 표의 `disclosure` 형식)
- Modify: `docs/superpowers/specs/2026-09-23-mode3-predicates-design.md` §1 표의 "CIA | 변경 없음" → "CIA | 개봉 API 의 공개 입력 길이 검사만 23 → 25(태그 위치 불변)"
- Modify: `scripts/run_tests.sh` 머리 주석(contract 그룹이 V7 zkey 를 요구한다는 줄이 있으면 갱신)

- [ ] **Step 1: 측정**

Run: `node scripts/bench_pi_cred.mjs pot21_final.ptau 2>&1 | tail -8` (제약 수·증명/검증 ms, N=10) 와 `node scripts/bench_mode3_onchain.mjs 2>&1 | tail -20` (:8545 필요).
결과를 `results/mode3_predicates_20260923.md` 에 표로: 제약 수(V6 25,369 → V7 실측), π_rp 증명/검증 ms, execute gas(공개 0 / 범위만 / 집합만 / 범위+집합), AttrGate.claim gas, 계정 배포 gas. 머리에 측정 환경(`results/mode3_rcl_sync_20260923.md` 와 같은 형식)과 명령.

- [ ] **Step 2: 문서**

`docs/MODE3_DEMO.md`:
- 0단계 목록에 `회로 V7(2026-09-23, 집합 소속)로 build/mode3 를 다시 만들었다 — 다른 기계의 build/mode3 도 다시 복사. 팩토리·AttrGate 재배포 필요(V6 증명과 호환 없음).`
- 선택 env 문단에 `MODE3_ALLOWED_COUNTRIES`(쉼표 구분 ISO 3166 numeric, 기본 `410,392,840,276,250`)·`MODE3_MIN_AGE`(기본 19) 한 줄.
- "트랜잭션의 선택 공개" 문단 끝에: `set: { slot, members }`(선택, 슬롯 하나) — 지갑이 members 로 root 를 계산해 `set_sel`·`set_root`(공개 입력 [23],[24]) 에 넣는다; 비소속 `disclosure_unsatisfiable`, 형식 `bad_disclosure`. 나이는 "나이 ≥ N" 버튼이 `hi[0] = 올해 − N`(연 단위).
- "AttrGate" 문단을 v2 정책으로: 11워드 꼬리, `mask & 1`, `set_sel == 2 && set_root == allowedCountriesRoot`, `hi[0] + minAge ≤ yearOf(block.timestamp)`; `attrGatePolicy` 로 재배포 판정. `rp_info.predicates`.
- 로그인 술어: RP 페이지 체크박스 → `require`, 미충족 `predicate_unmet`.
- 오류 사유 표에 `predicate_unmet` 행.

spec §1 표 정정 한 줄(위).

- [ ] **Step 3: 전체 검증**

Run: `npm test 2>&1 | tail -5 && bash scripts/run_tests.sh contract 2>&1 | tail -3 && bash scripts/run_tests.sh chain 2>&1 | tail -5 && bash scripts/run_tests.sh snap 2>&1 | tail -3`
Expected: 전부 통과(`browser` 그룹은 Chrome 이 있으면 돌리고, 없으면 BLOCKED 로 보고).

- [ ] **Step 4: Commit**

```bash
git add results/mode3_predicates_20260923.md docs/MODE3_DEMO.md docs/superpowers/specs/2026-09-23-mode3-predicates-design.md scripts/run_tests.sh
git commit -m "docs(mode3): V7 술어 확장 측정 결과·데모 문서(env·AttrGate v2·set 요청·predicate_unmet), spec CIA 줄 정정"
```

---

## Self-Review

**Spec coverage** — §0 결정(시각 상대 = 검증자, 집합 = root, 비교 제외, 연 단위): T3·T6·T7·T9. §1 표: 공개 입력 25(T2), 꼬리·다이제스트 11워드(T3), AttrGate 정책(T3), CIA(T6 + spec 정정 T9). §2 집합 트리: T1. §3 회로: T2. §4.1 execute: T3. §4.2 AttrGate·`_year`: T3(이름 `yearOf`, public pure — 테스트를 위해; spec 의 `_year` 와 동작 동일). §4.3 배포·env·재배포 판정: T3(`deployAttrGate`)·T6. §5.1 요청 형식·`normalizeDisclosure(disclose, attrs, set)`: T4·T5 — spec 의 단일 함수 대신 `normalizeDisclosure`(동기, 기존) + `normalizeSet`(비동기) 조합으로 구현(Ruling: 기존 동기 호출자를 깨지 않는다; 결과 객체 형식은 spec 과 같다). §5.2 Snap: T5·T7. §5.3 폼: T5. §6 RP: T6·T7. §7 빌드·측정: T3·T9. §8 보안 메모: 회로(T2 음성 케이스)·컨트랙트(T3 `BadDisclosure`)·RP(T6). §9 테스트 표: 전 그룹 T1–T8. §10 범위 밖 준수.

**Placeholder scan** — "Similar to Task N" 없음; 모든 코드 단계에 코드 블록. T4 의 `proveWith`·T5 의 `loginTestuser`·T7 의 `loginViaRp` 는 각 테스트 파일의 기존 헬퍼를 가리키며 이름 맞춤 지시가 있다.

**Type consistency** — `normalizeSet → { sel, root, index, path }`(bigint, bigint, number, bigint[8]) 를 T4·T5·T7·T8 이 같은 형식으로 쓴다. `payloadDigest`/`signPayload` 의 `setSel`·`setRoot` 키(T3)를 T5·T8 이 쓴다. `parseExecuteReceipt.disclosure.{setSel,setRoot}` 와 응답 `disclosure.set.{sel,root}` 는 `discStrings`(T5) 가 둘 다 받는다(`d.sel ?? d.setSel`). RP `disclosure.{sel,root}`(T6) 와 `discOf(...).set`(T6) 를 T7 이 쓴다. `ALLOWED_COUNTRIES_DEFAULT`·`MIN_AGE_DEFAULT`(T3) 를 T6 이 import 한다.
