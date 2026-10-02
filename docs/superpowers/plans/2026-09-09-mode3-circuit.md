# Mode 3 회로 구현 계획 — 단계 (c)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mode 3의 credential 증명 회로 `pi_cred`를 만들고, 제약 수와 증명 시간을 실측해 커밋 스킴을 확정한다.

**Architecture:** 회로 하나가 네 가지를 함께 증명한다 — CIA의 EdDSA-Poseidon 서명 검증, 커밋 `C` 개봉, `PPID` 유도, 폐기 트리 비멤버십. 폐기 트리는 샤딩 없는 단일 IMT(깊이 32)이고 기존 `lib/imt_v2.js`·`circuits/lib/imt_nonmembership_v2.circom`을 **그대로 재사용**한다(깊이만 다르고 구조가 같다). 새로 만드는 것은 Mode 3 전용 리프 헬퍼와 `pi_cred.circom` 둘뿐이다.

**Tech Stack:** circom 2.0, circomlib(Poseidon, EdDSAPoseidon, Pedersen, Num2Bits), snarkjs(Groth16), circomlibjs, Node.js ESM

**설계 문서:** `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md`

## Global Constraints

- **Mode 2를 건드리지 않는다.** `custom_idp.js`, `wallet_agent.js`, `server.js`, `circuits/pi_pk_i*.circom`, `lib/imt_v3.js`, `lib/idp_revocation_v3.js`, `lib/wallet_revocation_v3.js`, `idp_state.json`은 이 계획에서 **읽기 전용**이다.
- **실행 중인 데모(:3000/:4000/:5001)와 `idp_state.json`을 절대 건드리지 않는다.**
- 산출물은 전부 `build/mode3/` 아래에 만든다. 기존 `build/mode2/`를 덮어쓰지 않는다.
- **`npm run zk:compile`·`zk:key`를 실행하지 않는다.** 그 스크립트는 Mode 1 회로를 대상으로 하며 기존 산출물을 무효화한다. 회로 컴파일은 테스트 스크립트가 `circom`을 직접 호출해 `build/mode3/`에 만든다.
- **Task 4(zkey 생성)는 사용자 승인 후에만 실행한다.**
- 트리 깊이는 **32**로 고정한다. `createIMTv2`의 상한이 32이고 설계 문서 §7.1이 32를 명시한다.
- 명명은 설계 문서 §4.1의 Mode 2 대응표를 따른다: `arid`(RP 식별자), `s_u`(사용자 비밀), `blind`(커밋 블라인딩). **Mode 2의 `salt`는 `s_u`에 해당하며 `blind`가 아니다.**
- 새 테스트 파일은 반드시 `scripts/run_tests.sh`의 해당 그룹 배열에 등록한다.
- 커밋 메시지는 한글, 기존 저장소 관례(`feat(mode3): ...`)를 따른다.

## 이 계획이 다루지 않는 것

단계 (a) 오프체인 전 구간(`cia.js`, `RevocationLog` 컨트랙트, RP 로그인 검증)과 (b) 온체인 실행(`RevocationMirror`, `CredentialVerifier`, `PPIDWallet` 연동)은 **각각 별도 계획 문서**로 만든다. 이 계획의 산출물(제약 수, 증명 시간, 확정된 커밋 스킴)이 그 두 계획의 입력이다.

## File Structure

| 파일 | 책임 |
|---|---|
| `lib/mode3_revocation.js` (신규) | Mode 3 폐기 트리 헬퍼. 리프 유도(`credLeaf`)와 트리 생성. 트리 본체는 `imt_v2.js`에 위임 |
| `circuits/lib/mode3_commit.circom` (신규) | 커밋 스킴 두 판(`CommitPoseidon`, `CommitPedersen`). Task 2에서 하나를 확정 |
| `circuits/pi_cred.circom` (신규) | Mode 3 증명 회로. 설계 문서 §5의 ①~④ |
| `tests/test_mode3_revocation_tree.js` (신규) | 리프 유도와 트리 동작 |
| `tests/test_mode3_commit_scheme.mjs` (신규) | 커밋 스킴 두 판의 바인딩 검증과 제약 수 비교 |
| `tests/test_pi_cred_witness.mjs` (신규) | `pi_cred` witness 계산. 양성 1 + 음성 4 |
| `scripts/bench_pi_cred.mjs` (신규) | zkey 생성 후 증명·검증 시간 실측 (Task 4) |
| `scripts/run_tests.sh` (수정) | `UNIT`·`CIRCUIT` 배열에 신규 테스트 등록 |
| 설계 문서 §11 (수정) | 확정된 커밋 스킴과 실측값 기록 |

---

### Task 1: Mode 3 폐기 트리 헬퍼

**Files:**
- Create: `lib/mode3_revocation.js`
- Create: `tests/test_mode3_revocation_tree.js`
- Modify: `scripts/run_tests.sh` (`UNIT` 배열)

**Interfaces:**
- Consumes: `lib/imt_v2.js`의 `createIMTv2(depth)`, `leafValue(tag, raw)`
- Produces:
  - `MODE3_TREE_DEPTH: number` = 32
  - `TAG_MODE3_CRED: number` = 3
  - `async credLeaf(C: bigint): Promise<bigint>` — 트리에 넣는 리프 값. `Poseidon(3, C) & (2^252-1)`
  - `async createRevocationTree(depth?: number)` — `createIMTv2`가 반환하는 것과 같은 객체
  - 트리 객체 API(`imt_v2.js` 그대로): `getRoot()`, `await insert(v)`, `await getNonMembershipWitness(v)`, `has(v)`, `size()`, `getLeaves()`

- [ ] **Step 1: 실패하는 테스트를 쓴다**

`tests/test_mode3_revocation_tree.js`:

```js
// Mode 3 폐기 트리 헬퍼. 리프 유도와 트리 동작을 확인한다.
//   node tests/test_mode3_revocation_tree.js
//
// 트리 본체는 lib/imt_v2.js를 그대로 쓰므로 여기서는 재검증하지 않는다.
// 확인하는 것은 Mode 3이 얹는 부분 — 리프 유도가 결정적이고, 회로가 쓰는
// 252비트 범위 안에 들어오며, Mode 2의 태그와 충돌하지 않는다는 것이다.
import assert from 'node:assert/strict';
import {
  MODE3_TREE_DEPTH,
  TAG_MODE3_CRED,
  credLeaf,
  createRevocationTree,
} from '../lib/mode3_revocation.js';
import { TAG_SESSION, TAG_ACCOUNT } from '../lib/imt_v2.js';

const TWO_252 = 1n << 252n;
let failed = 0;

async function t(name, fn) {
  try {
    await fn();
    console.log(`ok   ${name}`);
  } catch (e) {
    failed++;
    console.error(`FAIL ${name}\n     ${e.message}`);
  }
}

await t('깊이는 32다', () => {
  assert.equal(MODE3_TREE_DEPTH, 32);
});

await t('태그가 Mode 2와 충돌하지 않는다', () => {
  assert.notEqual(TAG_MODE3_CRED, TAG_SESSION);
  assert.notEqual(TAG_MODE3_CRED, TAG_ACCOUNT);
});

await t('credLeaf는 결정적이고 252비트 안에 들어온다', async () => {
  const C = 123456789012345678901234567890n;
  const a = await credLeaf(C);
  const b = await credLeaf(C);
  assert.equal(a, b, '같은 C는 같은 리프를 준다');
  assert.ok(a < TWO_252, `리프가 2^252 미만이어야 한다: ${a}`);
  assert.ok(a > 0n, '리프가 0이면 anchor와 충돌한다');
});

await t('다른 C는 다른 리프를 준다', async () => {
  const a = await credLeaf(1n);
  const b = await credLeaf(2n);
  assert.notEqual(a, b);
});

await t('폐기 전에는 비멤버십 witness가 나오고 폐기 후에는 안 나온다', async () => {
  const tree = await createRevocationTree();
  const leaf = await credLeaf(42n);

  const before = await tree.getNonMembershipWitness(leaf);
  assert.ok(before, '폐기 전에는 witness가 나와야 한다');
  assert.equal(before.pathElements.length, MODE3_TREE_DEPTH);

  const rootBefore = tree.getRoot();
  assert.equal(await tree.insert(leaf), true);
  assert.notEqual(tree.getRoot().toString(), rootBefore.toString(),
    '삽입하면 root가 바뀌어야 한다');

  await assert.rejects(() => tree.getNonMembershipWitness(leaf), /is a member/);
});

await t('다른 credential은 남의 폐기에 영향받지 않는다', async () => {
  const tree = await createRevocationTree();
  const mine = await credLeaf(7n);
  await tree.insert(await credLeaf(8n));
  const w = await tree.getNonMembershipWitness(mine);
  assert.ok(w, '내 리프는 여전히 비멤버십이어야 한다');
});

await t('제거 기능이 없다 (append-only)', async () => {
  const tree = await createRevocationTree();
  assert.equal(typeof tree.remove, 'undefined');
});

process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 2: 실패를 확인한다**

```bash
cd /home/node1phi/Desktop/google-oidc-demo
node tests/test_mode3_revocation_tree.js
```

Expected: `Cannot find module '.../lib/mode3_revocation.js'` 로 실패

- [ ] **Step 3: 최소 구현을 쓴다**

`lib/mode3_revocation.js`:

```js
// Mode 3 폐기 트리.
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §7.1
//
// 단일 IMT, 깊이 32, 샤딩 없음, append-only. 리프는 **폐기가 일어날 때만** 생긴다
// (발급 때가 아니다). 그래서 트리가 작고 Mode 2의 샤딩·상위 트리·리셋 보조정리가
// 전부 필요 없다.
//
// 트리 본체는 lib/imt_v2.js를 그대로 쓴다 — Mode 3이 얹는 것은 리프 유도뿐이다.
// v2는 remove()를 노출하지 않으므로 append-only가 자료구조 수준에서 강제된다.
import { createIMTv2, leafValue } from './imt_v2.js';

export const MODE3_TREE_DEPTH = 32;

// TAG_SESSION=1, TAG_ACCOUNT=2는 Mode 2가 쓰고 있다(circuits/pi_pk_i_v3.circom).
// 같은 트리를 쓰지는 않지만, 리프 유도 함수를 공유하므로 값을 갈라 둔다.
export const TAG_MODE3_CRED = 3;

/**
 * 폐기 트리에 들어가는 리프 값.
 *
 * 설계 문서 §4.3: 리프를 C **로부터 유도**하는 것이 핵심이다. C 안의 속성으로
 * 두면 사용자가 값을 골라 아무 난수나 제시할 수 있어 발급 시 정합성 ZKP가
 * 필요해진다. 유도하면 회로가 비공개 입력 C에서 직접 계산하므로 다른 리프를
 * 들이밀 방법이 없다.
 *
 * leafValue()가 하위 252비트로 마스킹한다 — 회로의 LessThan(252)이 그 범위를
 * 전제하기 때문이다(circuits/lib/imt_nonmembership_v2.circom 주석 참조).
 */
export async function credLeaf(C) {
  return leafValue(TAG_MODE3_CRED, C);
}

export async function createRevocationTree(depth = MODE3_TREE_DEPTH) {
  return createIMTv2(depth);
}
```

- [ ] **Step 4: 통과를 확인한다**

```bash
node tests/test_mode3_revocation_tree.js
```

Expected: 모든 줄이 `ok`, 종료 코드 0

- [ ] **Step 5: `run_tests.sh`에 등록한다**

`scripts/run_tests.sh`의 `UNIT=(` 배열 마지막 항목 뒤에 한 줄 추가:

```bash
  tests/test_mode3_revocation_tree.js
```

확인:

```bash
bash scripts/run_tests.sh unit
```

Expected: 기존 테스트 전부 통과 + `test_mode3_revocation_tree.js` 통과

- [ ] **Step 6: 커밋**

```bash
git add lib/mode3_revocation.js tests/test_mode3_revocation_tree.js scripts/run_tests.sh
git commit -m "feat(mode3): 폐기 트리 헬퍼 추가 — 단일 IMT 깊이 32, 리프는 H(C)"
```

---

### Task 2: 커밋 스킴 두 판과 비교 측정

**Files:**
- Create: `circuits/lib/mode3_commit.circom`
- Create: `tests/test_mode3_commit_scheme.mjs`
- Modify: `scripts/run_tests.sh` (`CIRCUIT` 배열)
- Modify: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` (§11 커밋 스킴 행)

**왜 이 태스크가 필요한가.** 설계 문서 §11이 커밋 스킴을 미결로 남겼다. 두 후보의 값이 정반대 방향으로 든다:

- **Pedersen** — 발급 시 PoK가 Schnorr 시그마 프로토콜(수 ms, SNARK 없음, 셋업 없음)이지만, show 회로에서 5개 고정베이스 스칼라곱을 개봉해야 해 제약이 크다.
- **Poseidon** — show 회로가 훨씬 싸지만, 발급 시 PoK가 SNARK가 되어 **회로와 셋업이 하나 더** 필요하다.

show 회로는 root가 바뀔 때마다 브라우저에서 돌고, 발급 PoK는 세션당 한 번 돈다. 어느 쪽이 유리한지는 **제약 수를 재봐야** 안다.

**Interfaces:**
- Produces (circom 템플릿):
  - `CommitPoseidon()` — 입력 `uid, arid, s_u, blind, pk_i`, 출력 `C` (필드 원소 1개)
  - `CommitPedersen()` — 입력 동일, 출력 `Cx, Cy` (곡선 점)
- Produces (측정 결과): 두 판의 비선형 제약 수. Task 3이 이 결과로 하나를 고른다.

- [ ] **Step 1: 실패하는 테스트를 쓴다**

`tests/test_mode3_commit_scheme.mjs`:

```js
// Mode 3 커밋 스킴 두 판의 바인딩 검증과 제약 수 비교.
//   node tests/test_mode3_commit_scheme.mjs
//
// zkey는 만들지 않는다. circom --r1cs --wasm 으로 제약 수를 읽고 witness 계산까지만 한다.
// 산출물은 build/mode3/commit/ 에 만든다 (build/ 전체가 .gitignore 대상).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildPoseidon } from 'circomlibjs';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'mode3', 'commit');

const VARIANTS = {
  poseidon: `pragma circom 2.0.0;
include "lib/mode3_commit.circom";
component main = CommitPoseidon();
`,
  pedersen: `pragma circom 2.0.0;
include "lib/mode3_commit.circom";
component main = CommitPedersen();
`,
};

// 제약 수를 세려면 컴파일해야 한다. circom은 컴파일 요약에 비선형 제약 수를 찍는다.
function compile(name, src) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const wrapper = path.join(OUT_DIR, `${name}.circom`);
  fs.writeFileSync(wrapper, src);
  const out = execFileSync(
    'circom',
    [
      wrapper, '--r1cs', '--wasm', '-o', OUT_DIR,
      '-l', path.join(ROOT_DIR, 'circuits'),
      '-l', path.join(ROOT_DIR, 'circuits', 'lib'),
      '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits'),
    ],
    { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const m = /non-linear constraints:\s*(\d+)/.exec(out);
  assert.ok(m, `제약 수를 읽지 못했다:\n${out}`);
  return Number(m[1]);
}

async function witness(name, input) {
  const wc = await import(
    path.join(OUT_DIR, `${name}_js`, 'witness_calculator.js')
  ).then((m) => m.default);
  const wasm = fs.readFileSync(path.join(OUT_DIR, `${name}_js`, `${name}.wasm`));
  const calc = await wc(wasm);
  return calc.calculateWitness(input, true);
}

const INPUT = {
  uid: '11111111111111111111',
  arid: '22222222222222222222',
  s_u: '33333333333333333333',
  blind: '44444444444444444444',
  pk_i: '1234567890123456789012345678901234567890', // 160비트 주소 범위
};

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const counts = {};

for (const [name, src] of Object.entries(VARIANTS)) {
  await t(`${name}: 컴파일되고 witness가 계산된다`, async () => {
    counts[name] = compile(name, src);
    const w = await witness(name, INPUT);
    assert.ok(w.length > 0);
  });
}

await t('Poseidon 판은 같은 입력에 같은 C를 준다', async () => {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const expected = F.toObject(poseidon([
    BigInt(INPUT.uid), BigInt(INPUT.arid), BigInt(INPUT.s_u),
    BigInt(INPUT.blind), BigInt(INPUT.pk_i),
  ]));
  const w = await witness('poseidon', INPUT);
  // main 컴포넌트의 출력은 witness[1] 부터 놓인다 (witness[0]은 상수 1).
  assert.equal(w[1].toString(), expected.toString(),
    '회로가 계산한 C가 circomlibjs Poseidon과 달라서는 안 된다');
});

await t('blind 하나만 바꿔도 C가 바뀐다 (hiding의 전제)', async () => {
  const a = await witness('poseidon', INPUT);
  const b = await witness('poseidon', { ...INPUT, blind: '55555555555555555555' });
  assert.notEqual(a[1].toString(), b[1].toString());
});

console.log('');
console.log('## 커밋 스킴 제약 수');
console.log('');
console.log('| 판 | 비선형 제약 |');
console.log('|---|--:|');
for (const [k, v] of Object.entries(counts)) {
  console.log(`| ${k} | ${v.toLocaleString()} |`);
}
console.log('');
console.log(`차이: ${Math.abs(counts.pedersen - counts.poseidon).toLocaleString()} ` +
            `(Pedersen이 Poseidon의 ${(counts.pedersen / counts.poseidon).toFixed(1)}배)`);

process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 2: 실패를 확인한다**

```bash
node tests/test_mode3_commit_scheme.mjs
```

Expected: circom이 `lib/mode3_commit.circom`을 찾지 못해 실패

- [ ] **Step 3: 최소 구현을 쓴다**

`circuits/lib/mode3_commit.circom`:

```circom
pragma circom 2.0.0;

include "poseidon.circom";
include "pedersen.circom";
include "bitify.circom";

// Mode 3 커밋 스킴 두 판.
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §4.1, §11
//
// 커밋이 담는 것은 (uid, arid, s_u, blind, pk_i) 다섯이다.
//   uid   — 계정 식별자. PPID 유도에 쓰인다
//   arid  — RP 식별자. credential을 RP에 묶는다 (Mode 2의 rid)
//   s_u   — 사용자 비밀. CIA가 PPID를 열거하지 못하게 막는다 (Mode 2의 salt)
//   blind — 커밋 블라인딩. CIA가 공개된 (arid, pk_i)와 자기가 아는 uid로
//           C를 재계산해 대조하는 것을 막는다
//   pk_i  — 세션키. 이 π가 이 서명자의 것임을 묶는다

// 해시 판. show 회로가 싸다. 대신 발급 시 PoK가 SNARK가 되어 회로가 하나 더 필요하다.
template CommitPoseidon() {
    signal input uid;
    signal input arid;
    signal input s_u;
    signal input blind;
    signal input pk_i;
    signal output C;

    component h = Poseidon(5);
    h.inputs[0] <== uid;
    h.inputs[1] <== arid;
    h.inputs[2] <== s_u;
    h.inputs[3] <== blind;
    h.inputs[4] <== pk_i;
    C <== h.out;
}

// Pedersen 벡터 커밋 판. 발급 시 PoK가 Schnorr 시그마 프로토콜이라 SNARK도
// 셋업도 필요 없다. 대신 show 회로에서 고정베이스 스칼라곱을 개봉해야 한다.
//
// circomlib의 Pedersen(n)은 n비트를 4비트 창으로 나눠 고정베이스 테이블을
// 조회해 더한다. 다섯 스칼라의 비트를 이어 붙이면 창마다 베이스가 달라지므로
// 결과는 다섯 값에 대한 벡터 커밋이 된다.
template CommitPedersen() {
    signal input uid;
    signal input arid;
    signal input s_u;
    signal input blind;
    signal input pk_i;
    signal output Cx;
    signal output Cy;

    var N = 254;   // 필드 원소 하나의 비트 수 (Num2Bits_strict 출력 길이)

    component bUid   = Num2Bits_strict();
    component bArid  = Num2Bits_strict();
    component bSu    = Num2Bits_strict();
    component bBlind = Num2Bits_strict();
    component bPki   = Num2Bits_strict();
    bUid.in   <== uid;
    bArid.in  <== arid;
    bSu.in    <== s_u;
    bBlind.in <== blind;
    bPki.in   <== pk_i;

    component p = Pedersen(5 * N);
    for (var i = 0; i < N; i++) {
        p.in[0 * N + i] <== bUid.out[i];
        p.in[1 * N + i] <== bArid.out[i];
        p.in[2 * N + i] <== bSu.out[i];
        p.in[3 * N + i] <== bBlind.out[i];
        p.in[4 * N + i] <== bPki.out[i];
    }
    Cx <== p.out[0];
    Cy <== p.out[1];
}
```

- [ ] **Step 4: 통과와 제약 수를 확인한다**

```bash
node tests/test_mode3_commit_scheme.mjs
```

Expected: 모든 줄 `ok`, 마지막에 두 판의 제약 수 표가 출력된다

- [ ] **Step 5: 결과로 커밋 스킴을 확정하고 설계 문서에 기록한다**

**결정 규칙:**

- Pedersen이 Poseidon의 **3배 이하**면 → **Pedersen을 쓴다.** 발급 시 SNARK와 셋업을 하나 없애는 값이 show 회로의 제약 증가보다 크다.
- **3배를 넘으면** → **Poseidon을 쓴다.** show 회로는 root가 바뀔 때마다 브라우저에서 돌고, 발급 PoK 회로는 작아서(커밋 개봉 + `cm_u` 동일성만) 추가 셋업 비용을 감당할 수 있다.

설계 문서 `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` §11의 커밋 스킴 행을 실제 값으로 바꾼다. 예(Poseidon이 이긴 경우):

```markdown
| 커밋 스킴 | **Poseidon 확정** (2026-09-09 실측: Poseidon 241 제약, Pedersen 5,832 제약, 24배). 발급 PoK는 별도 SNARK로 단계 (a)에서 만든다 |
```

- [ ] **Step 6: `run_tests.sh`에 등록한다**

`scripts/run_tests.sh`의 `CIRCUIT=(` 배열 마지막 항목 뒤에 한 줄 추가:

```bash
  tests/test_mode3_commit_scheme.mjs
```

확인:

```bash
bash scripts/run_tests.sh circuit
```

Expected: 기존 회로 테스트 전부 통과 + 신규 통과

- [ ] **Step 7: 커밋**

```bash
git add circuits/lib/mode3_commit.circom tests/test_mode3_commit_scheme.mjs \
        scripts/run_tests.sh docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md
git commit -m "feat(mode3): 커밋 스킴 두 판 비교 측정, 설계 문서에 결정 기록"
```

---

### Task 3: `pi_cred` 회로

**Files:**
- Create: `circuits/pi_cred.circom`
- Create: `tests/test_pi_cred_witness.mjs`
- Modify: `scripts/run_tests.sh` (`CIRCUIT` 배열)

**Interfaces:**
- Consumes: Task 1의 `credLeaf`·`createRevocationTree`, Task 2에서 확정한 커밋 템플릿, `circuits/lib/imt_nonmembership_v2.circom`의 `IMTNonMembershipV2(depth)`
- Produces (회로 공개 입력, 순서 고정 — 단계 (a)·(b)가 이 순서에 의존한다):

```
[0] PPID
[1] arid
[2] pk_i
[3] max_height
[4] revRoot
[5] pk_CIA_x
[6] pk_CIA_y
```

**설계 문서 §5와의 두 가지 차이 (의도된 것):**

- **`C`는 회로 입력이 아니라 계산된 값이다.** §5는 `C`를 비공개 입력으로 적었지만,
  `(uid, arid, s_u, blind, pk_i)`에서 회로가 직접 계산하는 편이 낫다 — 입력이 하나 줄고,
  "`C` 안에 이 `pk_i`가 있다"는 바인딩이 별도 등식 없이 자동으로 성립한다.
- **`pk_CIA_x`, `pk_CIA_y`가 공개 입력에 추가된다.** 검증자가 어느 CIA 키로 검증할지
  알아야 한다. Mode 2 `pi_pk_i_v3`도 `pk_IdP_x`·`pk_IdP_y`를 공개 입력으로 둔다.

**두 가지 구현 결정과 근거:**

1. **`pk_i`는 160비트 값(세션키의 이더리움 주소)이다.** Mode 2의 `pi_pk_i.circom`이 같은 제약을 걸고 있고, 온체인 경로에서 `ecrecover` 프리컴파일(3,000 gas)로 검증할 수 있다. 설계 문서는 BAAR 표기를 따라 "Schnorr"라고 적었지만, 컨트랙트 안에서 Schnorr를 직접 검증하면 수십만 gas가 든다. 둘 다 이산로그 기반 서명이라 보안 논증은 바뀌지 않는다. **이 편차를 설계 문서 §11에 기록한다.**
2. **도메인 태그 `DOMAIN_MODE3_CRED = 1426111059989523219780`** (ASCII `"MODE3CRED"`의 빅엔디언 정수). Mode 2의 `DOMAIN_IDP_TOKEN`과 갈라 두어 서명이 모드를 넘어 재사용되지 않게 한다.

- [ ] **Step 1: 실패하는 테스트를 쓴다**

`tests/test_pi_cred_witness.mjs`:

```js
// pi_cred 회로의 witness 계산. 양성 1건 + 음성 4건.
//   node tests/test_pi_cred_witness.mjs
//
// zkey는 만들지 않는다 (Task 4에서 별도 승인 후). 여기서는 회로가 올바른 입력을
// 받아들이고 잘못된 입력을 거부하는지만 본다 — 그게 건전성의 핵심이다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildPoseidon, buildEddsa } from 'circomlibjs';
import { credLeaf, createRevocationTree, MODE3_TREE_DEPTH } from '../lib/mode3_revocation.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'mode3');
const NAME = 'pi_cred';
const DOMAIN_MODE3_CRED = 1426111059989523219780n;

function compile() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const out = execFileSync(
    'circom',
    [
      path.join(ROOT_DIR, 'circuits', `${NAME}.circom`),
      '--r1cs', '--wasm', '--sym', '-o', OUT_DIR,
      '-l', path.join(ROOT_DIR, 'circuits'),
      '-l', path.join(ROOT_DIR, 'circuits', 'lib'),
      '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits'),
    ],
    { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const m = /non-linear constraints:\s*(\d+)/.exec(out);
  console.log(`OK: 컴파일됨, 비선형 제약 ${m ? Number(m[1]).toLocaleString() : '?'}개`);
  return m ? Number(m[1]) : 0;
}

let calc = null;
async function witness(input) {
  if (!calc) {
    const wc = await import(path.join(OUT_DIR, `${NAME}_js`, 'witness_calculator.js'))
      .then((m) => m.default);
    calc = await wc(fs.readFileSync(path.join(OUT_DIR, `${NAME}_js`, `${NAME}.wasm`)));
  }
  return calc.calculateWitness(input, true);
}

// --- 정상 입력 하나를 만든다 -------------------------------------------------
async function buildValidInput() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const eddsa = await buildEddsa();

  const uid   = 11111111111111111111n;
  const arid  = 22222222222222222222n;
  const s_u   = 33333333333333333333n;
  const blind = 44444444444444444444n;
  const pk_i  = 0x1234567890123456789012345678901234567890n; // 160비트
  const max_height = 1000n;

  const C = F.toObject(poseidon([uid, arid, s_u, blind, pk_i]));
  const PPID = F.toObject(poseidon([uid, arid, s_u]));
  const msg = F.toObject(poseidon([DOMAIN_MODE3_CRED, C, max_height]));

  // CIA 서명키. 테스트 고정값이며 실제 키가 아니다.
  const prv = Buffer.from('0001020304050607080900010203040506070809000102030405060708090001', 'hex');
  const pub = eddsa.prv2pub(prv);
  const sig = eddsa.signPoseidon(prv, F.e(msg));

  // 폐기 트리에 남의 폐기를 하나 넣어 둔다 — 내 비멤버십은 여전히 성립해야 한다.
  const tree = await createRevocationTree();
  await tree.insert(await credLeaf(999n));
  const w = await tree.getNonMembershipWitness(await credLeaf(C));

  return {
    uid: uid.toString(),
    s_u: s_u.toString(),
    blind: blind.toString(),
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
    max_height: max_height.toString(),
    revRoot: tree.getRoot().toString(),
    pk_CIA_x: F.toObject(pub[0]).toString(),
    pk_CIA_y: F.toObject(pub[1]).toString(),
  };
}

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const constraints = compile();
const valid = await buildValidInput();

await t('양성: 정상 credential의 witness가 계산된다', async () => {
  const w = await witness(valid);
  assert.ok(w.length > 0);
});

await t('음성: PPID가 다르면 거부된다', async () => {
  await assert.rejects(
    () => witness({ ...valid, PPID: (BigInt(valid.PPID) + 1n).toString() }),
    /Assert Failed|Error/,
  );
});

await t('음성: 서명이 다른 max_height에 대한 것이면 거부된다', async () => {
  await assert.rejects(
    () => witness({ ...valid, max_height: (BigInt(valid.max_height) + 1n).toString() }),
    /Assert Failed|Error/,
  );
});

await t('음성: pk_i를 바꾸면 거부된다 (C 바인딩이 깨진다)', async () => {
  await assert.rejects(
    () => witness({ ...valid, pk_i: (BigInt(valid.pk_i) + 1n).toString() }),
    /Assert Failed|Error/,
  );
});

await t('음성: 폐기 전에 만든 witness는 폐기 후 root에서 거부된다 (낡은 증명)', async () => {
  // 회로 수준의 폐기 검증이다. 라이브러리가 폐기된 리프의 witness 생성을 거부하는
  // 것은 Task 1 테스트가 이미 확인했다 — 여기서 볼 것은 **회로가** 낡은 증명을
  // 거부하는가다.
  //
  // 폐기된 사용자가 증명을 제시할 수 있는 유일한 길은 폐기 **전**에 만든 witness를
  // 그대로 내는 것이다. 회로는 revRoot에 묶여 있으므로, 옛 witness + 새 root 조합은
  // 경로 검증에서 걸려야 한다. 컨트랙트가 최신 root만 받으므로(N=1) 이것이 폐기가
  // 실제로 작동하는 지점이다.
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const C = F.toObject(poseidon([
    11111111111111111111n, 22222222222222222222n, 33333333333333333333n,
    44444444444444444444n, 0x1234567890123456789012345678901234567890n,
  ]));
  const tree = await createRevocationTree();
  await tree.insert(await credLeaf(999n));   // valid 을 만들 때와 같은 상태
  await tree.insert(await credLeaf(C));       // 내 credential 폐기 → root 변경
  await assert.rejects(
    () => witness({ ...valid, revRoot: tree.getRoot().toString() }),
    /Assert Failed|Error/,
    '폐기 후 root에 대해 옛 witness가 통과하면 폐기가 무의미하다',
  );
});

console.log('');
console.log(`## pi_cred 비선형 제약: ${constraints.toLocaleString()}`);
console.log(`   (참고 — Mode 2 pi_pk_i_v3: 13,905)`);

process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 2: 실패를 확인한다**

```bash
node tests/test_pi_cred_witness.mjs
```

Expected: `circuits/pi_cred.circom` 가 없어 circom이 실패

- [ ] **Step 3: 회로를 쓴다**

`circuits/pi_cred.circom` (Task 2에서 Poseidon 판이 확정된 경우. Pedersen이 확정됐다면 `CommitPedersen`을 쓰고 `C` 대신 `(Cx, Cy)`를 `Poseidon(2)`로 압축해 아래 `C`가 있던 자리에 넣는다):

```circom
pragma circom 2.0.0;

include "lib/eddsaposeidon.circom";
include "lib/poseidon.circom";
include "lib/imt_nonmembership_v2.circom";
include "lib/bitify.circom";
include "lib/mode3_commit.circom";

// Mode 3 credential 증명.
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §5
//
// 네 가지를 함께 증명한다. 하나라도 빠지면 뚫린다:
//   ① CIA가 (C, max_height)에 서명했다        — 없으면 아무나 credential을 만든다
//   ② C 안에 이 pk_i가 있다                    — 없으면 남의 π를 주워 자기 키로 서명해 완전 사칭
//   ③ PPID = Poseidon(uid, arid, s_u)          — 없으면 지갑 주소를 특정할 수 없다
//   ④ H(C)가 폐기 트리에 없다                   — 없으면 폐기가 무의미
//
// ②는 커밋을 공개 입력 pk_i·arid로 **직접 계산**해서 얻는다. 별도 등식이 필요 없다 —
// 계산에 쓴 값이 곧 공개 입력이므로 다른 값을 넣으면 서명 검증이 깨진다.
//
// 리프를 C 안의 속성이 아니라 C **로부터** 유도하는 것이 §4.3의 핵심이다.
// 회로가 비공개 입력에서 직접 계산하므로 증명자가 다른 리프를 제시할 수 없고,
// 그 덕에 발급 시 리프 정합성 ZKP가 통째로 불필요해진다.
template PiCred(depth) {
    // ---- Private ----
    signal input uid;
    signal input s_u;
    signal input blind;

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
    signal input max_height;
    signal input revRoot;
    signal input pk_CIA_x;
    signal input pk_CIA_y;

    var DOMAIN_MODE3_CRED = 1426111059989523219780;  // ASCII "MODE3CRED"
    var TAG_MODE3_CRED = 3;                          // TAG_SESSION=1, TAG_ACCOUNT=2 와 갈라 둔다

    // pk_i는 세션키의 이더리움 주소다. 160비트를 넘을 수 없다.
    // (Mode 2 pi_pk_i.circom과 같은 제약 — 형제 크레덴셜 구멍을 막는다.)
    component pkIRange = Num2Bits(160);
    pkIRange.in <== pk_i;

    // ---- C 계산 ----
    component commit = CommitPoseidon();
    commit.uid   <== uid;
    commit.arid  <== arid;
    commit.s_u   <== s_u;
    commit.blind <== blind;
    commit.pk_i  <== pk_i;
    signal C;
    C <== commit.C;

    // ---- ① CIA 서명 검증 ----
    component msgHasher = Poseidon(3);
    msgHasher.inputs[0] <== DOMAIN_MODE3_CRED;
    msgHasher.inputs[1] <== C;
    msgHasher.inputs[2] <== max_height;

    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== pk_CIA_x;
    sigVerifier.Ay <== pk_CIA_y;
    sigVerifier.S <== S;
    sigVerifier.R8x <== R8x;
    sigVerifier.R8y <== R8y;
    sigVerifier.M <== msgHasher.out;

    // ---- ③ PPID 유도 ----
    // Mode 2 pi_ppid.circom 의 Poseidon(uid, rid, salt) 와 같은 구조다
    // (arid = rid, s_u = salt).
    component ppidHasher = Poseidon(3);
    ppidHasher.inputs[0] <== uid;
    ppidHasher.inputs[1] <== arid;
    ppidHasher.inputs[2] <== s_u;
    PPID === ppidHasher.out;

    // ---- ④ 폐기 비멤버십 ----
    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== TAG_MODE3_CRED;
    leafHasher.inputs[1] <== C;

    component nm = IMTNonMembershipV2(depth);
    nm.target <== leafHasher.out;
    nm.lowValue <== lowValue;
    nm.lowNextIndex <== lowNextIndex;
    nm.lowNextValue <== lowNextValue;
    for (var i = 0; i < depth; i++) {
        nm.pathElements[i] <== pathElements[i];
        nm.pathIndices[i] <== pathIndices[i];
    }
    nm.root <== revRoot;
}

// 공개 입력의 순서는 단계 (a)·(b)가 의존한다. 바꾸지 말 것.
component main {public [
    PPID, arid, pk_i, max_height, revRoot, pk_CIA_x, pk_CIA_y
]} = PiCred(32);
```

- [ ] **Step 4: 통과를 확인한다**

```bash
node tests/test_pi_cred_witness.mjs
```

Expected: 5줄 전부 `ok`, 마지막에 비선형 제약 수 출력

- [ ] **Step 5: `run_tests.sh`에 등록한다**

`scripts/run_tests.sh`의 `CIRCUIT=(` 배열에 한 줄 추가:

```bash
  tests/test_pi_cred_witness.mjs
```

확인:

```bash
bash scripts/run_tests.sh circuit
```

Expected: 전부 통과

- [ ] **Step 6: 설계 문서 §11에 `pk_i`/서명 편차를 기록한다**

§11 표에 두 행을 추가한다:

```markdown
| `pk_i`의 인코딩 | **확정: 160비트 이더리움 주소.** Mode 2 `pi_pk_i.circom`과 같은 제약 |
| 세션 서명 스킴 | **확정: secp256k1 ECDSA (`ecrecover`).** 설계 본문의 "Schnorr"는 BAAR 표기를 따른 것이며, 컨트랙트 안에서 Schnorr를 직접 검증하면 수십만 gas가 든다. 둘 다 이산로그 기반이라 보안 논증은 동일하다 |
```

- [ ] **Step 7: 커밋**

```bash
git add circuits/pi_cred.circom tests/test_pi_cred_witness.mjs \
        scripts/run_tests.sh docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md
git commit -m "feat(mode3): pi_cred 회로 추가 — CIA 서명·커밋 개봉·PPID·폐기 비멤버십"
```

---

### Task 4: zkey 생성과 증명 시간 실측

> **승인 게이트.** 이 태스크는 zkey를 만든다. 오래 걸리고 디스크를 크게 쓴다.
> **실행 전 사용자에게 확인을 받는다.** 기존 Mode 2 산출물은 건드리지 않는다
> (전부 `build/mode3/` 아래에 만들고 `npm run zk:key`를 쓰지 않는다).

**Files:**
- Create: `scripts/bench_pi_cred.mjs`
- Modify: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` (§11에 실측값)

**Interfaces:**
- Consumes: Task 3의 `build/mode3/pi_cred.r1cs`, `build/mode3/pi_cred_js/pi_cred.wasm`
- Produces: `build/mode3/pi_cred_final.zkey`, `build/mode3/pi_cred_vkey.json`, 증명·검증 시간 실측값

- [ ] **Step 1: ptau 파일이 있는지 확인한다**

```bash
cd /home/node1phi/Desktop/google-oidc-demo
ls -la *.ptau
```

Expected: `pot21_final.ptau` (약 2.4 GB)가 있다. 이 파일은 **2^21 = 2,097,152 제약**까지
덮으므로 Task 3에서 측정한 `pi_cred` 제약 수(Mode 2 기준 1만~3만 수준 예상)를 충분히 넘는다.
새로 만들 필요가 없다.

만약 제약 수가 2,097,152를 넘으면 **여기서 멈추고 사용자에게 보고한다** — 더 큰 ptau 생성은
몇 시간이 걸리고 회로를 줄이는 편이 낫다는 신호다.

- [ ] **Step 2: 벤치 스크립트를 쓴다**

`scripts/bench_pi_cred.mjs`:

```js
// pi_cred 회로의 zkey 생성과 증명·검증 시간 실측.
//   node scripts/bench_pi_cred.mjs <ptau 파일 경로>
//
// 산출물은 전부 build/mode3/ 아래에 만든다. Mode 2 산출물(build/mode2/)을
// 건드리지 않으며 npm run zk:key 를 쓰지 않는다.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import * as snarkjs from 'snarkjs';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'mode3');
const PTAU = process.argv[2];
if (!PTAU || !fs.existsSync(PTAU)) {
  console.error('사용법: node scripts/bench_pi_cred.mjs <ptau 파일 경로>');
  process.exit(2);
}

const R1CS = path.join(OUT_DIR, 'pi_cred.r1cs');
const ZKEY0 = path.join(OUT_DIR, 'pi_cred_0000.zkey');
const ZKEY = path.join(OUT_DIR, 'pi_cred_final.zkey');
const VKEY = path.join(OUT_DIR, 'pi_cred_vkey.json');
const WASM = path.join(OUT_DIR, 'pi_cred_js', 'pi_cred.wasm');

function sh(args) {
  execFileSync('npx', args, { cwd: ROOT_DIR, stdio: 'inherit' });
}

if (!fs.existsSync(ZKEY)) {
  console.log('… zkey 생성 (수 분 걸릴 수 있음)');
  sh(['snarkjs', 'groth16', 'setup', R1CS, PTAU, ZKEY0]);
  sh(['snarkjs', 'zkey', 'contribute', ZKEY0, ZKEY, '--name=mode3', '-v', '-e=mode3-bench']);
  sh(['snarkjs', 'zkey', 'export', 'verificationkey', ZKEY, VKEY]);
}

// 입력은 테스트가 쓰는 것과 같은 방식으로 만든다.
const { buildValidInput } = await import('../tests/helpers/mode3_fixture.mjs');
const input = await buildValidInput();

const N = 10;
const proveMs = [];
const verifyMs = [];
let proof, publicSignals;

for (let i = 0; i < N; i++) {
  const t0 = performance.now();
  ({ proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY));
  proveMs.push(performance.now() - t0);

  const vkey = JSON.parse(fs.readFileSync(VKEY, 'utf8'));
  const t1 = performance.now();
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  verifyMs.push(performance.now() - t1);
  if (!ok) throw new Error('검증 실패');
}

const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
console.log('');
console.log('## pi_cred 실측');
console.log('');
console.log(`| 항목 | 값 |`);
console.log(`|---|--:|`);
console.log(`| 증명 시간 (중앙값, ${N}회) | ${med(proveMs).toFixed(1)} ms |`);
console.log(`| 검증 시간 (중앙값, ${N}회) | ${med(verifyMs).toFixed(1)} ms |`);
console.log(`| zkey 크기 | ${(fs.statSync(ZKEY).size / 1e6).toFixed(1)} MB |`);
console.log(`| 공개 입력 수 | ${publicSignals.length} |`);
process.exit(0);
```

- [ ] **Step 3: 픽스처를 테스트에서 분리한다**

Task 3의 `tests/test_pi_cred_witness.mjs`에 있는 `buildValidInput()`을 `tests/helpers/mode3_fixture.mjs`로 옮기고 `export` 한다. 테스트는 거기서 `import { buildValidInput } from './helpers/mode3_fixture.mjs'` 로 가져다 쓴다. 벤치와 테스트가 같은 입력 생성기를 공유해야 두 측정이 같은 것을 재게 된다.

- [ ] **Step 4: 테스트가 여전히 통과하는지 확인한다**

```bash
node tests/test_pi_cred_witness.mjs
```

Expected: 5줄 전부 `ok` (리팩터링 전과 동일)

- [ ] **Step 5: 실측한다 (사용자 승인 후)**

```bash
node scripts/bench_pi_cred.mjs pot21_final.ptau
```

Expected: 증명·검증 시간과 zkey 크기 표가 출력된다

- [ ] **Step 6: 실측값을 설계 문서에 기록한다**

§11 표 아래에 실측 절을 추가한다:

```markdown
### 11.1 실측값 (2026-09-09)

| 항목 | 값 | 비교 (Mode 2 `pi_pk_i_v3`) |
|---|--:|--:|
| 비선형 제약 | (측정값) | 13,905 |
| 증명 시간 (중앙값) | (측정값) ms | 507.2 ms |
| 검증 시간 (중앙값) | (측정값) ms | — |
| zkey 크기 | (측정값) MB | — |

이 값이 §8.4의 재증명 빈도가 감당 가능한지를 판정하는 근거다.
브라우저는 이 값의 3~5배로 잡는다.
```

- [ ] **Step 7: 커밋**

```bash
git add scripts/bench_pi_cred.mjs tests/helpers/mode3_fixture.mjs \
        tests/test_pi_cred_witness.mjs \
        docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md
git commit -m "feat(mode3): pi_cred 증명 시간 실측 스크립트와 결과 기록"
```

---

## 완료 기준

- [ ] `bash scripts/run_tests.sh unit` 통과
- [ ] `bash scripts/run_tests.sh circuit` 통과
- [ ] 커밋 스킴이 실측으로 확정되어 설계 문서 §11에 기록됨
- [ ] `pi_cred` 제약 수와 증명 시간이 §11.1에 기록됨
- [ ] Mode 2 파일이 하나도 수정되지 않음 (`git diff --stat`으로 확인)
- [ ] 실행 중인 데모(:3000/:4000/:5001)가 그대로 동작함

## 다음 계획

- **(a) 오프체인 전 구간** — `cia.js`(등록·발급·폐기·트리·게시), `RevocationLog` 컨트랙트, RP 로그인 검증, 지갑의 트리 동기화. 이 계획의 커밋 스킴 결정에 따라 발급 PoK의 형태가 정해진다.
- **(b) 온체인 실행** — `RevocationMirror`, `CredentialVerifier`, `PPIDWallet` 연동, 가스 실측.

---

# 추가 (2026-09-10): Pedersen 전환 — Task 5~7

**배경.** Task 2에서 실측 규칙(3배)에 따라 Poseidon을 확정했으나, 사용자가 **발급 경로를 시그마
프로토콜로 두기 위해 우선 Pedersen으로 구현하고 나중에 Poseidon(+`π_issue`)으로 전환**하기로
결정했다(2026-09-10). Task 2의 `CommitPedersen`은 circomlib의 창 기반 `Pedersen(n)` 해시라
시그마 프로토콜을 짜기 어렵다. **교과서 형태로 다시 만든다:**

```
C = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + blind·H        (baby jubjub, 곡선 점)
Cf = Poseidon(Cx, Cy)                                       ← 서명·리프에 들어가는 압축값
```

**추가 Global Constraints (Task 5~7에 적용):**
- 스칼라 상한은 **2^250**이다. baby jubjub 소수 부분군 위수 `r`은 251비트(≈2^251.4)이므로
  `2^250 < r`. 회로는 `Num2Bits(250)`으로 강제하고, JS `credCommit`은 같은 상한을 throw로
  강제한다. **이 검사가 없으면 `e`와 `e+r`이 같은 점을 만들어 binding이 깨지고**, 한 `C`를
  두 `s_u`로 열어 `PPID` 두 개를 얻는 Sybil이 가능해진다.
- 생성원 5개는 circomlib `circuits/lib/pedersen.circom`의 `BASE[0..4]`(NUMS 점)를 그대로
  쓴다. 2026-09-10에 circomlibjs로 **5개 모두 `inCurve`·`inSubgroup` true**를 확인했다.
  순서: `G₁=BASE[0]`(uid), `G₂=BASE[1]`(arid), `G₃=BASE[2]`(s_u), `G₄=BASE[3]`(pk_i),
  `H=BASE[4]`(blind).
- 제약 수가 16,384를 넘을 것이 확실하므로(추정 약 19,900) zkey 셋업은 **`pot21_final.ptau`**로 한다.
  새 ptau를 만들지 않는다.
- 공개 입력 순서 `[PPID, arid, pk_i, max_height, revRoot, pk_CIA_x, pk_CIA_y]`는 **바뀌지 않는다.**
- `CommitPoseidon` 템플릿과 그 측정 테스트는 **남겨 둔다** — 나중 전환의 기준선이다.

---

### Task 5: 교과서 Pedersen 커밋 — 회로·JS·일치 테스트

**Files:**
- Modify: `circuits/lib/mode3_commit.circom` (`CommitPedersen` 본문 교체)
- Modify: `lib/mode3_credential.js` (`credCommit`을 Pedersen으로, `credCommitPoseidon`은 보존)
- Modify: `tests/test_mode3_commit_scheme.mjs` (Pedersen `(Cx, Cy)` 일치 테스트 추가, 상한 테스트 추가)
- Modify: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` (§11 커밋 스킴 행에 교과서 Pedersen 실측 추가)

**Interfaces:**
- Consumes: circomlib `EscalarMulFix(n, BASE)` (`e[n]` 비트 입력, `out[2]` 출력), `BabyAdd()`, `Num2Bits(n)`; circomlibjs `buildBabyjub()` → `mulPointEscalar(P, e)`, `addPoint(a, b)`, `F`
- Produces:
  - circom `CommitPedersen()` — 입력 `uid, arid, s_u, blind, pk_i`, 출력 `Cx, Cy`. 각 입력을 `Num2Bits(250)`으로 범위 제한
  - JS `export const SCALAR_BITS = 250`, `export const SCALAR_MAX = 1n << 250n`
  - JS `export const PEDERSEN_GENERATORS = { uid, arid, s_u, pk_i, blind }` (각 `[x, y]` bigint)
  - JS `async credCommit({ uid, arid, s_u, blind, pk_i }) → { Cx, Cy, Cf }` — 상한 위반 시 throw
  - JS `async credCommitPoseidon({...}) → bigint` — 기존 Poseidon 판 (전환 기준선용)

- [ ] **Step 1: 실패하는 테스트를 쓴다**

`tests/test_mode3_commit_scheme.mjs`에 다음을 **추가**한다 (기존 테스트는 그대로 둔다). 파일 상단 import에 `credCommit, SCALAR_MAX, PEDERSEN_GENERATORS` from `'../lib/mode3_credential.js'`와 `buildBabyjub` from `'circomlibjs'`를 추가한다.

```js
await t('Pedersen 판: 회로의 (Cx, Cy) 가 JS credCommit 과 일치한다', async () => {
  const w = await witness('pedersen', INPUT);
  // main 출력은 witness[1], witness[2] (Cx, Cy)
  const { Cx, Cy } = await credCommit({
    uid: BigInt(INPUT.uid), arid: BigInt(INPUT.arid), s_u: BigInt(INPUT.s_u),
    blind: BigInt(INPUT.blind), pk_i: BigInt(INPUT.pk_i),
  });
  assert.equal(w[1].toString(), Cx.toString(), 'Cx 불일치 — 생성원 순서나 스칼라 인코딩이 어긋났다');
  assert.equal(w[2].toString(), Cy.toString(), 'Cy 불일치');
});

await t('Pedersen 판: 생성원 5개가 곡선 위·소수 부분군 안에 있다', async () => {
  const bj = await buildBabyjub();
  for (const [name, g] of Object.entries(PEDERSEN_GENERATORS)) {
    const P = [bj.F.e(g[0]), bj.F.e(g[1])];
    assert.ok(bj.inCurve(P), `${name} 가 곡선 위에 없다`);
    assert.ok(bj.inSubgroup(P), `${name} 가 소수 부분군 밖이다 — binding 논증이 깨진다`);
  }
});

await t('Pedersen 판: 스칼라가 2^250 이상이면 JS 가 거부한다 (회로의 Num2Bits(250) 과 같은 상한)', async () => {
  await assert.rejects(
    () => credCommit({ uid: 1n, arid: 2n, s_u: SCALAR_MAX, blind: 4n, pk_i: 5n }),
    /2\^250/,
  );
});

await t('Pedersen 판: 회로도 2^250 이상 스칼라를 거부한다', async () => {
  await assert.rejects(
    () => witness('pedersen', { ...INPUT, s_u: SCALAR_MAX.toString() }),
    /Assert Failed/,
  );
});
```

- [ ] **Step 2: 실패를 확인한다**

```bash
node tests/test_mode3_commit_scheme.mjs
```

Expected: `credCommit` 가 `{Cx, Cy}` 를 돌려주지 않아(현재 Poseidon bigint) 첫 신규 테스트가 실패하고, `PEDERSEN_GENERATORS`·`SCALAR_MAX` import 가 undefined 라 나머지도 실패

- [ ] **Step 3: 회로를 교체한다**

`circuits/lib/mode3_commit.circom`의 `CommitPedersen` 템플릿 **전체를** 아래로 바꾼다. 파일 상단 include에 `escalarmulfix.circom`과 `babyjub.circom`을 추가하고, 더 이상 쓰지 않는 `pedersen.circom` include는 제거한다. `CommitPoseidon`은 손대지 않는다.

```circom
// 교과서 Pedersen 벡터 커밋 (2026-09-10, circomlib Pedersen 해시 판을 대체).
//
//   C = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + blind·H
//
// 왜 교과서 형태인가. circomlib 의 Pedersen(n) 은 비트를 4비트 창으로 잘라 부호 반전을 섞는
// 인코딩이라, 그 위에서 발급 시 시그마 프로토콜(§6.2)을 짜면 이웃 스칼라와 세그먼트를
// 공유하는 문제가 생긴다. 스칼라마다 생성원을 따로 두면 PoK 가 교과서 그대로다.
//
// 스칼라 상한 2^250. baby jubjub 소수 부분군 위수 r 은 251비트(≈2^251.4)라 2^250 < r.
// 이 검사가 없으면 e 와 e+r 이 같은 점을 만들어 binding 이 깨진다 — 한 C 를 두 s_u 로
// 열어 PPID 두 개를 얻는 Sybil 이 가능해진다. lib/mode3_credential.js 도 같은 상한을 지킨다.
//
// 생성원은 circomlib pedersen.circom 의 NUMS 점 BASE[0..4]. 서로의 이산로그를 아무도 모른다.
// 2026-09-10 circomlibjs 로 5개 모두 inCurve·inSubgroup 확인.
template CommitPedersen() {
    signal input uid;
    signal input arid;
    signal input s_u;
    signal input blind;
    signal input pk_i;
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
    var H_BLIND[2] = [20265828622013100949498132415626198973119240347465898028410217039057588424236,
                      1160461593266035632937973507065134938065359936056410650153315956301179689506];

    component bUid   = Num2Bits(N);  bUid.in   <== uid;
    component bArid  = Num2Bits(N);  bArid.in  <== arid;
    component bSu    = Num2Bits(N);  bSu.in    <== s_u;
    component bPki   = Num2Bits(N);  bPki.in   <== pk_i;
    component bBlind = Num2Bits(N);  bBlind.in <== blind;

    component mUid   = EscalarMulFix(N, G_UID);
    component mArid  = EscalarMulFix(N, G_ARID);
    component mSu    = EscalarMulFix(N, G_SU);
    component mPki   = EscalarMulFix(N, G_PKI);
    component mBlind = EscalarMulFix(N, H_BLIND);
    for (var i = 0; i < N; i++) {
        mUid.e[i]   <== bUid.out[i];
        mArid.e[i]  <== bArid.out[i];
        mSu.e[i]    <== bSu.out[i];
        mPki.e[i]   <== bPki.out[i];
        mBlind.e[i] <== bBlind.out[i];
    }

    // 덧셈 순서: uid + arid + s_u + pk_i + blind. JS 와 같은 순서 (결과는 순서와 무관하지만
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
    component a4 = BabyAdd();
    a4.x1 <== a3.xout;       a4.y1 <== a3.yout;
    a4.x2 <== mBlind.out[0]; a4.y2 <== mBlind.out[1];

    Cx <== a4.xout;
    Cy <== a4.yout;
}
```

- [ ] **Step 4: JS 를 쓴다**

`lib/mode3_credential.js`에서 기존 `credCommit`을 `credCommitPoseidon`으로 **개명**하고(본문 유지, 주석에 "Poseidon 전환 시 기준선" 명시), 아래를 **추가**한다. `import { buildBabyjub, buildPoseidon } from 'circomlibjs'`로 바꾼다.

```js
// ---- 교과서 Pedersen 커밋 (2026-09-10 부터 현행) ----
// circuits/lib/mode3_commit.circom 의 CommitPedersen 과 정확히 같은 생성원·순서·상한.

export const SCALAR_BITS = 250;
export const SCALAR_MAX = 1n << 250n;   // 회로의 Num2Bits(250). r(≈2^251.4) 미만이라 binding 이 유지된다

// circomlib pedersen.circom BASE[0..4]. 회로 파일의 G_UID/G_ARID/G_SU/G_PKI/H_BLIND 와 글자 단위로 같아야 한다.
export const PEDERSEN_GENERATORS = Object.freeze({
  uid:   [10457101036533406547632367118273992217979173478358440826365724437999023779287n,
          19824078218392094440610104313265183977899662750282163392862422243483260492317n],
  arid:  [2671756056509184035029146175565761955751135805354291559563293617232983272177n,
          2663205510731142763556352975002641716101654201788071096152948830924149045094n],
  s_u:   [5802099305472655231388284418920769829666717045250560929368476121199858275951n,
          5980429700218124965372158798884772646841287887664001482443826541541529227896n],
  pk_i:  [7107336197374528537877327281242680114152313102022415488494307685842428166594n,
          2857869773864086953506483169737724679646433914307247183624878062391496185654n],
  blind: [20265828622013100949498132415626198973119240347465898028410217039057588424236n,
          1160461593266035632937973507065134938065359936056410650153315956301179689506n],
});

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
```

(`getPoseidon`은 파일에 이미 있는 캐시 헬퍼를 쓴다.)

- [ ] **Step 5: 통과와 제약 수를 확인한다**

```bash
node tests/test_mode3_commit_scheme.mjs
```

Expected: 기존 테스트 + 신규 4건 전부 `ok`. 표에 `pedersen` 제약 수가 새 값으로 출력된다(추정 약 5,000). **이 값을 기록한다.**

- [ ] **Step 6: 설계 문서 §11 에 기록한다**

§11 표의 커밋 스킴 행을 다음으로 바꾼다 (숫자는 실측값으로):

```markdown
| 커밋 스킴 | **현행: 교과서 Pedersen** `C = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + blind·H` (실측 N 제약). Poseidon 은 321 로 15배 싸다고 실측됐으나(2026-09-09), 발급 경로를 시그마 프로토콜로 두기 위해 우선 Pedersen 으로 구현하고 **나중에 Poseidon + π_issue 로 전환**한다(2026-09-10 결정). circomlib Pedersen 해시(4,827)는 창 인코딩 때문에 시그마 프로토콜에 부적합해 쓰지 않는다 |
```

- [ ] **Step 7: 커밋**

```bash
git add circuits/lib/mode3_commit.circom lib/mode3_credential.js \
        tests/test_mode3_commit_scheme.mjs docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md
git commit -m "feat(mode3): 교과서 Pedersen 커밋 — 회로·JS·(Cx,Cy) 일치 테스트, 스칼라 상한 2^250"
```

---

### Task 6: `pi_cred` 를 Pedersen 으로 전환, zkey 재생성, 재실측

**Files:**
- Modify: `circuits/pi_cred.circom`
- Modify: `tests/helpers/mode3_fixture.mjs`
- Modify: `tests/test_pi_cred_witness.mjs` (리프 일치 테스트가 `Cf` 기준이 되도록)
- Modify: `scripts/bench_pi_cred.mjs` (ptau 인자 안내만)
- Modify: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` (§11.1 재실측)

**Interfaces:**
- Consumes: Task 5의 `CommitPedersen`, `credCommit → {Cx, Cy, Cf}`
- Produces: 회로 내부 신호 `Cf`(= `Poseidon(Cx, Cy)`)가 서명 메시지와 리프에 들어간다. 공개 입력 순서 **불변**. `build/mode3/pi_cred_final.zkey`(pot21 기준), `pi_cred_vkey.json`

- [ ] **Step 1: 픽스처와 테스트를 먼저 바꾼다 (실패 확인)**

`tests/helpers/mode3_fixture.mjs`의 `buildValidInput()`에서 `const C = await credCommit({...})` 부분을 `const { Cf: C } = await credCommit({...})`로 바꾼다 (이후 `C`를 쓰는 곳은 그대로 — 서명 메시지·반환값 모두 `Cf`를 쓰게 된다). 상한 규약에 맞게 픽스처의 `blind`와 `s_u`가 `2^250` 미만인지 확인한다 (현재 값 `333…`, `444…`는 20자리라 충분히 작다).

```bash
node tests/test_pi_cred_witness.mjs
```

Expected: 양성 테스트 **실패** — 회로는 아직 `CommitPoseidon`으로 `C`를 계산하는데 픽스처의 서명은 `Cf`에 대한 것이라 서명 검증이 `Assert Failed`

- [ ] **Step 2: 회로를 전환한다**

`circuits/pi_cred.circom`의 `// ---- C 계산 ----` 블록을 아래로 바꾼다. 나머지(서명·PPID·비멤버십·`main`)는 `C` 자리에 `Cf`가 들어가는 것 외에 바뀌지 않는다.

```circom
    // ---- C 계산 (교과서 Pedersen, 2026-09-10) ----
    // C 는 곡선 점 (Cx, Cy). 서명 메시지와 폐기 리프에는 Poseidon(Cx, Cy) 로 압축한 Cf 를 넣는다.
    // 압축 해시가 하나 더 붙지만(약 240 제약) 리프 규약 leafValue(tag, raw) 와 서명 메시지
    // Poseidon(DOMAIN, ·, max_height) 를 Poseidon 판과 같은 모양으로 유지할 수 있다 —
    // 나중에 Poseidon 으로 되돌릴 때 이 블록만 바꾸면 된다.
    component commit = CommitPedersen();
    commit.uid   <== uid;
    commit.arid  <== arid;
    commit.s_u   <== s_u;
    commit.blind <== blind;
    commit.pk_i  <== pk_i;

    component cf = Poseidon(2);
    cf.inputs[0] <== commit.Cx;
    cf.inputs[1] <== commit.Cy;
    signal Cf;
    Cf <== cf.out;
```

그리고 아래 세 곳의 `C`를 `Cf`로 바꾼다: `msgHasher.inputs[1] <== Cf;`, `leafHasher.inputs[1] <== Cf;`. (③ PPID 블록은 `C`를 쓰지 않으므로 그대로.) 상단 주석의 ② 설명에 "Pedersen 점을 Poseidon 으로 압축한 Cf" 한 줄을 덧붙인다.

- [ ] **Step 3: 통과를 확인한다**

```bash
node tests/test_pi_cred_witness.mjs
```

Expected: 6/6 `ok`. 리프 일치 테스트는 `credLeaf(validC)`(`validC`가 이제 `Cf`)와 회로의 `leafHasher.out`을 대조하므로 그대로 통과해야 한다. **제약 수를 기록한다** (추정 약 19,900).

- [ ] **Step 4: zkey 를 pot21 로 재생성하고 재실측한다**

기존 pot14 산출물을 지운 뒤 pot21 로 만든다 (`build/` 아래만):

```bash
rm -f build/mode3/pi_cred_0000.zkey build/mode3/pi_cred_final.zkey build/mode3/pi_cred_vkey.json
node scripts/bench_pi_cred.mjs pot21_final.ptau
```

Expected: 셋업 수 분(2.4GB ptau 읽기), 이후 증명·검증 시간 표. `scripts/bench_pi_cred.mjs` 상단 사용법 주석의 예시 ptau 를 `pot21_final.ptau`로 바꾸고, "제약이 16,384 를 넘으면 pot14 로는 셋업이 실패한다"를 한 줄 적는다.

- [ ] **Step 5: `run_tests.sh circuit` 한 번**

```bash
bash scripts/run_tests.sh circuit
```

Expected: 전부 통과

- [ ] **Step 6: §11.1 을 재실측값으로 갱신한다**

§11.1 표를 Pedersen 기준으로 바꾸되, **Poseidon 판 수치를 비교 열로 남긴다**:

```markdown
| 항목 | Pedersen (현행, 2026-09-10) | Poseidon (2026-09-09, 전환 기준선) | Mode 2 `pi_pk_i_v3` |
|---|--:|--:|--:|
| 비선형 제약 | (실측) | 15,008 | 13,905 |
| 증명 시간 (중앙값) | (실측) ms | 514.0 ms | 507.2 ms |
| 검증 시간 (중앙값) | (실측) ms | 22.0 ms | — |
| zkey 크기 | (실측) MB | 9.0 MB | — |
| 사용 ptau | pot21_final.ptau (2^21) | pot14_final.ptau (2^14) | pot21 |
| 도메인 여유 | (실측) | 1,368 | — |
```

- [ ] **Step 7: 커밋**

```bash
git add circuits/pi_cred.circom tests/helpers/mode3_fixture.mjs tests/test_pi_cred_witness.mjs \
        scripts/bench_pi_cred.mjs docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md
git commit -m "feat(mode3): pi_cred 를 교과서 Pedersen 으로 전환, pot21 재셋업·재실측"
```

---

### Task 7: 설계 문서를 Pedersen 기준으로 되돌리되 결정 이력을 남긴다

**Files:**
- Modify: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` (§4.1, §6.1, §6.2, §11, §12)

**Interfaces:** 없음 (문서만)

- [ ] **Step 1: §4.1**

`C = Commit(uid, arid, s_u, blind, pk_i) ← Poseidon 커밋. blind 가 은닉을 담당 (§11 실측으로 확정)` 를 다음으로:

```
C          = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + blind·H     ← 교과서 Pedersen (baby jubjub). blind 가 은닉
Cf         = Poseidon(Cx, Cy)                                    ← 서명·리프용 압축값
credential = (C, max_height, σ_CIA)
             σ_CIA = EdDSA-Poseidon.Sign(sk_CIA, Poseidon(DOMAIN, Cf ‖ max_height))
폐기 리프    = Poseidon(3, Cf)
```

그 아래에 한 문단: **"스칼라 상한 2^250. baby jubjub 소수 부분군 위수 r 은 251비트라 2^250 < r. 이 상한이 없으면 `e`와 `e+r`이 같은 점을 만들어 한 `C`를 두 `s_u`로 열 수 있고(Sybil), 회로(`Num2Bits(250)`)와 CIA(`credCommit`)가 함께 강제한다."**

- [ ] **Step 2: §6.1 등록**

`cm_u = Poseidon(s_u, r_u)` → `cm_u = s_u·G₃ + r_u·H  (같은 G₃·H. r_u 는 사용자가 보관하는 블라인딩)`.

- [ ] **Step 3: §6.2 발급 — 시그마 프로토콜로 되돌린다**

단계 2와 그 아래 설명 문단을 다음으로 교체한다:

```
2. 사용자 → CIA:
     C
     π_issue : Schnorr 시그마 프로토콜 (SNARK 아님)
        공개:   uid, cm_u, C
        증명:   C − uid·G₁ = arid·G₂ + s_u·G₃ + pk_i·G₄ + blind·H   의 (arid, s_u, pk_i, blind) 를 알고
                cm_u        = s_u·G₃ + r_u·H                        의 (s_u, r_u) 를 알며
                두 식의 s_u 가 같다                                  (동일 응답값 공유)
     Sign(sk_u, C)
```

설명 문단: **"`uid`는 CIA가 아는 값이라 커밋에서 빼고 검사한다. 커밋이 스칼라마다 생성원을 따로 가지므로 `s_u` 동일성은 교과서 equality-of-committed-value 로 끝난다 — 회로도 셋업도 없고 수 ms 다. 이것이 Pedersen 을 먼저 택한 이유다. `sk_i` 소지 증명은 넣지 않는다 (secp256k1 주소를 시그마 프로토콜로도 SNARK 로도 싸게 잇지 못한다. 막는 공격은 §2.2 의 자발적 양도)."**

- [ ] **Step 4: §11**

- `cm_u 동일성 증명` 행: `**시그마 프로토콜 (equality-of-committed-value)**. Poseidon 전환 시 π_issue 안으로 들어간다`
- `커밋 스킴 결정의 근거 범위` 행: `Poseidon 이 show 회로에서 15배 싸다고 실측됐으나, 발급 경로 단순성을 우선해 **Pedersen 으로 먼저 구현**(2026-09-10). Poseidon 전환은 π_issue 회로·셋업이 준비되면 한다`
- 새 행: `Poseidon 전환 시 바뀌는 것 | pi_cred 의 C 계산 블록, lib credCommit, §4.1/§6.1/§6.2 의 커밋 형태, π_issue 회로 신설. 공개 입력·리프 규약·서명 메시지 모양은 그대로 (Cf 자리에 Poseidon 출력이 들어갈 뿐)`

- [ ] **Step 5: §12 (a)**

`circuits/pi_issue.circom` 불릿을 제거하고 대신: `- 발급 시그마 프로토콜 (lib/mode3_issuance.js): §6.2 의 π_issue. SNARK 아님. CIA 가 검증`. 그리고 §12 끝에 **"Poseidon 전환 (보류)"** 소절을 추가: `pi_cred C 블록 교체 → credCommit 교체 → pi_issue 회로 신설·셋업 → §4.1/§6.x 갱신. 전환 시 공개 입력 순서와 리프 규약은 유지된다.`

- [ ] **Step 6: 전체 grep 으로 잔재 확인**

```bash
grep -n "Poseidon 커밋\|Poseidon(s_u, r_u)\|π_issue : ZK\|pi_issue.circom" docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md
```

Expected: §11 "전환 시" 설명과 §12 "보류" 소절 안의 언급만 남고, 현행 설명에는 없음

- [ ] **Step 7: 커밋**

```bash
git add docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md
git commit -m "docs(mode3): Pedersen 우선 구현으로 설계 본문 갱신, Poseidon 전환은 보류 항목으로"
```

---

## 완료 기준 (Task 5~7 추가분)

- [ ] `test_mode3_commit_scheme.mjs` 에서 Pedersen `(Cx, Cy)` 가 JS 와 일치
- [ ] `pi_cred` 6/6 통과, 리프 일치 테스트가 `Cf` 기준으로 통과
- [ ] pot21 로 zkey 재생성, §11.1 에 Pedersen/Poseidon 두 열 실측
- [ ] 설계 문서 본문이 Pedersen 현행 + Poseidon 보류로 일관
