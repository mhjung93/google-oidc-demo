# BAAR 기반 PairCT Revocation 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** IdP가 세션(`r_token`)과 계정(`auid`) 단위로 폐기할 수 있도록, indexed Merkle tree 비멤버십 증명을 `pi_pk_i` 회로에 넣고 root를 온체인 registry로 관리한다.

**Architecture:** IdP가 폐기 항목을 하나의 indexed Merkle tree(IMT)에 넣고 root만 `RevocationRegistry` 컨트랙트에 게시한다. 지갑은 `pi_pk_i` 증명 안에서 자기 `r_token`과 `auid`가 그 트리에 없음을 보인다. 폐기 대상은 회로 밖으로 나오지 않으므로 cross-service unlinkability가 유지된다. `PPIDWallet.execute()`는 증명에 쓰인 root가 최근 K개 안에 있는지만 확인한다(grace window).

**Tech Stack:** circom 2.1.9, circomlib, snarkjs 0.5.0 (Groth16), Solidity ^0.8.24, Hardhat, Node.js (ESM/CJS 혼용), circomlibjs

**설계 문서:** `docs/superpowers/specs/2026-08-23-baar-revocation-design.md`

> **spec과의 차이:** spec §2 비목표에 "구현은 범위 밖"이라고 적혀 있으나, 이후 구현 진행이 결정되었다. 본 계획은 spec §4(아키텍처)·§5(데이터 흐름)를 구현 대상으로 삼고, spec §8(검증 계획)의 "IMT 비용 확정"을 Task 1으로 앞당긴다.

## Global Constraints

- 폐기 단위는 **세션(`r_token`)과 계정(`auid`) 둘뿐**이다. PPID 단위는 구현하지 않는다 (IdP가 `ppid`를 알 수 없음).
- **`r_token`을 public input으로 올리지 않는다.** IdP의 `issuanceLog`(r_token → uid)와 온체인 지갑을 잇는 다리가 생겨 unlinkability가 무너진다.
- **`auid`를 public input으로 올리지 않는다.** 같은 계정의 여러 PPID 지갑이 온체인에서 연결된다.
- 도메인 태그 값은 `TAG_SESSION = 1`, `TAG_ACCOUNT = 2`로 고정한다.
- IMT 깊이는 `20`으로 고정한다 (2^20 ≈ 100만 항목).
- grace window 크기는 `K = 8`로 고정한다.
- 기존 회로 `pi_arid_i`, `pi_ppid`는 **변경하지 않는다.**
- 빌드는 `scripts/build_mode2_circuits.sh`를 통해서만 한다. ptau는 기존 `pot14_final.ptau`를 쓰되, 회로가 커져 부족하면 Task 3에서 상향한다.
- 테스트는 `tests/` 아래 단독 node 스크립트로 작성하고 `node tests/<name>` 으로 실행한다. 성공 시 `console.log('PASS: ...')`, 실패 시 `process.exit(1)`.
- 커밋은 각 Task 끝에서 한 번씩 한다. 브랜치는 `feat/baar-revocation`이며 롤백 기준점은 `ca94cec`다.

---

## File Structure

**신규**
- `circuits/lib/imt_nonmembership.circom` — IMT 비멤버십 검증 템플릿 (회로 재사용 단위)
- `lib/imt.js` — IMT 자료구조 (삽입, root 계산, 비멤버십 witness 생성). IdP와 wallet_agent가 공유
- `contracts/RevocationRegistry.sol` — root 순환 버퍼
- `scripts/push_revocation_root.cjs` — IdP의 root를 registry에 게시하는 오퍼레이터 스크립트
- `tests/test_imt_nonmembership_circuit.mjs`
- `tests/test_imt_lib.js`
- `test/RevocationRegistry.test.mjs`
- `tests/test_pi_pk_i_revocation.mjs`
- `tests/test_idp_revoke_endpoint.js`

**수정**
- `circuits/pi_pk_i.circom` — public input `revocationRoot` 추가, 바인딩 제약, 비멤버십 2회
- `contracts/PPIDWallet.sol` — `execute()`에 `revocationRoot` 인자, registry 조회, pubSignals 6개
- `custom_idp.js` — `POST /idp/revoke`, IMT 유지, `pushRoot` 호출
- `wallet_agent.js` — root·witness 조회, 증명 캐싱
- `scripts/build_mode2_circuits.sh` — 필요 시 ptau 상향

---

## Task 1: IMT 비멤버십 회로 컴포넌트

가장 불확실한 비용(spec은 9,720으로 추정)을 먼저 확정한다. 이 값에 따라 이후 설계 판단이 달라질 수 있다.

**Files:**
- Create: `circuits/lib/imt_nonmembership.circom`
- Test: `tests/test_imt_nonmembership_circuit.mjs`
- Create: `circuits/test_imt_only.circom` (측정 전용, Task 3에서 삭제)

**Interfaces:**
- Consumes: 없음
- Produces: `IMTNonMembership(depth)` 템플릿. 입력 `target`, `lowValue`, `lowNextValue`, `pathElements[depth]`, `pathIndices[depth]`, `root`. 출력 없음(제약만).

- [ ] **Step 1: 회로 템플릿 작성**

`circuits/lib/imt_nonmembership.circom`:

```circom
pragma circom 2.0.0;

include "poseidon.circom";
include "comparators.circom";
include "mux1.circom";
include "bitify.circom";

// Indexed Merkle Tree 비멤버십 증명.
//
// 리프는 값 순으로 정렬돼 있고 각 리프가 (value, nextValue)를 담는다.
// target이 트리에 없음을 보이려면, lowValue < target < lowNextValue 를
// 만족하는 리프 하나가 트리 안에 있음을 보이면 된다.
// lowNextValue == 0 은 "이 리프가 가장 큰 값"이라는 sentinel이므로,
// 그 경우 target < lowNextValue 검사를 건너뛴다.
template IMTNonMembership(depth) {
    signal input target;
    signal input lowValue;
    signal input lowNextValue;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input root;

    // 1) 리프 해시 = Poseidon(lowValue, lowNextValue)
    component leafHash = Poseidon(2);
    leafHash.inputs[0] <== lowValue;
    leafHash.inputs[1] <== lowNextValue;

    // 2) Merkle 경로 검증
    component h[depth];
    component muxL[depth];
    component muxR[depth];
    signal cur[depth + 1];
    cur[0] <== leafHash.out;

    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;
        muxL[i] = Mux1();
        muxL[i].c[0] <== cur[i];
        muxL[i].c[1] <== pathElements[i];
        muxL[i].s <== pathIndices[i];
        muxR[i] = Mux1();
        muxR[i].c[0] <== pathElements[i];
        muxR[i].c[1] <== cur[i];
        muxR[i].s <== pathIndices[i];
        h[i] = Poseidon(2);
        h[i].inputs[0] <== muxL[i].out;
        h[i].inputs[1] <== muxR[i].out;
        cur[i + 1] <== h[i].out;
    }
    root === cur[depth];

    // 3) 비교 전에 모든 피연산자를 252비트로 제한한다.
    //
    // circomlib의 LessThan(n)은 입력이 [0, 2^n) 범위라고 "가정"할 뿐 강제하지
    // 않는다. 우리 값은 Poseidon 출력이라 필드 전역에 균등 분포하고 약 67%가
    // 2^252를 넘으므로, 이 가정을 지키지 않으면 필드 wrap-around로 비교 결과가
    // 뒤집힌다(예: lowValue = p-1, target = 5 이면 회로가 lowValue < target 을
    // 참으로 판정한다). 그러면 폐기된 값도 비멤버십 증명을 통과시킬 수 있다.
    //
    // target은 호출자가 Poseidon 출력을 그대로 넘기므로 여기서 하위 252비트만
    // 취해 정규화하고, 트리에서 온 lowValue/lowNextValue는 이미 정규화된
    // 값이어야 하므로 범위만 검사한다. lib/imt.js도 같은 마스킹을 적용한다.
    component targetBits = Num2Bits_strict();
    targetBits.in <== target;
    signal targetMasked;
    var acc = 0;
    for (var i = 0; i < 252; i++) {
        acc += targetBits.out[i] * (1 << i);
    }
    targetMasked <== acc;

    component lowRange = Num2Bits(252);
    lowRange.in <== lowValue;
    component nextRange = Num2Bits(252);
    nextRange.in <== lowNextValue;

    // 4) lowValue < targetMasked
    component ltLow = LessThan(252);
    ltLow.in[0] <== lowValue;
    ltLow.in[1] <== targetMasked;
    ltLow.out === 1;

    // 5) targetMasked < lowNextValue, 단 lowNextValue == 0 이면 통과
    component isLast = IsZero();
    isLast.in <== lowNextValue;

    component ltHigh = LessThan(252);
    ltHigh.in[0] <== targetMasked;
    ltHigh.in[1] <== lowNextValue;

    // isLast == 1 이면 1, 아니면 ltHigh.out 이어야 한다
    component pick = Mux1();
    pick.c[0] <== ltHigh.out;
    pick.c[1] <== 1;
    pick.s <== isLast.out;
    pick.out === 1;
}
```

- [ ] **Step 2: 측정 전용 래퍼 작성**

`circuits/test_imt_only.circom`:

```circom
pragma circom 2.0.0;
include "lib/imt_nonmembership.circom";
component main {public [root]} = IMTNonMembership(20);
```

- [ ] **Step 3: 컴파일해서 constraint 수 확인**

```bash
mkdir -p /tmp/imt_measure
circom circuits/test_imt_only.circom --r1cs -o /tmp/imt_measure \
  -l circuits -l circuits/lib -l node_modules/circomlib/circuits
```

Expected: `non-linear constraints:` 값이 출력된다. 경로 4,860 + 비교 로직 + 252비트 정규화(`Num2Bits_strict` 1개 + `Num2Bits(252)` 2개)가 더해져 **6,500~7,500** 사이가 예상된다.

측정값을 기록한다. **이 값의 2배가 Task 3에서 `pi_pk_i`에 더해질 비용**이다.

- [ ] **Step 4: 회로 동작 테스트 작성**

`tests/test_imt_nonmembership_circuit.mjs`:

```javascript
import { buildPoseidon } from 'circomlibjs';
import fs from 'fs';

const DEPTH = 20;

// 테스트용 최소 IMT: 리프 2개짜리 트리를 손으로 만든다.
async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const H = (a, b) => F.toObject(poseidon([a, b]));

  // 리프: (10, 20) — 값 10이고 다음 값이 20. 따라서 10 < x < 20 인 x는 트리에 없다.
  const lowValue = 10n;
  const lowNextValue = 20n;
  const leaf = H(lowValue, lowNextValue);

  // 깊이 20 경로를 전부 0으로 채워 root를 계산한다.
  const pathElements = [];
  const pathIndices = [];
  let cur = leaf;
  for (let i = 0; i < DEPTH; i++) {
    pathElements.push(0n);
    pathIndices.push(0);
    cur = H(cur, 0n);
  }
  const root = cur;

  const wc = await import('/tmp/imt_measure/test_imt_only_js/witness_calculator.js');
  const wasmBuffer = await fs.promises.readFile('/tmp/imt_measure/test_imt_only_js/test_imt_only.wasm');
  const calc = await wc.default(wasmBuffer);

  const base = {
    lowValue: lowValue.toString(),
    lowNextValue: lowNextValue.toString(),
    pathElements: pathElements.map(String),
    pathIndices: pathIndices.map(String),
    root: root.toString(),
  };

  // 1) 15는 10과 20 사이 -> 비멤버십 증명 성공
  await calc.calculateWitness({ ...base, target: '15' }, true);
  console.log('OK: 15 is provably absent');

  // 2) 10은 리프 값 자체 -> lowValue < target 위반으로 실패해야 함
  let rejected = false;
  try {
    await calc.calculateWitness({ ...base, target: '10' }, true);
  } catch { rejected = true; }
  if (!rejected) { console.error('FAIL: target == lowValue was accepted'); process.exit(1); }
  console.log('OK: target == lowValue rejected');

  // 3) 25는 구간 밖 -> target < lowNextValue 위반으로 실패해야 함
  rejected = false;
  try {
    await calc.calculateWitness({ ...base, target: '25' }, true);
  } catch { rejected = true; }
  if (!rejected) { console.error('FAIL: out-of-range target was accepted'); process.exit(1); }
  console.log('OK: out-of-range target rejected');

  console.log('PASS: IMT non-membership circuit enforces low < target < next.');
}

main();
```

- [ ] **Step 5: 컴파일에 wasm 포함해 재빌드 후 테스트 실행**

```bash
circom circuits/test_imt_only.circom --r1cs --wasm -o /tmp/imt_measure \
  -l circuits -l circuits/lib -l node_modules/circomlib/circuits
node tests/test_imt_nonmembership_circuit.mjs
```

Expected: `PASS: IMT non-membership circuit enforces low < target < next.`

- [ ] **Step 6: sentinel(마지막 리프) 경로 테스트 추가**

`tests/test_imt_nonmembership_circuit.mjs`의 `console.log('PASS: ...')` 바로 앞에 삽입:

```javascript
  // 4) lowNextValue == 0 (가장 큰 리프) 이면 상한 검사를 건너뛴다
  const sentinelLeaf = H(100n, 0n);
  let sc = sentinelLeaf;
  for (let i = 0; i < DEPTH; i++) sc = H(sc, 0n);
  await calc.calculateWitness({
    target: '99999',
    lowValue: '100',
    lowNextValue: '0',
    pathElements: pathElements.map(String),
    pathIndices: pathIndices.map(String),
    root: sc.toString(),
  }, true);
  console.log('OK: sentinel leaf allows arbitrarily large target');
```

- [ ] **Step 7: 테스트 재실행**

```bash
node tests/test_imt_nonmembership_circuit.mjs
```

Expected: 4개 `OK:` 줄과 `PASS:` 줄이 모두 출력된다.

- [ ] **Step 8: 커밋**

```bash
git add circuits/lib/imt_nonmembership.circom circuits/test_imt_only.circom tests/test_imt_nonmembership_circuit.mjs
git commit -m "feat(revocation): add IMT non-membership circuit template

Depth-20 indexed Merkle tree non-membership: proves low < target < next
against a Merkle root, with lowNextValue == 0 as the +infinity sentinel.
Measured constraint count recorded in the plan."
```

---

## Task 2: JS IMT 라이브러리

IdP가 트리를 유지하고, 지갑이 witness를 계산하려면 같은 자료구조가 양쪽에 필요하다. 한 파일로 만들어 공유한다.

**Files:**
- Create: `lib/imt.js`
- Test: `tests/test_imt_lib.js`

**Interfaces:**
- Consumes: Task 1의 회로가 기대하는 리프 형식 `Poseidon(value, nextValue)`
- Produces:
  - `createIMT(depth)` → `{ insert(value), getRoot(), getNonMembershipWitness(target) }`
  - `getNonMembershipWitness(target)` → `{ lowValue, lowNextValue, pathElements, pathIndices, root }` (모두 문자열/문자열 배열)
  - `TAG_SESSION = 1n`, `TAG_ACCOUNT = 2n`
  - `leafValue(tag, raw)` → `bigint` (= `Poseidon(tag, raw)`)

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_imt_lib.js`:

```javascript
import assert from 'node:assert/strict';
import { createIMT, leafValue, TAG_SESSION, TAG_ACCOUNT } from '../lib/imt.js';

async function main() {
  const tree = await createIMT(20);

  // 빈 트리: 무엇이든 비멤버
  const w0 = await tree.getNonMembershipWitness(12345n);
  assert.ok(w0.root, 'empty tree must still produce a root');

  const a = await leafValue(TAG_ACCOUNT, 777n);
  const s = await leafValue(TAG_SESSION, 777n);
  assert.notEqual(a.toString(), s.toString(), 'domain tags must separate identical raw values');

  await tree.insert(a);
  const rootAfter = tree.getRoot();
  assert.notEqual(rootAfter.toString(), w0.root, 'insert must change the root');

  // 삽입한 값은 더 이상 비멤버가 아니다
  await assert.rejects(
    () => tree.getNonMembershipWitness(a),
    /is a member/,
  );

  // 삽입하지 않은 값은 여전히 비멤버이고 witness가 나온다
  const w1 = await tree.getNonMembershipWitness(s);
  assert.equal(w1.pathElements.length, 20);
  assert.equal(w1.pathIndices.length, 20);
  assert.equal(w1.root, rootAfter.toString());

  console.log('PASS: IMT library inserts, changes root, and produces non-membership witnesses.');
}

main();
```

- [ ] **Step 2: 테스트 실행해서 실패 확인**

```bash
node tests/test_imt_lib.js
```

Expected: FAIL — `Cannot find module '../lib/imt.js'`

- [ ] **Step 3: 라이브러리 구현**

`lib/imt.js`:

```javascript
// Indexed Merkle Tree — 폐기 집합의 비멤버십 증명용.
//
// 리프는 값 오름차순으로 정렬돼 있고 각 리프가 (value, nextValue)를 담는다.
// nextValue == 0 은 "가장 큰 값"이라는 sentinel이다.
// circuits/lib/imt_nonmembership.circom 과 리프 해시 형식이 일치해야 한다.
import { buildPoseidon } from 'circomlibjs';

export const TAG_SESSION = 1n;
export const TAG_ACCOUNT = 2n;

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

// 리프 값은 하위 252비트로 정규화한다. 회로의 LessThan(252)이 입력이
// [0, 2^252) 임을 전제하는데 Poseidon 출력은 필드 전역에 분포하므로,
// 정규화하지 않으면 비교가 wrap-around로 뒤집힌다.
// circuits/lib/imt_nonmembership.circom 의 targetMasked 계산과 일치해야 한다.
const MASK_252 = (1n << 252n) - 1n;

export async function leafValue(tag, raw) {
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([tag, BigInt(raw)])) & MASK_252;
}

export async function createIMT(depth) {
  const poseidon = await getPoseidon();
  const F = poseidon.F;
  const H = (a, b) => F.toObject(poseidon([a, b]));

  // 0은 항상 존재하는 anchor 리프다. 모든 리프 값은 Poseidon 출력을 마스킹한
  // 것이라 0이 될 확률은 무시할 수 있으므로, 0을 "모든 값보다 작은 하한"으로
  // 두면 어떤 target이든 자기보다 작은 리프를 항상 찾을 수 있다.
  //
  // anchor 없이 빈 트리를 특수 분기로 처리하면 두 가지가 깨진다:
  //  (1) 회로는 Poseidon(lowValue, lowNextValue) = Poseidon(0,0) 에서 경로를
  //      시작하는데 라이브러리가 리터럴 0에서 시작하면 root가 어긋난다.
  //  (2) 값이 하나라도 들어간 뒤에는 최솟값보다 작은 target의 low 리프를
  //      찾을 수 없게 된다.
  const values = [0n];

  function nextOf(i) {
    return i + 1 < values.length ? values[i + 1] : 0n;
  }

  // 리프 i의 해시
  function leafHash(i) {
    return H(values[i], nextOf(i));
  }

  // 전체 트리를 다시 쌓아 root와 각 리프의 경로를 만든다.
  // 폐기 집합은 작으므로(수천~수만) 매번 재구성해도 충분하다.
  function build() {
    // values 는 anchor 때문에 항상 최소 1개다.
    const levels = [values.map((_, i) => leafHash(i))];
    for (let d = 0; d < depth; d++) {
      const prev = levels[levels.length - 1];
      const next = [];
      for (let i = 0; i < prev.length; i += 2) {
        const l = prev[i];
        const r = i + 1 < prev.length ? prev[i + 1] : 0n;
        next.push(H(l, r));
      }
      levels.push(next.length ? next : [H(0n, 0n)]);
    }
    return levels;
  }

  function pathFor(levels, leafIndex) {
    const pathElements = [];
    const pathIndices = [];
    let idx = leafIndex;
    for (let d = 0; d < depth; d++) {
      const level = levels[d];
      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;
      pathElements.push(siblingIdx < level.length ? level[siblingIdx] : 0n);
      pathIndices.push(isRight ? 1 : 0);
      idx = Math.floor(idx / 2);
    }
    return { pathElements, pathIndices };
  }

  return {
    async insert(value) {
      const v = BigInt(value);
      if (v === 0n) throw new Error('0 is the anchor leaf and cannot be revoked');
      // 회로가 lowValue/lowNextValue 를 Num2Bits(252) 로 range-check 하므로,
      // 마스킹되지 않은 값이 트리에 들어가면 그 리프 주변의 증명이 불가능해진다.
      // leafValue() 를 거치지 않은 원시 Poseidon 다이제스트를 막는다.
      if (v < 0n || v >= (1n << 252n)) {
        throw new Error(`${v} is outside [0, 2^252); pass leafValue() output, not a raw digest`);
      }
      if (values.some((x) => x === v)) return; // 이미 폐기됨
      values.push(v);
      values.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    },

    getRoot() {
      const levels = build();
      return levels[levels.length - 1][0];
    },

    async getNonMembershipWitness(target) {
      // 회로는 target을 내부에서 하위 252비트로 정규화하므로, low 리프를 고를 때도
      // 같은 정규화를 거친 값으로 비교해야 한다. leafValue() 출력은 이미 마스킹돼
      // 있어 이 연산이 무해하고(idempotent), 원시 Poseidon 다이제스트를 그대로
      // 넘긴 경우에도 회로와 같은 값을 보게 된다.
      const t = BigInt(target) & MASK_252;
      if (values.some((x) => x === t)) {
        throw new Error(`${t} is a member of the revocation set`);
      }
      const levels = build();
      const root = levels[levels.length - 1][0];

      // t 보다 작은 값 중 가장 큰 것을 찾는다. anchor(0) 가 항상 있으므로
      // t > 0 인 한 반드시 하나는 찾는다.
      let lowIdx = -1;
      for (let i = 0; i < values.length; i++) {
        if (values[i] < t) lowIdx = i;
        else break;
      }
      if (lowIdx === -1) {
        throw new Error(`target ${t} must be greater than 0 (the anchor leaf)`);
      }
      const { pathElements, pathIndices } = pathFor(levels, lowIdx);
      return {
        lowValue: values[lowIdx].toString(),
        lowNextValue: nextOf(lowIdx).toString(),
        pathElements: pathElements.map(String),
        pathIndices: pathIndices.map(String),
        root: root.toString(),
      };
    },
  };
}
```

- [ ] **Step 4: 테스트 실행해서 통과 확인**

```bash
node tests/test_imt_lib.js
```

Expected: `PASS: IMT library inserts, changes root, and produces non-membership witnesses.`

- [ ] **Step 5: 회로와 라이브러리가 서로 맞는지 교차 검증 테스트 추가**

`tests/test_imt_lib.js`의 `console.log('PASS: ...')` 바로 앞에 삽입:

```javascript
  // 라이브러리가 만든 witness가 실제 회로를 통과해야 한다
  const fs = await import('node:fs');
  const wc = await import('/tmp/imt_measure/test_imt_only_js/witness_calculator.js');
  const wasmBuffer = fs.default.readFileSync('/tmp/imt_measure/test_imt_only_js/test_imt_only.wasm');
  const calc = await wc.default(wasmBuffer);
  await calc.calculateWitness({ ...w1, target: s.toString() }, true);
  console.log('OK: library witness verifies against the circuit');
```

- [ ] **Step 6: 교차 검증 실행**

```bash
node tests/test_imt_lib.js
```

Expected: `OK: library witness verifies against the circuit` 와 `PASS:` 둘 다 출력.

이 단계가 실패하면 리프 해시 형식이나 경로 인덱싱이 회로와 어긋난 것이므로, `lib/imt.js`의 `build()`/`pathFor()`를 회로의 루프와 대조해 맞춘다.

- [ ] **Step 7: 커밋**

```bash
git add lib/imt.js tests/test_imt_lib.js
git commit -m "feat(revocation): add shared IMT library for IdP and wallet

Sorted indexed Merkle tree with (value, nextValue) leaves matching
circuits/lib/imt_nonmembership.circom. Cross-verified: witnesses produced
by the library satisfy the circuit."
```

---

## Task 3: `pi_pk_i` 회로 확장

**Files:**
- Modify: `circuits/pi_pk_i.circom`
- Modify: `scripts/build_mode2_circuits.sh` (ptau 부족 시)
- Test: `tests/test_pi_pk_i_revocation.mjs`
- Delete: `circuits/test_imt_only.circom`

**Interfaces:**
- Consumes: Task 1의 `IMTNonMembership(20)`, Task 2의 `getNonMembershipWitness`
- Produces: `pi_pk_i` public signals가 **6개**로 확장 — `[pk_i, pk_IdP_x, pk_IdP_y, PPID, max_height, revocationRoot]`. Task 5의 컨트랙트가 이 순서에 의존한다.

- [ ] **Step 1: 회로 수정**

`circuits/pi_pk_i.circom` 전체를 아래로 교체한다:

```circom
pragma circom 2.0.0;

include "lib/eddsaposeidon.circom";
include "lib/poseidon.circom";
include "lib/imt_nonmembership.circom";

template PiPkI() {
    // Private inputs
    signal input rp_nonce;
    signal input arid_i;
    signal input auid_i;
    signal input r_token;
    signal input chain_id;
    signal input S;
    signal input R8x;
    signal input R8y;

    // Private inputs — 계정 바인딩용
    signal input uid;
    signal input rid;
    signal input salt;

    // Private inputs — 세션 비멤버십 witness
    signal input sess_lowValue;
    signal input sess_lowNextValue;
    signal input sess_pathElements[20];
    signal input sess_pathIndices[20];

    // Private inputs — 계정 비멤버십 witness
    signal input acct_lowValue;
    signal input acct_lowNextValue;
    signal input acct_pathElements[20];
    signal input acct_pathIndices[20];

    // Public inputs
    signal input pk_i;
    signal input pk_IdP_x;
    signal input pk_IdP_y;
    signal input PPID;
    signal input max_height;
    signal input revocationRoot;

    var DOMAIN_IDP_TOKEN = 1351534856589225444686;
    var TAG_SESSION = 1;
    var TAG_ACCOUNT = 2;

    // auid_i = PPID * rp_nonce
    auid_i === PPID * rp_nonce;

    // r_token = Poseidon(pk_i, max_height, rp_nonce)
    component tokenNonceHasher = Poseidon(3);
    tokenNonceHasher.inputs[0] <== pk_i;
    tokenNonceHasher.inputs[1] <== max_height;
    tokenNonceHasher.inputs[2] <== rp_nonce;
    r_token === tokenNonceHasher.out;

    // msg = Poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id])
    component msgHasher = Poseidon(6);
    msgHasher.inputs[0] <== DOMAIN_IDP_TOKEN;
    msgHasher.inputs[1] <== arid_i;
    msgHasher.inputs[2] <== auid_i;
    msgHasher.inputs[3] <== r_token;
    msgHasher.inputs[4] <== max_height;
    msgHasher.inputs[5] <== chain_id;

    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== pk_IdP_x;
    sigVerifier.Ay <== pk_IdP_y;
    sigVerifier.S <== S;
    sigVerifier.R8x <== R8x;
    sigVerifier.R8y <== R8y;
    sigVerifier.M <== msgHasher.out;

    // ---- 계정 바인딩 ----
    // PPID가 이 uid/rid/salt에서 나왔음을 보인다. 이게 없으면 사용자가
    // 폐기되지 않은 남의 auid를 가져다 쓸 수 있다.
    //
    // pi_ppid.circom 이 같은 관계를 이미 증명하지만 그 중복은 의도된 것이다:
    // pi_ppid 는 로그인 시 IdP 가 오프체인으로 검증하고, 이 회로는 온체인
    // 컨트랙트가 검증한다. 서로 다른 신뢰 경계에 있으므로 온체인 증명은
    // 독립적으로 바인딩해야 하며, 한쪽을 믿고 생략할 수 없다.
    component ppidHasher = Poseidon(3);
    ppidHasher.inputs[0] <== uid;
    ppidHasher.inputs[1] <== rid;
    ppidHasher.inputs[2] <== salt;
    PPID === ppidHasher.out;

    signal auid;
    component auidHasher = Poseidon(2);
    auidHasher.inputs[0] <== uid;
    auidHasher.inputs[1] <== salt;
    auid <== auidHasher.out;

    // ---- 폐기 비멤버십 ----
    component sessLeaf = Poseidon(2);
    sessLeaf.inputs[0] <== TAG_SESSION;
    sessLeaf.inputs[1] <== r_token;

    component sessNM = IMTNonMembership(20);
    sessNM.target <== sessLeaf.out;
    sessNM.lowValue <== sess_lowValue;
    sessNM.lowNextValue <== sess_lowNextValue;
    for (var i = 0; i < 20; i++) {
        sessNM.pathElements[i] <== sess_pathElements[i];
        sessNM.pathIndices[i] <== sess_pathIndices[i];
    }
    sessNM.root <== revocationRoot;

    component acctLeaf = Poseidon(2);
    acctLeaf.inputs[0] <== TAG_ACCOUNT;
    acctLeaf.inputs[1] <== auid;

    component acctNM = IMTNonMembership(20);
    acctNM.target <== acctLeaf.out;
    acctNM.lowValue <== acct_lowValue;
    acctNM.lowNextValue <== acct_lowNextValue;
    for (var i = 0; i < 20; i++) {
        acctNM.pathElements[i] <== acct_pathElements[i];
        acctNM.pathIndices[i] <== acct_pathIndices[i];
    }
    acctNM.root <== revocationRoot;
}

component main {public [pk_i, pk_IdP_x, pk_IdP_y, PPID, max_height, revocationRoot]} = PiPkI();
```

- [ ] **Step 2: constraint 수 확인 후 ptau 충분한지 판단**

```bash
mkdir -p /tmp/pkicheck
circom circuits/pi_pk_i.circom --r1cs -o /tmp/pkicheck \
  -l circuits -l circuits/lib -l node_modules/circomlib/circuits
```

Expected: Task 1 측정값 × 2 + 약 5,300 (기존 4,820 + 바인딩 501). 예상 범위 **18,000~20,500**.

`pot14_final.ptau`는 2^14 = 16,384 constraint까지만 지원한다. 측정값이 16,384를 넘으면 Step 3을 수행하고, 넘지 않으면 건너뛴다.

- [ ] **Step 3: (필요 시) ptau 상향**

`scripts/build_mode2_circuits.sh:7` 을 수정한다:

```bash
PTAU_FILE="pot21_final.ptau" # pi_pk_i가 2^14를 넘어 상향
```

`pot21_final.ptau`(2.4GB)는 저장소 루트에 이미 있다. 새로 생성하지 않는다.

- [ ] **Step 4: 전체 회로 재빌드**

```bash
bash scripts/build_mode2_circuits.sh
```

Expected: `🎉 All Mode 2 circuits compiled successfully in build/mode2`
`contracts/PiPkIVerifier.sol`이 6개 public signal용으로 재생성된다.

- [ ] **Step 5: 회로 테스트 작성**

`tests/test_pi_pk_i_revocation.mjs`:

```javascript
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { randomBytes } from 'crypto';
import fs from 'fs';
import { createIMT, leafValue, TAG_SESSION, TAG_ACCOUNT } from '../lib/imt.js';

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function main() {
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = eddsa.F;
  const pos = (arr) => poseidon.F.toObject(poseidon(arr));

  const sk = randomBytes(32);
  const pk = eddsa.prv2pub(sk);

  const uid = 12345n, rid = 999n, salt = 777n;
  const rp_nonce = 31337n, pk_i = 4242n, max_height = 1000n, chain_id = 1337n;

  const PPID = pos([uid, rid, salt]);
  const auid = pos([uid, salt]);
  const arid_i = (rid * rp_nonce) % P;
  const auid_i = (PPID * rp_nonce) % P;
  const r_token = pos([pk_i, max_height, rp_nonce]);

  const DOMAIN = 1351534856589225444686n;
  const sig = eddsa.signPoseidon(sk, poseidon([DOMAIN, arid_i, auid_i, r_token, max_height, chain_id]));

  // 폐기 트리: 무관한 항목 하나만 넣어 둔다
  const tree = await createIMT(20);
  await tree.insert(await leafValue(TAG_ACCOUNT, 555n));

  const sessTarget = await leafValue(TAG_SESSION, r_token);
  const acctTarget = await leafValue(TAG_ACCOUNT, auid);
  const sw = await tree.getNonMembershipWitness(sessTarget);
  const aw = await tree.getNonMembershipWitness(acctTarget);

  const input = {
    rp_nonce: rp_nonce.toString(), arid_i: arid_i.toString(), auid_i: auid_i.toString(),
    r_token: r_token.toString(), chain_id: chain_id.toString(),
    S: sig.S.toString(),
    R8x: F.toObject(sig.R8[0]).toString(), R8y: F.toObject(sig.R8[1]).toString(),
    uid: uid.toString(), rid: rid.toString(), salt: salt.toString(),
    sess_lowValue: sw.lowValue, sess_lowNextValue: sw.lowNextValue,
    sess_pathElements: sw.pathElements, sess_pathIndices: sw.pathIndices,
    acct_lowValue: aw.lowValue, acct_lowNextValue: aw.lowNextValue,
    acct_pathElements: aw.pathElements, acct_pathIndices: aw.pathIndices,
    pk_i: pk_i.toString(), pk_IdP_x: F.toObject(pk[0]).toString(), pk_IdP_y: F.toObject(pk[1]).toString(),
    PPID: PPID.toString(), max_height: max_height.toString(), revocationRoot: sw.root,
  };

  const wc = await import('../build/mode2/pi_pk_i_js/witness_calculator.cjs');
  const wasmBuffer = fs.default.readFileSync('build/mode2/pi_pk_i_js/pi_pk_i.wasm');
  const calc = await wc.default(wasmBuffer);

  await calc.calculateWitness(input, true);
  console.log('OK: unrevoked session and account produce a valid witness');

  // PPID를 다른 값으로 바꾸면 바인딩 제약에 걸려야 한다
  let rejected = false;
  try {
    await calc.calculateWitness({ ...input, PPID: (PPID + 1n).toString() }, true);
  } catch { rejected = true; }
  if (!rejected) { console.error('FAIL: mismatched PPID was accepted'); process.exit(1); }
  console.log('OK: PPID not derived from uid/rid/salt is rejected');

  console.log('PASS: pi_pk_i enforces account binding and revocation non-membership.');
}

main();
```

- [ ] **Step 6: 테스트 실행**

```bash
node tests/test_pi_pk_i_revocation.mjs
```

Expected: `PASS: pi_pk_i enforces account binding and revocation non-membership.`

- [ ] **Step 7: 폐기된 계정이 거부되는지 테스트 추가**

`tests/test_pi_pk_i_revocation.mjs`의 마지막 `console.log('PASS: ...')` 앞에 삽입:

```javascript
  // 이 계정을 실제로 폐기하면 witness 자체를 만들 수 없어야 한다
  await tree.insert(acctTarget);
  let witnessRefused = false;
  try {
    await tree.getNonMembershipWitness(acctTarget);
  } catch (e) {
    witnessRefused = /is a member/.test(e.message);
  }
  if (!witnessRefused) { console.error('FAIL: revoked account still produced a witness'); process.exit(1); }
  console.log('OK: revoked account cannot obtain a non-membership witness');
```

- [ ] **Step 8: 재실행**

```bash
node tests/test_pi_pk_i_revocation.mjs
```

Expected: 3개 `OK:` 줄과 `PASS:` 줄.

- [ ] **Step 9: 측정 전용 회로 삭제**

```bash
rm circuits/test_imt_only.circom
```

`tests/test_imt_nonmembership_circuit.mjs`와 `tests/test_imt_lib.js`가 `/tmp/imt_measure` 경로를 참조하므로, 두 파일에서 해당 경로를 `build/mode2/pi_pk_i_js/...`로 바꾸지 말고 **파일 상단에 재생성 방법을 주석으로 남긴다**:

```javascript
// 이 테스트는 측정 전용 래퍼 회로를 필요로 한다. 없으면 아래로 재생성한다:
//   printf 'pragma circom 2.0.0;\ninclude "lib/imt_nonmembership.circom";\ncomponent main {public [root]} = IMTNonMembership(20);\n' > /tmp/test_imt_only.circom
//   circom /tmp/test_imt_only.circom --r1cs --wasm -o /tmp/imt_measure -l circuits -l circuits/lib -l node_modules/circomlib/circuits
```

- [ ] **Step 10: 커밋**

```bash
git add circuits/pi_pk_i.circom scripts/build_mode2_circuits.sh contracts/PiPkIVerifier.sol build/mode2 tests/test_pi_pk_i_revocation.mjs tests/test_imt_nonmembership_circuit.mjs tests/test_imt_lib.js
git rm --cached circuits/test_imt_only.circom 2>/dev/null || true
git commit -m "feat(revocation): bind account identity and prove revocation non-membership in pi_pk_i

pi_pk_i now takes revocationRoot as a sixth public signal and privately
proves PPID == Poseidon(uid, rid, salt), auid == Poseidon(uid, salt), and
that neither Poseidon(TAG_SESSION, r_token) nor Poseidon(TAG_ACCOUNT, auid)
is in the revocation tree. Neither r_token nor auid becomes public."
```

---

## Task 4: `RevocationRegistry` 컨트랙트

**Files:**
- Create: `contracts/RevocationRegistry.sol`
- Test: `test/RevocationRegistry.test.mjs`

**Interfaces:**
- Consumes: 없음
- Produces: `RevocationRegistry` 컨트랙트. `constructor(address idp)`, `pushRoot(bytes32)`, `isRecentRoot(bytes32) view returns (bool)`, `latestRoot() view returns (bytes32)`. Task 5의 `PPIDWallet`이 `isRecentRoot`를 호출한다.

- [ ] **Step 1: 실패하는 테스트 작성**

`test/RevocationRegistry.test.mjs`:

```javascript
import hre from 'hardhat';
import { expect } from 'chai';

const { ethers } = hre;

describe('RevocationRegistry', function () {
  const R = (n) => ethers.zeroPadValue(ethers.toBeHex(n), 32);

  async function deploy() {
    const [idp, other] = await ethers.getSigners();
    const F = await ethers.getContractFactory('RevocationRegistry');
    const reg = await F.deploy(idp.address);
    return { reg, idp, other };
  }

  it('accepts a root from the IdP and reports it as recent', async function () {
    const { reg } = await deploy();
    await reg.pushRoot(R(1));
    expect(await reg.isRecentRoot(R(1))).to.equal(true);
    expect(await reg.latestRoot()).to.equal(R(1));
  });

  it('rejects pushRoot from a non-IdP caller', async function () {
    const { reg, other } = await deploy();
    await expect(reg.connect(other).pushRoot(R(1))).to.be.revertedWithCustomError(reg, 'NotIdP');
  });

  it('keeps the most recent K roots and evicts older ones', async function () {
    const { reg } = await deploy();
    for (let i = 1; i <= 8; i++) await reg.pushRoot(R(i));
    expect(await reg.isRecentRoot(R(1))).to.equal(true);
    await reg.pushRoot(R(9));
    expect(await reg.isRecentRoot(R(1))).to.equal(false, 'oldest root must be evicted');
    expect(await reg.isRecentRoot(R(9))).to.equal(true);
    expect(await reg.isRecentRoot(R(2))).to.equal(true);
  });

  it('reports an unknown root as not recent', async function () {
    const { reg } = await deploy();
    await reg.pushRoot(R(1));
    expect(await reg.isRecentRoot(R(42))).to.equal(false);
  });
});
```

- [ ] **Step 2: 테스트 실행해서 실패 확인**

```bash
npx hardhat test test/RevocationRegistry.test.mjs
```

Expected: FAIL — `HH700: Artifact for contract "RevocationRegistry" not found.`

- [ ] **Step 3: 컨트랙트 구현**

`contracts/RevocationRegistry.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice 폐기 트리 root의 순환 버퍼. IdP만 갱신할 수 있고,
///         최근 K개 root를 유효한 것으로 인정한다(grace window).
///
///         K개를 허용하는 이유: root가 바뀔 때마다 모든 지갑이 재증명해야 하면
///         세션당 1회 증명이라는 이점이 사라진다. 대신 폐기 반영이 최대
///         K번의 갱신만큼 늦어진다.
contract RevocationRegistry {
    uint256 public constant K = 8;

    address public immutable idp;
    bytes32[K] private roots;
    uint256 private head;      // 다음에 쓸 슬롯
    uint256 private filled;    // 채워진 슬롯 수 (K에서 포화)

    error NotIdP();

    event RootPushed(bytes32 indexed root, uint256 index);

    constructor(address _idp) {
        idp = _idp;
    }

    modifier onlyIdP() {
        if (msg.sender != idp) revert NotIdP();
        _;
    }

    function pushRoot(bytes32 newRoot) external onlyIdP {
        roots[head] = newRoot;
        emit RootPushed(newRoot, head);
        head = (head + 1) % K;
        if (filled < K) filled += 1;
    }

    /// @notice root가 최근 K개 안에 있는가.
    /// @dev K가 상수 8이므로 선형 탐색이 매핑보다 싸다(축출 시 매핑 정리 비용이 없음).
    function isRecentRoot(bytes32 root) external view returns (bool) {
        for (uint256 i = 0; i < filled; i++) {
            if (roots[i] == root) return true;
        }
        return false;
    }

    function latestRoot() external view returns (bytes32) {
        if (filled == 0) return bytes32(0);
        return roots[(head + K - 1) % K];
    }
}
```

- [ ] **Step 4: 테스트 실행해서 통과 확인**

```bash
npx hardhat test test/RevocationRegistry.test.mjs
```

Expected: 4 passing

- [ ] **Step 5: 커밋**

```bash
git add contracts/RevocationRegistry.sol test/RevocationRegistry.test.mjs
git commit -m "feat(revocation): add RevocationRegistry with K=8 grace window

IdP-only circular buffer of revocation tree roots. isRecentRoot accepts
any of the last 8 roots so wallets can cache proofs across root updates."
```

---

## Task 5: `PPIDWallet.execute()` 확장

**Files:**
- Modify: `contracts/PPIDWallet.sol`
- Modify: `contracts/PPIDWalletFactory.sol`
- Test: `test/PPIDWalletRevocation.test.mjs`

**Interfaces:**
- Consumes: Task 4의 `RevocationRegistry.isRecentRoot`, Task 3의 6개 public signal 순서
- Produces: `PPIDWallet.execute(payload, sig, proofA, proofB, proofC, pk_i, pk_IdP_x, pk_IdP_y, max_height, revocationRoot)`. `PPIDWalletFactory.deploy(ppid)` 시 registry 주소가 지갑에 주입된다.

- [ ] **Step 1: 실패하는 테스트 작성**

`test/PPIDWalletRevocation.test.mjs`:

```javascript
import hre from 'hardhat';
import { expect } from 'chai';

const { ethers } = hre;

describe('PPIDWallet revocation root check', function () {
  it('reverts when the proof root is not in the registry window', async function () {
    const [idp] = await ethers.getSigners();

    const Reg = await ethers.getContractFactory('RevocationRegistry');
    const reg = await Reg.deploy(idp.address);
    await reg.pushRoot(ethers.zeroPadValue(ethers.toBeHex(1), 32));

    const Verifier = await ethers.getContractFactory('PiPkIVerifier');
    const verifier = await Verifier.deploy();

    const Wallet = await ethers.getContractFactory('PPIDWallet');
    const wallet = await Wallet.deploy(123n, await verifier.getAddress(), 1n, 2n, await reg.getAddress());

    const payload = { to: idp.address, value: 0, data: '0x', nonce: 0 };
    const staleRoot = ethers.zeroPadValue(ethers.toBeHex(999), 32);

    await expect(
      wallet.execute(
        payload,
        '0x' + '00'.repeat(65),
        [0, 0], [[0, 0], [0, 0]], [0, 0],
        0, 1n, 2n, 999999n,
        staleRoot,
      ),
    ).to.be.revertedWithCustomError(wallet, 'StaleRevocationRoot');
  });
});
```

- [ ] **Step 2: 테스트 실행해서 실패 확인**

```bash
npx hardhat test test/PPIDWalletRevocation.test.mjs
```

Expected: FAIL — 생성자 인자 개수 불일치 또는 `StaleRevocationRoot` 미정의

- [ ] **Step 3: `PPIDWallet.sol` 수정**

`contracts/PPIDWallet.sol`에서 다음을 변경한다.

import와 상태 변수에 registry를 추가:

```solidity
import "./PiPkIVerifier.sol";
import "./RevocationRegistry.sol";

contract PPIDWallet {
    uint256 public immutable ppid;
    PiPkIVerifier public immutable verifier;
    uint256 public immutable trustedPkIdPX;
    uint256 public immutable trustedPkIdPY;
    RevocationRegistry public immutable registry;
    uint256 public nonce;
```

에러 선언에 추가:

```solidity
    error StaleRevocationRoot(bytes32 root);
```

생성자를 교체:

```solidity
    constructor(
        uint256 _ppid,
        address _verifier,
        uint256 _pkIdPX,
        uint256 _pkIdPY,
        address _registry
    ) {
        ppid = _ppid;
        verifier = PiPkIVerifier(_verifier);
        trustedPkIdPX = _pkIdPX;
        trustedPkIdPY = _pkIdPY;
        registry = RevocationRegistry(_registry);
    }
```

`execute()` 시그니처에 `revocationRoot`를 추가하고, 검증 순서에 root 확인을 넣는다. 기존 `uint[5] memory pubSignals` 줄을 아래로 교체:

```solidity
    function execute(
        Payload calldata payload,
        bytes calldata sig,
        uint[2] calldata proofA,
        uint[2][2] calldata proofB,
        uint[2] calldata proofC,
        uint256 pk_i,
        uint256 pk_IdP_x,
        uint256 pk_IdP_y,
        uint256 max_height,
        bytes32 revocationRoot
    ) external returns (bool ok) {
```

`if (pk_IdP_x != trustedPkIdPX || ...)` 바로 다음에 삽입:

```solidity
        // 폐기 root가 grace window 안인지 먼저 본다 — 증명 검증보다 싸다.
        if (!registry.isRecentRoot(revocationRoot)) revert StaleRevocationRoot(revocationRoot);
```

pubSignals를 6개로:

```solidity
        uint[6] memory pubSignals = [
            pk_i, pk_IdP_x, pk_IdP_y, ppid, max_height, uint256(revocationRoot)
        ];
        if (!verifier.verifyProof(proofA, proofB, proofC, pubSignals)) revert InvalidProof();
```

- [ ] **Step 4: `PPIDWalletFactory.sol` 수정**

`contracts/PPIDWalletFactory.sol`에서 registry 주소를 보관하고 지갑 생성 시 넘긴다. 생성자와 `deploy`/`computeAddress`의 `creationCode` 인코딩에 `_registry`를 추가한다:

```solidity
contract PPIDWalletFactory {
    address public immutable verifier;
    uint256 public immutable trustedPkIdPX;
    uint256 public immutable trustedPkIdPY;
    address public immutable registry;

    constructor(
        address _verifier,
        uint256 _pkIdPX,
        uint256 _pkIdPY,
        address _registry
    ) {
        verifier = _verifier;
        trustedPkIdPX = _pkIdPX;
        trustedPkIdPY = _pkIdPY;
        registry = _registry;
    }
```

`computeAddress`의 `abi.encodePacked(type(PPIDWallet).creationCode, abi.encode(...))` 안의 인자 목록 끝에 `registry`를 추가하고, `deploy`의 `new PPIDWallet{salt: salt}(...)` 호출 끝에도 `registry`를 추가한다.

> **주의:** creationCode 인자가 바뀌므로 **모든 PPIDWallet의 CREATE2 주소가 달라진다.** 기존에 배포된 지갑은 접근 불가가 되며, 이는 되돌릴 수 없다. Task 8에서 재배포한다.

- [ ] **Step 5: 테스트 실행해서 통과 확인**

```bash
npx hardhat test test/PPIDWalletRevocation.test.mjs
```

Expected: 1 passing

- [ ] **Step 6: 기존 컨트랙트 테스트가 깨지지 않는지 확인**

```bash
npx hardhat compile
```

Expected: 컴파일 성공. 실패하면 `scripts/redeploy_ppid_factory.cjs`가 옛 생성자 인자를 쓰고 있을 수 있으므로 Task 8에서 함께 고친다.

- [ ] **Step 7: 커밋**

```bash
git add contracts/PPIDWallet.sol contracts/PPIDWalletFactory.sol test/PPIDWalletRevocation.test.mjs
git commit -m "feat(revocation): check revocation root in PPIDWallet.execute

execute() now takes revocationRoot, rejects roots outside the registry's
grace window before verifying the proof, and passes six public signals.
Factory injects the registry address, which changes every CREATE2 wallet
address — redeployment required."
```

---

## Task 6: IdP 폐기 API

**Files:**
- Modify: `custom_idp.js`
- Test: `tests/test_idp_revoke_endpoint.js`

**Interfaces:**
- Consumes: Task 2의 `createIMT`, `leafValue`, `TAG_SESSION`, `TAG_ACCOUNT`
- Produces:
  - `POST /idp/revoke` — body `{ type: 'session' | 'account', value }`, 응답 `{ root }`
  - `GET /idp/revocation_state` — 응답 `{ root, revokedLeaves: string[] }`. wallet_agent가 witness를 계산하는 데 쓴다.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_idp_revoke_endpoint.js`:

```javascript
import assert from 'node:assert/strict';

const BASE = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';

async function main() {
  const before = await (await fetch(`${BASE}/idp/revocation_state`)).json();
  assert.ok(typeof before.root === 'string', 'revocation_state must expose a root');
  assert.ok(Array.isArray(before.revokedLeaves), 'revocation_state must expose revokedLeaves');

  const res = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'account', value: '424242' }),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(typeof body.root === 'string');
  assert.notEqual(body.root, before.root, 'revoking must change the root');

  const after = await (await fetch(`${BASE}/idp/revocation_state`)).json();
  assert.equal(after.revokedLeaves.length, before.revokedLeaves.length + 1);

  const bad = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'nonsense', value: '1' }),
  });
  assert.equal(bad.status, 400, 'unknown revocation type must be rejected');

  console.log('PASS: IdP revoke endpoint updates the tree and exposes state.');
}

main();
```

- [ ] **Step 2: IdP 실행 후 테스트 실패 확인**

```bash
node custom_idp.js &
sleep 2
node tests/test_idp_revoke_endpoint.js
```

Expected: FAIL — `/idp/revocation_state`가 404를 반환해 JSON 파싱 실패

- [ ] **Step 3: `custom_idp.js`에 IMT와 엔드포인트 추가**

`custom_idp.js` 상단 import 부근에 추가:

```javascript
import { createIMT, leafValue, TAG_SESSION, TAG_ACCOUNT } from './lib/imt.js';

// 폐기 트리. custom_idp.js의 다른 로그와 마찬가지로 메모리에만 두며,
// 재시작하면 비워진다(기존 issuanceLog/auidILog와 같은 의도된 데모 한계).
const revocationTree = await createIMT(20);
const revokedLeaves = [];
```

`app.get('/ps_public_keys', ...)` 바로 앞에 두 엔드포인트를 추가:

```javascript
// 폐기 대상 등록. type='session'이면 r_token, 'account'면 auid를 값으로 받는다.
// 어느 쪽이든 IdP가 이미 알고 있는 값이다(issuanceLog / user.lastAuid).
app.post('/idp/revoke', async (req, res) => {
  const { type, value } = req.body ?? {};
  if (value === undefined || value === null) {
    return res.status(400).json({ error: 'value is required' });
  }
  let tag;
  if (type === 'session') tag = TAG_SESSION;
  else if (type === 'account') tag = TAG_ACCOUNT;
  else return res.status(400).json({ error: "type must be 'session' or 'account'" });

  const leaf = await leafValue(tag, String(value));
  await revocationTree.insert(leaf);
  if (!revokedLeaves.includes(leaf.toString())) revokedLeaves.push(leaf.toString());

  const root = revocationTree.getRoot().toString();
  console.log(`[IdP] revoked ${type} -> leaf ${leaf}, new root ${root}`);
  res.json({ root });
});

// 지갑이 자기 witness를 계산하려면 폐기 목록 전체가 필요하다.
// 리프는 Poseidon 해시라 preimage가 드러나지 않으므로 공개해도 안전하다.
app.get('/idp/revocation_state', (req, res) => {
  res.json({ root: revocationTree.getRoot().toString(), revokedLeaves });
});
```

- [ ] **Step 4: IdP 재시작 후 테스트 통과 확인**

```bash
pkill -f custom_idp.js
node custom_idp.js &
sleep 2
node tests/test_idp_revoke_endpoint.js
```

Expected: `PASS: IdP revoke endpoint updates the tree and exposes state.`

- [ ] **Step 5: root를 온체인에 게시하는 오퍼레이터 스크립트 작성**

`custom_idp.js`에는 RPC 연결도 서명 키도 없다(체인 트랜잭션을 보낼 수 없음). 개인키를 IdP에 넣는 대신, `scripts/redeploy_ppid_factory.cjs`와 같은 방식으로 hardhat 서명자를 쓰는 별도 스크립트를 만든다.

`scripts/push_revocation_root.cjs`:

```javascript
const hre = require("hardhat");

// IdP의 현재 폐기 root를 읽어 RevocationRegistry에 게시한다.
// IdP에 개인키를 두지 않기 위해 오퍼레이터가 실행하는 별도 단계로 분리했다.
async function main() {
  const idpBaseUrl = process.env.CUSTOM_IDP_BASE_URL || "http://127.0.0.1:4000";
  const registryAddress = process.env.REVOCATION_REGISTRY_ADDRESS;
  if (!registryAddress) throw new Error("REVOCATION_REGISTRY_ADDRESS is required");

  const res = await fetch(`${idpBaseUrl}/idp/revocation_state`);
  if (!res.ok) throw new Error(`revocation_state failed: ${res.status}`);
  const { root } = await res.json();

  // 회로의 root는 필드 요소(10진 문자열)이고 컨트랙트는 bytes32를 받는다.
  const rootHex = hre.ethers.zeroPadValue(hre.ethers.toBeHex(BigInt(root)), 32);

  const registry = await hre.ethers.getContractAt("RevocationRegistry", registryAddress);
  if (await registry.isRecentRoot(rootHex)) {
    console.log("Root already published, nothing to do:", rootHex);
    return;
  }
  const tx = await registry.pushRoot(rootHex);
  await tx.wait();
  console.log("Pushed revocation root:", rootHex);
}

main().catch((e) => { console.error(e); process.exit(1); });
```

- [ ] **Step 6: 스크립트가 IdP root를 읽어오는지 확인**

로컬 체인과 registry가 아직 없으므로 여기서는 조회 부분만 확인한다.

```bash
node custom_idp.js > /tmp/idp.log 2>&1 &
sleep 2
curl -s http://127.0.0.1:4000/idp/revocation_state
pkill -f custom_idp.js
```

Expected: `{"root":"...","revokedLeaves":[]}` 형태의 JSON.

전체 게시 흐름은 registry가 배포된 뒤 Task 8 Step 5에서 검증한다.

- [ ] **Step 7: IdP 프로세스 정리**

```bash
pkill -f custom_idp.js
```

- [ ] **Step 8: 커밋**

```bash
git add custom_idp.js scripts/push_revocation_root.cjs tests/test_idp_revoke_endpoint.js
git commit -m "feat(revocation): add IdP revoke and revocation_state endpoints

POST /idp/revoke inserts Poseidon(tag, value) into the in-memory IMT and
returns the new root. GET /idp/revocation_state publishes the root and the
full leaf list so wallets can compute their own non-membership witnesses."
```

---

## Task 7: `wallet_agent.js` — root·witness 조회와 증명 캐싱

**Files:**
- Modify: `wallet_agent.js`
- Test: `tests/test_wallet_revocation_cache.js`

**Interfaces:**
- Consumes: Task 6의 `GET /idp/revocation_state`, Task 2의 `createIMT`, Task 3의 회로 입력 이름
- Produces: `/submitTransaction` 응답의 `data`가 6개 public signal용 `execute()` calldata를 담는다.

- [ ] **Step 1: 캐시 로직 단위 테스트 작성**

`tests/test_wallet_revocation_cache.js`:

```javascript
import assert from 'node:assert/strict';
import { shouldReuseProof } from '../wallet_agent.js';

// wallet_agent.js가 실제로 쓰는 판정 함수를 그대로 불러 검증한다.
// (증명 생성 자체는 느리므로 여기서는 재사용 판정 규칙만 본다.)
assert.equal(shouldReuseProof(null, 'r1', 's1'), false, 'no cache -> must prove');
assert.equal(shouldReuseProof({ root: 'r1', sessionKeyId: 's1' }, 'r1', 's1'), true, 'same root and session -> reuse');
assert.equal(shouldReuseProof({ root: 'r1', sessionKeyId: 's1' }, 'r2', 's1'), false, 'root changed -> reprove');
assert.equal(shouldReuseProof({ root: 'r1', sessionKeyId: 's1' }, 'r1', 's2'), false, 'new session key -> reprove');

console.log('PASS: proof cache is reused only for the same session key and root.');
```

- [ ] **Step 2: 테스트 실행**

```bash
node tests/test_wallet_revocation_cache.js
```

Expected: FAIL — `The requested module '../wallet_agent.js' does not provide an export named 'shouldReuseProof'`

`wallet_agent.js`가 아직 이 함수를 export하지 않으므로 실패한다.

- [ ] **Step 3: `wallet_agent.js`에 폐기 상태 조회 추가**

`wallet_agent.js`의 `getIdpPublicKeys` 정의 부근에 추가:

```javascript
import { createIMT, leafValue, TAG_SESSION, TAG_ACCOUNT } from './lib/imt.js';

// IdP가 공개한 폐기 목록으로 로컬 트리를 재구성해 자기 witness를 계산한다.
// 리프가 해시라 목록을 받아도 남의 값을 알 수 없다.
async function fetchRevocationWitnesses(rTokenField, auidField) {
  const res = await fetch(`${IDP_URL}/idp/revocation_state`);
  if (!res.ok) throw new Error(`revocation_state failed: ${res.status}`);
  const { root, revokedLeaves } = await res.json();

  const tree = await createIMT(20);
  for (const leaf of revokedLeaves) await tree.insert(BigInt(leaf));

  const localRoot = tree.getRoot().toString();
  if (localRoot !== root) {
    throw new Error(`local revocation tree root ${localRoot} != IdP root ${root}`);
  }

  const sessTarget = await leafValue(TAG_SESSION, rTokenField);
  const acctTarget = await leafValue(TAG_ACCOUNT, auidField);
  return {
    root,
    sess: await tree.getNonMembershipWitness(sessTarget),
    acct: await tree.getNonMembershipWitness(acctTarget),
  };
}
```

- [ ] **Step 4: 로그인 시 `uid`·`salt`·`rid`를 서버측에 보관**

`/submitTransaction`은 현재 `business`(요청 본문)에서 `arid_i`·`auid_i`·`PPID`만 받고 `uid`·`salt`·`rid`는 받지 않는다. 그리고 **이 값들을 요청 본문으로 받아서는 안 된다** — RP FE가 `uid`를 보지 못하게 하는 경계가 이미 세워져 있다. 세션 키와 같은 방식으로 wallet_agent 메모리에 보관한다.

`wallet_agent.js`의 `currentSessionKey` 선언 바로 아래에 추가:

```javascript
// pi_pk_i의 계정 바인딩(PPID === Poseidon(uid, rid, salt))과 auid 계산에 필요하다.
// 세션 키와 수명을 같이 하며, HTTP로 나가지 않는다.
let currentAccountSecrets = null; // { uid, salt, rid } — 전부 bigint
```

`generateNewSessionKey()` 안의 `cachedPiPkI = null;` 옆에 추가:

```javascript
  currentAccountSecrets = null;
```

Step 8 증명 생성 함수에서 **`generateNewSessionKey()` 호출 뒤에** 추가한다:

```javascript
  const { sk_i, pk_i: pkField, address, publicKeyHex } = generateNewSessionKey();
  // generateNewSessionKey()가 currentAccountSecrets를 비우므로 반드시 그 뒤에 채운다.
  // 앞에 두면 방금 넣은 값이 곧바로 지워져 /submitTransaction이 항상 실패한다.
  currentAccountSecrets = { uid: uidField, salt: saltField, rid };
```

**순서가 중요하다.** `generateNewSessionKey()`가 `currentAccountSecrets = null`을 수행하므로, 대입을 그 호출보다 앞에 두면 로그인 직후 값이 사라진다.

그리고 접근자를 `getCurrentSessionKey()` 옆에 추가:

```javascript
function getCurrentAccountSecrets() {
  if (!currentAccountSecrets) {
    throw new Error('No account secrets — call /generateStep8Proofs (login) first');
  }
  return currentAccountSecrets;
}
```

캐시 재사용 판정도 테스트 가능하도록 별도 함수로 분리해 **export**한다(모듈 최상위, `cachedPiPkI` 선언 근처):

```javascript
// 캐시된 pi_pk_i 증명을 재사용해도 되는지 판정한다.
// 세션 키가 같고 폐기 root도 같을 때만 재사용할 수 있다 — root가 바뀌었다면
// 그 사이에 누군가 폐기됐을 수 있으므로 다시 증명해야 한다.
// 테스트에서 직접 호출하므로 export 한다.
export function shouldReuseProof(cache, currentRoot, sessionKeyId) {
  if (!cache) return false;
  if (cache.sessionKeyId !== sessionKeyId) return false;
  if (cache.root !== currentRoot) return false;
  return true;
}
```

- [ ] **Step 5: `/submitTransaction`에서 witness를 회로 입력에 넣고 캐싱 적용**

`wallet_agent.js`의 모듈 스코프에 캐시 변수를 추가:

```javascript
// pi_pk_i는 세션 크레덴셜이라 같은 세션·같은 root면 증명을 재사용할 수 있다.
let cachedPiPkI = null; // { sessionKeyId, root, proofA, proofB, proofC }
```

`generateNewSessionKey()` 안 마지막에 추가:

```javascript
  cachedPiPkI = null;
```

`/submitTransaction` 핸들러에서 `circuitInput` 조립 부분을 아래로 교체한다. `uid`·`salt`·`rid`는 Step 8 로그인 시 저장해 둔 값을 쓴다(`step8.sessionKey` 옆에 함께 보관):

```javascript
    const { uid: uidField, salt: saltField, rid: ridField } = getCurrentAccountSecrets();
    const auidField = poseidon.F.toObject(poseidon([uidField, saltField]));
    const rev = await fetchRevocationWitnesses(r_token.toString(), auidField.toString());

    const sessionKeyId = pk_i.toString();
    let proofA, proofB, proofC;
    if (shouldReuseProof(cachedPiPkI, rev.root, sessionKeyId)) {
      ({ proofA, proofB, proofC } = cachedPiPkI);
      console.log('[WalletAgent][submitTransaction] reusing cached pi_pk_i proof');
    } else {
      const circuitInput = {
        rp_nonce: rp_nonce.toString(),
        arid_i: arid_i.toString(),
        auid_i: auid_i.toString(),
        r_token: r_token.toString(),
        chain_id: chain_id.toString(),
        S: idpTokenSig.S,
        R8x: idpTokenSig.R8[0],
        R8y: idpTokenSig.R8[1],
        uid: uidField.toString(),
        rid: ridField.toString(),
        salt: saltField.toString(),
        sess_lowValue: rev.sess.lowValue,
        sess_lowNextValue: rev.sess.lowNextValue,
        sess_pathElements: rev.sess.pathElements,
        sess_pathIndices: rev.sess.pathIndices,
        acct_lowValue: rev.acct.lowValue,
        acct_lowNextValue: rev.acct.lowNextValue,
        acct_pathElements: rev.acct.pathElements,
        acct_pathIndices: rev.acct.pathIndices,
        pk_i: pk_i.toString(),
        pk_IdP_x: pkIdP_x.toString(),
        pk_IdP_y: pkIdP_y.toString(),
        PPID: ppidField.toString(),
        max_height: maxHeightField.toString(),
        revocationRoot: rev.root,
      };
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInput,
        'build/mode2/pi_pk_i_js/pi_pk_i.wasm',
        'build/mode2/pi_pk_i_final.zkey',
      );
      const calldata = JSON.parse(`[${await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)}]`);
      [proofA, proofB, proofC] = calldata;
      cachedPiPkI = { sessionKeyId, root: rev.root, proofA, proofB, proofC };
    }
```

`execute` calldata 인코딩에 root를 추가:

```javascript
    const executeCalldata = walletInterface.encodeFunctionData('execute', [
      { to: payload.to, value: payload.value, data: payload.data, nonce: payload.nonce },
      sig,
      proofA,
      proofB,
      proofC,
      pk_i.toString(),
      pkIdP_x.toString(),
      pkIdP_y.toString(),
      maxHeightField.toString(),
      rev.root,
    ]);
```

`WALLET_ABI`의 `execute` 시그니처도 새 인자에 맞게 고친다(`wallet_agent.js:31`):

```javascript
  'function execute((address to, uint256 value, bytes data, uint256 nonce) payload, bytes sig, uint[2] proofA, uint[2][2] proofB, uint[2] proofC, uint256 pk_i, uint256 pk_IdP_x, uint256 pk_IdP_y, uint256 max_height, bytes32 revocationRoot) returns (bool ok)',
```

- [ ] **Step 6: 캐시 규칙 테스트 재실행**

```bash
node tests/test_wallet_revocation_cache.js
```

Expected: `PASS: proof cache is reused only for the same session key and root.`

- [ ] **Step 7: 커밋**

```bash
git add wallet_agent.js tests/test_wallet_revocation_cache.js
git commit -m "feat(revocation): fetch revocation witnesses and cache pi_pk_i per root

wallet_agent rebuilds the IdP's revocation tree locally, verifies the root
matches, and computes its own non-membership witnesses. The pi_pk_i proof
is reused while both the session key and the root are unchanged."
```

---

## Task 8: 재배포와 통합 검증

**Files:**
- Modify: `scripts/redeploy_ppid_factory.cjs`
- Test: `tests/test_revocation_e2e.js`

**Interfaces:**
- Consumes: Task 4~7 전부
- Produces: 없음 (최종 검증)

- [ ] **Step 1: 재배포 스크립트에 registry 배포 추가**

`scripts/redeploy_ppid_factory.cjs`에서 factory 배포 전에 registry를 배포하고, factory 생성자에 주소를 넘긴다:

```javascript
  const Registry = await hre.ethers.getContractFactory('RevocationRegistry');
  const registry = await Registry.deploy(idpAddress);
  await registry.waitForDeployment();
  const registryAddress = await registry.getAddress();
  console.log('RevocationRegistry deployed at', registryAddress);

  const Factory = await hre.ethers.getContractFactory('PPIDWalletFactory');
  const factory = await Factory.deploy(verifierAddress, pkIdPX, pkIdPY, registryAddress);
```

스크립트 마지막에 두 주소를 함께 출력한다:

```javascript
  console.log('PPID_WALLET_FACTORY_ADDRESS=', await factory.getAddress());
  console.log('REVOCATION_REGISTRY_ADDRESS=', registryAddress);
```

- [ ] **Step 2: 로컬 체인과 IdP 기동**

```bash
npx hardhat node > /tmp/hardhat.log 2>&1 &
sleep 3
node custom_idp.js > /tmp/idp.log 2>&1 &
sleep 2
```

- [ ] **Step 3: 재배포 실행**

```bash
node scripts/redeploy_ppid_factory.cjs
```

Expected: `RevocationRegistry deployed at 0x...` 와 두 개의 주소 출력.

출력된 `PPID_WALLET_FACTORY_ADDRESS`와 `REVOCATION_REGISTRY_ADDRESS`를 `.env`에 반영한다(이 단계는 사람이 직접 수행한다 — 계획 실행자는 `.env`를 읽거나 쓰지 않는다).

- [ ] **Step 4: 통합 테스트 작성**

`tests/test_revocation_e2e.js`:

```javascript
import assert from 'node:assert/strict';
import { createIMT, leafValue, TAG_ACCOUNT } from '../lib/imt.js';

const IDP = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';

// 폐기 전후로 witness 생성 가능 여부가 뒤집히는지 확인한다.
// 회로·온체인 검증까지 도는 전체 흐름은 test_mode2_integration.js가 담당하며,
// 여기서는 폐기가 실제로 반영되는지만 본다.
async function main() {
  const victim = '987654321';
  const leaf = await leafValue(TAG_ACCOUNT, victim);

  const before = await (await fetch(`${IDP}/idp/revocation_state`)).json();
  const t1 = await createIMT(20);
  for (const l of before.revokedLeaves) await t1.insert(BigInt(l));
  const w = await t1.getNonMembershipWitness(leaf);
  assert.equal(w.root, before.root, 'local tree must match IdP root before revocation');
  console.log('OK: unrevoked account has a non-membership witness');

  const res = await fetch(`${IDP}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'account', value: victim }),
  });
  assert.equal(res.status, 200);

  const after = await (await fetch(`${IDP}/idp/revocation_state`)).json();
  assert.notEqual(after.root, before.root, 'root must change after revocation');

  const t2 = await createIMT(20);
  for (const l of after.revokedLeaves) await t2.insert(BigInt(l));
  await assert.rejects(() => t2.getNonMembershipWitness(leaf), /is a member/);
  console.log('OK: revoked account can no longer obtain a witness');

  console.log('PASS: revocation flips witness availability end to end.');
}

main();
```

- [ ] **Step 5: root 게시 후 온체인 반영 확인**

```bash
export REVOCATION_REGISTRY_ADDRESS=<Step 3에서 출력된 주소>
node scripts/push_revocation_root.cjs
```

Expected: `Pushed revocation root: 0x...`

다시 실행하면 중복 게시를 건너뛰어야 한다:

```bash
node scripts/push_revocation_root.cjs
```

Expected: `Root already published, nothing to do: 0x...`

- [ ] **Step 6: 통합 테스트 실행**

```bash
node tests/test_revocation_e2e.js
```

Expected: `PASS: revocation flips witness availability end to end.`

폐기가 일어났으므로 root가 바뀌었다. 다시 게시한다:

```bash
node scripts/push_revocation_root.cjs
```

Expected: `Pushed revocation root: 0x...` (앞서와 다른 값)

- [ ] **Step 7: 기존 mode2 통합 테스트로 회귀 확인**

```bash
node tests/test_mode2_integration.js
```

Expected: 통과. 실패하면 6개 public signal 변경이 반영되지 않은 호출부가 남아 있는 것이므로, 오류 메시지가 가리키는 파일을 고친다.

- [ ] **Step 8: 증명 시간 재측정**

```bash
node /tmp/claude-1000/*/scratchpad/bench_mode2_warm_260820.mjs 2>/dev/null || echo "벤치마크 스크립트가 없으면 건너뛴다"
```

`pi_pk_i`의 새 평균을 기록한다. spec §7.1의 추정(779~922 ms)과 대조해 문서를 갱신한다.

- [ ] **Step 9: 프로세스 정리**

```bash
pkill -f custom_idp.js
pkill -f "hardhat node"
```

포트 3000·4000·8545가 비었는지 확인한다:

```bash
ss -ltnp 2>/dev/null | grep -E ':(3000|4000|8545)' || echo "포트 정리됨"
```

- [ ] **Step 10: 커밋**

```bash
git add scripts/redeploy_ppid_factory.cjs scripts/push_revocation_root.cjs tests/test_revocation_e2e.js
git commit -m "feat(revocation): deploy RevocationRegistry and verify end to end

redeploy script now deploys the registry and wires it into the factory.
E2E test confirms revoking an account removes its ability to produce a
non-membership witness."
```

---

## 롤백

문제가 생기면 세 경로 중 하나를 쓴다.

```bash
# 1) 특정 커밋으로 되돌리기
git reset --hard ca94cec

# 2) 원래 브랜치로 이탈 (작업 브랜치는 보존)
git switch trace

# 3) 파일 스냅샷에서 복구 (git 밖)
cat /tmp/claude-1000/*/scratchpad/LATEST_SNAPSHOT.txt
```

`.env`의 `PPID_WALLET_FACTORY_ADDRESS`는 **git·스냅샷 어디에도 없다.** Task 8 실행 전에 사람이 직접 백업해야 한다.

---

## 미해결 항목

- **IMT 비멤버십 실제 비용** — Task 1 Step 3에서 확정된다. spec 추정 9,720(2회분)보다 커지면 spec §7.1의 손익분기(N ≥ 10~11)를 재계산해야 한다.
- **ptau 상향 여부** — Task 3 Step 2의 측정값이 16,384를 넘는지에 달렸다. 넘으면 `pot21_final.ptau`(2.4GB)를 쓰게 되어 zkey 크기와 증명 시간이 함께 늘어난다.
- **폐기 목록 크기 증가 시 성능** — 현재 `lib/imt.js`는 삽입/조회마다 트리를 전부 재구성한다. 폐기가 수만 건을 넘으면 증분 갱신이 필요하다. YAGNI로 미룬다.
