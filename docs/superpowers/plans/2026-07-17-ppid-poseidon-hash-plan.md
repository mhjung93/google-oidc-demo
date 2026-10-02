# PPID Poseidon 해시 전환 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `PPID = uid * rid * salt` (평문 곱셈, cross-RP 대수적으로 연결 가능)를 `PPID = Poseidon(uid, rid, salt)`로 바꿔서, 논문의 formal `auid` 정의와 통일하고 cross-RP unlinkability를 확보한다.

**Architecture:** `circuits/pi_ppid.circom`과 `circuits/pi_arid_i.circom` 내부의 `ppid` 유도 제약을 곱셈에서 Poseidon(3) 해시로 교체하고, `wallet_agent.js`의 단일 계산 지점을 동일한 공식으로 맞춘다. `pi_pk_i.circom`/온체인 컨트랙트/`server.js`는 `PPID`를 opaque 값으로만 다뤄서 영향받지 않으므로 건드리지 않는다.

**Tech Stack:** circom 2.0.0, snarkjs (Groth16), circomlibjs(Poseidon), 기존 `pot14_final.ptau`.

## Global Constraints

- `ppid`/`PPID`/`auid_i` 등 기존 변수·필드·컨트랙트 이름은 절대 바꾸지 않는다 — 공식만 바꾼다.
- `auid_i = PPID * rp_nonce` 관계(곱셈)는 그대로 둔다 — 이번 작업 범위 밖.
- Poseidon 입력 순서는 반드시 `[uid, rid, salt]`로 통일한다 (기존 `pi_auid.circom`의 관례를 따름). 순서가 한 곳이라도 다르면 증명 검증이 조용히 실패한다.
- `circuits/pi_pk_i.circom`, `contracts/PPIDWallet.sol`, `contracts/PPIDWalletFactory.sol`, `contracts/PiPkIVerifier.sol`, `server.js`는 수정하지 않는다.
- `npm run zk:ptau`는 실행하지 않는다 — 기존 `pot14_final.ptau`(2^14=16384)를 재사용한다.
- 로컬 서버(`custom_idp.js`, `wallet_agent.js`)를 시작/종료하기 전에는 반드시 사용자에게 먼저 확인한다. 테스트가 끝나면 새로 띄운 포트(3000/4000/5001)를 정리한다.
- `build/mode2/pi_ppid_*`, `build/mode2/pi_arid_i_*`는 이 저장소에서 기존에 git으로 추적되는 빌드 산출물이다(예외적 관례) — 재생성 후 `.circom` 소스와 함께 커밋한다.

---

### Task 1: `pi_ppid.circom`/`pi_arid_i.circom`을 Poseidon 해시로 전환

**Files:**
- Modify: `circuits/pi_ppid.circom`
- Modify: `circuits/pi_arid_i.circom`
- Modify: `tests/test_pi_arid_i_no_rid.js:8-23`
- Create: `tests/test_pi_ppid_poseidon.js`
- Create: `tests/test_ppid_cross_rp_unlinkability.js`
- Delete: `circuits/pi_auid.circom`, `build/mode2/pi_auid.r1cs`, `build/mode2/pi_auid.sym`, `build/mode2/pi_auid_0000.zkey`, `build/mode2/pi_auid_final.zkey`, `build/mode2/pi_auid_js/`, `build/mode2/pi_auid_vkey.json`
- Regenerate: `build/mode2/pi_ppid.r1cs`, `build/mode2/pi_ppid.sym`, `build/mode2/pi_ppid_js/`, `build/mode2/pi_ppid_0000.zkey`, `build/mode2/pi_ppid_final.zkey`, `build/mode2/pi_ppid_vkey.json`
- Regenerate: `build/mode2/pi_arid_i.r1cs`, `build/mode2/pi_arid_i.sym`, `build/mode2/pi_arid_i_js/`, `build/mode2/pi_arid_i_0000.zkey`, `build/mode2/pi_arid_i_final.zkey`, `build/mode2/pi_arid_i_vkey.json`

**Interfaces:**
- Consumes: 저장소 루트의 기존 `pot14_final.ptau` (2^14 제약 커버).
- Produces: `build/mode2/pi_ppid_final.zkey` / `pi_ppid_vkey.json` / `pi_ppid_js/pi_ppid.wasm`, `build/mode2/pi_arid_i_final.zkey` / `pi_arid_i_vkey.json` / `pi_arid_i_js/pi_arid_i.wasm` — Task 2가 이 정확한 경로들을 그대로 사용한다(파일명 변경 없음).

- [ ] **Step 1: `pi_ppid.circom`용 신규 회로 테스트를 먼저 작성 (아직 회로는 안 고침 — red 상태 확인용)**

`tests/test_pi_ppid_poseidon.js` 생성:

```js
import { buildPoseidon } from 'circomlibjs';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function main() {
  const tmpDir = fs.mkdtempSync('/tmp/pi_ppid_poseidon_test-');

  const uid = 12345n;
  const salt = 111222n;
  const rid = 123456789n;

  const poseidon = await buildPoseidon();
  const ppid = poseidon.F.toObject(poseidon([uid, rid, salt]));

  console.log('Compiling circuit...');
  execSync(
    `circom circuits/pi_ppid.circom --r1cs --wasm --sym -l circuits -o ${tmpDir}`,
    { stdio: 'inherit' }
  );

  const goodInputs = {
    uid: uid.toString(),
    salt: salt.toString(),
    rid: rid.toString(),
    ppid: ppid.toString(),
  };
  const inputPathGood = path.join(tmpDir, 'input_good.json');
  fs.writeFileSync(inputPathGood, JSON.stringify(goodInputs, null, 2));

  console.log('Generating witness with Poseidon-consistent ppid (expect success)...');
  execSync(
    `node ${tmpDir}/pi_ppid_js/generate_witness.js ${tmpDir}/pi_ppid_js/pi_ppid.wasm ${inputPathGood} ${tmpDir}/witness_good.wtns`,
    { stdio: 'inherit' }
  );
  console.log('PASS: Poseidon-consistent witness generated.');

  // The old multiplicative value must now be rejected — this is the actual
  // migration check: the circuit no longer accepts uid*rid*salt as ppid.
  const oldPpid = (uid * rid * salt) % FIELD_PRIME;
  const badInputs = { ...goodInputs, ppid: oldPpid.toString() };
  const inputPathBad = path.join(tmpDir, 'input_bad.json');
  fs.writeFileSync(inputPathBad, JSON.stringify(badInputs, null, 2));

  console.log('Generating witness with the OLD multiplicative ppid (expect failure)...');
  try {
    execSync(
      `node ${tmpDir}/pi_ppid_js/generate_witness.js ${tmpDir}/pi_ppid_js/pi_ppid.wasm ${inputPathBad} ${tmpDir}/witness_bad.wtns`,
      { stdio: 'pipe' }
    );
    throw new Error('FAIL: witness generation should have failed for the old multiplicative ppid');
  } catch (err) {
    if (err.message.startsWith('FAIL:')) throw err;
    console.log('PASS: old multiplicative ppid correctly rejected (constraint violation).');
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
```

- [ ] **Step 2: 현재(수정 전) 회로로 테스트 실행 → "good" 케이스가 실패해야 정상**

Run: `node tests/test_pi_ppid_poseidon.js`
Expected: `Generating witness with Poseidon-consistent ppid (expect success)...` 직후 witness 생성이 constraint 위반으로 실패하며 종료(현재 회로는 아직 곱셈을 검사하므로 Poseidon 값은 거부됨). `TEST FAILED:`로 끝나는 것이 이 시점에는 정상.

- [ ] **Step 3: `pi_ppid.circom`을 Poseidon 해시로 교체**

`circuits/pi_ppid.circom` 전체를 다음으로 교체:

```
pragma circom 2.0.0;

include "lib/circom-rsa-verify/circomlib/circuits/poseidon.circom";

template PiPPID() {
    // Private Inputs (hidden from verifier)
    signal input uid;
    signal input salt;

    // Public Inputs
    signal input rid;
    signal input ppid;

    // ppid = Poseidon(uid, rid, salt)
    component hasher = Poseidon(3);
    hasher.inputs[0] <== uid;
    hasher.inputs[1] <== rid;
    hasher.inputs[2] <== salt;
    ppid === hasher.out;
}

component main {public [rid, ppid]} = PiPPID();
```

- [ ] **Step 4: `pi_ppid` 회로/키 재생성**

Run:
```bash
circom circuits/pi_ppid.circom --r1cs --wasm --sym -l circuits -o build/mode2
mv build/mode2/pi_ppid_js/generate_witness.js build/mode2/pi_ppid_js/generate_witness.cjs
mv build/mode2/pi_ppid_js/witness_calculator.js build/mode2/pi_ppid_js/witness_calculator.cjs
sed -i 's/witness_calculator.js/witness_calculator.cjs/g' build/mode2/pi_ppid_js/generate_witness.cjs
npx snarkjs groth16 setup build/mode2/pi_ppid.r1cs pot14_final.ptau build/mode2/pi_ppid_0000.zkey
npx snarkjs zkey contribute build/mode2/pi_ppid_0000.zkey build/mode2/pi_ppid_final.zkey --name="First Contribution" -v -e="$(openssl rand -hex 32)"
npx snarkjs zkey export verificationkey build/mode2/pi_ppid_final.zkey build/mode2/pi_ppid_vkey.json
```
Expected: 각 명령이 에러 없이 완료되고 `build/mode2/pi_ppid_final.zkey`, `pi_ppid_vkey.json`이 갱신된 타임스탬프로 존재.

- [ ] **Step 5: 테스트 재실행 → 이번엔 통과해야 함**

Run: `node tests/test_pi_ppid_poseidon.js`
Expected:
```
PASS: Poseidon-consistent witness generated.
PASS: old multiplicative ppid correctly rejected (constraint violation).
```

- [ ] **Step 6: `pi_arid_i.circom` 내부 `ppid` 유도도 동일하게 교체**

`circuits/pi_arid_i.circom` 전체를 다음으로 교체:

```
pragma circom 2.0.0;

include "lib/circom-rsa-verify/circomlib/circuits/poseidon.circom";

template PiAridI() {
    // Private Inputs (hidden from verifier)
    signal input rp_nonce;
    signal input salt;
    signal input rid;
    signal input pk_i;

    // Public Inputs
    signal input uid;
    signal input arid_i;
    signal input auid_i;
    signal input max_height;
    signal input token_nonce;

    // ppid = Poseidon(uid, rid, salt)
    component ppidHasher = Poseidon(3);
    ppidHasher.inputs[0] <== uid;
    ppidHasher.inputs[1] <== rid;
    ppidHasher.inputs[2] <== salt;
    signal ppid;
    ppid <== ppidHasher.out;

    // rid stays a pure private witness. The IdP no longer checks anything
    // about it — the RP backend independently verifies arid_i === rid *
    // rp_nonce using its own known rid and rp_nonce (see server.js), which is
    // sufficient to reject a bogus/unregistered rid without the IdP ever
    // needing to see or verify rid.

    // arid_i = rid * rp_nonce
    arid_i === rid * rp_nonce;

    // auid_i = ppid * rp_nonce
    auid_i === ppid * rp_nonce;

    // token_nonce = Poseidon(pk_i, max_height, rp_nonce)
    component tokenNonceHasher = Poseidon(3);
    tokenNonceHasher.inputs[0] <== pk_i;
    tokenNonceHasher.inputs[1] <== max_height;
    tokenNonceHasher.inputs[2] <== rp_nonce;
    token_nonce === tokenNonceHasher.out;
}

component main {public [uid, arid_i, auid_i, max_height, token_nonce]} = PiAridI();
```

- [ ] **Step 7: `tests/test_pi_arid_i_no_rid.js`의 `ppid` 계산을 Poseidon으로 교체**

`tests/test_pi_arid_i_no_rid.js:8-23`을 다음으로 교체 (기존 `uid`/`salt`/`rid`/`rp_nonce`/`pk_i`/`max_height` 값과 나머지 tamper-test 로직은 그대로 둔다):

```js
  const uid = 12345n;
  const salt = 111222n;
  const rid = 123456789n;
  const rp_nonce = 999888n;
  const pk_i = 555n;
  const max_height = 310n;

  const poseidon = await buildPoseidon();
  const ppid = poseidon.F.toObject(poseidon([uid, rid, salt]));
  const arid_i = (rid * rp_nonce) % FIELD_PRIME;
  const auid_i = (ppid * rp_nonce) % FIELD_PRIME;
  const token_nonce = poseidon.F.toObject(poseidon([pk_i, max_height, rp_nonce])).toString();
```

(기존에 `const poseidon = await buildPoseidon();`가 `token_nonce` 계산 직전에 따로 있었는데, 이제 `ppid` 계산에도 필요하므로 위로 끌어올려 한 번만 호출한다.)

- [ ] **Step 8: `pi_arid_i` 회로/키 재생성**

Run:
```bash
circom circuits/pi_arid_i.circom --r1cs --wasm --sym -l circuits -o build/mode2
mv build/mode2/pi_arid_i_js/generate_witness.js build/mode2/pi_arid_i_js/generate_witness.cjs
mv build/mode2/pi_arid_i_js/witness_calculator.js build/mode2/pi_arid_i_js/witness_calculator.cjs
sed -i 's/witness_calculator.js/witness_calculator.cjs/g' build/mode2/pi_arid_i_js/generate_witness.cjs
npx snarkjs groth16 setup build/mode2/pi_arid_i.r1cs pot14_final.ptau build/mode2/pi_arid_i_0000.zkey
npx snarkjs zkey contribute build/mode2/pi_arid_i_0000.zkey build/mode2/pi_arid_i_final.zkey --name="First Contribution" -v -e="$(openssl rand -hex 32)"
npx snarkjs zkey export verificationkey build/mode2/pi_arid_i_final.zkey build/mode2/pi_arid_i_vkey.json
```
Expected: 에러 없이 완료.

- [ ] **Step 9: `test_pi_arid_i_no_rid.js` 실행 → 통과해야 함**

Run: `node tests/test_pi_arid_i_no_rid.js`
Expected:
```
PASS: rid_public is gone from the compiled circuit.
PASS: consistent witness generated.
PASS: tampered arid_i correctly rejected (constraint violation).
```

- [ ] **Step 10: cross-RP unlinkability 회귀 테스트 작성 및 실행**

`tests/test_ppid_cross_rp_unlinkability.js` 생성:

```js
import { buildPoseidon } from 'circomlibjs';

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function main() {
  const uid = 12345n;
  const salt = 111222n;
  const rid1 = 123456789n;
  const rid2 = 987654321n;

  // Old (rejected) construction: PPID = uid * rid * salt is transparently
  // multiplicative, so cross-multiplying two RPs' public PPID/rid pairs
  // reveals whether they share the same uid*salt, even without knowing
  // uid or salt. Confirm this actually holds for the old scheme first, to
  // prove the test methodology is meaningful before checking the new one.
  const oldPpid1 = (uid * rid1 * salt) % FIELD_PRIME;
  const oldPpid2 = (uid * rid2 * salt) % FIELD_PRIME;
  const oldCrossCheck = (oldPpid1 * rid2) % FIELD_PRIME === (oldPpid2 * rid1) % FIELD_PRIME;
  if (!oldCrossCheck) {
    throw new Error('FAIL: old multiplicative construction should be cross-linkable, but the check did not hold. Test fixture is broken.');
  }
  console.log('PASS: old multiplicative PPID is confirmed cross-linkable (expected, motivates the fix).');

  // New construction: PPID = Poseidon(uid, rid, salt). The same
  // cross-multiplication check must NOT hold, since a hash output carries
  // no algebraic relationship to its inputs.
  const poseidon = await buildPoseidon();
  const newPpid1 = poseidon.F.toObject(poseidon([uid, rid1, salt]));
  const newPpid2 = poseidon.F.toObject(poseidon([uid, rid2, salt]));
  const newCrossCheck = (newPpid1 * rid2) % FIELD_PRIME === (newPpid2 * rid1) % FIELD_PRIME;
  if (newCrossCheck) {
    throw new Error('FAIL: Poseidon-based PPID should not be cross-linkable, but the check held.');
  }
  console.log('PASS: Poseidon-based PPID is not cross-linkable via cross-multiplication.');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
```

Run: `node tests/test_ppid_cross_rp_unlinkability.js`
Expected:
```
PASS: old multiplicative PPID is confirmed cross-linkable (expected, motivates the fix).
PASS: Poseidon-based PPID is not cross-linkable via cross-multiplication.
```

- [ ] **Step 11: 미사용 레거시 회로 `pi_auid` 삭제**

Run:
```bash
rm circuits/pi_auid.circom
rm -rf build/mode2/pi_auid.r1cs build/mode2/pi_auid.sym build/mode2/pi_auid_0000.zkey build/mode2/pi_auid_final.zkey build/mode2/pi_auid_js build/mode2/pi_auid_vkey.json
```
Expected: 위 파일/디렉토리가 모두 사라짐. `grep -rln "pi_auid" --include="*.js" .`(node_modules 제외)가 아무 결과도 안 냄(원래도 미사용이었으므로 확인용).

- [ ] **Step 12: 커밋**

```bash
git add circuits/pi_ppid.circom circuits/pi_arid_i.circom tests/test_pi_arid_i_no_rid.js tests/test_pi_ppid_poseidon.js tests/test_ppid_cross_rp_unlinkability.js build/mode2/pi_ppid.r1cs build/mode2/pi_ppid.sym build/mode2/pi_ppid_js build/mode2/pi_ppid_0000.zkey build/mode2/pi_ppid_final.zkey build/mode2/pi_ppid_vkey.json build/mode2/pi_arid_i.r1cs build/mode2/pi_arid_i.sym build/mode2/pi_arid_i_js build/mode2/pi_arid_i_0000.zkey build/mode2/pi_arid_i_final.zkey build/mode2/pi_arid_i_vkey.json
git rm circuits/pi_auid.circom build/mode2/pi_auid.r1cs build/mode2/pi_auid.sym build/mode2/pi_auid_0000.zkey build/mode2/pi_auid_final.zkey build/mode2/pi_auid_vkey.json
git rm -r build/mode2/pi_auid_js
git commit -m "feat(mode2): derive PPID via Poseidon(uid,rid,salt) instead of multiplication

Replaces the transparent multiplicative PPID relation, which let a
third party cross-multiply two RPs' public PPID/rid pairs to detect a
shared uid*salt without knowing either, with the paper's formal
auid = H(uid, rid, salt) construction. Scoped to pi_ppid.circom and
pi_arid_i.circom's internal derivation only; auid_i = PPID * rp_nonce
and all public interfaces/names are unchanged. Removes the unused
legacy pi_auid.circom that this supersedes."
```

---

### Task 2: `wallet_agent.js`/`client.js`를 새 공식에 맞춘다

**Files:**
- Modify: `wallet_agent.js` (Step 8 핸들러 내 `ppid` 계산부, 현재 388행 근방)
- Modify: `client.js:631-632` (설명 주석)

**Interfaces:**
- Consumes: Task 1이 만든 `build/mode2/pi_ppid_final.zkey`/`pi_ppid_js/pi_ppid.wasm`, `build/mode2/pi_arid_i_final.zkey`/`pi_arid_i_js/pi_arid_i.wasm` (경로 변경 없음). `wallet_agent.js`에 이미 있는 모듈 레벨 `poseidon` 객체(`buildPoseidon()`으로 생성됨, 파일 내 96/400행 등에서 이미 `poseidon.F.toObject(poseidon([...]))` 형태로 쓰이는 것과 동일한 인스턴스).
- Produces: `POST /generateStep8Proofs`의 `ppid` 필드가 이제 `Poseidon(uid, rid, salt)` 값 — 이후 요청 흐름(온체인 제출 등)은 이 값을 그대로 opaque하게 실어 나르므로 하위 소비자 인터페이스는 변경 없음.

- [ ] **Step 1: `wallet_agent.js`의 `ppid` 계산을 Poseidon으로 교체**

`wallet_agent.js`에서 다음 블록을 찾는다:

```js
    // PPID = uid * rid * salt, arid_i = rid * rp_nonce, auid_i = PPID * rp_nonce
    const ppid = (uidField * rid * saltField) % FIELD_PRIME;
    const arid_i = (rid * rpNonceField) % FIELD_PRIME;
    const auid_i = (ppid * rpNonceField) % FIELD_PRIME;
```

다음으로 교체:

```js
    // ppid = Poseidon(uid, rid, salt), arid_i = rid * rp_nonce, auid_i = ppid * rp_nonce
    const ppid = poseidon.F.toObject(poseidon([uidField, rid, saltField]));
    const arid_i = (rid * rpNonceField) % FIELD_PRIME;
    const auid_i = (ppid * rpNonceField) % FIELD_PRIME;
```

- [ ] **Step 2: `client.js`의 설명 주석 갱신**

`client.js:631-632`에서:

```js
    // pi_PPID is now a real Groth16 proof (circuits/pi_ppid.circom): it attests that
    // ppid = uid * rid * salt for some hidden uid/salt, with rid and ppid public.
```

다음으로 교체:

```js
    // pi_PPID is a real Groth16 proof (circuits/pi_ppid.circom): it attests that
    // ppid = Poseidon(uid, rid, salt) for some hidden uid/salt, with rid and ppid public.
```

(이 아래의 실제 검증 로직 — `snarkjs.groth16.verify`, `ridFromProof`/`ppidFromProof` 읽기, `auidBindingOk` 재계산 — 은 회로에 위임되는 구조라 변경 없음.)

- [ ] **Step 3: 구문 검사**

Run: `node --check wallet_agent.js && node --check client.js && echo OK`
Expected: `OK`

(이 태스크의 실제 동작 검증 — `/generateStep8Proofs`가 새 Poseidon 기반 `ppid`로 유효한 증명을 만들고, `client.js`의 Step 14 검증이 실제로 통과하는지 — 은 살아있는 서버가 필요하므로 Task 3의 라이브 검증에서 확인한다. `wallet_agent.js`는 이 프로젝트에서 원래 단위 테스트가 아니라 라이브 통합 테스트로 검증되는 파일이다.)

- [ ] **Step 4: 커밋**

```bash
git add wallet_agent.js client.js
git commit -m "feat(mode2): wire wallet_agent.js's ppid computation to the new Poseidon circuits

Single call site (Step 8 handler) now computes ppid the same way
pi_ppid.circom/pi_arid_i.circom verify it. Downstream consumers
(auid_i, both fullProve calls, on-chain submission) already treat
ppid as opaque and need no further changes."
```

---

### Task 3: 서버 재시작, `PPIDWalletFactory` 재배포, 라이브 검증

이 태스크는 컨트롤러가 직접 실행한다(서브에이전트에 위임하지 않음) — 사용자의 실제 로컬 서버/체인 상태를 다루는 운영 작업이라 실행 전 매 단계 사용자 확인이 필요하기 때문이다(CLAUDE.md).

**Files:**
- Create: `scripts/redeploy_ppid_factory.cjs`

**Interfaces:**
- Consumes: Task 1/2가 갱신한 `build/mode2/pi_arid_i_vkey.json`(`custom_idp.js`가 시작 시 1회 로드), 로컬 체인(8545)에 이미 배포된 `PiPkIVerifier`/`PPIDWalletFactory`(재배포 대상), `custom_idp.js`의 `GET /ps_public_keys`(재배포에 쓸 `pk_IdP` 조회).
- Produces: 새 `PPIDWalletFactory` 주소 — `wallet_agent.js` 재시작 시 `PPID_WALLET_FACTORY_ADDRESS` 환경변수로 넘긴다.

- [ ] **Step 1: 사용자에게 재시작 대상 확인**

`custom_idp.js`(4000), `wallet_agent.js`(5001)를 재시작해야 새 vkey/zkey가 반영된다는 것, 그리고 `custom_idp.js` 재시작으로 `pk_IdP`가 바뀌어 `PPIDWalletFactory` 재배포가 필요하다는 것(이번 세션에서 이미 겪은 것과 동일 패턴)을 사용자에게 알리고 진행 승인을 받는다.

- [ ] **Step 2: `custom_idp.js` 재시작**

Run:
```bash
pid=$(lsof -ti :4000 -sTCP:LISTEN)
kill $pid
sleep 1
lsof -i :4000 -sTCP:LISTEN | tail -n +2   # 비어있는지 확인
node custom_idp.js &
```
Expected: 새 프로세스가 4000에서 리스닝, 로그에 `[CustomIdP] PS Signatures Initialized` / `[CustomIdP] EdDSA-Poseidon Signatures Initialized` / `Custom IdP running at http://localhost:4000` 출력.

- [ ] **Step 3: 재배포 스크립트 작성**

`scripts/redeploy_ppid_factory.cjs` 생성:

```js
const hre = require("hardhat");

async function main() {
  const idpBaseUrl = process.env.CUSTOM_IDP_BASE_URL || "http://127.0.0.1:4000";
  const res = await fetch(`${idpBaseUrl}/ps_public_keys`);
  if (!res.ok) {
    throw new Error(`Failed to fetch pk_IdP from ${idpBaseUrl}/ps_public_keys: ${res.status}`);
  }
  const { pk_IdP } = await res.json();
  const [pk_IdP_x, pk_IdP_y] = pk_IdP;

  const Verifier = await hre.ethers.getContractFactory("PiPkIVerifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  console.log("PiPkIVerifier deployed at:", verifierAddress);

  const Factory = await hre.ethers.getContractFactory("PPIDWalletFactory");
  const factory = await Factory.deploy(verifierAddress, pk_IdP_x, pk_IdP_y);
  await factory.waitForDeployment();
  const factoryAddress = await factory.getAddress();
  console.log("PPIDWalletFactory deployed at:", factoryAddress);
  console.log(`\nSet this before starting wallet_agent.js:\nPPID_WALLET_FACTORY_ADDRESS=${factoryAddress}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

이 스크립트는 재사용 가능한 유틸리티다 — `custom_idp.js`가 재시작될 때마다 `pk_IdP`가 바뀌므로, 앞으로도 같은 상황이 생길 때마다 재실행할 수 있다.

- [ ] **Step 4: 재배포 실행**

Run: `npx hardhat run scripts/redeploy_ppid_factory.cjs --network localhost`
Expected: `PiPkIVerifier deployed at: 0x...`, `PPIDWalletFactory deployed at: 0x...` 출력. 새 factory 주소를 기록해둔다.

- [ ] **Step 5: `wallet_agent.js` 재시작**

Run:
```bash
pid=$(lsof -ti :5001 -sTCP:LISTEN)
kill $pid
sleep 1
lsof -i :5001 -sTCP:LISTEN | tail -n +2   # 비어있는지 확인
PPID_WALLET_FACTORY_ADDRESS=<Step 4에서 나온 새 주소> MODE2_ETH_RPC_URL=http://127.0.0.1:8545 node wallet_agent.js &
```
Expected: `[WalletAgent] Local wallet-side Step 8 agent listening on http://127.0.0.1:5001` 출력, pi_pk_i warm-up 4회 완료.

- [ ] **Step 6: 회귀 테스트 재실행 (최종 확인)**

Run:
```bash
node tests/test_pi_ppid_poseidon.js
node tests/test_pi_arid_i_no_rid.js
node tests/test_ppid_cross_rp_unlinkability.js
node tests/test_uid_wallet_boundary.js
```
Expected: 넷 다 에러 없이 `PASS`로 종료(`test_uid_wallet_boundary.js`는 이번 변경과 무관하지만, 같은 회로/파일을 건드렸으니 회귀 확인 차원에서 같이 돌린다).

- [ ] **Step 7: 사용자에게 라이브 브라우저 테스트 요청**

`server.js`(3000)가 이미 떠 있는지 확인하고(없으면 사용자 확인 후 기동), 사용자에게 브라우저에서 새로고침 후 로그인 → Step 14 검증 → 트랜잭션 제출까지 실제로 테스트해달라고 요청한다.

- [ ] **Step 8: 커밋**

```bash
git add scripts/redeploy_ppid_factory.cjs
git commit -m "chore(mode2): add reusable PPIDWalletFactory redeploy script

custom_idp.js regenerates its EdDSA keypair on every restart (not
persisted), so PPIDWallet/PPIDWalletFactory's immutable trusted pk_IdP
goes stale each time. This script fetches the current pk_IdP live and
redeploys both contracts against it."
```

- [ ] **Step 9: 포트 정리 여부 확인**

테스트가 끝나면 이번 태스크에서 새로 띄운 포트(4000, 5001, 그리고 사용자가 켜 달라고 한 경우 3000)를 정리할지 사용자에게 확인한다.

---

## Self-Review

- **스펙 커버리지**: 스펙의 "포함" 목록 6개 항목(두 회로, wallet_agent.js, client.js, 기존 테스트 수정, 신규 unlinkability 테스트, pi_auid 삭제, 빌드 재생성, 서버 재시작+재배포)이 Task 1~3에 모두 매핑됨. "범위 밖" 목록(이름 변경, auid_i 공식, pi_pk_i/컨트랙트/server.js, zk:ptau)은 어느 태스크에서도 건드리지 않음 — Global Constraints에 명시.
- **플레이스홀더 검사**: "TBD"/"나중에" 없음. 모든 스텝에 실행 가능한 정확한 코드/명령이 있음.
- **타입/이름 일관성**: `ppid`/`ppidHasher`/`tokenNonceHasher` 등 Task 1에서 정의한 이름이 Task 2/3에서 그대로 쓰임(Task 2는 wallet_agent.js 쪽 기존 `poseidon` 변수를 그대로 재사용, 새 이름 도입 없음).
