# auid(=H(uid,salt)) Wallet-IdP Salt-Binding Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** IdP가 세션(로그인) 간에 같은 계정이 항상 같은 `salt`를 쓰는지 검증할 수 있도록, `pi_arid_i.circom`에 `auid = Poseidon(uid, salt)`라는 새 public input을 추가하고, IdP가 계정별 최근 성공 로그인의 `auid`와 대조해서 불일치 시 로그인을 거부하게 한다.

**Architecture:** `uid`/`salt`는 이미 `pi_arid_i.circom`의 private witness이므로, 새 회로 없이 이 회로 안에서 `auid`를 계산하고 `===`로 강제 검증해 public으로 노출한다. `wallet_agent.js`가 이 값을 witness에 포함시키고, `custom_idp.js`가 증명 검증 성공 직후 계정별 `lastAuid`와 대조(첫 로그인이면 저장, 다르면 거부)한다.

**Tech Stack:** circom 2.0.0, snarkjs(Groth16), circomlibjs(Poseidon), 기존 `pot14_final.ptau` 재사용.

## Global Constraints

- `auid`(신규) = `Poseidon(uid, salt)`, `ppid`(기존, 논문의 PPID) = `Poseidon(uid, rid, salt)` — 이름이 비슷하니 절대 혼동하지 않는다. `auid_i`(기존, = `ppid * rp_nonce`)는 이번 변경과 무관, 손대지 않는다.
- `auid`는 `pi_arid_i.circom`의 public 리스트 **맨 끝**에 추가한다 (`[uid, arid_i, auid_i, max_height, token_nonce, auid]`) — 기존 인덱스 기반 검증(`verifySignals[1]`~`[4]`)이 안 밀리게 하기 위함.
- `auid`는 `signal input auid;`로 선언하고 `auid === bindHasher.out;`(등식 제약)으로 검증한다. 단순 `<==` 대입이 아니어야 한다 — 그러면 프로버가 임의 값을 그냥 우겨넣을 수 있다.
- `circuits/pi_ppid.circom`, `circuits/pi_pk_i.circom`, `contracts/*.sol`, `server.js`는 이번 변경과 무관 — 건드리지 않는다.
- `npm run zk:ptau`는 실행하지 않는다 — 기존 `pot14_final.ptau`를 재사용한다.
- IdP는 증명(Groth16 `isValid`)이 성공한 **이후에만** `auid`를 신뢰/저장한다 — 위조된 증명으로 저장값을 오염시키는 것을 막기 위함.
- 별도의 "커밋먼트 등록/enrollment" 단계는 만들지 않는다 — 계정의 첫 로그인 시 그냥 저장하고, 이후에는 비교만 한다.

---

### Task 1: `pi_arid_i.circom`에 `auid` public input 추가

**Files:**
- Modify: `circuits/pi_arid_i.circom`
- Modify: `tests/test_pi_arid_i_no_rid.js`
- Regenerate: `build/mode2/pi_arid_i.r1cs`, `.sym`, `pi_arid_i_js/`, `pi_arid_i_0000.zkey`, `pi_arid_i_final.zkey`, `pi_arid_i_vkey.json`

**Interfaces:**
- Consumes: 저장소 루트의 기존 `pot14_final.ptau`.
- Produces: `build/mode2/pi_arid_i_final.zkey`/`pi_arid_i_vkey.json`/`pi_arid_i_js/pi_arid_i.wasm` (경로는 기존과 동일, 내용만 6개 public signal로 바뀜) — Task 2가 이 경로들을 그대로 쓴다. 새 public 순서: `[uid, arid_i, auid_i, max_height, token_nonce, auid]`.

- [ ] **Step 1: 현재(수정 전) 회로로 `auid`를 포함한 witness를 만들어보고 실패를 확인 (red 상태)**

`tests/test_pi_arid_i_no_rid.js`를 통째로 다음으로 교체:

```js
import { buildPoseidon } from 'circomlibjs';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function main() {
  const tmpDir = fs.mkdtempSync('/tmp/pi_arid_i_no_rid_test-');

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
  const auid = poseidon.F.toObject(poseidon([uid, salt]));

  const baseInputs = {
    rp_nonce: rp_nonce.toString(),
    salt: salt.toString(),
    rid: rid.toString(),
    pk_i: pk_i.toString(),
    uid: uid.toString(),
    arid_i: arid_i.toString(),
    auid_i: auid_i.toString(),
    max_height: max_height.toString(),
    token_nonce,
    auid: auid.toString(),
  };

  console.log('Compiling circuit...');
  execSync(
    `circom circuits/pi_arid_i.circom --r1cs --wasm --sym -l circuits -o ${tmpDir}`,
    { stdio: 'inherit' }
  );

  console.log('Checking public signal count is 6...');
  const symContent = fs.readFileSync(path.join(tmpDir, 'pi_arid_i.sym'), 'utf8');
  // sanity: rid_public must not appear as a signal name anymore
  if (symContent.includes('rid_public')) {
    throw new Error('FAIL: rid_public signal still present in compiled circuit');
  }
  console.log('PASS: rid_public is gone from the compiled circuit.');

  const inputPathGood = path.join(tmpDir, 'input_good.json');
  fs.writeFileSync(inputPathGood, JSON.stringify(baseInputs, null, 2));

  console.log('Generating witness with consistent inputs (expect success)...');
  execSync(
    `node ${tmpDir}/pi_arid_i_js/generate_witness.js ${tmpDir}/pi_arid_i_js/pi_arid_i.wasm ${inputPathGood} ${tmpDir}/witness_good.wtns`,
    { stdio: 'inherit' }
  );
  console.log('PASS: consistent witness generated.');

  const badAridI = { ...baseInputs, arid_i: (arid_i + 1n).toString() };
  const inputPathBadArid = path.join(tmpDir, 'input_bad_arid.json');
  fs.writeFileSync(inputPathBadArid, JSON.stringify(badAridI, null, 2));

  console.log('Generating witness with a TAMPERED arid_i (expect failure)...');
  try {
    execSync(
      `node ${tmpDir}/pi_arid_i_js/generate_witness.js ${tmpDir}/pi_arid_i_js/pi_arid_i.wasm ${inputPathBadArid} ${tmpDir}/witness_bad_arid.wtns`,
      { stdio: 'pipe' }
    );
    throw new Error('FAIL: witness generation should have failed for a tampered arid_i');
  } catch (err) {
    if (err.message.startsWith('FAIL:')) throw err;
    console.log('PASS: tampered arid_i correctly rejected (constraint violation).');
  }

  const badAuid = { ...baseInputs, auid: (auid + 1n).toString() };
  const inputPathBadAuid = path.join(tmpDir, 'input_bad_auid.json');
  fs.writeFileSync(inputPathBadAuid, JSON.stringify(badAuid, null, 2));

  console.log('Generating witness with a TAMPERED auid (expect failure)...');
  try {
    execSync(
      `node ${tmpDir}/pi_arid_i_js/generate_witness.js ${tmpDir}/pi_arid_i_js/pi_arid_i.wasm ${inputPathBadAuid} ${tmpDir}/witness_bad_auid.wtns`,
      { stdio: 'pipe' }
    );
    throw new Error('FAIL: witness generation should have failed for a tampered auid');
  } catch (err) {
    if (err.message.startsWith('FAIL:')) throw err;
    console.log('PASS: tampered auid correctly rejected (constraint violation).');
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
```

- [ ] **Step 2: 현재(수정 전) 회로로 실행 → `auid` 관련 케이스가 실패해야 정상**

Run: `node tests/test_pi_arid_i_no_rid.js`
Expected: `Compiling circuit...` 단계에서 이미 실패한다 (현재 회로에 `auid`라는 입력 시그널이 없으므로 `circom`이 `input_good.json`에 있는 `auid` 필드를 못 쓰는 게 아니라, witness 생성 단계(`generate_witness.js`)에서 회로가 기대하지 않는 입력 필드가 있다는 에러, 또는 `baseInputs`에 `auid`가 있어도 회로가 그 시그널을 모르면 무시되거나 witness 생성이 실패한다). 정확한 에러 메시지와 무관하게 `TEST FAILED:`로 끝나는 것이 이 시점에는 정상.

- [ ] **Step 3: `pi_arid_i.circom`에 `auid` public input 추가**

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
    signal input auid;

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

    // auid = Poseidon(uid, salt) — a per-account fixed value (no rid, no
    // session nonce) that lets the IdP detect whether this wallet is reusing
    // the same salt across logins. Enforced with === (not <==) so a prover
    // cannot submit an auid that doesn't match the uid/salt actually used
    // elsewhere in this same proof.
    component bindHasher = Poseidon(2);
    bindHasher.inputs[0] <== uid;
    bindHasher.inputs[1] <== salt;
    auid === bindHasher.out;
}

component main {public [uid, arid_i, auid_i, max_height, token_nonce, auid]} = PiAridI();
```

- [ ] **Step 4: `pi_arid_i` 회로/키 재생성**

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
Expected: 에러 없이 완료. `npx snarkjs r1cs info build/mode2/pi_arid_i.r1cs`로 `# of Public Inputs: 6`인지 확인.

- [ ] **Step 5: 테스트 재실행 → 통과해야 함**

Run: `node tests/test_pi_arid_i_no_rid.js`
Expected:
```
PASS: rid_public is gone from the compiled circuit.
PASS: consistent witness generated.
PASS: tampered arid_i correctly rejected (constraint violation).
PASS: tampered auid correctly rejected (constraint violation).
```

- [ ] **Step 6: 커밋**

```bash
git add circuits/pi_arid_i.circom tests/test_pi_arid_i_no_rid.js build/mode2/pi_arid_i.r1cs build/mode2/pi_arid_i.sym build/mode2/pi_arid_i_js build/mode2/pi_arid_i_0000.zkey build/mode2/pi_arid_i_final.zkey build/mode2/pi_arid_i_vkey.json
git commit -m "feat(mode2): add auid=Poseidon(uid,salt) public input to pi_arid_i.circom

Lets the IdP detect a wallet reusing a different salt across logins
for the same account (cross-session PPID uniqueness). auid is a
per-account fixed value, unrelated to auid_i (which stays
session-blinded via rp_nonce, unchanged). Appended as the 6th and
last public signal so existing index-based checks in custom_idp.js
don't shift."
```

---

### Task 2: `wallet_agent.js`/`custom_idp.js` 배선

**Files:**
- Modify: `wallet_agent.js` (Step 8 핸들러, `wallet_agent.js:381-413` 근방)
- Modify: `custom_idp.js` (`users` 객체, `verifyPiIAndIssueToken()`)
- Create: `tests/test_auid_salt_binding.js`

**Interfaces:**
- Consumes: Task 1이 만든 `build/mode2/pi_arid_i_final.zkey`/`pi_arid_i_js/pi_arid_i.wasm`(경로 동일, public 순서 `[uid, arid_i, auid_i, max_height, token_nonce, auid]`), `wallet_agent.js`에 이미 있는 모듈 레벨 `poseidon` 객체.
- Produces: `custom_idp.js`의 `users[username].lastAuid` — 계정별 최근 성공 로그인의 `auid` 저장.

- [ ] **Step 1: `wallet_agent.js`에서 `auid` 계산 및 witness에 포함**

`wallet_agent.js`에서 다음 블록을 찾는다 (약 381-391행):

```js
    const walletSalt = getOrCreateWalletSalt();
    const uidField = valueToField(DEMO_BOUND_UID);
    const saltField = valueToField(walletSalt);
    const rid = BigInt(rpCredential.rid);
    const rpNonceField = valueToField(rpNonce);

    // ppid = Poseidon(uid, rid, salt), arid_i = rid * rp_nonce, auid_i = ppid * rp_nonce
    const ppid = poseidon.F.toObject(poseidon([uidField, rid, saltField]));
    const arid_i = (rid * rpNonceField) % FIELD_PRIME;
    const auid_i = (ppid * rpNonceField) % FIELD_PRIME;
    console.log(`[WalletAgent][Step 8] PPID/arid_i/auid_i computed ${ms(start)}`);
```

다음으로 교체:

```js
    const walletSalt = getOrCreateWalletSalt();
    const uidField = valueToField(DEMO_BOUND_UID);
    const saltField = valueToField(walletSalt);
    const rid = BigInt(rpCredential.rid);
    const rpNonceField = valueToField(rpNonce);

    // ppid = Poseidon(uid, rid, salt), arid_i = rid * rp_nonce, auid_i = ppid * rp_nonce
    const ppid = poseidon.F.toObject(poseidon([uidField, rid, saltField]));
    const arid_i = (rid * rpNonceField) % FIELD_PRIME;
    const auid_i = (ppid * rpNonceField) % FIELD_PRIME;
    // auid = Poseidon(uid, salt) — fixed per account, lets the IdP detect a
    // wallet reusing a different salt across logins for the same uid.
    const auid = poseidon.F.toObject(poseidon([uidField, saltField]));
    console.log(`[WalletAgent][Step 8] PPID/arid_i/auid_i/auid computed ${ms(start)}`);
```

그다음 `aridInputs` 객체(약 403-413행)를 찾는다:

```js
    const aridInputs = {
      rp_nonce: rpNonceField.toString(),
      salt: saltField.toString(),
      rid: rid.toString(),
      pk_i: pkField.toString(),
      uid: uidField.toString(),
      arid_i: arid_i.toString(),
      auid_i: auid_i.toString(),
      max_height: maxHeightField.toString(),
      token_nonce: tokenNonce.toString(),
    };
```

다음으로 교체:

```js
    const aridInputs = {
      rp_nonce: rpNonceField.toString(),
      salt: saltField.toString(),
      rid: rid.toString(),
      pk_i: pkField.toString(),
      uid: uidField.toString(),
      arid_i: arid_i.toString(),
      auid_i: auid_i.toString(),
      max_height: maxHeightField.toString(),
      token_nonce: tokenNonce.toString(),
      auid: auid.toString(),
    };
```

(이 아래 `snarkjs.groth16.fullProve` 호출과 응답 구성 코드는 `publicSignals.slice(1)`처럼 길이에 의존하지 않는 구조라 변경 불필요 — `auid`가 자동으로 같이 전달된다.)

- [ ] **Step 2: `custom_idp.js`의 `users` 객체에 `lastAuid` 필드 추가**

`custom_idp.js`에서:

```js
const users = {
  'testuser': { password: 'password123', uid: '12345', sub: '12345' },
  'alice': { password: 'secret456', uid: '67890', sub: '67890' }
};
```

다음으로 교체:

```js
const users = {
  'testuser': { password: 'password123', uid: '12345', sub: '12345', lastAuid: null },
  'alice': { password: 'secret456', uid: '67890', sub: '67890', lastAuid: null }
};
```

- [ ] **Step 3: `verifyPiIAndIssueToken()`에 auid 대조 로직 추가**

`custom_idp.js`에서 다음 블록을 찾는다:

```js
    if (!zkpProof || !zkpPublicSignals) throw new Error('ZKP data missing');
    assertDecimalSignals(zkpPublicSignals, 4, 'pi_i without uid');

    // The wallet/RP popup payload omits pi_i's public UID signal. The IdP
    // reconstructs it from the authenticated popup account before verification.
    const verifySignals = [user.uid.toString(), ...zkpPublicSignals];
    assertDecimalSignals(verifySignals, 5, 'pi_i');
    console.log(`[CustomIdP][Step 10] BINDING: using Session UID(${summarizeValue(user.uid)}) as pi_i UID input ${ms(start)}`);

    const isValid = await snarkjs.groth16.verify(vkeyAridI, verifySignals, zkpProof);

    if (!isValid) {
      throw new Error('Identity Mismatch: This proof was not made for you!');
    }
    const maxHeight = business?.maxHeight ?? business?.max_height;
```

다음으로 교체:

```js
    if (!zkpProof || !zkpPublicSignals) throw new Error('ZKP data missing');
    assertDecimalSignals(zkpPublicSignals, 5, 'pi_i without uid');

    // The wallet/RP popup payload omits pi_i's public UID signal. The IdP
    // reconstructs it from the authenticated popup account before verification.
    const verifySignals = [user.uid.toString(), ...zkpPublicSignals];
    assertDecimalSignals(verifySignals, 6, 'pi_i');
    console.log(`[CustomIdP][Step 10] BINDING: using Session UID(${summarizeValue(user.uid)}) as pi_i UID input ${ms(start)}`);

    const isValid = await snarkjs.groth16.verify(vkeyAridI, verifySignals, zkpProof);

    if (!isValid) {
      throw new Error('Identity Mismatch: This proof was not made for you!');
    }

    // auid = Poseidon(uid, salt) is the 6th (last) public signal — fixed per
    // account. Only trust it once the proof above has already verified, so a
    // bogus proof can't be used to pollute the stored value. If it differs
    // from the value seen at this account's last successful login, the
    // wallet is using a different salt than before.
    const auidFromProof = verifySignals[5];
    if (user.lastAuid !== null && String(user.lastAuid) !== String(auidFromProof)) {
      throw new Error('Wallet binding mismatch: this account is using a different salt than its last successful login');
    }
    user.lastAuid = auidFromProof;

    const maxHeight = business?.maxHeight ?? business?.max_height;
```

- [ ] **Step 4: 구문 검사**

Run: `node --check wallet_agent.js && node --check custom_idp.js && echo OK`
Expected: `OK`

- [ ] **Step 5: 신규 정적 검증 테스트 작성 및 실행**

`tests/test_auid_salt_binding.js` 생성 (이 프로젝트는 `custom_idp.js`를 모듈로 export하지 않으므로, 기존 `tests/test_uid_wallet_boundary.js`와 같은 소스 정적 검사 방식을 따르고, 대조 로직 자체는 별도로 재현해서 동작을 검증한다):

```js
import assert from 'node:assert/strict';
import fs from 'node:fs';

const circuitSource = fs.readFileSync('circuits/pi_arid_i.circom', 'utf8');
const walletAgentSource = fs.readFileSync('wallet_agent.js', 'utf8');
const idpSource = fs.readFileSync('custom_idp.js', 'utf8');

assert.match(
  circuitSource,
  /signal input auid;/,
  'pi_arid_i.circom must declare auid as a public input',
);
assert.match(
  circuitSource,
  /auid === bindHasher\.out;/,
  'pi_arid_i.circom must constrain auid with === (not a bare assignment)',
);
assert.match(
  circuitSource,
  /component main \{public \[uid, arid_i, auid_i, max_height, token_nonce, auid\]\}/,
  'auid must be the last public signal, after the existing five',
);

assert.match(
  walletAgentSource,
  /const auid = poseidon\.F\.toObject\(poseidon\(\[uidField, saltField\]\)\);/,
  'wallet_agent.js must compute auid = Poseidon(uid, salt)',
);
assert.match(
  walletAgentSource,
  /auid: auid\.toString\(\),/,
  'wallet_agent.js must include auid in the pi_arid_i witness',
);

assert.match(
  idpSource,
  /lastAuid: null/,
  'custom_idp.js must track lastAuid per demo account',
);
assert.match(
  idpSource,
  /assertDecimalSignals\(zkpPublicSignals, 5, 'pi_i without uid'\)/,
  'custom_idp.js must expect 5 signals from the wallet now that auid was added',
);
assert.match(
  idpSource,
  /assertDecimalSignals\(verifySignals, 6, 'pi_i'\)/,
  'custom_idp.js must expect 6 signals after re-prepending uid',
);
assert.match(
  idpSource,
  /Wallet binding mismatch/,
  "custom_idp.js must reject logins whose auid differs from the account's last successful login",
);

// Re-implements the exact compare-and-update logic added to
// verifyPiIAndIssueToken() in isolation, since that function isn't
// exported as a standalone unit (custom_idp.js is a top-level Express
// script, matching this project's existing static-inspection test
// convention for that file — see test_uid_wallet_boundary.js).
function checkAuidBinding(user, auidFromProof) {
  if (user.lastAuid !== null && String(user.lastAuid) !== String(auidFromProof)) {
    throw new Error('Wallet binding mismatch: this account is using a different salt than its last successful login');
  }
  user.lastAuid = auidFromProof;
}

const user = { lastAuid: null };
checkAuidBinding(user, '111'); // first login: bootstrap, no prior value to compare
assert.equal(user.lastAuid, '111');
checkAuidBinding(user, '111'); // same salt again: passes, no change
assert.equal(user.lastAuid, '111');
assert.throws(
  () => checkAuidBinding(user, '222'), // different salt: rejected
  /Wallet binding mismatch/,
);
assert.equal(user.lastAuid, '111', 'a rejected mismatch must not overwrite the stored value');

console.log('PASS: auid salt-binding check enforces same-salt-across-logins per account.');
```

Run: `node tests/test_auid_salt_binding.js`
Expected: `PASS: auid salt-binding check enforces same-salt-across-logins per account.` (아무 assert도 안 던지면 정상 종료)

- [ ] **Step 6: 커밋**

```bash
git add wallet_agent.js custom_idp.js tests/test_auid_salt_binding.js
git commit -m "feat(mode2): wire auid salt-binding check into wallet_agent.js/custom_idp.js

wallet_agent.js computes auid=Poseidon(uid,salt) and includes it in the
pi_arid_i witness. custom_idp.js compares it against the account's
lastAuid (stored after the Groth16 proof already verified, so a bogus
proof can't pollute it) and rejects the login on mismatch. First login
per account just bootstraps the stored value."
```

---

### Task 3: 서버 재시작, `PPIDWalletFactory` 재배포, 라이브 검증

이 태스크는 컨트롤러가 직접 실행한다(서브에이전트에 위임하지 않음) — 실제 로컬 서버/사용자 브라우저를 다루는 운영 작업이라 매 단계 사용자 확인이 필요하다.

**Files:** 없음(기존 `scripts/redeploy_ppid_factory.cjs` 재사용 — 지난 PPID Poseidon 전환 플랜에서 이미 만들어둔 스크립트).

**Interfaces:**
- Consumes: Task 1/2가 갱신한 `build/mode2/pi_arid_i_vkey.json`(`custom_idp.js`가 시작 시 1회 로드), `scripts/redeploy_ppid_factory.cjs`.

- [ ] **Step 1: 사용자에게 재시작 대상 확인**

`custom_idp.js`(4000), `wallet_agent.js`(5001)를 재시작해야 새 vkey/zkey가 반영된다는 것, `custom_idp.js` 재시작으로 `pk_IdP`가 바뀌어 `PPIDWalletFactory` 재배포가 필요하다는 것(기존 `scripts/redeploy_ppid_factory.cjs` 재사용)을 사용자에게 알리고 진행 승인을 받는다. `server.js`는 `pi_arid_i`/`pi_ppid` 검증을 전혀 하지 않으므로 재시작 불필요(이미 떠 있다면 그대로 둔다).

- [ ] **Step 2: `custom_idp.js`/`wallet_agent.js` 재시작**

Run:
```bash
pid4000=$(lsof -ti :4000 -sTCP:LISTEN); [ -n "$pid4000" ] && kill $pid4000
pid5001=$(lsof -ti :5001 -sTCP:LISTEN); [ -n "$pid5001" ] && kill $pid5001
sleep 1
node custom_idp.js &
sleep 3
```
Expected: `Custom IdP running at http://localhost:4000` 출력.

- [ ] **Step 3: `PPIDWalletFactory` 재배포**

Run: `npx hardhat run scripts/redeploy_ppid_factory.cjs --network localhost`
Expected: `PiPkIVerifier deployed at: 0x...`, `PPIDWalletFactory deployed at: 0x...` 출력. 새 factory 주소를 기록해둔다.

- [ ] **Step 4: `wallet_agent.js` 재시작**

Run: `PPID_WALLET_FACTORY_ADDRESS=<Step 3에서 나온 새 주소> MODE2_ETH_RPC_URL=http://127.0.0.1:8545 node wallet_agent.js &`
Expected: `[WalletAgent] Local wallet-side Step 8 agent listening on http://127.0.0.1:5001` 출력, pi_pk_i warm-up 4회 완료.

- [ ] **Step 5: 회귀 테스트 재실행**

Run:
```bash
node tests/test_pi_arid_i_no_rid.js
node tests/test_pi_ppid_poseidon.js
node tests/test_ppid_cross_rp_unlinkability.js
node tests/test_uid_wallet_boundary.js
node tests/test_auid_salt_binding.js
```
Expected: 다섯 개 다 에러 없이 `PASS`로 종료.

- [ ] **Step 6: 사용자에게 라이브 브라우저 테스트 요청**

`server.js`(3000)가 떠 있는지 확인(없으면 사용자 확인 후 기동)하고, 브라우저에서 새로고침 후 같은 계정으로 두 번 로그인해서 (1) 정상 로그인이 계속 성공하는지, (2) 가능하다면 `wallet_state.json`을 조작해 다른 salt를 강제로 써서 두 번째 로그인이 실제로 거부되는지 확인을 요청한다.

- [ ] **Step 7: 포트 정리 여부 확인**

테스트가 끝나면 이번에 새로 띄운 포트를 정리할지 사용자에게 확인한다.

## Self-Review

- **스펙 커버리지**: 스펙의 "포함" 목록(회로 변경, wallet_agent.js, custom_idp.js `lastAuid` 저장/대조, `assertDecimalSignals` 길이 갱신)이 Task 1~2에 모두 매핑됨. "범위 밖" 목록(pi_ppid/pi_pk_i/컨트랙트/server.js, 논문 개정)은 어느 태스크에서도 건드리지 않음.
- **플레이스홀더 검사**: 없음. 모든 스텝에 실행 가능한 정확한 코드/명령이 있음.
- **타입/이름 일관성**: `auid`/`lastAuid`/`auidFromProof`/`bindHasher` 이름이 Task 1→2→3 전체에서 일관되게 쓰임.
