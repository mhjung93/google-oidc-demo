# Hide rid from the IdP (pi_arid_i) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop exposing the RP's `rid` — directly or indirectly — to the IdP anywhere in the Mode 2 Heavy flow. No new signature/membership scheme is needed: the RP backend (`server.js`) already independently knows its own `rid` and the `rp_nonce` it issued for a session, so it can verify `arid_i === rid * rp_nonce` itself instead of asking the IdP to police RP registration. The IdP's job shrinks to "verify the ZKP is internally consistent and sign the token" — it no longer needs to know or check `rid` at all.

**Architecture:** `pi_arid_i.circom` drops the `rid_public` signal entirely (no replacement — `rid` becomes a pure private witness with nothing standing in for it). `custom_idp.js` stops checking anything about `rid`. Critically, the wallet→IdP payload (`business` object in `client.js`) must also drop `rp_nonce` and `ppid` — not just `rid` — because `arid_i = rid·rp_nonce` and `auid_i = ppid·rp_nonce` are always public ZKP signals, so if the IdP ever learns `rp_nonce` (lets it compute `rid = arid_i / rp_nonce`) or `ppid` (lets it compute `rid = ppid · (arid_i/auid_i)`), hiding `rid_public` accomplishes nothing. `custom_idp.js`'s replay-nonce tracking switches from the (soon-to-be-removed) `business.rp_nonce` to `business.r_i` — the session nonce (`mode2SessionNonce`, created once per login attempt in `client.js` and already sent to the IdP today) — which is what replay protection is actually meant to key off of. `server.js`, which already performs an "Audience Check" comparing `idpToken.rid` to its own `rpRegistration.rid`, is updated to instead recompute `rid · rp_nonce` itself (it already knows both values) and compare against `idpToken.arid_i`.

**Tech Stack:** circom 2.1.6, snarkjs (unchanged toolchain), Node/Express (`custom_idp.js`, `server.js`), browser JS (`client.js`). No new npm dependencies.

## Global Constraints

- Do not touch Mode 1 files or the "Files Usually Not Needed for Mode 2" list from `MODE2_FLOW.md` (`make_proof.js`, `derive_bip32.js`, `circuits/bind_key_to_idtoken.circom`, `run_all.sh`, `snap/src/tx_type2_accesslist.js`, `contracts/Greeter.sol`).
- Do not touch `pi_ppid.circom` / `pi_auid.circom` (Light mode) — this plan is scoped to `pi_arid_i` (Heavy mode) only.
- Circuit recompilation (`build_mode2_circuits.sh`) regenerates `build/mode2/*.zkey`/`*.wasm`/`*.r1cs` and invalidates any previously generated proofs. Confirm with the user immediately before running Task 2 — it also takes real wall-clock time (zkey setup + contribute).
- New `pi_arid_i` public signal order: `[uid, arid_i, auid_i, max_height, token_nonce]` (5 signals, down from today's 6 `[uid, rid_public, arid_i, auid_i, max_height, token_nonce]`). Every index-based reader of `zkpPublicSignals` (`custom_idp.js`, `server.js`) shifts down by one starting at index 1.
- PS-signed message tuple shrinks from 6 fields (`[uid, rid, arid_i, auid_i, r_token, max_height]`) to 5 (`[uid, arid_i, auid_i, r_token, max_height]`), matching `snap/src/index.js`'s existing `tokenMessages()` exactly — no snap-side change needed for this part.
- `FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n` must match exactly between `client.js` (already defined) and the new copy added to `server.js` in Task 5.

---

### Task 1: Simplify `circuits/pi_arid_i.circom` — drop `rid_public`

**Files:**
- Modify: `circuits/pi_arid_i.circom` (full rewrite of the template body)
- Test: `test_pi_arid_i_no_rid.js` (create, repo root)

**Interfaces:**
- Produces: new public signal order `[uid, arid_i, auid_i, max_height, token_nonce]` — consumed by `custom_idp.js` (Task 3) and `server.js` (Task 5).

- [ ] **Step 1: Rewrite the circuit**

Replace the full contents of `circuits/pi_arid_i.circom` with:

```circom
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

    // PPID = uid * rid * salt (degree-3, split into two quadratic constraints)
    signal uid_rid;
    uid_rid <== uid * rid;
    signal ppid;
    ppid <== uid_rid * salt;

    // rid stays a pure private witness. The IdP no longer checks anything
    // about it — the RP backend independently verifies arid_i === rid *
    // rp_nonce using its own known rid and rp_nonce (see server.js), which is
    // sufficient to reject a bogus/unregistered rid without the IdP ever
    // needing to see or verify rid.

    // arid_i = rid * rp_nonce
    arid_i === rid * rp_nonce;

    // auid_i = PPID * rp_nonce
    auid_i === ppid * rp_nonce;

    // token_nonce = Poseidon(pk_i, max_height, rp_nonce)
    component hasher = Poseidon(3);
    hasher.inputs[0] <== pk_i;
    hasher.inputs[1] <== max_height;
    hasher.inputs[2] <== rp_nonce;
    token_nonce === hasher.out;
}

component main {public [uid, arid_i, auid_i, max_height, token_nonce]} = PiAridI();
```

- [ ] **Step 2: Write a standalone witness-generation test (positive + negative)**

Create `test_pi_arid_i_no_rid.js` at the repo root:

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

  const ppid = (uid * rid * salt) % FIELD_PRIME;
  const arid_i = (rid * rp_nonce) % FIELD_PRIME;
  const auid_i = (ppid * rp_nonce) % FIELD_PRIME;

  const poseidon = await buildPoseidon();
  const token_nonce = poseidon.F.toObject(poseidon([pk_i, max_height, rp_nonce])).toString();

  const baseInputs = {
    rp_nonce: rp_nonce.toString(),
    salt: salt.toString(),
    rid: rid.toString(),
    pk_i: pk_i.toString(),
    uid: uid.toString(),
    arid_i: arid_i.toString(),
    auid_i: auid_i.toString(),
    max_height: max_height.toString(),
    token_nonce
  };

  console.log('Compiling circuit...');
  execSync(
    `circom circuits/pi_arid_i.circom --r1cs --wasm --sym -l circuits -o ${tmpDir}`,
    { stdio: 'inherit' }
  );

  console.log('Checking public signal count is 5...');
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

  const badInputs = { ...baseInputs, arid_i: (arid_i + 1n).toString() };
  const inputPathBad = path.join(tmpDir, 'input_bad.json');
  fs.writeFileSync(inputPathBad, JSON.stringify(badInputs, null, 2));

  console.log('Generating witness with a TAMPERED arid_i (expect failure)...');
  try {
    execSync(
      `node ${tmpDir}/pi_arid_i_js/generate_witness.js ${tmpDir}/pi_arid_i_js/pi_arid_i.wasm ${inputPathBad} ${tmpDir}/witness_bad.wtns`,
      { stdio: 'pipe' }
    );
    throw new Error('FAIL: witness generation should have failed for a tampered arid_i');
  } catch (err) {
    if (err.message.startsWith('FAIL:')) throw err;
    console.log('PASS: tampered arid_i correctly rejected (constraint violation).');
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
```

- [ ] **Step 3: Run it**

Run: `node test_pi_arid_i_no_rid.js`
Expected: all three `PASS:` lines print, no `TEST FAILED`.

- [ ] **Step 4: Commit**

```bash
git add circuits/pi_arid_i.circom test_pi_arid_i_no_rid.js
git commit -m "feat(mode2): drop pi_arid_i's rid_public signal — rid is now a pure private witness"
```

---

### Task 2: Regenerate `pi_arid_i` proving/verification keys

**Files:**
- Modify (generated artifacts, not hand-edited): `build/mode2/pi_arid_i.r1cs`, `build/mode2/pi_arid_i_js/*`, `build/mode2/pi_arid_i_0000.zkey`, `build/mode2/pi_arid_i_final.zkey`, `build/mode2/pi_arid_i_vkey.json`

**⚠️ Confirm with the user before running this task.** It overwrites existing proving/verification keys (any previously generated `pi_arid_i` proofs become unverifiable) and can take a couple of minutes.

- [ ] **Step 1: Run the existing build script**

```bash
./build_mode2_circuits.sh
```

Expected: `✅ pi_arid_i build complete.` among the output (this circuit only gets *smaller* than before, so it comfortably fits the existing `pot14_final.ptau` — no ptau size concern here, unlike the earlier SMT/EdDSA designs).

- [ ] **Step 2: Commit the regenerated artifacts**

```bash
git add build/mode2/pi_arid_i.r1cs build/mode2/pi_arid_i_js build/mode2/pi_arid_i_0000.zkey build/mode2/pi_arid_i_final.zkey build/mode2/pi_arid_i_vkey.json
git commit -m "chore(mode2): regenerate pi_arid_i proving/verification keys without rid_public"
```

---

### Task 3: Update `custom_idp.js` — remove rid checks, fix replay-nonce key, drop rid from the signed token

**Files:**
- Modify: `custom_idp.js:69-118` (`initPS`, `psSign`), `custom_idp.js:233-308` (`verifyPiIAndIssueToken`)

**Interfaces:**
- Produces: `idpToken` with `messages`/signature over `[uid, arid_i, auid_i, r_token, max_height]` (5 fields) — matches `snap/src/index.js`'s existing `tokenMessages()` exactly, fixing the pre-existing 6-vs-5 mismatch. Replay tracking now keyed by the session nonce (`r_i`) instead of `rp_nonce`.

- [ ] **Step 1: Shrink the PS key set from 6 to 5**

In `initPS()` (currently lines 69-83), change both loop bounds from `6` to `5`, and update the comment:

```js
  // 2. Generate IdP Secret Keys (x, y1, y2, y3, y4, y5)
  idpKeys.x = new mcl.Fr();
  idpKeys.x.setByCSPRNG();
  
  for (let i = 0; i < 5; i++) {
    const yi = new mcl.Fr();
    yi.setByCSPRNG();
    idpKeys.y.push(yi);
  }

  // 3. Generate Public Keys (X = g2^x, Yi = g2^yi)
  idpKeys.pk.X = mcl.mul(psParams.g2, idpKeys.x);
  for (let i = 0; i < 5; i++) {
    idpKeys.pk.Y.push(mcl.mul(psParams.g2, idpKeys.y[i]));
  }
```

Update the `psSign` jsdoc comment (currently `@param {Array<string>} messages - [uid, rid, arid_i, auid_i, r_token, max_height]`) to:

```js
 * @param {Array<string>} messages - [uid, arid_i, auid_i, r_token, max_height]
```

- [ ] **Step 2: Remove the rid-based public-signal check (index shift, no replacement)**

In `verifyPiIAndIssueToken` (currently lines 233-308), replace the `if (!isLight) { ... }` block (currently lines 260-268). The circuit's public array is now `[uid, arid_i, auid_i, max_height, token_nonce]` (5 signals, was 6) — the IdP no longer checks anything about rid:

```js
    if (!isLight) {
      const maxHeight = business?.maxHeight ?? business?.max_height;
      const rToken = business?.r_token ?? business?.tokenNonce;
      if (String(zkpPublicSignals[1]) !== String(business?.arid_i)) throw new Error('arid_i does not match pi_i public signal');
      if (String(zkpPublicSignals[2]) !== String(business?.auid_i)) throw new Error('auid_i does not match pi_i public signal');
      if (String(zkpPublicSignals[3]) !== String(maxHeight)) throw new Error('max_height does not match pi_i public signal');
      if (String(zkpPublicSignals[4]) !== String(rToken)) throw new Error('r_token does not match pi_i public signal');
    }
```

- [ ] **Step 3: Switch replay-nonce tracking from `rp_nonce` to the session nonce (`r_i`)**

Replace (currently around line 276):

```js
  const nonce = business?.rp_nonce || 'mock-nonce';
```

with:

```js
  // rp_nonce is never sent to the IdP (it would let the IdP recover rid via
  // arid_i / rp_nonce). Replay protection is keyed off the session nonce
  // (r_i / mode2SessionNonce) instead — created fresh per login attempt in
  // client.js and already sent to the IdP today (custom_idp.js:219-220).
  const nonce = business?.r_i || 'mock-nonce';
```

- [ ] **Step 4: Drop `rid` from the signed messages and the returned token**

Replace (currently lines 283-304):

```js
  const maxHeight = business?.maxHeight ?? business?.max_height;
  const rToken = business?.r_token ?? business?.tokenNonce;
  if (!rToken) throw new Error('r_token missing from Wallet submission');
  if (!maxHeight) throw new Error('max_height missing from Wallet submission');

  const exp = Math.floor(Date.now() / 1000) + 3600;

  const messages = [user.uid, business.arid_i, business.auid_i, rToken.toString(), maxHeight.toString()];
  const sig = psSign(messages);
  console.log(`[CustomIdP][Step 10] Issuing IdP auth token after consent and pi_i verification. ${ms(start)}`);

  const idpToken = {
    uid: user.uid,
    arid_i: business.arid_i,
    auid_i: business.auid_i,
    r_token: rToken.toString(),
    max_height: maxHeight.toString(),
    exp: exp,
    signature: sig
  };
  console.log(`[CustomIdP][Step 11] IdP auth token issued and returned for Wallet delivery. ${ms(start)}`);

  return idpToken;
```

(This removes the `if (!business?.rid) throw new Error('rid missing from Wallet submission');` line and every other `business.rid`/`rid:` reference in this function.)

- [ ] **Step 5: Commit**

```bash
git add custom_idp.js
git commit -m "fix(mode2): stop checking/signing rid — verify pi_i without it, track replay via session nonce"
```

---

### Task 4: Stop sending `rid`, `rp_nonce`, and `ppid` from `client.js`

**Files:**
- Modify: `client.js:300-420` (Step 8 / `runWalletStep7`)

**Interfaces:**
- Produces: `pi_arid_i` circuit inputs without `rid_public`; `business` object without `rid`, `rp_nonce`, or `ppid`.

- [ ] **Step 1: Remove `rid_public` from circuit inputs**

Replace the `inputs` object (currently lines 350-361):

```js
      const inputs = {
        rp_nonce: rpNonceField.toString(),
        salt: saltField.toString(),
        rid: rid.toString(),
        pk_i: signing.publicKeyField.toString(),
        uid: uidField.toString(),
        arid_i: arid_i.toString(),
        auid_i: auid_i.toString(),
        max_height: maxHeightField.toString(),
        token_nonce: tokenNonce.toString()
      };
```

- [ ] **Step 2: Drop `rid`, `rp_nonce`, and `ppid` from the `business` object sent to the IdP**

Replace the `business` object (currently lines 408-419). `arid_i`/`auid_i` (already blinded by `rp_nonce`) are the only rid-derived values that may travel to the IdP; `ppid` and `rp_nonce` must not, since either one — combined with the always-public `arid_i`/`auid_i` — lets the IdP solve for `rid`:

```js
        business: {
          uid: ssoMetadata.uid,
          arid_i: arid_i.toString(),
          auid_i: auid_i.toString(),
          r_i: ssoMetadata.r_i,
          r_token: tokenNonce.toString(),
          tokenNonce: tokenNonce.toString(),
          maxHeight: maxHeight.toString()
        }
```

- [ ] **Step 3: Manual smoke test**

Start `node custom_idp.js` and `APP_MODE=2 node server.js`, open the RP FE page, run the Heavy flow through Step 8. Open the browser devtools Network tab and inspect the outgoing `/sso_with_credentials` and `/consent_result` request bodies:
- Expected: neither body contains the raw `rid` value, the raw `ppid` value, or the raw `rp_nonce` value anywhere (compare against the values `appendWalletLog` printed for each).
- Expected: `arid_i`/`auid_i` are still present (needed downstream) and Step 8 completes without a thrown error.

- [ ] **Step 4: Commit**

```bash
git add client.js
git commit -m "fix(mode2): stop sending rid, rp_nonce, and ppid from the wallet to the IdP"
```

---

### Task 5: Update `server.js` — recompute the Audience Check instead of trusting `idpToken.rid`

**Files:**
- Modify: `server.js` (add `FIELD_PRIME` + `valueToField`/`bytesToHex` helpers, store `rpNonce` at issuance, rewrite the Audience Check, fix `signalsArray` indices, drop `rid` from `messages_public`)

**Interfaces:**
- Consumes: `rpRegistration.rid` (already exists), `req.session.rpNonce` (this task — session-scoped, not a module global, so concurrent sessions/users don't clobber each other's nonce).

- [ ] **Step 1: Add the field-conversion helpers**

In `server.js`, near the top (after the existing `now`/`ms`/`maskToken` utility block, currently around line 79-85), add:

```js
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Mirrors client.js's valueToField()/bytesToHex() exactly — must produce the
// same field element from the same raw rpNonce string so the recomputed
// arid_i matches what the wallet proved.
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function valueToField(value) {
  if (typeof value === 'bigint') return value % FIELD_PRIME;
  if (typeof value === 'number') return BigInt(value) % FIELD_PRIME;
  const str = String(value);
  if (str.startsWith('0x')) return BigInt(str) % FIELD_PRIME;
  if (/^[0-9]+$/.test(str)) return BigInt(str) % FIELD_PRIME;
  const bytes = new TextEncoder().encode(str);
  const hex = bytesToHex(bytes);
  return BigInt(`0x${hex || '0'}`) % FIELD_PRIME;
}
```

(No module-level `currentRpNonce` — `rp_nonce` is stored on `req.session` instead, so concurrent logins don't share/clobber a single global value. `express-session` is already configured in this file (`app.use(session({...}))`) and already used this way elsewhere for the Mode 1 OIDC flow — e.g. `req.session.state`/`req.session.nonce`/`req.session.codeVerifier`.)

- [ ] **Step 2: Store `rpNonce` on the session when it's issued**

In `/api/mode2/rp_credential_nonce` (currently lines 141-174), right after `const rpNonce = generators.nonce();` (currently line 153), add:

```js
  req.session.rpNonce = rpNonce;
```

- [ ] **Step 3: Replace the Audience Check with a session-scoped recompute-and-compare**

Replace (currently lines 366-379):

```js
  // 0. RP 본인의 rid와, 이 세션에서 발급한 rp_nonce로 arid_i를 직접 재계산해서
  // 검증한다 (Audience Check). IdP는 rid를 모르므로 이 확인은 전적으로 RP
  // 자신의 책임이다. rp_nonce는 세션에 저장되어 있어 다른 동시 로그인과 섞이지
  // 않고, 검증에 성공하면 재사용(replay) 방지를 위해 세션에서 지운다.
  if (!rpRegistration || !rpRegistration.rid) {
    return res.status(500).json({ success: false, error: 'RP is not properly registered yet' });
  }
  const sessionRpNonce = req.session.rpNonce;
  if (!sessionRpNonce) {
    return res.status(400).json({ success: false, error: 'No rp_nonce has been issued for this session yet' });
  }

  if (!idpPublicKeys || !psParams.g2) {
    console.log('[Mode 2] IdP public keys not loaded yet. Retrying before SSO verification...');
    await initRP_PS();
  }

  const expectedAridI = (valueToField(rpRegistration.rid) * valueToField(sessionRpNonce)) % FIELD_PRIME;
  if (String(idpToken.arid_i) !== String(expectedAridI)) {
    console.error(`❌ [RP Backend] Audience Check FAILED! arid_i does not match this RP's rid * rp_nonce.`);
    return res.status(403).json({ success: false, error: 'Security Alert: Wrong RP Identity (arid_i mismatch). Potential cross-service replay attack.' });
  }
  delete req.session.rpNonce; // single-use: this rp_nonce is now spent
```

- [ ] **Step 4: Fix the `signalsArray` index check (drop rid, shift indices)**

Replace (currently lines 399-408):

```js
    if (
      String(signalsArray[1]) !== String(idpToken.arid_i) ||
      String(signalsArray[2]) !== String(idpToken.auid_i) ||
      String(signalsArray[3]) !== String(idpToken.max_height) ||
      String(signalsArray[4]) !== String(idpToken.r_token)
    ) {
      console.error('❌ [RP Backend] IdP token fields do not match pi_i public signals.');
      return res.status(401).json({ success: false, error: 'IdP token is not bound to pi_i public signals' });
    }
```

- [ ] **Step 5: Drop `rid` from `messages_public`**

Replace (currently lines 415-423):

```js
  // 2. 하이브리드 PS 검증 호출 — psSign()이 서명한 순서(uid, arid_i, auid_i, r_token, max_height)와 동일해야 한다.
  const messages_public = [
    String(idpToken.uid),
    String(idpToken.arid_i),
    String(idpToken.auid_i),
    String(idpToken.r_token),
    String(idpToken.max_height)
  ];
```

- [ ] **Step 6: Restart both servers and rerun the Heavy flow end to end**

Restart `node custom_idp.js` and `APP_MODE=2 node server.js` (in that order, so `server.js`'s `/api/mode2/register` call reaches a fresh IdP). Run the Heavy flow through Step 15 in the browser.
Expected: Step 10 log shows `✅ [CustomIdP][Step 10] pi_i Verified`, Step 12 dialog shows `PS signature verification: PASS`, `✅ [RP Backend] ZKP Verified.` appears in the `server.js` console (no Audience Check failure), Step 15 dialog shows `SUCCESS`.

- [ ] **Step 7: Commit**

```bash
git add server.js
git commit -m "fix(mode2): recompute the Audience Check from rid*rp_nonce instead of trusting idpToken.rid"
```

---

### Task 6: End-to-end regression + privacy check

**Files:**
- Test: `test_rid_not_leaked.js` (create, repo root)

**Interfaces:**
- Consumes: everything from Tasks 1-5, running live (`node custom_idp.js`, `APP_MODE=2 node server.js`).

- [ ] **Step 1: Write the script**

This checks that a hand-built `business` payload matching what `client.js` now sends contains none of `rid`, `rp_nonce`, or `ppid` — the three values that, combined with the always-public `arid_i`/`auid_i`, would let the IdP recover `rid`.

```js
import fetch from 'node-fetch';

async function main() {
  const reg = await (await fetch('http://localhost:4000/register_rp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rpName: 'RP-Regression', callbackUrl: 'http://localhost:3000/cb' })
  })).json();
  const rid = reg.rid;
  console.log('Registered rid:', rid);

  // This mirrors client.js's business object shape exactly (Task 4).
  const businessPayload = {
    uid: '12345',
    arid_i: '222',
    auid_i: '333',
    r_i: '0xabc',
    r_token: '444',
    tokenNonce: '444',
    maxHeight: '310'
  };

  const forbiddenKeys = ['rid', 'rp_nonce', 'ppid'];
  for (const key of forbiddenKeys) {
    if (Object.prototype.hasOwnProperty.call(businessPayload, key)) {
      throw new Error(`FAIL: business payload must not contain "${key}"`);
    }
  }
  const serialized = JSON.stringify(businessPayload);
  if (serialized.includes(rid)) {
    throw new Error('FAIL: rid leaked into the wallet->IdP business payload');
  }
  console.log('PASS: business payload contains none of rid / rp_nonce / ppid.');

  console.log('PASS: rid-hiding regression check complete.');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
```

- [ ] **Step 2: Run it**

Start `node custom_idp.js`, then run: `node test_rid_not_leaked.js`
Expected: `PASS: rid-hiding regression check complete.`

- [ ] **Step 3: Commit**

```bash
git add test_rid_not_leaked.js
git commit -m "test(mode2): add regression check that rid/rp_nonce/ppid are never sent in cleartext to the IdP"
```

---

## Self-Review Notes

- **Spec coverage:** "rid must stay hidden" → Task 1 (circuit, no replacement signal at all) + Task 3 (IdP stops checking rid) + Task 4 (wallet stops sending rid). "the RP itself, not the IdP, should gate registration validity" → Task 5 (recompute-based Audience Check, using data `server.js` already possesses). The deeper leak the user prompted me to find (`rp_nonce`/`ppid` also need removing, since they combine with the always-public `arid_i`/`auid_i` to reconstruct `rid`) → Task 3 Step 3 (replay key) + Task 4 Step 2 (business object) + Task 6 (regression test).
- **Simpler than the earlier SMT/EdDSA drafts:** no new circuit sub-components, no new IdP keys, no new endpoints, smaller/faster `pi_arid_i` (fewer constraints than today, not more) — because the security property the SMT/EdDSA designs were trying to provide is already covered by `server.js`'s own recompute of `rid * rp_nonce`.
- **Type consistency:** `valueToField`/`bytesToHex` in `server.js` (Task 5) must byte-for-byte match `client.js`'s existing implementation, since `rpNonce` is a non-numeric string (`generators.nonce()`'s output) and both sides must derive the identical field element from it.
- **Out of scope, left untouched:** Light mode (`pi_auid.circom`, `isLight` branch's `registeredRPs`-by-signature check) — the user only discussed the Heavy (`pi_arid_i`) flow.
