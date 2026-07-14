# EdDSA-Poseidon Auth Token Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the PS (Pointcheval-Sanders) signature the IdP uses to sign Mode 2's auth
token with EdDSA-Poseidon, and move wallet-side verification of that signature out of the
MetaMask Snap (which cannot run the required library) into `wallet_agent.js`.

**Architecture:** `custom_idp.js` gains a second keypair (EdDSA-Poseidon, alongside its
existing PS keypair) and signs the auth token by Poseidon-hashing its fields into one value
and EdDSA-Poseidon-signing that hash. `server.js` and `wallet_agent.js` verify the same way.
`wallet_agent.js` gains a new endpoint that replaces the Snap's `verifyIdPAuthToken` method.

**Tech Stack:** Node.js/Express, `circomlibjs` (`buildEddsa`, `buildPoseidon`), existing
`mcl-wasm`-based PS code (untouched, for `RP_REG` only).

**Spec:** `docs/superpowers/specs/2026-07-14-eddsa-poseidon-auth-token-migration-design.md`

## Global Constraints

- The `RP_REG` signature (used by `/register_rp` and the A7 origin-binding check in
  `wallet_agent.js`) is PS-based and **must not be touched** by any task in this plan.
- `circuits/pi_arid_i.circom` and `circuits/pi_ppid.circom` are **not modified**.
- No new circuit (`pi_pk_i.circom`) is created in this plan — out of scope, follow-up work.
- All field elements are represented as **decimal strings** in JSON payloads (this codebase's
  existing convention — see `wallet_agent.js`'s `rid: rid.toString()` etc.), never hex, never
  raw circomlibjs field-internal representations.
- Reuse the existing `FIELD_PRIME` constant
  (`21888242871839275222246405745257275088548364400416034343698204186575808495617n`) and
  `valueToField`/`bytesToHex` helpers already defined identically in `wallet_agent.js`,
  `client.js`, and `server.js` — port a copy into `custom_idp.js` rather than inventing a new
  scheme.
- Every new network endpoint follows the existing security pattern already used in this
  codebase: `wallet_agent.js` endpoints require the `X-Wallet-Agent-Token` header (already
  enforced by existing middleware, applies automatically to new routes) and are CORS-gated to
  `RP_ORIGIN`.
- All library API usage in this plan was validated against the actually-installed
  `node_modules/circomlibjs` by running a real round-trip script (keygen → sign → verify →
  tamper-and-fail) before this plan was written — the exact validated code is Task 1.

---

## Task 1: Standalone EdDSA-Poseidon round-trip validation script

**Files:**
- Create: `tests/test_eddsa.js`

**Interfaces:**
- Produces: none consumed by later tasks (this is a standalone validation script, mirroring
  `tests/test_ps.js`'s style — no test framework, plain Node script, `process.exit(1)` on
  failure). Later tasks copy the *pattern* shown here (how to build `eddsa`/`poseidon`, how to
  compose `msg`, how to serialize `R8`/`S`) but do not import from this file.

- [ ] **Step 1: Write the script**

```js
// tests/test_eddsa.js
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { randomBytes } from 'crypto';

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function valueToField(value) {
  if (typeof value === 'bigint') return value % FIELD_PRIME;
  if (typeof value === 'number') return BigInt(value) % FIELD_PRIME;
  const str = String(value);
  if (str.startsWith('0x')) return BigInt(str) % FIELD_PRIME;
  if (/^[0-9]+$/.test(str)) return BigInt(str) % FIELD_PRIME;
  const bytes = new TextEncoder().encode(str);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return BigInt(`0x${hex || '0'}`) % FIELD_PRIME;
}

async function test() {
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = eddsa.F;

  // 1. KeyGen — private key is raw entropy (bytes), NOT a field element like PS's mcl.Fr.
  const prv = randomBytes(32);
  const pub = eddsa.prv2pub(prv); // [x, y], each an F-internal representation
  const pubDecimal = [F.toObject(pub[0]).toString(), F.toObject(pub[1]).toString()];
  console.log('pk_IdP (decimal):', pubDecimal);

  // 2. Compose msg exactly like the real auth token will: domain-separated Poseidon hash of
  // the 6 signed fields (matches custom_idp.js's existing PS message array
  // ['IDP_TOKEN', arid_i, auid_i, r_token, max_height, chain_id]).
  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const arid_i = valueToField('123456789');
  const auid_i = valueToField('987654321');
  const r_token = valueToField('555555');
  const max_height = valueToField('1000');
  const chain_id = valueToField('1337');

  // IMPORTANT: pass poseidon(...)'s raw return directly into signPoseidon/verifyPoseidon —
  // do NOT call poseidon.F.toObject() on it first. toObject() produces a plain BigInt for
  // display/JSON, but signPoseidon/verifyPoseidon need the F-internal representation.
  const msg = poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id]);

  // 3. Sign
  const sig = eddsa.signPoseidon(prv, msg);
  const sigJson = {
    R8: [F.toObject(sig.R8[0]).toString(), F.toObject(sig.R8[1]).toString()],
    S: sig.S.toString(),
  };
  console.log('signature (decimal):', sigJson);

  // 4. Verify (happy path) — rebuild msg/pub/sig from decimal strings exactly like a
  // separate process (server.js / wallet_agent.js) would after receiving them over HTTP.
  const pubRebuilt = [F.e(BigInt(pubDecimal[0])), F.e(BigInt(pubDecimal[1]))];
  const sigRebuilt = {
    R8: [F.e(BigInt(sigJson.R8[0])), F.e(BigInt(sigJson.R8[1]))],
    S: BigInt(sigJson.S),
  };
  const msgRebuilt = poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id]);
  const isValid = eddsa.verifyPoseidon(msgRebuilt, sigRebuilt, pubRebuilt);
  console.log('verify (expect true):', isValid);
  if (!isValid) {
    console.error('FAIL: valid signature was rejected');
    process.exit(1);
  }

  // 5. Tamper with one field and confirm verification now fails.
  const tamperedArid = valueToField('999999999');
  const msgTampered = poseidon([DOMAIN_IDP_TOKEN, tamperedArid, auid_i, r_token, max_height, chain_id]);
  const isTamperedValid = eddsa.verifyPoseidon(msgTampered, sigRebuilt, pubRebuilt);
  console.log('verify tampered (expect false):', isTamperedValid);
  if (isTamperedValid) {
    console.error('FAIL: tampered message was accepted');
    process.exit(1);
  }

  console.log('EdDSA-Poseidon round-trip: ALL CHECKS PASSED');
}

test();
```

- [ ] **Step 2: Run it**

Run: `node tests/test_eddsa.js`

Expected output ends with:
```
verify (expect true): true
verify tampered (expect false): false
EdDSA-Poseidon round-trip: ALL CHECKS PASSED
```
Exit code `0`. (This exact script was already run once while writing this plan and produced
this result — re-running now just confirms the committed file matches.)

- [ ] **Step 3: Commit**

```bash
git add tests/test_eddsa.js
git commit -m "test(mode2): add standalone EdDSA-Poseidon round-trip validation script"
```

---

## Task 2: `custom_idp.js` — EdDSA-Poseidon keypair and public key exposure

**Files:**
- Modify: `custom_idp.js:1-10` (imports), `custom_idp.js:48-93` (key state + `initPS`/`hashToFr`), `custom_idp.js:315-321` (`/ps_public_keys` handler), `custom_idp.js:322-326` (`app.listen` startup)

**Interfaces:**
- Produces: module-level `eddsa`, `poseidon` (built instances), `idpEdDSAKeys.pk` (`[x, y]`
  F-internal points), `idpEdDSAKeys.prv` (raw bytes), `valueToField(value)` helper, and a new
  `pk_IdP: [string, string]` field in the JSON returned by `GET /ps_public_keys`.
- Consumed by: Task 3 (signs with `idpEdDSAKeys.prv`), Task 4/5 (read `pk_IdP` from
  `/ps_public_keys`).

- [ ] **Step 1: Add the `circomlibjs` import and port `valueToField`/`bytesToHex`**

In `custom_idp.js`, after the existing imports (after line 10):

```js
import { buildEddsa, buildPoseidon } from 'circomlibjs';
```

After the `hashToFr` function (currently `custom_idp.js:89-93`), add:

```js
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// wallet_agent.js/client.js/server.js에 이미 있는 것과 동일한 구현 — 문자열/숫자를
// Poseidon이 받을 수 있는 필드 원소로 바꾼다. hashToFr()(mcl 전용)와는 호환 안 됨.
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

- [ ] **Step 2: Add EdDSA-Poseidon key state and `initEdDSA()`**

After the `idpKeys` object declaration (currently `custom_idp.js:54-61`), add:

```js
// EdDSA-Poseidon 키쌍 — RP_REG에 쓰는 PS 키(idpKeys)와는 완전히 별개. auth token(IDP_TOKEN)
// 서명 전용.
let eddsa = null;
let poseidon = null;
let idpEdDSAKeys = {
  prv: null, // raw bytes (Buffer) — circomlibjs signPoseidon()이 요구하는 형식, mcl.Fr 아님
  pub: null, // [x, y], F-internal representation
};

async function initEdDSA() {
  eddsa = await buildEddsa();
  poseidon = await buildPoseidon();
  idpEdDSAKeys.prv = randomBytes(32);
  idpEdDSAKeys.pub = eddsa.prv2pub(idpEdDSAKeys.prv);
  console.log('[CustomIdP] EdDSA-Poseidon Signatures Initialized');
}
```

- [ ] **Step 3: Call `initEdDSA()` at startup alongside `initPS()`**

Find the `app.listen` block (currently `custom_idp.js:322-326`):

```js
const server = app.listen(PORT, async () => {
  await initPS();
  await snarkjs.curves.getCurveFromName('bn128'); // bn128 WASM 모듈 미리 빌드 (첫 pi_i 검증 지연 방지)
  console.log(`Custom IdP running at http://localhost:${PORT}`);
});
```

Replace with:

```js
const server = app.listen(PORT, async () => {
  await initPS();
  await initEdDSA();
  await snarkjs.curves.getCurveFromName('bn128'); // bn128 WASM 모듈 미리 빌드 (첫 pi_i 검증 지연 방지)
  console.log(`Custom IdP running at http://localhost:${PORT}`);
});
```

- [ ] **Step 4: Expose `pk_IdP` on `/ps_public_keys`**

Find the handler (currently `custom_idp.js:315-321`):

```js
app.get('/ps_public_keys', (req, res) => {
  res.json({
    g2: psParams.g2.getStr(16),
    X: idpKeys.pk.X.getStr(16),
    Y: idpKeys.pk.Y.map(y => y.getStr(16))
  });
});
```

Replace with:

```js
app.get('/ps_public_keys', (req, res) => {
  res.json({
    g2: psParams.g2.getStr(16),
    X: idpKeys.pk.X.getStr(16),
    Y: idpKeys.pk.Y.map(y => y.getStr(16)),
    pk_IdP: [
      eddsa.F.toObject(idpEdDSAKeys.pub[0]).toString(),
      eddsa.F.toObject(idpEdDSAKeys.pub[1]).toString(),
    ],
  });
});
```

- [ ] **Step 5: Verify manually**

Run in one terminal: `node custom_idp.js`

In another terminal:
```bash
curl -s http://127.0.0.1:4000/ps_public_keys | python3 -c "import sys,json; d=json.load(sys.stdin); print('pk_IdP:', d.get('pk_IdP'))"
```

Expected: two decimal-string numbers printed (not `None`, not an error). Stop the
`custom_idp.js` process (`Ctrl+C`) after confirming.

- [ ] **Step 6: Commit**

```bash
git add custom_idp.js
git commit -m "feat(mode2): generate IdP EdDSA-Poseidon keypair, expose pk_IdP via /ps_public_keys"
```

---

## Task 3: `custom_idp.js` — sign the auth token with EdDSA-Poseidon

**Files:**
- Modify: `custom_idp.js:279-291` (inside `verifyPiIAndIssueToken`)

**Interfaces:**
- Consumes: `eddsa`, `poseidon`, `idpEdDSAKeys.prv`, `valueToField` from Task 2.
- Produces: `idpToken.signature = { R8: [string, string], S: string }` (was
  `{ sigma1, sigma2 }`). All other `idpToken` fields (`arid_i`, `auid_i`, `r_token`,
  `max_height`, `chain_id`, `exp`) are unchanged.
- Consumed by: Task 4 (`server.js` verification), Task 5 (`wallet_agent.js` verification),
  Task 6 (`client.js` relays `idpToken.signature` as `signature_prime`).

- [ ] **Step 1: Replace the signing call**

Find (currently `custom_idp.js:279-291`):

```js
  const messages = ['IDP_TOKEN', business.arid_i, business.auid_i, rToken.toString(), maxHeight.toString(), chainId.toString()];
  const sig = psSign(messages);
  console.log(`[CustomIdP][Step 10] Issuing IdP auth token after consent and pi_i verification. ${ms(start)}`);

  const idpToken = {
    arid_i: business.arid_i,
    auid_i: business.auid_i,
    r_token: rToken.toString(),
    max_height: maxHeight.toString(),
    chain_id: chainId.toString(),
    exp: exp,
    signature: sig
  };
```

Replace with:

```js
  // PS('IDP_TOKEN', ...) 대신 EdDSA-Poseidon: 6개 필드를 Poseidon으로 하나의 값으로 묶은
  // 뒤 그 값을 서명한다. domain 문자열도 다른 필드처럼 valueToField()로 필드 원소화한다
  // (Poseidon은 문자열을 직접 못 받음 — hashToFr()는 mcl 전용이라 여기 못 씀).
  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const msgFields = [
    DOMAIN_IDP_TOKEN,
    valueToField(business.arid_i),
    valueToField(business.auid_i),
    valueToField(rToken.toString()),
    valueToField(maxHeight.toString()),
    valueToField(chainId.toString()),
  ];
  // poseidon(...)의 원본 반환값을 그대로 signPoseidon에 넘긴다 — .toObject()로 변환한
  // BigInt를 넘기면 안 된다 (F-internal 표현이 필요함, tests/test_eddsa.js 참고).
  const msg = poseidon(msgFields);
  const sig = eddsa.signPoseidon(idpEdDSAKeys.prv, msg);
  const sigJson = {
    R8: [
      eddsa.F.toObject(sig.R8[0]).toString(),
      eddsa.F.toObject(sig.R8[1]).toString(),
    ],
    S: sig.S.toString(),
  };
  console.log(`[CustomIdP][Step 10] Issuing IdP auth token after consent and pi_i verification. ${ms(start)}`);

  const idpToken = {
    arid_i: business.arid_i,
    auid_i: business.auid_i,
    r_token: rToken.toString(),
    max_height: maxHeight.toString(),
    chain_id: chainId.toString(),
    exp: exp,
    signature: sigJson
  };
```

- [ ] **Step 2: Confirm `psSign`/`hashToFr` are still used elsewhere (don't delete them)**

Run: `grep -n "psSign\|hashToFr" custom_idp.js`

Expected: both still appear — `psSign` is still used by `/register_rp` (`RP_REG`
signature, untouched per Global Constraints), and `hashToFr` is used inside `psSign`. Do not
remove either function.

- [ ] **Step 3: Commit**

```bash
git add custom_idp.js
git commit -m "feat(mode2): sign IdP auth token with EdDSA-Poseidon instead of PS"
```

(This commit alone leaves `server.js`/`wallet_agent.js` unable to verify the new signature
shape — Tasks 4 and 5 fix that next. That's expected; each task's commit is independently
reviewable but the system isn't end-to-end working again until Task 6 lands.)

---

## Task 4: `server.js` — verify the auth token with EdDSA-Poseidon

**Files:**
- Modify: `server.js:1-16` (imports), `server.js:415-449` (`initRP_PS`), `server.js:571-591` (signature verification call in `/api/mode2/sso_success`)

**Interfaces:**
- Consumes: `rawIdpPublicKeys.pk_IdP` (already cached automatically by the existing
  `rawIdpPublicKeys = data` line in `initRP_PS()` — no change needed there since it stores the
  whole IdP response object).
- Produces: nothing new consumed by other tasks — this task is self-contained.

- [ ] **Step 1: Add the `circomlibjs` import and EdDSA build**

In `server.js`, after the existing imports (near the top, after line 16 or wherever the last
import is):

```js
import { buildEddsa, buildPoseidon } from 'circomlibjs';
```

After the `psParams`/`idpPublicKeys`/`rawIdpPublicKeys` declarations (currently
`server.js:415-418`), add:

```js
let eddsa = null;
let poseidon = null;
async function ensureEdDSA() {
  if (!eddsa) eddsa = await buildEddsa();
  if (!poseidon) poseidon = await buildPoseidon();
}
```

- [ ] **Step 2: Build EdDSA in `initRP_PS()`**

Find the start of `initRP_PS()` (currently `server.js:419-424`):

```js
async function initRP_PS() {
  try {
    await mcl.init(mcl.BN_SNARK1);
    console.log('[Mode 2] MCL Initialized');

    const response = await fetch(`${CUSTOM_IDP_BASE_URL}/ps_public_keys`);
```

Replace with:

```js
async function initRP_PS() {
  try {
    await mcl.init(mcl.BN_SNARK1);
    console.log('[Mode 2] MCL Initialized');
    await ensureEdDSA();

    const response = await fetch(`${CUSTOM_IDP_BASE_URL}/ps_public_keys`);
```

(`rawIdpPublicKeys = data;`, a few lines below this, is unchanged — it already captures the
whole response including the new `pk_IdP` field added in Task 2.)

- [ ] **Step 3: Add a `valueToField` copy if not already present**

Run: `grep -n "^function valueToField" server.js`

If it already exists (it should — this project note says it's already mirrored across
`client.js`/`wallet_agent.js`/`server.js`), skip this step. If it's missing, add the same
implementation shown in Task 2 Step 1 near the existing `FIELD_PRIME` constant
(`server.js:112`).

- [ ] **Step 4: Replace the signature verification call**

Find (currently around `server.js:571-591`, inside `/api/mode2/sso_success`):

```js
  // 1. PS 검증 호출 — psSign()이 서명한 순서(domain, arid_i, auid_i, r_token, max_height, chain_id)와 동일해야 한다.
  const messages_public = [
    'IDP_TOKEN',
    String(idpToken.arid_i),
    String(idpToken.auid_i),
    String(idpToken.r_token),
    String(idpToken.max_height),
    String(idpToken.chain_id)
  ];

  const isSigValid = verifyPS_Hybrid(
    idpToken.signature_prime,
    messages_public,
    idpPublicKeys
  );
  
  if (!isSigValid) {
    return res.status(401).json({ success: false, error: 'Invalid PS Signature' });
  }
```

Replace with:

```js
  // EdDSA-Poseidon 검증 — custom_idp.js가 서명한 것과 동일하게 6개 필드를 Poseidon으로
  // 묶어서 msg를 재계산한 뒤, IdP의 pk_IdP로 검증한다.
  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const msgFields = [
    DOMAIN_IDP_TOKEN,
    valueToField(idpToken.arid_i),
    valueToField(idpToken.auid_i),
    valueToField(idpToken.r_token),
    valueToField(idpToken.max_height),
    valueToField(idpToken.chain_id),
  ];
  const msg = poseidon(msgFields);

  const pkIdPRaw = rawIdpPublicKeys?.pk_IdP;
  if (!pkIdPRaw || pkIdPRaw.length !== 2) {
    return res.status(503).json({ success: false, error: 'IdP EdDSA public key not loaded yet' });
  }
  const pkIdP = [eddsa.F.e(BigInt(pkIdPRaw[0])), eddsa.F.e(BigInt(pkIdPRaw[1]))];
  const sigForVerify = {
    R8: [eddsa.F.e(BigInt(idpToken.signature_prime.R8[0])), eddsa.F.e(BigInt(idpToken.signature_prime.R8[1]))],
    S: BigInt(idpToken.signature_prime.S),
  };

  const isSigValid = eddsa.verifyPoseidon(msg, sigForVerify, pkIdP);

  if (!isSigValid) {
    return res.status(401).json({ success: false, error: 'Invalid EdDSA-Poseidon Signature' });
  }
```

- [ ] **Step 5: Update the required-field check earlier in the same handler**

Find (currently `server.js:513`):

```js
    if (!idpToken.signature_prime?.sigma1 || !idpToken.signature_prime?.sigma2) {
      throw new Error('idpToken.signature_prime is missing');
    }
```

Replace with:

```js
    if (!Array.isArray(idpToken.signature_prime?.R8) || idpToken.signature_prime.R8.length !== 2 || !idpToken.signature_prime?.S) {
      throw new Error('idpToken.signature_prime is missing or malformed');
    }
```

- [ ] **Step 6: Commit**

```bash
git add server.js
git commit -m "feat(mode2): verify IdP auth token with EdDSA-Poseidon instead of PS at RP backend"
```

(Still not end-to-end working — `wallet_agent.js`/`client.js`'s Step 12 path is fixed next in
Tasks 5–6. `server.js`'s own audience/max_height/chain_id checks, unrelated to the signature
swap, are untouched.)

---

## Task 5: `wallet_agent.js` — new `/verifyIdPAuthToken` endpoint

**Files:**
- Modify: `wallet_agent.js:1-9` (imports), `wallet_agent.js:20` (module state), `wallet_agent.js:128-135` (`getIdpPublicKeys`, no change needed but confirm), add new route near `wallet_agent.js:229` (after `/generateStep8Proofs`)

**Interfaces:**
- Consumes: `getIdpPublicKeys()` (existing, already caches the whole `/ps_public_keys`
  response including `pk_IdP` — no change needed), `valueToField` (existing in this file).
- Produces: `POST /verifyIdPAuthToken` — request body `{ idpToken, walletSubmission, business }`
  (same shape the Snap's `verifyIdPAuthToken` method received), response
  `{ success: boolean, message: string, checks: {...}, durationMs: number }` (same shape the
  Snap returned, minus the `snap_dialog` — see Task 6 for how `client.js` now needs to display
  this itself instead of relying on a Snap dialog).
- Consumed by: Task 6 (`client.js`'s `runWalletStep12()`).

- [ ] **Step 1: Add the `buildEddsa` import and cached builder**

Find the imports (currently `wallet_agent.js:1-9`):

```js
import express from 'express';
import cors from 'cors';
import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import mcl from 'mcl-wasm';
```

Replace the `circomlibjs` import line with:

```js
import { buildPoseidon, buildEddsa } from 'circomlibjs';
```

Find the module state near `let poseidon = null;` (currently `wallet_agent.js:20`) and add
alongside it:

```js
let eddsa = null;
async function ensureEdDSA() {
  if (!eddsa) eddsa = await buildEddsa();
  return eddsa;
}
```

- [ ] **Step 2: Port `tokenMessages` binding-check logic from the Snap**

Add this function near `verifyRpCredential` (after `wallet_agent.js:144`, the closing brace of
that function) — this is a direct, unmodified port of
`snap/src/index.js`'s `assertTokenMatchesWalletSubmission` (pure comparison logic, no
crypto library dependency, so it ports as-is):

```js
// snap/src/index.js의 assertTokenMatchesWalletSubmission()을 그대로 이식 — Step 12가
// Snap에서 여기로 옮겨오면서, 토큰 필드가 Step 8에서 지갑이 실제로 제출한 값과
// 일치하는지 대조하는 로직도 같이 옮겨온다.
function assertTokenMatchesWalletSubmission(token, walletSubmission, business) {
  const checks = {
    aridOk: String(token.arid_i) === String(walletSubmission?.arid_i ?? business?.arid_i),
    auidOk: String(token.auid_i) === String(walletSubmission?.auid_i ?? business?.auid_i),
    tokenNonceOk: String(token.r_token) === String(walletSubmission?.r_token ?? business?.r_token ?? business?.tokenNonce),
    maxHeightOk: String(token.max_height) === String(business?.maxHeight ?? business?.max_height),
    chainIdOk: String(token.chain_id) === String(business?.chain_id ?? business?.chainId),
  };
  const success = checks.aridOk && checks.auidOk && checks.tokenNonceOk && checks.maxHeightOk && checks.chainIdOk;
  return { success, checks };
}
```

- [ ] **Step 3: Add the new endpoint**

After the closing `});` of `app.post('/generateStep8Proofs', ...)` (currently ending around
`wallet_agent.js:345`), add:

```js
app.post('/verifyIdPAuthToken', async (req, res) => {
  const start = cursor();
  const verifyStart = now();
  try {
    const { idpToken, walletSubmission, business } = req.body ?? {};
    if (!idpToken) throw new Error('idpToken is required');

    await ensureEdDSA();
    if (!poseidon) throw new Error('Poseidon not initialized yet');

    const idpPublicKeys = await getIdpPublicKeys();
    const pkIdPRaw = idpPublicKeys?.pk_IdP;
    if (!pkIdPRaw || pkIdPRaw.length !== 2) throw new Error('IdP EdDSA public key not available');

    const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
    const msgFields = [
      DOMAIN_IDP_TOKEN,
      valueToField(idpToken.arid_i),
      valueToField(idpToken.auid_i),
      valueToField(idpToken.r_token),
      valueToField(idpToken.max_height),
      valueToField(idpToken.chain_id),
    ];
    const msg = poseidon(msgFields);
    const pkIdP = [eddsa.F.e(BigInt(pkIdPRaw[0])), eddsa.F.e(BigInt(pkIdPRaw[1]))];
    const sig = idpToken.signature ?? {};
    if (!Array.isArray(sig.R8) || sig.R8.length !== 2 || !sig.S) {
      throw new Error('idpToken.signature is missing or malformed');
    }
    const sigForVerify = {
      R8: [eddsa.F.e(BigInt(sig.R8[0])), eddsa.F.e(BigInt(sig.R8[1]))],
      S: BigInt(sig.S),
    };

    let accepted = eddsa.verifyPoseidon(msg, sigForVerify, pkIdP);
    const binding = assertTokenMatchesWalletSubmission(idpToken, walletSubmission, business);
    accepted = accepted && binding.success;
    const message = accepted
      ? 'EdDSA-Poseidon signature and Wallet bindings verified'
      : 'EdDSA-Poseidon signature or Wallet binding verification failed';

    console.log(`[WalletAgent][Step 12] verifyIdPAuthToken: ${accepted ? 'PASS' : 'FAIL'} ${ms(start)}`);
    res.json({ success: accepted, message, checks: binding.checks, durationMs: now() - verifyStart });
  } catch (err) {
    console.error(`[WalletAgent][Step 12] verifyIdPAuthToken error: ${err.message} ${ms(start)}`);
    res.status(400).json({ success: false, message: err.message, checks: {}, durationMs: now() - verifyStart });
  }
});
```

- [ ] **Step 4: Defer manual verification to Task 7**

A realistic `idpToken` (with a genuine EdDSA-Poseidon `signature`) can only be produced by
running the full Step 9–11 flow (login + consent + `pi_i` verification at `custom_idp.js`),
which itself depends on Task 3 already being in place. Rather than hand-constructing a fake
token here, verify this endpoint as part of Task 7's full end-to-end smoke test, which
exercises the real issuance path and then calls this endpoint with the real result.

- [ ] **Step 5: Commit**

```bash
git add wallet_agent.js
git commit -m "feat(mode2): add wallet_agent.js /verifyIdPAuthToken endpoint (EdDSA-Poseidon)"
```

---

## Task 6: `client.js` — Step 12 moves from Snap to `wallet_agent.js`

**Files:**
- Modify: `client.js:474-513` (`runWalletStep12`), `client.js:373-384` (tamper-test button)

**Interfaces:**
- Consumes: `POST http://127.0.0.1:5001/verifyIdPAuthToken` (Task 5), existing
  `/api/mode2/idp_public_keys` same-origin proxy (already returns whatever `/ps_public_keys`
  contains, including `pk_IdP` from Task 2 — no server.js change needed for this specific
  proxy since it already forwards the raw cached object).

- [ ] **Step 1: Replace the Snap call with a `wallet_agent.js` fetch**

Find (currently `client.js:474-513`):

```js
  async function runWalletStep12() {
    const start = now();

    try {
      if (!step11Completed) throw new Error('Step 11 must complete before Step 12');
      if (!walletReceivedIdPToken) throw new Error('Wallet has no IdP auth token');

      const psPublicKeys = await fetch('/api/mode2/idp_public_keys').then((r) => r.json());
      const verification = await window.ethereum.request({
        method: 'wallet_invokeSnap',
        params: {
          snapId,
          request: {
            method: 'verifyIdPAuthToken',
            params: {
              idpToken: walletReceivedIdPToken,
              psPublicKeys,
              walletSubmission: currentSSOProof?.walletSubmission,
              business: currentSSOProof?.business
            },
          },
        },
      });

      ssoMetadata.step12DurationMs = verification?.durationMs ?? null;
      measuredDurations.step12 = verification?.durationMs ?? null;
      const elapsedText = verification?.durationMs != null
        ? `(${Math.round(verification.durationMs)} ms, excluding Snap confirmation)`
        : formatMs(start);
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 12. Wallet verified IdP auth token (PS signature): ${verification?.success ? 'PASS' : 'FAIL'} ${elapsedText}.`;
      ssoMetadata.step12Verified = Boolean(verification?.success);
      if (!ssoMetadata.step12Verified) {
        throw new Error(verification?.message || 'Wallet rejected IdP auth token');
      }
      return true;
    } catch (err) {
      console.warn('[Mode 2] Step 12 Error:', err.message);
      ssoMetadata.step12Verified = false;
      return false;
    }
```

Replace with:

```js
  async function runWalletStep12() {
    const start = now();

    try {
      if (!step11Completed) throw new Error('Step 11 must complete before Step 12');
      if (!walletReceivedIdPToken) throw new Error('Wallet has no IdP auth token');

      // Snap의 SES 샌드박스가 circomlibjs를 거부해서, Step 8과 동일하게 wallet_agent.js
      // 로컬 프로세스에서 검증한다 (더 이상 Snap 다이얼로그로 결과를 안 보여주므로,
      // 아래에서 페이지 화면에 직접 표시한다).
      const tokenRes = await fetch('/api/mode2/wallet_agent_token');
      if (!tokenRes.ok) throw new Error('Failed to obtain wallet agent token');
      const { token } = await tokenRes.json();

      const verifyRes = await fetch('http://127.0.0.1:5001/verifyIdPAuthToken', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
        body: JSON.stringify({
          idpToken: walletReceivedIdPToken,
          walletSubmission: currentSSOProof?.walletSubmission,
          business: currentSSOProof?.business,
        }),
      });
      const verification = await verifyRes.json();

      ssoMetadata.step12DurationMs = verification?.durationMs ?? null;
      measuredDurations.step12 = verification?.durationMs ?? null;
      const elapsedText = verification?.durationMs != null
        ? `(${Math.round(verification.durationMs)} ms)`
        : formatMs(start);
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 12. Wallet verified IdP auth token (EdDSA-Poseidon signature): ${verification?.success ? 'PASS' : 'FAIL'} ${elapsedText}.`;
      ssoMetadata.step12Verified = Boolean(verification?.success);
      if (!ssoMetadata.step12Verified) {
        throw new Error(verification?.message || 'Wallet rejected IdP auth token');
      }
      return true;
    } catch (err) {
      console.warn('[Mode 2] Step 12 Error:', err.message);
      ssoMetadata.step12Verified = false;
      return false;
    }
```

(Only the body of the `try` block changed — the `catch` block and everything else in the
function is unchanged.)

- [ ] **Step 2: Fix the tamper-test button for the new signature shape**

Find (currently `client.js:373-384`):

```js
  document.getElementById('step25RPFEVerifyFail')?.addEventListener('click', () => {
    if (!currentIdPToken || !currentIdPToken.signature) return;
    mode2Status.innerText = 'SIMULATING ERROR: Tampering with IdP PS Signature...';
    
    currentIdPToken.signature.sigma1 = 'f' + currentIdPToken.signature.sigma1.slice(1);
    document.getElementById('step15NotifyWallet').disabled = true;
    document.getElementById('step3CompleteRP').disabled = true;

    console.warn('[Mode 2] IdP PS Signature tampered. RP Backend will reject this.');
    document.getElementById('ssoIntermediateDisplay').innerText += `\n\n[FAIL TEST] PS Signature tampered! Submit now to see RP BE rejection.`;
    mode2Status.innerText = 'Tampering complete. Step 12 or Step 14 should reject it.';
  });
```

Replace with:

```js
  document.getElementById('step25RPFEVerifyFail')?.addEventListener('click', () => {
    if (!currentIdPToken || !currentIdPToken.signature?.S) return;
    mode2Status.innerText = 'SIMULATING ERROR: Tampering with IdP EdDSA-Poseidon Signature...';

    // S is a decimal-string scalar; append a digit to change its value while keeping it a
    // valid decimal string, so it still parses but no longer matches the real signature.
    currentIdPToken.signature.S = currentIdPToken.signature.S + '1';
    document.getElementById('step15NotifyWallet').disabled = true;
    document.getElementById('step3CompleteRP').disabled = true;

    console.warn('[Mode 2] IdP EdDSA-Poseidon Signature tampered. RP Backend will reject this.');
    document.getElementById('ssoIntermediateDisplay').innerText += `\n\n[FAIL TEST] EdDSA-Poseidon Signature tampered! Submit now to see RP BE rejection.`;
    mode2Status.innerText = 'Tampering complete. Step 12 or Step 14 should reject it.';
  });
```

- [ ] **Step 3: Commit**

```bash
git add client.js
git commit -m "feat(mode2): move Step 12 verification from Snap to wallet_agent.js (EdDSA-Poseidon)"
```

---

## Task 7: End-to-end smoke test

**Files:** none (verification only, no code changes)

- [ ] **Step 1: Start all three processes**

```bash
node custom_idp.js &
node wallet_agent.js &
APP_MODE=2 BASE_URL=http://127.0.0.1:3000 CUSTOM_IDP_BASE_URL=http://127.0.0.1:4000 node server.js &
```

Wait ~2 seconds, then confirm all three logged successful startup (in particular
`custom_idp.js` should log `[CustomIdP] EdDSA-Poseidon Signatures Initialized` and
`server.js` should log `[Mode 2] IdP Public Keys loaded for PS Verification` with no errors).

- [ ] **Step 2: Register the RP**

```bash
curl -s -X POST http://127.0.0.1:3000/api/mode2/register -H "Content-Type: application/json" -d '{}'
```

Expected: JSON response with `rid`, `origin`, `signature` fields, no error.

- [ ] **Step 3: Full happy-path flow via the real browser UI**

Since Steps 1–2 (Snap connection) and Step 8 (wallet_agent.js call from the real page) still
require a browser with MetaMask Flask, run the actual demo end-to-end in the browser at
`http://127.0.0.1:3000` through all steps 1–15. Confirm:
- Step 8 still succeeds (unaffected by this plan).
- Step 9–11 succeed and the IdP issues a token with `signature: {R8: [...], S: "..."}`
  (visible in the page's intermediate display or via `console.log` inspection of
  `currentIdPToken`).
- **Step 12 now succeeds without opening a MetaMask Snap dialog** (this is the expected,
  intentional behavior change — verification moved to `wallet_agent.js`, which has no UI).
- Step 10 (RP backend `/api/mode2/sso_success`) accepts the token.
- Steps 13–15 complete as before (unaffected by this plan).

- [ ] **Step 4: Tamper-rejection check**

In the browser, after Step 11 completes, click the "step25RPFEVerifyFail" button (tamper
test) before Step 12 runs, then attempt Step 12. Confirm it now reports FAIL with message
`"EdDSA-Poseidon signature or Wallet binding verification failed"` (from `wallet_agent.js`),
not a crash or a silent pass.

- [ ] **Step 5: Stop all processes and confirm ports are free**

```bash
kill %1 %2 %3 2>/dev/null
sleep 1
lsof -i :3000 -i :4000 -i :5001 2>/dev/null | grep LISTEN || echo "all clear"
```

Expected: `all clear`.

- [ ] **Step 6: Update project memory**

Update the `project-mode2-wallet-agent-architecture` memory file (or add a new one) to record
that Step 12 has moved from the Snap to `wallet_agent.js`, and that auth tokens are now
EdDSA-Poseidon-signed (not PS) — the Snap's `verifyIdPAuthToken` method in
`snap/src/index.js` is now dead code and should be noted as such (not deleted in this plan —
deleting Snap code is out of scope; a future cleanup task can remove it once confirmed
unused).
