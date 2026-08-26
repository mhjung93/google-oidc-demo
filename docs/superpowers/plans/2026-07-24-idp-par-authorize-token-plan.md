# IdP-side /par + /authorize + /token Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add standards-shaped `POST /par`, `GET/POST /authorize`, `POST /token` endpoints to `custom_idp.js` (RFC 9126 Pushed Authorization Requests + RFC 6749 Authorization Code + RFC 7636 PKCE), issuing a new "PairCT signed login statement" — additive only, existing `/register_rp`/`/sso_with_credentials`/`/consent_result` untouched.

**Architecture:** `/par` structurally validates and stashes an unverified ZKP + PKCE challenge + request-binding signature, returning a short-lived `request_uri`. `GET /authorize` serves a small login/consent page; `POST /authorize/login` is where the ZKP actually gets fully verified (Groth16 `snarkjs.groth16.verify`), because `pi_arid_i`'s first public signal is `uid`, which the IdP only learns after password auth succeeds. `POST /authorize/consent` issues a single-use `code`. `POST /token` redeems the `code` (PKCE-checked, single-use) for the new statement, signed with EdDSA-Poseidon over an extended 9-field message (adds `iss`/`aud`/`nonce` to today's 6 fields).

**Tech Stack:** Node/Express (`custom_idp.js`, unchanged runtime), `ethers` (already a project dependency, used for `recoverAddress`/`keccak256`/`AbiCoder` — new import in this file only), Node's built-in `crypto` (`createHash` for PKCE S256, already imports `randomBytes` from here). No new npm dependencies.

## Global Constraints

- Do not modify `/register_rp`, `/sso_with_credentials`, `/consent_result`, `idp/login_popup.html`, `idp/login_popup.js` — this plan is purely additive.
- Do not modify `circuits/*.circom` or run `zk:compile`/`build_mode2_circuits.sh` — reuse today's `pi_arid_i` (8 public signals: `[uid, arid_i, auid_i, max_height, token_nonce, auid, pk_IdP_x, pk_IdP_y]`) exactly as already deployed.
- `FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n` and `valueToField()` already exist in `custom_idp.js` (lines 113–130) — reuse them, do not redefine.
- All new in-memory stores (`pushedRequests`, `authorizationCodes`) follow the existing pattern of `issuanceLog`/`auidILog`/`usedNonces`: memory-only, lost on restart, documented as intentional demo limitation — do not add file persistence.
- `client_id` is the fixed constant `'pairct-wallet'` — no dynamic client registration.
- `redirect_uri` must match `^http:\/\/127\.0\.0\.1:\d+\/oidc\/callback$` (loopback, any port) — reject anything else.
- Only `code_challenge_method: 'S256'` is supported (reject `'plain'` or anything else).
- PKCE verification: `base64url(SHA256(code_verifier)) === code_challenge`, using Node's built-in `crypto.createHash('sha256').update(code_verifier).digest('base64url')` (Node 22 supports `'base64url'` digest encoding natively — confirmed via `node --version` → `v22.20.0` and a direct test in this session).
- Request-binding signature: `bindingHash = keccak256(AbiCoder.defaultAbiCoder().encode(['string','string','string'], [state, nonce, code_challenge]))`; verify via `ethers.recoverAddress(bindingHash, requestBinding.signature)`, compared case-insensitively against `requestBinding.pk_i`. This exact scheme (keccak256 + AbiCoder + secp256k1 r/s/v signature) matches `wallet_agent.js`'s existing `/submitTransaction` payload-signing convention — Task 2 of the (not-yet-written) Wallet sub-project plan must produce signatures this way.
- New PairCT signed login statement fields: `{ iss: 'custom-idp', aud: 'pairct-wallet', nonce, arid_i, auid_i, r_token, max_height, chain_id, exp, signature: {R8, S} }`. Signed message (EdDSA-Poseidon over Poseidon hash): `[DOMAIN_PAIRCT_STATEMENT, valueToField(iss), valueToField(aud), valueToField(nonce), arid_i, auid_i, r_token, max_height, chain_id]` where `DOMAIN_PAIRCT_STATEMENT = valueToField('PAIRCT_STATEMENT')` — a **different** domain separator from `DOMAIN_IDP_TOKEN`/`DOMAIN_RP_REG`, so old- and new-format signed messages can never collide.
- TTLs: PAR pushed request 60s, authorization code 60s — both measured from issuance, checked via `expiresAt <= Date.now()`.

---

### Task 1: `POST /par`

**Files:**
- Modify: `custom_idp.js` (add imports, constants, in-memory stores, the `/par` route — insert after the existing `/register_rp` handler, i.e. after line 215 in the current file)
- Test: `tests/test_par_endpoint.js` (create)

**Interfaces:**
- Consumes: `assertDecimalSignals(signals, expectedLength, name)` (existing helper, `custom_idp.js:180`), `valueToField(value)` (existing helper, `custom_idp.js:121`).
- Produces: `pushedRequests` Map (`request_uri -> record`), consumed by Task 2. Record shape: `{ redirect_uri, state, nonce, code_challenge, code_challenge_method, zkpProof, zkpPublicSignals, chain_id, requestBinding, expiresAt }`. `POST /par` route consumed by the (future) Wallet sub-project.

- [ ] **Step 1: Add new imports**

At the top of `custom_idp.js`, change:

```js
import { randomBytes } from 'crypto';
```

to:

```js
import { randomBytes, createHash } from 'crypto';
```

And add a new import line right after the existing `import { buildEddsa, buildPoseidon } from 'circomlibjs';` (line 11):

```js
import { recoverAddress, keccak256, AbiCoder } from 'ethers';
```

- [ ] **Step 2: Add constants and in-memory stores**

Insert this block right after the closing `});` of the existing `/register_rp` handler (after line 215, before the `// 1.5. Initial Login` comment on line 217):

```js
// ── PAR (RFC 9126) + Authorization Code + PKCE ── additive alongside the
// existing /register_rp, /sso_with_credentials, /consent_result flow. See
// docs/superpowers/specs/2026-07-24-idp-par-authorize-token-design.md.
const PAIRCT_CLIENT_ID = 'pairct-wallet';
const LOOPBACK_REDIRECT_URI_PATTERN = /^http:\/\/127\.0\.0\.1:\d+\/oidc\/callback$/;
const PAR_REQUEST_TTL_MS = 60 * 1000;
const AUTHORIZATION_CODE_TTL_MS = 60 * 1000;

// request_uri -> { redirect_uri, state, nonce, code_challenge,
// code_challenge_method, zkpProof, zkpPublicSignals, chain_id,
// requestBinding, expiresAt, [authenticatedUid, arid_i, auid_i, max_height,
// token_nonce, auid] }. Memory-only, same "intentional demo limitation" as
// issuanceLog/auidILog/usedNonces below.
const pushedRequests = new Map();
// code -> { redirect_uri, code_challenge, code_challenge_method, nonce,
// arid_i, auid_i, max_height, token_nonce, auid, chain_id, uid, expiresAt }.
const authorizationCodes = new Map();

function pruneExpired(map) {
  const now = Date.now();
  for (const [key, record] of map) {
    if (record.expiresAt <= now) map.delete(key);
  }
}
```

- [ ] **Step 3: Add the `POST /par` route**

Insert immediately after the block from Step 2:

```js
app.post('/par', async (req, res) => {
  pruneExpired(pushedRequests);
  const {
    client_id, redirect_uri, response_type,
    state, nonce, code_challenge, code_challenge_method,
    zkpProof, zkpPublicSignals, chain_id, requestBinding,
  } = req.body ?? {};

  if (client_id !== PAIRCT_CLIENT_ID) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'unknown client_id' });
  }
  if (typeof redirect_uri !== 'string' || !LOOPBACK_REDIRECT_URI_PATTERN.test(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri must be a loopback http://127.0.0.1:{port}/oidc/callback URL' });
  }
  if (response_type !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type' });
  }
  if (!state || !nonce) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'state and nonce are required' });
  }
  if (!code_challenge || code_challenge_method !== 'S256') {
    return res.status(400).json({ error: 'invalid_request', error_description: 'code_challenge (S256) is required' });
  }
  if (!chain_id) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'chain_id is required' });
  }
  if (!requestBinding?.pk_i || !requestBinding?.signature) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'requestBinding.pk_i/signature are required' });
  }
  if (!zkpProof) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'zkpProof is required' });
  }

  // Structural check only — NOT a full Groth16 verify. pi_arid_i's first
  // public signal is uid, which the IdP doesn't know yet (login happens
  // later, at POST /authorize/login). Full verification happens there.
  try {
    assertDecimalSignals(zkpPublicSignals, 7, 'pi_i without uid');
  } catch (err) {
    return res.status(400).json({ error: 'invalid_request', error_description: err.message });
  }

  const bindingHash = keccak256(
    AbiCoder.defaultAbiCoder().encode(['string', 'string', 'string'], [state, nonce, code_challenge]),
  );
  let recovered;
  try {
    recovered = recoverAddress(bindingHash, requestBinding.signature);
  } catch (err) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'requestBinding.signature is malformed' });
  }
  if (recovered.toLowerCase() !== String(requestBinding.pk_i).toLowerCase()) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'requestBinding.signature does not match requestBinding.pk_i' });
  }

  const request_uri = `urn:pairct:par:${randomBytes(24).toString('hex')}`;
  pushedRequests.set(request_uri, {
    redirect_uri, state, nonce, code_challenge, code_challenge_method,
    zkpProof, zkpPublicSignals, chain_id, requestBinding,
    expiresAt: Date.now() + PAR_REQUEST_TTL_MS,
  });

  res.json({ request_uri, expires_in: PAR_REQUEST_TTL_MS / 1000 });
});
```

- [ ] **Step 4: Write the test script**

Create `tests/test_par_endpoint.js`. This needs a *real* `pi_arid_i` proof, so it calls the already-running `wallet_agent.js` (`http://127.0.0.1:5001/generateStep8Proofs`) exactly like the manual curl testing done earlier this session, and builds a real secp256k1 request-binding signature with `@noble/curves` + `ethers` directly (standing in for the Wallet sub-project's not-yet-built signing code).

```js
// Requires custom_idp.js (:4000), server.js (:3000), wallet_agent.js (:5001)
// running against a consistent factory/key set (see CLAUDE.md's restart-chain
// notes). Run: node tests/test_par_endpoint.js
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256, AbiCoder, recoverAddress } from 'ethers';

const IDP = 'http://127.0.0.1:4000';
const SERVER = 'http://127.0.0.1:3000';
const WALLET = 'http://127.0.0.1:5001';

async function getWalletAgentToken() {
  const res = await fetch(`${SERVER}/api/mode2/wallet_agent_token`);
  if (!res.ok) throw new Error(`wallet_agent_token failed: ${res.status}`);
  return (await res.json()).token;
}

async function registerAndGenerateProof() {
  const registration = await (await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })).json();
  const token = await getWalletAgentToken();
  const step8 = await (await fetch(`${WALLET}/generateStep8Proofs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token, Origin: SERVER },
    body: JSON.stringify({ rpCredential: registration, r_i: '111', rpNonce: '222' }),
  })).json();
  if (!step8.zkpProof) throw new Error(`generateStep8Proofs failed: ${JSON.stringify(step8)}`);
  return step8;
}

function signBinding(state, nonce, code_challenge) {
  const sk_i = secp256k1.utils.randomPrivateKey();
  const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
  // pk_i in this project is the Ethereum address of the session key, not the
  // raw public key — mirrors wallet_agent.js's generateNewSessionKey().
  const addressBytes = keccak256('0x' + Buffer.from(pubUncompressed.slice(1)).toString('hex')).slice(-40);
  const pk_i = `0x${addressBytes}`;
  const bindingHash = keccak256(AbiCoder.defaultAbiCoder().encode(['string', 'string', 'string'], [state, nonce, code_challenge]));
  const sigRaw = secp256k1.sign(bindingHash.slice(2), sk_i);
  const signature = '0x' + sigRaw.r.toString(16).padStart(64, '0') + sigRaw.s.toString(16).padStart(64, '0') + (27 + sigRaw.recovery).toString(16).padStart(2, '0');
  const recovered = recoverAddress(bindingHash, signature);
  if (recovered.toLowerCase() !== pk_i.toLowerCase()) throw new Error('self-test: recovered address does not match pk_i');
  return { pk_i, signature };
}

async function main() {
  const step8 = await registerAndGenerateProof();
  const state = 'test-state-1';
  const nonce = 'test-nonce-1';
  const code_challenge = 'dGVzdC1jaGFsbGVuZ2U'; // arbitrary base64url-looking string; /par doesn't verify it against a verifier
  const requestBinding = signBinding(state, nonce, code_challenge);

  console.log('-- valid /par request (expect 200 + request_uri) --');
  const goodRes = await fetch(`${IDP}/par`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: 'pairct-wallet',
      redirect_uri: 'http://127.0.0.1:49999/oidc/callback',
      response_type: 'code',
      state, nonce, code_challenge, code_challenge_method: 'S256',
      zkpProof: step8.zkpProof,
      zkpPublicSignals: step8.zkpPublicSignals,
      chain_id: step8.chain_id,
      requestBinding,
    }),
  });
  const goodBody = await goodRes.json();
  if (goodRes.status !== 200 || !goodBody.request_uri) {
    throw new Error(`FAIL: expected 200 + request_uri, got ${goodRes.status} ${JSON.stringify(goodBody)}`);
  }
  console.log('PASS:', goodBody.request_uri);

  console.log('-- wrong client_id (expect 400) --');
  const badClientRes = await fetch(`${IDP}/par`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: 'someone-else', redirect_uri: 'http://127.0.0.1:1/oidc/callback', response_type: 'code', state: 'x', nonce: 'y', code_challenge: 'z', code_challenge_method: 'S256', zkpProof: {}, zkpPublicSignals: [], chain_id: '1', requestBinding: { pk_i: '0x0', signature: '0x0' } }),
  });
  if (badClientRes.status !== 400) throw new Error(`FAIL: expected 400, got ${badClientRes.status}`);
  console.log('PASS: bad client_id rejected');

  console.log('-- non-loopback redirect_uri (expect 400) --');
  const badRedirectRes = await fetch(`${IDP}/par`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: 'pairct-wallet', redirect_uri: 'http://evil.example.com/callback', response_type: 'code', state: 'x', nonce: 'y', code_challenge: 'z', code_challenge_method: 'S256', zkpProof: {}, zkpPublicSignals: [], chain_id: '1', requestBinding: { pk_i: '0x0', signature: '0x0' } }),
  });
  if (badRedirectRes.status !== 400) throw new Error(`FAIL: expected 400, got ${badRedirectRes.status}`);
  console.log('PASS: non-loopback redirect_uri rejected');

  console.log('-- tampered requestBinding signature (expect 400) --');
  const tamperedBinding = { pk_i: requestBinding.pk_i, signature: requestBinding.signature.slice(0, -2) + '00' };
  const badSigRes = await fetch(`${IDP}/par`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: 'pairct-wallet', redirect_uri: 'http://127.0.0.1:49999/oidc/callback', response_type: 'code',
      state, nonce, code_challenge, code_challenge_method: 'S256',
      zkpProof: step8.zkpProof, zkpPublicSignals: step8.zkpPublicSignals, chain_id: step8.chain_id,
      requestBinding: tamperedBinding,
    }),
  });
  if (badSigRes.status !== 400) throw new Error(`FAIL: expected 400, got ${badSigRes.status}`);
  console.log('PASS: tampered requestBinding signature rejected');

  console.log('ALL PAR TESTS PASSED');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
```

- [ ] **Step 5: Run it**

Ensure `custom_idp.js` (:4000), `server.js` (:3000), and `wallet_agent.js` (:5001) are running against a consistent key/factory set (per this session's established restart-chain procedure). Run: `node tests/test_par_endpoint.js`
Expected: `ALL PAR TESTS PASSED`, no `TEST FAILED`.

- [ ] **Step 6: Commit**

```bash
git add custom_idp.js tests/test_par_endpoint.js
git commit -m "feat(mode2): add POST /par (RFC 9126 Pushed Authorization Request) to custom_idp.js"
```

---

### Task 2: `GET /authorize` + `POST /authorize/login` + `POST /authorize/consent`

**Files:**
- Create: `idp/authorize.html`
- Create: `idp/authorize.js`
- Modify: `custom_idp.js` (insert routes after Task 1's `/par` route)
- Test: `tests/test_authorize_endpoint.js` (create)

**Interfaces:**
- Consumes: `pushedRequests` Map (Task 1), `users` object (existing, `custom_idp.js:159-162`), `vkeyAridI` (existing, `custom_idp.js:19`), `eddsa`/`idpEdDSAKeys` (existing, initialized by `initEdDSA()`).
- Produces: `authorizationCodes` Map (`code -> record`), consumed by Task 3. Record shape: `{ redirect_uri, code_challenge, code_challenge_method, nonce, arid_i, auid_i, max_height, token_nonce, auid, chain_id, uid, expiresAt }`.

- [ ] **Step 1: Create `idp/authorize.html`**

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>PairCT Sign In</title>
</head>
<body>
  <div id="loginSection">
    <h3>A PairCT-compatible wallet application is requesting to sign you in.</h3>
    <input id="username" placeholder="username" /><br />
    <input id="password" type="password" placeholder="password" /><br />
    <button id="loginBtn">Log in</button>
    <p id="status"></p>
  </div>
  <div id="consentSection" style="display:none;">
    <p>Allow this sign-in?</p>
    <button id="allowBtn">Allow</button>
    <button id="denyBtn">Deny</button>
  </div>
  <script src="/idp/authorize.js"></script>
</body>
</html>
```

- [ ] **Step 2: Create `idp/authorize.js`**

```js
const requestUri = new URLSearchParams(location.search).get('request_uri');
const statusEl = document.getElementById('status');
const loginSection = document.getElementById('loginSection');
const consentSection = document.getElementById('consentSection');

document.getElementById('loginBtn').addEventListener('click', async () => {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  statusEl.innerText = 'Verifying...';
  try {
    const res = await fetch('/authorize/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request_uri: requestUri, username, password }),
    });
    const data = await res.json();
    if (!data.success) {
      statusEl.innerText = `Error: ${data.error}`;
      return;
    }
    loginSection.style.display = 'none';
    consentSection.style.display = 'block';
  } catch (err) {
    statusEl.innerText = `Error: ${err.message}`;
  }
});

async function submitConsent(allowed) {
  const res = await fetch('/authorize/consent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: requestUri, allowed }),
  });
  const data = await res.json();
  if (data.redirectTo) {
    window.location.href = data.redirectTo;
  } else {
    statusEl.innerText = `Error: ${data.error_description || data.error}`;
  }
}

document.getElementById('allowBtn').addEventListener('click', () => submitConsent(true));
document.getElementById('denyBtn').addEventListener('click', () => submitConsent(false));
```

- [ ] **Step 3: Add the three routes to `custom_idp.js`**

Insert immediately after Task 1's `/par` route:

```js
app.get('/authorize', (req, res) => {
  pruneExpired(pushedRequests);
  const { client_id, request_uri } = req.query;
  if (client_id !== PAIRCT_CLIENT_ID || !pushedRequests.has(request_uri)) {
    return res.status(400).send('Invalid or expired authorization request.');
  }
  res.sendFile(path.join(__dirname, 'idp', 'authorize.html'));
});

app.post('/authorize/login', async (req, res) => {
  pruneExpired(pushedRequests);
  const { request_uri, username, password } = req.body ?? {};
  const record = pushedRequests.get(request_uri);
  if (!record) {
    return res.status(400).json({ success: false, error: 'Invalid or expired authorization request' });
  }
  const user = users[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }

  try {
    const verifySignals = [user.uid.toString(), ...record.zkpPublicSignals];
    assertDecimalSignals(verifySignals, 8, 'pi_i');
    const isValid = await snarkjs.groth16.verify(vkeyAridI, verifySignals, record.zkpProof);
    if (!isValid) throw new Error('Identity Mismatch: This proof was not made for you!');

    const idpPubX = eddsa.F.toObject(idpEdDSAKeys.pub[0]).toString();
    const idpPubY = eddsa.F.toObject(idpEdDSAKeys.pub[1]).toString();
    if (String(verifySignals[6]) !== idpPubX || String(verifySignals[7]) !== idpPubY) {
      throw new Error('pi_i was proven against a different IdP key');
    }

    record.authenticatedUid = user.uid;
    record.arid_i = verifySignals[1];
    record.auid_i = verifySignals[2];
    record.max_height = verifySignals[3];
    record.token_nonce = verifySignals[4];
    record.auid = verifySignals[5];
  } catch (err) {
    return res.status(400).json({ success: false, error: err.message });
  }

  res.json({ success: true });
});

app.post('/authorize/consent', (req, res) => {
  pruneExpired(pushedRequests);
  const { request_uri, allowed } = req.body ?? {};
  const record = pushedRequests.get(request_uri);
  if (!record) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid or expired authorization request' });
  }
  if (!record.authenticatedUid) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Login has not completed for this request' });
  }

  pushedRequests.delete(request_uri); // single-use regardless of outcome

  if (!allowed) {
    return res.json({ redirectTo: `${record.redirect_uri}?error=access_denied&state=${encodeURIComponent(record.state)}` });
  }

  const code = randomBytes(24).toString('hex');
  authorizationCodes.set(code, {
    redirect_uri: record.redirect_uri,
    code_challenge: record.code_challenge,
    code_challenge_method: record.code_challenge_method,
    nonce: record.nonce,
    arid_i: record.arid_i,
    auid_i: record.auid_i,
    max_height: record.max_height,
    token_nonce: record.token_nonce,
    auid: record.auid,
    chain_id: record.chain_id,
    uid: record.authenticatedUid,
    expiresAt: Date.now() + AUTHORIZATION_CODE_TTL_MS,
  });

  res.json({ redirectTo: `${record.redirect_uri}?code=${code}&state=${encodeURIComponent(record.state)}` });
});
```

- [ ] **Step 4: Write the test script**

Create `tests/test_authorize_endpoint.js` — reuses the `registerAndGenerateProof()`/`signBinding()` pattern from `tests/test_par_endpoint.js` (Task 1), then drives `/authorize/login` and `/authorize/consent` directly (no real browser needed, since both are plain JSON POSTs):

```js
// Requires custom_idp.js (:4000), server.js (:3000), wallet_agent.js (:5001)
// running. Run: node tests/test_authorize_endpoint.js
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256, AbiCoder, recoverAddress } from 'ethers';

const IDP = 'http://127.0.0.1:4000';
const SERVER = 'http://127.0.0.1:3000';
const WALLET = 'http://127.0.0.1:5001';

async function getWalletAgentToken() {
  const res = await fetch(`${SERVER}/api/mode2/wallet_agent_token`);
  if (!res.ok) throw new Error(`wallet_agent_token failed: ${res.status}`);
  return (await res.json()).token;
}

async function registerAndGenerateProof() {
  const registration = await (await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })).json();
  const token = await getWalletAgentToken();
  const step8 = await (await fetch(`${WALLET}/generateStep8Proofs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token, Origin: SERVER },
    body: JSON.stringify({ rpCredential: registration, r_i: '111', rpNonce: '222' }),
  })).json();
  if (!step8.zkpProof) throw new Error(`generateStep8Proofs failed: ${JSON.stringify(step8)}`);
  return step8;
}

function signBinding(state, nonce, code_challenge) {
  const sk_i = secp256k1.utils.randomPrivateKey();
  const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
  const addressBytes = keccak256('0x' + Buffer.from(pubUncompressed.slice(1)).toString('hex')).slice(-40);
  const pk_i = `0x${addressBytes}`;
  const bindingHash = keccak256(AbiCoder.defaultAbiCoder().encode(['string', 'string', 'string'], [state, nonce, code_challenge]));
  const sigRaw = secp256k1.sign(bindingHash.slice(2), sk_i);
  const signature = '0x' + sigRaw.r.toString(16).padStart(64, '0') + sigRaw.s.toString(16).padStart(64, '0') + (27 + sigRaw.recovery).toString(16).padStart(2, '0');
  return { pk_i, signature };
}

async function pushRequest(step8) {
  const state = 'authz-test-state';
  const nonce = 'authz-test-nonce';
  const code_challenge = 'dGVzdC1jaGFsbGVuZ2U';
  const requestBinding = signBinding(state, nonce, code_challenge);
  const res = await fetch(`${IDP}/par`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: 'pairct-wallet', redirect_uri: 'http://127.0.0.1:49999/oidc/callback', response_type: 'code',
      state, nonce, code_challenge, code_challenge_method: 'S256',
      zkpProof: step8.zkpProof, zkpPublicSignals: step8.zkpPublicSignals, chain_id: step8.chain_id,
      requestBinding,
    }),
  });
  const body = await res.json();
  if (!body.request_uri) throw new Error(`FAIL: /par did not return request_uri: ${JSON.stringify(body)}`);
  return { request_uri: body.request_uri, state };
}

async function main() {
  const step8 = await registerAndGenerateProof();

  console.log('-- GET /authorize with unknown request_uri (expect 400) --');
  const badGet = await fetch(`${IDP}/authorize?client_id=pairct-wallet&request_uri=urn:pairct:par:doesnotexist`);
  if (badGet.status !== 400) throw new Error(`FAIL: expected 400, got ${badGet.status}`);
  console.log('PASS: unknown request_uri rejected');

  console.log('-- POST /authorize/login with wrong password (expect 401) --');
  const { request_uri: ruWrongPw } = await pushRequest(step8);
  const badLogin = await fetch(`${IDP}/authorize/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: ruWrongPw, username: 'testuser', password: 'WRONG' }),
  });
  if (badLogin.status !== 401) throw new Error(`FAIL: expected 401, got ${badLogin.status}`);
  console.log('PASS: wrong password rejected');

  console.log('-- POST /authorize/consent before login (expect 400) --');
  const consentBeforeLogin = await fetch(`${IDP}/authorize/consent`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: ruWrongPw, allowed: true }),
  });
  if (consentBeforeLogin.status !== 400) throw new Error(`FAIL: expected 400, got ${consentBeforeLogin.status}`);
  console.log('PASS: consent-before-login rejected');

  console.log('-- full happy path: login then consent (expect code in redirectTo) --');
  const { request_uri, state } = await pushRequest(step8);
  const goodLogin = await fetch(`${IDP}/authorize/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri, username: 'testuser', password: 'password123' }),
  });
  const goodLoginBody = await goodLogin.json();
  if (!goodLoginBody.success) throw new Error(`FAIL: login failed: ${JSON.stringify(goodLoginBody)}`);
  console.log('PASS: login succeeded (ZKP fully verified)');

  const consent = await fetch(`${IDP}/authorize/consent`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri, allowed: true }),
  });
  const consentBody = await consent.json();
  const redirectUrl = new URL(consentBody.redirectTo);
  const code = redirectUrl.searchParams.get('code');
  const returnedState = redirectUrl.searchParams.get('state');
  if (!code) throw new Error(`FAIL: no code in redirectTo: ${consentBody.redirectTo}`);
  if (returnedState !== state) throw new Error(`FAIL: state mismatch: ${returnedState} !== ${state}`);
  console.log('PASS: consent issued code, state round-tripped correctly:', code.slice(0, 12) + '...');

  console.log('-- reusing the same request_uri for consent again (expect 400, single-use) --');
  const reuseConsent = await fetch(`${IDP}/authorize/consent`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri, allowed: true }),
  });
  if (reuseConsent.status !== 400) throw new Error(`FAIL: expected 400, got ${reuseConsent.status}`);
  console.log('PASS: request_uri is single-use');

  console.log('ALL AUTHORIZE TESTS PASSED');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
```

- [ ] **Step 5: Run it**

Run: `node tests/test_authorize_endpoint.js`
Expected: `ALL AUTHORIZE TESTS PASSED`, no `TEST FAILED`.

- [ ] **Step 6: Commit**

```bash
git add idp/authorize.html idp/authorize.js custom_idp.js tests/test_authorize_endpoint.js
git commit -m "feat(mode2): add GET/POST /authorize (login + consent) to custom_idp.js"
```

---

### Task 3: `POST /token`

**Files:**
- Modify: `custom_idp.js` (insert route after Task 2's `/authorize/consent` route)
- Test: `tests/test_token_endpoint.js` (create)

**Interfaces:**
- Consumes: `authorizationCodes` Map (Task 2), `eddsa`/`poseidon`/`idpEdDSAKeys` (existing), `valueToField` (existing).
- Produces: PairCT signed login statement JSON (see Global Constraints for exact shape) — this is the final deliverable of this sub-project, consumed by the (future) Wallet sub-project.

- [ ] **Step 1: Add the `POST /token` route**

Insert immediately after Task 2's `/authorize/consent` route:

```js
app.post('/token', async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, code_verifier } = req.body ?? {};

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
  if (client_id !== PAIRCT_CLIENT_ID) {
    return res.status(400).json({ error: 'invalid_client' });
  }
  if (!code || !code_verifier || !redirect_uri) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'code, code_verifier, and redirect_uri are required' });
  }

  const record = authorizationCodes.get(code);
  if (!record || record.expiresAt <= Date.now()) {
    authorizationCodes.delete(code);
    return res.status(400).json({ error: 'invalid_grant', error_description: 'code is invalid, expired, or already used' });
  }
  if (record.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri does not match' });
  }

  const computedChallenge = createHash('sha256').update(code_verifier).digest('base64url');
  if (computedChallenge !== record.code_challenge) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier does not match code_challenge' });
  }

  authorizationCodes.delete(code); // single-use: burn immediately after successful validation

  const exp = Math.floor(Date.now() / 1000) + 3600;
  const DOMAIN_PAIRCT_STATEMENT = valueToField('PAIRCT_STATEMENT');
  const msgFields = [
    DOMAIN_PAIRCT_STATEMENT,
    valueToField('custom-idp'),
    valueToField(PAIRCT_CLIENT_ID),
    valueToField(record.nonce),
    valueToField(record.arid_i),
    valueToField(record.auid_i),
    valueToField(record.token_nonce),
    valueToField(record.max_height),
    valueToField(record.chain_id),
  ];
  const msg = poseidon(msgFields);
  const sig = eddsa.signPoseidon(idpEdDSAKeys.prv, msg);

  res.json({
    iss: 'custom-idp',
    aud: PAIRCT_CLIENT_ID,
    nonce: record.nonce,
    arid_i: record.arid_i,
    auid_i: record.auid_i,
    r_token: record.token_nonce,
    max_height: record.max_height,
    chain_id: record.chain_id,
    exp,
    signature: {
      R8: [eddsa.F.toObject(sig.R8[0]).toString(), eddsa.F.toObject(sig.R8[1]).toString()],
      S: sig.S.toString(),
    },
  });
});
```

- [ ] **Step 2: Write the test script**

Create `tests/test_token_endpoint.js` — drives the full `/par` → `/authorize/login` → `/authorize/consent` → `/token` chain with a real PKCE `code_verifier`/`code_challenge` pair, then checks negative cases:

```js
// Requires custom_idp.js (:4000), server.js (:3000), wallet_agent.js (:5001)
// running. Run: node tests/test_token_endpoint.js
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256, AbiCoder, recoverAddress } from 'ethers';
import { createHash, randomBytes } from 'crypto';
import { buildEddsa, buildPoseidon } from 'circomlibjs';

const IDP = 'http://127.0.0.1:4000';
const SERVER = 'http://127.0.0.1:3000';
const WALLET = 'http://127.0.0.1:5001';

async function getWalletAgentToken() {
  const res = await fetch(`${SERVER}/api/mode2/wallet_agent_token`);
  if (!res.ok) throw new Error(`wallet_agent_token failed: ${res.status}`);
  return (await res.json()).token;
}

async function registerAndGenerateProof() {
  const registration = await (await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })).json();
  const token = await getWalletAgentToken();
  const step8 = await (await fetch(`${WALLET}/generateStep8Proofs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token, Origin: SERVER },
    body: JSON.stringify({ rpCredential: registration, r_i: '111', rpNonce: '222' }),
  })).json();
  if (!step8.zkpProof) throw new Error(`generateStep8Proofs failed: ${JSON.stringify(step8)}`);
  return step8;
}

function signBinding(state, nonce, code_challenge) {
  const sk_i = secp256k1.utils.randomPrivateKey();
  const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
  const addressBytes = keccak256('0x' + Buffer.from(pubUncompressed.slice(1)).toString('hex')).slice(-40);
  const pk_i = `0x${addressBytes}`;
  const bindingHash = keccak256(AbiCoder.defaultAbiCoder().encode(['string', 'string', 'string'], [state, nonce, code_challenge]));
  const sigRaw = secp256k1.sign(bindingHash.slice(2), sk_i);
  const signature = '0x' + sigRaw.r.toString(16).padStart(64, '0') + sigRaw.s.toString(16).padStart(64, '0') + (27 + sigRaw.recovery).toString(16).padStart(2, '0');
  return { pk_i, signature };
}

async function getCode(codeChallenge, redirectUri) {
  const step8 = await registerAndGenerateProof();
  const state = 'token-test-state';
  const nonce = 'token-test-nonce';
  const requestBinding = signBinding(state, nonce, codeChallenge);
  const par = await (await fetch(`${IDP}/par`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: 'pairct-wallet', redirect_uri: redirectUri, response_type: 'code',
      state, nonce, code_challenge: codeChallenge, code_challenge_method: 'S256',
      zkpProof: step8.zkpProof, zkpPublicSignals: step8.zkpPublicSignals, chain_id: step8.chain_id,
      requestBinding,
    }),
  })).json();
  await fetch(`${IDP}/authorize/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: par.request_uri, username: 'testuser', password: 'password123' }),
  });
  const consent = await (await fetch(`${IDP}/authorize/consent`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: par.request_uri, allowed: true }),
  })).json();
  return new URL(consent.redirectTo).searchParams.get('code');
}

async function main() {
  const redirectUri = 'http://127.0.0.1:49998/oidc/callback';
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

  console.log('-- happy path: valid code + correct code_verifier (expect signed statement) --');
  const code = await getCode(codeChallenge, redirectUri);
  const tokenRes = await fetch(`${IDP}/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: 'pairct-wallet', code_verifier: codeVerifier }),
  });
  const statement = await tokenRes.json();
  if (tokenRes.status !== 200 || !statement.signature) {
    throw new Error(`FAIL: expected 200 + signature, got ${tokenRes.status} ${JSON.stringify(statement)}`);
  }
  if (statement.iss !== 'custom-idp' || statement.aud !== 'pairct-wallet') {
    throw new Error(`FAIL: unexpected iss/aud: ${statement.iss}/${statement.aud}`);
  }

  console.log('-- verify the returned signature (EdDSA-Poseidon, 9-field message) --');
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const idpKeysRes = await (await fetch(`${IDP}/ps_public_keys`)).json();
  const pkIdP = [eddsa.F.e(BigInt(idpKeysRes.pk_IdP[0])), eddsa.F.e(BigInt(idpKeysRes.pk_IdP[1]))];
  const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  function valueToField(value) {
    const str = String(value);
    if (/^[0-9]+$/.test(str)) return BigInt(str) % FIELD_PRIME;
    const bytes = new TextEncoder().encode(str);
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
    return BigInt(`0x${hex || '0'}`) % FIELD_PRIME;
  }
  const DOMAIN_PAIRCT_STATEMENT = valueToField('PAIRCT_STATEMENT');
  const msg = poseidon([
    DOMAIN_PAIRCT_STATEMENT, valueToField(statement.iss), valueToField(statement.aud), valueToField(statement.nonce),
    valueToField(statement.arid_i), valueToField(statement.auid_i), valueToField(statement.r_token),
    valueToField(statement.max_height), valueToField(statement.chain_id),
  ]);
  const sigForVerify = {
    R8: [eddsa.F.e(BigInt(statement.signature.R8[0])), eddsa.F.e(BigInt(statement.signature.R8[1]))],
    S: BigInt(statement.signature.S),
  };
  if (!eddsa.verifyPoseidon(msg, sigForVerify, pkIdP)) throw new Error('FAIL: signature does not verify against IdP public key');
  console.log('PASS: signature verifies, iss/aud correct');

  console.log('-- reusing the same code (expect 400, single-use) --');
  const reuseRes = await fetch(`${IDP}/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: 'pairct-wallet', code_verifier: codeVerifier }),
  });
  if (reuseRes.status !== 400) throw new Error(`FAIL: expected 400, got ${reuseRes.status}`);
  console.log('PASS: code reuse rejected');

  console.log('-- wrong code_verifier (expect 400) --');
  const code2 = await getCode(codeChallenge, redirectUri);
  const wrongVerifierRes = await fetch(`${IDP}/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code: code2, redirect_uri: redirectUri, client_id: 'pairct-wallet', code_verifier: 'wrong-verifier' }),
  });
  if (wrongVerifierRes.status !== 400) throw new Error(`FAIL: expected 400, got ${wrongVerifierRes.status}`);
  console.log('PASS: wrong code_verifier rejected');

  console.log('ALL TOKEN TESTS PASSED');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
```

- [ ] **Step 3: Run it**

Run: `node tests/test_token_endpoint.js`
Expected: `ALL TOKEN TESTS PASSED`, no `TEST FAILED`.

- [ ] **Step 4: Commit**

```bash
git add custom_idp.js tests/test_token_endpoint.js
git commit -m "feat(mode2): add POST /token, issuing the PairCT signed login statement"
```

---

### Task 4: Full end-to-end regression + existing-flow non-regression check

**Files:**
- Test: `tests/test_par_authorize_token_e2e.js` (create)

**Interfaces:**
- Consumes: everything from Tasks 1-3, plus the existing `/register_rp`/`/sso_with_credentials`/`/consent_result` flow (to confirm non-regression).

- [ ] **Step 1: Write the script**

Create `tests/test_par_authorize_token_e2e.js` — chains the full new flow once end-to-end (already exercised piecewise in Tasks 1-3's tests, this confirms it also works as one continuous run), then separately confirms the *existing* flow still works untouched:

```js
// Requires custom_idp.js (:4000), server.js (:3000), wallet_agent.js (:5001)
// running. Run: node tests/test_par_authorize_token_e2e.js
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256, AbiCoder } from 'ethers';
import { createHash, randomBytes } from 'crypto';

const IDP = 'http://127.0.0.1:4000';
const SERVER = 'http://127.0.0.1:3000';
const WALLET = 'http://127.0.0.1:5001';

async function getWalletAgentToken() {
  return (await (await fetch(`${SERVER}/api/mode2/wallet_agent_token`)).json()).token;
}

async function registerAndGenerateProof() {
  const registration = await (await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })).json();
  const token = await getWalletAgentToken();
  const step8 = await (await fetch(`${WALLET}/generateStep8Proofs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token, Origin: SERVER },
    body: JSON.stringify({ rpCredential: registration, r_i: '111', rpNonce: '222' }),
  })).json();
  return step8;
}

function signBinding(state, nonce, code_challenge) {
  const sk_i = secp256k1.utils.randomPrivateKey();
  const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
  const addressBytes = keccak256('0x' + Buffer.from(pubUncompressed.slice(1)).toString('hex')).slice(-40);
  const pk_i = `0x${addressBytes}`;
  const bindingHash = keccak256(AbiCoder.defaultAbiCoder().encode(['string', 'string', 'string'], [state, nonce, code_challenge]));
  const sigRaw = secp256k1.sign(bindingHash.slice(2), sk_i);
  const signature = '0x' + sigRaw.r.toString(16).padStart(64, '0') + sigRaw.s.toString(16).padStart(64, '0') + (27 + sigRaw.recovery).toString(16).padStart(2, '0');
  return { pk_i, signature };
}

async function testNewFlow() {
  console.log('=== New PAR -> authorize -> token flow ===');
  const step8 = await registerAndGenerateProof();
  const state = 'e2e-state';
  const nonce = 'e2e-nonce';
  const redirectUri = 'http://127.0.0.1:49997/oidc/callback';
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  const requestBinding = signBinding(state, nonce, codeChallenge);

  const par = await (await fetch(`${IDP}/par`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: 'pairct-wallet', redirect_uri: redirectUri, response_type: 'code',
      state, nonce, code_challenge: codeChallenge, code_challenge_method: 'S256',
      zkpProof: step8.zkpProof, zkpPublicSignals: step8.zkpPublicSignals, chain_id: step8.chain_id,
      requestBinding,
    }),
  })).json();
  if (!par.request_uri) throw new Error(`FAIL: /par: ${JSON.stringify(par)}`);

  const login = await (await fetch(`${IDP}/authorize/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: par.request_uri, username: 'testuser', password: 'password123' }),
  })).json();
  if (!login.success) throw new Error(`FAIL: /authorize/login: ${JSON.stringify(login)}`);

  const consent = await (await fetch(`${IDP}/authorize/consent`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: par.request_uri, allowed: true }),
  })).json();
  const code = new URL(consent.redirectTo).searchParams.get('code');
  if (!code) throw new Error(`FAIL: /authorize/consent: ${JSON.stringify(consent)}`);

  const statement = await (await fetch(`${IDP}/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: 'pairct-wallet', code_verifier: codeVerifier }),
  })).json();
  if (!statement.signature) throw new Error(`FAIL: /token: ${JSON.stringify(statement)}`);

  console.log('PASS: full new flow issued a signed statement:', JSON.stringify({ iss: statement.iss, aud: statement.aud }));
}

async function testExistingFlowUnaffected() {
  console.log('=== Existing /sso_with_credentials + /consent_result flow (non-regression) ===');
  const registration = await (await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })).json();
  const token = await getWalletAgentToken();
  const step8 = await (await fetch(`${WALLET}/generateStep8Proofs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token, Origin: SERVER },
    body: JSON.stringify({ rpCredential: registration, r_i: '333', rpNonce: '444' }),
  })).json();

  const cookieJar = [];
  const ssoRes = await fetch(`${IDP}/sso_with_credentials`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'testuser', password: 'password123',
      zkpProof: step8.zkpProof, zkpPublicSignals: step8.zkpPublicSignals, business: step8.business,
    }),
  });
  const setCookie = ssoRes.headers.get('set-cookie');
  if (setCookie) cookieJar.push(setCookie.split(';')[0]);
  const ssoBody = await ssoRes.json();
  if (!ssoBody.pendingConsent) throw new Error(`FAIL: /sso_with_credentials: ${JSON.stringify(ssoBody)}`);

  const consentRes = await fetch(`${IDP}/consent_result`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookieJar.join('; ') },
    body: JSON.stringify({ allowed: true }),
  });
  const consentBody = await consentRes.json();
  if (!consentBody.success || !consentBody.idpToken) throw new Error(`FAIL: /consent_result: ${JSON.stringify(consentBody)}`);
  console.log('PASS: existing flow still issues a 6-field-signed idpToken unaffected by this change');
}

async function main() {
  await testNewFlow();
  await testExistingFlowUnaffected();
  console.log('ALL E2E TESTS PASSED');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
```

- [ ] **Step 2: Run it**

Run: `node tests/test_par_authorize_token_e2e.js`
Expected: `ALL E2E TESTS PASSED`, no `TEST FAILED`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_par_authorize_token_e2e.js
git commit -m "test(mode2): add end-to-end regression test for /par + /authorize + /token"
```

---

## Self-Review Notes

- **Spec coverage:** All three endpoints (`/par`, `/authorize` family, `/token`) from the spec have a task each. The "ZKP verification deferred to login time" correction (agreed with the user before writing this plan) is reflected in Task 1 (structural-only check) and Task 2 (full `snarkjs.groth16.verify` at `/authorize/login`). PKCE, request-binding signature, single-use `code`/`request_uri`, loopback `redirect_uri` validation, and the 9-field signed statement are each implemented and tested.
- **Additive-only constraint:** Task 4's `testExistingFlowUnaffected()` explicitly re-runs the *old* `/sso_with_credentials`/`/consent_result` path and checks it still works, directly verifying the spec's "완전히 추가적" requirement rather than just asserting it.
- **Type/interface consistency:** `pushedRequests` record fields (Task 1) match exactly what Task 2 reads/writes (`authenticatedUid`, `arid_i`, etc. added in-place). `authorizationCodes` record fields (Task 2) match exactly what Task 3 reads (`record.nonce`, `record.arid_i`, ... `record.chain_id`). The PairCT signed login statement's field names in Task 3's response match the Global Constraints section and the spec exactly.
- **Placeholder scan:** No TBD/TODO; every step has complete, runnable code.
- **Out of scope, confirmed left untouched:** `wallet_agent.js` (loopback listener, browser launch, Snap dialog, `/par`/`/token` calling code), `client.js` (popup/relay simplification), `idp/login_popup.js`/`wallet/relay.*` (removal) — all explicitly deferred to the Wallet and RP sub-project plans per the spec's scope section.
