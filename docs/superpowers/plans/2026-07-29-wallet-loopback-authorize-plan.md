# Wallet Loopback + Authorize Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `wallet_agent.js` a working OAuth-shaped client of `custom_idp.js`'s `/par` + `/authorize` + `/token` (built in the prior sub-project): a polling job API for `client.js`, a loopback HTTP listener + system-browser launch, and a Snap `confirmLogin` approval dialog.

**Architecture:** `POST /startLogin` kicks off Step 8 proof generation in the background and returns a `jobId` immediately; `GET /loginStatus` is polled to track progress through a state machine (`generating_proof` → `awaiting_wallet_approval` → `awaiting_browser_login` → `exchanging_token` → `done`/`denied`/`failed`). Because `wallet_agent.js` is a Node process with no access to `window.ethereum`, the Snap confirmation itself is triggered by `client.js` (browser) and reported back via `POST /confirmLoginResult`; on approval, `wallet_agent.js` opens a loopback HTTP listener on an OS-assigned port, calls `POST /par`, opens the system browser to `/authorize`, and on receiving the loopback callback calls `POST /token` to complete the job.

**Tech Stack:** Node's built-in `http` module (loopback listener), the `open` npm package (new dependency, system browser launch), Node's built-in `crypto` (`createHash`/`randomBytes`/`webcrypto.randomUUID` — PKCE + job IDs), `@noble/curves/secp256k1` + `ethers` (`keccak256`/`AbiCoder`, already used by `/submitTransaction` — request-binding signature), MetaMask Snap's `snap_dialog` (already used elsewhere in `snap/src/index.js`).

## Global Constraints

- Do not modify `custom_idp.js`'s `/par`/`/authorize`/`/token` (already complete, from the prior sub-project — this plan is a pure consumer).
- Do not modify `client.js` or `idp/login_popup.js` or `wallet/relay.*` — out of scope (next sub-project).
- Do not touch `circuits/*.circom` — `pi_arid_i`/`pi_PPID` proof generation is reused exactly as-is via the existing `/generateStep8Proofs` logic (refactored into a shared function, not rewritten).
- `custom_idp.js`'s contract, exactly as shipped: `POST /par` takes `{client_id:'pairct-wallet', redirect_uri, response_type:'code', state, nonce, code_challenge, code_challenge_method:'S256', zkpProof, zkpPublicSignals, chain_id, requestBinding:{pk_i,signature}}` and returns `{request_uri, expires_in}`. `requestBinding.signature` is `keccak256(AbiCoder.defaultAbiCoder().encode(['string','string','string'],[state,nonce,code_challenge]))` signed with the session key `sk_i` (secp256k1, r/s/v hex — the exact same construction as `/submitTransaction`'s `payloadHash` signing, `wallet_agent.js` current lines 627-638). `POST /token` takes `{grant_type:'authorization_code', code, redirect_uri, client_id:'pairct-wallet', code_verifier}` and returns the PairCT signed login statement `{iss, aud, nonce, arid_i, auid_i, r_token, max_height, chain_id, exp, signature:{R8,S}}`.
- PKCE: `code_verifier` random, `code_challenge = base64url(SHA256(code_verifier))` via Node's built-in `crypto.createHash('sha256').update(code_verifier).digest('base64url')` — same construction as `custom_idp.js` already uses.
- `redirect_uri` must match `custom_idp.js`'s required pattern `^http:\/\/127\.0\.0\.1:\d+\/oidc\/callback$` — construct it from the loopback server's OS-assigned port.
- Loopback timeout: 90 seconds (margin over `/par`'s 60-second `request_uri` TTL — not touched by this plan; adjusting that TTL was explicitly deferred by the user).
- All new `wallet_agent.js` routes go after the existing `X-Wallet-Agent-Token` auth middleware (`wallet_agent.js:361-368`), same as all other sensitive routes.
- In-memory job store only (`Map`), same pattern as this project's other ephemeral stores (`custom_idp.js`'s `issuanceLog`/`pushedRequests`/etc.) — lost on restart, intentional demo limitation, do not add persistence.
- Job `done` result shape: `{ ppid, arid_i, auid_i, pk_i, publicKeyHex, pi_PPID, statement }` where `statement` is `/token`'s response verbatim and the other fields come from the Step 8 proof-generation result.

---

### Task 1: Refactor Step 8 proof generation into a shared function + job store + `POST /startLogin` + `GET /loginStatus`

**Files:**
- Modify: `wallet_agent.js:374-516` (the existing `/generateStep8Proofs` route)
- Test: `tests/test_wallet_login_job.js` (create)

**Interfaces:**
- Produces: `async function generateStep8ProofsData(rpCredential, r_i, rpNonce)` returning the exact object `/generateStep8Proofs` used to `res.json(...)` (fields: `rid, ppid, rpNonceField, arid_i, auid_i, currentBlock, chain_id, heightSource, maxHeight, tokenNonce, pk_i, publicKeyHex, zkpProof, zkpPublicSignals, pi_PPID, walletSubmission, business, durationMs`) — consumed by Task 2.
- Produces: `const loginJobs = new Map()` (module-level, `jobId -> job record`) and `function pruneExpiredJobs()` — consumed by Task 2.
- Produces: job record shape while pending: `{ status, expiresAt, step8?, error? }` where `status` is one of `'generating_proof' | 'awaiting_wallet_approval' | 'failed'` at the end of this task (Task 2 adds the later statuses) — consumed by Task 2.

- [ ] **Step 1: Extract the proof-generation body into `generateStep8ProofsData`**

In `wallet_agent.js`, replace the existing `app.post('/generateStep8Proofs', ...)` block (current lines 374-516) with:

```js
async function generateStep8ProofsData(rpCredential, r_i, rpNonce) {
  const requestStart = now();
  const start = cursor();
  console.log(`--- [WalletAgent][Step 8] generateStep8Proofs request received ---`);
  console.log(`[WalletAgent][Step 8] rid: ${preview(rpCredential?.rid)}, r_i: ${preview(r_i)}`);

  if (!rpCredential?.rid) throw new Error('rpCredential.rid is required');
  if (!rpCredential?.signature) throw new Error('rpCredential.signature is required');
  if (!r_i) throw new Error('r_i is required');
  if (!rpNonce) throw new Error('rpNonce is required');

  await verifyRpCredential(rpCredential);
  console.log(`[WalletAgent][Step 8] RP credential signature verified ${ms(start)}`);

  const heightInfo = await getMaxHeight();
  const maxHeight = heightInfo.maxHeight;
  console.log(`[WalletAgent][Step 8] chain_id/max_height computed: chainId=${heightInfo.chainId}, currentBlock=${heightInfo.currentBlock.toString()}, maxHeight=${maxHeight.toString()} ${ms(start)}`);

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

  // 세션 서명키: secp256k1, 로그인마다 새로 생성됨 (generateNewSessionKey 참고).
  // pk_i는 이제 공개키 블롭의 해시가 아니라 그 공개키의 이더리움 주소 자체다.
  const { pk_i: pkField, publicKeyHex } = generateNewSessionKey();
  console.log(`[WalletAgent][Step 8] session key ready. address(pk_i): ${preview(publicKeyHex, 34)} ${ms(start)}`);

  const maxHeightField = valueToField(maxHeight);

  const tokenNonce = poseidon.F.toObject(poseidon([pkField, maxHeightField, rpNonceField]));
  console.log(`[WalletAgent][Step 8] token nonce (Poseidon) generated ${ms(start)}`);

  // verifyRpCredential() above already checked this signature locally; here we
  // feed the same signature into pi_arid_i so the IdP can confirm (without
  // learning rid/origin) that a valid RP_REG credential was actually used.
  const idpPublicKeysForCircuit = await getIdpPublicKeys();
  const [pkIdPXForCircuit, pkIdPYForCircuit] = idpPublicKeysForCircuit.pk_IdP;

  const aridInputs = {
    rp_nonce: rpNonceField.toString(),
    salt: saltField.toString(),
    rid: rid.toString(),
    pk_i: pkField.toString(),
    origin: valueToField(rpCredential.origin).toString(),
    rp_reg_S: rpCredential.signature.S,
    rp_reg_R8x: rpCredential.signature.R8[0],
    rp_reg_R8y: rpCredential.signature.R8[1],
    uid: uidField.toString(),
    arid_i: arid_i.toString(),
    auid_i: auid_i.toString(),
    max_height: maxHeightField.toString(),
    token_nonce: tokenNonce.toString(),
    auid: auid.toString(),
    pk_IdP_x: pkIdPXForCircuit,
    pk_IdP_y: pkIdPYForCircuit,
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    aridInputs,
    'build/mode2/pi_arid_i_js/pi_arid_i.wasm',
    'build/mode2/pi_arid_i_final.zkey',
  );
  console.log(`[WalletAgent][Step 8] pi_i (pi_arid_i) proof generated ${ms(start)}`);

  const ppidInputs = {
    uid: uidField.toString(),
    salt: saltField.toString(),
    rid: rid.toString(),
    ppid: ppid.toString(),
  };
  const { proof: ppidProof, publicSignals: ppidPublicSignals } = await snarkjs.groth16.fullProve(
    ppidInputs,
    'build/mode2/pi_ppid_js/pi_ppid.wasm',
    'build/mode2/pi_ppid_final.zkey',
  );
  console.log(`[WalletAgent][Step 8] pi_PPID proof generated ${ms(start)}`);

  const durationMs = now() - requestStart;
  console.log(`✅ [WalletAgent][Step 8] All proofs ready ${ms(start)}`);

  return {
    rid: rid.toString(),
    ppid: ppid.toString(),
    rpNonceField: rpNonceField.toString(),
    arid_i: arid_i.toString(),
    auid_i: auid_i.toString(),
    currentBlock: heightInfo.currentBlock.toString(),
    chain_id: heightInfo.chainId,
    heightSource: heightInfo.source,
    maxHeight: maxHeightField.toString(),
    tokenNonce: tokenNonce.toString(),
    pk_i: pkField.toString(),
    publicKeyHex,
    zkpProof: proof,
    // pi_arid_i public signals are [uid, arid_i, auid_i, max_height, token_nonce, auid, pk_IdP_x, pk_IdP_y].
    // The IdP reconstructs uid from the authenticated account, so never expose it to RP FE.
    zkpPublicSignals: publicSignals.slice(1),
    pi_PPID: {
      type: 'pi_PPID',
      proof: ppidProof,
      publicSignals: ppidPublicSignals, // [rid, ppid], per circuit's public [rid, ppid]
      r_token: tokenNonce.toString(),
      generatedAt: new Date().toISOString(),
    },
    walletSubmission: {
      auid_i: auid_i.toString(),
      arid_i: arid_i.toString(),
      r_token: tokenNonce.toString(),
      pi_i: proof,
      r_i,
    },
    business: {
      ppid: ppid.toString(),
      arid_i: arid_i.toString(),
      auid_i: auid_i.toString(),
      r_i,
      r_token: tokenNonce.toString(),
      tokenNonce: tokenNonce.toString(),
      maxHeight: maxHeightField.toString(),
      chain_id: heightInfo.chainId,
    },
    durationMs,
  };
}

// Step 8을 대신 수행한다: PPID/arid_i/auid_i 계산, 세션 서명키 생성, Poseidon
// 토큰 논스, pi_i/pi_PPID Groth16 증명 생성. 이 프로세스는 사용자 로컬 머신에서만
// 돌고 RP_ORIGIN에서만 접근 가능하다 — RP 페이지(client.js)의 JS 컨텍스트와는
// 별도의 OS 프로세스라서, uid와 salt가 RP 페이지에 직접 노출되지 않는다.
app.post('/generateStep8Proofs', async (req, res) => {
  try {
    const { rpCredential, r_i, rpNonce } = req.body ?? {};
    if (Object.prototype.hasOwnProperty.call(req.body ?? {}, 'uid')) {
      throw new Error('uid must not be supplied by the RP frontend');
    }
    const result = await generateStep8ProofsData(rpCredential, r_i, rpNonce);
    res.json(result);
  } catch (err) {
    console.error(`❌ [WalletAgent][Step 8] generateStep8Proofs error: ${err.message}`);
    res.status(400).json({ error: err.message });
  }
});
```

This is a pure code-motion refactor — `/generateStep8Proofs`'s request/response behavior is unchanged.

- [ ] **Step 2: Add the job store and `POST /startLogin` + `GET /loginStatus`**

Insert immediately after the `/generateStep8Proofs` route from Step 1:

```js
// Wallet-driven login job store: jobId -> { status, expiresAt, step8?, error?,
// result? }. Memory-only, same pattern as this project's other in-memory
// stores (e.g. custom_idp.js's pushedRequests/authorizationCodes) — lost on
// restart, intentional demo limitation.
const loginJobs = new Map();
const LOGIN_JOB_TTL_MS = 10 * 60 * 1000; // generous — covers proof gen + human login/consent time

function pruneExpiredJobs() {
  const now = Date.now();
  for (const [jobId, job] of loginJobs) {
    if (job.expiresAt <= now) loginJobs.delete(jobId);
  }
}

// Step 8을 백그라운드로 돌리고 즉시 jobId만 응답한다 — 이후 단계(Snap 승인,
// 시스템 브라우저 로그인)가 사람 개입으로 수십 초~수 분 걸릴 수 있어서, RP FE가
// 하나의 HTTP 요청으로 계속 기다리게 하지 않는다. 대신 /loginStatus를 폴링한다.
app.post('/startLogin', async (req, res) => {
  const { rpCredential, r_i, rpNonce } = req.body ?? {};
  if (Object.prototype.hasOwnProperty.call(req.body ?? {}, 'uid')) {
    return res.status(400).json({ error: 'uid must not be supplied by the RP frontend' });
  }
  if (!rpCredential?.rid) return res.status(400).json({ error: 'rpCredential.rid is required' });
  if (!rpCredential?.signature) return res.status(400).json({ error: 'rpCredential.signature is required' });
  if (!r_i) return res.status(400).json({ error: 'r_i is required' });
  if (!rpNonce) return res.status(400).json({ error: 'rpNonce is required' });

  pruneExpiredJobs();
  const jobId = webcrypto.randomUUID();
  loginJobs.set(jobId, { status: 'generating_proof', expiresAt: Date.now() + LOGIN_JOB_TTL_MS });
  res.status(202).json({ jobId });

  try {
    const step8 = await generateStep8ProofsData(rpCredential, r_i, rpNonce);
    const job = loginJobs.get(jobId);
    if (!job) return; // expired/pruned while proof was generating
    job.status = 'awaiting_wallet_approval';
    job.step8 = step8;
    console.log(`[WalletAgent][startLogin] job ${jobId} awaiting_wallet_approval`);
  } catch (err) {
    const job = loginJobs.get(jobId);
    if (job) {
      job.status = 'failed';
      job.error = err.message;
    }
    console.error(`[WalletAgent][startLogin] job ${jobId} failed during proof generation: ${err.message}`);
  }
});

app.get('/loginStatus', (req, res) => {
  const { jobId } = req.query ?? {};
  const job = loginJobs.get(jobId);
  if (!job) return res.status(404).json({ error: 'Unknown or expired jobId' });

  if (job.status === 'done') {
    return res.json({ status: 'done', ...job.result });
  }
  if (job.status === 'failed') {
    return res.json({ status: 'failed', error: job.error });
  }
  res.json({ status: job.status });
});
```

- [ ] **Step 3: Write the test script**

Create `tests/test_wallet_login_job.js`:

```js
// Requires wallet_agent.js (:5001), server.js (:3000), custom_idp.js (:4000)
// running and key-consistent (see CLAUDE.md's restart-chain notes).
// Run: node tests/test_wallet_login_job.js
const SERVER = 'http://127.0.0.1:3000';
const WALLET = 'http://127.0.0.1:5001';

async function getWalletAgentToken() {
  return (await (await fetch(`${SERVER}/api/mode2/wallet_agent_token`)).json()).token;
}

async function main() {
  const registration = await (await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })).json();
  const token = await getWalletAgentToken();

  console.log('-- POST /startLogin (expect 202 + jobId) --');
  const startRes = await fetch(`${WALLET}/startLogin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ rpCredential: registration, r_i: '555', rpNonce: '666' }),
  });
  const startBody = await startRes.json();
  if (startRes.status !== 202 || !startBody.jobId) {
    throw new Error(`FAIL: expected 202 + jobId, got ${startRes.status} ${JSON.stringify(startBody)}`);
  }
  console.log('PASS:', startBody.jobId);

  console.log('-- poll /loginStatus until awaiting_wallet_approval (expect within 10s) --');
  const deadline = Date.now() + 10000;
  let lastStatus = null;
  while (Date.now() < deadline) {
    const statusBody = await (await fetch(`${WALLET}/loginStatus?jobId=${startBody.jobId}`, {
      headers: { 'X-Wallet-Agent-Token': token },
    })).json();
    lastStatus = statusBody.status;
    if (lastStatus === 'awaiting_wallet_approval') break;
    if (lastStatus === 'failed') throw new Error(`FAIL: job failed during proof generation: ${statusBody.error}`);
    await new Promise((r) => setTimeout(r, 300));
  }
  if (lastStatus !== 'awaiting_wallet_approval') {
    throw new Error(`FAIL: expected awaiting_wallet_approval within 10s, last status was ${lastStatus}`);
  }
  console.log('PASS: job reached awaiting_wallet_approval');

  console.log('-- GET /loginStatus with unknown jobId (expect 404) --');
  const unknownRes = await fetch(`${WALLET}/loginStatus?jobId=does-not-exist`, {
    headers: { 'X-Wallet-Agent-Token': token },
  });
  if (unknownRes.status !== 404) throw new Error(`FAIL: expected 404, got ${unknownRes.status}`);
  console.log('PASS: unknown jobId rejected');

  console.log('-- existing /generateStep8Proofs still works after the refactor (non-regression) --');
  const legacyRes = await fetch(`${WALLET}/generateStep8Proofs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ rpCredential: registration, r_i: '777', rpNonce: '888' }),
  });
  const legacyBody = await legacyRes.json();
  if (legacyRes.status !== 200 || !legacyBody.zkpProof) {
    throw new Error(`FAIL: /generateStep8Proofs regressed: ${legacyRes.status} ${JSON.stringify(legacyBody)}`);
  }
  console.log('PASS: /generateStep8Proofs unaffected by the refactor');

  console.log('ALL WALLET LOGIN JOB TESTS PASSED');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
```

- [ ] **Step 4: Run it**

Ensure `custom_idp.js` (:4000), `server.js` (:3000), and `wallet_agent.js` (:5001) are running against a consistent key/factory set. Run: `node tests/test_wallet_login_job.js`
Expected: `ALL WALLET LOGIN JOB TESTS PASSED`, no `TEST FAILED`.

- [ ] **Step 5: Commit**

```bash
git add wallet_agent.js tests/test_wallet_login_job.js
git commit -m "feat(mode2): add wallet_agent.js job-polling login API (/startLogin, /loginStatus)"
```

---

### Task 2: `POST /confirmLoginResult` + loopback listener + `/par`/`/token` calls + system browser launch

**Files:**
- Modify: `wallet_agent.js` (imports, new routes/functions, inserted after Task 1's `/loginStatus` route)
- Modify: `package.json` (new `open` dependency, via `npm install`)
- Test: `tests/test_wallet_login_loopback.js` (create)

**Interfaces:**
- Consumes: `loginJobs`, `pruneExpiredJobs()`, job record shape from Task 1.
- Consumes: `getCurrentSessionKey()` (existing, `wallet_agent.js:318-322`, returns `{sk_i, pk_i, address, publicKeyHex}` — the session key `generateStep8ProofsData` just generated for this job), `IDP_ORIGIN` (existing constant).
- Produces: job statuses `'awaiting_browser_login' | 'exchanging_token' | 'done' | 'denied'` added on top of Task 1's statuses. `done` job record gets a `result` field: `{ ppid, arid_i, auid_i, pk_i, publicKeyHex, pi_PPID, statement }`.

- [ ] **Step 1: Install the `open` package**

Run: `npm install open`
Expected: `package.json`'s `dependencies` gains an `"open"` entry; `package-lock.json` updates.

- [ ] **Step 2: Add new imports**

At the top of `wallet_agent.js`, change:

```js
import { webcrypto } from 'crypto';
```

to:

```js
import { webcrypto, createHash, randomBytes } from 'crypto';
import http from 'http';
import open from 'open';
```

- [ ] **Step 3: Add `POST /confirmLoginResult` and the loopback login lifecycle**

Insert immediately after Task 1's `GET /loginStatus` route:

```js
// client.js가 Snap confirmLogin 다이얼로그 결과를 보고하는 엔드포인트.
// wallet_agent.js는 Node 프로세스라 window.ethereum에 직접 접근할 수 없어서,
// Snap 호출 자체는 client.js가 대신 하고 그 결과만 여기로 보고받는다. 승인이면
// loopback 리스너를 열고 /par를 호출해서 시스템 브라우저 단계로 넘어간다.
app.post('/confirmLoginResult', async (req, res) => {
  const { jobId, approved } = req.body ?? {};
  const job = loginJobs.get(jobId);
  if (!job) return res.status(404).json({ error: 'Unknown or expired jobId' });
  if (job.status !== 'awaiting_wallet_approval') {
    return res.status(400).json({ error: `job is not awaiting approval (current status: ${job.status})` });
  }

  if (!approved) {
    job.status = 'denied';
    console.log(`[WalletAgent][confirmLoginResult] job ${jobId} denied at Snap approval`);
    return res.json({ success: true });
  }

  res.json({ success: true });
  startLoopbackLogin(jobId).catch((err) => {
    const j = loginJobs.get(jobId);
    if (j) {
      j.status = 'failed';
      j.error = err.message;
    }
    console.error(`[WalletAgent][confirmLoginResult] job ${jobId} failed: ${err.message}`);
  });
});

const LOOPBACK_TIMEOUT_MS = 90 * 1000; // /par's request_uri TTL (60s) plus margin

async function startLoopbackLogin(jobId) {
  const job = loginJobs.get(jobId);
  if (!job) return;
  const step8 = job.step8;

  const state = webcrypto.randomUUID();
  const nonce = webcrypto.randomUUID();
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

  const { sk_i, pk_i } = getCurrentSessionKey();
  const bindingHash = keccak256(
    AbiCoder.defaultAbiCoder().encode(['string', 'string', 'string'], [state, nonce, codeChallenge]),
  );
  const sigRaw = secp256k1.sign(bindingHash.slice(2), sk_i);
  const requestBindingSignature =
    '0x' +
    sigRaw.r.toString(16).padStart(64, '0') +
    sigRaw.s.toString(16).padStart(64, '0') +
    (27 + sigRaw.recovery).toString(16).padStart(2, '0');

  const server = http.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const redirectUri = `http://127.0.0.1:${port}/oidc/callback`;

  const timeoutHandle = setTimeout(() => {
    server.close();
    const j = loginJobs.get(jobId);
    if (j && j.status === 'awaiting_browser_login') {
      j.status = 'failed';
      j.error = 'Timed out waiting for the browser login/consent to complete';
      console.error(`[WalletAgent][loopback] job ${jobId} timed out waiting for callback`);
    }
  }, LOOPBACK_TIMEOUT_MS);

  server.on('request', (req, res) => {
    handleLoopbackCallback(jobId, req, res, { server, timeoutHandle, redirectUri, codeVerifier, state });
  });

  const parRes = await fetch(`${IDP_ORIGIN}/par`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: 'pairct-wallet',
      redirect_uri: redirectUri,
      response_type: 'code',
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      zkpProof: step8.zkpProof,
      zkpPublicSignals: step8.zkpPublicSignals,
      chain_id: step8.chain_id,
      requestBinding: { pk_i, signature: requestBindingSignature },
    }),
  });
  const parBody = await parRes.json();
  if (!parRes.ok || !parBody.request_uri) {
    clearTimeout(timeoutHandle);
    server.close();
    throw new Error(parBody.error_description || parBody.error || '/par failed');
  }

  job.status = 'awaiting_browser_login';
  console.log(`[WalletAgent][loopback] job ${jobId} pushed to IdP, request_uri=${parBody.request_uri}, redirect_uri=${redirectUri}`);

  const authorizeUrl = `${IDP_ORIGIN}/authorize?client_id=pairct-wallet&request_uri=${encodeURIComponent(parBody.request_uri)}`;
  try {
    await open(authorizeUrl);
  } catch (err) {
    // A headless/test environment may not have a browser to open — the URL is
    // still valid and the loopback listener is still waiting; log and continue
    // rather than failing the job outright.
    console.warn(`[WalletAgent][loopback] job ${jobId}: could not auto-open browser (${err.message}); visit manually: ${authorizeUrl}`);
  }
}

function handleLoopbackCallback(jobId, req, res, ctx) {
  const { server, timeoutHandle, redirectUri, codeVerifier, state } = ctx;
  const requestUrl = new URL(req.url, 'http://127.0.0.1');
  if (requestUrl.pathname !== '/oidc/callback') {
    res.writeHead(404).end();
    return;
  }

  clearTimeout(timeoutHandle);
  const returnedState = requestUrl.searchParams.get('state');
  const code = requestUrl.searchParams.get('code');
  const error = requestUrl.searchParams.get('error');

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<html><body><p>Login complete. You can close this tab and return to the app.</p></body></html>');
  server.close();

  const job = loginJobs.get(jobId);
  if (!job) return;

  if (returnedState !== state) {
    job.status = 'failed';
    job.error = 'state mismatch on loopback callback (possible CSRF)';
    console.error(`[WalletAgent][loopback] job ${jobId}: state mismatch on callback`);
    return;
  }
  if (error) {
    job.status = 'denied';
    console.log(`[WalletAgent][loopback] job ${jobId} denied at IdP consent: ${error}`);
    return;
  }
  if (!code) {
    job.status = 'failed';
    job.error = 'loopback callback had neither code nor error';
    return;
  }

  job.status = 'exchanging_token';
  exchangeToken(jobId, code, redirectUri, codeVerifier).catch((err) => {
    const j = loginJobs.get(jobId);
    if (j) {
      j.status = 'failed';
      j.error = err.message;
    }
    console.error(`[WalletAgent][loopback] job ${jobId} token exchange failed: ${err.message}`);
  });
}

async function exchangeToken(jobId, code, redirectUri, codeVerifier) {
  const job = loginJobs.get(jobId);
  if (!job) return;

  const tokenRes = await fetch(`${IDP_ORIGIN}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: 'pairct-wallet',
      code_verifier: codeVerifier,
    }),
  });
  const statement = await tokenRes.json();
  if (!tokenRes.ok || !statement.signature) {
    throw new Error(statement.error_description || statement.error || '/token failed');
  }

  const step8 = job.step8;
  job.status = 'done';
  job.result = {
    ppid: step8.ppid,
    arid_i: step8.arid_i,
    auid_i: step8.auid_i,
    pk_i: step8.pk_i,
    publicKeyHex: step8.publicKeyHex,
    pi_PPID: step8.pi_PPID,
    statement,
  };
  console.log(`[WalletAgent][loopback] job ${jobId} done`);
}
```

- [ ] **Step 4: Write the test script**

Create `tests/test_wallet_login_loopback.js`. This covers what the design spec says is auto-testable: `/confirmLoginResult`'s validation, the `approved:false` → `denied` path, and the `approved:true` path through `/par` succeeding (`awaiting_browser_login`). Actually completing the browser login/consent is a manual, controller-driven check (see design spec's Testing section) — this script deliberately does not attempt it, and leaves the loopback listener to time out on its own (harmless, isolated to `wallet_agent.js`'s own process state).

```js
// Requires wallet_agent.js (:5001), server.js (:3000), custom_idp.js (:4000)
// running and key-consistent. Run: node tests/test_wallet_login_loopback.js
// Only covers the auto-testable portion (see design spec): through /par
// succeeding and the job reaching awaiting_browser_login. Full completion
// requires a human finishing login/consent in the opened browser tab — a
// separate, controller-driven manual check.
const SERVER = 'http://127.0.0.1:3000';
const WALLET = 'http://127.0.0.1:5001';

async function getWalletAgentToken() {
  return (await (await fetch(`${SERVER}/api/mode2/wallet_agent_token`)).json()).token;
}

async function startJobToApproval(token) {
  const registration = await (await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })).json();
  const startRes = await fetch(`${WALLET}/startLogin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ rpCredential: registration, r_i: '111', rpNonce: '222' }),
  });
  const { jobId } = await startRes.json();
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    const statusBody = await (await fetch(`${WALLET}/loginStatus?jobId=${jobId}`, {
      headers: { 'X-Wallet-Agent-Token': token },
    })).json();
    if (statusBody.status === 'awaiting_wallet_approval') return jobId;
    if (statusBody.status === 'failed') throw new Error(`FAIL: job failed before approval: ${statusBody.error}`);
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error('FAIL: job never reached awaiting_wallet_approval');
}

async function pollUntil(token, jobId, predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    last = await (await fetch(`${WALLET}/loginStatus?jobId=${jobId}`, {
      headers: { 'X-Wallet-Agent-Token': token },
    })).json();
    if (predicate(last)) return last;
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`FAIL: timed out waiting for condition, last status: ${JSON.stringify(last)}`);
}

async function main() {
  const token = await getWalletAgentToken();

  console.log('-- /confirmLoginResult with unknown jobId (expect 404) --');
  const unknownRes = await fetch(`${WALLET}/confirmLoginResult`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ jobId: 'does-not-exist', approved: true }),
  });
  if (unknownRes.status !== 404) throw new Error(`FAIL: expected 404, got ${unknownRes.status}`);
  console.log('PASS: unknown jobId rejected');

  console.log('-- approved: false leads to denied status --');
  const deniedJobId = await startJobToApproval(token);
  const denyRes = await fetch(`${WALLET}/confirmLoginResult`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ jobId: deniedJobId, approved: false }),
  });
  if (denyRes.status !== 200) throw new Error(`FAIL: expected 200, got ${denyRes.status}`);
  const deniedStatus = await (await fetch(`${WALLET}/loginStatus?jobId=${deniedJobId}`, {
    headers: { 'X-Wallet-Agent-Token': token },
  })).json();
  if (deniedStatus.status !== 'denied') throw new Error(`FAIL: expected denied, got ${deniedStatus.status}`);
  console.log('PASS: Snap denial correctly sets status to denied');

  console.log('-- approved: true reaches awaiting_browser_login (/par succeeded) --');
  const approvedJobId = await startJobToApproval(token);
  const approveRes = await fetch(`${WALLET}/confirmLoginResult`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ jobId: approvedJobId, approved: true }),
  });
  if (approveRes.status !== 200) throw new Error(`FAIL: expected 200, got ${approveRes.status}`);
  const afterApproval = await pollUntil(
    token, approvedJobId,
    (s) => s.status === 'awaiting_browser_login' || s.status === 'failed',
    10000,
  );
  if (afterApproval.status !== 'awaiting_browser_login') {
    throw new Error(`FAIL: expected awaiting_browser_login, got ${afterApproval.status} (${afterApproval.error ?? ''})`);
  }
  console.log('PASS: job reached awaiting_browser_login — /par succeeded, loopback listener is open and waiting');

  console.log('ALL WALLET LOOPBACK TESTS PASSED (manual browser completion not covered — see design spec)');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
```

- [ ] **Step 5: Run it**

Run: `node tests/test_wallet_login_loopback.js`
Expected: `ALL WALLET LOOPBACK TESTS PASSED (manual browser completion not covered — see design spec)`, no `TEST FAILED`. It is normal/expected for a system browser window to attempt to open (or fail silently/log a warning if none is available) during this run, and for `wallet_agent.js`'s log to show a loopback timeout message ~90 seconds after the test process has already exited — that timeout is harmless.

- [ ] **Step 6: Commit**

```bash
git add wallet_agent.js package.json package-lock.json tests/test_wallet_login_loopback.js
git commit -m "feat(mode2): add loopback listener + /par + /token calls to wallet_agent.js login jobs"
```

---

### Task 3: Snap `confirmLogin` approval dialog

**Files:**
- Modify: `snap/src/index.js`

**Interfaces:**
- Produces: a new `onRpcRequest` case, `'confirmLogin'`, callable via `window.ethereum.request({method:'wallet_invokeSnap', request:{method:'confirmLogin', params:{}}})` (the actual call site is `client.js`, built in the next sub-project) — returns `{ approved: boolean }`.

- [ ] **Step 1: Add the `confirmLogin` case**

In `snap/src/index.js`, inside `onRpcRequest`'s `switch (request.method)`, insert a new case immediately after the existing `case 'hello': { ... }` block (which ends with the closing `}` before `case 'walletProcessSummary':`):

```js
    case 'confirmLogin': {
      const confirmed = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('Wallet Login Approval'),
            text(`Origin: **${origin}**`),
            text('A PairCT-compatible identity provider login is about to start in your system browser.'),
            text('Do you want to proceed?'),
          ]),
        },
      });
      return { approved: Boolean(confirmed) };
    }
```

- [ ] **Step 2: Rebuild the Snap**

Run (from the `snap/` directory): `cd snap && npm run build`
Expected: `mm-snap build` completes without errors and `snap/dist/bundle.js` is regenerated (check its mtime changed).

- [ ] **Step 3: Manual verification (controller/user, not automatable)**

This cannot be curl-tested — `snap_dialog` only runs inside a real MetaMask instance in a real browser. Note in the task report that:
1. The rebuilt Snap needs to be reconnected/reinstalled in the browser's MetaMask before this case is reachable at all.
2. Actually invoking `confirmLogin` end-to-end requires `client.js` to call it, which doesn't exist until the next sub-project — so full verification of this dialog is deferred to that sub-project's live testing. For this task, it is sufficient to confirm the build succeeds and the code is syntactically/structurally correct (e.g. by comparing against the working `hello` case's pattern, which this mirrors exactly).

- [ ] **Step 4: Commit**

```bash
git add snap/src/index.js snap/dist/bundle.js
git commit -m "feat(mode2): add Snap confirmLogin approval dialog"
```

---

## Self-Review Notes

- **Spec coverage:** All three spec-level deliverables (polling job API, loopback listener + system browser + `/par`/`/token` calls, Snap `confirmLogin`) map 1:1 to Tasks 1-3. The `open` package addition, PKCE generation, and request-binding signature construction (all called out in the spec's data structures/architecture sections) are in Task 2. The spec's explicit "auto-testable only up to `awaiting_browser_login`" boundary is reflected in Task 2's test scope and Task 3's manual-verification note.
- **Placeholder scan:** No TBD/TODO; every step has complete, runnable code.
- **Type/interface consistency:** `generateStep8ProofsData`'s return shape (Task 1) is exactly what Task 2's `startLoopbackLogin`/`exchangeToken` read (`step8.zkpProof`, `step8.zkpPublicSignals`, `step8.chain_id`, `step8.ppid`, `step8.arid_i`, `step8.auid_i`, `step8.pk_i`, `step8.publicKeyHex`, `step8.pi_PPID`) — checked field-by-field against Task 1's object literal. The `requestBinding` signature construction in Task 2 matches sub-project 1's plan/spec exactly (`keccak256(AbiCoder.encode(['string','string','string'],...))`, secp256k1 r/s/v hex).
- **Known pre-existing limitation, not introduced by this plan:** `generateNewSessionKey()`/`getCurrentSessionKey()` use a single module-level `currentSessionKey` (`wallet_agent.js:308`), so only one login job's session key is "current" at a time — already true of `/generateStep8Proofs` + `/submitTransaction` today. This plan's `/startLogin` reuses the exact same function and inherits the exact same limitation; fixing concurrent-job session-key isolation is out of scope here (not requested, not blocking for this demo's single-user-at-a-time usage).
- **Out of scope, confirmed left untouched:** `client.js` (calling these new endpoints, driving the Snap call, polling UI) and removal of `idp/login_popup.js`/`wallet/relay.*` — both explicitly deferred to the next (third) sub-project per the design spec.
