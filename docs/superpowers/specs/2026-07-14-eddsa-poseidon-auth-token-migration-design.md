# Mode 2: PS → EdDSA-Poseidon Auth Token Signature Migration

## Status

Design approved by user (2026-07-14). Not yet implemented.

## Background

The user's PPT (`documents/260710_meeting_MHJ.pptx`, slide 6) proposes replacing the PS
(Pointcheval-Sanders) signature scheme currently used for the IdP's auth token with
EdDSA-Poseidon, because PS signature verification would need >100k constraints inside a
zk-SNARK circuit, whereas EdDSA-Poseidon needs only ~4k constraints. This migration is a
prerequisite for a later "trace" feature (conditional traceability, PPT slides 4/25-27/30)
that depends on a new circuit, `pi_pk_i`, consuming an EdDSA-Poseidon-signed auth token as a
hidden witness. `pi_pk_i` itself is out of scope for this spec — it is built in a follow-up
brainstorming cycle once this migration lands.

This spec covers only the migration: swapping the auth token's signature algorithm from PS to
EdDSA-Poseidon, and relocating the wallet-side verification step out of the MetaMask Snap
(which cannot run the required library).

## Scope

**In scope:**
- IdP (`custom_idp.js`) signs the auth token (`IDP_TOKEN`) with EdDSA-Poseidon instead of PS.
- RP backend (`server.js`) verifies the auth token's EdDSA-Poseidon signature instead of PS.
- Wallet-side auth token verification moves from the MetaMask Snap to `wallet_agent.js`.

**Out of scope (explicitly):**
- The RP registration signature (`RP_REG`, used by `/register_rp` and the A7 origin-binding fix)
  stays PS-based and is untouched by this migration — it is a separate, unrelated signature.
- `pi_arid_i.circom` and `pi_ppid.circom` are not modified.
- The new `pi_pk_i.circom` circuit is not created in this work — that is a follow-up
  sub-project ("trace" feature), built after this migration lands. This spec only ensures the
  auth token's new signed-message format is compatible with what `pi_pk_i` will eventually
  need as a hidden witness.
- Step 1–11, 13–15 behavior/ordering is unchanged; only the signature *algorithm* used within
  Step 9–12's verification changes.

## Prerequisite finding: Snap SES compatibility

Before designing where wallet-side verification lives, we needed to know whether
`circomlibjs`'s EdDSA/BabyJub would work inside the MetaMask Snap's SES sandbox (which already
rejects `circomlibjs`'s `buildPoseidon()` — see
`project_mode2_wallet_agent_architecture` memory, which is why Step 8 already runs in
`wallet_agent.js` instead of the Snap).

Resolved via source inspection (no live Snap test needed): `node_modules/circomlibjs/src/eddsa.js`'s
`buildEddsa()` directly calls `buildPoseidon()` as one of its five dependencies (and
`buildBabyJub()`, which it also calls, uses the same `ffjavascript` `getCurveFromName` WASM path
that `buildPoseidon()` uses). Since `buildPoseidon()` is already confirmed to throw
`SES_EVAL_REJECTED` in the Snap, `buildEddsa()` will fail there too, with certainty — it is not
an indirect similarity, it is a direct call to the already-broken function.

**Conclusion:** wallet-side auth token verification (currently in the Snap, `verifyIdPAuthToken`)
must move to `wallet_agent.js`, following the same pattern already established for Step 8.

## Architecture

**Changes:**
- `custom_idp.js` signs the auth token with EdDSA-Poseidon (new `sk_IdP`/`pk_IdP` keypair,
  separate from the existing PS keypair used for `RP_REG`).
- Wallet-side auth token verification relocates from the Snap to `wallet_agent.js`.
- RP backend (`server.js`) verifies the auth token with EdDSA-Poseidon instead of PS-hybrid.
- New circuit `pi_pk_i.circom` — **not built now**; used later, after login (Step 15) completes,
  at blockchain-transaction-signing time (PPT slide 3). Out of scope here.

**Unchanged:**
- Step 1–11, 13–15 ordering and roles.
- `RP_REG` signature (PS, untouched).
- `pi_arid_i`, `pi_ppid` circuits.
- The Snap's role in Steps 1–2 (connection) and Step 15 (final result display).

## Components

### `custom_idp.js`
- Add `initEdDSA()` (parallel to `initPS()`, called at startup) — builds `(sk_IdP, pk_IdP)` via
  `circomlibjs`'s `buildEddsa()`/`buildBabyjub()`. Fine in a plain Node process (no SES).
- Auth token issuance: replace `psSign(['IDP_TOKEN', arid_i, auid_i, r_token, max_height, chain_id])`
  with:
  ```js
  // 'IDP_TOKEN' domain string must become a field element before Poseidon can hash it.
  // custom_idp.js's existing hashToFr() is mcl-wasm-specific (returns an mcl.Fr object) and
  // is NOT compatible with circomlibjs's Poseidon input, which expects a plain BigInt/decimal
  // string. Reuse this codebase's other existing helper instead: valueToField() (already used
  // identically in wallet_agent.js/client.js/server.js to turn arbitrary values, including
  // non-numeric strings, into Poseidon-compatible field elements) — port a copy of it into
  // custom_idp.js since it doesn't have one yet.
  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN'); // computed once, reused every signing call
  const msg = poseidon.F.toObject(poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id]));
  const sigma_i = eddsa.signPoseidon(sk_IdP, msg);
  ```
  `idpToken.signature_prime` changes shape from `{ sigma1, sigma2 }` (PS/G1 points, hex) to
  `{ R8: [x, y], S }` (EdDSA components, decimal strings, matching this codebase's existing
  decimal-string convention for field elements).
- Expose `pk_IdP` by adding a field to the existing `/ps_public_keys` response (not a new
  endpoint — same "fetch IdP public keys" call site everywhere already exists).
- `/register_rp` (`RP_REG` signing) is untouched.

### `wallet_agent.js`
- New endpoint `POST /verifyIdPAuthToken` — takes over what the Snap's `verifyIdPAuthToken`
  method currently does. Recomputes `msg` from `{idpToken, walletSubmission, business}` fields
  the same way the IdP did, verifies with `circomlibjs`'s `eddsa.verifyPoseidon(msg, sigma_i, pk_IdP)`.
- Reuses existing security pattern: `X-Wallet-Agent-Token` header, `cors({ origin: RP_ORIGIN })`.
- Cache the built `eddsa`/`babyJub` instances at module scope (mirrors existing `ensureMcl()`
  lazy-init pattern) — WASM build is expensive, do it once per process.

### `client.js`
- `runWalletStep12()`: replace `wallet_invokeSnap({method: 'verifyIdPAuthToken', ...})` with
  `fetch('http://127.0.0.1:5001/verifyIdPAuthToken', ...)` (same pattern as Step 8's
  `generateStep8Proofs` call). Payload shape (`idpToken`, `walletSubmission`, `business`)
  stays the same — only the destination changes.
- The `pk_IdP` fetch reuses the existing `/api/mode2/idp_public_keys` same-origin proxy
  (added during the earlier Referer/Origin-leak fix) — no new endpoint needed on the RP side
  for the browser to reach; the proxy's cached response just grows a field.

### `server.js`
- `/api/mode2/sso_success` handler: replace `verifyPS_Hybrid(idpToken.signature_prime, [...], idpPublicKeys)`
  with the equivalent EdDSA-Poseidon verification (same `msg` recomputation as above).
- `initRP_PS()` (or a renamed/extended version) also caches `pk_IdP` from the now-extended
  `/ps_public_keys` response.
- `arid_i` audience recompute/check and `max_height`/`chain_id` checks are unchanged — only the
  signature verification call is swapped.

## Data flow

1. **Startup:** `custom_idp.js` runs `initPS()` and `initEdDSA()`. `server.js` and
   `wallet_agent.js` each fetch `/ps_public_keys` (now including `pk_IdP`) and cache it.
2. **Token issuance** (`custom_idp.js`, after `pi_i` verification + consent): compute
   `msg = Poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id])` (domain
   string pre-hashed to a field element, see Components), sign with
   `eddsa.signPoseidon(sk_IdP, msg)`, return as `idpToken.signature_prime = {R8, S}`.
3. **RP verification** (`server.js`, `/api/mode2/sso_success`): unchanged `arid_i`/`max_height`/
   `chain_id` checks, then recompute `msg` and verify with `pk_IdP` instead of `verifyPS_Hybrid`.
4. **Wallet verification** (`wallet_agent.js`, new `/verifyIdPAuthToken`): same recomputation,
   verify with `pk_IdP`.

## Error handling

- `initEdDSA()` failure at IdP startup: fail loudly (same as `initPS()` today — no try/catch,
  the demo is meant to fail fast rather than degrade silently).
- `pk_IdP` not yet loaded at the RP/wallet: falls into the *existing* retry path
  (`initRP_PS()`'s catch+warn, `sso_success`'s re-fetch-if-missing) — just make sure the
  "are keys loaded" check also covers `pk_IdP`, not only the PS fields.
- Signature verification failure: same clear-error-message convention as today
  (e.g. `"Invalid EdDSA-Poseidon Signature"`). Tampered token fields change the recomputed
  `msg`, which naturally fails signature verification — no separate "field mismatch" error
  path needed.
- `buildEddsa()`/`buildBabyJub()` are WASM-backed and expensive to build — cache the built
  instance per process (mirrors `wallet_agent.js`'s existing `ensureMcl()` pattern) instead of
  rebuilding per request.

## Testing plan

- New `test_eddsa.js` (mirrors `test_ps.js`): pure-Node round-trip — keygen → sign → verify,
  plus a tampered-field-then-verify-fails case. No servers needed.
- End-to-end smoke test (same approach used for the recent A7 fix verification): run all three
  processes, `curl` through register → credential → Step 8 → token issuance → verification,
  both a normal-success case and a tampered-signature-rejected case.
- Side benefit: since Step 12 moves out of the Snap, it becomes `curl`-testable for the first
  time (previously required a real browser + MetaMask).
- Still requires a real browser: Steps 1–2 (Snap connection) and Step 15 (Snap displays final
  result) remain Snap-dependent.

## Open questions for the follow-up "trace" sub-project (not this spec)

- Exact `pi_pk_i.circom` circuit definition and where it's invoked in the post-login
  transaction flow (PPT slide 3).
- How the "later" trace verification (outside the ZK circuit, per the user's clarification)
  fits together with `pi_pk_i`.
