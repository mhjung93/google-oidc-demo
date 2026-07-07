# Mode 2 Flow Notes

## Scope

Mode 2 focuses on the Custom IdP based SSO flow using PS signatures, ZK proofs, and wallet/RP-side pseudonymous identifiers.

Out of scope unless explicitly needed:

- Google OIDC ID token proof flow
- `scripts/make_proof.js`
- Snap accessList transaction attachment
- Hardhat `Greeter` contract flow

## Main Components

### RP Backend

File: `server.js`

Relevant responsibilities:

- Runs the relying party server.
- Registers the RP with the Custom IdP through `/api/mode2/register`.
- Exposes current RP registration through `/api/mode2/rp_info`.
- Loads the IdP PS public keys with `initRP_PS()`.
- Receives the final IdP token and proof at `/api/mode2/sso_success`.
- Attempts RP-side ZKP and hybrid PS verification.

Relevant endpoints:

- `POST /api/mode2/register`
- `GET /api/mode2/rp_info`
- `POST /api/mode2/sso_success`

### Custom IdP

File: `custom_idp.js`

Relevant responsibilities:

- Runs a mock Custom IdP on port `4000`.
- Initializes PS signature parameters and keys in memory.
- Registers relying parties through `/register_rp`.
- Issues an initial login token through `/login`.
- Serves a popup login page through `/login_popup`.
- Verifies submitted credentials and ZKP through `/sso_with_credentials`.
- Issues a PS-signed `idpToken`.
- Exposes PS public keys through `/ps_public_keys`.

Relevant endpoints:

- `POST /register_rp`
- `POST /login`
- `GET /login_popup`
- `POST /sso_with_credentials`
- `GET /ps_public_keys`

### Browser Client

File: `client.js`

Relevant responsibilities:

- Activates Mode 2 UI when `window.APP_MODE === 2`.
- Registers the RP with the IdP.
- Logs into the Custom IdP with demo credentials.
- Connects MetaMask.
- Computes scalar Mode 2 values for `PPID`, `arid_i`, `auid_i`, and `token_nonce`.
- Generates Groth16 proofs in the browser with `snarkjs.groth16.fullProve`.
- Sends ZKP data to the Custom IdP popup via `postMessage`.
- Sends the returned IdP token and proof to the RP backend.

### UI

File: `index.html`

Relevant responsibilities:

- Shows the Mode 2 section.
- Provides step-by-step buttons for the SSO demo.
- Shows intermediate SSO data and RP FE / wallet progress logs.

### Mode 2 Circuits

Files:

- `circuits/pi_arid_i.circom`
- `circuits/pi_ppid.circom`
- `scripts/build_mode2_circuits.sh`

Generated artifacts:

- `build/mode2/pi_arid_i_js/pi_arid_i.wasm`
- `build/mode2/pi_arid_i_final.zkey`
- `build/mode2/pi_arid_i_vkey.json`
- matching files for `pi_ppid`

## Step Flow

### Step 0: Server Setup

Expected process setup:

```bash
node custom_idp.js
APP_MODE=2 BASE_URL=http://127.0.0.1:3000 CUSTOM_IDP_BASE_URL=http://127.0.0.1:4000 npm run dev
```

Expected RP setup behavior:

- `APP_MODE=2` enables Mode 2 UI and APIs.
- RP loads IdP PS public keys from the Custom IdP.
- Browser opens the RP at `http://127.0.0.1:3000`.

### Step 1: Delegated Login Starts

UI button:

- `Delegated Login`

Client action:

- Opens the Mode 2 SSO section.
- Requests MetaMask Snap permission through `wallet_requestSnaps`.
- Does not call `eth_requestAccounts`.
- Does not select or disclose an EOA account/address.

Output:

- Snap connection is available for later `wallet_invokeSnap` calls.

### Step 2: Initialize Wallet-Side Module

Client action:

- Initializes the wallet-side module implemented by the MetaMask Snap.
- Prepares the Custom IdP popup.
- Starts elapsed-time measurement after Snap initialization.

Output:

- Wallet-side module ready.
- No blockchain account address is selected.

### Step 3: RP FE Session Nonce Created

Client action:

- Creates `mode2SessionNonce`.
- Reuses it as `r_i` for the browser/popup/session binding.

Output:

- `sessionNonce`
- `r_i`

### Step 4: RP Credential and RP Nonce Request

RP endpoint:

- `POST /api/mode2/rp_credential_nonce`

Request body:

- `sessionNonce`
- `r_i`
- `requestedAt`

Notes:

- The request no longer includes `walletAddress`.
- RP account continuity is handled later through `PPID` (`auid` in the paper), not an EOA address.

### Step 5: RP Nonce Created

RP backend action:

- Generates fresh `rpNonce`.
- Stores it in `req.session.rpNonce` for the later RP-side audience check.

Output:

- `rpNonce`

### Step 6: RP Credential and Nonce Response

RP backend response:

- `rpCredential`
- `sessionNonce`
- `r_i`
- `rpNonce`

Current implementation naming:

- IdP registration output in `custom_idp.js`: `rpToken`
- RP backend stored object: `rpRegistration`
- Client response field: `rpCredential`

Protocol interpretation:

- `rpCredential` is the demo artifact corresponding to authenticated RP metadata.
- Its key protocol value is `rid`.

### Step 7: RP FE Sends Values to Wallet Context

Client action:

- Checks that returned `sessionNonce` matches `mode2SessionNonce`.
- Passes `rid`, mock RP signature, `r_i`, and `rpNonce` to the wallet-side flow.

Output:

- Wallet context has RP metadata and session values.

### Step 8: Wallet Generates PPID, Token Nonce, and ZKPs

Client action in `runWalletStep7()`:

- Treats IdP-issued `rid` as the RP audience scalar for the demo.
- Computes `PPID = uid * rid * salt`.
- Computes `arid_i = rid * rpNonce`.
- Computes `auid_i = PPID * rpNonce`.
- Generates a session signing key pair.
- Computes `r_token = Poseidon(pk_i, max_height, rpNonce)`.
- Generates `pi_i` with `pi_arid_i`.
- Generates `pi_PPID` with `pi_ppid`.

Output in `ssoMetadata`:

- `rid`
- `rpNonceField`
- `ppid`
- `arid_i`
- `auid_i`
- `tokenNonce`
- `pi_i`
- `pi_PPID`

Circuit:

- `pi_arid_i`

Witness inputs:

- private `rp_nonce`
- private `salt`
- private `rid`
- private `pk_i`
- public `uid`
- public `arid_i`
- public `auid_i`
- public `max_height`
- public `token_nonce`

Public signal order:

- `[uid, arid_i, auid_i, max_height, token_nonce]`

Proof call:

```js
snarkjs.groth16.fullProve(
  inputs,
  "/build/mode2/pi_arid_i_js/pi_arid_i.wasm",
  "/build/mode2/pi_arid_i_final.zkey"
)
```

Output:

- `currentSSOProof.zkpProof`
- `currentSSOProof.zkpPublicSignals`
- `currentSSOProof.walletSubmission`
- `currentSSOProof.business`

### Step 9: Submit to IdP

UI button:

- `Step 9. Submit to IdP`

Client action:

- Opens `http://127.0.0.1:4000/login_popup` if needed.
- Sends `currentSSOProof` to the popup with `postMessage`.

Popup action:

- User enters credentials.
- Popup sends credentials plus ZKP to `/sso_with_credentials`.
- Consent flow continues through `/consent_result`.

IdP action:

- Verifies credentials.
- Verifies `pi_i`.
- Tracks replay by `r_i`.
- Signs `[arid_i, auid_i, r_token, max_height]`.
- Returns `idpToken`.

Output:

- `currentIdPToken`

### Step 10: RP Backend Verifies pi_i and IdP Token

UI button:

- `Step 10. Verify pi_i & IdP Token`

RP endpoint:

- `POST /api/mode2/sso_success`

Request body:

- `idpToken`
- `zkpProof`
- `zkpPublicSignals`

RP action:

- Recomputes `expectedAridI = rpRegistration.rid * req.session.rpNonce`.
- Checks `idpToken.arid_i` against the recomputed value.
- Verifies Groth16 proof with `pi_arid_i_vkey.json`.
- Checks token fields against `pi_i` public signals.
- Calls `verifyPS_Hybrid` over `[arid_i, auid_i, r_token, max_height]`.
- Deletes `req.session.rpNonce` after the full RP-side verification succeeds.
- Returns `{ success: true }` on demo success.

Output:

- Step 11 runs when verification succeeds.

### Step 11: Send IdP Token to Wallet

Client action:

- Copies `currentIdPToken` into `walletReceivedIdPToken`.
- Marks Step 11 as completed.
- Calls Step 12.

Output:

- Wallet has the IdP auth token.

### Step 12: Wallet Verifies IdP Auth Token

Snap method:

- `verifyIdPAuthToken`

Client action:

- Fetches IdP PS public keys from `http://127.0.0.1:4000/ps_public_keys`.
- Calls `wallet_invokeSnap`.

Snap action:

- Verifies the PS signature over `[arid_i, auid_i, r_token, max_height]`.
- Checks token fields against `walletSubmission` and `business`.
- Displays a Snap dialog with the verification result.

Output:

- `ssoMetadata.step12Verified`
- `measuredDurations.step12`

### Step 13: Wallet Sends PPID and pi_PPID to RP FE

Client action:

- Requires Step 12 to have passed.
- Sends or exposes the wallet submission to RP FE in the demo flow.
- Uses `PPID` as the RP-side account identifier (`auid` in the paper).
- Includes `pi_PPID` so the RP FE can verify the PPID binding.

Output:

- RP FE has `PPID`, `pi_PPID`, and IdP token context.

### Step 14: RP FE Verifies Wallet Submission

Client action:

- Verifies `pi_PPID` with `pi_ppid_vkey.json`.
- Checks `max_height`.
- Checks `rid` from `pi_PPID` public signals against the RP's `rid`.
- Recomputes `auid_i = PPID * rpNonce`.
- Checks recomputed `auid_i` against the IdP token.

Output:

- `step14Result`
- `success`
- `ppid`
- binding check results

### Step 15: Notify Wallet of RP Auth Result

Snap method:

- `rpAuthResult`

Client action:

- Calls `wallet_invokeSnap` with `step14Result`.
- Displays final PPID authentication result in the Snap.
- Shows measured Step 8, Step 12, Step 14, and Step 15 timings.

Output:

- Final wallet-visible authentication result.

## RP Registration Support Flow

RP registration still exists as a setup/support action.

UI/API:

- `POST /api/mode2/register`
- `POST /register_rp`

Output:

- `rpRegistration`
- `rid`
- mock RP signature token

Used later by:

- `GET /api/mode2/rp_info`
- RP identity/audience checks

## Current Demo-Specific Behavior

These are implementation details that are useful for understanding the current prototype:

- `custom_idp.js` uses an in-memory mock user database.
- Demo credentials include `testuser` / `password123`.
- RP registration uses a mock signature string.
- `uid` is public in `pi_i`; `uid` and `salt` are hidden in `pi_PPID`.
- `rid` is private in `pi_i`; the RP backend performs the audience check by recomputing `arid_i = rid * rpNonce`.
- Delegated Login initializes the Snap/wallet-side module without selecting or disclosing an EOA account address.
- `PPID` is the implementation alias for the paper's `auid` and is used as the RP-side account identifier.
- Legacy EC and Light ZKP prototype paths were removed from the active client flow; old versions remain available through git history.
- RP-side ZKP failure handling returns an error.
- `verifyPS_Hybrid()` verifies the PS pairing equation over the signed Mode 2 token fields.

## Files Usually Not Needed for Mode 2

Unless the task explicitly requires them, these are not central to Mode 2:

- `scripts/make_proof.js`
- `scripts/derive_bip32.js`
- `circuits/bind_key_to_idtoken.circom`
- `scripts/run_all.sh`
- `snap/src/tx_type2_accesslist.js`
- `contracts/Greeter.sol`

## Suggested Next Work Areas

Potential Mode 2 focused improvements:

- Align endpoint URLs to use one configurable IdP origin consistently.
- Split Mode 2 client logic from Snap and Google OIDC client logic.
- Add a dedicated Mode 2 smoke test.
- Normalize the naming of `signature`, `signature_prime`, `zkpProof`, and `zkpPublicSignals`.
