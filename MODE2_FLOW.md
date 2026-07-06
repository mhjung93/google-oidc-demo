# Mode 2 Flow Notes

## Scope

Mode 2 focuses on the Custom IdP based SSO flow using PS signatures, ZK proofs, and wallet/RP-side pseudonymous identifiers.

Out of scope unless explicitly needed:

- Google OIDC ID token proof flow
- `make_proof.js`
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
- Computes BabyJubJub values for `arid_i`, `auid`, and `auid_i`.
- Generates Groth16 proofs in the browser with `snarkjs.groth16.fullProve`.
- Sends ZKP data to the Custom IdP popup via `postMessage`.
- Sends the returned IdP token and proof to the RP backend.

### UI

File: `index.html`

Relevant responsibilities:

- Shows the Mode 2 section.
- Provides step-by-step buttons for the SSO demo.
- Shows intermediate SSO data and error-test controls.

### Mode 2 Circuits

Files:

- `circuits/pi_arid_i.circom`
- `circuits/pi_auid.circom`
- `circuits/pi_uid.circom`
- `build_mode2_circuits.sh`

Generated artifacts:

- `build/mode2/pi_arid_i_js/pi_arid_i.wasm`
- `build/mode2/pi_arid_i_final.zkey`
- `build/mode2/pi_arid_i_vkey.json`
- matching files for `pi_auid` and `pi_uid`

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

### Step 1: RP Registration

UI button:

- `Register RP with IdP`

RP endpoint:

- `POST /api/mode2/register`

IdP endpoint:

- `POST /register_rp`

Output:

- `rpRegistration`
- `clientId`
- mock RP signature token

Used later by:

- `GET /api/mode2/rp_info`
- RP identity/audience checks

### Step 2: Initial Custom IdP Login

UI fields:

- `mode2Username`
- `mode2Password`

Client action:

- `POST http://localhost:4000/login`

Output:

- `authToken`
- `sub`
- PS signature over initial placeholder attributes

Local storage:

- `mode2_ps_token`

### Step 3: Wallet Connection

UI button:

- `Step 1. Connect Wallet`

Client action:

- Calls `eth_requestAccounts`.
- Stores the selected wallet address in `ssoMetadata.userAddress`.

Output:

- Wallet address
- Enables RP FE metadata preparation

### Step 7: RP FE Calculates `arid_i`

UI button:

- `Step 7. RP FE: Calculate arid_i`

Client actions:

- Initializes BabyJubJub.
- Fetches RP info from `/api/mode2/rp_info`.
- Uses `babyJub.Base8` as the current demo `rid` point.
- Generates random scalar `r_RP`.
- Computes `arid_i = rid * r_RP`.

Output in `ssoMetadata`:

- `rid`
- `r_RP`
- `arid_i`

### Step 8-9: Wallet Calculates `auid`

UI button:

- `Step 8-9. Wallet: Calculate auid`

Client actions:

- Computes demo `auid = Base8 * 12345`.

Output:

- `ssoMetadata.auid`

### Step 10: RP FE Calculates `auid_i`

UI button:

- `Step 10. RP FE: Calculate auid_i`

Client action:

- Computes `auid_i = auid * r_RP`.

Output:

- `ssoMetadata.auid_i`

### Step 11: Generate ZKP

UI button:

- `Step 11. Generate REAL ZKP`

Circuit:

- `pi_arid_i`

Witness inputs:

- private `r_RP`
- public `rid_x`, `rid_y`
- public `auid_x`, `auid_y`
- public `arid_i_x`, `arid_i_y`
- public `auid_i_x`, `auid_i_y`

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
- `currentSSOProof.business`

### Step 11-12: Submit to IdP

UI button:

- `Step 11-12. Submit to IdP`

Client action:

- Opens `http://localhost:4000/login_popup`.
- Sends `currentSSOProof` to the popup with `postMessage`.

Popup action:

- User enters credentials.
- Popup sends credentials plus ZKP to `/sso_with_credentials`.

IdP action:

- Verifies credentials.
- Verifies the ZKP.
- Signs `[sub, arid_i, auid_i, exp]`.
- Returns `idpToken`.

Output:

- `currentIdPToken`

### Step 13: RP FE Verifies IdP Token on Backend

UI button:

- `Step 13. RP FE: Verify IdP Token`

RP endpoint:

- `POST /api/mode2/sso_success`

Request body:

- `idpToken`
- `zkpProof`
- `zkpPublicSignals`

RP action:

- Attempts Groth16 verification with `pi_arid_i_vkey.json`.
- Calls `verifyPS_Hybrid`.
- Returns `{ success: true }` on demo success.

Output:

- Step 15 is enabled when verification succeeds.

### Step 15: Notify Wallet

UI button:

- `Step 15. Notify Wallet`

Current behavior:

- Updates UI state only.
- Enables final completion step.

### Step 16-17: Complete RP Login

UI button:

- `Step 16-17. Complete RP Login`

Current behavior:

- Button exists in UI.
- The main completion behavior should be reviewed before relying on this as a real session establishment step.

## Current Demo-Specific Behavior

These are implementation details that are useful for understanding the current prototype:

- `custom_idp.js` uses an in-memory mock user database.
- Demo credentials include `testuser` / `password123`.
- RP registration uses a mock signature string.
- `client.js` currently uses `babyJub.Base8` as demo `rid`.
- `auid` is currently generated as `Base8 * 12345`.
- Light ZKP code exists in `client.js`, but the UI block is commented out in `index.html`.
- RP-side ZKP failure handling in `server.js` is currently permissive for demo compatibility.
- `verifyPS_Hybrid()` currently emphasizes flow demonstration rather than a complete production-grade PS verification path.

## Files Usually Not Needed for Mode 2

Unless the task explicitly requires them, these are not central to Mode 2:

- `make_proof.js`
- `derive_bip32.js`
- `circuits/bind_key_to_idtoken.circom`
- `run_all.sh`
- `snap/src/tx_type2_accesslist.js`
- `contracts/Greeter.sol`

## Suggested Next Work Areas

Potential Mode 2 focused improvements:

- Align endpoint URLs to use one configurable IdP origin consistently.
- Split Mode 2 client logic from Snap and Google OIDC client logic.
- Add a dedicated Mode 2 smoke test.
- Clarify Step 16-17 behavior.
- Decide whether Light ZKP is part of the demo or should be removed from the active path.
- Make `rid` and `auid` derivation semantics explicit.
- Normalize the naming of `signature`, `signature_prime`, `zkpProof`, and `zkpPublicSignals`.
- Document exact public signal ordering for `pi_arid_i`.
