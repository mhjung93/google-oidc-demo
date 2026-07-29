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
