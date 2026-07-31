// Requires custom_idp.js (:4000), server.js (:3000), wallet_agent.js (:5001)
// running. Run: node tests/test_token_legacy_idptoken.js
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256, AbiCoder } from 'ethers';
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
  const state = 'legacy-idptoken-test-state';
  const nonce = 'legacy-idptoken-test-nonce';
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

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
function valueToField(value) {
  const str = String(value);
  if (/^[0-9]+$/.test(str)) return BigInt(str) % FIELD_PRIME;
  const bytes = new TextEncoder().encode(str);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return BigInt(`0x${hex || '0'}`) % FIELD_PRIME;
}

async function main() {
  const redirectUri = 'http://127.0.0.1:49997/oidc/callback';
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

  console.log('-- /token also returns a legacy 6-field idpToken alongside the new statement --');
  const code = await getCode(codeChallenge, redirectUri);
  const tokenRes = await fetch(`${IDP}/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: 'pairct-wallet', code_verifier: codeVerifier }),
  });
  const statement = await tokenRes.json();
  if (tokenRes.status !== 200 || !statement.signature) {
    throw new Error(`FAIL: expected 200 + signature, got ${tokenRes.status} ${JSON.stringify(statement)}`);
  }
  if (!statement.idpToken || !statement.idpToken.signature) {
    throw new Error(`FAIL: expected statement.idpToken.signature, got ${JSON.stringify(statement.idpToken)}`);
  }
  if (
    statement.idpToken.arid_i !== statement.arid_i ||
    statement.idpToken.auid_i !== statement.auid_i ||
    statement.idpToken.r_token !== statement.r_token ||
    statement.idpToken.max_height !== statement.max_height ||
    statement.idpToken.chain_id !== statement.chain_id
  ) {
    throw new Error(`FAIL: statement.idpToken fields do not match statement fields: ${JSON.stringify(statement)}`);
  }
  console.log('PASS: statement.idpToken carries the same arid_i/auid_i/r_token/max_height/chain_id as statement');

  console.log('-- statement.idpToken.signature verifies against the 6-field IDP_TOKEN domain (not PAIRCT_STATEMENT) --');
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const idpKeysRes = await (await fetch(`${IDP}/ps_public_keys`)).json();
  const pkIdP = [eddsa.F.e(BigInt(idpKeysRes.pk_IdP[0])), eddsa.F.e(BigInt(idpKeysRes.pk_IdP[1]))];

  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const msg = poseidon([
    DOMAIN_IDP_TOKEN,
    valueToField(statement.idpToken.arid_i),
    valueToField(statement.idpToken.auid_i),
    valueToField(statement.idpToken.r_token),
    valueToField(statement.idpToken.max_height),
    valueToField(statement.idpToken.chain_id),
  ]);
  const sigForVerify = {
    R8: [eddsa.F.e(BigInt(statement.idpToken.signature.R8[0])), eddsa.F.e(BigInt(statement.idpToken.signature.R8[1]))],
    S: BigInt(statement.idpToken.signature.S),
  };
  if (!eddsa.verifyPoseidon(msg, sigForVerify, pkIdP)) {
    throw new Error('FAIL: statement.idpToken.signature does not verify against the 6-field IDP_TOKEN message');
  }
  console.log('PASS: statement.idpToken.signature verifies against the legacy 6-field IDP_TOKEN domain');

  console.log('ALL LEGACY IDPTOKEN TESTS PASSED');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
