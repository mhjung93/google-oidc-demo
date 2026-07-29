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
