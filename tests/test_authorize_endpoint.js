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
