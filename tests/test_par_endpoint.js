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
