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
  // 동의는 로그인한 **그 브라우저 세션**에 묶인다. 그래서 로그인 응답의 세션 쿠키를
  // 들고 다녀야 한다(실제 브라우저가 하는 일과 같다).
  const goodLogin = await fetch(`${IDP}/authorize/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri, username: 'testuser', password: 'password123' }),
  });
  const goodLoginBody = await goodLogin.json();
  if (!goodLoginBody.success) throw new Error(`FAIL: login failed: ${JSON.stringify(goodLoginBody)}`);
  const sessionCookie = (goodLogin.headers.get('set-cookie') || '').split(';')[0];
  if (!sessionCookie) throw new Error('FAIL: /authorize/login did not set a session cookie');
  console.log('PASS: login succeeded (ZKP fully verified)');

  // request_uri는 비밀이 아니다 — RP FE가 팝업을 그 URL로 보내야 하므로 /loginStatus를
  // 통해 RP에 전달된다. IdP는 와일드카드 CORS까지 쓰므로, 동의가 request_uri 지식만으로
  // 인가되면 RP 페이지가 사용자 대신 승인(또는 거부)할 수 있다. 세션에 묶여야 한다.
  console.log('-- consent from a different session (expect 403) --');
  const foreignConsent = await fetch(`${IDP}/authorize/consent`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri, allowed: true }),
  });
  if (foreignConsent.status !== 403) {
    throw new Error(`FAIL: 다른 세션의 동의는 403이어야 한다 (받은 코드 ${foreignConsent.status})`);
  }
  console.log('PASS: 로그인하지 않은 세션은 동의할 수 없다');

  const consent = await fetch(`${IDP}/authorize/consent`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: sessionCookie },
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
    method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: sessionCookie },
    body: JSON.stringify({ request_uri, allowed: true }),
  });
  if (reuseConsent.status !== 400) throw new Error(`FAIL: expected 400, got ${reuseConsent.status}`);
  console.log('PASS: request_uri is single-use');

  console.log('-- POST /authorize/login with a cryptographically invalid proof (expect 400) --');
  const badState = 'bad-proof-state';
  const badNonce = 'bad-proof-nonce';
  const badChallenge = 'dGVzdC1jaGFsbGVuZ2U';
  const tamperedSignals = [...step8.zkpPublicSignals];
  tamperedSignals[0] = (BigInt(tamperedSignals[0]) + 1n).toString(); // flip arid_i so it no longer matches the proof
  const parBad = await (await fetch(`${IDP}/par`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: 'pairct-wallet', redirect_uri: 'http://127.0.0.1:49999/oidc/callback', response_type: 'code',
      state: badState, nonce: badNonce, code_challenge: badChallenge, code_challenge_method: 'S256',
      zkpProof: step8.zkpProof, zkpPublicSignals: tamperedSignals, chain_id: step8.chain_id,
      requestBinding: signBinding(badState, badNonce, badChallenge),
    }),
  })).json();
  if (!parBad.request_uri) throw new Error(`FAIL: /par (bad proof case) did not return request_uri: ${JSON.stringify(parBad)}`);
  const badProofLogin = await fetch(`${IDP}/authorize/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: parBad.request_uri, username: 'testuser', password: 'password123' }),
  });
  if (badProofLogin.status !== 400) throw new Error(`FAIL: expected 400, got ${badProofLogin.status}`);
  console.log('PASS: cryptographically invalid (tampered) proof rejected at full verification');

  console.log('ALL AUTHORIZE TESTS PASSED');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
