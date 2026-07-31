// Requires custom_idp.js (:4000), server.js (:3000), wallet_agent.js (:5001)
// running and key-consistent. Run: node tests/test_verify_statement_endpoint.js
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256, AbiCoder } from 'ethers';
import { createHash, randomBytes } from 'crypto';

const IDP = 'http://127.0.0.1:4000';
const SERVER = 'http://127.0.0.1:3000';
const WALLET = 'http://127.0.0.1:5001';

function extractSessionCookie(res) {
  const raw = res.headers.get('set-cookie');
  if (!raw) throw new Error('no set-cookie header returned');
  return raw.split(';')[0]; // "rp_sid=..."
}

async function getWalletAgentToken() {
  return (await (await fetch(`${SERVER}/api/mode2/wallet_agent_token`)).json()).token;
}

async function startRpSession() {
  const nonceRes = await fetch(`${SERVER}/api/mode2/rp_credential_nonce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionNonce: '0xaaaa' }),
  });
  const cookie = extractSessionCookie(nonceRes);
  const body = await nonceRes.json();
  return { cookie, rpCredential: body.rpCredential, rpNonce: body.rpNonce };
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

async function getStatement(rpCredential, rpNonce, redirectUri) {
  const token = await getWalletAgentToken();
  const step8 = await (await fetch(`${WALLET}/generateStep8Proofs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token, Origin: SERVER },
    body: JSON.stringify({ rpCredential, r_i: '0xaaaa', rpNonce }),
  })).json();
  if (!step8.zkpProof) throw new Error(`generateStep8Proofs failed: ${JSON.stringify(step8)}`);

  const state = `verify-statement-test-state-${Date.now()}-${Math.random()}`;
  const nonce = `verify-statement-test-nonce-${Date.now()}-${Math.random()}`;
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
  await fetch(`${IDP}/authorize/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: par.request_uri, username: 'testuser', password: 'password123' }),
  });
  const consent = await (await fetch(`${IDP}/authorize/consent`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: par.request_uri, allowed: true }),
  })).json();
  const code = new URL(consent.redirectTo).searchParams.get('code');

  const tokenRes = await fetch(`${IDP}/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: 'pairct-wallet', code_verifier: codeVerifier }),
  });
  const statement = await tokenRes.json();
  if (tokenRes.status !== 200 || !statement.signature) {
    throw new Error(`FAIL: could not obtain statement: ${tokenRes.status} ${JSON.stringify(statement)}`);
  }
  return { statement, ppid: step8.ppid };
}

async function main() {
  console.log('-- happy path: valid statement + matching RP session is accepted --');
  const session = await startRpSession();
  const { statement, ppid } = await getStatement(session.rpCredential, session.rpNonce, 'http://127.0.0.1:49995/oidc/callback');
  const okRes = await fetch(`${SERVER}/api/mode2/verify_statement`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: session.cookie },
    body: JSON.stringify({ statement, ppid }),
  });
  const okBody = await okRes.json();
  if (!okRes.ok || !okBody.success) throw new Error(`FAIL: expected success, got ${okRes.status} ${JSON.stringify(okBody)}`);
  console.log('PASS: valid statement accepted, RP session established');

  console.log('-- tampered iss is rejected --');
  const session2 = await startRpSession();
  const { statement: statement2, ppid: ppid2 } = await getStatement(session2.rpCredential, session2.rpNonce, 'http://127.0.0.1:49994/oidc/callback');
  const tamperedIss = { ...statement2, iss: 'evil-idp' };
  const issRes = await fetch(`${SERVER}/api/mode2/verify_statement`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: session2.cookie },
    body: JSON.stringify({ statement: tamperedIss, ppid: ppid2 }),
  });
  if (issRes.ok) throw new Error('FAIL: tampered iss was accepted');
  console.log('PASS: tampered iss rejected');

  console.log('-- statement issued for a different RP session (arid_i mismatch) is rejected --');
  const session3 = await startRpSession();
  const { statement: statement3, ppid: ppid3 } = await getStatement(session3.rpCredential, session3.rpNonce, 'http://127.0.0.1:49993/oidc/callback');
  const session4 = await startRpSession(); // 다른 rpNonce를 발급받은 별개 세션
  const wrongAudRes = await fetch(`${SERVER}/api/mode2/verify_statement`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: session4.cookie },
    body: JSON.stringify({ statement: statement3, ppid: ppid3 }),
  });
  if (wrongAudRes.status !== 403) throw new Error(`FAIL: expected 403 on arid_i mismatch, got ${wrongAudRes.status}`);
  console.log('PASS: cross-session replay rejected (arid_i audience check)');

  console.log('-- tampered signature is rejected --');
  const session5 = await startRpSession();
  const { statement: statement5, ppid: ppid5 } = await getStatement(session5.rpCredential, session5.rpNonce, 'http://127.0.0.1:49992/oidc/callback');
  const tamperedSig = { ...statement5, signature: { ...statement5.signature, S: statement5.signature.S + '1' } };
  const sigRes = await fetch(`${SERVER}/api/mode2/verify_statement`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: session5.cookie },
    body: JSON.stringify({ statement: tamperedSig, ppid: ppid5 }),
  });
  if (sigRes.ok) throw new Error('FAIL: tampered signature was accepted');
  console.log('PASS: tampered signature rejected');

  console.log('-- expired max_height is rejected --');
  const session6 = await startRpSession();
  const { statement: statement6, ppid: ppid6 } = await getStatement(session6.rpCredential, session6.rpNonce, 'http://127.0.0.1:49991/oidc/callback');
  const expiredMaxHeight = { ...statement6, max_height: '0' };
  const maxHeightRes = await fetch(`${SERVER}/api/mode2/verify_statement`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: session6.cookie },
    body: JSON.stringify({ statement: expiredMaxHeight, ppid: ppid6 }),
  });
  if (maxHeightRes.status !== 401) throw new Error(`FAIL: expected 401 on expired max_height, got ${maxHeightRes.status}`);
  console.log('PASS: expired max_height rejected');

  console.log('ALL VERIFY_STATEMENT TESTS PASSED');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
