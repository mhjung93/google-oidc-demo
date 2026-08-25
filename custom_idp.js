import express from 'express';
import bodyParser from 'body-parser';
import session from 'express-session';
import cors from 'cors';
import mcl from 'mcl-wasm';
import { randomBytes, createHash, timingSafeEqual } from 'crypto';
import * as snarkjs from 'snarkjs';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { recoverAddress, keccak256, AbiCoder } from 'ethers';
import { createIMT, leafValue, TAG_SESSION, TAG_ACCOUNT } from './lib/imt.js';

const app = express();
const PORT = 4000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// VKey 로드
const vkeyAridI = JSON.parse(fs.readFileSync('build/mode2/pi_arid_i_vkey.json', 'utf8'));

// 폐기 트리. custom_idp.js의 다른 로그와 마찬가지로 메모리에만 두며,
// 재시작하면 비워진다(기존 issuanceLog/auidILog와 같은 의도된 데모 한계).
const revocationTree = await createIMT(20);
const revokedLeaves = [];

function now() { return Date.now(); }
function cursor() { return { last: now() }; }
function ms(c) {
  const t = now();
  const delta = t - c.last;
  c.last = t;
  return `${delta.toFixed(0)} ms`;
}

app.use(cors());
app.use(bodyParser.json());
app.use('/idp', express.static(path.join(__dirname, 'idp')));
app.use(session({
  name: 'idp_sid', // server.js도 127.0.0.1에서 돌아서, 기본 이름(connect.sid)을 쓰면
                   // 브라우저 쿠키 잡(포트 구분 안 함)이 서로 덮어써버린다.
  secret: 'custom-idp-secret',
  resave: false,
  saveUninitialized: true
}));

app.get('/idp', (req, res) => {
  res.sendFile(path.join(__dirname, 'idp', 'index.html'));
});

app.get('/idp/', (req, res) => {
  res.sendFile(path.join(__dirname, 'idp', 'index.html'));
});

// --- PS Signature Implementation ---
let psParams = {
  g1: null,
  g2: null,
};

let idpKeys = {
  x: null,
  y: [], // For multiple attributes: [domain, arid_i, auid_i, r_token, max_height, chain_id]
  pk: {
    X: null,
    Y: []
  }
};

// EdDSA-Poseidon 키쌍 — RP_REG에 쓰는 PS 키(idpKeys)와는 완전히 별개. auth token(IDP_TOKEN)
// 서명 전용.
let eddsa = null;
let poseidon = null;
let idpEdDSAKeys = {
  prv: null, // raw bytes (Buffer) — circomlibjs signPoseidon()이 요구하는 형식, mcl.Fr 아님
  pub: null, // [x, y], F-internal representation
};

async function initEdDSA() {
  eddsa = await buildEddsa();
  poseidon = await buildPoseidon();
  idpEdDSAKeys.prv = randomBytes(32);
  idpEdDSAKeys.pub = eddsa.prv2pub(idpEdDSAKeys.prv);
  console.log('[CustomIdP] EdDSA-Poseidon Signatures Initialized');
}

async function initPS() {
  await mcl.init(mcl.BN_SNARK1);
  
  // 1. Setup Generators
  psParams.g1 = mcl.hashAndMapToG1('gen1');
  psParams.g2 = mcl.hashAndMapToG2('gen2');

  // 2. Generate IdP Secret Keys (x, y1, y2, y3, y4, y5, y6)
  idpKeys.x = new mcl.Fr();
  idpKeys.x.setByCSPRNG();

  for (let i = 0; i < 6; i++) {
    const yi = new mcl.Fr();
    yi.setByCSPRNG();
    idpKeys.y.push(yi);
  }

  // 3. Generate Public Keys (X = g2^x, Yi = g2^yi)
  idpKeys.pk.X = mcl.mul(psParams.g2, idpKeys.x);
  for (let i = 0; i < 6; i++) {
    idpKeys.pk.Y.push(mcl.mul(psParams.g2, idpKeys.y[i]));
  }

  console.log('[CustomIdP] PS Signatures Initialized');
}

function hashToFr(str) {
  const fr = new mcl.Fr();
  fr.setHashOf(str);
  return fr;
}

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// wallet_agent.js/client.js/server.js에 이미 있는 것과 동일한 구현 — 문자열/숫자를
// Poseidon이 받을 수 있는 필드 원소로 바꾼다. hashToFr()(mcl 전용)와는 호환 안 됨.
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function valueToField(value) {
  if (typeof value === 'bigint') return value % FIELD_PRIME;
  if (typeof value === 'number') return BigInt(value) % FIELD_PRIME;
  const str = String(value);
  if (str.startsWith('0x')) return BigInt(str) % FIELD_PRIME;
  if (/^[0-9]+$/.test(str)) return BigInt(str) % FIELD_PRIME;
  const bytes = new TextEncoder().encode(str);
  const hex = bytesToHex(bytes);
  return BigInt(`0x${hex || '0'}`) % FIELD_PRIME;
}

 /**
  * PS Multi-Message Sign
 * @param {Array<string>} messages - domain-separated message vector
  */
function psSign(messages) {
  const randomStr = randomBytes(32).toString('hex');
  const h = mcl.hashAndMapToG1(randomStr);

  // exponent = x + sum(yi * mi)
  let exponent = idpKeys.x.clone();

  for (let i = 0; i < messages.length; i++) {
    const mi = hashToFr(messages[i]);
    const yi_mi = mcl.mul(idpKeys.y[i], mi);
    exponent = mcl.add(exponent, yi_mi);
  }

  const sigma1 = h;
  const sigma2 = mcl.mul(h, exponent);

  return {
    sigma1: sigma1.getStr(16),
    sigma2: sigma2.getStr(16)
  };
}

// Mock Database (UID를 순수 숫자로 변경하여 ZKP와 일치시킴)
const users = {
  'testuser': { password: 'password123', uid: '12345', sub: '12345', lastAuid: null },
  'alice': { password: 'secret456', uid: '67890', sub: '67890', lastAuid: null }
};
const usedNonces = new Set();
// B2 추적용 발급 로그: r_token -> uid. 메모리 전용, 서버 재시작 시 소실됨(의도된 데모 한계).
const issuanceLog = new Map();
// B2 추적용 발급 로그: auid_i -> uid. auid_i = ppid * rp_nonce는 세션마다 값이 바뀌지만,
// 어느 세션의 auid_i든 같은 ppid(=같은 계정)면 항상 같은 uid로 귀결되므로, RP가 그
// 지갑으로 가장 최근에 로그인했을 때의 auid_i만 들고 있어도 이 로그로 uid를 찾을 수
// 있다. 메모리 전용, 서버 재시작 시 소실됨(의도된 데모 한계).
const auidILog = new Map();
// 비밀번호 인증(/sso_with_credentials) 후 동의 클릭(/consent_result)까지 허용하는 최대 시간.
const PENDING_CONSENT_TTL_MS = 5 * 60 * 1000;

function summarizeValue(value) {
  if (value === undefined || value === null) return 'missing';
  const str = typeof value === 'string' ? value : JSON.stringify(value);
  return str.length > 80 ? `${str.slice(0, 80)}...` : str;
}

function assertDecimalSignals(signals, expectedLength, name) {
  if (!Array.isArray(signals) || signals.length !== expectedLength) {
    throw new Error(`${name} public signals must be an array of length ${expectedLength}`);
  }
  for (const signal of signals) {
    if (typeof signal !== 'string' || !/^[0-9]+$/.test(signal)) {
      throw new Error(`${name} public signals must be decimal strings`);
    }
  }
  return signals;
}

// 1. RP Registration
app.post('/register_rp', (req, res) => {
  const { rpName, callbackUrl, origin } = req.body;
  if (!origin) {
    return res.status(400).json({ error: 'origin is required for RP registration' });
  }
  // rid를 큰 숫자 스칼라(248비트 랜덤)로 발급 — pi_i 회로의 private input rid로 쓰인다.
  const rid = BigInt('0x' + randomBytes(31).toString('hex')).toString();

  // origin을 서명 대상에 포함시켜서, rid와 origin의 묶음 자체를 IdP가 보증한다.
  // 이게 없으면 RP FE(client.js)가 이 rid를 다른 origin의 것인 척 wallet에
  // 제출해도(다른 RP의 정상 발급 rid를 몰래 끼워 넣어도) wallet이 구분할 방법이
  // 없다 — origin이 서명 안에 있어야 wallet이 "이 rid, 진짜 내가 보고 있는
  // origin 거 맞아?"를 credential 하나만으로 검증할 수 있다.
  // EdDSA-Poseidon으로 서명(예전엔 PS 서명이었음) — wallet_agent.js가 로컬에서
  // 검증하는 용도 외에, pi_arid_i 회로 안에서 "이 rid/origin이 IdP가 발급한 진짜
  // credential에 묶여있다"를 rid/origin을 공개하지 않고 증명하는 데도 쓴다(같은
  // idpEdDSAKeys를 재사용 — IDP_TOKEN 서명과 별개 키를 새로 만들 필요 없음).
  const DOMAIN_RP_REG = valueToField('RP_REG');
  const rpRegMsg = poseidon([DOMAIN_RP_REG, valueToField(rid), valueToField(origin)]);
  const rpRegSig = eddsa.signPoseidon(idpEdDSAKeys.prv, rpRegMsg);

  const rpToken = {
    rpName,
    rid,
    origin,
    signature: {
      R8: [
        eddsa.F.toObject(rpRegSig.R8[0]).toString(),
        eddsa.F.toObject(rpRegSig.R8[1]).toString(),
      ],
      S: rpRegSig.S.toString(),
    },
    issuedAt: new Date().toISOString()
  };

  res.json(rpToken);
});

// ── PAR (RFC 9126) + Authorization Code + PKCE ── additive alongside the
// existing /register_rp, /sso_with_credentials, /consent_result flow. See
// docs/superpowers/specs/2026-07-24-idp-par-authorize-token-design.md.
const PAIRCT_CLIENT_ID = 'pairct-wallet';
const LOOPBACK_REDIRECT_URI_PATTERN = /^http:\/\/127\.0\.0\.1:\d+\/oidc\/callback$/;
const PAR_REQUEST_TTL_MS = 60 * 1000;
const AUTHORIZATION_CODE_TTL_MS = 60 * 1000;

// request_uri -> { redirect_uri, state, nonce, code_challenge,
// code_challenge_method, zkpProof, zkpPublicSignals, chain_id,
// requestBinding, expiresAt, [authenticatedUid, arid_i, auid_i, max_height,
// token_nonce, auid] }. Memory-only, same "intentional demo limitation" as
// issuanceLog/auidILog/usedNonces below.
const pushedRequests = new Map();
// code -> { redirect_uri, code_challenge, code_challenge_method, nonce,
// arid_i, auid_i, max_height, token_nonce, auid, chain_id, uid, expiresAt }.
const authorizationCodes = new Map();

function pruneExpired(map) {
  const now = Date.now();
  for (const [key, record] of map) {
    if (record.expiresAt <= now) map.delete(key);
  }
}

app.post('/par', async (req, res) => {
  pruneExpired(pushedRequests);
  const {
    client_id, redirect_uri, response_type,
    state, nonce, code_challenge, code_challenge_method,
    zkpProof, zkpPublicSignals, chain_id, requestBinding,
  } = req.body ?? {};

  if (client_id !== PAIRCT_CLIENT_ID) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'unknown client_id' });
  }
  if (typeof redirect_uri !== 'string' || !LOOPBACK_REDIRECT_URI_PATTERN.test(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri must be a loopback http://127.0.0.1:{port}/oidc/callback URL' });
  }
  if (response_type !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type' });
  }
  if (!state || !nonce) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'state and nonce are required' });
  }
  if (!code_challenge || code_challenge_method !== 'S256') {
    return res.status(400).json({ error: 'invalid_request', error_description: 'code_challenge (S256) is required' });
  }
  if (!chain_id) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'chain_id is required' });
  }
  if (!requestBinding?.pk_i || !requestBinding?.signature) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'requestBinding.pk_i/signature are required' });
  }
  if (!zkpProof) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'zkpProof is required' });
  }

  // Structural check only — NOT a full Groth16 verify. pi_arid_i's first
  // public signal is uid, which the IdP doesn't know yet (login happens
  // later, at POST /authorize/login). Full verification happens there.
  try {
    assertDecimalSignals(zkpPublicSignals, 7, 'pi_i without uid');
  } catch (err) {
    return res.status(400).json({ error: 'invalid_request', error_description: err.message });
  }

  const bindingHash = keccak256(
    AbiCoder.defaultAbiCoder().encode(['string', 'string', 'string'], [state, nonce, code_challenge]),
  );
  let recovered;
  try {
    recovered = recoverAddress(bindingHash, requestBinding.signature);
  } catch (err) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'requestBinding.signature is malformed' });
  }
  if (recovered.toLowerCase() !== String(requestBinding.pk_i).toLowerCase()) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'requestBinding.signature does not match requestBinding.pk_i' });
  }

  const request_uri = `urn:pairct:par:${randomBytes(24).toString('hex')}`;
  pushedRequests.set(request_uri, {
    redirect_uri, state, nonce, code_challenge, code_challenge_method,
    zkpProof, zkpPublicSignals, chain_id, requestBinding,
    expiresAt: Date.now() + PAR_REQUEST_TTL_MS,
  });

  res.json({ request_uri, expires_in: PAR_REQUEST_TTL_MS / 1000 });
});

app.get('/authorize', (req, res) => {
  pruneExpired(pushedRequests);
  const { client_id, request_uri } = req.query;
  if (client_id !== PAIRCT_CLIENT_ID || !pushedRequests.has(request_uri)) {
    return res.status(400).send('Invalid or expired authorization request.');
  }
  res.sendFile(path.join(__dirname, 'idp', 'authorize.html'));
});

app.post('/authorize/login', async (req, res) => {
  pruneExpired(pushedRequests);
  const { request_uri, username, password } = req.body ?? {};
  const record = pushedRequests.get(request_uri);
  if (!record) {
    return res.status(400).json({ success: false, error: 'Invalid or expired authorization request' });
  }
  const user = users[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }

  try {
    const verifySignals = [user.uid.toString(), ...record.zkpPublicSignals];
    assertDecimalSignals(verifySignals, 8, 'pi_i');
    const isValid = await snarkjs.groth16.verify(vkeyAridI, verifySignals, record.zkpProof);
    if (!isValid) throw new Error('Identity Mismatch: This proof was not made for you!');

    const idpPubX = eddsa.F.toObject(idpEdDSAKeys.pub[0]).toString();
    const idpPubY = eddsa.F.toObject(idpEdDSAKeys.pub[1]).toString();
    if (String(verifySignals[6]) !== idpPubX || String(verifySignals[7]) !== idpPubY) {
      throw new Error('pi_i was proven against a different IdP key');
    }

    record.authenticatedUid = user.uid;
    record.arid_i = verifySignals[1];
    record.auid_i = verifySignals[2];
    record.max_height = verifySignals[3];
    record.token_nonce = verifySignals[4];
    record.auid = verifySignals[5];
  } catch (err) {
    return res.status(400).json({ success: false, error: err.message });
  }

  res.json({ success: true });
});

app.post('/authorize/consent', (req, res) => {
  pruneExpired(pushedRequests);
  const { request_uri, allowed } = req.body ?? {};
  const record = pushedRequests.get(request_uri);
  if (!record) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid or expired authorization request' });
  }
  if (!record.authenticatedUid) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Login has not completed for this request' });
  }

  pushedRequests.delete(request_uri); // single-use regardless of outcome

  if (!allowed) {
    return res.json({ redirectTo: `${record.redirect_uri}?error=access_denied&state=${encodeURIComponent(record.state)}` });
  }

  const code = randomBytes(24).toString('hex');
  authorizationCodes.set(code, {
    redirect_uri: record.redirect_uri,
    code_challenge: record.code_challenge,
    code_challenge_method: record.code_challenge_method,
    nonce: record.nonce,
    arid_i: record.arid_i,
    auid_i: record.auid_i,
    max_height: record.max_height,
    token_nonce: record.token_nonce,
    auid: record.auid,
    chain_id: record.chain_id,
    uid: record.authenticatedUid,
    expiresAt: Date.now() + AUTHORIZATION_CODE_TTL_MS,
  });

  res.json({ redirectTo: `${record.redirect_uri}?code=${code}&state=${encodeURIComponent(record.state)}` });
});

app.post('/token', async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, code_verifier } = req.body ?? {};

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
  if (client_id !== PAIRCT_CLIENT_ID) {
    return res.status(400).json({ error: 'invalid_client' });
  }
  if (!code || !code_verifier || !redirect_uri) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'code, code_verifier, and redirect_uri are required' });
  }

  const record = authorizationCodes.get(code);
  if (!record || record.expiresAt <= Date.now()) {
    authorizationCodes.delete(code);
    return res.status(400).json({ error: 'invalid_grant', error_description: 'code is invalid, expired, or already used' });
  }
  if (record.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri does not match' });
  }

  const computedChallenge = createHash('sha256').update(code_verifier).digest('base64url');
  if (computedChallenge !== record.code_challenge) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier does not match code_challenge' });
  }

  // r_token(token_nonce) replay guard — same protection the old /consent_result
  // flow already has (verifyPiIAndIssueToken's usedNonces check), applied here
  // too so the new flow isn't weaker than the one it's meant to replace.
  if (usedNonces.has(String(record.token_nonce))) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'r_token has already been used to issue a statement' });
  }

  authorizationCodes.delete(code); // single-use: burn immediately after successful validation
  usedNonces.add(String(record.token_nonce));

  const exp = Math.floor(Date.now() / 1000) + 3600;
  const DOMAIN_PAIRCT_STATEMENT = valueToField('PAIRCT_STATEMENT');
  const msgFields = [
    DOMAIN_PAIRCT_STATEMENT,
    valueToField('custom-idp'),
    valueToField(PAIRCT_CLIENT_ID),
    valueToField(record.nonce),
    valueToField(record.arid_i),
    valueToField(record.auid_i),
    valueToField(record.token_nonce),
    valueToField(record.max_height),
    valueToField(record.chain_id),
  ];
  const msg = poseidon(msgFields);
  const sig = eddsa.signPoseidon(idpEdDSAKeys.prv, msg);

  // 온체인 tx 제출(wallet_agent.js의 /submitTransaction, pi_pk_i 회로)은 이미 배포된
  // PiPkIVerifier가 옛 6-field IDP_TOKEN 도메인 서명만 검증하도록 불변으로 고정돼
  // 있다. 회로/컨트랙트를 바꾸는 대신, 같은 값들로 그 옛 포맷 서명도 하나 더
  // 만들어서 새 statement와 함께 내려준다 — 둘은 서로 다른 도메인 분리자를 쓰는
  // 별개 서명이라 절대 섞어 쓸 수 없다.
  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const idpTokenMsg = poseidon([
    DOMAIN_IDP_TOKEN,
    valueToField(record.arid_i),
    valueToField(record.auid_i),
    valueToField(record.token_nonce),
    valueToField(record.max_height),
    valueToField(record.chain_id),
  ]);
  const idpTokenSig = eddsa.signPoseidon(idpEdDSAKeys.prv, idpTokenMsg);

  // B2 authorized-opening trace logs — same bookkeeping the old
  // verifyPiIAndIssueToken does, so statements issued via this new flow stay
  // traceable through the existing /idp/lookup_uid_by_r_token and
  // /idp/lookup_uid_by_auid_i endpoints.
  issuanceLog.set(String(record.token_nonce), record.uid);
  auidILog.set(String(record.auid_i), record.uid);

  res.json({
    iss: 'custom-idp',
    aud: PAIRCT_CLIENT_ID,
    nonce: record.nonce,
    arid_i: record.arid_i,
    auid_i: record.auid_i,
    r_token: record.token_nonce,
    max_height: record.max_height,
    chain_id: record.chain_id,
    exp,
    signature: {
      R8: [eddsa.F.toObject(sig.R8[0]).toString(), eddsa.F.toObject(sig.R8[1]).toString()],
      S: sig.S.toString(),
    },
    idpToken: {
      arid_i: record.arid_i,
      auid_i: record.auid_i,
      r_token: record.token_nonce,
      max_height: record.max_height,
      chain_id: record.chain_id,
      signature: {
        R8: [eddsa.F.toObject(idpTokenSig.R8[0]).toString(), eddsa.F.toObject(idpTokenSig.R8[1]).toString()],
        S: idpTokenSig.S.toString(),
      },
    },
  });
});

// 1.5. Initial Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  if (user && user.password === password) {
    // Sign [domain, arid_i, auid_i, r_token, max_height, chain_id]
    const sig = psSign(["IDP_TOKEN", "init", "init", "0", "0", "0"]);
    res.json({
      success: true,
      authToken: {
        uid: user.uid,
        sub: user.sub,
        signature: sig,
        issuer: 'custom-idp'
      }
    });
  } else {
    res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
});

// 2. Popup Login Page
app.get('/login_popup', (req, res) => {
  const start = cursor();
  console.log(`[CustomIdP][Step 9] Login popup requested. ${ms(start)}`);
  res.sendFile(path.join(__dirname, 'idp', 'login_popup.html'));
});

// 3. ZKP + Credentials SSO Endpoint
app.post('/sso_with_credentials', async (req, res) => {
  const start = cursor();
  const { username, password, zkpProof, zkpPublicSignals, business, walletSubmission, pi_i } = req.body;

  console.log(`--- [CustomIdP][Step 9] SSO Attempt: ${username} (Mode 2 pi_i) ---`);
  console.log(`[CustomIdP][Step 9] Published endpoint hit: POST /sso_with_credentials ${ms(start)}`);
  console.log('[CustomIdP][Step 9] Wallet submission fields:', {
    auid_i: summarizeValue(walletSubmission?.auid_i ?? business?.auid_i),
    arid_i: summarizeValue(walletSubmission?.arid_i ?? business?.arid_i),
    r_token: summarizeValue(walletSubmission?.r_token ?? business?.r_token ?? business?.tokenNonce),
    pi_i: summarizeValue(walletSubmission?.pi_i ?? pi_i ?? zkpProof),
    r_i: summarizeValue(walletSubmission?.r_i ?? business?.r_i),
    r_i_check: Boolean(walletSubmission?.r_i ?? business?.r_i)
  });

  const user = users[username];
  if (!user || user.password !== password) {
    console.error(`❌ [CustomIdP][Step 9] Login Failed: Invalid credentials for ${username} ${ms(start)}`);
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }

  // 비밀번호 인증을 통과한 이 시도(username + 그때 제출된 proof/business)를 세션에
  // 고정해둔다. /consent_result는 이후 요청 본문을 신뢰하지 않고 이 값만 사용한다 —
  // 그래야 /sso_with_credentials를 건너뛰고 /consent_result만 직접 호출하거나, 여기서
  // 검증된 것과 다른 proof/business로 바꿔치기하는 걸 막을 수 있다.
  req.session.pendingPairCT = {
    username,
    zkpProof,
    zkpPublicSignals,
    business,
    createdAt: Date.now(),
  };

  console.log(`[CustomIdP][Step 9] Login verified for ${username}. Waiting for consent before pi_i verification. ${ms(start)}`);
  res.json({ success: true, pendingConsent: true });
});

async function verifyPiIAndIssueToken({ username, zkpProof, zkpPublicSignals, business, start = cursor() }) {
  const user = users[username];
  if (!user) throw new Error('Unknown user for consent verification');

  try {
    if (!zkpProof || !zkpPublicSignals) throw new Error('ZKP data missing');
    assertDecimalSignals(zkpPublicSignals, 7, 'pi_i without uid');

    // The wallet/RP popup payload omits pi_i's public UID signal. The IdP
    // reconstructs it from the authenticated popup account before verification.
    const verifySignals = [user.uid.toString(), ...zkpPublicSignals];
    assertDecimalSignals(verifySignals, 8, 'pi_i');
    console.log(`[CustomIdP][Step 10] BINDING: using Session UID(${summarizeValue(user.uid)}) as pi_i UID input ${ms(start)}`);

    const isValid = await snarkjs.groth16.verify(vkeyAridI, verifySignals, zkpProof);

    if (!isValid) {
      throw new Error('Identity Mismatch: This proof was not made for you!');
    }

    // pk_IdP_x/y (7th, 8th public signals) prove the circuit's internal
    // RP-registration-credential signature check ran against a real key — but
    // the circuit itself doesn't know which key is "the real IdP's," so it
    // only constrains internal consistency (signature verifies under
    // *whatever* pk_IdP_x/y was supplied). The IdP must additionally check
    // here that the supplied key is actually its own, otherwise a prover could
    // pass a self-chosen key + self-forged signature and this whole check
    // would be a no-op.
    const idpPubX = eddsa.F.toObject(idpEdDSAKeys.pub[0]).toString();
    const idpPubY = eddsa.F.toObject(idpEdDSAKeys.pub[1]).toString();
    if (String(verifySignals[6]) !== idpPubX || String(verifySignals[7]) !== idpPubY) {
      throw new Error('pi_i was proven against a different IdP key (RP registration credential check bypassed)');
    }

    // auid = Poseidon(uid, salt) is the 6th (last) public signal — fixed per
    // account. Only trust it once the proof above has already verified, so a
    // bogus proof can't be used to pollute the stored value. If it differs
    // from the value seen at this account's last successful login, the
    // wallet is using a different salt than before.
    const auidFromProof = verifySignals[5];
    if (user.lastAuid !== null && String(user.lastAuid) !== String(auidFromProof)) {
      throw new Error('Wallet binding mismatch: this account is using a different salt than its last successful login');
    }
    user.lastAuid = auidFromProof;

    const maxHeight = business?.maxHeight ?? business?.max_height;
    const rToken = business?.r_token ?? business?.tokenNonce;
    if (String(verifySignals[1]) !== String(business?.arid_i)) throw new Error('arid_i does not match pi_i public signal');
    if (String(verifySignals[2]) !== String(business?.auid_i)) throw new Error('auid_i does not match pi_i public signal');
    if (String(verifySignals[3]) !== String(maxHeight)) throw new Error('max_height does not match pi_i public signal');
    if (String(verifySignals[4]) !== String(rToken)) throw new Error('r_token does not match pi_i public signal');
    console.log(`✅ [CustomIdP][Step 10] pi_i Verified for user: ${username} ${ms(start)}`);
  } catch (err) {
    console.error(`❌ [CustomIdP][Step 10] pi_i Error: ${err.message} ${ms(start)}`);
    throw err;
  }


  // rp_nonce is never sent to the IdP (it would let the IdP recover rid via
  // arid_i / rp_nonce). r_i (mode2SessionNonce) is NOT usable for replay
  // protection here: it is never checked against the pi_i proof's public
  // signals above, so resubmitting an already-used proof with only r_i
  // changed would sail through undetected. r_i keeps its existing role as
  // the RP FE's own transient flow-correlation nonce (client.js matches it
  // against mode2SessionNonce when IDP_SSO_SUCCESS arrives); nothing about
  // that role changes here. Replay protection is instead keyed off
  // r_token, which is checked against verifySignals[4] above and so
  // cannot be forged or reused for a different proof.
  const maxHeight = business?.maxHeight ?? business?.max_height;
  const chainId = business?.chain_id ?? business?.chainId;
  const rToken = business?.r_token ?? business?.tokenNonce;
  if (!rToken) throw new Error('r_token missing from Wallet submission');
  if (!maxHeight) throw new Error('max_height missing from Wallet submission');
  if (!chainId) throw new Error('chain_id missing from Wallet submission');

  if (usedNonces.has(String(rToken))) {
    throw new Error('Replay detected: r_token was already used');
  }
  usedNonces.add(String(rToken));

  const exp = Math.floor(Date.now() / 1000) + 3600;

  // PS('IDP_TOKEN', ...) 대신 EdDSA-Poseidon: 6개 필드를 Poseidon으로 하나의 값으로 묶은
  // 뒤 그 값을 서명한다. domain 문자열도 다른 필드처럼 valueToField()로 필드 원소화한다
  // (Poseidon은 문자열을 직접 못 받음 — hashToFr()는 mcl 전용이라 여기 못 씀).
  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const msgFields = [
    DOMAIN_IDP_TOKEN,
    valueToField(business.arid_i),
    valueToField(business.auid_i),
    valueToField(rToken.toString()),
    valueToField(maxHeight.toString()),
    valueToField(chainId.toString()),
  ];
  // poseidon(...)의 원본 반환값을 그대로 signPoseidon에 넘긴다 — .toObject()로 변환한
  // BigInt를 넘기면 안 된다 (F-internal 표현이 필요함, tests/test_eddsa.js 참고).
  const msg = poseidon(msgFields);
  const sig = eddsa.signPoseidon(idpEdDSAKeys.prv, msg);
  const sigJson = {
    R8: [
      eddsa.F.toObject(sig.R8[0]).toString(),
      eddsa.F.toObject(sig.R8[1]).toString(),
    ],
    S: sig.S.toString(),
  };
  console.log(`[CustomIdP][Step 10] Issuing IdP auth token after consent and pi_i verification. ${ms(start)}`);

  const idpToken = {
    arid_i: business.arid_i,
    auid_i: business.auid_i,
    r_token: rToken.toString(),
    max_height: maxHeight.toString(),
    chain_id: chainId.toString(),
    exp: exp,
    signature: sigJson
  };
  issuanceLog.set(rToken.toString(), user.uid);
  auidILog.set(String(business.auid_i), user.uid);
  console.log(`[CustomIdP][Step 11] IdP auth token issued and returned for Wallet delivery. ${ms(start)}`);

  return idpToken;
}

app.post('/consent_result', async (req, res) => {
  const start = cursor();
  const { allowed } = req.body || {};

  // username/zkpProof/zkpPublicSignals/business는 요청 본문을 신뢰하지 않는다 — 반드시
  // /sso_with_credentials에서 비밀번호 인증과 함께 이 세션에 저장해둔 값만 쓴다. 성공/실패/
  // 거부 어느 경우든 한 번 쓰면 즉시 지워서 같은 pending 로그인을 재사용하지 못하게 막는다.
  const pending = req.session.pendingPairCT;
  delete req.session.pendingPairCT;

  if (!pending) {
    return res.status(400).json({ success: false, error: 'No pending login for this session' });
  }
  if (Date.now() - pending.createdAt > PENDING_CONSENT_TTL_MS) {
    return res.status(400).json({ success: false, error: 'Pending login expired, please sign in again' });
  }

  const { username, zkpProof, zkpPublicSignals, business } = pending;

  console.log('[CustomIdP][Step 10] Consent result received:', {
    username: summarizeValue(username),
    allowed: Boolean(allowed),
    auid_i: summarizeValue(business?.auid_i),
    arid_i: summarizeValue(business?.arid_i),
    r_token: summarizeValue(business?.r_token ?? business?.tokenNonce)
  });

  if (!allowed) {
    return res.json({ success: false, error: 'Consent denied' });
  }

  try {
    console.log(`[CustomIdP][Step 10] Consent approved. Verifying pi_i now. ${ms(start)}`);
    const idpToken = await verifyPiIAndIssueToken({ username, zkpProof, zkpPublicSignals, business, start });
    console.log(`[CustomIdP][Step 11] Consent flow complete, responding to RP FE. ${ms(start)}`);
    res.json({ success: true, idpToken });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message || 'pi_i verification failed' });
  }
});

// 3.5. B2 Trace Endpoint: Lookup UID by r_token
app.post('/idp/lookup_uid_by_r_token', (req, res) => {
  const { r_token } = req.body ?? {};
  if (!r_token) {
    return res.status(400).json({ error: 'r_token is required' });
  }
  const uid = issuanceLog.get(String(r_token));
  if (uid === undefined) {
    return res.status(404).json({ error: 'No issuance record found for this r_token' });
  }
  // uid는 users의 값일 뿐 키가 아니라서, 사람이 읽을 수 있는 username을 보여주려면
  // 역방향으로 찾아야 한다.
  const usernameEntry = Object.entries(users).find(([, user]) => String(user.uid) === String(uid));
  res.json({ uid, username: usernameEntry ? usernameEntry[0] : null });
});

// 3.6. B2 Trace Endpoint: Lookup UID by auid_i
app.post('/idp/lookup_uid_by_auid_i', (req, res) => {
  const { auid_i } = req.body ?? {};
  if (!auid_i) {
    return res.status(400).json({ error: 'auid_i is required' });
  }
  const uid = auidILog.get(String(auid_i));
  if (uid === undefined) {
    return res.status(404).json({ error: 'No issuance record found for this auid_i' });
  }
  const usernameEntry = Object.entries(users).find(([, user]) => String(user.uid) === String(uid));
  res.json({ uid, username: usernameEntry ? usernameEntry[0] : null });
});

// /idp/revoke는 운영자 전용 엔드포인트다. 인증 없이 열어두면 임의의 웹페이지가
// 전역 app.use(cors())를 타고 폐기를 유발해 root를 흔들 수 있고, 게시된 root와
// IdP root가 어긋나 모든 사용자의 execute()가 revert하는 무인증 DoS가 된다.
//
// 시크릿은 환경변수 IDP_ADMIN_SECRET에서만 읽는다(하드코딩 금지). 미설정이면
// 조용히 인증을 건너뛰지 않고 503으로 명확히 거부한다.
const IDP_ADMIN_SECRET = process.env.IDP_ADMIN_SECRET;

function secretMatches(provided, expected) {
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  // timingSafeEqual은 길이가 다르면 throw하므로 길이를 먼저 비교한다.
  // 길이 노출은 감수한다(내용 비교만 상수 시간으로 유지).
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function requireIdPAdmin(req, res, next) {
  if (!IDP_ADMIN_SECRET) {
    return res.status(503).json({ error: 'revocation endpoint is disabled: IDP_ADMIN_SECRET is not configured' });
  }
  // 전역 cors()는 다른 엔드포인트가 의존하므로 건드리지 않고, 이 엔드포인트에만
  // 오리진 제한을 건다. 브라우저는 cross-origin 요청에 항상 Origin 헤더를 붙이므로,
  // Origin이 있다는 것은 곧 브라우저에서 온 요청이라는 뜻이다. 운영자 도구(curl,
  // node 스크립트)는 Origin을 붙이지 않는다.
  const origin = req.get('Origin');
  if (origin !== undefined) {
    return res.status(403).json({ error: 'browser-originated requests are not allowed on this endpoint' });
  }
  const provided = req.get('X-IdP-Admin-Secret');
  if (typeof provided !== 'string' || !secretMatches(provided, IDP_ADMIN_SECRET)) {
    // 시크릿 값 자체는 로그에도 응답에도 남기지 않는다.
    console.warn('[IdP] rejected unauthenticated /idp/revoke attempt');
    return res.status(401).json({ error: 'invalid or missing admin secret' });
  }
  return next();
}

// 폐기 대상 등록. type='session'이면 r_token, 'account'면 auid를 값으로 받는다.
// 어느 쪽이든 IdP가 이미 알고 있는 값이다(issuanceLog / user.lastAuid).
app.post('/idp/revoke', requireIdPAdmin, async (req, res) => {
  const { type, value } = req.body ?? {};
  if (value === undefined || value === null) {
    return res.status(400).json({ error: 'value is required' });
  }

  // Reject non-numeric values: only decimal digits (after trimming) are allowed.
  const valueStr = String(value).trim();
  if (!/^[0-9]+$/.test(valueStr)) {
    return res.status(400).json({ error: 'value must be a non-empty decimal number' });
  }

  // 상한은 BN254 필드 크기 p다. 여기서 걸러야 하는 것은 "필드 원소가 아닌 입력"뿐이다.
  // 폐기 대상(r_token = Poseidon(...), auid = Poseidon(uid, salt))은 둘 다 Poseidon
  // 출력이라 [0, p)에 균등 분포한다. 예전에는 상한이 2^252였는데, 그러면 정상 대상의
  // 약 67%(1 - 2^252/p)가 400으로 거부되면서 폐기가 조용히 실패했다.
  // lib/imt.js의 leafValue()가 Poseidon '출력'을 & MASK_252로 정규화하므로
  // 252비트 제약은 리프 값에만 적용되며 입력에 적용해서는 안 된다.
  try {
    const valueBigInt = BigInt(valueStr);
    if (valueBigInt >= FIELD_PRIME) {
      return res.status(400).json({ error: 'value must be less than the BN254 field prime' });
    }
  } catch (err) {
    return res.status(400).json({ error: 'value must be a valid number' });
  }

  let tag;
  if (type === 'session') tag = TAG_SESSION;
  else if (type === 'account') tag = TAG_ACCOUNT;
  else return res.status(400).json({ error: "type must be 'session' or 'account'" });

  try {
    const leaf = await leafValue(tag, valueStr);
    await revocationTree.insert(leaf);
    if (!revokedLeaves.includes(leaf.toString())) revokedLeaves.push(leaf.toString());

    const root = revocationTree.getRoot().toString();
    console.log(`[IdP] revoked ${type} -> leaf ${leaf}, new root ${root}`);
    res.json({ root });
  } catch (err) {
    return res.status(400).json({ error: err.message || 'Failed to revoke value' });
  }
});

// 지갑이 자기 witness를 계산하려면 폐기 목록 전체가 필요하다.
// 리프는 Poseidon 해시라 preimage가 드러나지 않으므로 공개해도 안전하다.
app.get('/idp/revocation_state', (req, res) => {
  res.json({ root: revocationTree.getRoot().toString(), revokedLeaves });
});

// 4. Public Keys Endpoint (for RP verification)
app.get('/ps_public_keys', (req, res) => {
  res.json({
    g2: psParams.g2.getStr(16),
    X: idpKeys.pk.X.getStr(16),
    Y: idpKeys.pk.Y.map(y => y.getStr(16)),
    pk_IdP: [
      eddsa.F.toObject(idpEdDSAKeys.pub[0]).toString(),
      eddsa.F.toObject(idpEdDSAKeys.pub[1]).toString(),
    ],
  });
});

const server = app.listen(PORT, async () => {
  await initPS();
  await initEdDSA();
  await snarkjs.curves.getCurveFromName('bn128'); // bn128 WASM 모듈 미리 빌드 (첫 pi_i 검증 지연 방지)
  console.log(`Custom IdP running at http://localhost:${PORT}`);
  if (!IDP_ADMIN_SECRET) {
    // 값은 절대 출력하지 않고, 설정 여부만 알린다.
    console.warn('[IdP] IDP_ADMIN_SECRET is not set — POST /idp/revoke will return 503 until it is configured.');
  }
});
