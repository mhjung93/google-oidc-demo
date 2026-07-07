import express from 'express';
import bodyParser from 'body-parser';
import session from 'express-session';
import cors from 'cors';
import mcl from 'mcl-wasm';
import { randomBytes } from 'crypto';
import * as snarkjs from 'snarkjs';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
const PORT = 4000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// VKey 로드
const vkeyAridI = JSON.parse(fs.readFileSync('build/mode2/pi_arid_i_vkey.json', 'utf8'));

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
  y: [], // For multiple attributes: [arid_i, auid_i, r_token, max_height]
  pk: {
    X: null,
    Y: []
  }
};

async function initPS() {
  await mcl.init(mcl.BN_SNARK1);
  
  // 1. Setup Generators
  psParams.g1 = mcl.hashAndMapToG1('gen1');
  psParams.g2 = mcl.hashAndMapToG2('gen2');

  // 2. Generate IdP Secret Keys (x, y1, y2, y3, y4)
  idpKeys.x = new mcl.Fr();
  idpKeys.x.setByCSPRNG();

  for (let i = 0; i < 4; i++) {
    const yi = new mcl.Fr();
    yi.setByCSPRNG();
    idpKeys.y.push(yi);
  }

  // 3. Generate Public Keys (X = g2^x, Yi = g2^yi)
  idpKeys.pk.X = mcl.mul(psParams.g2, idpKeys.x);
  for (let i = 0; i < 4; i++) {
    idpKeys.pk.Y.push(mcl.mul(psParams.g2, idpKeys.y[i]));
  }

  console.log('[CustomIdP] PS Signatures Initialized');
}

function hashToFr(str) {
  const fr = new mcl.Fr();
  fr.setHashOf(str);
  return fr;
}

/**
 * PS Multi-Message Sign
 * @param {Array<string>} messages - [arid_i, auid_i, r_token, max_height]
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
  'testuser': { password: 'password123', uid: '12345', sub: '12345' },
  'alice': { password: 'secret456', uid: '67890', sub: '67890' }
};
const usedNonces = new Set();

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
  const { rpName, callbackUrl } = req.body;
  // rid를 큰 숫자 스칼라(248비트 랜덤)로 발급 — pi_i 회로의 private input rid로 쓰인다.
  const rid = BigInt('0x' + randomBytes(31).toString('hex')).toString();

  const rpToken = {
    rpName,
    rid,
    signature: psSign([rid]),
    issuedAt: new Date().toISOString()
  };

  res.json(rpToken);
});

// 1.5. Initial Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  if (user && user.password === password) {
    // Sign [arid_i, auid_i, r_token, max_height]
    const sig = psSign(["init", "init", "0", "0"]);
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

  console.log(`[CustomIdP][Step 9] Login verified for ${username}. Waiting for consent before pi_i verification. ${ms(start)}`);
  res.json({ success: true, pendingConsent: true });
});

async function verifyPiIAndIssueToken({ username, zkpProof, zkpPublicSignals, business, start = cursor() }) {
  const user = users[username];
  if (!user) throw new Error('Unknown user for consent verification');

  try {
    if (!zkpProof || !zkpPublicSignals) throw new Error('ZKP data missing');
    assertDecimalSignals(zkpPublicSignals, 5, 'pi_i');

    // Step 10 popup credentials bind the IdP account UID to pi_i's public UID.
    if (zkpPublicSignals.length >= 1) {
      console.log(`[CustomIdP][Step 10] BINDING: Overwriting ZKP UID(${summarizeValue(zkpPublicSignals[0])}) with Session UID(${summarizeValue(user.uid)}) ${ms(start)}`);
      zkpPublicSignals[0] = user.uid.toString();
    }

    const isValid = await snarkjs.groth16.verify(vkeyAridI, zkpPublicSignals, zkpProof);

    if (!isValid) {
      throw new Error('Identity Mismatch: This proof was not made for you!');
    }
    const maxHeight = business?.maxHeight ?? business?.max_height;
    const rToken = business?.r_token ?? business?.tokenNonce;
    if (String(zkpPublicSignals[1]) !== String(business?.arid_i)) throw new Error('arid_i does not match pi_i public signal');
    if (String(zkpPublicSignals[2]) !== String(business?.auid_i)) throw new Error('auid_i does not match pi_i public signal');
    if (String(zkpPublicSignals[3]) !== String(maxHeight)) throw new Error('max_height does not match pi_i public signal');
    if (String(zkpPublicSignals[4]) !== String(rToken)) throw new Error('r_token does not match pi_i public signal');
    console.log(`✅ [CustomIdP][Step 10] pi_i Verified for user: ${username} ${ms(start)}`);
  } catch (err) {
    console.error(`❌ [CustomIdP][Step 10] pi_i Error: ${err.message} ${ms(start)}`);
    throw err;
  }


  // rp_nonce is never sent to the IdP (it would let the IdP recover rid via
  // arid_i / rp_nonce). Replay protection is keyed off the session nonce
  // (r_i / mode2SessionNonce) instead — created fresh per login attempt in
  // client.js and already sent to the IdP today (custom_idp.js:219-220).
  const nonce = business?.r_i;
  if (!nonce) throw new Error('r_i missing from Wallet submission');

  if (usedNonces.has(nonce)) {
    throw new Error('Replay detected: RP nonce was already used');
  }
  usedNonces.add(nonce);

  const maxHeight = business?.maxHeight ?? business?.max_height;
  const rToken = business?.r_token ?? business?.tokenNonce;
  if (!rToken) throw new Error('r_token missing from Wallet submission');
  if (!maxHeight) throw new Error('max_height missing from Wallet submission');

  const exp = Math.floor(Date.now() / 1000) + 3600;

  const messages = [business.arid_i, business.auid_i, rToken.toString(), maxHeight.toString()];
  const sig = psSign(messages);
  console.log(`[CustomIdP][Step 10] Issuing IdP auth token after consent and pi_i verification. ${ms(start)}`);

  const idpToken = {
    arid_i: business.arid_i,
    auid_i: business.auid_i,
    r_token: rToken.toString(),
    max_height: maxHeight.toString(),
    exp: exp,
    signature: sig
  };
  console.log(`[CustomIdP][Step 11] IdP auth token issued and returned for Wallet delivery. ${ms(start)}`);

  return idpToken;
}

app.post('/consent_result', async (req, res) => {
  const start = cursor();
  const { username, allowed, walletSubmission, business, zkpProof, zkpPublicSignals } = req.body || {};

  console.log('[CustomIdP][Step 10] Consent result received:', {
    username: summarizeValue(username),
    allowed: Boolean(allowed),
    auid_i: summarizeValue(walletSubmission?.auid_i ?? business?.auid_i),
    arid_i: summarizeValue(walletSubmission?.arid_i ?? business?.arid_i),
    r_token: summarizeValue(walletSubmission?.r_token ?? business?.r_token ?? business?.tokenNonce)
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

// 4. Public Keys Endpoint (for RP verification)
app.get('/ps_public_keys', (req, res) => {
  res.json({
    g2: psParams.g2.getStr(16),
    X: idpKeys.pk.X.getStr(16),
    Y: idpKeys.pk.Y.map(y => y.getStr(16))
  });
});

const server = app.listen(PORT, async () => {
  await initPS();
  await snarkjs.curves.getCurveFromName('bn128'); // bn128 WASM 모듈 미리 빌드 (첫 pi_i 검증 지연 방지)
  console.log(`Custom IdP running at http://localhost:${PORT}`);
});
