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
const vkeyAuid = JSON.parse(fs.readFileSync('build/mode2/pi_auid_vkey.json', 'utf8'));

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
  y: [], // For multiple attributes: [uid, rid, arid_i, auid_i, r_token, max_height]
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

  // 2. Generate IdP Secret Keys (x, y1, y2, y3, y4, y5)
  idpKeys.x = new mcl.Fr();
  idpKeys.x.setByCSPRNG();

  for (let i = 0; i < 5; i++) {
    const yi = new mcl.Fr();
    yi.setByCSPRNG();
    idpKeys.y.push(yi);
  }

  // 3. Generate Public Keys (X = g2^x, Yi = g2^yi)
  idpKeys.pk.X = mcl.mul(psParams.g2, idpKeys.x);
  for (let i = 0; i < 5; i++) {
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
 * @param {Array<string>} messages - [uid, arid_i, auid_i, r_token, max_height]
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

/**
 * PS Multi-Message Verify (for reference)
 */
function psVerify(messages, sigma) {
  const s1 = new mcl.G1();
  s1.setStr(sigma.sigma1, 16);
  const s2 = new mcl.G1();
  s2.setStr(sigma.sigma2, 16);

  if (s1.isZero()) return false;

  // LHS = e(s1, X * prod(Yi^mi))
  let PK_total = new mcl.G2();
  PK_total = mcl.add(idpKeys.pk.X, PK_total);

  for (let i = 0; i < messages.length; i++) {
    const mi = hashToFr(messages[i]);
    PK_total = mcl.add(PK_total, mcl.mul(idpKeys.pk.Y[i], mi));
  }

  const lhs = mcl.pairing(s1, PK_total);
  const rhs = mcl.pairing(s2, psParams.g2);

  return lhs.isEqual(rhs);
}

// Mock Database (UID를 순수 숫자로 변경하여 ZKP와 일치시킴)
const users = {
  'testuser': { password: 'password123', uid: '12345', sub: '12345' },
  'alice': { password: 'secret456', uid: '67890', sub: '67890' }
};
const registeredRPs = {};
const usedNonces = new Set();

function summarizeValue(value) {
  if (value === undefined || value === null) return 'missing';
  const str = typeof value === 'string' ? value : JSON.stringify(value);
  return str.length > 80 ? `${str.slice(0, 80)}...` : str;
}

// 1. RP Registration
app.post('/register_rp', (req, res) => {
  const { rpName, callbackUrl } = req.body;
  // rid를 큰 숫자 스칼라(248비트 랜덤)로 발급 — pi_i 회로의 private input rid로 쓰인다.
  const rid = BigInt('0x' + randomBytes(31).toString('hex')).toString();

  // Still mock for RP registration for now
  const rpToken = {
    rpName,
    rid,
    signature: `mock-ps-sig-rp-${randomBytes(16).toString('hex')}`,
    issuedAt: new Date().toISOString()
  };

  registeredRPs[rid] = { ...rpToken, callbackUrl };
  res.json(rpToken);
});

// 1.5. Initial Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  if (user && user.password === password) {
    // Sign [uid, arid_i, auid_i, r_token, max_height]
    const sig = psSign([user.uid, "init", "init", "0", "0"]);
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
  const { username, password, zkpProof, zkpPublicSignals, business, isLight, walletSubmission, pi_i } = req.body;

  console.log(`--- [CustomIdP][Step 9] SSO Attempt: ${username} (${isLight ? 'LIGHT' : 'HEAVY'}) ---`);
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

async function verifyPiIAndIssueToken({ username, zkpProof, zkpPublicSignals, business, isLight, start = cursor() }) {
  const user = users[username];
  if (!user) throw new Error('Unknown user for consent verification');

  try {
    if (!zkpProof || !zkpPublicSignals) throw new Error('ZKP data missing');

    // [보안 강화 1] 세션의 진짜 UID를 ZKP 공개 입력값에 강제로 주입
    if (isLight && zkpPublicSignals.length >= 3) {
      console.log(`[CustomIdP][Step 10] BINDING: Overwriting ZKP UID(${zkpPublicSignals[0]}) with Session UID(${user.uid}) ${ms(start)}`);
      zkpPublicSignals[0] = user.uid.toString(); // 강제 교체

      // [보안 강화 2] ZKP에 들어있는 rid가 등록된 RP의 것인지 확인
      const claimedRid = zkpPublicSignals[1];
      const isRegisteredRP = Object.values(registeredRPs).some(rp => rp.signature === claimedRid);
      if (!isRegisteredRP && claimedRid !== '67890') { // 67890은 데모용 고정 mock값 허용
        throw new Error(`Unregistered Relying Party (RID: ${claimedRid})`);
      }
    }

    // 모드에 따라 VKey 선택
    const vkey = isLight ? vkeyAuid : vkeyAridI;
    const isValid = await snarkjs.groth16.verify(vkey, zkpPublicSignals, zkpProof);

    if (!isValid) {
      throw new Error('Identity Mismatch: This proof was not made for you!');
    }
    if (!isLight) {
      const maxHeight = business?.maxHeight ?? business?.max_height;
      const rToken = business?.r_token ?? business?.tokenNonce;
      if (String(zkpPublicSignals[1]) !== String(business?.arid_i)) throw new Error('arid_i does not match pi_i public signal');
      if (String(zkpPublicSignals[2]) !== String(business?.auid_i)) throw new Error('auid_i does not match pi_i public signal');
      if (String(zkpPublicSignals[3]) !== String(maxHeight)) throw new Error('max_height does not match pi_i public signal');
      if (String(zkpPublicSignals[4]) !== String(rToken)) throw new Error('r_token does not match pi_i public signal');
    }
    console.log(`✅ [CustomIdP][Step 10] pi_i Verified for user: ${username} ${ms(start)}`);
  } catch (err) {
    console.error(`❌ [CustomIdP][Step 10] pi_i Error: ${err.message} ${ms(start)}`);
    throw err;
  }


  // rp_nonce is never sent to the IdP (it would let the IdP recover rid via
  // arid_i / rp_nonce). Replay protection is keyed off the session nonce
  // (r_i / mode2SessionNonce) instead — created fresh per login attempt in
  // client.js and already sent to the IdP today (custom_idp.js:219-220).
  const nonce = business?.r_i || 'mock-nonce';

  if (usedNonces.has(nonce)) {
    throw new Error('Replay detected: RP nonce was already used');
  }
  usedNonces.add(nonce);

  const maxHeight = business?.maxHeight ?? business?.max_height;
  const rToken = business?.r_token ?? business?.tokenNonce;
  if (!rToken) throw new Error('r_token missing from Wallet submission');
  if (!maxHeight) throw new Error('max_height missing from Wallet submission');

  const exp = Math.floor(Date.now() / 1000) + 3600;

  const messages = [user.uid, business.arid_i, business.auid_i, rToken.toString(), maxHeight.toString()];
  const sig = psSign(messages);
  console.log(`[CustomIdP][Step 10] Issuing IdP auth token after consent and pi_i verification. ${ms(start)}`);

  const idpToken = {
    uid: user.uid,
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
  const { username, allowed, walletSubmission, business, zkpProof, zkpPublicSignals, isLight } = req.body || {};

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
    const idpToken = await verifyPiIAndIssueToken({ username, zkpProof, zkpPublicSignals, business, isLight, start });
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
