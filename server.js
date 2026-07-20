import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import cors from 'cors';
import { Issuer, generators } from 'openid-client';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs/promises';
import fs_sync from 'fs';
import { createCipheriv, randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { TextEncoder } from 'util';
import { Buffer } from 'buffer';
import mcl from 'mcl-wasm';
import { buildEddsa, buildPoseidon } from 'circomlibjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const {
  PORT = 3000,
  BASE_URL,
  CUSTOM_IDP_BASE_URL = 'http://127.0.0.1:4000',
  MODE2_ETH_RPC_URL = process.env.ETH_RPC_URL || 'http://127.0.0.1:8545',
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  SESSION_SECRET,
} = process.env;

const currentMode = parseInt(process.env.APP_MODE) || 1;
console.log(`[SERVER] Starting in Mode: ${currentMode}`);

const app = express();

let rpRegistration = null;
// B2 추적용 세션 로그: 로그인 세션마다 { auid_i, r_token, rp_nonce, timestamp }.
// 메모리 전용, 서버 재시작 시 소실됨(의도된 데모 한계).
const sessionLog = [];

app.use(cors({
  origin: 'http://127.0.0.1:4000'
}));

// Mode 2: Manual RP Registration Endpoint
app.post('/api/mode2/register', async (req, res) => {
  if (currentMode !== 2) return res.status(400).json({ error: 'Not in Mode 2' });
  
  try {
    const registrationRequest = {
      rpName: 'Manual-ZK-RP-Server',
      callbackUrl: `${BASE_URL}/api/mode2/sso_success`,
      origin: BASE_URL
    };
    const response = await fetch(`${CUSTOM_IDP_BASE_URL}/register_rp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(registrationRequest)
    });
    rpRegistration = await response.json();
    console.log(`[Mode 2] Manually Registered with Custom IdP. rid: ${previewValue(rpRegistration.rid)}`);
    console.log('[Mode 2] RP registration request:', registrationRequest);
    console.log('[Mode 2] RP registration response:', {
      ...rpRegistration,
      rid: previewValue(rpRegistration.rid),
      signature: previewValue(rpRegistration.signature)
    });
    if (!idpPublicKeys || !psParams.g2) {
      console.log('[Mode 2] Retrying IdP public key load after RP registration...');
      await initRP_PS();
    }

    // RP 등록 자체가 이 IdP에서 정말 발급된 것인지 확인 — RP_REG 도메인으로
    // psSign(['RP_REG', rid, origin])된 값이어야 통과한다.
    const isRpSigValid = verifyPS_Hybrid(rpRegistration.signature, ['RP_REG', String(rpRegistration.rid), String(rpRegistration.origin)], idpPublicKeys);
    if (!isRpSigValid) {
      console.error('[Mode 2] RP registration signature verification FAILED. Rejecting registration.');
      rpRegistration = null;
      return res.status(502).json({ error: 'RP registration signature verification failed' });
    }
    console.log('[Mode 2] RP registration signature verified.');

    res.json(rpRegistration);
  } catch (err) {
    console.error('[Mode 2] Manual registration failed:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// wallet_agent.js(로컬 전용 프로세스, 127.0.0.1:5001)는 curl 등 브라우저가 아닌
// 호출자에게 직접 토큰을 내주지 않는다. RP 서버가 같은 파일시스템에서 토큰을 읽어
// 자기 origin(브라우저가 이미 신뢰하는)으로만 전달해서, 다른 origin/프로세스가
// wallet_agent.js를 호출해 salt를 추출하지 못하게 한다.
app.get('/api/mode2/wallet_agent_token', (req, res) => {
  if (currentMode !== 2) return res.status(400).json({ error: 'Not in Mode 2' });
  try {
    const state = JSON.parse(fs_sync.readFileSync(path.join(__dirname, 'wallet_state.json'), 'utf8'));
    if (!state.agentToken) throw new Error('agentToken missing');
    res.json({ token: state.agentToken });
  } catch (err) {
    res.status(503).json({ error: 'wallet_agent.js has not initialized its token yet. Start wallet_agent.js first.' });
  }
});

// ─────────────────────────────────────────────────────────────
// 간단한 타이밍 유틸
function now() { return Date.now(); }
function ms(from, to = now()) { return `${(to - from).toFixed(0)} ms`; }
function maskToken(jwt) {
  if (!jwt || typeof jwt !== 'string') return '(none)';
  if (jwt.length <= 16) return '(short token hidden)';
  return `${jwt.slice(0, 16)}...${jwt.slice(-12)}`;
}
// ─────────────────────────────────────────────────────────────

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Mirrors client.js's valueToField()/bytesToHex() exactly — must produce the
// same field element from the same raw rpNonce string so the recomputed
// arid_i matches what the wallet proved.
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

function previewValue(value, maxChars = 48) {
  if (value === undefined || value === null) return 'n/a';
  const str = typeof value === 'string' ? value : JSON.stringify(value);
  return str.length > maxChars ? `${str.slice(0, maxChars)}...` : str;
}

function assertDecimalString(value, name) {
  if (typeof value !== 'string' || !/^[0-9]+$/.test(value)) {
    throw new Error(`${name} must be a decimal string`);
  }
  return value;
}

async function getCurrentHeightForToken(maxHeight) {
  // Browser wallets usually produce block-height max_height. If the wallet fell
  // back to unix time, the signed max_height is much larger than realistic block
  // heights and can be checked against server time.
  if (maxHeight >= 1000000000n) {
    return {
      value: BigInt(Math.floor(Date.now() / 1000)),
      source: 'unix-time',
    };
  }

  const response = await fetch(MODE2_ETH_RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'eth_blockNumber',
      params: [],
    }),
  });

  if (!response.ok) {
    throw new Error(`eth_blockNumber RPC failed with status ${response.status}`);
  }

  const data = await response.json();
  if (data.error || typeof data.result !== 'string') {
    throw new Error(data.error?.message || 'eth_blockNumber RPC returned no result');
  }

  return {
    value: BigInt(data.result),
    source: MODE2_ETH_RPC_URL,
  };
}

async function getRpcChainId() {
  const response = await fetch(MODE2_ETH_RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'eth_chainId',
      params: [],
    }),
  });

  if (!response.ok) {
    throw new Error(`eth_chainId RPC failed with status ${response.status}`);
  }

  const data = await response.json();
  if (data.error || typeof data.result !== 'string') {
    throw new Error(data.error?.message || 'eth_chainId RPC returned no result');
  }

  return BigInt(data.result).toString();
}

// wallet_agent.js의 rpcCall과 같은 패턴이지만, eth_accounts(배열)/eth_getTransactionReceipt(객체 또는
// null)처럼 문자열이 아닌 결과도 다뤄야 해서 결과 타입을 강제하지 않는다.
async function rpcCall(method, params = []) {
  const response = await fetch(MODE2_ETH_RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });

  if (!response.ok) {
    throw new Error(`${method} RPC failed with status ${response.status}`);
  }

  const data = await response.json();
  if (data.error) {
    throw new Error(data.error.message || `${method} RPC returned an error`);
  }
  return data.result;
}

async function waitForReceipt(txHash) {
  const maxAttempts = 30; // 1초 간격 폴링 * 30 = 최대 30초 대기 후 포기
  let receipt = null;
  for (let attempt = 0; attempt < maxAttempts && !receipt; attempt++) {
    receipt = await rpcCall('eth_getTransactionReceipt', [txHash]);
    if (!receipt) await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  if (!receipt) {
    throw new Error(`Timed out waiting for receipt of ${txHash} after ${maxAttempts}s`);
  }
  return receipt;
}

// deploy/execute 공통: 실제 전송 전에 eth_call로 dry-run해서 revert할 payload에 실제 gas를
// 쓰지 않도록 막은 뒤, 통과하면 로컬 Hardhat의 기본 unlock 계정으로 전송하고 영수증을 기다린다.
async function relaySingleCall(from, { to, data }) {
  await rpcCall('eth_call', [{ from, to, data }, 'latest']);
  const txHash = await rpcCall('eth_sendTransaction', [{ from, to, data }]);
  await waitForReceipt(txHash);
  return txHash;
}

app.use(session({
  name: 'rp_sid', // custom_idp.js도 127.0.0.1에서 돌아서, 기본 이름(connect.sid)을 쓰면
                  // 브라우저 쿠키 잡(포트 구분 안 함)이 서로 덮어써버린다.
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}));

// Global request logger
app.use((req, res, next) => {
  console.log(`[REQUEST] ${req.method} ${req.url} Query:`, req.query);
  next();
});

let clientPromise = null;
function getOidcClient() {
  if (!clientPromise) {
    const t_discovery_start = now();
    clientPromise = (async () => {
      const google = await Issuer.discover('https://accounts.google.com');
      const client = new google.Client({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uris: [`${BASE_URL}/oidc/callback`],
        response_types: ['code'],
      });
      console.log(`[OIDC] Discovery + Client 준비 완료: ${ms(t_discovery_start)}`);
      return client;
    })();
  }
  return clientPromise;
}

app.get('/', (req, res) => {
  const oidcLinks = currentMode === 2 ? '' : `
    <p><a href="/login">Sign in with Google</a></p>
    <p><a href="/me">/me (ID Token & Claims)</a></p>
    <p><a href="/logout">로그아웃</a></p>
    <hr>
  `;

  // 클라이언트 JS가 로드되기 전에 서버가 이미 아는 currentMode대로 바로 렌더링해서,
  // "Mode 1 버튼들이 잠깐 보였다가 Mode 2로 바뀌는" 깜빡임을 없앤다.
  const modeVisibilityStyle = currentMode === 2
    ? `<style>#mode2Section { display: block !important; } #snapSection { display: none !important; }</style>`
    : `<style>#mode2Section { display: none !important; }</style>`;

  res.send(`
    <h2>Conditional Privacy-Preserving Web3 Authentication - Mode ${currentMode}</h2>
    <script>window.APP_MODE = ${currentMode};</script>
    ${modeVisibilityStyle}
    ${oidcLinks}
    <!-- index.html content here -->
    ${fs_sync.readFileSync(path.join(__dirname, 'index.html'), 'utf-8')}
  `);
});

// 정적 파일 서비스 (client.js 등)
app.use(express.static(__dirname));
app.use(express.json()); // For parsing application/json

// Mode 2: RP credential and RP nonce request
app.post('/api/mode2/rp_credential_nonce', (req, res) => {
  const start = now();
  if (currentMode !== 2) return res.status(400).json({ error: 'Not in Mode 2' });

  const { sessionNonce, r_i, walletAddress } = req.body || {};
  const receivedRi = r_i || sessionNonce;
  console.log(`[Mode 2] Step 4. RP credential and RP nonce request ${ms(start)}:`, {
    walletAddress,
    r_i: receivedRi,
    r_i_check: Boolean(receivedRi)
  });

  const rpNonce = generators.nonce();
  req.session.rpNonce = rpNonce;
  console.log(`[Mode 2] Step 5. RP nonce created ${ms(start)}:`, { rpNonce: previewValue(rpNonce) });

  const responseBody = {
    success: Boolean(rpRegistration?.rid),
    rpCredential: rpRegistration,
    sessionNonce: receivedRi,
    r_i: receivedRi,
    rpNonce
  };

  console.log(`[Mode 2] Step 6. RP credential and nonce response ${ms(start)}:`, {
    ...responseBody,
    rpCredential: rpRegistration ? {
      ...rpRegistration,
      rid: previewValue(rpRegistration.rid),
      signature: previewValue(rpRegistration.signature),
    } : rpRegistration,
    rpNonce: previewValue(rpNonce),
  });

  if (!rpRegistration?.rid) {
    return res.status(400).json({
      ...responseBody,
      error: 'RP is not registered yet'
    });
  }

  res.json(responseBody);
});

// 로그인 시작
app.get('/login', async (req, res, next) => {
  console.log('[/login] Received query parameters:', req.query); // 디버그 로그 추가
  try {
    const client = await getOidcClient();
    req.session.t_flow_start = now();

    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);
    const state = generators.state();
    // Check for custom_nonce query parameter, otherwise generate a new one
    const nonce = req.query.custom_nonce || generators.nonce();

    req.session.codeVerifier = codeVerifier;
    req.session.state = state;
    req.session.nonce = nonce;

    const authUrl = client.authorizationUrl({
      scope: 'openid email profile',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
      nonce,
    });

    console.log(`[FLOW] /login → Google redirect (PKCE 준비 완료, state=${state})`);
    res.redirect(authUrl);
  } catch (e) { next(e); }
});

// 콜백: 토큰 교환 + 검증
app.get('/oidc/callback', async (req, res, next) => {
  try {
    const client = await getOidcClient();

    // ① state 확인
    const t_cb_start = now();
    if (req.query.state !== req.session.state) {
      console.error(`[FLOW] state 불일치 (expected=${req.session.state}, got=${req.query.state})`);
      return res.status(400).send('Invalid state');
    }

    // ② 토큰 교환 타이밍 측정
    const params = client.callbackParams(req);
    const t_token_start = now();
    const tokenSet = await client.callback(
      `${BASE_URL}/oidc/callback`,
      params,
      {
        state: req.session.state,
        nonce: req.session.nonce,
        code_verifier: req.session.codeVerifier,
      }
    );
    const t_token_end = now();

    // ③ 결과 정리
    const claims = tokenSet.claims();
    req.session.idToken = tokenSet.id_token;
    req.session.claims = claims;

    // 파일에 토큰 저장 (run_all.sh용)
    await fs.writeFile('.id_token.txt', tokenSet.id_token);
    console.log(`[OIDC] ID Token saved to .id_token.txt`);

    // ④ 로그 출력
    const flowStart = req.session.t_flow_start || t_cb_start;
    const idToken = tokenSet.id_token || '';
    console.log('────────────────────────────────────────────────────────────');
    console.log(`[FLOW] 로그인 완료`);
    console.log(`  • 총 소요시간: ${ms(flowStart)}`);
    console.log(`  • 콜백 처리시간: ${ms(t_cb_start)}`);
    console.log(`  • 토큰 교환(token endpoint): ${ms(t_token_start, t_token_end)}`);
    console.log(`  • ID 토큰 길이: ${idToken.length} chars (~${(idToken.length/1024).toFixed(2)} KB)`);
    console.log(`  • ID 토큰 미리보기: ${maskToken(idToken)}`);
    console.log(`  • 주요 클레임 요약:`);
    console.log(`      sub: ${claims.sub}`);
    console.log(`      email: ${claims.email} (verified=${claims.email_verified})`);
    console.log(`      aud: ${claims.aud}`);
    console.log(`      iss: ${claims.iss}`);
    console.log(`      iat: ${claims.iat}, exp: ${claims.exp}`);
    console.log('────────────────────────────────────────────────────────────');

    res.redirect('/me');
  } catch (e) { next(e); }
});

// 내 정보(검증된 클레임)
app.get('/me', (req, res) => {
  if (!req.session?.idToken) {
    return res.status(401).send(`로그인 필요 (Mode ${currentMode}). <a href="/login">Login</a>`);
  }
  const { claims, idToken } = req.session;
  res.type('html').send(`
    <h3>ID Token (JWT/PS) - Mode ${currentMode}</h3>
    <p><strong>length</strong>: ${idToken.length} chars</p>
    <pre style="white-space:pre-wrap;word-break:break-all">${idToken}</pre>
    <h3>Verified Claims</h3>
    <pre>${JSON.stringify(claims, null, 2)}</pre>
    <p><a href="/">Home</a></p>
  `);
});

// --- PS Signature Verification Logic (RP side) ---
let idpPublicKeys = null;
let psParams = { g2: null };
// 브라우저가 IdP(4000)로 직접 크로스오리진 fetch를 안 하고도 PS 공개키를 얻을 수
// 있도록, 파싱 전 raw hex 응답을 그대로 보관해서 /api/mode2/idp_public_keys로
// same-origin 프록시한다.
let rawIdpPublicKeys = null;

let eddsa = null;
let poseidon = null;
async function ensureEdDSA() {
  if (!eddsa) eddsa = await buildEddsa();
  if (!poseidon) poseidon = await buildPoseidon();
}

async function initRP_PS() {
  try {
    await mcl.init(mcl.BN_SNARK1);
    console.log('[Mode 2] MCL Initialized');
    await ensureEdDSA();

    const response = await fetch(`${CUSTOM_IDP_BASE_URL}/ps_public_keys`);
    if (!response.ok) {
      throw new Error(`IdP Server not reachable (Status: ${response.status})`);
    }
    const data = await response.json();
    rawIdpPublicKeys = data;

    psParams.g2 = new mcl.G2();
    psParams.g2.setStr(data.g2, 16);
    
    idpPublicKeys = {
      X: new mcl.G2(),
      Y: data.Y.map(yStr => {
        const y = new mcl.G2();
        y.setStr(yStr, 16);
        return y;
      })
    };
    idpPublicKeys.X.setStr(data.X, 16);
    console.log('[Mode 2] IdP Public Keys loaded for PS Verification');
    return true;
  } catch (err) {
    console.warn('[Mode 2] Failed to initialize PS Verification:', err.message);
    console.warn(`         Ensure custom_idp.js is running at ${CUSTOM_IDP_BASE_URL}`);
    return false;
  }
}

function hashToFr(str) {
  const fr = new mcl.Fr();
  fr.setHashOf(str);
  return fr;
}

function verifyPS_Hybrid(sigma_prime, messages, idpPK) {
  try {
    if (!idpPK || !psParams.g2) return false;

    const s1 = new mcl.G1();
    const s2 = new mcl.G1();

    // 1. 서명 데이터 로드
    s1.setStr(sigma_prime.sigma1, 16);
    s2.setStr(sigma_prime.sigma2, 16);

    // 2. PK_total = X * prod(Yi^mi) — custom_idp.js psSign()이
    // 서명한 순서와 동일해야 한다.
    let PK_total = new mcl.G2();
    PK_total = mcl.add(idpPK.X, PK_total);
    for (let i = 0; i < messages.length; i++) {
      const mi = hashToFr(messages[i]);
      PK_total = mcl.add(PK_total, mcl.mul(idpPK.Y[i], mi));
    }

    // 3. e(s1, PK_total) == e(s2, g2)
    const lhs = mcl.pairing(s1, PK_total);
    const rhs = mcl.pairing(s2, psParams.g2);
    const isValid = lhs.isEqual(rhs);

    console.log('[Mode 2] PS Signature Verification:', isValid);
    return isValid;

  } catch (err) {
    console.error('[Mode 2] PS Signature Verification Error:', err.message);
    return false;
  }
}

// Mode 2: SSO Success Callback (Hybrid Version)
app.post('/api/mode2/sso_success', async (req, res) => {
  const { idpToken } = req.body;
  
  if (!idpToken) {
    return res.status(400).json({ success: false, error: 'Missing IdP token for RP verification' });
  }

  console.log('--- [RP Backend] Verifying IdP Token + RP Audience ---');

  try {
    assertDecimalString(idpToken.arid_i, 'idpToken.arid_i');
    assertDecimalString(idpToken.auid_i, 'idpToken.auid_i');
    assertDecimalString(idpToken.r_token, 'idpToken.r_token');
    assertDecimalString(idpToken.max_height, 'idpToken.max_height');
    assertDecimalString(idpToken.chain_id, 'idpToken.chain_id');
    if (!Array.isArray(idpToken.signature_prime?.R8) || idpToken.signature_prime.R8.length !== 2 || !idpToken.signature_prime?.S) {
      throw new Error('idpToken.signature_prime is missing or malformed');
    }
  } catch (err) {
    return res.status(400).json({ success: false, error: err.message });
  }

  // 0. RP 본인의 rid와 rp_nonce로 arid_i를 직접 재계산해서 검증 (Audience Check).
  // IdP는 rid를 모르므로 이 확인은 전적으로 RP 자신의 책임이다.
  if (!rpRegistration || !rpRegistration.rid) {
    return res.status(500).json({ success: false, error: 'RP is not properly registered yet' });
  }
  const sessionRpNonce = req.session.rpNonce;
  if (!sessionRpNonce) {
    return res.status(400).json({ success: false, error: 'No rp_nonce has been issued for this session yet' });
  }

  if (!idpPublicKeys || !psParams.g2) {
    console.log('[Mode 2] IdP public keys not loaded yet. Retrying before SSO verification...');
    await initRP_PS();
  }

  const expectedAridI = (valueToField(rpRegistration.rid) * valueToField(sessionRpNonce)) % FIELD_PRIME;
  if (String(idpToken.arid_i) !== String(expectedAridI)) {
    console.error(`❌ [RP Backend] Audience Check FAILED! arid_i does not match this RP's rid * rp_nonce.`);
    return res.status(403).json({ success: false, error: 'Security Alert: Wrong RP Identity (arid_i mismatch). Potential cross-service replay attack.' });
  }

  console.log('✅ [RP Backend] Audience Check PASSED (arid_i matches this RP\'s rid * rp_nonce).');

  try {
    const maxHeight = BigInt(idpToken.max_height);
    const currentHeight = await getCurrentHeightForToken(maxHeight);
    if (currentHeight.source !== 'unix-time') {
      const rpcChainId = await getRpcChainId();
      if (String(idpToken.chain_id) !== rpcChainId) {
        console.error('[RP Backend] chain_id check FAILED:', {
          token_chain_id: idpToken.chain_id,
          rpc_chain_id: rpcChainId,
          source: currentHeight.source,
        });
        return res.status(401).json({ success: false, error: 'IdP token chain_id does not match RP verification chain' });
      }
      console.log('[RP Backend] chain_id check PASSED:', {
        chain_id: rpcChainId,
        source: currentHeight.source,
      });
    }
    if (currentHeight.value > maxHeight) {
      console.error('[RP Backend] max_height check FAILED:', {
        current: currentHeight.value.toString(),
        max_height: maxHeight.toString(),
        source: currentHeight.source,
      });
      return res.status(401).json({ success: false, error: 'IdP token expired by max_height' });
    }
    console.log('[RP Backend] max_height check PASSED:', {
      current: currentHeight.value.toString(),
      max_height: maxHeight.toString(),
      source: currentHeight.source,
    });
  } catch (err) {
    console.error('[RP Backend] max_height verification error:', err.message);
    return res.status(503).json({ success: false, error: `Unable to verify max_height: ${err.message}` });
  }

  // EdDSA-Poseidon 검증 — custom_idp.js가 서명한 것과 동일하게 6개 필드를 Poseidon으로
  // 묶어서 msg를 재계산한 뒤, IdP의 pk_IdP로 검증한다.
  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const msgFields = [
    DOMAIN_IDP_TOKEN,
    valueToField(idpToken.arid_i),
    valueToField(idpToken.auid_i),
    valueToField(idpToken.r_token),
    valueToField(idpToken.max_height),
    valueToField(idpToken.chain_id),
  ];
  const msg = poseidon(msgFields);

  const pkIdPRaw = rawIdpPublicKeys?.pk_IdP;
  if (!pkIdPRaw || pkIdPRaw.length !== 2) {
    return res.status(503).json({ success: false, error: 'IdP EdDSA public key not loaded yet' });
  }
  let isSigValid;
  try {
    const pkIdP = [eddsa.F.e(BigInt(pkIdPRaw[0])), eddsa.F.e(BigInt(pkIdPRaw[1]))];
    const sigForVerify = {
      R8: [eddsa.F.e(BigInt(idpToken.signature_prime.R8[0])), eddsa.F.e(BigInt(idpToken.signature_prime.R8[1]))],
      S: BigInt(idpToken.signature_prime.S),
    };

    isSigValid = eddsa.verifyPoseidon(msg, sigForVerify, pkIdP);
  } catch (err) {
    return res.status(400).json({ success: false, error: 'Malformed EdDSA-Poseidon signature data' });
  }

  if (!isSigValid) {
    return res.status(401).json({ success: false, error: 'Invalid EdDSA-Poseidon Signature' });
  }

  // B2 추적용: rp_nonce를 지우기 전에 나중에 재계산 가능하도록 세션 기록을 남긴다.
  sessionLog.push({
    auid_i: idpToken.auid_i,
    r_token: idpToken.r_token,
    rp_nonce: sessionRpNonce,
    timestamp: Date.now(),
  });

  // Single-use: spend the rp_nonce only after the full RP-side verification
  // succeeds, so malformed proof/signature attempts do not burn the session.
  delete req.session.rpNonce;

  console.log('[Mode 2] Verification SUCCESS. Session established.');
  res.json({ success: true });
});

// 로그아웃
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// API 엔드포인트: ID 토큰 및 클레임 반환
app.get('/api/id_token', (req, res) => {
  if (!req.session?.idToken || !req.session?.claims) {
    return res.status(401).json({ error: 'Not logged in or claims not available' });
  }
  res.json({
    idToken: req.session.idToken,
    claims: req.session.claims,
  });
});

// API 엔드포인트: 감사자 키로 데이터 암호화 (ECIES)
app.post('/api/encrypt', async (req, res, next) => {
  try {
    const { plaintext } = req.body;
    if (typeof plaintext !== 'string' || !plaintext) {
      return res.status(400).json({ error: 'plaintext (string) is required.' });
    }

    // 1. 감사자 공개키 로드
    const auditorKeysContent = await fs.readFile('auditor_keys.json', 'utf-8');
    const auditorKeys = JSON.parse(auditorKeysContent);
    const auditorPkHex = auditorKeys.AUDITOR_PK;

    // 2. ECIES 구현
    // 2a. 임시 키 쌍 생성
    const ephemeralSk = secp256k1.utils.randomPrivateKey();
    const ephemeralPk = secp256k1.getPublicKey(ephemeralSk); // 65-byte uncompressed

    // 2b. 공유 비밀 생성 (ECDH)
    const sharedSecret = secp256k1.getSharedSecret(ephemeralSk, auditorPkHex);
    const hashedSharedSecret = sha256(sharedSecret.slice(1)); // Use X-coordinate

    // 2c. 대칭 암호화 키 유도 (HKDF)
    const encryptionKey = hkdf(sha256, hashedSharedSecret, '', 'aes-256-gcm-key', 32);

    // 2d. AES-256-GCM으로 암호화
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);
    const plaintextBytes = new TextEncoder().encode(plaintext);
    const encrypted = Buffer.concat([cipher.update(plaintextBytes), cipher.final()]);
    const tag = cipher.getAuthTag();

    // 3. ECIES 표준에 따라 암호문 조합: 임시공개키 + IV + 인증태그 + 암호문
    const ciphertext = Buffer.concat([
      Buffer.from(ephemeralPk),
      iv,
      tag,
      encrypted,
    ]);

    res.json({ ciphertext: ciphertext.toString('hex') });

  } catch (err) {
    // 키 파일이 없는 경우 등의 에러 처리
    if (err.code === 'ENOENT') {
      console.error('[ERROR] /api/encrypt: auditor_keys.json not found. Please run generate_auditor_keys.js first.');
      return res.status(500).json({ error: 'Auditor keys are not configured on the server.' });
    }
    next(err);
  }
});


// 에러 핸들러
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);
  res.status(500).send(`<pre>${err.message}</pre>`);
});

// Mode 2: B2 추적 엔드포인트 — 분쟁 중인 온체인 트랜잭션의 공개 pk_i/max_height로
// sessionLog에서 일치하는 r_token을 찾고, Task 1의 custom_idp.js 엔드포인트에
// 위임해서 uid를 밝힌다.
app.post('/api/mode2/trace_transaction', async (req, res) => {
  const { pk_i, max_height } = req.body ?? {};
  if (!pk_i) return res.status(400).json({ error: 'pk_i is required' });
  if (!max_height) return res.status(400).json({ error: 'max_height is required' });

  await ensureEdDSA();
  if (!poseidon) return res.status(503).json({ error: 'Poseidon not initialized yet' });

  const pkField = valueToField(pk_i);
  const maxHeightField = valueToField(max_height);

  const match = sessionLog.find((record) => {
    const rpNonceField = valueToField(record.rp_nonce);
    const recomputed = poseidon.F.toObject(poseidon([pkField, maxHeightField, rpNonceField]));
    return String(recomputed) === String(record.r_token);
  });

  if (!match) {
    return res.status(404).json({ error: 'No matching session found for this pk_i/max_height' });
  }

  try {
    const idpResponse = await fetch(`${CUSTOM_IDP_BASE_URL}/idp/lookup_uid_by_r_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ r_token: match.r_token }),
    });
    const idpResult = await idpResponse.json();
    if (!idpResponse.ok) {
      return res.status(idpResponse.status).json(idpResult);
    }
    res.json({ uid: idpResult.uid });
  } catch (err) {
    res.status(502).json({ error: `Failed to reach IdP for uid lookup: ${err.message}` });
  }
});

app.post('/api/mode2/relay_transaction', async (req, res) => {
  const { deploy, to, data } = req.body ?? {};
  if (!to) return res.status(400).json({ error: 'to is required' });
  if (!data) return res.status(400).json({ error: 'data is required' });
  if (deploy && (!deploy.to || !deploy.data)) {
    return res.status(400).json({ error: 'deploy.to and deploy.data are required when deploy is present' });
  }

  try {
    const accounts = await rpcCall('eth_accounts', []);
    const from = accounts?.[0];
    if (!from) throw new Error('No unlocked account available from RPC node');

    if (deploy) {
      await relaySingleCall(from, deploy);
    }
    const txHash = await relaySingleCall(from, { to, data });

    res.json({ txHash });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

const server = app.listen(PORT, async () => {
  if (currentMode === 2) {
    await initRP_PS();
  }
  console.log(`OIDC demo running at ${BASE_URL}`);
});

// Mode 2: Provide RP registration info to the client
app.get('/api/mode2/rp_info', (req, res) => {
  if (currentMode !== 2 || !rpRegistration) {
    return res.status(404).json({ error: 'RP registration not found or not in Mode 2' });
  }
  res.json(rpRegistration);
});

// Mode 2: Proxy the IdP's PS public keys so the browser never has to make a
// direct cross-origin request to the IdP (avoids leaking the RP's origin via
// the Origin header on that request).
app.get('/api/mode2/idp_public_keys', (req, res) => {
  if (currentMode !== 2 || !rawIdpPublicKeys) {
    return res.status(404).json({ error: 'IdP public keys not loaded or not in Mode 2' });
  }
  res.json(rawIdpPublicKeys);
});
