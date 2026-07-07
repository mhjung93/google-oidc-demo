import express from 'express';
import cors from 'cors';
import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { webcrypto } from 'crypto';

const { subtle } = webcrypto;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.WALLET_AGENT_PORT || 5001;
const RP_ORIGIN = process.env.RP_ORIGIN || 'http://127.0.0.1:3000';
const STATE_FILE = path.join(__dirname, 'wallet_state.json');

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// client.js의 valueToField()/bytesToHex()와 동일한 필드 축소 규칙.
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

function now() { return Date.now(); }
function cursor() { return { last: now() }; }
function ms(c) {
  const t = now();
  const delta = t - c.last;
  c.last = t;
  return `${delta.toFixed(0)} ms`;
}
function preview(value, maxChars = 40) {
  if (value === undefined || value === null) return 'n/a';
  const str = typeof value === 'string' ? value : JSON.stringify(value);
  return str.length > maxChars ? `${str.slice(0, maxChars)}...` : str;
}

function readState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  } catch {
    return {};
  }
}

// state 파일에는 지갑 salt와 인증 토큰이 들어있으므로 소유자만 읽고 쓸 수 있게 한다.
function writeState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
  try {
    fs.chmodSync(STATE_FILE, 0o600);
  } catch {
    // best-effort; writeFileSync's mode already covers the common case.
  }
}

// 지갑 salt: 이 로컬 프로세스만 접근 가능한 파일에 보관하고, 최초 1회 생성 후 재사용한다.
function getOrCreateWalletSalt() {
  const state = readState();
  if (!state.mode2WalletSalt) {
    const bytes = webcrypto.getRandomValues(new Uint8Array(32));
    state.mode2WalletSalt = `0x${bytesToHex(bytes)}`;
    writeState(state);
  }
  return state.mode2WalletSalt;
}

// 인증 토큰: RP_ORIGIN 자신(server.js)만 이 파일을 직접 읽어서 브라우저 페이지에
// 전달할 수 있다 — CORS는 브라우저가 아닌 호출자(curl, 다른 로컬 프로세스, LAN의
// 다른 머신)를 막지 못하므로, 토큰 없이는 /generateStep8Proofs를 아무도 호출하지
// 못하게 해서 salt 추출(uid=1, rid=1 등으로 ppid=salt를 뽑아내는 것)을 막는다.
function getOrCreateAgentToken() {
  const state = readState();
  if (!state.agentToken) {
    const bytes = webcrypto.getRandomValues(new Uint8Array(32));
    state.agentToken = bytesToHex(bytes);
    writeState(state);
  }
  return state.agentToken;
}

const app = express();
app.use(cors({ origin: RP_ORIGIN }));
app.use(express.json());

app.use((req, res, next) => {
  const provided = req.get('X-Wallet-Agent-Token');
  if (!provided || provided !== getOrCreateAgentToken()) {
    console.warn(`[WalletAgent] Rejected request to ${req.path}: missing or invalid X-Wallet-Agent-Token`);
    return res.status(401).json({ error: 'Missing or invalid wallet agent token' });
  }
  next();
});

// Step 8을 대신 수행한다: PPID/arid_i/auid_i 계산, 세션 서명키 생성, Poseidon
// 토큰 논스, pi_i/pi_PPID Groth16 증명 생성. 이 프로세스는 사용자 로컬 머신에서만
// 돌고 RP_ORIGIN에서만 접근 가능하다 — RP 페이지(client.js)의 JS 컨텍스트와는
// 별도의 OS 프로세스라서, uid/salt/rid 같은 값이 RP 페이지에 직접 노출되지 않는다.
app.post('/generateStep8Proofs', async (req, res) => {
  const requestStart = now();
  const start = cursor();
  try {
    const { uid, rpCredential, r_i, rpNonce, maxHeight, chainId } = req.body ?? {};
    console.log(`--- [WalletAgent][Step 8] generateStep8Proofs request received ---`);
    console.log(`[WalletAgent][Step 8] rid: ${preview(rpCredential?.rid)}, r_i: ${preview(r_i)}, maxHeight: ${preview(maxHeight)}, chainId: ${preview(chainId)}`);

    if (uid == null) throw new Error('uid is required');
    if (!rpCredential?.rid) throw new Error('rpCredential.rid is required');
    if (!r_i) throw new Error('r_i is required');
    if (!rpNonce) throw new Error('rpNonce is required');
    if (!maxHeight) throw new Error('maxHeight is required');
    if (!chainId) throw new Error('chainId is required');

    const walletSalt = getOrCreateWalletSalt();
    const uidField = valueToField(uid);
    const saltField = valueToField(walletSalt);
    const rid = BigInt(rpCredential.rid);
    const rpNonceField = valueToField(rpNonce);

    // PPID = uid * rid * salt, arid_i = rid * rp_nonce, auid_i = PPID * rp_nonce
    const ppid = (uidField * rid * saltField) % FIELD_PRIME;
    const arid_i = (rid * rpNonceField) % FIELD_PRIME;
    const auid_i = (ppid * rpNonceField) % FIELD_PRIME;
    console.log(`[WalletAgent][Step 8] PPID/arid_i/auid_i computed ${ms(start)}`);

    // 세션 서명키는 이 프로세스 안에서만 생성하고, pk_i(공개 필드값)만 내보낸다.
    const signingKeyPair = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const publicKeyRaw = new Uint8Array(await subtle.exportKey('raw', signingKeyPair.publicKey));
    const publicKeyHex = `0x${bytesToHex(publicKeyRaw)}`;
    const pkField = valueToField(publicKeyHex);
    console.log(`[WalletAgent][Step 8] signing key pair generated. publicKey: ${preview(publicKeyHex, 34)} ${ms(start)}`);

    const maxHeightField = valueToField(maxHeight);

    const poseidon = await buildPoseidon();
    const tokenNonce = poseidon.F.toObject(poseidon([pkField, maxHeightField, rpNonceField]));
    console.log(`[WalletAgent][Step 8] token nonce (Poseidon) generated ${ms(start)}`);

    const aridInputs = {
      rp_nonce: rpNonceField.toString(),
      salt: saltField.toString(),
      rid: rid.toString(),
      pk_i: pkField.toString(),
      uid: uidField.toString(),
      arid_i: arid_i.toString(),
      auid_i: auid_i.toString(),
      max_height: maxHeightField.toString(),
      token_nonce: tokenNonce.toString(),
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      aridInputs,
      'build/mode2/pi_arid_i_js/pi_arid_i.wasm',
      'build/mode2/pi_arid_i_final.zkey',
    );
    console.log(`[WalletAgent][Step 8] pi_i (pi_arid_i) proof generated. publicSignals[0]: ${preview(publicSignals[0])} ${ms(start)}`);

    const ppidInputs = {
      uid: uidField.toString(),
      salt: saltField.toString(),
      rid: rid.toString(),
      ppid: ppid.toString(),
    };
    const { proof: ppidProof, publicSignals: ppidPublicSignals } = await snarkjs.groth16.fullProve(
      ppidInputs,
      'build/mode2/pi_ppid_js/pi_ppid.wasm',
      'build/mode2/pi_ppid_final.zkey',
    );
    console.log(`[WalletAgent][Step 8] pi_PPID proof generated ${ms(start)}`);

    const durationMs = now() - requestStart;
    console.log(`✅ [WalletAgent][Step 8] All proofs ready, responding to RP FE ${ms(start)}`);

    res.json({
      rid: rid.toString(),
      ppid: ppid.toString(),
      rpNonceField: rpNonceField.toString(),
      arid_i: arid_i.toString(),
      auid_i: auid_i.toString(),
      maxHeight: maxHeightField.toString(),
      tokenNonce: tokenNonce.toString(),
      publicKeyHex,
      zkpProof: proof,
      zkpPublicSignals: publicSignals,
      pi_PPID: {
        type: 'pi_PPID',
        proof: ppidProof,
        publicSignals: ppidPublicSignals, // [rid, ppid], per circuit's public [rid, ppid]
        r_token: tokenNonce.toString(),
        generatedAt: new Date().toISOString(),
      },
      walletSubmission: {
        auid_i: auid_i.toString(),
        arid_i: arid_i.toString(),
        r_token: tokenNonce.toString(),
        pi_i: proof,
        r_i,
      },
      business: {
        arid_i: arid_i.toString(),
        auid_i: auid_i.toString(),
        r_i,
        r_token: tokenNonce.toString(),
        tokenNonce: tokenNonce.toString(),
        maxHeight: maxHeightField.toString(),
        chain_id: chainId,
      },
      durationMs,
    });
  } catch (err) {
    console.error(`❌ [WalletAgent][Step 8] generateStep8Proofs error: ${err.message} ${ms(start)}`);
    res.status(400).json({ error: err.message });
  }
});

// 토큰은 첫 요청을 기다리지 않고 기동 시점에 바로 만들어둔다 — server.js의
// /api/mode2/wallet_agent_token이 이 프로세스에 요청이 오기 전에도 파일을
// 읽을 수 있어야 하기 때문이다 (닭이 먼저냐 달걀이 먼저냐 문제 방지).
getOrCreateAgentToken();

app.listen(PORT, '127.0.0.1', () => {
  console.log(`[WalletAgent] Local wallet-side Step 8 agent listening on http://127.0.0.1:${PORT}`);
  console.log(`[WalletAgent] Accepting requests only from RP origin: ${RP_ORIGIN}`);
  console.log(`[WalletAgent] Requires X-Wallet-Agent-Token header (see wallet_state.json).`);
});
