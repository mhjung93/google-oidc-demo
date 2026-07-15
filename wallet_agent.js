import express from 'express';
import cors from 'cors';
import * as snarkjs from 'snarkjs';
import { buildPoseidon, buildEddsa } from 'circomlibjs';
import mcl from 'mcl-wasm';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { webcrypto } from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256, AbiCoder } from 'ethers';

const { subtle } = webcrypto;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.WALLET_AGENT_PORT || 5001;
const RP_ORIGIN = process.env.RP_ORIGIN || 'http://127.0.0.1:3000';
const IDP_ORIGIN = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';
const MODE2_ETH_RPC_URL = process.env.MODE2_ETH_RPC_URL || process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';
const STATE_FILE = path.join(__dirname, 'wallet_state.json');
let poseidon = null;
let eddsa = null;
async function ensureEdDSA() {
  if (!eddsa) eddsa = await buildEddsa();
  return eddsa;
}

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const TOKEN_VALIDITY_SECONDS = 3600n;
const ETHEREUM_SLOT_SECONDS = 12n;

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

function validityWindowBlocks() {
  return (TOKEN_VALIDITY_SECONDS + ETHEREUM_SLOT_SECONDS - 1n) / ETHEREUM_SLOT_SECONDS;
}

async function rpcCall(method, params = []) {
  const response = await fetch(MODE2_ETH_RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method,
      params,
    }),
  });

  if (!response.ok) {
    throw new Error(`${method} RPC failed with status ${response.status}`);
  }

  const data = await response.json();
  if (data.error || typeof data.result !== 'string') {
    throw new Error(data.error?.message || `${method} RPC returned no result`);
  }
  return data.result;
}

async function getMaxHeight() {
  const chainIdHex = await rpcCall('eth_chainId');
  const blockHex = await rpcCall('eth_blockNumber');
  const currentBlock = BigInt(blockHex);
  return {
    chainId: BigInt(chainIdHex).toString(),
    currentBlock,
    maxHeight: currentBlock + validityWindowBlocks(),
    source: MODE2_ETH_RPC_URL,
  };
}

// custom_idp.js의 psSign() / server.js의 PS 서명 검증식과 동일하다.
// wallet_agent.js가 RP로부터 받은 rid가 정말 이 IdP가 psSign(['RP_REG', rid, origin])로
// 서명해서 발급한 값인지 확인한다. origin이 서명 대상에 포함돼 있으므로, 서명
// 검증을 통과했다면 "이 rid는 이 origin 것"이라는 것까지 IdP가 보증한 것이다.
// verifyRpCredential이 이어서 그 서명된 origin을 wallet_agent.js 자신의
// 신뢰 앵커인 RP_ORIGIN과 대조해서, RP FE(client.js)가 다른(피해자) RP의
// 정상 발급 rid를 몰래 끼워 넣는 것(A7, blind-message attack)을 막는다.
let mclReady = null;
function ensureMcl() {
  if (!mclReady) mclReady = mcl.init(mcl.BN_SNARK1);
  return mclReady;
}

function hashToFr(str) {
  const fr = new mcl.Fr();
  fr.setHashOf(str);
  return fr;
}

function verifyPSSignature(sigma, messages, idpPK) {
  try {
    const s1 = new mcl.G1();
    s1.setStr(sigma.sigma1, 16);
    const s2 = new mcl.G1();
    s2.setStr(sigma.sigma2, 16);

    let PK_total = new mcl.G2();
    const X = new mcl.G2();
    X.setStr(idpPK.X, 16);
    PK_total = mcl.add(X, PK_total);
    for (let i = 0; i < messages.length; i++) {
      const Yi = new mcl.G2();
      Yi.setStr(idpPK.Y[i], 16);
      const mi = hashToFr(messages[i]);
      PK_total = mcl.add(PK_total, mcl.mul(Yi, mi));
    }

    const g2 = new mcl.G2();
    g2.setStr(idpPK.g2, 16);
    const lhs = mcl.pairing(s1, PK_total);
    const rhs = mcl.pairing(s2, g2);
    return lhs.isEqual(rhs);
  } catch (err) {
    console.error(`[WalletAgent] RP credential signature check error: ${err.message}`);
    return false;
  }
}

let idpPublicKeysCache = null;
async function getIdpPublicKeys() {
  if (idpPublicKeysCache) return idpPublicKeysCache;
  const response = await fetch(`${IDP_ORIGIN}/ps_public_keys`);
  if (!response.ok) throw new Error(`Failed to fetch IdP public keys (${response.status})`);
  idpPublicKeysCache = await response.json();
  return idpPublicKeysCache;
}

async function verifyRpCredential(rpCredential) {
  await ensureMcl();
  const idpPublicKeys = await getIdpPublicKeys();
  const isValid = verifyPSSignature(
    rpCredential.signature,
    ['RP_REG', String(rpCredential.rid), String(rpCredential.origin)],
    idpPublicKeys,
  );
  if (!isValid) {
    throw new Error('RP credential signature verification failed: this rid/origin pair was not issued by the trusted IdP');
  }
  if (rpCredential.origin !== RP_ORIGIN) {
    throw new Error(
      `RP credential origin mismatch: credential is bound to ${rpCredential.origin}, but this wallet only trusts ${RP_ORIGIN}`,
    );
  }
}

// snap/src/index.js의 assertTokenMatchesWalletSubmission()을 그대로 이식 — Step 12가
// Snap에서 여기로 옮겨오면서, 토큰 필드가 Step 8에서 지갑이 실제로 제출한 값과
// 일치하는지 대조하는 로직도 같이 옮겨온다.
function assertTokenMatchesWalletSubmission(token, walletSubmission, business) {
  const checks = {
    aridOk: String(token.arid_i) === String(walletSubmission?.arid_i ?? business?.arid_i),
    auidOk: String(token.auid_i) === String(walletSubmission?.auid_i ?? business?.auid_i),
    tokenNonceOk: String(token.r_token) === String(walletSubmission?.r_token ?? business?.r_token ?? business?.tokenNonce),
    maxHeightOk: String(token.max_height) === String(business?.maxHeight ?? business?.max_height),
    chainIdOk: String(token.chain_id) === String(business?.chain_id ?? business?.chainId),
  };
  const success = checks.aridOk && checks.auidOk && checks.tokenNonceOk && checks.maxHeightOk && checks.chainIdOk;
  return { success, checks };
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

// pk_i의 이더리움 주소 계산 — 65바이트(0x04 prefix) 비압축 공개키에서 프리픽스를 떼고
// keccak256(X||Y)의 마지막 20바이트를 취한다. 표준 이더리움 주소 유도 공식.
function ethAddressFromSecp256k1Pubkey(pubKeyUncompressed65) {
  const xy = pubKeyUncompressed65.slice(1);
  const hash = keccak256(xy);
  return '0x' + hash.slice(-40);
}

// 세션 서명키(pk_i/sk_i): P-256 대신 secp256k1을 쓴다 — 이유는 PPIDWallet 컨트랙트가
// payload 서명을 회로 밖에서 ecrecover로 직접 검증하기 때문(온체인 ecrecover는
// secp256k1 전용). WebCrypto의 SubtleCrypto는 secp256k1을 지원하지 않으므로
// @noble/curves를 쓴다. 로그인 시점(Step 8)에 한 번 생성해서 state 파일에 저장해두고,
// 이후 트랜잭션 제출 단계(다른 HTTP 요청)에서 같은 키를 재사용한다 — 그전엔 이 키가
// 요청 하나 처리 후 버려졌었는데, payload 서명을 나중에 또 해야 하므로 영속화가
// 필요해졌다.
function getOrCreateSessionKey() {
  const state = readState();
  if (!state.mode2SessionKey) {
    const sk_i = secp256k1.utils.randomPrivateKey();
    state.mode2SessionKey = bytesToHex(sk_i);
    writeState(state);
  }
  const sk_i = Uint8Array.from(Buffer.from(state.mode2SessionKey, 'hex'));
  const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
  const address = ethAddressFromSecp256k1Pubkey(pubUncompressed);
  return { sk_i, pk_i: BigInt(address), address, publicKeyHex: `0x${bytesToHex(pubUncompressed)}` };
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
    const { uid, rpCredential, r_i, rpNonce } = req.body ?? {};
    console.log(`--- [WalletAgent][Step 8] generateStep8Proofs request received ---`);
    console.log(`[WalletAgent][Step 8] rid: ${preview(rpCredential?.rid)}, r_i: ${preview(r_i)}`);

    if (uid == null) throw new Error('uid is required');
    if (!rpCredential?.rid) throw new Error('rpCredential.rid is required');
    if (!rpCredential?.signature) throw new Error('rpCredential.signature is required');
    if (!r_i) throw new Error('r_i is required');
    if (!rpNonce) throw new Error('rpNonce is required');

    await verifyRpCredential(rpCredential);
    console.log(`[WalletAgent][Step 8] RP credential signature verified ${ms(start)}`);

    const heightInfo = await getMaxHeight();
    const maxHeight = heightInfo.maxHeight;
    console.log(`[WalletAgent][Step 8] chain_id/max_height computed: chainId=${heightInfo.chainId}, currentBlock=${heightInfo.currentBlock.toString()}, maxHeight=${maxHeight.toString()} ${ms(start)}`);

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

    // 세션 서명키: secp256k1, wallet_state.json에 영속화됨 (getOrCreateSessionKey 참고).
    // pk_i는 이제 공개키 블롭의 해시가 아니라 그 공개키의 이더리움 주소 자체다.
    const { pk_i: pkField, publicKeyHex } = getOrCreateSessionKey();
    console.log(`[WalletAgent][Step 8] session key ready. address(pk_i): ${preview(publicKeyHex, 34)} ${ms(start)}`);

    const maxHeightField = valueToField(maxHeight);

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
    console.log(`[WalletAgent][Step 8] pi_i (pi_arid_i) proof generated ${ms(start)}`);

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
      currentBlock: heightInfo.currentBlock.toString(),
      chain_id: heightInfo.chainId,
      heightSource: heightInfo.source,
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
        chain_id: heightInfo.chainId,
      },
      durationMs,
    });
  } catch (err) {
    console.error(`❌ [WalletAgent][Step 8] generateStep8Proofs error: ${err.message} ${ms(start)}`);
    res.status(400).json({ error: err.message });
  }
});

app.post('/verifyIdPAuthToken', async (req, res) => {
  const start = cursor();
  const verifyStart = now();
  try {
    const { idpToken, walletSubmission, business } = req.body ?? {};
    if (!idpToken) throw new Error('idpToken is required');

    await ensureEdDSA();
    if (!poseidon) throw new Error('Poseidon not initialized yet');

    const idpPublicKeys = await getIdpPublicKeys();
    const pkIdPRaw = idpPublicKeys?.pk_IdP;
    if (!pkIdPRaw || pkIdPRaw.length !== 2) throw new Error('IdP EdDSA public key not available');

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
    const pkIdP = [eddsa.F.e(BigInt(pkIdPRaw[0])), eddsa.F.e(BigInt(pkIdPRaw[1]))];
    const sig = idpToken.signature ?? {};
    if (!Array.isArray(sig.R8) || sig.R8.length !== 2 || !sig.S) {
      throw new Error('idpToken.signature is missing or malformed');
    }
    const sigForVerify = {
      R8: [eddsa.F.e(BigInt(sig.R8[0])), eddsa.F.e(BigInt(sig.R8[1]))],
      S: BigInt(sig.S),
    };

    let accepted = eddsa.verifyPoseidon(msg, sigForVerify, pkIdP);
    const binding = assertTokenMatchesWalletSubmission(idpToken, walletSubmission, business);
    accepted = accepted && binding.success;
    const message = accepted
      ? 'EdDSA-Poseidon signature and Wallet bindings verified'
      : 'EdDSA-Poseidon signature or Wallet binding verification failed';

    console.log(`[WalletAgent][Step 12] verifyIdPAuthToken: ${accepted ? 'PASS' : 'FAIL'} ${ms(start)}`);
    res.json({ success: accepted, message, checks: binding.checks, durationMs: now() - verifyStart });
  } catch (err) {
    console.error(`[WalletAgent][Step 12] verifyIdPAuthToken error: ${err.message} ${ms(start)}`);
    res.status(400).json({ success: false, message: err.message, checks: {}, durationMs: now() - verifyStart });
  }
});

// B1(PPID 트랜잭션 제출): payload에 세션키(pk_i/sk_i)로 서명하고, Step 12에서 검증했던
// EdDSA-Poseidon 인증 토큰 서명을 회로 안에서 다시 검증하는 pi_pk_i 증명을 생성한다.
// payloadHash는 PPIDWallet.sol의 execute()가 계산하는
// keccak256(abi.encode(to, value, data, nonce))와 정확히 같은 방식으로 계산해야
// 컨트랙트의 ecrecover가 세션키 주소(pk_i)를 그대로 복구할 수 있다.
app.post('/submitTransaction', async (req, res) => {
  const start = cursor();
  try {
    const { to, value, data, currentNonce, business, rpNonce } = req.body ?? {};
    if (!to) throw new Error('to is required');
    if (value === undefined) throw new Error('value is required');
    if (currentNonce === undefined) throw new Error('currentNonce is required');
    if (!business?.arid_i || !business?.auid_i) throw new Error('business.arid_i/auid_i are required');
    if (business?.PPID === undefined && business?.ppid === undefined) throw new Error('business.PPID/ppid is required');
    if (!rpNonce) throw new Error('rpNonce is required');

    await ensureEdDSA();
    if (!poseidon) throw new Error('Poseidon not initialized yet');

    const idpPublicKeys = await getIdpPublicKeys();
    const pkIdPRaw = idpPublicKeys?.pk_IdP;
    if (!pkIdPRaw || pkIdPRaw.length !== 2) throw new Error('IdP EdDSA public key not available');

    // sigma_i (인증 토큰 자체의 EdDSA-Poseidon 서명)도 요청 본문에서 받는다 —
    // 클라이언트는 walletReceivedIdPToken.signature.{R8,S}로 이미 갖고 있다.
    // circuitInput 조립보다 먼저 검사해서, S/R8x/R8y가 빈 값인 채로
    // snarkjs.groth16.fullProve가 호출되지 않도록 한다.
    const idpTokenSig = req.body?.idpToken?.signature;
    if (!idpTokenSig?.R8 || !idpTokenSig?.S) throw new Error('idpToken.signature is required');

    const { sk_i, pk_i } = getOrCreateSessionKey();

    const payloadData = data ?? '0x';
    const payload = { to, value: value.toString(), data: payloadData, nonce: currentNonce.toString() };

    const payloadHash = keccak256(
      AbiCoder.defaultAbiCoder().encode(
        ['address', 'uint256', 'bytes', 'uint256'],
        [payload.to, payload.value, payload.data, payload.nonce],
      ),
    );
    const sigRaw = secp256k1.sign(payloadHash.slice(2), sk_i);
    const sig =
      '0x' +
      sigRaw.r.toString(16).padStart(64, '0') +
      sigRaw.s.toString(16).padStart(64, '0') +
      (27 + sigRaw.recovery).toString(16).padStart(2, '0');

    const rp_nonce = valueToField(rpNonce);
    const arid_i = valueToField(business.arid_i);
    const auid_i = valueToField(business.auid_i);
    const r_token = valueToField(business.r_token ?? business.tokenNonce);
    const chain_id = valueToField(business.chain_id ?? business.chainId);
    const maxHeightField = valueToField(business.maxHeight ?? business.max_height);

    const pkIdP_x = BigInt(pkIdPRaw[0]);
    const pkIdP_y = BigInt(pkIdPRaw[1]);

    const circuitInput = {
      rp_nonce: rp_nonce.toString(),
      arid_i: arid_i.toString(),
      auid_i: auid_i.toString(),
      r_token: r_token.toString(),
      chain_id: chain_id.toString(),
      S: idpTokenSig.S,
      R8x: idpTokenSig.R8[0],
      R8y: idpTokenSig.R8[1],
      pk_i: pk_i.toString(),
      pk_IdP_x: pkIdP_x.toString(),
      pk_IdP_y: pkIdP_y.toString(),
      PPID: valueToField(business.PPID ?? business.ppid).toString(),
      max_height: maxHeightField.toString(),
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      'build/mode2/pi_pk_i_js/pi_pk_i.wasm',
      'build/mode2/pi_pk_i_final.zkey',
    );
    const calldata = JSON.parse(`[${await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)}]`);
    const [proofA, proofB, proofC] = calldata;

    console.log(`[WalletAgent][submitTransaction] proof generated ${ms(start)}`);
    res.json({
      payload,
      sig,
      proofA,
      proofB,
      proofC,
      pk_i: pk_i.toString(),
      pk_IdP_x: pkIdP_x.toString(),
      pk_IdP_y: pkIdP_y.toString(),
      max_height: maxHeightField.toString(),
    });
  } catch (err) {
    console.error(`[WalletAgent][submitTransaction] error: ${err.message} ${ms(start)}`);
    res.status(400).json({ error: err.message });
  }
});

// 토큰은 첫 요청을 기다리지 않고 기동 시점에 바로 만들어둔다 — server.js의
// /api/mode2/wallet_agent_token이 이 프로세스에 요청이 오기 전에도 파일을
// 읽을 수 있어야 하기 때문이다 (닭이 먼저냐 달걀이 먼저냐 문제 방지).
getOrCreateAgentToken();

try {
  console.log('[WalletAgent] Initializing Poseidon...');
  poseidon = await buildPoseidon();
  console.log('[WalletAgent] Poseidon initialized.');

  // custom_idp.js/server.js처럼 기동 시점에 미리 만들어둔다 — 안 그러면 첫
  // Step 12 요청이 buildEddsa()의 무거운 WASM 초기화(Poseidon 외에도
  // pedersenHash/mimc7/mimcSponge까지 같이 빌드됨) 비용을 그대로 떠안는다.
  console.log('[WalletAgent] Initializing EdDSA-Poseidon...');
  await ensureEdDSA();
  console.log('[WalletAgent] EdDSA-Poseidon initialized.');

  app.listen(PORT, '127.0.0.1', () => {
    console.log(`[WalletAgent] Local wallet-side Step 8 agent listening on http://127.0.0.1:${PORT}`);
    console.log(`[WalletAgent] Accepting requests only from RP origin: ${RP_ORIGIN}`);
    console.log(`[WalletAgent] Requires X-Wallet-Agent-Token header (see wallet_state.json).`);
  });
} catch (err) {
  console.error(`[WalletAgent] Failed to initialize Poseidon/EdDSA: ${err.message}`);
  process.exit(1);
}
