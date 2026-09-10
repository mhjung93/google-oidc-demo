// Mode 3 CIA (Credential Issuing Authority).
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §3, §6
//
// Mode 2 의 custom_idp.js 와 나란히 두는 별도 서버다(:4100). 그쪽 코드를 import 하지 않는다.
// 하는 일 넷: 등록(§6.1), 발급(§6.2), 폐기(§6.5), root 게시(§6.5). 로그인 검증은 하지 않는다 —
// 그것은 RP 의 일이고(§6.3) CIA 는 조회 경로에 있어서는 안 된다(§9.9).
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { readJson, writeJsonAtomic } from './lib/mode3_state.js';
import { credMessage, compressPoint } from './lib/mode3_credential.js';
import { credLeaf, createRevocationTree } from './lib/mode3_revocation.js';
import { verifyIssuance, pointFromStrings, parseProof } from './lib/mode3_issuance.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.CIA_PORT) || 4100;
const STATE_FILE = process.env.CIA_STATE_FILE || path.join(__dirname, 'cia_state.json');
const KEYS_FILE = process.env.CIA_KEYS_FILE || path.join(__dirname, 'cia_keys.json');
const ADMIN_SECRET = process.env.CIA_ADMIN_SECRET;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const TTL_BLOCKS = Number(process.env.CIA_TTL_BLOCKS) || 300;

const DOMAIN_ROOT = ethers.keccak256(ethers.toUtf8Bytes('MODE3_REVOCATION_ROOT_V1'));
const LOG_ABI = [
  'function root() view returns (bytes32)',
  'function epoch() view returns (uint64)',
  'function publishRoot(bytes32 newRoot, uint64 newEpoch, bytes32[] leaves, bytes sig)',
];

// 데모 계정. Mode 2 의 testuser 관례를 따른 프로토타입이다 — 실제 계정 체계가 아니다.
const DEMO_ACCOUNTS = {
  testuser: { password: 'password123', uid: '12345' },
  alice: { password: 'alicepw', uid: '67890' },
};

// ---- 키 ----
// EdDSA-Poseidon(credential 서명)과 secp256k1(root 게시) 둘. 파일은 0600.
let eddsa, poseidon, F;
let ciaPrv;        // Buffer 32 — signPoseidon 이 요구하는 형식
let ciaPub;        // [Ax, Ay]
let ethWallet;     // ethers.Wallet

function loadOrCreateKeys() {
  let keys = readJson(KEYS_FILE, null);
  if (!keys) {
    keys = { eddsaPrv: randomBytes(32).toString('hex'), ethPrv: ethers.Wallet.createRandom().privateKey };
    writeJsonAtomic(KEYS_FILE, keys, 0o600);
  }
  ciaPrv = Buffer.from(keys.eddsaPrv, 'hex');
  ciaPub = eddsa.prv2pub(ciaPrv);
  const ethPrv = process.env.CIA_ETH_PRIVATE_KEY || keys.ethPrv;   // 테스트는 배포한 로그와 맞는 키를 주입한다
  ethWallet = new ethers.Wallet(ethPrv, new ethers.JsonRpcProvider(RPC_URL));
}

// ---- 상태 ----
// accounts:  uid → { pk_u:{x,y}, cm_u:{x,y}, disabled }
// issued:    uid → [ { leaf(10진), max_height, C(10진) } ]   폐기 시 열거·재전송 거절용. 만료되면 걷어낸다
// revoked:   [leaf(10진)]                              지금까지 트리에 넣은 전부 — 재기동 시 재구성
// pending:   [leaf(10진)]                              아직 게시 안 한 것
// epoch
let state;
let tree;
function defaultState() { return { version: 1, accounts: {}, issued: {}, revoked: [], pending: [], epoch: 0 }; }
function persist() { writeJsonAtomic(STATE_FILE, state, 0o600); }

async function loadState() {
  state = readJson(STATE_FILE, defaultState());
  tree = await createRevocationTree();
  for (const l of state.revoked) await tree.insert(BigInt(l));
  // 기동 시 로컬 epoch 가 체인보다 뒤처져 있으면(§I1 — 게시 tx 는 성공했는데 persist() 전에
  // 죽은 경우) 컨트랙트를 진실로 삼아 따라잡는다. RPC 가 아직 안 떠 있어도 기동 자체는
  // 막지 않는다 — 그 경우 발급은 headHeight() 가 알아서 503 을 낸다.
  if (LOG_ADDRESS) {
    try {
      const log = new ethers.Contract(LOG_ADDRESS, LOG_ABI, ethWallet);
      const onchainEpoch = Number(await log.epoch());
      if (onchainEpoch > state.epoch) {
        console.warn(`[cia] 상태 파일 epoch(${state.epoch})가 체인 epoch(${onchainEpoch})보다 뒤처져 있어 맞춘다`);
        state.epoch = onchainEpoch;
        persist();
      }
    } catch (e) {
      console.warn(`[cia] 기동 시 체인 epoch 확인 실패, 계속 진행: ${e.message}`);
    }
  }
}

// ---- 유틸 ----
const S = (o) => ({ x: F.toObject(o[0]).toString(), y: F.toObject(o[1]).toString() });
const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const isPt = (p) => p && isDec(p.x) && isDec(p.y);
function secretMatches(a, b) {
  const A = Buffer.from(a), B = Buffer.from(b);
  return A.length === B.length && timingSafeEqual(A, B);
}
function requireAdmin(req, res, next) {
  if (!ADMIN_SECRET) return res.status(503).json({ error: 'admin endpoints disabled: CIA_ADMIN_SECRET is not configured' });
  const p = req.get('X-CIA-Admin-Secret');
  if (typeof p !== 'string' || !secretMatches(p, ADMIN_SECRET)) return res.status(401).json({ error: 'unauthorized' });
  next();
}
async function headHeight() {
  if (!LOG_ADDRESS) throw Object.assign(new Error('CIA_LOG_ADDRESS not configured'), { status: 503 });
  try {
    return BigInt(await ethWallet.provider.getBlockNumber());
  } catch {
    // RPC 가 안 뜬 상태면 fail-closed — CIA_LOG_ADDRESS 미설정과 같은 취급(503)으로 통일한다.
    throw Object.assign(new Error('chain unavailable'), { status: 503 });
  }
}
function pruneExpired(uid, head) {
  const list = state.issued[uid] ?? [];
  state.issued[uid] = list.filter((e) => BigInt(e.max_height) >= head);
  return state.issued[uid];
}

// ---- 앱 ----
const app = express();
app.use(express.json({ limit: '256kb' }));

app.get('/cia/public_keys', (req, res) => {
  res.json({ pk_CIA: S(ciaPub), ethAddress: ethWallet.address, ttlBlocks: TTL_BLOCKS, logAddress: LOG_ADDRESS });
});

// §6.1 등록. CIA 가 장기키를 만들어 주고 sk_u 는 기억하지 않는다(응답에 한 번 실어 보내고 버린다).
app.post('/cia/register', (req, res) => {
  const { uid, pwd, cm_u } = req.body ?? {};
  if (!isDec(uid) || typeof pwd !== 'string' || !isPt(cm_u)) return res.status(400).json({ error: 'uid, pwd, cm_u{x,y} required' });
  const acct = Object.values(DEMO_ACCOUNTS).find((a) => a.uid === uid);
  if (!acct || acct.password !== pwd) return res.status(401).json({ error: 'invalid credentials' });
  if (state.accounts[uid]) return res.status(409).json({ error: 'already registered' });
  const prv = randomBytes(32);
  const pub = eddsa.prv2pub(prv);
  state.accounts[uid] = { pk_u: S(pub), cm_u: { x: cm_u.x, y: cm_u.y }, disabled: false };
  persist();
  res.status(201).json({ pk_u: S(pub), sk_u: prv.toString('hex') });
});

// §6.2 발급. C 는 받지 않는다 — C_pt 에서 스스로 유도한다.
app.post('/cia/issue', async (req, res) => {
  try {
    const { uid, C_pt, proof, sig_u } = req.body ?? {};
    if (!isDec(uid) || !isPt(C_pt) || !proof || !sig_u) return res.status(400).json({ error: 'uid, C_pt, proof, sig_u required' });
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });

    const cpt = pointFromStrings(C_pt);
    // 사용자 인증: 등록된 pk_u 로 C_pt 에 대한 EdDSA-Poseidon 서명 검증
    let sigOk = false;
    try {
      const m = F.e(F.toObject(poseidon([cpt.x, cpt.y])));
      const sig = { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) };
      const pub = [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))];
      sigOk = eddsa.verifyPoseidon(m, sig, pub);
    } catch { sigOk = false; }
    if (!sigOk) return res.status(400).json({ error: 'bad user signature' });

    // π_issue: 이 C_pt 가 내 uid 의 것이고 s_u 가 등록된 cm_u 와 같다
    let proofOk = false;
    try { proofOk = await verifyIssuance({ uid: BigInt(uid), C_pt: cpt, cm_u: pointFromStrings(acct.cm_u), proof: parseProof(proof) }); }
    catch { proofOk = false; }
    if (!proofOk) return res.status(400).json({ error: 'bad issuance proof' });

    const head = await headHeight();
    const C = await compressPoint(cpt);
    const Cstr = C.toString();
    // 재전송 방지: 같은 C_pt(따라서 같은 C)로 이미 발급했다면 서명·증명을 그대로 재사용해
    // 다시 제출하는 것을 거절한다 — π_issue 자체에는 요청별 nonce 가 없다.
    const issuedList = pruneExpired(uid, head);
    if (issuedList.some((e) => e.C === Cstr)) return res.status(409).json({ error: 'credential already issued for this C_pt' });

    const max_height = head + BigInt(TTL_BLOCKS);
    const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessage(C, max_height)));
    const leaf = await credLeaf(C);
    issuedList.push({ leaf: leaf.toString(), max_height: max_height.toString(), C: Cstr });
    persist();
    res.json({
      C: Cstr, max_height: max_height.toString(),
      sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() },
      pk_CIA: S(ciaPub),
    });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

// §6.5 폐기. account = 그 uid 의 미만료 리프 전부 + disabled. credential = 리프 하나.
app.post('/cia/revoke', requireAdmin, async (req, res) => {
  try {
    const { uid, scope, leaf } = req.body ?? {};
    if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
    const head = await headHeight();
    let targets;
    if (scope === 'account') {
      targets = pruneExpired(uid, head).map((e) => e.leaf);
      state.accounts[uid].disabled = true;
    } else if (scope === 'credential') {
      if (!isDec(leaf)) return res.status(400).json({ error: 'leaf required' });
      targets = [leaf];
    } else return res.status(400).json({ error: "scope must be 'account' or 'credential'" });
    const inserted = [];
    for (const l of targets) {
      if (await tree.insert(BigInt(l))) { state.revoked.push(l); state.pending.push(l); inserted.push(l); }
    }
    persist();
    res.json({ inserted, root: tree.getRoot().toString(), pending: state.pending.length });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// §6.5 게시. 서명이 리프 배열까지 덮는다 — 릴레이어의 calldata 오염 방지.
// inner 의 계산은 tests/helpers/mode3_chain.mjs 의 signRootPublication() 및
// RevocationLog.digestFor() 와 바이트 단위로 같아야 한다(keccak(DOMAIN, root, epoch,
// keccak(leaves)) 를 personal_sign). cia.js 는 프로덕션 코드라 tests/ 를 import 하지 않으므로
// 계산을 여기 그대로 다시 적는다.
app.post('/cia/publish', requireAdmin, async (req, res) => {
  try {
    if (!LOG_ADDRESS) return res.status(503).json({ error: 'CIA_LOG_ADDRESS not configured' });
    if (state.pending.length === 0) return res.json({ published: false, epoch: state.epoch, root: tree.getRoot().toString() });
    const log = new ethers.Contract(LOG_ADDRESS, LOG_ABI, ethWallet);
    const leaves = state.pending.map((l) => ethers.zeroPadValue(ethers.toBeHex(BigInt(l)), 32));
    const root = ethers.zeroPadValue(ethers.toBeHex(tree.getRoot()), 32);
    // tx 가 체인에 반영된 뒤 persist() 전에 죽으면 로컬 epoch 는 뒤처진 채로 남는다. 그 상태로
    // 로컬 epoch+1 을 또 게시하면 이미 온체인에 있는 epoch 와 같아져 EpochNotIncreasing 으로
    // 영원히 막힌다 — 컨트랙트의 epoch 를 진실로 삼아 로컬·온체인 중 큰 쪽의 다음 값을 쓴다.
    // 이때 pending 이 비워지지 못해(위 크래시로 인해) 이미 게시됐던 리프가 이 새 epoch 로
    // 한 번 더 올라갈 수 있는데, 그 자체는 무해하다 — 지갑 쪽 재구성이 중복 리프를 걸러낸다.
    const onchainEpoch = Number(await log.epoch());
    const epoch = Math.max(state.epoch, onchainEpoch) + 1;
    const leavesHash = ethers.keccak256(ethers.solidityPacked(leaves.map(() => 'bytes32'), leaves));
    const inner = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ['bytes32', 'bytes32', 'uint64', 'bytes32'], [DOMAIN_ROOT, root, epoch, leavesHash]));
    const sig = await ethWallet.signMessage(ethers.getBytes(inner));
    const tx = await log.publishRoot(root, epoch, leaves, sig);
    await tx.wait();
    state.epoch = epoch;
    state.pending = [];
    persist();
    res.json({ published: true, epoch, root: tree.getRoot().toString(), txHash: tx.hash, leaves });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

app.post('/cia/account/set_disabled', requireAdmin, (req, res) => {
  const { uid, disabled } = req.body ?? {};
  if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
  state.accounts[uid].disabled = Boolean(disabled);
  persist();
  res.json({ uid, disabled: state.accounts[uid].disabled });
});

app.get('/cia/state', async (req, res) => {
  let head = null;
  try { head = (await headHeight()).toString(); } catch { /* 체인 없음 */ }
  res.json({ root: tree.getRoot().toString(), epoch: state.epoch, pendingCount: state.pending.length, leafCount: state.revoked.length, head });
});

// ---- 기동 ----
eddsa = await buildEddsa();
poseidon = await buildPoseidon();
F = poseidon.F;
loadOrCreateKeys();
await loadState();
app.listen(PORT, () => {
  console.log(`Mode 3 CIA running at http://localhost:${PORT} (log=${LOG_ADDRESS ?? 'none'}, ttl=${TTL_BLOCKS})`);
});
