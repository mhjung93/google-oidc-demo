// Mode 3 CIA (Credential Issuing Authority).
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §3, §6
//
// Mode 2 의 custom_idp.js 와 나란히 두는 별도 서버다(:4100). 그쪽 코드를 import 하지 않는다.
// 하는 일 넷: 등록(§6.1), 발급(§6.2), 폐기(§6.5), root 게시(§6.5). 로그인 검증은 하지 않는다 —
// 그것은 RP 의 일이고(§6.3) CIA 는 조회 경로에 있어서는 안 된다(§9.9).
import 'dotenv/config';
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
import { verifyIssuance, isValidPoint, pointFromStrings, parseProof } from './lib/mode3_issuance.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.CIA_PORT) || 4100;
const STATE_FILE = process.env.CIA_STATE_FILE || path.join(__dirname, 'cia_state.json');
const KEYS_FILE = process.env.CIA_KEYS_FILE || path.join(__dirname, 'cia_keys.json');
const ADMIN_SECRET = process.env.CIA_ADMIN_SECRET;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const TTL_BLOCKS = Number(process.env.CIA_TTL_BLOCKS) || 300;
// 발급 요청의 사용자 서명이 덮는 height 의 허용 창(블록). 요청 본문에 nonce 가 없으면 만료된
// 요청을 그대로 다시 내서 새 σ_CIA(새 max_height)를 받을 수 있다 — height 를 서명에 넣고 창 밖이면 거절한다.
const ISSUE_HEIGHT_WINDOW = 30n;
// 같은 C 재발급 거절(409)은 발급 기록이 max_height 까지만 남아서 유효하다. TTL 이 창보다 짧으면
// 기록이 지워진 뒤에도 창 안이라 만료된 본문을 그대로 다시 내서 새 σ_CIA 를 받을 수 있다.
if (BigInt(TTL_BLOCKS) <= ISSUE_HEIGHT_WINDOW + 1n) throw new Error(`CIA_TTL_BLOCKS(${TTL_BLOCKS}) 는 발급 창 ${ISSUE_HEIGHT_WINDOW}+1 보다 커야 한다`);

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
  // pending 은 revoked 의 접미사다 — /cia/revoke 가 둘 다에 push 하고 /cia/publish 가 pending 의
  // 앞부분만 지운다. 따라서 "게시된 리프" = revoked 의 앞 (revoked.length - pending.length) 개.
  let published = state.revoked.length - state.pending.length;
  for (const l of state.revoked.slice(0, published)) await tree.insert(BigInt(l));

  // 기동 시 로컬 트리를 온체인 root 와 대조한다. 어긋난 채로 다음 게시를 하면 서명 root 와 지갑이
  // 이벤트로 재구성한 root 가 달라져 전원이 fail-closed 되고, 로그 재배포 말고는 복구가 없다.
  //   - 게시 tx 는 성공했는데 persist() 전에 죽은 경우: 그 tx 에 실렸던 pending 앞부분이 이미
  //     체인에 있다. 게시된 접두사에 pending 을 하나씩 더해 가며 온체인 root 와 같아지는 지점을
  //     찾고, 그 앞부분은 pending 에서 걷어낸다(다시 올리면 리프 이벤트가 중복될 뿐 무해하지만,
  //     걷어내는 쪽이 정확하다). epoch 도 컨트랙트를 진실로 삼아 따라잡는다.
  //   - 어느 접두사도 맞지 않으면(로그 재배포, 상태 파일 유실·옛 백업 복원) 기동을 거부한다.
  //   - RPC 가 아직 안 떠 있으면 대조 없이 기동한다 — 발급은 headHeight() 가 503 을 내고,
  //     게시는 다음 기동 때 다시 대조된다.
  if (LOG_ADDRESS) {
    let onchainRoot = null, onchainEpoch = 0;
    try {
      const log = new ethers.Contract(LOG_ADDRESS, LOG_ABI, ethWallet);
      onchainRoot = BigInt(await log.root());
      onchainEpoch = Number(await log.epoch());
    } catch (e) {
      console.warn(`[cia] 기동 시 체인 확인 실패, root 대조 없이 계속 진행: ${e.message}`);
    }
    if (onchainRoot !== null) {
      let n = published;
      while (tree.getRoot() !== onchainRoot && n < state.revoked.length) { await tree.insert(BigInt(state.revoked[n])); n++; }
      if (tree.getRoot() !== onchainRoot) {
        console.error(`[cia] 기동 거부: 로컬 폐기 트리와 온체인 root 불일치 (로그 ${LOG_ADDRESS}, 온체인 epoch ${onchainEpoch}, ` +
          `로컬 revoked ${state.revoked.length}개 / pending ${state.pending.length}개). 로그를 재배포했거나 상태 파일이 ` +
          `유실·복원됐다. 이대로 게시하면 지갑의 이벤트 재구성이 전부 실패한다 — CIA_STATE_FILE 과 CIA_LOG_ADDRESS 를 확인할 것.`);
        process.exit(1);
      }
      let changed = false;
      if (n !== published) {
        console.warn(`[cia] 크래시 복구: pending ${n - published}개는 이미 체인에 게시돼 있어 걷어낸다`);
        state.pending = state.revoked.slice(n);
        published = n;
        changed = true;
      }
      if (onchainEpoch > state.epoch) {
        console.warn(`[cia] 상태 파일 epoch(${state.epoch})가 체인 epoch(${onchainEpoch})보다 뒤처져 있어 맞춘다`);
        state.epoch = onchainEpoch;
        changed = true;
      }
      if (changed) persist();
    }
  }
  for (const l of state.revoked.slice(published)) await tree.insert(BigInt(l));
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

// 관리자 패널(스펙 §5). 페이지 하나만 허용 목록으로 내보낸다 — express.static 은 쓰지 않는다.
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'cia_admin.html')));

app.get('/cia/public_keys', (req, res) => {
  res.json({ pk_CIA: S(ciaPub), ethAddress: ethWallet.address, ttlBlocks: TTL_BLOCKS, logAddress: LOG_ADDRESS });
});

// §6.1 등록. CIA 가 장기키를 만들어 주고 sk_u 는 기억하지 않는다(응답에 한 번 실어 보내고 버린다).
app.post('/cia/register', async (req, res) => {
  const { uid, pwd, cm_u } = req.body ?? {};
  if (!isDec(uid) || typeof pwd !== 'string' || !isPt(cm_u)) return res.status(400).json({ error: 'uid, pwd, cm_u{x,y} required' });
  const acct = Object.values(DEMO_ACCOUNTS).find((a) => a.uid === uid);
  if (!acct || acct.password !== pwd) return res.status(401).json({ error: 'invalid credentials' });
  if (state.accounts[uid]) return res.status(409).json({ error: 'already registered' });
  // 등록은 한 번뿐이다. 곡선·부분군 밖이거나 비정규 인코딩이면 이후 모든 발급이 400 이 되고
  // 재등록은 409 라 uid 가 영구히 잠기므로 여기서 거절한다.
  if (!(await isValidPoint(pointFromStrings(cm_u)))) return res.status(400).json({ error: 'cm_u is not a valid subgroup point' });
  const prv = randomBytes(32);
  const pub = eddsa.prv2pub(prv);
  state.accounts[uid] = { pk_u: S(pub), cm_u: { x: cm_u.x, y: cm_u.y }, disabled: false };
  persist();
  res.status(201).json({ pk_u: S(pub), sk_u: prv.toString('hex') });
});

// §6.2 발급. C 는 받지 않는다 — C_pt 에서 스스로 유도한다.
app.post('/cia/issue', async (req, res) => {
  try {
    const { uid, C_pt, proof, sig_u, height } = req.body ?? {};
    if (!isDec(uid) || !isPt(C_pt) || !proof || !sig_u || !isDec(height)) return res.status(400).json({ error: 'uid, C_pt, proof, sig_u, height required' });
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });

    const cpt = pointFromStrings(C_pt);
    const h = BigInt(height);
    // 사용자 인증: 등록된 pk_u 로 (C_pt, height) 에 대한 EdDSA-Poseidon 서명 검증
    let sigOk = false;
    try {
      const m = F.e(F.toObject(poseidon([cpt.x, cpt.y, h])));
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
    if (h > head + 1n || h + ISSUE_HEIGHT_WINDOW < head) return res.status(400).json({ error: `stale issue request: height ${h} not within [${head - ISSUE_HEIGHT_WINDOW}, ${head + 1n}]` });
    const C = await compressPoint(cpt);
    const Cstr = C.toString();
    // 재전송 방지: 같은 C_pt(따라서 같은 C)로 이미 발급했다면 서명·증명을 그대로 재사용해
    // 다시 제출하는 것을 거절한다 — π_issue 자체에는 요청별 nonce 가 없다.
    const issuedList = pruneExpired(uid, head);
    if (issuedList.some((e) => e.C === Cstr)) return res.status(409).json({ error: 'credential already issued for this C_pt' });

    const max_height = head + BigInt(TTL_BLOCKS);
    const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessage(C, max_height)));
    const leaf = await credLeaf(C);
    // 위 await 들(headHeight·compressPoint·credMessage·credLeaf) 사이에 /cia/revoke 가 끼어들 수 있다 —
    // 폐기 직후의 발급이 살아남으면 트리에 없는 새 credential 이 TTL 동안 유효하다. 마지막 await 뒤,
    // 기록 직전에 다시 확인한다. 끼어든 revoke 의 pruneExpired 가 목록 배열을 새로 만들었을 수 있어
    // issuedList 가 아니라 state.issued[uid] 에 넣는다.
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });
    state.issued[uid].push({ leaf: leaf.toString(), max_height: max_height.toString(), C: Cstr });
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
    const { uid, scope, leaf, C } = req.body ?? {};
    if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
    const head = await headHeight();
    let targets;
    if (scope === 'account') {
      targets = pruneExpired(uid, head).map((e) => e.leaf);
      state.accounts[uid].disabled = true;
    } else if (scope === 'credential') {
      // 그 uid 의 미만료 발급 목록에 있는 리프만 받는다 — 폐기는 append-only 라 잘못 넣은 리프가
      // 영구히 남고, 범위 밖 값은 트리가 throw 한다. leaf 대신 C 를 주면 서버가 리프를 유도한다.
      // 발급 기록은 {leaf, C} 쌍이라 다시 해시하지 않고 기록에서 찾는다. isDec 은 앞자리 0 을 허용하므로
      // BigInt 로 정규화한 뒤 비교한다.
      const issued = pruneExpired(uid, head);
      let entry;
      if (isDec(C)) entry = issued.find((e) => e.C === BigInt(C).toString());
      else if (isDec(leaf)) entry = issued.find((e) => e.leaf === BigInt(leaf).toString());
      else return res.status(400).json({ error: 'leaf or C required' });
      if (!entry) return res.status(404).json({ error: 'leaf not issued to this uid (or expired)' });
      targets = [entry.leaf];
    } else return res.status(400).json({ error: "scope must be 'account' or 'credential'" });
    const inserted = [];
    for (const l of targets) {
      if (await tree.insert(BigInt(l))) { state.revoked.push(l); state.pending.push(l); inserted.push(l); }
    }
    persist();
    res.json({ inserted, root: tree.getRoot().toString(), pending: state.pending.length });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// §6.5 게시. 서명이 리프 배열까지 덮는다 — 릴레이어의 calldata 오염 방지. 로그 주소도 덮는다 —
// 같은 CIA 키로 재배포한 다른 로그에 옛 게시를 재생하지 못하게(재생되면 root 가 옛 트리로 바뀐다).
// inner 의 계산은 tests/helpers/mode3_chain.mjs 의 signRootPublication() 및
// RevocationLog.digestFor() 와 바이트 단위로 같아야 한다(keccak(DOMAIN, address(log), root,
// epoch, keccak(leaves)) 를 personal_sign). cia.js 는 프로덕션 코드라 tests/ 를 import 하지
// 않으므로 계산을 여기 그대로 다시 적는다.
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
      ['bytes32', 'address', 'bytes32', 'uint64', 'bytes32'], [DOMAIN_ROOT, LOG_ADDRESS, root, epoch, leavesHash]));
    const sig = await ethWallet.signMessage(ethers.getBytes(inner));
    const tx = await log.publishRoot(root, epoch, leaves, sig);
    await tx.wait();
    state.epoch = epoch;
    // 위 await 들 사이에 /cia/revoke 가 pending 뒤에 붙인 리프는 이번 tx 에 실리지 않았다 —
    // 이번에 실은 앞부분만 지운다. 통째로 비우면 그 리프는 온체인 이벤트로 영영 나가지 않으면서
    // 이후 모든 서명 root 에는 들어 있어, 지갑의 이벤트 재구성이 전부 fail-closed 된다.
    state.pending = state.pending.slice(leaves.length);
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
