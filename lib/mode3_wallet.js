// Mode 3 지갑 측 라이브러리. 서버가 아니다 — 데모 UI 연동은 이 계획 밖이다.
// 설계 §6.1(등록값), §6.2(발급 요청), §7.1/§7.2(트리 동기화), §5(증명), §8.4(root 일치 규칙).
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { buildEddsa } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { randomScalar, ppid, normalizeAttrs } from './mode3_credential.js';
import { credLeaf, createRevocationTree, MODE3_TREE_DEPTH } from './mode3_revocation.js';
import { buildIMTv2 } from './imt_v2.js';
import { registrationCommit, proveIssuance, serializeProof, pointToStrings, issueRequestMessage } from './mode3_issuance.js';
import { LOG_ABI } from './mode3_log.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
export const WASM_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_cred_js', 'pi_cred.wasm');
export const ZKEY_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_cred_final.zkey');
export const VKEY_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_cred_vkey.json');

let eddsaP = null;
const getEddsa = () => (eddsaP ??= buildEddsa());

/** §6.1 — s_u, r_u 는 randomScalar (2^250 미만). cm_u 를 CIA 에 낸다. */
export async function createRegistration() {
  const s_u = randomScalar(), r_u = randomScalar();
  return { s_u, r_u, cm_u: await registrationCommit(s_u, r_u) };
}

/** 세션키 = secp256k1. pk_i 는 주소(160비트) — 회로의 Num2Bits(160) 과 맞는다. */
export function createSessionKey() {
  const wallet = ethers.Wallet.createRandom();
  return { wallet, pk_i: BigInt(wallet.address) };
}

/**
 * Sign(sk_u, (C_pt, chainid, nonce)): 등록된 장기키로 서명 (설계 2026-09-14 §4 단계 2). 메시지는 issueRequestMessage().
 * nonce 는 요청마다 새로 뽑고 CIA 가 (uid, nonce) 재사용을 거절한다 — 만료된 요청 본문을 그대로 다시 내서
 * 새 σ_CIA 를 받는 것(TTL 연장)을 막는다. 옛 height 창 검사의 자리다.
 */
export async function signUserRequest(sk_uHex, C_pt, chainid, nonce) {
  if (typeof chainid !== 'bigint' || typeof nonce !== 'bigint') throw new Error('signUserRequest: chainid·nonce(bigint) 가 필요하다');
  const eddsa = await getEddsa();
  const F = eddsa.F;
  const s = eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), F.e(await issueRequestMessage(C_pt, chainid, nonce)));
  return { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() };
}

/** §4 단계 1~2. blind·nonce 는 여기서 새로 뽑고 secrets 로 돌려준다 — 증명 생성 때 필요하다. attrs 는 생략하면 전부 0. */
export async function buildIssueRequest({ uid, arid, s_u, r_u, sk_u, session, chainid, attrs }) {
  if (typeof chainid !== 'bigint') throw new Error('buildIssueRequest: chainid(bigint) 가 필요하다');
  const blind = randomScalar();
  const nonce = randomScalar();
  const a4 = normalizeAttrs(attrs);
  const { C_pt, proof } = await proveIssuance({ uid, arid, s_u, blind, pk_i: session.pk_i, r_u, attrs: a4 });
  const body = {
    uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof),
    sig_u: await signUserRequest(sk_u, C_pt, chainid, nonce), chainid: chainid.toString(), nonce: nonce.toString(),
  };
  return { body, secrets: { blind, nonce } };
}

/**
 * §7.2 — Revoked 이벤트를 처음부터 재생해 트리를 재구성한다. CIA 없이도 된다는 것이 요점이다.
 * 재구성한 root 가 컨트랙트 root 와 다르면 throw — 릴레이어가 calldata 를 오염시켰거나
 * (서명이 리프까지 덮으므로 이론상 불가) 이 라이브러리와 CIA 의 리프 규약이 어긋난 것이다.
 * 의도적으로 fail-closed: 데이터 가용성이 깨진 채로 (틀렸을 수 있는) 트리를 조용히
 * 돌려주면, 지갑이 실제로는 비어있지 않은 비멤버십 증명을 만들어 낼 수 있다.
 *
 * ethers v6 는 getLogs·getBlockNumber 결과를 250 ms(cacheTimeout) 캐시한다. eth_call 은
 * 캐시하지 않는다. 모든 조회를 head 블록에 고정하면 (1) 네 RPC 가 같은 블록의 일관된
 * 스냅샷을 보고 (2) toBlock 이 sync 마다 달라져 캐시된 로그가 섞이지 않는다. head 자체가
 * 250 ms 묵을 수는 있으며 그 경우 스냅샷 전체가 그만큼 옛 블록일 뿐 불일치는 아니다.
 * 테스트처럼 게시 직후 즉시 동기화해야 하면 provider 를 `{ cacheTimeout: -1 }` 로 만들 것.
 */
export async function syncRevocationTree(provider, logAddress) {
  const log = new ethers.Contract(logAddress, LOG_ABI, provider);
  const head = BigInt(await provider.getBlockNumber());
  const blockTag = Number(head);
  const [events, onchainRoot, epoch] = await Promise.all([
    log.queryFilter(log.filters.Revoked(), 0, blockTag),
    log.root({ blockTag }),
    log.epoch({ blockTag }),
  ]);
  const leaves = [];
  for (const e of events) {
    for (const l of e.args.leaves) leaves.push(BigInt(l));
  }
  const tree = leaves.length === 0 ? await createRevocationTree() : await buildIMTv2(MODE3_TREE_DEPTH, leaves);
  const root = tree.getRoot();
  if (root !== BigInt(onchainRoot)) {
    throw new Error(`재구성한 root(${root}) 가 컨트랙트 root(${BigInt(onchainRoot)}) 와 다르다 — 리프 규약 불일치 또는 calldata 오염`);
  }
  return { tree, root, epoch, head };
}

/** §5 — 공개 입력 순서 [PPID, arid, pk_i, exptime, chainid, revRoot, pk_CIA_x, pk_CIA_y] 는 회로가 정한다. */
export async function buildCredentialProof({ uid, arid, s_u, blind, pk_i, attrs, credential, pk_CIA, tree, wasmPath = WASM_PATH, zkeyPath = ZKEY_PATH }) {
  const PPID = await ppid({ uid, arid, s_u, chainid: BigInt(credential.chainid) });
  const C = BigInt(credential.C);
  const a4 = normalizeAttrs(attrs);
  const w = await tree.getNonMembershipWitness(await credLeaf(C));   // 폐기됐으면 여기서 throw ("is a member")
  const input = {
    uid: uid.toString(), s_u: s_u.toString(), blind: blind.toString(),
    attrs: a4.map(String), nonce: BigInt(credential.nonce).toString(),
    S: credential.sigma.S, R8x: credential.sigma.R8x, R8y: credential.sigma.R8y,
    lowValue: String(w.lowValue), lowNextIndex: String(w.lowNextIndex), lowNextValue: String(w.lowNextValue),
    pathElements: w.pathElements.map(String), pathIndices: w.pathIndices.map(String),
    PPID: PPID.toString(), arid: arid.toString(), pk_i: pk_i.toString(),
    exptime: BigInt(credential.exptime).toString(), chainid: BigInt(credential.chainid).toString(), revRoot: tree.getRoot().toString(),
    pk_CIA_x: pk_CIA.x.toString(), pk_CIA_y: pk_CIA.y.toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  return { proof, publicSignals, revRoot: tree.getRoot() };
}

/** §8.4 — π 는 root 가 바뀔 때까지 재사용. 세션이 바뀌면 pk_i 가 달라 재사용 불가. */
export class ProofCache {
  #m = new Map();
  #key(root, sessionId) { return `${root}:${sessionId}`; }
  get(root, sessionId) { return this.#m.get(this.#key(root, sessionId)) ?? null; }
  set(root, sessionId, value) { this.#m.set(this.#key(root, sessionId), value); }
}

/** 요청마다 새 σ. EIP-191 personal sign — RP 는 ethers.verifyMessage 로 주소를 복원해 pk_i 와 대조한다. */
export function signChallenge(wallet, challenge) {
  return wallet.signMessage(challenge);
}
