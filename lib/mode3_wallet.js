// Mode 3 지갑 측 라이브러리. 서버가 아니다 — 데모 UI 연동은 이 계획 밖이다.
// 설계 §6.1(등록값), §6.2(발급 요청), §7.1/§7.2(트리 동기화), §5(증명), §8.4(root 일치 규칙).
// 자격증명 이중 구조(2026-09-21): 사용자 자격증명 C_u(사용자당 하나, π_u 로 받는다)와 세션 자격증명 C_s(로그인마다, ZKP 없음).
// 자격증명 V5 는 (Cf_u, Cf_s, max_height, chainid, allowAgent) 위 CIA 서명이고, 폐기 리프는 userLeaf(Cf_u) 하나다(§3.6).
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { buildEddsa } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { randomScalar, ppid, normalizeAttrs, sessionCommit, compressPoint, MAX_HEIGHT_MAX, ATTR_MAX } from './mode3_credential.js';
import { encryptTag } from './mode3_trace.js';
import { userLeaf, sessionLeaf, createRevocationTree, MODE3_TREE_DEPTH } from './mode3_revocation.js';
import { setPath, NO_SET } from './mode3_set_tree.js';
import { buildIMTv2 } from './imt_v2.js';
import {
  registrationCommit, proveUserCred, serializeUserCredProof, userCredRequestMessage, issueRequestMessageV4, pointToStrings, attrsRequestMessage,
  revokeSessionMessage,
} from './mode3_issuance.js';
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
 * 지갑이 정하는 만료(설계 2026-09-18 §3.2 갱신): max_height = ceil((head + ttl) / grid) × grid. 그리드로 뭉개는 이유는 AA 가 이 값을
 * 서명하고 온체인에서 다시 보기 때문이다 — 같은 창의 발급이 같은 값을 가져야 AA 가 시각으로 특정하지 못한다(§2). 검증자는
 * head ≤ max_height ≤ head + L 을 요구하므로 ttl + grid 가 L 을 넘지 않아야 한다.
 */
export function chooseMaxHeight(head, { ttlBlocks = 300n, grid = 100n } = {}) {
  for (const [k, v] of [['head', head], ['ttlBlocks', ttlBlocks], ['grid', grid]]) if (typeof v !== 'bigint' || v < 0n) throw new Error(`chooseMaxHeight: ${k} 는 음이 아닌 bigint`);
  if (grid === 0n) throw new Error('chooseMaxHeight: grid 는 양수');
  return ((head + ttlBlocks + grid - 1n) / grid) * grid;
}

const sigStrings = (F, s) => ({ R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() });

/** /cia/user_cred 요청 서명 = Sign(sk_u, Poseidon(D_USERCREDREQ, C_u_pt.x, C_u_pt.y)). */
export async function signUserCredRequest(sk_uHex, C_u_pt) {
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await userCredRequestMessage(C_u_pt))));
}

/** /cia/attrs 요청 서명 = Sign(sk_u, Poseidon(D_ATTRSREQ, uid, nonce)) (스펙 2026-09-22 §3.3). */
export async function signAttrsRequest(sk_uHex, uid, nonce) {
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await attrsRequestMessage(uid, nonce))));
}

/** /cia/revoke scope=session 요청 서명 = Sign(sk_u, Poseidon(D_REVOKESESS, uid, Cf_s, nonce)) (설계 2026-09-24 §2.2). */
export async function signRevokeSession(sk_uHex, uid, Cf_s, nonce) {
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await revokeSessionMessage(uid, Cf_s, nonce))));
}

/**
 * /wallet/tx 의 disclose([{lo,hi}|null ×4]) 를 회로 입력 { mask, lo[4], hi[4] } 로. 지갑이 먼저 lo ≤ a_k ≤ hi 를 확인한다 —
 * 안 맞으면 증명이 어차피 안 만들어진다(reason 'disclosure_unsatisfiable'). 형식·범위 오류는 'bad_disclosure'.
 */
export function normalizeDisclosure(disclose, attrs) {
  const fail = (reason, msg) => Object.assign(new Error(msg ?? reason), { reason });
  if (disclose === undefined || disclose === null) return { mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n] };
  if (!Array.isArray(disclose) || disclose.length !== 4) throw fail('bad_disclosure', 'disclose 는 길이 4 배열');
  let mask = 0n; const lo = [0n, 0n, 0n, 0n], hi = [0n, 0n, 0n, 0n];
  disclose.forEach((d, k) => {
    if (d === null || d === undefined) return;
    let l, h;
    try { l = BigInt(d.lo); h = BigInt(d.hi); } catch { throw fail('bad_disclosure', `슬롯 ${k}: lo·hi 는 10진`); }
    if (l < 0n || h < 0n || l >= ATTR_MAX || h >= ATTR_MAX || l > h) throw fail('bad_disclosure', `슬롯 ${k}: 0 ≤ lo ≤ hi < 2^64`);
    if (attrs[k] < l || attrs[k] > h) throw fail('disclosure_unsatisfiable', `슬롯 ${k}: 내 속성이 [${l}, ${h}] 밖`);
    mask |= 1n << BigInt(k); lo[k] = l; hi[k] = h;
  });
  return { mask, lo, hi };
}
export const disclosureKey = (d) => `${d.mask}:${d.lo.join(',')}:${d.hi.join(',')}:${d.sel ?? 0n}:${d.root ?? 0n}`;

/**
 * V7(2026-09-23 §5.1) — 요청의 set({ slot, members }) 를 회로 입력 { sel, root, index, path } 로. root 는 여기서 members 로부터 계산한다 —
 * 서비스가 준 root 를 믿지 않는다(증명하는 사실은 항상 "내 속성 ∈ 내가 받은 members"). 없으면 NO_SET.
 */
export async function normalizeSet(set, attrs) {
  const fail = (reason, msg) => Object.assign(new Error(msg ?? reason), { reason });
  if (set === undefined || set === null) return NO_SET;
  if (typeof set !== 'object' || Array.isArray(set)) throw fail('bad_disclosure', 'set 은 { slot, members } 객체');
  const { slot, members } = set;
  if (!Number.isInteger(slot) || slot < 0 || slot > 3) throw fail('bad_disclosure', 'set.slot 은 정수 0..3');
  const { index, path, root } = await setPath(members, attrs[slot]);   // bad_disclosure / disclosure_unsatisfiable 를 그대로 올린다
  return { sel: BigInt(slot) + 1n, root, index, path };
}

/** 술어가 하나라도 있으면(범위 또는 집합) 캐시 π 를 못 쓰고 새로 증명한다. */
export const hasPredicate = (d) => Boolean(d) && (d.mask !== 0n || (d.sel ?? 0n) !== 0n);

/**
 * 사용자 자격증명 요청(설계 2026-09-21 §3.1·§3.5). 사용자당 하나 — 첫 로그인 또는 속성 변경 때. blind_u 는 여기서 뽑아 secrets 로 돌려준다.
 * 지갑은 (C_u_pt, blind_u, attrs, leaf) 를 등록 정보와 함께 보관한다(에이전트 상태 v6).
 */
export async function buildUserCredRequest({ uid, s_u, r_u, sk_u, attrs }) {
  const blind_u = randomScalar();
  const a4 = normalizeAttrs(attrs);
  const { C_u_pt, proof } = await proveUserCred({ uid, s_u, blind_u, r_u, attrs: a4 });
  const Cf_u = await compressPoint(C_u_pt);
  const body = { uid: uid.toString(), C_u_pt: pointToStrings(C_u_pt), proof: serializeUserCredProof(proof), sig_u: await signUserCredRequest(sk_u, C_u_pt) };
  return { body, secrets: { blind_u }, C_u_pt, Cf_u, leaf: await userLeaf(Cf_u) };
}

/** /cia/issue V5 요청 서명 = Sign(sk_u, Poseidon(D_ISSUEREQ_V4, Cf_u, C_s_pt.x, C_s_pt.y, chainid, allowAgent, max_height)). */
export async function signIssueRequest(sk_uHex, Cf_u, C_s_pt, chainid, allowAgent, max_height) {
  if (typeof chainid !== 'bigint' || typeof allowAgent !== 'bigint' || typeof max_height !== 'bigint') throw new Error('signIssueRequest: chainid·allowAgent·max_height(bigint) 가 필요하다');
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await issueRequestMessageV4(Cf_u, C_s_pt, chainid, allowAgent, max_height))));
}

/**
 * 세션 발급 요청(설계 §3.2·§4.2). ZKP 없음. blind_s 는 여기서 뽑아 secrets 로 돌려준다. max_height 는 지갑이 정한다(chooseMaxHeight).
 * C_s 는 (arid, pk_i) 를 담는다 — AA 는 pk_i 를 못 보고, 서명이 Cf_s 를 덮으므로 바꿔치기는 불가능하다.
 */
export async function buildIssueRequest({ uid, Cf_u, arid, sk_u, session, chainid, allowAgent = 0n, max_height }) {
  if (typeof Cf_u !== 'bigint') throw new Error('buildIssueRequest: Cf_u(bigint) 가 필요하다 — 먼저 사용자 자격증명을 받는다');
  if (typeof chainid !== 'bigint') throw new Error('buildIssueRequest: chainid(bigint) 가 필요하다');
  if (typeof allowAgent !== 'bigint' || (allowAgent !== 0n && allowAgent !== 1n)) throw new Error('buildIssueRequest: allowAgent 는 0n 또는 1n');
  if (typeof max_height !== 'bigint' || max_height < 0n || max_height >= MAX_HEIGHT_MAX) throw new Error('buildIssueRequest: max_height(bigint, < 2^64) 가 필요하다 — 지갑이 chooseMaxHeight 로 정한다');
  const blind_s = randomScalar();
  const { Cx, Cy, Cf } = await sessionCommit({ arid, pk_i: session.pk_i, blind_s });
  const C_s_pt = { x: Cx, y: Cy };
  const body = {
    uid: uid.toString(), Cf_u: Cf_u.toString(), C_s_pt: pointToStrings(C_s_pt),
    sig_u: await signIssueRequest(sk_u, Cf_u, C_s_pt, chainid, allowAgent, max_height),
    chainid: chainid.toString(), allowAgent: allowAgent.toString(), max_height: max_height.toString(),
  };
  return { body, secrets: { blind_s }, C_s_pt, Cf_s: Cf };
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

/**
 * §5 — 공개 입력 순서 [PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, pk_CIA_x, pk_CIA_y, pk_trace_x, pk_trace_y,
 * tag_c1_x, tag_c1_y, tag_c2, disc_mask, disc_lo[4], disc_hi[4], set_sel, set_root]
 * (25개, V7 §3.3: [23] set_sel [24] set_root — 2026-09-22 §4.2 선택 공개 + 2026-09-23 §5.1 집합 소속 술어)는 회로가 정한다.
 * pk_trace 는 인증서 cert_s 에 실린 서비스의 조합 키다(2026-09-16 §3) — 호출자는 검증된 인증서의 값만 넘겨야 한다.
 * 태그의 r 은 여기서 새로 뽑는다(재검증으로 새 π 를 만들면 태그도 바뀐다). disclosure 를 안 주면(null) mask 0(아무것도 공개 안 함).
 */
export async function buildCredentialProof({ uid, arid, s_u, blind_u, blind_s, pk_i, attrs, credential, pk_CIA, pk_trace, tree, disclosure = null, tagR = undefined, wasmPath = WASM_PATH, zkeyPath = ZKEY_PATH }) {
  if (typeof blind_u !== 'bigint' || typeof blind_s !== 'bigint') throw new Error('buildCredentialProof: blind_u·blind_s(bigint) 가 필요하다 — blind_u 는 사용자 자격증명, blind_s 는 세션의 것');
  if (typeof pk_trace?.x !== 'bigint' || typeof pk_trace?.y !== 'bigint') throw new Error('buildCredentialProof: pk_trace{x,y}(bigint) 가 필요하다 — cert_s 에 실린 서비스 조합 키');
  const PPID = await ppid({ uid, arid, s_u, chainid: BigInt(credential.chainid) });
  const a4 = normalizeAttrs(attrs);
  // 리프는 사용자 자격증명 Cf_u 에서(2026-09-21 §3.6) — 폐기되면 모든 세션이 여기서 throw ("is a member")
  // V8: 세션 리프 비멤버십 증인 — 세션이 폐기됐으면 여기서 "is a member" 로 던진다. 호출자(proveSession)가 사용자 리프와 구분한다.
  // 두 증인은 반드시 같은 트리 상태에서 나와야 한다 — 공개 입력 revRoot 는 하나뿐이라 한쪽이라도 다른 root 를 보면 회로가
  // 튕긴다. getNonMembershipWitness 의 본문에는 await 가 없으므로 둘을 await 없이 연달아 부르면 그 사이에 다른 요청의
  // insert(증분 동기화, 스펙 §5)가 끼어들 수 없다. 그래도 어긋나면(스텁 등) 알아볼 수 없는 회로 assert 대신 여기서 던진다.
  const [uLeaf, sLeaf] = await Promise.all([userLeaf(BigInt(credential.Cf_u)), sessionLeaf(BigInt(credential.Cf_s))]);
  const [w, ws] = await Promise.all([tree.getNonMembershipWitness(uLeaf), tree.getNonMembershipWitness(sLeaf)]);
  if (String(ws.root) !== String(w.root)) throw new Error(`비멤버십 증인 두 개의 root 가 다르다(${w.root} vs ${ws.root}) — 증인 사이에 트리가 바뀌었다`);
  // 공개 입력 root 는 증인이 계산된 root 로 고정한다. 트리 객체를 여러 요청이 공유하면(증분 동기화, 스펙 §5)
  // 이 아래의 await 사이에 다른 요청의 insert 가 끼어들 수 있고, 그때 tree.getRoot() 를 다시 읽으면
  // 증인과 어긋난 root 로 증명을 만들게 된다.
  const revRoot = BigInt(w.root);
  // tagR 은 테스트 전용 — 태그 난수를 주입해 같은 c1 을 가진 트랜스크립트를 만든다(CIA 개봉 dup 키 회귀). 운영 경로는 넘기지 않는다.
  const tag = tagR === undefined ? await encryptTag(pk_trace, uid, arid) : await encryptTag(pk_trace, uid, arid, tagR);
  const disc = disclosure ?? { mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n] };
  const st = { sel: disc.sel ?? NO_SET.sel, root: disc.root ?? NO_SET.root, index: disc.index ?? 0, path: disc.path ?? NO_SET.path };
  const input = {
    uid: uid.toString(), s_u: s_u.toString(), blind_u: blind_u.toString(), blind_s: blind_s.toString(),
    attrs: a4.map(String),
    S: credential.sigma.S, R8x: credential.sigma.R8x, R8y: credential.sigma.R8y,
    lowValue: String(w.lowValue), lowNextIndex: String(w.lowNextIndex), lowNextValue: String(w.lowNextValue),
    pathElements: w.pathElements.map(String), pathIndices: w.pathIndices.map(String),
    s_lowValue: String(ws.lowValue), s_lowNextIndex: String(ws.lowNextIndex), s_lowNextValue: String(ws.lowNextValue),
    s_pathElements: ws.pathElements.map(String), s_pathIndices: ws.pathIndices.map(String),
    r: tag.r.toString(),
    PPID: PPID.toString(), arid: arid.toString(), pk_i: pk_i.toString(),
    max_height: BigInt(credential.max_height).toString(), chainid: BigInt(credential.chainid).toString(),
    allowAgent: BigInt(credential.allowAgent).toString(), revRoot: revRoot.toString(),
    pk_CIA_x: pk_CIA.x.toString(), pk_CIA_y: pk_CIA.y.toString(),
    pk_trace_x: pk_trace.x.toString(), pk_trace_y: pk_trace.y.toString(),
    tag_c1_x: tag.c1.x.toString(), tag_c1_y: tag.c1.y.toString(), tag_c2: tag.c2.toString(),
    disc_mask: disc.mask.toString(), disc_lo: disc.lo.map(String), disc_hi: disc.hi.map(String),
    set_sel: st.sel.toString(), set_root: st.root.toString(), set_index: String(st.index), set_path: [...st.path].map(String),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  return { proof, publicSignals, revRoot, tag: { c1: tag.c1, c2: tag.c2, h: tag.h } };
}

/** §8.4 — π 는 root 가 바뀔 때까지 재사용. 세션이 바뀌면 pk_i 가 달라 재사용 불가. discKey 가 다르면(선택 공개 조건이 다르면) 별개 항목이다. */
export class ProofCache {
  #m = new Map();
  #key(root, sessionId, discKey) { return `${root}:${sessionId}:${discKey}`; }
  get(root, sessionId, discKey = '0') { return this.#m.get(this.#key(root, sessionId, discKey)) ?? null; }
  set(root, sessionId, value, discKey = '0') { this.#m.set(this.#key(root, sessionId, discKey), value); }
  /** 한 세션(r_s)의 캐시 항목을 전부 지운다 — 세션 만료 정리에서 부른다. 키는 `${root}:${sessionId}:${discKey}` 이고
   *  root·sessionId 는 10진 문자열이라 ':' 이 없다(discKey 에는 있다) — 그래서 두 번째 필드만 대조한다. */
  deleteSession(sessionId) { for (const k of [...this.#m.keys()]) if (k.split(':')[1] === String(sessionId)) this.#m.delete(k); }
  clear() { this.#m.clear(); }
}

/** 요청마다 새 σ. EIP-191 personal sign — RP 는 ethers.verifyMessage 로 주소를 복원해 pk_i 와 대조한다. */
export function signChallenge(wallet, challenge) {
  return wallet.signMessage(challenge);
}

/** 세션 안 후속 요청 서명 (설계 §7). 메시지 = `${r_s}:${body}` 위 EIP-191. */
export function signSessionRequest(wallet, r_s, body) {
  return wallet.signMessage(`${r_s.toString()}:${body}`);
}
