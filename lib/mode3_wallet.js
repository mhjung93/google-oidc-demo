// Mode 3 지갑 측 라이브러리. 서버가 아니다 — 데모 UI 연동은 이 계획 밖이다.
// 설계 §6.1(등록값), §6.2(발급 요청), §7.1/§7.2(트리 동기화), §5(증명), §8.4(root 일치 규칙).
// 자격증명 이중 구조(2026-09-21): 사용자 자격증명 C_u(사용자당 하나)와 세션 자격증명 C_s(로그인마다). V11(2026-10-12)부터는
// 둘 다 /cia/issue 요청 하나로 받고, C_u 의 바인딩은 π_u(시그마) 대신 세션마다 제출하는 Groth16 π_IdP(lib/mode3_idp_proof.js)가 진다.
// 자격증명(토큰) 은 (Cf_u, Cf_s, auid_s, arid_s, chainid, allowAgent) 위 IdP 서명이다(V11, 등록부 리프는 Poseidon(auid, Cf_u)).
// V9(2026-10-01 §3·§5): 폐기 트리는 세션 리프 sessionLeaf(Cf_s) = Poseidon(5, Cf_s) 하나만 남는다 — 사용자 리프
// Poseidon(4, Cf_u) 는 회로도 IdP 도 더 이상 쓰지 않는다. 사용자 자격증명의 활성 여부는 대신 공개 등록부(슬롯 트리,
// lib/mode3_registry.js: 당시 리프 = Poseidon(cm_u.x, cm_u.y, Cf_u). V11 부터는 cm_u 가 없고 리프 = Poseidon(auid, Cf_u), D4)로
// 옮겨갔다 — 지갑은 자기 슬롯이 자기 자격증명인지
// 로컬에서 먼저 대조하고(buildCredentialProof) 그 포함 증명을 회로 조건 9 로 낸다.
// V11(2026-10-12): auid 등록, 세션마다 π_IdP(lib/mode3_idp_proof.js), C_s = (pk_i, max_height, r_s; r_rp), 토큰 7인자, 공개 입력 33 — 스펙 2026-10-12.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, createHash } from 'node:crypto';
import { ethers } from 'ethers';
import { buildEddsa } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { randomScalar, SCALAR_MAX, ppid, normalizeAttrs, userCommit, sessionCommit, auidOf, auidSOf, aridSOf, MAX_HEIGHT_MAX, ATTR_MAX, ATTR_SLOTS } from './mode3_credential.js';
import { encryptTag } from './mode3_trace.js';
import { sessionLeaf, createRevocationTree, MODE3_TREE_DEPTH } from './mode3_revocation.js';
import { setPath, NO_SET } from './mode3_set_tree.js';
import { buildIMTv2 } from './imt_v2.js';
import { registryLeaf } from './mode3_registry.js';
import { issueRequestMessageV11, pointToStrings, slotRequestMessage, revokeSessionMessage, registerMessage } from './mode3_issuance.js';
import { proveIdp } from './mode3_idp_proof.js';
import { MODE3_LOG_ABI } from './mode3_log.js';
export { createRegistrySync, syncRegistryTree } from './mode3_registry_sync.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
export const WASM_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_cred_js', 'pi_cred.wasm');
export const ZKEY_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_cred_final.zkey');
export const VKEY_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_cred_vkey.json');

let eddsaP = null;
const getEddsa = () => (eddsaP ??= buildEddsa());

/** EdDSA-Poseidon 공개키 (circomlibjs eddsa.prv2pub). sk_u 는 32바이트 hex. */
export async function eddsaPubOf(sk_uHex) {
  const eddsa = await getEddsa();
  const pub = eddsa.prv2pub(Buffer.from(sk_uHex, 'hex'));
  return { x: eddsa.F.toObject(pub[0]), y: eddsa.F.toObject(pub[1]) };
}

/** V11 §3.1 — s_u 는 randomScalar(2^250 미만), auid = Poseidon(T_AUID, uid, s_u) 를 IdP 에 낸다(cm_u·r_u 는 없어졌다). 등록 키 (sk_u, pk_u) 도 여기서 만든다 — IdP 는 pk_u 만 받는다. */
/** 복구 시드(2026-10-21): 32바이트 시드에서 s_u(2^250 미만, randomScalar 와 같은 범위)·sk_u 를 SHA-256 으로 결정적으로 유도한다.
 *  시드(복구 코드)만 보관하면 브라우저 저장소가 지워져도 같은 s_u 로 돌아와 모든 RP 에서 PPID 가 그대로다. 브라우저 번들에서는 createHash 쉼(lib/browser)이 돈다. */
export function registrationSecretsFromSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('registrationSecretsFromSeed: seed 는 32바이트');
  const h = (tag) => createHash('sha256').update(new Uint8Array(seed)).update(tag).digest();
  let v = 0n; for (const b of h('zkd3/s_u')) v = (v << 8n) | BigInt(b);
  return { s_u: v & (SCALAR_MAX - 1n), sk_u: h('zkd3/sk_u').toString('hex') };
}
export async function createRegistration(uid, seed = randomBytes(32)) {
  if (typeof uid !== 'bigint') throw new Error('createRegistration(uid: bigint) — auid = Poseidon(T_AUID, uid, s_u) 를 계산하려면 uid 가 필요하다');
  const { s_u, sk_u } = registrationSecretsFromSeed(new Uint8Array(seed));   // 2026-10-21: 난수 대신 시드에서 유도(복구 코드)
  return { s_u, auid: await auidOf({ uid, s_u }), sk_u, pk_u: await eddsaPubOf(sk_u), seed: Buffer.from(seed).toString('hex') };
}

/** 세션키 = secp256k1. pk_i 는 주소(160비트) — 회로의 Num2Bits(160) 과 맞는다. */
export function createSessionKey() {
  const wallet = ethers.Wallet.createRandom();
  return { wallet, pk_i: BigInt(wallet.address) };
}

/**
 * 지갑이 정하는 만료(설계 2026-09-18 §3.2 갱신): max_height = ceil((head + ttl) / grid) × grid. 그리드로 뭉개는 이유는 V11 은 이 값을
 * π_IdP 공개 입력으로 보고 기록만 하기 때문이다(AA 가 직접 서명하지 않는다 — C_s 가 덮고 토큰 서명이 Cf_s 를 덮는다) — 같은 창의
 * 발급이 같은 값을 가져야 AA 가 시각으로 특정하지 못한다(§2). 검증자는
 * head ≤ max_height ≤ head + L 을 요구하므로 ttl + grid 가 L 을 넘지 않아야 한다.
 */
export function chooseMaxHeight(head, { ttlBlocks = 300n, grid = 100n } = {}) {
  for (const [k, v] of [['head', head], ['ttlBlocks', ttlBlocks], ['grid', grid]]) if (typeof v !== 'bigint' || v < 0n) throw new Error(`chooseMaxHeight: ${k} 는 음이 아닌 bigint`);
  if (grid === 0n) throw new Error('chooseMaxHeight: grid 는 양수');
  return ((head + ttlBlocks + grid - 1n) / grid) * grid;
}

const sigStrings = (F, s) => ({ R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() });

/** /cia/slot 요청 서명 = Sign(sk_u, Poseidon(D_SLOTREQ, uid, nonce)) — 옛 상태 파일이 슬롯 번호를 되찾을 때(V9 §5). */
export async function signSlotRequest(sk_uHex, uid, nonce) {
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await slotRequestMessage(uid, nonce))));
}

/** /cia/revoke scope=session 요청 서명 = Sign(sk_u, Poseidon(D_REVOKESESS, uid, Cf_s, nonce)) (설계 2026-09-24 §2.2). */
export async function signRevokeSession(sk_uHex, uid, Cf_s, nonce) {
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await revokeSessionMessage(uid, Cf_s, nonce))));
}

/** /cia/register 소유 증명 = Sign(sk_u, Poseidon(D_REGISTER_V2, uid, auid)). */
export async function signRegistration(sk_uHex, uid, auid) {
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await registerMessage(uid, auid))));
}

/**
 * /wallet/tx 의 disclose([{lo,hi}|null ×1..6]) 를 회로 입력 { mask, lo[6], hi[6] } 로. 지갑이 먼저 lo ≤ a_k ≤ hi 를 확인한다 —
 * 안 맞으면 증명이 어차피 안 만들어진다(reason 'disclosure_unsatisfiable'). 형식·범위 오류는 'bad_disclosure'.
 */
export function normalizeDisclosure(disclose, attrs) {
  const fail = (reason, msg) => Object.assign(new Error(msg ?? reason), { reason });
  if (disclose === undefined || disclose === null) return { mask: 0n, lo: Array(ATTR_SLOTS).fill(0n), hi: Array(ATTR_SLOTS).fill(0n) };
  if (!Array.isArray(disclose) || disclose.length === 0 || disclose.length > ATTR_SLOTS) throw fail('bad_disclosure', 'disclose 는 길이 1..6 배열');
  let mask = 0n; const lo = Array(ATTR_SLOTS).fill(0n), hi = Array(ATTR_SLOTS).fill(0n);
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
 * RP 가 준 root 를 믿지 않는다(증명하는 사실은 항상 "내 속성 ∈ 내가 받은 members"). 없으면 NO_SET.
 */
export async function normalizeSet(set, attrs) {
  const fail = (reason, msg) => Object.assign(new Error(msg ?? reason), { reason });
  if (set === undefined || set === null) return NO_SET;
  if (typeof set !== 'object' || Array.isArray(set)) throw fail('bad_disclosure', 'set 은 { slot, members } 객체');
  const { slot, members } = set;
  if (!Number.isInteger(slot) || slot < 0 || slot >= ATTR_SLOTS) throw fail('bad_disclosure', 'set.slot 은 정수 0..5');
  const { index, path, root } = await setPath(members, attrs[slot]);   // bad_disclosure / disclosure_unsatisfiable 를 그대로 올린다
  return { sel: BigInt(slot) + 1n, root, index, path };
}

/** 술어가 하나라도 있으면(범위 또는 집합) 캐시 π 를 못 쓰고 새로 증명한다. */
export const hasPredicate = (d) => Boolean(d) && (d.mask !== 0n || (d.sel ?? 0n) !== 0n);

/** /cia/issue V11 요청 서명 = Sign(sk_u, Poseidon(D_ISSUEREQ_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height)). */
export async function signIssueRequest(sk_uHex, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height) {
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await issueRequestMessageV11(auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height))));
}

/**
 * 세션 발급 요청 V11(스펙 2026-10-12 §5.2, 그림 3 "DA request"). 한 요청에 (C_u, C_s, π_IdP, sig_u). 옛 /cia/user_cred 요청은 없어졌다 —
 * C_u 가 활성 자격증명과 다르면 IdP 가 등록부 슬롯을 갱신·게시한다(첫 로그인·속성 변경). blind_u 는 호출자가 정한다: 들고 있는
 * 사용자 자격증명을 재사용하면 그 blind_u, 새 C_u 가 필요하면 randomScalar(). auid 는 (uid, s_u) 에서 여기서 계산한다 — 시연
 * 덮어쓰기(가짜 s_u·uid)면 가짜 auid 로 증명돼 IdP 의 DB auid 와 어긋나 bad_idp_proof 가 된다(의도된 실패 경로).
 * r_rp·r_s 는 RP 챌린지의 값이다. max_height 는 지갑이 정한다(chooseMaxHeight).
 * fullProve 가 있으면 proveIdp 에 그대로 넘긴다(브라우저 워커 프록시 자리, 계획 2026-10-15 R7) — 없으면 proveIdp 자신의 기본값(snarkjs)이 쓰인다.
 */
export async function buildIssueRequest({ uid, s_u, blind_u, attrs, arid, r_rp, r_s, sk_u, session, chainid, allowAgent = 0n, max_height, idpWasmPath, idpZkeyPath, fullProve }) {
  for (const [k, v] of [['uid', uid], ['s_u', s_u], ['blind_u', blind_u], ['arid', arid], ['r_rp', r_rp], ['r_s', r_s], ['chainid', chainid]]) {
    if (typeof v !== 'bigint') throw new Error(`buildIssueRequest: ${k}(bigint) 가 필요하다`);
  }
  if (typeof allowAgent !== 'bigint' || (allowAgent !== 0n && allowAgent !== 1n)) throw new Error('buildIssueRequest: allowAgent 는 0n 또는 1n');
  if (typeof max_height !== 'bigint' || max_height < 0n || max_height >= MAX_HEIGHT_MAX) throw new Error('buildIssueRequest: max_height(bigint, < 2^64) 가 필요하다 — 지갑이 chooseMaxHeight 로 정한다');
  if (typeof session?.pk_i !== 'bigint') throw new Error('buildIssueRequest: session{pk_i} 가 필요하다(createSessionKey)');
  const a6 = normalizeAttrs(attrs);
  const cu = await userCommit({ uid, s_u, blind_u, attrs: a6 });
  const C_u_pt = { x: cu.Cx, y: cu.Cy };
  const cs = await sessionCommit({ pk_i: session.pk_i, max_height, r_s, r_rp });
  const C_s_pt = { x: cs.Cx, y: cs.Cy };
  const auid = await auidOf({ uid, s_u });
  const auid_s = await auidSOf({ auid, arid, r_rp });
  const arid_s = await aridSOf({ arid, r_rp });
  const idp = await proveIdp({ uid, s_u, blind_u, attrs: a6, arid, r_rp, pk_i: session.pk_i, r_s, auid, auid_s, C_u_pt, C_s_pt, max_height, ...(idpWasmPath ? { wasmPath: idpWasmPath } : {}), ...(idpZkeyPath ? { zkeyPath: idpZkeyPath } : {}), ...(fullProve ? { fullProve } : {}) });
  const body = {
    uid: uid.toString(), auid_s: auid_s.toString(), arid_s: arid_s.toString(),
    C_u_pt: pointToStrings(C_u_pt), C_s_pt: pointToStrings(C_s_pt),
    chainid: chainid.toString(), allowAgent: allowAgent.toString(), max_height: max_height.toString(),
    proof_idp: idp.proof,
    sig_u: await signIssueRequest(sk_u, auid_s, arid_s, cu.Cf, cs.Cf, chainid, allowAgent, max_height),
  };
  return { body, C_u_pt, Cf_u: cu.Cf, C_s_pt, Cf_s: cs.Cf, auid, auid_s, arid_s, idpPublicSignals: idp.publicSignals };
}

/**
 * §7.2 — Revoked 이벤트를 처음부터 재생해 트리를 재구성한다. IdP 없이도 된다는 것이 요점이다.
 * 재구성한 root 가 컨트랙트 root 와 다르면 throw — 릴레이어가 calldata 를 오염시켰거나
 * (서명이 리프까지 덮으므로 이론상 불가) 이 라이브러리와 IdP 의 리프 규약이 어긋난 것이다.
 * 의도적으로 fail-closed: 데이터 가용성이 깨진 채로 (틀렸을 수 있는) 트리를 조용히
 * 돌려주면, 지갑이 실제로는 비어있지 않은 비멤버십 증명을 만들어 낼 수 있다.
 *
 * ethers v6 는 getLogs·getBlockNumber 결과를 250 ms(cacheTimeout) 캐시한다. eth_call 은
 * 캐시하지 않는다. 모든 조회를 head 블록에 고정하면 (1) 네 RPC 가 같은 블록의 일관된
 * 스냅샷을 보고 (2) toBlock 이 sync 마다 달라져 캐시된 로그가 섞이지 않는다. head 자체가
 * 250 ms 묵을 수는 있으며 그 경우 스냅샷 전체가 그만큼 옛 블록일 뿐 불일치는 아니다.
 * 테스트처럼 게시 직후 즉시 동기화해야 하면 provider 를 `{ cacheTimeout: -1 }` 로 만들 것.
 *
 * V10(2026-10-02 §7/§9) — untilEpoch·expectRoot: 거울(Mode3Mirror)은 캐노니컬 로그보다 뒤처질 수 있어, 지갑이
 * 거울의 (revRoot, epoch) 로 검증하려면 "그 epoch 까지만" 재생할 수 있어야 한다(Task 9). untilEpoch 가 있으면
 * args.epoch 가 그보다 큰 Revoked 는 건너뛰고, 대조는 컨트랙트의 최신 root 대신 호출자가 준 expectRoot(거울의
 * revRoot)와 한다 — expectRoot 가 null 이면 대조를 생략한다(호출자 책임). untilEpoch 가 없으면 현행(최신 root 대조) 그대로.
 */
export async function syncRevocationTree(provider, logAddress, { untilEpoch = null, expectRoot = null } = {}) {
  const log = new ethers.Contract(logAddress, MODE3_LOG_ABI, provider);
  const head = BigInt(await provider.getBlockNumber());
  const blockTag = Number(head);
  const [events, onchainRoot, onchainEpoch] = await Promise.all([
    log.queryFilter(log.filters.Revoked(), 0, blockTag),
    log.revRoot({ blockTag }),
    log.epoch({ blockTag }),
  ]);
  const leaves = [];
  for (const e of events) {
    if (untilEpoch !== null && BigInt(e.args.epoch) > BigInt(untilEpoch)) continue;
    for (const l of e.args.leaves) leaves.push(BigInt(l));
  }
  const tree = leaves.length === 0 ? await createRevocationTree() : await buildIMTv2(MODE3_TREE_DEPTH, leaves);
  const root = tree.getRoot();
  if (untilEpoch === null) {
    if (root !== BigInt(onchainRoot)) {
      throw new Error(`재구성한 root(${root}) 가 컨트랙트 root(${BigInt(onchainRoot)}) 와 다르다 — 리프 규약 불일치 또는 calldata 오염`);
    }
    return { tree, root, epoch: onchainEpoch, head };
  }
  const epoch = BigInt(untilEpoch);
  if (expectRoot !== null && root !== BigInt(expectRoot)) {
    throw new Error(`폐기 트리 재생 root(${root}) 가 거울 revRoot(${BigInt(expectRoot)}) 와 다르다 — epoch ${epoch} 까지`);
  }
  return { tree, root, epoch, head };
}

const ZERO6 = Object.freeze(Array(ATTR_SLOTS).fill(0n));

/**
 * §5 — 공개 입력 33개의 순서는 circuits/pi_cred.circom 의 component main 선언(스펙 2026-10-12 Global Constraints) 그대로다 —
 * 드리프트를 피하려고 여기서 다시 나열하지 않는다. pk_trace 는 인증서 cert_s 에 실린 RP 의 조합 키다 — 호출자는 검증된 인증서의
 * 값만 넘겨야 한다. 태그의 r 은 여기서 새로 뽑는다(재검증으로 새 π 를 만들면 태그도 바뀐다). disclosure 를 안 주면(null) mask 0.
 * V11: auid_s·arid_s 는 비밀 r_rp 에서 다시 계산해 공개 입력 [30]·[31] 로 내고, r_s 는 [32] 로 낸다 — 발급 때와 같은 r_rp·r_s 가 아니면
 * 토큰 서명이 맞지 않아 회로가 거절한다. auid 는 **등록 때 IdP 에 낸 값**(파일의 공개 부분)으로 받아 등록부 대조에 쓴다 — 회로는 (uid, s_u) 로
 * 다시 계산하므로, 시연 덮어쓰기(가짜 s_u)는 로컬 대조를 통과하고 회로에서 죽어 호출자가 demo_proof_failed 로 보여 준다.
 * registry 는 동기화된 등록부 트리(lib/mode3_registry_sync.js), slot 은 내 등록 슬롯. 리프 = Poseidon(auid, Cf_u).
 * fullProve(기본 snarkjs.groth16.fullProve)는 브라우저가 워커 프록시를 꽂는 자리다(계획 2026-10-15 R7) — 호출 모양은 snarkjs 와 같다.
 */
export async function buildCredentialProof({ uid, arid, s_u, auid, blind_u, r_rp, r_s, pk_i, attrs, credential, pk_CIA, pk_trace, tree, registry, slot, disclosure = null, tagR = undefined, wasmPath = WASM_PATH, zkeyPath = ZKEY_PATH, fullProve = snarkjs.groth16.fullProve }) {
  for (const [k, v] of [['uid', uid], ['arid', arid], ['s_u', s_u], ['auid', auid], ['blind_u', blind_u], ['r_rp', r_rp], ['r_s', r_s], ['pk_i', pk_i]]) {
    if (typeof v !== 'bigint') throw new Error(`buildCredentialProof: ${k}(bigint) 가 필요하다`);
  }
  if (typeof pk_trace?.x !== 'bigint' || typeof pk_trace?.y !== 'bigint') throw new Error('buildCredentialProof: pk_trace{x,y}(bigint) 가 필요하다 — cert_s 에 실린 RP 조합 키');
  if (!registry || !Number.isInteger(slot)) throw new Error('buildCredentialProof: registry·slot 이 필요하다');
  const chainid = BigInt(credential.chainid);
  const PPID = await ppid({ uid, s_u, arid, chainid });
  const a6 = normalizeAttrs(attrs);
  const auid_s = await auidSOf({ auid, arid, r_rp });
  const arid_s = await aridSOf({ arid, r_rp });
  // 등록부 대조(V9 조건 9 → V11 리프) — 온체인에 내지 않고 여기서 먼저 "내 슬롯 = 내 자격증명" 을 확인한다(fail-closed).
  // 슬롯이 비어 있으면(0) 은퇴·아직 미게시, 다른 값이면 관리자 바꿔치기 등 — 호출자가 구분해 처리할 수 있도록 reason 을 싣는다.
  const expectedLeaf = await registryLeaf(auid, BigInt(credential.Cf_u));
  const onSlot = registry.leafAt(slot);
  if (onSlot !== expectedLeaf) throw Object.assign(new Error(onSlot === 0n ? 'registry_empty' : 'registry_mismatch'), { reason: onSlot === 0n ? 'registry_empty' : 'registry_mismatch', slot, expected: expectedLeaf.toString(), actual: onSlot.toString() });
  const regPath = registry.path(slot);
  const regRoot = registry.root();
  // 세션 리프 비멤버십 증인 — 세션이 폐기됐으면 여기서 "is a member" 로 던진다.
  const ws = await tree.getNonMembershipWitness(await sessionLeaf(BigInt(credential.Cf_s)));
  // 공개 입력 revRoot 는 이 증인이 계산된 root 로 고정한다(트리 객체를 여러 요청이 공유할 수 있다 — 스펙 2026-09-23 §5).
  const revRoot = BigInt(ws.root);
  // tagR 은 테스트 전용 — 태그 난수를 주입해 같은 c1 을 가진 트랜스크립트를 만든다(IdP 개봉 dup 키 회귀). 운영 경로는 넘기지 않는다.
  const tag = tagR === undefined ? await encryptTag(pk_trace, uid, arid) : await encryptTag(pk_trace, uid, arid, tagR);
  const disc = disclosure ?? { mask: 0n, lo: ZERO6, hi: ZERO6 };
  const st = { sel: disc.sel ?? NO_SET.sel, root: disc.root ?? NO_SET.root, index: disc.index ?? 0, path: disc.path ?? NO_SET.path };
  const input = {
    uid: uid.toString(), s_u: s_u.toString(), blind_u: blind_u.toString(), r_rp: r_rp.toString(),
    attrs: a6.map(String),
    S: credential.sigma.S, R8x: credential.sigma.R8x, R8y: credential.sigma.R8y,
    s_lowValue: String(ws.lowValue), s_lowNextIndex: String(ws.lowNextIndex), s_lowNextValue: String(ws.lowNextValue),
    s_pathElements: ws.pathElements.map(String), s_pathIndices: ws.pathIndices.map(String),
    reg_pathElements: regPath.pathElements.map(String), reg_pathIndices: regPath.pathIndices.map(String),
    r: tag.r.toString(),
    PPID: PPID.toString(), arid: arid.toString(), pk_i: pk_i.toString(),
    max_height: BigInt(credential.max_height).toString(), chainid: chainid.toString(),
    allowAgent: BigInt(credential.allowAgent).toString(), revRoot: revRoot.toString(), regRoot: regRoot.toString(),
    pk_CIA_x: pk_CIA.x.toString(), pk_CIA_y: pk_CIA.y.toString(),
    pk_trace_x: pk_trace.x.toString(), pk_trace_y: pk_trace.y.toString(),
    tag_c1_x: tag.c1.x.toString(), tag_c1_y: tag.c1.y.toString(), tag_c2: tag.c2.toString(),
    disc_mask: disc.mask.toString(), disc_lo: disc.lo.map(String), disc_hi: disc.hi.map(String),
    set_sel: st.sel.toString(), set_root: st.root.toString(), set_index: String(st.index), set_path: [...st.path].map(String),
    auid_s: auid_s.toString(), arid_s: arid_s.toString(), r_s: r_s.toString(),
  };
  const { proof, publicSignals } = await fullProve(input, wasmPath, zkeyPath);
  return { proof, publicSignals, revRoot, regRoot, tag: { c1: tag.c1, c2: tag.c2, h: tag.h } };
}

/** §8.4 — π 는 root 가 바뀔 때까지 재사용. 세션이 바뀌면 pk_i 가 달라 재사용 불가. discKey 가 다르면(선택 공개 조건이 다르면) 별개 항목이다. */
export class ProofCache {
  #m = new Map();
  // V10(2026-10-02): 칸 구분자는 '|' — rootKey 가 이제 'chainId:rev:reg' 로 ':' 를 품는다(브리프 형식). discKey 에도 ':' 가 있어
  // ':' 로 나누면 sessionId 자리를 찾을 수 없다. 세 칸 어디에도 '|' 는 없다(10진 문자열·disclosureKey 는 ':'·',' 만 쓴다).
  #key(root, sessionId, discKey) { return `${root}|${sessionId}|${discKey}`; }
  get(root, sessionId, discKey = '0') { return this.#m.get(this.#key(root, sessionId, discKey)) ?? null; }
  set(root, sessionId, value, discKey = '0') { this.#m.set(this.#key(root, sessionId, discKey), value); }
  /** 한 세션(r_s)의 캐시 항목을 전부 지운다 — 세션 만료 정리에서 부른다. 키는 `${root}|${sessionId}|${discKey}` 이고
   *  세 칸 모두 '|' 가 없다 — 그래서 두 번째 필드만 대조한다. */
  deleteSession(sessionId) { for (const k of [...this.#m.keys()]) if (k.split('|')[1] === String(sessionId)) this.#m.delete(k); }
  clear() { this.#m.clear(); }
  /** V9 — root 자리에 두 트리의 root(revRoot, regRoot)를 같이 넣을 때 쓰는 합성 키. V10(2026-10-02 §5): 대상 체인 id 를
   *  앞에 붙인다 — 지갑은 체인마다 그 체인 거울의 (revRoot, regRoot) 로 증명하므로, 같은 root 쌍이라도 체인이 다르면 다른 항목이다.
   *  옛 2인자 호출은 조용히 'rev:reg:undefined' 같은 키를 만들지 않도록 던진다. */
  static rootKey(chainId, rev, reg) {
    if (reg === undefined) throw new Error('ProofCache.rootKey(chainId, rev, reg) — 인자 3개가 필요하다');
    return `${chainId}:${rev}:${reg}`;
  }
}

/** 요청마다 새 σ. EIP-191 personal sign — RP 는 ethers.verifyMessage 로 주소를 복원해 pk_i 와 대조한다. */
export function signChallenge(wallet, challenge) {
  return wallet.signMessage(challenge);
}

/** 세션 안 후속 요청 서명 (설계 §7). 메시지 = `${r_s}:${body}` 위 EIP-191. */
export function signSessionRequest(wallet, r_s, body) {
  return wallet.signMessage(`${r_s.toString()}:${body}`);
}
