// pi_cred 회로용 공유 입력 픽스처 (V9 — 설계 2026-10-01 §5).
// tests/test_pi_cred_witness.mjs, scripts/bench_pi_cred.mjs, test/Mode3Wallet.test.mjs 가 같은 입력 생성기를 쓴다.
import { buildPoseidon, buildEddsa, buildBabyjub } from 'circomlibjs';
import { sessionLeaf, createRevocationTree } from '../../lib/mode3_revocation.js';
import { userCommit, sessionCommit, credMessageV5, ppid as computePpid } from '../../lib/mode3_credential.js';
import { registrationCommit } from '../../lib/mode3_issuance.js';
import { createRegistryTree, registryLeaf } from '../../lib/mode3_registry.js';
import { combinePublicKey, encryptTag } from '../../lib/mode3_trace.js';
import { setPath, NO_SET } from '../../lib/mode3_set_tree.js';

export const ZERO6 = Object.freeze([0n, 0n, 0n, 0n, 0n, 0n]);
export const FIXTURE_ATTRS = Object.freeze([1990n, 410n, 2n, 0n, 0n, 0n]);   // 데모 testuser 와 같은 값(cia.js DEMO_ACCOUNTS)

/** 정상 입력 하나. 옵션: pk_i(실제 세션키 주소), maxHeight, allowAgent, chainid, disclosure{mask, lo[6], hi[6]}, set{slot 0..5, members},
 *  revokedSessions(남의 세션 리프), registrySlot(기본 7), registryLeafOverride(음성용 — 슬롯에 넣을 리프를 강제). */
export async function buildValidInput({ pk_i: pkIOpt, maxHeight = 1789000000n, allowAgent = 0n, chainid = 31337n, disclosure = null, set = null, revokedSessions = [], registrySlot = 7, registryLeafOverride = null } = {}) {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const eddsa = await buildEddsa();

  const uid     = 11111111111111111111n;
  const arid    = 22222222222222222222n;
  const s_u     = 33333333333333333333n;
  const r_u     = 99999999999999999999n;   // V9: 등록 커밋 블라인딩
  const blind_u = 44444444444444444444n;
  const blind_s = 55555555555555555555n;
  const pk_i    = pkIOpt ?? 0x1234567890123456789012345678901234567890n;
  const attrs   = [...FIXTURE_ATTRS];
  const max_height = maxHeight;

  const bj = await buildBabyjub();
  const shareOf = (x) => ({ x, X: { x: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[0]), y: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[1]) } });
  const shares = { svc: shareOf(66666666666666666666n), aa: shareOf(77777777777777777777n) };
  const pk_trace = await combinePublicKey(shares.svc.X, shares.aa.X);
  const tag = await encryptTag(pk_trace, uid, arid, 88888888888888888888n);

  const { Cf: Cf_u } = await userCommit({ uid, s_u, blind_u, attrs });
  const { Cf: Cf_s } = await sessionCommit({ arid, pk_i, blind_s });
  const PPID = await computePpid({ uid, arid, s_u, chainid });
  const msg = await credMessageV5(Cf_u, Cf_s, max_height, chainid, allowAgent);

  const prv = Buffer.from('0001020304050607080900010203040506070809000102030405060708090001', 'hex');
  const pub = eddsa.prv2pub(prv);
  const sig = eddsa.signPoseidon(prv, F.e(msg));
  const ciaPub = { x: F.toObject(pub[0]), y: F.toObject(pub[1]) };

  // 폐기 트리: 남의 세션 폐기 리프만(V9 — 사용자 리프 없음). 내 세션 비멤버십은 성립해야 한다.
  const tree = await createRevocationTree();
  await tree.insert(await sessionLeaf(999n));
  for (const c of revokedSessions) await tree.insert(await sessionLeaf(BigInt(c)));
  const ws = await tree.getNonMembershipWitness(await sessionLeaf(Cf_s));

  // 등록부: 남의 슬롯 둘 + 내 슬롯(registrySlot). 리프 = Poseidon(cm_u.x, cm_u.y, Cf_u).
  const cm_u = await registrationCommit(s_u, r_u);
  const registry = await createRegistryTree();
  if (registrySlot === 0 || registrySlot === 3) throw new Error('registrySlot 은 남의 슬롯(0, 3)과 겹칠 수 없다');
  registry.set(0, 12345n);
  registry.set(3, 67890n);
  const myLeaf = registryLeafOverride ?? await registryLeaf(cm_u, Cf_u);
  registry.set(registrySlot, myLeaf);
  const rp = registry.path(registrySlot);

  const disc = disclosure ?? { mask: 0n, lo: [...ZERO6], hi: [...ZERO6] };
  let st = NO_SET;
  if (set) {
    const { index, path, root } = await setPath(set.members, attrs[set.slot]);
    st = { sel: BigInt(set.slot) + 1n, root, index, path };
  }

  const input = {
    uid: uid.toString(), s_u: s_u.toString(), r_u: r_u.toString(), blind_u: blind_u.toString(), blind_s: blind_s.toString(), attrs: attrs.map(String),
    S: sig.S.toString(), R8x: F.toObject(sig.R8[0]).toString(), R8y: F.toObject(sig.R8[1]).toString(),
    s_lowValue: ws.lowValue.toString(), s_lowNextIndex: ws.lowNextIndex.toString(), s_lowNextValue: ws.lowNextValue.toString(),
    s_pathElements: ws.pathElements.map(String), s_pathIndices: ws.pathIndices.map(String),
    reg_pathElements: rp.pathElements.map(String), reg_pathIndices: rp.pathIndices.map(String),
    r: tag.r.toString(),
    PPID: PPID.toString(), arid: arid.toString(), pk_i: pk_i.toString(),
    max_height: max_height.toString(), chainid: chainid.toString(), allowAgent: allowAgent.toString(),
    revRoot: tree.getRoot().toString(), regRoot: registry.root().toString(),
    pk_CIA_x: ciaPub.x.toString(), pk_CIA_y: ciaPub.y.toString(),
    pk_trace_x: pk_trace.x.toString(), pk_trace_y: pk_trace.y.toString(),
    tag_c1_x: tag.c1.x.toString(), tag_c1_y: tag.c1.y.toString(), tag_c2: tag.c2.toString(),
    disc_mask: disc.mask.toString(), disc_lo: disc.lo.map(String), disc_hi: disc.hi.map(String),
    set_sel: st.sel.toString(), set_root: st.root.toString(), set_index: String(st.index), set_path: st.path.map(String),
  };

  return { input, Cf_u, Cf_s, pk_trace, shares, tag, ciaPub, arid, uid, tree, registry, slot: registrySlot, cm_u, attrs, disclosure: disc, set: st };
}
