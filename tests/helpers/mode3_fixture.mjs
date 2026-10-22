// pi_cred 회로용 공유 입력 픽스처 (V11 — 스펙 2026-10-12 §5.3).
// tests/test_pi_cred_witness.mjs, scripts/bench_pi_cred.mjs, test/Mode3Wallet.test.mjs 가 같은 입력 생성기를 쓴다.
import { buildPoseidon, buildEddsa, buildBabyjub } from 'circomlibjs';
import { sessionLeaf, sessionLeafRange, createRevocationTree } from '../../lib/mode3_revocation.js';
import { userCommit, sessionCommit, credMessageV11, ppid as computePpid, auidOf, auidSOf, aridSOf } from '../../lib/mode3_credential.js';
import { createRegistryTree, registryLeaf } from '../../lib/mode3_registry.js';
import { combinePublicKey, encryptTag } from '../../lib/mode3_trace.js';
import { setPath, NO_SET } from '../../lib/mode3_set_tree.js';
import { LOGIN_COUNTER } from '../../lib/mode3_onchain.js';

export const ZERO6 = Object.freeze([0n, 0n, 0n, 0n, 0n, 0n]);
export const FIXTURE_ATTRS = Object.freeze([1990n, 410n, 2n, 0n, 0n, 0n]);   // 회로 입력 벡터(스키마와 무관 — 스펙 2 §9). 값 2 는 옛 데모 등급이지만 회로·벤치 입력은 바꾸지 않는다(재현성).

/** 정상 입력 하나. 옵션: pk_i(실제 세션키 주소), maxHeight, allowAgent, chainid, disclosure{mask, lo[6], hi[6]}, set{slot 0..5, members},
 *  revokedSessions(남의 세션 폐기 리프, [{Cf_s, bound}]), registrySlot(기본 7), registryLeafOverride(음성용), r_s·r_rp(V11 세션 난수 — 기본은 고정값),
 *  counter(2026-10-22 §6.5 — 기본 LOGIN_COUNTER, "이 세션의 폐기 리프가 하나도 없다"). */
export async function buildValidInput({ pk_i: pkIOpt, maxHeight = 1789000000n, allowAgent = 0n, chainid = 31337n, disclosure = null, set = null, revokedSessions = [], registrySlot = 7, registryLeafOverride = null, r_s = 13131313131313131313n, r_rp = 12121212121212121212n, counter = LOGIN_COUNTER } = {}) {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const eddsa = await buildEddsa();

  const uid     = 11111111111111111111n;
  const arid    = 22222222222222222222n;
  const s_u     = 33333333333333333333n;
  const blind_u = 44444444444444444444n;
  const pk_i    = pkIOpt ?? 0x1234567890123456789012345678901234567890n;
  const attrs   = [...FIXTURE_ATTRS];
  const max_height = maxHeight;

  const bj = await buildBabyjub();
  const shareOf = (x) => ({ x, X: { x: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[0]), y: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[1]) } });
  const shares = { svc: shareOf(66666666666666666666n), aa: shareOf(77777777777777777777n) };
  const pk_trace = await combinePublicKey(shares.svc.X, shares.aa.X);
  const tag = await encryptTag(pk_trace, uid, arid, 88888888888888888888n);

  const { Cf: Cf_u } = await userCommit({ uid, s_u, blind_u, attrs });
  const { Cf: Cf_s } = await sessionCommit({ pk_i, max_height, r_s, r_rp });
  const auid = await auidOf({ uid, s_u });
  const auid_s = await auidSOf({ auid, arid, r_rp });
  const arid_s = await aridSOf({ arid, r_rp });
  const PPID = await computePpid({ uid, s_u, arid, chainid });
  const msg = await credMessageV11(auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent);

  const prv = Buffer.from('0001020304050607080900010203040506070809000102030405060708090001', 'hex');
  const pub = eddsa.prv2pub(prv);
  const sig = eddsa.signPoseidon(prv, F.e(msg));
  const ciaPub = { x: F.toObject(pub[0]), y: F.toObject(pub[1]) };

  // 폐기 트리: 남의 세션 폐기 리프만. 내 세션 구간 비멤버십([H'·2^32, H'·2^32 + counter])은 성립해야 한다(2026-10-22 §6.5).
  const tree = await createRevocationTree();
  await tree.insert(await sessionLeaf(999n, 0n));
  for (const { Cf_s: rCfS, bound: rBound } of revokedSessions) await tree.insert(await sessionLeaf(BigInt(rCfS), BigInt(rBound)));
  const { lo: sLo, hi: sHi } = await sessionLeafRange(Cf_s, counter);
  const ws = await tree.getRangeNonMembershipWitness(sLo, sHi);

  // 등록부: 남의 슬롯 둘 + 내 슬롯(registrySlot). 리프 = Poseidon(auid, Cf_u).
  const registry = await createRegistryTree();
  if (registrySlot === 0 || registrySlot === 3) throw new Error('registrySlot 은 남의 슬롯(0, 3)과 겹칠 수 없다');
  registry.set(0, 12345n);
  registry.set(3, 67890n);
  const myLeaf = registryLeafOverride ?? await registryLeaf(auid, Cf_u);
  registry.set(registrySlot, myLeaf);
  const rp = registry.path(registrySlot);

  const disc = disclosure ?? { mask: 0n, lo: [...ZERO6], hi: [...ZERO6] };
  let st = NO_SET;
  if (set) {
    const { index, path, root } = await setPath(set.members, attrs[set.slot]);
    st = { sel: BigInt(set.slot) + 1n, root, index, path };
  }

  const input = {
    uid: uid.toString(), s_u: s_u.toString(), blind_u: blind_u.toString(), r_rp: r_rp.toString(), attrs: attrs.map(String),
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
    auid_s: auid_s.toString(), arid_s: arid_s.toString(), r_s: r_s.toString(),
    counter: counter.toString(),
  };

  return { input, Cf_u, Cf_s, pk_trace, shares, tag, ciaPub, arid, uid, tree, registry, slot: registrySlot, auid, auid_s, arid_s, r_rp, r_s, attrs, disclosure: disc, set: st };
}
