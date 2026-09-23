// pi_cred 회로용 공유 입력 픽스처 (V5 — 설계 2026-09-21 §5).
// tests/test_pi_cred_witness.mjs, scripts/bench_pi_cred.mjs, test/Mode3Wallet.test.mjs 가 같은 입력 생성기를 쓴다.
import { buildPoseidon, buildEddsa, buildBabyjub } from 'circomlibjs';
import { userLeaf, createRevocationTree } from '../../lib/mode3_revocation.js';
import { userCommit, sessionCommit, credMessageV5, ppid as computePpid } from '../../lib/mode3_credential.js';
import { combinePublicKey, encryptTag } from '../../lib/mode3_trace.js';
import { setPath, NO_SET } from '../../lib/mode3_set_tree.js';

// --- 정상 입력 하나를 만든다 -------------------------------------------------
// 옵션은 컨트랙트 테스트용이다: pk_i 는 실제 세션키의 주소, maxHeight 는 만료 케이스, allowAgent 는 플래그 케이스.
export async function buildValidInput({ pk_i: pkIOpt, maxHeight = 1789000000n, allowAgent = 0n, chainid = 31337n, disclosure = null, set = null } = {}) {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const eddsa = await buildEddsa();

  const uid     = 11111111111111111111n;
  const arid    = 22222222222222222222n;
  const s_u     = 33333333333333333333n;
  const blind_u = 44444444444444444444n;
  const blind_s = 55555555555555555555n;
  const pk_i    = pkIOpt ?? 0x1234567890123456789012345678901234567890n; // 160비트
  const attrs   = [1990n, 410n, 2n, 0n];   // 데모 testuser 와 같은 값(스펙 2026-09-22 §3.1) — 64비트
  const max_height = maxHeight;   // 블록 높이. 회로는 값만 통과시키고 검증자가 비교한다

  // 트레이스 태그(설계 2026-09-16 §4.1, 평문은 2026-09-18 §3.4). 조각은 테스트 고정값 — 실제 키가 아니다. r 도 고정.
  const bj = await buildBabyjub();
  const shareOf = (x) => ({ x, X: { x: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[0]), y: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[1]) } });
  const shares = { svc: shareOf(66666666666666666666n), aa: shareOf(77777777777777777777n) };
  const pk_trace = await combinePublicKey(shares.svc.X, shares.aa.X);
  const tag = await encryptTag(pk_trace, uid, arid, 88888888888888888888n);

  // 커밋 둘(2026-09-21 §3): 사용자 자격증명 C_u(사용자당 하나)와 세션 커밋 C_s(세션마다). 서명은 둘 다 덮는다.
  const { Cf: Cf_u } = await userCommit({ uid, s_u, blind_u, attrs });
  const { Cf: Cf_s } = await sessionCommit({ arid, pk_i, blind_s });
  const PPID = await computePpid({ uid, arid, s_u, chainid });
  const msg = await credMessageV5(Cf_u, Cf_s, max_height, chainid, allowAgent);

  // CIA 서명키. 테스트 고정값이며 실제 키가 아니다.
  const prv = Buffer.from('0001020304050607080900010203040506070809000102030405060708090001', 'hex');
  const pub = eddsa.prv2pub(prv);
  const sig = eddsa.signPoseidon(prv, F.e(msg));
  const ciaPub = { x: F.toObject(pub[0]), y: F.toObject(pub[1]) };

  // 폐기 트리에 남의 폐기를 하나 넣어 둔다 — 내 비멤버십은 여전히 성립해야 한다. 리프는 Cf_u 에서(§3.6).
  const tree = await createRevocationTree();
  await tree.insert(await userLeaf(999n));
  const w = await tree.getNonMembershipWitness(await userLeaf(Cf_u));

  const disc = disclosure ?? { mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n] };

  // V7 집합 소속(spec §3): set = { slot: 0..3, members: [...] } 이면 attrs[slot] 의 경로를 만든다. 없으면 NO_SET.
  let st = NO_SET;
  if (set) {
    const { index, path, root } = await setPath(set.members, attrs[set.slot]);
    st = { sel: BigInt(set.slot) + 1n, root, index, path };
  }

  const input = {
    uid: uid.toString(), s_u: s_u.toString(), blind_u: blind_u.toString(), blind_s: blind_s.toString(), attrs: attrs.map(String),
    S: sig.S.toString(), R8x: F.toObject(sig.R8[0]).toString(), R8y: F.toObject(sig.R8[1]).toString(),
    lowValue: w.lowValue.toString(), lowNextIndex: w.lowNextIndex.toString(), lowNextValue: w.lowNextValue.toString(),
    pathElements: w.pathElements.map(String), pathIndices: w.pathIndices.map(String),
    r: tag.r.toString(),
    PPID: PPID.toString(), arid: arid.toString(), pk_i: pk_i.toString(),
    max_height: max_height.toString(), chainid: chainid.toString(), allowAgent: allowAgent.toString(),
    revRoot: tree.getRoot().toString(),
    pk_CIA_x: ciaPub.x.toString(), pk_CIA_y: ciaPub.y.toString(),
    pk_trace_x: pk_trace.x.toString(), pk_trace_y: pk_trace.y.toString(),
    tag_c1_x: tag.c1.x.toString(), tag_c1_y: tag.c1.y.toString(), tag_c2: tag.c2.toString(),
    disc_mask: disc.mask.toString(), disc_lo: disc.lo.map(String), disc_hi: disc.hi.map(String),
    set_sel: st.sel.toString(), set_root: st.root.toString(), set_index: String(st.index), set_path: st.path.map(String),
  };

  return { input, Cf_u, Cf_s, pk_trace, shares, tag, ciaPub, arid, uid, tree, attrs, disclosure: disc, set: st };
}
