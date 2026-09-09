// pi_cred 회로용 공유 입력 픽스처.
// tests/test_pi_cred_witness.mjs와 scripts/bench_pi_cred.mjs가 같은 입력
// 생성기를 써야 두 측정(정확성 검증 / 증명 시간 실측)이 같은 것을 재게 된다.
import { buildPoseidon, buildEddsa } from 'circomlibjs';
import { credLeaf, createRevocationTree } from '../../lib/mode3_revocation.js';
import { credCommit, credMessage, ppid as computePpid } from '../../lib/mode3_credential.js';

// --- 정상 입력 하나를 만든다 -------------------------------------------------
// C(커밋)도 함께 돌려준다 — 폐기 후 root를 만드는 등 호출부가 C를 다시 계산할
// 필요 없이 재사용하도록.
export async function buildValidInput() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const eddsa = await buildEddsa();

  const uid   = 11111111111111111111n;
  const arid  = 22222222222222222222n;
  const s_u   = 33333333333333333333n;
  const blind = 44444444444444444444n;
  const pk_i  = 0x1234567890123456789012345678901234567890n; // 160비트
  const max_height = 1000n;

  const C = await credCommit({ uid, arid, s_u, blind, pk_i });
  const PPID = await computePpid({ uid, arid, s_u });
  const msg = await credMessage(C, max_height);

  // CIA 서명키. 테스트 고정값이며 실제 키가 아니다.
  const prv = Buffer.from('0001020304050607080900010203040506070809000102030405060708090001', 'hex');
  const pub = eddsa.prv2pub(prv);
  const sig = eddsa.signPoseidon(prv, F.e(msg));

  // 폐기 트리에 남의 폐기를 하나 넣어 둔다 — 내 비멤버십은 여전히 성립해야 한다.
  const tree = await createRevocationTree();
  await tree.insert(await credLeaf(999n));
  const w = await tree.getNonMembershipWitness(await credLeaf(C));

  const input = {
    uid: uid.toString(),
    s_u: s_u.toString(),
    blind: blind.toString(),
    S: sig.S.toString(),
    R8x: F.toObject(sig.R8[0]).toString(),
    R8y: F.toObject(sig.R8[1]).toString(),
    lowValue: w.lowValue.toString(),
    lowNextIndex: w.lowNextIndex.toString(),
    lowNextValue: w.lowNextValue.toString(),
    pathElements: w.pathElements.map(String),
    pathIndices: w.pathIndices.map(String),
    PPID: PPID.toString(),
    arid: arid.toString(),
    pk_i: pk_i.toString(),
    max_height: max_height.toString(),
    revRoot: tree.getRoot().toString(),
    pk_CIA_x: F.toObject(pub[0]).toString(),
    pk_CIA_y: F.toObject(pub[1]).toString(),
  };

  return { input, C };
}
