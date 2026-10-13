// pi_idp 회로용 입력 픽스처(V11 §4). tests/test_pi_idp_witness.mjs·scripts/bench_pi_idp.mjs 가 쓴다.
// 상수는 tests/helpers/mode3_fixture.mjs(pi_cred)와 같은 값을 쓴다 — 두 회로가 같은 세션을 본다.
import { userCommit, sessionCommit, auidOf, auidSOf, aridSOf } from '../../lib/mode3_credential.js';

export const IDP_FIXTURE = Object.freeze({
  uid: 11111111111111111111n, s_u: 33333333333333333333n, blind_u: 44444444444444444444n,
  arid: 22222222222222222222n, r_rp: 12121212121212121212n, r_s: 13131313131313131313n,
  pk_i: 0x1234567890123456789012345678901234567890n, attrs: Object.freeze([1990n, 410n, 2n, 0n, 0n, 0n]), max_height: 1789000000n,
});

/** 정상 입력 하나. 옵션으로 attrs·maxHeight·pk_i·r_s·r_rp 를 바꿀 수 있다(값은 자유 — IdP 는 속성을 보지 않는다, D15). */
export async function buildIdpInput({ attrs = IDP_FIXTURE.attrs, maxHeight = IDP_FIXTURE.max_height, pk_i = IDP_FIXTURE.pk_i, r_s = IDP_FIXTURE.r_s, r_rp = IDP_FIXTURE.r_rp } = {}) {
  const { uid, s_u, blind_u, arid } = IDP_FIXTURE;
  const a = [...attrs];
  const cu = await userCommit({ uid, s_u, blind_u, attrs: a });
  const cs = await sessionCommit({ pk_i, max_height: maxHeight, r_s, r_rp });
  const auid = await auidOf({ uid, s_u });
  const auid_s = await auidSOf({ auid, arid, r_rp });
  const arid_s = await aridSOf({ arid, r_rp });
  const input = {
    s_u: s_u.toString(), blind_u: blind_u.toString(), attrs: a.map(String), arid: arid.toString(), r_rp: r_rp.toString(), pk_i: pk_i.toString(), r_s: r_s.toString(),
    uid: uid.toString(), auid: auid.toString(), auid_s: auid_s.toString(), C_u_x: cu.Cx.toString(), C_u_y: cu.Cy.toString(), C_s_x: cs.Cx.toString(), C_s_y: cs.Cy.toString(), max_height: maxHeight.toString(),
  };
  return { input, uid, s_u, arid, r_rp, r_s, pk_i, auid, auid_s, arid_s, C_u: { x: cu.Cx, y: cu.Cy, Cf: cu.Cf }, C_s: { x: cs.Cx, y: cs.Cy, Cf: cs.Cf }, attrs: a, max_height: maxHeight };
}
