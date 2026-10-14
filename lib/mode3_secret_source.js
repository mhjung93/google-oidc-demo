// 지갑 에이전트의 비밀 공급원 — 스펙 2026-09-22 metamask-snap §3.3, V11(2026-10-12) 갱신.
//   file: 상태 파일의 registration 이 비밀을 든다(자동 테스트·헤드리스 데모).
//   snap: 비밀은 요청에 첨부된 witness(Snap 이 동의 창 뒤에 내준 것)에서만 오고, 파일에는 공개 부분만 남는다. 에이전트는 Snap 을
//         부를 수 없으므로 새 C_u·attrs 는 pending 에 모아 응답에 실어 페이지가 Snap 에 저장하게 한다.
// V11: 등록 비밀은 { s_u, sk_u } 둘(r_u·cm_u 삭제). 증인과 등록의 바인딩은 auid = Poseidon(T_AUID, uid, s_u) 로 본다.
import { SCALAR_MAX, normalizeAttrs, auidOf } from './mode3_credential.js';

const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const isHex64 = (v) => typeof v === 'string' && /^[0-9a-fA-F]{64}$/.test(v);
const isPt = (p) => p && isDec(p.x) && isDec(p.y);

export function stripSecrets(registration) {
  if (!registration) return null;
  const { uid, auid, pk_u, slot, attrs, profile = null, userCred } = registration;
  return { uid, auid, pk_u, slot, attrs, profile, userCred: userCred ? { Cf_u: userCred.Cf_u, issuedAt: userCred.issuedAt } : null };
}

/**
 * 증인 형식 검사. `publicAuid`(파일의 공개 `registration.auid`)를 주면 **증인이 그 등록에 실제로 묶였는지**까지 본다 —
 * Poseidon(T_AUID, uid, s_u) 가 등록 때 IdP 에 낸 auid 와 같아야 한다(2026-09-22 최종 리뷰 Minor 1 의 cm_u 바인딩을 V11 식으로).
 * 이 검사가 없으면 형식만 맞는 아무 s_u 나 받아 이 지갑의 등록과 무관한 증명 시도로 이어진다.
 */
export async function validateWitness(w, publicUid, publicAuid = null) {
  const fail = (msg) => { throw Object.assign(new Error(`bad_witness: ${msg}`), { reason: 'bad_witness' }); };
  if (!w || typeof w !== 'object') fail('witness 없음');
  if (!isDec(w.uid) || w.uid !== publicUid) fail('uid 가 등록과 다르다');
  if (!isDec(w.s_u) || BigInt(w.s_u) >= SCALAR_MAX) fail('s_u 범위');
  if (!isHex64(w.sk_u)) fail('sk_u 형식');
  if (!Array.isArray(w.attrs) || w.attrs.length !== 6 || !w.attrs.every(isDec)) fail('attrs 형식(10진 문자열 6개)');
  try { normalizeAttrs(w.attrs); } catch (e) { fail(`attrs: ${e.message}`); }
  if (w.userCred !== null && w.userCred !== undefined) {
    const u = w.userCred;
    if (!isPt(u.C_u_pt) || !isDec(u.Cf_u) || !isDec(u.blind_u) || BigInt(u.blind_u) >= SCALAR_MAX) fail('userCred 형식');
  }
  if (publicAuid !== null) {
    if (!isDec(publicAuid)) fail('등록의 auid 형식');
    const a = await auidOf({ uid: BigInt(w.uid), s_u: BigInt(w.s_u) });
    if (a.toString() !== publicAuid) fail('auid 가 등록과 다르다(s_u 불일치)');
  }
}

export function createSecretSource({ mode, state, witness = null }) {
  const pub = () => state.registration;
  if (mode === 'file') {
    return {
      mode, pending: {},
      registration: () => (pub() ? { uid: pub().uid, s_u: pub().s_u, sk_u: pub().sk_u, attrs: pub().attrs, auid: pub().auid, slot: pub().slot, pk_u: pub().pk_u, profile: pub().profile ?? null } : null),
      userCred: () => pub()?.userCred ?? null,
      setUserCred: (uc) => { state.registration.userCred = uc; },
      setAttrs: (attrs) => { state.registration.attrs = attrs; },
    };
  }
  if (mode !== 'snap') throw new Error(`unknown secret source mode: ${mode}`);
  const pending = {};
  return {
    mode, pending,
    registration: () => ((pub() && witness) ? { uid: pub().uid, s_u: witness.s_u, sk_u: witness.sk_u, attrs: witness.attrs, auid: pub().auid, slot: pub().slot, pk_u: pub().pk_u, profile: pub().profile ?? null } : null),
    userCred: () => witness?.userCred ?? null,
    setUserCred: (uc) => { pending.userCredIssued = uc; if (witness) witness.userCred = uc; state.registration.userCred = uc ? { Cf_u: uc.Cf_u, issuedAt: uc.issuedAt } : null; },
    setAttrs: (attrs) => { pending.attrsChanged = attrs; if (witness) witness.attrs = attrs; state.registration.attrs = attrs; },
  };
}
