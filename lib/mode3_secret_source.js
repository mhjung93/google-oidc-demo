// 지갑 에이전트의 비밀 공급원 — 스펙 2026-09-22 metamask-snap §3.3.
//   file: 지금처럼 상태 파일의 registration 이 비밀을 든다(자동 테스트·헤드리스 데모).
//   snap: 비밀은 요청에 첨부된 witness(Snap 이 동의 창 뒤에 내준 것)에서만 오고, 파일에는 공개 부분만 남는다. 에이전트는 Snap 을
//         부를 수 없으므로 새 C_u·attrs 는 pending 에 모아 응답에 실어 페이지가 Snap 에 저장하게 한다.
import { SCALAR_MAX, normalizeAttrs } from './mode3_credential.js';

const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const isHex64 = (v) => typeof v === 'string' && /^[0-9a-fA-F]{64}$/.test(v);
const isPt = (p) => p && isDec(p.x) && isDec(p.y);

export function stripSecrets(registration) {
  if (!registration) return null;
  const { uid, cm_u, attrs, userCred } = registration;
  return { uid, cm_u, attrs, userCred: userCred ? { Cf_u: userCred.Cf_u, leaf: userCred.leaf, issuedAt: userCred.issuedAt } : null };
}

export function validateWitness(w, publicUid) {
  const fail = (msg) => { throw Object.assign(new Error(`bad_witness: ${msg}`), { reason: 'bad_witness' }); };
  if (!w || typeof w !== 'object') fail('witness 없음');
  if (!isDec(w.uid) || w.uid !== publicUid) fail('uid 가 등록과 다르다');
  for (const k of ['s_u', 'r_u']) if (!isDec(w[k]) || BigInt(w[k]) >= SCALAR_MAX) fail(`${k} 범위`);
  if (!isHex64(w.sk_u)) fail('sk_u 형식');
  try { normalizeAttrs(w.attrs); } catch (e) { fail(`attrs: ${e.message}`); }
  if (!Array.isArray(w.attrs) || w.attrs.length !== 4) fail('attrs 길이');
  if (w.userCred !== null && w.userCred !== undefined) {
    const u = w.userCred;
    if (!isPt(u.C_u_pt) || !isDec(u.Cf_u) || !isDec(u.blind_u) || BigInt(u.blind_u) >= SCALAR_MAX || !isDec(u.leaf)) fail('userCred 형식');
  }
}

export function createSecretSource({ mode, state, witness = null }) {
  if (mode === 'file') {
    return {
      mode, pending: {},
      registration: () => state.registration ? { uid: state.registration.uid, s_u: state.registration.s_u, r_u: state.registration.r_u, sk_u: state.registration.sk_u, attrs: state.registration.attrs, cm_u: state.registration.cm_u } : null,
      userCred: () => state.registration?.userCred ?? null,
      setUserCred: (uc) => { state.registration.userCred = uc; },
      setAttrs: (attrs) => { state.registration.attrs = attrs; },
    };
  }
  if (mode !== 'snap') throw new Error(`unknown secret source mode: ${mode}`);
  const pending = {};
  return {
    mode, pending,
    registration: () => (state.registration && witness) ? { uid: state.registration.uid, s_u: witness.s_u, r_u: witness.r_u, sk_u: witness.sk_u, attrs: witness.attrs, cm_u: state.registration.cm_u } : null,
    userCred: () => witness?.userCred ?? null,
    setUserCred: (uc) => { pending.userCredIssued = uc; if (witness) witness.userCred = uc; state.registration.userCred = uc ? { Cf_u: uc.Cf_u, leaf: uc.leaf, issuedAt: uc.issuedAt } : null; },
    setAttrs: (attrs) => { pending.attrsChanged = attrs; if (witness) witness.attrs = attrs; state.registration.attrs = attrs; },
  };
}
