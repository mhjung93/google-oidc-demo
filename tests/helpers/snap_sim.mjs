// Snap 시뮬레이터 — 스펙 2026-09-22 metamask-snap §3.1 의 Snap 상태·RPC 를 Node 함수로 흉내 낸다.
// Task 3 의 snap-mode3/src/index.js 는 이 시뮬레이터와 같은 입출력을 구현한다(스펙 §3.1 표가 정본). 여기서는
// 대화상자를 decision('allow'|'deny') 인자로 대신하고, 오리진 검사는 하지 않는다(테스트 프로세스가 곧 지갑 페이지다).
import { createRegistration } from '../../lib/mode3_wallet.js';
import { pointToStrings } from '../../lib/mode3_issuance.js';

const clone = (v) => (v === null || v === undefined ? null : JSON.parse(JSON.stringify(v)));

export function createSnapSim() {
  const state = { registration: null, userCred: null, consents: {} };
  const requireRegistered = () => { if (!state.registration) throw new Error('snap_sim: 등록이 없다'); };
  return {
    state,   // 검사용 — 테스트가 상태 파일과 대조한다

    /** prompt(uid)·prompt(pwd) 대신 인자로 받는다. s_u·r_u 를 만들어 상태에 두고 공개 cm_u 만 돌려준다. */
    async register({ uid, pwd }) {
      if (state.registration) throw new Error('snap_sim: 이미 등록돼 있다');
      const reg = await createRegistration();
      state.registration = { uid, pwdHash: null, s_u: reg.s_u.toString(), r_u: reg.r_u.toString(), cm_u: pointToStrings(reg.cm_u), sk_u: null, attrs: null, registeredAt: new Date().toISOString() };
      return { uid, pwd, cm_u: clone(state.registration.cm_u) };
    },

    /** 에이전트 /wallet/register 응답의 sk_u·attrs 를 저장한다. */
    storeRegistration({ sk_u, attrs }) {
      requireRegistered();
      state.registration.sk_u = sk_u;
      state.registration.attrs = clone(attrs);
      return { ok: true };
    },

    /** 비밀 없음. */
    getPublicInfo() {
      const r = state.registration;
      return { registered: Boolean(r), uid: r?.uid ?? null, cm_u: clone(r?.cm_u), attrs: clone(r?.attrs), hasUserCred: Boolean(state.userCred), consents: clone(state.consents) };
    },

    /** 로그인 동의 창. 승인이면 증인 묶음(validateWitness 형식), 거절이면 { denied:true }. */
    consentLogin({ origin, arid, allowAgent }, decision = 'allow') {
      requireRegistered();
      if (decision !== 'allow') return { denied: true };
      state.consents[origin] = { arid, allowAgent, grantedAt: new Date().toISOString() };
      const r = state.registration;
      return { uid: r.uid, s_u: r.s_u, r_u: r.r_u, sk_u: r.sk_u, attrs: clone(r.attrs), userCred: clone(state.userCred) };
    },

    /** 속성 공개 동의 창. 슬롯 목록·대상·금액은 표시용이라 시뮬레이터는 보지 않는다. */
    consentDisclosure(_args, decision = 'allow') {
      return decision === 'allow' ? { ok: true } : { denied: true };
    },

    /** 에이전트가 새 C_u 를 발급받았을 때(응답 userCredIssued). */
    updateUserCred(uc) {
      requireRegistered();
      state.userCred = uc ? { C_u_pt: clone(uc.C_u_pt), Cf_u: uc.Cf_u, blind_u: uc.blind_u, leaf: uc.leaf, issuedAt: uc.issuedAt ?? new Date().toISOString() } : null;
      return { ok: true };
    },

    /** 에이전트가 AA 속성 변경을 알렸을 때(응답 attrsChanged). */
    syncAttrs({ attrs }) {
      requireRegistered();
      const changed = JSON.stringify(attrs) !== JSON.stringify(state.registration.attrs);
      if (changed) { state.registration.attrs = clone(attrs); state.userCred = null; }
      return { ok: true, changed };
    },

    /** prompt(pwd) 대신 인자로. */
    selfRevoke({ pwd }) {
      requireRegistered();
      return { uid: state.registration.uid, pwd };
    },

    reset() {
      state.registration = null; state.userCred = null; state.consents = {};
      return { ok: true };
    },
  };
}
