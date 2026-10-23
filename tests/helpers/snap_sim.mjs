// Snap 시뮬레이터 — 스펙 2026-09-22 metamask-snap §3.1 의 Snap 상태·RPC 를 Node 함수로 흉내 낸다.
// Task 3 의 snap-mode3/src/index.js 는 이 시뮬레이터와 같은 입출력을 구현한다(스펙 §3.1 표가 정본). 여기서는
// 대화상자를 decision('allow'|'deny') 인자로 대신하고, 오리진 검사는 하지 않는다(테스트 프로세스가 곧 지갑 페이지다).
import { createRegistration } from '../../lib/mode3_wallet.js';
import { ATTR_MAX } from '../../lib/mode3_credential.js';

const clone = (v) => (v === null || v === undefined ? null : JSON.parse(JSON.stringify(v)));
const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const fail = (msg) => { throw new Error(msg); };   // index.js 의 fail() 과 같은 모양 — 사유 문자열을 그대로 맞춘다

export function createSnapSim() {
  const state = { registration: null, userCred: null, consents: {} };
  const requireRegistered = () => { if (!state.registration) throw new Error('snap_sim: 등록이 없다'); };
  return {
    state,   // 검사용 — 테스트가 상태 파일과 대조한다

    /** V11 갱신(2026-10-23): 비밀번호 프롬프트는 없어졌다 — confirm(decision) 하나만. 실제 Snap(index.js register:102-112)과
     *  같은 순서로 검사한다: already_registered → bad_uid → 확인창. s_u·sk_u 를 만들어 상태에 두고(sk_u 는 register
     *  응답에 한 번만 싣는다 — V9 §7.1) s_u 와 함께 돌려준다. auid 는 등록이 아직 끝나지 않아 null(storeRegistration 이 채운다). */
    async register({ uid }, decision = 'allow') {
      if (state.registration) throw new Error('snap_sim: 이미 등록돼 있다');
      const uidStr = String(uid ?? '').trim();
      if (!isDec(uidStr)) fail('bad_uid: uid 는 10진 숫자 문자열이어야 한다');
      if (decision !== 'allow') return { denied: true };
      const reg = await createRegistration(BigInt(uidStr));
      state.registration = { uid: uidStr, pwdHash: null, s_u: reg.s_u.toString(), auid: null, sk_u: reg.sk_u, slot: null, attrs: null, registeredAt: new Date().toISOString() };
      return { uid: uidStr, s_u: state.registration.s_u, sk_u: reg.sk_u };
    },

    /** salt(s_u) 를 지갑 페이지에 보여 준다 — 실제 Snap(index.js showSalt:116-120)과 같은 입출력. */
    showSalt(decision = 'allow') {
      requireRegistered();
      return decision === 'allow' ? { s_u: state.registration.s_u } : { denied: true };
    },

    /** 에이전트 /wallet/register 응답의 slot·attrs·auid 를 저장한다(sk_u·s_u 는 register 때 이미 저장했으므로 받지 않는다).
     *  실제 Snap(index.js storeRegistration:119-130)과 같은 검사를 같은 사유 문자열로 한다(리뷰 2026-10-13 U1·U2) — 이 검사가
     *  없으면 시뮬레이터가 실제 Snap 보다 느슨하게 통과시켜 둘의 입출력이 어긋난다. */
    storeRegistration({ attrs, slot, auid }) {
      requireRegistered();
      if (!Array.isArray(attrs) || attrs.length !== 6 || !attrs.every((a) => isDec(String(a)))) fail('bad_attrs: attrs 는 10진 문자열 6개');
      if (!attrs.every((a) => BigInt(a) < ATTR_MAX)) fail('bad_attrs: attrs 원소는 2^64 미만');
      if (!Number.isInteger(slot) || slot < 0) fail('bad_slot');
      if (!isDec(String(auid ?? ''))) fail('bad_auid: auid 는 10진 문자열');
      state.registration.attrs = attrs.map(String);   // index.js 와 같이 문자열로 정규화
      state.registration.slot = slot;
      state.registration.auid = String(auid);
      return { ok: true };
    },

    /** 비밀 없음. */
    getPublicInfo() {
      const r = state.registration;
      return { registered: Boolean(r), uid: r?.uid ?? null, auid: r?.auid ?? null, attrs: clone(r?.attrs), slot: r?.slot ?? null, hasUserCred: Boolean(state.userCred), consents: clone(state.consents) };
    },

    /** 로그인 동의 창. 승인이면 증인 묶음(validateWitness 형식), 거절이면 { denied:true }.
     *  실제 Snap(index.js consentLogin:144-145)과 같다 — origin 이 없으면 대화상자도 띄우지 않고 거절한다(리뷰 2026-10-13 U1). */
    consentLogin({ origin, arid, allowAgent }, decision = 'allow') {
      requireRegistered();
      if (typeof origin !== 'string' || !origin) fail('bad_params: origin 필요');
      if (decision !== 'allow') return { denied: true };
      const r = state.registration;
      // 실제 Snap 의 buildWitness(index.js:74-77)와 같은 완결성 검사 — sk_u 64자 16진, uid·s_u 10진, attrs 배열(재리뷰 N4)
      if (!isDec(String(r.uid)) || !isDec(String(r.s_u)) || !/^[0-9a-fA-F]{64}$/.test(r.sk_u ?? '') || !Array.isArray(r.attrs)) fail('registration_incomplete: storeRegistration 이 아직 끝나지 않았다');
      state.consents[origin] = { arid, allowAgent, grantedAt: new Date().toISOString() };
      return { uid: r.uid, s_u: r.s_u, sk_u: r.sk_u, attrs: clone(r.attrs), userCred: clone(state.userCred) };
    },

    /** 속성 공개 동의 창. 슬롯 목록·대상·금액은 표시용이라 시뮬레이터는 보지 않는다. */
    consentDisclosure(_args, decision = 'allow') {
      return decision === 'allow' ? { ok: true } : { denied: true };
    },

    /** 에이전트가 새 C_u 를 발급받았을 때(응답 userCredIssued). */
    updateUserCred(uc) {
      requireRegistered();
      state.userCred = uc ? { C_u_pt: clone(uc.C_u_pt), Cf_u: uc.Cf_u, blind_u: uc.blind_u, issuedAt: uc.issuedAt ?? new Date().toISOString() } : null;
      return { ok: true };
    },

    /** 에이전트가 AA 속성 변경을 알렸을 때(응답 attrsChanged). */
    syncAttrs({ attrs }) {
      requireRegistered();
      // 실제 Snap(index.js syncAttrs)과 같은 검사·정규화(리뷰 2026-10-13 재리뷰 N4)
      if (!Array.isArray(attrs) || attrs.length !== 6 || !attrs.every((a) => isDec(String(a)))) fail('bad_attrs: attrs 는 10진 문자열 6개');
      const next = attrs.map(String);
      const changed = JSON.stringify(next) !== JSON.stringify(state.registration.attrs);
      if (changed) { state.registration.attrs = next; state.userCred = null; }
      return { ok: true, changed };
    },

    /** V8 세션 폐기 동의 창(설계 2026-09-24 §4). arid·발급 시각·만료 블록·허용 거래 수(bound, 2026-10-23 추가)는
     *  표시용이라 시뮬레이터는 보지 않는다. Snap 은 서명하지 않는다 — 서명은 에이전트가 세션의 메모리 증인에 든 sk_u 로 한다. */
    consentRevokeSession(_args, decision = 'allow') {
      requireRegistered();
      return decision === 'allow' ? { ok: true } : { denied: true };
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
