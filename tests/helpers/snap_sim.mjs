// Snap 시뮬레이터 — 스펙 2026-09-22 metamask-snap §3.1 의 Snap 상태·RPC 를 Node 함수로 흉내 낸다.
// Task 3 의 snap-mode3/src/index.js 는 이 시뮬레이터와 같은 입출력을 구현한다(스펙 §3.1 표가 정본). 여기서는
// 남은 대화상자(릴레이 출금 consentDisclosure)는 decision('allow'|'deny') 인자로 대신하고, 오리진 검사는 하지 않는다(테스트 프로세스가 곧 지갑 페이지다).
// 2026-11-05: 등록·로그인 동의·세션 폐기·salt 표시의 확인 창은 실제 Snap 과 함께 뺐다(중복 확인 제거) — decision 인자도 받지 않는다.
import { createHash } from 'node:crypto';
import { saltFromEntropy, skFromEntropy, ENTROPY_SALT_S_U, ENTROPY_SALT_SK_U, isIndex, INDEX_MAX } from '../../snap-mode3/src/crypto.js';
import { ATTR_MAX } from '../../lib/mode3_credential.js';

const clone = (v) => (v === null || v === undefined ? null : JSON.parse(JSON.stringify(v)));
const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const fail = (msg) => { throw new Error(msg); };   // index.js 의 fail() 과 같은 모양 — 사유 문자열을 그대로 맞춘다

/** 실제 스냅의 deriveRegistrationSecrets 와 같은 규칙(2026-11-12) — snap_getEntropy 대역은 sha256(`${srp}|${salt}`)(브라우저 스텁 ethereum_stub.js 와 같은 값).
 *  2026-11-12(스펙 snap-account-index): salt 끝에 계정 번호 index(기본 0). */
export const stubEntropy = (srp, salt) => '0x' + createHash('sha256').update(`${srp}|${salt}`).digest('hex');
export const derivedSecrets = (srp, index = 0) => ({ s_u: saltFromEntropy(stubEntropy(srp, `${ENTROPY_SALT_S_U}${index}`)), sk_u: skFromEntropy(stubEntropy(srp, `${ENTROPY_SALT_SK_U}${index}`)) });

export function createSnapSim({ srp = 'zkd-test-srp-1' } = {}) {
  const state = { registration: null, userCred: null, consents: {}, nextIndex: 0 };   // nextIndex: 다음 가입 번호 — reset 을 넘어 남는다(실제 Snap 과 같다)
  const indexParam = (v, dflt) => { if (v === undefined || v === null) return dflt; if (!isIndex(v)) fail('bad_index: 계정 번호는 0 이상 2^31−1 이하의 정수'); return v; };
  const requireRegistered = () => { if (!state.registration?.uid) throw new Error('not_registered: snap_sim: 등록이 없다'); };
  return {
    state,   // 검사용 — 테스트가 상태 파일과 대조한다

    /** V11 갱신(2026-10-23): 비밀번호 프롬프트는 없어졌고, 2026-11-05 에 확인 창도 뺐다. 실제 Snap(index.js register)과
     *  같은 순서로 검사한다: already_registered → bad_uid. s_u·sk_u 를 만들어 상태에 두고(sk_u 는 register
     *  응답에 한 번만 싣는다 — V9 §7.1) s_u 와 함께 돌려준다. auid 는 등록이 아직 끝나지 않아 null(storeRegistration 이 채운다). */
    async register({ uid, s_u: suIn, index: idxIn } = {}) {
      if (state.registration?.uid) throw new Error('already_registered: snap_sim: 이미 등록돼 있다');
      const uidStr = String(uid ?? '').trim();
      if (!isDec(uidStr)) fail('bad_uid: uid 는 10진 숫자 문자열이어야 한다');
      const index = indexParam(idxIn, state.nextIndex);
      const reg = derivedSecrets(srp, index);   // 2026-11-12: 시드 유도(실제 스냅과 같은 규칙, 계정 번호별)
      if (suIn !== undefined && suIn !== null && suIn !== '') {
        const su = String(suIn).trim();
        if (!isDec(su) || BigInt(su).toString() !== reg.s_u) fail('salt_not_derived: salt 는 이 스냅이 시드에서 유도한 값이어야 한다');
      }
      state.registration = { uid: uidStr, index, pwdHash: null, s_u: reg.s_u, auid: null, sk_u: reg.sk_u, slot: null, attrs: null, registeredAt: new Date().toISOString() };
      state.userCred = null;
      return { uid: uidStr, s_u: reg.s_u, sk_u: reg.sk_u, index };
    },

    /** Google 등록(2026-10-26): 실제 Snap(index.js prepareRegister)과 같은 입출력 — uid 없는 보류 등록, 보류가 있으면 같은 비밀. */
    prepareRegister({ index: idxIn } = {}) {
      if (state.registration?.uid) fail('already_registered: 이미 등록돼 있다 (초기화하려면 reset)');
      const pend = state.registration;
      if (pend) return { s_u: pend.s_u, sk_u: pend.sk_u, index: isIndex(pend.index) ? pend.index : 0 };
      const index = indexParam(idxIn, state.nextIndex);
      const { s_u, sk_u } = derivedSecrets(srp, index);   // 2026-11-12: 시드 유도
      state.registration = { uid: null, index, pwdHash: null, s_u, auid: null, sk_u, slot: null, attrs: null, provider: null, registeredAt: new Date().toISOString() };
      state.userCred = null;
      return { s_u: state.registration.s_u, sk_u, index };
    },

    /** 속성 도구용(2026-11-12) — 실제 Snap(index.js getSalt)과 같은 입출력: 등록 여부와 무관하게 유도 s_u. */
    getSalt({ index: idxIn } = {}) {   // 기본 번호: 등록(보류 포함) 번호 → 없으면 nextIndex(실제 Snap 의 Ruling P1)
      const own = state.registration && isIndex(state.registration.index) ? state.registration.index : null;
      const index = indexParam(idxIn, own ?? state.nextIndex);
      return { s_u: derivedSecrets(srp, index).s_u, index };
    },

    /** 다음 가입 번호(2026-11-12) — 실제 Snap(index.js setNextIndex)과 같은 입출력. */
    setNextIndex({ index } = {}) {
      if (!isIndex(index)) fail('bad_index: 계정 번호는 0 이상 2^31−1 이하의 정수');
      state.nextIndex = index;
      return { ok: true, nextIndex: index };
    },

    /** salt(s_u) 를 지갑 페이지에 보여 준다 — 실제 Snap(index.js showSalt)과 같은 입출력(확인 창 없음). */
    showSalt() {
      requireRegistered();
      return { s_u: state.registration.s_u };
    },

    /** 에이전트 /wallet/register 응답의 slot·attrs·auid 를 저장한다(sk_u·s_u 는 register 때 이미 저장했으므로 받지 않는다).
     *  실제 Snap(index.js storeRegistration:119-130)과 같은 검사를 같은 사유 문자열로 한다(리뷰 2026-10-13 U1·U2) — 이 검사가
     *  없으면 시뮬레이터가 실제 Snap 보다 느슨하게 통과시켜 둘의 입출력이 어긋난다. */
    storeRegistration({ attrs, slot, auid, uid, provider }) {
      if (!state.registration) fail('not_registered: snap_sim: 등록이 없다');
      const reg = state.registration;
      if (!Array.isArray(attrs) || attrs.length !== 6 || !attrs.every((a) => isDec(String(a)))) fail('bad_attrs: attrs 는 10진 문자열 6개');
      if (!attrs.every((a) => BigInt(a) < ATTR_MAX)) fail('bad_attrs: attrs 원소는 2^64 미만');
      if (!Number.isInteger(slot) || slot < 0) fail('bad_slot');
      if (!isDec(String(auid ?? ''))) fail('bad_auid: auid 는 10진 문자열');
      if (reg.uid === null || reg.uid === undefined) { if (!isDec(String(uid ?? ''))) fail('bad_uid: 보류 등록에는 uid(10진 문자열)가 필요하다'); }
      else if (uid !== undefined && String(uid) !== reg.uid) fail('uid_mismatch: 등록된 uid 와 다르다');
      if (provider !== undefined && !(typeof provider === 'string' && /^[A-Za-z0-9_-]{1,32}$/.test(provider))) fail('bad_provider: provider 는 영숫자·_·- 1~32자');
      if (reg.uid === null || reg.uid === undefined) reg.uid = String(uid);
      if (provider !== undefined) reg.provider = provider;
      reg.attrs = attrs.map(String);   // index.js 와 같이 문자열로 정규화
      reg.slot = slot;
      reg.auid = String(auid);
      state.nextIndex = Math.min(INDEX_MAX, Math.max(state.nextIndex, (isIndex(reg.index) ? reg.index : 0) + 1));
      return { ok: true };
    },

    /** 비밀 없음. */
    getPublicInfo() {
      const r = state.registration;
      return { registered: Boolean(r?.uid), pending: Boolean(r && !r.uid), uid: r?.uid ?? null, auid: r?.auid ?? null, attrs: clone(r?.attrs), slot: r?.slot ?? null, provider: r?.provider ?? null, hasUserCred: Boolean(state.userCred), consents: clone(state.consents), index: r && isIndex(r.index) ? r.index : null, nextIndex: state.nextIndex };
    },

    /** "내 계정"(2026-11-12) — 실제 Snap(index.js getStoredState)과 같은 모양: 저장 상태 전부(비밀 포함), 상태는 그대로. */
    getStoredState() {
      return { version: 1, registration: clone(state.registration), userCred: clone(state.userCred), consents: clone(state.consents) ?? {}, nextIndex: state.nextIndex };
    },

    /** 로그인 동의 — 증인 묶음(validateWitness 형식)과 동의 기록. 확인 창은 없다(2026-11-05).
     *  실제 Snap(index.js consentLogin)과 같다 — origin 이 없으면 거절한다(리뷰 2026-10-13 U1). */
    consentLogin({ origin, arid, allowAgent }) {
      requireRegistered();
      if (typeof origin !== 'string' || !origin) fail('bad_params: origin 필요');
      const r = state.registration;
      // 실제 Snap 의 buildWitness(index.js:74-77)와 같은 완결성 검사 — sk_u 64자 16진, uid·s_u 10진, attrs 배열(재리뷰 N4)
      if (!isDec(String(r.uid)) || !isDec(String(r.s_u)) || !/^[0-9a-fA-F]{64}$/.test(r.sk_u ?? '') || !Array.isArray(r.attrs)) fail('registration_incomplete: storeRegistration 이 아직 끝나지 않았다');
      state.consents[origin] = { arid, allowAgent, grantedAt: new Date().toISOString() };
      return { uid: r.uid, s_u: r.s_u, sk_u: r.sk_u, attrs: clone(r.attrs), userCred: clone(state.userCred) };
    },

    /** 속성 공개 동의. 2026-11-05: 대화상자는 릴레이 출금({ relay: true })만 띄운다 — 그 외는 묻지 않고 { ok: true }. 슬롯 목록·대상·금액은 표시용이라 시뮬레이터는 보지 않는다. */
    consentDisclosure(args, decision = 'allow') {
      if (args?.relay !== true) return { ok: true };
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

    /** V8 세션 폐기(설계 2026-09-24 §4). 2026-11-05: 동의 창은 뺐다 — 등록 여부만 보고 { ok: true }. Snap 은 서명하지 않는다 — 서명은 에이전트가 세션의 메모리 증인에 든 sk_u 로 한다. */
    consentRevokeSession() {
      requireRegistered();
      return { ok: true };
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
