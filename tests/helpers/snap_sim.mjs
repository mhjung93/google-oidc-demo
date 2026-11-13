// Snap 시뮬레이터 — 스펙 2026-09-22 metamask-snap §3.1 의 Snap 상태·RPC 를 Node 함수로 흉내 낸다.
// Task 3 의 snap-mode3/src/index.js 는 이 시뮬레이터와 같은 입출력을 구현한다(스펙 §3.1 표가 정본). 여기서는
// 남은 대화상자(릴레이 출금 consentDisclosure)는 decision('allow'|'deny') 인자로 대신하고, 오리진 검사는 하지 않는다(테스트 프로세스가 곧 지갑 페이지다).
// 2026-11-05: 등록·로그인 동의·세션 폐기·salt 표시의 확인 창은 실제 Snap 과 함께 뺐다(중복 확인 제거) — decision 인자도 받지 않는다.
// 0.5.0(2026-11-13, 스펙 2026-11-13 random-salt): 스냅 하나에 무작위 salt 하나 — initSalt·importSalt·confirmBackup·exportSaltForBackup, 백업 전에는 salt·가입·로그인 거절.
// 시드 유도(derivedSecrets·stubEntropy)와 계정 번호는 없어졌다. 설정이 끝난 시뮬레이터가 필요하면 createReadySnapSim 을 쓴다.
import { randomSalt, isSalt } from '../../snap-mode3/src/crypto.js';
import { ATTR_MAX } from '../../lib/mode3_credential.js';

const clone = (v) => (v === null || v === undefined ? null : JSON.parse(JSON.stringify(v)));
const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const fail = (msg) => { throw new Error(msg); };   // index.js 의 fail() 과 같은 모양 — 사유 문자열을 그대로 맞춘다

export function createSnapSim() {
  const state = { salt: null, registration: null, userCred: null, consents: {} };   // salt: { s_u, createdAt, source, backedUp, backedUpAt } | null — reset 을 넘어 남는다(실제 Snap 과 같다)
  const requireSalt = () => (state.salt?.s_u ? state.salt : fail('no_salt: 이 스냅에 salt 가 없다'));
  const requireBackedUp = () => { const salt = requireSalt(); if (salt.backedUp !== true) fail('backup_required: salt 백업을 확인한 뒤에 쓸 수 있다'); return salt; };
  const requireRegistered = () => { if (!state.registration?.uid) throw new Error('not_registered: snap_sim: 등록이 없다'); };
  return {
    state,   // 검사용 — 테스트가 상태 파일과 대조한다

    /** salt(0.5.0) — 실제 Snap(index.js)과 같은 입출력·같은 사유. importSalt 의 확인 창은 decision('allow'|'deny') 인자로 대신한다. */
    initSalt() {
      if (state.salt) fail('salt_exists: 이미 salt 가 있다');
      state.salt = { s_u: randomSalt(), createdAt: new Date().toISOString(), source: 'new', backedUp: false, backedUpAt: null };
      return { s_u: state.salt.s_u };
    },
    importSalt({ s_u } = {}, decision = 'allow') {
      const su = String(s_u ?? '').trim();
      if (!isSalt(su)) fail('bad_salt: salt 는 1 이상 2^250 미만의 10진 문자열');
      if (state.salt && (state.salt.backedUp === true || state.registration)) fail('salt_exists: 이미 쓰고 있는 salt 가 있다(바꾸려면 스냅을 제거한다)');
      if (decision !== 'allow') return { denied: true };
      const now = new Date().toISOString();
      state.salt = { s_u: BigInt(su).toString(), createdAt: now, source: 'import', backedUp: true, backedUpAt: now };
      state.registration = null; state.userCred = null;
      return { ok: true };
    },
    confirmBackup({ s_u } = {}) {
      const salt = requireSalt();
      const su = String(s_u ?? '').trim();
      if (!isSalt(su) || BigInt(su).toString() !== salt.s_u) fail('backup_mismatch: 백업 파일의 값이 이 스냅의 salt 와 다르다');
      salt.backedUp = true; salt.backedUpAt = new Date().toISOString();
      return { ok: true, backedUpAt: salt.backedUpAt };
    },
    exportSaltForBackup() { return { s_u: requireSalt().s_u }; },

    /** 등록 — 실제 Snap(index.js register)과 같은 순서: no_salt → backup_required → already_registered → bad_uid → salt_mismatch. 비밀은 스냅의 salt 다(등록 기록에는 두지 않는다). */
    async register({ uid, s_u: suIn } = {}) {
      const salt = requireBackedUp();
      if (state.registration?.uid) throw new Error('already_registered: snap_sim: 이미 등록돼 있다');
      const uidStr = String(uid ?? '').trim();
      if (!isDec(uidStr)) fail('bad_uid: uid 는 10진 숫자 문자열이어야 한다');
      if (suIn !== undefined && suIn !== null && suIn !== '') {
        const su = String(suIn).trim();
        if (!isDec(su) || BigInt(su).toString() !== salt.s_u) fail('salt_mismatch: 보낸 salt 가 이 스냅의 salt 와 다르다');
      }
      state.registration = { uid: uidStr, auid: null, slot: null, attrs: null, registeredAt: new Date().toISOString() };
      state.userCred = null;
      return { uid: uidStr, s_u: salt.s_u };
    },

    /** Google 등록(2026-10-26): 실제 Snap(index.js prepareRegister)과 같은 입출력 — uid 없는 보류 등록, 다시 불러도 같은 salt. */
    prepareRegister() {
      const salt = requireBackedUp();
      if (state.registration?.uid) fail('already_registered: 이미 등록돼 있다 (초기화하려면 reset)');
      if (!state.registration) { state.registration = { uid: null, auid: null, slot: null, attrs: null, provider: null, registeredAt: new Date().toISOString() }; state.userCred = null; }
      return { s_u: salt.s_u };
    },

    /** 속성 도구용 — 실제 Snap(index.js getSalt)과 같은 입출력. */
    getSalt() { return { s_u: requireBackedUp().s_u }; },

    /** salt(s_u) 를 지갑 페이지에 보여 준다 — 등록이 없어도 salt 가 있으면 답한다(0.5.0). */
    showSalt() { return { s_u: requireSalt().s_u }; },

    /** 에이전트 /wallet/register 응답의 slot·attrs·auid 를 저장한다(s_u 는 register 때 이미 저장했으므로 받지 않는다).
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
      return { ok: true };
    },

    /** 비밀 없음. */
    getPublicInfo() {
      const r = state.registration;
      return { registered: Boolean(r?.uid), pending: Boolean(r && !r.uid), uid: r?.uid ?? null, auid: r?.auid ?? null, attrs: clone(r?.attrs), slot: r?.slot ?? null, provider: r?.provider ?? null, hasUserCred: Boolean(state.userCred), consents: clone(state.consents), hasSalt: Boolean(state.salt?.s_u), backedUp: state.salt?.backedUp === true };
    },

    /** "내 계정"(2026-11-12) — 실제 Snap(index.js getStoredState)과 같은 모양: 저장 상태 전부(비밀 포함), 상태는 그대로. */
    getStoredState() {
      return { version: 2, salt: clone(state.salt), registration: clone(state.registration), userCred: clone(state.userCred), consents: clone(state.consents) ?? {} };
    },

    /** 로그인 동의 — 증인 묶음(validateWitness 형식)과 동의 기록. 확인 창은 없다(2026-11-05).
     *  실제 Snap(index.js consentLogin)과 같다 — origin 이 없으면 거절한다(리뷰 2026-10-13 U1). */
    consentLogin({ origin, arid, allowAgent }) {
      requireBackedUp();
      requireRegistered();
      if (typeof origin !== 'string' || !origin) fail('bad_params: origin 필요');
      const r = state.registration;
      // 실제 Snap 의 buildWitness(index.js:74-77)와 같은 완결성 검사 — uid·s_u 10진, attrs 배열(재리뷰 N4; 0.4.0 부터 sk_u 는 없다)
      if (!isDec(String(r.uid)) || !isDec(String(state.salt?.s_u)) || !Array.isArray(r.attrs)) fail('registration_incomplete: storeRegistration 이 아직 끝나지 않았다');
      state.consents[origin] = { arid, allowAgent, grantedAt: new Date().toISOString() };
      return { uid: r.uid, s_u: state.salt.s_u, attrs: clone(r.attrs), userCred: clone(state.userCred) };
    },

    /** 속성 공개 동의. 2026-11-05: 대화상자는 릴레이 출금({ relay: true })만 띄운다 — 그 외는 묻지 않고 { ok: true }. 슬롯 목록·대상·금액은 표시용이라 시뮬레이터는 보지 않는다. */
    consentDisclosure(args, decision = 'allow') {
      requireBackedUp();
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

    /** V8 세션 폐기(설계 2026-09-24 §4). 2026-11-05: 동의 창은 뺐다 — 등록 여부만 보고 { ok: true }. Snap 은 인증하지 않는다 — 인증 증명은 에이전트가 세션의 메모리 증인에 든 s_u 로 만든다. */
    consentRevokeSession() {
      requireRegistered();
      return { ok: true };
    },

    /** prompt(pwd) 대신 인자로. */
    selfRevoke({ pwd }) {
      requireRegistered();
      return { uid: state.registration.uid, pwd };
    },

    /** R8: 등록·동의 기록·userCred 만 지운다 — salt·backedUp 은 남는다. */
    reset() {
      state.registration = null; state.userCred = null; state.consents = {};
      return { ok: true };
    },
  };
}

/** 설정이 끝난 시뮬레이터(계획 P6) — s_u 를 주면 그 값을 불러오고(백업에서 복구한 스냅), 없으면 새로 만들어 백업 확인까지 끝낸다. */
export function createReadySnapSim({ s_u } = {}) {
  const sim = createSnapSim();
  if (s_u !== undefined && s_u !== null) sim.importSalt({ s_u: String(s_u) });
  else sim.confirmBackup({ s_u: sim.initSalt().s_u });
  return sim;
}
