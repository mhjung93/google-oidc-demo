// Mode 3 Snap — 등록 비밀(s_u·sk_u)을 MetaMask 암호화 저장소에 보관한다.
// 2026-11-05: 등록·로그인 동의·세션 폐기·salt 표시의 확인 대화상자는 뺐다 — 모두 사용자가 지갑·RP 페이지에서 직접 눌러 시작하는
// 요청이라 Snap 이 한 번 더 묻는 것은 중복이었다(사용자 결정). 남은 대화상자는 셋: 자기 폐기 비밀번호 프롬프트, 등록 초기화 확인,
// RP 릴레이 출금의 받는 주소·금액 확인(consentDisclosure { relay: true } — 사용자가 달리 확인할 창이 없는 유일한 전송).
// 정본은 스펙 2026-09-22 metamask-snap §3.1(RPC 표·상태 모양). tests/helpers/snap_sim.mjs(시뮬레이터)와 입출력이 같아야 한다.
// 시뮬레이터와 다른 점은 둘: 남은 대화상자를 실제로 띄운다는 것과, 호출 오리진을 검사한다는 것이다.
//
// @metamask/snaps-sdk 1.4.0 은 CommonJS·ESM 두 빌드를 함께 낸다. webpack 은 ESM 빌드를 집어 명명 export 가 보이고,
// Node 는 CommonJS 빌드를 집어 default 하나만 보인다(단위 테스트가 이 경로다). 두 경우를 모두 받는다.
import * as sdkNamespace from '@metamask/snaps-sdk';
import { deriveRegistrationSecrets, ATTR_MAX, SCALAR_MAX } from './crypto.js';

const sdk = typeof sdkNamespace.panel === 'function' ? sdkNamespace : sdkNamespace.default;
const { panel, text, heading, divider } = sdk;

// 지갑 페이지(:5100)만 이 Snap 을 부를 수 있다(스펙 §2·§3.1). 같은 개발 페이지의 두 철자를 모두 받는다 —
// 브라우저는 127.0.0.1 과 localhost 를 다른 오리진으로 보고, 어느 쪽으로 열었는지는 사용자가 정한다.
// 환경변수는 Snap 번들에 없으므로 여기 상수 목록이 정본이다. 다른 오리진(RP 포함)은 전부 거절한다.
const WALLET_ORIGINS = [
  'http://127.0.0.1:5100',
  'http://localhost:5100',
];

const SLOT_LABELS = ['출생연도', '국가', '예비 1', '예비 2', '미사용', '미사용'];      // a₀..a₅ — 기본 스키마 zkd-attrs v1(스펙 2, 2026-10-07). 스키마를 RPC 로 받는 것은 비범위(§10)
const SLOT_NAMES = ['a₀', 'a₁', 'a₂', 'a₃', 'a₄', 'a₅'];

/** 동의 창에 보이는 RP 이름 위생(2026-09-25 리뷰 D-2). 인증서(cert_s)가 덮는 것은 `origin` 뿐이고 serviceName 은
 *  RP 가 고른 임의의 문자열이다 — 개행·제어문자로 창에 가짜 줄("오리진: …" 같은)을 끼워 넣거나 긴 이름으로 아래
 *  줄을 밀어내지 못하도록 한 줄·48자로 자른다. 잘라서 빈 문자열이 되면 호출자가 오리진으로 대체한다. */
const MAX_SERVICE_NAME = 48;
function cleanServiceName(v) {
  if (typeof v !== 'string') return '';
  // 제어문자(BEL 등)를 먼저 공백으로 바꾸고, 남은 공백류(\s 는 U+2028·U+2029 도 포함)를 한 칸으로 모은다.
  const one = v.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
  const cp = [...one];
  return cp.length > MAX_SERVICE_NAME ? `${cp.slice(0, MAX_SERVICE_NAME - 1).join('')}…` : one;
}

/** 공개 술어를 대화상자 줄로(V6 범위 + V7 집합). consentLogin·consentDisclosure 가 같이 쓴다. */
function predicateLines(disclose, set) {
  const lines = [];
  const slots = Array.isArray(disclose) ? disclose : [];
  for (let i = 0; i < 6; i++) { const d = slots[i]; if (d) lines.push(`${SLOT_NAMES[i]}(${SLOT_LABELS[i]}) ∈ [${d.lo}, ${d.hi}]`); }
  if (set && Number.isInteger(set.slot) && set.slot >= 0 && set.slot <= 5 && Array.isArray(set.members)) {
    const ms = set.members.map(String);
    const shown = ms.length > 32 ? `${ms.slice(0, 8).join(', ')} … 외 ${ms.length - 8}개` : ms.join(', ');
    lines.push(`${SLOT_NAMES[set.slot]}(${SLOT_LABELS[set.slot]}) ∈ {${shown}} (${ms.length}개)`);
  }
  return lines;
}

/** wei 10진 문자열 → ETH 표기('0.01'); 숫자가 아니면 그대로(2026-11-05 — 동의 창이 wei 만 보이던 것을 고쳤다). */
const weiToEth = (wei) => { if (!/^[0-9]+$/.test(wei)) return wei; const w = BigInt(wei); return `${w / 10n ** 18n}.${String(w % 10n ** 18n).padStart(18, '0')}`.replace(/\.?0+$/, '') || '0'; };

const EMPTY_STATE = { version: 1, registration: null, userCred: null, consents: {} };
const clone = (v) => (v === null || v === undefined ? null : JSON.parse(JSON.stringify(v)));
const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const fail = (msg) => { throw new Error(msg); };

async function getState() {
  const s = await snap.request({ method: 'snap_manageState', params: { operation: 'get' } });
  if (!s || s.version !== 1) return { ...EMPTY_STATE, consents: {} };
  return { ...EMPTY_STATE, ...s, consents: s.consents ?? {} };
}

const setState = (newState) => snap.request({ method: 'snap_manageState', params: { operation: 'update', newState } });
const clearState = () => snap.request({ method: 'snap_manageState', params: { operation: 'clear' } });

const dialog = (params) => snap.request({ method: 'snap_dialog', params });

const prompt = (title, lines, placeholder) =>
  dialog({ type: 'prompt', content: panel([heading(title), ...lines.map((l) => text(l))]), placeholder });

const confirm = (title, lines) =>
  dialog({ type: 'confirmation', content: panel([heading(title), ...lines.map((l) => (l === null ? divider() : text(l)))]) });

// 보류 등록(prepareRegister, uid 없음 — 2026-10-26 Snap OIDC 래퍼)은 "등록 없음" 으로 본다: uid 없는 증인·프롬프트가 나가면 안 된다.
const requireRegistered = (state) => (state.registration?.uid ? state.registration : fail('not_registered: 이 Snap 에 등록이 없다'));

/** 증인 묶음 — lib/mode3_secret_source.js 의 validateWitness 형식(스펙 §3.1). consentLogin 응답으로만 나간다. */
function buildWitness(state) {
  const r = state.registration;
  if (!isDec(r.uid) || !isDec(r.s_u) || !/^[0-9a-fA-F]{64}$/.test(r.sk_u ?? '') || !Array.isArray(r.attrs)) {
    fail('registration_incomplete: storeRegistration 이 아직 끝나지 않았다');
  }
  return { uid: r.uid, s_u: r.s_u, sk_u: r.sk_u, attrs: clone(r.attrs), userCred: clone(state.userCred) };
}

/** 페이지가 { userCred } 로 감싸 보내도 받는다 — JSON-RPC 의 params 는 null 을 못 싣는 경우가 있다. */
function unwrapUserCred(params) {
  const raw = params ?? null;
  const uc = (raw && typeof raw === 'object' && !Array.isArray(raw) && 'userCred' in raw) ? raw.userCred : raw;
  if (!uc) return null;
  const okPt = uc.C_u_pt && isDec(uc.C_u_pt.x) && isDec(uc.C_u_pt.y);
  if (!okPt || !isDec(uc.Cf_u) || !isDec(uc.blind_u)) fail('bad_user_cred: C_u_pt{x,y}·Cf_u·blind_u(10진 문자열) 필요');
  return { C_u_pt: { x: uc.C_u_pt.x, y: uc.C_u_pt.y }, Cf_u: uc.Cf_u, blind_u: uc.blind_u, issuedAt: uc.issuedAt ?? new Date().toISOString() };
}

export const onRpcRequest = async ({ origin, request }) => {
  if (!WALLET_ORIGINS.includes(origin)) {
    fail(`unauthorized_origin: 지갑 페이지만 이 Snap 을 부를 수 있다 (origin=${origin})`);
  }
  const params = request.params ?? {};
  const state = await getState();

  switch (request.method) {
    // 등록(V11 갱신, 2026-10-23): 비밀번호 프롬프트는 없어졌다 — 지갑 페이지가 이미 받은 uid 를 params 로 넘기고,
    // Snap 은 s_u·sk_u 를 만들어 저장한다(2026-11-05: 확인 창도 뺐다). IdP 에는 커밋먼트(auid)와 공개키만 간다(storeRegistration).
    // 보류 등록(prepareRegister)이 있으면 덮어쓴다 — 완성 등록만 already_registered.
    case 'register': {
      if (state.registration?.uid) fail('already_registered: 이미 등록돼 있다 (초기화하려면 reset)');
      const uid = String(params.uid ?? '').trim();
      if (!isDec(uid)) fail('bad_uid: uid 는 10진 숫자 문자열이어야 한다');
      // 2026-11-12(스펙 snap-derived-secrets S1·S2): s_u·sk_u 는 시드에서 유도한다. 속성 도구가 getSalt 로 받은 salt 를 다시 실어 보내면
      // 유도값과 같은지만 본다 — 다르면(옛 기록의 직접 입력 salt) 등록하지 않는다. 시드로 복구할 수 없는 계정이 섞이지 않게.
      const secrets = await deriveRegistrationSecrets();
      if (params.s_u !== undefined && params.s_u !== null && params.s_u !== '') {
        const su = String(params.s_u).trim();
        if (!isDec(su) || BigInt(su).toString() !== secrets.s_u) fail('salt_not_derived: salt 는 이 스냅이 시드에서 유도한 값이어야 한다(속성 도구 "스냅에서 가져오기")');
      }
      state.registration = { uid, s_u: secrets.s_u, auid: null, sk_u: secrets.sk_u, slot: null, attrs: null, registeredAt: new Date().toISOString() };
      state.userCred = null; await setState(state);
      return { uid, s_u: secrets.s_u, sk_u: secrets.sk_u };
    }

    // Google 등록(2026-10-26 Snap OIDC 래퍼 §2.1): 등록 토큰의 nonce 는 pk_u 에 묶이는데(reg:H(pk_u)), uid 는 토큰을 받은 뒤에야
    // IdP 가 정한다 — 그래서 uid 없이 비밀을 먼저 만들어 "보류 등록" 으로 둔다. uid 는 storeRegistration 이 채운다.
    // 보류가 이미 있으면(Google·IdP 단계 실패 뒤 재시도) 같은 비밀을 돌려준다 — 같은 pk_u 라 nonce 도 같다.
    case 'prepareRegister': {
      if (state.registration?.uid) fail('already_registered: 이미 등록돼 있다 (초기화하려면 reset)');
      const pend = state.registration;
      if (pend) return { s_u: pend.s_u, sk_u: pend.sk_u };
      const secrets = await deriveRegistrationSecrets();
      state.registration = { uid: null, s_u: secrets.s_u, auid: null, sk_u: secrets.sk_u, slot: null, attrs: null, provider: null, registeredAt: new Date().toISOString() };
      state.userCred = null; await setState(state);
      return { s_u: secrets.s_u, sk_u: secrets.sk_u };
    }

    // 속성 도구용(2026-11-12, 스펙 §2.3): 등록 전에도 시드에서 유도한 s_u 를 돌려준다. 등록 여부와 무관하게 같은 값이고 상태를 바꾸지 않는다.
    // 부를 수 있는 오리진은 다른 RPC 와 같이 지갑 오리진(:5100)뿐이다 — 속성 도구(/attr.html)도 그 오리진에서 서빙된다.
    case 'getSalt': {
      const { s_u } = await deriveRegistrationSecrets();
      return { s_u };
    }

    // salt(s_u) 를 지갑 페이지에 보여 준다 — 시연용(복구 코드 설계 2026-10-21 과 무관, 화면 표시만). 확인 창은 2026-11-05 에 뺐다.
    case 'showSalt': {
      const reg = requireRegistered(state);
      return { s_u: reg.s_u };
    }

    // 에이전트 POST /wallet/register 응답(slot·attrs·auid)을 저장한다. sk_u·s_u 는 register/prepareRegister 때 이미 저장했으므로 받지 않는다(V9 §7.1).
    // 2026-10-26: 보류 등록(prepareRegister)은 여기서 uid 를 받아 완성된다. provider 는 IdP 응답의 값(데모 등록은 생략 가능).
    case 'storeRegistration': {
      const reg = state.registration ?? fail('not_registered: 이 Snap 에 등록이 없다');
      const { attrs, slot, auid, uid, provider } = params;
      if (!Array.isArray(attrs) || attrs.length !== 6 || !attrs.every((a) => isDec(String(a)))) fail('bad_attrs: attrs 는 10진 문자열 6개');
      if (!attrs.every((a) => BigInt(a) < ATTR_MAX)) fail('bad_attrs: attrs 원소는 2^64 미만');
      if (!Number.isInteger(slot) || slot < 0) fail('bad_slot');
      if (!isDec(String(auid ?? ''))) fail('bad_auid: auid 는 10진 문자열');
      if (reg.uid === null || reg.uid === undefined) { if (!isDec(String(uid ?? ''))) fail('bad_uid: 보류 등록에는 uid(10진 문자열)가 필요하다'); }
      else if (uid !== undefined && String(uid) !== reg.uid) fail('uid_mismatch: 등록된 uid 와 다르다');
      if (provider !== undefined && !(typeof provider === 'string' && /^[A-Za-z0-9_-]{1,32}$/.test(provider))) fail('bad_provider: provider 는 영숫자·_·- 1~32자');
      if (reg.uid === null || reg.uid === undefined) reg.uid = String(uid);
      if (provider !== undefined) reg.provider = provider;
      reg.attrs = attrs.map(String);
      reg.slot = slot;
      reg.auid = String(auid);
      await setState(state);
      return { ok: true };
    }

    // 비밀을 절대 싣지 않는다(스펙 §3.1).
    case 'getPublicInfo': {
      const r = state.registration;
      return {
        registered: Boolean(r?.uid), pending: Boolean(r && !r.uid), uid: r?.uid ?? null, auid: r?.auid ?? null, attrs: clone(r?.attrs), slot: r?.slot ?? null,
        provider: r?.provider ?? null, hasUserCred: Boolean(state.userCred), consents: clone(state.consents) ?? {},
      };
    }

    // 로그인 동의(스펙 §4.2) — 증인 묶음을 돌려주고 동의 기록을 남긴다. 2026-11-05: 확인 대화상자는 뺐다(사용자가 RP 에서 "로그인" 을
    // 눌러 시작한 요청이고, 지갑 팝업이 precheck(인증서·팩토리)를 통과한 뒤에만 이 RPC 를 부른다). 응답 모양은 그대로다.
    case 'consentLogin': {
      requireRegistered(state);
      const { origin: rpOrigin, arid, allowAgent } = params;
      if (typeof rpOrigin !== 'string' || !rpOrigin) fail('bad_params: origin 필요');
      const agentOk = allowAgent === true || allowAgent === 1 || allowAgent === '1';
      const witness = buildWitness(state);
      // allowAgent 는 '1'/'0' 로 굳혀 기록한다.
      state.consents[rpOrigin] = { arid: arid === undefined || arid === null ? null : String(arid), allowAgent: agentOk ? '1' : '0', grantedAt: new Date().toISOString() };
      await setState(state);
      return witness;
    }

    // 속성 공개 동의(스펙 §4.4). 2026-11-05: 대화상자는 RP 릴레이 출금({ relay: true }, mode3/wallet.html handleTxRequest)만 띄운다 —
    // 릴레이어가 보내는 트랜잭션은 MetaMask 확인 창을 거치지 않아 받는 주소·금액을 사용자가 볼 자리가 여기뿐이다. 지갑 페이지의
    // "보내기"(MetaMask 가 그 뒤에 트랜잭션 확인 창을 띄운다)는 묻지 않고 { ok: true } 를 돌려준다.
    case 'consentDisclosure': {
      const { arid, origin: rpOrigin, disclose, to, value, set, relay } = params;
      if (relay !== true) return { ok: true };
      // V7 집합 소속: 에이전트가 members 로부터 root 를 계산해 증명에 넣는다 — 여기서는 사용자에게 원소를 보여 준다(root 검산은 에이전트 몫, 스펙 §5.2).
      const lines = predicateLines(disclose, set);
      // 2026-11-05: 공개할 속성이 없는 평범한 출금은 "출금 확인" 창(서비스·받는 주소·금액)이다 — "속성 공개 동의 / 공개하는 속성 없음" 은 어색했다.
      const ok = await confirm(lines.length ? '속성 공개 동의' : '출금 확인', [
        rpOrigin ? `서비스: ${rpOrigin}` : '서비스: (지갑 페이지)',
        null,
        ...(lines.length ? ['공개할 속성:', ...lines, null] : []),
        `받는 주소: ${to}`,
        `금액: ${weiToEth(String(value ?? '0'))} ETH (${value ?? '0'} wei)`,
      ]);
      return ok ? { ok: true } : { denied: true };
    }

    // 에이전트 응답의 userCredIssued 를 저장한다. 명시적 null(또는 { userCred: null })이면 저장된 C_u 를 버린다.
    // 인자 자체가 없으면 거절한다(T3 리뷰 Ruling 6) — 페이지의 빈 호출이 조용히 C_u 를 버리면 안 된다.
    case 'updateUserCred': {
      requireRegistered(state);
      if (request.params === undefined) fail('bad_params: updateUserCred 는 C_u 또는 명시적 null(폐기) 이 필요하다');
      state.userCred = unwrapUserCred(request.params);
      await setState(state);
      return { ok: true };
    }

    // 에이전트 응답의 attrsChanged. 속성이 바뀌면 옛 C_u 는 더 못 쓰므로 함께 버린다.
    case 'syncAttrs': {
      const reg = requireRegistered(state);
      const { attrs } = params;
      if (!Array.isArray(attrs) || attrs.length !== 6 || !attrs.every((a) => isDec(String(a)))) fail('bad_attrs: attrs 는 10진 문자열 6개');
      const next = attrs.map(String);
      const changed = JSON.stringify(next) !== JSON.stringify(reg.attrs);
      if (changed) { reg.attrs = next; state.userCred = null; await setState(state); }
      return { ok: true, changed };
    }

    // 자기 폐기(스펙 §4.5) — 비밀번호만 받아 그대로 넘긴다(저장하지 않는다).
    case 'selfRevoke': {
      const reg = requireRegistered(state);
      const pwd = await prompt('자기 폐기', [`uid: ${reg.uid}`, '자기 폐기는 되돌릴 수 없습니다. 계정 비밀번호를 입력하세요.'], '비밀번호');
      if (pwd === null || pwd === '') return { denied: true };
      return { uid: reg.uid, pwd };
    }

    // V8 세션 폐기(설계 2026-09-24 §4). Snap 에는 Poseidon 이 없어 서명은 에이전트가 세션 증인의 sk_u 로 한다.
    // 2026-11-05: 동의 창은 뺐다(지갑 페이지의 "정말 폐기하시겠습니까?" 확인이 이미 있다) — 등록 여부만 보고 { ok: true }.
    case 'consentRevokeSession': {
      requireRegistered(state);
      return { ok: true };
    }

    // 데모 초기화 — 등록 비밀·동의 기록을 모두 지운다.
    case 'reset': {
      const ok = await confirm('등록 초기화', [
        '이 Snap 의 등록을 지웁니다. 등록 비밀(s_u·sk_u)과 동의 기록이 사라집니다.',
        '체인·AA 쪽 상태는 지워지지 않습니다.',
      ]);
      if (!ok) return { denied: true };
      await clearState();
      return { ok: true };
    }

    default:
      fail(`method_not_found: ${request.method}`);
  }
};
