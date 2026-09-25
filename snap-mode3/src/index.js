// Mode 3 Snap — 등록 비밀(s_u·r_u·sk_u)을 MetaMask 암호화 저장소에 보관하고 동의 대화상자를 띄운다.
// 정본은 스펙 2026-09-22 metamask-snap §3.1(RPC 표·상태 모양). tests/helpers/snap_sim.mjs(시뮬레이터)와 입출력이 같아야 한다.
// 시뮬레이터와 다른 점은 둘: 대화상자를 실제로 띄운다는 것과, 호출 오리진을 검사한다는 것이다.
//
// @metamask/snaps-sdk 1.4.0 은 CommonJS·ESM 두 빌드를 함께 낸다. webpack 은 ESM 빌드를 집어 명명 export 가 보이고,
// Node 는 CommonJS 빌드를 집어 default 하나만 보인다(단위 테스트가 이 경로다). 두 경우를 모두 받는다.
import * as sdkNamespace from '@metamask/snaps-sdk';
import { createRegistrationSecrets } from './crypto.js';

const sdk = typeof sdkNamespace.panel === 'function' ? sdkNamespace : sdkNamespace.default;
const { panel, text, heading, divider } = sdk;

// 지갑 페이지(:5100)만 이 Snap 을 부를 수 있다(스펙 §2·§3.1). 같은 개발 페이지의 두 철자를 모두 받는다 —
// 브라우저는 127.0.0.1 과 localhost 를 다른 오리진으로 보고, 어느 쪽으로 열었는지는 사용자가 정한다.
// 환경변수는 Snap 번들에 없으므로 여기 상수 목록이 정본이다. 다른 오리진(RP 포함)은 전부 거절한다.
const WALLET_ORIGINS = [
  'http://127.0.0.1:5100',
  'http://localhost:5100',
];

const SLOT_LABELS = ['출생연도', '국가', '등급', '예비'];      // a₀..a₃ (스펙 2026-09-22 selective-disclosure §3)
const SLOT_NAMES = ['a₀', 'a₁', 'a₂', 'a₃'];

/** 동의 창에 보이는 서비스 이름 위생(2026-09-25 리뷰 D-2). 인증서(cert_s)가 덮는 것은 `origin` 뿐이고 serviceName 은
 *  서비스가 고른 임의의 문자열이다 — 개행·제어문자로 창에 가짜 줄("오리진: …" 같은)을 끼워 넣거나 긴 이름으로 아래
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
  for (let i = 0; i < 4; i++) { const d = slots[i]; if (d) lines.push(`${SLOT_NAMES[i]}(${SLOT_LABELS[i]}) ∈ [${d.lo}, ${d.hi}]`); }
  if (set && Number.isInteger(set.slot) && set.slot >= 0 && set.slot <= 3 && Array.isArray(set.members)) {
    const ms = set.members.map(String);
    const shown = ms.length > 32 ? `${ms.slice(0, 8).join(', ')} … 외 ${ms.length - 8}개` : ms.join(', ');
    lines.push(`${SLOT_NAMES[set.slot]}(${SLOT_LABELS[set.slot]}) ∈ {${shown}} (${ms.length}개)`);
  }
  return lines;
}

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

const requireRegistered = (state) => state.registration ?? fail('not_registered: 이 Snap 에 등록이 없다');

/** 증인 묶음 — lib/mode3_secret_source.js 의 validateWitness 형식(스펙 §3.1). consentLogin 응답으로만 나간다. */
function buildWitness(state) {
  const r = state.registration;
  if (!isDec(r.uid) || !isDec(r.s_u) || !isDec(r.r_u) || typeof r.sk_u !== 'string' || !Array.isArray(r.attrs)) {
    fail('registration_incomplete: storeRegistration 이 아직 끝나지 않았다');
  }
  return { uid: r.uid, s_u: r.s_u, r_u: r.r_u, sk_u: r.sk_u, attrs: clone(r.attrs), userCred: clone(state.userCred) };
}

/** 페이지가 { userCred } 로 감싸 보내도 받는다 — JSON-RPC 의 params 는 null 을 못 싣는 경우가 있다. */
function unwrapUserCred(params) {
  const raw = params ?? null;
  const uc = (raw && typeof raw === 'object' && !Array.isArray(raw) && 'userCred' in raw) ? raw.userCred : raw;
  if (!uc) return null;
  const okPt = uc.C_u_pt && isDec(uc.C_u_pt.x) && isDec(uc.C_u_pt.y);
  if (!okPt || !isDec(uc.Cf_u) || !isDec(uc.blind_u) || !isDec(uc.leaf)) fail('bad_user_cred: C_u_pt{x,y}·Cf_u·blind_u·leaf(10진 문자열) 필요');
  return { C_u_pt: { x: uc.C_u_pt.x, y: uc.C_u_pt.y }, Cf_u: uc.Cf_u, blind_u: uc.blind_u, leaf: uc.leaf, issuedAt: uc.issuedAt ?? new Date().toISOString() };
}

export const onRpcRequest = async ({ origin, request }) => {
  if (!WALLET_ORIGINS.includes(origin)) {
    fail(`unauthorized_origin: 지갑 페이지만 이 Snap 을 부를 수 있다 (origin=${origin})`);
  }
  const params = request.params ?? {};
  const state = await getState();

  switch (request.method) {
    // 등록(스펙 §4.1): uid·비밀번호를 대화상자로 받고 s_u·r_u 를 만들어 저장한다. 비밀번호는 저장하지 않고 그대로 돌려준다.
    case 'register': {
      if (state.registration) fail('already_registered: 이미 등록돼 있다 (초기화하려면 reset)');
      const uid = await prompt('Mode 3 등록', ['사용자 uid(숫자)를 입력하세요.'], '12345');
      if (uid === null || uid === '') return { denied: true };
      if (!isDec(String(uid).trim())) fail('bad_uid: uid 는 10진 숫자 문자열이어야 한다');
      const pwd = await prompt('Mode 3 등록', [`uid: ${uid}`, '속성 기관(AA) 계정 비밀번호를 입력하세요. 비밀번호는 Snap 에 저장하지 않습니다.'], '비밀번호');
      if (pwd === null || pwd === '') return { denied: true };
      const secrets = createRegistrationSecrets();
      state.registration = {
        uid: String(uid).trim(), s_u: secrets.s_u, r_u: secrets.r_u, cm_u: secrets.cm_u,
        sk_u: null, attrs: null, registeredAt: new Date().toISOString(),
      };
      state.userCred = null;
      await setState(state);
      return { uid: state.registration.uid, pwd, cm_u: clone(secrets.cm_u) };
    }

    // 에이전트 POST /wallet/register 응답(sk_u·attrs)을 저장한다.
    case 'storeRegistration': {
      const reg = requireRegistered(state);
      const { sk_u, attrs } = params;
      if (typeof sk_u !== 'string' || !/^[0-9a-fA-F]{64}$/.test(sk_u)) fail('bad_sk_u: sk_u 는 64자리 16진 문자열');
      if (!Array.isArray(attrs) || attrs.length !== 4 || !attrs.every((a) => isDec(String(a)))) fail('bad_attrs: attrs 는 10진 문자열 4개');
      reg.sk_u = sk_u;
      reg.attrs = attrs.map(String);
      await setState(state);
      return { ok: true };
    }

    // 비밀을 절대 싣지 않는다(스펙 §3.1).
    case 'getPublicInfo': {
      const r = state.registration;
      return {
        registered: Boolean(r), uid: r?.uid ?? null, cm_u: clone(r?.cm_u), attrs: clone(r?.attrs),
        hasUserCred: Boolean(state.userCred), consents: clone(state.consents) ?? {},
      };
    }

    // 로그인 동의(스펙 §4.2). 승인이면 증인 묶음, 거절이면 { denied:true }.
    case 'consentLogin': {
      requireRegistered(state);
      const { origin: rpOrigin, arid, allowAgent, serviceName, disclose, set } = params;
      if (typeof rpOrigin !== 'string' || !rpOrigin) fail('bad_params: origin 필요');
      const agentOk = allowAgent === true || allowAgent === 1 || allowAgent === '1';
      const pred = predicateLines(disclose, set);
      const ok = await confirm('로그인 동의', [
        `서비스: ${cleanServiceName(serviceName) || rpOrigin}`,   // 이름은 서비스가 고른 값이다 — 인증서가 덮는 것은 아래 오리진 뿐
        `오리진: ${rpOrigin}`,
        `요청 식별자(arid): ${arid}`,
        null,
        `AI 에이전트 허용: ${agentOk ? '예' : '아니오'}`,
        ...(pred.length ? [null, '공개할 속성:', ...pred] : []),
        '승인하면 이 로그인에 쓸 등록 비밀이 지갑 페이지로 전달됩니다.',
      ]);
      if (!ok) return { denied: true };
      const witness = buildWitness(state);
      // 대화상자가 보여 준 그대로를 기록한다 — allowAgent 는 예/아니오 로 보였으므로 '1'/'0' 로 굳힌다.
      state.consents[rpOrigin] = { arid: arid === undefined || arid === null ? null : String(arid), allowAgent: agentOk ? '1' : '0', grantedAt: new Date().toISOString() };
      await setState(state);
      return witness;
    }

    // 속성 공개 동의(스펙 §4.4). 공개할 슬롯·구간과 트랜잭션 대상·금액을 보여 준다.
    case 'consentDisclosure': {
      const { arid, origin: rpOrigin, disclose, to, value, set } = params;
      // V7 집합 소속: 에이전트가 members 로부터 root 를 계산해 증명에 넣는다 — 여기서는 사용자에게 원소를 보여 준다(root 검산은 에이전트 몫, 스펙 §5.2).
      const lines = predicateLines(disclose, set);
      if (lines.length === 0) lines.push('공개하는 속성 없음');
      const ok = await confirm('속성 공개 동의', [
        rpOrigin ? `서비스: ${rpOrigin}` : '서비스: (지갑 페이지)',
        arid === undefined || arid === null ? undefined : `요청 식별자(arid): ${arid}`,   // 없으면 줄 자체를 뺀다(null 은 구분선)
        null,
        '공개할 속성:',
        ...lines,
        null,
        `대상 주소: ${to}`,
        `금액: ${value ?? '0'} wei`,
      ].filter((l) => l !== undefined));
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
      if (!Array.isArray(attrs) || attrs.length !== 4 || !attrs.every((a) => isDec(String(a)))) fail('bad_attrs: attrs 는 10진 문자열 4개');
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

    // V8 세션 폐기 동의(설계 2026-09-24 §4). Snap 에는 Poseidon 이 없어 서명은 에이전트가 세션 증인의 sk_u 로 한다 —
    // 여기서는 동의만 받는다(스펙 §4 의 signRevokeSession RPC 를 이 이름으로 갱신).
    case 'consentRevokeSession': {
      requireRegistered(state);
      const { arid, issuedAt, maxHeight } = params;
      const ok = await confirm('세션 폐기', [
        `서비스 arid: ${arid}`,
        `발급 시각: ${issuedAt}`,
        `만료 블록: ${maxHeight}`,
        null,
        '이 세션을 폐기합니다. 다음 게시부터 이 세션의 로그인·트랜잭션이 거부됩니다.',
      ]);
      return ok ? { ok: true } : { denied: true };
    }

    // 데모 초기화 — 등록 비밀·동의 기록을 모두 지운다.
    case 'reset': {
      const ok = await confirm('등록 초기화', [
        '이 Snap 의 등록을 지웁니다. 등록 비밀(s_u·r_u·sk_u)과 동의 기록이 사라집니다.',
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
