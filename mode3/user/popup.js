// mode3/user/popup.js — 사용자 페이지의 승인 팝업(?authorize=1, 스펙 2026-10-15 §4.2). mode3/wallet.html 의 runAuthorize 를 옮기고
// 메시지 종류(req.type)로 가른다: mode3-config·mode3-precheck·mode3-authorize·mode3-revalidate·mode3-request.
// 요청은 주소창이 아니라 postMessage 로 받고, 결과는 말을 건 오리진에만 돌려준다. 결과에는 비밀이 없다 — 코어의 성공 본문은
// 증명·공개 입력·세션 서명·pk_i 뿐이고(에이전트 /wallet/login 과 같은 모양), userCredIssued·attrsChanged 같은 이름은 혹시 몰라 뺀다.
// passkey-web(2026-11-17 계획 Task 6): 로그인은 승인 뒤 이 창이 zkIdP 인증 창(CIA_ISSUE_AUTH=code)을 다녀오고(idp_return.js — zk 스냅 화면의 goIdpAuth 와 같다),
// 돌아와서 첫 등록(등록 코드)·발급(발급 코드)을 한다. 요청 하나 전체를 core.withSalt 로 감싸 패스키는 한 번만 묻는다(R-8).
// 증명 로그인(2026-11-19 스펙 passkey-proof-login): zkIdP 의 발급 정책이 key 면(public_keys.issueAuth) 등록된 지갑은 인증 창 없이 패스키 증명만으로 발급받고(L1·L2),
// 로그인마다 패스키를 한 번 묻는다(L4). mode3-idp-login 은 zkIdP 페이지의 로그인 증명 요청이다 — zkIdP 오리진이 연 창에만 답한다(L8).
import { $, textKit, createUnlocker, postPresence, errText } from './ui.js';
import { RECOVER_RESULT_KEY, WRAP_END_RESULT_KEY, WRAP_ACCOUNT_RESULT_KEY, WRAP_BACKUP_RESULT_KEY, idpAuthUrl, savePending, takeIdpReturn, readAttrRecord, googleSignupUrl, saveSignupPending, takeGoogleReturn, googleAuthUrl, saveWrapperPending, takeWrapperReturn } from './idp_return.js';
import { newRecoveryCode } from '../../lib/mode3_salt_envelope.js';

const TYPES = ['mode3-config', 'mode3-precheck', 'mode3-authorize', 'mode3-revalidate', 'mode3-request', 'mode3-tx', 'mode3-idp-login'];
/** 동의 창에 보이는 서비스 이름 위생(2026-09-25 리뷰 D-2, wallet.html 과 같다) — 인증서가 덮는 것은 origin 뿐이고 이름은 임의 문자열이다. */
const MAX_SERVICE_NAME = 48;
function cleanServiceName(v) {
  if (typeof v !== 'string') return '';
  const one = v.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
  const cp = [...one];
  return cp.length > MAX_SERVICE_NAME ? `${cp.slice(0, MAX_SERVICE_NAME - 1).join('')}…` : one;
}

/** 저장소·설정을 못 열어 코어 없이 끝나는 팝업 — 첫 요청에 실패만 돌려주고 닫는다(RP 가 120초를 기다리지 않게). */
export function failPopup({ reason, detail }) {
  if (!window.opener) return;
  const onMessage = (ev) => {
    const req = ev.data;
    if (ev.source !== window.opener || !req || !TYPES.includes(req.type)) return;
    window.removeEventListener('message', onMessage);
    try { window.opener.postMessage({ type: `${req.type}-result`, r_s: req.r_s ?? null, result: { ok: false, reason, detail } }, ev.origin); } catch { /* 이미 닫혔다 */ }
    setTimeout(() => window.close(), 3000);
  };
  window.addEventListener('message', onMessage);
  window.opener.postMessage({ type: 'mode3-authorize-ready' }, '*');
}

/** oidc: zkIdP 의 public_keys.oidc(user.js 가 읽어 넘긴다) — 미등록 안내를 Google 용으로 고를지에만 쓴다.
 *  passkey: passkey-web 의 { derive, create }(user.js) — 코어가 이미 받아 salt 를 만든다. 팝업은 직접 부르지 않는다. */
export function runPopup({ core, config, Demo, meta, oidc = { enabled: false }, passkey = null }) {
  const PK = config.secrets === 'passkey-web';
  const WRAP = PK && config.wrapper === true;   // 래퍼 방식(스펙 2026-11-20 zkwrapper): 서비스 로그인이 zkIdP 인증 창 대신 Google 을 다녀온다
  const { tte, tt } = textKit(Demo);
  const { withUnlock } = createUnlocker({ core, Demo });
  let lastReq = null;        // 받은 요청(언어 전환 때 제목·요약을 다시 그린다)
  let lastIdentity = null;   // 신원 줄의 provider(언어 전환 때 요약과 함께 다시 그린다)
  let idpLoginOk = false;    // mode3-idp-login 이 zkIdP 오리진 대조를 통과했는가 — 그 뒤에만 제목·요약을 그린다(리뷰 M5)
  let signupMode = false;    // 패스키 가입 중인가(2026-11-20) — 제목이 "zkIdP 계정 만들기" 가 된다
  let fixedTitle = null;     // 백업 더하기 귀로(salt 봉투, 2026-11-24)의 제목 [키, 기본 문구] — 서비스 요청이 아니라 언어 전환 때도 이 제목을 그린다
  const step = (s) => { $('authStep').textContent = s; };
  const log = (s) => { $('authLog').textContent += `${s}\n`; };

  /** 요청이 무엇을 공개하라는지 사람 말로. 서비스가 보낸 값이므로 전부 textContent 로만 들어간다. */
  function requestConditions(req) {
    if (req.reauth === true) return [tt('wallet_auth_reauth')];
    const out = [];
    const d = Array.isArray(req.disclose) ? req.disclose : [];
    for (let i = 0; i < 6; i++) {
      const s = d[i];
      if (!s) continue;
      const attr = Demo.term(`attr${i}`);
      out.push(String(s.lo ?? '0') === '0' ? tt('wallet_cond_le', { attr, hi: s.hi }) : tt('wallet_cond_range', { attr, lo: s.lo, hi: s.hi }));
    }
    if (req.set && req.set.slot !== undefined && req.set.slot !== null) out.push(tt('wallet_cond_set', { attr: Demo.term(`attr${Number(req.set.slot)}`) }));
    if (req.allowAgent === '1' || req.allowAgent === true) out.push(tt('wallet_cond_agent'));
    return out.filter(Boolean);
  }
  /** 요약 표(#authSummary)에 한 줄을 더한다. 값은 서비스가 보낸 것일 수 있어 textContent 로만 들어간다. */
  function row(labelKey, value) {
    const dt = document.createElement('dt');
    dt.textContent = tt(labelKey) || labelKey;
    const dd = document.createElement('dd');
    dd.textContent = value;
    $('authSummary').append(dt, dd);
  }
  /** 승인 요청을 문장으로 — 서비스·주소, 로그인이면 요청한 조건, 세션 요청이면 서명할 본문. */
  function renderAuthSummary(req) {
    $('authSummary').textContent = '';
    if (req.type === 'mode3-idp-login') { if (idpLoginOk) row('user_auth_idp_origin', req.origin); return; }   // zkIdP 로그인(2026-11-19): 서비스가 아니라 zkIdP 주소 한 줄 — 대조 통과 뒤에만
    row('wallet_auth_service', cleanServiceName(req.serviceName) || req.origin);
    row('wallet_auth_origin', req.origin);
    if (req.type === 'mode3-authorize') {
      const conds = requestConditions(req);
      row('wallet_auth_conditions', conds.length ? conds.join(' · ') : tt('wallet_cond_none'));
    }
    if (req.type === 'mode3-request') row('user_auth_request_title', req.body === 'balance' ? (tt('user_auth_sign_balance') || '현재 잔액 확인 요청에 세션키로 서명합니다') : (tt('user_auth_sign_body', { body: String(req.body) }) || String(req.body)));   // 2026-10-21: RP 의 잔액 확인
  }
  /** 신원 줄(스펙 2026-10-16 §3.2): 어느 계정으로 로그인하는지 — provider 만, 이메일·이름은 없다(범위 밖). */
  function renderAuthIdentity(provider) {
    lastIdentity = provider;
    row('user_auth_identity', provider === 'demo' ? (tt('user_auth_identity_demo') || '데모 계정') : (tt('user_auth_identity_provider', { provider }) || provider));
  }
  /** GIS 버튼을 승인 창 안에 그리고 ID 토큰 하나를 받는다(2026-10-16). { ok, idToken } 또는 { ok:false, reason, detail }. 토큰은 변수로 돌려줄 뿐 저장하지 않는다. */
  function googleToken(cfg, nonce) {
    const gsi = window.Mode3Gsi ?? null;
    if (!gsi) return Promise.resolve({ ok: false, reason: 'gsi_unavailable', detail: '/common/gsi.js' });
    if (!gsi.originOk()) return Promise.resolve({ ok: false, reason: 'gsi_origin', detail: `http://localhost${location.port ? `:${location.port}` : ''}/` });
    const row = $('authGoogle'), slot = $('authGoogleSlot');
    row.hidden = false; slot.replaceChildren();
    return new Promise((resolve) => {
      gsi.render({ el: slot, clientId: cfg.clientId, nonce, text: 'continue_with', onToken: (t) => { row.hidden = true; slot.replaceChildren(); resolve(t ? { ok: true, idToken: t } : { ok: false, reason: 'oidc_invalid', detail: '토큰 없음' }); } })
        .catch((e) => { row.hidden = true; resolve({ ok: false, reason: e?.reason ?? 'gsi_unavailable', detail: e?.message ?? String(e) }); });
    });
  }
  /** 팝업 제목 — 아직 요청이 없으면 대기 문구, 있으면 어느 서비스의 무슨 요청인지. */
  function renderAuthTitle() {
    if (fixedTitle) { $('authTitle').textContent = tt(fixedTitle[0]) || fixedTitle[1]; return; }
    if (!window.opener) { tte($('authTitle'), 'wallet_auth_no_opener'); return; }
    if (!lastReq || lastReq.type === 'mode3-config' || lastReq.type === 'mode3-precheck') { tte($('authTitle'), 'wallet_auth_waiting'); return; }
    // zkIdP 로그인(2026-11-19): 제목은 zkIdP 오리진 대조를 통과한 뒤에만 그린다(리뷰 M5 — 남의 사이트가 이 창을 zkIdP 로그인 화면처럼 보이게 하지 못한다)
    if (lastReq.type === 'mode3-idp-login') { if (idpLoginOk) $('authTitle').textContent = signupMode ? (tt('user_auth_signup_title') || 'zkIdP 계정 만들기') : (tt('user_auth_idp_login_title') || 'zkIdP 로그인'); else tte($('authTitle'), 'wallet_auth_waiting'); return; }
    const service = cleanServiceName(lastReq.serviceName) || lastReq.origin;
    const key = lastReq.type === 'mode3-request' ? null : lastReq.type === 'mode3-tx' ? 'user_auth_tx_title' : lastReq.type === 'mode3-revalidate' ? 'user_auth_revalidate_title' : 'wallet_auth_approving';
    $('authTitle').textContent = key ? (tt(key, { service }) || service) : [service, tt('user_auth_request_title')].filter(Boolean).join(' — ');
  }
  // 언어·전문가 전환 — 제목·요약은 스크립트가 만든 텍스트라 여기서 다시 그린다.
  for (const k of ['setLang', 'setExpert']) {
    const orig = Demo[k];
    Demo[k] = (v) => { orig(v); renderAuthTitle(); if (lastReq && lastReq.origin && lastReq.type !== 'mode3-config') { renderAuthSummary(lastReq); if (lastIdentity) renderAuthIdentity(lastIdentity); } };
  }
  /** 승인·거절 버튼(요약 뒤에 보인다). 창을 닫으면 RP 쪽이 popup_closed 로 끝낸다.
   *  설정의 popupConsent 가 false 면(passkey-web 기본, 2026-11-18 사용자 요청) 버튼 없이 바로 진행한다 — 요약은 그대로 보인다. */
  function waitDecision() {
    if (config.popupConsent === false) return Promise.resolve(true);
    return new Promise((resolve) => {
      const a = $('authApproveBtn'), d = $('authDenyBtn');
      const done = (v) => { a.hidden = true; d.hidden = true; a.removeEventListener('click', onA); d.removeEventListener('click', onD); resolve(v); };
      const onA = () => done(true), onD = () => done(false);
      a.addEventListener('click', onA); d.addEventListener('click', onD);
      a.hidden = false; d.hidden = false;
    });
  }
  const fail = (r, fallback) => ({ ok: false, reason: r.body?.reason ?? fallback, detail: r.body?.detail ?? r.body?.error ?? null, status: r.status, ...(r.body?.demo ? { demo: r.body.demo } : {}) });
  // 등록 실패(코어 registerWith): zkIdP 가 거절하면 reason 은 register_failed 이고 zkIdP 의 사유는 cia 에 있다 — 그쪽을 먼저 본다(zk 스냅 화면 codeRegister 와 같다).
  const regFail = (r) => ({ ok: false, reason: r.body?.cia?.reason ?? r.body?.reason ?? 'register_failed', detail: r.body?.detail ?? r.body?.cia?.detail ?? r.body?.error ?? null, status: r.status });
  /** 승인 창의 안내 한 줄 + 링크(같은 오리진의 사용자 페이지·속성 도구). */
  function showHint(key, fallback, href) {
    const hint = $('authHint');
    hint.textContent = (key ? tt(key) : null) || fallback;
    if (href) { const a = document.createElement('a'); a.href = href; a.target = '_blank'; a.rel = 'noopener'; a.textContent = href; hint.append(' ', a); }
    hint.hidden = false;
  }
  const attrRecord = () => readAttrRecord({ fetch: window.fetch.bind(window), localStorage: window.localStorage });
  /** 계정 복구의 귀로(R-11, zk 스냅 화면 finishRecover 와 같다): 사용자 페이지 탭이 인증 창(등록 모드)을 다녀왔다 — 패스키로 salt → 등록 코드로
   *  등록(같은 계정·같은 auid 면 zkIdP 가 기존 슬롯을 돌려준다 — restored) → 결과를 남기고 사용자 화면으로. 결과·주소에 salt 는 없다. */
  async function finishRecover(back) {
    let out;
    // 복구는 등록 코드로만 한다 — 발급 코드로 돌아왔으면 코어·zkIdP 를 부르지 않고 멈춘다(대기분의 목적 대조가 먼저 거르지만, 목적을 남기지 않은 대기분 대비).
    if (back.purpose !== 'register') {
      out = { ok: false, restored: false, reason: 'recover_purpose_mismatch', detail: `돌아온 목적: ${back.purpose}` };
      try { sessionStorage.setItem(RECOVER_RESULT_KEY, JSON.stringify(out)); } catch { /* 결과를 못 남기면 화면이 상태로만 보인다 */ }
      location.replace('/');
      return;
    }
    step('계정 복구 중… (등록 증명에 수 초 걸린다)');
    try {
      const r = await core.withSalt(() => core.registerWithCode({ uid: back.uid, code: back.code, auid: back.auid, profile: back.req.profile ?? null, recordSalt: null }));
      if (r.status === 201) out = { ok: true, restored: r.body.restored === true, reason: null, detail: null };
      else { const f = regFail(r); out = { ok: false, restored: false, reason: f.reason, detail: f.detail }; }
    } catch (e) { out = { ok: false, restored: false, reason: e?.reason ?? 'internal', detail: e?.message ?? null }; }
    try { sessionStorage.setItem(RECOVER_RESULT_KEY, JSON.stringify(out)); } catch { /* 결과를 못 남기면 화면이 상태로만 보인다 */ }
    location.replace('/');
  }
  /** zkIdP 의 발급 정책(스펙 2026-11-19 passkey-proof-login L2) — 'key' 면 패스키 증명만으로 발급한다. 못 읽으면 'code' 로 본다(인증 창을 거치는 쪽이 안전하다). 창 하나에 한 번만 읽는다. */
  let issueAuthP = null;
  const issueAuthPolicy = () => (issueAuthP ??= (async () => {
    try { const k = await Promise.race([core.idp.publicKeys(), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000))]); return k?.status === 200 && k.body?.issueAuth === 'key' ? 'key' : 'code'; }
    catch { return 'code'; }
  })());
  /** 속성 변경(W5): 속성 도구 기록의 속성으로 맞춘다 — 이번 로그인이 새 속성의 C_u 를 받는다. 기록의 salt 가 이 등록과 다르면 실패(로그인하지 않는다). 기록이 없으면 그대로 통과. */
  async function syncAttrs(rec) {
    if (!rec?.profile) return null;
    const s = await core.syncProfileFromRecord({ recordSalt: rec.s_u ?? null, recordAuid: rec.auid ?? null, profile: rec.profile });   // 기록에는 salt 가 없다(2026-11-20) — auid 로 대조한다(옛 기록만 salt)
    if (s.status === 200) return null;
    step('속성 맞추기 실패 — 로그인하지 않는다.'); log(errText(s.status, s.body));
    return fail(s, 'login_failed');
  }
  /** passkey-web 의 로그인(mode3-authorize, 재승인 제외 — 스펙 W5, 계획 R-10). 처음 온 요청: (Google 이면 승인 전에 passkey_mode) → 승인 → 패스키 연결이 없으면
   *  passkey_setup_required → 미등록인데 속성 도구 기록이 없으면 attr_record_missing — 여기까지는 zkIdP 로 가지 않는다 → 대기 저장분을 두고 이 창이 zkIdP 인증 창
   *  (미등록이면 등록 모드)으로 간다. 돌아온 길(back): 등록 코드면 속성 도구 기록의 salt·속성으로 등록하고 함께 받은 발급 코드로, 발급 코드면 기록의 속성을
   *  맞춘 뒤 그 코드로 로그인한다(loginWith). salt 는 코어가 패스키에서 받는다 — 이 함수는 만지지 않는다. */
  async function authorizePasskey(req, evOrigin, back, { reply, loginWith }) {
    const attrMissing = () => {
      showHint('user_pk_attr_missing_hint', '이 브라우저의 속성 커밋먼트 도구에 기록이 없어 등록할 수 없습니다. 먼저 커밋먼트를 만드세요:', `${location.origin}/attr.html`);
      return reply({ ok: false, reason: 'attr_record_missing' }, { closeMs: 15_000 });
    };
    if (!back) {
      // Google 경로는 이 모드에 없다 — 승인 버튼을 띄우기 전에 거절한다(승인 뒤에 막으면 헛클릭 한 번, 2026-11-17 미뤄 둔 Minor).
      if (req.provider === 'google') { step('설치 없는 패스키 모드에서는 Google 로 로그인하지 않는다.'); return reply({ ok: false, reason: 'passkey_mode' }); }
      const st = await core.status();
      const registered = st.status === 200 ? Boolean(st.body?.registered) : true;   // 상태를 못 읽으면 등록된 것으로 보고 발급 창으로(zkIdP·코어가 다시 거른다)
      if (st.status === 200 && registered) renderAuthIdentity(st.body.provider ?? 'demo');
      if (config.popupConsent !== false) step('요청을 확인하고 승인하세요.');
      if (!(await waitDecision())) { step('동의 거절'); return reply({ ok: false, reason: 'user_denied' }); }
      const ps = await core.passkeyState();
      if (ps.status !== 200 || !ps.body?.credentialId) {
        showHint('user_pk_setup_hint', '이 브라우저에 연결된 패스키가 없습니다. 사용자 페이지에서 먼저 패스키를 설정하세요:', `${location.origin}/`);
        step('패스키 연결 없음 — zkIdP 로 가지 않는다.');
        return reply({ ok: false, reason: 'passkey_setup_required' }, { closeMs: 15_000 });
      }
      if (!registered && !(await attrRecord())) { step('속성 도구 기록 없음 — zkIdP 로 가지 않는다.'); return attrMissing(); }
      // 증명 로그인(스펙 2026-11-19 L1·L2): 등록된 지갑이고 zkIdP 정책이 key 면 인증 창(아이디·비밀번호)으로 가지 않는다 — 패스키 → π_IdP 가 본인 확인이다.
      if (st.status === 200 && registered && (await issueAuthPolicy()) === 'key') {
        const bad = await syncAttrs(await attrRecord());
        if (bad) return reply(bad);
        return loginWith({ authCode: null });
      }
      const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
      savePending(window.sessionStorage, { req, origin: evOrigin, nonce, at: Date.now(), purpose: registered ? 'issue' : 'register' });
      step(registered ? (tt('wallet_auth_to_idp') || 'zkIdP 로그인 페이지로 이동합니다…') : (tt('wallet_auth_to_idp_register') || 'zkIdP 에 처음 등록합니다 — zkIdP 로그인 페이지로 이동합니다…'));
      location.assign(idpAuthUrl({ ciaUrl: config.ciaUrl, walletOrigin: location.origin, nonce, purpose: registered ? 'issue' : 'register' }));
      return;
    }
    renderAuthIdentity('demo');
    const rec = await attrRecord();
    let authCode = back.code;
    if (back.purpose === 'register') {
      if (!rec) { step('속성 도구 기록 없음 — 등록하지 않는다.'); return attrMissing(); }
      step('zkIdP 에 등록하는 중… (등록 증명에 수 초 걸린다)');
      const r = await core.registerWithCode({ uid: back.uid, code: back.code, auid: back.auid, profile: rec.profile, recordSalt: rec.s_u ?? null, recordAuid: rec.auid ?? null });
      if (r.status !== 201) { step('등록 실패'); log(errText(r.status, r.body)); return reply(regFail(r)); }
      authCode = r.body.issue_code;   // CIA_ISSUE_AUTH=key 인 zkIdP 는 발급 코드를 주지 않는다(null) — 그러면 코드 없이 발급된다
      step('zkIdP 에 등록됨 — 이어서 로그인합니다.');
    } else {
      const bad = await syncAttrs(rec);
      if (bad) return reply(bad);
    }
    return loginWith({ authCode });
  }

  // ---- 패스키 가입(스펙 2026-11-20 passkey-google-signup §2): zkIdP 페이지의 "패스키로 로그인" 이 미등록 브라우저에서 Google 로 확인한 이메일로 계정을 만든다 ----
  /** zkIdP 가 패스키 가입을 열어 두었으면 그 OIDC 설정(clientId·signup.authorizeUrl·signup.redirectUri), 아니면 null. */
  async function signupConfig() {
    try {
      const k = await Promise.race([core.idp.publicKeys(), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000))]);
      const o = k?.status === 200 ? k.body?.oidc : null;
      return o?.enabled && typeof o.clientId === 'string' && typeof o.signup?.authorizeUrl === 'string' && typeof o.signup?.redirectUri === 'string' ? o : null;
    } catch { return null; }
  }
  /** 가입 창의 진행 줄(2026-11-20 화면 셀프 피드백 3·4): 보통 화면에도 보이는 한 줄 — 지금 무엇을 하는지 적는다. 경고 색의 안내(#authHint)와 다른 자리다. */
  const statusEl = () => { let e = $('authStatus'); if (!e) { e = document.createElement('p'); e.id = 'authStatus'; e.className = 'desc'; $('authHint').before(e); } return e; };
  const say = (key, fallback) => { const e = statusEl(); e.replaceChildren(document.createTextNode(tt(key) || fallback)); e.hidden = false; step(fallback); };
  /** 진행 줄에 설명과 버튼 하나를 그리고 눌릴 때까지 기다린다(패스키 만들기는 사람이 누른 뒤에 한다). */
  const waitClick = (id, label, key, fallback) => new Promise((resolve) => {
    const e = statusEl(), b = document.createElement('button');
    b.type = 'button'; b.id = id; b.textContent = label;
    e.replaceChildren(document.createTextNode(tt(key) || fallback), document.createElement('br'), b); e.hidden = false;
    b.addEventListener('click', () => resolve(), { once: true });
  });
  /** 1단계: (패스키가 없으면 만들고) 패스키 → uid 예약 → 등록·로그인 증명 → 공개값을 남기고 Google 로 간다. 실패는 zkIdP 페이지에 사유로 돌려준다. */
  async function startSignup(req, evOrigin, oidcCfg, reply) {
    let salt = null;
    signupMode = true; renderAuthTitle();
    const ps = await core.passkeyState();
    if (ps.status !== 200 || !ps.body?.credentialId) {
      if (typeof passkey?.create !== 'function') { step('패스키 연결 없음'); return reply({ ok: false, reason: 'passkey_setup_required' }); }
      await waitClick('authSignupPasskeyBtn', tt('user_signup_make_passkey') || '패스키 만들고 계정 만들기', 'user_signup_intro_new', '이 브라우저는 아직 zkIdP 계정에 연결돼 있지 않습니다. 패스키를 만들고, Google 로 이메일을 한 번 확인해 계정을 만듭니다.');
      say('user_signup_making_passkey', '패스키를 만드는 중입니다 — 브라우저의 패스키 창을 확인하세요.');
      let made;
      try { made = await passkey.create({}); } catch (e) { step('패스키 만들기 실패'); log(e?.message ?? String(e)); return reply({ ok: false, reason: e?.reason ?? 'passkey_cancelled', detail: e?.message ?? null }); }
      const c = await core.passkeyConnect({ credentialId: made.credentialId, s_u: made.s_u, info: made.info ?? null });
      if (c.status !== 200) { step('패스키 연결 실패'); log(errText(c.status, c.body)); return reply(fail(c, 'passkey_setup_failed')); }
      salt = made.s_u;   // 방금 만든 패스키의 값 — 바로 아래에서 다시 묻지 않는다(창의 메모리에만 있다)
    }
    say('user_signup_preparing', '계정을 만들 준비 중입니다 — 패스키를 확인하고 증명을 만듭니다(수 초 걸립니다).');
    const p = await withUnlock(() => core.signupPrepare({ loginNonce: req.nonce, salt }));
    if (p.cancelled) { step('잠금 해제 취소'); return reply({ ok: false, reason: 'user_denied' }); }
    if (p.status !== 200) { step('가입 준비 실패'); log(errText(p.status, p.body)); return reply(fail(p, 'signup_failed')); }
    const { url, state } = googleSignupUrl({ authorizeUrl: oidcCfg.signup.authorizeUrl, clientId: oidcCfg.clientId, redirectUri: oidcCfg.signup.redirectUri, nonce: p.body.googleNonce, walletOrigin: location.origin });
    // 남기는 것은 공개값뿐이다(uid·증명·state·시각) — salt 는 없다. Google 에서 돌아온 이 창만 읽는다(이 오리진·이 창의 sessionStorage).
    saveSignupPending(window.sessionStorage, { state, at: Date.now(), idpOrigin: evOrigin, loginNonce: req.nonce, uid: p.body.uid, reg: p.body.reg, login: p.body.login });
    say('user_signup_to_google', 'Google 로 이동합니다 — 계정을 고르면 그 이메일로 zkIdP 계정을 만듭니다.');
    location.assign(url);
  }
  /** 2단계(Google 에서 돌아온 길): 토큰과 남겨 둔 증명으로 가입+등록 → 미리 만든 zkIdP 로그인 증명을 zkIdP 페이지에 돌려준다. 그 Google 계정의 계정이 이미 있으면
   *  같은 패스키로 복구한다(패스키 한 번 더). zkIdP 페이지와의 연결(opener)이 끊겼으면 가입만 끝내고 다시 누르라고 안내한다. */
  async function finishSignup({ pend, idToken, error }) {
    lastReq = { type: 'mode3-idp-login' }; idpLoginOk = true; signupMode = true; renderAuthTitle();
    let idpOrigin = null;
    try { idpOrigin = new URL(config.ciaUrl).origin; } catch { /* 설정이 망가졌으면 아무에게도 답하지 않는다 */ }
    // 결과는 가기 전에 대조를 통과한 zkIdP 오리진에만 돌려준다
    const canReply = Boolean(window.opener) && Boolean(pend) && idpOrigin !== null && pend.idpOrigin === idpOrigin;
    const done = (result, fallbackKey, fallbackText) => {
      if (canReply) {
        try { window.opener.postMessage({ type: 'mode3-idp-login-result', r_s: null, result }, idpOrigin); } catch (e) { log(`결과 전송 실패: ${e.message}`); }
        setTimeout(() => window.close(), result.ok ? 200 : 3000);
      } else showHint(fallbackKey, fallbackText, null);
    };
    if (!pend) { step('Google 확인 결과를 이어받지 못했다.'); return showHint('user_signup_resume_failed', 'Google 확인 결과를 이어받지 못했습니다 — zkIdP 페이지에서 "패스키로 로그인" 을 다시 누르세요.', null); }
    if (!idToken) { step('Google 확인이 끝나지 않았다.'); log(String(error ?? '')); return done({ ok: false, reason: 'google_denied', detail: error ?? null }, 'user_signup_google_denied', 'Google 확인이 끝나지 않았습니다 — zkIdP 페이지에서 다시 시도하세요.'); }
    try {
      say('user_signup_creating', 'Google 확인이 끝났습니다 — zkIdP 에 계정을 만드는 중입니다.');
      let r = await core.signupFinish({ idToken, uid: pend.uid, reg: pend.reg });
      let login = pend.login ?? null;
      if (r.status === 409 && r.body?.reason === 'signup_exists' && /^[0-9]+$/.test(String(r.body?.cia?.uid ?? ''))) {
        // 이 Google 계정의 zkIdP 계정이 이미 있다 — 같은 패스키면 그 계정으로 잇는다. 그 uid 로 증명을 다시 만들어야 해서 패스키를 한 번 더 묻는다(G7).
        say('user_signup_restore', '이 Google 계정의 zkIdP 계정이 이미 있습니다 — 같은 패스키인지 확인합니다(패스키를 한 번 더 묻습니다).');
        const uid0 = String(r.body.cia.uid);
        const x = await withUnlock(() => core.withSalt(async () => {
          const rr = await core.signupRestore({ idToken, uid: uid0, n: pend.reg.n });
          if (rr.status !== 201) return rr;
          if (!pend.loginNonce) return { status: 201, body: { ...rr.body, login: null } };
          const lp = await core.idpLoginProof({ nonce: pend.loginNonce });
          return lp.status === 200 ? { status: 201, body: { ...rr.body, login: lp.body } } : lp;
        }));
        if (x.cancelled) { step('잠금 해제 취소'); return done({ ok: false, reason: 'user_denied' }, null, '가입을 끝내지 못했습니다.'); }
        r = x; login = x.status === 201 ? x.body.login : null;
      }
      if (r.status !== 201) { step('가입 실패'); log(errText(r.status, r.body)); return done(regFail(r), null, `가입을 끝내지 못했습니다 — ${Demo.reason(r.body?.cia?.reason ?? r.body?.reason)?.title ?? (r.body?.cia?.reason ?? r.body?.reason ?? `HTTP ${r.status}`)}`); }
      say('user_signup_done', `계정을 만들었습니다${r.body?.email ? ` (${r.body.email})` : ''} — 로그인합니다.`);
      if (canReply && login) return done({ ok: true, ...login });   // uid·nonce·π_IdP 필드뿐 — 비밀은 없다
      showHint('user_signup_done_retry', '계정을 만들었습니다 — zkIdP 페이지에서 "패스키로 로그인" 을 다시 누르세요.', null);
      if (canReply) done({ ok: false, reason: 'login_challenge_expired' });
    } catch (e) { step('오류'); log(e?.message ?? String(e)); done({ ok: false, reason: e?.reason ?? 'internal', detail: e?.message ?? null }, null, '가입을 끝내지 못했습니다.'); }
  }
  // Google 에서 돌아온 길(/?authorize=1#google_back=1&state=…&id_token=…) — 중계 화면이 이 창으로 넘겼다. 토큰이 주소창·히스토리에 남지 않게 조각부터 지운다.
  // 준비 신호(ready)를 다시 보내지 않는다 — 보내면 zkIdP 페이지가 같은 요청을 한 번 더 보낸다.
  // ---- 래퍼 로그인(스펙 2026-11-20 zkwrapper §2.2): 서비스 확인 → 요청 키 → Google(계정 선택) → 돌아옴 → 패스키 한 번 → 발급·π_RP → 서비스에 결과 ----
  /** 발급 서버의 래퍼 설정(public_keys: wrapper·oidc.clientId·authorizeUrl·redirectUri), 없으면 null. */
  async function wrapperConfig() {
    try {
      const k = await Promise.race([core.idp.publicKeys(), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000))]);
      const o = k?.status === 200 && k.body?.wrapper === true ? k.body.oidc : null;
      return o?.enabled && typeof o.clientId === 'string' && typeof o.authorizeUrl === 'string' && typeof o.redirectUri === 'string' ? o : null;
    } catch { return null; }
  }
  const loginBodyOf = (req) => ({
    arid: req.arid, origin: req.origin, cert_s: req.cert_s, pk_trace: req.pk_trace, r_s: req.r_s, r_rp: req.r_rp,
    allowAgent: req.allowAgent === '1' || req.allowAgent === true ? '1' : '0',
    factoryAddress: req.factoryAddress ?? null, attrGateAddress: req.attrGateAddress ?? null, disclose: req.disclose ?? null, set: req.set ?? null,
  });
  /** 1단계(서비스가 연 창): 서비스 인증서를 먼저 확인하고(틀린 서비스 때문에 Google 을 다녀오지 않게) 요청 키를 만든 뒤 Google 로 간다. 패스키는 아직 묻지 않는다. */
  async function authorizeWrapper(req, evOrigin, { reply }) {
    const cfg = await wrapperConfig();
    if (!cfg) { step('zkWrapper 설정을 읽지 못했다.'); return reply({ ok: false, reason: 'wrapper_disabled' }); }
    say('user_wrap_checking', '서비스를 확인하는 중입니다…');
    const pre = await core.precheck({ arid: req.arid, origin: req.origin, cert_s: req.cert_s, pk_trace: req.pk_trace, factoryAddress: req.factoryAddress ?? null });
    if (pre.status !== 200) { step('서비스 확인 실패'); log(errText(pre.status, pre.body)); return reply(fail(pre, 'precheck_failed')); }
    // 2026-11-24(사용자 결정): 속성 기본값이 없다 — 서비스가 조건을 거는 칸이 비어 있으면 Google 로 가기 전에 멈추고 속성 도구로 안내한다(패스키도 묻지 않는다)
    const ar = await core.wrapperAttrsReady({ disclose: req.disclose ?? null, set: req.set ?? null, profile: (await attrRecord())?.profile ?? null });
    if (ar.status !== 200) {
      step('속성 커밋먼트 없음 — Google 로 가지 않는다.');
      showHint('user_wrap_attrs_unset_hint', '이 서비스는 속성 조건을 확인합니다. 아직 속성 커밋먼트가 없어 로그인하지 않았습니다 — 속성 커밋먼트 도구에서 넣은 뒤 다시 로그인하세요:', `${location.origin}/attr.html`);
      return reply(fail(ar, 'attrs_unset'), { closeMs: 15_000 });
    }
    if (config.popupConsent !== false) step('요청을 확인하고 승인하세요.');
    if (!(await waitDecision())) { step('동의 거절'); return reply({ ok: false, reason: 'user_denied' }); }
    const b = await core.wrapperBegin();
    if (b.status !== 200) { step('로그인 준비 실패'); log(errText(b.status, b.body)); return reply(fail(b, 'login_failed')); }
    const { url, state } = googleAuthUrl({ authorizeUrl: cfg.authorizeUrl, clientId: cfg.clientId, redirectUri: cfg.redirectUri, nonce: b.body.googleNonce, walletOrigin: location.origin });
    // 남기는 것은 서비스 요청(공개값)·발신 오리진·state·시각뿐이다. Google 에서 돌아온 이 창만 읽는다(이 오리진·이 창의 sessionStorage).
    saveWrapperPending(window.sessionStorage, { state, at: Date.now(), req, origin: evOrigin });
    say('user_wrap_to_google', 'Google 로 이동합니다 — 계정을 고르면 돌아와 패스키로 로그인합니다.');
    location.assign(url);
  }
  /** 홈의 세션 끝내기 귀로(2026-11-23 사용자 요청): 홈 탭이 Google 을 다녀왔다 — 그 토큰(1회용 요청 키에 묶였다)으로 그 세션의 폐기를 요청하고
   *  결과를 남긴 뒤 홈으로 돌아간다. 패스키는 묻지 않는다. 결과·주소에 토큰은 남지 않는다. */
  async function finishWrapperEnd({ pend, idToken, error }) {
    let out;
    step('세션 폐기 요청 중…');
    try {
      if (!idToken) out = { ok: false, reason: 'google_denied', detail: error ?? null };
      else {
        const r = await core.wrapperRevokeSession({ r_s: pend.req.r_s, idToken });
        out = r.status === 200 ? { ok: true, svc: typeof pend.req.svc === 'string' ? pend.req.svc : '', Cf_s: r.body.Cf_s, inserted: r.body.inserted ?? null, pending: r.body.pending ?? null }
          : { ok: false, reason: r.body?.reason ?? (r.status === 404 ? 'unknown_account' : 'internal'), detail: r.body?.error ?? r.body?.detail ?? `HTTP ${r.status}` };
      }
    } catch (e) { out = { ok: false, reason: e?.reason ?? 'internal', detail: e?.message ?? null }; }
    try { sessionStorage.setItem(WRAP_END_RESULT_KEY, JSON.stringify(out)); } catch { /* 결과를 못 남기면 화면이 상태로만 보인다 */ }
    location.replace('/user');   // 2026-11-24: 세션 관리는 /user(홈은 쓰는 법만) — 세션 끝내기도 거기서 시작한다
  }
  /** /user 의 "내 계정 폐기" 귀로(2026-11-24 스펙 home-and-account-recovery 2부): 세션 끝내기와 같다 — 그 토큰으로 계정 폐기를 요청하고 결과를 남긴 뒤 /user 로 돌아간다.
   *  패스키는 묻지 않는다. 결과·주소에 토큰은 남지 않는다. */
  async function finishWrapperAccount({ idToken, error }) {
    let out;
    step('계정 폐기 요청 중…');
    try {
      if (!idToken) out = { ok: false, reason: 'google_denied', detail: error ?? null };
      else {
        const r = await core.wrapperRevokeAccount({ idToken });
        out = r.status === 200 ? { ok: true, sessions: r.body.sessions ?? 0, rpNotified: r.body.rpNotified ?? 0 }
          : { ok: false, reason: r.body?.reason ?? (r.status === 404 ? 'unknown_account' : 'internal'), detail: r.body?.error ?? r.body?.detail ?? `HTTP ${r.status}` };
      }
    } catch (e) { out = { ok: false, reason: e?.reason ?? 'internal', detail: e?.message ?? null }; }
    try { sessionStorage.setItem(WRAP_ACCOUNT_RESULT_KEY, JSON.stringify(out)); } catch { /* 결과를 못 남기면 화면이 상태로만 보인다 */ }
    location.replace('/user');
  }
  // ---- salt 봉투(계획 2026-11-24 salt-envelope Task 5): /user 의 백업 더하기·지우기 귀로, 승인 창의 패스키 분실 복구 화면 ----
  // 패스키는 클릭 한 번에 한 번만 묻는다 — 사용자 동작이 있어야 WebAuthn 을 여는 브라우저 대비 [m11]. salt·PRF·복구 코드는 화면 메모리에만 있고 끝나면 지운다.
  /** 진행 줄(#authStatus)을 nodes 로 다시 그린다 — 문자열은 글자, null 은 건너뛴다. */
  const drawStatus = (...nodes) => { const e = statusEl(); e.replaceChildren(...nodes.filter((n) => n !== null && n !== undefined).map((n) => (typeof n === 'string' ? document.createTextNode(n) : n))); e.hidden = false; return e; };
  /** 앞 시도가 왜 안 됐는지 한 줄(굵게) — 없으면 null. */
  const noteEl = (note) => { if (!note) return null; const p = document.createElement('span'); const b = document.createElement('strong'); b.textContent = note; p.append(document.createElement('br'), b); return p; };
  const mkBtn = (id, label, ghost = false) => { const b = document.createElement('button'); b.type = 'button'; if (id) b.id = id; b.textContent = label; if (ghost) b.className = 'btn-ghost'; return b; };
  /** 설명·앞 시도의 실패·버튼 하나를 그리고 눌릴 때까지 기다린다. */
  const clickOnce = (btn, intro, note = null) => new Promise((resolve) => { drawStatus(intro, noteEl(note), document.createElement('br'), btn); btn.addEventListener('click', () => resolve(), { once: true }); });
  /** 사유 한 줄(제목 — 조치). */
  const whyOf = (r) => { const x = Demo.reason(r.body?.reason); return x?.title ? [x.title, x.action].filter(Boolean).join(' — ') : (r.body?.reason ?? `HTTP ${r.status}`); };
  /** 보내기 전에 멈춘 실패(패스키 창 취소·같은 인증기·코드 오타) — 코어가 요청 키를 남겼으니 같은 화면에서 다시 한다. */
  const keptKey = (r) => typeof r.body?.reason === 'string' && (r.body.reason.startsWith('passkey_') || r.body.reason.startsWith('recovery_code_'));
  const backupCountOf = (list) => (Array.isArray(list) ? list.filter((e) => e?.kind === 'passkey' || e?.kind === 'code').length : 0);
  const saveBackupResult = (out) => { try { sessionStorage.setItem(WRAP_BACKUP_RESULT_KEY, JSON.stringify(out)); } catch { /* 결과를 못 남기면 /user 가 목록으로만 보인다 */ } };
  const failOut = (r) => ({ ok: false, reason: r.body?.reason ?? (r.status === 404 ? 'unknown_account' : 'internal'), detail: r.body?.detail ?? r.body?.error ?? null });
  /** 백업 더하기 귀로(/user 의 "백업 패스키 더하기"·"복구 코드 만들기"): /user 탭이 Google 을 다녀왔다(1회용 요청 키에 묶인 토큰).
   *  백업 패스키: ① 지금 패스키로 확인(salt — withSalt 범위의 메모) → ② 백업 패스키 만들기(코어가 지금 패스키·아는 백업을 빼고 만든다 [I7]).
   *  복구 코드: 여기서 만들어 한 번 보이고(Google 로 가기 전에 만들지 않는다 — sessionStorage 에 남지 않게), 적었다고 하면 지우고 다시 입력받는다. 저장을 누를 때 지금 패스키로 확인한다.
   *  보내기 전의 실패는 이 자리에서 다시, 보낸 뒤에는 결과(공개값)를 남기고 /user 로 간다. */
  async function finishWrapperBackupAdd({ pend, idToken, error }) {
    const kind = pend.req.kind === 'code' ? 'code' : 'passkey';
    fixedTitle = kind === 'code' ? ['user_backup_code_title', '복구 코드 만들기'] : ['user_backup_passkey_title', '백업 패스키 더하기'];
    renderAuthTitle();
    const finish = (out) => { saveBackupResult({ op: 'add', kind, ...out }); location.replace('/user'); };
    const done = (r) => finish(r.status === 200 ? { ok: true, n: backupCountOf(r.body?.envelopes) } : failOut(r));
    if (!idToken) return finish({ ok: false, reason: 'google_denied', detail: error ?? null });
    try {
      if (kind === 'passkey') {
        let note = null;
        for (;;) {
          await clickOnce(mkBtn('authBackupConfirmBtn', tt('user_backup_confirm_btn') || '① 지금 패스키로 확인'), tt('user_backup_passkey_intro') || 'Google 확인이 끝났습니다. 두 번 누릅니다 — ① 지금 패스키로 본인 확인, ② 백업 패스키 만들기.', note);
          say('user_backup_confirming', '지금 패스키를 확인하는 중입니다 — 브라우저의 패스키 창을 확인하세요.');
          const r = await core.withSalt(async () => {
            const a = await core.passkeyAuid();
            if (a.status !== 200) return a;
            let n2 = null;
            for (;;) {
              await clickOnce(mkBtn('authBackupCreateBtn', tt('user_backup_create_btn') || '② 백업 패스키 만들기'), tt('user_backup_create_intro') || '확인했습니다. 이제 백업 패스키를 만드세요 — 다른 기기나 보안 키를 고릅니다.', n2);
              say('user_backup_creating', '백업 패스키를 만드는 중입니다 — 브라우저의 패스키 창에서 다른 기기나 보안 키를 고르세요.');
              const x = await core.wrapperEnvelopeAdd({ idToken, kind: 'passkey' });
              if (x.status === 200 || !keptKey(x)) return x;
              n2 = whyOf(x);
            }
          });
          if (r.status === 200 || !keptKey(r)) return done(r);
          note = whyOf(r);
        }
      }
      const code = newRecoveryCode();
      const canon = (v) => String(v ?? '').toUpperCase().replace(/[-\s]/g, '').replace(/[IL]/g, '1').replace(/O/g, '0');
      const input = document.createElement('input'); input.id = 'authBackupCodeInput'; input.autocomplete = 'off'; input.spellcheck = false; input.size = 36;
      let show = true, note = null;
      for (;;) {
        if (show) {
          const c = document.createElement('code'); c.id = 'authBackupCode'; c.style.cssText = 'font-size:1.15em;user-select:all;word-break:break-all'; c.textContent = code;
          const ok = mkBtn('authBackupCodeWrittenBtn', tt('user_backup_code_written_btn') || '적었습니다');
          await new Promise((resolve) => { drawStatus(tt('user_backup_code_intro') || '아래 복구 코드를 안전한 곳에 적으세요.', document.createElement('br'), c, document.createElement('br'), ok); ok.addEventListener('click', () => resolve(), { once: true }); });
          c.textContent = '';
          show = false;
        }
        const save = mkBtn('authBackupCodeSaveBtn', tt('user_backup_code_save_btn') || '확인하고 저장'), again = mkBtn('authBackupCodeAgainBtn', tt('user_backup_code_again_btn') || '코드 다시 보기', true);
        const act = await new Promise((resolve) => {
          drawStatus(tt('user_backup_code_retype') || '적은 코드를 그대로 다시 입력하세요.', noteEl(note), document.createElement('br'), input, ' ', save, ' ', again);
          save.addEventListener('click', () => resolve('save'), { once: true });
          again.addEventListener('click', () => resolve('again'), { once: true });
          input.focus();
        });
        if (act === 'again') { show = true; note = null; continue; }
        if (canon(input.value) !== canon(code)) { note = tt('user_backup_code_mismatch') || '입력한 코드가 보여 드린 코드와 다릅니다 — 다시 확인하세요.'; continue; }
        say('user_backup_saving', '백업을 저장하는 중입니다 — 지금 패스키로 한 번 확인합니다.');
        const r = await core.wrapperEnvelopeAdd({ idToken, kind: 'code', code });
        if (r.status === 200 || !keptKey(r)) { input.value = ''; return done(r); }
        note = whyOf(r);
      }
    } catch (e) { finish({ ok: false, reason: e?.reason ?? 'internal', detail: e?.message ?? null }); }
  }
  /** 백업 지우기 귀로: 그 토큰과 지금 패스키로 봉투 하나를 지우고 결과를 남긴 뒤 /user 로. 최종 검토 I-1(2026-11-24): 지우기도 계정의 auid 를 실어야 해서(Google 계정만으로는
   *  지우지 못하게) 지금 패스키를 한 번 묻는다 — 버튼을 누를 때(클릭 한 번에 WebAuthn 한 번). 창을 취소하면 그 자리에서 다시. 이미 그 백업으로 복구한 기기는 자기 사본으로 계속 된다 [m6]. */
  async function finishWrapperBackupRemove({ pend, idToken, error }) {
    const kind = pend.req.kind === 'passkey' || pend.req.kind === 'code' ? pend.req.kind : null;
    fixedTitle = ['user_backup_remove_title', '백업 지우기'];
    renderAuthTitle();
    const finish = (out) => { saveBackupResult({ op: 'remove', kind, ...out }); location.replace('/user'); };
    if (!idToken) return finish({ ok: false, reason: 'google_denied', detail: error ?? null });
    try {
      let note = null;
      for (;;) {
        await clickOnce(mkBtn('authBackupRemoveBtn', tt('user_backup_remove_confirm_btn') || '지금 패스키로 확인하고 지우기'), tt('user_backup_remove_intro') || 'Google 확인이 끝났습니다. 지금 패스키로 한 번 확인하면 이 백업을 지웁니다.', note);
        say('user_backup_removing', '백업을 지우는 중입니다 — 브라우저의 패스키 창을 확인하세요.');
        const r = await core.wrapperEnvelopeRemove({ idToken, id: pend.req.id });
        if (r.status === 200) return finish({ ok: true, n: backupCountOf(r.body?.envelopes) });
        if (!keptKey(r)) return finish(failOut(r));
        note = whyOf(r);
      }
    } catch (e) { finish({ ok: false, reason: e?.reason ?? 'internal', detail: e?.message ?? null }); }
  }
  // 복구 화면에서 다시 해 볼 수 있는 실패 — 코어가 요청 키를 남긴다(그 밖은 서비스에서 처음부터: 발급이 받아들여진 뒤의 실패·토큰을 썼다·계정 폐기·10분이 지났다).
  const RECOVER_AGAIN = new Set(['recovery_code_typo', 'recovery_code_format', 'envelope_open_failed', 'envelope_credential_mismatch', 'recover_auid_mismatch', 'envelope_unknown']);
  /** 패스키 분실 복구 화면: 발급이 409 auid_pinned(이 Google 계정은 다른 salt 에 묶였다)이고 이 계정에 백업이 있다. 봉투마다 버튼 —
   *  백업 패스키(그 credential 로 좁힌 확인 한 번)·복구 코드(입력칸 #authRecoverCode — 코드 봉투가 여럿이면 차례로 열어 본다). 실패하면 이 자리에서 다시
   *  (요청 키는 Google 확인 뒤 10분 동안 남는다 [m2]). 코드는 입력칸에서만 읽고 끝나면 지운다. 돌려주는 값은 wrapperLoginRecover 의 마지막 응답. */
  async function recoverWrapper({ req, pend, idToken, envelopes }) {
    const opts = { idToken, verifiedOrigin: pend.origin, serviceName: cleanServiceName(req.serviceName) || null, policy: req.policy ?? null };
    const keys = envelopes.filter((e) => e.kind === 'passkey' || e.kind === 'device');
    const codes = envelopes.filter((e) => e.kind === 'code');
    const input = document.createElement('input'); input.id = 'authRecoverCode'; input.autocomplete = 'off'; input.spellcheck = false; input.size = 36;
    const go = mkBtn('authRecoverCodeBtn', tt('user_recover_code_go') || '복구');
    const row = document.createElement('p'); row.id = 'authRecoverCodeRow'; row.hidden = true;
    const lab = document.createElement('label'); lab.append(document.createTextNode(`${tt('user_recover_code_label') || '복구 코드'} `), input);
    row.append(lab, ' ', go);
    let note = null;
    for (;;) {
      const list = document.createElement('p'); list.id = 'authRecoverList'; list.className = 'auth-actions';
      const choice = await new Promise((resolve) => {
        const many = { passkey: keys.filter((e) => e.kind === 'passkey').length > 1, device: keys.filter((e) => e.kind === 'device').length > 1 }, nth = { passkey: 0, device: 0 };
        for (const e of keys) {
          const n = String(++nth[e.kind]);
          const label = e.kind === 'passkey' ? (tt(many.passkey ? 'user_recover_passkey_n_btn' : 'user_recover_passkey_btn', { n }) || '백업 패스키로 복구') : (tt(many.device ? 'user_recover_device_n_btn' : 'user_recover_device_btn', { n }) || '복구한 다른 기기의 패스키로 복구');
          const b = mkBtn(null, label, e.kind === 'device'); b.dataset.kind = e.kind; b.dataset.id = e.id;
          b.addEventListener('click', () => resolve({ ids: [e.id], code: null }), { once: true });
          list.append(b, ' ');
        }
        if (codes.length) {
          const b = mkBtn(null, tt('user_recover_code_btn') || '복구 코드로 복구', keys.length > 0); b.dataset.kind = 'code';
          b.addEventListener('click', () => { row.hidden = false; input.focus(); });
          list.append(b);
          go.onclick = () => { if (input.value.trim()) resolve({ ids: codes.map((e) => e.id), code: input.value }); };
        }
        drawStatus(tt('user_recover_intro') || '이 Google 계정에는 백업이 있습니다 — 백업으로 같은 계정을 되찾습니다.', noteEl(note), list, row);
      });
      say('user_recover_working', '백업을 열고 로그인하는 중입니다 — 세션 토큰을 받고 증명을 만듭니다(수 초 걸립니다).');
      let r = null;
      for (const id of choice.ids) {
        r = await core.wrapperLoginRecover(loginBodyOf(req), { ...opts, envelopeId: id, code: choice.code });
        // 코드 봉투가 여럿이면 이 봉투의 코드가 아닐 때(열리지 않는다) 다음 봉투로 — 형식·오타는 어느 봉투에도 같다
        if (choice.code === null || r.body?.reason !== 'envelope_open_failed') break;
      }
      const reason = r.body?.reason ?? null;
      if (r.status !== 200 && typeof reason === 'string' && (reason.startsWith('passkey_') || RECOVER_AGAIN.has(reason))) {
        note = choice.code !== null && reason === 'envelope_open_failed' ? (tt('user_recover_code_wrong') || '코드가 맞지 않습니다 — 적어 둔 코드를 다시 확인하세요.') : whyOf(r);
        if (choice.code !== null) row.hidden = false;
        continue;
      }
      input.value = '';
      return r;
    }
  }
  /** 2단계(Google 에서 돌아온 길): (패스키가 없으면 버튼 한 번으로 만들고) 패스키 → 발급 → π_RP → 서비스에 결과. 결과는 가기 전에 대조를 통과한 서비스 오리진(pend.origin)에만 돌려준다. */
  async function finishWrapper({ pend, idToken, error }) {
    if (!pend) { renderAuthTitle(); step('Google 확인 결과를 이어받지 못했다.'); return showHint('user_wrap_resume_failed', 'Google 확인 결과를 이어받지 못했습니다 — 서비스 페이지에서 다시 로그인하세요.', null); }
    const req = pend.req, t0 = pend.at;
    lastReq = req; renderAuthTitle(); renderAuthSummary(req);
    const reply = (result, { closeMs } = {}) => {
      if (!window.opener) { if (!result.ok) showHint('user_wrap_resume_failed', 'Google 확인 결과를 이어받지 못했습니다 — 서비스 페이지에서 다시 로그인하세요.', null); return; }
      try { window.opener.postMessage({ type: `${req.type}-result`, r_s: req.r_s ?? null, result }, pend.origin); } catch (e) { log(`결과 전송 실패: ${e.message}`); }
      setTimeout(() => window.close(), closeMs ?? (result.ok ? 200 : 3000));
    };
    try {
      if (!idToken) { step('Google 확인이 끝나지 않았다.'); log(String(error ?? '')); return reply({ ok: false, reason: 'google_denied', detail: error ?? null }); }
      const googleMs = Date.now() - t0;
      let salt = null, envKey = null;
      const ps = await core.passkeyState();
      if (ps.status !== 200 || !ps.body?.credentialId) {
        if (typeof passkey?.create !== 'function') { step('패스키 연결 없음'); return reply({ ok: false, reason: 'passkey_setup_required' }); }
        await waitClick('authWrapPasskeyBtn', tt('user_wrap_make_passkey') || '패스키 만들고 로그인', 'user_wrap_intro_new', 'Google 확인이 끝났습니다. 이 브라우저에는 아직 패스키가 없습니다 — 패스키를 만들면 그 값으로 바로 로그인합니다.');
        say('user_signup_making_passkey', '패스키를 만드는 중입니다 — 브라우저의 패스키 창을 확인하세요.');
        let made;
        try { made = await passkey.create({}); } catch (e) { step('패스키 만들기 실패'); log(e?.message ?? String(e)); return reply({ ok: false, reason: e?.reason ?? 'passkey_cancelled', detail: e?.message ?? null }); }
        const c = await core.passkeyConnect({ credentialId: made.credentialId, s_u: made.s_u, info: made.info ?? null });
        if (c.status !== 200) { step('패스키 연결 실패'); log(errText(c.status, c.body)); return reply(fail(c, 'passkey_setup_failed')); }
        salt = made.s_u;   // 방금 만든 패스키의 값 — 이 로그인에 바로 쓴다(창의 메모리에만 있다)
        envKey = made.envKey ?? null;   // 그 패스키의 봉투 열쇠(추출 불가 CryptoKey) — auid_pinned 뒤 복구가 이 기기 봉투를 만든다(다시 묻지 않는다 [I5])
      }
      const rec = await attrRecord();
      for (;;) {
        say('user_wrap_logging_in', '패스키를 확인하고 로그인하는 중입니다 — 세션 토큰을 받고 증명을 만듭니다(수 초 걸립니다).');
        const lg = await withUnlock(() => core.wrapperLogin(loginBodyOf(req), { idToken, verifiedOrigin: pend.origin, serviceName: cleanServiceName(req.serviceName) || null, policy: req.policy ?? null, googleMs, salt, envKey, profile: rec?.profile ?? null, recordAuid: rec?.auid ?? null }));
        if (lg.cancelled) { step('잠금 해제 취소'); return reply({ ok: false, reason: 'user_denied' }); }
        if (lg.status === 200) {
          const { userCredIssued, attrsChanged, ...toRp } = lg.body;
          await postPresence(core);
          step('로그인 성공 — 창을 닫는다.');
          return reply({ ok: true, ...toRp });
        }
        // 패스키를 취소했으면 Google 을 다시 다녀오지 않고 이 자리에서 한 번 더 물을 수 있다(토큰·요청 키는 아직 쓰지 않았다).
        if (lg.body?.reason === 'passkey_cancelled') { await waitClick('authWrapRetryBtn', tt('user_wrap_retry_passkey') || '패스키 다시 확인', 'user_wrap_passkey_cancelled', '패스키 확인이 취소됐습니다 — 다시 확인하면 이어서 로그인합니다.'); continue; }
        // salt 봉투(2026-11-24 Task 5): 이 Google 계정은 다른 패스키(salt)에 묶였고 서버에 백업이 있다 — 복구 화면. 백업이 없으면 아래의 지금 안내 그대로.
        const envs = lg.status === 409 && lg.body?.reason === 'auid_pinned' && Array.isArray(lg.body.recover?.envelopes) ? lg.body.recover.envelopes : [];
        if (envs.length) {
          const rr = await recoverWrapper({ req, pend, idToken, envelopes: envs });
          if (rr.status === 200) {
            const { userCredIssued, attrsChanged, ...toRp } = rr.body;
            await postPresence(core);
            step('복구·로그인 성공 — 창을 닫는다.');
            return reply({ ok: true, ...toRp });
          }
          step('복구 실패'); log(errText(rr.status, rr.body));
          showHint('user_recover_restart', '복구를 끝내지 못했습니다 — 서비스 페이지에서 다시 "zkWrapper 로 로그인" 을 누르세요.', null);
          return reply(fail(rr, 'login_failed'), { closeMs: 15_000 });
        }
        step('로그인 실패'); log(errText(lg.status, lg.body));
        return reply(fail(lg, 'login_failed'));
      }
    } catch (e) { step('오류'); log(e?.message ?? String(e)); reply({ ok: false, reason: e?.reason ?? 'internal', detail: e?.message ?? null }); }
  }
  // 래퍼 로그인의 귀환 — 가입 귀환과 같은 조각(#google_back=1…)이라 방식에 따라 한쪽만 본다. 준비 신호(ready)를 다시 보내지 않는다.
  const wback = WRAP ? takeWrapperReturn({ hash: location.hash, storage: window.sessionStorage, now: Date.now() }) : null;
  if (wback) { history.replaceState(null, '', `${location.pathname}?authorize=1`); const ty = wback.pend?.req?.type; if (ty === 'mode3-end-session') finishWrapperEnd(wback); else if (ty === 'mode3-revoke-account') finishWrapperAccount(wback); else if (ty === 'mode3-envelope-add') finishWrapperBackupAdd(wback); else if (ty === 'mode3-envelope-remove') finishWrapperBackupRemove(wback); else finishWrapper(wback); return; }
  const gback = PK && !WRAP ? takeGoogleReturn({ hash: location.hash, storage: window.sessionStorage, now: Date.now() }) : null;
  if (gback) { history.replaceState(null, '', `${location.pathname}?authorize=1`); finishSignup(gback); return; }

  // passkey-web: zkIdP 인증 창에서 돌아온 길(?authorize=1&idp_…). 계정 복구는 팝업이 아니라 사용자 페이지 탭이 다녀온 길이라 opener 가 없다 — opener 검사보다 먼저 본다(R-11).
  // 대기 저장분은 이 오리진·이 창의 sessionStorage 라 그 창이 남긴 것만 있다(takeIdpReturn 이 nonce·나이를 본다).
  const back = PK ? takeIdpReturn({ search: location.search, storage: window.sessionStorage, now: Date.now() }) : null;
  if (back) history.replaceState(null, '', `${location.pathname}?authorize=1`);   // 1회용 코드가 주소창·히스토리에 남지 않게
  if (back?.req?.type === 'mode3-recover') { finishRecover(back); return; }
  // 이어받지 못한 돌아온 길은 안내만 하고 멈춘다 — ready 를 다시 보내면 RP 가 같은 요청을 한 번 더 보낸다(그 요청은 승인을 다시 받아야 한다).
  if (back && back.req?.type !== 'mode3-authorize') {
    renderAuthTitle();
    const msg = tt('wallet_auth_resume_failed') || 'zkIdP 인증 결과를 이어받지 못했습니다 — 서비스 페이지에서 다시 로그인하세요.';
    step(msg); showHint('wallet_auth_resume_failed', msg, null);
    return;
  }
  if (!window.opener) { renderAuthTitle(); step('이 창은 RP 페이지가 열어야 한다(window.opener 가 없다).'); return; }

  /** 요청 한 건의 처리. evOrigin = 그 요청을 보낸 창의 오리진(postMessage 의 ev.origin — zkIdP 에서 돌아온 길이면 가기 전에 대조를 통과한 그 값).
   *  back = zkIdP 에서 돌아온 길(takeIdpReturn) — 있으면 승인은 이미 받았다(R-10). */
  async function handle(req, evOrigin, back = null) {
    // 결과는 요청을 보낸 창에만 돌려준다. 오리진이 어긋나면 진행하지 않고 실제로 말을 건 오리진에 실패만 알린다.
    const target = evOrigin === req.origin ? req.origin : evOrigin;
    // closeMs: 창을 닫기까지의 지연 — 기본은 성공 200ms·실패 3초(이유를 잠시 보이게), 미등록 안내처럼 읽을 것이 있으면 호출부가 늘린다.
    const reply = (result, { closeMs } = {}) => {
      try { window.opener.postMessage({ type: `${req.type}-result`, r_s: req.r_s ?? null, result }, target); }
      catch (e) { log(`결과 전송 실패: ${e.message}`); }
      setTimeout(() => window.close(), closeMs ?? (result.ok ? 200 : 3000));
    };
    lastReq = req;
    renderAuthTitle();
    try {
      // 설정 조회(R5): 사용자 페이지가 아는 RP 오리진에만, uid 없이 등록 여부·세션 수만.
      if (req.type === 'mode3-config') {
        if (!(config.rpOrigins ?? []).includes(evOrigin)) { step('모르는 RP — 설정을 알려 주지 않는다.'); log(`메시지 오리진=${evOrigin}`); return reply({ ok: false, reason: 'origin_mismatch' }); }
        const h = await core.health();
        step('설정을 알렸다 — 창을 닫는다.');
        return reply({ ok: true, secrets: config.secrets ?? 'web', registered: h.registered, rpCount: h.rpCount, sessions: h.sessions });
      }
      if (evOrigin !== req.origin) {
        step('오리진 불일치 — 이 요청은 진행하지 않는다.');
        log(`메시지 오리진=${evOrigin}\n인증서 오리진=${req.origin}`);
        return reply({ ok: false, reason: 'origin_mismatch' });
      }
      if (req.type === 'mode3-idp-login') {
        // zkIdP 페이지의 증명 로그인(스펙 2026-11-19 L8): **zkIdP 오리진이 연 창에만** 답한다. 다른 사이트가 자기 nonce 로 이 증명을 받아 가면 그 사이트가 이 사용자로 zkIdP 에
        // 들어간다 — 이 대조가 피싱 방어의 전부다. 위의 evOrigin === req.origin 은 이미 통과했으므로 여기서는 설정의 zkIdP 오리진과 견준다. RP 인증서 검사는 없다(zkIdP 는 RP 가 아니다).
        let idpOrigin = null;
        try { idpOrigin = new URL(config.ciaUrl).origin; } catch { /* 설정이 망가졌으면 아무에게도 답하지 않는다 */ }
        if (!idpOrigin || evOrigin !== idpOrigin) { step('zkIdP 가 아닌 페이지의 로그인 요청 — 진행하지 않는다.'); log(`메시지 오리진=${evOrigin}`); return reply({ ok: false, reason: 'origin_mismatch' }); }
        // 증명 로그인은 passkey-web 의 것이다(리뷰 M10) — web 모드의 동작은 건드리지 않는다(코어도 같은 사유로 거절한다)
        if (!PK) { step('이 모드에서는 zkIdP 로그인 증명을 내지 않는다.'); return reply({ ok: false, reason: 'not_passkey_mode' }); }
        idpLoginOk = true; renderAuthTitle(); renderAuthSummary(req);
        const st = await core.status();
        if (st.status === 200 && !st.body?.registered) {
          // 패스키 가입(스펙 2026-11-20 passkey-google-signup): zkIdP 가 그 길을 열어 두었으면 여기서 계정을 만든다 — 아니면 지금까지처럼 등록 없음.
          const su = await signupConfig();
          if (!su) { step('등록 없음 — 이 브라우저는 zkIdP 계정에 연결돼 있지 않다.'); return reply({ ok: false, reason: 'not_registered' }); }
          return await startSignup(req, evOrigin, su, reply);
        }
        if (config.popupConsent !== false) step('zkIdP 로그인 요청을 확인하고 승인하세요.');
        if (!(await waitDecision())) { step('동의 거절'); return reply({ ok: false, reason: 'user_denied' }); }
        step('zkIdP 로그인 증명 생성 중… (수 초 걸린다)');
        const r = await withUnlock(() => core.idpLoginProof({ nonce: req.nonce }));
        if (r.cancelled) { step('잠금 해제 취소'); return reply({ ok: false, reason: 'user_denied' }); }
        if (r.status !== 200) { step('증명 실패'); log(errText(r.status, r.body)); return reply(fail(r, 'login_failed')); }
        step('zkIdP 로그인 증명 완료 — 창을 닫는다.');
        return reply({ ok: true, ...r.body });   // uid·nonce·π_IdP 필드뿐 — 비밀은 없다
      }
      // 요약은 오리진 대조를 통과한 뒤에만 그린다 — 남이 보낸 서비스 이름을 승인 화면에 먼저 띄우지 않는다.
      renderAuthSummary(req);
      const certOf = (extra = {}) => ({ arid: req.arid, origin: req.origin, cert_s: req.cert_s, pk_trace: req.pk_trace, factoryAddress: req.factoryAddress ?? null, ...extra });

      if (req.type === 'mode3-precheck') {
        step('RP 인증서·팩토리 검사 중…');
        const pre = await core.precheck(certOf({ r_s: req.r_s ?? null }));
        if (pre.status !== 200) { step('RP 검증 실패'); log(errText(pre.status, pre.body)); return reply(fail(pre, 'precheck_failed')); }
        step('RP 검증 통과 — 창을 닫는다.');
        return reply({ ok: true });
      }

      if (req.type === 'mode3-revalidate') {
        // 동의 화면 없음(스펙): 캐시 히트면 바로 끝나고, 재증명이면 진행 문구만 보인다. 세션·오리진 대조는 코어가 한다.
        step('세션 재검증 중… (증명을 다시 만들어야 하면 수 초 걸린다)');
        const r = await withUnlock(() => core.revalidate({ r_s: req.r_s, skipSync: req.skipSync === true, arid: req.arid ?? null, origin: evOrigin }));
        if (r.cancelled) { step('잠금 해제 취소'); return reply({ ok: false, reason: 'user_denied' }); }
        if (r.status !== 200) { step('재검증 실패'); log(errText(r.status, r.body)); return reply(fail(r, 'revalidate_failed')); }
        await postPresence(core);
        step('재검증 완료 — 창을 닫는다.');
        return reply({ ok: true, ...r.body });
      }

      // 로그인·세션 요청은 인증서 검사를 통과해야 승인 버튼을 띄운다(2026-09-22 최종 리뷰 Important 1 — 임의 페이지가 자기 오리진·
      // 자기가 쓴 서비스 이름으로 동의 화면을 띄우지 못하게). 세션 요청·재승인은 r_s 를 함께 보내 그 RP 의 세션인지도 본다.
      step('RP 인증서·팩토리 검사 중…');
      const withSession = req.type === 'mode3-request' || req.type === 'mode3-tx' || req.reauth === true;
      const pre = await core.precheck(certOf({ r_s: withSession ? req.r_s : null }));
      if (pre.status !== 200) { step('RP 검증 실패'); log(errText(pre.status, pre.body)); return reply(fail(pre, 'precheck_failed')); }

      if (req.type === 'mode3-tx') {
        // 온체인 출금(2026-10-16): RP 페이지가 이 세션의 계정으로 보내 달라고 한다. 받는 주소·금액을 보여 주고 승인 뒤 코어가 증명·세션키 서명으로
        // execute calldata 를 만들고, 그 RP 의 릴레이(evOrigin — 세션의 오리진과 같아야 한다)가 보낸다. 사용자 페이지의 "트랜잭션 보내기"와 같은 경로.
        const s = await meta.session(req.r_s);
        if (!s || (s.origin && s.origin !== evOrigin)) { step('이 RP 의 세션이 아니다.'); return reply({ ok: false, reason: 'no_session' }); }
        const value = String(req.value ?? '0');
        if (typeof req.to !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(req.to) || !/^[0-9]+$/.test(value) || (req.data !== undefined && !/^0x([0-9a-fA-F]{2})*$/.test(String(req.data)))) { step('요청 형식 오류'); return reply({ ok: false, reason: 'malformed' }); }
        row('wallet_auth_tx_to', req.to); row('wallet_auth_tx_value', `${value} wei`);
        if (config.popupConsent !== false) step('보낼 트랜잭션을 확인하고 승인하세요.');
        if (!(await waitDecision())) { step('거절'); return reply({ ok: false, reason: 'user_denied' }); }
        // 시연(2026-11-23): ① buildOnly — 지금의 root·nonce 로 증명만 만들어 두고 보내지 않는다. ② replay — 코어가 ① 의 증명에 지금 root 만 붙인다.
        const replay = req.replay === true, buildOnly = !replay && req.buildOnly === true;
        step(replay ? '옛 증명·세션키 서명 중…' : buildOnly ? '증명 만드는 중… (보내지 않는다)' : '증명·세션키 서명 중… (수 초 걸린다)');
        const p = await withUnlock(() => core.prepareTx({ r_s: req.r_s, to: req.to, value, data: req.data ?? '0x', ...(replay ? { replay: true } : {}), ...(buildOnly ? { buildOnly: true } : {}) }));
        if (p.cancelled) { step('잠금 해제 취소'); return reply({ ok: false, reason: 'user_denied' }); }
        if (p.status !== 200) { step('준비 실패'); log(errText(p.status, p.body)); return reply(fail(p, 'tx_prepare_failed')); }
        if (buildOnly) { step('증명을 만들어 두었다 — 보내지 않고 창을 닫는다.'); return reply({ ok: true, held: true, nonce: p.body.nonce, root: p.body.root, wallet: p.body.walletAddr }); }
        const relayUrl = `${evOrigin}${config.relayPath ?? '/api/mode3/relay'}`;
        step('RP 릴레이로 보내는 중…');
        let relay;
        try {
          const r = await fetch(relayUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ to: p.body.walletAddr, data: p.body.calldata, ...(p.body.demo === 'replay_old_proof' ? { demo: 'replay_old_proof' } : {}) }) });
          relay = await r.json().catch(() => ({ ok: false, reason: 'internal', detail: `HTTP ${r.status}` }));
        } catch (e) { step('릴레이 호출 실패'); return reply({ ok: false, reason: 'relay_unavailable', detail: e.message }); }
        if (!relay.ok) { step('릴레이 거절'); log(`${relay.reason ?? ''} ${relay.detail ?? ''}`); return reply({ ok: false, reason: relay.reason ?? 'internal', detail: relay.detail ?? null }); }
        step('영수증 대기…');
        let rec = { status: 202, body: { pending: true, txHash: relay.txHash } };
        for (let i = 0; i < 30 && rec.status === 202; i++) { rec = await core.recordTx({ r_s: req.r_s, txHash: relay.txHash }); if (rec.status === 202) await new Promise((res) => setTimeout(res, 700)); }
        if (rec.status !== 200) { step('영수증 기록 실패'); log(errText(rec.status, rec.body)); return reply({ ok: false, reason: rec.body?.reason ?? (rec.status === 202 ? 'tx_pending' : 'tx_record_failed'), detail: rec.body, txHash: relay.txHash }); }
        const { disclosure, onchainDisclosure, ...pub } = rec.body;
        // 블록에 실렸지만 되돌려진 거래(status 0, 2026-11-23)는 실패다 — 그전에는 Executed 가 없어 ok 가 null 이라 성공으로 넘어갔다(가스 추정이 막아 보통은 오지 않았다).
        if (rec.body.status === 0) {
          step('거래가 블록에서 되돌려졌다 — 창을 닫는다.');
          return reply({ ok: false, reason: 'tx_reverted', detail: relay.expectRevert ?? null, txHash: relay.txHash, wallet: pub.wallet ?? null, blockNumber: rec.body.blockNumber ?? null, ...(p.body.race ? { race: p.body.race } : {}) });
        }
        await postPresence(core);
        step('전송 완료 — 창을 닫는다.');
        // RP 에는 영수증 사실만(지갑·nonce·gas·ok·txHash). 선택 공개는 이 요청에 없다(사용자 페이지 쪽).
        return reply({ ok: rec.body.ok !== false, ...pub, txHash: relay.txHash, deployTxHash: relay.deployTxHash ?? null });
      }

      if (req.type === 'mode3-request') {
        if (config.popupConsent !== false) step('서명할 요청을 확인하고 승인하세요.');
        if (!(await waitDecision())) { step('거절'); return reply({ ok: false, reason: 'user_denied' }); }
        step('세션키로 서명 중…');
        const r = await withUnlock(() => core.request({ r_s: req.r_s, body: req.body, arid: req.arid ?? null, origin: evOrigin }));
        if (r.cancelled) { step('잠금 해제 취소'); return reply({ ok: false, reason: 'user_denied' }); }
        if (r.status !== 200) { step('서명 실패'); log(errText(r.status, r.body)); return reply(fail(r, 'request_failed')); }
        step('서명 완료 — 창을 닫는다.');
        return reply({ ok: true, ...r.body });
      }

      // mode3-authorize
      if (req.reauth === true) {
        // 재승인(R12): web 모드의 세션은 IndexedDB 에 그대로 있어 다시 채울 증인이 없다. 세션이 있고(precheck 이 arid 로 확인) 그 RP 오리진의
        // 것인지만 확인하고 끝낸다 — RP 는 needs_consent 를 web 모드에서 받지 않으므로 보통은 오지 않는 요청이다.
        const s = await meta.session(req.r_s);
        if (!s || (s.origin && s.origin !== evOrigin)) { step('세션 정보를 받지 못했다 — 재승인하지 않는다.'); return reply({ ok: false, reason: 'no_session' }); }
        step('재승인 완료 — 창을 닫는다.');
        return reply({ ok: true, reauth: true });
      }
      /** 로그인·증명(공통 끝부분). idToken·issueN 은 Google 래퍼 경로, authCode 는 passkey-web 의 zkIdP 발급 코드(인증 창에서 받았거나 등록이 함께 준 것). */
      const loginWith = async ({ idToken = null, issueN = null, authCode = null } = {}) => {
        step('로그인·증명 생성 중… (수 초 걸린다)');
        const body = {
          arid: req.arid, origin: req.origin, cert_s: req.cert_s, pk_trace: req.pk_trace, r_s: req.r_s, r_rp: req.r_rp,
          allowAgent: req.allowAgent === '1' || req.allowAgent === true ? '1' : '0',
          factoryAddress: req.factoryAddress ?? null, attrGateAddress: req.attrGateAddress ?? null,
          disclose: req.disclose ?? null, set: req.set ?? null,
        };
        // verifiedOrigin: Origin 헤더 대신 이 창이 확인한 postMessage 의 오리진(스펙 §3.3). 금고가 잠겨 있으면 잠금 해제 창 → 한 번 다시.
        const lg = await withUnlock(() => core.login(body, { verifiedOrigin: evOrigin, serviceName: cleanServiceName(req.serviceName) || null, policy: req.policy ?? null, idToken, n: issueN, authCode }));   // 이름·정책은 표기용, idToken 은 래퍼 경로(2026-10-16), authCode 는 passkey-web
        if (lg.cancelled) { step('잠금 해제 취소'); return reply({ ok: false, reason: 'user_denied' }); }
        if (lg.status !== 200) { step('로그인 실패'); log(errText(lg.status, lg.body)); return reply(fail(lg, 'login_failed')); }
        // 지갑 안 정보(userCredIssued·attrsChanged)는 RP 에 넘기지 않는다 — 코어 응답에는 원래 없다(에이전트 snap 모드와 같은 경계).
        const { userCredIssued, attrsChanged, ...toRp } = lg.body;
        await postPresence(core);
        step('로그인 성공 — 창을 닫는다.');
        return reply({ ok: true, ...toRp });
      };
      if (WRAP) return await authorizeWrapper(req, evOrigin, { reply });   // 래퍼 방식: Google 을 다녀와 finishWrapper 가 잇는다
      if (PK) return await authorizePasskey(req, evOrigin, back, { reply, loginWith });
      // Google 로 로그인(RP 로그인 흐름, 2026-10-16): zkIdP 의 OIDC 설정을 읽는다 — 꺼져 있으면 Google 경로는 없다.
      const google = req.provider === 'google';
      let oidcCfg = null;
      if (google) {
        try { const k = await Promise.race([core.idp.publicKeys(), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000))]); if (k?.status === 200 && k.body?.oidc?.enabled) oidcCfg = k.body.oidc; } catch { /* 아래에서 꺼진 것으로 */ }
        if (!oidcCfg) { step('zkIdP 에 Google(OIDC) 설정이 없다.'); return reply({ ok: false, reason: 'oidc_disabled' }); }
      }
      const st = await core.status();
      if (st.status === 200 && !st.body?.registered && !google) {
        // 미등록(스펙 §3.2): Google 로 들어온 요청이면 Google 등록 안내 + 사용자 페이지 링크(이 창에서는 등록하지 않는다). 회신은 지금과 같은
        // not_registered(RP 쪽 표기는 불변). 안내를 읽을 수 있게 창은 15초 뒤에 닫는다(실패 기본 3초).
        const google = req.provider === 'google' && oidc?.enabled;
        const hint = $('authHint');
        hint.textContent = tt(google ? 'user_register_hint_google' : 'user_register_hint') || '먼저 사용자 페이지에서 등록하세요.';
        const a = document.createElement('a'); a.href = `${location.origin}/`; a.target = '_blank'; a.rel = 'noopener'; a.textContent = `${location.origin}/`;
        hint.append(' ', a); hint.hidden = false;
        step('등록 없음');
        return reply({ ok: false, reason: 'not_registered' }, { closeMs: 15_000 });
      }
      // 신원 줄(스펙 §3.2) — provider 가 없는 옛 등록은 데모 계정이다. 상태를 못 읽었으면 줄 없이 진행한다(로그인이 제 사유로 끝난다).
      if (st.status === 200 && st.body?.registered) renderAuthIdentity(st.body.provider ?? 'demo');
      else if (google) renderAuthIdentity(oidcCfg.provider);
      if (config.popupConsent !== false) step('요청을 확인하고 승인하세요.');
      if (!(await waitDecision())) { step('동의 거절'); return reply({ ok: false, reason: 'user_denied' }); }
      // Google 본인 확인(래퍼): 미등록이거나 Google 계정으로 등록된 브라우저면 이 로그인에 묶인 nonce 로 GIS 버튼을 그리고 토큰을 받는다.
      // 데모 계정으로 등록된 브라우저에서는 토큰이 그 계정과 맞지 않으므로 Google 단계 없이 데모 경로로 간다.
      let idToken = null, issueN = null;
      if (google && (!st.body?.registered || (st.body?.provider && st.body.provider !== 'demo'))) {
        // nonce 는 이 로그인의 tag 에 묶인다(2026-11-13) — allowAgent 는 아래 core.login 에 넘기는 값과 같은 식이어야 한다(다르면 oidc_nonce_mismatch).
        const prep = await core.loginPrepare({ arid: req.arid, r_rp: req.r_rp, allowAgent: req.allowAgent === '1' || req.allowAgent === true ? '1' : '0' });
        if (prep.status !== 200) { step('Google 로그인 준비 실패'); log(errText(prep.status, prep.body)); return reply(fail(prep, 'login_failed')); }
        step('Google 로 본인 확인 — 아래 Google 버튼을 누르세요.');
        const got = await googleToken(oidcCfg, prep.body.nonce);
        if (!got.ok) { step('Google 본인 확인 실패'); return reply({ ok: false, reason: got.reason, detail: got.detail ?? null }); }
        idToken = got.idToken; issueN = prep.body.n;
        step('로그인·증명 생성 중… (수 초 걸린다)');
      }
      return await loginWith({ idToken, issueN });
    } catch (e) {
      step('오류');
      log(e.message);
      reply({ ok: false, reason: e?.reason ?? 'internal', detail: e.message });
    }
  }
  // passkey-web: 요청 하나 전체를 withSalt 로 감싼다 — 그 안에서 salt 는 처음 한 번만 얻는다(패스키 최대 한 번, R-8). 그 밖의 모드는 지금 그대로.
  // 로그인은 패스키를 새로 묻는다(스펙 2026-11-19 L4) — 비밀번호 창이 빠진 자리의 사람 손이다. 2026-11-20 부터 salt 를 저장하지 않으므로(10분 보관 제거) 어느 요청이든
  // 이 창에서 salt 가 처음 필요할 때 패스키를 묻는다 — fresh 는 코어가 호환으로 받는 표시일 뿐이다(서비스 로그인은 zkIdP 정책이 key 일 때, zkIdP 로그인은 언제나 — 리뷰 M4).
  const isServiceLogin = (req) => req?.type === 'mode3-authorize' && req.reauth !== true;
  const run = async (req, evOrigin, back = null) => {
    if (!PK) return handle(req, evOrigin, back);
    const fresh = req?.type === 'mode3-idp-login' || (isServiceLogin(req) && (await issueAuthPolicy()) === 'key');
    return core.withSalt(() => handle(req, evOrigin, back), { fresh });
  };
  // zkIdP 에서 돌아온 길(passkey-web) — ready 를 다시 보내지 않고 저장해 둔 요청을 이어 처리한다. 결과는 가기 전의 발신 오리진(back.origin)으로.
  if (back) { run(back.req, back.origin, back); return; }
  let handled = false;
  const onMessage = (ev) => {
    const req = ev.data;
    // 우리를 연 창이 보낸 것만 본다 — 같은 이름으로 창 참조를 얻은 다른 페이지가 끼어들지 못하게(심층 방어).
    if (handled || ev.source !== window.opener || !req || !TYPES.includes(req.type)) return;
    handled = true;
    window.removeEventListener('message', onMessage);
    return run(req, ev.origin);
  };
  window.addEventListener('message', onMessage);
  renderAuthTitle();
  // 준비 신호는 오리진을 모르는 상태에서 보낸다('*'). 비밀은 실리지 않는다 — 요청을 받고 나서야 오리진을 대조한다.
  window.opener.postMessage({ type: 'mode3-authorize-ready' }, '*');
  step('RP 페이지의 요청을 기다리는 중…');
}
