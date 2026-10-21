// mode3/user/popup.js — 사용자 페이지의 승인 팝업(?authorize=1, 스펙 2026-10-15 §4.2). mode3/wallet.html 의 runAuthorize 를 옮기고
// 메시지 종류(req.type)로 가른다: mode3-config·mode3-precheck·mode3-authorize·mode3-revalidate·mode3-request.
// 요청은 주소창이 아니라 postMessage 로 받고, 결과는 말을 건 오리진에만 돌려준다. 결과에는 비밀이 없다 — 코어의 성공 본문은
// 증명·공개 입력·세션 서명·pk_i 뿐이고(에이전트 /wallet/login 과 같은 모양), userCredIssued·attrsChanged 같은 이름은 혹시 몰라 뺀다.
import { $, textKit, createUnlocker, postPresence, errText } from './ui.js';

const TYPES = ['mode3-config', 'mode3-precheck', 'mode3-authorize', 'mode3-revalidate', 'mode3-request', 'mode3-tx'];
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

/** oidc: IdP 의 public_keys.oidc(user.js 가 읽어 넘긴다) — 미등록 안내를 Google 용으로 고를지에만 쓴다. */
export function runPopup({ core, config, Demo, meta, oidc = { enabled: false } }) {
  const { tte, tt } = textKit(Demo);
  const { withUnlock } = createUnlocker({ core, Demo });
  let lastReq = null;        // 받은 요청(언어 전환 때 제목·요약을 다시 그린다)
  let lastIdentity = null;   // 신원 줄의 provider(언어 전환 때 요약과 함께 다시 그린다)
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
    if (!window.opener) { tte($('authTitle'), 'wallet_auth_no_opener'); return; }
    if (!lastReq || lastReq.type === 'mode3-config' || lastReq.type === 'mode3-precheck') { tte($('authTitle'), 'wallet_auth_waiting'); return; }
    const service = cleanServiceName(lastReq.serviceName) || lastReq.origin;
    const key = lastReq.type === 'mode3-request' ? null : lastReq.type === 'mode3-tx' ? 'user_auth_tx_title' : lastReq.type === 'mode3-revalidate' ? 'user_auth_revalidate_title' : 'wallet_auth_approving';
    $('authTitle').textContent = key ? (tt(key, { service }) || service) : [service, tt('user_auth_request_title')].filter(Boolean).join(' — ');
  }
  // 언어·전문가 전환 — 제목·요약은 스크립트가 만든 텍스트라 여기서 다시 그린다.
  for (const k of ['setLang', 'setExpert']) {
    const orig = Demo[k];
    Demo[k] = (v) => { orig(v); renderAuthTitle(); if (lastReq && lastReq.origin && lastReq.type !== 'mode3-config') { renderAuthSummary(lastReq); if (lastIdentity) renderAuthIdentity(lastIdentity); } };
  }
  /** 승인·거절 버튼(요약 뒤에 보인다). 창을 닫으면 RP 쪽이 popup_closed 로 끝낸다. */
  function waitDecision() {
    return new Promise((resolve) => {
      const a = $('authApproveBtn'), d = $('authDenyBtn');
      const done = (v) => { a.hidden = true; d.hidden = true; a.removeEventListener('click', onA); d.removeEventListener('click', onD); resolve(v); };
      const onA = () => done(true), onD = () => done(false);
      a.addEventListener('click', onA); d.addEventListener('click', onD);
      a.hidden = false; d.hidden = false;
    });
  }
  const fail = (r, fallback) => ({ ok: false, reason: r.body?.reason ?? fallback, detail: r.body?.detail ?? r.body?.error ?? null, status: r.status, ...(r.body?.demo ? { demo: r.body.demo } : {}) });

  if (!window.opener) { renderAuthTitle(); step('이 창은 RP 페이지가 열어야 한다(window.opener 가 없다).'); return; }
  let handled = false;
  const onMessage = async (ev) => {
    const req = ev.data;
    // 우리를 연 창이 보낸 것만 본다 — 같은 이름으로 창 참조를 얻은 다른 페이지가 끼어들지 못하게(심층 방어).
    if (handled || ev.source !== window.opener || !req || !TYPES.includes(req.type)) return;
    handled = true;
    window.removeEventListener('message', onMessage);
    // 결과는 요청을 보낸 창에만 돌려준다. 오리진이 어긋나면 진행하지 않고 실제로 말을 건 오리진에 실패만 알린다.
    const target = ev.origin === req.origin ? req.origin : ev.origin;
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
        if (!(config.rpOrigins ?? []).includes(ev.origin)) { step('모르는 RP — 설정을 알려 주지 않는다.'); log(`메시지 오리진=${ev.origin}`); return reply({ ok: false, reason: 'origin_mismatch' }); }
        const h = await core.health();
        step('설정을 알렸다 — 창을 닫는다.');
        return reply({ ok: true, secrets: 'web', registered: h.registered, rpCount: h.rpCount, sessions: h.sessions });
      }
      if (ev.origin !== req.origin) {
        step('오리진 불일치 — 이 요청은 진행하지 않는다.');
        log(`메시지 오리진=${ev.origin}\n인증서 오리진=${req.origin}`);
        return reply({ ok: false, reason: 'origin_mismatch' });
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
        const r = await withUnlock(() => core.revalidate({ r_s: req.r_s, skipSync: req.skipSync === true, arid: req.arid ?? null, origin: ev.origin }));
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
        // execute calldata 를 만들고, 그 RP 의 릴레이(ev.origin — 세션의 오리진과 같아야 한다)가 보낸다. 사용자 페이지의 "트랜잭션 보내기"와 같은 경로.
        const s = await meta.session(req.r_s);
        if (!s || (s.origin && s.origin !== ev.origin)) { step('이 RP 의 세션이 아니다.'); return reply({ ok: false, reason: 'no_session' }); }
        const value = String(req.value ?? '0');
        if (typeof req.to !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(req.to) || !/^[0-9]+$/.test(value) || (req.data !== undefined && !/^0x([0-9a-fA-F]{2})*$/.test(String(req.data)))) { step('요청 형식 오류'); return reply({ ok: false, reason: 'malformed' }); }
        row('wallet_auth_tx_to', req.to); row('wallet_auth_tx_value', `${value} wei`);
        step('보낼 트랜잭션을 확인하고 승인하세요.');
        if (!(await waitDecision())) { step('거절'); return reply({ ok: false, reason: 'user_denied' }); }
        step('증명·세션키 서명 중… (수 초 걸린다)');
        const p = await withUnlock(() => core.prepareTx({ r_s: req.r_s, to: req.to, value, data: req.data ?? '0x' }));
        if (p.cancelled) { step('잠금 해제 취소'); return reply({ ok: false, reason: 'user_denied' }); }
        if (p.status !== 200) { step('준비 실패'); log(errText(p.status, p.body)); return reply(fail(p, 'tx_prepare_failed')); }
        const relayUrl = `${ev.origin}${config.relayPath ?? '/api/mode3/relay'}`;
        step('RP 릴레이로 보내는 중…');
        let relay;
        try {
          const r = await fetch(relayUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ to: p.body.walletAddr, data: p.body.calldata }) });
          relay = await r.json().catch(() => ({ ok: false, reason: 'internal', detail: `HTTP ${r.status}` }));
        } catch (e) { step('릴레이 호출 실패'); return reply({ ok: false, reason: 'relay_unavailable', detail: e.message }); }
        if (!relay.ok) { step('릴레이 거절'); log(`${relay.reason ?? ''} ${relay.detail ?? ''}`); return reply({ ok: false, reason: relay.reason ?? 'internal', detail: relay.detail ?? null }); }
        step('영수증 대기…');
        let rec = { status: 202, body: { pending: true, txHash: relay.txHash } };
        for (let i = 0; i < 30 && rec.status === 202; i++) { rec = await core.recordTx({ r_s: req.r_s, txHash: relay.txHash }); if (rec.status === 202) await new Promise((res) => setTimeout(res, 700)); }
        if (rec.status !== 200) { step('영수증 기록 실패'); log(errText(rec.status, rec.body)); return reply({ ok: false, reason: rec.body?.reason ?? (rec.status === 202 ? 'tx_pending' : 'tx_record_failed'), detail: rec.body, txHash: relay.txHash }); }
        await postPresence(core);
        step('전송 완료 — 창을 닫는다.');
        // RP 에는 영수증 사실만(지갑·nonce·gas·ok·txHash). 선택 공개는 이 요청에 없다(사용자 페이지 쪽).
        const { disclosure, onchainDisclosure, ...pub } = rec.body;
        return reply({ ok: rec.body.ok !== false, ...pub, txHash: relay.txHash, deployTxHash: relay.deployTxHash ?? null });
      }

      if (req.type === 'mode3-request') {
        step('서명할 요청을 확인하고 승인하세요.');
        if (!(await waitDecision())) { step('거절'); return reply({ ok: false, reason: 'user_denied' }); }
        step('세션키로 서명 중…');
        const r = await withUnlock(() => core.request({ r_s: req.r_s, body: req.body, arid: req.arid ?? null, origin: ev.origin }));
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
        if (!s || (s.origin && s.origin !== ev.origin)) { step('세션 정보를 받지 못했다 — 재승인하지 않는다.'); return reply({ ok: false, reason: 'no_session' }); }
        step('재승인 완료 — 창을 닫는다.');
        return reply({ ok: true, reauth: true });
      }
      // Google 로 로그인(RP 로그인 흐름, 2026-10-16): IdP 의 OIDC 설정을 읽는다 — 꺼져 있으면 Google 경로는 없다.
      const google = req.provider === 'google';
      let oidcCfg = null;
      if (google) {
        try { const k = await Promise.race([core.idp.publicKeys(), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000))]); if (k?.status === 200 && k.body?.oidc?.enabled) oidcCfg = k.body.oidc; } catch { /* 아래에서 꺼진 것으로 */ }
        if (!oidcCfg) { step('IdP 에 Google(OIDC) 설정이 없다.'); return reply({ ok: false, reason: 'oidc_disabled' }); }
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
      step('요청을 확인하고 승인하세요.');
      if (!(await waitDecision())) { step('동의 거절'); return reply({ ok: false, reason: 'user_denied' }); }
      // Google 본인 확인(래퍼): 미등록이거나 Google 계정으로 등록된 브라우저면 이 로그인에 묶인 nonce 로 GIS 버튼을 그리고 토큰을 받는다.
      // 데모 계정으로 등록된 브라우저에서는 토큰이 그 계정과 맞지 않으므로 Google 단계 없이 데모 경로로 간다.
      let idToken = null;
      if (google && (!st.body?.registered || (st.body?.provider && st.body.provider !== 'demo'))) {
        const prep = await core.loginPrepare({ arid: req.arid, r_rp: req.r_rp });
        if (prep.status !== 200) { step('Google 로그인 준비 실패'); log(errText(prep.status, prep.body)); return reply(fail(prep, 'login_failed')); }
        step('Google 로 본인 확인 — 아래 Google 버튼을 누르세요.');
        const got = await googleToken(oidcCfg, prep.body.nonce);
        if (!got.ok) { step('Google 본인 확인 실패'); return reply({ ok: false, reason: got.reason, detail: got.detail ?? null }); }
        idToken = got.idToken;
        step('로그인·증명 생성 중… (수 초 걸린다)');
      }
      step('로그인·증명 생성 중… (수 초 걸린다)');
      const body = {
        arid: req.arid, origin: req.origin, cert_s: req.cert_s, pk_trace: req.pk_trace, r_s: req.r_s, r_rp: req.r_rp,
        allowAgent: req.allowAgent === '1' || req.allowAgent === true ? '1' : '0',
        factoryAddress: req.factoryAddress ?? null, attrGateAddress: req.attrGateAddress ?? null,
        disclose: req.disclose ?? null, set: req.set ?? null,
      };
      // verifiedOrigin: Origin 헤더 대신 이 창이 확인한 postMessage 의 오리진(스펙 §3.3). 금고가 잠겨 있으면 잠금 해제 창 → 한 번 다시.
      const lg = await withUnlock(() => core.login(body, { verifiedOrigin: ev.origin, serviceName: cleanServiceName(req.serviceName) || null, policy: req.policy ?? null, idToken }));   // 이름·정책은 표기용, idToken 은 래퍼 경로(2026-10-16)
      if (lg.cancelled) { step('잠금 해제 취소'); return reply({ ok: false, reason: 'user_denied' }); }
      if (lg.status !== 200) { step('로그인 실패'); log(errText(lg.status, lg.body)); return reply(fail(lg, 'login_failed')); }
      // 지갑 안 정보(userCredIssued·attrsChanged)는 RP 에 넘기지 않는다 — 코어 응답에는 원래 없다(에이전트 snap 모드와 같은 경계).
      const { userCredIssued, attrsChanged, ...toRp } = lg.body;
      await postPresence(core);
      step('로그인 성공 — 창을 닫는다.');
      return reply({ ok: true, ...toRp });
    } catch (e) {
      step('오류');
      log(e.message);
      reply({ ok: false, reason: e?.reason ?? 'internal', detail: e.message });
    }
  };
  window.addEventListener('message', onMessage);
  renderAuthTitle();
  // 준비 신호는 오리진을 모르는 상태에서 보낸다('*'). 비밀은 실리지 않는다 — 요청을 받고 나서야 오리진을 대조한다.
  window.opener.postMessage({ type: 'mode3-authorize-ready' }, '*');
  step('RP 페이지의 요청을 기다리는 중…');
}
