// mode3/user/ui.js — 브라우저 전용 사용자 페이지의 화면(스펙 2026-10-15 §4.2). mode3/wallet.html(에이전트 페이지)의 화면 로직을 옮겼다.
// 치환 규칙(계획 Task 9): 에이전트 HTTP 호출 → user_core 의 같은 이름 함수(같은 { status, body }), 트랜잭션은 RP 의 릴레이로(sendTxViaRelay),
// MetaMask·Snap 코드는 없다. 비밀(s_u·sk_u·blind_u·세션 개인키·금고 비밀번호·secrets 암호문)은 DOM·localStorage·로그·postMessage 에
// 넣지 않는다 — 코어 응답은 에이전트와 같은 모양이라 비밀이 실리지 않고, safeDetail 이 한 번 더 거른다. 비밀번호 입력칸은 읽자마자 비운다.
import { ZK_CACHE_NAME } from '../../lib/browser/zk_assets.js';
export const $ = (id) => document.getElementById(id);

/** 사전 도우미(wallet.html 의 tte·tt·setVerdict·pendingVerdict 와 같다). */
export function textKit(Demo) {
  /** 사전 텍스트를 요소에 쓴다. 사전에 없는 키(= /common 미로딩)면 아무것도 쓰지 않아 HTML 의 기본 텍스트가 남는다. */
  const tte = (el, k, vars) => { const s = Demo.t(k, vars); if (s !== k) el.textContent = s; };
  /** 스크립트가 값과 엮어 만드는 문구 — 사전이 없으면 키를 화면에 흘리지 않고 빈 문자열로 둔다. */
  const tt = (k, vars) => { const s = Demo.t(k, vars); return s === k ? '' : s; };
  /** 결과 카드. title 은 판정 키(사전 verdicts) 또는 ui 키. extra 는 객체이거나 그것을 돌려주는 함수(언어·전문가 전환 때 다시 그린다). */
  function setVerdict(el, ok, title, extra = {}) {
    Demo.verdict(el, () => ({ ok, title: window.DemoStrings?.verdicts?.[title] ? title : Demo.t(title), ...(typeof extra === 'function' ? extra() : extra) }));
  }
  const pendingVerdict = (el, key) => setVerdict(el, null, key, { pending: true });
  return { tte, tt, setVerdict, pendingVerdict };
}

/** '자세히'에 실을 응답 본문. 코어 응답에는 비밀이 없지만(에이전트 snap 모드와 같은 경계) 지갑 밖으로 내면 안 되는 이름은 한 번 더 거른다. */
export const safeDetail = (b) => { const { sk_u, s_u, blind_u, pwd, witness, userCredIssued, attrsChanged, sessionPrivKey, vaultPassword, ...rest } = b ?? {}; return rest; };
export const errText = (status, b) => `${status}: ${b.reason ?? b.error ?? ''}${b.detail ? ` (${b.detail})` : ''}${b.cia ? ` ${JSON.stringify(b.cia)}` : ''}`;

/** 존재 신호(계획 R4) — 정적 서버(같은 오리진)에 core.health() 의 6개 값만 알린다. 실패는 조용히 넘긴다(상태 패널이 늦을 뿐). */
export async function postPresence(core) {
  try { await fetch('/wallet/presence', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(await core.health()) }); }
  catch { /* 정적 서버가 없다 */ }
}

/** kv 의 공개 레코드만 읽는 창구 — 세션의 RP 오리진·arid, 잠금 해제 만료 시각. 비밀(secrets, unlock 의 CryptoKey)은 돌려주지 않는다.
 *  user_core.status() 의 세션 요약에는 origin 이 없다 — 릴레이 주소(그 세션의 RP)와 승인 창의 재승인 대조에 쓴다. */
export function publicMeta(kv) {
  return {
    async session(r_s) {
      try { const s = (await kv.get('sessions'))?.[BigInt(r_s).toString()]; return s ? { origin: s.origin ?? null, arid: String(s.arid) } : null; }
      catch { return null; }
    },
    async unlockedUntil() {
      try { const u = await kv.get('unlock'); return Number.isFinite(u?.expiresAt) ? u.expiresAt : null; }
      catch { return null; }
    },
  };
}

/**
 * 잠금 해제 창(#unlockModal). withUnlock(fn): fn 의 결과가 423(locked)이면 창을 띄우고, 금고가 열리면 fn 을 한 번만 다시 부른다.
 * 취소하면 423 결과에 cancelled:true 를 붙여 돌려준다 — 화면은 그 동작의 결과 카드에 locked 로, 승인 창은 user_denied 로 보인다.
 * 비밀번호는 읽자마자 입력칸에서 지운다. 해제 상태는 IndexedDB 로 공유된다(계획 R3) — 다른 탭은 다음 status() 에서 본다.
 */
export function createUnlocker({ core, Demo }) {
  const { setVerdict } = textKit(Demo);
  let pending = null;
  function ask() {
    if (pending) return pending;
    pending = new Promise((resolve) => {
      const modal = $('unlockModal'), pw = $('unlockPw'), go = $('unlockGo'), cancel = $('unlockCancel'), verdict = $('unlockVerdict');
      verdict.textContent = ''; verdict.className = '';
      pw.value = ''; modal.hidden = false; pw.focus();
      const done = (ok) => {
        modal.hidden = true; pw.value = '';
        go.removeEventListener('click', onGo); cancel.removeEventListener('click', onCancel); pw.removeEventListener('keydown', onKey);
        pending = null; resolve(ok);
      };
      async function onGo() {
        const v = pw.value; pw.value = '';
        if (!v || go.disabled) return;
        go.disabled = true;
        try {
          if (await core.vault.unlock(v)) { done(true); return; }
          setVerdict(verdict, false, 'user_unlock_failed', { reason: 'bad_password' });
        } catch (e) { setVerdict(verdict, false, 'user_unlock_failed', { reason: 'storage_unavailable', detail: e.message }); }
        finally { go.disabled = false; }
      }
      const onCancel = () => done(false);
      const onKey = (ev) => { if (ev.key === 'Enter') onGo(); else if (ev.key === 'Escape') onCancel(); };
      go.addEventListener('click', onGo); cancel.addEventListener('click', onCancel); pw.addEventListener('keydown', onKey);
    });
    return pending;
  }
  async function withUnlock(fn) {
    const r = await fn();
    if (r?.status !== 423) return r;
    if (!(await ask())) return { ...r, cancelled: true };
    return fn();
  }
  return { withUnlock, ask };
}

/** 입력칸 하나짜리 비밀번호 창(자기 폐기). 값을 돌려주고 입력칸은 비운다. 취소면 null. */
function askSecret({ modalId, inputId, goId, cancelId }) {
  return new Promise((resolve) => {
    const modal = $(modalId), pw = $(inputId), go = $(goId), cancel = $(cancelId);
    pw.value = ''; modal.hidden = false; pw.focus();
    const done = (v) => {
      modal.hidden = true; pw.value = '';
      go.removeEventListener('click', onGo); cancel.removeEventListener('click', onCancel); pw.removeEventListener('keydown', onKey);
      resolve(v);
    };
    const onGo = () => { const v = pw.value; if (v) done(v); };
    const onCancel = () => done(null);
    const onKey = (ev) => { if (ev.key === 'Enter') onGo(); else if (ev.key === 'Escape') onCancel(); };
    go.addEventListener('click', onGo); cancel.addEventListener('click', onCancel); pw.addEventListener('keydown', onKey);
  });
}

export function mountUi({ core, prover, config, Demo, meta }) {
  const { tte, tt, setVerdict, pendingVerdict } = textKit(Demo);
  const { withUnlock, ask: askUnlock } = createUnlocker({ core, Demo });
  // /wallet/config 대신 /user/config(같은 오리진). minAge·allowedCountries 는 없다 — claim 버튼이 기본값으로 대신한다(에이전트와 같다).
  const cfg = { ...config, secrets: 'web' };
  let lastAttrs = null;      // core.status() 가 준 값 — "정확히 공개" 버튼이 쓴다
  let lastSessions = {};     // core.status() 의 sessions — 선택된 세션의 attrGateAddress 로 claim 버튼이 폼을 채운다(스펙 §6.1)
  let lastStatus = null;     // 마지막 core.status() 본문(언어·전문가 전환 때 다시 그린다)
  let lastProof = null;      // 마지막 트랜잭션 증명 시간·캐시 히트(전문가 줄)
  let statusError = null;    // 상태를 못 읽었을 때의 원문
  const progress = { txOk: false, disclosed: false, revoked: false };   // 이 페이지가 아는 완료 신호(세션 중 메모리)
  let attrSchema = null;     // core.attrSchema() — 이름 ↔ 코드, 슬롯 타입(스펙 2)
  // U2: #discCountry 의 기본값은 내 국가다. 한 번이라도 사용자가 손대면 5초 주기 refresh() 가 다시 되돌리지 않는다.
  let countryTouched = false;
  // 등록 전·"속성 저장" 전에 입력 중인 attrN 값을 5초 주기 refresh() 가 지우지 않게 막는 플래그(wallet.html 과 같다).
  let profileDirty = false;
  let zk = { kind: 'idle' };  // 증명 키 내려받기 상태(#zkProgress): idle | loading{name,pct} | ready | fail{detail}

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  /** 2026-10-15 W5: 예비 1·예비 2(extra1·extra2) 슬롯은 화면에서 미사용 슬롯처럼 숨긴다(wallet.html 과 같다). */
  const isSpareSlot = (slot) => slot?.name === 'extra1' || slot?.name === 'extra2';
  /** 신원 카드의 속성 입력을 스키마 타입대로 그린다 — int 는 숫자, enum 은 선택 목록(이름), string 은 글자 입력. */
  function renderAttrsForm() {
    attrSchema.slots.forEach((slot, k) => {
      if (slot.type === 'unused' || isSpareSlot(slot)) return;
      const dd = $('attr' + k).closest('dd');
      let input;
      if (slot.type === 'enum') {
        input = document.createElement('select');
        const none = document.createElement('option'); none.value = ''; none.textContent = '—'; input.appendChild(none);
        for (const name of Object.keys(slot.values)) { const o = document.createElement('option'); o.value = name; o.textContent = name; input.appendChild(o); }
      } else {
        input = document.createElement('input');
        input.size = slot.type === 'int' ? 6 : 10;
      }
      input.id = 'attr' + k;
      input.addEventListener(slot.type === 'enum' ? 'change' : 'input', () => { profileDirty = true; });
      dd.replaceChildren(input);
    });
  }
  /** 신원 카드의 { slot.name: 입력값 } — unused 아닌 슬롯만. 등록·속성 저장의 profile 이 된다. */
  function readProfileForm() {
    const out = {};
    (attrSchema?.slots ?? []).forEach((slot, k) => { if (slot.type !== 'unused') out[slot.name] = $('attr' + k).value.trim(); });
    return out;
  }
  /** 국가 선택(#discCountry)의 옵션을 스키마의 이름→코드로 채운다(U2). */
  function populateCountrySelect() {
    const sel = $('discCountry');
    sel.textContent = '';
    const none = document.createElement('option'); none.value = '';
    tte(none, 'wallet_disc_country_none'); if (!none.textContent) none.textContent = '공개 안 함';
    sel.appendChild(none);
    const slot1 = attrSchema?.slots?.[1];
    if (slot1?.type === 'enum') {
      for (const [name, code] of Object.entries(slot1.values)) { const o = document.createElement('option'); o.value = String(code); o.textContent = name; sel.appendChild(o); }
    }
  }
  /** IdP 의 속성 스키마(코어가 받아 둔다). unused 행과 예비 슬롯(W5)은 숨긴다. */
  async function loadAttrSchema() {
    try { const r = await core.attrSchema(); attrSchema = r.status === 200 ? r.body.schema : null; } catch { attrSchema = null; }
    if (!attrSchema) return;
    attrSchema.slots.forEach((slot, k) => {
      if (slot.type !== 'unused' && !isSpareSlot(slot)) return;
      const row = $('dk' + k).closest('div');
      row.hidden = true; $('attr' + k).closest('dd').previousElementSibling.hidden = true; $('attr' + k).closest('dd').hidden = true; $('setSlot').querySelector(`option[value="${k}"]`).hidden = true;
    });
    populateCountrySelect();
    renderAttrsForm();
  }
  /** 집합 원소를 이름으로 적었으면 코드로(enum 슬롯). 그 밖은 그대로 — 코어가 형식을 검사한다. */
  function encodeMember(slot, token) {
    const s = attrSchema?.slots?.[slot];
    if (s?.type === 'enum' && Object.prototype.hasOwnProperty.call(s.values, token)) return String(s.values[token]);
    return token;
  }
  const profileText = (profile) => Object.entries(profile ?? {}).filter(([k, v]) => v !== '' && !isSpareSlot({ name: k })).map(([k, v]) => `${k}=${v}`).join(', ');

  // ---- 안내 바·작은 그리기 도우미 ----
  function renderGuide() {
    const s = lastStatus;
    const sessions = s ? Object.keys(s.sessions ?? {}).length : 0;
    const links = { admin: s?.ciaUrl ? `${s.ciaUrl}/admin` : null, account: s?.ciaUrl ? `${s.ciaUrl}/account` : null };
    if (Demo.tour?.enabled) { Demo.tour.evaluate({ progress: { registered: !!s?.registered, login: sessions > 0, used: progress.txOk, disclosed: progress.disclosed, revoked: progress.revoked }, links }); return; }
    const done = [];
    if (s?.registered) done.push('register');
    if (sessions) done.push('login');
    if (progress.txOk) done.push('use');
    if (progress.disclosed) done.push('disclose');
    if (progress.revoked) done.push('revoke');
    const current = !s?.registered ? 'register' : !sessions ? 'login' : !progress.txOk ? 'use' : 'disclose';
    Demo.guide({ done, current, links });
  }
  /** 짧게 줄인 값 + 전체 값은 title 로(둘 다 공개 값이다 — 비밀은 status 에 실리지 않는다). */
  function shortCode(full, n = 12) {
    const c = document.createElement('code');
    const s = String(full ?? '');
    c.textContent = s.length > n ? `${s.slice(0, n)}…` : s;
    c.title = s;
    return c;
  }
  function kvRow(dl, label, value, expert = false) {
    const dt = document.createElement('dt');
    const dd = document.createElement('dd');
    if (label instanceof Node) dt.appendChild(label); else dt.textContent = label;
    if (value instanceof Node) dd.appendChild(value); else dd.textContent = value;
    if (expert) { dt.className = 'expert'; dd.className = 'expert'; }
    dl.append(dt, dd);
  }
  const termEl = (name) => { const s = document.createElement('span'); s.dataset.term = name; s.textContent = Demo.term(name); return s; };

  // ---- 신원 카드 ----
  /** 국가 선택 기본값(내 국가) + 슬롯 2·3 체크박스의 "값 없음" 비활성화(U2). */
  function updateDiscloseForAttrs() {
    if (!countryTouched) {
      const sel = $('discCountry');
      const mine = lastAttrs ? String(lastAttrs[1]) : '';
      sel.value = mine !== '' && mine !== '0' && sel.querySelector(`option[value="${mine}"]`) ? mine : '';
    }
    for (const k of [2, 3]) {
      if (attrSchema?.slots?.[k]?.type === 'unused') continue;
      const noValue = !lastAttrs || String(lastAttrs[k]) === '0';
      $('dk' + k).disabled = noValue;
      if (noValue) $('dk' + k).checked = false;
      const note = $('discNoValue' + k);
      if (note) note.hidden = !noValue;
    }
  }
  function renderIdentity() {
    const s = lastStatus;
    lastAttrs = s?.attrs ?? null;
    updateDiscloseForAttrs();
    if (!profileDirty) {
      if (attrSchema) attrSchema.slots.forEach((slot, k) => { if (slot.type !== 'unused') $('attr' + k).value = s?.profile?.[slot.name] ?? ''; });
      else for (let k = 0; k < 6; k++) $('attr' + k).value = s?.attrsView?.[k]?.display ?? (lastAttrs ? lastAttrs[k] : '');
    }
    const badge = $('regBadge');
    badge.className = `badge ${s?.registered ? 'ok' : 'muted'}`;
    tte(badge, s?.registered ? 'wallet_reg_yes' : 'wallet_reg_no');
    const uc = s?.userCred ?? null;
    const credKey = !uc ? 'wallet_cred_none' : uc.revoked === true ? 'wallet_cred_revoked' : uc.revoked === false ? 'wallet_cred_yes' : 'wallet_cred_unknown';
    $('regInfo').textContent = s?.registered ? tt('wallet_uid', { uid: s.uid }) : '';
    $('credInfo').textContent = tt(credKey) || '-';
    $('aaInfo').textContent = s?.ciaUrl || tt('wallet_aa_none') || '-';
    // 등록 폼은 미등록일 때만 펼친다(설계 §4.1).
    $('fileRegFields').hidden = Boolean(s?.registered);
    // 등록부 확인 줄(V9 §8.2).
    const rg = s?.registry ?? null;
    const rb = $('registryBadge');
    const key = !rg ? 'wallet_registry_unknown' : rg.match === true ? 'wallet_registry_ok' : rg.leaf === '0' ? 'wallet_registry_empty' : 'wallet_registry_mismatch';
    rb.className = `badge ${!rg ? 'muted' : rg.match === true ? 'ok' : rg.leaf === '0' ? 'warn' : 'bad'}`;
    tte(rb, key);
    const slotInfo = rg ? (tt('wallet_registry_info', { slot: rg.slot, epoch: rg.epoch }) || `슬롯 ${rg.slot} · epoch ${rg.epoch}`) : '';
    $('registryInfo').textContent = rg ? [tt(key), slotInfo].filter(Boolean).join(' · ') : '';
  }

  // ---- 로그인 세션 카드 + 트랜잭션 세션 선택 ----
  function renderSessions() {
    const s = lastStatus;
    const entries = s ? Object.entries(s.sessions ?? {}) : [];
    lastSessions = s?.sessions ?? {};
    if (s) $('status').textContent = JSON.stringify(s, null, 2);
    else if (statusError) $('status').textContent = tt('wallet_status_failed', { err: statusError }) || `상태 조회 실패: ${statusError}`;
    $('mirrorInfo').textContent = s ? tt('wallet_mirror_line', { mirror: s.mirror?.epoch ?? '-', canonical: s.canonical?.epoch ?? '-' }) : '';
    $('chainInfo').textContent = s ? tt('wallet_chain_info', { head: s.head ?? '-', log: s.logAddress ?? '-', root: s.lastRoot ?? '-', regRoot: s.lastRegRoot ?? '-' }) : '';

    const sel = $('txSession');
    const prev = sel.value;
    sel.textContent = '';
    let anyFactory = false;
    for (const [r_s, c] of entries) {
      const opt = document.createElement('option');
      opt.value = r_s;
      const factory = tt(c.factoryAddress ? 'wallet_factory_yes' : 'wallet_factory_no');
      const acct = c.account ? `${c.account.slice(0, 6)}…${c.account.slice(-4)}` : `PPID ${String(c.PPID).slice(0, 8)}…`;
      opt.textContent = tt('wallet_tx_session_opt', { account: acct, arid: String(c.arid).slice(0, 10), factory }) || `${acct} / ${String(c.arid).slice(0, 10)}…`;
      opt.title = c.account ? `${c.account}  (PPID ${c.PPID})` : `PPID ${c.PPID}`;
      if (c.factoryAddress) anyFactory = true;
      sel.appendChild(opt);
    }
    if (entries.some(([r_s]) => r_s === prev)) sel.value = prev;
    $('txBtn').disabled = !anyFactory;

    const acts = $('sessionActions');
    acts.textContent = '';
    if (!entries.length) {
      const p = document.createElement('p');
      p.className = 'muted';
      p.textContent = '로그인 세션이 없습니다. RP 에서 로그인하세요.';
      tte(p, 'wallet_no_sessions');
      acts.appendChild(p);
      return;
    }
    for (const [r_s, c] of entries) {
      const box = document.createElement('div');
      const dl = document.createElement('dl');
      dl.className = 'kv';
      kvRow(dl, tt('wallet_session_service') || 'RP', shortCode(c.arid, 8));
      kvRow(dl, termEl('PPID'), shortCode(c.PPID, 12));
      kvRow(dl, tt('wallet_session_expiry') || '만료', tt('wallet_session_expires', { h: c.max_height }) || String(c.max_height));
      const agent = document.createElement('span');
      agent.className = `badge ${c.allowAgent === '1' ? 'ok' : 'muted'}`;
      agent.textContent = tt(c.allowAgent === '1' ? 'rp_agent_yes' : 'rp_agent_no') || c.allowAgent;
      kvRow(dl, termEl('allowAgent'), agent);
      kvRow(dl, termEl('session'), shortCode(r_s, 16), true);
      kvRow(dl, tt('wallet_session_addr') || '세션 주소', shortCode(c.sessionAddress, 20), true);
      kvRow(dl, tt('wallet_session_factory') || '팩토리', shortCode(c.factoryAddress ?? '-', 20), true);
      kvRow(dl, tt('wallet_session_issued') || '발급 시각', String(c.issuedAt), true);
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'danger';
      btn.textContent = tt('wallet_end_session') || '이 세션 끝내기(폐기)';
      btn.addEventListener('click', () => revokeSession(r_s, c, btn));
      box.append(dl, btn);
      acts.appendChild(box);
    }
  }
  /** 마지막 트랜잭션의 증명 시간(전문가 줄). */
  function renderProofInfo() {
    $('txProofInfo').textContent = lastProof
      ? (tt('wallet_proof_info', { ms: lastProof.ms ?? '-', cache: String(lastProof.cache) }) || `${lastProof.ms} ms`)
      : (tt('wallet_proof_none') || '');
  }
  /** 모드 안내 문구(언어 전환 때 다시 부른다). */
  function renderModeTexts() {
    tte($('intro'), 'user_intro_web');
    tte($('txNote'), 'user_tx_note_web');
  }
  /** 보관 상태 카드 — 금고 없음/잠김/해제(만료 시각) 배지와 버튼 활성. 동기 getter 는 core.status()·vault.refresh() 뒤에만 읽는다. */
  async function renderVault() {
    const has = core.vault.hasVault(), open = core.vault.isUnlocked();
    const badge = $('vaultBadge');
    if (!has) { badge.className = 'badge muted'; tte(badge, 'user_vault_none'); }
    else if (!open) { badge.className = 'badge warn'; tte(badge, 'user_vault_locked'); }
    else {
      const until = await meta.unlockedUntil();
      const when = until ? new Date(until).toLocaleTimeString(Demo.lang === 'en' ? 'en-US' : 'ko-KR') : '-';
      badge.className = 'badge ok';
      badge.textContent = tt('user_vault_unlocked', { until: when }) || `해제됨 · ${when} 까지`;
    }
    $('vaultInfo').textContent = has && !open ? tt('user_unlock_hint') : '';
    $('lockBtn').disabled = !(has && open);
    $('unlockBtn').disabled = !(has && !open);
    $('changePwBtn').disabled = !has;
    $('selfRevokeBtn').disabled = !lastStatus?.registered;
    // 금고가 이미 있으면 등록 폼에서 금고 비밀번호를 묻지 않는다(잠겨 있으면 잠금 해제 창이 대신 묻는다).
    $('vaultFields').hidden = has;
  }
  /** 증명 키 내려받기(#zkProgress). 워커의 진행률은 user.js 가 'mode3-zk-progress' 이벤트로 넘긴다. */
  function renderZk() {
    const el = $('zkProgress');
    if (zk.kind === 'loading') el.textContent = tt('user_zk_loading', { name: zk.name, pct: zk.pct }) || `${zk.name} ${zk.pct}%`;
    else if (zk.kind === 'ready') el.textContent = tt('user_zk_ready') || '증명 키 준비됨';
    else if (zk.kind === 'fail') el.textContent = `${Demo.reason('zk_assets_unavailable')?.title ?? 'zk_assets_unavailable'} — ${zk.detail}`;
    else el.textContent = '';
  }
  window.addEventListener('mode3-zk-progress', ({ detail: p }) => {
    if (zk.kind === 'ready' || !p) return;
    const pct = p.total ? Math.min(100, Math.floor((p.loaded * 100) / p.total)) : '…';
    if (zk.kind === 'loading' && zk.name === p.name && zk.pct === pct) return;   // 같은 숫자면 다시 그리지 않는다(청크마다 온다)
    zk = { kind: 'loading', name: p.name, pct };
    renderZk();
  });

  async function refresh(sync = false) {
    // "새로고침" 버튼(sync)은 "내 편집 버리고 저장된 값으로" — 주기적 refresh(false) 는 타이핑 중인 값을 건드리지 않는다.
    if (sync) profileDirty = false;
    try {
      const r = await core.status({ sync });
      if (r.status !== 200) throw new Error(r.body?.detail ?? r.body?.reason ?? `status ${r.status}`);
      lastStatus = r.body;
      statusError = null;
    } catch (e) {
      // 상태를 못 읽었으면 세션 목록도 믿을 수 없다 — 지워진 세션의 폐기 버튼이 남지 않게 함께 비운다.
      lastStatus = null;
      statusError = e.message;
    }
    renderIdentity();
    renderSessions();
    renderGuide();
    await renderVault();
    await postPresence(core);
  }
  // 언어·전문가 전환은 사전이 채우는 요소와 결과 카드만 바꾼다(Demo) — 스크립트가 만든 텍스트는 여기서 다시 그린다.
  for (const k of ['setLang', 'setExpert']) {
    const orig = Demo[k];
    Demo[k] = (v) => { orig(v); renderModeTexts(); renderProofInfo(); renderZk(); renderIdentity(); renderSessions(); renderVault(); };
  }

  // V8 세션 폐기(설계 2026-09-24 §4): 서명은 코어가 금고의 sk_u 로 한다(잠겨 있으면 잠금 해제 창).
  async function revokeSession(r_s, c, btn) {
    if (!Demo.confirmDanger('confirm_revoke')) return;
    const out = (m) => { $('sessionLog').textContent = m; };
    btn.disabled = true;
    pendingVerdict($('sessionVerdict'), 'working');
    try {
      const { status, body: b } = await withUnlock(() => core.revokeSession({ r_s }));
      if (status === 200) {
        out(`세션 폐기 요청 완료 (r_s=${r_s.slice(0, 12)}…): inserted=${b.inserted}, pending=${b.pending} — 다음 게시부터 효력`);
        progress.revoked = true;
        setVerdict($('sessionVerdict'), true, 'revoked_ok', () => ({ summary: tt('wallet_session_revoked') || '이 세션만 폐기를 요청했습니다 — 다음 게시부터 효력이 있습니다.', detail: safeDetail(b) }));
      } else {
        out(`세션 폐기 실패 — ${errText(status, b)}`);
        setVerdict($('sessionVerdict'), false, 'wallet_session_revoke_failed', { reason: b.reason ?? `HTTP ${status}`, detail: safeDetail(b) });
      }
    } catch (e) {
      out(`세션 폐기 실패: ${e.message}`);
      setVerdict($('sessionVerdict'), false, 'wallet_session_revoke_failed', { reason: 'internal', detail: e.message });
    } finally { btn.disabled = false; refresh(); }
  }
  $('refreshBtn').addEventListener('click', () => refresh(true));

  // 등록: 폼의 uid·pwd(IdP 계정) + 금고 비밀번호(금고가 없을 때만). s_u·sk_u 는 코어가 만들어 금고에만 넣는다.
  // IdP 비밀번호는 IdP 로 한 번 지날 뿐이고, 금고 비밀번호는 읽자마자 입력칸에서 지운다(DOM 에 남기지 않는다).
  $('registerBtn').addEventListener('click', async () => {
    pendingVerdict($('registerResult'), 'working');
    const vp = $('vaultPw').value, vp2 = $('vaultPw2').value;
    $('vaultPw').value = ''; $('vaultPw2').value = '';
    try {
      await core.vault.refresh();
      let vaultPassword = null;
      if (!core.vault.hasVault()) {
        if (vp !== vp2) { setVerdict($('registerResult'), false, 'wallet_register_failed', () => ({ summary: tt('user_vault_pw_mismatch') || '두 비밀번호가 다릅니다' })); return; }
        if (vp.length < 8) { setVerdict($('registerResult'), false, 'wallet_register_failed', () => ({ summary: tt('user_vault_pw_short') || '금고 비밀번호는 8자 이상이어야 합니다' })); return; }
        vaultPassword = vp;
      }
      // 폼을 하나도 안 건드렸으면(전부 빈 값) profile 을 보내지 않는다 — 코어의 DEFAULT_PROFILE(데모 기본값)이 적용된다.
      const profileForm = readProfileForm();
      const typedProfile = Object.values(profileForm).some((v) => v !== '') ? profileForm : null;
      const req = { uid: $('uid').value.trim(), pwd: $('pwd').value, profile: typedProfile, vaultPassword };
      const { status, body: b } = await withUnlock(() => core.register(req));
      req.pwd = null; req.vaultPassword = null;
      if (status !== 201) {
        setVerdict($('registerResult'), false, 'wallet_register_failed', () => ({ reason: b.reason ?? `HTTP ${status}`, detail: safeDetail(b) }));
        return;
      }
      // 카드에 쓸 값은 여기서 먼저 꺼내 둔다 — 인자 생성기가 응답 본문을 붙잡지 않게(wallet.html 과 같은 규칙).
      const uid = b.uid;
      const detail = safeDetail(b);
      profileDirty = false;
      setVerdict($('registerResult'), true, 'registered', () => ({ summary: tt('wallet_registered_summary', { uid, attrs: profileText(b.profile) }) || `uid ${uid} · ${profileText(b.profile)}`, detail }));
    } catch (e) {
      setVerdict($('registerResult'), false, 'wallet_register_failed', { reason: 'internal', detail: e.message });
    } finally { refresh(); }
  });

  // V11 §3.3 — 속성은 사용자가 넣는다. 바뀌면 옛 자격증명·세션이 지워지고 다음 로그인이 새 C_u 를 받는다(금고의 blind_u·세션키도 지우므로 잠겨 있으면 잠금 해제).
  $('profileSaveBtn').addEventListener('click', async () => {
    pendingVerdict($('registerResult'), 'working');
    try {
      const profile = readProfileForm();
      const { status, body: b } = await withUnlock(() => core.saveProfile(profile));
      if (status !== 200) { setVerdict($('registerResult'), false, 'wallet_profile_failed', { reason: b.reason ?? `HTTP ${status}`, detail: safeDetail(b) }); return; }
      profileDirty = false;
      setVerdict($('registerResult'), true, 'wallet_profile_saved', () => ({ summary: tt(b.changed ? 'wallet_profile_changed' : 'wallet_profile_same', { attrs: profileText(b.profile) }) || profileText(b.profile), detail: safeDetail(b) }));
    } catch (e) { setVerdict($('registerResult'), false, 'wallet_profile_failed', { reason: 'internal', detail: e.message }); }
    refresh();
  });

  // "출생연도를 내 값으로"(U2): 슬롯0 이 체크돼 있으면 lo=hi=내 출생연도.
  $('discExactBtn').addEventListener('click', () => {
    if (!lastAttrs || !$('dk0').checked) return;
    $('discLo0').value = lastAttrs[0]; $('discHi0').value = lastAttrs[0];
  });
  // "나이 ≥ N": 슬롯0 을 체크하고 hi = 올해 − N. lo 는 스키마의 min(기본 1900) — 서비스는 lo ≥ min 도 요구한다(최종 리뷰 I1).
  $('ageBtn').addEventListener('click', () => {
    $('dk0').checked = true; $('discLo0').value = String(attrSchema?.slots?.[0]?.min ?? 0); $('discHi0').value = String(new Date().getUTCFullYear() - Number($('minAgeIn').value || 19));
  });
  $('discCountry').addEventListener('change', () => { countryTouched = true; });

  // U3: 보내기 전에 체크된 조건을 lastAttrs 와 다시 대조한다 — 안 맞으면 체크 해제 + 행 옆에 안내(코어의 disclosure_unsatisfiable 이 페이지 경로에서는 안 나오게).
  function sanitizeDisclose() {
    $('discNote0').textContent = ''; $('discNote1').textContent = '';
    if ($('dk0').checked && lastAttrs) {
      try {
        const lo = BigInt($('discLo0').value.trim() || '0'), hi = BigInt($('discHi0').value.trim() || '0'), mine = BigInt(lastAttrs[0] ?? 0);
        if (mine < lo || mine > hi) {
          $('dk0').checked = false;
          $('discNote0').textContent = tt('wallet_disc_excluded', { v: lastAttrs[0] }) || `내 값 ${lastAttrs[0]} 은 범위 밖이라 제외했습니다.`;
        }
      } catch { /* 형식이 틀렸으면 그대로 보낸다 — 코어의 bad_disclosure 가 걸러낸다 */ }
    }
    if ($('dk1').checked && lastAttrs) {
      const v = $('discCountry').value;
      if (v !== '' && v !== String(lastAttrs[1])) {
        $('dk1').checked = false;
        $('discNote1').textContent = tt('wallet_disc_excluded', { v: lastAttrs[1] }) || `내 값 ${lastAttrs[1]} 은 범위 밖이라 제외했습니다.`;
      }
    }
  }
  // 체크된 슬롯만 {lo, hi}, 나머지는 null — normalizeDisclosure(lib/mode3_wallet.js) 가 회로 입력으로 바꾼다.
  const readDisclose = () => [0, 1, 2, 3, 4, 5].map((k) => {
    if (!$('dk' + k).checked) return null;
    if (k === 0) return { lo: $('discLo0').value.trim(), hi: $('discHi0').value.trim() };
    if (k === 1) { const v = $('discCountry').value; return v === '' ? null : { lo: v, hi: v }; }
    if (k === 2 || k === 3) { const v = lastAttrs ? String(lastAttrs[k]) : '0'; return v === '0' ? null : { lo: v, hi: v }; }
    return null;
  });
  // 집합 소속(V7): 슬롯이 "없음" 이면 null — 코어가 members 로 root 를 계산해 증명에 넣는다(normalizeSet).
  const readSet = () => { const s = $('setSlot').value; if (s === '') return null; return { slot: Number(s), members: $('setMembers').value.split(',').map((x) => x.trim()).filter(Boolean).map((x) => encodeMember(Number(s), x)) }; };
  const txForm = () => { sanitizeDisclose(); return { r_s: $('txSession').value, to: $('txTo').value.trim(), value: $('txValue').value.trim() || '0', data: $('txData').value.trim() || '0x', disclose: readDisclose(), set: readSet() }; };
  const txLog = (s) => { $('txLog').textContent += `${s}\n`; };
  // demo(시연 덮어쓰기)가 실린 실패는 "[시연 모드]" 를 앞에 붙인다(wallet.html 과 같은 규칙).
  const txFailed = (summaryKey, reason, detail) => setVerdict($('txVerdict'), false, 'tx_failed', () => ({ summary: detail?.demo ? `[시연 모드] ${Demo.reason(reason)?.title ?? ''}` : (summaryKey ? (tt(summaryKey) || undefined) : undefined), reason, detail }));
  function showTxResult(b, extra, deployed) {
    txLog(`${extra}지갑=${b.wallet}  nonce=${b.nonce}  ok(실행 성공)=${b.ok}  gasUsed=${b.gasUsed}\n공개=${JSON.stringify(b.disclosure)}\n온체인 공개(Disclosure 이벤트)=${JSON.stringify(b.onchainDisclosure)}\n실행=${JSON.stringify(b.executed)}`);
    // 영수증은 받았지만 계정 안의 호출이 revert 된 경우에는 성공으로 보이면 안 된다 — 안내 바의 '이용' 완료 신호도 이 값에 달려 있다.
    const okx = b.ok !== false;
    const hash = b.txHash;
    const detail = safeDetail(b);
    if (!okx) {
      setVerdict($('txVerdict'), false, 'tx_failed', () => ({ summary: tt('wallet_tx_inner_failed', { hash: hash ?? '-' }) || '트랜잭션은 보냈지만 내부 호출이 실패했습니다.', detail }));
      return;
    }
    progress.txOk = true;
    const d = b.disclosure;
    if (d && (String(d.mask ?? '0') !== '0' || d.set)) progress.disclosed = true;
    lastProof = { ms: b.timings?.proveMs ?? null, cache: b.cacheHit };
    renderProofInfo();
    setVerdict($('txVerdict'), true, 'tx_ok', () => ({
      summary: [tt(deployed ? 'wallet_tx_deployed' : 'wallet_tx_sent'), hash ? tt('wallet_tx_hash', { hash }) : ''].filter(Boolean).join(' '),
      detail,
    }));
  }
  /** 202 pending 이면 몇 번 다시 묻는다(영수증이 아직 없다). */
  async function recordTx(r_s, txHash, tries = 30) {
    for (let i = 0; i < tries; i++) {
      const r = await core.recordTx({ r_s, txHash });
      if (r.status !== 202) return r;
      await sleep(700);
    }
    return { status: 202, body: { pending: true, txHash } };
  }
  /** web 모드(계획 R6): 코어가 증명·세션키 서명으로 execute calldata 를 만들고, 그 세션의 RP 릴레이가 (필요하면 계정을 배포한 뒤) 보낸다. */
  async function sendTxViaRelay() {
    const f = txForm();
    txLog('증명·서명 준비 중…');
    const p = await withUnlock(() => core.prepareTx(f));
    if (p.status !== 200) {
      txLog(errText(p.status, p.body));
      txFailed('wallet_tx_prepare_failed', p.body.reason ?? `HTTP ${p.status}`, safeDetail(p.body));
      return;
    }
    const b = p.body;
    txLog(`지갑 주소=${b.walletAddr}  nonce=${b.nonce}  배포 필요=${b.deployNeeded}  캐시 히트=${b.cacheHit}  root=${b.root}\ntimings=${JSON.stringify(b.timings)}`);
    // 릴레이는 그 세션을 만든 RP 의 것이다(세션 레코드의 origin). 옛 세션에 origin 이 없으면 첫 RP 로 본다.
    const rpOrigin = (await meta.session(f.r_s))?.origin ?? cfg.rpOrigins?.[0] ?? null;
    const relayUrl = `${rpOrigin}${cfg.relayPath ?? '/api/mode3/relay'}`;
    txLog(`POST ${relayUrl} — RP 의 릴레이가 ${b.deployNeeded ? '계정을 배포하고 ' : ''}보낸다`);
    let relay;
    try {
      const r = await fetch(relayUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ to: b.walletAddr, data: b.calldata }) });
      relay = await r.json().catch(() => ({ ok: false, reason: null, detail: `HTTP ${r.status}` }));
    } catch (e) {
      txLog(`릴레이 호출 실패: ${e.message}`);
      txFailed(null, null, `${relayUrl}: ${e.message}`);
      return;
    }
    if (!relay.ok) {
      txLog(`릴레이 거절 — ${relay.reason ?? ''} ${relay.detail ?? ''}`);
      txFailed(null, relay.reason ?? 'internal', b.demo ? { ...relay, demo: b.demo } : relay);
      return;
    }
    txLog(`txHash=${relay.txHash}${relay.deployTxHash ? `  배포 txHash=${relay.deployTxHash}` : ''} — 영수증 대기…`);
    const rec = await recordTx(f.r_s, relay.txHash);
    if (rec.status !== 200) {
      txLog(errText(rec.status, rec.body));
      txFailed('wallet_tx_record_failed', rec.body.reason ?? `HTTP ${rec.status}`, safeDetail(rec.body));
      return;
    }
    // 존재 신호(txs·disclosedTxs)를 결과 카드보다 먼저 맞춘다 — RP·상태 패널이 성공을 보자마자 health 를 읽을 수 있다.
    await postPresence(core);
    showTxResult({ ...rec.body, timings: b.timings, cacheHit: b.cacheHit }, `txHash=${rec.body.txHash}${relay.deployTxHash ? `\n배포 txHash=${relay.deployTxHash}` : ''}\n캐시 히트=${b.cacheHit}  root=${b.root}\n`, Boolean(relay.deployed));
  }

  // "Selective disclosure proof 보내기"(U4): to/data 를 이 세션의 AttrGate 로 채우고, 조건이 비어 있으면 내 속성으로 늘 만족되는 값으로 채운다.
  $('claimBtn').addEventListener('click', () => {
    const c = lastSessions[$('txSession').value];
    if (!c || !c.attrGateAddress) return;
    $('txTo').value = c.attrGateAddress;
    $('txData').value = '0x4e71d92d';
    if (!$('dk0').checked) {
      const minAge = Number(c.minAge ?? cfg.minAge ?? 19);
      $('dk0').checked = true;
      $('discLo0').value = String(attrSchema?.slots?.[0]?.min ?? 0);
      $('discHi0').value = String(new Date().getUTCFullYear() - minAge);
    }
    $('setSlot').value = '1';
    const known = Array.isArray(c.allowedCountries) && c.allowedCountries.length ? c.allowedCountries
      : Array.isArray(cfg.allowedCountries) && cfg.allowedCountries.length ? cfg.allowedCountries : null;
    if (known) $('setMembers').value = known.join(',');
    else if (!$('setMembers').value.trim()) {
      const mine = lastAttrs && String(lastAttrs[1]) !== '0' ? String(lastAttrs[1]) : '';
      if (mine) $('setMembers').value = mine;
    }
  });

  $('txBtn').addEventListener('click', async () => {
    $('txBtn').disabled = true; $('txLog').textContent = '';
    pendingVerdict($('txVerdict'), 'proving');
    try { await sendTxViaRelay(); }
    catch (e) {
      txLog(`오류: ${e.message}`);
      txFailed(null, e?.reason ?? 'internal', e.message);
    } finally { $('txBtn').disabled = false; refresh(); }
  });

  // ---- 시연 카드(V9 §8.3, 전문가 보기 전용): 다음 발급/증명의 salt·uid 를 한 번만 덮어쓴다(코어의 kv `demo`) ----
  $('demoNewSalt').addEventListener('click', () => { const b = new Uint8Array(32); crypto.getRandomValues(b); b[0] &= 0x03; $('demoSalt').value = BigInt('0x' + [...b].map((x) => x.toString(16).padStart(2, '0')).join('')).toString(); });   // 2^250 미만
  $('demoApplyBtn').addEventListener('click', async () => {
    try {
      const body = { scope: $('demoScope').value };
      if ($('demoSalt').value.trim()) body.s_u = $('demoSalt').value.trim();
      if ($('demoUid').value.trim()) body.uid = $('demoUid').value.trim();
      const { status, body: b } = await core.demoOverride(body);
      if (status !== 200) { setVerdict($('demoVerdict'), false, 'wallet_demo_failed', { reason: b.error ?? b.reason ?? `HTTP ${status}` }); return; }
      setVerdict($('demoVerdict'), true, 'wallet_demo_set', () => ({ summary: tt('wallet_demo_set_summary', { scope: b.override.scope, fields: b.override.fields.join(', ') }) || `적용: ${b.override.scope} (${b.override.fields.join(', ')})` }));
    } catch (e) {
      setVerdict($('demoVerdict'), false, 'wallet_demo_failed', { reason: 'internal', detail: e.message });
    }
    refresh();
  });
  $('demoClearBtn').addEventListener('click', async () => {
    try {
      await core.demoOverride({ clear: true });
      setVerdict($('demoVerdict'), true, 'wallet_demo_cleared', () => ({ summary: tt('wallet_demo_cleared') || '원래대로' }));
    } catch (e) {
      setVerdict($('demoVerdict'), false, 'wallet_demo_failed', { reason: 'internal', detail: e.message });
    }
    refresh();
  });
  // 가짜 증명·가짜 서명(2026-10-14): s_u·uid 는 그대로다 — scope 만 보낸다. 다음 1회 로그인(또는 트랜잭션)의 보내는 복사본만 코어가 바꿔친다.
  async function armFakeDemo(scope, whatKey, whatFallback) {
    try {
      const { status, body: b } = await core.demoOverride({ scope });
      if (status !== 200) { setVerdict($('demoVerdict'), false, 'wallet_demo_failed', { reason: b.error ?? b.reason ?? `HTTP ${status}` }); return; }
      const what = tt(whatKey) || whatFallback;
      setVerdict($('demoVerdict'), true, 'wallet_demo_set', () => ({ summary: tt('wallet_demo_fake_armed', { what }) || `다음 1회: ${what}` }));
    } catch (e) {
      setVerdict($('demoVerdict'), false, 'wallet_demo_failed', { reason: 'internal', detail: e.message });
    }
    refresh();
  }
  $('demoFakeProofBtn').addEventListener('click', () => armFakeDemo('fake_proof', 'wallet_demo_fake_proof', '가짜 증명'));
  $('demoFakeSigBtn').addEventListener('click', () => armFakeDemo('fake_sig', 'wallet_demo_fake_sig', '가짜 서명'));

  // ---- 보관 상태 카드 ----
  const storageVerdict = () => $('storageVerdict');
  $('lockBtn').addEventListener('click', async () => { await core.vault.lock(); await renderVault(); });
  $('unlockBtn').addEventListener('click', async () => { await askUnlock(); await core.vault.refresh(); await renderVault(); });
  $('changePwBtn').addEventListener('click', () => {
    const modal = $('changePwModal'), oldEl = $('changePwOld'), newEl = $('changePwNew'), new2El = $('changePwNew2'), go = $('changePwGo'), cancel = $('changePwCancel'), v = $('changePwVerdict');
    const clear = () => { oldEl.value = ''; newEl.value = ''; new2El.value = ''; };
    clear(); v.textContent = ''; v.className = ''; modal.hidden = false; oldEl.focus();
    const close = () => { clear(); modal.hidden = true; go.removeEventListener('click', onGo); cancel.removeEventListener('click', onCancel); };
    async function onGo() {
      const o = oldEl.value, n = newEl.value, n2 = new2El.value;
      clear();
      if (n !== n2) { setVerdict(v, false, 'user_change_pw_failed', () => ({ summary: tt('user_vault_pw_mismatch') || '두 비밀번호가 다릅니다' })); return; }
      if (n.length < 8) { setVerdict(v, false, 'user_change_pw_failed', () => ({ summary: tt('user_vault_pw_short') || '금고 비밀번호는 8자 이상이어야 합니다' })); return; }
      go.disabled = true;
      try {
        if (!(await core.vault.changePassword(o, n))) { setVerdict(v, false, 'user_change_pw_failed', { reason: 'bad_password' }); return; }
        close();
        setVerdict(storageVerdict(), true, 'user_change_pw_done', {});
      } catch (e) { setVerdict(v, false, 'user_change_pw_failed', { reason: 'storage_unavailable', detail: e.message }); }
      finally { go.disabled = false; await core.vault.refresh(); await renderVault(); }
    }
    const onCancel = () => close();
    go.addEventListener('click', onGo); cancel.addEventListener('click', onCancel);
  });
  // 자기 폐기(스펙 §4.5): IdP 계정 비밀번호를 창에서 받아 코어가 IdP 로 바로 보낸다(cia.js CORS). 비밀번호는 보관하지 않는다.
  $('selfRevokeBtn').addEventListener('click', async () => {
    if (!Demo.confirmDanger('confirm_revoke')) return;
    const uid = lastStatus?.uid ?? null;
    if (!uid) return;
    const pwd = await askSecret({ modalId: 'selfRevokeModal', inputId: 'selfRevokePw', goId: 'selfRevokeGo', cancelId: 'selfRevokeCancel' });
    if (pwd === null) { setVerdict(storageVerdict(), false, 'wallet_self_revoke_failed', () => ({ summary: tt('wallet_cancelled') || '창에서 취소했습니다.' })); return; }
    pendingVerdict(storageVerdict(), 'working');
    try {
      const res = await core.selfRevoke({ uid, pwd });
      if (res.status === 200) {
        progress.revoked = true;
        setVerdict(storageVerdict(), true, 'revoked_ok', () => ({ summary: tt('wallet_self_revoke_ok', { uid }) || `uid ${uid} 계정의 폐기를 요청했습니다.`, detail: safeDetail(res.body) }));
      } else setVerdict(storageVerdict(), false, 'wallet_self_revoke_failed', { reason: res.body.reason ?? `HTTP ${res.status}`, detail: safeDetail(res.body) });
    } catch (e) {
      setVerdict(storageVerdict(), false, 'wallet_self_revoke_failed', { reason: 'internal', detail: e.message });
    }
    refresh();
  });
  $('wipeBtn').addEventListener('click', async () => {
    if (!Demo.confirmDanger('confirm_wipe')) return;
    pendingVerdict(storageVerdict(), 'working');
    try {
      const r = await core.wipe();
      if (r.status === 200) {
        // 스펙 §10 — "모두 지우기" 는 Snap 초기화의 등가물이라 증명 키 캐시까지 비운다(산출물 재생성 뒤 옛 zkey 가 남지 않게).
        if (typeof caches !== 'undefined') { try { await caches.delete(ZK_CACHE_NAME); } catch { /* 캐시 삭제 실패는 무시 — 다음 로드가 다시 받는다 */ } }
        Object.assign(progress, { txOk: false, disclosed: false, revoked: false });
        setVerdict(storageVerdict(), true, 'user_wipe_btn', () => ({ summary: tt('user_wipe_done') || '이 브라우저의 등록·비밀·세션을 지웠습니다.' }));
      } else setVerdict(storageVerdict(), false, 'error_title', { reason: r.body.reason ?? `HTTP ${r.status}`, detail: safeDetail(r.body) });
    } catch (e) { setVerdict(storageVerdict(), false, 'error_title', { reason: 'storage_unavailable', detail: e.message }); }
    refresh(true);
  });

  async function init() {
    // 체험 모드의 잠금(설계 §3.3). #registerBtn 은 지금까지 늘 활성이었다 — 그 규칙을 otherwise 로 그대로 옮긴다.
    Demo.tour?.lock({ id: 'registerBtn', cond: 'rp_approved', otherwise: () => true });
    Demo.tour?.onToggle(renderGuide);
    renderModeTexts();
    renderProofInfo();
    renderZk();
    await loadAttrSchema();
    await refresh();
    // 등록부 확인 줄(V9 §8.2)은 다른 창(RP 로그인·승인 창·관리자)이 바꾼 상태를 반영해야 한다 — 탭이 보일 때 5초마다 다시 읽는다.
    setInterval(() => { if (!document.hidden) refresh(); }, 5000);
    // 증명 키는 등록 전에도 받아 둔다(첫 로그인이 빨라진다). Cache API 에 있으면 진행률 없이 바로 준비된다.
    prover.warm().then(() => { zk = { kind: 'ready' }; renderZk(); }, (e) => { zk = { kind: 'fail', detail: e.message }; renderZk(); });
  }
  return init();
}
