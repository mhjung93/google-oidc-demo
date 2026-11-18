// mode3/user/ui.js — 브라우저 전용 사용자 페이지의 화면(스펙 2026-10-15 §4.2). mode3/wallet.html(에이전트 페이지)의 화면 로직을 옮겼다.
// 치환 규칙(계획 Task 9): 에이전트 HTTP 호출 → user_core 의 같은 이름 함수(같은 { status, body }), 트랜잭션은 RP 의 릴레이로(sendTxViaRelay),
// MetaMask·Snap 코드는 없다. 비밀(s_u·blind_u·세션 개인키·금고 비밀번호·secrets 암호문)은 DOM·localStorage·로그·postMessage 에
// 넣지 않는다 — 코어 응답은 에이전트와 같은 모양이라 비밀이 실리지 않고, safeDetail 이 한 번 더 거른다. 비밀번호 입력칸은 읽자마자 비운다.
import { ZK_CACHE_NAME } from '../../lib/browser/zk_assets.js';
import { RECOVER_RESULT_KEY, idpAuthUrl, savePending } from './idp_return.js';
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
/** 2026-10-16: 금고 비밀번호·잠금 해제 창을 없앴다(자동 금고). 호환을 위해 같은 모양을 돌려준다 — withUnlock 은 그냥 fn 을 부른다.
 *  옛 비밀번호 금고가 잠겨 있으면(423) 그 결과가 그대로 화면에 간다("모두 지우기" 뒤 다시 등록하면 자동 금고가 된다). */
export function createUnlocker() {
  return { withUnlock: (fn) => fn(), ask: async () => false };
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

/** oidc: IdP 의 public_keys.oidc({ enabled, provider, clientId, issuer }) — user.js 가 읽어 넘긴다. 못 읽으면 기본값(꺼짐)이라 Google 버튼만 숨는다.
 *  passkey: passkey-web 의 { derive, create }(user.js — RP ID 는 설정의 사용자 오리진 호스트). 설정 카드의 두 버튼만 직접 부른다. */
export function mountUi({ core, prover, config, Demo, meta, demoReset = false, passkey = null }) {
  const { tte, tt, setVerdict, pendingVerdict } = textKit(Demo);
  const { withUnlock, ask: askUnlock } = createUnlocker({ core, Demo });
  // /wallet/config 대신 /user/config(같은 오리진). minAge·allowedCountries 는 없다 — claim 버튼이 기본값으로 대신한다(에이전트와 같다).
  const cfg = { ...config, secrets: config.secrets ?? 'web' };
  // passkey-web(2026-11-17 계획 Task 7): salt 는 패스키 — 설정 카드·salt 보기·연결 끊기·계정 복구 카드를 보이고, 등록 폼·복구 코드는 숨긴다.
  const PK = cfg.secrets === 'passkey-web';
  // 패스키는 설정의 사용자 오리진 호스트(RP ID)에서만 쓸 수 있다 — 다른 호스트(127.0.0.1 등)로 열면 WebAuthn 을 부르지 않고 안내만 한다.
  const pkOriginOk = PK && (() => { try { return location.hostname === new URL(cfg.walletOrigin).hostname; } catch { return false; } })();
  let pkState = null;        // core.passkeyState() 본문 { credentialId, createdAt, heldUntil } — 공개값만(salt 없음)
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
    if (PK) lockAttrInputs();
  }
  /** passkey-web: 속성은 속성 커밋먼트 도구에서만 바꾸고 이 화면에는 저장 버튼이 없다 — 신원 카드의 속성 칸을 읽기 전용으로(선택 목록은 끔). */
  function lockAttrInputs() {
    for (let k = 0; k < 6; k++) { const el = $('attr' + k); if (!el) continue; if (el.tagName === 'SELECT') el.disabled = true; else el.readOnly = true; }
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
    // 안내 바 링크(2026-10-16 복원): 에이전트 페이지처럼 RP1·RP2 도 넣는다 — 설정의 rpOrigins(첫 RP, 두 번째 RP).
    const links = { rp: cfg.rpOrigins?.[0] ?? null, rp2: cfg.rpOrigins?.[1] ?? null, admin: s?.ciaUrl ? `${s.ciaUrl}/admin` : null, account: s?.ciaUrl ? `${s.ciaUrl}/account` : null };
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
    // Google 등으로 등록한 계정이면 어느 발급자의 계정인지 덧붙인다(데모 계정·provider 없는 옛 등록은 uid 만).
    const providerNote = s?.registered && s.provider && s.provider !== 'demo' ? tt('user_identity_provider', { provider: s.provider }) : '';
    $('regInfo').textContent = s?.registered ? [tt('wallet_uid', { uid: s.uid }), providerNote].filter(Boolean).join(' · ') : '';
    $('credInfo').textContent = tt(credKey) || '-';
    $('aaInfo').textContent = s?.ciaUrl || tt('wallet_aa_none') || '-';
    // 등록 폼은 미등록일 때만 펼친다(설계 §4.1).
    $('fileRegFields').hidden = PK || Boolean(s?.registered);   // passkey-web 은 첫 서비스 로그인이 등록이다(IdP 인증 창)
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
  /** 세션의 서비스 표기 — "zkONE(8674…)"(2026-10-16): 로그인 때 RP 가 보낸 이름(팝업이 오리진 대조 뒤 저장) + arid 앞 4자리. 이름이 없으면 오리진 host, 그것도 없으면 arid. */
  function rpLabel(c) {
    const a4 = `${String(c.arid ?? '').slice(0, 4)}…`;
    if (c.serviceName) return `${c.serviceName}(${a4})`;
    try { if (c.origin) return `${new URL(c.origin).host}(${a4})`; } catch { /* 오리진이 이상하면 arid 로 */ }
    return shortCode(c.arid, 8);
  }
  /** 보낸 트랜잭션 목록(2026-10-16) — 코어 status().txs(최신순). 해시는 앞부분만 보이고 title 에 전체. */
  // 거래 해시 복사(2026-10-21). 이 페이지는 localhost(보안 컨텍스트)라 보통 클립보드 API 가 되지만, 막히면 선택 복사로 대신한다.
  async function copyText(text, btn) {
    try { await navigator.clipboard.writeText(text); }
    catch { const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); } finally { ta.remove(); } }
    const prev = btn.textContent; btn.textContent = tt('rp_copied') || '복사됨'; btn.classList.add('copied');
    setTimeout(() => { btn.textContent = prev; btn.classList.remove('copied'); }, 1200);
  }
  let lastTxsKey = null;
  function renderTxs() {
    const host = $('txsList'); if (!host) return;
    const txs = lastStatus?.txs ?? [];
    // 2초 새로고침마다 같은 표를 다시 그리면 복사 버튼의 "복사됨" 표시가 바로 지워진다 — 바뀐 게 있을 때만 그린다.
    const key = JSON.stringify([txs, Demo.lang, Demo.expert]);
    if (key === lastTxsKey) return;
    lastTxsKey = key;
    host.textContent = '';
    if (!txs.length) { const p = document.createElement('p'); p.className = 'muted'; p.textContent = tt('wallet_txs_none') || '보낸 트랜잭션이 없습니다.'; host.appendChild(p); return; }
    const table = document.createElement('table'); table.className = 'list';
    const head = table.createTHead().insertRow();
    for (const [k, fb] of [['wallet_col_time', '시각'], ['wallet_col_rp', '서비스'], ['wallet_col_account', '내 주소'], ['wallet_col_to', '받는 주소'], ['wallet_col_value', '금액(wei)'], ['wallet_col_tx', '트랜잭션'], ['wallet_col_result', '결과']]) {
      const th = document.createElement('th'); th.textContent = tt(k) || fb; head.appendChild(th);
    }
    const body = table.createTBody();
    for (const x of txs) {
      const row = body.insertRow();
      const t = new Date(x.at); row.insertCell().textContent = Number.isNaN(t.getTime()) ? String(x.at ?? '') : t.toLocaleString(Demo.lang === 'en' ? 'en-US' : 'ko-KR');
      row.insertCell().textContent = rpLabel({ arid: x.arid, serviceName: x.serviceName, origin: x.origin });
      const acct = row.insertCell(); acct.textContent = x.wallet ? `${x.wallet.slice(0, 6)}…${x.wallet.slice(-4)}` : '-'; acct.title = x.wallet ?? '';
      const to = row.insertCell(); to.textContent = x.to ? `${x.to.slice(0, 6)}…${x.to.slice(-4)}` : '-'; to.title = x.to ?? '';
      row.insertCell().textContent = x.value ?? '-';
      const hx = row.insertCell(); const code = document.createElement('code'); code.textContent = `${String(x.txHash).slice(0, 12)}…`; code.title = x.txHash; hx.appendChild(code);
      const cb = document.createElement('button'); cb.type = 'button'; cb.className = 'copy-btn'; cb.textContent = '⧉'; cb.title = tt('copy_txhash_title') || '트랜잭션 해시 복사'; cb.setAttribute('aria-label', cb.title);
      cb.addEventListener('click', () => copyText(x.txHash, cb)); hx.append(' ', cb);
      const res = row.insertCell(); const b = document.createElement('span'); b.className = `badge ${x.ok === false ? 'bad' : 'ok'}`; b.textContent = x.ok === false ? (tt('wallet_tx_result_fail') || '실패(revert)') : (tt('wallet_tx_result_ok') || '성공');
      res.appendChild(b);
      if (x.disclosed) { const d = document.createElement('span'); d.className = 'badge muted'; d.textContent = tt('wallet_tx_disclosed') || '조건 공개'; res.append(' ', d); }
    }
    host.appendChild(table);
  }
  // ---- 영지식 증명 카드(2026-11-18 사용자 요청): 이 브라우저가 만든 증명(코어 proofs())의 목록·공개 입력·검증·값 바꿔 보기 ----
  // 공개 입력의 묶음 [첫 색인, 개수, 이름] — 회로의 공개 신호 순서 그대로다(circuits/pi_cred.circom·pi_idp.circom, lib/mode3_onchain.js PUB_INDEX).
  // 설명은 사전의 user_pub_s_<이름>·user_pub_idp_<이름>. 화면에서 회로 pi_cred 의 증명은 π_session(π_s) 로 적는다(사용자 결정).
  const PUB_ROWS = {
    pi_cred: [[0, 1, 'PPID'], [1, 1, 'arid'], [2, 1, 'pk_i'], [3, 1, 'max_height'], [4, 1, 'chainid'], [5, 1, 'allowAgent'], [6, 1, 'revRoot'], [7, 1, 'regRoot'], [8, 2, 'pk_CIA'], [10, 2, 'pk_trace'], [12, 3, 'tag'],
      [15, 1, 'disc_mask'], [16, 6, 'disc_lo'], [22, 6, 'disc_hi'], [28, 1, 'set_sel'], [29, 1, 'set_root'], [30, 1, 'auid_s'], [31, 1, 'arid_s'], [32, 1, 'r_s'], [33, 1, 'counter']],
    pi_idp: [[0, 1, 'uid'], [1, 1, 'auid'], [2, 1, 'auid_s'], [3, 2, 'C_u'], [5, 2, 'C_s'], [7, 1, 'max_height'], [8, 1, 'ctx'], [9, 1, 'tag']],
  };
  /** 버튼을 누르지 않아도 보이는 줄(사용자 결정): π_session 은 번호 1~7(arid … regRoot)만. π_IdP 는 목록에서 이미 버튼 뒤에 있으므로 전부. */
  const pubDefault = (kind, first) => kind !== 'pi_cred' || (first >= 1 && first <= 7);
  const pubDescKey = (kind, name) => `user_pub_${kind === 'pi_cred' ? 's' : 'idp'}_${name}`;
  const locale = () => (Demo.lang === 'en' ? 'en-US' : 'ko-KR');
  let lastProofs = [], proofsShowIdp = false, lastProofsKey = null;
  let proofOpen = null;   // 보기 창의 상태 { rec, all(전체 보기), edit(값 바꿔 보기), values(검증에 넣을 공개 입력 — 고친 값 포함) }
  const proofKindLabel = (kind) => tt(`user_proof_kind_${kind}`) || kind;
  const proofPurposeLabel = (x) => tt(`user_proof_purpose_${x.purpose}`) || x.purpose || '-';
  const proofTarget = (x) => (x.kind === 'pi_idp' ? [tt('user_proof_target_idp') || 'zkID', x.arid ? rpLabel(x) : null].filter(Boolean).join(' · ') : rpLabel(x));
  function renderProofs() {
    const host = $('proofsList'); if (!host) return;
    const list = lastProofs.filter((x) => proofsShowIdp || x.kind === 'pi_cred');
    // 2초 새로고침마다 표를 다시 그리지 않는다(거래 목록과 같다) — 줄·거래 해시·언어·보기 범위가 바뀔 때만.
    const key = JSON.stringify([list.map((x) => [x.id, x.txHash ?? null]), proofsShowIdp, Demo.lang]);
    if (key === lastProofsKey) return;
    lastProofsKey = key;
    const kb = $('proofsKindBtn'); kb.dataset.i18n = proofsShowIdp ? 'user_proofs_hide_idp' : 'user_proofs_show_idp'; kb.textContent = tt(kb.dataset.i18n) || kb.textContent;
    host.textContent = '';
    if (!list.length) { const p = document.createElement('p'); p.className = 'muted'; p.textContent = tt('user_proofs_none') || '아직 만든 증명이 없습니다.'; host.appendChild(p); return; }
    const table = document.createElement('table'); table.className = 'list';
    const head = table.createTHead().insertRow();
    for (const [k, fb] of [['wallet_col_time', '시각'], ['user_proof_col_kind', '증명'], ['user_proof_col_purpose', '용도'], ['user_proof_col_target', '대상'], ['user_proof_col_ms', '생성 시간'], [null, '']]) {
      const th = document.createElement('th'); th.textContent = k ? (tt(k) || fb) : fb; head.appendChild(th);
    }
    const body = table.createTBody();
    for (const x of list) {
      const row = body.insertRow(); row.dataset.proofKind = x.kind; row.dataset.proofPurpose = x.purpose ?? '';
      row.insertCell().textContent = new Date(x.at).toLocaleTimeString(locale());
      row.insertCell().textContent = proofKindLabel(x.kind);
      row.insertCell().textContent = proofPurposeLabel(x);
      row.insertCell().textContent = proofTarget(x);
      row.insertCell().textContent = `${(Number(x.ms) / 1000).toFixed(1)}s`;
      const b = document.createElement('button'); b.type = 'button'; b.className = 'btn-ghost proof-view'; b.textContent = tt('user_proof_view_btn') || '보기';
      b.addEventListener('click', () => openProof(x.id)); row.insertCell().appendChild(b);
    }
    host.appendChild(table);
  }
  /** 기록을 다시 읽는다 — 목록을 그린 뒤에 붙은 것(승인 창의 recordTx 가 단 거래 해시)도 보이게. */
  async function loadProofs() { try { const r = await core.proofs(); lastProofs = r.status === 200 ? r.body.proofs : []; } catch { lastProofs = []; } }
  async function openProof(id) {
    await loadProofs();
    const rec = lastProofs.find((x) => x.id === id); if (!rec) { renderProofs(); return; }   // 그 사이 지워졌다(모두 지우기·상한)
    proofOpen = { rec, all: false, edit: false, values: rec.publicSignals.map(String) };
    clearVerdict($('proofVerdict')); renderProofModal(); $('proofModal').hidden = false;
  }
  /** 창이 열린 동안 그 기록에 거래 해시가 붙으면 창도 따라간다(공개 입력·고친 값은 그대로 둔다). */
  function syncOpenProof() {
    if (!proofOpen) return;
    const cur = lastProofs.find((x) => x.id === proofOpen.rec.id);
    if (cur && (cur.txHash ?? null) !== (proofOpen.rec.txHash ?? null)) { proofOpen.rec = cur; renderProofModal(); }
  }
  const proofChanged = () => (proofOpen ? proofOpen.values.filter((v, i) => v !== proofOpen.rec.publicSignals[i]).length : 0);
  function renderProofModal() {
    if (!proofOpen) return;
    const { rec, all, edit, values } = proofOpen;
    $('proofTitle').textContent = `${proofKindLabel(rec.kind)} · ${proofPurposeLabel(rec)}`;
    $('proofMeta').textContent = [proofTarget(rec), new Date(rec.at).toLocaleString(locale()), `${(Number(rec.ms) / 1000).toFixed(1)}s`].join(' · ');
    // 출금 증명: 그 증명이 실린 거래(코어 recordTx 가 붙인 해시). 탐색기 주소(설정 explorerUrl)가 있으면 링크도.
    $('proofTxRow').hidden = !rec.txHash; $('proofTxHash').textContent = rec.txHash ?? '';
    const link = $('proofTxLink'); link.hidden = !(rec.txHash && cfg.explorerUrl); if (!link.hidden) link.href = `${cfg.explorerUrl}/tx/${rec.txHash}`;
    const rows = PUB_ROWS[rec.kind] ?? [];
    const shown = rows.filter(([first]) => all || pubDefault(rec.kind, first));
    $('proofInputsTitle').textContent = tt('user_proof_inputs_title', { shown: shown.reduce((n, r) => n + r[1], 0), total: values.length }) || '공개 입력';
    const table = $('proofInputs'); table.textContent = '';
    const head = table.createTHead().insertRow();
    for (const [k, fb] of [['user_proof_col_no', '번호'], ['user_proof_col_name', '이름'], ['user_proof_col_value', '값']]) { const th = document.createElement('th'); th.textContent = tt(k) || fb; head.appendChild(th); }
    const body = table.createTBody();
    for (const [first, count, name] of shown) {
      const row = body.insertRow(); row.dataset.pub = name;
      const no = row.insertCell(); no.className = 'pn'; no.textContent = count === 1 ? `[${first}]` : `[${first}–${first + count - 1}]`;
      const d = row.insertCell(); d.className = 'pd';
      const nm = document.createElement('strong'); nm.textContent = name; const ds = document.createElement('div'); ds.className = 'muted'; ds.textContent = tt(pubDescKey(rec.kind, name)) || '';
      d.append(nm, ds);
      const v = row.insertCell(); v.className = 'pv';
      for (let i = first; i < first + count; i++) {
        if (!edit) { const c = document.createElement('code'); c.textContent = values[i]; v.appendChild(c); continue; }
        // 값 바꿔 보기: 보이는 칸만 고친다 — 검증은 숨긴 칸까지 포함한 전체 공개 입력으로 돈다.
        const inp = document.createElement('input'); inp.value = values[i]; inp.spellcheck = false; inp.autocomplete = 'off'; inp.dataset.pubIndex = String(i);
        inp.classList.toggle('changed', values[i] !== rec.publicSignals[i]);
        inp.addEventListener('input', () => { values[i] = inp.value.trim(); inp.classList.toggle('changed', values[i] !== rec.publicSignals[i]); $('proofResetBtn').hidden = false; clearVerdict($('proofVerdict')); });
        v.appendChild(inp);
      }
    }
    const more = $('proofMoreBtn'); more.hidden = rows.every(([first]) => pubDefault(rec.kind, first));
    more.dataset.i18n = all ? 'user_proof_less_btn' : 'user_proof_more_btn'; more.textContent = tt(more.dataset.i18n) || more.textContent;
    $('proofEditBtn').hidden = edit; $('proofResetBtn').hidden = !edit;
    $('proofBody').textContent = JSON.stringify({ pi_a: rec.proof.pi_a, pi_b: rec.proof.pi_b, pi_c: rec.proof.pi_c }, null, 1);
  }
  $('proofsKindBtn').addEventListener('click', () => { proofsShowIdp = !proofsShowIdp; renderProofs(); });
  $('proofMoreBtn').addEventListener('click', () => { if (!proofOpen) return; proofOpen.all = !proofOpen.all; renderProofModal(); });
  $('proofEditBtn').addEventListener('click', () => { if (!proofOpen) return; proofOpen.edit = true; renderProofModal(); });
  $('proofResetBtn').addEventListener('click', () => { if (!proofOpen) return; proofOpen.edit = false; proofOpen.values = proofOpen.rec.publicSignals.map(String); clearVerdict($('proofVerdict')); renderProofModal(); });
  $('proofCloseBtn').addEventListener('click', () => { $('proofModal').hidden = true; proofOpen = null; clearVerdict($('proofVerdict')); });
  $('proofCopyBtn').addEventListener('click', () => copyText($('proofBody').textContent, $('proofCopyBtn')));
  // 검증: 증명 워커가 그 종류의 검증키(/zk/*_vkey.json)로 Groth16 검증을 다시 돌린다 — 값을 고쳤으면 고친 공개 입력으로.
  $('proofVerifyBtn').addEventListener('click', async () => {
    if (!proofOpen) return;
    const { rec, values } = proofOpen, changed = proofChanged(), el = $('proofVerdict');
    pendingVerdict(el, 'user_proof_verifying');
    try {
      const { ok, ms } = await prover.verify(rec.kind, rec.proof, values.slice());
      setVerdict(el, ok, ok ? 'user_proof_valid' : 'user_proof_invalid', () => ({ summary: tt(ok ? 'user_proof_valid_note' : changed ? 'user_proof_invalid_note_edited' : 'user_proof_invalid_note', { ms, n: changed }) }));
    } catch (e) { setVerdict(el, false, 'user_proof_verify_failed', { reason: e?.reason ?? 'internal', detail: e?.message }); }
  });
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
      opt.textContent = `${rpLabel(c)} · ${acct}${factory ? ` · ${factory}` : ''}`;   // 2026-10-16: 서비스 이름(zkONE(8674…))으로
      opt.title = c.account ? `${c.account}  (PPID ${c.PPID})` : `PPID ${c.PPID}`;
      if (c.factoryAddress) anyFactory = true;
      sel.appendChild(opt);
    }
    if (entries.some(([r_s]) => r_s === prev)) sel.value = prev;
    // txBtn 은 늘 활성(2026-10-16) — 팩토리가 없으면 눌렀을 때 결과 카드가 사유를 말한다.

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
      kvRow(dl, tt('wallet_session_service') || 'RP', rpLabel(c));   // 2026-10-16: zkONE(8674…) 꼴
      kvRow(dl, termEl('PPID'), shortCode(c.PPID, 12));
      kvRow(dl, tt('wallet_session_expiry') || '만료', tt('wallet_session_expires', { h: c.max_height }) || String(c.max_height));
      const agent = document.createElement('span');
      agent.className = `badge ${c.allowAgent === '1' ? 'ok' : 'muted'}`;
      agent.textContent = tt(c.allowAgent === '1' ? 'rp_agent_yes' : 'rp_agent_no') || c.allowAgent;
      if (!PK) kvRow(dl, termEl('allowAgent'), agent);   // 2026-11-18(사용자 요청): passkey-web 에는 대리 전송할 에이전트가 없다 — 줄을 내지 않는다
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
  /** 보관 상태 — 2026-10-16: 금고 비밀번호·잠금 UI 를 뺐다(자동 금고). 옛 비밀번호 금고가 잠겨 있으면 비밀이 필요한 동작이 잠금 해제 창을 띄운다. */
  async function renderVault() { /* 보여 줄 금고 상태가 없다 — 자리만 남긴다(언어 전환·refresh 호출 호환) */ }
  /** 결과 카드를 비운다(언어 전환 때 다시 그려지지 않게 인자도 지운다). */
  const clearVerdict = (el) => { el.__verdictArgs = null; el.className = ''; el.textContent = ''; };

  // ---- passkey-web: 설정 카드·패스키 줄·계정 복구 카드 ----
  /** 연결이 없으면 설정 카드, 있으면 보관 상태의 패스키 줄(credential ID 앞부분·보관 남은 분). 연결 끊기는 등록이 없을 때만. */
  function renderPasskey() {
    if (!PK) return;
    const cid = pkState?.credentialId ?? null;
    $('pkSetupCard').hidden = Boolean(cid);
    $('pkPanel').hidden = !cid;
    if (cid) {
      const left = Number.isFinite(pkState.heldUntil) ? pkState.heldUntil - Date.now() : 0;
      const held = left > 0 ? tt('user_pk_held', { min: Math.ceil(left / 60_000) }) : tt('user_pk_not_held');
      $('pkInfo').textContent = [tt('user_pk_credential', { id: `${cid.slice(0, 12)}…` }) || `${cid.slice(0, 12)}…`, held].filter(Boolean).join(' · ');
      const registered = Boolean(lastStatus?.registered);
      $('pkDisconnectBtn').disabled = registered;
      $('pkDisconnectHint').hidden = !registered;
    }
    renderRecover();
  }
  const RECOVER_DEFAULTS = { birthYear: '1990', country: 'KR' };   // 코어 기본값(DEFAULT_PROFILE)과 같다 — 사용자가 고친다(zk 스냅 화면과 같다)
  let recoverDrawn = false;
  /** 계정 복구 카드(스펙 W6): 연결 있음 ∧ 상태를 읽었고 미등록. 속성 칸은 처음 한 번만 그린다(입력 중인 값을 지우지 않게). */
  function renderRecover() {
    const show = PK && Boolean(pkState?.credentialId) && Boolean(lastStatus) && !lastStatus.registered;
    $('pkRecoverCard').hidden = !show;
    if (!show || recoverDrawn || !attrSchema) return;
    recoverDrawn = true;
    const dl = $('pkRecoverAttrs'); dl.replaceChildren();
    attrSchema.slots.forEach((slot) => {
      if (slot.type === 'unused' || isSpareSlot(slot)) return;
      const dt = document.createElement('dt'); dt.textContent = slot.label ?? slot.name;
      let input;
      if (slot.type === 'enum') {
        input = document.createElement('select');
        for (const name of Object.keys(slot.values)) { const o = document.createElement('option'); o.value = name; o.textContent = name; input.appendChild(o); }
      } else { input = document.createElement('input'); input.size = slot.type === 'int' ? 6 : 10; }
      input.dataset.slot = slot.name;
      if (RECOVER_DEFAULTS[slot.name] !== undefined) input.value = RECOVER_DEFAULTS[slot.name];
      const dd = document.createElement('dd'); dd.appendChild(input);
      dl.append(dt, dd);
    });
  }
  /** 복구 카드의 { 슬롯 이름: 값 } — 예비 슬롯은 빈 값(readProfileForm 과 같은 모양). */
  function readRecoverProfile() {
    const out = {};
    for (const slot of attrSchema?.slots ?? []) if (slot.type !== 'unused') out[slot.name] = '';
    for (const el of document.querySelectorAll('#pkRecoverAttrs [data-slot]')) out[el.dataset.slot] = el.value.trim();
    return out;
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
    if (PK) { try { const r = await core.passkeyState(); pkState = r.status === 200 ? r.body : null; } catch { pkState = null; } }
    await loadProofs(); syncOpenProof();
    renderIdentity();
    renderSessions();
    renderTxs();
    renderProofs();
    renderPasskey();
    renderGuide();
    await renderVault();
    await postPresence(core);
  }
  // 언어·전문가 전환은 사전이 채우는 요소와 결과 카드만 바꾼다(Demo) — 스크립트가 만든 텍스트는 여기서 다시 그린다.
  for (const k of ['setLang', 'setExpert']) {
    const orig = Demo[k];
    Demo[k] = (v) => { orig(v); renderModeTexts(); renderProofInfo(); renderZk(); renderIdentity(); renderSessions(); renderTxs(); renderProofs(); renderProofModal(); renderPasskey(); renderVault(); };
  }

  // V8 세션 폐기(설계 2026-09-24 §4): 인증 증명은 코어가 금고의 s_u 로 만든다(잠겨 있으면 잠금 해제 창).
  async function revokeSession(r_s, c, btn) {
    if (btn.dataset.busy === '1') return;   // 처리 중 재클릭만 무시(버튼은 비활성화하지 않는다, 2026-10-16)
    if (!Demo.confirmDanger('confirm_revoke')) return;
    const out = (m) => { $('sessionLog').textContent = m; };
    btn.dataset.busy = '1';
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
    } finally { delete btn.dataset.busy; refresh(); }
  }
  $('refreshBtn').addEventListener('click', () => refresh(true));

  // 폼을 하나도 안 건드렸으면(전부 빈 값) profile 을 보내지 않는다 — 코어의 DEFAULT_PROFILE(데모 기본값)이 적용된다.
  const typedProfile = () => { const f = readProfileForm(); return Object.values(f).some((v) => v !== '') ? f : null; };
  /** 등록 결과 카드(두 경로 공통). 성공(201)이면 true. */
  function showRegisterResult({ status, body: b }) {
    if (status !== 201) {
      setVerdict($('registerResult'), false, 'wallet_register_failed', () => ({ reason: b.reason ?? `HTTP ${status}`, detail: safeDetail(b) }));
      return false;
    }
    // 카드에 쓸 값은 여기서 먼저 꺼내 둔다 — 인자 생성기가 응답 본문을 붙잡지 않게(wallet.html 과 같은 규칙).
    const uid = b.uid;
    const detail = safeDetail(b);
    profileDirty = false;
    setVerdict($('registerResult'), true, 'registered', () => ({ summary: tt('wallet_registered_summary', { uid, attrs: profileText(b.profile) }) || `uid ${uid} · ${profileText(b.profile)}`, detail }));
    return true;
  }

  // 등록: 폼의 uid·pwd(IdP 계정). s_u 는 코어가 만들어 금고에만 넣는다 — 금고 비밀번호는 없다(자동 금고, 2026-10-16).
  // IdP 비밀번호는 IdP 로 한 번 지날 뿐이다.
  $('registerBtn').addEventListener('click', async () => {
    pendingVerdict($('registerResult'), 'working');
    try {
      const req = { uid: $('uid').value.trim(), pwd: $('pwd').value, profile: typedProfile(), vaultPassword: null };
      const res = await withUnlock(() => core.register(req));
      req.pwd = null;
      showRegisterResult(res);
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
    txLog(`${extra}PPID 계정=${b.wallet}  nonce=${b.nonce}  ok(실행 성공)=${b.ok}  gasUsed=${b.gasUsed}\n공개=${JSON.stringify(b.disclosure)}\n온체인 공개(Disclosure 이벤트)=${JSON.stringify(b.onchainDisclosure)}\n실행=${JSON.stringify(b.executed)}`);
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
    txLog(`PPID 계정 주소=${b.walletAddr}  nonce=${b.nonce}  배포 필요=${b.deployNeeded}  캐시 히트=${b.cacheHit}  root=${b.root}\ntimings=${JSON.stringify(b.timings)}`);
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
    if ($('txBtn').dataset.busy === '1') return;   // 처리 중 재클릭만 무시(2026-10-16)
    $('txBtn').dataset.busy = '1'; $('txLog').textContent = '';
    pendingVerdict($('txVerdict'), 'proving');
    try { await sendTxViaRelay(); }
    catch (e) {
      txLog(`오류: ${e.message}`);
      txFailed(null, e?.reason ?? 'internal', e.message);
    } finally { delete $('txBtn').dataset.busy; refresh(); }
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
  // 복구 코드(2026-10-21): 보기(모달에 코드·복사 버튼)와 복구(uid + 코드 → core.recover). 코드는 모달을 닫으면 화면에서 지운다.
  $('recoveryCodeBtn').addEventListener('click', async () => {
    try {
      const r = await core.recoveryCode();
      if (r.status !== 200) { setVerdict(storageVerdict(), false, 'user_recovery_code_title', { reason: r.body.reason ?? `HTTP ${r.status}`, detail: safeDetail(r.body) }); return; }
      $('recoveryCodeText').textContent = r.body.code; $('recoveryCodeModal').hidden = false;
    } catch (e) { setVerdict(storageVerdict(), false, 'user_recovery_code_title', { reason: 'internal', detail: e.message }); }
  });
  $('recoveryCodeClose').addEventListener('click', () => { $('recoveryCodeModal').hidden = true; $('recoveryCodeText').textContent = ''; });
  $('recoveryCodeCopy').addEventListener('click', () => copyText($('recoveryCodeText').textContent, $('recoveryCodeCopy')));
  $('recoverBtn').addEventListener('click', () => { $('recoverUid').value = ''; $('recoverCode').value = ''; $('recoverModal').hidden = false; $('recoverUid').focus(); });
  $('recoverCancel').addEventListener('click', () => { $('recoverModal').hidden = true; });
  $('recoverGo').addEventListener('click', async () => {
    const uid = $('recoverUid').value.trim(), code = $('recoverCode').value.trim();
    if (!uid || !code) return;
    $('recoverModal').hidden = true; $('recoverCode').value = '';
    pendingVerdict(storageVerdict(), 'working');
    try {
      const r = await core.recover({ uid, code });
      if (r.status === 200) setVerdict(storageVerdict(), true, 'user_recover_ok_title', () => ({ summary: tt('user_recover_ok', { uid: r.body.uid, slot: r.body.slot }) || `복구됨 — uid ${r.body.uid}, 등록부 슬롯 #${r.body.slot}. 같은 주소로 로그인할 수 있습니다.` }));
      else setVerdict(storageVerdict(), false, 'user_recover_failed', { reason: r.body.reason ?? `HTTP ${r.status}`, detail: safeDetail(r.body) });
    } catch (e) { setVerdict(storageVerdict(), false, 'user_recover_failed', { reason: 'internal', detail: e.message }); }
    refresh(true);
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

  // ---- passkey-web 동작: 패스키 연결(만들기·이미 있는 것)·salt 보기·연결 끊기·계정 복구 ----
  /** get() → { credentialId, s_u }(passkey_store — PRF 로 만든 salt). 코어가 금고를 만들고 credential 을 두고 salt 를 10분 보관한다. s_u 는 코어에만 넘긴다. */
  async function linkPasskey(get) {
    if (!pkOriginOk) return;
    const btns = [$('pkNewBtn'), $('pkExistingBtn')];
    if (btns.some((b) => b.dataset.busy === '1')) return;   // 패스키 창이 떠 있는 동안의 재클릭만 무시
    btns.forEach((b) => { b.dataset.busy = '1'; });
    pendingVerdict($('pkSetupVerdict'), 'working');
    try {
      const { credentialId, s_u } = await get();
      const r = await core.passkeyConnect({ credentialId, s_u });
      if (r.status === 200) setVerdict($('pkSetupVerdict'), true, 'user_pk_connected');
      else setVerdict($('pkSetupVerdict'), false, 'wallet_setup_passkey_failed', { reason: r.body?.reason ?? `HTTP ${r.status}` });
    } catch (e) {
      // 브라우저(WebAuthn) 오류는 passkey_store 가 이미 사유를 붙인다 — 사유 없는 오류는 예상하지 못한 것이다(passkey_unsupported 로 뭉뚱그리지 않는다).
      setVerdict($('pkSetupVerdict'), false, 'wallet_setup_passkey_failed', { reason: e?.reason ?? 'internal', detail: e?.message });
    } finally { btns.forEach((b) => { delete b.dataset.busy; }); refresh(); }
  }
  if (PK) {
    $('pkNewBtn').addEventListener('click', () => linkPasskey(() => passkey.create()));
    $('pkExistingBtn').addEventListener('click', () => linkPasskey(() => passkey.derive({})));
    // salt 보기(스펙 §2 4단계): 보관분 또는 패스키. 창에만 보이고 닫으면 지운다 — 저장·전송하지 않는다.
    $('pkShowSaltBtn').addEventListener('click', async () => {
      clearVerdict(storageVerdict());
      try {
        const r = await core.showSalt();
        if (r.status !== 200) { setVerdict(storageVerdict(), false, 'wallet_passkey_salt_failed', { reason: r.body?.reason ?? `HTTP ${r.status}` }); return; }
        $('pkSaltText').textContent = r.body.s_u; $('pkSaltModal').hidden = false;
      } catch (e) { setVerdict(storageVerdict(), false, 'wallet_passkey_salt_failed', { reason: e?.reason ?? 'internal', detail: e?.message }); }
      finally { refresh(); }   // 패스키로 새로 받았으면 보관 남은 시간이 바뀐다
    });
    $('pkSaltClose').addEventListener('click', () => { $('pkSaltModal').hidden = true; $('pkSaltText').textContent = ''; });
    $('pkSaltCopy').addEventListener('click', () => copyText($('pkSaltText').textContent, $('pkSaltCopy')));
    $('pkDisconnectBtn').addEventListener('click', async () => {
      if ($('pkDisconnectBtn').disabled) return;
      clearVerdict(storageVerdict());
      try {
        const r = await core.passkeyDisconnect();
        if (r.status !== 200) setVerdict(storageVerdict(), false, 'wallet_passkey_disconnect_failed', { reason: r.body?.reason ?? `HTTP ${r.status}` });
        else clearVerdict($('pkSetupVerdict'));   // "연결했습니다" 가 다시 뜬 설정 카드 옆에 남지 않게
      } catch (e) { setVerdict(storageVerdict(), false, 'wallet_passkey_disconnect_failed', { reason: e?.reason ?? 'internal', detail: e?.message }); }
      finally { refresh(); }
    });
    // 계정 복구(스펙 W6): auid 보기(인증 창에 넣는 값 — salt 는 코어 밖으로 나오지 않는다) → 인증 창(등록 모드). 돌아오면 /?authorize=1 의
    // runPopup 이 mode3-recover 를 보고 finishRecover(등록 코드로 등록 → 결과를 sessionStorage 에 남기고 '/')로 이어 간다. 대기 저장분에 salt 는 없다.
    $('pkRecoverAuidBtn').addEventListener('click', async () => {
      clearVerdict($('pkRecoverVerdict')); $('pkRecoverAuid').textContent = '';
      try {
        const r = await core.passkeyAuid();
        if (r.status !== 200) { setVerdict($('pkRecoverVerdict'), false, 'user_pk_recover_failed', { reason: r.body?.reason ?? `HTTP ${r.status}` }); return; }
        $('pkRecoverAuid').textContent = r.body.auid;
      } catch (e) { setVerdict($('pkRecoverVerdict'), false, 'user_pk_recover_failed', { reason: e?.reason ?? 'internal', detail: e?.message }); }
      finally { refresh(); }
    });
    $('pkRecoverGoBtn').addEventListener('click', () => {
      clearVerdict($('pkRecoverVerdict'));
      const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
      savePending(window.sessionStorage, { req: { type: 'mode3-recover', profile: readRecoverProfile() }, origin: location.origin, nonce, at: Date.now(), purpose: 'register' });
      location.assign(idpAuthUrl({ ciaUrl: cfg.ciaUrl, walletOrigin: location.origin, nonce, purpose: 'register' }));
    });
  }
  /** 복구 귀로(popup.js finishRecover)가 남긴 결과를 한 번 보이고 지운다. */
  function showRecoverResult() {
    let r = null;
    try { r = JSON.parse(sessionStorage.getItem(RECOVER_RESULT_KEY) ?? 'null'); sessionStorage.removeItem(RECOVER_RESULT_KEY); } catch { r = null; }
    if (!r) return;
    if (r.ok) setVerdict($('pkRecoverVerdict'), true, r.restored ? 'user_pk_recover_done_restored' : 'user_pk_recover_done_new');
    else setVerdict($('pkRecoverVerdict'), false, 'user_pk_recover_failed', { reason: r.reason ?? 'internal', ...(r.detail ? { detail: r.detail } : {}) });
  }
  /** passkey-web 화면 준비(한 번): 등록 폼·속성 저장·복구 코드 버튼을 숨기고 속성 칸을 읽기 전용으로, 속성 도구 링크를 보인다. 오리진이 맞지 않으면 두 버튼을 끄고 안내한다. */
  function preparePasskeyUi() {
    for (const id of ['registerBtn', 'profileSaveBtn', 'recoveryCodeBtn', 'recoverBtn']) $(id).hidden = true;
    $('fileRegFields').hidden = true;
    const link = $('pkAttrLink'); link.href = `${location.origin}/attr.html`; link.textContent = link.href;
    $('pkAttrNote').hidden = false;
    lockAttrInputs();   // 스키마가 없으면 index.html 의 기본 칸 그대로 — 스키마로 다시 그리면 renderAttrsForm 이 다시 잠근다
    if (!pkOriginOk) {
      $('pkNewBtn').disabled = true; $('pkExistingBtn').disabled = true;
      const a = $('pkOriginLink'); a.href = `${cfg.walletOrigin}/`; a.textContent = a.href;
      $('pkOriginRow').hidden = false;
      setVerdict($('pkSetupVerdict'), false, 'user_pk_setup_title', { reason: 'passkey_wrong_origin' });
    }
    showRecoverResult();
  }

  async function init() {
    // 체험 모드의 잠금(설계 §3.3). #registerBtn 은 지금까지 늘 활성이었다 — 그 규칙을 otherwise 로 그대로 옮긴다.
    Demo.tour?.lock({ id: 'registerBtn', cond: 'rp_approved', otherwise: () => true });
    Demo.tour?.onToggle(renderGuide);
    if (PK) preparePasskeyUi();
    renderModeTexts();
    renderProofInfo();
    renderZk();
    await loadAttrSchema();
    await refresh();
    // 데모 세대가 바뀌어 user.js 가 옛 등록·세션을 지웠으면(2026-10-21) 그 사실을 저장소 카드에 알린다.
    if (demoReset) setVerdict(storageVerdict(), true, 'user_demo_reset_title', () => ({ summary: tt('user_demo_reset') || '데모 스택이 새로 시작되어 이 브라우저의 이전 등록·세션을 지웠습니다. 다시 등록하세요.' }));
    // 등록부 확인 줄(V9 §8.2)은 다른 창(RP 로그인·승인 창·관리자)이 바꾼 상태를 반영해야 한다 — 탭이 보일 때 5초마다 다시 읽는다.
    // 2026-10-16: 5초 → 2초(사용자 요청). 앞 새로고침이 끝나기 전에는 다시 시작하지 않는다(체인·RP 응답이 느릴 때 겹치지 않게).
    let refreshing = false;
    setInterval(() => { if (document.hidden || refreshing) return; refreshing = true; refresh().finally(() => { refreshing = false; }); }, 2000);
    // 증명 키는 등록 전에도 받아 둔다(첫 로그인이 빨라진다). Cache API 에 있으면 진행률 없이 바로 준비된다.
    prover.warm().then(() => { zk = { kind: 'ready' }; renderZk(); }, (e) => { zk = { kind: 'fail', detail: e.message }; renderZk(); });
  }
  return init();
}
