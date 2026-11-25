// mode3/common/flow_page.js — "전체 플로우" 한 장(mode3/common/flow.html, 2026-11-20)의 페이지 스크립트. 의존 없음(지갑 오리진 CSP 아래에서 돈다 — 인라인 스크립트가 없다).
//   · 아랫줄(zk-Delegation)에 이 브라우저의 가장 최근 "zkIdP 로 로그인" 의 공개값을 채운다 — 지갑이 IndexedDB(mode3-user 의 kv 'loginFlow')에 남긴 기록을 **읽기만** 한다.
//     그 기록에는 비밀(salt·세션키)이 없다. 저장소가 아직 없으면 만들지 않는다(지갑이 자기 판으로 만들어야 한다 — 아래 readFlow).
//   · 서비스 오리진에서 열면(2026-11-25 스펙 service-flow-figure, zkWrapper 만) 지갑 기록 대신 /api/rp/me 의 seen(서비스가 실제로 받은 값)으로 지금 로그인한 방식의 줄만 채운다. 어디에도 저장하지 않는다.
//   · 줄마다 "처음부터 / 이전 / 다음 / 전체 보기" 로 화살표를 하나씩 켠다(발표용). 화살표를 누르면 그 단계의 설명과(아랫줄은) 세부 단계별 걸린 시간이 펴진다.
(() => {
  const $ = (id) => document.getElementById(id);
  const head = (v) => { const s = String(v ?? ''); return s.length > 17 ? `${s.slice(0, 17)}…` : s; };
  const head6 = (v) => { const s = String(v ?? ''); return s.length > 6 ? `${s.slice(0, 6)}…` : s; };   // 아랫줄 ③ 의 두 가명 — 17자면 두 세로선 밖으로 넘친다(2026-11-25). 전체는 title
  const fmtMs = (ms) => (!Number.isFinite(ms) ? '-' : ms < 0.01 ? '<0.01ms' : ms < 1000 ? `${Math.round(ms * 100) / 100}ms` : `${(ms / 1000).toFixed(2)}s`);

  /** 지갑의 가장 최근 로그인 기록(없으면 null). 저장소가 없을 때 open 이 빈 저장소를 만들어 버리면 지갑이 자기 판(kv 저장 칸)을 못 만든다 —
   *  만들어지려는 순간(onupgradeneeded) 그 거래를 취소해 아무것도 남기지 않는다. */
  const readFlow = () => new Promise((resolve) => {
    let created = false, req;
    try { req = indexedDB.open('mode3-user'); } catch { return resolve(null); }
    req.onupgradeneeded = () => { created = true; try { req.transaction.abort(); } catch { /* 이미 끝났다 */ } };
    req.onerror = () => resolve(null);
    req.onblocked = () => resolve(null);
    req.onsuccess = () => {
      const db = req.result;
      if (created || !db.objectStoreNames.contains('kv')) { db.close(); return resolve(null); }
      try {
        const q = db.transaction('kv').objectStore('kv').get('loginFlow');
        q.onsuccess = () => { db.close(); resolve(q.result ?? null); };
        q.onerror = () => { db.close(); resolve(null); };
      } catch { db.close(); resolve(null); }
    };
  });

  // ---- 단계 설명. zk 의 fine = 지갑 기록의 세부 단계 키(steps[].key) → 화면 이름 ----
  const FINE = {
    check_service: '서비스 확인 (인증서 · 팩토리)', passkey: '패스키로 salt 다시 만들기', sync: '체인 읽기 (등록부 · 폐기 목록)', random: '난수 뽑기',
    session_key: '임시 키 쌍 만들기 (pk_i)', issue: '가명 · 커밋먼트 · π_IdP 를 만들어 발급 요청 → zkIdP 의 서명', publish_wait: '등록부 게시 기다리기 (처음 등록한 로그인만)',
    prove_session: '영지식 증명 π_RP 만들기', sign: '세션키로 서명',
  };
  const STEPS = {
    oidc: [
      { title: '① 로그인 요청', body: '서비스가 브라우저를 Google 로 보냅니다. 요청에는 서비스의 식별자(client_id = rid)가 그대로 들어 있어, Google 은 이 사람이 어느 서비스에 로그인하려는지 압니다.' },
      { title: '② Google 계정으로 본인 확인', body: '사용자가 Google 에 로그인합니다. Google 은 누구인지(uid) 확인합니다.' },
      { title: '③ ID 토큰', body: 'Google 이 서명한 ID 토큰이 서비스로 갑니다. iss(누가 냈나) · sub(누구인가 = uid) · aud(어느 서비스용인가 = rid)가 그대로 적혀 있습니다. 같은 사람이 다른 서비스에 로그인해도 sub 는 같은 값입니다.' },
    ],
    zk: [
      { title: '① 로그인 요청', body: '서비스가 zk 클라이언트(사용자의 브라우저)에 자기 인증서와 1회용 난수를 보냅니다. zk 클라이언트는 인증서가 zkIdP 가 승인한 서비스의 것인지 확인합니다.', fine: ['check_service'] },
      { title: '② 패스키 → salt', body: '패스키가 내주는 값으로 salt 를 다시 만듭니다. 같은 패스키면 늘 같은 값이고 어디에도 저장하지 않습니다. salt 는 모든 가명의 뿌리이며 밖으로 나가지 않습니다.', fine: ['passkey'] },
      { title: '③ 가명 + 증명 π_IdP', body: 'zkIdP 에는 이번 로그인에만 쓰는 가명 둘(auid_s = 사용자, arid_s = 서비스)과, "이 계정의 salt 를 안다" 는 영지식 증명 π_IdP 를 보냅니다. arid_s 는 로그인마다 달라 zkIdP 는 어느 서비스인지 알 수 없습니다.', fine: ['sync', 'random', 'session_key', 'issue'] },
      { title: '④ 서명한 자격증명', body: 'zkIdP 가 증명을 확인하고 가명에 서명해 돌려줍니다. 서명하는 값은 auid_s · arid_s · Cf_u · Cf_s 와 chainid · allowAgent 입니다. 서비스는 가명 arid_s(= Poseidon(arid, r_rp))로만 들어가 zkIdP 는 로그인 때 어느 서비스인지 모릅니다 — r_rp 는 서비스가 만든 1회용 난수로, 서비스와 사용자의 브라우저만 압니다. 처음 등록한 로그인이면 등록부를 체인에 게시합니다.', fine: ['publish_wait'] },
      { title: '⑤ PPID + 증명 π_RP', body: '서비스에는 이 서비스에서만 쓰는 주소 PPID 와, "이 PPID 가 zkIdP 가 서명한 자격증명에서 나왔고 폐기되지 않았다" 는 영지식 증명 π_RP 를 보냅니다. zkIdP 를 거치지 않으므로 zkIdP 는 이 전달을 보지 못합니다.', fine: ['prove_session', 'sign'] },
      { title: '⑥ 검증', body: '서비스가 증명을 검증하고, 증명의 공개 입력이 체인의 최신 등록부 · 폐기 목록과 자기 식별자에 맞는지 확인합니다. uid 나 속성 값은 받지 않습니다.' },
    ],
  };

  // ---- zkWrapper(2026-11-20 스펙 zkwrapper §6): 별도 IdP 가 없다 — ③ 에는 π_IdP 대신 Google 토큰이, 발급자 자리에는 zkWrapper 가 있다 ----
  // 같은 오리진의 /user/config 가 wrapper 를 말할 때만 바꾼다(zkWrapper 서버·래퍼 방식의 지갑 서버). 설정이 없으면(다른 서버) 그대로다.
  let WRAP = false, SVC = null;   // SVC: 서비스 오리진이면 그 서비스의 rp_info(이름·walletKind), 아니면 null
  // 2026-11-24(스펙 home-and-account-recovery T1): 래퍼에서는 계산하는 주체를 "브라우저", 로그인을 "zkWrapper 로 로그인" 이라 부른다(strings.js wrapperText 와 같은 규칙)
  const W = (s) => (WRAP && typeof s === 'string' ? s.replace(/zk-?IdP/g, 'zkWrapper').replace(/zk 클라이언트\(사용자의 브라우저\)/g, '사용자의 브라우저').replace(/zk 클라이언트(?: 홈| 화면)/g, 'zkWrapper 홈')
    .replace(/zk 클라이언트/g, '브라우저').replace(/zk 로그인/g, 'zkWrapper 로 로그인') : s);
  const WRAP_STEPS = {
    2: { title: '② Google 계정 → 패스키 → salt', body: '서비스가 연 창이 Google 로 가서 계정을 고르고 돌아옵니다(본인 확인은 Google 이 합니다). 그다음 패스키가 내주는 값으로 salt 를 다시 만듭니다. 같은 패스키면 늘 같은 값이고 어디에도 저장하지 않습니다.', fine: ['google', 'passkey'] },
    3: { title: '③ 가명 + Google 토큰', body: 'zkWrapper 에는 이번 로그인에만 쓰는 가명 둘(auid_s = 사용자, arid_s = 서비스)과 Google ID 토큰을 보냅니다. 토큰은 이 요청 하나에 묶여 있어(1회용 요청 키의 서명) 다른 요청에 쓸 수 없습니다. 가명이 제대로 만들어졌는지는 ⑤ 의 증명 π_RP 가 서비스에 증명합니다. arid_s 는 로그인마다 달라 zkWrapper 는 어느 서비스인지 알 수 없습니다.', fine: ['sync', 'session_key', 'commit', 'pseudonym', 'issue'] },   // 2026-11-24: 코어가 재는 커밋먼트·가명 시간도 보인다
    4: { title: '④ 세션 토큰(서명한 자격증명)', body: 'zkWrapper 가 Google 토큰과 요청 서명을 확인하고 가명에 서명해 돌려줍니다. 서명하는 값은 auid_s · arid_s · Cf_u · Cf_s 와 chainid · allowAgent 입니다. 서비스는 가명 arid_s(= Poseidon(arid, r_rp))로만 들어가 zkWrapper 는 로그인 때 어느 서비스인지 모릅니다 — r_rp 는 서비스가 만든 1회용 난수로, 서비스와 사용자의 브라우저만 압니다. 처음 로그인이면 등록부를 체인에 게시합니다.', fine: ['publish_wait'] },
  };
  const getJson = async (url) => { try { const r = await fetch(url, { cache: 'no-store' }); return { status: r.status, body: r.ok ? await r.json() : null }; } catch { return { status: 0, body: null }; } };
  async function detectWrapper() {
    const cfg = (await getJson('/user/config')).body;
    if (cfg) WRAP = cfg.wrapper === true;
    else {
      // 지갑 설정이 없을 때만 서비스인지 본다 — "없으니 서비스" 로 넘겨짚지 않고 rp_info 가 실제로 답해야 한다(/mode3/health 는 부를 때마다 체인을 읽어 쓰지 않는다)
      const info = (await getJson('/api/mode3/rp_info')).body;
      if (info?.walletKind === 'zkwrapper') { SVC = info; WRAP = true; }
    }
    if (!WRAP) return;
    for (const [n, st] of Object.entries(WRAP_STEPS)) STEPS.zk[Number(n) - 1] = st;
    FINE.issue = '가명 · 커밋먼트 + Google 토큰으로 발급 요청 → zkWrapper 의 서명'; FINE.google = 'Google 에서 계정 고르기 (다녀온 시간)';
    FINE.commit = '커밋먼트 C_u · C_s 만들기'; FINE.pseudonym = '가명 auid_s · arid_s 만들기';
    FINE.passkey_wait = '패스키 확인 — 사용자 대기 (인증기 창 · 지문 · PIN)'; FINE.passkey_calc = 'salt 계산 (PRF 출력 → SHA-256)';
    // ④ 화살표 이름을 펼친 설명의 제목과 맞춘다(2026-11-24)
    const lbl4 = document.querySelector('#seqZk .st[data-step="4"] .lbl'); if (lbl4?.firstChild) lbl4.firstChild.textContent = '④ 세션 토큰(서명한 자격증명) ';
    const pi = $('zkProofIdp'); if (pi) pi.textContent = 'Google 토큰';
    const lbl2 = document.querySelector('#seqZk .st[data-step="2"] .lbl'); if (lbl2?.firstChild) lbl2.firstChild.textContent = '② Google 계정 · 패스키 → salt ';
    // 화면의 나머지 글자(제목·열 이름·"알게 되는 것"·발주)에서 zkIdP 를 zkWrapper 로
    const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = walk.nextNode(); n; n = walk.nextNode()) if (/zk-?IdP|zk 클라이언트|zk 로그인/.test(n.nodeValue)) n.nodeValue = W(n.nodeValue);
    const hn = $('hdrNote'); if (hn) hn.textContent = SVC ? `서비스 ${SVC.name ?? ''}` : 'zkWrapper';   // 머리말의 앱 이름
    document.title = W(document.title);
    // 사실 맞추기(2026-11-25): 래퍼는 Google 의 sub·이메일을 받고 uid 는 sub 의 해시다(윗줄의 uid 와 값이 다르다). "어느 서비스인지 모른다" 는 로그인 때의 이야기다 —
    // 온체인 거래의 공개 입력에는 arid·PPID·auid_s 가 함께 있다(스펙 2026-11-19 trace-without-tag §3).
    const B = (t) => Object.assign(document.createElement('b'), { textContent: t });
    $('kIdpWho')?.replaceChildren('누가 로그인했는지 — Google 의 ', B('sub 와 이메일'), '을 받는다 (uid', $('zkUid'), ' — sub 의 해시라 윗줄의 uid 와 다른 값)');
    $('kIdpSvc')?.replaceChildren('로그인 때는 ', B('어느 서비스'), '인지 모른다 — arid_s 는 로그인마다 다르다 (온체인 거래를 하면 공개 입력으로 이어질 수 있다)');
    $('footOpen')?.append(' 다만 온체인 거래를 하면 공개 입력에 서비스 · PPID · auid_s 가 함께 남아 zkWrapper 가 두 기록을 이을 수 있습니다.');
    $('zkHint').textContent = SVC ? '화살표를 누르면 설명이 펴집니다' : '화살표를 누르면 그 단계의 세부와 걸린 시간이 펴집니다 — ③ Google 토큰 · ④ 세션 토큰은 실제 값도 보입니다';
    if (!SVC) { const a = $('flowCardLink'); if (a) { a.href = '/user#flowCard'; a.textContent = '내 세션 관리(/user)의 "로그인 전체 플로우" 카드'; } return; }   // 그 카드는 홈이 아니라 /user 에 있다(2026-11-24)
    // 서비스 오리진의 글자
    $('zkSaltNote').textContent = '(이 서비스는 모름)';
    STEPS.zk[2] = { ...STEPS.zk[2], body: `${STEPS.zk[2].body} 서비스는 이 구간을 보지 못합니다 — 여기 적힌 auid_s · arid_s 는 서비스가 ⑤ 로 받은 같은 값입니다.` };
    const w2 = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = w2.nextNode(); n; n = w2.nextNode()) if (/zkTWO (도|의)/.test(n.nodeValue)) n.nodeValue = n.nodeValue.replace(/zkTWO (도|의)/g, '다른 서비스$1');   // zkTWO 에서 열면 자기 이름이라 틀린다
    $('mockNote').textContent = '지금 로그인한 방식의 줄만 이 서비스가 실제로 받은 값으로 채웁니다(앞부분만 — 전체는 마우스를 올리면 보입니다). 다른 줄은 값의 이름만 보입니다. 이 그림은 값을 저장하지 않습니다. 단계별 걸린 시간은 사용자의 브라우저만 압니다.';
  }

  let flow = null, seen = null;   // seen: 서비스 오리진에서만 — /api/rp/me 의 seen
  // ---- 값 채우기(아랫줄) ----
  function fill() {
    const zkSeen = seen?.protocol === 'zk' ? seen : null, gSeen = seen?.protocol === 'oidc' && seen.issuer === 'google' ? seen : null;
    const v = SVC ? zkSeen : flow?.values ?? null;
    const set = (id, text, title) => { const e = $(id); if (!e) return; e.textContent = text; const t = e.querySelector?.('title'); if (t) t.remove(); if (title) { const tt = document.createElementNS('http://www.w3.org/2000/svg', 'title'); tt.textContent = title; e.appendChild(tt); } };
    set('zkAuidS', v?.auid_s ? `auid_s ${head6(v.auid_s)}` : 'auid_s', v?.auid_s ?? null);
    set('zkAridS', v?.arid_s ? `arid_s ${head6(v.arid_s)}` : 'arid_s', v?.arid_s ?? null);
    set('zkPpid', v?.PPID ? head(v.PPID) : '', v?.PPID ?? null);
    if (SVC) {
      set('oidcClientId', gSeen?.rid ? `client_id ${head(gSeen.rid)}` : '', gSeen?.rid ?? null);
      set('oidcSub', gSeen?.uid ? `sub ${head(gSeen.uid)}` : '', gSeen?.uid ?? null);
      set('oidcAud', gSeen?.rid ? ` · aud ${head(gSeen.rid)}` : '', gSeen?.rid ?? null);
      for (const id of ['zkSvcName', 'oidcSvcName']) $(id).textContent = `서비스 ${SVC.name ?? ''}`;
      $('zkUid').textContent = ' = 이 서비스는 모름';
      const ro = $('recentOidc'); ro.hidden = false;
      ro.textContent = gSeen ? '지금 이 서비스에 Google 로 로그인한 상태입니다 — 아래 client_id · sub · aud 는 이 서비스가 받은 ID 토큰의 실제 값입니다.' : '지금은 이 서비스에 Google 로 로그인한 상태가 아닙니다 — 이 줄은 값의 이름만 보입니다.';
      $('recent').textContent = zkSeen ? '지금 이 서비스에 zkWrapper 로 로그인한 상태입니다 — 아래 값은 이 서비스가 실제로 받은 값입니다. auid_s · arid_s 는 로그인마다 다르고, PPID 는 이 서비스에서 늘 같습니다.' : '지금은 이 서비스에 zkWrapper 로 로그인한 상태가 아닙니다 — 이 줄은 값의 이름만 보입니다.';
      return;
    }
    for (const id of ['zkSvcName', 'oidcSvcName']) $(id).textContent = flow?.serviceName ? `서비스 ${flow.serviceName}` : '서비스';   // 윗줄도 같은 서비스 이름으로(같은 서비스에 두 방식으로 로그인하는 그림이다)
    // 래퍼 방식의 uid 는 해시라 길다(2026-11-24) — 다른 값처럼 앞부분만, 전체는 title
    const zu = $('zkUid'); zu.textContent = v?.uid ? ` = ${WRAP ? head(v.uid) : v.uid}` : ''; if (WRAP) zu.title = v?.uid ?? '';
    const r = $('recent');
    if (!flow) { r.textContent = WRAP ? '아직 이 브라우저에서 "zkWrapper 로 로그인" 을 한 적이 없습니다 — 그림에는 값의 이름만 보입니다. 서비스에서 로그인하면 실제 값이 채워집니다.' : '아직 이 브라우저에서 "zkIdP 로 로그인" 을 한 적이 없습니다 — 그림에는 값의 이름만 보입니다. 서비스에서 로그인하면 실제 값이 채워집니다.'; return; }
    const at = new Date(flow.at);
    r.replaceChildren('가장 최근 로그인: ', Object.assign(document.createElement('b'), { textContent: flow.serviceName ?? flow.origin ?? '-' }), ` · ${at.toLocaleTimeString()} · 전체 ${fmtMs(flow.totalMs)} — 아래 값은 그 로그인의 실제 값입니다.`);
  }

  // ---- 토큰 내용(래퍼 방식, 2026-11-25 사용자 요청): ③ Google 토큰 · ④ 세션 토큰을 누르면 그 로그인의 실제 본문을 보인다. 서명은 기록에 없다(지갑이 남기지 않는다) ----
  const CLAIM_NOTE = {
    google: { iss: '낸 곳', azp: '요청한 클라이언트', aud: 'zkWrapper 의 Google 클라이언트 ID — 서비스가 아니다', sub: 'Google 의 사용자 식별자', email: '사용자의 이메일', email_verified: 'Google 이 확인한 이메일인가', nonce: '이 요청의 1회용 키에 묶는 값', iat: '낸 시각', exp: '끝나는 시각' },
    session: { iss: '낸 곳', sub: '= auid_s (사용자의 가명 — 로그인마다 다르다)', aud: '= arid_s (서비스의 가명 — 로그인마다 다르다)', iat: '낸 시각', exp: '끝나는 시각' },
  };
  function tokenBox(d, title, note, rows) {
    const h = document.createElement('h5'); h.textContent = title; d.append(h);
    if (note) { const p = document.createElement('p'); p.style.color = '#5b6880'; p.textContent = note; d.append(p); }
    if (!rows) return;
    const tb = document.createElement('table'); tb.className = 'tok';
    for (const [k, value, why] of rows) {
      const tr = document.createElement('tr'), a = document.createElement('td'), b = document.createElement('td'), c = document.createElement('td'), code = document.createElement('code');
      a.textContent = k; code.textContent = value; code.dataset.claim = k; b.append(code); c.textContent = why ?? ''; c.style.color = '#5b6880'; tr.append(a, b, c); tb.append(tr);
    }
    d.append(tb);
  }
  const claimText = (k, x) => ((k === 'iat' || k === 'exp') && Number.isFinite(x) ? `${x} (${new Date(x * 1000).toLocaleString()})` : typeof x === 'string' ? x : JSON.stringify(x));
  const claimRows = (tok, kind) => [['alg', String(tok.header?.alg ?? '-'), '서명 방식'], ...Object.entries(tok.payload ?? {}).map(([k, x]) => [k, claimText(k, x), CLAIM_NOTE[kind][k]])];
  function renderTokens(d, step) {
    const v = flow?.values ?? null, tok = v?.tokens ?? null;
    const none = !flow ? '서비스에서 zkWrapper 로 로그인하면 여기에 그 로그인의 값이 보입니다.' : '이 로그인 기록에는 토큰 내용이 없습니다 — 다음 로그인부터 보입니다.';
    if (step === 3) {
      const t = tok?.google ?? null; d.dataset.token = 'google';
      tokenBox(d, 'Google ID 토큰 — 브라우저가 zkWrapper 에 보낸 것', t ? '서비스에는 가지 않습니다. 서명은 이 브라우저에 남기지 않아 본문만 보입니다.' : none, t ? claimRows(t, 'google') : null);
    } else if (step === 4) {
      const t = tok?.session ?? null; d.dataset.token = 'session';
      tokenBox(d, '세션 토큰 — zkWrapper 가 돌려준 ID 토큰(JWT)', t ? 'uid · 이메일이 없고, 서비스는 가명 arid_s 로만 들어 있습니다. ⑤ 에서 서비스에도 함께 갑니다. 서명은 남기지 않아 본문만 보입니다.' : none, t ? claimRows(t, 'session') : null);
      if (t) tokenBox(d, '함께 서명된 자격증명 (서명 σ 는 밖으로 내지 않고 ⑤ 의 증명 안에서만 씁니다)', null, [['auid_s', v.auid_s, '사용자 가명'], ['arid_s', v.arid_s, '서비스 가명'], ['C_u', v.Cf_u, 'uid · salt · 속성의 커밋먼트(난수로 가림)의 해시'],
        ['C_s', v.Cf_s, 'pk_i · max_height · 로그인 난수의 커밋먼트의 해시'], ['chainid', v.chainid, '체인'], ['allowAgent', v.allowAgent, '에이전트 허용'], ['max_height', v.max_height, '끝나는 블록 — 직접 서명되지 않고 C_s 안에 들어 있다']].filter((r) => r[1] !== null && r[1] !== undefined));
    }
  }

  // ---- 단계 켜기·세부 ----
  const state = { oidc: { n: null, open: null }, zk: { n: null, open: null } };   // n = 지금까지 켠 단계 수(null = 전체), open = 세부를 편 단계(1부터)
  const svgOf = { oidc: 'seqOidc', zk: 'seqZk' }, detailOf = { oidc: 'detailOidc', zk: 'detailZk' };
  function render(kind) {
    const st = state[kind], total = STEPS[kind].length, shown = st.n ?? total;
    for (const g of $(svgOf[kind]).querySelectorAll('.st, .stx')) { const k = Number(g.dataset.step); g.classList.toggle('off', k > shown); g.classList.toggle('cur', st.n !== null && k === shown && g.classList.contains('st')); }   // stx = 단계와 함께 켜지는 딸린 그림(누르는 대상 아님)
    const ctl = document.querySelector(`.ctl[data-ctl="${kind}"]`);
    ctl.querySelector('.pos').textContent = st.n === null ? `전체 (${total}단계)` : `${shown} / ${total} 단계`;
    ctl.querySelector('[data-act="prev"]').disabled = st.n !== null && st.n <= 0;
    ctl.querySelector('[data-act="next"]').disabled = st.n === null || st.n >= total;
    const d = $(detailOf[kind]);
    if (st.open === null) { d.hidden = true; d.replaceChildren(); return; }
    const s = STEPS[kind][st.open - 1];
    // 펼친 설명도 래퍼 방식이면 zkIdP 를 zkWrapper 로(2026-11-24 — 전에는 처음 그린 글자만 바꿨다)
    const h = document.createElement('h4'); h.textContent = W(s.title);
    const p = document.createElement('p'); p.textContent = W(s.body);
    d.replaceChildren(h, p);
    delete d.dataset.token;
    if (kind === 'zk' && WRAP && !SVC) renderTokens(d, st.open);
    if (kind === 'zk' && s.fine && !SVC) {
      let rows = s.fine.map((key) => [key, (flow?.steps ?? []).find((x) => x.key === key) ?? null]).filter(([key, rec]) => rec || !flow || key !== 'publish_wait');
      // 래퍼 방식(2026-11-24 사용자 요청): 패스키 시간을 사용자 대기(인증기 창)와 salt 계산으로 나눠 적는다 — 둘 다 잰 기록일 때만
      if (WRAP) rows = rows.flatMap(([key, rec]) => (key === 'passkey' && rec && Number.isFinite(rec.waitMs) && Number.isFinite(rec.calcMs) ? [['passkey_wait', { ms: rec.waitMs }], ['passkey_calc', { ms: rec.calcMs }]] : [[key, rec]]));
      if (rows.length) {
        const tb = document.createElement('table');
        for (const [key, rec] of rows) { const tr = document.createElement('tr'); const a = document.createElement('td'); a.textContent = W(FINE[key] ?? key); const b = document.createElement('td'); b.className = 'ms'; b.textContent = rec ? fmtMs(Number(rec.ms)) : flow ? '이번에는 없음' : '-'; tr.append(a, b); tb.append(tr); }
        d.append(tb);
        if (!flow) { const n = document.createElement('p'); n.style.color = '#5b6880'; n.textContent = '걸린 시간은 이 브라우저에서 로그인한 뒤에 채워집니다.'; d.append(n); }
      }
    }
    d.hidden = false;
  }
  function act(kind, a) {
    const st = state[kind], total = STEPS[kind].length;
    if (a === 'all') { st.n = null; st.open = null; }
    else if (a === 'first') { st.n = 0; st.open = null; }
    else if (a === 'next') { st.n = Math.min(total, (st.n ?? total) + 1); st.open = st.n; }   // 켠 단계의 설명을 함께 편다(발표 흐름)
    else if (a === 'prev') { st.n = Math.max(0, (st.n ?? total) - 1); st.open = st.n > 0 ? st.n : null; }
    render(kind);
  }
  for (const kind of ['oidc', 'zk']) {
    document.querySelector(`.ctl[data-ctl="${kind}"]`).addEventListener('click', (ev) => { const b = ev.target.closest('button[data-act]'); if (b) act(kind, b.dataset.act); });
    const toggle = (g) => { const k = Number(g.dataset.step); if (g.classList.contains('off')) return; state[kind].open = state[kind].open === k ? null : k; render(kind); };
    $(svgOf[kind]).addEventListener('click', (ev) => { const g = ev.target.closest('.st'); if (g) toggle(g); });
    $(svgOf[kind]).addEventListener('keydown', (ev) => { if (ev.key !== 'Enter' && ev.key !== ' ') return; const g = ev.target.closest('.st'); if (g) { ev.preventDefault(); toggle(g); } });
    render(kind);
  }

  // 다른 탭에서 로그인하면 그 값으로 바뀐다 — 보이는 동안 2초마다, 그리고 탭으로 돌아올 때 다시 읽는다(읽기만 한다)
  let lastAt = null, seenSeq = 0;
  /** 서비스 오리진: 서비스가 받은 값을 다시 읽는다. 늦게 온 응답은 버리고, 401(로그아웃·닫힌 세션)이면 그려 둔 값을 지운다. 서버를 못 읽었으면 그대로 둔다. */
  async function refreshSeen() {
    const my = ++seenSeq, r = await getJson('/api/rp/me');
    if (my !== seenSeq || (!r.body && r.status !== 401)) return;
    seen = r.body?.seen ?? null;
    fill(); render('oidc'); render('zk');
  }
  async function refresh() {
    if (SVC) return refreshSeen();
    const f = await readFlow();
    if ((f?.at ?? null) === lastAt && (f !== null) === (flow !== null)) return;
    flow = f; lastAt = f?.at ?? null;
    fill(); render('zk');
  }
  detectWrapper().finally(() => { fill(); render('oidc'); render('zk'); refresh(); });
  setInterval(() => { if (!document.hidden && !SVC) refresh(); }, 2000);   // 서비스 오리진은 열 때와 탭으로 돌아올 때만 읽는다 — /api/rp/me 는 부를 때마다 체인을 읽는다
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
})();
