// mode3/common/flow_page.js — "전체 플로우" 한 장(mode3/common/flow.html, 2026-11-20)의 페이지 스크립트. 의존 없음(지갑 오리진 CSP 아래에서 돈다 — 인라인 스크립트가 없다).
//   · 아랫줄(zk-Delegation)에 이 브라우저의 가장 최근 "zkIdP 로 로그인" 의 공개값을 채운다 — 지갑이 IndexedDB(mode3-user 의 kv 'loginFlow')에 남긴 기록을 **읽기만** 한다.
//     그 기록에는 비밀(salt·세션키)이 없다. 저장소가 아직 없으면 만들지 않는다(지갑이 자기 판으로 만들어야 한다 — 아래 readFlow).
//   · 줄마다 "처음부터 / 이전 / 다음 / 전체 보기" 로 화살표를 하나씩 켠다(발표용). 화살표를 누르면 그 단계의 설명과(아랫줄은) 세부 단계별 걸린 시간이 펴진다.
(() => {
  const $ = (id) => document.getElementById(id);
  const head = (v) => { const s = String(v ?? ''); return s.length > 17 ? `${s.slice(0, 17)}…` : s; };
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
      { title: '④ 서명한 자격증명', body: 'zkIdP 가 증명을 확인하고 가명에 서명해 돌려줍니다. 서명한 것에는 서비스 이름이 없습니다. 처음 등록한 로그인이면 등록부를 체인에 게시합니다.', fine: ['publish_wait'] },
      { title: '⑤ PPID + 증명 π_RP', body: '서비스에는 이 서비스에서만 쓰는 주소 PPID 와, "이 PPID 가 zkIdP 가 서명한 자격증명에서 나왔고 폐기되지 않았다" 는 영지식 증명 π_RP 를 보냅니다. zkIdP 를 거치지 않으므로 zkIdP 는 이 전달을 보지 못합니다.', fine: ['prove_session', 'sign'] },
      { title: '⑥ 검증', body: '서비스가 증명을 검증하고, 증명의 공개 입력이 체인의 최신 등록부 · 폐기 목록과 자기 식별자에 맞는지 확인합니다. uid 나 속성 값은 받지 않습니다.' },
    ],
  };

  let flow = null;
  // ---- 값 채우기(아랫줄) ----
  function fill() {
    const v = flow?.values ?? null;
    const set = (id, text, title) => { const e = $(id); if (!e) return; e.textContent = text; const t = e.querySelector?.('title'); if (t) t.remove(); if (title) { const tt = document.createElementNS('http://www.w3.org/2000/svg', 'title'); tt.textContent = title; e.appendChild(tt); } };
    set('zkAuidS', v?.auid_s ? `auid_s ${head(v.auid_s)}` : 'auid_s', v?.auid_s ?? null);
    set('zkAridS', v?.arid_s ? `arid_s ${head(v.arid_s)}` : 'arid_s', v?.arid_s ?? null);
    set('zkPpid', v?.PPID ? head(v.PPID) : '', v?.PPID ?? null);
    for (const id of ['zkSvcName', 'oidcSvcName']) $(id).textContent = flow?.serviceName ? `서비스 ${flow.serviceName}` : '서비스';   // 윗줄도 같은 서비스 이름으로(같은 서비스에 두 방식으로 로그인하는 그림이다)
    $('zkUid').textContent = v?.uid ? ` = ${v.uid}` : '';
    const r = $('recent');
    if (!flow) { r.textContent = '아직 이 브라우저에서 "zkIdP 로 로그인" 을 한 적이 없습니다 — 그림에는 값의 이름만 보입니다. 서비스에서 로그인하면 실제 값이 채워집니다.'; return; }
    const at = new Date(flow.at);
    r.replaceChildren('가장 최근 로그인: ', Object.assign(document.createElement('b'), { textContent: flow.serviceName ?? flow.origin ?? '-' }), ` · ${at.toLocaleTimeString()} · 전체 ${fmtMs(flow.totalMs)} — 아래 값은 그 로그인의 실제 값입니다.`);
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
    const h = document.createElement('h4'); h.textContent = s.title;
    const p = document.createElement('p'); p.textContent = s.body;
    d.replaceChildren(h, p);
    if (kind === 'zk' && s.fine) {
      const rows = s.fine.map((key) => [key, (flow?.steps ?? []).find((x) => x.key === key) ?? null]).filter(([key, rec]) => rec || !flow || key !== 'publish_wait');
      if (rows.length) {
        const tb = document.createElement('table');
        for (const [key, rec] of rows) { const tr = document.createElement('tr'); const a = document.createElement('td'); a.textContent = FINE[key] ?? key; const b = document.createElement('td'); b.className = 'ms'; b.textContent = rec ? fmtMs(Number(rec.ms)) : flow ? '이번에는 없음' : '-'; tr.append(a, b); tb.append(tr); }
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
  let lastAt = null;
  async function refresh() {
    const f = await readFlow();
    if ((f?.at ?? null) === lastAt && (f !== null) === (flow !== null)) return;
    flow = f; lastAt = f?.at ?? null;
    fill(); render('zk');
  }
  fill();
  refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, 2000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
})();
