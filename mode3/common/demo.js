// Mode 3 데모 공통 동작 — 설계 2026-09-24-mode3-demo-ux-design.md §1·§2·§3. 전역 스크립트. strings.js 뒤에 로드.
(function () {
  const S = window.DemoStrings;
  const store = { get(k) { try { return localStorage.getItem(k); } catch { return null; } }, set(k, v) { try { localStorage.setItem(k, v); } catch { /* 사생활 모드 등 */ } } };
  const D = {
    lang: S.langs.includes(store.get('mode3.lang')) ? store.get('mode3.lang') : 'ko',
    expert: store.get('mode3.expert') === '1',
    page: null, lastGuide: null,
    // split/join 으로 갈아 끼운다 — replace 의 치환 문자열은 $&·$' 같은 패턴을 해석해, 값에 $ 가 든 오류 메시지가
    // 문구를 망가뜨린다(문구 값에 든 {키} 는 그대로 두고 값만 넣어야 한다).
    t(key, vars = {}) { const e = S.ui[key]; let s = e ? (e[D.lang] ?? e.ko) : key; for (const [k, v] of Object.entries(vars)) s = s.split(`{${k}}`).join(String(v)); return s; },
    term(name) { const e = S.terms[name]; if (!e) return name; return D.expert ? `${e[D.lang]} (${e.expert})` : e[D.lang]; },
    verdictText(key) { const e = S.verdicts[key]; return e ? (e[D.lang] ?? e.ko) : key; },
    reason(code) { const r = S.reasons[code]; return r ? r[D.lang] ?? r.ko : null; },
    setLang(l) { if (!S.langs.includes(l)) return; D.lang = l; store.set('mode3.lang', l); document.documentElement.lang = l; D.applyI18n(); D.rerenderVerdicts(); if (D.lastGuide) D.guide(D.lastGuide); if (D.stack.state) D.stack.renderDots(); },
    // 토글을 페이지가 직접 부를 수도 있으므로(안내 바의 체크박스만이 아니다) 체크 상태를 여기서 맞춘다.
    // applyI18n 을 함께 부른다 — data-term 라벨은 term() 이 전문가 여부로 원래 기호를 덧붙이므로(설계 §3.1),
    // 여기서 다시 그리지 않으면 토글 뒤에도 옛 표기가 남는다(껐는데 기호가 보이는 등).
    setExpert(b) { D.expert = !!b; store.set('mode3.expert', b ? '1' : '0'); document.documentElement.toggleAttribute('data-expert', D.expert); const ex = document.getElementById('expertToggle'); if (ex) ex.checked = D.expert; D.applyI18n(); D.rerenderVerdicts(); if (D.lastGuide) D.guide(D.lastGuide); if (D.stack.state) D.stack.renderDots(); },
    applyI18n() { document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = D.t(el.dataset.i18n); }); document.querySelectorAll('[data-term]').forEach((el) => { el.textContent = D.term(el.dataset.term); }); },
    init({ page }) {
      D.page = page; document.documentElement.lang = D.lang; document.documentElement.toggleAttribute('data-expert', D.expert);
      const bar = document.getElementById('demoBar'); if (bar) { bar.innerHTML = '<div class="bar-steps"></div><div class="bar-next"></div><div class="bar-tools"><button type="button" class="btn-ghost" id="langToggle"></button><label class="switch"><input type="checkbox" id="expertToggle"> <span data-i18n="toggle_expert"></span></label></div>'; bar.querySelector('#langToggle').addEventListener('click', () => D.setLang(D.lang === 'ko' ? 'en' : 'ko')); const ex = bar.querySelector('#expertToggle'); ex.checked = D.expert; ex.addEventListener('change', () => D.setExpert(ex.checked)); }
      D.applyI18n(); D.guide({ done: [], current: null, hint: null, links: {} });
    },
    guide(g) {
      D.lastGuide = g; const bar = document.getElementById('demoBar'); if (!bar) return;
      const lt = bar.querySelector('#langToggle'); if (lt) lt.textContent = D.t('toggle_lang');
      const stepsEl = bar.querySelector('.bar-steps'); stepsEl.innerHTML = '';
      S.steps.forEach((s, i) => {
        const el = document.createElement('div'); const mine = s.where.includes(D.page);
        el.className = 'step' + (g.done?.includes(s.key) ? ' done' : '') + (g.current === s.key ? ' current' : '') + (mine ? '' : ' elsewhere');
        el.title = s[D.lang].hint; el.innerHTML = `<span class="n">${i + 1}</span><span class="label"></span>`; el.querySelector('.label').textContent = s[D.lang].title; stepsEl.appendChild(el);
      });
      const next = bar.querySelector('.bar-next'); next.innerHTML = '';
      const seen = new Set();   // 이미 붙인 링크 — URL 을 CSS 선택자에 끼워 넣지 않는다(따옴표가 든 URL 이면 선택자가 깨진다)
      const cur = S.steps.find((s) => s.key === g.current);
      if (cur) {
        const p = document.createElement('p'); p.className = 'hint'; p.textContent = cur[D.lang].hint; next.appendChild(p);
        const whereKey = cur.where.includes(D.page) ? D.page : cur.where[0];
        const q = document.createElement('p'); q.className = 'next';
        q.textContent = D.t('bar_next', { where: D.t(`where_${whereKey}`), what: D.t(g.hint || `hint_${cur.key}`) }); next.appendChild(q);
        // 이 페이지에서 끝나는 단계가 아니면 "다른 창에서 진행"을 함께 보인다(설계 §2.1).
        if (whereKey !== D.page) { const b = document.createElement('span'); b.className = 'badge muted'; b.textContent = D.t('bar_other_window'); next.appendChild(b); }
        if (whereKey !== D.page && g.links?.[whereKey]) { const a = document.createElement('a'); a.className = 'btn'; a.href = g.links[whereKey]; a.target = '_blank'; a.rel = 'noopener'; a.textContent = D.t(`go_${whereKey}`); next.appendChild(a); seen.add(a.href); }
      }
      for (const [k, url] of Object.entries(g.links || {})) { if (k === D.page || !url) continue; const a = document.createElement('a'); a.className = 'btn-ghost'; a.href = url; if (seen.has(a.href)) continue; a.target = '_blank'; a.rel = 'noopener'; a.textContent = D.t(`go_${k}`); next.appendChild(a); seen.add(a.href); }
    },
    /**
     * 결과 카드. args 는 인자 객체이거나 — 사전을 읽어 만드는 값이면 — 그것을 돌려주는 함수다. 인자를 요소에 붙여 두고
     * 언어·전문가가 바뀌면 같은 인자로 다시 그린다(사전은 그릴 때 읽으므로 번역이 카드에도 반영된다).
     */
    verdict(el, args) { el.__verdictArgs = args; D.renderVerdict(el, typeof args === 'function' ? args() : args); },
    /** 인자를 들고 있는 결과 카드를 전부 다시 그린다 — 페이지가 따로 기억할 필요가 없다. */
    rerenderVerdicts() { document.querySelectorAll('.verdict').forEach((el) => { if (el.__verdictArgs) D.verdict(el, el.__verdictArgs); }); },
    renderVerdict(el, { ok, title, summary, reason, detail, pending }) {
      // 페이지가 붙여 둔 다른 클래스(레이아웃·browser 테스트가 잡는 것)를 지우지 않는다 — 판정 클래스만 갈아 끼운다.
      el.innerHTML = ''; el.classList.add('verdict'); el.classList.remove('ok', 'bad', 'pending'); el.classList.add(pending ? 'pending' : ok ? 'ok' : 'bad');
      const badge = document.createElement('span'); badge.className = 'badge'; badge.textContent = pending ? '…' : ok ? '✓' : '✕'; el.appendChild(badge);
      const h = document.createElement('strong'); h.textContent = S.verdicts[title] ? D.verdictText(title) : (title ?? ''); el.appendChild(h);
      const r = reason ? D.reason(reason) : null;
      if (summary || r) { const p = document.createElement('p'); p.className = 'summary'; p.textContent = summary ?? r.title; el.appendChild(p); }
      if (r && !ok) { const c = document.createElement('p'); c.className = 'cause'; c.textContent = r.cause; el.appendChild(c); const a = document.createElement('p'); a.className = 'action'; a.textContent = r.action; el.appendChild(a); }
      // 사유 코드는 번역 여부와 상관없이 원문 그대로 함께 남긴다 — 사전에 있는 코드도 화면·로그에서 코드로 짚을 수 있어야 한다.
      if (reason) { const code = document.createElement('code'); code.className = 'reason'; code.textContent = reason; el.appendChild(code); }
      if (detail !== undefined) { const d = document.createElement('details'); if (D.expert) d.open = true; const s = document.createElement('summary'); s.textContent = D.t('details'); d.appendChild(s); const pre = document.createElement('pre'); pre.textContent = typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2); d.appendChild(pre); el.appendChild(d); }
    },
    confirmDanger(key, vars) { return window.confirm(D.t(key, vars)); },
    /**
     * 상태 패널(설계 2026-09-25 §2). cfg = { self:'aa'|'rp'|'wallet', urls:{ aa, rp, wallet } }.
     * 주소를 나중에 알게 되면(rp_info·health 응답) 같은 인자 모양으로 다시 부른다 — 주소만 합쳐지고 폴링은 한 번만 건다.
     * 자기 서버는 상대 주소 없이 '/mode3/health' 로 부른다(CORS 를 타지 않는다).
     */
    stack(cfg) {
      const st = (D.stack.state ??= { urls: {}, last: { at: 0, aa: null, rp: null, wallet: null, errors: {} }, timer: null, subs: [], open: false, sig: null });
      Object.assign(st.urls, cfg?.urls || {});
      if (cfg?.self) st.self = cfg.self;
      if (!st.timer) {
        const tick = () => { D.stack.poll(); };
        // 탭이 숨겨지면 읽지 않고, 다시 보이면 즉시 한 번 읽는다(설계 §2.3).
        st.timer = setInterval(() => { if (!document.hidden) tick(); }, 5000);
        document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });
        // 패널 밖 클릭·Esc 로 닫는다. 점 자체의 클릭은 점 쪽에서 막는다(토글이 곧바로 되돌려지지 않게).
        document.addEventListener('click', (ev) => { if (!st.open) return; if (ev.target?.closest?.('#stackPanel, .stack-dots')) return; st.open = false; D.stack.renderDots(); });
        document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && st.open) { st.open = false; D.stack.renderDots(); } });
        tick();
      }
      D.stack.renderDots();
    },
  };
  // ---- 상태 패널의 나머지(폴링·판정·그리기). stack() 이 함수라 여기에 붙인다. ----
  /** 판정 키 → 1차 사유 사전 코드(설계 §2.1). 서비스 비활성은 서버가 준 inactiveReason 을 그대로 쓴다. */
  const STACK_REASON = { stack_root_stale: 'root_too_old', stack_rp_pending: 'registration_pending', stack_wallet_cia_down: 'cia_unavailable' };
  const STACK_ROLES = ['aa', 'rp', 'wallet'];
  Object.assign(D.stack, {
    state: null,
    /** 2초 예산. AbortSignal.timeout 이 없는 브라우저면 AbortController + 타이머로 같은 일을 한다. */
    budget(ms) {
      if (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) return { signal: AbortSignal.timeout(ms), done() { /* 자체 타이머 */ } };
      const c = new AbortController(); const t = setTimeout(() => c.abort(), ms);
      return { signal: c.signal, done() { clearTimeout(t); } };
    },
    /** 구독자에게 알릴지 판단하는 값 — now(매 응답 달라짐)는 뺀다. 응답이 없으면 실패 종류('timeout'|'error')로 비교한다. */
    signature(last) { return JSON.stringify(STACK_ROLES.map((r) => (last[r] ? { ...last[r], now: undefined } : (last.errors[r] ?? null)))); },
    /** 폴링 결과가 바뀔 때 부른다(체험 모드·페이지가 주소를 알아내는 데 쓴다). 구독 해제 함수를 돌려준다. */
    onChange(fn) { const st = D.stack.state; if (!st || typeof fn !== 'function') return () => {}; st.subs.push(fn); return () => { const i = st.subs.indexOf(fn); if (i >= 0) st.subs.splice(i, 1); }; },
    async poll() {
      const st = D.stack.state; if (!st) return;
      const next = { at: Date.now(), aa: null, rp: null, wallet: null, errors: {} };
      await Promise.all(STACK_ROLES.map(async (role) => {
        const url = role === st.self ? '/mode3/health' : (st.urls[role] ? `${st.urls[role]}/mode3/health` : null);
        if (!url) return;                       // 주소를 아직 모른다 — 오류가 아니라 회색(모름)이다
        const b = D.stack.budget(2000);
        try {
          const r = await fetch(url, { signal: b.signal, cache: 'no-store' });
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          const body = await r.json();
          if (body?.role !== role) throw new Error('role');   // 다른 서버를 가리키고 있으면 초록으로 속이지 않는다
          next[role] = body;
        } catch (e) {
          // 실패는 콘솔에 남기지 않는다(설계 §2.3) — 점 색과 패널 문구로만 말한다.
          next.errors[role] = e && (e.name === 'AbortError' || e.name === 'TimeoutError') ? 'timeout' : 'error';
        } finally { b.done(); }
      }));
      st.last = next;
      D.stack.renderDots();
      const sig = D.stack.signature(next);
      if (sig !== st.sig) { st.sig = sig; for (const fn of st.subs.slice()) { try { fn(next); } catch { /* 구독자 오류가 폴링을 멈추지 않는다 */ } } }
    },
    /** 설계 §2.2 판정표. last 만 보는 순수 함수다(tests/test_mode3_stack_judge.js). */
    judge(last) {
      const lv = (level, key, vars = {}) => ({ level, key, vars });
      const anyChain = [last.aa, last.rp, last.wallet].find((h) => h?.chain);
      const chain = last.at === 0 ? lv('unknown', 'stack_unknown') : anyChain ? lv('ok', 'stack_head', { head: anyChain.chain.head }) : lv('bad', 'stack_chain_none');
      // 상한은 서비스가 체인에서 읽은 값이 정본이다. 서비스가 없으면 AA 의 하트비트 간격 2배를 임시 상한으로 쓴다.
      const maxAge = last.rp?.maxRootAge ?? (last.aa ? last.aa.heartbeatBlocks * 2 : null);
      const aa = !last.aa ? (last.errors.aa ? lv('bad', 'stack_no_response') : lv('unknown', 'stack_unknown'))
        : (maxAge && last.aa.rootAge !== null && last.aa.rootAge >= maxAge) ? lv('bad', 'stack_root_stale')
          : (maxAge && ((last.aa.rootAge !== null && last.aa.rootAge >= maxAge / 2) || last.aa.heartbeatBlocks >= maxAge)) ? lv('warn', 'stack_root_warn', { age: last.aa.rootAge ?? '?' })
            : last.aa.pendingLeaves > 0 ? lv('warn', 'stack_pending_leaves', { n: last.aa.pendingLeaves }) : lv('ok', 'stack_ok');
      const rp = !last.rp ? (last.errors.rp ? lv('bad', 'stack_no_response') : lv('unknown', 'stack_unknown'))
        : !last.rp.active ? lv('bad', 'stack_rp_inactive') : last.rp.status !== 'approved' ? lv('warn', 'stack_rp_pending') : lv('ok', 'stack_ok');
      const wallet = !last.wallet ? (last.errors.wallet ? lv('bad', 'stack_no_response') : lv('unknown', 'stack_unknown'))
        : !last.wallet.ciaReachable ? lv('warn', 'stack_wallet_cia_down') : !last.wallet.registered ? lv('unknown', 'stack_wallet_unregistered') : lv('ok', 'stack_ok');
      return { aa, rp, wallet, chain };
    },
    /** 안내 바 오른쪽의 점 4개 + (열려 있으면) 패널. 언어·전문가 전환과 폴링마다 다시 그린다. */
    renderDots() {
      const st = D.stack.state; if (!st) return;
      const bar = document.getElementById('demoBar'); if (!bar) return;
      const tools = bar.querySelector('.bar-tools'); if (!tools) return;
      let dots = bar.querySelector('.stack-dots');
      if (!dots) { dots = document.createElement('div'); dots.className = 'stack-dots'; tools.insertBefore(dots, tools.firstChild); }
      const v = D.stack.judge(st.last);
      dots.textContent = '';
      for (const role of ['aa', 'rp', 'wallet', 'chain']) {
        const b = document.createElement('button');
        b.type = 'button'; b.className = `dot ${role} ${v[role].level}`;
        const label = D.t(`stack_${role}`), msg = D.t(v[role].key, v[role].vars);
        b.textContent = label;                       // 색만으로 구분하지 않는다(1차 §4.5) — 라벨과 판정 문구를 함께 붙인다
        b.title = `${label}: ${msg}`; b.setAttribute('aria-label', `${label}: ${msg}`); b.setAttribute('aria-expanded', st.open ? 'true' : 'false');
        b.addEventListener('click', (ev) => { ev.stopPropagation(); st.open = !st.open; D.stack.renderDots(); });
        dots.appendChild(b);
      }
      D.stack.renderPanel(v);
    },
    renderPanel(v) {
      const st = D.stack.state; const bar = document.getElementById('demoBar'); if (!st || !bar) return;
      let panel = document.getElementById('stackPanel');
      if (!panel) { panel = document.createElement('div'); panel.id = 'stackPanel'; panel.className = 'stack-panel'; bar.appendChild(panel); }
      panel.textContent = ''; panel.hidden = !st.open;
      if (!st.open) return;
      const title = document.createElement('strong'); title.className = 'panel-title'; title.textContent = D.t('stack_panel_title'); panel.appendChild(title);
      for (const role of ['aa', 'rp', 'wallet', 'chain']) {
        const j = v[role];
        const row = document.createElement('div'); row.className = `row ${role} ${j.level}`;
        const name = document.createElement('span'); name.className = 'name'; name.textContent = D.t(`stack_${role}`); row.appendChild(name);
        const body = document.createElement('div');
        const msg = document.createElement('p'); msg.className = 'msg'; msg.textContent = D.t(j.key, j.vars); body.appendChild(msg);
        const code = j.key === 'stack_rp_inactive' ? (st.last.rp?.inactiveReason ?? null) : (STACK_REASON[j.key] ?? null);
        const r = code ? D.reason(code) : null;
        if (r) {
          const c = document.createElement('p'); c.className = 'cause'; c.textContent = r.cause; body.appendChild(c);
          const a = document.createElement('p'); a.className = 'action'; a.textContent = r.action; body.appendChild(a);
          const el = document.createElement('code'); el.className = 'reason'; el.textContent = code; body.appendChild(el);
        }
        // 원본 응답은 전문가 보기에서만. 체인은 세 응답이 함께 준 값이라 따로 싣지 않는다.
        if (role !== 'chain') { const pre = document.createElement('pre'); pre.className = 'expert'; pre.textContent = st.last[role] ? JSON.stringify(st.last[role], null, 2) : (st.last.errors[role] ?? '—'); body.appendChild(pre); }
        row.appendChild(body); panel.appendChild(row);
      }
    },
  });
  /** 마지막 폴링 묶음 — 페이지·체험 모드가 읽는다(설계 §2.3). */
  Object.defineProperty(D.stack, 'last', { get() { return D.stack.state ? D.stack.state.last : null; } });
  window.Demo = D;
})();
