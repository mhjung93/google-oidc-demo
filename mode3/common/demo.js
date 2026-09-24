// Mode 3 데모 공통 동작 — 설계 2026-09-24-mode3-demo-ux-design.md §1·§2·§3. 전역 스크립트. strings.js 뒤에 로드.
(function () {
  const S = window.DemoStrings;
  const store = { get(k) { try { return localStorage.getItem(k); } catch { return null; } }, set(k, v) { try { localStorage.setItem(k, v); } catch { /* 사생활 모드 등 */ } } };
  const D = {
    lang: S.langs.includes(store.get('mode3.lang')) ? store.get('mode3.lang') : 'ko',
    expert: store.get('mode3.expert') === '1',
    page: null, lastGuide: null,
    t(key, vars = {}) { const e = S.ui[key]; let s = e ? (e[D.lang] ?? e.ko) : key; for (const [k, v] of Object.entries(vars)) s = s.replace(`{${k}}`, String(v)); return s; },
    term(name) { const e = S.terms[name]; if (!e) return name; return D.expert ? `${e[D.lang]} (${e.expert})` : e[D.lang]; },
    verdictText(key) { const e = S.verdicts[key]; return e ? (e[D.lang] ?? e.ko) : key; },
    reason(code) { const r = S.reasons[code]; return r ? r[D.lang] ?? r.ko : null; },
    setLang(l) { if (!S.langs.includes(l)) return; D.lang = l; store.set('mode3.lang', l); document.documentElement.lang = l; D.applyI18n(); D.rerenderVerdicts(); if (D.lastGuide) D.guide(D.lastGuide); },
    // 토글을 페이지가 직접 부를 수도 있으므로(안내 바의 체크박스만이 아니다) 체크 상태를 여기서 맞춘다.
    // applyI18n 을 함께 부른다 — data-term 라벨은 term() 이 전문가 여부로 원래 기호를 덧붙이므로(설계 §3.1),
    // 여기서 다시 그리지 않으면 토글 뒤에도 옛 표기가 남는다(껐는데 기호가 보이는 등).
    setExpert(b) { D.expert = !!b; store.set('mode3.expert', b ? '1' : '0'); document.documentElement.toggleAttribute('data-expert', D.expert); const ex = document.getElementById('expertToggle'); if (ex) ex.checked = D.expert; D.applyI18n(); D.rerenderVerdicts(); if (D.lastGuide) D.guide(D.lastGuide); },
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
    async call(el, hintKey, fn) {
      if (el) D.verdict(el, { pending: true, title: D.t(hintKey || 'working') });
      try { return await fn(); }
      catch (e) { if (el) D.verdict(el, { ok: false, title: e.title ?? D.t('error_title'), reason: e.reason, detail: e.detail ?? e.message }); throw e; }
    },
    confirmDanger(key, vars) { return window.confirm(D.t(key, vars)); },
  };
  window.Demo = D;
})();
