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
    setLang(l) { if (!S.langs.includes(l)) return; D.lang = l; store.set('mode3.lang', l); document.documentElement.lang = l; D.applyI18n(); D.rerenderVerdicts(); D.tour.syncSwitch(); if (D.tour.lastEval) D.tour.evaluate(D.tour.lastEval); else if (D.lastGuide) D.guide(D.lastGuide); if (D.stack.state) D.stack.renderDots(); },
    // 토글을 페이지가 직접 부를 수도 있으므로(안내 바의 체크박스만이 아니다) 체크 상태를 여기서 맞춘다.
    // applyI18n 을 함께 부른다 — data-term 라벨은 term() 이 전문가 여부로 원래 기호를 덧붙이므로(설계 §3.1),
    // 여기서 다시 그리지 않으면 토글 뒤에도 옛 표기가 남는다(껐는데 기호가 보이는 등).
    setExpert(b) { D.expert = !!b; store.set('mode3.expert', b ? '1' : '0'); document.documentElement.toggleAttribute('data-expert', D.expert); const ex = document.getElementById('expertToggle'); if (ex) ex.checked = D.expert; D.applyI18n(); D.rerenderVerdicts(); D.tour.syncSwitch(); if (D.tour.lastEval) D.tour.evaluate(D.tour.lastEval); else if (D.lastGuide) D.guide(D.lastGuide); if (D.stack.state) D.stack.renderDots(); },
    applyI18n() { document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = D.t(el.dataset.i18n); }); document.querySelectorAll('[data-term]').forEach((el) => { el.textContent = D.term(el.dataset.term); }); },
    /** tour:false 면 체험 모드를 아예 켜지 않는다(승인 팝업 — 설계 2026-09-25 §3.1). */
    init({ page, tour = true }) {
      D.page = page; document.documentElement.lang = D.lang; document.documentElement.toggleAttribute('data-expert', D.expert);
      const bar = document.getElementById('demoBar'); if (bar) { bar.innerHTML = '<div class="bar-steps"></div><div class="bar-next"></div><div class="bar-tools"><button type="button" class="btn-ghost" id="langToggle"></button><label class="switch"><input type="checkbox" id="expertToggle"> <span data-i18n="toggle_expert"></span></label></div>'; bar.querySelector('#langToggle').addEventListener('click', () => D.setLang(D.lang === 'ko' ? 'en' : 'ko')); const ex = bar.querySelector('#expertToggle'); ex.checked = D.expert; ex.addEventListener('change', () => D.setExpert(ex.checked)); }
      D.applyI18n(); D.guide({ done: [], current: null, hint: null, links: {} });
      if (tour !== false) D.tour.init();
    },
    /** 다른 당사자 링크에 체험 모드를 나른다 — 오리진마다 저장소가 다르다(설계 §3.1). 쿼리·해시가 이미 있어도 망가지지 않게 붙인다. */
    withTour(url) {
      if (!url || !D.tour.enabled) return url;
      const [before, hash = ''] = String(url).split('#');
      return `${before}${before.includes('?') ? '&' : '?'}tour=1${hash ? '#' + hash : ''}`;
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
        if (whereKey !== D.page && g.links?.[whereKey]) { const a = document.createElement('a'); a.className = 'btn'; a.href = D.withTour(g.links[whereKey]); a.target = '_blank'; a.rel = 'noopener'; a.textContent = D.t(`go_${whereKey}`); next.appendChild(a); seen.add(a.href); }
      }
      for (const [k, url] of Object.entries(g.links || {})) { if (k === D.page || !url) continue; const a = document.createElement('a'); a.className = 'btn-ghost'; a.href = D.withTour(url); if (seen.has(a.href)) continue; a.target = '_blank'; a.rel = 'noopener'; a.textContent = D.t(`go_${k}`); next.appendChild(a); seen.add(a.href); }
      // 안내 바의 높이가 바뀌면 그 아래 요소가 밀린다 — 말풍선을 다시 앉힌다(설계 §3.4).
      D.tour.place(true);
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
      const st = D.stack.ensure();
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
    /**
     * 체험 모드(설계 2026-09-25 §3). 켜면 단계 순서대로만 진행되도록 앞 3단계 버튼을 잠그고, 지금 눌러야 할 곳에
     * 말풍선 하나를 붙인다. 기본은 꺼짐이고, 꺼지면 잠금·말풍선이 사라지고 버튼은 페이지의 원래 규칙으로 돌아간다.
     * 단계 판정은 서버 사실(Demo.stack 의 health)과 페이지 메모리(progress)를 합쳐 여기 한 곳에서 한다.
     */
    tour: {
      enabled: false, locks: [], lastEval: null, anchor: null, mode: 'below', epochRose: false, openingsDrained: false, started: false,
      init() {
        if (D.tour.started) return;
        D.tour.started = true;
        // ?tour=1|0 은 다른 당사자 창에서 건너온 신호다 — 자기 저장소에 새기고 주소창에서는 지운다(설계 §3.1).
        const q = new URLSearchParams(location.search), v = q.get('tour');
        if (v === '1' || v === '0') {
          store.set('mode3.tour', v === '1' ? '1' : '');
          q.delete('tour');
          const qs = q.toString();
          history.replaceState(null, '', location.pathname + (qs ? `?${qs}` : '') + location.hash);
        }
        D.tour.enabled = store.get('mode3.tour') === '1';
        const tools = document.querySelector('#demoBar .bar-tools');
        if (tools && !tools.querySelector('#tourToggle')) {
          const l = document.createElement('label'); l.className = 'switch';
          l.innerHTML = '<input type="checkbox" id="tourToggle"> <span data-i18n="tour_on"></span>';   // 값이 섞이지 않는 고정 틀
          tools.prepend(l);
          const cb = l.querySelector('input');
          cb.checked = D.tour.enabled;
          cb.addEventListener('change', () => D.tour.set(cb.checked));
          D.applyI18n();
        }
        D.tour.syncSwitch();
        // 서버 사실이 바뀌면 다시 판정한다. 폐기 게시(epoch 증가)와 개봉 처리(대기 0)는 지나가는 사건이라 여기서 붙잡아 둔다.
        let prevAa = null;                     // 마지막으로 읽힌 aa 응답(못 읽은 회차는 건너뛴다 — 비교 기준을 잃지 않게)
        D.stack.onChange((cur) => {
          if (cur.aa) {
            if (prevAa) {
              if (Number(prevAa.epoch) < Number(cur.aa.epoch)) D.tour.epochRose = true;
              if (prevAa.pendingOpenings > 0 && cur.aa.pendingOpenings === 0) D.tour.openingsDrained = true;
            }
            prevAa = cur.aa;
          }
          if (D.tour.lastEval) D.tour.evaluate(D.tour.lastEval);
        });
        addEventListener('scroll', () => D.tour.place(), { passive: true });
        addEventListener('resize', () => D.tour.place(true));
      },
      set(on) {
        D.tour.enabled = !!on; store.set('mode3.tour', on ? '1' : '');
        const cb = document.getElementById('tourToggle'); if (cb) cb.checked = D.tour.enabled;
        D.tour.syncSwitch();
        if (D.tour.lastEval) D.tour.evaluate(D.tour.lastEval); else D.tour.renderOverlay(null, false, null);
      },
      /** 스위치에 지금 무엇을 하게 되는지 붙인다(켜져 있으면 "끄면 …"). */
      syncSwitch() { const cb = document.getElementById('tourToggle'); if (cb?.parentElement) cb.parentElement.title = D.t(D.tour.enabled ? 'tour_off' : 'tour_on'); },
      /** 페이지가 버튼의 원래 활성 규칙(otherwise)과 함께 잠금을 건다. 같은 id 는 마지막 것만 남는다. */
      lock(spec) { if (!spec?.id) return; D.tour.locks = D.tour.locks.filter((l) => l.id !== spec.id); D.tour.locks.push(spec); D.tour.applyLocks(); },
      /** 설계 §3.2 판정. 서버 사실을 아직 모르면 null 을 돌려준다 — 모르는 동안에는 잠그지 않는다(막히는 것보다 열려 있는 편이 안전). */
      condMet(cond) {
        const l = D.stack.last; if (!l || l.at === 0) return null;
        if (cond === 'rp_approved') return l.rp ? l.rp.status === 'approved' : null;
        if (cond === 'wallet_registered') return l.wallet ? !!l.wallet.registered : null;
        if (cond === 'has_session') return (l.wallet?.sessions ?? 0) > 0 || (l.rp?.sessions ?? 0) > 0;
        return null;
      },
      /** 페이지의 renderGuide 가 부른다 — done/current 를 여기서 계산해 안내 바·잠금·말풍선을 한꺼번에 맞춘다. */
      evaluate({ progress = {}, links } = {}) {
        D.tour.lastEval = { progress, links };
        const l = D.stack.last, done = [];
        // 상대 서버에 닿지 못하면 health 판정은 null 이다 — 그때도 페이지가 자기 눈으로 본 사실(progress)이 있으면
        // 그 단계는 done 이다(1차의 판정 근거). 잠금은 이 값을 쓰지 않는다(설계 §3.2 "모르면 잠그지 않는다").
        if (D.tour.condMet('rp_approved') || progress.approved) done.push('approve');
        if (D.tour.condMet('wallet_registered') || progress.registered) done.push('register');
        if (D.tour.condMet('has_session') || progress.login) done.push('login');
        if (progress.used) done.push('use');
        if (progress.disclosed) done.push('disclose');
        if (progress.revoked || (l?.aa?.pendingLeaves ?? 0) > 0 || D.tour.epochRose) done.push('revoke');
        if (progress.opened || D.tour.openingsDrained) done.push('open');
        const order = S.steps.map((s) => s.key);
        const current = order.find((k) => !done.includes(k)) ?? null;
        const lk = links || D.lastGuide?.links || {};
        D.guide({ done, current, links: lk });
        D.tour.applyLocks();
        D.tour.renderOverlay(current, done.length === order.length, lk);
        return true;
      },
      /** 잠긴 버튼은 disabled + 사유 배지. 체험 모드가 꺼져 있거나 조건을 모르면 페이지의 원래 규칙으로 돌린다. */
      applyLocks() {
        for (const { id, cond, otherwise } of D.tour.locks) {
          const el = document.getElementById(id); if (!el) continue;
          // 페이지가 처리 중이라 스스로 막아 둔 버튼은 건드리지 않는다 — 폴링이 요청 도중에 다시 열어 주면 두 번 눌린다.
          if (el.dataset.tourBusy === '1') continue;
          const met = D.tour.enabled ? D.tour.condMet(cond) : true;
          const locked = D.tour.enabled && met === false;
          el.disabled = locked ? true : !(otherwise ? otherwise() : true);
          let badge = el.parentElement?.querySelector(`:scope > .tour-lock[data-for="${id}"]`) ?? null;
          if (locked) {
            if (!badge) { badge = document.createElement('span'); badge.className = 'tour-lock badge warn'; badge.dataset.for = id; el.after(badge); }
            badge.textContent = D.t(cond === 'rp_approved' ? 'tour_lock_register' : 'tour_lock_login');
          } else if (badge) badge.remove();
        }
      },
      /**
       * 말풍선 하나(#tourBubble)와, 이 페이지에 대상이 없을 때의 카드(#tourCard). 체험 모드가 꺼져 있으면 둘 다 치운다.
       * 다른 요소를 덮지 않도록 배경막은 두지 않는다 — 말풍선 자체만 화면에 얹힌다(설계 §3.4).
       */
      renderOverlay(current, allDone, links) {
        const bubble = document.getElementById('tourBubble'), card = document.getElementById('tourCard');
        if (!D.tour.enabled) { bubble?.remove(); card?.remove(); D.tour.anchor = null; return; }
        const step = S.steps.find((s) => s.key === current) ?? null;
        const targetId = allDone ? null : (step?.target?.[D.page] ?? null);
        let el = targetId ? document.getElementById(targetId) : null;
        if (el && el.offsetParent === null) el = null;             // 숨겨진 대상(다른 모드의 카드 등)에는 붙이지 않는다 — 화면 구석에 뜬다
        if (!el) { bubble?.remove(); D.tour.anchor = null; D.tour.renderCard(allDone, step, links); return; }
        card?.remove();
        let b = bubble;
        if (!b) { b = document.createElement('div'); b.id = 'tourBubble'; b.className = 'tour-bubble'; b.innerHTML = '<strong class="tour-title"></strong><p class="tour-body"></p>'; document.body.appendChild(b); }
        const txt = step.tour[D.lang] ?? step.tour.ko;
        b.querySelector('.tour-title').textContent = txt.title;
        b.querySelector('.tour-body').textContent = txt.body;
        D.tour.anchor = el;
        D.tour.place(true);
      },
      /** 안내 바 아래 카드 — 지금 할 일이 다른 창에 있거나(링크 포함) 7단계를 다 마쳤을 때. */
      renderCard(allDone, step, links) {
        const bar = document.getElementById('demoBar');
        if (!bar || (!allDone && !step)) { document.getElementById('tourCard')?.remove(); return; }
        let c = document.getElementById('tourCard');
        if (!c) { c = document.createElement('div'); c.id = 'tourCard'; c.className = 'tour-elsewhere'; bar.appendChild(c); }
        c.textContent = '';
        const title = document.createElement('strong');
        const body = document.createElement('p');
        if (allDone) { title.textContent = D.t('tour_done_title'); body.textContent = D.t('tour_done_body'); c.append(title, body); return; }
        const txt = step.tour[D.lang] ?? step.tour.ko;
        // 대상이 정해진 당사자 중 이 페이지가 아닌 첫 번째. 링크를 모르면 문구만 남는다.
        const whereKey = step.where.find((w) => w !== D.page && step.target?.[w]) ?? step.where.find((w) => w !== D.page) ?? step.where[0];
        title.textContent = txt.title;
        body.textContent = D.t('tour_elsewhere', { where: D.t(`where_${whereKey}`) });
        c.append(title, body);
        const url = links?.[whereKey];
        if (url) { const a = document.createElement('a'); a.className = 'btn'; a.href = D.withTour(url); a.target = '_blank'; a.rel = 'noopener'; a.textContent = D.t('tour_next'); c.appendChild(a); }
      },
      /**
       * 대상 요소 바로 아래에 앉힌다(좁은 창에서는 CSS 가 전폭으로 펴므로 top 만 쓰인다). 그 자리가 누를 수 있는 것을
       * 덮으면 오른쪽(빈 폭 392px 이상)으로, 그마저 안 되면 대상이 든 카드 아래로 내린다(설계 §3.4 "클릭을 막지 않는다").
       * recheck 는 자리 판단을 다시 하라는 뜻이다 — 스크롤은 같은 자리를 따라가기만 한다(매 프레임 짚어 보지 않는다).
       */
      place(recheck = false) {
        const b = document.getElementById('tourBubble'), el = D.tour.anchor;
        if (!b || !el || !el.isConnected) return;
        const put = (top, left, side = false) => {
          b.classList.toggle('side', side);
          b.style.top = `${Math.round(top + window.scrollY)}px`;
          b.style.left = `${Math.round(left + window.scrollX)}px`;
        };
        const r = el.getBoundingClientRect();
        const card = el.closest('.card');
        const cardRect = () => card.getBoundingClientRect();
        if (!recheck) {                                   // 스크롤: 직전에 고른 자리를 그대로 따라간다
          if (D.tour.mode === 'side') put(r.top, r.right + 12, true);
          else if (D.tour.mode === 'card' && card) { const c = cardRect(); put(c.bottom + 8, c.left); }
          else put(r.bottom + 8, r.left);
          return;
        }
        D.tour.mode = 'below'; put(r.bottom + 8, r.left);
        if (!D.tour.covers(b, el)) return;
        if (window.innerWidth - r.right >= 392) {
          put(r.top, r.right + 12, true);
          if (!D.tour.covers(b, el)) { D.tour.mode = 'side'; return; }
        }
        if (card) { const c = cardRect(); put(c.bottom + 8, c.left); D.tour.mode = 'card'; return; }
        put(r.bottom + 8, r.left);                        // 옮길 데가 없으면 원래 자리
      },
      /**
       * 말풍선 자리에 눌러야 할 것이 깔려 있나. 점 몇 개를 짚는 elementFromPoint 로는 작은 버튼이 샘플 사이로 빠져나가므로
       * 보이는 조작 요소들의 사각형과 직접 겹쳐 본다(대상 자신과 안내 바는 뺀다 — 안내 바는 sticky 라 스크롤이면 늘 걸린다).
       */
      covers(b, anchor) {
        const q = b.getBoundingClientRect();
        if (q.width === 0) return false;
        for (const e of document.querySelectorAll('button, a, input, select, textarea, summary, label')) {
          if (e === anchor || anchor.contains(e) || e.contains(anchor) || b.contains(e) || e.closest('#demoBar')) continue;
          if (e.offsetParent === null || e.disabled) continue;      // 안 보이거나 못 누르는 것은 덮여도 그만이다
          const r = e.getBoundingClientRect();
          if (r.width === 0 || r.height === 0) continue;
          if (r.left < q.right && r.right > q.left && r.top < q.bottom && r.bottom > q.top) return true;
        }
        return false;
      },
    },
  };
  // ---- 상태 패널의 나머지(폴링·판정·그리기). stack() 이 함수라 여기에 붙인다. ----
  /** 판정 키 → 1차 사유 사전 코드(설계 §2.1). 서비스 비활성은 서버가 준 inactiveReason 을 그대로 쓴다. */
  const STACK_REASON = { stack_root_stale: 'root_too_old', stack_rp_pending: 'registration_pending', stack_wallet_cia_down: 'cia_unavailable' };
  const STACK_ROLES = ['aa', 'rp', 'wallet'];
  Object.assign(D.stack, {
    state: null,
    /** 상태 묶음을 만들어 둔다 — 폴링은 stack() 이 걸고, 여기서는 구독만 먼저 받을 수 있게 한다(체험 모드가 페이지보다 먼저 켜진다). */
    ensure() { return (D.stack.state ??= { urls: {}, last: { at: 0, aa: null, rp: null, wallet: null, errors: {} }, timer: null, subs: [], open: false, sig: null }); },
    /** 2초 예산. AbortSignal.timeout 이 없는 브라우저면 AbortController + 타이머로 같은 일을 한다. */
    budget(ms) {
      if (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) return { signal: AbortSignal.timeout(ms), done() { /* 자체 타이머 */ } };
      const c = new AbortController(); const t = setTimeout(() => c.abort(), ms);
      return { signal: c.signal, done() { clearTimeout(t); } };
    },
    /** 구독자에게 알릴지 판단하는 값 — now(매 응답 달라짐)는 뺀다. 응답이 없으면 실패 종류('timeout'|'error')로 비교한다. */
    signature(last) { return JSON.stringify(STACK_ROLES.map((r) => (last[r] ? { ...last[r], now: undefined } : (last.errors[r] ?? null)))); },
    /** 폴링 결과가 바뀔 때 부른다(체험 모드·페이지가 주소를 알아내는 데 쓴다). 구독 해제 함수를 돌려준다. */
    onChange(fn) { if (typeof fn !== 'function') return () => {}; const st = D.stack.ensure(); st.subs.push(fn); return () => { const i = st.subs.indexOf(fn); if (i >= 0) st.subs.splice(i, 1); }; },
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
      const st = D.stack.state; if (!st || !st.self) return;      // 폴링을 아직 걸지 않았으면(체험 모드만 구독한 상태) 점을 만들지 않는다
      const bar = document.getElementById('demoBar'); if (!bar) return;
      const tools = bar.querySelector('.bar-tools'); if (!tools) return;
      let dots = bar.querySelector('.stack-dots');
      if (!dots) { dots = document.createElement('div'); dots.className = 'stack-dots'; tools.insertBefore(dots, tools.firstChild); }
      const v = D.stack.judge(st.last);
      for (const role of ['aa', 'rp', 'wallet', 'chain']) {
        // 점은 한 번만 만들고 이후에는 색·문구만 갈아 끼운다 — 5초마다 다시 만들면 눌러 둔 초점이 폴링마다 날아간다.
        let b = dots.querySelector(`button.${role}`);
        if (!b) {
          b = document.createElement('button'); b.type = 'button'; b.className = `dot ${role}`;
          b.addEventListener('click', (ev) => { ev.stopPropagation(); st.open = !st.open; D.stack.renderDots(); });
          dots.appendChild(b);
        }
        const label = D.t(`stack_${role}`), msg = D.t(v[role].key, v[role].vars);
        b.className = `dot ${role} ${v[role].level}`;
        if (b.textContent !== label) b.textContent = label;       // 색만으로 구분하지 않는다(1차 §4.5) — 라벨과 판정 문구를 함께 붙인다
        b.title = `${label}: ${msg}`; b.setAttribute('aria-label', `${label}: ${msg}`); b.setAttribute('aria-expanded', st.open ? 'true' : 'false');
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
