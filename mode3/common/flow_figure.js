// mode3/common/flow_figure.js — "누가 무엇을 받아 무엇을 검증하는가" 그림(2026-11-19 데모 시나리오 6·7). zkIdP 관리자 화면과 서비스 화면이 함께 쓴다.
// 그림은 상자 둘(보낸 쪽 → 받은 쪽)과 그 사이의 화살표 둘(보낸 것 · 돌려준 것)이다. 받은 쪽 상자 안에 "검증한 것"(✓)과 "알 수 없는 것"(✗)을 적는다.
// 값은 방금 한 로그인의 실제 값이다 — 전부 공개값(가명·커밋먼트·높이)이고, 긴 값은 줄여 보이되 전체는 title 에 둔다. 모든 글자는 textContent 로만 넣는다.
//   FlowFigure.render(host, { from: { name, sub }, to: { name, sub }, sent: { title, items }, back: { title, items } | null, lists: [{ kind: 'check'|'unknown'|'learn', title, rows: [문장] }] })
//   items: [{ name, value, note }]
(() => {
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined && text !== null) e.textContent = text; return e; };
  const short = (v) => { const s = String(v ?? '-'); return s.length > 26 ? `${s.slice(0, 10)}…${s.slice(-8)}` : s; };
  function items(list) {
    const dl = el('dl', 'flow-items');
    for (const it of list ?? []) {
      const dt = el('dt', null, it.name), dd = el('dd');
      const code = el('code', null, short(it.value)); code.title = String(it.value ?? ''); if (it.key) code.dataset.flow = it.key;
      dd.append(code); if (it.note) dd.append(el('small', 'muted', ` — ${it.note}`));
      dl.append(dt, dd);
    }
    return dl;
  }
  function node(n, cls) { const d = el('div', `flow-node ${cls}`); d.append(el('strong', null, n.name)); if (n.sub) d.append(el('small', 'muted', n.sub)); return d; }
  function render(host, f) {
    host.replaceChildren(); host.classList.add('flow-host');   // 칸의 폭으로 배치를 가른다(demo.css 의 @container)
    const fig = el('div', 'flow-fig');
    const mid = el('div', 'flow-mid');
    mid.append(el('div', 'flow-arrow', `${f.sent.title} →`), items(f.sent.items));
    if (f.back) mid.append(el('div', 'flow-arrow flow-back', `← ${f.back.title}`), items(f.back.items));
    const to = node(f.to, 'flow-to');
    const MARK = { check: '✓', unknown: '✗', learn: '!' };
    for (const l of f.lists ?? []) {   // lists: [{ kind: 'check' | 'unknown' | 'learn', title, rows }]
      if (!l.rows?.length) continue;
      to.append(el('div', 'flow-sub', l.title));
      const ul = el('ul', `flow-${l.kind}`); for (const r of l.rows) ul.append(el('li', null, `${MARK[l.kind] ?? '·'} ${r}`)); to.append(ul);
    }
    fig.append(node(f.from, 'flow-from'), mid, to);
    host.append(fig);
  }
  // 순서도(2026-11-19 스펙 login-flow-and-phone-passkey F6) — 주체의 줄(lanes) 위에 단계를 위에서 아래로 놓는다. 주고받는 단계는 두 줄에 걸친 화살표, 혼자 하는 계산은 한 줄 안의 상자.
  // 단계를 누르면(details) 의미와 값이 펴진다.
  //   FlowFigure.renderSequence(host, { lanes: [{ key, name, sub }], steps: [{ key, from, to, both, title, time, share(0~1), note, dim, meaning, items }] })
  function renderSequence(host, f) {
    const open = new Set([...host.querySelectorAll('details[open]')].map((d) => d.parentElement?.dataset.step));   // 다시 그려도 펴 둔 단계는 그대로
    host.replaceChildren(); host.classList.add('flow-host');
    const cols = f.lanes.length;
    const idx = (k) => Math.max(0, f.lanes.findIndex((l) => l.key === k));
    const wrap = el('div', 'seq'); wrap.style.setProperty('--seq-cols', String(cols));
    const head = el('div', 'seq-lanes');
    for (const l of f.lanes) { const d = el('div', 'seq-lane'); d.dataset.lane = l.key; d.append(el('strong', null, l.name)); if (l.sub) d.append(el('small', 'muted', l.sub)); head.append(d); }
    wrap.append(head);
    const ol = el('ol', 'seq-steps');
    f.steps.forEach((st, i) => {
      const a = idx(st.from), b = idx(st.to ?? st.from);
      const li = el('li', `seq-step${st.dim ? ' seq-dim' : ''}`); li.dataset.step = st.key; li.dataset.kind = a === b ? 'self' : 'arrow';
      const det = el('details'); if (open.has(st.key)) det.open = true;
      const row = el('summary', 'seq-row');
      const box = el('div', `seq-box ${a === b ? 'seq-self' : st.both ? 'seq-both' : a < b ? 'seq-right' : 'seq-left'}`);
      box.style.gridColumn = `${Math.min(a, b) + 1} / ${Math.max(a, b) + 2}`;
      const who = a === b ? f.lanes[a].name : `${f.lanes[a].name} ${st.both ? '⇄' : '→'} ${f.lanes[b].name}`;
      const line = el('div', 'seq-line');
      line.append(el('span', 'seq-n', String(i + 1)), el('span', 'seq-title', st.title));
      if (st.time) { const t = el('span', 'seq-time', st.time); t.dataset.seqTime = st.key; line.append(t); }
      box.append(el('small', 'seq-who muted', who), line);
      if (st.note) box.append(el('small', 'seq-note muted', st.note));
      if (typeof st.share === 'number' && st.share > 0) { const bar = el('span', 'seq-bar'); bar.style.width = `${Math.max(1, Math.min(100, st.share * 100)).toFixed(1)}%`; box.append(bar); }
      row.append(box);
      const body = el('div', 'seq-body');
      body.append(el('p', 'seq-meaning', st.meaning ?? ''));
      if (st.items?.length) body.append(items(st.items));
      det.append(row, body); li.append(det); ol.append(li);
    });
    const flow = el('div', 'seq-flow'), rails = el('div', 'seq-rails');   // 줄마다 세로 점선(주체의 생명선)
    for (let i = 0; i < cols; i++) rails.append(el('span'));
    flow.append(rails, ol);
    wrap.append(flow);
    host.append(wrap);
  }
  window.FlowFigure = { render, renderSequence };
})();
