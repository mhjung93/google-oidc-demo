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
  window.FlowFigure = { render };
})();
