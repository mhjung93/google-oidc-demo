// mode3/attr/attr_page.js — 속성 커밋먼트 도구(mode3/attr.html)의 페이지 스크립트. 2026-11-17: attr.html 의 인라인 <script> 를 그대로 옮겼다 —
// passkey-web 의 지갑 오리진 CSP(script-src 'self', 'unsafe-inline' 없음)가 인라인 스크립트를 막기 때문이다. classic script 라 전역·실행 순서는 전과 같다
// (body 끝에서 /attr/dist/attr.js·demo.js 뒤에 돈다). 스냅 에이전트(mode3_wallet_agent.js)도 같은 /attr 정적 경로로 낸다.
const $ = (id) => document.getElementById(id);
const STORE_KEY = 'mode3_attr_tool_v1';
const tt = (k, v) => { const s = Demo.t(k, v); return s === k ? '' : s; };
const verdict = (el, ok, title, extra) => Demo.verdict(el, () => ({ ok, title: window.DemoStrings?.verdicts?.[title] ? title : Demo.t(title), ...(typeof extra === 'function' ? extra() : extra) }));
const clearVerdict = (el) => { el.__verdictArgs = null; el.innerHTML = ''; el.classList.remove('verdict', 'ok', 'bad', 'pending'); };
const A = window.Mode3Attr;
const schema = A?.DEFAULT_ATTR_SCHEMA;

// 기록 version 6(2026-11-20 사용자 결정): **salt 를 기록에 두지 않는다** — { version, schema, auid, profile, attrs, commit, createdAt }. salt 는 커밋먼트를 계산하는 동안만
// 입력 칸·메모리에 있고, 계산이 끝나면 칸도 비운다. 대신 auid = Poseidon(T_AUID2, salt)(공개값 — zkIdP 가 아는 가명)를 둔다: 지갑이 "이 기록이 내 salt 로 만든 것인가" 를
// 대조하는 데 쓴다(전에는 기록의 salt 평문으로 대조했다). 식은 version 4·5 와 같다 — 옛 4·5 기록은 열 때 auid 로 바꿔 다시 쓴다(migrateOld — salt·uid 를 지운다).
// version 1~3(옛 식)은 읽지 않고 "다시 만드세요" 를 보인다.
const REC_VERSION = 6;
const raw = () => { try { return JSON.parse(localStorage.getItem(STORE_KEY) ?? 'null'); } catch { return null; } };
const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
function load() { const v = raw(); return v && v.version === REC_VERSION && isDec(v.auid) && A?.isAttrCommit(v.commit) ? v : null; }
function save(rec) { localStorage.setItem(STORE_KEY, JSON.stringify(rec)); }
/** 옛 기록(version 4·5 — salt 평문이 들어 있다)을 version 6 으로 바꿔 쓴다. 못 바꾸면(값이 망가졌다) 기록을 지운다 — 어느 쪽이든 salt 는 남지 않는다. */
async function migrateOld() {
  const v = raw();
  if (!v || ![4, 5].includes(v.version) || !('s_u' in v)) return;
  try {
    if (!A || !isDec(v.s_u) || !A.isAttrCommit(v.commit)) throw new Error('bad record');
    const { s_u, uid, ...rest } = v;
    save({ ...rest, version: REC_VERSION, auid: (await A.auidOf({ s_u: BigInt(s_u) })).toString() });
  } catch { try { localStorage.removeItem(STORE_KEY); } catch { /* 저장소 없음 */ } }
}

// 2026-11-13(R5): 자동 암호화 백업(D20)은 없앴다 — 예전에 이 브라우저에 둔 백업 설정(파일 핸들·키)을 지운다.
try { indexedDB.deleteDatabase('zkd-attr-backup'); } catch { /* 저장소 없음 */ }

function fillCountries() {
  const sel = $('country'); sel.innerHTML = '';
  const slot = schema.slots.find((s) => s.name === 'country');
  const empty = document.createElement('option'); empty.value = ''; empty.textContent = tt('attr_country_pick') || '선택'; sel.appendChild(empty);
  for (const code of Object.keys(slot.values)) { const o = document.createElement('option'); o.value = code; o.textContent = code; sel.appendChild(o); }
}
function render() {
  const rec = load(), old = !rec && [1, 2, 3].includes(raw()?.version);
  $('commitBox').hidden = !rec; $('noCommit').hidden = !!rec; $('commitActions').hidden = !rec; $('inputsView').hidden = !rec; $('oldRecord').hidden = !old;
  if (!rec) return;
  $('commitBox').textContent = rec.commit;
  $('domainShown').textContent = String(A.DOMAIN_MODE3_ATTRC);
  // salt 는 기록에 없다(version 6) — 재료 칸에는 "저장하지 않는다" 는 말만 있고, auid 는 만들 때 계산해 둔 값을 보인다.
  $('auidShown').textContent = rec.auid;
  // 속성 칸: 슬롯 이름 · 입력값 → 해시에 들어가는 인코딩 값(attrᵢ). 미사용 슬롯(늘 0)은 보이지 않는다(2026-11-11).
  const dl = $('attrsShown'); dl.innerHTML = '';
  rec.attrs.forEach((v, i) => {
    const slot = schema.slots[i];
    if (!slot || slot.type === 'unused') return;   // 2026-11-11(사용자 결정): 입력할 수 없는 미사용 슬롯(늘 0)은 보이지 않는다 — 해시에는 그대로 0
    const input = rec.profile[slot.name];
    const dt = document.createElement('dt'); dt.textContent = `attr${'₀₁₂₃₄₅'[i]} (${slot.name})`;
    const dd = document.createElement('dd'); dd.id = `attrShown${i}`;
    const code = document.createElement('code'); code.textContent = v;
    dd.append(`${input === '' || input === undefined ? '(빈 칸)' : input} → `, code);
    dl.append(dt, dd);
  });
  $('schemaShown').textContent = `${rec.schema?.id ?? '-'} v${rec.schema?.version ?? '-'}`;
  $('createdAt').textContent = new Date(rec.createdAt).toLocaleString();
  for (const k of ['birthYear', 'country', 'extra1', 'extra2']) if (rec.profile[k] !== undefined) $(k).value = rec.profile[k];
}

$('attrForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  clearVerdict($('formVerdict'));
  if (!A) return verdict($('formVerdict'), false, 'attr_make_failed', { reason: 'bundle_missing', detail: '/attr/dist/attr.js 가 없습니다 — npm run attr:build' });
  $('makeBtn').disabled = true;
  try {
    const profile = A.normalizeProfile(schema, { birthYear: $('birthYear').value, country: $('country').value, extra1: $('extra1').value, extra2: $('extra2').value });
    // 필수 칸이 비면 인코더가 거절한다(allowEmptyRequired:false — 0 은 "값 없음" 이라 나이 술어가 뚫린다. 지갑 폼과 같은 규칙).
    const attrs = await A.encodeProfile(schema, { birthYear: '', country: '', ...profile }, { allowEmptyRequired: false });
    // salt 는 입력 칸에서(2026-11-16) — 1 이상 2^250 미만의 10진수(스냅의 salt 범위와 같다).
    const s_u = $('salt').value.trim();
    if (!s_u) throw Object.assign(new Error('salt 칸이 비어 있습니다'), { reason: 'attr_salt_required' });
    if (!isDec(s_u) || BigInt(s_u) < 1n || BigInt(s_u) >= (1n << 250n)) throw Object.assign(new Error('salt 는 1 이상 2^250 미만의 숫자여야 합니다'), { reason: 'attr_bad_salt' });
    const commit = await A.attrCommit({ s_u, attrs });
    const auid = (await A.auidOf({ s_u: BigInt(s_u) })).toString();
    // salt 는 저장하지 않는다(2026-11-20) — 기록에는 공개값(auid·커밋먼트)과 속성만. 계산이 끝났으니 입력 칸도 비운다(속성만 바꿔 다시 만들려면 salt 를 다시 붙여 넣는다).
    save({ version: REC_VERSION, schema: { id: schema.id, version: schema.version }, auid, profile, attrs, commit, createdAt: new Date().toISOString() });
    $('salt').value = '';
    render();
    verdict($('formVerdict'), true, 'attr_make_ok', { summary: tt('attr_make_ok_summary') || '커밋먼트를 만들었습니다. 아래에서 복사해 zkIdP 프로필에 붙여 넣으세요.' });
  } catch (e) {
    verdict($('formVerdict'), false, 'attr_make_failed', { reason: e.reason ?? e.detail ?? 'bad_attr', detail: e.message, ...(e.summary ? { summary: e.summary } : {}) });
  } finally { $('makeBtn').disabled = false; }
});

async function copyText(text, btn) {
  try { await navigator.clipboard.writeText(text); }
  catch { const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); } finally { ta.remove(); } }
  const prev = btn.textContent; btn.textContent = tt('rp_copied') || '복사됨';
  setTimeout(() => { btn.textContent = prev; }, 1200);
}
$('copyBtn').addEventListener('click', () => { const rec = load(); if (rec) copyText(rec.commit, $('copyBtn')); });
$('copyAuidBtn').addEventListener('click', () => { const v = $('auidShown').textContent; if (/^[0-9]+$/.test(v)) copyText(v, $('copyAuidBtn')); });
$('clearBtn').addEventListener('click', () => {
  if (!window.confirm(tt('attr_clear_confirm') || '저장된 속성·커밋먼트를 이 브라우저에서 지웁니다. 같은 salt 와 같은 속성을 넣으면 같은 커밋먼트를 다시 만들 수 있습니다. 계속할까요?')) return;
  localStorage.removeItem(STORE_KEY); render(); clearVerdict($('formVerdict')); clearVerdict($('resultVerdict'));
});

Demo.init({ page: 'attr', tour: false });
// 데모 리셋(2026-11-11, 사용자 요청): 리셋 스크립트가 /attr/dist/reset.json 에 리셋 시각을 쓴다 — 이 브라우저가 본 값과 다르면(또는 처음이면) 이전 데모의
// 기록을 비운다. 같은 오리진의 정적 파일을 읽기만 한다(속성·salt 는 어디로도 보내지 않는다). 파일이 없으면(한 머신 데모·테스트) 아무것도 하지 않는다.
const RESET_KEY = 'mode3_attr_tool_reset';
// 2026-11-16(사용자 지적 "리셋해도 초기화가 안 된다"): 전에는 옛 기록을 먼저 그린 뒤 비웠고, uid·salt 칸은 비우지 않아 옛 값이 남았다. 이제 리셋을 먼저 보고 그린다.
// 탭을 열어 둔 채 리셋한 경우를 위해 탭으로 돌아올 때도 본다.
async function checkDemoReset() {
  let epoch = null;
  // 2026-11-18: 같은 파일에 지갑 모드(walletKind)도 실려 온다 — passkey-web 이면 이 화면도 "스냅" 대신 "zk 클라이언트" 로 그린다(이 도구는 상태 조회를 부르지 않는다).
  try { const r = await fetch('/attr/dist/reset.json', { cache: 'no-store' }); if (r.ok) { const j = await r.json(); epoch = String(j.epoch ?? ''); if (typeof j.walletKind === 'string') Demo.setWalletKind?.(j.walletKind); } } catch { epoch = null; }
  if (!epoch) return false;
  let seen = null; try { seen = localStorage.getItem(RESET_KEY); } catch { return false; }
  if (seen === epoch) return false;
  const had = raw() !== null;
  try { localStorage.removeItem(STORE_KEY); localStorage.setItem(RESET_KEY, epoch); } catch { return false; }
  for (const id of ['birthYear', 'country', 'extra1', 'extra2', 'salt']) if ($(id)) $(id).value = '';
  if (had) $('resetCleared').hidden = false;
  return true;
}
if (schema) fillCountries();
checkDemoReset().catch(() => false).then(() => migrateOld()).catch(() => {}).then(() => render());
document.addEventListener('visibilitychange', () => { if (!document.hidden) checkDemoReset().then((cleared) => { if (cleared) { render(); clearVerdict($('formVerdict')); clearVerdict($('resultVerdict')); } }).catch(() => {}); });
