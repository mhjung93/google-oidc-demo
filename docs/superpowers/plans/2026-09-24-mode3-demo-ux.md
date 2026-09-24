# Mode 3 데모 UX 개선(1차) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mode 3 데모 페이지 넷을 "개발자 콘솔"에서 세 청중(발표·개발자·혼자 체험)용 화면으로 바꾼다 — 공통 안내 바(7단계), 카드 레이아웃, 쉬운 용어 + 전문가 보기, 오류 사유의 원인·조치 번역, 한·영 토글.

**Architecture:** 새 `mode3/common/`(css·문구 사전·공통 JS)을 세 서버가 `/common`으로 서빙한다. 네 페이지는 기존 id·판정 문구·API 호출을 그대로 둔 채 마크업을 카드로 재구성하고 `Demo.*`를 호출한다. 서버는 정적 서빙 한 줄과 `ciaUrl` 응답 필드만 추가한다.

**Tech Stack:** 순수 HTML/CSS/JS(전역 스크립트, 빌드·의존성 없음), express.static, Node `vm`(사전 단위 테스트), Playwright(`@playwright/test` 이미 설치, Chrome `channel:'chrome'`).

**Spec:** `docs/superpowers/specs/2026-09-24-mode3-demo-ux-design.md`

## Global Constraints

- **테스트 계약**: `tests/test_mode3_browser.mjs`·`tests/test_mode3_demo_stack.mjs`·`tests/test_mode3_wallet_snap.mjs`는 **수정 없이** 통과해야 한다. 지갑 id `#connectBtn #mmStatus #snapPanel #fileRegFields #uid #pwd #registerBtn #registerResult #refreshBtn #status #sessionActions #sessionLog #txSession #txTo #txData #dk0 #discLo0 #discHi0 #setSlot #txBtn #txVerdict #txLog #forgedBtn`, 서비스 id `#walletMode #allowAgent #loginBtn #verdict #log #sessionId #revalidateBtn #skipSync #requestBtn #sessionVerdict #sessionLog`, 판정 문구 '로그인 성공' '등록됨' '전송 성공' '재검증 성공' '재승인 불가' '팝업이 차단됐다' '지갑 비밀=snap' `user_denied` `factory_constants_unavailable` 는 그대로(요소 `textContent`에 포함돼야 한다 — 숨겨도 된다, 제거는 안 된다). `window.__snapOnRpcRequest` 주입 경로 불변.
- 새 의존성·빌드 없음. 공통 파일은 전역 스크립트(`window.DemoStrings`, `window.Demo`).
- 기본 언어 `ko`, 전문가 보기 기본 off. 둘 다 `localStorage` 키 `mode3.lang`, `mode3.expert`(읽기·쓰기는 try/catch).
- 서버 변경은 `/common` 정적 서빙 3줄 + `rp_info`·`/wallet/status` 응답의 `ciaUrl` 필드뿐. 검증·발급·폐기 로직 불변.
- 사유 사전 문구는 `docs/MODE3_DEMO.md` 사유 표와 해당 소스의 실제 발생 조건을 확인해 쓴다. 사전에 없는 코드는 코드 그대로 + '자세히'.
- 파괴적 버튼(폐기·초기화·게시)은 `.danger` + `Demo.confirmDanger()` 한 번.
- 커밋 메시지 한글 + 트레일러 두 줄(세션 규칙). `.env`·`*_keys.json`·`*_state.json` 은 읽지 않는다. hardhat 노드는 스스로 띄우고(`> /dev/null 2>&1 &`) 끝나면 그 PID만 종료, :8545·:3000·:4000·:5001 비었는지 확인.

---

## 파일 구조

| 파일 | 책임 | 작업 |
|---|---|---|
| `mode3/common/strings.js` | 문구 사전(ui·terms·steps·verdicts·reasons) ko/en | T1 |
| `mode3/common/demo.js` | `Demo.init/t/guide/verdict/reason/call/confirmDanger/setLang/setExpert` | T1 |
| `mode3/common/demo.css` | 디자인 토큰·카드·배지·버튼·안내 바·표·스피너·`.expert`·반응형 | T1 |
| `tests/test_mode3_demo_strings.js` | 사전 완전성·needle 일치 (unit) | T1 |
| `cia.js`, `mode3_rp.js`, `mode3_wallet_agent.js` | `/common` 서빙, `ciaUrl` | T1 |
| `mode3/rp.html` | 서비스 페이지 재구성 | T2 |
| `mode3/wallet.html` | 지갑 페이지 재구성 | T3 |
| `mode3/cia_admin.html`, `mode3/cia_account.html` | 관리자·계정 페이지 재구성 | T4 |
| `scripts/screenshot_mode3.mjs`, `results/mode3_ux_20260924/`, `docs/MODE3_DEMO.md` | 스크린샷·문서·전체 검증 | T5 |

---

### Task 1: 공통 레이어 — 사전·`Demo`·CSS·서버 서빙·단위 테스트

**Files:**
- Create: `mode3/common/strings.js`, `mode3/common/demo.js`, `mode3/common/demo.css`, `tests/test_mode3_demo_strings.js`
- Modify: `cia.js`(≈251, `/admin` sendFile 근처), `mode3_rp.js`(≈282·284), `mode3_wallet_agent.js`(≈242, `/wallet/status` 핸들러), `scripts/run_tests.sh`(UNIT 배열)

**Interfaces (Produces — T2~T4가 그대로 쓴다):**
```js
window.DemoStrings = {
  langs: ['ko', 'en'],
  ui:       { [key]: { ko, en } },                       // 라벨·카드 제목·설명·버튼·힌트
  terms:    { [name]: { ko, en, expert } },              // PPID, AA, session, root, proof, disclosure, cred, tag, allowAgent, attr0..attr3
  steps:    [ { key, ko: { title, hint }, en: { title, hint }, where: ['admin'|'wallet'|'rp'|'account'] } ],  // 7개, 순서 고정
  verdicts: { [key]: { ko, en } },                       // 판정 문구(테스트 needle 포함)
  reasons:  { [code]: { where, ko: { title, cause, action }, en: { title, cause, action } } },
};
window.Demo = {
  init({ page }),                        // page: 'wallet'|'rp'|'admin'|'account'. #demoBar 렌더, data-i18n 채움, 저장된 lang/expert 복원
  t(key, vars),                          // ui[key][lang] 에 {name} 치환. 없으면 key 그대로
  term(name),                            // terms[name][lang]; 전문가 모드면 ` (expert)` 를 덧붙인다
  guide({ done, current, hint, links }), // done: 단계 키 배열, current: 키, hint: ui 키, links: { wallet?, rp?, admin?, account? }
  verdict(el, { ok, title, summary, reason, detail, pending }),  // 결과 카드. title 은 verdict 키 또는 원문. el.textContent 에 title 이 포함된다
  reason(code),                          // { title, cause, action } | null
  call(el, hintKey, fn),                 // el 에 스피너+힌트 표시 → fn() → 결과 반환; throw 면 verdict(el,{ok:false,...}) 뒤 rethrow
  confirmDanger(key, vars),              // window.confirm(t(key)) 결과
  setLang(l), setExpert(b), lang, expert,
};
```

- [ ] **Step 1: 실패하는 단위 테스트** — `tests/test_mode3_demo_strings.js`

```js
// 문구 사전(mode3/common/strings.js)의 완전성. 전역 스크립트라 vm 으로 window 를 흉내 내 읽는다. node tests/test_mode3_demo_strings.js
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const src = fs.readFileSync(new URL('../mode3/common/strings.js', import.meta.url), 'utf8');
const window = {};
vm.runInNewContext(src, { window });
const S = window.DemoStrings;

let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

// browser 테스트(tests/test_mode3_browser.mjs)가 잡는 한국어 판정 문구 — 사전의 ko 값이 이것과 글자 그대로 같아야 한다.
const NEEDLES = { login_ok: '로그인 성공', registered: '등록됨', tx_ok: '전송 성공', reval_ok: '재검증 성공', reauth_denied: '재승인 불가', popup_blocked: '팝업이 차단됐다' };
// 문서(docs/MODE3_DEMO.md)에 있는 사유 코드 — 전부 ko·en 세 줄(title·cause·action)이 있어야 한다.
const REASONS = ['stale_root', 'root_too_old', 'revalidate_required', 'predicate_unmet', 'factory_constants_unavailable', 'registration_pending', 'bad_signature', 'bad_rp_cert', 'bad_proof', 'expired', 'malformed',
  'revoked', 'revoked_session', 'account_disabled', 'needs_consent', 'bad_factory', 'no_code', 'factory_code_mismatch', 'verifier_code_mismatch', 'allow_agent_mismatch', 'no_session', 'not_registered', 'cia_unavailable', 'witness_required', 'internal',
  'user_denied', 'snap_unavailable', 'wallet_error', 'unknown_session', 'no_user_cred'];

t('langs 는 ko, en', () => assert.deepEqual(S.langs, ['ko', 'en']));
t('steps 는 7개, 키 고유, 순서 approve→register→login→use→disclose→revoke→open, 각 언어에 title·hint', () => {
  assert.deepEqual(S.steps.map((s) => s.key), ['approve', 'register', 'login', 'use', 'disclose', 'revoke', 'open']);
  for (const s of S.steps) for (const l of S.langs) { assert.ok(s[l]?.title, `${s.key}.${l}.title`); assert.ok(s[l]?.hint, `${s.key}.${l}.hint`); }
  for (const s of S.steps) assert.ok(Array.isArray(s.where) && s.where.length > 0, `${s.key}.where`);
});
t('판정 문구 ko 는 browser 테스트 needle 과 같다', () => { for (const [k, v] of Object.entries(NEEDLES)) assert.equal(S.verdicts[k]?.ko, v, k); });
t('판정 문구는 전부 en 도 있다', () => { for (const [k, v] of Object.entries(S.verdicts)) assert.ok(v.en, k); });
t('사유 사전은 문서의 코드를 전부 덮고 ko·en 에 title·cause·action 이 있다', () => {
  for (const c of REASONS) {
    const r = S.reasons[c]; assert.ok(r, `reasons.${c} 없음`);
    assert.ok(['rp', 'wallet', 'page', 'aa'].includes(r.where), `${c}.where`);
    for (const l of S.langs) for (const f of ['title', 'cause', 'action']) assert.ok(r[l]?.[f], `${c}.${l}.${f}`);
  }
});
t('ui·terms 항목은 전부 ko·en 이 있고 빈 문자열이 없다', () => {
  for (const [k, v] of Object.entries(S.ui)) for (const l of S.langs) assert.ok(typeof v[l] === 'string' && v[l].length, `ui.${k}.${l}`);
  for (const [k, v] of Object.entries(S.terms)) { for (const l of S.langs) assert.ok(v[l], `terms.${k}.${l}`); assert.ok(v.expert, `terms.${k}.expert`); }
  for (const n of ['PPID', 'AA', 'session', 'root', 'proof', 'disclosure', 'cred', 'tag', 'allowAgent', 'attr0', 'attr1', 'attr2', 'attr3']) assert.ok(S.terms[n], `terms.${n}`);
});
t('ui 에 안내 바·토글·공통 버튼 키가 있다', () => {
  for (const k of ['bar_next', 'bar_other_window', 'toggle_lang', 'toggle_expert', 'details', 'working', 'proving', 'confirm_revoke', 'confirm_publish', 'confirm_reset', 'go_wallet', 'go_rp', 'go_admin', 'go_account']) assert.ok(S.ui[k], k);
});
if (fails) { console.log(`\n${fails} FAIL`); process.exit(1); } else console.log('\nall ok');
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_demo_strings.js` → 파일 없음 오류.

- [ ] **Step 3: `mode3/common/strings.js`** — 아래 골격을 채운다. `ui`는 T2~T4가 쓸 키를 여기서 **미리** 넣는다(페이지 작업자가 키를 추가해도 된다 — 테스트는 존재하는 키의 ko·en만 검사).

```js
// Mode 3 데모 문구 사전 — 설계 2026-09-24-mode3-demo-ux-design.md §3. 전역 스크립트(빌드 없음).
// 규칙: verdicts.*.ko 는 tests/test_mode3_browser.mjs 의 needle 과 글자 그대로 같아야 한다(tests/test_mode3_demo_strings.js 가 검사).
// reasons.*.{cause,action} 은 docs/MODE3_DEMO.md 사유 표와 소스의 실제 발생 조건을 보고 쓴다 — 추측 금지.
window.DemoStrings = {
  langs: ['ko', 'en'],
  ui: {
    // 안내 바·토글
    bar_next: { ko: '다음: {where}에서 {what}', en: 'Next: {what} on {where}' },
    bar_other_window: { ko: '다른 창에서 진행', en: 'In another window' },
    toggle_lang: { ko: 'EN', en: '한국어' },
    toggle_expert: { ko: '전문가 보기', en: 'Expert view' },
    details: { ko: '자세히', en: 'Details' },
    working: { ko: '처리 중…', en: 'Working…' },
    proving: { ko: '영지식 증명 생성 중(약 1초)…', en: 'Generating zero-knowledge proof (~1 s)…' },
    go_wallet: { ko: '지갑 열기', en: 'Open wallet' }, go_rp: { ko: '서비스 열기', en: 'Open service' },
    go_admin: { ko: '신원 기관 관리자 열기', en: 'Open authority admin' }, go_account: { ko: '내 계정 페이지 열기', en: 'Open my account page' },
    where_wallet: { ko: '지갑', en: 'the wallet' }, where_rp: { ko: '서비스', en: 'the service' }, where_admin: { ko: '신원 기관 관리자', en: 'the authority admin' }, where_account: { ko: '내 계정 페이지', en: 'my account page' },
    confirm_revoke: { ko: '되돌릴 수 없습니다. 폐기할까요?', en: 'This cannot be undone. Revoke?' },
    confirm_publish: { ko: '폐기 목록을 체인에 게시합니다. 계속할까요?', en: 'Publish the revocation list on-chain. Continue?' },
    confirm_reset: { ko: 'Snap 의 등록 비밀과 동의 기록을 지웁니다. 계속할까요?', en: 'Erase the Snap’s registration secrets and consents. Continue?' },
    // 페이지 제목·카드 제목·설명 — T2~T4 가 쓴다(키 이름 = 페이지_카드_역할)
    wallet_title: { ko: 'Mode 3 지갑', en: 'Mode 3 Wallet' },
    wallet_identity_title: { ko: '내 신원', en: 'My identity' },
    wallet_identity_desc: { ko: '신원 기관에 한 번 등록합니다. 속성은 기관이 관리하고 지갑은 읽기만 합니다.', en: 'Register once with the identity authority. Attributes are managed by the authority; the wallet only reads them.' },
    wallet_sessions_title: { ko: '로그인 세션', en: 'Login sessions' },
    wallet_sessions_desc: { ko: '서비스마다 다른 주소로 로그인합니다. 세션 하나만 끝낼 수도 있습니다.', en: 'You log in with a different address per service. A single session can be ended on its own.' },
    wallet_tx_title: { ko: '트랜잭션 보내기', en: 'Send a transaction' },
    wallet_tx_desc: { ko: '이 서비스 전용 주소에서 보냅니다. 필요하면 속성 조건만 골라 공개합니다.', en: 'Sent from your service-specific address. Optionally reveal only chosen attribute conditions.' },
    wallet_snap_title: { ko: 'MetaMask · Snap', en: 'MetaMask · Snap' },
    wallet_snap_desc: { ko: '비밀은 Snap 안에 있습니다. 이 페이지는 동의만 받습니다.', en: 'Secrets live inside the Snap. This page only collects consent.' },
    wallet_auth_title: { ko: '로그인 승인', en: 'Approve login' },
    rp_title: { ko: 'Mode 3 서비스', en: 'Mode 3 Service' },
    rp_status_title: { ko: '서비스 상태', en: 'Service status' },
    rp_login_title: { ko: '로그인', en: 'Log in' },
    rp_login_desc: { ko: '지갑이 신원 기관의 서명과 영지식 증명으로 이 서비스 전용 주소를 만듭니다. 신원 기관은 어느 서비스인지 모릅니다.', en: 'The wallet derives a service-specific address from the authority’s signature and a zero-knowledge proof. The authority never learns which service.' },
    rp_session_title: { ko: '내 세션', en: 'My session' },
    rp_logins_title: { ko: '로그인 기록', en: 'Login records' },
    rp_open_title: { ko: '승인 개봉', en: 'Authorized opening' },
    rp_open_desc: { ko: '서비스와 신원 기관이 함께, 운영자 승인 아래에서만 사용자를 알아냅니다.', en: 'Only the service and the authority together, with operator approval, can identify the user.' },
    admin_title: { ko: 'Mode 3 신원 기관 관리자', en: 'Mode 3 Authority Admin' },
    admin_pending_rps: { ko: '승인 대기 서비스 {n}', en: '{n} services awaiting approval' },
    admin_pending_openings: { ko: '개봉 요청 {n}', en: '{n} opening requests' },
    admin_accounts_title: { ko: '계정', en: 'Accounts' }, admin_rps_title: { ko: '서비스', en: 'Services' }, admin_openings_title: { ko: '개봉 요청', en: 'Opening requests' }, admin_rcl_title: { ko: '폐기 목록', en: 'Revocation list' },
    account_title: { ko: 'Mode 3 내 계정', en: 'Mode 3 My Account' },
    account_revoke_title: { ko: '내 계정 폐기', en: 'Revoke my account' },
    account_revoke_desc: { ko: '기기를 잃었을 때 비밀번호만으로 계정을 폐기합니다. 지갑 키는 필요 없습니다.', en: 'Revoke your account with just the password, e.g. after losing a device. No wallet key needed.' },
    // 단계 힌트(안내 바 "다음" 문장의 {what})
    hint_approve: { ko: '등록된 서비스를 승인', en: 'approve the registered service' },
    hint_register: { ko: '지갑 등록', en: 'register the wallet' },
    hint_login: { ko: '로그인', en: 'log in' },
    hint_use: { ko: '재검증·세션 요청 또는 트랜잭션', en: 'revalidate, make a request, or send a transaction' },
    hint_disclose: { ko: '속성 조건을 골라 트랜잭션 또는 조건 요구 로그인', en: 'send a transaction with attribute conditions, or log in with a required predicate' },
    hint_revoke: { ko: '세션 하나 또는 계정 폐기 → 게시', en: 'revoke one session or the account → publish' },
    hint_open: { ko: '개봉 요청 → 관리자 승인 → 결과 확인', en: 'request opening → admin approves → read result' },
  },
  terms: {
    PPID: { ko: '이 서비스에서의 내 주소', en: 'My address at this service', expert: 'PPID = Poseidon(uid, s_u, chainid, arid)' },
    AA: { ko: '신원 기관', en: 'Identity authority', expert: 'AA / CIA, pk_CIA' },
    session: { ko: '로그인 세션', en: 'Login session', expert: 'r_s, pk_i, max_height' },
    root: { ko: '폐기 목록 버전', en: 'Revocation list version', expert: 'root, epoch, age(blocks)' },
    proof: { ko: '영지식 증명', en: 'Zero-knowledge proof', expert: 'π_rp (Groth16), prove ms, cache hit' },
    disclosure: { ko: '공개할 속성 조건', en: 'Attribute conditions to reveal', expert: 'disc_mask, lo[4], hi[4], set_sel, set_root' },
    cred: { ko: '내 자격증명', en: 'My credential', expert: 'C_u → Cf_u; session ticket C_s → Cf_s' },
    tag: { ko: '추적용 봉인', en: 'Sealed trace', expert: 'tag = (c1, c2) under pk_trace' },
    allowAgent: { ko: 'AI 에이전트 허용', en: 'Allow AI agent', expert: 'allowAgent ∈ {0,1}' },
    attr0: { ko: '출생연도', en: 'Birth year', expert: 'attrs[0] (a₁), 64-bit' },
    attr1: { ko: '국가', en: 'Country', expert: 'attrs[1] (a₂), ISO 3166 numeric' },
    attr2: { ko: '등급', en: 'Tier', expert: 'attrs[2] (a₃)' },
    attr3: { ko: '예비', en: 'Spare', expert: 'attrs[3] (a₄)' },
  },
  steps: [
    { key: 'approve', where: ['admin'], ko: { title: '서비스 승인', hint: '신원 기관 운영자가 서비스 등록을 승인합니다.' }, en: { title: 'Approve service', hint: 'The authority operator approves the service registration.' } },
    { key: 'register', where: ['wallet'], ko: { title: '지갑 등록', hint: '지갑이 신원 기관에 한 번 등록하고 자격증명을 받습니다.' }, en: { title: 'Register wallet', hint: 'The wallet registers once and receives a credential.' } },
    { key: 'login', where: ['rp'], ko: { title: '로그인', hint: '서비스 전용 주소로 로그인합니다.' }, en: { title: 'Log in', hint: 'Log in with a service-specific address.' } },
    { key: 'use', where: ['rp', 'wallet'], ko: { title: '이용', hint: '세션을 재검증하거나 요청·트랜잭션을 보냅니다.' }, en: { title: 'Use', hint: 'Revalidate the session, make a request, or send a transaction.' } },
    { key: 'disclose', where: ['wallet', 'rp'], ko: { title: '공개·조건', hint: '속성 조건만 골라 공개합니다.' }, en: { title: 'Disclose', hint: 'Reveal only chosen attribute conditions.' } },
    { key: 'revoke', where: ['wallet', 'account', 'admin'], ko: { title: '폐기·복구', hint: '세션 하나 또는 계정을 폐기하고 게시합니다.' }, en: { title: 'Revoke & recover', hint: 'Revoke one session or the account, then publish.' } },
    { key: 'open', where: ['rp', 'admin'], ko: { title: '승인 개봉', hint: '서비스와 기관이 함께 사용자를 알아냅니다.' }, en: { title: 'Authorized opening', hint: 'Service and authority identify the user together.' } },
  ],
  verdicts: {
    login_ok: { ko: '로그인 성공', en: 'Login succeeded' },
    registered: { ko: '등록됨', en: 'Registered' },
    tx_ok: { ko: '전송 성공', en: 'Sent' },
    reval_ok: { ko: '재검증 성공', en: 'Revalidated' },
    reauth_denied: { ko: '재승인 불가', en: 'Re-approval not possible' },
    popup_blocked: { ko: '팝업이 차단됐다', en: 'Popup was blocked' },
    request_ok: { ko: '세션 요청 성공', en: 'Request accepted' },
    revoked_ok: { ko: '폐기 요청 접수', en: 'Revocation accepted' },
    login_failed: { ko: '로그인 실패', en: 'Login failed' },
    reval_failed: { ko: '재검증 실패', en: 'Revalidation failed' },
    tx_failed: { ko: '전송 실패', en: 'Send failed' },
  },
  reasons: {
    // where: 'rp' | 'wallet' | 'page' | 'aa'. 예시 두 개 — 나머지는 같은 꼴로 docs/MODE3_DEMO.md 사유 표를 보고 채운다.
    stale_root: { where: 'rp', ko: { title: '폐기 목록이 오래됐습니다', cause: '지갑이 최신 폐기 목록으로 증명하지 않았습니다.', action: '"동기화 생략"을 끄고 다시 재검증하세요.' }, en: { title: 'Revocation list is stale', cause: 'The wallet did not prove against the latest revocation list.', action: 'Turn off "skip sync" and revalidate again.' } },
    revoked_session: { where: 'wallet', ko: { title: '이 세션은 폐기됐습니다', cause: '이 로그인 세션만 폐기 목록에 올라 게시됐습니다. 다른 세션과 계정은 그대로입니다.', action: '서비스에서 다시 로그인하세요.' }, en: { title: 'This session was revoked', cause: 'Only this login session was published on the revocation list. Other sessions and the account are intact.', action: 'Log in again at the service.' } },
    // …stale_root 와 같은 꼴로: root_too_old, revalidate_required, predicate_unmet, factory_constants_unavailable, registration_pending, bad_signature, bad_rp_cert, bad_proof, expired, malformed,
    //   revoked, account_disabled, needs_consent, bad_factory, no_code, factory_code_mismatch, verifier_code_mismatch, allow_agent_mismatch, no_session, not_registered, cia_unavailable, witness_required, internal,
    //   user_denied, snap_unavailable, wallet_error, unknown_session, no_user_cred
  },
};
```

- [ ] **Step 4: `mode3/common/demo.js`**

```js
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
    setLang(l) { if (!S.langs.includes(l)) return; D.lang = l; store.set('mode3.lang', l); document.documentElement.lang = l; D.applyI18n(); if (D.lastGuide) D.guide(D.lastGuide); },
    setExpert(b) { D.expert = !!b; store.set('mode3.expert', b ? '1' : '0'); document.documentElement.toggleAttribute('data-expert', D.expert); if (D.lastGuide) D.guide(D.lastGuide); },
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
      const cur = S.steps.find((s) => s.key === g.current);
      if (cur) {
        const p = document.createElement('p'); p.className = 'hint'; p.textContent = cur[D.lang].hint; next.appendChild(p);
        const whereKey = cur.where.includes(D.page) ? D.page : cur.where[0];
        const q = document.createElement('p'); q.className = 'next';
        q.textContent = D.t('bar_next', { where: D.t(`where_${whereKey}`), what: D.t(g.hint || `hint_${cur.key}`) }); next.appendChild(q);
        if (whereKey !== D.page && g.links?.[whereKey]) { const a = document.createElement('a'); a.className = 'btn'; a.href = g.links[whereKey]; a.target = '_blank'; a.rel = 'noopener'; a.textContent = D.t(`go_${whereKey}`); next.appendChild(a); }
      }
      for (const [k, url] of Object.entries(g.links || {})) { if (k === D.page || !url) continue; if (next.querySelector(`a[href="${url}"]`)) continue; const a = document.createElement('a'); a.className = 'btn-ghost'; a.href = url; a.target = '_blank'; a.rel = 'noopener'; a.textContent = D.t(`go_${k}`); next.appendChild(a); }
    },
    verdict(el, { ok, title, summary, reason, detail, pending }) {
      el.innerHTML = ''; el.className = 'verdict ' + (pending ? 'pending' : ok ? 'ok' : 'bad');
      const badge = document.createElement('span'); badge.className = 'badge'; badge.textContent = pending ? '…' : ok ? '✓' : '✕'; el.appendChild(badge);
      const h = document.createElement('strong'); h.textContent = S.verdicts[title] ? D.verdictText(title) : (title ?? ''); el.appendChild(h);
      const r = reason ? D.reason(reason) : null;
      if (summary || r) { const p = document.createElement('p'); p.className = 'summary'; p.textContent = summary ?? r.title; el.appendChild(p); }
      if (r && !ok) { const c = document.createElement('p'); c.className = 'cause'; c.textContent = r.cause; el.appendChild(c); const a = document.createElement('p'); a.className = 'action'; a.textContent = r.action; el.appendChild(a); }
      if (reason && !r) { const code = document.createElement('code'); code.textContent = reason; el.appendChild(code); }   // 사전에 없는 코드는 그대로
      if (detail !== undefined) { const d = document.createElement('details'); if (D.expert) d.open = true; const s = document.createElement('summary'); s.textContent = D.t('details'); d.appendChild(s); const pre = document.createElement('pre'); pre.textContent = typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2); d.appendChild(pre); el.appendChild(d); }
    },
    async call(el, hintKey, fn) {
      if (el) D.verdict(el, { pending: true, title: D.t(hintKey || 'working') });
      try { return await fn(); }
      catch (e) { if (el) D.verdict(el, { ok: false, title: e.title ?? 'error', reason: e.reason, detail: e.detail ?? e.message }); throw e; }
    },
    confirmDanger(key, vars) { return window.confirm(D.t(key, vars)); },
  };
  window.Demo = D;
})();
```

- [ ] **Step 5: `mode3/common/demo.css`** — 토큰·구성요소. 클래스: `.cards`(그리드), `.card`(+`.card h3`, `.card .desc`), `.badge`(+`.ok .bad .warn .muted`), `.btn .btn-ghost .danger`, `#demoBar`(+`.bar-steps .step .done .current .elsewhere .n .label`, `.bar-next .hint .next`, `.bar-tools .switch`), `.verdict`(+`.ok .bad .pending .summary .cause .action details pre`), `table.list`, `.spinner`, `.expert`(기본 `display:none`; `html[data-expert] .expert{display:revert}`), `.kv`(라벨·값 줄). 반응형: `.cards{grid-template-columns:1fr}` 기본, `@media (min-width:901px){.cards{grid-template-columns:1fr 1fr}}`, 카드에 `.span2` 로 두 칸.

```css
:root { --bg:#f7f8fa; --card:#fff; --ink:#1d2433; --muted:#5f6b7a; --line:#e3e7ee; --ok:#1b7f3b; --bad:#b3261e; --warn:#b26a00; --accent:#2455c3; --danger:#b3261e; --radius:12px; --gap:16px; }
* { box-sizing:border-box } body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans KR",sans-serif }
main.cards { display:grid; grid-template-columns:1fr; gap:var(--gap); max-width:1100px; margin:0 auto; padding:var(--gap) }
@media (min-width:901px) { main.cards { grid-template-columns:1fr 1fr } .card.span2 { grid-column:1 / -1 } }
.card { background:var(--card); border:1px solid var(--line); border-radius:var(--radius); padding:18px 20px }
.card h3 { margin:0 0 4px; font-size:17px } .card .desc { margin:0 0 12px; color:var(--muted); font-size:14px }
.badge { display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:600; background:#e9edf5; color:var(--ink) }
.badge.ok { background:#e3f4e8; color:var(--ok) } .badge.bad { background:#fbe6e4; color:var(--bad) } .badge.warn { background:#fff1dc; color:var(--warn) }
button, .btn { font:inherit; padding:8px 14px; border-radius:8px; border:1px solid var(--accent); background:var(--accent); color:#fff; cursor:pointer; text-decoration:none; display:inline-block }
button:disabled { opacity:.5; cursor:not-allowed } .btn-ghost { background:transparent; color:var(--accent) } .danger { background:transparent; color:var(--danger); border-color:var(--danger) }
input[type=text], input:not([type]), input[type=password], input[type=number], select, textarea { font:inherit; padding:6px 8px; border:1px solid var(--line); border-radius:8px }
#demoBar { position:sticky; top:0; z-index:5; background:var(--card); border-bottom:1px solid var(--line); padding:10px var(--gap); display:grid; grid-template-columns:1fr auto; gap:6px 16px; align-items:center }
.bar-steps { display:flex; flex-wrap:wrap; gap:6px } .step { display:flex; align-items:center; gap:6px; padding:4px 10px; border-radius:999px; border:1px solid var(--line); font-size:13px; color:var(--muted) }
.step .n { width:20px; height:20px; border-radius:50%; background:#e9edf5; display:grid; place-items:center; font-size:12px; font-weight:700 }
.step.done { color:var(--ok); border-color:#bfe3c9 } .step.done .n { background:#e3f4e8 } .step.current { color:var(--accent); border-color:var(--accent); font-weight:600 } .step.current .n { background:var(--accent); color:#fff } .step.elsewhere { opacity:.6 }
.bar-next { grid-column:1; display:flex; flex-wrap:wrap; gap:10px; align-items:center; font-size:14px } .bar-next .hint { margin:0; color:var(--muted) } .bar-next .next { margin:0; font-weight:600 }
.bar-tools { grid-column:2; grid-row:1 / span 2; display:flex; gap:12px; align-items:center } .switch { display:flex; gap:6px; align-items:center; font-size:13px; color:var(--muted) }
.verdict { margin-top:10px; padding:10px 12px; border-radius:10px; border:1px solid var(--line); background:#fafbfd } .verdict .badge { margin-right:8px }
.verdict.ok { border-color:#bfe3c9 } .verdict.bad { border-color:#f1c2be } .verdict.pending strong::after { content:''; display:inline-block; width:12px; height:12px; margin-left:8px; border:2px solid var(--accent); border-right-color:transparent; border-radius:50%; animation:spin .8s linear infinite; vertical-align:middle }
@keyframes spin { to { transform:rotate(360deg) } } .verdict p { margin:6px 0 0 } .verdict .cause { color:var(--muted) } .verdict .action { font-weight:600 } .verdict details { margin-top:6px } .verdict pre, pre { background:#f2f4f8; padding:8px 10px; border-radius:8px; white-space:pre-wrap; font-size:12.5px; margin:6px 0 0 }
table.list { width:100%; border-collapse:collapse; font-size:14px } table.list th, table.list td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top }
.kv { display:grid; grid-template-columns:auto 1fr; gap:4px 12px; font-size:14px } .kv dt { color:var(--muted) } .kv dd { margin:0; overflow-wrap:anywhere }
.muted { color:var(--muted); font-size:13px } .expert { display:none } html[data-expert] .expert { display:revert } .hidden, [hidden] { display:none !important }
```

- [ ] **Step 6: 서버 3곳 + `ciaUrl`**
  - `cia.js` `/admin` sendFile 줄 위: `app.use('/common', express.static(path.join(__dirname, 'mode3', 'common')));` (`path`·`express` 는 이미 import 되어 있다 — 확인).
  - `mode3_rp.js` `app.get('/'` 줄 위: 같은 한 줄. `rp_info` 응답 객체에 `ciaUrl: CIA_URL` 추가.
  - `mode3_wallet_agent.js` `app.get('/'` 줄 위: 같은 한 줄. `/wallet/status` 의 `res.json({...})` 에 `ciaUrl: CIA_URL` 추가(핸들러 안에서 응답 객체를 만드는 줄을 찾아 필드 하나 추가).
  - `scripts/run_tests.sh` UNIT 배열 끝에 `tests/test_mode3_demo_strings.js`.

- [ ] **Step 7: 통과 확인** — `node tests/test_mode3_demo_strings.js` all ok(모든 REASONS 를 채워야 통과한다 — 문구는 `docs/MODE3_DEMO.md` 의 사유 표를 읽고 쓴다); `bash scripts/run_tests.sh unit` 통과; `node -e "import('./mode3_rp.js')"` 같은 기동 확인 대신 `bash scripts/run_tests.sh chain` 중 `tests/test_mode3_demo_stack.mjs` 하나만 실행해 `rp_info.ciaUrl` 가 있어도 기존 케이스가 그대로 통과함을 본다(:8545 필요).
- [ ] **Step 8: 커밋** — `feat(mode3-ui): 공통 안내 레이어 — 문구 사전(ko/en)·Demo(안내 바·결과 카드·사유 번역)·CSS, /common 서빙, ciaUrl`

---

### Task 2: 서비스 페이지 `rp.html`

**Files:** Modify `mode3/rp.html`
**Interfaces:** Consumes T1 `Demo.*`·`DemoStrings`. id·판정 문구 계약(Global Constraints) 유지.

- [ ] **Step 1: 기준선** — hardhat 노드 띄우고 `node tests/test_mode3_browser.mjs` 가 지금 통과하는지 확인(기준선; 실패하면 원인을 보고하고 멈춘다).

- [ ] **Step 2: 마크업 재구성** — `<head>` 의 인라인 `<style>` 을 지우고 `<link rel="stylesheet" href="/common/demo.css">` + 두 `<script src="/common/…">`. `<body>` 를 아래 골격으로. **id 는 전부 유지**하고 `<pre id="log">`·`<pre id="sessionLog">`·`<pre id="openLog">` 는 `class="expert"`, `#skipSync` 라벨은 `class="expert"`.

```html
<body data-page="rp">
<header id="demoBar"></header>
<main class="cards">
  <section class="card span2">
    <h3 data-i18n="rp_status_title"></h3>
    <p><span id="rpStatusBadge" class="badge"></span> <span id="walletMode" class="badge"></span></p>
    <p id="rpInfo" class="muted"></p>
    <p id="attrGateInfo" class="muted"></p>
  </section>
  <section class="card">
    <h3 data-i18n="rp_login_title"></h3><p class="desc" data-i18n="rp_login_desc"></p>
    <label><input type="checkbox" id="allowAgent" /> <span data-term="allowAgent"></span></label><br />
    <label><input type="checkbox" id="requirePred" /> <span id="requirePredLabel"></span></label><br />
    <button id="loginBtn" data-i18n="rp_login_btn"></button>
    <div id="verdict"></div>
    <pre id="log" class="expert"></pre>
  </section>
  <section class="card">
    <h3 data-i18n="rp_session_title"></h3>
    <dl class="kv"><dt data-term="session"></dt><dd><code id="sessionId">(없음)</code></dd></dl>
    <button id="revalidateBtn" disabled data-i18n="rp_reval_btn"></button>
    <button id="requestBtn" disabled data-i18n="rp_request_btn"></button>
    <label class="expert"><input type="checkbox" id="skipSync" /> skipSync (stale_root 시연)</label>
    <div id="sessionVerdict"></div>
    <pre id="sessionLog" class="expert"></pre>
  </section>
  <section class="card span2">
    <h3 data-i18n="rp_logins_title"></h3>
    <button id="refreshLogins" class="btn-ghost" data-i18n="refresh"></button>
    <div id="logins"></div>
  </section>
  <section class="card span2">
    <h3 data-i18n="rp_open_title"></h3><p class="desc" data-i18n="rp_open_desc"></p>
    <label><span data-term="PPID"></span> <input id="openPpid" size="24" /></label> <button id="openBtn" data-i18n="rp_open_req"></button> <button id="openPollBtn" class="btn-ghost" data-i18n="rp_open_poll"></button><br />
    <label>tx hash <input id="openTx" size="66" placeholder="0x…" /></label> <button id="openTxBtn" data-i18n="rp_open_tx"></button>
    <div id="openVerdict"></div>
    <pre id="openLog" class="expert">-</pre>
  </section>
</main>
```
`strings.js` `ui` 에 없는 키(`rp_login_btn: {ko:'로그인', en:'Log in'}`, `rp_reval_btn`, `rp_request_btn`, `refresh`, `rp_open_req`, `rp_open_poll`, `rp_open_tx`, `rp_pending_badge: {ko:'승인 대기', en:'Awaiting approval'}`, `rp_active_badge: {ko:'활성', en:'Active'}`, `rp_policy: {ko:'정책: 국가 ∈ {{countries}}, 나이 ≥ {minAge}', en:'Policy: country ∈ {{countries}}, age ≥ {minAge}'}`, `rp_require_pred: {ko:'조건 요구(국가·나이)', en:'Require predicate (country·age)'}`, `rp_login_same_ppid: {ko:'새 세션. 이 서비스에서의 내 주소는 이전과 같습니다.', en:'New session. Your address at this service is unchanged.'}`, `rp_login_new_ppid`, `rp_reval_cached: {ko:'캐시된 증명 재사용', en:'Cached proof reused'}`)를 이 작업에서 추가한다.

- [ ] **Step 3: 스크립트 수정**
  - `setVerdict(el, ok, text)` 를 유지하되 내부를 `Demo.verdict` 로 바꾼다: 호출부의 `text` 는 지금 `'로그인 성공 …'` 같은 원문이다 — 판정 키를 아는 호출부(`로그인 성공`→`login_ok`, `재검증 성공`→`reval_ok`, `재승인 불가`→`reauth_denied`, `팝업이 차단됐다`→`popup_blocked`)는 `Demo.verdict($('verdict'), { ok, title: 'login_ok', summary, detail: w })` 로 바꾸고, 실패는 `Demo.verdict(el, { ok:false, title:'login_failed', reason: w.reason, detail: w })`. 원문 로그(`#log` 등)에는 지금처럼 JSON 을 계속 쓴다.
  - `#walletMode` 의 문구 `지갑 비밀=snap`/`지갑 비밀=file` 은 **그대로**(needle). 배지 클래스만 붙인다.
  - `loadInfo()` 끝에 `renderGuide()`; `setSession()` 과 각 성공 분기 뒤에도 `renderGuide()`:

```js
    const progress = { used: false, disclosed: false, opened: false };   // 이 페이지가 아는 완료 신호(세션 중 메모리)
    function renderGuide() {
      const done = [];
      if (info?.status === 'approved') done.push('approve');
      if (currentSession) done.push('login');
      if (progress.used) done.push('use'); if (progress.disclosed) done.push('disclose'); if (progress.opened) done.push('open');
      const current = info?.status !== 'approved' ? 'approve' : !currentSession ? 'login' : !progress.used ? 'use' : !progress.opened ? 'open' : 'open';
      Demo.guide({ done, current, links: { wallet: info?.walletAgentOrigin, admin: info?.ciaUrl ? `${info.ciaUrl}/admin` : null, account: info?.ciaUrl ? `${info.ciaUrl}/account` : null } });
    }
```
  재검증·요청 성공 시 `progress.used = true`, `require` 로그인 성공 시 `progress.disclosed = true`, 개봉 결과 수신 시 `progress.opened = true`.
  - `refreshLogins()` 는 `<pre>` 대신 `table.list`(주소 요약 `PPID.slice(0,10)+'…'`, 시각, 공개 조건 요약, allowAgent 배지, 행마다 "개봉 요청" 버튼 → `#openPpid` 채우고 `openBtn` 클릭). 전문가 모드에서는 PPID 전체를 `title` 로.
  - `Demo.init({ page: 'rp' })` 를 스크립트 맨 앞(기존 `loadInfo().then(refreshLogins)` 앞)에서 호출.

- [ ] **Step 4: 검증** — `node tests/test_mode3_browser.mjs` 통과(무수정), `node tests/test_mode3_demo_stack.mjs` 통과. 브라우저로 직접 열어 한국어·영어·전문가 토글이 동작하고 `#verdict` 에 '로그인 성공' 이 보이는지 확인(Playwright 스크립트 한 줄로 스크린샷 찍어 보고서에 첨부 — `page.screenshot({ path: '/tmp/…/rp.png', fullPage: true })`).
- [ ] **Step 5: 커밋** — `feat(mode3-ui): 서비스 페이지 카드 재구성 — 안내 바·결과 카드·사유 번역·로그인 기록 표, id·판정 문구 계약 유지`

---

### Task 3: 지갑 페이지 `wallet.html`

**Files:** Modify `mode3/wallet.html`
**Interfaces:** Consumes T1. id·판정 문구 계약 유지. `#registerResult` 에 '등록됨', `#txVerdict` 에 '전송 성공', `#mmStatus` 에 계정 주소, `#sessionActions` 에 세션 버튼.

- [ ] **Step 1: 마크업** — head 교체(T2 와 같음). body 골격:

```html
<body data-page="wallet">
<header id="demoBar"></header>
<div id="authorizeView" hidden class="card span2">
  <h3 data-i18n="wallet_auth_title"></h3>
  <p id="authTitle"></p>
  <div id="authSummary" class="kv"></div>            <!-- 서비스명·origin·요청 조건을 문장으로 -->
  <p id="authStep" class="muted expert"></p>
  <pre id="authLog" class="expert"></pre>
</div>
<main id="mainView" class="cards">
  <section class="card" id="identityCard">
    <h3 data-i18n="wallet_identity_title"></h3><p class="desc" data-i18n="wallet_identity_desc"></p>
    <p><span id="regBadge" class="badge"></span></p>
    <span id="fileRegFields"><label>uid <input id="uid" value="12345" size="8" /></label> <label>pwd <input id="pwd" type="password" value="password123" size="12" /></label><br /></span>
    <dl class="kv" id="attrsView">
      <dt data-term="attr0"></dt><dd><input id="attr0" size="6" readonly /></dd>
      <dt data-term="attr1"></dt><dd><input id="attr1" size="6" readonly /></dd>
      <dt data-term="attr2"></dt><dd><input id="attr2" size="6" readonly /></dd>
      <dt data-term="attr3"></dt><dd><input id="attr3" size="6" readonly /></dd>
    </dl>
    <button id="registerBtn" data-i18n="wallet_register_btn"></button>
    <button id="attrsBtn" class="btn-ghost" data-i18n="wallet_attrs_btn"></button>
    <div id="registerResult"></div>
    <p id="intro" class="muted expert"></p>
  </section>
  <section class="card" id="sessionsCard">
    <h3 data-i18n="wallet_sessions_title"></h3><p class="desc" data-i18n="wallet_sessions_desc"></p>
    <button id="refreshBtn" class="btn-ghost" data-i18n="refresh"></button>
    <div id="sessionActions"></div>
    <pre id="status" class="expert"></pre>
    <pre id="sessionLog" class="expert"></pre>
  </section>
  <section class="card span2" id="txCard">
    <h3 data-i18n="wallet_tx_title"></h3><p class="desc" data-i18n="wallet_tx_desc"></p>
    <p id="txNote" class="muted"></p>
    … 기존 txSession/txTo/txValue/txData 입력을 <dl class="kv"> 로, "공개할 조건" 은 <details id="discloseBox"><summary data-term="disclosure"></summary> 안에 기존 discloseRows/dk*/discLo*/discHi*/discExactBtn/setRow/setSlot/setMembers/ageBtn/minAgeIn 그대로 </details>
    <button id="txBtn" data-i18n="wallet_tx_btn"></button>
    <div id="txVerdict"></div>
    <pre id="txLog" class="expert"></pre>
  </section>
  <section class="card" id="snapPanel" hidden>
    <h3 data-i18n="wallet_snap_title"></h3><p class="desc" data-i18n="wallet_snap_desc"></p>
    <button id="connectBtn" data-i18n="wallet_connect_btn"></button> <span id="mmStatus" class="badge"></span><br />
    <button id="snapInfoBtn" class="btn-ghost" data-i18n="wallet_snap_info_btn"></button>
    <button id="selfRevokeBtn" class="danger" data-i18n="wallet_self_revoke_btn"></button>
    <button id="snapResetBtn" class="danger" data-i18n="wallet_snap_reset_btn"></button>
    <pre id="snapInfo" class="expert"></pre>
  </section>
</main>
```
(기존 파일에 `#forgedBtn` 이 있으면 tx 카드 안 `.expert` 로 유지.) 필요한 `ui` 키(`wallet_register_btn: {ko:'등록', en:'Register'}`, `wallet_attrs_btn: {ko:'신원 기관에서 다시 받기', en:'Refresh from authority'}`, `wallet_tx_btn: {ko:'트랜잭션 보내기', en:'Send transaction'}`, `wallet_connect_btn`, `wallet_snap_info_btn`, `wallet_self_revoke_btn: {ko:'계정 자기 폐기', en:'Self-revoke account'}`, `wallet_snap_reset_btn`, `wallet_end_session: {ko:'이 세션 끝내기(폐기)', en:'End this session (revoke)'}`, `wallet_reg_yes: {ko:'등록됨', en:'Registered'}`, `wallet_reg_no: {ko:'미등록', en:'Not registered'}`, `wallet_no_sessions: {ko:'로그인 세션이 없습니다. 서비스에서 로그인하세요.', en:'No login sessions. Log in at a service.'}`, `wallet_session_expires: {ko:'만료 블록 {h}', en:'expires at block {h}'}`)는 이 작업에서 추가한다.

- [ ] **Step 2: 스크립트**
  - `Demo.init({ page: 'wallet' })` 를 `init()` 첫 줄에.
  - `refresh()` 끝: `renderGuide(status)` — done: `registration`→`register`, 세션 있음→`login`, `progress.txOk`→`use`, `progress.disclosed`→`disclose`, `progress.revoked`→`revoke`; current 는 `!registration ? 'register' : 세션 없음 ? 'login' : !txOk ? 'use' : 'disclose'`; links `{ admin: status.ciaUrl && status.ciaUrl + '/admin', account: status.ciaUrl && status.ciaUrl + '/account' }`. 세션 목록 렌더에서 각 세션을 `.kv` 블록으로(서비스: `s.arid` 앞 8자리 — origin 은 상태에 없다; 주소 요약; 만료; allowAgent 배지; "이 세션 끝내기" 버튼은 `.danger` + `Demo.confirmDanger('confirm_revoke')`), 없으면 `wallet_no_sessions`.
  - 등록 결과: 성공은 `Demo.verdict($('registerResult'), { ok:true, title:'registered', summary: …, detail: b })`(needle '등록됨'), 실패는 `{ ok:false, title:'wallet_register_failed', reason:b.reason, detail:b }`.
  - `showTxResult` → 성공 `Demo.verdict($('txVerdict'), { ok:true, title:'tx_ok', summary: (deployed? …), detail })`, 실패 `{ ok:false, title:'tx_failed', reason, detail }`. 전송 중 `Demo.verdict($('txVerdict'), { pending:true, title: Demo.t('proving') })`.
  - 승인 팝업: `#authSummary` 에 `서비스`(serviceName 또는 origin)·`요청 조건`(disclose·set 을 문장으로: "출생연도 ≤ {hi}", "국가 ∈ 허용 집합", "AI 에이전트 허용")를 채운다. 기존 `step()`·`authLog` 는 그대로 `.expert`.
  - 파괴적 버튼 `selfRevokeBtn`·`snapResetBtn` 에 `Demo.confirmDanger('confirm_revoke' / 'confirm_reset')` 선행(기존 `confirm(...)` 이 있으면 대체).
  - `#status` 는 `.expert` 이지만 `textContent` 는 지금처럼 JSON 을 계속 쓴다(browser 테스트가 읽는다).

- [ ] **Step 3: 검증** — `node tests/test_mode3_browser.mjs`, `node tests/test_mode3_wallet_snap.mjs`(:8545), `node tests/test_mode3_demo_stack.mjs` 통과. 스크린샷(file 모드) 첨부.
- [ ] **Step 4: 커밋** — `feat(mode3-ui): 지갑 페이지 카드 재구성 — 내 신원·세션·트랜잭션·Snap 카드, 승인 팝업 문장화, 결과 카드`

---

### Task 4: 관리자·계정 페이지

**Files:** Modify `mode3/cia_admin.html`, `mode3/cia_account.html`
**Interfaces:** Consumes T1. 관리자 API 호출 형식 불변(`X-CIA-Admin-Secret`).

- [ ] **Step 1: `cia_admin.html`** — head 교체. body: 안내 바 → 카드 ① 인증(`#secret`, "이 창에서 기억" 체크 → `sessionStorage`) ② 상단 배지 줄(`#pendingBadges`: `admin_pending_rps`·`admin_pending_openings`, 로드·새로고침 때 `/cia/rps`·`/cia/openings` 로 계산) ③ 계정(`#accountsBtn`, `#accounts` 표 — 기존 `loadAccounts/loadSessions` 유지, 폐기·세션 폐기 버튼 `.danger` + `Demo.confirmDanger('confirm_revoke')`) ④ 서비스(`#rpsBtn`, `#rps`) ⑤ 개봉 요청(`#openingsBtn`, `#openings`) ⑥ 폐기 목록(`#stateBtn` → root·epoch·pending 을 `.kv` 로, `#publishBtn` `.danger` + `confirm_publish`, `#revokeBtn`·`#recoverBtn`·`#uid` 는 계정 카드로 이동). `#out` 은 `.expert` 로 유지하고 `call()` 결과는 `Demo.verdict($('adminVerdict'), …)` + `#out` JSON. `renderGuide()`: done — 대기 서비스 0 이고 승인된 서비스 ≥1 → `approve`; current — 대기 서비스 있으면 `approve`, 개봉 요청 있으면 `open`, 아니면 `revoke`; links `{ account: '/account' }`.
- [ ] **Step 2: `cia_account.html`** — head 교체. body: 안내 바 → 카드 하나(`account_revoke_title/desc`, `#uid`, `#pwd`, `#revokeBtn` `.danger` + `confirm_revoke`, `#accountVerdict`, `#out` `.expert`). `Demo.guide({ done: [], current: 'revoke', links: { admin: '/admin' } })`.
- [ ] **Step 3: 검증** — `node tests/test_mode3_demo_stack.mjs`(관리자 API 는 페이지를 안 거치므로 회귀 없음 확인용), 두 페이지를 브라우저에서 열어 승인·폐기·게시·개봉 승인이 되는지 수동 확인 + 스크린샷.
- [ ] **Step 4: 커밋** — `feat(mode3-ui): 관리자·계정 페이지 카드 재구성 — 대기 배지, 파괴적 조작 확인, 결과 카드`

---

### Task 5: 스크린샷 스크립트·문서·전체 검증

**Files:** Create `scripts/screenshot_mode3.mjs`, `results/mode3_ux_20260924/README.md`(+png); Modify `docs/MODE3_DEMO.md`

- [ ] **Step 1: `scripts/screenshot_mode3.mjs`** — `tests/helpers/isolated_mode3_stack.mjs` 의 `startIsolatedMode3Stack()`(`tests/test_mode3_browser.mjs:39` 와 같은 호출, 단 file 모드)로 스택을 띄우고, Playwright(`chromium.launch({ channel: 'chrome' })`, 같은 테스트의 launch 헬퍼와 동일)로 네 페이지를 `ko`·`en`·`expert` 세 상태로 각각 `fullPage` 캡처해 `results/mode3_ux_20260924/{wallet,rp,admin,account}-{ko,en,expert}.png` 로 저장한다. 언어·전문가 상태는 `page.evaluate(() => Demo.setLang('en'))`·`Demo.setExpert(true)` 로 바꾼다. 로그인 한 번(테스트의 `loginOnce` 경로)까지 진행한 뒤 찍어 결과 카드가 보이게 한다. 사용법 헤더 주석·`--out` 옵션. 끝나면 스택 종료.
- [ ] **Step 2: `results/mode3_ux_20260924/README.md`** — 찍은 날짜·명령·페이지 목록·한 줄 관찰(넘침·겹침 없음 등, 실제로 본 것만).
- [ ] **Step 3: `docs/MODE3_DEMO.md`** — 각본 표의 버튼 이름을 새 문구로("Mode 3 로그인"→"로그인", "정확히 공개(체크된 슬롯)"→"공개할 조건 > 정확히 공개" 등), "언어·전문가 보기" 절 추가(토글 위치, `localStorage` 키, 기본값), 페이지 구성 절(카드 목록), 사유 표에 "화면 문구" 열 추가(사전 제목).
- [ ] **Step 4: 전체 검증** — `npm test`, `bash scripts/run_tests.sh chain`, `snap`, `browser`. 실패는 그대로 보고. 포트 정리 확인.
- [ ] **Step 5: 커밋** — `docs/test(mode3-ui): 스크린샷 스크립트·결과, 데모 문서 갱신`

---

## Self-Review

**Spec coverage** — §0 결정: 전역 제약. §1.1~1.3 공통 파일·서버·골격: T1(+각 페이지 T2~T4). §1.4 테스트 계약: 전역 제약 + 각 작업 검증 단계. §2.1~2.3 단계·guide·카드 설명: T1(`steps`, `guide`), T2~T4 `renderGuide`·`desc`. §3.1 용어: T1 `terms`, 페이지 `data-term`. §3.2 전문가: T1 `.expert`·`setExpert`, 페이지 `.expert` 래핑. §3.3 사유 사전: T1(REASONS 강제). §3.4 결과 카드: T1 `verdict`, 페이지 호출. §4.1~4.4: T3·T2·T4. §4.5 공통 규칙: `.danger`+`confirmDanger`(T1·각 페이지), `Demo.call`(T1; 페이지는 verdict pending 으로 대체 가능 — 스펙의 "모든 fetch 는 Demo.call" 은 T2~T4 에서 fetch 헬퍼(`post`/`postJson`)를 감싸는 방식으로 적용한다: 명시), 반응형(T1 CSS). §5 사전 로드 실패 시 기본 텍스트: 페이지 마크업의 `data-i18n` 요소에 한국어 기본 텍스트를 **넣어 둔다**(T2~T4 골격의 빈 요소는 구현 시 한국어 텍스트를 채운다 — 명시). §6 테스트: T1 unit, T2~T5 browser·chain, T5 스크린샷. §7 파일: 전부 배정.

**Placeholder scan** — T2 Step 2 의 "… 기존 입력을 kv 로" 는 기존 요소 유지 지시(코드 필요 없음); T3 골격의 `…` 한 곳도 같은 성격. 사유 사전 문구는 스펙이 "소스 확인 후 작성"을 요구하므로 예시 2개 + 코드 목록으로 충분(테스트가 완전성을 강제).

**Type consistency** — `Demo.guide({done,current,hint,links})`, `Demo.verdict(el,{ok,title,summary,reason,detail,pending})`, `Demo.confirmDanger(key)` 시그니처를 T2~T4 가 그대로 씀; `ui` 키 이름은 각 작업이 추가하는 목록을 명시; `verdicts` 키 `login_ok/registered/tx_ok/reval_ok/reauth_denied/popup_blocked` 는 T1 테스트 NEEDLES 와 T2·T3 호출이 일치.
