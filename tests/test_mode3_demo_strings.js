// 문구 사전(mode3/common/strings.js)의 완전성. 전역 스크립트라 vm 으로 window 를 흉내 내 읽는다. node tests/test_mode3_demo_strings.js
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const src = fs.readFileSync(new URL('../mode3/common/strings.js', import.meta.url), 'utf8');
// 같은 realm 에서 돌린다 — runInNewContext 는 사전의 배열이 다른 realm 의 Array.prototype 을 갖게 해
// assert.deepEqual(=deepStrictEqual)의 프로토타입 검사에서 실패한다.
globalThis.window = {};
vm.runInThisContext(src);
const S = globalThis.window.DemoStrings;

let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

// browser 테스트(tests/test_mode3_browser.mjs)가 잡는 한국어 판정 문구 — 사전의 ko 값이 이것과 글자 그대로 같아야 한다.
const NEEDLES = { login_ok: '로그인 성공', registered: '등록됨', tx_ok: '전송 성공', reval_ok: '재검증 성공', reauth_denied: '재승인 불가', popup_blocked: '팝업이 차단됐다',
  // tests/test_mode3_user_web.mjs(web 모드 각본)가 더 잡는 문구.
  request_ok: '세션 요청 성공', revoked_ok: '폐기 요청 접수' };
// 문서(docs/MODE3_DEMO.md)에 있는 사유 코드 — 전부 ko·en 세 줄(title·cause·action)이 있어야 한다.
const REASONS = ['stale_root', 'stale_registry_root', 'root_too_old', 'revalidate_required', 'predicate_unmet', 'predicate_unavailable', 'factory_constants_unavailable', 'registration_pending', 'bad_signature', 'bad_rp_cert', 'bad_proof', 'expired', 'malformed',
  'bad_r_s', 'bad_arid_s',
  'revoked', 'revoked_session', 'account_disabled', 'needs_consent', 'bad_factory', 'no_code', 'factory_code_mismatch', 'verifier_code_mismatch', 'allow_agent_mismatch', 'no_session', 'not_registered', 'cia_unavailable', 'witness_required', 'internal',
  'user_denied', 'snap_unavailable', 'wallet_error', 'unknown_session',
  'registry_mismatch', 'registry_unpublished', 'registry_slot_unknown', 'user_cred_failed', 'issue_failed', 'bad_idp_proof', 'cred_revoked', 'demo_proof_failed', 'slot_failed',
  'admin_secret_required', 'admin_unauthorized', 'unknown_account', 'invalid_credentials',
  // 2026-10-11 데모 UI 도달 코드(런북 "실패 각본")
  'bad_disclosure', 'disclosure_unsatisfiable', 'predicate_type', 'duplicate_session', 'already_registered', 'register_failed',
  // 2026-10-15 브라우저 전용 사용자 페이지(web 모드) — 금고·증명 워커·RP 릴레이·승인 창
  'locked', 'bad_password', 'zk_assets_unavailable', 'storage_unavailable', 'relay_inactive', 'relay_bad_target', 'relay_bad_calldata', 'relay_gas', 'relay_rate_limited', 'origin_mismatch',
  'chain_unavailable', 'no_factory', 'execute_reverted', 'schema_invalid', 'bad_attr'];

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
  for (const n of ['PPID', 'AA', 'session', 'root', 'proof', 'disclosure', 'cred', 'tag', 'allowAgent', 'attr0', 'attr1', 'attr2', 'attr3', 'auid', 'auid_s', 'r_rp']) assert.ok(S.terms[n], `terms.${n}`);
});
t('ui 에 안내 바·토글·공통 버튼 키가 있다', () => {
  for (const k of ['bar_next', 'bar_other_window', 'toggle_lang', 'toggle_expert', 'details', 'working', 'proving', 'confirm_revoke', 'confirm_publish', 'confirm_reset', 'go_wallet', 'go_rp', 'go_admin', 'go_account', 'wallet_profile_save_btn', 'wallet_profile_saved', 'wallet_profile_failed', 'wallet_profile_saved_snap_pending']) assert.ok(S.ui[k], k);
});
// 상태 패널(설계 2026-09-25 §2) — 점 라벨·판정 문구. Demo.stack.judge 가 돌려주는 key 는 전부 여기 있어야 한다.
t('ui 에 상태 패널 키가 있다', () => {
  for (const k of ['stack_aa', 'stack_rp', 'stack_wallet', 'stack_chain', 'stack_unknown', 'stack_no_response', 'stack_chain_none', 'stack_root_stale', 'stack_root_warn', 'stack_pending_leaves', 'stack_rp_pending', 'stack_rp_inactive', 'stack_wallet_unregistered', 'stack_wallet_cia_down', 'stack_ok', 'stack_panel_title', 'stack_head']) assert.ok(S.ui[k], k);
});
// V10(2026-10-02) 상태 카드의 거울 줄 — 관리자·RP·지갑 페이지가 쓴다.
t('ui 에 거울 상태 줄 키가 있다', () => {
  for (const k of ['admin_mirror_line', 'admin_mirror_unreadable', 'rp_mirror_line', 'wallet_mirror_line']) assert.ok(S.ui[k], k);
});
// 체험 모드(설계 2026-09-25 §3) — 단계마다 말풍선 문구와 대상 요소 id, 그리고 스위치·잠금·완료 문구.
const TOUR_PAGES = ['rp', 'wallet', 'admin', 'account'];
t('steps 에 체험 모드 말풍선 문구(tour)와 대상 요소(target)가 있다', () => {
  for (const s of S.steps) {
    for (const l of S.langs) { assert.ok(s.tour?.[l]?.title, `${s.key}.tour.${l}.title`); assert.ok(s.tour?.[l]?.body, `${s.key}.tour.${l}.body`); }
    assert.ok(s.target && typeof s.target === 'object' && !Array.isArray(s.target), `${s.key}.target 은 객체`);
    const pages = Object.keys(s.target);
    assert.ok(pages.length > 0, `${s.key}.target 이 비었다`);
    for (const p of pages) {
      assert.ok(TOUR_PAGES.includes(p), `${s.key}.target.${p} 는 알 수 없는 페이지`);
      assert.ok(typeof s.target[p] === 'string' && s.target[p].length, `${s.key}.target.${p} 값`);
      // 대상은 그 단계가 일어나는 당사자의 페이지여야 한다 — 없는 곳을 가리키면 말풍선이 뜨지 않는다.
      assert.ok(s.where.includes(p), `${s.key}.target.${p} 가 where 밖`);
    }
  }
});
t('ui 에 체험 모드 키가 있다', () => {
  for (const k of ['tour_on', 'tour_off', 'tour_lock_login', 'tour_lock_register', 'tour_elsewhere', 'tour_done_title', 'tour_done_body', 'tour_next']) assert.ok(S.ui[k], k);
});
// 관리자 "사용자 자격증명 — 활성 목록"·"세션 — 폐기 목록" 두 표(2026-10-14 U1).
t('ui 에 관리자 자격증명·세션 폐기 목록 키가 있다', () => {
  for (const k of ['admin_creds_title', 'admin_creds_desc', 'admin_creds_empty',
    'admin_revoked_sessions_title', 'admin_revoked_sessions_desc', 'admin_revoked_sessions_empty',
    'admin_col_uid', 'admin_col_slot', 'admin_col_cfu', 'admin_col_issued', 'admin_col_state', 'admin_col_published',
    'admin_col_cfs', 'admin_col_chain', 'admin_col_maxh', 'admin_col_revoked_at',
    'admin_state_active', 'admin_state_retired', 'admin_state_disabled', 'admin_state_tampered',
    'admin_pub_yes', 'admin_pub_pending']) assert.ok(S.ui[k], k);
});
// 지갑 "공개할 속성 조건" 새 폼(국가 선택·예비 체크박스) + AttrGate claim 버튼(2026-10-14 U2~U4).
t('ui 에 지갑 공개 조건 폼·claim 버튼 키가 있다', () => {
  for (const k of ['wallet_disc_country_none', 'wallet_disc_no_value', 'wallet_disc_excluded',
    'wallet_tx_claim_btn', 'wallet_tx_claim_hint']) assert.ok(S.ui[k], k);
});
// RP 데모(zkONE 거래소 꾸밈, 2026-10-14 U5) — 상단 내비·KRW 시세표·내 자산 패널·컴플라이언스 묶음 문구.
t('ui 에 RP 거래소 꾸밈(내비·시세표·내 자산·컴플라이언스) 키가 있다', () => {
  for (const k of ['nav_market', 'nav_assets', 'nav_withdraw', 'rp_logout_btn', 'rp_pending_banner',
    'market_title', 'market_demo_note', 'market_col_coin', 'market_col_price', 'market_col_change', 'market_col_volume',
    'assets_title', 'rp_login_policy', 'rp_login_nav_hint', 'rp_session_expiry_label',
    'rp_withdraw_title', 'rp_withdraw_desc', 'rp_withdraw_amount_label', 'compliance_title']) assert.ok(S.ui[k], k);
});
// 가짜 증명·가짜 서명 시연 버튼(2026-10-14) — mode3_wallet_agent.js 의 fake_proof·fake_sig 스코프, mode3/wallet.html 의 #demoFakeProofBtn·#demoFakeSigBtn.
t('ui 에 가짜 증명·가짜 서명 시연 버튼 키가 있다', () => {
  for (const k of ['wallet_demo_fake_proof_btn', 'wallet_demo_fake_sig_btn', 'wallet_demo_fake_armed', 'wallet_demo_fake_proof', 'wallet_demo_fake_sig']) assert.ok(S.ui[k], k);
});

// 브라우저 전용 사용자 페이지(web 모드, 2026-10-15) — mode3/user/index.html·ui.js·popup.js 와 mode3/rp.html 의 web 분기.
t('ui 에 사용자 페이지(web 모드) 키가 있다', () => {
  for (const k of ['user_storage_title', 'user_storage_desc', 'user_vault_none', 'user_vault_locked', 'user_vault_unlocked', 'user_lock_btn', 'user_unlock_btn', 'user_change_pw_btn', 'user_wipe_btn', 'user_wipe_done',
    'user_vault_pw_label', 'user_vault_pw2_label', 'user_vault_pw_mismatch', 'user_vault_pw_short', 'user_unlock_title', 'user_unlock_hint', 'user_unlock_cancel', 'user_zk_loading', 'user_zk_ready',
    'user_auth_approve', 'user_auth_deny', 'user_auth_request_title', 'user_auth_sign_body', 'user_intro_web', 'user_tx_note_web', 'user_self_revoke_pw', 'confirm_wipe',
    'rp_wallet_web', 'rp_wallet_web_note', 'rp_wallet_mode_web']) assert.ok(S.ui[k], k);
  // web 각본이 잡는 한국어 조각(사전 값이 바뀌면 그 테스트가 조용히 시간 초과로 실패한다).
  assert.ok(S.ui.rp_wallet_web.ko.includes('사용자 비밀=브라우저')); assert.ok(S.ui.rp_wallet_mode_web.ko.includes('브라우저'));
  assert.ok(S.ui.user_vault_unlocked.ko.includes('해제')); assert.ok(S.ui.user_vault_locked.ko.includes('잠김'));
  assert.ok(S.ui.user_vault_none.ko.includes('없음')); assert.ok(S.ui.user_zk_ready.ko.includes('준비'));
  assert.ok(S.ui.wallet_no_sessions.ko.includes('로그인 세션이 없습니다'));
});

if (fails) { console.log(`\n${fails} FAIL`); process.exit(1); } else console.log('\nall ok');
