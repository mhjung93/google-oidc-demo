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
const NEEDLES = { login_ok: '로그인 성공', registered: '등록됨', tx_ok: '전송 성공', reval_ok: '재검증 성공', reauth_denied: '재승인 불가', popup_blocked: '팝업이 차단됐다' };
// 문서(docs/MODE3_DEMO.md)에 있는 사유 코드 — 전부 ko·en 세 줄(title·cause·action)이 있어야 한다.
const REASONS = ['stale_root', 'root_too_old', 'revalidate_required', 'predicate_unmet', 'factory_constants_unavailable', 'registration_pending', 'bad_signature', 'bad_rp_cert', 'bad_proof', 'expired', 'malformed',
  'revoked', 'revoked_session', 'account_disabled', 'needs_consent', 'bad_factory', 'no_code', 'factory_code_mismatch', 'verifier_code_mismatch', 'allow_agent_mismatch', 'no_session', 'not_registered', 'cia_unavailable', 'witness_required', 'internal',
  'user_denied', 'snap_unavailable', 'wallet_error', 'unknown_session', 'no_user_cred', 'user_cred_retired'];

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
