// 상태 패널 판정(Demo.stack.judge, 설계 2026-09-25 §2.2)의 순수 함수 검사. node tests/test_mode3_stack_judge.js
// mode3/common/{strings,demo}.js 는 전역 스크립트라 vm 으로 window 를 흉내 내 읽는다. judge 는 DOM 을 쓰지 않으므로
// document 없이도 부를 수 있다(demo.js 도 로드 시점에는 document 를 만지지 않는다 — 그 계약을 여기서 함께 지킨다).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

globalThis.window = {};
vm.runInThisContext(fs.readFileSync(new URL('../mode3/common/strings.js', import.meta.url), 'utf8'));
vm.runInThisContext(fs.readFileSync(new URL('../mode3/common/demo.js', import.meta.url), 'utf8'));
const S = globalThis.window.DemoStrings;
const judge = globalThis.window.Demo.stack.judge;

let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

const EMPTY = { at: 0, aa: null, rp: null, wallet: null, errors: {} };
const aaOk = { role: 'aa', chain: { id: '31337', head: '100' }, root: 'abc…', epoch: 3, lastPublishedBlock: '98', rootAge: 2, heartbeatBlocks: 20, pendingLeaves: 0, pendingRps: 0, pendingOpenings: 0, accounts: 2, walletOrigin: 'http://w', rpOrigins: ['http://r'] };
const rpOk = { role: 'rp', chain: { id: '31337', head: '100' }, status: 'approved', active: true, inactiveReason: null, maxRootAge: 60, rootAge: 2, sessions: 1, predicates: { countries: 3, minAge: 19 }, walletAgentOrigin: 'http://w', ciaUrl: 'http://a' };
const walletOk = { role: 'wallet', chain: { id: '31337', head: '100' }, secrets: 'file', registered: true, hasCred: true, sessions: 1, ciaReachable: true, rpOrigin: 'http://r', ciaUrl: 'http://a' };
/** 정상 묶음 위에 한 역할만 덮어써 한 규칙씩 본다. */
const last = (over = {}) => ({ at: 1000, aa: { ...aaOk }, rp: { ...rpOk }, wallet: { ...walletOk }, errors: {}, ...over });
const lv = (v) => [v.level, v.key];

t('첫 폴링 전(at=0)에는 넷 다 회색', () => {
  const j = judge(EMPTY);
  for (const r of ['aa', 'rp', 'wallet', 'chain']) assert.deepEqual(lv(j[r]), ['unknown', 'stack_unknown'], r);
});
t('응답 없음(errors)이면 빨강, 체인도 빨강', () => {
  const j = judge({ at: 1000, aa: null, rp: null, wallet: null, errors: { aa: 'error', rp: 'timeout', wallet: 'error' } });
  for (const r of ['aa', 'rp', 'wallet']) assert.deepEqual(lv(j[r]), ['bad', 'stack_no_response'], r);
  assert.deepEqual(lv(j.chain), ['bad', 'stack_chain_none']);
});
t('세 서버가 다 chain:null 이면 체인 빨강, 하나라도 주면 초록 + head', () => {
  const none = last({ aa: { ...aaOk, chain: null }, rp: { ...rpOk, chain: null }, wallet: { ...walletOk, chain: null } });
  assert.deepEqual(lv(judge(none).chain), ['bad', 'stack_chain_none']);
  const j = judge(last());
  assert.deepEqual(lv(j.chain), ['ok', 'stack_head']);
  assert.equal(j.chain.vars.head, '100');
});
t('AA rootAge ≥ maxRootAge 면 빨강(게시 멈춤)', () => {
  assert.deepEqual(lv(judge(last({ aa: { ...aaOk, rootAge: 60 } })).aa), ['bad', 'stack_root_stale']);
  assert.deepEqual(lv(judge(last({ aa: { ...aaOk, rootAge: 61 } })).aa), ['bad', 'stack_root_stale']);
});
t('AA rootAge ≥ maxRootAge/2 면 노랑(나이 표시)', () => {
  const j = judge(last({ aa: { ...aaOk, rootAge: 30 } }));
  assert.deepEqual(lv(j.aa), ['warn', 'stack_root_warn']);
  assert.equal(j.aa.vars.age, 30);
});
t('AA heartbeatBlocks ≥ maxRootAge 면 노랑', () => {
  assert.deepEqual(lv(judge(last({ aa: { ...aaOk, heartbeatBlocks: 60 } })).aa), ['warn', 'stack_root_warn']);
});
t('AA pendingLeaves > 0 이면 노랑(건수 표시)', () => {
  const j = judge(last({ aa: { ...aaOk, pendingLeaves: 2 } }));
  assert.deepEqual(lv(j.aa), ['warn', 'stack_pending_leaves']);
  assert.equal(j.aa.vars.n, 2);
});
t('서비스: 승인 대기는 노랑, 비활성은 빨강, approved+active 는 초록', () => {
  assert.deepEqual(lv(judge(last({ rp: { ...rpOk, status: 'pending' } })).rp), ['warn', 'stack_rp_pending']);
  assert.deepEqual(lv(judge(last({ rp: { ...rpOk, active: false, inactiveReason: 'registration_pending' } })).rp), ['bad', 'stack_rp_inactive']);
  assert.deepEqual(lv(judge(last()).rp), ['ok', 'stack_ok']);
});
t('지갑: 기관에 못 닿으면 노랑, 미등록이면 회색, 그 외 초록', () => {
  assert.deepEqual(lv(judge(last({ wallet: { ...walletOk, ciaReachable: false } })).wallet), ['warn', 'stack_wallet_cia_down']);
  assert.deepEqual(lv(judge(last({ wallet: { ...walletOk, registered: false } })).wallet), ['unknown', 'stack_wallet_unregistered']);
  assert.deepEqual(lv(judge(last()).wallet), ['ok', 'stack_ok']);
});
t('정상이면 넷 다 초록', () => {
  const j = judge(last());
  assert.deepEqual(lv(j.aa), ['ok', 'stack_ok']);
  assert.deepEqual(lv(j.rp), ['ok', 'stack_ok']);
  assert.deepEqual(lv(j.wallet), ['ok', 'stack_ok']);
  assert.equal(j.chain.level, 'ok');
});
t('서비스의 rootAge 가 null 이어도(세션 요청 전) AA 판정은 자기 rootAge 로 한다', () => {
  assert.deepEqual(lv(judge(last({ rp: { ...rpOk, rootAge: null } })).aa), ['ok', 'stack_ok']);
  assert.deepEqual(lv(judge(last({ aa: { ...aaOk, rootAge: 60 }, rp: { ...rpOk, rootAge: null } })).aa), ['bad', 'stack_root_stale']);
});
t('서비스가 없으면 상한은 AA 의 heartbeatBlocks·2', () => {
  const noRp = (aa) => judge({ at: 1000, aa, rp: null, wallet: { ...walletOk }, errors: {} }).aa;
  assert.deepEqual(lv(noRp({ ...aaOk, heartbeatBlocks: 5, rootAge: 10 })), ['bad', 'stack_root_stale']);
  assert.deepEqual(lv(noRp({ ...aaOk, heartbeatBlocks: 5, rootAge: 5 })), ['warn', 'stack_root_warn']);
  assert.deepEqual(lv(noRp({ ...aaOk, heartbeatBlocks: 5, rootAge: 4 })), ['ok', 'stack_ok']);
});
t('heartbeatBlocks 가 0(하트비트 없음)이고 서비스도 없으면 root 판정을 하지 않는다', () => {
  const j = judge({ at: 1000, aa: { ...aaOk, heartbeatBlocks: 0, rootAge: 9999 }, rp: null, wallet: { ...walletOk }, errors: {} });
  assert.deepEqual(lv(j.aa), ['ok', 'stack_ok']);
  assert.deepEqual(lv(j.rp), ['unknown', 'stack_unknown']);   // 주소를 모르면 오류가 아니라 회색이다
});
t('체인이 없으면 rootAge 는 null 이고 AA 는 root 로 빨강이 되지 않는다', () => {
  assert.deepEqual(lv(judge(last({ aa: { ...aaOk, chain: null, rootAge: null } })).aa), ['ok', 'stack_ok']);
});
t('judge 가 돌려주는 key 는 전부 사전에 있다', () => {
  const seen = new Set();
  const collect = (l) => { const j = judge(l); for (const r of ['aa', 'rp', 'wallet', 'chain']) seen.add(j[r].key); };
  collect(EMPTY);
  collect({ at: 1, aa: null, rp: null, wallet: null, errors: { aa: 'error', rp: 'error', wallet: 'error' } });
  for (const over of [{}, { aa: { ...aaOk, rootAge: 60 } }, { aa: { ...aaOk, rootAge: 30 } }, { aa: { ...aaOk, pendingLeaves: 1 } },
    { rp: { ...rpOk, status: 'pending' } }, { rp: { ...rpOk, active: false } }, { wallet: { ...walletOk, ciaReachable: false } }, { wallet: { ...walletOk, registered: false } }]) collect(last(over));
  for (const k of seen) assert.ok(S.ui[k], `ui.${k} 없음`);
  assert.ok(seen.size >= 10, `판정 문구 ${seen.size}종만 나왔다`);
});
t('judge 는 입력을 바꾸지 않는다', () => {
  const l = last();
  const copy = JSON.parse(JSON.stringify(l));
  judge(l);
  assert.deepEqual(JSON.parse(JSON.stringify(l)), copy);
});

if (fails) { console.log(`\n${fails} FAIL`); process.exit(1); } else console.log('\nall ok');
