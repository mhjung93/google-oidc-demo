// IdP 상태 v12(V11 2026-10-12) — 기본 상태·검사·옛 버전 거부. 외부 의존 없음(unit).  node tests/test_mode3_cia_state.js
import assert from 'node:assert/strict';
import { CIA_STATE_VERSION, defaultCiaState, migrateCiaState, rpKeyTag, findRpSlotByKey } from '../lib/mode3_cia_state.js';
let failed = 0;
function t(name, fn) { try { fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

t('기본 상태는 v12 이고 attrs·profile·issued 가 없다', () => {
  const s = defaultCiaState();
  assert.equal(s.version, 12); assert.equal(CIA_STATE_VERSION, 12);
  assert.deepEqual(s, { version: 12, accounts: {}, rps: {}, operators: {}, rpSlots: {}, openings: [], revoked: [], pending: [], epoch: 0, registry: { depth: 20, next: 0, leaves: {}, pendingSlots: [] }, pendingBounds: [], lastPublication: null, signedEpochMax: 0, attrSchemaHash: null, nextUid: 100001, codes: {} });
});
t('v12 는 그대로(notes 없음), 빠진 하위 필드는 채운다(nextUid·codes 포함), 계정 기본값(creds·sessions·tampered·receipt·slotRetired·provider·pwSalt·pwHash·pwAlgo·createdAt)', () => {
  const { state, notes } = migrateCiaState({ version: 12, accounts: { '12345': { pk_u: { x: '1', y: '2' }, auid: '99', slot: 0, disabled: false } }, rps: {}, openings: [], revoked: [], pending: [], epoch: 3, registry: {} });
  assert.deepEqual(notes, []); assert.equal(state.epoch, 3);
  assert.deepEqual(state.registry, { depth: 20, next: 0, leaves: {}, pendingSlots: [] });
  assert.equal(state.nextUid, 100001, '옛(이 필드 이전) 파일은 100001 부터'); assert.deepEqual(state.codes, {});
  assert.deepEqual(state.accounts['12345'], { pk_u: { x: '1', y: '2' }, auid: '99', slot: 0, disabled: false, creds: [], sessions: [], tampered: false, receipt: null, slotRetired: false, provider: 'demo', pwSalt: null, pwHash: null, pwAlgo: null, createdAt: null });
  assert.equal(state.signedEpochMax, 0); assert.equal(state.attrSchemaHash, null, '스키마 해시는 cia.js 기동이 기록한다');
});
t('Task 11(B2, 2026-10-22): 옛(이 필드 이전) 파일에 operators·rpSlots 가 빈 값으로 채워지고, 옛 rps 엔트리는 operator:null 인 레거시로 읽힌다', () => {
  const { state, notes } = migrateCiaState({ version: 12, accounts: {}, rps: { '1': { name: 'n', origin: 'http://x', pk_service: '0x0', X_svc: null, x_AA: null, pk_trace: null, status: 'pending', requestedAt: 't', decidedAt: null } }, openings: [], revoked: [], pending: [], epoch: 0, registry: {} });
  assert.deepEqual(notes, []);
  assert.deepEqual(state.operators, {}); assert.deepEqual(state.rpSlots, {});
  assert.equal(state.rps['1'].operator, null, '옛 RP 엔트리는 운영자 없음');
});
t('Task 11(B2): 이미 operators·rpSlots·rps[*].operator 가 있는 파일은 그대로(덮어쓰지 않음)', () => {
  const input = { ...defaultCiaState(), operators: { op1: { pwSalt: 'a', pwHash: 'b', pwAlgo: 'scrypt', createdAt: 'c' } },
    rpSlots: { s1: { opId: 'op1', name: 'zkX', pwSalt: 'd', pwHash: 'e', pwAlgo: 'scrypt', status: 'created', createdAt: 'f', arid: null } },
    rps: { '1': { name: 'n', origin: 'http://x', status: 'approved', operator: 'op1' } } };
  const { state } = migrateCiaState(input);
  assert.deepEqual(state.operators, { op1: { pwSalt: 'a', pwHash: 'b', pwAlgo: 'scrypt', createdAt: 'c' } });
  assert.deepEqual(state.rpSlots, { s1: { opId: 'op1', name: 'zkX', pwSalt: 'd', pwHash: 'e', pwAlgo: 'scrypt', status: 'created', createdAt: 'f', arid: null } });
  assert.equal(state.rps['1'].operator, 'op1');
});
t('Task 10(B1, 2026-10-22): 가입만 하고 등록 전인 계정(pk_u·auid·slot 모두 null)은 그대로 통과하고 pwSalt·pwHash·createdAt 이 채워진다, pwHash 있는데 pwAlgo 없으면 scrypt로 본다', () => {
  const { state } = migrateCiaState({ ...defaultCiaState(), accounts: { '100001': { pk_u: null, auid: null, slot: null, disabled: false, pwSalt: 'a', pwHash: 'b', createdAt: 'c' } } });
  assert.deepEqual(state.accounts['100001'], { pk_u: null, auid: null, slot: null, disabled: false, pwSalt: 'a', pwHash: 'b', pwAlgo: 'scrypt', createdAt: 'c', creds: [], sessions: [], tampered: false, receipt: null, slotRetired: false, provider: 'demo' });
});
t('Task 10: pk_u:null 인데 auid 또는 slot 이 null 이 아니면(손상) throw', () => {
  const mk = (over) => ({ ...defaultCiaState(), accounts: { '1': { pk_u: null, auid: null, slot: null, disabled: false, ...over } } });
  migrateCiaState(mk({}));   // 정상: 셋 다 null
  assert.throws(() => migrateCiaState(mk({ auid: '5' })), /등록 전\(pk_u:null\)인데 auid/);
  assert.throws(() => migrateCiaState(mk({ slot: 0 })), /등록 전\(pk_u:null\)인데 slot/);
});
t('OIDC 래퍼(2026-10-16): provider 없는 v12 계정은 migrateCiaState 뒤 demo 가 되고, 이미 있는 provider(google)는 유지된다', () => {
  const { state } = migrateCiaState({ version: 12, accounts: {
    noProvider: { pk_u: { x: '1', y: '2' }, auid: '99', slot: 0, disabled: false },
    google: { pk_u: { x: '3', y: '4' }, auid: '77', slot: 1, disabled: false, provider: 'google' },
  }, rps: {}, openings: [], revoked: [], pending: [], epoch: 0, registry: {} });
  assert.equal(state.accounts.noProvider.provider, 'demo');
  assert.equal(state.accounts.google.provider, 'google');
});
t('v11 이하(v2·v4·v8·v10·v11)와 미래 버전(13), 버전 없음은 전부 throw — 이행하지 않는다', () => {
  for (const v of [2, 4, 8, 10, 11, 13, undefined]) assert.throws(() => migrateCiaState({ version: v, accounts: {} }), /unsupported IdP state version/, String(v));
  assert.throws(() => migrateCiaState({ version: 11, accounts: {} }), /재시연 세트/);
});
t('v12 인데 auid 가 없거나 V10 필드(attrs·profile·cm_u)가 남은 계정은 throw', () => {
  const base = () => ({ ...defaultCiaState(), accounts: { '1': { pk_u: { x: '1', y: '2' }, auid: '5', slot: 0, disabled: false } } });
  migrateCiaState(base());
  const noAuid = base(); delete noAuid.accounts['1'].auid;
  assert.throws(() => migrateCiaState(noAuid), /auid/);
  for (const k of ['attrs', 'profile', 'cm_u']) { const s = base(); s.accounts['1'][k] = {}; assert.throws(() => migrateCiaState(s), /V10 fields/, k); }
});
t('리뷰 S5: v12 계정의 slot 이 음이 아닌 정수가 아니면 throw(기동 거부)', () => {
  const mk = (slot) => ({ ...defaultCiaState(), accounts: { '1': { pk_u: { x: '1', y: '2' }, auid: '5', slot, disabled: false } } });
  migrateCiaState(mk(0)); migrateCiaState(mk(7));
  for (const slot of [undefined, null, -1, 1.5, '0', NaN]) assert.throws(() => migrateCiaState(mk(slot)), /valid slot/, String(slot));
});
t('리뷰 S5: v12 계정의 pk_u 가 {x, y} 10진 문자열이 아니면 throw(기동 거부) — pk_u:null 은 Task 10 의 "등록 전" sentinel 이라 제외(auid·slot 도 null 이어야 하므로 다른 테스트가 본다)', () => {
  const mk = (pk_u) => ({ ...defaultCiaState(), accounts: { '1': { pk_u, auid: '5', slot: 0, disabled: false } } });
  for (const pk_u of [undefined, {}, { x: '1' }, { x: 1, y: 2 }, { x: '-1', y: '2' }, { x: '0x1', y: '2' }, '1,2']) assert.throws(() => migrateCiaState(mk(pk_u)), /valid pk_u/, JSON.stringify(pk_u));
});
// 2026-10-25 root 유효 창 §4: pendingBounds 는 v12 확장 — 기본값 [] 이고 옛 파일에는 ??= 로 채운다.
t('pendingBounds 기본값·보존', () => {
  assert.deepEqual(defaultCiaState().pendingBounds, []);
  const old = defaultCiaState(); delete old.pendingBounds;
  migrateCiaState(old);
  assert.deepEqual(old.pendingBounds, []);
  const kept = { ...defaultCiaState(), pendingBounds: [{ pk_i: '1', bound: '2', epoch: null }] };
  migrateCiaState(kept);
  assert.deepEqual(kept.pendingBounds, [{ pk_i: '1', bound: '2', epoch: null }], '있는 대기열은 보존');
});
// 리뷰 C2(2026-10-26): register_rp 의 rp_key 대조가 'created' 슬롯 전부에 scrypt 를 돌던 것(무인증 증폭 DoS) — keyTag(SHA-256) 로
// 슬롯을 먼저 찾고 scrypt(verify) 는 그 한 슬롯에만. verify 는 호출 횟수를 세는 가짜(결정적 — 시간 측정이 아니다).
t('findRpSlotByKey: 태그 슬롯 N개에서 맞는 키는 verify 1회, 틀린 키는 0회; keyTag 없는 레거시 슬롯만 폴백으로 훑는다', () => {
  let calls = 0;
  const verify = (slot, key) => { calls++; return slot.secret === key; };
  const slots = {};
  for (let i = 0; i < 50; i++) { const key = `k${i}`.padEnd(64, 'a'); slots[`s${i}`] = { name: `zk${i}`, status: 'created', keyTag: rpKeyTag(key), secret: key }; }
  slots.bound = { name: 'zkB', status: 'pending', keyTag: rpKeyTag('kb'), secret: 'kb' };
  assert.match(rpKeyTag('x'), /^[0-9a-f]{64}$/);
  calls = 0; assert.equal(findRpSlotByKey(slots, 'k7'.padEnd(64, 'a'), verify), slots.s7); assert.equal(calls, 1, '맞는 키: verify 1회');
  calls = 0; assert.equal(findRpSlotByKey(slots, 'f'.repeat(64), verify), null); assert.equal(calls, 0, '틀린 키: 레거시 슬롯이 없으면 verify 0회');
  calls = 0; assert.equal(findRpSlotByKey(slots, 'kb', verify), null, "'created' 가 아닌 슬롯은 대상이 아니다"); assert.equal(calls, 0);
  // 태그는 맞는데 verify(scrypt) 가 거절하면(손상) null — 다른 슬롯으로 넘어가지 않는다
  calls = 0; assert.equal(findRpSlotByKey({ a: { status: 'created', keyTag: rpKeyTag('z'), secret: 'other' } }, 'z', verify), null); assert.equal(calls, 1);
  // 레거시(keyTag 없음, 옛 상태 파일) 슬롯: 태그 일치가 없을 때만, 그 레거시 슬롯들만 verify
  slots.legacy = { name: 'zkL', status: 'created', secret: 'legacy-key' };
  calls = 0; assert.equal(findRpSlotByKey(slots, 'legacy-key', verify), slots.legacy); assert.equal(calls, 1, '레거시 1개만 verify');
  calls = 0; assert.equal(findRpSlotByKey(slots, 'f'.repeat(64), verify), null); assert.equal(calls, 1, '틀린 키는 레거시 수만큼만');
  assert.equal(findRpSlotByKey({}, 'x', verify), null);
});
process.exit(failed === 0 ? 0 : 1);
