// CIA 상태 v8 → v9 이행(등록부·슬롯). (unit)  node tests/test_mode3_cia_state_v9.js
import assert from 'node:assert/strict';
import { CIA_STATE_VERSION, defaultCiaState, migrateCiaState } from '../lib/mode3_cia_state.js';
let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }
const v8 = () => ({ version: 8, accounts: {
  '67890': { pk_u: { x: '1', y: '2' }, cm_u: { x: '3', y: '4' }, disabled: false, creds: [], attrs: ['2005', '840', '1', '0'], sessions: [] },
  '12345': { pk_u: { x: '5', y: '6' }, cm_u: { x: '7', y: '8' }, disabled: false, creds: [{ Cf_u: '99', C_u_pt: { x: '1', y: '1' }, leaf: '0', issuedAt: 'x', revoked: false }], attrs: ['1990', '410', '2', '0'], sessions: [] },
}, rps: {}, openings: [], revoked: [], pending: [], epoch: 3 });
t('CIA_STATE_VERSION = 9, defaultCiaState 에 registry', () => {
  assert.equal(CIA_STATE_VERSION, 9);
  assert.deepEqual(defaultCiaState().registry, { depth: 20, next: 0, leaves: {}, pendingSlots: [] });
});
t('v8 → v9: 슬롯은 uid 오름차순(12345 → 0, 67890 → 1), registry.next = 2, 속성은 6칸으로 0 패딩, tampered:false', () => {
  const { state, notes } = migrateCiaState(v8());
  assert.equal(state.version, 9);
  assert.equal(state.accounts['12345'].slot, 0); assert.equal(state.accounts['67890'].slot, 1);
  assert.equal(state.registry.next, 2); assert.deepEqual(state.registry.leaves, {}); assert.deepEqual(state.registry.pendingSlots, []);
  assert.deepEqual(state.accounts['12345'].attrs, ['1990', '410', '2', '0', '0', '0']);
  assert.equal(state.accounts['12345'].tampered, false);
  assert.ok(notes.some((n) => n.startsWith('v8→v9')), notes.join('|'));
  assert.equal(state.epoch, 3, '게시 epoch 는 그대로');
});
t('v9 는 그대로 통과하고 slot 이 있는 계정은 다시 배정하지 않는다', () => {
  const { state: s1 } = migrateCiaState(v8());
  const { state: s2, notes } = migrateCiaState(JSON.parse(JSON.stringify(s1)));
  assert.deepEqual(notes, []); assert.equal(s2.accounts['67890'].slot, 1); assert.equal(s2.registry.next, 2);
});
t('손으로 적은 v9 파일의 registry 가 부분적이어도(빈 객체) 하위 필드가 채워진다', () => {
  const { state } = migrateCiaState({ version: 9, accounts: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0, registry: {} });
  assert.deepEqual(state.registry, { depth: 20, next: 0, leaves: {}, pendingSlots: [] });
});
process.exit(fails ? 1 : 0);
