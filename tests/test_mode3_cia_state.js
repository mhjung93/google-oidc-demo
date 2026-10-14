// IdP 상태 v12(V11 2026-10-12) — 기본 상태·검사·옛 버전 거부. 외부 의존 없음(unit).  node tests/test_mode3_cia_state.js
import assert from 'node:assert/strict';
import { CIA_STATE_VERSION, defaultCiaState, migrateCiaState } from '../lib/mode3_cia_state.js';
let failed = 0;
function t(name, fn) { try { fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

t('기본 상태는 v12 이고 attrs·profile·issued 가 없다', () => {
  const s = defaultCiaState();
  assert.equal(s.version, 12); assert.equal(CIA_STATE_VERSION, 12);
  assert.deepEqual(s, { version: 12, accounts: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0, registry: { depth: 20, next: 0, leaves: {}, pendingSlots: [] }, lastPublication: null, signedEpochMax: 0, attrSchemaHash: null });
});
t('v12 는 그대로(notes 없음), 빠진 하위 필드는 채운다, 계정 기본값(creds·sessions·tampered·receipt·slotRetired)', () => {
  const { state, notes } = migrateCiaState({ version: 12, accounts: { '12345': { pk_u: { x: '1', y: '2' }, auid: '99', slot: 0, disabled: false } }, rps: {}, openings: [], revoked: [], pending: [], epoch: 3, registry: {} });
  assert.deepEqual(notes, []); assert.equal(state.epoch, 3);
  assert.deepEqual(state.registry, { depth: 20, next: 0, leaves: {}, pendingSlots: [] });
  assert.deepEqual(state.accounts['12345'], { pk_u: { x: '1', y: '2' }, auid: '99', slot: 0, disabled: false, creds: [], sessions: [], tampered: false, receipt: null, slotRetired: false });
  assert.equal(state.signedEpochMax, 0); assert.equal(state.attrSchemaHash, null, '스키마 해시는 cia.js 기동이 기록한다');
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
t('리뷰 S5: v12 계정의 pk_u 가 {x, y} 10진 문자열이 아니면 throw(기동 거부)', () => {
  const mk = (pk_u) => ({ ...defaultCiaState(), accounts: { '1': { pk_u, auid: '5', slot: 0, disabled: false } } });
  for (const pk_u of [undefined, null, {}, { x: '1' }, { x: 1, y: 2 }, { x: '-1', y: '2' }, { x: '0x1', y: '2' }, '1,2']) assert.throws(() => migrateCiaState(mk(pk_u)), /valid pk_u/, JSON.stringify(pk_u));
});
process.exit(failed === 0 ? 0 : 1);
