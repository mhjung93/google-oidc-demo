// CIA 상태 파일 이행 (설계 2026-09-18 §4.4). 외부 의존 없음.
//   node tests/test_mode3_cia_state.js
import assert from 'node:assert/strict';
import { CIA_STATE_VERSION, defaultCiaState, migrateCiaState } from '../lib/mode3_cia_state.js';

let failed = 0;
function t(name, fn) { try { fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

t('기본 상태는 v5 이고 빈 컬렉션', () => {
  const s = defaultCiaState();
  assert.equal(s.version, 5); assert.equal(CIA_STATE_VERSION, 5);
  assert.deepEqual(s, { version: 5, accounts: {}, issued: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 });
});

t('v4 → v5: issued 를 비우고(V3 서명은 죽은 자격증명) openings 에 resolved·allowAgent·max_height·chainid 를 채운다, 나머지는 그대로', () => {
  const v4 = {
    version: 4,
    accounts: { '12345': { pk_u: { x: '1', y: '2' }, cm_u: { x: '3', y: '4' }, disabled: false } },
    issued: { '12345': [{ leaf: '9', C: '8', exptime: '1789000000' }] },
    rps: { '777': { name: 's', origin: 'http://127.0.0.1:3100', pk_service: '0x' + '11'.repeat(20), X_svc: { x: '1', y: '2' }, x_AA: '5', pk_trace: { x: '6', y: '7' }, status: 'approved', requestedAt: 'a', decidedAt: 'b' } },
    openings: [{ id: 'o1', arid: '777', r_s: '55', PPID: '99', c1: { x: '1', y: '2' }, c2: '3', D_svc: { x: '4', y: '5' }, status: 'approved', requestedAt: 'a', decidedAt: 'b', uid: '12345' },
               { id: 'o2', arid: '777', r_s: '56', PPID: '99', c1: { x: '1', y: '2' }, c2: '3', D_svc: { x: '4', y: '5' }, status: 'pending', requestedAt: 'a', decidedAt: null }],
    revoked: ['9'], pending: ['9'], epoch: 3,
  };
  const { state, notes } = migrateCiaState(structuredClone(v4));
  assert.equal(state.version, 5);
  assert.deepEqual(state.issued, {});
  assert.deepEqual(state.accounts, v4.accounts); assert.deepEqual(state.rps, v4.rps);
  assert.deepEqual(state.revoked, ['9']); assert.deepEqual(state.pending, ['9']); assert.equal(state.epoch, 3);
  assert.equal(state.openings[0].resolved, true); assert.equal(state.openings[0].uid, '12345');
  assert.equal(state.openings[1].resolved, null);
  for (const o of state.openings) { assert.equal(o.allowAgent, null); assert.equal(o.max_height, null); assert.equal(o.chainid, null); }
  assert.ok(notes.some((n) => /v4→v5/.test(n) && /1개/.test(n)), notes.join('|'));
});

t('v3 → v5: used_rs 버림, rps 는 approved·조각 없음, openings [] (v4 규칙을 거쳐 온다)', () => {
  const { state, notes } = migrateCiaState({ version: 3, accounts: {}, issued: {}, used_rs: { '12345': ['1'] }, rps: { '777': { name: 'old', origin: 'http://127.0.0.1:3100', at: '2026-09-15T00:00:00.000Z' } }, revoked: [], pending: [], epoch: 0 });
  assert.equal(state.version, 5); assert.equal(state.used_rs, undefined);
  const e = state.rps['777'];
  assert.equal(e.status, 'approved'); assert.equal(e.pk_service, null); assert.equal(e.X_svc, null); assert.equal(e.x_AA, null); assert.equal(e.pk_trace, null);
  assert.equal(e.requestedAt, '2026-09-15T00:00:00.000Z');
  assert.deepEqual(state.openings, []);
  assert.equal(notes.length, 2);
});

t('v5 는 그대로(notes 없음), v2 이하·미래 버전은 throw', () => {
  const { state, notes } = migrateCiaState(defaultCiaState());
  assert.equal(state.version, 5); assert.deepEqual(notes, []);
  assert.throws(() => migrateCiaState({ version: 2 }), /version 2/);
  assert.throws(() => migrateCiaState({ version: 6 }), /version 6/);
});

process.exit(failed === 0 ? 0 : 1);
