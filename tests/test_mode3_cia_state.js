// CIA 상태 파일 이행 (설계 2026-09-18 §4.4). 외부 의존 없음.
//   node tests/test_mode3_cia_state.js
import assert from 'node:assert/strict';
import { CIA_STATE_VERSION, defaultCiaState, migrateCiaState } from '../lib/mode3_cia_state.js';

let failed = 0;
function t(name, fn) { try { fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

t('기본 상태는 v7 이고 issued 가 없다', () => {
  const s = defaultCiaState();
  assert.equal(s.version, 7); assert.equal(CIA_STATE_VERSION, 7);
  assert.deepEqual(s, { version: 7, accounts: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 });
});

t('v5 → v7(v6 을 거쳐): issued 를 버리고 각 계정에 creds:[] 를 넣는다', () => {
  const v5 = { version: 5, accounts: { '12345': { pk_u: { x: '1', y: '2' }, cm_u: { x: '3', y: '4' }, disabled: false } },
    issued: { '12345': [{ leaf: '9', C: '8', max_height: '100', chainid: '31337' }] }, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 };
  const { state, notes } = migrateCiaState(structuredClone(v5));
  assert.equal(state.version, 7); assert.equal(state.issued, undefined);
  assert.deepEqual(state.accounts['12345'].creds, []);
  assert.deepEqual(state.accounts['12345'].attrs, ['0', '0', '0', '0'], 'demoAttrs 콜백 없이 부르면 0 네 개');
  assert.ok(notes.some((n) => n.includes('v5→v6') && n.includes('1개')));
  assert.ok(notes.some((n) => n.includes('v6→v7')));
});

t('v4 → v7(v6 을 거쳐): issued 를 버리고(V3 서명은 죽은 자격증명) openings 에 resolved·allowAgent·max_height·chainid 를 채운다, 계정에 creds:[], 나머지는 그대로', () => {
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
  assert.equal(state.version, 7);
  assert.equal(state.issued, undefined);
  assert.deepEqual(state.accounts, { '12345': { ...v4.accounts['12345'], creds: [], attrs: ['0', '0', '0', '0'] } }); assert.deepEqual(state.rps, v4.rps);
  assert.deepEqual(state.revoked, ['9']); assert.deepEqual(state.pending, ['9']); assert.equal(state.epoch, 3);
  assert.equal(state.openings[0].resolved, true); assert.equal(state.openings[0].uid, '12345');
  assert.equal(state.openings[1].resolved, null);
  for (const o of state.openings) { assert.equal(o.allowAgent, null); assert.equal(o.max_height, null); assert.equal(o.chainid, null); }
  assert.ok(notes.some((n) => /v4→v5/.test(n) && /1개/.test(n)), notes.join('|'));
  assert.ok(notes.some((n) => /v5→v6/.test(n) && /0개/.test(n)), notes.join('|'));
  assert.ok(notes.some((n) => /v6→v7/.test(n)), notes.join('|'));
});

t('v3 → v7(v6 을 거쳐): used_rs 버림, rps 는 approved·조각 없음, openings [] (v4·v5 규칙을 거쳐 온다)', () => {
  const { state, notes } = migrateCiaState({ version: 3, accounts: {}, issued: {}, used_rs: { '12345': ['1'] }, rps: { '777': { name: 'old', origin: 'http://127.0.0.1:3100', at: '2026-09-15T00:00:00.000Z' } }, revoked: [], pending: [], epoch: 0 });
  assert.equal(state.version, 7); assert.equal(state.used_rs, undefined); assert.equal(state.issued, undefined);
  const e = state.rps['777'];
  assert.equal(e.status, 'approved'); assert.equal(e.pk_service, null); assert.equal(e.X_svc, null); assert.equal(e.x_AA, null); assert.equal(e.pk_trace, null);
  assert.equal(e.requestedAt, '2026-09-15T00:00:00.000Z');
  assert.deepEqual(state.openings, []);
  assert.equal(notes.length, 4);
});

t('v7 는 그대로(notes 없음), v2 이하·미래 버전은 throw', () => {
  const { state, notes } = migrateCiaState(defaultCiaState());
  assert.equal(state.version, 7); assert.deepEqual(notes, []);
  assert.throws(() => migrateCiaState({ version: 2 }), /version 2/);
  assert.throws(() => migrateCiaState({ version: 8 }), /version 8/);
});

t('v6 → v7: attrs 가 채워지고 활성 자격증명은 전부 물려 revoked·pending 에 리프가 들어간다', () => {
  const s = { version: 6, accounts: { '12345': { pk_u: {}, cm_u: {}, disabled: false, creds: [{ Cf_u: '1', C_u_pt: {}, leaf: '111', issuedAt: 'x', revoked: false }, { Cf_u: '2', C_u_pt: {}, leaf: '222', issuedAt: 'y', revoked: true }] } }, rps: {}, openings: [], revoked: ['222'], pending: [], epoch: 0 };
  const { state } = migrateCiaState(s, { demoAttrs: (uid) => (uid === '12345' ? ['1990', '410', '2', '0'] : null) });
  assert.equal(state.version, 7);
  assert.deepEqual(state.accounts['12345'].attrs, ['1990', '410', '2', '0']);
  assert.equal(state.accounts['12345'].creds[0].revoked, true);
  assert.deepEqual(state.revoked, ['222', '111']); assert.deepEqual(state.pending, ['111']);
});
t('v7 기본 상태와 demoAttrs 없는 계정은 0 네 개', () => {
  assert.equal(defaultCiaState().version, 7);
  const { state } = migrateCiaState({ version: 6, accounts: { '1': { pk_u: {}, cm_u: {}, disabled: false, creds: [] } }, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 });
  assert.deepEqual(state.accounts['1'].attrs, ['0', '0', '0', '0']);
});

process.exit(failed === 0 ? 0 : 1);
