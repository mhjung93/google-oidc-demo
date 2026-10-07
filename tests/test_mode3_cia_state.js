// CIA 상태 파일 이행 (설계 2026-09-18 §4.4, 2026-10-01 §3 v9 등록부). 외부 의존 없음.
//   node tests/test_mode3_cia_state.js
import assert from 'node:assert/strict';
import { CIA_STATE_VERSION, defaultCiaState, migrateCiaState } from '../lib/mode3_cia_state.js';

let failed = 0;
function t(name, fn) { try { fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

t('기본 상태는 v11 이고 issued 가 없다', () => {
  const s = defaultCiaState();
  assert.equal(s.version, 11); assert.equal(CIA_STATE_VERSION, 11);
  assert.deepEqual(s, { version: 11, accounts: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0, registry: { depth: 20, next: 0, leaves: {}, pendingSlots: [] }, lastPublication: null, signedEpochMax: 0, attrSchemaHash: null });
  assert.equal(s.attrSchemaHash, null, '최종 리뷰 I4: 스키마 해시는 cia.js 기동이 처음 기록한다');
});

t('v5 → v9(v6·v7·v8 을 거쳐): issued 를 버리고 각 계정에 creds:[]·sessions:[] 를 넣는다', () => {
  const v5 = { version: 5, accounts: { '12345': { pk_u: { x: '1', y: '2' }, cm_u: { x: '3', y: '4' }, disabled: false } },
    issued: { '12345': [{ leaf: '9', C: '8', max_height: '100', chainid: '31337' }] }, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 };
  const { state, notes } = migrateCiaState(structuredClone(v5));
  assert.equal(state.version, 11); assert.equal(state.issued, undefined);
  assert.deepEqual(state.accounts['12345'].creds, []);
  assert.deepEqual(state.accounts['12345'].sessions, []);
  assert.deepEqual(state.accounts['12345'].attrs, ['0', '0', '0', '0', '0', '0'], 'demoAttrs 콜백 없이 부르면 0 여섯 개');
  assert.equal(state.accounts['12345'].slot, 0); assert.equal(state.accounts['12345'].tampered, false);
  assert.ok(notes.some((n) => n.includes('v5→v6') && n.includes('1개')));
  assert.ok(notes.some((n) => n.includes('v6→v7')));
  assert.ok(notes.some((n) => n.includes('v7→v8')));
  assert.ok(notes.some((n) => n.includes('v8→v9')));
});

t('v4 → v9(v6·v7·v8 을 거쳐): issued 를 버리고(V3 서명은 죽은 자격증명) openings 에 resolved·allowAgent·max_height·chainid 를 채운다, 계정에 creds:[]·sessions:[]·slot·tampered, 나머지는 그대로', () => {
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
  assert.equal(state.version, 11);
  assert.equal(state.issued, undefined);
  assert.deepEqual(state.accounts, { '12345': { ...v4.accounts['12345'], creds: [], sessions: [], attrs: ['0', '0', '0', '0', '0', '0'], slot: 0, tampered: false, receipt: null, slotRetired: false, profile: {} } }); assert.deepEqual(state.rps, v4.rps);
  assert.deepEqual(state.revoked, ['9']); assert.deepEqual(state.pending, ['9']); assert.equal(state.epoch, 3);
  assert.equal(state.openings[0].resolved, true); assert.equal(state.openings[0].uid, '12345');
  assert.equal(state.openings[1].resolved, null);
  for (const o of state.openings) { assert.equal(o.allowAgent, null); assert.equal(o.max_height, null); assert.equal(o.chainid, null); }
  assert.ok(notes.some((n) => /v4→v5/.test(n) && /1개/.test(n)), notes.join('|'));
  assert.ok(notes.some((n) => /v5→v6/.test(n) && /0개/.test(n)), notes.join('|'));
  assert.ok(notes.some((n) => /v6→v7/.test(n)), notes.join('|'));
  assert.ok(notes.some((n) => /v7→v8/.test(n)), notes.join('|'));
  assert.ok(notes.some((n) => /v8→v9/.test(n)), notes.join('|'));
});

t('v3 → v9(v6·v7·v8 을 거쳐): used_rs 버림, rps 는 approved·조각 없음, openings [] (v4·v5 규칙을 거쳐 온다)', () => {
  const { state, notes } = migrateCiaState({ version: 3, accounts: {}, issued: {}, used_rs: { '12345': ['1'] }, rps: { '777': { name: 'old', origin: 'http://127.0.0.1:3100', at: '2026-09-15T00:00:00.000Z' } }, revoked: [], pending: [], epoch: 0 });
  assert.equal(state.version, 11); assert.equal(state.used_rs, undefined); assert.equal(state.issued, undefined);
  const e = state.rps['777'];
  assert.equal(e.status, 'approved'); assert.equal(e.pk_service, null); assert.equal(e.X_svc, null); assert.equal(e.x_AA, null); assert.equal(e.pk_trace, null);
  assert.equal(e.requestedAt, '2026-09-15T00:00:00.000Z');
  assert.deepEqual(state.openings, []);
  assert.equal(notes.length, 8);
});

t('v7 → v9(v8 을 거쳐): 계정마다 sessions:[] 가 생기고 다른 필드는 그대로', () => {
  const s = { version: 7, accounts: { '1': { creds: [{ Cf_u: '9', leaf: '8', revoked: false }], attrs: ['1', '2', '3', '4'], disabled: false } }, rps: {}, openings: [], revoked: [], pending: [], epoch: 3 };
  const { state, notes } = migrateCiaState(s);
  assert.equal(state.version, 11);
  assert.deepEqual(state.accounts['1'].sessions, []);
  assert.deepEqual(state.accounts['1'].creds, [{ Cf_u: '9', leaf: '8', revoked: false }]);
  assert.equal(state.epoch, 3);
  assert.ok(notes.some((n) => n.startsWith('v7→v8')));
  assert.ok(notes.some((n) => n.startsWith('v8→v9')));
});
t('v8 → v9: sessions 가 빠진 계정은 채워지고 슬롯이 배정된다', () => {
  const s = { version: 8, accounts: { '1': { creds: [] } }, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 };
  const { state, notes } = migrateCiaState(s);
  assert.equal(state.version, 11);
  assert.deepEqual(state.accounts['1'].sessions, []);
  assert.equal(state.accounts['1'].slot, 0); assert.equal(state.accounts['1'].tampered, false);
  assert.ok(notes.some((n) => n.startsWith('v8→v9')));
});

t('v11 은 그대로(notes 없음), v2 이하·미래 버전은 throw', () => {
  const { state, notes } = migrateCiaState(defaultCiaState());
  assert.equal(state.version, 11); assert.deepEqual(notes, []);
  assert.throws(() => migrateCiaState({ version: 2 }), /version 2/);
  assert.throws(() => migrateCiaState({ version: 12 }), /version 12/);
});

t('v6 → v9(v7·v8 을 거쳐): attrs 가 채워지고 활성 자격증명은 전부 물려 revoked·pending 에 리프가 들어간다', () => {
  const s = { version: 6, accounts: { '12345': { pk_u: {}, cm_u: {}, disabled: false, creds: [{ Cf_u: '1', C_u_pt: {}, leaf: '111', issuedAt: 'x', revoked: false }, { Cf_u: '2', C_u_pt: {}, leaf: '222', issuedAt: 'y', revoked: true }] } }, rps: {}, openings: [], revoked: ['222'], pending: [], epoch: 0 };
  const { state } = migrateCiaState(s, { demoAttrs: (uid) => (uid === '12345' ? ['1990', '410', '2', '0'] : null) });
  assert.equal(state.version, 11);
  assert.deepEqual(state.accounts['12345'].attrs, ['1990', '410', '0', '0', '0', '0']);
  assert.deepEqual(state.accounts['12345'].profile, { birthYear: '1990', country: 'KR' }, 'v10→v11: profile 은 옛 attrs 에서 되살린다(등급 2 는 버림)');
  assert.equal(state.accounts['12345'].creds[0].revoked, true);
  assert.deepEqual(state.revoked, ['222', '111']); assert.deepEqual(state.pending, ['111']);
  assert.deepEqual(state.accounts['12345'].sessions, []);
  assert.equal(state.accounts['12345'].slot, 0);
});
t('v9 기본 상태와 demoAttrs 없는 계정은 0 여섯 개', () => {
  assert.equal(defaultCiaState().version, 11);
  const { state } = migrateCiaState({ version: 6, accounts: { '1': { pk_u: {}, cm_u: {}, disabled: false, creds: [] } }, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 });
  assert.deepEqual(state.accounts['1'].attrs, ['0', '0', '0', '0', '0', '0']);
});

t('v9 → v10: 계정마다 receipt=null·slotRetired=false, lastPublication=null(V10 접수증·대기열 은퇴)', () => {
  const v9 = { version: 9, accounts: { '1': { creds: [], sessions: [], slot: 0, tampered: false, attrs: ['0', '0', '0', '0', '0', '0'] } }, rps: {}, openings: [], revoked: [], pending: [], epoch: 4,
    registry: { depth: 20, next: 1, leaves: {}, pendingSlots: [] } };
  const { state, notes } = migrateCiaState(v9);
  assert.equal(state.version, 11);
  assert.equal(state.accounts['1'].receipt, null);
  assert.equal(state.accounts['1'].slotRetired, false);
  assert.equal(state.lastPublication, null);
  assert.equal(state.epoch, 4);
  assert.ok(notes.some((n) => n.startsWith('v9→v10')), notes.join('|'));
});

// 2026-10-02 V10 최종 리뷰 I-2(a): signedEpochMax 는 버전을 올리지 않고 v10 안에서 기본 0 으로 채운다.
t('v10 파일에 signedEpochMax 가 없으면 0, 있으면 그대로(버전 11 유지·notes 없음)', () => {
  const old = defaultCiaState(); delete old.signedEpochMax;
  const a = migrateCiaState(old);
  assert.equal(a.state.version, 11); assert.equal(a.state.signedEpochMax, 0); assert.deepEqual(a.notes, []);
  const b = migrateCiaState({ ...defaultCiaState(), epoch: 3, signedEpochMax: 5 });
  assert.equal(b.state.signedEpochMax, 5);
});

// 2026-10-07 최종 리뷰 I4: attrSchemaHash 도 같은 방식(버전 그대로, 없으면 null — cia.js 가 기록·대조).
t('attrSchemaHash 가 없는 v11 파일은 null 로 채우고, 있으면 그대로(notes 없음)', () => {
  const old = defaultCiaState(); delete old.attrSchemaHash;
  const a = migrateCiaState(old);
  assert.equal(a.state.version, 11); assert.equal(a.state.attrSchemaHash, null); assert.deepEqual(a.notes, []);
  assert.equal(migrateCiaState({ ...defaultCiaState(), attrSchemaHash: 'ab'.repeat(32) }).state.attrSchemaHash, 'ab'.repeat(32));
});

t('v10 → v11: profile 생성, 표현 못 하는 값(등급·알 수 없는 국가·예비 슬롯) 버림, attrs 가 바뀐 계정만 attrsChanged, 바뀌지 않은 계정은 그대로', () => {
  const v10 = { ...defaultCiaState(), version: 10, accounts: {
    '12345': { pk_u: {}, cm_u: {}, slot: 0, tampered: false, disabled: false, creds: [{ Cf_u: '1', C_u_pt: {}, leaf: '0', issuedAt: 'x', revoked: false }], attrs: ['1990', '410', '2', '0', '0', '0'], sessions: [], receipt: null, slotRetired: false },
    '67890': { pk_u: {}, cm_u: {}, slot: 1, tampered: false, disabled: false, creds: [], attrs: ['2005', '999', '0', '55', '0', '0'], sessions: [], receipt: null, slotRetired: false },
    '77777': { pk_u: {}, cm_u: {}, slot: 2, tampered: false, disabled: false, creds: [], attrs: ['1980', '392', '0', '0', '0', '0'], sessions: [], receipt: null, slotRetired: false },
  } };
  const { state, notes, attrsChanged } = migrateCiaState(structuredClone(v10));
  assert.equal(state.version, 11);
  assert.deepEqual(state.accounts['12345'].profile, { birthYear: '1990', country: 'KR' });
  assert.deepEqual(state.accounts['12345'].attrs, ['1990', '410', '0', '0', '0', '0']);
  assert.deepEqual(state.accounts['67890'].profile, { birthYear: '2005' });
  assert.deepEqual(state.accounts['67890'].attrs, ['2005', '0', '0', '0', '0', '0']);
  assert.deepEqual(state.accounts['77777'].profile, { birthYear: '1980', country: 'JP' });
  assert.deepEqual(state.accounts['77777'].attrs, ['1980', '392', '0', '0', '0', '0']);
  assert.deepEqual(attrsChanged.sort(), ['12345', '67890'], '값이 바뀐 계정만 — 77777 은 그대로');
  assert.equal(state.accounts['12345'].creds[0].revoked, false, '이행 함수는 자격증명을 물리지 않는다 — cia.js 기동이 attrsChanged 로 물리고 슬롯 0 을 게시한다');
  assert.ok(notes.some((n) => n.startsWith('v10→v11') && n.includes('2개')), notes.join('|'));
  assert.ok(notes.some((n) => n.includes('uid 12345') && n.includes('슬롯 2')), '버린 값마다 한 줄');
});

t('v11 파일: profile 이 없는 계정(손으로 고친 파일)은 attrs 에서 되살리고 attrs 는 건드리지 않는다, attrsChanged 는 빈 배열', () => {
  const v11 = { ...defaultCiaState(), accounts: { '1': { pk_u: {}, cm_u: {}, slot: 0, disabled: false, creds: [], attrs: ['1990', '410', '77', '0', '0', '0'], sessions: [] } } };
  const { state, attrsChanged } = migrateCiaState(structuredClone(v11));
  assert.deepEqual(state.accounts['1'].profile, { birthYear: '1990', country: 'KR' });
  assert.deepEqual(state.accounts['1'].attrs, ['1990', '410', '77', '0', '0', '0']);
  assert.deepEqual(attrsChanged, []);
});

process.exit(failed === 0 ? 0 : 1);
