// SecretSource — 스펙 2026-09-22 metamask-snap §3.3. 외부 의존 없음.   node tests/test_mode3_secret_source.js
import assert from 'node:assert/strict';
import { createSecretSource, stripSecrets, validateWitness } from '../lib/mode3_secret_source.js';

let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

const REG = { uid: '12345', s_u: '11', r_u: '22', sk_u: 'ab'.repeat(32), attrs: ['1990', '410', '2', '0'], cm_u: { x: '1', y: '2' },
  userCred: { C_u_pt: { x: '3', y: '4' }, Cf_u: '5', blind_u: '33', leaf: '6', issuedAt: 'now' } };

await t('file 모드: registration()/userCred() 는 상태 파일 값 그대로, setUserCred/setAttrs 는 상태를 바꾼다', () => {
  const state = { registration: structuredClone(REG) };
  const src = createSecretSource({ mode: 'file', state });
  assert.equal(src.mode, 'file');
  assert.equal(src.registration().s_u, '11'); assert.equal(src.userCred().blind_u, '33');
  src.setUserCred(null); assert.equal(state.registration.userCred, null);
  src.setAttrs(['1', '2', '3', '4']); assert.deepEqual(state.registration.attrs, ['1', '2', '3', '4']);
  assert.deepEqual(src.pending, {});
});

await t('snap 모드: 비밀은 witness 에서만 오고 상태는 바꾸지 않으며 pending 에 쌓인다', () => {
  const state = { registration: stripSecrets(REG) };
  const witness = { uid: '12345', s_u: '11', r_u: '22', sk_u: 'ab'.repeat(32), attrs: REG.attrs, userCred: REG.userCred };
  const src = createSecretSource({ mode: 'snap', state, witness });
  assert.equal(src.registration().s_u, '11'); assert.equal(src.registration().cm_u.x, '1', 'cm_u 는 파일의 공개값');
  const uc = { C_u_pt: { x: '7', y: '8' }, Cf_u: '9', blind_u: '44', leaf: '10', issuedAt: 'later' };
  src.setUserCred(uc);
  assert.deepEqual(src.pending.userCredIssued, uc);
  assert.deepEqual(state.registration.userCred, { Cf_u: '9', leaf: '10', issuedAt: 'later' }, '파일에는 공개 부분만');
  assert.equal(JSON.stringify(state).includes('"blind_u"'), false);
  src.setAttrs(['1', '2', '3', '4']); assert.deepEqual(src.pending.attrsChanged, ['1', '2', '3', '4']); assert.deepEqual(state.registration.attrs, ['1', '2', '3', '4']);
});

await t('stripSecrets 는 s_u·r_u·sk_u·blind_u 를 지운다', () => {
  const s = stripSecrets(REG);
  assert.deepEqual(Object.keys(s).sort(), ['attrs', 'cm_u', 'uid', 'userCred']);
  assert.deepEqual(s.userCred, { Cf_u: '5', leaf: '6', issuedAt: 'now' });
  assert.equal(stripSecrets({ ...REG, userCred: null }).userCred, null);
});

await t('validateWitness: uid 불일치·형식·범위 오류는 bad_witness', () => {
  const w = { uid: '12345', s_u: '11', r_u: '22', sk_u: 'ab'.repeat(32), attrs: ['1', '2', '3', '4'], userCred: null };
  validateWitness(w, '12345');
  for (const bad of [{ ...w, uid: '1' }, { ...w, s_u: 'x' }, { ...w, s_u: (1n << 250n).toString() }, { ...w, sk_u: 'zz' }, { ...w, attrs: ['1'] }, { ...w, attrs: [(1n << 64n).toString(), '0', '0', '0'] }, null]) {
    assert.throws(() => validateWitness(bad, '12345'), (e) => e.reason === 'bad_witness', JSON.stringify(bad));
  }
});
process.exit(failed === 0 ? 0 : 1);
