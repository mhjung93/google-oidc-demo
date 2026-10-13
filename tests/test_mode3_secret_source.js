// 비밀 공급원(file·snap)·증인 검사 — V11 auid 바인딩. (unit)  node tests/test_mode3_secret_source.js
import assert from 'node:assert/strict';
import { createSecretSource, stripSecrets, validateWitness } from '../lib/mode3_secret_source.js';
import { auidOf } from '../lib/mode3_credential.js';

let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }
const AUID = (await auidOf({ uid: 12345n, s_u: 11n })).toString();
const REG = { uid: '12345', s_u: '11', sk_u: 'ab'.repeat(32), attrs: ['1990', '410', '2', '0', '0', '0'], auid: AUID, pk_u: { x: '9', y: '10' }, slot: 0, profile: { birthYear: '1990', country: 'KR' },
  userCred: { C_u_pt: { x: '1', y: '2' }, Cf_u: '3', blind_u: '4', issuedAt: 't' } };

await t('file 모드: registration 은 파일의 비밀·auid·profile 을 그대로, setUserCred/setAttrs 는 파일을 바꾸고 pending 은 비어 있다', () => {
  const state = { registration: structuredClone(REG) };
  const src = createSecretSource({ mode: 'file', state });
  assert.equal(src.registration().s_u, '11'); assert.equal(src.registration().auid, AUID); assert.deepEqual(src.registration().profile, REG.profile);
  src.setAttrs(['1', '0', '0', '0', '0', '0']); src.setUserCred(null);
  assert.deepEqual(state.registration.attrs, ['1', '0', '0', '0', '0', '0']); assert.equal(state.registration.userCred, null); assert.deepEqual(src.pending, {});
});
await t('snap 모드: 비밀은 증인에서, auid·slot 은 파일에서; setUserCred 는 pending.userCredIssued + 파일에는 공개 부분만', () => {
  const state = { registration: stripSecrets(REG) };
  const witness = { uid: '12345', s_u: '11', sk_u: 'ab'.repeat(32), attrs: REG.attrs, userCred: REG.userCred };
  const src = createSecretSource({ mode: 'snap', state, witness });
  assert.equal(src.registration().s_u, '11'); assert.equal(src.registration().auid, AUID, 'auid 는 파일의 공개값');
  const uc = { C_u_pt: { x: '5', y: '6' }, Cf_u: '7', blind_u: '8', issuedAt: 'u' };
  src.setUserCred(uc);
  assert.deepEqual(src.pending.userCredIssued, uc); assert.deepEqual(state.registration.userCred, { Cf_u: '7', issuedAt: 'u' });
  src.setAttrs(['2', '0', '0', '0', '0', '0']);
  assert.deepEqual(src.pending.attrsChanged, ['2', '0', '0', '0', '0', '0']); assert.deepEqual(witness.attrs, ['2', '0', '0', '0', '0', '0']);
});
await t('stripSecrets 는 s_u·sk_u·blind_u 를 지우고 auid·profile 을 남긴다', () => {
  const s = stripSecrets(REG);
  assert.deepEqual(Object.keys(s).sort(), ['attrs', 'auid', 'pk_u', 'profile', 'slot', 'uid', 'userCred']);
  assert.deepEqual(s.userCred, { Cf_u: '3', issuedAt: 't' }); assert.equal(s.auid, AUID);
  assert.equal(stripSecrets({ ...REG, profile: undefined }).profile, null, 'profile 이 없으면 null');
  assert.equal(stripSecrets(null), null);
});
await t('validateWitness: uid 불일치·형식·범위 오류는 bad_witness; r_u 는 더 요구하지 않는다', async () => {
  const w = { uid: '12345', s_u: '11', sk_u: 'ab'.repeat(32), attrs: ['1', '2', '3', '4', '5', '6'], userCred: null };
  await validateWitness(w, '12345');
  for (const bad of [{ ...w, uid: '1' }, { ...w, s_u: 'x' }, { ...w, s_u: (1n << 250n).toString() }, { ...w, sk_u: 'zz' }, { ...w, attrs: ['1'] }, { ...w, attrs: [(1n << 64n).toString(), '0', '0', '0', '0', '0'] }, { ...w, attrs: ['', '2', '3', '4', '5', '6'] }, { ...w, attrs: [true, '2', '3', '4', '5', '6'] }, { ...w, userCred: { Cf_u: '1' } }, null]) {
    await assert.rejects(() => validateWitness(bad, '12345'), (e) => e.reason === 'bad_witness', JSON.stringify(bad));
  }
});
await t('validateWitness: auid 를 주면 s_u 가 등록과 묶였는지 본다', async () => {
  const w = { uid: '12345', s_u: '11', sk_u: 'ab'.repeat(32), attrs: ['1', '2', '3', '4', '5', '6'], userCred: null };
  await validateWitness(w, '12345', AUID);                              // 맞는 증인은 통과
  await validateWitness({ ...w, s_u: '12' }, '12345');                  // auid 를 안 주면 형식만 본다
  await assert.rejects(() => validateWitness({ ...w, s_u: '12' }, '12345', AUID), (e) => e.reason === 'bad_witness' && /auid/.test(e.message));
  await assert.rejects(() => validateWitness(w, '12345', 'zz'), (e) => e.reason === 'bad_witness', '등록 auid 형식 오류');
});
process.exit(failed === 0 ? 0 : 1);
