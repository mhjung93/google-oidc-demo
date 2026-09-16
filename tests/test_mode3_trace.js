// 2-of-2 트레이스 태그 (설계 2026-09-16 §4.1). 외부 의존 없음.
//   node tests/test_mode3_trace.js
import assert from 'node:assert/strict';
import { buildBabyjub } from 'circomlibjs';
import { SCALAR_MAX } from '../lib/mode3_credential.js';
import { B8, isTracePoint, createShare, combinePublicKey, randomTraceScalar, encryptTag, partialDecrypt, combineDecrypt } from '../lib/mode3_trace.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const bj = await buildBabyjub();
const F = bj.F;
const uid = 12345n;

await t('B8 는 circomlibjs Base8 이고 부분군 점이다', async () => {
  assert.equal(B8[0], F.toObject(bj.Base8[0])); assert.equal(B8[1], F.toObject(bj.Base8[1]));
  assert.equal(await isTracePoint({ x: B8[0], y: B8[1] }), true);
});

await t('isTracePoint: 항등원·곡선 밖·비정규 인코딩은 false', async () => {
  assert.equal(await isTracePoint({ x: 0n, y: 1n }), false, '항등원 X_svc 면 CIA 조각만으로 복호된다');
  assert.equal(await isTracePoint({ x: 1n, y: 1n }), false);
  assert.equal(await isTracePoint({ x: B8[0] + F.p, y: B8[1] }), false);
  assert.equal(await isTracePoint({ x: '1', y: 1n }), false);
});

await t('createShare: x < 2^250, X = x·B8', async () => {
  const s = await createShare();
  assert.ok(s.x > 0n && s.x < SCALAR_MAX);
  const P = bj.mulPointEscalar(bj.Base8, s.x);
  assert.equal(s.X.x, F.toObject(P[0])); assert.equal(s.X.y, F.toObject(P[1]));
});

await t('양성: 두 조각의 부분 복호를 더하면 uid 가 나온다', async () => {
  const svc = await createShare(), aa = await createShare();
  const pk = await combinePublicKey(svc.X, aa.X);
  const tag = await encryptTag(pk, uid);
  assert.ok(tag.r > 0n && tag.r < SCALAR_MAX);
  const D_svc = await partialDecrypt(svc.x, tag.c1);
  const D_aa = await partialDecrypt(aa.x, tag.c1);
  assert.equal(await combineDecrypt(tag.c2, D_svc, D_aa), uid);
  assert.equal(await combineDecrypt(tag.c2, D_aa, D_svc), uid, '순서 무관');
});

await t('음성: 조각 하나로는 uid 가 나오지 않는다', async () => {
  const svc = await createShare(), aa = await createShare();
  const pk = await combinePublicKey(svc.X, aa.X);
  const tag = await encryptTag(pk, uid);
  const D_svc = await partialDecrypt(svc.x, tag.c1);
  const zero = { x: 0n, y: 1n };
  assert.notEqual(await combineDecrypt(tag.c2, D_svc, zero), uid);
  const D_wrong = await partialDecrypt((await createShare()).x, tag.c1);
  assert.notEqual(await combineDecrypt(tag.c2, D_svc, D_wrong), uid);
});

await t('태그는 r 마다 다르고, 같은 r 이면 결정적', async () => {
  const svc = await createShare(), aa = await createShare();
  const pk = await combinePublicKey(svc.X, aa.X);
  const a = await encryptTag(pk, uid), b = await encryptTag(pk, uid);
  assert.notEqual(a.c2, b.c2);
  const c = await encryptTag(pk, uid, a.r);
  assert.equal(c.c2, a.c2); assert.equal(c.c1.x, a.c1.x);
});

await t('encryptTag 는 r = 0, r ≥ 2^250, 상한 밖 uid 를 거절한다', async () => {
  const pk = await combinePublicKey((await createShare()).X, (await createShare()).X);
  await assert.rejects(() => encryptTag(pk, uid, 0n), /r/);
  await assert.rejects(() => encryptTag(pk, uid, SCALAR_MAX), /r/);
  await assert.rejects(() => encryptTag(pk, SCALAR_MAX, 5n), /uid/);
  assert.ok(randomTraceScalar() > 0n);
});

process.exit(failed === 0 ? 0 : 1);
