// 2-of-2 트레이스 태그 (설계 2026-09-16 §4.1). 외부 의존 없음.
//   node tests/test_mode3_trace.js
import assert from 'node:assert/strict';
import { buildBabyjub } from 'circomlibjs';
import { SCALAR_MAX } from '../lib/mode3_credential.js';
import { B8, isTracePoint, createShare, combinePublicKey, randomTraceScalar, encryptTag, partialDecrypt, combineDecrypt, tagPlaintext, resolveTagPlaintext, proveShare, verifyShare, sharePublicKey } from '../lib/mode3_trace.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const bj = await buildBabyjub();
const F = bj.F;
const uid = 12345n;
const arid = 22222n;

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
  const tag = await encryptTag(pk, uid, arid);
  assert.ok(tag.r > 0n && tag.r < SCALAR_MAX);
  const D_svc = await partialDecrypt(svc.x, tag.c1);
  const D_aa = await partialDecrypt(aa.x, tag.c1);
  const h = await combineDecrypt(tag.c2, D_svc, D_aa);
  assert.equal(h, tag.h);
  assert.equal(h, await tagPlaintext(uid, arid), '평문은 Poseidon(uid, arid)');
  assert.notEqual(h, uid, 'uid 원문이 아니다');
  assert.equal(await combineDecrypt(tag.c2, D_aa, D_svc), h, '순서 무관');
  assert.equal(await resolveTagPlaintext(h, arid, ['1', '12345', '67890']), '12345');
  assert.equal(await resolveTagPlaintext(h, arid, ['1', '67890']), null);
  assert.equal(await resolveTagPlaintext(h, arid + 1n, ['12345']), null, '다른 arid 의 평문은 같은 uid 로 풀리지 않는다');
});

await t('음성: 조각 하나로는 uid 가 나오지 않는다', async () => {
  const svc = await createShare(), aa = await createShare();
  const pk = await combinePublicKey(svc.X, aa.X);
  const tag = await encryptTag(pk, uid, arid);
  const D_svc = await partialDecrypt(svc.x, tag.c1);
  const zero = { x: 0n, y: 1n };
  assert.notEqual(await combineDecrypt(tag.c2, D_svc, zero), tag.h);
  const D_wrong = await partialDecrypt((await createShare()).x, tag.c1);
  assert.notEqual(await combineDecrypt(tag.c2, D_svc, D_wrong), tag.h);
});

await t('태그는 r 마다 다르고, 같은 r 이면 결정적', async () => {
  const svc = await createShare(), aa = await createShare();
  const pk = await combinePublicKey(svc.X, aa.X);
  const a = await encryptTag(pk, uid, arid), b = await encryptTag(pk, uid, arid);
  assert.notEqual(a.c2, b.c2);
  const c = await encryptTag(pk, uid, arid, a.r);
  assert.equal(c.c2, a.c2); assert.equal(c.c1.x, a.c1.x);
});

await t('encryptTag 는 r = 0, r ≥ 2^250, 상한 밖 uid 를 거절한다', async () => {
  const pk = await combinePublicKey((await createShare()).X, (await createShare()).X);
  await assert.rejects(() => encryptTag(pk, uid, arid, 0n), /r/);
  await assert.rejects(() => encryptTag(pk, uid, arid, SCALAR_MAX), /r/);
  await assert.rejects(() => encryptTag(pk, SCALAR_MAX, arid, 5n), /uid/);
  assert.ok(randomTraceScalar() > 0n);
});

// ---- CIA 조각의 Schnorr PoK — rogue key 방지(2026-09-21) ----
await t('proveShare/verifyShare: 정직한 조각은 통과하고, 다른 arid·다른 X_svc·다른 X·변조된 z 는 실패한다', async () => {
  const svc = await createShare(), aa = await createShare();
  const ctx = { arid: 77n, X_svc: svc.X };
  const pok = await proveShare(aa.x, ctx);
  assert.deepEqual(pok.X, aa.X);
  assert.deepEqual(await sharePublicKey(aa.x), aa.X);
  assert.equal(await verifyShare(pok.X, pok, ctx), true);
  assert.equal(await verifyShare(pok.X, pok, { arid: 78n, X_svc: svc.X }), false, '다른 등록의 증명은 재사용할 수 없다');
  assert.equal(await verifyShare(pok.X, pok, { arid: 77n, X_svc: (await createShare()).X }), false);
  assert.equal(await verifyShare((await createShare()).X, pok, ctx), false);
  assert.equal(await verifyShare(pok.X, { ...pok, z: (pok.z + 1n) % bj.subOrder }, ctx), false);
  assert.equal(await verifyShare(pok.X, { ...pok, c: pok.c ^ 1n }, ctx), false);
  assert.equal(await verifyShare({ x: 0n, y: 1n }, pok, ctx), false, '항등원 조각은 거절');
  assert.equal(await verifyShare(pok.X, null, ctx), false);
  assert.equal(await verifyShare(pok.X, { T: { x: '1', y: 1n }, c: pok.c, z: pok.z }, ctx), false);
});

await t('rogue key: CIA 가 X_AA = X′ − X_svc 로 고르면 pk_trace = X′ 의 비밀을 혼자 알지만, x_AA 를 몰라 PoK 를 낼 수 없다', async () => {
  const svc = await createShare();
  const rogue = await createShare();               // X′ = x′·B8 — CIA 가 이산로그를 아는 점
  const negSvc = { x: (F.p - svc.X.x) % F.p, y: svc.X.y };
  const X_AA = await combinePublicKey(rogue.X, negSvc);   // X′ − X_svc
  const pk_trace = await combinePublicKey(svc.X, X_AA);
  assert.deepEqual(pk_trace, rogue.X, '조합 키가 CIA 혼자 아는 X′ 가 된다');
  // CIA 가 손에 쥔 것은 x′ 뿐 — 그것으로 낸 증명은 X_AA 에 대해 검증되지 않는다
  const ctx = { arid: 77n, X_svc: svc.X };
  const forged = await proveShare(rogue.x, ctx);
  assert.equal(await verifyShare(X_AA, forged, ctx), false);
  assert.equal(await verifyShare(X_AA, { ...forged, X: X_AA }, ctx), false);
  // 정직한 조각이면 통과 — 대조군
  const honest = await createShare();
  assert.equal(await verifyShare(honest.X, await proveShare(honest.x, ctx), ctx), true);
});

process.exit(failed === 0 ? 0 : 1);
