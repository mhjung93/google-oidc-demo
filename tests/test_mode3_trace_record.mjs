// lib/mode3_trace_record.js — PPID 계정 추적 기록의 암호화·2-of-3 임계 복호(스펙 2026-11-26 ppid-account-trace). 체인·회로 없이 돈다. (unit)
//   node tests/test_mode3_trace_record.mjs
import assert from 'node:assert/strict';
import { openFromParts, AUDITORS, THRESHOLD, TRACE_PUB_INDEX, dealAuditorKey, sharePublic, pkFromShares, isSubgroupPoint, encryptTrace, partialDecryptTrace, verifyPartial, combineTrace, traceWitness, samePublicSignals, partToJson, partFromJson, ptToJson, ptFromJson } from '../lib/mode3_trace_record.js';
import { auidOf, ppid, randomScalar } from '../lib/mode3_credential.js';

let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const key = await dealAuditorKey();
const s_u = randomScalar(), auid = await auidOf({ s_u });
const pairs = [[0, 1], [0, 2], [1, 2]];

await t('키 생성: 조각 셋, 공개키는 부분군의 점, 조각 공개키는 x·B8 — 어느 둘로도 같은 pk_aud 가 다시 나온다', async () => {
  assert.equal(AUDITORS, 3); assert.equal(THRESHOLD, 2); assert.deepEqual(key.shares.map((s) => s.index), [1, 2, 3]);
  assert.equal(await isSubgroupPoint(key.pk), true); assert.equal('x' in key, false, '비밀 x 를 돌려준다');
  for (const s of key.shares) assert.deepEqual(await sharePublic(s.x), s.X);
  for (const [a, b] of pairs) assert.deepEqual(await pkFromShares(key.shares[a], key.shares[b]), key.pk);
  assert.notDeepEqual((await dealAuditorKey()).pk, key.pk, '두 번 만든 키가 같다');
});
await t('암호화 → 어느 두 조각으로도 auid 가 나온다(순서를 바꿔도), 같은 평문의 두 암호문은 서로 다르다', async () => {
  const ct = await encryptTrace(key.pk, auid);
  for (const [a, b] of pairs) {
    const pa = await partialDecryptTrace(key.shares[a], ct.c1), pb = await partialDecryptTrace(key.shares[b], ct.c1);
    assert.equal(await combineTrace(ct.c2, pa, pb), auid); assert.equal(await combineTrace(ct.c2, pb, pa), auid);
  }
  const ct2 = await encryptTrace(key.pk, auid);
  assert.notDeepEqual(ct2.c1, ct.c1); assert.notEqual(ct2.c2, ct.c2);
});
await t('조각 하나로는 안 된다: 같은 조각을 두 번 내면 거절하고, 다른 키의 조각을 섞으면 auid 가 아니다', async () => {
  const ct = await encryptTrace(key.pk, auid);
  const p1 = await partialDecryptTrace(key.shares[0], ct.c1);
  await assert.rejects(() => combineTrace(ct.c2, p1, p1), /index/);
  const other = await dealAuditorKey();
  const bad = await partialDecryptTrace(other.shares[1], ct.c1);
  assert.notEqual(await combineTrace(ct.c2, p1, bad), auid);
});
await t('부분 복호의 증명(DLEQ): 맞는 조각은 통과, 다른 조각·바꾼 D·바꾼 z·다른 암호문·다른 공개키는 거절', async () => {
  const ct = await encryptTrace(key.pk, auid), sh = key.shares[1];
  const part = await partialDecryptTrace(sh, ct.c1);
  assert.equal(await verifyPartial(sh.X, ct.c1, part), true);
  assert.equal(await verifyPartial(key.shares[0].X, ct.c1, part), false, '다른 감사자의 공개키');
  const other = await partialDecryptTrace(key.shares[2], ct.c1);
  assert.equal(await verifyPartial(sh.X, ct.c1, { ...part, D: other.D }), false, 'D 바꿈');
  assert.equal(await verifyPartial(sh.X, ct.c1, { ...part, proof: { ...part.proof, z: part.proof.z + 1n } }), false, 'z 바꿈');
  assert.equal(await verifyPartial(sh.X, (await encryptTrace(key.pk, auid)).c1, part), false, '다른 암호문');
  for (const junk of [null, {}, { D: part.D }, { D: { x: 1n, y: 2n }, proof: part.proof }, { D: part.D, proof: { A: part.proof.A, B: part.proof.B, z: -1n } }]) assert.equal(await verifyPartial(sh.X, ct.c1, junk), false);
});
await t('JSON 으로 옮겨도 같다(점·부분 복호)', async () => {
  const ct = await encryptTrace(key.pk, auid), part = await partialDecryptTrace(key.shares[0], ct.c1);
  const back = partFromJson(JSON.parse(JSON.stringify(partToJson(part))));
  assert.deepEqual(back, part); assert.equal(await verifyPartial(key.shares[0].X, ptFromJson(JSON.parse(JSON.stringify(ptToJson(ct.c1)))), back), true);
  assert.throws(() => ptFromJson({ x: 'a', y: '1' }));
});
await t('회로 입력: 공개 입력 8개가 정해진 순서이고 PPID·auid 가 자격증명 쪽 식과 같다 — rho 를 주면 같은 암호문', async () => {
  const arid = 1234n, chainid = 31337n;
  const w = await traceWitness({ s_u, arid, chainid, pk_aud: key.pk });
  assert.equal(w.publicSignals.length, TRACE_PUB_INDEX.COUNT); assert.equal(w.PPID, await ppid({ s_u, arid, chainid })); assert.equal(w.auid, auid);
  assert.deepEqual([w.publicSignals[TRACE_PUB_INDEX.PPID], w.publicSignals[TRACE_PUB_INDEX.ARID], w.publicSignals[TRACE_PUB_INDEX.CHAINID]], [w.PPID.toString(), '1234', '31337']);
  assert.deepEqual([w.publicSignals[TRACE_PUB_INDEX.PK_AUD_X], w.publicSignals[TRACE_PUB_INDEX.PK_AUD_Y]], [key.pk.x.toString(), key.pk.y.toString()]);
  assert.deepEqual([w.publicSignals[TRACE_PUB_INDEX.C1_X], w.publicSignals[TRACE_PUB_INDEX.C1_Y], w.publicSignals[TRACE_PUB_INDEX.C2]], [w.c1.x.toString(), w.c1.y.toString(), w.c2.toString()]);
  assert.deepEqual(Object.keys(w.input).sort(), ['PPID', 'arid', 'c1_x', 'c1_y', 'c2', 'chainid', 'pk_aud_x', 'pk_aud_y', 'rho', 's_u']);
  const again = await traceWitness({ s_u, arid, chainid, pk_aud: key.pk, rho: BigInt(w.input.rho) });
  assert.equal(samePublicSignals(again.publicSignals, w.publicSignals), true); assert.equal(samePublicSignals(w.publicSignals.slice(1), w.publicSignals), false);
  // 그 암호문을 두 조각으로 열면 그 auid 다
  const pa = await partialDecryptTrace(key.shares[0], w.c1), pb = await partialDecryptTrace(key.shares[2], w.c1);
  assert.equal(await combineTrace(w.c2, pa, pb), auid);
});
await t('잘못된 입력은 던진다: 부분군 밖의 pk_aud, rho 0·2^250 이상, 범위 밖 조각', async () => {
  await assert.rejects(() => encryptTrace({ x: 1n, y: 2n }, auid)); await assert.rejects(() => encryptTrace({ x: 0n, y: 1n }, auid), /부분군/);
  await assert.rejects(() => encryptTrace(key.pk, auid, 0n)); await assert.rejects(() => encryptTrace(key.pk, auid, 1n << 250n));
  const ct = await encryptTrace(key.pk, auid);
  await assert.rejects(() => partialDecryptTrace({ index: 1, x: 0n }, ct.c1)); await assert.rejects(() => partialDecryptTrace(key.shares[0], { x: 0n, y: 1n }));
});
await t('요청 결속(ctx): 한 요청에 낸 부분 복호는 다른 요청의 것으로 통과하지 않는다 — 조합도 ctx 가 맞아야 열린다', async () => {
  const ct = await encryptTrace(key.pk, auid), sh = key.shares[0];
  const part = await partialDecryptTrace(sh, ct.c1, 7n);
  assert.equal(await verifyPartial(sh.X, ct.c1, part, 7n), true); assert.equal(await verifyPartial(sh.X, ct.c1, part, 8n), false); assert.equal(await verifyPartial(sh.X, ct.c1, part), false, 'ctx 없이');
  await assert.rejects(() => partialDecryptTrace(sh, ct.c1, -1n)); await assert.rejects(() => partialDecryptTrace(sh, ct.c1, 7));
  const parts = [part, await partialDecryptTrace(key.shares[1], ct.c1, 7n)], shareXs = Object.fromEntries(key.shares.map((x) => [x.index, x.X])), base = { pk: key.pk, shareXs, c1: ct.c1, c2: ct.c2, parts };
  assert.equal((await openFromParts({ ...base, ctx: 7n })).auid, auid);
  await assert.rejects(() => openFromParts({ ...base, ctx: 8n }), (e) => e.reason === 'trace_share_bad');
});
await t('조합은 맞는 쌍을 찾는다: 다른 키의 조각(그 키의 공개키와는 짝이 맞는)이 하나 섞여도 나머지 둘로 열린다 — 맞는 쌍이 없으면 trace_key_mismatch', async () => {
  const other = await dealAuditorKey(), ct = await encryptTrace(key.pk, auid);
  const p1 = await partialDecryptTrace(other.shares[0], ct.c1), p2 = await partialDecryptTrace(key.shares[1], ct.c1), p3 = await partialDecryptTrace(key.shares[2], ct.c1);
  const shareXs = { 1: other.shares[0].X, 2: key.shares[1].X, 3: key.shares[2].X }, base = { pk: key.pk, shareXs, c1: ct.c1, c2: ct.c2 };
  const opened = await openFromParts({ ...base, parts: [p1, p2, p3] });
  assert.equal(opened.auid, auid); assert.deepEqual(opened.used, [2, 3]);
  await assert.rejects(() => openFromParts({ ...base, parts: [p1, p2] }), (e) => e.reason === 'trace_key_mismatch');
});
console.log(fails ? `\n${fails} FAILED` : '\nall ok');
process.exit(fails ? 1 : 0);
