// 발급 PoK 시그마 프로토콜 (설계 §6.2). 외부 의존 없음.
//   node tests/test_mode3_issuance.js
import assert from 'node:assert/strict';
import { buildBabyjub } from 'circomlibjs';
import { randomScalar, credCommit, PEDERSEN_GENERATORS, compressPoint } from '../lib/mode3_credential.js';
import {
  DOMAIN_MODE3_ISSUE, randomZr, registrationCommit, proveIssuance, verifyIssuance,
  serializeProof, parseProof, pointToStrings, pointFromStrings,
} from '../lib/mode3_issuance.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const uid = 12345n;
const arid = 22222222222222222222n;
const pk_i = 0x1234567890123456789012345678901234567890n;

async function freshUser() {
  const s_u = randomScalar();
  const r_u = randomScalar();
  const blind = randomScalar();
  const cm_u = await registrationCommit(s_u, r_u);
  return { s_u, r_u, blind, cm_u };
}

await t('도메인 태그는 "MODE3ISSUE" 빅엔디언이다', () => {
  assert.equal(DOMAIN_MODE3_ISSUE, BigInt('0x' + Buffer.from('MODE3ISSUE').toString('hex')));
});

await t('randomZr 는 [0, r) 안이다', async () => {
  const bj = await buildBabyjub();
  for (let i = 0; i < 20; i++) {
    const z = await randomZr();
    assert.ok(z >= 0n && z < bj.subOrder);
  }
});

await t('양성: 올바른 witness 의 증명이 검증된다', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  assert.equal(cm_u.x, u.cm_u.x); assert.equal(cm_u.y, u.cm_u.y);
  assert.equal(await verifyIssuance({ uid, C_pt, cm_u, proof }), true);
});

await t('C_pt 는 credCommit 과 같은 점이다 (회로가 여는 그 커밋)', async () => {
  const u = await freshUser();
  const { C_pt } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  const { Cx, Cy, Cf } = await credCommit({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i });
  assert.equal(C_pt.x, Cx); assert.equal(C_pt.y, Cy);
  assert.equal(await compressPoint(C_pt), Cf, 'CIA 가 C_pt 에서 유도하는 C 가 credCommit 의 Cf 와 같아야 한다');
});

await t('음성: 등록된 cm_u 와 다른 s_u 로 만든 C_pt 는 거절된다 (Sybil)', async () => {
  const u = await freshUser();
  const other_su = randomScalar();
  // 공격자: C_pt 는 other_su 로, cm_u 는 등록된 것(u.s_u)을 제시
  const forged = await proveIssuance({ uid, arid, s_u: other_su, blind: u.blind, pk_i, r_u: u.r_u });
  assert.equal(await verifyIssuance({ uid, C_pt: forged.C_pt, cm_u: u.cm_u, proof: forged.proof }), false);
});

await t('음성: 다른 uid 로 재생하면 거절된다 (Fiat-Shamir 가 uid 를 덮는다)', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  assert.equal(await verifyIssuance({ uid: uid + 1n, C_pt, cm_u, proof }), false);
});

await t('음성: 응답 하나를 바꾸면 거절된다', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  const bad = { ...proof, z_arid: (proof.z_arid + 1n) };
  assert.equal(await verifyIssuance({ uid, C_pt, cm_u, proof: bad }), false);
});

await t('음성: 곡선 밖의 점은 거절된다', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  assert.equal(await verifyIssuance({ uid, C_pt: { x: 1n, y: 1n }, cm_u, proof }), false);
});

await t('직렬화 왕복이 값을 보존한다', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  const wire = JSON.parse(JSON.stringify({ C_pt: pointToStrings(C_pt), cm_u: pointToStrings(cm_u), proof: serializeProof(proof) }));
  assert.equal(await verifyIssuance({ uid, C_pt: pointFromStrings(wire.C_pt), cm_u: pointFromStrings(wire.cm_u), proof: parseProof(wire.proof) }), true);
});

process.exit(failed === 0 ? 0 : 1);
