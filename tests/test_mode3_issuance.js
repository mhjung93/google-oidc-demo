// 발급 PoK 시그마 프로토콜 (설계 §6.2). 외부 의존 없음.
//   node tests/test_mode3_issuance.js
import assert from 'node:assert/strict';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import { randomScalar, credCommit, PEDERSEN_GENERATORS, compressPoint, SCALAR_MAX } from '../lib/mode3_credential.js';
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

await t('음성: z_ru 를 바꾸면 거절된다 (두 번째 등식)', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  const bj = await buildBabyjub();
  const bad = { ...proof, z_ru: (proof.z_ru + 1n) % bj.subOrder };
  assert.equal(await verifyIssuance({ uid, C_pt, cm_u, proof: bad }), false);
});

// C_pt 표현은 other_su 로 만들되, 챌린지·cm_u 는 등록된 (s_u, r_u) 로 맞춘 공격자 위조
// 트랜스크립트. eq1(=C_pt 표현 지식)은 통과하지만 eq2(=cm_u 와의 s_u 결속)에서 걸려야
// 한다 — 이것이 Sybil 을 막는 실제 등식이다.
async function forgeMismatchedSu(u) {
  const bj = await buildBabyjub();
  const r = bj.subOrder;
  const G = (name) => [bj.F.e(PEDERSEN_GENERATORS[name][0]), bj.F.e(PEDERSEN_GENERATORS[name][1])];
  const [G1, G2, G3, G4, H] = ['uid', 'arid', 's_u', 'pk_i', 'blind'].map(G);
  const msm = (terms) => terms.reduce((acc, [e, P]) => {
    const Q = bj.mulPointEscalar(P, e);
    return acc === null ? Q : bj.addPoint(acc, Q);
  }, null);
  const toObj = (P) => ({ x: bj.F.toObject(P[0]), y: bj.F.toObject(P[1]) });

  const other_su = randomScalar();
  const C_pt = toObj(msm([[uid, G1], [arid, G2], [other_su, G3], [pk_i, G4], [u.blind, H]]));
  const cm_u = u.cm_u; // 등록된 커밋 그대로 제시

  const a = {};
  for (const k of ['arid', 'su', 'pki', 'blind', 'ru']) a[k] = await randomZr();
  const T1 = toObj(msm([[a.arid, G2], [a.su, G3], [a.pki, G4], [a.blind, H]]));
  const T2 = toObj(msm([[a.su, G3], [a.ru, H]]));

  const ps = await buildPoseidon();
  const c = ps.F.toObject(ps([
    DOMAIN_MODE3_ISSUE, uid, C_pt.x, C_pt.y, cm_u.x, cm_u.y, T1.x, T1.y, T2.x, T2.y,
  ])) & ((1n << 250n) - 1n);

  const z = (ax, x) => (ax + c * x) % r;
  const proof = {
    T1, T2, c,
    z_arid: z(a.arid, arid), z_su: z(a.su, other_su), z_pki: z(a.pki, pk_i),
    z_blind: z(a.blind, u.blind), z_ru: z(a.ru, u.r_u),
  };
  return { C_pt, cm_u, proof, G1, G2, G3, G4, H, bj };
}

await t('음성: 챌린지를 등록된 cm_u 로 맞춰도 s_u 가 다르면 두 번째 등식에서 거절된다 (Sybil 의 실제 방어선)', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof, G1, G2, G3, G4, H, bj } = await forgeMismatchedSu(u);

  assert.equal(await verifyIssuance({ uid, C_pt, cm_u, proof }), false);

  // eq1 은 로컬에서 재계산해도 통과함을 확인한다 — 즉 위 거절의 원인이 eq2 임을 보인다.
  const mulP = (P, e) => bj.mulPointEscalar(P, e);
  const addP = (A, B) => bj.addPoint(A, B);
  const negP = (P) => [bj.F.neg(P[0]), P[1]];
  const fromObj = (o) => [bj.F.e(o.x), bj.F.e(o.y)];
  const eqPt = (A, B) => bj.F.eq(A[0], B[0]) && bj.F.eq(A[1], B[1]);

  const Y1 = addP(fromObj(C_pt), negP(mulP(G1, uid)));
  const lhs1 = addP(addP(addP(mulP(G2, proof.z_arid), mulP(G3, proof.z_su)), mulP(G4, proof.z_pki)), mulP(H, proof.z_blind));
  const rhs1 = addP(fromObj(proof.T1), mulP(Y1, proof.c));
  assert.ok(eqPt(lhs1, rhs1), 'eq1 은 통과해야 한다 (거절 원인이 eq2 임을 확인)');
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

await t('음성: 좌표가 p 이상인 비정규 인코딩은 거절된다', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  const bj = await buildBabyjub();
  const nonCanonical = { x: C_pt.x + bj.F.p, y: C_pt.y };
  assert.equal(await verifyIssuance({ uid, C_pt: nonCanonical, cm_u, proof }), false);
});

await t('음성: uid·arid 가 2^250 이상이면 발급 요청을 만들지 않는다 (show 회로의 Num2Bits(250) 이 열 수 없는 credential)', async () => {
  const u = await freshUser();
  await assert.rejects(() => proveIssuance({ uid: SCALAR_MAX, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u }), /2\^250/);
  await assert.rejects(() => proveIssuance({ uid, arid: SCALAR_MAX, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u }), /2\^250/);
});

await t('음성: CIA 쪽 검증도 uid 가 2^250 이상이면 거절한다', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  assert.equal(await verifyIssuance({ uid: SCALAR_MAX, C_pt, cm_u, proof }), false);
});

await t('직렬화 왕복이 값을 보존한다', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  const wire = JSON.parse(JSON.stringify({ C_pt: pointToStrings(C_pt), cm_u: pointToStrings(cm_u), proof: serializeProof(proof) }));
  assert.equal(await verifyIssuance({ uid, C_pt: pointFromStrings(wire.C_pt), cm_u: pointFromStrings(wire.cm_u), proof: parseProof(wire.proof) }), true);
});

process.exit(failed === 0 ? 0 : 1);
