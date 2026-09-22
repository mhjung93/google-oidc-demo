// 사용자 자격증명 PoK π_u 시그마 프로토콜 (설계 §6.2, 2026-09-21 §3.5)과 요청 서명 메시지. 외부 의존 없음.
//   node tests/test_mode3_issuance.js
import assert from 'node:assert/strict';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import { randomScalar, PEDERSEN_GENERATORS, SCALAR_MAX, normalizeAttrs, userCommit } from '../lib/mode3_credential.js';
import {
  randomZr, registrationCommit, proveUserCred, verifyUserCred, userCredRequestMessage, issueRequestMessageV4,
  serializeUserCredProof, parseUserCredProof, attrsRequestMessage,
  DOMAIN_MODE3_USERCRED_V2, DOMAIN_MODE3_ATTRSREQ, DOMAIN_MODE3_USERCREDREQ, DOMAIN_MODE3_ISSUEREQ_V4,
} from '../lib/mode3_issuance.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const uid = 12345n;

async function freshUser() {
  const s_u = randomScalar();
  const r_u = randomScalar();
  const blind = randomScalar();
  const cm_u = await registrationCommit(s_u, r_u);
  const attrs = [19n, 410n, 0n, 0n];
  return { s_u, r_u, blind, cm_u, attrs };
}

await t('randomZr 는 [0, r) 안이다', async () => {
  const bj = await buildBabyjub();
  for (let i = 0; i < 20; i++) {
    const z = await randomZr();
    assert.ok(z >= 0n && z < bj.subOrder);
  }
});

await t('normalizeAttrs: 배열이 아닌 입력은 throw, 길이 초과·범위 밖도 throw, 정상값은 정규화된다', () => {
  assert.throws(() => normalizeAttrs('12345'));
  assert.throws(() => normalizeAttrs(5));
  assert.throws(() => normalizeAttrs(['1', '2', '3', '4', '5']));
  assert.throws(() => normalizeAttrs(['-1']));
  assert.deepEqual(normalizeAttrs(['7']), [7n, 0n, 0n, 0n]);
  assert.deepEqual(normalizeAttrs(undefined), [0n, 0n, 0n, 0n]);
});

// ---- V5 (2026-09-21): 사용자 자격증명 증명 π_u; V2(2026-09-22): 속성은 AA 기록, PoK 는 (s_u, blind_u, r_u) 만 ----
await t('도메인 상수는 ASCII 빅엔디언이고 서로·옛 값과 다르다 (2026-09-22: USERCRED_V2·ATTRSREQ 추가, USERCRED 는 옛 값)', () => {
  const be = (s) => BigInt('0x' + Buffer.from(s).toString('hex'));
  assert.equal(DOMAIN_MODE3_USERCRED_V2, be('MODE3USERCRED2'));
  assert.equal(DOMAIN_MODE3_ATTRSREQ, be('MODE3ATTRSREQ'));
  assert.equal(DOMAIN_MODE3_USERCREDREQ, be('MODE3USERCREDREQ'));
  assert.equal(DOMAIN_MODE3_ISSUEREQ_V4, be('MODE3ISSUEREQV4'));
  const old = [be('MODE3ISSUE'), be('MODE3ISSUEREQV3'), be('MODE3USERCRED')];
  assert.equal(new Set([DOMAIN_MODE3_USERCRED_V2, DOMAIN_MODE3_ATTRSREQ, DOMAIN_MODE3_USERCREDREQ, DOMAIN_MODE3_ISSUEREQ_V4, ...old]).size, 7);
});

await t('π_u V2 양성: AA 가 자기 기록 attrs 로 검증하면 통과하고 C_u_pt 는 userCommit 과 같은 점', async () => {
  const uid = 12345n, s_u = randomScalar(), r_u = randomScalar(), blind_u = randomScalar(), attrs = [1990n, 410n, 2n, 0n];
  const { C_u_pt, cm_u, proof } = await proveUserCred({ uid, s_u, blind_u, r_u, attrs });
  const c = await userCommit({ uid, s_u, blind_u, attrs });
  assert.equal(C_u_pt.x, c.Cx); assert.equal(C_u_pt.y, c.Cy);
  assert.equal(await verifyUserCred({ uid, attrs, C_u_pt, cm_u, proof }), true);
  assert.equal(Object.hasOwn(proof, 'z_attr'), false, 'V2 에는 z_attr 이 없다 — 속성은 공개값');
});

await t('π_u V2 음성: AA 기록과 다른 attrs, cm_u 와 다른 s_u(Sybil), 다른 uid, 응답 변조, 곡선 밖 점', async () => {
  const uid = 12345n, s_u = randomScalar(), r_u = randomScalar(), blind_u = randomScalar(), attrs = [1990n, 410n, 2n, 0n];
  const { C_u_pt, cm_u, proof } = await proveUserCred({ uid, s_u, blind_u, r_u, attrs });
  assert.equal(await verifyUserCred({ uid, attrs: [1991n, 410n, 2n, 0n], C_u_pt, cm_u, proof }), false, '지갑이 넣은 속성이 AA 기록과 다르면 실패');
  assert.equal(await verifyUserCred({ uid: 12346n, attrs, C_u_pt, cm_u, proof }), false);
  const other = await proveUserCred({ uid, s_u: randomScalar(), blind_u, r_u, attrs });
  assert.equal(await verifyUserCred({ uid, attrs, C_u_pt: other.C_u_pt, cm_u, proof: other.proof }), false, 'cm_u 의 s_u 와 다르면 실패');
  assert.equal(await verifyUserCred({ uid, attrs, C_u_pt, cm_u, proof: { ...proof, z_su: (proof.z_su + 1n) } }), false);
  assert.equal(await verifyUserCred({ uid, attrs, C_u_pt: { x: 1n, y: 1n }, cm_u, proof }), false);
  await assert.rejects(() => proveUserCred({ uid, s_u, blind_u, r_u, attrs: [1n << 64n, 0n, 0n, 0n] }), /attr0/);
});

await t('attrsRequestMessage = Poseidon(DOMAIN_MODE3_ATTRSREQ, uid, nonce)', async () => {
  const ps = await buildPoseidon();
  assert.equal(await attrsRequestMessage(12345n, 7n), ps.F.toObject(ps([DOMAIN_MODE3_ATTRSREQ, 12345n, 7n])));
  await assert.rejects(() => attrsRequestMessage('12345', 7n), /uid/);
});

// C_u_pt 표현은 other_su 로 만들되, 챌린지·cm_u 는 등록된 (s_u, r_u) 로 맞춘 공격자 위조
// 트랜스크립트. eq1(=C_u_pt 표현 지식)은 통과하지만 eq2(=cm_u 와의 s_u 결속)에서 걸려야
// 한다 — 이것이 Sybil 을 막는 실제 등식이다. V2: attrs 는 공개값이라 witness/T1 에서 빠진다.
await t('π_u V2 음성: 챌린지를 등록된 cm_u 로 맞춰도 s_u 가 다르면 두 번째 등식에서 거절된다 (Sybil 의 실제 방어선)', async () => {
  const u = await freshUser();
  const bj = await buildBabyjub();
  const r = bj.subOrder;
  const G = (name) => [bj.F.e(PEDERSEN_GENERATORS[name][0]), bj.F.e(PEDERSEN_GENERATORS[name][1])];
  const [G1, G3, H] = ['uid', 's_u', 'blind'].map(G);
  const GA = ['attr0', 'attr1', 'attr2', 'attr3'].map(G);
  const msm = (terms) => terms.reduce((acc, [e, P]) => {
    const Q = bj.mulPointEscalar(P, e);
    return acc === null ? Q : bj.addPoint(acc, Q);
  }, null);
  const toObj = (P) => ({ x: bj.F.toObject(P[0]), y: bj.F.toObject(P[1]) });
  const fromObj = (o) => [bj.F.e(o.x), bj.F.e(o.y)];
  const eqPt = (A, B) => bj.F.eq(A[0], B[0]) && bj.F.eq(A[1], B[1]);

  const other_su = randomScalar();
  const C_u_pt = toObj(msm([[uid, G1], [other_su, G3], ...u.attrs.map((v, i) => [v, GA[i]]), [u.blind, H]]));
  const cm_u = u.cm_u; // 등록된 커밋 그대로 제시
  const a = {};
  for (const k of ['su', 'blind', 'ru']) a[k] = await randomZr();
  const T1 = toObj(msm([[a.su, G3], [a.blind, H]]));
  const T2 = toObj(msm([[a.su, G3], [a.ru, H]]));
  const ps = await buildPoseidon();
  const c = ps.F.toObject(ps([DOMAIN_MODE3_USERCRED_V2, uid, ...u.attrs, C_u_pt.x, C_u_pt.y, cm_u.x, cm_u.y, T1.x, T1.y, T2.x, T2.y])) & ((1n << 250n) - 1n);
  const z = (ax, x) => (ax + c * x) % r;
  const proof = { T1, T2, c, z_su: z(a.su, other_su), z_blind: z(a.blind, u.blind), z_ru: z(a.ru, u.r_u) };

  assert.equal(await verifyUserCred({ uid, attrs: u.attrs, C_u_pt, cm_u, proof }), false);
  // eq1 은 로컬에서 재계산해도 통과함을 확인한다 — 즉 위 거절의 원인이 eq2 임을 보인다.
  const known = msm([[uid, G1], ...u.attrs.map((v, i) => [v, GA[i]])]);
  const Y1 = bj.addPoint(fromObj(C_u_pt), [bj.F.neg(known[0]), known[1]]);
  const lhs1 = msm([[proof.z_su, G3], [proof.z_blind, H]]);
  const rhs1 = bj.addPoint(fromObj(proof.T1), bj.mulPointEscalar(Y1, proof.c));
  assert.ok(eqPt(lhs1, rhs1), 'eq1 은 통과해야 한다 (거절 원인이 eq2 임을 확인)');
});

await t('π_u V2 음성: 좌표가 p 이상인 비정규 인코딩은 거절된다', async () => {
  const u = await freshUser();
  const { C_u_pt, cm_u, proof } = await proveUserCred({ uid, s_u: u.s_u, blind_u: u.blind, r_u: u.r_u, attrs: u.attrs });
  const bj = await buildBabyjub();
  assert.equal(await verifyUserCred({ uid, attrs: u.attrs, C_u_pt: { x: C_u_pt.x + bj.F.p, y: C_u_pt.y }, cm_u, proof }), false);
  assert.equal(await verifyUserCred({ uid: SCALAR_MAX, attrs: u.attrs, C_u_pt, cm_u, proof }), false, 'CIA 쪽 검증도 uid 가 2^250 이상이면 거절한다');
});

await t('π_u V2 직렬화 왕복', async () => {
  const u = await freshUser();
  const { C_u_pt, cm_u, proof } = await proveUserCred({ uid, s_u: u.s_u, blind_u: u.blind, r_u: u.r_u, attrs: u.attrs });
  const back = parseUserCredProof(JSON.parse(JSON.stringify(serializeUserCredProof(proof))));
  assert.deepEqual(back, proof);
  assert.equal(await verifyUserCred({ uid, attrs: u.attrs, C_u_pt, cm_u, proof: back }), true);
});

await t('요청 서명 메시지: userCredRequestMessage(C_u_pt), issueRequestMessageV4(Cf_u, C_s_pt, chainid, allowAgent, max_height)', async () => {
  const ps = await buildPoseidon();
  const P = { x: 5n, y: 6n };
  assert.equal(await userCredRequestMessage(P), ps.F.toObject(ps([DOMAIN_MODE3_USERCREDREQ, 5n, 6n])));
  const m = await issueRequestMessageV4(7n, P, 31337n, 0n, 1000n);
  assert.equal(m, ps.F.toObject(ps([DOMAIN_MODE3_ISSUEREQ_V4, 7n, 5n, 6n, 31337n, 0n, 1000n])));
  assert.notEqual(m, await issueRequestMessageV4(8n, P, 31337n, 0n, 1000n), 'Cf_u 를 덮는다 — 남의 C_u 에 내 C_s 를 못 붙인다');
  assert.notEqual(m, await issueRequestMessageV4(7n, P, 31337n, 0n, 1001n));
  await assert.rejects(() => issueRequestMessageV4(7n, P, 31337n, 2n, 1000n), /allowAgent/);
  await assert.rejects(() => issueRequestMessageV4(7n, P, 31337n, 0n, 1n << 64n), /max_height/);
  await assert.rejects(() => issueRequestMessageV4('7', P, 31337n, 0n, 1000n), /bigint/);
});

process.exit(failed === 0 ? 0 : 1);
