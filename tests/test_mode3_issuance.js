// V11 요청 서명 메시지·점 검사·직렬화 (스펙 2026-10-12 §3.1·§5.2). 외부 의존 없음(unit).
//   node tests/test_mode3_issuance.js
import assert from 'node:assert/strict';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import * as issuance from '../lib/mode3_issuance.js';
import { SCALAR_MAX, MAX_HEIGHT_MAX } from '../lib/mode3_credential.js';
const { issueRequestMessageV11, registerMessage, slotRequestMessage, revokeSessionMessage, isValidPoint, pointToStrings, pointFromStrings,
  DOMAIN_MODE3_ISSUEREQ_V11, DOMAIN_MODE3_REGISTER_V2, DOMAIN_MODE3_SLOTREQ, DOMAIN_MODE3_REVOKESESS } = issuance;

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}
const be = (s) => BigInt('0x' + Buffer.from(s).toString('hex'));
const ps = await buildPoseidon();
const H = (arr) => ps.F.toObject(ps(arr));

await t('도메인 상수는 ASCII 빅엔디언이고 서로 다르다', () => {
  assert.equal(DOMAIN_MODE3_ISSUEREQ_V11, be('MODE3ISSUEREQV11'));
  assert.equal(DOMAIN_MODE3_REGISTER_V2, be('MODE3REGISTER2'));
  assert.equal(DOMAIN_MODE3_SLOTREQ, be('MODE3SLOTREQ'));
  assert.equal(DOMAIN_MODE3_REVOKESESS, be('MODE3REVOKESESS'));
  assert.equal(new Set([DOMAIN_MODE3_ISSUEREQ_V11, DOMAIN_MODE3_REGISTER_V2, DOMAIN_MODE3_SLOTREQ, DOMAIN_MODE3_REVOKESESS]).size, 4);
});
await t('V10 의 σ-프로토콜·등록 커밋 export 는 없다 (registrationCommit, proveUserCred, verifyUserCred, attrsRequestMessage, issueRequestMessageV4)', () => {
  for (const k of ['registrationCommit', 'proveUserCred', 'verifyUserCred', 'attrsRequestMessage', 'issueRequestMessageV4', 'userCredRequestMessage', 'randomZr']) assert.equal(issuance[k], undefined, k);
});
await t('issueRequestMessageV11 = Poseidon(D, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height); allowAgent 2·max_height ≥ 2^64·비bigint 는 throw', async () => {
  assert.equal(await issueRequestMessageV11(1n, 2n, 3n, 4n, 31337n, 1n, 500n), H([DOMAIN_MODE3_ISSUEREQ_V11, 1n, 2n, 3n, 4n, 31337n, 1n, 500n]));
  await assert.rejects(() => issueRequestMessageV11(1n, 2n, 3n, 4n, 31337n, 2n, 500n), /allowAgent/);
  await assert.rejects(() => issueRequestMessageV11(1n, 2n, 3n, 4n, 31337n, 0n, MAX_HEIGHT_MAX), /2\^64/);
  await assert.rejects(() => issueRequestMessageV11('1', 2n, 3n, 4n, 31337n, 0n, 500n), /bigint/);
});
await t('registerMessage = Poseidon(D_REGISTER_V2, uid, auid); uid ≥ 2^250 은 throw', async () => {
  assert.equal(await registerMessage(12345n, 99n), H([DOMAIN_MODE3_REGISTER_V2, 12345n, 99n]));
  await assert.rejects(() => registerMessage(SCALAR_MAX, 99n), /2\^250/);
  await assert.rejects(() => registerMessage(12345n, '99'), /auid/);
});
await t('registerMessage: auid ≥ p(BN254 스칼라 필드 소수)는 throw — isField 상한(모듈러로 다시 줄어든 값이 조용히 통과하면 안 된다)', async () => {
  const bj = await buildBabyjub();
  await assert.rejects(() => registerMessage(12345n, bj.F.p), /auid/);
});
await t('slotRequestMessage = Poseidon(D_SLOTREQ, uid, nonce); revokeSessionMessage = Poseidon(D_REVOKESESS, uid, Cf_s, bound, nonce)(2026-10-22)', async () => {
  assert.equal(await slotRequestMessage(12345n, 7n), H([DOMAIN_MODE3_SLOTREQ, 12345n, 7n]));
  await assert.rejects(() => slotRequestMessage(12345n, SCALAR_MAX), /nonce/);
  assert.equal(await revokeSessionMessage(12345n, 8n, 3n, 9n), H([DOMAIN_MODE3_REVOKESESS, 12345n, 8n, 3n, 9n]));
  // 옛 3인자 호출: 3번째 위치 인자(9n)가 새 시그니처의 bound 자리로 들어가 범위 안의 유효한 bound 가 되므로 bound 가드는
  // 통과하고, 대신 4번째 자리(nonce)가 undefined 로 비어 Poseidon 입력 변환에서 깨진다 — 조용히 틀린 해시를 내지는 않는다.
  await assert.rejects(() => revokeSessionMessage(12345n, 8n, 9n), /BigInt/, '옛 3인자 호출은 거부(실제로는 nonce 자리가 비어 BigInt 변환에서 거부)');
  await assert.rejects(() => revokeSessionMessage(12345n, 8n, 1n << 32n, 9n), /bound/, '상한');
  // 경계값: 0 과 2^32-1 은 throw 없이 값을 낸다.
  assert.equal(await revokeSessionMessage(12345n, 8n, 0n, 9n), H([DOMAIN_MODE3_REVOKESESS, 12345n, 8n, 0n, 9n]));
  assert.equal(await revokeSessionMessage(12345n, 8n, (1n << 32n) - 1n, 9n), H([DOMAIN_MODE3_REVOKESESS, 12345n, 8n, (1n << 32n) - 1n, 9n]));
  await assert.rejects(() => revokeSessionMessage(12345n, 8n, 3, 9n), /bound/, 'bound 가 bigint 가 아니면(number) 거부');
});
await t('isValidPoint: Base8 은 참, 비정규 인코딩·곡선 밖·문자열은 거짓', async () => {
  const bj = await buildBabyjub();
  const G = { x: bj.F.toObject(bj.Base8[0]), y: bj.F.toObject(bj.Base8[1]) };
  assert.equal(await isValidPoint(G), true);
  assert.equal(await isValidPoint({ x: G.x + bj.F.p, y: G.y }), false);
  assert.equal(await isValidPoint({ x: 1n, y: 1n }), false);
  assert.equal(await isValidPoint({ x: '1', y: '2' }), false);
});
await t('pointToStrings ↔ pointFromStrings', () => {
  const p = { x: 123n, y: 456n };
  assert.deepEqual(pointToStrings(p), { x: '123', y: '456' });
  assert.deepEqual(pointFromStrings(pointToStrings(p)), p);
});
process.exit(failed === 0 ? 0 : 1);
