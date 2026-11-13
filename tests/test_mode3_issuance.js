// V11 점 검사·직렬화 (스펙 2026-10-12 §3.1·§5.2). 요청 서명 메시지는 2026-11-13 에 없어졌다(스펙 no-pk-u). 외부 의존 없음(unit).
//   node tests/test_mode3_issuance.js
import assert from 'node:assert/strict';
import { buildBabyjub } from 'circomlibjs';
import * as issuance from '../lib/mode3_issuance.js';
const { isValidPoint, pointToStrings, pointFromStrings } = issuance;

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

await t('V10 의 σ-프로토콜·등록 커밋 export 는 없다 (registrationCommit, proveUserCred, verifyUserCred, attrsRequestMessage, issueRequestMessageV4)', () => {
  for (const k of ['registrationCommit', 'proveUserCred', 'verifyUserCred', 'attrsRequestMessage', 'issueRequestMessageV4', 'userCredRequestMessage', 'randomZr']) assert.equal(issuance[k], undefined, k);
});
await t('요청 서명 메시지 함수는 없어졌다(2026-11-13 스펙 no-pk-u — 인증은 π_IdP 의 ctx·tag, lib/mode3_credential.js)', async () => {
  const m = await import('../lib/mode3_issuance.js');
  for (const k of ['issueRequestMessageV11', 'registerMessage', 'slotRequestMessage', 'revokeSessionMessage', 'DOMAIN_MODE3_ISSUEREQ_V11', 'DOMAIN_MODE3_REGISTER_V2', 'DOMAIN_MODE3_SLOTREQ', 'DOMAIN_MODE3_REVOKESESS']) assert.equal(k in m, false, k);
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
