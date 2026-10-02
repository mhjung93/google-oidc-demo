// 서비스 인증서 cert_s V2 (설계 2026-09-16 §3) — (arid, origin, pk_trace) 를 덮는다. 외부 의존 없음.
//   node tests/test_mode3_rp_cert.js
import assert from 'node:assert/strict';
import { buildEddsa } from 'circomlibjs';
import { randomScalar, SCALAR_MAX } from '../lib/mode3_credential.js';
import { DOMAIN_MODE3_CERT_S, DOMAIN_MODE3_CERT_S_V2, originToField, certSMessage, signRpCert, verifyRpCert } from '../lib/mode3_rp_cert.js';
import { createShare, combinePublicKey } from '../lib/mode3_trace.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const eddsa = await buildEddsa();
const F = eddsa.F;
const prv = Buffer.alloc(32, 9);
const pub = eddsa.prv2pub(prv);
const pkCIA = { x: F.toObject(pub[0]), y: F.toObject(pub[1]) };
const arid = randomScalar();
const origin = 'http://127.0.0.1:3100';
const pk_trace = await combinePublicKey((await createShare()).X, (await createShare()).X);
const other_trace = await combinePublicKey((await createShare()).X, (await createShare()).X);

await t('도메인 태그: V1 "MODE3CERTS", V2 "MODE3CERTS2" 빅엔디언', () => {
  assert.equal(DOMAIN_MODE3_CERT_S, BigInt('0x' + Buffer.from('MODE3CERTS').toString('hex')));
  assert.equal(DOMAIN_MODE3_CERT_S_V2, BigInt('0x' + Buffer.from('MODE3CERTS2').toString('hex')));
});

await t('originToField 는 250비트 미만이고 오리진마다 다르다', () => {
  const a = originToField(origin), b = originToField('http://127.0.0.1:3101');
  assert.ok(a < SCALAR_MAX && b < SCALAR_MAX);
  assert.notEqual(a, b);
  assert.equal(a, originToField(origin), '결정론적');
});

await t('certSMessage 는 pk_trace 를 덮는다 (다른 키면 다른 메시지), 문자열 좌표도 받는다', async () => {
  const m = await certSMessage(arid, origin, pk_trace);
  assert.notEqual(m, await certSMessage(arid, origin, other_trace));
  assert.equal(m, await certSMessage(arid, origin, { x: pk_trace.x.toString(), y: pk_trace.y.toString() }));
});

await t('양성: 서명한 (arid, origin, pk_trace) 가 검증된다', async () => {
  const cert = await signRpCert(prv, { arid, origin, pk_trace });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace, cert }), true);
});

await t('음성: pk_trace 가 다르면 거절 (서비스가 자기만 아는 키를 지갑에 주는 공격)', async () => {
  const cert = await signRpCert(prv, { arid, origin, pk_trace });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace: other_trace, cert }), false);
});

await t('음성: origin 이 다르면 거절 (피싱 페이지가 남의 arid 를 끼워 넣는 경우)', async () => {
  const cert = await signRpCert(prv, { arid, origin, pk_trace });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin: 'http://evil.example', pk_trace, cert }), false);
});

await t('음성: arid 가 다르면 거절', async () => {
  const cert = await signRpCert(prv, { arid, origin, pk_trace });
  assert.equal(await verifyRpCert(pkCIA, { arid: arid + 1n, origin, pk_trace, cert }), false);
});

await t('음성: 다른 키의 서명은 거절', async () => {
  const cert = await signRpCert(Buffer.alloc(32, 7), { arid, origin, pk_trace });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace, cert }), false);
});

await t('음성: 형식이 깨진 cert·pk_trace 는 throw 없이 false', async () => {
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace, cert: { R8x: 'x', R8y: '1', S: '1' } }), false);
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace, cert: null }), false);
  const cert = await signRpCert(prv, { arid, origin, pk_trace });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace: null, cert }), false);
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, pk_trace: { x: 'abc', y: '1' }, cert }), false);
});

process.exit(failed === 0 ? 0 : 1);
