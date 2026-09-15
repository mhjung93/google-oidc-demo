// 서비스 인증서 cert_s (설계 2026-09-15 §3). 외부 의존 없음.
//   node tests/test_mode3_rp_cert.js
import assert from 'node:assert/strict';
import { buildEddsa } from 'circomlibjs';
import { randomScalar, SCALAR_MAX } from '../lib/mode3_credential.js';
import { DOMAIN_MODE3_CERT_S, originToField, certSMessage, signRpCert, verifyRpCert } from '../lib/mode3_rp_cert.js';

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

await t('도메인 태그는 "MODE3CERTS" 빅엔디언이다', () => {
  assert.equal(DOMAIN_MODE3_CERT_S, BigInt('0x' + Buffer.from('MODE3CERTS').toString('hex')));
});

await t('originToField 는 250비트 미만이고 오리진마다 다르다', () => {
  const a = originToField(origin), b = originToField('http://127.0.0.1:3101');
  assert.ok(a < SCALAR_MAX && b < SCALAR_MAX);
  assert.notEqual(a, b);
  assert.equal(a, originToField(origin), '결정론적');
});

await t('양성: 서명한 (arid, origin) 이 검증된다', async () => {
  const cert = await signRpCert(prv, { arid, origin });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, cert }), true);
});

await t('음성: origin 이 다르면 거절 (피싱 페이지가 남의 arid 를 끼워 넣는 경우)', async () => {
  const cert = await signRpCert(prv, { arid, origin });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin: 'http://evil.example', cert }), false);
});

await t('음성: arid 가 다르면 거절', async () => {
  const cert = await signRpCert(prv, { arid, origin });
  assert.equal(await verifyRpCert(pkCIA, { arid: arid + 1n, origin, cert }), false);
});

await t('음성: 다른 키의 서명은 거절', async () => {
  const cert = await signRpCert(Buffer.alloc(32, 7), { arid, origin });
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, cert }), false);
});

await t('음성: 형식이 깨진 cert 는 throw 없이 false', async () => {
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, cert: { R8x: 'x', R8y: '1', S: '1' } }), false);
  assert.equal(await verifyRpCert(pkCIA, { arid, origin, cert: null }), false);
});

process.exit(failed === 0 ? 0 : 1);
