// 개봉 요청·결과 메시지와 서명 (설계 2026-09-16 §6). 외부 의존 없음.
//   node tests/test_mode3_opening.js
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { openRequestMessage, openResultMessage, signOpenRequest, signOpenResult, recoverSigner, isFreshTs } from '../lib/mode3_opening.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const svc = ethers.Wallet.createRandom();
const fields = { arid: '22222', r_s: '55555', PPID: '99999', D_svc: { x: '123', y: '456' }, ts: '1789000000' };

await t('메시지 형식은 스펙 §6 그대로', () => {
  assert.equal(openRequestMessage(fields), 'mode3-open:22222:55555:99999:123:1789000000');
  assert.equal(openResultMessage('abcd', '1789000001'), 'mode3-open-result:abcd:1789000001');
});

await t('서명한 요청은 서비스 주소로 복원되고, 필드 하나가 바뀌면 다른 주소가 나온다', async () => {
  const sig = await signOpenRequest(svc, fields);
  assert.equal(recoverSigner(openRequestMessage(fields), sig), svc.address);
  assert.notEqual(recoverSigner(openRequestMessage({ ...fields, ts: '1789000001' }), sig), svc.address);
  const rsig = await signOpenResult(svc, 'abcd', '1789000001');
  assert.equal(recoverSigner(openResultMessage('abcd', '1789000001'), rsig), svc.address);
});

await t('깨진 서명은 throw 없이 null', () => {
  assert.equal(recoverSigner('x', '0x00'), null);
  assert.equal(recoverSigner('x', 'not-a-sig'), null);
});

await t('isFreshTs: ±300초 안이면 true, 밖·비수치는 false', () => {
  const now = 1789000000_000;
  assert.equal(isFreshTs('1789000000', now), true);
  assert.equal(isFreshTs('1788999701', now), true);
  assert.equal(isFreshTs('1788999699', now), false);
  assert.equal(isFreshTs('1789000301', now), false);
  assert.equal(isFreshTs('abc', now), false);
  assert.equal(isFreshTs(1789000000, now), false, '10진 문자열만');
});

process.exit(failed === 0 ? 0 : 1);
