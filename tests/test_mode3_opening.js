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
// 2026-11-19(스펙 trace-without-tag T7): 요청을 특정하는 것은 태그의 c1·부분 복호가 아니라 그 로그인의 auid_s 다. 접두어도 바뀌었다(mode3-open2).
const fields = { arid: '22222', PPID: '99999', auid_s: '777', ts: '1789000000' };

await t('메시지 형식: mode3-open2:arid:PPID:auid_s:ts — auid_s 가 요청을 특정한다(태그·D_svc 없음)', () => {
  assert.equal(openRequestMessage(fields), 'mode3-open2:22222:99999:777:1789000000');
  assert.equal(openResultMessage('abcd', '1789000001'), 'mode3-open-result:abcd:1789000001');
});

await t('서명한 요청은 RP 주소로 복원되고, 필드 하나가 바뀌면 다른 주소가 나온다', async () => {
  const sig = await signOpenRequest(svc, fields);
  assert.equal(recoverSigner(openRequestMessage(fields), sig), svc.address);
  assert.notEqual(recoverSigner(openRequestMessage({ ...fields, ts: '1789000001' }), sig), svc.address);
  assert.notEqual(recoverSigner(openRequestMessage({ ...fields, auid_s: '778' }), sig), svc.address, 'auid_s 가 서명에 든다');
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
