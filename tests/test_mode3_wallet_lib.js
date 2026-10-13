// 지갑 라이브러리의 체인·zkey 없는 부분(V11) — 등록값·서명 메시지·ProofCache. (unit)  node tests/test_mode3_wallet_lib.js
import assert from 'node:assert/strict';
import { buildEddsa } from 'circomlibjs';
import { createRegistration, signRegistration, signSlotRequest, eddsaPubOf, ProofCache, chooseMaxHeight } from '../lib/mode3_wallet.js';
import { registerMessage, slotRequestMessage } from '../lib/mode3_issuance.js';
import { auidOf, SCALAR_MAX } from '../lib/mode3_credential.js';
import { IDP_PUB_INDEX, idpPublicSignals, verifyIdp } from '../lib/mode3_idp_proof.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }
const eddsa = await buildEddsa(); const F = eddsa.F;
const verify = (m, sig, pub) => eddsa.verifyPoseidon(F.e(m), { R8: [F.e(BigInt(sig.R8x)), F.e(BigInt(sig.R8y))], S: BigInt(sig.S) }, [F.e(pub.x), F.e(pub.y)]);

await t('createRegistration(uid) = { s_u, auid = Poseidon(T_AUID, uid, s_u), sk_u(hex64), pk_u }; uid 없이는 throw', async () => {
  const reg = await createRegistration(12345n);
  assert.ok(reg.s_u < SCALAR_MAX); assert.match(reg.sk_u, /^[0-9a-f]{64}$/); assert.equal(typeof reg.pk_u.x, 'bigint');
  assert.equal(reg.auid, await auidOf({ uid: 12345n, s_u: reg.s_u }));
  assert.deepEqual(await eddsaPubOf(reg.sk_u), reg.pk_u);
  await assert.rejects(() => createRegistration(), /uid/);
  assert.notEqual((await createRegistration(12345n)).auid, reg.auid, 's_u 가 매번 다르다');
});
await t('signRegistration 은 registerMessage(uid, auid) 위 서명 — 다른 키·다른 auid 는 검증 실패', async () => {
  const reg = await createRegistration(12345n);
  const sig = await signRegistration(reg.sk_u, 12345n, reg.auid);
  assert.equal(verify(await registerMessage(12345n, reg.auid), sig, reg.pk_u), true);
  assert.equal(verify(await registerMessage(12345n, reg.auid + 1n), sig, reg.pk_u), false);
  assert.equal(verify(await registerMessage(12345n, reg.auid), sig, (await createRegistration(12345n)).pk_u), false);
});
await t('signSlotRequest 는 slotRequestMessage(uid, nonce) 위 서명', async () => {
  const reg = await createRegistration(12345n);
  const sig = await signSlotRequest(reg.sk_u, 12345n, 7n);
  assert.equal(verify(await slotRequestMessage(12345n, 7n), sig, reg.pk_u), true);
  assert.equal(verify(await slotRequestMessage(12345n, 8n), sig, reg.pk_u), false);
});
await t('idpPublicSignals: 8개 10진 문자열, 순서 = IDP_PUB_INDEX; 범위 밖은 throw', () => {
  const pub = idpPublicSignals({ uid: 1n, auid: 2n, auid_s: 3n, C_u_pt: { x: 4n, y: 5n }, C_s_pt: { x: 6n, y: 7n }, max_height: 8n });
  assert.deepEqual(pub, ['1', '2', '3', '4', '5', '6', '7', '8']); assert.equal(IDP_PUB_INDEX.COUNT, 8); assert.equal(pub[IDP_PUB_INDEX.MAX_HEIGHT], '8');
  assert.throws(() => idpPublicSignals({ uid: SCALAR_MAX, auid: 2n, auid_s: 3n, C_u_pt: { x: 4n, y: 5n }, C_s_pt: { x: 6n, y: 7n }, max_height: 8n }), /uid/);
  assert.throws(() => idpPublicSignals({ uid: 1n, auid: 2n, auid_s: 3n, C_u_pt: { x: 4n, y: 5n }, C_s_pt: { x: 6n, y: 7n }, max_height: 1n << 64n }), /max_height/);
});
// 리뷰(2026-10-13) 테스트 공백: verifyIdp 의 입력 검사 음성 케이스. vkey 는 접근을 기록하는 Proxy 다 — 형식 검사에서 거절되면 snarkjs 까지 가지
// 않으므로 touched 가 false 로 남는다(snarkjs 가 던져서 false 가 된 것과 구별된다). 대조군(정규 8개)은 snarkjs 까지 가서 vkey 를 읽는다.
await t('verifyIdp: 길이 7·9, 앞자리 0, 10진 아님(음수·0x·공백·숫자형)은 snarkjs 전에 false; 증명이 객체가 아니면 false', async () => {
  let touched = false;
  const vkey = new Proxy({}, { get: (o, k) => { touched = true; return undefined; }, ownKeys: () => { touched = true; return []; }, has: () => { touched = true; return false; } });
  const good = ['1', '2', '3', '4', '5', '6', '7', '8'];
  const proof = { pi_a: ['1', '2', '1'], pi_b: [['1', '2'], ['3', '4'], ['1', '0']], pi_c: ['1', '2', '1'], protocol: 'groth16', curve: 'bn128' };
  const bad = [
    ['길이 7', good.slice(0, 7)], ['길이 9', [...good, '9']], ['배열 아님', '1,2,3,4,5,6,7,8'],
    ['앞자리 0', ['01', ...good.slice(1)]], ['앞자리 0(뒤쪽)', [...good.slice(0, 7), '007']],
    ['음수', ['-1', ...good.slice(1)]], ['0x', ['0x1', ...good.slice(1)]], ['공백', [' 1', ...good.slice(1)]], ['+', ['+1', ...good.slice(1)]],
    ['빈 문자열', ['', ...good.slice(1)]], ['숫자형', [1, ...good.slice(1)]], ['bigint', [1n, ...good.slice(1)]],
  ];
  for (const [label, pub] of bad) {
    touched = false;
    assert.equal(await verifyIdp(vkey, pub, proof), false, label);
    assert.equal(touched, false, `${label}: 형식 검사에서 거절돼 vkey 를 읽지 않아야 한다`);
  }
  for (const p of [null, undefined, 'proof', 7]) { touched = false; assert.equal(await verifyIdp(vkey, good, p), false, String(p)); assert.equal(touched, false, `proof=${String(p)}`); }
  // 대조군: 정규 8개·객체 증명은 형식 검사를 지나 snarkjs 가 vkey 를 읽는다(가짜 vkey 라 결과는 false — 예외는 삼킨다)
  touched = false;
  assert.equal(await verifyIdp(vkey, good, proof), false);
  assert.equal(touched, true, '정규 입력은 snarkjs 까지 가야 한다(위 거절들이 형식 검사 덕임을 보이는 대조군)');
});
await t('V10 ProofCache.rootKey(chainId, rev, reg) = "chainId:rev:reg", 2인자는 throw, deleteSession 은 세션만', () => {
  assert.equal(ProofCache.rootKey(31337n, 1n, 2n), '31337:1:2');
  assert.throws(() => ProofCache.rootKey(1n, 2n));
  assert.notEqual(ProofCache.rootKey(1n, 5n, 6n), ProofCache.rootKey(2n, 5n, 6n));
  const c = new ProofCache();
  c.set(ProofCache.rootKey(31337n, 1n, 2n), '77', 'a', '1:0,0:0,0:0:0'); c.set(ProofCache.rootKey(31337n, 1n, 2n), '88', 'b');
  c.deleteSession('77');
  assert.equal(c.get(ProofCache.rootKey(31337n, 1n, 2n), '77', '1:0,0:0,0:0:0'), null); assert.equal(c.get(ProofCache.rootKey(31337n, 1n, 2n), '88'), 'b');
});
await t('chooseMaxHeight 그리드', () => { assert.equal(chooseMaxHeight(1234n), 1600n); assert.equal(chooseMaxHeight(10n, { ttlBlocks: 5n, grid: 1n }), 15n); });
process.exit(fails ? 1 : 0);
