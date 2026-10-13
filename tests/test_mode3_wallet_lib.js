// 지갑 라이브러리의 체인·zkey 없는 부분(V11) — 등록값·서명 메시지·ProofCache. (unit)  node tests/test_mode3_wallet_lib.js
import assert from 'node:assert/strict';
import { buildEddsa } from 'circomlibjs';
import { createRegistration, signRegistration, signSlotRequest, eddsaPubOf, ProofCache, chooseMaxHeight } from '../lib/mode3_wallet.js';
import { registerMessage, slotRequestMessage } from '../lib/mode3_issuance.js';
import { auidOf, SCALAR_MAX } from '../lib/mode3_credential.js';
import { IDP_PUB_INDEX, idpPublicSignals } from '../lib/mode3_idp_proof.js';

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
