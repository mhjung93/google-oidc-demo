// V9 라이브러리 단위 테스트 — 제너레이터 6개, 속성 6슬롯. (unit 그룹)  node tests/test_mode3_v9_lib.js
import assert from 'node:assert/strict';
import { buildPedersenHash } from 'circomlibjs';
import { PEDERSEN_GENERATORS, ATTR_SLOTS, normalizeAttrs, userCommit } from '../lib/mode3_credential.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

await t('ATTR_SLOTS = 6, normalizeAttrs 는 길이 6 으로 0 패딩', () => {
  assert.equal(ATTR_SLOTS, 6);
  assert.deepEqual(normalizeAttrs(['1990', '410', '2']), [1990n, 410n, 2n, 0n, 0n, 0n]);
  assert.throws(() => normalizeAttrs([1n, 2n, 3n, 4n, 5n, 6n, 7n]), /최대 6개/);
  assert.throws(() => normalizeAttrs([1n << 64n]), /2\^64/);
});
await t('attr4·attr5 = circomlibjs getBasePoint(9)·(10) (회로 상수와 같은 글자)', async () => {
  const ph = await buildPedersenHash();
  const F = ph.babyJub.F;
  // circomlibjs getBasePoint(baseHashType, pointIdx) — 두 번째 인자가 표의 색인이다.
  // circomlib pedersen.circom BASE[0..9] 와 같은 생성 방식(blake) 이어야 같은 점이 나온다.
  for (const [name, i] of [['attr4', 9], ['attr5', 10]]) {
    const P = ph.getBasePoint('blake', i);
    assert.deepEqual([...PEDERSEN_GENERATORS[name]], [F.toObject(P[0]), F.toObject(P[1])], name);
  }
  // 기존 9개도 getBasePoint(0..8) 과 같다 — 표를 옮겨 적다 생긴 오타를 잡는다.
  // 실제 색인 순서는 uid,arid,s_u,pk_i,blind,attr0..3 다(blind 가 attr 들보다 먼저 배정됐다 —
  // attr0..3 은 2026-09-14 에 나중에 추가됐다).
  const names = ['uid', 'arid', 's_u', 'pk_i', 'blind', 'attr0', 'attr1', 'attr2', 'attr3'];
  names.forEach((n, i) => { const P = ph.getBasePoint('blake', i); assert.deepEqual([...PEDERSEN_GENERATORS[n]], [F.toObject(P[0]), F.toObject(P[1])], n); });
});
await t('userCommit 은 슬롯 6개를 쓴다 — 5번째 슬롯이 다르면 커밋이 다르다', async () => {
  const base = { uid: 1n, s_u: 2n, blind_u: 3n };
  const a = await userCommit({ ...base, attrs: [1990n, 410n, 2n, 0n, 0n, 0n] });
  const b = await userCommit({ ...base, attrs: [1990n, 410n, 2n, 0n, 7n, 0n] });
  const c = await userCommit({ ...base, attrs: [1990n, 410n, 2n, 0n, 0n, 7n] });
  assert.notEqual(a.Cf, b.Cf); assert.notEqual(a.Cf, c.Cf); assert.notEqual(b.Cf, c.Cf);
});
await t('등록 메시지·서명: registerMessage = Poseidon(D_REG, uid, cm.x, cm.y), 지갑 키로 서명·검증', async () => {
  const { registerMessage, DOMAIN_MODE3_REGISTER } = await import('../lib/mode3_issuance.js');
  const { createRegistration, signRegistration, eddsaPubOf } = await import('../lib/mode3_wallet.js');
  const { buildEddsa, buildPoseidon } = await import('circomlibjs');
  assert.equal(DOMAIN_MODE3_REGISTER, BigInt('0x' + Buffer.from('MODE3REGISTER').toString('hex')));
  const ps = await buildPoseidon();
  assert.equal(await registerMessage(12345n, { x: 1n, y: 2n }), ps.F.toObject(ps([DOMAIN_MODE3_REGISTER, 12345n, 1n, 2n])));
  const reg = await createRegistration();
  assert.match(reg.sk_u, /^[0-9a-f]{64}$/); assert.equal(typeof reg.pk_u.x, 'bigint');
  assert.deepEqual(await eddsaPubOf(reg.sk_u), reg.pk_u);
  const sig = await signRegistration(reg.sk_u, 12345n, reg.cm_u);
  const eddsa = await buildEddsa(); const F = eddsa.F;
  const m = F.e(await registerMessage(12345n, reg.cm_u));
  const ok = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig.R8x)), F.e(BigInt(sig.R8y))], S: BigInt(sig.S) }, [F.e(reg.pk_u.x), F.e(reg.pk_u.y)]);
  assert.equal(ok, true);
  const other = await createRegistration();
  assert.equal(eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig.R8x)), F.e(BigInt(sig.R8y))], S: BigInt(sig.S) }, [F.e(other.pk_u.x), F.e(other.pk_u.y)]), false);
});
process.exit(fails ? 1 : 0);
