// tests/test_mode3_attr_commit.mjs — C_attr(lib/mode3_attr_commit.js) 단위: 결정성·형식 검사(blind 는 2026-11-13 에 없앴다). 외부 의존 없음. (unit)
import assert from 'node:assert/strict';
import { buildPoseidon } from 'circomlibjs';
import { attrCommit, isAttrCommit, DOMAIN_MODE3_ATTRC, FIELD_P } from '../lib/mode3_attr_commit.js';
import { DEFAULT_ATTR_SCHEMA, encodeProfile } from '../lib/mode3_attr_schema.js';

let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

await t('도메인 상수는 ASCII "MODE3ATTRC4" 빅엔디언(2026-11-13 스펙 random-salt R15: blind 를 뺀 정의 — 옛 "MODE3ATTRC"·"MODE3ATTRC2"·"MODE3ATTRC3" 과 다르다)', () => {
  assert.equal(DOMAIN_MODE3_ATTRC, 93461614427471203550774068n);
  assert.equal(DOMAIN_MODE3_ATTRC, BigInt('0x' + Buffer.from('MODE3ATTRC4').toString('hex')));
  for (const old of ['MODE3ATTRC', 'MODE3ATTRC2', 'MODE3ATTRC3']) assert.notEqual(DOMAIN_MODE3_ATTRC, BigInt('0x' + Buffer.from(old).toString('hex')));
});
await t('randomBlind 는 없어졌다(R15)', async () => {
  assert.equal((await import('../lib/mode3_attr_commit.js')).randomBlind, undefined);
});
const U = { s_u: '987654321987654321' };
await t('R15: attrCommit 은 Poseidon(T, s_u, attrs[0..5]) 과 같고 결정적이다 — blind·uid 는 식에 없다(줘도 읽지 않는다)', async () => {
  const attrs = await encodeProfile(DEFAULT_ATTR_SCHEMA, { birthYear: '1990', country: 'KR', extra1: 'x' });
  const c1 = await attrCommit({ ...U, attrs }), c2 = await attrCommit({ ...U, attrs });
  assert.equal(c1, c2);
  const poseidon = await buildPoseidon();
  const want = poseidon.F.toObject(poseidon([DOMAIN_MODE3_ATTRC, BigInt(U.s_u), ...attrs.map(BigInt)])).toString();
  assert.equal(c1, want);
  assert.equal(await attrCommit({ ...U, attrs, blind: '5' }), c1, 'blind 를 줘도 값이 같다');
  assert.equal(await attrCommit({ ...U, uid: '4242', attrs }), c1, 'uid 를 줘도 값이 같다');
  assert.ok(isAttrCommit(c1));
});
await t('속성·s_u 중 하나라도 다르면 커밋먼트가 다르다 — 같은 salt·같은 속성이면 항상 같은 값(복구 뒤 프로필을 바꾸지 않아도 된다)', async () => {
  const attrs = await encodeProfile(DEFAULT_ATTR_SCHEMA, { birthYear: '1990', country: 'KR' });
  const c = await attrCommit({ ...U, attrs });
  const attrs2 = await encodeProfile(DEFAULT_ATTR_SCHEMA, { birthYear: '1991', country: 'KR' });
  assert.notEqual(c, await attrCommit({ ...U, attrs: attrs2 }));
  assert.notEqual(c, await attrCommit({ ...U, s_u: '987654321987654322', attrs }), 's_u');
  assert.equal(c, await attrCommit({ ...U, attrs: [...attrs] }));
});
await t('형식 검사: attrs 6개가 아니거나 10진이 아니거나 필드 밖이면 오류; isAttrCommit 은 빈 값·필드 밖·비10진을 거절', async () => {
  await assert.rejects(attrCommit({ ...U, attrs: ['1', '2'] }), /6개/);
  await assert.rejects(attrCommit({ ...U, attrs: ['1', '2', '3', '4', '5', 'x'] }), /10진/);
  await assert.rejects(attrCommit({ ...U, attrs: ['1', '2', '3', '4', '5', FIELD_P.toString()] }), /필드 밖/);
  await assert.rejects(attrCommit({ attrs: ['1', '2', '3', '4', '5', '6'] }), /s_u/, 's_u 없음');
  await assert.rejects(attrCommit({ s_u: 'abc', attrs: ['1', '2', '3', '4', '5', '6'] }), /s_u/, 's_u 형식');
  assert.equal(isAttrCommit(''), false); assert.equal(isAttrCommit('0x12'), false); assert.equal(isAttrCommit(FIELD_P.toString()), false);
  assert.equal(isAttrCommit('0'), true);
});

if (failed) { console.error(`${failed} failed`); process.exit(1); }
console.log('all passed');
