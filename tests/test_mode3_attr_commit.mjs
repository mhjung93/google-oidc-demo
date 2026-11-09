// tests/test_mode3_attr_commit.mjs — C_attr(lib/mode3_attr_commit.js) 단위: 결정성·blind 분리·형식 검사. 외부 의존 없음. (unit)
import assert from 'node:assert/strict';
import { buildPoseidon } from 'circomlibjs';
import { attrCommit, randomBlind, isAttrCommit, DOMAIN_MODE3_ATTRC, FIELD_P } from '../lib/mode3_attr_commit.js';
import { DEFAULT_ATTR_SCHEMA, encodeProfile } from '../lib/mode3_attr_schema.js';

let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

await t('도메인 상수는 ASCII "MODE3ATTRC" 빅엔디언', () => {
  assert.equal(DOMAIN_MODE3_ATTRC, BigInt('0x' + Buffer.from('MODE3ATTRC').toString('hex')));
});
await t('randomBlind 는 10진·필드 안·매번 다르다', () => {
  const a = randomBlind(), b = randomBlind();
  assert.match(a, /^[0-9]+$/); assert.ok(BigInt(a) < FIELD_P); assert.notEqual(a, b);
});
await t('attrCommit 은 Poseidon(T, attrs[0..5], blind) 과 같고 결정적이다', async () => {
  const attrs = await encodeProfile(DEFAULT_ATTR_SCHEMA, { birthYear: '1990', country: 'KR', extra1: 'x' });
  const blind = '12345678901234567890';
  const c1 = await attrCommit({ attrs, blind }), c2 = await attrCommit({ attrs, blind });
  assert.equal(c1, c2);
  const poseidon = await buildPoseidon();
  const want = poseidon.F.toObject(poseidon([DOMAIN_MODE3_ATTRC, ...attrs.map(BigInt), BigInt(blind)])).toString();
  assert.equal(c1, want);
  assert.ok(isAttrCommit(c1));
});
await t('blind 가 다르거나 속성 하나가 다르면 커밋먼트가 다르다(RP 값은 입력에 없다 — 인자 자체가 없다)', async () => {
  const attrs = await encodeProfile(DEFAULT_ATTR_SCHEMA, { birthYear: '1990', country: 'KR' });
  const c = await attrCommit({ attrs, blind: '1' });
  assert.notEqual(c, await attrCommit({ attrs, blind: '2' }));
  const attrs2 = await encodeProfile(DEFAULT_ATTR_SCHEMA, { birthYear: '1991', country: 'KR' });
  assert.notEqual(c, await attrCommit({ attrs: attrs2, blind: '1' }));
});
await t('형식 검사: attrs 6개가 아니거나 10진이 아니거나 필드 밖이면 오류; isAttrCommit 은 빈 값·필드 밖·비10진을 거절', async () => {
  await assert.rejects(attrCommit({ attrs: ['1', '2'], blind: '1' }), /6개/);
  await assert.rejects(attrCommit({ attrs: ['1', '2', '3', '4', '5', 'x'], blind: '1' }), /10진/);
  await assert.rejects(attrCommit({ attrs: ['1', '2', '3', '4', '5', '6'], blind: FIELD_P.toString() }), /필드 밖/);
  assert.equal(isAttrCommit(''), false); assert.equal(isAttrCommit('0x12'), false); assert.equal(isAttrCommit(FIELD_P.toString()), false);
  assert.equal(isAttrCommit('0'), true);
});

if (failed) { console.error(`${failed} failed`); process.exit(1); }
console.log('all passed');
