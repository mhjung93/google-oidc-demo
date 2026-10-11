// 속성 매핑 계층(스펙 2026-10-07 §3·§4) — 스키마 검증·타입별 인코딩. 외부 의존 없음(Poseidon 은 circomlibjs). (unit)
//   node tests/test_mode3_attr_schema.mjs
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { buildPoseidon } from 'circomlibjs';
import {
  DEFAULT_ATTR_SCHEMA, DOMAIN_MODE3_ATTRSTR, STRING_MAX_BYTES, canonicalJson, loadSchema, schemaInfo, slotIndexOf, allowedPredicates,
  encodeSlotValue, encodeProfile, encodeMembers, decodeAttrs, profileFromAttrs, reencodeLossy, assertPredicateTypes, normalizeProfile,
} from '../lib/mode3_attr_schema.js';

let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }
const U64 = 1n << 64n;
const { schema: S, hash: H } = loadSchema(DEFAULT_ATTR_SCHEMA);
const withSlots = (slots) => ({ id: 'x', version: 1, slots });
const six = (...s) => [...s, ...Array(6 - s.length).fill({ type: 'unused' })];

await t('기본 스키마: 6슬롯, birthYear=0·country=1·extra1=2·extra2=3·unused=4,5, 해시는 정규 JSON 의 sha256', () => {
  assert.equal(S.slots.length, 6);
  assert.equal(slotIndexOf(S, 'birthYear'), 0); assert.equal(slotIndexOf(S, 'country'), 1);
  assert.equal(slotIndexOf(S, 'extra1'), 2); assert.equal(slotIndexOf(S, 'extra2'), 3); assert.equal(slotIndexOf(S, 'nope'), -1);
  assert.equal(S.slots[4].type, 'unused'); assert.equal(S.slots[5].type, 'unused');
  assert.equal(H, createHash('sha256').update(canonicalJson(DEFAULT_ATTR_SCHEMA)).digest('hex'));
  assert.deepEqual(schemaInfo(S, H), { id: 'zkd-attrs', version: 1, hash: H });
  assert.equal(S.slots[1].values.KR, 410); assert.equal(S.slots[1].values.SG, 702);
});

await t('canonicalJson: 키 정렬·공백 없음·undefined 키 제외', () => {
  assert.equal(canonicalJson({ b: 1, a: [2, { d: 'x', c: null }], u: undefined }), '{"a":[2,{"c":null,"d":"x"}],"b":1}');
  assert.equal(canonicalJson({ a: 1, b: 2 }), canonicalJson({ b: 2, a: 1 }));
});

await t('loadSchema 검증 실패: 슬롯 수, name 형식·중복, unused 에 name, int min>max, enum 코드 0·중복·범위, string maxBytes>124, type 오타', () => {
  const bad = (slots, re) => assert.throws(() => loadSchema(withSlots(slots)), (e) => e.reason === 'bad_schema' && re.test(e.message), re.source);
  bad([{ type: 'unused' }], /6개/);
  bad(six({ name: '1abc', type: 'int' }), /name/);
  bad(six({ name: 'a', type: 'int' }, { name: 'a', type: 'int' }), /중복/);
  bad(six({ name: 'x', type: 'unused' }), /unused/);
  bad(six({ name: 'a', type: 'int', min: 5, max: 4 }), /min/);
  bad(six({ name: 'a', type: 'int', max: U64.toString() }), /2\^64/);
  bad(six({ name: 'c', type: 'enum', values: { A: 0 } }), /0/);
  bad(six({ name: 'c', type: 'enum', values: { A: 1, B: 1 } }), /중복/);
  bad(six({ name: 'c', type: 'enum', values: { A: U64.toString() } }), /2\^64/);
  bad(six({ name: 'c', type: 'enum', values: {} }), /values/);
  bad(six({ name: 's', type: 'string', maxBytes: 125 }), /maxBytes/);
  bad(six({ name: 's', type: 'date' }), /type/);
  assert.throws(() => loadSchema({ id: 'x', version: 0, slots: six() }), /version/);
  assert.throws(() => loadSchema(null), /객체/);
  assert.equal(STRING_MAX_BYTES, 124);
});

await t('int: 그대로·공백 제거·빈 값 0(min 무관)·범위 밖 오류·형식 오류', async () => {
  assert.equal(await encodeSlotValue(S, 0, '1990'), '1990');
  assert.equal(await encodeSlotValue(S, 0, ' 1990 '), '1990');
  assert.equal(await encodeSlotValue(S, 0, 1990), '1990');
  assert.equal(await encodeSlotValue(S, 0, ''), '0'); assert.equal(await encodeSlotValue(S, 0, undefined), '0');
  await assert.rejects(encodeSlotValue(S, 0, '1800'), (e) => e.reason === 'bad_attr' && e.slot === 0 && e.field === 'birthYear' && e.detail === 'range');
  await assert.rejects(encodeSlotValue(S, 0, '2101'), (e) => e.detail === 'range');
  await assert.rejects(encodeSlotValue(S, 0, '19a'), (e) => e.detail === 'format');
  await assert.rejects(encodeSlotValue(S, 0, '-1'), (e) => e.detail === 'format');
  assert.equal(await encodeSlotValue(S, 0, '0001990'), '1990', '정규 10진(앞자리 0 없음)');
});

await t('enum: 이름 → 코드, 표에 있는 코드 숫자도 받음, 빈 값 0, 없는 이름·코드·소문자 오류', async () => {
  assert.equal(await encodeSlotValue(S, 1, 'KR'), '410'); assert.equal(await encodeSlotValue(S, 1, 'JP'), '392');
  assert.equal(await encodeSlotValue(S, 1, '410'), '410'); assert.equal(await encodeSlotValue(S, 1, 840), '840');
  assert.equal(await encodeSlotValue(S, 1, ''), '0');
  await assert.rejects(encodeSlotValue(S, 1, 'XX'), (e) => e.reason === 'bad_attr' && e.slot === 1 && e.detail === 'enum');
  await assert.rejects(encodeSlotValue(S, 1, '999'), (e) => e.detail === 'enum');
  await assert.rejects(encodeSlotValue(S, 1, 'kr'), (e) => e.detail === 'enum');
});

await t('string: 해시는 1 ≤ v < 2^64, 결정적, 슬롯이 다르면 다름, NFC 정규화로 같은 글자는 같음, 빈 값 0, 124바이트 초과 오류', async () => {
  const a = BigInt(await encodeSlotValue(S, 2, 'vip'));
  assert.ok(a >= 1n && a < U64);
  assert.equal(await encodeSlotValue(S, 2, 'vip'), a.toString());
  assert.notEqual(await encodeSlotValue(S, 3, 'vip'), a.toString(), '슬롯 분리(slotIndex 가 해시 입력)');
  assert.equal(await encodeSlotValue(S, 2, '\u00e9'), await encodeSlotValue(S, 2, 'e\u0301'), 'NFC');
  assert.equal(await encodeSlotValue(S, 2, ''), '0');
  const max = BigInt(await encodeSlotValue(S, 2, 'x'.repeat(124)));
  assert.ok(max >= 1n && max < U64, '124바이트(4조각 가득)는 통과');
  await assert.rejects(encodeSlotValue(S, 2, 'x'.repeat(125)), (e) => e.detail === 'length');
  await assert.rejects(encodeSlotValue(S, 2, '한'.repeat(42)), (e) => e.detail === 'length', '한글 42자 = 126바이트');
  // 명세대로 계산: Poseidon(DOMAIN, slot, byteLen, c0..c3) mod (2^64-1) + 1
  const poseidon = await buildPoseidon();
  const bytes = Buffer.from('vip', 'utf8'); let c0 = 0n; for (const b of bytes) c0 = (c0 << 8n) | BigInt(b);
  const h = poseidon.F.toObject(poseidon([DOMAIN_MODE3_ATTRSTR, 2n, BigInt(bytes.length), c0, 0n, 0n, 0n]));
  assert.equal(a, (h % (U64 - 1n)) + 1n);
  assert.equal(DOMAIN_MODE3_ATTRSTR, 23926173293432628108999218258n);
});

await t('unused: 빈 값·0 만 받고 결과 0', async () => {
  assert.equal(await encodeSlotValue(S, 4, ''), '0'); assert.equal(await encodeSlotValue(S, 4, '0'), '0'); assert.equal(await encodeSlotValue(S, 5, undefined), '0');
  await assert.rejects(encodeSlotValue(S, 4, '1'), (e) => e.reason === 'bad_attr' && e.slot === 4 && e.detail === 'unused');
});

await t('encodeProfile: 데모 값, string 포함, 스키마에 없는 키·필수(int·enum) 키 누락·배열 입력은 bad_attr', async () => {
  assert.deepEqual(await encodeProfile(S, { birthYear: '1990', country: 'KR' }), ['1990', '410', '0', '0', '0', '0']);
  assert.deepEqual(await encodeProfile(S, { birthYear: '2005', country: 'US' }), ['2005', '840', '0', '0', '0', '0']);
  const withStr = await encodeProfile(S, { birthYear: '1990', country: 'KR', extra1: 'vip', extra2: '' });
  assert.equal(withStr[2], await encodeSlotValue(S, 2, 'vip')); assert.equal(withStr[3], '0');
  await assert.rejects(encodeProfile(S, { birthYear: '1990', country: 'KR', nope: '1' }), (e) => e.reason === 'bad_attr' && e.detail === 'unknown_field' && e.field === 'nope');
  await assert.rejects(encodeProfile(S, { country: 'KR' }), (e) => e.reason === 'bad_attr' && e.detail === 'missing_field' && e.field === 'birthYear');
  await assert.rejects(encodeProfile(S, ['1990']), (e) => e.reason === 'bad_attr' && e.detail === 'type');
  assert.deepEqual(await encodeProfile(S, { birthYear: '', country: '' }), ['0', '0', '0', '0', '0', '0'], '빈 값은 0');
});

await t('encodeMembers: 이름·코드 혼용 → bigint, 빈 토큰·없는 이름 오류', async () => {
  assert.deepEqual(await encodeMembers(S, 1, ['KR', '392', 'US']), [410n, 392n, 840n]);
  await assert.rejects(encodeMembers(S, 1, ['KR', '']), (e) => e.reason === 'bad_attr');
  await assert.rejects(encodeMembers(S, 1, ['XX']), (e) => e.detail === 'enum');
  assert.deepEqual(await encodeMembers(S, 0, ['1990', '2000']), [1990n, 2000n]);
});

await t('decodeAttrs: int 그대로, enum 코드 → 이름(없으면 #코드), string 은 profile 원문(없으면 #값), 0 은 빈 표시, unused 빈 표시', async () => {
  const attrs = ['1990', '410', await encodeSlotValue(S, 2, 'vip'), '0', '0', '0'];
  const v = decodeAttrs(S, attrs, { extra1: 'vip' });
  assert.deepEqual(v.map((x) => x.display), ['1990', 'KR', 'vip', '', '', '']);
  assert.deepEqual(v.map((x) => x.name), ['birthYear', 'country', 'extra1', 'extra2', null, null]);
  assert.equal(v[1].label, '국가'); assert.equal(v[1].type, 'enum'); assert.equal(v[1].value, '410');
  assert.equal(decodeAttrs(S, ['0', '999', '77', '0', '0', '0'])[1].display, '#999');
  assert.equal(decodeAttrs(S, ['0', '999', '77', '0', '0', '0'])[2].display, '#77');
  assert.deepEqual(decodeAttrs(S, null).map((x) => x.display), ['', '', '', '', '', '']);
});

await t('profileFromAttrs/reencodeLossy(이행용, 동기): 등급 2 는 버려지고(lost why string), 국가 코드 → 이름, 없는 코드는 버림', () => {
  const r = reencodeLossy(S, ['1990', '410', '2', '0', '0', '0']);
  assert.deepEqual(r.profile, { birthYear: '1990', country: 'KR' });
  assert.deepEqual(r.attrs, ['1990', '410', '0', '0', '0', '0']);
  assert.deepEqual(r.lost, [{ slot: 2, value: '2', why: 'string' }]);
  const u = reencodeLossy(S, ['2005', '999', '0', '0', '7', '0']);
  assert.deepEqual(u.profile, { birthYear: '2005' });
  assert.deepEqual(u.attrs, ['2005', '0', '0', '0', '0', '0']);
  assert.deepEqual(u.lost.map((l) => l.why), ['enum', 'unused']);
  assert.deepEqual(profileFromAttrs(S, ['0', '0', '0', '0', '0', '0']), { profile: {}, lost: [] });
  assert.deepEqual(reencodeLossy(S, ['1990', '410', '2', '0']).attrs, ['1990', '410', '0', '0', '0', '0'], '짧은 배열은 0 패딩');
  assert.deepEqual(reencodeLossy(S, ['1800', '410', '0', '0', '0', '0']).lost, [{ slot: 0, value: '1800', why: 'range' }]);
});

await t('allowedPredicates·assertPredicateTypes: int 범위·집합, enum·string 집합만, unused 없음', () => {
  assert.deepEqual(allowedPredicates(S, 0), { range: true, set: true });
  assert.deepEqual(allowedPredicates(S, 1), { range: false, set: true });
  assert.deepEqual(allowedPredicates(S, 2), { range: false, set: true });
  assert.deepEqual(allowedPredicates(S, 4), { range: false, set: false });
  assert.deepEqual(allowedPredicates(S, 9), { range: false, set: false });
  assertPredicateTypes(S, [{ lo: '0', hi: '2007' }, null, null, null], { slot: 1, members: [410] });
  assertPredicateTypes(S, null, null); assertPredicateTypes(S, 'garbage', { slot: 'x' });   // 형식 오류는 normalizeDisclosure 의 몫
  assert.throws(() => assertPredicateTypes(S, [null, { lo: '410', hi: '410' }], null), (e) => e.reason === 'predicate_type');
  assert.throws(() => assertPredicateTypes(S, null, { slot: 4, members: [0] }), (e) => e.reason === 'predicate_type');
  assertPredicateTypes(S, null, { slot: 2, members: [1] });
});

// 최종 리뷰 I1(2026-10-07): 관리자 입력은 min > 0 인 int 슬롯·enum 슬롯의 빈 값을 거절한다 — 0 은 "값 없음"인데 나이 술어의
// hi 만 보는 검사(AttrGate)는 0 을 통과시킨다. 등록·이행·데모 인코딩은 기본값(허용) 그대로.
await t('encodeProfile allowEmptyRequired:false — int(min>0)·enum 의 빈 값은 bad_attr empty, int(min 0)·string 의 빈 값은 허용; 기본 옵션은 여전히 0', async () => {
  await assert.rejects(encodeProfile(S, { birthYear: '', country: 'KR' }, { allowEmptyRequired: false }), (e) => e.reason === 'bad_attr' && e.detail === 'empty' && e.slot === 0 && e.field === 'birthYear');
  await assert.rejects(encodeProfile(S, { birthYear: ' ', country: 'KR' }, { allowEmptyRequired: false }), (e) => e.detail === 'empty' && e.slot === 0, '공백만 있는 값도 빈 값');
  await assert.rejects(encodeProfile(S, { birthYear: '1990', country: '' }, { allowEmptyRequired: false }), (e) => e.detail === 'empty' && e.slot === 1 && e.field === 'country');
  assert.deepEqual(await encodeProfile(S, { birthYear: '1990', country: 'KR', extra1: '' }, { allowEmptyRequired: false }), ['1990', '410', '0', '0', '0', '0'], 'string 의 빈 값은 허용');
  assert.deepEqual(await encodeProfile(S, { birthYear: '', country: 'KR' }), ['0', '410', '0', '0', '0', '0'], '기본 옵션(등록·이행·데모)은 빈 값 0');
  const S0 = loadSchema(withSlots(six({ name: 'n', type: 'int' }))).schema;   // min 0 — 0 이 범위 안이라 빈 값이 의미를 바꾸지 않는다
  assert.deepEqual(await encodeProfile(S0, { n: '' }, { allowEmptyRequired: false }), ['0', '0', '0', '0', '0', '0']);
});

// 최종 리뷰 I3: 관리자 경로가 저장하는 profile 은 정규형이다 — enum 은 이름, int 는 정규 10진, string 은 앞뒤 공백 제거, 빈 값은 키 생략.
await t('normalizeProfile: enum 코드 → 이름, int 정규 10진, string trim, 빈 값은 키 생략, 숫자 입력도', () => {
  assert.deepEqual(normalizeProfile(S, { birthYear: ' 1990 ', country: '410', extra1: 'vip', extra2: '' }), { birthYear: '1990', country: 'KR', extra1: 'vip' });
  assert.deepEqual(normalizeProfile(S, { birthYear: '0001990', country: 'KR', extra1: '  a b  ' }), { birthYear: '1990', country: 'KR', extra1: 'a b' });
  assert.deepEqual(normalizeProfile(S, { birthYear: 2005, country: 840 }), { birthYear: '2005', country: 'US' });
  assert.deepEqual(normalizeProfile(S, { birthYear: '', country: '' }), {});
  assert.deepEqual(normalizeProfile(S, Object.assign(Object.create({ extra1: 'inherited' }), { birthYear: '1990' })), { birthYear: '1990' }, '상속된 키는 보지 않는다(M3)');
});

// 최종 리뷰 M2: string 도 앞뒤 공백을 뗀다(내부 공백은 유지) — 관리자 화면·API 의 공백 처리가 int·enum 과 같아진다.
await t('string: 앞뒤 공백은 떼고 내부 공백은 유지', async () => {
  assert.equal(await encodeSlotValue(S, 2, ' vip '), await encodeSlotValue(S, 2, 'vip'));
  assert.notEqual(await encodeSlotValue(S, 2, 'a b'), await encodeSlotValue(S, 2, 'ab'));
  assert.equal(await encodeSlotValue(S, 2, '   '), '0', '공백만이면 빈 값');
});

// 최종 리뷰 M3: 사용자 정의 스키마의 이름이 Object.prototype 의 키와 겹치면 조회가 상속 값을 집는다 — 스키마에서 막고, 조회는 hasOwn.
await t('M3: loadSchema 는 예약 이름(constructor·prototype·toString 등)을 슬롯·enum 이름으로 거절, 안전하지 않은 number 는 format, 상속 키는 무시', async () => {
  for (const n of ['constructor', 'prototype', 'hasOwnProperty', 'toString', 'valueOf']) {
    assert.throws(() => loadSchema(withSlots(six({ name: n, type: 'string' }))), (e) => e.reason === 'bad_schema' && /예약/.test(e.message), `슬롯 이름 ${n}`);
    assert.throws(() => loadSchema(withSlots(six({ name: 'c', type: 'enum', values: { [n]: 1 } }))), (e) => e.reason === 'bad_schema' && /예약/.test(e.message), `enum 이름 ${n}`);
  }
  assert.throws(() => loadSchema(JSON.parse('{"id":"x","version":1,"slots":[{"name":"c","type":"enum","values":{"__proto__":1}},{"type":"unused"},{"type":"unused"},{"type":"unused"},{"type":"unused"},{"type":"unused"}]}')), (e) => e.reason === 'bad_schema');
  await assert.rejects(encodeSlotValue(S, 0, 2 ** 53 + 2), (e) => e.reason === 'bad_attr' && e.detail === 'format');
  await assert.rejects(encodeSlotValue(S, 0, 1990.5), (e) => e.detail === 'format');
  await assert.rejects(encodeSlotValue(S, 2, NaN), (e) => e.detail === 'format', 'string 슬롯도 숫자 입력은 안전한 정수만');
  assert.deepEqual(await encodeProfile(S, Object.assign(Object.create({ extra1: 'vip' }), { birthYear: '1990', country: 'KR' })), ['1990', '410', '0', '0', '0', '0'], '상속된 extra1 은 값이 아니다');
  assert.equal(decodeAttrs(S, ['0', '0', '77', '0', '0', '0'], Object.create({ extra1: 'x' }))[2].display, '#77');
});

process.exit(failed === 0 ? 0 : 1);
