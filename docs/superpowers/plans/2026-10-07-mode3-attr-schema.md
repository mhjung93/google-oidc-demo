# Mode 3 속성 매핑 계층(스펙 2) 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 사용자 속성을 사람이 읽는 값(`birthYear "1990"`, `country "KR"`, 문자열)으로 다루고, 공개 스키마가 정한 타입별 규칙(int 그대로, enum 은 스키마의 코드, string 은 64비트 Poseidon 해시)으로 인코딩해 기존 C_u 6슬롯에 넣는다. 회로·서명·Snap·지갑 상태의 내부 표현("10진 문자열 6개")은 바꾸지 않는다.

**Architecture:** 공유 모듈 `lib/mode3_attr_schema.js` 하나가 기본 스키마·검증·인코더·디코더·술어 타입 표를 들고, IdP(`cia.js`)가 `GET /cia/attr_schema` 로 스키마를 공개하며 계정의 정본을 `profile`(원래 값)로 바꾼다(상태 v10→v11). 지갑 에이전트와 RP 는 기동 때 그 스키마를 받아 술어 타입 검사(`predicate_type`)·국가 이름 정책(`MODE3_ALLOWED_COUNTRIES=KR,JP`)·슬롯 번호 조회에 쓰고, 화면은 이름값으로 그린다. AttrGate(불변 컨트랙트)는 그대로이며 기본 스키마가 그 슬롯 위치(출생연도 0, 국가 1)를 지킨다.

**Tech Stack:** Node 22 ESM, express, circomlibjs(Poseidon), 기존 테스트 양식(`tests/*.mjs|js` 는 `t(name, fn)` 스크립트, 격리 스택 `tests/helpers/isolated_cia.mjs`·`isolated_mode3_stack.mjs`). 회로·컨트랙트·zkey 변경 없음.

**Spec:** `docs/superpowers/specs/2026-10-07-mode3-attr-schema-design.md` (결정 D1~D5, §3 스키마, §4 인코딩, §5 구성 요소, §6 이행, §7 오류표가 이 계획의 근거다.)

## Global Constraints

- 회로(`circuits/pi_cred.circom`)·`build/mode3/`·`PiCredVerifier.sol`·`AttrGate.sol`·공개 입력 30개·`ATTR_SLOTS = 6`·`ATTR_MAX = 2^64` 는 **건드리지 않는다**(스펙 D3). `npm run zk:*` 를 실행하지 않는다.
- 외부 인터페이스 `attrs`(10진 문자열 6개)는 CIA·지갑·Snap 사이에서 **그대로** 흐른다. 새 필드(`profile`, `schemaHash`, `attrSchema`, `attrsView`)는 **추가**만 한다.
- 인코딩 규칙(스펙 §4, 글자 그대로): 결과는 정규 10진 문자열. int 는 `^[0-9]+$`(앞뒤 공백 제거), 빈 값 = `"0"`(min 과 무관하게 허용), 아니면 `[min, max]`. enum 은 이름(대소문자 구분) 또는 표에 있는 코드 숫자, 빈 값 = `"0"`, 코드 0 은 예약. string 은 NFC → UTF-8, 빈 문자열 = `"0"`, `maxBytes`(기본·상한 124) 초과는 오류, 31바이트 조각 c₀…c₃(big-endian, 모자라면 0), `h = Poseidon(DOMAIN_MODE3_ATTRSTR, slotIndex, byteLength, c₀, c₁, c₂, c₃)`, 값 = `(h mod (2^64 − 1)) + 1`. `DOMAIN_MODE3_ATTRSTR = 23926173293432628108999218258n`(ASCII `"MODE3ATTRSTR"` 빅엔디언 — `lib/mode3_credential.js` 의 `DOMAIN_MODE3_CRED_V5` 와 같은 방식). unused 는 입력이 비어 있거나 `"0"` 이어야 하고 결과 `"0"`.
- 스키마 검증(스펙 §3.1): 슬롯 정확히 6개, `name` 은 `^[a-zA-Z][a-zA-Z0-9_]*$` 이고 서로 다름(`unused` 는 name 없음), int `0 ≤ min ≤ max < 2^64`, enum 코드 유일·`0 < 코드 < 2^64`, `string.maxBytes ≤ 124`. 어기면 **기동 실패**. 스키마 해시 = 키를 정렬한 정규 JSON(공백 없음)의 SHA-256 16진.
- 기본 스키마 `zkd-attrs` v1(스펙 §3.2): a₀ `birthYear` int 1900~2100, a₁ `country` enum `{KR:410, JP:392, US:840, DE:276, FR:250, GB:826, CN:156, CA:124, AU:36, SG:702}`, a₂ `extra1` string, a₃ `extra2` string, a₄·a₅ unused. 데모 계정: testuser `{birthYear:"1990", country:"KR"}` → attrs `['1990','410','0','0','0','0']`, alice `{birthYear:"2005", country:"US"}` → `['2005','840','0','0','0','0']`(등급 제거, D4).
- 오류 코드(스펙 §7): 관리자 입력 인코딩 실패 → 400 `{ error:'bad_attr', slot, reason }`; 예전 `{attrs:[…]}` → 400 `use_profile`; 지갑의 술어 타입 위반 → 400 `predicate_type`; RP 정책 국가가 표에 없음 → 기동 실패; 스키마에 `country`/`birthYear` 없음 → 로그인 `predicate_unavailable`.
- 상태 파일: CIA `CIA_STATE_VERSION` 10 → **11**(`accounts[uid].profile`). 지갑·Snap 상태 버전은 올리지 않는다(`profile` 은 선택 필드). `idp_state.json`·`cia_state.json` 을 지우지 않는다.
- 테스트 실행: `unit` 그룹은 `node tests/<file>` 로 바로. `chain` 그룹은 :8545 hardhat 노드가 필요하다 — 떠 있지 않으면 구현자가 `npx hardhat node` 를 백그라운드로 띄워도 되고(CLAUDE.md 2026-09-11 허용), 자기가 띄운 노드는 작업 끝에 종료해 :8545 가 비었는지 확인한다. 이미 떠 있던 노드는 건드리지 않는다. `browser` 그룹은 Chrome 이 필요하다(없으면 `BLOCKED:` 로 실패 — 그 사실만 보고).
- 커밋은 사용자 승인 뒤(CLAUDE.md). 계획의 "Commit" 단계는 메시지 제안이다 — SDD 실행 때 사용자가 커밋을 허용했으면 그대로 수행하고, 아니면 메시지만 남긴다. 커밋 트레일러: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` + `Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN`.
- 기존 규칙 유지: `.env`·키 파일 읽기 금지, 새 테스트는 `scripts/run_tests.sh` 의 그룹에 넣는다, 문서 용어·문체 유지(한글).

---

## 파일 구조

| 파일 | 책임 |
|---|---|
| `lib/mode3_attr_schema.js` (신규) | 기본 스키마, `loadSchema`, `canonicalJson`, `encodeSlotValue`/`encodeProfile`/`encodeMembers`, `decodeAttrs`, `profileFromAttrs`/`reencodeLossy`(이행용 동기), `slotIndexOf`, `allowedPredicates`, `assertPredicateTypes`, `schemaInfo` |
| `tests/test_mode3_attr_schema.mjs` (신규, unit) | 위 모듈의 단위 테스트 |
| `lib/mode3_cia_state.js` (수정) | v10→v11 이행: `profile` 생성, 표현 불가 값 버림, `attrsChanged` 반환 |
| `lib/mode3_health.js` (수정) | `buildAaHealth` 에 `attrSchema` |
| `cia.js` (수정) | 스키마 로드(`CIA_ATTR_SCHEMA_FILE`), DEMO `profile`, 이행 뒤 자격증명 은퇴, `GET /cia/attr_schema`, 응답 `profile`·`schemaHash`, 관리자 `{profile}` |
| `lib/mode3_secret_source.js` (수정) | `stripSecrets` 가 `profile` 을 통과시킨다 |
| `mode3_wallet_agent.js` (수정) | 스키마 캐시, `predicate_type`, `profile` 보관, `/wallet/status` 추가 필드, `GET /wallet/attr_schema` |
| `mode3_rp.js` (수정) | 스키마 수신, `MODE3_ALLOWED_COUNTRIES` 이름 해석, 슬롯 번호 조회, AttrGate 가드, `rp_info.predicates` 추가 필드, `predicate_unavailable` |
| `snap-mode3/src/index.js` (수정) | `SLOT_LABELS` 만 |
| `mode3/common/strings.js`, `mode3/cia_admin.html`, `mode3/wallet.html`, `mode3/rp.html` (수정) | 이름값 화면 |
| `docs/MODE3_DEMO.md`, `docs/superpowers/specs/2026-10-01-mode3-v9-registry-design.md` (수정) | 문서 |
| `tests/*`(수정) | 데모 값 변경(등급 2 → 0)·관리자 `{profile}`·새 단언 |

---

### Task 1: 공유 모듈 `lib/mode3_attr_schema.js` + 단위 테스트

**Files:**
- Create: `lib/mode3_attr_schema.js`
- Create: `tests/test_mode3_attr_schema.mjs`
- Modify: `scripts/run_tests.sh:30-51` (UNIT 배열에 한 줄)

**Interfaces:**
- Consumes: `ATTR_SLOTS`, `ATTR_MAX` from `lib/mode3_credential.js`; `buildPoseidon` from `circomlibjs`.
- Produces (뒤 작업 전부가 이 이름을 쓴다):
  - `DEFAULT_ATTR_SCHEMA: object`, `DOMAIN_MODE3_ATTRSTR: bigint`, `STRING_MAX_BYTES = 124`
  - `canonicalJson(value) → string`
  - `loadSchema(json) → { schema, hash }` — 실패 시 `Error{ reason:'bad_schema' }`
  - `schemaInfo(schema, hash) → { id, version, hash }`
  - `slotIndexOf(schema, name) → number` (없으면 -1)
  - `allowedPredicates(schema, slotIndex) → { range: boolean, set: boolean }`
  - `encodeSlotValue(schema, slotIndex, value) → Promise<string>` — 실패 시 `Error{ reason:'bad_attr', slot, field, detail }`
  - `encodeProfile(schema, profile) → Promise<string[6]>` — 스키마에 없는 키·필수 키 누락도 `bad_attr`
  - `encodeMembers(schema, slotIndex, tokens: string[]) → Promise<bigint[]>` — 빈 토큰은 오류
  - `decodeAttrs(schema, attrs, profile?) → [{ slot, name, label, type, value, display }]` (동기)
  - `profileFromAttrs(schema, attrs) → { profile, lost: [{slot, value, why}] }` (동기)
  - `reencodeLossy(schema, attrs) → { profile, attrs: string[6], lost }` (동기)
  - `assertPredicateTypes(schema, disclose, set)` — 위반 시 `Error{ reason:'predicate_type' }`

- [ ] **Step 1: 실패하는 단위 테스트 작성**

`tests/test_mode3_attr_schema.mjs`:

```js
// 속성 매핑 계층(스펙 2026-10-07 §3·§4) — 스키마 검증·타입별 인코딩. 외부 의존 없음(Poseidon 은 circomlibjs). (unit)
//   node tests/test_mode3_attr_schema.mjs
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { buildPoseidon } from 'circomlibjs';
import {
  DEFAULT_ATTR_SCHEMA, DOMAIN_MODE3_ATTRSTR, STRING_MAX_BYTES, canonicalJson, loadSchema, schemaInfo, slotIndexOf, allowedPredicates,
  encodeSlotValue, encodeProfile, encodeMembers, decodeAttrs, profileFromAttrs, reencodeLossy, assertPredicateTypes,
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
  assert.equal(await encodeSlotValue(S, 2, 'é'), await encodeSlotValue(S, 2, 'é'), 'NFC');
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

process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_attr_schema.mjs`
Expected: `ERR_MODULE_NOT_FOUND` (`lib/mode3_attr_schema.js` 없음)

- [ ] **Step 3: 모듈 구현**

`lib/mode3_attr_schema.js`:

```js
// Mode 3 속성 매핑 계층(스펙 2, 2026-10-07): 공개 스키마와 타입별 인코딩. 회로·서명·Snap·지갑 상태가 쓰는 내부 표현
// ("인코딩된 10진 문자열 6개", lib/mode3_credential.js 의 normalizeAttrs)은 바꾸지 않고 그 앞에 얹는다.
//   int    → 10진 그대로(빈 값 0, 아니면 [min, max])
//   enum   → 스키마에 적힌 코드(이름 또는 표에 있는 코드 숫자 입력, 빈 값 0, 코드 0 은 예약)
//   string → NFC·UTF-8 → Poseidon(DOMAIN, slot, len, c0..c3) 를 64비트로 줄인 값 (1 ≤ v < 2^64 — 빈 값 0·SET_PAD 2^64 와 겹치지 않음)
//   unused → 항상 0
// 이 모듈은 IdP(cia.js)·지갑(mode3_wallet_agent.js)·RP(mode3_rp.js)가 같이 쓴다(결정 D5). 스키마는 서명에 묶이지 않는다(스펙 §8).
import { createHash } from 'node:crypto';
import { buildPoseidon } from 'circomlibjs';
import { ATTR_SLOTS, ATTR_MAX } from './mode3_credential.js';

export const DOMAIN_MODE3_ATTRSTR = 23926173293432628108999218258n;   // ASCII "MODE3ATTRSTR" 빅엔디언(DOMAIN_MODE3_CRED_V5 와 같은 방식)
export const STRING_MAX_BYTES = 124;   // 31바이트 × 4 조각 — 조각 하나가 BN254 필드(254비트)에 들어가는 최대
const CHUNK = 31;
const CHUNKS = 4;
const NAME_RE = /^[a-zA-Z][a-zA-Z0-9_]*$/;
const U64_MAX = ATTR_MAX - 1n;   // 2^64 − 1
const TYPES = ['int', 'enum', 'string', 'unused'];

/** 기본 스키마 zkd-attrs v1(스펙 §3.2). AttrGate(불변)가 전제하는 위치: birthYear = 슬롯 0, country = 슬롯 1. */
export const DEFAULT_ATTR_SCHEMA = Object.freeze({
  id: 'zkd-attrs',
  version: 1,
  slots: [
    { name: 'birthYear', label: '출생연도', type: 'int', min: 1900, max: 2100 },
    { name: 'country', label: '국가', type: 'enum', values: { KR: 410, JP: 392, US: 840, DE: 276, FR: 250, GB: 826, CN: 156, CA: 124, AU: 36, SG: 702 } },   // ISO 3166-1 numeric
    { name: 'extra1', label: '예비 1', type: 'string' },
    { name: 'extra2', label: '예비 2', type: 'string' },
    { type: 'unused' },
    { type: 'unused' },
  ],
});

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

/** 키를 정렬한 정규 JSON(공백 없음). undefined 값인 키는 뺀다. 스키마 해시의 입력이다. */
export function canonicalJson(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v !== null && typeof v === 'object') {
    return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}

function toU64(v, fail, field) {
  let b;
  try { b = typeof v === 'bigint' ? v : BigInt(typeof v === 'number' ? (Number.isSafeInteger(v) ? v : NaN) : String(v).trim()); }
  catch { throw fail(`${field} 는 정수`); }
  if (b < 0n || b > U64_MAX) throw fail(`${field} 는 0..2^64-1`);
  return b;
}

/** 스키마 검증(스펙 §3.1). 통과하면 { schema(입력 그대로), hash }. 어기면 Error{ reason:'bad_schema' } — 호출자는 기동을 멈춘다. */
export function loadSchema(json) {
  const fail = (msg) => Object.assign(new Error(`attr schema: ${msg}`), { reason: 'bad_schema' });
  if (!json || typeof json !== 'object' || Array.isArray(json)) throw fail('객체여야 한다');
  if (typeof json.id !== 'string' || json.id === '') throw fail('id 는 비어 있지 않은 문자열');
  if (!Number.isInteger(json.version) || json.version < 1) throw fail('version 은 1 이상의 정수');
  if (!Array.isArray(json.slots) || json.slots.length !== ATTR_SLOTS) throw fail(`slots 는 정확히 ${ATTR_SLOTS}개`);
  const names = new Set();
  json.slots.forEach((s, i) => {
    const at = (m) => fail(`슬롯 ${i}: ${m}`);
    if (!s || typeof s !== 'object' || Array.isArray(s)) throw at('객체여야 한다');
    if (!TYPES.includes(s.type)) throw at(`type 은 ${TYPES.join('|')} (${s.type})`);
    if (s.type === 'unused') { if (s.name !== undefined) throw at('unused 슬롯은 name 이 없어야 한다'); return; }
    if (typeof s.name !== 'string' || !NAME_RE.test(s.name)) throw at('name 은 ^[a-zA-Z][a-zA-Z0-9_]*$');
    if (names.has(s.name)) throw at(`name 중복 (${s.name})`);
    names.add(s.name);
    if (s.label !== undefined && typeof s.label !== 'string') throw at('label 은 문자열');
    if (s.type === 'int') {
      const min = toU64(s.min ?? 0, at, 'min'), max = toU64(s.max ?? U64_MAX, at, 'max');
      if (min > max) throw at('min ≤ max');
    } else if (s.type === 'enum') {
      if (!s.values || typeof s.values !== 'object' || Array.isArray(s.values) || Object.keys(s.values).length === 0) throw at('values 는 비어 있지 않은 객체');
      const seen = new Set();
      for (const [k, v] of Object.entries(s.values)) {
        if (!NAME_RE.test(k)) throw at(`enum 이름 ${k} 은 ^[a-zA-Z][a-zA-Z0-9_]*$`);
        const code = toU64(v, at, `values.${k}`);
        if (code === 0n) throw at(`values.${k}: 코드 0 은 "값 없음"으로 예약`);
        if (seen.has(code)) throw at(`values.${k}: 코드 ${code} 중복`);
        seen.add(code);
      }
    } else if (s.type === 'string') {
      if (s.maxBytes !== undefined && !(Number.isInteger(s.maxBytes) && s.maxBytes >= 1 && s.maxBytes <= STRING_MAX_BYTES)) throw at(`maxBytes 는 1..${STRING_MAX_BYTES}`);
    }
  });
  return { schema: json, hash: createHash('sha256').update(canonicalJson(json)).digest('hex') };
}

export const schemaInfo = (schema, hash) => ({ id: schema.id, version: schema.version, hash });
export const slotIndexOf = (schema, name) => schema.slots.findIndex((s) => s.type !== 'unused' && s.name === name);
/** 슬롯에 쓸 수 있는 술어(스펙 §3.1 표): 범위는 int 만, 집합은 int·enum·string. */
export function allowedPredicates(schema, slotIndex) {
  const type = schema.slots[slotIndex]?.type;
  return { range: type === 'int', set: type === 'int' || type === 'enum' || type === 'string' };
}

const attrFail = (slotIndex, field, detail, msg) => Object.assign(new Error(msg), { reason: 'bad_attr', slot: slotIndex, field, detail });

async function hashString(slotIndex, bytes) {
  const chunks = [];
  for (let k = 0; k < CHUNKS; k++) {
    let v = 0n;
    for (const b of bytes.subarray(k * CHUNK, (k + 1) * CHUNK)) v = (v << 8n) | BigInt(b);
    chunks.push(v);
  }
  const poseidon = await getPoseidon();
  const h = poseidon.F.toObject(poseidon([DOMAIN_MODE3_ATTRSTR, BigInt(slotIndex), BigInt(bytes.length), ...chunks]));
  return (h % U64_MAX) + 1n;   // 1 ≤ 값 ≤ 2^64 − 1
}

/** 슬롯 하나의 값을 인코딩한다(스펙 §4). 결과는 정규 10진 문자열. 실패는 Error{ reason:'bad_attr', slot, field, detail }. */
export async function encodeSlotValue(schema, slotIndex, value) {
  const s = schema.slots[slotIndex];
  const fail = (detail, msg) => attrFail(slotIndex, s?.name ?? null, detail, `슬롯 ${slotIndex}${s?.name ? `(${s.name})` : ''}: ${msg}`);
  if (!s) throw fail('no_slot', '없는 슬롯');
  let raw;
  if (value === undefined || value === null) raw = '';
  else if (typeof value === 'string') raw = value;
  else if (typeof value === 'number' || typeof value === 'bigint') raw = String(value);
  else throw fail('type', '문자열·숫자만 받는다');
  if (s.type !== 'string') raw = raw.trim();
  if (s.type === 'unused') { if (raw !== '' && raw !== '0') throw fail('unused', '미사용 슬롯에 값이 있다'); return '0'; }
  if (raw === '') return '0';
  if (s.type === 'int') {
    if (!/^[0-9]+$/.test(raw)) throw fail('format', `10진 정수여야 한다: ${raw}`);
    const v = BigInt(raw);
    const min = BigInt(s.min ?? 0), max = BigInt(s.max ?? U64_MAX);
    if (v < min || v > max) throw fail('range', `[${min}, ${max}] 밖: ${v}`);
    return v.toString();
  }
  if (s.type === 'enum') {
    if (Object.prototype.hasOwnProperty.call(s.values, raw)) return BigInt(s.values[raw]).toString();
    if (/^[0-9]+$/.test(raw)) { const code = BigInt(raw); if (Object.values(s.values).some((c) => BigInt(c) === code)) return code.toString(); }
    throw fail('enum', `표에 없는 값: ${raw}`);
  }
  const bytes = Buffer.from(raw.normalize('NFC'), 'utf8');
  const maxBytes = s.maxBytes ?? STRING_MAX_BYTES;
  if (bytes.length > maxBytes) throw fail('length', `${maxBytes}바이트 초과 (${bytes.length}바이트)`);
  return (await hashString(slotIndex, bytes)).toString();
}

/** profile({ 슬롯 이름: 값 }) → attrs(10진 문자열 6개). int·enum 슬롯 이름은 키가 있어야 한다(값은 빈 문자열 가능) — 빈 객체 한 번으로
 *  속성이 통째로 지워지는 것을 막는다(2026-09-23 점검 A-I2 와 같은 이유). string 키는 생략 가능(= 빈 값). 스키마에 없는 키는 오류. */
export async function encodeProfile(schema, profile) {
  if (profile === undefined || profile === null) profile = {};
  if (typeof profile !== 'object' || Array.isArray(profile)) throw attrFail(null, null, 'type', 'profile 은 { 이름: 값 } 객체여야 한다');
  const named = schema.slots.filter((s) => s.type !== 'unused');
  const known = new Set(named.map((s) => s.name));
  for (const k of Object.keys(profile)) if (!known.has(k)) throw attrFail(null, k, 'unknown_field', `스키마에 없는 필드: ${k}`);
  for (const s of named) if ((s.type === 'int' || s.type === 'enum') && !Object.prototype.hasOwnProperty.call(profile, s.name)) throw attrFail(slotIndexOf(schema, s.name), s.name, 'missing_field', `필드가 없다: ${s.name}`);
  const out = [];
  for (let i = 0; i < schema.slots.length; i++) {
    const s = schema.slots[i];
    out.push(await encodeSlotValue(schema, i, s.type === 'unused' ? '' : profile[s.name]));
  }
  return out;
}

/** 집합 술어의 원소 목록(RP 정책 `KR,JP`·`410,392`, 지갑 요청)을 같은 슬롯의 인코더로. 빈 토큰은 오류(0 이 조용히 들어가지 않게). */
export async function encodeMembers(schema, slotIndex, tokens) {
  const out = [];
  for (const tok of tokens) {
    const s = typeof tok === 'string' ? tok.trim() : String(tok);
    if (s === '') throw attrFail(slotIndex, schema.slots[slotIndex]?.name ?? null, 'empty', `슬롯 ${slotIndex}: 빈 원소`);
    out.push(BigInt(await encodeSlotValue(schema, slotIndex, s)));
  }
  return out;
}

const enumName = (s, value) => { const hit = Object.entries(s.values).find(([, c]) => BigInt(c) === BigInt(value)); return hit ? hit[0] : null; };

/** 표시용 디코드(동기). string 은 일방향이라 profile 의 원문을 쓴다(없으면 #값). 0 은 빈 표시. */
export function decodeAttrs(schema, attrs, profile = null) {
  return schema.slots.map((s, i) => {
    const value = String(attrs?.[i] ?? '0');
    const base = { slot: i, name: s.name ?? null, label: s.label ?? s.name ?? null, type: s.type, value };
    if (s.type === 'unused' || value === '0') return { ...base, display: '' };
    if (s.type === 'int') return { ...base, display: value };
    if (s.type === 'enum') return { ...base, display: enumName(s, value) ?? `#${value}` };
    const orig = profile?.[s.name];
    return { ...base, display: typeof orig === 'string' && orig !== '' ? orig : `#${value}` };
  });
}

/** 인코딩된 attrs 에서 profile 을 되살린다(이행용, 동기 — Poseidon 이 필요 없다). int → 10진(범위 안일 때), enum → 이름.
 *  string·unused 의 0 아닌 값, 범위 밖 int, 표에 없는 enum 코드는 되살릴 수 없어 lost 에 적고 profile 에서 뺀다. 0 은 빈 값(키 없음). */
export function profileFromAttrs(schema, attrs) {
  const profile = {}; const lost = [];
  schema.slots.forEach((s, i) => {
    const v = String(attrs?.[i] ?? '0');
    if (v === '0') return;
    if (s.type === 'unused') { lost.push({ slot: i, value: v, why: 'unused' }); return; }
    if (s.type === 'int') {
      const b = BigInt(v);
      if (b >= BigInt(s.min ?? 0) && b <= BigInt(s.max ?? U64_MAX)) profile[s.name] = b.toString(); else lost.push({ slot: i, value: v, why: 'range' });
      return;
    }
    if (s.type === 'enum') { const n = enumName(s, v); if (n) profile[s.name] = n; else lost.push({ slot: i, value: v, why: 'enum' }); return; }
    lost.push({ slot: i, value: v, why: 'string' });
  });
  return { profile, lost };
}

/** profileFromAttrs 의 결과를 다시 인코딩한 attrs(동기 — string 슬롯은 빈 값이라 해시가 필요 없다). 이행(v10→v11)이 쓴다. */
export function reencodeLossy(schema, attrs) {
  const { profile, lost } = profileFromAttrs(schema, attrs);
  const out = schema.slots.map((s) => {
    if (s.type === 'unused' || !(s.name in profile)) return '0';
    return s.type === 'enum' ? BigInt(s.values[profile[s.name]]).toString() : BigInt(profile[s.name]).toString();
  });
  return { profile, attrs: out, lost };
}

/** 지갑 요청의 disclose/set 이 슬롯 타입에 맞는 술어인지(스펙 §5.3). 형식 오류는 보지 않는다 — normalizeDisclosure/normalizeSet 의 bad_disclosure 가 맡는다. */
export function assertPredicateTypes(schema, disclose, set) {
  const fail = (msg) => Object.assign(new Error(msg), { reason: 'predicate_type' });
  if (Array.isArray(disclose)) {
    disclose.forEach((d, k) => {
      if (d === null || d === undefined || k >= schema.slots.length) return;
      if (!allowedPredicates(schema, k).range) throw fail(`슬롯 ${k}(${schema.slots[k].type})에는 범위 술어를 쓸 수 없다`);
    });
  }
  if (set && typeof set === 'object' && !Array.isArray(set) && Number.isInteger(set.slot) && set.slot >= 0 && set.slot < schema.slots.length) {
    if (!allowedPredicates(schema, set.slot).set) throw fail(`슬롯 ${set.slot}(${schema.slots[set.slot].type})에는 집합 술어를 쓸 수 없다`);
  }
}
```

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_attr_schema.mjs`
Expected: 모든 줄 `ok`, 종료 코드 0.

- [ ] **Step 5: `scripts/run_tests.sh` UNIT 배열에 추가**

`tests/test_mode3_cia_state_v9.js` 줄 다음에:

```bash
  tests/test_mode3_attr_schema.mjs
```

Run: `bash scripts/run_tests.sh unit` → 전부 통과(기존 unit 은 아직 영향 없음).

- [ ] **Step 6: Commit (제안)**

```bash
git add lib/mode3_attr_schema.js tests/test_mode3_attr_schema.mjs scripts/run_tests.sh
git commit -m "feat(mode3): 속성 매핑 계층 공유 모듈 — 공개 스키마 검증·int/enum/string/unused 인코딩·술어 타입 표"
```

---

### Task 2: CIA 상태 v10 → v11 이행 (`lib/mode3_cia_state.js`)

**Files:**
- Modify: `lib/mode3_cia_state.js` (헤더 주석·`CIA_STATE_VERSION`·`migrateCiaState`)
- Modify: `tests/test_mode3_cia_state.js:10-14, 88-100` 와 `tests/test_mode3_cia_state_v9.js:11-13, 17-21`

**Interfaces:**
- Consumes: `DEFAULT_ATTR_SCHEMA`, `reencodeLossy`, `profileFromAttrs` (Task 1).
- Produces: `CIA_STATE_VERSION = 11`; `migrateCiaState(state, { demoAttrs, attrSchema = DEFAULT_ATTR_SCHEMA }) → { state, notes, attrsChanged: string[] }` — `attrsChanged` 는 v10→v11 에서 `attrs` 가 바뀐 uid 목록(cia.js 가 자격증명을 물리고 슬롯 0 으로 게시한다). 계정마다 `profile` 객체.

- [ ] **Step 1: 단위 테스트 갱신·추가(실패하게)**

`tests/test_mode3_cia_state.js`:
- 10~14행 `'기본 상태는 v10 …'` → `v11`: `assert.equal(s.version, 11); assert.equal(CIA_STATE_VERSION, 11);` 와 deepEqual 의 `version: 11`.
- 88행 `assert.throws(() => migrateCiaState({ version: 11 }), /version 11/);` → `{ version: 12 }`, `/version 12/`.
- 91~100행(v6 → 케이스)의 `assert.equal(state.version, 10)` → `11`, `attrs` 단언을 `['1990', '410', '0', '0', '0', '0']` 로, 그리고 바로 뒤에 추가:

```js
  assert.deepEqual(state.accounts['12345'].profile, { birthYear: '1990', country: 'KR' }, 'v10→v11: profile 은 옛 attrs 에서 되살린다(등급 2 는 버림)');
```

- 파일 끝의 `process.exit` 앞에 새 케이스:

```js
t('v10 → v11: profile 생성, 표현 못 하는 값(등급·알 수 없는 국가·예비 슬롯) 버림, attrs 가 바뀐 계정만 attrsChanged, 바뀌지 않은 계정은 그대로', () => {
  const v10 = { ...defaultCiaState(), version: 10, accounts: {
    '12345': { pk_u: {}, cm_u: {}, slot: 0, tampered: false, disabled: false, creds: [{ Cf_u: '1', C_u_pt: {}, leaf: '0', issuedAt: 'x', revoked: false }], attrs: ['1990', '410', '2', '0', '0', '0'], sessions: [], receipt: null, slotRetired: false },
    '67890': { pk_u: {}, cm_u: {}, slot: 1, tampered: false, disabled: false, creds: [], attrs: ['2005', '999', '0', '55', '0', '0'], sessions: [], receipt: null, slotRetired: false },
    '77777': { pk_u: {}, cm_u: {}, slot: 2, tampered: false, disabled: false, creds: [], attrs: ['1980', '392', '0', '0', '0', '0'], sessions: [], receipt: null, slotRetired: false },
  } };
  const { state, notes, attrsChanged } = migrateCiaState(structuredClone(v10));
  assert.equal(state.version, 11);
  assert.deepEqual(state.accounts['12345'].profile, { birthYear: '1990', country: 'KR' });
  assert.deepEqual(state.accounts['12345'].attrs, ['1990', '410', '0', '0', '0', '0']);
  assert.deepEqual(state.accounts['67890'].profile, { birthYear: '2005' });
  assert.deepEqual(state.accounts['67890'].attrs, ['2005', '0', '0', '0', '0', '0']);
  assert.deepEqual(state.accounts['77777'].profile, { birthYear: '1980', country: 'JP' });
  assert.deepEqual(state.accounts['77777'].attrs, ['1980', '392', '0', '0', '0', '0']);
  assert.deepEqual(attrsChanged.sort(), ['12345', '67890'], '값이 바뀐 계정만 — 77777 은 그대로');
  assert.equal(state.accounts['12345'].creds[0].revoked, false, '이행 함수는 자격증명을 물리지 않는다 — cia.js 기동이 attrsChanged 로 물리고 슬롯 0 을 게시한다');
  assert.ok(notes.some((n) => n.startsWith('v10→v11') && n.includes('2개')), notes.join('|'));
  assert.ok(notes.some((n) => n.includes('uid 12345') && n.includes('슬롯 2')), '버린 값마다 한 줄');
});

t('v11 파일: profile 이 없는 계정(손으로 고친 파일)은 attrs 에서 되살리고 attrs 는 건드리지 않는다, attrsChanged 는 빈 배열', () => {
  const v11 = { ...defaultCiaState(), accounts: { '1': { pk_u: {}, cm_u: {}, slot: 0, disabled: false, creds: [], attrs: ['1990', '410', '77', '0', '0', '0'], sessions: [] } } };
  const { state, attrsChanged } = migrateCiaState(structuredClone(v11));
  assert.deepEqual(state.accounts['1'].profile, { birthYear: '1990', country: 'KR' });
  assert.deepEqual(state.accounts['1'].attrs, ['1990', '410', '77', '0', '0', '0']);
  assert.deepEqual(attrsChanged, []);
});
```

`tests/test_mode3_cia_state_v9.js`:
- 13행 `assert.equal(CIA_STATE_VERSION, 10);` → `11`.
- 21행 `assert.deepEqual(state.accounts['12345'].attrs, ['1990', '410', '2', '0', '0', '0']);` → `['1990', '410', '0', '0', '0', '0']` 로 바꾸고 다음 줄 추가:

```js
  assert.deepEqual(state.accounts['12345'].profile, { birthYear: '1990', country: 'KR' }); assert.deepEqual(state.accounts['67890'].profile, { birthYear: '2005', country: 'US' });
```

(67890 의 옛 등급 1 도 버려져 attrs `['2005','840','0','0','0','0']` — 그 파일에 67890 의 attrs 단언이 있으면 같이 고친다.)

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_cia_state.js; node tests/test_mode3_cia_state_v9.js`
Expected: 버전·profile 단언에서 FAIL.

- [ ] **Step 3: 이행 구현**

`lib/mode3_cia_state.js`:
- import 추가: `import { DEFAULT_ATTR_SCHEMA, reencodeLossy, profileFromAttrs } from './mode3_attr_schema.js';`
- 헤더 주석에 한 줄: `// version 11 (2026-10-07): 속성 매핑 계층(스펙 2) — accounts[uid].profile(원래 값, 스키마 이름 → 문자열)이 정본이고 attrs 는 그 인코딩. 옛 attrs 에서 profile 을 되살리되 표현할 수 없는 값(등급 슬롯 2, 예비 슬롯의 0 아닌 값, 표에 없는 국가 코드)은 버린다 — attrs 가 바뀐 계정은 cia.js 기동이 활성 자격증명을 물리고 슬롯 0 을 게시한다(관리자 속성 변경과 같은 경로).`
- `export const CIA_STATE_VERSION = 11;`
- 시그니처: `export function migrateCiaState(state, { demoAttrs = () => null, attrSchema = DEFAULT_ATTR_SCHEMA } = {}) {` 와 `const attrsChanged = [];` 를 `const notes = [];` 다음에.
- `if (state.version === 9) {...}` 블록 뒤에:

```js
  if (state.version === 10) {
    let lostN = 0;
    for (const [uid, a] of Object.entries(state.accounts ?? {})) {
      const before = [...(a.attrs ?? []), '0', '0', '0', '0', '0', '0'].slice(0, 6).map(String);
      const { profile, attrs, lost } = reencodeLossy(attrSchema, before);
      a.profile = profile;
      a.attrs = attrs;
      if (JSON.stringify(attrs) !== JSON.stringify(before)) attrsChanged.push(uid);
      lostN += lost.length;
      for (const l of lost) notes.push(`v10→v11: uid ${uid} 슬롯 ${l.slot} 값 ${l.value} 버림(${l.why} — 새 스키마로 표현할 수 없다)`);
    }
    state.version = 11;
    notes.push(`v10→v11: 계정마다 profile(스키마 ${attrSchema.id} v${attrSchema.version}), 표현할 수 없는 값 ${lostN}개 버림, 속성이 바뀐 계정 ${attrsChanged.length}개(기동이 활성 자격증명을 물리고 슬롯 0 으로 게시한다)`);
  }
```

- 끝의 방어 블록 `for (const a of Object.values(state.accounts)) { a.creds ??= []; … }` 에 `a.profile ??= profileFromAttrs(attrSchema, a.attrs ?? []).profile;` 추가.
- `return { state, notes };` → `return { state, notes, attrsChanged };`

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_cia_state.js && node tests/test_mode3_cia_state_v9.js`
Expected: 전부 `ok`.

- [ ] **Step 5: Commit (제안)**

```bash
git add lib/mode3_cia_state.js tests/test_mode3_cia_state.js tests/test_mode3_cia_state_v9.js
git commit -m "feat(cia): 상태 v10→v11 — 계정 profile 생성, 등급·표현 불가 값 버림, attrsChanged 반환"
```

---

### Task 3: IdP(`cia.js`) — 스키마 공개·profile 정본·관리자 `{profile}`·기동 이행 + chain 테스트 갱신

**Files:**
- Modify: `cia.js:25` (import), `:95-98` (DEMO_ACCOUNTS), `:211-262` (loadState), `:379-397` (health), `:479-498` (register), `:547-561` (`/cia/attrs`), `:581-604` (관리자 속성), `:1063-1065` (`/cia/accounts`); 새 라우트 `GET /cia/attr_schema`
- Modify: `lib/mode3_health.js:26-31` (`buildAaHealth`에 `attrSchema`)
- Modify (데모 값 2 → 0, 벡터만): `tests/test_cia_opening.mjs`, `tests/test_mode3_session_revoke.mjs:23`, `tests/test_cia_issue_race.mjs:67,165`, `tests/test_mode3_e2e.mjs:14`, `tests/test_cia_mirror_relay.mjs:25`, `tests/test_cia_register_issue.mjs:45,575,581`, `tests/test_cia_registry.mjs:21`, `tests/test_cia_startup.mjs:51`
- Modify (문자열 벡터·기대값): `tests/test_mode3_wallet_agent.mjs:67,70,76`, `tests/test_mode3_wallet_snap.mjs:60,68`, `tests/test_cia_register_issue.mjs:174,563,567,585-603`, `tests/test_cia_startup.mjs:152,174`, `tests/test_cia_registry.mjs:34,214`, `tests/test_mode3_browser.mjs:401,404,409`
- Modify: `tests/test_cia_startup.mjs` 에 v10→v11 기동 테스트 추가; `tests/test_mode3_health_shape.js` 에 `attrSchema` 단언 추가

**Interfaces:**
- Consumes: Task 1 전부, Task 2 의 `attrsChanged`.
- Produces(지갑·RP·화면이 의존): `GET /cia/attr_schema → { schema, hash }`; `POST /cia/register` 201 `{ slot, attrs, profile, schemaHash }`; `POST /cia/attrs` 200 `{ attrs, profile, schemaHash }`; `POST /cia/accounts/:uid/attrs` body `{ profile }` → 200 `{ uid, attrs, profile, retired, published }`, 400 `{ error:'bad_attr', slot, field, reason }` / `{ error:'use_profile' }`; `GET /cia/accounts` 항목에 `profile`; `/mode3/health.attrSchema = { id, version, hash }`; env `CIA_ATTR_SCHEMA_FILE`(선택).

- [ ] **Step 1: health 모양 단위 테스트(실패하게)**

`tests/test_mode3_health_shape.js` 의 AA 케이스(17행 블록) 끝에:

```js
  assert.equal(h.attrSchema, null, 'attrSchema 를 안 주면 null');
  assert.deepEqual(buildAaHealth({ ...base, attrSchema: { id: 'zkd-attrs', version: 1, hash: 'ab' } }).attrSchema, { id: 'zkd-attrs', version: 1, hash: 'ab' });
```

(`base` 는 그 테스트 파일이 23행 케이스에서 쓰는 기본 인자 객체다 — 17행 케이스 안에서 쓸 수 있는 같은 이름의 객체가 없으면 그 케이스의 인자를 `const base = {…}` 로 빼서 두 호출에 쓴다.)

Run: `node tests/test_mode3_health_shape.js` → FAIL(`attrSchema` undefined).

- [ ] **Step 2: `lib/mode3_health.js` 수정**

`buildAaHealth` 시그니처에 `attrSchema = null` 추가, 반환 객체 끝에:

```js
    attrSchema: attrSchema ? { id: String(attrSchema.id), version: num(attrSchema.version), hash: String(attrSchema.hash) } : null,
```

Run: `node tests/test_mode3_health_shape.js` → ok.

- [ ] **Step 3: chain 테스트를 먼저 새 동작에 맞춘다(실패하게)**

(a) bigint 벡터 — 아래 파일에서만 `[1990n, 410n, 2n, 0n, 0n, 0n]` → `[1990n, 410n, 0n, 0n, 0n, 0n]` (lib 수준 벡터인 `tests/test_mode3_wallet.mjs`·`test_mode3_issuance.js`·`test_mode3_v9_lib.js`·`tests/helpers/mode3_fixture.mjs` 는 **바꾸지 않는다** — CIA 와 맞출 필요가 없는 회로·라이브러리 입력이다):

```bash
sed -i 's/\[1990n, 410n, 2n, 0n, 0n, 0n\]/[1990n, 410n, 0n, 0n, 0n, 0n]/g' tests/test_cia_opening.mjs tests/test_mode3_session_revoke.mjs tests/test_cia_issue_race.mjs tests/test_mode3_e2e.mjs tests/test_cia_mirror_relay.mjs tests/test_cia_register_issue.mjs tests/test_cia_registry.mjs tests/test_cia_startup.mjs
grep -n "410n, 2n" tests/test_cia_*.mjs tests/test_mode3_e2e.mjs tests/test_mode3_session_revoke.mjs   # 남은 것이 없어야 한다
```

(b) 문자열 기대값 `['1990', '410', '2', '0', '0', '0']` → `['1990', '410', '0', '0', '0', '0']`:
- `tests/test_mode3_wallet_agent.mjs:70,76` (67행 주석도 `attrs = ['1990','410','0','0','0','0'](스펙 2: 등급 없음)`). **720~733행은 지갑 상태 파일 패딩 테스트라 그대로 둔다.**
- `tests/test_mode3_wallet_snap.mjs:60,68` (**308행은 Snap 쪽 값이라 그대로**).
- `tests/test_cia_register_issue.mjs:174,563,567`.
- `tests/test_cia_startup.mjs:174`, 그리고 같은 파일의 `assert.equal(saved.version, 10)` 두 곳(v3·v4 케이스) → `11`.
- `tests/test_cia_registry.mjs:34,214` (204행의 v8 입력 `['1990', '410', '2', '0']` 은 그대로 — 이행이 '2' 를 버린다).
- `tests/test_mode3_browser.mjs:401` 그리고 404·409행:

```js
    assert.equal((await stack.cia.adminPost('/cia/accounts/12345/attrs', { profile: { birthYear: '1990', country: 'KR', extra1: 'tier3' } })).status, 200);
```
```js
    assert.deepEqual(snapState.registration.attrs, ['1990', '410', await encodeSlotValue(DEFAULT_ATTR_SCHEMA, 2, 'tier3'), '0', '0', '0'], 'syncAttrs 가 Snap 의 속성을 갱신했다');
```
와 파일 상단 import 추가 `import { DEFAULT_ATTR_SCHEMA, encodeSlotValue } from '../lib/mode3_attr_schema.js';`

(c) `tests/test_cia_register_issue.mjs` 585~603행(관리자 속성 변경 케이스)을 아래로 교체(584행의 `const w = await freshWallet(); … 201` 두 줄은 유지):

```js
    const r = await cia.adminPost('/cia/accounts/12345/attrs', { profile: { birthYear: '1990', country: 'KR', extra1: 'vip' } });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.retired, 1);
    const vip = await encodeSlotValue(DEFAULT_ATTR_SCHEMA, 2, 'vip');
    assert.deepEqual(r.body.attrs, ['1990', '410', vip, '0', '0', '0']); assert.deepEqual(r.body.profile, { birthYear: '1990', country: 'KR', extra1: 'vip' });
    // published 는 false — 이 지점에서는 이미 "publish: 온체인 root가..." 케이스가 의도적으로 온체인 root 를
    // 로컬과 영영 어긋나게 해 뒀다(그 테스트 자체의 주석: "이 뒤로는 ... 게시가 전부 503"). V9 는 이 요청도
    // 즉시 게시를 시도하므로 그 503 을 그대로 맞고 조용히 삼켜진다 — retired(등록부 반영)는 그와 무관하게 맞다.
    assert.equal(r.body.published, false);
    assert.equal((await cia.post('/cia/user_cred', good.body)).status, 400, '옛 속성의 C_u 는 더 이상 통과하지 않는다');
    const next = await buildUserCredRequest({ uid: 12345n, s_u: w.s_u, r_u: w.r_u, sk_u: w.sk_u, attrs: [1990n, 410n, BigInt(vip), 0n, 0n, 0n] });
    assert.equal((await cia.post('/cia/user_cred', next.body)).status, 201);
    // 스펙 2 §7: 인코딩 실패는 400 bad_attr(슬롯·이유), 예전 배열 형식은 400 use_profile, 모르는 계정은 404
    const bad = await cia.adminPost('/cia/accounts/12345/attrs', { profile: { birthYear: '1990', country: 'XX' } });
    assert.equal(bad.status, 400); assert.equal(bad.body.error, 'bad_attr'); assert.equal(bad.body.slot, 1); assert.equal(bad.body.reason, 'enum');
    const range = await cia.adminPost('/cia/accounts/12345/attrs', { profile: { birthYear: '1800', country: 'KR' } });
    assert.equal(range.status, 400); assert.equal(range.body.error, 'bad_attr'); assert.equal(range.body.slot, 0); assert.equal(range.body.reason, 'range');
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { profile: { birthYear: '1990', country: 'KR', nope: '1' } })).body.error, 'bad_attr');
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { profile: { country: 'KR' } })).body.reason, 'missing_field', 'int·enum 키는 있어야 한다(빈 객체로 속성이 통째로 지워지는 것을 막는다 — A-I2)');
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { attrs: ['1990', '410', '0', '0', '0', '0'] })).body.error, 'use_profile');
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', {})).body.error, 'bad_attr', 'profile 이 없으면 bad_attr(profile_required)');
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { profile: 'x' })).status, 400);
    assert.equal((await cia.adminPost('/cia/accounts/424242/attrs', { profile: { birthYear: '1', country: 'KR' } })).status, 404);
    const after = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === '12345');
    assert.deepEqual(after.attrs, ['1990', '410', vip, '0', '0', '0'], '거절된 요청은 속성을 바꾸지 않았다');
    assert.deepEqual(after.profile, { birthYear: '1990', country: 'KR', extra1: 'vip' });
```

파일 상단 import 에 `import { DEFAULT_ATTR_SCHEMA, encodeSlotValue } from '../lib/mode3_attr_schema.js';` 추가. 같은 파일의 `/cia/attrs` 케이스(563~568행)에 한 줄 더:

```js
    assert.deepEqual(r.body.profile, { birthYear: '1990', country: 'KR' }); assert.equal(r.body.schemaHash, (await cia.get('/cia/attr_schema')).body.hash);
```
와 register 케이스(172~176행)에 `assert.deepEqual(w.registerBody.profile, { birthYear: '1990', country: 'KR' }); assert.match(w.registerBody.schemaHash, /^[0-9a-f]{64}$/);`

(d) `tests/test_cia_startup.mjs` — v4 케이스(170~178행) 뒤에 새 케이스:

```js
  await t('v10 상태 파일은 v11 로 이행된다 — 등급 2 를 버려 attrs 가 바뀐 계정은 활성 자격증명이 물리고 슬롯 0 이 자동 게시된다, profile 생성', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-v10-'));
    const stateFile = path.join(dir, 'cia_state.json');
    fs.writeFileSync(stateFile, JSON.stringify({
      version: 10, accounts: { '12345': { pk_u: { x: '1', y: '2' }, cm_u: { x: '3', y: '4' }, slot: 0, tampered: false, disabled: false,
        creds: [{ Cf_u: '111', C_u_pt: { x: '3', y: '4' }, leaf: '0', issuedAt: '2026-01-01T00:00:00.000Z', revoked: false }], attrs: ['1990', '410', '2', '0', '0', '0'], sessions: [], receipt: null, slotRetired: false } },
      rps: {}, openings: [], revoked: [], pending: [], epoch: 0, registry: { depth: 20, next: 1, leaves: {}, pendingSlots: [] }, lastPublication: null, signedEpochMax: 0,
    }), { mode: 0o600 });
    const cia = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile } });
    try {
      assert.match(cia.log(), /v10→v11/); assert.match(cia.log(), /슬롯 2 값 2 버림/);
      assert.match(cia.log(), /속성 스키마 이행으로 계정 1개의 활성 자격증명을 물렸다/);
      const saved = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      assert.equal(saved.version, 11);
      assert.deepEqual(saved.accounts['12345'].profile, { birthYear: '1990', country: 'KR' });
      assert.deepEqual(saved.accounts['12345'].attrs, ['1990', '410', '0', '0', '0', '0']);
      assert.equal(saved.accounts['12345'].creds[0].revoked, true, '옛 속성의 자격증명은 물린다');
      assert.equal(saved.registry.leaves['0'], undefined, '슬롯 0 은 비웠다');
      assert.deepEqual(saved.registry.pendingSlots, [], '자동 게시가 pendingSlots 를 비웠다');
      assert.equal((await cia.get('/cia/state')).body.epoch, 1, '자동 게시가 epoch 를 올렸다');
      const acct = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === '12345');
      assert.deepEqual(acct.profile, { birthYear: '1990', country: 'KR' }); assert.equal(acct.activeCf_u, null);
      const sch = await cia.get('/cia/attr_schema');
      assert.equal(sch.status, 200); assert.equal(sch.body.schema.id, 'zkd-attrs'); assert.match(sch.body.hash, /^[0-9a-f]{64}$/);
      const h = (await cia.get('/mode3/health')).body;
      assert.deepEqual(h.attrSchema, { id: 'zkd-attrs', version: 1, hash: sch.body.hash });
    } finally { await cia.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await t('CIA_ATTR_SCHEMA_FILE 이 검증에 실패하면 기동하지 않는다', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-badschema-'));
    const schemaFile = path.join(dir, 'schema.json');
    fs.writeFileSync(schemaFile, JSON.stringify({ id: 'x', version: 1, slots: [{ type: 'unused' }] }));
    await expectStartupRefused({ env: { CIA_ATTR_SCHEMA_FILE: schemaFile } });
    fs.rmSync(dir, { recursive: true, force: true });
  });
```

(`expectStartupRefused` 는 그 파일이 이미 쓰는 헬퍼다 — 140행 케이스 참고. 시그니처가 다르면 그 케이스와 같은 방식으로 맞춘다.)

- [ ] **Step 4: `cia.js` 구현**

(a) import(25행 다음):

```js
import { DEFAULT_ATTR_SCHEMA, loadSchema, encodeProfile, schemaInfo } from './lib/mode3_attr_schema.js';
```

(b) 스키마 로드 — `const VKEY_PATH = …` 다음에:

```js
// 속성 매핑 계층(스펙 2, 2026-10-07): 스키마는 공유 모듈의 기본값이고 CIA_ATTR_SCHEMA_FILE(JSON)로 바꿀 수 있다. 검증 실패는 기동 거부.
const ATTR_SCHEMA_FILE = process.env.CIA_ATTR_SCHEMA_FILE || null;
let ATTR_SCHEMA, ATTR_SCHEMA_HASH;
try {
  ({ schema: ATTR_SCHEMA, hash: ATTR_SCHEMA_HASH } = loadSchema(ATTR_SCHEMA_FILE ? JSON.parse(fs.readFileSync(ATTR_SCHEMA_FILE, 'utf8')) : DEFAULT_ATTR_SCHEMA));
} catch (e) {
  console.error(`[cia] 기동 거부: 속성 스키마 오류(${ATTR_SCHEMA_FILE ?? '기본 스키마'}) — ${e.message}`);
  process.exit(1);
}
```

(c) DEMO_ACCOUNTS(95~98행):

```js
// 데모 계정의 속성은 사람이 읽는 profile(스키마 이름 → 값)이고, attrs(인코딩)는 loadState 가 스키마로 만든다(스펙 2 §5.2). 등급은 없다(D4).
const DEMO_ACCOUNTS = {
  testuser: { password: 'password123', uid: '12345', profile: { birthYear: '1990', country: 'KR' }, attrs: null },
  alice: { password: 'alicepw', uid: '67890', profile: { birthYear: '2005', country: 'US' }, attrs: null },
};
```

(d) `loadState()` — 함수 첫 줄에:

```js
  for (const a of Object.values(DEMO_ACCOUNTS)) a.attrs = await encodeProfile(ATTR_SCHEMA, a.profile);
```

`migrateCiaState(state, { demoAttrs: …, attrSchema: ATTR_SCHEMA })` 로 인자 추가. 등록부 재구성(`registry = await createRegistryTree(…); for (…) registry.set(…)`) **다음, 리프 채우기 루프(`let filled = 0;`) 앞**에:

```js
  // v10→v11(스펙 2 §6): 새 스키마로 표현할 수 없는 값을 버려 attrs 가 바뀐 계정은 관리자 속성 변경과 같은 경로를 탄다 —
  // 활성 자격증명 은퇴 → 슬롯 0 → (아래 자동 게시). 지갑은 다음 로그인의 bad user credential proof → /cia/attrs 재동기화로 새 C_u 를 받는다.
  let retiredByMigration = 0;
  for (const uid of migrated.attrsChanged ?? []) { if (retireActiveCred(uid)) { setSlot(uid, 0n); retiredByMigration++; } }
  if (retiredByMigration) { console.warn(`[cia] 속성 스키마 이행으로 계정 ${retiredByMigration}개의 활성 자격증명을 물렸다(슬롯 0) — 아래 자동 게시`); persist(); }
```

(자동 게시 조건 `if (state.registry.pendingSlots.length > 0 || …)` 은 pendingSlots 가 남으므로 그대로 걸린다.)

(e) `/mode3/health`: `buildAaHealth({ …, mirrors, attrSchema: schemaInfo(ATTR_SCHEMA, ATTR_SCHEMA_HASH) })`.

(f) 새 라우트 — `/cia/public_keys` 라우트 다음에:

```js
// 속성 스키마 공개(스펙 2 §5.2, 인증 없음). 지갑·RP 가 기동 때 받아 술어 타입·정책 이름을 해석하고, 화면이 이름값을 그린다.
app.get('/cia/attr_schema', (req, res) => res.json({ schema: ATTR_SCHEMA, hash: ATTR_SCHEMA_HASH }));
```

(g) `/cia/register`(495·497행): 계정 객체에 `attrs: [...acct.attrs], profile: { ...acct.profile },` 응답 `res.status(201).json({ slot, attrs: state.accounts[uid].attrs, profile: state.accounts[uid].profile, schemaHash: ATTR_SCHEMA_HASH });`

(h) `/cia/attrs`(559행): `res.json({ attrs: acct.attrs, profile: acct.profile ?? {}, schemaHash: ATTR_SCHEMA_HASH });`

(i) 관리자 속성 변경(581~604행)을 다음으로 교체:

```js
// 2026-09-22 §3.3 관리자가 속성을 바꾼다. 활성 자격증명은 옛 속성이라 물린다(슬롯 0 → 즉시 게시). 지갑은 다음 발급에서 재동기화한다.
// 스펙 2(2026-10-07): 본문은 { profile } — 스키마 이름 → 사람이 읽는 값. 인코딩은 encodeProfile(int·enum 키 필수 — 빈 객체 한 번으로
// 속성이 통째로 지워지던 A-I2 를 같은 선에서 막는다). 예전 { attrs:[…] } 는 400 use_profile.
app.post('/cia/accounts/:uid/attrs', requireAdmin, async (req, res) => {
  try {
    const uid = req.params.uid;
    const acct = state.accounts[uid];
    if (!isDec(uid) || !acct) return res.status(404).json({ error: 'unknown account' });
    if (req.body?.attrs !== undefined) return res.status(400).json({ error: 'use_profile', detail: '속성은 { profile: { 이름: 값 } } 로 보낸다(스펙 2)' });
    const profile = req.body?.profile;
    if (!profile || typeof profile !== 'object' || Array.isArray(profile)) return res.status(400).json({ error: 'bad_attr', slot: null, field: null, reason: 'profile_required' });
    let attrs;
    try { attrs = await encodeProfile(ATTR_SCHEMA, profile); }
    catch (e) { if (e.reason === 'bad_attr') return res.status(400).json({ error: 'bad_attr', slot: e.slot, field: e.field, reason: e.detail, detail: e.message }); throw e; }
    acct.profile = { ...profile };
    acct.attrs = attrs;
    const retired = retireActiveCred(uid);
    if (retired) setSlot(uid, 0n);   // 물린 게 없으면(활성 자격증명이 없었다) 슬롯은 건드리지 않는다
    persist();   // attrs·(물렸다면) 슬롯 변경을 게시 시도 전에 먼저 저장한다 — 게시 중 죽어도 다음 기동이 백로그를 본다
    const pub = retired ? await publishSafely() : { published: false };
    res.json({ uid, attrs, profile: acct.profile, retired, published: Boolean(pub.published) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
```

(`normalizeAttrs`·`ATTR_SLOTS` import 가 이 라우트 밖에서 쓰이지 않으면 25행 import 에서 지운다 — `grep -n "normalizeAttrs\|ATTR_SLOTS" cia.js` 로 확인.)

(j) `/cia/accounts`(1064행) 항목에 `profile: a.profile ?? {},` 추가.

- [ ] **Step 5: 통과 확인(unit → chain)**

```bash
node tests/test_mode3_health_shape.js
bash scripts/run_tests.sh unit
# :8545 가 비어 있으면 hardhat 노드를 띄운다(끝나면 종료)
node tests/test_cia_startup.mjs
node tests/test_cia_register_issue.mjs
node tests/test_cia_registry.mjs
node tests/test_mode3_wallet_agent.mjs      # 등록 응답 attrs 단언만 바뀐 상태 — 나머지는 Task 4 에서
```
Expected: 전부 `ok`(`test_mode3_wallet_agent.mjs` 는 `/wallet/status` 의 attrs 단언까지 통과).

- [ ] **Step 6: Commit (제안)**

```bash
git add cia.js lib/mode3_health.js tests/
git commit -m "feat(cia): 속성 스키마 공개(GET /cia/attr_schema)·계정 profile 정본·관리자 {profile}·v11 이행 뒤 자격증명 은퇴 — 데모 등급 제거에 맞춰 테스트 벡터 갱신"
```

---

### Task 4: 지갑 에이전트 — 스키마 캐시·`predicate_type`·profile 보관·`/wallet/attr_schema`

**Files:**
- Modify: `mode3_wallet_agent.js:24-30` (import), `:183-195` 근처(스키마 캐시), `:213-222` (`syncAttrsFromCia`), `:429-460` (`/wallet/status`), `:477-505` (`/wallet/register`), `:548-551` (`/wallet/login`), `:941-946` (`/wallet/request` 의 disclosure), 새 라우트 `GET /wallet/attr_schema`
- Modify: `lib/mode3_secret_source.js:12-16` (`stripSecrets`)
- Modify: `tests/test_mode3_secret_source.js:36-41`, `tests/test_mode3_wallet_agent.mjs` (새 케이스 2개), `tests/test_mode3_wallet_snap.mjs:60-68`

**Interfaces:**
- Consumes: `GET /cia/attr_schema`, `/cia/register`·`/cia/attrs` 응답의 `profile`·`schemaHash` (Task 3); `loadSchema`, `assertPredicateTypes`, `decodeAttrs`, `schemaInfo`, `DEFAULT_ATTR_SCHEMA` (Task 1).
- Produces(화면이 의존): `GET /wallet/attr_schema → { schema, hash, source: 'cia'|'default' }`; `/wallet/status` 에 `profile`, `attrSchema: {id, version, hash} | null`, `attrsView: decodeAttrs(...) | null`; `/wallet/register` 201 에 `profile`; `/wallet/login`·`/wallet/tx` 400 `{ reason:'predicate_type', detail }`.

- [ ] **Step 1: 테스트(실패하게)**

`tests/test_mode3_secret_source.js:38`: `['attrs', 'cm_u', 'pk_u', 'slot', 'uid', 'userCred']` → `['attrs', 'cm_u', 'pk_u', 'profile', 'slot', 'uid', 'userCred']`, 그리고 `assert.equal(stripSecrets(REG).profile, null, 'profile 이 없으면 null');` 추가.

`tests/test_mode3_wallet_agent.mjs` — 등록 케이스(66~78행) 안 `assert.deepEqual(r.body, { uid, slot: 0, attrs: [...] })` 를 다음으로:

```js
    assert.deepEqual(r.body, { uid, slot: 0, attrs: ['1990', '410', '0', '0', '0', '0'], profile: { birthYear: '1990', country: 'KR' } });
```
그리고 `/wallet/status` 단언 뒤에:

```js
    assert.deepEqual(s.body.profile, { birthYear: '1990', country: 'KR' });
    const sch = (await cia.get('/cia/attr_schema')).body;
    assert.deepEqual(s.body.attrSchema, { id: 'zkd-attrs', version: 1, hash: sch.hash });
    assert.deepEqual(s.body.attrsView.map((v) => v.display), ['1990', 'KR', '', '', '', '']);
    const ws = await wallet.get('/wallet/attr_schema');
    assert.equal(ws.status, 200); assert.equal(ws.body.hash, sch.hash); assert.equal(ws.body.source, 'cia');
```

같은 파일, `'V7 /wallet/tx: set 으로 …'` 케이스(607~623행) 바로 뒤에 새 케이스:

```js
  await t('스펙 2 predicate_type: 범위 술어를 enum 슬롯(1)에, 집합 술어를 unused 슬롯(4)에 걸면 /wallet/tx·/wallet/login 모두 400 predicate_type — 증명 전에 거른다', async () => {
    const to = '0x000000000000000000000000000000000000dEaD';
    const s = await loginOnce({ factoryAddress });
    const r1 = await wallet.post('/wallet/tx', { r_s: s.r_s, to, disclose: [null, { lo: '410', hi: '410' }, null, null, null, null] }, { Origin: stack.rpOriginForWallet });
    assert.equal(r1.status, 400, j(r1.body)); assert.equal(r1.body.reason, 'predicate_type'); assert.match(r1.body.detail, /슬롯 1/);
    const r2 = await wallet.post('/wallet/tx', { r_s: s.r_s, to, set: { slot: 4, members: [0] } }, { Origin: stack.rpOriginForWallet });
    assert.equal(r2.status, 400, j(r2.body)); assert.equal(r2.body.reason, 'predicate_type');
    const r3 = await loginNoRelay(newRs(), { disclose: [null, { lo: '410', hi: '410' }] });
    assert.equal(r3.status, 400, j(r3.body)); assert.equal(r3.body.reason, 'predicate_type');
    // string 슬롯(2)의 집합 술어는 허용된다 — 내 값(0)이 집합에 없으면 그다음 단계의 disclosure_unsatisfiable
    const r4 = await wallet.post('/wallet/tx', { r_s: s.r_s, to, set: { slot: 2, members: [7] } }, { Origin: stack.rpOriginForWallet });
    assert.equal(r4.status, 400, j(r4.body)); assert.equal(r4.body.reason, 'disclosure_unsatisfiable');
  });
```

그리고 같은 파일 581~603행 케이스의 `const ok = await wallet.post('/wallet/tx', { …, disclose: [{ lo: '0', hi: '2007' }, { lo: '410', hi: '410' }, null, null] }` 은 슬롯 1 범위라 이제 `predicate_type` 이 된다 → `disclose: [{ lo: '0', hi: '2007' }, null, null, null]` 로 바꾸고 그 아래 단언을 `mask '1'`, `lo ['0','0','0','0','0','0']`, `hi ['2007','0','0','0','0','0']` 로. 같은 케이스 끝의 `six`(슬롯 2 범위 `{lo:'3',hi:'3'}`)도 string 슬롯 범위라 `predicate_type` → 그 블록을 다음으로 교체:

```js
    // V9: disclose 는 길이 1..6 — 6칸을 다 채운 요청도 받는다(범위는 int 슬롯만 — 슬롯 0 을 6칸 배열의 첫 칸에).
    const six = await wallet.post('/wallet/tx', { r_s: s.r_s, to, disclose: [{ lo: '1990', hi: '1990' }, null, null, null, null, null] }, { Origin: stack.rpOriginForWallet });
    assert.equal(six.status, 200, j(six.body));
    assert.equal(six.body.disclosure.mask, '1');
    assert.equal(six.body.onchainDisclosure.mask, '1');
    assert.deepEqual(six.body.onchainDisclosure.lo, ['1990', '0', '0', '0', '0', '0']);
    assert.deepEqual(six.body.onchainDisclosure.hi, ['1990', '0', '0', '0', '0', '0']);
```

`tests/test_mode3_wallet_snap.mjs:60` 옆에 `assert.deepEqual(r.body.profile, { birthYear: '1990', country: 'KR' });`, 68행의 상태 단언 뒤 `assert.deepEqual(s.profile, { birthYear: '1990', country: 'KR' });`.

Run: `node tests/test_mode3_secret_source.js` → FAIL(키 목록). (chain 테스트는 Step 3 뒤에.)

- [ ] **Step 2: `lib/mode3_secret_source.js` `stripSecrets`**

```js
export function stripSecrets(registration) {
  if (!registration) return null;
  const { uid, cm_u, pk_u, slot, attrs, profile = null, userCred } = registration;
  return { uid, cm_u, pk_u, slot, attrs, profile, userCred: userCred ? { Cf_u: userCred.Cf_u, issuedAt: userCred.issuedAt } : null };
}
```

Run: `node tests/test_mode3_secret_source.js` → ok.

- [ ] **Step 3: `mode3_wallet_agent.js` 구현**

(a) import: `import { DEFAULT_ATTR_SCHEMA, loadSchema, assertPredicateTypes, decodeAttrs, schemaInfo } from './lib/mode3_attr_schema.js';`

(b) `pkCia()` 정의 다음에:

```js
// 속성 스키마(스펙 2 §5.3): IdP 가 공개하는 것을 받아 둔다. 못 받으면 공유 모듈의 기본 스키마로 간다(경고) — 술어 타입 검사는
// 기본 스키마 기준이 되고, IdP 가 다른 스키마를 쓰면 응답의 schemaHash 불일치 경고로 드러난다. 기본 스키마인 동안은 호출마다 다시 받아 본다.
let attrSchema = null;   // { schema, hash, source: 'cia' | 'default' }
async function fetchAttrSchema() {
  try {
    const r = await fetch(`${CIA_URL}/cia/attr_schema`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const b = await r.json();
    const { schema, hash } = loadSchema(b.schema);
    if (b.hash && b.hash !== hash) console.warn(`[wallet] IdP 가 알린 스키마 해시(${b.hash})와 계산값(${hash})이 다르다 — 계산값을 쓴다`);
    attrSchema = { schema, hash, source: 'cia' };
  } catch (e) {
    if (!attrSchema) { attrSchema = { ...loadSchema(DEFAULT_ATTR_SCHEMA), source: 'default' }; console.warn(`[wallet] 속성 스키마를 IdP 에서 받지 못해 기본 스키마를 쓴다: ${e.message}`); }
  }
  return attrSchema;
}
/** 보관 스키마. hashHint(IdP 응답의 schemaHash)가 다르면 다시 받고, 그래도 다르면 경고만(스펙 §7 — 지갑은 IdP 를 바꿀 수 없다). */
async function schemaFor(hashHint = null) {
  if (!attrSchema || attrSchema.source === 'default' || (hashHint && hashHint !== attrSchema.hash)) await fetchAttrSchema();
  if (hashHint && attrSchema.hash !== hashHint) console.warn(`[wallet] IdP 응답의 schemaHash(${hashHint})가 보관 스키마(${attrSchema.hash})와 다르다`);
  return attrSchema;
}
fetchAttrSchema();   // 기동 때 한 번(실패는 안에서 경고로 삼킨다 — 기동을 막지 않는다)
```

(c) `syncAttrsFromCia`(213~222행): `const attrs = …` 다음에

```js
  if (r.body.profile && typeof r.body.profile === 'object') state.registration.profile = r.body.profile;   // 표시용(스펙 2) — 증명은 attrs 만 쓴다
  await schemaFor(r.body.schemaHash ?? null);
```

(d) `/wallet/register`(492~501행): `const attrs = …` 다음 `const profile = r.body.profile && typeof r.body.profile === 'object' ? r.body.profile : null;` 두 `state.registration = …` 객체에 `profile,` 추가(snap 모드는 `stripSecrets({ …, attrs, profile, userCred: null })`), 두 응답 `res.status(201).json({ uid, slot: r.body.slot, attrs, profile })`. 그 앞에 `await schemaFor(r.body.schemaHash ?? null);`.

(e) `/wallet/login`(548~551행) — `if (disclose || set) {` 블록 첫 줄에:

```js
      try { assertPredicateTypes((await schemaFor()).schema, disclose, set); }
      catch (e) { if (e.reason === 'predicate_type') return res.status(400).json({ reason: 'predicate_type', detail: e.message }); throw e; }
```

(f) `/wallet/request`(941~946행) — `let disclosure; try {` 블록 안, `const attrs = …` 앞에:

```js
    try { assertPredicateTypes((await schemaFor()).schema, disclose, set); }
    catch (e) { if (e.reason === 'predicate_type') return fail(400, { reason: 'predicate_type', detail: e.message }); throw e; }
```

(g) `/wallet/status`(453행 응답): `registered: …, attrs: reg?.attrs ?? null,` 뒤에

```js
    profile: reg?.profile ?? null, attrSchema: attrSchema ? schemaInfo(attrSchema.schema, attrSchema.hash) : null,
    attrsView: reg && attrSchema ? decodeAttrs(attrSchema.schema, reg.attrs, reg.profile ?? null) : null,
```

(h) 새 라우트(`/wallet/status` 다음):

```js
// 지갑 페이지(같은 오리진)가 이름 ↔ 코드를 바꾸는 데 쓰는 전체 스키마(스펙 2 §5.6). 에이전트가 IdP 에서 받아 보관한 것.
app.get('/wallet/attr_schema', async (req, res) => { const s = await schemaFor(); res.json({ schema: s.schema, hash: s.hash, source: s.source }); });
```

- [ ] **Step 4: 통과 확인**

```bash
node tests/test_mode3_secret_source.js
node tests/test_mode3_wallet_agent.mjs
node tests/test_mode3_wallet_snap.mjs
```
Expected: 전부 `ok`.

- [ ] **Step 5: Commit (제안)**

```bash
git add mode3_wallet_agent.js lib/mode3_secret_source.js tests/test_mode3_secret_source.js tests/test_mode3_wallet_agent.mjs tests/test_mode3_wallet_snap.mjs
git commit -m "feat(wallet): 속성 스키마 수신·predicate_type 검사·profile 보관·/wallet/attr_schema — 범위 술어는 int 슬롯만"
```

---

### Task 5: RP — 국가 이름 정책·슬롯 번호 조회·AttrGate 가드·`predicate_unavailable`

**Files:**
- Modify: `mode3_rp.js:20-21` (import), `:54` 다음(스키마 수신), `:131-136` (정책 파싱), `:212-219` (`ensureAttrGate`), `:305` (`currentPredicates`), `:349-352` (술어 검사)
- Modify: `mode3/common/strings.js:423` 근처(사유 `predicate_unavailable`), `tests/test_mode3_demo_strings.js:21-24` (REASONS 에 추가)
- Modify: `tests/test_mode3_demo_full.mjs:6,41,108`, `tests/test_mode3_demo_stack.mjs:110-121`

**Interfaces:**
- Consumes: `GET /cia/attr_schema` (Task 3); `loadSchema`, `slotIndexOf`, `encodeMembers`, `schemaInfo`, `DEFAULT_ATTR_SCHEMA` (Task 1).
- Produces: `rp_info.predicates` 에 `allowedCountryNames: string[]`, `attrSchema: {id, version, hash}` 추가(숫자 필드 그대로); 로그인 `reason:'predicate_unavailable'`; env `MODE3_ALLOWED_COUNTRIES` 가 이름·코드 혼용 허용.

- [ ] **Step 1: 테스트(실패하게)**

`tests/test_mode3_demo_stack.mjs` rp_info 케이스(110~121행) 끝에:

```js
    assert.deepEqual(r.body.predicates.allowedCountries, ['410', '392', '840', '276', '250']);
    assert.deepEqual(r.body.predicates.allowedCountryNames, ['KR', 'JP', 'US', 'DE', 'FR'], '스펙 2: 기본 정책을 이름으로도 낸다');
    assert.deepEqual(r.body.predicates.attrSchema, { id: 'zkd-attrs', version: 1, hash: (await cia.get('/cia/attr_schema')).body.hash });
```

`tests/test_mode3_demo_full.mjs:41`: `MODE3_ALLOWED_COUNTRIES: '410,392'` → `'KR,JP'`(6행 주석 `허용 국가 410·392` → `허용 국가 KR·JP(=410·392)`, `속성 1990/410/2` → `1990/410`). 108행 뒤에:

```js
    assert.deepEqual(x.predicates.allowedCountryNames, ['KR', 'JP'], 'MODE3_ALLOWED_COUNTRIES=KR,JP 가 410,392 와 같은 정책이 된다');
```

`tests/test_mode3_demo_strings.js` REASONS 배열의 `'predicate_unmet'` 뒤에 `'predicate_unavailable'` 추가.

Run: `node tests/test_mode3_demo_strings.js` → FAIL(사유 없음). (chain 테스트는 Step 3 뒤.)

- [ ] **Step 2: `strings.js` 사유 추가** — `predicate_unmet:` 줄 바로 아래:

```js
    predicate_unavailable: { where: 'rp', ko: { title: '서비스가 이 조건을 요구할 수 없습니다', cause: '서비스가 받은 속성 스키마에 국가(country) 또는 출생연도(birthYear) 슬롯이 없어 그 조건을 검사할 수 없습니다.', action: '로그인 화면에서 요구 조건을 끄거나, 신원 기관의 속성 스키마를 확인하세요.' }, en: { title: 'The service cannot require this condition', cause: 'The attribute schema the service received has no country or birthYear slot, so the condition cannot be checked.', action: 'Turn the requirement off on the login form, or check the identity authority\'s attribute schema.' } },
```

Run: `node tests/test_mode3_demo_strings.js` → ok.

- [ ] **Step 3: `mode3_rp.js` 구현**

(a) import: `import { DEFAULT_ATTR_SCHEMA, loadSchema, slotIndexOf, encodeMembers, schemaInfo } from './lib/mode3_attr_schema.js';`

(b) `const pkCIA = await resolvePkCia();` 다음에:

```js
// 속성 스키마(스펙 2 §5.4): CIA 가 공개하는 것을 기동 때 한 번 받는다(pk_CIA 와 같은 TOFU 성격). 못 받으면 공유 모듈 기본 스키마 + 경고.
async function resolveAttrSchema() {
  try {
    const r = await fetch(`${CIA_URL}/cia/attr_schema`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const b = await r.json();
    return { ...loadSchema(b.schema), source: 'cia' };
  } catch (e) {
    console.warn(`[rp] 속성 스키마를 CIA 에서 받지 못해 기본 스키마를 쓴다: ${e.message}`);
    return { ...loadSchema(DEFAULT_ATTR_SCHEMA), source: 'default' };
  }
}
const ATTR_SCHEMA = await resolveAttrSchema();
const COUNTRY_SLOT = slotIndexOf(ATTR_SCHEMA.schema, 'country');     // -1 이면 국가 술어를 요구할 수 없다(predicate_unavailable)
const BIRTH_SLOT = slotIndexOf(ATTR_SCHEMA.schema, 'birthYear');
```

(c) 정책 파싱(132~133행)을 교체:

```js
// V7 술어 정책(설계 2026-09-23 §4.3·§6): AttrGate 배포와 오프체인 로그인 정책이 같은 값을 쓴다.
// 스펙 2: MODE3_ALLOWED_COUNTRIES 는 이름(KR,JP)과 코드(410,392)를 모두 받아 country 슬롯의 인코더로 바꾼다. 표에 없으면 기동 실패.
const ALLOWED_COUNTRY_TOKENS = (process.env.MODE3_ALLOWED_COUNTRIES ?? '').split(',').map((s) => s.trim()).filter(Boolean);
let ALLOWED_COUNTRIES = [];
if (ALLOWED_COUNTRY_TOKENS.length) {
  if (COUNTRY_SLOT < 0) { console.error('[rp] 속성 스키마에 country 슬롯이 없어 MODE3_ALLOWED_COUNTRIES 를 해석할 수 없다'); process.exit(1); }
  try { ALLOWED_COUNTRIES = await encodeMembers(ATTR_SCHEMA.schema, COUNTRY_SLOT, ALLOWED_COUNTRY_TOKENS); }
  catch (e) { console.error(`[rp] MODE3_ALLOWED_COUNTRIES 해석 실패: ${e.message}`); process.exit(1); }
}
const ALLOWED_COUNTRIES_EFFECTIVE = ALLOWED_COUNTRIES.length ? ALLOWED_COUNTRIES : [...ALLOWED_COUNTRIES_DEFAULT];
const countryName = (code) => { const s = COUNTRY_SLOT >= 0 ? ATTR_SCHEMA.schema.slots[COUNTRY_SLOT] : null; const hit = s ? Object.entries(s.values).find(([, c]) => BigInt(c) === code) : null; return hit ? hit[0] : `#${code}`; };
const ALLOWED_COUNTRY_NAMES = ALLOWED_COUNTRIES_EFFECTIVE.map(countryName);
```

(d) `ensureAttrGate` 첫 줄(팩토리 검사 앞)에:

```js
  // AttrGate(불변)는 "출생연도 = 슬롯 0, 국가 = set_sel 2(슬롯 1)" 을 코드에 박고 있다(스펙 2 §3.2) — 스키마가 다르면 배포하지 않는다.
  if (BIRTH_SLOT !== 0 || COUNTRY_SLOT !== 1) { console.warn(`[rp] 속성 스키마의 birthYear(${BIRTH_SLOT})·country(${COUNTRY_SLOT}) 슬롯이 AttrGate 의 전제(0·1)와 달라 AttrGate 배포를 건너뛴다`); return; }
```

(e) `currentPredicates`:

```js
const currentPredicates = () => ({ allowedCountries: ALLOWED_COUNTRIES_EFFECTIVE.map(String), allowedCountryNames: ALLOWED_COUNTRY_NAMES, allowedCountriesRoot: ALLOWED_COUNTRIES_ROOT.toString(), minAge: MIN_AGE.toString(), attrSchema: schemaInfo(ATTR_SCHEMA.schema, ATTR_SCHEMA.hash) });
```

(f) 술어 검사(349~352행):

```js
    if (requireP) {
      const d = v.disclosure;
      // 슬롯 번호는 스키마에서 찾는다(스펙 2 §5.4). 슬롯이 없으면 그 조건은 요구할 수 없다 — predicate_unavailable.
      if (requireP.countrySet) {
        if (COUNTRY_SLOT < 0) return res.json({ ok: false, reason: 'predicate_unavailable' });
        if (!(d.sel === BigInt(COUNTRY_SLOT) + 1n && d.root === ALLOWED_COUNTRIES_ROOT)) return res.json({ ok: false, reason: 'predicate_unmet' });
      }
      if (requireP.minAge) {
        if (BIRTH_SLOT < 0) return res.json({ ok: false, reason: 'predicate_unavailable' });
        if (!(((d.mask >> BigInt(BIRTH_SLOT)) & 1n) === 1n && d.hi[BIRTH_SLOT] + MIN_AGE <= BigInt(new Date().getUTCFullYear()))) return res.json({ ok: false, reason: 'predicate_unmet' });
      }
    }
```

(g) AttrGate 배포 로그(218행)의 `국가∈{${ALLOWED_COUNTRIES_EFFECTIVE.join(',')}}` → `국가∈{${ALLOWED_COUNTRY_NAMES.join(',')}}`.

- [ ] **Step 4: 통과 확인**

```bash
node tests/test_mode3_demo_strings.js
node tests/test_mode3_demo_stack.mjs
node tests/test_mode3_demo_full.mjs      # 두 체인(:8546)이 필요하면 그 테스트의 머리말대로 — 없으면 BLOCKED 사유만 보고
```
Expected: `ok`.

- [ ] **Step 5: Commit (제안)**

```bash
git add mode3_rp.js mode3/common/strings.js tests/test_mode3_demo_strings.js tests/test_mode3_demo_stack.mjs tests/test_mode3_demo_full.mjs
git commit -m "feat(rp): MODE3_ALLOWED_COUNTRIES 이름 해석·슬롯 번호 스키마 조회·AttrGate 가드·predicate_unavailable"
```

---

### Task 6: 화면·Snap·용어 — 이름값으로 그린다

**Files:**
- Modify: `snap-mode3/src/index.js:21`
- Modify: `mode3/common/strings.js:261, 377-382` (`admin_col_attrs`, `attr2..attr5`)
- Modify: `mode3/cia_admin.html:39, 276-283, 353-357`
- Modify: `mode3/wallet.html:40-45, 84-99, 106-115, 216, 455-458, 750-752` + 스키마 수신·폼 적용 함수
- Modify: `mode3/rp.html:158`
- Test: `node tests/test_mode3_demo_strings.js`, `bash scripts/run_tests.sh snap`, `bash scripts/run_tests.sh browser`

**Interfaces:**
- Consumes: `GET /cia/attr_schema`(관리자 페이지, 같은 오리진), `GET /wallet/attr_schema`·`/wallet/status.attrsView`(지갑 페이지), `rp_info.predicates.allowedCountryNames`(RP 페이지), `POST /cia/accounts/:uid/attrs { profile }`.
- Produces: 없음(화면만).

- [ ] **Step 1: Snap 이름표**

`snap-mode3/src/index.js:21`:

```js
const SLOT_LABELS = ['출생연도', '국가', '예비 1', '예비 2', '미사용', '미사용'];      // a₀..a₅ — 기본 스키마 zkd-attrs v1(스펙 2, 2026-10-07). 스키마를 RPC 로 받는 것은 비범위(§10)
```

Run: `bash scripts/run_tests.sh snap` → ok(`snap-mode3/node_modules` 없으면 그 사실만 보고).

- [ ] **Step 2: `strings.js` 용어**

```js
    admin_col_attrs: { ko: '속성(출생연도 · 국가 · 예비 1 · 예비 2)', en: 'Attributes (birth year · country · spare 1 · spare 2)' },
```
```js
    attr2: { ko: '예비 1', en: 'Spare 1', expert: 'attrs[2] (a₃), string → 64-bit Poseidon' },
    attr3: { ko: '예비 2', en: 'Spare 2', expert: 'attrs[3] (a₄), string → 64-bit Poseidon' },
    attr4: { ko: '미사용', en: 'Unused', expert: 'attrs[4] (a₅), always 0' },
    attr5: { ko: '미사용', en: 'Unused', expert: 'attrs[5] (a₆), always 0' },
```
`attr1.expert` 를 `'attrs[1] (a₂), enum → ISO 3166-1 numeric'` 로.

Run: `node tests/test_mode3_demo_strings.js` → ok.

- [ ] **Step 3: 관리자 페이지 `mode3/cia_admin.html`**

39행 문구를 `속성을 바꾸면(출생연도·국가·예비 문자열) 활성 자격증명이 물리고 등록부 슬롯이 0 으로 즉시 게시됩니다 — 지갑은 다음 발급에서 다시 받습니다.` 로(strings.js `admin_accounts_attrs_note` 의 ko·en 도 같은 뜻으로).

`let accounts = null;`(109행) 옆에 `let attrSchema = null;   // GET /cia/attr_schema 의 schema(인증 없음)` 와 함수:

```js
    async function loadAttrSchema() {
      if (attrSchema) return attrSchema;
      try { attrSchema = (await (await fetch('/cia/attr_schema')).json()).schema; } catch { attrSchema = null; }
      return attrSchema;
    }
```

`loadAccounts()`(330행) 안에서 `/cia/accounts` 호출 전에 `await loadAttrSchema();`.

276~283행(입력 생성·셀)을 교체:

```js
        // 스펙 2: 슬롯마다 스키마 타입대로 그린다 — int 숫자 입력, enum 선택 목록(이름), string 글자 입력, unused 는 숨김. 저장은 { profile }.
        const fields = [];
        (attrSchema?.slots ?? []).forEach((slot, i) => {
          if (slot.type === 'unused') return;
          let input;
          if (slot.type === 'enum') {
            input = document.createElement('select');
            const none = document.createElement('option'); none.value = ''; none.textContent = '—'; input.appendChild(none);
            for (const name of Object.keys(slot.values)) { const o = document.createElement('option'); o.value = name; o.textContent = name; input.appendChild(o); }
          } else {
            input = document.createElement('input'); input.size = slot.type === 'int' ? 6 : 10;
          }
          input.value = a.profile?.[slot.name] ?? '';
          input.title = `${slot.label ?? slot.name} (${slot.name})`;
          fields.push({ name: slot.name, input });
        });
        const attrCell = row.insertCell();
        if (!fields.length) attrCell.textContent = (a.attrs ?? []).join(' ');   // 스키마를 못 받았으면 인코딩값만 보인다(저장 불가)
        fields.forEach(({ input }, i) => { if (i > 0) attrCell.appendChild(document.createTextNode(' ')); attrCell.appendChild(input); });
        const act = row.insertCell();
        act.appendChild(button('admin_save_btn', 'btn-ghost', () => saveAttrs(a.uid, Object.fromEntries(fields.map(({ name, input }) => [name, input.value.trim()])))));
```
(기존 `const act = row.insertCell(); act.appendChild(button('admin_save_btn', …, () => saveAttrs(a.uid, inputs.map(…))))` 두 줄은 위 코드가 대신한다 — 중복이 남지 않게 지운다.)

353~357행:

```js
    function saveAttrs(uid, profile) {
      run('admin_attrs_failed', () => call('POST', `/cia/accounts/${uid}/attrs`, { profile }), ({ body }) => {
        const shown = Object.entries(profile).filter(([, v]) => v !== '').map(([k, v]) => `${k}=${v}`).join(', ') || '—';
        setVerdict($('adminVerdict'), true, 'admin_attrs_title', () => ({ summary: Demo.t('admin_attrs_summary', { uid, attrs: shown }), detail: safeDetail(body) }));
        loadAccounts(); loadState();
      });
    }
```

- [ ] **Step 4: 지갑 페이지 `mode3/wallet.html`**

(a) 40~45행 이름표: `등급` → `예비 1`, `예비` → `예비 2`, `속성 5`·`속성 6` → `미사용`(90~99행 체크박스 라벨, 108~113행 select 옵션도 같은 글자). 115행 `setMembers` 기본값 `value="KR,JP,US,DE,FR"`.

(b) 상태 변수(182행 근처)에 `let attrSchema = null;   // GET /wallet/attr_schema — 이름 ↔ 코드, 슬롯 타입(스펙 2)` 와 함수들:

```js
    /** 에이전트가 IdP 에서 받아 둔 스키마. 슬롯 타입에 따라 폼을 맞춘다 — 범위 체크박스는 int 슬롯만, unused 행은 숨긴다. */
    async function loadAttrSchema() {
      try { attrSchema = (await (await fetch('/wallet/attr_schema')).json()).schema; } catch { attrSchema = null; }
      if (!attrSchema) return;
      attrSchema.slots.forEach((slot, k) => {
        const row = $('dk' + k).closest('div');
        if (slot.type === 'unused') { row.hidden = true; $('attr' + k).closest('dd').previousElementSibling.hidden = true; $('attr' + k).closest('dd').hidden = true; $('setSlot').querySelector(`option[value="${k}"]`).hidden = true; return; }
        if (slot.type !== 'int') { $('dk' + k).disabled = true; $('dk' + k).title = '범위 조건은 정수 속성에만 쓸 수 있습니다'; }
      });
    }
    /** 집합 원소를 이름으로 적었으면 코드로(enum 슬롯). 그 밖은 그대로 — 지갑 에이전트가 형식을 검사한다. */
    function encodeMember(slot, token) {
      const s = attrSchema?.slots?.[slot];
      if (s?.type === 'enum' && Object.prototype.hasOwnProperty.call(s.values, token)) return String(s.values[token]);
      return token;
    }
    const profileText = (profile) => Object.entries(profile ?? {}).filter(([, v]) => v !== '').map(([k, v]) => `${k}=${v}`).join(', ');
```
페이지 초기화(기존 `renderIdentity`/status 폴링을 시작하는 곳) 앞에 `await loadAttrSchema();`(또는 `loadAttrSchema().then(…)`) 한 번.

(c) 216행 `attrsText` 는 그대로 두고, 등록(701행)·재동기화(727~728행) 요약에서 `attrsText(attrs)` → `b.profile ? profileText(b.profile) : attrsText(attrs)`.

(d) `renderIdentity`(455~458행): `for (let k = 0; k < 6; k++) $('attr' + k).value = s?.attrsView?.[k]?.display ?? (lastAttrs ? lastAttrs[k] : '');`

(e) `readSet`(752행): `members: $('setMembers').value.split(',').map((x) => x.trim()).filter(Boolean).map((x) => encodeMember(Number(s), x))`.

- [ ] **Step 5: RP 페이지 `mode3/rp.html:158`**

```js
      if (info.attrGateAddress) tte($('attrGateInfo'), 'rp_policy', { countries: (info.predicates.allowedCountryNames ?? info.predicates.allowedCountries).join(', '), minAge: info.predicates.minAge });
```

- [ ] **Step 6: 확인**

```bash
node tests/test_mode3_demo_strings.js
bash scripts/run_tests.sh browser     # Chrome 필요 — 지갑·RP·관리자 페이지 각본(속성 변경 → 재로그인 포함)
```
Expected: ok. browser 그룹이 `BLOCKED:` 면 그 사실을 보고하고, 대신 세 페이지를 수동 점검 항목으로 남긴다(관리자 표에 enum 선택 목록, 지갑 "내 신원" 에 `KR`, RP 정책 문구 `국가 ∈ {KR, JP, …}`).

- [ ] **Step 7: Commit (제안)**

```bash
git add snap-mode3/src/index.js mode3/common/strings.js mode3/cia_admin.html mode3/wallet.html mode3/rp.html
git commit -m "feat(mode3-ui): 속성을 이름값으로 — 관리자 타입별 입력({profile}), 지갑 attrsView·집합 이름 입력, RP 정책 이름, Snap 이름표"
```

---

### Task 7: 문서·픽스처 주석·전체 회귀

**Files:**
- Modify: `docs/MODE3_DEMO.md:169, 437, 518-530, 574, 717, 721, 724, 747-751`
- Modify: `docs/superpowers/specs/2026-10-01-mode3-v9-registry-design.md:210`
- Modify: `tests/helpers/mode3_fixture.mjs:12` (주석만), `scripts/bench_zkp_inventory.mjs:57` (주석만)

- [ ] **Step 1: `docs/MODE3_DEMO.md`**

(a) 169행 env 표의 `MODE3_ALLOWED_COUNTRIES` 설명: `쉼표 구분 ISO 3166 numeric, 기본 410,392,840,276,250` → `쉼표 구분 — 국가 이름(KR,JP) 또는 ISO 3166 numeric(410,392), 스키마 표에 없으면 기동 실패, 기본 410,392,840,276,250(= KR,JP,US,DE,FR)`.

(b) 437·574·717행의 `[1990, 410, 2, 0, 0, 0]` → `[1990, 410, 0, 0, 0, 0]`(지갑 화면에는 `출생연도 1990 · 국가 KR` 로 보인다는 말을 덧붙인다). 721행 S6 의 `슬롯 1 [410, 410] 공개` → `집합 소속 조건=국가, 허용 원소 KR,JP,US,DE,FR`(범위 술어는 정수 슬롯에만 — `predicate_type`). 724행 S8′ 의 `a₂ 를 3 으로 변경` → `예비 1(extra1) 에 문자열(예: tier3) 입력` 과 결과 `[1990, 410, 3, 0, 0, 0]` → `[1990, 410, <64비트 해시>, 0, 0, 0]`.

(c) 518~530행 "속성과 선택 공개" 절의 첫 두 단락을 교체:

```markdown
**속성 출처와 스키마(스펙 2, 2026-10-07).** 속성은 **AA(`cia.js`) 계정 기록**이고 관리자만 바꾼다. 정본은 사람이 읽는 `profile`(스키마 이름 → 값)이고,
회로·서명·Snap 이 쓰는 `attrs`(10진 문자열 6개)는 **공개 스키마**가 정한 규칙으로 인코딩한 값이다. 기본 스키마 `zkd-attrs` v1:
`a₀ birthYear`(int 1900~2100, 범위 술어 가능), `a₁ country`(enum — ISO 3166-1 숫자 코드: KR 410, JP 392, US 840, DE 276, FR 250, GB 826, CN 156,
CA 124, AU 36, SG 702), `a₂ extra1`·`a₃ extra2`(string — NFC·UTF-8 을 Poseidon 으로 64비트(1 ≤ v < 2^64)로 줄인 값, 일방향이라 화면은 `profile` 원문을 보인다),
`a₄`·`a₅` 미사용(항상 0). 범위 술어는 int 슬롯에만, 집합 술어는 int·enum·string 슬롯에만 걸 수 있다 — 어기면 지갑이 400 `predicate_type`.
스키마와 해시는 `GET /cia/attr_schema`(인증 없음)로 공개되고 `/mode3/health.attrSchema`·`/wallet/status.attrSchema`·`rp_info.predicates.attrSchema` 에 id·version·hash 가 실린다.
IdP 는 `CIA_ATTR_SCHEMA_FILE`(JSON)로 다른 스키마를 쓸 수 있다(검증 실패는 기동 거부). 데모 계정: `testuser`(uid 12345) `{birthYear: 1990, country: KR}` → `[1990, 410, 0, 0, 0, 0]`,
`alice`(uid 67890) `{birthYear: 2005, country: US}` → `[2005, 840, 0, 0, 0, 0]`. 슬롯 하나는 **64비트**(`[0, 2^64)`, 회로 `Num2Bits(64)`·`LessEqThan(64)`) 범위다 — `lib/mode3_credential.js` 의 `ATTR_MAX`.

**관리자 속성 변경.** CIA 관리자 페이지(또는 `POST /cia/accounts/:uid/attrs` 본문 `{ profile: { birthYear, country, extra1?, extra2? } }`, `requireAdmin`)에서
속성을 바꾸면 그 계정의 **활성 C_u 가 물린다**(등록부 슬롯 0 → 즉시 게시). 인코딩 실패(표에 없는 국가, 범위 밖 연도, 124바이트 넘는 문자열)는
400 `bad_attr`(슬롯·이유), 예전 `{ attrs: [...] }` 형식은 400 `use_profile`. `GET /cia/accounts` 로 전 계정의 `profile`·`attrs`·`disabled`·`activeCf_u` 를 볼 수 있다.
**상태 파일 v11 이행**: 옛 `attrs` 에서 `profile` 을 되살리되 새 스키마로 표현할 수 없는 값(옛 등급 슬롯 2, 예비 슬롯의 0 아닌 값, 표에 없는 국가 코드)은 버리고,
그래서 `attrs` 가 바뀐 계정은 기동이 활성 자격증명을 물려 슬롯 0 을 자동 게시한다 — 지갑은 다음 로그인에서 재동기화로 새 C_u 를 받는다(기동 전 상태 파일 백업 권장).
```

(이어지는 "시각 상관 주의사항" 문장은 그대로 둔다.)

(d) 751행 API 표의 `disclose`: `{lo,hi}\|null × 4` → `{lo,hi}\|null × 1..6(int 슬롯만)`; `POST /cia/accounts/:uid/attrs` 행 설명을 `속성 변경({profile}) — 활성 C_u 를 물린다(슬롯 0 즉시 게시)` 로; 표에 `GET /cia/attr_schema | CIA | 속성 스키마·해시(인증 없음)` 와 `GET /wallet/attr_schema | 지갑 | 에이전트가 보관한 스키마(페이지용)` 두 행 추가.

(e) RP 거절 사유 절(`predicate_unmet` 가 있는 표)에 `predicate_unavailable` 한 행: `서비스의 스키마에 country/birthYear 슬롯이 없어 요구 조건을 검사할 수 없다 — 요구를 끄거나 스키마를 확인`.

- [ ] **Step 2: V9 스펙 §13(210행)**

```markdown
- 스펙 2: 속성 매핑 계층 — **`2026-10-07-mode3-attr-schema-design.md` 로 확정·구현**(스키마 `GET /cia/attr_schema`, 인코더 `lib/mode3_attr_schema.js`, 화면의 이름값, RP 정책의 이름 표현).
```

- [ ] **Step 3: 픽스처·벤치 주석**

`tests/helpers/mode3_fixture.mjs:12` 주석: `// 회로 입력 벡터(스키마와 무관 — 스펙 2 §9). 값 2 는 옛 데모 등급이지만 회로·벤치 입력은 바꾸지 않는다(재현성).` `scripts/bench_zkp_inventory.mjs:57` 주석도 같은 뜻으로(값은 그대로).

- [ ] **Step 4: 전체 회귀**

```bash
npm test                               # unit + circuit
bash scripts/run_tests.sh contract
bash scripts/run_tests.sh chain        # :8545 필요 — 내가 띄웠으면 끝나고 종료
bash scripts/run_tests.sh browser      # Chrome 없으면 BLOCKED 보고
bash scripts/run_tests.sh snap
node tests/test_mode3_demo_full.mjs    # 전 구간(두 체인) — 거래소 정책 KR,JP
```
Expected: 전부 통과. 실패하면 그 출력과 함께 멈춘다(스펙 §9 "마지막에 demo_full").

- [ ] **Step 5: Commit (제안)**

```bash
git add docs/MODE3_DEMO.md docs/superpowers/specs/2026-10-01-mode3-v9-registry-design.md tests/helpers/mode3_fixture.mjs scripts/bench_zkp_inventory.mjs
git commit -m "docs(mode3): 속성 스키마·profile·predicate_type·국가 이름 정책 — 런북·API 표·V9 스펙 §13"
```

---

## 자체 점검 기록

- **스펙 대조**: D1 → Task 1(`loadSchema`·`CIA_ATTR_SCHEMA_FILE` Task 3), D2 → 기본 스키마 코드표(Task 1), D3 → 회로 미변경·a₄·a₅ unused, D4 → DEMO `profile`(Task 3)·이행(Task 2), D5 → 공유 모듈 + `/cia/attr_schema`(Task 3). §4 인코딩 → Task 1 테스트가 규칙마다 한 케이스. §5.2 → Task 3, §5.3 → Task 4, §5.4 → Task 5, §5.5·§5.6 → Task 6, §5.7 → Task 7. §6 이행 → Task 2 + Task 3 기동 경로(+ 기동 테스트). §7 오류표 → `bad_attr`/`use_profile`(Task 3), `predicate_type`(Task 4), 기동 실패·`predicate_unavailable`(Task 5), 스키마 해시 불일치 경고(Task 4 `schemaFor`). §9 테스트 → 각 Task 의 테스트 + Task 7 회귀.
- **스펙과 다른 결정(룰링)**: (1) `encodeProfile` 은 int·enum 슬롯 이름의 **키가 있어야** 한다(값은 빈 문자열 가능) — 빈 객체 한 번으로 속성이 통째로 지워지던 A-I2 를 같은 선에서 막는다. (2) `/wallet/status` 에 `attrsView`(디코드 결과)를 더해 페이지가 디코드 로직을 복제하지 않게 했고, 지갑 페이지용 `GET /wallet/attr_schema` 를 추가했다(스펙 §5.3 의 "id·version·hash" 에 더한 것). (3) `tests/helpers/mode3_fixture.mjs` 의 `FIXTURE_ATTRS` 와 `bench_zkp_inventory.mjs` 벡터는 **바꾸지 않는다**(회로·벤치 입력은 스키마와 무관, 재현성) — 주석만 고친다. (4) 지갑·RP 가 스키마를 못 받으면 기본 스키마로 간다(경고) — 기동 실패로 두면 CIA 가 잠깐 죽은 것만으로 지갑·RP 가 뜨지 않는다.
- **플레이스홀더**: 없음(모든 단계에 코드·명령·기대값). `expectStartupRefused` 는 `tests/test_cia_startup.mjs` 에 이미 있는 헬퍼다(140행 사용 예).
- **이름 일관성**: `encodeSlotValue/encodeProfile/encodeMembers/decodeAttrs/reencodeLossy/profileFromAttrs/assertPredicateTypes/schemaInfo/slotIndexOf/allowedPredicates/loadSchema/DEFAULT_ATTR_SCHEMA` 는 Task 1 정의와 Task 2~6 사용이 같다. 응답 필드 `profile`·`schemaHash`·`attrSchema`·`attrsView`·`allowedCountryNames`, 오류 `bad_attr{slot,field,reason}`·`use_profile`·`predicate_type`·`predicate_unavailable` 도 전 Task 에서 같은 철자다.
