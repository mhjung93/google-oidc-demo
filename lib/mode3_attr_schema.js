// Mode 3 속성 매핑 계층(스펙 2, 2026-10-07): 공개 스키마와 타입별 인코딩. 회로·서명·Snap·지갑 상태가 쓰는 내부 표현
// ("인코딩된 10진 문자열 6개", lib/mode3_credential.js 의 normalizeAttrs)은 바꾸지 않고 그 앞에 얹는다.
//   int    → 10진 그대로(빈 값 0, 아니면 [min, max])
//   enum   → 스키마에 적힌 코드(이름 또는 표에 있는 코드 숫자 입력, 빈 값 0, 코드 0 은 예약)
//   string → 앞뒤 공백 제거·NFC·UTF-8 → Poseidon(DOMAIN, slot, len, c0..c3) 를 64비트로 줄인 값 (1 ≤ v < 2^64 — 빈 값 0·SET_PAD 2^64 와 겹치지 않음)
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
// 최종 리뷰 M3: 슬롯·enum 이름이 Object.prototype 의 키와 겹치면 profile[name]·values[name] 조회가 상속 값을 집는다 — 스키마에서 막는다.
const RESERVED_NAMES = new Set(['constructor', '__proto__', 'prototype', 'hasOwnProperty', 'toString', 'valueOf']);

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
    if (RESERVED_NAMES.has(s.name)) throw at(`name ${s.name} 은 예약된 이름`);
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
        if (RESERVED_NAMES.has(k)) throw at(`enum 이름 ${k} 은 예약된 이름`);
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
const isBlank = (v) => v === undefined || v === null || (typeof v === 'string' && v.trim() === '');
/** 관리자 입력에서 빈 값을 받지 않는 슬롯(최종 리뷰 I1): enum, 그리고 0 이 범위 밖인 int(min > 0). */
const valueRequired = (s) => s.type === 'enum' || (s.type === 'int' && BigInt(s.min ?? 0) > 0n);

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
  else if (typeof value === 'number') { if (!Number.isSafeInteger(value)) throw fail('format', `숫자 입력은 안전한 정수여야 한다: ${value}`); raw = String(value); }
  else if (typeof value === 'bigint') raw = String(value);
  else throw fail('type', '문자열·숫자만 받는다');
  raw = raw.trim();   // 최종 리뷰 M2: string 도 앞뒤 공백만 뗀다(내부 공백은 값의 일부)
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
    if (Object.hasOwn(s.values, raw)) return BigInt(s.values[raw]).toString();
    if (/^[0-9]+$/.test(raw)) { const code = BigInt(raw); if (Object.values(s.values).some((c) => BigInt(c) === code)) return code.toString(); }
    throw fail('enum', `표에 없는 값: ${raw}`);
  }
  const bytes = Buffer.from(raw.normalize('NFC'), 'utf8');
  const maxBytes = s.maxBytes ?? STRING_MAX_BYTES;
  if (bytes.length > maxBytes) throw fail('length', `${maxBytes}바이트 초과 (${bytes.length}바이트)`);
  return (await hashString(slotIndex, bytes)).toString();
}

/** profile({ 슬롯 이름: 값 }) → attrs(10진 문자열 6개). int·enum 슬롯 이름은 키가 있어야 한다(값은 빈 문자열 가능) — 빈 객체 한 번으로
 *  속성이 통째로 지워지는 것을 막는다(2026-09-23 점검 A-I2 와 같은 이유). string 키는 생략 가능(= 빈 값). 스키마에 없는 키는 오류.
 *  allowEmptyRequired:false(관리자 입력, 최종 리뷰 I1)면 min > 0 인 int 슬롯과 enum 슬롯의 빈 값도 거절한다(bad_attr detail 'empty') —
 *  0 은 "값 없음"인데 출생연도 0 이 나이 술어의 hi 검사(AttrGate)를 통과하기 때문이다. 등록·이행·데모 인코딩은 기본값(허용). */
export async function encodeProfile(schema, profile, { allowEmptyRequired = true } = {}) {
  if (profile === undefined || profile === null) profile = {};
  if (typeof profile !== 'object' || Array.isArray(profile)) throw attrFail(null, null, 'type', 'profile 은 { 이름: 값 } 객체여야 한다');
  const named = schema.slots.filter((s) => s.type !== 'unused');
  const known = new Set(named.map((s) => s.name));
  for (const k of Object.keys(profile)) if (!known.has(k)) throw attrFail(null, k, 'unknown_field', `스키마에 없는 필드: ${k}`);
  for (const s of named) if ((s.type === 'int' || s.type === 'enum') && !Object.hasOwn(profile, s.name)) throw attrFail(slotIndexOf(schema, s.name), s.name, 'missing_field', `필드가 없다: ${s.name}`);
  const out = [];
  for (let i = 0; i < schema.slots.length; i++) {
    const s = schema.slots[i];
    const v = s.type !== 'unused' && Object.hasOwn(profile, s.name) ? profile[s.name] : '';
    if (!allowEmptyRequired && valueRequired(s) && isBlank(v)) throw attrFail(i, s.name, 'empty', `슬롯 ${i}(${s.name}): 빈 값은 받지 않는다(0 은 "값 없음")`);
    out.push(await encodeSlotValue(schema, i, v));
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

/** 저장용 정규 profile(최종 리뷰 I3, 동기): enum 은 이름(코드 입력 → 이름), int 는 정규 10진, string 은 앞뒤 공백만 뗀 원문, 빈 값은 키 생략.
 *  encodeProfile 을 통과한 profile 을 받는다 — 모르는 키·unused 는 거기서 이미 거절됐으므로 여기서는 스키마의 이름 있는 슬롯만 본다.
 *  관리자 화면의 <select> 는 이름으로 그리므로 코드('410')를 그대로 저장하면 빈 칸으로 보이고 다음 저장이 국가를 지운다. */
export function normalizeProfile(schema, profile) {
  const out = {};
  for (const s of schema.slots) {
    if (s.type === 'unused' || !profile || !Object.hasOwn(profile, s.name) || isBlank(profile[s.name])) continue;
    const raw = String(profile[s.name]).trim();
    if (s.type === 'int') out[s.name] = /^[0-9]+$/.test(raw) ? BigInt(raw).toString() : raw;
    else if (s.type === 'enum') out[s.name] = Object.hasOwn(s.values, raw) ? raw : (/^[0-9]+$/.test(raw) && enumName(s, raw)) || raw;
    else out[s.name] = raw;
  }
  return out;
}

/** 표시용 디코드(동기). string 은 일방향이라 profile 의 원문을 쓴다(없으면 #값). 0 은 빈 표시. */
export function decodeAttrs(schema, attrs, profile = null) {
  return schema.slots.map((s, i) => {
    const value = String(attrs?.[i] ?? '0');
    const base = { slot: i, name: s.name ?? null, label: s.label ?? s.name ?? null, type: s.type, value };
    if (s.type === 'unused' || value === '0') return { ...base, display: '' };
    if (s.type === 'int') return { ...base, display: value };
    if (s.type === 'enum') return { ...base, display: enumName(s, value) ?? `#${value}` };
    const orig = profile && Object.hasOwn(profile, s.name) ? profile[s.name] : undefined;
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
    if (s.type === 'unused' || !Object.hasOwn(profile, s.name)) return '0';
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
