// lib/mode3_attr_commit.js — 사용자 속성 커밋먼트 C_attr(2026-11-09 설계, Phase 1). IdP 프로필의 `name` 칸에 들어가는 값이다.
//   C_attr = Poseidon(DOMAIN_MODE3_ATTRC, attrs[0..5], blind)   (입력 8개 — circomlibjs Poseidon 은 16개까지 받는다)
// RP 관련 값(arid 등)은 들어가지 않는다 — 사용자가 어느 서비스에 내든 같은 커밋먼트다(사용자 결정 2026-11-09). blind 는 속성 도구 페이지
// (mode3/attr.html)에만 남고 IdP·지갑·RP 어디에도 가지 않는다. 브라우저 번들(scripts/build_attr_tool.mjs)과 Node 양쪽에서 쓰므로
// node:crypto 는 randomBytes 만 쓴다(lib/browser/node_crypto.js shim 이 제공하는 함수).
import { randomBytes } from 'node:crypto';
import { buildPoseidon } from 'circomlibjs';

export const DOMAIN_MODE3_ATTRC = 365084431357309388870211n;   // ASCII "MODE3ATTRC" 빅엔디언(DOMAIN_MODE3_ATTRSTR 과 같은 방식)
export const ATTR_COUNT = 6;
// BN254 스칼라 필드 크기 — blind 와 입력은 이 아래여야 한다.
export const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

/** 10진 문자열·bigint·정수를 필드 원소로. 형식이 틀리거나 필드 밖이면 오류(조용히 0 이 되지 않게). */
export function toField(v, what = 'value') {
  let b;
  if (typeof v === 'bigint') b = v;
  else if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) b = BigInt(v);
  else if (typeof v === 'string' && /^[0-9]+$/.test(v)) b = BigInt(v);
  else throw new Error(`${what}: 10진 정수여야 한다`);
  if (b >= FIELD_P) throw new Error(`${what}: 필드 밖 값`);
  return b;
}

/** 무작위 blind(10진 문자열, < FIELD_P). 31바이트(248비트)면 필드 안이고 편향이 없다. */
export function randomBlind() {
  return BigInt('0x' + randomBytes(31).toString('hex')).toString();
}

/** C_attr 계산. attrs 는 인코딩된 속성 6개(lib/mode3_attr_schema.js encodeProfile 의 출력), blind 는 randomBlind(). 10진 문자열을 돌려준다. */
export async function attrCommit({ attrs, blind }) {
  if (!Array.isArray(attrs) || attrs.length !== ATTR_COUNT) throw new Error(`attrs 는 ${ATTR_COUNT}개여야 한다`);
  const a = attrs.map((v, i) => toField(v, `attrs[${i}]`));
  const b = toField(blind, 'blind');
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_ATTRC, ...a, b])).toString();
}

/** IdP 프로필 `name` 칸·ID 토큰의 name 클레임으로 받아들일 커밋먼트 형식인지(10진, 필드 안). 빈 값은 "없음" 으로 보고 false. */
export function isAttrCommit(v) {
  if (typeof v !== 'string' || !/^[0-9]+$/.test(v) || v.length > 78) return false;
  return BigInt(v) < FIELD_P;
}
