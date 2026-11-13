// lib/mode3_attr_commit.js — 사용자 속성 커밋먼트 C_attr(2026-11-09 설계, Phase 1). IdP 프로필의 `name` 칸에 들어가는 값이다.
//   C_attr = Poseidon(DOMAIN_MODE3_ATTRC, s_u, attrs[0..5])   (입력 8개 — circomlibjs Poseidon 은 16개까지 받는다)
// 2026-11-13(스펙 random-salt R15, 사용자 결정): 식에서 blind 를 뺐다 — 백업에는 salt 만 두므로(R5), 무작위 blind 가 있으면 복구 뒤 같은 커밋먼트를 다시 만들 수 없다.
// salt 가 이미 식 안의 250비트 비밀이라 숨김은 그대로다(IdP 는 salt 없이 속성을 대입해 볼 수 없다). 대가: 같은 salt·같은 속성이면 항상 같은 값이다.
// 옛 정의(blind 포함, MODE3ATTRC3 — 같은 날 오전)와 섞이지 않게 도메인을 MODE3ATTRC4 로 바꿨다.
// 2026-11-13(사용자 결정): 식에서 uid 를 뺐다 — 커밋먼트는 지갑의 salt 에만 묶인다. 속성 도구는 uid 를 묻지 않고 zkID 로그인 세션에서 받아와 기록에만 둔다
// (auid 표시·첫 등록의 계정 대조용). 옛 정의(uid 포함, MODE3ATTRC2)와 섞이지 않게 도메인 상수를 다시 바꿨다(MODE3ATTRC3).
// 2026-11-10(사용자 결정 B+b1): uid·s_u(salt)를 묶어 커밋먼트가 계정·지갑에 속하게 했다. 도구 페이지는 여전히 아무와도 통신하지 않고,
// 사용자가 zk 지갑 화면(계정 탭 → 상세)의 uid·salt 를 복사해 넣는다. 옛 정의(uid·s_u 없음)와 섞이지 않게 도메인 상수도 바꿨다(MODE3ATTRC → MODE3ATTRC2).
// RP 관련 값(arid 등)은 들어가지 않는다 — 사용자가 어느 서비스에 내든 같은 커밋먼트다(사용자 결정 2026-11-09).
// 브라우저 번들(scripts/build_attr_tool.mjs)과 Node 양쪽에서 쓴다.
import { buildPoseidon } from 'circomlibjs';

export const DOMAIN_MODE3_ATTRC = BigInt('0x' + Buffer.from('MODE3ATTRC4').toString('hex'));   // ASCII "MODE3ATTRC4" 빅엔디언(= 93461614427471203550774068). "MODE3ATTRC"(2026-11-09, uid·s_u 없음)·"MODE3ATTRC2"(2026-11-10, uid·s_u·blind)·"MODE3ATTRC3"(2026-11-13 오전, s_u·blind)은 옛 정의
export const ATTR_COUNT = 6;
// BN254 스칼라 필드 크기 — 입력은 이 아래여야 한다.
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

/** C_attr 계산. s_u 는 스냅의 salt(10진), attrs 는 인코딩된 속성 6개(lib/mode3_attr_schema.js encodeProfile 의 출력).
 *  10진 문자열을 돌려준다. uid·blind 는 식에 없다(2026-11-13) — 인자로 줘도 읽지 않는다. */
export async function attrCommit({ s_u, attrs }) {
  const su = toField(s_u, 's_u');
  if (!Array.isArray(attrs) || attrs.length !== ATTR_COUNT) throw new Error(`attrs 는 ${ATTR_COUNT}개여야 한다`);
  const a = attrs.map((v, i) => toField(v, `attrs[${i}]`));
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_ATTRC, su, ...a])).toString();
}

/** IdP 프로필 `name` 칸·ID 토큰의 name 클레임으로 받아들일 커밋먼트 형식인지(10진, 필드 안). 빈 값은 "없음" 으로 보고 false. */
export function isAttrCommit(v) {
  if (typeof v !== 'string' || !/^[0-9]+$/.test(v) || v.length > 78) return false;
  return BigInt(v) < FIELD_P;
}
