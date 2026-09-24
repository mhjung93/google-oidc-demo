// Mode 3 폐기 트리.
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §7.1
//
// 단일 IMT, 깊이 32, 샤딩 없음, append-only. 리프는 **폐기가 일어날 때만** 생긴다
// (발급 때가 아니다). 그래서 트리가 작고 Mode 2의 샤딩·상위 트리·리셋 보조정리가
// 전부 필요 없다.
//
// 트리 본체는 lib/imt_v2.js를 그대로 쓴다 — Mode 3이 얹는 것은 리프 유도뿐이다.
// v2는 remove()를 노출하지 않으므로 append-only가 자료구조 수준에서 강제된다.
import { createIMTv2, leafValue } from './imt_v2.js';

export const MODE3_TREE_DEPTH = 32;

// TAG_SESSION=1, TAG_ACCOUNT=2는 Mode 2가 쓰고 있다(circuits/pi_pk_i_v3.circom). 3 은 V4 세션 리프가 쓰던 값이다(2026-09-21 폐기).
// 같은 트리를 쓰지는 않지만, 리프 유도 함수를 공유하므로 값을 갈라 둔다.
export const TAG_MODE3_USER = 4n;

/** 세션 리프 태그(2026-09-24 세션 폐기). 사용자 리프(4)와 같은 트리에 들어가므로 값을 가른다. */
export const TAG_MODE3_SESSION = 5n;
/** 세션 폐기 리프 = leafValue(5, Cf_s). Cf_s 는 회로가 공개 arid·pk_i 로 재계산하므로 다른 값을 들이밀 수 없다. */
export async function sessionLeaf(Cf_s) {
  return leafValue(TAG_MODE3_SESSION, Cf_s);
}

/**
 * 폐기 트리에 들어가는 리프 값. 2026-09-21 자격증명 이중 구조(설계 §3.6): 리프는 세션이 아니라
 * **사용자 자격증명** Cf_u 에서 뽑는다. 사용자당 하나 — 리프 하나로 그 사용자의 모든 세션이 함께 죽는다.
 *
 * 설계 문서 §4.3: 리프를 커밋 **으로부터 유도**하는 것이 핵심이다. 커밋 안의 속성으로
 * 두면 사용자가 값을 골라 아무 난수나 제시할 수 있어 발급 시 정합성 ZKP가
 * 필요해진다. 유도하면 회로가 비공개 입력 C_u 에서 직접 계산하므로 다른 리프를
 * 들이밀 방법이 없다.
 *
 * leafValue()가 하위 252비트로 마스킹한다 — 회로의 LessThan(252)이 그 범위를
 * 전제하기 때문이다(circuits/lib/imt_nonmembership_v2.circom 주석 참조).
 */
export async function userLeaf(Cf_u) {
  return leafValue(TAG_MODE3_USER, Cf_u);
}

export async function createRevocationTree(depth = MODE3_TREE_DEPTH) {
  return createIMTv2(depth);
}
