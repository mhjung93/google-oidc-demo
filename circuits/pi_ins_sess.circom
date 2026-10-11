pragma circom 2.0.0;

include "lib/imt_insert_batch.circom";

// 세션 층 서브트리(깊이 8)의 삽입 전이 증명. 설계 문서 13.2절.
// 공개 신호는 oldRoot, newRoot 둘뿐이다 — 컨트랙트는 이 둘로 상위 트리를 접어 올린다.
//
// K=4의 근거: 한 회차에 **같은 샤드**로 들어오는 폐기 건수다. 세션 샤드는 4,096개이므로
// 한 회차에 같은 샤드가 여러 번 맞는 일 자체가 드물다. 더 필요하면 같은 샤드에 대한
// 업데이트를 여러 건 이어 붙이면 된다(컨트랙트가 순차로 접으므로 자연스럽게 연결된다).
component main {public [oldRoot, newRoot]} = IMTInsertBatch(8, 4);
