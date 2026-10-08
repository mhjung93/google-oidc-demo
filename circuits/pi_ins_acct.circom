pragma circom 2.0.0;

include "lib/imt_insert_batch.circom";

// 계정 층 서브트리(깊이 10)의 삽입 전이 증명. 설계 문서 13.2절.
component main {public [oldRoot, newRoot]} = IMTInsertBatch(10, 4);
