pragma circom 2.0.0;

include "poseidon.circom";
include "mux1.circom";

// 깊이 depth 머클 포함 증명(V9 등록부, 설계 2026-10-01 §5.2 조건 9). lib/mode3_registry.js 와 같은 규약:
//   내부 노드 = Poseidon(left, right), pathIndices[i] = (index >> i) & 1, 0 이면 현재 노드가 왼쪽 자식.
// pi_cred 의 집합 소속 경로(깊이 8)와 같은 MultiMux1 배선을 매개변수화한 것이다.
template MerkleInclusion(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    component mux[depth];
    component hash[depth];
    signal cur[depth + 1];
    cur[0] <== leaf;
    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;
        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== cur[i];            mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];   mux[i].c[1][1] <== cur[i];
        mux[i].s <== pathIndices[i];
        hash[i] = Poseidon(2);
        hash[i].inputs[0] <== mux[i].out[0];
        hash[i].inputs[1] <== mux[i].out[1];
        cur[i + 1] <== hash[i].out;
    }
    root <== cur[depth];
}
