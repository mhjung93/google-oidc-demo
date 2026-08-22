pragma circom 2.0.0;

include "poseidon.circom";
include "comparators.circom";
include "mux1.circom";

// Indexed Merkle Tree 비멤버십 증명.
//
// 리프는 값 순으로 정렬돼 있고 각 리프가 (value, nextValue)를 담는다.
// target이 트리에 없음을 보이려면, lowValue < target < lowNextValue 를
// 만족하는 리프 하나가 트리 안에 있음을 보이면 된다.
// lowNextValue == 0 은 "이 리프가 가장 큰 값"이라는 sentinel이므로,
// 그 경우 target < lowNextValue 검사를 건너뛴다.
template IMTNonMembership(depth) {
    signal input target;
    signal input lowValue;
    signal input lowNextValue;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input root;

    // 1) 리프 해시 = Poseidon(lowValue, lowNextValue)
    component leafHash = Poseidon(2);
    leafHash.inputs[0] <== lowValue;
    leafHash.inputs[1] <== lowNextValue;

    // 2) Merkle 경로 검증
    component h[depth];
    component muxL[depth];
    component muxR[depth];
    signal cur[depth + 1];
    cur[0] <== leafHash.out;

    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;
        muxL[i] = Mux1();
        muxL[i].c[0] <== cur[i];
        muxL[i].c[1] <== pathElements[i];
        muxL[i].s <== pathIndices[i];
        muxR[i] = Mux1();
        muxR[i].c[0] <== pathElements[i];
        muxR[i].c[1] <== cur[i];
        muxR[i].s <== pathIndices[i];
        h[i] = Poseidon(2);
        h[i].inputs[0] <== muxL[i].out;
        h[i].inputs[1] <== muxR[i].out;
        cur[i + 1] <== h[i].out;
    }
    root === cur[depth];

    // 3) lowValue < target
    component ltLow = LessThan(252);
    ltLow.in[0] <== lowValue;
    ltLow.in[1] <== target;
    ltLow.out === 1;

    // 4) target < lowNextValue, 단 lowNextValue == 0 이면 통과
    component isLast = IsZero();
    isLast.in <== lowNextValue;

    component ltHigh = LessThan(252);
    ltHigh.in[0] <== target;
    ltHigh.in[1] <== lowNextValue;

    // isLast == 1 이면 1, 아니면 ltHigh.out 이어야 한다
    component pick = Mux1();
    pick.c[0] <== ltHigh.out;
    pick.c[1] <== 1;
    pick.s <== isLast.out;
    pick.out === 1;
}
