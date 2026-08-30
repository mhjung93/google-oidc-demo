pragma circom 2.0.0;

include "poseidon.circom";
include "comparators.circom";
include "mux1.circom";
include "bitify.circom";

// 정석(proper) Indexed Merkle Tree 비멤버십 증명 — v2.
//
// v1(lib/imt_nonmembership.circom)과의 차이는 딱 하나다: 리프가 다음 리프의
// 물리 인덱스를 **명시적으로** 담으므로 리프 해시가 Poseidon(2) -> Poseidon(3)
// 이 되고 입력 신호 lowNextIndex 가 하나 늘었다.
//   v1: leaf = Poseidon(value, nextValue)              (next는 물리적 인접성에서 유도)
//   v2: leaf = Poseidon(value, nextIndex, nextValue)   (next를 리프에 저장)
// Merkle 경로 검증, 252비트 정규화/범위 검사, LessThan 비교, sentinel 처리는
// 전부 v1과 동일하다.
//
// lowNextIndex 에 범위 검사를 걸지 않는 이유: 비멤버십의 건전성은
// "lowValue < target < lowNextValue 를 담은 리프가 트리 안에 있다"는 Merkle
// 경로가 보장한다. lowNextIndex 가 틀리면 리프 해시가 달라져 경로 검증에서
// 걸리므로, 증명에 쓰이지 않는 부수 필드다 (설계 문서 4절).
//
// lib/imt_v2.js 의 leafHash() 와 인자 순서가 일치해야 한다.
template IMTNonMembershipV2(depth) {
    signal input target;
    signal input lowValue;
    signal input lowNextIndex;
    signal input lowNextValue;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input root;

    // 1) 리프 해시 = Poseidon(lowValue, lowNextIndex, lowNextValue)
    component leafHash = Poseidon(3);
    leafHash.inputs[0] <== lowValue;
    leafHash.inputs[1] <== lowNextIndex;
    leafHash.inputs[2] <== lowNextValue;

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

    // 3) 비교 전에 모든 피연산자를 252비트로 제한한다.
    //
    // circomlib의 LessThan(n)은 입력이 [0, 2^n) 범위라고 "가정"할 뿐 강제하지
    // 않는다. 우리 값은 Poseidon 출력이라 필드 전역에 균등 분포하고 약 67%가
    // 2^252를 넘으므로, 이 가정을 지키지 않으면 필드 wrap-around로 비교 결과가
    // 뒤집힌다(예: lowValue = p-1, target = 5 이면 회로가 lowValue < target 을
    // 참으로 판정한다). 그러면 폐기된 값도 비멤버십 증명을 통과시킬 수 있다.
    //
    // target은 호출자가 Poseidon 출력을 그대로 넘기므로 여기서 하위 252비트만
    // 취해 정규화하고, 트리에서 온 lowValue/lowNextValue는 이미 정규화된
    // 값이어야 하므로 범위만 검사한다. lib/imt_v2.js도 같은 마스킹을 적용한다.
    component targetBits = Num2Bits_strict();
    targetBits.in <== target;
    signal targetMasked;
    var acc = 0;
    for (var i = 0; i < 252; i++) {
        acc += targetBits.out[i] * (1 << i);
    }
    targetMasked <== acc;

    component lowRange = Num2Bits(252);
    lowRange.in <== lowValue;
    component nextRange = Num2Bits(252);
    nextRange.in <== lowNextValue;

    // 4) lowValue < targetMasked
    component ltLow = LessThan(252);
    ltLow.in[0] <== lowValue;
    ltLow.in[1] <== targetMasked;
    ltLow.out === 1;

    // 5) targetMasked < lowNextValue, 단 lowNextValue == 0 이면 통과
    component isLast = IsZero();
    isLast.in <== lowNextValue;

    component ltHigh = LessThan(252);
    ltHigh.in[0] <== targetMasked;
    ltHigh.in[1] <== lowNextValue;

    // isLast == 1 이면 1, 아니면 ltHigh.out 이어야 한다
    component pick = Mux1();
    pick.c[0] <== ltHigh.out;
    pick.c[1] <== 1;
    pick.s <== isLast.out;
    pick.out === 1;
}
