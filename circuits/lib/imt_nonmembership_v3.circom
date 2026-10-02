pragma circom 2.0.0;

include "poseidon.circom";
include "comparators.circom";
include "mux1.circom";
include "bitify.circom";

// 정석 Indexed Merkle Tree 비멤버십 증명 — v3 (샤드 포레스트용).
//
// v2와의 차이는 딱 하나다: **샤드 인덱스를 출력으로 노출한다.**
//   v2: 깊이 20 트리 하나
//   v3: 깊이 d 서브트리 하나 + 그 서브트리가 몇 번 샤드인지
//
// 비멤버십 판정 논리(리프 해시 Poseidon(3), Merkle 경로, 252비트 정규화, LessThan,
// sentinel 처리)는 v2와 **완전히 동일**하다. 그대로 복제한 이유는 v2를 파라미터화하면
// 이미 배선·검증이 끝난 현행 경로(pi_pk_i)의 회로가 함께 바뀌기 때문이다. Stage A에서는
// 나란히 두고, 전환이 끝난 뒤에 v2를 정리한다(v1 -> v2 때와 같은 방식).
//
// 왜 샤드 인덱스가 필요한가. 트리를 서브트리 여러 개로 쪼개면 "target이 이 서브트리에
// 없다"만으로는 아무것도 증명하지 못한다 — 증명자가 **비어 있는 서브트리**를 골라
// 제시하면 그만이기 때문이다. 그래서 회로가 "이 target은 정의상 샤드 s에 속한다"까지
// 함께 보여야 하고, 컨트랙트는 그 s를 상위 트리 경로의 인덱스로 써야 한다.
// (설계 문서 2026-09-05-revocation-dual-tree-design.md 4절 조건 1·3)
//
// 비용은 0이다. target은 이미 v2에서 Num2Bits_strict로 분해되므로, 하위 shardBits개
// 비트의 선형 결합을 하나 더 만드는 것뿐이다 — 실측으로 constraint 증가가 없었다
// (results/mode2_sharded_circuit_constraints_20260904.csv).
//
// 주의: shardIndex는 target의 **하위 비트**다. 상위 비트를 쓰면 Poseidon 출력의 분포가
// 균등하더라도 252비트 마스킹 경계와 얽혀 분석이 지저분해진다.
template IMTNonMembershipV3(depth, shardBits) {
    assert(shardBits >= 0);
    assert(shardBits <= 252);

    signal input target;
    signal input lowValue;
    signal input lowNextIndex;
    signal input lowNextValue;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input root;

    // target 하위 shardBits비트. 호출자는 이 값을 자기 public signal과 대조해야 한다.
    signal output shardIndex;

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

    // 3) 비교 전에 모든 피연산자를 252비트로 제한한다 (v2와 동일 — 근거는 v2 주석 참조).
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

    component pick = Mux1();
    pick.c[0] <== ltHigh.out;
    pick.c[1] <== 1;
    pick.s <== isLast.out;
    pick.out === 1;

    // 6) 샤드 인덱스 = target 하위 shardBits비트. targetBits를 재사용하므로 추가 비용이
    //    없다. lib/imt_v3.js의 shardOf()와 반드시 같은 식이어야 한다.
    var sacc = 0;
    for (var i = 0; i < shardBits; i++) {
        sacc += targetBits.out[i] * (1 << i);
    }
    shardIndex <== sacc;
}
