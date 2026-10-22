pragma circom 2.0.0;
include "poseidon.circom";
include "comparators.circom";
include "mux1.circom";
include "bitify.circom";

// 구간 비멤버십(2026-10-22 세션 폐기 상한): [lo, hi] 안에 리프가 없다 ⇔ lowValue < lo 이고 (lowNextValue > hi 또는 lowNextValue == 0).
// 리프 해시·Merkle 경로·252비트 정규화는 imt_nonmembership_v2.circom 과 같다. lo·hi 는 호출자(pi_cred)가 H'·2^32 + counter 로
// 만들어 2^252 미만이 보장되지만 여기서도 범위를 검사한다. lib/imt_v2.js getRangeNonMembershipWitness 와 짝.
// 전제: 호출자가 lo ≤ hi 를 보장한다(pi_cred 는 hi = lo + counter 라 구조적으로 성립). lo > hi 이면 빈 구간이라 통과한다.
template IMTRangeNonMembershipV2(depth) {
    signal input lo;
    signal input hi;
    signal input lowValue;
    signal input lowNextIndex;
    signal input lowNextValue;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input root;

    component leafHash = Poseidon(3);
    leafHash.inputs[0] <== lowValue;
    leafHash.inputs[1] <== lowNextIndex;
    leafHash.inputs[2] <== lowNextValue;

    component h[depth];
    component muxL[depth];
    component muxR[depth];
    signal cur[depth + 1];
    cur[0] <== leafHash.out;
    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;
        muxL[i] = Mux1(); muxL[i].c[0] <== cur[i]; muxL[i].c[1] <== pathElements[i]; muxL[i].s <== pathIndices[i];
        muxR[i] = Mux1(); muxR[i].c[0] <== pathElements[i]; muxR[i].c[1] <== cur[i]; muxR[i].s <== pathIndices[i];
        h[i] = Poseidon(2); h[i].inputs[0] <== muxL[i].out; h[i].inputs[1] <== muxR[i].out;
        cur[i + 1] <== h[i].out;
    }
    root === cur[depth];

    component loRange = Num2Bits(252);  loRange.in <== lo;
    component hiRange = Num2Bits(252);  hiRange.in <== hi;
    component lowRange = Num2Bits(252); lowRange.in <== lowValue;
    component nextRange = Num2Bits(252); nextRange.in <== lowNextValue;

    // lowValue < lo
    component ltLow = LessThan(252);
    ltLow.in[0] <== lowValue; ltLow.in[1] <== lo;
    ltLow.out === 1;

    // hi < lowNextValue, 단 lowNextValue == 0 이면 통과
    component isLast = IsZero();
    isLast.in <== lowNextValue;
    component ltHigh = LessThan(252);
    ltHigh.in[0] <== hi; ltHigh.in[1] <== lowNextValue;
    component pick = Mux1();
    pick.c[0] <== ltHigh.out; pick.c[1] <== 1; pick.s <== isLast.out;
    pick.out === 1;
}
