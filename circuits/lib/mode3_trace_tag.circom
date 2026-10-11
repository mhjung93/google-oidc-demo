pragma circom 2.0.0;

include "poseidon.circom";
include "bitify.circom";
include "escalarmulfix.circom";
include "escalarmulany.circom";

// 2-of-2 트레이스 태그 — 설계 2026-09-16 §4.1/§4.2 (조건 ⑤).
//   c1 = r·B8,  K = r·pk_trace,  c2 = Poseidon(uid, arid) + Poseidon(K.x, K.y)
// pk_trace 는 공개 입력이다 — 서비스가 자기 등록 파일의 값과 대조한다(대조하지 않으면 사용자가 아무 키로나
// 암호화한 태그를 낼 수 있다). 평문 h = Poseidon(uid, arid) 의 uid 는 커밋을 여는 것과 같은 신호라 "이 태그를 열면 이 성명의 uid 가 나온다"가
// 회로로 보증된다(검증 가능 암호화). JS 판은 lib/mode3_trace.js — 같은 B8, 같은 Poseidon(2), 같은 250비트 상한.
// pk_trace 의 곡선·부분군 검사는 넣지 않는다: 그 값은 CIA 가 승인 때 검사한 X_svc 에 자기 조각을 더한 것이고,
// 서비스가 자기 값과 같은지 대조한다.
template TraceTag() {
    signal input r;
    signal input uid;
    signal input arid;
    signal input pk_trace_x;
    signal input pk_trace_y;
    signal output c1x;
    signal output c1y;
    signal output c2;

    var N = 250;
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component bits = Num2Bits(N);
    bits.in <== r;

    component mFix = EscalarMulFix(N, BASE8);
    component mAny = EscalarMulAny(N);
    for (var i = 0; i < N; i++) {
        mFix.e[i] <== bits.out[i];
        mAny.e[i] <== bits.out[i];
    }
    mAny.p[0] <== pk_trace_x;
    mAny.p[1] <== pk_trace_y;

    c1x <== mFix.out[0];
    c1y <== mFix.out[1];

    // 평문 h = Poseidon(uid, arid) — 설계 2026-09-18 §3.4. JS 판은 lib/mode3_trace.js 의 tagPlaintext().
    component h = Poseidon(2);
    h.inputs[0] <== uid;
    h.inputs[1] <== arid;

    component mask = Poseidon(2);
    mask.inputs[0] <== mAny.out[0];
    mask.inputs[1] <== mAny.out[1];
    c2 <== h.out + mask.out;
}
