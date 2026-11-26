pragma circom 2.0.0;

include "lib/poseidon.circom";
include "lib/bitify.circom";
include "lib/comparators.circom";
include "lib/escalarmulfix.circom";
include "lib/escalarmulany.circom";

// π_trace — PPID 계정에 한 번 남기는 추적 기록의 올바름(스펙 2026-11-26 ppid-account-trace §4.2).
//   "이 암호문은 이 PPID 의 주인의 auid 를 감사자 키 pk_aud 로 암호화한 것이다."
//
//   PPID = Poseidon(s_u, arid, chainid)                  ← pi_cred ③ 과 같은 식
//   auid = Poseidon(DOMAIN_MODE3_AUID, s_u)              ← pi_cred ② 와 같은 식
//   c1   = rho·B8,   K = rho·pk_aud,   c2 = auid + Poseidon(K.x, K.y)     (rho ≠ 0, rho < 2^250)
//
// 비공개: s_u, rho.  공개(이 순서 — contracts/TraceRegistry.sol·lib/mode3_trace_record.js 와 함께 바꾼다):
//   [0] PPID [1] arid [2] chainid [3] pk_aud_x [4] pk_aud_y [5] c1_x [6] c1_y [7] c2
// PPID 가 salt 를 정하므로(다른 salt 로 같은 PPID 를 만들 수 없다) 등록부·폐기는 여기서 보지 않는다 — 그 salt 가 등록된 신원인지는 로그인·거래의 π_RP 가 본다.
// pk_aud 는 등록부 컨트랙트가 자기 값과 대조한다(대조하지 않으면 사용자가 자기 키로 암호화한다). 곡선·부분군 검사는 넣지 않는다 — 그 값은 컨트랙트를 배포할 때 정한다.
// 암호문의 모양은 옛 TraceTag(circuits/lib/mode3_trace_tag.circom)와 같고 평문만 auid 다. JS 판은 lib/mode3_trace_record.js.
template PiTrace() {
    signal input s_u;
    signal input rho;

    signal input PPID;
    signal input arid;
    signal input chainid;
    signal input pk_aud_x;
    signal input pk_aud_y;
    signal input c1_x;
    signal input c1_y;
    signal input c2;

    var DOMAIN_MODE3_AUID = 365084431357309404922930;   // "MODE3AUID2" — circuits/pi_cred.circom 과 같은 값
    var N = 250;
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component ppidHasher = Poseidon(3);
    ppidHasher.inputs[0] <== s_u;
    ppidHasher.inputs[1] <== arid;
    ppidHasher.inputs[2] <== chainid;
    PPID === ppidHasher.out;

    component ah = Poseidon(2);
    ah.inputs[0] <== DOMAIN_MODE3_AUID;
    ah.inputs[1] <== s_u;

    component nz = IsZero();
    nz.in <== rho;
    nz.out === 0;

    component bits = Num2Bits(N);
    bits.in <== rho;
    component mFix = EscalarMulFix(N, BASE8);
    component mAny = EscalarMulAny(N);
    for (var i = 0; i < N; i++) {
        mFix.e[i] <== bits.out[i];
        mAny.e[i] <== bits.out[i];
    }
    mAny.p[0] <== pk_aud_x;
    mAny.p[1] <== pk_aud_y;

    c1_x === mFix.out[0];
    c1_y === mFix.out[1];

    component mask = Poseidon(2);
    mask.inputs[0] <== mAny.out[0];
    mask.inputs[1] <== mAny.out[1];
    c2 === ah.out + mask.out;
}

component main {public [PPID, arid, chainid, pk_aud_x, pk_aud_y, c1_x, c1_y, c2]} = PiTrace();
