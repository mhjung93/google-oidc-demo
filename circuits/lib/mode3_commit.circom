pragma circom 2.0.0;

include "poseidon.circom";
include "bitify.circom";
include "escalarmulfix.circom";
include "babyjub.circom";

// Mode 3 커밋 스킴 두 판.
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §4.1, §11
//
// 커밋이 담는 것은 (uid, arid, s_u, blind, pk_i) 다섯이다.
//   uid   — 계정 식별자. PPID 유도에 쓰인다
//   arid  — RP 식별자. credential을 RP에 묶는다 (Mode 2의 rid)
//   s_u   — 사용자 비밀. CIA가 PPID를 열거하지 못하게 막는다 (Mode 2의 salt)
//   blind — 커밋 블라인딩. CIA가 공개된 (arid, pk_i)와 자기가 아는 uid로
//           C를 재계산해 대조하는 것을 막는다
//   pk_i  — 세션키. 이 π가 이 서명자의 것임을 묶는다

// 해시 판. show 회로가 싸다. 대신 발급 시 PoK가 SNARK가 되어 회로가 하나 더 필요하다.
template CommitPoseidon() {
    signal input uid;
    signal input arid;
    signal input s_u;
    signal input blind;
    signal input pk_i;
    signal output C;

    component h = Poseidon(5);
    h.inputs[0] <== uid;
    h.inputs[1] <== arid;
    h.inputs[2] <== s_u;
    h.inputs[3] <== blind;
    h.inputs[4] <== pk_i;
    C <== h.out;
}

// 교과서 Pedersen 벡터 커밋 (2026-09-10, circomlib Pedersen 해시 판을 대체).
//
//   C = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + blind·H
//
// 왜 교과서 형태인가. circomlib 의 Pedersen(n) 은 비트를 4비트 창으로 잘라 부호 반전을 섞는
// 인코딩이라, 그 위에서 발급 시 시그마 프로토콜(§6.2)을 짜면 이웃 스칼라와 세그먼트를
// 공유하는 문제가 생긴다. 스칼라마다 생성원을 따로 두면 PoK 가 교과서 그대로다.
//
// 스칼라 상한 2^250. baby jubjub 소수 부분군 위수 r 은 251비트(≈2^250.6)라 2^250 < r.
// 이 검사가 없으면 e 와 e+r 이 같은 점을 만들어 binding 이 깨진다 — 한 C 를 두 s_u 로
// 열어 PPID 두 개를 얻는 Sybil 이 가능해진다. lib/mode3_credential.js 도 같은 상한을 지킨다.
//
// 생성원은 circomlib pedersen.circom 의 NUMS 점 BASE[0..4]. 서로의 이산로그를 아무도 모른다.
// 2026-09-10 circomlibjs 로 5개 모두 inCurve·inSubgroup 확인.
template CommitPedersen() {
    signal input uid;
    signal input arid;
    signal input s_u;
    signal input blind;
    signal input pk_i;
    signal output Cx;
    signal output Cy;

    var N = 250;

    var G_UID[2]   = [10457101036533406547632367118273992217979173478358440826365724437999023779287,
                      19824078218392094440610104313265183977899662750282163392862422243483260492317];
    var G_ARID[2]  = [2671756056509184035029146175565761955751135805354291559563293617232983272177,
                      2663205510731142763556352975002641716101654201788071096152948830924149045094];
    var G_SU[2]    = [5802099305472655231388284418920769829666717045250560929368476121199858275951,
                      5980429700218124965372158798884772646841287887664001482443826541541529227896];
    var G_PKI[2]   = [7107336197374528537877327281242680114152313102022415488494307685842428166594,
                      2857869773864086953506483169737724679646433914307247183624878062391496185654];
    var H_BLIND[2] = [20265828622013100949498132415626198973119240347465898028410217039057588424236,
                      1160461593266035632937973507065134938065359936056410650153315956301179689506];

    component bUid   = Num2Bits(N);  bUid.in   <== uid;
    component bArid  = Num2Bits(N);  bArid.in  <== arid;
    component bSu    = Num2Bits(N);  bSu.in    <== s_u;
    component bPki   = Num2Bits(N);  bPki.in   <== pk_i;
    component bBlind = Num2Bits(N);  bBlind.in <== blind;

    component mUid   = EscalarMulFix(N, G_UID);
    component mArid  = EscalarMulFix(N, G_ARID);
    component mSu    = EscalarMulFix(N, G_SU);
    component mPki   = EscalarMulFix(N, G_PKI);
    component mBlind = EscalarMulFix(N, H_BLIND);
    for (var i = 0; i < N; i++) {
        mUid.e[i]   <== bUid.out[i];
        mArid.e[i]  <== bArid.out[i];
        mSu.e[i]    <== bSu.out[i];
        mPki.e[i]   <== bPki.out[i];
        mBlind.e[i] <== bBlind.out[i];
    }

    // 덧셈 순서: uid + arid + s_u + pk_i + blind. JS 와 같은 순서 (결과는 순서와 무관하지만
    // 읽는 사람이 대조하기 쉽도록 맞춘다).
    component a1 = BabyAdd();
    a1.x1 <== mUid.out[0];   a1.y1 <== mUid.out[1];
    a1.x2 <== mArid.out[0];  a1.y2 <== mArid.out[1];
    component a2 = BabyAdd();
    a2.x1 <== a1.xout;       a2.y1 <== a1.yout;
    a2.x2 <== mSu.out[0];    a2.y2 <== mSu.out[1];
    component a3 = BabyAdd();
    a3.x1 <== a2.xout;       a3.y1 <== a2.yout;
    a3.x2 <== mPki.out[0];   a3.y2 <== mPki.out[1];
    component a4 = BabyAdd();
    a4.x1 <== a3.xout;       a4.y1 <== a3.yout;
    a4.x2 <== mBlind.out[0]; a4.y2 <== mBlind.out[1];

    Cx <== a4.xout;
    Cy <== a4.yout;
}
