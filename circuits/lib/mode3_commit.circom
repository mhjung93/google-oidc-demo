pragma circom 2.0.0;

include "poseidon.circom";
include "pedersen.circom";
include "bitify.circom";

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

// Pedersen 벡터 커밋 판. 발급 시 PoK가 Schnorr 시그마 프로토콜이라 SNARK도
// 셋업도 필요 없다. 대신 show 회로에서 고정베이스 스칼라곱을 개봉해야 한다.
//
// circomlib의 Pedersen(n)은 n비트를 4비트 창으로 나눠 고정베이스 테이블을
// 조회해 더한다. 다섯 스칼라의 비트를 이어 붙이면 창마다 베이스가 달라지므로
// 결과는 다섯 값에 대한 벡터 커밋이 된다.
template CommitPedersen() {
    signal input uid;
    signal input arid;
    signal input s_u;
    signal input blind;
    signal input pk_i;
    signal output Cx;
    signal output Cy;

    var N = 254;   // 필드 원소 하나의 비트 수 (Num2Bits_strict 출력 길이)

    component bUid   = Num2Bits_strict();
    component bArid  = Num2Bits_strict();
    component bSu    = Num2Bits_strict();
    component bBlind = Num2Bits_strict();
    component bPki   = Num2Bits_strict();
    bUid.in   <== uid;
    bArid.in  <== arid;
    bSu.in    <== s_u;
    bBlind.in <== blind;
    bPki.in   <== pk_i;

    component p = Pedersen(5 * N);
    for (var i = 0; i < N; i++) {
        p.in[0 * N + i] <== bUid.out[i];
        p.in[1 * N + i] <== bArid.out[i];
        p.in[2 * N + i] <== bSu.out[i];
        p.in[3 * N + i] <== bBlind.out[i];
        p.in[4 * N + i] <== bPki.out[i];
    }
    Cx <== p.out[0];
    Cy <== p.out[1];
}
