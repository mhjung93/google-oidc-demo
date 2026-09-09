pragma circom 2.0.0;

include "lib/eddsaposeidon.circom";
include "lib/poseidon.circom";
include "lib/imt_nonmembership_v2.circom";
include "lib/bitify.circom";
include "lib/mode3_commit.circom";

// Mode 3 credential 증명.
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §5
//
// 네 가지를 함께 증명한다. 하나라도 빠지면 뚫린다:
//   ① CIA가 (C, max_height)에 서명했다        — 없으면 아무나 credential을 만든다
//   ② C 안에 이 pk_i가 있다                    — 없으면 남의 π를 주워 자기 키로 서명해 완전 사칭
//   ③ PPID = Poseidon(uid, arid, s_u)          — 없으면 지갑 주소를 특정할 수 없다
//   ④ H(C)가 폐기 트리에 없다                   — 없으면 폐기가 무의미
//
// ②는 커밋을 공개 입력 pk_i·arid로 **직접 계산**해서 얻는다. 별도 등식이 필요 없다 —
// 계산에 쓴 값이 곧 공개 입력이므로 다른 값을 넣으면 서명 검증이 깨진다.
//
// 리프를 C 안의 속성이 아니라 C **로부터** 유도하는 것이 §4.3의 핵심이다.
// 회로가 비공개 입력에서 직접 계산하므로 증명자가 다른 리프를 제시할 수 없고,
// 그 덕에 발급 시 리프 정합성 ZKP가 통째로 불필요해진다.
template PiCred(depth) {
    // ---- Private ----
    signal input uid;
    signal input s_u;
    signal input blind;

    // CIA EdDSA-Poseidon 서명
    signal input S;
    signal input R8x;
    signal input R8y;

    // 폐기 비멤버십 witness
    signal input lowValue;
    signal input lowNextIndex;
    signal input lowNextValue;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // ---- Public ----
    signal input PPID;
    signal input arid;
    signal input pk_i;
    signal input max_height;
    signal input revRoot;
    signal input pk_CIA_x;
    signal input pk_CIA_y;

    var DOMAIN_MODE3_CRED = 1426111059989523219780;  // ASCII "MODE3CRED"
    var TAG_MODE3_CRED = 3;                          // TAG_SESSION=1, TAG_ACCOUNT=2 와 갈라 둔다

    // pk_i는 세션키의 이더리움 주소다. 160비트를 넘을 수 없다.
    // (Mode 2 pi_pk_i.circom과 같은 제약 — 형제 크레덴셜 구멍을 막는다.)
    component pkIRange = Num2Bits(160);
    pkIRange.in <== pk_i;

    // ---- C 계산 ----
    component commit = CommitPoseidon();
    commit.uid   <== uid;
    commit.arid  <== arid;
    commit.s_u   <== s_u;
    commit.blind <== blind;
    commit.pk_i  <== pk_i;
    signal C;
    C <== commit.C;

    // ---- ① CIA 서명 검증 ----
    component msgHasher = Poseidon(3);
    msgHasher.inputs[0] <== DOMAIN_MODE3_CRED;
    msgHasher.inputs[1] <== C;
    msgHasher.inputs[2] <== max_height;

    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== pk_CIA_x;
    sigVerifier.Ay <== pk_CIA_y;
    sigVerifier.S <== S;
    sigVerifier.R8x <== R8x;
    sigVerifier.R8y <== R8y;
    sigVerifier.M <== msgHasher.out;

    // ---- ③ PPID 유도 ----
    // Mode 2 pi_ppid.circom 의 Poseidon(uid, rid, salt) 와 같은 구조다
    // (arid = rid, s_u = salt).
    component ppidHasher = Poseidon(3);
    ppidHasher.inputs[0] <== uid;
    ppidHasher.inputs[1] <== arid;
    ppidHasher.inputs[2] <== s_u;
    PPID === ppidHasher.out;

    // ---- ④ 폐기 비멤버십 ----
    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== TAG_MODE3_CRED;
    leafHasher.inputs[1] <== C;

    component nm = IMTNonMembershipV2(depth);
    nm.target <== leafHasher.out;
    nm.lowValue <== lowValue;
    nm.lowNextIndex <== lowNextIndex;
    nm.lowNextValue <== lowNextValue;
    for (var i = 0; i < depth; i++) {
        nm.pathElements[i] <== pathElements[i];
        nm.pathIndices[i] <== pathIndices[i];
    }
    nm.root <== revRoot;
}

// 공개 입력의 순서는 단계 (a)·(b)가 의존한다. 바꾸지 말 것.
// pk_CIA_x/y 는 공개 입력이다. 검증자는 반드시 이 값을 고정된 CIA 키와 비교해야 한다 (설계 §5).
component main {public [
    PPID, arid, pk_i, max_height, revRoot, pk_CIA_x, pk_CIA_y
]} = PiCred(32);
