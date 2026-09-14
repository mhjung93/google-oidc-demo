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
//   ① CIA가 (C, exptime, chainid, nonce)에 서명했다 — 없으면 아무나 credential을 만든다
//   ② C 안에 이 pk_i가 있다                    — 없으면 남의 π를 주워 자기 키로 서명해 완전 사칭
//   ③ PPID = Poseidon(uid, arid, s_u)          — 없으면 지갑 주소를 특정할 수 없다
//   ④ H(C)가 폐기 트리에 없다                   — 없으면 폐기가 무의미
//
//   attrs[4] 는 커밋에만 실린다 — CIA 는 값을 모르고(설계 2026-09-14 §2) 이 회로는 술어를 검증하지 않는다.
//   nonce 는 비공개다 — 공개하면 RP 로그와 CIA 의 (uid, nonce) 기록이 맞물려 uid↔RP 가 이어진다(§5).
//
// ②는 커밋을 공개 입력 pk_i·arid로 **직접 계산**해서 얻는다. 별도 등식이 필요 없다 —
// 계산에 쓴 값이 곧 공개 입력이므로 다른 값을 넣으면 서명 검증이 깨진다.
// C는 교과서 Pedersen 점 (Cx, Cy)이고, 서명·리프에는 이를 Poseidon으로 압축한 Cf가 들어간다.
//
// 리프를 C 안의 속성이 아니라 C **로부터** 유도하는 것이 §4.3의 핵심이다.
// 회로가 비공개 입력에서 직접 계산하므로 증명자가 다른 리프를 제시할 수 없고,
// 그 덕에 발급 시 리프 정합성 ZKP가 통째로 불필요해진다.
template PiCred(depth) {
    // ---- Private ----
    signal input uid;
    signal input s_u;
    signal input blind;
    signal input attrs[4];
    signal input nonce;

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
    signal input exptime;
    signal input chainid;
    signal input revRoot;
    signal input pk_CIA_x;
    signal input pk_CIA_y;

    var DOMAIN_MODE3_CRED_V2 = 93461614427473393731524146;  // ASCII "MODE3CREDV2"
    var TAG_MODE3_CRED = 3;                                  // TAG_SESSION=1, TAG_ACCOUNT=2 와 갈라 둔다

    // pk_i는 세션키의 이더리움 주소다. 160비트를 넘을 수 없다.
    // (Mode 2 pi_pk_i.circom과 같은 제약 — 형제 크레덴셜 구멍을 막는다.)
    component pkIRange = Num2Bits(160);
    pkIRange.in <== pk_i;

    // ---- C 계산 (교과서 Pedersen, 2026-09-10) ----
    // C 는 곡선 점 (Cx, Cy). 서명 메시지와 폐기 리프에는 Poseidon(Cx, Cy) 로 압축한 Cf 를 넣는다.
    // 압축 해시가 하나 더 붙지만(약 240 제약) 리프 규약 leafValue(tag, raw) 와 서명 메시지
    // Poseidon(DOMAIN, ·, exptime, chainid, nonce) 를 Poseidon 판과 같은 모양으로 유지할 수 있다 —
    // 나중에 Poseidon 으로 되돌릴 때 이 블록만 바꾸면 된다.
    component commit = CommitPedersen();
    commit.uid   <== uid;
    commit.arid  <== arid;
    commit.s_u   <== s_u;
    commit.blind <== blind;
    commit.pk_i  <== pk_i;
    for (var j = 0; j < 4; j++) commit.attrs[j] <== attrs[j];

    component cf = Poseidon(2);
    cf.inputs[0] <== commit.Cx;
    cf.inputs[1] <== commit.Cy;
    signal Cf;
    Cf <== cf.out;

    // ---- ① CIA 서명 검증 ----
    // nonce 는 비공개 witness 로 메시지에만 들어간다. 스칼라 상한은 서명 메시지 안에서는 필요 없지만
    // JS 쪽(credMessage·CIA)이 2^250 미만으로 강제하므로 여기서도 같은 검사를 둔다 — 두 값이 r 을
    // 넘나들어 같은 해시를 내는 일이 없게.
    component nonceRange = Num2Bits(250);
    nonceRange.in <== nonce;
    component msgHasher = Poseidon(5);
    msgHasher.inputs[0] <== DOMAIN_MODE3_CRED_V2;
    msgHasher.inputs[1] <== Cf;
    msgHasher.inputs[2] <== exptime;
    msgHasher.inputs[3] <== chainid;
    msgHasher.inputs[4] <== nonce;

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
    leafHasher.inputs[1] <== Cf;

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

// 공개 입력의 순서는 lib/mode3_wallet.js·lib/mode3_rp.js 가 의존한다. 바꾸지 말 것.
// pk_CIA_x/y 는 공개 입력이다. 검증자는 반드시 이 값을 고정된 CIA 키와 비교해야 한다 (설계 §5).
component main {public [
    PPID, arid, pk_i, exptime, chainid, revRoot, pk_CIA_x, pk_CIA_y
]} = PiCred(32);
