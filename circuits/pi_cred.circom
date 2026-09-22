pragma circom 2.0.0;

include "lib/eddsaposeidon.circom";
include "lib/poseidon.circom";
include "lib/imt_nonmembership_v2.circom";
include "lib/bitify.circom";
include "lib/comparators.circom";
include "lib/mode3_commit.circom";
include "lib/mode3_trace_tag.circom";

// Mode 3 credential 증명.
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §5
// 속성·(max_height, chainid, allowAgent) 서명: docs/superpowers/specs/2026-09-18-mode3-onchain-execution-design.md §3
// V4(max_height·allowAgent, 태그 평문 Poseidon(uid, arid)): docs/superpowers/specs/2026-09-18-mode3-onchain-execution-design.md §3
//
// V5(2026-09-21): 커밋 둘(C_u 사용자 자격증명, C_s 세션) — 서명은 둘을 덮고 리프는 C_u 에서만 뽑는다. 설계 docs/superpowers/specs/2026-09-21-mode3-two-tier-credential-design.md §5
// V6(2026-09-22): 공개 술어 disc_mask/lo/hi, 속성 64비트. 설계 2026-09-22-mode3-selective-disclosure-design.md §4
// 다섯 가지를 함께 증명한다. 하나라도 빠지면 뚫린다:
//   ① CIA가 (Cf_u, Cf_s, max_height, chainid, allowAgent)에 서명했다 — 없으면 아무나 credential을 만든다
//   ② C_s 안에 이 pk_i·arid 가 있다                — 없으면 남의 π를 주워 자기 키로 서명해 완전 사칭
//   ③ PPID = Poseidon(uid, s_u, chainid, arid) — 없으면 지갑 주소를 특정할 수 없다
//   ④ Poseidon(TAG=4, Cf_u) 가 폐기 트리에 없다     — 없으면 폐기가 무의미. 리프는 C_u 에서만 뽑는다(세션이 아니라 사용자당 하나)
//   ⑤ tag = Enc(pk_trace, uid) 가 잘 만들어졌다  — 없으면 개봉이 엉뚱한 값을 연다 (2026-09-16 §4)
//
//   attrs[4] 는 C_u 에만 실린다 — CIA 는 값을 모르고(설계 2026-09-14 §2) 이 회로는 술어를 검증하지 않는다.
//   r_s 는 더 이상 서명·공개 입력에 없다(설계 2026-09-18 §2) — 온체인 공개 입력은 AA 도 보므로 AA 가 발급 때 본 값을 두지 않는다.
//   allowAgent ∈ {0,1} 은 AA 속성이다(2026-09-18 §3.1) — 서명이 덮고, 공개 입력으로 나가 온체인 이벤트·개봉 결과에 남는다.
//
// ②는 세션 커밋 C_s 를 공개 입력 pk_i·arid로 **직접 계산**해서 얻는다. 별도 등식이 필요 없다 —
// 계산에 쓴 값이 곧 공개 입력이므로 다른 값을 넣으면 서명 검증이 깨진다.
// C_u·C_s 는 각각 교과서 Pedersen 점 (Cx, Cy)이고, 서명에는 둘을 Poseidon으로 압축한 Cf_u·Cf_s 가,
// 리프에는 Cf_u 만 들어간다. uid·s_u 는 C_u 안에 있어 서명이 C_u 를 덮는 것으로 PPID 의 출처가 묶인다.
//
// 리프를 커밋 안의 속성이 아니라 C_u **로부터** 유도하는 것이 §4.3의 핵심이다.
// 회로가 비공개 입력에서 직접 계산하므로 증명자가 다른 리프를 제시할 수 없고,
// 그 덕에 발급 시 리프 정합성 ZKP가 통째로 불필요해진다.
template PiCred(depth) {
    // ---- Private ----
    signal input uid;
    signal input s_u;
    signal input blind_u;
    signal input blind_s;
    signal input attrs[4];
    signal input r;   // 태그 무작위값(로그인마다 새로)

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
    signal input chainid;
    signal input allowAgent;
    signal input revRoot;
    signal input pk_CIA_x;
    signal input pk_CIA_y;
    signal input pk_trace_x;
    signal input pk_trace_y;
    signal input tag_c1_x;
    signal input tag_c1_y;
    signal input tag_c2;

    // 선택 공개(2026-09-22 §4.2). 비트 k 가 1 이면 disc_lo[k] ≤ attrs[k] ≤ disc_hi[k]. 등식 공개는 lo = hi. 0 인 슬롯은 무시.
    signal input disc_mask;
    signal input disc_lo[4];
    signal input disc_hi[4];

    var DOMAIN_MODE3_CRED_V5 = 93461614427473393731524149;  // ASCII "MODE3CREDV5"
    var TAG_MODE3_USER = 4;  // 사용자 자격증명 리프. Mode 2 의 1·2, V4 의 3 과 갈라 둔다

    // pk_i는 세션키의 이더리움 주소다. 160비트를 넘을 수 없다.
    // (Mode 2 pi_pk_i.circom과 같은 제약 — 형제 크레덴셜 구멍을 막는다.)
    component pkIRange = Num2Bits(160);
    pkIRange.in <== pk_i;

    // ---- 커밋 둘 (2026-09-21 §3) ----
    // C_u: 사용자 속성(uid, s_u, attrs). 사용자당 하나. 서명·리프에는 Poseidon(Cx, Cy) 로 압축한 Cf_u.
    component cu = CommitUser();
    cu.uid <== uid;  cu.s_u <== s_u;  cu.blind_u <== blind_u;
    for (var j = 0; j < 4; j++) cu.attrs[j] <== attrs[j];
    component cfu = Poseidon(2);
    cfu.inputs[0] <== cu.Cx;  cfu.inputs[1] <== cu.Cy;
    signal Cf_u;
    Cf_u <== cfu.out;
    // C_s: 세션 속성(arid, pk_i). 공개 입력 arid·pk_i 로 직접 계산 — 다른 값을 넣으면 서명 검증이 깨진다.
    component cs = CommitSession();
    cs.arid <== arid;  cs.pk_i <== pk_i;  cs.blind_s <== blind_s;
    component cfs = Poseidon(2);
    cfs.inputs[0] <== cs.Cx;  cfs.inputs[1] <== cs.Cy;
    signal Cf_s;
    Cf_s <== cfs.out;

    // ---- ① CIA 서명 검증 ----
    // max_height 는 2^64 미만(컨트랙트 uint64 비교와 맞춘다), allowAgent 는 불리언.
    component mhRange = Num2Bits(64);
    mhRange.in <== max_height;
    allowAgent * (allowAgent - 1) === 0;
    component msgHasher = Poseidon(6);
    msgHasher.inputs[0] <== DOMAIN_MODE3_CRED_V5;
    msgHasher.inputs[1] <== Cf_u;
    msgHasher.inputs[2] <== Cf_s;
    msgHasher.inputs[3] <== max_height;
    msgHasher.inputs[4] <== chainid;
    msgHasher.inputs[5] <== allowAgent;

    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== pk_CIA_x;
    sigVerifier.Ay <== pk_CIA_y;
    sigVerifier.S <== S;
    sigVerifier.R8x <== R8x;
    sigVerifier.R8y <== R8y;
    sigVerifier.M <== msgHasher.out;

    // ---- ③ PPID 유도 ----
    // PPID = Poseidon(uid, s_u, chainid, arid) — 발표 자료의 H(ID, salt, chain, rid) 순서.
    // chainid 는 서명 메시지에도 들어가는 같은 공개 입력이라, 서명이 보증하는 체인과 가명의 체인이
    // 어긋날 수 없다. 같은 사용자·같은 RP 라도 체인이 다르면 가명이 달라진다(2026-09-15).
    // Mode 2 pi_ppid.circom 의 Poseidon(uid, rid, salt) 와는 더 이상 같은 구조가 아니다.
    component ppidHasher = Poseidon(4);
    ppidHasher.inputs[0] <== uid;
    ppidHasher.inputs[1] <== s_u;
    ppidHasher.inputs[2] <== chainid;
    ppidHasher.inputs[3] <== arid;
    PPID === ppidHasher.out;

    // ---- ④ 폐기 비멤버십 ----
    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== TAG_MODE3_USER;
    leafHasher.inputs[1] <== Cf_u;

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

    // ---- ⑤ 트레이스 태그 ----
    // r ≠ 0 (2026-09-21 결정): c1 = r·B8 가 항등원이면 c2 가 평문을 그대로 드러낸다. 컨트랙트·서비스의 c1 ≠ O 검사와 중복 방어.
    component rNZ = IsZero();
    rNZ.in <== r;
    rNZ.out === 0;

    // uid 는 ② 의 커밋 개봉과 ③ 의 PPID 유도에 쓴 바로 그 신호다 — 태그를 열면 이 성명의 uid 가 나온다.
    // 평문은 Poseidon(uid, arid) 다 — 태그를 열면 이 성명의 (uid, arid) 값이 나오고 CIA 가 등록부로 uid 를 되찾는다(2026-09-18 §6.2).
    component tag = TraceTag();
    tag.r <== r;
    tag.uid <== uid;
    tag.arid <== arid;
    tag.pk_trace_x <== pk_trace_x;
    tag.pk_trace_y <== pk_trace_y;
    tag_c1_x === tag.c1x;
    tag_c1_y === tag.c1y;
    tag_c2 === tag.c2;

    // ---- ⑥ 선택 공개 술어 (2026-09-22) ----
    // 속성은 CommitUser 에서 Num2Bits(64) 로 잘려 있다. lo·hi 도 64비트로 묶어야 LessEqThan(64) 이 성립한다.
    component maskBits = Num2Bits(4);
    maskBits.in <== disc_mask;
    component loBits[4]; component hiBits[4]; component ge[4]; component le[4];
    signal discOk[4];
    for (var k = 0; k < 4; k++) {
        loBits[k] = Num2Bits(64); loBits[k].in <== disc_lo[k];
        hiBits[k] = Num2Bits(64); hiBits[k].in <== disc_hi[k];
        ge[k] = LessEqThan(64); ge[k].in[0] <== disc_lo[k]; ge[k].in[1] <== attrs[k];
        le[k] = LessEqThan(64); le[k].in[0] <== attrs[k];   le[k].in[1] <== disc_hi[k];
        discOk[k] <== ge[k].out * le[k].out;
        maskBits.out[k] * (1 - discOk[k]) === 0;
    }
}

// 공개 입력의 순서는 lib/mode3_wallet.js·lib/mode3_rp.js·cia.js(개봉)·contracts/Mode3Wallet.sol 가 의존한다. 바꾸지 말 것.
// pk_CIA_x/y 와 pk_trace_x/y 는 공개 입력이다. 검증자는 반드시 전자를 고정된 CIA 키와, 후자를 자기 등록 파일의
// 조합 키와 비교해야 한다 (설계 §5, 2026-09-16 §4.2).
// [14] disc_mask [15..18] disc_lo [19..22] disc_hi
component main {public [
    PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, pk_CIA_x, pk_CIA_y,
    pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2,
    disc_mask, disc_lo, disc_hi
]} = PiCred(32);
