pragma circom 2.0.0;

include "lib/eddsaposeidon.circom";
include "lib/poseidon.circom";
include "lib/imt_nonmembership_v2.circom";
include "lib/merkle_inclusion.circom";
include "lib/bitify.circom";
include "lib/comparators.circom";
include "lib/mux1.circom";
include "lib/mode3_commit.circom";
include "lib/mode3_trace_tag.circom";

// Mode 3 credential 증명.
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §5
// 속성·(max_height, chainid, allowAgent) 서명: docs/superpowers/specs/2026-09-18-mode3-onchain-execution-design.md §3
//
// V5(2026-09-21): 커밋 둘(C_u 사용자 자격증명, C_s 세션) — 서명은 둘을 덮고 리프는 C_u 에서만 뽑는다. 설계 docs/superpowers/specs/2026-09-21-mode3-two-tier-credential-design.md §5
// V6(2026-09-22): 공개 술어 disc_mask/lo/hi, 속성 64비트. 설계 2026-09-22-mode3-selective-disclosure-design.md §4
// V7(2026-09-23): 집합 소속 set_sel/set_root(공개)·set_index/set_path(비공개). 설계 2026-09-23-mode3-predicates-design.md §3
// V8(2026-09-24): 세션 리프 Poseidon(5, Cf_s) 비멤버십 추가 — 설계 2026-09-24-mode3-session-revocation-design.md §3
// V9(2026-10-01): 등록부 — 사용자 리프 비멤버십(④)을 빼고 조건 ⑨ "cm_u = s_u·G_SU + r_u·H 를 다시 만들어 리프 Poseidon(cm.x, cm.y, Cf_u) 가
//   깊이 20 등록부(regRoot)에 있다" 를 넣는다. 속성 6슬롯, 공개 입력 30. 설계 docs/superpowers/specs/2026-10-01-mode3-v9-registry-design.md §5
// 여섯 가지를 함께 증명한다. 하나라도 빠지면 뚫린다:
//   ① CIA가 (Cf_u, Cf_s, max_height, chainid, allowAgent)에 서명했다 — 없으면 아무나 credential을 만든다
//   ② C_s 안에 이 pk_i·arid 가 있다                — 없으면 남의 π를 주워 자기 키로 서명해 완전 사칭
//   ③ PPID = Poseidon(uid, s_u, chainid, arid) — 없으면 지갑 주소를 특정할 수 없다
//   ④′ Poseidon(TAG=5, Cf_s) 가 폐기 트리에 없다 — 세션 단위 폐기(V8, 2026-09-24)
//   ⑨ cm_u = s_u·G_SU + r_u·H 를 다시 만들어 리프 Poseidon(cm.x, cm.y, Cf_u) 가 깊이 20 등록부(regRoot)에 있다
//      — 없으면 아직 등록하지 않았거나 관리자가 바꿔치기한 자격증명도 통과한다(V9, 2026-10-01. 옛 ④ 사용자 비멤버십을 대신한다)
//   ⑤ tag = Enc(pk_trace, uid) 가 잘 만들어졌다  — 없으면 개봉이 엉뚱한 값을 연다 (2026-09-16 §4)
//
//   attrs[6] 는 C_u 에만 실린다 — CIA 는 값을 모르고(설계 2026-09-14 §2) 이 회로는 술어를 검증하지 않는다.
//   r_s 는 더 이상 서명·공개 입력에 없다(설계 2026-09-18 §2) — 온체인 공개 입력은 AA 도 보므로 AA 가 발급 때 본 값을 두지 않는다.
//   allowAgent ∈ {0,1} 은 AA 속성이다(2026-09-18 §3.1) — 서명이 덮고, 공개 입력으로 나가 온체인 이벤트·개봉 결과에 남는다.
//
// ②는 세션 커밋 C_s 를 공개 입력 pk_i·arid로 **직접 계산**해서 얻는다. 별도 등식이 필요 없다 —
// 계산에 쓴 값이 곧 공개 입력이므로 다른 값을 넣으면 서명 검증이 깨진다.
// C_u·C_s 는 각각 교과서 Pedersen 점 (Cx, Cy)이고, 서명에는 둘을 Poseidon으로 압축한 Cf_u·Cf_s 가 들어간다.
// 세션 리프 Poseidon(5, Cf_s) 는 폐기 트리에 대해 비멤버십으로 증명한다(④′). 사용자 쪽은 V9 부터 비멤버십이 아니라
// 등록부 멤버십이다(⑨) — Cf_u 는 등록 커밋 cm_u 와 함께 등록부 리프 Poseidon(cm.x, cm.y, Cf_u) 를 이루고, 그 리프가
// 깊이 20 등록부(regRoot)에 있어야 한다. uid·s_u 는 C_u 안에 있어 서명이 C_u 를 덮는 것으로 PPID 의 출처가 묶인다.
//
// 리프를 커밋 안의 속성이 아니라 C_u·cm_u 로부터 유도하는 것이 §4.3의 핵심이다.
// 회로가 비공개 입력에서 직접 계산하므로 증명자가 다른 리프를 제시할 수 없고,
// 그 덕에 발급 시 리프 정합성 ZKP가 통째로 불필요해진다.
template PiCred(depth, regDepth) {
    // ---- Private ----
    signal input uid;
    signal input s_u;
    signal input r_u;        // V9: 등록 커밋 cm_u 의 블라인딩 — 조건 ⑨
    signal input blind_u;
    signal input blind_s;
    signal input attrs[6];
    signal input r;

    signal input S;
    signal input R8x;
    signal input R8y;

    // V8 세션 리프 비멤버십 증인(폐기 트리). V9 에서 사용자 리프 증인은 없다.
    signal input s_lowValue;
    signal input s_lowNextIndex;
    signal input s_lowNextValue;
    signal input s_pathElements[depth];
    signal input s_pathIndices[depth];

    // V9 등록부 경로(비공개). 슬롯 번호는 pathIndices 비트에만 있다 — 공개되지 않는다.
    signal input reg_pathElements[regDepth];
    signal input reg_pathIndices[regDepth];

    // V7 집합 소속 경로(비공개)
    signal input set_index;
    signal input set_path[8];

    // ---- Public (순서 = lib/mode3_wallet.js·lib/mode3_rp.js·contracts/Mode3Wallet.sol 의 계약) ----
    signal input PPID;
    signal input arid;
    signal input pk_i;
    signal input max_height;
    signal input chainid;
    signal input allowAgent;
    signal input revRoot;
    signal input regRoot;
    signal input pk_CIA_x;
    signal input pk_CIA_y;
    signal input pk_trace_x;
    signal input pk_trace_y;
    signal input tag_c1_x;
    signal input tag_c1_y;
    signal input tag_c2;
    signal input disc_mask;
    signal input disc_lo[6];
    signal input disc_hi[6];
    signal input set_sel;
    signal input set_root;

    var DOMAIN_MODE3_CRED_V5 = 93461614427473393731524149;  // ASCII "MODE3CREDV5" — 서명 도메인은 V9 에서도 그대로(메시지 모양 불변)
    var TAG_MODE3_SESSION = 5;

    // pk_i는 세션키의 이더리움 주소다. 160비트를 넘을 수 없다.
    // (Mode 2 pi_pk_i.circom과 같은 제약 — 형제 크레덴셜 구멍을 막는다.)
    component pkIRange = Num2Bits(160);
    pkIRange.in <== pk_i;

    // ---- ② 커밋 둘 ----
    component cu = CommitUser();
    cu.uid <== uid;  cu.s_u <== s_u;  cu.blind_u <== blind_u;
    for (var j = 0; j < 6; j++) cu.attrs[j] <== attrs[j];
    component cfu = Poseidon(2);
    cfu.inputs[0] <== cu.Cx;  cfu.inputs[1] <== cu.Cy;
    signal Cf_u;
    Cf_u <== cfu.out;
    component cs = CommitSession();
    cs.arid <== arid;  cs.pk_i <== pk_i;  cs.blind_s <== blind_s;
    component cfs = Poseidon(2);
    cfs.inputs[0] <== cs.Cx;  cfs.inputs[1] <== cs.Cy;
    signal Cf_s;
    Cf_s <== cfs.out;

    // ---- ① CIA 서명 ----
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

    // ---- ③ PPID ----
    // chainid 는 서명 메시지에도 들어가는 같은 공개 입력이라, 서명이 보증하는 체인과 가명의 체인이
    // 어긋날 수 없다. 같은 사용자·같은 RP 라도 체인이 다르면 가명이 달라진다(2026-09-15).
    component ppidHasher = Poseidon(4);
    ppidHasher.inputs[0] <== uid;
    ppidHasher.inputs[1] <== s_u;
    ppidHasher.inputs[2] <== chainid;
    ppidHasher.inputs[3] <== arid;
    PPID === ppidHasher.out;

    // ---- ④′ 세션 비멤버십 (폐기 트리) ----
    component sLeaf = Poseidon(2);
    sLeaf.inputs[0] <== TAG_MODE3_SESSION;
    sLeaf.inputs[1] <== Cf_s;
    component nmS = IMTNonMembershipV2(depth);
    nmS.target <== sLeaf.out;
    nmS.lowValue <== s_lowValue;
    nmS.lowNextIndex <== s_lowNextIndex;
    nmS.lowNextValue <== s_lowNextValue;
    for (var i = 0; i < depth; i++) {
        nmS.pathElements[i] <== s_pathElements[i];
        nmS.pathIndices[i] <== s_pathIndices[i];
    }
    nmS.root <== revRoot;

    // ---- ⑨ 등록부 멤버십 (V9) ----
    // cm_u 를 s_u·r_u 로 다시 만든다. s_u 는 ②·③ 과 같은 신호 — 등록 때 낸 salt 와 지금 PPID 의 salt 가 같다는 뜻이다.
    component rc = RegistrationCommit();
    rc.s_u <== s_u;  rc.r_u <== r_u;
    component regLeaf = Poseidon(3);
    regLeaf.inputs[0] <== rc.Cx;  regLeaf.inputs[1] <== rc.Cy;  regLeaf.inputs[2] <== Cf_u;
    component inc = MerkleInclusion(regDepth);
    inc.leaf <== regLeaf.out;
    for (var i = 0; i < regDepth; i++) {
        inc.pathElements[i] <== reg_pathElements[i];
        inc.pathIndices[i] <== reg_pathIndices[i];
    }
    inc.root === regRoot;

    // ---- ⑤ 트레이스 태그 ----
    // r ≠ 0 (2026-09-21 결정): c1 = r·B8 가 항등원이면 c2 가 평문을 그대로 드러낸다. 컨트랙트·서비스의 c1 ≠ O 검사와 중복 방어.
    component rNZ = IsZero();
    rNZ.in <== r;
    rNZ.out === 0;
    component tag = TraceTag();
    tag.r <== r;
    tag.uid <== uid;
    tag.arid <== arid;
    tag.pk_trace_x <== pk_trace_x;
    tag.pk_trace_y <== pk_trace_y;
    tag_c1_x === tag.c1x;
    tag_c1_y === tag.c1y;
    tag_c2 === tag.c2;

    // ---- ⑥ 선택 공개 (슬롯 6) ----
    // 속성은 CommitUser 에서 Num2Bits(64) 로 잘려 있다. lo·hi 도 64비트로 묶어야 LessEqThan(64) 이 성립한다.
    component maskBits = Num2Bits(6);
    maskBits.in <== disc_mask;
    component loBits[6]; component hiBits[6]; component ge[6]; component le[6];
    signal discOk[6];
    for (var k = 0; k < 6; k++) {
        loBits[k] = Num2Bits(64); loBits[k].in <== disc_lo[k];
        hiBits[k] = Num2Bits(64); hiBits[k].in <== disc_hi[k];
        ge[k] = LessEqThan(64); ge[k].in[0] <== disc_lo[k]; ge[k].in[1] <== attrs[k];
        le[k] = LessEqThan(64); le[k].in[0] <== attrs[k];   le[k].in[1] <== disc_hi[k];
        discOk[k] <== ge[k].out * le[k].out;
        maskBits.out[k] * (1 - discOk[k]) === 0;
    }

    // ---- ⑦ 집합 소속 (set_sel ∈ {0..6}) ----
    // sel 을 원핫 7개로 풀고 합이 1 이어야 한다 — sel ∉ {0..6} 는 여기서 죽는다.
    component selIs[7];
    var selSum = 0;
    for (var j = 0; j < 7; j++) {
        selIs[j] = IsEqual();
        selIs[j].in[0] <== set_sel;
        selIs[j].in[1] <== j;
        selSum += selIs[j].out;
    }
    selSum === 1;
    signal selTerm[6];
    for (var k = 0; k < 6; k++) selTerm[k] <== selIs[k + 1].out * attrs[k];
    signal setVal;
    setVal <== selTerm[0] + selTerm[1] + selTerm[2] + selTerm[3] + selTerm[4] + selTerm[5];
    component setInc = MerkleInclusion(8);
    setInc.leaf <== setVal;
    component setIdxBits = Num2Bits(8);
    setIdxBits.in <== set_index;
    for (var i = 0; i < 8; i++) {
        setInc.pathElements[i] <== set_path[i];
        setInc.pathIndices[i] <== setIdxBits.out[i];
    }
    (1 - selIs[0].out) * (setInc.root - set_root) === 0;
    selIs[0].out * set_root === 0;
}

// 공개 입력의 순서는 lib/mode3_wallet.js·lib/mode3_rp.js·cia.js(개봉)·contracts/Mode3Wallet.sol 가 의존한다. 바꾸지 말 것.
// pk_CIA_x/y 와 pk_trace_x/y 는 공개 입력이다. 검증자는 반드시 전자를 고정된 CIA 키와, 후자를 자기 등록 파일의
// 조합 키와 비교해야 한다 (설계 §5, 2026-09-16 §4.2).
// [0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot [7] regRoot [8,9] pk_CIA [10,11] pk_trace
// [12..14] tag [15] disc_mask [16..21] disc_lo [22..27] disc_hi [28] set_sel [29] set_root
component main {public [
    PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, regRoot, pk_CIA_x, pk_CIA_y,
    pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2,
    disc_mask, disc_lo, disc_hi, set_sel, set_root
]} = PiCred(32, 20);
