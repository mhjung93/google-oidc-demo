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

// Mode 3 credential 증명 π_RP — V11(2026-10-12, 그림 261012 · 덱 7장). 설계 docs/superpowers/specs/2026-10-12-mode3-v11-figure-protocol-design.md §5.3
// 이력: V5 커밋 둘(09-21) · V6 선택 공개(09-22) · V7 집합 소속(09-23) · V8 세션 비멤버십(09-24) · V9 등록부 멤버십(10-01) · V11 가명·세션 바인딩(10-12).
// 여덟 가지를 함께 증명한다. 하나라도 빠지면 뚫린다:
//   ① 토큰: IdP 가 (auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent) 에 서명했다 — 없으면 아무나 credential 을 만든다
//   ② ID 정확성: auid = Poseidon(T_AUID, uid, s_u), auid_s = Poseidon(T_AUIDS, auid, arid, r_rp), arid_s = Poseidon(T_ARIDS, arid, r_rp)
//      — 없으면 토큰의 세션 가명이 이 uid·arid 와 무관하다(남의 토큰을 자기 arid 로 쓴다)
//   ③ PPID = Poseidon(uid, s_u, arid, chainid) — 없으면 지갑 주소를 특정할 수 없다(D13 순서)
//   ④ 선택 공개·집합 소속(불변) — 사용자가 넣은 attrs 위에서(D15)
//   ⑤ 같은 r_rp: ② 의 두 해시와 ⑦ 의 C_s 블라인딩이 하나의 비공개 r_rp — 없으면 토큰(C_s)과 가명이 다른 세션 것일 수 있다
//   ⑥ 등록부: Poseidon(auid, Cf_u) ∈ Tree(regRoot)(깊이 20) · 폐기: Poseidon(5, Cf_s) ∉ Tree(revRoot)(IMT 32)
//      — 없으면 미등록·관리자 바꿔치기·은퇴한 자격증명, 폐기된 세션이 통과한다
//   ⑦ C_s = pk_i·G_PK + max_height·G_EXP + r_s·G_RS + r_rp·H — r_s(공개)·max_height(공개)·pk_i(공개) 가 토큰의 Cf_s 에 묶인다(재전송 방지: RP 가 r_s 를 1회 소비)
//   ⑧ tag = Enc(pk_trace, Poseidon(uid, arid); ρ), ρ ≠ 0 — 없으면 개봉이 엉뚱한 값을 연다
//
//   attrs[6] 는 C_u 에만 실린다 — IdP 는 값을 모른다(D15). 공개 입력은 AA(IdP)·RP·체인이 모두 보므로 uid·s_u·r_rp 는 어디에도 평문으로 없다.
//   auid_s·arid_s·r_s 는 공개 입력 끝(30·31·32)에 붙었다 — 색인 0~29 는 V9 와 같아 contracts/Mode3Wallet.sol 의 꼬리 15워드·다이제스트가 불변이다(D12).
template PiCred(depth, regDepth) {
    // ---- Private ----
    signal input uid;
    signal input s_u;
    signal input blind_u;
    signal input r_rp;       // V11: RP 난수 — auid_s·arid_s·C_s 블라인딩을 하나로 묶는다(⑤)
    signal input attrs[6];
    signal input r;

    signal input S;
    signal input R8x;
    signal input R8y;

    // V8 세션 리프 비멤버십 증인(폐기 트리)
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

    // ---- Public (순서 = lib/mode3_wallet.js·lib/mode3_rp.js·lib/mode3_onchain.js PUB_INDEX·contracts/Mode3Wallet.sol 의 계약) ----
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
    signal input auid_s;     // V11 [30]
    signal input arid_s;     // V11 [31]
    signal input r_s;        // V11 [32]

    var DOMAIN_MODE3_CRED_V11 = 23926173293433188795270181169;   // ASCII "MODE3CREDV11" — lib/mode3_credential.js DOMAIN_MODE3_CRED_V11
    var DOMAIN_MODE3_AUID  = 1426111059989489862980;             // "MODE3AUID"
    var DOMAIN_MODE3_AUIDS = 365084431357309404922963;           // "MODE3AUIDS"
    var DOMAIN_MODE3_ARIDS = 365084431357309354591315;           // "MODE3ARIDS"
    var TAG_MODE3_SESSION = 5;

    // ---- 커밋 둘 ----
    component cu = CommitUser();
    cu.uid <== uid;  cu.s_u <== s_u;  cu.blind_u <== blind_u;
    for (var j = 0; j < 6; j++) cu.attrs[j] <== attrs[j];
    component cfu = Poseidon(2);
    cfu.inputs[0] <== cu.Cx;  cfu.inputs[1] <== cu.Cy;
    signal Cf_u;
    Cf_u <== cfu.out;
    // ⑦ C_s 는 공개 입력 pk_i·max_height·r_s 와 비공개 r_rp 로 **직접 계산**한다 — 다른 값을 넣으면 토큰 서명이 깨진다.
    //    pk_i 160비트·max_height 64비트 범위는 CommitSessionV11 안의 Num2Bits 가 잡는다(옛 pkIRange·mhRange 를 대신한다).
    component cs = CommitSessionV11();
    cs.pk_i <== pk_i;  cs.max_height <== max_height;  cs.r_s <== r_s;  cs.r_rp <== r_rp;
    component cfs = Poseidon(2);
    cfs.inputs[0] <== cs.Cx;  cfs.inputs[1] <== cs.Cy;
    signal Cf_s;
    Cf_s <== cfs.out;

    // ---- ② ID 정확성 (⑤: 같은 r_rp 신호) ----
    component ah = Poseidon(3);
    ah.inputs[0] <== DOMAIN_MODE3_AUID;  ah.inputs[1] <== uid;  ah.inputs[2] <== s_u;
    signal auid;
    auid <== ah.out;
    component ash = Poseidon(4);
    ash.inputs[0] <== DOMAIN_MODE3_AUIDS;  ash.inputs[1] <== auid;  ash.inputs[2] <== arid;  ash.inputs[3] <== r_rp;
    auid_s === ash.out;
    component arh = Poseidon(3);
    arh.inputs[0] <== DOMAIN_MODE3_ARIDS;  arh.inputs[1] <== arid;  arh.inputs[2] <== r_rp;
    arid_s === arh.out;

    // ---- ① 토큰 ----
    allowAgent * (allowAgent - 1) === 0;
    component msgHasher = Poseidon(7);
    msgHasher.inputs[0] <== DOMAIN_MODE3_CRED_V11;
    msgHasher.inputs[1] <== auid_s;
    msgHasher.inputs[2] <== arid_s;
    msgHasher.inputs[3] <== Cf_u;
    msgHasher.inputs[4] <== Cf_s;
    msgHasher.inputs[5] <== chainid;
    msgHasher.inputs[6] <== allowAgent;
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== pk_CIA_x;
    sigVerifier.Ay <== pk_CIA_y;
    sigVerifier.S <== S;
    sigVerifier.R8x <== R8x;
    sigVerifier.R8y <== R8y;
    sigVerifier.M <== msgHasher.out;

    // ---- ③ PPID (D13 순서) ----
    // chainid 는 토큰 메시지에도 들어가는 같은 공개 입력이라, 토큰이 보증하는 체인과 가명의 체인이 어긋날 수 없다.
    component ppidHasher = Poseidon(4);
    ppidHasher.inputs[0] <== uid;
    ppidHasher.inputs[1] <== s_u;
    ppidHasher.inputs[2] <== arid;
    ppidHasher.inputs[3] <== chainid;
    PPID === ppidHasher.out;

    // ---- ⑥ 세션 비멤버십 (폐기 트리) ----
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

    // ---- ⑥ 등록부 멤버십 (V11 리프 Poseidon(auid, Cf_u)) ----
    // auid 는 ② 와 같은 신호 — 등록 때 낸 가명의 salt 와 지금 PPID 의 salt 가 같다는 뜻이다. 회로가 비공개 입력에서
    // 직접 계산하므로 증명자가 다른 리프를 제시할 수 없다.
    component regLeaf = Poseidon(2);
    regLeaf.inputs[0] <== auid;  regLeaf.inputs[1] <== Cf_u;
    component inc = MerkleInclusion(regDepth);
    inc.leaf <== regLeaf.out;
    for (var i = 0; i < regDepth; i++) {
        inc.pathElements[i] <== reg_pathElements[i];
        inc.pathIndices[i] <== reg_pathIndices[i];
    }
    inc.root === regRoot;

    // ---- ⑧ 트레이스 태그 ----
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

    // ---- ④ 선택 공개 (슬롯 6) ----
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

    // ---- ④ 집합 소속 (set_sel ∈ {0..6}) ----
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

// 공개 입력의 순서는 lib/mode3_wallet.js·lib/mode3_rp.js·lib/mode3_onchain.js(PUB_INDEX)·cia.js(개봉)·contracts/Mode3Wallet.sol 가 의존한다. 바꾸지 말 것.
// pk_CIA_x/y 와 pk_trace_x/y 는 공개 입력이다. 검증자는 반드시 전자를 고정된 CIA 키와, 후자를 자기 등록 파일의 조합 키와 비교해야 한다.
// [0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot [7] regRoot [8,9] pk_CIA [10,11] pk_trace
// [12..14] tag [15] disc_mask [16..21] disc_lo [22..27] disc_hi [28] set_sel [29] set_root [30] auid_s [31] arid_s [32] r_s
component main {public [
    PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, regRoot, pk_CIA_x, pk_CIA_y,
    pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2,
    disc_mask, disc_lo, disc_hi, set_sel, set_root,
    auid_s, arid_s, r_s
]} = PiCred(32, 20);
