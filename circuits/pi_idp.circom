pragma circom 2.0.0;

include "lib/poseidon.circom";
include "lib/mode3_commit.circom";

// π_IdP — V11(스펙 2026-10-12 §4, 덱 6장). 세션(토큰 발급)마다 지갑이 IdP 에 낸다(D2).
// IdP 는 서명하기 전에 **uid·salt 관계와 세션 바인딩**만 본다 — 속성 값은 보지 않는다(D15: attrs 는 64비트 범위만).
//   ① C_u = uid·G_UID + s_u·G_SU + Σ attrs·G_ATTR + blind_u·H     (CommitUser 재사용)
//   ② auid   = Poseidon(T_AUID2, s_u)                            — IdP DB 의 auid 와 같은가(2026-11-13 스펙 random-salt R10: uid 를 뺐다 — uid 와의 묶음은 ① C_u 와 IdP 의 계정 대조)
//   ③ auid_s = Poseidon(T_AUIDS, auid, arid, r_rp)               — 토큰에 들어갈 세션 가명이 정형인가(D3·D7)
//   ④ C_s = pk_i·G_PK + max_height·G_EXP + r_s·G_RS + r_rp·H      — ③ 과 **같은 r_rp**(세션 가명과 세션 커밋의 결합)
//   ⑤ tag = Poseidon(T_TAG, s_u, ctx)                             — 이 증명을 요청(ctx)에 묶는다(스펙 2026-11-12 no-pk-u §2). ctx 의 내용은 회로 밖.
// 비공개: s_u, blind_u, attrs[6], arid, r_rp, pk_i, r_s — arid·r_rp 가 비공개라 IdP 는 RP 를 알아보지 못한다(G4).
// 공개 입력 순서는 lib/mode3_idp_proof.js IDP_PUB_INDEX 와 cia.js 의 조립 순서가 의존한다. 바꾸지 말 것:
//   [0] uid [1] auid [2] auid_s [3] C_u_x [4] C_u_y [5] C_s_x [6] C_s_y [7] max_height [8] ctx [9] tag
// 온체인에 가지 않는다(IdP 만 검증, §6).
template PiIdp() {
    // ---- Private ----
    signal input s_u;
    signal input blind_u;
    signal input attrs[6];
    signal input arid;
    signal input r_rp;
    signal input pk_i;
    signal input r_s;
    // ---- Public (선언 순서 = witness 순서) ----
    signal input uid;
    signal input auid;
    signal input auid_s;
    signal input C_u_x;
    signal input C_u_y;
    signal input C_s_x;
    signal input C_s_y;
    signal input max_height;
    signal input ctx;
    signal input tag;

    var DOMAIN_MODE3_AUID  = 365084431357309404922930;   // ASCII "MODE3AUID2" — lib/mode3_credential.js DOMAIN_MODE3_AUID (2026-11-13: uid 를 뺀 새 정의)
    var DOMAIN_MODE3_AUIDS = 365084431357309404922963;   // ASCII "MODE3AUIDS" — DOMAIN_MODE3_AUIDS
    var DOMAIN_MODE3_TAG   = 5570746328085184839;        // ASCII "MODE3TAG"   — DOMAIN_MODE3_TAG

    // ① C_u 재계산
    component cu = CommitUser();
    cu.uid <== uid;  cu.s_u <== s_u;  cu.blind_u <== blind_u;
    for (var j = 0; j < 6; j++) cu.attrs[j] <== attrs[j];
    C_u_x === cu.Cx;
    C_u_y === cu.Cy;

    // ② auid — 스냅(salt)의 가명. uid 는 여기 없다.
    component ah = Poseidon(2);
    ah.inputs[0] <== DOMAIN_MODE3_AUID;  ah.inputs[1] <== s_u;
    auid === ah.out;

    // ③ auid_s
    component ash = Poseidon(4);
    ash.inputs[0] <== DOMAIN_MODE3_AUIDS;  ash.inputs[1] <== auid;  ash.inputs[2] <== arid;  ash.inputs[3] <== r_rp;
    auid_s === ash.out;

    // ④ C_s 재계산 — 같은 r_rp
    component cs = CommitSessionV11();
    cs.pk_i <== pk_i;  cs.max_height <== max_height;  cs.r_s <== r_s;  cs.r_rp <== r_rp;
    C_s_x === cs.Cx;
    C_s_y === cs.Cy;

    // ⑤ tag — ② 와 같은 s_u. ctx 는 공개 입력으로만 들어온다.
    component th = Poseidon(3);
    th.inputs[0] <== DOMAIN_MODE3_TAG;  th.inputs[1] <== s_u;  th.inputs[2] <== ctx;
    tag === th.out;
}

component main {public [uid, auid, auid_s, C_u_x, C_u_y, C_s_x, C_s_y, max_height, ctx, tag]} = PiIdp();
