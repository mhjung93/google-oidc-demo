pragma circom 2.0.0;

include "lib/eddsaposeidon.circom";
include "lib/poseidon.circom";
include "lib/imt_nonmembership_v3.circom";
include "lib/bitify.circom";

// pi_pk_i — 이중 트리(샤딩) 판. circuits/pi_pk_i.circom 과 나란히 둔다.
//
// 설계: docs/superpowers/specs/2026-09-05-revocation-dual-tree-design.md
//
// 현행(pi_pk_i.circom)과의 차이는 폐기 비멤버십 부분뿐이다. 나머지(auid_i 관계, pk_i
// 160비트 제약, r_token, IdP EdDSA 서명, PPID/auid 계정 바인딩)는 한 글자도 바뀌지
// 않았다 — 바뀐 것은 "어느 트리에 대해 비멤버십을 보이는가" 하나다.
//
//   현행: 깊이 20 트리 하나, public signal revocationRoot 1개
//   v3  : 세션 깊이 8 서브트리 + 계정 깊이 10 서브트리, 각각의 root와 샤드 인덱스
//
// 왜 나누는가. 지금은 폐기가 하나만 게시돼도 revocationRoot가 바뀌어 **전 지갑의 증명이
// 동시에 죽는다**(설계 문서 1절 Case 2). 트리를 샤드로 쪼개면 증명은 자기 서브트리의
// root에만 묶이므로, 다른 샤드의 폐기에는 살아남는다. 상위 트리는 회로 밖(컨트랙트,
// keccak)에서 검증하므로 여기 들어오지 않는다.
//
// 샤딩 기준이 층마다 다르다(설계 문서 3.2/3.3):
//   세션 — (max_height mod 512) * 8 + L_sess 하위 3비트.
//          상위(만료) 축은 컨트랙트가 max_height로 직접 계산하므로 회로는 하위 3비트만
//          고정한다. 그래서 여기 public signal은 sess_shard_low(3비트)다.
//   계정 — L_acct 하위 8비트. 계정 폐기의 만료는 증명자가 모르므로 값에서 유도한다.
//
// 건전성: 두 NM 인스턴스의 shardIndex 출력을 public signal과 === 로 묶는 것이 핵심이다.
// 이게 없으면 증명자가 **비어 있는 서브트리**를 골라 제시해 폐기를 통째로 우회한다
// (설계 문서 4절 조건 1·3).
template PiPkIV3() {
    // Private inputs
    signal input rp_nonce;
    signal input arid_i;
    signal input auid_i;
    signal input r_token;
    signal input chain_id;
    signal input S;
    signal input R8x;
    signal input R8y;

    // Private inputs — 계정 바인딩용
    signal input uid;
    signal input rid;
    signal input salt;

    // Private inputs — 세션 비멤버십 witness (서브트리 깊이 8)
    signal input sess_lowValue;
    signal input sess_lowNextIndex;
    signal input sess_lowNextValue;
    signal input sess_pathElements[8];
    signal input sess_pathIndices[8];

    // Private inputs — 계정 비멤버십 witness (서브트리 깊이 10)
    signal input acct_lowValue;
    signal input acct_lowNextIndex;
    signal input acct_lowNextValue;
    signal input acct_pathElements[10];
    signal input acct_pathIndices[10];

    // Public inputs
    signal input pk_i;
    signal input pk_IdP_x;
    signal input pk_IdP_y;
    signal input PPID;
    signal input max_height;
    signal input sess_root;
    signal input sess_shard_low;
    signal input acct_root;
    signal input acct_shard;

    var DOMAIN_IDP_TOKEN = 1351534856589225444686;
    var TAG_SESSION = 1;
    var TAG_ACCOUNT = 2;
    var SESS_SHARD_BITS = 3;   // 값 축. 만료 축은 컨트랙트가 담당한다.
    var ACCT_SHARD_BITS = 12;  // 4,096칸 (2026-09-07: 256에서 상향)

    // auid_i = PPID * rp_nonce
    auid_i === PPID * rp_nonce;

    // pk_i는 160비트를 넘을 수 없다 (근거는 pi_pk_i.circom 주석 참조 — 형제 크레덴셜 구멍).
    component pkIRange = Num2Bits(160);
    pkIRange.in <== pk_i;

    // r_token = Poseidon(pk_i, max_height, rp_nonce)
    component tokenNonceHasher = Poseidon(3);
    tokenNonceHasher.inputs[0] <== pk_i;
    tokenNonceHasher.inputs[1] <== max_height;
    tokenNonceHasher.inputs[2] <== rp_nonce;
    r_token === tokenNonceHasher.out;

    // msg = Poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id])
    component msgHasher = Poseidon(6);
    msgHasher.inputs[0] <== DOMAIN_IDP_TOKEN;
    msgHasher.inputs[1] <== arid_i;
    msgHasher.inputs[2] <== auid_i;
    msgHasher.inputs[3] <== r_token;
    msgHasher.inputs[4] <== max_height;
    msgHasher.inputs[5] <== chain_id;

    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== pk_IdP_x;
    sigVerifier.Ay <== pk_IdP_y;
    sigVerifier.S <== S;
    sigVerifier.R8x <== R8x;
    sigVerifier.R8y <== R8y;
    sigVerifier.M <== msgHasher.out;

    // ---- 계정 바인딩 ----
    component ppidHasher = Poseidon(3);
    ppidHasher.inputs[0] <== uid;
    ppidHasher.inputs[1] <== rid;
    ppidHasher.inputs[2] <== salt;
    PPID === ppidHasher.out;

    signal auid;
    component auidHasher = Poseidon(2);
    auidHasher.inputs[0] <== uid;
    auidHasher.inputs[1] <== salt;
    auid <== auidHasher.out;

    // ---- 세션 비멤버십 (샤드 하나) ----
    component sessLeaf = Poseidon(2);
    sessLeaf.inputs[0] <== TAG_SESSION;
    sessLeaf.inputs[1] <== r_token;

    component sessNM = IMTNonMembershipV3(8, SESS_SHARD_BITS);
    sessNM.target <== sessLeaf.out;
    sessNM.lowValue <== sess_lowValue;
    sessNM.lowNextIndex <== sess_lowNextIndex;
    sessNM.lowNextValue <== sess_lowNextValue;
    for (var i = 0; i < 8; i++) {
        sessNM.pathElements[i] <== sess_pathElements[i];
        sessNM.pathIndices[i] <== sess_pathIndices[i];
    }
    sessNM.root <== sess_root;
    // 값 축 고정. 만료 축(max_height mod 512)은 컨트랙트가 검증한다 — 둘 다 있어야
    // 샤드가 확정된다(설계 문서 4절 조건 2·3).
    sessNM.shardIndex === sess_shard_low;

    // ---- 계정 비멤버십 (샤드 하나) ----
    component acctLeaf = Poseidon(2);
    acctLeaf.inputs[0] <== TAG_ACCOUNT;
    acctLeaf.inputs[1] <== auid;

    component acctNM = IMTNonMembershipV3(10, ACCT_SHARD_BITS);
    acctNM.target <== acctLeaf.out;
    acctNM.lowValue <== acct_lowValue;
    acctNM.lowNextIndex <== acct_lowNextIndex;
    acctNM.lowNextValue <== acct_lowNextValue;
    for (var i = 0; i < 10; i++) {
        acctNM.pathElements[i] <== acct_pathElements[i];
        acctNM.pathIndices[i] <== acct_pathIndices[i];
    }
    acctNM.root <== acct_root;
    acctNM.shardIndex === acct_shard;
}

component main {public [
    pk_i, pk_IdP_x, pk_IdP_y, PPID, max_height,
    sess_root, sess_shard_low, acct_root, acct_shard
]} = PiPkIV3();
