pragma circom 2.0.0;

include "lib/eddsaposeidon.circom";
include "lib/poseidon.circom";
include "lib/imt_nonmembership.circom";

template PiPkI() {
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

    // Private inputs — 세션 비멤버십 witness
    signal input sess_lowValue;
    signal input sess_lowNextValue;
    signal input sess_pathElements[20];
    signal input sess_pathIndices[20];

    // Private inputs — 계정 비멤버십 witness
    signal input acct_lowValue;
    signal input acct_lowNextValue;
    signal input acct_pathElements[20];
    signal input acct_pathIndices[20];

    // Public inputs
    signal input pk_i;
    signal input pk_IdP_x;
    signal input pk_IdP_y;
    signal input PPID;
    signal input max_height;
    signal input revocationRoot;

    var DOMAIN_IDP_TOKEN = 1351534856589225444686;
    var TAG_SESSION = 1;
    var TAG_ACCOUNT = 2;

    // auid_i = PPID * rp_nonce
    auid_i === PPID * rp_nonce;

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
    // PPID가 이 uid/rid/salt에서 나왔음을 보인다. 이게 없으면 사용자가
    // 폐기되지 않은 남의 auid를 가져다 쓸 수 있다.
    //
    // pi_ppid.circom 이 같은 관계를 이미 증명하지만 그 중복은 의도된 것이다:
    // pi_ppid 는 로그인 시 IdP 가 오프체인으로 검증하고, 이 회로는 온체인
    // 컨트랙트가 검증한다. 서로 다른 신뢰 경계에 있으므로 온체인 증명은
    // 독립적으로 바인딩해야 하며, 한쪽을 믿고 생략할 수 없다.
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

    // ---- 폐기 비멤버십 ----
    component sessLeaf = Poseidon(2);
    sessLeaf.inputs[0] <== TAG_SESSION;
    sessLeaf.inputs[1] <== r_token;

    component sessNM = IMTNonMembership(20);
    sessNM.target <== sessLeaf.out;
    sessNM.lowValue <== sess_lowValue;
    sessNM.lowNextValue <== sess_lowNextValue;
    for (var i = 0; i < 20; i++) {
        sessNM.pathElements[i] <== sess_pathElements[i];
        sessNM.pathIndices[i] <== sess_pathIndices[i];
    }
    sessNM.root <== revocationRoot;

    component acctLeaf = Poseidon(2);
    acctLeaf.inputs[0] <== TAG_ACCOUNT;
    acctLeaf.inputs[1] <== auid;

    component acctNM = IMTNonMembership(20);
    acctNM.target <== acctLeaf.out;
    acctNM.lowValue <== acct_lowValue;
    acctNM.lowNextValue <== acct_lowNextValue;
    for (var i = 0; i < 20; i++) {
        acctNM.pathElements[i] <== acct_pathElements[i];
        acctNM.pathIndices[i] <== acct_pathIndices[i];
    }
    acctNM.root <== revocationRoot;
}

component main {public [pk_i, pk_IdP_x, pk_IdP_y, PPID, max_height, revocationRoot]} = PiPkI();
