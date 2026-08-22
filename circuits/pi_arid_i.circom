pragma circom 2.0.0;

include "lib/poseidon.circom";
include "lib/eddsaposeidon.circom";

template PiAridI() {
    // Private Inputs (hidden from verifier)
    signal input rp_nonce;
    signal input salt;
    signal input rid;
    signal input pk_i;
    signal input origin;
    signal input rp_reg_S;
    signal input rp_reg_R8x;
    signal input rp_reg_R8y;

    // Public Inputs
    signal input uid;
    signal input arid_i;
    signal input auid_i;
    signal input max_height;
    signal input token_nonce;
    signal input auid;
    signal input pk_IdP_x;
    signal input pk_IdP_y;

    // ppid = Poseidon(uid, rid, salt)
    component ppidHasher = Poseidon(3);
    ppidHasher.inputs[0] <== uid;
    ppidHasher.inputs[1] <== rid;
    ppidHasher.inputs[2] <== salt;
    signal ppid;
    ppid <== ppidHasher.out;

    // rid/origin stay pure private witnesses — this doesn't prove "this rid
    // belongs to the origin the RP claims" (the wallet's own
    // verifyRpCredential() + A7's origin binding already cover that off-chain,
    // before this proof is even built). What this DOES add: proof that the
    // prover holds an IdP-issued RP_REG credential (EdDSA-Poseidon signature)
    // for *some* rid/origin pair, without revealing which — so the IdP isn't
    // signing pseudonym tokens for wallets that never went through any
    // registered RP at all. pk_IdP_x/y are public so the IdP can confirm the
    // signature was checked against its own real key, not a self-chosen one
    // (see custom_idp.js's verifyPiIAndIssueToken).
    //
    // DOMAIN_RP_REG = valueToField('RP_REG'), precomputed in JS (same value
    // custom_idp.js uses to sign the RP registration credential).
    var DOMAIN_RP_REG = 90505150088519;
    component rpRegMsgHasher = Poseidon(3);
    rpRegMsgHasher.inputs[0] <== DOMAIN_RP_REG;
    rpRegMsgHasher.inputs[1] <== rid;
    rpRegMsgHasher.inputs[2] <== origin;

    component rpRegSigVerifier = EdDSAPoseidonVerifier();
    rpRegSigVerifier.enabled <== 1;
    rpRegSigVerifier.Ax <== pk_IdP_x;
    rpRegSigVerifier.Ay <== pk_IdP_y;
    rpRegSigVerifier.S <== rp_reg_S;
    rpRegSigVerifier.R8x <== rp_reg_R8x;
    rpRegSigVerifier.R8y <== rp_reg_R8y;
    rpRegSigVerifier.M <== rpRegMsgHasher.out;

    // arid_i = rid * rp_nonce
    arid_i === rid * rp_nonce;

    // auid_i = ppid * rp_nonce
    auid_i === ppid * rp_nonce;

    // token_nonce = Poseidon(pk_i, max_height, rp_nonce)
    component tokenNonceHasher = Poseidon(3);
    tokenNonceHasher.inputs[0] <== pk_i;
    tokenNonceHasher.inputs[1] <== max_height;
    tokenNonceHasher.inputs[2] <== rp_nonce;
    token_nonce === tokenNonceHasher.out;

    // auid = Poseidon(uid, salt) — a per-account fixed value (no rid, no
    // session nonce) that lets the IdP detect whether this wallet is reusing
    // the same salt across logins. Enforced with === (not <==) so a prover
    // cannot submit an auid that doesn't match the uid/salt actually used
    // elsewhere in this same proof.
    component bindHasher = Poseidon(2);
    bindHasher.inputs[0] <== uid;
    bindHasher.inputs[1] <== salt;
    auid === bindHasher.out;
}

component main {public [uid, arid_i, auid_i, max_height, token_nonce, auid, pk_IdP_x, pk_IdP_y]} = PiAridI();
