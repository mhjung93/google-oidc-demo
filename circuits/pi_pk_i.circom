pragma circom 2.0.0;

include "lib/eddsaposeidon.circom";
include "lib/poseidon.circom";

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

    // Public inputs
    signal input pk_i;
    signal input pk_IdP_x;
    signal input pk_IdP_y;
    signal input PPID;
    signal input max_height;

    // DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN'), precomputed in JS (same value
    // custom_idp.js/server.js/wallet_agent.js already use for auth token signing/verifying).
    var DOMAIN_IDP_TOKEN = 1351534856589225444686;

    // auid_i = PPID * rp_nonce
    auid_i === PPID * rp_nonce;

    // r_token = Poseidon(pk_i, max_height, rp_nonce)  (same formula as the existing
    // Step 8 tokenNonce computation)
    component tokenNonceHasher = Poseidon(3);
    tokenNonceHasher.inputs[0] <== pk_i;
    tokenNonceHasher.inputs[1] <== max_height;
    tokenNonceHasher.inputs[2] <== rp_nonce;
    r_token === tokenNonceHasher.out;

    // msg = Poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id])
    // (same 6-field construction custom_idp.js uses to sign the auth token)
    component msgHasher = Poseidon(6);
    msgHasher.inputs[0] <== DOMAIN_IDP_TOKEN;
    msgHasher.inputs[1] <== arid_i;
    msgHasher.inputs[2] <== auid_i;
    msgHasher.inputs[3] <== r_token;
    msgHasher.inputs[4] <== max_height;
    msgHasher.inputs[5] <== chain_id;

    // SigVerify(pk_IdP, sigma_i) == True
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== pk_IdP_x;
    sigVerifier.Ay <== pk_IdP_y;
    sigVerifier.S <== S;
    sigVerifier.R8x <== R8x;
    sigVerifier.R8y <== R8y;
    sigVerifier.M <== msgHasher.out;
}

component main {public [pk_i, pk_IdP_x, pk_IdP_y, PPID, max_height]} = PiPkI();
