pragma circom 2.0.0;

include "lib/circom-rsa-verify/circomlib/circuits/poseidon.circom";

template PiAridI() {
    // Private Inputs (hidden from verifier)
    signal input rp_nonce;
    signal input salt;
    signal input rid;
    signal input pk_i;

    // Public Inputs
    signal input uid;
    signal input arid_i;
    signal input auid_i;
    signal input max_height;
    signal input token_nonce;
    signal input auid;

    // ppid = Poseidon(uid, rid, salt)
    component ppidHasher = Poseidon(3);
    ppidHasher.inputs[0] <== uid;
    ppidHasher.inputs[1] <== rid;
    ppidHasher.inputs[2] <== salt;
    signal ppid;
    ppid <== ppidHasher.out;

    // rid stays a pure private witness. The IdP no longer checks anything
    // about it — the RP backend independently verifies arid_i === rid *
    // rp_nonce using its own known rid and rp_nonce (see server.js), which is
    // sufficient to reject a bogus/unregistered rid without the IdP ever
    // needing to see or verify rid.

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

component main {public [uid, arid_i, auid_i, max_height, token_nonce, auid]} = PiAridI();
