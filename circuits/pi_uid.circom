pragma circom 2.0.0;

include "lib/circom-rsa-verify/circomlib/circuits/poseidon.circom";

// Simplified Ownership Proof using Poseidon Commitment
// commitment = Poseidon(uid, secret)
template PiUid() {
    // Private Inputs
    signal input uid;
    signal input secret;

    // Public Input
    signal input commitment;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== uid;
    hasher.inputs[1] <== secret;

    commitment === hasher.out;
}

component main {public [commitment]} = PiUid();
