pragma circom 2.0.0;

include "lib/circom-rsa-verify/circomlib/circuits/poseidon.circom";

template PiPPID() {
    // Private Inputs (hidden from verifier)
    signal input uid;
    signal input salt;

    // Public Inputs
    signal input rid;
    signal input ppid;

    // ppid = Poseidon(uid, rid, salt)
    component hasher = Poseidon(3);
    hasher.inputs[0] <== uid;
    hasher.inputs[1] <== rid;
    hasher.inputs[2] <== salt;
    ppid === hasher.out;
}

component main {public [rid, ppid]} = PiPPID();
