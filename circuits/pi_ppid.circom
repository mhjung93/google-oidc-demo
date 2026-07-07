pragma circom 2.0.0;

template PiPPID() {
    // Private Inputs (hidden from verifier)
    signal input uid;
    signal input salt;

    // Public Inputs
    signal input rid;
    signal input ppid;

    // PPID = uid * rid * salt (degree-3, split into two quadratic constraints)
    signal uid_rid;
    uid_rid <== uid * rid;
    ppid === uid_rid * salt;
}

component main {public [rid, ppid]} = PiPPID();
