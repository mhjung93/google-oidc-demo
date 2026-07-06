
include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/babyjub.circom";

template BindKeyToIdToken() {
    signal input sk;   // private
    signal input h;    // private

    signal input Ax;   // public
    signal input Ay;   // public
    signal input comm; // public

    component mul = BabyJubScalarMul();
    mul.e <== sk;
    mul.base[0] <== BabyJub.Base[0];
    mul.base[1] <== BabyJub.Base[1];

    mul.out[0] === Ax;
    mul.out[1] === Ay;

    component H = Poseidon(2);
    H.inputs[0] <== h;
    H.inputs[1] <== sk;
    H.out === comm;
}

component main = BindKeyToIdToken();
