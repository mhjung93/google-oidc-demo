pragma circom 2.0.0;

include "lib/circom-rsa-verify/circomlib/circuits/escalarmulany.circom";
include "lib/circom-rsa-verify/circomlib/circuits/bitify.circom";

template PiAridI() {
    // Private Input
    signal input r_RP;

    // Public Inputs (Points on BabyJubjub: Ax, Ay)
    signal input rid_x;
    signal input rid_y;
    signal input auid_x;
    signal input auid_y;
    
    signal input arid_i_x;
    signal input arid_i_y;
    signal input auid_i_x;
    signal input auid_i_y;

    // Convert r_RP to bits
    component r_bits = Num2Bits(253);
    r_bits.in <== r_RP;

    // 1. arid_i = rid * r_RP
    component mul1 = EscalarMulAny(253);
    mul1.p[0] <== rid_x;
    mul1.p[1] <== rid_y;
    for (var i=0; i<253; i++) {
        mul1.e[i] <== r_bits.out[i];
    }

    arid_i_x === mul1.out[0];
    arid_i_y === mul1.out[1];

    // 2. auid_i = auid * r_RP
    component mul2 = EscalarMulAny(253);
    mul2.p[0] <== auid_x;
    mul2.p[1] <== auid_y;
    for (var i=0; i<253; i++) {
        mul2.e[i] <== r_bits.out[i];
    }

    auid_i_x === mul2.out[0];
    auid_i_y === mul2.out[1];
}

component main {public [rid_x, rid_y, auid_x, auid_y, arid_i_x, arid_i_y, auid_i_x, auid_i_y]} = PiAridI();
