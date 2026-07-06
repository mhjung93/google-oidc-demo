pragma circom 2.0.0;

include "./jwt_verify_main.circom";

include "circuits/lib/circom-rsa-verify/circomlib/circuits/poseidon.circom";
include "circuits/lib/circom-rsa-verify/circomlib/circuits/babyjub.circom";

//include "circomlib/circuits/poseidon.circom";
//include "circomlib/circuits/babyjub.circom";

// ---- helpers: pack 16 bytes (LE) into a field element (<2^128) ----
template PackBytes16LE() {
    signal input b[16];      // each is 0..255
    signal output out;       // < 2^128

    var acc = 0;
    var pow = 1;
    for (var i = 0; i < 16; i++) {
        acc += b[i] * pow;
        pow = pow * 256;
    }
    out <== acc;
}

template PackBytes128To8Chunks() {
    signal input inBytes[128];   // zero-padded
    signal output chunks[8];     // each chunk packs 16 bytes (LE)

    component p[8];
    for (var c = 0; c < 8; c++) {
        p[c] = PackBytes16LE();
        for (var j = 0; j < 16; j++) {
            p[c].b[j] <== inBytes[c*16 + j];
        }
        chunks[c] <== p[c].out;
    }
}

template BindKeyToIdToken() {
    // ---- private ----
    // sk is derived inside from JWT claims, not taken as input.

    // ---- JWT verify / claim parse inputs (make_proof.js와 동일 이름/크기) ----
    signal input payload_packed[100];

    signal input sub_chunk_sel[100];
    signal input sub_off_sel[16];
    signal input sub_val_sel[128];

    signal input aud_chunk_sel[100];
    signal input aud_off_sel[16];
    signal input aud_val_sel[128];

    signal input iss_chunk_sel[100];
    signal input iss_off_sel[16];
    signal input iss_val_sel[128];

    signal input nonce_chunk_sel[100];
    signal input nonce_off_sel[16];
    signal input nonce_val_sel[128];

    signal input iss_expected[128];
    signal input iss_expected_len;
    signal input aud_expected[128];
    signal input aud_expected_len;

    signal input exp[32];
    signal input sign[32];
    signal input modulus[32];
    signal input hashed[4];

    // ---- public outputs ----
    signal output Ax;
    signal output Ay;

    // 1) JWT signature verify + claim parsing (iss/aud enforcement 포함)
    component jwt = JwtVerifyMain(64, 32, 17, 4);

    for (var i = 0; i < 100; i++) jwt.payload_packed[i] <== payload_packed[i];

    for (var i = 0; i < 100; i++) jwt.sub_chunk_sel[i] <== sub_chunk_sel[i];
    for (var i = 0; i < 16; i++)  jwt.sub_off_sel[i] <== sub_off_sel[i];
    for (var i = 0; i < 128; i++) jwt.sub_val_sel[i] <== sub_val_sel[i];

    for (var i = 0; i < 100; i++) jwt.aud_chunk_sel[i] <== aud_chunk_sel[i];
    for (var i = 0; i < 16; i++)  jwt.aud_off_sel[i] <== aud_off_sel[i];
    for (var i = 0; i < 128; i++) jwt.aud_val_sel[i] <== aud_val_sel[i];

    for (var i = 0; i < 100; i++) jwt.iss_chunk_sel[i] <== iss_chunk_sel[i];
    for (var i = 0; i < 16; i++)  jwt.iss_off_sel[i] <== iss_off_sel[i];
    for (var i = 0; i < 128; i++) jwt.iss_val_sel[i] <== iss_val_sel[i];

    for (var i = 0; i < 100; i++) jwt.nonce_chunk_sel[i] <== nonce_chunk_sel[i];
    for (var i = 0; i < 16; i++)  jwt.nonce_off_sel[i] <== nonce_off_sel[i];
    for (var i = 0; i < 128; i++) jwt.nonce_val_sel[i] <== nonce_val_sel[i];

    for (var i = 0; i < 128; i++) jwt.iss_expected[i] <== iss_expected[i];
    jwt.iss_expected_len <== iss_expected_len;

    for (var i = 0; i < 128; i++) jwt.aud_expected[i] <== aud_expected[i];
    jwt.aud_expected_len <== aud_expected_len;

    for (var i = 0; i < 32; i++) jwt.exp[i] <== exp[i];
    for (var i = 0; i < 32; i++) jwt.sign[i] <== sign[i];
    for (var i = 0; i < 32; i++) jwt.modulus[i] <== modulus[i];
    for (var i = 0; i < 4;  i++) jwt.hashed[i] <== hashed[i];

    // 2) Derive deterministic sk from Hash(iss, aud, sub, "salt")
    component packIss = PackBytes128To8Chunks();
    component packAud = PackBytes128To8Chunks();
    component packSub = PackBytes128To8Chunks();

    for (var i = 0; i < 128; i++) {
        packIss.inBytes[i] <== jwt.iss_bytes[i];
        packAud.inBytes[i] <== jwt.aud_bytes[i];
        packSub.inBytes[i] <== jwt.sub_bytes[i];
    }

    // per-claim digest: Poseidon(9) = 8 chunks + len
    component hIss = Poseidon(9);
    component hAud = Poseidon(9);
    component hSub = Poseidon(9);

    for (var i = 0; i < 8; i++) {
        hIss.inputs[i] <== packIss.chunks[i];
        hAud.inputs[i] <== packAud.chunks[i];
        hSub.inputs[i] <== packSub.chunks[i];
    }
    hIss.inputs[8] <== jwt.iss_len;
    hAud.inputs[8] <== jwt.aud_len;
    hSub.inputs[8] <== jwt.sub_len;

    // salt = "salt" (상수 문자열 그대로)
    signal saltBytes16[16];
    saltBytes16[0] <== 115; // 's'
    saltBytes16[1] <== 97;  // 'a'
    saltBytes16[2] <== 108; // 'l'
    saltBytes16[3] <== 116; // 't'
    for (var i = 4; i < 16; i++) saltBytes16[i] <== 0;

    component packSalt = PackBytes16LE();
    for (var i = 0; i < 16; i++) packSalt.b[i] <== saltBytes16[i];

    // final hash becomes the internal secret key (domainSep=1)
    component hFinal = Poseidon(5);
    hFinal.inputs[0] <== 1;
    hFinal.inputs[1] <== hIss.out;
    hFinal.inputs[2] <== hAud.out;
    hFinal.inputs[3] <== hSub.out;
    hFinal.inputs[4] <== packSalt.out;

    signal sk_internal;
    sk_internal <== hFinal.out;

    // 3) pk = sk_internal*G (BabyJub)
    component pbk = BabyPbk();
    pbk.in <== sk_internal;

    // 4) Constrain public outputs to be the derived public key
    Ax <== pbk.Ax;
    Ay <== pbk.Ay;
}

// public 신호 지정
component main = BindKeyToIdToken();
