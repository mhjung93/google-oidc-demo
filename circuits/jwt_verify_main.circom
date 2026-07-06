pragma circom 2.0.0;

include "./lib/circom-rsa-verify/circuits/rsa_verify.circom";

// Added from pseudonym generation
include "circomlib/circuits/poseidon.circom";


//include "./claim_parse.circom";
include "./claim_parse_packed.circom";

// This is the main component that will be compiled.
// It instantiates the RSA verification circuit and wires the inputs.
//
// Parameters:
// w: bits per limb
// nb: number of limbs for modulus/signature
// e_bits: number of limbs for exponent
// hashLen: number of limbs for hash


// Original
template JwtVerifyMain(w, nb, e_bits, hashLen) {
// Added
//template JwtVerifyMain(w, nb, e_bits, hashLen, Lmax, SUB_MAX, AUD_MAX, ISS_MAX, NONCE_MAX) {

    // Added from pseudonym generation
    signal output pseudonym_hash;


// Added from gate compaction of zkLogin
// packed payload
    signal input payload_packed[100]; // NPACK=ceil(1600/16)=100

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

// Added from pseudonym generation
// ---- expose parsed claims (for pseudonym binding circuit) ----
    signal output sub_bytes[128];
    signal output sub_len;

    signal output aud_bytes[128];
    signal output aud_len;

    signal output iss_bytes[128];
    signal output iss_len;

    signal output nonce_bytes[128];
    signal output nonce_len;




// previously 
    signal input exp[nb];

    signal input sign[nb];
    signal input modulus[nb];
    signal input hashed[hashLen];

    component rsa_verify = RsaVerifyPkcs1v15(w, nb, e_bits, hashLen);

// previously e_bits
    for (var i = 0; i < nb; i++) {
        rsa_verify.exp[i] <== exp[i];
    }

    for (var i = 0; i < nb; i++) {
        rsa_verify.sign[i] <== sign[i];
        rsa_verify.modulus[i] <== modulus[i];
    }
    for (var i = 0; i < hashLen; i++) {
        rsa_verify.hashed[i] <== hashed[i];
    }

    // Added from gate compaction from zkLogin
    // K 값: worst-case offset(15) + window 길이를 16으로 나눈 올림
    // SUB/AUD/ISS window: MAX+9 => 128+9=137 => ceil((15+137)/16)=10
    // NONCE window: MAX+11 => 139 => ceil((15+139)/16)=10
    component p = Parse4ClaimsPacked(100, 10, 10, 128, 128, 128, 128);

    for (var i = 0; i < 100; i++) p.payloadPacked[i] <== payload_packed[i];

    for (var i = 0; i < 100; i++) p.sub_chunk_sel[i] <== sub_chunk_sel[i];
    for (var i = 0; i < 16; i++) p.sub_off_sel[i] <== sub_off_sel[i];
    for (var i = 0; i < 128; i++) p.sub_val_sel[i] <== sub_val_sel[i];

    for (var i = 0; i < 100; i++) p.aud_chunk_sel[i] <== aud_chunk_sel[i];
    for (var i = 0; i < 16; i++) p.aud_off_sel[i] <== aud_off_sel[i];
    for (var i = 0; i < 128; i++) p.aud_val_sel[i] <== aud_val_sel[i];

    for (var i = 0; i < 100; i++) p.iss_chunk_sel[i] <== iss_chunk_sel[i];
    for (var i = 0; i < 16; i++) p.iss_off_sel[i] <== iss_off_sel[i];
    for (var i = 0; i < 128; i++) p.iss_val_sel[i] <== iss_val_sel[i];

    for (var i = 0; i < 100; i++) p.nonce_chunk_sel[i] <== nonce_chunk_sel[i];
    for (var i = 0; i < 16; i++) p.nonce_off_sel[i] <== nonce_off_sel[i];
    for (var i = 0; i < 128; i++) p.nonce_val_sel[i] <== nonce_val_sel[i];

    for (var i = 0; i < 128; i++) p.iss_expected[i] <== iss_expected[i];
    p.iss_expected_len <== iss_expected_len;
    for (var i = 0; i < 128; i++) p.aud_expected[i] <== aud_expected[i];
    p.aud_expected_len <== aud_expected_len;


    //Added from pseudonym generation
    // Wire parsed outputs to template outputs
    for (var i = 0; i < 128; i++) {
        sub_bytes[i] <== p.sub_bytes[i];
        aud_bytes[i] <== p.aud_bytes[i];
        iss_bytes[i] <== p.iss_bytes[i];
    }
    sub_len <== p.sub_len;
    aud_len <== p.aud_len;
    iss_len <== p.iss_len;

    // Added from pseudonym generation    
        // ---- pack iss/aud/sub (each 128 bytes -> 8 field chunks)
    component packIss = PackBytes128To8Chunks();
    component packAud = PackBytes128To8Chunks();
    component packSub = PackBytes128To8Chunks();

    for (var i = 0; i < 128; i++) {
        packIss.inBytes[i] <== p.iss_bytes[i];
        packAud.inBytes[i] <== p.aud_bytes[i];
        packSub.inBytes[i] <== p.sub_bytes[i];
    }

    // ---- per-claim digest: Poseidon(9) = 8 chunks + length
    component hIss = Poseidon(9);
    component hAud = Poseidon(9);
    component hSub = Poseidon(9);

    for (var i = 0; i < 8; i++) {
        hIss.inputs[i] <== packIss.chunks[i];
        hAud.inputs[i] <== packAud.chunks[i];
        hSub.inputs[i] <== packSub.chunks[i];
    }
    hIss.inputs[8] <== p.iss_len;
    hAud.inputs[8] <== p.aud_len;
    hSub.inputs[8] <== p.sub_len;

    // ---- salt = "salt" (literal bytes), pad to 16 bytes then pack
    signal saltBytes16[16];
    saltBytes16[0] <== 115; // 's'
    saltBytes16[1] <== 97;  // 'a'
    saltBytes16[2] <== 108; // 'l'
    saltBytes16[3] <== 116; // 't'
    for (var i = 4; i < 16; i++) saltBytes16[i] <== 0;

    component packSalt = PackBytes16LE();
    for (var i = 0; i < 16; i++) packSalt.b[i] <== saltBytes16[i];

    // ---- final pseudonym = Poseidon(5)(domainSep, hIss, hAud, hSub, saltPacked)
    // domainSep는 "이 해시가 pseudonym용"이라는 구분(충돌 방지)용 상수
    component hFinal = Poseidon(5);
    hFinal.inputs[0] <== 1;               // domainSep = 1
    hFinal.inputs[1] <== hIss.out;
    hFinal.inputs[2] <== hAud.out;
    hFinal.inputs[3] <== hSub.out;
    hFinal.inputs[4] <== packSalt.out;

    pseudonym_hash <== hFinal.out;

}

// Instantiate the main component with parameters matching make_proof.js
// w = 64, nb = 32 (2048 bits total), e_bits = 32, hashLen = 4 (256 bits total)

// Original
//component main = JwtVerifyMain(64, 32, 17, 4);
//component main = JwtVerifyMain(64, 32, 17, 4, 1500, 128, 256, 128, 256);


