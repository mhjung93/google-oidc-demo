pragma circom 2.0.0;

template AssertBool() {
    signal input b;
    b * (b - 1) === 0;
}

template OneHot(n) {
    signal input sel[n];
    component ab[n];
    var s = 0;
    for (var i = 0; i < n; i++) {
        ab[i] = AssertBool();
        ab[i].b <== sel[i];
        s += sel[i];
    }
    s === 1;
}

template PrefixOnes(n) {
    signal input sel[n];
    component ab[n];
    for (var i = 0; i < n; i++) {
        ab[i] = AssertBool();
        ab[i].b <== sel[i];
        if (i + 1 < n) {
            sel[i + 1] * (1 - sel[i]) === 0;
        }
    }
    sel[0] === 1;
}

// unpack 128-bit packed element into 16 bytes (little-endian)
template Unpack128ToBytes16() {
    signal input in;
    signal output b[16];

    component bits = NumToBits(128);
    bits.in <== in;

    for (var j = 0; j < 16; j++) {
        var acc = 0;
        var pow = 1;
        for (var k = 0; k < 8; k++) {
            acc += bits.out[j * 8 + k] * pow;
            pow = pow + pow;
        }
        b[j] <== acc; // 0..255
    }
}

// quadratic-safe delimiter check: ',' or '}'
template IsCommaOrBrace() {
    signal input b;
    signal output ok;
    (b - 44) * (b - 125) === 0;
    ok <== 1;
}

/*
  Select K packed elements starting at chunk_sel (one-hot over NPACK), allowing shift by j.
  outPacked[j] = payloadPacked[startChunk + j]
*/
template SlicePacked(NPACK, K) {
    signal input payloadPacked[NPACK];
    signal input chunk_sel[NPACK]; // one-hot
    signal output outPacked[K];

    component oh = OneHot(NPACK);
    for (var i = 0; i < NPACK; i++) oh.sel[i] <== chunk_sel[i];

    // shifted selectors sel[j][i] = (i>=j)? chunk_sel[i-j] : 0
    signal sel[K][NPACK];
    for (var j = 0; j < K; j++) {
        for (var i = 0; i < NPACK; i++) {
            if (i >= j) sel[j][i] <== chunk_sel[i - j];
            else sel[j][i] <== 0;
        }
    }

    // outPacked[j] = sum_i payloadPacked[i] * sel[j][i]
    signal prod[K][NPACK];
    for (var j = 0; j < K; j++) {
        var sum = 0;
        for (var i = 0; i < NPACK; i++) {
            prod[j][i] <== payloadPacked[i] * sel[j][i];
            sum += prod[j][i];
        }
        outPacked[j] <== sum;
    }
}

/*
  Build a W-byte window starting at (startByteIdx) = (startChunk*16 + offset),
  where startChunk is given as chunk_sel one-hot and offset as off_sel one-hot (size 16).
  We first slice K packed elements (K chosen to cover worst-case offset),
  unpack to 16*K bytes, then select window with 16-way offset.
*/
template WindowFromPacked(NPACK, K, W) {
    signal input payloadPacked[NPACK];
    signal input chunk_sel[NPACK];
    signal input off_sel[16]; // one-hot
    signal output window[W];

    component ohOff = OneHot(16);
    for (var i = 0; i < 16; i++) ohOff.sel[i] <== off_sel[i];

    component sl = SlicePacked(NPACK, K);
    for (var i = 0; i < NPACK; i++) sl.payloadPacked[i] <== payloadPacked[i];
    for (var i = 0; i < NPACK; i++) sl.chunk_sel[i] <== chunk_sel[i];

    component un[K];
    signal bytesFlat[16 * K];
    for (var j = 0; j < K; j++) {
        un[j] = Unpack128ToBytes16();
        un[j].in <== sl.outPacked[j];
        for (var t = 0; t < 16; t++) {
            bytesFlat[j * 16 + t] <== un[j].b[t];
        }
    }

    // window[t] = sum_u bytesFlat[t+u] * off_sel[u]
    // (assumes W+15 <= 16*K)
    signal prod[W][16];
    for (var t = 0; t < W; t++) {
        var sum = 0;
        for (var u = 0; u < 16; u++) {
            prod[t][u] <== bytesFlat[t + u] * off_sel[u];
            sum += prod[t][u];
        }
        window[t] <== sum;
    }
}

/*
  Given window[] starting at '"' of key, enforce:
    - fixed key bytes at offsets 0..KEYLEN-1
    - value length chosen by val_sel (prefix ones)
    - closing quote and delimiter checks ("," or "}")
  Outputs masked value bytes and len.
*/
template ExtractClaimFromWindow(W, MAXV, KEYLEN, VAL_OFF) {
    signal input window[W];
    signal input val_sel[MAXV];

    signal output val[MAXV];
    signal output len;

    component po = PrefixOnes(MAXV);
    for (var j = 0; j < MAXV; j++) po.sel[j] <== val_sel[j];

    // len
    var ls = 0;
    for (var j = 0; j < MAXV; j++) ls += val_sel[j];
    len <== ls;

    // key bytes are checked by caller (we wire them as constraints below)

    // end_here on last selected index
    signal end_here[MAXV];
    component endBool[MAXV];
    for (var j = 0; j < MAXV - 1; j++) end_here[j] <== val_sel[j] - val_sel[j + 1];
    end_here[MAXV - 1] <== val_sel[MAXV - 1];

    var endSum = 0;
    for (var j = 0; j < MAXV; j++) {
        endBool[j] = AssertBool();
        endBool[j].b <== end_here[j];
        endSum += end_here[j];
    }
    endSum === 1;

    // value bytes
    for (var j = 0; j < MAXV; j++) {
        val[j] <== window[VAL_OFF + j] * val_sel[j];
    }

    // closing quote at VAL_OFF + lastIndex + 1
    signal qterm[MAXV];
    signal q;
    var qsum = 0;
    for (var j = 0; j < MAXV; j++) {
        qterm[j] <== end_here[j] * window[VAL_OFF + j + 1];
        qsum += qterm[j];
    }
    q <== qsum;
    q === 34;

    // delimiter at VAL_OFF + lastIndex + 2
    signal dterm[MAXV];
    signal d;
    var dsum = 0;
    for (var j = 0; j < MAXV; j++) {
        dterm[j] <== end_here[j] * window[VAL_OFF + j + 2];
        dsum += dterm[j];
    }
    d <== dsum;

    component dc = IsCommaOrBrace();
    dc.b <== d;
}

// ---- Parse 4 claims using packed slicing ----
template Parse4ClaimsPacked(NPACK, K_SUB, K_NONCE, SUB_MAX, AUD_MAX, ISS_MAX, NONCE_MAX) {
    signal input payloadPacked[NPACK];

    signal input sub_chunk_sel[NPACK];
    signal input sub_off_sel[16];
    signal input sub_val_sel[SUB_MAX];

    signal input aud_chunk_sel[NPACK];
    signal input aud_off_sel[16];
    signal input aud_val_sel[AUD_MAX];

    signal input iss_chunk_sel[NPACK];
    signal input iss_off_sel[16];
    signal input iss_val_sel[ISS_MAX];

    signal input nonce_chunk_sel[NPACK];
    signal input nonce_off_sel[16];
    signal input nonce_val_sel[NONCE_MAX];

    // expected (optional enforcement by outer circuit)
    signal input iss_expected[ISS_MAX];
    signal input iss_expected_len;
    signal input aud_expected[AUD_MAX];
    signal input aud_expected_len;

    signal output sub_bytes[SUB_MAX];
    signal output sub_len;

    signal output nonce_bytes[NONCE_MAX];
    signal output nonce_len;

    signal output iss_bytes[ISS_MAX];
    signal output iss_len;

    signal output aud_bytes[AUD_MAX];
    signal output aud_len;

    // ---- sub window: W = SUB_MAX + 9 (need up to VAL_OFF+MAXV+2 with VAL_OFF=7)
    var W_SUB = SUB_MAX + 9;
    component wsub = WindowFromPacked(NPACK, K_SUB, W_SUB);
    for (var i = 0; i < NPACK; i++) wsub.payloadPacked[i] <== payloadPacked[i];
    for (var i = 0; i < NPACK; i++) wsub.chunk_sel[i] <== sub_chunk_sel[i];
    for (var i = 0; i < 16; i++) wsub.off_sel[i] <== sub_off_sel[i];

    // enforce key bytes: "sub":"  => [34,115,117,98,34,58,34]
    wsub.window[0] === 34;
    wsub.window[1] === 115;
    wsub.window[2] === 117;
    wsub.window[3] === 98;
    wsub.window[4] === 34;
    wsub.window[5] === 58;
    wsub.window[6] === 34;

    component esub = ExtractClaimFromWindow(W_SUB, SUB_MAX, 7, 7);
    for (var i = 0; i < W_SUB; i++) esub.window[i] <== wsub.window[i];
    for (var i = 0; i < SUB_MAX; i++) esub.val_sel[i] <== sub_val_sel[i];
    for (var i = 0; i < SUB_MAX; i++) sub_bytes[i] <== esub.val[i];
    sub_len <== esub.len;

    // ---- aud window: W = AUD_MAX + 9 (VAL_OFF=7)
    var W_AUD = AUD_MAX + 9;
    component waud = WindowFromPacked(NPACK, K_SUB, W_AUD);
    for (var i = 0; i < NPACK; i++) waud.payloadPacked[i] <== payloadPacked[i];
    for (var i = 0; i < NPACK; i++) waud.chunk_sel[i] <== aud_chunk_sel[i];
    for (var i = 0; i < 16; i++) waud.off_sel[i] <== aud_off_sel[i];

    // "aud":"  => [34,97,117,100,34,58,34]
    waud.window[0] === 34;
    waud.window[1] === 97;
    waud.window[2] === 117;
    waud.window[3] === 100;
    waud.window[4] === 34;
    waud.window[5] === 58;
    waud.window[6] === 34;

    component eaud = ExtractClaimFromWindow(W_AUD, AUD_MAX, 7, 7);
    for (var i = 0; i < W_AUD; i++) eaud.window[i] <== waud.window[i];
    for (var i = 0; i < AUD_MAX; i++) eaud.val_sel[i] <== aud_val_sel[i];
    for (var i = 0; i < AUD_MAX; i++) aud_bytes[i] <== eaud.val[i];
    aud_len <== eaud.len;

    // ---- iss window: W = ISS_MAX + 9 (VAL_OFF=7)
    var W_ISS = ISS_MAX + 9;
    component wiss = WindowFromPacked(NPACK, K_SUB, W_ISS);
    for (var i = 0; i < NPACK; i++) wiss.payloadPacked[i] <== payloadPacked[i];
    for (var i = 0; i < NPACK; i++) wiss.chunk_sel[i] <== iss_chunk_sel[i];
    for (var i = 0; i < 16; i++) wiss.off_sel[i] <== iss_off_sel[i];

    // "iss":" => [34,105,115,115,34,58,34]
    wiss.window[0] === 34;
    wiss.window[1] === 105;
    wiss.window[2] === 115;
    wiss.window[3] === 115;
    wiss.window[4] === 34;
    wiss.window[5] === 58;
    wiss.window[6] === 34;

    component eiss = ExtractClaimFromWindow(W_ISS, ISS_MAX, 7, 7);
    for (var i = 0; i < W_ISS; i++) eiss.window[i] <== wiss.window[i];
    for (var i = 0; i < ISS_MAX; i++) eiss.val_sel[i] <== iss_val_sel[i];
    for (var i = 0; i < ISS_MAX; i++) iss_bytes[i] <== eiss.val[i];
    iss_len <== eiss.len;

    // ---- nonce window: W = NONCE_MAX + 11 (VAL_OFF=9 for "nonce":" )
    var W_NONCE = NONCE_MAX + 11;
    component wno = WindowFromPacked(NPACK, K_NONCE, W_NONCE);
    for (var i = 0; i < NPACK; i++) wno.payloadPacked[i] <== payloadPacked[i];
    for (var i = 0; i < NPACK; i++) wno.chunk_sel[i] <== nonce_chunk_sel[i];
    for (var i = 0; i < 16; i++) wno.off_sel[i] <== nonce_off_sel[i];

    // "nonce":" => [34,110,111,110,99,101,34,58,34]
    wno.window[0] === 34;
    wno.window[1] === 110;
    wno.window[2] === 111;
    wno.window[3] === 110;
    wno.window[4] === 99;
    wno.window[5] === 101;
    wno.window[6] === 34;
    wno.window[7] === 58;
    wno.window[8] === 34;

    component eno = ExtractClaimFromWindow(W_NONCE, NONCE_MAX, 9, 9);
    for (var i = 0; i < W_NONCE; i++) eno.window[i] <== wno.window[i];
    for (var i = 0; i < NONCE_MAX; i++) eno.val_sel[i] <== nonce_val_sel[i];
    for (var i = 0; i < NONCE_MAX; i++) nonce_bytes[i] <== eno.val[i];
    nonce_len <== eno.len;

    // ---- optional enforcement: iss == expected, aud == expected
    // length equality
    iss_len === iss_expected_len;
    aud_len === aud_expected_len;

    // masked equality: for j < len, extracted byte must equal expected byte
    for (var j = 0; j < ISS_MAX; j++) {
        iss_bytes[j] === iss_expected[j] * iss_val_sel[j];
    }
    for (var j = 0; j < AUD_MAX; j++) {
        aud_bytes[j] === aud_expected[j] * aud_val_sel[j];
    }
}
