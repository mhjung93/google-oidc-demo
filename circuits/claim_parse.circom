pragma circom 2.0.0;

// ---------------- basic gadgets ----------------
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

// prefix ones: 111..1100..00 (non-empty)
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
    sel[0] === 1; // require non-empty
}

// payload[start+REL] selected by one-hot start_sel
// payload[start+REL] selected by one-hot start_sel
template ByteRel(Lmax, REL) {
    signal input payload[Lmax];
    signal input start_sel[Lmax];
    signal output out;

    // 각 곱을 따로 signal로 만들어서 "곱의 합"을 피한다
    signal prod[Lmax];

    var sum = 0;

    for (var i = 0; i < Lmax; i++) {
        if (i + REL < Lmax) {
            prod[i] <== payload[i + REL] * start_sel[i];  // (1) 곱 1개 = constraint 1개
            sum += prod[i];                               // (2) 선형 합
        } else {
            // out-of-range start 금지
            start_sel[i] === 0;
            prod[i] <== 0;
        }
    }

    out <== sum; // 선형식이므로 OK
}


template IsCommaOrBrace() {
    signal input b;
    signal output ok;

    // accept only b==44 (',') or b==125 ('}')
    (b - 44) * (b - 125) === 0;

    ok <== 1;
}


/*
  Extract claim of fixed pattern (NO spaces):
    "sub":"VALUE",   or  "iss":"VALUE"}  etc.

  Inputs:
    payload[Lmax]
    start_sel[Lmax] : one-hot selecting the index of first '"' in the key
    val_sel[MAXV]   : prefix ones selecting VALUE length (>=1)

  Params:
    VAL_OFF : value starts at payload[start + VAL_OFF]
             for "sub":"  VAL_OFF = 7
             for "nonce":" VAL_OFF = 9
  Output:
    val[MAXV] (masked)
    len (sum of val_sel)
*/
template ExtractFixedKeyClaim(Lmax, MAXV, VAL_OFF) {
    signal input payload[Lmax];
    signal input start_sel[Lmax];
    signal input val_sel[MAXV];

    signal output val[MAXV];
    signal output len;

    // shape constraints
    component oh = OneHot(Lmax);
    for (var i = 0; i < Lmax; i++) oh.sel[i] <== start_sel[i];

    component po = PrefixOnes(MAXV);
    for (var j = 0; j < MAXV; j++) po.sel[j] <== val_sel[j];

    // len = sum(val_sel)
    var ls = 0;
    for (var j = 0; j < MAXV; j++) ls += val_sel[j];
    len <== ls;

    // end_here[j] = 1 only at last selected index
    signal end_here[MAXV];
    component endBool[MAXV];

    for (var j = 0; j < MAXV - 1; j++) {
        end_here[j] <== val_sel[j] - val_sel[j + 1];
    }
    end_here[MAXV - 1] <== val_sel[MAXV - 1];

    var endSum = 0;
    for (var j = 0; j < MAXV; j++) {
        endBool[j] = AssertBool();
        endBool[j].b <== end_here[j];
        endSum += end_here[j];
    }
    endSum === 1;

    // extract value bytes
    component bj[MAXV];
    for (var j = 0; j < MAXV; j++) {
        bj[j] = ByteRel(Lmax, VAL_OFF + j);
        bj[j].payload <== payload;
        bj[j].start_sel <== start_sel;
        val[j] <== bj[j].out * val_sel[j];
    }

    // closing quote at (VAL_OFF + lastIndex + 1)
    component bclose[MAXV];
    signal qterm[MAXV];
    signal q;

    var qsum = 0;
    for (var j = 0; j < MAXV; j++) {
        bclose[j] = ByteRel(Lmax, VAL_OFF + j + 1);
        bclose[j].payload <== payload;
        bclose[j].start_sel <== start_sel;

        // 곱은 signal에 분리
        qterm[j] <== end_here[j] * bclose[j].out;
        qsum += qterm[j];
    }
    q <== qsum;
    q === 34; // '"'


    /// delimiter at (VAL_OFF + lastIndex + 2)
    component bdelim[MAXV];
    signal dterm[MAXV];
    signal d;

    var dsum = 0;
    for (var j = 0; j < MAXV; j++) {
        bdelim[j] = ByteRel(Lmax, VAL_OFF + j + 2);
        bdelim[j].payload <== payload;
        bdelim[j].start_sel <== start_sel;

        // 곱은 signal에 분리
        dterm[j] <== end_here[j] * bdelim[j].out;
        dsum += dterm[j];
    }
    d <== dsum;

    component dc = IsCommaOrBrace();
    dc.b <== d;
}

// ---------------- 4-claim parser ----------------
template Parse4Claims(Lmax, SUB_MAX, AUD_MAX, ISS_MAX, NONCE_MAX) {
    signal input payload[Lmax];

    signal input sub_start_sel[Lmax];
    signal input aud_start_sel[Lmax];
    signal input iss_start_sel[Lmax];
    signal input nonce_start_sel[Lmax];

    signal input sub_val_sel[SUB_MAX];
    signal input aud_val_sel[AUD_MAX];
    signal input iss_val_sel[ISS_MAX];
    signal input nonce_val_sel[NONCE_MAX];

    signal output sub_bytes[SUB_MAX];
    signal output aud_bytes[AUD_MAX];
    signal output iss_bytes[ISS_MAX];
    signal output nonce_bytes[NONCE_MAX];

    signal output sub_len;
    signal output aud_len;
    signal output iss_len;
    signal output nonce_len;

    // --- key/punct checks + extract ---

    // "sub":"  => offsets 0..6 fixed, value starts at 7
    component s0 = ByteRel(Lmax, 0); s0.payload <== payload; s0.start_sel <== sub_start_sel; s0.out === 34;
    component s1 = ByteRel(Lmax, 1); s1.payload <== payload; s1.start_sel <== sub_start_sel; s1.out === 115;
    component s2 = ByteRel(Lmax, 2); s2.payload <== payload; s2.start_sel <== sub_start_sel; s2.out === 117;
    component s3 = ByteRel(Lmax, 3); s3.payload <== payload; s3.start_sel <== sub_start_sel; s3.out === 98;
    component s4 = ByteRel(Lmax, 4); s4.payload <== payload; s4.start_sel <== sub_start_sel; s4.out === 34;
    component s5 = ByteRel(Lmax, 5); s5.payload <== payload; s5.start_sel <== sub_start_sel; s5.out === 58;
    component s6 = ByteRel(Lmax, 6); s6.payload <== payload; s6.start_sel <== sub_start_sel; s6.out === 34;

    component sub = ExtractFixedKeyClaim(Lmax, SUB_MAX, 7);
    sub.payload <== payload;
    sub.start_sel <== sub_start_sel;
    for (var i = 0; i < SUB_MAX; i++) sub.val_sel[i] <== sub_val_sel[i];
    for (var i = 0; i < SUB_MAX; i++) sub_bytes[i] <== sub.val[i];
    sub_len <== sub.len;

    // "aud":"  value starts at 7
    component a0 = ByteRel(Lmax, 0); a0.payload <== payload; a0.start_sel <== aud_start_sel; a0.out === 34;
    component a1 = ByteRel(Lmax, 1); a1.payload <== payload; a1.start_sel <== aud_start_sel; a1.out === 97;
    component a2 = ByteRel(Lmax, 2); a2.payload <== payload; a2.start_sel <== aud_start_sel; a2.out === 117;
    component a3 = ByteRel(Lmax, 3); a3.payload <== payload; a3.start_sel <== aud_start_sel; a3.out === 100;
    component a4 = ByteRel(Lmax, 4); a4.payload <== payload; a4.start_sel <== aud_start_sel; a4.out === 34;
    component a5 = ByteRel(Lmax, 5); a5.payload <== payload; a5.start_sel <== aud_start_sel; a5.out === 58;
    component a6 = ByteRel(Lmax, 6); a6.payload <== payload; a6.start_sel <== aud_start_sel; a6.out === 34;

    component aud = ExtractFixedKeyClaim(Lmax, AUD_MAX, 7);
    aud.payload <== payload;
    aud.start_sel <== aud_start_sel;
    for (var i = 0; i < AUD_MAX; i++) aud.val_sel[i] <== aud_val_sel[i];
    for (var i = 0; i < AUD_MAX; i++) aud_bytes[i] <== aud.val[i];
    aud_len <== aud.len;

    // "iss":"  value starts at 7
    component i0 = ByteRel(Lmax, 0); i0.payload <== payload; i0.start_sel <== iss_start_sel; i0.out === 34;
    component i1 = ByteRel(Lmax, 1); i1.payload <== payload; i1.start_sel <== iss_start_sel; i1.out === 105;
    component i2 = ByteRel(Lmax, 2); i2.payload <== payload; i2.start_sel <== iss_start_sel; i2.out === 115;
    component i3 = ByteRel(Lmax, 3); i3.payload <== payload; i3.start_sel <== iss_start_sel; i3.out === 115;
    component i4 = ByteRel(Lmax, 4); i4.payload <== payload; i4.start_sel <== iss_start_sel; i4.out === 34;
    component i5 = ByteRel(Lmax, 5); i5.payload <== payload; i5.start_sel <== iss_start_sel; i5.out === 58;
    component i6 = ByteRel(Lmax, 6); i6.payload <== payload; i6.start_sel <== iss_start_sel; i6.out === 34;

    component iss = ExtractFixedKeyClaim(Lmax, ISS_MAX, 7);
    iss.payload <== payload;
    iss.start_sel <== iss_start_sel;
    for (var i = 0; i < ISS_MAX; i++) iss.val_sel[i] <== iss_val_sel[i];
    for (var i = 0; i < ISS_MAX; i++) iss_bytes[i] <== iss.val[i];
    iss_len <== iss.len;

    // "nonce":" value starts at 9
    component n0 = ByteRel(Lmax, 0); n0.payload <== payload; n0.start_sel <== nonce_start_sel; n0.out === 34;
    component n1 = ByteRel(Lmax, 1); n1.payload <== payload; n1.start_sel <== nonce_start_sel; n1.out === 110;
    component n2 = ByteRel(Lmax, 2); n2.payload <== payload; n2.start_sel <== nonce_start_sel; n2.out === 111;
    component n3 = ByteRel(Lmax, 3); n3.payload <== payload; n3.start_sel <== nonce_start_sel; n3.out === 110;
    component n4 = ByteRel(Lmax, 4); n4.payload <== payload; n4.start_sel <== nonce_start_sel; n4.out === 99;
    component n5 = ByteRel(Lmax, 5); n5.payload <== payload; n5.start_sel <== nonce_start_sel; n5.out === 101;
    component n6 = ByteRel(Lmax, 6); n6.payload <== payload; n6.start_sel <== nonce_start_sel; n6.out === 34;
    component n7 = ByteRel(Lmax, 7); n7.payload <== payload; n7.start_sel <== nonce_start_sel; n7.out === 58;
    component n8 = ByteRel(Lmax, 8); n8.payload <== payload; n8.start_sel <== nonce_start_sel; n8.out === 34;

    component nonce = ExtractFixedKeyClaim(Lmax, NONCE_MAX, 9);
    nonce.payload <== payload;
    nonce.start_sel <== nonce_start_sel;
    for (var i = 0; i < NONCE_MAX; i++) nonce.val_sel[i] <== nonce_val_sel[i];
    for (var i = 0; i < NONCE_MAX; i++) nonce_bytes[i] <== nonce.val[i];
    nonce_len <== nonce.len;
}
