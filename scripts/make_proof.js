// make_proof.js (ESM) - Rewritten for circom-rsa-verify
import fs from 'node:fs';
//import { createHash } from 'node:crypto';
import fetch from 'node-fetch';
import { decodeProtectedHeader } from 'jose';
import {importJWK, compactVerify} from 'jose';
import e from 'express';

// Added from pseudonym generation
import { buildPoseidon, buildBabyjub } from "circomlibjs";
import { createHash, randomBytes } from 'node:crypto';
import { Buffer } from "node:buffer";



// Added from pseudonym generation
function u8ToBigIntBE(u8) {
  // big-endian으로 BigInt 변환
  return BigInt("0x" + Buffer.from(u8).toString("hex"));
}

function pack16LEBytes(buf16) {
  let x = 0n;
  for (let i = 0; i < 16; i++) x += BigInt(buf16[i]) << (8n * BigInt(i));
  return x;
}

function pack128BytesTo8Chunks(bytes128) {
  const out = [];
  for (let c = 0; c < 8; c++) {
    const chunk = bytes128.slice(c * 16, c * 16 + 16);
    out.push(pack16LEBytes(chunk));
  }
  return out;
}

function asciiPad128(str) {
  const b = Buffer.from(str, "utf8");
  const out = Buffer.concat([b, Buffer.alloc(128 - b.length, 0)]);
  return out;
}

function toBigIntAny(x) {
  if (typeof x === "bigint") return x;

  if (typeof x === "number") return BigInt(x);

  if (typeof x === "string") {
    const s = x.trim();

    // "178,38,..." 같은 CSV 바이트 문자열 처리
    if (s.includes(",")) {
      const bytes = s.split(",").map(v => Number(v.trim()));
      if (bytes.some(n => !Number.isFinite(n))) {
        throw new Error(`[toBigIntAny] bad CSV byte string: ${s}`);
      }
      const hex = Buffer.from(bytes).toString("hex");
      return BigInt("0x" + (hex.length ? hex : "0"));
    }

    // 0x... 또는 10진수 문자열
    return BigInt(s.startsWith("0x") || s.startsWith("0X") ? s : s);
  }

  // Uint8Array / Buffer / Array<number> 처리
  if (x instanceof Uint8Array || Buffer.isBuffer(x)) {
    const hex = Buffer.from(x).toString("hex");
    return BigInt("0x" + (hex.length ? hex : "0"));
  }
  if (Array.isArray(x)) {
    const hex = Buffer.from(x).toString("hex");
    return BigInt("0x" + (hex.length ? hex : "0"));
  }

  // Field object 등: toString() 결과로 재시도
  if (x && typeof x === "object" && typeof x.toString === "function") {
    return toBigIntAny(x.toString());
  }

  throw new Error(`[toBigIntAny] unsupported type: ${typeof x}`);
}

function toEthLikeAddressFromField(x) {
  const xb = toBigIntAny(x);
  const mask160 = (1n << 160n) - 1n;
  const y = xb & mask160;
  return "0x" + y.toString(16).padStart(40, "0");
}



//  Gate compaction from zkLogin
function pack16LE(bytes16) {
    let x = 0n;
    for (let i = 0; i < 16; i++) x += BigInt(bytes16[i]) << (8n * BigInt(i)); // little-endian
    return x;
  }
  
  function packPayloadAsciiTo128(payloadStr, LMAX) {
    const buf = Buffer.from(payloadStr, 'utf8');
    if (buf.length > LMAX) throw new Error(`payload too long: ${buf.length} > ${LMAX}`);
    const padded = Buffer.concat([buf, Buffer.alloc(LMAX - buf.length, 0)]);
    const N = Math.ceil(LMAX / 16);
    const out = [];
    for (let k = 0; k < N; k++) {
      const chunk = padded.subarray(k * 16, k * 16 + 16);
      out.push(pack16LE([...chunk]));
    }
    return out; // BigInt[]
  }
  
  function oneHot(len, idx) {
    if (idx < 0 || idx >= len) throw new Error(`oneHot idx out of range: ${idx}`);
    return Array.from({ length: len }, (_, i) => (i === idx ? 1 : 0));
  }
  
  function prefixOnes(maxLen, len) {
    if (!Number.isInteger(len)) throw new Error(`len not int: ${len}`);
    if (len < 1 || len > maxLen) throw new Error(`bad len ${len} (max ${maxLen})`);
    const arr = Array(maxLen).fill(0);
    for (let i = 0; i < len; i++) arr[i] = 1;
    return arr;
  }
  
  
  function asciiPadded(str, MAX) {
    const b = Buffer.from(str, 'utf8');
    if (b.length > MAX) throw new Error(`expected str too long: ${b.length} > ${MAX}`);
    const arr = Array.from(b.values());
    while (arr.length < MAX) arr.push(0);
    return arr;
  }
  
  function findClaim(payloadStr, key) {
    const pat = `"${key}":"`;             // key prefix (공백 없는 형태)
    const keyStart = payloadStr.indexOf(pat);
    if (keyStart < 0) throw new Error(`claim ${key} not found`);
  
    const valueStart = keyStart + pat.length;
    const valueEnd = payloadStr.indexOf('"', valueStart);
    if (valueEnd < 0) throw new Error(`claim ${key} unterminated`);
  
    const len = valueEnd - valueStart;
    return { keyStart, valueStart, len, patLen: pat.length };
  }
  
  


// Helper function added from zkLogin ckt
//function oneHot(L, idx) {
    //if (idx < 0 || idx >= L) throw new Error(`oneHot idx out of range: ${idx}`);
    //return Array.from({ length: L }, (_, i) => (i === idx ? 1 : 0));
//}
  
  //function prefixOnes(maxLen, len) {
    //if (len <= 0) throw new Error(`len must be >= 1`);
    //if (len > maxLen) throw new Error(`len ${len} > maxLen ${maxLen}`);
    //return Array.from({ length: maxLen }, (_, i) => (i < len ? 1 : 0));
//}
  
  function toAsciiPadded(str, Lmax) {
    const buf = Buffer.from(str, 'utf8');
    if (buf.length > Lmax) throw new Error(`payload too long: ${buf.length} > ${Lmax}`);
    const arr = Array.from(buf.values());
    while (arr.length < Lmax) arr.push(0);
    return arr;
}
  
  function findFixedPattern(jsonStr, pat) {
    const idx = jsonStr.indexOf(pat);
    if (idx < 0) throw new Error(`pattern not found: ${pat}`);
    const valStart = idx + pat.length; // pat ends right after opening quote
    const endQ = jsonStr.indexOf('"', valStart);
    if (endQ < 0) throw new Error(`closing quote not found for: ${pat}`);
    const valLen = endQ - valStart;
    return { idx, valLen };
}


// Helper function to split a BigInt into an array of smaller BigInts (limbs)
// Ported from the library's test file.
// n: number of bits in each limb
// k: number of limbs
// x: the BigInt to split
function bigint_to_array(n, k, x) {
    let mod = 1n;
    for (var idx = 0; idx < n; idx++) {
        mod = mod * 2n;
    }

    let ret = [];
    var x_temp = x;
    for (var idx = 0; idx < k; idx++) {
        ret.push(x_temp % mod);
        x_temp = x_temp / mod;
    }
    return ret;
}

// Main async function
(async () => {
  console.log('[zk:input] Starting input generation for RSA verification...');
  const t0 = Date.now();

  // 1. Get ID Token
  const idToken = process.env.ID_TOKEN;
  if (!idToken) {
    throw new Error('ID_TOKEN environment variable not set.');
  }
  console.log('[zk:input] ID Token loaded.');

  // 2. Parse JWT and prepare signed data
  const jwtParts = idToken.split('.');
  if (jwtParts.length !== 3) {
    throw new Error('Invalid JWT format.');
  }
  const headerB64 = jwtParts[0];
  const payloadB64 = jwtParts[1];
  const signatureB64 = jwtParts[2];
  const signedData = `${headerB64}.${payloadB64}`;

  // 3. Create SHA-256 hash of the signed data

  // Original
  //  const hash = createHash('sha256').update(signedData).digest('hex');
  // Modified
  const hash = createHash('sha256').update(signedData, 'ascii').digest('hex');

  const hashedBigInt = BigInt('0x' + hash);
  console.log('[zk:input] SHA-256 hash of signed data created.');

  // 4. Decode signature
  
  //Original
  //const signatureBigInt = BigInt('0x' + Buffer.from(signatureB64, 'base64').toString('hex'));

  //Modified
  const sigBuf = Buffer.from(signatureB64, 'base64url');   
  const signatureBigInt = BigInt('0x' + sigBuf.toString('hex'));

  console.log('[zk:input] Signature decoded.');

  // 5. Fetch Google's public keys (JWKS)
  const header = decodeProtectedHeader(idToken);
  const kid = header.kid;
  if (!kid) {
    throw new Error('Key ID (kid) not found in JWT header.');
  }
  const jwksUrl = 'https://www.googleapis.com/oauth2/v3/certs';
  const jwksResponse = await fetch(jwksUrl);
  if (!jwksResponse.ok) {
    throw new Error(`Failed to fetch JWKS from ${jwksUrl}`);
  }
  const jwks = await jwksResponse.json();
  
  const jwk = jwks.keys.find(key => key.kid === kid);
  if (!jwk) {
    throw new Error(`Public key with kid "${kid}" not found in JWKS.`);
  }
  console.log('[zk:input] Matching public key found in JWKS.');

  // Add part
  const key_test = await importJWK(jwk, "RS256");
  await compactVerify(idToken, key_test);
  console.log("[zk:input] jose compactVerify OK");


  // 6. Extract modulus (n) and exponent (e) from the JWK
  //Original
  //const modulusBigInt = BigInt('0x' + Buffer.from(jwk.n, 'base64').toString('hex'));
  //const exponentBigInt = BigInt('0x' + Buffer.from(jwk.e, 'base64').toString('hex'));

  //Modified
  const nBuf = Buffer.from(jwk.n, 'base64url');   
  const eBuf = Buffer.from(jwk.e, 'base64url');   

  console.log('[zk:input] key sizes:',
  { nBytes: nBuf.length, eBytes: eBuf.length, sigBytes: sigBuf.length }
  );

  // 회로 파라미터가 2048-bit(256 bytes)를 가정하므로 강제 체크
  if (nBuf.length !== 256) {
      throw new Error(`JWKS modulus size is ${nBuf.length} bytes (expected 256 for 2048-bit). Fix nb/w or select a 2048-bit key.`);
    }

    if (sigBuf.length !== 256) {
          throw new Error(`JWT signature size is ${sigBuf.length} bytes (expected 256 for 2048-bit).`);
    }

  const modulusBigInt  = BigInt('0x' + nBuf.toString('hex'));
  const exponentBigInt = BigInt('0x' + eBuf.toString('hex'));


  if (exponentBigInt !== 65537n) {
      console.warn("Warning: Public key exponent is not 65537. The circuit is hardcoded for e=65537.");
  }

  // 7. Format all inputs into limb arrays for the circuit
  // Parameters based on RsaVerifyPkcs1v15 template: w=64, nb=32, e_bits=?, hashLen=4
  // We assume a 2048-bit key (32 limbs * 64 bits/limb)
  const n = 64; // bits per limb
  const nb = 32; // number of limbs for key/sig
  const hash_k = 4; // number of limbs for hash

  // ✅ exp는 limb가 아니라 "bit array(0/1)"로 넣기 (32 bits)
  const expBits = Array(nb).fill(0n);
  expBits[0] = 1n;    // 2^0
  expBits[16] = 1n;   // 2^16  -> 65537

  // MSB-First인 경우 뒤집기
  //expBits[nb - 1 - 0]  = 1n;   // bit0
  //expBits[nb - 1 - 16] = 1n;   // bit16

  const circuitInputs = {
      // Original
      //"exp": bigint_to_array(n, k, exponentBigInt),
      
      // Modified
      "exp": expBits,
      "sign": bigint_to_array(n, nb, signatureBigInt),
      "modulus": bigint_to_array(n, nb, modulusBigInt),
      "hashed": bigint_to_array(n, hash_k, hashedBigInt)
  };
  console.log('[zk:input] All inputs formatted for the circuit.');

  


  // 7.5 Debug for endian
  function modPow(base, exp, mod) {
    let r = 1n;
    let b = base % mod;
    let e = exp;
    while (e > 0n) {
      if (e & 1n) r = (r * b) % mod;
      b = (b * b) % mod;
      e >>= 1n;
    }
    return r;
  }
  
  // RSA “복호 결과(EM)”를 BigInt로 구함
  const em = modPow(signatureBigInt, exponentBigInt, modulusBigInt);
  
  // EM을 회로와 같은 64-bit limb 배열로 변환
  const emLimbs = bigint_to_array(64, 32, em);
  
  // 회로가 강제하는 상수(당신 rsa_verify.circom 그대로)
  console.log("em[0..6] =", emLimbs.slice(0, 7).map(x=>x.toString()));
  console.log("em[4] should be", "217300885422736416");
  console.log("em[5] should be", "938447882527703397");
  console.log("em[31] should be", "562949953421311");

  // hashed limbs 출력하여 em[0..3]과 같은지 확인
  const hashedLimbs = bigint_to_array(64, 4, hashedBigInt);
  console.log("hashed[0..3] =", hashedLimbs.map(x => x.toString()));
  

// expected iss/aud(원하면 회로에서 강제)
// 예: Google iss는 흔히 아래 값; aud는 client_id
const ISS_EXPECTED = process.env.ISS_EXPECTED ?? "https://accounts.google.com";
const AUD_EXPECTED = process.env.AUD_EXPECTED ?? "588661703676-so4rftcahdeo203pdge9csmse64dlfd8.apps.googleusercontent.com"; // 반드시 설정 권장(당신 RP client_id)

  // Added part from zkLogin ckt
  const Lmax = 1500;
//const SUB_MAX = 128;
//const AUD_MAX = 256;
//const ISS_MAX = 128;
//const NONCE_MAX = 256;

// payload decode (base64url)
//const payloadStr = b64urlToBuf(payloadB64).toString('utf8');
const payloadStr = Buffer.from(payloadB64, 'base64url').toString('utf8');

const payloadObj = JSON.parse(payloadStr);
const tokenAud = Array.isArray(payloadObj.aud) ? payloadObj.aud[0] : payloadObj.aud;

console.log("[zk:input] token aud =", tokenAud);
console.log("[zk:input] token aud byteLen =", Buffer.byteLength(tokenAud, "utf8"));

console.log("\n[zk:stmt] ===== What this ZKP proves (human-readable) =====");
console.log("[zk:stmt] 1) The JWT RS256 signature verifies under Google JWKS (kid matched)");
console.log("[zk:stmt] 2) The signed message hash = SHA256(base64url(header) + '.' + base64url(payload))");
console.log(`[zk:stmt] 3) The payload contains claims (sub/aud/iss/nonce) at constrained positions (non-malleable parsing)`);
console.log(`[zk:stmt] 4) Enforced issuer: iss == "${ISS_EXPECTED}"`);
console.log(`[zk:stmt] 5) Enforced audience: aud == "${AUD_EXPECTED}"`);
console.log("[zk:stmt] -----------------------------------------------");
console.log("[zk:stmt] Extracted from token payload:");
console.log({
  iss: payloadObj.iss,
  aud: payloadObj.aud,
  sub: payloadObj.sub,
  nonce: payloadObj.nonce,
});
console.log("[zk:stmt] ===============================================\n");


// Gate compaction from zkLogin
// ====== packed params (zkLogin style) ======
const LMAX = 1600;            // zkLogin uses Lmax=1600 :contentReference[oaicite:3]{index=3}
const PACK = 16;
const NPACK = Math.ceil(LMAX / PACK);

// max lengths (줄일수록 회로 작아짐; 보통 128이면 충분)
const SUB_MAX = 128;
const AUD_MAX = 128;
const ISS_MAX = 128;
const NONCE_MAX = 128;

// payload packed
const payloadPacked = packPayloadAsciiTo128(payloadStr, LMAX);

// claim 위치/길이(밖에서 찾되, 회로에서 key/punct/종료조건을 강제해서 조작을 막는 방식)
const sub = findClaim(payloadStr, "sub");
const aud = findClaim(payloadStr, "aud");
const iss = findClaim(payloadStr, "iss");
const nonce = findClaim(payloadStr, "nonce");

const audValue = payloadStr.slice(aud.valueStart, aud.valueStart + aud.len);
console.log("[zk:input] aud extracted =", audValue);
console.log("[zk:input] aud_len =", aud.len);



// chunk index + intra-chunk offset
function mkStartSel(startByteIdx) {
  const chunk = Math.floor(startByteIdx / 16);
  const off = startByteIdx % 16;
  return { chunk_sel: oneHot(NPACK, chunk), off_sel: oneHot(16, off) };
}

const subSel   = mkStartSel(sub.keyStart);
const audSel   = mkStartSel(aud.keyStart);
const issSel   = mkStartSel(iss.keyStart);
const nonceSel = mkStartSel(nonce.keyStart);

console.log("sub@keyStart:", payloadStr.slice(sub.keyStart, sub.keyStart + 12));    // 기대: "sub":"
console.log("sub@valueStart:", payloadStr.slice(sub.valueStart, sub.valueStart + 12));


// circuit inputs
circuitInputs.payload_packed = payloadPacked.map(x => x.toString());

circuitInputs.sub_chunk_sel = subSel.chunk_sel;
circuitInputs.sub_off_sel = subSel.off_sel;
circuitInputs.sub_val_sel = prefixOnes(SUB_MAX, sub.len);

circuitInputs.aud_chunk_sel = audSel.chunk_sel;
circuitInputs.aud_off_sel = audSel.off_sel;
circuitInputs.aud_val_sel = prefixOnes(AUD_MAX, aud.len);

circuitInputs.iss_chunk_sel = issSel.chunk_sel;
circuitInputs.iss_off_sel = issSel.off_sel;
circuitInputs.iss_val_sel = prefixOnes(ISS_MAX, iss.len);

circuitInputs.nonce_chunk_sel = nonceSel.chunk_sel;
circuitInputs.nonce_off_sel = nonceSel.off_sel;
circuitInputs.nonce_val_sel = prefixOnes(NONCE_MAX, nonce.len);

// expected bytes/len (aud/iss 강제용)
circuitInputs.iss_expected = asciiPadded(ISS_EXPECTED, ISS_MAX);
circuitInputs.iss_expected_len = Buffer.from(ISS_EXPECTED, 'utf8').length;

if (!AUD_EXPECTED) {
  throw new Error("Set AUD_EXPECTED to the exact aud (client_id) in the ID token payload.");
}
circuitInputs.aud_expected = asciiPadded(AUD_EXPECTED, AUD_MAX);
//circuitInputs.aud_expected_len = AUD_EXPECTED ? Buffer.from(AUD_EXPECTED, 'utf8').length : 0;
//circuitInputs.aud_expected_len = Buffer.from(AUD_EXPECTED, 'utf8').length; // <- 0 허용하지 말고 강제 권장
circuitInputs.aud_expected_len = Buffer.byteLength(AUD_EXPECTED, "utf8");

if (circuitInputs.aud_expected_len !== aud.len) {
  console.warn("[zk:input] AUD length mismatch!", {
    extracted_aud_len: aud.len,
    expected_aud_len: circuitInputs.aud_expected_len,
  });
}



// fixed patterns (no spaces) — 회로가 이 형태를 강제함
//const sub = findFixedPattern(payloadStr, '"sub":"');
//const aud = findFixedPattern(payloadStr, '"aud":"');
//const iss = findFixedPattern(payloadStr, '"iss":"');
//const nonce = findFixedPattern(payloadStr, '"nonce":"');

//circuitInputs.payload_ascii = toAsciiPadded(payloadStr, Lmax);

//circuitInputs.sub_start_sel = oneHot(Lmax, sub.idx);
//circuitInputs.aud_start_sel = oneHot(Lmax, aud.idx);
//circuitInputs.iss_start_sel = oneHot(Lmax, iss.idx);
//circuitInputs.nonce_start_sel = oneHot(Lmax, nonce.idx);

//circuitInputs.sub_val_sel = prefixOnes(SUB_MAX, sub.valLen);
//circuitInputs.aud_val_sel = prefixOnes(AUD_MAX, aud.valLen);
//circuitInputs.iss_val_sel = prefixOnes(ISS_MAX, iss.valLen);
//circuitInputs.nonce_val_sel = prefixOnes(NONCE_MAX, nonce.valLen);


// 7.5 prefix ones 검사
function assertPrefixOnes(name, arr) {
  if (!Array.isArray(arr)) throw new Error(`${name}: not an array`);
  if (arr.length === 0) throw new Error(`${name}: empty`);
  const toNum = (x) => (typeof x === "string" ? Number(x) : x);

  if (toNum(arr[0]) !== 1) {
    throw new Error(`${name}: arr[0] must be 1 (got ${arr[0]})`);
  }
  for (let i = 0; i < arr.length; i++) {
    const v = toNum(arr[i]);
    if (!(v === 0 || v === 1)) throw new Error(`${name}: non-bool at ${i} = ${arr[i]}`);
    if (i + 1 < arr.length) {
      const v2 = toNum(arr[i + 1]);
      // prefix-ones 조건: 0 다음에 1이 오면 안 됨
      if (v === 0 && v2 === 1) {
        throw new Error(`${name}: not prefix ones (0->1) at i=${i}`);
      }
    }
  }
}

console.log("lens:", {
  sub: sub.len, aud: aud.len, iss: iss.len, nonce: nonce.len,
});

assertPrefixOnes("sub_val_sel", circuitInputs.sub_val_sel);
assertPrefixOnes("aud_val_sel", circuitInputs.aud_val_sel);
assertPrefixOnes("iss_val_sel", circuitInputs.iss_val_sel);
assertPrefixOnes("nonce_val_sel", circuitInputs.nonce_val_sel);

console.log("sub_val_sel head/tail", circuitInputs.sub_val_sel.slice(0, 20), circuitInputs.sub_val_sel.slice(-20));
console.log("aud_val_sel head/tail", circuitInputs.aud_val_sel.slice(0, 20), circuitInputs.aud_val_sel.slice(-20));
console.log("iss_val_sel head/tail", circuitInputs.iss_val_sel.slice(0, 20), circuitInputs.iss_val_sel.slice(-20));
console.log("nonce_val_sel head/tail", circuitInputs.nonce_val_sel.slice(0, 20), circuitInputs.nonce_val_sel.slice(-20));




// --- Deterministic Key Generation from JWT claims ---
const poseidon = await buildPoseidon();
const babyJub = await buildBabyjub();
const F = poseidon.F; // Field object from Poseidon

const issStr = payloadObj.iss;
const audStr = Array.isArray(payloadObj.aud) ? payloadObj.aud[0] : payloadObj.aud;
const subStr = payloadObj.sub;

const issBytes = asciiPad128(issStr);
const audBytes = asciiPad128(audStr);
const subBytes = asciiPad128(subStr);

const hIssFE = poseidon([...pack128BytesTo8Chunks(issBytes), BigInt(Buffer.byteLength(issStr, "utf8"))]);
const hAudFE = poseidon([...pack128BytesTo8Chunks(audBytes), BigInt(Buffer.byteLength(audStr, "utf8"))]);
const hSubFE = poseidon([...pack128BytesTo8Chunks(subBytes), BigInt(Buffer.byteLength(subStr, "utf8"))]);

const hIss = u8ToBigIntBE(hIssFE);
const hAud = u8ToBigIntBE(hAudFE);
const hSub = u8ToBigIntBE(hSubFE);

const salt16 = Buffer.concat([Buffer.from("salt", "utf8"), Buffer.alloc(12, 0)]);
const saltPacked = pack16LEBytes(salt16);

// The hash of claims becomes the deterministic secret key `sk`
const sk_internal_FE = poseidon([1n, hIss, hAud, hSub, saltPacked]);
const sk = u8ToBigIntBE(sk_internal_FE);

// For logging/verification, we can calculate the expected public key.
// The circuit will calculate and output this publicly.
const pk = babyJub.mulPointEscalar(babyJub.Base8, sk);
const Ax = F.toObject(pk[0]);
const Ay = F.toObject(pk[1]);

console.log("--- Deterministic Key Generation ---");
console.log("sk (derived from JWT claims):", sk.toString());
console.log("pk.Ax (derived from sk):", Ax.toString());
console.log("pk.Ay (derived from sk):", Ay.toString());
console.log("------------------------------------");



  // 8. Write input.json
  fs.writeFileSync('./build/input.json', JSON.stringify(circuitInputs, (key, value) =>
    typeof value === 'bigint' ? value.toString() : value, 2));
  console.log('[zk:input] input.json file created successfully.');
  
  const t_end = Date.now();
  console.log(`[zk:input] TOTAL: ${t_end - t0} ms`);

})().catch((e) => {
  console.error('[make_proof.js] ERROR:', e);
  process.exit(1);
});
