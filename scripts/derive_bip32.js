// derive_bip32.js (ESM)
import BIP32Factory from 'bip32';
import * as ecc from '@bitcoinerlab/secp256k1';   // ✅ tiny-secp256k1 호환 (isPoint 등 제공)
import { createHash, hkdfSync, randomBytes } from 'node:crypto';
import fs from 'node:fs';

const bip32 = BIP32Factory(ecc);                  // ✅ bip32@5와 호환

const t = () => Date.now();
const ms = (a, b) => `${(b - a).toFixed(0)} ms`;

function sha256Buf(str) {
  return createHash('sha256').update(str).digest();
}

function seedFromIdToken(idToken, salt = undefined, info = 'OIDC-BIP32') {
  const t0 = t();
  const ikm = sha256Buf(idToken);
  const t1 = t();
  const _salt = salt || randomBytes(32);
  const t2 = t();
  const okm = hkdfSync('sha256', ikm, _salt, info, 32); // Buffer(32)
  const t3 = t();

  console.log(`[derive] sha256(id_token): ${ms(t0, t1)}`);
  console.log(`[derive] salt gen:          ${ms(t1, t2)}`);
  console.log(`[derive] hkdf sha256 (32B): ${ms(t2, t3)}`);

  return { seed: okm, salt: _salt };
}

function deriveChildFromSeed(seed, path = `m/44'/0'/0'/0/0`) {
  const a0 = t();
  const master = bip32.fromSeed(Buffer.from(seed));
  const a1 = t();
  const child = master.derivePath(path);
  const a2 = t();
  if (!child.privateKey) throw new Error('Child has no private key');

  const priv = child.privateKey;         // Buffer(32)
  const a3 = t();
  // bip32가 제공하는 압축 공개키
  const pubFromBip32 = child.publicKey;  // Buffer(33)
  const a4 = t();
  // (검증용) tiny-secp256k1 호환 API로 공개키 계산
  const pubFromECC = ecc.pointFromScalar(priv, true); // Buffer(33) | null
  if (!pubFromECC) throw new Error('Invalid private key: pointFromScalar returned null');
  const a5 = t();

  console.log(`[derive] fromSeed(HMAC-SHA512): ${ms(a0, a1)}`);
  console.log(`[derive] derivePath(${path}):    ${ms(a1, a2)}`);
  console.log(`[derive] get priv (32B):         ${ms(a2, a3)}`);
  console.log(`[derive] pub (bip32):            ${ms(a3, a4)}`);
  console.log(`[derive] pub (ecc check):        ${ms(a4, a5)}`);

  // 안전 확인: 두 결과가 동일해야 함
  if (!Buffer.from(pubFromBip32).equals(Buffer.from(pubFromECC))) {
    console.warn('[derive] WARN: bip32와 ECC 공개키가 일치하지 않습니다.');
  }

  return {
    path,
    masterXprv: master.toBase58(),
    masterXpub: master.neutered().toBase58(),
    childPrvHex: Buffer.from(priv).toString('hex'),
    childPubHex: Buffer.from(pubFromBip32).toString('hex'),
  };
}

export function deriveFromIdToken(idToken, path) {
  const s0 = t();
  const { seed, salt } = seedFromIdToken(idToken);
  const s1 = t();
  const out = deriveChildFromSeed(seed, path);
  const s2 = t();

  console.log(`[derive] seedFromIdToken total: ${ms(s0, s1)}`);
  console.log(`[derive] BIP32 derive total:    ${ms(s1, s2)}`);
  return { ...out, saltHex: Buffer.from(salt).toString('hex') };
}

// CLI
if (process.argv[1] === new URL(import.meta.url).pathname) {
  const idToken = process.env.ID_TOKEN;
  if (!idToken) {
    console.error('Set ID_TOKEN env');
    process.exit(1);
  }
  const path = process.env.DERIVE_PATH || `m/44'/0'/0'/0/0`;
  const t0 = t();
  const res = deriveFromIdToken(idToken, path);
  const t1 = t();
  fs.writeFileSync('./bip32_out.json', JSON.stringify(res, null, 2));
  const t2 = t();

  console.log(`[derive] write bip32_out.json:   ${ms(t1, t2)}`);
  console.log(`[derive] TOTAL:                   ${ms(t0, t2)}`);
}
