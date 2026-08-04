import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { randomBytes } from 'crypto';

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function valueToField(value) {
  if (typeof value === 'bigint') return value % FIELD_PRIME;
  if (typeof value === 'number') return BigInt(value) % FIELD_PRIME;
  const str = String(value);
  if (str.startsWith('0x')) return BigInt(str) % FIELD_PRIME;
  if (/^[0-9]+$/.test(str)) return BigInt(str) % FIELD_PRIME;
  const bytes = new TextEncoder().encode(str);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return BigInt(`0x${hex || '0'}`) % FIELD_PRIME;
}

async function test() {
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = eddsa.F;

  const sk_IdP = randomBytes(32);
  const pk_IdP = eddsa.prv2pub(sk_IdP);

  const rp_nonce = valueToField('rp-nonce-test');
  const rid = valueToField('rid-test');
  const uid = valueToField('12345');
  const salt = valueToField('salt-test');
  const pk_i = valueToField('0x04deadbeef1234567890abcdef');
  const max_height = valueToField('1000');
  const chain_id = valueToField('1337');

  const PPID = (uid * rid * salt) % FIELD_PRIME;
  const arid_i = (rid * rp_nonce) % FIELD_PRIME;
  const auid_i = (PPID * rp_nonce) % FIELD_PRIME;
  const r_token = poseidon.F.toObject(poseidon([pk_i, max_height, rp_nonce]));

  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const msgFields = [DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id];
  const msg = poseidon(msgFields);
  const sig = eddsa.signPoseidon(sk_IdP, msg);

  const input = {
    rp_nonce: rp_nonce.toString(),
    arid_i: arid_i.toString(),
    auid_i: auid_i.toString(),
    r_token: r_token.toString(),
    chain_id: chain_id.toString(),
    S: sig.S.toString(),
    R8x: F.toObject(sig.R8[0]).toString(),
    R8y: F.toObject(sig.R8[1]).toString(),
    pk_i: pk_i.toString(),
    pk_IdP_x: F.toObject(pk_IdP[0]).toString(),
    pk_IdP_y: F.toObject(pk_IdP[1]).toString(),
    PPID: PPID.toString(),
    max_height: max_height.toString(),
  };

  const wc = await import('../build/mode2/pi_pk_i_js/witness_calculator.cjs');
  const fs = await import('fs');
  const wasmBuffer = await fs.promises.readFile('build/mode2/pi_pk_i_js/pi_pk_i.wasm');
  const witnessCalculator = await wc.default(wasmBuffer);

  // 1. 유효한 값 -> witness 계산 성공해야 함
  await witnessCalculator.calculateWitness(input, true);
  console.log('✅ Valid witness computed successfully.');

  // 2. auid_i 조작 -> witness 계산 실패해야 함 (constraint 위반)
  const tamperedInput = { ...input, auid_i: (auid_i + 1n).toString() };
  try {
    await witnessCalculator.calculateWitness(tamperedInput, true);
    console.error('FAIL: tampered auid_i was accepted');
    process.exit(1);
  } catch (err) {
    console.log('✅ Tampered auid_i correctly rejected:', err.message);
  }

  console.log('pi_pk_i circuit test: ALL CHECKS PASSED');
}

test();
