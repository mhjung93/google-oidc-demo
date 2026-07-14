// tests/test_eddsa.js
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

  // 1. KeyGen — private key is raw entropy (bytes), NOT a field element like PS's mcl.Fr.
  const prv = randomBytes(32);
  const pub = eddsa.prv2pub(prv); // [x, y], each an F-internal representation
  const pubDecimal = [F.toObject(pub[0]).toString(), F.toObject(pub[1]).toString()];
  console.log('pk_IdP (decimal):', pubDecimal);

  // 2. Compose msg exactly like the real auth token will: domain-separated Poseidon hash of
  // the 6 signed fields (matches custom_idp.js's existing PS message array
  // ['IDP_TOKEN', arid_i, auid_i, r_token, max_height, chain_id]).
  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const arid_i = valueToField('123456789');
  const auid_i = valueToField('987654321');
  const r_token = valueToField('555555');
  const max_height = valueToField('1000');
  const chain_id = valueToField('1337');

  // IMPORTANT: pass poseidon(...)'s raw return directly into signPoseidon/verifyPoseidon —
  // do NOT call poseidon.F.toObject() on it first. toObject() produces a plain BigInt for
  // display/JSON, but signPoseidon/verifyPoseidon need the F-internal representation.
  const msg = poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id]);

  // 3. Sign
  const sig = eddsa.signPoseidon(prv, msg);
  const sigJson = {
    R8: [F.toObject(sig.R8[0]).toString(), F.toObject(sig.R8[1]).toString()],
    S: sig.S.toString(),
  };
  console.log('signature (decimal):', sigJson);

  // 4. Verify (happy path) — rebuild msg/pub/sig from decimal strings exactly like a
  // separate process (server.js / wallet_agent.js) would after receiving them over HTTP.
  const pubRebuilt = [F.e(BigInt(pubDecimal[0])), F.e(BigInt(pubDecimal[1]))];
  const sigRebuilt = {
    R8: [F.e(BigInt(sigJson.R8[0])), F.e(BigInt(sigJson.R8[1]))],
    S: BigInt(sigJson.S),
  };
  const msgRebuilt = poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id]);
  const isValid = eddsa.verifyPoseidon(msgRebuilt, sigRebuilt, pubRebuilt);
  console.log('verify (expect true):', isValid);
  if (!isValid) {
    console.error('FAIL: valid signature was rejected');
    process.exit(1);
  }

  // 5. Tamper with one field and confirm verification now fails.
  const tamperedArid = valueToField('999999999');
  const msgTampered = poseidon([DOMAIN_IDP_TOKEN, tamperedArid, auid_i, r_token, max_height, chain_id]);
  const isTamperedValid = eddsa.verifyPoseidon(msgTampered, sigRebuilt, pubRebuilt);
  console.log('verify tampered (expect false):', isTamperedValid);
  if (isTamperedValid) {
    console.error('FAIL: tampered message was accepted');
    process.exit(1);
  }

  console.log('EdDSA-Poseidon round-trip: ALL CHECKS PASSED');
}

test();
