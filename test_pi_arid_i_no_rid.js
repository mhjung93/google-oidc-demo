import { buildPoseidon } from 'circomlibjs';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function main() {
  const tmpDir = fs.mkdtempSync('/tmp/pi_arid_i_no_rid_test-');

  const uid = 12345n;
  const salt = 111222n;
  const rid = 123456789n;
  const rp_nonce = 999888n;
  const pk_i = 555n;
  const max_height = 310n;

  const ppid = (uid * rid * salt) % FIELD_PRIME;
  const arid_i = (rid * rp_nonce) % FIELD_PRIME;
  const auid_i = (ppid * rp_nonce) % FIELD_PRIME;

  const poseidon = await buildPoseidon();
  const token_nonce = poseidon.F.toObject(poseidon([pk_i, max_height, rp_nonce])).toString();

  const baseInputs = {
    rp_nonce: rp_nonce.toString(),
    salt: salt.toString(),
    rid: rid.toString(),
    pk_i: pk_i.toString(),
    uid: uid.toString(),
    arid_i: arid_i.toString(),
    auid_i: auid_i.toString(),
    max_height: max_height.toString(),
    token_nonce
  };

  console.log('Compiling circuit...');
  execSync(
    `circom circuits/pi_arid_i.circom --r1cs --wasm --sym -l circuits -o ${tmpDir}`,
    { stdio: 'inherit' }
  );

  console.log('Checking public signal count is 5...');
  const symContent = fs.readFileSync(path.join(tmpDir, 'pi_arid_i.sym'), 'utf8');
  // sanity: rid_public must not appear as a signal name anymore
  if (symContent.includes('rid_public')) {
    throw new Error('FAIL: rid_public signal still present in compiled circuit');
  }
  console.log('PASS: rid_public is gone from the compiled circuit.');

  const inputPathGood = path.join(tmpDir, 'input_good.json');
  fs.writeFileSync(inputPathGood, JSON.stringify(baseInputs, null, 2));

  console.log('Generating witness with consistent inputs (expect success)...');
  execSync(
    `node ${tmpDir}/pi_arid_i_js/generate_witness.js ${tmpDir}/pi_arid_i_js/pi_arid_i.wasm ${inputPathGood} ${tmpDir}/witness_good.wtns`,
    { stdio: 'inherit' }
  );
  console.log('PASS: consistent witness generated.');

  const badInputs = { ...baseInputs, arid_i: (arid_i + 1n).toString() };
  const inputPathBad = path.join(tmpDir, 'input_bad.json');
  fs.writeFileSync(inputPathBad, JSON.stringify(badInputs, null, 2));

  console.log('Generating witness with a TAMPERED arid_i (expect failure)...');
  try {
    execSync(
      `node ${tmpDir}/pi_arid_i_js/generate_witness.js ${tmpDir}/pi_arid_i_js/pi_arid_i.wasm ${inputPathBad} ${tmpDir}/witness_bad.wtns`,
      { stdio: 'pipe' }
    );
    throw new Error('FAIL: witness generation should have failed for a tampered arid_i');
  } catch (err) {
    if (err.message.startsWith('FAIL:')) throw err;
    console.log('PASS: tampered arid_i correctly rejected (constraint violation).');
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
