import { buildPoseidon } from 'circomlibjs';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function main() {
  const tmpDir = fs.mkdtempSync('/tmp/pi_ppid_poseidon_test-');

  const uid = 12345n;
  const salt = 111222n;
  const rid = 123456789n;

  const poseidon = await buildPoseidon();
  const ppid = poseidon.F.toObject(poseidon([uid, rid, salt]));

  console.log('Compiling circuit...');
  execSync(
    `circom circuits/pi_ppid.circom --r1cs --wasm --sym -l circuits -o ${tmpDir}`,
    { stdio: 'inherit' }
  );

  const goodInputs = {
    uid: uid.toString(),
    salt: salt.toString(),
    rid: rid.toString(),
    ppid: ppid.toString(),
  };
  const inputPathGood = path.join(tmpDir, 'input_good.json');
  fs.writeFileSync(inputPathGood, JSON.stringify(goodInputs, null, 2));

  console.log('Generating witness with Poseidon-consistent ppid (expect success)...');
  execSync(
    `node ${tmpDir}/pi_ppid_js/generate_witness.js ${tmpDir}/pi_ppid_js/pi_ppid.wasm ${inputPathGood} ${tmpDir}/witness_good.wtns`,
    { stdio: 'inherit' }
  );
  console.log('PASS: Poseidon-consistent witness generated.');

  // The old multiplicative value must now be rejected — this is the actual
  // migration check: the circuit no longer accepts uid*rid*salt as ppid.
  const oldPpid = (uid * rid * salt) % FIELD_PRIME;
  const badInputs = { ...goodInputs, ppid: oldPpid.toString() };
  const inputPathBad = path.join(tmpDir, 'input_bad.json');
  fs.writeFileSync(inputPathBad, JSON.stringify(badInputs, null, 2));

  console.log('Generating witness with the OLD multiplicative ppid (expect failure)...');
  try {
    execSync(
      `node ${tmpDir}/pi_ppid_js/generate_witness.js ${tmpDir}/pi_ppid_js/pi_ppid.wasm ${inputPathBad} ${tmpDir}/witness_bad.wtns`,
      { stdio: 'pipe' }
    );
    throw new Error('FAIL: witness generation should have failed for the old multiplicative ppid');
  } catch (err) {
    if (err.message.startsWith('FAIL:')) throw err;
    console.log('PASS: old multiplicative ppid correctly rejected (constraint violation).');
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
