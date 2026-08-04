import { buildPoseidon } from 'circomlibjs';

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function main() {
  const uid = 12345n;
  const salt = 111222n;
  const rid1 = 123456789n;
  const rid2 = 987654321n;

  // Old (rejected) construction: PPID = uid * rid * salt is transparently
  // multiplicative, so cross-multiplying two RPs' public PPID/rid pairs
  // reveals whether they share the same uid*salt, even without knowing
  // uid or salt. Confirm this actually holds for the old scheme first, to
  // prove the test methodology is meaningful before checking the new one.
  const oldPpid1 = (uid * rid1 * salt) % FIELD_PRIME;
  const oldPpid2 = (uid * rid2 * salt) % FIELD_PRIME;
  const oldCrossCheck = (oldPpid1 * rid2) % FIELD_PRIME === (oldPpid2 * rid1) % FIELD_PRIME;
  if (!oldCrossCheck) {
    throw new Error('FAIL: old multiplicative construction should be cross-linkable, but the check did not hold. Test fixture is broken.');
  }
  console.log('PASS: old multiplicative PPID is confirmed cross-linkable (expected, motivates the fix).');

  // New construction: PPID = Poseidon(uid, rid, salt). The same
  // cross-multiplication check must NOT hold, since a hash output carries
  // no algebraic relationship to its inputs.
  const poseidon = await buildPoseidon();
  const newPpid1 = poseidon.F.toObject(poseidon([uid, rid1, salt]));
  const newPpid2 = poseidon.F.toObject(poseidon([uid, rid2, salt]));
  const newCrossCheck = (newPpid1 * rid2) % FIELD_PRIME === (newPpid2 * rid1) % FIELD_PRIME;
  if (newCrossCheck) {
    throw new Error('FAIL: Poseidon-based PPID should not be cross-linkable, but the check held.');
  }
  console.log('PASS: Poseidon-based PPID is not cross-linkable via cross-multiplication.');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
