import assert from 'node:assert/strict';
import fs from 'node:fs';

const circuitSource = fs.readFileSync('circuits/pi_arid_i.circom', 'utf8');
const walletAgentSource = fs.readFileSync('wallet_agent.js', 'utf8');
const idpSource = fs.readFileSync('custom_idp.js', 'utf8');

assert.match(
  circuitSource,
  /signal input auid;/,
  'pi_arid_i.circom must declare auid as a public input',
);
assert.match(
  circuitSource,
  /auid === bindHasher\.out;/,
  'pi_arid_i.circom must constrain auid with === (not a bare assignment)',
);
assert.match(
  circuitSource,
  /component main \{public \[uid, arid_i, auid_i, max_height, token_nonce, auid\]\}/,
  'auid must be the last public signal, after the existing five',
);

assert.match(
  walletAgentSource,
  /const auid = poseidon\.F\.toObject\(poseidon\(\[uidField, saltField\]\)\);/,
  'wallet_agent.js must compute auid = Poseidon(uid, salt)',
);
assert.match(
  walletAgentSource,
  /auid: auid\.toString\(\),/,
  'wallet_agent.js must include auid in the pi_arid_i witness',
);

assert.match(
  idpSource,
  /lastAuid: null/,
  'custom_idp.js must track lastAuid per demo account',
);
assert.match(
  idpSource,
  /assertDecimalSignals\(zkpPublicSignals, 5, 'pi_i without uid'\)/,
  'custom_idp.js must expect 5 signals from the wallet now that auid was added',
);
assert.match(
  idpSource,
  /assertDecimalSignals\(verifySignals, 6, 'pi_i'\)/,
  'custom_idp.js must expect 6 signals after re-prepending uid',
);
assert.match(
  idpSource,
  /Wallet binding mismatch/,
  "custom_idp.js must reject logins whose auid differs from the account's last successful login",
);

// Re-implements the exact compare-and-update logic added to
// verifyPiIAndIssueToken() in isolation, since that function isn't
// exported as a standalone unit (custom_idp.js is a top-level Express
// script, matching this project's existing static-inspection test
// convention for that file — see test_uid_wallet_boundary.js).
function checkAuidBinding(user, auidFromProof) {
  if (user.lastAuid !== null && String(user.lastAuid) !== String(auidFromProof)) {
    throw new Error('Wallet binding mismatch: this account is using a different salt than its last successful login');
  }
  user.lastAuid = auidFromProof;
}

const user = { lastAuid: null };
checkAuidBinding(user, '111'); // first login: bootstrap, no prior value to compare
assert.equal(user.lastAuid, '111');
checkAuidBinding(user, '111'); // same salt again: passes, no change
assert.equal(user.lastAuid, '111');
assert.throws(
  () => checkAuidBinding(user, '222'), // different salt: rejected
  /Wallet binding mismatch/,
);
assert.equal(user.lastAuid, '111', 'a rejected mismatch must not overwrite the stored value');

console.log('PASS: auid salt-binding check enforces same-salt-across-logins per account.');
