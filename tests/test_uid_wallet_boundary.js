import assert from 'node:assert/strict';
import fs from 'node:fs';

const clientSource = fs.readFileSync('client.js', 'utf8');
const walletAgentSource = fs.readFileSync('wallet_agent.js', 'utf8');
const idpPopupSource = fs.readFileSync('idp/login_popup.js', 'utf8');

assert.doesNotMatch(
  clientSource,
  /ssoMetadata\.uid|uid\s*:\s*['"]12345['"]|auth token\.uid/,
  'client.js must not store, send, or display uid',
);

assert.match(
  walletAgentSource,
  /const DEMO_BOUND_UID = ['"]12345['"];/,
  'wallet_agent.js must own the demo Wallet-IdP uid binding',
);
assert.match(
  walletAgentSource,
  /hasOwnProperty\.call\(req\.body \?\? \{\}, ['"]uid['"]\)/,
  'wallet_agent.js must reject an RP-supplied uid',
);
assert.match(
  walletAgentSource,
  /const uidField = valueToField\(DEMO_BOUND_UID\);/,
  'wallet_agent.js must derive the uid witness from its internal binding',
);
assert.match(
  walletAgentSource,
  /zkpPublicSignals:\s*publicSignals\.slice\(1\)/,
  'wallet_agent.js must remove uid from public signals before responding to RP FE',
);

const walletPublicSignals = ['12345', 'arid_i', 'auid_i', 'max_height', 'token_nonce'];
const rpVisibleSignals = walletPublicSignals.slice(1);
assert.deepEqual(
  rpVisibleSignals,
  ['arid_i', 'auid_i', 'max_height', 'token_nonce'],
  'RP FE must receive only the four uid-free IdP verification signals',
);
assert(!rpVisibleSignals.includes('12345'), 'RP-visible signals must not contain uid');

assert.match(
  idpPopupSource,
  /function zkpSignalsWithoutUid\(\)[\s\S]*?\? pendingZKP\.zkpPublicSignals\s*:/,
  'IdP popup must forward the already uid-free signals without slicing again',
);
assert.doesNotMatch(
  idpPopupSource,
  /pendingZKP\.zkpPublicSignals\.slice\(1\)/,
  'IdP popup must not remove a second signal',
);

const authenticatedIdpUid = '12345';
const idpVerificationSignals = [authenticatedIdpUid, ...rpVisibleSignals];
assert.deepEqual(
  idpVerificationSignals,
  walletPublicSignals,
  'IdP must reconstruct the original proof-verification signal order from its authenticated uid',
);

console.log('PASS: uid and salt remain behind the Wallet-agent boundary in the inspected flow.');
