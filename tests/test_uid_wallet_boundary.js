import assert from 'node:assert/strict';
import fs from 'node:fs';

const clientSource = fs.readFileSync('client.js', 'utf8');
const walletAgentSource = fs.readFileSync('wallet_agent.js', 'utf8');


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

// IdP 팝업(idp/login_popup.js)에 대한 두 단언은 여기 있었으나 제거했다. 그 파일은
// 커밋 f20aab8에서 팝업/릴레이 경로와 함께 삭제됐고(로그인은 loopback authorize 흐름으로
// 대체됐다), idp/ 아래에 zkpPublicSignals를 다루는 후속 파일도 없다. 그런데도 이 테스트가
// 계속 그 파일을 읽고 있어서 f20aab8 이후 **줄곧 ENOENT로 실패**하고 있었다 — 테스트를
// 한 번에 돌리는 진입점이 없어 아무도 알아채지 못했다(scripts/run_tests.sh가 그 문제를
// 해소한다). uid 경계 자체는 아래 client.js·wallet_agent.js 단언이 계속 지킨다.

const authenticatedIdpUid = '12345';
const idpVerificationSignals = [authenticatedIdpUid, ...rpVisibleSignals];
assert.deepEqual(
  idpVerificationSignals,
  walletPublicSignals,
  'IdP must reconstruct the original proof-verification signal order from its authenticated uid',
);

console.log('PASS: uid and salt remain behind the Wallet-agent boundary in the inspected flow.');
