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
// custom_idp.js가 verifySignals[5]로 auid를 읽으므로 auid는 반드시 6번째(0-based 5) 공개
// 신호여야 한다. 뒤에 신호가 더 붙는 것은 무방하다 — 실제로 pk_IdP_x/pk_IdP_y가 나중에
// 추가됐고, 목록 전체를 통째로 단정했던 예전 형태는 그때부터 이 테스트를 깨뜨리고 있었다.
assert.match(
  circuitSource,
  /component main \{public \[uid, arid_i, auid_i, max_height, token_nonce, auid[,\]]/,
  'auid must be the 6th public signal — custom_idp.js reads it as verifySignals[5]',
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
// pi_arid_i의 public signal은 8개(uid, arid_i, auid_i, max_height, token_nonce, auid,
// pk_IdP_x, pk_IdP_y)다. 지갑은 uid를 빼고 7개를 보내고, IdP가 uid를 앞에 붙여 8개로 검증한다.
// 회로에 signal을 추가하면 이 두 숫자도 함께 갱신해야 한다 — pk_IdP_x/y가 추가됐을 때
// 갱신되지 않아 이 테스트가 한동안 실패 상태로 방치돼 있었다.
assert.match(
  idpSource,
  /assertDecimalSignals\(zkpPublicSignals, 7, 'pi_i without uid'\)/,
  'custom_idp.js must expect 7 signals from the wallet (8 public signals minus uid)',
);
assert.match(
  idpSource,
  /assertDecimalSignals\(verifySignals, 8, 'pi_i'\)/,
  'custom_idp.js must expect 8 signals after re-prepending uid',
);
assert.match(
  idpSource,
  /Wallet binding mismatch/,
  "custom_idp.js must reject logins whose auid differs from the account's last successful login",
);

// 로그인 경로가 둘이므로 한쪽에만 검사가 있으면 폐기가 그대로 우회된다 — 실제로
// /authorize/login(PAR 흐름)에 이 검사가 빠져 있었고, salt를 갈아끼운 지갑이 다른 auid를
// 제시해 자기 계정 폐기 리프 Poseidon(TAG_ACCOUNT, auid)를 통과할 수 있었다.
// 두 경로가 모두 공용 헬퍼를 부르는지 확인한다.
function bodyOf(source, startMarker) {
  const start = source.indexOf(startMarker);
  assert.notEqual(start, -1, `custom_idp.js must still contain ${startMarker}`);
  const rest = source.slice(start + startMarker.length);
  // 다음 최상위 정의(라우트 또는 함수)까지를 이 핸들러의 본문으로 본다.
  const end = rest.search(/\n(?:app\.(?:post|get|use)\(|(?:async )?function )/);
  return end === -1 ? rest : rest.slice(0, end);
}

for (const marker of ["app.post('/authorize/login'", 'async function verifyPiIAndIssueToken']) {
  assert.match(
    bodyOf(idpSource, marker),
    /pinAuidToAccount\(user, verifySignals\[5\]\)/,
    `${marker} must pin auid — otherwise account revocation is bypassable from that login path`,
  );
}

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
