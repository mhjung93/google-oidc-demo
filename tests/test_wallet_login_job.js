// Requires wallet_agent.js (:5001), server.js (:3000), custom_idp.js (:4000)
// running and key-consistent (see CLAUDE.md's restart-chain notes).
// Run: node tests/test_wallet_login_job.js
const SERVER = 'http://127.0.0.1:3000';
const WALLET = 'http://127.0.0.1:5001';

async function getWalletAgentToken() {
  return (await (await fetch(`${SERVER}/api/mode2/wallet_agent_token`)).json()).token;
}

async function main() {
  const registration = await (await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })).json();
  const token = await getWalletAgentToken();

  console.log('-- POST /startLogin (expect 202 + jobId) --');
  const startRes = await fetch(`${WALLET}/startLogin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ rpCredential: registration, r_i: '555', rpNonce: '666' }),
  });
  const startBody = await startRes.json();
  if (startRes.status !== 202 || !startBody.jobId) {
    throw new Error(`FAIL: expected 202 + jobId, got ${startRes.status} ${JSON.stringify(startBody)}`);
  }
  console.log('PASS:', startBody.jobId);

  console.log('-- poll /loginStatus until awaiting_wallet_approval (expect within 10s) --');
  const deadline = Date.now() + 10000;
  let lastStatus = null;
  while (Date.now() < deadline) {
    const statusBody = await (await fetch(`${WALLET}/loginStatus?jobId=${startBody.jobId}`, {
      headers: { 'X-Wallet-Agent-Token': token },
    })).json();
    lastStatus = statusBody.status;
    if (lastStatus === 'awaiting_wallet_approval') break;
    if (lastStatus === 'failed') throw new Error(`FAIL: job failed during proof generation: ${statusBody.error}`);
    await new Promise((r) => setTimeout(r, 300));
  }
  if (lastStatus !== 'awaiting_wallet_approval') {
    throw new Error(`FAIL: expected awaiting_wallet_approval within 10s, last status was ${lastStatus}`);
  }
  console.log('PASS: job reached awaiting_wallet_approval');

  console.log('-- GET /loginStatus with unknown jobId (expect 404) --');
  const unknownRes = await fetch(`${WALLET}/loginStatus?jobId=does-not-exist`, {
    headers: { 'X-Wallet-Agent-Token': token },
  });
  if (unknownRes.status !== 404) throw new Error(`FAIL: expected 404, got ${unknownRes.status}`);
  console.log('PASS: unknown jobId rejected');

  console.log('-- GET /loginStatus for a still-valid job is unaffected by the pruneExpiredJobs() call (expect 200, same status) --');
  const stillValidRes = await fetch(`${WALLET}/loginStatus?jobId=${startBody.jobId}`, {
    headers: { 'X-Wallet-Agent-Token': token },
  });
  if (stillValidRes.status !== 200) throw new Error(`FAIL: expected 200 for a still-valid job, got ${stillValidRes.status}`);
  const stillValidBody = await stillValidRes.json();
  if (stillValidBody.status !== 'awaiting_wallet_approval') {
    throw new Error(`FAIL: expected awaiting_wallet_approval, got ${stillValidBody.status}`);
  }
  console.log('PASS: pruneExpiredJobs() in /loginStatus does not affect a still-valid job');

  console.log('-- existing /generateStep8Proofs still works after the refactor (non-regression) --');
  const legacyRes = await fetch(`${WALLET}/generateStep8Proofs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ rpCredential: registration, r_i: '777', rpNonce: '888' }),
  });
  const legacyBody = await legacyRes.json();
  if (legacyRes.status !== 200 || !legacyBody.zkpProof) {
    throw new Error(`FAIL: /generateStep8Proofs regressed: ${legacyRes.status} ${JSON.stringify(legacyBody)}`);
  }
  console.log('PASS: /generateStep8Proofs unaffected by the refactor');

  console.log('ALL WALLET LOGIN JOB TESTS PASSED');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
