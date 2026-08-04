// Requires wallet_agent.js (:5001), server.js (:3000), custom_idp.js (:4000)
// running and key-consistent. Run: node tests/test_wallet_login_loopback.js
// Only covers the auto-testable portion (see design spec): through /par
// succeeding and the job reaching awaiting_browser_login. Full completion
// requires a human finishing login/consent in the opened browser tab — a
// separate, controller-driven manual check.
const SERVER = 'http://127.0.0.1:3000';
const WALLET = 'http://127.0.0.1:5001';

async function getWalletAgentToken() {
  return (await (await fetch(`${SERVER}/api/mode2/wallet_agent_token`)).json()).token;
}

async function startJobToApproval(token) {
  const registration = await (await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })).json();
  const startRes = await fetch(`${WALLET}/startLogin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ rpCredential: registration, r_i: '111', rpNonce: '222' }),
  });
  const { jobId } = await startRes.json();
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    const statusBody = await (await fetch(`${WALLET}/loginStatus?jobId=${jobId}`, {
      headers: { 'X-Wallet-Agent-Token': token },
    })).json();
    if (statusBody.status === 'awaiting_wallet_approval') return jobId;
    if (statusBody.status === 'failed') throw new Error(`FAIL: job failed before approval: ${statusBody.error}`);
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error('FAIL: job never reached awaiting_wallet_approval');
}

async function pollUntil(token, jobId, predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    last = await (await fetch(`${WALLET}/loginStatus?jobId=${jobId}`, {
      headers: { 'X-Wallet-Agent-Token': token },
    })).json();
    if (predicate(last)) return last;
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`FAIL: timed out waiting for condition, last status: ${JSON.stringify(last)}`);
}

async function testConcurrentJobsDoNotCorruptSessionKeys(token) {
  console.log('-- two /startLogin jobs back-to-back both reach awaiting_browser_login independently (session-key isolation) --');
  const registrationA = await (await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })).json();
  const startARes = await fetch(`${WALLET}/startLogin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ rpCredential: registrationA, r_i: '333', rpNonce: '444' }),
  });
  const { jobId: jobIdA } = await startARes.json();

  const registrationB = await (await fetch(`${SERVER}/api/mode2/register`, { method: 'POST' })).json();
  const startBRes = await fetch(`${WALLET}/startLogin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ rpCredential: registrationB, r_i: '555', rpNonce: '666' }),
  });
  const { jobId: jobIdB } = await startBRes.json();

  const approvalA = await pollUntil(token, jobIdA, (s) => s.status === 'awaiting_wallet_approval' || s.status === 'failed', 10000);
  if (approvalA.status !== 'awaiting_wallet_approval') throw new Error(`FAIL: job A never reached awaiting_wallet_approval: ${JSON.stringify(approvalA)}`);
  const approvalB = await pollUntil(token, jobIdB, (s) => s.status === 'awaiting_wallet_approval' || s.status === 'failed', 10000);
  if (approvalB.status !== 'awaiting_wallet_approval') throw new Error(`FAIL: job B never reached awaiting_wallet_approval: ${JSON.stringify(approvalB)}`);

  await fetch(`${WALLET}/confirmLoginResult`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ jobId: jobIdA, approved: true }),
  });
  await fetch(`${WALLET}/confirmLoginResult`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ jobId: jobIdB, approved: true }),
  });

  const finalA = await pollUntil(token, jobIdA, (s) => s.status === 'awaiting_browser_login' || s.status === 'failed', 10000);
  const finalB = await pollUntil(token, jobIdB, (s) => s.status === 'awaiting_browser_login' || s.status === 'failed', 10000);
  if (finalA.status !== 'awaiting_browser_login') throw new Error(`FAIL: job A did not reach awaiting_browser_login (session-key corruption?): ${JSON.stringify(finalA)}`);
  if (finalB.status !== 'awaiting_browser_login') throw new Error(`FAIL: job B did not reach awaiting_browser_login (session-key corruption?): ${JSON.stringify(finalB)}`);
  console.log('PASS: both concurrent jobs independently reached awaiting_browser_login — session keys were not cross-contaminated');
}

async function main() {
  const token = await getWalletAgentToken();

  console.log('-- /confirmLoginResult with unknown jobId (expect 404) --');
  const unknownRes = await fetch(`${WALLET}/confirmLoginResult`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ jobId: 'does-not-exist', approved: true }),
  });
  if (unknownRes.status !== 404) throw new Error(`FAIL: expected 404, got ${unknownRes.status}`);
  console.log('PASS: unknown jobId rejected');

  console.log('-- approved: false leads to denied status --');
  const deniedJobId = await startJobToApproval(token);
  const denyRes = await fetch(`${WALLET}/confirmLoginResult`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ jobId: deniedJobId, approved: false }),
  });
  if (denyRes.status !== 200) throw new Error(`FAIL: expected 200, got ${denyRes.status}`);
  const deniedStatus = await (await fetch(`${WALLET}/loginStatus?jobId=${deniedJobId}`, {
    headers: { 'X-Wallet-Agent-Token': token },
  })).json();
  if (deniedStatus.status !== 'denied') throw new Error(`FAIL: expected denied, got ${deniedStatus.status}`);
  console.log('PASS: Snap denial correctly sets status to denied');

  console.log('-- approved: true reaches awaiting_browser_login (/par succeeded) --');
  const approvedJobId = await startJobToApproval(token);
  const approveRes = await fetch(`${WALLET}/confirmLoginResult`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ jobId: approvedJobId, approved: true }),
  });
  if (approveRes.status !== 200) throw new Error(`FAIL: expected 200, got ${approveRes.status}`);
  const afterApproval = await pollUntil(
    token, approvedJobId,
    (s) => s.status === 'awaiting_browser_login' || s.status === 'failed',
    10000,
  );
  if (afterApproval.status !== 'awaiting_browser_login') {
    throw new Error(`FAIL: expected awaiting_browser_login, got ${afterApproval.status} (${afterApproval.error ?? ''})`);
  }
  console.log('PASS: job reached awaiting_browser_login — /par succeeded, loopback listener is open and waiting');

  if (typeof afterApproval.requestUri !== 'string' || afterApproval.requestUri.length === 0) {
    throw new Error(`FAIL: expected non-empty string requestUri, got ${JSON.stringify(afterApproval.requestUri)}`);
  }
  console.log('PASS: /loginStatus exposes a non-empty requestUri once /par succeeds');

  await testConcurrentJobsDoNotCorruptSessionKeys(token);

  console.log('ALL WALLET LOOPBACK TESTS PASSED (manual browser completion not covered — see design spec)');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
