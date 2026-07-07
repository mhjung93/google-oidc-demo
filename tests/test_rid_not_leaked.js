import fetch from 'node-fetch';

async function main() {
  const reg = await (await fetch('http://localhost:4000/register_rp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rpName: 'RP-Regression', callbackUrl: 'http://localhost:3000/cb' })
  })).json();
  const rid = reg.rid;
  console.log('Registered rid:', rid);

  // This mirrors client.js's business object shape exactly (Task 4).
  const businessPayload = {
    uid: '12345',
    arid_i: '222',
    auid_i: '333',
    r_i: '0xabc',
    r_token: '444',
    tokenNonce: '444',
    maxHeight: '310'
  };

  const forbiddenKeys = ['rid', 'rp_nonce', 'ppid'];
  for (const key of forbiddenKeys) {
    if (Object.prototype.hasOwnProperty.call(businessPayload, key)) {
      throw new Error(`FAIL: business payload must not contain "${key}"`);
    }
  }
  const serialized = JSON.stringify(businessPayload);
  if (serialized.includes(rid)) {
    throw new Error('FAIL: rid leaked into the wallet->IdP business payload');
  }
  console.log('PASS: business payload contains none of rid / rp_nonce / ppid.');

  // This mirrors idp/login_popup.js's doLogin() payload construction (post-fix).
  // pendingZKP is the wallet's full currentSSOProof object, which includes a
  // pi_PPID field whose publicSignals[0] is the raw rid. doLogin() must build
  // an explicit allowlist (matching custom_idp.js's /sso_with_credentials
  // destructuring) instead of spreading pendingZKP wholesale, so pi_PPID (and
  // the raw rid inside it) never reaches the IdP.
  const fakeRid = 'FAKE_RID_999888777';
  const pendingZKP = {
    zkpProof: { a: '1', b: '2' },
    zkpPublicSignals: ['5', '6'],
    business: businessPayload,
    isLight: true,
    walletSubmission: { arid_i: '222', auid_i: '333' },
    pi_i: 'fake_pi_i',
    pi_PPID: {
      type: 'pi_PPID',
      proof: { a: '7', b: '8' },
      publicSignals: [fakeRid, 'fake_ppid_value'],
      r_token: '444',
      generatedAt: Date.now(),
    },
  };
  const username = 'testuser';
  const password = 'password123';
  const doLoginPayload = pendingZKP
    ? {
        username,
        password,
        zkpProof: pendingZKP.zkpProof,
        zkpPublicSignals: pendingZKP.zkpPublicSignals,
        business: pendingZKP.business,
        isLight: pendingZKP.isLight,
        walletSubmission: pendingZKP.walletSubmission,
        pi_i: pendingZKP.pi_i,
      }
    : { username, password };

  if (Object.prototype.hasOwnProperty.call(doLoginPayload, 'pi_PPID')) {
    throw new Error('FAIL: doLogin() payload must not contain "pi_PPID"');
  }
  const doLoginSerialized = JSON.stringify(doLoginPayload);
  if (doLoginSerialized.includes(fakeRid)) {
    throw new Error('FAIL: raw rid leaked into the doLogin() /sso_with_credentials payload');
  }
  console.log('PASS: doLogin() /sso_with_credentials payload omits pi_PPID and the raw rid.');

  console.log('PASS: rid-hiding regression check complete.');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
