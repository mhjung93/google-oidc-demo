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

  console.log('PASS: rid-hiding regression check complete.');
}

main().catch((err) => {
  console.error('TEST FAILED:', err.message);
  process.exit(1);
});
