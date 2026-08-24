import assert from 'node:assert/strict';

const BASE = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';

async function main() {
  const before = await (await fetch(`${BASE}/idp/revocation_state`)).json();
  assert.ok(typeof before.root === 'string', 'revocation_state must expose a root');
  assert.ok(Array.isArray(before.revokedLeaves), 'revocation_state must expose revokedLeaves');

  const res = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'account', value: '424242' }),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(typeof body.root === 'string');
  assert.notEqual(body.root, before.root, 'revoking must change the root');

  const after = await (await fetch(`${BASE}/idp/revocation_state`)).json();
  assert.equal(after.revokedLeaves.length, before.revokedLeaves.length + 1);

  const bad = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'nonsense', value: '1' }),
  });
  assert.equal(bad.status, 400, 'unknown revocation type must be rejected');

  console.log('PASS: IdP revoke endpoint updates the tree and exposes state.');
}

main();
