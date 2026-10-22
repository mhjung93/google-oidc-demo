// IdP 세션 폐기 요청의 허용 거래 수 bound(설계 2026-10-22 §3) — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_revoke_bound.mjs
import assert from 'node:assert/strict';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { randomScalar } from '../lib/mode3_credential.js';
import { sessionLeaf, SESSION_BOUND_MAX } from '../lib/mode3_revocation.js';
import { signRevokeSession } from '../lib/mode3_wallet.js';
import { issueV11, userOf, TESTUSER_ATTRS } from './helpers/mode3_flow.mjs';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const provider = getProvider();
const cia = await startIsolatedCia();
const arid = 22222222222222222222n;
const uid = 12345n;
let user;   // userOf(registerUser('12345'))

/** 세션 하나 새로 발급(매번 새 blind_u → 새 C_u → 독립된 세션) → Cf_s 를 돌려준다. */
async function freshSession() {
  const iss = await issueV11(cia, user, { arid, provider });
  assert.equal(iss.r.status, 200, j(iss.r.body));
  return iss.cred.Cf_s;
}

try {
  await t('준비: 등록', async () => {
    user = userOf(await cia.registerUser('12345', 'password123'), '12345', TESTUSER_ATTRS);
  });

  await t('세션 폐기(bound): 서명이 bound 를 덮고, 리프 = sessionLeaf(Cf_s, bound), 레코드·관리자 목록에 bound', async () => {
    const Cf_s = await freshSession();
    const bound = 3n, nonce = randomScalar();
    const sig_u = await signRevokeSession(user.sk_u, uid, BigInt(Cf_s), bound, nonce);
    const r = await cia.post('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s, bound: bound.toString(), nonce: nonce.toString(), sig_u });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.inserted, true); assert.equal(r.body.bound, '3');
    assert.equal(r.body.leaf, (await sessionLeaf(BigInt(Cf_s), bound)).toString());
    const list = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions;
    assert.equal(list.find((s) => s.Cf_s === Cf_s).bound, '3');
  });

  await t('bound 가 없거나 범위 밖(2^32)이면 400; 서명의 bound 와 본문 bound 가 다르면 400 bad user signature', async () => {
    const Cf_s = await freshSession();
    const nonce = randomScalar();
    const sig_u = await signRevokeSession(user.sk_u, uid, BigInt(Cf_s), 1n, nonce);   // bound=1 로 서명
    const noBound = await cia.post('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s, nonce: nonce.toString(), sig_u });
    assert.equal(noBound.status, 400, j(noBound.body));
    const outOfRange = await cia.post('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s, bound: SESSION_BOUND_MAX.toString(), nonce: nonce.toString(), sig_u });
    assert.equal(outOfRange.status, 400, j(outOfRange.body));
    const mismatched = await cia.post('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s, bound: '2', nonce: nonce.toString(), sig_u });   // 본문 bound=2 ≠ 서명 bound=1
    assert.equal(mismatched.status, 400, j(mismatched.body)); assert.equal(mismatched.body.error, 'bad user signature');
  });

  await t('관리자 폐기는 bound 기본 0(전부 차단), bound 를 주면 그 값', async () => {
    const Cf_sA = await freshSession();
    const Cf_sB = await freshSession();
    const rA = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: Cf_sA });
    assert.equal(rA.status, 200, j(rA.body)); assert.equal(rA.body.bound, '0');
    assert.equal(rA.body.leaf, (await sessionLeaf(BigInt(Cf_sA), 0n)).toString());
    const rB = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: Cf_sB, bound: '5' });
    assert.equal(rB.status, 200, j(rB.body)); assert.equal(rB.body.bound, '5');
    assert.equal(rB.body.leaf, (await sessionLeaf(BigInt(Cf_sB), 5n)).toString());
  });
} finally {
  await cia.stop();
  provider.destroy();
}

process.exit(failed === 0 ? 0 : 1);
