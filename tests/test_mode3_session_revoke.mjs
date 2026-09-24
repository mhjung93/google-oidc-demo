// CIA 세션 폐기(설계 2026-09-24 V8) — 발급 세션 기록, /cia/revoke scope=session, 관리자 세션 목록. 격리 CIA + :8545. (chain 그룹)
//   node tests/test_mode3_session_revoke.mjs
import assert from 'node:assert/strict';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createRegistration, createSessionKey, buildUserCredRequest, buildIssueRequest, signRevokeSession } from '../lib/mode3_wallet.js';
import { sessionLeaf } from '../lib/mode3_revocation.js';
import { pointToStrings } from '../lib/mode3_issuance.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

// provider 는 하나만 만든다 — mode3_chain.mjs 는 캐시하지 않아 호출마다 폴링 타이머가 하나씩 는다.
const provider = getProvider();
const cia = await startIsolatedCia();

const UID = '12345';                    // 데모 계정 testuser
const uid = BigInt(UID);
const arid = 22222222222222222222n;
const CHAIN_ID = 31337n;
const TESTUSER_ATTRS = [1990n, 410n, 2n, 0n];   // AA 가 보증하는 데모 속성(cia.js DEMO_ACCOUNTS)

try {
  // 등록 → 사용자 자격증명(C_u) → 세션 발급. test_mode3_wallet.mjs / test_cia_register_issue.mjs 의 준비 코드와 같은 흐름이다.
  const reg = await createRegistration();
  const registered = await cia.post('/cia/register', { uid: UID, pwd: 'password123', cm_u: pointToStrings(reg.cm_u) });
  assert.equal(registered.status, 201, JSON.stringify(registered.body));
  const sk_u = registered.body.sk_u;
  const uc = await buildUserCredRequest({ uid, s_u: reg.s_u, r_u: reg.r_u, sk_u, attrs: TESTUSER_ATTRS });
  const userCred = await cia.post('/cia/user_cred', uc.body);
  assert.equal(userCred.status, 201, JSON.stringify(userCred.body));

  /** 세션 하나 발급. 세션키·blind_s 가 매번 새로 뽑히므로 Cf_s 도 매번 다르다. */
  async function issueWith({ max_height } = {}) {
    const mh = max_height ?? BigInt(await provider.getBlockNumber()) + 300n;
    const req = await buildIssueRequest({ uid, Cf_u: uc.Cf_u, arid, sk_u, session: createSessionKey(), chainid: CHAIN_ID, max_height: mh });
    const r = await cia.post('/cia/issue', req.body);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    return r;
  }

  const issued1 = await issueWith();
  const issued2 = await issueWith();

  await t('발급이 세션 기록을 남긴다(관리자 조회)', async () => {
    const r = await cia.adminGet(`/cia/admin/sessions?uid=${UID}`);
    assert.equal(r.status, 200);
    assert.equal(r.body.sessions.length, 2);
    assert.ok(r.body.sessions.some((s) => s.Cf_s === issued1.body.Cf_s && s.revokedAt === null));
    const rec = r.body.sessions.find((s) => s.Cf_s === issued2.body.Cf_s);
    assert.equal(rec.chainid, CHAIN_ID.toString());
    assert.equal(rec.max_height, issued2.body.max_height);
    assert.equal(rec.allowAgent, '0');
    assert.equal(rec.expired, false, '아직 만료 전');
  });

  await t('관리자 세션 목록은 관리자 시크릿을 요구하고, 모르는 계정은 404', async () => {
    assert.equal((await cia.get(`/cia/admin/sessions?uid=${UID}`)).status, 401);
    assert.equal((await cia.adminGet('/cia/admin/sessions?uid=424242')).status, 404);
  });

  await t('사용자 서명으로 세션 하나 폐기 → 리프 pending, 다시 하면 멱등, 다른 세션은 그대로', async () => {
    const nonce = 12345n;
    const sig_u = await signRevokeSession(sk_u, uid, BigInt(issued1.body.Cf_s), nonce);
    const r = await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued1.body.Cf_s, sig_u, nonce: nonce.toString() });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.inserted, true);
    assert.equal(BigInt(r.body.leaf), await sessionLeaf(BigInt(issued1.body.Cf_s)));
    assert.ok(r.body.pending >= 1, '리프가 게시 대기열에 들어간다');
    const again = await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued1.body.Cf_s, sig_u, nonce: nonce.toString() });
    assert.equal(again.status, 200);
    assert.equal(again.body.inserted, false);
    const list = (await cia.adminGet(`/cia/admin/sessions?uid=${UID}`)).body.sessions;
    assert.ok(list.find((s) => s.Cf_s === issued1.body.Cf_s).revokedAt);
    assert.equal(list.find((s) => s.Cf_s === issued2.body.Cf_s).revokedAt, null);
  });

  await t('서명이 다른 세션 것이면 400, 관리자 헤더 없이 서명도 없으면 401, 모르는 Cf_s 는 404', async () => {
    const bad = await signRevokeSession(sk_u, uid, BigInt(issued2.body.Cf_s), 1n);
    assert.equal((await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued1.body.Cf_s, sig_u: bad, nonce: '1' })).status, 400);
    assert.equal((await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued2.body.Cf_s })).status, 401);
    assert.equal((await cia.adminPost('/cia/revoke', { uid: UID, scope: 'session', Cf_s: '424242' })).status, 404);
  });

  await t('scope=account·credential 은 여전히 관리자 전용(401)', async () => {
    assert.equal((await cia.post('/cia/revoke', { uid: UID, scope: 'account' })).status, 401);
    assert.equal((await cia.post('/cia/revoke', { uid: UID, scope: 'credential' })).status, 401);
  });

  await t('관리자 폐기(서명 없이) 200; 만료된 세션은 409 expired', async () => {
    const r = await cia.adminPost('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued2.body.Cf_s });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.inserted, true);
    // 만료: max_height 를 현재 head 로 발급한 세션을 하나 더 만들고 블록을 진행시킨 뒤 폐기 → 409
    const expiring = await issueWith({ max_height: BigInt(await provider.getBlockNumber()) + 1n });
    await provider.send('evm_mine', []); await provider.send('evm_mine', []);
    const e = await cia.adminPost('/cia/revoke', { uid: UID, scope: 'session', Cf_s: expiring.body.Cf_s });
    assert.equal(e.status, 409, JSON.stringify(e.body));
    assert.equal(e.body.reason, 'expired');
    const rec = (await cia.adminGet(`/cia/admin/sessions?uid=${UID}`)).body.sessions.find((s) => s.Cf_s === expiring.body.Cf_s);
    assert.equal(rec.expired, true);
    assert.equal(rec.revokedAt, null, '만료된 세션은 폐기 기록이 남지 않는다');
  });
} finally {
  await cia.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
