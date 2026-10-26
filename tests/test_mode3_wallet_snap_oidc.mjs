// snap 모드 지갑 에이전트의 OIDC 래퍼 경로(스펙 2026-10-26 Snap OIDC 래퍼 §2·§6). Snap 은 시뮬레이터, Google 은 RS256 발급자 스텁.
// 격리 IdP 는 CIA_ISSUE_AUTH=code — Google 계정은 인증 창 코드 대신 발급마다 id_token 을 낸다. hardhat :8545 필요. (chain 그룹)
//   node tests/test_mode3_wallet_snap_oidc.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { createSnapSim } from './helpers/snap_sim.mjs';
import { VKEY_PATH, eddsaPubOf } from '../lib/mode3_wallet.js';
import { aridSOf } from '../lib/mode3_credential.js';
import { uidOf, regNonce, issueNonce, isRevokeNonce } from '../lib/mode3_oidc_nonce.js';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); }
}

assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);
const stack = await startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'snap' }, ciaEnv: { CIA_ISSUE_AUTH: 'code' }, oidc: true });
const { cia, wallet, rp, oidc: stub } = stack;
const sim = createSnapSim();
const SUB = 'g-snap-1';
const UID = uidOf(stub.provider, SUB);

try {
  const stateFile = () => fs.readFileSync(stack.walletStateFile, 'utf8');
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const loginBase = async () => {
    const ch = (await rp.post('/api/mode3/challenge')).body;
    return { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, allowAgent: '0', factoryAddress: ch.factoryAddress, attrGateAddress: ch.attrGateAddress, verifiedOrigin: info.origin };
  };
  const tokens = [];   // 상태 파일에 남지 않는지 마지막에 본다
  const mint = async (o) => { const tok = await stub.mint(o); tokens.push(tok); return tok; };

  await t('config.oidc 는 IdP 의 public_keys.oidc 를 그대로 싣는다', async () => {
    const r = await wallet.get('/wallet/config');
    assert.equal(r.status, 200);
    assert.deepEqual(r.body.oidc, { enabled: true, provider: stub.provider, clientId: stub.clientId, issuer: stub.issuer });
  });

  let prep = null;
  await t('oidc/nonce: register = regNonce(pk_u(sk_u)); revoke 는 revoke:hex64; 등록 전 issue 는 409; 모르는 purpose·잘못된 sk_u 는 400', async () => {
    prep = sim.prepareRegister();
    assert.deepEqual(sim.prepareRegister(), prep, '재시도는 같은 비밀');
    const n = await wallet.post('/wallet/oidc/nonce', { purpose: 'register', sk_u: prep.sk_u });
    assert.equal(n.status, 200, j(n.body)); assert.equal(n.body.nonce, regNonce(await eddsaPubOf(prep.sk_u)));
    const rv = await wallet.post('/wallet/oidc/nonce', { purpose: 'revoke' });
    assert.equal(rv.status, 200); assert.ok(isRevokeNonce(rv.body.nonce), rv.body.nonce);
    assert.equal((await wallet.post('/wallet/oidc/nonce', { purpose: 'issue', arid: '1', r_rp: '2' })).status, 409);
    assert.equal((await wallet.post('/wallet/oidc/nonce', { purpose: 'nope' })).status, 400);
    assert.equal((await wallet.post('/wallet/oidc/nonce', { purpose: 'register', sk_u: 'zz' })).status, 400);
  });

  await t('register(id_token): uid·pwd 와 함께면 400, 못 읽는 토큰 400 bad_id_token, nonce 가 다른 토큰은 IdP 가 거절(502, cia.reason=oidc_nonce_mismatch)', async () => {
    const good = await mint({ sub: SUB, nonce: regNonce(await eddsaPubOf(prep.sk_u)) });
    assert.equal((await wallet.post('/wallet/register', { id_token: good, uid: UID, s_u: prep.s_u, sk_u: prep.sk_u })).status, 400);
    assert.equal((await wallet.post('/wallet/register', { id_token: good, pwd: 'x', s_u: prep.s_u, sk_u: prep.sk_u })).status, 400);
    const bad = await wallet.post('/wallet/register', { id_token: 'not-a-jwt', s_u: prep.s_u, sk_u: prep.sk_u });
    assert.equal(bad.status, 400); assert.equal(bad.body.reason, 'bad_id_token');
    const other = await mint({ sub: SUB, nonce: 'reg:' + '0'.repeat(64) });
    const mm = await wallet.post('/wallet/register', { id_token: other, s_u: prep.s_u, sk_u: prep.sk_u });
    assert.equal(mm.status, 502, j(mm.body)); assert.equal(mm.body.cia?.reason, 'oidc_nonce_mismatch');
    assert.equal((await wallet.get('/wallet/status')).body.registered, false, '실패한 등록은 상태를 남기지 않는다');
  });

  await t('register(id_token): 201 { uid=H(provider|sub), provider } → Snap storeRegistration(uid·provider) → status.provider', async () => {
    const tok = await mint({ sub: SUB, nonce: regNonce(await eddsaPubOf(prep.sk_u)) });
    const r = await wallet.post('/wallet/register', { id_token: tok, s_u: prep.s_u, sk_u: prep.sk_u });
    assert.equal(r.status, 201, j(r.body));
    assert.equal(r.body.uid, UID); assert.equal(r.body.provider, stub.provider);
    assert.ok(!('sk_u' in r.body) && !('s_u' in r.body));
    sim.storeRegistration({ attrs: r.body.attrs, slot: r.body.slot, auid: r.body.auid, uid: r.body.uid, provider: r.body.provider });
    assert.equal(sim.getPublicInfo().registered, true); assert.equal(sim.getPublicInfo().provider, stub.provider);
    const s = (await wallet.get('/wallet/status')).body;
    assert.equal(s.registered, true); assert.equal(s.uid, UID); assert.equal(s.provider, stub.provider);
  });

  await t('login: id_token 없으면 IdP 401 oidc_required 를 그대로; 다른 로그인(r_rp)의 nonce 토큰은 502 cia.reason=oidc_nonce_mismatch; 다른 계정 토큰은 403 uid_mismatch·못 읽는 토큰은 400; 맞는 토큰은 200', async () => {
    const w = () => sim.consentLogin({ origin: info.origin, arid: info.arid, allowAgent: '0' });
    const b0 = await loginBase();
    const no = await wallet.post('/wallet/login', { ...b0, witness: w() });
    assert.equal(no.status, 401, j(no.body)); assert.equal(no.body.reason, 'oidc_required');
    const b1 = await loginBase();
    const nOther = (await wallet.post('/wallet/oidc/nonce', { purpose: 'issue', arid: b0.arid, r_rp: b0.r_rp })).body.nonce;
    const mm = await wallet.post('/wallet/login', { ...b1, witness: w(), id_token: await mint({ sub: SUB, nonce: nOther }) });
    assert.equal(mm.status, 502, j(mm.body)); assert.equal(mm.body.cia?.reason, 'oidc_nonce_mismatch');
    if (mm.body.userCredIssued !== undefined) sim.updateUserCred(mm.body.userCredIssued);
    // 최종 리뷰 I1: 올바른 nonce 라도 다른 Google 계정의 토큰이면 account_disabled 가 아니라 403 uid_mismatch(체인 작업 전에 에이전트가 끝낸다)
    const bx = await loginBase();
    const nx = (await wallet.post('/wallet/oidc/nonce', { purpose: 'issue', arid: bx.arid, r_rp: bx.r_rp })).body.nonce;
    const wrongAcct = await wallet.post('/wallet/login', { ...bx, witness: w(), id_token: await mint({ sub: 'someone-else', nonce: nx }) });
    assert.equal(wrongAcct.status, 403, j(wrongAcct.body)); assert.equal(wrongAcct.body.reason, 'uid_mismatch');
    const unreadable = await wallet.post('/wallet/login', { ...bx, witness: w(), id_token: 'not-a-jwt' });
    assert.equal(unreadable.status, 400, j(unreadable.body)); assert.equal(unreadable.body.reason, 'bad_id_token');
    const b2 = await loginBase();
    const n = await wallet.post('/wallet/oidc/nonce', { purpose: 'issue', arid: b2.arid, r_rp: b2.r_rp });
    assert.equal(n.status, 200);
    const regPk = JSON.parse(stateFile()).registration.pk_u;
    assert.equal(n.body.nonce, issueNonce(regPk, await aridSOf({ arid: BigInt(b2.arid), r_rp: BigInt(b2.r_rp) })));
    const tok2 = await mint({ sub: SUB, nonce: n.body.nonce });
    const ok = await stack.withRelay(() => wallet.post('/wallet/login', { ...b2, witness: w(), id_token: tok2 }));
    assert.equal(ok.status, 200, j(ok.body)); assert.equal(ok.body.issued, true);
    if (ok.body.userCredIssued) sim.updateUserCred(ok.body.userCredIssued);
  });

  await t('self_revoke(id_token): 다른 계정 토큰 403 uid_mismatch, pwd 와 함께면 400, 맞는 토큰 200 → 다음 로그인 403 account_disabled', async () => {
    const nr = async () => (await wallet.post('/wallet/oidc/nonce', { purpose: 'revoke' })).body.nonce;
    const other = await wallet.post('/wallet/self_revoke', { id_token: await mint({ sub: 'someone-else', nonce: await nr() }) });
    assert.equal(other.status, 403, j(other.body)); assert.equal(other.body.reason, 'uid_mismatch');
    assert.equal((await wallet.post('/wallet/self_revoke', { id_token: await mint({ sub: SUB, nonce: await nr() }), pwd: 'x' })).status, 400);
    const ok = await wallet.post('/wallet/self_revoke', { id_token: await mint({ sub: SUB, nonce: await nr() }) });
    assert.equal(ok.status, 200, j(ok.body));
    const b = await loginBase();
    const n = (await wallet.post('/wallet/oidc/nonce', { purpose: 'issue', arid: b.arid, r_rp: b.r_rp })).body.nonce;
    const after = await wallet.post('/wallet/login', { ...b, witness: sim.consentLogin({ origin: info.origin, arid: info.arid, allowAgent: '0' }), id_token: await mint({ sub: SUB, nonce: n }) });
    assert.equal(after.status, 403, j(after.body)); assert.equal(after.body.reason, 'account_disabled');
  });

  await t('id_token 은 에이전트 상태 파일에 남지 않는다', async () => {
    const file = stateFile();
    for (const tok of tokens) assert.equal(file.includes(tok), false, '토큰이 상태 파일에 있다');
    assert.equal(file.includes('id_token'), false);
  });
} finally {
  await stack.stop();
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed === 0 ? 0 : 1);
