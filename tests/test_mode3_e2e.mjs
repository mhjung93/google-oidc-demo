// Mode 3 전 구간(V9): 등록(지갑 키) → 사용자 자격증명(π_u, 슬롯 게시) → 세션 발급 → 로그인 → 은퇴(슬롯 0) → 거절 → 재발급 → 로그인
//  → 관리자 바꿔치기 → registry_mismatch → 되돌리기. 격리 CIA + :8545 Mode3Log + 지갑 라이브러리 + RP 검증기. (chain 그룹)
//   node tests/test_mode3_e2e.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createSessionKey, buildUserCredRequest, buildIssueRequest, syncRevocationTree, syncRegistryTree, buildCredentialProof, signChallenge, ProofCache, VKEY_PATH } from '../lib/mode3_wallet.js';
import { createRpVerifier } from '../lib/mode3_rp.js';
import { randomScalar } from '../lib/mode3_credential.js';
import { createShare, combinePublicKey } from '../lib/mode3_trace.js';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
const ATTRS = [1990n, 410n, 2n, 0n, 0n, 0n];   // cia.js DEMO_ACCOUNTS.testuser
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH}`);
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = getProvider();
const cia = await startIsolatedCia();
const uid = 12345n;
try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  const { arid: aridStr } = await cia.registerRp('http://127.0.0.1:1');
  const arid = BigInt(aridStr);
  const pk_trace = await combinePublicKey((await createShare()).X, (await createShare()).X);
  const rp = createRpVerifier({ provider, logAddress: cia.logAddress, vkey, pkCIA: pk_CIA, arid, chainId: 31337n, pkTrace: pk_trace });
  const cache = new ProofCache();
  let u, session, userCred, blind_u, blind_s, cred, sessionRs;

  async function trees() {
    const rev = await syncRevocationTree(provider, cia.logAddress);
    const reg = await syncRegistryTree(provider, cia.logAddress);
    return { tree: rev.tree, revRoot: rev.root, registry: reg.tree, regRoot: reg.root };
  }
  async function loginRound() {
    const { tree, revRoot, registry, regRoot } = await trees();
    const key = ProofCache.rootKey(revRoot, regRoot);
    let cached = cache.get(key, session.wallet.address);
    if (!cached) {
      cached = await buildCredentialProof({ uid, arid, s_u: u.s_u, r_u: u.r_u, blind_u, blind_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree, registry, slot: u.slot, cm_u: u.cm_u });
      cache.set(key, session.wallet.address, cached);
    }
    return submit(cached);
  }
  const submit = async (cached) => rp.verifyLogin({ proof: cached.proof, publicSignals: cached.publicSignals, sig: await signChallenge(session.wallet, sessionRs.toString()), r_s: sessionRs });
  async function ensureUserCred() {
    if (userCred) return;
    const uc = await buildUserCredRequest({ uid, s_u: u.s_u, r_u: u.r_u, sk_u: u.sk_u, attrs: ATTRS });
    const r = await cia.post('/cia/user_cred', uc.body);
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.slot, u.slot); assert.equal(r.body.published, true);
    userCred = uc; blind_u = uc.secrets.blind_u;
  }
  async function newSessionAndIssue() {
    await ensureUserCred();
    session = createSessionKey();
    const req = await buildIssueRequest({ uid, Cf_u: userCred.Cf_u, arid, sk_u: u.sk_u, session, chainid: 31337n, max_height: BigInt(await provider.getBlockNumber()) + 300n });
    blind_s = req.secrets.blind_s; sessionRs = randomScalar();
    return cia.post('/cia/issue', req.body);
  }

  await t('등록(지갑 키): 슬롯 0, sk_u 는 지갑에만', async () => {
    u = await cia.registerUser('12345', 'password123');
    assert.equal(u.slot, 0); assert.equal(u.body.sk_u, undefined);
  });
  await t('발급 → 슬롯 게시 → 로그인 성공 (공개 입력 30, [7] = regRoot)', async () => {
    const r = await newSessionAndIssue();
    assert.equal(r.status, 200, j(r.body)); cred = r.body;
    const v = await loginRound();
    assert.equal(v.ok, true, j(v));
    const { regRoot } = await trees();
    const cached = cache.get(ProofCache.rootKey(v.root, regRoot), session.wallet.address);
    assert.equal(cached.publicSignals.length, 30); assert.equal(BigInt(cached.publicSignals[7]), regRoot); assert.equal(v.regRoot, regRoot);
  });
  let PPID1, staleProof;
  await t('같은 root 둘이면 캐시 π 재사용', async () => {
    const tr = await trees();
    const before = cache.get(ProofCache.rootKey(tr.revRoot, tr.regRoot), session.wallet.address);
    const v = await loginRound(); assert.equal(v.ok, true, j(v));
    PPID1 = v.PPID; staleProof = before;
  });
  await t('은퇴(scope=credential): 슬롯 0 게시 → 옛 π 는 stale_registry_root, 새 π 는 registry_empty; 재발급 뒤 PPID 는 그대로', async () => {
    const rv = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.retired, 1); assert.equal(rv.body.published, true);
    const v = await submit(staleProof);
    assert.equal(v.ok, false); assert.equal(v.reason, 'stale_registry_root', j(v));
    const { tree, registry } = await trees();
    await assert.rejects(() => buildCredentialProof({ uid, arid, s_u: u.s_u, r_u: u.r_u, blind_u, blind_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree, registry, slot: u.slot, cm_u: u.cm_u }), (e) => e.reason === 'registry_empty');
    userCred = null;
    const r2 = await newSessionAndIssue(); assert.equal(r2.status, 200, j(r2.body)); cred = r2.body;
    const v2 = await loginRound(); assert.equal(v2.ok, true, j(v2)); assert.equal(v2.PPID, PPID1, 'PPID 는 salt 에서 나오므로 그대로');
  });
  await t('관리자 바꿔치기: 슬롯에 가짜 리프 → 지갑은 registry_mismatch 로 증명을 만들지 않는다; 되돌리기 뒤 다시 로그인', async () => {
    assert.equal((await cia.adminPost('/cia/admin/registry/tamper', { uid: '12345' })).status, 200);
    const { tree, registry } = await trees();
    await assert.rejects(() => buildCredentialProof({ uid, arid, s_u: u.s_u, r_u: u.r_u, blind_u, blind_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree, registry, slot: u.slot, cm_u: u.cm_u }), (e) => e.reason === 'registry_mismatch');
    assert.equal((await cia.adminPost('/cia/admin/registry/restore', { uid: '12345' })).status, 200);
    const v = await loginRound(); assert.equal(v.ok, true, j(v));
  });
  await t('V6: 공개 mask ≠ 0(6슬롯) 로그인도 받는다', async () => {
    const { tree, registry } = await trees();
    const disclosure = { mask: 3n, lo: [0n, 410n, 0n, 0n, 0n, 0n], hi: [2007n, 410n, 0n, 0n, 0n, 0n] };
    const piD = await buildCredentialProof({ uid, arid, s_u: u.s_u, r_u: u.r_u, blind_u, blind_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree, registry, slot: u.slot, cm_u: u.cm_u, disclosure });
    const v = await rp.verifyLogin({ proof: piD.proof, publicSignals: piD.publicSignals, sig: await signChallenge(session.wallet, sessionRs.toString()), r_s: sessionRs });
    assert.equal(v.ok, true, j(v)); assert.equal(v.disclosure.mask, 3n); assert.deepEqual(v.disclosure.hi.map(String), ['2007', '410', '0', '0', '0', '0']);
  });
  await t('세션 폐기(폐기 트리)는 그대로: 리프 게시 뒤 옛 π 는 stale_root, 새 π 는 is a member', async () => {
    const nonce = randomScalar();
    const { signRevokeSession } = await import('../lib/mode3_wallet.js');
    const rv = await cia.post('/cia/revoke', { uid: '12345', scope: 'session', Cf_s: cred.Cf_s, sig_u: await signRevokeSession(u.sk_u, uid, BigInt(cred.Cf_s), nonce), nonce: nonce.toString() });
    assert.equal(rv.status, 200, j(rv.body));
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const { tree, registry } = await trees();
    await assert.rejects(() => buildCredentialProof({ uid, arid, s_u: u.s_u, r_u: u.r_u, blind_u, blind_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree, registry, slot: u.slot, cm_u: u.cm_u }), /is a member/);
  });
  await t('계정 폐기 → disabled 재발급 거절(403) → 복구 → 새 자격증명 → 로그인, PPID 유지', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' })).status, 200);
    userCred = null;
    // ensureUserCred 는 201 을 단언하므로 newSessionAndIssue 를 그대로 쓰면 403 응답이 아니라 그 단언에서 먼저 던진다 —
    // 여기서는 /cia/user_cred 를 직접 불러 403 을 확인한다(task-10-brief.md Step 1 바로 아래 지시).
    const uc = await buildUserCredRequest({ uid, s_u: u.s_u, r_u: u.r_u, sk_u: u.sk_u, attrs: ATTRS });
    assert.equal((await cia.post('/cia/user_cred', uc.body)).status, 403);
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: '12345', disabled: false })).status, 200);
    const r2 = await newSessionAndIssue(); assert.equal(r2.status, 200, j(r2.body)); cred = r2.body;
    const v = await loginRound(); assert.equal(v.ok, true, j(v)); assert.equal(v.PPID, PPID1);
  });
} finally { await cia.stop(); provider.destroy(); }
process.exit(failed === 0 ? 0 : 1);
