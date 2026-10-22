// Mode 3 전 구간(V11): 등록(auid) → 세션 발급(C_u·C_s·π_IdP, 한 요청) → 로그인 → 은퇴(슬롯 0) → 거절 → 재발급 → 로그인
//  → 관리자 바꿔치기 → registry_mismatch → 되돌리기. 격리 IdP + :8545 Mode3Log + 지갑 라이브러리 + RP 검증기. (chain 그룹)
//   node tests/test_mode3_e2e.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { syncRevocationTree, syncRegistryTree, signChallenge, signRevokeSession, ProofCache, VKEY_PATH } from '../lib/mode3_wallet.js';
import { LOGIN_COUNTER } from '../lib/mode3_onchain.js';
import { createRpVerifier } from '../lib/mode3_rp.js';
import { randomScalar } from '../lib/mode3_credential.js';
import { createShare, combinePublicKey } from '../lib/mode3_trace.js';
import { issueV11, proveV11, userOf, TESTUSER_ATTRS } from './helpers/mode3_flow.mjs';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH}`);
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = getProvider();
const cia = await startIsolatedCia();
try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  const { arid: aridStr } = await cia.registerRp('http://127.0.0.1:1');
  const arid = BigInt(aridStr);
  const pk_trace = await combinePublicKey((await createShare()).X, (await createShare()).X);
  const rp = createRpVerifier({ provider, logAddress: cia.logAddress, vkey, pkCIA: pk_CIA, arid, chainId: 31337n, pkTrace: pk_trace });
  const cache = new ProofCache();
  let u, session, blind_u, cred, sessionRs, sessionRrp, lastIssued;

  async function trees() {
    const rev = await syncRevocationTree(provider, cia.logAddress);
    const reg = await syncRegistryTree(provider, cia.logAddress);
    return { tree: rev.tree, revRoot: rev.root, registry: reg.tree, regRoot: reg.root };
  }
  async function loginRound() {
    const { tree, revRoot, registry, regRoot } = await trees();
    const key = ProofCache.rootKey(31337n, revRoot, regRoot);
    let cached = cache.get(key, session.wallet.address);
    if (!cached) {
      cached = await proveV11(lastIssued, { arid, pk_CIA, pk_trace, tree, registry });
      cache.set(key, session.wallet.address, cached);
    }
    return submit(cached);
  }
  const submit = async (cached) => rp.verifyLogin({ proof: cached.proof, publicSignals: cached.publicSignals, sig: await signChallenge(session.wallet, sessionRs.toString()), r_s: sessionRs, r_rp: sessionRrp });
  /** 세션 발급 한 번. blind_u 가 없으면(처음, 또는 은퇴로 null 이 된 뒤) 새 C_u 를 받는다 — 있으면 그 C_u 를 재사용한다. */
  async function newSessionAndIssue() {
    blind_u ??= randomScalar();
    const iss = await issueV11(cia, u, { arid, provider, blind_u, r_s: (sessionRs = randomScalar()), r_rp: (sessionRrp = randomScalar()) });
    session = iss.session; lastIssued = iss;
    return iss.r;
  }

  await t('등록(지갑 키): 슬롯 0, sk_u 는 지갑에만', async () => {
    const reg = await cia.registerUser('12345', 'password123');
    u = userOf(reg, '12345', TESTUSER_ATTRS);
    assert.equal(u.slot, 0); assert.equal(reg.body.sk_u, undefined);
  });
  await t('발급 → 슬롯 게시 → 로그인 성공 (공개 입력 34, [7] = regRoot, [30..32] = auid_s·arid_s·r_s)', async () => {
    const r = await newSessionAndIssue();
    assert.equal(r.status, 200, j(r.body)); cred = r.body;
    const v = await loginRound();
    assert.equal(v.ok, true, j(v));
    const { regRoot } = await trees();
    const cached = cache.get(ProofCache.rootKey(31337n, v.root, regRoot), session.wallet.address);
    assert.equal(cached.publicSignals.length, 34); assert.equal(BigInt(cached.publicSignals[7]), regRoot); assert.equal(v.regRoot, regRoot);
    assert.equal(BigInt(cached.publicSignals[30]), v.auid_s); assert.equal(BigInt(cached.publicSignals[31]), v.arid_s); assert.equal(BigInt(cached.publicSignals[32]), sessionRs);
    assert.equal(cached.publicSignals[33], LOGIN_COUNTER.toString(), '로그인은 counter=LOGIN_COUNTER');
  });
  let PPID1, staleProof;
  await t('같은 root 둘이면 캐시 π 재사용', async () => {
    const tr = await trees();
    const key = ProofCache.rootKey(31337n, tr.revRoot, tr.regRoot);
    const before = cache.get(key, session.wallet.address);
    assert.ok(before, '첫 로그인 결과가 캐시에 있어야 한다');
    const v = await loginRound(); assert.equal(v.ok, true, j(v));
    assert.equal(cache.get(key, session.wallet.address), before, '같은 root·세션이면 π 를 다시 만들지 않는다');
    PPID1 = v.PPID; staleProof = before;
  });
  await t('은퇴(scope=credential): 슬롯 0 게시 → 옛 π 는 stale_registry_root, 새 π 는 registry_empty; 재발급(새 C_u) 뒤 PPID 는 그대로', async () => {
    const rv = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.retired, 1); assert.equal(rv.body.published, true);
    const v = await submit(staleProof);
    assert.equal(v.ok, false); assert.equal(v.reason, 'stale_registry_root', j(v));
    const { tree, registry } = await trees();
    await assert.rejects(() => proveV11(lastIssued, { arid, pk_CIA, pk_trace, tree, registry }), (e) => e.reason === 'registry_empty');
    blind_u = null;   // 은퇴한 C_u 는 다시 받을 수 없다 — 새 C_u 부터
    const r2 = await newSessionAndIssue(); assert.equal(r2.status, 200, j(r2.body)); cred = r2.body;
    const v2 = await loginRound(); assert.equal(v2.ok, true, j(v2)); assert.equal(v2.PPID, PPID1, 'PPID 는 salt 에서 나오므로 그대로');
  });
  await t('관리자 바꿔치기: 슬롯에 가짜 리프 → 지갑은 registry_mismatch 로 증명을 만들지 않는다; 되돌리기 뒤 다시 로그인', async () => {
    assert.equal((await cia.adminPost('/cia/admin/registry/tamper', { uid: '12345' })).status, 200);
    const { tree, registry } = await trees();
    await assert.rejects(() => proveV11(lastIssued, { arid, pk_CIA, pk_trace, tree, registry }), (e) => e.reason === 'registry_mismatch');
    assert.equal((await cia.adminPost('/cia/admin/registry/restore', { uid: '12345' })).status, 200);
    const v = await loginRound(); assert.equal(v.ok, true, j(v));
  });
  await t('V6: 공개 mask ≠ 0(6슬롯) 로그인도 받는다', async () => {
    const { tree, registry } = await trees();
    const disclosure = { mask: 3n, lo: [0n, 410n, 0n, 0n, 0n, 0n], hi: [2007n, 410n, 0n, 0n, 0n, 0n] };
    const piD = await proveV11(lastIssued, { arid, pk_CIA, pk_trace, tree, registry, disclosure });
    const v = await rp.verifyLogin({ proof: piD.proof, publicSignals: piD.publicSignals, sig: await signChallenge(session.wallet, sessionRs.toString()), r_s: sessionRs, r_rp: sessionRrp });
    assert.equal(v.ok, true, j(v)); assert.equal(v.disclosure.mask, 3n); assert.deepEqual(v.disclosure.hi.map(String), ['2007', '410', '0', '0', '0', '0']);
  });
  await t('세션 폐기(폐기 트리)는 그대로: 리프 게시 뒤 옛 π 는 stale_root, 새 π 는 is a member', async () => {
    const nonce = randomScalar();
    const bound = 0n;
    const rv = await cia.post('/cia/revoke', { uid: '12345', scope: 'session', Cf_s: cred.Cf_s, bound: bound.toString(), sig_u: await signRevokeSession(u.sk_u, u.uid, BigInt(cred.Cf_s), bound, nonce), nonce: nonce.toString() });
    assert.equal(rv.status, 200, j(rv.body));
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const { tree, registry } = await trees();
    await assert.rejects(() => proveV11(lastIssued, { arid, pk_CIA, pk_trace, tree, registry }), /is a member/);
  });
  await t('계정 폐기 → disabled 재발급 거절(403, account_disabled) → 복구 → 새 자격증명 → 로그인, PPID 유지', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' })).status, 200);
    // /cia/issue 는 disabled 를 서명·π_IdP 확인보다 먼저 본다 — 옛(여전히 구문상 유효한) blind_u(C_u)로도 재현된다.
    const rIssue = await issueV11(cia, u, { arid, provider, blind_u });
    assert.equal(rIssue.r.status, 403, j(rIssue.r.body)); assert.equal(rIssue.r.body.reason, 'account_disabled');
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: '12345', disabled: false })).status, 200);
    blind_u = null;   // V11: 계정 폐기로 은퇴한 C_u 는 다시 받을 수 없다 — 새 C_u 부터
    const r2 = await newSessionAndIssue(); assert.equal(r2.status, 200, j(r2.body)); cred = r2.body;
    assert.notEqual(cred.slot, 0, 'V10: 계정 폐기로 슬롯 0 은 은퇴 — 복구 뒤 재발급은 새 슬롯');
    const v = await loginRound(); assert.equal(v.ok, true, j(v)); assert.equal(v.PPID, PPID1);
  });
} finally { await cia.stop(); provider.destroy(); }
process.exit(failed === 0 ? 0 : 1);
