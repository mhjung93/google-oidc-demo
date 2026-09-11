// Mode 3 전 구간: 등록 → 발급 → 로그인 → 계정 폐기 → 게시 → 거절 → 복구 → 재발급 → 로그인.
// 격리 CIA + :8545 RevocationLog + 지갑 라이브러리 + RP 검증기. (chain 그룹)
//   node tests/test_mode3_e2e.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createRegistration, createSessionKey, buildIssueRequest, syncRevocationTree, buildCredentialProof, signChallenge, ProofCache, VKEY_PATH } from '../lib/mode3_wallet.js';
import { pointToStrings } from '../lib/mode3_issuance.js';
import { createRpVerifier } from '../lib/mode3_rp.js';

// verifyLogin 은 PPID·pk_i 를 BigInt 로 준다. assert 의 메시지 인자는 단언 성공 여부와
// 무관하게 먼저 평가되므로, 맨 JSON.stringify 를 쓰면 성공 경로에서도 터진다.
const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

// 게시 직후 즉시 동기화한다 — ethers v6 의 250ms 로그·헤드 캐시를 끈다.
// vkey 는 CIA 를 띄우기 전에 읽는다 — 없으면 자식 프로세스를 고아로 남기지 않고 바로 죽는다.
assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = getProvider();
const cia = await startIsolatedCia();
const uid = 12345n, arid = 22222222222222222222n;

try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  const rp = createRpVerifier({ provider, logAddress: cia.logAddress, vkey, pkCIA: pk_CIA, arid });
  const cache = new ProofCache();

  // 지갑 상태
  const reg = await createRegistration();
  let sk_u, session, blind, cred;

  /** 최신 root 로 동기화해 π 를 만들고(캐시 히트면 재사용) 새 σ 와 함께 RP 에 제출. */
  async function loginRound(label) {
    const { tree, root } = await syncRevocationTree(provider, cia.logAddress);
    let cached = cache.get(root, session.wallet.address);
    if (!cached) {
      cached = await buildCredentialProof({ uid, arid, s_u: reg.s_u, blind, pk_i: session.pk_i, credential: cred, pk_CIA, tree });
      cache.set(root, session.wallet.address, cached);
    }
    return submit(cached, label);
  }
  /** 이미 가진 π 를 그대로 제출 — root 가 바뀐 뒤의 재제출을 흉내낸다. */
  async function submit(cached, label) {
    const challenge = `${label}-${Date.now()}`;
    return rp.verifyLogin({ proof: cached.proof, publicSignals: cached.publicSignals, challenge, sig: await signChallenge(session.wallet, challenge) });
  }
  async function newSessionAndIssue() {
    session = createSessionKey();
    const req = await buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, height: BigInt(await provider.getBlockNumber()) });
    blind = req.secrets.blind;
    const r = await cia.post('/cia/issue', req.body);
    return r;
  }

  await t('등록', async () => {
    const r = await cia.post('/cia/register', { uid: uid.toString(), pwd: 'password123', cm_u: pointToStrings(reg.cm_u) });
    assert.equal(r.status, 201, j(r.body));
    sk_u = r.body.sk_u;
  });

  await t('발급 → 로그인 성공', async () => {
    const r = await newSessionAndIssue();
    assert.equal(r.status, 200, j(r.body));
    cred = r.body;
    const v = await loginRound('login1');
    assert.equal(v.ok, true, j(v));
  });

  let PPID1, staleProof;
  await t('같은 root 면 두 번째 요청은 캐시된 π 로 통과 (σ 만 새로)', async () => {
    const { root } = await syncRevocationTree(provider, cia.logAddress);
    const before = cache.get(root, session.wallet.address);
    assert.ok(before, '첫 로그인이 이 root 로 π 를 캐시해 뒀어야 한다');
    const v = await loginRound('login2');
    assert.equal(v.ok, true, j(v));
    assert.equal(cache.get(root, session.wallet.address), before, '같은 root·세션이면 π 를 다시 만들지 않는다');
    PPID1 = v.PPID;
    staleProof = before;   // 폐기 뒤 재제출용
  });

  await t('계정 폐기 + 게시 → 옛 π 는 stale_root 로 거절', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    // 지갑이 갖고 있던 옛 root 의 π 를 그대로 재제출 — 검증기가 최신 root 와 비교해 거절해야 한다
    const v = await submit(staleProof, 'after-revoke');
    assert.equal(v.ok, false);
    assert.equal(v.reason, 'stale_root');
  });

  await t('폐기된 credential 로는 새 root 에 대한 π 도 만들 수 없다', async () => {
    const { tree } = await syncRevocationTree(provider, cia.logAddress);
    await assert.rejects(() => buildCredentialProof({ uid, arid, s_u: reg.s_u, blind, pk_i: session.pk_i, credential: cred, pk_CIA, tree }), /is a member/);
  });

  await t('disabled 계정은 재발급 거절 (403)', async () => {
    assert.equal((await newSessionAndIssue()).status, 403);
  });

  await t('복구(set_disabled false) → 재발급 → 로그인, PPID 유지 (§6.6)', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    const r = await newSessionAndIssue();
    assert.equal(r.status, 200, j(r.body));
    cred = r.body;
    const v = await loginRound('after-recover');
    assert.equal(v.ok, true, j(v));
    assert.equal(v.PPID, PPID1, 'PPID = H(uid, arid, s_u) 는 폐기·복구로 바뀌지 않는다');
  });
} finally {
  await cia.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
