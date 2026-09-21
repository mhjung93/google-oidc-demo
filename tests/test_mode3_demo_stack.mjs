// Mode 3 데모 스택 전 구간(HTTP): 격리 CIA + 지갑 에이전트 + RP. 스펙 §6 시연 각본 8단계 + r_s 음성. (chain 그룹)
//   node tests/test_mode3_demo_stack.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { VKEY_PATH, createRegistration, createSessionKey, buildUserCredRequest, buildIssueRequest, syncRevocationTree, buildCredentialProof, signChallenge } from '../lib/mode3_wallet.js';
import { pointToStrings } from '../lib/mode3_issuance.js';
import { getProvider } from './helpers/mode3_chain.mjs';

const j = (o) => JSON.stringify(o);
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

// vkey 는 스택을 띄우기 전에 확인한다 — 없으면 자식 프로세스를 고아로 남기지 않고 바로 죽는다.
assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);

// 만료 테스트용 짧은 TTL. 단 첫 로그인(발급+증명, 1~3초)이 TTL 안에 끝나야 하므로 너무 짧게 잡지 않는다.
const stack = await startIsolatedMode3Stack({ rpEnv: { MODE3_CHALLENGE_TTL_MS: '6000' } });
const { cia, wallet, rp } = stack;
const uid = '12345';

/** 브라우저의 RP 페이지가 하는 일을 그대로: rp_info → r_s → 지갑 login → RP login. 세션 r_s 를 돌려준다. */
async function loginViaRp(allowAgent = '0') {
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const { r_s, factoryAddress } = (await rp.post('/api/mode3/challenge')).body;
  const w = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s, allowAgent, factoryAddress }, { Origin: rp.origin });
  if (w.status !== 200) return { walletStatus: w.status, wallet: w.body, r_s };
  const r = await rp.post('/api/mode3/login', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, r_s });
  return { walletStatus: 200, wallet: w.body, rpStatus: r.status, rp: r.body, r_s, factoryAddress };
}
/** 세션 재검증: 지갑이 같은 성명으로 (root 가 바뀌었으면 새) π 를 만들어 RP 에 낸다. */
async function revalidateViaRp(r_s, { skipSync = false } = {}) {
  const w = await wallet.post('/wallet/revalidate', { r_s, skipSync }, { Origin: rp.origin });
  if (w.status !== 200) return { walletStatus: w.status, wallet: w.body };
  const r = await rp.post('/api/mode3/revalidate', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, r_s });
  return { walletStatus: 200, wallet: w.body, rpStatus: r.status, rp: r.body };
}

try {
  await t('rp_info: arid·origin·cert_s·logAddress·walletAgentOrigin·chainId, pk_CIA 는 TOFU', async () => {
    const r = await rp.get('/api/mode3/rp_info');
    assert.equal(r.status, 200);
    assert.match(r.body.arid, /^[0-9]+$/);
    assert.equal(r.body.origin, rp.origin);
    assert.ok(r.body.cert_s?.S);
    assert.equal(r.body.logAddress, cia.logAddress);
    assert.equal(r.body.walletAgentOrigin, wallet.origin);
    assert.equal(r.body.pkCiaSource, 'tofu');
    assert.equal(r.body.status, 'approved'); assert.ok(r.body.pk_trace?.x);
    assert.match(r.body.factoryAddress, /^0x[0-9a-fA-F]{40}$/); assert.match(r.body.verifierAddress, /^0x[0-9a-fA-F]{40}$/);
  });

  await t('0. 서비스 등록 승인: 관리자 목록에 approved 이고 조합 키가 있다 (헬퍼가 승인을 대행했다)', async () => {
    const list = (await cia.adminGet('/cia/rps')).body.rps;
    const mine = list.find((e) => e.origin === rp.origin);
    assert.equal(mine.status, 'approved'); assert.ok(mine.pk_trace?.x);
    assert.equal((await rp.get('/api/mode3/rp_info')).body.status, 'approved');
  });

  await t('1. 등록', async () => {
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['19', '410', '0', '0'] })).status, 201);
  });

  let PPID1, S1;
  await t('2. 로그인: 발급(issued=true) + RP ok, PPID, 세션 생성', async () => {
    const r = await loginViaRp();
    assert.equal(r.walletStatus, 200, j(r));
    assert.equal(r.wallet.issued, true);
    assert.equal(r.rpStatus, 200);
    assert.equal(r.rp.ok, true, j(r.rp));
    assert.match(r.rp.PPID, /^[0-9]+$/);
    assert.equal(r.rp.r_s, r.r_s);
    assert.equal(r.rp.allowAgent, '0');
    PPID1 = r.rp.PPID; S1 = r.r_s;
    // r_s 전문은 로그인 응답에만 낸다 — 조회 엔드포인트는 축약만(설계 §2, I1).
    const { logins } = (await rp.get('/api/mode3/logins')).body;
    const { sessions } = (await rp.get('/api/mode3/sessions')).body;
    assert.ok(logins.length > 0);
    for (const l of logins) assert.ok(l.r_s.length <= 9 && l.r_s.endsWith('…'), j(l));
    assert.ok(sessions.length > 0);
    for (const s of sessions) assert.ok(s.r_s.length <= 9 && s.r_s.endsWith('…'), j(s));
  });

  await t('3. 세션 재검증(root 같음): 캐시 π 재사용, RP ok', async () => {
    const r = await revalidateViaRp(S1);
    assert.equal(r.walletStatus, 200, j(r));
    assert.equal(r.wallet.cacheHit, true);
    assert.equal(r.rp.ok, true, j(r.rp));
  });

  await t("3'. 세션 요청: 세션키 서명이 RP 에서 검증된다", async () => {
    const w = await wallet.post('/wallet/request', { r_s: S1, body: 'hello' }, { Origin: rp.origin });
    assert.equal(w.status, 200, j(w.body));
    const r = await rp.post('/api/mode3/request', { r_s: S1, body: 'hello', sig: w.body.sig });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.ok, true);
    const bad = await rp.post('/api/mode3/request', { r_s: S1, body: 'hellp', sig: w.body.sig });
    assert.equal(bad.status, 401); assert.equal(bad.body.reason, 'bad_signature');
  });

  await t("3''. 로그인 다시: 새 세션 = 새 발급, PPID 동일", async () => {
    const r = await loginViaRp();
    assert.equal(r.wallet.issued, true);
    assert.equal(r.rp.ok, true, j(r.rp));
    assert.equal(r.rp.PPID, PPID1);
    assert.notEqual(r.r_s, S1);
  });

  let TX1;
  await t('2a. 온체인 트랜잭션: 지갑 배포 + execute ok, 두 번째는 같은 π 재사용(cacheHit)', async () => {
    const to = '0x000000000000000000000000000000000000dEaD';
    const r1 = await wallet.post('/wallet/tx', { r_s: S1, to }, { Origin: rp.origin });
    assert.equal(r1.status, 200, j(r1.body)); assert.equal(r1.body.ok, true); assert.equal(r1.body.deployed, true);
    const r2 = await wallet.post('/wallet/tx', { r_s: S1, to }, { Origin: rp.origin });
    assert.equal(r2.status, 200, j(r2.body)); assert.equal(r2.body.cacheHit, true); assert.equal(r2.body.nonce, '1');
    TX1 = r2.body.txHash;
  });

  await t('2b. 해시 기반 개봉: 서비스가 txHash 로 요청 → 승인 → uid·allowAgent(0)', async () => {
    const r = await rp.post('/api/mode3/open', { txHash: TX1 });
    assert.ok([200, 202].includes(r.status), j(r.body));   // 같은 세션(같은 c1)의 개봉이 9 보다 먼저 여기서 생긴다 → 202. 이미 있으면 200
    const id = r.body.id;
    assert.equal((await cia.adminPost(`/cia/openings/${id}/approve`)).body.status, 'approved');
    const res = await rp.get(`/api/mode3/open/${id}`);
    assert.equal(res.status, 200, j(res.body)); assert.equal(res.body.uid, uid); assert.equal(res.body.allowAgent, '0'); assert.equal(res.body.PPID, PPID1);
    assert.equal((await rp.post('/api/mode3/open', { txHash: '0x' + '11'.repeat(32) })).status, 404);
  });

  await t("session_mismatch: 다른 사용자가 같은 r_s 로 받은 성명으로 남의 세션을 재검증할 수 없다", async () => {
    // alice(uid 67890) 를 라이브러리로 등록·발급한다 — 지갑 에이전트는 한 계정만 등록하므로 서버 없이 만든다.
    // CIA 의 used_rs 는 uid 별이라 같은 r_s 로 두 번째 발급이 성공한다. RP 의 session_mismatch 가 이것을 막아야 한다.
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const mine = await loginViaRp();
    assert.equal(mine.rp.ok, true, j(mine));
    const reg = await createRegistration();
    const r = await cia.post('/cia/register', { uid: '67890', pwd: 'alicepw', cm_u: pointToStrings(reg.cm_u) });
    assert.equal(r.status, 201, j(r.body));
    // V5(2026-09-21): 사용자 자격증명(/cia/user_cred) 을 먼저 받고 그 Cf_u 위에 세션 자격증명(/cia/issue) 을 받는다
    const attrs = [0n, 0n, 0n, 0n];
    const ucReq = await buildUserCredRequest({ uid: 67890n, s_u: reg.s_u, r_u: reg.r_u, sk_u: r.body.sk_u, attrs });
    const uc = await cia.post('/cia/user_cred', ucReq.body);
    assert.equal(uc.status, 201, j(uc.body));
    const session = createSessionKey();
    const req = await buildIssueRequest({ uid: 67890n, Cf_u: ucReq.Cf_u, arid: BigInt(info.arid), sk_u: r.body.sk_u, session, chainid: BigInt(info.chainId), max_height: BigInt(await getProvider().getBlockNumber()) + 300n });
    const issued = await cia.post('/cia/issue', req.body);
    assert.equal(issued.status, 200, j(issued.body));
    const provider = getProvider();
    try {
      const { tree } = await syncRevocationTree(provider, cia.logAddress);
      const keys = (await cia.get('/cia/public_keys')).body;
      const { proof, publicSignals } = await buildCredentialProof({ uid: 67890n, arid: BigInt(info.arid), s_u: reg.s_u, blind_u: ucReq.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs, credential: issued.body, pk_CIA: { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) }, pk_trace: { x: BigInt(info.pk_trace.x), y: BigInt(info.pk_trace.y) }, tree });
      const sig = await signChallenge(session.wallet, mine.r_s);
      const rv = await rp.post('/api/mode3/revalidate', { proof, publicSignals, sig, r_s: mine.r_s });
      assert.equal(rv.status, 401, j(rv.body));
      assert.equal(rv.body.reason, 'session_mismatch');
    } finally { provider.destroy(); }
  });

  await t('같은 r_s 로 /login 을 다시 내면 bad_challenge (r_s 는 로그인 때 소비된다)', async () => {
    const w = await wallet.post('/wallet/revalidate', { r_s: S1, skipSync: true }, { Origin: rp.origin });
    const r = await rp.post('/api/mode3/login', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, r_s: S1 });
    assert.equal(r.status, 401); assert.equal(r.body.reason, 'bad_challenge');
  });

  await t('같은 r_s 로 /wallet/login 을 두 번 내면 두 번째는 409 duplicate_session (RP 에는 내지 않는다)', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const { r_s } = (await rp.post('/api/mode3/challenge')).body;
    const body = { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s };
    const first = await wallet.post('/wallet/login', body, { Origin: rp.origin });
    assert.equal(first.status, 200, j(first.body));
    const again = await wallet.post('/wallet/login', body, { Origin: rp.origin });
    assert.equal(again.status, 409); assert.equal(again.body.reason, 'duplicate_session');
  });

  await t('4. 계정 폐기 + 게시', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'account' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
  });

  await t('5. 동기화 생략 재검증 → RP stale_root; 세션 요청은 revalidate_required', async () => {
    const r = await revalidateViaRp(S1, { skipSync: true });
    assert.equal(r.walletStatus, 200, j(r));
    assert.equal(r.rp.ok, false); assert.equal(r.rp.reason, 'stale_root');
    const w = await wallet.post('/wallet/request', { r_s: S1, body: 'x' }, { Origin: rp.origin });
    const q = await rp.post('/api/mode3/request', { r_s: S1, body: 'x', sig: w.body.sig });
    assert.equal(q.status, 401); assert.equal(q.body.reason, 'revalidate_required');
  });

  await t('6. 동기화 재검증 → 지갑 403 revoked; 새 로그인 → 지갑 403 account_disabled', async () => {
    const r = await revalidateViaRp(S1);
    assert.equal(r.walletStatus, 403, j(r)); assert.equal(r.wallet.reason, 'revoked');
    const l = await loginViaRp();
    assert.equal(l.walletStatus, 403, j(l)); assert.equal(l.wallet.reason, 'account_disabled');
    // 위 재검증이 이미 S1 을 지웠다(/wallet/tx 도 revoked 를 보면 같은 규칙으로 지운다) — 그래서 여기 tx 는
    // revoked 를 다시 보지 못하고 no_session 이 된다. 순서(재검증이 먼저 revoked 를 관측)를 보존하기 위해
    // /wallet/tx 호출은 재검증 뒤로 옮겼다.
    const tx = await wallet.post('/wallet/tx', { r_s: S1, to: '0x000000000000000000000000000000000000dEaD' }, { Origin: rp.origin });
    assert.equal(tx.status, 404, j(tx.body)); assert.equal(tx.body.reason, 'no_session');
  });

  await t('7. 복구', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
  });

  await t('8. 로그인: 재발급 + RP ok, PPID 동일', async () => {
    const r = await loginViaRp();
    assert.equal(r.walletStatus, 200, j(r));
    assert.equal(r.wallet.issued, true);
    assert.equal(r.rp.ok, true, j(r.rp));
    assert.equal(r.rp.PPID, PPID1);
  });

  await t('9. 개봉: RP 가 PPID 로 요청 → 관리자 승인 → RP 가 uid 를 받는다; 같은 세션 재요청은 같은 id', async () => {
    const r = await rp.post('/api/mode3/open', { PPID: PPID1 });
    assert.equal(r.status, 202, j(r.body)); const id = r.body.id;
    assert.equal((await rp.get(`/api/mode3/open/${id}`)).status, 202);
    const pend = (await cia.adminGet('/cia/openings')).body.openings.find((o) => o.id === id);
    assert.equal(pend.status, 'pending'); assert.equal(pend.uid, null);   // CIA V4(Task 5) 는 pending 항목에 uid:null 을 명시적으로 둔다
    assert.equal((await cia.adminPost(`/cia/openings/${id}/approve`)).body.status, 'approved');
    const res = await rp.get(`/api/mode3/open/${id}`);
    assert.equal(res.status, 200, j(res.body)); assert.equal(res.body.uid, uid); assert.equal(res.body.PPID, PPID1);
    const r2 = await rp.post('/api/mode3/open', { PPID: PPID1 });   // 같은 (arid, c1) — CIA 가 같은 id 로 dedup 한다
    assert.equal(r2.status, 200); assert.equal(r2.body.id, id);
    assert.equal((await rp.post('/api/mode3/open', { PPID: '1' })).status, 404);
  });

  await t('9a. allowAgent=1 로그인 → PPID 개봉 결과에 allowAgent 1', async () => {
    const r = await loginViaRp('1');
    assert.equal(r.rp.ok, true, j(r)); assert.equal(r.rp.allowAgent, '1');
    const o = await rp.post('/api/mode3/open', { PPID: PPID1 });
    assert.equal(o.status, 202, j(o.body));
    assert.equal((await cia.adminPost(`/cia/openings/${o.body.id}/approve`)).status, 200);
    const res = await rp.get(`/api/mode3/open/${o.body.id}`);
    assert.equal(res.body.allowAgent, '1'); assert.equal(res.body.uid, uid);
  });

  await t("4'. 사용자 자기 폐기(비밀번호) → 게시 → 재검증 stale_root → 지갑 revoked → 관리자 복구 → PPID 동일", async () => {
    const before = await loginViaRp();
    assert.equal(before.rp.ok, true, j(before));
    const r = await cia.post('/cia/account/self_revoke', { uid, pwd: 'password123' });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.disabled, true);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const stale = await revalidateViaRp(before.r_s, { skipSync: true });
    assert.equal(stale.rp.ok, false); assert.equal(stale.rp.reason, 'stale_root');
    const denied = await revalidateViaRp(before.r_s);
    assert.equal(denied.walletStatus, 403, j(denied)); assert.equal(denied.wallet.reason, 'revoked');
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
    const again = await loginViaRp();
    assert.equal(again.rp.ok, true, j(again)); assert.equal(again.rp.PPID, PPID1);
  });

  await t('bad_rp_cert: cert_s 의 origin 과 다른 origin 을 주장하면 지갑이 403', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const { r_s } = (await rp.post('/api/mode3/challenge')).body;
    const w = await wallet.post('/wallet/login', { arid: info.arid, origin: 'http://evil.example', cert_s: info.cert_s, pk_trace: info.pk_trace, r_s }, { Origin: rp.origin });
    assert.equal(w.status, 403); assert.equal(w.body.reason, 'bad_rp_cert');
    const w2 = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: { ...info.cert_s, S: '1' }, pk_trace: info.pk_trace, r_s }, { Origin: rp.origin });
    assert.equal(w2.status, 403); assert.equal(w2.body.reason, 'bad_rp_cert');
  });

  await t('r_s 음성: 미발급 r_s → RP bad_challenge, 만료(TTL 6s) → bad_challenge', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const bogus = '123456789';
    const w = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: bogus }, { Origin: rp.origin });
    assert.equal(w.status, 200, j(w.body));   // 지갑은 r_s 의 출처를 모른다 — RP 가 거절한다
    const r = await rp.post('/api/mode3/login', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, r_s: bogus });
    assert.equal(r.status, 401); assert.equal(r.body.reason, 'bad_challenge');
    const { r_s } = (await rp.post('/api/mode3/challenge')).body;
    const w2 = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s }, { Origin: rp.origin });
    await new Promise((res) => setTimeout(res, 6500));
    const r2 = await rp.post('/api/mode3/login', { proof: w2.body.proof, publicSignals: w2.body.publicSignals, sig: w2.body.sig, r_s });
    assert.equal(r2.status, 401); assert.equal(r2.body.reason, 'bad_challenge');
  });

  await t('login 입력 검증: 필드 누락 → 400', async () => {
    assert.equal((await rp.post('/api/mode3/login', { proof: {} })).status, 400);
  });

  await t('페이지 서빙: 지갑 /, RP /, CIA /admin 이 text/html', async () => {
    for (const [c, p, marker] of [[wallet, '/', 'Mode 3 지갑'], [rp, '/', 'Mode 3 로그인'], [cia, '/admin', 'CIA 관리자'], [cia, '/account', 'CIA 사용자']]) {
      const r = await fetch(`${c.base}${p}`);
      assert.equal(r.status, 200, `${p}`);
      assert.match(r.headers.get('content-type') ?? '', /text\/html/);
      assert.ok((await r.text()).includes(marker), `${p} 에 "${marker}" 가 있어야 한다`);
    }
  });
} finally {
  await stack.stop();
}
process.exit(failed === 0 ? 0 : 1);
