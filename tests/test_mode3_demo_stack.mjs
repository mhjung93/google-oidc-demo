// Mode 3 데모 스택 전 구간(HTTP): 격리 CIA + 지갑 에이전트 + RP. 스펙 §6 시연 각본 8단계 + r_s 음성. (chain 그룹)
//   node tests/test_mode3_demo_stack.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { VKEY_PATH, createRegistration, createSessionKey, buildUserCredRequest, buildIssueRequest, syncRevocationTree, buildCredentialProof, signChallenge, normalizeDisclosure } from '../lib/mode3_wallet.js';
import { pointToStrings } from '../lib/mode3_issuance.js';
import { signPayload, proofToCalldata, parseExecuteReceipt, factoryAt, walletAt } from '../lib/mode3_onchain.js';
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
  const { r_s, factoryAddress, attrGateAddress } = (await rp.post('/api/mode3/challenge')).body;
  const w = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s, allowAgent, factoryAddress, attrGateAddress }, { Origin: rp.origin });
  if (w.status !== 200) return { walletStatus: w.status, wallet: w.body, r_s };
  const r = await rp.post('/api/mode3/login', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, r_s });
  return { walletStatus: 200, wallet: w.body, rpStatus: r.status, rp: r.body, r_s, factoryAddress, attrGateAddress };
}
/** 세션 재검증: 지갑이 같은 성명으로 (root 가 바뀌었으면 새) π 를 만들어 RP 에 낸다. */
async function revalidateViaRp(r_s, { skipSync = false } = {}) {
  const w = await wallet.post('/wallet/revalidate', { r_s, skipSync }, { Origin: rp.origin });
  if (w.status !== 200) return { walletStatus: w.status, wallet: w.body };
  const r = await rp.post('/api/mode3/revalidate', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, r_s });
  return { walletStatus: 200, wallet: w.body, rpStatus: r.status, rp: r.body };
}

// ---- alice(uid 67890, 2005/840/1/0) — 지갑 에이전트는 testuser 하나만 들고 있으므로(§4.1) 선택 공개 시나리오 11 은
// 라이브러리로 alice 의 등록·자격증명·세션을 직접 만들고 signPayload/walletAt 으로 execute() 를 직접 보낸다
// (Ruling 2 — /wallet/tx 를 흉내낸다. mode3_wallet_agent.js 의 같은 이름 로직과 순서를 맞춘다).
let aliceReg = null;   // { reg, sk_u, attrs(bigint[]) } — uid 67890 등록은 한 번뿐이라 캐시한다
async function ensureAlice() {
  if (aliceReg) return aliceReg;
  const reg = await createRegistration();
  const r = await cia.post('/cia/register', { uid: '67890', pwd: 'alicepw', cm_u: pointToStrings(reg.cm_u) });
  assert.equal(r.status, 201, j(r.body));
  aliceReg = { reg, sk_u: r.body.sk_u, attrs: r.body.attrs.map(BigInt) };
  return aliceReg;
}
/** alice 의 사용자 자격증명 + 세션 자격증명을 한 번 받아 execute() 를 직접 서명·제출하는 tx(to, data, disclose) 를 돌려준다. */
async function makeAliceAgent() {
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const { reg, sk_u, attrs } = await ensureAlice();
  const provider = getProvider();
  const arid = BigInt(info.arid), chainId = BigInt(info.chainId), factoryAddress = info.factoryAddress;
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  const pk_trace = { x: BigInt(info.pk_trace.x), y: BigInt(info.pk_trace.y) };
  const ucReq = await buildUserCredRequest({ uid: 67890n, s_u: reg.s_u, r_u: reg.r_u, sk_u, attrs });
  const uc = await cia.post('/cia/user_cred', ucReq.body);
  assert.ok(uc.status === 200 || uc.status === 201, j(uc.body));
  const session = createSessionKey();
  const max_height = BigInt(await provider.getBlockNumber()) + 300n;
  const issueReq = await buildIssueRequest({ uid: 67890n, Cf_u: ucReq.Cf_u, arid, sk_u, session, chainid: chainId, max_height });
  const issued = await cia.post('/cia/issue', issueReq.body);
  assert.equal(issued.status, 200, j(issued.body));
  async function tx(to, data, disclose) {
    let disclosure;
    try { disclosure = normalizeDisclosure(disclose, attrs); }
    catch (e) { if (e.reason) return { status: 400, body: { reason: e.reason, detail: e.message } }; throw e; }
    const { tree } = await syncRevocationTree(provider, cia.logAddress);
    const built = await buildCredentialProof({ uid: 67890n, arid, s_u: reg.s_u, blind_u: ucReq.secrets.blind_u, blind_s: issueReq.secrets.blind_s, pk_i: session.pk_i, attrs, credential: issued.body, pk_CIA, pk_trace, tree, disclosure });
    const PPID = BigInt(built.publicSignals[0]);
    const walletAddr = await factoryAt(factoryAddress, provider).computeAddress(PPID);
    const relayer = await provider.getSigner(0);
    if ((await provider.getCode(walletAddr)) === '0x') await (await factoryAt(factoryAddress, relayer).deploy(PPID)).wait();
    const walletC = walletAt(walletAddr, relayer);
    const nonce = await walletC.nonce();
    const payload = { to, value: 0n, data, nonce };
    const sig = signPayload(session.wallet, { chainId, wallet: walletAddr, ...payload, discMask: disclosure.mask, discLo: disclosure.lo, discHi: disclosure.hi });
    const { a, b, c, pub } = await proofToCalldata(built.proof, built.publicSignals);
    const receipt = await (await walletC.execute(payload, sig, a, b, c, pub)).wait();
    const parsed = parseExecuteReceipt(receipt, walletAddr);
    return { status: 200, body: { ok: parsed.executed?.success ?? null, onchainDisclosure: parsed.disclosure ? { mask: parsed.disclosure.mask.toString(), lo: parsed.disclosure.lo.map(String), hi: parsed.disclosure.hi.map(String) } : null } };
  }
  /** RP 챌린지 r_s 위의 로그인 성명(π+σ)만 만든다 — 온체인 실행은 하지 않는다. disclosure 는 { mask, lo, hi }(bigint). */
  async function login(rs, disclosure) {
    const { tree } = await syncRevocationTree(provider, cia.logAddress);
    const built = await buildCredentialProof({ uid: 67890n, arid, s_u: reg.s_u, blind_u: ucReq.secrets.blind_u, blind_s: issueReq.secrets.blind_s, pk_i: session.pk_i, attrs, credential: issued.body, pk_CIA, pk_trace, tree, disclosure });
    const sig = await signChallenge(session.wallet, rs.toString());
    return { proof: built.proof, publicSignals: built.publicSignals, sig };
  }
  return { tx, login, stop: () => provider.destroy() };
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
    const { reg, sk_u, attrs } = await ensureAlice();
    // V5(2026-09-21): 사용자 자격증명(/cia/user_cred) 을 먼저 받고 그 Cf_u 위에 세션 자격증명(/cia/issue) 을 받는다.
    // 속성은 AA 기록(§3.4) — 여기서 임의 값을 쓰면 bad user credential proof 로 거절되므로 alice 의 실제 속성을 쓴다.
    const ucReq = await buildUserCredRequest({ uid: 67890n, s_u: reg.s_u, r_u: reg.r_u, sk_u, attrs });
    const uc = await cia.post('/cia/user_cred', ucReq.body);
    assert.ok(uc.status === 200 || uc.status === 201, j(uc.body));
    const session = createSessionKey();
    const req = await buildIssueRequest({ uid: 67890n, Cf_u: ucReq.Cf_u, arid: BigInt(info.arid), sk_u, session, chainid: BigInt(info.chainId), max_height: BigInt(await getProvider().getBlockNumber()) + 300n });
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

  await t('10. 선택 공개: testuser 가 [0,2007]·[410,410] 을 공개해 AttrGate.claim → Claimed; 두 번째는 already claimed(success=false)', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    assert.ok(info.attrGateAddress);
    const s = await loginViaRp();
    assert.equal(s.rp.ok, true, j(s));
    // 스펙 §6.1(Ruling 9): 지갑은 로그인 때 받은 attrGateAddress 를 세션에 실어 /wallet/status 로 내준다(폼 기본값 to 로 쓰인다).
    const status = (await wallet.get('/wallet/status')).body;
    assert.equal(status.sessions[s.r_s].attrGateAddress, info.attrGateAddress);
    const disclose = [{ lo: '0', hi: '2007' }, { lo: '410', hi: '410' }, null, null];
    const tx = await wallet.post('/wallet/tx', { r_s: s.r_s, to: info.attrGateAddress, data: '0x4e71d92d', disclose }, { Origin: rp.origin });
    assert.equal(tx.status, 200, j(tx.body));
    assert.equal(tx.body.ok, true, j(tx.body));
    assert.equal(tx.body.onchainDisclosure.mask, '3');
    const again = await wallet.post('/wallet/tx', { r_s: s.r_s, to: info.attrGateAddress, data: '0x4e71d92d', disclose }, { Origin: rp.origin });
    assert.equal(again.status, 200, j(again.body));
    assert.equal(again.body.ok, false, j(again.body));   // already claimed — nonce 는 소비되지만 성공은 아니다
  });

  // Ruling 2: 지갑 에이전트는 testuser 하나만 들고 있어(§4.1) alice(우리 DEMO_ACCOUNTS) 는 라이브러리로 직접 만든다.
  await t('11. 선택 공개: alice(2005, 840) 는 country 로 실패(success=false); 슬롯 0 을 [0,1980] 으로 공개하면 지갑이 disclosure_unsatisfiable', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    assert.ok(info.attrGateAddress);
    const alice = await makeAliceAgent();
    try {
      const tx = await alice.tx(info.attrGateAddress, '0x4e71d92d', [{ lo: '0', hi: '2007' }, { lo: '840', hi: '840' }, null, null]);
      assert.equal(tx.status, 200, j(tx.body));
      assert.equal(tx.body.ok, false, j(tx.body));   // 국가 불일치(840 ≠ 410) — claim() 이 country 로 revert, Executed(success=false)
      const bad = await alice.tx(info.attrGateAddress, '0x4e71d92d', [{ lo: '0', hi: '1980' }, null, null, null]);
      assert.equal(bad.status, 400, j(bad.body));
      assert.equal(bad.body.reason, 'disclosure_unsatisfiable');   // alice 의 출생연도(2005) 가 [0,1980] 밖
    } finally { alice.stop(); }
  });

  await t('V7 로그인 술어: require.countrySet+minAge 를 만족하는 로그인은 ok·세션에 set; 술어 없이 보내면 predicate_unmet', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const year = new Date().getUTCFullYear();
    const disclose = [{ lo: '0', hi: String(year - Number(info.predicates.minAge)) }, null, null, null];
    const set = { slot: 1, members: info.predicates.allowedCountries };
    const ch = (await rp.post('/api/mode3/challenge')).body;
    const w = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, allowAgent: '0', factoryAddress: ch.factoryAddress, attrGateAddress: ch.attrGateAddress, disclose, set }, { Origin: rp.origin });
    assert.equal(w.status, 200, j(w.body));
    assert.equal(w.body.disclosure.set.sel, '2');
    const r = await rp.post('/api/mode3/login', { r_s: ch.r_s, proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, require: { countrySet: true, minAge: true } });
    assert.equal(r.body.ok, true, j(r.body));
    assert.equal(r.body.disclosure.set.root, info.predicates.allowedCountriesRoot);
    // 술어 없는 성명 + require → predicate_unmet
    const ch2 = (await rp.post('/api/mode3/challenge')).body;
    const w2 = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch2.r_s, allowAgent: '0', factoryAddress: ch2.factoryAddress, attrGateAddress: ch2.attrGateAddress }, { Origin: rp.origin });
    assert.equal(w2.status, 200, j(w2.body));
    const r2 = await rp.post('/api/mode3/login', { r_s: ch2.r_s, proof: w2.body.proof, publicSignals: w2.body.publicSignals, sig: w2.body.sig, require: { countrySet: true } });
    assert.deepEqual(r2.body, { ok: false, reason: 'predicate_unmet' });
  });

  await t('12. 선택 공개: 관리자가 testuser a₂ 를 3 으로 → 게시 → 다음 로그인이 재동기화·새 C_u, PPID 동일', async () => {
    const before = await loginViaRp();
    assert.equal(before.rp.ok, true, j(before));
    assert.equal((await cia.adminPost(`/cia/accounts/${uid}/attrs`, { attrs: ['1990', '410', '3', '0'] })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const after = await loginViaRp();
    assert.equal(after.rp.ok, true, j(after));
    assert.equal(after.rp.PPID, before.rp.PPID);
    assert.deepEqual((await wallet.get('/wallet/status')).body.attrs, ['1990', '410', '3', '0']);
  });

  // 리뷰 반영(2026-09-22): 위의 disclosure 기록은 지금까지 인프로세스 rp.verifyLogin() 이나 execute() 경로로만 봤다 —
  // 실제 RP 서버(HTTP)의 /api/mode3/login → sessions/logins/LOGIN_LOG 경로는 아무 테스트도 거치지 않았다.
  await t('13. 선택 공개(HTTP): /api/mode3/login 이 disclosure 를 세션·logins 에 기록한다; mask ≥ 16 은 bad_disclosure', async () => {
    const alice = await makeAliceAgent();
    try {
      const disclosure = { mask: 3n, lo: [0n, 840n, 0n, 0n], hi: [2007n, 840n, 0n, 0n] };   // alice[2005,840,1,0] 에 맞는 구간
      const { r_s } = (await rp.post('/api/mode3/challenge')).body;
      const good = await alice.login(r_s, disclosure);
      const login = await rp.post('/api/mode3/login', { proof: good.proof, publicSignals: good.publicSignals, sig: good.sig, r_s });
      assert.equal(login.status, 200, j(login.body));
      assert.equal(login.body.ok, true, j(login.body));
      assert.equal(login.body.disclosure.mask, '3');

      const rsShortForm = r_s.slice(0, 8) + '…';   // mode3_rp.js 의 rsShort() 와 같은 규칙
      const mine = (await rp.get('/api/mode3/sessions')).body.sessions.find((s) => s.r_s === rsShortForm);
      assert.ok(mine, '방금 로그인한 세션이 목록에 있어야 한다');
      assert.deepEqual(mine.disclosure, { mask: '3', lo: ['0', '840', '0', '0'], hi: ['2007', '840', '0', '0'] });

      const logins = (await rp.get('/api/mode3/logins')).body.logins;
      assert.equal(logins[logins.length - 1].disclosure.mask, '3');

      // mask ≥ 16 은 Groth16 검증 전에 걸리므로 증명 자체는 손대지 않고 publicSignals[14] 만 바꿔도 충분하다.
      const { r_s: r_s2 } = (await rp.post('/api/mode3/challenge')).body;
      const bad = await alice.login(r_s2, disclosure);
      const badPs = [...bad.publicSignals]; badPs[14] = '16';
      const r2 = await rp.post('/api/mode3/login', { proof: bad.proof, publicSignals: badPs, sig: bad.sig, r_s: r_s2 });
      assert.equal(r2.status, 200, j(r2.body));
      assert.equal(r2.body.ok, false);
      assert.equal(r2.body.reason, 'bad_disclosure');
    } finally { alice.stop(); }
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

  // 자기 폐기 프록시(metamask-snap §4.5, Ruling 7). snap 모드의 지갑 페이지는 cia.js 에 CORS 가 없어 :4100 을 직접 부를 수
  // 없다 — 에이전트가 중계한다. 여기서는 file 모드 스택으로 그 중계 경로만 본다(Snap 은 비밀번호를 묻는 역할일 뿐이다).
  await t("4″. 자기 폐기 프록시: 지갑 POST /wallet/self_revoke 가 CIA 로 중계한다(형식 400, 남의 uid 403, 잘못된 비밀번호 401)", async () => {
    assert.equal((await wallet.post('/wallet/self_revoke', { uid })).status, 400);
    // 이 지갑이 들고 있지 않은 계정(alice)은 CIA 에 닿기 전에 막힌다 — 임의 uid·pwd 를 던져 보는 통로가 되지 않는다.
    const other = await wallet.post('/wallet/self_revoke', { uid: '67890', pwd: 'alicepw' });
    assert.equal(other.status, 403, j(other.body)); assert.equal(other.body.reason, 'uid_mismatch');
    assert.equal((await wallet.post('/wallet/self_revoke', { uid, pwd: 'wrong-password' })).status, 401);
    const r = await wallet.post('/wallet/self_revoke', { uid, pwd: 'password123' });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.disabled, true);
    // 이 태스크의 핵심 불변식: 비밀번호는 중계만 되고 에이전트의 상태 파일·로그 어디에도 남지 않는다.
    assert.ok(!fs.readFileSync(stack.walletStateFile, 'utf8').includes('password123'), '비밀번호가 지갑 상태 파일에 남았다');
    // 양성 대조: stdout 캡처가 깨져 log() 가 늘 빈 문자열이면 위 "비밀번호가 없다" 단언이 조용히 무장해제된다.
    assert.ok(wallet.log().includes('Mode 3 wallet agent at'), '로그 캡처 양성 대조');
    assert.ok(!wallet.log().includes('password123'), '비밀번호가 지갑 로그에 남았다');
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    // 뒤 시나리오들이 로그인을 이어 가므로 복구해 둔다 — 4′ 과 같이 PPID 는 그대로여야 한다.
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
  // 블록을 상한 너머로 진행시키므로(앞 케이스들의 세션이 만료된다) 끝부분에 둔다.
  await t('Ruling 1: 세션 요청도 root 나이로 fail-closed — 게시 없이 상한을 넘기면 root_too_old, 새 게시 뒤 새 세션은 통과', async () => {
    // 나이를 스스로 0 으로 만든다(속성 변경 → 게시). 앞 케이스의 게시 시점에 기대지 않는다.
    assert.equal((await cia.adminPost(`/cia/accounts/${uid}/attrs`, { attrs: ['1991', '410', '3', '0'] })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const l = await loginViaRp();
    assert.equal(l.rp?.ok, true, j(l.rp));
    const w = await wallet.post('/wallet/request', { r_s: l.r_s, body: 'hello' }, { Origin: rp.origin });
    assert.equal(w.status, 200, j(w.body));
    const ok1 = await rp.post('/api/mode3/request', { r_s: l.r_s, body: 'hello', sig: w.body.sig });
    assert.equal(ok1.body.ok, true, j(ok1.body));
    // 게시 없이 101블록 — 팩토리 maxRootAge(100) 초과. max_height(head+300~400)는 아직 안 지났으므로 expired 가 아니다.
    const provider = getProvider();
    try { await provider.send('hardhat_mine', ['0x65']); } finally { provider.destroy(); }
    const stale = await rp.post('/api/mode3/request', { r_s: l.r_s, body: 'hello', sig: w.body.sig });
    assert.equal(stale.status, 503, j(stale.body)); assert.equal(stale.body.reason, 'root_too_old', j(stale.body));
    // 새 게시가 나이를 0 으로 되돌린다. 게시로 root 가 바뀌므로 옛 세션이 아니라 새 로그인으로 확인한다.
    assert.equal((await cia.adminPost(`/cia/accounts/${uid}/attrs`, { attrs: ['1992', '410', '3', '0'] })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const l2 = await loginViaRp();
    assert.equal(l2.rp?.ok, true, j(l2.rp));
    const w2 = await wallet.post('/wallet/request', { r_s: l2.r_s, body: 'hi' }, { Origin: rp.origin });
    const ok2 = await rp.post('/api/mode3/request', { r_s: l2.r_s, body: 'hi', sig: w2.body.sig });
    assert.equal(ok2.body.ok, true, j(ok2.body));
  });

  // 맨 끝에 둔다 — RP 를 재기동하면 메모리 세션·챌린지가 사라져 앞 케이스들이 쓰던 세션이 죽는다.
  await t('D-I2: 팩토리 배포 뒤 env 만 바꿔 RP 를 재기동하면 팩토리의 maxRootAge·maxLifetime 을 채택하고 경고한다', async () => {
    const before = (await rp.get('/api/mode3/rp_info')).body;
    assert.ok(before.factoryAddress, '이 시점엔 팩토리가 배포돼 있어야 한다');
    // env 상한을 200 으로 내려 다시 띄운다. env 를 따랐다면 지갑의 max_height(head+300~400)가 bad_expiry 로 막힌다 —
    // 온체인 immutable(400)을 채택하므로 로그인은 그대로 통과해야 한다.
    await stack.restartRp({ MODE3_MAX_LIFETIME_BLOCKS: '200', MODE3_MAX_ROOT_AGE: '7' });
    const after = (await rp.get('/api/mode3/rp_info')).body;
    assert.equal(after.factoryAddress, before.factoryAddress, '팩토리는 재배포되지 않는다');
    assert.match(rp.log(), /온체인 값을 쓴다/, 'env 와 다르면 경고가 남아야 한다');
    const l = await loginViaRp();
    assert.equal(l.rp?.ok, true, `env(200)가 아니라 팩토리(400)를 써야 통과한다: ${j(l.rp)}`);
  });
  // 이 케이스는 RP 를 활성화되지 않는 상태로 두므로 반드시 맨 마지막이다.
  await t('I-1: 팩토리 상수를 못 읽으면 env 로 되돌아가지 않고 검증기를 만들지 않는다 (503 factory_constants_unavailable, fail-closed)', async () => {
    // MODE3_RP_FACTORY_ADDRESS 에 팩토리가 아닌 주소(폐기 로그)를 주면 maxRootAge()/maxLifetime() 조회가 실패한다.
    await stack.restartRp({ MODE3_RP_FACTORY_ADDRESS: cia.logAddress }, { waitActive: false });
    const info = (await rp.get('/api/mode3/rp_info')).body;
    assert.equal(info.active, false, 'verifier 를 만들면 안 된다');
    const login = await rp.post('/api/mode3/login', {});
    assert.equal(login.status, 503); assert.equal(login.body.reason, 'factory_constants_unavailable', j(login.body));
    const req = await rp.post('/api/mode3/request', {});
    assert.equal(req.status, 503); assert.equal(req.body.reason, 'factory_constants_unavailable', j(req.body));
    assert.match(rp.log(), /검증기를 만들지 않는다\(fail-closed\)/);
  });
} finally {
  await stack.stop();
}
process.exit(failed === 0 ? 0 : 1);
