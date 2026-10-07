// Mode 3 데모 스택 전 구간(HTTP): 격리 CIA + 지갑 에이전트 + RP. 스펙 §6 시연 각본 8단계 + r_s 음성. (chain 그룹)
//   node tests/test_mode3_demo_stack.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { VKEY_PATH, createSessionKey, buildUserCredRequest, buildIssueRequest, syncRevocationTree, syncRegistryTree, buildCredentialProof, signChallenge, normalizeDisclosure, normalizeSet } from '../lib/mode3_wallet.js';
import { signPayload, statementDigestFields, proofToCalldata, parseExecuteReceipt, factoryAt, walletAt } from '../lib/mode3_onchain.js';
import { ethers } from 'ethers';
import { getProvider, getFunder } from './helpers/mode3_chain.mjs';
import { MODE3_LOG_ABI } from '../lib/mode3_log.js';
import { DEFAULT_ATTR_SCHEMA, encodeSlotValue } from '../lib/mode3_attr_schema.js';

const j = (o) => JSON.stringify(o);
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

// vkey 는 스택을 띄우기 전에 확인한다 — 없으면 자식 프로세스를 고아로 남기지 않고 바로 죽는다.
assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);

// 만료 테스트용 짧은 TTL. 단 첫 로그인(발급+증명, 1~3초)이 TTL 안에 끝나야 하므로 너무 짧게 잡지 않는다.
// V10(2026-10-02 Task 9): 새 자격증명 로그인은 거울이 내 리프를 실을 때까지 한 번 더 기다린다(릴레이 + 지갑 폴링 2초) —
// 6초로는 첫 로그인이 챌린지 만료(bad_challenge)에 걸려 12초로 늘렸다(만료 케이스의 대기도 같이).
const stack = await startIsolatedMode3Stack({ rpEnv: { MODE3_CHALLENGE_TTL_MS: '12000' } });
const { cia, wallet, rp } = stack;
const uid = '12345';

/** 브라우저의 RP 페이지가 하는 일을 그대로: rp_info → r_s → 지갑 login → RP login. 세션 r_s 를 돌려준다.
 *  V10(2026-10-02 Task 9): RP·지갑 모두 거울을 기준으로 한다. 격리 CIA 는 거울 릴레이 주기가 꺼져 있으므로, 지갑 로그인 동안
 *  (새 자격증명이면 거울이 내 리프를 실을 때까지 기다린다) 거울이 뒤처지면 릴레이를 대신 눌러 준다(stack.withRelay). */
async function loginViaRp(allowAgent = '0') {
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const { r_s, factoryAddress, attrGateAddress } = (await rp.post('/api/mode3/challenge')).body;
  const w = await stack.withRelay(() => wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s, allowAgent, factoryAddress, attrGateAddress }, { Origin: rp.origin }));
  if (w.status !== 200) return { walletStatus: w.status, wallet: w.body, r_s };
  const r = await rp.post('/api/mode3/login', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, r_s });
  return { walletStatus: 200, wallet: w.body, rpStatus: r.status, rp: r.body, r_s, factoryAddress, attrGateAddress };
}
/** 세션 재검증: 지갑이 같은 성명으로 (root 가 바뀌었으면 새) π 를 만들어 RP 에 낸다. */
async function revalidateViaRp(r_s, { skipSync = false } = {}) {
  await stack.relayIfBehind();   // V10: 앞선 폐기·게시를 거울(RP 가 읽는 곳)에 실어 둔다 — 기존 각본은 "게시 = 서비스가 본다" 를 전제한다
  const w = await wallet.post('/wallet/revalidate', { r_s, skipSync }, { Origin: rp.origin });
  if (w.status !== 200) return { walletStatus: w.status, wallet: w.body };
  const r = await rp.post('/api/mode3/revalidate', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, r_s });
  return { walletStatus: 200, wallet: w.body, rpStatus: r.status, rp: r.body };
}

// ---- alice(uid 67890, 2005/840/1/0) — 지갑 에이전트는 testuser 하나만 들고 있으므로(§4.1) 선택 공개 시나리오 11 은
// 라이브러리로 alice 의 등록·자격증명·세션을 직접 만들고 signPayload/walletAt 으로 execute() 를 직접 보낸다
// (Ruling 2 — /wallet/tx 를 흉내낸다. mode3_wallet_agent.js 의 같은 이름 로직과 순서를 맞춘다).
let aliceReg = null;   // { reg, sk_u, attrs(bigint[]) } — uid 67890 등록은 한 번뿐이라 캐시한다. reg 에는 slot·cm_u·r_u 도 있다(V9 §7.1 등록 헬퍼).
async function ensureAlice() {
  if (aliceReg) return aliceReg;
  const reg = await cia.registerUser('67890', 'alicepw');
  aliceReg = { reg, sk_u: reg.sk_u, attrs: reg.attrs.map(BigInt) };
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
  async function tx(to, data, disclose, set = null) {
    let disclosure;
    try { disclosure = { ...normalizeDisclosure(disclose, attrs), ...(await normalizeSet(set, attrs)) }; }
    catch (e) { if (e.reason) return { status: 400, body: { reason: e.reason, detail: e.message } }; throw e; }
    await stack.relayIfBehind();   // V10: 계정 컨트랙트는 거울을 읽는다 — 캐노니컬 최신으로 증명하므로 거울을 먼저 맞춘다
    const { tree } = await syncRevocationTree(provider, cia.logAddress);
    const { tree: registry } = await syncRegistryTree(provider, cia.logAddress);
    const built = await buildCredentialProof({ uid: 67890n, arid, s_u: reg.s_u, r_u: reg.r_u, blind_u: ucReq.secrets.blind_u, blind_s: issueReq.secrets.blind_s, pk_i: session.pk_i, attrs, credential: issued.body, pk_CIA, pk_trace, tree, registry, slot: reg.slot, cm_u: reg.cm_u, disclosure });
    const PPID = BigInt(built.publicSignals[0]);
    const walletAddr = await factoryAt(factoryAddress, provider).computeAddress(PPID);
    const relayer = await provider.getSigner(0);
    if ((await provider.getCode(walletAddr)) === '0x') await (await factoryAt(factoryAddress, relayer).deploy(PPID)).wait();
    const walletC = walletAt(walletAddr, relayer);
    const nonce = await walletC.nonce();
    const payload = { to, value: 0n, data, nonce };
    const sig = signPayload(session.wallet, { chainId, wallet: walletAddr, ...payload, discMask: disclosure.mask, discLo: disclosure.lo, discHi: disclosure.hi, setSel: disclosure.sel, setRoot: disclosure.root, ...statementDigestFields(built.publicSignals) });
    const { a, b, c, pub } = await proofToCalldata(built.proof, built.publicSignals);
    const receipt = await (await walletC.execute(payload, sig, a, b, c, pub)).wait();
    const parsed = parseExecuteReceipt(receipt, walletAddr);
    return { status: 200, body: { ok: parsed.executed?.success ?? null, onchainDisclosure: parsed.disclosure ? { mask: parsed.disclosure.mask.toString(), lo: parsed.disclosure.lo.map(String), hi: parsed.disclosure.hi.map(String), set: parsed.disclosure.setSel !== 0n ? { sel: parsed.disclosure.setSel.toString(), root: parsed.disclosure.setRoot.toString() } : null } : null } };
  }
  /** RP 챌린지 r_s 위의 로그인 성명(π+σ)만 만든다 — 온체인 실행은 하지 않는다. disclosure 는 { mask, lo, hi }(bigint). */
  async function login(rs, disclosure) {
    await stack.relayIfBehind();   // V10: RP 는 거울을 읽는다 — 위 tx 와 같은 이유
    const { tree } = await syncRevocationTree(provider, cia.logAddress);
    const { tree: registry } = await syncRegistryTree(provider, cia.logAddress);
    const built = await buildCredentialProof({ uid: 67890n, arid, s_u: reg.s_u, r_u: reg.r_u, blind_u: ucReq.secrets.blind_u, blind_s: issueReq.secrets.blind_s, pk_i: session.pk_i, attrs, credential: issued.body, pk_CIA, pk_trace, tree, registry, slot: reg.slot, cm_u: reg.cm_u, disclosure });
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
    assert.deepEqual(r.body.predicates.allowedCountries, ['410', '392', '840', '276', '250']);
    assert.deepEqual(r.body.predicates.allowedCountryNames, ['KR', 'JP', 'US', 'DE', 'FR'], '스펙 2: 기본 정책을 이름으로도 낸다');
    assert.deepEqual(r.body.predicates.attrSchema, { id: 'zkd-attrs', version: 1, hash: (await cia.get('/cia/attr_schema')).body.hash });
    assert.equal(r.body.predicates.birthYearMin, '1900', '최종 리뷰 I1: 페이지가 나이 술어의 lo 로 쓰는 스키마 min');
  });

  await t('0. 서비스 등록 승인: 관리자 목록에 approved 이고 조합 키가 있다 (헬퍼가 승인을 대행했다)', async () => {
    const list = (await cia.adminGet('/cia/rps')).body.rps;
    const mine = list.find((e) => e.origin === rp.origin);
    assert.equal(mine.status, 'approved'); assert.ok(mine.pk_trace?.x);
    assert.equal((await rp.get('/api/mode3/rp_info')).body.status, 'approved');
  });

  await t('1. 등록', async () => {
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['19', '410', '0', '0', '0', '0'] })).status, 201);
  });

  let PPID1, S1;
  await t('2. 로그인: 발급(issued=true) + RP ok, PPID, 세션 생성', async () => {
    const r = await loginViaRp();
    assert.equal(r.walletStatus, 200, j(r));
    assert.equal(r.wallet.issued, true);
    assert.equal(r.rpStatus, 200, j(r.rp));
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
      await stack.relayIfBehind();   // V10: RP 는 거울을 읽는다 — alice 의 발급 게시를 거울에 실은 뒤 캐노니컬 최신으로 증명한다
      const { tree } = await syncRevocationTree(provider, cia.logAddress);
      const { tree: registry } = await syncRegistryTree(provider, cia.logAddress);
      const keys = (await cia.get('/cia/public_keys')).body;
      const { proof, publicSignals } = await buildCredentialProof({ uid: 67890n, arid: BigInt(info.arid), s_u: reg.s_u, r_u: reg.r_u, blind_u: ucReq.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs, credential: issued.body, pk_CIA: { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) }, pk_trace: { x: BigInt(info.pk_trace.x), y: BigInt(info.pk_trace.y) }, tree, registry, slot: reg.slot, cm_u: reg.cm_u });
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
    // session_mismatch 에서 alice 의 /cia/user_cred(즉시 게시, V9)가 등록부 root 를 한 번 바꿔 놓았고, 그 뒤
    // "같은 r_s 로 /wallet/login 두 번" 로그인이 지갑의 lastSync 를 그 새 root 로 갱신해 뒀다 — 그런데 S1 의 캐시 π 는
    // 아직 더 옛 root 것이다. 아래 5 의 skipSync 전제("폐기 직전까지는 유효했다")가 성립하려면 S1 을 지금 root 로
    // 한 번 다시 증명해 캐시를 채워 둬야 한다(그래야 폐기 뒤에야 비로소 낡아진다).
    const warm = await revalidateViaRp(S1);
    assert.equal(warm.walletStatus, 200, j(warm));
    const rv = await cia.adminPost('/cia/revoke', { uid, scope: 'account' });
    assert.equal(rv.status, 200, j(rv.body));
    // V9: 계정 폐기가 활성 자격증명을 물려 슬롯을 0 으로 비우고 그 자리에서 즉시 게시한다(cia.js revokeAccount) —
    // 뒤이은 수동 게시는 더 낼 것이 없어 published:false 다.
    assert.equal(rv.body.published, true, j(rv.body));
    assert.equal((await cia.adminPost('/cia/publish')).body.published, false);
  });

  await t('5. 동기화 생략 재검증 → RP stale_registry_root; 세션 요청은 revalidate_required', async () => {
    const r = await revalidateViaRp(S1, { skipSync: true });
    assert.equal(r.walletStatus, 200, j(r));
    // V9: 계정 폐기는 등록부(슬롯)만 바꾼다 — 폐기 트리(revRoot)는 그대로라 RP 의 첫 검사(b, stale_root)는 통과하고
    // 등록부 검사(b‴)에서 걸린다(lib/mode3_rp.js).
    assert.equal(r.rp.ok, false); assert.equal(r.rp.reason, 'stale_registry_root', j(r.rp));
    // 세션 "요청"(서명만, 새 증명 없음)도 두 root 가 함께 신선해야 한다 — regRoot 만 바뀐 폐기(위 단언)도 막아야 하므로
    // mode3_rp.js 의 세션 신선도 검사는 root(revRoot)·regRoot 를 둘 다 본다(2026-10-01).
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

  await t('10. V7 술어: testuser 가 나이 ≥ minAge(올해 − 출생연도) + 국가 ∈ 허용 집합으로 AttrGate.claim → Claimed; 두 번째는 already claimed', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    assert.ok(info.attrGateAddress);
    const s = await loginViaRp();
    assert.equal(s.rp.ok, true, j(s));
    // 스펙 §6.1(Ruling 9): 지갑은 로그인 때 받은 attrGateAddress 를 세션에 실어 /wallet/status 로 내준다(폼 기본값 to 로 쓰인다).
    const status = (await wallet.get('/wallet/status')).body;
    assert.equal(status.sessions[s.r_s].attrGateAddress, info.attrGateAddress);
    const year = new Date().getUTCFullYear();
    const disclose = [{ lo: '0', hi: String(year - Number(info.predicates.minAge)) }, null, null, null];
    const set = { slot: 1, members: info.predicates.allowedCountries };
    const tx = await wallet.post('/wallet/tx', { r_s: s.r_s, to: info.attrGateAddress, data: '0x4e71d92d', disclose, set }, { Origin: rp.origin });
    assert.equal(tx.status, 200, j(tx.body));
    assert.equal(tx.body.ok, true, j(tx.body));
    assert.equal(tx.body.onchainDisclosure.mask, '1');
    assert.equal(tx.body.onchainDisclosure.set.root, info.predicates.allowedCountriesRoot);
    const again = await wallet.post('/wallet/tx', { r_s: s.r_s, to: info.attrGateAddress, data: '0x4e71d92d', disclose, set }, { Origin: rp.origin });
    assert.equal(again.status, 200, j(again.body));
    assert.equal(again.body.ok, false, j(again.body));   // already claimed — nonce 는 소비되지만 성공은 아니다
  });

  // Ruling 2: 지갑 에이전트는 testuser 하나만 들고 있어(§4.1) alice(우리 DEMO_ACCOUNTS) 는 라이브러리로 직접 만든다.
  await t('11. V7 술어: alice(2005, 840) — 임의 집합([840,392])은 root 불일치로 country revert; 허용 집합에서 840 을 빼면 disclosure_unsatisfiable; 정책보다 넓은 나이 구간([0,year-5])은 age revert', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    assert.ok(info.attrGateAddress);
    const year = new Date().getUTCFullYear();
    const alice = await makeAliceAgent();
    try {
      // 840 은 이 작은 members 안에 있어 지갑의 setPath 는 성공하지만, 그 root 는 RP 의 allowedCountriesRoot 와 다르다
      // → claim() 이 country 로 revert(Executed(success=false)). 슬롯 0(나이)도 같이 공개해야 need slot0 을 지난다.
      const rootMismatch = await alice.tx(info.attrGateAddress, '0x4e71d92d', [{ lo: '0', hi: '2007' }, null, null, null], { slot: 1, members: [840, 392] });
      assert.equal(rootMismatch.status, 200, j(rootMismatch.body));
      assert.equal(rootMismatch.body.ok, false, j(rootMismatch.body));

      // 허용 집합에서 자신의 국가(840)를 빼면 지갑이 온체인에 내기 전에 disclosure_unsatisfiable 로 막는다
      const excluded = { slot: 1, members: info.predicates.allowedCountries.filter((c) => c !== '840') };
      const unsatisfiable = await alice.tx(info.attrGateAddress, '0x4e71d92d', null, excluded);
      assert.equal(unsatisfiable.status, 400, j(unsatisfiable.body));
      assert.equal(unsatisfiable.body.reason, 'disclosure_unsatisfiable');

      // 나이: 실제 정책([0, year-19])은 2005 ≤ year-19 이므로 통과하지만, 정책보다 넓은 구간(hi=year-5)을 공개하면
      // minAge 를 증명하지 못해 claim() 이 age 로 revert 한다(국가는 실제 허용 집합이라 country 는 통과).
      const ageBad = await alice.tx(info.attrGateAddress, '0x4e71d92d', [{ lo: '0', hi: String(year - 5) }, null, null, null], { slot: 1, members: info.predicates.allowedCountries });
      assert.equal(ageBad.status, 200, j(ageBad.body));
      assert.equal(ageBad.body.ok, false, j(ageBad.body));
    } finally { alice.stop(); }
  });

  await t('V7 로그인 술어: require.countrySet+minAge 를 만족하는 로그인(lo = 스키마 min)은 ok·세션에 set; 술어 없이 보내면 predicate_unmet; lo 0 은 predicate_unmet', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const year = new Date().getUTCFullYear();
    // 최종 리뷰 I1: RP 는 lo ≥ 스키마 min 도 요구한다 — "값 없음"(0) 출생연도는 그 술어를 만들 수 없다(지갑이 lo ≤ a₀ 를 강제).
    const disclose = [{ lo: info.predicates.birthYearMin, hi: String(year - Number(info.predicates.minAge)) }, null, null, null];
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
    // lo 0 인 나이 구간([0, year − minAge])은 출생연도 0(값 없음)도 만족하므로 RP 가 거절한다(AttrGate 는 hi 만 본다 — 런북 한계).
    const ch3 = (await rp.post('/api/mode3/challenge')).body;
    const w3 = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch3.r_s, allowAgent: '0', factoryAddress: ch3.factoryAddress, attrGateAddress: ch3.attrGateAddress, disclose: [{ lo: '0', hi: String(year - Number(info.predicates.minAge)) }, null, null, null], set }, { Origin: rp.origin });
    assert.equal(w3.status, 200, j(w3.body));
    const r3 = await rp.post('/api/mode3/login', { r_s: ch3.r_s, proof: w3.body.proof, publicSignals: w3.body.publicSignals, sig: w3.body.sig, require: { countrySet: true, minAge: true } });
    assert.deepEqual(r3.body, { ok: false, reason: 'predicate_unmet' });
  });

  await t('12. 선택 공개: 관리자가 testuser a₂ 를 3 으로 → 게시 → 다음 로그인이 재동기화·새 C_u, PPID 동일', async () => {
    const before = await loginViaRp();
    assert.equal(before.rp.ok, true, j(before));
    // 스펙 2: 관리자 속성 변경은 { profile } 로 보낸다 — attrs 배열은 cia.js 가 400 use_profile 로 거부한다.
    // slot 2(extra1)는 이제 string 타입이라 인코딩이 Poseidon 해시다 — '3' 이 아니라 encodeSlotValue 로 기대값을 구한다.
    const chg = await cia.adminPost(`/cia/accounts/${uid}/attrs`, { profile: { birthYear: '1990', country: 'KR', extra1: 'tier3' } });
    assert.equal(chg.status, 200, j(chg.body));
    // V9: 속성 변경이 활성 자격증명을 물려(옛 속성이라) 슬롯을 0 으로 비우고 즉시 게시한다(cia.js /cia/accounts/:uid/attrs) —
    // 뒤이은 수동 게시는 더 낼 것이 없어 published:false 다.
    assert.equal(chg.body.published, true, j(chg.body));
    assert.equal((await cia.adminPost('/cia/publish')).body.published, false);
    const after = await loginViaRp();
    assert.equal(after.rp.ok, true, j(after));
    assert.equal(after.rp.PPID, before.rp.PPID);
    const extra1Encoded = await encodeSlotValue(DEFAULT_ATTR_SCHEMA, 2, 'tier3');
    assert.deepEqual((await wallet.get('/wallet/status')).body.attrs, ['1990', '410', extra1Encoded, '0', '0', '0']);
  });

  // 리뷰 반영(2026-09-22): 위의 disclosure 기록은 지금까지 인프로세스 rp.verifyLogin() 이나 execute() 경로로만 봤다 —
  // 실제 RP 서버(HTTP)의 /api/mode3/login → sessions/logins/LOGIN_LOG 경로는 아무 테스트도 거치지 않았다.
  await t('13. 선택 공개(HTTP): /api/mode3/login 이 disclosure 를 세션·logins 에 기록한다; mask ≥ 64 는 bad_disclosure', async () => {
    const alice = await makeAliceAgent();
    try {
      const disclosure = { mask: 3n, lo: [0n, 840n, 0n, 0n, 0n, 0n], hi: [2007n, 840n, 0n, 0n, 0n, 0n] };   // alice[2005,840,1,0,0,0] 에 맞는 구간(V9 6슬롯)
      const { r_s } = (await rp.post('/api/mode3/challenge')).body;
      const good = await alice.login(r_s, disclosure);
      const login = await rp.post('/api/mode3/login', { proof: good.proof, publicSignals: good.publicSignals, sig: good.sig, r_s });
      assert.equal(login.status, 200, j(login.body));
      assert.equal(login.body.ok, true, j(login.body));
      assert.equal(login.body.disclosure.mask, '3');

      const rsShortForm = r_s.slice(0, 8) + '…';   // mode3_rp.js 의 rsShort() 와 같은 규칙
      const mine = (await rp.get('/api/mode3/sessions')).body.sessions.find((s) => s.r_s === rsShortForm);
      assert.ok(mine, '방금 로그인한 세션이 목록에 있어야 한다');
      assert.deepEqual(mine.disclosure, { mask: '3', lo: ['0', '840', '0', '0', '0', '0'], hi: ['2007', '840', '0', '0', '0', '0'], set: null });

      const logins = (await rp.get('/api/mode3/logins')).body.logins;
      assert.equal(logins[logins.length - 1].disclosure.mask, '3');

      // mask ≥ 64(V9 6슬롯, PUB_INDEX.DISC_MASK=15) 는 Groth16 검증 전에 걸리므로 증명 자체는 손대지 않고
      // publicSignals[15] 만 바꿔도 충분하다(lib/mode3_onchain.js 의 PUB_INDEX, lib/mode3_rp.js 의 공개 입력 30개 분해와 같은 색인).
      const { r_s: r_s2 } = (await rp.post('/api/mode3/challenge')).body;
      const bad = await alice.login(r_s2, disclosure);
      const badPs = [...bad.publicSignals]; badPs[15] = '64';
      const r2 = await rp.post('/api/mode3/login', { proof: bad.proof, publicSignals: badPs, sig: bad.sig, r_s: r_s2 });
      assert.equal(r2.status, 200, j(r2.body));
      assert.equal(r2.body.ok, false);
      assert.equal(r2.body.reason, 'bad_disclosure');
    } finally { alice.stop(); }
  });

  // C-4(2026-09-25 리뷰): 재검증은 세션을 **마지막 증명에 다시 묶어야** 한다. root·disclosure 만 갱신하면
  // allowAgent=1 로 로그인한 세션이 allowAgent=0 인 성명으로 재검증돼도 조회 API·화면은 1 을 계속 싣는다 —
  // 세션 상태가 실제로 보증된 것보다 넓어진다. max_height(만료)도 같다.
  await t('C-4: 재검증이 세션의 allowAgent·max_height 를 마지막 증명의 값으로 다시 묶는다', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const { reg, sk_u, attrs } = await ensureAlice();
    const provider = getProvider();
    try {
      const arid = BigInt(info.arid), chainId = BigInt(info.chainId);
      const keys = (await cia.get('/cia/public_keys')).body;
      const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
      const pk_trace = { x: BigInt(info.pk_trace.x), y: BigInt(info.pk_trace.y) };
      const ucReq = await buildUserCredRequest({ uid: 67890n, s_u: reg.s_u, r_u: reg.r_u, sk_u, attrs });
      const uc = await cia.post('/cia/user_cred', ucReq.body);
      assert.ok(uc.status === 200 || uc.status === 201, j(uc.body));
      // 같은 세션 키(pk_i) 위에 allowAgent·만료가 다른 자격증명을 둘 발급한다 — PPID·pk_i 가 같아야 재검증이 그 세션에 붙는다.
      const session = createSessionKey();
      const issue = async (allowAgent, ttl) => {
        const max_height = BigInt(await provider.getBlockNumber()) + ttl;
        const req = await buildIssueRequest({ uid: 67890n, Cf_u: ucReq.Cf_u, arid, sk_u, session, chainid: chainId, allowAgent, max_height });
        const r = await cia.post('/cia/issue', req.body);
        assert.equal(r.status, 200, j(r.body));
        return { cred: r.body, blind_s: req.secrets.blind_s, max_height };
      };
      const prove = async (c, rs) => {
        await stack.relayIfBehind();   // V10: RP 는 거울을 읽는다 — alice 의 발급 게시를 거울에 실은 뒤 캐노니컬 최신으로 증명한다
        const { tree } = await syncRevocationTree(provider, cia.logAddress);
        const { tree: registry } = await syncRegistryTree(provider, cia.logAddress);
        const built = await buildCredentialProof({ uid: 67890n, arid, s_u: reg.s_u, r_u: reg.r_u, blind_u: ucReq.secrets.blind_u, blind_s: c.blind_s, pk_i: session.pk_i, attrs, credential: c.cred, pk_CIA, pk_trace, tree, registry, slot: reg.slot, cm_u: reg.cm_u });
        return { proof: built.proof, publicSignals: built.publicSignals, sig: await signChallenge(session.wallet, rs.toString()), r_s: rs };
      };
      const agentCred = await issue(1n, 300n);
      const plainCred = await issue(0n, 200n);

      const { r_s } = (await rp.post('/api/mode3/challenge')).body;
      const login = await rp.post('/api/mode3/login', await prove(agentCred, r_s));
      assert.equal(login.body.ok, true, j(login.body));
      assert.equal(login.body.allowAgent, '1');
      const shortRs = r_s.slice(0, 8) + '…';   // mode3_rp.js 의 rsShort() 와 같은 규칙
      const sessionOf = async () => (await rp.get('/api/mode3/sessions')).body.sessions.find((s) => s.r_s === shortRs);
      const first = await sessionOf();
      assert.ok(first, '방금 로그인한 세션이 목록에 있어야 한다');
      assert.equal(first.allowAgent, '1'); assert.equal(first.max_height, agentCred.max_height.toString());

      const rv = await rp.post('/api/mode3/revalidate', await prove(plainCred, r_s));
      assert.equal(rv.body.ok, true, j(rv.body));
      const after = await sessionOf();
      assert.equal(after.allowAgent, '0', '재검증한 성명이 대리 실행을 허용하지 않으면 세션도 허용하지 않아야 한다');
      assert.equal(after.max_height, plainCred.max_height.toString(), '만료도 마지막 증명의 값이어야 한다');
    } finally { provider.destroy(); }
  });

  await t("4'. 사용자 자기 폐기(비밀번호) → 게시 → 재검증 stale_registry_root → 지갑 revoked → 관리자 복구 → PPID 동일", async () => {
    const before = await loginViaRp();
    assert.equal(before.rp.ok, true, j(before));
    const r = await cia.post('/cia/account/self_revoke', { uid, pwd: 'password123' });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.disabled, true);
    // V9: 자기 폐기도 revokeAccount 를 그대로 타 슬롯을 0 으로 비우고 즉시 게시한다 — 수동 게시는 더 낼 것이 없다.
    assert.equal(r.body.published, true, j(r.body));
    assert.equal((await cia.adminPost('/cia/publish')).body.published, false);
    const stale = await revalidateViaRp(before.r_s, { skipSync: true });
    // V9: 자기 폐기도 등록부(슬롯)만 바꾼다 — revRoot 는 그대로라 stale_root 가 아니라 stale_registry_root 다(위 5 와 같은 이유).
    assert.equal(stale.rp.ok, false); assert.equal(stale.rp.reason, 'stale_registry_root', j(stale.rp));
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
    // V9: 이 프록시도 CIA 의 revokeAccount 결과를 그대로 중계한다 — 즉시 게시됐으니 수동 게시는 더 낼 것이 없다.
    assert.equal(r.body.published, true, j(r.body));
    assert.equal((await cia.adminPost('/cia/publish')).body.published, false);
    // 뒤 시나리오들이 로그인을 이어 가므로 복구해 둔다 — 4′ 과 같이 PPID 는 그대로여야 한다.
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
    const again = await loginViaRp();
    assert.equal(again.rp.ok, true, j(again)); assert.equal(again.rp.PPID, PPID1);
  });

  // V8 세션 폐기(설계 2026-09-24). 계정이 살아 있고(바로 위 4″ 가 복구해 뒀다) 블록을 크게 진행시키는 케이스
  // (맨 끝의 Ruling 1)보다 앞인 이 자리에 둔다 — 앞 케이스들의 세션이 만료되면 폐기가 409 expired 로 막힌다.
  await t('V8 세션 폐기: 세션 둘 → 하나만 폐기(지갑 버튼 경로) → 게시 → 그 세션은 더 못 쓰고 다른 세션·재로그인은 정상; 관리자 폐기는 revoked_session', async () => {
    const s1 = await loginViaRp();
    // s2 의 Cf_s 를 뒤에서 직접 집으려고 로그인 직전 기록을 찍어 둔다 — 목록 순서·만료 정리에 기대지 않는다(최종 리뷰 F6).
    const before = new Set((await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.map((x) => x.Cf_s));
    const s2 = await loginViaRp();
    const cf2 = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.map((x) => x.Cf_s).find((c) => !before.has(c));
    assert.ok(cf2, 's2 의 세션 기록이 있어야 한다');
    assert.equal(s1.rp?.ok, true, j(s1)); assert.equal(s2.rp?.ok, true, j(s2));
    // 양성 대조: 폐기 전에는 s1 의 세션 요청이 통과한다(같은 서명을 폐기 뒤에 다시 써서 대조한다).
    const w1 = await wallet.post('/wallet/request', { r_s: s1.r_s, body: 'x' }, { Origin: rp.origin });
    assert.equal(w1.status, 200, j(w1.body));
    assert.equal((await rp.post('/api/mode3/request', { r_s: s1.r_s, body: 'x', sig: w1.body.sig })).body.ok, true);

    const rev = await wallet.post('/wallet/session/revoke', { r_s: s1.r_s });
    assert.equal(rev.status, 200, j(rev.body));
    assert.equal(rev.body.revoked, true); assert.equal(rev.body.inserted, true);
    // AA 가 받아들인 순간 지갑은 그 세션을 버린다 — 게시 전이라도 두 번째 요청은 404 no_session 이다.
    assert.equal((await wallet.post('/wallet/session/revoke', { r_s: s1.r_s })).status, 404);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    await stack.relay();   // V10: 서비스는 거울을 읽는다 — 게시가 거울에 실려야 옛 서명이 revalidate_required 가 된다

    // s1: 서비스 관점 — 게시로 root 가 바뀌어 옛 서명은 revalidate_required 이고, 재검증할 지갑 세션은 이미 없다.
    const q1 = await rp.post('/api/mode3/request', { r_s: s1.r_s, body: 'x', sig: w1.body.sig });
    assert.notEqual(q1.body.ok, true, j(q1.body));
    assert.equal(q1.body.reason, 'revalidate_required', j(q1.body));
    const rv1 = await wallet.post('/wallet/revalidate', { r_s: s1.r_s }, { Origin: rp.origin });
    assert.equal(rv1.status, 404, j(rv1.body)); assert.equal(rv1.body.reason, 'no_session');

    // s2 는 그대로 산다 — 사용자 자격증명은 폐기되지 않았다.
    const rv2 = await revalidateViaRp(s2.r_s);
    assert.equal(rv2.walletStatus, 200, j(rv2));
    assert.equal(rv2.rp.ok, true, j(rv2.rp));

    // 관리자 경로: 지갑 밖에서 s2 를 폐기하면 지갑은 그 세션만 403 revoked_session 으로 버린다.
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'session', Cf_s: cf2 })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const rv2b = await revalidateViaRp(s2.r_s);
    assert.equal(rv2b.walletStatus, 403, j(rv2b)); assert.equal(rv2b.wallet.reason, 'revoked_session');

    // 계정은 살아 있다 — 새 로그인은 같은 PPID 로 정상이다(계정 폐기(4·6)와 달리 account_disabled 가 아니다).
    const s3 = await loginViaRp();
    assert.equal(s3.rp?.ok, true, j(s3)); assert.equal(s3.rp.PPID, PPID1);
  });

  await t('각본 10(V9): 관리자 바꿔치기 → 지갑 로그인 403 registry_mismatch → 되돌리기 → 로그인 ok', async () => {
    assert.equal((await cia.adminPost('/cia/admin/registry/tamper', { uid })).status, 200);
    const bad = await loginViaRp();
    assert.equal(bad.walletStatus, 403, j(bad.wallet)); assert.equal(bad.wallet.reason, 'registry_mismatch');
    assert.equal((await cia.adminPost('/cia/admin/registry/restore', { uid })).status, 200);
    const ok = await loginViaRp();
    assert.equal(ok.walletStatus, 200, j(ok.wallet)); assert.equal(ok.rp.ok, true, j(ok.rp));
    assert.equal(ok.rp.PPID, PPID1);
  });

  // 시연 카드(설계 §8.3, mode3/wallet.html): 전문가 보기에서 다음 발급·증명의 s_u·uid 를 한 번만 덮어써 오류 경로를 보여준다.
  await t('각본 11(V9): 시연 카드 — salt·uid 덮어쓰기(발급) → user_cred_failed(bad user credential proof), 다음 증명 덮어쓰기 → demo_proof_failed', async () => {
    // 발급 덮어쓰기(scope='issue')를 보려면 먼저 활성 자격증명을 물려야(슬롯 0) ensureUserCred 가 새로 받는 경로를 탄다.
    const rv = await cia.adminPost('/cia/revoke', { uid, scope: 'credential' });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.retired, 1, j(rv.body));

    // salt(s_u) 바꾸기 — 다시 받는 C_u 가 등록 커밋(cm_u)과 어긋나 CIA 가 bad user credential proof 로 거절한다.
    assert.equal((await wallet.post('/wallet/demo/override', { scope: 'issue', s_u: '999999999999999999' })).body.ok, true);
    const badSalt = await loginViaRp();
    assert.equal(badSalt.walletStatus, 502, j(badSalt.wallet));
    assert.equal(badSalt.wallet.reason, 'user_cred_failed', j(badSalt.wallet));
    assert.equal(badSalt.wallet.cia?.error, 'bad user credential proof', j(badSalt.wallet));
    assert.equal(badSalt.wallet.demo, 'override:issue');

    // uid 바꾸기 — 요청 본문의 uid 는 진짜로 되돌려 보내지만(스펙 §8.3) C_u 안의 uid 만 바뀌어 같은 사유로 거절된다.
    assert.equal((await wallet.post('/wallet/demo/override', { scope: 'issue', uid: '99999' })).body.ok, true);
    const badUid = await loginViaRp();
    assert.equal(badUid.walletStatus, 502, j(badUid.wallet));
    assert.equal(badUid.wallet.reason, 'user_cred_failed', j(badUid.wallet));
    assert.equal(badUid.wallet.cia?.error, 'bad user credential proof', j(badUid.wallet));
    assert.equal(badUid.wallet.demo, 'override:issue');

    // 덮어쓰기 없이 다시 로그인하면 진짜 비밀로 새 사용자 자격증명을 받아 복구된다 — PPID 는 그대로.
    const recovered = await loginViaRp();
    assert.equal(recovered.walletStatus, 200, j(recovered.wallet));
    assert.equal(recovered.rp.ok, true, j(recovered.rp));
    assert.equal(recovered.rp.PPID, PPID1);

    // 증명 덮어쓰기(scope='prove')는 다음 로그인(= 새 세션이라 캐시가 비어 반드시 새로 증명한다)에서 걸려
    // 등록부 포함 증명(V9 조건 9)이 안 만들어진다 — 발급 단계와 구분된 사유(409 demo_proof_failed)로 보인다.
    assert.equal((await wallet.post('/wallet/demo/override', { scope: 'prove', s_u: '999999999999999999' })).body.ok, true);
    const badProve = await loginViaRp();
    assert.equal(badProve.walletStatus, 409, j(badProve.wallet));
    assert.equal(badProve.wallet.reason, 'demo_proof_failed', j(badProve.wallet));
    assert.equal(badProve.wallet.demo, 'override:prove');

    // 덮어쓰기는 한 번 쓰면 사라진다 — 다시 로그인하면 정상이고, /wallet/status 의 demoOverride 도 비어 있다.
    const after = await loginViaRp();
    assert.equal(after.walletStatus, 200, j(after.wallet));
    assert.equal(after.rp.ok, true, j(after.rp));
    assert.equal(after.rp.PPID, PPID1);
    assert.equal((await wallet.get('/wallet/status')).body.demoOverride, null);
  });

  // V10(2026-10-02 §4.5): 계정 폐기는 슬롯을 영구 은퇴시키고, 관리자가 되살린 뒤의 재발급은 새 슬롯을 받는다 — 앞의 4·4'
  // (계정 폐기·자기 폐기 → 복구)를 지난 testuser 는 더 이상 슬롯 0 이 아니다. 슬롯이 서로 다르고, 지갑이 CIA 가 준 새 슬롯을
  // 따랐는지(결정 3)를 본다.
  await t('각본 12(V9): 두 사용자의 슬롯은 다르고 각자 PPID 로 로그인된다(V10: testuser 는 복구 재발급으로 새 슬롯, 지갑이 따른다)', async () => {
    const accts = (await cia.adminGet('/cia/accounts')).body.accounts;
    const slotOf = (u) => accts.find((a) => a.uid === u).slot;
    assert.equal(slotOf('67890'), 1);
    assert.notEqual(slotOf('12345'), slotOf('67890'));
    assert.notEqual(slotOf('12345'), 0, '계정 폐기로 은퇴한 슬롯 0 은 다시 쓰지 않는다');
    assert.equal((await wallet.get('/wallet/status')).body.slot, slotOf('12345'), '지갑이 재발급 응답의 새 슬롯을 따랐다');
    const t1 = await loginViaRp();
    assert.equal(t1.rp?.ok, true, j(t1)); assert.equal(t1.rp.PPID, PPID1);
    const alice = await makeAliceAgent();
    try {
      const { r_s } = (await rp.post('/api/mode3/challenge')).body;
      const al = await alice.login(r_s);
      const r = await rp.post('/api/mode3/login', { proof: al.proof, publicSignals: al.publicSignals, sig: al.sig, r_s });
      assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.ok, true, j(r.body));
      assert.notEqual(r.body.PPID, t1.rp.PPID, 'alice 의 PPID 는 testuser 와 달라야 한다');
    } finally { alice.stop(); }
  });

  // V10(2026-10-02 설계 §5) 거울 지연: 서비스(RP)·계정 컨트랙트는 거울만 읽는다. 캐노니컬에 폐기가 게시돼도 릴레이 전에는
  // 거울 기준으로 옛 π 가 그대로 통한다(지연 창 = 릴레이 주기). 릴레이가 거울을 올리는 순간 옛 서명은 revalidate_required 가
  // 되고, 살아 있는 세션은 새 π 로 재검증되며, 폐기된 세션은 지갑이 revoked_session 으로 버린다.
  // 주의: revalidateViaRp 는 거울을 먼저 맞추므로(relayIfBehind) 지연 창 안에서는 쓰지 않고 지갑·RP 를 직접 부른다.
  await t('각본 13(V10): 거울 지연 — 세션 폐기 게시 후 릴레이 전엔 캐시 π 로 재승인 ok, POST /cia/admin/relay 뒤엔 revalidate_required → 새 π, 폐기된 세션은 revoked_session', async () => {
    const sA = await loginViaRp();
    const before = new Set((await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.map((x) => x.Cf_s));
    const sB = await loginViaRp();
    const cfB = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.map((x) => x.Cf_s).find((c) => !before.has(c));
    assert.equal(sA.rp?.ok, true, j(sA)); assert.equal(sB.rp?.ok, true, j(sB)); assert.ok(cfB, 'sB 의 세션 기록이 있어야 한다');
    await stack.relayIfBehind();
    const w1 = await wallet.post('/wallet/request', { r_s: sA.r_s, body: 'lag' }, { Origin: rp.origin });
    assert.equal(w1.status, 200, j(w1.body));
    assert.equal((await rp.post('/api/mode3/request', { r_s: sA.r_s, body: 'lag', sig: w1.body.sig })).body.ok, true);

    const mirrorEpoch0 = await cia.mirrorContract.epoch();
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'session', Cf_s: cfB })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const health = (await cia.get('/mode3/health')).body;
    assert.ok(health.mirrors[0].behind > 0, `캐노니컬은 올랐고 거울은 그대로여야 한다: ${j(health.mirrors)}`);
    assert.equal(await cia.mirrorContract.epoch(), mirrorEpoch0, '릴레이 전 거울 epoch 는 그대로');

    // 지연 창: 지갑은 거울 뷰로 증명하므로 캐시 π 를 그대로 내고, RP(거울 기준)는 받아들인다. 옛 세션 서명도 아직 통한다.
    const lagW = await wallet.post('/wallet/revalidate', { r_s: sA.r_s }, { Origin: rp.origin });
    assert.equal(lagW.status, 200, j(lagW.body)); assert.equal(lagW.body.cacheHit, true, j(lagW.body));
    const lagR = await rp.post('/api/mode3/revalidate', { proof: lagW.body.proof, publicSignals: lagW.body.publicSignals, sig: lagW.body.sig, r_s: sA.r_s });
    assert.equal(lagR.body.ok, true, j(lagR.body));
    assert.equal((await rp.post('/api/mode3/request', { r_s: sA.r_s, body: 'lag', sig: w1.body.sig })).body.ok, true, '릴레이 전에는 서비스가 폐기를 아직 모른다');

    // 릴레이 — 거울이 캐노니컬을 따라잡는다. RP 세션의 root 와 거울 root 가 달라져 옛 서명은 revalidate_required.
    const rl = await stack.relay();
    assert.equal(rl.mirrors[0].epoch, (await cia.mirrorContract.epoch()).toString()); assert.ok(await cia.mirrorContract.epoch() > mirrorEpoch0);
    assert.equal((await cia.get('/mode3/health')).body.mirrors[0].behind, 0);
    const q = await rp.post('/api/mode3/request', { r_s: sA.r_s, body: 'lag', sig: w1.body.sig });
    assert.equal(q.status, 401, j(q.body)); assert.equal(q.body.reason, 'revalidate_required', j(q.body));
    // 살아 있는 세션은 새 거울 root 로 새 π 를 만든다.
    const fresh = await revalidateViaRp(sA.r_s);
    assert.equal(fresh.walletStatus, 200, j(fresh)); assert.equal(fresh.wallet.cacheHit, false, j(fresh.wallet));
    assert.equal(fresh.rp.ok, true, j(fresh.rp));
    // 폐기된 세션은 지갑이 버린다.
    const dead = await revalidateViaRp(sB.r_s);
    assert.equal(dead.walletStatus, 403, j(dead)); assert.equal(dead.wallet.reason, 'revoked_session');
  });

  // V10(2026-10-02 설계 §4) 접수증 강제: 계정 폐기 응답의 receipt 는 "이 슬롯은 비어 있어야 한다" 는 IdP 서명이다. 사용자가
  // 그것을 캐노니컬 로그의 requestRevocation 으로 올리면, 다음 게시는 그 슬롯을 0 으로 실어야만 통과하고 슬롯은 영구 은퇴한다.
  // 관리자가 계정을 되살리면 재발급은 새 슬롯을 받고 지갑이 따른다(각본 12 와 같은 규칙).
  // 이 각본은 접수증 → 대기열 → 게시의 흐름을 보일 뿐 컨트랙트의 강제 자체는 아니다(정직한 CIA 는 어차피 슬롯을 0 으로 싣는다) —
  // 0 으로 싣지 않은 게시의 거절(PendingRevocationNotApplied)은 test/Mode3Log.test.mjs 가 본다.
  await t('각본 14(V10): 접수증 강제 — 자기 폐기 receipt 를 requestRevocation 으로 올림 → /cia/publish 가 (slot,0) 을 실어 통과·isRetired → 복구 재발급은 새 슬롯', async () => {
    const pre = await loginViaRp();
    assert.equal(pre.rp?.ok, true, j(pre));
    const r = await cia.post('/cia/account/self_revoke', { uid, pwd: 'password123' });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.disabled, true);
    const rc = r.body.receipt;
    assert.ok(rc && rc.sig, `계정 폐기 응답에 receipt 가 있어야 한다: ${j(r.body)}`);
    assert.equal(rc.canonicalLogAddress.toLowerCase(), cia.logAddress.toLowerCase()); assert.equal(rc.canonicalChainId, '31337');
    const s0 = Number(rc.slot);
    const provider = getProvider();
    try {
      const log = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, await getFunder(provider));
      assert.equal(await log.isRetired(s0), false, '전제: 아직 은퇴하지 않았다');
      await (await log.requestRevocation(s0, rc.epochAtRequest, rc.requestedAt, rc.sig)).wait();
      assert.deepEqual((await log.pendingSlots()).map(Number), [s0]);
      const pub = await cia.adminPost('/cia/publish', {});
      assert.equal(pub.status, 200, j(pub.body)); assert.equal(pub.body.published, true, j(pub.body));
      assert.deepEqual((await log.pendingSlots()).map(Number), [], '게시가 대기열을 비웠다');
      assert.equal(await log.isRetired(s0), true, '슬롯이 영구 은퇴했다');
    } finally { provider.destroy(); }
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
    const again = await loginViaRp();
    assert.equal(again.rp?.ok, true, j(again)); assert.equal(again.rp.PPID, PPID1);
    const slotNow = (await wallet.get('/wallet/status')).body.slot;
    assert.notEqual(Number(slotNow), s0, '지갑은 재발급이 준 새 슬롯을 따른다');
    assert.equal((await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === uid).slot, slotNow);
  });

  await t('bad_rp_cert: cert_s 의 origin 과 다른 origin 을 주장하면 지갑이 403', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const { r_s } = (await rp.post('/api/mode3/challenge')).body;
    const w = await wallet.post('/wallet/login', { arid: info.arid, origin: 'http://evil.example', cert_s: info.cert_s, pk_trace: info.pk_trace, r_s }, { Origin: rp.origin });
    assert.equal(w.status, 403); assert.equal(w.body.reason, 'bad_rp_cert');
    const w2 = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: { ...info.cert_s, S: '1' }, pk_trace: info.pk_trace, r_s }, { Origin: rp.origin });
    assert.equal(w2.status, 403); assert.equal(w2.body.reason, 'bad_rp_cert');
  });

  await t('r_s 음성: 미발급 r_s → RP bad_challenge, 만료(TTL 12s) → bad_challenge', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const bogus = '123456789';
    const w = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: bogus }, { Origin: rp.origin });
    assert.equal(w.status, 200, j(w.body));   // 지갑은 r_s 의 출처를 모른다 — RP 가 거절한다
    const r = await rp.post('/api/mode3/login', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, r_s: bogus });
    assert.equal(r.status, 401); assert.equal(r.body.reason, 'bad_challenge');
    const { r_s } = (await rp.post('/api/mode3/challenge')).body;
    const w2 = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s }, { Origin: rp.origin });
    await new Promise((res) => setTimeout(res, 12500));
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
    // 스펙 2: { profile } 로 보낸다 — 여기서는 속성 변경이 자격증명을 물리는 트리거일 뿐 attrs 값 자체는 뒤에서 보지 않는다.
    const a1 = await cia.adminPost(`/cia/accounts/${uid}/attrs`, { profile: { birthYear: '1991', country: 'KR', extra1: 'tier3' } });
    assert.equal(a1.status, 200, j(a1.body));
    // V9: 속성 변경이 즉시 게시한다 — 수동 게시는 더 낼 것이 없다.
    assert.equal(a1.body.published, true, j(a1.body));
    assert.equal((await cia.adminPost('/cia/publish')).body.published, false);
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
    const a2 = await cia.adminPost(`/cia/accounts/${uid}/attrs`, { profile: { birthYear: '1992', country: 'KR', extra1: 'tier3' } });
    assert.equal(a2.status, 200, j(a2.body));
    assert.equal(a2.body.published, true, j(a2.body));   // V9: 즉시 게시 — 수동 게시는 더 낼 것이 없다.
    assert.equal((await cia.adminPost('/cia/publish')).body.published, false);
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
  // C-5(2026-09-25 리뷰): 개봉 **조회**만 fail-closed 가 빠져 있었다 — 검증기가 없는(등록 대기·팩토리 상수 조회 실패)
  // RP 가 CIA 로 서명한 조회를 계속 중계했다. 다른 라우트와 같은 503 이어야 한다. 위 I-1 과 같은 이유로 맨 끝에 둔다.
  await t('C-5: 검증기가 없으면 GET /api/mode3/open/:id 도 503 (개봉 조회 fail-closed)', async () => {
    await stack.restartRp({ MODE3_RP_FACTORY_ADDRESS: cia.logAddress }, { waitActive: false });
    assert.equal((await rp.get('/api/mode3/rp_info')).body.active, false, '전제: 검증기가 없는 상태');
    const post = await rp.post('/api/mode3/open', { PPID: '1' });   // 양성 대조 — 개봉 요청은 이미 막혀 있다
    assert.equal(post.status, 503, j(post.body)); assert.equal(post.body.reason, 'factory_constants_unavailable');
    const get = await rp.get('/api/mode3/open/abc');
    assert.equal(get.status, 503, j(get.body)); assert.equal(get.body.reason, 'factory_constants_unavailable', j(get.body));
  });
} finally {
  await stack.stop();
}
process.exit(failed === 0 ? 0 : 1);
