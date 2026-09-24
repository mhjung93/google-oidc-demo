// Mode 3 지갑 에이전트 단독. RP 없이 검증기는 이 프로세스에서 조립한다. (chain 그룹)
//   node tests/test_mode3_wallet_agent.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { VKEY_PATH } from '../lib/mode3_wallet.js';
import { createRpVerifier } from '../lib/mode3_rp.js';
import { randomScalar } from '../lib/mode3_credential.js';
import { deployVerifier, deployFactory, walletAt } from '../lib/mode3_onchain.js';
import { LOG_ABI } from '../lib/mode3_log.js';
import { setRoot } from '../lib/mode3_set_tree.js';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

// vkey 는 스택을 띄우기 전에 읽는다 — 없으면 자식 프로세스를 고아로 남기지 않고 바로 죽는다.
assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = getProvider();
const stack = await startIsolatedMode3Stack({ rp: false, ciaEnv: { CIA_HEARTBEAT_BLOCKS: '5', CIA_HEARTBEAT_POLL_MS: '300' } });
const { cia, wallet } = stack;
const uid = '12345';

try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  // 실제 RP 프로세스는 안 띄우지만, 지갑의 CORS 오리진(rpOriginForWallet)으로 CIA 에 서비스를 등록해
  // (arid, cert_s) 를 얻는다 — /wallet/login 이 요구하는 서비스 인증 정보다.
  const { arid, cert_s, origin, pk_trace } = await cia.registerRp(stack.rpOriginForWallet);
  const rp = createRpVerifier({ provider, logAddress: cia.logAddress, vkey, pkCIA: pk_CIA, arid: BigInt(arid), chainId: 31337n, pkTrace: pk_trace });

  const newRs = () => randomScalar().toString();
  const login = (r_s = newRs(), extra = {}) => wallet.post('/wallet/login', { arid, origin, cert_s, pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }, r_s, ...extra }, { Origin: stack.rpOriginForWallet });
  const revalidate = (r_s, extra = {}) => wallet.post('/wallet/revalidate', { r_s, ...extra }, { Origin: stack.rpOriginForWallet });
  const verify = (body, r_s) => rp.verifyLogin({ proof: body.proof, publicSignals: body.publicSignals, sig: body.sig, r_s: BigInt(r_s) });

  await t('미등록 상태: status.registered=false, login 은 409 not_registered', async () => {
    const s = await wallet.get('/wallet/status');
    assert.equal(s.status, 200);
    assert.equal(s.body.registered, false);
    const r = await login();
    assert.equal(r.status, 409);
    assert.equal(r.body.reason, 'not_registered');
  });

  await t('등록: AA 속성을 저장하고 본문의 attrs 는 무시한다(201); 두 번째는 409, 잘못된 pwd 는 CIA 의 401 을 그대로; /wallet/status 에 attrs', async () => {
    // uid 12345 는 cia.js DEMO_ACCOUNTS.testuser — AA 기록 attrs = ['1990','410','2','0'](2026-09-22 §3.3). 본문의 attrs 는 무시된다.
    const r = await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['1', '2', '3', '4'] });
    assert.equal(r.status, 201, j(r.body));
    assert.deepEqual(r.body, { uid, attrs: ['1990', '410', '2', '0'] });
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123' })).status, 409);
    const s = await wallet.get('/wallet/status');
    assert.equal(s.body.registered, true);
    assert.equal(s.body.uid, uid);
    assert.deepEqual(s.body.attrs, ['1990', '410', '2', '0']);
  });

  let first, PPID1, S1;
  await t('첫 로그인: 자동 발급(issued=true) + 검증 통과, 응답에 uid 없음', async () => {
    const rs = newRs();
    const r = await login(rs);
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, true);
    assert.equal(r.body.cacheHit, false);
    assert.equal(r.body.r_s, rs);
    assert.ok(!('uid' in r.body), 'uid 는 RP 로 나가면 안 된다');
    assert.equal(typeof r.body.timings.proveMs, 'number');
    assert.equal(r.body.publicSignals.length, 25, 'V7: 기존 14 + 선택 공개 disc_mask·disc_lo[4]·disc_hi[4] + 집합 소속 set_sel·set_root');
    assert.equal(r.body.publicSignals[4], '31337');
    assert.equal(r.body.allowAgent, '0'); assert.equal(r.body.publicSignals[5], '0');
    const v = await verify(r.body, rs);
    assert.equal(v.ok, true, j(v));
    first = r.body; PPID1 = v.PPID; S1 = rs;
    assert.ok(r.body.timings.userCredMs > 0, '첫 로그인은 사용자 자격증명을 새로 받는다');
    const s = await wallet.get('/wallet/status');
    assert.ok(s.body.sessions[rs], 'r_s 별 세션이 상태에 있어야 한다');
    assert.ok(s.body.userCred?.Cf_u, '사용자 자격증명이 상태에 있어야 한다');
    assert.equal(s.body.userCred.revoked, false);
    // 격리 스택은 임시 디렉터리라 캐시 파일이 없는 상태에서 시작한다 — 콜드 스타트 첫 로그인은 항상 bootstrap.
    assert.equal(s.body.rcl.lastMode, 'bootstrap', '콜드 스타트 첫 로그인 뒤에는 캐시가 없어 bootstrap 이어야 한다');
  });

  let S1b;
  await t('두 번째 로그인(새 r_s): 사용자 자격증명 재사용 → userCredMs=0, 세션만 새로 발급', async () => {
    S1b = newRs();
    const r = await login(S1b);
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, true);
    assert.equal(r.body.timings.userCredMs, 0);
    assert.equal((await verify(r.body, S1b)).ok, true);
  });

  // 2026-09-23 점검 B-I1: precheck 의 r_s 분기(재승인 동의 창이 쓸 세션의 실제 allowAgent). 라우트에 모드 분기가 없어
  // snap 테스트와 같은 코드를 타지만, file 모드에서도 돈다는 것을 여기서 못 박는다(리뷰 Minor 7).
  await t('precheck: r_s 를 주면 그 세션의 allowAgent 를 돌려주고, 모르는 r_s 는 404 no_session', async () => {
    const pkt = { x: pk_trace.x.toString(), y: pk_trace.y.toString() };
    const S1c = newRs();
    assert.equal((await login(S1c, { allowAgent: '1' })).status, 200);
    const base = { arid, origin, cert_s, pk_trace: pkt };
    const noRs = await wallet.post('/wallet/authorize/precheck', base);
    assert.equal(noRs.status, 200, j(noRs.body)); assert.equal('sessionAllowAgent' in noRs.body, false, 'r_s 가 없으면 세션 값을 싣지 않는다');
    const one = await wallet.post('/wallet/authorize/precheck', { ...base, r_s: S1c });
    assert.equal(one.status, 200, j(one.body)); assert.equal(one.body.sessionAllowAgent, '1');
    const zero = await wallet.post('/wallet/authorize/precheck', { ...base, r_s: S1 });
    assert.equal(zero.status, 200, j(zero.body)); assert.equal(zero.body.sessionAllowAgent, '0');
    const none = await wallet.post('/wallet/authorize/precheck', { ...base, r_s: '424242' });
    assert.equal(none.status, 404, j(none.body)); assert.equal(none.body.reason, 'no_session');
    assert.equal((await wallet.post('/wallet/authorize/precheck', { ...base, r_s: 'nope' })).status, 400);
  });

  await t('재검증: 캐시 히트(cacheHit=true), publicSignals 동일, σ 는 r_s 위 서명(ECDSA 결정적이라 매번 같다)', async () => {
    const r = await revalidate(S1);
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.cacheHit, true);
    assert.deepEqual(r.body.publicSignals, first.publicSignals);
    assert.equal(r.body.sig, first.sig, 'r_s 가 그대로라 서명 메시지도 그대로 — RFC6979 결정적 서명이라 σ 도 같다');
    assert.equal((await verify(r.body, S1)).ok, true);
  });

  await t('CORS: RP 오리진에만 Access-Control-Allow-Origin, 다른 오리진엔 없음. /wallet/tx 는 오리진 불문 열지 않는다(I1)', async () => {
    const good = await wallet.raw('/wallet/login', { method: 'OPTIONS', headers: { Origin: stack.rpOriginForWallet, 'Access-Control-Request-Method': 'POST' } });
    assert.equal(good.headers.get('access-control-allow-origin'), stack.rpOriginForWallet);
    const bad = await wallet.raw('/wallet/login', { method: 'OPTIONS', headers: { Origin: 'http://evil.example', 'Access-Control-Request-Method': 'POST' } });
    assert.equal(bad.headers.get('access-control-allow-origin'), null);
    // /wallet/tx 는 지갑 페이지(같은 오리진)에서만 부른다 — RP 오리진이라도 CORS 를 열지 않는다.
    const txFromRp = await wallet.raw('/wallet/tx', { method: 'OPTIONS', headers: { Origin: stack.rpOriginForWallet, 'Access-Control-Request-Method': 'POST' } });
    assert.equal(txFromRp.headers.get('access-control-allow-origin'), null);
  });

  await t('계정 폐기 + 게시 → skipSync 재검증은 옛 π 를 그대로 → 검증기 stale_root', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'account' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const r = await revalidate(S1, { skipSync: true });
    assert.equal(r.status, 200, j(r.body));
    assert.deepEqual(r.body.publicSignals, first.publicSignals);
    const v = await verify(r.body, S1);
    assert.equal(v.ok, false);
    assert.equal(v.reason, 'stale_root');
  });

  await t('동기화: 재검증 → 폐기 감지 → 두 세션 모두 403 revoked(리프 하나); status userCred.revoked=true; 새 로그인 → CIA 403 → account_disabled', async () => {
    const r = await revalidate(S1);
    assert.equal(r.status, 403, j(r.body));
    assert.equal(r.body.reason, 'revoked');
    // 폐기 리프는 사용자 자격증명 하나 — 같은 자격증명 위의 다른 세션도 함께 죽는다(설계 2026-09-21 §3.6)
    const r2 = await revalidate(S1b);
    assert.equal(r2.status, 403, j(r2.body));
    assert.equal(r2.body.reason, 'revoked');
    const s = await wallet.get('/wallet/status');
    assert.equal(s.body.userCred?.revoked, true, j(s.body.userCred));
    const l = await login();
    assert.equal(l.status, 403, j(l.body));
    assert.equal(l.body.reason, 'account_disabled');
  });

  let S2;
  await t('복구 → 로그인: 사용자 자격증명 재발급(userCredMs>0, Cf_u 바뀜), issued=true, 검증 통과, PPID 동일', async () => {
    const before = (await wallet.get('/wallet/status')).body.userCred.Cf_u;
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
    const rs = newRs();
    const r = await login(rs);
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, true);
    assert.ok(r.body.timings.userCredMs > 0, '폐기된 사용자 자격증명은 새로 받는다');
    const v = await verify(r.body, rs);
    assert.equal(v.ok, true, j(v));
    assert.equal(v.PPID, PPID1, 'PPID 는 폐기·복구로 바뀌지 않는다');
    const s = await wallet.get('/wallet/status');
    assert.notEqual(s.body.userCred.Cf_u, before, '새 사용자 자격증명은 Cf_u 가 다르다');
    assert.equal(s.body.userCred.revoked, false);
    S2 = rs;
  });

  // 이 지점부터는 first(첫 로그인의 π)를 더는 참조하지 않는다 — 재시작으로 증명 캐시가 비면 새로 만든 π 의 tag(재무작위화)가
  // first 와 달라 앞의 deepEqual 비교들이 깨진다. S2 는 방금 복구돼 살아 있고 폐기되지 않았다.
  await t('폐기 트리 동기화: 리셋 뒤 sync 는 bootstrap, 재시작 뒤 재검증은 restore, 다시 리셋하면 bootstrap 으로 돈다 (스펙 §3·§6·§8)', async () => {
    // 여기까지 이미 로그인·재검증이 여러 번 지나 lastMode 가 delta 일 수 있다 — 먼저 리셋해 다음 sync 가 확실히 bootstrap 이 되게 한다.
    assert.equal((await wallet.post('/wallet/rcl/reset', { confirm: true })).body.deferred, false);
    const boot = await revalidate(S2);
    assert.equal(boot.status, 200, j(boot.body));
    const s1 = (await wallet.get('/wallet/status')).body;
    assert.equal(s1.rcl.lastMode, 'bootstrap');
    assert.ok(fs.existsSync(s1.rcl.cacheFile), `캐시 파일이 있어야 한다: ${s1.rcl.cacheFile}`);
    const leavesBefore = s1.rcl.leaves;
    await stack.restartWallet();
    const r = await revalidate(S2);
    assert.equal(r.status, 200, j(r.body));
    const s2 = (await wallet.get('/wallet/status')).body;
    assert.equal(s2.rcl.lastMode, 'restore');
    assert.equal(s2.rcl.leaves, leavesBefore);
  });

  await t('POST /wallet/rcl/reset 은 confirm:true 없으면 400, 있으면 캐시를 지우고 다음 재검증이 bootstrap 으로 돈다', async () => {
    const before = (await wallet.get('/wallet/status')).body.rcl.cacheFile;
    const noConfirm = await wallet.post('/wallet/rcl/reset', {});
    assert.equal(noConfirm.status, 400, j(noConfirm.body));
    // CSRF 방어 논거 자체를 고정한다: 다른 오리진 페이지가 프리플라이트 없이 보낼 수 있는 것은 text/plain 같은 단순 요청뿐인데,
    // express.json() 은 그걸 파싱하지 않으므로 req.body 가 비어 400 이 된다(mode3_wallet_agent.js 의 주석).
    const plain = await wallet.raw('/wallet/rcl/reset', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: JSON.stringify({ confirm: true }) });
    assert.equal(plain.status, 400, 'text/plain 단순 요청은 파싱되지 않아 confirm 이 없다');
    assert.ok(fs.existsSync(before), 'confirm 없이는 캐시가 지워지면 안 된다');
    const r = await wallet.post('/wallet/rcl/reset', { confirm: true });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.deferred, false, '이 시점엔 진행 중인 동기화가 없다');
    assert.ok(!fs.existsSync(before));
    const v = await revalidate(S2);
    assert.equal(v.status, 200, j(v.body));
    assert.equal((await wallet.get('/wallet/status')).body.rcl.lastMode, 'bootstrap');
  });

  await t('자격증명만 폐기(scope=credential), 게시 전 로그인: CIA no_user_cred → 지갑이 새 C_u 를 받아 재시도 → 200, PPID 동일, Cf_u 바뀜', async () => {
    const before = (await wallet.get('/wallet/status')).body.userCred;
    assert.equal(before.revoked, false);
    const rv = await cia.adminPost('/cia/revoke', { uid, scope: 'credential' });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.inserted.length, 1, '활성 C_u 리프 하나가 pending 에 들어간다');
    // 게시하지 않는다 — 체인 트리에는 리프가 없어 ensureUserCred 는 옛 C_u 를 그대로 쓰고 /cia/issue 가 403 no_user_cred 를 낸다.
    const rs = newRs();
    const r = await login(rs);
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, true);
    assert.ok(r.body.timings.userCredMs > 0, '거절을 받고 사용자 자격증명을 새로 받았어야 한다');
    const v = await verify(r.body, rs);
    assert.equal(v.ok, true, j(v));
    assert.equal(v.PPID, PPID1, 'PPID 는 s_u 에서 나오므로 C_u 재발급으로 바뀌지 않는다');
    const s = await wallet.get('/wallet/status');
    assert.notEqual(s.body.userCred.Cf_u, before.Cf_u, '새 사용자 자격증명은 Cf_u 가 다르다');
    assert.equal(s.body.userCred.revoked, false);
    assert.equal(s.body.sessions[S2], undefined, '물린 자격증명 위의 옛 세션은 지워진다');
    assert.equal(s.body.sessions[rs].PPID, PPID1.toString());
    S2 = rs;   // 이후 테스트는 이 세션을 쓴다
    // 그 사이 pending 이던 옛 리프가 게시돼도 새 C_u 는 영향이 없다
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const rr = await revalidate(S2);
    assert.equal(rr.status, 200, j(rr.body)); assert.equal(rr.body.cacheHit, false);
  });

  await t('입력 검증: r_s 없음 / cert_s 없음 / pk_trace 없음 → 400', async () => {
    assert.equal((await wallet.post('/wallet/login', { arid, origin, cert_s }, { Origin: stack.rpOriginForWallet })).status, 400);
    assert.equal((await wallet.post('/wallet/login', { arid, origin, r_s: newRs() }, { Origin: stack.rpOriginForWallet })).status, 400);
    assert.equal((await wallet.post('/wallet/login', { arid, origin, cert_s, r_s: newRs() }, { Origin: stack.rpOriginForWallet })).status, 400);
    assert.equal((await login(newRs(), { allowAgent: '2' })).status, 400);
  });

  await t('bad_rp_cert: 인증서와 다른 pk_trace 를 주면 403 (서비스 혼자 아는 키로 바꿔치기)', async () => {
    const r = await login(newRs(), { pk_trace: { x: '1', y: '2' } });
    assert.equal(r.status, 403); assert.equal(r.body.reason, 'bad_rp_cert');
  });

  await t('status: 세션이 max_height(블록)·allowAgent·PPID 를 보여주고 exptime 은 없다', async () => {
    const s = await wallet.get('/wallet/status');
    const c = s.body.sessions[S2];
    assert.ok(c, 'S2 세션이 상태에 있어야 한다');
    assert.match(String(c.max_height), /^[0-9]+$/);
    assert.equal(c.exptime, undefined);
    assert.equal(c.allowAgent, '0');
    assert.match(String(c.PPID), /^[0-9]+$/);
    assert.ok(BigInt(c.max_height) > BigInt(await provider.getBlockNumber()));
    assert.equal(BigInt(c.max_height) % 100n, 0n, '지갑이 그리드(100)로 정한 max_height');
  });

  await t('revalidate: 모르는 r_s 는 404 no_session', async () => {
    const r = await revalidate(newRs());
    assert.equal(r.status, 404);
    assert.equal(r.body.reason, 'no_session');
  });

  await t('request: 세션키 서명 반환', async () => {
    const r = await wallet.post('/wallet/request', { r_s: S2, body: 'ping' }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(typeof r.body.sig, 'string');
    assert.equal(typeof r.body.pk_i, 'string');
  });

  await t('allowAgent=1 로그인: 공개 입력 [5] 가 1', async () => {
    const rs = newRs();
    const r = await login(rs, { allowAgent: '1' });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.publicSignals[5], '1'); assert.equal(r.body.allowAgent, '1');
    assert.equal((await verify(r.body, rs)).ok, true);
  });

  await t('login: 인증서와 다른 arid 로 배포된 팩토리, 또는 컨트랙트가 아닌 주소를 factoryAddress 로 주면 409 bad_factory (2026-09-18 점검 3)', async () => {
    const signer = await provider.getSigner(0);
    const v = await deployVerifier(signer);
    const wrongArid = await deployFactory(signer, { verifierAddress: v, arid: BigInt(arid) + 1n, pkCIA: pk_CIA, pkTrace: pk_trace, logAddress: cia.logAddress, maxRootAge: 10n });
    const r1 = await login(newRs(), { factoryAddress: wrongArid });
    assert.equal(r1.status, 409, j(r1.body)); assert.equal(r1.body.reason, 'bad_factory');
    const r2 = await login(newRs(), { factoryAddress: ethers.Wallet.createRandom().address });
    assert.equal(r2.status, 409, j(r2.body)); assert.equal(r2.body.reason, 'bad_factory');
  });

  await t('login: 무엇이든 통과시키는 검증자를 가리키는 팩토리(immutable 은 전부 정상)는 409 bad_factory / verifier_code_mismatch (참조 코드 대조, 2026-09-23)', async () => {
    const signer = await provider.getSigner(0);
    const { abi, bytecode } = JSON.parse(fs.readFileSync(new URL('../artifacts/contracts/test/AcceptAllPiCredVerifier.sol/AcceptAllPiCredVerifier.json', import.meta.url), 'utf8'));   // 테스트 전용 검증자(contracts/test)
    const fake = await new ethers.ContractFactory(abi, bytecode, signer).deploy();
    await fake.waitForDeployment();
    const rogue = await deployFactory(signer, { verifierAddress: await fake.getAddress(), arid: BigInt(arid), pkCIA: pk_CIA, pkTrace: pk_trace, logAddress: cia.logAddress });
    const r = await login(newRs(), { factoryAddress: rogue });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'bad_factory'); assert.equal(r.body.detail, 'verifier_code_mismatch');
  });

  let factoryAddress, S3, walletAddr;
  await t('tx: factoryAddress 없이 로그인한 세션은 409 no_factory', async () => {
    const r = await wallet.post('/wallet/tx', { r_s: S2, to: ethers.Wallet.createRandom().address }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'no_factory');
  });

  await t('tx: 팩토리를 준 세션 — 첫 트랜잭션은 지갑 배포 + 실행 ok, 두 번째는 캐시 π 재사용·nonce 1', async () => {
    const signer = await provider.getSigner(0);
    const verifierAddress = await deployVerifier(signer);
    factoryAddress = await deployFactory(signer, { verifierAddress, arid, pkCIA: pk_CIA, pkTrace: pk_trace, logAddress: cia.logAddress, maxRootAge: 10n });
    S3 = newRs();
    const l = await login(S3, { factoryAddress });
    assert.equal(l.status, 200, j(l.body));
    const to = ethers.Wallet.createRandom().address;
    const r1 = await wallet.post('/wallet/tx', { r_s: S3, to, value: '0' }, { Origin: stack.rpOriginForWallet });
    assert.equal(r1.status, 200, j(r1.body));
    assert.equal(r1.body.deployed, true); assert.equal(r1.body.ok, true); assert.equal(r1.body.nonce, '0'); assert.match(r1.body.txHash, /^0x[0-9a-f]{64}$/);
    walletAddr = r1.body.wallet;
    assert.notEqual(await provider.getCode(walletAddr), '0x');
    const r2 = await wallet.post('/wallet/tx', { r_s: S3, to }, { Origin: stack.rpOriginForWallet });
    assert.equal(r2.status, 200, j(r2.body));
    assert.equal(r2.body.deployed, false); assert.equal(r2.body.cacheHit, true); assert.equal(r2.body.nonce, '1');
    assert.equal(await walletAt(walletAddr, provider).nonce(), 2n);
    console.log(`     execute gas ${r1.body.gasUsed} (배포 포함 tx 아님 — execute 만)`);
  });

  await t('tx: 값 전송 — 릴레이어가 지갑에 입금한 뒤 value 를 보내면 수신자 잔액이 는다', async () => {
    const signer = await provider.getSigner(0);
    await (await signer.sendTransaction({ to: walletAddr, value: ethers.parseEther('0.5') })).wait();
    const to = ethers.Wallet.createRandom().address;
    const r = await wallet.post('/wallet/tx', { r_s: S3, to, value: ethers.parseEther('0.1').toString() }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.ok, true);
    assert.equal(await provider.getBalance(to), ethers.parseEther('0.1'));
  });

  await t('tx: root 게시가 maxRootAge(10) 보다 오래되면 execute_reverted RootTooOld, CIA 하트비트 뒤 다시 ok', async () => {
    const log = new ethers.Contract(cia.logAddress, LOG_ABI, provider);
    const last0 = await log.lastPublishedBlock();
    await provider.send('hardhat_mine', ['0xb']);
    // 하트비트가 먼저 돌아 버리면 revert 를 못 본다 — 게시 뒤 11 블록 안에 제출한다(하트비트는 5 블록마다 300ms 폴링).
    const r = await wallet.post('/wallet/tx', { r_s: S3, to: ethers.Wallet.createRandom().address }, { Origin: stack.rpOriginForWallet });
    if (r.status === 409) assert.match(r.body.detail, /RootTooOld/, j(r.body));
    else assert.equal(r.status, 200, j(r.body));   // 하트비트가 이미 따라잡았으면 그대로 ok — 아래에서 lastPublishedBlock 전진만 확인
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline && (await log.lastPublishedBlock()) === last0) await new Promise((res) => setTimeout(res, 200));
    assert.ok((await log.lastPublishedBlock()) > last0, `하트비트가 게시했어야 한다\n${cia.log()}`);
    // :8545 는 공유 노드다(CLAUDE.md) — 다른 프로세스가 그 사이 블록을 더 진행시키면 maxRootAge(10) 를 다시
    // 넘길 수 있다(관찰됨). 첫 시도가 또 RootTooOld 면 짧게 재시도한다 — 대상 자체는 여전히 "곧 성공" 이다.
    let ok;
    for (let attempt = 0; attempt < 5; attempt++) {
      ok = await wallet.post('/wallet/tx', { r_s: S3, to: ethers.Wallet.createRandom().address }, { Origin: stack.rpOriginForWallet });
      if (ok.status === 200) break;
      await new Promise((res) => setTimeout(res, 200));
    }
    assert.equal(ok.status, 200, j(ok.body)); assert.equal(ok.body.ok, true);
  });

  await t('tx: 계정 폐기 + 게시 뒤에는 403 revoked (재증명 불가)', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'account' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const r = await wallet.post('/wallet/tx', { r_s: S3, to: ethers.Wallet.createRandom().address }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.reason, 'revoked');
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
  });

  await t('tx 입력 검증: r_s 없음·주소 아님·모르는 세션', async () => {
    assert.equal((await wallet.post('/wallet/tx', { to: walletAddr }, { Origin: stack.rpOriginForWallet })).status, 400);
    assert.equal((await wallet.post('/wallet/tx', { r_s: S3, to: 'nope' }, { Origin: stack.rpOriginForWallet })).status, 400);
    assert.equal((await wallet.post('/wallet/tx', { r_s: newRs(), to: walletAddr }, { Origin: stack.rpOriginForWallet })).status, 404);
  });

  await t('register: 이미 등록된 계정에는 attrs 내용과 무관하게 409(2026-09-22 §3.3 — attrs 본문은 이제 형식도 검사하지 않고 무시한다)', async () => {
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['1', '2', '3', '4', '5'] })).status, 409);
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['x'] })).status, 409);
  });

  // 지갑이 로그인용으로 쓰는 헬퍼 — 등록은 이미 위에서 됐으므로 새 r_s 로 로그인만 한다. PPID 는 다른 케이스와 같이
  // verify(RP 검증기)를 거쳐 검증된 로그인에서 읽는다(Task 6 이후 publicSignals.length===25 을 받아들인다).
  async function loginOnce(extra = {}) {
    const rs = newRs();
    const r = await login(rs, extra);
    assert.equal(r.status, 200, j(r.body));
    const v = await verify(r.body, rs);
    assert.equal(v.ok, true, j(v));
    return { ...r.body, r_s: rs, PPID: v.PPID.toString() };
  }
  async function publishOnce() {
    const r = await cia.adminPost('/cia/publish');
    assert.equal(r.body.published, true, j(r.body));
  }

  await t('관리자가 속성을 바꾸면 다음 로그인이 bad proof → /cia/attrs 재동기화 → 새 C_u 로 성공, PPID 동일', async () => {
    const first = await loginOnce();
    assert.equal((await cia.adminPost(`/cia/accounts/${uid}/attrs`, { attrs: ['1990', '410', '3', '0'] })).status, 200);
    await publishOnce();   // 물린 옛 리프가 트리에 올라야 ensureUserCred 가 새 C_u 를 시도하고(옛 attrs 로) bad proof 를 만난다
    const second = await loginOnce();
    assert.equal(second.PPID, first.PPID);
    assert.equal(second.timings.userCredMs > 0, true, '재동기화 뒤 새 C_u 를 받았다');
    assert.deepEqual((await wallet.get('/wallet/status')).body.attrs, ['1990', '410', '3', '0']);
  });

  await t('/wallet/attrs 는 사라졌고(404) /wallet/attrs/sync 는 값을 다시 받는다', async () => {
    assert.equal((await wallet.post('/wallet/attrs', { attrs: ['1', '0', '0', '0'] })).status, 404);
    const r = await wallet.post('/wallet/attrs/sync', {});
    assert.equal(r.status, 200, j(r.body)); assert.equal(Array.isArray(r.body.attrs), true);
    assert.deepEqual(r.body.attrs, ['1990', '410', '3', '0']); assert.equal(r.body.changed, false, '이미 최신이라 바뀐 게 없다');
  });

  // V8 세션 폐기(설계 2026-09-24 §4). 계획서는 이 두 케이스를 앞쪽 '동기화: 재검증 → 폐기 감지 …' 앞에 두라고 했지만,
  // 그 자리는 바로 앞 케이스가 계정을 폐기·게시해 둔 구간이라 loginOnce 가 account_disabled 로 막히고, 게시로 root 가
  // 바뀌면 그 케이스의 skipSync 단언(캐시 π 재제출)도 깨진다. 계정이 살아 있고 loginOnce·publishOnce 가 이미 쓰이는
  // 이 지점으로 옮겼다 — 단언 내용은 계획서 그대로다.
  await t('V8 세션 폐기: 세션 둘 중 하나를 /wallet/session/revoke → 게시 → 그 세션만 403 revoked_session, 다른 세션은 재검증 성공, 새 로그인 정상', async () => {
    const a = await loginOnce(), b = await loginOnce();
    const r = await wallet.post('/wallet/session/revoke', { r_s: a.r_s });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.revoked, true);
    assert.equal((await wallet.get('/wallet/status')).body.sessions[a.r_s], undefined, '폐기 요청 뒤 지갑은 세션을 버린다');
    await publishOnce();
    const rb = await revalidate(b.r_s);
    assert.equal(rb.status, 200, j(rb.body));
    const c = await loginOnce();   // 사용자 자격증명은 살아 있다
    assert.ok(c.r_s);
    const missing = await wallet.post('/wallet/session/revoke', { r_s: '999' });
    assert.equal(missing.status, 404); assert.equal(missing.body.reason, 'no_session');
  });

  await t('V8: 세션 하나가 지갑 밖에서(관리자) 폐기되면 재검증이 403 revoked_session 으로 그 세션만 지운다 — 사용자 자격증명은 그대로', async () => {
    const before = new Set((await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.map((x) => x.Cf_s));
    const a = await loginOnce();
    // 관리자가 이 세션만 폐기(지갑은 모른다). 이 로그인이 새로 만든 기록을 Cf_s 로 직접 집는다 —
    // 목록 순서나 만료 정리 시점에 기대지 않는다(최종 리뷰 F6).
    const cf = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.map((x) => x.Cf_s).find((c) => !before.has(c));
    assert.ok(cf, '방금 로그인의 세션 기록이 있어야 한다');
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'session', Cf_s: cf })).status, 200);
    await publishOnce();
    const r = await revalidate(a.r_s);
    assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.reason, 'revoked_session');
    const s = await wallet.get('/wallet/status');
    assert.equal(s.body.userCred?.revoked, false, '사용자 자격증명은 그대로');
    assert.equal(s.body.sessions[a.r_s], undefined, '폐기된 세션만 지워진다');
    // 같은 세션을 다시 재검증하면 이미 지워져 404 no_session 이다(지갑은 그 세션을 더 들고 있지 않다)
    assert.equal((await revalidate(a.r_s)).status, 404);
  });

  await t('/wallet/tx disclose: 만족하는 구간은 새 π 로 실행되고 onchainDisclosure 가 있다; 불만족은 400 disclosure_unsatisfiable; mask 0 은 그대로 진행된다', async () => {
    // attrGateAddress 는 Task 6 가 RP 에 준다 — 그 전엔 dEaD 로 보내고 onchainDisclosure 만 본다(회로·컨트랙트 배선 확인이 목적).
    const to = '0x000000000000000000000000000000000000dEaD';
    const s = await loginOnce({ factoryAddress });
    const ok = await wallet.post('/wallet/tx', { r_s: s.r_s, to, data: '0x4e71d92d', disclose: [{ lo: '0', hi: '2007' }, { lo: '410', hi: '410' }, null, null] }, { Origin: stack.rpOriginForWallet });
    assert.equal(ok.status, 200, j(ok.body));
    assert.equal(ok.body.disclosure.mask, '3'); assert.equal(ok.body.cacheHit, false);
    assert.equal(ok.body.onchainDisclosure.mask, '3');
    assert.deepEqual(ok.body.onchainDisclosure.lo, ['0', '410', '0', '0']);
    assert.deepEqual(ok.body.onchainDisclosure.hi, ['2007', '410', '0', '0']);
    const bad = await wallet.post('/wallet/tx', { r_s: s.r_s, to, disclose: [{ lo: '0', hi: '1980' }, null, null, null] }, { Origin: stack.rpOriginForWallet });
    assert.equal(bad.status, 400, j(bad.body)); assert.equal(bad.body.reason, 'disclosure_unsatisfiable');
    const plain = await wallet.post('/wallet/tx', { r_s: s.r_s, to }, { Origin: stack.rpOriginForWallet });
    assert.equal(plain.status, 200, j(plain.body)); assert.equal(plain.body.disclosure, null); assert.equal(plain.body.onchainDisclosure, null);
  });

  await t('V7 /wallet/tx: set 으로 국가 ∈ 집합을 증명하면 onchainDisclosure.set 이 sel 2·root 로 남는다; 비소속 집합은 400 disclosure_unsatisfiable; slot 4 는 bad_disclosure', async () => {
    const to = '0x000000000000000000000000000000000000dEaD';
    const s = await loginOnce({ factoryAddress });
    const members = [410, 392, 840, 276, 250];
    const ok = await wallet.post('/wallet/tx', { r_s: s.r_s, to, disclose: [null, null, null, null], set: { slot: 1, members } }, { Origin: stack.rpOriginForWallet });
    assert.equal(ok.status, 200, j(ok.body));
    assert.equal(ok.body.onchainDisclosure.mask, '0');
    assert.equal(ok.body.onchainDisclosure.set.sel, '2');
    assert.equal(ok.body.onchainDisclosure.set.root, (await setRoot(members)).toString());
    const miss = await wallet.post('/wallet/tx', { r_s: s.r_s, to, set: { slot: 1, members: [392, 840] } }, { Origin: stack.rpOriginForWallet });
    assert.equal(miss.status, 400, j(miss.body)); assert.equal(miss.body.reason, 'disclosure_unsatisfiable');
    const bad = await wallet.post('/wallet/tx', { r_s: s.r_s, to, set: { slot: 4, members } }, { Origin: stack.rpOriginForWallet });
    assert.equal(bad.status, 400, j(bad.body)); assert.equal(bad.body.reason, 'bad_disclosure');
  });

  // 마지막에 둔다 — CIA 를 끈다. stack.stop() 의 cia.stop() 은 이미 죽은 프로세스를 건너뛴다.
  await t('attrs/sync: CIA 가 죽어 요청 자체가 실패해도(500) 옛 자격증명·속성·세션이 그대로 남고 재검증은 계속 된다', async () => {
    const before = (await wallet.get('/wallet/status')).body;
    await cia.stop();
    const r = await wallet.post('/wallet/attrs/sync', {});
    assert.equal(r.status, 500, j(r.body));
    const after = (await wallet.get('/wallet/status')).body;
    assert.equal(after.userCred.Cf_u, before.userCred.Cf_u, 'CIA 다운이어도 옛 자격증명이 남는다');
    assert.deepEqual(Object.keys(after.sessions), Object.keys(before.sessions), 'CIA 다운이어도 세션은 그대로');
    assert.equal((await revalidate(Object.keys(after.sessions)[0])).status, 200, '재검증은 CIA 없이 된다');
  });
} finally {
  await stack.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
