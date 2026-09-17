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

  await t('등록: 201, 두 번째는 409, 잘못된 pwd 는 CIA 의 401 을 그대로', async () => {
    const r = await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['19', '410', '0', '0'] });
    assert.equal(r.status, 201, j(r.body));
    assert.deepEqual(r.body, { uid });
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123' })).status, 409);
    const s = await wallet.get('/wallet/status');
    assert.equal(s.body.registered, true);
    assert.equal(s.body.uid, uid);
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
    assert.equal(r.body.publicSignals.length, 14);
    assert.equal(r.body.publicSignals[4], '31337');
    assert.equal(r.body.allowAgent, '0'); assert.equal(r.body.publicSignals[5], '0');
    const v = await verify(r.body, rs);
    assert.equal(v.ok, true, j(v));
    first = r.body; PPID1 = v.PPID; S1 = rs;
    const s = await wallet.get('/wallet/status');
    assert.ok(s.body.sessions[rs], 'r_s 별 세션이 상태에 있어야 한다');
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

  await t('동기화: 재검증 → 폐기 감지 → 403 revoked; 새 로그인 → CIA 403 → account_disabled', async () => {
    const r = await revalidate(S1);
    assert.equal(r.status, 403, j(r.body));
    assert.equal(r.body.reason, 'revoked');
    const l = await login();
    assert.equal(l.status, 403, j(l.body));
    assert.equal(l.body.reason, 'account_disabled');
  });

  let S2;
  await t('복구 → 로그인: 재발급(issued=true), 검증 통과, PPID 동일', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
    const rs = newRs();
    const r = await login(rs);
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, true);
    const v = await verify(r.body, rs);
    assert.equal(v.ok, true, j(v));
    assert.equal(v.PPID, PPID1, 'PPID 는 폐기·복구로 바뀌지 않는다');
    S2 = rs;
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

  await t('register: attrs 가 4개를 넘거나 10진이 아니면 400', async () => {
    // 이미 등록된 상태에서는 409 가 먼저이므로 형식 검사는 등록 앞에 있어야 한다 — 새 인스턴스 없이 확인하려면
    // 400 이 409 보다 먼저 나오는지를 본다.
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['1', '2', '3', '4', '5'] })).status, 400);
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['x'] })).status, 400);
  });
} finally {
  await stack.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
