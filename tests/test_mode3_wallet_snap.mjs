// snap 모드 지갑 에이전트 — 스펙 2026-09-22 metamask-snap §3.3·§7. Snap 은 tests/helpers/snap_sim.mjs 로, MetaMask 의
// eth_sendTransaction 은 hardhat 계정(EOA 역할)으로 흉내 낸다. hardhat :8545 필요. (chain 그룹)
//   node tests/test_mode3_wallet_snap.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { createSnapSim } from './helpers/snap_sim.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { VKEY_PATH } from '../lib/mode3_wallet.js';
import { createRpVerifier } from '../lib/mode3_rp.js';
import { validateWitness } from '../lib/mode3_secret_source.js';
import { attrGateAt, decodeExecuteCalldata } from '../lib/mode3_onchain.js';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); }
}

// vkey 는 스택을 띄우기 전에 확인한다 — 없으면 자식 프로세스를 고아로 남기지 않고 바로 죽는다.
assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = getProvider();
const stack = await startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'snap' } });
const { cia, wallet, rp } = stack;
const sim = createSnapSim();

try {
  assert.ok(stack.walletStateFile, '헬퍼가 walletStateFile 을 준다');
  assert.equal(typeof stack.restartWallet, 'function', '헬퍼가 restartWallet() 을 준다');
  const stateFile = () => fs.readFileSync(stack.walletStateFile, 'utf8');
  const keys = (await cia.get('/cia/public_keys')).body;
  // 팩토리·AttrGate 주소는 승인 뒤 RP 가 배포하면서 채워진다 — 필요한 곳에서 다시 읽는다(info 의 arid·pk_trace·cert_s 는 고정)
  const rpInfo = async () => (await rp.get('/api/mode3/rp_info')).body;
  const info = await rpInfo();
  const verifier = createRpVerifier({ provider, logAddress: cia.logAddress, vkey, pkCIA: { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) }, arid: BigInt(info.arid), chainId: BigInt(info.chainId), pkTrace: { x: BigInt(info.pk_trace.x), y: BigInt(info.pk_trace.y) } });
  const verify = (body, r_s) => verifier.verifyLogin({ proof: body.proof, publicSignals: body.publicSignals, sig: body.sig, r_s: BigInt(r_s) });
  /** 지갑 페이지 팝업이 만드는 /wallet/login 본문(증인 제외). */
  const loginBase = async () => {
    const ch = (await rp.post('/api/mode3/challenge')).body;
    return { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, allowAgent: '0', factoryAddress: ch.factoryAddress, attrGateAddress: ch.attrGateAddress, verifiedOrigin: info.origin };
  };

  await t('config: secrets=snap', async () => {
    const r = await wallet.get('/wallet/config');
    assert.equal(r.status, 200); assert.equal(r.body.secrets, 'snap');
  });

  await t('register: cm_u 없으면 400; 응답에 sk_u·attrs; 상태 파일에는 비밀 없음; status 는 공개 uid·attrs 를 보인다', async () => {
    const r0 = await sim.register({ uid: '12345', pwd: 'password123' });
    assert.equal((await wallet.post('/wallet/register', { uid: r0.uid, pwd: r0.pwd })).status, 400, 'snap 모드는 cm_u 필수');
    assert.equal((await wallet.post('/wallet/register', { uid: r0.uid, pwd: r0.pwd, cm_u: { x: 'zz', y: '1' } })).status, 400);
    const r = await wallet.post('/wallet/register', { uid: r0.uid, pwd: r0.pwd, cm_u: r0.cm_u });
    assert.equal(r.status, 201, j(r.body));
    assert.match(r.body.sk_u, /^[0-9a-f]{64}$/);
    assert.deepEqual(r.body.attrs, ['1990', '410', '2', '0']);
    assert.equal(r.body.uid, '12345');
    sim.storeRegistration({ sk_u: r.body.sk_u, attrs: r.body.attrs });
    const file = stateFile();
    for (const k of ['"s_u"', '"r_u"', '"sk_u"', '"blind_u"']) assert.equal(file.includes(k), false, `${k} 가 파일에 있다`);
    assert.ok(file.includes('"cm_u"'), '공개 cm_u 는 파일에 있다');
    assert.equal((await wallet.post('/wallet/register', { uid: r0.uid, pwd: r0.pwd, cm_u: r0.cm_u })).status, 409);
    const s = (await wallet.get('/wallet/status')).body;
    assert.equal(s.registered, true); assert.equal(s.uid, '12345'); assert.deepEqual(s.attrs, ['1990', '410', '2', '0']); assert.equal(s.userCred, null);
    assert.equal(sim.getPublicInfo().registered, true); assert.equal(sim.getPublicInfo().hasUserCred, false);
  });

  await t('precheck: 정상 ok, 인증서 위조 403 bad_rp_cert, 팩토리 주소 오류 409 bad_factory', async () => {
    const ch = (await rp.post('/api/mode3/challenge')).body;
    const base = { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, factoryAddress: ch.factoryAddress };
    const ok = await wallet.post('/wallet/authorize/precheck', base);
    assert.equal(ok.status, 200, j(ok.body)); assert.equal(ok.body.ok, true);
    const bad = await wallet.post('/wallet/authorize/precheck', { ...base, origin: 'http://evil.example' });
    assert.equal(bad.status, 403); assert.equal(bad.body.reason, 'bad_rp_cert');
    const badF = await wallet.post('/wallet/authorize/precheck', { ...base, factoryAddress: cia.logAddress });
    assert.equal(badF.status, 409); assert.equal(badF.body.reason, 'bad_factory');
    assert.equal((await wallet.post('/wallet/authorize/precheck', { arid: info.arid })).status, 400);
  });

  await t('CORS: snap 모드는 /wallet/login 에 CORS 없음, /wallet/revalidate·/wallet/request 는 RP 오리진에 열려 있음', async () => {
    const opt = (p) => wallet.raw(p, { method: 'OPTIONS', headers: { Origin: rp.origin, 'Access-Control-Request-Method': 'POST' } });
    assert.equal((await opt('/wallet/login')).headers.get('access-control-allow-origin'), null);
    assert.equal((await opt('/wallet/revalidate')).headers.get('access-control-allow-origin'), rp.origin);
    assert.equal((await opt('/wallet/request')).headers.get('access-control-allow-origin'), rp.origin);
    assert.equal((await opt('/wallet/tx/prepare')).headers.get('access-control-allow-origin'), null);
  });

  let S1 = null, W1 = null, S2 = null;   // S2 는 allowAgent='1' 로 만든 세션(B-I1 검사용)
  await t('login: witness 없으면 400 witness_required; uid 다르면 400 bad_witness; verifiedOrigin 불일치 403; 정상은 세션·userCredIssued', async () => {
    const base = await loginBase();
    const noW = await wallet.post('/wallet/login', base);
    assert.equal(noW.status, 400, j(noW.body)); assert.equal(noW.body.reason, 'witness_required');
    const w = sim.consentLogin({ origin: info.origin, arid: info.arid, allowAgent: '0' });
    await validateWitness(w, '12345', sim.state.registration.cm_u);   // 시뮬레이터의 증인은 에이전트의 형식·cm_u 검사를 통과해야 한다
    assert.equal(w.userCred, null, '첫 로그인 전에는 C_u 가 없다');
    const badW = await wallet.post('/wallet/login', { ...base, witness: { ...w, uid: '1' } });
    assert.equal(badW.status, 400, j(badW.body)); assert.equal(badW.body.reason, 'bad_witness');
    // cm_u 바인딩(최종 리뷰 Minor 1): 형식은 맞지만 등록의 s_u 가 아닌 증인은 거절된다.
    const badCm = await wallet.post('/wallet/login', { ...base, witness: { ...w, s_u: '12345' } });
    assert.equal(badCm.status, 400, j(badCm.body)); assert.equal(badCm.body.reason, 'bad_witness');
    assert.match(badCm.body.detail ?? '', /cm_u/);
    const badO = await wallet.post('/wallet/login', { ...base, witness: w, verifiedOrigin: 'http://evil:1' });
    assert.equal(badO.status, 403, j(badO.body)); assert.equal(badO.body.reason, 'bad_rp_cert');
    // Origin 헤더는 snap 모드에서 무시된다(같은 오리진 호출) — verifiedOrigin 만 본다
    const ok = await wallet.post('/wallet/login', { ...base, witness: w }, { Origin: 'http://whatever.example' });
    assert.equal(ok.status, 200, j(ok.body));
    assert.equal(ok.body.issued, true);
    assert.ok(ok.body.userCredIssued, '첫 로그인은 새 C_u 를 응답에 실어 페이지가 Snap 에 저장한다');
    for (const k of ['C_u_pt', 'Cf_u', 'blind_u', 'leaf', 'issuedAt']) assert.ok(k in ok.body.userCredIssued, `userCredIssued.${k}`);
    assert.equal('attrsChanged' in ok.body, false);
    assert.ok(!('uid' in ok.body) && !('s_u' in ok.body), '비밀·uid 는 응답에 없다');
    sim.updateUserCred(ok.body.userCredIssued);
    assert.equal(sim.getPublicInfo().hasUserCred, true);
    const v = await verify(ok.body, base.r_s); assert.equal(v.ok, true, j(v));
    S1 = base.r_s; W1 = ok.body;
    const file = stateFile();
    for (const k of ['"s_u"', '"r_u"', '"sk_u"', '"blind_u"', '"witness"']) assert.equal(file.includes(k), false, `${k} 가 파일에 있다`);
    assert.ok(file.includes('"Cf_u"') && file.includes('"leaf"'), 'C_u 의 공개 부분(Cf_u·leaf)은 파일에 있다');
    const s = (await wallet.get('/wallet/status')).body;
    assert.ok(s.sessions[S1]); assert.equal(s.userCred?.Cf_u, ok.body.userCredIssued.Cf_u); assert.equal(s.userCred.revoked, false);
    assert.equal((await wallet.post('/wallet/login', { ...base, witness: w })).body.reason, 'duplicate_session');
  });

  await t('두 번째 로그인: Snap 의 userCred 를 증인에 실으면 C_u 재사용(userCredMs=0, userCredIssued 없음)', async () => {
    const base = await loginBase();
    const w = sim.consentLogin({ origin: info.origin, arid: info.arid, allowAgent: '1' });
    assert.ok(w.userCred?.blind_u);
    const r = await wallet.post('/wallet/login', { ...base, allowAgent: '1', witness: w });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.timings.userCredMs, 0); assert.equal('userCredIssued' in r.body, false);
    assert.equal(r.body.allowAgent, '1');
    assert.equal((await verify(r.body, base.r_s)).ok, true);
    S2 = base.r_s;
  });

  await t('revalidate 는 메모리 witness 로 되고(캐시 히트), 재시작하면 needs_consent → /wallet/session/witness 로 복구(재증명); /wallet/request 는 증인 불필요', async () => {
    const { attrGateAddress } = await rpInfo();
    assert.ok(attrGateAddress);
    const rv = await wallet.post('/wallet/revalidate', { r_s: S1 }, { Origin: rp.origin });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.cacheHit, true);
    assert.equal((await verify(rv.body, S1)).ok, true);
    // 세션 경로는 동의 때 검증된 메모리 증인만 쓴다 — RP 오리진이 CORS 로 부를 수 있으므로 본문 증인은 무시한다(리뷰 Ruling 4).
    // 엉뚱한 증인(userCred:null)을 실어도 세션이 지워지지 않고 정상 200 이어야 한다.
    const evil = { ...sim.consentLogin({ origin: info.origin, arid: info.arid, allowAgent: '0' }), userCred: null };
    const rvEvil = await wallet.post('/wallet/revalidate', { r_s: S1, witness: evil }, { Origin: rp.origin });
    assert.equal(rvEvil.status, 200, j(rvEvil.body));
    assert.equal((await verify(rvEvil.body, S1)).ok, true);
    assert.ok((await wallet.get('/wallet/status')).body.sessions[S1], '본문 증인으로 세션을 지울 수 없다');
    await stack.restartWallet();
    assert.equal((await wallet.get('/wallet/config')).body.secrets, 'snap');
    const s = (await wallet.get('/wallet/status')).body;
    assert.ok(s.sessions[S1], '세션은 파일에서 살아난다');
    const nc = await wallet.post('/wallet/revalidate', { r_s: S1 }, { Origin: rp.origin });
    assert.equal(nc.status, 409, j(nc.body)); assert.equal(nc.body.reason, 'needs_consent');
    // 재시작 뒤에도 본문 증인은 세션 경로를 열어 주지 않는다 — /wallet/session/witness 로만 채운다
    const ncW = await wallet.post('/wallet/revalidate', { r_s: S1, witness: sim.consentLogin({ origin: info.origin, arid: info.arid, allowAgent: '0' }) }, { Origin: rp.origin });
    assert.equal(ncW.status, 409, j(ncW.body)); assert.equal(ncW.body.reason, 'needs_consent');
    const req = await wallet.post('/wallet/request', { r_s: S1, body: 'hello' }, { Origin: rp.origin });
    assert.equal(req.status, 200, j(req.body)); assert.equal(req.body.pk_i, W1.pk_i);
    const pre = await wallet.post('/wallet/tx/prepare', { r_s: S1, to: attrGateAddress });
    assert.equal(pre.status, 409, j(pre.body)); assert.equal(pre.body.reason, 'needs_consent');
    // 재승인: 팝업이 consentLogin 을 다시 받아 세션에 채운다
    const w = sim.consentLogin({ origin: info.origin, arid: info.arid, allowAgent: '0' });
    assert.equal((await wallet.post('/wallet/session/witness', { r_s: S1, witness: { ...w, uid: '1' }, allowAgent: '0' })).body.reason, 'bad_witness');
    assert.equal((await wallet.post('/wallet/session/witness', { r_s: '424242', witness: w, allowAgent: '0' })).status, 404);
    const sw = await wallet.post('/wallet/session/witness', { r_s: S1, witness: w, allowAgent: '0' });
    assert.equal(sw.status, 200, j(sw.body)); assert.equal(sw.body.ok, true);
    const rv2 = await wallet.post('/wallet/revalidate', { r_s: S1 }, { Origin: rp.origin });
    assert.equal(rv2.status, 200, j(rv2.body)); assert.equal(rv2.body.cacheHit, false, '재시작으로 캐시가 비어 재증명');
    assert.equal((await verify(rv2.body, S1)).ok, true);
    assert.equal(stateFile().includes('"witness"'), false, '증인은 파일에 쓰지 않는다');
  });

  // 2026-09-23 점검 B-I1: 재승인 동의 창의 "AI 에이전트 허용" 은 서비스가 보낸 값이 아니라 그 세션의 실제 값이어야 한다.
  // 팝업은 precheck 으로 세션 값을 받아 동의 창에 쓰고, /wallet/session/witness 가 어긋난 값을 409 로 막는다.
  await t('B-I1: precheck(r_s) 가 세션의 allowAgent 를 돌려주고, session/witness 는 다른 allowAgent 를 409 로 거절한다', async () => {
    const base = { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace };
    const pre = await wallet.post('/wallet/authorize/precheck', { ...base, r_s: S2 });
    assert.equal(pre.status, 200, j(pre.body)); assert.equal(pre.body.sessionAllowAgent, '1');
    const w = sim.consentLogin({ origin: info.origin, arid: info.arid, allowAgent: '1' });
    const bad = await wallet.post('/wallet/session/witness', { r_s: S2, witness: w, allowAgent: '0' });
    assert.equal(bad.status, 409, j(bad.body)); assert.equal(bad.body.reason, 'allow_agent_mismatch');
    // allowAgent 는 필수다 — 빼면 "문구와 세션이 어긋났는지" 를 판정할 수 없다(리뷰 Ruling 5).
    assert.equal((await wallet.post('/wallet/session/witness', { r_s: S2, witness: w })).status, 400);
    const good = await wallet.post('/wallet/session/witness', { r_s: S2, witness: w, allowAgent: '1' });
    assert.equal(good.status, 200, j(good.body));
    const none = await wallet.post('/wallet/authorize/precheck', { ...base, r_s: '424242' });
    assert.equal(none.status, 404, j(none.body)); assert.equal(none.body.reason, 'no_session');
    // 세션을 보는 precheck 도 인증서 검사를 먼저 거친다 — 남의 오리진이 세션의 allowAgent 를 물어볼 수 없다.
    const badCert = await wallet.post('/wallet/authorize/precheck', { ...base, origin: 'http://evil.example', r_s: S2 });
    assert.equal(badCert.status, 403, j(badCert.body)); assert.equal(badCert.body.reason, 'bad_rp_cert');
    // 제 인증서를 가진 **다른** 서비스도 남의 세션은 못 본다 — 세션의 arid 와 다르면 없는 것과 같이 404(리뷰 Minor 3).
    const other = await cia.registerRp('http://other-rp.example', 'other-rp');
    const otherArid = await wallet.post('/wallet/authorize/precheck', {
      arid: other.arid, origin: other.origin, cert_s: other.cert_s,
      pk_trace: { x: other.pk_trace.x.toString(), y: other.pk_trace.y.toString() }, r_s: S2,
    });
    assert.equal(otherArid.status, 404, j(otherArid.body)); assert.equal(otherArid.body.reason, 'no_session');
  });

  await t('tx/prepare + hardhat 계정이 EOA 로 전송 + tx/record 가 영수증을 파싱한다 (mask 1 + set(V7) → AttrGate claim)', async () => {
    const info = await rpInfo();
    assert.ok(info.attrGateAddress);
    const year = new Date().getUTCFullYear();
    // V7: AttrGate 는 set_sel==2 && set_root==allowedCountriesRoot 와 hi[0]+minAge<=올해 를 요구한다(국가 범위 공개가 아니다).
    const disclose = [{ lo: '0', hi: String(year - Number(info.predicates.minAge)) }, null, null, null];
    const set = { slot: 1, members: info.predicates.allowedCountries };
    assert.deepEqual(sim.consentDisclosure({ arid: info.arid, origin: info.origin, disclose, set, to: info.attrGateAddress, value: '0' }), { ok: true });
    const pre = await wallet.post('/wallet/tx/prepare', { r_s: S1, to: info.attrGateAddress, data: '0x4e71d92d', disclose, set });
    assert.equal(pre.status, 200, j(pre.body));
    assert.match(pre.body.walletAddr, /^0x[0-9a-fA-F]{40}$/);
    assert.equal(pre.body.factoryAddress, info.factoryAddress);
    assert.equal(pre.body.deployNeeded, true); assert.match(pre.body.deployCalldata, /^0x[0-9a-f]+$/);
    assert.equal(pre.body.nonce, '0');
    assert.equal(pre.body.disclosure.mask, '1');
    assert.equal(pre.body.disclosure.set.sel, '2');
    assert.equal(pre.body.disclosure.set.root, info.predicates.allowedCountriesRoot);
    assert.equal(typeof pre.body.timings.proveMs, 'number');
    const dec = decodeExecuteCalldata(pre.body.calldata);
    assert.equal(dec.payload.to.toLowerCase(), info.attrGateAddress.toLowerCase()); assert.equal(dec.payload.data, '0x4e71d92d'); assert.equal(dec.pub[14], '1');
    // MetaMask 대신 hardhat 계정 #1 이 사용자 EOA 로 두 트랜잭션을 순서대로 보낸다
    const eoa = await provider.getSigner(1);
    const deployTx = await eoa.sendTransaction({ to: pre.body.factoryAddress, data: pre.body.deployCalldata });
    await deployTx.wait();
    assert.notEqual(await provider.getCode(pre.body.walletAddr), '0x', '팩토리 deploy 로 지갑 코드가 생겼다');
    const tx = await eoa.sendTransaction({ to: pre.body.walletAddr, data: pre.body.calldata });
    await tx.wait();
    // 영수증 없는 해시는 202 pending
    const pending = await wallet.post('/wallet/tx/record', { r_s: S1, txHash: '0x' + '11'.repeat(32) });
    assert.equal(pending.status, 202, j(pending.body)); assert.equal(pending.body.pending, true);
    const rec = await wallet.post('/wallet/tx/record', { r_s: S1, txHash: tx.hash });
    assert.equal(rec.status, 200, j(rec.body));
    assert.equal(rec.body.ok, true); assert.equal(rec.body.txHash, tx.hash); assert.equal(rec.body.wallet, pre.body.walletAddr);
    assert.match(rec.body.gasUsed, /^[0-9]+$/); assert.equal(rec.body.executed.success, true); assert.equal(rec.body.executed.nonceUsed, '0');
    assert.equal(rec.body.disclosure.mask, '1'); assert.equal(rec.body.onchainDisclosure.mask, '1');
    assert.equal(rec.body.disclosure.set.sel, '2'); assert.equal(rec.body.onchainDisclosure.set.sel, '2');
    assert.equal(rec.body.onchainDisclosure.set.root, info.predicates.allowedCountriesRoot);
    assert.deepEqual(rec.body.onchainDisclosure.lo, ['0', '0', '0', '0']); assert.deepEqual(rec.body.onchainDisclosure.hi, [String(year - Number(info.predicates.minAge)), '0', '0', '0']);
    assert.equal(await attrGateAt(info.attrGateAddress, provider).claimed(pre.body.walletAddr), true);
    // 두 번째 prepare: 배포 끝났으니 deployNeeded=false, nonce 1, 같은 root·disclosure 라 캐시 히트
    const pre2 = await wallet.post('/wallet/tx/prepare', { r_s: S1, to: info.attrGateAddress, data: '0x4e71d92d', disclose, set });
    assert.equal(pre2.status, 200, j(pre2.body)); assert.equal(pre2.body.deployNeeded, false); assert.equal(pre2.body.deployCalldata, null); assert.equal(pre2.body.nonce, '1');
    assert.equal(pre2.body.cacheHit, true);
    assert.equal((await wallet.post('/wallet/tx/prepare', { r_s: S1, to: info.attrGateAddress, disclose: [{ lo: '0', hi: '1980' }, null, null, null] })).body.reason, 'disclosure_unsatisfiable');
    assert.equal((await wallet.post('/wallet/tx/record', { r_s: S1, txHash: 'nope' })).status, 400);
    // 배포 tx 처럼 이 지갑으로 가지 않은 트랜잭션은 실행 결과로 받지 않는다(리뷰 Minor)
    const notOurs = await wallet.post('/wallet/tx/record', { r_s: S1, txHash: deployTx.hash });
    assert.equal(notOurs.status, 409, j(notOurs.body)); assert.equal(notOurs.body.reason, 'not_our_tx');
    assert.equal((await wallet.post('/wallet/tx/record', { r_s: '424242', txHash: tx.hash })).status, 404);
  });

  await t('file 모드 전용 /wallet/tx 는 snap 모드에서 409 use_tx_prepare', async () => {
    const r = await wallet.post('/wallet/tx', { r_s: S1, to: (await rpInfo()).attrGateAddress });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'use_tx_prepare');
  });

  // V8 세션 폐기(설계 2026-09-24 §4). snap 모드의 서명 키는 세션의 **메모리** 증인에 있다 — Snap 은 Poseidon 이 없어
  // 동의(consentRevokeSession)만 하고 서명은 에이전트가 한다. 위 revalidate 케이스와 같은 재시작 패턴으로 증인 없는
  // 상태(409 needs_consent)와 증인 있는 상태(200)를 모두 지난다. 여기서 S1·S2 의 메모리 증인도 함께 사라지지만
  // 아래 케이스들은 그것을 쓰지 않는다.
  await t('V8 세션 폐기(snap 모드): 증인이 없으면 409 needs_consent, /wallet/session/witness 로 채우면 200 revoked 와 세션 삭제', async () => {
    const base = await loginBase();
    const l = await wallet.post('/wallet/login', { ...base, witness: sim.consentLogin({ origin: info.origin, arid: info.arid, allowAgent: '0' }) });
    assert.equal(l.status, 200, j(l.body));
    const rs = base.r_s;
    const c = (await wallet.get('/wallet/status')).body.sessions[rs];
    assert.ok(c, '폐기할 세션이 상태에 있어야 한다');
    // 페이지는 에이전트를 부르기 전에 Snap 동의를 받는다 — 거절이면 아예 부르지 않는다.
    assert.deepEqual(sim.consentRevokeSession({ arid: c.arid, issuedAt: c.issuedAt, maxHeight: c.max_height }, 'deny'), { denied: true });
    assert.ok((await wallet.get('/wallet/status')).body.sessions[rs], '동의 거절은 세션을 건드리지 않는다');
    // 재시작하면 메모리 증인이 사라진다 → sk_u 가 없어 409 needs_consent
    await stack.restartWallet();
    assert.deepEqual(sim.consentRevokeSession({ arid: c.arid, issuedAt: c.issuedAt, maxHeight: c.max_height }), { ok: true });
    const nc = await wallet.post('/wallet/session/revoke', { r_s: rs });
    assert.equal(nc.status, 409, j(nc.body)); assert.equal(nc.body.reason, 'needs_consent');
    assert.ok((await wallet.get('/wallet/status')).body.sessions[rs], 'needs_consent 는 세션을 지우지 않는다');
    // 팝업이 동의를 다시 받아 세션 증인을 채우면(재승인 경로) 서명이 되고 폐기된다
    const w = sim.consentLogin({ origin: info.origin, arid: info.arid, allowAgent: '0' });
    assert.equal((await wallet.post('/wallet/session/witness', { r_s: rs, witness: w, allowAgent: '0' })).status, 200);
    const r = await wallet.post('/wallet/session/revoke', { r_s: rs });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.revoked, true);
    assert.equal((await wallet.get('/wallet/status')).body.sessions[rs], undefined, '폐기 요청 뒤 지갑은 세션을 버린다');
    assert.equal((await wallet.post('/wallet/session/revoke', { r_s: rs })).status, 404, '이미 버린 세션은 no_session');
  });

  await t('consent 거절: 시뮬레이터가 denied 를 주면 페이지가 로그인하지 않는다(시뮬레이터 수준 검증)', async () => {
    const base = await loginBase();
    const before = Object.keys((await wallet.get('/wallet/status')).body.sessions).length;
    const w = sim.consentLogin({ origin: 'http://other.example', arid: info.arid, allowAgent: '0' }, 'deny');
    assert.deepEqual(w, { denied: true });
    assert.equal('http://other.example' in sim.state.consents, false, '거절은 consents 에 남지 않는다');
    assert.deepEqual(sim.consentDisclosure({}, 'deny'), { denied: true });
    // 페이지 로직: denied 면 /wallet/login 을 부르지 않고 RP 에 user_denied 를 돌려준다 — 세션 수가 그대로다
    if (!w.denied) await wallet.post('/wallet/login', { ...base, witness: w });
    assert.equal(Object.keys((await wallet.get('/wallet/status')).body.sessions).length, before);
  });

  await t('시뮬레이터: selfRevoke 는 uid·pwd, syncAttrs 는 changed 와 C_u 폐기, reset 은 상태를 비운다', async () => {
    assert.deepEqual(sim.selfRevoke({ pwd: 'password123' }), { uid: '12345', pwd: 'password123' });
    assert.deepEqual(sim.syncAttrs({ attrs: ['1990', '410', '2', '0'] }), { ok: true, changed: false });
    assert.deepEqual(sim.syncAttrs({ attrs: ['1991', '410', '2', '0'] }), { ok: true, changed: true });
    assert.equal(sim.getPublicInfo().hasUserCred, false, '속성이 바뀌면 옛 C_u 는 물린다');
    assert.deepEqual(sim.reset(), { ok: true });
    assert.equal(sim.getPublicInfo().registered, false);
  });
} finally {
  await stack.stop();
  provider.destroy();
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
// 다른 Mode 3 테스트와 같은 관례 — snarkjs 가 남기는 핸들 때문에 저절로 끝나지 않는다
process.exit(failed === 0 ? 0 : 1);
