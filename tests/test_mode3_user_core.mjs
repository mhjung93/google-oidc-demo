// tests/test_mode3_user_core.mjs — 브라우저 사용자 코어를 Node 에서(메모리 kv·진짜 snarkjs) 격리 IdP·RP 에 대고 돌린다. 등록 → 로그인(RP 검증) → 재검증 →
// 세션 요청 → 트랜잭션(RP 릴레이) → Selective disclosure proof(AttrGate) → 세션 폐기 → 잠금·해제 → 시연 가짜 증명·서명. :8545·build/mode3 필요. (chain)
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createMemKv } from '../mode3/user/core/kv_mem.js';
import { createUserCore } from '../mode3/user/core/user_core.js';
import { attrGateAt } from '../lib/mode3_onchain.js';
import * as snarkjs from 'snarkjs';

// 정적 서버는 dist 가 없으면 기동을 거부한다 — 단독 실행도 되게 여기서 만든다.
execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
const stack = await startIsolatedMode3Stack({ userMode: 'web', autoRelay: true });
const { wallet, rp, cia } = stack;
const provider = getProvider();
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
try {
  const config = (await wallet.get('/user/config')).body;
  const kv = createMemKv();
  const fullProve = { idp: (input, w, z) => snarkjs.groth16.fullProve(input, w, z), cred: (input, w, z) => snarkjs.groth16.fullProve(input, w, z) };
  const core = createUserCore({ kv, config, provider, canonProvider: provider, fullProve });
  // RP 는 active 가 된 뒤에 AttrGate 를 배포한다(mode3_rp.js activate(): 검증기 → ensureAttrGate) — 기동 직후 ~100ms 동안 attrGateAddress 가 null 이다.
  let info = (await rp.get('/api/mode3/rp_info')).body;
  for (let i = 0; i < 50 && !info.attrGateAddress; i++) { await sleep(200); info = (await rp.get('/api/mode3/rp_info')).body; }
  const PW = 'vault-pw-1';
  const loginBody = (ch, extra = {}) => ({ arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, allowAgent: '0', factoryAddress: info.factoryAddress, attrGateAddress: info.attrGateAddress, ...extra });
  const challenge = async () => (await rp.post('/api/mode3/challenge')).body;
  async function relayAndRecord(r_s, p) {
    const r = await rp.post(config.relayPath, { to: p.walletAddr, data: p.calldata }, { Origin: wallet.origin });
    assert.equal(r.status, 200, j(r.body));
    for (let i = 0; i < 60; i++) { const rec = await core.recordTx({ r_s, txHash: r.body.txHash }); if (rec.status !== 202) return { relay: r.body, rec }; await sleep(300); }
    throw new Error('영수증 없음');
  }
  let rs1;

  await t('미등록: status.registered=false, 금고 없음, login 은 409 not_registered', async () => {
    const s = await core.status(); assert.equal(s.status, 200); assert.equal(s.body.registered, false); assert.equal(core.vault.hasVault(), false);
    assert.equal((await core.login(loginBody(await challenge()), { verifiedOrigin: info.origin })).body.reason, 'not_registered');
    assert.deepEqual(await core.health(), { registered: false, hasCred: false, sessions: 0, rpCount: 0, txs: 0, disclosedTxs: 0 });
  });
  await t('등록 재시도: 첫 시도가 IdP 401 로 실패해도 금고는 남는다 — 다른 금고 비밀번호로 재시도하면 400 bad_password, 같은 비밀번호면 다음 케이스가 201', async () => {
    const r1 = await core.register({ uid: '12345', pwd: 'wrong-idp-pw', profile: { birthYear: '1990', country: 'KR' }, vaultPassword: PW });
    assert.ok(r1.status === 401 || r1.status === 502, j(r1)); assert.equal(r1.body.reason, 'register_failed');
    await core.vault.refresh(); assert.equal(core.vault.hasVault(), true);
    const r2 = await core.register({ uid: '12345', pwd: 'password123', profile: { birthYear: '1990', country: 'KR' }, vaultPassword: 'other-pw' });
    assert.equal(r2.status, 400, j(r2.body)); assert.equal(r2.body.reason, 'bad_password');
    assert.equal((await core.status()).body.registered, false);
  });
  await t('등록: 금고를 만들고 IdP 에 등록 — registration 은 평문(공개 부분), secrets 는 암호문, 비밀은 kv 어디에도 평문으로 없다', async () => {
    const r = await core.register({ uid: '12345', pwd: 'password123', profile: { birthYear: '1990', country: 'KR' }, vaultPassword: PW });
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.uid, '12345'); assert.deepEqual(r.body.attrs, ['1990', '410', '0', '0', '0', '0']);
    const reg = await kv.get('registration'); assert.equal(reg.uid, '12345'); assert.ok(!('s_u' in reg) && !('sk_u' in reg));
    const sec = await kv.get('secrets'); assert.ok(sec.iv && sec.ct);
    const secrets = await core.vault.readSecrets(); assert.match(secrets.sk_u, /^[0-9a-f]{64}$/);
    const all = {}; for (const k of await kv.keys()) all[k] = await kv.get(k);
    const dump = j(all); assert.ok(!dump.includes(secrets.s_u) && !dump.includes(secrets.sk_u), '비밀 평문이 kv 어디에도 없다');
    assert.equal((await core.register({ uid: '12345', pwd: 'password123', vaultPassword: PW })).body.reason, 'already_registered');
    assert.equal((await core.health()).registered, true);
  });
  await t('잠금: lock() 뒤 login 은 423 locked, 틀린 비밀번호 unlock false, 맞으면 true', async () => {
    await core.vault.lock(); assert.equal(core.vault.isUnlocked(), false);
    assert.equal((await core.login(loginBody(await challenge()), { verifiedOrigin: info.origin })).status, 423);
    assert.equal(await core.vault.unlock('wrong'), false); assert.equal(await core.vault.unlock(PW), true);
  });
  await t('로그인: π_IdP 발급 → π_RP → RP /api/mode3/login ok; 응답에 비밀·uid 없음; 세션 저장·proofCache 저장·세션키는 secrets 에만', async () => {
    const ch = await challenge(); rs1 = ch.r_s;
    const r = await core.login(loginBody(ch), { verifiedOrigin: info.origin, serviceName: 'zkONE', policy: { minAge: 19, allowedCountries: ['KR', 'JP'] } });   // serviceName·policy 는 표기용(2026-10-16)
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.issued, true); assert.ok(r.body.timings.proveMs > 0);
    for (const k of ['s_u', 'sk_u', 'blind_u', 'uid', 'sessionPrivKey', 'witness']) assert.ok(!j(r.body).includes(`"${k}"`), k);
    const v = await rp.post('/api/mode3/login', { proof: r.body.proof, publicSignals: r.body.publicSignals, sig: r.body.sig, r_s: ch.r_s });
    assert.equal(v.body.ok, true, j(v.body));
    const sessions = await kv.get('sessions'); const s = sessions[ch.r_s];
    assert.equal(s.origin, info.origin); assert.ok(s.proofCache?.proof); assert.ok(!('sessionPrivKey' in s)); assert.match(s.account, /^0x[0-9a-fA-F]{40}$/);
    assert.ok((await core.vault.readSecrets()).sessionKeys[ch.r_s]);
    assert.equal((await core.status()).body.sessions[ch.r_s].serviceName, 'zkONE'); assert.deepEqual((await core.status()).body.sessions[ch.r_s].allowedCountries, ['KR', 'JP']); assert.equal((await core.status()).body.sessions[ch.r_s].minAge, 19); assert.equal((await core.status()).body.sessions[ch.r_s].origin, info.origin);
    assert.deepEqual(await core.health(), { registered: true, hasCred: true, sessions: 1, rpCount: 1, txs: 0, disclosedTxs: 0 });
  });
  await t('로그아웃·대체(2026-10-16): RP /api/mode3/logout 뒤 status() 가 세션을 정리한다; 다시 로그인하면 같은 PPID 의 이전 세션을 RP 가 대체하고 지갑 목록도 하나만 남는다', async () => {
    const before = Object.keys((await core.status()).body.sessions); assert.equal(before.length, 1);
    assert.equal((await rp.post('/api/mode3/logout', { r_s: rs1 })).body.removed, true);
    assert.deepEqual((await rp.post('/api/mode3/sessions/check', { r_s: [rs1] }, { Origin: wallet.origin })).body.alive, { [rs1]: false });
    assert.equal(Object.keys((await core.status()).body.sessions).length, 0, '로그아웃된 세션은 목록에서 빠진다');
    // 2026-10-21: RP 가 모르는 세션(재시작 뒤 등)의 로그아웃도 묘비를 남긴다 — removed:false 지만 check 는 false
    const unknown = '123456789012345678901234567890';
    assert.equal((await rp.post('/api/mode3/logout', { r_s: unknown })).body.removed, false);
    assert.deepEqual((await rp.post('/api/mode3/sessions/check', { r_s: [unknown] }, { Origin: wallet.origin })).body.alive, { [unknown]: false });
    // 다시 로그인 두 번 → RP 에는 최신 하나만(같은 PPID 대체), 지갑도 정리 뒤 하나만
    const chA = await challenge(); const a = await core.login(loginBody(chA), { verifiedOrigin: info.origin, serviceName: 'zkONE' }); assert.equal(a.status, 200, j(a.body));
    assert.equal((await rp.post('/api/mode3/login', { proof: a.body.proof, publicSignals: a.body.publicSignals, sig: a.body.sig, r_s: chA.r_s })).body.ok, true);
    const chB = await challenge(); const b = await core.login(loginBody(chB), { verifiedOrigin: info.origin, serviceName: 'zkONE' }); assert.equal(b.status, 200, j(b.body));
    assert.equal((await rp.post('/api/mode3/login', { proof: b.body.proof, publicSignals: b.body.publicSignals, sig: b.body.sig, r_s: chB.r_s })).body.ok, true);
    const alive = (await rp.post('/api/mode3/sessions/check', { r_s: [chA.r_s, chB.r_s] }, { Origin: wallet.origin })).body.alive;
    assert.deepEqual(alive, { [chA.r_s]: false, [chB.r_s]: true });
    const after = Object.keys((await core.status()).body.sessions); assert.deepEqual(after, [BigInt(chB.r_s).toString()]);
    rs1 = chB.r_s;   // 이후 케이스는 이 세션으로
  });
  await t('로그인 거절: verifiedOrigin 이 인증서 오리진과 다르면 403 bad_rp_cert, 같은 r_s 재사용은 409 duplicate_session', async () => {
    assert.equal((await core.login(loginBody(await challenge()), { verifiedOrigin: 'http://evil.example' })).body.reason, 'bad_rp_cert');
    assert.equal((await core.login(loginBody({ r_s: rs1, r_rp: '1' }), { verifiedOrigin: info.origin })).body.reason, 'duplicate_session');
  });
  await t('재검증: 캐시 히트(cacheHit:true) → RP ok; 다른 오리진·다른 arid 로는 404 no_session', async () => {
    const r = await core.revalidate({ r_s: rs1, origin: info.origin }); assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.cacheHit, true);
    assert.equal((await rp.post('/api/mode3/revalidate', { proof: r.body.proof, publicSignals: r.body.publicSignals, sig: r.body.sig, r_s: rs1 })).body.ok, true);
    assert.equal((await core.revalidate({ r_s: rs1, origin: 'http://other.example' })).status, 404);
    assert.equal((await core.revalidate({ r_s: rs1, origin: info.origin, arid: String(BigInt(info.arid) + 1n) })).status, 404);
  });
  await t('skipSync 재검증: 새로 연 페이지(팝업 — lastSync 없음)도 저장된 proofCache 의 π 를 동기화 없이 그대로 → RP ok; proofCache 가 없으면 409 no_cached_proof', async () => {
    const fresh = await core.revalidate({ r_s: rs1, origin: info.origin }); assert.equal(fresh.status, 200, j(fresh.body));
    const popup = createUserCore({ kv, config, provider, canonProvider: provider, fullProve });   // 같은 kv 위의 새 코어 = 새 페이지
    const r = await popup.revalidate({ r_s: rs1, origin: info.origin, skipSync: true });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.cacheHit, true); assert.equal(r.body.root, fresh.body.root); assert.equal(r.body.regRoot, fresh.body.regRoot);
    assert.equal((await rp.post('/api/mode3/revalidate', { proof: r.body.proof, publicSignals: r.body.publicSignals, sig: r.body.sig, r_s: rs1 })).body.ok, true);
    const sessions = await kv.get('sessions'); const s = sessions[rs1];
    await kv.set('sessions', { ...sessions, [rs1]: { ...s, proofCache: null } });
    try { const n = await popup.revalidate({ r_s: rs1, origin: info.origin, skipSync: true }); assert.equal(n.status, 409, j(n.body)); assert.equal(n.body.reason, 'no_cached_proof'); }
    finally { await kv.set('sessions', { ...(await kv.get('sessions')), [rs1]: s }); }   // 뒤 케이스를 위해 그대로 되돌린다
  });
  await t('세션 요청: 세션키 서명 → RP /api/mode3/request ok', async () => {
    const r = await core.request({ r_s: rs1, body: 'hello', origin: info.origin }); assert.equal(r.status, 200);
    assert.equal((await rp.post('/api/mode3/request', { r_s: rs1, body: 'hello', sig: r.body.sig })).body.ok, true);
    // 2026-10-21: 'balance' 는 시연용 장부와 온체인 계정(PPID 주소) 잔액을 함께 돌려준다 — 거래 없는 RP 상호작용
    const b = await core.request({ r_s: rs1, body: 'balance', origin: info.origin }); assert.equal(b.status, 200);
    const q = (await rp.post('/api/mode3/request', { r_s: rs1, body: 'balance', sig: b.body.sig })).body; assert.equal(q.ok, true, j(q));
    assert.equal(q.balance.ledger.KRW, '1,000,000'); assert.equal(q.balance.onchain, undefined, '온체인 계정 잔액은 내지 않는다(2026-10-21)');
  });
  await t('트랜잭션: prepareTx → RP 릴레이(배포 포함) → recordTx 영수증 파싱 ok, txs 기록·health 카운터', async () => {
    // 체크섬(EIP-55)이 틀린 대소문자 입력도 받는다(2026-10-16) — 바이트가 같은 주소다
    const bad = await core.prepareTx({ r_s: rs1, to: '0x000000000000000000000000000000000000DEAD', value: '0', data: '0x' }); assert.equal(bad.status, 200, j(bad.body));
    const p = await core.prepareTx({ r_s: rs1, to: '0x000000000000000000000000000000000000dEaD', value: '0', data: '0x' });
    assert.equal(p.status, 200, j(p.body)); assert.equal(p.body.deployNeeded, true);
    const { relay, rec } = await relayAndRecord(rs1, p.body);
    assert.equal(relay.deployed, true); assert.equal(rec.status, 200, j(rec.body)); assert.equal(rec.body.ok, true); assert.equal(rec.body.executed.success, true);
    assert.equal((await kv.get('txs')).length, 1); assert.equal((await core.health()).txs, 1);
    const tx = (await core.status()).body.txs[0]; assert.equal(tx.txHash, relay.txHash); assert.equal(tx.to.toLowerCase(), '0x000000000000000000000000000000000000dead'); assert.equal(tx.value, '0'); assert.equal(tx.serviceName, 'zkONE'); assert.equal(tx.ok, true);   // 보낸 트랜잭션 목록(2026-10-16)
  });
  await t('Selective disclosure proof: 나이·국가 집합 조건을 실어 AttrGate.claim → claimed(account) true, disclosedTxs 1', async () => {
    const year = new Date().getUTCFullYear();
    const p = await core.prepareTx({ r_s: rs1, to: info.attrGateAddress, value: '0', data: '0x4e71d92d', disclose: [{ lo: '1900', hi: String(year - Number(info.predicates.minAge)) }], set: { slot: 1, members: info.predicates.allowedCountries } });
    assert.equal(p.status, 200, j(p.body)); assert.equal(p.body.cacheHit, false, '술어가 있으면 새 증명');
    const { rec } = await relayAndRecord(rs1, p.body); assert.equal(rec.body.ok, true);
    assert.equal(await attrGateAt(info.attrGateAddress, provider).claimed(p.body.walletAddr), true);
    assert.equal((await core.health()).disclosedTxs, 1);
  });
  await t('불만족 조건은 증명 전에 400 disclosure_unsatisfiable; 모르는 세션은 404', async () => {
    assert.equal((await core.prepareTx({ r_s: rs1, to: '0x000000000000000000000000000000000000dEaD', disclose: [{ lo: '2000', hi: '2001' }] })).body.reason, 'disclosure_unsatisfiable');
    assert.equal((await core.prepareTx({ r_s: '7', to: '0x000000000000000000000000000000000000dEaD' })).status, 404);
  });
  await t('시연 fake_proof: 다음 로그인의 증명만 바꿔친다 → RP bad_proof, demo 플래그; 그 다음 로그인은 정상', async () => {
    assert.equal((await core.demoOverride({ scope: 'fake_proof' })).status, 200);
    const ch = await challenge(); const r = await core.login(loginBody(ch), { verifiedOrigin: info.origin });
    assert.equal(r.status, 200); assert.equal(r.body.demo, 'override:fake_proof');
    assert.equal((await rp.post('/api/mode3/login', { proof: r.body.proof, publicSignals: r.body.publicSignals, sig: r.body.sig, r_s: ch.r_s })).body.reason, 'bad_proof');
    const ch2 = await challenge(); const r2 = await core.login(loginBody(ch2), { verifiedOrigin: info.origin });
    assert.equal((await rp.post('/api/mode3/login', { proof: r2.body.proof, publicSignals: r2.body.publicSignals, sig: r2.body.sig, r_s: ch2.r_s })).body.ok, true);
  });
  await t('시연 fake_sig: 다음 트랜잭션 서명만 가짜 → 릴레이 estimateGas 가 BadSignature 로 거절(relay_gas)', async () => {
    assert.equal((await core.demoOverride({ scope: 'fake_sig' })).status, 200);
    const p = await core.prepareTx({ r_s: rs1, to: '0x000000000000000000000000000000000000dEaD' }); assert.equal(p.body.demo, 'override:fake_sig');
    const r = await rp.post(config.relayPath, { to: p.body.walletAddr, data: p.body.calldata }, { Origin: wallet.origin });
    assert.equal(r.status, 400); assert.equal(r.body.reason, 'relay_gas'); assert.match(String(r.body.detail), /BadSignature/);
  });
  await t('세션 폐기: IdP 에 서명 요청 → 세션·세션키·캐시 삭제, 다음 게시 뒤 재검증은 세션 없음', async () => {
    const r = await core.revokeSession({ r_s: rs1 }); assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.revoked, true);
    assert.equal(r.body.rpNotified, true, '2026-10-21: RP 에 로그아웃을 알린다'); assert.ok(!(await rp.get('/api/mode3/sessions')).body.sessions.some((x) => x.r_s === `${rs1.slice(0, 8)}…`), 'RP 세션 목록에서 빠진다');
    assert.equal((await kv.get('sessions'))[rs1], undefined); assert.equal((await core.vault.readSecrets()).sessionKeys[rs1], undefined);
    assert.equal((await core.revalidate({ r_s: rs1, origin: info.origin })).status, 404);
  });
  await t('속성 변경: 바뀌면 userCred·세션·캐시를 버린다(다음 로그인이 새 C_u), 같으면 changed:false', async () => {
    const same = await core.saveProfile({ birthYear: '1990', country: 'KR' }); assert.equal(same.body.changed, false);
    const diff = await core.saveProfile({ birthYear: '1991', country: 'KR' }); assert.equal(diff.body.changed, true);
    assert.equal((await kv.get('registration')).userCred, null); assert.deepEqual(await kv.get('sessions'), {});
    const ch = await challenge(); const r = await core.login(loginBody(ch), { verifiedOrigin: info.origin }); assert.equal(r.status, 200, j(r.body)); assert.ok(r.body.timings.userCredMs > 0, '새 C_u');
  });
  await t('비밀번호 변경·자동 잠금: changePassword 뒤 옛 비밀번호는 false, 새 것은 true; ttl 이 지나면 key() 가 null', async () => {
    assert.equal(await core.vault.changePassword(PW, 'pw-2'), true); await core.vault.lock();
    assert.equal(await core.vault.unlock(PW), false); assert.equal(await core.vault.unlock('pw-2'), true);
    const u = await kv.get('unlock'); await kv.set('unlock', { ...u, expiresAt: Date.now() - 1 });
    assert.equal(await core.vault.key(), null); assert.equal(await kv.get('unlock'), undefined);
  });
  await t('wipe(): 전부 지운다 — 금고 없음·미등록', async () => { await core.wipe(); assert.equal(core.vault.hasVault(), false); assert.equal((await core.status()).body.registered, false); });
  await t('자동 금고(2026-10-16): vaultPassword 없이 등록하면 비밀번호 없는 금고가 생기고 늘 열려 있다 — lock() 은 거절, changePassword 는 false, 로그인은 된다', async () => {
    // IdP 쪽 12345 는 위에서 이미 등록됐다 → 다른 데모 계정(alice/67890)으로.
    const r = await core.register({ uid: '67890', pwd: 'alicepw', profile: { birthYear: '1992', country: 'KR' } });
    assert.equal(r.status, 201, j(r.body));
    assert.equal(core.vault.hasVault(), true); assert.equal(core.vault.isAuto(), true); assert.equal(core.vault.isUnlocked(), true);
    assert.equal(await core.vault.lock(), false); assert.ok(await core.vault.key(), '잠그기 뒤에도 키가 있다');
    assert.equal(await core.vault.changePassword('x', 'yyyyyyyy'), false);
    const u = await kv.get('unlock'); assert.equal(u.expiresAt, null); assert.equal((await kv.get('meta')).mode, 'auto');
    const lg = await core.login(loginBody(await challenge()), { verifiedOrigin: info.origin }); assert.equal(lg.status, 200, j(lg.body));
  });
  await t('로그인 조건 강제(2026-10-21): MODE3_REQUIRE_DISCLOSURE=1 로 재기동한 RP 는 술어 없는 로그인을 predicate_unmet 으로 거절하고, 국가·나이 술어가 있는 로그인은 받는다', async () => {
    await stack.restartRp({ MODE3_REQUIRE_DISCLOSURE: '1' });
    const info2 = (await rp.get('/api/mode3/rp_info')).body; assert.equal(info2.requireDisclosure, true);
    const ch = await challenge(); const a = await core.login(loginBody(ch), { verifiedOrigin: info.origin }); assert.equal(a.status, 200, j(a.body));
    const bad = (await rp.post('/api/mode3/login', { proof: a.body.proof, publicSignals: a.body.publicSignals, sig: a.body.sig, r_s: ch.r_s })).body;
    assert.equal(bad.ok, false); assert.equal(bad.reason, 'predicate_unmet');
    const year = new Date().getUTCFullYear();
    const ch2 = await challenge();
    const b = await core.login(loginBody(ch2, { disclose: [{ lo: String(info2.predicates.birthYearMin ?? '1900'), hi: String(year - Number(info2.predicates.minAge)) }, null, null, null], set: { slot: 1, members: info2.predicates.allowedCountries } }), { verifiedOrigin: info.origin });
    assert.equal(b.status, 200, j(b.body));
    const ok = (await rp.post('/api/mode3/login', { proof: b.body.proof, publicSignals: b.body.publicSignals, sig: b.body.sig, r_s: ch2.r_s })).body;
    assert.equal(ok.ok, true, j(ok)); assert.ok(ok.disclosure?.set, '세션에 국가 집합 공개가 실린다');
  });
} finally { await stack.stop(); }
process.exit(fails ? 1 : 0);
