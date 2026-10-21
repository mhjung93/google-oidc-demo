// tests/test_mode3_user_core_oidc.mjs — 사용자 코어의 Google(OIDC 래퍼) 등록·자기 폐기(스펙 2026-10-16 §3.1·§3.3). 격리 web 스택 + 발급자 스텁, Node 에서 메모리 kv. (chain)
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createMemKv } from '../mode3/user/core/kv_mem.js';
import { createUserCore } from '../mode3/user/core/user_core.js';
import { uidOf, newRevokeNonce } from '../lib/mode3_oidc_nonce.js';
import * as snarkjs from 'snarkjs';

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
const stack = await startIsolatedMode3Stack({ userMode: 'web', autoRelay: true, oidc: true });
const { wallet, rp, oidc: stub } = stack;
const provider = getProvider();
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
try {
  const config = (await wallet.get('/user/config')).body;
  const kv = createMemKv();
  const fullProve = { idp: (i, w, z) => snarkjs.groth16.fullProve(i, w, z), cred: (i, w, z) => snarkjs.groth16.fullProve(i, w, z) };
  const core = createUserCore({ kv, config, provider, canonProvider: provider, fullProve });
  let info = (await rp.get('/api/mode3/rp_info')).body;
  for (let i = 0; i < 50 && !info.attrGateAddress; i++) { await new Promise((r) => setTimeout(r, 200)); info = (await rp.get('/api/mode3/rp_info')).body; }   // RP 등록 승인·팩토리 배포를 기다린다(test_mode3_user_core.mjs 와 같다)
  assert.ok(info.attrGateAddress, 'RP 의 AttrGate 가 배포되지 않았다');
  const PW = 'vault-oidc';
  const SUB = 'google-user-77';
  await t('prepareRegistration: nonce 가 "reg:"+hex64 이고 pk_u 를 돌려준다; 다시 부르면 새 재료', async () => {
    const a = await core.prepareRegistration(); assert.match(a.nonce, /^reg:[0-9a-f]{64}$/); assert.match(a.pk_u.x, /^[0-9]+$/);
    const b = await core.prepareRegistration(); assert.notEqual(a.nonce, b.nonce);
  });
  await t('completeRegistration: 스텁 토큰(nonce = prepare 의 것) → 201, uid = uidOf(provider, sub), registration.provider = 스텁 provider, 비밀은 금고에만', async () => {
    const p = await core.prepareRegistration();
    const idToken = await stub.mint({ sub: SUB, nonce: p.nonce });
    const r = await core.completeRegistration({ idToken, profile: { birthYear: '1990', country: 'KR' }, vaultPassword: PW });
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.uid, uidOf(stub.provider, SUB)); assert.equal(r.body.provider, stub.provider);
    const reg = await kv.get('registration'); assert.equal(reg.provider, stub.provider); assert.equal(reg.uid, r.body.uid); assert.ok(!('s_u' in reg) && !('sk_u' in reg));
    assert.equal((await core.status()).body.provider, stub.provider);
  });
  await t('nonce 가 다른 토큰·pending 없음·토큰 형식 오류의 사유', async () => {
    assert.equal((await core.completeRegistration({ idToken: await stub.mint({ sub: 'x', nonce: 'reg:' + 'f'.repeat(64) }) })).body.reason, 'already_registered');   // 이미 등록됨이 먼저
    await core.wipe();
    assert.equal((await core.completeRegistration({ idToken: 'a.b.c', vaultPassword: PW })).body.reason, 'no_pending_registration');
    const p = await core.prepareRegistration();
    assert.equal((await core.completeRegistration({ idToken: await stub.mint({ sub: 'x', nonce: 'reg:' + 'f'.repeat(64) }), vaultPassword: PW })).body.reason, 'oidc_nonce_mismatch');
    const bad = await core.completeRegistration({ idToken: 'not-a-jwt', vaultPassword: PW });
    assert.equal(bad.status, 400); assert.equal(bad.body.reason, 'oidc_invalid');
    // 서명을 변조한 토큰(payload·nonce 는 그대로): IdP 가 401 oidc_invalid → 사유·상태가 그대로 온다(IdP 발 oidc_* 통과 분기).
    // 서명 조각의 끝 글자는 패딩 비트만 바뀌어 같은 바이트로 디코드될 수 있어 첫 글자를 바꾼다.
    const [h, pl, sg] = (await stub.mint({ sub: SUB, nonce: p.nonce })).split('.');
    const forged = await core.completeRegistration({ idToken: `${h}.${pl}.${sg[0] === 'A' ? 'B' : 'A'}${sg.slice(1)}`, vaultPassword: PW });
    assert.equal(forged.status, 401, j(forged.body)); assert.equal(forged.body.reason, 'oidc_invalid');
    // 같은 sub 로 다시 등록(새 재료): IdP 의 409 는 register_failed 로 감싸져 상태 409 로 온다
    const again = await core.completeRegistration({ idToken: await stub.mint({ sub: SUB, nonce: p.nonce }), vaultPassword: PW });
    assert.equal(again.status, 409, j(again.body)); assert.equal(again.body.reason, 'register_failed');
  });
  await t('Google 로 등록한 계정으로 RP 로그인이 된다(증명 경로 불변)', async () => {
    await core.wipe();
    const p = await core.prepareRegistration();
    const r = await core.completeRegistration({ idToken: await stub.mint({ sub: 'google-user-78', nonce: p.nonce }), profile: { birthYear: '1991', country: 'KR' }, vaultPassword: PW });
    assert.equal(r.status, 201, j(r.body));
    const ch = (await rp.post('/api/mode3/challenge')).body;
    // 2026-10-16: Google 로 만든 계정은 로그인(발급)마다 그 로그인에 묶인 토큰이 필요하다 — loginPrepare 의 nonce 로 받는다.
    const prep = await core.loginPrepare({ arid: info.arid, r_rp: ch.r_rp });
    const lg = await core.login({ arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, allowAgent: '0', factoryAddress: info.factoryAddress, attrGateAddress: info.attrGateAddress }, { verifiedOrigin: info.origin, idToken: await stub.mint({ sub: 'google-user-78', nonce: prep.body.nonce }) });
    assert.equal(lg.status, 200, j(lg.body));
    assert.equal((await rp.post('/api/mode3/login', { proof: lg.body.proof, publicSignals: lg.body.publicSignals, sig: lg.body.sig, r_s: ch.r_s })).body.ok, true);
  });
  await t('selfRevokeWithIdToken: 다른 Google 계정(sub)의 revoke 토큰 → 403 uid_mismatch(IdP 를 부르지 않는다) — 그 계정·이 지갑의 계정 모두 살아 있다', async () => {
    assert.equal((await core.selfRevokeWithIdToken({ idToken: 'not-a-jwt' })).body.reason, 'oidc_invalid');
    // SUB 는 앞 케이스에서 IdP 에 등록된 계정이다 — 지갑이 막지 않으면 IdP 가 200 으로 폐기한다(되돌릴 수 없다).
    const r = await core.selfRevokeWithIdToken({ idToken: await stub.mint({ sub: SUB, nonce: newRevokeNonce() }) });
    assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.reason, 'uid_mismatch');
    const accounts = (await stack.cia.adminGet('/cia/accounts')).body.accounts;
    for (const sub of [SUB, 'google-user-78']) {
      const a = accounts.find((x) => x.uid === uidOf(stub.provider, sub));
      assert.ok(a, sub); assert.equal(a.disabled, false, sub);
    }
  });
  await t('selfRevokeWithIdToken: revoke 토큰 → 200, 그 뒤 로그인은 403 account_disabled; 등록 토큰으로는 400', async () => {
    const regTok = await stub.mint({ sub: 'google-user-78', nonce: (await core.prepareRegistration()).nonce });
    assert.equal((await core.selfRevokeWithIdToken({ idToken: regTok })).status, 400);
    const r = await core.selfRevokeWithIdToken({ idToken: await stub.mint({ sub: 'google-user-78', nonce: newRevokeNonce() }) });
    assert.equal(r.status, 200, j(r.body));
    const ch = (await rp.post('/api/mode3/challenge')).body;
    const lg = await core.login({ arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, allowAgent: '0', factoryAddress: info.factoryAddress, attrGateAddress: info.attrGateAddress }, { verifiedOrigin: info.origin });
    assert.equal(lg.status, 403, j(lg.body)); assert.equal(lg.body.reason, 'account_disabled');
  });
  await t('데모 계정 register 는 그대로이고 provider demo 를 저장한다', async () => {
    await core.wipe();
    const r = await core.register({ uid: '12345', pwd: 'password123', vaultPassword: PW }); assert.equal(r.status, 201, j(r.body));
    assert.equal((await kv.get('registration')).provider, 'demo'); assert.equal((await core.status()).body.provider, 'demo');
  });
  await t('RP 로그인 흐름의 Google(2026-10-16): 미등록 브라우저 → loginPrepare(nonce) → 토큰 → login({ idToken }) 이 IdP 에 암묵 등록 + 발급 → RP 로그인 ok; 토큰 없는 재로그인은 oidc_required; nonce 가 다른 토큰은 oidc_nonce_mismatch', async () => {
    await core.wipe();
    const SUBG = 'g-login-77';
    const ch1 = (await rp.post('/api/mode3/challenge')).body;
    const body1 = { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch1.r_s, r_rp: ch1.r_rp, allowAgent: '0', factoryAddress: info.factoryAddress, attrGateAddress: info.attrGateAddress };
    const prep = await core.loginPrepare({ arid: info.arid, r_rp: ch1.r_rp });
    assert.equal(prep.status, 200, j(prep.body)); assert.equal(prep.body.registered, false); assert.match(prep.body.nonce, /^issue:[0-9a-f]{64}$/);
    const tok = await stub.mint({ sub: SUBG, nonce: prep.body.nonce });
    const lg = await core.login(body1, { verifiedOrigin: info.origin, serviceName: 'zkONE', idToken: tok });
    assert.equal(lg.status, 200, j(lg.body));
    assert.equal((await rp.post('/api/mode3/login', { proof: lg.body.proof, publicSignals: lg.body.publicSignals, sig: lg.body.sig, r_s: ch1.r_s })).body.ok, true);
    const st = (await core.status()).body;
    assert.equal(st.registered, true); assert.equal(st.provider, stub.provider); assert.equal(st.uid, uidOf(stub.provider, SUBG)); assert.ok(Number.isInteger(st.slot) && st.slot >= 0, j(st.slot));
    const reg = await kv.get('registration'); assert.equal(reg.pendingIdp, false); assert.ok(!('s_u' in reg) && !('sk_u' in reg));
    // 토큰 없이 다시 로그인 → 래퍼가 거절(oidc_required)
    const ch2 = (await rp.post('/api/mode3/challenge')).body;
    const body2 = { ...body1, r_s: ch2.r_s, r_rp: ch2.r_rp };
    const noTok = await core.login(body2, { verifiedOrigin: info.origin });
    assert.equal(noTok.status, 401, j(noTok.body)); assert.equal(noTok.body.reason, 'oidc_required');
    // nonce 가 다른 토큰(다른 로그인의 것) → oidc_nonce_mismatch
    const bad = await core.login(body2, { verifiedOrigin: info.origin, idToken: tok });
    assert.equal(bad.status, 400, j(bad.body)); assert.equal(bad.body.reason, 'oidc_nonce_mismatch');
    // 이 로그인의 nonce 로 받은 토큰 → ok(같은 PPID)
    const prep2 = await core.loginPrepare({ arid: info.arid, r_rp: ch2.r_rp }); assert.equal(prep2.body.registered, true);
    const ok2 = await core.login(body2, { verifiedOrigin: info.origin, idToken: await stub.mint({ sub: SUBG, nonce: prep2.body.nonce }) });
    assert.equal(ok2.status, 200, j(ok2.body));
    const v2 = await rp.post('/api/mode3/login', { proof: ok2.body.proof, publicSignals: ok2.body.publicSignals, sig: ok2.body.sig, r_s: ch2.r_s }); assert.equal(v2.body.ok, true, j(v2.body));
    const sessions = (await core.status()).body.sessions; const ppids = new Set(Object.values(sessions).map((s) => s.PPID)); assert.equal(ppids.size, 1, 'Google 계정의 PPID 는 로그인마다 같다');
  });
} finally { await stack.stop(); }
process.exit(fails ? 1 : 0);
