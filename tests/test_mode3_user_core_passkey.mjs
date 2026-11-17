// tests/test_mode3_user_core_passkey.mjs — 웹 코어의 passkey-web 경로(스펙 2026-11-17-mode3-passkey-web, 계획 Task 5)를 Node 에서(메모리 kv·진짜 snarkjs)
// 격리 IdP(CIA_ISSUE_AUTH=code)·RP 에 대고 돌린다. 패스키는 대역(derive 호출 수를 센다). 패스키 연결 → salt 보기(보관분) → 등록 코드로 등록 →
// 발급 코드로 로그인 → 다른 탭·보관 만료·withSalt → 다른 패스키 → 속성 기록 동기화 → wipe → 계정 복구(restored). :8545·build/mode3 필요. (chain)
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createMemKv } from '../mode3/user/core/kv_mem.js';
import { createUserCore } from '../mode3/user/core/user_core.js';
import { randomScalar, auidOf } from '../lib/mode3_credential.js';
import * as snarkjs from 'snarkjs';

// 정적 서버는 dist 가 없으면 기동을 거부한다 — 단독 실행도 되게 여기서 만든다.
execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
// passkey-web 정적 서버는 IP 오리진으로 뜨지 않는다(WebAuthn RP ID 제약) — 지갑 자리를 localhost 로 띄운다.
const stack = await startIsolatedMode3Stack({ userMode: 'web', walletHost: 'localhost', walletEnv: { MODE3_WALLET_SECRETS: 'passkey-web' }, ciaEnv: { CIA_ISSUE_AUTH: 'code' }, autoRelay: true });
const { wallet, rp, cia } = stack;
const provider = getProvider();
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
try {
  const config = (await wallet.get('/user/config')).body;
  assert.equal(config.secrets, 'passkey-web'); assert.equal(config.passkeyHoldSeconds, 600);
  const kv = createMemKv();
  const fullProve = { idp: (input, w, z) => snarkjs.groth16.fullProve(input, w, z), cred: (input, w, z) => snarkjs.groth16.fullProve(input, w, z) };
  const SALT = randomScalar().toString(), CID = 'Y2lkLWE';
  const AUID = (await auidOf({ s_u: BigInt(SALT) })).toString();
  let calls = 0;
  let deriveFn = async () => ({ credentialId: CID, s_u: SALT });
  const passkey = { derive: async (a) => { calls++; return deriveFn(a); } };
  let skew = 0; const now = () => Date.now() + skew;
  const mk = (cfg = config) => createUserCore({ kv, config: cfg, provider, canonProvider: provider, fullProve, now, passkey });
  const coreA = mk(), coreB = mk();   // 같은 kv 를 쓰는 두 탭
  let info = (await rp.get('/api/mode3/rp_info')).body;
  for (let i = 0; i < 50 && !info.attrGateAddress; i++) { await sleep(200); info = (await rp.get('/api/mode3/rp_info')).body; }
  const loginBody = (ch) => ({ arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, allowAgent: '0', factoryAddress: info.factoryAddress, attrGateAddress: info.attrGateAddress });
  const challenge = async () => (await rp.post('/api/mode3/challenge')).body;
  const authCode = async (purpose) => { const r = await cia.post('/cia/auth/code', { uid: '12345', pwd: 'password123', auid: AUID, purpose }); assert.equal(r.status, 200, j(r.body)); return r.body.code; };
  const loginRp = async (core, code) => {
    const ch = await challenge(); const r = await core.login(loginBody(ch), { verifiedOrigin: info.origin, authCode: code });
    if (r.status !== 200) return { r, ch };
    const v = await rp.post('/api/mode3/login', { proof: r.body.proof, publicSignals: r.body.publicSignals, sig: r.body.sig, r_s: ch.r_s });
    return { r, ch, v };
  };
  const dumpKv = async () => { const all = {}; for (const k of await kv.keys()) all[k] = await kv.get(k); return j(all); };
  let reg201, rs1, slot0, ppid0;

  await t('생성자: passkey-web 인데 passkey.derive 가 없으면 던진다', async () => {
    assert.throws(() => createUserCore({ kv: createMemKv(), config, provider, canonProvider: provider, fullProve }));
  });
  await t('설정 전: showSalt 409 passkey_setup_required, register·recoveryCode·loginPrepare 409 passkey_mode', async () => {
    const s = await coreA.showSalt(); assert.equal(s.status, 409, j(s.body)); assert.equal(s.body.reason, 'passkey_setup_required');
    for (const r of [await coreA.register({ uid: '12345', pwd: 'password123' }), await coreA.recoveryCode(), await coreA.loginPrepare({ arid: '1', r_rp: '1', allowAgent: '0' }), await coreA.recover({ uid: '12345', code: 'zkd1.x' }), await coreA.completeRegistration({ idToken: 'a.b.c' })]) {
      assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'passkey_mode');
    }
    const lg = await coreA.login(loginBody({ r_s: '5', r_rp: '5' }), { verifiedOrigin: info.origin, idToken: 'a.b.c', n: '1' }); assert.equal(lg.status, 409); assert.equal(lg.body.reason, 'passkey_mode');
    await assert.rejects(coreA.prepareRegistration(), (e) => e.reason === 'passkey_mode');
    assert.equal(calls, 0);
  });
  await t('passkeyConnect: 자동 금고·credential 저장·보관; 다른 credential 409 passkey_already_set', async () => {
    assert.equal((await coreA.passkeyConnect({ credentialId: 'not base64url!', s_u: SALT })).body.reason, 'bad_credential_id');
    const r = await coreA.passkeyConnect({ credentialId: CID, s_u: SALT }); assert.equal(r.status, 200, j(r.body)); assert.deepEqual(r.body, { ok: true, held: true });
    await coreA.vault.refresh(); assert.equal(coreA.vault.isAuto(), true);
    assert.equal((await kv.get('passkey')).credentialId, CID);
    const st = await coreA.passkeyState(); assert.equal(st.status, 200); assert.equal(st.body.credentialId, CID); assert.equal(typeof st.body.createdAt, 'number'); assert.ok(st.body.heldUntil > now(), j(st.body));
    const o = await coreA.passkeyConnect({ credentialId: 'b3RoZXI', s_u: SALT }); assert.equal(o.status, 409); assert.equal(o.body.reason, 'passkey_already_set');
    assert.equal(calls, 0);
  });
  await t('showSalt·passkeyAuid 는 보관분 — derive 0회', async () => {
    const s = await coreA.showSalt(); assert.equal(s.status, 200, j(s.body)); assert.equal(s.body.s_u, SALT);
    const a = await coreB.passkeyAuid(); assert.equal(a.status, 200, j(a.body)); assert.equal(a.body.auid, AUID); assert.ok(!('s_u' in a.body));
    assert.equal(calls, 0);
  });
  await t('기록 salt·auid 불일치는 IdP 를 부르지 않는다', async () => {
    const code = await authCode('register');
    const a = await coreA.registerWithCode({ uid: '12345', code, recordSalt: '7' }); assert.equal(a.status, 409, j(a.body)); assert.equal(a.body.reason, 'attr_record_salt_mismatch');
    const b = await coreA.registerWithCode({ uid: '12345', code, auid: '1' + AUID }); assert.equal(b.status, 409, j(b.body)); assert.equal(b.body.reason, 'register_auid_mismatch');
    assert.equal(await kv.get('registration'), undefined);
    reg201 = await coreA.registerWithCode({ uid: '12345', code, auid: AUID, recordSalt: SALT, profile: { birthYear: '1990', country: 'KR' } });   // 같은 코드 — 타지 않았다
    assert.equal(reg201.status, 201, j(reg201.body));
    slot0 = reg201.body.slot;
  });
  await t('코드 등록 201: issue_code·secrets.s_u null·seed null·평문 salt 없음', async () => {
    assert.equal(typeof reg201.body.issue_code, 'string'); assert.equal(reg201.body.auid, AUID); assert.equal(reg201.body.uid, '12345'); assert.ok(!('restored' in reg201.body));
    const sec = await coreA.vault.readSecrets(); assert.equal(sec.s_u, null); assert.equal(sec.seed, null);
    assert.ok(!(await dumpKv()).includes(SALT), '평문 salt 가 kv 어디에도 없다');
    assert.equal((await coreA.passkeyDisconnect()).body.reason, 'registered');
    const again = await coreA.registerWithCode({ uid: '12345', code: 'x' }); assert.equal(again.status, 409); assert.equal(again.body.reason, 'already_registered');
  });
  await t('로그인: issue_code 로 200 → RP ok; 코드 없이 401 auth_code_required; 쓴 코드 재사용 401 bad_code', async () => {
    const { r, ch, v } = await loginRp(coreA, reg201.body.issue_code); assert.equal(r.status, 200, j(r.body)); assert.equal(v.body.ok, true, j(v.body));
    rs1 = ch.r_s; ppid0 = r.body.publicSignals[0];
    const n = await loginRp(coreA, null); assert.equal(n.r.status, 401, j(n.r.body)); assert.equal(n.r.body.reason, 'auth_code_required');
    const u = await loginRp(coreA, reg201.body.issue_code); assert.equal(u.r.status, 401, j(u.r.body)); assert.equal(u.r.body.reason, 'bad_code');
    assert.ok(!(await dumpKv()).includes(SALT));
    assert.equal(calls, 0, '보관분으로 — 패스키 0회');
  });
  await t('다른 탭은 보관분으로 재검증 — derive 0회', async () => {
    const r = await coreB.revalidate({ r_s: rs1, origin: info.origin }); assert.equal(r.status, 200, j(r.body));
    assert.equal((await rp.post('/api/mode3/revalidate', { proof: r.body.proof, publicSignals: r.body.publicSignals, sig: r.body.sig, r_s: rs1 })).body.ok, true);
    assert.equal(calls, 0);
  });
  await t('보관 만료 뒤 재검증은 derive 1회, 다시 보관', async () => {
    skew += 11 * 60_000;
    assert.equal((await coreA.passkeyState()).body.heldUntil, null);
    const r = await coreB.revalidate({ r_s: rs1, origin: info.origin }); assert.equal(r.status, 200, j(r.body)); assert.equal(calls, 1);
    assert.ok((await coreA.passkeyState()).body.heldUntil > now());
    assert.equal((await coreA.revalidate({ r_s: rs1, origin: info.origin })).status, 200); assert.equal(calls, 1);
  });
  await t('withSalt: 보관 0초 코어에서 범위 안 두 동작 derive 1회, 범위 밖 2회', async () => {
    const z = mk({ ...config, passkeyHoldSeconds: 0 });
    await z.vault.clearHold(); const c0 = calls;
    const inside = await z.withSalt(async () => [await z.showSalt(), await z.revalidate({ r_s: rs1, origin: info.origin })]);
    assert.equal(inside[0].status, 200); assert.equal(inside[1].status, 200, j(inside[1].body)); assert.equal(calls - c0, 1);
    assert.equal((await z.passkeyState()).body.heldUntil, null, '보관 0초는 보관하지 않는다');
    assert.equal((await z.showSalt()).status, 200); assert.equal((await z.passkeyAuid()).status, 200); assert.equal(calls - c0, 3);
    // 범위가 던져도 메모는 버린다
    await assert.rejects(z.withSalt(async () => { await z.showSalt(); throw new Error('boom'); }), /boom/); assert.equal(calls - c0, 4);
    await z.showSalt(); assert.equal(calls - c0, 5);
  });
  await t('withSalt 범위 안에서 보관이 끝나도 derive 1회', async () => {
    await coreA.vault.clearHold(); const c0 = calls;
    const out = await coreA.withSalt(async () => {
      const a = await coreA.showSalt();
      skew += 11 * 60_000;   // 범위 도중 보관 만료
      const b = await coreA.revalidate({ r_s: rs1, origin: info.origin });
      return [a, b];
    });
    assert.equal(out[0].status, 200); assert.equal(out[1].status, 200, j(out[1].body)); assert.equal(calls - c0, 1);
  });
  await t('다른 패스키: credential 다르면 409 passkey_mismatch, 같은 credential 다른 salt 도 passkey_mismatch, 보관하지 않는다', async () => {
    await coreA.vault.clearHold();
    deriveFn = async () => ({ credentialId: 'b3RoZXI', s_u: SALT });
    const a = await coreA.showSalt(); assert.equal(a.status, 409, j(a.body)); assert.equal(a.body.reason, 'passkey_mismatch');
    deriveFn = async () => ({ credentialId: CID, s_u: randomScalar().toString() });
    const b = await coreA.revalidate({ r_s: rs1, origin: info.origin }); assert.equal(b.status, 409, j(b.body)); assert.equal(b.body.reason, 'passkey_mismatch');
    assert.equal((await coreA.passkeyState()).body.heldUntil, null); assert.equal(await kv.get('passkeyHold'), undefined);
    deriveFn = async () => ({ credentialId: CID, s_u: SALT });
  });
  await t('syncProfileFromRecord: 다른 salt 409, 같은 salt·다른 속성 changed:true → 다음 로그인 userCredMs > 0', async () => {
    const bad = await coreA.syncProfileFromRecord({ recordSalt: randomScalar().toString(), profile: { birthYear: '1991', country: 'KR' } }); assert.equal(bad.status, 409); assert.equal(bad.body.reason, 'attr_record_salt_mismatch');
    assert.equal((await kv.get('registration')).profile.birthYear, '1990');
    const same = await coreA.syncProfileFromRecord({ recordSalt: SALT, profile: { birthYear: '1990', country: 'KR' } }); assert.equal(same.status, 200); assert.equal(same.body.changed, false);
    const ok = await coreA.syncProfileFromRecord({ recordSalt: SALT, profile: { birthYear: '1991', country: 'KR' } }); assert.equal(ok.status, 200, j(ok.body)); assert.equal(ok.body.changed, true);
    const { r, v } = await loginRp(coreA, await authCode('issue')); assert.equal(r.status, 200, j(r.body)); assert.ok(r.body.timings.userCredMs > 0, '새 C_u'); assert.equal(v.body.ok, true);
  });
  await t('wipe 는 credential 만 남긴다', async () => {
    assert.equal((await coreA.wipe()).status, 200);
    assert.equal((await kv.get('passkey')).credentialId, CID);
    assert.equal(await kv.get('passkeyHold'), undefined); assert.equal(await kv.get('registration'), undefined);
    assert.equal((await coreA.status()).body.registered, false);
  });
  await t('계정 복구: wipe 뒤 같은 auid 등록 코드로 registerWithCode(recordSalt 없이) 201 restored:true, 같은 slot, 로그인 PPID 같음', async () => {
    const c0 = calls;
    const r = await coreA.registerWithCode({ uid: '12345', code: await authCode('register'), auid: AUID }); assert.equal(r.status, 201, j(r.body));
    assert.equal(r.body.restored, true); assert.equal(r.body.slot, slot0); assert.equal(typeof r.body.issue_code, 'string');
    assert.equal(calls - c0, 1, '보관분이 없어 패스키 1회');
    assert.equal((await coreA.vault.readSecrets()).s_u, null); assert.ok(!(await dumpKv()).includes(SALT));
    const { r: l, v } = await loginRp(coreA, r.body.issue_code); assert.equal(l.status, 200, j(l.body)); assert.equal(v.body.ok, true, j(v.body));
    assert.equal(l.body.publicSignals[0], ppid0, '같은 PPID');
  });
  await t('웹 모드 코어에서는 registerWithCode 409 not_passkey_mode', async () => {
    const w = createUserCore({ kv: createMemKv(), config: { ...config, secrets: 'web' }, provider, canonProvider: provider, fullProve });
    const r = await w.registerWithCode({ uid: '12345', code: 'x' }); assert.equal(r.status, 409); assert.equal(r.body.reason, 'not_passkey_mode');
  });
} finally { await stack.stop(); }
process.exit(fails ? 1 : 0);
