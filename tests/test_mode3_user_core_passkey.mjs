// tests/test_mode3_user_core_passkey.mjs — 웹 코어의 passkey-web 경로(스펙 2026-11-17-mode3-passkey-web, 계획 Task 5)를 Node 에서(메모리 kv·진짜 snarkjs)
// 격리 IdP(CIA_ISSUE_AUTH=code)·RP 에 대고 돌린다. 패스키는 대역(derive 호출 수를 센다). 패스키 연결 → salt 보기(보관분) → 등록 코드로 등록 →
// 발급 코드로 로그인 → 다른 탭·보관 만료·withSalt → 다른 패스키 → 속성 기록 동기화 → wipe → 계정 복구(restored). :8545·build/mode3 필요. (chain)
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createMemKv } from '../mode3/user/core/kv_mem.js';
import { createUserCore } from '../mode3/user/core/user_core.js';
import { randomScalar, auidOf, loginCtx, slotCtx } from '../lib/mode3_credential.js';
import { loadIdpVkey, idpPublicSignals, verifyIdp } from '../lib/mode3_idp_proof.js';
import { pointFromStrings } from '../lib/mode3_issuance.js';
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
  let reg201, rs1, slot0, ppid0, login1;

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
  // ---- 로그인 전체 플로우(스펙 2026-11-19 login-flow-and-phone-passkey F1~F5) ----
  await t('loginFlow: 로그인 전에는 기록이 없다(flow null)', async () => {
    const f = await coreA.loginFlow(); assert.equal(f.status, 200, j(f.body)); assert.equal(f.body.flow, null);
  });
  await t('로그인: issue_code 로 200 → RP ok; 코드 없이 401 auth_code_required; 쓴 코드 재사용 401 bad_code', async () => {
    const { r, ch, v } = await loginRp(coreA, reg201.body.issue_code); assert.equal(r.status, 200, j(r.body)); assert.equal(v.body.ok, true, j(v.body));
    rs1 = ch.r_s; ppid0 = r.body.publicSignals[0];
    login1 = r.body;
    const n = await loginRp(coreA, null); assert.equal(n.r.status, 401, j(n.r.body)); assert.equal(n.r.body.reason, 'auth_code_required');
    const u = await loginRp(coreA, reg201.body.issue_code); assert.equal(u.r.status, 401, j(u.r.body)); assert.equal(u.r.body.reason, 'bad_code');
    // 2026-11-17(미뤄 둔 Minor C): 문자열이 아니거나 빈 authCode 는 IdP 에 가기 전에 400
    for (const bad of [5, '', {}, ['c']]) { const b = await loginRp(coreA, bad); assert.equal(b.r.status, 400, `${j(bad)} ${j(b.r.body)}`); assert.match(b.r.body.error, /authCode/); }
    assert.ok(!(await dumpKv()).includes(SALT));
    assert.equal(calls, 0, '보관분으로 — 패스키 0회');
  });
  await t('loginFlow: 성공한 로그인의 단계·시간·공개값 — 뒤의 실패한 로그인이 덮지 않고, 비밀은 없다', async () => {
    const f = (await coreA.loginFlow()).body.flow; assert.ok(f, '기록이 있다');
    assert.equal(f.values.r_s, rs1, '뒤의 실패한 로그인들이 덮지 않았다');
    assert.equal(f.arid, info.arid); assert.equal(f.origin, info.origin); assert.equal(typeof f.at, 'number');
    assert.deepEqual(f.steps.map((x) => x.key), ['check_service', 'passkey', 'sync', 'random', 'session_key', 'commit', 'pseudonym', 'prove_idp', 'issue', 'publish_wait', 'prove_session', 'sign']);
    for (const x of f.steps) assert.ok(typeof x.ms === 'number' && Number.isFinite(x.ms) && x.ms >= 0, j(x));
    const step = (k) => f.steps.find((x) => x.key === k);
    assert.ok(step('prove_idp').ms > 50 && step('prove_session').ms > 50, j(f.steps));
    assert.ok(step('pseudonym').ms < step('prove_idp').ms, '가명은 증명보다 훨씬 짧다');
    assert.equal(step('passkey').held, true, '보관분을 썼다 — 패스키를 묻지 않았다');
    assert.equal(step('prove_session').cacheHit, false);
    assert.ok(f.totalMs >= step('prove_idp').ms + step('prove_session').ms, j(f));
    const v = f.values, ps = login1.publicSignals;
    assert.equal(v.PPID, ppid0); assert.equal(v.pk_i, ps[2]); assert.equal(v.max_height, ps[3]); assert.equal(v.auid_s, ps[25]); assert.equal(v.arid_s, ps[26]);
    assert.equal(v.uid, '12345'); assert.equal(typeof v.hasIdToken, 'boolean');
    for (const k of ['Cf_u', 'Cf_s', 'r_rp']) assert.match(String(v[k]), /^\d+$/, k);
    const dump = j(f);
    assert.ok(!dump.includes(SALT), 'salt 가 없다');
    for (const bad of ['blind', 'privateKey', 's_u', '"n"', 'auth_code']) assert.ok(!dump.includes(bad), `${bad} 가 기록에 없다`);
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
  // ---- 스펙 2026-11-19 passkey-proof-login L4·L8: 로그인은 패스키를 한 번 묻는다(fresh), zkIdP 로그인 증명 ----
  await t('withSalt fresh: 보관분이 있어도 범위의 첫 salt 는 패스키에서(derive 1회) — 범위 안 다음 동작은 메모, 보관은 갱신, 범위 밖·fresh 없는 범위는 보관분', async () => {
    assert.equal((await coreA.showSalt()).status, 200);
    const held0 = (await coreA.passkeyState()).body.heldUntil; assert.ok(held0 > now(), '보관분이 있다');
    const c0 = calls; skew += 60_000;
    const out = await coreA.withSalt(async () => [await coreA.showSalt(), await coreA.revalidate({ r_s: rs1, origin: info.origin })], { fresh: true });
    assert.equal(out[0].status, 200); assert.equal(out[1].status, 200, j(out[1].body)); assert.equal(calls - c0, 1);
    assert.ok((await coreA.passkeyState()).body.heldUntil > held0, '새로 얻은 값으로 보관을 갱신한다');
    assert.equal((await coreA.showSalt()).status, 200); assert.equal(calls - c0, 1, '범위 밖은 보관분');
    assert.equal((await coreA.withSalt(() => coreA.showSalt())).status, 200); assert.equal(calls - c0, 1, 'fresh 없는 범위는 보관분');
  });
  await t('loginFlow: fresh 범위의 로그인은 passkey 단계가 held:false(패스키 1회) — 새 C_u 가 아니면 publish_wait 단계가 없고, 기록은 이 로그인으로 바뀐다', async () => {
    const c0 = calls, code = await authCode('issue');
    const { r, ch, v } = await coreA.withSalt(() => loginRp(coreA, code), { fresh: true });
    assert.equal(r.status, 200, j(r.body)); assert.equal(v.body.ok, true, j(v.body)); assert.equal(calls - c0, 1);
    const f = (await coreB.loginFlow()).body.flow;   // 다른 탭(같은 kv)에서도 읽힌다
    assert.equal(f.values.r_s, ch.r_s);
    assert.equal(f.steps.find((x) => x.key === 'passkey').held, false);
    assert.equal(f.steps.find((x) => x.key === 'passkey').before, undefined, '로그인 안에서 물은 패스키는 전체 시간 안이다');
    assert.ok(f.steps.reduce((a, x) => a + x.ms, 0) <= f.totalMs + 1, `단계 합이 전체를 넘지 않는다: ${j(f.steps.map((x) => x.ms))} / ${f.totalMs}`);
    assert.ok(!f.steps.some((x) => x.key === 'publish_wait'), j(f.steps.map((x) => x.key)));
  });
  // 리뷰 2026-11-19 I-1: 승인 창은 등록(registerWithCode)과 로그인을 한 범위에서 잇는다 — 패스키는 등록 때 물었고 그 시간은 로그인의 totalMs 밖이다.
  await t('loginFlow: 같은 범위에서 로그인 전에 패스키를 물었으면 passkey 단계에 before:true 가 붙는다(전체 시간 밖)', async () => {
    const c0 = calls, code = await authCode('issue');
    const { r, v } = await coreA.withSalt(async () => { assert.equal((await coreA.showSalt()).status, 200); return loginRp(coreA, code); }, { fresh: true });
    assert.equal(r.status, 200, j(r.body)); assert.equal(v.body.ok, true, j(v.body)); assert.equal(calls - c0, 1, '범위 안에서 패스키는 한 번');
    const pk = (await coreA.loginFlow()).body.flow.steps.find((x) => x.key === 'passkey');
    assert.equal(pk.held, false); assert.equal(pk.before, true, j(pk));
  });
  // 리뷰 2026-11-19 M-6: 시연용 변조(가짜 서명)를 건 로그인은 코어에서는 200 이지만 서비스가 거절한다 — "가장 최근 (성공한) 로그인" 기록을 바꾸지 않는다.
  await t('loginFlow: 시연용 변조(fake_sig)를 건 로그인은 기록하지 않는다 — 앞의 성공한 로그인 기록이 그대로다', async () => {
    const before = (await coreA.loginFlow()).body.flow;
    assert.equal((await coreA.demoOverride({ scope: 'fake_sig' })).status, 200);
    const { r, v } = await coreA.withSalt(async () => loginRp(coreA, await authCode('issue')), { fresh: true });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.demo, 'override:fake_sig'); assert.notEqual(v.body.ok, true, '서비스는 가짜 서명을 거절한다');
    assert.deepEqual((await coreA.loginFlow()).body.flow, before);
  });
  await t('withSalt fresh: 패스키가 실패하면(다른 패스키·취소) 보관분으로 넘어가지 않는다', async () => {
    const keep = deriveFn;
    try {
      deriveFn = async () => ({ credentialId: 'b3RoZXI', s_u: SALT });
      const m = await coreA.withSalt(() => coreA.showSalt(), { fresh: true }); assert.equal(m.status, 409, j(m.body)); assert.equal(m.body.reason, 'passkey_mismatch');
      deriveFn = async () => { throw Object.assign(new Error('cancelled'), { reason: 'passkey_cancelled' }); };
      const c = await coreA.withSalt(() => coreA.showSalt(), { fresh: true }); assert.equal(c.status, 409, j(c.body)); assert.equal(c.body.reason, 'passkey_cancelled');
    } finally { deriveFn = keep; }
    assert.equal((await coreA.showSalt()).status, 200, '보관분은 그대로다');
  });
  await t('idpLoginProof: 로그인 증명은 loginCtx(nonce) 에만 맞는다 — uid·nonce·π_IdP 필드뿐(비밀 없음), 증명 기록의 purpose 는 idp_login', async () => {
    const nonce = randomScalar().toString();
    const r = await coreA.idpLoginProof({ nonce }); assert.equal(r.status, 200, j(r.body));
    assert.deepEqual(Object.keys(r.body).sort(), ['C_s_pt', 'C_u_pt', 'auid_s', 'max_height', 'nonce', 'proof_idp', 'tag', 'uid']);
    assert.equal(r.body.uid, '12345'); assert.equal(r.body.nonce, nonce); assert.ok(!j(r.body).includes(SALT), '응답에 salt 가 없다');
    const vk = await loadIdpVkey();
    const pubOf = (ctx) => idpPublicSignals({ uid: 12345n, auid: BigInt(AUID), auid_s: BigInt(r.body.auid_s), C_u_pt: pointFromStrings(r.body.C_u_pt), C_s_pt: pointFromStrings(r.body.C_s_pt), max_height: BigInt(r.body.max_height), ctx, tag: BigInt(r.body.tag) });
    assert.equal(await verifyIdp(vk, pubOf(await loginCtx({ nonce: BigInt(nonce) })), r.body.proof_idp), true, '로그인 ctx 로 검증된다');
    assert.equal(await verifyIdp(vk, pubOf(await loginCtx({ nonce: BigInt(nonce) + 1n })), r.body.proof_idp), false, '다른 nonce');
    assert.equal(await verifyIdp(vk, pubOf(await slotCtx({ nonce: BigInt(nonce) })), r.body.proof_idp), false, '슬롯 조회용 ctx');
    const last = (await coreA.proofs()).body.proofs[0];
    assert.equal(last.kind, 'pi_idp'); assert.equal(last.purpose, 'idp_login');
    for (const bad of [undefined, '', 'abc', '-1', (1n << 255n).toString()]) { const b = await coreA.idpLoginProof({ nonce: bad }); assert.equal(b.status, 400, `${bad}: ${j(b.body)}`); assert.equal(b.body.reason, 'malformed'); }
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
  // ---- 2026-11-17(미뤄 둔 Minor C) — 각 케이스는 새 kv·새 코어로 자기 상태를 만든다(앞 케이스의 등록·보관분과 무관) ----
  const freshCore = (cfg = config) => { const k = createMemKv(); return { k, c: createUserCore({ kv: k, config: cfg, provider, canonProvider: provider, fullProve, now, passkey }) }; };
  // 2026-11-18(사용자 요청): 데모 리셋은 패스키 연결도 끊는다 — 사용자 페이지가 wipe({ keepPasskey: false }) 로 부른다. 화면의 "모두 지우기"(기본)는 그대로 연결을 남긴다.
  await t('wipe({ keepPasskey: false }) 는 등록·보관분과 함께 패스키 연결도 지운다', async () => {
    const { k, c } = freshCore();
    assert.equal((await c.passkeyConnect({ credentialId: CID, s_u: SALT })).status, 200);
    assert.ok(await k.get('passkey')); assert.ok(await k.get('passkeyHold'));
    assert.equal((await c.wipe({ keepPasskey: false })).status, 200);
    assert.equal(await k.get('passkey'), undefined); assert.equal(await k.get('passkeyHold'), undefined);
    assert.equal((await c.passkeyState()).body.credentialId, null);
    const s2 = await c.showSalt(); assert.equal(s2.status, 409); assert.equal(s2.body.reason, 'passkey_setup_required');
  });
  // ---- 휴대폰 패스키(스펙 2026-11-19 login-flow-and-phone-passkey P2) ----
  await t('passkeyConnect: 인증기의 공개 정보(info)를 함께 두고 passkeyState 가 돌려준다 — 모르는 값은 버리고, 이후의 derive 는 transports·hints 를 받는다', async () => {
    const { k, c } = freshCore();
    const r = await c.passkeyConnect({ credentialId: CID, s_u: SALT, info: { attachment: 'cross-platform', transports: ['hybrid', 'internal', '<x>'], backupEligible: true, backedUp: true, hint: 'hybrid', extra: 'x' } });
    assert.equal(r.status, 200, j(r.body));
    const want = { attachment: 'cross-platform', transports: ['hybrid', 'internal'], backupEligible: true, backedUp: true, hint: 'hybrid' };
    assert.deepEqual((await c.passkeyState()).body.info, want);
    assert.deepEqual((await k.get('passkey')).info, want);
    const prev = deriveFn; let got = null;
    deriveFn = async (a) => { got = a; return prev(a); };
    try { skew += 11 * 60_000; assert.equal((await c.showSalt()).status, 200); } finally { deriveFn = prev; }
    assert.deepEqual(got, { credentialId: CID, transports: ['hybrid', 'internal'], hints: ['hybrid'] });
  });
  await t('passkeyConnect: info 가 없으면 지금까지와 같다(info null, derive 는 credentialId 만) — 형식이 틀린 info 는 400 bad_passkey_info', async () => {
    const { c } = freshCore();
    assert.equal((await c.passkeyConnect({ credentialId: CID, s_u: SALT, info: 'phone' })).body.reason, 'bad_passkey_info');
    assert.equal((await c.passkeyConnect({ credentialId: CID, s_u: SALT })).status, 200);
    assert.equal((await c.passkeyState()).body.info, null);
    const prev = deriveFn; let got = null;
    deriveFn = async (a) => { got = a; return prev(a); };
    try { skew += 11 * 60_000; assert.equal((await c.showSalt()).status, 200); } finally { deriveFn = prev; }
    assert.deepEqual(got, { credentialId: CID });
  });
  await t('passkeyDisconnect(미등록): 200 — credential·보관분을 지운다, 이어서 showSalt 는 passkey_setup_required', async () => {
    const { k, c } = freshCore();
    assert.equal((await c.passkeyConnect({ credentialId: CID, s_u: SALT })).status, 200);
    assert.ok(await k.get('passkeyHold'));
    const d = await c.passkeyDisconnect(); assert.equal(d.status, 200, j(d.body)); assert.deepEqual(d.body, { ok: true });
    assert.equal(await k.get('passkey'), undefined); assert.equal(await k.get('passkeyHold'), undefined);
    const st = await c.passkeyState(); assert.equal(st.body.credentialId, null); assert.equal(st.body.heldUntil, null);
    const s2 = await c.showSalt(); assert.equal(s2.status, 409); assert.equal(s2.body.reason, 'passkey_setup_required');
  });
  await t('passkeyDisconnect 는 withSalt 메모도 버린다 — 범위 안에서 끊은 뒤의 salt 요청은 passkey_setup_required', async () => {
    const { c } = freshCore(); const c0 = calls;
    assert.equal((await c.passkeyConnect({ credentialId: CID, s_u: SALT })).status, 200);
    const out = await c.withSalt(async () => [await c.showSalt(), await c.passkeyDisconnect(), await c.showSalt()]);
    assert.equal(out[0].status, 200); assert.equal(out[0].body.s_u, SALT);
    assert.equal(out[1].status, 200, j(out[1].body));
    assert.equal(out[2].status, 409, `끊은 뒤에도 메모의 salt 가 나왔다: ${j(out[2].body)}`); assert.equal(out[2].body.reason, 'passkey_setup_required');
    assert.equal(calls - c0, 0);
  });
  await t('passkeyConnect: 같은 credential 인데 보관분과 다른 s_u 는 409 passkey_mismatch — 보관분을 덮지 않는다; 같은 s_u 면 200', async () => {
    const { k, c } = freshCore();
    assert.equal((await c.passkeyConnect({ credentialId: CID, s_u: SALT })).status, 200);
    const until0 = (await c.passkeyState()).body.heldUntil;
    const other = randomScalar().toString();
    const r = await c.passkeyConnect({ credentialId: CID, s_u: other }); assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'passkey_mismatch');
    assert.equal(await c.vault.heldSalt(), SALT, '보관분은 그대로');
    assert.equal((await c.passkeyState()).body.heldUntil, until0);
    assert.equal((await c.passkeyConnect({ credentialId: CID, s_u: SALT })).status, 200, '같은 패스키·같은 salt 는 다시 연결해도 된다');
    assert.equal((await k.get('passkey')).credentialId, CID);
  });
  await t('syncProfileFromRecord(미등록): 409 not_registered — 속성을 저장하지 않는다', async () => {
    const { k, c } = freshCore();
    const r = await c.syncProfileFromRecord({ recordSalt: SALT, profile: { birthYear: '1990', country: 'KR' } });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'not_registered');
    assert.equal(await k.get('registration'), undefined);
  });
  await t('idpLoginProof(미등록): 409 not_registered — 패스키를 묻지 않는다', async () => {
    const { c } = freshCore(); assert.equal((await c.passkeyConnect({ credentialId: CID, s_u: SALT })).status, 200);
    const c0 = calls; const r = await c.idpLoginProof({ nonce: '7' }); assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'not_registered'); assert.equal(calls, c0);
  });
  await t('웹 모드 코어에서는 registerWithCode 409 not_passkey_mode', async () => {
    const w = createUserCore({ kv: createMemKv(), config: { ...config, secrets: 'web' }, provider, canonProvider: provider, fullProve });
    const r = await w.registerWithCode({ uid: '12345', code: 'x' }); assert.equal(r.status, 409); assert.equal(r.body.reason, 'not_passkey_mode');
  });
  // 리뷰(2026-11-19) M10: 증명 로그인은 passkey-web 의 것이다 — web 모드 코어는 zkIdP 로그인 증명을 내지 않는다(스펙의 "web 모드의 동작은 그대로").
  await t('웹 모드 코어에서는 idpLoginProof 409 not_passkey_mode', async () => {
    const w = createUserCore({ kv: createMemKv(), config: { ...config, secrets: 'web' }, provider, canonProvider: provider, fullProve });
    const r = await w.idpLoginProof({ nonce: '7' }); assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'not_passkey_mode');
  });
} finally { await stack.stop(); }
process.exit(fails ? 1 : 0);
