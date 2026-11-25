// tests/test_mode3_user_core_wrapper.mjs — 웹 코어의 래퍼 로그인(스펙 2026-11-20 zkwrapper §2.2, 계획 Task 3)을 Node 에서(메모리 kv·진짜 snarkjs) 격리 발급 서버(CIA_WRAPPER)·
// Google 대역·RP 에 대고 돌린다. 패스키는 대역(derive 호출 수를 센다 — credential 여럿·envKey·excludeCredentialIds 를 흉내 낸다, salt 봉투 계획 Task 4). wrapperBegin(요청 키) → Google 토큰 → wrapperLogin(패스키 한 번 → 발급 → π_RP) → 서비스 검증. :8545·build/mode3 필요. (chain)
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createMemKv } from '../mode3/user/core/kv_mem.js';
import { createUserCore } from '../mode3/user/core/user_core.js';
import { randomScalar, auidOf } from '../lib/mode3_credential.js';
import { uidOf } from '../lib/mode3_oidc_nonce.js';
import { wrapperNonce } from '../lib/mode3_wrapper_auth.js';
import { envKeyFromPrf, newRecoveryCode } from '../lib/mode3_salt_envelope.js';
import { PUB_INDEX } from '../lib/mode3_onchain.js';
import * as snarkjs from 'snarkjs';

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });   // 정적 서버는 dist 가 없으면 기동을 거부한다
const stack = await startIsolatedMode3Stack({ userMode: 'web', walletHost: 'localhost', walletEnv: { MODE3_WALLET_SECRETS: 'passkey-web' }, wrapper: true, autoRelay: true });
const { wallet, rp, cia } = stack;
const stub = stack.oidc;
const provider = getProvider();
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
try {
  const config = { ...(await wallet.get('/user/config')).body, wrapper: true };
  assert.equal(config.secrets, 'passkey-web');
  const fullProve = { idp: () => { throw new Error('래퍼 방식은 π_IdP 를 만들지 않는다'); }, cred: (input, w, z) => snarkjs.groth16.fullProve(input, w, z) };
  const rnd32 = () => globalThis.crypto.getRandomValues(new Uint8Array(32));
  const cancelled = () => Object.assign(new Error('NotAllowedError'), { reason: 'passkey_cancelled' });
  /** 인증기의 credential 하나 — PRF 바이트(envKey 를 만든다)와 그 PRF 로 나오는 salt(직접 쓰는 salt). */
  const mkCred = (cid, s_u = randomScalar().toString()) => ({ cid, s_u, prf: rnd32() });
  /** 브라우저 하나 = kv 하나 + 패스키 하나(salt). sent 에 발급 서버로 간 요청 본문을, recv 에 그 응답을 모은다. rewrite(url, body) 가 새 본문을 주면 응답을 바꿔치기한다.
   *  패스키 대역: derive({ credentialId }) 는 그 credential 이 이 브라우저(손에 든 인증기)에 있을 때만(없으면 passkey_cancelled — 맞지 않는 allowCredentials),
   *  create({ excludeCredentialIds }) 는 createQueue 의 다음 credential 을 만든다(제외 목록에 있으면 passkey_already_registered). cancelNext 면 다음 derive 를 취소한다.
   *  chainDownAfterIssue: 처음으로 발급이 200 으로 돌아온 뒤 이 브라우저의 체인 RPC 가 모두 실패한다(한 번만 걸린다, chainDown 을 false 로 돌리면 다시 된다) — 발급 뒤 단계의 실패를 흉내 낸다.
   *  throwAfterIssue(최종 검토 I-2): 처음으로 발급이 200 으로 돌아온 뒤 다음 증명이 던진다(한 번만) — login 이 값을 돌려주지 못하고 끝나는 경우(증명 중 창이 닫힘 등)를 흉내 낸다.
   *  blockIssue: 다음 /cia/issue 요청을 서버로 보내지 않고 fetch 가 실패한다(한 번만) — 발급이 받아들여지지 않은 실패. swapNext: 다음 derive 가 요청과 다른 그 credential 을 돌려준다(한 번만). */
  const browser = (salt = randomScalar().toString(), cid = 'Y2lkLWE', now = Date.now, { prf = rnd32(), extra = [], createQueue = [], chainDownAfterIssue = false, throwAfterIssue = false } = {}) => {
    const kv = createMemKv(), b = { kv, salt, cid, calls: 0, sent: [], recv: [], deriveIds: [], creates: [], cancelNext: false, rewrite: null, chainDown: false, armChain: chainDownAfterIssue,
      armThrow: throwAfterIssue, throwProve: false, blockIssue: false, swapNext: null };
    // 메서드는 원래 객체에 묶어 돌려준다(ethers 의 private 필드) — chainDown 이면 모든 호출이 거절된다
    const prov = chainDownAfterIssue ? new Proxy(provider, { get(tgt, p) { const v = Reflect.get(tgt, p, tgt); if (typeof v !== 'function') return v; return b.chainDown ? () => Promise.reject(new Error('RPC 꺼짐(테스트)')) : v.bind(tgt); } }) : provider;
    const creds = new Map([[cid, { cid, s_u: salt, prf }], ...extra.map((c) => [c.cid, c])]);
    const passkey = {
      derive: async ({ credentialId } = {}) => {
        b.calls++; b.deriveIds.push(credentialId ?? null);
        if (b.cancelNext) { b.cancelNext = false; throw cancelled(); }
        const swap = b.swapNext; b.swapNext = null;
        const c = creds.get(swap ?? credentialId ?? cid);
        if (!c) throw cancelled();
        return { credentialId: c.cid, s_u: c.s_u, envKey: await envKeyFromPrf(c.prf) };
      },
      create: async ({ excludeCredentialIds = [] } = {}) => {
        b.creates.push({ excludeCredentialIds: [...excludeCredentialIds] });
        const c = createQueue.shift();
        if (!c) throw cancelled();
        if (excludeCredentialIds.includes(c.cid)) throw Object.assign(new Error('InvalidStateError'), { reason: 'passkey_already_registered' });
        creds.set(c.cid, c);
        return { credentialId: c.cid, s_u: c.s_u, envKey: await envKeyFromPrf(c.prf), info: null };
      },
    };
    const fetchSpy = async (url, init) => {
      const u = String(url), mine = u.includes('/cia/') && Boolean(init?.body);
      if (mine) b.sent.push({ url: u, body: JSON.parse(init.body) });
      if (mine && b.blockIssue && u.endsWith('/cia/issue')) { b.blockIssue = false; throw new TypeError('fetch failed(테스트 — 발급 서버에 닿지 못했다)'); }
      const res = await globalThis.fetch(url, init);
      if (!mine) return res;
      const body = await res.clone().json().catch(() => null);
      b.recv.push({ url: u, status: res.status, body });
      if (b.armChain && u.endsWith('/cia/issue') && res.status === 200) { b.chainDown = true; b.armChain = false; }   // 한 번만
      if (b.armThrow && u.endsWith('/cia/issue') && res.status === 200) { b.throwProve = true; b.armThrow = false; }
      const nb = b.rewrite && body ? b.rewrite(u, body) : null;
      return nb ? new Response(JSON.stringify(nb), { status: res.status, headers: { 'Content-Type': 'application/json' } }) : res;
    };
    const prove = { idp: fullProve.idp, cred: (...a) => { if (b.throwProve) { b.throwProve = false; throw new Error('증명 중 창이 닫혔다(테스트)'); } return fullProve.cred(...a); } };
    b.core = createUserCore({ kv, config, provider: prov, canonProvider: prov, fullProve: prove, passkey, fetch: fetchSpy, now });
    b.dump = async () => { const all = {}; for (const k of await kv.keys()) all[k] = await kv.get(k); return j(all); };
    b.issues = () => b.sent.filter((x) => x.url.endsWith('/cia/issue'));
    return b;
  };
  let info = (await rp.get('/api/mode3/rp_info')).body;
  for (let i = 0; i < 50 && !info.attrGateAddress; i++) { await sleep(200); info = (await rp.get('/api/mode3/rp_info')).body; }
  const loginBody = (ch) => ({ arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, allowAgent: '0', factoryAddress: info.factoryAddress, attrGateAddress: info.attrGateAddress });
  const challenge = async () => (await rp.post('/api/mode3/challenge')).body;
  const mint = (sub, nonce) => stub.mint({ sub, nonce, extra: { email: `${sub}@example.com`, email_verified: true } });
  /** 창이 하는 일: wrapperBegin → Google(대역)에서 그 nonce 의 토큰 → wrapperLogin → 서비스 검증. */
  const wlogin = async (b, sub) => {
    const bg = await b.core.wrapperBegin(); assert.equal(bg.status, 200, j(bg.body));
    const idToken = await mint(sub, bg.body.googleNonce);
    const ch = await challenge();
    const r = await b.core.wrapperLogin(loginBody(ch), { idToken, verifiedOrigin: info.origin, googleMs: 1234 });
    if (r.status !== 200) return { r, ch, idToken };
    const v = await rp.post('/api/mode3/login', { proof: r.body.proof, publicSignals: r.body.publicSignals, sig: r.body.sig, r_s: ch.r_s });
    return { r, ch, v, idToken, PPID: r.body.publicSignals[PUB_INDEX.PPID] };
  };
  const accounts = async () => (await cia.adminGet('/cia/accounts')).body.accounts;
  const A = browser(); const UID_A = uidOf(stub.provider, 'g-anna');
  let first;

  await t('패스키 연결 전: wrapperLogin 은 409 passkey_setup_required — 계정·로컬 등록이 생기지 않는다', async () => {
    const out = await wlogin(A, 'g-anna');
    assert.equal(out.r.status, 409, j(out.r.body)); assert.equal(out.r.body.reason, 'passkey_setup_required');
    assert.equal(await A.kv.get('registration'), undefined); assert.equal((await accounts()).some((a) => a.uid === UID_A), false);
  });
  await t('wrapperBegin: 패스키를 묻지 않는다(derive 0회), googleNonce 는 그 요청 키의 "wrap:"…, 개인키는 꺼낼 수 없다', async () => {
    assert.equal((await A.core.passkeyConnect({ credentialId: A.cid, s_u: A.salt })).status, 200);
    const calls0 = A.calls;
    const bg = await A.core.wrapperBegin(); assert.equal(bg.status, 200, j(bg.body));
    assert.ok(bg.body.googleNonce.startsWith('wrap:')); assert.equal(bg.body.googleNonce, await wrapperNonce(bg.body.pkE));
    const wk = await A.kv.get('wrapperKey'); assert.equal(wk.privateKey.extractable, false); assert.deepEqual(wk.pkE, bg.body.pkE);
    assert.equal(A.calls, calls0);
    const again = await A.core.wrapperBegin(); assert.notEqual(again.body.googleNonce, bg.body.googleNonce, '부를 때마다 새 요청 키');
  });
  await t('wrapperLogin(처음): derive 1회, 계정·로컬 등록이 생기고 서비스 검증 통과 — 발급 요청에 uid·n·tag·proof_idp 가 없다', async () => {
    const calls0 = A.calls; A.sent.length = 0;
    first = await wlogin(A, 'g-anna');
    assert.equal(first.r.status, 200, j(first.r.body)); assert.equal(first.v.status, 200, j(first.v.body));
    assert.equal(A.calls - calls0, 1, '패스키는 한 번');
    const issue = A.sent.filter((x) => x.url.endsWith('/cia/issue')); assert.equal(issue.length, 1);
    for (const k of ['uid', 'n', 'tag', 'proof_idp', 'registration', 'auth_code']) assert.equal(k in issue[0].body, false, `발급 요청에 ${k}`);
    for (const k of ['id_token', 'pk_e', 'sig', 'auid', 'auid_s', 'arid_s', 'C_u_pt', 'C_s_pt']) assert.ok(k in issue[0].body, `발급 요청에 ${k} 가 없다`);
    assert.equal(A.sent.some((x) => /\/cia\/(register|slot|signup)/.test(x.url)), false, '등록·슬롯 경로를 부르지 않는다');
    const reg = await A.kv.get('registration');
    assert.equal(reg.uid, UID_A); assert.equal(reg.auid, (await auidOf({ s_u: BigInt(A.salt) })).toString()); assert.equal(Number.isInteger(reg.slot), true); assert.ok(!reg.pendingIdp); assert.equal(reg.wrapper, true);
    const acct = (await accounts()).find((a) => a.uid === UID_A); assert.equal(acct.auid, reg.auid); assert.equal(acct.id, 'g-anna@example.com');
  });
  await t('끝난 뒤 kv 에 요청 키·salt·Google 토큰이 없다', async () => {
    assert.equal(await A.kv.get('wrapperKey'), undefined);
    const d = await A.dump(); assert.ok(!d.includes(A.salt), 'salt 가 남았다'); assert.ok(!d.includes(first.idToken), 'Google 토큰이 남았다');
  });
  await t('loginFlow 기록: prove_idp 가 없고 google·passkey·issue·prove_session 이 있다', async () => {
    const f = (await A.core.loginFlow()).body.flow; const keys = f.steps.map((s) => s.key);
    assert.equal(keys.includes('prove_idp'), false, j(keys));
    for (const k of ['google', 'passkey', 'issue', 'prove_session']) assert.ok(keys.includes(k), `${k} 없음: ${j(keys)}`);
    assert.equal(f.steps.find((s) => s.key === 'google').ms, 1234); assert.equal(f.values.uid, UID_A);
  });
  await t('wrapperLogin(두 번째): derive 1회, 같은 PPID', async () => {
    const calls0 = A.calls;
    const second = await wlogin(A, 'g-anna');
    assert.equal(second.r.status, 200, j(second.r.body)); assert.equal(second.v.status, 200, j(second.v.body));
    assert.equal(A.calls - calls0, 1); assert.equal(second.PPID, first.PPID);
  });
  await t('wrapperBegin 없이 wrapperLogin: 409 wrapper_key_missing — 패스키를 묻지 않는다', async () => {
    const calls0 = A.calls; const ch = await challenge();
    const r = await A.core.wrapperLogin(loginBody(ch), { idToken: await mint('g-anna', 'wrap:' + '0'.repeat(64)), verifiedOrigin: info.origin });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'wrapper_key_missing'); assert.equal(A.calls, calls0);
  });
  await t('토큰이 지금의 요청 키의 것이 아니면(그 사이 wrapperBegin 을 다시 불렀다) 409 wrapper_key_missing', async () => {
    const bg1 = await A.core.wrapperBegin(); const stale = await mint('g-anna', bg1.body.googleNonce);
    await A.core.wrapperBegin();
    const r = await A.core.wrapperLogin(loginBody(await challenge()), { idToken: stale, verifiedOrigin: info.origin });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'wrapper_key_missing');
  });
  await t('요청 키에는 수명이 있다(최종 검토 M-8): wrapperBegin 뒤 10분이 지나면 409 wrapper_key_missing — 패스키를 묻지 않고 키를 지운다', async () => {
    let clock = Date.now();
    const C = browser(undefined, undefined, () => clock);
    const bg = await C.core.wrapperBegin(); assert.equal(bg.status, 200, j(bg.body));
    const idToken = await mint('g-late', bg.body.googleNonce);
    clock += 10 * 60_000 + 1;
    const r = await C.core.wrapperLogin(loginBody(await challenge()), { idToken, verifiedOrigin: info.origin });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'wrapper_key_missing'); assert.equal(C.calls, 0);
    assert.equal(await C.kv.get('wrapperKey'), undefined, '오래된 요청 키는 남기지 않는다');
  });
  await t('다른 패스키(다른 salt)로 같은 Google 계정: 409 auid_pinned, 로컬 등록이 생기지 않는다', async () => {
    const B = browser(undefined, 'Y2lkLWI'); await B.core.passkeyConnect({ credentialId: B.cid, s_u: B.salt });
    const out = await wlogin(B, 'g-anna');
    assert.equal(out.r.status, 409, j(out.r.body)); assert.equal(out.r.body.reason, 'auid_pinned');
    assert.equal(await B.kv.get('registration'), undefined); assert.equal(await B.kv.get('wrapperKey'), undefined);
  });
  // 2026-11-25(사용자 결정): C_u 교체의 최소 간격을 없앴다 — 새 브라우저 둘이 잇달아 와도(교체 두 번) 둘 다 로그인된다
  await t('같은 패스키·같은 Google 계정을 새 브라우저에서(새 C_u): 첫 교체도 두 번째 교체도 바로 되고 로컬 등록이 남는다', async () => {
    const C = browser(A.salt, A.cid); await C.core.passkeyConnect({ credentialId: C.cid, s_u: C.salt });
    const first = await wlogin(C, 'g-anna');
    assert.equal(first.r.status, 200, j(first.r.body));
    const D = browser(A.salt, A.cid); await D.core.passkeyConnect({ credentialId: D.cid, s_u: D.salt });
    const out = await wlogin(D, 'g-anna');
    assert.equal(out.r.status, 200, j(out.r.body));
    assert.notEqual(await D.kv.get('registration'), undefined);
  });
  await t('이 브라우저가 다른 Google 계정에 묶여 있으면 409 wrapper_account_mismatch — 발급 서버로 가지 않는다', async () => {
    A.sent.length = 0;
    const out = await wlogin(A, 'g-other');
    assert.equal(out.r.status, 409, j(out.r.body)); assert.equal(out.r.body.reason, 'wrapper_account_mismatch');
    assert.equal(A.sent.some((x) => x.url.endsWith('/cia/issue')), false); assert.equal((await A.kv.get('registration')).uid, UID_A);
  });
  await t('예전 방식의 로컬 등록(wrapper 표시 없음)은 래퍼 로그인이 새 등록으로 바꾼다', async () => {
    const D = browser(undefined, 'Y2lkLWQ'); await D.core.passkeyConnect({ credentialId: D.cid, s_u: D.salt });
    const auid = (await auidOf({ s_u: BigInt(D.salt) })).toString();
    await D.kv.set('registration', { uid: '777', auid, slot: 3, provider: 'demo', profile: {}, attrs: ['0', '0', '0', '0', '0', '0'], userCred: null });
    const out = await wlogin(D, 'g-dora');
    assert.equal(out.r.status, 200, j(out.r.body)); assert.equal(out.v.status, 200, j(out.v.body));
    const reg = await D.kv.get('registration'); assert.equal(reg.uid, uidOf(stub.provider, 'g-dora')); assert.equal(reg.wrapper, true);
  });
  await t('방금 만든 패스키의 값(salt)을 주면 그 로그인에 바로 쓴다(derive 0회) — 속성 도구 기록은 이 패스키의 것일 때만 쓰고, 아니면 409 attr_record_salt_mismatch', async () => {
    const E = browser(undefined, 'Y2lkLWU'); await E.core.passkeyConnect({ credentialId: E.cid, s_u: E.salt });
    const auidE = (await auidOf({ s_u: BigInt(E.salt) })).toString();
    const go = async (extra) => { const bg = await E.core.wrapperBegin(); const ch = await challenge(); return { ch, r: await E.core.wrapperLogin(loginBody(ch), { idToken: await mint('g-ella', bg.body.googleNonce), verifiedOrigin: info.origin, salt: E.salt, ...extra }) }; };
    const bad = await go({ profile: { birthYear: '2001', country: 'KR' }, recordAuid: '12345' });
    assert.equal(bad.r.status, 409, j(bad.r.body)); assert.equal(bad.r.body.reason, 'attr_record_salt_mismatch'); assert.equal(await E.kv.get('registration'), undefined);
    const ok = await go({ profile: { birthYear: '2001', country: 'KR' }, recordAuid: auidE });
    assert.equal(ok.r.status, 200, j(ok.r.body)); assert.equal(E.calls, 0, '방금 만든 값으로 — 패스키를 다시 묻지 않는다');
    assert.equal((await E.kv.get('registration')).profile.birthYear, '2001'); assert.ok(!(await E.dump()).includes(E.salt));
    assert.equal((await go({ salt: 'not-a-number' })).r.body.reason, 'passkey_bad_salt');
  });
  // ---- salt 봉투(계획 2026-11-24 zkwrapper salt-envelope Task 4): 백업 더하기·지우기, auid_pinned 뒤 복구 ----
  /** wrapperBegin → 그 요청 키에 묶인 Google 토큰(대역). */
  const tokenFor = async (b, sub) => { const bg = await b.core.wrapperBegin(); assert.equal(bg.status, 200, j(bg.body)); return mint(sub, bg.body.googleNonce); };
  /** 409 auid_pinned 를 받은 같은 토큰으로 복구 → 서비스 검증. */
  const recoverLogin = async (b, { idToken, envelopeId, code = null }) => {
    const ch = await challenge();
    const r = await b.core.wrapperLoginRecover(loginBody(ch), { idToken, verifiedOrigin: info.origin, envelopeId, code });
    if (r.status !== 200) return { r };
    const v = await rp.post('/api/mode3/login', { proof: r.body.proof, publicSignals: r.body.publicSignals, sig: r.body.sig, r_s: ch.r_s });
    return { r, v, PPID: r.body.publicSignals[PUB_INDEX.PPID] };
  };
  /** 새 계정을 만들고(첫 로그인) 백업을 더한 브라우저. */
  const owner = async (sub, { cid, backups = [] }) => {
    const queue = backups.filter((x) => x.kind === 'passkey').map((x) => x.cred);
    const b = browser(undefined, cid, Date.now, { createQueue: queue });
    assert.equal((await b.core.passkeyConnect({ credentialId: b.cid, s_u: b.salt })).status, 200);
    const f = await wlogin(b, sub); assert.equal(f.r.status, 200, j(f.r.body)); assert.equal(f.v.status, 200, j(f.v.body));
    for (const x of backups) {
      const r = await b.core.wrapperEnvelopeAdd({ idToken: await tokenFor(b, sub), kind: x.kind, ...(x.code ? { code: x.code } : {}) });
      assert.equal(r.status, 200, j(r.body));
    }
    return { b, PPID: f.PPID };
  };
  const pinnedBody = (b) => [...b.recv].reverse().find((x) => x.url.endsWith('/cia/issue') && x.body?.reason === 'auid_pinned')?.body;
  const credB = mkCred('Y2lkLWJhY2t1cA');
  const CODE = newRecoveryCode();
  let BA = null, PPID_BAK = null, C = null, c1 = null;
  await t('봉투 더하기: 백업 패스키(create 의 exclude 에 연결된 cA) → 목록 1, 복구 코드 → 목록 2 — 패스키는 더할 때마다 salt 한 번, 저장소에 salt·코드가 없다', async () => {
    BA = browser(undefined, 'Y2lkLUE', Date.now, { createQueue: [credB] });
    await BA.core.passkeyConnect({ credentialId: BA.cid, s_u: BA.salt });
    const f = await wlogin(BA, 'g-bak'); assert.equal(f.r.status, 200, j(f.r.body)); PPID_BAK = f.PPID;
    const calls0 = BA.calls;
    const add1 = await BA.core.wrapperEnvelopeAdd({ idToken: await tokenFor(BA, 'g-bak'), kind: 'passkey' });
    assert.equal(add1.status, 200, j(add1.body)); assert.equal(add1.body.envelopes.length, 1);
    assert.equal(add1.body.envelopes[0].kind, 'passkey'); assert.equal(add1.body.envelopes[0].credentialId, credB.cid); assert.equal('ct' in add1.body.envelopes[0], false);
    assert.ok(BA.creates[0].excludeCredentialIds.includes(BA.cid), j(BA.creates)); assert.equal(BA.calls - calls0, 1, 'salt 는 패스키 한 번');
    assert.equal(BA.sent.filter((x) => x.url.endsWith('/cia/wrapper/envelope')).at(-1).body.auid, (await auidOf({ s_u: BigInt(BA.salt) })).toString(), '추가 요청에 계정 auid(최종 검토 I-1)');
    const add2 = await BA.core.wrapperEnvelopeAdd({ idToken: await tokenFor(BA, 'g-bak'), kind: 'code', code: CODE });
    assert.equal(add2.status, 200, j(add2.body)); assert.equal(add2.body.envelopes.length, 2); assert.equal(add2.body.envelopes[1].credentialId, null);
    assert.equal((await BA.kv.get('envelopes')).length, 2); assert.equal(await BA.kv.get('wrapperKey'), undefined);
    const d = await BA.dump();
    for (const secret of [BA.salt, CODE, CODE.replace(/-/g, '')]) assert.ok(!d.includes(secret), '저장소에 salt·코드가 남았다');
  });
  await t('봉투 더하기: 이미 있는 백업 패스키를 또 만들면(같은 인증기) passkey_already_registered — 요청 키는 남는다', async () => {
    // A 와 같은 상태의 브라우저에서 인증기가 이미 등록된 credB 를 다시 내놓는다(같은 GPM) — exclude 에 봉투의 credentialId 가 있어 인증기가 거절한다
    const B2 = browser(BA.salt, BA.cid, Date.now, { createQueue: [credB] });
    await B2.kv.set('passkey', await BA.kv.get('passkey')); await B2.kv.set('envelopes', await BA.kv.get('envelopes'));
    await B2.kv.set('registration', await BA.kv.get('registration'));
    const r = await B2.core.wrapperEnvelopeAdd({ idToken: await tokenFor(B2, 'g-bak'), kind: 'passkey' });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'passkey_already_registered');
    assert.ok(B2.creates[0].excludeCredentialIds.includes(credB.cid), j(B2.creates)); assert.ok(await B2.kv.get('wrapperKey'), '요청 키가 남아야 한다');
    assert.equal(B2.sent.some((x) => x.url.endsWith('/cia/wrapper/envelope')), false);
  });
  await t('새 기기 C 로 같은 계정: 409 auid_pinned + recover.envelopes 2개(id·kind·credentialId 만) — 응답에 암호문·대조값이 없고, 요청 키는 남고, 로컬 등록은 되돌린다', async () => {
    C = browser(undefined, 'Y2lkLUM', Date.now, { extra: [credB] });
    await C.core.passkeyConnect({ credentialId: C.cid, s_u: C.salt });
    c1 = await wlogin(C, 'g-bak');
    assert.equal(c1.r.status, 409, j(c1.r.body)); assert.equal(c1.r.body.reason, 'auid_pinned');
    const envs = c1.r.body.recover.envelopes; assert.equal(envs.length, 2);
    for (const e of envs) assert.deepEqual(Object.keys(e).sort(), ['credentialId', 'id', 'kind']);
    const raw = pinnedBody(C); assert.ok(raw?.auidCheck && raw.envelopes.length === 2, '서버 409 본문');
    const out = j(c1.r.body);
    assert.ok(!out.includes(raw.auidCheck) && !out.includes('auidCheck'), '대조값이 응답에'); for (const e of raw.envelopes) assert.ok(!out.includes(e.ct), '암호문이 응답에');
    assert.ok(!out.includes('"ct"') && !('cia' in c1.r.body));
    assert.ok(await C.kv.get('wrapperKey'), '요청 키가 남아야 한다'); assert.equal(await C.kv.get('registration'), undefined);
  });
  await t('C 복구(백업 패스키): derive 1회(cB) → 200, PPID = A 의 PPID, 발급에 기기 봉투, kv passkey.via = envelope — 저장소에 salt 가 없다', async () => {
    const envP = c1.r.body.recover.envelopes.find((e) => e.kind === 'passkey');
    const calls0 = C.calls; C.deriveIds.length = 0;
    const rc = await recoverLogin(C, { idToken: c1.idToken, envelopeId: envP.id });
    assert.equal(rc.r.status, 200, j(rc.r.body)); assert.equal(rc.v.status, 200, j(rc.v.body));
    assert.equal(C.calls - calls0, 1); assert.deepEqual(C.deriveIds, [credB.cid]); assert.equal(rc.PPID, PPID_BAK);
    const last = C.issues().at(-1).body; assert.equal(last.envelope.kind, 'device'); assert.equal(last.envelope.credentialId, C.cid);
    const pk = await C.kv.get('passkey'); assert.equal(pk.via, 'envelope'); assert.equal(pk.credentialId, C.cid); assert.equal(pk.envelope.id, last.envelope.id); assert.equal(pk.envelope.ct, last.envelope.ct);
    assert.equal(await C.kv.get('wrapperKey'), undefined); assert.ok(!(await C.dump()).includes(BA.salt), 'salt 가 남았다');
  });
  await t('C 의 다음 로그인: derive 1회(cC — 로컬 봉투), 같은 PPID', async () => {
    const calls0 = C.calls; C.deriveIds.length = 0;
    const n = await wlogin(C, 'g-bak');
    assert.equal(n.r.status, 200, j(n.r.body)); assert.equal(n.v.status, 200, j(n.v.body));
    assert.equal(C.calls - calls0, 1); assert.deepEqual(C.deriveIds, [C.cid]); assert.equal(n.PPID, PPID_BAK);
  });
  await t('A 가 C 의 기기 봉투를 지운다(Review Focus 4) → 목록에 백업 2개만, C 는 로컬 사본으로 계속 같은 PPID — 지우기도 패스키를 한 번 묻고 auid 를 싣는다(최종 검토 I-1)', async () => {
    const devId = (await C.kv.get('passkey')).envelope.id;
    const calls0 = BA.calls; BA.sent.length = 0;
    const rm = await BA.core.wrapperEnvelopeRemove({ idToken: await tokenFor(BA, 'g-bak'), id: devId });
    assert.equal(rm.status, 200, j(rm.body)); assert.equal(BA.calls - calls0, 1, '지우기는 패스키 한 번');
    const auidBA = (await auidOf({ s_u: BigInt(BA.salt) })).toString();
    const sentRm = BA.sent.filter((x) => x.url.endsWith('/cia/wrapper/envelope')); assert.equal(sentRm.length, 1); assert.equal(sentRm[0].body.auid, auidBA, '삭제 요청에 계정 auid');
    assert.ok(!j(rm.body).includes(auidBA), '응답에 auid 가 있다'); assert.equal(rm.body.envelopes.length, 2); assert.equal(rm.body.envelopes.some((e) => e.kind === 'device' || e.id === devId), false);
    assert.deepEqual(await BA.kv.get('envelopes'), rm.body.envelopes); assert.equal(await BA.kv.get('wrapperKey'), undefined);
    const n = await wlogin(C, 'g-bak');
    assert.equal(n.r.status, 200, j(n.r.body)); assert.equal(n.PPID, PPID_BAK);
  });
  await t('지우기에서 패스키 창을 취소하면 passkey_cancelled — 서버로 보내지 않고 요청 키가 남아 다시 하면 된다(최종 검토 I-1)', async () => {
    const id = (await BA.kv.get('envelopes'))[0].id;
    const idToken = await tokenFor(BA, 'g-bak');
    BA.cancelNext = true; BA.sent.length = 0;
    const r = await BA.core.wrapperEnvelopeRemove({ idToken, id });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'passkey_cancelled'); assert.ok(await BA.kv.get('wrapperKey'), '요청 키가 남아야 한다');
    assert.equal(BA.sent.some((x) => x.url.endsWith('/cia/wrapper/envelope')), false, '취소했는데 서버로 갔다');
    await BA.kv.del('wrapperKey');   // 다음 사례는 새 요청 키로 — 이 키로는 지우지 않는다(백업 2개를 뒤 사례가 쓴다)
  });
  await t('앞선 409 없이 wrapperLoginRecover → 409 recover_offer_missing — 패스키를 묻지 않는다', async () => {
    const calls0 = BA.calls;
    const r = await BA.core.wrapperLoginRecover(loginBody(await challenge()), { idToken: await tokenFor(BA, 'g-bak'), verifiedOrigin: info.origin, envelopeId: '0'.repeat(32) });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'recover_offer_missing'); assert.equal(BA.calls, calls0);
  });
  await t('새로 만든 패스키 [I5]: salt·envKey 를 넘긴 wrapperLogin → 409 → 복구 코드 → 200(derive 0회), 다음 로그인은 그 패스키 한 번으로 같은 PPID', async () => {
    const CODE_E = newRecoveryCode();
    const own = await owner('g-rec-e', { cid: 'Y2lkLUVB', backups: [{ kind: 'code', code: CODE_E }] });
    const credE = mkCred('Y2lkLUVF');
    const E = browser(credE.s_u, credE.cid, Date.now, { prf: credE.prf });
    await E.core.passkeyConnect({ credentialId: E.cid, s_u: E.salt });
    const idToken = await tokenFor(E, 'g-rec-e');
    const r1 = await E.core.wrapperLogin(loginBody(await challenge()), { idToken, verifiedOrigin: info.origin, salt: E.salt, envKey: await envKeyFromPrf(credE.prf) });
    assert.equal(r1.status, 409, j(r1.body)); assert.equal(r1.body.reason, 'auid_pinned'); assert.equal(r1.body.recover.envelopes.length, 1);
    const rc = await recoverLogin(E, { idToken, envelopeId: r1.body.recover.envelopes[0].id, code: CODE_E.toLowerCase() });
    assert.equal(rc.r.status, 200, j(rc.r.body)); assert.equal(rc.v.status, 200, j(rc.v.body)); assert.equal(E.calls, 0, '패스키를 묻지 않는다'); assert.equal(rc.PPID, own.PPID);
    const n = await wlogin(E, 'g-rec-e');
    assert.equal(n.r.status, 200, j(n.r.body)); assert.equal(E.calls, 1); assert.equal(n.PPID, own.PPID);
    assert.ok(!(await E.dump()).includes(CODE_E), '코드가 남았다');
  });
  await t('첫 시도의 패스키가 바로 백업 패스키 [I4]: 다시 묻지 않고(derive 추가 0회) 200 — 기기 봉투를 보내지 않아 서버 봉투 수 그대로, 다음 로그인도 같은 PPID', async () => {
    const credBF = mkCred('Y2lkLUJG');
    const own = await owner('g-rec-f', { cid: 'Y2lkLUZB', backups: [{ kind: 'passkey', cred: credBF }] });
    const F = browser(credBF.s_u, credBF.cid, Date.now, { prf: credBF.prf });
    await F.core.passkeyConnect({ credentialId: F.cid, s_u: F.salt });
    const f1 = await wlogin(F, 'g-rec-f'); assert.equal(f1.r.status, 409, j(f1.r.body)); assert.equal(F.calls, 1);
    const rc = await recoverLogin(F, { idToken: f1.idToken, envelopeId: f1.r.body.recover.envelopes[0].id });
    assert.equal(rc.r.status, 200, j(rc.r.body)); assert.equal(rc.v.status, 200, j(rc.v.body)); assert.equal(F.calls, 1, '다시 묻지 않는다'); assert.equal(rc.PPID, own.PPID);
    assert.equal('envelope' in F.issues().at(-1).body, false, '기기 봉투를 보내지 않는다');
    const pk = await F.kv.get('passkey'); assert.equal(pk.via, 'envelope'); assert.equal(pk.envelope.id, f1.r.body.recover.envelopes[0].id);
    const probe = browser(undefined, 'Y2lkLVBy'); await probe.core.passkeyConnect({ credentialId: probe.cid, s_u: probe.salt });
    const p = await wlogin(probe, 'g-rec-f'); assert.equal(p.r.status, 409, j(p.r.body)); assert.equal(p.r.body.recover.envelopes.length, 1, '서버 봉투 수 그대로');
    const n = await wlogin(F, 'g-rec-f'); assert.equal(n.r.status, 200, j(n.r.body)); assert.equal(F.calls, 2); assert.equal(n.PPID, own.PPID);
  });
  let D = null, d1 = null;
  const CODE_D = newRecoveryCode();
  await t('복구 코드가 틀리면: 한 글자 → recovery_code_typo, 검사 문자까지 맞는 다른 코드 → envelope_open_failed — 발급 요청을 보내지 않고 요청 키는 남는다. 맞는 코드 → 200', async () => {
    const own = await owner('g-rec-d', { cid: 'Y2lkLURB', backups: [{ kind: 'code', code: CODE_D }] });
    D = browser(undefined, 'Y2lkLUQ'); await D.core.passkeyConnect({ credentialId: D.cid, s_u: D.salt });
    d1 = await wlogin(D, 'g-rec-d'); assert.equal(d1.r.status, 409, j(d1.r.body));
    const envelopeId = d1.r.body.recover.envelopes[0].id;
    const typo = (CODE_D[0] === 'A' ? 'B' : 'A') + CODE_D.slice(1);
    const r1 = await recoverLogin(D, { idToken: d1.idToken, envelopeId, code: typo }); assert.equal(r1.r.body.reason, 'recovery_code_typo', j(r1.r.body));
    const r2 = await recoverLogin(D, { idToken: d1.idToken, envelopeId, code: newRecoveryCode() }); assert.equal(r2.r.body.reason, 'envelope_open_failed', j(r2.r.body));
    assert.equal(D.issues().length, 1, '발급 요청은 첫 시도 한 번뿐'); assert.ok(await D.kv.get('wrapperKey'));
    const ok = await recoverLogin(D, { idToken: d1.idToken, envelopeId, code: CODE_D });
    assert.equal(ok.r.status, 200, j(ok.r.body)); assert.equal(ok.v.status, 200, j(ok.v.body)); assert.equal(ok.PPID, own.PPID); assert.equal(D.issues().length, 2);
  });
  await t('봉투 바꿔치기(Review Focus 3): 409 본문의 봉투를 다른 계정 것으로 → 그 계정의 코드로도 envelope_open_failed, 발급 없음', async () => {
    const S = browser(undefined, 'Y2lkLVM'); await S.core.passkeyConnect({ credentialId: S.cid, s_u: S.salt });
    const foreign = pinnedBody(C).envelopes;
    S.rewrite = (u, body) => (u.endsWith('/cia/issue') && body.reason === 'auid_pinned' ? { ...body, envelopes: foreign } : null);
    const s1 = await wlogin(S, 'g-rec-d'); assert.equal(s1.r.status, 409, j(s1.r.body)); assert.equal(s1.r.body.recover.envelopes.length, 2);
    const codeEnv = s1.r.body.recover.envelopes.find((e) => e.kind === 'code');
    const r = await recoverLogin(S, { idToken: s1.idToken, envelopeId: codeEnv.id, code: CODE });
    assert.equal(r.r.status, 409, j(r.r.body)); assert.equal(r.r.body.reason, 'envelope_open_failed'); assert.equal(S.issues().length, 1);
  });
  await t('대조값이 맞지 않으면 [I1]: 맞는 코드로 봉투를 열어도 409 recover_auid_mismatch — 발급을 보내지 않는다', async () => {
    // credential ID 는 기기마다 다르다(같으면 I4 로 그 기기 봉투를 고른다) — 앞 사례의 브라우저들과 겹치지 않게 준다
    const S = browser(undefined, 'Y2lkLVMy'); await S.core.passkeyConnect({ credentialId: S.cid, s_u: S.salt });
    S.rewrite = (u, body) => (u.endsWith('/cia/issue') && body.reason === 'auid_pinned' ? { ...body, auidCheck: '0'.repeat(64) } : null);
    const s1 = await wlogin(S, 'g-rec-d'); assert.equal(s1.r.status, 409, j(s1.r.body));
    const codeEnv = s1.r.body.recover.envelopes.find((e) => e.kind === 'code');
    const r = await recoverLogin(S, { idToken: s1.idToken, envelopeId: codeEnv.id, code: CODE_D });
    assert.equal(r.r.status, 409, j(r.r.body)); assert.equal(r.r.body.reason, 'recover_auid_mismatch'); assert.equal(S.issues().length, 1);
  });
  await t('복구 중 백업 패스키 창을 취소(Review Focus 2) → passkey_cancelled, 요청 키가 남아 다시 하면 200', async () => {
    const credBG = mkCred('Y2lkLUJH');
    const own = await owner('g-rec-g', { cid: 'Y2lkLUdB', backups: [{ kind: 'passkey', cred: credBG }] });
    const G = browser(undefined, 'Y2lkLUc', Date.now, { extra: [credBG] });
    await G.core.passkeyConnect({ credentialId: G.cid, s_u: G.salt });
    const g1 = await wlogin(G, 'g-rec-g'); assert.equal(g1.r.status, 409, j(g1.r.body));
    const envelopeId = g1.r.body.recover.envelopes[0].id;
    G.cancelNext = true;
    const r1 = await recoverLogin(G, { idToken: g1.idToken, envelopeId });
    assert.equal(r1.r.status, 409, j(r1.r.body)); assert.equal(r1.r.body.reason, 'passkey_cancelled'); assert.ok(await G.kv.get('wrapperKey')); assert.equal(G.issues().length, 1);
    const ok = await recoverLogin(G, { idToken: g1.idToken, envelopeId });
    assert.equal(ok.r.status, 200, j(ok.r.body)); assert.equal(ok.PPID, own.PPID);
  });
  await t('발급이 받아들여진 뒤 실패해도(체인이 끊겨 503) 로컬 봉투 사본을 남긴다 — 요청 키는 지우고, 다음 로그인은 패스키 한 번으로 같은 PPID', async () => {
    const CODE_H = newRecoveryCode();
    const own = await owner('g-rec-h', { cid: 'Y2lkLUhB', backups: [{ kind: 'code', code: CODE_H }] });
    const H = browser(undefined, 'Y2lkLUg', Date.now, { chainDownAfterIssue: true });
    await H.core.passkeyConnect({ credentialId: H.cid, s_u: H.salt });
    const h1 = await wlogin(H, 'g-rec-h'); assert.equal(h1.r.status, 409, j(h1.r.body)); assert.equal(H.chainDown, false);
    const rc = await recoverLogin(H, { idToken: h1.idToken, envelopeId: h1.r.body.recover.envelopes[0].id, code: CODE_H });
    assert.equal(rc.r.status, 503, j(rc.r.body)); assert.equal(rc.r.body.reason, 'chain_unavailable'); assert.equal(H.chainDown, true, '발급은 200 이었다');
    const pk = await H.kv.get('passkey'); assert.equal(pk.via, 'envelope', '로컬 사본이 없다'); assert.equal(pk.envelope.id, H.issues().at(-1).body.envelope.id);
    assert.equal((await H.kv.get('registration')).pendingIdp, false); assert.equal(await H.kv.get('wrapperKey'), undefined, '쓴 토큰의 요청 키가 남았다');
    H.chainDown = false;
    const calls0 = H.calls;
    const n = await wlogin(H, 'g-rec-h');
    assert.equal(n.r.status, 200, j(n.r.body)); assert.equal(n.v.status, 200, j(n.v.body)); assert.equal(H.calls - calls0, 1); assert.equal(n.PPID, own.PPID);
  });
  // 2026-11-24 최종 검토 I-2: 로컬 사본은 대조가 맞은 바로 뒤, 발급을 보내기 전에 쓴다 — login 이 던지거나(증명 중 창이 닫힘·서비스 창의 300초) 받아들여지지 않아도 사본은 검증된 salt 다.
  await t('발급이 받아들여진 뒤 login 이 던져도(증명 중 창이 닫힘 — 최종 검토 I-2) 로컬 사본이 있다 — 요청 키는 지우고, 다음 wrapperLogin 은 패스키 한 번으로 같은 PPID', async () => {
    const CODE_I = newRecoveryCode();
    const own = await owner('g-rec-i', { cid: 'Y2lkLUlB', backups: [{ kind: 'code', code: CODE_I }] });
    const I = browser(undefined, 'Y2lkLUk', Date.now, { throwAfterIssue: true });
    await I.core.passkeyConnect({ credentialId: I.cid, s_u: I.salt });
    const i1 = await wlogin(I, 'g-rec-i'); assert.equal(i1.r.status, 409, j(i1.r.body));
    // login 이 던진 오류는 op 경계(guard)가 500 internal 로 바꾼다 — 그 앞의 단계(사본·되돌림)는 던진 오류가 건너뛴다
    let threw = null, out = null;
    try { out = (await recoverLogin(I, { idToken: i1.idToken, envelopeId: i1.r.body.recover.envelopes[0].id, code: CODE_I })).r; } catch (e) { threw = e; }
    assert.ok(/창이 닫혔다/.test(threw?.message ?? out?.body?.detail ?? ''), `증명에서 던진 오류가 아니다: ${threw?.message ?? j(out)}`);
    assert.equal(I.recv.filter((x) => x.url.endsWith('/cia/issue') && x.status === 200).length, 1, '발급은 200 이었다');
    const pk = await I.kv.get('passkey'); assert.equal(pk?.via, 'envelope', '로컬 사본이 없다'); assert.equal(pk.envelope.id, I.issues().at(-1).body.envelope.id);
    assert.equal(await I.kv.get('wrapperKey'), undefined, '쓴 토큰의 요청 키가 남았다');
    const calls0 = I.calls;
    const n = await wlogin(I, 'g-rec-i');
    assert.equal(n.r.status, 200, j(n.r.body)); assert.equal(n.v.status, 200, j(n.v.body)); assert.equal(I.calls - calls0, 1); assert.equal(n.PPID, own.PPID);
  });
  await t('발급 서버에 닿지 못한 복구(받아들여지지 않음, 최종 검토 I-2): 로컬 등록은 되돌리고 요청 키는 남는다 — 로컬 사본은 남아 다음 wrapperLogin 이 그 사본으로 같은 PPID', async () => {
    const CODE_J = newRecoveryCode();
    const own = await owner('g-rec-j', { cid: 'Y2lkLUpB', backups: [{ kind: 'code', code: CODE_J }] });
    const J = browser(undefined, 'Y2lkLUo');
    await J.core.passkeyConnect({ credentialId: J.cid, s_u: J.salt });
    const j1 = await wlogin(J, 'g-rec-j'); assert.equal(j1.r.status, 409, j(j1.r.body));
    J.blockIssue = true;
    const rc = await recoverLogin(J, { idToken: j1.idToken, envelopeId: j1.r.body.recover.envelopes[0].id, code: CODE_J });
    assert.notEqual(rc.r.status, 200, j(rc.r.body)); assert.equal(J.blockIssue, false, '발급 요청을 보내려 했다');
    assert.equal(await J.kv.get('registration'), undefined, '받아들여지지 않은 로컬 등록이 남았다'); assert.ok(await J.kv.get('wrapperKey'), '요청 키가 남아야 한다 [m2]');
    assert.equal((await J.kv.get('passkey'))?.via, 'envelope', '로컬 사본이 없다');
    assert.ok(!(await J.dump()).includes(CODE_J), '코드가 남았다');
    const calls0 = J.calls;
    const n = await wlogin(J, 'g-rec-j');
    assert.equal(n.r.status, 200, j(n.r.body)); assert.equal(n.v.status, 200, j(n.v.body)); assert.equal(J.calls - calls0, 1); assert.equal(n.PPID, own.PPID);
  });
  await t('백업 패스키 대신 다른 패스키를 고르면 envelope_credential_mismatch — 발급을 보내지 않고 요청 키가 남아, 맞는 패스키로 다시 하면 200', async () => {
    const credBK = mkCred('Y2lkLUJL');
    const own = await owner('g-rec-k', { cid: 'Y2lkLUtB', backups: [{ kind: 'passkey', cred: credBK }] });
    const K = browser(undefined, 'Y2lkLUs', Date.now, { extra: [credBK] });
    await K.core.passkeyConnect({ credentialId: K.cid, s_u: K.salt });
    const k1 = await wlogin(K, 'g-rec-k'); assert.equal(k1.r.status, 409, j(k1.r.body));
    const envelopeId = k1.r.body.recover.envelopes[0].id;
    K.swapNext = K.cid;
    const r1 = await recoverLogin(K, { idToken: k1.idToken, envelopeId });
    assert.equal(r1.r.status, 409, j(r1.r.body)); assert.equal(r1.r.body.reason, 'envelope_credential_mismatch');
    assert.equal(K.issues().length, 1, '발급을 보냈다'); assert.ok(await K.kv.get('wrapperKey'), '요청 키가 남아야 한다');
    const ok = await recoverLogin(K, { idToken: k1.idToken, envelopeId });
    assert.equal(ok.r.status, 200, j(ok.r.body)); assert.equal(ok.v.status, 200, j(ok.v.body)); assert.equal(ok.PPID, own.PPID);
  });
  await t('래퍼 설정이 아닌 코어에서는 wrapperBegin·wrapperLogin 이 409 not_wrapper_mode', async () => {
    const kv = createMemKv();
    const core = createUserCore({ kv, config: { ...config, wrapper: false }, provider, canonProvider: provider, fullProve, passkey: { derive: async () => ({}) } });
    assert.equal((await core.wrapperBegin()).body.reason, 'not_wrapper_mode');
    assert.equal((await core.wrapperLogin({}, { idToken: 'a.b.c' })).body.reason, 'not_wrapper_mode');
    assert.equal((await core.wrapperLoginRecover({}, { idToken: 'a.b.c' })).body.reason, 'not_wrapper_mode');
    assert.equal((await core.wrapperEnvelopeAdd({ idToken: 'a.b.c', kind: 'code' })).body.reason, 'not_wrapper_mode');
    assert.equal((await core.wrapperEnvelopeRemove({ idToken: 'a.b.c', id: '0'.repeat(32) })).body.reason, 'not_wrapper_mode');
  });
} finally { await stack.stop(); }
console.log(fails ? `\n${fails} 실패` : '\n모두 통과');
process.exit(fails ? 1 : 0);
