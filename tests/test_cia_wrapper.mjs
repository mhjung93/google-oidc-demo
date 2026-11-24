// tests/test_cia_wrapper.mjs — 발급 서버의 래퍼 방식(CIA_WRAPPER=1, 스펙 2026-11-20 zkwrapper §2.2·§3·§10). 격리 IdP + Google 대역 발급자. :8545·build/mode3 필요. (chain)
// 본인 확인은 Google ID 토큰이다(π_IdP 없음). 토큰은 1회용 요청 키에 묶인다 — nonce = wrapperNonce(pk_e), 본문에 pk_e 의 서명. 받은 세션 토큰으로 π_RP 를 만들어 서비스 검증까지 간다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createRegistration, createSessionKey, buildWrapperIssueBody, signChallenge, VKEY_PATH } from '../lib/mode3_wallet.js';
import { uidOf } from '../lib/mode3_oidc_nonce.js';
import { randomScalar } from '../lib/mode3_credential.js';
import { createRpVerifier } from '../lib/mode3_rp.js';
import { PUB_INDEX } from '../lib/mode3_onchain.js';
import { signOpenRequest } from '../lib/mode3_opening.js';
import { generateRequestKey, wrapperNonce, signIssue, signDigest, revokeDigest, issueDigest } from '../lib/mode3_wrapper_auth.js';
import { proveV11, TESTUSER_ATTRS } from './helpers/mode3_flow.mjs';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = getProvider();
const cia = await startIsolatedCia({ wrapper: true });
const stub = cia.oidc, AUD = cia.base;
const accounts = async () => { const a = (await cia.adminGet('/cia/accounts')).body; return a.accounts ?? a; };
const acctOf = async (uid) => (await accounts()).find((a) => String(a.uid) === String(uid)) ?? null;
/** 한 사람 = Google 계정(sub) + 패스키(seed → s_u). uid 는 래퍼가 sub 에서 정한다. */
async function person(sub, seed = null) {
  const uid = uidOf(stub.provider, sub);
  const reg = seed === null ? await createRegistration(BigInt(uid)) : await createRegistration(BigInt(uid), Buffer.from(seed, 'hex'));
  return { sub, uid: BigInt(uid), s_u: reg.s_u, auid: reg.auid, seed: reg.seed, attrs: [...TESTUSER_ATTRS], blind_u: randomScalar(), slot: null };
}
/** 브라우저가 하는 일: 요청 키 → 그 키의 nonce 로 Google 토큰 → 본문 → 서명 → /cia/issue. opts 로 한 부분씩 어긋나게 만든다. */
async function wrapIssue(who, svc, { key = null, tokenKey = null, token = null, mutate = null, sign = true, blind_u = who.blind_u, email = `${who.sub}@example.com`, r_s = randomScalar(), r_rp = randomScalar() } = {}) {
  const k = key ?? await generateRequestKey();
  const id_token = token ?? await stub.mint({ sub: who.sub, nonce: await wrapperNonce((tokenKey ?? k).pkE), extra: { email, email_verified: true } });
  const session = createSessionKey();
  const max_height = BigInt(await provider.getBlockNumber()) + 300n;
  const built = await buildWrapperIssueBody({ uid: who.uid, s_u: who.s_u, blind_u, attrs: who.attrs, arid: BigInt(svc.arid), r_rp, r_s, session, chainid: 31337n, allowAgent: 0n, max_height });
  const sig = sign ? await signIssue(k.privateKey, built.body, AUD) : undefined;
  const body = { id_token, pk_e: k.pkE, ...(sig ? { sig } : {}), ...built.body };
  if (mutate) mutate(body);
  const r = await cia.post('/cia/issue', body);
  return { r, cred: r.body, req: built, session, r_s, r_rp, blind_u, user: who, key: k, id_token };
}
try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  const S1 = await cia.registerRp('http://127.0.0.1:3101', 's1'), S2 = await cia.registerRp('http://127.0.0.1:3102', 's2');
  const rp1 = createRpVerifier({ provider, logAddress: cia.logAddress, vkey, pkCIA: pk_CIA, arid: BigInt(S1.arid), chainId: 31337n, pkTrace: S1.pk_trace });
  const login = async (iss, svc = S1, verifier = rp1) => {
    const out = await proveV11(iss, { arid: svc.arid, pk_CIA, provider, logAddress: cia.logAddress });
    const v = await verifier.verifyLogin({ proof: out.proof, publicSignals: out.publicSignals, sig: await signChallenge(iss.session.wallet, iss.r_s.toString()), r_s: iss.r_s, r_rp: iss.r_rp });
    return { ...out, v };
  };
  const alice = await person('g-alice');
  let first;

  await t('public_keys: wrapper 표시와 Google 로 갈 주소·돌아올 주소', async () => {
    assert.equal(keys.wrapper, true); assert.equal(keys.oidc.enabled, true);
    assert.equal(typeof keys.oidc.authorizeUrl, 'string'); assert.equal(keys.oidc.redirectUri, 'https://127.0.0.1:5100/google-relay');
  });
  await t('첫 발급: 계정이 생기고(auid 고정·슬롯 배정) 세션 토큰이 나온다 — 본문에 uid·n·tag·proof_idp 가 없다', async () => {
    assert.equal(await acctOf(alice.uid), null);
    first = await wrapIssue(alice, S1);
    assert.equal(first.r.status, 200, j(first.r.body));
    for (const k of ['uid', 'n', 'tag', 'proof_idp', 'registration']) assert.equal(k in first.req.body, false, `본문에 ${k} 가 있다`);
    assert.equal(first.cred.uid, alice.uid.toString()); assert.equal(typeof first.cred.slot, 'number'); assert.equal(first.cred.email, 'g-alice@example.com');
    assert.equal(first.cred.Cf_u, first.req.Cf_u.toString()); assert.equal(first.cred.Cf_s, first.req.Cf_s.toString()); assert.ok(first.cred.sigma?.S);
    const a = await acctOf(alice.uid);
    assert.equal(a.auid, alice.auid.toString()); assert.equal(a.id, 'g-alice@example.com'); assert.equal(a.lastAuidS.value, first.req.auid_s.toString());
    alice.slot = first.cred.slot;
  });
  await t('그 토큰으로 π_RP 가 만들어지고 서비스 검증을 통과한다 — π_IdP 없이 끝까지', async () => {
    const out = await login(first);
    assert.equal(out.v.ok, true, j(out.v)); assert.equal(out.publicSignals[PUB_INDEX.AUID_S], first.req.auid_s.toString());
  });
  await t('두 번째 발급: 같은 auid·같은 C_u 면 200, 같은 PPID 로 로그인된다', async () => {
    const second = await wrapIssue(alice, S1);
    assert.equal(second.r.status, 200, j(second.r.body)); assert.equal(second.cred.slot, alice.slot);
    const a = await login(first), b = await login(second);
    assert.equal(b.v.ok, true, j(b.v)); assert.equal(b.publicSignals[PUB_INDEX.PPID], a.publicSignals[PUB_INDEX.PPID]);
  });
  await t('같은 Google 계정이 다른 패스키(다른 auid)로 오면 409 auid_pinned — 계정의 auid·등록부는 그대로', async () => {
    const other = await person('g-alice');   // 같은 sub, 다른 salt
    const before = await acctOf(alice.uid), state0 = (await cia.get('/cia/state')).body;
    const r = (await wrapIssue(other, S1)).r;
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'auid_pinned');
    const after = await acctOf(alice.uid);
    assert.equal(after.auid, before.auid); assert.equal(after.activeCf_u, before.activeCf_u); assert.equal((await cia.get('/cia/state')).body.regRoot, state0.regRoot);
  });
  await t('토큰이 다른 요청 키의 것이면 400 wrapper_nonce_mismatch, 서명이 없거나 다른 키의 것이면 400 wrapper_bad_signature — 계정이 생기지 않는다', async () => {
    const bob = await person('g-bob'); const k1 = await generateRequestKey(), k2 = await generateRequestKey();
    let r = (await wrapIssue(bob, S1, { key: k1, tokenKey: k2 })).r;
    assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, 'wrapper_nonce_mismatch');
    r = (await wrapIssue(bob, S1, { sign: false })).r; assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, 'wrapper_bad_signature');
    const stolen = await signIssue(k2.privateKey, { ...first.req.body }, AUD);
    r = (await wrapIssue(bob, S1, { key: k1, mutate: (b) => { b.sig = stolen; } })).r; assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, 'wrapper_bad_signature');
    assert.equal(await acctOf(bob.uid), null);
  });
  await t('서명한 뒤 본문을 바꾸면(auid_s·C_s·max_height) 거절한다', async () => {
    const bob = await person('g-bob2');
    for (const mutate of [(b) => { b.auid_s = (BigInt(b.auid_s) + 1n).toString(); }, (b) => { b.max_height = (BigInt(b.max_height) + 1n).toString(); }, (b) => { b.C_s_pt = { ...first.req.body.C_s_pt }; }]) {
      const r = (await wrapIssue(bob, S1, { mutate })).r; assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, 'wrapper_bad_signature');
    }
    assert.equal(await acctOf(bob.uid), null);
  });
  await t('같은 토큰을 두 번 쓰지 못한다 — 두 번째는 409 wrapper_token_used', async () => {
    const carol = await person('g-carol'); const k = await generateRequestKey();
    const a = await wrapIssue(carol, S1, { key: k }); assert.equal(a.r.status, 200, j(a.r.body));
    const b = await wrapIssue(carol, S1, { key: k, token: a.id_token }); assert.equal(b.r.status, 409, j(b.r.body)); assert.equal(b.r.body.reason, 'wrapper_token_used');
  });
  await t('남의 auid_s 로는 발급받지 못한다(409 auid_s_taken) — 그 계정의 기록에 남지 않고, 같은 계정의 같은 auid_s 는 받는다', async () => {
    const mallory = await person('g-mallory');
    const m0 = await wrapIssue(mallory, S1); assert.equal(m0.r.status, 200, j(m0.r.body));
    const X = first.req.auid_s.toString();
    const r = (await wrapIssue(mallory, S1, { mutate: null, r_rp: first.r_rp, r_s: randomScalar(), blind_u: mallory.blind_u, key: null, ...{ } })).r;   // 정상 요청(자기 가명) — 통과해야 한다
    assert.equal(r.status, 200, j(r.body));
    const k = await generateRequestKey(); const session = createSessionKey();
    const built = await buildWrapperIssueBody({ uid: mallory.uid, s_u: mallory.s_u, blind_u: mallory.blind_u, attrs: mallory.attrs, arid: BigInt(S1.arid), r_rp: randomScalar(), r_s: randomScalar(), session, chainid: 31337n, allowAgent: 0n, max_height: BigInt(await provider.getBlockNumber()) + 300n });
    const forged = { ...built.body, auid_s: X };   // 주운 남의 세션 가명을 자기 요청에 넣는다
    const bad = await cia.post('/cia/issue', { id_token: await stub.mint({ sub: mallory.sub, nonce: await wrapperNonce(k.pkE), extra: { email: 'm@example.com', email_verified: true } }), pk_e: k.pkE, sig: await signIssue(k.privateKey, forged, AUD), ...forged });
    assert.equal(bad.status, 409, j(bad.body)); assert.equal(bad.body.reason, 'auid_s_taken');
    assert.notEqual((await acctOf(mallory.uid)).lastAuidS.value, X, '공격자의 기록에 남의 auid_s 가 남으면 안 된다');
  });
  await t('개봉: 서비스가 낸 로그인 증명의 auid_s 로 그 Google 계정의 uid 를 찾는다', async () => {
    const out = await login(first);
    const ts = String(Math.floor(Date.now() / 1000)), auid_s = out.publicSignals[PUB_INDEX.AUID_S], PPID = out.publicSignals[PUB_INDEX.PPID];
    const rq = await cia.post('/cia/open/request', { arid: S1.arid, publicSignals: out.publicSignals, proof: out.proof, ts, sig: await signOpenRequest(S1.serviceWallet, { arid: S1.arid, PPID, auid_s, ts }) });
    assert.ok(rq.status === 200 || rq.status === 202, j(rq.body));
    const ap = await cia.adminPost(`/cia/openings/${rq.body.id}/approve`); assert.equal(ap.status, 200, j(ap.body)); assert.equal(ap.body.resolved, true, j(ap.body));
    const o = (await cia.adminGet('/cia/openings')).body.openings.find((x) => x.id === rq.body.id);
    assert.equal(String(o.uid), alice.uid.toString(), j(o));
  });
  await t('한 패스키는 한 계정에만(R11 유지): 다른 Google 계정이 같은 auid 를 내면 409 auid_taken', async () => {
    const twin = await person('g-alice-second', alice.seed);
    const r = (await wrapIssue(twin, S1)).r; assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'auid_taken');
    assert.equal(await acctOf(twin.uid), null);
  });
  await t('폐기된 계정의 패스키도 그 계정의 것이다(2026-11-21 사용자 결정): 계정이 폐기된 뒤 다른 Google 계정이 같은 auid 를 내면 409 auid_taken — 관리자가 지우면 풀린다', async () => {
    const owner = await person('g-stolen-owner');
    assert.equal((await wrapIssue(owner, S1)).r.status, 200);
    assert.equal((await cia.adminPost('/cia/revoke', { uid: owner.uid.toString(), scope: 'account' })).status, 200);
    const thief = await person('g-stolen-thief', owner.seed);
    const r = (await wrapIssue(thief, S1)).r;
    assert.equal(r.status, 409, j(r.body) + ' — 장치를 훔친 사람이 새 Google 계정으로 같은 PPID 에 돌아오면 안 된다'); assert.equal(r.body.reason, 'auid_taken');
    assert.equal(await acctOf(thief.uid), null);
    assert.equal((await cia.adminPost('/cia/account/delete', { uid: owner.uid.toString() })).status, 200);
    assert.equal((await wrapIssue(thief, S1)).r.status, 200, '관리자가 지운 계정의 패스키는 다른 계정이 쓸 수 있다');
  });
  await t('다른 계정이 이미 낸 C_u 로는 발급받지 못한다(409 cf_u_taken) — 등록부는 그대로', async () => {
    const mallory = await person('g-mallory2');
    const regRoot0 = (await cia.get('/cia/state')).body.regRoot;
    const k = await generateRequestKey(); const session = createSessionKey();
    const built = await buildWrapperIssueBody({ uid: mallory.uid, s_u: mallory.s_u, blind_u: mallory.blind_u, attrs: mallory.attrs, arid: BigInt(S1.arid), r_rp: randomScalar(), r_s: randomScalar(), session, chainid: 31337n, allowAgent: 0n, max_height: BigInt(await provider.getBlockNumber()) + 300n });
    const body = { ...built.body, C_u_pt: { ...first.req.body.C_u_pt } };   // 남(alice)의 사용자 커밋먼트를 자기 요청에 넣는다
    const r = await cia.post('/cia/issue', { id_token: await stub.mint({ sub: mallory.sub, nonce: await wrapperNonce(k.pkE), extra: {} }), pk_e: k.pkE, sig: await signIssue(k.privateKey, body, AUD), ...body });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'cf_u_taken');
    assert.equal((await cia.get('/cia/state')).body.regRoot, regRoot0);
  });
  // 2026-11-24(사용자 결정): 첫 등록이 빈 속성이라 첫 로그인 직후 속성을 넣는 것이 보통의 흐름이다 — 계정이 처음 받은 C_u 의 첫 교체는 기다리지 않는다.
  // 그다음 교체부터 10분에 한 번(§10 I1 — 토큰 하나로 등록부를 계속 갈아 끼우지 못하게)은 그대로다.
  await t('C_u 를 바꾸는 발급(속성 변경): 처음 받은 C_u 의 첫 교체는 바로 되고, 10분 안에 또 바꾸면 429 cred_change_too_soon, 같은 C_u 의 재발급은 된다', async () => {
    const dave = await person('g-dave');
    assert.equal((await wrapIssue(dave, S1)).r.status, 200);
    const blind2 = randomScalar();
    const first = await wrapIssue(dave, S1, { blind_u: blind2 });   // 새 blind → 새 C_u(첫 교체)
    assert.equal(first.r.status, 200, j(first.r.body));
    const changed = await wrapIssue(dave, S1, { blind_u: randomScalar() });   // 두 번째 교체
    assert.equal(changed.r.status, 429, j(changed.r.body)); assert.equal(changed.r.body.reason, 'cred_change_too_soon');
    assert.equal((await wrapIssue(dave, S1, { blind_u: blind2 })).r.status, 200, '지금의 C_u 는 된다');
  });
  await t('틀린 auid(그 salt 의 것이 아님)로 등록하면 토큰은 나오지만 π_RP 를 만들 수 없다', async () => {
    const erin = await person('g-erin');
    const bogus = { ...erin, auid: erin.auid + 1n };
    const k = await generateRequestKey(); const session = createSessionKey(); const r_s = randomScalar(), r_rp = randomScalar();
    const built = await buildWrapperIssueBody({ uid: erin.uid, s_u: erin.s_u, blind_u: erin.blind_u, attrs: erin.attrs, arid: BigInt(S1.arid), r_rp, r_s, session, chainid: 31337n, allowAgent: 0n, max_height: BigInt(await provider.getBlockNumber()) + 300n });
    const body = { ...built.body, auid: bogus.auid.toString() };
    const r = await cia.post('/cia/issue', { id_token: await stub.mint({ sub: erin.sub, nonce: await wrapperNonce(k.pkE), extra: { email: 'e@example.com', email_verified: true } }), pk_e: k.pkE, sig: await signIssue(k.privateKey, body, AUD), ...body });
    assert.equal(r.status, 200, j(r.body));
    await assert.rejects(proveV11({ cred: r.body, user: { ...erin, slot: r.body.slot }, blind_u: erin.blind_u, r_rp, r_s, session }, { arid: S1.arid, pk_CIA, provider, logAddress: cia.logAddress }));
  });
  await t('부분군에 없는 점(C_u)은 400', async () => {
    const frank = await person('g-frank');
    const r = (await wrapIssue(frank, S1, { sign: true, mutate: null, blind_u: frank.blind_u, key: null })).r; assert.equal(r.status, 200, j(r.body));
    const k = await generateRequestKey(); const built = first.req.body; const bad = { ...built, auid: frank.auid.toString(), C_u_pt: { x: '1', y: '1' } };
    const x = await cia.post('/cia/issue', { id_token: await stub.mint({ sub: frank.sub, nonce: await wrapperNonce(k.pkE), extra: {} }), pk_e: k.pkE, sig: await signIssue(k.privateKey, bad, AUD), ...bad });
    assert.equal(x.status, 400, j(x.body));
  });
  await t('세션 폐기: 그 계정의 토큰 + 그 Cf_s 에 대한 서명이면 폐기된다 — 다른 계정의 토큰·다른 Cf_s 의 서명·발급용 서명은 거절', async () => {
    const gina = await person('g-gina'); const iss = await wrapIssue(gina, S1); assert.equal(iss.r.status, 200, j(iss.r.body));
    const Cf_s = iss.cred.Cf_s;
    const revoke = async ({ sub = gina.sub, sigFor = { scope: 'session', Cf_s }, sigOverride = null } = {}) => {
      const k = await generateRequestKey();
      const id_token = await stub.mint({ sub, nonce: await wrapperNonce(k.pkE), extra: {} });
      return cia.post('/cia/revoke', { scope: 'session', Cf_s, bound: '0', id_token, pk_e: k.pkE, sig: sigOverride ?? await signDigest(k.privateKey, revokeDigest(sigFor, AUD)) });
    };
    let r = await revoke({ sub: 'g-mallory' }); assert.ok(r.status === 403 || r.status === 404, j(r.body));
    r = await revoke({ sigFor: { scope: 'session', Cf_s: (BigInt(Cf_s) + 1n).toString() } }); assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, 'wrapper_bad_signature');
    r = await revoke({ sigFor: { scope: 'account' } }); assert.equal(r.status, 400, j(r.body));
    r = await revoke(); assert.equal(r.status, 200, j(r.body));
  });
  await t('동시 요청: 두 계정이 같은 auid_s 로 동시에 발급받으면(둘 다 새 C_u) 하나만 200, 다른 하나는 409 auid_s_taken — 두 기록에 함께 남지 않는다(최종 검토 C-1)', async () => {
    const p1 = await person('g-race-1'), p2 = await person('g-race-2');
    const r_rp = randomScalar(), session = createSessionKey(), mh = BigInt(await provider.getBlockNumber()) + 300n;
    const make = async (who, auid_s = null) => {
      const k = await generateRequestKey();
      const built = await buildWrapperIssueBody({ uid: who.uid, s_u: who.s_u, blind_u: who.blind_u, attrs: who.attrs, arid: BigInt(S1.arid), r_rp, r_s: randomScalar(), session, chainid: 31337n, allowAgent: 0n, max_height: mh });
      const body = { ...built.body, ...(auid_s ? { auid_s } : {}) };
      return { body: { id_token: await stub.mint({ sub: who.sub, nonce: await wrapperNonce(k.pkE), extra: {} }), pk_e: k.pkE, sig: await signIssue(k.privateKey, body, AUD), ...body }, auid_s: body.auid_s };
    };
    const a = await make(p1); const b = await make(p2, a.auid_s);
    const [ra, rb] = await Promise.all([cia.post('/cia/issue', a.body), cia.post('/cia/issue', b.body)]);
    const codes = [ra.status, rb.status].sort();
    assert.deepEqual(codes, [200, 409], `${ra.status} ${j(ra.body).slice(0, 120)} / ${rb.status} ${j(rb.body).slice(0, 120)}`);
    assert.equal((ra.status === 409 ? ra : rb).body.reason, 'auid_s_taken');
    const owners = (await accounts()).filter((x) => x.lastAuidS?.value === a.auid_s); assert.equal(owners.length, 1, '기록이 한 계정에만 있어야 한다');
  });
  await t('계정 자기 폐기(래퍼 방식): 그 계정의 토큰 + "계정 폐기" 서명이면 폐기된다 — 발급·세션 폐기용 서명, 같은 토큰 두 번은 거절(최종 검토 I-1)', async () => {
    const hana = await person('g-hana'); const iss = await wrapIssue(hana, S1); assert.equal(iss.r.status, 200, j(iss.r.body));
    const call = async ({ digestOf = () => revokeDigest({ scope: 'account' }, AUD), key = null, token = null } = {}) => {
      const k = key ?? await generateRequestKey();
      const id_token = token ?? await stub.mint({ sub: hana.sub, nonce: await wrapperNonce(k.pkE), extra: {} });
      return { r: await cia.post('/cia/account/self_revoke', { id_token, pk_e: k.pkE, sig: await signDigest(k.privateKey, digestOf()) }), k, id_token };
    };
    let x = await call({ digestOf: () => revokeDigest({ scope: 'session', Cf_s: iss.cred.Cf_s }, AUD) }); assert.equal(x.r.status, 400, j(x.r.body)); assert.equal(x.r.body.reason, 'wrapper_bad_signature');
    x = await call({ digestOf: () => issueDigest(iss.req.body, AUD) }); assert.equal(x.r.status, 400, j(x.r.body)); assert.equal(x.r.body.reason, 'wrapper_bad_signature');
    assert.equal((await acctOf(hana.uid)).disabled, false, '거절된 요청이 계정을 바꾸면 안 된다');
    const ok = await call(); assert.equal(ok.r.status, 200, j(ok.r.body)); assert.equal((await acctOf(hana.uid)).disabled, true);
    const again = await call({ key: ok.k, token: ok.id_token }); assert.equal(again.r.status, 409, j(again.r.body)); assert.equal(again.r.body.reason, 'wrapper_token_used');
  });
  await t('래퍼 방식에서 막힌 경로: 가입·비밀번호 로그인·등록·슬롯·증명 로그인·일반 OIDC 는 403 wrapper_mode', async () => {
    for (const [m, p, body] of [['post', '/cia/signup', { id: 'abc', pwd: 'password123' }], ['post', '/cia/user/login', { id: 'abc', pwd: 'x' }], ['post', '/cia/register', { uid: '1', pwd: 'x', auid: '1' }], ['post', '/cia/slot', { uid: '1', nonce: '1' }], ['post', '/cia/signup/reserve', {}], ['post', '/cia/user/login_challenge', {}], ['get', '/oidc/authorize?client_id=x', undefined]]) {
      const r = await cia[m](p, body); assert.equal(r.status, 403, `${p}: ${j(r.body)}`); assert.equal(r.body.reason, 'wrapper_mode', p);
    }
  });
  await t('막힌 경로는 대소문자·끝 슬래시를 바꿔도 막힌다(Express 는 그런 주소도 같은 경로로 받는다)', async () => {
    for (const [m, p, body] of [['post', '/CIA/Register', { uid: '1', pwd: 'x', auid: '1' }], ['post', '/cia/register/', { uid: '1', pwd: 'x', auid: '1' }], ['post', '/cia/Slot', { uid: '1', nonce: '1' }], ['post', '/cia/signup/', { id: 'abc', pwd: 'password123' }],
      ['post', '/Cia/User/Login', { id: 'abc', pwd: 'x' }], ['get', '/User', undefined], ['get', '/LOGIN/', undefined], ['get', '/OIDC/authorize?client_id=x', undefined]]) {
      const r = await cia[m](p, body); assert.equal(r.status, 403, `${p}: ${r.status} ${j(r.body).slice(0, 120)}`); assert.equal(r.body.reason, 'wrapper_mode', p);
    }
  });
} finally { await cia.stop(); }
// 기동 검사: 래퍼의 Google 클라이언트 ID 가 서비스의 것과 같으면 뜨지 않는다(스펙 §10 C2)
await t('기동 검사: 서비스와 같은 Google 클라이언트 ID 면 뜨지 않는다', async () => {
  let started = null;
  try { started = await startIsolatedCia({ wrapper: true, readyTimeoutMs: 8000, env: { MODE3_RP_GOOGLE_CLIENT_ID_DENY: 'other-id, mode3-test-client' } }); }
  catch (e) { assert.match(e.message, /래퍼는 전용 클라이언트 ID 가 필요하다/); return; }
  await started.stop();   // 떠 버렸으면 남기지 않는다
  assert.fail('서비스와 같은 클라이언트 ID 인데 떴다');
});
await t('기동 검사: 래퍼 방식은 MODE3_OIDC_CLIENT_ID 를 직접 줘야 한다 — Mode 1 공유 ID(GOOGLE_CLIENT_ID)로 떨어지지 않는다(최종 검토 I-2 a)', async () => {
  let started = null;
  try { started = await startIsolatedCia({ wrapper: true, readyTimeoutMs: 8000, env: { MODE3_OIDC_CLIENT_ID: '', GOOGLE_CLIENT_ID: 'mode3-test-client' } }); }
  catch (e) { assert.match(e.message, /MODE3_OIDC_CLIENT_ID 가 없다/); return; }
  await started.stop(); assert.fail('공유 ID 로 떴다');
});
await t('기동 검사: MODE3_OIDC_CLIENT_ID 가 GOOGLE_CLIENT_ID(Mode 1 공유 ID)와 같으면 뜨지 않는다(재검토 Minor)', async () => {
  let started = null;
  try { started = await startIsolatedCia({ wrapper: true, readyTimeoutMs: 8000, env: { GOOGLE_CLIENT_ID: 'mode3-test-client' } }); }
  catch (e) { assert.match(e.message, /GOOGLE_CLIENT_ID\(Mode 1 공유 ID\)와 같다/); return; }
  await started.stop(); assert.fail('공유 ID 와 같은 ID 로 떴다');
});
console.log(fails ? `\n${fails} 실패` : '\n모두 통과');
process.exit(fails ? 1 : 0);
