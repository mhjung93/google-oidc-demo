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
import { generateRequestKey, wrapperNonce, signIssue, signDigest, revokeDigest, issueDigest, envelopeDigest, linkDigest } from '../lib/mode3_wrapper_auth.js';
import { auidCheckOf, BACKUP_LIMIT, DEVICE_LIMIT } from '../lib/mode3_salt_envelope.js';
import { signLinkProof, linkKeyOf } from '../lib/mode3_link_key.js';
import { randomBytes } from 'node:crypto';
import { proveV11, TESTUSER_ATTRS } from './helpers/mode3_flow.mjs';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = getProvider();
const cia = await startIsolatedCia({ wrapper: true });
const stub = cia.oidc, AUD = cia.base;
const accounts = async () => { const a = (await cia.adminGet('/cia/accounts')).body; return a.accounts ?? a; };
const acctOf = async (uid) => (await accounts()).find((a) => String(a.uid) === String(uid)) ?? null;
// salt 봉투(2026-11-24 Task 2): 서버는 암호문을 열지 않는다 — 모양만 맞는 무작위 값으로 시험한다.
const b64 = (n) => randomBytes(n).toString('base64url');
const mkEnv = (kind, over = {}) => ({ id: randomBytes(16).toString('hex'), kind, credentialId: kind === 'code' ? null : b64(16), ct: b64(60), ...over });
/** 한 사람 = Google 계정(sub) + 패스키(seed → s_u). uid 는 래퍼가 sub 에서 정한다. */
async function person(sub, seed = null) {
  const uid = uidOf(stub.provider, sub);
  const reg = seed === null ? await createRegistration(BigInt(uid)) : await createRegistration(BigInt(uid), Buffer.from(seed, 'hex'));
  return { sub, uid: BigInt(uid), s_u: reg.s_u, auid: reg.auid, seed: reg.seed, attrs: [...TESTUSER_ATTRS], blind_u: randomScalar(), slot: null };
}
/** 브라우저가 하는 일: 요청 키 → 그 키의 nonce 로 Google 토큰 → 본문 → 서명 → /cia/issue. opts 로 한 부분씩 어긋나게 만든다. */
// envelope(2026-11-24 salt 봉투 Task 2): 발급 본문에 실을 기기 봉투 — 서명하는 글(issueDigest)에 들어간다.
async function wrapIssue(who, svc, { key = null, tokenKey = null, token = null, mutate = null, sign = true, blind_u = who.blind_u, email = `${who.sub}@example.com`, r_s = randomScalar(), r_rp = randomScalar(), envelope = null } = {}) {
  const k = key ?? await generateRequestKey();
  const id_token = token ?? await stub.mint({ sub: who.sub, nonce: await wrapperNonce((tokenKey ?? k).pkE), extra: { email, email_verified: true } });
  const session = createSessionKey();
  const max_height = BigInt(await provider.getBlockNumber()) + 300n;
  const built = await buildWrapperIssueBody({ uid: who.uid, s_u: who.s_u, blind_u, attrs: who.attrs, arid: BigInt(svc.arid), r_rp, r_s, session, chainid: 31337n, allowAgent: 0n, max_height });
  const signed = envelope ? { ...built.body, envelope } : built.body;
  const sig = sign ? await signIssue(k.privateKey, signed, AUD) : undefined;
  const body = { id_token, pk_e: k.pkE, ...(sig ? { sig } : {}), ...signed };
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
  // 2026-11-25(사용자 결정): C_u 교체의 최소 간격(§10 I1, 10분)을 없앴다 — 두 번째 교체도 바로 된다. 물린 C_u 로 되돌아가는 것(cred_revoked)은 그대로 막는다.
  await t('C_u 를 바꾸는 발급(속성 변경): 첫 교체도 두 번째 교체도 바로 되고, 같은 C_u 의 재발급은 되며, 물린 C_u 로는 돌아가지 못한다', async () => {
    const dave = await person('g-dave');
    assert.equal((await wrapIssue(dave, S1)).r.status, 200);
    const blind2 = randomScalar();
    const first = await wrapIssue(dave, S1, { blind_u: blind2 });   // 새 blind → 새 C_u(첫 교체)
    assert.equal(first.r.status, 200, j(first.r.body));
    const blind3 = randomScalar();
    const changed = await wrapIssue(dave, S1, { blind_u: blind3 });   // 두 번째 교체 — 바로 된다
    assert.equal(changed.r.status, 200, j(changed.r.body));
    assert.equal((await wrapIssue(dave, S1, { blind_u: blind3 })).r.status, 200, '지금의 C_u 는 된다');
    const back = await wrapIssue(dave, S1, { blind_u: blind2 });   // 물린(은퇴한) C_u 로 되돌리기
    assert.equal(back.r.status, 409, j(back.r.body)); assert.equal(back.r.body.reason, 'cred_revoked');
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
    const root0 = (await cia.get('/mode3/health')).body.root;
    r = await revoke(); assert.equal(r.status, 200, j(r.body));
    // 2026-11-24(구조 점검 4번): 래퍼 방식은 세션 폐기를 바로 게시한다 — 관리자 게시·하트비트를 기다리지 않는다
    assert.equal(r.body.published, true, j(r.body)); assert.equal(r.body.pending, 0, j(r.body));
    assert.notEqual((await cia.get('/mode3/health')).body.root, root0, '폐기했는데 root 가 바로 바뀌지 않았다');
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
  // ---- salt 봉투(계획 2026-11-24 zkwrapper salt-envelope Task 2) ----
  /** POST /cia/wrapper/envelope — 요청 키·그 키에 묶인 토큰·envelopeDigest 서명. key·token 을 주면 같은 요청 키·토큰을 다시 쓴다.
   *  auid(최종 검토 I-1): 기본은 그 사람의 auid(salt 를 안다). 다른 값을 주면 그 값을 서명해 보낸다, null 이면 싣지 않는다(서명 없이 — 모양 검사가 먼저다). */
  const envCall = async (who, req0, { key = null, token = null, signFor = null, auid = who.auid.toString() } = {}) => {
    const req = auid === null ? req0 : { ...req0, auid };
    const k = key ?? await generateRequestKey();
    const id_token = token ?? await stub.mint({ sub: who.sub, nonce: await wrapperNonce(k.pkE), extra: {} });
    const sig = auid === null ? 'A'.repeat(86) : await signDigest(k.privateKey, envelopeDigest(signFor ? { auid, ...signFor } : req, AUD));
    return { r: await cia.post('/cia/wrapper/envelope', { id_token, pk_e: k.pkE, sig, ...req }), k, id_token };
  };
  /** 계정의 봉투(암호문 포함) — 같은 Google 계정의 다른 패스키로 발급을 청해 409 auid_pinned 본문에서 읽는다(상태를 바꾸지 않는다). */
  const envelopesOf = async (who) => { const r = (await wrapIssue(await person(who.sub), S1)).r; assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'auid_pinned'); return r.body.envelopes; };
  await t('봉투 추가: 등록된 계정의 add(passkey) 는 200 이고 목록에 암호문이 없다 — 같은 토큰 두 번째는 409 wrapper_token_used', async () => {
    const ivy = await person('g-env-ivy'); assert.equal((await wrapIssue(ivy, S1)).r.status, 200);
    const P1 = mkEnv('passkey');
    const a = await envCall(ivy, { op: 'add', envelope: P1 });
    assert.equal(a.r.status, 200, j(a.r.body)); assert.equal(a.r.body.envelopes.length, 1);
    const [e] = a.r.body.envelopes; assert.deepEqual(Object.keys(e).sort(), ['createdAt', 'credentialId', 'id', 'kind']); assert.equal(e.id, P1.id); assert.equal(e.credentialId, P1.credentialId); assert.equal('ct' in e, false);
    const again = await envCall(ivy, { op: 'add', envelope: mkEnv('code') }, { key: a.k, token: a.id_token });
    assert.equal(again.r.status, 409, j(again.r.body)); assert.equal(again.r.body.reason, 'wrapper_token_used');
    const notReg = await envCall(await person('g-env-nobody'), { op: 'add', envelope: mkEnv('passkey') }); assert.equal(notReg.r.status, 404, j(notReg.r.body));
  });
  // 2026-11-24 최종 검토 I-1: Google 계정만 가진 사람은 409 auid_pinned 로 봉투 id 를 알아도 백업을 지우거나 한도를 채우지 못한다 — 추가·삭제는 계정의 auid(salt 를 아는 사람만 안다)를 서명해 싣는다.
  await t('봉투 추가·삭제의 auid 증명(I-1): auid 가 없으면 400 envelope_bad, 다른 auid 면 409 envelope_auid_mismatch — 둘 다 토큰을 쓰지 않아 같은 토큰으로 맞는 auid 면 된다; 응답에 auid 가 없다', async () => {
    const ola = await person('g-env-ola'); assert.equal((await wrapIssue(ola, S1)).r.status, 200);
    const thief = await person(ola.sub);   // 같은 Google 계정, 다른 패스키(다른 salt) — 봉투 id 는 409 에서 안다
    const P1 = mkEnv('passkey');
    const missing = await envCall(ola, { op: 'add', envelope: P1 }, { auid: null });
    assert.equal(missing.r.status, 400, j(missing.r.body)); assert.equal(missing.r.body.reason, 'envelope_bad');
    const wrong = await envCall(ola, { op: 'add', envelope: P1 }, { key: missing.k, token: missing.id_token, auid: thief.auid.toString() });
    assert.equal(wrong.r.status, 409, j(wrong.r.body)); assert.equal(wrong.r.body.reason, 'envelope_auid_mismatch');
    assert.equal(JSON.stringify(wrong.r.body).includes(ola.auid.toString()), false, '응답에 계정 auid 가 있다');
    const ok = await envCall(ola, { op: 'add', envelope: P1 }, { key: missing.k, token: missing.id_token });
    assert.equal(ok.r.status, 200, j(ok.r.body) + ' — 거절된 두 요청은 토큰을 쓰지 않는다'); assert.equal(ok.r.body.envelopes.length, 1);
    assert.equal(JSON.stringify(ok.r.body).includes(ola.auid.toString()), false, '응답에 auid 가 있다');
    // 서명은 auid 를 덮는다 — 맞는 auid 로 서명하고 본문의 auid 만 바꾸면 서명이 맞지 않는다
    const k2 = await generateRequestKey(); const t2 = await stub.mint({ sub: ola.sub, nonce: await wrapperNonce(k2.pkE), extra: {} });
    const sig2 = await signDigest(k2.privateKey, envelopeDigest({ op: 'remove', auid: ola.auid.toString(), id: P1.id }, AUD));
    const swapped = await cia.post('/cia/wrapper/envelope', { id_token: t2, pk_e: k2.pkE, sig: sig2, op: 'remove', auid: thief.auid.toString(), id: P1.id });
    assert.equal(swapped.status, 400, j(swapped.body)); assert.equal(swapped.body.reason, 'wrapper_bad_signature');
    // 삭제도 같다: 409 로 본 봉투 id 를 다른 salt 의 auid 로 지우려 하면 거절, 토큰은 남아 맞는 auid 로 지운다
    assert.equal((await envelopesOf(ola)).length, 1);
    const rmMissing = await envCall(thief, { op: 'remove', id: P1.id }, { auid: null }); assert.equal(rmMissing.r.status, 400, j(rmMissing.r.body)); assert.equal(rmMissing.r.body.reason, 'envelope_bad');
    const rmWrong = await envCall(thief, { op: 'remove', id: P1.id }, { key: rmMissing.k, token: rmMissing.id_token });
    assert.equal(rmWrong.r.status, 409, j(rmWrong.r.body)); assert.equal(rmWrong.r.body.reason, 'envelope_auid_mismatch');
    assert.equal((await envelopesOf(ola)).length, 1, '봉투가 그대로다');
    const rmOk = await envCall(ola, { op: 'remove', id: P1.id }, { key: rmMissing.k, token: rmMissing.id_token });
    assert.equal(rmOk.r.status, 200, j(rmOk.r.body)); assert.equal(rmOk.r.body.envelopes.length, 0);
    // 한도 채우기도 막힌다: 다른 auid 로는 백업 하나도 더하지 못한다
    assert.equal((await envCall(thief, { op: 'add', envelope: mkEnv('code') })).r.body.reason, 'envelope_auid_mismatch');
    assert.deepEqual(await envelopesOf(ola), []);
  });
  await t('auid_pinned(복구): 본문에 auid 가 없고 auidCheck = auidCheckOf(uid, 계정 auid)·봉투 암호문이 있다 — 같은 토큰·요청 키로 맞는 auid + 기기 봉투면 200, 봉투 +1; 봉투만 바꾸면 wrapper_bad_signature', async () => {
    const kim = await person('g-env-kim'); assert.equal((await wrapIssue(kim, S1)).r.status, 200);
    const P1 = mkEnv('passkey'); assert.equal((await envCall(kim, { op: 'add', envelope: P1 })).r.status, 200);
    const k = await generateRequestKey(); const T = await stub.mint({ sub: kim.sub, nonce: await wrapperNonce(k.pkE), extra: {} });
    const pinned = (await wrapIssue(await person(kim.sub), S1, { key: k, token: T })).r;   // 새 기기 — 다른 패스키(다른 salt)
    assert.equal(pinned.status, 409, j(pinned.body)); assert.equal(pinned.body.reason, 'auid_pinned');
    assert.equal('auid' in pinned.body, false, 'auid 는 싣지 않는다 [I1]'); assert.equal(JSON.stringify(pinned.body).includes(kim.auid.toString()), false, '본문 어디에도 auid 가 없다');
    assert.equal(pinned.body.auidCheck, await auidCheckOf(kim.uid.toString(), kim.auid.toString()));
    assert.deepEqual(pinned.body.envelopes, [{ id: P1.id, kind: 'passkey', credentialId: P1.credentialId, ct: P1.ct }]);
    const D = mkEnv('device');
    const tampered = (await wrapIssue(kim, S1, { key: k, token: T, envelope: D, mutate: (b) => { b.envelope = { ...D, ct: b64(60) }; } })).r;
    assert.equal(tampered.status, 400, j(tampered.body)); assert.equal(tampered.body.reason, 'wrapper_bad_signature');
    for (const bad of [mkEnv('passkey'), { ...D, ct: 'a|b' }, { ...D, credentialId: null }, 'x']) {
      // 서명 없이 보낸다 — 모양 검사가 서명보다 먼저라 wrapper_bad_signature 가 아니라 envelope_bad 여야 한다
      const r = (await wrapIssue(kim, S1, { key: k, token: T, envelope: bad, sign: false })).r;
      assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, 'envelope_bad', JSON.stringify(bad));
    }
    const ok = (await wrapIssue(kim, S1, { key: k, token: T, envelope: D })).r;   // 봉투를 열어 salt 를 되찾은 뒤 — 같은 토큰(아직 쓰지 않았다)
    assert.equal(ok.status, 200, j(ok.body));
    let envs = await envelopesOf(kim); assert.equal(envs.length, 2); assert.deepEqual(envs.find((e) => e.id === D.id), { id: D.id, kind: 'device', credentialId: D.credentialId, ct: D.ct });
    // 멱등 [I2]: 같은 토큰으로 다시 오면 토큰에서 막히고, 새 토큰으로 같은 봉투가 다시 오면(cred_revoked 재시도 등) 봉투는 그대로 하나다.
    const sameTok = (await wrapIssue(kim, S1, { key: k, token: T, envelope: D })).r; assert.equal(sameTok.status, 409, j(sameTok.body)); assert.equal(sameTok.body.reason, 'wrapper_token_used');
    assert.equal((await wrapIssue(kim, S1, { envelope: D })).r.status, 200);
    envs = await envelopesOf(kim); assert.equal(envs.length, 2, '같은 봉투는 한 번만'); assert.equal(envs.filter((e) => e.id === D.id).length, 1);
    // 같은 credentialId 의 다른 봉투(그 기기의 패스키로 다시 복구)는 바꿔 넣는다.
    const D2 = mkEnv('device', { credentialId: D.credentialId });
    assert.equal((await wrapIssue(kim, S1, { envelope: D2 })).r.status, 200);
    envs = await envelopesOf(kim); assert.equal(envs.length, 2); assert.equal(envs.some((e) => e.id === D.id), false); assert.equal(envs.find((e) => e.id === D2.id)?.ct, D2.ct);
  });
  await t(`봉투 한도·중복: 백업 ${BACKUP_LIMIT}개 뒤 6번째는 409 envelope_limit(토큰은 그대로 — 같은 토큰으로 remove 가 된다), 같은 credentialId·같은 id 는 envelope_exists, device add 는 envelope_bad, 없는 id 삭제는 envelope_unknown`, async () => {
    const lee = await person('g-env-lee'); assert.equal((await wrapIssue(lee, S1)).r.status, 200);
    const backups = [mkEnv('passkey'), mkEnv('code'), mkEnv('passkey'), mkEnv('passkey'), mkEnv('code')];
    for (const e of backups) { const x = await envCall(lee, { op: 'add', envelope: e }); assert.equal(x.r.status, 200, j(x.r.body)); }
    const sixth = await envCall(lee, { op: 'add', envelope: mkEnv('passkey') });
    assert.equal(sixth.r.status, 409, j(sixth.r.body)); assert.equal(sixth.r.body.reason, 'envelope_limit');
    const rm = await envCall(lee, { op: 'remove', id: backups[0].id }, { key: sixth.k, token: sixth.id_token });
    assert.equal(rm.r.status, 200, j(rm.r.body) + ' — 한도에 걸린 요청은 토큰을 쓰지 않는다 [m1]'); assert.equal(rm.r.body.envelopes.length, BACKUP_LIMIT - 1); assert.equal(rm.r.body.envelopes.some((e) => e.id === backups[0].id), false);
    for (const [req, reason, status] of [
      [{ op: 'add', envelope: mkEnv('passkey', { credentialId: backups[2].credentialId }) }, 'envelope_exists', 409],
      [{ op: 'add', envelope: mkEnv('code', { id: backups[1].id }) }, 'envelope_exists', 409],
      [{ op: 'add', envelope: mkEnv('device') }, 'envelope_bad', 400],
      [{ op: 'remove', id: 'f'.repeat(32) }, 'envelope_unknown', 404],
    ]) { const x = await envCall(lee, req); assert.equal(x.r.status, status, j(x.r.body)); assert.equal(x.r.body.reason, reason, JSON.stringify(req)); }
    for (const req of [{ op: 'add', envelope: { ...mkEnv('passkey'), ct: '' } }, { op: 'remove', id: 'xyz' }, { op: 'list' }]) {
      const k = await generateRequestKey(); const id_token = await stub.mint({ sub: lee.sub, nonce: await wrapperNonce(k.pkE), extra: {} });
      const x = await cia.post('/cia/wrapper/envelope', { id_token, pk_e: k.pkE, sig: 'A'.repeat(86), ...req }); assert.equal(x.status, 400, j(x.body)); assert.equal(x.body.reason, 'envelope_bad', JSON.stringify(req));
    }
    const P = mkEnv('passkey');
    const forged = await envCall(lee, { op: 'add', envelope: P }, { signFor: { op: 'add', envelope: { ...P, ct: b64(60) } } });
    assert.equal(forged.r.status, 400, j(forged.r.body)); assert.equal(forged.r.body.reason, 'wrapper_bad_signature');
    assert.equal((await envCall(lee, { op: 'add', envelope: P })).r.status, 200, '다시 다섯');
    // 한도 [I3]: 백업이 찬 계정에서도 기기 봉투를 실은 복구 발급은 된다. 기기 봉투가 DEVICE_LIMIT 를 넘으면 가장 오래된 것이 밀린다.
    const devices = [];
    for (let i = 0; i <= DEVICE_LIMIT; i++) { const D = mkEnv('device'); devices.push(D); const r = (await wrapIssue(lee, S1, { envelope: D })).r; assert.equal(r.status, 200, `${i}: ${j(r.body)}`); }
    const envs = await envelopesOf(lee);
    assert.equal(envs.filter((e) => e.kind === 'device').length, DEVICE_LIMIT); assert.equal(envs.filter((e) => e.kind !== 'device').length, BACKUP_LIMIT, '백업은 그대로');
    assert.equal(envs.some((e) => e.id === devices[0].id), false, '가장 오래된 기기 봉투가 밀렸다'); assert.equal(envs.some((e) => e.id === devices.at(-1).id), true);
  });
  await t('폐기된 계정에는 봉투를 더하지 못한다(403 account_disabled) — 관리자 삭제 뒤 새로 등록한 계정에는 봉투가 없다', async () => {
    const max = await person('g-env-max'); assert.equal((await wrapIssue(max, S1)).r.status, 200);
    assert.equal((await cia.adminPost('/cia/revoke', { uid: max.uid.toString(), scope: 'account' })).status, 200);
    const x = await envCall(max, { op: 'add', envelope: mkEnv('passkey') }); assert.equal(x.r.status, 403, j(x.r.body)); assert.equal(x.r.body.reason, 'account_disabled');
    const nina = await person('g-env-nina'); assert.equal((await wrapIssue(nina, S1)).r.status, 200);
    assert.equal((await envCall(nina, { op: 'add', envelope: mkEnv('passkey') })).r.status, 200);
    assert.equal((await envelopesOf(nina)).length, 1);
    assert.equal((await cia.adminPost('/cia/account/delete', { uid: nina.uid.toString() })).status, 200);
    assert.equal((await wrapIssue(nina, S1)).r.status, 200, '지운 뒤 같은 Google 계정의 새 등록');
    assert.deepEqual(await envelopesOf(nina), [], '봉투는 계정과 함께 사라졌다');
  });
  // ---- 한 신원에 Google 계정 여럿(스펙 2026-11-26 identity-multi-login) ----
  /** POST /cia/wrapper/link — 요청 키·그 키에 묶인 토큰(sub)·linkDigest 서명. key·token 을 주면 다시 쓰고, digest 를 주면 그 글에 서명한다(목적 바꿔 쓰기). */
  const linkCall = async (sub, req, { key = null, token = null, digest = null } = {}) => {
    const k = key ?? await generateRequestKey();
    const id_token = token ?? await stub.mint({ sub, nonce: await wrapperNonce(k.pkE), extra: { email: `${sub}@example.com`, email_verified: true } });
    return { r: await cia.post('/cia/wrapper/link', { id_token, pk_e: k.pkE, sig: await signDigest(k.privateKey, digest ?? linkDigest(req, AUD)), ...req }), k, id_token };
  };
  const nextOf = async (k) => (await wrapperNonce(k.pkE)).slice('wrap:'.length);
  /** begin(owner 의 계정 bySub·auid) → finish(sub2). begin 이 실패하면 그 응답을 돌려준다. */
  // salt: 연결 열쇠(salt 에서 유도)로 next 에 서명한다 — 기본은 그 신원의 salt. null 이면 서명을 싣지 않는다.
  const beginReq = async (owner, next, { auid = owner.auid.toString(), salt = owner.s_u } = {}) => ({ op: 'begin', auid, next, ...(salt === null ? {} : { link_sig: await signLinkProof(salt, { op: 'begin', next }, AUD) }) });
  const link = async (owner, sub2, { bySub = owner.sub, auid = owner.auid.toString(), salt = owner.s_u } = {}) => {
    const k2 = await generateRequestKey();
    const b = await linkCall(bySub, await beginReq(owner, await nextOf(k2), { auid, salt }));
    return b.r.status === 200 ? linkCall(sub2, { op: 'finish' }, { key: k2 }) : b;
  };
  const openUid = async (iss) => {
    const out = await login(iss);
    const ts = String(Math.floor(Date.now() / 1000)), auid_s = out.publicSignals[PUB_INDEX.AUID_S], PPID = out.publicSignals[PUB_INDEX.PPID];
    const rq = await cia.post('/cia/open/request', { arid: S1.arid, publicSignals: out.publicSignals, proof: out.proof, ts, sig: await signOpenRequest(S1.serviceWallet, { arid: S1.arid, PPID, auid_s, ts }) });
    assert.ok(rq.status === 200 || rq.status === 202, j(rq.body));
    assert.equal((await cia.adminPost(`/cia/openings/${rq.body.id}/approve`)).body.resolved, true);
    const o = (await cia.adminGet('/cia/openings')).body.openings.find((x) => x.id === rq.body.id);
    return { uid: String(o.uid), identity: String(o.identity), PPID };
  };
  const oscar = await person('g-oscar'), oscar2 = { ...oscar, sub: 'g-oscar-2' }, uid2 = uidOf(stub.provider, 'g-oscar-2');
  let oscarFirst;
  await t('계정 연결: begin(지금 계정 토큰 + auid + 다음 요청 키) → finish(더할 계정 토큰) — 목록에 둘, 더한 계정의 레코드는 생기지 않는다', async () => {
    oscarFirst = await wrapIssue(oscar, S1); assert.equal(oscarFirst.r.status, 200, j(oscarFirst.r.body));
    const x = await link(oscar, 'g-oscar-2'); assert.equal(x.r.status, 200, j(x.r.body));
    assert.deepEqual(x.r.body.logins.map((l) => [l.uid, l.email, l.primary === true]), [[oscar.uid.toString(), 'g-oscar@example.com', true], [uid2, 'g-oscar-2@example.com', false]]);
    assert.equal(await acctOf(uid2), null, '더한 계정의 레코드가 생겼다');
    assert.deepEqual((await acctOf(oscar.uid)).logins.map((l) => l.uid), [uid2]);
    assert.ok(!j(x.r.body).includes(oscar.auid.toString()), '응답에 auid 가 있다');
    assert.equal(oscarFirst.req.body.link_key, linkKeyOf(oscar.s_u), '발급 본문에 연결 열쇠의 주소');
    assert.equal('linkKey' in (await acctOf(oscar.uid)), false, '관리자 계정 표에 연결 열쇠를 싣지 않는다');
  });
  await t('연결한 계정으로 발급: 같은 계정·같은 슬롯·같은 C_u 로 200 이고 같은 PPID 로 로그인된다 — 응답의 logins 는 둘', async () => {
    const before = await acctOf(oscar.uid);
    const iss = await wrapIssue(oscar2, S1); assert.equal(iss.r.status, 200, j(iss.r.body));
    assert.equal(iss.cred.uid, oscar.uid.toString()); assert.equal(iss.cred.slot, oscarFirst.cred.slot); assert.equal(iss.cred.Cf_u, oscarFirst.cred.Cf_u);
    assert.deepEqual(iss.cred.logins.map((l) => l.uid), [oscar.uid.toString(), uid2]);
    const after = await acctOf(oscar.uid); assert.equal(after.activeCf_u, before.activeCf_u, 'C_u 가 바뀌었다'); assert.equal(after.id, 'g-oscar@example.com', '아이디(첫 계정의 이메일)가 바뀌었다');
    assert.equal(await acctOf(uid2), null);
    const a = await openUid(oscarFirst), b = await openUid(iss);
    assert.equal(a.PPID, b.PPID, '두 Google 계정의 PPID 가 다르다');
    // 개봉(M6): 그 로그인에 쓴 계정 하나 — 첫 계정의 로그인은 첫 uid, 더한 계정의 로그인은 그 uid
    assert.equal(a.uid, oscar.uid.toString()); assert.equal(b.uid, uid2);
    // 보안 검토 I-2: 관리자 기록에는 그 PPID 를 쓰는 신원(계정 표의 uid)이 따로 남는다 — 폐기는 그 값으로 한다
    assert.equal(b.identity, oscar.uid.toString()); assert.equal(a.identity, oscar.uid.toString());
  });
  await t('연결 거절: auid 가 틀리면 409 link_auid_mismatch, begin 없는 finish 는 409 link_not_started, 서명 목적을 바꿔 쓰면 400, 모양이 틀리면 400 link_bad', async () => {
    const pat = await person('g-pat'); assert.equal((await wrapIssue(pat, S1)).r.status, 200);
    // Google 계정만 가진 사람(다른 salt): 자기 계정에 붙이려 해도 auid 를 모르면 안 된다 — 남의 auid 로 자기 계정에 begin 해도 자기 계정의 auid 와 달라 거절
    let x = await link(oscar, 'g-new-1', { auid: pat.auid.toString() }); assert.equal(x.r.status, 409, j(x.r.body)); assert.equal(x.r.body.reason, 'link_auid_mismatch');
    x = await link(oscar, 'g-new-1', { bySub: 'g-pat' }); assert.equal(x.r.status, 409, j(x.r.body)); assert.equal(x.r.body.reason, 'link_auid_mismatch');
    x = await linkCall('g-new-1', { op: 'finish' }); assert.equal(x.r.status, 409, j(x.r.body)); assert.equal(x.r.body.reason, 'link_not_started');
    const k2 = await generateRequestKey(), next = await nextOf(k2);
    x = await linkCall('g-oscar', await beginReq(oscar, next), { digest: linkDigest({ op: 'finish' }, AUD) }); assert.equal(x.r.body.reason, 'wrapper_bad_signature', j(x.r.body));
    x = await linkCall('g-oscar', await beginReq(oscar, next), { digest: linkDigest({ op: 'begin', auid: oscar.auid.toString(), next: 'ab'.repeat(32) }, AUD) }); assert.equal(x.r.body.reason, 'wrapper_bad_signature', j(x.r.body));
    // 보안 검토 I-1: auid 를 알아도(브라우저 저장소·서버에 있는 값) 패스키(salt)가 없으면 안 된다 — 연결 열쇠의 서명이 없거나, 다른 salt 의 것이거나, 다른 next 에 한 것이면 409 link_salt_proof
    x = await linkCall('g-oscar', await beginReq(oscar, next, { salt: null })); assert.equal(x.r.status, 409, j(x.r.body)); assert.equal(x.r.body.reason, 'link_salt_proof');
    x = await linkCall('g-oscar', await beginReq(oscar, next, { salt: pat.s_u })); assert.equal(x.r.body.reason, 'link_salt_proof', j(x.r.body));
    x = await linkCall('g-oscar', { op: 'begin', auid: oscar.auid.toString(), next, link_sig: await signLinkProof(oscar.s_u, { op: 'begin', next: 'cd'.repeat(32) }, AUD) }); assert.equal(x.r.body.reason, 'link_salt_proof', j(x.r.body));
    x = await linkCall('g-oscar', { op: 'begin', auid: oscar.auid.toString(), next, link_sig: await signLinkProof(oscar.s_u, { op: 'begin', next }, 'https://other.example') }); assert.equal(x.r.body.reason, 'link_salt_proof', j(x.r.body));
    x = await linkCall('g-new-1', { op: 'finish' }, { key: k2 }); assert.equal(x.r.body.reason, 'link_not_started', 'begin 이 거절됐는데 finish 가 됐다');
    for (const req of [{ op: 'begin', auid: oscar.auid.toString(), next: 'xyz' }, { op: 'begin', next }, { op: 'remove', auid: oscar.auid.toString() }, { op: 'merge' }]) {
      const r = await cia.post('/cia/wrapper/link', { id_token: 'x', pk_e: k2.pkE, sig: 'A'.repeat(86), ...req }); assert.equal(r.status, 400, j(req)); assert.equal(r.body.reason, 'link_bad', j(r.body));
    }
    // begin 의 토큰·요청 키로 finish 를 하지 못한다(다음 요청 키의 토큰이어야 한다), 같은 begin 토큰은 두 번 못 쓴다
    const b = await linkCall('g-oscar', await beginReq(oscar, next));
    assert.equal(b.r.status, 200, j(b.r.body));
    // 같은 next 의 대기분은 덮어쓰지 못한다(M-4) — 다른 신원이 같은 next 로 begin 해도 409 link_pending, 같은 토큰을 다시 써도 거절
    x = await linkCall('g-pat', await beginReq(pat, next)); assert.equal(x.r.status, 409, j(x.r.body)); assert.equal(x.r.body.reason, 'link_pending');
    x = await linkCall('g-oscar', await beginReq(oscar, await nextOf(await generateRequestKey())), { key: b.k, token: b.id_token }); assert.equal(x.r.body.reason, 'wrapper_token_used', j(x.r.body));
    x = await linkCall('g-new-1', { op: 'finish' }, { key: b.k }); assert.equal(x.r.body.reason, 'wrapper_token_used', j(x.r.body));   // begin 의 요청 키는 이미 썼다
    assert.deepEqual((await acctOf(oscar.uid)).logins.map((l) => l.uid), [uid2], '거절된 요청이 목록을 바꿨다');
  });
  await t('연결 거절: 자기 계정이 있는 Google 계정·다른 신원에 붙은 계정은 409 link_has_account, 이미 이 신원의 계정은 409 link_exists — 합치지 않는다', async () => {
    const pat = await person('g-pat');   // 앞 사례에서 계정을 만들었다(같은 sub → 같은 uid). salt 는 다르지만 이 사례는 pat 의 salt 를 쓰지 않는다
    let x = await link(oscar, 'g-pat'); assert.equal(x.r.status, 409, j(x.r.body)); assert.equal(x.r.body.reason, 'link_has_account');
    x = await link(oscar, 'g-oscar-2'); assert.equal(x.r.body.reason, 'link_exists', j(x.r.body));
    x = await link(oscar, 'g-oscar', { bySub: 'g-oscar-2' }); assert.equal(x.r.body.reason, 'link_exists', j(x.r.body));
    const rita = await person('g-rita'); assert.equal((await wrapIssue(rita, S1)).r.status, 200);
    x = await link(rita, 'g-oscar-2'); assert.equal(x.r.body.reason, 'link_has_account', j(x.r.body));
    assert.deepEqual((await acctOf(rita.uid)).logins, []); assert.ok((await acctOf(pat.uid)) !== null);
  });
  await t('떼기: 첫 계정은 409 link_primary, 모르는 uid 는 404, auid 가 틀리면 409 — 뗀 계정은 그 패스키로 다시 발급받지 못한다(409 auid_taken)', async () => {
    const rm = async (sub, uid, auid = oscar.auid.toString(), salt = oscar.s_u) => linkCall(sub, { op: 'remove', auid, uid, ...(salt === null ? {} : { link_sig: await signLinkProof(salt, { op: 'remove', uid }, AUD) }) });
    let x = await rm('g-oscar-2', oscar.uid.toString()); assert.equal(x.r.status, 409, j(x.r.body)); assert.equal(x.r.body.reason, 'link_primary');
    x = await rm('g-oscar', '12345'); assert.equal(x.r.status, 404, j(x.r.body)); assert.equal(x.r.body.reason, 'link_unknown');
    x = await rm('g-oscar', uid2, (oscar.auid + 1n).toString()); assert.equal(x.r.body.reason, 'link_auid_mismatch', j(x.r.body));
    x = await linkCall('g-oscar', { op: 'remove', auid: oscar.auid.toString(), uid: uid2 }, { digest: linkDigest({ op: 'remove', auid: oscar.auid.toString(), uid: '12345' }, AUD) }); assert.equal(x.r.body.reason, 'wrapper_bad_signature', j(x.r.body));
    x = await rm('g-oscar', uid2, oscar.auid.toString(), null); assert.equal(x.r.body.reason, 'link_salt_proof', j(x.r.body));
    x = await linkCall('g-oscar', { op: 'remove', auid: oscar.auid.toString(), uid: uid2, link_sig: await signLinkProof(oscar.s_u, { op: 'remove', uid: '12345' }, AUD) }); assert.equal(x.r.body.reason, 'link_salt_proof', '다른 uid 에 한 서명');
    // I-3: 뗄 계정(g-oscar-2)이 해 둔 begin 은 떼는 순간 없어진다 — 그 뒤의 finish 는 409 link_not_started
    const kPend = await generateRequestKey(); { const b = await linkCall('g-oscar-2', await beginReq(oscar, await nextOf(kPend))); assert.equal(b.r.status, 200, j(b.r.body)); }
    assert.deepEqual((await acctOf(oscar.uid)).logins.map((l) => l.uid), [uid2]);
    x = await rm('g-oscar-2', uid2); assert.equal(x.r.status, 200, j(x.r.body)); assert.deepEqual(x.r.body.logins.map((l) => l.uid), [oscar.uid.toString()]);
    { const f = await linkCall('g-late', { op: 'finish' }, { key: kPend }); assert.equal(f.r.status, 409, j(f.r.body)); assert.equal(f.r.body.reason, 'link_not_started'); assert.deepEqual((await acctOf(oscar.uid)).logins, []); }
    const iss = await wrapIssue(oscar2, S1); assert.equal(iss.r.status, 409, j(iss.r.body)); assert.equal(iss.r.body.reason, 'auid_taken');
    assert.equal(await acctOf(uid2), null);
    // 뗀 뒤에도 지난 로그인의 기록은 남는다 — 첫 계정은 계속 된다
    assert.equal((await wrapIssue(oscar, S1)).r.status, 200);
  });
  await t('계정 폐기는 신원 전체다(M7): 연결한 계정의 토큰으로 "내 계정 폐기" → 첫 계정도 연결한 계정도 발급 거절(403 account_disabled)', async () => {
    const x = await link(oscar, 'g-oscar-3'); assert.equal(x.r.status, 200, j(x.r.body));
    const k = await generateRequestKey();
    const id_token = await stub.mint({ sub: 'g-oscar-3', nonce: await wrapperNonce(k.pkE), extra: {} });
    // 보안 검토 M-3: 브라우저가 폐기하려는 신원(owner)을 실으면 토큰의 신원과 같아야 한다 — 다르면 409 이고 토큰은 남는다(같은 토큰으로 맞는 owner 를 다시 낼 수 있다)
    const rita = uidOf(stub.provider, 'g-rita');
    const sigR = await signDigest(k.privateKey, revokeDigest({ scope: 'account' }, AUD));
    const wrong = await cia.post('/cia/account/self_revoke', { id_token, pk_e: k.pkE, sig: sigR, owner: rita }); assert.equal(wrong.status, 409, j(wrong.body)); assert.equal(wrong.body.reason, 'wrapper_account_mismatch');
    assert.equal((await acctOf(oscar.uid)).disabled, false); assert.equal((await acctOf(rita)).disabled, false);
    const r = await cia.post('/cia/account/self_revoke', { id_token, pk_e: k.pkE, sig: sigR, owner: oscar.uid.toString() });
    assert.equal(r.status, 200, j(r.body)); assert.equal((await acctOf(oscar.uid)).disabled, true);
    for (const who of [oscar, { ...oscar, sub: 'g-oscar-3' }]) { const iss = await wrapIssue(who, S1); assert.equal(iss.r.status, 403, j(iss.r.body)); assert.equal(iss.r.body.reason, 'account_disabled'); }
    const y = await link(oscar, 'g-oscar-4'); assert.equal(y.r.status, 403, j(y.r.body)); assert.equal(y.r.body.reason, 'account_disabled');
  });
  await t('한도: 첫 계정 말고 4개까지 — 다섯 번째 begin 은 409 link_limit', async () => {
    const quinn = await person('g-quinn'); assert.equal((await wrapIssue(quinn, S1)).r.status, 200);
    for (let i = 1; i <= 4; i++) assert.equal((await link(quinn, `g-quinn-${i}`)).r.status, 200, `연결 ${i}`);
    const x = await link(quinn, 'g-quinn-5'); assert.equal(x.r.status, 409, j(x.r.body)); assert.equal(x.r.body.reason, 'link_limit');
    assert.equal((await acctOf(quinn.uid)).logins.length, 4);
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
await t('래퍼가 아닌 서버에는 /cia/wrapper/envelope 가 없다(404)', async () => {
  const plain = await startIsolatedCia();
  try { const r = await plain.post('/cia/wrapper/envelope', { op: 'add' }); assert.equal(r.status, 404, `${r.status}`); assert.equal((await plain.post('/cia/wrapper/link', { op: 'begin' })).status, 404, '연결 경로'); } finally { await plain.stop(); }
});
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
