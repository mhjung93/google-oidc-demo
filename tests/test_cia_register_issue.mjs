// CIA 엔드포인트 — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_register_issue.mjs
import assert from 'node:assert/strict';
import { buildBabyjub, buildEddsa, buildPoseidon } from 'circomlibjs';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { randomScalar, sessionCommit, compressPoint, credMessageV5, SCALAR_MAX } from '../lib/mode3_credential.js';
import { sessionLeaf } from '../lib/mode3_revocation.js';
import { registrationCommit, proveUserCred, serializeUserCredProof, userCredRequestMessage, issueRequestMessageV4, pointToStrings } from '../lib/mode3_issuance.js';
import { buildUserCredRequest, signAttrsRequest } from '../lib/mode3_wallet.js';
import { verifyRpCert } from '../lib/mode3_rp_cert.js';
import { verifyShare, combinePublicKey } from '../lib/mode3_trace.js';
import { createShare } from '../lib/mode3_trace.js';
import { MODE3_LOG_ABI, signPublicationV2 } from '../lib/mode3_log.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

// 테스트가 만드는 provider 는 하나뿐이다 — getProvider() 를 호출할 때마다 새 JsonRpcProvider 를
// 만들면(mode3_chain.mjs 는 캐시하지 않는다) 각자 폴링 타이머를 띄워 cia.stop() 후에도 프로세스가
// 안 끝난다. 하나만 만들어 finally 에서 destroy() 한다.
const provider = getProvider();

const cia = await startIsolatedCia();
const eddsa = await buildEddsa();
const poseidon = await buildPoseidon();
const F = poseidon.F;
const uid = 12345n;
const arid = 22222222222222222222n;
let user;   // { s_u, r_u, cm_u, sk_u(Buffer), pk_u }

// 자격증명 이중 구조(2026-09-21): 사용자 자격증명(/cia/user_cred, π_u, 서명은 C_u_pt 를 덮는다) 위에 세션 발급(/cia/issue V5,
// ZKP 없음, 서명은 Cf_u·C_s_pt·chainid·allowAgent·max_height 를 덮는다). CIA 는 세션 기록을 남기지 않는다 — 옛 본문 재생으로
// 얻는 것은 같은 C_s 의 세션 하나뿐이고 sk_i 없이는 쓸 수 없다.
const CHAIN_ID = 31337n;
const signMsg = async (prvBuf, m) => { const s = eddsa.signPoseidon(prvBuf, F.e(m)); return { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() }; };
// 만료는 지갑이 정한다(2026-09-18 §3.2 갱신) — 테스트는 head + ttl 로 정하고 CIA 는 그대로 서명해야 한다.
const mhOf = async (ttl = 300n) => BigInt(await provider.getBlockNumber()) + ttl;

// AA 가 보증하는 데모 계정 속성(cia.js DEMO_ACCOUNTS, 2026-09-22 §3.4) — user_cred 의 π_u 가 이 값과 다르면 400.
const TESTUSER_ATTRS = [1990n, 410n, 2n, 0n, 0n, 0n];

/** 사용자 자격증명 요청 본문. u 는 { s_u, r_u, sk_u(Buffer), attrs }. 다른 계정이면 uidBig 을 준다. */
async function userCredRequest(u, overrides = {}, uidBig = uid) {
  const blind_u = randomScalar();
  const { C_u_pt, proof } = await proveUserCred({ uid: uidBig, s_u: u.s_u, blind_u, r_u: u.r_u, attrs: u.attrs ?? TESTUSER_ATTRS });
  const Cf_u = await compressPoint(C_u_pt);
  return { body: { uid: uidBig.toString(), C_u_pt: pointToStrings(C_u_pt), proof: serializeUserCredProof(proof), sig_u: await signMsg(u.sk_u, await userCredRequestMessage(C_u_pt)), ...overrides }, C_u_pt, Cf_u, blind_u };
}
/** 데모 계정 하나를 등록만 한다(user_cred 없음). { s_u, r_u, cm_u, sk_u(Buffer) } 를 돌려준다. */
async function freshRegistered(uidStr, pwd) {
  const u = await cia.registerUser(uidStr, pwd);
  return { s_u: u.s_u, r_u: u.r_u, cm_u: u.cm_u, sk_u: Buffer.from(u.sk_u, 'hex') };
}
let _testuserWallet = null;
/** uid 12345(testuser) 등록 — uid 는 한 번만 등록되므로 메모이즈해 재사용한다(2026-09-22 브리프의 freshWallet).
 *  { s_u, r_u, cm_u, sk_u(16진 문자열), pk_u, registerBody } 를 돌려준다. */
async function freshWallet() {
  if (_testuserWallet) return _testuserWallet;
  const u = await cia.registerUser('12345', 'password123');
  _testuserWallet = { s_u: u.s_u, r_u: u.r_u, cm_u: u.cm_u, sk_u: u.sk_u, pk_u: u.pk_u, registerBody: u.body };
  return _testuserWallet;
}
/** 세션 발급 요청 본문. cred 는 userCredRequest 의 반환값. */
async function issueRequest(u, cred, overrides = {}, { chainid = CHAIN_ID, allowAgent = 0n, max_height, pk_i = 0x1234n } = {}) {
  if (max_height === undefined) max_height = await mhOf();
  const blind_s = randomScalar();
  const { Cx, Cy } = await sessionCommit({ arid, pk_i, blind_s });
  const C_s_pt = { x: Cx, y: Cy };
  const sig_u = await signMsg(u.sk_u, await issueRequestMessageV4(cred.Cf_u, C_s_pt, chainid, allowAgent, max_height));
  return { body: { uid: uid.toString(), Cf_u: cred.Cf_u.toString(), C_s_pt: pointToStrings(C_s_pt), chainid: chainid.toString(), allowAgent: allowAgent.toString(), max_height: max_height.toString(), sig_u, ...overrides }, C_s_pt, blind_s, max_height };
}
/**
 * 활성 자격증명으로 세션을 하나 발급해 그 세션을 폐기한다 — 폐기 트리에 리프 하나가 pending 으로 들어간다(V9: scope=
 * credential|account 는 더 이상 폐기 트리에 아무것도 넣지 않는다 — 등록부 슬롯만 비우고 즉시 게시한다. 트리에 리프를
 * 추가하는 경로는 scope=session 뿐이다). 새 사용자 자격증명을 하나 받아 세션을 발급한 뒤, 먼저 그 자격증명을 물려
 * (scope=credential, 즉시 게시 — 호출 전처럼 활성 자격증명을 남기지 않아 credCount 를 가정하는 뒤 케이스들과 호환)
 * **그 다음** 세션을 폐기한다(scope=session, 즉시 게시하지 않고 폐기 트리 pending 에만 쌓는다) — 순서가 반대면
 * 자격증명 폐기의 즉시 게시가 방금 쌓은 세션 리프까지 같은 트랜잭션으로 실어 가 "아직 게시되지 않은 pending 리프"
 * 라는 이 함수의 계약이 깨진다. 세션 리프(10진)를 돌려준다.
 */
async function revokedLeaf() {
  const c = await userCredRequest(user);
  assert.equal((await cia.post('/cia/user_cred', c.body)).status, 201);
  const iss = await issueRequest(user, c);
  const issued = await cia.post('/cia/issue', iss.body);
  assert.equal(issued.status, 200, JSON.stringify(issued.body));
  const rc = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential' });
  assert.equal(rc.status, 200, JSON.stringify(rc.body)); assert.equal(rc.body.retired, 1);
  const r = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: issued.body.Cf_s });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.inserted, true);
  return r.body.leaf;
}

try {
  await t('public_keys 가 CIA EdDSA 키·ETH 주소·TTL·로그 주소를 준다', async () => {
    const r = await cia.get('/cia/public_keys');
    assert.equal(r.status, 200);
    assert.equal(r.body.ethAddress.toLowerCase(), cia.ethAddress.toLowerCase());
    assert.equal(r.body.ttlBlocks, undefined, 'CIA 는 더 이상 만료를 정하지 않는다'); assert.equal(r.body.heartbeatBlocks, 0); assert.deepEqual(r.body.chainIds, ['31337']);
    assert.equal(r.body.logAddress.toLowerCase(), cia.logAddress.toLowerCase());
  });

  await t('register: 곡선 밖·부분군 밖의 cm_u 는 400 이고 uid 는 잠기지 않는다', async () => {
    // 등록은 한 번뿐이고 되돌릴 길이 없다 — 여기서 걸러내지 않으면 이후 모든 발급이 400 이고 재등록은 409 다.
    // pk_u·sig_reg 는 필드 존재만 필요하다 — cm_u 검사가 그보다 먼저이므로 값 자체는 이 테스트와 무관하다.
    const dummyPk = { x: '1', y: '1' }, dummySig = { R8x: '1', R8y: '1', S: '1' };
    const r = await cia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: { x: '1', y: '1' }, pk_u: dummyPk, sig_reg: dummySig });
    assert.equal(r.status, 400, JSON.stringify(r.body));
    const bj = await buildBabyjub();
    const p = bj.F.p;
    const G = { x: bj.F.toObject(bj.Base8[0]), y: bj.F.toObject(bj.Base8[1]) };
    const nonCanonical = { x: (G.x + p).toString(), y: G.y.toString() };   // 값은 같아도 비정규 인코딩
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: nonCanonical, pk_u: dummyPk, sig_reg: dummySig })).status, 400);
  });

  await t('register_rp: 등록은 pending 202 → 승인 → 같은 키로 재호출하면 200 에 pk_trace·cert_s(V2), 같은 origin 은 같은 arid', async () => {
    const w = ethers.Wallet.createRandom(); const share = await createShare();
    const body = { name: 'demo-rp', origin: 'http://127.0.0.1:3100', pk_service: w.address, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() } };
    const r = await cia.post('/cia/register_rp', body);
    assert.equal(r.status, 202, JSON.stringify(r.body)); assert.equal(r.body.status, 'pending');
    assert.match(r.body.arid, /^[0-9]+$/); assert.ok(BigInt(r.body.arid) < SCALAR_MAX);
    assert.equal(r.body.cert_s, undefined, '승인 전에는 인증서가 없다');
    const again = await cia.post('/cia/register_rp', body);
    assert.equal(again.status, 202); assert.equal(again.body.arid, r.body.arid);
    const list = await cia.adminGet('/cia/rps');
    assert.equal(list.status, 200);
    const mine = list.body.rps.find((e) => e.arid === r.body.arid);
    assert.equal(mine.status, 'pending'); assert.equal(mine.pk_trace, null); assert.equal(mine.pk_service, w.address);
    assert.equal((await cia.adminPost(`/cia/rps/${r.body.arid}/approve`)).status, 200);
    const ok = await cia.post('/cia/register_rp', body);
    assert.equal(ok.status, 200, JSON.stringify(ok.body)); assert.equal(ok.body.arid, r.body.arid);
    const keys = (await cia.get('/cia/public_keys')).body;
    const pk_trace = { x: BigInt(ok.body.pk_trace.x), y: BigInt(ok.body.pk_trace.y) };
    assert.equal(await verifyRpCert({ x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) }, { arid: BigInt(ok.body.arid), origin: body.origin, pk_trace, cert: ok.body.cert_s }), true);
    // pk_trace = X_svc + x_AA·B8 — 서비스 조각이 들어 있어야 한다(같은 점이면 CIA 혼자 아는 키)
    assert.notEqual(ok.body.pk_trace.x, body.X_svc.x);
    // CIA 조각 X_AA 와 Schnorr PoK(2026-09-21, rogue key 방지): pk_trace == X_svc + X_AA 이고 PoK 가 (arid, X_svc) 에 대해 검증된다
    const P = (o) => ({ x: BigInt(o.x), y: BigInt(o.y) });
    const X_AA = P(ok.body.X_AA);
    const pok = { T: P(ok.body.share_pok.T), c: BigInt(ok.body.share_pok.c), z: BigInt(ok.body.share_pok.z) };
    assert.equal(await verifyShare(X_AA, pok, { arid: BigInt(ok.body.arid), X_svc: share.X }), true, 'CIA 조각 PoK');
    assert.deepEqual(await combinePublicKey(share.X, X_AA), pk_trace, 'pk_trace = X_svc + X_AA');
    assert.equal(await verifyShare(X_AA, pok, { arid: BigInt(ok.body.arid) + 1n, X_svc: share.X }), false, '다른 arid 에는 재사용 불가');
    assert.equal((await cia.adminPost(`/cia/rps/${r.body.arid}/approve`)).status, 409, '이미 결정된 항목은 409');
  });

  await t('register_rp: 다른 키로 같은 origin 은 409, 거절된 origin 은 403, 항등원·형식 오류는 400, 없는 arid 승인은 404', async () => {
    const origin = 'http://127.0.0.1:3101';
    const w = ethers.Wallet.createRandom(); const share = await createShare();
    const base = { name: 'x', origin, pk_service: w.address, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() } };
    assert.equal((await cia.post('/cia/register_rp', { ...base, X_svc: { x: '0', y: '1' } })).status, 400);
    assert.equal((await cia.post('/cia/register_rp', { ...base, X_svc: { x: '1', y: '1' } })).status, 400);
    assert.equal((await cia.post('/cia/register_rp', { ...base, pk_service: 'nope' })).status, 400);
    assert.equal((await cia.post('/cia/register_rp', { name: 'x' })).status, 400);
    const r = await cia.post('/cia/register_rp', base);
    assert.equal(r.status, 202, JSON.stringify(r.body));
    const other = await cia.post('/cia/register_rp', { ...base, pk_service: ethers.Wallet.createRandom().address });
    assert.equal(other.status, 409); assert.equal(other.body.error, 'service_key_mismatch');
    assert.equal((await cia.adminPost('/cia/rps/123/approve')).status, 404);
    assert.equal((await cia.adminPost(`/cia/rps/${r.body.arid}/deny`)).status, 200);
    const denied = await cia.post('/cia/register_rp', base);
    assert.equal(denied.status, 403); assert.equal(denied.body.status, 'denied');
    assert.equal((await cia.adminGet('/cia/rps')).body.rps.find((e) => e.arid === r.body.arid).status, 'denied');
  });

  await t('register: cm_u 등록, 장기키 발급, 응답에 AA 기록 attrs', async () => {
    const w = await freshWallet();
    assert.deepEqual(w.registerBody.attrs, ['1990', '410', '2', '0', '0', '0']);
    user = { s_u: w.s_u, r_u: w.r_u, cm_u: w.cm_u, sk_u: Buffer.from(w.sk_u, 'hex'), pk_u: w.pk_u };
  });

  await t('register: 잘못된 비밀번호는 401, 재등록은 409', async () => {
    const cm = pointToStrings(await registrationCommit(1n, 2n));
    const dummyPk = { x: '1', y: '1' }, dummySig = { R8x: '1', R8y: '1', S: '1' };
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'wrong', cm_u: cm, pk_u: dummyPk, sig_reg: dummySig })).status, 401);
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: cm, pk_u: dummyPk, sig_reg: dummySig })).status, 409);
  });

  await t('user_cred: 201 {Cf_u, slot, published}; 같은 Cf_u 재요청은 200; 잘못된 증명·서명은 400; cm_u 와 다른 s_u 는 400', async () => {
    const c = await userCredRequest(user);
    const r = await cia.post('/cia/user_cred', c.body);
    assert.equal(r.status, 201, JSON.stringify(r.body));
    assert.equal(r.body.Cf_u, c.Cf_u.toString());
    assert.equal(r.body.slot, 0, 'testuser 는 이 파일의 첫 등록이라 슬롯 0'); assert.equal(r.body.published, true);
    assert.equal((await cia.post('/cia/user_cred', c.body)).status, 200);
    const bad = await userCredRequest(user); bad.body.proof.z_su = '1';
    assert.equal((await cia.post('/cia/user_cred', bad.body)).status, 400);
    const sybil = await userCredRequest({ ...user, s_u: user.s_u + 1n });
    assert.equal((await cia.post('/cia/user_cred', sybil.body)).status, 400);
    const badSig = await userCredRequest(user); badSig.body.sig_u = (await userCredRequest(user)).body.sig_u;
    assert.equal((await cia.post('/cia/user_cred', badSig.body)).status, 400);
    assert.equal((await cia.get('/cia/state')).body.credCount, 1, '활성 자격증명은 하나');
  });

  await t('user_cred: 새 자격증명을 받으면 옛 것은 revoked 되고 등록부 슬롯이 새 리프로 갱신된다 (재발급 — attrs 는 AA 기록이라 매번 같다, 매번 새 blind_u)', async () => {
    // V9: 교체는 등록부 슬롯만 바꾸고 즉시 게시한다(폐기 트리는 건드리지 않는다) — 같은 슬롯의 리프가 바뀌므로 regRoot 가
    // 바뀐다. 옛 Cf_u 는 활성 자격증명 기록(creds[].revoked)에서 바로 거절된다.
    const a = await userCredRequest(user); const ra = await cia.post('/cia/user_cred', a.body); assert.equal(ra.status, 201);
    const b = await userCredRequest(user); const rb = await cia.post('/cia/user_cred', b.body); assert.equal(rb.status, 201);
    assert.equal(rb.body.slot, ra.body.slot);
    assert.notEqual(rb.body.regRoot, ra.body.regRoot, '같은 슬롯의 리프가 바뀌어 regRoot 도 바뀐다');
    assert.equal((await cia.get('/cia/state')).body.credCount, 1);
    // 옛 Cf_u 로는 세션 발급이 안 된다
    const old = await issueRequest(user, a);
    const r = await cia.post('/cia/issue', old.body);
    assert.equal(r.status, 403); assert.equal(r.body.reason, 'no_user_cred');
    // 물린 Cf_u 를 다시 올려도 되살아나지 않는다(409) — account 기록에 이미 revoked 로 남아 있다
    assert.equal((await cia.post('/cia/user_cred', a.body)).status, 409);
  });

  await t('issue V5: 정상 200 — 응답에 Cf_u·Cf_s·서명, CIA 는 세션 기록을 남기지 않는다', async () => {
    const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
    const req = await issueRequest(user, cred);
    const r = await cia.post('/cia/issue', req.body);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.Cf_u, cred.Cf_u.toString());
    assert.equal(r.body.Cf_s, (await compressPoint(req.C_s_pt)).toString());
    assert.equal(r.body.max_height, req.body.max_height);
    assert.equal(r.body.chainid, '31337'); assert.equal(r.body.allowAgent, '0');
    assert.equal(r.body.C, undefined); assert.equal(r.body.exptime, undefined);
    const m = await credMessageV5(BigInt(r.body.Cf_u), BigInt(r.body.Cf_s), BigInt(r.body.max_height), CHAIN_ID, 0n);
    assert.ok(eddsa.verifyPoseidon(F.e(m), { R8: [F.e(BigInt(r.body.sigma.R8x)), F.e(BigInt(r.body.sigma.R8y))], S: BigInt(r.body.sigma.S) }, [F.e(BigInt(r.body.pk_CIA.x)), F.e(BigInt(r.body.pk_CIA.y))]));
    assert.equal((await cia.get('/cia/state')).body.issuedCount, undefined, '세션 기록 없음');
    // 같은 본문 재생도 200 — 기록이 없으니 막을 것도 없고, 같은 C_s 에 묶여 sk_i 없이는 쓸 수 없다
    assert.equal((await cia.post('/cia/issue', req.body)).status, 200);
  });

  await t('issue V5: 서명이 Cf_u·C_s·chainid·allowAgent·max_height 를 덮는다 — 하나라도 바꾸면 400; 등록 안 된 Cf_u 는 403 no_user_cred; C_s_pt 가 부분군 밖이면 400', async () => {
    const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
    for (const patch of [{ max_height: '1' }, { allowAgent: '1' }, { chainid: '1' }, { Cf_u: (BigInt(cred.Cf_u) + 1n).toString() }]) {
      const req = await issueRequest(user, cred, patch);
      assert.equal((await cia.post('/cia/issue', req.body)).status, 400, JSON.stringify(patch));
    }
    const other = await issueRequest(user, cred);
    const swapped = await issueRequest(user, cred);
    swapped.body.C_s_pt = other.body.C_s_pt;
    assert.equal((await cia.post('/cia/issue', swapped.body)).status, 400);
    const foreign = await issueRequest(user, { Cf_u: 12345n });
    const r = await cia.post('/cia/issue', foreign.body);
    assert.equal(r.status, 403); assert.equal(r.body.reason, 'no_user_cred');
    const badPt = await issueRequest(user, cred); badPt.body.C_s_pt = { x: '1', y: '1' };
    assert.equal((await cia.post('/cia/issue', badPt.body)).status, 400);
  });

  await t('issue V5: 사용자 서명이 다른 키면 400', async () => {
    const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
    const req = await issueRequest(user, cred);
    req.body.sig_u = await signMsg(Buffer.alloc(32, 7), await issueRequestMessageV4(cred.Cf_u, req.C_s_pt, CHAIN_ID, 0n, req.max_height));
    assert.equal((await cia.post('/cia/issue', req.body)).status, 400);
  });

  await t('issue V5: max_height 는 서명이 덮는다 — 값만 바꾸면 400, 2^64 이상 400, 없으면 400; 먼 미래 값도 CIA 는 그대로 서명(상한은 검증자)', async () => {
    const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
    const tampered = await issueRequest(user, cred);
    tampered.body.max_height = (BigInt(tampered.body.max_height) + 1n).toString();
    assert.equal((await cia.post('/cia/issue', tampered.body)).status, 400);
    const huge = await issueRequest(user, cred);
    huge.body.max_height = (1n << 64n).toString();   // 서명은 정상값 위 — 범위 검사가 서명 검사보다 먼저 400
    assert.equal((await cia.post('/cia/issue', huge.body)).status, 400);
    const missing = await issueRequest(user, cred);
    delete missing.body.max_height;
    assert.equal((await cia.post('/cia/issue', missing.body)).status, 400);
    const far = await issueRequest(user, cred, {}, { max_height: 10_000_000n });
    const r = await cia.post('/cia/issue', far.body);
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.max_height, '10000000');
  });

  await t('issue V5: allowAgent 는 서명이 덮는다 — 2 는 400, 없으면 400, 허용 목록 밖 chainid 는 400; allowAgent=1 로 서명하면 200 이고 응답도 1', async () => {
    const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
    const two = await issueRequest(user, cred, { allowAgent: '2' });
    assert.equal((await cia.post('/cia/issue', two.body)).status, 400);
    const missing = await issueRequest(user, cred);
    delete missing.body.allowAgent;
    assert.equal((await cia.post('/cia/issue', missing.body)).status, 400);
    const wrongChain = await issueRequest(user, cred, {}, { chainid: 1n });
    const r2 = await cia.post('/cia/issue', wrongChain.body);
    assert.equal(r2.status, 400, JSON.stringify(r2.body));
    assert.match(r2.body.error, /chainid/);
    const agent = await issueRequest(user, cred, {}, { allowAgent: 1n });
    const r = await cia.post('/cia/issue', agent.body);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.allowAgent, '1');
  });

  await t('revoke(account): 활성 자격증명의 슬롯이 비워지고(retired 1) disabled; 재요청은 멱등(retired 0); 이후 issue 403', async () => {
    const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
    const pendingBefore = (await cia.get('/cia/state')).body.pendingCount;
    const r = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.retired, 1); assert.equal(r.body.published, true);
    assert.equal(r.body.pending, pendingBefore, '계정 폐기는 폐기 트리를 건드리지 않는다(V9: 슬롯만 비운다)');
    const again = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' });
    assert.equal(again.status, 200); assert.equal(again.body.retired, 0);
    assert.equal((await cia.get('/cia/state')).body.credCount, 0);
    const req = await issueRequest(user, cred);
    const denied = await cia.post('/cia/issue', req.body);
    assert.equal(denied.status, 403); assert.equal(denied.body.reason, 'account_disabled');
    assert.equal((await cia.post('/cia/user_cred', (await userCredRequest(user)).body)).status, 403, 'disabled 면 새 자격증명도 안 준다');
  });

  await t('publish: 세션 폐기로 쌓인 대기 리프가 명시적 publish 로 Mode3Log 에 올라간다', async () => {
    // 앞의 revoke(account) 테스트가 계정을 disabled 로 남겼다 — 세션을 발급하려면 활성 자격증명이 있어야 하므로
    // 먼저 되살린다(뒤의 revoke(credential) 테스트도 §6.6 복구로 다시 한 번 건다 — 멱등이라 무해하다).
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    const leaf = await revokedLeaf();   // scope=session 하나 — state.pending 에 쌓이고 아직 게시되지 않는다(내부의 다른
    // 호출들은 모두 즉시 게시돼 끝난 뒤이므로 여기서부터 epoch 기준점을 잡으면 된다)
    const before = await cia.get('/cia/state');
    const r = await cia.adminPost('/cia/publish');
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.published, true);
    assert.equal(r.body.epoch, before.body.epoch + 1);
    assert.equal(r.body.leaves.length, 1);
    assert.equal(BigInt(r.body.leaves[0]), BigInt(leaf));
    const log = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
    assert.equal(BigInt(await log.revRoot()).toString(), BigInt(r.body.root).toString());
    assert.equal(await log.epoch(), BigInt(before.body.epoch) + 1n);
    const st = await cia.get('/cia/state');
    assert.equal(st.body.pendingCount, 0);
    assert.equal(st.body.epoch, before.body.epoch + 1);
  });

  await t('publish: 대기 리프가 없으면 published:false 이고 epoch 그대로', async () => {
    const before = (await cia.get('/cia/state')).body.epoch;
    const r = await cia.adminPost('/cia/publish');
    assert.equal(r.status, 200);
    assert.equal(r.body.published, false);
    assert.equal((await cia.get('/cia/state')).body.epoch, before);
  });

  await t('revoke(credential): 슬롯만 비워지고 계정은 살아 있다 — 새 user_cred 를 받으면 다시 발급된다 (set_disabled false 복구 §6.6 포함)', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
    const r = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential' });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.retired, 1); assert.equal(r.body.published, true);
    const denied = await cia.post('/cia/issue', (await issueRequest(user, cred)).body);
    assert.equal(denied.status, 403); assert.equal(denied.body.reason, 'no_user_cred');
    // 활성 자격증명이 없으면 물릴 것이 없다 — retired 0(슬롯은 사용자당 하나라 leaf/C 인자는 받지 않는다, 있어도 무시)
    const ignored = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential', leaf: '777', C: '1' });
    assert.equal(ignored.status, 200, JSON.stringify(ignored.body)); assert.equal(ignored.body.retired, 0);
    const cred2 = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred2.body)).status, 201);
    assert.equal((await cia.post('/cia/issue', (await issueRequest(user, cred2)).body)).status, 200);
  });

  await t('self_revoke: 잘못된 비밀번호 401, 등록 안 된 계정 404, 형식 오류 400', async () => {
    // 관리자 시크릿 없이 부른다 — 이 경로의 인증은 계정 비밀번호뿐이다(설계 §6.5.1).
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: '12345', pwd: 'wrong' })).status, 401);
    // alice(67890) 는 데모 계정이지만 이 인스턴스에 등록한 적이 없다.
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: '67890', pwd: 'alicepw' })).status, 404);
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: 'abc', pwd: 'password123' })).status, 400);
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: '12345' })).status, 400);
    // 실패한 요청은 아무것도 바꾸지 않는다
    const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
    const { body } = await issueRequest(user, cred);
    assert.equal((await cia.post('/cia/issue', body)).status, 200, '계정은 여전히 활성이어야 한다');
  });

  await t('revoke: 활성 자격증명이 없는 계정의 account 폐기는 disabled 만 건다 (retired 0)', async () => {
    // 등록만 하고 user_cred 를 받지 않은 새 계정 — 데모 계정 alice(67890). 앞 케이스가 "등록 안 된 계정 404" 를 본 뒤여야 한다.
    const u2 = await freshRegistered('67890', 'alicepw');
    const pendingBefore = (await cia.get('/cia/state')).body.pendingCount;
    const r = await cia.adminPost('/cia/revoke', { uid: '67890', scope: 'account' });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.retired, 0); assert.equal(r.body.published, false);
    assert.equal(r.body.pending, pendingBefore);
    assert.equal((await cia.post('/cia/user_cred', (await userCredRequest(u2, {}, 67890n)).body)).status, 403);
  });

  await t('self_revoke: 비밀번호만으로 계정 폐기 — 슬롯이 비워지고(retired 1) disabled; 재요청은 멱등(retired 0)', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
    const issued = await cia.post('/cia/issue', (await issueRequest(user, cred)).body);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const r = await cia.post('/cia/account/self_revoke', { uid: uid.toString(), pwd: 'password123' });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.retired, 1, '활성 사용자 자격증명이 물려야 한다'); assert.equal(r.body.disabled, true); assert.equal(r.body.published, true);
    const again = await cia.post('/cia/account/self_revoke', { uid: uid.toString(), pwd: 'password123' });
    assert.equal(again.status, 200); assert.equal(again.body.retired, 0); assert.equal(again.body.disabled, true);
    assert.equal((await cia.post('/cia/issue', (await issueRequest(user, cred)).body)).status, 403);
    // 복구는 관리자만 한다(§6.6). 뒤 케이스들을 위해 여기서 되살린다 — 사용자 자격증명부터 다시 받아야 발급된다.
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    const cred2 = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred2.body)).status, 201);
    assert.equal((await cia.post('/cia/issue', (await issueRequest(user, cred2)).body)).status, 200);
  });

  await t('self_revoke: 체인이 죽어도 200 이고 disabled·슬롯 0 이 걸리며 published:false, pendingSlots 가 쌓인다', async () => {
    // 죽은 RPC 로 두 번째 격리 인스턴스를 띄운다 — 기동 시 root 대조는 RPC 실패를 건너뛰므로 기동 자체는 된다.
    const dead = await startIsolatedCia({ env: { CIA_RPC_URL: 'http://127.0.0.1:1' } });
    try {
      const u2 = await dead.registerUser('12345', 'password123');

      // 사용자 자격증명 발급은 체인을 보지 않는다(세션 발급만 chainAlive) — 죽은 체인에서도 201(게시만 실패).
      const dc = await userCredRequest({ s_u: u2.s_u, r_u: u2.r_u, sk_u: Buffer.from(u2.sk_u, 'hex') });
      const r0 = await dead.post('/cia/user_cred', dc.body);
      assert.equal(r0.status, 201, JSON.stringify(r0.body)); assert.equal(r0.body.published, false);

      const r = await dead.post('/cia/account/self_revoke', { uid: '12345', pwd: 'password123' });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      assert.equal(r.body.disabled, true);
      // treeUpdated 는 옛 판(체인이 죽으면 삽입을 미루는)의 필드다 — V9 에는 처음부터 없다(폐기 트리에 아예 넣지 않는다).
      assert.equal(r.body.treeUpdated, undefined);
      assert.equal(r.body.retired, 1, '체인이 죽어도 활성 자격증명은 물려야 한다'); assert.equal(r.body.slot, 0);
      assert.equal(r.body.published, false, '게시는 체인이 없어 실패한다(조용히 삼켜진다)');
      assert.ok((await dead.get('/cia/state')).body.pendingSlots >= 1, '백로그가 남아 다음 기동·하트비트가 재시도한다');

      // 발급은 disabled 검사가 chainid 허용 목록 확인보다 먼저다(cia.js /cia/issue) — 체인 없이도 403 이어야 한다.
      const issued = await dead.post('/cia/issue', {
        uid: '12345', Cf_u: dc.Cf_u.toString(), C_s_pt: { x: '1', y: '1' }, sig_u: {}, chainid: '31337', allowAgent: '0', max_height: '1',
      });
      assert.equal(issued.status, 403, JSON.stringify(issued.body));
    } finally {
      await dead.stop();
    }
  });

  await t('publish: 체인의 epoch 가 앞서 있어도 CIA 가 따라잡는다 (크래시 복구)', async () => {
    // 앞 케이스들이 남긴 활성 자격증명을 물리고(등록부는 즉시 게시되므로 여기서는 영향 없음) 폐기 트리 pending 을 먼저
    // 비워 둔다 — 아래의 직접 게시는 "CIA 가 올렸을 것"과 똑같이 pending 전부를 실어야 하는데, 여기서는 이 케이스가
    // 세션으로 폐기한 리프 하나만 싣기 때문이다.
    assert.equal((await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).status, 200);
    // 세션 하나를 발급해 폐기한다 (계정은 앞의 self_revoke 멱등 케이스 끝에서 재활성화됨)
    const leaf = await revokedLeaf();

    // CIA 가 아직 게시하기 전에, 체인에 직접 다음 epoch 를 (이 리프를 실어) 게시한다 — tx 는 성공해
    // 이벤트까지 나갔는데 CIA 가 persist() 전에 죽어버린 크래시 시나리오를 흉내낸다.
    const before = await cia.get('/cia/state');
    const current = before.body.epoch;
    const log = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
    assert.equal(await log.epoch(), BigInt(current), '아직은 로컬·온체인 epoch 가 같아야 한다');
    const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32);
    const revRoot = b32(before.body.root), regRoot = b32(before.body.regRoot);
    const directEpoch = current + 1;
    const sig = await signPublicationV2(cia.ciaEthWallet, { logAddress: cia.logAddress, revRoot, regRoot, epoch: directEpoch, revLeaves: [b32(leaf)], slotIdx: [], slotLeaves: [] });
    const tx = await log.connect(cia.ciaEthWallet).publish(revRoot, regRoot, directEpoch, [b32(leaf)], [], [], sig);
    await tx.wait();
    assert.equal(await log.epoch(), BigInt(directEpoch));

    // CIA 가 로컬 기록만 보고 게시하면 온체인과 같은 epoch 를 또 보내 영원히 막힌다. 게시 직전 대조가
    // 이미 체인에 있는 리프를 pending 에서 걷어내고 epoch 를 따라잡아야 한다 — 남은 pending 이 없으니 이번엔
    // 게시하지 않고(published:false) epoch 만 current+1 로 맞춘다.
    const r = await cia.adminPost('/cia/publish');
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.published, false);
    assert.equal(r.body.epoch, current + 1);
    assert.equal((await cia.get('/cia/state')).body.pendingCount, 0);
    // 다음 폐기: V9 에서는 revokedLeaf() 자체가 사용자 자격증명 발급(등록부, 즉시 게시)을 한 번 거치므로, 그 호출
    // 하나만으로도 epoch 가 한 번 더 늘어난다 — "따라잡은 epoch 의 바로 다음" 이라는 V8 식 절대값 예측이 더 이상
    // 맞지 않는다. revokedLeaf() 가 끝난 뒤를 새 기준점으로 잡고 거기서부터 상대값으로 확인한다.
    const leaf2 = await revokedLeaf();
    const before2 = await cia.get('/cia/state');
    const r2 = await cia.adminPost('/cia/publish');
    assert.equal(r2.status, 200, JSON.stringify(r2.body));
    assert.equal(r2.body.published, true);
    assert.equal(r2.body.epoch, before2.body.epoch + 1);
    assert.equal(r2.body.leaves.length, 1); assert.equal(BigInt(r2.body.leaves[0]), BigInt(leaf2));
    assert.equal(await log.epoch(), BigInt(before2.body.epoch) + 1n);
  });

  await t('publish 도중 들어온 revoke 의 리프는 pending 에 남아 다음 publish 로 나간다', async () => {
    // publish 는 tx.wait() 를 기다리는 동안 다른 요청을 받는다. 그 사이 revoke 가 pending 에 붙인
    // 리프를 publish 가 pending 전체를 비우며 버리면, 그 리프는 온체인 이벤트로 영영 안 나가고
    // 이후 모든 서명 root 에는 들어 있어 지갑의 재구성이 전부 fail-closed 된다.
    // automine 을 꺼서 tx.wait() 를 확실히 붙잡아 둔 채로 revoke 를 끼워 넣는다.
    //
    // V9: /cia/user_cred·/cia/revoke(account|credential) 는 모두 호출 즉시 게시를 트리거하고, 그 publishNow() 는
    // 폐기 트리 pending 과 등록부 pendingSlots 를 **한 트랜잭션에 같이** 비운다. 그래서 L1 을 큐에 넣은(scope=session)
    // 뒤 자격증명을 하나 더 발급해(세션 하나를 더 받으려고) L2 를 만들면, 그 발급의 즉시 게시가 아직 손대지 않은 L1
    // 까지 조용히 먼저 실어 가 버려 "L1 은 이미 게시, L2 만 pending" 이라는 이 테스트의 전제가 깨진다. 그래서 자격증명
    // 하나로 세션 **둘**을 미리 받아 두고(발급 자체는 게시를 트리거하지 않는다), 하나만 먼저 폐기해 L1 을 만든다.
    const st0 = (await cia.get('/cia/state')).body;
    assert.equal(st0.credCount, 0, '앞 케이스가 활성 자격증명을 남기지 않았어야 한다'); assert.equal(st0.pendingCount, 0);
    const c = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', c.body)).status, 201);
    const issued1 = await cia.post('/cia/issue', (await issueRequest(user, c)).body);
    assert.equal(issued1.status, 200, JSON.stringify(issued1.body));
    const issued2 = await cia.post('/cia/issue', (await issueRequest(user, c)).body);
    assert.equal(issued2.status, 200, JSON.stringify(issued2.body));

    const rv1 = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'session', Cf_s: issued1.body.Cf_s });
    assert.equal(rv1.status, 200, JSON.stringify(rv1.body)); assert.equal(rv1.body.inserted, true);
    const L1 = rv1.body.leaf;
    const L2 = (await sessionLeaf(BigInt(issued2.body.Cf_s))).toString();

    await provider.send('evm_setAutomine', [false]);
    try {
      const publishing = cia.adminPost('/cia/publish');
      // CIA 가 tx 를 mempool 에 넣고 tx.wait() 에 들어갈 때까지 기다린다
      const deadline = Date.now() + 15_000;
      while ((await provider.send('eth_pendingTransactions', [])).length === 0) {
        assert.ok(Date.now() < deadline, 'publish tx 가 mempool 에 오지 않았다');
        await new Promise((r) => setTimeout(r, 100));
      }
      const rv = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'session', Cf_s: issued2.body.Cf_s });
      assert.equal(rv.status, 200, JSON.stringify(rv.body));
      assert.equal(rv.body.inserted, true); assert.equal(rv.body.leaf, L2);
      assert.equal(rv.body.pending, 2, 'publish 가 아직 안 끝났으니 L1, L2 둘 다 pending 이어야 한다');
      await provider.send('evm_mine', []);
      const pub = await publishing;
      assert.equal(pub.status, 200, JSON.stringify(pub.body));
      assert.equal(pub.body.published, true);
      assert.equal(pub.body.leaves.length, 1, '첫 publish 는 L1 만 실었어야 한다');
    } finally {
      await provider.send('evm_setAutomine', [true]);
    }

    const st = await cia.get('/cia/state');
    assert.equal(st.body.pendingCount, 1, 'L2 는 pending 에 남아 있어야 한다');
    const pub2 = await cia.adminPost('/cia/publish');
    assert.equal(pub2.body.published, true, JSON.stringify(pub2.body));
    assert.equal(pub2.body.leaves.length, 1);
    assert.equal(BigInt(pub2.body.leaves[0]), BigInt(L2));
    // 지갑이 이벤트만으로 재구성한 root 가 서명 root 와 같아야 한다 — syncRevocationTree(lib/mode3_wallet.js) 는
    // 아직 V1 LOG_ABI 라(Task 10 전) 여기서는 Mode3Log 의 revRoot() 로 직접 대조한다.
    const log7 = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
    assert.equal(BigInt(await log7.revRoot()).toString(), pub2.body.root);
  });

  await t('admin 엔드포인트는 시크릿 없이 401', async () => {
    assert.equal((await cia.post('/cia/revoke', { uid: '12345', scope: 'account' })).status, 401);
  });

  // 마지막에 둔다 — 이 뒤로는 온체인 root 가 로컬과 어긋난 채 남아 게시가 전부 503 이다.
  await t('publish: 온체인 root 가 로컬 기록의 어느 접두사와도 다르면 503 이고 올리지 않는다', async () => {
    // CIA 가 켜진 채로 로그가 (같은 CIA 키로) 다른 root 로 갈라졌다고 치자 — 직접 엉뚱한 root 를 올린다.
    // 게시 직전 대조가 없으면 CIA 는 이벤트로 나간 적 없는 리프를 품은 root 를 서명해 올려 전원의 재구성이 깨진다.
    const log = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
    const current = Number(await log.epoch());
    const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32);
    const sameRegRoot = b32((await cia.get('/cia/state')).body.regRoot);
    const bogus = b32(12345n);
    const sig = await signPublicationV2(cia.ciaEthWallet, { logAddress: cia.logAddress, revRoot: bogus, regRoot: sameRegRoot, epoch: current + 1, revLeaves: [], slotIdx: [], slotLeaves: [] });
    await (await log.connect(cia.ciaEthWallet).publish(bogus, sameRegRoot, current + 1, [], [], [], sig)).wait();
    await revokedLeaf();
    const r = await cia.adminPost('/cia/publish');
    assert.equal(r.status, 503, JSON.stringify(r.body));
    assert.match(r.body.error, /어느 접두사와도 다르다/);
    assert.equal(await log.epoch(), BigInt(current + 1), '올리지 않았어야 한다');
    assert.equal((await cia.get('/cia/state')).body.pendingCount, 1, 'pending 은 그대로여야 한다');
  });

  await t('하트비트: CIA_HEARTBEAT_BLOCKS=2 면 게시 없이 블록이 지나도 같은 root 가 새 epoch 로 재게시되고 lastPublishedBlock 이 갱신된다', async () => {
    const hbCia = await startIsolatedCia({ env: { CIA_HEARTBEAT_BLOCKS: '2', CIA_HEARTBEAT_POLL_MS: '300' } });
    try {
      const log = new ethers.Contract(hbCia.logAddress, MODE3_LOG_ABI, provider);
      const root0 = await log.revRoot(), epoch0 = await log.epoch();
      await provider.send('hardhat_mine', ['0x3']);
      const deadline = Date.now() + 10_000;
      while (Date.now() < deadline && (await log.epoch()) === epoch0) await new Promise((r) => setTimeout(r, 200));
      assert.equal(await log.epoch(), epoch0 + 1n, hbCia.log());
      assert.equal(await log.revRoot(), root0, '하트비트는 root 를 바꾸지 않는다');
      assert.ok(BigInt(await log.lastPublishedBlock()) > 0n);
      assert.equal((await hbCia.get('/cia/state')).body.epoch, Number(epoch0) + 1, 'CIA 상태의 epoch 도 따라간다');
    } finally { await hbCia.stop(); }
  });

  // 2026-09-22 §3.3·§3.4: 속성은 AA 기록이다. 이 셋은 uid 12345(testuser) 의 attrs 를 관리자 엔드포인트로 영구히 바꾸므로
  // (앞의 revokedLeaf()·userCredRequest(user) 는 모두 기본 attrs 를 가정한다) 파일의 맨 끝, publish 가 이미 깨진 뒤에 둔다.
  await t('register 응답에 AA 기록 attrs 가 실린다; /cia/attrs 는 sk_u 서명으로 같은 값을 돌려준다', async () => {
    const w = await freshWallet();                                           // 파일의 등록 헬퍼(uid 12345 testuser)
    assert.deepEqual(w.registerBody.attrs, ['1990', '410', '2', '0', '0', '0']);
    const nonce = 99n;
    const sig_u = await signAttrsRequest(w.sk_u, 12345n, nonce);
    const r = await cia.post('/cia/attrs', { uid: '12345', nonce: nonce.toString(), sig_u });
    assert.equal(r.status, 200); assert.deepEqual(r.body.attrs, ['1990', '410', '2', '0', '0', '0']);
    assert.equal((await cia.post('/cia/attrs', { uid: '12345', nonce: '100', sig_u })).status, 400, '다른 nonce 의 서명은 거절');
  });

  await t('user_cred: 지갑이 AA 기록과 다른 attrs 로 만든 C_u 는 400 bad proof; 같은 값이면 201', async () => {
    const w = await freshWallet();
    const bad = await buildUserCredRequest({ uid: 12345n, s_u: w.s_u, r_u: w.r_u, sk_u: w.sk_u, attrs: [1991n, 410n, 2n, 0n, 0n, 0n] });
    assert.equal((await cia.post('/cia/user_cred', bad.body)).status, 400);
    const good = await buildUserCredRequest({ uid: 12345n, s_u: w.s_u, r_u: w.r_u, sk_u: w.sk_u, attrs: [1990n, 410n, 2n, 0n, 0n, 0n] });
    assert.equal((await cia.post('/cia/user_cred', good.body)).status, 201);
  });

  await t('관리자 속성 변경: 활성 C_u 가 물리고(retired 1) 다음 user_cred 는 새 값으로만 통과', async () => {
    const w = await freshWallet();
    const good = await buildUserCredRequest({ uid: 12345n, s_u: w.s_u, r_u: w.r_u, sk_u: w.sk_u, attrs: [1990n, 410n, 2n, 0n, 0n, 0n] });
    assert.equal((await cia.post('/cia/user_cred', good.body)).status, 201);
    const r = await cia.adminPost('/cia/accounts/12345/attrs', { attrs: ['1990', '410', '3', '0', '0', '0'] });
    assert.equal(r.status, 200); assert.equal(r.body.retired, 1);
    // published 는 false — 이 지점에서는 이미 "publish: 온체인 root가..." 케이스가 의도적으로 온체인 root 를
    // 로컬과 영영 어긋나게 해 뒀다(그 테스트 자체의 주석: "이 뒤로는 ... 게시가 전부 503"). V9 는 이 요청도
    // 즉시 게시를 시도하므로 그 503 을 그대로 맞고 조용히 삼켜진다 — retired(등록부 반영)는 그와 무관하게 맞다.
    assert.equal(r.body.published, false);
    assert.equal((await cia.post('/cia/user_cred', good.body)).status, 400, '옛 속성의 C_u 는 더 이상 통과하지 않는다');
    const next = await buildUserCredRequest({ uid: 12345n, s_u: w.s_u, r_u: w.r_u, sk_u: w.sk_u, attrs: [1990n, 410n, 3n, 0n, 0n, 0n] });
    assert.equal((await cia.post('/cia/user_cred', next.body)).status, 201);
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { attrs: [(1n << 64n).toString(), '0', '0', '0', '0', '0'] })).status, 400);
    assert.equal((await cia.adminPost('/cia/accounts/424242/attrs', { attrs: ['1', '0', '0', '0', '0', '0'] })).status, 404);
    // A-I2: 본문이 없거나 짧으면 0 패딩으로 속성이 지워지고 옛 C_u 리프가 되돌릴 수 없게 게시된다 → 길이 6 배열만 받는다
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', {})).status, 400);
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { attrs: ['1990', '410'] })).status, 400);
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { attrs: 'x' })).status, 400);
    // M2(2026-09-23 최종 리뷰): 길이가 맞아도 빈 칸은 BigInt('') === 0n 으로 통과했다 — 관리자 UI 가 보내는 바로 그 모양
    // (cia_admin.html 의 `i.value.trim()`). 슬롯이 조용히 0 이 되고 옛 C_u 리프가 되돌릴 수 없게 게시된다.
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { attrs: ['1990', '', '2', '0', '0', '0'] })).status, 400, '빈 슬롯');
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { attrs: ['1990', ' 410 ', '2', '0', '0', '0'] })).status, 400, '공백이 낀 값(BigInt 는 받아들인다)');
    assert.deepEqual((await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === '12345').attrs, ['1990', '410', '3', '0', '0', '0'], '거절된 요청은 속성을 바꾸지 않았다');
  });
} finally {
  await cia.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
