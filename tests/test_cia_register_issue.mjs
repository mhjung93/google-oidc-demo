// IdP 엔드포인트 — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_register_issue.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider, canonOf } from './helpers/mode3_chain.mjs';
import { randomScalar, credMessageV11, auidOf, SCALAR_MAX } from '../lib/mode3_credential.js';
import { sessionLeaf } from '../lib/mode3_revocation.js';
import { pointToStrings } from '../lib/mode3_issuance.js';
import { createRegistration, signRegistration, signSlotRequest } from '../lib/mode3_wallet.js';
import { verifyRpCert } from '../lib/mode3_rp_cert.js';
import { verifyShare, combinePublicKey } from '../lib/mode3_trace.js';
import { createShare } from '../lib/mode3_trace.js';
import { MODE3_LOG_ABI, signPublicationV3 } from '../lib/mode3_log.js';
import { issueV11, userOf, TESTUSER_ATTRS, ALICE_ATTRS } from './helpers/mode3_flow.mjs';

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
let user;   // userOf(registerUser('12345'))

// V11(2026-10-12): /cia/issue 한 요청으로 (C_u, C_s, π_IdP, sig_u) 를 받아 발급한다 — 사용자 자격증명과 세션 발급이
// 더 이상 나뉘어 있지 않다. 서명은 auid_s·arid_s·Cf_u·Cf_s·chainid·allowAgent·max_height 를 덮는다. IdP 는 세션
// 기록을 남긴다(V8) — 개별 폐기(/cia/revoke scope=session)가 그 기록을 찾는다.
const CHAIN_ID = 31337n;

/** 데모 계정 하나를 등록만 한다. userOf 는 body(등록 응답)를 들지 않으므로 여기서 다시 붙인다 — 등록 응답 모양을 보는
 *  케이스가 cia.registerUser 를 또 불러 409(이미 등록됨)를 맞지 않게. */
async function freshRegistered(uidStr, pwd, attrs = TESTUSER_ATTRS) { const reg = await cia.registerUser(uidStr, pwd); return Object.assign(userOf(reg, uidStr, attrs), { body: reg.body }); }
let _testuser = null;
/** uid 12345(testuser) 등록 — uid 는 한 번만 등록되므로 메모이즈한다. */
async function freshWallet() { return (_testuser ??= await freshRegistered('12345', 'password123')); }
/** 발급 한 번(기본값: 새 C_u, head+300). issueV11 의 얇은 포장 — 이 파일의 케이스가 자주 쓰는 모양. */
const issue = (u, opts = {}) => issueV11(cia, u, { arid, provider, ...opts });
/** 리뷰 S1(2026-10-13): 응답 시간 상한을 건 POST. 서명 S 가 음수면 예전 IdP 는 verifyPoseidon 안(mulPointEscalar)에서 끝나지 않아
 *  프로세스 전체가 멈췄다 — 그 회귀는 여기서 ms 뒤 TimeoutError 로 드러난다(상한이 없으면 테스트가 같이 멈출 뿐 실패하지 않는다). */
const postWithin = (inst, p, body, ms = 2000) => fetch(`${inst.base}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body ?? {}), signal: AbortSignal.timeout(ms) })
  .then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));
/** 서명 { R8x, R8y, S } 의 비정규·범위 밖 변형. 앞의 셋(음수)이 예전 IdP 를 멈추던 값이고 나머지는 같은 파서가 함께 거르는 값이다. */
const badSigVariants = (g) => [
  ['S=-1', { ...g, S: '-1' }], ['S=-7', { ...g, S: '-7' }], ['R8x=-1', { ...g, R8x: '-1' }],
  ['S=subOrder', { ...g, S: eddsa.babyJub.subOrder.toString() }], ['S=subOrder+S', { ...g, S: (eddsa.babyJub.subOrder + BigInt(g.S)).toString() }], ['R8y=R8y+p', { ...g, R8y: (BigInt(g.R8y) + F.p).toString() }],
  ['S 숫자형', { ...g, S: Number(1) }], ['S=0x', { ...g, S: '0x1' }], ['S 공백', { ...g, S: ` ${g.S}` }], ['R8x 없음', { R8y: g.R8y, S: g.S }], ['문자열', 'sig'],
];

/** 세션 하나 발급 → 그 자격증명 은퇴(scope=credential, 즉시 게시) → 그 세션 폐기(scope=session, pending 에만 쌓는다). 리프(10진)를 돌려준다. (설명은 V10 과 같다) */
async function revokedLeaf() {
  const iss = await issue(user);
  assert.equal(iss.r.status, 200, JSON.stringify(iss.r.body));
  const rc = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential' });
  assert.equal(rc.status, 200, JSON.stringify(rc.body)); assert.equal(rc.body.retired, 1);
  const r = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: iss.cred.Cf_s });
  assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.inserted, true);
  return r.body.leaf;
}

try {
  await t('public_keys 가 IdP EdDSA 키·ETH 주소·TTL·로그 주소를 준다', async () => {
    const r = await cia.get('/cia/public_keys');
    assert.equal(r.status, 200);
    assert.equal(r.body.ethAddress.toLowerCase(), cia.ethAddress.toLowerCase());
    assert.equal(r.body.ttlBlocks, undefined, 'CIA 는 더 이상 만료를 정하지 않는다'); assert.equal(r.body.heartbeatBlocks, 0); assert.deepEqual(r.body.chainIds, ['31337']);
    assert.equal(r.body.logAddress.toLowerCase(), cia.logAddress.toLowerCase());
  });

  await t('register: auid 가 10진이 아니거나 필드 밖이면 400 이고 uid 는 잠기지 않는다', async () => {
    const dummyPk = { x: '1', y: '1' }, dummySig = { R8x: '1', R8y: '1', S: '1' };
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'password123', auid: 'zz', pk_u: dummyPk, sig_reg: dummySig })).status, 400);
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'password123', auid: F.p.toString(), pk_u: dummyPk, sig_reg: dummySig })).status, 400, '필드 밖');
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'password123', auid: '7', pk_u: dummyPk, sig_reg: dummySig })).status, 400, 'pk_u 가 곡선 밖');
  });

  // uid 12345 는 아직 등록되지 않았다(바로 위 케이스가 "uid 는 잠기지 않는다" 를 확인한다) — freshWallet() 이 실제로
  // 등록하기 전에, 서명이 본문과 다른 auid 를 보증하면 거절되는지를 본다(등록은 되돌릴 수 없어 §6.1 이 여기서 걸러낸다).
  await t('register: 등록 서명이 본문과 다른 auid 를 보증하면 400 bad_registration_signature', async () => {
    const reg = await createRegistration(12345n);
    const sig_reg = await signRegistration(reg.sk_u, 12345n, reg.auid + 1n);   // auid+1 을 보증 — 본문의 auid(reg.auid)와 다르다
    const r = await cia.post('/cia/register', { uid: '12345', pwd: 'password123', auid: reg.auid.toString(), pk_u: pointToStrings(reg.pk_u), sig_reg });
    assert.equal(r.status, 400); assert.equal(r.body.error, 'bad_registration_signature');
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
    // pk_trace = X_svc + x_AA·B8 — RP 조각이 들어 있어야 한다(같은 점이면 IdP 혼자 아는 키)
    assert.notEqual(ok.body.pk_trace.x, body.X_svc.x);
    // IdP 조각 X_AA 와 Schnorr PoK(2026-09-21, rogue key 방지): pk_trace == X_svc + X_AA 이고 PoK 가 (arid, X_svc) 에 대해 검증된다
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

  await t('register: auid 등록 → 201 { slot, schemaHash, uid, provider }, 속성·profile 은 없다(D15), 계정 상태에도 attrs 없음', async () => {
    user = await freshWallet();
    assert.equal(user.slot, 0); assert.equal(user.auid, await auidOf({ uid, s_u: user.s_u }));
    assert.deepEqual(Object.keys(user.body).sort(), ['provider', 'schemaHash', 'slot', 'uid'], '등록 응답은 slot·schemaHash + uid·provider(OIDC 래퍼 2026-10-16)');
    assert.equal(user.body.uid, '12345'); assert.equal(user.body.provider, 'demo');
    const acct = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === '12345');
    assert.equal(acct.attrs, undefined); assert.equal(acct.profile, undefined); assert.equal(acct.activeCf_u, null); assert.equal(acct.slot, 0);
  });

  await t('register: 잘못된 비밀번호는 401, 재등록은 409', async () => {
    const dummyPk = { x: '1', y: '1' }, dummySig = { R8x: '1', R8y: '1', S: '1' };
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'wrong', auid: '1', pk_u: dummyPk, sig_reg: dummySig })).status, 401);
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'password123', auid: '1', pk_u: dummyPk, sig_reg: dummySig })).status, 409);
  });

  await t('issue V11: 첫 발급 — 새 C_u 가 슬롯에 게시(published:true)되고 토큰·세션 기록; 같은 C_u 재발급은 published:false, 활성 자격증명은 하나', async () => {
    const a = await issue(user);
    assert.equal(a.r.status, 200, JSON.stringify(a.r.body));
    assert.deepEqual(Object.keys(a.cred).sort(), ['Cf_s', 'Cf_u', 'allowAgent', 'chainid', 'epoch', 'max_height', 'pk_CIA', 'published', 'regRoot', 'sigma', 'slot']);
    assert.equal(a.cred.Cf_u, a.req.Cf_u.toString()); assert.equal(a.cred.Cf_s, a.req.Cf_s.toString()); assert.equal(a.cred.published, true);
    const m = F.e(await credMessageV11(a.req.auid_s, a.req.arid_s, a.req.Cf_u, a.req.Cf_s, CHAIN_ID, 0n));
    const pk = (await cia.get('/cia/public_keys')).body.pk_CIA;
    assert.equal(eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(a.cred.sigma.R8x)), F.e(BigInt(a.cred.sigma.R8y))], S: BigInt(a.cred.sigma.S) }, [F.e(BigInt(pk.x)), F.e(BigInt(pk.y))]), true, '토큰은 (auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent) 위 CIA 서명');
    const b = await issue(user, { blind_u: a.blind_u });   // 같은 C_u, 새 세션
    assert.equal(b.r.status, 200); assert.equal(b.cred.published, false); assert.equal(b.cred.Cf_u, a.cred.Cf_u); assert.notEqual(b.cred.Cf_s, a.cred.Cf_s);
    assert.equal((await cia.get('/cia/state')).body.credCount, 1);
    const sessions = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions;
    assert.ok(sessions.some((s) => s.Cf_s === a.cred.Cf_s) && sessions.some((s) => s.Cf_s === b.cred.Cf_s), '세션 기록 둘');
    assert.ok(sessions.every((s) => s.auid_s === undefined && s.arid_s === undefined), 'D1: auid_s·arid_s 는 기록하지 않는다');
    const file = fs.readFileSync(path.join(cia.dir, 'cia_state.json'), 'utf8');
    for (const k of ['"attrs"', '"profile"', '"auid_s"', '"arid_s"', '"cm_u"']) assert.equal(file.includes(k), false, `${k} 가 상태 파일에 있다`);
  });

  await t('issue V11: 다른 C_u(새 blind_u·같은 속성 또는 다른 속성)로 발급하면 옛 C_u 는 revoked·슬롯은 새 리프, 옛 C_u 재사용은 409 cred_revoked', async () => {
    const a = await issue(user);
    const b = await issue(user, { blind_u: randomScalar() });
    assert.equal(b.r.status, 200); assert.equal(b.cred.published, true); assert.notEqual(b.cred.Cf_u, a.cred.Cf_u);
    assert.equal(b.cred.slot, a.cred.slot, '슬롯은 사용자당 하나 — 교체여도 같은 슬롯'); assert.notEqual(b.cred.regRoot, a.cred.regRoot, '리프가 바뀌었으니 regRoot 도 바뀐다');
    assert.equal((await cia.get('/cia/state')).body.credCount, 1);
    const again = await issue(user, { blind_u: a.blind_u });
    assert.equal(again.r.status, 409); assert.equal(again.r.body.reason, 'cred_revoked');
    const other = await issue({ ...user, attrs: [1991n, 392n, 0n, 0n, 0n, 0n] });   // D15: 속성은 사용자 몫 — 어떤 값이든 발급된다
    assert.equal(other.r.status, 200, JSON.stringify(other.r.body)); assert.equal(other.cred.published, true);
  });

  await t('issue V11: π_IdP 가 다른 auid(다른 salt 의 지갑)·다른 uid 면 400 bad_idp_proof; 증명 손상도 400; 없으면 400', async () => {
    const stranger = { ...user, s_u: randomScalar() };   // 같은 uid, 다른 salt → auid 가 DB 와 다르다
    const bad = await issue(stranger);
    assert.equal(bad.r.status, 400, JSON.stringify(bad.r.body)); assert.equal(bad.r.body.reason, 'bad_idp_proof');
    const fakeUid = await issue({ ...user, uid: 99999n }, { uidInBody: '12345' });   // C_u 안의 uid 만 바꾸고 본문 uid 는 진짜
    assert.equal(fakeUid.r.status, 400); assert.equal(fakeUid.r.body.reason, 'bad_idp_proof');
    const good = await issue(user);
    const broken = await issue(user, { overrides: { proof_idp: { ...good.req.body.proof_idp, pi_a: ['1', '2', '1'] } } });
    assert.equal(broken.r.status, 400); assert.equal(broken.r.body.reason, 'bad_idp_proof');
    assert.equal((await issue(user, { overrides: { proof_idp: undefined } })).r.status, 400);
  });

  await t('issue V11: 서명이 auid_s·arid_s·C_u·C_s·chainid·allowAgent·max_height 를 덮는다 — 하나라도 바꾸면 400; 부분군 밖 점은 400', async () => {
    // max_height 를 고정한다(999999n) — 기본값(provider 로 head+300)을 쓰면, g 자신의 발급(새 blind_u → 첫 C_u 교체 →
    // 즉시 게시 tx)이 블록을 하나 전진시켜, 뒤이은 호출의 "기본" max_height(head+300)가 g.max_height+1 과 우연히
    // 같아져 아래 max_height 패치가 패치가 아니라 공교롭게 "제자리" 값이 돼 버린다(관찰됨: 200 이 나왔다 — 2026-10-12).
    const g = await issue(user, { max_height: 999999n }); assert.equal(g.r.status, 200);
    for (const patch of [{ auid_s: '1' }, { arid_s: '1' }, { allowAgent: '1' }, { max_height: (BigInt(g.req.body.max_height) + 1n).toString() }]) {
      const r = await issue(user, { blind_u: g.blind_u, max_height: 999999n, overrides: patch });
      assert.equal(r.r.status, 400, JSON.stringify(patch)); assert.equal(r.r.body.error, 'bad user signature', JSON.stringify(patch));
    }
    // chainid 는 서명 검증보다 먼저인 허용 목록 검사에 걸린다 — 다른 에러 문구이므로 상태 코드만 본다.
    assert.equal((await issue(user, { blind_u: g.blind_u, max_height: 999999n, overrides: { chainid: '1' } })).r.status, 400);
    const h = await issue(user, { blind_u: g.blind_u, max_height: 999999n });   // 다른 요청의 C_s 로 바꿔치기 — 서명·π 모두 어긋난다
    assert.equal((await issue(user, { blind_u: g.blind_u, max_height: 999999n, overrides: { C_s_pt: h.req.body.C_s_pt } })).r.status, 400);
    assert.equal((await issue(user, { overrides: { C_s_pt: { x: '1', y: '1' } } })).r.status, 400);
    assert.equal((await issue(user, { overrides: { C_u_pt: { x: '1', y: '1' } } })).r.status, 400);
  });

  await t('issue V11: 사용자 서명이 다른 키면 400', async () => {
    const other = await issue({ ...user, sk_u: (await createRegistration(uid)).sk_u });
    assert.equal(other.r.status, 400); assert.equal(other.r.body.error, 'bad user signature');
    assert.equal((await issue(user, { overrides: { sig_u: other.req.body.sig_u } })).r.status, 400);
  });

  await t('issue V11: max_height 는 서명이 덮는다 — 값만 바꾸면 400, 2^64 이상 400, 없으면 400; 먼 미래 값도 IdP 는 그대로 서명(상한은 검증자)', async () => {
    // g 와 뒤이은 호출 모두 max_height 를 고정한다(999999n) — 바로 위 케이스와 같은 이유(기본값이면 g 자신의 즉시
    // 게시 tx 가 블록을 전진시켜 "+1" 패치가 뒤 호출의 기본값과 우연히 같아진다, 2026-10-12 관찰).
    const g = await issue(user, { max_height: 999999n }); assert.equal(g.r.status, 200, JSON.stringify(g.r.body));
    const tampered = await issue(user, { blind_u: g.blind_u, max_height: 999999n, overrides: { max_height: (BigInt(g.req.body.max_height) + 1n).toString() } });
    assert.equal(tampered.r.status, 400);
    await assert.rejects(() => issue(user, { blind_u: g.blind_u, max_height: 1n << 64n }));
    const huge = await issue(user, { blind_u: g.blind_u, max_height: 999999n, overrides: { max_height: (1n << 64n).toString() } });
    assert.equal(huge.r.status, 400);
    const missing = await issue(user, { blind_u: g.blind_u, max_height: 999999n, overrides: { max_height: undefined } });
    assert.equal(missing.r.status, 400);
    const far = await issue(user, { blind_u: g.blind_u, max_height: 10_000_000n });
    assert.equal(far.r.status, 200, JSON.stringify(far.r.body)); assert.equal(far.cred.max_height, '10000000');
  });

  // 리뷰 L5/A8(2026-10-13): arid_s(·auid_s) = 유효값 + p 는 Poseidon 안에서 유효값과 같아져 서명은 그대로 맞는다 — 예전에는 200 이었다.
  // 본문만 바꿔 보내는 post 훅을 쓴다(서명·π_IdP 는 원래 값으로 만들었다). /cia/register 의 auid 와 같이 필드 밖은 400.
  await t('issue V11: arid_s·auid_s 가 필드 밖(유효값 + p)이면 400 — 서명이 맞아도 정규형만 받는다', async () => {
    const lift = (k) => (p, b) => cia.post(p, { ...b, [k]: (BigInt(b[k]) + F.p).toString() });
    for (const k of ['arid_s', 'auid_s']) {
      const r = await issue(user, { max_height: 999999n, post: lift(k) });
      assert.equal(r.r.status, 400, `${k}: ${JSON.stringify(r.r.body)}`); assert.match(r.r.body.error, /field elements/, k);
    }
    const ok = await issue(user, { max_height: 999999n });   // 대조군: 같은 경로를 본문 그대로 보내면 발급된다
    assert.equal(ok.r.status, 200, JSON.stringify(ok.r.body));
  });

  await t('issue V11: allowAgent 는 서명이 덮는다 — 2 는 400, 없으면 400, 허용 목록 밖 chainid 는 400; allowAgent=1 로 서명하면 200 이고 응답도 1', async () => {
    const g = await issue(user); assert.equal(g.r.status, 200, JSON.stringify(g.r.body));
    const two = await issue(user, { blind_u: g.blind_u, overrides: { allowAgent: '2' } });
    assert.equal(two.r.status, 400);
    const missing = await issue(user, { blind_u: g.blind_u, overrides: { allowAgent: undefined } });
    assert.equal(missing.r.status, 400);
    const wrongChain = await issue(user, { blind_u: g.blind_u, chainid: 1n });
    assert.equal(wrongChain.r.status, 400, JSON.stringify(wrongChain.r.body));
    assert.match(wrongChain.r.body.error, /chainid/);
    const agent = await issue(user, { blind_u: g.blind_u, allowAgent: 1n });
    assert.equal(agent.r.status, 200, JSON.stringify(agent.r.body));
    assert.equal(agent.cred.allowAgent, '1');
  });

  await t('revoke(account): 활성 자격증명의 슬롯이 비워지고(retired 1) disabled; 재요청은 멱등(retired 0); 이후 issue 403', async () => {
    const iss = await issue(user); assert.equal(iss.r.status, 200);
    const pendingBefore = (await cia.get('/cia/state')).body.pendingCount;
    const r = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.retired, 1); assert.equal(r.body.published, true);
    assert.equal(r.body.pending, pendingBefore, '계정 폐기는 폐기 트리를 건드리지 않는다(V9: 슬롯만 비운다)');
    const again = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' });
    assert.equal(again.status, 200); assert.equal(again.body.retired, 0);
    assert.equal((await cia.get('/cia/state')).body.credCount, 0);
    const denied = await issue(user, { blind_u: iss.blind_u });
    assert.equal(denied.r.status, 403); assert.equal(denied.r.body.reason, 'account_disabled');
    assert.equal((await issue(user)).r.status, 403, 'disabled 면 새 자격증명도 안 준다');
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

  await t('revoke(credential): 슬롯만 비워지고 계정은 살아 있다 — 새 C_u 로 발급하면 다시 발급된다 (set_disabled false 복구 §6.6 포함)', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    const iss = await issue(user); assert.equal(iss.r.status, 200);
    const r = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential' });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.retired, 1); assert.equal(r.body.published, true);
    const denied = await issue(user, { blind_u: iss.blind_u });
    assert.equal(denied.r.status, 409); assert.equal(denied.r.body.reason, 'cred_revoked');
    // 활성 자격증명이 없으면 물릴 것이 없다 — retired 0(슬롯은 사용자당 하나라 leaf/C 인자는 받지 않는다, 있어도 무시)
    const ignored = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential', leaf: '777', C: '1' });
    assert.equal(ignored.status, 200, JSON.stringify(ignored.body)); assert.equal(ignored.body.retired, 0);
    const again = await issue(user);
    assert.equal(again.r.status, 200, JSON.stringify(again.r.body)); assert.equal(again.cred.published, true);
  });

  await t('self_revoke: 잘못된 비밀번호 401, 등록 안 된 계정 404, 형식 오류 400', async () => {
    // 관리자 시크릿 없이 부른다 — 이 경로의 인증은 계정 비밀번호뿐이다(설계 §6.5.1).
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: '12345', pwd: 'wrong' })).status, 401);
    // alice(67890) 는 데모 계정이지만 이 인스턴스에 등록한 적이 없다.
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: '67890', pwd: 'alicepw' })).status, 404);
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: 'abc', pwd: 'password123' })).status, 400);
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: '12345' })).status, 400);
    // 실패한 요청은 아무것도 바꾸지 않는다
    const iss = await issue(user); assert.equal(iss.r.status, 200);
    assert.equal((await issue(user, { blind_u: iss.blind_u })).r.status, 200, '계정은 여전히 활성이어야 한다');
  });

  await t('revoke: 활성 자격증명이 없는 계정의 account 폐기는 disabled 만 건다 (retired 0)', async () => {
    // 등록만 하고 세션 발급을 받지 않은 새 계정 — 데모 계정 alice(67890). 앞 케이스가 "등록 안 된 계정 404" 를 본 뒤여야 한다.
    const u2 = await freshRegistered('67890', 'alicepw', ALICE_ATTRS);
    const pendingBefore = (await cia.get('/cia/state')).body.pendingCount;
    const r = await cia.adminPost('/cia/revoke', { uid: '67890', scope: 'account' });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.retired, 0); assert.equal(r.body.published, false);
    assert.equal(r.body.pending, pendingBefore);
    assert.equal((await issue(u2)).r.status, 403);
  });

  await t('self_revoke: 비밀번호만으로 계정 폐기 — 슬롯이 비워지고(retired 1) disabled; 재요청은 멱등(retired 0)', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    const iss = await issue(user); assert.equal(iss.r.status, 200, JSON.stringify(iss.r.body));
    const r = await cia.post('/cia/account/self_revoke', { uid: uid.toString(), pwd: 'password123' });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.retired, 1, '활성 사용자 자격증명이 물려야 한다'); assert.equal(r.body.disabled, true); assert.equal(r.body.published, true);
    const again = await cia.post('/cia/account/self_revoke', { uid: uid.toString(), pwd: 'password123' });
    assert.equal(again.status, 200); assert.equal(again.body.retired, 0); assert.equal(again.body.disabled, true);
    assert.equal((await issue(user, { blind_u: iss.blind_u })).r.status, 403);
    // 복구는 관리자만 한다(§6.6). 뒤 케이스들을 위해 여기서 되살린다.
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    assert.equal((await issue(user)).r.status, 200);
  });

  await t('self_revoke: 체인이 죽어도 200 이고 disabled·슬롯 0 이 걸리며 published:false, pendingSlots 가 쌓인다', async () => {
    // 죽은 RPC 로 두 번째 격리 인스턴스를 띄운다 — 기동 시 root 대조는 RPC 실패를 건너뛰므로 기동 자체는 된다.
    const dead = await startIsolatedCia({ env: { CIA_RPC_URL: 'http://127.0.0.1:1' } });
    try {
      const u2 = await dead.registerUser('12345', 'password123');
      const user = userOf(u2, '12345');   // 바깥의 user 를 가리지 않는다 — 이 블록 안에서만 쓴다

      // C_u 발급은 체인의 캐노니컬 연결을 보지 않는다(세션 관리는 CIA_CHAIN_RPCS 의 응용 체인을 본다 — 죽은 쪽은
      // ethWallet 뿐이다) — 죽은 체인에서도 200(게시만 실패).
      const iss = await issueV11(dead, user, { arid, max_height: 1000n });
      assert.equal(iss.r.status, 200, JSON.stringify(iss.r.body)); assert.equal(iss.cred.published, false);

      const r = await dead.post('/cia/account/self_revoke', { uid: '12345', pwd: 'password123' });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      assert.equal(r.body.disabled, true);
      // treeUpdated 는 옛 판(체인이 죽으면 삽입을 미루는)의 필드다 — V9 에는 처음부터 없다(폐기 트리에 아예 넣지 않는다).
      assert.equal(r.body.treeUpdated, undefined);
      assert.equal(r.body.retired, 1, '체인이 죽어도 활성 자격증명은 물려야 한다'); assert.equal(r.body.slot, 0);
      assert.equal(r.body.published, false, '게시는 체인이 없어 실패한다(조용히 삼켜진다)');
      assert.ok((await dead.get('/cia/state')).body.pendingSlots >= 1, '백로그가 남아 다음 기동·하트비트가 재시도한다');

      // 발급은 disabled 검사가 chainid 허용 목록 확인·π_IdP 검증보다 먼저다(cia.js /cia/issue) — 체인 없이도 403 이어야 한다.
      const issued = await issueV11(dead, user, { arid, max_height: 1000n, post: (p, b) => dead.post(p, b) });
      assert.equal(issued.r.status, 403, JSON.stringify(issued.r.body));
    } finally {
      await dead.stop();
    }
  });

  await t('publish: 체인의 epoch 가 앞서 있어도 IdP 가 따라잡는다 (크래시 복구)', async () => {
    // 앞 케이스들이 남긴 활성 자격증명을 물리고(등록부는 즉시 게시되므로 여기서는 영향 없음) 폐기 트리 pending 을 먼저
    // 비워 둔다 — 아래의 직접 게시는 "IdP 가 올렸을 것"과 똑같이 pending 전부를 실어야 하는데, 여기서는 이 케이스가
    // 세션으로 폐기한 리프 하나만 싣기 때문이다.
    assert.equal((await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).status, 200);
    // 세션 하나를 발급해 폐기한다 (계정은 앞의 self_revoke 멱등 케이스 끝에서 재활성화됨)
    const leaf = await revokedLeaf();

    // IdP 가 아직 게시하기 전에, 체인에 직접 다음 epoch 를 (이 리프를 실어) 게시한다 — tx 는 성공해
    // 이벤트까지 나갔는데 IdP 가 persist() 전에 죽어버린 크래시 시나리오를 흉내낸다.
    const before = await cia.get('/cia/state');
    const current = before.body.epoch;
    const log = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
    assert.equal(await log.epoch(), BigInt(current), '아직은 로컬·온체인 epoch 가 같아야 한다');
    const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32);
    const revRoot = b32(before.body.root), regRoot = b32(before.body.regRoot);
    const directEpoch = current + 1;
    const sig = await signPublicationV3(cia.ciaEthWallet, { ...(await canonOf(log, provider)), revRoot, regRoot, epoch: directEpoch, revLeaves: [b32(leaf)], slotIdx: [], slotLeaves: [] });
    const tx = await log.connect(cia.ciaEthWallet).publish(revRoot, regRoot, directEpoch, [b32(leaf)], [], [], sig);
    await tx.wait();
    assert.equal(await log.epoch(), BigInt(directEpoch));

    // IdP 가 로컬 기록만 보고 게시하면 온체인과 같은 epoch 를 또 보내 영원히 막힌다. 게시 직전 대조가
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
    // V9: /cia/issue·/cia/revoke(account|credential) 는 모두 호출 즉시 게시를 트리거하고, 그 publishNow() 는
    // 폐기 트리 pending 과 등록부 pendingSlots 를 **한 트랜잭션에 같이** 비운다. 그래서 L1 을 큐에 넣은(scope=session)
    // 뒤 자격증명을 하나 더 발급해(세션 하나를 더 받으려고) L2 를 만들면, 그 발급의 즉시 게시가 아직 손대지 않은 L1
    // 까지 조용히 먼저 실어 가 버려 "L1 은 이미 게시, L2 만 pending" 이라는 이 테스트의 전제가 깨진다. 그래서 같은
    // C_u(blind_u 재사용)로 세션 **둘**을 미리 받아 두고(C_u 가 같으면 게시를 트리거하지 않는다), 하나만 먼저 폐기해
    // L1 을 만든다.
    const st0 = (await cia.get('/cia/state')).body;
    assert.equal(st0.credCount, 0, '앞 케이스가 활성 자격증명을 남기지 않았어야 한다'); assert.equal(st0.pendingCount, 0);
    const issued1 = await issue(user); assert.equal(issued1.r.status, 200, JSON.stringify(issued1.r.body));
    const issued2 = await issue(user, { blind_u: issued1.blind_u }); assert.equal(issued2.r.status, 200, JSON.stringify(issued2.r.body));

    const rv1 = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'session', Cf_s: issued1.cred.Cf_s });
    assert.equal(rv1.status, 200, JSON.stringify(rv1.body)); assert.equal(rv1.body.inserted, true);
    const L1 = rv1.body.leaf;
    const L2 = (await sessionLeaf(BigInt(issued2.cred.Cf_s))).toString();

    await provider.send('evm_setAutomine', [false]);
    try {
      const publishing = cia.adminPost('/cia/publish');
      // IdP 가 tx 를 mempool 에 넣고 tx.wait() 에 들어갈 때까지 기다린다
      const deadline = Date.now() + 15_000;
      while ((await provider.send('eth_pendingTransactions', [])).length === 0) {
        assert.ok(Date.now() < deadline, 'publish tx 가 mempool 에 오지 않았다');
        await new Promise((r) => setTimeout(r, 100));
      }
      const rv = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'session', Cf_s: issued2.cred.Cf_s });
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
    // IdP 가 켜진 채로 로그가 (같은 IdP 키로) 다른 root 로 갈라졌다고 치자 — 직접 엉뚱한 root 를 올린다.
    // 게시 직전 대조가 없으면 IdP 는 이벤트로 나간 적 없는 리프를 품은 root 를 서명해 올려 전원의 재구성이 깨진다.
    const log = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
    const current = Number(await log.epoch());
    const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32);
    const sameRegRoot = b32((await cia.get('/cia/state')).body.regRoot);
    const bogus = b32(12345n);
    const sig = await signPublicationV3(cia.ciaEthWallet, { ...(await canonOf(log, provider)), revRoot: bogus, regRoot: sameRegRoot, epoch: current + 1, revLeaves: [], slotIdx: [], slotLeaves: [] });
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

  await t('V11: 사라진 라우트는 404 — /cia/user_cred, /cia/attrs, /cia/accounts/:uid/attrs; /cia/slot 은 D_SLOTREQ 서명으로 슬롯을 준다', async () => {
    assert.equal((await cia.post('/cia/user_cred', {})).status, 404);
    assert.equal((await cia.post('/cia/attrs', {})).status, 404);
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { profile: {} })).status, 404);
    const nonce = randomScalar();
    const r = await cia.post('/cia/slot', { uid: '12345', nonce: nonce.toString(), sig_u: await signSlotRequest(user.sk_u, uid, nonce) });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(typeof r.body.slot, 'number');
    assert.equal((await cia.post('/cia/slot', { uid: '12345', nonce: '100', sig_u: await signSlotRequest(user.sk_u, uid, nonce) })).status, 400, '다른 nonce 의 서명은 거절');
  });

  // 리뷰 S1(2026-10-13): 서명 필드를 BigInt() 로 그대로 파싱하던 때는 S='-1' 하나로 IdP 가 영구히 멈췄다(verifyPoseidon 의 mulPointEscalar(-1n)).
  // 회귀하면 그 인스턴스가 멈추므로 별도 격리 인스턴스에서 돌린다 — 공유 인스턴스(위 케이스들)를 끌고 들어가지 않게. 요청마다 2초 상한.
  // /cia/revoke scope=session 의 같은 검사는 tests/test_mode3_session_revoke.mjs 에 있다.
  await t('리뷰 S1: 서명 필드가 음수·비10진·범위 밖이면 register·slot·issue 모두 2초 안에 400 — 프로세스는 계속 응답하고 정상 서명은 통한다', async () => {
    const sc = await startIsolatedCia();
    try {
      const reg = await createRegistration(uid);
      const regBody = (sig_reg) => ({ uid: '12345', pwd: 'password123', auid: reg.auid.toString(), pk_u: pointToStrings(reg.pk_u), sig_reg });
      const goodReg = await signRegistration(reg.sk_u, uid, reg.auid);
      for (const [label, bad] of badSigVariants(goodReg)) {
        const r = await postWithin(sc, '/cia/register', regBody(bad));
        assert.equal(r.status, 400, `register ${label}: ${JSON.stringify(r.body)}`); assert.equal(r.body.error, 'bad_registration_signature', `register ${label}`);
      }
      const okReg = await postWithin(sc, '/cia/register', regBody(goodReg));   // 거절된 시도는 uid 를 잠그지 않았다
      assert.equal(okReg.status, 201, JSON.stringify(okReg.body));
      const u = userOf({ ...reg, slot: okReg.body.slot }, '12345');

      const nonce = randomScalar();
      const goodSlot = await signSlotRequest(reg.sk_u, uid, nonce);
      for (const [label, bad] of badSigVariants(goodSlot)) {
        const r = await postWithin(sc, '/cia/slot', { uid: '12345', nonce: nonce.toString(), sig_u: bad });
        assert.equal(r.status, 400, `slot ${label}: ${JSON.stringify(r.body)}`); assert.equal(r.body.error, 'bad user signature', `slot ${label}`);
      }
      assert.equal((await postWithin(sc, '/cia/slot', { uid: '12345', nonce: nonce.toString(), sig_u: goodSlot })).status, 200);

      // /cia/issue: 요청 하나를 만들어 두고(보내지 않는다) sig_u 만 바꿔 보낸다 — 서명 검사는 π_IdP 검증·체인 조회보다 앞이다.
      let body = null;
      await issueV11(sc, u, { arid, max_height: 999999n, post: async (p, b) => { body = b; return { status: 0, body: null }; } });
      for (const [label, bad] of badSigVariants(body.sig_u)) {
        const r = await postWithin(sc, '/cia/issue', { ...body, sig_u: bad });
        assert.equal(r.status, 400, `issue ${label}: ${JSON.stringify(r.body)}`); assert.equal(r.body.error, 'bad user signature', `issue ${label}`);
      }
      assert.equal((await postWithin(sc, '/cia/issue', body, 10_000)).status, 200, '대조군: 같은 요청을 원래 서명으로 보내면 발급된다');
      const alive = await fetch(`${sc.base}/cia/public_keys`, { signal: AbortSignal.timeout(2000) });
      assert.equal(alive.status, 200, '프로세스가 계속 응답한다');
    } finally { await sc.stop(); }
  });

  // 리뷰 S4(2026-10-13): π_IdP vkey 를 못 읽으면 503 이되 응답은 고정 사유뿐 — 절대경로·ENOENT 는 지갑을 거쳐 페이지까지 가므로 서버 로그에만.
  await t('리뷰 S4: π_IdP vkey 가 없으면 /cia/issue 는 503 idp_vkey_unavailable — 응답에 경로·ENOENT 없음(서버 로그에만)', async () => {
    const missing = path.join(cia.dir, 'no-such-pi_idp_vkey.json');
    const vc = await startIsolatedCia({ env: { MODE3_IDP_VKEY_PATH: missing } });
    try {
      const u = userOf(await vc.registerUser('12345', 'password123'), '12345');
      const r = await issueV11(vc, u, { arid, max_height: 999999n });
      assert.equal(r.r.status, 503, JSON.stringify(r.r.body));
      assert.deepEqual(r.r.body, { error: 'idp_vkey_unavailable', reason: 'idp_vkey_unavailable' });
      assert.ok(vc.log().includes('ENOENT'), '원인은 서버 로그에 남는다');
    } finally { await vc.stop(); }
  });
} finally {
  await cia.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
