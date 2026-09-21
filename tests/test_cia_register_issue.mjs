// CIA 엔드포인트 — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_register_issue.mjs
import assert from 'node:assert/strict';
import { buildBabyjub, buildEddsa, buildPoseidon } from 'circomlibjs';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider, logAbi, signRootPublication } from './helpers/mode3_chain.mjs';
import { randomScalar, sessionCommit, compressPoint, credMessageV5, SCALAR_MAX } from '../lib/mode3_credential.js';
import { userLeaf } from '../lib/mode3_revocation.js';
import { registrationCommit, proveUserCred, serializeUserCredProof, userCredRequestMessage, issueRequestMessageV4, pointToStrings } from '../lib/mode3_issuance.js';
import { syncRevocationTree } from '../lib/mode3_wallet.js';
import { verifyRpCert } from '../lib/mode3_rp_cert.js';
import { createShare } from '../lib/mode3_trace.js';
import { LOG_ABI } from '../lib/mode3_log.js';

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

/** 사용자 자격증명 요청 본문. u 는 { s_u, r_u, sk_u(Buffer), attrs }. 다른 계정이면 uidBig 을 준다. */
async function userCredRequest(u, overrides = {}, uidBig = uid) {
  const blind_u = randomScalar();
  const { C_u_pt, proof } = await proveUserCred({ uid: uidBig, s_u: u.s_u, blind_u, r_u: u.r_u, attrs: u.attrs ?? [19n, 410n, 0n, 0n] });
  const Cf_u = await compressPoint(C_u_pt);
  return { body: { uid: uidBig.toString(), C_u_pt: pointToStrings(C_u_pt), proof: serializeUserCredProof(proof), sig_u: await signMsg(u.sk_u, await userCredRequestMessage(C_u_pt)), ...overrides }, C_u_pt, Cf_u, blind_u, leaf: await userLeaf(Cf_u) };
}
/** 데모 계정 하나를 등록만 한다(user_cred 없음). { s_u, r_u, cm_u, sk_u(Buffer) } 를 돌려준다. */
async function freshRegistered(uidStr, pwd) {
  const s_u = randomScalar(), r_u = randomScalar();
  const cm_u = await registrationCommit(s_u, r_u);
  const r = await cia.post('/cia/register', { uid: uidStr, pwd, cm_u: pointToStrings(cm_u) });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  return { s_u, r_u, cm_u, sk_u: Buffer.from(r.body.sk_u, 'hex') };
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
/** 새 사용자 자격증명을 받고(201) 곧바로 물려(scope=credential) 그 리프를 pending 에 넣는다. 활성 자격증명이 없는 상태에서 불러야
 *  inserted 가 정확히 그 리프 하나다(있으면 user_cred 가 옛 것을 먼저 물려 리프가 둘 들어간다). 리프(10진)를 돌려준다. */
async function revokedLeaf() {
  const c = await userCredRequest(user);
  assert.equal((await cia.post('/cia/user_cred', c.body)).status, 201);
  const r = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.inserted, [c.leaf.toString()]);
  return c.leaf.toString();
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
    const r = await cia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: { x: '1', y: '1' } });
    assert.equal(r.status, 400, JSON.stringify(r.body));
    const bj = await buildBabyjub();
    const p = bj.F.p;
    const G = { x: bj.F.toObject(bj.Base8[0]), y: bj.F.toObject(bj.Base8[1]) };
    const nonCanonical = { x: (G.x + p).toString(), y: G.y.toString() };   // 값은 같아도 비정규 인코딩
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: nonCanonical })).status, 400);
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

  await t('register: cm_u 등록, 장기키 발급', async () => {
    const s_u = randomScalar(), r_u = randomScalar();
    const cm_u = await registrationCommit(s_u, r_u);
    const r = await cia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: pointToStrings(cm_u) });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    const sk_u = Buffer.from(r.body.sk_u, 'hex');
    const pub = eddsa.prv2pub(sk_u);
    assert.equal(F.toObject(pub[0]).toString(), r.body.pk_u.x, '돌려준 sk_u 가 pk_u 와 맞아야 한다');
    user = { s_u, r_u, cm_u, sk_u, pk_u: r.body.pk_u };
  });

  await t('register: 잘못된 비밀번호는 401, 재등록은 409', async () => {
    const cm = pointToStrings(await registrationCommit(1n, 2n));
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'wrong', cm_u: cm })).status, 401);
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: cm })).status, 409);
  });

  await t('user_cred: 201 {Cf_u, leaf}; 같은 Cf_u 재요청은 200; 잘못된 증명·서명은 400; cm_u 와 다른 s_u 는 400', async () => {
    const c = await userCredRequest(user);
    const r = await cia.post('/cia/user_cred', c.body);
    assert.equal(r.status, 201, JSON.stringify(r.body));
    assert.equal(r.body.Cf_u, c.Cf_u.toString()); assert.equal(r.body.leaf, c.leaf.toString());
    assert.equal((await cia.post('/cia/user_cred', c.body)).status, 200);
    const bad = await userCredRequest(user); bad.body.proof.z_su = '1';
    assert.equal((await cia.post('/cia/user_cred', bad.body)).status, 400);
    const sybil = await userCredRequest({ ...user, s_u: user.s_u + 1n });
    assert.equal((await cia.post('/cia/user_cred', sybil.body)).status, 400);
    const badSig = await userCredRequest(user); badSig.body.sig_u = (await userCredRequest(user)).body.sig_u;
    assert.equal((await cia.post('/cia/user_cred', badSig.body)).status, 400);
    assert.equal((await cia.get('/cia/state')).body.credCount, 1, '활성 자격증명은 하나');
  });

  await t('user_cred: 새 자격증명을 받으면 옛 것은 revoked 되고 리프가 pending 에 들어간다 (속성 변경)', async () => {
    const a = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', a.body)).status, 201);
    const before = (await cia.get('/cia/state')).body.pendingCount;
    const b = await userCredRequest({ ...user, attrs: [20n, 410n, 0n, 0n] }); assert.equal((await cia.post('/cia/user_cred', b.body)).status, 201);
    const st = (await cia.get('/cia/state')).body;
    assert.equal(st.pendingCount, before + 1);
    assert.equal(st.credCount, 1);
    // 옛 Cf_u 로는 세션 발급이 안 된다
    const old = await issueRequest(user, a);
    const r = await cia.post('/cia/issue', old.body);
    assert.equal(r.status, 403); assert.equal(r.body.reason, 'no_user_cred');
    // 물린 Cf_u 를 다시 올려도 되살아나지 않는다(409) — 리프가 이미 트리에 있다
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

  await t('revoke(account): 활성 자격증명 리프 하나가 트리에 들어가고 disabled; 재요청은 멱등(새 리프 없음); 이후 issue 403', async () => {
    const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
    const pendingBefore = (await cia.get('/cia/state')).body.pendingCount;
    const r = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.deepEqual(r.body.inserted, [cred.leaf.toString()]);
    assert.equal(r.body.pending, pendingBefore + 1);
    const again = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' });
    assert.equal(again.status, 200); assert.deepEqual(again.body.inserted, []);
    assert.equal((await cia.get('/cia/state')).body.credCount, 0);
    const req = await issueRequest(user, cred);
    const denied = await cia.post('/cia/issue', req.body);
    assert.equal(denied.status, 403); assert.equal(denied.body.reason, 'account_disabled');
    assert.equal((await cia.post('/cia/user_cred', (await userCredRequest(user)).body)).status, 403, 'disabled 면 새 자격증명도 안 준다');
  });

  await t('publish: 서명 root 가 RevocationLog 에 올라가고 epoch 1', async () => {
    const r = await cia.adminPost('/cia/publish');
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.published, true);
    assert.equal(r.body.epoch, 1);
    const log = new ethers.Contract(cia.logAddress, logAbi(), provider);
    assert.equal(BigInt(await log.root()).toString(), BigInt(r.body.root).toString());
    assert.equal(await log.epoch(), 1n);
    const st = await cia.get('/cia/state');
    assert.equal(st.body.pendingCount, 0);
    assert.equal(st.body.epoch, 1);
  });

  await t('publish: 대기 리프가 없으면 published:false 이고 epoch 그대로', async () => {
    const r = await cia.adminPost('/cia/publish');
    assert.equal(r.status, 200);
    assert.equal(r.body.published, false);
    assert.equal((await cia.get('/cia/state')).body.epoch, 1);
  });

  await t('revoke(credential): 리프만 넣고 계정은 살아 있다 — 새 user_cred 를 받으면 다시 발급된다 (set_disabled false 복구 §6.6 포함)', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
    const r = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential' });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.deepEqual(r.body.inserted, [cred.leaf.toString()]);
    const denied = await cia.post('/cia/issue', (await issueRequest(user, cred)).body);
    assert.equal(denied.status, 403); assert.equal(denied.body.reason, 'no_user_cred');
    // leaf/C 인자는 무시된다(400 아님) — 활성 자격증명이 없으니 inserted 는 빈 배열
    const ignored = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential', leaf: '777', C: '1' });
    assert.equal(ignored.status, 200, JSON.stringify(ignored.body)); assert.deepEqual(ignored.body.inserted, []);
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

  await t('revoke: 활성 자격증명이 없는 계정의 account 폐기는 disabled 만 건다 (inserted 빈 배열)', async () => {
    // 등록만 하고 user_cred 를 받지 않은 새 계정 — 데모 계정 alice(67890). 앞 케이스가 "등록 안 된 계정 404" 를 본 뒤여야 한다.
    const u2 = await freshRegistered('67890', 'alicepw');
    const pendingBefore = (await cia.get('/cia/state')).body.pendingCount;
    const r = await cia.adminPost('/cia/revoke', { uid: '67890', scope: 'account' });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.deepEqual(r.body.inserted, []);
    assert.equal(r.body.pending, pendingBefore);
    assert.equal((await cia.post('/cia/user_cred', (await userCredRequest(u2, {}, 67890n)).body)).status, 403);
  });

  await t('self_revoke: 비밀번호만으로 계정 폐기 — 활성 자격증명 리프 하나 + disabled; 재요청은 새 리프 없이 200', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
    const issued = await cia.post('/cia/issue', (await issueRequest(user, cred)).body);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const before = (await cia.get('/cia/state')).body.pendingCount;
    const r = await cia.post('/cia/account/self_revoke', { uid: uid.toString(), pwd: 'password123' });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.inserted, [cred.leaf.toString()], '활성 사용자 자격증명의 리프가 들어가야 한다(세션 리프는 없다)'); assert.equal(r.body.disabled, true);
    assert.equal(r.body.pending, before + 1);
    assert.equal((await cia.get('/cia/state')).body.pendingCount, r.body.pending);
    const again = await cia.post('/cia/account/self_revoke', { uid: uid.toString(), pwd: 'password123' });
    assert.equal(again.status, 200); assert.deepEqual(again.body.inserted, []); assert.equal(again.body.disabled, true);
    assert.equal(again.body.pending, r.body.pending);
    assert.equal((await cia.post('/cia/issue', (await issueRequest(user, cred)).body)).status, 403);
    // 복구는 관리자만 한다(§6.6). 뒤 케이스들을 위해 여기서 되살린다 — 사용자 자격증명부터 다시 받아야 발급된다.
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    const cred2 = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred2.body)).status, 201);
    assert.equal((await cia.post('/cia/issue', (await issueRequest(user, cred2)).body)).status, 200);
  });

  await t('self_revoke: 체인이 죽어도 200 이고 disabled 가 걸리며 treeUpdated 필드가 없다', async () => {
    // 죽은 RPC 로 두 번째 격리 인스턴스를 띄운다 — 기동 시 root 대조는 RPC 실패를 건너뛰므로 기동 자체는 된다.
    const dead = await startIsolatedCia({ env: { CIA_RPC_URL: 'http://127.0.0.1:1' } });
    try {
      const cmSu = randomScalar(), cmRu = randomScalar();
      const cm_u = await registrationCommit(cmSu, cmRu);
      const reg = await dead.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: pointToStrings(cm_u) });
      assert.equal(reg.status, 201, JSON.stringify(reg.body));

      // 사용자 자격증명 발급은 체인을 보지 않는다(세션 발급만 chainAlive) — 죽은 체인에서도 201.
      const dc = await userCredRequest({ s_u: cmSu, r_u: cmRu, sk_u: Buffer.from(reg.body.sk_u, 'hex') });
      assert.equal((await dead.post('/cia/user_cred', dc.body)).status, 201);

      const r = await dead.post('/cia/account/self_revoke', { uid: '12345', pwd: 'password123' });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      assert.equal(r.body.disabled, true);
      // treeUpdated 는 옛 판(체인이 죽으면 삽입을 미루는)의 필드다 — 리프가 사용자 자격증명에서 나와 만료·체인 헤드와
      // 무관해지면서 삽입 자체에 체인이 필요 없어졌다(설계 2026-09-21 §3.6).
      assert.equal(r.body.treeUpdated, undefined);
      assert.deepEqual(r.body.inserted, [dc.leaf.toString()], '체인이 죽어도 활성 자격증명의 리프는 들어간다');
      assert.equal((await dead.get('/cia/state')).body.pendingCount, 1);

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
    // 앞 케이스들이 남긴 활성 자격증명을 물리고 pending 을 먼저 비운다 — 아래의 직접 게시는 "CIA 가 올렸을 것"과 똑같이
    // pending 전부를 실어야 하는데, 여기서는 이 케이스가 폐기한 리프 하나만 싣기 때문이다.
    assert.equal((await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).status, 200);
    // 새 사용자 자격증명을 하나 받아 폐기한다 (계정은 앞의 self_revoke 멱등 케이스 끝에서 재활성화됨)
    const leaf = await revokedLeaf();

    // CIA 가 아직 게시하기 전에, 체인에 직접 다음 epoch 를 (이 리프를 실어) 게시한다 — tx 는 성공해
    // 이벤트까지 나갔는데 CIA 가 persist() 전에 죽어버린 크래시 시나리오를 흉내낸다.
    const before = await cia.get('/cia/state');
    const current = before.body.epoch;
    const log = new ethers.Contract(cia.logAddress, logAbi(), provider);
    assert.equal(await log.epoch(), BigInt(current), '아직은 로컬·온체인 epoch 가 같아야 한다');
    const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32);
    const root = b32(before.body.root);
    const directEpoch = current + 1;
    const sig = await signRootPublication(cia.ciaEthWallet, { logAddress: cia.logAddress, root, epoch: directEpoch, leaves: [b32(leaf)] });
    const tx = await log.connect(cia.ciaEthWallet).publishRoot(root, directEpoch, [b32(leaf)], sig);
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
    // 다음 폐기는 따라잡은 epoch 의 다음(current+2) 으로 나간다
    await revokedLeaf();
    const r2 = await cia.adminPost('/cia/publish');
    assert.equal(r2.status, 200, JSON.stringify(r2.body));
    assert.equal(r2.body.published, true);
    assert.equal(r2.body.epoch, current + 2);
    assert.equal(await log.epoch(), BigInt(current + 2));
  });

  await t('publish 도중 들어온 revoke 의 리프는 pending 에 남아 다음 publish 로 나간다', async () => {
    // publish 는 tx.wait() 를 기다리는 동안 다른 요청을 받는다. 그 사이 revoke 가 pending 에 붙인
    // 리프를 publish 가 pending 전체를 비우며 버리면, 그 리프는 온체인 이벤트로 영영 안 나가고
    // 이후 모든 서명 root 에는 들어 있어 지갑의 재구성이 전부 fail-closed 된다.
    // automine 을 꺼서 tx.wait() 를 확실히 붙잡아 둔 채로 revoke 를 끼워 넣는다.
    const st0 = (await cia.get('/cia/state')).body;
    assert.equal(st0.credCount, 0, '앞 케이스가 활성 자격증명을 남기지 않았어야 한다'); assert.equal(st0.pendingCount, 0);
    const L1 = await revokedLeaf();
    const c2 = await userCredRequest(user);   // 활성으로 두고 아직 폐기하지 않는다 — publish 가 tx 를 보낸 뒤에 한다
    assert.equal((await cia.post('/cia/user_cred', c2.body)).status, 201);
    const L2 = c2.leaf.toString();

    await provider.send('evm_setAutomine', [false]);
    try {
      const publishing = cia.adminPost('/cia/publish');
      // CIA 가 tx 를 mempool 에 넣고 tx.wait() 에 들어갈 때까지 기다린다
      const deadline = Date.now() + 15_000;
      while ((await provider.send('eth_pendingTransactions', [])).length === 0) {
        assert.ok(Date.now() < deadline, 'publish tx 가 mempool 에 오지 않았다');
        await new Promise((r) => setTimeout(r, 100));
      }
      const rv = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' });
      assert.equal(rv.status, 200, JSON.stringify(rv.body));
      assert.deepEqual(rv.body.inserted, [L2]);
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
    // 지갑이 이벤트만으로 재구성한 root 가 서명 root 와 같아야 한다 (fail-closed 검사가 통과)
    const synced = await syncRevocationTree(provider, cia.logAddress);
    assert.equal(synced.root.toString(), pub2.body.root);
  });

  await t('admin 엔드포인트는 시크릿 없이 401', async () => {
    assert.equal((await cia.post('/cia/revoke', { uid: '12345', scope: 'account' })).status, 401);
  });

  // 마지막에 둔다 — 이 뒤로는 온체인 root 가 로컬과 어긋난 채 남아 게시가 전부 503 이다.
  await t('publish: 온체인 root 가 로컬 기록의 어느 접두사와도 다르면 503 이고 올리지 않는다', async () => {
    // CIA 가 켜진 채로 로그가 (같은 CIA 키로) 다른 root 로 갈라졌다고 치자 — 직접 엉뚱한 root 를 올린다.
    // 게시 직전 대조가 없으면 CIA 는 이벤트로 나간 적 없는 리프를 품은 root 를 서명해 올려 전원의 재구성이 깨진다.
    const log = new ethers.Contract(cia.logAddress, logAbi(), provider);
    const current = Number(await log.epoch());
    const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32);
    const bogus = b32(12345n);
    const sig = await signRootPublication(cia.ciaEthWallet, { logAddress: cia.logAddress, root: bogus, epoch: current + 1, leaves: [] });
    await (await log.connect(cia.ciaEthWallet).publishRoot(bogus, current + 1, [], sig)).wait();
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
      const log = new ethers.Contract(hbCia.logAddress, LOG_ABI, provider);
      const root0 = await log.root(), epoch0 = await log.epoch();
      await provider.send('hardhat_mine', ['0x3']);
      const deadline = Date.now() + 10_000;
      while (Date.now() < deadline && (await log.epoch()) === epoch0) await new Promise((r) => setTimeout(r, 200));
      assert.equal(await log.epoch(), epoch0 + 1n, hbCia.log());
      assert.equal(await log.root(), root0, '하트비트는 root 를 바꾸지 않는다');
      assert.ok(BigInt(await log.lastPublishedBlock()) > 0n);
      assert.equal((await hbCia.get('/cia/state')).body.epoch, Number(epoch0) + 1, 'CIA 상태의 epoch 도 따라간다');
    } finally { await hbCia.stop(); }
  });
} finally {
  await cia.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
