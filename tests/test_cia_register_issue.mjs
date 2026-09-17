// CIA 엔드포인트 — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_register_issue.mjs
import assert from 'node:assert/strict';
import { buildBabyjub, buildEddsa, buildPoseidon } from 'circomlibjs';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider, logAbi, signRootPublication } from './helpers/mode3_chain.mjs';
import { randomScalar, credMessage, compressPoint, SCALAR_MAX } from '../lib/mode3_credential.js';
import { credLeaf } from '../lib/mode3_revocation.js';
import { registrationCommit, proveIssuance, serializeProof, pointToStrings } from '../lib/mode3_issuance.js';
import { syncRevocationTree, signUserRequest } from '../lib/mode3_wallet.js';
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
const pk_i = BigInt(ethers.Wallet.createRandom().address);
let user;   // { s_u, r_u, cm_u, sk_u(Buffer), pk_u }

// 사용자 서명은 (C_pt, chainid, allowAgent) 를 덮는다(2026-09-18 §3.3). CIA 는 로그인당 기록이 없다 — 옛 본문 재생으로
// 얻는 것은 같은 C_pt 의 자격증명 하나뿐이고 sk_i 없이는 쓸 수 없다.
const CHAIN_ID = 31337n;
const signUser = (prvBuf, C_pt, chainid, allowAgent) => signUserRequest(prvBuf.toString('hex'), C_pt, chainid, allowAgent);

async function issueRequest(u, overrides = {}, { chainid = CHAIN_ID, allowAgent = 0n, attrs = [19n, 410n, 0n, 0n] } = {}) {
  const blind = randomScalar();
  const { C_pt, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind, pk_i, r_u: u.r_u, attrs });
  return { body: { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u: await signUser(u.sk_u, C_pt, chainid, allowAgent), chainid: chainid.toString(), allowAgent: allowAgent.toString(), ...overrides }, C_pt, blind };
}

try {
  await t('public_keys 가 CIA EdDSA 키·ETH 주소·TTL·로그 주소를 준다', async () => {
    const r = await cia.get('/cia/public_keys');
    assert.equal(r.status, 200);
    assert.equal(r.body.ethAddress.toLowerCase(), cia.ethAddress.toLowerCase());
    assert.equal(r.body.ttlBlocks, 300); assert.equal(r.body.heightGrid, 100); assert.equal(r.body.heartbeatBlocks, 0); assert.deepEqual(r.body.chainIds, ['31337']);
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

  let cred;
  await t('issue: 올바른 π_issue + 사용자 서명 → CIA 서명 credential', async () => {
    const { body, C_pt } = await issueRequest(user);
    const r = await cia.post('/cia/issue', body);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    cred = r.body;
    // C 는 CIA 가 C_pt 에서 유도한 값이어야 한다
    assert.equal(cred.C, (await compressPoint(C_pt)).toString());
    // σ_CIA 가 credMessage(C, max_height, chainid, allowAgent) 에 대한 pk_CIA 서명인지
    const msg = F.e(await credMessage(BigInt(cred.C), BigInt(cred.max_height), BigInt(cred.chainid), BigInt(cred.allowAgent)));
    const sig = { R8: [F.e(BigInt(cred.sigma.R8x)), F.e(BigInt(cred.sigma.R8y))], S: BigInt(cred.sigma.S) };
    const pub = [F.e(BigInt(cred.pk_CIA.x)), F.e(BigInt(cred.pk_CIA.y))];
    assert.ok(eddsa.verifyPoseidon(msg, sig, pub));
    // max_height = ceil((head + 300) / 100) × 100 — 그리드 배수이고 [head+300, head+400) 안(2026-09-18 §3.2)
    const head = BigInt(await provider.getBlockNumber());
    const mh = BigInt(cred.max_height);
    assert.equal(mh % 100n, 0n, cred.max_height);
    assert.ok(mh >= head + 300n && mh < head + 400n, `max_height ${mh} vs head ${head}`);
    assert.equal(cred.chainid, '31337');
    assert.equal(cred.allowAgent, '0');
    assert.equal(cred.exptime, undefined); assert.equal(cred.r_s, undefined);
  });

  await t('issue: 다른 s_u 로 만든 C_pt 는 400 (cm_u 동일성)', async () => {
    const fake = { ...user, s_u: randomScalar() };
    const { body } = await issueRequest(fake);
    assert.equal((await cia.post('/cia/issue', body)).status, 400);
  });

  await t('issue: 사용자 서명이 다른 키면 400', async () => {
    const { body, C_pt } = await issueRequest(user);
    body.sig_u = await signUser(Buffer.alloc(32, 7), C_pt, CHAIN_ID, 0n);
    assert.equal((await cia.post('/cia/issue', body)).status, 400);
  });

  await t('issue: allowAgent 는 서명이 덮는다 — 플래그만 바꾸면 400, 2 는 400, 없으면 400, 허용 목록 밖 chainid 는 400', async () => {
    const flipped = await issueRequest(user);
    flipped.body.allowAgent = '1';
    assert.equal((await cia.post('/cia/issue', flipped.body)).status, 400);
    const two = await issueRequest(user, { allowAgent: '2' });
    assert.equal((await cia.post('/cia/issue', two.body)).status, 400);
    const missing = await issueRequest(user);
    delete missing.body.allowAgent;
    assert.equal((await cia.post('/cia/issue', missing.body)).status, 400);
    const wrongChain = await issueRequest(user, {}, { chainid: 1n });
    const r2 = await cia.post('/cia/issue', wrongChain.body);
    assert.equal(r2.status, 400, JSON.stringify(r2.body));
    assert.match(r2.body.error, /chainid/);
  });

  await t('issue: allowAgent = 1 로 서명한 요청은 200 이고 응답의 allowAgent 도 1', async () => {
    const { body } = await issueRequest(user, {}, { allowAgent: 1n });
    const r = await cia.post('/cia/issue', body);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.allowAgent, '1');
  });

  await t('issue: 같은 C_pt 재요청은 200 — 같은 C 의 기록은 하나이고 max_height 는 큰 쪽(2026-09-18 §3.3·§4.3)', async () => {
    const { body } = await issueRequest(user);
    const a = await cia.post('/cia/issue', body);
    assert.equal(a.status, 200, JSON.stringify(a.body));
    await provider.send('hardhat_mine', ['0x64']);   // 100 블록 → 다음 그리드
    const b = await cia.post('/cia/issue', body);
    assert.equal(b.status, 200, JSON.stringify(b.body));
    assert.equal(b.body.C, a.body.C);
    assert.ok(BigInt(b.body.max_height) > BigInt(a.body.max_height));
    // 기록이 하나여야 한다: 리프로 폐기하면 inserted 가 정확히 1 개
    const r = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential', C: a.body.C });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.inserted.length, 1);
  });

  await t('revoke(account): 미만료 credential 리프가 트리에 들어가고 disabled 된다', async () => {
    // 앞의 '같은 C_pt 재요청' 케이스가 리프 하나를 이미 pending 에 남겨 뒀다(§3.3·§4.3 재요청 갱신 테스트) — 이번
    // 호출이 넣는 개수만큼 늘었는지를 본다(절대값 대신).
    const pendingBefore = (await cia.get('/cia/state')).body.pendingCount;
    const r = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const leaf = await credLeaf(BigInt(cred.C));
    assert.ok(r.body.inserted.map((h) => BigInt(h)).includes(leaf), '발급했던 credential 의 리프가 있어야 한다');
    assert.equal(r.body.pending, pendingBefore + r.body.inserted.length);
    const { body } = await issueRequest(user);
    assert.equal((await cia.post('/cia/issue', body)).status, 403, 'disabled 계정은 발급 거절');
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

  await t('set_disabled false → 다시 발급된다 (복구, §6.6)', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: '12345', disabled: false })).status, 200);
    const { body } = await issueRequest(user);
    assert.equal((await cia.post('/cia/issue', body)).status, 200);
  });

  await t('self_revoke: 잘못된 비밀번호 401, 등록 안 된 계정 404, 형식 오류 400', async () => {
    // 관리자 시크릿 없이 부른다 — 이 경로의 인증은 계정 비밀번호뿐이다(설계 §6.5.1).
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: '12345', pwd: 'wrong' })).status, 401);
    // alice(67890) 는 데모 계정이지만 이 인스턴스에 등록한 적이 없다.
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: '67890', pwd: 'alicepw' })).status, 404);
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: 'abc', pwd: 'password123' })).status, 400);
    assert.equal((await cia.post('/cia/account/self_revoke', { uid: '12345' })).status, 400);
    // 실패한 요청은 아무것도 바꾸지 않는다
    const { body } = await issueRequest(user);
    assert.equal((await cia.post('/cia/issue', body)).status, 200, '계정은 여전히 활성이어야 한다');
  });

  await t('self_revoke: 비밀번호만으로 계정 전체 폐기 — 리프 삽입 + disabled, 이후 발급 403', async () => {
    const { body: ib } = await issueRequest(user);
    const issued = await cia.post('/cia/issue', ib);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const leaf = await credLeaf(BigInt(issued.body.C));
    const before = (await cia.get('/cia/state')).body.pendingCount;

    const r = await cia.post('/cia/account/self_revoke', { uid: '12345', pwd: 'password123' });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.disabled, true);
    assert.ok(r.body.inserted.map((h) => BigInt(h)).includes(leaf), '방금 발급한 credential 의 리프가 들어가야 한다');
    assert.equal(r.body.pending, before + r.body.inserted.length);
    assert.equal((await cia.get('/cia/state')).body.pendingCount, r.body.pending);

    const { body } = await issueRequest(user);
    assert.equal((await cia.post('/cia/issue', body)).status, 403, 'disabled 계정은 발급 거절');
  });

  await t('self_revoke: 재요청은 멱등 — 새 리프 없이 200, disabled 유지', async () => {
    const pendingBefore = (await cia.get('/cia/state')).body.pendingCount;
    const r = await cia.post('/cia/account/self_revoke', { uid: '12345', pwd: 'password123' });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.inserted, []);
    assert.equal(r.body.disabled, true);
    assert.equal(r.body.pending, pendingBefore);
    // 복구는 관리자만 한다(§6.6). 뒤 케이스들을 위해 여기서 되살린다.
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: '12345', disabled: false })).status, 200);
    const { body } = await issueRequest(user);
    assert.equal((await cia.post('/cia/issue', body)).status, 200);
  });

  await t('self_revoke: 체인이 죽어도 200 이고 disabled 가 걸리며 treeUpdated 필드가 없다', async () => {
    // 죽은 RPC 로 두 번째 격리 인스턴스를 띄운다 — 기동 시 root 대조는 RPC 실패를 건너뛰므로 기동 자체는 된다.
    const dead = await startIsolatedCia({ env: { CIA_RPC_URL: 'http://127.0.0.1:1' } });
    try {
      const cm_u = await registrationCommit(randomScalar(), randomScalar());
      const reg = await dead.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: pointToStrings(cm_u) });
      assert.equal(reg.status, 201, JSON.stringify(reg.body));

      const r = await dead.post('/cia/account/self_revoke', { uid: '12345', pwd: 'password123' });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      assert.equal(r.body.disabled, true);
      // treeUpdated 는 옛 판(체인이 죽으면 삽입을 미루는)의 필드다 — 만료 판정이 벽시계가 되면서
      // 삽입 자체에 체인이 필요 없어져 사라졌다(설계 2026-09-14 §7, 기반 설계 §6.5.1 개정).
      assert.equal(r.body.treeUpdated, undefined);
      // 이 uid 는 등록 직후 곧바로 self_revoke 됐다 — 이 dead 인스턴스에서 발급받은 credential 이
      // 아예 없으므로(체인이 죽어 있어 /cia/issue 도 503 이라 발급을 시도할 수도 없다) 넣을 리프가 없다.
      // 삽입 자체가 벽시계 기준이라 체인이 필요 없다는 것은 앞의 '비밀번호만으로 계정 전체 폐기' 케이스(라이브
      // 인스턴스에서 발급 → self_revoke → inserted 에 그 리프가 들어감)로 이미 검증됐다.
      assert.deepEqual(r.body.inserted, []);
      assert.equal((await dead.get('/cia/state')).body.pendingCount, 0);

      // 발급은 disabled 검사가 chainid 허용 목록 확인보다 먼저다(cia.js /cia/issue) — 체인 없이도 403 이어야 한다.
      const issued = await dead.post('/cia/issue', {
        uid: '12345', C_pt: { x: '1', y: '1' }, proof: {}, sig_u: {}, chainid: '31337', allowAgent: '0',
      });
      assert.equal(issued.status, 403, JSON.stringify(issued.body));
    } finally {
      await dead.stop();
    }
  });

  await t('revoke(credential): 이 uid 에 발급되지 않은 리프는 404 이고 트리에 들어가지 않는다', async () => {
    // 폐기는 append-only 라 오타 하나가 영구히 남는다 — 그 uid 의 미만료 발급 목록에 있는 리프만 받는다.
    const before = (await cia.get('/cia/state')).body.leafCount;
    for (const leaf of ['777', '0']) {
      const r = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential', leaf });
      assert.equal(r.status, 404, `leaf=${leaf}: ${JSON.stringify(r.body)}`);
    }
    assert.equal((await cia.get('/cia/state')).body.leafCount, before);
  });

  await t('revoke(credential): C 로 지정하면 서버가 리프를 유도한다', async () => {
    const { body } = await issueRequest(user);
    const issued = await cia.post('/cia/issue', body);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const r = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential', C: issued.body.C });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.inserted, [(await credLeaf(BigInt(issued.body.C))).toString()]);
  });

  await t('publish: 체인의 epoch 가 앞서 있어도 CIA 가 따라잡는다 (크래시 복구)', async () => {
    // 앞 케이스들이 남긴 pending 을 먼저 비운다 — 아래의 직접 게시는 "CIA 가 올렸을 것"과 똑같이 pending 전부를
    // 실어야 하는데, 여기서는 이 케이스가 폐기한 리프 하나만 싣기 때문이다.
    assert.equal((await cia.adminPost('/cia/publish')).status, 200);
    // 새 credential 을 하나 발급해서 폐기한다 (계정은 앞의 self_revoke 멱등 케이스 끝에서 재활성화됨)
    const { body: issueBody } = await issueRequest(user);
    const issued = await cia.post('/cia/issue', issueBody);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const leaf = (await credLeaf(BigInt(issued.body.C))).toString();
    const rv = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential', leaf });
    assert.equal(rv.status, 200, JSON.stringify(rv.body));

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
    const { body: issueBody2 } = await issueRequest(user);
    const issued2 = await cia.post('/cia/issue', issueBody2);
    assert.equal(issued2.status, 200, JSON.stringify(issued2.body));
    assert.equal((await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential', C: issued2.body.C })).status, 200);
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
    const issueLeaf = async () => {
      const { body } = await issueRequest(user);
      const r = await cia.post('/cia/issue', body);
      assert.equal(r.status, 200, JSON.stringify(r.body));
      return (await credLeaf(BigInt(r.body.C))).toString();
    };
    const L1 = await issueLeaf();
    assert.equal((await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential', leaf: L1 })).status, 200);
    const L2 = await issueLeaf();   // 아직 폐기하지 않는다 — publish 가 tx 를 보낸 뒤에 한다

    await provider.send('evm_setAutomine', [false]);
    try {
      const publishing = cia.adminPost('/cia/publish');
      // CIA 가 tx 를 mempool 에 넣고 tx.wait() 에 들어갈 때까지 기다린다
      const deadline = Date.now() + 15_000;
      while ((await provider.send('eth_pendingTransactions', [])).length === 0) {
        assert.ok(Date.now() < deadline, 'publish tx 가 mempool 에 오지 않았다');
        await new Promise((r) => setTimeout(r, 100));
      }
      const rv = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential', leaf: L2 });
      assert.equal(rv.status, 200, JSON.stringify(rv.body));
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
    const { body: ib } = await issueRequest(user);
    const issued = await cia.post('/cia/issue', ib);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal((await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential', C: issued.body.C })).status, 200);
    const r = await cia.adminPost('/cia/publish');
    assert.equal(r.status, 503, JSON.stringify(r.body));
    assert.match(r.body.error, /어느 접두사와도 다르다/);
    assert.equal(await log.epoch(), BigInt(current + 1), '올리지 않았어야 한다');
    assert.equal((await cia.get('/cia/state')).body.pendingCount, 1, 'pending 은 그대로여야 한다');
  });

  await t('I1: max_height 가 지나도 CIA_REVOKE_SKEW_BLOCKS 안이면 계정 폐기 대상에 남는다', async () => {
    const skewCia = await startIsolatedCia({ env: { CIA_TTL_BLOCKS: '1', CIA_HEIGHT_GRID: '1', CIA_REVOKE_SKEW_BLOCKS: '600' } });
    try {
      const s_u = randomScalar(), r_u = randomScalar();
      const cm_u = await registrationCommit(s_u, r_u);
      const reg = await skewCia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: pointToStrings(cm_u) });
      assert.equal(reg.status, 201, JSON.stringify(reg.body));
      const sk_u = Buffer.from(reg.body.sk_u, 'hex');
      const blind = randomScalar();
      const { C_pt, proof } = await proveIssuance({ uid, arid, s_u, blind, pk_i, r_u, attrs: [19n, 410n, 0n, 0n] });
      const body = { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u: await signUser(sk_u, C_pt, CHAIN_ID, 0n), chainid: CHAIN_ID.toString(), allowAgent: '0' };
      const issued = await skewCia.post('/cia/issue', body);
      assert.equal(issued.status, 200, JSON.stringify(issued.body));
      await provider.send('hardhat_mine', ['0x5']);   // max_height(head+1) 는 지났지만 여유(600) 안
      const leaf = await credLeaf(BigInt(issued.body.C));
      const r = await skewCia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      assert.ok(r.body.inserted.map((h) => BigInt(h)).includes(leaf), '만료됐지만 여유 안이라 폐기 대상에 남아야 한다');
    } finally { await skewCia.stop(); }
  });

  await t('I2: 여유까지 지난 기록은 걷어내져 계정 폐기 대상에서 빠진다', async () => {
    const ttlCia = await startIsolatedCia({ env: { CIA_TTL_BLOCKS: '1', CIA_HEIGHT_GRID: '1', CIA_REVOKE_SKEW_BLOCKS: '0' } });
    try {
      const s_u = randomScalar(), r_u = randomScalar();
      const cm_u = await registrationCommit(s_u, r_u);
      const reg = await ttlCia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: pointToStrings(cm_u) });
      assert.equal(reg.status, 201, JSON.stringify(reg.body));
      const sk_u = Buffer.from(reg.body.sk_u, 'hex');
      const blind = randomScalar();
      const { C_pt, proof } = await proveIssuance({ uid, arid, s_u, blind, pk_i, r_u, attrs: [19n, 410n, 0n, 0n] });
      const body = { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u: await signUser(sk_u, C_pt, CHAIN_ID, 0n), chainid: CHAIN_ID.toString(), allowAgent: '0' };
      const first = await ttlCia.post('/cia/issue', body);
      assert.equal(first.status, 200, JSON.stringify(first.body));
      await provider.send('hardhat_mine', ['0x5']);
      const r = await ttlCia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      assert.deepEqual(r.body.inserted, [], '만료·여유 0 이면 리프가 걷어내져 있어야 한다');
    } finally { await ttlCia.stop(); }
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
