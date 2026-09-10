// CIA 엔드포인트 — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_register_issue.mjs
import assert from 'node:assert/strict';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider, logAbi, signRootPublication } from './helpers/mode3_chain.mjs';
import { randomScalar, credMessage, compressPoint } from '../lib/mode3_credential.js';
import { credLeaf } from '../lib/mode3_revocation.js';
import { registrationCommit, proveIssuance, serializeProof, pointToStrings } from '../lib/mode3_issuance.js';

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

function signUser(prvBuf, C_pt) {
  const m = F.e(F.toObject(poseidon([C_pt.x, C_pt.y])));
  const s = eddsa.signPoseidon(prvBuf, m);
  return { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() };
}

async function issueRequest(u, overrides = {}) {
  const blind = randomScalar();
  const { C_pt, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind, pk_i, r_u: u.r_u });
  return { body: { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u: signUser(u.sk_u, C_pt), ...overrides }, C_pt, blind };
}

try {
  await t('public_keys 가 CIA EdDSA 키·ETH 주소·TTL·로그 주소를 준다', async () => {
    const r = await cia.get('/cia/public_keys');
    assert.equal(r.status, 200);
    assert.equal(r.body.ethAddress.toLowerCase(), cia.ethAddress.toLowerCase());
    assert.equal(r.body.ttlBlocks, 300);
    assert.equal(r.body.logAddress.toLowerCase(), cia.logAddress.toLowerCase());
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
    // σ_CIA 가 credMessage(C, max_height) 에 대한 pk_CIA 서명인지
    const msg = F.e(await credMessage(BigInt(cred.C), BigInt(cred.max_height)));
    const sig = { R8: [F.e(BigInt(cred.sigma.R8x)), F.e(BigInt(cred.sigma.R8y))], S: BigInt(cred.sigma.S) };
    const pub = [F.e(BigInt(cred.pk_CIA.x)), F.e(BigInt(cred.pk_CIA.y))];
    assert.ok(eddsa.verifyPoseidon(msg, sig, pub));
    // max_height = head + 300
    const head = await provider.getBlockNumber();
    assert.ok(BigInt(cred.max_height) >= BigInt(head) + 299n && BigInt(cred.max_height) <= BigInt(head) + 301n);
  });

  await t('issue: 다른 s_u 로 만든 C_pt 는 400 (cm_u 동일성)', async () => {
    const fake = { ...user, s_u: randomScalar() };
    const { body } = await issueRequest(fake);
    assert.equal((await cia.post('/cia/issue', body)).status, 400);
  });

  await t('issue: 사용자 서명이 다른 키면 400', async () => {
    const { body, C_pt } = await issueRequest(user);
    body.sig_u = signUser(Buffer.alloc(32, 7), C_pt);
    assert.equal((await cia.post('/cia/issue', body)).status, 400);
  });

  await t('issue: 같은 C_pt 로 재요청하면 409 (재전송 방지)', async () => {
    const { body } = await issueRequest(user);
    const first = await cia.post('/cia/issue', body);
    assert.equal(first.status, 200, JSON.stringify(first.body));
    const second = await cia.post('/cia/issue', body);
    assert.equal(second.status, 409, JSON.stringify(second.body));
  });

  await t('revoke(account): 미만료 credential 리프가 트리에 들어가고 disabled 된다', async () => {
    const r = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const leaf = await credLeaf(BigInt(cred.C));
    assert.ok(r.body.inserted.map((h) => BigInt(h)).includes(leaf), '발급했던 credential 의 리프가 있어야 한다');
    assert.equal(r.body.pending, r.body.inserted.length);
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

  await t('publish: 체인의 epoch 가 앞서 있어도 CIA 가 따라잡는다 (크래시 복구)', async () => {
    // 새 credential 을 하나 발급해서 폐기한다 (계정은 앞의 'set_disabled false' 케이스에서 재활성화됨)
    const { body: issueBody } = await issueRequest(user);
    const issued = await cia.post('/cia/issue', issueBody);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const leaf = (await credLeaf(BigInt(issued.body.C))).toString();
    const rv = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential', leaf });
    assert.equal(rv.status, 200, JSON.stringify(rv.body));

    // CIA 가 아직 게시하기 전에, 체인에 직접 다음 epoch 를 게시한다 — tx 는 성공했는데
    // CIA 가 persist() 전에 죽어버린 크래시 시나리오를 흉내낸다.
    const before = await cia.get('/cia/state');
    const current = before.body.epoch;
    const log = new ethers.Contract(cia.logAddress, logAbi(), provider);
    assert.equal(await log.epoch(), BigInt(current), '아직은 로컬·온체인 epoch 가 같아야 한다');
    const root = ethers.zeroPadValue(ethers.toBeHex(BigInt(before.body.root)), 32);
    const directEpoch = current + 1;
    const sig = await signRootPublication(cia.ciaEthWallet, { root, epoch: directEpoch, leaves: [] });
    const tx = await log.connect(cia.ciaEthWallet).publishRoot(root, directEpoch, [], sig);
    await tx.wait();
    assert.equal(await log.epoch(), BigInt(directEpoch));

    // CIA 가 로컬 epoch(current) 만 보고 게시하면 온체인과 같은 epoch 를 또 보내 영원히 막힌다.
    // 수정 후에는 온체인 epoch 를 따라잡아 current+2 로 게시돼야 한다.
    const r = await cia.adminPost('/cia/publish');
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.published, true);
    assert.equal(r.body.epoch, current + 2);
    assert.equal(await log.epoch(), BigInt(current + 2));
  });

  await t('admin 엔드포인트는 시크릿 없이 401', async () => {
    assert.equal((await cia.post('/cia/revoke', { uid: '12345', scope: 'account' })).status, 401);
  });
} finally {
  await cia.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
