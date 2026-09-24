// CIA 기동 시 로컬 폐기 트리와 온체인 root 대조 — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_startup.mjs
//
// 배경: /cia/publish 가 tx 를 보낸 뒤 persist() 전에 죽으면 상태 파일이 체인보다 뒤처진다(크래시 복구).
// 반대로 로그를 재배포했거나 옛 백업을 복원하면 상태 파일이 체인보다 앞선다. 둘 다 그대로
// 두면 다음 publish 가 서명하는 root 와 지갑이 이벤트로 재구성한 root 가 어긋나 전원이
// fail-closed 된다. 기동 시 "revoked 의 접두사 중 온체인 root 와 같은 것" 을 찾아, 있으면
// 그 뒤만 pending 으로 남기고 없으면 기동을 거부한다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider, logAbi, signRootPublication, rootToBytes32 } from './helpers/mode3_chain.mjs';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { randomScalar, sessionCommit, compressPoint } from '../lib/mode3_credential.js';
import { createRevocationTree } from '../lib/mode3_revocation.js';
import { registrationCommit, proveUserCred, serializeUserCredProof, userCredRequestMessage, issueRequestMessageV4, pointToStrings } from '../lib/mode3_issuance.js';
import { syncRevocationTree } from '../lib/mode3_wallet.js';
import { createShare } from '../lib/mode3_trace.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const provider = getProvider();
const eddsa = await buildEddsa();
const F = (await buildPoseidon()).F;
const uid = 12345n, arid = 22222222222222222222n;
const pk_i = BigInt(ethers.Wallet.createRandom().address);
const signMsg = (prvHex, m) => { const sg = eddsa.signPoseidon(Buffer.from(prvHex, 'hex'), F.e(m)); return { R8x: F.toObject(sg.R8[0]).toString(), R8y: F.toObject(sg.R8[1]).toString(), S: sg.S.toString() }; };
const keep = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-cia-startup-'));   // 첫 인스턴스의 상태·키 파일 사본
const keptState = path.join(keep, 'cia_state.json');
const keptKeys = path.join(keep, 'cia_keys.json');

/**
 * 등록 → 사용자 자격증명(/cia/user_cred, 매번 새 blind_u 라 새 Cf_u) → 세션 발급 V5 한 번. 폐기 리프(10진)를 돌려준다.
 * 새 사용자 자격증명은 앞의 활성 자격증명을 물리므로(리프 → pending) 호출자는 그 pending 을 감안해야 한다.
 */
async function registerAndIssueLeaf(cia, user) {
  if (!user.sk_u) {
    const r = await cia.post('/cia/register', { uid: uid.toString(), pwd: 'password123', cm_u: pointToStrings(user.cm_u) });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    user.sk_u = r.body.sk_u;
  }
  // uid 12345 는 cia.js DEMO_ACCOUNTS.testuser 이고 AA 가 attrs 를 보증한다(2026-09-22 §3.4) — 여기서 임의값을 쓰면 π_u 가 400.
  const { C_u_pt, proof } = await proveUserCred({ uid, s_u: user.s_u, blind_u: randomScalar(), r_u: user.r_u, attrs: [1990n, 410n, 2n, 0n] });
  const uc = await cia.post('/cia/user_cred', { uid: uid.toString(), C_u_pt: pointToStrings(C_u_pt), proof: serializeUserCredProof(proof), sig_u: signMsg(user.sk_u, await userCredRequestMessage(C_u_pt)) });
  assert.equal(uc.status, 201, JSON.stringify(uc.body));
  const Cf_u = BigInt(uc.body.Cf_u);
  const { Cx, Cy } = await sessionCommit({ arid, pk_i, blind_s: randomScalar() });
  const C_s_pt = { x: Cx, y: Cy };
  const max_height = BigInt(await getProvider().getBlockNumber()) + 300n;
  const sig_u = signMsg(user.sk_u, await issueRequestMessageV4(Cf_u, C_s_pt, 31337n, 0n, max_height));
  const r = await cia.post('/cia/issue', { uid: uid.toString(), Cf_u: Cf_u.toString(), C_s_pt: pointToStrings(C_s_pt), sig_u, chainid: '31337', allowAgent: '0', max_height: max_height.toString() });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.Cf_s, (await compressPoint(C_s_pt)).toString());
  return uc.body.leaf;
}

/** 기동이 거부돼야 한다. 거부되지 않고 떠 버리면 잔존 프로세스를 남기지 않도록 멈춘 뒤 실패시킨다. */
async function expectStartupRefused(opts) {
  let cia;
  try { cia = await startIsolatedCia(opts); }
  catch (e) { assert.match(e.message, /root 불일치/); return; }
  await cia.stop();
  assert.fail('기동이 거부돼야 하는데 떠 버렸다');
}

let first = await startIsolatedCia();
const firstLog = first.logAddress;
const firstEthPrv = first.ciaEthWallet.privateKey;
const b32 = (leaf) => rootToBytes32(BigInt(leaf));

try {
  const s_u = randomScalar(), r_u = randomScalar();
  const user = { s_u, r_u, cm_u: await registrationCommit(s_u, r_u), sk_u: null };
  // 상황 만들기: L1 은 정상 게시(epoch 1). L2, L3 는 pending. 그 다음 "L2 만 실은 epoch 2 게시 tx 는
  // 성공했는데 CIA 가 persist() 전에 죽었다" 를 흉내낸다 — 체인에 직접 게시하고 상태 파일은 그대로 둔다.
  // V5 에서 리프는 사용자 자격증명(Cf_u)에서 나온다: 폐기(scope=credential)는 활성 자격증명을 물리고, 새 자격증명 발급은
  // 앞의 활성 자격증명을 물린다 — 둘 다 리프를 pending 에 넣는다. 그 순서를 써서 L1 → 게시, L2·L3 → pending 을 만든다.
  const L1 = await registerAndIssueLeaf(first, user);
  const rv1 = await first.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential' });
  assert.equal(rv1.status, 200, JSON.stringify(rv1.body)); assert.deepEqual(rv1.body.inserted, [L1]);
  assert.equal((await first.adminPost('/cia/publish')).body.epoch, 1);
  const L2 = await registerAndIssueLeaf(first, user);   // 활성 자격증명 L2 (L1 은 이미 revoked)
  const L3 = await registerAndIssueLeaf(first, user);   // L2 를 물린다 → pending [L2]
  const rv3 = await first.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential' });
  assert.equal(rv3.status, 200, JSON.stringify(rv3.body)); assert.deepEqual(rv3.body.inserted, [L3]);
  assert.equal((await first.get('/cia/state')).body.pendingCount, 2);

  const tree12 = await createRevocationTree();
  await tree12.insert(BigInt(L1)); await tree12.insert(BigInt(L2));
  const root12 = rootToBytes32(tree12.getRoot());
  const log = new ethers.Contract(firstLog, logAbi(), first.ciaEthWallet);
  const sig = await signRootPublication(first.ciaEthWallet, { logAddress: firstLog, root: root12, epoch: 2, leaves: [b32(L2)] });
  await (await log.publishRoot(root12, 2, [b32(L2)], sig)).wait();
  assert.equal(await log.epoch(), 2n);

  fs.copyFileSync(path.join(first.dir, 'cia_state.json'), keptState);
  fs.copyFileSync(path.join(first.dir, 'cia_keys.json'), keptKeys);
  await first.stop();
  first = null;

  await t('크래시 복구: 이미 게시된 pending 접두사(L2)는 걷어내고 나머지(L3)만 pending 으로 남긴다', async () => {
    const cia = await startIsolatedCia({ env: { CIA_STATE_FILE: keptState, CIA_KEYS_FILE: keptKeys, CIA_LOG_ADDRESS: firstLog, CIA_ETH_PRIVATE_KEY: firstEthPrv } });
    try {
      const st = (await cia.get('/cia/state')).body;
      assert.equal(st.epoch, 2, '온체인 epoch 를 따라잡아야 한다');
      assert.equal(st.leafCount, 3, 'revoked 는 그대로');
      assert.equal(st.pendingCount, 1, 'L2 는 이미 체인에 있으므로 L3 만 남아야 한다');
      const pub = await cia.adminPost('/cia/publish');
      assert.equal(pub.body.published, true, JSON.stringify(pub.body));
      assert.equal(pub.body.epoch, 3);
      assert.equal(pub.body.leaves.length, 1, 'L3 만 실려야 한다');
      assert.equal(BigInt(pub.body.leaves[0]), BigInt(L3));
      // 지갑이 이벤트만으로 재구성한 root 가 CIA 의 root 와 같아야 한다 (L2 가 두 번 나가지 않았다)
      const synced = await syncRevocationTree(provider, firstLog);
      assert.equal(synced.root.toString(), pub.body.root);
    } finally { await cia.stop(); }
  });

  await t('불일치 거부: 상태 파일의 리프가 로그에 없으면(로그 재배포) 기동하지 않는다', async () => {
    // 기본 하네스는 빈 로그를 새로 배포한다 — 상태 파일은 리프 3개가 전부 게시됐다고 믿고 있다.
    await expectStartupRefused({ env: { CIA_STATE_FILE: keptState, CIA_KEYS_FILE: keptKeys } });
  });

  await t('불일치 거부: 빈 상태 파일로 리프가 있는 로그를 가리켜도 기동하지 않는다 (상태 파일 유실)', async () => {
    await expectStartupRefused({ env: { CIA_LOG_ADDRESS: firstLog, CIA_ETH_PRIVATE_KEY: firstEthPrv } });
  });

  await t('v3 상태 파일은 v8 으로 마이그레이션된다 — used_rs 버림, rps 는 approved·조각 없음, openings 빈 배열', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-v3-'));
    const stateFile = path.join(dir, 'cia_state.json');
    fs.writeFileSync(stateFile, JSON.stringify({ version: 3, accounts: {}, issued: {}, used_rs: { '12345': ['1', '2'] }, rps: { '777': { name: 'old', origin: 'http://127.0.0.1:3100', at: '2026-09-15T00:00:00.000Z' } }, revoked: [], pending: [], epoch: 0 }), { mode: 0o600 });
    const cia = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile } });
    try {
      const saved = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      assert.equal(saved.version, 8); assert.equal(saved.used_rs, undefined); assert.equal(saved.issued, undefined); assert.deepEqual(saved.openings, []);
      const e = (await cia.adminGet('/cia/rps')).body.rps.find((x) => x.arid === '777');
      assert.equal(e.status, 'approved'); assert.equal(e.pk_trace, null); assert.equal(e.pk_service, null);
      // 옛 등록이 키를 내며 재등록하면 무허가 바인딩을 막기 위해 pending 으로 돌아간다 — 운영자 승인이 다시 필요하다(§3)
      const w = ethers.Wallet.createRandom(); const share = await createShare();
      const body = { name: 'old', origin: 'http://127.0.0.1:3100', pk_service: w.address, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() } };
      const r = await cia.post('/cia/register_rp', body);
      assert.equal(r.status, 202, JSON.stringify(r.body)); assert.equal(r.body.arid, '777'); assert.equal(r.body.status, 'pending');
      assert.equal((await cia.adminPost('/cia/rps/777/approve')).status, 200);
      const ok = await cia.post('/cia/register_rp', body);
      assert.equal(ok.status, 200, JSON.stringify(ok.body)); assert.equal(ok.body.arid, '777'); assert.ok(ok.body.pk_trace?.x);
    } finally { await cia.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await t('v4 상태 파일은 v8 로 이행된다 — 발급 기록은 버리고 계정에 creds:[]·attrs(uid 12345 는 DEMO_ACCOUNTS 값), 서비스·폐기·epoch 는 유지', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-v4-'));
    const stateFile = path.join(dir, 'cia_state.json');
    fs.writeFileSync(stateFile, JSON.stringify({ version: 4, accounts: { '12345': { pk_u: { x: '1', y: '2' }, cm_u: { x: '3', y: '4' }, disabled: false } }, issued: { '12345': [{ leaf: '9', C: '8', exptime: '1789000000' }] }, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 }), { mode: 0o600 });
    const cia = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile } });
    try {
      const saved = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      assert.equal(saved.version, 8); assert.equal(saved.issued, undefined); assert.deepEqual(saved.accounts['12345'].creds, []);
      assert.deepEqual(saved.accounts['12345'].attrs, ['1990', '410', '2', '0'], 'uid 12345 는 cia.js DEMO_ACCOUNTS.testuser 라 demoAttrs 콜백이 채운다');
      assert.match(cia.log(), /v4→v5/); assert.match(cia.log(), /v5→v6/); assert.match(cia.log(), /v6→v7/);
    } finally { await cia.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
  });

  // 최종 리뷰 Important(2026-09-22, Ruling 8): v6→v7 이행이 pending 리프를 남기면(보증되지 않은 활성 C_u 물림) CIA 기동이
  // 게시를 한 번 자동으로 시도한다 — 안 그러면 다음 하트비트까지 옛 C_u 로도 π 가 여전히 만들어져 세션 발급이 통과한다.
  await t('v6→v7 이행이 pending 리프를 남기면 CIA 기동이 자동으로 게시한다', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-v6-autopublish-'));
    const stateFile = path.join(dir, 'cia_state.json');
    // uid 99999 는 DEMO_ACCOUNTS 에 없다 — demoAttrs 콜백이 null 을 돌려줘 attrs 는 0 네 개가 된다(이행 로직 확인에는 무관).
    fs.writeFileSync(stateFile, JSON.stringify({
      version: 6,
      accounts: { '99999': { cm_u: { x: '1', y: '2' }, disabled: false, creds: [{ Cf_u: '111', C_u_pt: { x: '3', y: '4' }, leaf: '555666777888', issuedAt: '2026-01-01T00:00:00.000Z', revoked: false }] } },
      rps: {}, openings: [], revoked: [], pending: [], epoch: 0,
    }), { mode: 0o600 });
    const cia = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile } });
    try {
      assert.match(cia.log(), /v6→v7/);
      assert.match(cia.log(), /이행 뒤 자동 게시/, '기동이 v7 이행 리프를 자동 게시했어야 한다');
      const st = (await cia.get('/cia/state')).body;
      assert.equal(st.epoch, 1, '자동 게시가 epoch 를 올렸어야 한다');
      assert.equal(st.leafCount, 1);
      assert.equal(st.pendingCount, 0, '자동 게시가 pending 을 비웠어야 한다');
      const saved = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      assert.equal(saved.epoch, 1); assert.deepEqual(saved.pending, []);
    } finally { await cia.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await t('자동 게시가 체인 RPC 를 못 읽으면 경고만 남기고 기동은 계속한다(수동 /cia/publish 안내)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-v6-autopublish-norpc-'));
    const stateFile = path.join(dir, 'cia_state.json');
    fs.writeFileSync(stateFile, JSON.stringify({
      version: 6,
      accounts: { '99999': { cm_u: { x: '1', y: '2' }, disabled: false, creds: [{ Cf_u: '111', C_u_pt: { x: '3', y: '4' }, leaf: '999888777666', issuedAt: '2026-01-01T00:00:00.000Z', revoked: false }] } },
      rps: {}, openings: [], revoked: [], pending: [], epoch: 0,
    }), { mode: 0o600 });
    // CIA 앱 자체는 뜨지만(readiness 는 체인을 안 본다), CIA_RPC_URL 을 응답 없는 주소로 돌려 게시 시도가 실패하게 한다.
    const cia = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile, CIA_RPC_URL: 'http://127.0.0.1:1' } });
    try {
      assert.match(cia.log(), /v6→v7/);
      assert.match(cia.log(), /이행 뒤 자동 게시 실패/);
      assert.match(cia.log(), /\/cia\/publish/, '수동으로 /cia/publish 를 호출하라는 안내가 있어야 한다');
      const st = (await cia.get('/cia/state')).body;
      assert.equal(st.pendingCount, 1, '게시가 실패했으므로 pending 은 그대로 남아 있어야 한다');
    } finally { await cia.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
  });
} finally {
  if (first) await first.stop();
  fs.rmSync(keep, { recursive: true, force: true });
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
