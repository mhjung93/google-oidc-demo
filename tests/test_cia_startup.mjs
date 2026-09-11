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
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider, logAbi, signRootPublication, rootToBytes32 } from './helpers/mode3_chain.mjs';
import { randomScalar } from '../lib/mode3_credential.js';
import { credLeaf, createRevocationTree } from '../lib/mode3_revocation.js';
import { registrationCommit, proveIssuance, serializeProof, pointToStrings } from '../lib/mode3_issuance.js';
import { syncRevocationTree } from '../lib/mode3_wallet.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const provider = getProvider();
const eddsa = await buildEddsa();
const poseidon = await buildPoseidon();
const F = poseidon.F;
const uid = 12345n, arid = 22222222222222222222n;
const pk_i = BigInt(ethers.Wallet.createRandom().address);
const keep = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-cia-startup-'));   // 첫 인스턴스의 상태·키 파일 사본
const keptState = path.join(keep, 'cia_state.json');
const keptKeys = path.join(keep, 'cia_keys.json');

/** 등록 → 발급 한 번. 폐기 리프(10진)를 돌려준다. */
async function registerAndIssueLeaf(cia, user) {
  if (!user.sk_u) {
    const r = await cia.post('/cia/register', { uid: uid.toString(), pwd: 'password123', cm_u: pointToStrings(user.cm_u) });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    user.sk_u = Buffer.from(r.body.sk_u, 'hex');
  }
  const blind = randomScalar();
  const { C_pt, proof } = await proveIssuance({ uid, arid, s_u: user.s_u, blind, pk_i, r_u: user.r_u });
  const m = F.e(F.toObject(poseidon([C_pt.x, C_pt.y])));
  const s = eddsa.signPoseidon(user.sk_u, m);
  const sig_u = { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() };
  const r = await cia.post('/cia/issue', { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return (await credLeaf(BigInt(r.body.C))).toString();
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
  const L1 = await registerAndIssueLeaf(first, user);
  const L2 = await registerAndIssueLeaf(first, user);
  const L3 = await registerAndIssueLeaf(first, user);

  // 상황 만들기: L1 은 정상 게시(epoch 1). L2, L3 는 pending. 그 다음 "L2 만 실은 epoch 2 게시 tx 는
  // 성공했는데 CIA 가 persist() 전에 죽었다" 를 흉내낸다 — 체인에 직접 게시하고 상태 파일은 그대로 둔다.
  assert.equal((await first.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential', leaf: L1 })).status, 200);
  assert.equal((await first.adminPost('/cia/publish')).body.epoch, 1);
  assert.equal((await first.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential', leaf: L2 })).status, 200);
  assert.equal((await first.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential', leaf: L3 })).status, 200);
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
} finally {
  if (first) await first.stop();
  fs.rmSync(keep, { recursive: true, force: true });
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
