// 지갑 라이브러리 — 트리 동기화·증명 생성·캐시. :8545 + build/mode3 zkey 필요. (chain 그룹)
//   node tests/test_mode3_wallet.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { getProvider, fundAddress, deployRevocationLog, signRootPublication, rootToBytes32 } from './helpers/mode3_chain.mjs';
import { createRevocationTree, credLeaf } from '../lib/mode3_revocation.js';
import { credMessage, compressPoint } from '../lib/mode3_credential.js';
import {
  createRegistration, createSessionKey, buildIssueRequest, syncRevocationTree,
  buildCredentialProof, ProofCache, signChallenge, ZKEY_PATH, VKEY_PATH,
} from '../lib/mode3_wallet.js';
import { pointFromStrings } from '../lib/mode3_issuance.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}
assert.ok(fs.existsSync(ZKEY_PATH), `zkey 가 없다: ${ZKEY_PATH} — 단계 (c) Task 6 의 bench 를 먼저 돌려야 한다`);

const provider = getProvider();
const ciaEth = ethers.Wallet.createRandom().connect(provider);
await fundAddress(ciaEth.address, '1', provider);
const { address: logAddress, contract: log } = await deployRevocationLog(ciaEth.address, provider);
const eddsa = await buildEddsa();
const poseidon = await buildPoseidon();
const F = poseidon.F;
const ciaPrv = Buffer.alloc(32, 9);
const ciaPub = eddsa.prv2pub(ciaPrv);
const pk_CIA = { x: F.toObject(ciaPub[0]), y: F.toObject(ciaPub[1]) };
const uid = 12345n, arid = 22222222222222222222n;

// 서버 없이 CIA 역할을 로컬에서 흉내낸다 (서명만)
async function localIssue(C_pt, head) {
  const C = await compressPoint(C_pt);
  const max_height = BigInt(head) + 300n;
  const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessage(C, max_height)));
  return { C: C.toString(), max_height: max_height.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
async function publish(leavesBig) {
  const tree = await createRevocationTree();
  const ev = await log.queryFilter(log.filters.Revoked());
  for (const e of ev) for (const l of e.args.leaves) await tree.insert(BigInt(l));
  for (const l of leavesBig) await tree.insert(l);
  const root = rootToBytes32(tree.getRoot());
  const epoch = (await log.epoch()) + 1n;
  const leaves = leavesBig.map(rootToBytes32);
  const sig = await signRootPublication(ciaEth, { root, epoch, leaves });
  await (await log.connect(ciaEth).publishRoot(root, epoch, leaves, sig)).wait();
}

await t('빈 로그를 동기화하면 빈 트리 root 와 같다', async () => {
  const { tree, root, epoch } = await syncRevocationTree(provider, logAddress);
  assert.equal(root, (await createRevocationTree()).getRoot());
  assert.equal(epoch, 0n);
  assert.equal(tree.size(), 1, 'anchor 만');
});

await t('게시된 리프가 동기화된 트리에 있고 root 가 컨트랙트와 같다', async () => {
  await publish([777n]);
  const { tree, root } = await syncRevocationTree(provider, logAddress);
  assert.ok(tree.has(777n));
  assert.equal(rootToBytes32(root), await log.root());
});

let reg, session, req, cred, tree0;
await t('발급 요청 → 로컬 CIA 서명 → 증명 생성 → vkey 로 검증된다', async () => {
  reg = await createRegistration();
  session = createSessionKey();
  const sk_u = Buffer.alloc(32, 3).toString('hex');
  req = await buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session });
  const head = await provider.getBlockNumber();
  cred = await localIssue(pointFromStrings(req.body.C_pt), head);
  ({ tree: tree0 } = await syncRevocationTree(provider, logAddress));
  const { proof, publicSignals, revRoot } = await buildCredentialProof({
    uid, arid, s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, credential: cred, pk_CIA, tree: tree0,
  });
  assert.equal(revRoot, tree0.getRoot());
  assert.equal(publicSignals.length, 7);
  assert.equal(BigInt(publicSignals[2]), session.pk_i);
  assert.equal(BigInt(publicSignals[4]), tree0.getRoot());
  const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
  assert.ok(await snarkjs.groth16.verify(vkey, publicSignals, proof));
});

await t('ProofCache 는 같은 root·세션이면 재사용, root 가 바뀌면 miss', async () => {
  const cache = new ProofCache();
  cache.set(tree0.getRoot(), 's1', { proof: 'p' });
  assert.deepEqual(cache.get(tree0.getRoot(), 's1'), { proof: 'p' });
  assert.equal(cache.get(tree0.getRoot() + 1n, 's1'), null);
  assert.equal(cache.get(tree0.getRoot(), 's2'), null);
});

await t('내 credential 이 폐기되면 동기화된 트리로는 witness 를 만들 수 없다', async () => {
  await publish([await credLeaf(BigInt(cred.C))]);
  const { tree } = await syncRevocationTree(provider, logAddress);
  await assert.rejects(
    () => buildCredentialProof({ uid, arid, s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, credential: cred, pk_CIA, tree }),
    /is a member/,
  );
});

await t('챌린지 서명은 세션키 주소로 복원된다', async () => {
  const sig = await signChallenge(session.wallet, 'challenge-123');
  assert.equal(BigInt(ethers.verifyMessage('challenge-123', sig)), session.pk_i);
});

provider.destroy();
process.exit(failed === 0 ? 0 : 1);
