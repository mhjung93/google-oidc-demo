// 지갑 라이브러리 — 트리 동기화·증명 생성·캐시. :8545 + build/mode3 zkey 필요. (chain 그룹)
//   node tests/test_mode3_wallet.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { getProvider, fundAddress, deployRevocationLog, signRootPublication, rootToBytes32 } from './helpers/mode3_chain.mjs';
import { createRevocationTree, credLeaf } from '../lib/mode3_revocation.js';
import { credMessage, compressPoint, randomScalar } from '../lib/mode3_credential.js';
import {
  createRegistration, createSessionKey, buildIssueRequest, syncRevocationTree,
  buildCredentialProof, ProofCache, signChallenge, signSessionRequest, ZKEY_PATH, VKEY_PATH, chooseMaxHeight,
} from '../lib/mode3_wallet.js';
import { verifySessionRequest } from '../lib/mode3_rp.js';
import { pointFromStrings } from '../lib/mode3_issuance.js';
import { createShare, combinePublicKey, partialDecrypt, combineDecrypt, tagPlaintext } from '../lib/mode3_trace.js';

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

// 서버 없이 CIA 역할을 로컬에서 흉내낸다 (서명만). max_height 는 지갑(요청)이 정한 값을 그대로 서명한다(2026-09-18 §3.2 갱신).
const mh = async (ttl = 300n) => chooseMaxHeight(BigInt(await provider.getBlockNumber()), { ttlBlocks: ttl });
async function localIssue(C_pt, chainid, { max_height, allowAgent = 0n } = {}) {
  const C = await compressPoint(C_pt);
  if (max_height === undefined) max_height = await mh();
  const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessage(C, max_height, chainid, allowAgent)));
  return { C: C.toString(), max_height: max_height.toString(), chainid: chainid.toString(), allowAgent: allowAgent.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
async function publish(leavesBig) {
  const tree = await createRevocationTree();
  const ev = await log.queryFilter(log.filters.Revoked());
  for (const e of ev) for (const l of e.args.leaves) await tree.insert(BigInt(l));
  for (const l of leavesBig) await tree.insert(l);
  const root = rootToBytes32(tree.getRoot());
  const epoch = (await log.epoch()) + 1n;
  const leaves = leavesBig.map(rootToBytes32);
  const sig = await signRootPublication(ciaEth, { logAddress, root, epoch, leaves });
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

const svcShare = await createShare(), aaShare = await createShare();
const pk_trace = await combinePublicKey(svcShare.X, aaShare.X);

let reg, session, req, cred, tree0;
await t('발급 요청 → 로컬 CIA 서명 → 증명 생성 → vkey 로 검증된다', async () => {
  reg = await createRegistration();
  session = createSessionKey();
  const sk_u = Buffer.alloc(32, 3).toString('hex');
  req = await buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n, attrs: [19n, 410n, 0n, 0n], max_height: await mh() });
  cred = await localIssue(pointFromStrings(req.body.C_pt), 31337n, { max_height: BigInt(req.body.max_height) });
  ({ tree: tree0 } = await syncRevocationTree(provider, logAddress));
  const { proof, publicSignals, revRoot, tag } = await buildCredentialProof({
    uid, arid, s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, attrs: [19n, 410n, 0n, 0n], credential: cred, pk_CIA, pk_trace, tree: tree0,
  });
  assert.equal(revRoot, tree0.getRoot());
  assert.equal(publicSignals.length, 14);
  assert.equal(BigInt(publicSignals[2]), session.pk_i);
  assert.equal(BigInt(publicSignals[3]), BigInt(cred.max_height));
  assert.equal(BigInt(publicSignals[4]), 31337n);
  assert.equal(BigInt(publicSignals[5]), 0n, 'allowAgent');
  assert.equal(BigInt(publicSignals[6]), tree0.getRoot());
  assert.equal(BigInt(publicSignals[9]), pk_trace.x); assert.equal(BigInt(publicSignals[10]), pk_trace.y);
  assert.equal(BigInt(publicSignals[11]), tag.c1.x); assert.equal(BigInt(publicSignals[13]), tag.c2);
  assert.equal(tag.h, await tagPlaintext(uid, arid), '태그 평문은 Poseidon(uid, arid)');
  // 태그는 두 조각으로 이 성명의 평문 h = Poseidon(uid, arid) 로 열린다 (검증 가능 암호화)
  assert.equal(await combineDecrypt(tag.c2, await partialDecrypt(svcShare.x, tag.c1), await partialDecrypt(aaShare.x, tag.c1)), await tagPlaintext(uid, arid));
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
    () => buildCredentialProof({ uid, arid, s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, attrs: [19n, 410n, 0n, 0n], credential: cred, pk_CIA, pk_trace, tree }),
    /is a member/,
  );
});

await t('buildCredentialProof 는 pk_trace 없이는 throw — 태그 없는 성명은 이제 없다', async () => {
  await assert.rejects(
    () => buildCredentialProof({ uid, arid, s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, attrs: [19n, 410n, 0n, 0n], credential: cred, pk_CIA, tree: tree0 }),
    /pk_trace/,
  );
});

await t('buildIssueRequest 는 allowAgent 를 싣고(기본 0) r_s 는 더 이상 받지 않는다', async () => {
  const session = createSessionKey();
  const sk_u = Buffer.alloc(32, 3).toString('hex');
  const h = await mh();
  const a = await buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n, max_height: h });
  assert.equal(a.body.allowAgent, '0');
  assert.equal(a.body.r_s, undefined);
  assert.equal(a.body.max_height, h.toString(), '지갑이 정한 max_height 를 그대로 싣는다');
  const b = await buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n, allowAgent: 1n, max_height: h });
  assert.equal(b.body.allowAgent, '1');
  await assert.rejects(() => buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n, allowAgent: 2n, max_height: h }), /allowAgent/);
  await assert.rejects(() => buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n }), /max_height/);
  // 그리드: 같은 창의 head 는 같은 값, 항상 head + ttl 이상, 그리드 배수
  assert.equal(chooseMaxHeight(1234n), 1600n); assert.equal(chooseMaxHeight(1299n), 1600n); assert.equal(chooseMaxHeight(1300n), 1600n); assert.equal(chooseMaxHeight(1301n), 1700n);
  assert.equal(chooseMaxHeight(10n, { ttlBlocks: 5n, grid: 1n }), 15n);
});

await t('signSessionRequest 는 (r_s, body) 를 세션키로 서명하고 verifySessionRequest 가 복원한다', async () => {
  const r_s = randomScalar();
  const sig = await signSessionRequest(session.wallet, r_s, 'hello');
  assert.equal(verifySessionRequest({ pk_i: session.pk_i, r_s, body: 'hello', sig }), true);
  assert.equal(verifySessionRequest({ pk_i: session.pk_i, r_s, body: 'hellp', sig }), false);
  assert.equal(verifySessionRequest({ pk_i: session.pk_i, r_s: r_s + 1n, body: 'hello', sig }), false);
});

await t('챌린지 서명은 세션키 주소로 복원된다', async () => {
  const sig = await signChallenge(session.wallet, 'challenge-123');
  assert.equal(BigInt(ethers.verifyMessage('challenge-123', sig)), session.pk_i);
});

provider.destroy();
process.exit(failed === 0 ? 0 : 1);
