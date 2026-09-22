// 지갑 라이브러리 — 트리 동기화·증명 생성·캐시. :8545 + build/mode3 zkey 필요. (chain 그룹)
//   node tests/test_mode3_wallet.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { getProvider, fundAddress, deployRevocationLog, signRootPublication, rootToBytes32 } from './helpers/mode3_chain.mjs';
import { createRevocationTree, userLeaf } from '../lib/mode3_revocation.js';
import { credMessageV5, compressPoint, randomScalar } from '../lib/mode3_credential.js';
import {
  createRegistration, createSessionKey, buildUserCredRequest, buildIssueRequest, syncRevocationTree,
  buildCredentialProof, ProofCache, signChallenge, signSessionRequest, ZKEY_PATH, VKEY_PATH, chooseMaxHeight,
  normalizeDisclosure, signAttrsRequest,
} from '../lib/mode3_wallet.js';
import { attrsRequestMessage } from '../lib/mode3_issuance.js';
import { verifySessionRequest } from '../lib/mode3_rp.js';
import { verifyUserCred, parseUserCredProof } from '../lib/mode3_issuance.js';
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

// 서버 없이 CIA 역할을 로컬에서 흉내낸다 (서명만). V5: Sign(D_V5, Cf_u, Cf_s, max_height, chainid, allowAgent). max_height 는 요청 값 그대로.
const mh = async (ttl = 300n) => chooseMaxHeight(BigInt(await provider.getBlockNumber()), { ttlBlocks: ttl });
async function localIssue(Cf_u, C_s_pt, chainid, { max_height, allowAgent = 0n } = {}) {
  const Cf_s = await compressPoint(C_s_pt);
  if (max_height === undefined) max_height = await mh();
  const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessageV5(Cf_u, Cf_s, max_height, chainid, allowAgent)));
  return { Cf_u: Cf_u.toString(), Cf_s: Cf_s.toString(), max_height: max_height.toString(), chainid: chainid.toString(), allowAgent: allowAgent.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
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

let reg, session, uc, req, cred, tree0;
await t('사용자 자격증명 요청(π_u) → 세션 발급 요청 → 로컬 CIA 서명 → 증명 생성 → vkey 로 검증된다', async () => {
  reg = await createRegistration();
  session = createSessionKey();
  const sk_u = Buffer.alloc(32, 3).toString('hex');
  uc = await buildUserCredRequest({ uid, s_u: reg.s_u, r_u: reg.r_u, sk_u, attrs: [19n, 410n, 0n, 0n] });
  assert.equal(await verifyUserCred({ uid, attrs: [19n, 410n, 0n, 0n], C_u_pt: uc.C_u_pt, cm_u: reg.cm_u, proof: parseUserCredProof(uc.body.proof) }), true, 'CIA 가 하는 검증');
  assert.equal(uc.body.uid, uid.toString());
  assert.equal(uc.body.C_u_pt.x, uc.C_u_pt.x.toString());
  assert.equal(uc.Cf_u, await compressPoint(uc.C_u_pt));
  assert.equal(uc.leaf, await userLeaf(uc.Cf_u), '지갑이 보관하는 리프 = userLeaf(Cf_u)');
  assert.ok(uc.body.sig_u?.S, '요청 서명');
  req = await buildIssueRequest({ uid, Cf_u: uc.Cf_u, arid, sk_u, session, chainid: 31337n, max_height: await mh() });
  cred = await localIssue(uc.Cf_u, req.C_s_pt, 31337n, { max_height: BigInt(req.body.max_height) });
  assert.equal(cred.Cf_s, req.Cf_s.toString(), 'CIA 가 압축한 Cf_s 와 지갑의 Cf_s 가 같다');
  ({ tree: tree0 } = await syncRevocationTree(provider, logAddress));
  const { proof, publicSignals, revRoot, tag } = await buildCredentialProof({
    uid, arid, s_u: reg.s_u, blind_u: uc.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs: [19n, 410n, 0n, 0n],
    credential: cred, pk_CIA, pk_trace, tree: tree0,
  });
  assert.equal(revRoot, tree0.getRoot());
  assert.equal(publicSignals.length, 23, 'V6: 기존 14 + 선택 공개 disc_mask·disc_lo[4]·disc_hi[4] 9개(2026-09-22)');
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

await t('내 사용자 자격증명 리프(userLeaf(Cf_u))가 폐기되면 동기화된 트리로는 witness 를 만들 수 없다', async () => {
  await publish([await userLeaf(BigInt(cred.Cf_u))]);
  const { tree } = await syncRevocationTree(provider, logAddress);
  await assert.rejects(
    () => buildCredentialProof({ uid, arid, s_u: reg.s_u, blind_u: uc.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs: [19n, 410n, 0n, 0n], credential: cred, pk_CIA, pk_trace, tree }),
    /is a member/,
  );
});

await t('buildCredentialProof 는 pk_trace 없이는 throw — 태그 없는 성명은 이제 없다', async () => {
  await assert.rejects(
    () => buildCredentialProof({ uid, arid, s_u: reg.s_u, blind_u: uc.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs: [19n, 410n, 0n, 0n], credential: cred, pk_CIA, tree: tree0 }),
    /pk_trace/,
  );
});

await t('buildIssueRequest 는 allowAgent 를 싣고(기본 0) ZKP·C_pt 없이 Cf_u·C_s_pt 를 싣는다', async () => {
  const session = createSessionKey();
  const sk_u = Buffer.alloc(32, 3).toString('hex');
  const h = await mh();
  const a = await buildIssueRequest({ uid, Cf_u: uc.Cf_u, arid, sk_u, session, chainid: 31337n, max_height: h });
  assert.equal(a.body.allowAgent, '0');
  assert.equal(a.body.r_s, undefined);
  assert.equal(a.body.proof, undefined, 'V5 세션 요청에는 ZKP 가 없다');
  assert.equal(a.body.C_pt, undefined);
  assert.equal(a.body.Cf_u, uc.Cf_u.toString());
  assert.equal(a.body.chainid, '31337');
  assert.deepEqual(Object.keys(a.body).sort(), ['C_s_pt', 'Cf_u', 'allowAgent', 'chainid', 'max_height', 'sig_u', 'uid']);
  assert.equal(a.body.C_s_pt.x, a.C_s_pt.x.toString());
  assert.equal(a.Cf_s, await compressPoint(a.C_s_pt));
  assert.equal(typeof a.secrets.blind_s, 'bigint');
  assert.equal(a.body.max_height, h.toString(), '지갑이 정한 max_height 를 그대로 싣는다');
  const b = await buildIssueRequest({ uid, Cf_u: uc.Cf_u, arid, sk_u, session, chainid: 31337n, allowAgent: 1n, max_height: h });
  assert.equal(b.body.allowAgent, '1');
  await assert.rejects(() => buildIssueRequest({ uid, Cf_u: uc.Cf_u, arid, sk_u, session, chainid: 31337n, allowAgent: 2n, max_height: h }), /allowAgent/);
  await assert.rejects(() => buildIssueRequest({ uid, Cf_u: uc.Cf_u, arid, sk_u, session, chainid: 31337n }), /max_height/);
  await assert.rejects(() => buildIssueRequest({ uid, arid, sk_u, session, chainid: 31337n, max_height: h }), /Cf_u/);
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

await t('normalizeDisclosure: null 넷 → mask 0; 구간·등식; 불만족은 disclosure_unsatisfiable; 64비트 밖·lo > hi 는 bad_disclosure', async () => {
  const attrs = [1990n, 410n, 2n, 0n];
  assert.deepEqual(normalizeDisclosure([null, null, null, null], attrs), { mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n] });
  assert.deepEqual(normalizeDisclosure(undefined, attrs).mask, 0n);
  assert.deepEqual(normalizeDisclosure([{ lo: '0', hi: '2007' }, { lo: '410', hi: '410' }, null, null], attrs), { mask: 3n, lo: [0n, 410n, 0n, 0n], hi: [2007n, 410n, 0n, 0n] });
  assert.throws(() => normalizeDisclosure([{ lo: '0', hi: '1980' }, null, null, null], attrs), (e) => e.reason === 'disclosure_unsatisfiable');
  assert.throws(() => normalizeDisclosure([{ lo: '5', hi: '4' }, null, null, null], attrs), (e) => e.reason === 'bad_disclosure');
  assert.throws(() => normalizeDisclosure([null, null, null, { lo: '0', hi: (1n << 64n).toString() }], attrs), (e) => e.reason === 'bad_disclosure');
  assert.throws(() => normalizeDisclosure([null, null, null, null, null], attrs), (e) => e.reason === 'bad_disclosure');
});
await t('signAttrsRequest 는 attrsRequestMessage 위 EdDSA 서명이다', async () => {
  const eddsa = await buildEddsa(); const F = eddsa.F;
  const prv = Buffer.from('11'.repeat(32), 'hex'); const pub = eddsa.prv2pub(prv);
  const sig = await signAttrsRequest(prv.toString('hex'), 12345n, 7n);
  assert.equal(eddsa.verifyPoseidon(F.e(await attrsRequestMessage(12345n, 7n)), { R8: [F.e(BigInt(sig.R8x)), F.e(BigInt(sig.R8y))], S: BigInt(sig.S) }, pub), true);
});
await t('ProofCache 는 공개 키가 다르면 다른 항목이다', () => {
  const c = new ProofCache();
  c.set('r', 's', 'A'); c.set('r', 's', 'B', '3:0,410,0,0:2007,410,0,0');
  assert.equal(c.get('r', 's'), 'A'); assert.equal(c.get('r', 's', '3:0,410,0,0:2007,410,0,0'), 'B'); assert.equal(c.get('r', 's', '1:0,0,0,0:9,0,0,0'), null);
});

// 2026-09-23 점검 M-1: 세션이 만료로 정리되면 그 세션의 π 도 같이 버린다(같은 r_s 재로그인이 옛 π 를 히트하지 않게).
await t('ProofCache.deleteSession 은 그 세션 항목만 지운다(공개 키가 달라도)', () => {
  const c = new ProofCache();
  c.set('r', 's', 'A'); c.set('r', 's', 'B', '3:0,410,0,0:2007,410,0,0'); c.set('r', 'other', 'C');
  c.deleteSession('s');
  assert.equal(c.get('r', 's'), null);
  assert.equal(c.get('r', 's', '3:0,410,0,0:2007,410,0,0'), null);
  assert.notEqual(c.get('r', 'other'), null);
});

await t('증인을 만든 뒤 트리가 바뀌어도 증명의 revRoot 는 증인 root 다 (스펙 §5)', async () => {
  // 위 121행 테스트가 cred.Cf_u 의 리프를 온체인에 폐기해 버렸다(append-only — 되돌릴 수 없다).
  // 그 cred 를 그대로 쓰면 root 고정과 무관하게 getNonMembershipWitness 가 "is a member" 로
  // 즉시 throw 하므로, 이 테스트만은 새 등록·세션·발급으로 폐기되지 않은 자격증명을 새로 만든다.
  const reg2 = await createRegistration();
  const session2 = createSessionKey();
  const sk_u2 = Buffer.alloc(32, 5).toString('hex');
  const uc2 = await buildUserCredRequest({ uid, s_u: reg2.s_u, r_u: reg2.r_u, sk_u: sk_u2, attrs: [19n, 410n, 0n, 0n] });
  const req2 = await buildIssueRequest({ uid, Cf_u: uc2.Cf_u, arid, sk_u: sk_u2, session: session2, chainid: 31337n, max_height: await mh() });
  const cred2 = await localIssue(uc2.Cf_u, req2.C_s_pt, 31337n, { max_height: BigInt(req2.body.max_height) });

  const { tree } = await syncRevocationTree(provider, logAddress);
  const rootBefore = tree.getRoot();
  const orig = tree.getNonMembershipWitness.bind(tree);
  let witnessRoot = null;
  tree.getNonMembershipWitness = async (target) => {
    const w = await orig(target);
    witnessRoot = BigInt(w.root);
    await tree.insert(999_999_999n);            // 다른 요청의 sync() 가 끼어든 상황을 흉내
    return w;
  };
  const out = await buildCredentialProof({
    uid, arid, s_u: reg2.s_u, blind_u: uc2.secrets.blind_u, blind_s: req2.secrets.blind_s, pk_i: session2.pk_i, attrs: [19n, 410n, 0n, 0n],
    credential: cred2, pk_CIA, pk_trace, tree,
  });
  assert.equal(witnessRoot, rootBefore);
  assert.equal(out.revRoot, rootBefore, '증인 root 여야 한다');
  assert.notEqual(tree.getRoot(), rootBefore, '트리는 실제로 바뀌었다');
  assert.equal(BigInt(out.publicSignals[6]), rootBefore, '공개 입력의 revRoot 자리도 증인 root 여야 한다');
});

provider.destroy();
process.exit(failed === 0 ? 0 : 1);
