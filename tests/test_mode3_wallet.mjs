// 지갑 라이브러리 — 트리 동기화·증명 생성·캐시. :8545 + build/mode3 zkey 필요. (chain 그룹)
//   node tests/test_mode3_wallet.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { getProvider, fundAddress, deployMode3Log, rootToBytes32, publishV2 } from './helpers/mode3_chain.mjs';
import { createRevocationTree } from '../lib/mode3_revocation.js';
import { createRegistryTree, registryLeaf } from '../lib/mode3_registry.js';
import { credMessageV5, compressPoint, randomScalar } from '../lib/mode3_credential.js';
import {
  createRegistration, createSessionKey, buildUserCredRequest, buildIssueRequest, syncRevocationTree, syncRegistryTree,
  buildCredentialProof, ProofCache, signChallenge, signSessionRequest, ZKEY_PATH, VKEY_PATH, chooseMaxHeight,
  normalizeDisclosure, signAttrsRequest, normalizeSet, hasPredicate, disclosureKey,
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
const { address: logAddress, contract: log } = await deployMode3Log(ciaEth.address, provider);
const eddsa = await buildEddsa();
const poseidon = await buildPoseidon();
const F = poseidon.F;
const ciaPrv = Buffer.alloc(32, 9);
const ciaPub = eddsa.prv2pub(ciaPrv);
const pk_CIA = { x: F.toObject(ciaPub[0]), y: F.toObject(ciaPub[1]) };
const uid = 12345n, arid = 22222222222222222222n;
const registry = await createRegistryTree();   // V9: 등록부(조건 9) — 사용자 자격증명의 활성 여부는 이제 여기서 본다
const SLOT = 0;

// 서버 없이 CIA 역할을 로컬에서 흉내낸다 (서명만). V5: Sign(D_V5, Cf_u, Cf_s, max_height, chainid, allowAgent). max_height 는 요청 값 그대로.
const mh = async (ttl = 300n) => chooseMaxHeight(BigInt(await provider.getBlockNumber()), { ttlBlocks: ttl });
async function localIssue(Cf_u, C_s_pt, chainid, { max_height, allowAgent = 0n } = {}) {
  const Cf_s = await compressPoint(C_s_pt);
  if (max_height === undefined) max_height = await mh();
  const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessageV5(Cf_u, Cf_s, max_height, chainid, allowAgent)));
  return { Cf_u: Cf_u.toString(), Cf_s: Cf_s.toString(), max_height: max_height.toString(), chainid: chainid.toString(), allowAgent: allowAgent.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
// V9: 폐기 리프를 넣고 두 root(폐기·등록부)를 같이 올린다 — Mode3Log 는 root 를 하나씩 받지 않는다.
async function publish(leavesBig) {
  const tree = await createRevocationTree();
  const ev = await log.queryFilter(log.filters.Revoked());
  for (const e of ev) for (const l of e.args.leaves) await tree.insert(BigInt(l));
  for (const l of leavesBig) await tree.insert(l);
  const epoch = (await log.epoch()) + 1n;
  await publishV2(log, ciaEth, { revRoot: tree.getRoot(), regRoot: registry.root(), epoch, revLeaves: leavesBig });
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
  assert.equal(rootToBytes32(root), await log.revRoot());
});

const svcShare = await createShare(), aaShare = await createShare();
const pk_trace = await combinePublicKey(svcShare.X, aaShare.X);

let reg, session, uc, req, cred, tree0;
/**
 * 등록 → 사용자 자격증명(C_u) → 슬롯 게시(등록부) → 세션 발급 → 로컬 CIA 서명 → buildCredentialProof 까지의
 * 픽스처 준비를 묶는다. disclosure 를 그대로 buildCredentialProof 에 넘긴다(null 이면 선택 공개 없음).
 * reg·session·uc·req·cred·tree0 는 이 파일의 이후 테스트가 그대로 참조하는 전역이라 여기서도 채운다.
 * V9 조건 9: 첫 로그인(증명) 전에 내 슬롯(SLOT=0)을 내 자격증명 리프로 채우고 게시해 둬야 한다 — 그러지
 * 않으면 buildCredentialProof 가 registry_empty 로 던진다.
 */
async function proveWith(disclosure) {
  reg = await createRegistration();
  session = createSessionKey();
  uc = await buildUserCredRequest({ uid, s_u: reg.s_u, r_u: reg.r_u, sk_u: reg.sk_u, attrs: [19n, 410n, 0n, 0n, 0n, 0n] });
  req = await buildIssueRequest({ uid, Cf_u: uc.Cf_u, arid, sk_u: reg.sk_u, session, chainid: 31337n, max_height: await mh() });
  cred = await localIssue(uc.Cf_u, req.C_s_pt, 31337n, { max_height: BigInt(req.body.max_height) });
  ({ tree: tree0 } = await syncRevocationTree(provider, logAddress));
  registry.set(SLOT, await registryLeaf(reg.cm_u, uc.Cf_u));
  await publishV2(log, ciaEth, { revRoot: tree0.getRoot(), regRoot: registry.root(), epoch: (await log.epoch()) + 1n, slotIdx: [SLOT], slotLeaves: [registry.leafAt(SLOT)] });
  return buildCredentialProof({
    uid, arid, s_u: reg.s_u, r_u: reg.r_u, blind_u: uc.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs: [19n, 410n, 0n, 0n, 0n, 0n],
    credential: cred, pk_CIA, pk_trace, tree: tree0, registry, slot: SLOT, cm_u: reg.cm_u, disclosure,
  });
}

await t('사용자 자격증명 요청(π_u) → 세션 발급 요청 → 로컬 CIA 서명 → 증명 생성 → vkey 로 검증된다', async () => {
  const { proof, publicSignals, revRoot, tag } = await proveWith(null);
  assert.equal(await verifyUserCred({ uid, attrs: [19n, 410n, 0n, 0n, 0n, 0n], C_u_pt: uc.C_u_pt, cm_u: reg.cm_u, proof: parseUserCredProof(uc.body.proof) }), true, 'CIA 가 하는 검증');
  assert.equal(uc.body.uid, uid.toString());
  assert.equal(uc.body.C_u_pt.x, uc.C_u_pt.x.toString());
  assert.equal(uc.Cf_u, await compressPoint(uc.C_u_pt));
  assert.ok(uc.body.sig_u?.S, '요청 서명');
  assert.equal(cred.Cf_s, req.Cf_s.toString(), 'CIA 가 압축한 Cf_s 와 지갑의 Cf_s 가 같다');
  assert.equal(revRoot, tree0.getRoot());
  assert.equal(publicSignals.length, 30, 'V9: V7 25개 + 등록부 조건 9 regRoot 1개 + 속성 6칸(lo·hi 각 +2) = 30');
  assert.equal(BigInt(publicSignals[2]), session.pk_i);
  assert.equal(BigInt(publicSignals[3]), BigInt(cred.max_height));
  assert.equal(BigInt(publicSignals[4]), 31337n);
  assert.equal(BigInt(publicSignals[5]), 0n, 'allowAgent');
  assert.equal(BigInt(publicSignals[6]), tree0.getRoot());
  assert.equal(BigInt(publicSignals[7]), registry.root(), 'V9: regRoot');
  assert.equal(BigInt(publicSignals[10]), pk_trace.x); assert.equal(BigInt(publicSignals[11]), pk_trace.y);
  assert.equal(BigInt(publicSignals[12]), tag.c1.x); assert.equal(BigInt(publicSignals[14]), tag.c2);
  assert.equal(tag.h, await tagPlaintext(uid, arid), '태그 평문은 Poseidon(uid, arid)');
  // 태그는 두 조각으로 이 성명의 평문 h = Poseidon(uid, arid) 로 열린다 (검증 가능 암호화)
  assert.equal(await combineDecrypt(tag.c2, await partialDecrypt(svcShare.x, tag.c1), await partialDecrypt(aaShare.x, tag.c1)), await tagPlaintext(uid, arid));
  const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
  assert.ok(await snarkjs.groth16.verify(vkey, publicSignals, proof));
});

await t('V9 buildCredentialProof: set 을 주면 publicSignals[28] = sel, [29] = root; 안 주면 0·0 — 30개', async () => {
  const attrs = [1990n, 410n, 2n, 0n, 0n, 0n];
  const st = await normalizeSet({ slot: 1, members: [410, 392] }, attrs);
  const built = await proveWith({ mask: 0n, lo: [0n, 0n, 0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n, 0n, 0n], ...st });
  assert.equal(built.publicSignals.length, 30);
  assert.equal(built.publicSignals[28], '2'); assert.equal(built.publicSignals[29], st.root.toString());
  const plain = await proveWith(null);
  assert.equal(plain.publicSignals[28], '0'); assert.equal(plain.publicSignals[29], '0');
});

await t('ProofCache 는 같은 root·세션이면 재사용, root 가 바뀌면 miss', async () => {
  const cache = new ProofCache();
  cache.set(tree0.getRoot(), 's1', { proof: 'p' });
  assert.deepEqual(cache.get(tree0.getRoot(), 's1'), { proof: 'p' });
  assert.equal(cache.get(tree0.getRoot() + 1n, 's1'), null);
  assert.equal(cache.get(tree0.getRoot(), 's2'), null);
});

// V9: 사용자 자격증명의 활성 여부는 더 이상 폐기 트리(userLeaf)가 아니라 등록부 슬롯이 가진다 — 은퇴는
// 슬롯을 0 으로 게시하는 것이다(브리프 규칙 5). 동기화한 등록부로 대조하면 registry_empty 로 던진다.
await t('내 등록부 슬롯이 은퇴(0 으로 게시)되면 동기화된 등록부로는 증명을 만들 수 없다 (registry_empty)', async () => {
  registry.set(SLOT, 0n);
  await publishV2(log, ciaEth, { revRoot: tree0.getRoot(), regRoot: registry.root(), epoch: (await log.epoch()) + 1n, slotIdx: [SLOT], slotLeaves: [0n] });
  const { tree: registrySynced } = await syncRegistryTree(provider, logAddress);
  await assert.rejects(
    () => buildCredentialProof({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, blind_u: uc.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs: [19n, 410n, 0n, 0n, 0n, 0n], credential: cred, pk_CIA, pk_trace, tree: tree0, registry: registrySynced, slot: SLOT, cm_u: reg.cm_u }),
    (e) => e.reason === 'registry_empty',
  );
});

await t('buildCredentialProof 는 pk_trace 없이는 throw — 태그 없는 성명은 이제 없다', async () => {
  await assert.rejects(
    () => buildCredentialProof({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, blind_u: uc.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs: [19n, 410n, 0n, 0n, 0n, 0n], credential: cred, pk_CIA, tree: tree0, registry, slot: SLOT, cm_u: reg.cm_u }),
    /pk_trace/,
  );
});

await t('buildIssueRequest 는 allowAgent 를 싣고(기본 0) ZKP·C_pt 없이 Cf_u·C_s_pt 를 싣는다', async () => {
  const session = createSessionKey();
  const sk_u = reg.sk_u;
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

await t('normalizeDisclosure: null 여섯 → mask 0; 구간·등식; 불만족은 disclosure_unsatisfiable; 64비트 밖·lo > hi 는 bad_disclosure', async () => {
  const attrs = [1990n, 410n, 2n, 0n, 0n, 0n];
  assert.deepEqual(normalizeDisclosure([null, null, null, null, null, null], attrs), { mask: 0n, lo: [0n, 0n, 0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n, 0n, 0n] });
  assert.deepEqual(normalizeDisclosure(undefined, attrs).mask, 0n);
  assert.deepEqual(normalizeDisclosure([{ lo: '0', hi: '2007' }, { lo: '410', hi: '410' }, null, null, null, null], attrs), { mask: 3n, lo: [0n, 410n, 0n, 0n, 0n, 0n], hi: [2007n, 410n, 0n, 0n, 0n, 0n] });
  assert.throws(() => normalizeDisclosure([{ lo: '0', hi: '1980' }, null, null, null, null, null], attrs), (e) => e.reason === 'disclosure_unsatisfiable');
  assert.throws(() => normalizeDisclosure([{ lo: '5', hi: '4' }, null, null, null, null, null], attrs), (e) => e.reason === 'bad_disclosure');
  assert.throws(() => normalizeDisclosure([null, null, null, { lo: '0', hi: (1n << 64n).toString() }, null, null], attrs), (e) => e.reason === 'bad_disclosure');
  // V9: ATTR_SLOTS 가 6 이라 길이 6 까지는 허용된다 — 밖으로 나가려면 7개가 필요하다(옛 4슬롯 때는 5개였다).
  assert.throws(() => normalizeDisclosure([null, null, null, null, null, null, null], attrs), (e) => e.reason === 'bad_disclosure');
});
await t('V9 normalizeSet: 없음 → NO_SET; 소속이면 sel = slot+1·root·경로; 비소속은 disclosure_unsatisfiable; 형식 오류·슬롯 범위 밖(0..5)은 bad_disclosure', async () => {
  const attrs = [1990n, 410n, 2n, 0n, 0n, 0n];
  const none = await normalizeSet(null, attrs);
  assert.deepEqual({ sel: none.sel, root: none.root, index: none.index, path: [...none.path] }, { sel: 0n, root: 0n, index: 0, path: Array(8).fill(0n) });
  const s = await normalizeSet({ slot: 1, members: [410, 392, 840, 276, 250] }, attrs);
  assert.equal(s.sel, 2n); assert.equal(s.index, 3); assert.equal(s.path.length, 8); assert.notEqual(s.root, 0n);
  await assert.rejects(() => normalizeSet({ slot: 1, members: [392, 840] }, attrs), (e) => e.reason === 'disclosure_unsatisfiable');
  // V9: 슬롯 범위가 0..5 로 늘어 옛 bad case(slot: 4)는 이제 유효하다 — 새 상한 6 으로 바꾼다.
  for (const bad of [{ slot: 6, members: [1] }, { slot: -1, members: [1] }, { slot: '1', members: [1] }, { slot: 1, members: [] }, { slot: 1 }, { members: [1] }, 'x']) {
    await assert.rejects(() => normalizeSet(bad, attrs), (e) => e.reason === 'bad_disclosure', `허용되면 안 됨: ${JSON.stringify(bad)}`);
  }
});
await t('V9 disclosureKey·hasPredicate: set 이 키에 들어가고, mask 0 이라도 sel ≠ 0 이면 술어가 있다', async () => {
  const attrs = [1990n, 410n, 2n, 0n, 0n, 0n];
  const base = normalizeDisclosure(null, attrs);
  const withSet = { ...base, ...(await normalizeSet({ slot: 1, members: [410] }, attrs)) };
  assert.notEqual(disclosureKey(base), disclosureKey(withSet));
  assert.equal(hasPredicate(base), false); assert.equal(hasPredicate(withSet), true);
  assert.equal(hasPredicate(normalizeDisclosure([{ lo: '0', hi: '2007' }, null, null, null, null, null], attrs)), true);
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
  // V9: 바로 위 테스트가 (옛 userLeaf 온체인 폐기 대신) 내 등록부 슬롯을 0 으로 게시해 버렸다 — 그 reg/uc
  // 를 그대로 쓰면 root 고정과 무관하게 registry_empty 로 즉시 throw 하므로, 이 테스트만은 새 등록·세션·
  // 발급과 그 전용(은퇴되지 않은) 등록부로 자격증명을 새로 만든다.
  const reg2 = await createRegistration();
  const session2 = createSessionKey();
  const uc2 = await buildUserCredRequest({ uid, s_u: reg2.s_u, r_u: reg2.r_u, sk_u: reg2.sk_u, attrs: [19n, 410n, 0n, 0n, 0n, 0n] });
  const req2 = await buildIssueRequest({ uid, Cf_u: uc2.Cf_u, arid, sk_u: reg2.sk_u, session: session2, chainid: 31337n, max_height: await mh() });
  const cred2 = await localIssue(uc2.Cf_u, req2.C_s_pt, 31337n, { max_height: BigInt(req2.body.max_height) });
  const registry2 = await createRegistryTree();   // 이 테스트 전용 — 체인에 올리지 않는다(브리프 규칙 4의 "단순 케이스")
  registry2.set(SLOT, await registryLeaf(reg2.cm_u, uc2.Cf_u));

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
    uid, arid, s_u: reg2.s_u, r_u: reg2.r_u, blind_u: uc2.secrets.blind_u, blind_s: req2.secrets.blind_s, pk_i: session2.pk_i, attrs: [19n, 410n, 0n, 0n, 0n, 0n],
    credential: cred2, pk_CIA, pk_trace, tree, registry: registry2, slot: SLOT, cm_u: reg2.cm_u,
  });
  assert.equal(witnessRoot, rootBefore);
  assert.equal(out.revRoot, rootBefore, '증인 root 여야 한다');
  assert.notEqual(tree.getRoot(), rootBefore, '트리는 실제로 바뀌었다');
  assert.equal(BigInt(out.publicSignals[6]), rootBefore, '공개 입력의 revRoot 자리도 증인 root 여야 한다');
});

// 2026-09-25 리뷰 E-7 가드("두 비멤버십 증인의 root 가 다르면 던진다")는 V9 에서 사라졌다 — lib/mode3_wallet.js
// buildCredentialProof 의 조건 9 주석대로 "사용자 리프 비멤버십 증인은 없다"; 세션 리프 증인 하나만 남아
// getNonMembershipWitness 를 한 번만 부르므로 "두 증인이 어긋난다" 는 경우 자체가 구조적으로 불가능해졌다
// (grep 으로 확인: lib/mode3_wallet.js 에 그 가드·에러 문구가 더 이상 없다). 이 테스트가 지키던 성질의 V9
// 쪽 등가물은 "증인을 정확히 한 번만 요청하고 그 root 를 그대로 쓴다" 이므로 그렇게 바꾼다 — 사용자 리프
// 비멤버십 증인이 되살아나는 회귀가 생기면(두 번째 호출) n 이 1 을 넘어 이 테스트가 잡는다.
await t('V9: 비멤버십 증인은 세션 리프 하나만 요청한다 (사용자 리프 증인이 되살아나는 회귀를 잡는다)', async () => {
  const reg3 = await createRegistration();
  const session3 = createSessionKey();
  const uc3 = await buildUserCredRequest({ uid, s_u: reg3.s_u, r_u: reg3.r_u, sk_u: reg3.sk_u, attrs: [19n, 410n, 0n, 0n, 0n, 0n] });
  const req3 = await buildIssueRequest({ uid, Cf_u: uc3.Cf_u, arid, sk_u: reg3.sk_u, session: session3, chainid: 31337n, max_height: await mh() });
  const cred3 = await localIssue(uc3.Cf_u, req3.C_s_pt, 31337n, { max_height: BigInt(req3.body.max_height) });
  const registry3 = await createRegistryTree();   // 이 테스트 전용 — 체인에 올리지 않는다(브리프 규칙 4의 "단순 케이스")
  registry3.set(SLOT, await registryLeaf(reg3.cm_u, uc3.Cf_u));

  const { tree } = await syncRevocationTree(provider, logAddress);
  const orig = tree.getNonMembershipWitness.bind(tree);
  let n = 0;
  tree.getNonMembershipWitness = async (target) => { n++; return orig(target); };
  const out = await buildCredentialProof({
    uid, arid, s_u: reg3.s_u, r_u: reg3.r_u, blind_u: uc3.secrets.blind_u, blind_s: req3.secrets.blind_s, pk_i: session3.pk_i,
    attrs: [19n, 410n, 0n, 0n, 0n, 0n], credential: cred3, pk_CIA, pk_trace, tree, registry: registry3, slot: SLOT, cm_u: reg3.cm_u,
  });
  assert.equal(n, 1, '사용자 리프 비멤버십 증인이 되살아나면(회귀) 이 수가 늘어난다');
  assert.equal(BigInt(out.publicSignals[6]), tree.getRoot());
});

provider.destroy();
process.exit(failed === 0 ? 0 : 1);
