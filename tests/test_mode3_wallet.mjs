// 지갑 라이브러리 — 트리 동기화·증명 생성·캐시. :8545 + build/mode3 zkey 필요. (chain 그룹)
//   node tests/test_mode3_wallet.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { getProvider, fundAddress, deployMode3Log, rootToBytes32, publishV3 } from './helpers/mode3_chain.mjs';
import { createRevocationTree } from '../lib/mode3_revocation.js';
import { createRegistryTree, registryLeaf } from '../lib/mode3_registry.js';
import { credMessageV11, compressPoint, randomScalar, auidSOf, aridSOf } from '../lib/mode3_credential.js';
import {
  createRegistration, createSessionKey, buildIssueRequest, syncRevocationTree, syncRegistryTree,
  buildCredentialProof, ProofCache, signChallenge, signSessionRequest, ZKEY_PATH, VKEY_PATH, chooseMaxHeight,
  normalizeDisclosure, normalizeSet, hasPredicate, disclosureKey,
} from '../lib/mode3_wallet.js';
import { IDP_VKEY_PATH, loadIdpVkey, verifyIdp, idpPublicSignals } from '../lib/mode3_idp_proof.js';
import { verifySessionRequest } from '../lib/mode3_rp.js';
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

const mh = async (ttl = 300n) => chooseMaxHeight(BigInt(await provider.getBlockNumber()), { ttlBlocks: ttl });
// 서버 없이 IdP 역할을 로컬에서 흉내낸다 (서명만). V11: Sign(D_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent). max_height 는 C_s 안.
async function localIssue(req, chainid, { allowAgent = 0n } = {}) {
  const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessageV11(req.auid_s, req.arid_s, req.Cf_u, req.Cf_s, chainid, allowAgent)));
  return { Cf_u: req.Cf_u.toString(), Cf_s: req.Cf_s.toString(), max_height: req.body.max_height, chainid: chainid.toString(), allowAgent: allowAgent.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
// V9: 폐기 리프를 넣고 두 root(폐기·등록부)를 같이 올린다 — Mode3Log 는 root 를 하나씩 받지 않는다.
async function publish(leavesBig) {
  const tree = await createRevocationTree();
  const ev = await log.queryFilter(log.filters.Revoked());
  for (const e of ev) for (const l of e.args.leaves) await tree.insert(BigInt(l));
  for (const l of leavesBig) await tree.insert(l);
  const epoch = (await log.epoch()) + 1n;
  await publishV3(log, ciaEth, { revRoot: tree.getRoot(), regRoot: registry.root(), epoch, revLeaves: leavesBig });
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

let reg, session, req, cred, tree0; const ATTRS = [19n, 410n, 0n, 0n, 0n, 0n]; let blind_u, r_rp, r_s;
/**
 * 등록 → 발급 요청(C_u·C_s·π_IdP) → 슬롯 게시(등록부) → 로컬 IdP 서명 → buildCredentialProof 까지의
 * 픽스처 준비를 묶는다. disclosure 를 그대로 buildCredentialProof 에 넘긴다(null 이면 선택 공개 없음).
 * reg·session·req·cred·tree0·blind_u·r_rp·r_s 는 이 파일의 이후 테스트가 그대로 참조하는 전역이라 여기서도 채운다.
 * V9 조건 9: 첫 로그인(증명) 전에 내 슬롯(SLOT=0)을 내 자격증명 리프로 채우고 게시해 둬야 한다 — 그러지
 * 않으면 buildCredentialProof 가 registry_empty 로 던진다.
 */
async function proveWith(disclosure) {
  reg = await createRegistration(uid);
  session = createSessionKey();
  blind_u = randomScalar(); r_rp = randomScalar(); r_s = randomScalar();
  req = await buildIssueRequest({ uid, s_u: reg.s_u, blind_u, attrs: ATTRS, arid, r_rp, r_s, sk_u: reg.sk_u, session, chainid: 31337n, max_height: await mh() });
  cred = await localIssue(req, 31337n);
  ({ tree: tree0 } = await syncRevocationTree(provider, logAddress));
  registry.set(SLOT, await registryLeaf(reg.auid, req.Cf_u));
  await publishV3(log, ciaEth, { revRoot: tree0.getRoot(), regRoot: registry.root(), epoch: (await log.epoch()) + 1n, slotIdx: [SLOT], slotLeaves: [registry.leafAt(SLOT)] });
  return buildCredentialProof({ uid, arid, s_u: reg.s_u, auid: reg.auid, blind_u, r_rp, r_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree: tree0, registry, slot: SLOT, disclosure });
}

await t('V11: 발급 요청(C_u·C_s·π_IdP·sig_u) → 로컬 IdP 서명 → 증명 생성 → vkey 로 검증; 공개 입력 33, [30..32] = auid_s·arid_s·r_s', async () => {
  const { proof, publicSignals, revRoot, tag } = await proveWith(null);
  assert.deepEqual(Object.keys(req.body).sort(), ['C_s_pt', 'C_u_pt', 'allowAgent', 'arid_s', 'auid_s', 'chainid', 'max_height', 'proof_idp', 'sig_u', 'uid']);
  const vkIdp = await loadIdpVkey(IDP_VKEY_PATH);
  const pubIdp = idpPublicSignals({ uid, auid: reg.auid, auid_s: req.auid_s, C_u_pt: req.C_u_pt, C_s_pt: req.C_s_pt, max_height: BigInt(req.body.max_height) });
  assert.deepEqual(pubIdp, req.idpPublicSignals, 'CIA 가 스스로 조립한 공개 입력이 지갑의 것과 같다');
  assert.equal(await verifyIdp(vkIdp, pubIdp, req.body.proof_idp), true, 'CIA 가 하는 π_IdP 검증');
  assert.equal(await verifyIdp(vkIdp, idpPublicSignals({ uid, auid: reg.auid + 1n, auid_s: req.auid_s, C_u_pt: req.C_u_pt, C_s_pt: req.C_s_pt, max_height: BigInt(req.body.max_height) }), req.body.proof_idp), false, '다른 auid 로는 통과하지 않는다');
  assert.equal(req.auid_s, await auidSOf({ auid: reg.auid, arid, r_rp })); assert.equal(req.arid_s, await aridSOf({ arid, r_rp }));
  assert.equal(cred.Cf_s, req.Cf_s.toString());
  assert.equal(revRoot, tree0.getRoot());
  assert.equal(publicSignals.length, 34, 'V11: V9 30 + auid_s·arid_s·r_s·counter');
  assert.equal(BigInt(publicSignals[2]), session.pk_i);
  assert.equal(BigInt(publicSignals[3]), BigInt(cred.max_height));
  assert.equal(BigInt(publicSignals[4]), 31337n);
  assert.equal(BigInt(publicSignals[5]), 0n, 'allowAgent');
  assert.equal(BigInt(publicSignals[6]), tree0.getRoot());
  assert.equal(BigInt(publicSignals[7]), registry.root(), 'regRoot');
  assert.equal(BigInt(publicSignals[10]), pk_trace.x); assert.equal(BigInt(publicSignals[11]), pk_trace.y);
  assert.equal(BigInt(publicSignals[12]), tag.c1.x); assert.equal(BigInt(publicSignals[14]), tag.c2);
  assert.equal(BigInt(publicSignals[30]), req.auid_s); assert.equal(BigInt(publicSignals[31]), req.arid_s); assert.equal(BigInt(publicSignals[32]), r_s);
  assert.equal(tag.h, await tagPlaintext(uid, arid), '태그 평문은 Poseidon(uid, arid)');
  assert.equal(await combineDecrypt(tag.c2, await partialDecrypt(svcShare.x, tag.c1), await partialDecrypt(aaShare.x, tag.c1)), await tagPlaintext(uid, arid));
  const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
  assert.ok(await snarkjs.groth16.verify(vkey, publicSignals, proof));
});

await t('V9 buildCredentialProof: set 을 주면 publicSignals[28] = sel, [29] = root; 안 주면 0·0 — 34개', async () => {
  const attrs = [1990n, 410n, 2n, 0n, 0n, 0n];
  const st = await normalizeSet({ slot: 1, members: [410, 392] }, attrs);
  const built = await proveWith({ mask: 0n, lo: [0n, 0n, 0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n, 0n, 0n], ...st });
  assert.equal(built.publicSignals.length, 34);
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
  await publishV3(log, ciaEth, { revRoot: tree0.getRoot(), regRoot: registry.root(), epoch: (await log.epoch()) + 1n, slotIdx: [SLOT], slotLeaves: [0n] });
  const { tree: registrySynced } = await syncRegistryTree(provider, logAddress);
  await assert.rejects(
    () => buildCredentialProof({ uid, arid, s_u: reg.s_u, auid: reg.auid, blind_u, r_rp, r_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree: tree0, registry: registrySynced, slot: SLOT }),
    (e) => e.reason === 'registry_empty',
  );
});

await t('buildCredentialProof 는 pk_trace 없이는 throw — 태그 없는 성명은 이제 없다', async () => {
  await assert.rejects(
    () => buildCredentialProof({ uid, arid, s_u: reg.s_u, auid: reg.auid, blind_u, r_rp, r_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, tree: tree0, registry, slot: SLOT }),
    /pk_trace/,
  );
});

await t('V11 buildIssueRequest: 본문 10필드, allowAgent 기본 0, Cf_u·Cf_s·auid 를 돌려준다; 범위·누락은 throw', async () => {
  const session = createSessionKey();
  const h = await mh();
  const base = { uid, s_u: reg.s_u, blind_u: randomScalar(), attrs: ATTRS, arid, r_rp: randomScalar(), r_s: randomScalar(), sk_u: reg.sk_u, session, chainid: 31337n, max_height: h };
  const a = await buildIssueRequest(base);
  assert.equal(a.body.allowAgent, '0'); assert.equal(a.body.chainid, '31337'); assert.equal(a.body.max_height, h.toString());
  assert.equal(a.body.C_u_pt.x, a.C_u_pt.x.toString()); assert.equal(a.body.C_s_pt.x, a.C_s_pt.x.toString());
  assert.equal(a.Cf_u, await compressPoint(a.C_u_pt)); assert.equal(a.Cf_s, await compressPoint(a.C_s_pt));
  assert.equal(a.auid, reg.auid); assert.ok(a.body.proof_idp?.pi_a, 'π_IdP 가 실린다');
  assert.equal((await buildIssueRequest({ ...base, allowAgent: 1n })).body.allowAgent, '1');
  await assert.rejects(() => buildIssueRequest({ ...base, allowAgent: 2n }), /allowAgent/);
  await assert.rejects(() => buildIssueRequest({ ...base, max_height: undefined }), /max_height/);
  await assert.rejects(() => buildIssueRequest({ ...base, r_rp: undefined }), /r_rp/);
  assert.equal(chooseMaxHeight(1234n), 1600n); assert.equal(chooseMaxHeight(1299n), 1600n); assert.equal(chooseMaxHeight(1300n), 1600n); assert.equal(chooseMaxHeight(1301n), 1700n);
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
  // V9: 바로 위 테스트가 (옛 userLeaf 온체인 폐기 대신) 내 등록부 슬롯을 0 으로 게시해 버렸다 — 그 reg
  // 를 그대로 쓰면 root 고정과 무관하게 registry_empty 로 즉시 throw 하므로, 이 테스트만은 새 등록·세션·
  // 발급과 그 전용(은퇴되지 않은) 등록부로 자격증명을 새로 만든다.
  const reg2 = await createRegistration(uid);
  const session2 = createSessionKey();
  const b2 = randomScalar(), rp2 = randomScalar(), rs2 = randomScalar();
  const req2 = await buildIssueRequest({ uid, s_u: reg2.s_u, blind_u: b2, attrs: ATTRS, arid, r_rp: rp2, r_s: rs2, sk_u: reg2.sk_u, session: session2, chainid: 31337n, max_height: await mh() });
  const cred2 = await localIssue(req2, 31337n);
  const registry2 = await createRegistryTree();   // 이 테스트 전용 — 체인에 올리지 않는다(브리프 규칙 4의 "단순 케이스")
  registry2.set(SLOT, await registryLeaf(reg2.auid, req2.Cf_u));

  const { tree } = await syncRevocationTree(provider, logAddress);
  const rootBefore = tree.getRoot();
  // 2026-10-22: buildCredentialProof 는 이제 세션 구간 비멤버십(getRangeNonMembershipWitness)을 쓴다 — 점 증인(getNonMembershipWitness)은 더 이상 안 부른다.
  const orig = tree.getRangeNonMembershipWitness.bind(tree);
  let witnessRoot = null;
  tree.getRangeNonMembershipWitness = async (lo, hi) => {
    const w = await orig(lo, hi);
    witnessRoot = BigInt(w.root);
    await tree.insert(999_999_999n);            // 다른 요청의 sync() 가 끼어든 상황을 흉내
    return w;
  };
  const out = await buildCredentialProof({
    uid, arid, s_u: reg2.s_u, auid: reg2.auid, blind_u: b2, r_rp: rp2, r_s: rs2, pk_i: session2.pk_i, attrs: ATTRS,
    credential: cred2, pk_CIA, pk_trace, tree, registry: registry2, slot: SLOT,
  });
  assert.equal(witnessRoot, rootBefore);
  assert.equal(out.revRoot, rootBefore, '증인 root 여야 한다');
  assert.notEqual(tree.getRoot(), rootBefore, '트리는 실제로 바뀌었다');
  assert.equal(BigInt(out.publicSignals[6]), rootBefore, '공개 입력의 revRoot 자리도 증인 root 여야 한다');
});

// 2026-09-25 리뷰 E-7 가드("두 비멤버십 증인의 root 가 다르면 던진다")는 V9 에서 사라졌다 — lib/mode3_wallet.js
// buildCredentialProof 의 조건 9 주석대로 "사용자 리프 비멤버십 증인은 없다"; 세션 리프 증인 하나만 남아
// (2026-10-22 부터는 getRangeNonMembershipWitness) 한 번만 부르므로 "두 증인이 어긋난다" 는 경우 자체가 구조적으로
// 불가능해졌다(grep 으로 확인: lib/mode3_wallet.js 에 그 가드·에러 문구가 더 이상 없다). 이 테스트가 지키던 성질의 V9
// 쪽 등가물은 "증인을 정확히 한 번만 요청하고 그 root 를 그대로 쓴다" 이므로 그렇게 바꾼다 — 사용자 리프
// 비멤버십 증인이 되살아나는 회귀가 생기면(두 번째 호출) n 이 1 을 넘어 이 테스트가 잡는다.
await t('V9: 비멤버십 증인은 세션 리프 하나만 요청한다 (사용자 리프 증인이 되살아나는 회귀를 잡는다)', async () => {
  const reg3 = await createRegistration(uid);
  const session3 = createSessionKey();
  const b3 = randomScalar(), rp3 = randomScalar(), rs3 = randomScalar();
  const req3 = await buildIssueRequest({ uid, s_u: reg3.s_u, blind_u: b3, attrs: ATTRS, arid, r_rp: rp3, r_s: rs3, sk_u: reg3.sk_u, session: session3, chainid: 31337n, max_height: await mh() });
  const cred3 = await localIssue(req3, 31337n);
  const registry3 = await createRegistryTree();   // 이 테스트 전용 — 체인에 올리지 않는다(브리프 규칙 4의 "단순 케이스")
  registry3.set(SLOT, await registryLeaf(reg3.auid, req3.Cf_u));

  const { tree } = await syncRevocationTree(provider, logAddress);
  const orig = tree.getRangeNonMembershipWitness.bind(tree);
  let n = 0;
  tree.getRangeNonMembershipWitness = async (lo, hi) => { n++; return orig(lo, hi); };
  const out = await buildCredentialProof({
    uid, arid, s_u: reg3.s_u, auid: reg3.auid, blind_u: b3, r_rp: rp3, r_s: rs3, pk_i: session3.pk_i,
    attrs: ATTRS, credential: cred3, pk_CIA, pk_trace, tree, registry: registry3, slot: SLOT,
  });
  assert.equal(n, 1, '사용자 리프 비멤버십 증인이 되살아나면(회귀) 이 수가 늘어난다');
  assert.equal(BigInt(out.publicSignals[6]), tree.getRoot());
});

// V10 7/N — 거울 epoch 시점의 등록부(untilEpoch·expectRoot). 이 테스트만 쓰는 빈 슬롯(SLOT_V10)을 두 번 바꿔
// 첫 게시 epoch 로 재구성하면 첫 값의 root 가 나오는지 본다(두 번째 게시는 재생에서 보이면 안 된다).
await t('V10 syncRegistryTree: untilEpoch·expectRoot 로 첫 게시 epoch 시점의 등록부를 재구성한다', async () => {
  const SLOT_V10 = 9;
  const leafA = 1111n, leafB = 2222n;
  registry.set(SLOT_V10, leafA);
  await publishV3(log, ciaEth, { revRoot: tree0.getRoot(), regRoot: registry.root(), epoch: (await log.epoch()) + 1n, slotIdx: [SLOT_V10], slotLeaves: [leafA] });
  const e1 = await log.epoch(); const regRootAtE1 = BigInt(await log.regRoot());
  registry.set(SLOT_V10, leafB);
  await publishV3(log, ciaEth, { revRoot: tree0.getRoot(), regRoot: registry.root(), epoch: (await log.epoch()) + 1n, slotIdx: [SLOT_V10], slotLeaves: [leafB] });
  const r = await syncRegistryTree(provider, logAddress, { untilEpoch: e1, expectRoot: regRootAtE1 });
  assert.equal(r.root, regRootAtE1); assert.equal(r.epoch, e1);
  assert.equal(r.tree.leafAt(SLOT_V10), leafA, '두 번째 게시(leafB)는 재생에서 보이면 안 된다');
  await assert.rejects(syncRegistryTree(provider, logAddress, { untilEpoch: e1, expectRoot: 12345n }), /거울 regRoot/);
});

provider.destroy();
process.exit(failed === 0 ? 0 : 1);
