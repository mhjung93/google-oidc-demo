// RP 검증기 — §6.3 7단계와 음성 6건. :8545 + build/mode3 필요. (chain 그룹)
//   node tests/test_mode3_rp.mjs
// hardhat_mine 으로 :8545 블록을 진행시킨다 (기존 chain 그룹과 같은 성질).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { getProvider, fundAddress, deployRevocationLog, signRootPublication, rootToBytes32, mineBlocks } from './helpers/mode3_chain.mjs';
import { userLeaf } from '../lib/mode3_revocation.js';
import { credMessageV5, compressPoint, randomScalar } from '../lib/mode3_credential.js';
import { createRegistration, createSessionKey, buildUserCredRequest, buildIssueRequest, syncRevocationTree, buildCredentialProof, signChallenge, normalizeSet, VKEY_PATH } from '../lib/mode3_wallet.js';
import { createRpVerifier, maskDisclosure } from '../lib/mode3_rp.js';
import { createShare, combinePublicKey } from '../lib/mode3_trace.js';
import { setRoot } from '../lib/mode3_set_tree.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const provider = getProvider();
const ciaEth = ethers.Wallet.createRandom().connect(provider);
await fundAddress(ciaEth.address, '1', provider);
const { address: logAddress, contract: log } = await deployRevocationLog(ciaEth.address, provider);
const eddsa = await buildEddsa();
const ps = await buildPoseidon();
const F = ps.F;
assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const keyOf = (prv) => { const p = eddsa.prv2pub(prv); return { prv, pub: { x: F.toObject(p[0]), y: F.toObject(p[1]) } }; };
const CIA = keyOf(Buffer.alloc(32, 9));
const ATTACKER = keyOf(Buffer.alloc(32, 66));
const uid = 12345n, arid = 22222222222222222222n, otherArid = 33333333333333333333n;
const svcShare = await createShare(), aaShare = await createShare();
const pk_trace = await combinePublicKey(svcShare.X, aaShare.X);
const other_trace = await combinePublicKey((await createShare()).X, (await createShare()).X);

// 서버 없이 CIA 서명만 흉내낸다. V5: Sign(D_V5, Cf_u, Cf_s, max_height, chainid, allowAgent).
async function issueWith(key, Cf_u, C_s_pt, { max_height, chainid = 31337n, allowAgent = 0n } = {}) {
  const Cf_s = await compressPoint(C_s_pt);
  const s = eddsa.signPoseidon(key.prv, F.e(await credMessageV5(Cf_u, Cf_s, max_height, chainid, allowAgent)));
  return { Cf_u: Cf_u.toString(), Cf_s: Cf_s.toString(), max_height: max_height.toString(), chainid: chainid.toString(), allowAgent: allowAgent.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
async function publish(leavesBig) {
  const { tree } = await syncRevocationTree(provider, logAddress);
  for (const l of leavesBig) await tree.insert(l);
  const root = rootToBytes32(tree.getRoot()), epoch = (await log.epoch()) + 1n, leaves = leavesBig.map(rootToBytes32);
  await (await log.connect(ciaEth).publishRoot(root, epoch, leaves, await signRootPublication(ciaEth, { logAddress, root, epoch, leaves }))).wait();
}
async function makeLogin({ key = CIA, useArid = arid, ttlBlocks = 300n, chainid = 31337n, useTrace = pk_trace, allowAgent = 0n, disclosure = null } = {}) {
  const reg = await createRegistration();
  const session = createSessionKey();
  const attrs = [19n, 410n, 0n, 0n];
  const r_s = randomScalar();   // 서비스 챌린지 — σ 에만 쓴다(공개 입력엔 없다)
  const max_height = BigInt(await provider.getBlockNumber()) + ttlBlocks;   // 지갑이 정한다(2026-09-18 §3.2 갱신)
  const sk_u = Buffer.alloc(32, 3).toString('hex');
  const uc = await buildUserCredRequest({ uid, s_u: reg.s_u, r_u: reg.r_u, sk_u, attrs });   // 사용자 자격증명(π_u) — CIA 검증은 test_mode3_wallet 에서
  const req = await buildIssueRequest({ uid, Cf_u: uc.Cf_u, arid: useArid, sk_u, session, chainid, allowAgent, max_height });
  const cred = await issueWith(key, uc.Cf_u, req.C_s_pt, { max_height, chainid, allowAgent });
  const { tree } = await syncRevocationTree(provider, logAddress);
  // disclosure 는 정규화 없이 그대로 회로로 간다(lib/mode3_wallet.js 의 buildCredentialProof) — 지갑의 normalizeDisclosure 를
  // 거치지 않는 경로라, 마스크 밖 슬롯이 0 이 아닌 유효한 π 를 일부러 만들 수 있다(아래 C-2 E2E 케이스).
  const { proof, publicSignals } = await buildCredentialProof({ uid, arid: useArid, s_u: reg.s_u, blind_u: uc.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs, credential: cred, pk_CIA: key.pub, pk_trace: useTrace, tree, disclosure });
  return { proof, publicSignals, r_s, sig: await signChallenge(session.wallet, r_s.toString()), session, cred, reg };
}

const rp = createRpVerifier({ provider, logAddress, vkey, pkCIA: CIA.pub, arid, chainId: 31337n, pkTrace: pk_trace });

await t('양성: 7단계 전부 통과, PPID 와 pk_i 를 돌려준다', async () => {
  const L = await makeLogin();
  const r = await rp.verifyLogin(L);
  assert.equal(r.ok, true, JSON.stringify(r, (_, v) => (typeof v === 'bigint' ? v.toString() : v)));
  assert.equal(r.PPID, BigInt(L.publicSignals[0]));
  assert.equal(r.pk_i, L.session.pk_i);
});

await t('V7: publicSignals 가 14개면 malformed, 25개면 통과하고 disclosure 를 돌려준다, [14] ≥ 16 은 bad_disclosure', async () => {
  const good = await makeLogin();
  assert.equal(good.publicSignals.length, 25);
  const v = await rp.verifyLogin(good);
  assert.equal(v.ok, true, JSON.stringify(v, (k, vv) => (typeof vv === 'bigint' ? vv.toString() : vv)));
  assert.equal(v.disclosure.mask, 0n);
  assert.equal((await rp.verifyLogin({ ...good, publicSignals: good.publicSignals.slice(0, 14) })).reason, 'malformed');
  const ps = [...good.publicSignals]; ps[14] = '16';
  assert.equal((await rp.verifyLogin({ ...good, publicSignals: ps })).reason, 'bad_disclosure');
});

await t('V7: set_sel/set_root 가 disclosure 에 실린다; sel 5·(sel 0, root ≠ 0) 은 bad_disclosure; maskDisclosure 는 sel 0 이면 root 를 지운다', async () => {
  const members = [410, 392, 840, 276, 250];
  const attrs = [19n, 410n, 0n, 0n];   // makeLogin 이 쓰는 attrs 와 같다(위 함수 정의)
  const st = await normalizeSet({ slot: 1, members }, attrs);
  const good = await makeLogin({ disclosure: { mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n], ...st } });
  const v = await rp.verifyLogin(good);
  assert.equal(v.ok, true, v.reason);
  assert.equal(v.disclosure.sel, 2n); assert.equal(v.disclosure.root, await setRoot(members));
  const ps = [...good.publicSignals]; ps[23] = '5';
  assert.equal((await rp.verifyLogin({ ...good, publicSignals: ps })).reason, 'bad_disclosure');
  const plain = await makeLogin();
  const ps2 = [...plain.publicSignals]; ps2[24] = '7';
  assert.equal((await rp.verifyLogin({ ...plain, publicSignals: ps2 })).reason, 'bad_disclosure');
  assert.deepEqual(maskDisclosure({ mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n], sel: 0n, root: 9n }).root, 0n);
  assert.deepEqual(maskDisclosure({ mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n] }), { mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n], sel: 0n, root: 0n });
});

// I-2(2026-09-25 전체 코드 리뷰): 회로 ⑦ 은 "선택한 속성이 set_root 의 트리에 들어 있다" 만 증명한다 —
// **누구의 트리인지는 모른다.** 정책 집합을 아는 서비스가 대조하지 않으면, 자기 국가 하나만 든 집합의 root 로
// "허용 집합 소속" 을 주장하는 유효한 π 가 만들어지고 세션·로그인 기록·화면이 그것을 보증처럼 싣는다.
// 온체인 AttrGate 는 이미 setRoot == allowedCountriesRoot 를 요구하므로 오프체인도 같은 선을 그어야 한다.
await t('I-2: policySetRoot 를 준 검증기는 정책 집합이 아닌 set_root 를 bad_disclosure 로 거절한다', async () => {
  const members = [410, 392, 840, 276, 250];
  const attrs = [19n, 410n, 0n, 0n];   // makeLogin 이 쓰는 attrs 와 같다(위 함수 정의)
  const policyRoot = await setRoot(members);
  const rpPolicy = createRpVerifier({ provider, logAddress, vkey, pkCIA: CIA.pub, arid, chainId: 31337n, pkTrace: pk_trace, policySetRoot: policyRoot });
  const zeros = { mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n] };

  // 자기 국가만 든 집합([410])으로 "소속" 을 주장하는 **유효한** π — 회로도 서명도 정상이다.
  const mineSet = await normalizeSet({ slot: 1, members: [410] }, attrs);
  const bad = await makeLogin({ disclosure: { ...zeros, ...mineSet } });
  assert.equal(BigInt(bad.publicSignals[23]), 2n, '전제: set_sel = 2(슬롯 1)');
  assert.notEqual(BigInt(bad.publicSignals[24]), policyRoot, '전제: 정책 집합이 아닌 트리의 root 다');
  const r = await rpPolicy.verifyLogin(bad);
  assert.equal(r.ok, false); assert.equal(r.reason, 'bad_disclosure');

  // 정책 집합이면 통과한다.
  const good = await makeLogin({ disclosure: { ...zeros, ...(await normalizeSet({ slot: 1, members }, attrs)) } });
  const g = await rpPolicy.verifyLogin(good);
  assert.equal(g.ok, true, JSON.stringify(g, (k, v) => (typeof v === 'bigint' ? v.toString() : v)));
  assert.equal(g.disclosure.root, policyRoot);

  // 집합 술어가 없는 로그인(sel = 0)은 정책과 무관하게 그대로 통과한다.
  const plain = await makeLogin();
  assert.equal((await rpPolicy.verifyLogin(plain)).ok, true, 'sel = 0 은 집합을 주장하지 않는다');

  // policySetRoot 를 안 주면 예전처럼 검사하지 않는다(일반 검증기 계약 유지).
  assert.equal((await rp.verifyLogin(bad)).ok, true);

  // 타입 검사: 실수로 문자열·숫자를 넘기면 비교가 늘 false 가 되어 모든 집합 로그인이 막힌다 — 기동 때 막는다.
  for (const v of [policyRoot.toString(), 1, {}]) {
    assert.throws(() => createRpVerifier({ provider, logAddress, vkey, pkCIA: CIA.pub, arid, chainId: 31337n, pkTrace: pk_trace, policySetRoot: v }), /policySetRoot/);
  }
});

await t('음성 d: 공격자가 자기 CIA 키로 서명한 credential 은 untrusted_cia (유일한 위조 방어선)', async () => {
  const L = await makeLogin({ key: ATTACKER });
  const r = await rp.verifyLogin(L);
  assert.deepEqual(r, { ok: false, reason: 'untrusted_cia' });
});

await t('음성 f: 챌린지 서명이 다른 키면 bad_signature', async () => {
  const L = await makeLogin();
  L.sig = await signChallenge(ethers.Wallet.createRandom(), L.r_s.toString());
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'bad_signature' });
});

await t('음성 f: 다른 r_s 위의 서명을 붙이면 bad_signature', async () => {
  const L = await makeLogin();
  const sig = await signChallenge(L.session.wallet, (L.r_s + 1n).toString());
  assert.deepEqual(await rp.verifyLogin({ proof: L.proof, publicSignals: L.publicSignals, sig, r_s: L.r_s }), { ok: false, reason: 'bad_signature' });
});

await t('음성 f: 서버가 다른 r_s 를 넘기면 bad_signature (σ 는 서버가 준 챌린지 위여야 한다)', async () => {
  const L = await makeLogin();
  const r = await rp.verifyLogin({ proof: L.proof, publicSignals: L.publicSignals, sig: L.sig, r_s: L.r_s + 1n });
  assert.equal(r.ok, false); assert.equal(r.reason, 'bad_signature');
});

await t('양성: verifyLogin 이 max_height·allowAgent·root 를 돌려준다 (서버가 세션을 만들 재료)', async () => {
  const L = await makeLogin({ allowAgent: 1n });
  const r = await rp.verifyLogin({ proof: L.proof, publicSignals: L.publicSignals, sig: L.sig, r_s: L.r_s });
  assert.equal(r.ok, true, JSON.stringify(r, (k, v) => (typeof v === 'bigint' ? v.toString() : v)));
  assert.equal(r.max_height, BigInt(L.cred.max_height));
  assert.equal(r.allowAgent, 1n);
  assert.equal(r.root, BigInt(L.publicSignals[6]));
  assert.equal(r.r_s, undefined, 'r_s 는 검증기가 돌려주지 않는다 — 서버가 이미 안다');
});

await t('음성 arid: 다른 RP 용 credential 은 wrong_arid', async () => {
  const L = await makeLogin({ useArid: otherArid });
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'wrong_arid' });
});

await t('음성 d″: 다른 조합 키로 만든 태그는 wrong_trace_key (서비스가 자기 키와 대조한다)', async () => {
  const L = await makeLogin({ useTrace: other_trace });
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'wrong_trace_key' });
});

await t('음성 태그: c1 이 항등원(0,1)이면 bad_tag (r=0 이 평문을 드러내는 것을 막는다)', async () => {
  const L = await makeLogin();
  const bad = [...L.publicSignals];
  bad[11] = '0'; bad[12] = '1';
  assert.deepEqual(await rp.verifyLogin({ ...L, publicSignals: bad }), { ok: false, reason: 'bad_tag' });
});

await t('양성: verifyLogin 이 태그를 돌려준다 (서비스가 로그에 남길 재료)', async () => {
  const L = await makeLogin();
  const r = await rp.verifyLogin(L);
  assert.equal(r.ok, true);
  assert.equal(r.tag.c1x, BigInt(L.publicSignals[11])); assert.equal(r.tag.c2, BigInt(L.publicSignals[13]));
});

await t('createRpVerifier 는 pkTrace 없이는 throw', () => {
  assert.throws(() => createRpVerifier({ provider, logAddress, vkey, pkCIA: CIA.pub, arid, chainId: 31337n }), /pkTrace/);
});

await t('음성 c\'\': max_height 가 head + L(400) 을 넘으면 bad_expiry — 지갑이 정한 만료의 상한 (2026-09-18 §3.2 갱신)', async () => {
  const L = await makeLogin({ ttlBlocks: 401n });
  const r = await rp.verifyLogin({ proof: L.proof, publicSignals: L.publicSignals, sig: L.sig, r_s: L.r_s });
  assert.equal(r.ok, false); assert.equal(r.reason, 'bad_expiry');
  const ok = await makeLogin({ ttlBlocks: 400n });
  assert.equal((await rp.verifyLogin({ proof: ok.proof, publicSignals: ok.publicSignals, sig: ok.sig, r_s: ok.r_s })).ok, true, '경계 head + L 은 통과');
});

await t('음성 c: head 가 max_height 를 넘으면 expired (블록 높이)', async () => {
  const L = await makeLogin({ ttlBlocks: 2n });
  await provider.send('hardhat_mine', ['0x3']);
  const r = await rp.verifyLogin({ proof: L.proof, publicSignals: L.publicSignals, sig: L.sig, r_s: L.r_s });
  assert.equal(r.ok, false); assert.equal(r.reason, 'expired');
});

await t('앞자리 0 이 붙은 10진 공개 입력도 통과하지만, 돌려주는 publicSignals 는 정규형이다 (개봉 재료 — 2026-09-18 점검 1)', async () => {
  const L = await makeLogin();
  const ps = [...L.publicSignals]; ps[1] = '0' + ps[1]; ps[11] = '00' + ps[11];
  const r = await rp.verifyLogin({ proof: L.proof, publicSignals: ps, sig: L.sig, r_s: L.r_s });
  assert.equal(r.ok, true, JSON.stringify(r, (k, v) => (typeof v === 'bigint' ? v.toString() : v)));
  assert.deepEqual(r.publicSignals, L.publicSignals, '기록·개봉에는 정규 문자열을 써야 CIA 의 문자열 비교·서명 재구성과 맞는다');
});

await t('음성: allowAgent 가 1 을 넘는 공개 입력은 bad_allow_agent (증명 검증 전에 걸린다)', async () => {
  const L = await makeLogin();
  const ps = [...L.publicSignals]; ps[5] = '2';
  const r = await rp.verifyLogin({ proof: L.proof, publicSignals: ps, sig: L.sig, r_s: L.r_s });
  assert.equal(r.ok, false); assert.equal(r.reason, 'bad_allow_agent');
});

await t("음성 c': 다른 chainid 로 발급된 credential 은 wrong_chain", async () => {
  const L = await makeLogin({ chainid: 1n });
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'wrong_chain' });
});

await t('음성 b: 폐기 게시 후 옛 root 의 π 는 stale_root', async () => {
  const L = await makeLogin();
  assert.equal((await rp.verifyLogin(L)).ok, true);
  await publish([await userLeaf(BigInt(L.cred.Cf_u))]);
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'stale_root' });
});

await t('음성 b′(C-1): 마지막 게시가 maxRootAge 블록보다 오래되면 root_too_old (온체인 RootTooOld 와 같은 상한, fail-closed)', async () => {
  const short = createRpVerifier({ provider, logAddress, vkey, pkCIA: CIA.pub, arid, chainId: 31337n, pkTrace: pk_trace, maxLifetimeBlocks: 400n, maxRootAge: 5n });
  await publish([]);   // 나이를 스스로 0 으로 만든다 — 앞 케이스의 게시에 기대지 않는다(2026-09-23 리뷰 M-1)
  const L = await makeLogin();
  assert.equal((await short.verifyLogin(L)).ok, true, '게시 직후에는 통과한다');
  await mineBlocks(6, provider);   // 게시 없이 6블록 → 나이 6 > 5
  const r = await short.verifyLogin({ ...L, sig: await signChallenge(L.session.wallet, L.r_s.toString()) });
  assert.equal(r.ok, false); assert.equal(r.reason, 'root_too_old');
  // 하트비트(같은 root, 새 epoch)를 게시하면 나이가 0 으로 돌아와 다시 통과한다.
  await publish([]);
  const again = await short.verifyLogin({ ...L, sig: await signChallenge(L.session.wallet, L.r_s.toString()) });
  assert.equal(again.ok, true, JSON.stringify(again, (k, v) => (typeof v === 'bigint' ? v.toString() : v)));
});

await t('음성 e: 증명을 손대면 bad_proof', async () => {
  const L = await makeLogin();
  const bad = JSON.parse(JSON.stringify(L.proof));
  bad.pi_a[0] = (BigInt(bad.pi_a[0]) + 1n).toString();
  assert.deepEqual(await rp.verifyLogin({ ...L, proof: bad }), { ok: false, reason: 'bad_proof' });
});

await t('음성 a: 체인을 못 읽고 캐시가 10분보다 오래되면 chain_unavailable (fail-closed)', async () => {
  let now = Date.now();
  const broken = { getBlockNumber: async () => { throw new Error('rpc down'); } };
  const rp2 = createRpVerifier({ provider: broken, logAddress, vkey, pkCIA: CIA.pub, arid, chainId: 31337n, pkTrace: pk_trace, now: () => now });
  const L = await makeLogin();
  assert.deepEqual(await rp2.verifyLogin(L), { ok: false, reason: 'chain_unavailable' });
});

await t('a: 캐시가 10분 안이면 RPC 가 죽어도 캐시로 검증한다', async () => {
  let now = Date.now();
  let alive = true;
  // ethers v6 provider 메서드는 private(#) 필드를 쓰므로 this 가 target 이 아니면(=Proxy 그
  // 자체면) "Receiver must be an instance of class AbstractProvider" 로 죽는다. 함수는
  // target 에 bind 해서 돌려준다 — destroy 등 다른 메서드는 그대로 target 메서드로 동작한다.
  const flaky = new Proxy(provider, { get: (tgt, k) => {
    if (k === 'getBlockNumber' && !alive) return async () => { throw new Error('rpc down'); };
    const v = tgt[k];
    return typeof v === 'function' ? v.bind(tgt) : v;
  } });
  const rp2 = createRpVerifier({ provider: flaky, logAddress, vkey, pkCIA: CIA.pub, arid, chainId: 31337n, pkTrace: pk_trace, now: () => now });
  const L = await makeLogin();
  assert.equal((await rp2.verifyLogin(L)).ok, true);
  alive = false; now += 5 * 60_000;
  assert.equal((await rp2.verifyLogin(L)).ok, true, '5분 된 캐시는 유효');
  now += 6 * 60_000;
  assert.deepEqual(await rp2.verifyLogin(L), { ok: false, reason: 'chain_unavailable' }, '11분이면 거절');
});

await t('같은 사용자·같은 RP 라도 chainid 가 다르면 PPID 가 다르다 (체인 간 unlinkability)', async () => {
  // 등록값(s_u)을 공유하는 두 로그인을 체인 31337 과 1 로 만든다. 두 번째는 이 RP(31337)에서 wrong_chain 이지만,
  // 여기서 보는 것은 공개 입력의 PPID 자체가 다르다는 사실이다 — 체인 1 의 RP 가 본 가명으로 체인 31337 의
  // 사용자를 특정할 수 없다.
  const reg = await createRegistration();
  const sk_u = Buffer.alloc(32, 3).toString('hex');
  const attrs = [0n, 0n, 0n, 0n];
  const uc = await buildUserCredRequest({ uid, s_u: reg.s_u, r_u: reg.r_u, sk_u, attrs });   // 사용자 자격증명은 체인과 무관 — 하나를 두 체인에 쓴다
  const ppids = [];
  for (const chainid of [31337n, 1n]) {
    const session = createSessionKey();
    const max_height = BigInt(await provider.getBlockNumber()) + 300n;
    const req = await buildIssueRequest({ uid, Cf_u: uc.Cf_u, arid, sk_u, session, chainid, max_height });
    const cred = await issueWith(CIA, uc.Cf_u, req.C_s_pt, { max_height, chainid });
    const { tree } = await syncRevocationTree(provider, logAddress);
    const { publicSignals } = await buildCredentialProof({ uid, arid, s_u: reg.s_u, blind_u: uc.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs, credential: cred, pk_CIA: CIA.pub, pk_trace, tree });
    ppids.push(BigInt(publicSignals[0]));
  }
  assert.notEqual(ppids[0], ppids[1]);
});

await t('C-2: maskDisclosure 는 mask 비트가 0 인 슬롯의 lo/hi 를 0 으로 지운다 (회로가 그 슬롯을 검증하지 않으므로 기록·표시하면 안 된다)', () => {
  const d = maskDisclosure({ mask: 1n, lo: [0n, 410n, 7n, 0n], hi: [2007n, 410n, 9n, 0n] });
  assert.deepEqual(d.lo, [0n, 0n, 0n, 0n]); assert.deepEqual(d.hi, [2007n, 0n, 0n, 0n]); assert.equal(d.mask, 1n);
  const e = maskDisclosure({ mask: 10n, lo: [1n, 2n, 3n, 4n], hi: [5n, 6n, 7n, 8n] });   // 비트 1·3
  assert.deepEqual(e.lo, [0n, 2n, 0n, 4n]); assert.deepEqual(e.hi, [0n, 6n, 0n, 8n]);
  // 길이 4 가 아니면 mask 비트와 슬롯이 어긋난다 — 공개 함수이므로 오용을 막는다(2026-09-23 리뷰 M-4)
  assert.throws(() => maskDisclosure({ mask: 1n, lo: [0n, 0n, 0n], hi: [0n, 0n, 0n, 0n] }), /길이 4/);
});

await t('C-2 E2E: 마스크 밖 슬롯이 0 이 아닌 **유효한** π 여도 verifyLogin 은 그 슬롯을 지워 돌려준다 (maskDisclosure 호출 고정)', async () => {
  // 회로는 mask 비트가 0 인 슬롯의 disc_lo/hi 에 64비트 범위 말고 아무 제약도 걸지 않는다(2026-09-22 §4.3). 지갑의
  // normalizeDisclosure 를 거치지 않고 buildCredentialProof 에 직접 넘기면 그런 π 가 실제로 만들어진다 — 즉 "실제 증명으로는
  // 재현 불가" 가 아니다(2026-09-23 최종 리뷰 M5). lib/mode3_rp.js 의 maskDisclosure 래핑을 벗기면 이 케이스가 빨개진다.
  const L = await makeLogin({ disclosure: { mask: 1n, lo: [0n, 410n, 0n, 0n], hi: [2007n, 410n, 0n, 0n] } });
  // 전제: 공개 입력에는 마스크 밖 슬롯(1)의 값이 그대로 실려 있다. [14]=mask, [15..18]=lo, [19..22]=hi
  assert.equal(BigInt(L.publicSignals[14]), 1n, 'mask 는 슬롯 0 만');
  assert.equal(BigInt(L.publicSignals[16]), 410n, 'lo[1] 이 0 이 아닌 π 여야 이 케이스가 의미가 있다');
  assert.equal(BigInt(L.publicSignals[20]), 410n, 'hi[1] 도 마찬가지');
  const r = await rp.verifyLogin(L);
  assert.equal(r.ok, true, JSON.stringify(r, (k, v) => (typeof v === 'bigint' ? v.toString() : v)));
  assert.equal(r.disclosure.mask, 1n);
  assert.equal(r.disclosure.lo[0], 0n); assert.equal(r.disclosure.hi[0], 2007n, '공개한 슬롯 0 은 그대로');
  assert.equal(r.disclosure.lo[1], 0n, '마스크 밖 슬롯 1 의 lo 는 지워야 한다 — AA 가 보증하지 않은 값이다');
  assert.equal(r.disclosure.hi[1], 0n, '마스크 밖 슬롯 1 의 hi 도 마찬가지');
});

// C-1(2026-09-25 전체 코드 리뷰 Critical): 정책 검사와 groth16.verify 가 **같은 값**을 봐야 한다.
// snarkjs 의 unstringifyBigInts 는 /^[0-9]+$/ 가 아닌 문자열을 BigInt 로 바꾸지 않고 그대로 두고,
// Scalar.toRprLE 가 그 문자열에 .toString(16) 을 불러 16진으로 파싱한다(실측: " 1"→0, " 2000"→0, "2007 "→8199).
// 그래서 정상 로그인 π(mask=0, lo=hi=0)에 " 1"·" 2000" 을 실으면 증명 검증은 원래 값 0 으로 통과하는데
// 서비스는 BigInt 로 1·2000 을 읽어 "출생연도 ≤ 2000 을 공개했다" 고 믿는다 — 나이·집합·allowAgent 술어가 통째로 위조된다.
await t('C-1: 정규 10진 문자열이 아닌 공개 입력은 malformed — 증명과 정책이 다른 값을 보지 못한다', async () => {
  const good = await makeLogin();
  assert.equal(good.publicSignals[14], '0', '전제: 로그인 π 의 disc_mask 는 0');
  assert.equal(good.publicSignals[19], '0', '전제: 로그인 π 의 disc_hi[0] 은 0');

  // 공격: 증명은 그대로 두고 공개 입력에 공백만 넣는다.
  const forged = [...good.publicSignals];
  forged[14] = ' 1';      // 서비스가 보면 mask = 1, 증명이 보증하는 값은 0
  forged[19] = ' 2000';   // 서비스가 보면 disc_hi[0] = 2000, 증명이 보증하는 값은 0
  assert.equal(BigInt(forged[14]), 1n); assert.equal(BigInt(forged[19]), 2000n);   // 서비스 쪽 파싱을 못 박는다
  const r = await rp.verifyLogin({ ...good, publicSignals: forged });
  assert.equal(r.ok, false, '공백 섞인 공개 입력이 통과하면 술어 위조가 된다');
  assert.equal(r.reason, 'malformed');

  // 같은 이유로 막아야 하는 다른 표기들(전부 BigInt 는 받아 주지만 snarkjs 와 어긋나거나 비정규형이다)
  for (const bad of [' 410', '410 ', '0x10', '', ' ', 0, 1n, null]) {
    const ps2 = [...good.publicSignals]; ps2[14] = bad;
    const v = await rp.verifyLogin({ ...good, publicSignals: ps2 });
    assert.equal(v.reason, 'malformed', `${JSON.stringify(String(bad))} 는 malformed 여야 한다`);
  }

  // 정상 입력은 그대로 통과한다(회귀 방지).
  assert.equal((await rp.verifyLogin(good)).ok, true);
});

provider.destroy();
process.exit(failed === 0 ? 0 : 1);
