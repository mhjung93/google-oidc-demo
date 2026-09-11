// RP 검증기 — §6.3 7단계와 음성 6건. :8545 + build/mode3 필요. (chain 그룹)
//   node tests/test_mode3_rp.mjs
// hardhat_mine 으로 :8545 블록을 진행시킨다 (기존 chain 그룹과 같은 성질).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { getProvider, fundAddress, deployRevocationLog, signRootPublication, rootToBytes32, mineBlocks } from './helpers/mode3_chain.mjs';
import { credLeaf, createRevocationTree } from '../lib/mode3_revocation.js';
import { credMessage, compressPoint } from '../lib/mode3_credential.js';
import { pointFromStrings } from '../lib/mode3_issuance.js';
import { createRegistration, createSessionKey, buildIssueRequest, syncRevocationTree, buildCredentialProof, signChallenge, VKEY_PATH } from '../lib/mode3_wallet.js';
import { createRpVerifier } from '../lib/mode3_rp.js';

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

async function issueWith(key, C_pt, ttl = 300n) {
  const C = await compressPoint(C_pt);
  const max_height = BigInt(await provider.getBlockNumber()) + ttl;
  const s = eddsa.signPoseidon(key.prv, F.e(await credMessage(C, max_height)));
  return { C: C.toString(), max_height: max_height.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
async function publish(leavesBig) {
  const { tree } = await syncRevocationTree(provider, logAddress);
  for (const l of leavesBig) await tree.insert(l);
  const root = rootToBytes32(tree.getRoot()), epoch = (await log.epoch()) + 1n, leaves = leavesBig.map(rootToBytes32);
  await (await log.connect(ciaEth).publishRoot(root, epoch, leaves, await signRootPublication(ciaEth, { logAddress, root, epoch, leaves }))).wait();
}
async function makeLogin({ key = CIA, useArid = arid, ttl = 300n } = {}) {
  const reg = await createRegistration();
  const session = createSessionKey();
  const req = await buildIssueRequest({ uid, arid: useArid, s_u: reg.s_u, r_u: reg.r_u, sk_u: Buffer.alloc(32, 3).toString('hex'), session, height: BigInt(await provider.getBlockNumber()) });
  const cred = await issueWith(key, pointFromStrings(req.body.C_pt), ttl);
  const { tree } = await syncRevocationTree(provider, logAddress);
  const { proof, publicSignals } = await buildCredentialProof({ uid, arid: useArid, s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, credential: cred, pk_CIA: key.pub, tree });
  const challenge = 'rp-challenge-' + Math.random();
  return { proof, publicSignals, challenge, sig: await signChallenge(session.wallet, challenge), session, cred, reg };
}

const rp = createRpVerifier({ provider, logAddress, vkey, pkCIA: CIA.pub, arid });

await t('양성: 7단계 전부 통과, PPID 와 pk_i 를 돌려준다', async () => {
  const L = await makeLogin();
  const r = await rp.verifyLogin(L);
  assert.equal(r.ok, true, JSON.stringify(r, (_, v) => (typeof v === 'bigint' ? v.toString() : v)));
  assert.equal(r.PPID, BigInt(L.publicSignals[0]));
  assert.equal(r.pk_i, L.session.pk_i);
});

await t('음성 d: 공격자가 자기 CIA 키로 서명한 credential 은 untrusted_cia (유일한 위조 방어선)', async () => {
  const L = await makeLogin({ key: ATTACKER });
  const r = await rp.verifyLogin(L);
  assert.deepEqual(r, { ok: false, reason: 'untrusted_cia' });
});

await t('음성 f: 챌린지 서명이 다른 키면 bad_signature', async () => {
  const L = await makeLogin();
  L.sig = await signChallenge(ethers.Wallet.createRandom(), L.challenge);
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'bad_signature' });
});

await t('음성 f: 다른 챌린지에 대한 서명 재생은 bad_signature', async () => {
  const L = await makeLogin();
  assert.deepEqual(await rp.verifyLogin({ ...L, challenge: 'other' }), { ok: false, reason: 'bad_signature' });
});

await t('음성 arid: 다른 RP 용 credential 은 wrong_arid', async () => {
  const L = await makeLogin({ useArid: otherArid });
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'wrong_arid' });
});

await t('음성 c: max_height 를 지나면 expired', async () => {
  const L = await makeLogin({ ttl: 5n });
  await mineBlocks(10, provider);
  rp.refreshChainView && await rp.refreshChainView();
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'expired' });
});

await t('음성 b: 폐기 게시 후 옛 root 의 π 는 stale_root', async () => {
  const L = await makeLogin();
  assert.equal((await rp.verifyLogin(L)).ok, true);
  await publish([await credLeaf(BigInt(L.cred.C))]);
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'stale_root' });
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
  const rp2 = createRpVerifier({ provider: broken, logAddress, vkey, pkCIA: CIA.pub, arid, now: () => now });
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
  const rp2 = createRpVerifier({ provider: flaky, logAddress, vkey, pkCIA: CIA.pub, arid, now: () => now });
  const L = await makeLogin();
  assert.equal((await rp2.verifyLogin(L)).ok, true);
  alive = false; now += 5 * 60_000;
  assert.equal((await rp2.verifyLogin(L)).ok, true, '5분 된 캐시는 유효');
  now += 6 * 60_000;
  assert.deepEqual(await rp2.verifyLogin(L), { ok: false, reason: 'chain_unavailable' }, '11분이면 거절');
});

provider.destroy();
process.exit(failed === 0 ? 0 : 1);
