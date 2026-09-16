// 승인된 개봉 — 격리 CIA + :8545 + build/mode3 (설계 2026-09-16 §6). (chain 그룹)
//   node tests/test_cia_opening.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { randomScalar } from '../lib/mode3_credential.js';
import { createRegistration, createSessionKey, buildIssueRequest, syncRevocationTree, buildCredentialProof, VKEY_PATH } from '../lib/mode3_wallet.js';
import { createShare, combinePublicKey, partialDecrypt } from '../lib/mode3_trace.js';
import { signOpenRequest, signOpenResult } from '../lib/mode3_opening.js';

const j = (o) => JSON.stringify(o, (_, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH}`);
const provider = getProvider();
const cia = await startIsolatedCia();
const uid = 12345n;
const nowTs = () => Math.floor(Date.now() / 1000).toString();

try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  const S1 = await cia.registerRp('http://127.0.0.1:3101', 's1');
  const S2 = await cia.registerRp('http://127.0.0.1:3102', 's2');

  // 사용자 등록·발급·증명(지갑 lib 그대로)
  const reg = await createRegistration();
  const r0 = await cia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: { x: reg.cm_u.x.toString(), y: reg.cm_u.y.toString() } });
  assert.equal(r0.status, 201, j(r0.body));
  const sk_u = r0.body.sk_u;
  async function loginTranscript(svc, pk_trace = svc.pk_trace) {
    const session = createSessionKey();
    const r_s = randomScalar();
    const req = await buildIssueRequest({ uid, arid: BigInt(svc.arid), s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n, attrs: [0n, 0n, 0n, 0n], r_s });
    const issued = await cia.post('/cia/issue', req.body);
    assert.equal(issued.status, 200, j(issued.body));
    const { tree } = await syncRevocationTree(provider, cia.logAddress);
    const { proof, publicSignals, tag } = await buildCredentialProof({ uid, arid: BigInt(svc.arid), s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, attrs: [0n, 0n, 0n, 0n], credential: issued.body, pk_CIA, pk_trace, tree });
    return { proof, publicSignals, tag, r_s: r_s.toString(), PPID: publicSignals[0] };
  }
  async function openRequest(svc, T, { share = svc.share, wallet = svc.serviceWallet, ts = nowTs(), arid = svc.arid } = {}) {
    const D = await partialDecrypt(share.x, T.tag.c1);
    const D_svc = { x: D.x.toString(), y: D.y.toString() };
    const sig = await signOpenRequest(wallet, { arid, r_s: T.r_s, PPID: T.PPID, D_svc, ts });
    return cia.post('/cia/open/request', { arid, publicSignals: T.publicSignals, proof: T.proof, D_svc, ts, sig });
  }
  async function fetchResult(svc, id, { wallet = svc.serviceWallet, ts = nowTs() } = {}) {
    const sig = await signOpenResult(wallet, id, ts);
    return cia.get(`/cia/open/${id}?ts=${ts}&sig=${encodeURIComponent(sig)}`);
  }

  let T1, id1;
  await t('정상 경로: 요청 202 pending(uid 없음) → 승인 → 결과 200 에 uid', async () => {
    T1 = await loginTranscript(S1);
    const r = await openRequest(S1, T1);
    assert.equal(r.status, 202, j(r.body)); assert.equal(r.body.status, 'pending'); id1 = r.body.id;
    const list = (await cia.adminGet('/cia/openings')).body.openings;
    const mine = list.find((o) => o.id === id1);
    assert.equal(mine.status, 'pending'); assert.equal(mine.uid, undefined, '승인 전에는 uid 가 계산되지 않는다');
    assert.equal((await fetchResult(S1, id1)).status, 202);
    const a = await cia.adminPost(`/cia/openings/${id1}/approve`);
    assert.equal(a.status, 200, j(a.body)); assert.equal(a.body.status, 'approved');
    const res = await fetchResult(S1, id1);
    assert.equal(res.status, 200, j(res.body)); assert.equal(res.body.uid, '12345'); assert.equal(res.body.PPID, T1.PPID); assert.equal(res.body.r_s, T1.r_s);
    assert.equal((await cia.adminGet('/cia/openings')).body.openings.find((o) => o.id === id1).uid, '12345', '감사 기록에 uid');
  });

  await t('같은 (arid, r_s) 재요청은 새 id 를 만들지 않는다 (200, 같은 id)', async () => {
    const r = await openRequest(S1, T1);
    assert.equal(r.status, 200); assert.equal(r.body.id, id1);
  });

  await t('거절 → 결과 403 denied', async () => {
    const T = await loginTranscript(S1);
    const { body: { id } } = await openRequest(S1, T);
    assert.equal((await cia.adminPost(`/cia/openings/${id}/deny`)).status, 200);
    const res = await fetchResult(S1, id);
    assert.equal(res.status, 403); assert.equal(res.body.status, 'denied');
    assert.equal((await cia.adminPost(`/cia/openings/${id}/approve`)).status, 409, '결정된 항목은 다시 결정할 수 없다');
    // denied 는 재요청을 막지 않는다 — 새 id 로 다시 심사에 올릴 수 있다.
    const r2 = await openRequest(S1, T);
    assert.equal(r2.status, 202, JSON.stringify(r2.body)); assert.notEqual(r2.body.id, id);
    assert.equal((await cia.adminPost(`/cia/openings/${r2.body.id}/deny`)).status, 200);
  });

  await t('틀린 D_svc(다른 조각) → 승인 시 failed, 결과 403', async () => {
    const T = await loginTranscript(S1);
    const { body: { id } } = await openRequest(S1, T, { share: await createShare() });
    const a = await cia.adminPost(`/cia/openings/${id}/approve`);
    assert.equal(a.status, 200); assert.equal(a.body.status, 'failed');
    assert.equal((await fetchResult(S1, id)).status, 403);
    // failed 는 재요청을 막지 않는다 — 맞는 조각으로 다시 내면 새 id 로 승인·개봉된다.
    const r2 = await openRequest(S1, T);
    assert.equal(r2.status, 202, JSON.stringify(r2.body)); assert.notEqual(r2.body.id, id);
    const a2 = await cia.adminPost(`/cia/openings/${r2.body.id}/approve`);
    assert.equal(a2.status, 200, JSON.stringify(a2.body)); assert.equal(a2.body.status, 'approved');
    const res2 = await fetchResult(S1, r2.body.id);
    assert.equal(res2.status, 200, JSON.stringify(res2.body)); assert.equal(res2.body.uid, '12345');
  });

  await t('남의 트랜스크립트: S2 가 S1 의 세션을 열려 하면 wrong_arid 403 (유출된 로그로는 못 연다)', async () => {
    const r = await openRequest(S2, T1, { share: S2.share, wallet: S2.serviceWallet, arid: S2.arid });
    assert.equal(r.status, 403); assert.equal(r.body.error, 'wrong_arid');
  });

  await t('자기 arid 로 남의 조합 키 태그: wrong_trace_key 403', async () => {
    const fake = await combinePublicKey((await createShare()).X, (await createShare()).X);
    const T = await loginTranscript(S1, fake);
    const r = await openRequest(S1, T);
    assert.equal(r.status, 403); assert.equal(r.body.error, 'wrong_trace_key');
  });

  await t('서명·신선도·형식: 다른 키 서명 401, 오래된 ts 401, 손댄 증명 403, 승인 안 된 서비스 403, 미등록 arid 404', async () => {
    const T = await loginTranscript(S1);
    assert.equal((await openRequest(S1, T, { wallet: ethers.Wallet.createRandom() })).body.error, 'bad_signature');
    const stale = await openRequest(S1, T, { ts: (Number(nowTs()) - 600).toString() });
    assert.equal(stale.status, 401); assert.equal(stale.body.error, 'stale');
    const bad = JSON.parse(JSON.stringify(T.proof)); bad.pi_a[0] = (BigInt(bad.pi_a[0]) + 1n).toString();
    const r = await openRequest(S1, { ...T, proof: bad });
    assert.equal(r.status, 403); assert.equal(r.body.error, 'bad_proof');
    // 승인 안 된 서비스: 직접 pending 으로 등록만
    const w = ethers.Wallet.createRandom(); const share = await createShare();
    const p = await cia.post('/cia/register_rp', { name: 's3', origin: 'http://127.0.0.1:3103', pk_service: w.address, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() } });
    assert.equal(p.status, 202);
    const na = await openRequest(S1, T, { wallet: w, share, arid: p.body.arid });
    assert.equal(na.status, 403); assert.equal(na.body.error, 'not_approved');
    assert.equal((await openRequest(S1, T, { arid: '999' })).status, 404);
  });

  await t('결과 수령: 다른 서비스의 서명이면 401, 오래된 ts 401, 없는 id 404', async () => {
    assert.equal((await fetchResult(S1, id1, { wallet: S2.serviceWallet })).status, 401);
    assert.equal((await fetchResult(S1, id1, { ts: (Number(nowTs()) - 600).toString() })).status, 401);
    assert.equal((await fetchResult(S1, 'deadbeef')).status, 404);
  });

  await t('admin 엔드포인트는 시크릿 없이 401', async () => {
    assert.equal((await cia.get('/cia/openings')).status, 401);
    assert.equal((await cia.post(`/cia/openings/${id1}/approve`)).status, 401);
  });
} finally {
  await cia.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
