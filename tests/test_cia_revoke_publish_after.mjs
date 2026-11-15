// 시연(2026-11-12 Race (2)): CIA_REVOKE_PUBLISH_AFTER_BLOCKS — pk_i 를 실은 세션 폐기를 받은 뒤 그 세션 체인의 블록이 N 개
// 지나면 IdP 가 스스로 게시하고 거울로 중계한다. 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_revoke_publish_after.mjs
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { MODE3_MIRROR_ABI } from '../lib/mode3_log.js';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { randomScalar } from '../lib/mode3_credential.js';
import { signRevokeBind } from '../lib/mode3_revocation.js';
import { issueV11, userOf, revokeSessionBody, TESTUSER_ATTRS } from './helpers/mode3_flow.mjs';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const mine = async (n) => { for (let i = 0; i < n; i++) await provider.send('evm_mine', []); };

const provider = getProvider();
const cia = await startIsolatedCia({ env: { CIA_REVOKE_PUBLISH_AFTER_BLOCKS: '3' } });
const arid = 22222222222222222222n;
const uid = 12345n;

try {
  const user = userOf(await cia.registerUser('12345', 'password123'), '12345', TESTUSER_ATTRS);
  const mirrorC = new ethers.Contract(cia.mirrorAddress, MODE3_MIRROR_ABI, provider);
  const revokeWithBind = async (iss, bound) => {
    const Cf_s = iss.cred.Cf_s, nonce = randomScalar();
    return cia.post('/cia/revoke', {
      ...(await revokeSessionBody(user, { Cf_s, bound, nonce })),
      pk_i: iss.session.pk_i.toString(), sig_i: await signRevokeBind(iss.session.wallet.privateKey, { uid, Cf_s, bound, nonce }),
    });
  };

  await t('pk_i 를 실은 세션 폐기 → 2블록 뒤에는 거울이 비어 있고, 3블록째에 IdP 가 스스로 게시·중계해 거울 counter = bound+1', async () => {
    const iss = await issueV11(cia, user, { arid, provider });
    assert.equal(iss.r.status, 200, j(iss.r.body));
    const pk = BigInt(iss.session.pk_i);
    const r = await revokeWithBind(iss, 1n);
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.mirrorBound, true);
    await mine(2);
    await sleep(1500);   // 감시가 돌 시간을 충분히 준다 — 그래도 게시하면 안 된다
    assert.equal(await mirrorC.sessionBoundOf(pk), 0n, '2블록 뒤: 아직 거울 반영 전');
    await mine(1);
    let got = 0n;
    for (let i = 0; i < 40 && got === 0n; i++) { await sleep(250); got = await mirrorC.sessionBoundOf(pk); }
    assert.equal(got, 2n, '3블록 뒤: 거울 counter = c + 1');
  });

  // 2026-11-15(시연자 화면 리뷰): 먼저 한 세션 폐기를 관리자가 "게시" 로 올린 뒤에도 그 폐기의 예약이 남아, 3블록째에 **뒤에 온** 폐기까지
  // 게시했다 — 시연 순서(세션 폐기 → 게시 → Race (2) 2블록)에서 "2블록 뒤 보내기" 가 통과 대신 막혔다. 이미 실린 폐기의 예약은 아무것도 올리지 않는다.
  await t('앞선 폐기를 관리자가 이미 게시했으면, 그 예약은 뒤에 온 폐기를 앞당겨 게시하지 않는다', async () => {
    const issA = await issueV11(cia, user, { arid, provider });
    assert.equal(issA.r.status, 200, j(issA.r.body));
    const rA = await revokeWithBind(issA, 1n);
    assert.equal(rA.status, 200, j(rA.body));
    const headA = await provider.getBlockNumber();
    const pub = await cia.adminPost('/cia/publish', {});
    assert.equal(pub.status, 200, j(pub.body)); assert.equal(pub.body.published, true, j(pub.body));
    const pendingCount = async () => (await cia.adminGet('/cia/state')).body.pendingCount;
    assert.equal(await pendingCount(), 0, '관리자 게시로 앞선 폐기가 실렸다(대기 0)');
    const issB = await issueV11(cia, user, { arid, provider });
    assert.equal(issB.r.status, 200, j(issB.r.body));
    const pkB = BigInt(issB.session.pk_i);
    const rB = await revokeWithBind(issB, 1n);
    assert.equal(rB.status, 200, j(rB.body));
    const headB = await provider.getBlockNumber();
    const left = 3 - (headB - headA);   // 앞선 폐기의 예약이 닿을 때까지 남은 블록
    assert.ok(left >= 1 && left <= 2, `이 각본은 앞선 예약이 아직 살아 있고(남은 블록 ≥ 1) 뒤 폐기의 3블록보다 먼저 닿아야 한다(≤ 2) — 남은 블록 ${left} (headA=${headA}, headB=${headB})`);
    await mine(left);
    await sleep(2000);   // 앞선 예약이 돌 시간
    assert.equal(await pendingCount(), 1, `앞선 폐기의 3블록째(뒤 폐기로는 ${left}블록째): 뒤 폐기는 아직 게시 대기여야 한다`);
    assert.equal(await mirrorC.sessionBoundOf(pkB), 0n, '뒤 폐기는 아직 거울 반영 전이다');
    await mine(3 - left);
    let gotB = 0n;
    for (let i = 0; i < 40 && gotB === 0n; i++) { await sleep(250); gotB = await mirrorC.sessionBoundOf(pkB); }
    assert.equal(gotB, 2n, '뒤 폐기는 자기 3블록째에 게시된다');
  });

  await t('pk_i 없는 폐기(관리자)는 자동 게시를 걸지 않는다', async () => {
    const iss = await issueV11(cia, user, { arid, provider });
    assert.equal(iss.r.status, 200, j(iss.r.body));
    const before = (await cia.adminGet('/cia/state')).body.pendingCount;
    const r = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: iss.cred.Cf_s, bound: '0' });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.mirrorBound, false);
    await mine(4);
    await sleep(1500);
    assert.equal((await cia.adminGet('/cia/state')).body.pendingCount, before + 1, '게시되지 않고 대기열에 남는다');
  });
} finally {
  await cia.stop();
  provider.destroy();
}

process.exit(failed === 0 ? 0 : 1);
