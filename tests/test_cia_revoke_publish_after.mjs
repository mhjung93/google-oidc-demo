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
