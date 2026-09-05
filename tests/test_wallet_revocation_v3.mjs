// 지갑 쪽 v3 폐기 동기화가 IdP 응답만으로 올바른 witness를 만드는지 본다.
//   node tests/test_wallet_revocation_v3.mjs
//
// 격리 IdP를 띄워 실제 HTTP로 왕복한다. 전제: hardhat 노드.
//
// 무엇을 고정하는가:
//   1) 왕복      IdP 응답만으로 root·경로·witness가 나오고 스스로 검증을 통과한다
//   2) Case 2    타인 폐기 뒤에도 내 서브트리 root와 witness가 그대로다
//   3) Case 1    내가 폐기되면 witness 자체가 나오지 않는다
//   4) 자기검증  IdP가 어긋난 값을 주면 그대로 믿지 않고 던진다
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { leafValue, TAG_ACCOUNT } from '../lib/imt.js';
import { accountShardOf } from '../lib/imt_v3.js';
import { fetchRevocationWitnessesV3 } from '../lib/wallet_revocation_v3.js';
import { startIsolatedIdP } from './helpers/isolated_idp.mjs';

const uniqueValue = () => `${Date.now()}${Math.floor(Math.random() * 1e6)}`;
const MAX_HEIGHT = 100000n;

async function publish(idp) {
  const p = await idp.post('/idp/publish/prepare');
  assert.equal(p.status, 200, JSON.stringify(p.body));
  const c = await idp.post('/idp/publish/commit', { root: p.body.expectedRoot });
  assert.equal(c.status, 200, JSON.stringify(c.body));
}

async function main() {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-v3-'));
  const idp = await startIsolatedIdP({ dir: stateDir });
  try {
    const myAuid = uniqueValue();
    const myRToken = uniqueValue();
    const myAcctLeaf = (await leafValue(TAG_ACCOUNT, myAuid)).toString();
    const myShard = accountShardOf(myAcctLeaf);

    // ── 1) 왕복 ──────────────────────────────────────────────────────────
    const w0 = await fetchRevocationWitnessesV3(idp.base, myRToken, myAuid, MAX_HEIGHT);
    assert.equal(w0.acctShard, myShard);
    assert.ok(w0.sessSiblings.length === 12, `세션 상위 경로 길이 ${w0.sessSiblings.length} != 12`);
    assert.ok(w0.acctSiblings.length === 8, `계정 상위 경로 길이 ${w0.acctSiblings.length} != 8`);
    assert.ok(w0.sess.pathElements.length === 8 && w0.acct.pathElements.length === 10);
    assert.match(w0.topRoot, /^0x[0-9a-f]{64}$/);
    assert.equal(w0.needsBackfill, false);
    console.log(`OK: 1) IdP 응답만으로 witness/경로 생성 (계정 샤드 ${myShard})`);

    // ── 2) Case 2 — 타인 폐기 ────────────────────────────────────────────
    let other = null;
    for (let i = 0; i < 400; i++) {
      const v = uniqueValue();
      const leaf = (await leafValue(TAG_ACCOUNT, v)).toString();
      if (accountShardOf(leaf) !== myShard) { other = v; break; }
    }
    assert.ok(other, '다른 샤드에 떨어지는 값을 찾지 못했다');
    assert.equal((await idp.post('/idp/revoke', { type: 'account', value: other })).status, 200);
    await publish(idp);

    const w1 = await fetchRevocationWitnessesV3(idp.base, myRToken, myAuid, MAX_HEIGHT);
    assert.equal(w1.acctRoot, w0.acctRoot, '타인 폐기가 내 계정 서브트리 root를 바꿨다');
    assert.equal(w1.sessRoot, w0.sessRoot, '타인 폐기가 내 세션 서브트리 root를 바꿨다');
    assert.deepEqual(w1.acct, w0.acct, '타인 폐기가 내 witness를 바꿨다');
    assert.notEqual(w1.topRoot, w0.topRoot, 'top root는 바뀌어야 한다');
    assert.notDeepEqual(w1.acctSiblings, w0.acctSiblings, '상위 형제는 갱신돼야 한다');
    console.log('OK: 2) Case 2 — SNARK가 보는 값은 불변, 상위 형제만 갱신된다');

    // ── 3) Case 1 — 본인 폐기 ────────────────────────────────────────────
    assert.equal((await idp.post('/idp/revoke', { type: 'account', value: myAuid })).status, 200);
    await publish(idp);
    await assert.rejects(
      () => fetchRevocationWitnessesV3(idp.base, myRToken, myAuid, MAX_HEIGHT),
      /is a member of the revocation set/,
      '폐기된 계정에 대해 witness가 만들어졌다',
    );
    console.log('OK: 3) Case 1 — 폐기된 계정은 witness 자체가 나오지 않는다');

    // ── 4) 자기검증 — 어긋난 응답을 그대로 믿지 않는다 ───────────────────
    {
      const real = await (await fetch(`${idp.base}/idp/revocation_state_v3?accountShard=0&sessionShard=0`)).json();
      const tampered = { ...real, topRoot: '0x' + '11'.repeat(32) };
      const server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(tampered));
      });
      await new Promise((r) => server.listen(0, '127.0.0.1', r));
      const fakeBase = `http://127.0.0.1:${server.address().port}`;
      try {
        await assert.rejects(
          () => fetchRevocationWitnessesV3(fakeBase, uniqueValue(), uniqueValue(), MAX_HEIGHT),
          /combined root .* != IdP/,
          '어긋난 topRoot를 그대로 믿었다',
        );
      } finally {
        await new Promise((r) => server.close(r));
      }
      console.log('OK: 4) IdP가 어긋난 root를 줘도 그대로 믿지 않고 던진다');
    }

    console.log('\n== 지갑 v3 동기화 4종 통과 ==');
  } finally {
    await idp.stop();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
}

main().catch((err) => { console.error(err); process.exit(1); });
