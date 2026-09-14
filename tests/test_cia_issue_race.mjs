// /cia/issue 와 /cia/revoke 의 경합 — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_issue_race.mjs
//
// /cia/issue 는 disabled·서명·π_issue·같은 C 를 검사한 뒤 기록 직전에 chainAlive() 로 eth_blockNumber 를
// 한 번 불러 체인 가용성만 본다(값은 쓰지 않는다). 그 await 동안 관리자가 계정을 폐기하면 폐기 직후의
// 발급이 살아남아, 트리에 없는 새 credential 이 TTL 동안 유효하다. 결정적으로 재현하기 위해 CIA 의 RPC
// 앞에 eth_blockNumber 응답을 붙잡는 게이트 프록시를 둔다 — 요청이 게이트에 닿은 것을 Promise 로 알고,
// 게이트를 내린 뒤 revoke 를 끝까지 보내고 나서 응답을 풀어 준다. 벽시계 대기가 없다.
// (CIA 의 provider 는 cacheTimeout:-1 이라 revoke 의 headHeight() 조회가 붙잡힌 issue 의 chainAlive() 조회에
// 합류하지 않는다 — 게이트가 내려간 뒤의 조회이므로 그대로 통과한다.)
import assert from 'node:assert/strict';
import http from 'node:http';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { randomScalar } from '../lib/mode3_credential.js';
import { registrationCommit, proveIssuance, serializeProof, pointToStrings } from '../lib/mode3_issuance.js';
import { signUserRequest } from '../lib/mode3_wallet.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}
function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

// ---- eth_blockNumber 응답을 게이트로 붙잡는 JSON-RPC 프록시 (이 프로세스 안, 변수로 제어) ----
// hold = { seen, released }: eth_blockNumber 가 오면 seen 을 resolve 하고 released 가 풀릴 때까지 기다린다.
const UPSTREAM = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
let hold = null;
const proxy = http.createServer(async (req, res) => {
  let body = '';
  for await (const c of req) body += c;
  let gate = null;
  try {
    const j = JSON.parse(body);
    const methods = (Array.isArray(j) ? j : [j]).map((x) => x.method);
    if (methods.includes('eth_blockNumber') && hold) gate = hold;
  } catch { /* 형식 무관 — 그대로 전달 */ }
  if (gate) { gate.seen.resolve(); await gate.released.promise; }
  const up = await fetch(UPSTREAM, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
  res.writeHead(up.status, { 'content-type': 'application/json' });
  res.end(await up.text());
});
await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;

const uid = 12345n, arid = 22222222222222222222n;
const pk_i = BigInt(ethers.Wallet.createRandom().address);

const cia = await startIsolatedCia({ env: { CIA_RPC_URL: proxyUrl } });
try {
  const s_u = randomScalar(), r_u = randomScalar();
  const reg = await cia.post('/cia/register', { uid: uid.toString(), pwd: 'password123', cm_u: pointToStrings(await registrationCommit(s_u, r_u)) });
  assert.equal(reg.status, 201, JSON.stringify(reg.body));
  const sk_u = reg.body.sk_u;

  async function issueBody() {
    const blind = randomScalar(), nonce = randomScalar();
    const { C_pt, proof } = await proveIssuance({ uid, arid, s_u, blind, pk_i, r_u, attrs: [0n, 0n, 0n, 0n] });
    return { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u: await signUserRequest(sk_u, C_pt, 31337n, nonce), chainid: '31337', nonce: nonce.toString() };
  }

  await t('issue 가 체인 가용성을 확인하는 동안 계정이 폐기되면 발급하지 않는다 (403, 기록도 남지 않는다)', async () => {
    const body = await issueBody();
    hold = { seen: deferred(), released: deferred() };
    const inflight = cia.post('/cia/issue', body);   // 검증을 지나 chainAlive() 의 eth_blockNumber 에서 게이트에 붙잡힌다
    await hold.seen.promise;
    const gate = hold;
    hold = null;                                      // 이후의 eth_blockNumber(revoke 의 것)는 그대로 통과
    const rv = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' });
    assert.equal(rv.status, 200, JSON.stringify(rv.body));
    gate.released.resolve();
    const r = await inflight;
    assert.equal(r.status, 403, `폐기 뒤에 발급이 살아남았다: ${JSON.stringify(r.body)}`);
    // 기록도 남지 않았어야 한다 — 복구 후 같은 요청을 다시 내면 409(이미 발급) 가 아니라 200 이어야 한다
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    const again = await cia.post('/cia/issue', body);
    assert.equal(again.status, 200, JSON.stringify(again.body));
  });

  await t('프록시 경유 정상 발급 (게이트 없음)', async () => {
    const r = await cia.post('/cia/issue', await issueBody());
    assert.equal(r.status, 200, JSON.stringify(r.body));
  });
} finally {
  await cia.stop();
  proxy.close();
}
process.exit(failed === 0 ? 0 : 1);
