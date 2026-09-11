// /cia/issue 와 /cia/revoke 의 경합 — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_issue_race.mjs
//
// /cia/issue 는 disabled 를 검사한 뒤 head 를 RPC 로 읽는다. 그 await 동안 관리자가 계정을 폐기하면
// 폐기 직후의 발급이 살아남아, 트리에 없는 새 credential 이 TTL 동안 유효하다. 결정적으로 재현하기
// 위해 CIA 의 RPC 앞에 eth_blockNumber 만 지연시키는 프록시를 두고, 그 사이에 revoke 를 끼워 넣는다.
import assert from 'node:assert/strict';
import http from 'node:http';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { randomScalar } from '../lib/mode3_credential.js';
import { registrationCommit, proveIssuance, serializeProof, pointToStrings } from '../lib/mode3_issuance.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- eth_blockNumber 만 delayMs 만큼 늦추는 JSON-RPC 프록시 (이 프로세스 안, 변수로 제어) ----
const UPSTREAM = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
let delayMs = 0;
const proxy = http.createServer(async (req, res) => {
  let body = '';
  for await (const c of req) body += c;
  let wait = 0;
  try {
    const j = JSON.parse(body);
    const methods = (Array.isArray(j) ? j : [j]).map((x) => x.method);
    if (methods.includes('eth_blockNumber')) wait = delayMs;
  } catch { /* 형식 무관 — 그대로 전달 */ }
  if (wait) await sleep(wait);
  const up = await fetch(UPSTREAM, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
  res.writeHead(up.status, { 'content-type': 'application/json' });
  res.end(await up.text());
});
await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;

const eddsa = await buildEddsa();
const poseidon = await buildPoseidon();
const F = poseidon.F;
const uid = 12345n, arid = 22222222222222222222n;
const pk_i = BigInt(ethers.Wallet.createRandom().address);

const cia = await startIsolatedCia({ env: { CIA_RPC_URL: proxyUrl } });
try {
  const s_u = randomScalar(), r_u = randomScalar();
  const reg = await cia.post('/cia/register', { uid: uid.toString(), pwd: 'password123', cm_u: pointToStrings(await registrationCommit(s_u, r_u)) });
  assert.equal(reg.status, 201, JSON.stringify(reg.body));
  const sk_u = Buffer.from(reg.body.sk_u, 'hex');

  async function issueBody() {
    const blind = randomScalar();
    const { C_pt, proof } = await proveIssuance({ uid, arid, s_u, blind, pk_i, r_u });
    const height = BigInt((await cia.get('/cia/state')).body.head);
    const s = eddsa.signPoseidon(sk_u, F.e(F.toObject(poseidon([C_pt.x, C_pt.y, height]))));
    const sig_u = { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() };
    return { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u, height: height.toString() };
  }

  await t('프록시 경유 정상 발급', async () => {
    const r = await cia.post('/cia/issue', await issueBody());
    assert.equal(r.status, 200, JSON.stringify(r.body));
  });

  await t('issue 가 head 를 읽는 동안 계정이 폐기되면 발급하지 않는다 (403, 기록도 남지 않는다)', async () => {
    const body = await issueBody();
    // issueBody 가 /cia/state 로 head 를 읽게 했고, CIA 의 ethers provider 는 getBlockNumber 를 250 ms 캐시한다.
    // 캐시가 식은 뒤에 보내야 발급 요청의 head 조회가 실제 RPC(=프록시 지연)를 탄다.
    await sleep(400);
    delayMs = 3000;
    const inflight = cia.post('/cia/issue', body);   // 서명·π_issue 검증을 지나 headHeight() 에서 멈춘다
    await sleep(700);
    delayMs = 0;
    const rv = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' });
    assert.equal(rv.status, 200, JSON.stringify(rv.body));
    const r = await inflight;
    assert.equal(r.status, 403, `폐기 뒤에 발급이 살아남았다: ${JSON.stringify(r.body)}`);
    // 기록도 남지 않았어야 한다 — 복구 후 같은 요청을 다시 내면 409(이미 발급) 가 아니라 200 이어야 한다
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    const again = await cia.post('/cia/issue', body);
    assert.equal(again.status, 200, JSON.stringify(again.body));
  });
} finally {
  await cia.stop();
  proxy.close();
}
process.exit(failed === 0 ? 0 : 1);
