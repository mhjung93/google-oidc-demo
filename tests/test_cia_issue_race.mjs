// /cia/issue 와 /cia/revoke 의 경합 — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_issue_race.mjs
//
// /cia/issue(V11) 는 disabled·chainid 허용·부분군·서명·π_IdP 를 검사한 뒤 서명 직전에 chainAlive() 로 eth_blockNumber 를
// 한 번 불러 체인 가용성만 본다(값은 쓰지 않는다). 그 await 동안 관리자가 계정을 폐기하면 폐기 직후의
// 발급이 살아남아, 물린 자격증명 위에 새 세션이 max_height 까지 유효하다. 결정적으로 재현하기 위해 CIA 의 RPC
// 앞에 eth_blockNumber 응답을 붙잡는 게이트 프록시를 둔다 — 요청이 게이트에 닿은 것을 Promise 로 알고,
// 게이트를 내린 뒤 revoke 를 끝까지 보내고 나서 응답을 풀어 준다. 벽시계 대기가 없다.
// (CIA 의 provider 는 cacheTimeout:-1 이라 revoke 의 headHeight() 조회가 붙잡힌 issue 의 chainAlive() 조회에
// 합류하지 않는다 — 게이트가 내려간 뒤의 조회이므로 그대로 통과한다.)
import assert from 'node:assert/strict';
import http from 'node:http';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { registryLeaf } from '../lib/mode3_registry.js';
import { randomScalar } from '../lib/mode3_credential.js';
import { issueV11, userOf, TESTUSER_ATTRS } from './helpers/mode3_flow.mjs';

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
const provider = new ethers.JsonRpcProvider(UPSTREAM);   // 테스트의 헤드 조회는 프록시(게이트)를 거치지 않는다
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

const arid = 22222222222222222222n;

// isolated_cia 가 V10 Task 4 부터 CIA_CHAIN_RPCS 를 :8545 직결로 기본 설정하므로, /cia/issue 의 headOf() 도 게이트 프록시를 타게 덮어쓴다.
const cia = await startIsolatedCia({ env: { CIA_RPC_URL: proxyUrl, CIA_CHAIN_RPCS: '31337=' + proxyUrl } });
try {
  const u = userOf(await cia.registerUser('12345', 'password123'), '12345', TESTUSER_ATTRS);

  /** issueV11 의 얇은 포장 — 이 파일의 케이스가 자주 쓰는 모양(이 CIA·이 서비스·이 사용자, 기본값은 새 C_u). */
  const issue = (opts = {}) => issueV11(cia, u, { arid, provider, ...opts });

  await t('issue 동시 요청 둘(같은 uid, 다른 blind_u): 둘 다 200, 활성 자격증명은 하나, 슬롯은 승자의 리프로 수렴; 패자의 blind_u 로 다시 발급하면 409 cred_revoked', async () => {
    const first = await issue();
    assert.equal(first.r.status, 200, JSON.stringify(first.r.body));
    const before = (await cia.get('/cia/state')).body;
    assert.equal(before.credCount, 1);
    const [a, b] = await Promise.all([issue({ blind_u: undefined }), issue({ blind_u: undefined })]);
    assert.equal(a.r.status, 200, JSON.stringify(a.r.body)); assert.equal(b.r.status, 200, JSON.stringify(b.r.body));
    const after = (await cia.get('/cia/state')).body;
    assert.equal(after.credCount, 1, '활성 자격증명은 하나여야 한다');
    // V9: 교체는 등록부 슬롯만 바꾸고(폐기 트리는 건드리지 않는다) — 두 승자 후보(a·b) 중 나중에 물린 쪽의
    // Cf_u 로 등록부 슬롯·activeCf_u 가 함께 수렴해야 한다.
    const acct = (await cia.adminGet('/cia/accounts')).body.accounts.find((x) => x.uid === '12345');
    assert.ok([a.cred.Cf_u, b.cred.Cf_u].includes(acct.activeCf_u), `activeCf_u(${acct.activeCf_u}) 는 a·b 중 하나여야 한다`);
    assert.equal(acct.registryLeaf, String(await registryLeaf(u.auid, BigInt(acct.activeCf_u))));
    // 패자(활성이 아닌 쪽)의 blind_u 로 다시 발급하면 그 C_u 는 이미 물린 적이 있어 409 cred_revoked
    const loser = a.cred.Cf_u === acct.activeCf_u ? b : a;
    const again = await issue({ blind_u: loser.blind_u });
    assert.equal(again.r.status, 409, JSON.stringify(again.r.body)); assert.equal(again.r.body.reason, 'cred_revoked');
  });

  await t('issue 와 revoke(account) 동시 요청: 어느 쪽이 먼저든 disabled 계정에 활성 자격증명이 남지 않는다', async () => {
    // issue 가 retireActiveCred 의 await 에 있는 동안 revoke 가 disabled 를 걸 수 있다 — 마지막 await 뒤 disabled 재확인이
    // 없으면 disabled 계정에 새 활성 자격증명이 올라간다. 둘 다 체인을 부르지 않아 게이트로 순서를 강제할 수는 없다 — 두 순서
    // 모두에서 성립해야 하는 불변식(credCount 0, 이후 issue 403 'account disabled')을 본다.
    const before = (await cia.get('/cia/state')).body;
    assert.equal(before.credCount, 1, '앞 케이스가 활성 자격증명 하나를 남겨 둔다');
    const [uc, rv] = await Promise.all([issue(), cia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' })]);
    assert.equal(rv.status, 200, JSON.stringify(rv.body));
    assert.ok(uc.r.status === 200 || uc.r.status === 403, JSON.stringify(uc.r.body));
    const after = (await cia.get('/cia/state')).body;
    assert.equal(after.credCount, 0, 'disabled 계정에 활성 자격증명이 남았다');
    // V9: issue 교체·revoke(account) 모두 등록부 슬롯만 바꾸고 폐기 트리는 건드리지 않는다 — 어느 쪽이
    // 이기든 슬롯은 0 으로 수렴해야 한다(교체가 이기면 새 자격증명이 바로 뒤이어 revoke 에 물려 슬롯이 다시 0 이 된다).
    const acct = (await cia.adminGet('/cia/accounts')).body.accounts.find((x) => x.uid === '12345');
    assert.equal(acct.registryLeaf, '0');
    const denied = await issue();
    assert.equal(denied.r.status, 403); assert.equal(denied.r.body.error, 'account disabled');
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: '12345', disabled: false })).status, 200);   // 뒤 케이스용 복구
  });

  await t('issue 가 체인 가용성을 확인하는 동안 계정이 폐기되면 발급하지 않는다 (403, 활성 자격증명도 0)', async () => {
    const first = await issue();
    assert.equal(first.r.status, 200, JSON.stringify(first.r.body));
    hold = { seen: deferred(), released: deferred() };
    const inflight = issue({ blind_u: first.blind_u });   // 같은 C_u(이미 활성) — 검증을 지나 headOf() 의 eth_blockNumber 에서 게이트에 붙잡힌다
    await hold.seen.promise;
    const gate = hold;
    hold = null;                                      // 이후의 eth_blockNumber(revoke 의 것)는 그대로 통과
    const rv = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' });
    assert.equal(rv.status, 200, JSON.stringify(rv.body));
    assert.equal(rv.body.retired, 1, '활성 자격증명이 물려야 한다');
    gate.released.resolve();
    const r = await inflight;
    assert.equal(r.r.status, 403, `폐기 뒤에 발급이 살아남았다: ${JSON.stringify(r.r.body)}`);
    assert.equal(r.r.body.reason, 'account_disabled');
    assert.equal((await cia.get('/cia/state')).body.credCount, 0, '폐기 뒤 활성 자격증명은 없어야 한다');
    // 복구해도 물린 Cf_u(같은 blind_u)로는 발급되지 않는다 — 새 C_u 부터
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: '12345', disabled: false })).status, 200);
    const retry = await issue({ blind_u: first.blind_u });
    assert.equal(retry.r.status, 409); assert.equal(retry.r.body.reason, 'cred_revoked');
    assert.equal((await issue()).r.status, 200);
  });

  await t('프록시 경유 정상 발급 (게이트 없음)', async () => {
    const r = await issue();
    assert.equal(r.r.status, 200, JSON.stringify(r.r.body));
  });

  // 2026-09-25 리뷰 I-1: pruneExpiredSessions() 가 계정 순회 **안**에서 head 를 읽으면, 그 await 동안 /cia/issue 가
  // acct.sessions 를 새 배열로 갈아끼운다 — 재개한 정리는 옛 배열로 만든 keep 을 대입해 방금 발급된 기록을 덮어쓴다.
  // 그 세션은 이후 /cia/revoke scope=session 에서 404 unknown_session 이라 만료될 때까지 개별 폐기가 안 된다.
  // 결정적으로 재현하려고 하트비트를 켠 두 번째 격리 CIA 를 띄우되, **세션 헤드 조회(headOf)만** 게이트 프록시를
  // 거치게 하고(CIA_CHAIN_RPCS) 로그·하트비트 게시용 provider 는 업스트림에 직접 물린다(CIA_RPC_URL).
  // 그래야 게이트에 걸리는 eth_blockNumber 가 정리의 것 하나뿐이라 "정리가 head 를 기다리는 순간"을 골라 발급을 끼워 넣을 수 있다.
  await t('경합: 하트비트 정리가 head 를 기다리는 동안 발급해도 세션 기록이 사라지지 않는다 (2026-09-25 리뷰 I-1)', async () => {
    const hb = await startIsolatedCia({ env: { CIA_RPC_URL: UPSTREAM, CIA_CHAIN_RPCS: `31337=${proxyUrl}`, CIA_HEARTBEAT_BLOCKS: '1', CIA_HEARTBEAT_POLL_MS: '200' } });
    try {
      const u2 = userOf(await hb.registerUser('12345', 'password123'), '12345', TESTUSER_ATTRS);
      const fixedBlind = randomScalar();   // 두 호출 모두 같은 C_u — 교체(등록부 게시)가 끼어 섞이지 않게
      const issueOne = (opts) => issueV11(hb, u2, { arid, provider, blind_u: fixedBlind, post: (p, b) => hb.post(p, b), ...opts });
      const first = await issueOne();   // 기록이 하나 있어야 정리의 계정 순회가 head 조회까지 간다
      assert.equal(first.r.status, 200, JSON.stringify(first.r.body));
      hold = { seen: deferred(), released: deferred() };
      let timer;
      await Promise.race([
        hold.seen.promise,
        new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('하트비트 정리가 15초 안에 head 를 읽지 않았다')), 15_000); }),
      ]).finally(() => clearTimeout(timer));
      const gate = hold;
      hold = null;                      // 발급의 head 조회는 그대로 통과시킨다
      const second = await issueOne();   // 같은 C_u — 정리가 멈춰 있는 사이 acct.sessions 가 새 배열로 바뀐다
      assert.equal(second.r.status, 200, JSON.stringify(second.r.body));
      gate.released.resolve();          // 정리 재개 — 옛 배열로 만든 keep 을 대입하면 second 가 사라진다
      await new Promise((r) => setTimeout(r, 500));   // 정리가 끝날 시간(하트비트 주기 200ms)
      const list = (await hb.adminGet(`/cia/admin/sessions?uid=12345`)).body.sessions;
      const have = new Set(list.map((s) => s.Cf_s));
      const missing = [first, second].map((r) => r.cred.Cf_s).filter((c) => !have.has(c));
      assert.deepEqual(missing, [], '발급된 세션 기록이 정리에 덮여 사라졌다');
      // 사용자에게 보이는 증상까지 본다 — 기록이 없으면 개별 폐기가 404 unknown_session 이다.
      const rv = await hb.adminPost('/cia/revoke', { uid: '12345', scope: 'session', Cf_s: second.cred.Cf_s });
      assert.equal(rv.status, 200, `정리에 덮인 세션은 개별 폐기가 안 된다: ${JSON.stringify(rv.body)}`);
    } finally { await hb.stop(); }
  });
} finally {
  await cia.stop();
  proxy.close();
}
process.exit(failed === 0 ? 0 : 1);
