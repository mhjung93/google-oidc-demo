// /cia/issue 와 /cia/revoke 의 경합 — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_issue_race.mjs
//
// /cia/issue(V5) 는 disabled·서명·활성 Cf_u·C_s_pt 를 검사한 뒤 서명 직전에 chainAlive() 로 eth_blockNumber 를
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
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { randomScalar, sessionCommit } from '../lib/mode3_credential.js';
import { registrationCommit, proveUserCred, serializeUserCredProof, userCredRequestMessage, issueRequestMessageV4, pointToStrings } from '../lib/mode3_issuance.js';

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

const uid = 12345n, arid = 22222222222222222222n;
const pk_i = BigInt(ethers.Wallet.createRandom().address);
const eddsa = await buildEddsa();
const F = (await buildPoseidon()).F;
const signMsg = (prvHex, m) => { const sg = eddsa.signPoseidon(Buffer.from(prvHex, 'hex'), F.e(m)); return { R8x: F.toObject(sg.R8[0]).toString(), R8y: F.toObject(sg.R8[1]).toString(), S: sg.S.toString() }; };

const cia = await startIsolatedCia({ env: { CIA_RPC_URL: proxyUrl } });
try {
  const s_u = randomScalar(), r_u = randomScalar();
  const reg = await cia.post('/cia/register', { uid: uid.toString(), pwd: 'password123', cm_u: pointToStrings(await registrationCommit(s_u, r_u)) });
  assert.equal(reg.status, 201, JSON.stringify(reg.body));
  const sk_u = reg.body.sk_u;

  /** 사용자 자격증명 요청 본문(매번 새 blind_u → 새 Cf_u). 응답의 Cf_u 는 요청자가 미리 알 수 없으니 CIA 응답에서 읽는다.
   *  attrs 는 cia.js DEMO_ACCOUNTS.testuser(uid 12345) 의 AA 기록과 같아야 π_u 가 통과한다(2026-09-22 §3.4). */
  async function userCredBody() {
    const { C_u_pt, proof } = await proveUserCred({ uid, s_u, blind_u: randomScalar(), r_u, attrs: [1990n, 410n, 2n, 0n] });
    return { uid: uid.toString(), C_u_pt: pointToStrings(C_u_pt), proof: serializeUserCredProof(proof), sig_u: signMsg(sk_u, await userCredRequestMessage(C_u_pt)) };
  }
  /** 세션 발급 V5 본문. Cf_u 는 /cia/user_cred 응답값(10진 문자열). */
  async function issueBody(Cf_u) {
    const { Cx, Cy } = await sessionCommit({ arid, pk_i, blind_s: randomScalar() });
    const C_s_pt = { x: Cx, y: Cy };
    const max_height = BigInt(await provider.getBlockNumber()) + 300n;
    return { uid: uid.toString(), Cf_u, C_s_pt: pointToStrings(C_s_pt), sig_u: signMsg(sk_u, await issueRequestMessageV4(BigInt(Cf_u), C_s_pt, 31337n, 0n, max_height)), chainid: '31337', allowAgent: '0', max_height: max_height.toString() };
  }

  await t('user_cred 동시 요청 둘(같은 uid, 다른 blind_u): 둘 다 201, 활성 자격증명은 정확히 하나, 물린 리프는 옛 활성 + 패자 둘', async () => {
    // 활성 자격증명이 있는 상태에서 겹치게 한다 — retireActiveCred 의 await(리프 삽입) 가 있어야 두 요청이 교차할 수 있다.
    // (실제 교차는 이벤트 루프 스케줄에 달려 결정적으로 강제할 수 없다 — 이 케이스는 어느 순서로 처리돼도 성립해야 하는 불변식만 본다.)
    const first = await cia.post('/cia/user_cred', await userCredBody());
    assert.equal(first.status, 201, JSON.stringify(first.body));
    const before = (await cia.get('/cia/state')).body;
    assert.equal(before.credCount, 1);
    const [bodyA, bodyB] = await Promise.all([userCredBody(), userCredBody()]);
    const [ra, rb] = await Promise.all([cia.post('/cia/user_cred', bodyA), cia.post('/cia/user_cred', bodyB)]);
    assert.equal(ra.status, 201, JSON.stringify(ra.body)); assert.equal(rb.status, 201, JSON.stringify(rb.body));
    const after = (await cia.get('/cia/state')).body;
    assert.equal(after.credCount, 1, '활성 자격증명은 하나여야 한다');
    assert.equal(after.pendingCount, before.pendingCount + 2, '옛 활성 리프와 패자의 리프, 둘이 pending 에');
    assert.equal(after.leafCount, before.leafCount + 2);
    // 둘 중 정확히 하나만 세션을 받는다
    const [ia, ib] = await Promise.all([cia.post('/cia/issue', await issueBody(ra.body.Cf_u)), cia.post('/cia/issue', await issueBody(rb.body.Cf_u))]);
    assert.deepEqual([ia.status, ib.status].sort(), [200, 403], JSON.stringify([ia.body, ib.body]));
    assert.equal((ia.status === 403 ? ia : ib).body.reason, 'no_user_cred');
  });

  await t('user_cred 와 revoke(account) 동시 요청: 어느 쪽이 먼저든 disabled 계정에 활성 자격증명이 남지 않는다', async () => {
    // user_cred 가 retireActiveCred 의 await 에 있는 동안 revoke 가 disabled 를 걸 수 있다 — 마지막 await 뒤 disabled 재확인이
    // 없으면 disabled 계정에 새 활성 자격증명이 올라간다. 둘 다 체인을 부르지 않아 게이트로 순서를 강제할 수는 없다 — 두 순서
    // 모두에서 성립해야 하는 불변식(credCount 0, 이후 user_cred 403 'account disabled')과 pending 증가량을 본다.
    const before = (await cia.get('/cia/state')).body;
    assert.equal(before.credCount, 1, '앞 케이스가 활성 자격증명 하나를 남겨 둔다');
    const body = await userCredBody();
    const [uc, rv] = await Promise.all([cia.post('/cia/user_cred', body), cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' })]);
    assert.equal(rv.status, 200, JSON.stringify(rv.body));
    assert.ok(uc.status === 201 || uc.status === 403, JSON.stringify(uc.body));
    const after = (await cia.get('/cia/state')).body;
    assert.equal(after.credCount, 0, 'disabled 계정에 활성 자격증명이 남았다');
    // user_cred 가 먼저면 옛 활성 + 새 것(revoke 가 물림) = +2, revoke 가 먼저면 옛 활성만 +1
    assert.equal(after.pendingCount, before.pendingCount + (uc.status === 201 ? 2 : 1), `uc=${uc.status}`);
    const denied = await cia.post('/cia/user_cred', await userCredBody());
    assert.equal(denied.status, 403); assert.equal(denied.body.error, 'account disabled');
    if (uc.status === 201) assert.equal((await cia.post('/cia/issue', await issueBody(uc.body.Cf_u))).status, 403);
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);   // 뒤 케이스용 복구
  });

  await t('issue 가 체인 가용성을 확인하는 동안 계정이 폐기되면 발급하지 않는다 (403, 활성 자격증명도 0)', async () => {
    const uc = await cia.post('/cia/user_cred', await userCredBody());
    assert.equal(uc.status, 201, JSON.stringify(uc.body));
    const body = await issueBody(uc.body.Cf_u);
    hold = { seen: deferred(), released: deferred() };
    const inflight = cia.post('/cia/issue', body);   // 검증을 지나 headOf() 의 eth_blockNumber 에서 게이트에 붙잡힌다
    await hold.seen.promise;
    const gate = hold;
    hold = null;                                      // 이후의 eth_blockNumber(revoke 의 것)는 그대로 통과
    const rv = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' });
    assert.equal(rv.status, 200, JSON.stringify(rv.body));
    assert.equal(rv.body.inserted.length, 1, "활성 자격증명 리프 하나가 물려야 한다");
    gate.released.resolve();
    const r = await inflight;
    assert.equal(r.status, 403, `폐기 뒤에 발급이 살아남았다: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.reason, 'no_user_cred');
    assert.equal((await cia.get('/cia/state')).body.credCount, 0, '폐기 뒤 활성 자격증명은 없어야 한다');
    // 복구해도 물린 Cf_u 로는 발급되지 않는다 — 새 user_cred 부터
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    assert.equal((await cia.post('/cia/issue', body)).status, 403);
    const uc2 = await cia.post('/cia/user_cred', await userCredBody());
    assert.equal(uc2.status, 201, JSON.stringify(uc2.body));
    assert.equal((await cia.post('/cia/issue', await issueBody(uc2.body.Cf_u))).status, 200);
  });

  await t('프록시 경유 정상 발급 (게이트 없음)', async () => {
    const uc = await cia.post('/cia/user_cred', await userCredBody());
    assert.equal(uc.status, 201, JSON.stringify(uc.body));
    const r = await cia.post('/cia/issue', await issueBody(uc.body.Cf_u));
    assert.equal(r.status, 200, JSON.stringify(r.body));
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
      const s_u2 = randomScalar(), r_u2 = randomScalar();
      const reg = await hb.post('/cia/register', { uid: uid.toString(), pwd: 'password123', cm_u: pointToStrings(await registrationCommit(s_u2, r_u2)) });
      assert.equal(reg.status, 201, JSON.stringify(reg.body));
      const sk = reg.body.sk_u;
      const { C_u_pt, proof } = await proveUserCred({ uid, s_u: s_u2, blind_u: randomScalar(), r_u: r_u2, attrs: [1990n, 410n, 2n, 0n] });
      const uc = await hb.post('/cia/user_cred', { uid: uid.toString(), C_u_pt: pointToStrings(C_u_pt), proof: serializeUserCredProof(proof), sig_u: signMsg(sk, await userCredRequestMessage(C_u_pt)) });
      assert.equal(uc.status, 201, JSON.stringify(uc.body));
      async function issueOne() {
        const { Cx, Cy } = await sessionCommit({ arid, pk_i, blind_s: randomScalar() });
        const C_s_pt = { x: Cx, y: Cy };
        const mh = BigInt(await provider.getBlockNumber()) + 300n;
        const body = { uid: uid.toString(), Cf_u: uc.body.Cf_u, C_s_pt: pointToStrings(C_s_pt), sig_u: signMsg(sk, await issueRequestMessageV4(BigInt(uc.body.Cf_u), C_s_pt, 31337n, 0n, mh)), chainid: '31337', allowAgent: '0', max_height: mh.toString() };
        const r = await hb.post('/cia/issue', body);
        assert.equal(r.status, 200, JSON.stringify(r.body));
        return r;
      }
      const first = await issueOne();   // 기록이 하나 있어야 정리의 계정 순회가 head 조회까지 간다
      hold = { seen: deferred(), released: deferred() };
      let timer;
      await Promise.race([
        hold.seen.promise,
        new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('하트비트 정리가 15초 안에 head 를 읽지 않았다')), 15_000); }),
      ]).finally(() => clearTimeout(timer));
      const gate = hold;
      hold = null;                      // 발급의 head 조회는 그대로 통과시킨다
      const second = await issueOne();  // 정리가 멈춰 있는 사이 acct.sessions 가 새 배열로 바뀐다
      gate.released.resolve();          // 정리 재개 — 옛 배열로 만든 keep 을 대입하면 second 가 사라진다
      await new Promise((r) => setTimeout(r, 500));   // 정리가 끝날 시간(하트비트 주기 200ms)
      const list = (await hb.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions;
      const have = new Set(list.map((s) => s.Cf_s));
      const missing = [first, second].map((r) => r.body.Cf_s).filter((c) => !have.has(c));
      assert.deepEqual(missing, [], '발급된 세션 기록이 정리에 덮여 사라졌다');
      // 사용자에게 보이는 증상까지 본다 — 기록이 없으면 개별 폐기가 404 unknown_session 이다.
      const rv = await hb.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: second.body.Cf_s });
      assert.equal(rv.status, 200, `정리에 덮인 세션은 개별 폐기가 안 된다: ${JSON.stringify(rv.body)}`);
    } finally { await hb.stop(); }
  });
} finally {
  await cia.stop();
  proxy.close();
}
process.exit(failed === 0 ? 0 : 1);
