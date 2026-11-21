// tests/test_cia_wrapper_race.mjs — 래퍼 방식(CIA_WRAPPER=1) 발급의 경합. 격리 IdP + Google 대역 + :8545 앞의 게이트 프록시. (chain 그룹)
//   node tests/test_cia_wrapper_race.mjs
// 게이트는 test_cia_issue_race.mjs 와 같다: 발급의 게시 tx(eth_sendRawTransaction)를 붙잡아 "게시를 기다리는 동안" 을 결정적으로 만든다.
import assert from 'node:assert/strict';
import http from 'node:http';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { createRegistration, createSessionKey, buildWrapperIssueBody } from '../lib/mode3_wallet.js';
import { uidOf } from '../lib/mode3_oidc_nonce.js';
import { randomScalar } from '../lib/mode3_credential.js';
import { generateRequestKey, wrapperNonce, signIssue } from '../lib/mode3_wrapper_auth.js';
import { TESTUSER_ATTRS } from './helpers/mode3_flow.mjs';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };

const UPSTREAM = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const provider = new ethers.JsonRpcProvider(UPSTREAM);
let hold = null;
const proxy = http.createServer(async (req, res) => {
  let body = '';
  for await (const c of req) body += c;
  let gate = null;
  try {
    const m = JSON.parse(body); const methods = (Array.isArray(m) ? m : [m]).map((x) => x.method);
    if (hold && methods.includes(hold.method)) gate = hold;
  } catch { /* 그대로 전달 */ }
  if (gate) { gate.seen.resolve(); await gate.released.promise; }
  const up = await fetch(UPSTREAM, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
  res.writeHead(up.status, { 'content-type': 'application/json' }); res.end(await up.text());
});
await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
const gateNext = () => { hold = { method: 'eth_sendRawTransaction', seen: deferred(), released: deferred() }; return hold; };
// JWKS 게이트(2026-11-21 셀프 피드백 — M-2 를 결정적으로): jose 의 createRemoteJWKSet 은 받아 오는 중인 JWKS 를 기다리는 요청끼리 나눈다.
// 막 뜬 IdP 의 첫 JWKS 를 붙잡으면 같은 계정의 두 요청이 auid_pinned 검사 앞(wrapperAuth)에서 함께 서고, 풀면 둘 다 그 검사를 지나 등록에서 만난다.
let jwksUpstream = null, jwksHold = null;
const jwksProxy = http.createServer(async (req, res) => {
  const g = jwksHold; if (g) { g.seen.resolve(); await g.released.promise; }
  const up = await fetch(jwksUpstream);
  res.writeHead(up.status, { 'content-type': 'application/json' }); res.end(await up.text());
});
await new Promise((r) => jwksProxy.listen(0, '127.0.0.1', r));

const cia = await startIsolatedCia({ wrapper: true, env: { CIA_RPC_URL: proxyUrl, CIA_CHAIN_RPCS: '31337=' + proxyUrl, CIA_AUID_S_LOG_MAX: '2', MODE3_OIDC_JWKS_URL: `http://127.0.0.1:${jwksProxy.address().port}/.well-known/jwks.json` } });
const stub = cia.oidc, AUD = cia.base;
jwksUpstream = stub.jwksUrl;
async function person(sub) {
  const uid = uidOf(stub.provider, sub);
  const reg = await createRegistration(BigInt(uid));
  return { sub, uid: BigInt(uid), s_u: reg.s_u, attrs: [...TESTUSER_ATTRS], blind_u: randomScalar() };
}
/** 요청 키·토큰·본문·서명을 만든다. 같은 key·id_token 으로 본문만 바꿔 다시 만들 수 있다(재시도). */
async function makeIssue(who, { key = null, id_token = null, blind_u = who.blind_u, r_rp = randomScalar(), mutate = null } = {}) {
  const k = key ?? await generateRequestKey();
  const tok = id_token ?? await stub.mint({ sub: who.sub, nonce: await wrapperNonce(k.pkE), extra: {} });
  const max_height = BigInt(await provider.getBlockNumber()) + 300n;
  const built = await buildWrapperIssueBody({ uid: who.uid, s_u: who.s_u, blind_u, attrs: who.attrs, arid: 33333333333333333333n, r_rp, r_s: randomScalar(), session: createSessionKey(), chainid: 31337n, allowAgent: 0n, max_height });
  // mutate: 서명 전에 본문을 바꾼다(악의적인 클라이언트 — 남의 auid_s·C_u 를 낸다). 서명은 바뀐 본문 위에 한다.
  if (mutate) built.body = mutate({ ...built.body });
  return { key: k, id_token: tok, body: { id_token: tok, pk_e: k.pkE, sig: await signIssue(k.privateKey, built.body, AUD), ...built.body }, built };
}
const credCount = async () => (await cia.get('/cia/state')).body.credCount;

try {
  await t('M-3: 새 C_u 발급이 게시를 기다리는 중 관리자가 그 자격증명을 물리면 409 cred_revoked — 같은 토큰·같은 요청 키로 새 C_u 를 내 다시 하면 200(토큰을 태우지 않았다)', async () => {
    const ann = await person('g-race-ann');
    const first = await makeIssue(ann);
    const gate = gateNext();
    const inflight = cia.post('/cia/issue', first.body);
    await gate.seen.promise; hold = null;
    const rvP = cia.adminPost('/cia/revoke', { uid: ann.uid.toString(), scope: 'credential' });
    const deadline = Date.now() + 10_000;
    while ((await credCount()) !== 0) { assert.ok(Date.now() < deadline, '관리자 폐기의 은퇴가 돌지 않았다'); await new Promise((r) => setTimeout(r, 50)); }
    gate.released.resolve();
    const [r, rv] = await Promise.all([inflight, rvP]);
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'cred_revoked');
    assert.equal(rv.status, 200, j(rv.body));
    const retry = await makeIssue(ann, { key: first.key, id_token: first.id_token, blind_u: randomScalar() });
    const rr = await cia.post('/cia/issue', retry.body);
    assert.equal(rr.status, 200, j(rr.body) + ' — 토큰은 토큰을 내지 못한 요청에 쓰이지 않았다');
    const again = await cia.post('/cia/issue', retry.body);
    assert.equal(again.status, 409, j(again.body)); assert.equal(again.body.reason, 'wrapper_token_used', '성공한 요청은 토큰을 태운다');
  });

  await t('재검토 Minor: 발급 기록 상한(auid_log_full)은 진행 중인 발급까지 센다 — 게시를 기다리는 발급이 있으면 그 계정의 다른 발급이 상한을 넘기지 못한다', async () => {
    // 상한 2 — 첫 발급(게시 대기) 중에 같은 C_u 로 두 번 더 낸다. 진행 중인 것까지 세면 두 번째에서 찬다.
    const bo = await person('g-race-bo');
    const first = await makeIssue(bo);
    const gate = gateNext();
    const inflight = cia.post('/cia/issue', first.body);
    await gate.seen.promise; hold = null;
    const same = async () => cia.post('/cia/issue', (await makeIssue(bo)).body);   // 같은 blind_u → 같은 C_u(게시 없이 재서명)
    const r2 = await same();
    assert.equal(r2.status, 200, j(r2.body));
    const r3 = await same();
    gate.released.resolve();
    const r1 = await inflight;
    assert.equal(r1.status, 200, j(r1.body));
    assert.equal(r3.status, 409, j(r3.body) + ' — 진행 중인 발급을 세지 않으면 기록이 상한을 넘는다'); assert.equal(r3.body.reason, 'auid_log_full');
  });
  await t('M-2: 같은 Google 계정의 첫 발급이 서로 다른 패스키(auid)로 동시에 오면 늦은 쪽은 409 auid_pinned(사유 있음) — 사유 없는 409 로 끝나지 않는다', async () => {
    // 첫 발급의 계정 등록은 요청 안의 await 사이에 일어난다 — 여러 쌍을 함께 보내 겹치는 경우를 만든다(겹치지 않으면 늦은 쪽은 원래의 auid_pinned 로 끝난다).
    const results = await Promise.all(Array.from({ length: 6 }, async (_, i) => {
      const sub = `g-race-pin-${i}`, a = await person(sub), b = await person(sub);   // 같은 Google 계정, 다른 패스키
      const [ia, ib] = await Promise.all([makeIssue(a), makeIssue(b)]);
      return Promise.all([cia.post('/cia/issue', ia.body), cia.post('/cia/issue', ib.body)]);
    }));
    for (const [ra, rb] of results) {
      assert.deepEqual([ra.status, rb.status].sort(), [200, 409], `${j(ra.body).slice(0, 120)} / ${j(rb.body).slice(0, 120)}`);
      const late = ra.status === 409 ? ra : rb;
      assert.equal(late.body.reason, 'auid_pinned', j(late.body));
    }
  });

  await t('M-2(결정적): 막 뜬 IdP 의 첫 JWKS 를 붙잡아 같은 Google 계정·다른 패스키의 첫 발급 둘을 auid_pinned 검사 너머로 함께 보내면 늦은 쪽은 등록에서 막혀 409 auid_pinned', async () => {
    await cia.restart();   // JWKS 캐시를 비운다(새 프로세스)
    const sub = 'g-race-pin-det', a = await person(sub), b = await person(sub);
    const [ia, ib] = await Promise.all([makeIssue(a), makeIssue(b)]);
    jwksHold = { seen: deferred(), released: deferred() };
    const pa = cia.post('/cia/issue', ia.body);
    await jwksHold.seen.promise;
    const pb = cia.post('/cia/issue', ib.body);
    await new Promise((r) => setTimeout(r, 700));   // b 가 같은 JWKS 를 기다리는 자리까지 오게
    const g = jwksHold; jwksHold = null; g.released.resolve();
    const [ra, rb] = await Promise.all([pa, pb]);
    assert.deepEqual([ra.status, rb.status].sort(), [200, 409], `${j(ra.body).slice(0, 160)} / ${j(rb.body).slice(0, 160)}`);
    const late = ra.status === 409 ? ra : rb;
    assert.equal(late.body.reason, 'auid_pinned', j(late.body));
  });

  await t('재검토 Minor(R-1, 결정적): 같은 계정의 두 발급이 같은 auid_s 를 쥐고 하나가 먼저 실패해도(cf_u_taken) 예약은 남는다 — 다른 계정은 그 auid_s 로 409 auid_s_taken', async () => {
    // U 의 첫 발급(auid_s X)을 게시에서 붙잡고, 그 사이 U 가 같은 X 로 남의 C_u 를 내 예약 뒤에 실패한다(기록 없음). 먼저 끝난 요청이 예약을 지우면 V 가 X 를 가져간다.
    const v0 = await person('g-r1-v0'), u = await person('g-r1-u'), v = await person('g-r1-v');
    const v0i = await makeIssue(v0); assert.equal((await cia.post('/cia/issue', v0i.body)).status, 200);
    const R = randomScalar();
    const u1 = await makeIssue(u, { r_rp: R });
    const X = u1.body.auid_s;
    const gate = gateNext();
    const p1 = cia.post('/cia/issue', u1.body);
    await gate.seen.promise; hold = null;
    const u2 = await makeIssue(u, { r_rp: R, blind_u: randomScalar(), mutate: (b) => ({ ...b, C_u_pt: v0i.body.C_u_pt }) });
    assert.equal(u2.body.auid_s, X, '같은 r_rp → 같은 auid_s');
    const r2 = await cia.post('/cia/issue', u2.body);
    assert.equal(r2.status, 409, j(r2.body)); assert.equal(r2.body.reason, 'cf_u_taken', j(r2.body));
    const vi = await makeIssue(v, { mutate: (b) => ({ ...b, auid_s: X }) });
    const pv = cia.post('/cia/issue', vi.body);
    const early = await Promise.race([pv, new Promise((r) => setTimeout(() => r(null), 3000))]);
    gate.released.resolve();
    const [r1, rv] = await Promise.all([p1, pv]);
    assert.equal(r1.status, 200, j(r1.body));
    assert.ok(early !== null, 'V 는 U 의 게시를 기다리지 않고 곧바로 거절돼야 한다');
    assert.equal(rv.status, 409, j(rv.body) + ' — 먼저 끝난 요청이 같은 계정의 다른 요청의 예약을 지웠다'); assert.equal(rv.body.reason, 'auid_s_taken');
  });

  await t('M-1: 쓴 토큰은 재기동 뒤에도 쓴 것이다 — 같은 요청(본문·서명)을 재기동 뒤 다시 보내면 409 wrapper_token_used', async () => {
    const cy = await person('g-race-cy');
    const req = await makeIssue(cy);
    assert.equal((await cia.post('/cia/issue', req.body)).status, 200);
    await cia.restart();
    const again = await cia.post('/cia/issue', req.body);
    assert.equal(again.status, 409, j(again.body) + ' — 메모리에만 두면 재기동 뒤 같은 요청이 다시 받아진다'); assert.equal(again.body.reason, 'wrapper_token_used');
  });
} finally {
  await cia.stop();
  proxy.close(); jwksProxy.close();
  provider.destroy();
}
console.log(fails ? `\n${fails} 실패` : '\n모두 통과');
process.exit(fails ? 1 : 0);
