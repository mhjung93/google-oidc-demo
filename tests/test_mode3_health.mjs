// GET /mode3/health 실제 응답·CORS. :8545 필요. node tests/test_mode3_health.mjs
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { createShare } from '../lib/mode3_trace.js';
import { createRegistration, createSessionKey, buildUserCredRequest, buildIssueRequest } from '../lib/mode3_wallet.js';
import { pointToStrings } from '../lib/mode3_issuance.js';
const stack = await startIsolatedMode3Stack();
const { cia, rp, wallet } = stack;
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.message); } }
const get = (base, origin) => fetch(`${base}/mode3/health`, { headers: origin ? { Origin: origin } : {} });
await t('세 서버가 role·ok·chain 을 준다', async () => {
  for (const [b, role] of [[cia.base, 'aa'], [rp.base, 'rp'], [wallet.base, 'wallet']]) { const r = await get(b); const j = await r.json(); assert.equal(r.status, 200); assert.equal(j.role, role); assert.equal(j.ok, true); assert.ok(j.chain?.head, `${role} chain`); assert.equal(r.headers.get('cache-control'), 'no-store'); }
});
await t('민감 키 없음(전 깊이)', async () => {
  const bad = ['uid', 'PPID', 'secret', 'sk_u', 'pk_u', 'pk_CIA', 'arid', 'r_s'];
  for (const b of [cia.base, rp.base, wallet.base]) { const s = JSON.stringify(await (await get(b)).json()); for (const k of bad) assert.ok(!s.includes(`"${k}"`), `${b} has ${k}`); }
});
await t('CORS: 허용 오리진에만 헤더', async () => {
  assert.equal((await get(rp.base, wallet.origin)).headers.get('access-control-allow-origin'), wallet.origin);
  assert.equal((await get(rp.base, 'http://evil.example')).headers.get('access-control-allow-origin'), null);
  assert.equal((await get(wallet.base, rp.origin)).headers.get('access-control-allow-origin'), rp.origin);
  assert.equal((await get(cia.base, wallet.origin)).headers.get('access-control-allow-origin'), wallet.origin);   // MODE3_WALLET_AGENT_ORIGIN
  assert.equal((await get(cia.base, rp.origin)).headers.get('access-control-allow-origin'), rp.origin);           // 승인된 서비스
  assert.equal((await get(cia.base, 'http://evil.example')).headers.get('access-control-allow-origin'), null);
});
await t('RP: approved·active, 지갑: 미등록·ciaReachable', async () => {
  const r = await (await get(rp.base)).json(); assert.equal(r.status, 'approved'); assert.equal(r.active, true); assert.equal(typeof r.maxRootAge, 'number');
  const w = await (await get(wallet.base)).json(); assert.equal(w.registered, false); assert.equal(w.ciaReachable, true);
});
// 헬퍼는 자기 RP 를 승인해 둔다 — 승인 전 상태는 CIA 에 직접 등록한 두 번째 서비스로 본다(승인 전에는 허용 목록에 없다).
await t('AA CORS: 승인 전 서비스 오리진은 거부, 승인 뒤 허용', async () => {
  const pendingOrigin = 'http://127.0.0.1:59999';
  const share = await createShare();
  const reg = await cia.post('/cia/register_rp', { name: 'pending-rp', origin: pendingOrigin, pk_service: ethers.Wallet.createRandom().address, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() } });
  assert.equal(reg.status, 202, JSON.stringify(reg.body));
  const before = await get(cia.base, pendingOrigin);
  assert.equal(before.headers.get('access-control-allow-origin'), null, '승인 전에는 CORS 헤더가 없어야 한다');
  const bj = await before.json();
  assert.ok(bj.pendingRps >= 1, `pendingRps ${bj.pendingRps}`);
  assert.ok(!bj.rpOrigins.includes(pendingOrigin), 'rpOrigins 에 승인 전 서비스가 들어가면 안 된다');
  const ap = await cia.adminPost(`/cia/rps/${reg.body.arid}/approve`);
  assert.equal(ap.status, 200, JSON.stringify(ap.body));
  const after = await get(cia.base, pendingOrigin);
  assert.equal(after.headers.get('access-control-allow-origin'), pendingOrigin);
  assert.ok((await after.json()).rpOrigins.includes(pendingOrigin));
});
await t('Vary: Origin 은 허용·거절 모두에 붙는다(중간 캐시가 응답을 섞지 않게)', async () => {
  const has = (r) => (r.headers.get('vary') ?? '').toLowerCase().split(',').map((v) => v.trim()).includes('origin');
  assert.ok(has(await get(rp.base, wallet.origin)), '허용 경로');
  assert.ok(has(await get(rp.base, 'http://evil.example')), '거절 경로');
  assert.ok(has(await get(wallet.base, rp.origin)) && has(await get(cia.base, wallet.origin)), '지갑·AA 허용 경로');
});
// 2026-09-25 리뷰: 위 '민감 키 없음' 은 **키 이름**만 본다 — uid 를 'account' 같은 다른 이름으로 싣는 순간
// 통째로 무력해진다. 여기서는 테스트가 값을 직접 만든 뒤(등록·자격증명·세션) 그 **값**이 세 응답 어디에도
// 문자열로 없는지 본다. 맨 뒤에 둔다 — 계정·세션을 만들어 앞 케이스들의 카운터를 흔들지 않게.
await t('민감 "값" 없음 — 등록 uid·s_u·r_u·sk_u, C_u 의 Cf_u, 세션의 Cf_s 가 응답에 안 실린다', async () => {
  // 지갑에도 계정을 하나 만든다(testuser) — 지갑 health 가 registered 상태에서 uid 를 흘리지 않는지 보려면 필요하다.
  const wreg = await wallet.post('/wallet/register', { uid: '12345', pwd: 'password123' });
  assert.equal(wreg.status, 201, JSON.stringify(wreg.body));
  // AA 에는 alice(67890) 로 등록 → 사용자 자격증명 → 세션. 비밀을 테스트가 직접 뽑으므로 값을 전부 안다.
  const uidB = 67890n;
  const reg = await createRegistration();
  const r = await cia.post('/cia/register', { uid: '67890', pwd: 'alicepw', cm_u: pointToStrings(reg.cm_u) });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  const sk_u = r.body.sk_u;
  const uc = await buildUserCredRequest({ uid: uidB, s_u: reg.s_u, r_u: reg.r_u, sk_u, attrs: [2005n, 840n, 1n, 0n] });
  assert.equal((await cia.post('/cia/user_cred', uc.body)).status, 201);
  const chain = (await (await get(cia.base)).json()).chain;
  const iss = await buildIssueRequest({ uid: uidB, Cf_u: uc.Cf_u, arid: 22222222222222222222n, sk_u, session: createSessionKey(), chainid: BigInt(chain.id), max_height: BigInt(chain.head) + 300n });
  const issued = await cia.post('/cia/issue', iss.body);
  assert.equal(issued.status, 200, JSON.stringify(issued.body));

  const secrets = {
    s_u: reg.s_u.toString(), r_u: reg.r_u.toString(), sk_u, cm_u_x: reg.cm_u.x.toString(),
    Cf_u: uc.Cf_u.toString(), blind_u: uc.secrets.blind_u.toString(),
    Cf_s: issued.body.Cf_s, blind_s: iss.secrets.blind_s.toString(),
    arid: '22222222222222222222',
  };
  // uid 는 다섯 자리라 단순 부분 문자열로 보면 공개 블록 번호·root 앞자리와 우연히 겹칠 수 있다. 그 셋은
  // 계정과 무관한 공개값이므로 uid 검사에서만 지우고, 숫자 경계까지 맞을 때만 유출로 본다.
  const scrubbed = (j) => JSON.stringify({ ...j, root: undefined, lastPublishedBlock: undefined, chain: j.chain ? { ...j.chain, head: 'X' } : null });
  for (const [b, who] of [[cia.base, 'aa'], [rp.base, 'rp'], [wallet.base, 'wallet']]) {
    const j = await (await get(b)).json();
    const s = JSON.stringify(j);
    for (const [k, v] of Object.entries(secrets)) assert.ok(!s.includes(v), `${who} 응답에 ${k} 값이 실렸다`);
    const sc = scrubbed(j);
    for (const uid of ['12345', '67890']) {
      assert.ok(!new RegExp(`(?<![0-9])${uid}(?![0-9])`).test(sc), `${who} 응답에 uid ${uid} 가 실렸다: ${sc}`);
    }
  }
});

await stack.stop();
if (fails) { console.log(`\n${fails} FAIL`); process.exit(1); } console.log('\nall ok');
