// tests/test_mode3_zkwrapper_server.mjs — zkWrapper 서버 진입점(mode3_zkwrapper.js, 스펙 2026-11-20 zkwrapper §4·§5, 계획 Task 5): 한 포트에서 사용자 앱(홈·번들·회로·설정)과
// 발급 API(래퍼 방식)가 함께 난다. 체인 읽기 경로(/rpc/*)·지갑 설정·존재 신호 경로는 없다 — 브라우저가 체인 노드를 직접 부른다. :8545·build/mode3 필요. (chain)
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });   // 번들이 없으면 서버가 기동을 거부한다
const j = (o) => JSON.stringify(o);
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const CHAIN = 'http://127.0.0.1:8545';
const ENV = { CIA_PORT: '', MODE3_ZKWRAPPER_PORT: '{port}', CIA_PUBLIC_URL: 'http://localhost:{port}', MODE3_CHAIN_RPC_BROWSER: CHAIN };
const cia = await startIsolatedCia({ wrapper: true, entry: 'mode3_zkwrapper.js', env: ENV });
const raw = (p, init) => fetch(`${cia.base}${p}`, init);
const PUBLIC = `http://localhost:${cia.port}`;
try {
  await t('한 포트에서 홈(/)·번들·회로·설정과 발급 API 가 함께 난다', async () => {
    const home = await raw('/'); assert.equal(home.status, 200); const html = await home.text(); assert.ok(html.includes('id="mainView"'), '홈이 사용자 앱이 아니다');
    assert.equal((await raw('/dist/user.js')).status, 200); assert.equal((await raw('/common/strings.js')).status, 200); assert.equal((await raw('/attr.html')).status, 200); assert.equal((await raw('/google-relay')).status, 200);
    const vk = await raw('/zk/pi_cred_vkey.json'); assert.equal(vk.status, 200); assert.equal((await vk.json()).protocol, 'groth16');
    const k = (await cia.get('/cia/public_keys')).body; assert.equal(k.wrapper, true); assert.equal(k.wrapperAud, PUBLIC);
    const iss = await cia.post('/cia/issue', {}); assert.equal(iss.status, 400, j(iss.body));
    assert.equal((await cia.get('/cia/rps')).status === 404, false, '서비스 등록 경로가 없다');
  });
  await t('/user/config: 래퍼 방식·패스키, 지갑 오리진 = 발급 서버 = 이 서버, 체인 주소는 서버를 거치지 않는 노드 주소', async () => {
    const c = (await cia.get('/user/config')).body;
    assert.equal(c.wrapper, true); assert.equal(c.secrets, 'passkey-web'); assert.equal(c.walletOrigin, PUBLIC); assert.equal(c.ciaUrl, PUBLIC);
    assert.equal(c.rpcUrl, CHAIN); assert.equal(c.chainRpcUrl, CHAIN); assert.equal(c.revRpcUrl, CHAIN); assert.ok(!String(c.rpcUrl).startsWith('/'), '상대 경로(프록시)면 안 된다');
    assert.equal(c.logAddress, cia.logAddress); assert.equal(c.mirrorAddress, cia.mirrorAddress); assert.equal(c.chainId, '31337');
    assert.equal(c.wrapperClientId, cia.oidc.clientId); assert.deepEqual(c.pkCia, (await cia.get('/cia/public_keys')).body.pk_CIA);
    assert.ok(Array.isArray(c.rpOrigins)); assert.equal(c.popupConsent, false);
  });
  await t('체인 프록시·지갑 설정·존재 신호 경로가 없다(/rpc/app·/rpc/rev·/wallet/config·/wallet/presence 는 404)', async () => {
    for (const [m, p] of [['POST', '/rpc/app'], ['POST', '/rpc/rev'], ['GET', '/wallet/config'], ['POST', '/wallet/presence']]) {
      const r = await raw(p, { method: m, headers: { 'Content-Type': 'application/json' }, ...(m === 'POST' ? { body: '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' } : {}) });
      assert.equal(r.status, 404, `${m} ${p} → ${r.status}`);
    }
  });
  await t('계정·로그인 화면은 닫혀 있고(/user·/login·/account 403 wrapper_mode), 운영자·관리자 화면은 열려 있다', async () => {
    for (const p of ['/user', '/user/info', '/login', '/account']) { const r = await cia.get(p); assert.equal(r.status, 403, p); assert.equal(r.body.reason, 'wrapper_mode', p); }
    assert.equal((await raw('/admin')).status, 200); assert.equal((await raw('/rp')).status, 200);
  });
  await t('CSP 는 사용자 앱 경로에만 붙는다 — 연결 대상은 자기 오리진·체인 노드·승인된 서비스뿐, 관리자 화면에는 없다', async () => {
    const csp = (await raw('/')).headers.get('content-security-policy') ?? '';
    assert.ok(csp.includes("script-src 'self' 'wasm-unsafe-eval'"), csp); assert.ok(csp.includes(CHAIN), csp);
    assert.ok(((await raw('/dist/user.js')).headers.get('content-security-policy') ?? '').includes("script-src 'self'"), '번들(워커)에도 CSP');
    assert.ok(!((await raw('/admin')).headers.get('content-security-policy') ?? '').includes('script-src'), '관리자 화면에는 사용자 앱의 스크립트 정책을 달지 않는다(그 화면은 지금 그대로다)');
  });
  await t('승인된 서비스가 설정과 CSP 에 들어온다 — 서비스 등록은 지금까지와 같다(대기 → 승인)', async () => {
    const before = (await cia.get('/user/config')).body.rpOrigins; assert.ok(!before.includes('http://127.0.0.1:3555'));
    const s = await cia.registerRp('http://127.0.0.1:3555', 'zkONE'); assert.ok(s.arid);
    assert.ok((await cia.get('/user/config')).body.rpOrigins.includes('http://127.0.0.1:3555'));
    assert.ok(((await raw('/')).headers.get('content-security-policy') ?? '').includes('http://127.0.0.1:3555'));
  });
} finally { await cia.stop(); }
await t('기동 검사: 공개 주소가 IP 면 뜨지 않는다(패스키는 이름 오리진에서만 된다)', async () => {
  let started = null;
  try { started = await startIsolatedCia({ wrapper: true, entry: 'mode3_zkwrapper.js', readyTimeoutMs: 8000, env: { ...ENV, CIA_PUBLIC_URL: 'http://127.0.0.1:{port}' } }); }
  catch (e) { assert.match(e.message, /IP 가 아닌 호스트/); return; }
  await started.stop(); assert.fail('IP 오리진인데 떴다');
});
console.log(fails ? `\n${fails} 실패` : '\n모두 통과');
process.exit(fails ? 1 : 0);
