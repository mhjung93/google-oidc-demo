// tests/test_cia_cors.mjs — IdP 가 사용자 오리진(MODE3_WALLET_AGENT_ORIGIN)에 여는 CORS(스펙 2026-10-15 §5.3). 격리 IdP 만 띄운다. (chain)
import assert from 'node:assert/strict';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
const USER = 'http://127.0.0.1:5199';
const cia = await startIsolatedCia({ env: { MODE3_WALLET_AGENT_ORIGIN: USER } });
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.message); } }
const pre = (p, origin, method = 'POST', headers = 'content-type') => fetch(`${cia.base}${p}`, { method: 'OPTIONS', headers: { Origin: origin, 'Access-Control-Request-Method': method, 'Access-Control-Request-Headers': headers } });
const h = (r, k) => r.headers.get(k);
try {
  await t('프리플라이트: 5 POST 라우트가 사용자 오리진에 ACAO·POST·Content-Type 을 허용한다', async () => {
    for (const p of ['/cia/register', '/cia/issue', '/cia/slot', '/cia/revoke', '/cia/account/self_revoke']) {
      const r = await pre(p, USER);
      assert.ok([200, 204].includes(r.status), `${p} ${r.status}`);
      assert.equal(h(r, 'access-control-allow-origin'), USER, p);
      assert.match(h(r, 'access-control-allow-methods') ?? '', /POST/, p);
      assert.match((h(r, 'access-control-allow-headers') ?? '').toLowerCase(), /content-type/, p);
      assert.ok(!(h(r, 'access-control-allow-headers') ?? '').toLowerCase().includes('x-cia-admin-secret'), `${p} 관리자 헤더는 허용하지 않는다`);
    }
  });
  await t('실제 요청: public_keys·attr_schema GET 과 register POST(400 이어도) 에 ACAO 가 붙고 Vary: Origin', async () => {
    for (const p of ['/cia/public_keys', '/cia/attr_schema']) { const r = await fetch(`${cia.base}${p}`, { headers: { Origin: USER } }); assert.equal(r.status, 200); assert.equal(h(r, 'access-control-allow-origin'), USER, p); assert.match(h(r, 'vary') ?? '', /Origin/); }
    const r = await fetch(`${cia.base}/cia/register`, { method: 'POST', headers: { Origin: USER, 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(r.status, 400); assert.equal(h(r, 'access-control-allow-origin'), USER);
  });
  await t('다른 오리진에는 ACAO 가 없다(프리플라이트·실제 요청 모두)', async () => {
    for (const o of ['http://evil.example', 'http://127.0.0.1:5198', USER + '/']) {
      assert.equal(h(await pre('/cia/issue', o), 'access-control-allow-origin'), null, o);
      assert.equal(h(await fetch(`${cia.base}/cia/public_keys`, { headers: { Origin: o } }), 'access-control-allow-origin'), null, o);
    }
  });
  await t('관리자 라우트에는 사용자 오리진이어도 CORS 가 없다', async () => {
    for (const [p, m] of [['/cia/rps', 'GET'], ['/cia/admin/relay', 'POST'], ['/cia/admin/registry', 'GET']]) {
      assert.equal(h(await pre(p, USER, m, 'content-type,x-cia-admin-secret'), 'access-control-allow-origin'), null, p);
      assert.equal(h(await fetch(`${cia.base}${p}`, { method: m, headers: { Origin: USER } }), 'access-control-allow-origin'), null, p);
    }
  });
  await t('/cia/revoke 의 scope=session 사용자 서명 경로는 CORS 를 타고(400 bad user signature), 관리자 헤더가 실린 교차 요청은 프리플라이트가 막는다', async () => {
    const r = await fetch(`${cia.base}/cia/revoke`, { method: 'POST', headers: { Origin: USER, 'Content-Type': 'application/json' }, body: JSON.stringify({ uid: '12345', scope: 'session', Cf_s: '1', sig_u: { R8x: '1', R8y: '1', S: '1' }, nonce: '1' }) });
    assert.equal(h(r, 'access-control-allow-origin'), USER); assert.ok([400, 404].includes(r.status));
    const p = await pre('/cia/revoke', USER, 'POST', 'content-type,x-cia-admin-secret');
    // cors 패키지는 요청한 헤더를 그대로 돌려주지 않고 설정값(Content-Type)만 돌려준다 — 브라우저가 x-cia-admin-secret 을 거절한다.
    assert.ok(!(h(p, 'access-control-allow-headers') ?? '').toLowerCase().includes('x-cia-admin-secret'));
  });
} finally { await cia.stop(); }
process.exit(fails ? 1 : 0);
