// tests/test_cia_admin_open.mjs — 데모 설정 CIA_ADMIN_OPEN=1(2026-10-21): 관리자 경로가 시크릿을 묻지 않는다. 기본(끔)은 지금처럼 401.
// 폐기 경로는 관리자 헤더가 있는 요청만 관리자로 본다(헤더 없는 사용자 본인 서명 요청과 가르기 위해). 격리 IdP 만 띄운다. (chain)
import assert from 'node:assert/strict';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.message); } }
const revoke = (cia, body, headers = {}) => fetch(`${cia.base}/cia/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) }).then((r) => r.status);
const closed = await startIsolatedCia();
const open = await startIsolatedCia({ env: { CIA_ADMIN_OPEN: '1' } });
const openNoSecret = await startIsolatedCia({ env: { CIA_ADMIN_OPEN: '1', CIA_ADMIN_SECRET: '' } });
try {
  await t('기본(끔): 시크릿 없는 관리자 목록은 401, 맞는 시크릿은 200, 폐기(account)는 시크릿이 없거나 자리표시 값이면 401', async () => {
    assert.equal((await closed.get('/cia/rps')).status, 401);
    assert.equal((await closed.adminGet('/cia/rps')).status, 200);
    assert.equal(await revoke(closed, { uid: '1', scope: 'account' }), 401);
    assert.equal(await revoke(closed, { uid: '1', scope: 'account' }, { 'X-CIA-Admin-Secret': 'open' }), 401, '자리표시 값은 시크릿이 아니다');
  });
  await t('CIA_ADMIN_OPEN=1: 시크릿 없이 관리자 목록이 200(rps·accounts·openings)', async () => {
    for (const p of ['/cia/rps', '/cia/accounts', '/cia/openings']) assert.equal((await open.get(p)).status, 200, p);
  });
  await t('CIA_ADMIN_OPEN=1: 폐기(account)는 헤더가 있을 때만 관리자 — 없으면 401, 자리표시 헤더면 인증을 지나 모르는 계정 404', async () => {
    assert.equal(await revoke(open, { uid: '1', scope: 'account' }), 401);
    assert.equal(await revoke(open, { uid: '1', scope: 'account' }, { 'X-CIA-Admin-Secret': 'open' }), 404);
  });
  await t('CIA_ADMIN_OPEN=1 이면 CIA_ADMIN_SECRET 이 비어도 503 이 아니라 200', async () => {
    assert.equal((await openNoSecret.get('/cia/rps')).status, 200);
  });
} finally { await closed.stop(); await open.stop(); await openNoSecret.stop(); }
if (fails) { console.log(`\n${fails} FAIL`); process.exit(1); } else console.log('\nall ok');
