// Mode 3 지갑 에이전트 단독. RP 없이 검증기는 이 프로세스에서 조립한다. (chain 그룹)
//   node tests/test_mode3_wallet_agent.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { VKEY_PATH } from '../lib/mode3_wallet.js';
import { createRpVerifier } from '../lib/mode3_rp.js';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

// vkey 는 스택을 띄우기 전에 읽는다 — 없으면 자식 프로세스를 고아로 남기지 않고 바로 죽는다.
assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = getProvider();
const stack = await startIsolatedMode3Stack({ rp: false });
const { cia, wallet } = stack;
const uid = '12345', arid = '22222222222222222222';

try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  const rp = createRpVerifier({ provider, logAddress: cia.logAddress, vkey, pkCIA: pk_CIA, arid: BigInt(arid), chainId: 31337n });

  async function verify(body, challenge) {
    return rp.verifyLogin({ proof: body.proof, publicSignals: body.publicSignals, challenge, sig: body.sig });
  }

  await t('미등록 상태: status.registered=false, login 은 409 not_registered', async () => {
    const s = await wallet.get('/wallet/status');
    assert.equal(s.status, 200);
    assert.equal(s.body.registered, false);
    const r = await wallet.post('/wallet/login', { arid, challenge: 'c0' });
    assert.equal(r.status, 409);
    assert.equal(r.body.reason, 'not_registered');
  });

  await t('등록: 201, 두 번째는 409, 잘못된 pwd 는 CIA 의 401 을 그대로', async () => {
    const r = await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['19', '410', '0', '0'] });
    assert.equal(r.status, 201, j(r.body));
    assert.deepEqual(r.body, { uid });
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123' })).status, 409);
    const s = await wallet.get('/wallet/status');
    assert.equal(s.body.registered, true);
    assert.equal(s.body.uid, uid);
  });

  let first, PPID1;
  await t('첫 로그인: 자동 발급(issued=true) + 검증 통과, 응답에 uid 없음', async () => {
    const challenge = 'login-1';
    const r = await wallet.post('/wallet/login', { arid, challenge });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, true);
    assert.equal(r.body.cacheHit, false);
    assert.ok(!('uid' in r.body), 'uid 는 RP 로 나가면 안 된다');
    assert.equal(typeof r.body.timings.proveMs, 'number');
    assert.equal(r.body.publicSignals.length, 8);
    assert.equal(r.body.publicSignals[4], '31337');
    const v = await verify(r.body, challenge);
    assert.equal(v.ok, true, j(v));
    first = r.body; PPID1 = v.PPID;
    const s = await wallet.get('/wallet/status');
    assert.ok(s.body.credentials[arid], 'arid 별 credential 이 상태에 있어야 한다');
    assert.equal(s.body.cachedProofRoot, r.body.root);
  });

  await t('두 번째 로그인: 캐시 히트(cacheHit=true, issued=false), publicSignals 동일, σ 만 새로', async () => {
    const challenge = 'login-2';
    const r = await wallet.post('/wallet/login', { arid, challenge });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, false);
    assert.equal(r.body.cacheHit, true);
    assert.deepEqual(r.body.publicSignals, first.publicSignals);
    assert.notEqual(r.body.sig, first.sig);
    assert.equal((await verify(r.body, challenge)).ok, true);
  });

  await t('CORS: RP 오리진에만 Access-Control-Allow-Origin, 다른 오리진엔 없음', async () => {
    const good = await wallet.raw('/wallet/login', { method: 'OPTIONS', headers: { Origin: stack.rpOriginForWallet, 'Access-Control-Request-Method': 'POST' } });
    assert.equal(good.headers.get('access-control-allow-origin'), stack.rpOriginForWallet);
    const bad = await wallet.raw('/wallet/login', { method: 'OPTIONS', headers: { Origin: 'http://evil.example', 'Access-Control-Request-Method': 'POST' } });
    assert.equal(bad.headers.get('access-control-allow-origin'), null);
  });

  await t('계정 폐기 + 게시 → skipSync 로그인은 옛 π 를 그대로 → 검증기 stale_root', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'account' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const challenge = 'stale';
    const r = await wallet.post('/wallet/login', { arid, challenge, skipSync: true });
    assert.equal(r.status, 200, j(r.body));
    assert.deepEqual(r.body.publicSignals, first.publicSignals);
    const v = await verify(r.body, challenge);
    assert.equal(v.ok, false);
    assert.equal(v.reason, 'stale_root');
  });

  await t('동기화 로그인: 폐기 감지 → 재발급 시도 → CIA 403 → account_disabled', async () => {
    const r = await wallet.post('/wallet/login', { arid, challenge: 'after-revoke' });
    assert.equal(r.status, 403, j(r.body));
    assert.equal(r.body.reason, 'account_disabled');
  });

  await t('복구 → 로그인: 재발급(issued=true), 검증 통과, PPID 동일', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
    const challenge = 'after-recover';
    const r = await wallet.post('/wallet/login', { arid, challenge });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, true);
    const v = await verify(r.body, challenge);
    assert.equal(v.ok, true, j(v));
    assert.equal(v.PPID, PPID1, 'PPID 는 폐기·복구로 바뀌지 않는다');
  });

  await t('입력 검증: arid 비10진 / challenge 없음 → 400', async () => {
    assert.equal((await wallet.post('/wallet/login', { arid: '0x1', challenge: 'c' })).status, 400);
    assert.equal((await wallet.post('/wallet/login', { arid })).status, 400);
  });

  await t('status: credential 이 exptime(Unix 초)을 보여주고 max_height 는 없다', async () => {
    const s = await wallet.get('/wallet/status');
    const [, c] = Object.entries(s.body.credentials)[0];
    assert.match(String(c.exptime), /^[0-9]+$/);
    assert.equal(c.max_height, undefined);
    assert.ok(Number(c.exptime) > Math.floor(Date.now() / 1000));
  });

  await t('register: attrs 가 4개를 넘거나 10진이 아니면 400', async () => {
    // 이미 등록된 상태에서는 409 가 먼저이므로 형식 검사는 등록 앞에 있어야 한다 — 새 인스턴스 없이 확인하려면
    // 400 이 409 보다 먼저 나오는지를 본다.
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['1', '2', '3', '4', '5'] })).status, 400);
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['x'] })).status, 400);
  });
} finally {
  await stack.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
