// Mode 3 데모 스택 전 구간(HTTP): 격리 CIA + 지갑 에이전트 + RP. 스펙 §6 시연 각본 8단계 + challenge 음성. (chain 그룹)
//   node tests/test_mode3_demo_stack.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { VKEY_PATH } from '../lib/mode3_wallet.js';

const j = (o) => JSON.stringify(o);
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

// vkey 는 스택을 띄우기 전에 확인한다 — 없으면 자식 프로세스를 고아로 남기지 않고 바로 죽는다.
assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);

// 만료 테스트용 짧은 TTL. 단 첫 로그인(발급+증명, 1~3초)이 TTL 안에 끝나야 하므로 너무 짧게 잡지 않는다.
const stack = await startIsolatedMode3Stack({ rpEnv: { MODE3_CHALLENGE_TTL_MS: '6000' } });
const { cia, wallet, rp } = stack;
const uid = '12345';

/** 브라우저의 RP 페이지가 하는 일을 그대로: rp_info → challenge → 지갑 login → RP login. */
async function loginViaRp({ skipSync = false } = {}) {
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const { challenge } = (await rp.post('/api/mode3/challenge')).body;
  const w = await wallet.post('/wallet/login', { arid: info.arid, challenge, skipSync }, { Origin: rp.origin });
  if (w.status !== 200) return { walletStatus: w.status, wallet: w.body };
  const r = await rp.post('/api/mode3/login', { challenge, proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig });
  return { walletStatus: 200, wallet: w.body, rpStatus: r.status, rp: r.body };
}

try {
  await t('rp_info: arid·logAddress·walletAgentOrigin, pk_CIA 는 TOFU', async () => {
    const r = await rp.get('/api/mode3/rp_info');
    assert.equal(r.status, 200);
    assert.equal(r.body.arid, '22222222222222222222');
    assert.equal(r.body.logAddress, cia.logAddress);
    assert.equal(r.body.walletAgentOrigin, wallet.origin);
    assert.equal(r.body.pkCiaSource, 'tofu');
  });

  await t('1. 등록', async () => {
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123' })).status, 201);
  });

  let PPID1, firstSignals;
  await t('2. 로그인: 자동 발급 + RP ok, PPID', async () => {
    const r = await loginViaRp();
    assert.equal(r.walletStatus, 200, j(r));
    assert.equal(r.wallet.issued, true);
    assert.equal(r.rpStatus, 200);
    assert.equal(r.rp.ok, true, j(r.rp));
    assert.match(r.rp.PPID, /^[0-9]+$/);
    PPID1 = r.rp.PPID; firstSignals = r.wallet.publicSignals;
  });

  await t('3. 로그인 (다시): 캐시 히트, 같은 PPID', async () => {
    const r = await loginViaRp();
    assert.equal(r.wallet.cacheHit, true);
    assert.equal(r.rp.ok, true, j(r.rp));
    assert.equal(r.rp.PPID, PPID1);
    const l = await rp.get('/api/mode3/logins');
    assert.equal(l.body.logins.length, 2);
  });

  await t('4. 계정 폐기 + 게시', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'account' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
  });

  await t('5. skipSync 로그인 → RP stale_root', async () => {
    const r = await loginViaRp({ skipSync: true });
    assert.equal(r.walletStatus, 200, j(r));
    assert.deepEqual(r.wallet.publicSignals, firstSignals);
    assert.equal(r.rp.ok, false);
    assert.equal(r.rp.reason, 'stale_root');
  });

  await t('6. 동기화 로그인 → 지갑 403 account_disabled (RP 까지 안 간다)', async () => {
    const r = await loginViaRp();
    assert.equal(r.walletStatus, 403, j(r));
    assert.equal(r.wallet.reason, 'account_disabled');
  });

  await t('7. 복구', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
  });

  await t('8. 로그인: 재발급 + RP ok, PPID 동일', async () => {
    const r = await loginViaRp();
    assert.equal(r.walletStatus, 200, j(r));
    assert.equal(r.wallet.issued, true);
    assert.equal(r.rp.ok, true, j(r.rp));
    assert.equal(r.rp.PPID, PPID1);
  });

  await t('challenge 음성: 미발급 → 401, 재사용 → 401', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const { challenge } = (await rp.post('/api/mode3/challenge')).body;
    const w = (await wallet.post('/wallet/login', { arid: info.arid, challenge })).body;
    const body = { challenge, proof: w.proof, publicSignals: w.publicSignals, sig: w.sig };
    const fake = await rp.post('/api/mode3/login', { ...body, challenge: 'deadbeef'.repeat(8) });
    assert.equal(fake.status, 401);
    assert.equal(fake.body.reason, 'bad_challenge');
    assert.equal((await rp.post('/api/mode3/login', body)).body.ok, true);
    const again = await rp.post('/api/mode3/login', body);
    assert.equal(again.status, 401);
    assert.equal(again.body.reason, 'bad_challenge');
  });

  await t('challenge 음성: 만료(TTL 6s) → 401', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const { challenge } = (await rp.post('/api/mode3/challenge')).body;
    const w = (await wallet.post('/wallet/login', { arid: info.arid, challenge })).body;
    await new Promise((r) => setTimeout(r, 6500));
    const r = await rp.post('/api/mode3/login', { challenge, proof: w.proof, publicSignals: w.publicSignals, sig: w.sig });
    assert.equal(r.status, 401);
    assert.equal(r.body.reason, 'bad_challenge');
  });

  await t('challenge 음성: 다른 challenge 에 대한 σ → bad_signature (challenge 는 소비됨)', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const a = (await rp.post('/api/mode3/challenge')).body.challenge;
    const b = (await rp.post('/api/mode3/challenge')).body.challenge;
    const w = (await wallet.post('/wallet/login', { arid: info.arid, challenge: a })).body;
    const r = await rp.post('/api/mode3/login', { challenge: b, proof: w.proof, publicSignals: w.publicSignals, sig: w.sig });
    assert.equal(r.status, 200);
    assert.equal(r.body.ok, false);
    assert.equal(r.body.reason, 'bad_signature');
    // b 는 실패했어도 소비됐다 — 같은 b 로 다시 오면 bad_challenge
    const again = await rp.post('/api/mode3/login', { challenge: b, proof: w.proof, publicSignals: w.publicSignals, sig: w.sig });
    assert.equal(again.status, 401);
  });

  await t('login 입력 검증: 필드 누락 → 400', async () => {
    assert.equal((await rp.post('/api/mode3/login', { challenge: 'x' })).status, 400);
  });

  await t('페이지 서빙: 지갑 /, RP /, CIA /admin 이 text/html', async () => {
    for (const [c, p, marker] of [[wallet, '/', 'Mode 3 지갑'], [rp, '/', 'Mode 3 로그인'], [cia, '/admin', 'CIA 관리자']]) {
      const r = await fetch(`${c.base}${p}`);
      assert.equal(r.status, 200, `${p}`);
      assert.match(r.headers.get('content-type') ?? '', /text\/html/);
      assert.ok((await r.text()).includes(marker), `${p} 에 "${marker}" 가 있어야 한다`);
    }
  });
} finally {
  await stack.stop();
}
process.exit(failed === 0 ? 0 : 1);
