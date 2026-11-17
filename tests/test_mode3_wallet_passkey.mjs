// passkey 모드 지갑 에이전트 — 스펙 2026-11-17-mode3-passkey-mode §3. 페이지가 패스키 PRF 로 만들 salt 는
// tests/helpers/snap_sim.mjs 의 salt 로 대신한다(에이전트는 salt 의 출처를 모른다). hardhat :8545 필요. (chain 그룹)
//   node tests/test_mode3_wallet_passkey.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { createReadySnapSim } from './helpers/snap_sim.mjs';
import { VKEY_PATH } from '../lib/mode3_wallet.js';
import { auidOf } from '../lib/mode3_credential.js';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); }
}

// tests/test_mode3_wallet_snap.mjs 와 같은 쿠키 jar — /cia/user/login → /cia/user/register_code.
function makeJar(base) {
  const jar = {};
  return async (p, init = {}) => {
    const r = await fetch(`${base}${p}`, { ...init, headers: { 'Content-Type': 'application/json', ...(jar.cookie ? { Cookie: jar.cookie } : {}), ...(init.headers ?? {}) } });
    const sc = r.headers.get('set-cookie');
    if (sc) jar.cookie = sc.split(';')[0];
    return { status: r.status, body: await r.json().catch(() => null) };
  };
}

assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);

// 스택보다 먼저: IP 오리진이면 passkey 모드는 뜨지 않는다(P6). 상단에서 던지므로 체인·IdP 없이도 끝난다.
await t('IP 오리진이면 passkey 모드 기동 거부', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pk-origin-'));
  const emptyEnv = path.join(dir, 'empty.env'); fs.writeFileSync(emptyEnv, '');
  const r = spawnSync(process.execPath, ['mode3_wallet_agent.js'], {
    env: { PATH: process.env.PATH, DOTENV_CONFIG_PATH: emptyEnv, MODE3_WALLET_SECRETS: 'passkey', MODE3_WALLET_PORT: '59991', MODE3_WALLET_PUBLIC_ORIGIN: 'http://127.0.0.1:59991', MODE3_WALLET_STATE_FILE: path.join(dir, 's.json') },
    encoding: 'utf8', timeout: 20000,
  });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.notEqual(r.status, 0, `종료 코드 ${r.status}`);
  assert.match(r.stderr, /localhost/);
});

const stack = await startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'passkey' }, walletHost: 'localhost' });
const { cia, wallet, rp } = stack;
const sim = createReadySnapSim();   // salt 공급원 대역 — 페이지의 패스키 PRF 자리
const S_U = sim.state.salt.s_u;

try {
  const stateFile = () => fs.readFileSync(stack.walletStateFile, 'utf8');
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const same = { 'Sec-Fetch-Site': 'same-origin' };
  const pkState = async () => { const r = await wallet.get('/wallet/passkey/state', same); assert.equal(r.status, 200, j(r.body)); return r.body; };
  /** 패스키 어댑터(consentLogin)가 하는 증인 조립 — 에이전트의 공개 등록 + userCred(blind_u 포함) + 패스키 salt. */
  const witnessFrom = async () => { const st = await pkState(); return { uid: st.registration.uid, s_u: S_U, attrs: st.registration.attrs, userCred: st.userCred }; };
  const loginBase = async () => {
    const ch = (await rp.post('/api/mode3/challenge')).body;
    return { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, allowAgent: '0', factoryAddress: ch.factoryAddress, attrGateAddress: ch.attrGateAddress, verifiedOrigin: info.origin };
  };

  await t('config 가 passkey 를 알린다', async () => {
    const r = await wallet.get('/wallet/config');
    assert.equal(r.status, 200); assert.equal(r.body.secrets, 'passkey'); assert.equal(r.body.snapId, null);
    assert.match(r.body.walletOrigin, /^http:\/\/localhost:/);
  });

  await t('credential 라우트: 저장·같은 값 200·다른 값 409·cross-site 403 bad_origin·형식 400', async () => {
    assert.equal((await pkState()).passkey, null);
    assert.equal((await wallet.put('/wallet/passkey/credential', { credentialId: 'not base64url!' }, same)).status, 400);
    const a = await wallet.put('/wallet/passkey/credential', { credentialId: 'AAECAwQ' }, same);
    assert.equal(a.status, 200, j(a.body));
    assert.equal((await pkState()).passkey.credentialId, 'AAECAwQ');
    assert.equal((await wallet.put('/wallet/passkey/credential', { credentialId: 'AAECAwQ' }, same)).status, 200);
    const b = await wallet.put('/wallet/passkey/credential', { credentialId: 'BBBB' }, same);
    assert.equal(b.status, 409, j(b.body)); assert.equal(b.body.reason, 'passkey_already_set');
    const x = await wallet.get('/wallet/passkey/state', { 'Sec-Fetch-Site': 'cross-site' });
    assert.equal(x.status, 403, j(x.body)); assert.equal(x.body.reason, 'bad_origin', '지갑 전역 오리진 정책(리뷰 D2)이 막는다');
  });

  let S1 = null, SLOT1 = null;
  await t('가입·로그인은 증인을 요구하고 s_u 를 파일에 쓰지 않는다; blind_u 는 파일에 있다', async () => {
    const withJar = makeJar(cia.base);
    assert.equal((await withJar('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid: '12345', pwd: 'password123' }) })).status, 200);
    const code = (await withJar('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) })).body.code;
    assert.equal((await wallet.post('/wallet/register', { uid: '12345', code })).status, 400, 'passkey 모드도 s_u 필수');
    const reg = await wallet.post('/wallet/register', { uid: '12345', code, s_u: S_U });
    assert.equal(reg.status, 201, j(reg.body));
    SLOT1 = reg.body.slot; assert.equal('restored' in reg.body, false, '첫 등록에는 restored 가 없다');
    const base = await loginBase();
    const noW = await wallet.post('/wallet/login', base);
    assert.equal(noW.status, 400, j(noW.body)); assert.equal(noW.body.reason, 'witness_required');
    const w = await witnessFrom();
    assert.equal(w.userCred, null, '첫 로그인 전에는 C_u 가 없다');
    const ok = await stack.withRelay(() => wallet.post('/wallet/login', { ...base, witness: w }, { Origin: wallet.origin }));
    assert.equal(ok.status, 200, j(ok.body));
    S1 = base.r_s;
    const st = await pkState();
    assert.match(st.userCred?.blind_u ?? '', /^[0-9]+$/, '에이전트가 새 C_u 의 blind_u 를 저장한다(P4)');
    assert.equal(st.userCred.Cf_u, ok.body.userCredIssued.Cf_u);
    const file = stateFile();
    assert.equal(file.includes(S_U), false, 's_u 가 상태 파일에 있다');
    assert.equal(file.includes('"witness"'), false);
    // 두 번째 로그인은 저장된 C_u 를 재사용한다
    const base2 = await loginBase();
    const r2 = await wallet.post('/wallet/login', { ...base2, witness: await witnessFrom() }, { Origin: wallet.origin });
    assert.equal(r2.status, 200, j(r2.body)); assert.equal('userCredIssued' in r2.body, false);
  });

  await t('등록이 있으면 패스키 연결 끊기 409 registered', async () => {
    const d = await wallet.raw('/wallet/passkey/credential', { method: 'DELETE', headers: same });
    assert.equal(d.status, 409); assert.equal((await d.json()).reason, 'registered');
  });

  await t('동의 기록', async () => {
    const c = await wallet.post('/wallet/passkey/consent', { origin: info.origin, arid: info.arid, allowAgent: '1' }, same);
    assert.equal(c.status, 200, j(c.body));
    const st = await pkState();
    assert.equal(st.consents[info.origin].allowAgent, '1'); assert.equal(st.consents[info.origin].arid, String(info.arid));
    assert.equal((await wallet.post('/wallet/passkey/consent', { origin: info.origin, arid: info.arid, allowAgent: 'x' }, same)).status, 400);
  });

  await t('재시작 뒤 session_restore_required(needs_consent 아님), 세션 증인으로 복구', async () => {
    const { attrGateAddress } = (await rp.get('/api/mode3/rp_info')).body;
    const before = (await wallet.get('/wallet/status')).body;
    assert.equal(before.sessions[S1].hasWitness, true);
    await stack.restartWallet();
    const s = (await wallet.get('/wallet/status')).body;
    assert.equal(s.sessions[S1].hasWitness, false);
    const rv = await wallet.post('/wallet/revalidate', { r_s: S1 }, { Origin: rp.origin });
    assert.equal(rv.status, 409, j(rv.body)); assert.equal(rv.body.reason, 'session_restore_required');
    const pre = await wallet.post('/wallet/tx/prepare', { r_s: S1, to: attrGateAddress });
    assert.equal(pre.status, 409, j(pre.body)); assert.equal(pre.body.reason, 'session_restore_required');
    const tx = await wallet.post('/wallet/tx', { r_s: S1, to: attrGateAddress, value: '0' }, { Origin: wallet.base });
    assert.equal(tx.status, 409, j(tx.body)); assert.equal(tx.body.reason, 'session_restore_required', 'passkey 모드의 /wallet/tx 는 use_tx_prepare 가 아니다(R-B)');
    const rq = await wallet.post('/wallet/request', { r_s: S1, body: 'hello' }, { Origin: rp.origin });
    assert.equal(rq.status, 200, `증인이 필요 없는 /wallet/request 는 그대로: ${j(rq.body)}`);
    const sw = await wallet.post('/wallet/session/witness', { r_s: S1, witness: await witnessFrom(), allowAgent: '0' });
    assert.equal(sw.status, 200, j(sw.body));
    assert.equal((await wallet.get('/wallet/status')).body.sessions[S1].hasWitness, true);
    const rv2 = await wallet.post('/wallet/revalidate', { r_s: S1 }, { Origin: rp.origin });
    assert.equal(rv2.status, 200, j(rv2.body));
    assert.equal(stateFile().includes(S_U), false, '복구 뒤에도 s_u 는 파일에 없다');
  });

  await t('세션 폐기도 증인이 없으면 session_restore_required', async () => {
    await stack.restartWallet();
    const r = await wallet.post('/wallet/session/revoke', { r_s: S1 });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'session_restore_required');
  });

  // 리뷰 I-2(스펙 §4.2): 등록이 있는데 연결된 패스키가 없으면(다른 모드의 상태 파일 등) 고른 패스키의 salt 를 auid 로 대조한다 — 다르면 passkey_mismatch.
  // 그 상태를 상태 파일로 만든다(연결 끊기는 등록이 있으면 409 라 API 로는 못 만든다): passkey 를 비우고 재시작.
  await t('등록이 있으면 패스키 연결은 auid 대조: s_u 없음·다른 salt 는 409 passkey_mismatch, 같은 salt 는 200(s_u 는 저장하지 않는다)', async () => {
    const st0 = JSON.parse(stateFile()); assert.ok(st0.registration, '등록이 있어야 한다');
    st0.passkey = null; fs.writeFileSync(stack.walletStateFile, JSON.stringify(st0));
    await stack.restartWallet();
    assert.equal((await pkState()).passkey, null);
    const noSu = await wallet.put('/wallet/passkey/credential', { credentialId: 'CCCC' }, same);
    assert.equal(noSu.status, 409, j(noSu.body)); assert.equal(noSu.body.reason, 'passkey_mismatch');
    const other = await wallet.put('/wallet/passkey/credential', { credentialId: 'CCCC', s_u: createReadySnapSim().state.salt.s_u }, same);
    assert.equal(other.status, 409, j(other.body)); assert.equal(other.body.reason, 'passkey_mismatch');
    assert.equal((await pkState()).passkey, null, '거절된 패스키는 연결하지 않는다');
    const ok = await wallet.put('/wallet/passkey/credential', { credentialId: 'AAECAwQ', s_u: S_U }, same);
    assert.equal(ok.status, 200, j(ok.body));
    assert.equal((await pkState()).passkey.credentialId, 'AAECAwQ');
    assert.equal(stateFile().includes(S_U), false, '대조에 쓴 s_u 는 저장하지 않는다');
  });

  await t('데모 리셋은 등록·동의를 지우고 패스키 연결은 남긴다; 그 뒤 연결 끊기 200', async () => {
    const rs = await wallet.post('/wallet/reset', { confirm: true });
    assert.equal(rs.status, 200, j(rs.body));
    const st = await pkState();
    assert.equal(st.registration, null); assert.deepEqual(st.consents, {}); assert.equal(st.passkey.credentialId, 'AAECAwQ');
    const d = await wallet.raw('/wallet/passkey/credential', { method: 'DELETE', headers: same });
    assert.equal(d.status, 200);
    assert.equal((await pkState()).passkey, null);
  });

  // 스펙 §10 P15: 계정 복구 — 같은 계정·같은 auid 로 다시 등록하면 IdP 가 기존 슬롯을 돌려주고(restored), 에이전트가 그 표시를 싣는다.
  await t('같은 auid 로 다시 등록하면 restored: true, 같은 slot', async () => {
    assert.equal((await wallet.get('/wallet/status')).body.registered, false, '앞 케이스가 등록을 비웠다');
    const auid = (await auidOf({ s_u: BigInt(S_U) })).toString();
    const ac = await fetch(`${cia.base}/cia/auth/code`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ uid: '12345', pwd: 'password123', auid, purpose: 'register' }) });
    const acBody = await ac.json(); assert.equal(ac.status, 200, j(acBody));
    const r = await wallet.post('/wallet/register', { uid: '12345', code: acBody.code, s_u: S_U });
    assert.equal(r.status, 201, j(r.body));
    assert.equal(r.body.restored, true); assert.equal(r.body.slot, SLOT1, '같은 슬롯');
  });
} finally {
  await stack.stop();
}

console.log(failed ? `\n${failed} failed` : '\nall passed');
// snarkjs 가 남기는 핸들 때문에 저절로 끝나지 않는다(다른 Mode 3 테스트와 같은 관례)
process.exit(failed === 0 ? 0 : 1);
