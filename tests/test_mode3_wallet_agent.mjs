// Mode 3 지갑 에이전트 단독. RP 없이 검증기는 이 프로세스에서 조립한다. (chain 그룹)
//   node tests/test_mode3_wallet_agent.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { ethers } from 'ethers';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider, deployRevocationLog } from './helpers/mode3_chain.mjs';
import { VKEY_PATH, createRegistration } from '../lib/mode3_wallet.js';
import { createRpVerifier } from '../lib/mode3_rp.js';
import { randomScalar, SCALAR_MAX } from '../lib/mode3_credential.js';
import { deployVerifier, deployFactory, walletAt, walletInterface, LOGIN_COUNTER } from '../lib/mode3_onchain.js';
import { LOG_ABI, MODE3_MIRROR_ABI, MODE3_ROOTS_ABI } from '../lib/mode3_log.js';
import { setRoot } from '../lib/mode3_set_tree.js';
import { DEFAULT_ATTR_SCHEMA, encodeSlotValue } from '../lib/mode3_attr_schema.js';

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
const SECOND_RP_ORIGIN = 'http://127.0.0.1:3199';   // 두 번째 RP 오리진 — 서버는 안 띄운다(CORS 허용 목록만 시험)
const stack = await startIsolatedMode3Stack({ rp: false, ciaEnv: { CIA_HEARTBEAT_BLOCKS: '5', CIA_HEARTBEAT_POLL_MS: '300' }, extraRpOrigins: [SECOND_RP_ORIGIN] });
const { cia, wallet } = stack;
const uid = '12345';

try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  // 실제 RP 프로세스는 안 띄우지만, 지갑의 CORS 오리진(rpOriginForWallet)으로 IdP 에 RP 를 등록해
  // (arid, cert_s) 를 얻는다 — /wallet/login 이 요구하는 RP 인증 정보다.
  const { arid, cert_s, origin, pk_trace } = await cia.registerRp(stack.rpOriginForWallet);
  // V10(2026-10-02 Task 9): RP 는 대상 체인 거울만 읽는다(mode3_rp.js 와 같이) — 지갑의 π 도 거울의 (revRoot, regRoot) 다.
  const rp = createRpVerifier({ provider, logAddress: cia.mirrorAddress, vkey, pkCIA: pk_CIA, arid: BigInt(arid), chainId: 31337n, pkTrace: pk_trace });
  const mirrorC = new ethers.Contract(cia.mirrorAddress, MODE3_MIRROR_ABI, provider);
  const canonC = new ethers.Contract(cia.logAddress, MODE3_ROOTS_ABI, provider);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // 거울 릴레이(V10): 격리 IdP 는 릴레이 주기가 꺼져 있다 — 거울은 /cia/admin/relay 로만 오른다(stack.relay). 지갑은 새 자격증명
  // 뒤 거울이 내 리프를 실을 때까지 기다리므로, 기존 시나리오의 로그인은 거울이 뒤처졌을 때만 릴레이를 대신 눌러 주는 펌프와
  // 같이 돈다(login = stack.withRelay). 거울 지연 자체를 보는 케이스는 loginNoRelay 를 쓴다.
  const { relay, relayIfBehind } = stack;

  const newRs = () => randomScalar().toString();
  const newCh = () => ({ r_s: randomScalar().toString(), r_rp: randomScalar().toString() });
  const loginNoRelay = (ch = newCh(), extra = {}) => wallet.post('/wallet/login', { arid, origin, cert_s, pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }, r_s: ch.r_s, r_rp: ch.r_rp, ...extra }, { Origin: stack.rpOriginForWallet });
  const login = (ch = newCh(), extra = {}) => stack.withRelay(() => loginNoRelay(ch, extra));
  const revalidate = (r_s, extra = {}) => wallet.post('/wallet/revalidate', { r_s, ...extra }, { Origin: stack.rpOriginForWallet });
  const verify = (body, ch) => rp.verifyLogin({ proof: body.proof, publicSignals: body.publicSignals, sig: body.sig, r_s: BigInt(ch.r_s), r_rp: BigInt(ch.r_rp) });

  await t('미등록 상태: status.registered=false, login 은 409 not_registered', async () => {
    const s = await wallet.get('/wallet/status');
    assert.equal(s.status, 200);
    assert.equal(s.body.registered, false);
    const r = await login();
    assert.equal(r.status, 409);
    assert.equal(r.body.reason, 'not_registered');
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'wrong' })).status, 401, 'CIA 의 401 을 그대로');
    const badAttr = await wallet.post('/wallet/register', { uid, pwd: 'password123', profile: { birthYear: '1800', country: 'KR' } });
    assert.equal(badAttr.status, 400); assert.equal(badAttr.body.reason, 'bad_attr');
    assert.equal((await wallet.get('/wallet/status')).body.registered, false, '인코딩 실패는 CIA 에 등록하지 않는다');
    const salt = await wallet.get('/wallet/secrets/salt');
    assert.equal(salt.status, 409, j(salt.body)); assert.equal(salt.body.reason, 'not_registered');
  });

  await t('등록: profile 없이 → 기본 { 1990, KR }(201, 슬롯 0, auid); 두 번째는 409; 잘못된 pwd 는 IdP 의 401; /wallet/status 에 auid·attrs·profile·slot', async () => {
    const r = await wallet.post('/wallet/register', { uid, pwd: 'password123' });
    assert.equal(r.status, 201, j(r.body));
    assert.deepEqual(Object.keys(r.body).sort(), ['attrs', 'auid', 'profile', 'slot', 'uid']);
    assert.equal(r.body.uid, uid); assert.equal(r.body.slot, 0); assert.match(r.body.auid, /^[0-9]+$/);
    assert.deepEqual(r.body.attrs, ['1990', '410', '0', '0', '0', '0']); assert.deepEqual(r.body.profile, { birthYear: '1990', country: 'KR' });
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123' })).status, 409);
    assert.equal((await wallet.post('/wallet/register', { uid: '67890', pwd: 'wrong' })).status, 409, '지갑은 한 계정만 — 등록된 뒤에는 CIA 를 부르지 않는다');
    const s = await wallet.get('/wallet/status');
    assert.equal(s.body.registered, true); assert.equal(s.body.uid, uid); assert.equal(s.body.slot, 0); assert.equal(s.body.auid, r.body.auid);
    assert.deepEqual(s.body.attrs, ['1990', '410', '0', '0', '0', '0']); assert.deepEqual(s.body.profile, { birthYear: '1990', country: 'KR' });
    assert.equal(s.body.registry, null, '아직 동기화 전');
    const sch = (await cia.get('/cia/attr_schema')).body;
    assert.deepEqual(s.body.attrSchema, { id: 'zkd-attrs', version: 1, hash: sch.hash });
    assert.deepEqual(s.body.attrsView.map((v) => v.display), ['1990', 'KR', '', '', '', '']);
    const acct = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === uid);
    assert.equal(acct.attrs, undefined, 'D15: IdP 는 속성을 받지 않는다'); assert.equal(acct.auid, undefined, '/cia/accounts 는 auid 를 내지 않아도 된다(계획: 공개 필드 아님)');
    // Task 13: file 모드는 등록 뒤 /wallet/secrets/salt 로 s_u(10진 문자열)를 본다 — 같은 오리진 전용이라 CORS 는 열지 않는다.
    const salt = await wallet.get('/wallet/secrets/salt');
    assert.equal(salt.status, 200, j(salt.body)); assert.match(salt.body.s_u, /^[0-9]+$/);
  });

  let first, PPID1, S1;
  await t('첫 로그인: 자동 발급(issued=true) + 검증 통과, 응답에 uid 없음', async () => {
    const ch = newCh();
    const r = await login(ch);
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, true);
    assert.equal(r.body.cacheHit, false);
    assert.equal(r.body.r_s, ch.r_s);
    assert.ok(!('uid' in r.body), 'uid 는 RP 로 나가면 안 된다');
    assert.equal(typeof r.body.timings.proveMs, 'number');
    assert.equal(r.body.publicSignals.length, 34, 'V11: 30 + auid_s·arid_s·r_s·counter');
    assert.equal(r.body.publicSignals[32], ch.r_s);
    assert.equal(r.body.publicSignals[33], LOGIN_COUNTER.toString(), '로그인은 counter=LOGIN_COUNTER');
    assert.equal(r.body.publicSignals[4], '31337');
    assert.equal(r.body.allowAgent, '0'); assert.equal(r.body.publicSignals[5], '0');
    const v = await verify(r.body, ch);
    assert.equal(v.ok, true, j(v));
    first = r.body; PPID1 = v.PPID; S1 = ch;
    assert.ok(r.body.timings.userCredMs > 0, '첫 로그인은 사용자 자격증명을 새로 받는다');
    assert.equal((await wallet.post('/wallet/login', { arid, origin, cert_s, pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }, r_s: newCh().r_s }, { Origin: stack.rpOriginForWallet })).status, 400, 'r_rp 없으면 400');
    const s = await wallet.get('/wallet/status');
    assert.ok(s.body.sessions[ch.r_s], 'r_s 별 세션이 상태에 있어야 한다');
    assert.ok(s.body.userCred?.Cf_u, '사용자 자격증명이 상태에 있어야 한다');
    assert.equal(s.body.userCred.revoked, false);
    // V9 §8.2: 등록부 확인 — 내 슬롯(0)의 리프가 내 자격증명과 같아야 한다.
    assert.equal(s.body.registry.match, true);
    assert.equal(s.body.registry.slot, 0);
    assert.equal(s.body.registry.leaf, s.body.registry.expected);
    // 격리 스택은 임시 디렉터리라 캐시 파일이 없는 상태에서 시작한다 — 콜드 스타트 첫 syncAll() 은 bootstrap 이다.
    // V9: 첫 로그인은 사용자 자격증명도 새로 받으므로(fresh) 슬롯이 게시될 때까지 다시 syncAll() 을 돈다(§8.3) —
    // 그 두 번째 rcl.sync() 는 이미 메모리에 있는 트리에 대한 것이라 lastMode 는 delta 로 끝난다.
    assert.equal(s.body.rcl.lastMode, 'delta', '첫 로그인은 fresh 라 등록부 게시를 기다리며 한 번 더 동기화한다');
  });

  let S1b;
  await t('두 번째 로그인(새 r_s): 사용자 자격증명 재사용 → userCredMs=0, 세션만 새로 발급', async () => {
    const ch = newCh();
    const r = await login(ch);
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, true);
    assert.equal(r.body.timings.userCredMs, 0);
    assert.equal((await verify(r.body, ch)).ok, true);
    S1b = ch.r_s;
  });

  // 2026-09-23 점검 B-I1: precheck 의 r_s 분기(재승인 동의 창이 쓸 세션의 실제 allowAgent). 라우트에 모드 분기가 없어
  // snap 테스트와 같은 코드를 타지만, file 모드에서도 돈다는 것을 여기서 못 박는다(리뷰 Minor 7).
  await t('precheck: r_s 를 주면 그 세션의 allowAgent 를 돌려주고, 모르는 r_s 는 404 no_session', async () => {
    const pkt = { x: pk_trace.x.toString(), y: pk_trace.y.toString() };
    const chC = newCh();
    assert.equal((await login(chC, { allowAgent: '1' })).status, 200);
    const S1c = chC.r_s;
    const base = { arid, origin, cert_s, pk_trace: pkt };
    const noRs = await wallet.post('/wallet/authorize/precheck', base);
    assert.equal(noRs.status, 200, j(noRs.body)); assert.equal('sessionAllowAgent' in noRs.body, false, 'r_s 가 없으면 세션 값을 싣지 않는다');
    const one = await wallet.post('/wallet/authorize/precheck', { ...base, r_s: S1c });
    assert.equal(one.status, 200, j(one.body)); assert.equal(one.body.sessionAllowAgent, '1');
    const zero = await wallet.post('/wallet/authorize/precheck', { ...base, r_s: S1.r_s });
    assert.equal(zero.status, 200, j(zero.body)); assert.equal(zero.body.sessionAllowAgent, '0');
    const none = await wallet.post('/wallet/authorize/precheck', { ...base, r_s: '424242' });
    assert.equal(none.status, 404, j(none.body)); assert.equal(none.body.reason, 'no_session');
    assert.equal((await wallet.post('/wallet/authorize/precheck', { ...base, r_s: 'nope' })).status, 400);
  });

  await t('재검증: 캐시 히트(cacheHit=true), publicSignals 동일, σ 는 r_s 위 서명(ECDSA 결정적이라 매번 같다)', async () => {
    const r = await revalidate(S1.r_s);
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.cacheHit, true);
    assert.deepEqual(r.body.publicSignals, first.publicSignals);
    assert.equal(r.body.sig, first.sig, 'r_s 가 그대로라 서명 메시지도 그대로 — RFC6979 결정적 서명이라 σ 도 같다');
    assert.equal((await verify(r.body, S1)).ok, true);
  });

  await t('CORS: RP 오리진에만 Access-Control-Allow-Origin, 다른 오리진엔 없음. /wallet/tx 는 오리진 불문 열지 않는다(I1)', async () => {
    const good = await wallet.raw('/wallet/login', { method: 'OPTIONS', headers: { Origin: stack.rpOriginForWallet, 'Access-Control-Request-Method': 'POST' } });
    assert.equal(good.headers.get('access-control-allow-origin'), stack.rpOriginForWallet);
    const bad = await wallet.raw('/wallet/login', { method: 'OPTIONS', headers: { Origin: 'http://evil.example', 'Access-Control-Request-Method': 'POST' } });
    assert.equal(bad.headers.get('access-control-allow-origin'), null);
    // /wallet/tx 는 지갑 페이지(같은 오리진)에서만 부른다 — RP 오리진이라도 CORS 를 열지 않는다.
    const txFromRp = await wallet.raw('/wallet/tx', { method: 'OPTIONS', headers: { Origin: stack.rpOriginForWallet, 'Access-Control-Request-Method': 'POST' } });
    assert.equal(txFromRp.headers.get('access-control-allow-origin'), null);
    // Task 13: /wallet/secrets/salt 도 같은 오리진 전용 — RP 오리진에 CORS 를 열지 않는다(s_u 는 RP 에 내지 않는다).
    const saltFromRp = await wallet.raw('/wallet/secrets/salt', { headers: { Origin: stack.rpOriginForWallet } });
    assert.equal(saltFromRp.headers.get('access-control-allow-origin'), null);
  });

  // 2026-09-30: MODE3_RP_ORIGIN 은 쉼표 목록 — 지갑 하나가 RP 여럿에 로그인한다(같은 사용자, RP 마다 다른 PPID).
  await t('CORS: MODE3_RP_ORIGIN 목록의 두 번째 RP 오리진도 login·revalidate·request·config 에 허용, 목록 밖은 거절', async () => {
    for (const p of ['/wallet/login', '/wallet/revalidate', '/wallet/request']) {
      const r = await wallet.raw(p, { method: 'OPTIONS', headers: { Origin: SECOND_RP_ORIGIN, 'Access-Control-Request-Method': 'POST' } });
      assert.equal(r.headers.get('access-control-allow-origin'), SECOND_RP_ORIGIN, p);
      const first = await wallet.raw(p, { method: 'OPTIONS', headers: { Origin: stack.rpOriginForWallet, 'Access-Control-Request-Method': 'POST' } });
      assert.equal(first.headers.get('access-control-allow-origin'), stack.rpOriginForWallet, p + ' (첫 오리진도 그대로)');
    }
    const cfg = await wallet.raw('/wallet/config', { headers: { Origin: SECOND_RP_ORIGIN } });
    assert.equal(cfg.headers.get('access-control-allow-origin'), SECOND_RP_ORIGIN, '/wallet/config');
    const other = await wallet.raw('/wallet/revalidate', { method: 'OPTIONS', headers: { Origin: 'http://127.0.0.1:3198', 'Access-Control-Request-Method': 'POST' } });
    assert.equal(other.headers.get('access-control-allow-origin'), null, '목록에 없는 오리진');
    const h = (await wallet.get('/mode3/health')).body;
    assert.deepEqual(h.rpOrigins, [stack.rpOriginForWallet, SECOND_RP_ORIGIN], 'health 가 허용 목록을 그대로 낸다');
    assert.equal(h.rpOrigin, stack.rpOriginForWallet, '첫 오리진은 기존 필드로도');
  });

  // Task 13(B4): 동적 RP 허용 목록 — env 목록 밖의 오리진도 IdP 가 승인하면 폴링(10초 주기)으로 열린다.
  // 테스트가 /cia/register_rp 를 직접 부른다(cia.registerRp 가 그 호출 + 관리자 승인을 대행한다).
  await t('동적 RP 허용 목록: IdP 가 승인한 새 RP 오리진에 10초 안에 CORS 가 열린다', async () => {
    const NEW_ORIGIN = 'http://127.0.0.1:3999';
    await cia.registerRp(NEW_ORIGIN);
    const deadline = Date.now() + 12_000;
    let acao = null;
    while (Date.now() < deadline) {
      const r = await wallet.raw('/wallet/login', { method: 'OPTIONS', headers: { Origin: NEW_ORIGIN, 'Access-Control-Request-Method': 'POST' } });
      acao = r.headers.get('access-control-allow-origin');
      if (acao === NEW_ORIGIN) break;
      await new Promise((res) => setTimeout(res, 500));
    }
    assert.equal(acao, NEW_ORIGIN, '12초 안에 폴링이 새 RP 오리진을 허용 목록에 넣어야 한다');
    // env 로 준 오리진들은 폴링 뒤에도 그대로 — 폴링이 기존 목록을 지우지 않는다(env ∪ IdP 목록).
    const stillFirst = await wallet.raw('/wallet/login', { method: 'OPTIONS', headers: { Origin: stack.rpOriginForWallet, 'Access-Control-Request-Method': 'POST' } });
    assert.equal(stillFirst.headers.get('access-control-allow-origin'), stack.rpOriginForWallet);
    const h = (await wallet.get('/mode3/health')).body;
    assert.ok(h.rpOrigins.includes(NEW_ORIGIN), 'health 도 폴링된 목록을 낸다');
  });

  await t('계정 폐기 → 즉시 게시(V9: 등록부 슬롯) → skipSync 재검증은 옛 π 를 그대로 → 검증기 stale_registry_root', async () => {
    // V9: 계정 폐기는 등록부 슬롯을 비우고 그 자리에서 게시한다(cia.js revokeAccount) — 별도 /cia/publish 가 필요 없다.
    // 폐기 트리(revRoot)는 건드리지 않으므로(사용자 쪽은 더 이상 그 트리를 쓰지 않는다) stale_root 가 아니라 stale_registry_root 다.
    const rv = await cia.adminPost('/cia/revoke', { uid, scope: 'account' });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.published, true, j(rv.body));
    await relay();   // V10: 검증기는 거울을 읽는다 — 폐기가 거울에 실려야 옛 π 가 stale 이 된다
    const r = await revalidate(S1.r_s, { skipSync: true });
    assert.equal(r.status, 200, j(r.body));
    assert.deepEqual(r.body.publicSignals, first.publicSignals);
    const v = await verify(r.body, S1);
    assert.equal(v.ok, false);
    assert.equal(v.reason, 'stale_registry_root');
  });

  await t('동기화: 재검증 → 폐기 감지 → 두 세션 모두 403 revoked(리프 하나); status userCred.revoked=true; 새 로그인 → IdP 403 → account_disabled', async () => {
    const r = await revalidate(S1.r_s);
    assert.equal(r.status, 403, j(r.body));
    assert.equal(r.body.reason, 'revoked');
    // 폐기 리프는 사용자 자격증명 하나 — 같은 자격증명 위의 다른 세션도 함께 죽는다(설계 2026-09-21 §3.6)
    const r2 = await revalidate(S1b);
    assert.equal(r2.status, 403, j(r2.body));
    assert.equal(r2.body.reason, 'revoked');
    const s = await wallet.get('/wallet/status');
    assert.equal(s.body.userCred?.revoked, true, j(s.body.userCred));
    const l = await login();
    assert.equal(l.status, 403, j(l.body));
    assert.equal(l.body.reason, 'account_disabled');
  });

  let S2;
  await t('복구 → 로그인: 사용자 자격증명 재발급(userCredMs>0, Cf_u 바뀜), issued=true, 검증 통과, PPID 동일', async () => {
    const st0 = (await wallet.get('/wallet/status')).body;
    const before = st0.userCred.Cf_u;
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
    const ch = newCh();
    const r = await login(ch);
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, true);
    assert.ok(r.body.timings.userCredMs > 0, '폐기된 사용자 자격증명은 새로 받는다');
    const v = await verify(r.body, ch);
    assert.equal(v.ok, true, j(v));
    assert.equal(v.PPID, PPID1, 'PPID 는 폐기·복구로 바뀌지 않는다');
    const s = await wallet.get('/wallet/status');
    assert.notEqual(s.body.userCred.Cf_u, before, '새 사용자 자격증명은 Cf_u 가 다르다');
    assert.equal(s.body.userCred.revoked, false);
    // V10(§4.5, 결정 3): 계정 폐기로 옛 슬롯은 영구 은퇴됐다 — 되살린 뒤의 재발급은 새 슬롯을 받고, 지갑이 그 슬롯을 따른다.
    assert.notEqual(s.body.slot, st0.slot, `재발급 응답의 새 슬롯을 따라야 한다(옛 ${st0.slot})`);
    assert.equal(s.body.registry.slot, s.body.slot); assert.equal(s.body.registry.match, true);
    S2 = ch.r_s;
  });

  // 이 지점부터는 first(첫 로그인의 π)를 더는 참조하지 않는다 — 재시작으로 증명 캐시가 비면 새로 만든 π 의 tag(재무작위화)가
  // first 와 달라 앞의 deepEqual 비교들이 깨진다. S2 는 방금 복구돼 살아 있고 폐기되지 않았다.
  await t('폐기 트리 동기화: 리셋 뒤 sync 는 bootstrap, 재시작 뒤 재검증은 restore, 다시 리셋하면 bootstrap 으로 돈다 (스펙 §3·§6·§8)', async () => {
    // 여기까지 이미 로그인·재검증이 여러 번 지나 lastMode 가 delta 일 수 있다 — 먼저 리셋해 다음 sync 가 확실히 bootstrap 이 되게 한다.
    assert.equal((await wallet.post('/wallet/rcl/reset', { confirm: true })).body.deferred, false);
    const boot = await revalidate(S2);
    assert.equal(boot.status, 200, j(boot.body));
    const s1 = (await wallet.get('/wallet/status')).body;
    assert.equal(s1.rcl.lastMode, 'bootstrap');
    assert.ok(fs.existsSync(s1.rcl.cacheFile), `캐시 파일이 있어야 한다: ${s1.rcl.cacheFile}`);
    const leavesBefore = s1.rcl.leaves;
    await stack.restartWallet();
    const r = await revalidate(S2);
    assert.equal(r.status, 200, j(r.body));
    const s2 = (await wallet.get('/wallet/status')).body;
    assert.equal(s2.rcl.lastMode, 'restore');
    assert.equal(s2.rcl.leaves, leavesBefore);
  });

  await t('POST /wallet/rcl/reset 은 confirm:true 없으면 400, 있으면 캐시를 지우고 다음 재검증이 bootstrap 으로 돈다', async () => {
    const before = (await wallet.get('/wallet/status')).body.rcl.cacheFile;
    const noConfirm = await wallet.post('/wallet/rcl/reset', {});
    assert.equal(noConfirm.status, 400, j(noConfirm.body));
    // CSRF 방어 논거 자체를 고정한다: 다른 오리진 페이지가 프리플라이트 없이 보낼 수 있는 것은 text/plain 같은 단순 요청뿐인데,
    // express.json() 은 그걸 파싱하지 않으므로 req.body 가 비어 400 이 된다(mode3_wallet_agent.js 의 주석).
    const plain = await wallet.raw('/wallet/rcl/reset', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: JSON.stringify({ confirm: true }) });
    assert.equal(plain.status, 400, 'text/plain 단순 요청은 파싱되지 않아 confirm 이 없다');
    assert.ok(fs.existsSync(before), 'confirm 없이는 캐시가 지워지면 안 된다');
    const r = await wallet.post('/wallet/rcl/reset', { confirm: true });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.deferred, false, '이 시점엔 진행 중인 동기화가 없다');
    assert.ok(!fs.existsSync(before));
    const v = await revalidate(S2);
    assert.equal(v.status, 200, j(v.body));
    assert.equal((await wallet.get('/wallet/status')).body.rcl.lastMode, 'bootstrap');
  });

  await t('자격증명만 폐기(scope=credential), 즉시 게시(V9) → 다음 로그인이 슬롯 0 을 보고 새 C_u 를 받아 성공, PPID 동일, Cf_u 바뀜', async () => {
    const before = (await wallet.get('/wallet/status')).body.userCred;
    assert.equal(before.revoked, false);
    const rv = await cia.adminPost('/cia/revoke', { uid, scope: 'credential' });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.retired, 1, j(rv.body)); assert.equal(rv.body.published, true, j(rv.body));
    // V9: 즉시 게시된다 — 지갑은 다음 syncAll() 에서 바로 슬롯 0(등록부에 내 자격증명 없음)을 보고 새로 받는다(옛 no_user_cred 재시도 경로를 타지 않는다).
    const ch = newCh();
    const r = await login(ch);
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, true);
    assert.ok(r.body.timings.userCredMs > 0, '등록부에서 슬롯 0 을 보고 사용자 자격증명을 새로 받았어야 한다');
    const v = await verify(r.body, ch);
    assert.equal(v.ok, true, j(v));
    assert.equal(v.PPID, PPID1, 'PPID 는 s_u 에서 나오므로 C_u 재발급으로 바뀌지 않는다');
    const s = await wallet.get('/wallet/status');
    assert.notEqual(s.body.userCred.Cf_u, before.Cf_u, '새 사용자 자격증명은 Cf_u 가 다르다');
    assert.equal(s.body.userCred.revoked, false);
    assert.equal(s.body.sessions[S2], undefined, '물린 자격증명 위의 옛 세션은 지워진다');
    assert.equal(s.body.sessions[ch.r_s].PPID, PPID1.toString());
    S2 = ch.r_s;   // 이후 테스트는 이 세션을 쓴다
  });

  await t('입력 검증: r_s 없음 / cert_s 없음 / pk_trace 없음 → 400', async () => {
    assert.equal((await wallet.post('/wallet/login', { arid, origin, cert_s }, { Origin: stack.rpOriginForWallet })).status, 400);
    assert.equal((await wallet.post('/wallet/login', { arid, origin, r_s: newRs() }, { Origin: stack.rpOriginForWallet })).status, 400);
    assert.equal((await wallet.post('/wallet/login', { arid, origin, cert_s, r_s: newRs() }, { Origin: stack.rpOriginForWallet })).status, 400);
    assert.equal((await login(newCh(), { allowAgent: '2' })).status, 400);
  });

  await t('입력 검증: r_s·r_rp 가 2^250 이상이면 400', async () => {
    const tooBig = SCALAR_MAX.toString();
    assert.equal((await login(newCh(), { r_s: tooBig })).status, 400);
    assert.equal((await login(newCh(), { r_rp: tooBig })).status, 400);
  });

  await t('bad_rp_cert: 인증서와 다른 pk_trace 를 주면 403 (RP 혼자 아는 키로 바꿔치기)', async () => {
    const r = await login(newCh(), { pk_trace: { x: '1', y: '2' } });
    assert.equal(r.status, 403); assert.equal(r.body.reason, 'bad_rp_cert');
  });

  await t('status: 세션이 max_height(블록)·allowAgent·PPID 를 보여주고 exptime 은 없다', async () => {
    const s = await wallet.get('/wallet/status');
    const c = s.body.sessions[S2];
    assert.ok(c, 'S2 세션이 상태에 있어야 한다');
    assert.match(String(c.max_height), /^[0-9]+$/);
    assert.equal(c.exptime, undefined);
    assert.equal(c.allowAgent, '0');
    assert.match(String(c.PPID), /^[0-9]+$/);
    assert.ok(BigInt(c.max_height) > BigInt(await provider.getBlockNumber()));
    assert.equal(BigInt(c.max_height) % 100n, 0n, '지갑이 그리드(100)로 정한 max_height');
  });

  await t('revalidate: 모르는 r_s 는 404 no_session', async () => {
    const r = await revalidate(newRs());
    assert.equal(r.status, 404);
    assert.equal(r.body.reason, 'no_session');
  });

  await t('request: 세션키 서명 반환', async () => {
    const r = await wallet.post('/wallet/request', { r_s: S2, body: 'ping' }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(typeof r.body.sig, 'string');
    assert.equal(typeof r.body.pk_i, 'string');
  });

  // 2026-09-25 리뷰 D-4: precheck 의 r_s 분기와 같은 규칙을 세션 라우트에도. 지금은 CORS 가 RP 오리진 하나만
  // 열어 브라우저에서는 실현되지 않지만, CORS 는 브라우저에만 걸리므로 서버가 직접 거절해야 한다.
  await t('D-4: 세션 라우트는 남의 RP 요청을 세션 없는 것으로 다룬다 — 본문 arid·요청 오리진이 세션과 다르면 404 no_session (F-1: 맞는 arid 로도 Origin 대조를 끄지 못한다)', async () => {
    const otherArid = (BigInt(arid) + 1n).toString();
    const evilOrigin = { Origin: 'http://evil.example' };
    const rq = (extra, headers) => wallet.post('/wallet/request', { r_s: S2, body: 'ping', ...extra }, headers);
    const badArid = await rq({ arid: otherArid }, { Origin: stack.rpOriginForWallet });
    assert.equal(badArid.status, 404, j(badArid.body)); assert.equal(badArid.body.reason, 'no_session');
    const badOrigin = await rq({}, evilOrigin);
    assert.equal(badOrigin.status, 404, j(badOrigin.body)); assert.equal(badOrigin.body.reason, 'no_session');
    // 2026-09-25 최종 리뷰 F-1: arid 는 비밀이 아니다(GET /api/mode3/rp_info 가 그대로 싣는다). 맞는 arid 를
    // 실어도 Origin 대조가 꺼지면 안 된다 — 둘 다 있으면 둘 다 본다.
    const goodAridBadOrigin = await rq({ arid }, evilOrigin);
    assert.equal(goodAridBadOrigin.status, 404, j(goodAridBadOrigin.body)); assert.equal(goodAridBadOrigin.body.reason, 'no_session');
    const same = await rq({ arid }, { Origin: stack.rpOriginForWallet });
    assert.equal(same.status, 200, j(same.body)); assert.equal(typeof same.body.sig, 'string');
    const rvArid = await revalidate(S2, { arid: otherArid });
    assert.equal(rvArid.status, 404, j(rvArid.body)); assert.equal(rvArid.body.reason, 'no_session');
    const rvOrigin = await wallet.post('/wallet/revalidate', { r_s: S2 }, evilOrigin);
    assert.equal(rvOrigin.status, 404, j(rvOrigin.body)); assert.equal(rvOrigin.body.reason, 'no_session');
    const rvGoodAridBadOrigin = await wallet.post('/wallet/revalidate', { r_s: S2, arid }, evilOrigin);
    assert.equal(rvGoodAridBadOrigin.status, 404, j(rvGoodAridBadOrigin.body)); assert.equal(rvGoodAridBadOrigin.body.reason, 'no_session');
  });

  await t('allowAgent=1 로그인: 공개 입력 [5] 가 1', async () => {
    const ch = newCh();
    const r = await login(ch, { allowAgent: '1' });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.publicSignals[5], '1'); assert.equal(r.body.allowAgent, '1');
    assert.equal((await verify(r.body, ch)).ok, true);
  });

  await t('login: 인증서와 다른 arid 로 배포된 팩토리, 또는 컨트랙트가 아닌 주소를 factoryAddress 로 주면 409 bad_factory (2026-09-18 점검 3)', async () => {
    const signer = await provider.getSigner(0);
    const v = await deployVerifier(signer);
    const wrongArid = await deployFactory(signer, { verifierAddress: v, arid: BigInt(arid) + 1n, pkCIA: pk_CIA, pkTrace: pk_trace, logAddress: cia.mirrorAddress, maxRootAge: 10n });
    const r1 = await login(newCh(), { factoryAddress: wrongArid });
    assert.equal(r1.status, 409, j(r1.body)); assert.equal(r1.body.reason, 'bad_factory');
    const r2 = await login(newCh(), { factoryAddress: ethers.Wallet.createRandom().address });
    assert.equal(r2.status, 409, j(r2.body)); assert.equal(r2.body.reason, 'bad_factory');
  });

  await t('login: 무엇이든 통과시키는 검증자를 가리키는 팩토리(immutable 은 전부 정상)는 409 bad_factory / verifier_code_mismatch (참조 코드 대조, 2026-09-23)', async () => {
    const signer = await provider.getSigner(0);
    const { abi, bytecode } = JSON.parse(fs.readFileSync(new URL('../artifacts/contracts/test/AcceptAllPiCredVerifier.sol/AcceptAllPiCredVerifier.json', import.meta.url), 'utf8'));   // 테스트 전용 검증자(contracts/test)
    const fake = await new ethers.ContractFactory(abi, bytecode, signer).deploy();
    await fake.waitForDeployment();
    const rogue = await deployFactory(signer, { verifierAddress: await fake.getAddress(), arid: BigInt(arid), pkCIA: pk_CIA, pkTrace: pk_trace, logAddress: cia.mirrorAddress });
    const r = await login(newCh(), { factoryAddress: rogue });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'bad_factory'); assert.equal(r.body.detail, 'verifier_code_mismatch');
  });

  // 2026-09-25 리뷰 I-3(+시험 공백 E-2): 위 두 건은 arid·코드만 본다. 나머지 생성자 인자 — 폐기 로그·pk_CIA·pk_trace 와
  // 참조 코드 대조가 0 으로 지우는 maxRootAge·maxLifetime — 도 값으로 막히는지 한 번에 본다. 상한이 너무 크면 AA 가
  // 게시를 멈춰도 온체인 실행이 계속되고(폐기 신선도 상실), 0 이면 그 계정의 모든 execute 가 revert 해 이미 보낸 자산이
  // 영구 동결된다(주소가 이 인자들로 결정돼 다른 값으로 재배포할 수 없다).
  await t('I-3/E-2: 팩토리의 log·pk_CIA·pk_trace·maxRootAge·maxLifetime 이 기대와 다르면 409 bad_factory', async () => {
    const signer = await provider.getSigner(0);
    const v = await deployVerifier(signer);
    const base = { verifierAddress: v, arid: BigInt(arid), pkCIA: pk_CIA, pkTrace: pk_trace, logAddress: cia.mirrorAddress };   // V10: 계정은 거울을 읽는다
    const otherLog = (await deployRevocationLog(await signer.getAddress(), provider)).address;   // RP 가 통제하는 로그
    const cases = [
      ['다른 폐기 로그', { ...base, logAddress: otherLog }],
      ['캐노니컬 로그(V10: 대상 체인 거울이어야 한다)', { ...base, logAddress: cia.logAddress }],
      ['다른 pk_CIA', { ...base, pkCIA: { x: pk_CIA.x + 1n, y: pk_CIA.y } }],
      ['다른 pk_trace', { ...base, pkTrace: { x: BigInt(pk_trace.x) + 1n, y: BigInt(pk_trace.y) } }],
      ['maxRootAge 상한 밖', { ...base, maxRootAge: 2n ** 40n }],
      ['maxRootAge 0 (계정 영구 동결)', { ...base, maxRootAge: 0n }],
      ['maxLifetime 상한 밖', { ...base, maxLifetime: 2n ** 40n }],
    ];
    for (const [name, opts] of cases) {
      const f = await deployFactory(signer, opts);
      const r = await login(newCh(), { factoryAddress: f });
      assert.equal(r.status, 409, `${name}: ${j(r.body)}`);
      assert.equal(r.body.reason, 'bad_factory', name);
    }
  });

  let factoryAddress, S3, walletAddr;
  await t('tx: factoryAddress 없이 로그인한 세션은 409 no_factory', async () => {
    const r = await wallet.post('/wallet/tx', { r_s: S2, to: ethers.Wallet.createRandom().address }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'no_factory');
  });

  await t('tx: 팩토리를 준 세션 — 첫 트랜잭션은 지갑 배포 + 실행 ok, 두 번째는 새 π(counter=nonce 1 이라 캐시 미스)·nonce 1', async () => {
    const signer = await provider.getSigner(0);
    const verifierAddress = await deployVerifier(signer);
    factoryAddress = await deployFactory(signer, { verifierAddress, arid, pkCIA: pk_CIA, pkTrace: pk_trace, logAddress: cia.mirrorAddress, maxRootAge: 10n });
    const ch3 = newCh();
    S3 = ch3.r_s;
    const l = await login(ch3, { factoryAddress });
    assert.equal(l.status, 200, j(l.body));
    const to = ethers.Wallet.createRandom().address;
    const r1 = await wallet.post('/wallet/tx', { r_s: S3, to, value: '0' }, { Origin: stack.rpOriginForWallet });
    assert.equal(r1.status, 200, j(r1.body));
    assert.equal(r1.body.deployed, true); assert.equal(r1.body.ok, true); assert.equal(r1.body.nonce, '0'); assert.match(r1.body.txHash, /^0x[0-9a-f]{64}$/);
    walletAddr = r1.body.wallet;
    assert.notEqual(await provider.getCode(walletAddr), '0x');
    const r2 = await wallet.post('/wallet/tx', { r_s: S3, to }, { Origin: stack.rpOriginForWallet });
    assert.equal(r2.status, 200, j(r2.body));
    // 2026-10-22: 거래 π 는 counter=nonce 를 공개 입력으로 싣는다 — nonce 가 0→1 로 바뀌면 캐시 키도 바뀌어 새로 증명한다(브리프 §6.5).
    assert.equal(r2.body.deployed, false); assert.equal(r2.body.cacheHit, false); assert.equal(r2.body.nonce, '1');
    assert.equal(await walletAt(walletAddr, provider).nonce(), 2n);
    console.log(`     execute gas ${r1.body.gasUsed} (배포 포함 tx 아님 — execute 만)`);
  });

  await t('tx: 값 전송 — 릴레이어가 지갑에 입금한 뒤 value 를 보내면 수신자 잔액이 는다', async () => {
    const signer = await provider.getSigner(0);
    await (await signer.sendTransaction({ to: walletAddr, value: ethers.parseEther('0.5') })).wait();
    const to = ethers.Wallet.createRandom().address;
    const r = await wallet.post('/wallet/tx', { r_s: S3, to, value: ethers.parseEther('0.1').toString() }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.ok, true);
    assert.equal(await provider.getBalance(to), ethers.parseEther('0.1'));
  });

  // V10: 계정 컨트랙트는 거울의 lastPublishedBlock 을 본다. 격리 IdP 는 거울 릴레이 주기가 꺼져 있어 캐노니컬 하트비트만으로는
  // 거울이 오르지 않는다 — 하트비트 대신 /cia/admin/relay 로 거울을 올린다.
  await t('tx: 거울 게시가 maxRootAge(10) 보다 오래되면 execute_reverted RootTooOld, 거울 릴레이 뒤 다시 ok', async () => {
    const log = new ethers.Contract(cia.mirrorAddress, LOG_ABI, provider);
    const last0 = await log.lastPublishedBlock();
    await provider.send('hardhat_mine', ['0xb']);
    const r = await wallet.post('/wallet/tx', { r_s: S3, to: ethers.Wallet.createRandom().address }, { Origin: stack.rpOriginForWallet });
    if (r.status === 409) assert.match(r.body.detail, /RootTooOld/, j(r.body));
    else assert.equal(r.status, 200, j(r.body));   // 공유 노드에서 그 사이 릴레이가 끼어들었으면 그대로 ok — 아래에서 lastPublishedBlock 전진만 확인
    await relay();
    assert.ok((await log.lastPublishedBlock()) > last0, `릴레이가 거울에 게시했어야 한다\n${cia.log()}`);
    // :8545 는 공유 노드다(CLAUDE.md) — 다른 프로세스가 그 사이 블록을 더 진행시키면 maxRootAge(10) 를 다시
    // 넘길 수 있다(관찰됨). 첫 시도가 또 RootTooOld 면 짧게 재시도한다 — 대상 자체는 여전히 "곧 성공" 이다.
    let ok;
    for (let attempt = 0; attempt < 5; attempt++) {
      ok = await wallet.post('/wallet/tx', { r_s: S3, to: ethers.Wallet.createRandom().address }, { Origin: stack.rpOriginForWallet });
      if (ok.status === 200) break;
      await new Promise((res) => setTimeout(res, 200));
    }
    assert.equal(ok.status, 200, j(ok.body)); assert.equal(ok.body.ok, true);
  });

  await t('tx: 계정 폐기 + 즉시 게시(V9) 뒤에는 403 revoked (재증명 불가)', async () => {
    const rv = await cia.adminPost('/cia/revoke', { uid, scope: 'account' });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.published, true, j(rv.body));
    const r = await wallet.post('/wallet/tx', { r_s: S3, to: ethers.Wallet.createRandom().address }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.reason, 'revoked');
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
  });

  await t('tx 입력 검증: r_s 없음·주소 아님·모르는 세션', async () => {
    assert.equal((await wallet.post('/wallet/tx', { to: walletAddr }, { Origin: stack.rpOriginForWallet })).status, 400);
    assert.equal((await wallet.post('/wallet/tx', { r_s: S3, to: 'nope' }, { Origin: stack.rpOriginForWallet })).status, 400);
    assert.equal((await wallet.post('/wallet/tx', { r_s: newRs(), to: walletAddr }, { Origin: stack.rpOriginForWallet })).status, 404);
  });

  await t('register: 이미 등록된 계정에는 본문과 무관하게 409', async () => {
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['1', '2', '3', '4', '5'] })).status, 409);
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['x'] })).status, 409);
  });

  // 지갑이 로그인용으로 쓰는 헬퍼 — 등록은 이미 위에서 됐으므로 새 r_s 로 로그인만 한다. PPID 는 다른 케이스와 같이
  // verify(RP 검증기)를 거쳐 검증된 로그인에서 읽는다(Task 6 이후 publicSignals.length===25 을 받아들인다).
  async function loginOnce(extra = {}) {
    const ch = newCh();
    const r = await login(ch, extra);
    assert.equal(r.status, 200, j(r.body));
    const v = await verify(r.body, ch);
    assert.equal(v.ok, true, j(v));
    return { ...r.body, r_s: ch.r_s, PPID: v.PPID.toString() };
  }
  async function publishOnce() {
    const r = await cia.adminPost('/cia/publish');
    assert.equal(r.body.published, true, j(r.body));
  }

  // 스펙 2(2026-10-07): 지갑의 PUT /wallet/profile 은 { profile } 만 받는다(스키마에 안 맞으면 400 bad_attr) — extra1(string, 슬롯 2)에
  // 값을 넣어 string 슬롯의 인코딩(해시)도 같이 재동기화 경로로 거친다.
  const tier3 = await encodeSlotValue(DEFAULT_ATTR_SCHEMA, 2, 'tier3');

  await t('D15: 지갑에서 속성을 바꾸면(PUT /wallet/profile) 옛 C_u·세션이 버려지고 다음 로그인이 새 C_u 로 성공, PPID 동일, IdP 상태에는 속성이 없다', async () => {
    const first = await loginOnce();
    const same = await wallet.put('/wallet/profile', { profile: { birthYear: '1990', country: '410' } });   // 코드 표기 → 정규형 KR, attrs 불변
    assert.equal(same.status, 200, j(same.body)); assert.equal(same.body.changed, false); assert.deepEqual(same.body.profile, { birthYear: '1990', country: 'KR' });
    assert.ok(Object.keys((await wallet.get('/wallet/status')).body.sessions).length > 0, '속성이 그대로면 세션을 버리지 않는다');
    const chg = await wallet.put('/wallet/profile', { profile: { birthYear: '1990', country: 'KR', extra1: 'tier3' } });
    assert.equal(chg.status, 200, j(chg.body)); assert.equal(chg.body.changed, true);
    assert.deepEqual(chg.body.attrs, ['1990', '410', tier3, '0', '0', '0']);
    assert.equal('attrsChanged' in chg.body, false, 'file 모드는 attrsChanged 를 내지 않는다(snap 전용)');
    const st = (await wallet.get('/wallet/status')).body;
    assert.deepEqual(st.sessions, {}, '옛 C_u 위의 세션은 버린다'); assert.equal(st.userCred, null);
    assert.deepEqual(st.profile, { birthYear: '1990', country: 'KR', extra1: 'tier3' });
    const second = await loginOnce();
    assert.equal(second.PPID, first.PPID, 'PPID 는 (uid, s_u, arid, chainid) — 속성과 무관');
    assert.equal(second.timings.userCredMs > 0, true, '새 C_u');
    const bad = await wallet.put('/wallet/profile', { profile: { birthYear: '1800', country: 'KR' } });
    assert.equal(bad.status, 400); assert.equal(bad.body.reason, 'bad_attr');
    assert.equal((await wallet.put('/wallet/profile', { profile: { country: 'KR' } })).body.detail, 'missing_field');
    assert.equal((await wallet.put('/wallet/profile', {})).status, 400);
    const acct = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === uid);
    assert.equal(acct.attrs, undefined); assert.equal(acct.profile, undefined);
  });

  await t('V11: /wallet/attrs·/wallet/attrs/sync 는 404', async () => {
    assert.equal((await wallet.post('/wallet/attrs', { attrs: ['1', '0', '0', '0'] })).status, 404);
    assert.equal((await wallet.post('/wallet/attrs/sync', {})).status, 404);
  });

  // V8 세션 폐기(설계 2026-09-24 §4). 계획서는 이 두 케이스를 앞쪽 '동기화: 재검증 → 폐기 감지 …' 앞에 두라고 했지만,
  // 그 자리는 바로 앞 케이스가 계정을 폐기·게시해 둔 구간이라 loginOnce 가 account_disabled 로 막히고, 게시로 root 가
  // 바뀌면 그 케이스의 skipSync 단언(캐시 π 재제출)도 깨진다. 계정이 살아 있고 loginOnce·publishOnce 가 이미 쓰이는
  // 이 지점으로 옮겼다 — 단언 내용은 계획서 그대로다.
  await t('V8 세션 폐기: 세션 둘 중 하나를 /wallet/session/revoke → 게시 → 그 세션만 403 revoked_session, 다른 세션은 재검증 성공, 새 로그인 정상', async () => {
    const a = await loginOnce(), b = await loginOnce();
    const r = await wallet.post('/wallet/session/revoke', { r_s: a.r_s });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.revoked, true);
    assert.equal((await wallet.get('/wallet/status')).body.sessions[a.r_s], undefined, '폐기 요청 뒤 지갑은 세션을 버린다');
    await publishOnce();
    const rb = await revalidate(b.r_s);
    assert.equal(rb.status, 200, j(rb.body));
    const c = await loginOnce();   // 사용자 자격증명은 살아 있다
    assert.ok(c.r_s);
    const missing = await wallet.post('/wallet/session/revoke', { r_s: '999' });
    assert.equal(missing.status, 404); assert.equal(missing.body.reason, 'no_session');
  });

  // 2026-10-23 리뷰 3-1: 제목이 약속하는 세 가지(nonce k 성공·nonce k+1 은 revoked_session·재검증도 revoked_session)를
  // 실제로 집행해 확인한다 — 관리자 경로로 bound 를 걸고(V8 관리자 케이스와 같은 구도) /wallet/tx 두 번·/wallet/revalidate 로 본다.
  // 재검증은 그 세션 하나가 revoked_session 이 되면 지갑이 즉시 버리므로(같은 r_s 로 두 번째 호출은 no_session), tx 쪽과
  // 재검증 쪽을 각각 다른 세션으로 나눈다. 계정 nonce 는 이 파일의 다른 케이스들과 공유하는 값이라 절대값이 아니라
  // "이 케이스가 시작할 때의 값 + k" 로 비교한다.
  await t('폐기 상한(2026-10-22): 관리자 경로로 실제 집행 — nonce k 는 통과, nonce k+1 은 revoked_session, 재검증도 revoked_session, 기본 bound = 계정 nonce', async () => {
    // (1) 거래 k(=2)회 → 관리자가 bound=시작nonce+k+1 로 폐기·게시·중계 → nonce(시작+k) 통과, nonce(시작+k+1) 차단.
    const before1 = new Set((await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.map((x) => x.Cf_s));
    const a = await loginOnce({ factoryAddress });
    const cfA = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.map((x) => x.Cf_s).find((c) => !before1.has(c));
    assert.ok(cfA, 'a 의 세션 기록이 있어야 한다');
    await relay();
    const n0 = BigInt((await wallet.get('/wallet/status')).body.sessions[a.r_s].nonce);
    const K = 2n;
    for (let i = 0n; i < K; i++) assert.equal((await wallet.post('/wallet/tx', { r_s: a.r_s, to: ethers.ZeroAddress, value: '0' })).status, 200);
    assert.equal((await wallet.get('/wallet/status')).body.sessions[a.r_s].nonce, (n0 + K).toString(), '거래 k 회 뒤 nonce 는 시작값 + k');
    const boundAdmin = n0 + K + 1n;
    const rvAdmin = await cia.adminPost('/cia/revoke', { uid, scope: 'session', Cf_s: cfA, bound: boundAdmin.toString() });
    assert.equal(rvAdmin.status, 200, j(rvAdmin.body));
    await publishOnce();
    await relay();
    const passOk = await wallet.post('/wallet/tx', { r_s: a.r_s, to: ethers.ZeroAddress, value: '0' });          // nonce(시작+k) < bound → 통과
    assert.equal(passOk.status, 200, j(passOk.body));
    const blocked = await wallet.post('/wallet/tx', { r_s: a.r_s, to: ethers.ZeroAddress, value: '0' });         // nonce(시작+k+1) == bound → 차단
    assert.equal(blocked.status, 403, j(blocked.body)); assert.equal(blocked.body.reason, 'revoked_session');

    // (2) 재검증도 같은 사유로 막힌다. 재검증은 거래가 없어 counter=LOGIN_COUNTER 를 쓰므로 bound 값과 무관하게
    //     "이 세션이 폐기된 적 있는지" 만 본다 — 별도 세션으로 bound(아무 값)만 걸어서 바로 확인한다.
    const before2 = new Set((await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.map((x) => x.Cf_s));
    const a2 = await loginOnce({ factoryAddress });
    const cfA2 = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.map((x) => x.Cf_s).find((c) => !before2.has(c));
    assert.ok(cfA2, 'a2 의 세션 기록이 있어야 한다');
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'session', Cf_s: cfA2, bound: '0' })).status, 200);
    await publishOnce();
    await relay();
    const rvA2 = await revalidate(a2.r_s);
    assert.equal(rvA2.status, 403, j(rvA2.body)); assert.equal(rvA2.body.reason, 'revoked_session');

    // (3) 기본 bound(지갑 버튼 경로, bound 생략) = 계정의 현재 nonce.
    const a3 = await loginOnce({ factoryAddress });
    await relay();
    assert.equal((await wallet.post('/wallet/tx', { r_s: a3.r_s, to: ethers.ZeroAddress, value: '0' })).status, 200);
    const nonce3 = (await wallet.get('/wallet/status')).body.sessions[a3.r_s].nonce;
    const r3 = await wallet.post('/wallet/session/revoke', { r_s: a3.r_s });   // bound 생략
    assert.equal(r3.status, 200, j(r3.body));
    assert.equal(r3.body.bound, nonce3, '기본 bound = 계정 nonce');

    // (4) pendingBounds/apply 생명주기(지갑 버튼 경로, 명시 bound) — 전역 길이 단언은 케이스 순서에 의존하므로
    //     이 케이스가 늘리고 줄이는 수만 본다(리뷰 지적).
    const beforeLen = (await wallet.get('/wallet/status')).body.pendingBounds.length;
    const b1 = await loginOnce({ factoryAddress });
    const bSessionAddress = (await wallet.get('/wallet/status')).body.sessions[b1.r_s].sessionAddress;
    await relay();
    for (const _ of [0, 1]) assert.equal((await wallet.post('/wallet/tx', { r_s: b1.r_s, to: ethers.ZeroAddress, value: '0' })).status, 200);
    const r = await wallet.post('/wallet/session/revoke', { r_s: b1.r_s, bound: '3' });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.bound, '3'); assert.ok(r.body.pendingBoundId);
    await publishOnce();
    const st = (await wallet.get('/wallet/status')).body;
    assert.equal(st.pendingBounds.length, beforeLen + 1, '이 케이스가 만든 항목만큼만 늘어야 한다');
    assert.ok(st.pendingBounds.some((p) => p.id === r.body.pendingBoundId && p.bound === '3' && p.applicableSession === null));
    // 같은 계정의 새 세션으로 "지금 반영" → setSessionBound 거래 → §1 수정: Executed.success·온체인 sessionBound 를 둘 다 확인해야 applied:true.
    const b2 = await loginOnce({ factoryAddress });
    await relay();
    const ap = await wallet.post('/wallet/bounds/apply', { id: r.body.pendingBoundId, r_s: b2.r_s });
    assert.equal(ap.status, 200, j(ap.body)); assert.equal(ap.body.applied, true); assert.equal(ap.body.bound, '3');
    assert.equal((await wallet.get('/wallet/status')).body.pendingBounds.length, beforeLen);
    const acct = walletAt(ap.body.wallet, provider);
    assert.equal(await acct.sessionBound(BigInt(bSessionAddress)), 4n);   // 저장값 = 3 + 1 (bSessionAddress 는 세션 b1 의 세션키 주소)

    // (5) §1 (b)+(c): 대기 항목(bound=5, pk_i=c1 의 세션키)을 만든 뒤 **다른** 세션(c2)으로 같은 pk_i 에 더 낮은
    //     bound(=2)를 /wallet/tx 로 직접 보낸다(setSessionBound 는 OnlySelf — 계정 자신만 호출, 어느 세션으로 보내도 된다;
    //     pendingBounds 밖의 경로라 이 대기 항목은 그대로 남아 있다). 이 대기 항목(c1, 5)을 나중에 apply 하면 컨트랙트는
    //     BoundNotLowered 로 revert 하지만(§1-c: 5+1 ≥ 2+1 이미 걸린 값), 온체인 값(2)이 요청(5)보다 이미 낮으므로
    //     applied:true, alreadyLower:true 로 지워야 한다(§1-b).
    const c1 = await loginOnce({ factoryAddress });
    const c1Pk = BigInt((await wallet.get('/wallet/status')).body.sessions[c1.r_s].sessionAddress);
    await relay();
    const rc1 = await wallet.post('/wallet/session/revoke', { r_s: c1.r_s, bound: '5' });
    assert.equal(rc1.status, 200, j(rc1.body)); assert.ok(rc1.body.pendingBoundId);
    await publishOnce();
    const c2 = await loginOnce({ factoryAddress });
    await relay();
    const acctAddr = (await wallet.get('/wallet/status')).body.sessions[c2.r_s].account;
    const lowerData = walletInterface.encodeFunctionData('setSessionBound', [c1Pk, 2]);
    const lowerTx = await wallet.post('/wallet/tx', { r_s: c2.r_s, to: acctAddr, value: '0', data: lowerData });
    assert.equal(lowerTx.status, 200, j(lowerTx.body)); assert.equal(lowerTx.body.ok, true, j(lowerTx.body));
    assert.equal(await acct.sessionBound(c1Pk), 3n, '직접 보낸 setSessionBound(2) 의 저장값 = 2+1');
    const c3 = await loginOnce({ factoryAddress });
    await relay();
    const ap3 = await wallet.post('/wallet/bounds/apply', { id: rc1.body.pendingBoundId, r_s: c3.r_s });
    assert.equal(ap3.status, 200, j(ap3.body));
    assert.equal(ap3.body.applied, true, j(ap3.body)); assert.equal(ap3.body.alreadyLower, true, j(ap3.body));
    assert.equal((await wallet.get('/wallet/status')).body.pendingBounds.length, beforeLen);
  });

  // F-14/F-2(2026-10-23): /wallet/tx/record 의 pendingBoundId 경로도 file 모드 /wallet/bounds/apply 와 같은 판정
  // 헬퍼(boundApplyVerdict)를 쓴다 — snap 모드는 MetaMask 가 보낸 뒤 이 라우트로 들어오지만 판정 자체는 모드와
  // 무관하다. 이 file 모드 스택에서 setSessionBound 거래를 직접 보내고(= snap 모드가 MetaMask 로 보내는 것과 같은
  // 모양) 그 txHash 를 /wallet/tx/record 에 pendingBoundId 로 실어, /wallet/bounds/apply 와 같은 결과(applied·
  // alreadyLower)가 나오는지 본다.
  //   bound_not_applied 분기(브리프 F-2)는 이 경로로 못 만들었다 — contracts/Mode3Wallet.sol:55-58 의 두 revert 중
  //   BoundNotLowered 는 cur != 0(이미 값이 있다) 일 때만 나고, 그 revert 조건(uint256(bound)+1 >= cur) 이 성립하면
  //   수학적으로 cur-1 <= bound(= reqBound) 가 항상 같이 성립해 onchainBound 재조회가 늘 alreadyLower 로 떨어진다
  //   (onchainBound 가 null 인 경우는 cur==0 이라 BoundNotLowered 자체가 안 난다). OnlySelf 는 이 코드가 늘
  //   execute() 의 self-call(payload.to = 그 계정 자신)로만 보내 나지 않는다. 그래서 bound_not_applied 는 이
  //   테스트들로 커버하지 못했다 — 보고서에 남긴다.
  await t('F-14: /wallet/tx/record + pendingBoundId 가 /wallet/bounds/apply 와 같은 판정(applied, alreadyLower)을 낸다', async () => {
    // applied: true — d1 을 bound=7 로 폐기해 대기 항목을 만들고, 같은 계정의 새 세션(d2)으로 직접 setSessionBound
    // (d1Pk, 7) 을 보낸 뒤, 그 영수증을 /wallet/tx/record 에 pendingBoundId 로 넘긴다.
    const d1 = await loginOnce({ factoryAddress });
    const d1Pk = BigInt((await wallet.get('/wallet/status')).body.sessions[d1.r_s].sessionAddress);
    await relay();
    const rd1 = await wallet.post('/wallet/session/revoke', { r_s: d1.r_s, bound: '7' });
    assert.equal(rd1.status, 200, j(rd1.body)); assert.ok(rd1.body.pendingBoundId);
    await publishOnce();
    const d2 = await loginOnce({ factoryAddress });
    await relay();
    const d2Acct = (await wallet.get('/wallet/status')).body.sessions[d2.r_s].account;
    const setData = walletInterface.encodeFunctionData('setSessionBound', [d1Pk, 7]);
    const sendTx = await wallet.post('/wallet/tx', { r_s: d2.r_s, to: d2Acct, value: '0', data: setData });
    assert.equal(sendTx.status, 200, j(sendTx.body)); assert.equal(sendTx.body.ok, true, j(sendTx.body));
    const rec = await wallet.post('/wallet/tx/record', { r_s: d2.r_s, txHash: sendTx.body.txHash, pendingBoundId: rd1.body.pendingBoundId });
    assert.equal(rec.status, 200, j(rec.body)); assert.equal(rec.body.applied, true, j(rec.body));
    assert.equal((await wallet.get('/wallet/status')).body.pendingBounds.some((p) => p.id === rd1.body.pendingBoundId), false, 'applied 뒤 pending 이 지워진다');

    // alreadyLower: true — e1 을 bound=9 로 폐기해 대기 항목을 만들고, 다른 세션(e2)이 먼저 더 낮은 값(4)을 걸어 둔
    // 뒤, 대기 항목(bound=9)과 같은 setSessionBound(e1Pk, 9) 를 직접 보내면 내부 호출은 BoundNotLowered 로 실패해도
    // (ok:false) 트랜잭션 자체는 성공한다 — 그 영수증을 record 에 넘기면 온체인 값(4)이 요청(9)보다 이미 낮아
    // applied:true, alreadyLower:true 가 나와야 한다(/wallet/bounds/apply 의 §1-b·c 와 같은 계약).
    const e1 = await loginOnce({ factoryAddress });
    const e1Pk = BigInt((await wallet.get('/wallet/status')).body.sessions[e1.r_s].sessionAddress);
    await relay();
    const re1 = await wallet.post('/wallet/session/revoke', { r_s: e1.r_s, bound: '9' });
    assert.equal(re1.status, 200, j(re1.body)); assert.ok(re1.body.pendingBoundId);
    await publishOnce();
    const e2 = await loginOnce({ factoryAddress });
    await relay();
    const e2Acct = (await wallet.get('/wallet/status')).body.sessions[e2.r_s].account;
    const lowerData = walletInterface.encodeFunctionData('setSessionBound', [e1Pk, 4]);
    const lowerTx = await wallet.post('/wallet/tx', { r_s: e2.r_s, to: e2Acct, value: '0', data: lowerData });
    assert.equal(lowerTx.status, 200, j(lowerTx.body)); assert.equal(lowerTx.body.ok, true, j(lowerTx.body));
    assert.equal(await walletAt(e2Acct, provider).sessionBound(e1Pk), 5n, '직접 보낸 setSessionBound(4) 의 저장값 = 4 + 1');
    const e3 = await loginOnce({ factoryAddress });
    await relay();
    const e3Acct = (await wallet.get('/wallet/status')).body.sessions[e3.r_s].account;
    const raiseData = walletInterface.encodeFunctionData('setSessionBound', [e1Pk, 9]);
    const raiseTx = await wallet.post('/wallet/tx', { r_s: e3.r_s, to: e3Acct, value: '0', data: raiseData });
    assert.equal(raiseTx.status, 200, j(raiseTx.body));
    assert.equal(raiseTx.body.ok, false, j(raiseTx.body), '내부 setSessionBound(9) 는 이미 4 라 BoundNotLowered 로 실패해야 한다');
    const rec2 = await wallet.post('/wallet/tx/record', { r_s: e3.r_s, txHash: raiseTx.body.txHash, pendingBoundId: re1.body.pendingBoundId });
    assert.equal(rec2.status, 200, j(rec2.body));
    assert.equal(rec2.body.applied, true, j(rec2.body)); assert.equal(rec2.body.alreadyLower, true, j(rec2.body));
    assert.equal((await wallet.get('/wallet/status')).body.pendingBounds.some((p) => p.id === re1.body.pendingBoundId), false, 'alreadyLower 뒤에도 pending 이 지워진다');
  });

  await t('V8: 세션 하나가 지갑 밖에서(관리자) 폐기되면 재검증이 403 revoked_session 으로 그 세션만 지운다 — 사용자 자격증명은 그대로', async () => {
    const before = new Set((await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.map((x) => x.Cf_s));
    const a = await loginOnce();
    // 관리자가 이 세션만 폐기(지갑은 모른다). 이 로그인이 새로 만든 기록을 Cf_s 로 직접 집는다 —
    // 목록 순서나 만료 정리 시점에 기대지 않는다(최종 리뷰 F6).
    const cf = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.map((x) => x.Cf_s).find((c) => !before.has(c));
    assert.ok(cf, '방금 로그인의 세션 기록이 있어야 한다');
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'session', Cf_s: cf })).status, 200);
    await publishOnce();
    const r = await revalidate(a.r_s);
    assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.reason, 'revoked_session');
    const s = await wallet.get('/wallet/status');
    assert.equal(s.body.userCred?.revoked, false, '사용자 자격증명은 그대로');
    assert.equal(s.body.sessions[a.r_s], undefined, '폐기된 세션만 지워진다');
    // 같은 세션을 다시 재검증하면 이미 지워져 404 no_session 이다(지갑은 그 세션을 더 들고 있지 않다)
    assert.equal((await revalidate(a.r_s)).status, 404);
  });

  await t('V9 등록부 확인: 관리자 바꿔치기 → status.registry.match=false, 로그인 403 registry_mismatch; 되돌리기 → 로그인 ok', async () => {
    assert.equal((await cia.adminPost('/cia/admin/registry/tamper', { uid })).status, 200);
    const r = await login();
    assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.reason, 'registry_mismatch');
    const s = await wallet.get('/wallet/status');
    assert.equal(s.body.registry.match, false);
    assert.equal((await cia.adminPost('/cia/admin/registry/restore', { uid })).status, 200);
    const ok = await login(); assert.equal(ok.status, 200, j(ok.body));
    assert.equal((await wallet.get('/wallet/status')).body.registry.match, true);
  });
  await t('V9 은퇴(scope=credential): 다음 로그인이 슬롯 0 을 보고 새 자격증명을 받아(userCredMs>0) 성공, PPID 유지', async () => {
    const before = (await wallet.get('/wallet/status')).body;
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'credential' })).status, 200);
    const ch = newCh();
    const r = await login(ch); assert.equal(r.status, 200, j(r.body)); assert.ok(r.body.timings.userCredMs > 0);
    const v = await verify(r.body, ch); assert.equal(v.ok, true, j(v));
    assert.equal(v.PPID.toString(), Object.values(before.sessions)[0].PPID);
  });
  await t('시연 덮어쓰기(issue): salt 를 바꾸면 AA 가 bad idp proof 로 거절; uid 를 바꿔도 같다; 자동 해제', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'credential' })).status, 200);   // 다음 로그인이 user_cred 를 새로 받게
    assert.equal((await wallet.post('/wallet/demo/override', { s_u: randomScalar().toString(), scope: 'issue' })).status, 200);
    assert.deepEqual((await wallet.get('/wallet/status')).body.demoOverride, { scope: 'issue', fields: ['s_u'] });
    const r = await login();
    assert.equal(r.status, 502, j(r.body)); assert.equal(r.body.reason, 'user_cred_failed'); assert.equal(r.body.cia.error, 'bad idp proof'); assert.equal(r.body.cia.reason, 'bad_idp_proof'); assert.equal(r.body.demo, 'override:issue');
    assert.equal((await wallet.get('/wallet/status')).body.demoOverride, null, '한 번 쓰면 해제');
    assert.equal((await wallet.post('/wallet/demo/override', { uid: '99999', scope: 'issue' })).status, 200);
    const r2 = await login();
    assert.equal(r2.status, 502, j(r2.body)); assert.equal(r2.body.cia.error, 'bad idp proof'); assert.equal(r2.body.reason, 'user_cred_failed'); assert.equal(r2.body.demo, 'override:issue');
    const ok = await login(); assert.equal(ok.status, 200, j(ok.body));   // 덮어쓰기 없이 다시 — 새 자격증명 발급 성공
  });
  await t('시연 덮어쓰기(prove): salt 를 바꾸면 증명 생성이 실패한다(500 아님 — 409 demo_proof_failed)', async () => {
    assert.equal((await wallet.post('/wallet/demo/override', { s_u: randomScalar().toString(), scope: 'prove' })).status, 200);
    const r = await login();
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'demo_proof_failed'); assert.equal(r.body.demo, 'override:prove');
    assert.equal((await wallet.get('/wallet/status')).body.demoOverride, null);
    assert.equal((await wallet.post('/wallet/demo/override', { clear: true })).status, 200);
  });

  // 2026-10-14 사용자 요청: "증명도 가짜, 서명도 가짜" 버튼 — issue·prove 와 달리 발급·증명 자체는 정상으로 끝내고,
  // 지갑이 **보내는 복사본**만 바꿔친다(proveSession·buildExecute). 지갑은 자기 증명·서명을 검증하지 않으므로 /wallet/login
  // 은 200 을 낸다 — 거절은 받는 쪽(RP 의 verifyLogin, 체인의 PiCredVerifier·ecrecover)에서 일어난다.
  await t('시연 덮어쓰기(fake_proof) + 로그인: 지갑은 200, RP 검증은 bad_proof; 캐시는 더럽혀지지 않아 같은 세션 재검증·다음 로그인은 정상', async () => {
    assert.equal((await wallet.post('/wallet/demo/override', { scope: 'fake_proof' })).status, 200);
    assert.deepEqual((await wallet.get('/wallet/status')).body.demoOverride, { scope: 'fake_proof', fields: [] });
    const ch = newCh();
    const r = await login(ch);
    assert.equal(r.status, 200, j(r.body));   // 지갑은 자기 증명을 검증하지 않는다
    assert.equal(r.body.demo, 'override:fake_proof');
    assert.equal((await wallet.get('/wallet/status')).body.demoOverride, null, '한 번 쓰면 해제');
    const v = await verify(r.body, ch);
    assert.equal(v.ok, false, j(v)); assert.equal(v.reason, 'bad_proof');
    // 캐시가 더럽혀졌다면 같은 세션의 재검증(캐시 히트)도 같은 가짜 증명을 돌려준다 — 정상이어야 더럽혀지지 않은 것이다.
    const rv = await revalidate(ch.r_s);
    assert.equal(rv.status, 200, j(rv.body));
    assert.equal((await verify(rv.body, ch)).ok, true, '프루프 캐시가 더럽혀지지 않았다');
    // 다음 로그인(덮어쓰기 없이)도 정상 — 데모 스코프가 전역에 새지 않았다
    const ok = await login();
    assert.equal(ok.status, 200, j(ok.body));
  });
  await t('시연 덮어쓰기(fake_sig) + 로그인: 지갑은 200, RP 검증은 bad_signature; 한 번 쓰면 해제', async () => {
    assert.equal((await wallet.post('/wallet/demo/override', { scope: 'fake_sig' })).status, 200);
    const ch = newCh();
    const r = await login(ch);
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.demo, 'override:fake_sig');
    assert.equal((await wallet.get('/wallet/status')).body.demoOverride, null);
    const v = await verify(r.body, ch);
    assert.equal(v.ok, false, j(v)); assert.equal(v.reason, 'bad_signature');
    const ok = await login();
    assert.equal(ok.status, 200, j(ok.body));
  });
  await t('시연 덮어쓰기(fake_proof) + /wallet/tx: 체인이 InvalidProof 로 되돌리고 demo 플래그가 실린다', async () => {
    const to = '0x000000000000000000000000000000000000dEaD';
    const s = await loginOnce({ factoryAddress });
    await relay();
    assert.equal((await wallet.post('/wallet/demo/override', { scope: 'fake_proof' })).status, 200);
    const r = await wallet.post('/wallet/tx', { r_s: s.r_s, to }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 409, j(r.body));
    assert.equal(r.body.reason, 'execute_reverted'); assert.equal(r.body.detail, 'InvalidProof'); assert.equal(r.body.demo, 'override:fake_proof');
    assert.equal((await wallet.get('/wallet/status')).body.demoOverride, null, '한 번 쓰면 해제');
  });
  await t('시연 덮어쓰기(fake_sig) + /wallet/tx: 체인이 BadSignature 로 되돌리고 demo 플래그가 실린다', async () => {
    const to = '0x000000000000000000000000000000000000dEaD';
    const s = await loginOnce({ factoryAddress });
    await relay();
    assert.equal((await wallet.post('/wallet/demo/override', { scope: 'fake_sig' })).status, 200);
    const r = await wallet.post('/wallet/tx', { r_s: s.r_s, to }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 409, j(r.body));
    assert.equal(r.body.reason, 'execute_reverted'); assert.equal(r.body.detail, 'BadSignature'); assert.equal(r.body.demo, 'override:fake_sig');
  });

  await t('/wallet/tx disclose: 만족하는 구간은 새 π 로 실행되고 onchainDisclosure 가 있다; 불만족은 400 disclosure_unsatisfiable; mask 0 은 그대로 진행된다', async () => {
    // attrGateAddress 는 Task 6 가 RP 에 준다 — 그 전엔 dEaD 로 보내고 onchainDisclosure 만 본다(회로·컨트랙트 배선 확인이 목적).
    const to = '0x000000000000000000000000000000000000dEaD';
    const s = await loginOnce({ factoryAddress });
    // V10: 계정은 거울의 lastPublishedBlock 으로 maxRootAge(10) 를 본다. 격리 IdP 는 거울 하트비트가 꺼져 있어(캐노니컬 하트비트만
    // 돈다) 앞 케이스들 동안 거울이 늙었을 수 있다 — 실행 직전에 거울을 새로 올린다(운영에서는 IdP 의 거울 하트비트가 하는 일).
    await relay();
    const ok = await wallet.post('/wallet/tx', { r_s: s.r_s, to, data: '0x4e71d92d', disclose: [{ lo: '0', hi: '2007' }, null, null, null] }, { Origin: stack.rpOriginForWallet });
    assert.equal(ok.status, 200, j(ok.body));
    assert.equal(ok.body.disclosure.mask, '1'); assert.equal(ok.body.cacheHit, false);
    assert.equal(ok.body.onchainDisclosure.mask, '1');
    assert.deepEqual(ok.body.onchainDisclosure.lo, ['0', '0', '0', '0', '0', '0']);
    assert.deepEqual(ok.body.onchainDisclosure.hi, ['2007', '0', '0', '0', '0', '0']);
    const bad = await wallet.post('/wallet/tx', { r_s: s.r_s, to, disclose: [{ lo: '0', hi: '1980' }, null, null, null] }, { Origin: stack.rpOriginForWallet });
    assert.equal(bad.status, 400, j(bad.body)); assert.equal(bad.body.reason, 'disclosure_unsatisfiable');
    const plain = await wallet.post('/wallet/tx', { r_s: s.r_s, to }, { Origin: stack.rpOriginForWallet });
    assert.equal(plain.status, 200, j(plain.body)); assert.equal(plain.body.disclosure, null); assert.equal(plain.body.onchainDisclosure, null);
    // V9: disclose 는 길이 1..6 — 6칸을 다 채운 요청도 받는다(범위는 int 슬롯만 — 슬롯 0 을 6칸 배열의 첫 칸에).
    const six = await wallet.post('/wallet/tx', { r_s: s.r_s, to, disclose: [{ lo: '1990', hi: '1990' }, null, null, null, null, null] }, { Origin: stack.rpOriginForWallet });
    assert.equal(six.status, 200, j(six.body));
    assert.equal(six.body.disclosure.mask, '1');
    assert.equal(six.body.onchainDisclosure.mask, '1');
    assert.deepEqual(six.body.onchainDisclosure.lo, ['1990', '0', '0', '0', '0', '0']);
    assert.deepEqual(six.body.onchainDisclosure.hi, ['1990', '0', '0', '0', '0', '0']);
  });

  await t('V7 /wallet/tx: set 으로 국가 ∈ 집합을 증명하면 onchainDisclosure.set 이 sel 2·root 로 남는다; 비소속 집합은 400 disclosure_unsatisfiable; slot 6 은 bad_disclosure(V9: 0..5)', async () => {
    const to = '0x000000000000000000000000000000000000dEaD';
    const s = await loginOnce({ factoryAddress });
    // V10: 계정은 거울의 lastPublishedBlock 으로 maxRootAge(10) 를 본다. 격리 IdP 는 거울 하트비트가 꺼져 있어(캐노니컬 하트비트만
    // 돈다) 앞 케이스들 동안 거울이 늙었을 수 있다 — 실행 직전에 거울을 새로 올린다(운영에서는 IdP 의 거울 하트비트가 하는 일).
    await relay();
    const members = [410, 392, 840, 276, 250];
    const ok = await wallet.post('/wallet/tx', { r_s: s.r_s, to, disclose: [null, null, null, null], set: { slot: 1, members } }, { Origin: stack.rpOriginForWallet });
    assert.equal(ok.status, 200, j(ok.body));
    assert.equal(ok.body.onchainDisclosure.mask, '0');
    assert.equal(ok.body.onchainDisclosure.set.sel, '2');
    assert.equal(ok.body.onchainDisclosure.set.root, (await setRoot(members)).toString());
    const miss = await wallet.post('/wallet/tx', { r_s: s.r_s, to, set: { slot: 1, members: [392, 840] } }, { Origin: stack.rpOriginForWallet });
    assert.equal(miss.status, 400, j(miss.body)); assert.equal(miss.body.reason, 'disclosure_unsatisfiable');
    const bad = await wallet.post('/wallet/tx', { r_s: s.r_s, to, set: { slot: 6, members } }, { Origin: stack.rpOriginForWallet });
    assert.equal(bad.status, 400, j(bad.body)); assert.equal(bad.body.reason, 'bad_disclosure');
  });

  await t('스펙 2 predicate_type: 범위 술어를 enum 슬롯(1)에, 집합 술어를 unused 슬롯(4)에 걸면 /wallet/tx·/wallet/login 모두 400 predicate_type — 증명 전에 거른다', async () => {
    const to = '0x000000000000000000000000000000000000dEaD';
    const s = await loginOnce({ factoryAddress });
    const r1 = await wallet.post('/wallet/tx', { r_s: s.r_s, to, disclose: [null, { lo: '410', hi: '410' }, null, null, null, null] }, { Origin: stack.rpOriginForWallet });
    assert.equal(r1.status, 400, j(r1.body)); assert.equal(r1.body.reason, 'predicate_type'); assert.match(r1.body.detail, /슬롯 1/);
    const r2 = await wallet.post('/wallet/tx', { r_s: s.r_s, to, set: { slot: 4, members: [0] } }, { Origin: stack.rpOriginForWallet });
    assert.equal(r2.status, 400, j(r2.body)); assert.equal(r2.body.reason, 'predicate_type');
    const r3 = await loginNoRelay(newCh(), { disclose: [null, { lo: '410', hi: '410' }] });
    assert.equal(r3.status, 400, j(r3.body)); assert.equal(r3.body.reason, 'predicate_type');
    // string 슬롯(2)의 집합 술어는 허용된다 — 내 값(0)이 집합에 없으면 그다음 단계의 disclosure_unsatisfiable
    const r4 = await wallet.post('/wallet/tx', { r_s: s.r_s, to, set: { slot: 2, members: [7] } }, { Origin: stack.rpOriginForWallet });
    assert.equal(r4.status, 400, j(r4.body)); assert.equal(r4.body.reason, 'disclosure_unsatisfiable');
  });

  // ---- V10(2026-10-02 Task 9): 거울 뷰 기준 증명 ----
  await t('로그인 π 는 거울의 (revRoot, regRoot) 를 쓴다 — 캐노니컬이 앞서 있어도', async () => {
    await relay();                                              // 내 등록부 리프를 거울에 반영(첫 로그인 전제)
    // 캐노니컬만 epoch +1: 내 세션 하나를 폐기하고 게시한다(새 로그인의 세션·자격증명과는 무관). 거울은 릴레이 전이라 그대로다.
    const victim = newCh();
    assert.equal((await login(victim)).status, 200);
    assert.equal((await wallet.post('/wallet/session/revoke', { r_s: victim.r_s })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    assert.notEqual(BigInt(await canonC.revRoot()), BigInt(await mirrorC.revRoot()), '전제: 캐노니컬이 거울보다 앞서 있다');
    const ch = newCh();
    const r = await loginNoRelay(ch);
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.root, BigInt(await mirrorC.revRoot()).toString());
    assert.equal(r.body.regRoot, BigInt(await mirrorC.regRoot()).toString());
    assert.equal((await verify(r.body, ch)).ok, true, '거울을 읽는 검증기가 받아들인다');
    // 거울이 따라오면 root 가 바뀐다 — 새 재검증은 새 거울 root 로 다시 증명한다(캐시 키가 (chainId, rev, reg)).
    await relay();
    const rv = await revalidate(ch.r_s);
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.cacheHit, false);
    assert.equal(rv.body.root, BigInt(await mirrorC.revRoot()).toString());
    assert.equal((await verify(rv.body, ch)).ok, true);
  });
  await t('새 자격증명은 거울에 내 슬롯이 반영될 때까지 registry_unpublished 로 기다렸다가 릴레이 뒤 성공한다', async () => {
    // 이 지갑은 등록이 하나뿐이다 — "첫 발급" 대신 자격증명 은퇴(캐노니컬 즉시 게시, 거울은 그대로) 뒤의 재발급으로 같은 경로를 탄다.
    await relayIfBehind();
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'credential' })).status, 200);
    const ch = newCh();
    let doneAt = null;
    const p = loginNoRelay(ch);                                 // 폴링 시작
    p.then(() => { doneAt = Date.now(); }, () => { doneAt = Date.now(); });
    await sleep(1500);
    assert.equal(doneAt, null, '릴레이 전에는 끝나지 않는다(거울에 새 리프가 없다)');
    const relayStart = Date.now();
    await relay();
    const r = await p;
    // 판별력(Task 9 수정 Minor): 로그인은 릴레이를 누른 뒤에야 끝났어야 한다 — 거울 반영을 기다리지 않았다면 그 전에 끝났다.
    assert.ok(doneAt >= relayStart, `로그인 완료(${doneAt})가 릴레이 시작(${relayStart}) 뒤여야 한다`);
    assert.equal(r.status, 200, j(r.body)); assert.ok(r.body.timings.userCredMs > 0);
    assert.equal(r.body.regRoot, BigInt(await mirrorC.regRoot()).toString());
    assert.equal((await verify(r.body, ch)).ok, true);
  });
  await t('fresh 가 아닌 경로: 거울의 내 슬롯이 캐노니컬과 다르면(거울 지연) 재검증은 503 registry_unpublished(세션 유지), 릴레이 뒤 200', async () => {
    // 기존 세션 하나를 잡고, 거울에만 "내 슬롯 ≠ 내 자격증명" 상태를 만든다: 바꿔치기 → 릴레이 → 되돌리기(릴레이 안 함).
    // 캐노니컬은 내 자격증명으로 돌아왔으므로 지갑은 폐기로 보지 않고, 거울 뷰로는 증인이 없어 증명하지 않는다.
    const ch = newCh();
    assert.equal((await login(ch)).status, 200);
    assert.equal((await cia.adminPost('/cia/admin/registry/tamper', { uid })).status, 200);
    await relay();
    assert.equal((await cia.adminPost('/cia/admin/registry/restore', { uid })).status, 200);
    const lag = await revalidate(ch.r_s);
    assert.equal(lag.status, 503, j(lag.body)); assert.equal(lag.body.reason, 'registry_unpublished');
    assert.ok((await wallet.get('/wallet/status')).body.sessions[ch.r_s], '세션은 지우지 않는다');
    await relay();
    const ok = await revalidate(ch.r_s);
    assert.equal(ok.status, 200, j(ok.body));
    assert.equal(ok.body.regRoot, BigInt(await mirrorC.regRoot()).toString());
    assert.equal((await verify(ok.body, ch)).ok, true);
  });
  await t('/wallet/status 에 mirror·canonical 이 있다', async () => {
    const s = (await wallet.get('/wallet/status')).body;
    assert.equal(s.mirror.address.toLowerCase(), cia.mirrorAddress.toLowerCase());
    assert.equal(s.mirror.epoch, (await mirrorC.epoch()).toString());
    assert.equal(s.mirror.lastPublishedBlock, (await mirrorC.lastPublishedBlock()).toString());
    assert.equal(s.canonical.logAddress.toLowerCase(), cia.logAddress.toLowerCase());
    assert.equal(s.canonical.epoch, (await canonC.epoch()).toString());
    assert.match(s.canonical.rpc, /^http/);
  });

} finally {
  await stack.stop();
  provider.destroy();
}

// ---- 독립 시험(공유 stack 과 무관한 자기 IdP·지갑): 지갑 상태 파일 8→10 이행이 auid 를 재계산하는지(file 모드)와
// snap 모드(파일에 비밀 없음)는 등록을 비우는지. isolated_mode3_stack.mjs 의 walletEnv 는 자신의 MODE3_WALLET_STATE_FILE 뒤에
// 스프레드되므로(헬퍼 수정 없이) 이 경로를 바로 덮어쓸 수 있다 — v8 모양 상태 파일을 그 경로에 미리 써 둔다.
// uid 424242 는 IdP 에 등록돼 있지 않지만 /wallet/status 는 파일의 공개 부분만 읽고 IdP 를 부르지 않으므로 상관없다.
await t('지갑 상태 파일 8→10 이행: file 모드 등록은 auid 를 s_u 로 재계산해 유지(r_u·cm_u 삭제, 세션 비움), snap 모드(비밀 없음) 등록은 비운다; pendingBounds 는 빈 배열 (+ V10: 거울 주소가 없으면 체인 라우트는 503)', async () => {
  const { auidOf } = await import('../lib/mode3_credential.js');
  const reg = await createRegistration(424242n);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-wallet-v8-'));
  const stateFile = path.join(dir, 'mode3_wallet_state.json');
  try {
    fs.writeFileSync(stateFile, JSON.stringify({ version: 8, registration: { uid: '424242', s_u: reg.s_u.toString(), r_u: '1', cm_u: { x: '1', y: '2' }, sk_u: reg.sk_u, pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() }, slot: 3, attrs: ['1990', '410', '2', '0', '0', '0'], profile: { birthYear: '1990', country: 'KR' }, userCred: { Cf_u: '9' } }, sessions: { '5': {} } }));
    const stack2 = await startIsolatedMode3Stack({ rp: false, walletEnv: { MODE3_WALLET_STATE_FILE: stateFile, MODE3_MIRROR_ADDRESS: '' } });
    try {
      const s = (await stack2.wallet.get('/wallet/status')).body;
      assert.equal(s.registered, true); assert.equal(s.uid, '424242'); assert.equal(s.slot, 3);
      assert.equal(s.auid, (await auidOf({ uid: 424242n, s_u: reg.s_u })).toString(), 'auid 는 s_u 로 재계산');
      assert.deepEqual(s.attrs, ['1990', '410', '2', '0', '0', '0']); assert.deepEqual(s.sessions, {}); assert.equal(s.userCred, null);
      assert.deepEqual(s.pendingBounds, [], '2026-10-22: 이행 뒤 pendingBounds 는 빈 배열');
      const onDisk = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      assert.equal(onDisk.version, 10); assert.equal(onDisk.registration.r_u, undefined); assert.equal(onDisk.registration.cm_u, undefined); assert.ok(onDisk.registration.auid);
      assert.deepEqual(onDisk.pendingBounds, []);
      const pre = await stack2.wallet.post('/wallet/authorize/precheck', { arid: '1', origin: 'http://x', cert_s: {}, pk_trace: { x: '1', y: '2' } });
      assert.equal(pre.status, 503, j(pre.body)); assert.equal(pre.body.detail, 'MODE3_MIRROR_ADDRESS not configured');
    } finally { await stack2.stop(); }
    fs.writeFileSync(stateFile, JSON.stringify({ version: 8, registration: { uid: '424242', cm_u: { x: '1', y: '2' }, pk_u: { x: '1', y: '2' }, slot: 0, attrs: ['1990', '410', '0', '0', '0', '0'], userCred: null }, sessions: {} }));
    const stack3 = await startIsolatedMode3Stack({ rp: false, walletEnv: { MODE3_WALLET_STATE_FILE: stateFile, MODE3_WALLET_SECRETS: 'snap', MODE3_MIRROR_ADDRESS: '' } });
    try { assert.equal((await stack3.wallet.get('/wallet/status')).body.registered, false, 'snap 모드 옛 등록은 auid 를 재계산할 수 없어 비운다'); }
    finally { await stack3.stop(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ---- 독립 시험(리뷰 T2·S2, 2026-10-13): /wallet/login 의 cred_revoked 1회 재시도. 재시도 경로는 "지갑은 캐노니컬 등록부에서 자기 C_u 가
// 살아 있다고 보는데 IdP 는 이미 물렸다" 일 때만 탄다(평소엔 등록부가 먼저 알려 처음부터 새 C_u 를 만든다). 그 순간을 결정적으로 만들려고
// 자기 스택의 CIA_RPC_URL(캐노니컬 게시) 앞에 eth_sendRawTransaction 을 붙잡는 게이트 프록시를 둔다 — 관리자 scope=credential 의 은퇴(동기)는
// 끝났지만 그 게시 tx 는 프록시에 붙잡혀 체인에는 옛 리프가 남아 있다. 세션 헤드 조회(CIA_CHAIN_RPCS)·지갑·거울 릴레이는 :8545 직결이다.
// 재시도가 실제로 일어났는지는 timings 로 가른다: 재시도 경로만 issueMs(첫 시도 + 재시도) > userCredMs(재시도분)다(처음부터 새 C_u 면 둘이 같다).
await t('리뷰 T2: IdP 가 먼저 물린 C_u(체인엔 아직 살아 있음) → 409 cred_revoked → 새 C_u 로 한 번 재시도해 200(userCredMs>0, Cf_u 바뀜); 재시도도 409 면 무한 재시도 없이 502 issue_failed', async () => {
  const UPSTREAM = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
  const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  let hold = null;   // { seen, released } — 다음 eth_sendRawTransaction 하나를 붙잡는다
  const proxy = http.createServer(async (req, res) => {
    let body = '';
    for await (const c of req) body += c;
    let gate = null;
    try { const jj = JSON.parse(body); if (hold && (Array.isArray(jj) ? jj : [jj]).some((x) => x.method === 'eth_sendRawTransaction')) gate = hold; } catch { /* 그대로 전달 */ }
    if (gate) { gate.seen.resolve(); await gate.released.promise; }
    try {
      const up = await fetch(UPSTREAM, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
      res.writeHead(up.status, { 'content-type': 'application/json' }); res.end(await up.text());
    } catch { res.writeHead(502); res.end(); }
  });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const st = await startIsolatedMode3Stack({ rp: false, ciaEnv: { CIA_RPC_URL: `http://127.0.0.1:${proxy.address().port}` } });
  try {
    const { cia: c2, wallet: w2 } = st;
    const svc = await c2.registerRp(st.rpOriginForWallet);
    const canon = new ethers.Contract(c2.logAddress, MODE3_ROOTS_ABI, c2.revProvider);   // 공유 provider 는 위 finally 에서 이미 닫혔다
    const post = () => w2.post('/wallet/login', { arid: svc.arid, origin: svc.origin, cert_s: svc.cert_s, pk_trace: { x: svc.pk_trace.x.toString(), y: svc.pk_trace.y.toString() }, r_s: randomScalar().toString(), r_rp: randomScalar().toString() }, { Origin: st.rpOriginForWallet });
    const active = async () => (await c2.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === uid)?.activeCf_u ?? null;
    const walletCf = async () => (await w2.get('/wallet/status')).body.userCred?.Cf_u ?? null;
    const until = async (pred, label, ms = 15_000) => { const end = Date.now() + ms; while (!(await pred())) { assert.ok(Date.now() < end, label); await sleep(100); } };
    assert.equal((await w2.post('/wallet/register', { uid, pwd: 'password123' })).status, 201);
    const l0 = await st.withRelay(post);
    assert.equal(l0.status, 200, j(l0.body));
    const cf0 = await walletCf();
    assert.equal(await active(), cf0);
    await st.relayIfBehind();   // 게이트를 거는 동안 withRelay 의 첫 릴레이가 게시 잠금에 묶이지 않게 거울을 미리 맞춘다

    // (i) 재시도 성공
    const reg0 = await canon.regRoot();
    hold = { seen: deferred(), released: deferred() };
    const rv1 = c2.adminPost('/cia/revoke', { uid, scope: 'credential' });   // 은퇴(동기) → 즉시 게시 tx 가 게이트에 붙잡힌다
    await hold.seen.promise;
    let gate = hold;
    hold = null;
    assert.equal(await active(), null, '관리자 폐기의 은퇴는 게시 전에 끝난다');
    assert.equal(await canon.regRoot(), reg0, '체인에는 아직 옛 리프 — 지갑은 자기 C_u 가 살아 있다고 본다');
    const p1 = post();   // 재사용 → 409 cred_revoked → 새 C_u 로 재시도 → 그 게시는 잠금(붙잡힌 폐기 게시) 뒤에 줄 선다
    await until(async () => { const a = await active(); return a !== null && a !== cf0; }, '재시도의 새 C_u 가 CIA 에 앉지 않았다');
    gate.released.resolve();
    const r1 = await st.withRelay(() => p1);   // 지갑이 거울 반영을 기다리므로 릴레이를 대신 눌러 준다
    assert.equal(r1.status, 200, j(r1.body));
    assert.ok(r1.body.timings.userCredMs > 0, '재시도로 새 C_u 를 받았다');
    assert.ok(r1.body.timings.issueMs > r1.body.timings.userCredMs, `재시도 경로여야 한다(첫 시도 409 + 재시도): ${j(r1.body.timings)}`);
    const cf1 = await walletCf();
    assert.ok(cf1 && cf1 !== cf0, '지갑의 사용자 자격증명이 새 Cf_u 로 바뀐다');
    assert.equal(await active(), cf1, 'CIA 의 활성 자격증명 = 지갑의 새 Cf_u');
    assert.equal((await rv1).status, 200);

    // (ii) 재시도도 409 — 재시도의 새 C_u 도 게시 대기 중에 관리자가 물린다(리뷰 S2 → 409 cred_revoked). 지갑은 한 번만 다시 시도한다.
    await st.relayIfBehind();
    const reg1 = await canon.regRoot();
    hold = { seen: deferred(), released: deferred() };
    const rv2 = c2.adminPost('/cia/revoke', { uid, scope: 'credential' });
    await hold.seen.promise;
    gate = hold;
    hold = null;
    assert.equal(await canon.regRoot(), reg1, '체인에는 아직 cf1 의 리프 — 지갑의 첫 시도는 재사용(→ 409)');
    const p2 = post();
    await until(async () => { const a = await active(); return a !== null && a !== cf1; }, '재시도의 새 C_u 가 CIA 에 앉지 않았다');
    const rv3 = c2.adminPost('/cia/revoke', { uid, scope: 'credential' });
    await until(async () => (await active()) === null, '두 번째 관리자 폐기의 은퇴가 돌지 않았다');
    const releasedAt = Date.now();
    gate.released.resolve();
    const r2 = await st.withRelay(() => p2);
    const tookMs = Date.now() - releasedAt;
    assert.ok(tookMs < 15_000, `재시도가 끝나지 않는다(${tookMs}ms)`);
    assert.equal(r2.status, 502, j(r2.body)); assert.equal(r2.body.reason, 'issue_failed'); assert.equal(r2.body.cia?.reason, 'cred_revoked');
    assert.ok(r2.body.timings.issueMs > r2.body.timings.userCredMs, `두 번 시도했어야 한다: ${j(r2.body.timings)}`);
    assert.equal(await active(), null, '세 번째 시도는 없다(있었다면 새 C_u 가 앉았다)');
    assert.equal(await walletCf(), null, '지갑은 물린 C_u 를 보관하지 않는다');
    assert.equal((await rv2).status, 200); assert.equal((await rv3).status, 200);
    // 회복: 다음 로그인은 처음부터 새 C_u 로 성공한다
    const r3 = await st.withRelay(post);
    assert.equal(r3.status, 200, j(r3.body)); assert.ok(r3.body.timings.userCredMs > 0);
    assert.equal(await active(), await walletCf());
  } finally {
    await st.stop();
    proxy.close();
  }
});

// ---- 독립 시험(Task 13 B4): auth_code 전달 — IdP 가 CIA_ISSUE_AUTH=code 로 떠 있을 때만 의미가 있어 자기 스택을 쓴다
// (공유 stack 의 IdP 는 isolated_cia.mjs 가 CIA_ISSUE_AUTH='' 로 고정한다).
await t('/wallet/login 의 auth_code 가 /cia/issue 로 전달된다(IdP 를 CIA_ISSUE_AUTH=code 로 띄운 스택): 코드 없으면 401 auth_code_required, 있으면 200', async () => {
  const st = await startIsolatedMode3Stack({ rp: false, ciaEnv: { CIA_ISSUE_AUTH: 'code' } });
  try {
    const { cia: c3, wallet: w3 } = st;
    const svc = await c3.registerRp(st.rpOriginForWallet);
    const regR = await w3.post('/wallet/register', { uid, pwd: 'password123' });
    assert.equal(regR.status, 201, j(regR.body));
    const base = { arid: svc.arid, origin: svc.origin, cert_s: svc.cert_s, pk_trace: { x: svc.pk_trace.x.toString(), y: svc.pk_trace.y.toString() } };
    const noCode = await st.withRelay(() => w3.post('/wallet/login', { ...base, r_s: randomScalar().toString(), r_rp: randomScalar().toString() }, { Origin: st.rpOriginForWallet }));
    assert.equal(noCode.status, 401, j(noCode.body)); assert.equal(noCode.body.reason, 'auth_code_required');
    const authResp = await c3.post('/cia/auth/code', { uid, pwd: 'password123', auid: regR.body.auid });
    assert.equal(authResp.status, 200, j(authResp.body));
    const withCode = await st.withRelay(() => w3.post('/wallet/login', { ...base, r_s: randomScalar().toString(), r_rp: randomScalar().toString(), auth_code: authResp.body.code }, { Origin: st.rpOriginForWallet }));
    assert.equal(withCode.status, 200, j(withCode.body));
  } finally { await st.stop(); }
});

// ---- 독립 시험(Task 13 B4): code 로 등록 — IdP 의 /cia/user/register_code(사용자 세션 필요)로 받은 1회용 코드를 pwd 대신 쓴다.
// fetch 는 쿠키를 자동으로 보내지 않으므로(tests/test_cia_accounts.mjs 와 같은 관례) Set-Cookie 를 되돌리는 작은 jar 를 둔다.
await t('/wallet/register { uid, code }: register_code 로 받은 코드로 등록된다(pwd 없이)', async () => {
  const st = await startIsolatedMode3Stack({ rp: false });
  try {
    const { cia: c4, wallet: w4 } = st;
    const jar = {};
    const ciaFetch = async (p, init = {}) => {
      const r = await fetch(`${c4.base}${p}`, { ...init, headers: { 'Content-Type': 'application/json', ...(jar.cookie ? { Cookie: jar.cookie } : {}), ...(init.headers ?? {}) } });
      const sc = r.headers.get('set-cookie');
      if (sc) jar.cookie = sc.split(';')[0];
      return { status: r.status, body: await r.json().catch(() => null) };
    };
    assert.equal((await ciaFetch('/cia/user/login', { method: 'POST', body: JSON.stringify({ uid, pwd: 'password123' }) })).status, 200, '시드 계정(12345) 로그인');
    const rc = await ciaFetch('/cia/user/register_code', { method: 'POST', body: JSON.stringify({}) });
    assert.equal(rc.status, 200, j(rc.body));
    assert.match(rc.body.code, /^[0-9a-f]+$/);
    const r = await w4.post('/wallet/register', { uid, code: rc.body.code });
    assert.equal(r.status, 201, j(r.body));
    assert.equal(r.body.uid, uid);
    assert.equal((await w4.get('/wallet/status')).body.registered, true);
  } finally { await st.stop(); }
});

process.exit(failed === 0 ? 0 : 1);
