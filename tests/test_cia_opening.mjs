// 승인된 개봉 — 격리 IdP + :8545 + build/mode3. (chain 그룹)   node tests/test_cia_opening.mjs
// 2026-11-19(스펙 2026-11-19-mode3-trace-without-tag T6~T8): 트레이스 태그가 없다. 서비스는 그 PPID 의 가장 최신 로그인의 증명 한 벌(공개 입력에 PPID·arid·auid_s)을 내고,
// zkIdP 는 증명·서명·arid 를 확인해 대기 목록에 둔다. 관리자가 승인하면 발급 때 남긴 auid_s 기록에서 uid 를 찾는다(복호·조각·전수 대입 없음).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { VKEY_PATH } from '../lib/mode3_wallet.js';
import { PUB_INDEX } from '../lib/mode3_onchain.js';
import { signOpenRequest, signOpenResult } from '../lib/mode3_opening.js';
import { issueV11, proveV11, userOf, regBody, TESTUSER_ATTRS, ALICE_ATTRS } from './helpers/mode3_flow.mjs';

const j = (o) => JSON.stringify(o, (_, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH}`);
const provider = getProvider();
const cia = await startIsolatedCia();
const nowTs = () => Math.floor(Date.now() / 1000).toString();

try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  const S1 = await cia.registerRp('http://127.0.0.1:3101', 's1');
  const S2 = await cia.registerRp('http://127.0.0.1:3102', 's2');

  // 사용자 등록(지갑 lib 그대로). C_u(사용자 자격증명)는 사용자당 하나 — user.blind_u 가 처음 발급에서 정해져 모든 트랜스크립트가 재사용한다.
  const reg = await cia.registerUser('12345', 'password123');
  const user = userOf(reg, '12345', TESTUSER_ATTRS);
  async function loginTranscript(svc, who = user, allowAgent = 0n) {
    const iss = await issueV11(cia, who, { arid: svc.arid, provider, allowAgent, blind_u: who.blind_u });
    assert.equal(iss.r.status, 200, j(iss.r.body));
    who.blind_u = iss.blind_u;   // 처음 호출이면 새로 받은 blind_u 를 저장해 이후 호출이 같은 C_u 를 재사용한다
    const { proof, publicSignals } = await proveV11(iss, { arid: svc.arid, pk_CIA, provider, logAddress: cia.logAddress });
    return { proof, publicSignals, PPID: publicSignals[PUB_INDEX.PPID], auid_s: publicSignals[PUB_INDEX.AUID_S] };
  }
  async function openRequest(svc, T, { wallet = svc.serviceWallet, ts = nowTs(), arid = svc.arid, auid_s = T.auid_s, publicSignals = T.publicSignals, proof = T.proof } = {}) {
    const sig = await signOpenRequest(wallet, { arid, PPID: T.PPID, auid_s, ts });
    return cia.post('/cia/open/request', { arid, publicSignals, proof, ts, sig });
  }
  async function fetchResult(svc, id, { wallet = svc.serviceWallet, ts = nowTs() } = {}) {
    const sig = await signOpenResult(wallet, id, ts);
    return cia.get(`/cia/open/${id}?ts=${ts}&sig=${encodeURIComponent(sig)}`);
  }
  const opening = async (id) => (await cia.adminGet('/cia/openings')).body.openings.find((o) => o.id === id);

  let T1, id1;
  await t('정상 경로: 요청 202 pending(uid 없음) → 승인 → 결과 200 에 uid — 태그·조각 없이 그 로그인의 auid_s 로 찾는다', async () => {
    T1 = await loginTranscript(S1);
    assert.equal(T1.publicSignals.length, 29);
    const r = await openRequest(S1, T1);
    assert.equal(r.status, 202, j(r.body)); assert.equal(r.body.status, 'pending'); id1 = r.body.id;
    const mine = await opening(id1);
    assert.equal(mine.status, 'pending'); assert.equal(mine.uid, null, '승인 전에는 uid 를 찾지 않는다'); assert.equal(mine.auid_s, T1.auid_s);
    for (const k of ['c1', 'c2', 'D_svc', 'tagKey']) assert.equal(k in mine, false, `${k} 는 더 이상 없다`);
    assert.equal((await fetchResult(S1, id1)).status, 202);
    const a = await cia.adminPost(`/cia/openings/${id1}/approve`);
    assert.equal(a.status, 200, j(a.body)); assert.equal(a.body.status, 'approved'); assert.equal(a.body.resolved, true);
    const res = await fetchResult(S1, id1);
    assert.equal(res.status, 200, j(res.body)); assert.equal(res.body.uid, '12345'); assert.equal(res.body.resolved, true);
    assert.equal(res.body.PPID, T1.PPID); assert.equal(res.body.r_s, undefined);
    assert.equal(res.body.allowAgent, '0'); assert.equal(res.body.max_height, T1.publicSignals[PUB_INDEX.MAX_HEIGHT]); assert.equal(res.body.chainid, '31337');
    assert.equal((await opening(id1)).uid, '12345', '감사 기록에 uid');
  });

  await t('zkIdP 는 발급마다 auid_s 를 기록한다 — 다른 서비스에 다시 로그인해(최신 auid_s 가 바뀌어도) 앞 로그인의 개봉이 된다', async () => {
    const Told = await loginTranscript(S1);
    const Tnew = await loginTranscript(S2);   // 같은 사용자의 더 최신 발급 — 계정의 lastAuidS 는 이제 이 값이다
    assert.notEqual(Told.auid_s, Tnew.auid_s);
    const acct = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === '12345');
    assert.equal(acct.lastAuidS.value, Tnew.auid_s);
    const { body: { id } } = await openRequest(S1, Told);
    assert.equal((await cia.adminPost(`/cia/openings/${id}/approve`)).body.resolved, true);
    assert.equal((await fetchResult(S1, id)).body.uid, '12345');
  });

  await t('allowAgent = 1 로 로그인한 세션의 개봉 결과에는 allowAgent 1 이 남는다', async () => {
    const T = await loginTranscript(S1, user, 1n);
    const { body: { id } } = await openRequest(S1, T);
    assert.equal((await cia.adminPost(`/cia/openings/${id}/approve`)).status, 200);
    const res = await fetchResult(S1, id);
    assert.equal(res.status, 200, j(res.body)); assert.equal(res.body.allowAgent, '1'); assert.equal(res.body.uid, '12345');
  });

  await t('같은 로그인(arid·PPID·auid_s)의 재요청은 새 id 를 만들지 않는다(200, 같은 id) — 다른 로그인은 새 id', async () => {
    const r = await openRequest(S1, T1);
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.id, id1);
    const r2 = await openRequest(S1, await loginTranscript(S1));
    assert.equal(r2.status, 202, j(r2.body)); assert.notEqual(r2.body.id, id1);
  });

  const regA = await cia.registerUser('67890', 'alicepw');
  const userB = userOf(regA, '67890', ALICE_ATTRS);
  await t('다른 사용자의 로그인은 그 사용자의 uid 로 열린다', async () => {
    const TB = await loginTranscript(S1, userB);
    const { body: { id } } = await openRequest(S1, TB);
    assert.equal((await cia.adminPost(`/cia/openings/${id}/approve`)).status, 200);
    assert.equal((await fetchResult(S1, id)).body.uid, '67890');
  });

  await t('앞자리 0 이 붙은 공개 입력으로 요청해도 IdP 는 정규형으로 맞춰 받는다 (2026-09-18 점검 1)', async () => {
    const T = await loginTranscript(S1);
    const padded = T.publicSignals.map((v, i) => (i === PUB_INDEX.PPID ? '0' + v : v));
    const r = await openRequest(S1, T, { publicSignals: padded });
    assert.equal(r.status, 202, j(r.body));
    assert.equal((await opening(r.body.id)).PPID, T.PPID, '저장은 정규형');
  });

  await t('거절 → 결과 403 denied; 결정된 항목은 다시 결정할 수 없고, 거절된 로그인은 다시 요청할 수 있다', async () => {
    const T = await loginTranscript(S1);
    const { body: { id } } = await openRequest(S1, T);
    assert.equal((await cia.adminPost(`/cia/openings/${id}/deny`)).status, 200);
    const res = await fetchResult(S1, id);
    assert.equal(res.status, 403, j(res.body)); assert.equal(res.body.status, 'denied'); assert.equal(res.body.uid, undefined);
    assert.equal((await cia.adminPost(`/cia/openings/${id}/approve`)).status, 409, '결정된 항목은 다시 결정할 수 없다');
    const r2 = await openRequest(S1, T);
    assert.equal(r2.status, 202, j(r2.body)); assert.notEqual(r2.body.id, id, '거절된 로그인은 새 요청이 된다');
    assert.equal((await opening(id)).uid, null, '거절한 항목에는 uid 가 없다');
  });

  await t('기록에 없는 auid_s(이 zkIdP 가 낸 값이 아니다): 서비스는 증명 없이 값을 지어낼 수 없다 — 공개 입력을 고치면 증명이 깨진다(bad_proof)', async () => {
    const T = await loginTranscript(S1);
    const forged = [...T.publicSignals]; forged[PUB_INDEX.AUID_S] = (BigInt(T.auid_s) + 1n).toString();
    const r = await openRequest(S1, T, { publicSignals: forged, auid_s: forged[PUB_INDEX.AUID_S] });
    assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.error, 'bad_proof');
    // 서명한 auid_s 와 증명의 auid_s 가 다르면 서명부터 맞지 않는다
    const r2 = await openRequest(S1, T, { auid_s: (BigInt(T.auid_s) + 1n).toString() });
    assert.equal(r2.status, 401, j(r2.body)); assert.equal(r2.body.error, 'bad_signature');
  });

  await t('남의 트랜스크립트: S2 가 S1 의 로그인을 열려 하면 wrong_arid 403 (유출된 로그로는 못 연다)', async () => {
    const r = await openRequest(S2, T1);
    assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.error, 'wrong_arid');
  });

  await t('서명·신선도·형식: 다른 키 서명 401, 오래된 ts 401, 손댄 증명 403, 옛 34개 배열 400, 미등록 arid 404', async () => {
    const T = await loginTranscript(S1);
    assert.equal((await openRequest(S1, T, { wallet: S2.serviceWallet })).status, 401, '다른 서비스의 키');
    assert.equal((await openRequest(S1, T, { ts: (Number(nowTs()) - 3600).toString() })).status, 401, '오래된 ts');
    const bad = JSON.parse(JSON.stringify(T.proof)); bad.pi_a[0] = (BigInt(bad.pi_a[0]) + 1n).toString();
    const rp = await openRequest(S1, T, { proof: bad });
    assert.equal(rp.status, 403, j(rp.body)); assert.equal(rp.body.error, 'bad_proof');
    assert.equal((await openRequest(S1, T, { publicSignals: [...T.publicSignals, '0', '0', '0', '0', '0'] })).status, 400, '태그 시절의 34개');
    assert.equal((await openRequest(S1, T, { arid: '999999' })).status, 404, '미등록 arid');
  });

  await t('결과 수령: 다른 RP 의 서명이면 401, 오래된 ts 401, 없는 id 404', async () => {
    assert.equal((await fetchResult(S1, id1, { wallet: S2.serviceWallet })).status, 401);
    assert.equal((await fetchResult(S1, id1, { ts: (Number(nowTs()) - 3600).toString() })).status, 401);
    assert.equal((await fetchResult(S1, 'deadbeef')).status, 404);
  });

  await t('admin 엔드포인트는 시크릿 없이 401', async () => {
    assert.equal((await cia.get('/cia/openings')).status, 401);
    assert.equal((await cia.post(`/cia/openings/${id1}/approve`)).status, 401);
    assert.equal((await cia.get('/cia/rps')).status, 401);
  });

  await t('MODE3_VKEY_PATH 가 없으면 개봉 요청은 503', async () => {
    const cia2 = await startIsolatedCia({ env: { MODE3_VKEY_PATH: '/nonexistent/vkey.json' } });
    try {
      const S = await cia2.registerRp('http://127.0.0.1:3199', 's-vkey-missing');
      // cia2 는 별도 격리 인스턴스라 다시 등록해야 한다 — 같은 지갑 정체성(reg)으로 등록 증명을 만들어 등록한다.
      const r0 = await cia2.post('/cia/register', { uid: '12345', pwd: 'password123', ...(await regBody(reg, '12345')) });
      assert.equal(r0.status, 201, j(r0.body));
      const user2 = userOf(reg, '12345', TESTUSER_ATTRS);
      const iss2 = await issueV11(cia2, user2, { arid: S.arid, provider });
      assert.equal(iss2.r.status, 200, j(iss2.r.body));
      const keys2 = (await cia2.get('/cia/public_keys')).body;
      const { proof, publicSignals } = await proveV11(iss2, { arid: S.arid, pk_CIA: { x: BigInt(keys2.pk_CIA.x), y: BigInt(keys2.pk_CIA.y) }, provider, logAddress: cia2.logAddress });
      const ts = nowTs();
      const sig = await signOpenRequest(S.serviceWallet, { arid: S.arid, PPID: publicSignals[PUB_INDEX.PPID], auid_s: publicSignals[PUB_INDEX.AUID_S], ts });
      const r = await cia2.post('/cia/open/request', { arid: S.arid, publicSignals, proof, ts, sig });
      assert.equal(r.status, 503, j(r.body));
    } finally { await cia2.stop(); }
  });

  // 리뷰 2026-11-19(trace I-1·M-8): 기록을 밀어내면 사용자가 발급을 되풀이해 지난 로그인의 개봉을 스스로 막는다 — 차면 발급을 거절한다.
  // 승인 경로의 resolved:false 는 계정을 지워(관리자) 기록이 없어진 경우로 본다.
  await t('발급 기록은 밀려나지 않는다: 상한(CIA_AUID_S_LOG_MAX=2)에 닿으면 발급은 409 auid_log_full 이고 첫 로그인은 여전히 열린다 — 기록에 없는 auid_s 는 승인해도 resolved:false(uid 없음)', async () => {
    const cia3 = await startIsolatedCia({ env: { CIA_AUID_S_LOG_MAX: '2' } });
    try {
      const S = await cia3.registerRp('http://127.0.0.1:3198', 's-log-cap');
      const r0 = await cia3.post('/cia/register', { uid: '12345', pwd: 'password123', ...(await regBody(reg, '12345')) });
      assert.equal(r0.status, 201, j(r0.body));
      const u3 = userOf(reg, '12345', TESTUSER_ATTRS);
      const keys3 = (await cia3.get('/cia/public_keys')).body, pk3 = { x: BigInt(keys3.pk_CIA.x), y: BigInt(keys3.pk_CIA.y) };
      const transcript = async () => {
        const iss = await issueV11(cia3, u3, { arid: S.arid, provider, ...(u3.blind_u ? { blind_u: u3.blind_u } : {}) });
        if (iss.r.status !== 200) return { r: iss.r };
        u3.blind_u = iss.blind_u;
        const { proof, publicSignals } = await proveV11(iss, { arid: S.arid, pk_CIA: pk3, provider, logAddress: cia3.logAddress });
        return { r: iss.r, proof, publicSignals, PPID: publicSignals[PUB_INDEX.PPID], auid_s: publicSignals[PUB_INDEX.AUID_S] };
      };
      const request = async (T) => { const ts = nowTs(); return cia3.post('/cia/open/request', { arid: S.arid, publicSignals: T.publicSignals, proof: T.proof, ts, sig: await signOpenRequest(S.serviceWallet, { arid: S.arid, PPID: T.PPID, auid_s: T.auid_s, ts }) }); };
      const result = async (id) => { const ts = nowTs(); return cia3.get(`/cia/open/${id}?ts=${ts}&sig=${encodeURIComponent(await signOpenResult(S.serviceWallet, id, ts))}`); };
      const Ta = await transcript(), Tb = await transcript();
      assert.equal(Ta.r.status, 200, j(Ta.r.body)); assert.equal(Tb.r.status, 200, j(Tb.r.body));
      const full = await transcript();
      assert.equal(full.r.status, 409, j(full.r.body)); assert.equal(full.r.body.reason, 'auid_log_full');
      const acct = (await cia3.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === '12345');
      assert.equal(acct.lastAuidS.value, Tb.auid_s, '거절된 발급은 아무것도 바꾸지 않는다');
      const qa = await request(Ta); assert.equal(qa.status, 202, j(qa.body));
      assert.equal((await cia3.adminPost(`/cia/openings/${qa.body.id}/approve`)).body.resolved, true, '첫 로그인의 기록이 남아 있다');
      assert.equal((await result(qa.body.id)).body.uid, '12345');
      const qb = await request(Tb); assert.equal(qb.status, 202, j(qb.body));
      const del = await cia3.adminPost('/cia/account/delete', { uid: '12345' }); assert.equal(del.body.deleted, true, j(del.body));
      const ap = await cia3.adminPost(`/cia/openings/${qb.body.id}/approve`);
      assert.equal(ap.body.status, 'approved'); assert.equal(ap.body.resolved, false, j(ap.body));
      const rb = await result(qb.body.id);
      assert.equal(rb.status, 200, j(rb.body)); assert.equal(rb.body.resolved, false); assert.equal(rb.body.uid, null);
    } finally { await cia3.stop(); }
  });
} finally {
  await cia.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
