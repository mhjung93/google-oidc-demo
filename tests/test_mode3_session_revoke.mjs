// IdP 세션 폐기(설계 2026-09-24 V8) — 발급 세션 기록, /cia/revoke scope=session, 관리자 세션 목록. 격리 IdP + :8545. (chain 그룹)
//   node tests/test_mode3_session_revoke.mjs
import assert from 'node:assert/strict';
import { buildEddsa } from 'circomlibjs';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { signRevokeSession } from '../lib/mode3_wallet.js';
import { sessionLeaf } from '../lib/mode3_revocation.js';
import { randomScalar } from '../lib/mode3_credential.js';
import { issueV11, userOf, TESTUSER_ATTRS, ALICE_ATTRS } from './helpers/mode3_flow.mjs';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

// provider 는 하나만 만든다 — mode3_chain.mjs 는 캐시하지 않아 호출마다 폴링 타이머가 하나씩 는다.
const provider = getProvider();
const cia = await startIsolatedCia();

const UID = '12345';                    // 데모 계정 testuser
const uid = BigInt(UID);
const arid = 22222222222222222222n;
const CHAIN_ID = 31337n;

try {
  // 등록 → 세션 발급 여러 번(같은 C_u 재사용). test_mode3_wallet.mjs / test_cia_register_issue.mjs 의 준비 코드와 같은 흐름이다.
  const reg = await cia.registerUser(UID, 'password123');
  const user = userOf(reg, UID, TESTUSER_ATTRS);
  user.blind_u = randomScalar();   // 세션마다 같은 C_u 를 재사용 — 매번 등록부를 다시 게시하지 않는다

  /** 세션 하나 발급. 세션키·r_s·r_rp 가 매번 새로 뽑히므로 Cf_s 도 매번 다르다. */
  async function issueWith({ max_height } = {}) {
    const r = await issueV11(cia, user, { arid, provider, max_height, blind_u: user.blind_u, chainid: CHAIN_ID });
    assert.equal(r.r.status, 200, JSON.stringify(r.r.body));
    return r;
  }

  const issued1 = await issueWith();
  const issued2 = await issueWith();

  await t('발급이 세션 기록을 남긴다(관리자 조회)', async () => {
    const r = await cia.adminGet(`/cia/admin/sessions?uid=${UID}`);
    assert.equal(r.status, 200);
    assert.equal(r.body.sessions.length, 2);
    assert.ok(r.body.sessions.some((s) => s.Cf_s === issued1.cred.Cf_s && s.revokedAt === null));
    const rec = r.body.sessions.find((s) => s.Cf_s === issued2.cred.Cf_s);
    assert.equal(rec.chainid, CHAIN_ID.toString());
    assert.equal(rec.max_height, issued2.cred.max_height);
    assert.equal(rec.allowAgent, '0');
    assert.equal(rec.expired, false, '아직 만료 전');
  });

  await t('관리자 세션 목록은 관리자 시크릿을 요구하고, 모르는 계정은 404', async () => {
    assert.equal((await cia.get(`/cia/admin/sessions?uid=${UID}`)).status, 401);
    assert.equal((await cia.adminGet('/cia/admin/sessions?uid=424242')).status, 404);
  });

  await t('사용자 서명으로 세션 하나 폐기 → 리프 pending, 다시 하면 멱등, 다른 세션은 그대로', async () => {
    const nonce = 12345n;
    const bound = 0n;
    const sig_u = await signRevokeSession(user.sk_u, uid, BigInt(issued1.cred.Cf_s), bound, nonce);
    const r = await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued1.cred.Cf_s, bound: bound.toString(), sig_u, nonce: nonce.toString() });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.inserted, true);
    // 2026-10-23 리뷰 3-7: 기대 리프는 응답의 bound(r.body.bound) 가 아니라 **요청에 쓴** 지역 변수 bound 로 계산한다 —
    // 응답값으로 계산하면 서버가 엉뚱한 bound 를 돌려줘도(리프 계산과 자기 일관되면) 통과하는 순환 단언이 된다.
    assert.equal(r.body.bound, bound.toString());
    assert.equal(BigInt(r.body.leaf), await sessionLeaf(BigInt(issued1.cred.Cf_s), bound));
    assert.ok(r.body.pending >= 1, '리프가 게시 대기열에 들어간다');
    const again = await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued1.cred.Cf_s, bound: bound.toString(), sig_u, nonce: nonce.toString() });
    assert.equal(again.status, 200);
    assert.equal(again.body.inserted, false);
    const list = (await cia.adminGet(`/cia/admin/sessions?uid=${UID}`)).body.sessions;
    assert.ok(list.find((s) => s.Cf_s === issued1.cred.Cf_s).revokedAt);
    assert.equal(list.find((s) => s.Cf_s === issued2.cred.Cf_s).revokedAt, null);
  });

  await t('관리자 폐기 세션 목록(/cia/admin/revoked_sessions): 폐기된 세션만, 리프·pending 포함; 게시 뒤 pending=false; 등록부 목록에 Cf_u·pending', async () => {
    const r = await cia.adminGet('/cia/admin/revoked_sessions');
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const mine = r.body.sessions.filter((s) => s.uid === UID);
    assert.equal(mine.length, 1, '폐기한 세션 하나만 나온다(다른 세션은 revokedAt 없음)');
    assert.equal(mine[0].Cf_s, issued1.cred.Cf_s);
    assert.ok(mine[0].revokedAt && /^[0-9]+$/.test(mine[0].leaf));
    assert.equal(mine[0].pending, true, '게시 전이라 pending');
    assert.ok(!('auid_s' in mine[0]) && !('arid_s' in mine[0]), 'D1: 세션 가명은 없다');
    assert.equal((await cia.get('/cia/admin/revoked_sessions')).status, 401, '관리자 전용');
    const reg = await cia.adminGet('/cia/admin/registry');
    assert.equal(reg.status, 200, JSON.stringify(reg.body));
    const slot = reg.body.slots.find((x) => x.uid === UID);
    assert.ok(slot && slot.active && /^[0-9]+$/.test(slot.Cf_u) && slot.issuedAt, '등록부 목록에 활성 Cf_u·발급 시각');
    assert.equal(slot.disabled, false); assert.equal(typeof slot.pending, 'boolean');
    const pub = await cia.adminPost('/cia/publish', {});
    assert.equal(pub.status, 200, JSON.stringify(pub.body));
    const after = (await cia.adminGet('/cia/admin/revoked_sessions')).body.sessions.find((s) => s.uid === UID);
    assert.equal(after.pending, false, '게시 뒤에는 pending 이 풀린다');
  });

  await t('서명이 다른 세션 것이면 400, 관리자 헤더 없이 서명도 없으면 401, 모르는 Cf_s 는 관리자에게만 404', async () => {
    const bad = await signRevokeSession(user.sk_u, uid, BigInt(issued2.cred.Cf_s), 0n, 1n);
    assert.equal((await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued1.cred.Cf_s, sig_u: bad, nonce: '1', bound: '0' })).status, 400);
    assert.equal((await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued2.cred.Cf_s, bound: '0' })).status, 401);
    assert.equal((await cia.adminPost('/cia/revoke', { uid: UID, scope: 'session', Cf_s: '424242' })).status, 404);
    // 검사 순서 고정: 인증 없는 요청은 기록 조회보다 서명을 먼저 본다 — 모르는 Cf_s 라도 404 가 아니라 400 이라야
    // "그 Cf_s 가 이 계정 것인지" 가 서명 없이 새지 않는다.
    assert.equal((await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: '424242', sig_u: bad, nonce: '1', bound: '0' })).status, 400, '서명이 먼저다');
  });

  await t('scope=account·credential 은 여전히 관리자 전용(401)', async () => {
    assert.equal((await cia.post('/cia/revoke', { uid: UID, scope: 'account' })).status, 401);
    assert.equal((await cia.post('/cia/revoke', { uid: UID, scope: 'credential' })).status, 401);
  });

  await t('관리자 폐기(서명 없이) 200; 만료된 세션은 409 expired', async () => {
    const r = await cia.adminPost('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued2.cred.Cf_s });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.inserted, true);
    // 만료: max_height 를 현재 head 로 발급한 세션을 하나 더 만들고 블록을 진행시킨 뒤 폐기 → 409
    const expiring = await issueWith({ max_height: BigInt(await provider.getBlockNumber()) + 1n });
    await provider.send('evm_mine', []); await provider.send('evm_mine', []);
    const e = await cia.adminPost('/cia/revoke', { uid: UID, scope: 'session', Cf_s: expiring.cred.Cf_s });
    assert.equal(e.status, 409, JSON.stringify(e.body));
    assert.equal(e.body.reason, 'expired');
    const rec = (await cia.adminGet(`/cia/admin/sessions?uid=${UID}`)).body.sessions.find((s) => s.Cf_s === expiring.cred.Cf_s);
    assert.equal(rec.expired, true);
    assert.equal(rec.revokedAt, null, '만료된 세션은 폐기 기록이 남지 않는다');
  });

  // 경계는 컨트랙트(Mode3Wallet.sol `block.number > pub[3]`)·RP(lib/mode3_rp.js)와 같아야 한다 — head == max_height 는 아직 산 세션이다.
  await t('경계: head == max_height 면 아직 살아 있어 폐기 200, head > max_height 라야 409 expired', async () => {
    const mhA = BigInt(await provider.getBlockNumber()) + 1n;
    const a = await issueWith({ max_height: mhA });
    await provider.send('evm_mine', []);
    assert.equal(BigInt(await provider.getBlockNumber()), mhA, 'head == max_height 인 순간');
    const listed = (await cia.adminGet(`/cia/admin/sessions?uid=${UID}`)).body.sessions.find((s) => s.Cf_s === a.cred.Cf_s);
    assert.equal(listed.expired, false, 'head == max_height 는 만료가 아니다');
    const ok = await cia.adminPost('/cia/revoke', { uid: UID, scope: 'session', Cf_s: a.cred.Cf_s });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.equal(ok.body.inserted, true);
    // 한 블록 더 — 같은 만료로 새로 발급한 세션은 이제 head > max_height 라 409 다.
    await provider.send('evm_mine', []);
    const b = await issueWith({ max_height: mhA });
    const e = await cia.adminPost('/cia/revoke', { uid: UID, scope: 'session', Cf_s: b.cred.Cf_s });
    assert.equal(e.status, 409, JSON.stringify(e.body));
    assert.equal(e.body.reason, 'expired');
  });

  // 하트비트가 꺼져 있으면(격리 IdP 의 기본) 정리가 하트비트에서는 영영 안 돈다 — 발급 경로가 같은 일을 한다(최종 리뷰 F2).
  await t('하트비트가 꺼져 있어도 발급이 이 계정의 만료 기록을 지운다 — 리프·pending 은 그대로', async () => {
    const short = await issueWith({ max_height: BigInt(await provider.getBlockNumber()) + 2n });
    const rv = await cia.adminPost('/cia/revoke', { uid: UID, scope: 'session', Cf_s: short.cred.Cf_s });
    assert.equal(rv.status, 200, JSON.stringify(rv.body));
    assert.equal(rv.body.inserted, true);
    const { root, pending } = rv.body;   // 세션 리프가 막 들어간 직후의 트리 상태
    for (let i = 0; i < 3; i++) await provider.send('evm_mine', []);
    await issueWith();                   // 이 발급이 정리를 돌린다(하트비트는 꺼져 있다)
    const list = (await cia.adminGet(`/cia/admin/sessions?uid=${UID}`)).body.sessions;
    assert.equal(list.find((s) => s.Cf_s === short.cred.Cf_s), undefined, '만료된 기록은 사라진다');
    const st = (await cia.adminGet('/cia/state')).body;
    assert.equal(st.root, root, '리프는 트리에 남는다 — 기록만 지운다(설계 §6)');
    assert.equal(st.pendingCount, pending, 'pending 도 그대로');
  });

  // 2026-09-25 리뷰 E-8: 기록 조회는 **그 계정의** sessions 안에서만 해야 한다. 계정 밖에서 찾으면
  // A 가 자기 키로 서명한 요청 하나로 남의 세션을 끊을 수 있다(서명은 (uid, Cf_s, nonce) 위라 A 의 uid 로도
  // 다른 계정의 Cf_s 를 서명할 수 있다 — 그 자체는 막을 수 없고, 막는 것은 기록 조회의 범위다).
  await t('E-8: 다른 계정의 세션은 내 서명으로 폐기되지 않는다 — 404 unknown_session, 그 세션은 그대로', async () => {
    // B(alice, uid 67890) 계정 → 세션 하나.
    const UID_B = '67890', uidB = BigInt(UID_B);
    const regB = await cia.registerUser(UID_B, 'alicepw');
    const userB = userOf(regB, UID_B, ALICE_ATTRS);
    const issuedB = await issueV11(cia, userB, { arid, provider, chainid: CHAIN_ID });
    assert.equal(issuedB.r.status, 200, JSON.stringify(issuedB.r.body));

    // A(testuser)가 자기 uid 와 **B 의 Cf_s** 위에 제대로 서명해 보낸다 — 서명 자체는 유효하다.
    const nonce = 777n;
    const sig_u = await signRevokeSession(user.sk_u, uid, BigInt(issuedB.cred.Cf_s), 0n, nonce);
    const cross = await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issuedB.cred.Cf_s, bound: '0', sig_u, nonce: nonce.toString() });
    assert.equal(cross.status, 404, JSON.stringify(cross.body));
    assert.equal(cross.body.reason, 'unknown_session');

    // B 의 세션은 그대로고(리프도 안 들어갔고), B 자신은 여전히 폐기할 수 있다.
    const recB = (await cia.adminGet(`/cia/admin/sessions?uid=${UID_B}`)).body.sessions.find((s) => s.Cf_s === issuedB.cred.Cf_s);
    assert.ok(recB, 'B 의 세션 기록이 있어야 한다');
    assert.equal(recB.revokedAt, null, 'A 의 요청으로 B 의 세션이 폐기되면 안 된다');
    const sigB = await signRevokeSession(userB.sk_u, uidB, BigInt(issuedB.cred.Cf_s), 0n, 1n);
    const own = await cia.post('/cia/revoke', { uid: UID_B, scope: 'session', Cf_s: issuedB.cred.Cf_s, bound: '0', sig_u: sigB, nonce: '1' });
    assert.equal(own.status, 200, JSON.stringify(own.body));
    assert.equal(own.body.inserted, true, '주인의 폐기는 리프를 넣는다');
    assert.equal(BigInt(own.body.leaf), await sessionLeaf(BigInt(issuedB.cred.Cf_s), BigInt(own.body.bound)));
  });

  // 리뷰 S1(2026-10-13): 사용자 서명 경로의 서명 필드를 BigInt() 로 그대로 파싱하던 때는 S='-1' 하나로 IdP 가 영구히 멈췄다
  // (verifyPoseidon 의 mulPointEscalar(-1n)). 요청마다 2초 상한 — 회귀하면 여기서 TimeoutError 로 실패한다. 마지막 케이스로 둔다(회귀 시
  // 인스턴스가 멈추므로 뒤 케이스를 끌고 들어가지 않게). register·slot·issue 의 같은 검사는 tests/test_cia_register_issue.mjs 에 있다.
  await t('리뷰 S1: scope=session 사용자 서명 필드가 음수·비10진·범위 밖이면 2초 안에 400 — 세션은 그대로, 정상 서명은 통한다', async () => {
    const subOrder = (await buildEddsa()).babyJub.subOrder;
    const live = await issueWith();
    const nonce = 4242n;
    const good = await signRevokeSession(user.sk_u, uid, BigInt(live.cred.Cf_s), 0n, nonce);
    const postWithin = (body) => fetch(`${cia.base}/cia/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(2000) })
      .then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));
    const variants = [['S=-1', { ...good, S: '-1' }], ['R8y=-1', { ...good, R8y: '-1' }], ['S=subOrder', { ...good, S: subOrder.toString() }], ['S=1e3', { ...good, S: '1e3' }], ['S 숫자형', { ...good, S: 5 }]];
    for (const [label, bad] of variants) {
      const r = await postWithin({ uid: UID, scope: 'session', Cf_s: live.cred.Cf_s, sig_u: bad, nonce: nonce.toString(), bound: '0' });
      assert.equal(r.status, 400, `${label}: ${JSON.stringify(r.body)}`); assert.equal(r.body.error, 'bad user signature', label);
    }
    const rec = (await cia.adminGet(`/cia/admin/sessions?uid=${UID}`)).body.sessions.find((x) => x.Cf_s === live.cred.Cf_s);
    assert.equal(rec.revokedAt, null, '거절된 요청은 세션을 건드리지 않는다');
    const ok = await postWithin({ uid: UID, scope: 'session', Cf_s: live.cred.Cf_s, sig_u: good, nonce: nonce.toString(), bound: '0' });
    assert.equal(ok.status, 200, JSON.stringify(ok.body)); assert.equal(ok.body.inserted, true, '대조군: 정상 서명은 통한다');
  });
} finally {
  await cia.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
