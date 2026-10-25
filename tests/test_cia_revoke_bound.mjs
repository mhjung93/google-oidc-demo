// IdP 세션 폐기 요청의 허용 거래 수 bound(설계 2026-10-22 §3) — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_revoke_bound.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ethers } from 'ethers';
import { MODE3_LOG_ABI, MODE3_MIRROR_ABI } from '../lib/mode3_log.js';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { randomScalar } from '../lib/mode3_credential.js';
import { signRevokeBind, sessionLeaf, SESSION_BOUND_MAX } from '../lib/mode3_revocation.js';
import { signRevokeSession } from '../lib/mode3_wallet.js';
import { issueV11, userOf, TESTUSER_ATTRS } from './helpers/mode3_flow.mjs';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const provider = getProvider();
const cia = await startIsolatedCia();
const arid = 22222222222222222222n;
const uid = 12345n;
let user;   // userOf(registerUser('12345'))

/** 세션 하나 새로 발급(매번 새 blind_u → 새 C_u → 독립된 세션) → Cf_s 를 돌려준다. */
async function freshSession() {
  const iss = await issueV11(cia, user, { arid, provider });
  assert.equal(iss.r.status, 200, j(iss.r.body));
  return iss.cred.Cf_s;
}

try {
  await t('준비: 등록', async () => {
    user = userOf(await cia.registerUser('12345', 'password123'), '12345', TESTUSER_ATTRS);
  });

  await t('세션 폐기(bound): 서명이 bound 를 덮고, 리프 = sessionLeaf(Cf_s, bound), 레코드·관리자 목록에 bound', async () => {
    const Cf_s = await freshSession();
    const bound = 3n, nonce = randomScalar();
    const sig_u = await signRevokeSession(user.sk_u, uid, BigInt(Cf_s), bound, nonce);
    const r = await cia.post('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s, bound: bound.toString(), nonce: nonce.toString(), sig_u });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.inserted, true); assert.equal(r.body.bound, '3');
    assert.equal(r.body.leaf, (await sessionLeaf(BigInt(Cf_s), bound)).toString());
    const list = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions;
    assert.equal(list.find((s) => s.Cf_s === Cf_s).bound, '3');
  });

  await t('bound 가 없거나 범위 밖(2^32)이면 400; 서명의 bound 와 본문 bound 가 다르면 400 bad user signature', async () => {
    const Cf_s = await freshSession();
    const nonce = randomScalar();
    const sig_u = await signRevokeSession(user.sk_u, uid, BigInt(Cf_s), 1n, nonce);   // bound=1 로 서명
    const noBound = await cia.post('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s, nonce: nonce.toString(), sig_u });
    assert.equal(noBound.status, 400, j(noBound.body));
    const outOfRange = await cia.post('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s, bound: SESSION_BOUND_MAX.toString(), nonce: nonce.toString(), sig_u });
    assert.equal(outOfRange.status, 400, j(outOfRange.body));
    const mismatched = await cia.post('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s, bound: '2', nonce: nonce.toString(), sig_u });   // 본문 bound=2 ≠ 서명 bound=1
    assert.equal(mismatched.status, 400, j(mismatched.body)); assert.equal(mismatched.body.error, 'bad user signature');
  });

  await t('관리자 폐기는 bound 기본 0(전부 차단), bound 를 주면 그 값', async () => {
    const Cf_sA = await freshSession();
    const Cf_sB = await freshSession();
    const rA = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: Cf_sA });
    assert.equal(rA.status, 200, j(rA.body)); assert.equal(rA.body.bound, '0');
    assert.equal(rA.body.leaf, (await sessionLeaf(BigInt(Cf_sA), 0n)).toString());
    const rB = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: Cf_sB, bound: '5' });
    assert.equal(rB.status, 200, j(rB.body)); assert.equal(rB.body.bound, '5');
    assert.equal(rB.body.leaf, (await sessionLeaf(BigInt(Cf_sB), 5n)).toString());
  });
  // ── 2026-10-25 root 유효 창 §4: pk_i + sig_i → 거울 공개 counter ──
  const logC = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
  const mirrorC = new ethers.Contract(cia.mirrorAddress, MODE3_MIRROR_ABI, provider);
  const stateJson = () => JSON.parse(fs.readFileSync(path.join(cia.dir, 'cia_state.json'), 'utf8'));   // 격리 인스턴스의 임시 상태 파일(테스트 소유)
  /** 사용자 폐기 요청 본문(sk_u 서명 + 선택 pk_i/sig_i). */
  async function revokeBody(iss, bound, { withBind = true, bindKey = iss.session.wallet.privateKey, bindBound = bound } = {}) {
    const Cf_s = iss.cred.Cf_s, nonce = randomScalar();
    const body = { uid: uid.toString(), scope: 'session', Cf_s, bound: bound.toString(), nonce: nonce.toString(), sig_u: await signRevokeSession(user.sk_u, uid, BigInt(Cf_s), bound, nonce) };
    if (withBind) { body.pk_i = iss.session.pk_i.toString(); body.sig_i = await signRevokeBind(bindKey, { uid, Cf_s, bound: bindBound, nonce }); }
    return body;
  }
  const fresh = async () => { const iss = await issueV11(cia, user, { arid, provider }); assert.equal(iss.r.status, 200, j(iss.r.body)); return iss; };

  await t('pk_i+sig_i 를 실은 사용자 폐기: 대기열(pendingBounds, 영속)에 들어가고 게시 → 캐노니컬 sessionBoundOf = bound+1 → 중계 → 거울도 같다 → 대기열에서 빠진다; 레코드·관리자 목록에 pk_i', async () => {
    const iss = await fresh(); const pk_i = iss.session.pk_i.toString();
    const r = await cia.post('/cia/revoke', await revokeBody(iss, 2n));
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.inserted, true); assert.equal(r.body.mirrorBound, true);
    assert.deepEqual(stateJson().pendingBounds.find((e) => e.pk_i === pk_i), { pk_i, bound: '2', epoch: null });
    const list = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions;
    assert.equal(list.find((s) => s.Cf_s === iss.cred.Cf_s).pk_i, pk_i, '레코드에 pk_i');
    const revoked = (await cia.adminGet('/cia/admin/revoked_sessions')).body.sessions;
    assert.equal(revoked.find((s) => s.Cf_s === iss.cred.Cf_s).pk_i, pk_i, '관리자 폐기 목록에 pk_i');
    assert.equal(await logC.sessionBoundOf(BigInt(pk_i)), 0n, '게시 전');
    const pub = await cia.adminPost('/cia/publish', {});
    assert.equal(pub.status, 200, j(pub.body)); assert.equal(pub.body.published, true); assert.ok(pub.body.bounds >= 1, j(pub.body));
    assert.equal(await logC.sessionBoundOf(BigInt(pk_i)), 3n, '캐노니컬: c + 1');
    assert.equal(stateJson().pendingBounds.find((e) => e.pk_i === pk_i).epoch, String(pub.body.epoch), '실린 epoch 기록 — 거울이 받을 때까지 유지');
    assert.equal(await mirrorC.sessionBoundOf(BigInt(pk_i)), 0n, '중계 전 거울은 비어 있다');
    const rl = await cia.adminPost('/cia/admin/relay', {}); assert.equal(rl.status, 200, j(rl.body));
    assert.equal(await mirrorC.sessionBoundOf(BigInt(pk_i)), 3n, '거울: c + 1');
    assert.equal(stateJson().pendingBounds.some((e) => e.pk_i === pk_i), false, '모든 거울이 받았으니 대기열에서 빠진다');
  });
  await t('pk_i 만·sig_i 만·다른 키·다른 bound 위의 sig_i·범위 밖 pk_i 는 400 bad_session_signature 이고 리프를 넣지 않는다', async () => {
    const iss = await fresh();
    const good = await revokeBody(iss, 1n);
    const other = ethers.Wallet.createRandom();
    const cases = [
      ['pk_i 만', { ...good, sig_i: undefined }],
      ['sig_i 만', { ...good, pk_i: undefined }],
      ['다른 키의 sig_i', { ...good, sig_i: await signRevokeBind(other.privateKey, { uid, Cf_s: iss.cred.Cf_s, bound: 1n, nonce: good.nonce }) }],
      ['다른 bound 위의 sig_i', { ...good, sig_i: await signRevokeBind(iss.session.wallet.privateKey, { uid, Cf_s: iss.cred.Cf_s, bound: 0n, nonce: good.nonce }) }],
      ['pk_i 범위 밖(2^160)', { ...good, pk_i: (1n << 160n).toString() }],
    ];
    for (const [name, body] of cases) {
      const r = await cia.post('/cia/revoke', JSON.parse(JSON.stringify(body)));   // undefined 필드 제거
      assert.equal(r.status, 400, `${name}: ${j(r.body)}`); assert.equal(r.body.reason, 'bad_session_signature', name);
    }
    const ok = await cia.post('/cia/revoke', good);
    assert.equal(ok.status, 200, j(ok.body)); assert.equal(ok.body.inserted, true, '위 400 들은 리프를 넣지 않았다');
  });
  await t('pk_i 없는 폐기(관리자·옛 지갑)는 그대로 받되 거울 counter 는 게시하지 않는다(mirrorBound=false, sessionBoundOf=0)', async () => {
    const iss = await fresh(); const pk = BigInt(iss.session.pk_i);
    const r = await cia.post('/cia/revoke', await revokeBody(iss, 0n, { withBind: false }));
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.inserted, true); assert.equal(r.body.mirrorBound, false);
    const iss2 = await fresh();
    const rA = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: iss2.cred.Cf_s });
    assert.equal(rA.status, 200, j(rA.body)); assert.equal(rA.body.mirrorBound, false);
    assert.equal((await cia.adminPost('/cia/publish', {})).body.published, true);
    await cia.adminPost('/cia/admin/relay', {});
    assert.equal(await logC.sessionBoundOf(pk), 0n); assert.equal(await mirrorC.sessionBoundOf(pk), 0n);
    assert.equal(await mirrorC.sessionBoundOf(BigInt(iss2.session.pk_i)), 0n);
  });
  await t('낮추기만: 같은 세션을 bound 3 → 1 로 재폐기하면 거울 2(=1+1); 그 뒤 5 는 멱등 응답(inserted:false)이고 거울 그대로', async () => {
    const iss = await fresh(); const pk = BigInt(iss.session.pk_i);
    assert.equal((await cia.post('/cia/revoke', await revokeBody(iss, 3n))).body.inserted, true);
    const lower = await cia.post('/cia/revoke', await revokeBody(iss, 1n));
    assert.equal(lower.status, 200, j(lower.body)); assert.equal(lower.body.inserted, true); assert.equal(lower.body.bound, '1');
    assert.equal(stateJson().pendingBounds.find((e) => e.pk_i === pk.toString()).bound, '1', '대기열은 더 낮은 값으로 갈아끼운다');
    assert.equal((await cia.adminPost('/cia/publish', {})).body.published, true);
    await cia.adminPost('/cia/admin/relay', {});
    assert.equal(await mirrorC.sessionBoundOf(pk), 2n);
    const raise = await cia.post('/cia/revoke', await revokeBody(iss, 5n));
    assert.equal(raise.status, 200, j(raise.body)); assert.equal(raise.body.inserted, false);
    assert.equal((await cia.adminPost('/cia/publish', {})).body.published, false, '새로 실을 것이 없다');
    assert.equal(await mirrorC.sessionBoundOf(pk), 2n);
  });
  await t('건너뛴 epoch: 두 번 게시(각각 pk_i 하나) 뒤 한 번만 중계해도 거울에 둘 다 실린다(누적 재전송), 그 뒤 대기열이 비워진다', async () => {
    const a = await fresh(), b = await fresh();
    assert.equal((await cia.post('/cia/revoke', await revokeBody(a, 1n))).status, 200);
    const p1 = await cia.adminPost('/cia/publish', {}); assert.equal(p1.body.published, true);
    assert.equal((await cia.post('/cia/revoke', await revokeBody(b, 2n))).status, 200);
    const p2 = await cia.adminPost('/cia/publish', {}); assert.equal(p2.body.published, true); assert.ok(p2.body.bounds >= 2, '앞 게시의 항목도 다시 실린다: ' + j(p2.body));
    assert.ok((await mirrorC.epoch()) < BigInt(p1.body.epoch), '전제: 거울은 두 게시 모두 아직 못 받았다');
    await cia.adminPost('/cia/admin/relay', {});
    assert.equal(await mirrorC.epoch(), BigInt(p2.body.epoch), '중계는 최신 epoch 만 옮긴다');
    assert.equal(await mirrorC.sessionBoundOf(BigInt(a.session.pk_i)), 2n, '건너뛴 게시(p1)의 bound 도 실렸다');
    assert.equal(await mirrorC.sessionBoundOf(BigInt(b.session.pk_i)), 3n);
    const pend = stateJson().pendingBounds.map((e) => e.pk_i);
    assert.equal(pend.includes(a.session.pk_i.toString()) || pend.includes(b.session.pk_i.toString()), false, '거울이 받았으니 비운다');
  });
  await t('I1: 관리자가 먼저 폐기한(pk_i 없음) 세션을 사용자가 pk_i 를 실어 같은 bound 로 재폐기하면 pk_i 가 붙어 거울 counter 가 게시된다(멱등 응답, 리프는 그대로)', async () => {
    const iss = await fresh(); const pk = BigInt(iss.session.pk_i);
    const rA = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: iss.cred.Cf_s, bound: '2' });
    assert.equal(rA.status, 200, j(rA.body)); assert.equal(rA.body.mirrorBound, false);
    const pendingBefore = stateJson().pending.length;
    const r = await cia.post('/cia/revoke', await revokeBody(iss, 2n));
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.inserted, false); assert.equal(r.body.mirrorBound, true); assert.equal(r.body.bound, '2');
    assert.equal(stateJson().pending.length, pendingBefore, '새 리프 없음');
    assert.deepEqual(stateJson().pendingBounds.find((e) => e.pk_i === pk.toString()), { pk_i: pk.toString(), bound: '2', epoch: null });
    assert.equal((await cia.adminPost('/cia/publish', {})).body.published, true);
    await cia.adminPost('/cia/admin/relay', {});
    assert.equal(await mirrorC.sessionBoundOf(pk), 3n);
  });
} finally {
  await cia.stop();
  provider.destroy();
}

process.exit(failed === 0 ? 0 : 1);
