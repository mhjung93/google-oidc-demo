// CIA 등록부(V9) — 등록 키·슬롯·즉시 게시·은퇴·마이그레이션. 격리 CIA + :8545 Mode3Log. (chain)  node tests/test_cia_registry.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createRegistration, signRegistration, buildUserCredRequest, buildIssueRequest, createSessionKey, signRevokeSession } from '../lib/mode3_wallet.js';
import { pointToStrings } from '../lib/mode3_issuance.js';
import { userCommit, randomScalar } from '../lib/mode3_credential.js';
import { registryLeaf, createRegistryTree } from '../lib/mode3_registry.js';
import { MODE3_LOG_ABI, verifyReceipt } from '../lib/mode3_log.js';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }
const provider = getProvider();
const cia = await startIsolatedCia();
const log = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
const ATTRS = [1990n, 410n, 2n, 0n, 0n, 0n];
const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32);
let u;   // registerUser 결과
let alice;   // registerUser('67890', 'alicepw') 결과 — 관리자 바꿔치기 케이스(Task 9)가 쓴다
try {
  await t('등록: pk_u·sig_reg 필수, 틀린 서명 400, 정상 201 { slot 0, attrs 6 }, sk_u 없음, 두 번째 계정은 슬롯 1', async () => {
    const reg = await createRegistration();
    const base = { uid: '12345', pwd: 'password123', cm_u: pointToStrings(reg.cm_u), pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() } };
    assert.equal((await cia.post('/cia/register', { ...base, pk_u: undefined, sig_reg: await signRegistration(reg.sk_u, 12345n, reg.cm_u) })).status, 400);
    const other = await createRegistration();
    const bad = await cia.post('/cia/register', { ...base, sig_reg: await signRegistration(other.sk_u, 12345n, reg.cm_u) });
    assert.equal(bad.status, 400); assert.equal(bad.body.error, 'bad_registration_signature');
    u = await cia.registerUser('12345', 'password123');
    assert.equal(u.slot, 0); assert.deepEqual(u.attrs, ['1990', '410', '2', '0', '0', '0']); assert.equal(u.body.sk_u, undefined);
    alice = await cia.registerUser('67890', 'alicepw');
    assert.equal(alice.slot, 1);
  });
  let cred;
  await t('발급: 201 { Cf_u, slot, regRoot, epoch, published:true } — 체인 regRoot·SlotUpdated(0, L_reg) 가 같이 간다', async () => {
    cred = await buildUserCredRequest({ uid: 12345n, s_u: u.s_u, r_u: u.r_u, sk_u: u.sk_u, attrs: ATTRS });
    const r = await cia.post('/cia/user_cred', cred.body);
    assert.equal(r.status, 201, j(r.body));
    assert.equal(r.body.slot, 0); assert.equal(r.body.published, true); assert.equal(r.body.leaf, undefined, 'V9: 사용자 리프는 없다');
    assert.equal(b32(r.body.regRoot), await log.regRoot());
    const ev = await log.queryFilter(log.filters.SlotUpdated(), 0, 'latest');
    assert.equal(ev.length, 1); assert.equal(Number(ev[0].args.index), 0);
    assert.equal(BigInt(ev[0].args.leaf), await registryLeaf(u.cm_u, cred.Cf_u));
    const same = await cia.post('/cia/user_cred', cred.body);   // 멱등
    assert.equal(same.status, 200); assert.equal(same.body.published, false);
  });
  await t('교체: 새 C_u 를 받으면 슬롯 리프가 바뀌고 게시된다; 옛 Cf_u 로 세션 발급은 403 no_user_cred', async () => {
    const cred2 = await buildUserCredRequest({ uid: 12345n, s_u: u.s_u, r_u: u.r_u, sk_u: u.sk_u, attrs: ATTRS });
    const r = await cia.post('/cia/user_cred', cred2.body);
    assert.equal(r.status, 201); assert.equal(r.body.published, true);
    const ev = await log.queryFilter(log.filters.SlotUpdated(), 0, 'latest');
    assert.equal(BigInt(ev.at(-1).args.leaf), await registryLeaf(u.cm_u, cred2.Cf_u));
    const iss = await buildIssueRequest({ uid: 12345n, Cf_u: cred.Cf_u, arid: 22222222222222222222n, sk_u: u.sk_u, session: createSessionKey(), chainid: 31337n, max_height: BigInt(await provider.getBlockNumber()) + 300n });
    const rs = await cia.post('/cia/issue', iss.body);
    assert.equal(rs.status, 403); assert.equal(rs.body.reason, 'no_user_cred');
    cred = cred2;
  });
  await t('은퇴(scope=credential): 슬롯 0 게시, 폐기 트리 리프 수는 불변', async () => {
    const before = (await cia.get('/cia/state')).body.leafCount;
    const r = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.retired, 1); assert.equal(r.body.published, true);
    const ev = await log.queryFilter(log.filters.SlotUpdated(), 0, 'latest');
    assert.equal(BigInt(ev.at(-1).args.leaf), 0n);
    assert.equal((await cia.get('/cia/state')).body.leafCount, before, '사용자 리프를 폐기 트리에 넣지 않는다');
    const again = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' });
    assert.equal(again.body.retired, 0);
  });
  await t('계정 폐기(scope=account): disabled + 슬롯 0; 세션 폐기는 여전히 폐기 트리 리프(pending → publish 로 Revoked)', async () => {
    const c3 = await buildUserCredRequest({ uid: 12345n, s_u: u.s_u, r_u: u.r_u, sk_u: u.sk_u, attrs: ATTRS });
    assert.equal((await cia.post('/cia/user_cred', c3.body)).status, 201);
    const iss = await buildIssueRequest({ uid: 12345n, Cf_u: c3.Cf_u, arid: 22222222222222222222n, sk_u: u.sk_u, session: createSessionKey(), chainid: 31337n, max_height: BigInt(await provider.getBlockNumber()) + 300n });
    const issued = await cia.post('/cia/issue', iss.body);
    assert.equal(issued.status, 200, j(issued.body));
    const nonce = randomScalar();
    const rv = await cia.post('/cia/revoke', { uid: '12345', scope: 'session', Cf_s: issued.body.Cf_s, sig_u: await signRevokeSession(u.sk_u, 12345n, BigInt(issued.body.Cf_s), nonce), nonce: nonce.toString() });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.inserted, true);
    assert.equal((await cia.get('/cia/state')).body.pendingCount, 1);
    const ra = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' });
    assert.equal(ra.status, 200, j(ra.body)); assert.equal(ra.body.disabled, true); assert.equal(ra.body.published, true);
    assert.equal((await cia.get('/cia/state')).body.pendingCount, 0, '계정 폐기 게시에 세션 리프도 함께 나갔다');
    const rev = await log.queryFilter(log.filters.Revoked(), 0, 'latest');
    assert.equal(rev.at(-1).args.leaves.length, 1);
  });
  await t('/cia/state·/cia/accounts: regRoot·슬롯 정보', async () => {
    const s = (await cia.get('/cia/state')).body;
    assert.equal(b32(s.regRoot), await log.regRoot()); assert.equal(s.pendingSlots, 0);
    const a = (await cia.adminGet('/cia/accounts')).body.accounts.find((x) => x.uid === '12345');
    assert.equal(a.slot, 0); assert.equal(a.tampered, false); assert.equal(a.registryLeaf, '0');
  });
  await t('관리자 바꿔치기: 슬롯에 가짜 리프를 게시하면 regRoot 가 바뀌고 tampered:true; 되돌리기로 진짜 리프·false', async () => {
    const c4 = await buildUserCredRequest({ uid: 67890n, s_u: alice.s_u, r_u: alice.r_u, sk_u: alice.sk_u, attrs: [2005n, 840n, 1n, 0n, 0n, 0n] });
    assert.equal((await cia.post('/cia/user_cred', c4.body)).status, 201);
    const real = await registryLeaf(alice.cm_u, c4.Cf_u);
    const before = await log.regRoot();
    const tp = await cia.adminPost('/cia/admin/registry/tamper', { uid: '67890' });
    assert.equal(tp.status, 200, j(tp.body)); assert.equal(tp.body.slot, 1); assert.notEqual(BigInt(tp.body.leaf), real); assert.equal(tp.body.published, true);
    assert.notEqual(await log.regRoot(), before);
    const reg = (await cia.adminGet('/cia/admin/registry')).body;
    const s = reg.slots.find((x) => x.index === 1);
    assert.equal(s.uid, '67890'); assert.equal(s.tampered, true); assert.equal(s.leaf, tp.body.leaf);
    const rs = await cia.adminPost('/cia/admin/registry/restore', { uid: '67890' });
    assert.equal(rs.status, 200, j(rs.body)); assert.equal(BigInt(rs.body.leaf), real);
    assert.equal((await cia.adminGet('/cia/admin/registry')).body.slots.find((x) => x.index === 1).tampered, false);
    assert.equal((await cia.adminPost('/cia/admin/registry/tamper', { uid: '12345' })).status, 409, '활성 자격증명 없음(폐기된 계정)');
  });
  // V10(2026-10-02 §4) 폐기 접수증·대기열 강제. 브리프의 slotOf/issueUserCred 헬퍼는 이 파일에 없어 /cia/accounts 와
  // buildUserCredRequest 로 대신한다. alice(67890, 슬롯 1)는 위 바꿔치기 케이스 뒤 활성 자격증명을 가진 채로 남아 있다.
  const slotOf = async (uid) => (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === uid).slot;
  await t('자기 폐기 응답에 IdP 서명 접수증이 실리고, 접수증은 캐노니컬 로그가 받아들인다', async () => {
    const r = await cia.post('/cia/account/self_revoke', { uid: '67890', pwd: 'alicepw' });
    assert.equal(r.status, 200, j(r.body));
    const rc = r.body.receipt;
    assert.ok(rc && typeof rc.sig === 'string' && rc.slot === await slotOf('67890'), j(rc));
    assert.equal(verifyReceipt(cia.ethAddress, rc, rc.sig), true);
    const again = await cia.post('/cia/account/self_revoke', { uid: '67890', pwd: 'alicepw' });   // 멱등 재요청은 같은 접수증
    assert.deepEqual(again.body.receipt, rc);
    const logW = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, await provider.getSigner(0));
    // 이미 즉시 게시로 0 이 됐어도 접수증 제출은 유효하고, 다음 게시가 (slot, 0) 을 실어 통과한다
    await (await logW.requestRevocation(rc.slot, rc.epochAtRequest, rc.requestedAt, rc.sig)).wait();
    assert.deepEqual((await log.pendingSlots()).map(Number), [rc.slot]);
    const pub = await cia.adminPost('/cia/publish', {});   // heartbeat 가 꺼져 있어 수동 게시
    assert.equal(pub.status, 200, j(pub.body)); assert.equal(pub.body.published, true);
    assert.deepEqual((await log.pendingSlots()).map(Number), []);
    assert.equal(await log.isRetired(rc.slot), true);
    assert.equal(b32((await cia.get('/cia/state')).body.regRoot), await log.regRoot());
  });
  await t('은퇴된 슬롯의 계정을 되살려 재발급하면 새 슬롯을 받는다', async () => {
    const en = await cia.adminPost('/cia/account/set_disabled', { uid: '67890', disabled: false });
    assert.equal(en.status, 200, j(en.body));
    const before = await slotOf('67890');
    const c5 = await buildUserCredRequest({ uid: 67890n, s_u: alice.s_u, r_u: alice.r_u, sk_u: alice.sk_u, attrs: [2005n, 840n, 1n, 0n, 0n, 0n] });
    const r = await cia.post('/cia/user_cred', c5.body);
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.published, true, '새 슬롯 쓰기는 SlotIsRetired 에 걸리지 않는다');
    const after = await slotOf('67890');
    assert.notEqual(after, before); assert.equal(r.body.slot, after);
    assert.equal(b32(r.body.regRoot), await log.regRoot());
  });
  await t('scope=credential 폐기는 접수증을 내지 않는다', async () => {
    const r = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.receipt, undefined, '자격증명 은퇴는 IdP 개시라 접수증 필드 자체가 없다');
  });
  await t('계정 폐기 → 관리자 복구 → 재발급은 새 슬롯, 옛 접수증을 나중에 올려도 다음 게시가 통과하고 옛 슬롯은 0 그대로', async () => {
    const rv = await cia.post('/cia/account/self_revoke', { uid: '67890', pwd: 'alicepw' });   // alice 는 앞 케이스에서 새 슬롯의 활성 자격증명을 가진다
    assert.equal(rv.status, 200, j(rv.body));
    const rc = rv.body.receipt, s0 = await slotOf('67890');
    assert.ok(rc && rc.slot === s0, j(rc));
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: '67890', disabled: false })).status, 200);
    const c6 = await buildUserCredRequest({ uid: 67890n, s_u: alice.s_u, r_u: alice.r_u, sk_u: alice.sk_u, attrs: [2005n, 840n, 1n, 0n, 0n, 0n] });
    const uc = await cia.post('/cia/user_cred', c6.body);
    assert.equal(uc.status, 201, j(uc.body)); assert.equal(uc.body.published, true);
    const s1 = await slotOf('67890');
    assert.notEqual(s1, s0, '계정 폐기는 슬롯을 로컬에서 영구 은퇴시켜 재발급이 새 슬롯을 받는다');
    const logW = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, await provider.getSigner(0));
    await (await logW.requestRevocation(rc.slot, rc.epochAtRequest, rc.requestedAt, rc.sig)).wait();   // 옛 접수증을 뒤늦게 제출
    assert.deepEqual((await log.pendingSlots()).map(Number), [s0]);
    const pub = await cia.adminPost('/cia/publish', {});
    assert.equal(pub.status, 200, j(pub.body)); assert.equal(pub.body.published, true);
    assert.deepEqual((await log.pendingSlots()).map(Number), []);
    assert.equal(await log.isRetired(s0), true);
    const ev = await log.queryFilter(log.filters.SlotUpdated(), 0, 'latest');
    assert.equal(BigInt(ev.filter((e) => Number(e.args.index) === s0).at(-1).args.leaf), 0n, '옛 슬롯은 0 그대로');
    const acct = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === '67890');
    assert.equal(acct.slot, s1); assert.equal(acct.disabled, false, '옛 슬롯의 접수증은 새 슬롯의 계정을 다시 막지 않는다');
    assert.equal(BigInt(acct.registryLeaf), await registryLeaf(alice.cm_u, c6.Cf_u), '새 슬롯의 리프는 그대로');
    assert.equal(b32((await cia.get('/cia/state')).body.regRoot), await log.regRoot());
  });
} finally { await cia.stop(); }

// ---- 마이그레이션: v8 상태 파일로 기동하면 슬롯을 배정하고 활성 자격증명 리프를 채워 게시한다 ----
await t('v8 상태 파일 → 기동 시 등록부 생성·게시', async () => {
  const reg = await createRegistration();
  const blind_u = randomScalar();
  const { Cx, Cy, Cf } = await userCommit({ uid: 12345n, s_u: reg.s_u, blind_u, attrs: ATTRS });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-v8-'));
  const stateFile = path.join(dir, 'cia_state.json');
  fs.writeFileSync(stateFile, JSON.stringify({ version: 8, accounts: { '12345': { pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() }, cm_u: pointToStrings(reg.cm_u), disabled: false, creds: [{ Cf_u: Cf.toString(), C_u_pt: { x: Cx.toString(), y: Cy.toString() }, leaf: '0', issuedAt: 'x', revoked: false }], attrs: ['1990', '410', '2', '0'], sessions: [] } }, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 }));
  const cia2 = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile } });
  try {
    const log2 = new ethers.Contract(cia2.logAddress, MODE3_LOG_ABI, provider);
    const expected = await registryLeaf(reg.cm_u, Cf);
    const tree = await createRegistryTree(); tree.set(0, expected);
    assert.equal(await log2.regRoot(), b32(tree.root()), '기동 자동 게시로 체인 regRoot 가 슬롯 0 하나짜리 트리');
    const ev = await log2.queryFilter(log2.filters.SlotUpdated(), 0, 'latest');
    assert.equal(ev.length, 1); assert.equal(BigInt(ev[0].args.leaf), expected);
    const a = (await cia2.adminGet('/cia/accounts')).body.accounts[0];
    assert.equal(a.slot, 0); assert.deepEqual(a.attrs, ['1990', '410', '2', '0', '0', '0']);
    assert.equal(a.registryLeaf, expected.toString());
  } finally { await cia2.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
});

// ---- 재기동 백로그(리뷰 Important 1): setSlot+persist 뒤 게시 전에 죽으면 migrated.notes·filled 둘 다 0 이라
// 옛 게이트가 pendingSlots 를 영영 못 봤다. 상태 파일을 그 시점 그대로 손으로 적어 기동만으로 재현한다. ----
await t('재기동 백로그 자동 게시: 리프는 이미 저장됐지만 게시 전에 죽은 상태 — 기동이 pendingSlots 를 비운다', async () => {
  const reg = await createRegistration();
  const blind_u = randomScalar();
  const { Cx, Cy, Cf } = await userCommit({ uid: 12345n, s_u: reg.s_u, blind_u, attrs: ATTRS });
  const expected = await registryLeaf(reg.cm_u, Cf);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-backlog-'));
  const stateFile = path.join(dir, 'cia_state.json');
  fs.writeFileSync(stateFile, JSON.stringify({
    version: 9,
    accounts: { '12345': { pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() }, cm_u: pointToStrings(reg.cm_u), disabled: false, slot: 0, tampered: false,
      creds: [{ Cf_u: Cf.toString(), C_u_pt: { x: Cx.toString(), y: Cy.toString() }, issuedAt: 'x', revoked: false }], attrs: ATTRS.map(String), sessions: [] } },
    rps: {}, openings: [], revoked: [], pending: [], epoch: 0,
    registry: { depth: 20, next: 1, leaves: { '0': expected.toString() }, pendingSlots: [{ index: 0, leaf: expected.toString() }] },
  }));
  const cia3 = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile } });
  try {
    const log3 = new ethers.Contract(cia3.logAddress, MODE3_LOG_ABI, provider);
    const s = (await cia3.get('/cia/state')).body;
    assert.equal(s.pendingSlots, 0, '기동이 리프가 이미 채워진 백로그를 자동 게시했어야 한다 — migrated.notes·filled 가 둘 다 0 이어도');
    assert.equal(await log3.regRoot(), b32(s.regRoot));
    const ev = await log3.queryFilter(log3.filters.SlotUpdated(), 0, 'latest');
    assert.ok(ev.some((e) => Number(e.args.index) === 0 && BigInt(e.args.leaf) === expected), '슬롯 0 을 새 리프로 올리는 SlotUpdated 가 없다');
  } finally { await cia3.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
});

// ---- 대조 때 체인이 앞섬(리뷰 Important 3): 옛 백업으로 되돌아가 로컬 슬롯 0 이 0 인데 체인 이벤트 역사에는
// 0 이 아닌 값이 남아 있으면, 지금 비어 있는 칸도 다시 게시해야 지갑이 수렴한다. ciaEthWallet(= CIA_ETH_PRIVATE_KEY)
// 을 그대로 재사용해 같은 로그 컨트랙트에 이어서 게시할 수 있게 한다 — 그래야 재기동한 CIA 의 서명이 컨트랙트의
// 불변 cia 주소와 맞는다. ----
await t('대조(체인이 앞섬): 로컬에서 비워진 칸도 다시 게시해야 지갑이 수렴한다', async () => {
  const cia4 = await startIsolatedCia();
  let savedState, ciaKey, logAddr;
  try {
    const u1 = await cia4.registerUser('12345', 'password123');
    await cia4.registerUser('67890', 'alicepw');
    const cred1 = await buildUserCredRequest({ uid: 12345n, s_u: u1.s_u, r_u: u1.r_u, sk_u: u1.sk_u, attrs: ATTRS });
    assert.equal((await cia4.post('/cia/user_cred', cred1.body)).status, 201);
    savedState = JSON.parse(fs.readFileSync(path.join(cia4.dir, 'cia_state.json'), 'utf8'));
    ciaKey = cia4.ciaEthWallet.privateKey;
    logAddr = cia4.logAddress;
  } finally { await cia4.stop(); }
  // 체인은 그대로 둔다(슬롯 0 = 방금 게시한 리프). 로컬만 옛 백업으로 되돌린 것처럼 슬롯 0 을 지운다.
  delete savedState.registry.leaves['0'];
  savedState.accounts['12345'].creds = [];
  savedState.registry.pendingSlots = [];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-ahead-'));
  const stateFile = path.join(dir, 'cia_state.json');
  fs.writeFileSync(stateFile, JSON.stringify(savedState));
  const cia5 = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile, CIA_LOG_ADDRESS: logAddr, CIA_ETH_PRIVATE_KEY: ciaKey } });
  try {
    const log5 = new ethers.Contract(logAddr, MODE3_LOG_ABI, provider);
    const s = (await cia5.get('/cia/state')).body;
    assert.equal(s.pendingSlots, 0, '대조가 로컬에서 비워진 칸(슬롯 0)도 다시 게시했어야 한다');
    assert.equal(await log5.regRoot(), b32(s.regRoot));
    const ev = await log5.queryFilter(log5.filters.SlotUpdated(), 0, 'latest');
    assert.ok(ev.some((e) => Number(e.args.index) === 0 && BigInt(e.args.leaf) === 0n), '슬롯 0 을 0 으로 되돌리는 SlotUpdated 가 없다');
  } finally { await cia5.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
});

// ---- 게시 직전 대조는 pendingSlots 만 싣는다(리뷰 2차): 사용자가 N 명이면 교체 게시가 N 칸을 전부 다시
// 실으면 가스·SlotUpdated 양이 가입자 수에 비례해 버린다 — 바뀐 슬롯 하나만 실려야 한다. ----
await t('게시 직전 대조: 두 사용자가 있어도 교체 게시는 바뀐 슬롯 하나만 싣는다(N 명분 전체 재발행 금지)', async () => {
  const cia6 = await startIsolatedCia();
  try {
    const v1 = await cia6.registerUser('12345', 'password123');
    const v2 = await cia6.registerUser('67890', 'alicepw');
    const c1a = await buildUserCredRequest({ uid: 12345n, s_u: v1.s_u, r_u: v1.r_u, sk_u: v1.sk_u, attrs: ATTRS });
    assert.equal((await cia6.post('/cia/user_cred', c1a.body)).status, 201);   // 첫 게시 — 슬롯 0
    const c2 = await buildUserCredRequest({ uid: 67890n, s_u: v2.s_u, r_u: v2.r_u, sk_u: v2.sk_u, attrs: v2.attrs.map(BigInt) });   // alice 는 자기 attrs 를 써야 한다
    assert.equal((await cia6.post('/cia/user_cred', c2.body)).status, 201);   // 둘째 게시 — 슬롯 1
    const c1b = await buildUserCredRequest({ uid: 12345n, s_u: v1.s_u, r_u: v1.r_u, sk_u: v1.sk_u, attrs: ATTRS });   // 교체 — 슬롯 0 만 바뀐다
    const r3 = await cia6.post('/cia/user_cred', c1b.body);   // 셋째 게시
    assert.equal(r3.status, 201, j(r3.body)); assert.equal(r3.body.published, true);
    const log6 = new ethers.Contract(cia6.logAddress, MODE3_LOG_ABI, provider);
    const ev = await log6.queryFilter(log6.filters.SlotUpdated(BigInt(r3.body.epoch)), 0, 'latest');
    assert.equal(ev.length, 1, `세 번째 게시가 SlotUpdated 를 ${ev.length}개 냈다 — pendingSlots 대신 non-zero 인 칸 전부를 실었는지 의심`);
    assert.equal(Number(ev[0].args.index), 0);
    assert.equal(BigInt(ev[0].args.leaf), await registryLeaf(v1.cm_u, c1b.Cf_u));
    assert.equal(b32(r3.body.regRoot), await log6.regRoot());
  } finally { await cia6.stop(); }
});

// ---- 게시 경합(최종 리뷰 A2): publishSafely/heartbeatTick 이 진행 중인 게시를 기다렸다 재시도해야, 그 사이 들어온
// 슬롯 변경이 조용한 로컬 체인에서 하트비트 없이 영영 묻히지 않는다. 두 사용자를 동시에 credential 폐기해 본다 —
// 이 레이스는 타이밍에 따라 한쪽 게시가 상대방의 트랜잭션에 자연히 묻어갈 수도 있어(둘 다 setSlot 은 동기라 pending
// 스냅샷 시점에 이미 같이 들어 있을 수 있다) 옛 코드에서도 항상 관찰되지는 않는다 — 그래도 고친 코드에서 두 슬롯이
// 모두 수렴해 게시됨을 보장하는 회귀 방지 시험으로 남긴다. ----
await t('게시 경합: 두 사용자를 동시에 credential 폐기해도 두 슬롯 모두 결국 게시된다(pendingSlots 0, regRoot 일치)', async () => {
  const cia7 = await startIsolatedCia();
  try {
    const v1 = await cia7.registerUser('12345', 'password123');
    const v2 = await cia7.registerUser('67890', 'alicepw');
    const c1 = await buildUserCredRequest({ uid: 12345n, s_u: v1.s_u, r_u: v1.r_u, sk_u: v1.sk_u, attrs: ATTRS });
    assert.equal((await cia7.post('/cia/user_cred', c1.body)).status, 201, j(c1));
    const c2 = await buildUserCredRequest({ uid: 67890n, s_u: v2.s_u, r_u: v2.r_u, sk_u: v2.sk_u, attrs: v2.attrs.map(BigInt) });   // alice 는 자기 attrs 를 써야 한다
    assert.equal((await cia7.post('/cia/user_cred', c2.body)).status, 201, j(c2));
    const log7 = new ethers.Contract(cia7.logAddress, MODE3_LOG_ABI, provider);
    const [r1, r2] = await Promise.all([
      cia7.adminPost('/cia/revoke', { uid: '12345', scope: 'credential' }),
      cia7.adminPost('/cia/revoke', { uid: '67890', scope: 'credential' }),
    ]);
    assert.equal(r1.status, 200, j(r1.body)); assert.equal(r2.status, 200, j(r2.body));
    assert.equal(r1.body.retired, 1); assert.equal(r2.body.retired, 1);
    const s = (await cia7.get('/cia/state')).body;
    assert.equal(s.pendingSlots, 0, '동시 폐기 중 한쪽이 publishing 중(409)이어도 그 몫이 다음 하트비트까지 묻히면 안 된다');
    assert.equal(b32(s.regRoot), await log7.regRoot());
    const ev = await log7.queryFilter(log7.filters.SlotUpdated(), 0, 'latest');
    assert.ok(ev.some((e) => Number(e.args.index) === 0 && BigInt(e.args.leaf) === 0n), '슬롯 0(uid 12345) 이 0 으로 게시돼야 한다');
    assert.ok(ev.some((e) => Number(e.args.index) === 1 && BigInt(e.args.leaf) === 0n), '슬롯 1(uid 67890) 이 0 으로 게시돼야 한다');
  } finally { await cia7.stop(); }
});

// ---- 은퇴 슬롯 방어(V10 Task 6, Task 5 리뷰 이월): 옛 백업을 복원하면 체인에선 이미 은퇴한 슬롯(isRetired)의 0 아닌 리프가
// 되살아나고, 기동 대조(epoch 어긋남)가 그것을 pendingSlots 로 다시 싣는다. 그대로 올리면 SlotIsRetired 로 매번 거절돼 root 가
// 늙는다 — 게시 직전에 그 슬롯을 0 으로 바꿔 실어야 한다. 이 상태는 어느 관리자 엔드포인트로도 만들 수 없어(tamper 는 활성
// 자격증명이 필요하고 계정 폐기 뒤 재발급은 새 슬롯을 받는다) 상태 파일을 은퇴 전 시점으로 되돌려 재현한다. ----
await t('은퇴 슬롯 방어: 은퇴 전 백업으로 재기동해도 은퇴 슬롯은 0 으로 실려 게시가 통과하고 계정은 폐기 상태가 된다', async () => {
  const cia8 = await startIsolatedCia();
  let backup, ciaKey, logAddr, slot;
  try {
    const v = await cia8.registerUser('12345', 'password123');
    const c = await buildUserCredRequest({ uid: 12345n, s_u: v.s_u, r_u: v.r_u, sk_u: v.sk_u, attrs: ATTRS });
    assert.equal((await cia8.post('/cia/user_cred', c.body)).status, 201);
    backup = JSON.parse(fs.readFileSync(path.join(cia8.dir, 'cia_state.json'), 'utf8'));   // 은퇴 전: 슬롯 0 = 0 아닌 리프
    const rv = await cia8.post('/cia/account/self_revoke', { uid: '12345', pwd: 'password123' });
    assert.equal(rv.status, 200, j(rv.body));
    const rc = rv.body.receipt; slot = rc.slot;
    const logW = new ethers.Contract(cia8.logAddress, MODE3_LOG_ABI, await provider.getSigner(0));
    await (await logW.requestRevocation(rc.slot, rc.epochAtRequest, rc.requestedAt, rc.sig)).wait();
    assert.equal((await cia8.adminPost('/cia/publish', {})).status, 200);
    const log8 = new ethers.Contract(cia8.logAddress, MODE3_LOG_ABI, provider);
    assert.equal(await log8.isRetired(slot), true);
    ciaKey = cia8.ciaEthWallet.privateKey; logAddr = cia8.logAddress;
  } finally { await cia8.stop(); }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-retired-'));
  const stateFile = path.join(dir, 'cia_state.json');
  fs.writeFileSync(stateFile, JSON.stringify(backup));
  const cia9 = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile, CIA_LOG_ADDRESS: logAddr, CIA_ETH_PRIVATE_KEY: ciaKey } });
  try {
    const log9 = new ethers.Contract(logAddr, MODE3_LOG_ABI, provider);
    const s = (await cia9.get('/cia/state')).body;
    assert.equal(s.pendingSlots, 0, `기동 자동 게시가 SlotIsRetired 에 막혀 백로그가 남았다\n${cia9.log().split('\n').filter((l) => /cia\]/.test(l)).join('\n')}`);
    assert.equal(await log9.regRoot(), b32(s.regRoot));
    const acct = (await cia9.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === '12345');
    assert.equal(acct.registryLeaf, '0'); assert.equal(acct.disabled, true); assert.equal(acct.activeCf_u, null);
  } finally { await cia9.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
});

provider.destroy();
process.exit(failed === 0 ? 0 : 1);
