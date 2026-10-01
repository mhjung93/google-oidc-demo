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
import { MODE3_LOG_ABI } from '../lib/mode3_log.js';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }
const provider = getProvider();
const cia = await startIsolatedCia();
const log = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
const ATTRS = [1990n, 410n, 2n, 0n, 0n, 0n];
const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32);
let u;   // registerUser 결과
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
    const a = await cia.registerUser('67890', 'alicepw');
    assert.equal(a.slot, 1);
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

provider.destroy();
process.exit(failed === 0 ? 0 : 1);
