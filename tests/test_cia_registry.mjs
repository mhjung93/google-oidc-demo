// CIA 등록부(V9) — 등록 키·슬롯·즉시 게시·은퇴·마이그레이션. 격리 CIA + :8545 Mode3Log. (chain)  node tests/test_cia_registry.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createRegistration, signRegistration, buildUserCredRequest, buildIssueRequest, createSessionKey, signRevokeSession } from '../lib/mode3_wallet.js';
import { pointToStrings, registrationCommit } from '../lib/mode3_issuance.js';
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
provider.destroy();
process.exit(failed === 0 ? 0 : 1);
