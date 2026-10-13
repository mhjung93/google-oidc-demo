// CIA 기동 시 로컬 폐기 트리와 온체인 root 대조 — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_startup.mjs
//
// 배경: /cia/publish 가 tx 를 보낸 뒤 persist() 전에 죽으면 상태 파일이 체인보다 뒤처진다(크래시 복구).
// 반대로 로그를 재배포했거나 옛 백업을 복원하면 상태 파일이 체인보다 앞선다. 둘 다 그대로
// 두면 다음 publish 가 서명하는 root 와 지갑이 이벤트로 재구성한 root 가 어긋나 전원이
// fail-closed 된다. 기동 시 "revoked 의 접두사 중 온체인 root 와 같은 것" 을 찾아, 있으면
// 그 뒤만 pending 으로 남기고 없으면 기동을 거부한다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider, rootToBytes32, canonOf } from './helpers/mode3_chain.mjs';
import { MODE3_LOG_ABI, signPublicationV3 } from '../lib/mode3_log.js';
import { randomScalar } from '../lib/mode3_credential.js';
import { createRevocationTree } from '../lib/mode3_revocation.js';
import { DEFAULT_ATTR_SCHEMA, loadSchema } from '../lib/mode3_attr_schema.js';
import { issueV11, userOf } from './helpers/mode3_flow.mjs';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const provider = getProvider();
const uid = 12345n, arid = 22222222222222222222n;
const keep = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-cia-startup-'));   // 첫 인스턴스의 상태·키 파일 사본
const keptState = path.join(keep, 'cia_state.json');
const keptKeys = path.join(keep, 'cia_keys.json');

/**
 * 등록(최초 1회) → 세션 발급(V11, 매번 새 r_s·r_rp 라 새 Cf_s) → 그 세션을 scope=session 으로 폐기. 폐기 리프(10진)를
 * 돌려준다. V9: scope=credential|account 는 더 이상 폐기 트리에 아무것도 넣지 않는다(등록부 슬롯만 비우고 즉시
 * 게시한다) — 트리에 리프를 추가하는 경로는 scope=session 뿐이므로, "폐기 트리 vs 온체인 root 대조"를 보는 이
 * 파일의 시나리오는 세션 단위로 재현한다. 사용자 자격증명은 한 번만 받아 재사용한다(매번 다시 받으면 그 발급
 * 자체가 등록부를 즉시 게시해 epoch 가 예측과 어긋난다).
 */
async function registerAndIssueLeaf(cia, user) {
  if (!user.sk_u) Object.assign(user, userOf(await cia.registerUser(uid.toString(), 'password123'), uid), { blind_u: randomScalar() });
  // 사용자 자격증명은 한 번만(매번 새 C_u 면 그 발급 자체가 등록부를 즉시 게시해 epoch 가 예측과 어긋난다) — 같은 blind_u 를 다시 준다.
  const iss = await issueV11(cia, user, { arid, provider: getProvider(), blind_u: user.blind_u });
  assert.equal(iss.r.status, 200, JSON.stringify(iss.r.body));
  const rv = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: iss.cred.Cf_s });
  assert.equal(rv.status, 200, JSON.stringify(rv.body)); assert.equal(rv.body.inserted, true);
  return rv.body.leaf;
}

/** 기동이 거부돼야 한다. 거부되지 않고 떠 버리면 잔존 프로세스를 남기지 않도록 멈춘 뒤 실패시킨다.
 *  cia.js 의 기동 거부 로그는 모두 `[cia] 기동 거부:` 로 시작한다(root 불일치·속성 스키마 오류 등 — 2026-10-07 §3 추가분).
 *  거부 메시지(기동 로그 포함)를 돌려준다 — 거부 사유가 여럿일 수 있는 케이스가 사유를 따로 대조한다. */
async function expectStartupRefused(opts) {
  let cia;
  try { cia = await startIsolatedCia(opts); }
  catch (e) { assert.match(e.message, /기동 거부:/); return e.message; }
  await cia.stop();
  assert.fail('기동이 거부돼야 하는데 떠 버렸다');
}

let first = await startIsolatedCia();
const firstLog = first.logAddress;
const firstEthPrv = first.ciaEthWallet.privateKey;
const b32 = (leaf) => rootToBytes32(BigInt(leaf));

try {
  const user = { sk_u: null };
  // 상황 만들기: L1 은 정상 게시, L2·L3 는 pending. 그 다음 "L2 만 실은 게시 tx 는 성공했는데 CIA 가 persist() 전에
  // 죽었다" 를 흉내낸다 — 체인에 직접 게시하고 상태 파일은 그대로 둔다. V9: registerAndIssueLeaf 안의 사용자
  // 자격증명 발급(최초 1회)이 등록부를 즉시 게시하므로(세션 폐기 pending 과는 별개 epoch 증가) 아래는 전부
  // 상대값으로 잰다 — "L1 은 epoch 1" 같은 V8 식 절대값은 더 이상 맞지 않는다.
  const L1 = await registerAndIssueLeaf(first, user);
  const pub1 = await first.adminPost('/cia/publish');
  assert.equal(pub1.status, 200, JSON.stringify(pub1.body)); assert.equal(pub1.body.published, true);
  const epoch1 = pub1.body.epoch;   // L1 이 게시된 epoch
  const L2 = await registerAndIssueLeaf(first, user);
  const L3 = await registerAndIssueLeaf(first, user);
  assert.equal((await first.get('/cia/state')).body.pendingCount, 2);

  const tree12 = await createRevocationTree();
  await tree12.insert(BigInt(L1)); await tree12.insert(BigInt(L2));
  const root12 = rootToBytes32(tree12.getRoot());
  const regRootNow = rootToBytes32(BigInt((await first.get('/cia/state')).body.regRoot));
  const log = new ethers.Contract(firstLog, MODE3_LOG_ABI, first.ciaEthWallet);
  const directEpoch = epoch1 + 1;
  const sig = await signPublicationV3(first.ciaEthWallet, { ...(await canonOf(log, provider)), revRoot: root12, regRoot: regRootNow, epoch: directEpoch, revLeaves: [b32(L2)], slotIdx: [], slotLeaves: [] });
  await (await log.publish(root12, regRootNow, directEpoch, [b32(L2)], [], [], sig)).wait();
  assert.equal(await log.epoch(), BigInt(directEpoch));

  fs.copyFileSync(path.join(first.dir, 'cia_state.json'), keptState);
  fs.copyFileSync(path.join(first.dir, 'cia_keys.json'), keptKeys);
  await first.stop();
  first = null;

  await t('크래시 복구: 이미 게시된 pending 접두사(L2)는 걷어내고 남은 L3 는 기동 시 자동 게시로 올라간다', async () => {
    const cia = await startIsolatedCia({ env: { CIA_STATE_FILE: keptState, CIA_KEYS_FILE: keptKeys, CIA_LOG_ADDRESS: firstLog, CIA_ETH_PRIVATE_KEY: firstEthPrv } });
    try {
      // V9: 기동 대조가 L2 접두사를 걷어낸 뒤에도 L3 가 pending 으로 남으면, 같은 기동이 그 백로그를 자동으로
      // 게시한다(2026-10-01 리뷰 Important 1, loadState 의 "펜딩이 남으면 게시를 한 번 시도") — 그래서
      // startIsolatedCia() 가 돌아올 때는 이미 directEpoch+1, pending 0 이다. V8 처럼 "대조만 하고 L3 는
      // 명시적 publish 를 기다린다" 는 더 이상 관찰되지 않는다.
      const st = (await cia.get('/cia/state')).body;
      assert.equal(st.epoch, directEpoch + 1, '대조로 directEpoch 를 따라잡고 L3 백로그를 자동 게시해 한 번 더 올라가야 한다');
      assert.equal(st.leafCount, 3, 'revoked 는 그대로');
      assert.equal(st.pendingCount, 0, '자동 게시가 L3 까지 비웠어야 한다');
      const log2 = new ethers.Contract(firstLog, MODE3_LOG_ABI, provider);
      assert.equal(await log2.epoch(), BigInt(directEpoch) + 1n);
      const ev = await log2.queryFilter(log2.filters.Revoked(directEpoch + 1), 0, 'latest');
      assert.equal(ev.length, 1); assert.equal(ev[0].args.leaves.length, 1, 'L3 만 실려야 한다(L2 를 중복으로 다시 싣지 않는다)');
      assert.equal(BigInt(ev[0].args.leaves[0]), BigInt(L3));
      // 명시적 publish 를 또 불러도 더 실을 것이 없다
      const pub = await cia.adminPost('/cia/publish');
      assert.equal(pub.body.published, false, JSON.stringify(pub.body));
      // 지갑이 이벤트만으로 재구성한 root 가 CIA 의 root 와 같아야 한다(L2 가 두 번 나가지 않았다) — syncRevocationTree
      // (lib/mode3_wallet.js) 는 아직 V1 LOG_ABI 라(Task 10 전) 여기서는 Mode3Log 의 revRoot() 로 직접 대조한다.
      assert.equal(BigInt(await log2.revRoot()).toString(), st.root);
    } finally { await cia.stop(); }
  });

  await t('불일치 거부: 상태 파일의 리프가 로그에 없으면(로그 재배포) 기동하지 않는다', async () => {
    // 기본 하네스는 빈 로그를 새로 배포한다 — 상태 파일은 리프 3개가 전부 게시됐다고 믿고 있다.
    await expectStartupRefused({ env: { CIA_STATE_FILE: keptState, CIA_KEYS_FILE: keptKeys } });
  });

  await t('불일치 거부: 빈 상태 파일로 리프가 있는 로그를 가리켜도 기동하지 않는다 (상태 파일 유실)', async () => {
    await expectStartupRefused({ env: { CIA_LOG_ADDRESS: firstLog, CIA_ETH_PRIVATE_KEY: firstEthPrv } });
  });

  await t('V11: v11 이하 상태 파일(v4·v11)은 기동 거부 — 사유 한 줄에 "재시연 세트"', async () => {
    for (const v of [4, 11]) {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), `mode3-old-v${v}-`));
      const stateFile = path.join(dir, 'cia_state.json');
      fs.writeFileSync(stateFile, JSON.stringify({ version: v, accounts: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 }), { mode: 0o600 });
      const msg = await expectStartupRefused({ env: { CIA_STATE_FILE: stateFile } });
      assert.match(msg, /unsupported CIA state version/); assert.match(msg, /재시연 세트/);
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  await t('V11: 백로그(pendingSlots)가 남은 v12 파일은 기동이 자동 게시한다; 자동 게시가 RPC 를 못 읽으면 경고만 남기고 기동은 계속한다', async () => {
    const { createRegistration } = await import('../lib/mode3_wallet.js');
    const { userCommit } = await import('../lib/mode3_credential.js');
    const { registryLeaf } = await import('../lib/mode3_registry.js');
    const reg = await createRegistration(12345n);
    const { Cx, Cy, Cf } = await userCommit({ uid: 12345n, s_u: reg.s_u, blind_u: randomScalar(), attrs: [1990n, 410n, 0n, 0n, 0n, 0n] });
    const leaf = (await registryLeaf(reg.auid, Cf)).toString();
    const mk = () => ({ version: 12, accounts: { '12345': { pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() }, auid: reg.auid.toString(), slot: 0, tampered: false, disabled: false, creds: [{ Cf_u: Cf.toString(), C_u_pt: { x: Cx.toString(), y: Cy.toString() }, issuedAt: 'x', revoked: false }], sessions: [], receipt: null, slotRetired: false } },
      rps: {}, openings: [], revoked: [], pending: [], epoch: 0, registry: { depth: 20, next: 1, leaves: { '0': leaf }, pendingSlots: [{ index: 0, leaf }] }, lastPublication: null, signedEpochMax: 0, attrSchemaHash: null });
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-v12-backlog-'));
    const stateFile = path.join(dir, 'cia_state.json');
    fs.writeFileSync(stateFile, JSON.stringify(mk()), { mode: 0o600 });
    const cia = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile } });
    try {
      const st = (await cia.get('/cia/state')).body;
      assert.equal(st.pendingSlots, 0, '기동이 백로그를 게시했어야 한다'); assert.equal(st.epoch, 1);
    } finally { await cia.stop(); }
    fs.writeFileSync(stateFile, JSON.stringify(mk()), { mode: 0o600 });
    const dead = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile, CIA_RPC_URL: 'http://127.0.0.1:1' } });
    try {
      assert.match(dead.log(), /\/cia\/publish/, '수동 게시 안내');
      assert.equal((await dead.get('/cia/state')).body.pendingSlots, 1, '게시가 실패했으므로 백로그는 그대로');
    } finally { await dead.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await t('CIA_ATTR_SCHEMA_FILE 이 검증에 실패하면 기동하지 않는다', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-badschema-'));
    const schemaFile = path.join(dir, 'schema.json');
    fs.writeFileSync(schemaFile, JSON.stringify({ id: 'x', version: 1, slots: [{ type: 'unused' }] }));
    await expectStartupRefused({ env: { CIA_ATTR_SCHEMA_FILE: schemaFile } });
    fs.rmSync(dir, { recursive: true, force: true });
  });

  // 최종 리뷰 I4(2026-10-07): 계정 attrs 는 저장 당시 스키마로 인코딩돼 있다 — 상태 파일이 해시를 기억하고, 다른 스키마로 뜨면 거부한다.
  await t('스키마 해시: 해시가 없던 v12 상태 파일은 지금 스키마의 해시를 기록하고, 해시가 다른 v12 상태 파일은 기동 거부', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-schemahash-'));
    const stateFile = path.join(dir, 'cia_state.json');
    const schemaFile = path.join(dir, 'schema.json');
    try {
      fs.writeFileSync(stateFile, JSON.stringify({ version: 12, accounts: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0, registry: { depth: 20, next: 0, leaves: {}, pendingSlots: [] }, lastPublication: null, signedEpochMax: 0 }), { mode: 0o600 });
      const cia = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile } });
      try {
        const sch = (await cia.get('/cia/attr_schema')).body;
        assert.equal(JSON.parse(fs.readFileSync(stateFile, 'utf8')).attrSchemaHash, sch.hash, '기동이 지금 스키마의 해시를 기록했다');
      } finally { await cia.stop(); }
      // 기본 스키마와 다르지만 유효한 스키마
      const other = { ...DEFAULT_ATTR_SCHEMA, id: 'zkd-attrs-alt', slots: DEFAULT_ATTR_SCHEMA.slots.map((sl, i) => (i === 3 ? { name: 'note', label: '메모', type: 'string' } : sl)) };
      fs.writeFileSync(schemaFile, JSON.stringify(other));
      assert.notEqual(loadSchema(other).hash, loadSchema(DEFAULT_ATTR_SCHEMA).hash);
      const msg = await expectStartupRefused({ env: { CIA_STATE_FILE: stateFile, CIA_ATTR_SCHEMA_FILE: schemaFile } });
      assert.match(msg, /속성 스키마가 바뀌었다/, msg);
      assert.ok(msg.includes(loadSchema(DEFAULT_ATTR_SCHEMA).hash) && msg.includes(loadSchema(other).hash), '저장 해시와 현재 해시를 둘 다 보여 준다');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  // 나머지(크래시 복구·불일치 거부·하트비트)는 registerAndIssueLeaf 로 이미 덮인다.
} finally {
  if (first) await first.stop();
  fs.rmSync(keep, { recursive: true, force: true });
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
