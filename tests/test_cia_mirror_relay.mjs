// V10(2026-10-02 설계 §5 결정 3) CIA 거울 릴레이. 격리 CIA + :8545 의 캐노니컬 로그·거울. (chain)
// 2026-10-05(전체 코드 리뷰 3·9번): 게시 직후 뒤처진 거울에 즉시 중계하고(CIA_MIRROR_RELAY_ON_PUBLISH, 기본 켬), 따라잡은 거울을 위해
// 캐노니컬 하트비트를 새로 만들지 않는다. 첫 인스턴스는 즉시 중계를 꺼(0) 주기 틱만의 동작을 보고, 마지막 인스턴스가 즉시 중계를 본다.
//   node tests/test_cia_mirror_relay.mjs
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider, mineBlocks, publishV3, relayToMirror, canonOf, fundAddress } from './helpers/mode3_chain.mjs';
import { MODE3_MIRROR_ABI, MODE3_LOG_ABI, signPublicationV3 } from '../lib/mode3_log.js';
import { buildUserCredRequest } from '../lib/mode3_wallet.js';
import { registryLeaf } from '../lib/mode3_registry.js';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }
/** pred 가 참이 될 때까지 200ms 마다 본다. ms 안에 안 되면 throw. */
async function waitFor(pred, ms) {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await pred()) return;
    if (Date.now() > deadline) throw new Error(`waitFor: ${ms}ms 안에 조건이 성립하지 않았다`);
    await new Promise((r) => setTimeout(r, 200));
  }
}
const ATTRS = [1990n, 410n, 2n, 0n, 0n, 0n];
const uid = '12345', pwd = 'password123';
const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** 2026-10-02 V10 최종 리뷰 I-2: 캐노니컬에 올라가지 않은(revert 된 게시를 흉내 낸) CIA 서명 게시를 만들어 거울에 먼저 올린다.
 *  격리 CIA 의 키(ciaEthWallet)로 서명한다 — 실제 경합에서 공개되는 것도 IdP 가 서명한 calldata 다. */
async function forgeToMirror(inst, mirrorC, { epoch, revRoot, regRoot }) {
  const logC = new ethers.Contract(inst.logAddress, MODE3_LOG_ABI, provider);
  const p = { revRoot: b32(revRoot), regRoot: b32(regRoot), epoch, revLeaves: [], slotIdx: [], slotLeaves: [] };
  const sig = await signPublicationV3(inst.ciaEthWallet, { ...(await canonOf(logC, provider)), ...p });
  await relayToMirror(mirrorC, await provider.getSigner(0), { p, sig });
}
let u, alice;   // registerUser 결과 — 동시성 케이스가 다시 쓴다

const provider = getProvider();
// 캐노니컬 하트비트는 끈다(0) — 캐노니컬에 새 epoch 가 없을 때 릴레이가 하트비트를 스스로 만들지 **않는지** 본다(9번).
// 게시 직후 즉시 중계도 끈다('0') — 이 인스턴스는 주기 틱(H=5)만의 동작(뒤처짐·behindSince·불일치 복구)을 본다.
const cia = await startIsolatedCia({ env: { CIA_MIRROR_HEARTBEAT_BLOCKS: '5', CIA_MIRROR_POLL_MS: '300', CIA_HEARTBEAT_BLOCKS: '0', CIA_MIRROR_RELAY_ON_PUBLISH: '0' } });
const mirror = new ethers.Contract(cia.mirrorAddress, MODE3_MIRROR_ABI, provider);
const log = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
try {
  await t('계정 등록·발급 직후: 캐노니컬 epoch 는 올랐지만 거울은 아직 0 (하트비트 주기 전)', async () => {
    assert.equal(await mirror.epoch(), 0n, '기동 직후 거울은 0');
    u = await cia.registerUser(uid, pwd);
    const cred = await buildUserCredRequest({ uid: BigInt(uid), s_u: u.s_u, r_u: u.r_u, sk_u: u.sk_u, attrs: ATTRS });
    const r = await cia.post('/cia/user_cred', cred.body);   // 즉시 게시로 캐노니컬 epoch ≥ 1
    assert.equal(r.status, 201, j(r.body));
    alice = await cia.registerUser('67890', 'alicepw');   // 동시성 케이스에서 자기 폐기할 두 번째 사용자
    const ca = await buildUserCredRequest({ uid: 67890n, s_u: alice.s_u, r_u: alice.r_u, sk_u: alice.sk_u, attrs: alice.attrs.map(BigInt) });
    assert.equal((await cia.post('/cia/user_cred', ca.body)).status, 201);
    assert.ok((await log.epoch()) >= 1n); assert.equal(await mirror.epoch(), 0n);
  });
  await t('주기만큼 블록이 지나면 릴레이가 거울을 캐노니컬 epoch 로 올린다', async () => {
    await mineBlocks(6, provider);
    await waitFor(async () => (await mirror.epoch()) === (await log.epoch()), 5000);
    assert.equal(await mirror.revRoot(), await log.revRoot()); assert.equal(await mirror.regRoot(), await log.regRoot());
  });
  // 2026-10-05(9번): 예전에는 여기서 캐노니컬 하트비트를 새로 만들어 옮겼다 — 거울 수·짧은 H 에 비례해 캐노니컬 게시가 늘었다.
  await t('따라잡은 거울은 주기가 지나도 건드리지 않는다 — 캐노니컬 하트비트를 새로 만들지 않는다(epoch 둘 다 그대로)', async () => {
    const e0 = await mirror.epoch(), c0 = await log.epoch();
    assert.equal(e0, c0, '앞 케이스 뒤 거울과 캐노니컬이 같은 epoch 여야 이 경로를 탄다');
    await mineBlocks(12, provider);   // H=5 의 두 배 이상
    await sleep(1500);                // 릴레이 틱(300ms) 다섯 번
    assert.equal(await log.epoch(), c0, '캐노니컬에 하트비트가 새로 올라가면 안 된다');
    assert.equal(await mirror.epoch(), e0);
  });
  await t('POST /cia/admin/relay 는 주기와 무관하게 즉시 갱신하고 /mode3/health 가 mirrors 를 낸다', async () => {
    const rv = await cia.post('/cia/account/self_revoke', { uid, pwd });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.published, true);
    assert.ok((await mirror.epoch()) < (await log.epoch()), '폐기 게시 직후에는 거울이 뒤처져 있다');
    const r = await cia.adminPost('/cia/admin/relay', {});
    assert.equal(r.status, 200, j(r.body));
    assert.equal(await mirror.epoch(), await log.epoch());
    assert.equal(r.body.mirrors.length, 1); assert.equal(r.body.mirrors[0].chainId, '31337'); assert.equal(r.body.mirrors[0].epoch, (await log.epoch()).toString());
    const again = await cia.adminPost('/cia/admin/relay', {});   // 새 epoch 없이 force — 하트비트를 올려 다시 갱신하거나 이미 갱신됨
    assert.equal(again.status, 200, j(again.body));
    assert.equal(await mirror.epoch(), await log.epoch());
    const h = (await cia.get('/mode3/health')).body;
    assert.equal(h.mirrors.length, 1, j(h)); assert.equal(h.mirrors[0].behind, 0);
    assert.equal(h.mirrors[0].chainId, '31337'); assert.equal(h.mirrors[0].address, cia.mirrorAddress);
    assert.equal(typeof h.mirrors[0].rootAge, 'number');
    const pk = (await cia.get('/cia/public_keys')).body;
    assert.deepEqual(pk.mirrors, [{ chainId: '31337', address: cia.mirrorAddress }]);
  });
  // 리뷰 C1(2026-10-02): 게시 잠금이 원자적이지 않으면 발급 게시·폐기 게시·거울 tx 가 같은 키로 겹쳐(nonce 경합) 한쪽 몫이
  // { published:false } 로 묻히거나 게시가 겹친다. 셋을 동시에 쏘고, 두 변경이 모두 체인에 실렸는지와 상태가 수렴했는지 본다.
  // published 플래그는 보지 않는다 — 앞선 게시에 묻어가면 정상적으로 false 일 수 있다. 판정은 SlotUpdated 다.
  await t('동시성: 발급·자기 폐기·관리자 relay 를 한꺼번에 — 두 변경 모두 게시되고 regRoot·거울이 수렴한다', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);   // 12345 재발급은 새 슬롯
    const cred = await buildUserCredRequest({ uid: BigInt(uid), s_u: u.s_u, r_u: u.r_u, sk_u: u.sk_u, attrs: ATTRS });
    const fromBlock = await provider.getBlockNumber();
    const [iss, rv, rl] = await Promise.all([
      cia.post('/cia/user_cred', cred.body),
      cia.post('/cia/account/self_revoke', { uid: '67890', pwd: 'alicepw' }),
      cia.adminPost('/cia/admin/relay', {}),
    ]);
    assert.equal(iss.status, 201, j(iss.body)); assert.equal(rv.status, 200, j(rv.body));
    assert.equal(rl.status, 200, j(rl.body)); assert.ok(rl.body.mirrors.every((m) => !m.error), j(rl.body));
    assert.deepEqual((await log.pendingSlots()).map(Number), []);
    const reg = (await cia.adminGet('/cia/admin/registry')).body;
    assert.equal(reg.pendingSlots, 0, '로컬 백로그가 남았다 — 한쪽 게시가 409 로 묻혔다');
    assert.equal(b32(reg.regRoot), await log.regRoot());
    const ev = await log.queryFilter(log.filters.SlotUpdated(), fromBlock + 1, 'latest');
    const want = await registryLeaf(u.cm_u, cred.Cf_u);
    assert.ok(ev.some((e) => Number(e.args.index) === iss.body.slot && BigInt(e.args.leaf) === want), `발급 슬롯 ${iss.body.slot} 의 SlotUpdated 가 없다`);
    assert.ok(ev.some((e) => Number(e.args.index) === alice.slot && BigInt(e.args.leaf) === 0n), `자기 폐기 슬롯 ${alice.slot} 의 0 SlotUpdated 가 없다`);
    const again = await cia.adminPost('/cia/admin/relay', {});
    assert.equal(again.status, 200, j(again.body));
    assert.equal(await mirror.epoch(), await log.epoch());
    assert.equal(await mirror.regRoot(), await log.regRoot());
  });
  // 2026-10-02 V10 최종 리뷰 I-1: lastPublishedBlock 은 누구나(캐노니컬에 공개된 중간 epoch 서명을 올려) 갱신할 수 있다.
  // 트리거가 head − lastPublishedBlock 뿐이면 릴레이 직전마다 중간 epoch 를 하나씩 올려 폐기 반영을 (중간 epoch 수 + 1)·H 로
  // 늘릴 수 있었다. 이제는 거울이 뒤처진 것을 처음 본 블록(behindSince)부터 H 안에 따라잡아야 한다(H=5).
  await t('I-1: 중간 epoch 서명을 거울에 올려 lastPublishedBlock 을 리셋해도 최초 뒤처짐 관측 + H 안에 거울이 최신 epoch 가 된다', async () => {
    assert.equal((await cia.adminPost('/cia/admin/relay', {})).status, 200);   // 거울 = 캐노니컬, lastPublishedBlock = M
    const c = await log.epoch();
    assert.equal(await mirror.epoch(), c);
    const rev = BigInt(await log.revRoot()), reg = BigInt(await log.regRoot());
    const pubs = [];   // 캐노니컬 M+1..M+3 — IdP 가 게시한 것과 같은 서명들(같은 root 의 하트비트)
    for (let i = 1n; i <= 3n; i++) pubs.push(await publishV3(log, cia.ciaEthWallet, { revRoot: rev, regRoot: reg, epoch: c + i }));
    await sleep(1200);   // 릴레이 틱(300ms)이 뒤처짐을 관측할 시간 — behindSince ≤ M+3
    const funder = await provider.getSigner(0);
    await relayToMirror(mirror, funder, pubs[0]);   // M+4: 거울 lastPublishedBlock 리셋
    await relayToMirror(mirror, funder, pubs[1]);   // M+5: 다시 리셋
    assert.equal(await mirror.epoch(), c + 2n);
    await mineBlocks(3, provider);                  // M+8: behindSince + 5 는 지났고, head − lastPublishedBlock 은 3
    await waitFor(async () => (await mirror.epoch()) >= c + 3n && (await mirror.epoch()) === (await log.epoch()), 4000);
    assert.equal(await mirror.revRoot(), await log.revRoot());
  });
  // 2026-10-02 V10 최종 리뷰 I-2(b): 같은 epoch 다른 root 의 서명(revert 된 게시의 calldata)이 거울에 먼저 올라가면 지갑의
  // syncAt(untilEpoch, expectRoot) 가 전부 어긋난다. 릴레이는 주기와 무관하게 즉시 새 하트비트를 올려 덮어야 한다.
  await t('I-2: 캐노니컬과 같은 epoch·다른 root 의 서명이 거울에 올라가면 릴레이 틱이 주기를 기다리지 않고 덮는다', async () => {
    assert.equal((await cia.adminPost('/cia/admin/relay', {})).status, 200);
    const c = await log.epoch();
    const rev = BigInt(await log.revRoot()), reg = BigInt(await log.regRoot());
    await publishV3(log, cia.ciaEthWallet, { revRoot: rev, regRoot: reg, epoch: c + 1n });          // 캐노니컬 epoch c+1
    await forgeToMirror(cia, mirror, { epoch: c + 1n, revRoot: rev + 1n, regRoot: reg });          // 거울 epoch c+1, 다른 revRoot
    assert.notEqual(await mirror.revRoot(), await log.revRoot());
    // 블록을 캐지 않는다 — head − lastPublishedBlock 은 0 이라 주기 트리거로는 H 블록 동안 안 고쳐진다
    await waitFor(async () => (await mirror.epoch()) > c + 1n && (await mirror.epoch()) === (await log.epoch()), 4000);
    assert.equal(await mirror.revRoot(), await log.revRoot()); assert.equal(await mirror.regRoot(), await log.regRoot());
    const h = (await cia.get('/mode3/health')).body;
    assert.equal(h.mirrors[0].mismatch, false, j(h.mirrors));
  });
  await t('관리자 relay 는 관리자 시크릿이 필요하다', async () => {
    assert.equal((await cia.post('/cia/admin/relay', {})).status, 401);
  });
} finally { await cia.stop(); }

// 2026-10-02 V10 최종 리뷰 I-2(a)·(b): 릴레이 틱을 끈 별도 인스턴스 — 실패한 게시의 epoch 는 소비되고, 거울이 캐노니컬보다
// 앞선 서명을 받으면 health 가 mismatch:true 를 내며 관리자 relay 가 그보다 큰 epoch 로 덮는다.
const cia2 = await startIsolatedCia();
const log2 = new ethers.Contract(cia2.logAddress, MODE3_LOG_ABI, provider);
const mirror2 = new ethers.Contract(cia2.mirrorAddress, MODE3_MIRROR_ABI, provider);
try {
  await t('I-2(a): 서명 뒤 실패한 게시의 epoch 는 소비된다 — 다음 게시는 그 epoch 를 건너뛴다', async () => {
    assert.equal((await cia2.adminPost('/cia/admin/relay', {})).status, 200);
    const e0 = await log2.epoch();
    const w = cia2.ciaEthWallet, funder = await provider.getSigner(0);
    const gp = (await provider.getFeeData()).gasPrice;
    const bal = await provider.getBalance(w.address);
    await (await w.sendTransaction({ to: await funder.getAddress(), value: bal - 21000n * gp, gasPrice: gp, gasLimit: 21000n, type: 0 })).wait();
    const bad = await cia2.adminPost('/cia/admin/relay', {});   // 하트비트 서명 → 송금 실패(잔고 0)
    assert.notEqual(bad.status, 200, j(bad.body));
    assert.equal(await log2.epoch(), e0);
    await fundAddress(w.address, '1', provider);
    const ok = await cia2.adminPost('/cia/admin/relay', {});
    assert.equal(ok.status, 200, j(ok.body));
    assert.equal(await log2.epoch(), e0 + 2n, '실패한 게시가 서명한 epoch 를 다시 쓰면 안 된다');
    assert.equal(await mirror2.epoch(), await log2.epoch());
  });
  await t('I-2(b): 거울이 캐노니컬보다 앞선 epoch 를 받으면 health mismatch:true, 관리자 relay 가 덮어 mismatch 해소', async () => {
    const c = await log2.epoch();
    await forgeToMirror(cia2, mirror2, { epoch: c + 1n, revRoot: BigInt(await log2.revRoot()) + 1n, regRoot: BigInt(await log2.regRoot()) });
    const h1 = (await cia2.get('/mode3/health')).body;
    assert.equal(h1.mirrors[0].mismatch, true, j(h1.mirrors));
    const r = await cia2.adminPost('/cia/admin/relay', {});
    assert.equal(r.status, 200, j(r.body));
    assert.ok((await mirror2.epoch()) > c + 1n);
    assert.equal(await mirror2.epoch(), await log2.epoch());
    assert.equal(await mirror2.revRoot(), await log2.revRoot()); assert.equal(await mirror2.regRoot(), await log2.regRoot());
    const h2 = (await cia2.get('/mode3/health')).body;
    assert.equal(h2.mirrors[0].mismatch, false, j(h2.mirrors)); assert.equal(h2.mirrors[0].behind, 0);
  });
} finally { await cia2.stop(); }

// 2026-10-05(전체 코드 리뷰 3번): 게시 직후 즉시 중계(기본값). 주기(H=5)가 지나지 않게 블록을 캐지 않고, 캐노니컬 하트비트는 끈다 —
// 거울이 따라오면 그것은 즉시 중계 덕이고, 캐노니컬 epoch 는 게시한 횟수만큼만 오른다(따라잡은 거울용 하트비트 없음).
const cia3 = await startIsolatedCia({ env: { CIA_MIRROR_HEARTBEAT_BLOCKS: '5', CIA_MIRROR_POLL_MS: '300', CIA_HEARTBEAT_BLOCKS: '0' } });
const log3 = new ethers.Contract(cia3.logAddress, MODE3_LOG_ABI, provider);
const mirror3 = new ethers.Contract(cia3.mirrorAddress, MODE3_MIRROR_ABI, provider);
try {
  await t('게시 직후 즉시 중계: 발급·자기 폐기 게시가 블록을 캐지 않아도 곧바로 거울에 실리고, 캐노니컬 epoch 는 게시 횟수만큼만 오른다', async () => {
    await waitFor(async () => (await mirror3.epoch()) === (await log3.epoch()), 4000);   // 기동 게시가 있었다면 기동 직후 중계가 따라잡게 한다
    const c0 = await log3.epoch();
    const u3 = await cia3.registerUser(uid, pwd);
    const cred = await buildUserCredRequest({ uid: BigInt(uid), s_u: u3.s_u, r_u: u3.r_u, sk_u: u3.sk_u, attrs: ATTRS });
    const iss = await cia3.post('/cia/user_cred', cred.body);
    assert.equal(iss.status, 201, j(iss.body));
    await waitFor(async () => (await mirror3.regRoot()) === (await log3.regRoot()) && (await mirror3.epoch()) === (await log3.epoch()), 4000);
    assert.equal(await log3.epoch(), c0 + 1n, '발급 게시 한 번 — 중계를 위해 하트비트가 더 올라가면 안 된다');
    const rv = await cia3.post('/cia/account/self_revoke', { uid, pwd });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.published, true);
    await waitFor(async () => (await mirror3.regRoot()) === (await log3.regRoot()) && (await mirror3.epoch()) === (await log3.epoch()), 4000);
    assert.equal(await log3.epoch(), c0 + 2n);
    await mineBlocks(12, provider); await sleep(1500);   // 주기가 지나도 따라잡은 거울에는 아무 일도 없다
    assert.equal(await log3.epoch(), c0 + 2n); assert.equal(await mirror3.epoch(), c0 + 2n);
    const h = (await cia3.get('/mode3/health')).body;
    assert.equal(h.mirrors[0].behind, 0, j(h.mirrors)); assert.equal(h.mirrors[0].mismatch, false);
  });
} finally { await cia3.stop(); }

provider.destroy();
process.exit(failed === 0 ? 0 : 1);
