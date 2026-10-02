// V10(2026-10-02 설계 §5 결정 3) CIA 거울 릴레이. 격리 CIA + :8545 의 캐노니컬 로그·거울. 릴레이가 하트비트 주기로만 거울을
// 갱신하는지, 캐노니컬에 새 epoch 가 없으면 캐노니컬 하트비트를 먼저 올리는지, 수동 relay 가 즉시 갱신하는지. (chain)
//   node tests/test_cia_mirror_relay.mjs
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider, mineBlocks } from './helpers/mode3_chain.mjs';
import { MODE3_MIRROR_ABI, MODE3_LOG_ABI } from '../lib/mode3_log.js';
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
let u, alice;   // registerUser 결과 — 동시성 케이스가 다시 쓴다

const provider = getProvider();
// 캐노니컬 하트비트는 끈다(0) — "캐노니컬에 새 epoch 가 없을 때" 릴레이가 스스로 하트비트를 먼저 올리는 경로를 본다.
const cia = await startIsolatedCia({ env: { CIA_MIRROR_HEARTBEAT_BLOCKS: '5', CIA_MIRROR_POLL_MS: '300', CIA_HEARTBEAT_BLOCKS: '0' } });
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
  await t('캐노니컬에 새 epoch 가 없어도 주기가 지나면 캐노니컬 하트비트를 먼저 올리고 거울을 갱신한다', async () => {
    const e0 = await mirror.epoch(), c0 = await log.epoch();
    assert.equal(e0, c0, '앞 케이스 뒤 거울과 캐노니컬이 같은 epoch 여야 이 경로를 탄다');
    await mineBlocks(6, provider);
    await waitFor(async () => (await mirror.epoch()) > e0, 5000);
    assert.ok((await log.epoch()) > c0, '캐노니컬 하트비트가 먼저 올라갔어야 한다');
    assert.equal(await mirror.epoch(), await log.epoch());
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
  await t('관리자 relay 는 관리자 시크릿이 필요하다', async () => {
    assert.equal((await cia.post('/cia/admin/relay', {})).status, 401);
  });
} finally { await cia.stop(); }

provider.destroy();
process.exit(failed === 0 ? 0 : 1);
