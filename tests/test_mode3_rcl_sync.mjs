// RCL 증분 동기화(체크포인트+델타). :8545 필요. (chain 그룹)
//   node tests/test_mode3_rcl_sync.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ethers } from 'ethers';
import { getProvider, fundAddress, deployRevocationLog, signRootPublication, rootToBytes32 } from './helpers/mode3_chain.mjs';
import { createRevocationTree } from '../lib/mode3_revocation.js';
import { syncRevocationTree } from '../lib/mode3_wallet.js';
import { createRevocationSync, RCL_CACHE_VERSION } from '../lib/mode3_rcl_sync.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); }
}

const provider = getProvider();
const ciaEth = ethers.Wallet.createRandom().connect(provider);
await fundAddress(ciaEth.address, '1', provider);
const { address: logAddress, contract: log } = await deployRevocationLog(ciaEth.address, provider);
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-rcl-'));
const cacheFile = path.join(dir, 'mode3_wallet_rcl.json');
const warnings = [];
const warn = (m) => warnings.push(String(m));

// CIA 흉내: 지금까지의 리프 + 새 리프로 root 를 만들어 게시한다(test_mode3_wallet.mjs 와 같은 방식)
async function publish(leavesBig) {
  const tree = await createRevocationTree();
  const ev = await log.queryFilter(log.filters.Revoked());
  for (const e of ev) for (const l of e.args.leaves) await tree.insert(BigInt(l));
  for (const l of leavesBig) await tree.insert(l);
  const root = rootToBytes32(tree.getRoot());
  const epoch = (await log.epoch()) + 1n;
  const leaves = leavesBig.map(rootToBytes32);
  const sig = await signRootPublication(ciaEth, { logAddress, root, epoch, leaves });
  await (await log.connect(ciaEth).publishRoot(root, epoch, leaves, sig)).wait();
}

// eth_getLogs 호출을 기록하는 provider. ethers v6 의 _perform 은 this.send 를 부르므로 인스턴스의 send 를 감싸면 된다.
function spyProvider() {
  const p = getProvider();
  const calls = [];
  const orig = p.send.bind(p);
  p.send = async (method, params) => {
    if (method === 'eth_getLogs') calls.push({ fromBlock: Number(params[0].fromBlock), toBlock: Number(params[0].toBlock) });
    return orig(method, params);
  };
  return { p, calls };
}

// root() 의 eth_call 만 가로채 다른 값을 돌려주는 provider(fail-closed 시험용). root() 셀렉터 0xebf0c717.
// lieCount: 처음 그만큼의 root() 호출만 거짓말하고 그 뒤는 정직해진다(기본 Infinity — 항상 거짓말).
// 같은 provider 인스턴스를 계속 쓰는 rcl 을 "거짓말이 끝난 뒤 정직해진 노드에 재동기화"하는 시험에 쓴다(I2).
function lyingRootProvider(fakeRootBig, lieCount = Infinity) {
  const p = getProvider();
  let told = 0;
  const orig = p.send.bind(p);
  p.send = async (method, params) => {
    if (method === 'eth_call' && String(params[0]?.data ?? '').startsWith('0xebf0c717') && told < lieCount) {
      told++;
      return rootToBytes32(fakeRootBig);
    }
    return orig(method, params);
  };
  return p;
}

const readCache = () => JSON.parse(fs.readFileSync(cacheFile, 'utf8'));

// 1. 델타 = 전체
await t('부트스트랩 뒤 델타를 적용한 root 가 전체 재생 root 와 같다', async () => {
  await publish([11n, 12n, 13n]);
  const rcl = createRevocationSync({ provider, logAddress, cacheFile, log: warn });
  const a = await rcl.sync();
  assert.equal(a.mode, 'bootstrap');
  assert.ok(fs.existsSync(cacheFile), '부트스트랩 뒤 캐시가 써진다');
  await publish([14n, 15n]);
  const b = await rcl.sync();
  assert.equal(b.mode, 'delta');
  const full = await syncRevocationTree(provider, logAddress);
  assert.equal(b.root, full.root);
  assert.equal(b.epoch, full.epoch);
  assert.ok(b.tree.has(15n) && b.tree.has(11n));
  assert.equal(rcl.stats().leaves, 5);
  assert.equal(readCache().leaves.length, 5, '리프가 붙었으니 캐시가 갱신된다');
});

// 2. 조회 범위
await t('두 번째 sync 는 lastSyncedBlock+1 부터만 getLogs 하고, 같은 head 에서는 getLogs 를 부르지 않는다', async () => {
  const { p, calls } = spyProvider();
  const rcl = createRevocationSync({ provider: p, logAddress, cacheFile, log: warn });
  const a = await rcl.sync();                       // 캐시 복원 → 델타
  assert.equal(a.mode, 'restore');
  const before = calls.length;
  await publish([16n]);
  const b = await rcl.sync();
  assert.equal(b.mode, 'delta');
  const d = calls.slice(before);
  assert.equal(d.length, 1, 'getLogs 1회');
  assert.equal(d[0].fromBlock, Number(a.head) + 1);
  assert.equal(d[0].toBlock, Number(b.head));
  const c = await rcl.sync();                       // 블록이 안 늘었다
  assert.equal(c.head, b.head);
  assert.equal(calls.length, before + 1, '같은 head 재조회 없음');
  p.destroy();
});

// 3. 하트비트
await t('리프가 빈 Revoked(하트비트)는 델타 0·epoch 갱신·캐시 파일 미변경', async () => {
  const rcl = createRevocationSync({ provider, logAddress, cacheFile, log: warn });
  const a = await rcl.sync();
  const mtime = fs.statSync(cacheFile).mtimeMs;
  await new Promise((r) => setTimeout(r, 20));
  await publish([]);                                // 같은 root, epoch+1
  const b = await rcl.sync();
  assert.equal(b.mode, 'delta');
  assert.equal(b.root, a.root);
  assert.equal(b.epoch, a.epoch + 1n);
  assert.equal(rcl.stats().leaves, 6);
  assert.equal(fs.statSync(cacheFile).mtimeMs, mtime, '리프가 없으면 쓰지 않는다');
});

// 4. 복원
await t('새 인스턴스는 캐시에서 복원하고 캐시의 lastSyncedBlock+1 부터만 훑는다', async () => {
  const c0 = readCache();
  const { p, calls } = spyProvider();
  const rcl = createRevocationSync({ provider: p, logAddress, cacheFile, log: warn });
  const a = await rcl.sync();
  assert.equal(a.mode, 'restore');
  assert.equal(a.root, (await syncRevocationTree(provider, logAddress)).root);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].fromBlock, Number(c0.lastSyncedBlock) + 1);
  p.destroy();
});

// 5. 캐시 무효 세 가지
await t('logAddress 불일치·JSON 손상·version 불일치 캐시는 경고 후 부트스트랩', async () => {
  const good = readCache();
  for (const bad of [
    { ...good, logAddress: ethers.ZeroAddress },
    'not json {',
    { ...good, version: RCL_CACHE_VERSION + 1 },
  ]) {
    fs.writeFileSync(cacheFile, typeof bad === 'string' ? bad : JSON.stringify(bad));
    warnings.length = 0;
    const rcl = createRevocationSync({ provider, logAddress, cacheFile, log: warn });
    const r = await rcl.sync();
    assert.equal(r.mode, 'bootstrap');
    assert.equal(warnings.length, 1, `경고 1회: ${warnings.join(' | ')}`);
    assert.equal(r.root, (await syncRevocationTree(provider, logAddress)).root);
  }
  assert.deepEqual(readCache().leaves, good.leaves, '부트스트랩이 올바른 캐시를 다시 쓴다');
});

// 6. 델타 불일치 → fallback
await t('복원은 통과하지만 델타 뒤 컨트랙트 root 와 어긋나면 전체 재생 1회로 복구한다', async () => {
  const good = readCache();
  // 리프 하나를 바꾸고 그 리프들로 만든 root 를 함께 적어 복원 검사(파일 root == 복원 root)는 통과시킨다
  const forged = [...good.leaves]; forged[0] = '4242';
  const ft = await createRevocationTree();
  for (const v of forged) await ft.insert(BigInt(v));
  fs.writeFileSync(cacheFile, JSON.stringify({ ...good, leaves: forged, root: ft.getRoot().toString() }));
  warnings.length = 0;
  const rcl = createRevocationSync({ provider, logAddress, cacheFile, log: warn });
  const r = await rcl.sync();
  assert.equal(r.mode, 'fallback');
  assert.equal(r.root, (await syncRevocationTree(provider, logAddress)).root);
  assert.ok(r.tree.has(11n) && !r.tree.has(4242n));
  assert.equal(warnings.length, 1, warnings.join(' | '));
  assert.deepEqual(readCache().leaves, good.leaves, 'fallback 이 올바른 캐시를 다시 쓴다');
});

// 7. fail-closed (+ I2: throw 뒤 오염된 트리로 delta 를 돌려주지 않는다 — bootstrap() 의 `tree = null` 선행 불변식)
await t('전체 재생도 컨트랙트 root 와 다르면 throw 하고 캐시는 건드리지 않는다; 거짓말이 끝난 뒤 같은 인스턴스로 재시도하면 깨끗이 부트스트랩된다', async () => {
  const before = fs.readFileSync(cacheFile, 'utf8');
  // 캐시가 유효한 상태에서 시작 → 첫 sync() 는 복원(tree 비-null) 뒤 top-level root() 거짓말로 불일치를 만나
  // bootstrap('fallback') 으로 빠지고, 거기서 syncRevocationTree 내부의 두 번째 root() 도 거짓말이라 throw 한다.
  // 딱 2번만 거짓말하도록 세어, 그 뒤(재시도)는 같은 provider 인스턴스가 정직해지게 한다.
  const p = lyingRootProvider(777777n, 2);
  const rcl = createRevocationSync({ provider: p, logAddress, cacheFile, log: warn });
  await assert.rejects(() => rcl.sync(), /root/);
  assert.equal(fs.readFileSync(cacheFile, 'utf8'), before, '실패한 시도는 캐시를 건드리지 않는다');
  // I2: bootstrap() 이 await 전에 tree 를 null 로 되돌리지 않으면(퇴행), 다음 sync() 가 이 tree===null 분기를
  // 건너뛰어 "복원됐던(하지만 검증되지 않은) 트리"로 그냥 delta 를 계산해버린다 — mode 가 'bootstrap' 대신
  // 'delta' 로 나오는 것이 그 신호다. 이 분기가 실제로 taken 되도록 캐시를 지워 강제한다(readCache()==null).
  fs.rmSync(cacheFile, { force: true });
  const r = await rcl.sync();                          // 이제 provider 는 정직하다(거짓말 2회 소진)
  assert.equal(r.mode, 'bootstrap', 'throw 후 tree 가 null 로 되돌아갔어야 다음 sync 가 부트스트랩을 taken 한다');
  assert.equal(r.root, (await syncRevocationTree(provider, logAddress)).root);
  p.destroy();
});

// 8. 동시성
await t('동시 sync() 3개는 같은 tree 객체·같은 head 를 받고 getLogs 는 1회', async () => {
  const { p, calls } = spyProvider();
  const rcl = createRevocationSync({ provider: p, logAddress, cacheFile, log: warn });
  await rcl.sync();                                 // restore
  await publish([17n]);
  const n = calls.length;
  const [a, b, c] = await Promise.all([rcl.sync(), rcl.sync(), rcl.sync()]);
  assert.ok(a.tree === b.tree && b.tree === c.tree);
  assert.equal(a.head, b.head); assert.equal(b.head, c.head);
  assert.equal(calls.length, n + 1);
  p.destroy();
});

// 9. 체인 리셋
await t('캐시의 lastSyncedBlock 이 head 보다 크면 경고 후 부트스트랩', async () => {
  const good = readCache();
  fs.writeFileSync(cacheFile, JSON.stringify({ ...good, lastSyncedBlock: String(Number(good.lastSyncedBlock) + 100000) }));
  warnings.length = 0;
  const rcl = createRevocationSync({ provider, logAddress, cacheFile, log: warn });
  const r = await rcl.sync();
  assert.equal(r.mode, 'bootstrap');
  assert.equal(warnings.length, 1, warnings.join(' | '));
});

// reset() vs 진행 중인 sync() — I1
await t('진행 중인 sync() 와 겹치는 reset() 은 그 sync() 를 깨지 않고, 완료된 뒤에만 효력이 있다', async () => {
  const rcl = createRevocationSync({ provider, logAddress, cacheFile, log: warn });
  await rcl.sync();                                    // tree·lastSyncedBlock 을 먼저 확립한다(복원 또는 부트스트랩)
  await publish([18n]);                                 // 델타가 실제로 있어야 다음 sync() 가 lastSyncedBlock+1n 을 밟는다
  const p = rcl.sync();
  rcl.reset();                                           // in-flight 도중 — 수정 전이면 즉시 tree=null 로 지워 재개한 run() 의 tree.insert()/getRoot() 가 null 역참조로 깨진다
  const r = await p;
  assert.equal(r.root, (await syncRevocationTree(provider, logAddress)).root);
  assert.ok(!fs.existsSync(cacheFile), 'in-flight 종료 후 지연된 reset 이 캐시를 지운다');
  assert.equal(rcl.stats().leaves, 0);
  assert.equal((await rcl.sync()).mode, 'bootstrap');
});

// reset()
await t('reset() 은 캐시 파일을 지우고 다음 sync 는 부트스트랩', async () => {
  const rcl = createRevocationSync({ provider, logAddress, cacheFile, log: warn });
  await rcl.sync();
  rcl.reset();
  assert.ok(!fs.existsSync(cacheFile));
  assert.equal(rcl.stats().leaves, 0);
  assert.equal((await rcl.sync()).mode, 'bootstrap');
});

provider.destroy();
fs.rmSync(dir, { recursive: true, force: true });
process.exit(failed === 0 ? 0 : 1);
