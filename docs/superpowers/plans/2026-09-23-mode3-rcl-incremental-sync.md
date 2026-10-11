# Mode 3 RCL 증분 동기화(체크포인트+델타) 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 지갑 에이전트가 로그인·재검증·트랜잭션마다 창세기부터 `Revoked` 이벤트를 재생하던 것을, 메모리 IMT + 별도 캐시 파일에 `lastSyncedBlock` 이후 델타만 적용하는 방식으로 바꾼다. 검증 의미(root 대조·fail-closed)와 반환 형태는 그대로.

**Architecture:** (1) `lib/mode3_rcl_sync.js` 의 `createRevocationSync()` 가 메모리 트리·캐시 파일·in-flight 공유를 맡고, 기존 `syncRevocationTree()` 를 "전체 재생" 원시 연산으로 부른다(부트스트랩·fallback). (2) 에이전트는 이 객체 하나를 만들어 세 호출부에서 `rcl.sync()` 를 부른다. (3) 트리를 공유하면 생기는 경합을 없애기 위해 `buildCredentialProof` 는 증인의 `w.root` 를 공개 입력으로 쓰고, `proveSession` 은 증명의 `revRoot` 를 응답·캐시 키로 쓴다. (4) 회로·컨트랙트·CIA·서비스는 바뀌지 않는다.

**Tech Stack:** Node 22 ESM, ethers v6(`JsonRpcProvider`, `Contract.queryFilter`), IMT v2(`lib/imt_v2.js`), hardhat :8545(테스트·벤치).

**Spec:** `docs/superpowers/specs/2026-09-23-mode3-rcl-incremental-sync-design.md` (이하 "스펙").

## Global Constraints

- `syncRevocationTree(provider, logAddress)` 의 시그니처·동작·반환 `{ tree, root, epoch, head }` 는 바꾸지 않는다. 기존 7개 테스트(`test_mode3_wallet/e2e/rp/demo_stack/cia_register_issue/cia_startup/cia_opening`)는 수정 없이 통과해야 한다.
- 지갑 상태 파일 `mode3_wallet_state.json` 의 `WALLET_STATE_VERSION` 은 **7 그대로**. 캐시는 별도 파일 `mode3_wallet_rcl.json`(환경변수 `MODE3_WALLET_RCL_CACHE`, 기본값 = 상태 파일과 같은 디렉터리). 캐시에는 리프(공개 값)만 — 비밀은 절대 없다.
- 캐시 파일 형식(스펙 §4): `{ version: 1, logAddress, chainId, lastSyncedBlock, epoch, root, leaves: [10진 문자열…] }`. 리프는 삽입 순서, anchor(값 0) 제외. 유효 조건 하나라도 틀리면 경고 후 부트스트랩.
- 델타 root ≠ 컨트랙트 root → 경고 1줄 → 전체 재생 **1회** → 그래도 다르면 `syncRevocationTree` 가 throw(재시도 루프 없음).
- 캐시 쓰기는 리프가 새로 붙었을 때와 부트스트랩 뒤에만. 원자적(`writeJsonAtomic`). 쓰기 실패는 경고만.
- 동시 `sync()` 는 진행 중인 promise 하나를 공유한다(스펙 §5).
- `buildCredentialProof` 의 `revRoot`(공개 입력·반환)는 `w.root`. `proveSession` 의 응답 `root` 와 캐시 키는 증명의 `revRoot`(스펙 §5).
- 회로·컨트랙트·`cia.js`·`mode3_rp.js`·Mode 2 파일 수정 금지. `npm run zk:*` 금지. 상태·키 파일(`mode3_wallet_state.json`, `cia_state.json`, `*_keys.json`, `.env`) 읽기·삭제 금지.
- 새 테스트는 `scripts/run_tests.sh` 의 **CHAIN** 그룹에 넣는다(hardhat :8545 만 필요). hardhat 노드는 세션이 띄운 것을 쓰고 끄지 않는다.
- 모든 주석·커밋 메시지·문서 한글. 커밋 트레일러 2줄: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`, `Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN`.
- 기존 결과 파일(`results/*.md`)은 덮어쓰지 않는다 — 벤치는 새 파일 `results/mode3_rcl_sync_<YYYYMMDD>.md`.

---

## 파일 구조

| 파일 | 책임 | Task |
|---|---|---|
| `lib/mode3_wallet.js` | `buildCredentialProof` 의 `revRoot` 를 `w.root` 로 | 1 |
| `tests/test_mode3_wallet.mjs` | 증인 root == 공개 입력 root 단언 1건 추가 | 1 |
| `lib/mode3_rcl_sync.js` (신규) | `createRevocationSync({ provider, logAddress, cacheFile, log })` → `{ sync, stats, reset }` | 2 |
| `tests/test_mode3_rcl_sync.mjs` (신규) | 스펙 §6 1~9 | 2 |
| `scripts/run_tests.sh`, `.gitignore` | CHAIN 등록, `mode3_wallet_rcl.json` 무시 | 2 |
| `mode3_wallet_agent.js` | `rcl` 하나 생성, 세 호출부 교체, `proveSession` root 출처, `/wallet/status.rcl`, `POST /wallet/rcl/reset` | 3 |
| `tests/test_mode3_wallet_agent.mjs` | 재시작 → `restore` → 재검증 성공, `/wallet/rcl/reset` → 다음 로그인 `bootstrap` | 3 |
| `scripts/bench_mode3_rcl_sync.mjs` (신규), `results/mode3_rcl_sync_<YYYYMMDD>.md` (신규) | 스펙 §7 | 4 |
| `docs/MODE3_DEMO.md`, 스펙 §9 | 운영 메모·테스트 절, 결정 기록 | 4 |

---

### Task 1: `buildCredentialProof` 의 root 를 증인에 고정 (동작 불변 정정)

**Files:**
- Modify: `lib/mode3_wallet.js:171-190` (`buildCredentialProof`)
- Test: `tests/test_mode3_wallet.mjs`

**Interfaces:**
- Consumes: `tree.getNonMembershipWitness(leaf)` 가 `{ …, root: string }` 을 돌려준다(`lib/imt_v2.js:324-347`).
- Produces: `buildCredentialProof(...)` 반환 `{ proof, publicSignals, revRoot: bigint, tag }` — `revRoot` 는 이제 증인의 root(호출 시점 `tree.getRoot()` 와 단일 스레드에서는 같은 값). 시그니처 불변.

배경: 지금은 증인을 받은 뒤 `encryptTag` 를 `await` 하고 `tree.getRoot()` 를 다시 읽는다(스펙 §5). 트리를 공유하기 전에 먼저 고정한다 — 이 태스크만으로는 관찰 가능한 동작 변화가 없어야 한다.

- [ ] **Step 1: 실패하는 테스트 — 증인 뒤에 트리가 바뀌어도 증명의 root 는 증인 root**

`tests/test_mode3_wallet.mjs` 의 `ProofCache` 테스트 앞(파일 끝 `provider.destroy()` 앞)에 추가. 이 파일은 이미 `tree`·`credential`·증명 픽스처를 만드는 테스트가 있으므로, 가장 가까운 "증명 생성" 테스트가 쓰는 변수 이름을 그대로 쓴다(파일을 읽고 그 테스트의 `buildCredentialProof` 호출 인자 객체를 복사한다). 핵심은 **`getNonMembershipWitness` 를 감싸 증인을 돌려준 직후 트리에 리프를 하나 넣는** 것이다:

```js
await t('증인을 만든 뒤 트리가 바뀌어도 증명의 revRoot 는 증인 root 다 (스펙 §5)', async () => {
  const { tree } = await syncRevocationTree(provider, logAddress);
  const rootBefore = tree.getRoot();
  const orig = tree.getNonMembershipWitness.bind(tree);
  let witnessRoot = null;
  tree.getNonMembershipWitness = async (target) => {
    const w = await orig(target);
    witnessRoot = BigInt(w.root);
    await tree.insert(999_999_999n);            // 다른 요청의 sync() 가 끼어든 상황을 흉내
    return w;
  };
  const out = await buildCredentialProof({ /* 위 증명 테스트의 인자 객체를 그대로 복사, tree 만 이 tree */ });
  assert.equal(witnessRoot, rootBefore);
  assert.equal(out.revRoot, rootBefore, '증인 root 여야 한다');
  assert.notEqual(tree.getRoot(), rootBefore, '트리는 실제로 바뀌었다');
  // 공개 입력의 revRoot 자리도 같은 값이어야 한다(publicSignals 배열에서 revRoot 의 인덱스는 lib/mode3_wallet.js 의 공개 입력 순서 주석 참고)
});
```

`publicSignals` 의 revRoot 인덱스는 `lib/mode3_wallet.js` 의 "§5 — 공개 입력 순서 [PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, …]" 주석대로 **6** 이다: `assert.equal(BigInt(out.publicSignals[6]), rootBefore)`.

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_wallet.mjs 2>&1 | grep -A2 "증인을 만든 뒤"`
Expected: `FAIL … 증인 root 여야 한다` (지금은 `tree.getRoot()` 를 다시 읽어 바뀐 root 가 나오고, 그 root 로는 증인이 맞지 않아 `fullProve` 가 먼저 throw 할 수도 있다 — 어느 쪽이든 FAIL).

- [ ] **Step 3: 구현**

`lib/mode3_wallet.js` `buildCredentialProof` 에서:

```js
  const w = await tree.getNonMembershipWitness(await userLeaf(BigInt(credential.Cf_u)));
  // 공개 입력 root 는 증인이 계산된 root 로 고정한다. 트리 객체를 여러 요청이 공유하면(증분 동기화, 스펙 §5)
  // 이 아래의 await 사이에 다른 요청의 insert 가 끼어들 수 있고, 그때 tree.getRoot() 를 다시 읽으면
  // 증인과 어긋난 root 로 증명을 만들게 된다.
  const revRoot = BigInt(w.root);
```

그리고 `input` 의 `revRoot: tree.getRoot().toString()` → `revRoot: revRoot.toString()`, 반환의 `revRoot: tree.getRoot()` → `revRoot`.

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_wallet.mjs`
Expected: 새 케이스 `ok`, 기존 케이스 전부 `ok`, 종료 코드 0.

- [ ] **Step 5: 커밋**

```bash
git add lib/mode3_wallet.js tests/test_mode3_wallet.mjs
git commit -m "fix(mode3): buildCredentialProof 의 revRoot 를 증인 root 로 고정 (트리 공유 대비, 스펙 §5)"
```

---

### Task 2: `lib/mode3_rcl_sync.js` — 체크포인트+델타 동기화 모듈과 테스트

**Files:**
- Create: `lib/mode3_rcl_sync.js`
- Create: `tests/test_mode3_rcl_sync.mjs`
- Modify: `scripts/run_tests.sh` (CHAIN 배열에 `tests/test_mode3_rcl_sync.mjs` — `tests/test_mode3_wallet.mjs` 바로 뒤), `.gitignore` (`mode3_wallet_state.json` 다음 줄에 `mode3_wallet_rcl.json`)

**Interfaces:**
- Consumes: `syncRevocationTree(provider, logAddress)` (`lib/mode3_wallet.js`), `createRevocationTree()` (`lib/mode3_revocation.js`), `LOG_ABI` (`lib/mode3_log.js`), `readJson`/`writeJsonAtomic` (`lib/mode3_state.js`), IMT `insert/getRoot/getLeaves/has`.
- Produces:
  ```js
  export const RCL_CACHE_VERSION = 1;
  export function createRevocationSync({ provider, logAddress, cacheFile, log = console.warn })
  // → {
  //   sync():  Promise<{ tree, root: bigint, epoch: bigint, head: bigint, mode: 'delta'|'restore'|'bootstrap'|'fallback' }>
  //   stats(): { leaves: number, lastSyncedBlock: bigint|null, lastMode: string|null, cacheFile: string }
  //   reset(): void   // 메모리 트리 폐기 + 캐시 파일 삭제(없으면 무시)
  // }
  ```
  `mode` 는 이번 `sync()` 가 어떤 경로였는지: `restore` 는 "캐시에서 복원한 뒤 델타 적용"(첫 호출), `bootstrap` 은 캐시 없음/무효/체인 리셋으로 전체 재생, `fallback` 은 델타 root 불일치로 전체 재생, `delta` 는 그 밖(리프 0개 포함).

- [ ] **Step 1: 테스트 파일 골격과 헬퍼**

`tests/test_mode3_rcl_sync.mjs`:

```js
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
function lyingRootProvider(fakeRootBig) {
  const p = getProvider();
  const orig = p.send.bind(p);
  p.send = async (method, params) => {
    if (method === 'eth_call' && String(params[0]?.data ?? '').startsWith('0xebf0c717')) return rootToBytes32(fakeRootBig);
    return orig(method, params);
  };
  return p;
}

const readCache = () => JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
```

- [ ] **Step 2: 테스트 1~9 (스펙 §6) 작성**

이어서:

```js
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
    { ...good, version: 0 },
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

// 7. fail-closed
await t('전체 재생도 컨트랙트 root 와 다르면 throw 하고 캐시는 건드리지 않는다', async () => {
  const before = fs.readFileSync(cacheFile, 'utf8');
  const p = lyingRootProvider(777777n);
  const rcl = createRevocationSync({ provider: p, logAddress, cacheFile, log: warn });
  await assert.rejects(() => rcl.sync(), /root/);
  assert.equal(fs.readFileSync(cacheFile, 'utf8'), before);
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
```

- [ ] **Step 3: 실패 확인**

Run: `node tests/test_mode3_rcl_sync.mjs`
Expected: import 단계에서 `Cannot find module '../lib/mode3_rcl_sync.js'` 로 즉시 실패.

- [ ] **Step 4: 모듈 구현**

`lib/mode3_rcl_sync.js`:

```js
// Mode 3 지갑의 폐기 트리(RCL) 증분 동기화 — 체크포인트(캐시 파일) + 델타(lastSyncedBlock 이후 Revoked 이벤트).
// 설계: docs/superpowers/specs/2026-09-23-mode3-rcl-incremental-sync-design.md
//
// syncRevocationTree()(창세기부터 전체 재생, fail-closed)는 그대로 두고 여기서 "전체 재생" 원시 연산으로 쓴다.
// 검증 의미는 같다: 델타를 적용한 root 가 head 블록의 컨트랙트 root 와 다르면 전체 재생으로 한 번 복구하고,
// 그래도 다르면 syncRevocationTree 가 throw 한다. 캐시는 정확성에 관여하지 않는다 — 지워도, 손상돼도 느려질 뿐이다.
import fs from 'node:fs';
import { ethers } from 'ethers';
import { LOG_ABI } from './mode3_log.js';
import { createRevocationTree } from './mode3_revocation.js';
import { syncRevocationTree } from './mode3_wallet.js';
import { readJson, writeJsonAtomic } from './mode3_state.js';

export const RCL_CACHE_VERSION = 1;

const isDec = (s) => typeof s === 'string' && /^[0-9]+$/.test(s);

export function createRevocationSync({ provider, logAddress, cacheFile, log = console.warn }) {
  if (!logAddress) throw new Error('createRevocationSync: logAddress 가 필요하다');
  if (!cacheFile) throw new Error('createRevocationSync: cacheFile 이 필요하다');
  const contract = new ethers.Contract(logAddress, LOG_ABI, provider);
  let tree = null;                 // 메모리 IMT. null 이면 다음 sync 가 복원 또는 부트스트랩
  let lastSyncedBlock = null;      // bigint
  let lastMode = null;
  let chainId = null;              // 한 번만 읽는다
  let inFlight = null;

  const leavesOf = (tr) => tr.getLeaves().slice(1).map((l) => l.value.toString());   // [0] 은 anchor

  function writeCache(root, epoch) {
    try {
      writeJsonAtomic(cacheFile, {
        version: RCL_CACHE_VERSION, logAddress, chainId: chainId.toString(),
        lastSyncedBlock: lastSyncedBlock.toString(), epoch: epoch.toString(), root: root.toString(), leaves: leavesOf(tree),
      }, 0o644);   // 공개 데이터 — 상태 파일(0o600)과 달리 비밀이 없다
    } catch (e) {
      log(`[rcl] 캐시 쓰기 실패(무시): ${e.message}`);
    }
  }

  /** 캐시 파일을 읽어 유효하면 { leaves: bigint[], lastSyncedBlock: bigint, root: bigint } 를, 아니면 null 을(경고 1줄) */
  function readCache() {
    if (!fs.existsSync(cacheFile)) return null;
    let c;
    try { c = readJson(cacheFile, null); } catch (e) { log(`[rcl] 캐시 손상(무시, 전체 재생): ${e.message}`); return null; }
    const bad =
      !c || typeof c !== 'object' ? '형식' :
      c.version !== RCL_CACHE_VERSION ? `version ${c.version}` :
      String(c.logAddress ?? '').toLowerCase() !== logAddress.toLowerCase() ? `logAddress ${c.logAddress}` :
      String(c.chainId) !== chainId.toString() ? `chainId ${c.chainId}` :
      !isDec(c.lastSyncedBlock) ? 'lastSyncedBlock' :
      !isDec(c.root) ? 'root' :
      !Array.isArray(c.leaves) || !c.leaves.every(isDec) ? 'leaves' : null;
    if (bad) { log(`[rcl] 캐시 무효(${bad}) — 무시하고 전체 재생`); return null; }
    return { leaves: c.leaves.map(BigInt), lastSyncedBlock: BigInt(c.lastSyncedBlock), root: BigInt(c.root) };
  }

  async function bootstrap(mode) {
    tree = null;
    const full = await syncRevocationTree(provider, logAddress);   // root 불일치면 여기서 throw (fail-closed)
    tree = full.tree;
    lastSyncedBlock = full.head;
    lastMode = mode;
    writeCache(full.root, full.epoch);
    return { tree, root: full.root, epoch: full.epoch, head: full.head, mode };
  }

  async function run() {
    if (chainId === null) chainId = (await provider.getNetwork()).chainId;
    const head = BigInt(await provider.getBlockNumber());
    const blockTag = Number(head);
    const [onchainRoot, epoch] = await Promise.all([contract.root({ blockTag }), contract.epoch({ blockTag })]);

    let mode = 'delta';
    if (tree === null) {
      const c = readCache();
      if (!c) return bootstrap('bootstrap');
      const restored = await createRevocationTree();
      for (const v of c.leaves) await restored.insert(v);
      if (restored.getRoot() !== c.root) { log('[rcl] 캐시의 root 가 리프와 맞지 않는다(손상) — 전체 재생'); return bootstrap('bootstrap'); }
      tree = restored;
      lastSyncedBlock = c.lastSyncedBlock;
      mode = 'restore';
    }

    if (head < lastSyncedBlock) {
      log(`[rcl] head(${head}) < lastSyncedBlock(${lastSyncedBlock}) — 체인이 되감겼다. 전체 재생`);
      return bootstrap('bootstrap');
    }

    let appended = 0;
    if (head > lastSyncedBlock) {
      const events = await contract.queryFilter(contract.filters.Revoked(), Number(lastSyncedBlock + 1n), blockTag);
      for (const e of events) for (const l of e.args.leaves) { if (await tree.insert(BigInt(l))) appended++; }
    }

    const root = tree.getRoot();
    if (root !== BigInt(onchainRoot)) {
      log(`[rcl] 델타 적용 root(${root}) ≠ 컨트랙트 root(${BigInt(onchainRoot)}) — 전체 재생으로 복구`);
      return bootstrap('fallback');
    }
    lastSyncedBlock = head;
    lastMode = mode;
    if (appended > 0) writeCache(root, epoch);
    return { tree, root, epoch, head, mode };
  }

  return {
    sync() {
      if (inFlight) return inFlight;
      inFlight = run().finally(() => { inFlight = null; });
      return inFlight;
    },
    stats() {
      return { leaves: tree ? tree.size() - 1 : 0, lastSyncedBlock, lastMode, cacheFile };
    },
    reset() {
      tree = null; lastSyncedBlock = null; lastMode = null;
      try { fs.rmSync(cacheFile, { force: true }); } catch (e) { log(`[rcl] 캐시 삭제 실패(무시): ${e.message}`); }
    },
  };
}
```

주의: `tree.size()` 는 anchor 포함 개수라 `-1`. `insert` 는 이미 있는 값이면 `false` 를 돌려주므로 `appended` 는 실제 새 리프 수다.

`writeJsonAtomic` 의 세 번째 인자(mode)는 `lib/mode3_state.js:13` 시그니처대로 `0o644` 를 넘긴다 — 캐시는 공개 데이터라 상태 파일의 0o600 을 쓸 이유가 없다(다른 도구가 읽어도 된다). 기본값(0o600)을 그대로 두어도 틀리지는 않는다.

- [ ] **Step 5: 통과 확인**

Run: `node tests/test_mode3_rcl_sync.mjs`
Expected: 10개 전부 `ok`, 종료 코드 0. 실패하면 메시지대로 고친다 — 흔한 함정: (a) 테스트 2·4 의 `fromBlock` 비교는 `a.head+1`/캐시 `lastSyncedBlock+1` 이어야 하는데, 테스트 3 의 하트비트 뒤 `lastSyncedBlock` 이 메모리에선 갱신됐지만 파일에는 안 써졌으므로 테스트 4 는 **파일 값** 기준이 맞다(의도된 동작). (b) 테스트 5 의 `warnings.length === 1` — `readCache` 가 경고 1줄만 내야 한다(손상 JSON 은 `readJson` 이 throw → catch 에서 1줄).

- [ ] **Step 6: 그룹 등록·gitignore**

`scripts/run_tests.sh` CHAIN 배열의 `tests/test_mode3_wallet.mjs` 다음 줄에 `tests/test_mode3_rcl_sync.mjs`. `.gitignore` 의 `mode3_wallet_state.json` 다음 줄에 `mode3_wallet_rcl.json`.

Run: `bash -n scripts/run_tests.sh && grep -n "rcl" scripts/run_tests.sh .gitignore`
Expected: 두 파일에 한 줄씩.

- [ ] **Step 7: 기존 지갑 테스트 회귀 확인**

Run: `node tests/test_mode3_wallet.mjs`
Expected: 전부 `ok`(이 태스크는 `lib/mode3_wallet.js` 를 건드리지 않았으므로 당연히 통과해야 한다 — 확인만).

- [ ] **Step 8: 커밋**

```bash
git add lib/mode3_rcl_sync.js tests/test_mode3_rcl_sync.mjs scripts/run_tests.sh .gitignore
git commit -m "feat(mode3): RCL 증분 동기화 모듈 createRevocationSync — 캐시 파일 복원·델타·불일치 시 전체 재생 1회·in-flight 공유"
```

---

### Task 3: 에이전트 배선 — `rcl.sync()`, `proveSession` root 출처, `/wallet/status.rcl`, `POST /wallet/rcl/reset`

**Files:**
- Modify: `mode3_wallet_agent.js` (import, 상수 `RCL_CACHE_FILE`, `rcl` 생성, 호출부 `:331`·`:460`·`:558`, `proveSession :413-445`, `/wallet/status :234-250`, 새 라우트)
- Test: `tests/test_mode3_wallet_agent.mjs`

**Interfaces:**
- Consumes: `createRevocationSync({ provider, logAddress, cacheFile, log })` → `{ sync, stats, reset }` (Task 2); `buildCredentialProof` 반환의 `revRoot: bigint` (Task 1).
- Produces: `GET /wallet/status` 응답에 `rcl: { leaves, lastSyncedBlock: string|null, lastMode: string|null, cacheFile }`; `POST /wallet/rcl/reset`(같은 오리진, CORS 없음, 본문 없음) → `200 { ok: true }`. 환경변수 `MODE3_WALLET_RCL_CACHE`.

- [ ] **Step 1: 실패하는 테스트 2건**

`tests/test_mode3_wallet_agent.mjs` 에서 로그인·재검증이 성공한 뒤(파일의 기존 로그인 테스트 다음, 마지막 정리 앞)에 추가. 이 파일은 `stack = startIsolatedMode3Stack({ rp:false, … })` 를 쓰고 `stack.restartWallet()` 가 있다(`tests/helpers/isolated_mode3_stack.mjs`). 로그인 테스트가 만든 `r_s` 변수 이름은 파일을 읽고 맞춘다(아래에서는 `rs` 로 표기).

```js
await t('첫 로그인 뒤 상태의 rcl 은 bootstrap, 재시작 뒤 재검증은 restore 로 통과한다 (스펙 §3·§6)', async () => {
  const s1 = (await wallet.get('/wallet/status')).body;
  assert.equal(s1.rcl.lastMode, 'bootstrap');
  assert.ok(fs.existsSync(s1.rcl.cacheFile), `캐시 파일이 있어야 한다: ${s1.rcl.cacheFile}`);
  const leavesBefore = s1.rcl.leaves;
  await stack.restartWallet();
  const r = await wallet.post('/wallet/revalidate', { r_s: rs });
  assert.equal(r.status, 200, j(r.body));
  const s2 = (await wallet.get('/wallet/status')).body;
  assert.equal(s2.rcl.lastMode, 'restore');
  assert.equal(s2.rcl.leaves, leavesBefore);
});

await t('POST /wallet/rcl/reset 은 캐시를 지우고 다음 재검증이 bootstrap 으로 돈다', async () => {
  const before = (await wallet.get('/wallet/status')).body.rcl.cacheFile;
  const r = await wallet.post('/wallet/rcl/reset', {});
  assert.equal(r.status, 200, j(r.body));
  assert.ok(!fs.existsSync(before));
  const v = await wallet.post('/wallet/revalidate', { r_s: rs });
  assert.equal(v.status, 200, j(v.body));
  assert.equal((await wallet.get('/wallet/status')).body.rcl.lastMode, 'bootstrap');
});
```

`file` 모드(기본)라 재시작 뒤 `needs_consent` 는 나오지 않는다. 재검증 응답의 `root` 는 증명의 `revRoot` 여야 하므로, 기존 재검증 테스트 중 `root` 를 비교하는 곳이 있으면 그대로 통과해야 한다(값은 같다 — 단일 요청에서는 `synced.root === revRoot`).

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_wallet_agent.mjs 2>&1 | grep -E "^(ok|FAIL)" | tail -4`
Expected: 두 새 케이스 `FAIL`(`s1.rcl` 가 undefined / `/wallet/rcl/reset` 404).

- [ ] **Step 3: 에이전트 구현**

(a) import·상수:

```js
import { createRevocationSync } from './lib/mode3_rcl_sync.js';
// …STATE_FILE 정의 뒤:
// 폐기 트리 체크포인트(공개 데이터만). 지우면 다음 동기화가 창세기부터 재생한다(스펙 2026-09-23 §4).
const RCL_CACHE_FILE = process.env.MODE3_WALLET_RCL_CACHE || path.join(path.dirname(STATE_FILE), 'mode3_wallet_rcl.json');
```

(b) `lastSync` 선언(`:82`) 근처에, `provider`·`LOG_ADDRESS` 가 정의된 뒤:

```js
// 증분 동기화 객체. LOG_ADDRESS 가 없으면 null — 그 경우 세 라우트는 지금처럼 chain_unavailable 을 낸다.
const rcl = LOG_ADDRESS ? createRevocationSync({ provider, logAddress: LOG_ADDRESS, cacheFile: RCL_CACHE_FILE, log: (m) => console.warn(`[wallet] ${m}`) }) : null;
async function syncTree() {
  if (!rcl) throw new Error('CIA_LOG_ADDRESS not configured');
  return rcl.sync();
}
```

(c) 세 호출부(`:331`, `:460`, `:558`)의 `await syncRevocationTree(provider, LOG_ADDRESS)` → `await syncTree()`. `lastSync = { root: synced.root.toString(), head: …, tree: synced.tree }` 줄은 그대로(`/wallet/status.userCred.revoked` 와 `skipSync` 경로가 쓴다). import 목록에서 `syncRevocationTree` 가 더 이상 쓰이지 않으면 제거한다.

(d) `proveSession`(`:413-445`): 캐시 키와 응답 root 를 증명의 root 로.

```js
  let cached = cache.get(synced.root, rsKey, discKey);
  const cacheHit = Boolean(cached);
  if (!cached) {
    …(기존 revoked 사전 검사 두 줄은 synced.tree 로 그대로)…
    cached = await buildCredentialProof({ … tree: synced.tree, disclosure });
    timings.proveMs = Date.now() - t;
    // 증명은 증인이 계산된 root(cached.revRoot)에 대한 것이다. 동기화와 증인 생성 사이에 다른 요청이 리프를 붙였다면
    // synced.root 보다 새 root 이고, 그 root 로 캐시해야 다음 재검증이 맞는 π 를 찾는다(스펙 §5).
    cache.set(cached.revRoot, rsKey, cached, discKey);
    if (cached.revRoot !== synced.root) cache.set(synced.root, rsKey, cached, discKey);   // 이번 sync 의 root 로 찾는 호출도 맞춰 준다
  }
  const root = (cached.revRoot ?? synced.root).toString();
  const sig = await signChallenge(sessionWallet, rsKey);
  return { proof: cached.proof, publicSignals: cached.publicSignals, sig, pk_i: s.pk_i, r_s: rsKey, root, cacheHit, allowAgent: s.allowAgent, max_height: s.credential.max_height };
```

`ProofCache` 에 저장되는 객체는 `buildCredentialProof` 의 반환값 전체(`proof, publicSignals, revRoot, tag`)이므로 `cached.revRoot` 를 읽을 수 있다. 캐시 히트 경로에서 `cached.revRoot` 가 없을 일은 없지만 `?? synced.root` 로 방어한다.

(e) `/wallet/status` 응답에 추가:

```js
  const st = rcl ? rcl.stats() : null;
  res.json({
    …기존 필드…,
    rcl: st ? { leaves: st.leaves, lastSyncedBlock: st.lastSyncedBlock === null ? null : st.lastSyncedBlock.toString(), lastMode: st.lastMode, cacheFile: st.cacheFile } : null,
  });
```

(f) 새 라우트(`/wallet/self_revoke` 옆, CORS 없음):

```js
// 운영·시연용: 폐기 트리 체크포인트를 버린다. 다음 동기화가 창세기부터 재생한다(스펙 §8). 같은 오리진만.
app.post('/wallet/rcl/reset', (req, res) => {
  if (!rcl) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
  rcl.reset();
  res.json({ ok: true });
});
```

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_wallet_agent.mjs`
Expected: 새 2건 포함 전부 `ok`, 종료 코드 0.

- [ ] **Step 5: 에이전트를 지나는 다른 chain 테스트**

Run: `node tests/test_mode3_e2e.mjs && node tests/test_mode3_demo_stack.mjs && node tests/test_mode3_wallet_snap.mjs`
Expected: 전부 통과. 데모 스택 시나리오 중 "재검증 stale_root(skipSync)" 가 있으면 `lastSync.root` 경로가 살아 있어야 통과한다 — (c) 에서 `lastSync` 갱신을 지우지 않았는지 확인.

- [ ] **Step 6: 커밋**

```bash
git add mode3_wallet_agent.js tests/test_mode3_wallet_agent.mjs
git commit -m "feat(mode3): 지갑 에이전트가 증분 동기화(rcl.sync)를 쓴다 — proveSession root 는 증명의 revRoot, /wallet/status.rcl, POST /wallet/rcl/reset"
```

---

### Task 4: 벤치·문서·스펙 §9

**Files:**
- Create: `scripts/bench_mode3_rcl_sync.mjs`, `results/mode3_rcl_sync_<YYYYMMDD>.md`(실행일 날짜, 기존 파일 덮어쓰지 않음)
- Modify: `docs/MODE3_DEMO.md`("하지 말 것 / 재시연" 절에 캐시 한 줄, "테스트" 절에 새 파일, "엔드포인트" 표에 `/wallet/rcl/reset`), `docs/superpowers/specs/2026-09-23-mode3-rcl-incremental-sync-design.md` §9(결정: `/wallet/rcl/reset` 넣음, 실측 요약 1줄), 상단 "상태" 줄을 "구현 완료" 로.

**Interfaces:**
- Consumes: `createRevocationSync`(Task 2), `syncRevocationTree`, `tests/helpers/mode3_chain.mjs` 의 `deployRevocationLog/signRootPublication/rootToBytes32/fundAddress/getProvider`.

- [ ] **Step 1: 벤치 스크립트**

`scripts/bench_mode3_rcl_sync.mjs`:

```js
// RCL 동기화 실측: 전체 재생 vs 캐시 복원 vs 델타 (스펙 2026-09-23 §7).
//   node scripts/bench_mode3_rcl_sync.mjs [반복=5]        (:8545 hardhat 노드 필요)
// 임시 RevocationLog 를 배포하고 리프 N ∈ {0, 100, 1000} 을 50개씩 게시한 뒤, 각 N 에서
//   (a) syncRevocationTree — 창세기부터 전체 재생
//   (b) 새 createRevocationSync 의 첫 sync() — 캐시 복원(+델타 0)
//   (c) 리프 1개 게시 뒤 sync() — 델타 1
//   (d) 블록 변화 없이 sync() — 델타 0(getLogs 없음)
// 의 벽시계 시간을 반복 측정해 중앙값(최소–최대)을 Markdown 표로 stdout 에 낸다. results/mode3_rcl_sync_<YYYYMMDD>.md 로 저장한다(새 파일).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ethers } from 'ethers';
import { getProvider, fundAddress, deployRevocationLog, signRootPublication, rootToBytes32 } from '../tests/helpers/mode3_chain.mjs';
import { createRevocationTree } from '../lib/mode3_revocation.js';
import { syncRevocationTree } from '../lib/mode3_wallet.js';
import { createRevocationSync } from '../lib/mode3_rcl_sync.js';

const REPS = Number(process.argv[2] || 5);
const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
const fmt = (a) => `${med(a).toFixed(0)} (${Math.min(...a).toFixed(0)}–${Math.max(...a).toFixed(0)})`;
const now = () => performance.now();

const provider = getProvider();
const ciaEth = ethers.Wallet.createRandom().connect(provider);
await fundAddress(ciaEth.address, '5', provider);
const { address: logAddress, contract: log } = await deployRevocationLog(ciaEth.address, provider);
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-rcl-bench-'));
const cacheFile = path.join(dir, 'mode3_wallet_rcl.json');

// CIA 흉내: 로컬 트리를 유지하며 리프를 게시한다(매번 이벤트를 다시 읽지 않는다 — 벤치 자체가 느려지지 않게)
const ciaTree = await createRevocationTree();
let nextLeaf = 1_000_001n;
async function publish(count) {
  const leavesBig = [];
  for (let i = 0; i < count; i++) { leavesBig.push(nextLeaf); await ciaTree.insert(nextLeaf); nextLeaf++; }
  const root = rootToBytes32(ciaTree.getRoot());
  const epoch = (await log.epoch()) + 1n;
  const leaves = leavesBig.map(rootToBytes32);
  const sig = await signRootPublication(ciaEth, { logAddress, root, epoch, leaves });
  await (await log.connect(ciaEth).publishRoot(root, epoch, leaves, sig)).wait();
}

const rows = [];
let total = 0;
for (const N of [0, 100, 1000]) {
  while (total < N) { const c = Math.min(50, N - total); await publish(c); total += c; }
  const full = [], restore = [], delta1 = [], delta0 = [];
  for (let i = 0; i < REPS; i++) {
    let t = now(); await syncRevocationTree(provider, logAddress); full.push(now() - t);
    // 캐시를 채운 뒤 새 인스턴스로 복원 시간을 잰다
    const warm = createRevocationSync({ provider, logAddress, cacheFile, log: () => {} });
    await warm.sync();
    const cold = createRevocationSync({ provider, logAddress, cacheFile, log: () => {} });
    t = now(); const r = await cold.sync(); restore.push(now() - t);
    if (r.mode !== 'restore') throw new Error(`복원이어야 한다: ${r.mode}`);
    await publish(1); total += 1;
    t = now(); const d1 = await cold.sync(); delta1.push(now() - t);
    if (d1.mode !== 'delta') throw new Error(`델타여야 한다: ${d1.mode}`);
    t = now(); await cold.sync(); delta0.push(now() - t);
  }
  rows.push({ N: total, full, restore, delta1, delta0 });
}

const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
let md = `## Mode 3 RCL 동기화 실측 (반복 ${REPS}, 중앙값 (최소–최대), ms)\n\n`;
md += `hardhat 로컬 노드, 임시 RevocationLog, 리프는 50개씩 게시. N 은 측정 시점의 누적 리프 수(반복마다 델타 1개가 더해진다).\n\n`;
md += `| 리프 N | (a) 전체 재생 syncRevocationTree | (b) 캐시 복원 첫 sync | (c) 델타 1 | (d) 델타 0 |\n|--:|--:|--:|--:|--:|\n`;
for (const r of rows) md += `| ${r.N} | ${fmt(r.full)} | ${fmt(r.restore)} | ${fmt(r.delta1)} | ${fmt(r.delta0)} |\n`;
md += `\n(a) 는 로그인마다 내던 비용(옛 동작), (c)/(d) 가 새 동작의 로그인당 비용, (b) 는 에이전트 재시작 1회 비용이다.\n`;
console.log(md);
const out = path.join('results', `mode3_rcl_sync_${date}.md`);
if (fs.existsSync(out)) console.error(`이미 있음 — 덮어쓰지 않는다: ${out}`); else { fs.writeFileSync(out, md); console.error(`저장: ${out}`); }
fs.rmSync(dir, { recursive: true, force: true });
provider.destroy();
```

- [ ] **Step 2: 실행**

Run: `node scripts/bench_mode3_rcl_sync.mjs 5`
Expected: 표 3행 출력, `results/mode3_rcl_sync_<오늘>.md` 생성. N=1000 에서 (a) 가 (c)/(d) 보다 뚜렷히 크고, (b) 는 (a) 보다 작거나 비슷(둘 다 O(N) Poseidon 이지만 (b) 는 getLogs 가 짧다). 결과가 그 방향이 아니면 그대로 적고 보고한다 — 수치를 다듬지 않는다.

- [ ] **Step 3: 문서**

`docs/MODE3_DEMO.md`:
- "하지 말 것 / 재시연" 재시연 세트 항목 끝에: "`mode3_wallet_rcl.json`(지갑의 폐기 트리 체크포인트, 공개 데이터)은 지워도 되고 안 지워도 된다 — 로그 주소가 바뀌면 자동으로 무시되고, 지우면 첫 로그인이 창세기부터 재생한다. 강제로 다시 재생시키려면 `POST /wallet/rcl/reset`."
- "엔드포인트" 표에 `POST /wallet/rcl/reset` 행(같은 오리진, 본문 없음, `{ ok:true }`), `GET /wallet/status` 행에 `rcl` 필드 설명.
- "테스트" 절 `chain` 항목 뒤에: "`tests/test_mode3_rcl_sync.mjs` — 증분 동기화(복원·델타·불일치 fallback·fail-closed·동시성). `node scripts/bench_mode3_rcl_sync.mjs` 가 실측을 낸다(`results/mode3_rcl_sync_*.md`)."

스펙 §9: "열린 것" 을 "`POST /wallet/rcl/reset` 넣음(Task 3)" 으로 닫고, §7 아래에 실측 결과 파일 경로와 N=1000 의 (a)/(c) 한 줄을 적는다. 상단 "**상태: 초안. 사용자 검토 대기.**" → "**상태: 구현 완료(2026-09-23).**".

- [ ] **Step 4: 전 그룹 실행**

Run: `bash scripts/run_tests.sh chain` (hardhat :8545 는 세션이 띄운 것을 쓴다). `contract`·`npm test` 는 이번 변경(지갑 라이브러리·에이전트·문서)과 무관하므로 생략하되 그 사유를 보고서에 적는다. `browser` 는 에이전트 경로가 바뀌었으므로 Chrome 이 있으면 돌린다.
Expected: chain 전부 통과(새 파일 포함 15개).

- [ ] **Step 5: 커밋**

```bash
git add scripts/bench_mode3_rcl_sync.mjs results/mode3_rcl_sync_*.md docs/MODE3_DEMO.md docs/superpowers/specs/2026-09-23-mode3-rcl-incremental-sync-design.md
git commit -m "docs(mode3): RCL 증분 동기화 벤치·실측·데모 문서·스펙 §9"
```

---

## 자체 점검

- **스펙 커버리지**: §1 표 → T2·T3; §2 파일·인터페이스 → T2(모듈)·T3(에이전트·status·reset)·T4(문서); §3 알고리즘(복원/부트스트랩/체인 리셋/델타/fallback/캐시 쓰기 시점) → T2 모듈 + 테스트 1·4·5·6·9; §4 캐시 형식·유효 조건·원자적 쓰기·쓰기 시점 → T2(`writeCache`/`readCache`, 테스트 3·5); §5 동시성(in-flight 공유, `w.root`, `proved.revRoot`) → T2 테스트 8, T1, T3(d); §6 테스트 1~9 → T2, 에이전트 재시작 복원 → T3; §7 벤치 → T4; §8 오류 표 → T2(경고·throw)·T3(503)·T4 문서; §9 → T4.
- **자리표시자**: T1 Step 1 의 `buildCredentialProof` 인자 객체는 "기존 증명 테스트의 것을 복사"라고 적었다 — 파일에 그 테스트가 실제로 있고(`buildCredentialProof` 를 import 해 쓰는 케이스), 인자 이름은 `proveSession` 의 호출과 같다(`uid, arid, s_u, blind_u, blind_s, pk_i, attrs, credential, pk_CIA, pk_trace, tree`). 구현자가 읽어 채우는 것이 맞다(픽스처 생성 코드가 수십 줄이라 여기 복제하면 드리프트한다).
- **타입 일관성**: `sync()` 반환 `{ tree, root: bigint, epoch: bigint, head: bigint, mode }` 가 T2 모듈·테스트·T3 에이전트에서 같다. `stats().lastSyncedBlock` 은 bigint|null 이고 T3 가 `.toString()` 으로 직렬화한다. `buildCredentialProof` 반환 `revRoot: bigint` 를 T3 가 `cache.set(cached.revRoot, …)` 에 그대로 쓴다(`ProofCache.#key` 는 템플릿 문자열이라 bigint 도 `synced.root`(bigint)와 같은 표현).
