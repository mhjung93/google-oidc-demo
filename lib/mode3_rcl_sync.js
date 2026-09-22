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
  // chainId 는 프로세스당 한 번만 읽는다. 그래서 프로세스가 살아 있는 동안 다른 chainId 의 체인으로 바뀌면 캐시의
  // chainId 검사는 무력해진다 — 그때도 head 되감김 검사와 최종 root 대조가 안전망으로 남는다.
  let chainId = null;
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
      // 체인 리셋 검사(M2 리뷰): 캐시를 읽은 직후, 리프를 O(N) 재삽입해 복원하기 전에 검사한다.
      // 어차피 버릴 복원 작업(Poseidon N회)을 먼저 하지 않기 위함이다.
      if (head < c.lastSyncedBlock) {
        log(`[rcl] head(${head}) < 캐시 lastSyncedBlock(${c.lastSyncedBlock}) — 체인이 되감겼다. 전체 재생`);
        return bootstrap('bootstrap');
      }
      const restored = await createRevocationTree();
      // insert 는 값이 anchor(0)이거나 2^252 이상이면 throw 한다(lib/imt_v2.js validateValue). readCache 의 10진 검사로는
      // 그런 값을 거를 수 없으므로 여기서 잡는다 — 잡지 않으면 sync() 전체가 reject 돼 라우트가 영구히 503 을 낸다
      // (실패한 sync 는 캐시를 다시 쓰지 않아 재시작해도 같다). 캐시는 정확성에 관여하지 않는다는 성질을 지킨다.
      try {
        await Promise.all(c.leaves.map((v) => restored.insert(v)));   // 델타와 같은 이유로 한 틱에 넣는다(아래 참조)
      } catch (e) {
        log(`[rcl] 캐시 리프가 유효하지 않다(손상) — 전체 재생: ${e.message}`);
        return bootstrap('bootstrap');
      }
      if (restored.getRoot() !== c.root) { log('[rcl] 캐시의 root 가 리프와 맞지 않는다(손상) — 전체 재생'); return bootstrap('bootstrap'); }
      tree = restored;
      lastSyncedBlock = c.lastSyncedBlock;
      mode = 'restore';
    } else if (head < lastSyncedBlock) {
      // 메모리 트리가 이미 있는 상태(연속 delta)에서도 체인이 되감길 수 있다(프로세스가 오래 떠 있는 동안 hardhat 재기동 등).
      log(`[rcl] head(${head}) < lastSyncedBlock(${lastSyncedBlock}) — 체인이 되감겼다. 전체 재생`);
      return bootstrap('bootstrap');
    }

    let appended = 0;
    if (head > lastSyncedBlock) {
      const events = await contract.queryFilter(contract.filters.Revoked(), Number(lastSyncedBlock + 1n), blockTag);
      // 삽입마다 await 하면 안 된다. insert 본문에는 await 가 없어(lib/imt_v2.js) 호출 즉시 동기적으로 끝나지만,
      // `await` 자체가 삽입 사이에 마이크로태스크 경계를 만들어 **같은 트리 객체를 쥔 다른 요청**의 증인 생성이
      // 그 사이에 끼어들 수 있다. 그러면 리프가 절반만 들어간, 체인에 게시된 적 없는 중간 root 로 증명이 만들어져
      // RP 는 stale_root, 온체인은 StaleRevocationRoot 로 거절한다(원인이 로그에 남지 않는 간헐 실패).
      // 먼저 전부 호출해 한 틱에 넣고 결과만 모아 센다 — 증인이 보는 root 는 델타 이전 아니면 이후, 둘 다 게시된 root 다.
      const pending = [];
      for (const e of events) for (const l of e.args.leaves) pending.push(tree.insert(BigInt(l)));
      const results = await Promise.all(pending);     // insert 가 (용량 초과 등으로) 던지면 여기서 그대로 reject 된다
      appended = results.filter(Boolean).length;
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

  let pendingReset = false;   // reset() 이 진행 중인 run() 과 겹쳤을 때 — I1 리뷰 참조

  // 메모리 트리·캐시 파일을 실제로 버린다. reset() 과 sync() 의 지연 처리(pendingReset) 둘 다 이걸 쓴다.
  function doReset() {
    tree = null; lastSyncedBlock = null; lastMode = null;
    try { fs.rmSync(cacheFile, { force: true }); } catch (e) { log(`[rcl] 캐시 삭제 실패(무시): ${e.message}`); }
  }

  return {
    sync() {
      if (inFlight) return inFlight;
      inFlight = run().finally(() => {
        inFlight = null;
        // reset() 이 이 run() 도중 불렸다면 여기서 처리한다. run() 이 진행 중일 때 즉시 지우면 두 가지로 깨진다(I1):
        // (A) RPC 대기 중(root()·epoch() 등)에 지우면 재개한 run() 이 tree===null 을 보고 bootstrap() 으로
        //     캐시를 되살려버려 reset 이 조용히 무효화된다. (B) queryFilter 대기 중에 지우면 재개한 뒤
        //     tree.insert()/tree.getRoot() 가 null 이 된 tree 를 참조해 역참조 TypeError 로 죽는다.
        // 그래서 즉시 지우지 않고 run() 이 끝난 뒤에만 doReset() 한다.
        if (pendingReset) { pendingReset = false; doReset(); }
      });
      return inFlight;
    },
    stats() {
      return { leaves: tree ? tree.size() - 1 : 0, lastSyncedBlock, lastMode, cacheFile };
    },
    // reset() 은 진행 중인 동기화가 끝난 뒤에야 효력이 있다 — 그 동기화 자체는 방해받지 않고 끝까지 간다.
    // 돌려주는 { deferred } 는 즉시 지웠는지(false) 진행 중인 sync() 뒤로 미뤘는지(true)를 호출자가 알 수 있게 한다.
    reset() {
      if (inFlight) { pendingReset = true; return { deferred: true }; }
      doReset();
      return { deferred: false };
    },
  };
}
