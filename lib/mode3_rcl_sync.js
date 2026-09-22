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
