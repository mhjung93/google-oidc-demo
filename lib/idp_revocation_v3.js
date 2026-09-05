// IdP 쪽 v3(이중 트리) 폐기 상태. custom_idp.js가 몇 군데서만 호출한다.
//
// 설계: docs/superpowers/specs/2026-09-05-revocation-dual-tree-design.md
//
// 왜 별도 모듈인가. custom_idp.js의 v2 절은 게시(prepare/commit)·만료·재기준화·변경
// 로그가 서로 얽혀 있어 그 사이에 v3를 끼워 넣으면 어느 쪽 결함인지 구분하기 어려워진다.
// v1 -> v2 전환 때처럼 **나란히** 두고, 전환은 배선이 끝난 뒤에 한다.
//
// v2 대비 사라지는 것이 많다는 점이 이 설계의 실질적 이득이다.
//   - 변경 로그/seq/epoch/tooOld: 없다. 서브트리 하나가 최대 256~1,024리프라 지갑이
//     자기 샤드를 통째로 받아도 싸다. 증분 동기화 프로토콜 자체가 필요 없다.
//   - 세션 층 재기준화: 없다. 샤드 인덱스의 만료 축이 곧 그 안의 리프들의 만료이므로,
//     창을 벗어난 샤드는 통째로 버리면 된다.
import {
  createSessionForest,
  createAccountForest,
  computeTopPath,
  combineTopRoots,
  sessionShardOf,
  sessionShardLowOf,
  accountShardOf,
  SESSION_RING,
  SESSION_VALUE_BITS,
  SESSION_SHARD_COUNT,
  ACCOUNT_SHARD_COUNT,
} from './imt_v3.js';

export const LAYER_SESSION = 'session';
export const LAYER_ACCOUNT = 'account';

/**
 * 세션 링 슬롯이 지금 살아있는가.
 *
 * 슬롯 r은 max_height ≡ r (mod 512)인 크레덴셜을 담는다. assertMaxHeightWithinBound가
 * max_height를 (현재, 현재 + lifetimeSpan]으로 묶으므로, 어느 시점에나 살아있는 슬롯은
 * lifetimeSpan개뿐이고 나머지는 전부 죽은 것이다 — 통째로 버려도 된다.
 *
 * 링이 512칸이고 창이 332칸이므로, 슬롯 하나가 죽고 나서 다시 쓰이기까지 180블록의
 * 여유가 있다. 그 여유가 링 재사용의 안전 마진이다.
 */
export function isSessionRingSlotLive(slot, currentBlock, lifetimeSpan) {
  const ring = Number(SESSION_RING);
  const lo = BigInt(currentBlock) + 1n;
  const span = BigInt(lifetimeSpan);
  if (span >= BigInt(ring)) return true; // 창이 링보다 넓으면 모든 슬롯이 살아있다
  const offset = ((BigInt(slot) - lo) % BigInt(ring) + BigInt(ring)) % BigInt(ring);
  return offset <= span - 1n;
}

export async function createIdPRevocationV3() {
  let session = await createSessionForest();
  let account = await createAccountForest();

  // 리프가 어느 층인지. 리프는 Poseidon(TAG, value)라 해시만 보고는 층을 알 수 없으므로
  // 접수 시점(/idp/revoke, type을 아는 유일한 지점)에 기록해 둔다.
  const layer = new Map();        // leafKey -> LAYER_SESSION | LAYER_ACCOUNT
  const sessionMaxHeight = new Map(); // leafKey -> BigInt, 세션 샤드 라우팅용

  // v4 이하 상태 파일에서 올라온 경우, 이미 게시된 폐기의 층을 복원할 방법이 없다
  // (리프가 해시다). 그 사실을 조용히 넘기지 않고 플래그로 드러낸다 — 전환(E단계) 전에
  // 운영자가 살아있는 폐기를 다시 접수해야 한다.
  let needsBackfill = false;

  return {
    get needsBackfill() {
      return needsBackfill;
    },
    markNeedsBackfill() {
      needsBackfill = true;
    },

    /** /idp/revoke에서 접수할 때 호출한다. 층과 (세션이면) 만료를 기억해 둔다. */
    record(leafKey, type, expiryBlock) {
      if (type !== LAYER_SESSION && type !== LAYER_ACCOUNT) {
        throw new Error(`unknown revocation layer: ${type}`);
      }
      const prev = layer.get(leafKey);
      const prevMax = sessionMaxHeight.get(leafKey);
      layer.set(leafKey, type);
      if (type === LAYER_SESSION) sessionMaxHeight.set(leafKey, BigInt(expiryBlock));
      // 롤백용 이전 값 — /idp/revoke는 저장 실패 시 인메모리 변경을 되돌린다.
      return { prev, prevMax };
    },

    /** record()의 롤백. */
    unrecord(leafKey, { prev, prevMax }) {
      if (prev === undefined) layer.delete(leafKey);
      else layer.set(leafKey, prev);
      if (prevMax === undefined) sessionMaxHeight.delete(leafKey);
      else sessionMaxHeight.set(leafKey, prevMax);
    },

    /**
     * 게시 확정(commit)에서 호출한다. 층에 따라 알맞은 포레스트로 라우팅한다.
     *
     * 층을 모르는 리프는 **넣지 않고 던진다.** 조용히 한쪽에 넣으면 그 폐기는 증명에
     * 보이지 않아 무효가 되는데, 그건 아무 데서도 드러나지 않는 실패다(설계 문서 조건 4).
     */
    async applyCommit(leafKeys) {
      let sessionAdded = 0;
      let accountAdded = 0;
      for (const leafKey of leafKeys) {
        const l = layer.get(leafKey);
        if (l === LAYER_SESSION) {
          const mh = sessionMaxHeight.get(leafKey);
          if (mh === undefined) throw new Error(`session leaf ${leafKey} has no recorded max_height`);
          if (await session.insert(leafKey, { maxHeight: mh })) sessionAdded += 1;
        } else if (l === LAYER_ACCOUNT) {
          if (await account.insert(leafKey)) accountAdded += 1;
        } else {
          throw new Error(
            `leaf ${leafKey} has no recorded layer; refusing to guess which forest it belongs to`,
          );
        }
      }
      return { sessionAdded, accountAdded };
    },

    /**
     * 만료 창을 벗어난 세션 샤드를 통째로 비운다. v2의 재기준화를 대신하는 경로이고,
     * 전 지갑 재다운로드를 유발하지 않는다 — 그 샤드를 쓰던 크레덴셜은 이미 만료라
     * 어차피 온체인에서 거부되기 때문이다.
     */
    resetExpiredSessionShards(currentBlock, lifetimeSpan) {
      let reset = 0;
      for (const shard of session.activeShards()) {
        const slot = Math.floor(shard / (1 << SESSION_VALUE_BITS));
        if (!isSessionRingSlotLive(slot, currentBlock, lifetimeSpan)) {
          if (session.resetShard(shard)) reset += 1;
        }
      }
      if (reset > 0) {
        // 메타데이터도 함께 정리한다. 안 하면 로그인마다 커지기만 한다.
        for (const [leafKey, mh] of [...sessionMaxHeight]) {
          if (BigInt(mh) <= BigInt(currentBlock)) {
            sessionMaxHeight.delete(leafKey);
            layer.delete(leafKey);
          }
        }
      }
      return reset;
    },

    /** 온체인에 게시되는 값. 두 층을 2-리프 keccak으로 합친 것이다. */
    combinedRoot() {
      return combineTopRoots(session.getTopRoot(), account.getTopRoot());
    },

    sessionTopRoot() {
      return session.getTopRoot();
    },
    accountTopRoot() {
      return account.getTopRoot();
    },

    shardsFor(sessLeaf, maxHeight, acctLeaf) {
      return {
        sessionShard: sessionShardOf(sessLeaf, maxHeight),
        sessionShardLow: sessionShardLowOf(sessLeaf),
        accountShard: accountShardOf(acctLeaf),
      };
    },

    /**
     * 지갑이 받아가는 상태. 루트 목록 전체(4,096 + 256)를 매번 보내면 수백 KB가 되므로,
     * **비어 있지 않은 샤드만** 덮어쓰기 목록으로 보낸다. 폐기가 드물다는 전제에서
     * 응답이 사실상 상수 크기가 된다.
     */
    snapshot({ sessionShard, accountShard } = {}) {
      const sessionRootOverrides = {};
      for (const s of session.activeShards()) sessionRootOverrides[s] = session.getSubtreeRoot(s);
      const accountRootOverrides = {};
      for (const s of account.activeShards()) accountRootOverrides[s] = account.getSubtreeRoot(s);

      const out = {
        sessionShardCount: SESSION_SHARD_COUNT,
        accountShardCount: ACCOUNT_SHARD_COUNT,
        sessionEmptyRoot: session.emptyRoot,
        accountEmptyRoot: account.emptyRoot,
        sessionRootOverrides,
        accountRootOverrides,
        sessionTopRoot: session.getTopRoot(),
        accountTopRoot: account.getTopRoot(),
        topRoot: combineTopRoots(session.getTopRoot(), account.getTopRoot()),
        needsBackfill,
      };
      if (Number.isInteger(sessionShard)) {
        out.sessionShard = sessionShard;
        out.sessionShardLeaves = session.getShardLeafValues(sessionShard);
        out.sessionShardSiblings = computeTopPath(session.getSubtreeRoots(), sessionShard);
      }
      if (Number.isInteger(accountShard)) {
        out.accountShard = accountShard;
        out.accountShardLeaves = account.getShardLeafValues(accountShard);
        out.accountShardSiblings = computeTopPath(account.getSubtreeRoots(), accountShard);
      }
      return out;
    },

    usage() {
      return { session: session.usage(), account: account.usage() };
    },

    serialize() {
      const sessionShards = {};
      for (const s of session.activeShards()) sessionShards[s] = session.getShardLeafValues(s);
      const accountShards = {};
      for (const s of account.activeShards()) accountShards[s] = account.getShardLeafValues(s);
      return {
        layer: Object.fromEntries(layer),
        sessionMaxHeight: Object.fromEntries(
          [...sessionMaxHeight].map(([k, v]) => [k, v.toString()]),
        ),
        sessionShards,
        accountShards,
        needsBackfill,
      };
    },

    /** 저장된 스냅샷에서 복원한다. 샤드별 리프 배열은 물리 순서 그대로여야 한다. */
    async restore(obj) {
      session = await createSessionForest();
      account = await createAccountForest();
      layer.clear();
      sessionMaxHeight.clear();
      needsBackfill = Boolean(obj?.needsBackfill);

      for (const [k, v] of Object.entries(obj?.layer ?? {})) {
        if (v !== LAYER_SESSION && v !== LAYER_ACCOUNT) {
          throw new Error(`v3.layer[${k}] must be "session" or "account"`);
        }
        layer.set(k, v);
      }
      for (const [k, v] of Object.entries(obj?.sessionMaxHeight ?? {})) {
        sessionMaxHeight.set(k, BigInt(v));
      }
      for (const [s, values] of Object.entries(obj?.sessionShards ?? {})) {
        await session.loadShard(Number(s), values);
      }
      for (const [s, values] of Object.entries(obj?.accountShards ?? {})) {
        await account.loadShard(Number(s), values);
      }
    },

    /** 테스트/진단용 — 내부 포레스트를 직접 본다. */
    _forests() {
      return { session, account };
    },
  };
}
