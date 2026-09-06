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
  // 계정 리프의 만료. 세션과 달리 샤드 인덱스가 만료를 담지 않으므로(계정 샤드는 값
  // 기반이다) 회수하려면 만료를 따로 들고 있어야 한다. v2의 leafExpiry와 같은 역할이다.
  const accountExpiry = new Map();    // leafKey -> BigInt

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
    /** 운영자가 backfill 완료(또는 불필요)를 확인했을 때. */
    ackBackfill() {
      needsBackfill = false;
    },

    /**
     * /idp/revoke에서 접수할 때 호출한다. 층과 라우팅에 필요한 값을 기억해 둔다.
     *
     * 세션과 계정이 서로 다른 값을 필요로 한다는 점이 중요하다.
     *   세션 — 샤드가 **그 크레덴셜의 max_height**로 정해진다. "폐기 리프의 만료"가
     *          아니다. 둘은 지금 우연히 같지만(세션 폐기의 만료 = max_height), 그건
     *          불변식이 아니라 우연이다. 만료 쪽 값을 넘기면 리프가 틀린 샤드로 조용히
     *          들어가 증명에 보이지 않게 된다(설계 문서 조건 4의 무성 실패).
     *          그래서 만료가 아니라 max_height를 **따로** 받는다.
     *   계정 — 샤드가 리프 값으로 정해지므로 만료는 회수(재기준화)에만 쓴다.
     */
    record(leafKey, type, { expiry, maxHeight } = {}) {
      if (type !== LAYER_SESSION && type !== LAYER_ACCOUNT) {
        throw new Error(`unknown revocation layer: ${type}`);
      }
      if (type === LAYER_SESSION && (maxHeight === undefined || maxHeight === null)) {
        throw new Error('session revocation requires maxHeight (the credential max_height, not the leaf expiry)');
      }
      if (type === LAYER_ACCOUNT && (expiry === undefined || expiry === null)) {
        throw new Error('account revocation requires expiry');
      }
      const prev = layer.get(leafKey);
      const prevMax = sessionMaxHeight.get(leafKey);
      const prevExp = accountExpiry.get(leafKey);
      layer.set(leafKey, type);
      if (type === LAYER_SESSION) sessionMaxHeight.set(leafKey, BigInt(maxHeight));
      else accountExpiry.set(leafKey, BigInt(expiry));
      // 롤백용 이전 값 — /idp/revoke는 저장 실패 시 인메모리 변경을 되돌린다.
      return { prev, prevMax, prevExp };
    },

    /** record()의 롤백. */
    unrecord(leafKey, { prev, prevMax, prevExp }) {
      if (prev === undefined) layer.delete(leafKey);
      else layer.set(leafKey, prev);
      if (prevMax === undefined) sessionMaxHeight.delete(leafKey);
      else sessionMaxHeight.set(leafKey, prevMax);
      if (prevExp === undefined) accountExpiry.delete(leafKey);
      else accountExpiry.set(leafKey, prevExp);
    },

    /**
     * 게시 확정(commit)에서 호출한다. 층에 따라 알맞은 포레스트로 라우팅한다.
     *
     * 층을 모르는 리프는 **넣지 않는다.** 조용히 한쪽에 넣으면 그 폐기는 증명에
     * 보이지 않아 무효가 되는데, 그건 아무 데서도 드러나지 않는 실패다(설계 문서 조건 4).
     *
     * 다만 리프 하나가 실패해도 **배치 전체를 버리지 않는다.** 호출부(commit)는 v2에
     * 이미 전부 삽입한 뒤라, 여기서 중간에 던지면 뒤쪽 리프들이 v2에만 있고 v3에는
     * 없는 상태로 조용히 갈라진다. 실패한 리프를 목록으로 돌려주어 backfill 때
     * **무엇을 다시 넣어야 하는지** 알 수 있게 한다.
     */
    async applyCommit(leafKeys) {
      let sessionAdded = 0;
      let accountAdded = 0;
      const failed = [];
      for (const leafKey of leafKeys) {
        try {
          const l = layer.get(leafKey);
          if (l === LAYER_SESSION) {
            const mh = sessionMaxHeight.get(leafKey);
            if (mh === undefined) throw new Error('no recorded max_height');
            if (await session.insert(leafKey, { maxHeight: mh })) sessionAdded += 1;
          } else if (l === LAYER_ACCOUNT) {
            if (await account.insert(leafKey)) accountAdded += 1;
          } else {
            throw new Error('no recorded layer; refusing to guess which forest it belongs to');
          }
        } catch (err) {
          failed.push({ leaf: leafKey, reason: err.message });
        }
      }
      if (failed.length > 0) needsBackfill = true;
      return { sessionAdded, accountAdded, failed };
    },

    /**
     * 만료 창을 벗어난 세션 샤드를 통째로 비운다. v2의 재기준화를 대신하는 경로이고,
     * 전 지갑 재다운로드를 유발하지 않는다 — 그 샤드를 쓰던 크레덴셜은 이미 만료라
     * 어차피 온체인에서 거부되기 때문이다.
     */
    // 주의: 반드시 applyCommit **뒤에** 호출해야 한다. 먼저 부르면 만료 직전 리프의
    // 층 기록이 지워져 applyCommit이 그 리프를 실패로 처리한다.
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

    /**
     * 만료된 계정 리프를 회수한다. 계정 샤드는 값 기반이라 세션처럼 "샤드를 통째로
     * 버리는" 수가 없으므로, **샤드 단위 재기준화**로 살아있는 값만 다시 쌓는다.
     *
     * v2의 전역 재기준화와 결정적으로 다른 점: 바뀌는 것은 그 샤드뿐이라 **다른 샤드를
     * 쓰는 지갑은 아무 영향도 받지 않는다.** v2에서는 재기준화 한 번이 전 지갑에
     * O(n) 재다운로드를 물렸다.
     *
     * 만료 정보가 없는 리프는 살아있는 것으로 남긴다 — 폐기 경로 전반의 보수적 처리와
     * 같다(fail-open을 피한다).
     */
    async rebaselineExpiredAccountShards(currentBlock) {
      const block = BigInt(currentBlock);
      let shardsRebaselined = 0;
      let leavesReclaimed = 0;
      for (const shard of account.activeShards()) {
        const values = account.getShardLeafValues(shard);
        const live = values.filter((v) => {
          const e = accountExpiry.get(v);
          return e === undefined || e > block;
        });
        if (live.length === values.length) continue;
        // 정렬해 쌓아 root가 입력 순서와 무관한 순수 함수가 되게 한다(v2 rebaseline과 동일).
        live.sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0));
        leavesReclaimed += values.length - live.length;
        shardsRebaselined += 1;
        if (live.length === 0) account.resetShard(shard);
        else await account.loadShard(shard, live);
        for (const v of values) {
          if (!live.includes(v)) {
            accountExpiry.delete(v);
            layer.delete(v);
          }
        }
      }
      return { shardsRebaselined, leavesReclaimed };
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
        accountExpiry: Object.fromEntries(
          [...accountExpiry].map(([k, v]) => [k, v.toString()]),
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
      accountExpiry.clear();
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
      for (const [k, v] of Object.entries(obj?.accountExpiry ?? {})) {
        accountExpiry.set(k, BigInt(v));
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
