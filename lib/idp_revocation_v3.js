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

// 세션 샤드 회수는 "링 슬롯이 지금 살아있는 슬롯인가"로 판정하지 않는다.
//
// 그렇게 하면 슬롯이 죽어 있는 창(링 512칸 - 만료창 332칸 = 180블록 = 약 36분) 안에
// 정리를 돌려야만 회수된다. sweep 주기가 그보다 길거나 다운타임이 겹치면 만료된 리프가
// 다음 주기까지 살아남아, 링이 재사용될 때 **새 크레덴셜과 같은 샤드에 섞인다.**
// 건전성은 깨지지 않지만(다른 값의 비멤버십은 여전히 옳다) 샤드 용량이 잠식돼,
// 깊이 8(256슬롯)이 차면 insert가 던져 게시가 멈춘다. (2026-09-06 리뷰에서 재현.)
//
// 대신 **샤드가 담고 있는 max_height를 직접 기록한다.** 한 샤드의 리프는 모두 같은
// max_height를 공유하므로(샤드 = f(max_height, 값)) 그 값 하나면 충분하고, 판정이
// 타이밍에 의존하지 않는다. 삽입 시 기록된 값과 다르면 먼저 비워서 자가 치유한다.

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
  // 세션 샤드가 담고 있는 max_height. 샤드 하나의 리프는 모두 같은 값을 공유한다.
  // 회수 판정과 링 재사용 시 자가 치유의 근거다(위 주석 참조).
  const shardMaxHeight = new Map();   // shard(number) -> BigInt

  // ── 전이 서술자 버퍼 (설계 문서 13.2절) ────────────────────────────────
  //
  // RevocationRegistryV4는 root를 받지 않고 **유도한다.** 그러려면 이 회차가 포레스트를
  // 어떻게 바꿨는지를 순서 그대로 넘겨야 한다. 반환값 모양을 건드리지 않으려고(호출부와
  // 테스트가 의존한다) 내부 버퍼에 쌓고 takeRoundUpdates()로 꺼낸다.
  //
  // **순서와 형제 경로가 계약이다.** 서술자는 포레스트를 실제로 바꾼 순서대로 쌓이고,
  // siblings는 그 샤드를 바꾼 **직후** 뽑는다. 컨트랙트가 순차로 접으므로 i번째 서술자의
  // 형제는 0..i-1이 반영된 상태여야 하기 때문이다. 자기 샤드의 변경은 자기 형제에 영향을
  // 주지 않으므로 "직후"로 충분하다.
  let roundUpdates = [];

  /** 삽입 하나를 서술자로 남긴다. transcripts가 증명의 재료다. */
  function pushInsertUpdate(forest, isAccount, shard, transcript) {
    roundUpdates.push({
      kind: 'insert',
      account: isAccount,
      shard,
      oldSubRoot: transcript.oldRoot,
      newSubRoot: transcript.newRoot,
      siblings: forest.topPathFor(shard),
      // 회로는 K=4까지 담지만 여기서는 삽입 하나당 서술자 하나를 만든다. 같은 샤드로
      // 연달아 들어오는 경우가 드물어(세션 4,096 / 계정 256 샤드) 묶어도 이득이 거의 없고,
      // 묶으려면 "형제를 언제 뽑는가"가 단계마다 달라져 계약이 복잡해진다.
      transcripts: [transcript],
    });
  }

  return {
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
            // 링 재사용 자가 치유: 이 샤드가 다른 max_height의 리프를 담고 있으면
            // 그건 지난 주기의 잔재다. 정리 창을 놓쳤더라도 여기서 비워진다.
            const shard = sessionShardOf(leafKey, mh);
            const held = shardMaxHeight.get(shard);
            if (held !== undefined && held !== mh) {
              // 지난 주기의 잔재가 남은 샤드다. 예전에는 여기서 조용히 비웠지만
              // (링 재사용 자가 치유), 그 리셋은 **컨트랙트가 검증할 수 없다**: 이 샤드는
              // 곧 살아있는 크레덴셜을 담으므로 리셋 창이 닫혀 있다(설계 문서 13.2절의
              // d > maxCredentialSpan 조건이 성립하지 않는다).
              //
              // 회수를 삽입보다 먼저 하도록 바꾼 뒤로 이 경로는 정상 운영에서 도달할 수
              // 없다 — 잔재가 있었다면 같은 commit의 resetExpiredSessionShards가 이미
              // 비웠어야 한다. 도달했다면 shardMaxHeight가 유실된 것이므로, 조용히 고치는
              // 대신 회차를 실패시켜 드러낸다(commit이 5xx로 되돌리고 push는 일어나지 않는다).
              throw new Error(
                `session shard ${shard} still holds max_height ${held} while inserting ${mh}; ` +
                'expiry reclamation should have cleared it first — refusing to silently reset ' +
                '(the contract cannot verify a reset while the shard is about to hold live credentials)',
              );
            }
            const r = await session.insertWithTranscript(leafKey, { maxHeight: mh });
            if (r) {
              sessionAdded += 1;
              pushInsertUpdate(session, false, r.shard, r.transcript);
            }
            shardMaxHeight.set(shard, mh);
          } else if (l === LAYER_ACCOUNT) {
            const r = await account.insertWithTranscript(leafKey);
            if (r) {
              accountAdded += 1;
              pushInsertUpdate(account, true, r.shard, r.transcript);
            }
          } else {
            throw new Error('no recorded layer; refusing to guess which forest it belongs to');
          }
        } catch (err) {
          failed.push({ leaf: leafKey, reason: err.message });
        }
      }
      // 실패분은 별도 표식을 남기지 않는다. 호출자(commit)가 회차를 5xx로 되돌리고
      // pendingAdds를 정리하지 않으므로, 실패한 리프는 다음 prepare가 자동으로 다시
      // 집어 든다(hasLeaf가 여전히 false다). 자가 복구라 수동 backfill 경로가 필요없다.
      return { sessionAdded, accountAdded, failed };
    },

    /**
     * 만료 창을 벗어난 세션 샤드를 통째로 비운다. v2의 재기준화를 대신하는 경로이고,
     * 전 지갑 재다운로드를 유발하지 않는다 — 그 샤드를 쓰던 크레덴셜은 이미 만료라
     * 어차피 온체인에서 거부되기 때문이다.
     */
    // 주의: 반드시 applyCommit **앞에** 호출해야 한다(2026-09-07에 순서를 뒤집었다).
    //
    // 뒤에 부르면, 게시가 지연돼 명목 만료가 지나간 폐기가 트리에 들어가자마자 같은
    // 회차에서 회수돼 한 번도 효력을 갖지 못한다. 회수 대상은 "이번 회차 **이전에** 이미
    // 게시돼 있던 만료 리프"이고 그것이 정확히 prepare의 expiredPublished다.
    // (tests/test_idp_publish_behavior.mjs 케이스 3이 이 순서를 고정한다.)
    //
    // 이 함수는 shardMaxHeight만 지우고 layer/sessionMaxHeight는 건드리지 않으므로,
    // 먼저 불러도 applyCommit의 층 판정에는 영향이 없다. 층 기록을 지우는 것은
    // pruneExpiredMetadata이고 그쪽은 여전히 대기열 정리 뒤에 불러야 한다.
    resetExpiredSessionShards(currentBlock) {
      const block = BigInt(currentBlock);
      let reset = 0;
      for (const [shard, mh] of [...shardMaxHeight]) {
        if (mh <= block) {
          const oldSubRoot = session.getSubtreeRoot(shard);
          if (session.resetShard(shard)) {
            reset += 1;
            roundUpdates.push({
              kind: 'sessionReset',
              account: false,
              shard,
              oldSubRoot,
              newSubRoot: session.getSubtreeRoot(shard),   // = emptyRoot
              siblings: session.topPathFor(shard),
            });
          }
          shardMaxHeight.delete(shard);
        }
      }
      return reset;
    },

    /**
     * 만료된 메타데이터를 정리한다. 게시 여부와 무관하다.
     *
     * layer/sessionMaxHeight/accountExpiry는 접수 시점에 쓰이는데, 게시되지 않은 접수분은
     * 어떤 회수 경로도 건드리지 않아 **영구 누적**됐다(2026-09-06 리뷰에서 재현). 이 맵들은
     * saveIdPState에 실려 로그인마다 다시 쓰이므로, 상태 파일이 서서히 커진다.
     *
     * 만료된 것만 지운다. 호출자는 대기열의 만료분 정리를 **먼저** 끝내야 한다 —
     * 아직 대기 중인데 층 기록이 사라지면 다음 commit이 그 리프를 실패로 처리한다.
     */
    pruneExpiredMetadata(currentBlock) {
      const block = BigInt(currentBlock);
      let pruned = 0;
      for (const [leafKey, mh] of [...sessionMaxHeight]) {
        if (mh <= block) { sessionMaxHeight.delete(leafKey); layer.delete(leafKey); pruned += 1; }
      }
      for (const [leafKey, e] of [...accountExpiry]) {
        if (e <= block) { accountExpiry.delete(leafKey); layer.delete(leafKey); pruned += 1; }
      }
      return pruned;
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
        const oldSubRoot = account.getSubtreeRoot(shard);
        if (live.length === 0) account.resetShard(shard);
        else await account.loadShard(shard, live);
        // 이 전이만 증명되지 않는다(설계 문서 13.2절의 잔여 신뢰). 계정 폐기 리프의 만료가
        // 리프에 없고, 만료로 샤딩하면 지갑이 조회할 샤드를 특정할 수 없기 때문이다.
        roundUpdates.push({
          kind: 'accountRebaseline',
          account: true,
          shard,
          oldSubRoot,
          newSubRoot: account.getSubtreeRoot(shard),
          siblings: account.topPathFor(shard),
        });
        for (const v of values) {
          if (!live.includes(v)) {
            accountExpiry.delete(v);
            layer.delete(v);
          }
        }
      }
      return { shardsRebaselined, leavesReclaimed };
    },


    /**
     * 어느 층이든 이 리프가 들어 있는가. 대기열 중복제거의 기준이다(설계 문서 13.1절):
     * "이미 게시됐는가"의 답을 게시의 진실인 이 포레스트가 낸다.
     */
    async hasLeaf(leafKey) {
      const l = layer.get(leafKey);
      if (l === LAYER_SESSION) {
        const mh = sessionMaxHeight.get(leafKey);
        return mh === undefined ? false : session.has(leafKey, { maxHeight: mh });
      }
      if (l === LAYER_ACCOUNT) return account.has(leafKey);
      return false;
    },

    /**
     * v3에 실제로 들어 있는 리프 전체(두 층 합집합).
     *
     * v2의 publishedLeaves()에 대응하지만 **같은 집합이 아니다.** v2는 append-only라
     * 만료 리프를 재기준화 전까지 들고 있고, v3는 세션 샤드를 만료 시 리셋하고 계정
     * 샤드를 재기준화로 회수한다. 그래서 v3 쪽이 "만료됐지만 아직 v2에서 회수되지 않은"
     * 리프만큼 작다. 그 차이는 결함이 아니라 설계다(설계 문서 13.1절).
     */
    publishedLeafSet() {
      const out = new Set();
      for (const s of session.activeShards()) for (const v of session.getShardLeafValues(s)) out.add(v);
      for (const s of account.activeShards()) for (const v of account.getShardLeafValues(s)) out.add(v);
      return out;
    },

    /**
     * 이 회차가 포레스트를 어떻게 바꿨는지를 **순서 그대로** 꺼내고 버퍼를 비운다.
     * RevocationRegistryV4에 넘길 전이 서술자다(증명은 아직 없다 — sweep이 붙인다).
     *
     * commit이 회차를 시작할 때 beginRound()로 비우고, 끝에서 이걸 부른다. 회차가 실패해
     * 5xx로 되돌아가면 다음 beginRound()가 버려진 서술자를 지운다.
     */
    takeRoundUpdates() {
      const out = roundUpdates;
      roundUpdates = [];
      return out;
    },

    /** 회차 시작. 이전 회차의 잔재를 지운다. */
    beginRound() {
      roundUpdates = [];
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
        shardMaxHeight: Object.fromEntries(
          [...shardMaxHeight].map(([k, v]) => [String(k), v.toString()]),
        ),
        sessionShards,
        accountShards,
      };
    },

    /** 저장된 스냅샷에서 복원한다. 샤드별 리프 배열은 물리 순서 그대로여야 한다. */
    async restore(obj) {
      session = await createSessionForest();
      account = await createAccountForest();
      layer.clear();
      sessionMaxHeight.clear();
      accountExpiry.clear();
      shardMaxHeight.clear();


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
      for (const [k, v] of Object.entries(obj?.shardMaxHeight ?? {})) {
        shardMaxHeight.set(Number(k), BigInt(v));
      }
      for (const [s, values] of Object.entries(obj?.sessionShards ?? {})) {
        await session.loadShard(Number(s), values);
      }
      for (const [s, values] of Object.entries(obj?.accountShards ?? {})) {
        await account.loadShard(Number(s), values);
      }

      // shardMaxHeight가 없는 옛 스냅샷 복구.
      //
      // 이 맵이 생기기 전에 쓰인 v5 파일에는 없다. 없으면 resetExpiredSessionShards가
      // 그 샤드를 영영 회수하지 못해(판정 근거가 사라진다) 리프가 쌓인다.
      // 다행히 재구성할 수 있다 — 샤드 안의 아무 리프나 골라 그 leafKey의 max_height를
      // 보면 된다(한 샤드의 리프는 모두 같은 값을 공유한다).
      for (const shard of session.activeShards()) {
        if (shardMaxHeight.has(shard)) continue;
        const values = session.getShardLeafValues(shard);
        const mh = values.map((v) => sessionMaxHeight.get(v)).find((x) => x !== undefined);
        if (mh !== undefined) {
          shardMaxHeight.set(shard, mh);
        } else {
          // 메타데이터까지 없으면 회수 근거가 없다. 남겨두면 영구히 쌓이므로 비운다 —
          // 층 기록이 없는 리프는 어차피 어느 포레스트에 속하는지 알 수 없고, 만료됐다면
          // 되찾을 필요도 없다.
          session.resetShard(shard);
        }
      }
    },

    /** 테스트/진단용 — 내부 포레스트를 직접 본다. */
    _forests() {
      return { session, account };
    },
  };
}
