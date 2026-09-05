// 지갑 쪽 v3(이중 트리) 폐기 동기화. wallet_agent.js가 /submitTransaction에서 쓴다.
//
// 설계: docs/superpowers/specs/2026-09-05-revocation-dual-tree-design.md
//
// v2 경로(wallet_agent.js의 doSyncRevocationTreeV2)와 비교하면 사라진 것이 많다.
//
//   - **캐시가 없다.** v2는 깊이 20 트리 하나를 요청 간에 들고 있어야 했고(재구성이
//     리프 32,000개에 24.75초), 그래서 증분 동기화·epoch·seq·tooOld와 그 캐시를
//     보호하는 직렬화 큐가 전부 필요했다. v3는 자기 샤드 하나가 최대 256~1,024리프라
//     매 호출마다 새로 쌓아도 싸다. 캐시가 없으면 캐시 일관성 결함도 없다.
//   - **증분 프로토콜이 없다.** 위와 같은 이유다.
//
// 남은 것은 하나다: 받은 것이 실제로 맞는지 스스로 검증하는 것. IdP가 준 루트·경로를
// 그대로 믿고 증명을 만들면, 어긋났을 때 온체인에서야 드러난다(가스만 태우고 revert).
import {
  createSessionForest,
  createAccountForest,
  computeTopRoot,
  computeTopPath,
  combineTopRoots,
  rootToBytes32,
  sessionShardOf,
  sessionShardLowOf,
  accountShardOf,
  leafValue,
  TAG_SESSION,
  TAG_ACCOUNT,
  SESSION_SHARD_COUNT,
  ACCOUNT_SHARD_COUNT,
} from './imt_v3.js';

/** 응답의 (빈 루트 + 덮어쓰기 목록)에서 전체 루트 배열을 복원한다. */
function rebuildRoots(emptyRoot, overrides, count, label) {
  if (typeof emptyRoot !== 'string') throw new Error(`${label}: emptyRoot missing`);
  const roots = new Array(count).fill(emptyRoot);
  for (const [shard, root] of Object.entries(overrides ?? {})) {
    const idx = Number(shard);
    if (!Number.isInteger(idx) || idx < 0 || idx >= count) {
      throw new Error(`${label}: override shard ${shard} out of range`);
    }
    roots[idx] = String(root);
  }
  return roots;
}

/**
 * 자기 샤드 두 개만 받아 비멤버십 witness와 상위 경로를 만든다.
 *
 * @param idpOrigin  IdP 주소
 * @param rTokenField  r_token (10진 문자열/BigInt)
 * @param auidField    auid
 * @param maxHeight    이 크레덴셜의 max_height — 세션 샤드의 만료 축이다
 */
export async function fetchRevocationWitnessesV3(idpOrigin, rTokenField, auidField, maxHeight) {
  const sessLeaf = await leafValue(TAG_SESSION, rTokenField);
  const acctLeaf = await leafValue(TAG_ACCOUNT, auidField);
  const sessionShard = sessionShardOf(sessLeaf, maxHeight);
  const accountShard = accountShardOf(acctLeaf);

  const url =
    `${idpOrigin}/idp/revocation_state_v3` +
    `?sessionShard=${sessionShard}&accountShard=${accountShard}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`revocation_state_v3 failed: ${res.status}`);
  const body = await res.json();

  // ── 받은 것을 스스로 재구성해 대조한다 ────────────────────────────────
  const sessRoots = rebuildRoots(
    body.sessionEmptyRoot, body.sessionRootOverrides, SESSION_SHARD_COUNT, 'session',
  );
  const acctRoots = rebuildRoots(
    body.accountEmptyRoot, body.accountRootOverrides, ACCOUNT_SHARD_COUNT, 'account',
  );

  const sessTop = computeTopRoot(sessRoots);
  const acctTop = computeTopRoot(acctRoots);
  if (sessTop !== body.sessionTopRoot) {
    throw new Error(`session top root ${sessTop} != IdP ${body.sessionTopRoot}`);
  }
  if (acctTop !== body.accountTopRoot) {
    throw new Error(`account top root ${acctTop} != IdP ${body.accountTopRoot}`);
  }
  const topRoot = combineTopRoots(sessTop, acctTop);
  if (topRoot !== body.topRoot) {
    throw new Error(`combined root ${topRoot} != IdP ${body.topRoot}`);
  }

  // ── 자기 샤드를 직접 쌓아 root가 맞는지 본다 ──────────────────────────
  // IdP가 준 root를 그냥 믿으면, 리프 목록과 어긋났을 때 온체인에서야 드러난다.
  const sessForest = await createSessionForest();
  const acctForest = await createAccountForest();
  const sessRootLocal = await sessForest.loadShard(sessionShard, body.sessionShardLeaves ?? []);
  const acctRootLocal = await acctForest.loadShard(accountShard, body.accountShardLeaves ?? []);
  if (sessRootLocal !== sessRoots[sessionShard]) {
    throw new Error(`rebuilt session subtree root ${sessRootLocal} != served ${sessRoots[sessionShard]}`);
  }
  if (acctRootLocal !== acctRoots[accountShard]) {
    throw new Error(`rebuilt account subtree root ${acctRootLocal} != served ${acctRoots[accountShard]}`);
  }

  // ── 비멤버십 witness ─────────────────────────────────────────────────
  // 폐기됐다면 여기서 던진다(Case 1). 그 경우 증명을 만들 방법이 없다.
  const sess = await sessForest.getNonMembershipWitness(sessLeaf, { maxHeight });
  const acct = await acctForest.getNonMembershipWitness(acctLeaf);

  // 상위 경로는 로컬 계산을 쓴다. IdP가 함께 준 값과 다르면 그 자체가 이상 신호다.
  const sessSiblings = computeTopPath(sessRoots, sessionShard);
  const acctSiblings = computeTopPath(acctRoots, accountShard);
  if (body.sessionShardSiblings && String(body.sessionShardSiblings) !== String(sessSiblings)) {
    throw new Error('IdP-supplied session top path disagrees with the locally computed one');
  }
  if (body.accountShardSiblings && String(body.accountShardSiblings) !== String(acctSiblings)) {
    throw new Error('IdP-supplied account top path disagrees with the locally computed one');
  }

  return {
    // 회로 입력 (private witness)
    sess,
    acct,
    // 회로 public signal
    sessRoot: sessRoots[sessionShard],
    sessShardLow: sessionShardLowOf(sessLeaf),
    acctRoot: acctRoots[accountShard],
    acctShard: accountShard,
    // 컨트랙트 calldata
    sessRootBytes32: rootToBytes32(sessRoots[sessionShard]),
    acctRootBytes32: rootToBytes32(acctRoots[accountShard]),
    sessSiblings,
    acctSiblings,
    // 온체인 대조용
    topRoot,
    sessionShard,
    needsBackfill: Boolean(body.needsBackfill),
  };
}
