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
  computeTopFromPath,
  combineTopRoots,
  rootToBytes32,
  sessionShardOf,
  sessionShardLowOf,
  accountShardOf,
  leafValue,
  TAG_SESSION,
  TAG_ACCOUNT,
} from './imt_v3.js';

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
  //
  // 두 단계다. 어느 쪽도 IdP가 준 root를 그냥 믿지 않는다.
  //   1) 내 서브트리를 **받은 리프로 직접 쌓아** root를 얻는다
  //   2) 그 root를 **형제 경로로 접어 올려** 층 상위 root를 얻는다
  // 2번은 컨트랙트가 하는 계산과 정확히 같다(PPIDWalletV3._climbAcct). 그래서 여기서
  // 나온 combined root가 온체인 레지스트리와 맞으면, 그 사이의 모든 값이 맞은 것이다.
  //
  // 예전에는 비어 있지 않은 **모든** 샤드의 root 목록을 받아 상위 트리를 통째로 다시
  // 쌓았다. 같은 결론을 얻지만 응답이 샤드 수에 비례해 커진다 — 계정 샤드 4,096 기준
  // 233 KB 대 1 KB다(실측: scripts/exp_account_shard_count.mjs). 다른 샤드의 내용은
  // 지갑에게 필요가 없으므로 받지 않는다.
  const sessForest = await createSessionForest();
  const acctForest = await createAccountForest();
  const sessRootLocal = await sessForest.loadShard(sessionShard, body.sessionShardLeaves ?? []);
  const acctRootLocal = await acctForest.loadShard(accountShard, body.accountShardLeaves ?? []);

  const sessSiblings = body.sessionShardSiblings;
  const acctSiblings = body.accountShardSiblings;
  if (!Array.isArray(sessSiblings) || !Array.isArray(acctSiblings)) {
    throw new Error('revocation_state_v3 응답에 상위 형제 경로가 없다 (sessionShard/accountShard를 함께 요청했는가)');
  }

  const sessTop = computeTopFromPath(sessRootLocal, sessionShard, sessSiblings);
  const acctTop = computeTopFromPath(acctRootLocal, accountShard, acctSiblings);
  const topRoot = combineTopRoots(sessTop, acctTop);

  // IdP가 함께 실어 보낸 값과 다르면 그 자체가 이상 신호다. 진짜 기준점은 온체인
  // 레지스트리이고 그 대조는 호출자(wallet_agent)가 하지만, 여기서 먼저 걸리면
  // 원인을 훨씬 빨리 안다.
  if (body.sessionTopRoot && sessTop !== body.sessionTopRoot) {
    throw new Error(`session top root ${sessTop} != IdP ${body.sessionTopRoot}`);
  }
  if (body.accountTopRoot && acctTop !== body.accountTopRoot) {
    throw new Error(`account top root ${acctTop} != IdP ${body.accountTopRoot}`);
  }
  if (body.topRoot && topRoot !== body.topRoot) {
    throw new Error(`combined root ${topRoot} != IdP ${body.topRoot}`);
  }

  // ── 비멤버십 witness ─────────────────────────────────────────────────
  // 폐기됐다면 여기서 던진다(Case 1). 그 경우 증명을 만들 방법이 없다.
  const sess = await sessForest.getNonMembershipWitness(sessLeaf, { maxHeight });
  const acct = await acctForest.getNonMembershipWitness(acctLeaf);

  return {
    // 회로 입력 (private witness)
    sess,
    acct,
    // 회로 public signal
    sessRoot: sessRootLocal,
    sessShardLow: sessionShardLowOf(sessLeaf),
    acctRoot: acctRootLocal,
    acctShard: accountShard,
    // 컨트랙트 calldata
    sessRootBytes32: rootToBytes32(sessRootLocal),
    acctRootBytes32: rootToBytes32(acctRootLocal),
    sessSiblings,
    acctSiblings,
    // 온체인 대조용
    topRoot,
    sessionShard,
  };
}
