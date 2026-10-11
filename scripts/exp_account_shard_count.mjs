// 실험: 계정 층 샤드 수를 바꾸면 무엇이 좋아지고 무엇이 나빠지는가.
//
//   node scripts/exp_account_shard_count.mjs [--dau 100000000] [--revoke-rate 0.001]
//
// 앞선 실험(exp_shard_axis_collateral.mjs)의 결론은 "축은 uid_hash가 맞는데 현행 계정 층은
// 샤드가 256개뿐이라 무효화가 심하다"였다. 그러면 샤드를 늘리면 되는데, 늘리면 무엇을
// 대가로 내는지가 이 실험이다.
//
// ── 재는 것 ──────────────────────────────────────────────────────────────
//   좋아지는 쪽
//     · 무효화 확률 / 세션당 재증명 횟수 — 1/S로 준다
//     · 샤드당 리프 수 — 용량 여유가 늘어난다
//     · 전체 계정 용량 S x 1,023
//   나빠지는 쪽
//     · 상위 트리 깊이 log2(S) — execute()마다 접어 올린다 (실측 단가 1,141 gas/단계,
//       scripts/bench_top_path_gas.cjs)
//     · **지갑이 받는 응답 크기** — 비어 있지 않은 샤드의 root 덮어쓰기 목록이라,
//       샤드가 늘면 폐기가 흩어져 비어 있지 않은 샤드가 늘어난다. 이게 가장 덜 자명한
//       비용이라 실제 포레스트를 만들어 직렬화해서 잰다.
//   그리고 한 번만 내는 비용
//     · 회로가 바뀐다. circuits/pi_pk_i_v3.circom이 IMTNonMembershipV3(10, ACCT_SHARD_BITS)로
//       **샤드 비트를 회로에 박아** 두므로, 256 -> 4,096은 ACCT_SHARD_BITS 8 -> 12이고
//       새 zkey · 새 verifier · factory 재배포(= CREATE2 지갑 주소 전부 변경)가 따라온다.
import fs from 'node:fs';
import { leafValue, TAG_ACCOUNT } from '../lib/imt.js';
import { createShardForest, ACCOUNT_SUBTREE_DEPTH } from '../lib/imt_v3.js';

const CREDENTIAL_LIFETIME_BLOCKS = 300;
const MAX_HEIGHT_SLACK_BLOCKS = 32;
const LIFETIME = CREDENTIAL_LIFETIME_BLOCKS + MAX_HEIGHT_SLACK_BLOCKS;
const BLOCKS_PER_DAY = 7200;

const SUBTREE_CAPACITY = 2 ** ACCOUNT_SUBTREE_DEPTH - 1;   // 1,023
const GAS_PER_TOP_LEVEL = 1141;                            // 실측: bench_top_path_gas.cjs
const EXECUTE_GAS = 332272;                                // 실측: 라이브 E2E 구간 A
const REPROVE_MS = 507.2;                                  // 실측: pi_pk_i_v3 warm 평균
const CURRENT_SHARDS = 256;
const CURRENT_SHARD_BITS = 8;

function arg(name, dflt) {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? dflt : process.argv[i + 1];
}
const DAU = Number(arg('dau', 100_000_000));
const REVOKE_RATE = Number(arg('revoke-rate', 0.001));
const CANDIDATES = [256, 1024, 4096, 16384];

// 수명 동안 살아 있는 계정 폐기 수. 계정 폐기 리프도 수명(332블록) 뒤 회수되므로,
// 어느 순간 트리에 들어 있는 리프 수가 곧 이 값이다.
const LIVE = Math.max(1, Math.round(DAU * (LIFETIME / BLOCKS_PER_DAY) * REVOKE_RATE));

/** 그 샤드 수로 실제 포레스트를 만들어 LIVE건을 넣고 관측한다. */
async function measure(shardCount, leaves) {
  const shardBits = Math.log2(shardCount);
  const shardOf = (leaf) => Number(BigInt(leaf) & BigInt(shardCount - 1));
  const forest = await createShardForest({
    shardCount,
    depth: ACCOUNT_SUBTREE_DEPTH,
    shardOf,
    leafBelongsToShard: (leaf, shard) => shardOf(leaf) === shard,
  });

  const load = new Map();
  for (const l of leaves) {
    await forest.insert(l);
    const sh = shardOf(l);
    load.set(sh, (load.get(sh) ?? 0) + 1);
  }
  let peak = 0;
  for (const v of load.values()) if (v > peak) peak = v;

  // 지갑이 받는 응답. lib/idp_revocation_v3.js의 snapshot()이 만드는 것과 같은 모양이다:
  // 빈 서브트리 root 상수 하나 + 비어 있지 않은 샤드의 덮어쓰기 목록.
  const overrides = {};
  for (const s of forest.activeShards()) overrides[s] = forest.getSubtreeRoot(s);
  const responseBytes = JSON.stringify({
    accountShardCount: shardCount,
    accountEmptyRoot: forest.emptyRoot,
    accountRootOverrides: overrides,
    accountTopRoot: forest.getTopRoot(),
  }).length;

  // 대안: 전체 목록 대신 **자기 샤드의 형제 경로만** 보낸다.
  //
  // 지갑이 전체 덮어쓰기 목록을 받는 이유는 (1) topRoot 재계산, (2) 형제 경로 계산인데,
  // 둘 다 형제 경로만으로 된다 — 자기 서브트리 root를 형제와 접어 올려 topRoot가 나오면
  // 그것으로 충분하고(컨트랙트가 하는 계산과 동일하다), 다른 샤드의 내용은 알 필요가 없다.
  // 그러면 응답이 **샤드 수와 무관하게** 상수 크기가 된다.
  const someShard = forest.activeShards()[0] ?? 0;
  const siblingOnlyBytes = JSON.stringify({
    accountShard: someShard,
    accountShardLeaves: forest.getShardLeafValues(someShard),
    accountShardSiblings: forest.topPathFor(someShard),
    accountTopRoot: forest.getTopRoot(),
  }).length;

  return {
    shardCount, shardBits, activeShards: forest.activeShards().length, peak,
    responseBytes, siblingOnlyBytes,
  };
}

const leaves = [];
process.stderr.write(`  … 폐기 리프 ${LIVE.toLocaleString()}개 생성 중\n`);
for (let i = 0; i < LIVE; i++) leaves.push((await leafValue(TAG_ACCOUNT, BigInt(i) * 7919n + 13n)).toString());

const rows = [];
for (const S of CANDIDATES) {
  process.stderr.write(`  … 샤드 ${S.toLocaleString()} 측정 중\n`);
  rows.push(await measure(S, leaves));
}

const fmtKB = (b) => `${(b / 1024).toFixed(0)} KB`;

console.log('# 계정 층 샤드 수 스윕');
console.log('');
console.log(`DAU ${DAU.toLocaleString()} / 폐기율 ${(REVOKE_RATE * 100).toFixed(3)}%`);
console.log(`-> 어느 순간에도 트리에 살아 있는 계정 폐기 ${LIVE.toLocaleString()}건`);
console.log(`서브트리 깊이 ${ACCOUNT_SUBTREE_DEPTH} = 샤드당 용량 ${SUBTREE_CAPACITY.toLocaleString()}리프`);
console.log('');

console.log('## 좋아지는 쪽');
console.log('');
console.log('| 샤드 | 무효화 확률 | 세션당 재증명 | 재증명에 쓰는 시간 | 트랜잭션당 미스(2분) | 최대 샤드 점유 | 용량 대비 |');
console.log('|--:|--:|--:|--:|--:|--:|--:|');
for (const r of rows) {
  const pAny = 1 - Math.pow(1 - 1 / r.shardCount, LIVE);
  const mean = LIVE / r.shardCount;
  // 트랜잭션 간격 2분(10블록) 동안 들어오는 폐기는 LIVE x (10/332)건이다.
  const pTx = 1 - Math.pow(1 - 1 / r.shardCount, LIVE * (10 / LIFETIME));
  console.log(
    `| ${r.shardCount.toLocaleString()} | ${(pAny * 100).toFixed(1)}% | ${mean.toFixed(1)}회 | ` +
    `${(mean * REPROVE_MS / 1000).toFixed(1)}초 | ` +
    `${(pTx * 100).toFixed(2)}% | ${r.peak}리프 | ${((r.peak / SUBTREE_CAPACITY) * 100).toFixed(1)}% |`,
  );
}
console.log('');

console.log('## 나빠지는 쪽');
console.log('');
console.log('| 샤드 | 상위 깊이 | execute() 추가 gas | 증가율 | 비어있지 않은 샤드 | 지갑 응답(현행) | 지갑 응답(형제만) |');
console.log('|--:|--:|--:|--:|--:|--:|--:|');
for (const r of rows) {
  const dGas = (r.shardBits - CURRENT_SHARD_BITS) * GAS_PER_TOP_LEVEL;
  console.log(
    `| ${r.shardCount.toLocaleString()} | ${r.shardBits} | ${dGas >= 0 ? '+' : ''}${dGas.toLocaleString()} | ` +
    `${dGas >= 0 ? '+' : ''}${((dGas / EXECUTE_GAS) * 100).toFixed(2)}% | ` +
    `${r.activeShards.toLocaleString()} | ${fmtKB(r.responseBytes)} | ${r.siblingOnlyBytes.toLocaleString()} B |`,
  );
}
console.log('');
console.log('지갑 응답이 커지는 이유: 덮어쓰기 목록은 **비어 있지 않은 샤드**만 싣는데,');
console.log(`샤드를 늘리면 같은 ${LIVE.toLocaleString()}건이 더 흩어져 비어 있지 않은 샤드가 늘어난다.`);
console.log(`샤드 수가 폐기 건수를 넘어서면 항목 수는 폐기 건수(${LIVE.toLocaleString()})에서 포화한다.`);
console.log('');
console.log('**다만 이 비용은 없앨 수 있다.** 지갑이 전체 목록을 받는 이유는 (1) topRoot 재계산,');
console.log('(2) 형제 경로 계산 두 가지인데(lib/wallet_revocation_v3.js), 둘 다 형제 경로만으로');
console.log('된다 — 자기 서브트리 root를 형제와 접어 올려 topRoot가 나오면 충분하고, 그건');
console.log('컨트랙트가 하는 계산과 정확히 같다. 다른 샤드의 내용은 지갑에게 필요가 없다.');
console.log('그렇게 바꾸면 응답이 샤드 수와 무관하게 상수 크기가 된다(위 마지막 열).');
console.log('');

console.log('## 한 번만 내는 비용 — 회로가 바뀐다');
console.log('');
console.log('circuits/pi_pk_i_v3.circom이 IMTNonMembershipV3(10, ACCT_SHARD_BITS)로 샤드 비트를');
console.log('회로에 박아 둔다. 샤드 수를 바꾸면:');
for (const r of rows) {
  if (r.shardCount === CURRENT_SHARDS) continue;
  console.log(`  ${CURRENT_SHARDS} -> ${r.shardCount.toLocaleString()}: ACCT_SHARD_BITS ${CURRENT_SHARD_BITS} -> ${r.shardBits}` +
              ' => 새 zkey · 새 verifier · factory 재배포(CREATE2 지갑 주소 전부 변경)');
}
console.log('');
console.log('제약 수는 늘지 않는다 — 샤드 인덱스는 이미 분해된 target 비트의 선형 결합이라');
console.log('비트 수만 달라진다(circuits/lib/imt_nonmembership_v3.circom 주석의 실측 근거).');
console.log('');

const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
const out = `results/account_shard_count_${stamp}.csv`;
fs.mkdirSync('results', { recursive: true });
fs.writeFileSync(
  out,
  `# 계정 층 샤드 수 스윕. DAU=${DAU} revokeRate=${REVOKE_RATE} live=${LIVE}\n` +
  `# gas/level=${GAS_PER_TOP_LEVEL} (실측), execute=${EXECUTE_GAS} (실측)\n` +
  'shards,shard_bits,invalidation_prob,mean_reproofs,tx_miss_2min,peak_leaves,capacity_pct,' +
  'top_depth,added_gas,active_shards,response_bytes,sibling_only_bytes\n' +
  rows.map((r) => {
    const pAny = 1 - Math.pow(1 - 1 / r.shardCount, LIVE);
    const pTx = 1 - Math.pow(1 - 1 / r.shardCount, LIVE * (10 / LIFETIME));
    const dGas = (r.shardBits - CURRENT_SHARD_BITS) * GAS_PER_TOP_LEVEL;
    return `${r.shardCount},${r.shardBits},${pAny.toFixed(4)},${(LIVE / r.shardCount).toFixed(2)},` +
           `${pTx.toFixed(4)},${r.peak},${((r.peak / SUBTREE_CAPACITY) * 100).toFixed(1)},` +
           `${r.shardBits},${dGas},${r.activeShards},${r.responseBytes},${r.siblingOnlyBytes}`;
  }).join('\n') + '\n',
);
console.log(`wrote ${out}`);
process.exit(0);
