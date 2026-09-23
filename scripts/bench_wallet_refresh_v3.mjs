// 지갑의 폐기 상태 갱신 비용 (로컬 계산분) — 076d882 이후의 실제 경로.
//
// 무엇이 바뀌었나. 그 커밋 전까지 지갑은 비어 있지 않은 **모든 샤드의 root 목록**을 받아
// 상위 트리를 통째로 다시 쌓았다(computeTopPath). 지금은 자기 서브트리만 재구성하고
// **형제 경로를 접어 올린다**(computeTopFromPath) — 컨트랙트가 하는 계산과 같다. 응답도
// 샤드 수와 무관하게 약 1 KB 상수가 됐다. 그래서 옛 측정(상위 트리 재구성 77 ms)은
// 더 이상 이 시스템을 서술하지 않는다.
//
// 무엇을 재는가. lib/wallet_revocation_v3.js가 응답을 받은 뒤 하는 일 전부:
//   서브트리 재구성(loadShard, Poseidon) → 형제 경로 접기(computeTopFromPath, keccak)
//   → 비멤버십 witness 생성
// HTTP 왕복은 뺀다 — 그건 scripts/bench_wallet_revocation_v3.mjs가 살아있는 IdP로 잰다.
//
// 사용: node scripts/bench_wallet_refresh_v3.mjs [rounds]
import { writeFileSync } from 'node:fs';
import {
  createSessionForest, createAccountForest, computeTopFromPath, leafValue,
  TAG_SESSION, TAG_ACCOUNT, sessionShardOf, accountShardOf,
  SESSION_SHARD_COUNT, ACCOUNT_SHARD_COUNT, SESSION_SUBTREE_DEPTH, ACCOUNT_SUBTREE_DEPTH,
} from '../lib/imt_v3.js';

const ROUNDS = Number(process.argv[2] ?? 10);
const MAX_HEIGHT = 1000n;
const ms = (t) => Number(process.hrtime.bigint() - t) / 1e6;
const avg = (a) => a.reduce((s, v) => s + v, 0) / a.length;
const sd  = (a) => { const m = avg(a); return Math.sqrt(a.reduce((s,v)=>s+(v-m)**2,0)/Math.max(1,a.length-1)); };
const f = (v) => v.toFixed(2);

// 내 샤드에 리프가 n개 있을 때의 로컬 갱신 비용.
async function measure(layer, n, rounds) {
  const depth = layer === 'session' ? SESSION_SUBTREE_DEPTH : ACCOUNT_SUBTREE_DEPTH;
  const shardCount = layer === 'session' ? SESSION_SHARD_COUNT : ACCOUNT_SHARD_COUNT;
  const topDepth = Math.log2(shardCount);
  const mine = await leafValue(layer === 'session' ? TAG_SESSION : TAG_ACCOUNT, 12345n);
  const shard = layer === 'session' ? sessionShardOf(mine, MAX_HEIGHT) : accountShardOf(mine);
  // 같은 샤드에 떨어지는 이웃 리프 n개를 만든다(내 리프는 넣지 않는다 — 비멤버십이어야 하므로)
  const neighbours = [];
  for (let i = 0; neighbours.length < n; i++) {
    const v = await leafValue(layer === 'session' ? TAG_SESSION : TAG_ACCOUNT, BigInt(1_000_000 + i));
    const s = layer === 'session' ? sessionShardOf(v, MAX_HEIGHT) : accountShardOf(v);
    if (s === shard && v !== mine) neighbours.push(v);
    if (i > 400000) break;                    // 못 채우면 있는 만큼으로 잰다
  }
  const siblings = Array.from({ length: topDepth }, (_, i) =>
    '0x' + (i + 1).toString(16).padStart(64, '0'));
  const times = [];
  let cold = null;
  for (let r = 0; r <= rounds; r++) {
    const t = process.hrtime.bigint();
    const forest = layer === 'session' ? await createSessionForest() : await createAccountForest();
    const root = await forest.loadShard(shard, neighbours);
    computeTopFromPath(root, shard, siblings);
    await forest.getNonMembershipWitness(mine, layer === 'session' ? { maxHeight: MAX_HEIGHT } : undefined);
    const d = ms(t);
    if (r === 0) cold = d; else times.push(d);
  }
  return { layer, n: neighbours.length, depth, topDepth, cold, mean: avg(times), sd: sd(times) };
}

const rows = [];
for (const layer of ['session', 'account']) {
  const cap = (1 << (layer === 'session' ? SESSION_SUBTREE_DEPTH : ACCOUNT_SUBTREE_DEPTH)) - 1;
  for (const n of [0, 1, 2, 8, 32, Math.min(128, cap)]) rows.push(await measure(layer, n, ROUNDS));
}

console.log(`\n## 지갑 폐기 상태 갱신 — 로컬 계산분 (warm ${ROUNDS}회)\n`);
console.log(`세션 ${SESSION_SHARD_COUNT}샤드/깊이 ${SESSION_SUBTREE_DEPTH}, 계정 ${ACCOUNT_SHARD_COUNT}샤드/깊이 ${ACCOUNT_SUBTREE_DEPTH}`);
console.log(`형제 경로 길이 = 세션 ${Math.log2(SESSION_SHARD_COUNT)}, 계정 ${Math.log2(ACCOUNT_SHARD_COUNT)}\n`);
console.log('| 층 | 내 샤드의 이웃 리프 | cold (ms) | warm 평균 (ms) | SD |');
console.log('|---|---:|---:|---:|---:|');
for (const r of rows) console.log(`| ${r.layer} | ${r.n} | ${f(r.cold)} | ${f(r.mean)} | ${f(r.sd)} |`);

const pick = (l, n) => rows.find((r) => r.layer === l && r.n === n) ?? rows.find((r) => r.layer === l);
const ref = (pick('session', 2)?.mean ?? 0) + (pick('account', 1)?.mean ?? 0);
console.log(`\n**기준 시나리오(폐기율 0.1%: 세션 샤드당 약 1.7리프, 계정 약 1.1리프) 갱신 1회 = 약 ${f(ref)} ms**`);
console.log('비교: pi_pk_i 재증명 510.3 ms. 갱신은 재증명의 ' + `${(ref/510.3*100).toFixed(1)}%.`);

const stamp = new Date().toISOString().slice(0,10).replace(/-/g,'');
const out = `results/mode2_wallet_refresh_${stamp}.csv`;
writeFileSync(out, [
  `# 지갑 폐기 갱신 로컬 계산분 (076d882 이후 경로). warm ${ROUNDS}회. HTTP 왕복 제외.`,
  `# session ${SESSION_SHARD_COUNT}샤드 깊이${SESSION_SUBTREE_DEPTH} / account ${ACCOUNT_SHARD_COUNT}샤드 깊이${ACCOUNT_SUBTREE_DEPTH}`,
  `# 기준 시나리오 갱신 1회 = ${f(ref)} ms`,
  'layer,neighbour_leaves,subtree_depth,top_depth,cold_ms,warm_mean_ms,warm_sd_ms',
  ...rows.map((r)=>[r.layer,r.n,r.depth,r.topDepth,f(r.cold),f(r.mean),f(r.sd)].join(',')),
].join('\n')+'\n');
console.log(`\n기록: ${out}`);
