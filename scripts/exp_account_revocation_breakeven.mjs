// 계정 폐기율의 실용 경계 — 가정하지 않고 경계를 잰다.
//
// 왜. 계정 층(256샤드)의 무효화 빈도를 말하려면 "계정 폐기가 얼마나 잦은가"를 가정해야
// 하는데, 그 값은 배포마다 다르고 근거를 댈 수 없다. 그래서 방향을 뒤집는다 — 폐기율을
// 가정하는 대신 **어느 폐기율까지 실용적인가**를 보고한다.
//
// 무엇을 재는가. 척도는 scripts/exp_shard_axis_collateral.mjs의 척도 A와 **같은 정의**를
// 쓴다(비교 가능해야 하므로): "마지막 증명 이후 Δ블록 안에 내 샤드로 폐기가 들어왔는가".
// grace window는 여기서 모델링하지 않는다 — 척도 A가 그렇고, grace의 효과는 논문 §VI-B가
// 따로 서술한다.
//
// 계정 층은 uid_hash 축이라 uid 상관(코호트 침해 등)이 샤드로 전파되지 않는다. 실측에서도
// uid_hash는 시나리오에 둔감했으므로 여기서는 uniform 하나만 돌린다.
//
// 사용: node scripts/exp_account_revocation_breakeven.mjs [trials]
import { writeFileSync } from 'node:fs';
import { ACCOUNT_SHARD_COUNT, ACCOUNT_SUBTREE_DEPTH } from '../lib/imt_v3.js';

const TRIALS = Number(process.argv[2] ?? 20000);
const S = ACCOUNT_SHARD_COUNT;                 // 256
const CAP = (1 << ACCOUNT_SUBTREE_DEPTH) - 1;  // 1,023 (anchor 리프 제외)
const L = 332;            // 크레덴셜 수명(블록) — assertMaxHeightWithinBound
const BLOCK_SEC = 12;
const DAU = 1e8;
const WIN_PER_DAY = (1440 * 60) / (L * BLOCK_SEC);
const TARGET = 0.10;      // 기준점: 재증명율 10%

function mkRng(seed) { let x = seed >>> 0; return () => ((x ^= x << 13, x ^= x >>> 17, x ^= x << 5, x >>> 0) / 4294967296); }

// 수명당 폐기 R개를 L블록 × S샤드에 균등 배치하고, 임의 증명자의 Δ창 재증명율과
// 최번 샤드 점유를 잰다.
function simulate(R, gaps, trials, seed) {
  const rng = mkRng(seed);
  const hits = new Map(gaps.map((g) => [g, 0]));
  let busiestSum = 0, busiestMax = 0;
  const ROUNDS = Math.max(1, Math.round(trials / 200));
  for (let r = 0; r < ROUNDS; r++) {
    // 한 번의 폐기 배치를 만들고 그 위에서 증명자 200명을 뽑는다
    const perShard = new Int32Array(S);
    const times = Array.from({ length: S }, () => []);
    for (let i = 0; i < R; i++) {
      const s = Math.floor(rng() * S);
      perShard[s] += 1;
      times[s].push(rng() * L);
    }
    for (const arr of times) arr.sort((a, b) => a - b);
    let busiest = 0;
    for (let s = 0; s < S; s++) if (perShard[s] > busiest) busiest = perShard[s];
    busiestSum += busiest; if (busiest > busiestMax) busiestMax = busiest;
    for (let p = 0; p < 200; p++) {
      const s = Math.floor(rng() * S);
      const t0 = rng() * L;
      for (const g of gaps) {
        const lo = t0, hi = t0 + g;
        let hit = false;
        for (const x of times[s]) { if (x >= lo && x <= hi) { hit = true; break; } if (x > hi) break; }
        if (hit) hits.set(g, hits.get(g) + 1);
      }
    }
  }
  const n = ROUNDS * 200;
  return {
    rates: new Map(gaps.map((g) => [g, hits.get(g) / n])),
    busiestMean: busiestSum / ROUNDS, busiestMax,
  };
}

const GAPS = [1, 10, 60];
const DAILY = [1e3, 5e3, 1e4, 1.94e4, 5e4, 1e5, 5e5, 1e6];
const theory = (R, g) => 1 - Math.exp(-(R * g) / (L * S));
const pct = (v) => `${(v * 100).toFixed(v < 0.01 ? 2 : 1)}%`;

const rows = [];
for (const daily of DAILY) {
  const R = daily / WIN_PER_DAY;
  const sim = simulate(Math.round(R), GAPS, TRIALS, 12345 + Math.round(daily));
  rows.push({ daily, share: daily / DAU, R, sim });
}

console.log(`\n## 계정 폐기율별 재증명율 — DAU ${DAU.toExponential(0)}, 로그인 1회/일\n`);
console.log(`샤드 ${S}개, 서브트리 용량 ${CAP}리프, 수명 ${L}블록(${(L*BLOCK_SEC/60).toFixed(1)}분)`);
console.log(`재증명율 = "마지막 증명 이후 Δ블록 안에 내 샤드로 폐기가 들어옴" (척도 A와 같은 정의)\n`);
console.log('| 계정 폐기/일 | 사용자 대비 | R/수명 | Δ=1블록 | Δ=10블록 | Δ=60블록 | 최번 샤드 (평균/최대) | 용량 대비 |');
console.log('|---:|---:|---:|---:|---:|---:|---:|---:|');
for (const r of rows) {
  const c = GAPS.map((g) => pct(r.sim.rates.get(g)));
  console.log(`| ${r.daily.toLocaleString()} | ${(r.share*100).toFixed(4)}% | ${Math.round(r.R).toLocaleString()} | ${c[0]} | ${c[1]} | ${c[2]} | ${r.sim.busiestMean.toFixed(0)} / ${r.sim.busiestMax} | ${(r.sim.busiestMax/CAP*100).toFixed(1)}% |`);
}

// 기준점: Δ=10에서 재증명율 TARGET이 되는 폐기율
const Rstar = -Math.log(1 - TARGET) * L * S / 10;
const dailyStar = Rstar * WIN_PER_DAY;
console.log(`\n**기준점 — Δ=10블록에서 재증명율 ${TARGET*100}%: 하루 ${Math.round(dailyStar).toLocaleString()}건 = 사용자의 ${(dailyStar/DAU*100).toFixed(3)}%**\n`);
// 용량 한계 — 최번 샤드가 용량을 넘기 시작하는 R을 이진탐색으로 찾는다.
function capacityLimit() {
  let lo = 1e3, hi = 2e6;                       // lo: 안 넘침, hi: 넘침 이 되도록 잡는다
  if (simulate(Math.round(hi), [10], 2000, 999).busiestMax <= CAP) return hi;
  for (let i = 0; i < 25; i++) {
    const mid = Math.round((lo + hi) / 2);
    if (simulate(mid, [10], 2000, 999).busiestMax > CAP) hi = mid; else lo = mid;
  }
  return lo;
}
const Rcap = capacityLimit();
const dailyCap = Rcap * WIN_PER_DAY;
console.log(`용량 한계(최번 샤드가 ${CAP}리프를 넘는 지점): 수명당 약 ${Math.round(Rcap).toLocaleString()}건 = 하루 ${Math.round(dailyCap).toLocaleString()}건 = 사용자의 ${(dailyCap/DAU*100).toFixed(2)}%`);
console.log(`→ 용량은 재증명 기준보다 약 ${Math.round(dailyCap/dailyStar)}배 느슨하다. **구속 조건은 용량이 아니라 재증명이다.**`);

// 이론식과의 일치 확인
console.log('\n검증 — 시뮬레이션 vs 이론식 1−exp(−R·Δ/(L·S)), Δ=10:');
for (const r of rows.slice(0, 4)) {
  console.log(`  R=${Math.round(r.R).toString().padStart(6)}  sim ${pct(r.sim.rates.get(10))}  theory ${pct(theory(r.R,10))}`);
}

const stamp = new Date().toISOString().slice(0,10).replace(/-/g,'');
const out = `results/account_revocation_breakeven_${stamp}.csv`;
writeFileSync(out, [
  `# 계정 폐기율의 실용 경계. DAU=${DAU} shards=${S} capacity=${CAP} lifetime=${L} trials=${TRIALS}`,
  `# 재증명율 정의는 exp_shard_axis_collateral.mjs 척도 A와 동일. grace 미반영.`,
  `# 기준점 Δ=10, 재증명율 ${TARGET}: 하루 ${Math.round(dailyStar)}건 = 사용자의 ${(dailyStar/DAU*100).toFixed(3)}%`,
  'daily_revocations,share_of_users,per_lifetime,reprove_gap1,reprove_gap10,reprove_gap60,busiest_mean,busiest_max,capacity_pct',
  ...rows.map((r)=>[r.daily, (r.share).toFixed(8), Math.round(r.R),
    ...GAPS.map((g)=>r.sim.rates.get(g).toFixed(4)),
    r.sim.busiestMean.toFixed(1), r.sim.busiestMax, (r.sim.busiestMax/CAP*100).toFixed(2)].join(',')),
].join('\n') + '\n');
console.log(`\n기록: ${out}`);
