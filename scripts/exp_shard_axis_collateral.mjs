// 실험: 폐기 리스트를 **어떤 축으로 샤딩하는가**에 따라, 남의 폐기가 내 증명을 얼마나
// 자주 못 쓰게 만드는가 (부수적 무효화, collateral invalidation).
//
//   node scripts/exp_shard_axis_collateral.mjs [옵션]
//     --dau 100000000        일 활성 사용자 (기본 1억)
//     --revoke-rate 0.001    로그인 대비 폐기 비율 (기본 0.1%)
//     --trials 2000          시나리오당 피해자 표본 수
//     --seed 1               난수 시드 (재현용)
//     --scenario all         uniform | session-wave | cohort-burst | all
//
// ── 무엇을 재는가 ─────────────────────────────────────────────────────────
// 이중 트리에서 증명의 public signal은 **자기 서브트리 root** 둘이다(sess_root, acct_root).
// 상위 root가 바뀌어도 내 증명은 그대로 쓸 수 있다 — 바뀌는 것은 컨트랙트가 다시 접는
// keccak 형제 경로뿐이다. 그래서
//
//     내 증명이 못 쓰게 된다  ⇔  **내 샤드에** 폐기가 들어온다
//
// 이 실험은 그 사건의 빈도를 축별로 비교한다.
//
// ── 비교하는 세 축 ───────────────────────────────────────────────────────
//   max_height : shard = (max_height mod 512) * 8 + (리프 하위 3비트)   [현행 세션 층]
//                내 샤드 동료 = **같은 블록에 로그인한 사람들**(만료가 같은 사람들)
//   uid_hash   : shard = 리프 해시 하위 log2(S)비트                      [현행 계정 층]
//                내 샤드 동료 = 무작위 1/S. 아무것과도 상관되지 않는다.
//   uid_range  : shard = floor(uid / (총사용자/S))                       [문자 그대로의 "uid 구간"]
//                내 샤드 동료 = **uid가 인접한 사람들**(대개 가입 시기가 비슷하다)
//
// 셋 다 폐기가 **무작위로** 일어나면 충돌률이 같다(≈ R/S). 축이 갈리는 것은 폐기가
// **무언가와 상관될 때**다. 그래서 상관 시나리오를 함께 돌린다.
//
// ── 시나리오 ─────────────────────────────────────────────────────────────
//   uniform      : 아무 사용자나 아무 때나 폐기된다. 기준선.
//   session-wave : 특정 시간 창에 로그인한 세션이 통째로 폐기된다.
//                  (예: RP 침해로 그 사이 발급된 세션을 전부 무효화)
//                  -> max_height 축이 직격탄을 맞는다.
//   cohort-burst : uid가 인접한 계정 무리가 통째로 폐기된다.
//                  (예: 같은 시기에 만들어진 봇 계정 일괄 차단)
//                  -> uid_range 축이 직격탄을 맞는다.
//
// ── 이 실험이 재지 않는 것 ───────────────────────────────────────────────
// 회수(만료 정리)로 인한 무효화는 축마다 성질이 다른데, 그건 시뮬레이션이 아니라
// **구조적으로** 결론이 난다. 아래 reclamationNote()가 그 근거를 함께 출력한다.
import fs from 'node:fs';
import { leafValue, TAG_SESSION } from '../lib/imt.js';
import {
  SESSION_RING, SESSION_VALUE_BITS, SESSION_SUBTREE_DEPTH, ACCOUNT_SUBTREE_DEPTH,
} from '../lib/imt_v3.js';

// ── 시스템 상수 (custom_idp.js와 같아야 한다) ────────────────────────────
const CREDENTIAL_LIFETIME_BLOCKS = 300;
const MAX_HEIGHT_SLACK_BLOCKS = 32;
const LIFETIME = CREDENTIAL_LIFETIME_BLOCKS + MAX_HEIGHT_SLACK_BLOCKS; // 332
const BLOCK_SECONDS = 12;
const BLOCKS_PER_DAY = Math.round((24 * 3600) / BLOCK_SECONDS);        // 7200

const RING = Number(SESSION_RING);          // 512
const VALUE_SPAN = 1 << SESSION_VALUE_BITS; // 8

// ── 인자 ─────────────────────────────────────────────────────────────────
function arg(name, dflt) {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? dflt : process.argv[i + 1];
}
const DAU = Number(arg('dau', 100_000_000));
const REVOKE_RATE = Number(arg('revoke-rate', 0.001));
const TRIALS = Number(arg('trials', 2000));
const SEED = Number(arg('seed', 1));
const SCENARIO = String(arg('scenario', 'all'));

// 재현 가능한 PRNG (mulberry32). Math.random을 쓰면 같은 시드로 다시 못 돌린다.
function makeRng(seed) {
  let a = seed >>> 0;
  return function rng() {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const randInt = (rng, n) => Math.floor(rng() * n);

// ── 축 정의 ──────────────────────────────────────────────────────────────
// 각 축은 (사용자, 크레덴셜) -> 샤드 인덱스. 샤드 수 S는 밖에서 준다 — 축의 효과와
// 샤드 개수의 효과를 분리해서 봐야 하기 때문이다.
//
// leafLowBits는 미리 계산해 둔다(Poseidon은 느리다).
function makeAxes(S) {
  const valueSpan = Math.min(VALUE_SPAN, S);
  const ringSlots = Math.max(1, Math.floor(S / valueSpan));
  return {
    // 현행 세션 층 규칙을 S에 맞춰 일반화한 것. S=4096이면 정확히 (mh mod 512)*8 + low3.
    max_height: (u) => (u.maxHeight % ringSlots) * valueSpan + (u.leafLow3 % valueSpan),
    // 현행 계정 층 규칙. 리프 해시의 하위 비트라 균등하다.
    uid_hash: (u) => u.leafLowBits % S,
    // 문자 그대로의 "uid 구간". 인접한 uid가 같은 샤드에 모인다.
    uid_range: (u) => Math.min(S - 1, Math.floor(u.uid / Math.ceil(DAU / S))),
  };
}
const AXIS_NAMES = ['max_height', 'uid_hash', 'uid_range'];

// ── 사용자/크레덴셜 생성 ─────────────────────────────────────────────────
//
// 리프 해시 비트는 **실제 Poseidon 출력**에서 가져온다. 축 비교의 핵심이 "해시 하위 비트가
// 균등한가"이므로 모형 난수로 대체하면 그 축만 부당하게 유리해진다.
//
// 다만 uid마다 그때그때 Poseidon을 부르면 1억 uid에서 캐시가 거의 맞지 않아 수천만 번
// 해싱하게 된다(수십 분 걸린다 — 실제로 그랬다). 그래서 **풀을 한 번 만들어 두고**
// uid -> pool[uid % P]로 쓴다:
//   · 같은 uid는 항상 같은 샤드로 간다(결정적)
//   · 비트 분포는 여전히 실제 Poseidon 출력의 분포다
//   · 인접한 uid는 인접한 풀 항목으로 가는데 그 해시들은 서로 무관하므로,
//     cohort-burst에서 uid_hash가 흩어지는 성질이 그대로 재현된다
const POOL_SIZE = Number(arg('pool', 100_000));
let POOL = null;

async function buildPool() {
  const low3 = new Uint8Array(POOL_SIZE);
  const lowBits = new Uint32Array(POOL_SIZE);
  for (let i = 0; i < POOL_SIZE; i++) {
    const leaf = await leafValue(TAG_SESSION, BigInt(i));
    low3[i] = Number(leaf & 7n);
    lowBits[i] = Number(leaf & 0xFFFFFn);
  }
  POOL = { low3, lowBits };
}

function makeCredential(uid, loginBlock, insertedAt = 0) {
  const k = uid % POOL_SIZE;
  return {
    uid,
    loginBlock,
    maxHeight: loginBlock + LIFETIME,
    leafLow3: POOL.low3[k],
    leafLowBits: POOL.lowBits[k],
    // 이 폐기가 트리에 들어간 블록. 척도 A(트랜잭션 1회)가 쓴다.
    insertedAt,
  };
}

// ── 시나리오: 내 크레덴셜 수명 동안 일어나는 폐기들을 만든다 ─────────────
//
// 규모의 근거. 내 크레덴셜은 LIFETIME(332블록 ≈ 66분) 산다. 그동안 발생하는 로그인은
// DAU × (332 / 7200)이고, 그 중 REVOKE_RATE만큼이 폐기된다.
function revocationsPerLifetime() {
  return Math.max(1, Math.round(DAU * (LIFETIME / BLOCKS_PER_DAY) * REVOKE_RATE));
}

//
// ── 모형: 삽입 시각을 먼저 뽑는다 (중요) ────────────────────────────────
//
// 내 증명을 무효화하려면 폐기가 **내 증명이 유효한 동안 트리에 들어와야** 한다. 그래서
// 먼저 삽입 시각 T를 내 수명 [t0, t0+L]에서 뽑고, **그 시점에 살아있는** 크레덴셜 하나를
// 고른다: 살아있으려면 max_height ∈ [T, T+L]이다(만료된 세션은 /idp/revoke가 410으로 막는다).
//
// 처음에는 폐기의 로그인 블록을 [t0-L, t0+L]에서 균등하게 뽑았는데 **틀렸다.** 그러면
// max_height가 폭 2L에 걸쳐 균등해지는데, 실제로는 삽입 시각마다 폭 L 창이 슬라이딩하며
// 겹쳐 **삼각 분포**가 되고 그 꼭대기가 하필 내 max_height 자리다. 그 오류는 max_height
// 축의 충돌을 실제보다 낮게 보이게 만들었다(관측 0.91 vs 올바른 값 ~1.4).
//
// 올바른 모형이 드러내는 것: 링은 512칸이지만 어느 순간에도 **살아있는 크레덴셜이 들어
// 있는 칸은 L=332칸뿐**이다. 나머지 180칸은 비어 있다(그래서 리셋 창이 열린다). 따라서
// 세션 축의 **실효 샤드 수는 4,096이 아니라 332 × 8 = 2,656**이다.
function drawScenario(name, rng, victim, R) {
  const out = [];
  const t0 = victim.loginBlock;                 // 내 증명이 유효한 구간 = [t0, t0+LIFETIME]
  // 삽입 시각 T에 살아있는 크레덴셜 하나를 고른다: max_height ∈ [T, T+LIFETIME].
  const liveAt = (T) => T + randInt(rng, LIFETIME) - LIFETIME; // = 그 크레덴셜의 loginBlock

  if (name === 'uniform') {
    // 아무 사용자나, 내 수명 중 아무 때나 폐기된다.
    for (let i = 0; i < R; i++) {
      const T = t0 + randInt(rng, LIFETIME);
      out.push(makeCredential(randInt(rng, DAU), liveAt(T), T));
    }
  } else if (name === 'session-wave') {
    // 특정 시간 창(10블록 = 2분)에 로그인한 세션이 한꺼번에 폐기된다.
    // 그 세션들은 폐기 시점 T_w에 살아 있어야 하므로 창은 [T_w-L, T_w-10] 안에 있다.
    const Tw = t0 + randInt(rng, LIFETIME);
    const waveWidth = 10;
    const waveStart = Tw - LIFETIME + randInt(rng, LIFETIME - waveWidth);
    for (let i = 0; i < R; i++) {
      // wave는 한 시점에 통째로 들어간다.
      out.push(makeCredential(randInt(rng, DAU), waveStart + randInt(rng, waveWidth), Tw));
    }
  } else if (name === 'cohort-burst') {
    // uid가 인접한 계정 무리가 통째로 폐기된다. 로그인 시각은 평범하게 흩어져 있다.
    const cohortStart = randInt(rng, Math.max(1, DAU - R));
    for (let i = 0; i < R; i++) {
      const T = t0 + randInt(rng, LIFETIME);
      out.push(makeCredential(cohortStart + i, liveAt(T), T));
    }
  } else {
    throw new Error(`unknown scenario ${name}`);
  }
  return out;
}

// ── 한 시나리오 × 한 샤드 수에 대해 축별 부수 무효화를 센다 ──────────────
function runScenario(name, S, rng, Roverride) {
  const axes = makeAxes(S);
  const R = Roverride ?? revocationsPerLifetime();
  const hits = Object.fromEntries(AXIS_NAMES.map((a) => [a, []]));
  // 척도 A용: 시행마다 (내 증명 유효 구간 t0, 내 샤드에 들어온 폐기들의 삽입 시각)
  const timeline = Object.fromEntries(AXIS_NAMES.map((a) => [a, []]));
  // 척도 C용: 시행마다 **가장 붐비는 샤드의 리프 수**.
  //
  // 관측 창을 LIFETIME으로 잡는 근거: 그보다 오래된 리프는 만료돼 회수된다(세션은 샤드
  // 리셋, 계정은 샤드 재기준화). 그래서 한 샤드에 동시에 존재할 수 있는 리프 수는
  // 대략 "최근 LIFETIME 동안 그 샤드로 라우팅된 폐기 수"다 — 그것이 서브트리 용량과
  // 직접 비교할 값이다.
  const peakOccupancy = Object.fromEntries(AXIS_NAMES.map((a) => [a, []]));

  for (let t = 0; t < TRIALS; t++) {
    // 피해자: 아무 uid, 아무 로그인 블록.
    const victim = makeCredential(randInt(rng, DAU), randInt(rng, BLOCKS_PER_DAY));
    const revs = drawScenario(name, rng, victim, R);

    for (const a of AXIS_NAMES) {
      const mine = axes[a](victim);
      let n = 0;
      // drawScenario가 이미 "내 수명 안에 삽입되고 그때 살아있던" 것만 만든다.
      const times = [];
      for (const r of revs) if (axes[a](r) === mine) { n += 1; times.push(r.insertedAt); }
      hits[a].push(n);
      timeline[a].push({ t0: victim.loginBlock, times });

      // 이 회차 폐기 전체를 샤드별로 세어 최대 점유를 본다.
      const load = new Map();
      for (const r of revs) {
        const sh = axes[a](r);
        load.set(sh, (load.get(sh) ?? 0) + 1);
      }
      let peak = 0;
      for (const v of load.values()) if (v > peak) peak = v;
      peakOccupancy[a].push(peak);
    }
  }
  return { name, S, R, hits, timeline, peakOccupancy };
}

// ── 집계 ─────────────────────────────────────────────────────────────────
function stats(xs) {
  const sorted = [...xs].sort((a, b) => a - b);
  const mean = xs.reduce((s, x) => s + x, 0) / xs.length;
  const q = (p) => sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))];
  return {
    mean,
    p50: q(0.5),
    p95: q(0.95),
    p99: q(0.99),
    max: sorted[sorted.length - 1],
    anyRate: xs.filter((x) => x > 0).length / xs.length,
  };
}

/**
 * 회수(만료 정리)로 인한 무효화는 시뮬레이션이 아니라 구조로 결론이 난다.
 * 이 차이가 실험 결과만큼 중요해서 함께 출력한다.
 */
function reclamationNote() {
  return [
    '## 회수(만료 정리)로 인한 무효화 — 시뮬레이션이 아니라 구조적 결론',
    '',
    '  max_height 축: **살아있는 증명을 절대 무효화하지 않는다.**',
    '    샤드를 통째로 비우는 조건이 "그 샤드의 발급된 모든 크레덴셜이 이미 만료"이고,',
    '    컨트랙트가 block.number만으로 그것을 검증한다(d = (k - B) mod 512 > 332).',
    '    즉 리셋되는 샤드에는 살아있는 크레덴셜이 존재할 수 없다.',
    '',
    '  uid_hash / uid_range 축: **살아있는 증명을 무효화한다.**',
    '    만료가 샤드 인덱스에 들어 있지 않으므로 통째로 비울 수 없고, 살아있는 값만',
    '    다시 쌓는 샤드 단위 재기준화로 회수한다. 그 샤드의 root가 바뀌므로, 같은 샤드에',
    '    있는 **만료되지 않은** 폐기의 이웃들도 증명을 다시 만들어야 한다.',
    '',
    '  이 비대칭은 위 표의 폐기 충돌과 별개로 더해진다.',
  ].join('\n');
}

// ── 실행 ─────────────────────────────────────────────────────────────────
const scenarios = SCENARIO === 'all'
  ? ['uniform', 'session-wave', 'cohort-burst']
  : [SCENARIO];

// 두 가지로 본다:
//   4096 — 축의 효과만 분리해 보기 위해 셋을 같은 샤드 수로 맞춘 비교
//   (현행) 세션 4096 / 계정 256 — 실제 배포된 값. 표 아래에 따로 적는다.
const SHARD_COUNTS = [4096, 256];

console.log(`# 샤딩 축별 부수 무효화 실험`);
console.log('');
console.log(`DAU ${DAU.toLocaleString()} / 폐기율 ${(REVOKE_RATE * 100).toFixed(3)}% / 시드 ${SEED} / 표본 ${TRIALS}`);
console.log(`크레덴셜 수명 ${LIFETIME}블록 (${(LIFETIME * BLOCK_SECONDS / 60).toFixed(0)}분), 블록 ${BLOCK_SECONDS}초`);
console.log(`수명 동안 발생하는 폐기 R = ${revocationsPerLifetime().toLocaleString()}건`);
console.log('');

process.stderr.write(`  … 리프 해시 풀 ${POOL_SIZE.toLocaleString()}개 생성 중\n`);
await buildPool();

const rows = [];
for (const S of SHARD_COUNTS) {
  console.log(`## 샤드 ${S.toLocaleString()}개`);
  console.log('');
  console.log('| 시나리오 | 축 | 무효화 확률 | 평균 | p95 | p99 | 최대 |');
  console.log('|:--|:--|--:|--:|--:|--:|--:|');
  for (const sc of scenarios) {
    const rng = makeRng(SEED + S);           // 시나리오 간 비교가 같은 난수열을 쓰도록
    const res = runScenario(sc, S, rng);
    for (const a of AXIS_NAMES) {
      const st = stats(res.hits[a]);
      console.log(
        `| ${sc} | ${a} | ${(st.anyRate * 100).toFixed(1)}% | ${st.mean.toFixed(2)} | ` +
        `${st.p95} | ${st.p99} | ${st.max} |`,
      );
      rows.push({ shards: S, scenario: sc, axis: a, R: res.R, ...st });
    }
  }
  console.log('');
}

// ── 척도 A: 트랜잭션 1회 기준 ────────────────────────────────────────────
//
// 위 표는 "세션 수명 전체(66분) 동안 한 번이라도" 기준이다. 트랜잭션 하나만 놓고 보면
// 노출 창이 훨씬 짧다: **마지막으로 증명을 만든 시점부터 지금 제출까지**만 문제다.
// (wallet_agent.js의 shouldReuseProof가 sessRoot/acctRoot 불변을 조건으로 캐시를 재사용한다.)
//
// 그래서 트랜잭션 간격 Δ를 파라미터로 두고, 무작위 제출 시각 직전 Δ블록 안에 내 샤드로
// 폐기가 들어왔을 확률을 잰다 = **이번 트랜잭션에서 캐시가 빗나갈 확률**.
const TX_GAPS = [1, 10, 60];   // 블록. 12초 / 2분 / 12분
function cacheMissRate(timelineForAxis, gap, rng) {
  let miss = 0;
  for (const { t0, times } of timelineForAxis) {
    // 제출 시각을 내 증명 유효 구간에서 무작위로 잡는다. 그 직전 gap블록이 노출 창이다.
    const tSub = t0 + randInt(rng, LIFETIME);
    if (times.some((T) => T > tSub - gap && T <= tSub)) miss += 1;
  }
  return miss / timelineForAxis.length;
}

// ── 척도 B: 세션당 재증명 횟수와 그 비용 ────────────────────────────────
//
// 무효화 1회 = IdP에서 내 샤드 재조회 + pi_pk_i 재생성. 증명 시간은 실측값을 쓴다
// (results/mode2_pi_pk_i_v3_proof_20260906.csv, warm 5회 평균 507.2 ms).
const REPROVE_MS = 507.2;

console.log('## 척도 A — 트랜잭션 1회 기준 캐시 미스율 (샤드 4,096, 축 비교)');
console.log('');
console.log('| 시나리오 | 축 | Δ=1블록(12초) | Δ=10블록(2분) | Δ=60블록(12분) |');
console.log('|:--|:--|--:|--:|--:|');
for (const sc of scenarios) {
  const rng = makeRng(SEED + 4096);
  const res = runScenario(sc, 4096, rng);
  for (const a of AXIS_NAMES) {
    const cells = TX_GAPS.map((g) => `${(cacheMissRate(res.timeline[a], g, makeRng(SEED + g)) * 100).toFixed(2)}%`);
    console.log(`| ${sc} | ${a} | ${cells.join(' | ')} |`);
    rows.push({ shards: 4096, scenario: `txgap:${sc}`, axis: a, R: res.R,
                anyRate: Number(cells[1].replace('%','')) / 100, mean: 0, p50: 0, p95: 0, p99: 0, max: 0 });
  }
}
console.log('');

console.log('## 척도 B — 세션(66분) 하나당 재증명 횟수와 지연 (샤드 4,096, 축 비교)');
console.log('');
// p95만 보면 분포가 두 갈래인 행을 놓친다(대다수 0, 소수가 수십 회). p99와 최대를 함께 낸다.
console.log('| 시나리오 | 축 | 평균 재증명 | p95 | p99 | 최대 | 평균 지연 | 최악 지연 |');
console.log('|:--|:--|--:|--:|--:|--:|--:|--:|');
for (const sc of scenarios) {
  const rng = makeRng(SEED + 4096);
  const res = runScenario(sc, 4096, rng);
  for (const a of AXIS_NAMES) {
    const st = stats(res.hits[a]);
    console.log(
      `| ${sc} | ${a} | ${st.mean.toFixed(2)}회 | ${st.p95} | ${st.p99} | ${st.max} | ` +
      `${(st.mean * REPROVE_MS / 1000).toFixed(2)}초 | ${(st.max * REPROVE_MS / 1000).toFixed(1)}초 |`,
    );
  }
}
console.log('');
console.log(`(재증명 1회 = ${REPROVE_MS} ms, 실측 warm 평균. IdP 샤드 재조회 왕복은 별도다.)`);
console.log('');

// ── 척도 C: 샤드 점유 vs 서브트리 용량 ──────────────────────────────────
//
// 무효화는 지연(507 ms 재증명)이지만 **용량 초과는 보안 기능 정지**다. 서브트리가 꽉 차면
// lib/imt_v2.js의 insert()가 던지고, 그 폐기는 게시 자체가 되지 않는다. 앞의 척도들이
// 전혀 보지 못하는 실패라 따로 잰다.
//
// 집중형 축이 무효화 지표에서 이기는 바로 그 성질이 여기서는 정확히 불리하게 작용한다.
const SESSION_SUBTREE_CAPACITY = 2 ** SESSION_SUBTREE_DEPTH - 1;   // 255 (anchor 제외)
const ACCOUNT_SUBTREE_CAPACITY = 2 ** ACCOUNT_SUBTREE_DEPTH - 1;   // 1023

console.log('## 척도 C — 가장 붐비는 샤드의 리프 수 vs 서브트리 용량 (샤드 4,096)');
console.log('');
console.log(`서브트리 용량: 세션(깊이 ${SESSION_SUBTREE_DEPTH}) ${SESSION_SUBTREE_CAPACITY}리프 / ` +
            `계정(깊이 ${ACCOUNT_SUBTREE_DEPTH}) ${ACCOUNT_SUBTREE_CAPACITY}리프`);
console.log('');
console.log('| 시나리오 | 축 | 최대 점유(평균) | 최대 점유(최악) | 세션 용량 대비 | 계정 용량 대비 |');
console.log('|:--|:--|--:|--:|--:|--:|');
for (const sc of scenarios) {
  const rng = makeRng(SEED + 4096);
  const res = runScenario(sc, 4096, rng);
  for (const a of AXIS_NAMES) {
    const st = stats(res.peakOccupancy[a]);
    const sPct = (st.max / SESSION_SUBTREE_CAPACITY) * 100;
    const aPct = (st.max / ACCOUNT_SUBTREE_CAPACITY) * 100;
    const mark = (p) => (p > 100 ? `**${p.toFixed(0)}% 초과**` : `${p.toFixed(0)}%`);
    console.log(
      `| ${sc} | ${a} | ${st.mean.toFixed(0)} | ${st.max} | ${mark(sPct)} | ${mark(aPct)} |`,
    );
    rows.push({ shards: 4096, scenario: `peak:${sc}`, axis: a, R: res.R,
                anyRate: 0, mean: st.mean, p50: st.p50, p95: st.p95, p99: st.p99, max: st.max });
  }
}
console.log('');
console.log('“초과”는 그 시나리오에서 서브트리가 꽉 차 insert()가 던진다는 뜻이다 —');
console.log('폐기가 지연되는 것이 아니라 **게시되지 않는다**.');
console.log('');

// ── 척도 C-2: 몇 건짜리 사건부터 서브트리가 넘치는가 ────────────────────
//
// "지금 규모에서 안전한가"보다 실무적으로 중요한 것은 **얼마나 여유가 있는가**다.
// 시나리오별로 폐기 건수를 두 배씩 올리며 최대 점유가 용량을 넘는 지점을 찾는다.
// (평균 최대점유 기준. 표본을 줄여 빠르게 훑는다.)
function overflowThresholds(scenario, axis, S, capacities) {
  const TRIALS_LIGHT = 40;
  const R_MAX = 262_144;               // 2^18. 이보다 큰 사건은 "—"로 둔다.
  const axes = makeAxes(S);
  const found = capacities.map(() => null);
  for (let R = 64; R <= R_MAX; R *= 2) {
    const rng = makeRng(SEED + 77);
    let peakSum = 0;
    for (let t = 0; t < TRIALS_LIGHT; t++) {
      const victim = makeCredential(randInt(rng, DAU), randInt(rng, BLOCKS_PER_DAY));
      const revs = drawScenario(scenario, rng, victim, R);
      const load = new Map();
      for (const r of revs) {
        const sh = axes[axis](r);
        load.set(sh, (load.get(sh) ?? 0) + 1);
      }
      let peak = 0;
      for (const v of load.values()) if (v > peak) peak = v;
      peakSum += peak;
    }
    const meanPeak = peakSum / TRIALS_LIGHT;
    // 두 용량을 한 번의 측정으로 함께 판정한다(따로 돌면 일이 두 배가 된다).
    capacities.forEach((cap, k) => { if (found[k] === null && meanPeak > cap) found[k] = R; });
    if (found.every((x) => x !== null)) break;
  }
  return found;
}

console.log('## 척도 C-2 — 서브트리가 넘치기 시작하는 사건 규모 (샤드 4,096)');
console.log('');
console.log('| 시나리오 | 축 | 세션 용량(255) 초과 | 계정 용량(1023) 초과 |');
console.log('|:--|:--|--:|--:|');
for (const sc of scenarios) {
  for (const a of AXIS_NAMES) {
    const fmt = (x) => (x === null ? '> 262,144건' : `${x.toLocaleString()}건`);
    const [sT, aT] = overflowThresholds(sc, a, 4096,
      [SESSION_SUBTREE_CAPACITY, ACCOUNT_SUBTREE_CAPACITY]);
    console.log(`| ${sc} | ${a} | ${fmt(sT)} | ${fmt(aT)} |`);
  }
}
console.log('');
console.log(`(현재 기준 규모는 수명당 ${revocationsPerLifetime().toLocaleString()}건. 그보다 작은 값이 나오면 이미 넘친다는 뜻이다.)`);
console.log('');

// ── 현행 배포 구성: 세션(max_height, 4096) vs 계정(uid_hash, 256) ────────
// 위 표는 축의 효과를 분리하려고 샤드 수를 맞춘 것이다. 실제 시스템은 두 층이 서로 다른
// 축과 서로 다른 샤드 수를 쓰므로, 그 조합을 그대로 비교해 둔다 — 운영에서 실제로
// 보게 되는 숫자다.
console.log('## 현행 배포 구성 — 세션 층(max_height, 4096) vs 계정 층(uid_hash, 256)');
console.log('');
console.log('| 시나리오 | 층 | 무효화 확률 | 평균 | p95 | 최대 |');
console.log('|:--|:--|--:|--:|--:|--:|');
for (const sc of scenarios) {
  for (const [layer, S, axis] of [['세션 (max_height, 4096)', 4096, 'max_height'],
                                  ['계정 (uid_hash, 256)', 256, 'uid_hash']]) {
    const rng = makeRng(SEED + 1000);
    const res = runScenario(sc, S, rng);
    const st = stats(res.hits[axis]);
    console.log(
      `| ${sc} | ${layer} | ${(st.anyRate * 100).toFixed(1)}% | ${st.mean.toFixed(2)} | ${st.p95} | ${st.max} |`,
    );
    rows.push({ shards: S, scenario: `deployed:${sc}`, axis, R: res.R, ...st });
  }
}
console.log('');

// ── 규모 민감도 (uniform 기준) ───────────────────────────────────────────
// "몇 명 규모부터 캐시된 증명이 사실상 매번 무효화되는가"가 실무적으로 가장 중요한 질문이다.
// 세션 층은 **실효 샤드 수**를 쓴다. 링은 512칸이지만 어느 순간에도 살아있는 크레덴셜이
// 들어 있는 칸은 LIFETIME(332)칸뿐이므로, 실효값은 4,096이 아니라 332 × 8 = 2,656이다.
const SESSION_EFFECTIVE_SHARDS = LIFETIME * VALUE_SPAN;   // 2,656
console.log('## 규모 민감도 — uniform 시나리오');
console.log('');
console.log(`세션 층의 실효 샤드 수는 명목 4,096이 아니라 **${SESSION_EFFECTIVE_SHARDS.toLocaleString()}**이다`);
console.log('(링 512칸 중 살아있는 크레덴셜이 들어 있는 칸은 수명 332칸뿐 × 값축 8).');
console.log('');
console.log('| DAU | 폐기율 | 수명당 폐기 R | 세션(실효 2,656) | 계정(256) |');
console.log('|--:|--:|--:|--:|--:|');
for (const dau of [1_000_000, 10_000_000, 100_000_000]) {
  for (const rate of [0.0001, 0.001]) {
    const R = Math.max(1, Math.round(dau * (LIFETIME / BLOCKS_PER_DAY) * rate));
    // 균등 분포에서 내 샤드를 한 번도 안 맞을 확률은 (1 - 1/S)^R.
    const p = (S) => 1 - Math.pow(1 - 1 / S, R);
    console.log(
      `| ${dau.toLocaleString()} | ${(rate * 100).toFixed(2)}% | ${R.toLocaleString()} | ` +
      `${(p(SESSION_EFFECTIVE_SHARDS) * 100).toFixed(1)}% | ${(p(256) * 100).toFixed(1)}% |`,
    );
  }
}
console.log('');

console.log(reclamationNote());
console.log('');

const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
const out = `results/shard_axis_collateral_${stamp}.csv`;
fs.mkdirSync('results', { recursive: true });
fs.writeFileSync(
  out,
  `# 샤딩 축별 부수 무효화. DAU=${DAU} revokeRate=${REVOKE_RATE} trials=${TRIALS} seed=${SEED}\n` +
  '# anyRate = 수명 동안 내 증명이 한 번이라도 무효화될 확률\n' +
  'shards,scenario,axis,revocations_per_lifetime,any_rate,mean,p50,p95,p99,max\n' +
  rows.map((r) =>
    `${r.shards},${r.scenario},${r.axis},${r.R},${r.anyRate.toFixed(4)},${r.mean.toFixed(4)},` +
    `${r.p50},${r.p95},${r.p99},${r.max}`).join('\n') + '\n',
);
console.log(`wrote ${out}`);
process.exit(0);
