// 폐기 트리 삽입 비용 실측 — lib/imt.js(v1) vs lib/imt_v2.js(v2).
//
//   node scripts/bench_imt_v2.mjs                # n = 1000 8000 32000
//   node scripts/bench_imt_v2.mjs 1000 4000      # n을 직접 지정
//
// 무엇을 재는가.
//
//  (A) 증분 반영 비용 — 폐기가 **하나 더** 게시됐을 때, 지갑이 새 root와 새
//      비멤버십 witness를 손에 넣기까지의 비용. 트랜잭션마다 치르는 값이다.
//        v1: insert(배열 정렬) + getRoot(전체 재구성) + witness(또 전체 재구성)
//        v2: insert(경로 2개 갱신) + getRoot(캐시) + witness(경로 읽기)
//      v1은 n에 비례해 커지고 v2는 거의 평평해야 한다. 이 스크립트의 요점이다.
//
//  (B) 콜드 구성 비용 — n개짜리 트리를 처음부터 쌓는 비용. 둘 다 O(n)이라
//      비슷해야 정상이다(v2는 재기준화/첫 동기화에서만 이 비용을 치른다).
//
// 파일을 쓰지 않고 stdout에만 출력한다.
import { createIMT } from '../lib/imt.js';
import { buildIMTv2 } from '../lib/imt_v2.js';

const SIZES = process.argv.slice(2).length
  ? process.argv.slice(2).map((x) => Number(x))
  : [1000, 8000, 32000];

// 재현 가능한 252비트 의사난수 값. Poseidon을 돌리면(leafValue) 값 생성만으로
// 수 초가 날아가는데, 이 벤치가 재는 건 트리 연산이지 리프 값 유도가 아니다.
function makeValues(count, seed) {
  let s = BigInt(seed) | 1n;
  const M = (1n << 64n) - 1n;
  const next = () => {
    s = (s * 6364136223846793005n + 1442695040888963407n) & M;
    return s >> 8n; // 상위 비트가 더 고르다
  };
  const seen = new Set();
  const out = [];
  const MASK_252 = (1n << 252n) - 1n;
  while (out.length < count) {
    const v = ((next() << 168n) ^ (next() << 84n) ^ next()) & MASK_252;
    if (v === 0n || seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

function ms(t0) {
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

async function timed(fn) {
  const t0 = process.hrtime.bigint();
  const r = await fn();
  return { ms: ms(t0), value: r };
}

// 여분의 값으로 marginal insert를 reps번 반복해 평균을 낸다.
async function measureIncremental(tree, extras, reps, witnessTarget) {
  let insertTotal = 0;
  let rootTotal = 0;
  let witnessTotal = 0;
  for (let r = 0; r < reps; r++) {
    const i = await timed(() => tree.insert(extras[r]));
    insertTotal += i.ms;
    const g = await timed(async () => tree.getRoot());
    rootTotal += g.ms;
    const w = await timed(() => tree.getNonMembershipWitness(witnessTarget));
    witnessTotal += w.ms;
  }
  return {
    insert: insertTotal / reps,
    root: rootTotal / reps,
    witness: witnessTotal / reps,
    total: (insertTotal + rootTotal + witnessTotal) / reps,
  };
}

async function main() {
  const rows = [];

  // JIT/Poseidon 워밍업. 없으면 첫 크기의 콜드 구성 비용에 컴파일 시간이 섞여
  // n=200이 n=500보다 느리게 나오는 식으로 표가 망가진다.
  {
    const warm = makeValues(300, 1);
    const t1 = await createIMT(20);
    for (const v of warm) await t1.insert(v);
    t1.getRoot();
    const t2 = await buildIMTv2(20, warm);
    await t2.getNonMembershipWitness(1n);
  }

  for (const n of SIZES) {
    const values = makeValues(n + 64, n * 7919);
    const base = values.slice(0, n);
    const extras = values.slice(n);
    // 어떤 값도 트리에 없어야 witness가 나온다. extras의 마지막 값을 쓴다.
    const witnessTarget = extras[extras.length - 1];

    const repsV1 = n >= 8000 ? 3 : 10;
    const repsV2 = 30;

    // ---- v1 (lib/imt.js) ----
    const v1Cold = await timed(async () => {
      const t = await createIMT(20);
      for (const v of base) await t.insert(v);
      t.getRoot(); // 캐시가 없으므로 매번 전체 재구성
      return t;
    });
    const v1 = await measureIncremental(v1Cold.value, extras, repsV1, witnessTarget);

    // ---- v2 (lib/imt_v2.js) ----
    const v2Cold = await timed(() => buildIMTv2(20, base));
    const v2 = await measureIncremental(v2Cold.value, extras, repsV2, witnessTarget);

    rows.push({ n, v1Cold: v1Cold.ms, v1, v2Cold: v2Cold.ms, v2, repsV1, repsV2 });
    console.error(`  … n=${n} done`);
  }

  const f = (x) => x.toFixed(x < 10 ? 3 : 1);

  console.log('');
  console.log('## (A) 증분 반영 비용 — 폐기 1건이 더 게시됐을 때 지갑이 치르는 비용 (ms, 평균)');
  console.log('');
  console.log('| n | v1 insert | v1 getRoot | v1 witness | **v1 합계** | v2 insert | v2 getRoot | v2 witness | **v2 합계** | 배율 |');
  console.log('|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|');
  for (const r of rows) {
    console.log(
      `| ${r.n.toLocaleString()} | ${f(r.v1.insert)} | ${f(r.v1.root)} | ${f(r.v1.witness)} | **${f(r.v1.total)}** `
      + `| ${f(r.v2.insert)} | ${f(r.v2.root)} | ${f(r.v2.witness)} | **${f(r.v2.total)}** `
      + `| ${(r.v1.total / r.v2.total).toFixed(1)}x |`,
    );
  }

  console.log('');
  console.log('## (B) 콜드 구성 비용 — n개 리프 트리를 처음부터 (ms)');
  console.log('');
  console.log('| n | v1 | v2 |');
  console.log('|---:|---:|---:|');
  for (const r of rows) {
    console.log(`| ${r.n.toLocaleString()} | ${f(r.v1Cold)} | ${f(r.v2Cold)} |`);
  }

  console.log('');
  console.log(`반복 횟수: v1 ${rows[0].repsV1}회(n>=8000이면 3회), v2 ${rows[0].repsV2}회. node ${process.version}.`);
  console.log('');
  const first = rows[0].v2.total;
  const last = rows[rows.length - 1].v2.total;
  console.log(
    `v2 증분 비용은 n=${rows[0].n.toLocaleString()} -> n=${rows[rows.length - 1].n.toLocaleString()} 에서 `
    + `${f(first)} -> ${f(last)} ms (${(last / first).toFixed(2)}x). `
    + `같은 구간에서 v1은 ${f(rows[0].v1.total)} -> ${f(rows[rows.length - 1].v1.total)} ms `
    + `(${(rows[rows.length - 1].v1.total / rows[0].v1.total).toFixed(1)}x).`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
