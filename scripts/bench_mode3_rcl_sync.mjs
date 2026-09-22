// RCL 동기화 실측: 전체 재생 vs 캐시 복원 vs 델타 (스펙 2026-09-23 §7).
//   node scripts/bench_mode3_rcl_sync.mjs [반복=5]        (:8545 hardhat 노드 필요)
// 임시 RevocationLog 를 배포하고 리프 N ∈ {0, 100, 1000} 을 50개씩 게시한 뒤, 각 N 에서
//   (a) syncRevocationTree — 창세기부터 전체 재생
//   (b) 새 createRevocationSync 의 첫 sync() — 캐시 복원(+델타 0)
//   (c) 리프 1개 게시 뒤 sync() — 델타 1
//   (d) 블록 변화 없이 sync() — 델타 0(getLogs 없음)
// 의 벽시계 시간을 반복 측정해 중앙값(최소–최대)을 Markdown 표로 stdout 에 낸다. results/mode3_rcl_sync_<YYYYMMDD>.md 로 저장한다(새 파일).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ethers } from 'ethers';
import { getProvider, fundAddress, deployRevocationLog, signRootPublication, rootToBytes32 } from '../tests/helpers/mode3_chain.mjs';
import { createRevocationTree } from '../lib/mode3_revocation.js';
import { syncRevocationTree } from '../lib/mode3_wallet.js';
import { createRevocationSync } from '../lib/mode3_rcl_sync.js';

const REPS = Number(process.argv[2] || 5);
const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
const fmt = (a) => `${med(a).toFixed(0)} (${Math.min(...a).toFixed(0)}–${Math.max(...a).toFixed(0)})`;
const now = () => performance.now();

const provider = getProvider();
const ciaEth = ethers.Wallet.createRandom().connect(provider);
await fundAddress(ciaEth.address, '5', provider);
const { address: logAddress, contract: log } = await deployRevocationLog(ciaEth.address, provider);
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-rcl-bench-'));
const cacheFile = path.join(dir, 'mode3_wallet_rcl.json');

// CIA 흉내: 로컬 트리를 유지하며 리프를 게시한다(매번 이벤트를 다시 읽지 않는다 — 벤치 자체가 느려지지 않게)
const ciaTree = await createRevocationTree();
let nextLeaf = 1_000_001n;
async function publish(count) {
  const leavesBig = [];
  for (let i = 0; i < count; i++) { leavesBig.push(nextLeaf); await ciaTree.insert(nextLeaf); nextLeaf++; }
  const root = rootToBytes32(ciaTree.getRoot());
  const epoch = (await log.epoch()) + 1n;
  const leaves = leavesBig.map(rootToBytes32);
  const sig = await signRootPublication(ciaEth, { logAddress, root, epoch, leaves });
  await (await log.connect(ciaEth).publishRoot(root, epoch, leaves, sig)).wait();
}

const rows = [];
let total = 0;
for (const N of [0, 100, 1000]) {
  while (total < N) { const c = Math.min(50, N - total); await publish(c); total += c; }
  const startTotal = total;                    // 라벨은 측정 **시작 시** 리프 수 — 반복마다 델타 1개가 더해진다
  const full = [], restore = [], delta1 = [], delta0 = [];
  for (let i = 0; i < REPS; i++) {
    let t = now(); await syncRevocationTree(provider, logAddress); full.push(now() - t);
    // 캐시를 채운 뒤 새 인스턴스로 복원 시간을 잰다
    const warm = createRevocationSync({ provider, logAddress, cacheFile, log: () => {} });
    await warm.sync();
    const cold = createRevocationSync({ provider, logAddress, cacheFile, log: () => {} });
    t = now(); const r = await cold.sync(); restore.push(now() - t);
    if (r.mode !== 'restore') throw new Error(`복원이어야 한다: ${r.mode}`);
    await publish(1); total += 1;
    t = now(); const d1 = await cold.sync(); delta1.push(now() - t);
    if (d1.mode !== 'delta') throw new Error(`델타여야 한다: ${d1.mode}`);
    t = now(); await cold.sync(); delta0.push(now() - t);
  }
  rows.push({ N: startTotal, full, restore, delta1, delta0 });
}

// 로컬 날짜로 이름을 짓는다(toISOString 은 UTC 라 KST 새벽에 돌리면 전날 이름이 된다 — results/ 는 재현성 산출물이다).
const d = new Date();
const date = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
let md = `## Mode 3 RCL 동기화 실측 (반복 ${REPS}, 중앙값 (최소–최대), ms)\n\n`;
md += `hardhat 로컬 노드, 임시 RevocationLog, 리프는 50개씩 게시. N 은 측정 시작 시의 리프 수 — 반복마다 델타 1개가 더해지므로 마지막 반복은 N+${REPS - 1} 리프에서 잰 값이다.\n\n`;
md += `| 리프 N | (a) 전체 재생 syncRevocationTree | (b) 캐시 복원 첫 sync | (c) 델타 1 | (d) 델타 0 |\n|--:|--:|--:|--:|--:|\n`;
for (const r of rows) md += `| ${r.N} | ${fmt(r.full)} | ${fmt(r.restore)} | ${fmt(r.delta1)} | ${fmt(r.delta0)} |\n`;
md += `\n(a) 는 로그인마다 내던 비용(옛 동작), (c)/(d) 가 새 동작의 로그인당 비용, (b) 는 에이전트 재시작 1회 비용이다.\n`;
console.log(md);
const out = path.join('results', `mode3_rcl_sync_${date}.md`);
if (fs.existsSync(out)) console.error(`이미 있음 — 덮어쓰지 않는다: ${out}`); else { fs.writeFileSync(out, md); console.error(`저장: ${out}`); }
fs.rmSync(dir, { recursive: true, force: true });
provider.destroy();
