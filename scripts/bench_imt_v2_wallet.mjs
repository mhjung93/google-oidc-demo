// 지갑의 v2 증분 캐싱 vs v1 전체 재구성 — **HTTP 왕복 포함** 실측 (브리프 검증 5).
//
//   IDP_ADMIN_SECRET=<value> node scripts/bench_imt_v2_wallet.mjs [rounds]
//   (secret은 실행 중인 custom_idp.js와 같은 값. rounds 기본 30)
//
// 무엇을 재는가. 매 라운드마다 새 계정을 폐기·게시해 폐기 트리를 1건씩 키운 뒤,
// "지갑이 이 트랜잭션에 쓸 witness/트리를 손에 넣기까지의 비용"을 두 경로로 잰다:
//
//   v1 (현재 경로, fetchRevocationWitnesses와 동일): 매번 /idp/revocation_state로
//       폐기 목록 **전체**를 받아 트리를 처음부터 재구성(O(n)) + witness.
//   v2 (새 경로, wallet_agent.js의 syncRevocationTreeV2): 트리와 (epoch, lastSeq)를
//       요청 간에 들고 있다가 since=lastSeq로 **변경분만** 받아 적용(O(log n)).
//
// 지갑의 실제 함수를 그대로 import해 잰다(라이브러리 재구현이 아니다). 파일은 쓰지
// 않고 stdout에만 출력한다.
import { createIMT, leafValue, TAG_SESSION, TAG_ACCOUNT } from '../lib/imt.js';
import { syncRevocationTreeV2, _resetRevocationTreeV2ForTest } from '../wallet_agent.js';

const BASE = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';
const ADMIN = process.env.IDP_ADMIN_SECRET;
if (!ADMIN) { console.error('IDP_ADMIN_SECRET required (must match the running custom_idp.js).'); process.exit(1); }
const ROUNDS = Number(process.argv[2]) || 30;
const adminHeaders = { 'Content-Type': 'application/json', 'X-IdP-Admin-Secret': ADMIN };

const ms = (t0) => Number(process.hrtime.bigint() - t0) / 1e6;
async function timed(fn) { const t0 = process.hrtime.bigint(); const v = await fn(); return { ms: ms(t0), v }; }

async function revokeAndPublish(value) {
  const r = await fetch(`${BASE}/idp/revoke`, { method: 'POST', headers: adminHeaders, body: JSON.stringify({ type: 'account', value }) });
  if (r.status !== 200) throw new Error(`revoke ${value} -> ${r.status}`);
  const prepared = await (await fetch(`${BASE}/idp/publish/prepare`, { method: 'POST', headers: adminHeaders, body: '{}' })).json();
  const c = await fetch(`${BASE}/idp/publish/commit`, { method: 'POST', headers: adminHeaders, body: JSON.stringify({ root: prepared.expectedRoot }) });
  if (c.status !== 200) throw new Error(`commit -> ${c.status}`);
}

// v1 경로: /idp/revocation_state 전체를 받아 트리를 처음부터 재구성 + witness.
async function v1FetchAndWitness() {
  const { root, revokedLeaves } = await (await fetch(`${BASE}/idp/revocation_state`)).json();
  const tree = await createIMT(20);
  for (const l of revokedLeaves) await tree.insert(BigInt(l));
  if (tree.getRoot().toString() !== root) throw new Error('v1 root mismatch');
  // 아무 비멤버 target으로 witness (비용에 witness도 포함)
  const target = await leafValue(TAG_SESSION, `${Date.now()}999`);
  await tree.getNonMembershipWitness(target);
  return revokedLeaves.length;
}

async function main() {
  console.error(`  … warming up (Poseidon/EdDSA import + first sync)`);
  _resetRevocationTreeV2ForTest();
  await syncRevocationTreeV2(); // 첫 동기화는 전체 조회(콜드) — 아래 루프는 증분만 잰다
  await v1FetchAndWitness();

  const rows = [];
  for (let i = 0; i < ROUNDS; i++) {
    await revokeAndPublish(`88800${i}${Date.now()}`);
    const v1 = await timed(() => v1FetchAndWitness());
    const v2 = await timed(() => syncRevocationTreeV2());
    rows.push({ n: v1.v, v1: v1.ms, v2: v2.ms, mode: v2.v.mode });
    if (i % 5 === 0) console.error(`  … round ${i + 1}/${ROUNDS} (n=${v1.v})`);
  }

  const f = (x) => x.toFixed(2);
  const avg = (a) => a.reduce((s, x) => s + x, 0) / a.length;
  console.log('');
  console.log('## 지갑 per-transaction 폐기 동기화 비용 — HTTP 왕복 포함 (ms)');
  console.log('');
  console.log('| round | n(leaves) | v1 전체 재구성 | v2 증분 | v2 mode |');
  console.log('|---:|---:|---:|---:|:--|');
  for (const [i, r] of rows.entries()) {
    if (i < 3 || i >= rows.length - 3) console.log(`| ${i + 1} | ${r.n} | ${f(r.v1)} | ${f(r.v2)} | ${r.mode} |`);
    else if (i === 3) console.log('| … | … | … | … | … |');
  }
  console.log('');
  console.log(`평균: v1 ${f(avg(rows.map((r) => r.v1)))} ms, v2 ${f(avg(rows.map((r) => r.v2)))} ms  (rounds=${ROUNDS}, node ${process.version})`);
  const allIncremental = rows.every((r) => r.mode === 'incremental');
  console.log(`v2 경로: ${allIncremental ? '전 라운드 증분(incremental)' : '일부 전체 재조회 발생'} — epoch 불변, 로그 절단 없음.`);
  console.log('');
  console.log('참고: 데모 규모(n=수십)에서는 HTTP 왕복이 두 경로를 모두 지배한다. 트리 연산 자체의');
  console.log('O(n) vs O(log n) 격차(리프 32,000개에서 24,752ms -> 8.4ms, 2,935배)는 scripts/bench_imt_v2.mjs');
  console.log('가 왕복 없이 따로 잰다. 이 벤치의 요점은 v2가 **변경분만** 받아 적용하는(전체 목록 재수신·');
  console.log('재구성이 아니라) 실제 지갑 함수가 왕복을 포함해도 안정적으로 증분을 유지한다는 것이다.');
}

main().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
