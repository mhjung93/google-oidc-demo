// 지갑의 per-transaction 폐기 동기화 비용 — **HTTP 왕복 포함** 실측 (v3 이중 트리).
//
//   IDP_ADMIN_SECRET=<value> node scripts/bench_wallet_revocation_v3.mjs [rounds]
//   (secret은 실행 중인 custom_idp.js와 같은 값. rounds 기본 30)
//
// 이 파일은 scripts/bench_imt_v2_wallet.mjs를 대체한다. 그 벤치는 "v1 전체 재구성(O(n)) vs
// v2 증분(O(log n))"을 쟀는데, v3에서는 **증분 프로토콜 자체가 없어져서** 그 비교가 성립하지
// 않는다. 대신 v3가 그 자리에서 주장하는 것을 잰다:
//
//   지갑은 캐시도 증분도 없이 **매 트랜잭션마다 자기 샤드 하나를 통째로** 받아 재구성하는데,
//   그게 v2의 증분 동기화보다 싸다.
//
// 왜 그런가. v2에서 지갑이 들고 있어야 했던 것은 깊이 20 트리 하나였고, 캐시가 없으면
// 재구성이 리프 32,000개에서 24.75초였다(scripts/bench_imt_v2.mjs, 왕복 제외). 그래서
// 캐시·epoch·seq·변경 로그·tooOld가 전부 필요했다. v3에서 지갑이 만지는 것은 깊이 8/10의
// 서브트리 두 개(최대 256/1,024리프)뿐이라 매번 새로 쌓아도 싸고, 그래서 캐시가 없다.
// 캐시가 없으면 캐시 일관성 결함도 없다 — 이 벤치는 그 교환이 실제로 성립하는지를 본다.
//
// 지갑의 실제 모듈(lib/wallet_revocation_v3.js)을 그대로 부른다. 그 함수는 받은 root와
// 경로를 스스로 재구성해 대조하므로, 여기서 재는 시간에는 그 검증 비용도 포함된다.
// 파일은 쓰지 않고 stdout에만 출력한다.
import { fetchRevocationWitnessesV3 } from '../lib/wallet_revocation_v3.js';

const BASE = process.env.CUSTOM_IDP_BASE_URL || 'http://127.0.0.1:4000';
const ADMIN = process.env.IDP_ADMIN_SECRET;
if (!ADMIN) {
  console.error('IDP_ADMIN_SECRET required (must match the running custom_idp.js).');
  process.exit(1);
}
const ROUNDS = Number(process.argv[2]) || 30;
const adminHeaders = { 'Content-Type': 'application/json', 'X-IdP-Admin-Secret': ADMIN };

// 계정 층만 본다. max_height는 세션 샤드 선택에만 쓰이므로 고정값이면 된다.
const MAX_HEIGHT = 1n;
const R_TOKEN = 1n;

const ms = (t0) => Number(process.hrtime.bigint() - t0) / 1e6;
async function timed(fn) {
  const t0 = process.hrtime.bigint();
  const v = await fn();
  return { ms: ms(t0), v };
}

async function revokeAndPublish(value) {
  const r = await fetch(`${BASE}/idp/revoke`, {
    method: 'POST', headers: adminHeaders, body: JSON.stringify({ type: 'account', value }),
  });
  if (r.status !== 200) throw new Error(`revoke ${value} -> ${r.status}`);
  const prepared = await (await fetch(`${BASE}/idp/publish/prepare`, {
    method: 'POST', headers: adminHeaders, body: '{}',
  })).json();
  const c = await fetch(`${BASE}/idp/publish/commit`, {
    method: 'POST', headers: adminHeaders, body: JSON.stringify({ roundToken: prepared.roundToken }),
  });
  if (c.status !== 200) throw new Error(`commit -> ${c.status}`);
}

/** 응답 크기도 함께 본다 — v2는 전체 리프 배열이라 n에 비례해 자랐다. */
async function responseBytes() {
  const res = await fetch(`${BASE}/idp/revocation_state_v3?accountShard=0&sessionShard=0`);
  return (await res.text()).length;
}

async function main() {
  console.error('  … warming up (Poseidon import + first fetch)');
  await fetchRevocationWitnessesV3(BASE, R_TOKEN, `warmup${Date.now()}`, MAX_HEIGHT);

  const rows = [];
  for (let i = 0; i < ROUNDS; i++) {
    await revokeAndPublish(`88800${i}${Date.now()}`);
    // 매 라운드 새 계정으로 조회한다 — 폐기되지 않은 계정이어야 witness가 나온다.
    const target = `77700${i}${Date.now()}`;
    const t = await timed(() => fetchRevocationWitnessesV3(BASE, R_TOKEN, target, MAX_HEIGHT));
    const bytes = await responseBytes();
    rows.push({ round: i + 1, ms: t.ms, bytes, shard: t.v.acctShard });
    if (i % 5 === 0) console.error(`  … round ${i + 1}/${ROUNDS}`);
  }

  const f = (x) => x.toFixed(2);
  const avg = (a) => a.reduce((s, x) => s + x, 0) / a.length;
  const times = rows.map((r) => r.ms);
  const sorted = [...times].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];

  console.log('');
  console.log('## 지갑 per-transaction 폐기 동기화 비용 — HTTP 왕복 + 자체 검증 포함 (v3)');
  console.log('');
  console.log('| round | witness+검증 (ms) | 응답 크기 (bytes) | 계정 샤드 |');
  console.log('|---:|---:|---:|---:|');
  for (const [i, r] of rows.entries()) {
    if (i < 3 || i >= rows.length - 3) {
      console.log(`| ${r.round} | ${f(r.ms)} | ${r.bytes} | ${r.shard} |`);
    } else if (i === 3) {
      console.log('| … | … | … | … |');
    }
  }
  console.log('');
  console.log(
    `평균 ${f(avg(times))} ms, 중앙값 ${f(median)} ms, 범위 ${f(sorted[0])}-${f(sorted[sorted.length - 1])} ms ` +
    `(rounds=${ROUNDS}, node ${process.version})`,
  );
  console.log(`응답 크기 평균 ${Math.round(avg(rows.map((r) => r.bytes)))} bytes`);
  console.log('');
  console.log('읽는 법. 이 시간에는 (1) HTTP 왕복, (2) 받은 상위 root·경로를 지갑이 스스로');
  console.log('재계산해 대조하는 검증, (3) 자기 서브트리를 처음부터 쌓기, (4) 비멤버십 witness');
  console.log('생성이 모두 들어 있다. **캐시는 없다** — 매 라운드가 콜드다.');
  console.log('');
  console.log('비교 대상. v2에서 같은 일을 캐시 없이 하면 깊이 20 트리를 통째로 재구성해야 했고,');
  console.log('리프 32,000개에서 24,752 ms였다(scripts/bench_imt_v2.mjs, 왕복 제외). 그래서 v2는');
  console.log('캐시와 증분 동기화가 필수였다. v3는 서브트리가 작아 캐시 없이도 위 수치에 머문다.');
  console.log('응답 크기가 폐기 건수에 따라 자라지 않는 것도 같은 이유다 — 빈 서브트리 상수 하나와');
  console.log('비어 있지 않은 샤드의 덮어쓰기 목록만 보내기 때문이다(설계 문서 5절).');
}

main().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
