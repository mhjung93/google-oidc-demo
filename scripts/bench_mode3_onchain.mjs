// Mode 3 온체인 실행 모델 성능 실측 (2026-09-18 max_height 지갑 결정 판, 2026-09-21 자격증명 이중 구조 V5,
// 2026-09-22 선택 공개 V6 — 회로 공개 입력 23개, AttrGate,
// 2026-09-23 집합 소속 술어 V7 — 회로 공개 입력 25개(set_sel, set_root 추가), AttrGate v2).
//   node scripts/bench_mode3_onchain.mjs [N]        (기본 N=10, :8545 hardhat 노드 필요)
//
// 격리 스택(CIA + 지갑 에이전트, 각자 빈 포트)을 띄우고 실제 HTTP 경로로 측정한다 — 개발 서버(:4100/:5100/:3100)는
// 건드리지 않는다. 검증기는 이 프로세스에서 조립한다(tests/test_mode3_wallet_agent.mjs 와 같은 방식).
//
// 측정 항목:
//   1. 로그인(첫 발급): 지갑의 timings(sync/userCred/issue/prove) + 전체 왕복 + 서비스 verifyLogin (mask=0 고정)
//   2. 재검증(캐시 π): 왕복 + verifyLogin
//   3. 가스: PiCredVerifier·Mode3WalletFactory 배포, 계정 배포(CREATE2), execute(첫/캐시), RevocationLog 게시·하트비트
//   4. /wallet/tx 왕복(mask=0, 캐시 π, 채굴 포함)
//   5. /wallet/tx 왕복(mask=3, 매번 새 π) + AttrGate.claim — claimed 매핑이 지갑 주소당 한 번뿐이라(지갑 주소는 PPID 로
//      정해지고 세션과 무관하다) 반복마다 AttrGate 를 새로 배포한다. discKey 도 반복마다 바꿔(hi[0] 를 늘려) 캐시를 피하고
//      매번 진짜 새 π 를 잰다 — AttrGate 정책(국가=410, 출생연도 ≤ 2007)은 그대로 만족시킨다.
// 결과는 Markdown 표로 stdout 에 낸다. 스펙 §8·논문 Table 3 에 옮겨 적는다.
import fs from 'node:fs';
import { ethers } from 'ethers';
import { startIsolatedMode3Stack } from '../tests/helpers/isolated_mode3_stack.mjs';
import { getProvider } from '../tests/helpers/mode3_chain.mjs';
import { VKEY_PATH, ZKEY_PATH } from '../lib/mode3_wallet.js';
import { createRpVerifier } from '../lib/mode3_rp.js';
import { randomScalar } from '../lib/mode3_credential.js';
import { deployVerifier, deployFactory, FACTORY_ABI, deployAttrGate, ATTR_GATE_ABI } from '../lib/mode3_onchain.js';
import { LOG_ABI } from '../lib/mode3_log.js';

const N = Number(process.argv[2] || 10);
const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
const fmt = (a) => `${med(a).toFixed(0)} (${Math.min(...a).toFixed(0)}–${Math.max(...a).toFixed(0)})`;
const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));

const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = getProvider();
const stack = await startIsolatedMode3Stack({ rp: false, ciaEnv: { CIA_HEARTBEAT_BLOCKS: '5', CIA_HEARTBEAT_POLL_MS: '300' } });
const { cia, wallet } = stack;
const uid = '12345';   // 격리 CIA 의 데모 계정
const startBlock = await provider.getBlockNumber();

try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  const { arid, cert_s, origin, pk_trace } = await cia.registerRp(stack.rpOriginForWallet);
  const rp = createRpVerifier({ provider, logAddress: cia.logAddress, vkey, pkCIA: pk_CIA, arid: BigInt(arid), chainId: 31337n, pkTrace: pk_trace });
  const reg = await wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: ['19', '410', '0', '0'] });
  if (reg.status !== 201) throw new Error(`register ${reg.status} ${j(reg.body)}`);

  // 가스: 배포
  const signer = await provider.getSigner(0);
  const verifierAddress = await deployVerifier(signer);
  const verifierGas = (await provider.getTransactionReceipt((await provider.getBlock('latest', true)).transactions[0])).gasUsed;
  const factoryAddress = await deployFactory(signer, { verifierAddress, arid, pkCIA: pk_CIA, pkTrace: pk_trace, logAddress: cia.logAddress, maxRootAge: 100n });
  const factoryGas = (await provider.getTransactionReceipt((await provider.getBlock('latest', true)).transactions[0])).gasUsed;
  const factory = new ethers.Contract(factoryAddress, FACTORY_ABI, signer);
  const walletDeployGas = (await (await factory.deploy(randomScalar() % (1n << 250n))).wait()).gasUsed;   // 임의 PPID — 계정 배포 가스만

  const login = (r_s, extra = {}) => wallet.post('/wallet/login', { arid, origin, cert_s, pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }, r_s, factoryAddress, ...extra }, { Origin: stack.rpOriginForWallet });
  const verify = (body, r_s) => rp.verifyLogin({ proof: body.proof, publicSignals: body.publicSignals, sig: body.sig, r_s: BigInt(r_s) });

  // 1. 로그인 N회 — 매번 새 r_s = 새 세션 = 새 발급 + 새 증명
  const L = { total: [], sync: [], userCred: [], issue: [], prove: [], verify: [] };
  let lastRs;
  for (let i = 0; i < N; i++) {
    const rs = randomScalar().toString();
    const t0 = performance.now();
    const r = await login(rs);
    L.total.push(performance.now() - t0);
    if (r.status !== 200 || !r.body.issued) throw new Error(`login ${r.status} ${j(r.body)}`);
    L.sync.push(r.body.timings.syncMs); L.userCred.push(r.body.timings.userCredMs ?? 0); L.issue.push(r.body.timings.issueMs); L.prove.push(r.body.timings.proveMs);
    const t1 = performance.now();
    const v = await verify(r.body, rs);
    L.verify.push(performance.now() - t1);
    if (!v.ok) throw new Error(`verify ${j(v)}`);
    lastRs = rs;
  }

  // 2. 재검증 N회 (캐시 π)
  const R = { total: [], verify: [] };
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    const r = await wallet.post('/wallet/revalidate', { r_s: lastRs }, { Origin: stack.rpOriginForWallet });
    R.total.push(performance.now() - t0);
    if (r.status !== 200 || !r.body.cacheHit) throw new Error(`revalidate ${r.status} ${j(r.body)}`);
    const t1 = performance.now();
    const v = await verify(r.body, lastRs);
    R.verify.push(performance.now() - t1);
    if (!v.ok) throw new Error(`verify ${j(v)}`);
  }

  // 3·4. 트랜잭션: 첫 번째는 계정 배포 + execute, 이후 N회는 캐시 π 로 execute
  const to = ethers.Wallet.createRandom().address;
  const r1 = await wallet.post('/wallet/tx', { r_s: lastRs, to, value: '0' }, { Origin: stack.rpOriginForWallet });
  if (r1.status !== 200 || !r1.body.ok) throw new Error(`tx1 ${r1.status} ${j(r1.body)}`);
  const T = { total: [], gas: [] };
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    const r = await wallet.post('/wallet/tx', { r_s: lastRs, to }, { Origin: stack.rpOriginForWallet });
    T.total.push(performance.now() - t0);
    if (r.status !== 200 || !r.body.ok || !r.body.cacheHit) throw new Error(`tx ${r.status} ${j(r.body)}`);
    T.gas.push(Number(r.body.gasUsed));
  }

  // 5. mask=1 + set(V7 선택 공개) 새 π + AttrGate.claim — 국가(a₁)=410 은 집합 소속으로, 출생연도(a₀) 는 구간 공개
  // (반복마다 hi 를 늘려 discKey 를 바꾼다). deployAttrGate 의 기본 정책(집합 [410,392,840,276,250]·minAge 19)을 그대로 쓴다.
  const claimSelector = ethers.id('claim()').slice(0, 10);
  const G = { total: [], gas: [] };
  for (let i = 0; i < N; i++) {
    const gateAddress = await deployAttrGate(signer, { factoryAddress });
    const disclose = [{ lo: '0', hi: String(1990 + i) }, null, null, null];
    const set = { slot: 1, members: [410, 392, 840, 276, 250] };
    const t0 = performance.now();
    const r = await wallet.post('/wallet/tx', { r_s: lastRs, to: gateAddress, data: claimSelector, disclose, set }, { Origin: stack.rpOriginForWallet });
    G.total.push(performance.now() - t0);
    if (r.status !== 200 || !r.body.ok) throw new Error(`claim tx ${r.status} ${j(r.body)}`);
    const gate = new ethers.Contract(gateAddress, ATTR_GATE_ABI, provider);
    if (!(await gate.claimed(r.body.wallet))) throw new Error('claim 이 반영되지 않음');
    G.gas.push(Number(r.body.gasUsed));
  }

  // 6. 집합만(mask=0, set 만, to=dEaD) — V6 대비 공개 입력 +2(set_sel, set_root)의 gas 비용. members 를 반복마다 바꿔
  // (더미 원소 추가) discKey 를 바꾸고 캐시를 피한다 — 국가(410)는 항상 그대로 포함해 membership 은 유지한다.
  const deadAddress = '0x000000000000000000000000000000000000dEaD';
  const S = { gas: [] };
  for (let i = 0; i < N; i++) {
    const set = { slot: 1, members: [410, 392, 840, 276, 250, 900 + i] };
    const r = await wallet.post('/wallet/tx', { r_s: lastRs, to: deadAddress, set }, { Origin: stack.rpOriginForWallet });
    if (r.status !== 200 || !r.body.ok) throw new Error(`set-only tx ${r.status} ${j(r.body)}`);
    S.gas.push(Number(r.body.gasUsed));
  }

  // RevocationLog: 게시(리프 있음)와 하트비트(리프 없음) 가스 — 폐기 한 건을 만들어 정식 게시를 한 번 일으키고, 그 뒤 하트비트를 기다린다
  const logIface = new ethers.Interface(LOG_ABI);
  const collectPublishes = async () => {
    const logs = await provider.getLogs({ address: cia.logAddress, fromBlock: startBlock, toBlock: 'latest' });
    const out = [];
    for (const lg of logs) {
      const rc = await provider.getTransactionReceipt(lg.transactionHash);
      const tx = await provider.getTransaction(lg.transactionHash);
      const { args } = logIface.parseTransaction({ data: tx.data });
      out.push({ leaves: args[2].length, gas: Number(rc.gasUsed) });
    }
    return out;
  };
  const rv = await cia.adminPost('/cia/revoke', { uid, scope: 'account' });
  if (rv.status !== 200) throw new Error(`revoke ${rv.status} ${j(rv.body)}`);
  const pub = await cia.adminPost('/cia/publish');
  if (!pub.body.published) throw new Error(`publish ${j(pub.body)}`);
  // 하트비트: 5 블록 진행 뒤 CIA 타이머가 빈 게시를 낸다
  await provider.send('hardhat_mine', ['0x6']);
  const deadline = Date.now() + 15_000;
  let pubs;
  while (Date.now() < deadline) {
    pubs = await collectPublishes();
    if (pubs.some((p) => p.leaves === 0)) break;
    await new Promise((r) => setTimeout(r, 300));
  }
  const publishGas = pubs.filter((p) => p.leaves > 0).map((p) => p.gas);
  const heartbeatGas = pubs.filter((p) => p.leaves === 0).map((p) => p.gas);

  const zkeyBytes = fs.statSync(ZKEY_PATH).size;
  console.log('');
  console.log(`## Mode 3 온체인 실행 실측 (N=${N}, 중앙값 (최소–최대), ms)`);
  console.log('');
  console.log('| 항목 | 값 |');
  console.log('|---|--:|');
  console.log(`| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | ${fmt(L.total)} |`);
  console.log(`| ├ 체인 동기화 syncMs | ${fmt(L.sync)} |`);
  console.log(`| ├ 사용자 자격증명 발급 userCredMs (π_u; 첫 로그인 ${L.userCred[0]} ms, 이후 재사용) | ${fmt(L.userCred)} |`);
  console.log(`| ├ CIA 세션 발급 issueMs (ZKP 없음, sig_u 검증 + 서명) | ${fmt(L.issue)} |`);
  console.log(`| ├ 증명 proveMs (pi_cred V6) | ${fmt(L.prove)} |`);
  console.log(`| 서비스 verifyLogin (Groth16 + σ + root) | ${fmt(L.verify)} |`);
  console.log(`| 재검증 왕복(캐시 π) | ${fmt(R.total)} |`);
  console.log(`| 재검증 verifyLogin | ${fmt(R.verify)} |`);
  console.log(`| /wallet/tx 왕복(mask=0, 캐시 π, 서명+제출+채굴) | ${fmt(T.total)} |`);
  console.log(`| execute gas (mask=0, 캐시 π, N회) | ${med(T.gas)} (${Math.min(...T.gas)}–${Math.max(...T.gas)}) |`);
  console.log(`| execute gas (첫 tx, 계정 배포 tx 는 별도) | ${r1.body.gasUsed} |`);
  console.log(`| /wallet/tx 왕복(mask=1 + set, 새 π + AttrGate.claim, N회) | ${fmt(G.total)} |`);
  console.log(`| execute gas (mask=1 + set, 새 π + claim, N회) | ${med(G.gas)} (${Math.min(...G.gas)}–${Math.max(...G.gas)}) |`);
  console.log(`| execute gas (집합만, mask=0 + set, to=dEaD, N회) | ${med(S.gas)} (${Math.min(...S.gas)}–${Math.max(...S.gas)}) |`);
  console.log(`| 계정 배포 gas (factory.deploy, CREATE2) | ${walletDeployGas} |`);
  console.log(`| PiCredVerifier 배포 gas | ${verifierGas} |`);
  console.log(`| Mode3WalletFactory 배포 gas | ${factoryGas} |`);
  console.log(`| RevocationLog 게시 gas (리프 ${pubs.filter((p) => p.leaves > 0).map((p) => p.leaves).join('/')}) | ${publishGas.join(', ') || '-'} |`);
  console.log(`| RevocationLog 하트비트 gas (리프 0) | ${heartbeatGas.join(', ') || '-'} |`);
  console.log(`| zkey 크기 | ${zkeyBytes} bytes |`);
  console.log(`| 공개 입력 수 | 25 |`);
} finally {
  await stack.stop();
}
process.exit(0);
