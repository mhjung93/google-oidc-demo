// Mode 3 온체인 실행 모델 성능 실측 (2026-09-18 max_height 지갑 결정 판, 2026-09-21 자격증명 이중 구조 V5,
// 2026-09-22 선택 공개 V6, 2026-09-23 집합 소속 술어 V7 — 회로 공개 입력 25개(V6 은 23개; V7 에서 set_sel·set_root
// 추가), AttrGate v2, 2026-10-01 등록부 소속 조건 V9 — 공개 입력 30개(REG_ROOT 추가, attrs 6슬롯), Mode3Log 가
// revRoot·regRoot 를 한 tx 로 같이 게시(Revoked + SlotUpdated 이벤트)).
//   node scripts/bench_mode3_onchain.mjs [N]        (기본 N=10, :8545 hardhat 노드 필요)
//
// 격리 스택(CIA + 지갑 에이전트, 각자 빈 포트)을 띄우고 실제 HTTP 경로로 측정한다 — 개발 서버(:4100/:5100/:3100)는
// 건드리지 않는다. 검증기는 이 프로세스에서 조립한다(tests/test_mode3_wallet_agent.mjs 와 같은 방식).
//
// 측정 항목:
//   1. 로그인(첫 발급): 지갑의 timings(sync/userCred/issue/prove) + 전체 왕복 + 서비스 verifyLogin (mask=0 고정)
//   2. 재검증(캐시 π): 왕복 + verifyLogin
//   3. 가스: PiCredVerifier·Mode3WalletFactory 배포, 계정 배포(CREATE2), execute(첫/캐시), RevocationLog 게시·하트비트
//   4. /wallet/tx 왕복(mask=0, 캐시 π, 채굴 포함) — "공개 0" 변형
//   5. /wallet/tx 왕복(mask=1 + set, 매번 새 π) + AttrGate.claim — "범위+집합" 변형. claimed 매핑이 지갑 주소당 한 번뿐이라
//      (지갑 주소는 PPID 로 정해지고 세션과 무관하다) 반복마다 AttrGate 를 새로 배포한다. discKey 도 반복마다 바꿔(hi[0] 를
//      늘려) 캐시를 피하고 매번 진짜 새 π 를 잰다 — AttrGate 정책(국가 집합·minAge)은 그대로 만족시킨다.
//   6. /wallet/tx(mask=1, set 없음, to=dEaD) — "범위만" 변형. hi[0] 를 반복마다 늘려 캐시를 피한다.
//   7. /wallet/tx(mask=0, set 만, to=dEaD) — "집합만" 변형. members 에 더미 원소를 반복마다 추가해 캐시를 피한다
//      (국가는 항상 포함해 membership 은 유지).
// 결과는 Markdown 표로 stdout 에 낸다. 스펙 §8·논문 Table 3 에 옮겨 적는다.
import fs from 'node:fs';
import { ethers } from 'ethers';
import { startIsolatedMode3Stack } from '../tests/helpers/isolated_mode3_stack.mjs';
import { getProvider } from '../tests/helpers/mode3_chain.mjs';
import { VKEY_PATH, ZKEY_PATH } from '../lib/mode3_wallet.js';
import { createRpVerifier } from '../lib/mode3_rp.js';
import { randomScalar } from '../lib/mode3_credential.js';
import { deployVerifier, deployFactory, FACTORY_ABI, deployAttrGate, ATTR_GATE_ABI } from '../lib/mode3_onchain.js';
import { MODE3_LOG_ABI } from '../lib/mode3_log.js';

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
  // V9: /wallet/register 는 uid·pwd 만 받는다 — attrs 는 CIA 의 DEMO_ACCOUNTS(['1990','410','2','0','0','0'])가 정한다(설계 2026-10-01 §7.1).
  const reg = await wallet.post('/wallet/register', { uid, pwd: 'password123' });
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
    const disclose = [{ lo: '0', hi: String(1990 + i) }, null, null, null, null, null];
    const set = { slot: 1, members: [410, 392, 840, 276, 250] };
    const t0 = performance.now();
    const r = await wallet.post('/wallet/tx', { r_s: lastRs, to: gateAddress, data: claimSelector, disclose, set }, { Origin: stack.rpOriginForWallet });
    G.total.push(performance.now() - t0);
    if (r.status !== 200 || !r.body.ok) throw new Error(`claim tx ${r.status} ${j(r.body)}`);
    const gate = new ethers.Contract(gateAddress, ATTR_GATE_ABI, provider);
    if (!(await gate.claimed(r.body.wallet))) throw new Error('claim 이 반영되지 않음');
    G.gas.push(Number(r.body.gasUsed));
  }

  const deadAddress = '0x000000000000000000000000000000000000dEaD';

  // 6. 범위만(mask=1, set 없음, to=dEaD) — "네 가지 disclosure 변형"(공개 0 / 범위만 / 집합만 / 범위+집합) 표의 나머지 한 칸.
  // hi[0] 를 반복마다 늘려 discKey 를 바꾸고 캐시를 피한다(lo=0 은 항상 만족 — 하한 없음).
  const RA = { gas: [] };
  for (let i = 0; i < N; i++) {
    const disclose = [{ lo: '0', hi: String(2000 + i) }, null, null, null, null, null];
    const r = await wallet.post('/wallet/tx', { r_s: lastRs, to: deadAddress, disclose }, { Origin: stack.rpOriginForWallet });
    if (r.status !== 200 || !r.body.ok) throw new Error(`range-only tx ${r.status} ${j(r.body)}`);
    RA.gas.push(Number(r.body.gasUsed));
  }

  // 7. 집합만(mask=0, set 만, to=dEaD) — V6 대비 공개 입력 +2(set_sel, set_root)의 gas 비용. members 를 반복마다 바꿔
  // (더미 원소 추가) discKey 를 바꾸고 캐시를 피한다 — 국가(410)는 항상 그대로 포함해 membership 은 유지한다.
  const S = { gas: [] };
  for (let i = 0; i < N; i++) {
    const set = { slot: 1, members: [410, 392, 840, 276, 250, 900 + i] };
    const r = await wallet.post('/wallet/tx', { r_s: lastRs, to: deadAddress, set }, { Origin: stack.rpOriginForWallet });
    if (r.status !== 200 || !r.body.ok) throw new Error(`set-only tx ${r.status} ${j(r.body)}`);
    S.gas.push(Number(r.body.gasUsed));
  }

  // Mode3Log(V9, 설계 2026-10-01 §4): revRoot·regRoot 를 한 tx 로 같이 게시한다. publish() 는 항상 Revoked(epoch,root,leaves)
  // 하나를 내고, 슬롯이 바뀐 만큼(0개 이상) SlotUpdated(epoch,index,leaf) 를 더 낸다(contracts/Mode3Log.sol). 같은 tx 해시에
  // SlotUpdated 가 있는지로 세 가지를 가른다 — 슬롯 게시(로그인 루프의 /cia/user_cred 가 등록부에 슬롯을 쓴 것) / 리프 게시
  // (지금부터 세션 하나를 폐기해 만든다) / 하트비트(pending 없이 타이머가 낸다).
  const log = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
  const classifyPublishes = async () => {
    const [revokedEvents, slotEvents] = await Promise.all([
      log.queryFilter(log.filters.Revoked(), startBlock, 'latest'),
      log.queryFilter(log.filters.SlotUpdated(), startBlock, 'latest'),
    ]);
    const slotTxSet = new Set(slotEvents.map((e) => e.transactionHash));
    const out = [];
    for (const ev of revokedEvents) {
      const rc = await provider.getTransactionReceipt(ev.transactionHash);
      out.push({ leaves: ev.args.leaves.length, hasSlot: slotTxSet.has(ev.transactionHash), gas: Number(rc.gasUsed), blockNumber: ev.blockNumber });
    }
    return out;
  };

  // 리프 1개 게시: 세션 하나를 폐기한다(scope:'account'/'credential' 은 등록부 슬롯도 같이 바꿔 "리프 1개"가 아니게 된다).
  // /cia/publish 응답이 txHash 를 직접 주므로(V9 publishNow()) 그 영수증에서 바로 gas 를 읽는다 — 이벤트 스캔이 필요 없다.
  const sessRevoke = await wallet.post('/wallet/session/revoke', { r_s: lastRs });
  if (sessRevoke.status !== 200 || !sessRevoke.body.revoked || !sessRevoke.body.inserted) throw new Error(`session revoke ${sessRevoke.status} ${j(sessRevoke.body)}`);
  const pub = await cia.adminPost('/cia/publish');
  if (!pub.body.published) throw new Error(`publish ${j(pub.body)}`);
  if (pub.body.leaves.length !== 1 || pub.body.slots !== 0) throw new Error(`게시 1건에 리프 1개·슬롯 0개를 기대했다: ${j(pub.body)}`);
  const leafPublishReceipt = await provider.getTransactionReceipt(pub.body.txHash);
  const leafPublishGas = Number(leafPublishReceipt.gasUsed);

  // 하트비트: pending 없이 5 블록(CIA_HEARTBEAT_BLOCKS) 더 지나면 CIA 타이머가 빈 게시를 낸다. 방금 리프를 게시한 블록
  // 이후만 본다 — 로그인 루프 중 자동으로 났을 수 있는 하트비트와 섞이지 않게.
  await provider.send('hardhat_mine', ['0x6']);
  const heartbeatDeadline = Date.now() + 15_000;
  let sawHeartbeat = false;
  while (Date.now() < heartbeatDeadline) {
    const evs = await log.queryFilter(log.filters.Revoked(), leafPublishReceipt.blockNumber + 1, 'latest');
    if (evs.some((e) => e.args.leaves.length === 0)) { sawHeartbeat = true; break; }
    await new Promise((r) => setTimeout(r, 300));
  }
  if (!sawHeartbeat) console.warn('[bench] 하트비트 게시를 15000ms 안에 못 봤다 — CIA_HEARTBEAT_BLOCKS/POLL_MS 설정을 확인할 것');

  const pubs = await classifyPublishes();
  const slotPublishGas = pubs.filter((p) => p.hasSlot).map((p) => p.gas);
  const heartbeatGas = pubs.filter((p) => !p.hasSlot && p.leaves === 0 && p.blockNumber > leafPublishReceipt.blockNumber).map((p) => p.gas);

  const zkeyBytes = fs.statSync(ZKEY_PATH).size;
  console.log('');
  console.log(`## Mode 3 온체인 실행 실측 (N=${N}, 중앙값 (최소–최대), ms)`);
  console.log('');
  console.log('| 항목 | 값 |');
  console.log('|---|--:|');
  console.log(`| 로그인 전체 왕복(발급+증명, 지갑 HTTP) | ${fmt(L.total)} |`);
  console.log(`| ├ 첫 로그인(사용자 자격증명 신규 발급 + 등록부 게시 대기 포함) | ${L.total[0].toFixed(0)} ms |`);
  console.log(`| ├ 체인 동기화 syncMs | ${fmt(L.sync)} |`);
  console.log(`| ├ 사용자 자격증명 발급 userCredMs (π_u; 첫 로그인 ${L.userCred[0]} ms, 이후 재사용) | ${fmt(L.userCred)} |`);
  console.log(`| ├ CIA 세션 발급 issueMs (ZKP 없음, sig_u 검증 + 서명) | ${fmt(L.issue)} |`);
  console.log(`| ├ 증명 proveMs (pi_cred V9) | ${fmt(L.prove)} |`);
  console.log(`| 서비스 verifyLogin (Groth16 + σ + root) | ${fmt(L.verify)} |`);
  console.log(`| 재검증 왕복(캐시 π) | ${fmt(R.total)} |`);
  console.log(`| 재검증 verifyLogin | ${fmt(R.verify)} |`);
  console.log(`| /wallet/tx 왕복(mask=0, 캐시 π, 서명+제출+채굴) | ${fmt(T.total)} |`);
  console.log(`| execute gas (mask=0, 캐시 π, N회) | ${med(T.gas)} (${Math.min(...T.gas)}–${Math.max(...T.gas)}) |`);
  console.log(`| execute gas (첫 tx, 계정 배포 tx 는 별도) | ${r1.body.gasUsed} |`);
  console.log(`| /wallet/tx 왕복(mask=1 + set, 새 π + AttrGate.claim, N회) | ${fmt(G.total)} |`);
  console.log(`| execute gas (mask=1 + set, 새 π + claim, N회) | ${med(G.gas)} (${Math.min(...G.gas)}–${Math.max(...G.gas)}) |`);
  console.log(`| execute gas (범위만, mask=1, to=dEaD, N회) | ${med(RA.gas)} (${Math.min(...RA.gas)}–${Math.max(...RA.gas)}) |`);
  console.log(`| execute gas (집합만, mask=0 + set, to=dEaD, N회) | ${med(S.gas)} (${Math.min(...S.gas)}–${Math.max(...S.gas)}) |`);
  console.log(`| 계정 배포 gas (factory.deploy, CREATE2) | ${walletDeployGas} |`);
  console.log(`| PiCredVerifier 배포 gas | ${verifierGas} |`);
  console.log(`| Mode3WalletFactory 배포 gas | ${factoryGas} |`);
  console.log(`| Mode3Log 등록부 슬롯 게시 gas (슬롯 1개, SlotUpdated 1건) | ${slotPublishGas.join(', ') || '미측정'} |`);
  console.log(`| Mode3Log 폐기 리프 게시 gas (리프 1개) | ${leafPublishGas} |`);
  console.log(`| Mode3Log 하트비트 게시 gas (리프 0, 슬롯 0) | ${heartbeatGas.join(', ') || '미측정(15s 내 관측 안 됨)'} |`);
  console.log(`| zkey 크기 | ${zkeyBytes} bytes |`);
  console.log(`| 공개 입력 수 | 30 |`);
} finally {
  await stack.stop();
}
process.exit(0);
