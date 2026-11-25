// 로컬 Blockscout 컨트랙트 자동 검증 감시자 — 스펙 docs/superpowers/specs/2026-11-18-blockscout-auto-verify-design.md.
// 응용 체인을 0번 블록부터 따라가며, 올라온 컨트랙트(Mode3Mirror·PiCredVerifier·Mode3WalletFactory·AttrGate·계정마다의 Mode3Wallet)를
// Blockscout 에 소스 검증으로 올린다. 배포 지점이 VM(서비스)·이 PC(에이전트) 여럿이라 체인을 보는 한 프로세스가 맡는다(B3).
// 폐기(RCL) 체인은 같은 감시자를 하나 더 띄운다(2026-11-25, BS_URL=http://127.0.0.1:4001 BS_RPC=http://127.0.0.1:8548 — Mode3Log).
// scripts/demo_split_start.sh 가 띄우고 내린다. 데모 기동을 막지 않는다 — 실패는 WARN 한 줄과 재시도뿐이다.
//   node scripts/blockscout_verify_watch.mjs        BS_URL(기본 http://127.0.0.1:4000) BS_RPC(http://127.0.0.1:8547) BS_POLL_MS(3000)
//   BS_VERIFY_WAIT_MS(60000 — 제출 뒤 검증 완료를 기다리는 시간) BS_INDEX_WAIT_MS(600000 — Blockscout 가 그 주소를 색인하기를 기다리는 시간)
import { ethers } from 'ethers';
import { loadArtifacts, matchRuntime, ctorArgsFromCreation, walletCtorArgs, DEPLOY_SELECTOR, FACTORY_GETTERS } from '../lib/blockscout_verify.mjs';

const BS_URL = (process.env.BS_URL || 'http://127.0.0.1:4000').replace(/\/+$/, '');
const BS_RPC = process.env.BS_RPC || 'http://127.0.0.1:8547';
const POLL_MS = Number(process.env.BS_POLL_MS) || 3000;
const VERIFY_WAIT_MS = Number(process.env.BS_VERIFY_WAIT_MS) || 60_000;
const INDEX_WAIT_MS = Number(process.env.BS_INDEX_WAIT_MS) || 600_000;
const MAX_TRIES = 5;   // 주소별 제출 횟수(B9) — 색인 대기는 여기 넣지 않는다

const log = (...a) => console.log(new Date().toLocaleTimeString('en-GB'), ...a);   // 이 PC 의 시각(HH:MM:SS) — 다른 데모 로그와 같다
const arts = loadArtifacts();
const artOf = Object.fromEntries(arts.map((a) => [a.name, a]));
const provider = new ethers.JsonRpcProvider(BS_RPC, undefined, { staticNetwork: true });
const factoryIface = new ethers.Interface(artOf.Mode3WalletFactory.abi);

const items = new Map();       // 주소(소문자) → { name, address, ctorArgs, state: 'new'|'submitted', tries, seenAt, submittedAt }
const factories = new Map();   // 팩토리 주소(소문자) → 게터 값(지갑 생성자 인자의 재료)
let next = 0;                  // 다음에 볼 블록
let lastWarn = '';             // 같은 경고를 회차마다 되풀이하지 않는다

function add(name, address, ctorArgs) {
  const k = address.toLowerCase();
  if (!items.has(k)) items.set(k, { name, address, ctorArgs, state: 'new', tries: 0, seenAt: Date.now(), submittedAt: 0 });
}

/** 블록 하나: 직접 배포(B4·B5)와 팩토리의 deploy 호출(B6)을 찾는다. 실패한 tx 는 건너뛴다. */
async function scanBlock(n) {
  const block = await provider.getBlock(n, true);
  for (const tx of block?.prefetchedTransactions ?? []) {
    const to = tx.to ? tx.to.toLowerCase() : null;
    if (to !== null && !(factories.has(to) && tx.data.startsWith(DEPLOY_SELECTOR))) continue;
    const receipt = await provider.getTransactionReceipt(tx.hash);
    if (!receipt || receipt.status !== 1) continue;
    if (to === null) {
      const address = receipt.contractAddress; if (!address) continue;
      const name = matchRuntime(await provider.getCode(address), arts);
      if (!name) { log(`verify ? ${address} skip(no_match)`); continue; }
      const ctorArgs = ctorArgsFromCreation(tx.data, artOf[name]);
      if (ctorArgs === null) { log(`verify ${name} ${address} skip(creation_code_mismatch)`); continue; }
      add(name, address, ctorArgs);
      if (name === 'Mode3WalletFactory') {
        const f = new ethers.Contract(address, factoryIface, provider);
        factories.set(address.toLowerCase(), Object.fromEntries(await Promise.all(FACTORY_GETTERS.map(async (g) => [g, await f[g]()]))));
      }
    } else {
      const [ppid] = factoryIface.decodeFunctionData('deploy', tx.data);
      const address = await new ethers.Contract(tx.to, factoryIface, provider).computeAddress(ppid);
      if (matchRuntime(await provider.getCode(address), arts) !== 'Mode3Wallet') { log(`verify Mode3Wallet ${address} skip(no_match)`); continue; }
      add('Mode3Wallet', address, walletCtorArgs(factories.get(to), ppid));
    }
  }
}

/** 표준 입력 검증을 접수시킨다(B7) — 200 은 접수일 뿐이고 결과는 나중에 is_verified 로 본다(B8). */
async function submit(item) {
  const a = artOf[item.name];
  const fd = new FormData();
  fd.set('compiler_version', `v${a.solcLongVersion}`);
  fd.set('contract_name', a.name);
  fd.set('license_type', 'none');
  fd.set('autodetect_constructor_args', 'false');
  fd.set('constructor_args', item.ctorArgs);
  fd.set('files[0]', new Blob([JSON.stringify(a.standardInput)], { type: 'application/json' }), 'input.json');
  const r = await fetch(`${BS_URL}/api/v2/smart-contracts/${item.address}/verification/via/standard-input`, { method: 'POST', body: fd, signal: AbortSignal.timeout(30_000) });
  if (!r.ok) throw new Error(`HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
}

/** 대기 중인 주소 하나를 한 걸음 진행한다. 끝났으면(검증됨·포기) true. */
async function step(item) {
  const now = Date.now(), tag = `verify ${item.name} ${item.address}`;
  let info = null;
  try { const r = await fetch(`${BS_URL}/api/v2/addresses/${item.address}`, { signal: AbortSignal.timeout(10_000) }); if (r.ok) info = await r.json(); } catch { info = null; }
  if (!info?.is_contract) {   // 아직 색인 안 됨(리셋 직후·팩토리가 만든 지갑) — 제출 횟수에 넣지 않고 따로 기다린다(B9)
    if (now - item.seenAt > INDEX_WAIT_MS) { log(`${tag} skip(not_indexed)`); return true; }
    return false;
  }
  if (info.is_verified) { log(`${tag} ${item.tries ? 'ok' : 'skip(already_verified)'}`); return true; }
  if (item.state === 'submitted') {
    if (now - item.submittedAt < VERIFY_WAIT_MS) return false;
    log(`${tag} WARN(not_verified_after_${Math.round(VERIFY_WAIT_MS / 1000)}s, try ${item.tries}/${MAX_TRIES})`);
    item.state = 'new';
  }
  if (item.tries >= MAX_TRIES) { log(`${tag} WARN(gave_up)`); return true; }
  item.tries++;
  try { await submit(item); item.state = 'submitted'; item.submittedAt = Date.now(); log(`${tag} submitted(try ${item.tries}/${MAX_TRIES})`); }
  catch (e) { log(`${tag} WARN(submit: ${e.message}, try ${item.tries}/${MAX_TRIES})`); }
  return false;
}

async function tick() {
  const head = await provider.getBlockNumber();
  if (head + 1 < next) { log(`체인이 새로 시작됐다(head ${head} < ${next}) — 0번부터 다시 본다`); next = 0; items.clear(); factories.clear(); }
  for (; next <= head; next++) await scanBlock(next);   // 한 회차에 새 블록만(B9)
  for (const [k, item] of items) if (await step(item)) items.delete(k);
}

log(`감시 시작 — 체인 ${BS_RPC}, Blockscout ${BS_URL}, 주기 ${POLL_MS}ms, 대상 ${arts.map((a) => a.name).join('·')}`);
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => { log('감시 끝'); process.exit(0); });
for (;;) {
  try { await tick(); lastWarn = ''; }
  catch (e) { const m = String(e?.shortMessage ?? e?.message ?? e).slice(0, 200); if (m !== lastWarn) { log(`WARN(${m})`); lastWarn = m; } }
  await new Promise((r) => setTimeout(r, POLL_MS));
}
