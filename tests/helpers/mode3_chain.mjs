// :8545 hardhat 노드용 헬퍼 (chain 그룹). 컨트랙트 테스트(test/*.test.mjs)는 이걸 쓰지
// 않는다 — 그쪽은 hardhat 인프로세스 체인이다.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { createRevocationTree } from '../../lib/mode3_revocation.js';
import { createRegistryTree } from '../../lib/mode3_registry.js';
// digest·bytes32 변환은 lib/mode3_log.js 하나다 — 여기는 이름만 다시 내보낸다(이 파일 안에서도 쓴다).
import { DOMAIN_ROOT, rootToBytes32, signRootPublication, signPublicationV3, entryHashes } from '../../lib/mode3_log.js';
export { DOMAIN_ROOT as DOMAIN, rootToBytes32, signRootPublication };

const ROOT_DIR = fileURLToPath(new URL('../..', import.meta.url));
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const ARTIFACT = path.join(ROOT_DIR, 'artifacts', 'contracts', 'RevocationLog.sol', 'RevocationLog.json');
const ARTIFACT_V2 = path.join(ROOT_DIR, 'artifacts', 'contracts', 'Mode3Log.sol', 'Mode3Log.json');
const ARTIFACT_MIRROR = path.join(ROOT_DIR, 'artifacts', 'contracts', 'Mode3Mirror.sol', 'Mode3Mirror.json');

function artifact() {
  if (!fs.existsSync(ARTIFACT)) {
    execFileSync('npx', ['hardhat', 'compile', '--quiet'], { cwd: ROOT_DIR, stdio: 'inherit' });
  }
  return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
}
export const logAbi = () => artifact().abi;

function artifactV2() {
  if (!fs.existsSync(ARTIFACT_V2)) execFileSync('npx', ['hardhat', 'compile', '--quiet'], { cwd: ROOT_DIR, stdio: 'inherit' });
  return JSON.parse(fs.readFileSync(ARTIFACT_V2, 'utf8'));
}

function artifactMirror() {
  if (!fs.existsSync(ARTIFACT_MIRROR)) execFileSync('npx', ['hardhat', 'compile', '--quiet'], { cwd: ROOT_DIR, stdio: 'inherit' });
  return JSON.parse(fs.readFileSync(ARTIFACT_MIRROR, 'utf8'));
}

// 테스트는 게시 직후 수 ms 안에 동기화하므로 provider 레벨 250ms 캐시를 끈다.
// url: 2026-10-03 두 체인 각본(test_mode3_demo_full.mjs)용 — 폐기 체인(:8546)을 따로 읽는다. 생략하면 지금처럼 RPC_URL.
export function getProvider(url = RPC_URL) { return new ethers.JsonRpcProvider(url, undefined, { cacheTimeout: -1 }); }
export async function getFunder(provider = getProvider()) { return provider.getSigner(0); }

export async function fundAddress(addr, eth = '1', provider = getProvider()) {
  const funder = await getFunder(provider);
  await (await funder.sendTransaction({ to: addr, value: ethers.parseEther(eth) })).wait();
}

export async function deployRevocationLog(ciaAddress, provider = getProvider()) {
  const { abi, bytecode } = artifact();
  const emptyRoot = rootToBytes32((await createRevocationTree()).getRoot());
  const factory = new ethers.ContractFactory(abi, bytecode, await getFunder(provider));
  const contract = await factory.deploy(ciaAddress, emptyRoot);
  await contract.waitForDeployment();
  return { address: await contract.getAddress(), contract };
}

/** V9: Mode3Log 배포 — 빈 폐기 root + 빈 등록부 root. */
export async function deployMode3Log(ciaAddress, provider = getProvider()) {
  const { abi, bytecode } = artifactV2();
  const emptyRev = rootToBytes32((await createRevocationTree()).getRoot());
  const emptyReg = rootToBytes32((await createRegistryTree()).root());
  const factory = new ethers.ContractFactory(abi, bytecode, await getFunder(provider));
  const contract = await factory.deploy(ciaAddress, emptyRev, emptyReg);
  await contract.waitForDeployment();
  return { address: await contract.getAddress(), contract };
}

export async function mineBlocks(n, provider = getProvider()) {
  await provider.send('hardhat_mine', ['0x' + n.toString(16)]);
}

/** V10: 캐노니컬 Mode3Log 의 chainid·주소를 digest 에 묶는 두 값. */
export async function canonOf(log, provider = getProvider()) {
  return { canonicalChainId: (await provider.getNetwork()).chainId, canonicalLogAddress: await log.getAddress() };
}

/** V10: Mode3Mirror 배포 — 캐노니컬 로그와 같은 빈 root 로 시작한다.
 *  canonicalChainId: 캐노니컬 로그가 있는 체인. 생략하면 거울과 같은 체인(지금까지의 단일 체인 구성). 두 체인 구성(2026-10-03)은
 *  폐기 체인의 chainid(31338)를 준다 — 거울은 그 값을 digest 에 넣어 캐노니컬 서명을 그대로 받는다. */
export async function deployMode3Mirror(ciaAddress, canonicalLogAddress, provider = getProvider(), canonicalChainId = null) {
  const { abi, bytecode } = artifactMirror();
  const emptyRev = rootToBytes32((await createRevocationTree()).getRoot());
  const emptyReg = rootToBytes32((await createRegistryTree()).root());
  const factory = new ethers.ContractFactory(abi, bytecode, await getFunder(provider));
  const contract = await factory.deploy(ciaAddress, canonicalChainId ?? (await provider.getNetwork()).chainId, canonicalLogAddress, emptyRev, emptyReg);
  await contract.waitForDeployment();
  return { address: await contract.getAddress(), contract };
}

/** V10 게시 헬퍼 — 테스트가 CIA 없이 캐노니컬 Mode3Log 에 두 root 를 올린다. 인자는 bigint, 서명은 ciaWallet. */
export async function publishV3(log, ciaWallet, { revRoot, regRoot, epoch, revLeaves = [], slotIdx = [], slotLeaves = [] }) {
  const b = rootToBytes32;
  const p = { revRoot: b(revRoot), regRoot: b(regRoot), epoch, revLeaves: revLeaves.map(b), slotIdx, slotLeaves: slotLeaves.map(b) };
  const sig = await signPublicationV3(ciaWallet, { ...(await canonOf(log, ciaWallet.provider)), ...p });
  await (await log.connect(ciaWallet).publish(p.revRoot, p.regRoot, epoch, p.revLeaves, slotIdx, p.slotLeaves, sig)).wait();
  return { sig, p };
}

/** V10: 캐노니컬에 이미 올라간 게시(p, sig)를 거울에 중계한다 — 같은 서명이 거울에도 그대로 유효하다. */
export async function relayToMirror(mirror, signer, { p, sig }) {
  const h = entryHashes(p);
  await (await mirror.connect(signer).publish(p.revRoot, p.regRoot, p.epoch, h.hLeaves, h.hIdx, h.hSlots, sig)).wait();
}

// ---- 폐기 체인 노드(2026-10-03, 두 체인 각본) ----
// 사용자 승인(2026-10-03): 테스트가 두 번째 hardhat 노드(:8546, chainId 31338)를 스스로 띄우고 끝나면 끈다. 이미 떠 있던 노드는
// 사용자 것이므로 chainId 만 확인하고 건드리지 않는다(started:false, stop() 은 아무것도 안 한다).
async function rpcChainId(url) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }), signal: AbortSignal.timeout(2000) });
  const j = await r.json();
  return Number(BigInt(j.result));
}
function portOpen(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port });
    s.once('connect', () => { s.destroy(); resolve(true); });
    s.once('error', () => resolve(false));
  });
}

// 이 헬퍼가 띄운 노드의 pid 파일(2026-10-03 리뷰 Minor 1). 외부 SIGKILL 등으로 정리 훅이 못 돌아 노드가 남으면, 다음 실행이
// 그 노드를 "사용자 노드"(started:false)로 오인해 영영 끄지 않게 된다 — pid 파일이 살아 있는 우리 hardhat 을 가리키면 우리 것으로 본다.
const pidFileFor = (port) => path.join(os.tmpdir(), `mode3-revchain-${port}.pid`);
function readOurPid(port) {
  try {
    const { pid, port: p, dir } = JSON.parse(fs.readFileSync(pidFileFor(port), 'utf8'));
    if (p !== port || !Number.isInteger(pid)) return null;
    process.kill(pid, 0);   // 살아 있는가(없으면 ESRCH 로 던진다)
    const cmd = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0');
    // 우리가 띄운 명령 모양(node …/hardhat/internal/cli/bootstrap.js node --port <port>)인지까지 본다 — pid 재사용 오인 방지.
    if (!cmd.some((a) => a.endsWith(path.join('hardhat', 'internal', 'cli', 'bootstrap.js'))) || cmd[cmd.indexOf('--port') + 1] !== String(port)) return null;
    return { pid, dir };
  } catch { return null; }
}
const removePidFile = (port) => { try { fs.rmSync(pidFileFor(port), { force: true }); } catch { /* */ } };
async function waitPortClosed(port) {
  for (let i = 0; i < 50 && await portOpen(port); i++) await new Promise((r) => setTimeout(r, 100));
  if (await portOpen(port)) throw new Error(`폐기 체인 노드를 껐는데 :${port} 가 아직 열려 있다`);
}

/** :port 에 chainId 노드를 보장한다. 반환 { url, started, logFile, stop() }. 포트가 다른 chainId(또는 RPC 가 아닌 것)로 차 있으면 던진다.
 *  started:true 는 "이 헬퍼가 띄운 노드"(이번 실행이 띄웠거나, 앞선 실행이 띄우고 정리하지 못한 것 — pid 파일로 확인)이고 stop() 이 끈다.
 *  그 밖의 이미 떠 있던 노드는 started:false 이고 stop() 은 아무것도 하지 않는다(사용자 노드는 끄지 않는다). */
export async function ensureRevChainNode({ port = 8546, chainId = 31338, readyTimeoutMs = 60_000 } = {}) {
  const url = `http://127.0.0.1:${port}`;
  if (await portOpen(port)) {
    let got;
    try { got = await rpcChainId(url); } catch (e) { throw new Error(`:${port} 가 이미 쓰이고 있는데 JSON-RPC 노드가 아니다(${e.message}) — 폐기 체인 노드를 띄울 수 없다`); }
    if (got !== chainId) throw new Error(`:${port} 에 이미 떠 있는 노드의 chainId 가 ${got} 이다(기대 ${chainId}) — 그 노드는 건드리지 않는다. 끄거나 HARDHAT_CHAIN_ID=${chainId} 로 다시 띄울 것`);
    const orphan = readOurPid(port);
    if (orphan) {
      console.warn(`[revchain] :${port} 의 노드(pid ${orphan.pid})는 앞선 실행이 띄우고 정리하지 못한 것이다(pid 파일) — 이번 실행이 이어받아 끝에 끈다`);
      return {
        url, started: true, logFile: null,
        async stop() {
          try { process.kill(orphan.pid, 'SIGTERM'); } catch { /* 이미 없음 */ }
          for (let i = 0; i < 50; i++) { try { process.kill(orphan.pid, 0); } catch { break; } await new Promise((r) => setTimeout(r, 100)); }
          try { process.kill(orphan.pid, 'SIGKILL'); } catch { /* */ }
          await waitPortClosed(port);
          removePidFile(port);
          // 앞선 실행의 로그 디렉터리도 치운다 — 우리가 만든 이름(mode3-revchain-*)일 때만.
          if (typeof orphan.dir === 'string' && path.dirname(orphan.dir) === os.tmpdir() && path.basename(orphan.dir).startsWith('mode3-revchain-')) fs.rmSync(orphan.dir, { recursive: true, force: true });
        },
      };
    }
    return { url, started: false, logFile: null, async stop() { /* 사용자 노드 — 끄지 않는다 */ } };
  }
  removePidFile(port);   // 포트가 비어 있으면 남은 pid 파일은 낡은 것이다
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-revchain-'));
  const logFile = path.join(dir, 'hardhat_node.log');
  const out = fs.openSync(logFile, 'a');
  // npx 를 거치지 않고 hardhat CLI 를 node 로 직접 띄운다 — 프로세스 하나라 stop() 이 확실히 끈다.
  // ETHERNAL_*: hardhat.config.cjs 의 hardhat-ethernal 플러그인이 .env 의 토큰으로 원격 작업공간을 초기화하지 않게 비운다
  // (dotenv 는 이미 있는 키를 — 빈 문자열이어도 — 덮지 않는다).
  const child = spawn(process.execPath, [path.join(ROOT_DIR, 'node_modules', 'hardhat', 'internal', 'cli', 'bootstrap.js'), 'node', '--port', String(port)], {
    cwd: ROOT_DIR, env: { ...process.env, HARDHAT_CHAIN_ID: String(chainId), ETHERNAL_API_TOKEN: '', ETHERNAL_WORKSPACE: '' }, stdio: ['ignore', out, out],
  });
  fs.writeFileSync(pidFileFor(port), JSON.stringify({ pid: child.pid, port, chainId, dir, startedAt: new Date().toISOString() }));
  let exited = false;
  child.once('exit', () => { exited = true; });
  // 테스트가 예외로 죽어도 노드를 남기지 않는다(동기 kill 만 가능한 exit 훅).
  const onExit = () => { if (!exited) { try { child.kill('SIGKILL'); } catch { /* */ } } removePidFile(port); try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ } };
  process.once('exit', onExit);
  // 외부 SIGINT/SIGTERM 은 'exit' 를 거치지 않는다 — 노드를 죽이고 같은 신호를 기본 동작으로 다시 받아 종료한다(리뷰 Minor 1).
  const onSignal = (sig) => {
    onExit();
    process.removeListener('SIGINT', onSignal); process.removeListener('SIGTERM', onSignal);
    process.kill(process.pid, sig);
  };
  process.once('SIGINT', onSignal); process.once('SIGTERM', onSignal);
  const stop = async () => {
    process.removeListener('exit', onExit);
    process.removeListener('SIGINT', onSignal); process.removeListener('SIGTERM', onSignal);
    if (!exited) {
      child.kill('SIGTERM');
      await new Promise((resolve) => {
        const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } resolve(); }, 5000);
        child.once('exit', () => { clearTimeout(t); resolve(); });
        if (exited) { clearTimeout(t); resolve(); }
      });
    }
    // 포트가 실제로 비었는지 확인한다(CLAUDE.md — 내가 띄운 것은 정리하고 비었는지 본다).
    await waitPortClosed(port);
    removePidFile(port);
    fs.rmSync(dir, { recursive: true, force: true });
  };
  const deadline = Date.now() + readyTimeoutMs;
  while (Date.now() < deadline) {
    if (exited) break;
    try { if ((await rpcChainId(url)) === chainId) return { url, started: true, logFile, stop }; } catch { /* 아직 */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  const log = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8').slice(-2000) : '';
  await stop().catch(() => {});
  throw new Error(`폐기 체인 노드(:${port}, chainId ${chainId}) 기동 실패\n${log}`);
}
