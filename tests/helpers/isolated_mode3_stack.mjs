// 격리 Mode 3 스택: 격리 CIA(isolated_cia.mjs) + 지갑 에이전트 + RP 를 임시 포트·임시 상태 파일로.
// :4100/:5100/:3100 개발용 프로세스를 건드리지 않는다. stop() 이 세 프로세스와 임시 디렉터리를 정리한다.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startIsolatedCia, freePort } from './isolated_cia.mjs';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));

/** node <script> 를 env 로 띄우고 readyUrl 이 200 을 줄 때까지 기다린다. */
async function spawnServer(script, { env, readyUrl, logFile, readyTimeoutMs = 60_000 }) {
  const out = fs.openSync(logFile, 'a');
  const child = spawn('node', [script], { cwd: REPO_ROOT, env: { ...process.env, ...env }, stdio: ['ignore', out, out] });
  let spawnError = null;
  child.on('error', (e) => { spawnError = e; });
  const deadline = Date.now() + readyTimeoutMs;
  let ready = false;
  while (Date.now() < deadline) {
    if (spawnError || child.exitCode !== null) break;
    try { if ((await fetch(readyUrl)).ok) { ready = true; break; } } catch { /* not yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  if (!ready) {
    const log = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : '';
    try { child.kill('SIGKILL'); } catch { /* */ }
    throw new Error(`${script} 기동 실패.${spawnError ? ' spawn: ' + spawnError.message : ''}\n${log}`);
  }
  return child;
}

async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  await new Promise((resolve) => {
    const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } resolve(); }, 3000);
    child.once('exit', () => { clearTimeout(t); resolve(); });
  });
}

const json = async (r) => ({ status: r.status, body: await r.json().catch(() => null) });
function client(base, logFile) {
  return {
    base, origin: base,
    get: (p, headers = {}) => fetch(`${base}${p}`, { headers }).then(json),
    post: (p, body, headers = {}) => fetch(`${base}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body ?? {}) }).then(json),
    raw: (p, init) => fetch(`${base}${p}`, init),
    log: () => (fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : ''),
  };
}

export async function startIsolatedMode3Stack(opts = {}) {
  const { rp: withRp = true, rpEnv = {}, walletEnv = {} } = opts;
  const cia = await startIsolatedCia();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-stack-'));
  const walletPort = await freePort();
  const rpPort = await freePort();
  const walletOrigin = `http://127.0.0.1:${walletPort}`;
  const rpOrigin = `http://127.0.0.1:${rpPort}`;
  const children = [];
  try {
    const walletLog = path.join(dir, 'wallet.log');
    children.push(await spawnServer('mode3_wallet_agent.js', {
      env: {
        MODE3_WALLET_PORT: String(walletPort),
        MODE3_WALLET_STATE_FILE: path.join(dir, 'mode3_wallet_state.json'),
        MODE3_CIA_URL: cia.base,
        MODE3_RP_ORIGIN: rpOrigin,
        CIA_LOG_ADDRESS: cia.logAddress,
        ...walletEnv,
      },
      readyUrl: `${walletOrigin}/wallet/status`, logFile: walletLog,
    }));
    const wallet = client(walletOrigin, walletLog);

    let rp = null;
    if (withRp) {
      const rpLog = path.join(dir, 'rp.log');
      children.push(await spawnServer('mode3_rp.js', {
        env: {
          MODE3_RP_PORT: String(rpPort),
          MODE3_CIA_URL: cia.base,
          MODE3_WALLET_AGENT_ORIGIN: walletOrigin,
          CIA_LOG_ADDRESS: cia.logAddress,
          ...rpEnv,
        },
        readyUrl: `${rpOrigin}/api/mode3/rp_info`, logFile: rpLog,
      }));
      rp = client(rpOrigin, rpLog);
    }

    return {
      cia, wallet, rp, dir,
      rpOriginForWallet: rpOrigin,   // rp:false 여도 지갑에는 이 값을 CORS 오리진으로 넘겼다
      async stop() {
        for (const c of children.reverse()) await stopChild(c);
        await cia.stop();
        fs.rmSync(dir, { recursive: true, force: true });
      },
    };
  } catch (e) {
    for (const c of children.reverse()) await stopChild(c);
    await cia.stop();
    fs.rmSync(dir, { recursive: true, force: true });
    throw e;
  }
}
