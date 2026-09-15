// 격리 CIA 인스턴스. 임시 포트·임시 디렉터리·자체 키·자체 RevocationLog. :4100 개발용을 건드리지 않는다.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { getProvider, fundAddress, deployRevocationLog } from './mode3_chain.mjs';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));

export function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
    s.on('error', reject);
  });
}

export async function startIsolatedCia(opts = {}) {
  const { env: extraEnv = {}, readyTimeoutMs = 30_000 } = opts;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-cia-'));
  const port = await freePort();
  const adminSecret = randomBytes(16).toString('hex');
  const ethWallet = ethers.Wallet.createRandom();
  const provider = getProvider();
  const ciaEthWallet = ethWallet.connect(provider);   // 테스트가 CIA 몰래 로그에 직접 게시할 때 씀(크래시 복구 테스트)
  await fundAddress(ethWallet.address, '1', provider);
  const { address: logAddress } = await deployRevocationLog(ethWallet.address, provider);

  // 자식은 dotenv/config 로 .env 를 읽는다 — 개발용 값(CIA_TTL_SECONDS·CIA_CHAIN_IDS 포함)이 새어 들어오지
  // 않도록 테스트가 기대하는 값으로 고정한다. dotenv 는 이미 있는 키(빈 문자열 포함)를 덮지 않으므로
  // 빈 문자열이 "기본값 사용"(TTL 3600 초, chainId 는 기동 시 RPC 에서 읽은 값 하나)이 된다.
  const env = {
    ...process.env,
    CIA_RPC_URL: process.env.CIA_RPC_URL || 'http://127.0.0.1:8545',
    CIA_TTL_SECONDS: '',
    CIA_CHAIN_IDS: '',
    CIA_PORT: String(port),
    CIA_STATE_FILE: path.join(dir, 'cia_state.json'),
    CIA_KEYS_FILE: path.join(dir, 'cia_keys.json'),
    CIA_ADMIN_SECRET: adminSecret,
    CIA_LOG_ADDRESS: logAddress,
    CIA_ETH_PRIVATE_KEY: ethWallet.privateKey,
    ...extraEnv,
  };
  const logFile = path.join(dir, 'cia.log');
  const out = fs.openSync(logFile, 'a');
  const child = spawn('node', ['cia.js'], { cwd: REPO_ROOT, env, stdio: ['ignore', out, out] });
  let spawnError = null;
  child.on('error', (e) => { spawnError = e; });

  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + readyTimeoutMs;
  let ready = false;
  while (Date.now() < deadline) {
    if (spawnError || child.exitCode !== null) break;
    try {
      const r = await fetch(`${base}/cia/public_keys`);
      if (r.ok) { ready = true; break; }
    } catch { /* not yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  if (!ready) {
    const log = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : '';
    try { child.kill('SIGKILL'); } catch { /* */ }
    // 기동 거부가 정상 경로인 테스트(test_cia_startup.mjs)가 있다 — 실패해도 잔존물을 남기지 않는다.
    provider.destroy();
    fs.rmSync(dir, { recursive: true, force: true });
    throw new Error(`격리 CIA 기동 실패(${port}).${spawnError ? ' spawn: ' + spawnError.message : ''}\n${log}`);
  }

  const adminHeaders = { 'Content-Type': 'application/json', 'X-CIA-Admin-Secret': adminSecret };
  const json = async (r) => ({ status: r.status, body: await r.json().catch(() => null) });
  return {
    base, port, dir, adminSecret, adminHeaders, ethAddress: ethWallet.address, logAddress, ciaEthWallet,
    log: () => (fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : ''),
    post: (p, body) => fetch(`${base}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body ?? {}) }).then(json),
    adminPost: (p, body) => fetch(`${base}${p}`, { method: 'POST', headers: adminHeaders, body: JSON.stringify(body ?? {}) }).then(json),
    get: (p) => fetch(`${base}${p}`).then(json),
    registerRp: (origin, name = 'test-rp') => fetch(`${base}/cia/register_rp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, origin }) }).then(json).then((r) => { if (r.status !== 201 && r.status !== 200) throw new Error('register_rp 실패: ' + JSON.stringify(r.body)); return { arid: r.body.arid, cert_s: r.body.cert_s, origin: r.body.origin }; }),
    async stop() {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGTERM');
        await new Promise((resolve) => {
          const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } resolve(); }, 3000);
          child.once('exit', () => { clearTimeout(t); resolve(); });
        });
      }
      provider.destroy();   // fundAddress/deployRevocationLog/ciaEthWallet 가 같이 쓰던 provider
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}
