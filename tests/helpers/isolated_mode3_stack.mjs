// 격리 Mode 3 스택: 격리 CIA(isolated_cia.mjs) + 지갑 에이전트 + RP 를 임시 포트·임시 상태 파일로.
// :4100/:5100/:3100 개발용 프로세스를 건드리지 않는다. stop() 이 세 프로세스와 임시 디렉터리를 정리한다.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { startIsolatedCia, freePort } from './isolated_cia.mjs';
import { MODE3_ROOTS_ABI } from '../../lib/mode3_log.js';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));

// 자식은 dotenv/config 로 .env 를 읽는다 — 개발용 pk_CIA 고정·arid·TTL 이 새어 들어오면 격리 스택의 로그인이
// untrusted_cia 로 깨진다. 테스트가 기대하는 값으로 고정한다(dotenv 는 이미 있는 키를 덮지 않으므로 빈 문자열이
// "기본값 사용"이다). 호출자의 env 가 우선한다.
const PINNED_ENV = {
  CIA_RPC_URL: process.env.CIA_RPC_URL || 'http://127.0.0.1:8545',
  MODE3_PK_CIA_X: '', MODE3_PK_CIA_Y: '', MODE3_RP_REGISTRATION_FILE: '', MODE3_CHALLENGE_TTL_MS: '',
  MODE3_RP_REGISTRATION_POLL_MS: '300', MODE3_RP_LOGIN_LOG: '',
  MODE3_RP_FACTORY_ADDRESS: '', MODE3_VERIFIER_ADDRESS: '', MODE3_RELAYER_INDEX: '', MODE3_MAX_ROOT_AGE: '', MODE3_MAX_LIFETIME_BLOCKS: '',
  MODE3_TTL_BLOCKS: '', MODE3_HEIGHT_GRID: '', MODE3_ALLOWED_COUNTRIES: '', MODE3_MIN_AGE: '',
  MODE3_REV_CHAIN_RPC: '',   // V10: 지갑의 캐노니컬 RPC — 비우면 CIA_RPC_URL(격리 스택은 체인 하나)
};

/** node <script> 를 env 로 띄우고 readyUrl 이 200 을 줄 때까지 기다린다. */
async function spawnServer(script, { env, readyUrl, logFile, readyTimeoutMs = 60_000 }) {
  const out = fs.openSync(logFile, 'a');
  const child = spawn('node', [script], { cwd: REPO_ROOT, env: { ...process.env, ...PINNED_ENV, ...env }, stdio: ['ignore', out, out] });
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
  const { rp: withRp = true, rpEnv = {}, walletEnv = {}, ciaEnv = {}, extraRpOrigins = [], autoRelay = false } = opts;   // autoRelay: 아래 relayIfBehind 를 뒤에서 계속 돌린다(브라우저 각본용, V10)   // extraRpOrigins: 지갑 CORS 허용 목록에 더할 서비스 오리진(두 번째 서비스 시험용)
  // 지갑 포트·오리진은 CIA 보다 **먼저** 잡는다 — CIA 의 /mode3/health CORS 허용 목록(설계 2026-09-25 §1.2)에
  // MODE3_WALLET_AGENT_ORIGIN 으로 넘겨야 한다. 호출자의 ciaEnv 가 우선한다.
  const walletPort = await freePort();
  const walletOrigin = `http://127.0.0.1:${walletPort}`;
  const cia = await startIsolatedCia({ env: { MODE3_WALLET_AGENT_ORIGIN: walletOrigin, ...ciaEnv } });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-stack-'));
  const rpPort = await freePort();
  const rpOrigin = `http://127.0.0.1:${rpPort}`;
  const children = [];
  try {
    const walletLog = path.join(dir, 'wallet.log');
    const walletStateFile = path.join(dir, 'mode3_wallet_state.json');
    // 지갑 자식은 restartWallet() 이 같은 상태 파일·env 로 다시 띄운다(snap 모드의 "재시작 뒤 needs_consent" 시험용).
    const walletSpawn = { env: { MODE3_WALLET_PORT: String(walletPort), MODE3_WALLET_STATE_FILE: walletStateFile, MODE3_CIA_URL: cia.base, MODE3_RP_ORIGIN: [rpOrigin, ...extraRpOrigins].join(','), CIA_LOG_ADDRESS: cia.logAddress, MODE3_MIRROR_ADDRESS: cia.mirrorAddress, ...walletEnv }, readyUrl: `${walletOrigin}/wallet/status`, logFile: walletLog };
    let walletChild = await spawnServer('mode3_wallet_agent.js', walletSpawn);
    children.push(walletChild);
    const wallet = client(walletOrigin, walletLog);

    let rp = null;
    let rpChild = null;
    // RP 자식은 restartRp() 가 같은 등록 파일·오리진으로 다시 띄운다(이미 배포된 팩토리를 물고 뜨는 경로 시험용).
    let rpSpawn = null;
    if (withRp) {
      const rpLog = path.join(dir, 'rp.log');
      rpSpawn = {
        env: {
          MODE3_RP_PORT: String(rpPort),
          MODE3_CIA_URL: cia.base,
          MODE3_WALLET_AGENT_ORIGIN: walletOrigin,
          CIA_LOG_ADDRESS: cia.logAddress,   // RP 가 /api/mode3/rp_info 에 캐노니컬로 보여줄 뿐, 검증기는 아래 거울만 읽는다(V10)
          MODE3_MIRROR_ADDRESS: cia.mirrorAddress,
          MODE3_RP_REGISTRATION_FILE: path.join(dir, 'mode3_rp_registration.json'),
          MODE3_RP_PUBLIC_ORIGIN: rpOrigin,
          MODE3_RP_LOGIN_LOG: path.join(dir, 'mode3_rp_logins.jsonl'),
          ...rpEnv,
        },
        readyUrl: `${rpOrigin}/api/mode3/rp_info`, logFile: rpLog,
      };
      rpChild = await spawnServer('mode3_rp.js', rpSpawn);
      children.push(rpChild);
      rp = client(rpOrigin, rpLog);

      // 등록 승인 대행(2026-09-16 §3): RP 는 pending 으로 떠 있다. 관리자 시크릿으로 승인하고 활성화를 기다린다.
      // status==='approved' 만 보면 안 된다 — 그 값은 registerOnce() 가 세팅하고 activate() 는 그 뒤에 돌아,
      // "approved 인데 verifier 는 아직 null" 창이 컨트랙트 2개 배포 시간만큼 열린다(2026-09-23 리뷰 I-2).
      // rp_info.active(= verifier 가 생겼는가)까지 기다려야 첫 /challenge 가 503 을 맞지 않는다.
      const deadline = Date.now() + 60_000;
      let approved = false;
      while (Date.now() < deadline) {
        const list = (await cia.adminGet('/cia/rps')).body?.rps ?? [];
        const mine = list.find((e) => e.origin === rpOrigin);
        if (mine?.status === 'pending') await cia.adminPost(`/cia/rps/${mine.arid}/approve`);
        const info = (await rp.get('/api/mode3/rp_info')).body;
        if (info?.status === 'approved' && info?.active) { approved = true; break; }
        await new Promise((r) => setTimeout(r, 200));
      }
      if (!approved) throw new Error(`RP 등록 승인·활성화 실패\n${rp.log()}`);
    }

    // 거울 릴레이(V10 Task 9): 격리 CIA 는 릴레이 주기가 꺼져 있어(CIA_MIRROR_HEARTBEAT_BLOCKS=0) 거울은 /cia/admin/relay 로만
    // 오른다. 지갑은 새 자격증명 뒤 거울이 내 리프를 실을 때까지 기다리므로(registry_unpublished 폴링), 그 사이 릴레이를 대신
    // 눌러 주는 펌프가 필요하다 — 거울이 캐노니컬보다 뒤처졌을 때만 누른다(따라잡은 거울에 force 릴레이를 하면 캐노니컬
    // 하트비트가 하나 더 오른다).
    const canonC = new ethers.Contract(cia.logAddress, MODE3_ROOTS_ABI, cia.mirrorContract.runner);
    const relay = async () => {
      const r = await cia.adminPost('/cia/admin/relay', {});
      if (r.status !== 200) throw new Error(`relay 실패(${r.status}): ${JSON.stringify(r.body)}`);
      return r.body;
    };
    const relayIfBehind = async () => { if ((await canonC.epoch()) > (await cia.mirrorContract.epoch())) await relay(); };
    /** p(진행 중인 요청의 promise)가 끝날 때까지 거울이 뒤처지면 릴레이한다. 시작 전에 한 번 맞춰 둔다. */
    const withRelay = async (fn) => {
      await relayIfBehind();
      let done = false;
      const pump = (async () => { while (!done) { try { await relayIfBehind(); } catch { /* 다음 바퀴 */ } await new Promise((r) => setTimeout(r, 400)); } })();
      try { return await fn(); } finally { done = true; await pump; }
    };
    // 브라우저 각본(tour·browser)은 로그인이 페이지 안에서 일어나 withRelay 로 감쌀 수 없다 — 운영의 거울 하트비트 자리를 대신해
    // 거울이 뒤처지면 0.5초 안에 릴레이한다. 뒤처졌을 때만 누르므로 블록을 스스로 계속 만들지는 않는다.
    let autoTimer = null, autoBusy = false;
    if (autoRelay) {
      autoTimer = setInterval(async () => {
        if (autoBusy) return;
        autoBusy = true;
        try { await relayIfBehind(); } catch { /* 다음 틱 */ } finally { autoBusy = false; }
      }, 500);
    }

    return {
      cia, wallet, rp, dir, walletStateFile, relay, relayIfBehind, withRelay,
      rpOriginForWallet: rpOrigin,   // rp:false 여도 지갑에는 이 값을 CORS 오리진으로 넘겼다
      /** 지갑 자식만 죽이고 같은 상태 파일·env 로 다시 띄운다. 메모리(세션 witness·증명 캐시)만 사라진다. */
      async restartWallet() {
        await stopChild(walletChild);
        children.splice(children.indexOf(walletChild), 1);
        walletChild = await spawnServer('mode3_wallet_agent.js', walletSpawn);
        children.push(walletChild);
      },
      /**
       * RP 자식만 죽이고 같은 등록 파일·같은 공개 오리진으로 다시 띄운다(env 는 extraEnv 로 덮는다).
       * 메모리(챌린지·세션·logins 배열)만 사라진다 — 등록·팩토리·AttrGate 는 파일에 있어 그대로 물고 뜬다.
       * 팩토리 배포 뒤 env 만 바꿔 재기동하는 상황(2026-09-23 점검 D-I2)을 시험한다.
       * 기본으로 rp_info.active 까지 기다린다. 일부러 활성화에 실패시키는 시험(예: 팩토리가 아닌 주소를
       * MODE3_RP_FACTORY_ADDRESS 로 주기)에서는 waitActive:false 로 끈다.
       * **extraEnv 는 이전 재기동의 env 위에 누적된다** — 한 번 넣은 값은 뒤의 재기동에도 그대로 남는다.
       * 잘못된 팩토리 주소 등을 넣은 케이스 뒤에 정상 케이스를 두지 말 것(원인 불명의 503 factory_constants_unavailable
       * 로 깨진다). 꼭 필요하면 그 값을 되돌리는 extraEnv 를 명시적으로 다시 넘긴다(2026-09-23 최종 리뷰 M6).
       */
      async restartRp(extraEnv = {}, { waitActive = true } = {}) {
        if (!rpChild) throw new Error('restartRp: rp:false 로 띄운 스택이다');
        await stopChild(rpChild);
        children.splice(children.indexOf(rpChild), 1);
        rpSpawn = { ...rpSpawn, env: { ...rpSpawn.env, ...extraEnv } };
        rpChild = await spawnServer('mode3_rp.js', rpSpawn);
        children.push(rpChild);
        if (!waitActive) return;
        const deadline = Date.now() + 60_000;
        while (Date.now() < deadline) {
          if ((await rp.get('/api/mode3/rp_info')).body?.active) return;
          await new Promise((r) => setTimeout(r, 200));
        }
        throw new Error(`restartRp: 재기동한 RP 가 활성화되지 않았다\n${rp.log()}`);
      },
      async stop() {
        if (autoTimer) clearInterval(autoTimer);
        while (autoBusy) await new Promise((r) => setTimeout(r, 50));
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
