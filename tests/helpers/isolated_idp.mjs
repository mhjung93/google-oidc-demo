// 격리된 custom_idp.js 인스턴스를 띄우는 테스트 하네스.
//
// 왜 필요한가. 지금까지 IdP 테스트는 개발자가 띄워 둔 :4000 인스턴스를 상대로만 돌 수
// 있었다. 그래서 (1) clean checkout이나 CI에서 실행이 불가능했고, (2) 관리자 시크릿을
// 테스트가 스스로 마련할 수 없었으며, (3) **실패 경로를 돌리면 그 인스턴스가 망가지므로**
// 실패 경로 테스트 자체를 쓸 수 없었다. 이 하네스는 임시 디렉터리·임의 포트·자체 시크릿으로
// 인스턴스를 따로 띄워 그 셋을 모두 없앤다.
//
// 체인 접근만은 격리하지 못한다 — IdP가 기동과 게시 경로에서 블록 높이를 읽으므로
// ETH_RPC_URL(기본 http://127.0.0.1:8545)에 hardhat 노드가 떠 있어야 한다.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

// 포트 충돌을 피하려고 매번 다른 포트를 쓴다(고정 포트를 쓰면 테스트를 겹쳐 돌릴 수 없다).
function randomPort() {
  return 4100 + Math.floor(Math.random() * 800);
}

/**
 * 격리 IdP를 띄운다. 반환값의 stop()을 반드시 호출해야 프로세스가 남지 않는다.
 *
 * @param {object} [opts]
 * @param {Record<string,string>} [opts.env] custom_idp.js에 넘길 추가 환경변수
 *   (예: IDP_MUTATION_LOG_MAX, IDP_REBASELINE_FORCE_RATIO)
 * @param {number} [opts.readyTimeoutMs]
 */
export async function startIsolatedIdP(opts = {}) {
  const { env: extraEnv = {}, readyTimeoutMs = 30_000 } = opts;

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'idp-test-'));
  const port = randomPort();
  const adminSecret = randomBytes(16).toString('hex');
  const auditorSecret = randomBytes(16).toString('hex');
  const logFile = path.join(dir, 'idp.log');

  const env = {
    ...process.env,
    CUSTOM_IDP_PORT: String(port),
    IDP_STATE_FILE: path.join(dir, 'idp_state.json'),
    IDP_KEY_FILE: path.join(dir, 'idp_keys.json'),
    IDP_ADMIN_SECRET: adminSecret,
    IDP_AUDITOR_SECRET: auditorSecret,
    ...extraEnv,
  };

  const out = fs.openSync(logFile, 'a');
  const child = spawn('node', ['custom_idp.js'], { cwd: REPO_ROOT, env, stdio: ['ignore', out, out] });

  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + readyTimeoutMs;
  let ready = false;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) break;
    try {
      const r = await fetch(`${base}/idp/revocation_state_v2`);
      if (r.ok) {
        ready = true;
        break;
      }
    } catch {
      /* 아직 기동 중 */
    }
    await new Promise((r) => setTimeout(r, 200));
  }

  if (!ready) {
    const log = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : '(로그 없음)';
    try {
      child.kill('SIGKILL');
    } catch {
      /* 이미 죽었다 */
    }
    throw new Error(`격리 IdP가 뜨지 않았다 (port ${port}). 로그:\n${log}`);
  }

  const adminHeaders = { 'Content-Type': 'application/json', 'X-IdP-Admin-Secret': adminSecret };

  return {
    base,
    port,
    dir,
    adminSecret,
    auditorSecret,
    adminHeaders,
    log: () => (fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : ''),
    /** 관리자 인증이 붙은 POST. { status, body }를 돌려준다(에러 응답도 그대로 본다). */
    async post(pathname, body) {
      const r = await fetch(`${base}${pathname}`, {
        method: 'POST',
        headers: adminHeaders,
        body: JSON.stringify(body ?? {}),
      });
      return { status: r.status, body: await r.json().catch(() => null) };
    },
    async get(pathname) {
      const r = await fetch(`${base}${pathname}`);
      return { status: r.status, body: await r.json().catch(() => null) };
    },
    async stop() {
      if (child.exitCode === null) {
        child.kill('SIGTERM');
        await new Promise((resolve) => {
          const t = setTimeout(() => {
            try {
              child.kill('SIGKILL');
            } catch {
              /* 이미 죽었다 */
            }
            resolve();
          }, 3000);
          child.once('exit', () => {
            clearTimeout(t);
            resolve();
          });
        });
      }
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** 폐기 1건을 접수하고 곧바로 게시까지 마친다(테스트에서 가장 흔한 조작). */
export async function revokeAndPublish(idp, value, type = 'account') {
  const revoked = await idp.post('/idp/revoke', { type, value });
  if (revoked.status !== 200) throw new Error(`revoke -> ${revoked.status} ${JSON.stringify(revoked.body)}`);
  const prepared = await idp.post('/idp/publish/prepare');
  if (prepared.status !== 200) throw new Error(`prepare -> ${prepared.status} ${JSON.stringify(prepared.body)}`);
  const committed = await idp.post('/idp/publish/commit', { root: prepared.body.expectedRoot });
  if (committed.status !== 200) throw new Error(`commit -> ${committed.status} ${JSON.stringify(committed.body)}`);
  return { prepared: prepared.body, committed: committed.body };
}
