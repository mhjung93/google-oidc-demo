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

// 포트 충돌을 피한다. 고정 포트를 쓰면 테스트를 겹쳐 돌릴 수 없고, 임의 포트를 그냥
// 쓰면 **남의 인스턴스가 이미 잡고 있는 포트**를 고를 수 있다 — 그 경우 아래 준비 확인이
// 남의 IdP에서 200을 받아 ready로 판정해 버리고, 테스트가 격리되지 않은 인스턴스의 폐기
// 트리를 바꾼다(이 하네스가 막으려는 바로 그 사고다). 그래서 OS가 비어 있다고 확인해 준
// 포트만 쓴다: 0번 포트로 listen해 커널이 배정한 번호를 받고 곧바로 닫는다.
async function freePort() {
  const { createServer } = await import('node:net');
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

/**
 * 격리 IdP를 띄운다. 반환값의 stop()을 반드시 호출해야 프로세스가 남지 않는다.
 *
 * @param {object} [opts]
 * @param {Record<string,string>} [opts.env] custom_idp.js에 넘길 추가 환경변수
 *   (예: IDP_MUTATION_LOG_MAX, IDP_REBASELINE_FORCE_RATIO)
 * @param {string} [opts.dir] 기존 인스턴스의 상태·키 디렉터리를 재사용한다.
 *   설정만 바꿔 **재기동**하는 상황(운영자가 임계치를 조정하는 등)을 재현할 때 쓴다.
 *   이 경우 stop()이 디렉터리를 지우지 않는다 — 만든 쪽이 지운다.
 * @param {number} [opts.readyTimeoutMs]
 */
export async function startIsolatedIdP(opts = {}) {
  const { env: extraEnv = {}, dir: reuseDir, readyTimeoutMs = 30_000 } = opts;

  const dir = reuseDir ?? fs.mkdtempSync(path.join(os.tmpdir(), 'idp-test-'));
  const port = await freePort();
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
  // 'error'(spawn 자체 실패: node 없음, cwd 없음 등) 리스너가 없으면 처리되지 않은
  // 예외로 테스트 프로세스가 죽어, 아래의 진단 메시지에 도달하지 못한다.
  let spawnError = null;
  child.on('error', (err) => {
    spawnError = err;
  });

  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + readyTimeoutMs;
  let ready = false;
  while (Date.now() < deadline) {
    // 시그널로 죽은 경우 exitCode는 null이고 signalCode가 채워진다 — 둘 다 봐야
    // 타임아웃까지 기다리지 않고 곧바로 실패 보고를 할 수 있다.
    if (child.exitCode !== null || child.signalCode !== null) break;
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
    // 임시 디렉터리에는 이 인스턴스가 만든 idp_keys.json(PS/EdDSA 개인키)이 들어 있다.
    // 실패 경로에서 지우지 않으면 /tmp에 개인키가 계속 쌓인다. 재사용 디렉터리는
    // 만든 쪽 책임이므로 건드리지 않는다.
    if (!reuseDir) fs.rmSync(dir, { recursive: true, force: true });
    const cause = spawnError ? ` spawn 실패: ${spawnError.message}.` : '';
    throw new Error(`격리 IdP가 뜨지 않았다 (port ${port}).${cause} 로그:\n${log}`);
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
      // exitCode만 보면 시그널로 죽은 자식(exitCode === null, signalCode 채워짐)에 대해
      // 이미 끝난 'exit'를 다시 기다리게 되어 매번 3초 타임아웃을 소비한다.
      if (child.exitCode === null && child.signalCode === null) {
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
      // 재사용 디렉터리는 지우지 않는다(만든 쪽이 책임진다).
      if (!reuseDir) fs.rmSync(dir, { recursive: true, force: true });
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
