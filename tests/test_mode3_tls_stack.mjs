// 세 서버 TLS 기동 — IdP https, RP https → IdP https 서버 간 호출(passkey-web Task 1). (chain 그룹: :8545 hardhat 노드)
//   node tests/test_mode3_tls_stack.mjs
// 자체 서명 인증서를 NODE_EXTRA_CA_CERTS 로 신뢰시켜야 fetch 가 통과한다 — 그 env 는 프로세스 시작 때만 읽히므로
// 인증서를 만들고 같은 파일을 그 env 로 다시 실행한다. 다시 실행했는지는 이 테스트의 표시(T_TLS_CERT)로 본다 — 사용자 셸에 NODE_EXTRA_CA_CERTS 가
// 이미 있어도(데모 CA 등) 건너뛰지 않는다(2026-11-17 미뤄 둔 Minor C). 격리 헬퍼는 자식의 NODE_EXTRA_CA_CERTS 를 비우므로 자식에게도 명시해 넘긴다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

if (!process.env.T_TLS_CERT) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-tls-stack-'));
  const c = path.join(dir, 'c.pem');
  const k = path.join(dir, 'k.pem');
  const gen = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', k, '-out', c], { stdio: 'pipe' });
  if (gen.status !== 0) { console.error('BLOCKED: openssl 로 시험용 인증서를 만들 수 없다'); process.exit(1); }
  const r = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
    env: { ...process.env, NODE_EXTRA_CA_CERTS: c, T_TLS_CERT: c, T_TLS_KEY: k }, stdio: 'inherit' });
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(r.status ?? 1);
}

const { startIsolatedCia, freePort } = await import('./helpers/isolated_cia.mjs');
const { spawnServer, stopChild, RP_ADMIN_SECRET } = await import('./helpers/isolated_mode3_stack.mjs');

const TLS = { MODE3_TLS_CERT: process.env.T_TLS_CERT, MODE3_TLS_KEY: process.env.T_TLS_KEY, NODE_EXTRA_CA_CERTS: process.env.T_TLS_CERT };
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

let cia = null;
let rpChild = null;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-tls-rp-'));
try {
  await t('IdP https', async () => {
    cia = await startIsolatedCia({ scheme: 'https', env: TLS });
    assert.ok(cia.base.startsWith('https://'), cia.base);
    assert.equal((await fetch(`${cia.base}/mode3/health`)).status, 200);
  });
  await t('RP https → IdP https 서버 간 호출', async () => {
    assert.ok(cia, 'IdP 가 떠 있어야 한다');
    const port = await freePort();
    const origin = `https://127.0.0.1:${port}`;
    rpChild = await spawnServer('mode3_rp.js', {
      env: {
        MODE3_RP_PORT: String(port),
        MODE3_CIA_URL: cia.base,
        MODE3_WALLET_AGENT_ORIGIN: `https://127.0.0.1:${await freePort()}`,   // rpSpawnFor 와 같은 키 — 지갑은 띄우지 않지만 셸 값이 새지 않게 이 테스트의 값으로
        CIA_LOG_ADDRESS: cia.logAddress,
        MODE3_MIRROR_ADDRESS: cia.mirrorAddress,
        MODE3_RP_REGISTRATION_FILE: path.join(tmp, 'mode3_rp_registration.json'),
        MODE3_RP_PUBLIC_ORIGIN: origin,
        MODE3_RP_LOGIN_LOG: path.join(tmp, 'mode3_rp_logins.jsonl'),
        MODE3_RP_ACCOUNTS_FILE: path.join(tmp, 'mode3_rp_accounts.json'),
        MODE3_RP_ADMIN_SECRET: RP_ADMIN_SECRET,
        ...TLS,
      },
      readyUrl: `${origin}/api/mode3/rp_info`, logFile: path.join(tmp, 'rp.log'),
    });
    // RP 가 https 로 IdP 에 등록 요청을 보냈다면 IdP 목록에 그 origin 이 보인다.
    const deadline = Date.now() + 30_000;
    let seen = false;
    while (Date.now() < deadline && !seen) {
      const list = (await cia.adminGet('/cia/rps')).body?.rps ?? [];
      seen = list.some((e) => e.origin === origin);
      if (!seen) await new Promise((r) => setTimeout(r, 300));
    }
    assert.ok(seen, `IdP 목록에 ${origin} 이 없다`);
  });
} finally {
  if (rpChild) await stopChild(rpChild);
  if (cia) await cia.stop();
  fs.rmSync(tmp, { recursive: true, force: true });
}
process.exit(failed === 0 ? 0 : 1);
