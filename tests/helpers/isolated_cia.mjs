// 격리 CIA 인스턴스. 임시 포트·임시 디렉터리·자체 키·자체 Mode3Log. :4100 개발용을 건드리지 않는다.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { getProvider, fundAddress, deployMode3Log, deployMode3Mirror } from './mode3_chain.mjs';
import { MODE3_MIRROR_ABI } from '../../lib/mode3_log.js';
import { createShare } from '../../lib/mode3_trace.js';
import { createRegistration, signRegistration } from '../../lib/mode3_wallet.js';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));

export function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
    s.on('error', reject);
  });
}

export async function startIsolatedCia(opts = {}) {
  const { env: extraEnv = {}, readyTimeoutMs = 30_000, oidc = null } = opts;
  // OIDC 래퍼(스펙 2026-10-16 Task 3): oidc 를 주면 발급자 스텁을 먼저 띄우고 그 설정을 env 로 넣는다. 옵션이 없으면
  // 빈 문자열로 고정한다 — 개발용 .env 의 GOOGLE_CLIENT_ID 가 새어 들어와 테스트 IdP 가 Google 을 켜지 않게 막는다.
  let oidcStub = null;
  if (oidc) {
    const { startOidcIssuerStub } = await import('./oidc_issuer_stub.mjs');
    oidcStub = await startOidcIssuerStub(typeof oidc === 'object' ? oidc : {});
  }
  // 두 체인(2026-10-03, test_mode3_demo_full.mjs): revRpcUrl 을 주면 캐노니컬 로그는 그 체인(폐기 체인)에, 거울은 appRpcUrl
  // (기본 CIA_RPC_URL 또는 :8545)에 배포한다. 둘 다 없으면 지금처럼 한 체인에 로그와 거울을 함께 둔다.
  const defaultRpc = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
  const twoChains = Boolean(opts.revRpcUrl);
  const appRpcUrl = opts.appRpcUrl || defaultRpc;
  const revRpcUrl = opts.revRpcUrl || appRpcUrl;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-cia-'));
  const port = await freePort();
  const adminSecret = randomBytes(16).toString('hex');
  const ethWallet = ethers.Wallet.createRandom();
  const provider = getProvider(appRpcUrl);                               // 응용 체인(거울·팩토리·계정). 단일 체인이면 유일한 체인
  const revProvider = twoChains ? getProvider(revRpcUrl) : provider;     // 폐기 체인(캐노니컬 Mode3Log)
  const ciaEthWallet = ethWallet.connect(revProvider);   // 테스트가 CIA 몰래 로그에 직접 게시할 때 씀(크래시 복구 테스트) — 로그가 있는 체인
  // CIA 의 이더 키는 두 체인 모두에서 가스가 필요하다 — 캐노니컬 게시는 폐기 체인, 거울 중계는 응용 체인.
  await fundAddress(ethWallet.address, '1', revProvider);
  if (twoChains) await fundAddress(ethWallet.address, '1', provider);
  const { address: logAddress } = await deployMode3Log(ethWallet.address, revProvider);
  const canonicalChainId = (await revProvider.getNetwork()).chainId;
  const appChainId = (await provider.getNetwork()).chainId;
  const { address: mirrorAddress } = await deployMode3Mirror(ethWallet.address, logAddress, provider, canonicalChainId);
  const rpcUrl = revRpcUrl;   // CIA_RPC_URL = 캐노니컬 로그가 있는 체인

  // 자식은 dotenv/config 로 .env 를 읽는다 — 개발용 값(체인 RPC·하트비트)이 새어 들어오지 않도록 테스트가 기대하는 값으로
  // 고정한다. dotenv 는 이미 있는 키(빈 문자열 포함)를 덮지 않으므로 빈 문자열이 "기본값 사용"이다(CIA_CHAIN_RPCS 가 비면
  // chainId 는 기동 시 RPC 에서 읽은 값 하나). 하트비트는 끈다 — 테스트가 기대하지 않은 epoch 증가·블록 소비를 막는다.
  // 하트비트 테스트는 extraEnv 로 다시 켠다. 옛 키(TTL·그리드·skew)는 CIA 가 경고만 내고 무시한다.
  // CIA_MIRRORS·CIA_CHAIN_RPCS·CIA_MIRROR_HEARTBEAT_BLOCKS 는 V10 거울 중계용(설계 §5). 릴레이 주기는 기본 '0'(끔) —
  // 거울 갱신을 보는 테스트(test_cia_mirror_relay.mjs)만 extraEnv 로 켠다(2026-10-02 Task 6).
  const env = {
    ...process.env,
    CIA_RPC_URL: rpcUrl,
    CIA_CHAIN_RPCS: `${appChainId}=${appRpcUrl}`,   // 세션 발급·거울 중계 대상 = 응용 체인(단일 체인이면 31337=:8545 로 지금과 같다)
    CIA_HEARTBEAT_BLOCKS: '0',
    CIA_MIRRORS: `${appChainId}=${mirrorAddress}`,
    CIA_MIRROR_HEARTBEAT_BLOCKS: '0',
    CIA_TTL_SECONDS: '', CIA_CHAIN_IDS: '',   // 옛 키 — 경고만 나오게 비운다
    CIA_PORT: String(port),
    CIA_STATE_FILE: path.join(dir, 'cia_state.json'),
    CIA_KEYS_FILE: path.join(dir, 'cia_keys.json'),
    CIA_ADMIN_SECRET: adminSecret,
    CIA_LOG_ADDRESS: logAddress,
    CIA_ETH_PRIVATE_KEY: ethWallet.privateKey,
    MODE3_OIDC_ISSUER: oidcStub?.issuer ?? '',
    MODE3_OIDC_JWKS_URL: oidcStub?.jwksUrl ?? '',
    MODE3_OIDC_CLIENT_ID: oidcStub?.clientId ?? '',
    MODE3_OIDC_PROVIDER: oidcStub?.provider ?? '',
    // cia.js 는 MODE3_OIDC_CLIENT_ID 가 비면 GOOGLE_CLIENT_ID(Mode 1 용, .env 에 있을 수 있다)로 떨어진다 — 그 값까지
    // 빈 문자열로 막아야 oidc 옵션 없는 격리 IdP 가 뜻하지 않게 Google 을 켜지 않는다.
    GOOGLE_CLIENT_ID: '',
    // 데모 설정(2026-10-21)은 기본으로 끈다 — 데모 스크립트가 내보낸 값이 셸에 남아 있어도 테스트 IdP 는 시크릿을 묻는다. 켜는 테스트만 extraEnv 로.
    CIA_ADMIN_OPEN: '',
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
    if (revProvider !== provider) revProvider.destroy();
    if (oidcStub) await oidcStub.stop();
    fs.rmSync(dir, { recursive: true, force: true });
    throw new Error(`격리 CIA 기동 실패(${port}).${spawnError ? ' spawn: ' + spawnError.message : ''}\n${log}`);
  }

  const adminHeaders = { 'Content-Type': 'application/json', 'X-CIA-Admin-Secret': adminSecret };
  const json = async (r) => ({ status: r.status, body: await r.json().catch(() => null) });
  return {
    base, port, dir, adminSecret, adminHeaders, ethAddress: ethWallet.address, logAddress, ciaEthWallet,
    mirrorAddress, mirrorContract: new ethers.Contract(mirrorAddress, MODE3_MIRROR_ABI, provider),
    oidc: oidcStub,   // Task 3: oidc:true 로 띄우면 발급자 스텁(mint·stop 포함), 아니면 null
    // 두 체인(2026-10-03): 캐노니컬은 revProvider, 거울은 provider(appProvider) 로 읽는다. 단일 체인이면 둘이 같은 객체다.
    twoChains, revRpcUrl, appRpcUrl, revProvider, appProvider: provider,
    log: () => (fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : ''),
    post: (p, body) => fetch(`${base}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body ?? {}) }).then(json),
    adminPost: (p, body) => fetch(`${base}${p}`, { method: 'POST', headers: adminHeaders, body: JSON.stringify(body ?? {}) }).then(json),
    get: (p) => fetch(`${base}${p}`).then(json),
    adminGet: (p) => fetch(`${base}${p}`, { headers: adminHeaders }).then(json),
    /** V11 등록(스펙 2026-10-12 §3.1): 지갑 키·auid 를 만들어 /cia/register 를 부른다. { s_u, auid, sk_u, pk_u, slot, body } */
    async registerUser(uid, pwd) {
      const reg = await createRegistration(BigInt(uid));
      const r = await this.post('/cia/register', { uid, pwd, auid: reg.auid.toString(), pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() }, sig_reg: await signRegistration(reg.sk_u, BigInt(uid), reg.auid) });
      if (r.status !== 201) throw new Error(`register 실패(${r.status}): ${JSON.stringify(r.body)}`);
      return { ...reg, slot: r.body.slot, body: r.body };
    },
    // 서비스 등록 + 운영자 승인 대행(설계 2026-09-16 §3). keys 를 주면 그 키로(재등록·불일치 테스트용).
    async registerRp(origin, name = 'test-rp', keys = null) {
      const serviceWallet = keys?.serviceWallet ?? ethers.Wallet.createRandom();
      const share = keys?.share ?? await createShare();
      const body = { name, origin, pk_service: serviceWallet.address, X_svc: { x: share.X.x.toString(), y: share.X.y.toString() } };
      const post = () => fetch(`${base}/cia/register_rp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(json);
      let r = await post();
      if (r.status === 202) {
        const a = await fetch(`${base}/cia/rps/${r.body.arid}/approve`, { method: 'POST', headers: adminHeaders }).then(json);
        if (a.status !== 200) throw new Error('approve 실패: ' + JSON.stringify(a.body));
        r = await post();
      }
      if (r.status !== 200) throw new Error('register_rp 실패: ' + JSON.stringify(r.body));
      return { arid: r.body.arid, origin: r.body.origin, cert_s: r.body.cert_s, pk_trace: { x: BigInt(r.body.pk_trace.x), y: BigInt(r.body.pk_trace.y) }, serviceWallet, share };
    },
    async stop() {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGTERM');
        await new Promise((resolve) => {
          const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } resolve(); }, 3000);
          child.once('exit', () => { clearTimeout(t); resolve(); });
        });
      }
      provider.destroy();   // fundAddress/deployMode3Log/ciaEthWallet 가 같이 쓰던 provider
      if (revProvider !== provider) revProvider.destroy();
      if (oidcStub) await oidcStub.stop();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}
