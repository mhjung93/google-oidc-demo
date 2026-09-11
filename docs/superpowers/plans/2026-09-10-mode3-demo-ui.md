# Mode 3 데모 UI 연동 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 단계 (a)의 라이브러리(`lib/mode3_wallet.js`, `lib/mode3_rp.js`)와 `cia.js` 위에 지갑 에이전트(:5100)·RP(:3100)·CIA 관리자 패널을 올려, 브라우저 버튼만으로 "등록 → 로그인(자동 발급) → 폐기·게시 → `stale_root` 거절 → `account_disabled` → 복구 → 로그인, PPID 동일"이 시연되게 하고 그 전 구간을 HTTP 테스트로 고정한다.

**Architecture:** 새 프로세스 둘 — `mode3_wallet_agent.js`(지갑 상태 파일 + 트리 동기화 + 증명, `lib/mode3_wallet.js`를 그대로 씀)와 `mode3_rp.js`(challenge 발급 + `createRpVerifier`) — 와 정적 페이지 셋(`mode3/`). 발급은 로그인 안에서 필요할 때 자동으로 일어난다(스펙 §3.3). `cia.js`에는 `/admin` 페이지 라우트와 dotenv만 붙는다. 격리 하네스가 세 프로세스를 임시 포트로 띄워 chain 그룹 테스트가 한 프로세스에서 조립한다.

**Tech Stack:** Node.js ESM, express 5, `cors`(이미 의존성), ethers 6, `lib/mode3_*.js`, vanilla JS 페이지. 새 의존성 없음.

**Spec:** `docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md` (이하 "스펙"). 프로토콜 설계는 `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` (이하 "설계").

## Global Constraints

- **Mode 2 파일을 건드리지 않는다:** `server.js`, `client.js`, `index.html`, `wallet_agent.js`, `custom_idp.js`, `lib/imt_v3.js`, `contracts/`, `circuits/`, `build/`. `lib/mode3_*.js`도 이 계획에서는 수정하지 않는다.
- **실행 중인 데모(:3000/:4000/:5001)를 절대 건드리지 않는다.** 새 포트는 :5100(지갑), :3100(RP). CIA는 :4100. 격리 테스트는 임시 포트·임시 디렉터리를 쓴다.
- **:8545 hardhat 노드는 사용자 프로세스다.** chain 그룹 테스트는 거기 `RevocationLog`를 새로 배포해 쓴다(기존 `isolated_cia.mjs`가 한다).
- 정적 파일은 **허용 목록 `sendFile`만**. `express.static`으로 루트를 서빙하지 않는다(스펙 §2).
- 지갑 에이전트·RP는 `127.0.0.1`에 바인드. CORS는 지갑의 `/wallet/login`에 RP 오리진만(함수형 `origin`으로 일치할 때만 헤더를 붙인다).
- `/wallet/login` 응답에 `uid`를 넣지 않는다(스펙 §3.2).
- 비밀(`sk_u`, `s_u`, `r_u`, `blind`, 세션 개인키, 관리자 secret)은 로그·응답·`localStorage`에 쓰지 않는다. 상태 파일은 0600.
- BigInt는 JSON 경계에서 10진 문자열이다(기존 규약).
- 새 테스트는 `scripts/run_tests.sh` CHAIN에 등록한다.
- 커밋은 태스크마다 하되 **사용자 승인 후** 한다(CLAUDE.md). 커밋 메시지 끝에 세션 attribution 두 줄을 붙인다.
- `cia_state.json`·`mode3_wallet_state.json`을 지우지 않는다(재시연은 스펙 §7의 한 세트로만).

---

## File Structure

| 파일 | 책임 |
|---|---|
| `mode3_wallet_agent.js` (신규) | 지갑 상태 파일, `/wallet/register`·`/wallet/login`·`/wallet/status`, 지갑 페이지 서빙. `lib/mode3_wallet.js` 호출만 한다 |
| `mode3_rp.js` (신규) | `pk_CIA` 고정(env 또는 TOFU), challenge Map, `/api/mode3/*`, 로그인 페이지 서빙. `lib/mode3_rp.js` 호출만 한다 |
| `mode3/wallet.html`, `mode3/rp.html`, `mode3/cia_admin.html` (신규) | 페이지 셋. 각각 자기 서버의 API만 부른다(RP 페이지만 지갑 `/wallet/login`을 CORS로 부른다) |
| `cia.js` (수정) | `import 'dotenv/config'` + `GET /admin` 한 라우트 |
| `tests/helpers/isolated_cia.mjs` (수정) | `freePort` export |
| `tests/helpers/isolated_mode3_stack.mjs` (신규) | 격리 CIA + 지갑 에이전트 + RP 기동·정리 |
| `tests/test_mode3_wallet_agent.mjs` (신규) | 지갑 에이전트 단독(RP 없이, 검증기는 테스트 안에서 조립) |
| `tests/test_mode3_demo_stack.mjs` (신규) | 세 프로세스 HTTP 전 구간 + challenge 음성 + 페이지 서빙 |
| `scripts/deploy_mode3_log.cjs` (수정) | 배포하면서 CIA 주소에 ETH를 채운다(게시 tx 가스) |
| `docs/MODE3_DEMO.md` (신규) | 기동 순서·env·시연 각본·재시연 메모 |
| `.gitignore`, `scripts/run_tests.sh` (수정) | `mode3_wallet_state.json`, CHAIN 등록 |

---

### Task 1: 지갑 에이전트 `mode3_wallet_agent.js`와 격리 하네스

**Files:**
- Create: `mode3_wallet_agent.js`
- Create: `tests/helpers/isolated_mode3_stack.mjs`
- Modify: `tests/helpers/isolated_cia.mjs` (`freePort`에 `export`)
- Test: `tests/test_mode3_wallet_agent.mjs`

**Interfaces:**
- Consumes (`lib/mode3_wallet.js`): `createRegistration() → {s_u, r_u, cm_u}`, `createSessionKey() → {wallet, pk_i}`, `buildIssueRequest({uid, arid, s_u, r_u, sk_u, session}) → {body, secrets:{blind}}`, `syncRevocationTree(provider, logAddress) → {tree, root, epoch, head}`, `buildCredentialProof({uid, arid, s_u, blind, pk_i, credential, pk_CIA, tree}) → {proof, publicSignals, revRoot}`, `signChallenge(wallet, challenge) → Promise<string>`, `ProofCache`. (`lib/mode3_revocation.js`) `credLeaf(C) → bigint`, `tree.has(leaf) → boolean`. (`lib/mode3_issuance.js`) `pointToStrings`. (`lib/mode3_state.js`) `readJson(file, fallback)`, `writeJsonAtomic(file, obj, mode)`. (`tests/helpers/isolated_cia.mjs`) `startIsolatedCia() → {base, logAddress, adminPost, post, get, stop, ...}`.
- Produces (HTTP, 지갑 에이전트):
  - `GET /wallet/status → 200 {registered, uid|null, credentials:{[arid]:{max_height, sessionAddress, issuedAt}}, head|null, lastRoot|null, cachedProofRoot|null, logAddress}`
  - `POST /wallet/register {uid, pwd} → 201 {uid}` | 400 | 409 `{reason:'already_registered'}` | CIA 401/409 그대로 | 502 `{reason:'register_failed', cia}`
  - `POST /wallet/login {arid, challenge, skipSync?} → 200 {proof, publicSignals, sig, pk_i, root, issued, cacheHit, timings:{syncMs, issueMs, proveMs}}` | 400 | 409 `{reason:'not_registered'|'no_cached_proof'}` | 403 `{reason:'account_disabled'}` | 502 `{reason:'issue_failed', cia}` | 503 `{reason:'chain_unavailable'}`
  - `GET / → mode3/wallet.html` (Task 3에서 파일이 생긴다. 그전에는 404)
  - env: `MODE3_WALLET_PORT`(5100), `MODE3_WALLET_STATE_FILE`, `MODE3_CIA_URL`, `MODE3_RP_ORIGIN`, `CIA_LOG_ADDRESS`(필수), `CIA_RPC_URL`
- Produces (하네스): `startIsolatedMode3Stack({ rp = true } = {}) → { cia, wallet:{base, origin, get, post, log}, rp:{base, origin, get, post, log}|null, stop() }`. `rp:false`면 RP를 띄우지 않는다(이 태스크에서는 `mode3_rp.js`가 아직 없다).

- [x] **Step 1: `isolated_cia.mjs`의 `freePort`를 export 한다**

`tests/helpers/isolated_cia.mjs` 14행 `function freePort() {` → `export function freePort() {`. 다른 변경 없음.

- [x] **Step 2: 격리 하네스를 쓴다**

`tests/helpers/isolated_mode3_stack.mjs`:

```js
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
```

- [x] **Step 3: 실패하는 테스트를 쓴다**

`tests/test_mode3_wallet_agent.mjs`:

```js
// Mode 3 지갑 에이전트 단독. RP 없이 검증기는 이 프로세스에서 조립한다. (chain 그룹)
//   node tests/test_mode3_wallet_agent.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { VKEY_PATH } from '../lib/mode3_wallet.js';
import { createRpVerifier } from '../lib/mode3_rp.js';

const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const provider = getProvider();
const stack = await startIsolatedMode3Stack({ rp: false });
const { cia, wallet } = stack;
const uid = '12345', arid = '22222222222222222222';
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));

try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  const rp = createRpVerifier({ provider, logAddress: cia.logAddress, vkey, pkCIA: pk_CIA, arid: BigInt(arid) });

  async function verify(body, challenge) {
    return rp.verifyLogin({ proof: body.proof, publicSignals: body.publicSignals, challenge, sig: body.sig });
  }

  await t('미등록 상태: status.registered=false, login 은 409 not_registered', async () => {
    const s = await wallet.get('/wallet/status');
    assert.equal(s.status, 200);
    assert.equal(s.body.registered, false);
    const r = await wallet.post('/wallet/login', { arid, challenge: 'c0' });
    assert.equal(r.status, 409);
    assert.equal(r.body.reason, 'not_registered');
  });

  await t('등록: 201, 두 번째는 409, 잘못된 pwd 는 CIA 의 401 을 그대로', async () => {
    const r = await wallet.post('/wallet/register', { uid, pwd: 'password123' });
    assert.equal(r.status, 201, j(r.body));
    assert.deepEqual(r.body, { uid });
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123' })).status, 409);
    const s = await wallet.get('/wallet/status');
    assert.equal(s.body.registered, true);
    assert.equal(s.body.uid, uid);
  });

  let first, PPID1;
  await t('첫 로그인: 자동 발급(issued=true) + 검증 통과, 응답에 uid 없음', async () => {
    const challenge = 'login-1';
    const r = await wallet.post('/wallet/login', { arid, challenge });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, true);
    assert.equal(r.body.cacheHit, false);
    assert.ok(!('uid' in r.body), 'uid 는 RP 로 나가면 안 된다');
    assert.equal(typeof r.body.timings.proveMs, 'number');
    const v = await verify(r.body, challenge);
    assert.equal(v.ok, true, j(v));
    first = r.body; PPID1 = v.PPID;
    const s = await wallet.get('/wallet/status');
    assert.ok(s.body.credentials[arid], 'arid 별 credential 이 상태에 있어야 한다');
    assert.equal(s.body.cachedProofRoot, r.body.root);
  });

  await t('두 번째 로그인: 캐시 히트(cacheHit=true, issued=false), publicSignals 동일, σ 만 새로', async () => {
    const challenge = 'login-2';
    const r = await wallet.post('/wallet/login', { arid, challenge });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, false);
    assert.equal(r.body.cacheHit, true);
    assert.deepEqual(r.body.publicSignals, first.publicSignals);
    assert.notEqual(r.body.sig, first.sig);
    assert.equal((await verify(r.body, challenge)).ok, true);
  });

  await t('CORS: RP 오리진에만 Access-Control-Allow-Origin, 다른 오리진엔 없음', async () => {
    const good = await wallet.raw('/wallet/login', { method: 'OPTIONS', headers: { Origin: stack.rpOriginForWallet, 'Access-Control-Request-Method': 'POST' } });
    assert.equal(good.headers.get('access-control-allow-origin'), stack.rpOriginForWallet);
    const bad = await wallet.raw('/wallet/login', { method: 'OPTIONS', headers: { Origin: 'http://evil.example', 'Access-Control-Request-Method': 'POST' } });
    assert.equal(bad.headers.get('access-control-allow-origin'), null);
  });

  await t('계정 폐기 + 게시 → skipSync 로그인은 옛 π 를 그대로 → 검증기 stale_root', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'account' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const challenge = 'stale';
    const r = await wallet.post('/wallet/login', { arid, challenge, skipSync: true });
    assert.equal(r.status, 200, j(r.body));
    assert.deepEqual(r.body.publicSignals, first.publicSignals);
    const v = await verify(r.body, challenge);
    assert.equal(v.ok, false);
    assert.equal(v.reason, 'stale_root');
  });

  await t('동기화 로그인: 폐기 감지 → 재발급 시도 → CIA 403 → account_disabled', async () => {
    const r = await wallet.post('/wallet/login', { arid, challenge: 'after-revoke' });
    assert.equal(r.status, 403, j(r.body));
    assert.equal(r.body.reason, 'account_disabled');
  });

  await t('복구 → 로그인: 재발급(issued=true), 검증 통과, PPID 동일', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
    const challenge = 'after-recover';
    const r = await wallet.post('/wallet/login', { arid, challenge });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.issued, true);
    const v = await verify(r.body, challenge);
    assert.equal(v.ok, true, j(v));
    assert.equal(v.PPID, PPID1, 'PPID 는 폐기·복구로 바뀌지 않는다');
  });

  await t('입력 검증: arid 비10진 / challenge 없음 → 400', async () => {
    assert.equal((await wallet.post('/wallet/login', { arid: '0x1', challenge: 'c' })).status, 400);
    assert.equal((await wallet.post('/wallet/login', { arid })).status, 400);
  });
} finally {
  await stack.stop();
  provider.destroy();
}
process.exit(failed === 0 ? 0 : 1);
```

- [x] **Step 4: 실패를 확인한다**

```bash
node tests/test_mode3_wallet_agent.mjs
```

Expected: `mode3_wallet_agent.js 기동 실패` 로 throw (파일 없음: `Cannot find module`). exit 1.

- [x] **Step 5: 지갑 에이전트를 쓴다**

`mode3_wallet_agent.js`:

```js
// Mode 3 지갑 에이전트 (:5100). 스펙: docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md §3
//
// Mode 2 의 wallet_agent.js 와 나란히 두는 별도 프로세스다. 그쪽 코드를 import 하지 않는다.
// 암호학은 전부 lib/mode3_wallet.js 에 있고 여기는 상태 파일 + HTTP 만이다.
// 발급은 로그인 안에서 필요할 때(없음·만료·폐기됨) 자동으로 일어난다(스펙 §3.3, 설계 §6.2 "세션마다").
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { readJson, writeJsonAtomic } from './lib/mode3_state.js';
import { createRegistration, createSessionKey, buildIssueRequest, syncRevocationTree, buildCredentialProof, signChallenge, ProofCache } from './lib/mode3_wallet.js';
import { pointToStrings } from './lib/mode3_issuance.js';
import { credLeaf } from './lib/mode3_revocation.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.MODE3_WALLET_PORT) || 5100;
const STATE_FILE = process.env.MODE3_WALLET_STATE_FILE || path.join(__dirname, 'mode3_wallet_state.json');
const CIA_URL = process.env.MODE3_CIA_URL || 'http://127.0.0.1:4100';
const RP_ORIGIN = process.env.MODE3_RP_ORIGIN || 'http://127.0.0.1:3100';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';

// 게시 직후의 로그인이 옛 root 를 보지 않도록 ethers 의 250ms 캐시를 끈다(lib/mode3_wallet.js 주석).
const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 });

// ---- 상태 ----
// registration: { uid, s_u, r_u, cm_u:{x,y}, sk_u }            §6.1. 한 번
// credentials:  arid → { credential:{C,max_height,sigma,pk_CIA}, blind, sessionPrivKey, pk_i, issuedAt }
// BigInt 는 전부 10진 문자열. 데모용이라 비밀이 평문으로 들어간다(0600).
let state = readJson(STATE_FILE, { version: 1, registration: null, credentials: {} });
function persist() { writeJsonAtomic(STATE_FILE, state, 0o600); }

const cache = new ProofCache();   // (root, 세션 주소) → {proof, publicSignals}. 메모리만
let lastSync = null;              // { root, head }
let lastProof = null;             // skipSync 재제출용: { arid, sessionPrivKey, pk_i, root, proof, publicSignals }

const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const json = async (r) => ({ status: r.status, body: await r.json().catch(() => null) });
const ciaPost = (p, body) => fetch(`${CIA_URL}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(json);

async function issueCredential(arid) {
  const reg = state.registration;
  const session = createSessionKey();
  const req = await buildIssueRequest({
    uid: BigInt(reg.uid), arid: BigInt(arid), s_u: BigInt(reg.s_u), r_u: BigInt(reg.r_u), sk_u: reg.sk_u, session,
  });
  const r = await ciaPost('/cia/issue', req.body);
  if (r.status === 200) {
    state.credentials[arid] = {
      credential: r.body, blind: req.secrets.blind.toString(),
      sessionPrivKey: session.wallet.privateKey, pk_i: session.pk_i.toString(),
      issuedAt: new Date().toISOString(),
    };
    persist();
  }
  return r;
}

// ---- 앱 ----
const app = express();
app.use(express.json({ limit: '1mb' }));

// RP 페이지(다른 오리진)가 부르는 것은 /wallet/login 뿐이다. 문자열 origin 은 cors 가 요청 Origin 과
// 무관하게 헤더를 붙이므로, 일치할 때만 붙이도록 함수형으로 둔다.
const loginCors = cors({ origin: (origin, cb) => cb(null, origin === RP_ORIGIN), methods: ['POST'] });
app.options('/wallet/login', loginCors);

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'wallet.html')));

app.get('/wallet/status', async (req, res) => {
  let head = null;
  try { head = (await provider.getBlockNumber()).toString(); } catch { /* 체인 없음 */ }
  const credentials = {};
  for (const [arid, e] of Object.entries(state.credentials)) {
    credentials[arid] = { max_height: e.credential.max_height, sessionAddress: new ethers.Wallet(e.sessionPrivKey).address, issuedAt: e.issuedAt };
  }
  res.json({
    registered: Boolean(state.registration), uid: state.registration?.uid ?? null, credentials,
    head, lastRoot: lastSync?.root ?? null, cachedProofRoot: lastProof?.root ?? null, logAddress: LOG_ADDRESS,
  });
});

app.post('/wallet/register', async (req, res) => {
  try {
    const { uid, pwd } = req.body ?? {};
    if (!isDec(uid) || typeof pwd !== 'string') return res.status(400).json({ error: 'uid(10진 문자열), pwd 필요' });
    if (state.registration) return res.status(409).json({ reason: 'already_registered', uid: state.registration.uid });
    const reg = await createRegistration();
    const r = await ciaPost('/cia/register', { uid, pwd, cm_u: pointToStrings(reg.cm_u) });
    if (r.status !== 201) {
      const status = r.status === 401 || r.status === 409 ? r.status : 502;
      return res.status(status).json({ reason: 'register_failed', cia: r.body });
    }
    state.registration = { uid, s_u: reg.s_u.toString(), r_u: reg.r_u.toString(), cm_u: pointToStrings(reg.cm_u), sk_u: r.body.sk_u };
    persist();
    res.status(201).json({ uid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/wallet/login', loginCors, async (req, res) => {
  try {
    const { arid, challenge, skipSync } = req.body ?? {};
    if (!isDec(arid) || typeof challenge !== 'string' || challenge.length === 0) return res.status(400).json({ error: 'arid(10진 문자열), challenge 필요' });
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    if (!LOG_ADDRESS) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });

    // 시연용: 동기화·발급을 건너뛰고 마지막 π 를 그대로 재제출한다(RP 의 stale_root 거절을 보이기 위해).
    if (skipSync) {
      if (!lastProof || lastProof.arid !== arid) return res.status(409).json({ reason: 'no_cached_proof' });
      const sig = await signChallenge(new ethers.Wallet(lastProof.sessionPrivKey), challenge);
      return res.json({ proof: lastProof.proof, publicSignals: lastProof.publicSignals, sig, pk_i: lastProof.pk_i, root: lastProof.root.toString(), issued: false, cacheHit: true, timings: { syncMs: 0, issueMs: 0, proveMs: 0 } });
    }

    const timings = { syncMs: 0, issueMs: 0, proveMs: 0 };
    let t = Date.now();
    let synced;
    try { synced = await syncRevocationTree(provider, LOG_ADDRESS); }
    catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    timings.syncMs = Date.now() - t;
    lastSync = { root: synced.root.toString(), head: synced.head.toString() };

    // 없거나, 만료됐거나, 폐기 트리에 있으면 새로 발급받는다.
    let entry = state.credentials[arid];
    let issued = false;
    const needIssue = !entry
      || synced.head > BigInt(entry.credential.max_height)
      || synced.tree.has(await credLeaf(BigInt(entry.credential.C)));
    if (needIssue) {
      t = Date.now();
      const r = await issueCredential(arid);
      timings.issueMs = Date.now() - t;
      if (r.status === 403) return res.status(403).json({ reason: 'account_disabled', timings });
      if (r.status !== 200) return res.status(502).json({ reason: 'issue_failed', cia: r.body, timings });
      entry = state.credentials[arid];
      issued = true;
    }

    const reg = state.registration;
    const sessionWallet = new ethers.Wallet(entry.sessionPrivKey);
    let cached = cache.get(synced.root, sessionWallet.address);
    const cacheHit = Boolean(cached);
    if (!cached) {
      t = Date.now();
      cached = await buildCredentialProof({
        uid: BigInt(reg.uid), arid: BigInt(arid), s_u: BigInt(reg.s_u), blind: BigInt(entry.blind), pk_i: BigInt(entry.pk_i),
        credential: entry.credential, pk_CIA: { x: BigInt(entry.credential.pk_CIA.x), y: BigInt(entry.credential.pk_CIA.y) }, tree: synced.tree,
      });
      timings.proveMs = Date.now() - t;
      cache.set(synced.root, sessionWallet.address, cached);
    }
    lastProof = { arid, sessionPrivKey: entry.sessionPrivKey, pk_i: entry.pk_i, root: synced.root, proof: cached.proof, publicSignals: cached.publicSignals };
    const sig = await signChallenge(sessionWallet, challenge);
    res.json({ proof: cached.proof, publicSignals: cached.publicSignals, sig, pk_i: entry.pk_i, root: synced.root.toString(), issued, cacheHit, timings });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Mode 3 wallet agent at http://127.0.0.1:${PORT} (cia=${CIA_URL}, rp=${RP_ORIGIN}, log=${LOG_ADDRESS ?? 'none'})`);
});
```

- [x] **Step 6: 통과를 확인한다**

```bash
node tests/test_mode3_wallet_agent.mjs
```

Expected: 9줄 `ok`, exit 0. 실패하면 `stack.wallet.log()`로 에이전트 로그를 본다(테스트 `finally` 전에 `console.error(wallet.log())`를 임시로 넣어도 된다 — 커밋 전에 지운다).

- [x] **Step 7: 포트·프로세스 잔존 확인**

```bash
ss -ltn | grep -E ':(3000|4000|4100|5001|5100|3100)\b'; pgrep -af 'mode3_wallet_agent|cia.js' | grep -v pgrep
```

Expected: 둘 다 비어 있음(개발용 포트가 원래 떠 있었다면 그것만).

- [x] **Step 8: 커밋 (사용자 승인 후)**

```bash
git add mode3_wallet_agent.js tests/helpers/isolated_mode3_stack.mjs tests/helpers/isolated_cia.mjs tests/test_mode3_wallet_agent.mjs
git commit -m "feat(mode3): 지갑 에이전트 — 등록·로그인(자동 발급)·skipSync 재제출·상태 파일, 격리 스택 하네스"
```

---

### Task 2: RP `mode3_rp.js`와 전 구간 HTTP 테스트

**Files:**
- Create: `mode3_rp.js`
- Test: `tests/test_mode3_demo_stack.mjs`

**Interfaces:**
- Consumes: Task 1의 지갑 API·하네스(`startIsolatedMode3Stack()` 기본값 `rp:true`, `rpEnv`). `lib/mode3_rp.js`의 `createRpVerifier({provider, logAddress, vkey, pkCIA, arid}) → {verifyLogin({proof, publicSignals, challenge, sig}) → {ok, PPID, pk_i} | {ok:false, reason}}`. `lib/mode3_wallet.js`의 `VKEY_PATH`.
- Produces (HTTP, RP):
  - `GET /api/mode3/rp_info → 200 {arid, logAddress, walletAgentOrigin, pkCiaSource:'env'|'tofu'}`
  - `POST /api/mode3/challenge → 200 {challenge, expiresAt}`
  - `POST /api/mode3/login {challenge, proof, publicSignals, sig} → 200 {ok:true, PPID, pk_i, root}` | 401 `{ok:false, reason:'bad_challenge'}` | 200 `{ok:false, reason}`(검증기 reason 그대로) | 400
  - `GET /api/mode3/logins → 200 {logins:[{PPID, at, root}]}`
  - `GET / → mode3/rp.html`
  - env: `MODE3_RP_PORT`(3100), `MODE3_RP_ARID`(`22222222222222222222`), `MODE3_PK_CIA_X`/`MODE3_PK_CIA_Y`, `MODE3_CIA_URL`, `MODE3_WALLET_AGENT_ORIGIN`, `CIA_LOG_ADDRESS`(필수), `CIA_RPC_URL`, `MODE3_CHALLENGE_TTL_MS`(120000)

- [x] **Step 1: 실패하는 테스트를 쓴다**

`tests/test_mode3_demo_stack.mjs`:

```js
// Mode 3 데모 스택 전 구간(HTTP): 격리 CIA + 지갑 에이전트 + RP. 스펙 §6 시연 각본 8단계 + challenge 음성.
//   node tests/test_mode3_demo_stack.mjs
import assert from 'node:assert/strict';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';

const j = (o) => JSON.stringify(o);
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

// 만료 테스트용 짧은 TTL. 단 첫 로그인(발급+증명, 1~3초)이 TTL 안에 끝나야 하므로 너무 짧게 잡지 않는다.
const stack = await startIsolatedMode3Stack({ rpEnv: { MODE3_CHALLENGE_TTL_MS: '6000' } });
const { cia, wallet, rp } = stack;
const uid = '12345';

/** 브라우저의 RP 페이지가 하는 일을 그대로: rp_info → challenge → 지갑 login → RP login. */
async function loginViaRp({ skipSync = false } = {}) {
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const { challenge } = (await rp.post('/api/mode3/challenge')).body;
  const w = await wallet.post('/wallet/login', { arid: info.arid, challenge, skipSync }, { Origin: rp.origin });
  if (w.status !== 200) return { walletStatus: w.status, wallet: w.body };
  const r = await rp.post('/api/mode3/login', { challenge, proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig });
  return { walletStatus: 200, wallet: w.body, rpStatus: r.status, rp: r.body };
}

try {
  await t('rp_info: arid·logAddress·walletAgentOrigin, pk_CIA 는 TOFU', async () => {
    const r = await rp.get('/api/mode3/rp_info');
    assert.equal(r.status, 200);
    assert.equal(r.body.arid, '22222222222222222222');
    assert.equal(r.body.logAddress, cia.logAddress);
    assert.equal(r.body.walletAgentOrigin, wallet.origin);
    assert.equal(r.body.pkCiaSource, 'tofu');
  });

  await t('1. 등록', async () => {
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123' })).status, 201);
  });

  let PPID1, firstSignals;
  await t('2. 로그인: 자동 발급 + RP ok, PPID', async () => {
    const r = await loginViaRp();
    assert.equal(r.walletStatus, 200, j(r));
    assert.equal(r.wallet.issued, true);
    assert.equal(r.rpStatus, 200);
    assert.equal(r.rp.ok, true, j(r.rp));
    assert.match(r.rp.PPID, /^[0-9]+$/);
    PPID1 = r.rp.PPID; firstSignals = r.wallet.publicSignals;
  });

  await t('3. 로그인 (다시): 캐시 히트, 같은 PPID', async () => {
    const r = await loginViaRp();
    assert.equal(r.wallet.cacheHit, true);
    assert.equal(r.rp.ok, true, j(r.rp));
    assert.equal(r.rp.PPID, PPID1);
    const l = await rp.get('/api/mode3/logins');
    assert.equal(l.body.logins.length, 2);
  });

  await t('4. 계정 폐기 + 게시', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'account' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
  });

  await t('5. skipSync 로그인 → RP stale_root', async () => {
    const r = await loginViaRp({ skipSync: true });
    assert.equal(r.walletStatus, 200, j(r));
    assert.deepEqual(r.wallet.publicSignals, firstSignals);
    assert.equal(r.rp.ok, false);
    assert.equal(r.rp.reason, 'stale_root');
  });

  await t('6. 동기화 로그인 → 지갑 403 account_disabled (RP 까지 안 간다)', async () => {
    const r = await loginViaRp();
    assert.equal(r.walletStatus, 403, j(r));
    assert.equal(r.wallet.reason, 'account_disabled');
  });

  await t('7. 복구', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
  });

  await t('8. 로그인: 재발급 + RP ok, PPID 동일', async () => {
    const r = await loginViaRp();
    assert.equal(r.walletStatus, 200, j(r));
    assert.equal(r.wallet.issued, true);
    assert.equal(r.rp.ok, true, j(r.rp));
    assert.equal(r.rp.PPID, PPID1);
  });

  await t('challenge 음성: 미발급 → 401, 재사용 → 401', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const { challenge } = (await rp.post('/api/mode3/challenge')).body;
    const w = (await wallet.post('/wallet/login', { arid: info.arid, challenge })).body;
    const body = { challenge, proof: w.proof, publicSignals: w.publicSignals, sig: w.sig };
    const fake = await rp.post('/api/mode3/login', { ...body, challenge: 'deadbeef'.repeat(8) });
    assert.equal(fake.status, 401);
    assert.equal(fake.body.reason, 'bad_challenge');
    assert.equal((await rp.post('/api/mode3/login', body)).body.ok, true);
    const again = await rp.post('/api/mode3/login', body);
    assert.equal(again.status, 401);
    assert.equal(again.body.reason, 'bad_challenge');
  });

  await t('challenge 음성: 만료(TTL 6s) → 401', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const { challenge } = (await rp.post('/api/mode3/challenge')).body;
    const w = (await wallet.post('/wallet/login', { arid: info.arid, challenge })).body;
    await new Promise((r) => setTimeout(r, 6500));
    const r = await rp.post('/api/mode3/login', { challenge, proof: w.proof, publicSignals: w.publicSignals, sig: w.sig });
    assert.equal(r.status, 401);
    assert.equal(r.body.reason, 'bad_challenge');
  });

  await t('challenge 음성: 다른 challenge 에 대한 σ → bad_signature (challenge 는 소비됨)', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const a = (await rp.post('/api/mode3/challenge')).body.challenge;
    const b = (await rp.post('/api/mode3/challenge')).body.challenge;
    const w = (await wallet.post('/wallet/login', { arid: info.arid, challenge: a })).body;
    const r = await rp.post('/api/mode3/login', { challenge: b, proof: w.proof, publicSignals: w.publicSignals, sig: w.sig });
    assert.equal(r.status, 200);
    assert.equal(r.body.ok, false);
    assert.equal(r.body.reason, 'bad_signature');
  });

  await t('login 입력 검증: 필드 누락 → 400', async () => {
    assert.equal((await rp.post('/api/mode3/login', { challenge: 'x' })).status, 400);
  });
} finally {
  await stack.stop();
}
process.exit(failed === 0 ? 0 : 1);
```

- [x] **Step 2: 실패를 확인한다**

```bash
node tests/test_mode3_demo_stack.mjs
```

Expected: `mode3_rp.js 기동 실패` throw, exit 1.

- [x] **Step 3: RP 를 쓴다**

`mode3_rp.js`:

```js
// Mode 3 RP (:3100). 스펙: docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md §4
//
// server.js(:3000, Mode 1/2)와 나란히 두는 별도 프로세스다. 그쪽 코드를 import 하지 않는다.
// 검증(설계 §6.3 7단계)은 전부 lib/mode3_rp.js 에 있고 여기는 challenge 관리 + HTTP 만이다.
// 세션·쿠키는 없다 — 데모의 요점은 검증 결과다(스펙 §4.2).
import 'dotenv/config';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { createRpVerifier } from './lib/mode3_rp.js';
import { VKEY_PATH } from './lib/mode3_wallet.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.MODE3_RP_PORT) || 3100;
const ARID = process.env.MODE3_RP_ARID || '22222222222222222222';   // e2e 와 같은 값. < 2^250
const CIA_URL = process.env.MODE3_CIA_URL || 'http://127.0.0.1:4100';
const WALLET_ORIGIN = process.env.MODE3_WALLET_AGENT_ORIGIN || 'http://127.0.0.1:5100';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const CHALLENGE_TTL_MS = Number(process.env.MODE3_CHALLENGE_TTL_MS) || 120_000;

if (!LOG_ADDRESS) { console.error('[rp] CIA_LOG_ADDRESS 가 없다'); process.exit(1); }
if (!/^[0-9]+$/.test(ARID)) { console.error('[rp] MODE3_RP_ARID 는 10진 문자열이어야 한다'); process.exit(1); }

// pk_CIA 고정(설계 §5 — 유일한 위조 방어선). env 가 있으면 그것, 없으면 기동 시 CIA 에서 한 번 받아
// 프로세스 수명 동안 고정한다(TOFU, 데모 단축). 기동 후에는 CIA 에 다시 묻지 않는다(설계 §9.9).
async function resolvePkCia() {
  const { MODE3_PK_CIA_X: x, MODE3_PK_CIA_Y: y } = process.env;
  if (x && y) return { x: BigInt(x), y: BigInt(y), source: 'env' };
  const r = await fetch(`${CIA_URL}/cia/public_keys`);
  if (!r.ok) throw new Error(`CIA ${CIA_URL} 에서 pk_CIA 를 받지 못했다 (${r.status})`);
  const k = await r.json();
  console.warn(`[rp] pk_CIA 를 CIA 에서 받아 고정한다(TOFU). 운영이라면 env 로 박는다:\n  MODE3_PK_CIA_X=${k.pk_CIA.x}\n  MODE3_PK_CIA_Y=${k.pk_CIA.y}`);
  return { x: BigInt(k.pk_CIA.x), y: BigInt(k.pk_CIA.y), source: 'tofu' };
}

const pkCIA = await resolvePkCia();
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 });
const verifier = createRpVerifier({ provider, logAddress: LOG_ADDRESS, vkey, pkCIA, arid: BigInt(ARID) });

// ---- challenge: 메모리, TTL, 1회용 ----
const challenges = new Map();   // challenge → expiresAt(ms)
function sweepChallenges() { const now = Date.now(); for (const [c, exp] of challenges) if (exp < now) challenges.delete(c); }
function issueChallenge() {
  sweepChallenges();
  const challenge = randomBytes(32).toString('hex');
  const expiresAt = Date.now() + CHALLENGE_TTL_MS;
  challenges.set(challenge, expiresAt);
  return { challenge, expiresAt };
}
/** 있으면 지우고(1회용) 만료 여부를 돌려준다. 검증 전에 부른다 — 실패해도 재사용 못 하게. */
function consumeChallenge(challenge) {
  const exp = challenges.get(challenge);
  if (exp === undefined) return false;
  challenges.delete(challenge);
  return Date.now() <= exp;
}

const logins = [];   // { PPID, at, root }. 메모리만

// ---- 앱 ----
const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'rp.html')));

app.get('/api/mode3/rp_info', (req, res) => {
  res.json({ arid: ARID, logAddress: LOG_ADDRESS, walletAgentOrigin: WALLET_ORIGIN, pkCiaSource: pkCIA.source });
});

app.post('/api/mode3/challenge', (req, res) => res.json(issueChallenge()));

app.post('/api/mode3/login', async (req, res) => {
  try {
    const { challenge, proof, publicSignals, sig } = req.body ?? {};
    if (typeof challenge !== 'string' || !proof || !Array.isArray(publicSignals) || typeof sig !== 'string') {
      return res.status(400).json({ ok: false, reason: 'malformed' });
    }
    if (!consumeChallenge(challenge)) return res.status(401).json({ ok: false, reason: 'bad_challenge' });
    const v = await verifier.verifyLogin({ proof, publicSignals, challenge, sig });
    if (!v.ok) return res.json({ ok: false, reason: v.reason });
    const root = String(publicSignals[4]);
    logins.push({ PPID: v.PPID.toString(), at: new Date().toISOString(), root });
    res.json({ ok: true, PPID: v.PPID.toString(), pk_i: v.pk_i.toString(), root });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});

app.get('/api/mode3/logins', (req, res) => res.json({ logins }));

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Mode 3 RP at http://127.0.0.1:${PORT} (arid=${ARID}, log=${LOG_ADDRESS}, wallet=${WALLET_ORIGIN}, pk_CIA=${pkCIA.source})`);
});
```

- [x] **Step 4: 통과를 확인한다**

```bash
node tests/test_mode3_demo_stack.mjs
```

Expected: 13줄 `ok`, exit 0. (만료 테스트가 6.5초 기다린다.)

- [x] **Step 5: 포트·프로세스 잔존 확인 후 커밋 (사용자 승인 후)** — CHAIN 등록은 Task 4 를 기다리지 않고 여기서 함께 했다(CLAUDE.md 규칙)

```bash
ss -ltn | grep -E ':(3100|5100)\b'; pgrep -af 'mode3_rp|mode3_wallet_agent|cia.js' | grep -v pgrep
git add mode3_rp.js tests/test_mode3_demo_stack.mjs
git commit -m "feat(mode3): RP 서버 — pk_CIA 고정(env/TOFU)·1회용 challenge·로그인 검증, 데모 스택 전 구간 HTTP 테스트"
```

---

### Task 3: 페이지 셋과 CIA `/admin`

**Files:**
- Create: `mode3/wallet.html`, `mode3/rp.html`, `mode3/cia_admin.html`
- Modify: `cia.js` (import 블록 첫 줄에 `import 'dotenv/config';`, `/cia/public_keys` 라우트 바로 위에 `GET /admin`)
- Modify: `tests/test_mode3_demo_stack.mjs` (페이지 서빙 3건 추가)

**Interfaces:**
- Consumes: Task 1·2의 HTTP API, `cia.js`의 기존 `GET /cia/state`, `POST /cia/revoke`, `POST /cia/publish`, `POST /cia/account/set_disabled` (관리자 헤더 `X-CIA-Admin-Secret`).
- Produces: `GET /`(지갑·RP), `GET /admin`(CIA) → `text/html`.

- [ ] **Step 1: 페이지 서빙 테스트를 `test_mode3_demo_stack.mjs` 끝(`login 입력 검증` 다음, `finally` 앞)에 추가한다**

```js
  await t('페이지 서빙: 지갑 /, RP /, CIA /admin 이 text/html', async () => {
    for (const [c, p, marker] of [[wallet, '/', 'Mode 3 지갑'], [rp, '/', 'Mode 3 로그인'], [cia, '/admin', 'CIA 관리자']]) {
      const r = await fetch(`${c.base}${p}`);
      assert.equal(r.status, 200, `${p}`);
      assert.match(r.headers.get('content-type') ?? '', /text\/html/);
      assert.ok((await r.text()).includes(marker), `${p} 에 "${marker}" 가 있어야 한다`);
    }
  });
```

- [ ] **Step 2: 실패를 확인한다**

```bash
node tests/test_mode3_demo_stack.mjs 2>&1 | tail -5
```

Expected: 마지막 테스트만 `FAIL 페이지 서빙 ...` (404), 나머지 13줄 ok.

- [ ] **Step 3: 지갑 페이지**

`mode3/wallet.html`:

```html
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="referrer" content="same-origin" />
  <title>Mode 3 지갑</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 760px; margin: 24px auto; padding: 0 16px; }
    fieldset { border: 2px solid #4CAF50; margin-bottom: 16px; }
    pre { background: #f6f6f6; padding: 10px; white-space: pre-wrap; font-size: 0.85em; }
    .muted { color: #666; font-size: 0.9em; }
  </style>
</head>
<body>
  <h2>Mode 3 지갑 에이전트</h2>
  <p class="muted">이 페이지는 지갑 에이전트(:5100)와 같은 오리진에서만 열린다. 비밀은 <code>mode3_wallet_state.json</code>에 있고 화면에 나오지 않는다.</p>

  <fieldset>
    <legend>등록 (§6.1, 한 번)</legend>
    <label>uid <input id="uid" value="12345" size="8" /></label>
    <label>pwd <input id="pwd" type="password" value="password123" size="12" /></label>
    <button id="registerBtn">등록</button>
    <span id="registerResult" class="muted"></span>
  </fieldset>

  <fieldset>
    <legend>상태 <button id="refreshBtn">새로고침</button></legend>
    <pre id="status">불러오는 중…</pre>
  </fieldset>

  <p class="muted">로그인·발급은 RP 페이지(:3100)의 버튼이 시작한다 — 발급은 로그인 안에서 필요할 때 자동으로 일어난다(설계 §6.2 "세션마다").</p>

  <script>
    const $ = (id) => document.getElementById(id);
    async function refresh() {
      try {
        const r = await fetch('/wallet/status');
        const s = await r.json();
        const lines = [
          `등록: ${s.registered ? `예 (uid=${s.uid})` : '아니오'}`,
          `체인 head: ${s.head ?? '(RPC 없음)'}   RevocationLog: ${s.logAddress ?? '(없음)'}`,
          `마지막 동기화 root: ${s.lastRoot ?? '-'}`,
          `캐시된 π 의 root:   ${s.cachedProofRoot ?? '-'}`,
          '',
          'credentials (arid 별):',
        ];
        const entries = Object.entries(s.credentials);
        if (entries.length === 0) lines.push('  (없음)');
        for (const [arid, c] of entries) lines.push(`  arid=${arid}\n    max_height=${c.max_height}  세션 주소=${c.sessionAddress}\n    발급=${c.issuedAt}`);
        $('status').textContent = lines.join('\n');
      } catch (e) { $('status').textContent = `상태 조회 실패: ${e.message}`; }
    }
    $('registerBtn').addEventListener('click', async () => {
      $('registerResult').textContent = '…';
      const r = await fetch('/wallet/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ uid: $('uid').value.trim(), pwd: $('pwd').value }) });
      const b = await r.json().catch(() => ({}));
      $('registerResult').textContent = r.status === 201 ? `등록됨 (uid=${b.uid})` : `${r.status}: ${b.reason ?? b.error ?? ''} ${b.cia ? JSON.stringify(b.cia) : ''}`;
      refresh();
    });
    $('refreshBtn').addEventListener('click', refresh);
    refresh();
  </script>
</body>
</html>
```

- [ ] **Step 4: RP 로그인 페이지**

`mode3/rp.html`:

```html
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="referrer" content="same-origin" />
  <title>Mode 3 RP</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 760px; margin: 24px auto; padding: 0 16px; }
    fieldset { border: 2px solid #1976d2; margin-bottom: 16px; }
    pre { background: #f6f6f6; padding: 10px; white-space: pre-wrap; font-size: 0.85em; }
    .ok { color: #2e7d32; font-weight: bold; } .bad { color: #c62828; font-weight: bold; }
    .muted { color: #666; font-size: 0.9em; }
  </style>
</head>
<body>
  <h2>Mode 3 로그인 (RP)</h2>
  <p class="muted" id="rpInfo">RP 정보 불러오는 중…</p>

  <fieldset>
    <legend>로그인</legend>
    <button id="loginBtn">Mode 3 로그인</button>
    <label><input type="checkbox" id="skipSync" /> 동기화 생략(캐시된 π 재사용) — 폐기 후 <code>stale_root</code> 거절 시연</label>
    <p id="verdict"></p>
    <pre id="log"></pre>
  </fieldset>

  <fieldset>
    <legend>이 RP 에 기록된 로그인 <button id="refreshLogins">새로고침</button></legend>
    <pre id="logins">-</pre>
  </fieldset>

  <script>
    const $ = (id) => document.getElementById(id);
    let info = null;
    const post = (url, body) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body ?? {}) });
    const ms = (t0) => `${Date.now() - t0} ms`;

    async function loadInfo() {
      info = await (await fetch('/api/mode3/rp_info')).json();
      $('rpInfo').textContent = `arid=${info.arid}   RevocationLog=${info.logAddress}   지갑 에이전트=${info.walletAgentOrigin}   pk_CIA=${info.pkCiaSource}`;
    }
    async function refreshLogins() {
      const { logins } = await (await fetch('/api/mode3/logins')).json();
      $('logins').textContent = logins.length ? logins.map((l) => `${l.at}  PPID=${l.PPID}  root=${l.root.slice(0, 18)}…`).join('\n') : '(없음)';
    }
    $('loginBtn').addEventListener('click', async () => {
      $('loginBtn').disabled = true; $('verdict').textContent = ''; $('log').textContent = '';
      const log = (s) => { $('log').textContent += s + '\n'; };
      try {
        if (!info) await loadInfo();
        let t0 = Date.now();
        const { challenge } = await (await post('/api/mode3/challenge')).json();
        log(`1. challenge 발급 ${ms(t0)}: ${challenge.slice(0, 16)}…`);

        t0 = Date.now();
        const w = await post(`${info.walletAgentOrigin}/wallet/login`, { arid: info.arid, challenge, skipSync: $('skipSync').checked });
        const wb = await w.json().catch(() => ({}));
        if (w.status !== 200) {
          log(`2. 지갑 ${w.status} ${ms(t0)}: ${wb.reason ?? wb.error ?? ''} ${wb.detail ?? ''}`);
          $('verdict').innerHTML = `<span class="bad">로그인 실패 — 지갑: ${wb.reason ?? w.status}</span>`;
          return;
        }
        const tm = wb.timings ?? {};
        log(`2. 지갑 π+σ ${ms(t0)} (동기화 ${tm.syncMs} ms, 발급 ${tm.issueMs} ms, 증명 ${tm.proveMs} ms, 캐시 히트=${wb.cacheHit}, 새 발급=${wb.issued})\n   root=${wb.root}`);

        t0 = Date.now();
        const r = await post('/api/mode3/login', { challenge, proof: wb.proof, publicSignals: wb.publicSignals, sig: wb.sig });
        const rb = await r.json();
        log(`3. RP 검증 ${ms(t0)}: ${JSON.stringify(rb)}`);
        $('verdict').innerHTML = rb.ok
          ? `<span class="ok">로그인 성공</span> PPID=${rb.PPID}`
          : `<span class="bad">거절: ${rb.reason}</span>`;
        refreshLogins();
      } catch (e) {
        log(`오류: ${e.message}`);
        $('verdict').innerHTML = `<span class="bad">오류</span>`;
      } finally { $('loginBtn').disabled = false; }
    });
    $('refreshLogins').addEventListener('click', refreshLogins);
    loadInfo().then(refreshLogins);
  </script>
</body>
</html>
```

- [ ] **Step 5: CIA 관리자 패널**

`mode3/cia_admin.html`:

```html
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="referrer" content="same-origin" />
  <title>Mode 3 CIA 관리자</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 760px; margin: 24px auto; padding: 0 16px; }
    fieldset { border: 2px solid #ef6c00; margin-bottom: 16px; }
    pre { background: #f6f6f6; padding: 10px; white-space: pre-wrap; font-size: 0.85em; }
    .muted { color: #666; font-size: 0.9em; }
  </style>
</head>
<body>
  <h2>Mode 3 CIA 관리자</h2>
  <p class="muted">secret 은 요청 헤더로만 쓰고 저장하지 않는다. 폐기는 append-only 다 — 게시하면 되돌릴 수 없다(설계 §6.5).</p>

  <fieldset>
    <legend>인증</legend>
    <label>CIA_ADMIN_SECRET <input id="secret" type="password" size="36" /></label>
    <label style="margin-left:12px">uid <input id="uid" value="12345" size="8" /></label>
  </fieldset>

  <fieldset>
    <legend>조작</legend>
    <button id="stateBtn">상태 보기</button>
    <button id="revokeBtn">계정 폐기 (scope=account)</button>
    <button id="publishBtn">게시 (root → 체인)</button>
    <button id="recoverBtn">복구 (disabled=false)</button>
  </fieldset>

  <pre id="out">-</pre>

  <script>
    const $ = (id) => document.getElementById(id);
    async function call(method, path, body) {
      const headers = { 'Content-Type': 'application/json', 'X-CIA-Admin-Secret': $('secret').value };
      const r = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
      const b = await r.json().catch(() => null);
      $('out').textContent = `${method} ${path} → ${r.status}\n${JSON.stringify(b, null, 2)}`;
    }
    $('stateBtn').addEventListener('click', () => call('GET', '/cia/state'));
    $('revokeBtn').addEventListener('click', () => call('POST', '/cia/revoke', { uid: $('uid').value.trim(), scope: 'account' }));
    $('publishBtn').addEventListener('click', () => call('POST', '/cia/publish', {}));
    $('recoverBtn').addEventListener('click', () => call('POST', '/cia/account/set_disabled', { uid: $('uid').value.trim(), disabled: false }));
  </script>
</body>
</html>
```

`GET /cia/state`는 관리자 헤더가 필요 없지만 같은 `call()`로 보내도 무해하다.

- [ ] **Step 6: `cia.js` 두 곳**

(1) 파일 맨 위 import 블록의 첫 import 앞에 한 줄:

```js
import 'dotenv/config';
```

(2) `app.get('/cia/public_keys', ...)` 바로 위에:

```js
// 관리자 패널(스펙 §5). 페이지 하나만 허용 목록으로 내보낸다 — express.static 은 쓰지 않는다.
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'cia_admin.html')));
```

- [ ] **Step 7: 통과를 확인한다**

```bash
node tests/test_mode3_demo_stack.mjs 2>&1 | tail -3
bash scripts/run_tests.sh unit 2>&1 | tail -3
```

Expected: 14줄 ok; unit 8/8 (dotenv 추가가 `test_cia_register_issue.mjs` 같은 격리 CIA 테스트를 깨지 않는지는 Task 4의 chain 그룹에서 본다).

- [ ] **Step 8: 커밋 (사용자 승인 후)**

```bash
git add mode3/wallet.html mode3/rp.html mode3/cia_admin.html cia.js tests/test_mode3_demo_stack.mjs
git commit -m "feat(mode3): 지갑·RP 로그인·CIA 관리자 페이지, cia.js /admin 라우트 + dotenv"
```

---

### Task 4: 배포 스크립트 자금, 문서, 등록, 실제 스택 스모크

**Files:**
- Modify: `scripts/deploy_mode3_log.cjs` (CIA 주소에 ETH 송금)
- Create: `docs/MODE3_DEMO.md`
- Modify: `.gitignore` (`mode3_wallet_state.json`), `scripts/run_tests.sh` (CHAIN에 2개)

**Interfaces:** 새 인터페이스 없음.

- [ ] **Step 1: 배포 스크립트가 CIA 주소에 자금을 넣게 한다**

CIA 가 `/cia/publish`에서 tx 를 보내려면 ETH 가 필요하다. 격리 하네스는 `fundAddress`로 넣어주지만 실제 데모에는 그 단계가 없었다. `scripts/deploy_mode3_log.cjs`의 `const log = await F.deploy(cia, emptyRoot);` 앞에:

```js
  // CIA 는 publishRoot tx 를 자기 키로 보낸다 — hardhat 기본 계정에서 가스비를 채워 준다.
  const [funder] = await hre.ethers.getSigners();
  const bal = await hre.ethers.provider.getBalance(cia);
  if (bal < hre.ethers.parseEther("0.5")) {
    await (await funder.sendTransaction({ to: cia, value: hre.ethers.parseEther("1") })).wait();
    console.log(`funded ${cia} with 1 ETH`);
  }
```

- [ ] **Step 2: `.gitignore`와 `run_tests.sh`**

`.gitignore`의 `cia_state.json` 다음 줄에 `mode3_wallet_state.json`.

`scripts/run_tests.sh` CHAIN 배열의 `tests/test_mode3_e2e.mjs` 다음에:

```bash
  tests/test_mode3_wallet_agent.mjs
  tests/test_mode3_demo_stack.mjs
```

- [ ] **Step 3: chain 그룹 전체를 돌린다**

```bash
bash scripts/run_tests.sh chain
```

Expected: 10/10 PASS. 끝나고 `ss -ltn | grep -E ':(3100|5100|41[0-9]{2})\b'` 비어 있음, `pgrep -af 'cia.js|mode3_' | grep -v pgrep` 비어 있음.

- [ ] **Step 4: `docs/MODE3_DEMO.md`**

```markdown
# Mode 3 데모 — 기동과 시연

설계: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md`
UI 스펙: `docs/superpowers/specs/2026-09-10-mode3-demo-ui-design.md`

Mode 2 데모(:3000/:4000/:5001)와 **공존**한다. 포트·상태 파일이 다르고 코드를 공유하지 않는다.

## 프로세스와 포트

| 프로세스 | 포트 | 명령 | 상태 파일 |
|---|---|---|---|
| hardhat 노드 | :8545 | `npx hardhat node` | — |
| CIA | :4100 | `node cia.js` | `cia_state.json`, `cia_keys.json` |
| 지갑 에이전트 | :5100 | `node mode3_wallet_agent.js` | `mode3_wallet_state.json` |
| RP | :3100 | `node mode3_rp.js` | (메모리) |

## 처음 한 번: 배포와 `.env`

1. `npx hardhat node` (다른 터미널에 상주).
2. `CIA_ADMIN_SECRET=<아무 문자열> node cia.js` — 처음 기동에서 `cia_keys.json`을 만든다. `curl -s :4100/cia/public_keys`의 `ethAddress`를 적어 두고 종료한다.
3. `CIA_ETH_ADDRESS=<ethAddress> npx hardhat run scripts/deploy_mode3_log.cjs --network localhost` — `RevocationLog`를 배포하고 CIA 주소에 1 ETH를 넣는다. 출력의 `CIA_LOG_ADDRESS=0x…`를 `.env`에 추가한다.
4. `.env`에 `CIA_ADMIN_SECRET=<2의 값>`도 넣는다. (세 서버 모두 `dotenv`로 `.env`를 읽는다. `CIA_*`·`MODE3_*` 키는 이 데모만 쓴다.)

선택: 운영이라면 RP의 `pk_CIA`를 TOFU가 아니라 env로 박는다 — `curl -s :4100/cia/public_keys`의 `pk_CIA.x/y`를 `MODE3_PK_CIA_X`/`MODE3_PK_CIA_Y`에.

## 매번: 기동 순서

```
npx hardhat node                # 이미 떠 있으면 생략
node cia.js                     # :4100
node mode3_wallet_agent.js      # :5100
node mode3_rp.js                # :3100 (기동 시 CIA 에서 pk_CIA 를 받아 고정 — CIA 가 먼저 떠 있어야 한다)
```

페이지: 지갑 `http://127.0.0.1:5100/`, RP `http://127.0.0.1:3100/`, CIA 관리자 `http://127.0.0.1:4100/admin`.

## 시연 각본

| # | 어디서 | 조작 | 기대 |
|---|---|---|---|
| 1 | 지갑 | 등록 (`12345` / `password123`) | `등록됨` |
| 2 | RP | Mode 3 로그인 | `새 발급=true`, 로그인 성공, PPID |
| 3 | RP | 로그인 (다시) | `캐시 히트=true`, 증명 0 ms, 같은 PPID |
| 4 | 관리자 | 계정 폐기 → 게시 | `published:true`, epoch +1 |
| 5 | RP | "동기화 생략" 체크 → 로그인 | 거절 `stale_root` |
| 6 | RP | 체크 해제 → 로그인 | 지갑이 폐기를 감지해 재발급 시도 → `account_disabled` |
| 7 | 관리자 | 복구 | `disabled:false` |
| 8 | RP | 로그인 | `새 발급=true`, 성공, **PPID 가 2 와 같다** (설계 §6.6) |

같은 각본이 `tests/test_mode3_demo_stack.mjs`(HTTP)와 `tests/test_mode3_e2e.mjs`(라이브러리)로 고정돼 있다.

## 하지 말 것 / 재시연

- **`cia_state.json`을 지우지 않는다.** 체인의 `RevocationLog.root`와 어긋나 지갑의 `syncRevocationTree`가 root 불일치로 전원을 막는다(Mode 2의 `idp_state.json`과 같은 이유).
- 재시연은 **한 세트로만**: hardhat 노드 재시작 → 위 "처음 한 번" 2~3(재배포, `.env`의 `CIA_LOG_ADDRESS` 갱신) → `cia_state.json`·`mode3_wallet_state.json` 삭제 → 세 서버 재시작. `cia_keys.json`은 그대로 둬도 된다(같은 CIA 주소로 재배포하면 된다).
- 데모 계정은 `cia.js`의 `DEMO_ACCOUNTS`(`testuser`/`password123` → uid 12345, `alice`/`alicepw` → uid 67890). 지갑 에이전트는 한 계정만 등록한다.

## 테스트

- `bash scripts/run_tests.sh chain` — 격리 스택(임시 포트)으로 전 구간. :8545 만 있으면 된다.
```

- [ ] **Step 5: 실제 스택 스모크 (임시 상태 파일, 실제 포트)**

`.env`를 고치지 않고 env 로 넘긴다. 상태 파일은 스크래치 디렉터리에 두어 저장소 루트에 남기지 않는다. `:8545`가 떠 있어야 한다. `SCRATCH`는 세션 스크래치 디렉터리.

```bash
SCRATCH=<scratchpad>/mode3-smoke; mkdir -p "$SCRATCH"
# 1) CIA 를 로그 주소 없이 띄워 ethAddress 를 얻는다
CIA_ADMIN_SECRET=smoke CIA_STATE_FILE=$SCRATCH/cia_state.json CIA_KEYS_FILE=$SCRATCH/cia_keys.json node cia.js > $SCRATCH/cia.log 2>&1 &   # (백그라운드)
curl -s 127.0.0.1:4100/cia/public_keys   # ethAddress
# 2) 배포(+자금)
CIA_ETH_ADDRESS=<ethAddress> npx hardhat run scripts/deploy_mode3_log.cjs --network localhost
# 3) CIA 재시작(로그 주소 포함), 지갑, RP
kill %1; CIA_ADMIN_SECRET=smoke CIA_STATE_FILE=$SCRATCH/cia_state.json CIA_KEYS_FILE=$SCRATCH/cia_keys.json CIA_LOG_ADDRESS=<addr> node cia.js > $SCRATCH/cia.log 2>&1 &
MODE3_WALLET_STATE_FILE=$SCRATCH/mode3_wallet_state.json CIA_LOG_ADDRESS=<addr> node mode3_wallet_agent.js > $SCRATCH/wallet.log 2>&1 &
CIA_LOG_ADDRESS=<addr> node mode3_rp.js > $SCRATCH/rp.log 2>&1 &
```

브라우저(playwright)로 `http://127.0.0.1:5100/` 등록 → `http://127.0.0.1:3100/` 로그인 → `http://127.0.0.1:4100/admin` 폐기·게시 → RP 생략 체크 로그인(`stale_root`) → 해제 로그인(`account_disabled`) → 복구 → 로그인(PPID 동일). 각 단계 스크린샷 또는 페이지 텍스트로 확인한다.

끝나면 세 프로세스를 종료하고 `ss -ltn | grep -E ':(3100|4100|5100)\b'`가 비어 있는지, `$SCRATCH` 밖(저장소 루트)에 `cia_state.json`·`mode3_wallet_state.json`이 생기지 않았는지(`git status --short | grep -E 'cia_|mode3_wallet_state'` 비어 있음) 확인한다.

- [ ] **Step 6: 커밋 (사용자 승인 후)**

```bash
git add scripts/deploy_mode3_log.cjs docs/MODE3_DEMO.md .gitignore scripts/run_tests.sh
git commit -m "docs(mode3): 데모 기동·시연 문서, 배포 스크립트가 CIA 에 자금 공급, 데모 스택 테스트 CHAIN 등록"
```

---

## 완료 기준

- [ ] `bash scripts/run_tests.sh chain` 10/10 (기존 8 + `test_mode3_wallet_agent.mjs`, `test_mode3_demo_stack.mjs`)
- [ ] `bash scripts/run_tests.sh unit` 8/8 (변화 없음)
- [ ] 실제 스택(:4100/:5100/:3100) 브라우저 스모크 8단계 통과, 8단계 PPID = 2단계 PPID
- [ ] Mode 2 파일 무변경: `git diff --stat c9d44a1..HEAD -- server.js client.js index.html wallet_agent.js custom_idp.js lib/imt_v3.js contracts circuits` 비어 있음. `lib/mode3_*.js`도 무변경
- [ ] 개발용 포트(3000/4000/5001)와 :8545 프로세스 그대로, 임시 프로세스·디렉터리 잔존 없음
- [ ] `mode3_wallet_state.json`이 `.gitignore`에 있고 저장소 루트에 상태 파일이 커밋되지 않음
- [ ] `/wallet/login` 응답에 `uid` 없음(테스트로 고정), CORS 헤더는 RP 오리진에만(테스트로 고정)

## 다음 (이 계획 밖)

- 브라우저 내 증명(설계 §8.3 브라우저 T 실측)
- Poseidon 전환(설계 §12 보류) — 그때 `pk_i` 인코딩·세션 서명 스킴 재검토(설계 §11)
