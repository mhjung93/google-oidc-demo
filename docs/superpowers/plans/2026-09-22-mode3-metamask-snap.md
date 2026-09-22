# Mode 3 MetaMask/Snap 구색 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 등록 비밀을 MetaMask Snap 에 두고, 지갑 페이지(:5100)가 유일한 dapp 으로 Snap 동의 창·MetaMask 트랜잭션 전송·RP 팝업 로그인을 맡게 한다. 자동 테스트와 헤드리스 데모는 `file` 모드로 지금 동작을 유지한다.

**Architecture:** (1) 에이전트에 `SecretSource` 를 두어 비밀 공급원을 `file`(상태 파일, 기존) / `snap`(요청에 첨부된 증인, 세션 동안 메모리) 로 나눈다. (2) 새 Snap 패키지 `snap-mode3/` 가 등록 비밀을 `snap_manageState` 에 보관하고 RPC 8개(등록 입력, 로그인 동의→증인, 공개 동의, 자기 폐기 입력 등)를 낸다. (3) 지갑 페이지가 MetaMask 연결·Snap 호출·`/authorize` 팝업(`postMessage` 핸드셰이크로 RP 오리진 검증)·`eth_sendTransaction` 을 맡고, RP 페이지는 로그인만 팝업으로 열며 재검증·세션 요청은 지금처럼 CORS 로 부른다. (4) 회로·컨트랙트·CIA·RP 서버는 바뀌지 않는다.

**Tech Stack:** Node 22 ESM, express, ethers v6, circomlibjs, `@metamask/snaps-cli` + `@metamask/snaps-sdk`(Mode 2 `snap/` 과 같은 방식), MetaMask Flask(수동 데모), Playwright(브라우저 테스트 — 설치는 사용자 승인 필요, §Task 5).

**Spec:** `docs/superpowers/specs/2026-09-22-mode3-metamask-snap-design.md` (이하 "스펙").

## Global Constraints

- 비밀 공급원 환경변수 `MODE3_WALLET_SECRETS` = `snap` | `file`(기본 `file`). `file` 모드의 동작·응답·상태 파일 형식은 지금과 같아야 하고 기존 chain·데모 스택 테스트가 그대로 통과한다.
- `snap` 모드에서 에이전트 상태 파일에는 **s_u, r_u, sk_u, blind_u 가 절대 쓰이지 않는다**. 파일의 `registration` 은 `{ uid, cm_u, attrs, userCred: { Cf_u, leaf, issuedAt } }` 공개 부분만. 세션의 `witness` 는 메모리에만(`persist()` 가 제외).
- 증인 형식(스펙 §3.1 `consentLogin` 응답 = `/wallet/login` 본문 `witness`): `{ uid, s_u, r_u, sk_u, attrs:[4], userCred: { C_u_pt:{x,y}, Cf_u, blind_u, leaf, issuedAt } | null }` — 모두 10진 문자열(sk_u 는 hex). 에이전트는 `witness.uid` 가 파일의 공개 `uid` 와 다르면 `400 bad_witness`.
- Snap RPC 8개 이름·인자·반환은 스펙 §3.1 표 그대로: `register`, `storeRegistration`, `getPublicInfo`, `consentLogin`, `consentDisclosure`, `updateUserCred`, `syncAttrs`, `selfRevoke`, `reset`(9개 — `reset` 포함). 호출 오리진이 `WALLET_ORIGIN` 이 아니면 거절. 비밀번호는 저장하지 않는다.
- 팝업 프로토콜(스펙 §3.2·§4.2): 팝업 → opener `{ type:'mode3-authorize-ready' }`; RP → 팝업 `{ type:'mode3-authorize', arid, origin, cert_s, pk_trace, r_s, allowAgent, factoryAddress, attrGateAddress, serviceName, reauth? }`; 팝업은 `event.origin === request.origin` 일 때만 진행; 결과 `{ type:'mode3-authorize-result', r_s, result }` 를 `request.origin` 으로만 보낸다. RP 페이지는 `event.origin === walletAgentOrigin` 검사.
- `snap` 모드 `/wallet/login` 은 같은 오리진만(CORS 없음), 본문 `verifiedOrigin` 을 인증서 오리진과 대조. `/wallet/revalidate`·`/wallet/request` 는 두 모드 모두 RP 오리진 CORS 유지.
- 트랜잭션: `snap` 모드는 `POST /wallet/tx/prepare` → 페이지가 `eth_sendTransaction` → `POST /wallet/tx/record`. `file` 모드의 `POST /wallet/tx`(릴레이어)는 그대로.
- Snap 패키지 `snap-mode3/`, 개발 서버 포트 **8082**, Snap ID 기본 `local:http://localhost:8082`(에이전트 `MODE3_SNAP_ID`). Mode 2 `snap/` 은 건드리지 않는다.
- 새 의존성(`@metamask/snaps-sdk`, `@metamask/snaps-cli` 는 `snap-mode3/package.json` 안에서만; Playwright 는 루트 devDependency) 추가는 사용자 승인 후. 승인 전에는 브라우저 테스트를 `docs/MODE3_DEMO.md` 의 수동 체크리스트로 대체한다.
- 모든 주석·커밋 메시지·문서 한글. 커밋 트레일러: `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`, `Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN`.
- 상태·키 파일(`mode3_wallet_state.json`, `cia_state.json`, `*_keys.json`, `.env`)은 읽거나 지우지 않는다. 회로 빌드 없음. `npm run zk:*` 금지. 테스트용 hardhat 은 세션이 띄운다.

---

## 파일 구조

| 파일 | 책임 | Task |
|---|---|---|
| `lib/mode3_secret_source.js` | `createSecretSource({ mode, state, witness })` — `file`/`snap` 두 구현, `stripSecrets(state)` | 1 |
| `mode3_wallet_agent.js` | 모드 분기, `witness`·`verifiedOrigin`, 세션 메모리 증인, 새 엔드포인트(`/wallet/config`, `/wallet/authorize/precheck`, `/wallet/session/witness`, `/wallet/tx/prepare`, `/wallet/tx/record`) | 1, 2 |
| `tests/helpers/snap_sim.mjs` | Snap 시뮬레이터(상태·RPC 를 Node 함수로) | 2 |
| `tests/test_mode3_wallet_snap.mjs` | `snap` 모드 에이전트 테스트 | 2 |
| `snap-mode3/{package.json, snap.config.js, snap.manifest.json, src/index.js, src/crypto.js}` | Snap | 3 |
| `snap-mode3/test/rpc.test.mjs` | `onRpcRequest` 단위 테스트(`snap.request` 스텁) | 3 |
| `mode3/wallet.html` | MetaMask 연결, Snap 경로 등록·트랜잭션, `/authorize` 팝업 화면 | 4 |
| `mode3/rp.html` | 팝업 열기·핸드셰이크·`needs_consent` 재팝업 | 5 |
| `tests/test_mode3_browser.mjs` (Playwright 승인 시) | 브라우저 경로 | 5 |
| `docs/MODE3_DEMO.md`, `scripts/run_tests.sh` | Snap 절·Flask 체크리스트, 테스트 그룹 등록 | 6 |

---

### Task 1: `SecretSource` 추상화와 `file` 모드 리팩터 (동작 불변)

**Files:**
- Create: `lib/mode3_secret_source.js`
- Modify: `mode3_wallet_agent.js` (상태 접근을 `SecretSource` 로, `MODE3_WALLET_SECRETS` 읽기, `/wallet/config`)
- Test: `tests/test_mode3_secret_source.js` (새 unit 파일 — `scripts/run_tests.sh` UNIT 그룹에 추가), 기존 `tests/test_mode3_wallet_agent.mjs`

**Interfaces:**
- Produces:
  ```js
  // lib/mode3_secret_source.js
  export function createSecretSource({ mode, state, witness = null })
  // 반환 객체:
  //   mode: 'file' | 'snap'
  //   registration()  → { uid, s_u, r_u, sk_u, attrs, cm_u } | null      (비밀 포함; snap 은 witness 에서)
  //   userCred()      → { C_u_pt, Cf_u, blind_u, leaf, issuedAt } | null (snap 은 witness.userCred)
  //   setUserCred(uc) → file: state.registration.userCred = uc; snap: pending.userCredIssued = uc
  //   setAttrs(attrs) → file: state.registration.attrs = attrs; snap: pending.attrsChanged = attrs
  //   pending         → { userCredIssued?, attrsChanged? }   (snap 모드에서 응답에 실어 페이지가 Snap 에 저장)
  export function stripSecrets(registration)   // { uid, cm_u, attrs, userCred: { Cf_u, leaf, issuedAt } | null } — snap 모드가 파일에 쓰는 형태
  export function validateWitness(witness, publicUid) // 형식·범위 검사, uid 불일치 → throw Object.assign(new Error('bad_witness'), { reason:'bad_witness' })
  ```
  - `GET /wallet/config` → `{ secrets: 'file'|'snap', snapId, walletOrigin, rpcUrl, chainId }`.

- [ ] **Step 1: 실패하는 unit 테스트**

`tests/test_mode3_secret_source.js`:

```js
// SecretSource — 스펙 2026-09-22 metamask-snap §3.3. 외부 의존 없음.   node tests/test_mode3_secret_source.js
import assert from 'node:assert/strict';
import { createSecretSource, stripSecrets, validateWitness } from '../lib/mode3_secret_source.js';

let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

const REG = { uid: '12345', s_u: '11', r_u: '22', sk_u: 'ab'.repeat(32), attrs: ['1990', '410', '2', '0'], cm_u: { x: '1', y: '2' },
  userCred: { C_u_pt: { x: '3', y: '4' }, Cf_u: '5', blind_u: '33', leaf: '6', issuedAt: 'now' } };

await t('file 모드: registration()/userCred() 는 상태 파일 값 그대로, setUserCred/setAttrs 는 상태를 바꾼다', () => {
  const state = { registration: structuredClone(REG) };
  const src = createSecretSource({ mode: 'file', state });
  assert.equal(src.mode, 'file');
  assert.equal(src.registration().s_u, '11'); assert.equal(src.userCred().blind_u, '33');
  src.setUserCred(null); assert.equal(state.registration.userCred, null);
  src.setAttrs(['1', '2', '3', '4']); assert.deepEqual(state.registration.attrs, ['1', '2', '3', '4']);
  assert.deepEqual(src.pending, {});
});

await t('snap 모드: 비밀은 witness 에서만 오고 상태는 바꾸지 않으며 pending 에 쌓인다', () => {
  const state = { registration: stripSecrets(REG) };
  const witness = { uid: '12345', s_u: '11', r_u: '22', sk_u: 'ab'.repeat(32), attrs: REG.attrs, userCred: REG.userCred };
  const src = createSecretSource({ mode: 'snap', state, witness });
  assert.equal(src.registration().s_u, '11'); assert.equal(src.registration().cm_u.x, '1', 'cm_u 는 파일의 공개값');
  const uc = { C_u_pt: { x: '7', y: '8' }, Cf_u: '9', blind_u: '44', leaf: '10', issuedAt: 'later' };
  src.setUserCred(uc);
  assert.deepEqual(src.pending.userCredIssued, uc);
  assert.deepEqual(state.registration.userCred, { Cf_u: '9', leaf: '10', issuedAt: 'later' }, '파일에는 공개 부분만');
  assert.equal(JSON.stringify(state).includes('"blind_u"'), false);
  src.setAttrs(['1', '2', '3', '4']); assert.deepEqual(src.pending.attrsChanged, ['1', '2', '3', '4']); assert.deepEqual(state.registration.attrs, ['1', '2', '3', '4']);
});

await t('stripSecrets 는 s_u·r_u·sk_u·blind_u 를 지운다', () => {
  const s = stripSecrets(REG);
  assert.deepEqual(Object.keys(s).sort(), ['attrs', 'cm_u', 'uid', 'userCred']);
  assert.deepEqual(s.userCred, { Cf_u: '5', leaf: '6', issuedAt: 'now' });
  assert.equal(stripSecrets({ ...REG, userCred: null }).userCred, null);
});

await t('validateWitness: uid 불일치·형식·범위 오류는 bad_witness', () => {
  const w = { uid: '12345', s_u: '11', r_u: '22', sk_u: 'ab'.repeat(32), attrs: ['1', '2', '3', '4'], userCred: null };
  validateWitness(w, '12345');
  for (const bad of [{ ...w, uid: '1' }, { ...w, s_u: 'x' }, { ...w, s_u: (1n << 250n).toString() }, { ...w, sk_u: 'zz' }, { ...w, attrs: ['1'] }, { ...w, attrs: [(1n << 64n).toString(), '0', '0', '0'] }, null]) {
    assert.throws(() => validateWitness(bad, '12345'), (e) => e.reason === 'bad_witness', JSON.stringify(bad));
  }
});
process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_secret_source.js` → 모듈 없음으로 실패.

- [ ] **Step 3: 구현 `lib/mode3_secret_source.js`**

```js
// 지갑 에이전트의 비밀 공급원 — 스펙 2026-09-22 metamask-snap §3.3.
//   file: 지금처럼 상태 파일의 registration 이 비밀을 든다(자동 테스트·헤드리스 데모).
//   snap: 비밀은 요청에 첨부된 witness(Snap 이 동의 창 뒤에 내준 것)에서만 오고, 파일에는 공개 부분만 남는다. 에이전트는 Snap 을
//         부를 수 없으므로 새 C_u·attrs 는 pending 에 모아 응답에 실어 페이지가 Snap 에 저장하게 한다.
import { SCALAR_MAX, ATTR_MAX, normalizeAttrs } from './mode3_credential.js';

const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const isHex64 = (v) => typeof v === 'string' && /^[0-9a-fA-F]{64}$/.test(v);
const isPt = (p) => p && isDec(p.x) && isDec(p.y);

export function stripSecrets(registration) {
  if (!registration) return null;
  const { uid, cm_u, attrs, userCred } = registration;
  return { uid, cm_u, attrs, userCred: userCred ? { Cf_u: userCred.Cf_u, leaf: userCred.leaf, issuedAt: userCred.issuedAt } : null };
}

export function validateWitness(w, publicUid) {
  const fail = (msg) => { throw Object.assign(new Error(`bad_witness: ${msg}`), { reason: 'bad_witness' }); };
  if (!w || typeof w !== 'object') fail('witness 없음');
  if (!isDec(w.uid) || w.uid !== publicUid) fail('uid 가 등록과 다르다');
  for (const k of ['s_u', 'r_u']) if (!isDec(w[k]) || BigInt(w[k]) >= SCALAR_MAX) fail(`${k} 범위`);
  if (!isHex64(w.sk_u)) fail('sk_u 형식');
  try { normalizeAttrs(w.attrs); } catch (e) { fail(`attrs: ${e.message}`); }
  if (!Array.isArray(w.attrs) || w.attrs.length !== 4) fail('attrs 길이');
  if (w.userCred !== null && w.userCred !== undefined) {
    const u = w.userCred;
    if (!isPt(u.C_u_pt) || !isDec(u.Cf_u) || !isDec(u.blind_u) || BigInt(u.blind_u) >= SCALAR_MAX || !isDec(u.leaf)) fail('userCred 형식');
  }
  void ATTR_MAX;
}

export function createSecretSource({ mode, state, witness = null }) {
  if (mode === 'file') {
    return {
      mode, pending: {},
      registration: () => state.registration ? { uid: state.registration.uid, s_u: state.registration.s_u, r_u: state.registration.r_u, sk_u: state.registration.sk_u, attrs: state.registration.attrs, cm_u: state.registration.cm_u } : null,
      userCred: () => state.registration?.userCred ?? null,
      setUserCred: (uc) => { state.registration.userCred = uc; },
      setAttrs: (attrs) => { state.registration.attrs = attrs; },
    };
  }
  if (mode !== 'snap') throw new Error(`unknown secret source mode: ${mode}`);
  const pending = {};
  return {
    mode, pending,
    registration: () => (state.registration && witness) ? { uid: state.registration.uid, s_u: witness.s_u, r_u: witness.r_u, sk_u: witness.sk_u, attrs: witness.attrs, cm_u: state.registration.cm_u } : null,
    userCred: () => witness?.userCred ?? null,
    setUserCred: (uc) => { pending.userCredIssued = uc; if (witness) witness.userCred = uc; state.registration.userCred = uc ? { Cf_u: uc.Cf_u, leaf: uc.leaf, issuedAt: uc.issuedAt } : null; },
    setAttrs: (attrs) => { pending.attrsChanged = attrs; if (witness) witness.attrs = attrs; state.registration.attrs = attrs; },
  };
}
```

- [ ] **Step 4: 에이전트 리팩터(동작 불변)**

`mode3_wallet_agent.js`:
- 상단: `const SECRETS = process.env.MODE3_WALLET_SECRETS || 'file'; if (!['file','snap'].includes(SECRETS)) throw …; const SNAP_ID = process.env.MODE3_SNAP_ID || 'local:http://localhost:8082';`
- `reg.s_u`·`reg.r_u`·`reg.sk_u`·`reg.attrs`·`reg.userCred` 를 직접 읽던 곳(`ensureUserCred`, `syncAttrsFromCia`, `issueSession`, `proveSession`, `replaceUserCred`, `/wallet/status`, `/wallet/attrs/sync`)을 **요청마다 만든 `src = createSecretSource({ mode: SECRETS, state, witness })`** 로 읽도록 바꾼다. 이 Task 에서는 `witness` 가 항상 `null`(file) 이라 동작이 같다. `replaceUserCred(uc)` 는 `src.setUserCred(uc)` + 세션 비움 + 캐시 clear 로.
- 세션 레코드에 증인이 필요한 함수(`proveSession`)는 `src` 를 인자로 받는다: `proveSession(rsKey, synced, timings, disclosure, src)`.
- `GET /wallet/config` 추가.

- [ ] **Step 5: 통과 확인** — `node tests/test_mode3_secret_source.js`, `bash scripts/run_tests.sh unit`(UNIT 목록에 새 파일 추가), 그리고 hardhat 위에서 `node tests/test_mode3_wallet_agent.mjs && node tests/test_mode3_demo_stack.mjs`(동작 불변 확인).

- [ ] **Step 6: 커밋** — `feat(mode3): Snap 1/6 — SecretSource 추상화(file 모드 동작 불변), /wallet/config`

---

### Task 2: 에이전트 `snap` 모드 + Snap 시뮬레이터 테스트

**Files:**
- Modify: `mode3_wallet_agent.js`
- Create: `tests/helpers/snap_sim.mjs`, `tests/test_mode3_wallet_snap.mjs`
- Modify: `scripts/run_tests.sh` (CHAIN 그룹에 `tests/test_mode3_wallet_snap.mjs`)

**Interfaces:**
- Consumes: Task 1 `createSecretSource`, `stripSecrets`, `validateWitness`.
- Produces(에이전트, `snap` 모드):
  - `POST /wallet/register { uid, pwd, cm_u:{x,y} }` → 201 `{ uid, sk_u, attrs }` (파일에는 `stripSecrets` 결과만). `cm_u` 형식 오류 400.
  - `POST /wallet/authorize/precheck { arid, origin, cert_s, pk_trace, factoryAddress }` → `{ ok:true }` | 403 `{ reason:'bad_rp_cert' }` | 409 `{ reason:'bad_factory' }`.
  - `POST /wallet/login { …기존 필드, witness, verifiedOrigin }` (같은 오리진만): `witness` 없으면 400 `witness_required`; `validateWitness` 실패 400 `bad_witness`; `verifiedOrigin !== origin` 이면 403 `bad_rp_cert`. 응답 = 기존 + `userCredIssued?`, `attrsChanged?`. 성공 시 `sessions[r_s].witness = { s_u, blind_u: userCred.blind_u, attrs, sk_u }` (메모리만).
  - `POST /wallet/session/witness { r_s, witness }` → `{ ok }` (재시작 뒤 재승인).
  - `/wallet/revalidate`·`/wallet/request`·`/wallet/tx/prepare`: 세션에 `witness` 가 없으면 409 `{ reason:'needs_consent' }` (`request` 는 세션키 서명만 하므로 증인 불필요 — `needs_consent` 대상 아님).
  - `POST /wallet/tx/prepare { r_s, to, value?, data?, disclose? }` → `{ walletAddr, factoryAddress, deployNeeded, deployCalldata|null, calldata, nonce, disclosure, timings }`. `calldata` = `walletInterface.encodeFunctionData('execute', [payload, sig, a, b, c, pub])`, `deployCalldata` = 팩토리 `deploy(PPID)` 인코딩(코드가 없을 때만).
  - `POST /wallet/tx/record { r_s, txHash }` → 기존 `/wallet/tx` 응답 형식(`ok`, `gasUsed`, `executed`, `disclosure`, `onchainDisclosure`, `txHash`, `wallet`). 영수증이 아직 없으면 202 `{ pending:true }`.
  - `persist()` 는 세션의 `witness` 를 제외하고 쓴다(`JSON.stringify` replacer).
- Produces(시뮬레이터 `tests/helpers/snap_sim.mjs`):
  ```js
  export function createSnapSim()                       // 상태 { registration:null, userCred:null, consents:{} }
  sim.register({ uid, pwd })  → { uid, pwd, cm_u }       // s_u·r_u 생성(createRegistration 재사용)
  sim.storeRegistration({ sk_u, attrs })
  sim.consentLogin({ origin, arid, allowAgent }, decision='allow') → witness | { denied:true }
  sim.consentDisclosure(args, decision='allow') → { ok } | { denied:true }
  sim.updateUserCred(uc); sim.syncAttrs({ attrs }); sim.getPublicInfo(); sim.selfRevoke({ pwd }); sim.reset()
  sim.state  // 검사용
  ```
  Task 3 의 Snap `src/index.js` 는 이 시뮬레이터와 같은 입출력을 구현한다(스펙 §3.1 표가 정본).

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_wallet_snap.mjs`(격리 스택을 `MODE3_WALLET_SECRETS=snap` 으로 띄움; `isolated_mode3_stack.mjs` 의 `spawnServer` env 로 전달 — 헬퍼에 `walletEnv` 옵션 추가):

```js
// snap 모드 지갑 에이전트 — 스펙 2026-09-22 metamask-snap §3.3·§7. hardhat :8545 필요.
await t('register: 응답에 sk_u·attrs, 상태 파일에는 비밀 없음', async () => {
  const r0 = sim.register({ uid: '12345', pwd: 'password123' });
  const r = await wallet.post('/wallet/register', { uid: r0.uid, pwd: r0.pwd, cm_u: r0.cm_u });
  assert.equal(r.status, 201); assert.match(r.body.sk_u, /^[0-9a-f]{64}$/); assert.deepEqual(r.body.attrs, ['1990', '410', '2', '0']);
  sim.storeRegistration({ sk_u: r.body.sk_u, attrs: r.body.attrs });
  const file = fs.readFileSync(stack.walletStateFile, 'utf8');
  for (const k of ['"s_u"', '"r_u"', '"sk_u"', '"blind_u"']) assert.equal(file.includes(k), false, `${k} 가 파일에 있다`);
});
await t('login: witness 없으면 400 witness_required; uid 다르면 400 bad_witness; verifiedOrigin 불일치 403; 정상은 세션·userCredIssued', async () => {
  const info = (await rp.get('/api/mode3/rp_info')).body; const ch = (await rp.post('/api/mode3/challenge')).body;
  const base = { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, allowAgent: '0', factoryAddress: ch.factoryAddress, attrGateAddress: ch.attrGateAddress, verifiedOrigin: info.origin };
  assert.equal((await wallet.post('/wallet/login', base)).body.reason, 'witness_required');
  const w = sim.consentLogin({ origin: info.origin, arid: info.arid, allowAgent: '0' });
  assert.equal((await wallet.post('/wallet/login', { ...base, witness: { ...w, uid: '1' } })).body.reason, 'bad_witness');
  assert.equal((await wallet.post('/wallet/login', { ...base, witness: w, verifiedOrigin: 'http://evil:1' })).status, 403);
  const ok = await wallet.post('/wallet/login', { ...base, witness: w });
  assert.equal(ok.status, 200, JSON.stringify(ok.body)); assert.ok(ok.body.userCredIssued, '첫 로그인은 새 C_u');
  sim.updateUserCred(ok.body.userCredIssued);
  const v = await verify(ok.body, BigInt(ch.r_s)); assert.equal(v.ok, true);
  assert.equal(fs.readFileSync(stack.walletStateFile, 'utf8').includes('"blind_u"'), false);
});
await t('revalidate 는 메모리 witness 로 되고, 에이전트를 재시작하면 needs_consent → /wallet/session/witness 로 복구', async () => { /* 로그인 → revalidate 200 → stack.restartWallet() → revalidate 409 needs_consent → session/witness → revalidate 200 */ });
await t('tx/prepare + hardhat 계정이 EOA 로 전송 + tx/record 가 영수증을 파싱한다 (mask 3 → AttrGate claim)', async () => { /* prepare → deployCalldata 있으면 signer.sendTransaction({to:factory,data}) → sendTransaction({to:walletAddr,data:calldata}) → record → executed.success, onchainDisclosure.mask '3' */ });
await t('file 모드 전용 /wallet/tx 는 snap 모드에서 409 use_tx_prepare', async () => { … });
await t('consent 거절: 시뮬레이터가 denied 를 주면 페이지가 로그인하지 않는다(시뮬레이터 수준 검증)', async () => { … });
```

(각 케이스의 본문은 위 인터페이스대로 채운다. `stack.restartWallet()` 은 격리 스택 헬퍼에 추가 — 지갑 자식만 죽이고 같은 상태 파일로 다시 띄운다.)

- [ ] **Step 2: 실패 확인** — 헬퍼 옵션·엔드포인트 없음으로 실패.

- [ ] **Step 3: 구현** — 위 인터페이스대로. 핵심 코드:

```js
// persist: 세션의 witness 는 메모리에만(스펙 §3.3)
function persist() { writeJsonAtomic(STATE_FILE, JSON.parse(JSON.stringify(state, (k, v) => (k === 'witness' ? undefined : v))), 0o600); }

function secretSourceFor(req, rsKey = null) {
  if (SECRETS === 'file') return createSecretSource({ mode: 'file', state });
  const w = req.body?.witness ?? (rsKey ? state.sessions[rsKey]?.witness : null);
  if (!w) throw Object.assign(new Error('needs_consent'), { reason: rsKey ? 'needs_consent' : 'witness_required' });
  return createSecretSource({ mode: 'snap', state, witness: w });
}
```

`/wallet/login`(snap): `validateWitness(req.body.witness, state.registration.uid)` → `src` → 기존 흐름(`ensureUserCred(tree, src)`, `issueSession(…, src)`, `proveSession(…, src)`) → 성공 시 `state.sessions[rsKey].witness = { s_u, blind_u, attrs, sk_u }`(userCred 가 새로 발급됐으면 그 blind_u) → 응답에 `...src.pending`. 오리진 검사: `SECRETS === 'snap' ? req.body.verifiedOrigin === origin : req.get('Origin') === origin`. `loginCors` 는 `file` 모드에서만 `app.options`/핸들러에 붙인다. `/wallet/tx/prepare` 는 기존 `/wallet/tx` 의 "증명·서명·calldata 준비" 부분을 떼어 낸 것 — `execute` 전송 대신 `walletInterface.encodeFunctionData` 로 돌려준다(`lib/mode3_onchain.js` 의 `walletInterface` 이미 export). `/wallet/tx/record` 는 `provider.getTransactionReceipt(txHash)` → `parseExecuteReceipt`.

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_wallet_snap.mjs`, 그리고 회귀 `node tests/test_mode3_wallet_agent.mjs && node tests/test_mode3_demo_stack.mjs`(file 모드).
- [ ] **Step 5: 커밋** — `feat(mode3): Snap 2/6 — 에이전트 snap 모드(증인 첨부 로그인·세션 메모리 증인·needs_consent·tx/prepare·tx/record), Snap 시뮬레이터 테스트`

---

### Task 3: Snap 패키지 `snap-mode3/`

**Files:**
- Create: `snap-mode3/package.json`, `snap-mode3/snap.config.js`, `snap-mode3/snap.manifest.json`, `snap-mode3/src/index.js`, `snap-mode3/src/crypto.js`, `snap-mode3/test/rpc.test.mjs`, `snap-mode3/README.md`
- (의존성 추가는 사용자 승인 뒤: `@metamask/snaps-sdk`, `@metamask/snaps-cli`, `circomlibjs`)

**Interfaces:**
- Consumes: 스펙 §3.1 RPC 표(정본), Task 2 시뮬레이터와 같은 입출력.
- Produces: `onRpcRequest({ origin, request })` — Mode 2 `snap/src/index.js` 와 같은 구조. `src/crypto.js`: `createRegistrationSecrets()` → `{ s_u, r_u, cm_u }`(lib/mode3_issuance.js 의 `registrationCommit` 과 같은 계산 — 라이브러리를 그대로 import 하지 말고 필요한 두 함수를 Snap 번들에 맞게 복사하되 동일 결과를 테스트로 고정).

- [ ] **Step 1: 실패하는 테스트** — `snap-mode3/test/rpc.test.mjs`: 전역 `snap.request` 스텁(`snap_manageState` 는 메모리 맵, `snap_dialog` 는 시나리오별 응답 큐)으로 `onRpcRequest` 를 부른다. 케이스: (a) 다른 origin 은 거절, (b) `register` 가 prompt 두 번 뒤 `{ uid, pwd, cm_u }` 를 주고 상태에 s_u·r_u 저장·pwd 미저장, (c) `storeRegistration`, (d) `getPublicInfo` 에 비밀 없음, (e) `consentLogin` 승인 → 증인(형식은 Task 1 `validateWitness` 로 검증), 거절 → `{ denied:true }`, (f) `consentDisclosure` 대화상자 내용에 슬롯·구간·대상이 들어감, (g) `updateUserCred`/`syncAttrs`/`selfRevoke`/`reset`. `cm_u` 가 `registrationCommit(s_u, r_u)`(루트 lib) 와 같은 점인지 대조.
- [ ] **Step 2: 실패 확인**.
- [ ] **Step 3: 구현** — manifest 권한 `endowment:rpc { dapps:true }`, `snap_dialog`, `snap_manageState`; `snap.config.js` 포트 8082; `src/index.js` 는 `switch (request.method)` 로 9개; 상태 버전 1; 대화상자 문구는 한글(스펙 §3.1). SES 아래 circomlibjs 동작 여부를 먼저 `mm-snap build` 로 확인(열린 항목 c) — 실패하면 `crypto.js` 에서 s_u·r_u 만 만들고 `cm_u` 계산은 페이지가 하도록 스펙 §9(c) 대안으로 전환하고 리포트에 기록.
- [ ] **Step 4: 통과 확인** — `node snap-mode3/test/rpc.test.mjs`, `cd snap-mode3 && npm run build`.
- [ ] **Step 5: 커밋** — `feat(mode3): Snap 3/6 — snap-mode3 패키지(등록 비밀 보관, 동의 창 RPC 9개, 단위 테스트)`

---

### Task 4: 지갑 페이지 — MetaMask 연결, Snap 경로, `/authorize` 팝업

**Files:**
- Modify: `mode3/wallet.html`, `mode3_wallet_agent.js`(`GET /?authorize=1` 도 같은 파일; `/wallet/config` 는 Task 1)

**Interfaces:**
- Consumes: Task 2 엔드포인트, Task 3 RPC, 스펙 §3.2·§4.
- Produces: 페이지 함수 `connectMetaMask()`, `invokeSnap(method, params)`, `runAuthorize()`(핸드셰이크·precheck·consentLogin·login·postMessage), `sendTxViaMetaMask()`(prepare → deploy? → execute → record).

- [ ] **Step 1: 구현** — `/wallet/config` 의 `secrets` 가 `snap` 이면 Snap 경로 UI 를, `file` 이면 지금 UI 를 보인다. 팝업 모드(`location.search` 에 `authorize=1`)에서는 폼 대신 "서비스 X 로그인 승인 중…" 화면. 핸드셰이크·오리진 검사·결과 전송은 Global Constraints 의 프로토콜 그대로. `eth_sendTransaction` 은 `{ from: account, to, data }` 만(가스는 MetaMask 추정).
- [ ] **Step 2: 검증** — 브라우저 없이: `node --check` 로 인라인 스크립트 문법, 그리고 Playwright 가 있으면 Task 5 에서. 없으면 수동 체크리스트(Task 6).
- [ ] **Step 3: 커밋** — `feat(mode3): Snap 4/6 — 지갑 페이지 MetaMask 연결·Snap 경로·/authorize 팝업`

---

### Task 5: RP 페이지 팝업 로그인 + 브라우저 테스트

**Files:**
- Modify: `mode3/rp.html`
- Create (Playwright 승인 시): `tests/test_mode3_browser.mjs`, `tests/helpers/ethereum_stub.js`(페이지에 주입할 `window.ethereum` 스텁)
- Modify: `scripts/run_tests.sh`(승인 시 CHAIN 그룹 추가), `package.json` devDependencies(승인 시)

**Interfaces:**
- Consumes: Task 4 팝업 프로토콜, `rp_info.walletAgentOrigin`.
- Produces: RP 페이지 `loginViaPopup()`: 팝업 열기 → `ready` 대기 → 요청 전송 → 결과 → `/api/mode3/login`. `needs_consent`(재검증 409) 시 같은 팝업에 `reauth:true`.

- [ ] **Step 1: 구현(rp.html)** — `window.open(`${info.walletAgentOrigin}/?authorize=1`, 'mode3-authorize', 'width=480,height=640')`; `message` 리스너에서 `event.origin === info.walletAgentOrigin` 과 `event.data.r_s === r_s` 검사; 팝업 `null` 이면 "팝업 차단" 안내; `file` 모드(`/wallet/config.secrets === 'file'` 을 `rp_info` 경유로 알 수 없으므로 RP 페이지는 먼저 `${walletAgentOrigin}/wallet/config` 를 CORS 로 읽는다 — `/wallet/config` 에 RP 오리진 CORS 허용)이면 지금처럼 직접 호출.
- [ ] **Step 2: 브라우저 테스트(승인 시)** — Playwright chromium 으로 지갑·RP 페이지를 열고 `addInitScript` 로 `window.ethereum` 스텁 주입(`eth_requestAccounts` → hardhat 계정 0, `wallet_requestSnaps` → ok, `wallet_invokeSnap` → Task 2 시뮬레이터를 페이지 안에서 흉내(스텁이 시뮬레이터 로직을 번들), `eth_sendTransaction` → 스텁이 `fetch` 로 테스트 하네스의 `/__send` 에 넘겨 hardhat 계정이 실제 전송). 시나리오: 연결 → 등록 → RP 로그인(팝업 자동 처리) → 공개 트랜잭션 → `AttrGate.claim` 성공 → 재검증 → `needs_consent` 재팝업.
- [ ] **Step 3: 커밋** — `feat(mode3): Snap 5/6 — RP 페이지 팝업 로그인·needs_consent 재승인(+브라우저 테스트)`

---

### Task 6: 문서·테스트 그룹·슬라이드 메모

**Files:**
- Modify: `docs/MODE3_DEMO.md`(Snap 절: Flask 설치, `snap-mode3` 빌드·serve, 연결·등록·로그인·공개 트랜잭션 체크리스트, `MODE3_WALLET_SECRETS`, EOA 노출 한계), `scripts/run_tests.sh`(새 파일 등록 확인), 스펙 §9 결정 기록.

- [ ] **Step 1: 문서** · **Step 2: 전 그룹 실행**(`contract`, `npm test`, `chain`) · **Step 3: 커밋** — `docs(mode3): Snap 6/6 — 데모 절차·Flask 체크리스트·테스트 그룹`

---

## 자체 점검
- 스펙 커버리지: §3.1 Snap → T3; §3.2 페이지 → T4; §3.3 에이전트(SecretSource, 세션 증인, 엔드포인트, CORS) → T1·T2; §3.4 RP → T5; §4 흐름 → T2(에이전트)·T4·T5(브라우저); §5 오류 → T2(400/403/409 코드)·T4·T5(UI 문구); §6 보안 메모 → T6 문서; §7 테스트 3층 → T2(시뮬레이터)·T5(Playwright)·T6(체크리스트); §8 순서 일치.
- 타입 일관성: 증인 객체 키(`uid, s_u, r_u, sk_u, attrs, userCred`)와 `userCred` 키(`C_u_pt, Cf_u, blind_u, leaf, issuedAt`)가 T1 검증기·T2 응답·T3 Snap 상태·시뮬레이터에서 같다. `pending` 키(`userCredIssued`, `attrsChanged`)가 T1·T2·T4 에서 같다. 팝업 메시지 `type` 세 값이 T4·T5 에서 같다.
- 자리표시자: T2 Step 1 의 세 케이스는 본문 대신 흐름 주석으로 적었다(구현자가 인터페이스대로 채운다) — 나머지는 코드 그대로.
