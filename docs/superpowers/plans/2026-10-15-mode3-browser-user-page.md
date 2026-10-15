# Mode 3 브라우저 전용 사용자 페이지 + RP 릴레이 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Snap·Node 에이전트 설치 없이 브라우저만으로 Mode 3 사용자 흐름(등록·로그인 팝업·재검증·세션 요청·트랜잭션·Selective disclosure proof·세션 폐기·시연 스위치)이 돌아가게 한다 — 비밀은 IndexedDB 에 비밀번호로 암호화해 두고, 가스는 RP 의 릴레이가 댄다.

**Architecture:** `lib/mode3_*.js`(공유 암호·트리·체인 코드)를 esbuild 로 브라우저 번들에 넣고 Node 전용 모듈(`node:crypto`·`node:fs`·`node:path`·`node:url`)만 `lib/browser/` shim 으로 바꿔 끼운다. 사용자 앱 `mode3/user/`는 DOM 없는 코어(`core/`, Node 에서도 돈다 — chain 그룹 테스트)와 화면(`ui.js`·`popup.js`)으로 나눈다. 정적 서버 `mode3_user_static.js`(:5100)는 앱·`/zk/*`·공개 설정·존재 신호(health)만 낸다. RP 는 `POST /api/mode3/relay` 로 `execute` 를 대신 보내고, IdP 는 사용자 오리진에 CORS 를 연다. Node 에이전트와 그 테스트는 그대로 둔다.

**Tech Stack:** esbuild(번들, devDependency 승인 2026-10-15), `buffer`(브라우저 Buffer 폴리필 — node_modules 에 6.0.3 이미 있음, devDependency 로 명시), snarkjs 0.7.5 브라우저 빌드(`build/browser.esm.js`), circomlibjs 0.1.7, ethers 6, WebCrypto(PBKDF2·AES-GCM), IndexedDB, Cache API, Web Worker(module), Playwright + Chrome(브라우저 테스트), express(정적 서버·릴레이).

**Spec:** `docs/superpowers/specs/2026-10-15-mode3-browser-user-page-design.md` (커밋 5821015). 아래 "스펙 대비 결정" 이 스펙과 다른 점을 전부 적는다 — 실행자는 스펙과 이 절을 함께 읽는다.

## Global Constraints

- 응답·문서·주석·커밋 메시지는 한글. 기존 파일의 문체·용어(IdP·RP·사용자, "Mode 3" 는 화면 문구에 쓰지 않음)를 지킨다.
- **Node 에이전트 불변**(스펙 D4): `mode3_wallet_agent.js`·`tests/test_mode3_wallet_agent.mjs`·`tests/test_mode3_wallet_snap.mjs`·`tests/test_mode3_browser.mjs`·`tests/test_mode3_tour.mjs` 는 고치지 않는다(Task 6 의 `isolated_mode3_stack.mjs` 옵션 추가는 기본 동작을 바꾸지 않는다). 공유 라이브러리 변경은 **기본값이 지금과 같은 선택적 인자 추가**만 허용한다.
- 프로토콜(회로·토큰·컨트랙트·IdP 라우트의 의미) 변경 금지. 공개 입력 33개, `PUB_INDEX`, 리프 식, 서명 메시지는 그대로.
- 비밀(`s_u`·`sk_u`·`blind_u`·세션 개인키)은 **암호화된 `secrets` 레코드 안에서만** 저장되고, 화면·DOM·`localStorage`·로그·RP 로 가는 메시지·정적 서버 어디에도 나오지 않는다. 팝업이 RP 에 돌려주는 결과에 `uid` 도 싣지 않는다.
- 정적 서버는 비밀·세션을 받지 않는다. 받는 것은 `POST /wallet/presence` 의 불리언·정수 6개뿐이다.
- 번들 산출물 `mode3/user/dist/` 는 커밋하지 않는다(`.gitignore`). 빌드 명령은 `npm run user:build`.
- 새 사유 코드는 `mode3/common/strings.js` `reasons` 에 ko·en 의 `title·cause·action` 과 `where` 를 넣고 `tests/test_mode3_demo_strings.js` 의 `REASONS` 에도 넣는다. 새 ui 키는 `user_*`(사용자 페이지)·`rp_*`(RP 페이지) 접두어, ko·en 둘 다.
- 새 테스트는 `scripts/run_tests.sh` 의 해당 그룹에 넣는다(unit = 외부 의존 없음, chain = :8545, browser = chain + Chrome).
- `.env`·`cia_keys.json`·`idp_state.json`·저장소 루트의 `cia_state.json`·`mode3_wallet_state.json`·`mode3_rp_registration.json` 은 읽지도 고치지도 않는다. 테스트는 격리 스택(`tests/helpers/`)만 쓴다.
- 커밋은 태스크마다 하나 이상, 메시지 끝에 `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` 와 `Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN` 두 줄.
- 라이브 데모 포트(3100·3101·4100·5100·8082·8545)의 프로세스는 건드리지 않는다. 테스트는 `freePort()` 로 임시 포트를 쓴다.

## 스펙 대비 결정 (2026-10-15 코드 조사 결과 — 실행자는 이것을 스펙보다 우선한다)

| # | 스펙 | 결정 | 이유 |
|---|---|---|---|
| R1 | D3: 정적 서버가 COOP `same-origin`·COEP `require-corp` 헤더를 낸다 | **두 헤더를 내지 않는다** | COOP `same-origin` 은 다른 오리진(RP)이 연 팝업의 `window.opener` 를 끊어 postMessage 흐름(D6)이 깨진다. snarkjs 0.7.5·ffjavascript 0.3.1 브라우저 빌드는 `SharedArrayBuffer` 를 쓰지 않는다(`node_modules/snarkjs/build/browser.esm.js`·`.../ffjavascript/build/browser.esm.js` 에 0건, `threadman.js` 는 postMessage 워커) — 헤더 없이도 멀티스레드다. |
| R2 | §3 `rcl` 키(증분 동기화 체크포인트) | **`rcl` 키를 두지 않는다.** 브라우저는 `syncRevocationTree`·`syncRegistryTree`(창세기 재생, fail-closed)로만 동기화한다 | `lib/mode3_rcl_sync.js` 는 `node:fs`·`mode3_state.js` 에 묶여 있어 번들에 넣으려면 에이전트 호출부를 바꿔야 한다(D4 위배). 데모 규모(리프 수십)에서 전체 재생은 수백 ms 다. 증분은 후속. |
| R3 | §3 잠금: 키는 메모리(탭 수명)에만 | **잠금 해제 키를 추출 불가(`extractable:false`) `CryptoKey` 로 IndexedDB `unlock` 레코드에 두고 30분(`UNLOCK_TTL_MS`) 뒤 자동 잠금.** "잠그기" 는 그 레코드를 지운다 | 팝업은 요청마다 새 창이라 탭 메모리로는 로그인·재검증·요청·트랜잭션마다 비밀번호를 물어야 한다(사용자가 반복 입력을 불편하다고 한 전례, 2026-10-14). 저장 중 비밀은 여전히 암호문이고, 해제 중의 키는 같은 오리진 스크립트만 쓸 수 있다(스펙 §9 의 XSS 한계와 같은 범위). 런북·§9 에 적는다. |
| R4 | §2·D6: web 모드에서 RP 가 사용자 오리진에 fetch 하지 않는다; 정적 서버는 상태를 전혀 다루지 않는다 | 정적 서버가 **공개·무비밀** 두 GET(`/wallet/config`, `/mode3/health`)을 지금 에이전트와 같은 CORS 규칙으로 내고, 사용자 페이지가 같은 오리진에서 `POST /wallet/presence`(불리언·정수 6개)로 health 의 `registered·hasCred·sessions·rpCount·txs·disclosedTxs` 를 채운다. RP 페이지의 `/wallet/login·revalidate·request·config` 비밀 경로 fetch 는 없어진다 | 상태 패널·체험 모드(`Demo.stack` 이 `${wallet}/mode3/health` 를 폴링, `two_rps`·`wallet_registered` 판정)가 RP 창에서 사용자 창의 사실을 알 길이 이것뿐이다. 팝업으로 알리려면 사용자 제스처(클릭) 없이는 창을 못 연다. |
| R5 | §4.2 `mode3-config` 응답에 `uid?` | **uid 를 싣지 않는다** | `uid` 는 `SENSITIVE_KEYS`(lib/mode3_health.js) — RP 가 알면 안 된다. |
| R6 | §5.1 릴레이 본문 `{ to, data }`, 검사 (2) `isWallet(to)` 또는 로그인 기록 PPID 대조 | 검사 (2) = **`factory.computeAddress(pub[0]) === to`**(pub[0] 이 PPID). 코드가 없는 주소면 릴레이어가 **`factory.deploy(pub[0])` 를 먼저 보낸 뒤** `execute` 를 보낸다. 응답 `{ txHash, deployed, deployTxHash }` | 첫 트랜잭션은 계정 배포가 필요하다(에이전트 file 모드와 같다). CREATE2 라 배포 전에도 대조가 된다. 로그인 기록 대조는 RP 재시작으로 사라지는 메모리라 쓰지 않는다. |
| R7 | §6 `assets` 인자(URL/ArrayBuffer)로 `fullProve` 에 버퍼를 넘긴다 | **`fullProve` 함수 주입**: `proveIdp`·`buildIssueRequest`·`buildCredentialProof` 에 선택 인자 `fullProve`(기본 `snarkjs.groth16.fullProve`)를 더한다. 브라우저는 워커에 입력만 보내는 함수를 넘긴다 | zkey(22 MB)를 메인 스레드에 올리지 않고 §6 의 워커 설계를 그대로 살린다. Node 호출부는 바뀌지 않는다. |
| R8 | §6 `setStringHasher(fn)` 주입 | 주입 없음. `node:crypto` shim 이 **동기 `createHash('sha256')`** 를 순수 JS(`lib/browser/sha256.js`)로 제공한다 | `createHash` 가 쓰이는 곳은 `loadSchema`(스키마 해시)·`originToField`(rp_cert) 두 동기 호출이다 — 문자열 속성 해시는 Poseidon 이라 shim 대상이 아니다. |
| R9 | D5 `scripts/build_user_app.sh` + esbuild CLI `--alias` | **`scripts/build_user_app.mjs`**(esbuild JS API, `onResolve` 플러그인으로 `node:*` → shim) | `node:` 접두어 alias 의 CLI 지원이 버전마다 달라 플러그인이 확실하다. `npm run user:build` 는 그대로. |
| R10 | §7 "Snap 동의 창을 대신하는 동의 화면" | 팝업 카드에 **승인·거절 버튼**(`#authApproveBtn`·`#authDenyBtn`). 잠겨 있으면 같은 카드 안에 비밀번호 입력(`#unlockPw`·`#unlockBtn`) | Snap 대화상자가 없으니 페이지가 직접 묻는다. |
| R11 | D4 "`MODE3_USER_MODE=web`" | 그런 env 는 두지 않는다. :5100 에 **에이전트 대신 `node mode3_user_static.js` 를 띄우는 것**이 web 모드다 | 두 프로세스는 포트가 같아 동시에 뜰 수 없고, 읽는 코드가 없는 env 는 혼란만 준다. |
| R12 | §4.2 재승인(`reauth`) | web 모드는 비밀이 사라지지 않으므로 `needs_consent` 가 나지 않는다. `mode3-authorize` 에 `reauth:true` 가 오면 세션 존재·인증서 검사만 하고 `{ ok:true, reauth:true }` 를 돌려준다 | RP 페이지 코드 호환. |

## 파일 구조

| 파일 | 역할 | 태스크 |
|---|---|---|
| `lib/browser/sha256.js` | 순수 JS SHA-256(`sha256(Uint8Array) → Uint8Array`, `sha256Hex`) | 1 |
| `lib/browser/node_crypto.js` | `node:crypto` shim — `randomBytes(n)`(Buffer), `createHash('sha256')`(동기) | 1 |
| `lib/browser/node_fs.js`·`node_path.js`·`node_url.js` | 번들용 shim(`fs` 는 호출되면 throw, `path.join`·`fileURLToPath` 는 문자열 연산) | 4 |
| `lib/browser/globals_shim.js` | `globalThis.Buffer`(`buffer` 패키지)·`globalThis.process` 주입 | 4 |
| `lib/browser/secret_box.js` | PBKDF2(SHA-256, 310,000, salt 16B) → AES-GCM-256 키, JSON 암복호, check 박스 | 2 |
| `lib/browser/zk_assets.js` | `/zk/*` fetch + Cache API(`mode3-zk-v1`) + 진행률 | 9 |
| `lib/mode3_idp_proof.js`·`lib/mode3_wallet.js` | `fullProve` 선택 인자(R7) | 3 |
| `scripts/build_user_app.mjs` | esbuild 번들(`user`·`prover_worker` 두 엔트리 → `mode3/user/dist/`) | 4 |
| `package.json`·`.gitignore` | devDependencies(esbuild·buffer), `user:build`·`user:static` 스크립트, `mode3/user/dist/` 무시 | 4 |
| `mode3_user_static.js` | :5100 정적 서버 — `/`, `/dist/*`, `/common/*`, `/zk/*`, `/user/config`, `/wallet/config`, `/mode3/health`, `/wallet/presence` | 5 |
| `tests/helpers/isolated_mode3_stack.mjs` | 옵션 `userMode: 'web'`(정적 서버를 지갑 자리에) | 5 |
| `cia.js` | 사용자 오리진 CORS(7 라우트) | 6 |
| `mode3_rp.js` | `POST /api/mode3/relay`, `GET /api/mode3/relay/:txHash` | 7 |
| `mode3/user/core/kv_mem.js`·`kv_idb.js` | 키-값 저장소(메모리 / IndexedDB `mode3-user` v1, 저장소 `kv`) | 8 |
| `mode3/user/core/vault.js` | 비밀번호 금고(meta·secrets·unlock, R3) | 8 |
| `mode3/user/core/chain.js` | `mirrorView`·`syncAll`(전체 재생)·`accountAddressOf` | 8 |
| `mode3/user/core/idp.js` | IdP 호출(`ciaPost`·`pkCia`·속성 스키마) | 8 |
| `mode3/user/core/user_core.js` | 에이전트 라우트의 등가 함수들 — `{ status, body }` 를 돌려준다 | 8 |
| `mode3/user/prover_worker.js`·`prover_client.js` | 증명 워커와 메인 쪽 클라이언트 | 9 |
| `mode3/user/index.html`·`ui.js`·`popup.js`·`user.js` | 화면(`data-page="wallet"` 유지)·팝업 프로토콜·엔트리 | 9 |
| `mode3/common/strings.js`·`tests/test_mode3_demo_strings.js` | `user_*`·`rp_wallet_web*` 키, 새 사유 10개 | 9 |
| `mode3/rp.html` | `walletCfg.secrets === 'web'` 분기(팝업 4종) | 9 |
| `tests/test_browser_sha256.js`·`tests/test_secret_box.mjs`·`tests/test_mode3_wallet_lib.js` | unit | 1·2·3 |
| `tests/test_mode3_user_static.mjs`·`tests/test_cia_cors.mjs`·`tests/test_mode3_rp_relay.mjs`·`tests/test_mode3_user_core.mjs` | chain | 5·6·7·8 |
| `tests/test_mode3_user_web.mjs` | browser | 9·10 |
| `docs/MODE3_DEMO.md`·스펙 상태 줄·`scripts/run_tests.sh` | 런북·테스트 그룹 | 11 |

---

### Task 1: 순수 JS SHA-256 과 `node:crypto` shim

**Files:**
- Create: `lib/browser/sha256.js`
- Create: `lib/browser/node_crypto.js`
- Test: `tests/test_browser_sha256.js` (unit)

**Interfaces:**
- Produces: `sha256(bytes: Uint8Array): Uint8Array`, `sha256Hex(bytes): string`(소문자 hex), `utf8Bytes(str): Uint8Array`; shim `randomBytes(n): Buffer`, `createHash(alg): { update(data, enc?), digest(enc?) }` — `alg` 는 `'sha256'` 만, 그 밖은 throw. `update` 는 문자열(기본 utf8, `'hex'` 허용)·Uint8Array·Buffer 를 받고 체이닝한다. `digest()` 는 Buffer, `digest('hex')` 는 문자열.
- Consumes: 없음(브라우저·Node 공통 코드 — Node 테스트가 `node:crypto` 를 오라클로 쓴다). shim 은 `globalThis.Buffer` 가 있어야 한다(Node 는 늘 있고, 브라우저는 Task 4 의 `globals_shim.js` 가 넣는다).

- [ ] **Step 1: 실패하는 테스트**

```js
// tests/test_browser_sha256.js — 순수 JS SHA-256 과 node:crypto shim 이 Node 의 crypto 와 같은 값을 낸다. (unit)  node tests/test_browser_sha256.js
import assert from 'node:assert/strict';
import { createHash as nodeCreateHash, randomBytes as nodeRandomBytes } from 'node:crypto';
import { sha256, sha256Hex, utf8Bytes } from '../lib/browser/sha256.js';
import { createHash, randomBytes } from '../lib/browser/node_crypto.js';

let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

t('표준 벡터: 빈 입력·abc·448비트 경계·2블록', () => {
  assert.equal(sha256Hex(new Uint8Array(0)), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256Hex(utf8Bytes('abc')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256Hex(utf8Bytes('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')), '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  assert.equal(sha256Hex(utf8Bytes('a'.repeat(1000))), nodeCreateHash('sha256').update('a'.repeat(1000)).digest('hex'));
});
t('임의 길이 0..300 바이트 200개가 node:crypto 와 같다', () => {
  for (let i = 0; i < 200; i++) {
    const n = Math.floor(Math.random() * 301);
    const b = new Uint8Array(nodeRandomBytes(n));
    assert.equal(sha256Hex(b), nodeCreateHash('sha256').update(b).digest('hex'), `len=${n}`);
  }
});
t('createHash shim: 문자열(utf8)·hex 문자열·Uint8Array·체이닝·digest()/digest(hex) 가 node 와 같다', () => {
  const s = '한글 origin http://127.0.0.1:3100';
  assert.equal(createHash('sha256').update(s, 'utf8').digest('hex'), nodeCreateHash('sha256').update(s, 'utf8').digest('hex'));
  assert.equal(createHash('sha256').update(s).digest('hex'), nodeCreateHash('sha256').update(s).digest('hex'));
  assert.equal(createHash('sha256').update('deadbeef', 'hex').digest('hex'), nodeCreateHash('sha256').update('deadbeef', 'hex').digest('hex'));
  assert.equal(createHash('sha256').update('ab').update(new Uint8Array([1, 2])).digest('hex'), nodeCreateHash('sha256').update('ab').update(new Uint8Array([1, 2])).digest('hex'));
  const d = createHash('sha256').update('x').digest();
  assert.ok(Buffer.isBuffer(d) && d.length === 32);
  assert.throws(() => createHash('md5'), /sha256/);
});
t('randomBytes shim: 길이·Buffer·toString(hex)·연속 호출이 다르다', () => {
  const a = randomBytes(32), b = randomBytes(32);
  assert.ok(Buffer.isBuffer(a) && a.length === 32);
  assert.match(a.toString('hex'), /^[0-9a-f]{64}$/);
  assert.notEqual(a.toString('hex'), b.toString('hex'));
  assert.equal(randomBytes(0).length, 0);
});
t('originToField·loadSchema 와 같은 입력에서 shim 과 node 가 같다(encodeProfile 경로 동등성)', async () => {
  const { canonicalJson, DEFAULT_ATTR_SCHEMA } = await import('../lib/mode3_attr_schema.js');
  const cj = canonicalJson(DEFAULT_ATTR_SCHEMA);
  assert.equal(createHash('sha256').update(cj).digest('hex'), nodeCreateHash('sha256').update(cj).digest('hex'));
  for (const o of ['http://127.0.0.1:3100', 'https://rp.example.com', 'http://localhost:3101']) assert.equal(createHash('sha256').update(o, 'utf8').digest('hex'), nodeCreateHash('sha256').update(o, 'utf8').digest('hex'));
});
process.exit(fails ? 1 : 0);
```

- [ ] **Step 2: 실패 확인** — `node tests/test_browser_sha256.js` → `ERR_MODULE_NOT_FOUND` (lib/browser/sha256.js 없음).

- [ ] **Step 3: 구현**

```js
// lib/browser/sha256.js — 순수 JS SHA-256(FIPS 180-4). 브라우저 번들에서 node:crypto 의 createHash('sha256') 를 대신한다(계획 R8).
// WebCrypto 의 digest 는 비동기라 loadSchema(동기)·originToField(동기)를 바꾸지 않으려면 동기 구현이 필요하다. 입력은 수 KB 이하다.
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const rotr = (x, n) => (x >>> n) | (x << (32 - n));

export function sha256(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error('sha256: Uint8Array 가 필요하다');
  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const bitLen = bytes.length * 8;
  const padLen = ((bytes.length + 9 + 63) >> 6) << 6;   // 길이 + 0x80 + 8바이트 길이를 64의 배수로
  const m = new Uint8Array(padLen);
  m.set(bytes); m[bytes.length] = 0x80;
  const dv = new DataView(m.buffer);
  dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000)); dv.setUint32(padLen - 4, bitLen >>> 0);
  const W = new Uint32Array(64);
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(i * 4, H[i]);
  return out;
}
export const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
export const sha256Hex = (bytes) => toHex(sha256(bytes));
export const utf8Bytes = (s) => new TextEncoder().encode(s);
export function hexBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error('hexBytes: 짝수 길이 hex 문자열이 필요하다');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
```

```js
// lib/browser/node_crypto.js — 브라우저 번들에서 'node:crypto' 자리에 들어가는 shim(계획 R8). 쓰이는 두 함수만 제공한다:
//   randomBytes(n)            lib/mode3_credential.js(randomScalar)·mode3_trace.js·mode3_wallet.js(sk_u)
//   createHash('sha256')      lib/mode3_attr_schema.js(loadSchema 해시, 동기)·lib/mode3_rp_cert.js(originToField, 동기)
// Buffer 는 globalThis.Buffer(Node 는 내장, 브라우저는 lib/browser/globals_shim.js 가 buffer 패키지로 넣는다)를 쓴다.
import { sha256, hexBytes, utf8Bytes } from './sha256.js';

export function randomBytes(n) {
  if (!Number.isInteger(n) || n < 0) throw new Error('randomBytes: 음이 아닌 정수');
  const u8 = new Uint8Array(n);
  if (n > 0) globalThis.crypto.getRandomValues(u8);
  return globalThis.Buffer.from(u8);
}

export function createHash(alg) {
  if (alg !== 'sha256') throw new Error(`createHash shim 은 sha256 만 지원한다: ${alg}`);
  const parts = [];
  const h = {
    update(data, enc = 'utf8') {
      if (typeof data === 'string') parts.push(enc === 'hex' ? hexBytes(data) : utf8Bytes(data));
      else if (data instanceof Uint8Array) parts.push(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
      else throw new Error('createHash shim: 문자열 또는 Uint8Array 만 받는다');
      return h;
    },
    digest(enc) {
      const total = parts.reduce((n, p) => n + p.length, 0);
      const all = new Uint8Array(total);
      let o = 0; for (const p of parts) { all.set(p, o); o += p.length; }
      const d = sha256(all);
      return enc === 'hex' ? [...d].map((b) => b.toString(16).padStart(2, '0')).join('') : globalThis.Buffer.from(d);
    },
  };
  return h;
}
export default { randomBytes, createHash };
```

- [ ] **Step 4: 통과 확인** — `node tests/test_browser_sha256.js` → 5개 `ok`.
- [ ] **Step 5: `scripts/run_tests.sh` 의 `UNIT=(` 배열 끝(`tests/test_mode3_attr_schema.mjs` 다음 줄)에 `tests/test_browser_sha256.js` 추가.**
- [ ] **Step 6: 커밋** — `git add lib/browser/sha256.js lib/browser/node_crypto.js tests/test_browser_sha256.js scripts/run_tests.sh` / `git commit -m "feat(user-web): 순수 JS SHA-256 과 node:crypto shim(브라우저 번들용)"` (+ 트레일러 두 줄).

---
### Task 2: 비밀번호 금고 원시 연산 `lib/browser/secret_box.js`

**Files:**
- Create: `lib/browser/secret_box.js`
- Test: `tests/test_secret_box.mjs` (unit — Node 22 의 `globalThis.crypto.subtle` 로 돈다, 외부 의존 없음)

**Interfaces:**
- Produces:
  - `KDF_ITERATIONS = 310000`, `SALT_BYTES = 16`, `CHECK_PLAINTEXT = 'mode3-user'`
  - `randomSaltHex(): string`(32자 hex)
  - `deriveKey(password: string, saltHex: string, iterations = KDF_ITERATIONS, { extractable = false } = {}): Promise<CryptoKey>` — PBKDF2-SHA-256 → AES-GCM 256, usages `['encrypt','decrypt']`
  - `encryptJson(key, obj): Promise<{ iv: string(hex 24자), ct: string(hex) }>`, `decryptJson(key, box): Promise<any>`(실패 시 `Error{ reason:'bad_password' }`)
  - `makeCheck(key): Promise<box>`, `verifyCheck(key, box): Promise<boolean>`
  - `createMeta(password): Promise<{ meta, key }>` — `meta = { version: 1, createdAt: ISO, kdf: { salt, iterations }, check }`
  - `openMeta(password, meta): Promise<CryptoKey | null>`(비밀번호가 틀리면 null)
- Consumes: 없음.

- [ ] **Step 1: 실패하는 테스트**

```js
// tests/test_secret_box.mjs — PBKDF2/AES-GCM 금고 원시 연산(스펙 D1). Node 22 WebCrypto 로 돈다. (unit)  node tests/test_secret_box.mjs
import assert from 'node:assert/strict';
import { KDF_ITERATIONS, SALT_BYTES, randomSaltHex, deriveKey, encryptJson, decryptJson, makeCheck, verifyCheck, createMeta, openMeta } from '../lib/browser/secret_box.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

await t('상수: 310,000회·salt 16바이트, randomSaltHex 는 32자 hex 이고 매번 다르다', () => {
  assert.equal(KDF_ITERATIONS, 310000); assert.equal(SALT_BYTES, 16);
  const a = randomSaltHex(), b = randomSaltHex();
  assert.match(a, /^[0-9a-f]{32}$/); assert.notEqual(a, b);
});
await t('deriveKey: 기본은 추출 불가 AES-GCM 256, 같은 (pw, salt) 는 같은 암복호 키, 다른 salt·다른 pw 는 다른 키', async () => {
  const salt = randomSaltHex();
  const k1 = await deriveKey('pw-1', salt, 1000), k2 = await deriveKey('pw-1', salt, 1000);
  assert.equal(k1.extractable, false); assert.equal(k1.algorithm.name, 'AES-GCM'); assert.equal(k1.algorithm.length, 256);
  const box = await encryptJson(k1, { s_u: '123', sk_u: 'ab'.repeat(32) });
  assert.deepEqual(await decryptJson(k2, box), { s_u: '123', sk_u: 'ab'.repeat(32) });
  for (const k of [await deriveKey('pw-2', salt, 1000), await deriveKey('pw-1', randomSaltHex(), 1000)]) {
    await assert.rejects(() => decryptJson(k, box), (e) => e.reason === 'bad_password');
  }
  const ex = await deriveKey('pw-1', salt, 1000, { extractable: true });
  assert.equal(ex.extractable, true);
});
await t('encryptJson: iv 12바이트(hex 24자), 같은 평문도 iv 가 달라 암호문이 다르다, 손상된 ct 는 bad_password', async () => {
  const k = await deriveKey('pw', randomSaltHex(), 1000);
  const a = await encryptJson(k, { x: 1 }), b = await encryptJson(k, { x: 1 });
  assert.match(a.iv, /^[0-9a-f]{24}$/); assert.notEqual(a.iv, b.iv); assert.notEqual(a.ct, b.ct);
  const broken = { iv: a.iv, ct: a.ct.slice(0, -2) + (a.ct.endsWith('00') ? '01' : '00') };
  await assert.rejects(() => decryptJson(k, broken), (e) => e.reason === 'bad_password');
});
await t('makeCheck/verifyCheck: 맞는 키 true, 다른 키 false(throw 하지 않는다)', async () => {
  const salt = randomSaltHex();
  const k = await deriveKey('pw', salt, 1000), other = await deriveKey('no', salt, 1000);
  const check = await makeCheck(k);
  assert.equal(await verifyCheck(k, check), true);
  assert.equal(await verifyCheck(other, check), false);
});
await t('createMeta/openMeta: 메타 모양, 맞는 비밀번호는 키·틀리면 null, iterations 를 메타가 정한다', async () => {
  const { meta, key } = await createMeta('demo-pw');
  assert.equal(meta.version, 1); assert.ok(Date.parse(meta.createdAt) > 0);
  assert.match(meta.kdf.salt, /^[0-9a-f]{32}$/); assert.equal(meta.kdf.iterations, KDF_ITERATIONS);
  assert.ok(meta.check.iv && meta.check.ct);
  const box = await encryptJson(key, { hello: 'world' });
  const reopened = await openMeta('demo-pw', meta);
  assert.ok(reopened); assert.deepEqual(await decryptJson(reopened, box), { hello: 'world' });
  assert.equal(await openMeta('wrong', meta), null);
  const fast = { ...meta, kdf: { ...meta.kdf, iterations: 1000 } };
  assert.equal(await openMeta('demo-pw', fast), null, 'iterations 가 다르면 다른 키');
});
process.exit(fails ? 1 : 0);
```

- [ ] **Step 2: 실패 확인** — `node tests/test_secret_box.mjs` → `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: 구현**

```js
// lib/browser/secret_box.js — 사용자 페이지의 비밀 금고 원시 연산(스펙 2026-10-15 D1·§3). WebCrypto 만 쓴다(브라우저·Node 22 공통).
//   비밀번호 → PBKDF2(SHA-256, 310,000회, salt 16B) → AES-GCM-256 키(기본 추출 불가 — 계획 R3: IndexedDB 에 CryptoKey 로 보관해도
//   원시 키 바이트는 꺼낼 수 없다). 비밀 JSON 은 iv 12B 와 함께 암호화한다. meta.check 는 'mode3-user' 의 암호문 — 비밀번호 검증용.
export const KDF_ITERATIONS = 310000;
export const SALT_BYTES = 16;
export const CHECK_PLAINTEXT = 'mode3-user';
const subtle = () => globalThis.crypto.subtle;
const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const badPassword = (msg = 'bad_password') => Object.assign(new Error(msg), { reason: 'bad_password' });

export function randomSaltHex() { const s = new Uint8Array(SALT_BYTES); globalThis.crypto.getRandomValues(s); return toHex(s); }

export async function deriveKey(password, saltHex, iterations = KDF_ITERATIONS, { extractable = false } = {}) {
  if (typeof password !== 'string' || !password) throw new Error('deriveKey: 비밀번호 문자열이 필요하다');
  if (!/^[0-9a-f]{32}$/.test(saltHex)) throw new Error('deriveKey: salt 는 16바이트 hex');
  const base = await subtle().importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return subtle().deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(saltHex), iterations }, base, { name: 'AES-GCM', length: 256 }, extractable, ['encrypt', 'decrypt']);
}
export async function encryptJson(key, obj) {
  const iv = new Uint8Array(12); globalThis.crypto.getRandomValues(iv);
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj)));
  return { iv: toHex(iv), ct: toHex(new Uint8Array(ct)) };
}
export async function decryptJson(key, box) {
  if (!box || typeof box.iv !== 'string' || typeof box.ct !== 'string') throw badPassword('secret box 형식');
  let pt;
  try { pt = await subtle().decrypt({ name: 'AES-GCM', iv: fromHex(box.iv) }, key, fromHex(box.ct)); }
  catch { throw badPassword(); }   // WebCrypto 는 키 불일치·손상을 모두 OperationError 로 낸다 — 구분하지 않는다
  return JSON.parse(new TextDecoder().decode(pt));
}
export const makeCheck = (key) => encryptJson(key, CHECK_PLAINTEXT);
export async function verifyCheck(key, box) {
  try { return (await decryptJson(key, box)) === CHECK_PLAINTEXT; } catch { return false; }
}
export async function createMeta(password) {
  const salt = randomSaltHex();
  const key = await deriveKey(password, salt);
  return { meta: { version: 1, createdAt: new Date().toISOString(), kdf: { salt, iterations: KDF_ITERATIONS }, check: await makeCheck(key) }, key };
}
export async function openMeta(password, meta) {
  if (!meta || meta.version !== 1 || !meta.kdf?.salt) throw new Error('openMeta: meta 형식');
  let key;
  try { key = await deriveKey(password, meta.kdf.salt, meta.kdf.iterations); } catch { return null; }
  return (await verifyCheck(key, meta.check)) ? key : null;
}
```

- [ ] **Step 4: 통과 확인** — `node tests/test_secret_box.mjs` → 5개 `ok`(310,000회 PBKDF2 두 번이라 1~2초 걸린다).
- [ ] **Step 5: `scripts/run_tests.sh` UNIT 배열에 `tests/test_secret_box.mjs` 추가.**
- [ ] **Step 6: 커밋** — `feat(user-web): PBKDF2/AES-GCM 비밀 금고 원시 연산(secret_box)`.

---

### Task 3: 공유 라이브러리에 `fullProve` 주입 인자 (R7)

**Files:**
- Modify: `lib/mode3_idp_proof.js:32-42` (`proveIdp`)
- Modify: `lib/mode3_wallet.js:141-165` (`buildIssueRequest`), `lib/mode3_wallet.js:225-271` (`buildCredentialProof`)
- Test: `tests/test_mode3_wallet_lib.js` (unit, 케이스 추가)

**Interfaces:**
- Produces: `proveIdp({ …, wasmPath, zkeyPath, fullProve = snarkjs.groth16.fullProve })`, `buildIssueRequest({ …, idpWasmPath, idpZkeyPath, fullProve })`(있으면 `proveIdp` 에 그대로 넘긴다), `buildCredentialProof({ …, wasmPath, zkeyPath, fullProve = snarkjs.groth16.fullProve })`. `fullProve(input, wasmPath, zkeyPath) → Promise<{ proof, publicSignals }>` — snarkjs 와 같은 호출 모양. **기본값이 지금 동작이라 Node 호출부(에이전트·테스트)는 바뀌지 않는다.**
- Consumes: 없음.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_wallet_lib.js` 끝(`process.exit` 앞)에 추가:

```js
await t('R7: proveIdp 는 fullProve 를 주입받는다 — 회로 입력 전부를 넘기고 결과를 그대로 돌려준다', async () => {
  const { proveIdp } = await import('../lib/mode3_idp_proof.js');
  const calls = [];
  const stub = async (input, wasmPath, zkeyPath) => { calls.push({ input, wasmPath, zkeyPath }); return { proof: { pi_a: ['stub'] }, publicSignals: ['1', '2'] }; };
  const out = await proveIdp({ uid: 12345n, s_u: 7n, blind_u: 8n, attrs: [1990n, 410n], arid: 3n, r_rp: 4n, pk_i: 5n, r_s: 6n, auid: 9n, auid_s: 10n, C_u_pt: { x: 1n, y: 2n }, C_s_pt: { x: 3n, y: 4n }, max_height: 100n, wasmPath: 'W', zkeyPath: 'Z', fullProve: stub });
  assert.deepEqual(out, { proof: { pi_a: ['stub'] }, publicSignals: ['1', '2'] });
  assert.equal(calls.length, 1); assert.equal(calls[0].wasmPath, 'W'); assert.equal(calls[0].zkeyPath, 'Z');
  assert.deepEqual(Object.keys(calls[0].input).sort(), ['C_s_x', 'C_s_y', 'C_u_x', 'C_u_y', 'arid', 'attrs', 'auid', 'auid_s', 'blind_u', 'max_height', 'pk_i', 'r_rp', 'r_s', 's_u', 'uid']);
  assert.deepEqual(calls[0].input.attrs, ['1990', '410', '0', '0', '0', '0']);
});
await t('R7: buildIssueRequest 는 fullProve 를 proveIdp 에 넘긴다(기본값이면 snarkjs 를 부른다 — 여기서는 스텁으로 호출만 확인)', async () => {
  const { buildIssueRequest, createSessionKey } = await import('../lib/mode3_wallet.js');
  const reg = await createRegistration(12345n);
  let seen = null;
  const req = await buildIssueRequest({ uid: 12345n, s_u: reg.s_u, blind_u: 11n, attrs: [1990n, 410n], arid: 3n, r_rp: 4n, r_s: 6n, sk_u: reg.sk_u, session: createSessionKey(), chainid: 31337n, max_height: 100n, fullProve: async (input) => { seen = input; return { proof: { stub: true }, publicSignals: [] }; } });
  assert.ok(seen && seen.uid === '12345', 'proveIdp 가 주입된 fullProve 로 돌았다');
  assert.deepEqual(req.body.proof_idp, { stub: true });
  assert.equal(req.body.auid_s, req.auid_s.toString());
});
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_wallet_lib.js` → 두 케이스 FAIL(`fullProve` 를 무시하고 진짜 snarkjs 를 부르다 `W` 경로 없음으로 throw).

- [ ] **Step 3: 구현** — `lib/mode3_idp_proof.js`:

```js
/** 증명. … fullProve(기본 snarkjs.groth16.fullProve)는 브라우저가 워커 프록시를 꽂는 자리다(계획 2026-10-15 R7) — 호출 모양은 snarkjs 와 같다. */
export async function proveIdp({ uid, s_u, blind_u, attrs, arid, r_rp, pk_i, r_s, auid, auid_s, C_u_pt, C_s_pt, max_height, wasmPath = IDP_WASM_PATH, zkeyPath = IDP_ZKEY_PATH, fullProve = snarkjs.groth16.fullProve }) {
  // … (검사·pub·input 조립은 그대로)
  const { proof, publicSignals } = await fullProve(input, wasmPath, zkeyPath);
  return { proof, publicSignals };
}
```

`lib/mode3_wallet.js` `buildIssueRequest`: 시그니처에 `fullProve` 추가, `proveIdp({ …, ...(fullProve ? { fullProve } : {}) })`. `buildCredentialProof`: 시그니처에 `fullProve = snarkjs.groth16.fullProve`, 끝의 `snarkjs.groth16.fullProve(input, wasmPath, zkeyPath)` 를 `fullProve(input, wasmPath, zkeyPath)` 로. 각 함수의 JSDoc 에 한 줄(R7)을 더한다.

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_wallet_lib.js` 전체 ok. 회귀: `node tests/test_mode3_credential_v11.js`, 그리고 chain 노드가 있으면 `node tests/test_mode3_wallet.mjs`(실제 증명 경로 — 기본값 불변 확인).
- [ ] **Step 5: 커밋** — `feat(lib): proveIdp·buildIssueRequest·buildCredentialProof 에 fullProve 주입 인자(기본값 불변)`.

---
### Task 4: esbuild 번들 도구와 나머지 Node shim

**Files:**
- Modify: `package.json` (devDependencies `esbuild`·`buffer`, scripts `user:build`·`user:static`)
- Modify: `.gitignore` (`mode3/user/dist/`)
- Create: `lib/browser/node_fs.js`, `lib/browser/node_path.js`, `lib/browser/node_url.js`, `lib/browser/globals_shim.js`
- Create: `scripts/build_user_app.mjs`
- Create: `mode3/user/user.js`(이 태스크에서는 번들 가능성을 증명하는 최소 엔트리 — Task 9 가 실제 엔트리로 바꾼다), `mode3/user/prover_worker.js`(최소 엔트리 — Task 9 가 채운다)

**Interfaces:**
- Produces: `npm run user:build` → `mode3/user/dist/user.js`, `mode3/user/dist/prover_worker.js`(+ `.map`). 빌드 스크립트는 `node scripts/build_user_app.mjs` 로 직접 불러도 되고, 끝나면 `built mode3/user/dist/user.js (N KB), prover_worker.js (M KB)` 한 줄을 찍는다. 실패하면 exit 1.
- Consumes: Task 1 의 `node_crypto.js`.

- [ ] **Step 1: 의존성 추가**

```bash
npm install --save-dev esbuild@^0.28.2 buffer@^6.0.3
```
(`buffer` 6.0.3 은 이미 `node_modules` 에 전이 의존성으로 있다 — package.json 에 명시하는 것뿐이다. `package-lock.json` 변경도 함께 커밋한다.) `package.json` scripts 에 추가:

```json
"user:build": "node scripts/build_user_app.mjs",
"user:static": "node mode3_user_static.js",
```
`.gitignore` 의 `# generated zk build artifacts` 블록 아래에 한 줄: `mode3/user/dist/`.

- [ ] **Step 2: shim 네 개**

```js
// lib/browser/node_fs.js — 브라우저 번들에서 'node:fs' 자리. lib/mode3_idp_proof.js(loadIdpVkey)·lib/mode3_onchain.js(readArtifact·verifyReferenceCode)가
// import 만 하고 web 모드 경로에서는 부르지 않는다 — 부르면 분명한 오류로 죽게 한다(조용히 빈 값을 주지 않는다).
const nope = (name) => () => { throw new Error(`fs.${name} 는 브라우저에서 쓸 수 없다(web 모드는 이 경로를 쓰지 않아야 한다)`); };
const fs = { existsSync: () => false, readFileSync: nope('readFileSync'), writeFileSync: nope('writeFileSync'), openSync: nope('openSync'), rmSync: nope('rmSync'), promises: { readFile: async () => nope('promises.readFile')() } };
export default fs;
export const { existsSync, readFileSync, promises } = fs;
```
```js
// lib/browser/node_path.js — 'node:path' 자리. lib/mode3_wallet.js·mode3_idp_proof.js·mode3_onchain.js 가 기본 경로 상수를 만들 때 join 만 쓴다(값은 web 모드에서 쓰이지 않는다).
const join = (...p) => p.filter((s) => s !== undefined && s !== null && s !== '').join('/').replace(/\/{2,}/g, '/');
const dirname = (p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) || '/' : '.');
const basename = (p) => p.slice(p.lastIndexOf('/') + 1);
const resolve = (...p) => join(...p);
const path = { join, dirname, basename, resolve, sep: '/' };
export default path;
export { join, dirname, basename, resolve };
```
```js
// lib/browser/node_url.js — 'node:url' 자리. fileURLToPath(new URL('..', import.meta.url)) 가 번들 URL 문자열을 그대로 받는다.
export const fileURLToPath = (u) => String(u);
export default { fileURLToPath };
```
```js
// lib/browser/globals_shim.js — esbuild `inject` 로 모든 엔트리 맨 앞에 들어간다. circomlibjs(eddsa·blake-hash)와 우리 lib 가 전역 Buffer 를 쓰고,
// 일부 라이브러리가 typeof 검사 없이 process.env 를 읽는다.
import { Buffer } from 'buffer';
if (!globalThis.Buffer) globalThis.Buffer = Buffer;
if (!globalThis.process) globalThis.process = { env: {}, browser: true };
```

- [ ] **Step 3: 빌드 스크립트**

```js
// scripts/build_user_app.mjs — 브라우저 사용자 앱 번들(설계 2026-10-15 D5, 계획 R9). `npm run user:build`.
//   엔트리 두 개(페이지·증명 워커)를 ESM 으로 mode3/user/dist/ 에 낸다. Node 전용 모듈은 lib/browser/ shim 으로 바꿔 끼운다 —
//   공유 lib 는 고치지 않는다. snarkjs·ffjavascript 는 package.json 의 exports.browser(브라우저 빌드)로 자동 해석된다.
import * as esbuild from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SHIMS = { crypto: 'lib/browser/node_crypto.js', fs: 'lib/browser/node_fs.js', path: 'lib/browser/node_path.js', url: 'lib/browser/node_url.js' };
const nodeShims = {
  name: 'node-shims',
  setup(build) {
    build.onResolve({ filter: /^(node:)?(crypto|fs|path|url)$/ }, (args) => ({ path: path.join(ROOT, SHIMS[args.path.replace(/^node:/, '')]) }));
    // 그 밖의 node: 모듈이 끼어들면 조용히 빈 모듈이 되지 않고 빌드가 실패해야 한다 — esbuild 기본(platform:browser)이 그렇게 한다.
  },
};
const outdir = path.join(ROOT, 'mode3', 'user', 'dist');
const result = await esbuild.build({
  entryPoints: { user: path.join(ROOT, 'mode3/user/user.js'), prover_worker: path.join(ROOT, 'mode3/user/prover_worker.js') },
  bundle: true, format: 'esm', platform: 'browser', target: ['es2022'], outdir, sourcemap: true, logLevel: 'warning', metafile: true,
  plugins: [nodeShims],
  inject: [path.join(ROOT, 'lib/browser/globals_shim.js')],
  define: { 'process.env.NODE_ENV': '"production"', global: 'globalThis' },
});
const kb = (f) => Math.round(fs.statSync(path.join(outdir, f)).size / 1024);
console.log(`built mode3/user/dist/user.js (${kb('user.js')} KB), prover_worker.js (${kb('prover_worker.js')} KB)`);
// 남아 있는 node: 참조는 번들이 브라우저에서 import 실패로 죽는다는 뜻이다 — 여기서 잡는다.
for (const f of ['user.js', 'prover_worker.js']) {
  const src = fs.readFileSync(path.join(outdir, f), 'utf8');
  if (/from\s*["']node:/.test(src) || /require\(["']node:/.test(src)) { console.error(`${f}: node: 모듈 참조가 남아 있다`); process.exit(1); }
}
```

- [ ] **Step 4: 최소 엔트리(번들 가능성 증명용)** — `mode3/user/user.js`:

```js
// mode3/user/user.js — 사용자 페이지 엔트리(Task 9 가 실제 내용으로 바꾼다). 지금은 공유 lib 가 브라우저 번들에 들어가는지만 증명한다.
import { ethers } from 'ethers';
import { createRegistration, normalizeDisclosure } from '../../lib/mode3_wallet.js';
import { payloadDigest, PUB_INDEX } from '../../lib/mode3_onchain.js';
import { loadSchema, DEFAULT_ATTR_SCHEMA } from '../../lib/mode3_attr_schema.js';
import { originToField } from '../../lib/mode3_rp_cert.js';
console.log('mode3 user bundle ok', ethers.version, PUB_INDEX.COUNT, loadSchema(DEFAULT_ATTR_SCHEMA).hash.slice(0, 8), originToField('http://127.0.0.1:3100').toString().slice(0, 6));
window.__mode3UserSmoke = async () => { const r = await createRegistration(12345n); return { auid: r.auid.toString(), mask: normalizeDisclosure(null, []).mask.toString(), digest: payloadDigest({ chainId: 31337n, wallet: ethers.ZeroAddress, to: ethers.ZeroAddress, value: 0n, data: '0x', nonce: 0n, maxHeight: 1n, allowAgent: 0n, tagC1X: 0n, tagC1Y: 0n, tagC2: 0n }) }; };
```
`mode3/user/prover_worker.js`:
```js
// mode3/user/prover_worker.js — 증명 워커(Task 9 가 채운다). 지금은 snarkjs 브라우저 빌드가 번들되는지만 본다.
import * as snarkjs from 'snarkjs';
self.onmessage = (ev) => { self.postMessage({ id: ev.data?.id ?? null, pong: true, hasGroth16: typeof snarkjs.groth16?.fullProve === 'function' }); };
```

- [ ] **Step 5: 빌드 확인** — `npm run user:build` → `built …` 한 줄, exit 0. `ls -la mode3/user/dist/` 에 두 `.js` 와 `.map`. `grep -c "node:" mode3/user/dist/user.js` 는 import 문이 아닌 문자열(주석·메시지)만 남아야 한다(스크립트의 자체 검사가 import 를 거른다).
- [ ] **Step 6: 브라우저 스모크(수동 1회, Chrome)** — `cd mode3/user && python3 -m http.server 5199` 로 임시 서빙하고 `index.html` 이 아직 없으므로 `about:blank` 콘솔에서 `import('http://127.0.0.1:5199/dist/user.js')` 뒤 `await __mode3UserSmoke()` — `auid` 10진 문자열, `mask '0'`, `digest 0x…` 가 나오면 Buffer·circomlibjs·ethers 가 브라우저에서 돈 것이다. 끝나면 http.server 를 내린다. (자동화는 Task 9 의 브라우저 테스트가 한다.)
- [ ] **Step 7: 커밋** — `git add package.json package-lock.json .gitignore lib/browser/node_fs.js lib/browser/node_path.js lib/browser/node_url.js lib/browser/globals_shim.js scripts/build_user_app.mjs mode3/user/user.js mode3/user/prover_worker.js` / `build(user-web): esbuild 번들 도구·Node shim·최소 엔트리(npm run user:build)`.

---

### Task 5: 정적 서버 `mode3_user_static.js` 와 격리 스택 옵션 `userMode:'web'`

**Files:**
- Create: `mode3_user_static.js`
- Modify: `tests/helpers/isolated_mode3_stack.mjs` (옵션 추가 — 기본 동작 불변)
- Test: `tests/test_mode3_user_static.mjs` (chain — :8545 와 `npm run user:build` 산출물 필요; 테스트가 빌드를 스스로 돈다)

**Interfaces:**
- Produces (서버, env 는 에이전트와 같은 이름): `MODE3_WALLET_PORT`(5100) · `MODE3_WALLET_PUBLIC_ORIGIN` · `MODE3_CIA_URL`(http://127.0.0.1:4100) · `MODE3_RP_ORIGIN`(쉼표 목록) · `CIA_RPC_URL`(http://127.0.0.1:8545) · `MODE3_REV_CHAIN_RPC`(기본 = CIA_RPC_URL) · `CIA_LOG_ADDRESS` · `MODE3_MIRROR_ADDRESS` · `MODE3_TTL_BLOCKS`(300) · `MODE3_HEIGHT_GRID`(100) · `MODE3_PK_CIA_X/Y`(선택 고정) · `MODE3_RELAY_PATH`(기본 `/api/mode3/relay`, RP 쪽 라우트 이름).
  - `GET /` → `mode3/user/index.html`(`?authorize=1` 도 같은 파일). `GET /dist/*` → `mode3/user/dist/`, `GET /common/*` → `mode3/common/`.
  - `GET /zk/:name` — 허용 이름 6개만: `pi_cred.wasm`(→ `build/mode3/pi_cred_js/pi_cred.wasm`), `pi_cred_final.zkey`, `pi_cred_vkey.json`, `pi_idp.wasm`(→ `build/mode3/pi_idp_js/pi_idp.wasm`), `pi_idp_final.zkey`, `pi_idp_vkey.json`. 그 밖은 404. 헤더 `Cache-Control: public, max-age=31536000, immutable`(산출물은 세트로만 바뀐다 — 바뀌면 Cache API 이름 `mode3-zk-v1` 도 올린다).
  - `GET /user/config`(같은 오리진 전용 — CORS 없음) → `{ secrets:'web', walletOrigin, ciaUrl, rpcUrl, revRpcUrl, chainId(문자열|null), logAddress, mirrorAddress, ttlBlocks, heightGrid, rpOrigins:[…], pkCia:{x,y}|null, relayPath }`.
  - `GET /wallet/config`(CORS: `MODE3_RP_ORIGIN` 목록, 에이전트 `configCors` 와 같은 함수형 origin) → `{ secrets:'web', snapId:null, walletOrigin, rpcUrl, chainId }` — 에이전트 응답과 키가 같다.
  - `GET /mode3/health`(에이전트와 같은 `applyHealthHeaders(RP 오리진 + CIA_URL)`) → `buildWalletHealth({ now, chain, secrets:'web', …presence, ciaReachable, rpOrigin, rpOrigins, ciaUrl })`. `chain` 은 1.2초 예산의 `getBlockNumber`, `ciaReachable` 은 에이전트와 같은 10초 캐시 ping.
  - `POST /wallet/presence`(같은 오리진 전용, JSON) 본문 `{ registered:boolean, hasCred:boolean, sessions:int≥0, rpCount:int≥0, txs:int≥0, disclosedTxs:int≥0 }` — 타입이 하나라도 다르면 400 `{ reason:'malformed' }`. 메모리에만 둔다(재시작하면 모두 false/0).
  - 기동 때 `mode3/user/dist/user.js` 가 없으면 `npm run user:build 먼저` 를 찍고 exit 1. `127.0.0.1` 에만 listen. 기동 로그 `Mode 3 user static at http://127.0.0.1:PORT (cia=…, rp=…, log=…, mirror=…)`.
- Produces (헬퍼): `startIsolatedMode3Stack({ userMode: 'web' })` — 지갑 자리에 `mode3_user_static.js` 를 같은 `walletSpawn.env` 로 띄우고 `readyUrl` 을 `${walletOrigin}/wallet/config` 로 한다. `stack.userMode` 를 돌려준다. `restartWallet()` 도 같은 스크립트를 다시 띄운다. 기본값 `'agent'` 는 지금과 완전히 같다.
- Consumes: Task 4 의 dist, `lib/mode3_health.js`.

- [ ] **Step 1: 실패하는 테스트**

```js
// tests/test_mode3_user_static.mjs — 사용자 정적 서버(web 모드)의 라우트·CORS·존재 신호. :8545 필요(health 의 chain 조회), 번들은 여기서 만든다. (chain)
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
const stack = await startIsolatedMode3Stack({ userMode: 'web' });
const { wallet, rp, cia } = stack;
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.message); } }
const hdr = (r, k) => r.headers.get(k);
try {
  await t('/ 와 /?authorize=1 은 index.html(data-page="wallet"), /dist/user.js·/dist/prover_worker.js·/common/demo.js 가 200', async () => {
    for (const p of ['/', '/?authorize=1']) { const r = await wallet.raw(p); assert.equal(r.status, 200); assert.ok((await r.text()).includes('data-page="wallet"'), p); }
    for (const p of ['/dist/user.js', '/dist/prover_worker.js', '/common/demo.js', '/common/strings.js']) assert.equal((await wallet.raw(p)).status, 200, p);
  });
  await t('/zk/* 는 허용 이름 6개만 — vkey 는 JSON, 그 밖은 404, immutable 캐시 헤더', async () => {
    for (const n of ['pi_cred.wasm', 'pi_cred_final.zkey', 'pi_cred_vkey.json', 'pi_idp.wasm', 'pi_idp_final.zkey', 'pi_idp_vkey.json']) {
      const r = await wallet.raw(`/zk/${n}`, { method: 'HEAD' });
      assert.equal(r.status, 200, n); assert.match(hdr(r, 'cache-control') ?? '', /immutable/);
    }
    const v = await (await wallet.raw('/zk/pi_cred_vkey.json')).json(); assert.equal(v.protocol, 'groth16');
    for (const n of ['pi_cred.r1cs', '../package.json', 'x.zkey']) assert.equal((await wallet.raw(`/zk/${encodeURIComponent(n)}`)).status, 404, n);
  });
  await t('/user/config 는 같은 오리진 전용(CORS 없음)이고 공개 설정만 싣는다', async () => {
    const r = await wallet.raw('/user/config', { headers: { Origin: rp.origin } });
    const b = await r.json();
    assert.equal(r.status, 200); assert.equal(hdr(r, 'access-control-allow-origin'), null);
    assert.equal(b.secrets, 'web'); assert.equal(b.ciaUrl, cia.base); assert.equal(b.logAddress, cia.logAddress); assert.equal(b.mirrorAddress, cia.mirrorAddress);
    assert.deepEqual(b.rpOrigins, [rp.origin]); assert.equal(b.ttlBlocks, '300'); assert.equal(b.heightGrid, '100'); assert.equal(b.relayPath, '/api/mode3/relay');
    assert.match(b.chainId, /^[0-9]+$/);
    for (const k of ['s_u', 'sk_u', 'uid', 'secret']) assert.ok(!JSON.stringify(b).includes(`"${k}"`), k);
  });
  await t('/wallet/config 는 에이전트와 같은 키, RP 오리진에만 CORS', async () => {
    const ok = await wallet.raw('/wallet/config', { headers: { Origin: rp.origin } });
    assert.equal(hdr(ok, 'access-control-allow-origin'), rp.origin);
    assert.deepEqual(Object.keys(await ok.json()).sort(), ['chainId', 'rpcUrl', 'secrets', 'snapId', 'walletOrigin']);
    assert.equal((await wallet.get('/wallet/config')).body.secrets, 'web');
    assert.equal(hdr(await wallet.raw('/wallet/config', { headers: { Origin: 'http://evil.example' } }), 'access-control-allow-origin'), null);
  });
  await t('/mode3/health: role wallet·secrets web·기본 false/0, RP·IdP 오리진에만 CORS, 민감 키 없음', async () => {
    const r = await wallet.raw('/mode3/health', { headers: { Origin: rp.origin } });
    const h = await r.json();
    assert.equal(hdr(r, 'access-control-allow-origin'), rp.origin); assert.equal(hdr(r, 'cache-control'), 'no-store');
    assert.equal(h.role, 'wallet'); assert.equal(h.secrets, 'web'); assert.equal(h.registered, false); assert.equal(h.sessions, 0); assert.equal(h.rpCount, 0); assert.ok(h.chain?.head);
    assert.equal(hdr(await wallet.raw('/mode3/health', { headers: { Origin: cia.base } }), 'access-control-allow-origin'), cia.base);
    assert.equal(hdr(await wallet.raw('/mode3/health', { headers: { Origin: 'http://evil.example' } }), 'access-control-allow-origin'), null);
    for (const k of ['uid', 'PPID', 'sk_u', 'pk_u', 'arid', 'r_s']) assert.ok(!JSON.stringify(h).includes(`"${k}"`), k);
  });
  await t('/wallet/presence: 형식 검사 400, 반영된 값이 health 에 나온다, CORS 없음', async () => {
    assert.equal((await wallet.post('/wallet/presence', { registered: 'yes' })).status, 400);
    assert.equal((await wallet.post('/wallet/presence', { registered: true, hasCred: true, sessions: 2, rpCount: 1, txs: 3, disclosedTxs: 1, uid: '12345' })).status, 400, '모르는 키도 400');
    const ok = await wallet.post('/wallet/presence', { registered: true, hasCred: true, sessions: 2, rpCount: 2, txs: 3, disclosedTxs: 1 });
    assert.equal(ok.status, 200);
    const h = (await wallet.get('/mode3/health')).body;
    assert.equal(h.registered, true); assert.equal(h.hasCred, true); assert.equal(h.sessions, 2); assert.equal(h.rpCount, 2); assert.equal(h.txs, 3); assert.equal(h.disclosedTxs, 1);
    const pre = await wallet.raw('/wallet/presence', { method: 'OPTIONS', headers: { Origin: rp.origin, 'Access-Control-Request-Method': 'POST' } });
    assert.equal(hdr(pre, 'access-control-allow-origin'), null);
  });
  await t('restartWallet() 뒤에도 web 모드이고 presence 는 초기화된다', async () => {
    await stack.restartWallet();
    assert.equal((await wallet.get('/wallet/config')).body.secrets, 'web');
    assert.equal((await wallet.get('/mode3/health')).body.registered, false);
  });
} finally { await stack.stop(); }
process.exit(fails ? 1 : 0);
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_user_static.mjs` → 헬퍼가 `userMode` 를 몰라 에이전트가 뜨고 첫 케이스부터 FAIL(`/dist/user.js` 404).

- [ ] **Step 3: 헬퍼 옵션** — `tests/helpers/isolated_mode3_stack.mjs`:
  - `startIsolatedMode3Stack(opts)` 의 구조분해에 `userMode = 'agent'` 추가. `walletSpawn` 을 만들 때 `const walletScript = userMode === 'web' ? 'mode3_user_static.js' : 'mode3_wallet_agent.js'; const walletReady = userMode === 'web' ? `${walletOrigin}/wallet/config` : `${walletOrigin}/wallet/status`;` 로 두고 `spawnServer(walletScript, { ...walletSpawn, readyUrl: walletReady })`. `restartWallet()` 도 `walletScript` 를 쓴다. 반환 객체에 `userMode` 를 더한다. 파일 머리 주석에 한 줄 추가.

- [ ] **Step 4: 서버 구현** — `mode3_user_static.js`(핵심 부분):

```js
// Mode 3 사용자 정적 서버(:5100, web 모드 — 설계 2026-10-15 D3, 계획 R1·R4·R11). 에이전트(mode3_wallet_agent.js) 대신 같은 포트에 띄운다.
// 비밀·세션을 받지 않는다. 내는 것: 앱(mode3/user)·공통 레이어·zk 산출물·공개 설정, 그리고 사용자 페이지가 알려 준 존재 신호(health).
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { buildWalletHealth, applyHealthHeaders, bounded, originList, allowOrigin } from './lib/mode3_health.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.MODE3_WALLET_PORT) || 5100;
const WALLET_ORIGIN = process.env.MODE3_WALLET_PUBLIC_ORIGIN || `http://127.0.0.1:${PORT}`;
const CIA_URL = process.env.MODE3_CIA_URL || 'http://127.0.0.1:4100';
const RP_ORIGINS = originList((process.env.MODE3_RP_ORIGIN || 'http://127.0.0.1:3100').split(',').map((s) => s.trim()));
if (RP_ORIGINS.length === 0) throw new Error('MODE3_RP_ORIGIN 에 유효한 origin 이 하나도 없다');
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const REV_RPC = process.env.MODE3_REV_CHAIN_RPC || RPC_URL;
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const MIRROR_ADDRESS = process.env.MODE3_MIRROR_ADDRESS || null;
const envBig = (k, d) => { const v = process.env[k]; return v === undefined || v === '' ? String(d) : String(BigInt(v)); };
const TTL_BLOCKS = envBig('MODE3_TTL_BLOCKS', 300), HEIGHT_GRID = envBig('MODE3_HEIGHT_GRID', 100);
const PK_CIA = process.env.MODE3_PK_CIA_X && process.env.MODE3_PK_CIA_Y ? { x: process.env.MODE3_PK_CIA_X, y: process.env.MODE3_PK_CIA_Y } : null;
const RELAY_PATH = process.env.MODE3_RELAY_PATH || '/api/mode3/relay';
const DIST = path.join(__dirname, 'mode3', 'user', 'dist');
if (!fs.existsSync(path.join(DIST, 'user.js'))) { console.error('mode3/user/dist/user.js 가 없다 — npm run user:build 먼저'); process.exit(1); }
const ZK = {
  'pi_cred.wasm': 'build/mode3/pi_cred_js/pi_cred.wasm', 'pi_cred_final.zkey': 'build/mode3/pi_cred_final.zkey', 'pi_cred_vkey.json': 'build/mode3/pi_cred_vkey.json',
  'pi_idp.wasm': 'build/mode3/pi_idp_js/pi_idp.wasm', 'pi_idp_final.zkey': 'build/mode3/pi_idp_final.zkey', 'pi_idp_vkey.json': 'build/mode3/pi_idp_vkey.json',
};
const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, { cacheTimeout: -1 });
let chainId = null;
provider.getNetwork().then((n) => { chainId = n.chainId.toString(); }).catch(() => { /* health 가 null 로 보인다 */ });

// 존재 신호(계획 R4): 사용자 페이지가 같은 오리진에서 알려 주는 불리언·정수 6개. 재시작하면 초깃값.
const PRESENCE_KEYS = ['registered', 'hasCred', 'sessions', 'rpCount', 'txs', 'disclosedTxs'];
let presence = { registered: false, hasCred: false, sessions: 0, rpCount: 0, txs: 0, disclosedTxs: 0 };
function validPresence(b) {
  if (!b || typeof b !== 'object' || Array.isArray(b)) return false;
  if (Object.keys(b).some((k) => !PRESENCE_KEYS.includes(k)) || PRESENCE_KEYS.some((k) => !(k in b))) return false;
  return typeof b.registered === 'boolean' && typeof b.hasCred === 'boolean' && ['sessions', 'rpCount', 'txs', 'disclosedTxs'].every((k) => Number.isInteger(b[k]) && b[k] >= 0);
}
let ciaSeenAt = 0, pinging = null; const CIA_FRESH_MS = 10_000;
function pingCia() { if (!pinging) pinging = (async () => { const c = new AbortController(); const tm = setTimeout(() => c.abort(), 1500); try { if ((await fetch(`${CIA_URL}/cia/public_keys`, { signal: c.signal })).ok) ciaSeenAt = Date.now(); } catch { /* */ } finally { clearTimeout(tm); pinging = null; } })(); return pinging; }

const app = express();
app.use(express.json({ limit: '16kb' }));
const configCors = cors({ origin: (origin, cb) => cb(null, allowOrigin(origin, RP_ORIGINS)), methods: ['GET'] });
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'mode3', 'user', 'index.html')));
app.use('/dist', express.static(DIST));
app.use('/common', express.static(path.join(__dirname, 'mode3', 'common')));
app.get('/zk/:name', (req, res) => {
  const rel = ZK[req.params.name];
  if (!rel) return res.status(404).json({ reason: 'not_found' });
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  res.sendFile(path.join(__dirname, rel), (err) => { if (err && !res.headersSent) res.status(err.statusCode === 404 ? 404 : 500).json({ reason: err.statusCode === 404 ? 'zk_assets_unavailable' : 'internal' }); });
});
app.get('/user/config', (req, res) => res.json({ secrets: 'web', walletOrigin: WALLET_ORIGIN, ciaUrl: CIA_URL, rpcUrl: RPC_URL, revRpcUrl: REV_RPC, chainId, logAddress: LOG_ADDRESS, mirrorAddress: MIRROR_ADDRESS, ttlBlocks: TTL_BLOCKS, heightGrid: HEIGHT_GRID, rpOrigins: RP_ORIGINS, pkCia: PK_CIA, relayPath: RELAY_PATH }));
app.get('/wallet/config', configCors, (req, res) => res.json({ secrets: 'web', snapId: null, walletOrigin: WALLET_ORIGIN, rpcUrl: RPC_URL, chainId }));
const HEALTH_ALLOW = originList(RP_ORIGINS, CIA_URL);
app.get('/mode3/health', async (req, res) => {
  applyHealthHeaders(req, res, HEALTH_ALLOW);
  if (Date.now() - ciaSeenAt > CIA_FRESH_MS) pingCia();
  let chain = null;
  try { const head = await bounded(provider.getBlockNumber(), 1200); chain = { id: chainId ?? '', head: head.toString() }; } catch { /* 체인 없음 */ }
  res.json(buildWalletHealth({ now: new Date().toISOString(), chain, secrets: 'web', ...presence, ciaReachable: Date.now() - ciaSeenAt <= CIA_FRESH_MS, rpOrigin: RP_ORIGINS[0], rpOrigins: RP_ORIGINS, ciaUrl: CIA_URL }));
});
app.post('/wallet/presence', (req, res) => {
  if (!validPresence(req.body)) return res.status(400).json({ reason: 'malformed' });
  presence = { ...req.body };
  res.json({ ok: true });
});
app.use((err, req, res, next) => { if (res.headersSent) return next(err); if (err?.type === 'entity.parse.failed') return res.status(400).json({ reason: 'malformed' }); res.status(500).json({ reason: 'internal' }); });
app.listen(PORT, '127.0.0.1', () => console.log(`Mode 3 user static at http://127.0.0.1:${PORT} (cia=${CIA_URL}, rp=${RP_ORIGINS.join(',')}, log=${LOG_ADDRESS ?? 'none'}, mirror=${MIRROR_ADDRESS ?? 'none'})`));
```
`index.html` 은 Task 9 에서 만든다 — 이 태스크의 첫 케이스가 통과하려면 **임시 `mode3/user/index.html`** 을 두어야 한다: `<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>사용자 페이지</title></head><body data-page="wallet"><script type="module" src="/dist/user.js"></script></body></html>`(Task 9 가 전체로 바꾼다).

- [ ] **Step 5: 통과 확인** — `node tests/test_mode3_user_static.mjs` → 7개 ok. 회귀: `node tests/test_mode3_health.mjs`(헬퍼 기본 동작 불변).
- [ ] **Step 6: `scripts/run_tests.sh` CHAIN 배열의 `tests/test_mode3_health.mjs` 다음 줄에 `tests/test_mode3_user_static.mjs` 추가**(주석: `# web 모드 정적 서버 — 번들을 스스로 만든다(esbuild devDependency)`).
- [ ] **Step 7: 커밋** — `feat(user-web): 사용자 정적 서버(:5100, /zk·공개 설정·존재 신호)와 격리 스택 userMode:'web'`.

---
### Task 6: IdP CORS — 사용자 오리진에 7 라우트 (스펙 §5.3)

**Files:**
- Modify: `cia.js` (import `cors`; `WALLET_AGENT_ORIGIN` 상수를 라우트들보다 앞(`ADMIN_SECRET` 근처, 55행 부근)으로 올리고 `/mode3/health` 쪽 중복 선언 제거; 7 라우트에 미들웨어)
- Test: `tests/test_cia_cors.mjs` (chain — 격리 IdP 만 띄운다, 가볍다)

**Interfaces:**
- Produces: `/cia/register`·`/cia/issue`·`/cia/slot`·`/cia/revoke`·`/cia/account/self_revoke`(POST + OPTIONS 프리플라이트), `/cia/public_keys`·`/cia/attr_schema`(GET)에 `Access-Control-Allow-Origin: <MODE3_WALLET_AGENT_ORIGIN>`(요청 Origin 이 정확히 그 값일 때만), `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers: Content-Type`(**`X-CIA-Admin-Secret` 은 허용하지 않는다** — `/cia/revoke` 의 관리자 경로는 브라우저 교차 오리진에서 막힌다), `Vary: Origin`. 관리자 라우트(`/cia/rps*`, `/cia/admin/*`, `/cia/accounts*`)와 그 밖에는 CORS 헤더가 없다.
- Consumes: 없음.

- [ ] **Step 1: 실패하는 테스트**

```js
// tests/test_cia_cors.mjs — IdP 가 사용자 오리진(MODE3_WALLET_AGENT_ORIGIN)에 여는 CORS(스펙 2026-10-15 §5.3). 격리 IdP 만 띄운다. (chain)
import assert from 'node:assert/strict';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
const USER = 'http://127.0.0.1:5199';
const cia = await startIsolatedCia({ env: { MODE3_WALLET_AGENT_ORIGIN: USER } });
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.message); } }
const pre = (p, origin, method = 'POST', headers = 'content-type') => fetch(`${cia.base}${p}`, { method: 'OPTIONS', headers: { Origin: origin, 'Access-Control-Request-Method': method, 'Access-Control-Request-Headers': headers } });
const h = (r, k) => r.headers.get(k);
try {
  await t('프리플라이트: 5 POST 라우트가 사용자 오리진에 ACAO·POST·Content-Type 을 허용한다', async () => {
    for (const p of ['/cia/register', '/cia/issue', '/cia/slot', '/cia/revoke', '/cia/account/self_revoke']) {
      const r = await pre(p, USER);
      assert.ok([200, 204].includes(r.status), `${p} ${r.status}`);
      assert.equal(h(r, 'access-control-allow-origin'), USER, p);
      assert.match(h(r, 'access-control-allow-methods') ?? '', /POST/, p);
      assert.match((h(r, 'access-control-allow-headers') ?? '').toLowerCase(), /content-type/, p);
      assert.ok(!(h(r, 'access-control-allow-headers') ?? '').toLowerCase().includes('x-cia-admin-secret'), `${p} 관리자 헤더는 허용하지 않는다`);
    }
  });
  await t('실제 요청: public_keys·attr_schema GET 과 register POST(400 이어도) 에 ACAO 가 붙고 Vary: Origin', async () => {
    for (const p of ['/cia/public_keys', '/cia/attr_schema']) { const r = await fetch(`${cia.base}${p}`, { headers: { Origin: USER } }); assert.equal(r.status, 200); assert.equal(h(r, 'access-control-allow-origin'), USER, p); assert.match(h(r, 'vary') ?? '', /Origin/); }
    const r = await fetch(`${cia.base}/cia/register`, { method: 'POST', headers: { Origin: USER, 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(r.status, 400); assert.equal(h(r, 'access-control-allow-origin'), USER);
  });
  await t('다른 오리진에는 ACAO 가 없다(프리플라이트·실제 요청 모두)', async () => {
    for (const o of ['http://evil.example', 'http://127.0.0.1:5198', USER + '/']) {
      assert.equal(h(await pre('/cia/issue', o), 'access-control-allow-origin'), null, o);
      assert.equal(h(await fetch(`${cia.base}/cia/public_keys`, { headers: { Origin: o } }), 'access-control-allow-origin'), null, o);
    }
  });
  await t('관리자 라우트에는 사용자 오리진이어도 CORS 가 없다', async () => {
    for (const [p, m] of [['/cia/rps', 'GET'], ['/cia/admin/relay', 'POST'], ['/cia/admin/registry', 'GET']]) {
      assert.equal(h(await pre(p, USER, m, 'content-type,x-cia-admin-secret'), 'access-control-allow-origin'), null, p);
      assert.equal(h(await fetch(`${cia.base}${p}`, { method: m, headers: { Origin: USER } }), 'access-control-allow-origin'), null, p);
    }
  });
  await t('/cia/revoke 의 scope=session 사용자 서명 경로는 CORS 를 타고(400 bad user signature), 관리자 헤더가 실린 교차 요청은 프리플라이트가 막는다', async () => {
    const r = await fetch(`${cia.base}/cia/revoke`, { method: 'POST', headers: { Origin: USER, 'Content-Type': 'application/json' }, body: JSON.stringify({ uid: '12345', scope: 'session', Cf_s: '1', sig_u: { R8x: '1', R8y: '1', S: '1' }, nonce: '1' }) });
    assert.equal(h(r, 'access-control-allow-origin'), USER); assert.ok([400, 404].includes(r.status));
    const p = await pre('/cia/revoke', USER, 'POST', 'content-type,x-cia-admin-secret');
    // cors 패키지는 요청한 헤더를 그대로 돌려주지 않고 설정값(Content-Type)만 돌려준다 — 브라우저가 x-cia-admin-secret 을 거절한다.
    assert.ok(!(h(p, 'access-control-allow-headers') ?? '').toLowerCase().includes('x-cia-admin-secret'));
  });
} finally { await cia.stop(); }
process.exit(fails ? 1 : 0);
```

- [ ] **Step 2: 실패 확인** — `node tests/test_cia_cors.mjs` → 첫 케이스 FAIL(ACAO null).

- [ ] **Step 3: 구현** — `cia.js`:

```js
import cors from 'cors';   // 상단 import 들 사이
// … ADMIN_SECRET 선언 바로 아래:
// 사용자 오리진(web 모드 사용자 페이지 또는 에이전트, 스펙 2026-10-15 §5.3). health 의 허용 목록과 아래 userCors 가 같은 값을 쓴다.
const WALLET_AGENT_ORIGIN = process.env.MODE3_WALLET_AGENT_ORIGIN || 'http://127.0.0.1:5100';
// 사용자 페이지가 브라우저에서 직접 부르는 라우트에만 연다(계획 2026-10-15 Task 6). 관리자 헤더는 허용 목록에 없다 —
// 교차 오리진에서 관리자 경로를 부를 수 없다(관리자 페이지는 같은 오리진 /admin 이다). 문자열이 아니라 함수형 origin 이어야
// 일치할 때만 헤더가 붙는다(에이전트의 loginCors 와 같은 이유).
const userCors = cors({ origin: (origin, cb) => cb(null, origin === WALLET_AGENT_ORIGIN), methods: ['GET', 'POST'], allowedHeaders: ['Content-Type'] });
```
그리고 `app.use(express.json(...))` 바로 뒤에 `for (const p of ['/cia/register', '/cia/issue', '/cia/slot', '/cia/revoke', '/cia/account/self_revoke']) app.options(p, userCors);`, 각 라우트 선언에 미들웨어: `app.post('/cia/register', userCors, async (req, res) => …` (5개 POST), `app.get('/cia/public_keys', userCors, …)`, `app.get('/cia/attr_schema', userCors, …)`. 414행의 기존 `const WALLET_AGENT_ORIGIN = …` 는 지운다(위로 올렸다).

- [ ] **Step 4: 통과 확인** — `node tests/test_cia_cors.mjs` 5개 ok. 회귀: `node tests/test_cia_register_issue.mjs`, `node tests/test_mode3_health.mjs`.
- [ ] **Step 5: CHAIN 배열 `tests/test_cia_startup.mjs` 다음에 `tests/test_cia_cors.mjs` 추가. 커밋** — `feat(cia): 사용자 오리진 CORS — register·issue·slot·revoke·self_revoke·public_keys·attr_schema`.

---

### Task 7: RP 릴레이 `POST /api/mode3/relay` (스펙 §5.1, R6)

**Files:**
- Modify: `mode3_rp.js` (import `cors`, `walletInterface`·`FACTORY_ABI` 는 이미 import 되어 있는 것을 확인하고 없으면 추가; 라우트 2개; env 2개)
- Test: `tests/test_mode3_rp_relay.mjs` (chain)

**Interfaces:**
- Produces:
  - env `MODE3_RELAY_GAS_CAP`(기본 `1200000`), `MODE3_RELAY_RATE`(기본 `10`, 계정당 분당). 빈 문자열은 기본값(`||`).
  - `POST /api/mode3/relay` 본문 `{ to: address, data: hex, value?: '0' }`. CORS 는 `WALLET_ORIGIN`(함수형 origin, POST·GET, `Content-Type`)에만, `app.options` 프리플라이트 포함. 검사 순서와 응답(모두 `{ ok:false, reason, detail? }` 봉투 — 다른 `/api/mode3/*` 와 같다):
    1. `!verifier || !reg.factoryAddress` → 503 `relay_inactive`(detail: `inactiveReason()` 또는 `'no_factory'`)
    2. `value` 가 있고 `String(value) !== '0'` → 400 `relay_bad_calldata`(detail `'value'`); `to` 가 주소가 아니거나 `data` 가 hex 가 아님 → 400 `relay_bad_calldata`(detail `'format'`)
    3. `decodeExecuteCalldata(data)` 가 null 이거나 `pub.length !== 33` → 400 `relay_bad_calldata`(detail `'selector'`); `pub[PUB_INDEX.ARID] !== String(reg.arid)` → 400 `relay_bad_calldata`(detail `'arid'`)
    4. `factory.computeAddress(BigInt(pub[PUB_INDEX.PPID]))` 가 `to` 와(소문자 비교) 다름 → 400 `relay_bad_target`
    5. 속도 제한: 키 `to.toLowerCase()`, 지난 60초의 성공·실패 호출 수가 `RELAY_RATE` 이상 → 429 `relay_rate_limited`. **여기까지 통과한 호출을 지금 센다**(아래 체인 작업 전에).
    6. `provider.getCode(to) === '0x'` 면 `factory.connect(relayer).deploy(ppid)` 를 보내고 `wait()`.
    7. `provider.estimateGas({ from: relayerAddress, to, data })` — revert 면 400 `relay_gas`(detail = `walletInterface.parseError(e.data)?.name ?? e.shortMessage ?? e.message`, 예 `NonceMismatch`·`InvalidProof`·`BadSignature`); 추정치 > `RELAY_GAS_CAP` 이면 400 `relay_gas`(detail `gas N > cap M`).
    8. `relayer.sendTransaction({ to, data, gasLimit: min(gas * 12n / 10n, RELAY_GAS_CAP) })` → 200 `{ ok:true, txHash, deployed, deployTxHash }`. 기다리지 않는다(페이지가 영수증을 본다).
    9. 그 밖 예외 → 500 `{ ok:false, reason:'internal', detail }`.
  - `GET /api/mode3/relay/:txHash`(같은 CORS) → 형식 틀리면 400 `malformed`; 영수증 없으면 200 `{ ok:true, pending:true }`; 있으면 `{ ok:true, pending:false, status, blockNumber, gasUsed, to }`.
- Consumes: `lib/mode3_onchain.js` 의 `decodeExecuteCalldata`·`PUB_INDEX`·`walletInterface`·`FACTORY_ABI`(모두 이미 export).

- [ ] **Step 1: 실패하는 테스트**

```js
// tests/test_mode3_rp_relay.mjs — RP 릴레이(스펙 2026-10-15 §5.1, 계획 R6): 양성 1 + 음성 6(비활성·대상·셀렉터·arid·가스 상한·속도 제한)·CORS.
// file 모드 에이전트의 /wallet/tx/prepare 가 만든 진짜 calldata 를 쓴다. :8545 와 build/mode3 필요. (chain)
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { walletInterface, decodeExecuteCalldata, parseExecuteReceipt, factoryAt, FACTORY_ABI } from '../lib/mode3_onchain.js';

const stack = await startIsolatedMode3Stack({ autoRelay: true });
const { wallet, rp, cia } = stack;
const provider = getProvider();
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.message); } }
const relay = (body, origin = wallet.origin) => rp.post('/api/mode3/relay', body, { Origin: origin });
const relayRaw = (body, headers = {}) => rp.raw('/api/mode3/relay', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: wallet.origin, ...headers }, body: JSON.stringify(body) });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitReceipt(hash) { for (let i = 0; i < 60; i++) { const r = await provider.getTransactionReceipt(hash); if (r) return r; await sleep(300); } throw new Error('영수증 없음 ' + hash); }
try {
  // 준비: 등록 → RP 챌린지 → 에이전트 로그인 → RP 로그인 → 세션 r_s. (test_mode3_demo_stack.mjs 의 로그인 각본과 같다)
  assert.equal((await wallet.post('/wallet/register', { uid: '12345', pwd: 'password123' })).status, 201);
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const ch = (await rp.post('/api/mode3/challenge')).body;
  const lg = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, factoryAddress: info.factoryAddress, attrGateAddress: info.attrGateAddress }, { Origin: rp.origin });
  assert.equal(lg.status, 200, JSON.stringify(lg.body));
  assert.equal((await rp.post('/api/mode3/login', { proof: lg.body.proof, publicSignals: lg.body.publicSignals, sig: lg.body.sig, r_s: ch.r_s })).body.ok, true);
  const prepare = (extra = {}) => wallet.post('/wallet/tx/prepare', { r_s: ch.r_s, to: '0x000000000000000000000000000000000000dEaD', value: '0', data: '0x', ...extra });
  const factory = factoryAt(info.factoryAddress, provider);

  await t('양성: 첫 execute — 릴레이어가 계정을 배포하고 보낸다, 영수증에 Executed·Mode3Auth', async () => {
    const p = await prepare(); assert.equal(p.status, 200, JSON.stringify(p.body)); assert.equal(p.body.deployNeeded, true);
    const r = await relay({ to: p.body.walletAddr, data: p.body.calldata });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.ok, true); assert.equal(r.body.deployed, true); assert.match(r.body.deployTxHash, /^0x[0-9a-f]{64}$/);
    const rc = await waitReceipt(r.body.txHash);
    assert.equal(rc.status, 1); const parsed = parseExecuteReceipt(rc, p.body.walletAddr); assert.equal(parsed.executed.success, true); assert.ok(parsed.auth);
    const st = (await rp.get(`/api/mode3/relay/${r.body.txHash}`)).body; assert.equal(st.pending, false); assert.equal(st.status, 1);
    assert.equal((await rp.get('/api/mode3/relay/0xzz')).status, 400);
    assert.equal((await rp.get(`/api/mode3/relay/0x${'11'.repeat(32)}`)).body.pending, true);
  });
  await t('양성 2: 두 번째 execute 는 배포 없이(deployed:false), 영수증 성공', async () => {
    const p = await prepare(); assert.equal(p.body.deployNeeded, false);
    const r = await relay({ to: p.body.walletAddr, data: p.body.calldata });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.deployed, false);
    assert.equal((await waitReceipt(r.body.txHash)).status, 1);
  });
  await t('음성: value 가 0 이 아니면·to 가 주소가 아니면·data 가 hex 가 아니면 400 relay_bad_calldata', async () => {
    const p = (await prepare()).body;
    for (const b of [{ to: p.walletAddr, data: p.calldata, value: '1' }, { to: 'nope', data: p.calldata }, { to: p.walletAddr, data: 'zz' }]) { const r = await relay(b); assert.equal(r.status, 400, JSON.stringify(b).slice(0, 60)); assert.equal(r.body.reason, 'relay_bad_calldata'); }
  });
  await t('음성: execute 가 아닌 calldata(팩토리 deploy)·pub[1]≠arid 는 relay_bad_calldata', async () => {
    const p = (await prepare()).body;
    const deployData = new ethers.Interface(FACTORY_ABI).encodeFunctionData('deploy', [1n]);
    let r = await relay({ to: p.walletAddr, data: deployData }); assert.equal(r.status, 400); assert.equal(r.body.reason, 'relay_bad_calldata'); assert.equal(r.body.detail, 'selector');
    const dec = decodeExecuteCalldata(p.calldata);
    const pub = dec.pub.map(BigInt); pub[1] += 1n;
    const tampered = walletInterface.encodeFunctionData('execute', [dec.payload, dec.sig, dec.a.map(BigInt), dec.b.map((row) => row.map(BigInt)), dec.c.map(BigInt), pub]);
    r = await relay({ to: p.walletAddr, data: tampered }); assert.equal(r.status, 400); assert.equal(r.body.reason, 'relay_bad_calldata'); assert.equal(r.body.detail, 'arid');
  });
  await t('음성: to 가 pub[0](PPID) 의 계정 주소가 아니면 relay_bad_target', async () => {
    const p = (await prepare()).body;
    const other = await factory.computeAddress(BigInt(decodeExecuteCalldata(p.calldata).pub[0]) + 1n);
    const r = await relay({ to: other, data: p.calldata }); assert.equal(r.status, 400); assert.equal(r.body.reason, 'relay_bad_target');
  });
  await t('음성: 이미 쓴 nonce 의 calldata 를 다시 보내면 estimateGas 가 revert — 400 relay_gas, detail 에 NonceMismatch', async () => {
    const p = (await prepare()).body;
    const ok = await relay({ to: p.walletAddr, data: p.calldata }); assert.equal(ok.status, 200); await waitReceipt(ok.body.txHash);
    const again = await relay({ to: p.walletAddr, data: p.calldata }); assert.equal(again.status, 400); assert.equal(again.body.reason, 'relay_gas'); assert.match(String(again.body.detail), /NonceMismatch/);
  });
  await t('CORS: 사용자 오리진에만 ACAO(프리플라이트·실제), 다른 오리진은 없음', async () => {
    const pre = await rp.raw('/api/mode3/relay', { method: 'OPTIONS', headers: { Origin: wallet.origin, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' } });
    assert.equal(pre.headers.get('access-control-allow-origin'), wallet.origin);
    const real = await relayRaw({ to: 'x', data: 'y' }); assert.equal(real.headers.get('access-control-allow-origin'), wallet.origin);
    const bad = await relayRaw({ to: 'x', data: 'y' }, { Origin: 'http://evil.example' }); assert.equal(bad.headers.get('access-control-allow-origin'), null);
  });
  await t('음성: 가스 상한(MODE3_RELAY_GAS_CAP=100000) 아래로 재기동하면 relay_gas(cap)', async () => {
    await stack.restartRp({ MODE3_RELAY_GAS_CAP: '100000' });
    const p = (await prepare()).body;
    const r = await relay({ to: p.walletAddr, data: p.calldata }); assert.equal(r.status, 400); assert.equal(r.body.reason, 'relay_gas'); assert.match(String(r.body.detail), /cap/);
  });
  await t('음성: 속도 제한(MODE3_RELAY_RATE=1) — 같은 계정의 두 번째 호출은 429, 실패한 호출도 센다', async () => {
    await stack.restartRp({ MODE3_RELAY_GAS_CAP: '', MODE3_RELAY_RATE: '1' });
    const p = (await prepare()).body;
    const first = await relay({ to: p.walletAddr, data: p.calldata }); assert.equal(first.status, 200, JSON.stringify(first.body)); await waitReceipt(first.body.txHash);
    const second = await relay({ to: p.walletAddr, data: (await prepare()).body.calldata }); assert.equal(second.status, 429); assert.equal(second.body.reason, 'relay_rate_limited');
  });
  await t('음성: 검증기가 없으면(팩토리 상수 조회 실패) 503 relay_inactive — 마지막 케이스(env 누적)', async () => {
    await stack.restartRp({ MODE3_RELAY_RATE: '', MODE3_RP_FACTORY_ADDRESS: cia.logAddress }, { waitActive: false });
    await sleep(1500);
    const r = await relay({ to: ethers.ZeroAddress, data: '0x' }); assert.equal(r.status, 503); assert.equal(r.body.reason, 'relay_inactive');
  });
} finally { await stack.stop(); }
process.exit(fails ? 1 : 0);
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_rp_relay.mjs` → 양성 케이스 FAIL(404 — 라우트 없음).

- [ ] **Step 3: 구현** — `mode3_rp.js` 의 `/api/mode3/request` 라우트 다음에:

```js
// ---- 릴레이(설계 2026-10-15 §5.1, 계획 R6): 브라우저 사용자 페이지의 execute 를 RP 의 릴레이어 계정이 대신 보낸다 ----
// 릴레이어는 서명만 한다 — 사용자 비밀을 보지 않는다. 검열(거부·지연) 가능성은 런북의 한계에 적는다.
// 검사 순서: 활성 → 본문 형식(value 0 고정) → execute 셀렉터·pub 33·pub[1]=arid → to = computeAddress(pub[0]) → 속도 제한 → (코드 없으면 deploy) → estimateGas ≤ cap → 전송.
const RELAY_GAS_CAP = BigInt(process.env.MODE3_RELAY_GAS_CAP || 1_200_000);
const RELAY_RATE = Number(process.env.MODE3_RELAY_RATE || 10);     // 계정당 분당
const relayCors = cors({ origin: (origin, cb) => cb(null, origin === WALLET_ORIGIN), methods: ['POST', 'GET'], allowedHeaders: ['Content-Type'] });
app.options('/api/mode3/relay', relayCors);
const relayHits = new Map();   // to(소문자) → [ms, …] 지난 60초
const isAddr = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
const revertName = (e) => { try { const n = e?.data ? walletInterface.parseError(e.data)?.name : null; if (n) return n; } catch { /* 모르는 에러 */ } return e?.revert?.name ?? e?.shortMessage ?? e?.message ?? 'revert'; };
app.post('/api/mode3/relay', relayCors, async (req, res) => {
  try {
    if (!verifier || !reg.factoryAddress) return res.status(503).json({ ok: false, reason: 'relay_inactive', detail: verifier ? 'no_factory' : inactiveReason() });
    const { to, data, value } = req.body ?? {};
    if (value !== undefined && String(value) !== '0') return res.status(400).json({ ok: false, reason: 'relay_bad_calldata', detail: 'value' });
    if (!isAddr(to) || typeof data !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(data)) return res.status(400).json({ ok: false, reason: 'relay_bad_calldata', detail: 'format' });
    const dec = decodeExecuteCalldata(data);
    if (!dec || dec.pub.length !== PUB_INDEX.COUNT) return res.status(400).json({ ok: false, reason: 'relay_bad_calldata', detail: 'selector' });
    if (dec.pub[PUB_INDEX.ARID] !== String(reg.arid)) return res.status(400).json({ ok: false, reason: 'relay_bad_calldata', detail: 'arid' });
    const factory = new ethers.Contract(reg.factoryAddress, FACTORY_ABI, provider);
    const ppid = BigInt(dec.pub[PUB_INDEX.PPID]);
    const expected = await factory.computeAddress(ppid);
    if (expected.toLowerCase() !== to.toLowerCase()) return res.status(400).json({ ok: false, reason: 'relay_bad_target' });
    const key = to.toLowerCase(), now = Date.now();
    const hits = (relayHits.get(key) ?? []).filter((t) => now - t < 60_000);
    if (hits.length >= RELAY_RATE) { relayHits.set(key, hits); return res.status(429).json({ ok: false, reason: 'relay_rate_limited' }); }
    hits.push(now); relayHits.set(key, hits);
    const relayer = await provider.getSigner(RELAYER_INDEX);
    let deployTxHash = null;
    if ((await provider.getCode(to)) === '0x') { const dtx = await factory.connect(relayer).deploy(ppid); await dtx.wait(); deployTxHash = dtx.hash; }
    let gas;
    try { gas = await provider.estimateGas({ from: await relayer.getAddress(), to, data }); }
    catch (e) { return res.status(400).json({ ok: false, reason: 'relay_gas', detail: revertName(e) }); }
    if (gas > RELAY_GAS_CAP) return res.status(400).json({ ok: false, reason: 'relay_gas', detail: `gas ${gas} > cap ${RELAY_GAS_CAP}` });
    const gasLimit = (gas * 12n) / 10n > RELAY_GAS_CAP ? RELAY_GAS_CAP : (gas * 12n) / 10n;
    const tx = await relayer.sendTransaction({ to, data, gasLimit });
    res.json({ ok: true, txHash: tx.hash, deployed: Boolean(deployTxHash), deployTxHash });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});
app.get('/api/mode3/relay/:txHash', relayCors, async (req, res) => {
  try {
    const { txHash } = req.params;
    if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) return res.status(400).json({ ok: false, reason: 'malformed' });
    const rc = await provider.getTransactionReceipt(txHash);
    if (!rc) return res.json({ ok: true, pending: true });
    res.json({ ok: true, pending: false, status: rc.status, blockNumber: rc.blockNumber, gasUsed: rc.gasUsed.toString(), to: rc.to });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});
```
`import cors from 'cors';` 를 상단에 더하고, `lib/mode3_onchain.js` import 에 `walletInterface` 가 빠져 있으면 더한다(`decodeExecuteCalldata`·`PUB_INDEX`·`FACTORY_ABI` 는 이미 있다). `/mode3/health` 의 `buildRpHealth` 는 바꾸지 않는다.

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_rp_relay.mjs` 10개 ok(격리 스택 기동 포함 2~3분). 회귀: `node tests/test_mode3_rp.mjs`.
- [ ] **Step 5: CHAIN 배열 `tests/test_mode3_rp.mjs` 다음에 `tests/test_mode3_rp_relay.mjs` 추가. 커밋** — `feat(rp): POST /api/mode3/relay — 사용자 오리진의 execute 를 릴레이어가 배포·전송(검사 6단계·속도 제한)`.

---
### Task 8: 사용자 코어 `mode3/user/core/` — DOM 없는 에이전트 등가물 (Node 에서 chain 테스트)

**Files:**
- Create: `mode3/user/core/kv_mem.js`, `mode3/user/core/kv_idb.js`, `mode3/user/core/vault.js`, `mode3/user/core/chain.js`, `mode3/user/core/idp.js`, `mode3/user/core/user_core.js`
- Test: `tests/test_mode3_user_core.mjs` (chain — 격리 IdP·RP(릴레이 포함) + Node 에서 코어를 메모리 kv 로 돌린다; 증명은 진짜 snarkjs)

**Interfaces:**
- `kv` 인터페이스(두 구현 공통): `get(key) → Promise<any|undefined>`, `set(key, value) → Promise<void>`, `del(key)`, `clear()`, `keys()`. `kv_idb.js`: `openIdbKv(name = 'mode3-user', version = 1) → Promise<kv>` — 객체 저장소 `kv`(키 = 문자열). IndexedDB 가 없거나 열기 실패면 `Error{ reason:'storage_unavailable' }`. `kv_mem.js`: `createMemKv() → kv`(Map).
- 저장 키(스펙 §3 — `rcl` 제외(R2), `unlock` 추가(R3)): `meta`, `registration`, `secrets`, `sessions`(객체: r_s → 세션), `txs`(배열), `demo`, `unlock`(`{ key: CryptoKey, expiresAt: ms }`).
- `vault.js`: `createVault(kv, { now = Date.now, ttlMs = UNLOCK_TTL_MS })` → `{ hasVault(), isUnlocked(), setup(password) /*meta 생성+unlock*/, unlock(password) /*bad_password → false*/, lock(), key() /*CryptoKey|null — 만료면 null 로 만들고 레코드 삭제*/, readSecrets() /*{ s_u, sk_u, blind_u, sessionKeys }*/, writeSecrets(obj), changePassword(oldPw, newPw) }`. `UNLOCK_TTL_MS = 30 * 60_000`. 잠겨 있을 때 `readSecrets()`·`writeSecrets()` 는 `Error{ reason:'locked' }`.
- `chain.js`: `createChain({ provider, canonProvider, logAddress, mirrorAddress })` → `{ chainId(), mirrorView(), syncAll() /*에이전트 syncAll 과 같은 모양: { root, regRoot, epoch, head, tree, registry, chainId, mirror:{lastPublishedBlock}, canonical:{ root, regRoot, epoch, tree, registry } }, 실패는 Error{ reason:'chain_unavailable'|'sync_unstable' }*/, accountAddressOf(factoryAddress, PPID) /*캐시*/, head() }`. 동기화는 `syncRevocationTree`·`syncRegistryTree` 전체 재생(R2), head 가 같아질 때까지 3회, 거울이 뒤처지면 `untilEpoch`·`expectRoot` 로 되감기 — `mode3_wallet_agent.js:135-160` 의 규칙 그대로.
- `idp.js`: `createIdp({ ciaUrl, fetch = globalThis.fetch, pinnedPk = null })` → `{ post(path, body) → { status, body }, publicKeys(), pkCia() /*TOFU 메모이즈, 실패면 Error{ reason:'cia_unavailable' }*/, schema() /*{ schema, hash, source }; 실패면 DEFAULT_ATTR_SCHEMA source:'default'*/ }`.
- `user_core.js`: `createUserCore({ kv, config, provider, canonProvider, fetch = globalThis.fetch, fullProve: { idp, cred }, now = Date.now, log = () => {} })` — `config` 는 정적 서버 `/user/config` 본문 모양(`ciaUrl, rpcUrl, revRpcUrl, logAddress, mirrorAddress, ttlBlocks, heightGrid, rpOrigins, pkCia, relayPath, walletOrigin`). 모든 동작은 **에이전트 라우트와 같은 `{ status, body }`** 를 돌려준다(throw 하지 않는다 — 예외는 `{ status: 500, body: { reason:'internal', detail } }`). 잠겨 있으면 `{ status: 423, body: { reason: 'locked' } }`:
  - `status()` ← `/wallet/status`(`demoOverride` 포함, `rcl` 는 null)
  - `health()` → presence 6개 `{ registered, hasCred, sessions, rpCount, txs, disclosedTxs }`(세션 수·rpCount 는 저장 세션에서, txs·disclosedTxs 는 `txs` 배열에서 센다 — 재시작을 넘긴다)
  - `vault` (위 객체 그대로 노출), `wipe()`(kv.clear)
  - `register({ uid, pwd, profile, vaultPassword })` ← `/wallet/register`(file 모드 규칙; 금고가 없으면 `vaultPassword` 로 만들고, 있으면 잠금 해제 상태여야 한다)
  - `saveProfile(profile)` ← `PUT /wallet/profile`
  - `precheck({ arid, origin, cert_s, pk_trace, factoryAddress, r_s })` ← `/wallet/authorize/precheck`(참조 코드 대조 생략 — 스펙 §6)
  - `login(body, { verifiedOrigin })` ← `/wallet/login`(snap 모드의 `verifiedOrigin` 대조 규칙: `verifiedOrigin !== body.origin` → 403 `bad_rp_cert`; witness 없음)
  - `revalidate({ r_s, skipSync, arid, origin })` ← `/wallet/revalidate`(`origin` 은 `sessionMatchesRequester` 의 Origin 헤더 자리)
  - `request({ r_s, body, arid, origin })` ← `/wallet/request`
  - `prepareTx({ r_s, to, value, data, disclose, set })` ← `/wallet/tx/prepare`(+ `demo`)
  - `recordTx({ r_s, txHash, receipt, tx })` ← `/wallet/tx/record` 의 파싱부(영수증·tx 는 호출자가 RPC 로 받아 넘긴다 — 코어는 `provider` 로 직접 받아도 된다: `recordTx({ r_s, txHash })` 가 `provider.getTransactionReceipt/getTransaction` 을 부르고 없으면 202 `{ pending:true }`)
  - `revokeSession({ r_s })` ← `/wallet/session/revoke`, `selfRevoke({ uid, pwd })` ← `/wallet/self_revoke`
  - `demoOverride({ scope, s_u, uid, clear })` ← `/wallet/demo/override`
  - `attrSchema()` ← `/wallet/attr_schema`
- 증명 캐시: 세션마다 `sessions[r_s].proofCache = { key: 'chainId:rev:reg|discKey', proof, publicSignals, revRoot, regRoot }`(IndexedDB 에 남는다 — 팝업·재방문에서도 히트). 메모리 `ProofCache` 는 쓰지 않는다.
- 세션 개인키는 `secrets.sessionKeys[r_s]`(hex)에만. 세션 공개 레코드는 에이전트 세션 레코드에서 `sessionPrivKey`·`witness` 를 뺀 것 + `origin`·`account`(computeAddress 캐시)·`proofCache`.

- [ ] **Step 1: 실패하는 테스트**

```js
// tests/test_mode3_user_core.mjs — 브라우저 사용자 코어를 Node 에서(메모리 kv·진짜 snarkjs) 격리 IdP·RP 에 대고 돌린다. 등록 → 로그인(RP 검증) → 재검증 →
// 세션 요청 → 트랜잭션(RP 릴레이) → Selective disclosure proof(AttrGate) → 세션 폐기 → 잠금·해제 → 시연 가짜 증명·서명. :8545·build/mode3 필요. (chain)
import assert from 'node:assert/strict';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createMemKv } from '../mode3/user/core/kv_mem.js';
import { createUserCore } from '../mode3/user/core/user_core.js';
import { attrGateAt } from '../lib/mode3_onchain.js';
import * as snarkjs from 'snarkjs';

const stack = await startIsolatedMode3Stack({ userMode: 'web', autoRelay: true });
const { wallet, rp, cia } = stack;
const provider = getProvider();
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
try {
  const config = (await wallet.get('/user/config')).body;
  const kv = createMemKv();
  const fullProve = { idp: (input, w, z) => snarkjs.groth16.fullProve(input, w, z), cred: (input, w, z) => snarkjs.groth16.fullProve(input, w, z) };
  const core = createUserCore({ kv, config, provider, canonProvider: provider, fullProve });
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const PW = 'vault-pw-1';
  const loginBody = (ch, extra = {}) => ({ arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, allowAgent: '0', factoryAddress: info.factoryAddress, attrGateAddress: info.attrGateAddress, ...extra });
  const challenge = async () => (await rp.post('/api/mode3/challenge')).body;
  async function relayAndRecord(r_s, p) {
    const r = await rp.post(config.relayPath, { to: p.walletAddr, data: p.calldata }, { Origin: wallet.origin });
    assert.equal(r.status, 200, j(r.body));
    for (let i = 0; i < 60; i++) { const rec = await core.recordTx({ r_s, txHash: r.body.txHash }); if (rec.status !== 202) return { relay: r.body, rec }; await sleep(300); }
    throw new Error('영수증 없음');
  }
  let rs1;

  await t('미등록: status.registered=false, 금고 없음, login 은 409 not_registered', async () => {
    const s = await core.status(); assert.equal(s.status, 200); assert.equal(s.body.registered, false); assert.equal(core.vault.hasVault(), false);
    assert.equal((await core.login(loginBody(await challenge()), { verifiedOrigin: info.origin })).body.reason, 'not_registered');
    assert.deepEqual(await core.health(), { registered: false, hasCred: false, sessions: 0, rpCount: 0, txs: 0, disclosedTxs: 0 });
  });
  await t('등록: 금고를 만들고 IdP 에 등록 — registration 은 평문(공개 부분), secrets 는 암호문, 비밀은 kv 어디에도 평문으로 없다', async () => {
    const r = await core.register({ uid: '12345', pwd: 'password123', profile: { birthYear: '1990', country: 'KR' }, vaultPassword: PW });
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.uid, '12345'); assert.deepEqual(r.body.attrs, ['1990', '410', '0', '0', '0', '0']);
    const reg = await kv.get('registration'); assert.equal(reg.uid, '12345'); assert.ok(!('s_u' in reg) && !('sk_u' in reg));
    const sec = await kv.get('secrets'); assert.ok(sec.iv && sec.ct);
    const secrets = await core.vault.readSecrets(); assert.match(secrets.sk_u, /^[0-9a-f]{64}$/);
    const all = {}; for (const k of await kv.keys()) all[k] = await kv.get(k);
    const dump = j(all); assert.ok(!dump.includes(secrets.s_u) && !dump.includes(secrets.sk_u), '비밀 평문이 kv 어디에도 없다');
    assert.equal((await core.register({ uid: '12345', pwd: 'password123', vaultPassword: PW })).body.reason, 'already_registered');
    assert.equal((await core.health()).registered, true);
  });
  await t('잠금: lock() 뒤 login 은 423 locked, 틀린 비밀번호 unlock false, 맞으면 true', async () => {
    await core.vault.lock(); assert.equal(core.vault.isUnlocked(), false);
    assert.equal((await core.login(loginBody(await challenge()), { verifiedOrigin: info.origin })).status, 423);
    assert.equal(await core.vault.unlock('wrong'), false); assert.equal(await core.vault.unlock(PW), true);
  });
  await t('로그인: π_IdP 발급 → π_RP → RP /api/mode3/login ok; 응답에 비밀·uid 없음; 세션 저장·proofCache 저장·세션키는 secrets 에만', async () => {
    const ch = await challenge(); rs1 = ch.r_s;
    const r = await core.login(loginBody(ch), { verifiedOrigin: info.origin });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.issued, true); assert.ok(r.body.timings.proveMs > 0);
    for (const k of ['s_u', 'sk_u', 'blind_u', 'uid', 'sessionPrivKey', 'witness']) assert.ok(!j(r.body).includes(`"${k}"`), k);
    const v = await rp.post('/api/mode3/login', { proof: r.body.proof, publicSignals: r.body.publicSignals, sig: r.body.sig, r_s: ch.r_s });
    assert.equal(v.body.ok, true, j(v.body));
    const sessions = await kv.get('sessions'); const s = sessions[ch.r_s];
    assert.equal(s.origin, info.origin); assert.ok(s.proofCache?.proof); assert.ok(!('sessionPrivKey' in s)); assert.match(s.account, /^0x[0-9a-fA-F]{40}$/);
    assert.ok((await core.vault.readSecrets()).sessionKeys[ch.r_s]);
    assert.deepEqual(await core.health(), { registered: true, hasCred: true, sessions: 1, rpCount: 1, txs: 0, disclosedTxs: 0 });
  });
  await t('로그인 거절: verifiedOrigin 이 인증서 오리진과 다르면 403 bad_rp_cert, 같은 r_s 재사용은 409 duplicate_session', async () => {
    assert.equal((await core.login(loginBody(await challenge()), { verifiedOrigin: 'http://evil.example' })).body.reason, 'bad_rp_cert');
    assert.equal((await core.login(loginBody({ r_s: rs1, r_rp: '1' }), { verifiedOrigin: info.origin })).body.reason, 'duplicate_session');
  });
  await t('재검증: 캐시 히트(cacheHit:true) → RP ok; 다른 오리진·다른 arid 로는 404 no_session', async () => {
    const r = await core.revalidate({ r_s: rs1, origin: info.origin }); assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.cacheHit, true);
    assert.equal((await rp.post('/api/mode3/revalidate', { proof: r.body.proof, publicSignals: r.body.publicSignals, sig: r.body.sig, r_s: rs1 })).body.ok, true);
    assert.equal((await core.revalidate({ r_s: rs1, origin: 'http://other.example' })).status, 404);
    assert.equal((await core.revalidate({ r_s: rs1, origin: info.origin, arid: String(BigInt(info.arid) + 1n) })).status, 404);
  });
  await t('세션 요청: 세션키 서명 → RP /api/mode3/request ok', async () => {
    const r = await core.request({ r_s: rs1, body: 'hello', origin: info.origin }); assert.equal(r.status, 200);
    assert.equal((await rp.post('/api/mode3/request', { r_s: rs1, body: 'hello', sig: r.body.sig })).body.ok, true);
  });
  await t('트랜잭션: prepareTx → RP 릴레이(배포 포함) → recordTx 영수증 파싱 ok, txs 기록·health 카운터', async () => {
    const p = await core.prepareTx({ r_s: rs1, to: '0x000000000000000000000000000000000000dEaD', value: '0', data: '0x' });
    assert.equal(p.status, 200, j(p.body)); assert.equal(p.body.deployNeeded, true);
    const { relay, rec } = await relayAndRecord(rs1, p.body);
    assert.equal(relay.deployed, true); assert.equal(rec.status, 200, j(rec.body)); assert.equal(rec.body.ok, true); assert.equal(rec.body.executed.success, true);
    assert.equal((await kv.get('txs')).length, 1); assert.equal((await core.health()).txs, 1);
  });
  await t('Selective disclosure proof: 나이·국가 집합 조건을 실어 AttrGate.claim → claimed(account) true, disclosedTxs 1', async () => {
    const year = new Date().getUTCFullYear();
    const p = await core.prepareTx({ r_s: rs1, to: info.attrGateAddress, value: '0', data: '0x4e71d92d', disclose: [{ lo: '1900', hi: String(year - Number(info.predicates.minAge)) }], set: { slot: 1, members: info.predicates.allowedCountries } });
    assert.equal(p.status, 200, j(p.body)); assert.equal(p.body.cacheHit, false, '술어가 있으면 새 증명');
    const { rec } = await relayAndRecord(rs1, p.body); assert.equal(rec.body.ok, true);
    assert.equal(await attrGateAt(info.attrGateAddress, provider).claimed(p.body.walletAddr), true);
    assert.equal((await core.health()).disclosedTxs, 1);
  });
  await t('불만족 조건은 증명 전에 400 disclosure_unsatisfiable; 모르는 세션은 404', async () => {
    assert.equal((await core.prepareTx({ r_s: rs1, to: '0x000000000000000000000000000000000000dEaD', disclose: [{ lo: '2000', hi: '2001' }] })).body.reason, 'disclosure_unsatisfiable');
    assert.equal((await core.prepareTx({ r_s: '7', to: '0x000000000000000000000000000000000000dEaD' })).status, 404);
  });
  await t('시연 fake_proof: 다음 로그인의 증명만 바꿔친다 → RP bad_proof, demo 플래그; 그 다음 로그인은 정상', async () => {
    assert.equal((await core.demoOverride({ scope: 'fake_proof' })).status, 200);
    const ch = await challenge(); const r = await core.login(loginBody(ch), { verifiedOrigin: info.origin });
    assert.equal(r.status, 200); assert.equal(r.body.demo, 'override:fake_proof');
    assert.equal((await rp.post('/api/mode3/login', { proof: r.body.proof, publicSignals: r.body.publicSignals, sig: r.body.sig, r_s: ch.r_s })).body.reason, 'bad_proof');
    const ch2 = await challenge(); const r2 = await core.login(loginBody(ch2), { verifiedOrigin: info.origin });
    assert.equal((await rp.post('/api/mode3/login', { proof: r2.body.proof, publicSignals: r2.body.publicSignals, sig: r2.body.sig, r_s: ch2.r_s })).body.ok, true);
  });
  await t('시연 fake_sig: 다음 트랜잭션 서명만 가짜 → 릴레이 estimateGas 가 BadSignature 로 거절(relay_gas)', async () => {
    assert.equal((await core.demoOverride({ scope: 'fake_sig' })).status, 200);
    const p = await core.prepareTx({ r_s: rs1, to: '0x000000000000000000000000000000000000dEaD' }); assert.equal(p.body.demo, 'override:fake_sig');
    const r = await rp.post(config.relayPath, { to: p.body.walletAddr, data: p.body.calldata }, { Origin: wallet.origin });
    assert.equal(r.status, 400); assert.equal(r.body.reason, 'relay_gas'); assert.match(String(r.body.detail), /BadSignature/);
  });
  await t('세션 폐기: IdP 에 서명 요청 → 세션·세션키·캐시 삭제, 다음 게시 뒤 재검증은 세션 없음', async () => {
    const r = await core.revokeSession({ r_s: rs1 }); assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.revoked, true);
    assert.equal((await kv.get('sessions'))[rs1], undefined); assert.equal((await core.vault.readSecrets()).sessionKeys[rs1], undefined);
    assert.equal((await core.revalidate({ r_s: rs1, origin: info.origin })).status, 404);
  });
  await t('속성 변경: 바뀌면 userCred·세션·캐시를 버린다(다음 로그인이 새 C_u), 같으면 changed:false', async () => {
    const same = await core.saveProfile({ birthYear: '1990', country: 'KR' }); assert.equal(same.body.changed, false);
    const diff = await core.saveProfile({ birthYear: '1991', country: 'KR' }); assert.equal(diff.body.changed, true);
    assert.equal((await kv.get('registration')).userCred, null); assert.deepEqual(await kv.get('sessions'), {});
    const ch = await challenge(); const r = await core.login(loginBody(ch), { verifiedOrigin: info.origin }); assert.equal(r.status, 200, j(r.body)); assert.ok(r.body.timings.userCredMs > 0, '새 C_u');
  });
  await t('비밀번호 변경·자동 잠금: changePassword 뒤 옛 비밀번호는 false, 새 것은 true; ttl 이 지나면 key() 가 null', async () => {
    assert.equal(await core.vault.changePassword(PW, 'pw-2'), true); await core.vault.lock();
    assert.equal(await core.vault.unlock(PW), false); assert.equal(await core.vault.unlock('pw-2'), true);
    const u = await kv.get('unlock'); await kv.set('unlock', { ...u, expiresAt: Date.now() - 1 });
    assert.equal(await core.vault.key(), null); assert.equal(await kv.get('unlock'), undefined);
  });
  await t('wipe(): 전부 지운다 — 금고 없음·미등록', async () => { await core.wipe(); assert.equal(core.vault.hasVault(), false); assert.equal((await core.status()).body.registered, false); });
} finally { await stack.stop(); }
process.exit(fails ? 1 : 0);
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_user_core.mjs` → `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: 저장소·금고 구현**

```js
// mode3/user/core/kv_mem.js — 메모리 키-값(테스트·IndexedDB 없는 환경의 대체). kv 계약: get/set/del/clear/keys 전부 Promise.
export function createMemKv() {
  const m = new Map();
  return { async get(k) { return m.get(k); }, async set(k, v) { m.set(k, v); }, async del(k) { m.delete(k); }, async clear() { m.clear(); }, async keys() { return [...m.keys()]; } };
}
```
```js
// mode3/user/core/kv_idb.js — IndexedDB `mode3-user`(v1) 의 객체 저장소 `kv` 하나에 { key, value } 를 둔다(스펙 2026-10-15 §3). CryptoKey(추출 불가)도 그대로 저장된다(계획 R3).
const req = (r) => new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
export async function openIdbKv(name = 'mode3-user', version = 1) {
  if (typeof indexedDB === 'undefined') throw Object.assign(new Error('IndexedDB 없음'), { reason: 'storage_unavailable' });
  let db;
  try {
    const open = indexedDB.open(name, version);
    open.onupgradeneeded = () => { if (!open.result.objectStoreNames.contains('kv')) open.result.createObjectStore('kv'); };
    db = await req(open);
  } catch (e) { throw Object.assign(new Error(`IndexedDB 열기 실패: ${e?.message ?? e}`), { reason: 'storage_unavailable' }); }
  const tx = (mode) => db.transaction('kv', mode).objectStore('kv');
  return {
    get: (k) => req(tx('readonly').get(k)),
    set: (k, v) => req(tx('readwrite').put(v, k)).then(() => {}),
    del: (k) => req(tx('readwrite').delete(k)).then(() => {}),
    clear: () => req(tx('readwrite').clear()).then(() => {}),
    keys: () => req(tx('readonly').getAllKeys()),
  };
}
```
```js
// mode3/user/core/vault.js — 비밀 금고(스펙 D1·§3, 계획 R3). meta(공개)·secrets(암호문)·unlock(추출 불가 CryptoKey + 만료) 세 레코드.
import { createMeta, openMeta, deriveKey, randomSaltHex, makeCheck, encryptJson, decryptJson, KDF_ITERATIONS } from '../../../lib/browser/secret_box.js';
export const UNLOCK_TTL_MS = 30 * 60_000;
const EMPTY_SECRETS = () => ({ s_u: null, sk_u: null, blind_u: null, sessionKeys: {} });
const locked = () => Object.assign(new Error('locked'), { reason: 'locked' });
export function createVault(kv, { now = Date.now, ttlMs = UNLOCK_TTL_MS } = {}) {
  let meta = null;   // meta 는 kv 에서 읽어 메모리에 둔다(공개값). unlock 은 **매번 kv 에서** 읽는다 — 팝업·다른 탭이 지우거나 바꾼 것을 바로 보기 위해(R3).
  const load = async () => { if (meta === null) meta = (await kv.get('meta')) ?? false; return meta || null; };
  const v = {
    async hasVault() { return Boolean(await load()); },
    async key() {
      const u = (await kv.get('unlock')) ?? null;
      if (!u) return null;
      if (!(u.expiresAt > now())) { await kv.del('unlock'); return null; }
      return u.key;
    },
    async isUnlocked() { return (await v.key()) !== null; },
    async setup(password) {
      if (await load()) throw new Error('이미 금고가 있다');
      const { meta: m, key } = await createMeta(password);
      await kv.set('meta', m); meta = m;
      await kv.set('secrets', await encryptJson(key, EMPTY_SECRETS()));
      await v._remember(key);
      return true;
    },
    async unlock(password) {
      const m = await load(); if (!m) return false;
      const key = await openMeta(password, m); if (!key) return false;
      await v._remember(key); return true;
    },
    async _remember(key) { await kv.set('unlock', { key, expiresAt: now() + ttlMs }); },
    async lock() { await kv.del('unlock'); },
    async readSecrets() { const key = await v.key(); if (!key) throw locked(); const box = await kv.get('secrets'); return box ? await decryptJson(key, box) : EMPTY_SECRETS(); },
    async writeSecrets(obj) { const key = await v.key(); if (!key) throw locked(); await kv.set('secrets', await encryptJson(key, obj)); },
    async changePassword(oldPw, newPw) {
      const m = await load(); if (!m) return false;
      const oldKey = await openMeta(oldPw, m); if (!oldKey) return false;
      const plain = await decryptJson(oldKey, (await kv.get('secrets')) ?? await encryptJson(oldKey, EMPTY_SECRETS()));
      const salt = randomSaltHex(); const key = await deriveKey(newPw, salt);
      const nm = { ...m, kdf: { salt, iterations: KDF_ITERATIONS }, check: await makeCheck(key) };
      await kv.set('secrets', await encryptJson(key, plain)); await kv.set('meta', nm); meta = nm;
      await v._remember(key); return true;
    },
    /** wipe 뒤 메모리도 비운다 — user_core.wipe() 가 부른다. */
    reset() { meta = null; },
  };
  return v;
}
```

- [ ] **Step 4: 체인·IdP 모듈**

```js
// mode3/user/core/chain.js — 거울 뷰 동기화(V10 규칙, mode3_wallet_agent.js syncAll 과 같다). 증분 체크포인트는 없다(계획 R2): 두 트리를 창세기부터 재생한다.
import { ethers } from 'ethers';
import { syncRevocationTree, syncRegistryTree } from '../../../lib/mode3_wallet.js';
import { MODE3_ROOTS_ABI } from '../../../lib/mode3_log.js';
import { factoryAt } from '../../../lib/mode3_onchain.js';
const tagged = (reason, msg) => Object.assign(new Error(msg ?? reason), { reason });
export function createChain({ provider, canonProvider = provider, logAddress, mirrorAddress }) {
  const mirror = mirrorAddress ? new ethers.Contract(mirrorAddress, MODE3_ROOTS_ABI, provider) : null;
  let chainIdCache = null; const acct = new Map();
  const missing = () => (!logAddress ? 'CIA_LOG_ADDRESS not configured' : !mirrorAddress ? 'MODE3_MIRROR_ADDRESS not configured' : null);
  const c = {
    async chainId() { if (chainIdCache === null) chainIdCache = (await provider.getNetwork()).chainId; return chainIdCache; },
    async head() { return BigInt(await provider.getBlockNumber()); },
    async mirrorView() {
      const head = await c.head(); const blockTag = Number(head);
      const [revRoot, regRoot, epoch, last] = await Promise.all([mirror.revRoot({ blockTag }), mirror.regRoot({ blockTag }), mirror.epoch({ blockTag }), mirror.lastPublishedBlock({ blockTag })]);
      return { root: BigInt(revRoot), regRoot: BigInt(regRoot), epoch: BigInt(epoch), head, lastPublishedBlock: BigInt(last) };
    },
    /** 에이전트 syncAll 과 같은 반환 모양. RPC 실패는 chain_unavailable, 거울·캐노니컬 불일치는 sync_unstable 로 태그한다. */
    async syncAll() {
      const m = missing(); if (m) throw tagged('chain_unavailable', m);
      let mv, rev = null, reg = null;
      try {
        mv = await c.mirrorView();
        for (let i = 0; i < 3; i++) { rev = await syncRevocationTree(canonProvider, logAddress); reg = await syncRegistryTree(canonProvider, logAddress); if (BigInt(rev.head) === BigInt(reg.head)) break; rev = null; }
      } catch (e) { if (e.reason) throw e; throw tagged('chain_unavailable', e.shortMessage ?? e.message); }
      if (!rev) throw tagged('sync_unstable');
      const canonical = { root: rev.root, regRoot: reg.root, epoch: reg.epoch, tree: rev.tree, registry: reg.tree };
      if (mv.epoch > canonical.epoch) throw tagged('sync_unstable', `거울 epoch(${mv.epoch}) 가 캐노니컬 epoch(${canonical.epoch}) 보다 앞서 있다`);
      let tree = rev.tree, registry = reg.tree;
      if (rev.root !== mv.root || reg.root !== mv.regRoot) {
        try {
          tree = (await syncRevocationTree(canonProvider, logAddress, { untilEpoch: mv.epoch, expectRoot: mv.root })).tree;
          registry = (await syncRegistryTree(canonProvider, logAddress, { untilEpoch: mv.epoch, expectRoot: mv.regRoot })).tree;
        } catch (e) { throw tagged('sync_unstable', e.message); }
      }
      return { root: mv.root, regRoot: mv.regRoot, epoch: mv.epoch, head: mv.head, tree, registry, chainId: await c.chainId(), mirror: { lastPublishedBlock: mv.lastPublishedBlock }, canonical };
    },
    async accountAddressOf(factoryAddress, PPID) {
      const k = `${factoryAddress}:${PPID}`; if (acct.has(k)) return acct.get(k);
      try { const a = await factoryAt(factoryAddress, provider).computeAddress(BigInt(PPID)); acct.set(k, a); return a; } catch { return null; }
    },
    factory: (address) => factoryAt(address, provider),
  };
  return c;
}
```
```js
// mode3/user/core/idp.js — IdP 호출(브라우저 fetch, CORS 는 cia.js 가 연다 — Task 6). pk_CIA 는 env 고정(config.pkCia)이 있으면 그것, 없으면 TOFU.
import { DEFAULT_ATTR_SCHEMA, loadSchema } from '../../../lib/mode3_attr_schema.js';
export function createIdp({ ciaUrl, fetch = globalThis.fetch, pinnedPk = null, timeoutMs = 2000 }) {
  const json = async (r) => ({ status: r.status, body: await r.json().catch(() => null) });
  let pkP = null, schemaCache = null;
  return {
    post: (p, body) => fetch(`${ciaUrl}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(json),
    publicKeys: () => fetch(`${ciaUrl}/cia/public_keys`).then(json),
    pkCia() {
      return (pkP ??= (async () => {
        if (pinnedPk) return { x: BigInt(pinnedPk.x), y: BigInt(pinnedPk.y) };
        let r; try { r = await fetch(`${ciaUrl}/cia/public_keys`); } catch (e) { throw Object.assign(new Error(e.message), { reason: 'cia_unavailable' }); }
        if (!r.ok) throw Object.assign(new Error(`IdP ${r.status}`), { reason: 'cia_unavailable' });
        const k = await r.json(); return { x: BigInt(k.pk_CIA.x), y: BigInt(k.pk_CIA.y) };
      })().catch((e) => { pkP = null; throw e; }));
    },
    /** { schema, hash, source:'cia'|'default' }. 에이전트의 fetchAttrSchema 와 같은 규칙(실패·검증 실패면 기본 스키마). */
    async schema(force = false) {
      if (schemaCache && !force) return schemaCache;
      const c = new AbortController(); const tm = setTimeout(() => c.abort(), timeoutMs);
      try {
        const r = await fetch(`${ciaUrl}/cia/attr_schema`, { signal: c.signal }); if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const b = await r.json(); const loaded = loadSchema(b?.schema);
        schemaCache = { schema: loaded.schema, hash: loaded.hash, source: 'cia' };
      } catch { schemaCache ??= { ...loadSchema(DEFAULT_ATTR_SCHEMA), source: 'default' }; }
      finally { clearTimeout(tm); }
      return schemaCache;
    },
  };
}
```

- [ ] **Step 5: `user_core.js`** — 아래 뼈대대로 `mode3_wallet_agent.js` 의 라우트 본문을 옮긴다. **옮길 때 바꾸는 것**: `state.registration` → `await kv.get('registration')`, `state.sessions` → `await kv.get('sessions') ?? {}`(바꾼 뒤 `kv.set`), `persist()` → 해당 `kv.set`, `src.registration()`/`src.userCred()` → `secrets`(금고)와 `registration`(공개)에서 조립, `cache(ProofCache)` → `sessions[r_s].proofCache`, `res.status(n).json(b)` → `return { status: n, body: b }`, `takeOverride` → kv `demo` 레코드를 읽고 지운다, `lastSync`/`lastRegistry` → 메모리 변수(페이지 수명), `provider.getSigner` 경로(`/wallet/tx`) 는 없음(릴레이가 대신). 주석은 원문의 "왜" 를 유지하고 "에이전트 라우트 X 의 등가" 를 한 줄 붙인다.

```js
// mode3/user/core/user_core.js — 브라우저 사용자 페이지의 코어(스펙 2026-10-15 §4). mode3_wallet_agent.js 의 라우트 하나하나에 대응하는
// 함수이고 같은 { status, body } 를 돌려준다 — 화면(ui.js·popup.js)이 에이전트 응답을 다루던 코드를 그대로 쓰기 위해서다.
// DOM·fetch 전역에 의존하지 않아 Node 에서도 돈다(tests/test_mode3_user_core.mjs). 비밀은 vault 로만 드나든다.
import { ethers } from 'ethers';
import { createVault } from './vault.js';
import { createChain } from './chain.js';
import { createIdp } from './idp.js';
import { encodeProfile, normalizeProfile, assertPredicateTypes, decodeAttrs, schemaInfo } from '../../../lib/mode3_attr_schema.js';
import { createRegistration, createSessionKey, buildIssueRequest, buildCredentialProof, signChallenge, signSessionRequest, signSlotRequest, signRevokeSession, signRegistration, normalizeDisclosure, normalizeSet, disclosureKey, hasPredicate, chooseMaxHeight } from '../../../lib/mode3_wallet.js';
import { sessionLeaf } from '../../../lib/mode3_revocation.js';
import { registryLeaf } from '../../../lib/mode3_registry.js';
import { signPayload, statementDigestFields, proofToCalldata, parseExecuteReceipt, decodeExecuteCalldata, walletAt, walletInterface, FACTORY_ABI, FACTORY_MAX_ROOT_AGE_BAND, FACTORY_MAX_LIFETIME_BAND, PUB_INDEX } from '../../../lib/mode3_onchain.js';
import { SCALAR_MAX, ppid, randomScalar } from '../../../lib/mode3_credential.js';
import { verifyRpCert } from '../../../lib/mode3_rp_cert.js';

export const USER_STATE_VERSION = 1;
export const DEFAULT_PROFILE = Object.freeze({ birthYear: '1990', country: 'KR' });
const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const isAddr = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
const R = (status, body) => ({ status, body });
const LOCKED = () => R(423, { reason: 'locked' });

export function createUserCore({ kv, config, provider, canonProvider = provider, fetch = globalThis.fetch, fullProve, now = Date.now, log = () => {} }) {
  if (!fullProve?.idp || !fullProve?.cred) throw new Error('createUserCore: fullProve.idp·fullProve.cred 가 필요하다');
  const vault = createVault(kv, { now });
  const chain = createChain({ provider, canonProvider, logAddress: config.logAddress, mirrorAddress: config.mirrorAddress });
  const idp = createIdp({ ciaUrl: config.ciaUrl, fetch, pinnedPk: config.pkCia ?? null });
  const TTL = BigInt(config.ttlBlocks ?? 300), GRID = BigInt(config.heightGrid ?? 100);
  const factoryInterface = new ethers.Interface(FACTORY_ABI);
  let lastSync = null, lastRegistry = null;   // 페이지 수명 메모리(에이전트와 같다)

  // ---- 저장 도우미 ----
  const getReg = async () => (await kv.get('registration')) ?? null;
  const getSessions = async () => (await kv.get('sessions')) ?? {};
  const putSessions = (s) => kv.set('sessions', s);
  const getTxs = async () => (await kv.get('txs')) ?? [];
  /** 비밀 공급원(에이전트 SecretSource 의 등가): 공개 registration + 금고의 secrets 를 합친 뷰. 잠겨 있으면 null. */
  async function source() {
    const reg = await getReg(); if (!reg) return null;
    if (!(await vault.isUnlocked())) return 'locked';
    const sec = await vault.readSecrets();
    return {
      reg, sec,
      registration: () => ({ uid: reg.uid, s_u: sec.s_u, sk_u: sec.sk_u, attrs: reg.attrs, auid: reg.auid, slot: reg.slot, pk_u: reg.pk_u, profile: reg.profile ?? null }),
      userCred: () => (reg.userCred ? { ...reg.userCred, blind_u: sec.blind_u } : null),
      async setUserCred(uc) { reg.userCred = uc ? { C_u_pt: uc.C_u_pt, Cf_u: uc.Cf_u, issuedAt: uc.issuedAt } : null; sec.blind_u = uc ? uc.blind_u : null; await kv.set('registration', reg); await vault.writeSecrets(sec); },
      async setAttrs(attrs) { reg.attrs = attrs; await kv.set('registration', reg); },
    };
  }
  async function takeOverride(scope) { const ov = await kv.get('demo'); if (!ov || ov.scope !== scope) return null; await kv.del('demo'); return ov; }
  async function dropSessions() { await putSessions({}); const sec = await vault.readSecrets(); sec.sessionKeys = {}; await vault.writeSecrets(sec); }
  async function deleteSession(rsKey) { const s = await getSessions(); delete s[rsKey]; await putSessions(s); const sec = await vault.readSecrets(); delete sec.sessionKeys[rsKey]; await vault.writeSecrets(sec); }
  async function pruneSessions(head) { const s = await getSessions(); let changed = false; for (const [k, e] of Object.entries(s)) if (BigInt(e.credential.max_height) < head) { delete s[k]; changed = true; } if (changed) await putSessions(s); }
  const syncSnapshot = (synced) => ({ root: synced.root.toString(), regRoot: synced.regRoot.toString(), epoch: synced.epoch.toString(), head: synced.head.toString(), chainId: synced.chainId.toString(), lastPublishedBlock: synced.mirror.lastPublishedBlock.toString(), canonicalEpoch: synced.canonical.epoch.toString() });
  const canonicalView = (synced) => ({ registry: synced.canonical.registry, regRoot: synced.canonical.regRoot, regEpoch: synced.canonical.epoch });
  const discStrings = (d) => (d ? { mask: d.mask.toString(), lo: d.lo.map(String), hi: d.hi.map(String), set: (d.sel ?? d.setSel ?? 0n) !== 0n ? { sel: (d.sel ?? d.setSel).toString(), root: (d.root ?? d.setRoot).toString() } : null } : null);

  // ---- 에이전트 함수의 등가(본문은 mode3_wallet_agent.js 의 같은 이름 함수에서 옮긴다) ----
  async function registryCheck(view, reg, uc) { /* agent registryCheck — lastRegistry 갱신 */ }
  async function mirrorLeafMatches(synced, reg, uc) { /* agent mirrorLeafMatches */ }
  async function chooseUserCred(synced, src) { /* agent chooseUserCred — SECRETS==='snap' 분기는 없다 */ }
  async function checkService({ arid, origin, cert_s, pk_trace, factoryAddress }) { /* agent checkService — verifyReferenceCode 호출은 뺀다(스펙 §6: web 모드 생략) */ }
  async function issueSession({ arid, r_s, r_rp, pk_trace, allowAgent, factoryAddress, attrGateAddress, head, src, blind_u, origin }) {
    /* agent issueSession + fullProve.idp 주입(buildIssueRequest({ …, fullProve: fullProve.idp })). 세션 레코드에 origin·account(chain.accountAddressOf) 를 함께 넣고
       sessionPrivKey 는 secrets.sessionKeys[r_s] 에 저장한다. */
  }
  async function proveSession(rsKey, synced, timings, disclosure, src) {
    /* agent proveSession — 캐시는 sessions[rsKey].proofCache({ key, proof, publicSignals, revRoot, regRoot }) 하나. 캐시 미스면 buildCredentialProof({ …, fullProve: fullProve.cred });
       거울 root 와 어긋나면 untilEpoch 재생으로 1회 재증명(에이전트와 같다). fake_proof 덮어쓰기는 보내는 복사본만. */
  }
  const sessionMatches = (s, origin, arid) => !(origin && s.origin && origin !== s.origin) && (arid === undefined || arid === null || String(arid) === String(s.arid));

  const core = {
    vault, chain, idp,
    async status() { /* agent GET /wallet/status 등가 — sessions 에 account·sessionAddress(secrets 없이: 세션 레코드에 pk_i 의 주소를 저장해 둔다) */ },
    async health() {
      const reg = await getReg(); const sessions = await getSessions(); const txs = await getTxs();
      return { registered: Boolean(reg), hasCred: Boolean(reg?.userCred), sessions: Object.keys(sessions).length, rpCount: new Set(Object.values(sessions).map((s) => String(s.arid))).size, txs: txs.length, disclosedTxs: txs.filter((t) => t.disclosed).length };
    },
    async attrSchema() { const s = await idp.schema(); return R(200, { schema: s.schema, hash: s.hash, source: s.source }); },
    async register({ uid, pwd, profile = null, vaultPassword = null }) { /* agent POST /wallet/register(file 규칙) + 금고: hasVault() 가 false 면 vaultPassword 로 setup, true 면 잠금 해제 상태 필요(아니면 423). 성공 시 registration(공개)·secrets({ s_u, sk_u, blind_u:null, sessionKeys:{} }) 저장. */ },
    async saveProfile(profile) { /* agent PUT /wallet/profile — changed 면 userCred null·dropSessions() */ },
    async precheck(body) { /* agent POST /wallet/authorize/precheck */ },
    async login(body, { verifiedOrigin } = {}) { /* agent POST /wallet/login(snap 의 verifiedOrigin 대조·file 의 비밀) — 사유·상태 코드 동일. 성공 body 에 비밀·uid 없음. */ },
    async revalidate({ r_s, skipSync = false, arid = null, origin = null }) { /* agent POST /wallet/revalidate; sessionMatches(s, origin, arid) */ },
    async request({ r_s, body, arid = null, origin = null }) { /* agent POST /wallet/request */ },
    async prepareTx(body) { /* agent buildExecute + /wallet/tx/prepare 응답 모양(walletAddr·factoryAddress·deployNeeded·deployCalldata·calldata·nonce·disclosure·cacheHit·root·regRoot·timings·demo) */ },
    async recordTx({ r_s, txHash }) { /* agent POST /wallet/tx/record — provider 로 영수증·tx 를 읽고 없으면 202 { pending:true }. 성공하면 txs 에 { txHash, r_s, at, ok, disclosed:boolean, wallet, nonce } 를 push(같은 txHash 는 한 번만). */ },
    async revokeSession({ r_s }) { /* agent POST /wallet/session/revoke — sk_u 는 금고에서; 성공 시 deleteSession */ },
    async selfRevoke({ uid, pwd }) { /* agent POST /wallet/self_revoke — IdP /cia/account/self_revoke 를 직접 부른다 */ },
    async demoOverride({ scope = null, s_u = null, uid = null, clear = false }) { /* agent POST /wallet/demo/override — kv 'demo' */ },
    async wipe() { await kv.clear(); vault.reset(); lastSync = null; lastRegistry = null; },
  };
  return core;
}
```
(위 `/* … */` 자리는 **에이전트의 해당 함수 본문을 옮긴 코드**로 채운다 — 실행자는 `mode3_wallet_agent.js` 의 해당 줄 범위(status 452-486, register 515-546, profile 550-567, precheck 571-591, login 597-737, proveSession 783-865, revalidate 867-914, self_revoke 925-936, session/revoke 941-964, request 976-985, buildExecute 1000-1070, receiptResult 1073-1082, tx/record 1134-1153, chooseUserCred 268-281, issueSession 284-308, checkService 334-359, registryCheck 250-257, mirrorLeafMatches 261-264)를 읽고 위 "옮길 때 바꾸는 것" 규칙으로 바꾼다. 응답 사유 문자열·상태 코드는 한 글자도 바꾸지 않는다.)

- [ ] **Step 6: 통과 확인** — `node tests/test_mode3_user_core.mjs` 16개 ok(증명 여러 번 — 3~5분). 회귀: `node tests/test_mode3_wallet_lib.js`, `node tests/test_mode3_user_static.mjs`.
- [ ] **Step 7: CHAIN 배열 `tests/test_mode3_user_static.mjs` 다음에 `tests/test_mode3_user_core.mjs` 추가. 커밋** — `feat(user-web): 사용자 코어 — 금고·체인 동기화·IdP 호출·에이전트 라우트 등가 함수(Node 에서 검증)`.

---
### Task 9: 사용자 페이지·팝업·증명 워커·RP web 분기 (스펙 §4.2·§6 워커·§7·§8)

**Files:**
- Create: `lib/browser/zk_assets.js`, `mode3/user/prover_worker.js`(Task 4 의 최소본을 교체), `mode3/user/prover_client.js`, `mode3/user/index.html`(Task 5 의 임시본을 교체), `mode3/user/ui.js`, `mode3/user/popup.js`, `mode3/user/user.js`(Task 4 의 최소본을 교체)
- Modify: `mode3/common/strings.js`(ui 키·reasons 10개), `tests/test_mode3_demo_strings.js`(`REASONS` 에 10개), `mode3/rp.html`(web 분기)
- Test: `tests/test_mode3_user_web.mjs`(browser) — 이 태스크에서는 **각본 A**(등록 → 로그인 → 재검증 → 요청 → 트랜잭션 → Selective disclosure proof → 세션 폐기)까지. 각본 B 는 Task 10.

**Interfaces:**
- `lib/browser/zk_assets.js`: `loadAsset(url, { onProgress } = {}) → Promise<Uint8Array>` — `caches.open('mode3-zk-v1')` 에 있으면 그것, 없으면 `fetch` 를 스트림으로 읽어 `onProgress({ url, loaded, total })` 를 부르고 캐시에 넣는다(`caches` 가 없으면 캐시 없이). `loadJson(url) → Promise<any>`. 실패는 `Error{ reason:'zk_assets_unavailable' }`.
- `prover_worker.js`(module worker) 메시지: 요청 `{ id, kind:'pi_idp'|'pi_cred', input }` → 응답 `{ id, proof, publicSignals, ms }` 또는 `{ id, error, reason }`; 다운로드 중 `{ kind:'progress', name, url, loaded, total }`. kind 마다 첫 증명 뒤 `snarkjs.groth16.verify(vkey, …)` 로 산출물 짝을 한 번 확인한다(실패 → `zk_assets_unavailable`). 자산 URL: `/zk/pi_idp.wasm`·`/zk/pi_idp_final.zkey`·`/zk/pi_idp_vkey.json`, `/zk/pi_cred.wasm`·`/zk/pi_cred_final.zkey`·`/zk/pi_cred_vkey.json`.
- `prover_client.js`: `createProver({ workerUrl = '/dist/prover_worker.js', onProgress }) → { fullProve: { idp(input), cred(input) }, warm() /*두 kind 자산 미리 받기: 워커에 { id, kind:'warm', which }*/ }` — 각 함수는 `(input) → Promise<{ proof, publicSignals }>`(lib 가 넘기는 wasmPath·zkeyPath 는 무시).
- 페이지(`index.html`, `data-page="wallet"` 유지): 카드 다섯 개는 `mode3/wallet.html` 14-154행의 마크업을 그대로 가져오고 다음만 바꾼다 — (1) `#snapPanel` → `#storagePanel`("보관 상태": `#vaultBadge`, `#vaultInfo`, `#lockBtn`, `#unlockBtn`, `#changePwBtn`, `#wipeBtn`, `#selfRevokeBtn`, `#zkProgress`), (2) `#fileRegFields` 안에 `#uid`·`#pwd` 유지 + `<span id="vaultFields"><label>금고 비밀번호 <input id="vaultPw" type="password"></label> <label>확인 <input id="vaultPw2" type="password"></label></span>`(금고가 이미 있으면 숨김), (3) 잠금 해제 모달 `#unlockModal`(`#unlockPw`, `#unlockGo`, `#unlockCancel`, `#unlockVerdict`) — 팝업 뷰에서도 같은 모달을 쓴다, (4) `#authorizeView` 카드에 `#authApproveBtn`·`#authDenyBtn`(요청 요약 뒤에 보임), (5) 시연 카드·트랜잭션 카드·세션 카드의 id 는 전부 그대로(`#registerBtn`·`#txBtn`·`#claimBtn`·`#sessionActions`·`#demoFakeProofBtn`·`#demoFakeSigBtn`·`#refreshBtn`·`#txSession`·`#dk0..5`·`#discLo0`·`#discHi0`·`#discCountry`·`#setSlot`·`#setMembers`·`#minAgeIn`·`#ageBtn`·`#discExactBtn`·`#txVerdict`·`#sessionVerdict`·`#registerResult`·`#demoVerdict`·`#regBadge`·`#registryBadge`·`#registryInfo`·`#status`·`#txLog`·`#sessionLog`). `<script type="module" src="/dist/user.js">`, `/common/strings.js`·`/common/demo.js`·`/common/demo.css` 는 wallet.html 과 같은 `<head>` 줄로.
- `ui.js`: `mountUi({ core, prover, config, Demo })` — `mode3/wallet.html` 160-1152행의 화면 로직을 옮긴다. **치환 규칙**: `fetch('/wallet/status')` → `core.status()`, `postJson('/wallet/register', b)` → `core.register({ …b, vaultPassword })`, `putJson('/wallet/profile', …)` → `core.saveProfile`, `/wallet/session/revoke` → `core.revokeSession`, `/wallet/self_revoke` → `core.selfRevoke`(비밀번호는 `prompt` 대신 모달 `#selfRevokePw`), `/wallet/demo/override` → `core.demoOverride`, `/wallet/attr_schema` → `core.attrSchema()`, `sendTxViaRelayer/MetaMask` → `sendTxViaRelay()`(아래), `/wallet/config` → `config`(`cfg.secrets = 'web'`), MetaMask·Snap 코드(`connectMetaMask`·`invokeSnap`·`applyPendingToSnap`·`applySnapMode`·`#connectBtn`·`#snapInfoBtn`·`#snapResetBtn`) 는 **넣지 않는다**. 423 `locked` 응답은 공통 래퍼 `withUnlock(fn)` 이 모달을 띄워 `core.vault.unlock(pw)` 뒤 한 번 재시도한다(취소 → 그 동작의 결과 카드에 `locked`). `refresh()` 끝에 `postPresence()`(`fetch('/wallet/presence', POST core.health())`)와 `renderVault()`. 5초 주기 refresh 는 그대로.
  - `sendTxViaRelay()`: `txForm()` → `withUnlock(() => core.prepareTx(f))` → 실패면 `txFailed` → `fetch(`${rpOrigin}${config.relayPath}`, POST { to: b.walletAddr, data: b.calldata })`(세션의 `origin` 이 RP 오리진; 사용자 오리진에서 부르므로 CORS 는 Task 7) → `relay_*` 사유면 `txFailed(null, reason, body)`(`b.demo` 가 있으면 `[시연 모드]` 접두어 — 기존 `txFailed` 규칙) → `core.recordTx({ r_s, txHash })` 를 700 ms 간격 최대 30회 → `showTxResult(rec.body, …, relay.deployed)`.
  - `renderVault()`: 금고 없음/잠김/해제(만료 시각) 배지, 버튼 활성.
  - zk 진행률: `prover` 의 `onProgress` → `#zkProgress` 에 `tt('user_zk_loading', { name, pct })`; 첫 로드 뒤 `tt('user_zk_ready')`. `init()` 끝에 `prover.warm()`(등록 전에도 받아 두어 첫 로그인이 빨라진다).
- `popup.js`: `runPopup({ core, config, Demo })` — `mode3/wallet.html` 340-492행(`runAuthorize`) 을 옮기되 `req.type` 으로 분기한다. 공통: `ev.origin !== req.origin` → `origin_mismatch` 회신(기존 규칙), `reply(result)` 는 `{ type: `${req.type}-result`, r_s: req.r_s ?? null, result }` 를 `target` 오리진으로, 성공 200 ms·실패 3000 ms 뒤 `window.close()`. 준비 신호 `{ type:'mode3-authorize-ready' }` 는 지금처럼 `'*'` 로(비밀 없음).
  - `mode3-config`: `ev.origin ∈ config.rpOrigins` 아니면 `{ ok:false, reason:'origin_mismatch' }`; 아니면 `{ ok:true, secrets:'web', ...(await core.health()) }` 에서 `registered·rpCount·sessions` 만 골라 회신(R5: uid 없음).
  - `mode3-precheck`: `core.precheck({ arid, origin, cert_s, pk_trace, factoryAddress, r_s })` → 200 이면 `{ ok:true }`, 아니면 `{ ok:false, reason, detail, status }`.
  - `mode3-authorize`: `renderAuthSummary(req)` → `withUnlock`(잠겨 있으면 모달; 취소 → `user_denied`) → `core.precheck` → 실패면 회신 → `reauth` 면(R12) 세션 존재·오리진 확인 뒤 `{ ok:true, reauth:true }` → 아니면 승인·거절 버튼 대기(거절 → `user_denied`) → `core.login(req, { verifiedOrigin: ev.origin })` → 200 이면 `{ ok:true, ...body }`, 아니면 `{ ok:false, reason: body.reason ?? 'login_failed', detail: body.detail ?? null, status }`. 진행 단계는 `#authStep` 에(기존 `step()`).
  - `mode3-revalidate`: `withUnlock(() => core.revalidate({ r_s, skipSync, arid, origin: ev.origin }))` → 200 `{ ok:true, ...body }` / 실패 `{ ok:false, reason, status, detail }`. 동의 화면 없음(스펙: 캐시 히트면 화면 없음, 재증명이면 진행 화면 = `#authStep`).
  - `mode3-request`: 요약에 `body` 를 `textContent` 로 보이고 승인·거절 → `withUnlock(() => core.request({ r_s, body, arid, origin: ev.origin }))`.
  - 성공 뒤(`authorize`·`revalidate`) `postPresence()`.
- `user.js`(엔트리): `config = await (await fetch('/user/config')).json()` → `kv = await openIdbKv()`(실패 → 화면에 `storage_unavailable` 사유 카드, 중단) → `provider = new ethers.JsonRpcProvider(config.rpcUrl, undefined, { cacheTimeout: -1 })`, `canonProvider`(revRpcUrl) → `prover = createProver({ onProgress })` → `core = createUserCore({ kv, config, provider, canonProvider, fullProve: prover.fullProve })` → `IS_AUTHORIZE ? runPopup(...) : mountUi(...)`. `Demo.init({ page:'wallet', tour: !IS_AUTHORIZE })`, `Demo.stack({ self:'wallet', urls: { aa: config.ciaUrl, rp: config.rpOrigins[0] } })`(에이전트 페이지의 `syncStack` 과 같은 역할).
- `strings.js` 추가 — ui: `user_storage_title`(보관 상태), `user_storage_desc`, `user_vault_none`(금고 없음 — 등록할 때 비밀번호를 정합니다), `user_vault_locked`(잠김), `user_vault_unlocked`(해제됨 · {until} 까지), `user_lock_btn`(잠그기), `user_unlock_btn`(잠금 해제), `user_change_pw_btn`(비밀번호 변경), `user_wipe_btn`(모두 지우기), `user_wipe_done`, `user_vault_pw_label`(금고 비밀번호), `user_vault_pw2_label`(확인), `user_vault_pw_mismatch`(두 비밀번호가 다릅니다), `user_vault_pw_short`(8자 이상), `user_unlock_title`(잠금 해제), `user_unlock_hint`, `user_unlock_cancel`(취소), `user_zk_loading`(증명 키 받는 중 {name} {pct}%), `user_zk_ready`(증명 키 준비됨), `user_auth_approve`(승인), `user_auth_deny`(거절), `user_auth_request_title`(세션 요청 서명), `user_auth_sign_body`(이 요청에 세션키로 서명합니다: {body}), `user_intro_web`(이 페이지는 설치 없이 브라우저에서 돕니다. 비밀은 이 브라우저의 저장소에 비밀번호로 암호화해 둡니다.), `user_tx_note_web`(이 RP 전용 주소에서 보냅니다. 가스는 RP 의 릴레이가 냅니다.), `user_self_revoke_pw`(IdP 계정 비밀번호), `confirm_wipe`(이 브라우저에 보관된 등록·비밀·세션을 모두 지웁니다. 되돌릴 수 없습니다.), `rp_wallet_web`(사용자 비밀=브라우저), `rp_wallet_web_note`(사용자 페이지가 브라우저 안에서 증명을 만들고 RP 의 릴레이로 트랜잭션을 보냅니다.), `rp_wallet_mode_web`(브라우저). reasons(`where`): `locked`(wallet) · `bad_password`(wallet) · `zk_assets_unavailable`(wallet) · `storage_unavailable`(wallet) · `relay_inactive`(rp) · `relay_bad_target`(rp) · `relay_bad_calldata`(rp) · `relay_gas`(rp) · `relay_rate_limited`(rp) · `origin_mismatch`(wallet, 없을 때만). 각각 ko·en `title·cause·action` — cause 는 발생 조건(위 Task 7·8 의 검사), action 은 사용자가 할 일.
- `rp.html` web 분기: `const WEB = () => walletCfg.secrets === 'web'`; `renderWalletMode()` 에 `web` 배지·노트(`rp_wallet_web`·`rp_wallet_web_note`); `connectWallet()` 의 `mode` 표기 `cfg.secrets === 'web' ? (tt('rp_wallet_mode_web') || '브라우저') : …`; `authorizeViaPopup(request)` 를 `popupCall(type, request)` 로 일반화(창 이름 `mode3-${type}-${r_s}`, 보내는 메시지 `{ type, ...request }`, 기다리는 응답 `${type}-result`; `authorizeViaPopup = (r) => popupCall('mode3-authorize', r)` 유지) — `startIdpLogin` 의 분기를 `if (walletCfg.secrets === 'snap' || WEB())` 로; 재검증: `WEB()` 이면 `callRevalidate = async () => { const r = await popupCall('mode3-revalidate', authorizeRequest({ r_s: currentSession, skipSync })); return r.ok ? { status: 200, body: r } : { status: r.status ?? 500, body: r }; }`(이후 코드는 그대로 — `needs_consent` 분기는 snap 전용 조건이라 web 에서는 타지 않는다); 요청: `WEB()` 이면 `const r = await popupCall('mode3-request', authorizeRequest({ r_s: currentSession, body })); const w = { status: r.ok ? 200 : (r.status ?? 500) }, wb = r;`. 모든 `walletCfg.secrets === 'snap'` 로그 문구 "MetaMask·Snap 동의" 는 `WEB()` 이면 "사용자 창에서 승인" 으로.

- [ ] **Step 1: 실패하는 테스트(각본 A)**

```js
// tests/test_mode3_user_web.mjs — 브라우저 전용 사용자 페이지(web 모드)를 실제 Chrome 에서. 정적 서버 + 격리 IdP·RP(릴레이). 비밀은 IndexedDB 암호문에만.
// hardhat :8545, build/mode3, Chrome 필요. 번들은 여기서 만든다. (browser)   node tests/test_mode3_user_web.mjs   MODE3_BROWSER_DEBUG=1 로 콘솔을 본다.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { attrGateAt } from '../lib/mode3_onchain.js';

const DEBUG = process.env.MODE3_BROWSER_DEBUG === '1';
const j = (o) => JSON.stringify(o);
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); } }
async function launchBrowser() { const tried = []; for (const opts of [{ channel: 'chrome' }, {}]) { try { return await chromium.launch(opts); } catch (e) { tried.push(`${j(opts)}: ${e.message.split('\n')[0]}`); } } throw new Error(`BLOCKED: 브라우저를 띄우지 못했다.\n  ${tried.join('\n  ')}`); }

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
const browser = await launchBrowser();
const provider = getProvider();
const stack = await startIsolatedMode3Stack({ userMode: 'web', autoRelay: true });
const { wallet, rp } = stack;
const PW = 'demo-vault-pw';
try {
  const context = await browser.newContext();
  if (DEBUG) context.on('page', (p) => { p.on('console', (m) => console.log(`    [${new URL(p.url()).port}] ${m.type()}: ${m.text()}`)); p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`)); });
  const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
  async function waitText(page, sel, needle, timeout = 60_000) {
    try { await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout }); }
    catch { throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`); }
  }
  const idbDump = (page) => page.evaluate(async () => { const open = indexedDB.open('mode3-user', 1); const db = await new Promise((r, x) => { open.onsuccess = () => r(open.result); open.onerror = () => x(open.error); }); const st = db.transaction('kv', 'readonly').objectStore('kv'); const keys = await new Promise((r) => { const q = st.getAllKeys(); q.onsuccess = () => r(q.result); }); const out = {}; for (const k of keys) out[k] = await new Promise((r) => { const q = st.get(k); q.onsuccess = () => r(q.result); }); return JSON.parse(JSON.stringify(out, (k, v) => (v instanceof CryptoKey ? '[CryptoKey]' : v))); });
  const pageDump = (page) => page.evaluate(() => [document.documentElement.outerHTML, [...document.querySelectorAll('input,textarea,select')].map((e) => `${e.id}=${e.value}`).join('\n'), (() => { try { return JSON.stringify(localStorage) + JSON.stringify(sessionStorage); } catch { return ''; } })()].join('\n'));
  /** RP 페이지 동작이 여는 팝업을 잡아 fn(popup) 으로 조작하고, RP 쪽 결과를 기다린다. */
  async function viaPopup(trigger, fn) { const [popup] = await Promise.all([context.waitForEvent('page'), trigger()]); await popup.waitForSelector('#authorizeView:not([hidden])'); await fn(popup); if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 120_000 }); }
  const approve = async (popup) => { await popup.waitForSelector('#authApproveBtn:not([hidden])', { timeout: 60_000 }); await popup.click('#authApproveBtn'); };

  const userPage = await context.newPage();
  await userPage.goto(`${wallet.base}/`);
  await userPage.waitForSelector('#mainView:not([hidden])');
  const rpPage = await context.newPage();
  await rpPage.goto(`${rp.base}/`);
  await waitText(rpPage, '#walletMode', '사용자 비밀=브라우저');
  let account = null;

  await t('A1 등록: 금고 비밀번호를 정하고 IdP 에 등록 — 등록됨, IndexedDB 에 registration(공개)·secrets(암호문)·meta·unlock(CryptoKey) 만, 비밀 평문 없음', async () => {
    await userPage.fill('#vaultPw', PW); await userPage.fill('#vaultPw2', PW);
    await userPage.click('#registerBtn');
    await waitText(userPage, '#registerResult', '등록됨', 90_000);
    const d = await idbDump(userPage);
    assert.deepEqual(Object.keys(d).sort(), ['meta', 'registration', 'secrets', 'sessions', 'unlock'].filter((k) => k in d).sort());
    assert.equal(d.registration.uid, '12345'); assert.ok(!('s_u' in d.registration) && !('sk_u' in d.registration));
    assert.ok(d.secrets.iv && d.secrets.ct); assert.equal(d.unlock.key, '[CryptoKey]');
    const dump = await pageDump(userPage); assert.ok(!dump.includes(d.secrets.ct), '암호문도 DOM 에 없다'); assert.ok(!dump.includes(PW), '비밀번호가 DOM 에 남지 않는다');
    await waitText(userPage, '#vaultBadge', '해제');
  });
  await t('A2 로그인: RP 로그인 → 사용자 팝업(승인 버튼) → 로그인 성공; 팝업 DOM 에 비밀 없음', async () => {
    let popupDump = null;
    await viaPopup(async () => { await rpPage.click('#loginBtn'); await rpPage.click('#idpLoginBtn'); }, async (popup) => { await waitText(popup, '#authSummary', rp.origin); await approve(popup); popupDump = await pageDump(popup).catch(() => ''); });
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    const d = await idbDump(userPage); const s = Object.values(d.sessions)[0]; assert.ok(s?.proofCache?.proof, '증명 캐시가 저장됐다'); assert.ok(!('sessionPrivKey' in s)); account = s.account;
    assert.ok(popupDump !== null && !popupDump.includes('"s_u"') && !popupDump.includes('sessionPrivKey'));
    await rpPage.click('#connectWalletBtn'); await waitText(rpPage, '#walletPillText', '브라우저');
  });
  await t('A3 재검증: 팝업이 캐시 히트로 바로 끝난다(승인 버튼 없음) → 재검증 성공', async () => {
    await viaPopup(() => rpPage.click('#revalidateBtn'), async (popup) => { assert.equal(await popup.$('#authApproveBtn:not([hidden])'), null, '캐시 히트는 동의 화면이 없다'); });
    await waitText(rpPage, '#sessionVerdict', '재검증 성공');
  });
  await t('A4 세션 요청: 팝업 승인 → 세션 요청 성공', async () => {
    await viaPopup(() => rpPage.click('#requestBtn'), async (popup) => { await waitText(popup, '#authSummary', 'hello'); await approve(popup); });
    await waitText(rpPage, '#sessionVerdict', '세션 요청 성공');
  });
  await t('A5 트랜잭션: 사용자 페이지에서 보내기 → RP 릴레이가 배포·전송 → 전송 성공, 체인에 Executed', async () => {
    await userPage.click('#refreshBtn'); await userPage.waitForFunction(() => document.querySelector('#txSession')?.options.length > 0);
    await userPage.click('#txBtn');
    await waitText(userPage, '#txVerdict', '전송 성공', 120_000);
    assert.ok((await text(userPage, '#txLog')).includes('txHash='));
    assert.notEqual(await provider.getCode(account), '0x', '계정이 배포됐다');
  });
  await t('A6 Selective disclosure proof: 버튼으로 AttrGate 조건을 채우고 보내기 → 전송 성공, claimed(account)=true', async () => {
    await userPage.click('#claimBtn'); await userPage.click('#txBtn');
    await waitText(userPage, '#txVerdict', '전송 성공', 120_000);
    const info = (await rp.get('/api/mode3/rp_info')).body;
    assert.equal(await attrGateAt(info.attrGateAddress, provider).claimed(account), true);
    assert.equal((await wallet.get('/mode3/health')).body.disclosedTxs, 1, '존재 신호가 health 에 반영된다');
  });
  await t('A7 세션 폐기: 확인창 승인 → 폐기 요청 접수, 세션 목록이 빈다', async () => {
    userPage.once('dialog', (d) => d.accept());
    await userPage.click('#sessionActions button.danger');
    await waitText(userPage, '#sessionVerdict', '폐기 요청 접수');
    await waitText(userPage, '#sessionActions', '로그인 세션이 없습니다', 15_000);
  });
} finally { await browser.close(); await stack.stop(); }
process.exit(failed ? 1 : 0);
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_user_web.mjs` → `#walletMode` 에 '사용자 비밀=브라우저' 가 안 나와 첫 대기에서 FAIL.

- [ ] **Step 3: 워커·클라이언트·자산 로더**

```js
// lib/browser/zk_assets.js — zk 산출물(wasm·zkey·vkey) 받기 + Cache API(스펙 2026-10-15 §6 워커). 진행률은 Content-Length 가 있을 때만 total 이 있다.
const CACHE = 'mode3-zk-v1';
const fail = (msg) => Object.assign(new Error(msg), { reason: 'zk_assets_unavailable' });
async function cacheOpen() { try { return typeof caches !== 'undefined' ? await caches.open(CACHE) : null; } catch { return null; } }
export async function loadAsset(url, { onProgress = () => {} } = {}) {
  const cache = await cacheOpen();
  const hit = cache ? await cache.match(url) : null;
  if (hit) return new Uint8Array(await hit.arrayBuffer());
  let r; try { r = await fetch(url); } catch (e) { throw fail(`${url}: ${e.message}`); }
  if (!r.ok || !r.body) throw fail(`${url}: HTTP ${r.status}`);
  const total = Number(r.headers.get('content-length')) || null;
  const reader = r.body.getReader(); const chunks = []; let loaded = 0;
  for (;;) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); loaded += value.length; onProgress({ url, loaded, total }); }
  const out = new Uint8Array(loaded); let o = 0; for (const c of chunks) { out.set(c, o); o += c.length; }
  if (cache) { try { await cache.put(url, new Response(out, { headers: { 'Content-Type': 'application/octet-stream' } })); } catch { /* 저장 공간 부족 등 — 다음에 다시 받는다 */ } }
  return out;
}
export async function loadJson(url) { return JSON.parse(new TextDecoder().decode(await loadAsset(url))); }
```
```js
// mode3/user/prover_worker.js — 증명 워커(스펙 §6). 메인 스레드는 입력만 보내고 zkey 는 여기서만 산다. kind 마다 첫 증명 뒤 vkey 로 한 번 자기 검증한다(산출물 짝 확인 — 에이전트의 artifacts 검사 대체).
import * as snarkjs from 'snarkjs';
import { loadAsset, loadJson } from '../../lib/browser/zk_assets.js';
const ASSETS = { pi_idp: { wasm: '/zk/pi_idp.wasm', zkey: '/zk/pi_idp_final.zkey', vkey: '/zk/pi_idp_vkey.json' }, pi_cred: { wasm: '/zk/pi_cred.wasm', zkey: '/zk/pi_cred_final.zkey', vkey: '/zk/pi_cred_vkey.json' } };
const loaded = {}, verified = {};
function assets(kind) {
  return (loaded[kind] ??= (async () => {
    const a = ASSETS[kind]; if (!a) throw Object.assign(new Error(`모르는 kind ${kind}`), { reason: 'zk_assets_unavailable' });
    const onProgress = (p) => self.postMessage({ kind: 'progress', name: kind, ...p });
    const [wasm, zkey, vkey] = await Promise.all([loadAsset(a.wasm, { onProgress }), loadAsset(a.zkey, { onProgress }), loadJson(a.vkey)]);
    return { wasm, zkey, vkey };
  })().catch((e) => { delete loaded[kind]; throw e; }));
}
self.onmessage = async ({ data }) => {
  const { id, kind, input, which } = data ?? {};
  try {
    if (kind === 'warm') { await Promise.all((which ?? ['pi_idp', 'pi_cred']).map(assets)); return self.postMessage({ id, warmed: true }); }
    const a = await assets(kind);
    const t = Date.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, a.wasm, a.zkey);
    if (!verified[kind]) {
      if (!(await snarkjs.groth16.verify(a.vkey, publicSignals, proof))) throw Object.assign(new Error(`${kind}: vkey 가 zkey 와 짝이 아니다(산출물 세트 불일치)`), { reason: 'zk_assets_unavailable' });
      verified[kind] = true;
    }
    self.postMessage({ id, proof, publicSignals, ms: Date.now() - t });
  } catch (e) { self.postMessage({ id, error: e?.message ?? String(e), reason: e?.reason ?? null }); }
};
```
```js
// mode3/user/prover_client.js — 메인 스레드의 워커 클라이언트. lib 가 넘기는 (input, wasmPath, zkeyPath) 중 input 만 보낸다(계획 R7).
export function createProver({ workerUrl = '/dist/prover_worker.js', onProgress = () => {} } = {}) {
  const worker = new Worker(workerUrl, { type: 'module' });
  const pending = new Map(); let seq = 0;
  worker.onmessage = ({ data }) => {
    if (data?.kind === 'progress') return onProgress(data);
    const p = pending.get(data?.id); if (!p) return; pending.delete(data.id);
    if (data.error) p.reject(Object.assign(new Error(data.error), { reason: data.reason ?? 'zk_assets_unavailable' }));
    else p.resolve(data);
  };
  worker.onerror = (e) => { for (const p of pending.values()) p.reject(Object.assign(new Error(e.message ?? 'worker error'), { reason: 'zk_assets_unavailable' })); pending.clear(); };
  const call = (msg) => new Promise((resolve, reject) => { const id = ++seq; pending.set(id, { resolve, reject }); worker.postMessage({ id, ...msg }); });
  const prove = (kind) => async (input) => { const { proof, publicSignals } = await call({ kind, input }); return { proof, publicSignals }; };
  return { fullProve: { idp: prove('pi_idp'), cred: prove('pi_cred') }, warm: (which) => call({ kind: 'warm', which }) };
}
```

- [ ] **Step 4: 페이지·팝업·엔트리·문구·RP 분기** — 위 Interfaces 의 규칙대로 작성한다. `mode3/wallet.html` 의 해당 줄을 읽고 옮긴다. `index.html` 의 `<head>` 는 `mode3/wallet.html` 1-13행과 같고(`<title>사용자 페이지</title>`), 스크립트는 `<script type="module" src="/dist/user.js"></script>` 하나다.

- [ ] **Step 5: 통과 확인** — `npm run user:build && node tests/test_mode3_user_web.mjs` → A1~A7 ok. `node tests/test_mode3_demo_strings.js` ok(새 키·사유). 회귀: `bash scripts/run_tests.sh browser`(snap 모드 두 테스트 — `rp.html` 의 snap 분기가 그대로여야 한다).
- [ ] **Step 6: `scripts/run_tests.sh` BROWSER 배열에 `tests/test_mode3_user_web.mjs` 추가(주석: `# web 모드 — 정적 서버 + 팝업 프로토콜 + 릴레이; 번들을 스스로 만든다`). 커밋**(둘로 나눠도 좋다: ① 워커·클라이언트·자산 로더·문구, ② 페이지·팝업·엔트리·RP 분기·테스트) — `feat(user-web): 브라우저 사용자 페이지·승인 팝업·증명 워커, RP 페이지 web 분기`.

---
### Task 10: 브라우저 각본 B — 잠금·시연 거절·오리진 위조·두 번째 RP·초기화

**Files:**
- Modify: `tests/test_mode3_user_web.mjs` (각본 B 추가 — `finally` 앞)
- Modify(필요할 때만): `mode3/user/ui.js`·`popup.js`(각본이 드러낸 결함 수정)

**Interfaces:**
- Consumes: Task 9 의 페이지·팝업·`viaPopup`·`idbDump`·`pageDump` 헬퍼, `stack` 은 `extraRps: [{ name: 'zkTWO', env: { MODE3_ALLOWED_COUNTRIES: 'KR,JP' } }]` 로 띄우도록 **Task 9 의 `startIsolatedMode3Stack` 호출을 바꾼다**(`rps[1]` 이 두 번째 RP). 두 번째 RP 오리진은 정적 서버의 `MODE3_RP_ORIGIN` 에 헬퍼가 넣는다(기존 동작).

- [ ] **Step 1: 각본 B 추가**

```js
  // ---- 각본 B ----
  const rp2 = stack.rps[1];
  await t('B1 잠금: 잠그기 뒤 트랜잭션은 모달을 띄운다 — 틀린 비밀번호는 bad_password, 맞으면 진행해 전송 성공', async () => {
    // 새 세션이 필요하다(A7 에서 폐기했다)
    await viaPopup(async () => { await rpPage.click('#loginBtn'); await rpPage.click('#idpLoginBtn'); }, approve);
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
    await userPage.click('#lockBtn'); await waitText(userPage, '#vaultBadge', '잠김');
    assert.equal((await idbDump(userPage)).unlock, undefined, 'unlock 레코드가 지워졌다');
    await userPage.click('#refreshBtn'); await userPage.waitForFunction(() => document.querySelector('#txSession')?.options.length > 0);
    await userPage.click('#txBtn');
    await userPage.waitForSelector('#unlockModal:not([hidden])');
    await userPage.fill('#unlockPw', 'wrong'); await userPage.click('#unlockGo');
    await waitText(userPage, '#unlockVerdict', '비밀번호', 10_000);
    await userPage.fill('#unlockPw', PW); await userPage.click('#unlockGo');
    await waitText(userPage, '#txVerdict', '전송 성공', 120_000);
    await waitText(userPage, '#vaultBadge', '해제');
  });
  await t('B2 잠긴 상태의 팝업: 재검증 팝업이 비밀번호를 묻고, 취소하면 RP 에 user_denied', async () => {
    await userPage.click('#lockBtn'); await waitText(userPage, '#vaultBadge', '잠김');
    await viaPopup(() => rpPage.click('#revalidateBtn'), async (popup) => { await popup.waitForSelector('#unlockModal:not([hidden])'); await popup.click('#unlockCancel'); });
    await waitText(rpPage, '#sessionVerdict', 'user_denied');
    await viaPopup(() => rpPage.click('#revalidateBtn'), async (popup) => { await popup.waitForSelector('#unlockModal:not([hidden])'); await popup.fill('#unlockPw', PW); await popup.click('#unlockGo'); });
    await waitText(rpPage, '#sessionVerdict', '재검증 성공');
    await waitText(userPage, '#vaultBadge', '해제', 10_000);   // 팝업의 해제가 IndexedDB 를 거쳐 메인 탭에도 보인다(R3)
  });
  await t('B3 시연 가짜 증명: 다음 로그인이 RP 에서 bad_proof 로 거절되고 [시연 모드] 표기; 가짜 서명: 다음 트랜잭션이 relay_gas(BadSignature)', async () => {
    await userPage.evaluate(() => Demo.setExpert(true)); await userPage.waitForSelector('#demoCard', { state: 'visible' });
    await userPage.click('#demoFakeProofBtn'); await waitText(userPage, '#demoVerdict', '적용', 10_000);
    await viaPopup(async () => { await rpPage.click('#loginBtn'); await rpPage.click('#idpLoginBtn'); }, approve);
    await waitText(rpPage, '#verdict', 'bad_proof', 120_000);
    assert.ok((await text(rpPage, '#verdict')).includes('[시연 모드]'));
    await userPage.click('#demoFakeSigBtn'); await waitText(userPage, '#demoVerdict', '적용', 10_000);
    await userPage.click('#refreshBtn'); await userPage.click('#txBtn');
    await waitText(userPage, '#txVerdict', 'relay_gas', 120_000);
    assert.match(await text(userPage, '#txVerdict'), /\[시연 모드\]|BadSignature/);
    await userPage.evaluate(() => Demo.setExpert(false));
  });
  await t('B4 오리진 위조: 다른 오리진에서 보낸 mode3-authorize 는 origin_mismatch; 세션 주인이 아닌 RP 의 mode3-revalidate 는 no_session; mode3-config 는 RP 오리진에만', async () => {
    const info = (await rp.get('/api/mode3/rp_info')).body;
    const sessionsBefore = Object.keys((await idbDump(userPage)).sessions);
    const forged = async (fromPage, type, request) => {
      await fromPage.evaluate(({ walletOrigin, type: ty, request: req }) => {
        document.getElementById('forgedBtn')?.remove();
        window.__forged = new Promise((resolve) => { window.__forgedResolve = resolve; });
        const btn = document.createElement('button'); btn.id = 'forgedBtn';
        btn.addEventListener('click', () => {
          const popup = window.open(`${walletOrigin}/?authorize=1`, `forged-${ty}-${Math.random()}`, 'width=480,height=680');
          window.addEventListener('message', (ev) => { if (ev.origin !== walletOrigin || ev.source !== popup || !ev.data) return; if (ev.data.type === 'mode3-authorize-ready') { popup.postMessage({ type: ty, ...req }, walletOrigin); return; } if (ev.data.type === `${ty}-result`) window.__forgedResolve(ev.data.result); });
        });
        document.body.appendChild(btn);
      }, { walletOrigin: wallet.base, type, request });
      const [popup] = await Promise.all([context.waitForEvent('page'), fromPage.click('#forgedBtn')]);
      const result = await fromPage.evaluate(() => Promise.race([window.__forged, new Promise((r) => setTimeout(() => r({ timeout: true }), 60_000))]));
      if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 15_000 }).catch(() => {});
      return result;
    };
    // (a) rp2 페이지가 rp1 의 인증서를 들고 로그인 요청 — 메시지 오리진(rp2) ≠ 인증서 오리진(rp1)
    const rp2Page = await context.newPage(); await rp2Page.goto(`${rp2.base}/`); await waitText(rp2Page, '#walletMode', '사용자 비밀=브라우저');
    const a = await forged(rp2Page, 'mode3-authorize', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: '11', r_rp: '12', serviceName: 'x' });
    assert.equal(a.reason, 'origin_mismatch', j(a));
    // (b) rp2 가 rp1 세션의 r_s 로 재검증 — 세션 오리진이 다르다
    const info2 = (await rp2.get('/api/mode3/rp_info')).body;
    const b = await forged(rp2Page, 'mode3-revalidate', { arid: info2.arid, origin: info2.origin, r_s: sessionsBefore[0] });
    assert.equal(b.reason, 'no_session', j(b));
    // (c) mode3-config 는 RP 오리진이면 registered·rpCount·sessions 만(uid 없음)
    const c = await forged(rp2Page, 'mode3-config', { origin: info2.origin });
    assert.equal(c.ok, true); assert.equal(c.registered, true); assert.equal(typeof c.rpCount, 'number'); assert.ok(!('uid' in c), j(c));
    await rp2Page.close();
  });
  await t('B5 두 번째 RP(zkTWO) 로그인: 다른 계정 주소, health.rpCount=2, RP 페이지 브랜드 zkTWO', async () => {
    const rp2Page = await context.newPage(); await rp2Page.goto(`${rp2.base}/`); await waitText(rp2Page, '#walletMode', '사용자 비밀=브라우저');
    assert.equal(await rp2Page.evaluate(() => document.body.dataset.brand), 'zkTWO');
    await viaPopup(async () => { await rp2Page.click('#loginBtn'); await rp2Page.click('#idpLoginBtn'); }, approve);
    await waitText(rp2Page, '#verdict', '로그인 성공', 120_000);
    const sessions = Object.values((await idbDump(userPage)).sessions);
    const accounts = new Set(sessions.map((s) => s.account)); assert.ok(accounts.size >= 2, 'RP 마다 다른 계정 주소');
    await userPage.click('#refreshBtn');
    await userPage.waitForFunction(async () => (await (await fetch('/mode3/health')).json()).rpCount >= 2, undefined, { timeout: 15_000 });
    await rp2Page.close();
  });
  await t('B6 증명 키 캐시: 새 탭에서 페이지를 열면 /zk/*.zkey 를 다시 받지 않는다(Cache API 히트)', async () => {
    const p2 = await context.newPage(); const zkFetches = [];
    p2.on('request', (r) => { if (r.url().includes('/zk/') && r.url().endsWith('.zkey')) zkFetches.push(r.url()); });
    await p2.goto(`${wallet.base}/`); await p2.waitForSelector('#mainView:not([hidden])'); await waitText(p2, '#zkProgress', '준비', 60_000);
    assert.equal(zkFetches.length, 0, `네트워크로 다시 받았다: ${j(zkFetches)}`);
    await p2.close();
  });
  await t('B7 모두 지우기: 확인 → IndexedDB 가 비고 미등록·금고 없음으로 돌아간다, 재등록은 IdP 가 409(already registered) 로 막는다(재시연 세트 필요)', async () => {
    userPage.once('dialog', (d) => d.accept());
    await userPage.click('#wipeBtn');
    await waitText(userPage, '#vaultBadge', '없음', 10_000);
    assert.deepEqual(await idbDump(userPage), {});
    await userPage.fill('#vaultPw', PW); await userPage.fill('#vaultPw2', PW); await userPage.click('#registerBtn');
    await waitText(userPage, '#registerResult', 'register_failed', 60_000);
  });
```
`startIsolatedMode3Stack({ userMode: 'web', autoRelay: true, extraRps: [{ name: 'zkTWO', env: { MODE3_ALLOWED_COUNTRIES: 'KR,JP' } }] })` 로 바꾼다.

- [ ] **Step 2: 실행** — `node tests/test_mode3_user_web.mjs` → A1~A7·B1~B7 전부 ok. 실패한 각본은 페이지·팝업 결함이다 — 고치고 다시 돈다(각본을 깎아 맞추지 않는다).
- [ ] **Step 3: 회귀** — `bash scripts/run_tests.sh browser`(세 테스트), `bash scripts/run_tests.sh unit`.
- [ ] **Step 4: 커밋** — `test(user-web): 브라우저 각본 B — 잠금·시연 거절·오리진 위조·두 번째 RP·캐시·초기화`.

---

### Task 11: 런북·스펙 상태·테스트 그룹 정리

**Files:**
- Modify: `docs/MODE3_DEMO.md` — (1) "프로세스와 포트" 표에 행 `| 사용자 페이지(web 모드, 선택) | :5100 | npm run user:build && node mode3_user_static.js | — (비밀은 브라우저 IndexedDB 에 암호문) — 에이전트 대신 띄운다 |`; (2) "MetaMask / Snap 경로" 절 다음에 새 절 `## 브라우저 전용 사용자 페이지 (web 모드, 2026-10-15)` — 구성(정적 서버·번들·IdP CORS·RP 릴레이), 기동 순서(IdP → `npm run user:build` → `node mode3_user_static.js` → RP), 금고(등록 때 비밀번호, 30분 자동 잠금, "잠그기", R3 의 보안 메모), 팝업 프로토콜 5종 표(스펙 §4.2 그대로 + R5·R12), 릴레이 검사 6단계와 사유(`relay_*`), env(`MODE3_RELAY_GAS_CAP`·`MODE3_RELAY_RATE`), 한계(XSS·사이트 데이터 삭제·릴레이 검열·auid_s 노출 그대로·참조 코드 대조 생략), 다른 기계(`build/mode3` 묶음 + `npm run user:build`; Chrome/Edge/Firefox 최신); (3) "하지 말 것 / 재시연" 의 재시연 세트 문단 끝에 `**web 모드로 시연 중이었다면 사용자 페이지의 "모두 지우기"(또는 127.0.0.1:5100 의 사이트 데이터 삭제)도 함께 한다** — Snap 초기화에 해당한다.`; (4) "엔드포인트" 절에 `POST /api/mode3/relay`·`GET /api/mode3/relay/:txHash`·정적 서버의 `GET /user/config`·`POST /wallet/presence`; (5) "RP 거절 사유" 표에 `relay_inactive`·`relay_bad_target`·`relay_bad_calldata`·`relay_gas`·`relay_rate_limited`, 사용자 쪽 `locked`·`bad_password`·`zk_assets_unavailable`·`storage_unavailable`; (6) "테스트" 절에 `tests/test_mode3_user_static.mjs`·`test_cia_cors.mjs`·`test_mode3_rp_relay.mjs`·`test_mode3_user_core.mjs`(chain)·`test_mode3_user_web.mjs`(browser)·`test_browser_sha256.js`·`test_secret_box.mjs`(unit) 한 줄씩.
- Modify: `docs/superpowers/specs/2026-10-15-mode3-browser-user-page-design.md` 3행 상태를 `**승인(2026-10-15) — 구현 계획 docs/superpowers/plans/2026-10-15-mode3-browser-user-page.md 의 "스펙 대비 결정" R1~R12 가 우선한다**` 로.
- Verify: `scripts/run_tests.sh` 에 Task 1·2·5·6·7·8·9 가 넣은 줄이 전부 있는지, `bash scripts/run_tests.sh unit` 이 통과하는지.

- [ ] **Step 1: 문서 수정**(위 목록대로; 기존 절의 문체·표 형식을 따른다. 수치는 이 계획과 코드의 값만 쓴다 — 추측 금지).
- [ ] **Step 2: `bash scripts/run_tests.sh unit`** 통과. `grep -n "test_mode3_user\|test_cia_cors\|test_mode3_rp_relay\|test_browser_sha256\|test_secret_box" scripts/run_tests.sh` 로 7개 줄 확인.
- [ ] **Step 3: 커밋** — `docs(mode3): web 모드(브라우저 사용자 페이지·릴레이) 런북·사유 표·테스트 목록, 스펙 상태 갱신`.

---

## 자기 검토 (2026-10-15)

- **스펙 커버리지**: §2 구성요소(Task 5·8·9), §3 상태(Task 8 — `rcl` 제외 R2, `unlock` 추가 R3), §4.1 흐름(Task 8 코어·Task 9 UI), §4.2 팝업 5종(Task 9), §4.3 동기화(Task 8 chain.js), §5.1 릴레이(Task 7), §5.2 RP 페이지(Task 9), §5.3 IdP CORS(Task 6), §5.4 에이전트 불변(Global), §6 shim·워커(Task 1·3·4·9), §7 화면(Task 9), §8 사유(Task 9 strings), §9 메모(Task 11 런북), §10 런북(Task 11), §11 테스트(Task 1·2·5·6·7·8·9·10). 빠진 요구는 없다.
- **자리표시자**: Task 8 Step 5 의 `/* … */` 는 **존재하는 코드(`mode3_wallet_agent.js` 의 명시한 줄 범위)를 명시한 치환 규칙으로 옮기라는 지시**다 — 새로 지어낼 내용이 아니라 여기 다시 베끼지 않았다. 그 밖에 TBD·TODO 없음.
- **타입·이름 일관성**: `createUserCore({ kv, config, provider, canonProvider, fetch, fullProve:{idp,cred}, now })`(Task 8 정의·Task 8 테스트·Task 9 user.js 사용 동일); `createProver().fullProve.{idp,cred}`(Task 9) ↔ `fullProve.idp/cred`(Task 8); 팝업 메시지 `type`·`${type}-result`(Task 9 popup.js·rp.html·Task 10 forged 동일); 정적 서버 라우트(Task 5 정의 ↔ Task 5 테스트 ↔ Task 9 user.js `/user/config`·`/wallet/presence` ↔ Task 10 B5 `/mode3/health`); 릴레이 봉투 `{ ok, reason, detail }`·사유 5개(Task 7 ↔ Task 8 테스트 ↔ Task 9 strings ↔ Task 11 문서); vault API(`hasVault/isUnlocked/setup/unlock/lock/key/readSecrets/writeSecrets/changePassword/reset`, Task 8 정의 ↔ Task 8 테스트 ↔ Task 9 `withUnlock`).
- **환경 전제**: Task 4 는 `npm install` 로 `package-lock.json` 을 바꾼다(네트워크 필요). browser 그룹은 Chrome 이 있어야 한다. Task 7·8·9·10 은 격리 스택 기동 포함 각 3~6분이다.
