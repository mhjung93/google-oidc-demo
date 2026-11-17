# Mode 3 패스키 모드 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 스냅 모드 옆에 세 번째 비밀 공급 모드 `MODE3_WALLET_SECRETS=passkey` 를 더한다 — salt 는 패스키 PRF 로 매번 유도하고 어디에도 저장하지 않으며, 증인 없는 세션은 zk 스냅 화면에서 한 번에 복구한다.

**Architecture:** 에이전트는 스냅 모드의 증인 경로(요청마다 witness, 세션 증인은 메모리)를 "증인 모드" 로 일반화해 passkey 에도 쓰고, `blind_u`·동의 기록·credential ID 만 파일에 더 둔다. 화면은 스냅 RPC 와 같은 이름·입출력의 어댑터(`mode3/common/passkey_store.js`)를 두고 `invokeSnap` 진입점이 모드에 따라 스냅 또는 어댑터로 보낸다. 서비스 페이지는 passkey 를 팝업 경로로 보고, 새 사유 `session_restore_required` 에 zk 스냅 화면 안내를 띄운다.

**Tech Stack:** Node 22 · Express(에이전트) · 전역 스크립트 HTML(`mode3/*.html`, `mode3/common/*.js`) · WebAuthn PRF 확장 · Playwright(설치된 Chrome) · hardhat 노드(:8545)

**Spec:** `docs/superpowers/specs/2026-11-17-mode3-passkey-mode-design.md`

## Global Constraints

- 모든 커밋·브랜치 작업은 **사용자 승인 뒤**(CLAUDE.md). 각 Task 의 Commit 단계는 승인을 받고 한다. `git add` 는 경로 지정만.
- 회로·zkey·컨트랙트·IdP(`cia.js`)·스냅(`snap-mode3/`)은 바꾸지 않는다. `npm run zk:*` 금지. 새 의존성 금지.
- 스냅 모드·파일 모드의 동작은 바꾸지 않는다 — 기존 테스트(`unit`, `snap`, `contract`, `chain`, `browser`)가 그대로 통과해야 한다.
- salt 유도식(spec P2, 바꾸지 않는다): PRF 입력 `eval.first = utf8("zkd-s_u-v1")`, `s_u = BigInt(SHA-256(utf8("zkd-passkey-s_u-v1") ‖ prfFirst32)) >> 6n`, 0 이면 `passkey_bad_salt`. 결과는 10진 문자열, [1, 2^250).
- salt(`s_u`)는 에이전트 파일·`localStorage`·`sessionStorage`·IndexedDB 어디에도 쓰지 않는다(P3).
- 패스키 모드는 `localhost` 전용(P6): RP ID `'localhost'`, 에이전트 지갑 오리진 기본값 `http://localhost:<PORT>`, `MODE3_WALLET_PUBLIC_ORIGIN` 호스트가 IP 면 기동 거부.
- 사유 문자열(spec §5, 철자 그대로): `passkey_wrong_origin`, `passkey_unsupported`, `passkey_prf_unsupported`, `passkey_unstable`, `passkey_cancelled`, `passkey_mismatch`, `passkey_setup_required`, `passkey_already_set`, `passkey_bad_salt`, `session_restore_required`.
- 응답·문서는 한국어, 기존 문체 유지. 새 테스트 파일은 `scripts/run_tests.sh` 의 해당 그룹에 넣는다.
- 체인 테스트는 동시에 돌리지 않는다. :8545 가 비어 있으면 직접 `ETHERNAL_WORKSPACE= ETHERNAL_API_TOKEN= npx hardhat node` 를 띄우고 끝나면 내린다. 사용자의 :5100/:8082 는 건드리지 않는다.

## Rulings (계획 단계에서 정한 것 — 스펙이 말하지 않은 곳)

- **R-A 브라우저 테스트의 패스키:** CDP 가상 인증기는 탭(대상)마다 따로라서, 승인 팝업(새 창)은 zk 스냅 화면에서 만든 패스키를 볼 수 없고 PRF 비밀은 CDP 로 옮길 수 없다. 그래서 흐름 시험(가입·로그인·복구)은 **결정적 WebAuthn 스텁**(`tests/helpers/webauthn_stub.js`, 모든 페이지에 init script — 지금의 `ethereum_stub.js` 와 같은 방식)으로 하고, **실제 Chrome WebAuthn 코드 경로**는 zk 스냅 화면 한 탭에서 CDP 가상 인증기로 따로 시험한다(만들기·재계산 같은 값·`hasPrf:false` 거절). 스펙 §7 의 "CDP 가상 인증기" 를 이렇게 나눠 지킨다. 틀렸을 때 대가: 스텁과 실제 API 의 작은 차이를 놓칠 수 있다 — 가상 인증기 케이스가 그 경로를 덮는다.
- **R-B zk 스냅 화면의 "보내기" 탭:** 패스키 모드에는 MetaMask 가 없으므로 파일 모드처럼 `/wallet/tx`(에이전트 릴레이어 `MODE3_RELAYER_INDEX`)로 보낸다. 에이전트의 `/wallet/tx` 는 `SECRETS === 'snap'` 일 때만 `use_tx_prepare` 로 거절하게 둔다. 대가: 패스키 모드의 자기 출금은 에이전트 릴레이어 잔고에 기댄다(데모 hardhat 계정이라 문제 없음).
- **R-C `/wallet/secrets/salt`** 는 파일 모드 전용 그대로(패스키 모드에서 409 `snap_mode`). 화면의 "salt 보기" 는 어댑터의 `showSalt`(패스키 한 번)로 한다.
- **R-D `/wallet/register/resume`·`restoreSnapIfEmpty`·`attrsChanged` 응답** 은 스냅 전용 그대로 — 패스키 모드에서는 에이전트 자체가 등록 보관자다(spec §4.3).
- **R-E `passkey_mismatch` 판정:** 화면에는 Poseidon 이 없으므로 auid 를 화면에서 계산하지 않는다. 어댑터는 **돌아온 credential ID 가 에이전트에 저장된 것과 다르면** `passkey_mismatch` 로 멈추고, 그래도 다른 salt 가 들어가면 에이전트의 `validateWitness` auid 대조(`bad_witness`)가 막는다. 대가: "이미 있는 패스키 쓰기" 에서 credential ID 가 없고 등록만 남은(손으로 고친 상태 파일 같은) 경우는 다음 로그인 때 `bad_witness` 로 드러난다.

## Review Focus

1. **팝업 하나에 패스키 두 번:** 가입 팝업이 `prepareRegister` 와 `consentLogin` 을 둘 다 부를 때 패스키 창이 두 번 뜨면 안 된다 — 스텁의 `get` 호출 수로 고정(Task 3).
2. **다른 오리진 철자:** `127.0.0.1:5100` 으로 연 zk 스냅 화면·승인 팝업이 패스키를 부르지 않고 `passkey_wrong_origin` 만 보인다(Task 3).
3. **복구 중 일부 실패:** 세션 둘 중 하나가 `user_cred_mismatch` 여도 다른 하나는 복구되고 결과가 세션별로 나온다(Task 4).
4. **재시작 뒤 재검증 응답 사유:** 패스키 모드에서 `needs_consent` 가 새지 않는다 — `/wallet/revalidate`·`/wallet/tx/prepare`·`/wallet/tx`·`/wallet/session/revoke` 모두 `session_restore_required`(증인이 필요 없는 `/wallet/request` 는 그대로 200)(Task 2).
5. **s_u 가 저장소에 남음:** 가입·로그인·복구·salt 보기 뒤 에이전트 상태 파일과 브라우저 저장소 어디에도 s_u 10진 문자열이 없다(Task 2·Task 4).

---

## File Structure

| 파일 | 책임 | Task |
|---|---|---|
| `mode3/common/passkey_store.js` (새) | 전역 `window.Mode3Passkey`: 유도식(`saltFromPrf`), WebAuthn 호출(`createPasskey`, `derivePrf`), 스냅 RPC 대응 어댑터(`createPasskeyStore`) | 1, 3 |
| `mode3/common/strings.js` | 새 사유 10개·새 문구 키 | 1 |
| `mode3_wallet_agent.js` | `passkey` 모드·라우트·`session_restore_required`·`hasWitness` | 2 |
| `lib/mode3_secret_source.js` | `stripSecrets(registration, { keepBlind })` | 2 |
| `mode3/wallet.html` | 진입점 분기, 설정 카드, 오리진 안내, 세션 복구 카드, 내 계정, 보내기 | 3, 4 |
| `mode3/rp.html` | passkey 를 팝업 경로로, `session_restore_required` 안내 | 3, 4 |
| `tests/test_mode3_passkey_salt.mjs` (새, unit) | 유도식 | 1 |
| `tests/test_mode3_wallet_passkey.mjs` (새, chain) | 에이전트 passkey 모드 | 2 |
| `tests/helpers/webauthn_stub.js` (새) | 결정적 WebAuthn 스텁 init script | 3 |
| `tests/test_mode3_passkey_browser.mjs` (새, browser) | 화면 흐름 + 가상 인증기 | 3, 4 |
| `tests/test_mode3_demo_strings.js` | `REASONS` 에 새 사유 | 1 |
| `scripts/run_tests.sh` | 새 테스트 3개 등록 | 1, 2, 3 |
| `scripts/demo_web_reset.sh`, `scripts/demo_split_start.sh` | `WALLET_MODE=passkey` | 5 |
| `docs/MODE3_DEMO.md` | 패스키 모드 절 | 5 |

---

### Task 1: salt 유도식과 사유 사전

**Files:**
- Create: `mode3/common/passkey_store.js`
- Modify: `mode3/common/strings.js`, `tests/test_mode3_demo_strings.js`, `scripts/run_tests.sh`(UNIT)
- Test: `tests/test_mode3_passkey_salt.mjs`

**Interfaces:**
- Produces: 전역 `window.Mode3Passkey = { PRF_INPUT: Uint8Array, SALT_DOMAIN: 'zkd-passkey-s_u-v1', saltFromPrf(prfFirst: ArrayBuffer|Uint8Array): Promise<string> }`. 32바이트가 아니면 `Error` 의 `reason = 'passkey_prf_unsupported'`, 결과 0 이면 `reason = 'passkey_bad_salt'`. `crypto.subtle` 만 쓴다(Node 22 의 `globalThis.crypto` 로도 돈다). 이 파일은 strings.js 처럼 전역 스크립트다(`vm.runInThisContext` 로 테스트에서 읽는다).
- Produces: 사전 항목 10개(Global Constraints 의 철자), `where` 는 spec §5 표.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_passkey_salt.mjs`(strings 테스트처럼 `globalThis.window = {}` + `vm.runInThisContext`):
  - `saltFromPrf(new Uint8Array(32))` 의 결과 = `(BigInt('0x' + sha256hex(utf8('zkd-passkey-s_u-v1') ‖ 32×0x00)) >> 6n).toString()` (테스트 안에서 `node:crypto` 로 기대값 계산).
  - 결과 `BigInt` 가 `1n` 이상 `1n << 250n` 미만.
  - 같은 입력 두 번 → 같은 값, 첫 바이트만 다른 입력 → 다른 값.
  - 31바이트 입력 → reject, `e.reason === 'passkey_prf_unsupported'`.
  - `PRF_INPUT` 바이트 = `utf8('zkd-s_u-v1')`.
  - `tests/test_mode3_demo_strings.js` 의 `REASONS` 에 새 사유 10개를 더한다(같은 커밋).
- [ ] **Step 2:** `node tests/test_mode3_passkey_salt.mjs` → FAIL(파일 없음). `node tests/test_mode3_demo_strings.js` → FAIL(사전에 사유 없음).
- [ ] **Step 3:** `mode3/common/passkey_store.js` 에 위 세 멤버를 구현하고, `strings.js` 의 사유 사전(기존 `needs_consent` 항목과 같은 모양 `{ where, ko: { title, cause, action }, en: {…} }`)에 10개를 더한다. `session_restore_required` 의 조치는 "zk 스냅 화면(http://localhost:5100)의 '세션 복구' 를 누르세요. 다시 로그인할 필요는 없습니다." 취지.
- [ ] **Step 4:** 두 테스트 PASS. `bash scripts/run_tests.sh unit` 전부 통과(UNIT 배열에 새 파일을 넣은 뒤).
- [ ] **Step 5: Commit**(승인 뒤) — `feat(mode3): 패스키 모드 1 — salt 유도식(PRF)과 사유 사전`

---

### Task 2: 에이전트 passkey 모드

**Files:**
- Modify: `mode3_wallet_agent.js`, `lib/mode3_secret_source.js`, `scripts/run_tests.sh`(CHAIN 그룹 — `test_mode3_wallet_snap.mjs` 옆)
- Test: `tests/test_mode3_wallet_passkey.mjs`(구성은 `tests/test_mode3_wallet_snap.mjs` 를 따른다 — `startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'passkey' }, walletHost: 'localhost' })`, 페이지 대신 `createReadySnapSim()` 의 salt 로 증인을 만든다)

**Interfaces:**
- Consumes: 없음(Task 1 과 독립).
- Produces(HTTP, 지갑 오리진, `Sec-Fetch-Site` 가 있으면 `same-origin` 만 — 아니면 403 `cross_site`):
  - `GET /wallet/config` → `secrets: 'passkey'`, `snapId: null`.
  - `GET /wallet/passkey/state` → `{ passkey: { credentialId, createdAt } | null, registration: { uid, auid, slot, attrs, profile, provider } | null, userCred: { C_u_pt, Cf_u, blind_u, issuedAt } | null, consents: { [origin]: { arid, allowAgent, grantedAt } } }`. passkey 모드가 아니면 409 `not_passkey_mode`.
  - `PUT /wallet/passkey/credential { credentialId }` → `{ ok: true }`; 다른 값이 있으면 409 `passkey_already_set`; base64url 이 아니면 400 `bad_credential_id`.
  - `DELETE /wallet/passkey/credential` → `{ ok: true }`; 등록이 있으면 409 `registered`.
  - `POST /wallet/passkey/consent { origin, arid, allowAgent: '0'|'1' }` → `{ ok: true }`.
  - `GET /wallet/status` 의 각 세션에 `hasWitness: boolean`(file 모드는 늘 `true`).
  - 증인 없는 세션: passkey 모드는 409 `session_restore_required`(snap 은 지금처럼 `needs_consent`).
  - `POST /wallet/session/witness` 는 snap·passkey 모두 받는다.
  - `stripSecrets(registration, { keepBlind = false } = {})` — `keepBlind` 면 `userCred` 를 `{ C_u_pt, Cf_u, blind_u, issuedAt }` 로 남긴다.

- [ ] **Step 1: 실패하는 테스트**(`tests/test_mode3_wallet_passkey.mjs`, 케이스 이름 그대로):
  - `config 가 passkey 를 알린다` — `secrets === 'passkey'`, `snapId === null`, `walletOrigin` 이 `http://localhost:`로 시작.
  - `IP 오리진이면 passkey 모드 기동 거부` — `MODE3_WALLET_PUBLIC_ORIGIN=http://127.0.0.1:<빈 포트>` 로 에이전트를 직접 띄우면 종료 코드 ≠ 0, stderr 에 `localhost`.
  - `credential 라우트` — PUT 성공 → 같은 값 PUT 200 → 다른 값 409 `passkey_already_set` → `Sec-Fetch-Site: cross-site` GET 403 → (등록 뒤) DELETE 409 `registered`.
  - `가입·로그인은 증인을 요구하고 s_u 를 파일에 쓰지 않는다` — 증인 없는 `/wallet/login` 400 `witness_required`; 증인 있는 로그인 200; 상태 파일 문자열에 s_u 10진 값이 없다; `GET /wallet/passkey/state` 의 `userCred.blind_u` 가 10진 문자열.
  - `동의 기록` — `POST /wallet/passkey/consent` 뒤 state 의 `consents[origin].allowAgent === '1'`.
  - `재시작 뒤 session_restore_required, 세션 증인으로 복구` — `stack.restartWallet()` → `/wallet/status` 세션 `hasWitness === false` → `/wallet/revalidate`·`/wallet/tx/prepare`·`/wallet/tx`·`/wallet/session/revoke` 모두 409 `session_restore_required`(`needs_consent` 가 어디서도 나오지 않는다) → `/wallet/session/witness { r_s, witness, allowAgent }` 200 → `hasWitness === true` → 재검증 200.
  - `파일 모드 hasWitness 는 늘 true` — 기존 파일 모드 스택이 있는 테스트(`tests/test_mode3_wallet_agent.mjs`)에 한 줄 단언 추가.
- [ ] **Step 2:** `node tests/test_mode3_wallet_passkey.mjs` → FAIL(`MODE3_WALLET_SECRETS 는 'file' 또는 'snap'` 로 기동 실패).
- [ ] **Step 3: 구현** — `mode3_wallet_agent.js`:
  - `:80` 허용값에 `'passkey'`. `const WITNESS_MODE = SECRETS !== 'file';`
  - `:82` 지갑 오리진: passkey 면 기본 `http://localhost:${PORT}`, 주어진 값의 `new URL(...).hostname` 이 IP(`net.isIP`)면 `throw new Error('passkey 모드는 localhost 오리진만 — …')`.
  - 분기 분류(현재 줄 번호): **`WITNESS_MODE` 로 바꿈** — 327, 670, 698, 712, 725, 739, 860, 871, 880, 979, 1001, 1239, 1559. **`'snap'` 그대로** — 507 의 `snapId`(passkey 면 `null`), 752(resume), 780(attrsChanged), 1510(`/wallet/tx` 거절, R-B). **`'file'` 그대로** — 375, 453, 479, 480, 519.
  - `secretSourceFor`(:374): 증인 없음 사유를 `rsKey ? (SECRETS === 'passkey' ? 'session_restore_required' : 'needs_consent') : 'witness_required'`. 이 사유를 받는 라우트들이 409 로 내보내는지 확인(지금 `needs_consent` 를 409 로 바꾸는 곳 전부 — `grep -n "needs_consent" mode3_wallet_agent.js`).
  - 상태: `state.passkey`, `state.consents` 를 상태 파일 읽기·쓰기에 더한다(없으면 `null`/`{}`). `/wallet/reset`(데모 리셋)은 등록·세션·`consents` 를 지우되 **`passkey` 는 남긴다**.
  - C_u 저장: passkey 모드에서 로그인이 새 C_u 를 받으면(`src.pending.userCredIssued`) `state.registration.userCred` 에 `blind_u` 까지 저장한다(`stripSecrets(…, { keepBlind: true })` 또는 직접 대입). snap 모드는 지금처럼 공개 부분만.
  - 위 Interfaces 의 라우트 4개와 `hasWitness`.
  - `lib/mode3_secret_source.js` `stripSecrets` 에 `{ keepBlind }`.
- [ ] **Step 4:** `node tests/test_mode3_wallet_passkey.mjs` 전부 ok. 회귀: `node tests/test_mode3_wallet_snap.mjs`, `node tests/test_mode3_wallet_agent.mjs`, `node tests/test_mode3_secret_source.js` 통과.
- [ ] **Step 5: Commit**(승인 뒤) — `feat(mode3): 패스키 모드 2 — 에이전트 MODE3_WALLET_SECRETS=passkey, session_restore_required, hasWitness`

---

### Task 3: zk 스냅 화면·승인 팝업·서비스 팝업 경로

**Files:**
- Modify: `mode3/common/passkey_store.js`, `mode3/wallet.html`, `mode3/rp.html`, `scripts/run_tests.sh`(BROWSER)
- Create: `tests/helpers/webauthn_stub.js`, `tests/test_mode3_passkey_browser.mjs`

**Interfaces:**
- Consumes: Task 1 `Mode3Passkey.saltFromPrf`, `PRF_INPUT`; Task 2 의 라우트·`secrets: 'passkey'`.
- Produces(`window.Mode3Passkey` 에 더함):
  - `createPasskey(): Promise<{ credentialId: string, s_u: string }>` — spec §4.2 의 `create` 옵션(rp `{ id: 'localhost', name: 'zk 스냅' }`, user id 무작위 16바이트, `residentKey: 'required'`, `userVerification: 'required'`, `pubKeyCredParams` ES256·RS256, `prf.eval.first = PRF_INPUT`) → `prf.enabled !== true` 면 `passkey_prf_unsupported` → `derivePrf` 한 번 → 생성 때 PRF 결과가 있으면 대조, 다르면 `passkey_unstable`.
  - `derivePrf({ credentialId?: string }): Promise<{ credentialId: string, s_u: string }>` — `credentialId` 가 없으면 `allowCredentials` 없이(이미 있는 패스키 쓰기).
  - 오류 매핑: `location.hostname !== 'localhost'` → `passkey_wrong_origin`(WebAuthn 을 부르기 전), `PublicKeyCredential` 없음·`!isSecureContext` → `passkey_unsupported`, `NotAllowedError`·`AbortError` → `passkey_cancelled`, PRF 결과 없음 → `passkey_prf_unsupported`. 오류는 `Error` 의 `.reason`.
  - `createPasskeyStore({ fetchJson, confirmBox, promptBox }): { call(method, params): Promise<any>, withSalt(fn): Promise<any> }` — spec §4.1 표대로. `withSalt(fn)` 안에서는 `derivePrf` 를 한 번만 부르고 결과를 재사용, `fn` 이 끝나면(성공·실패 모두) 버린다. `fetchJson` 은 화면의 기존 `postJson` 계열, `confirmBox(title, lines): Promise<boolean>`, `promptBox(title, lines, placeholder): Promise<string|null>` 는 화면이 준다.
- Produces(`tests/helpers/webauthn_stub.js`): `buildWebAuthnStub({ secretHex, prf = true, cancel = false }): string`(init script 문자열). 스텁은 `navigator.credentials.create/get` 을 바꾸고 PRF = HMAC-SHA256(secret, `"WebAuthn PRF\0" ‖ input`) 를 돌려준다. `window.__webauthnCalls = { create: n, get: n }` 를 센다. 같은 `secretHex` 를 모든 페이지(팝업 포함 — `context.addInitScript`)에 넣으면 같은 패스키로 동작한다.

- [ ] **Step 1: 실패하는 테스트**(`tests/test_mode3_passkey_browser.mjs` — 스택·브라우저·IdP 인증 창 처리는 `tests/test_mode3_browser.mjs` 의 `launchBrowser`·`completeIdpAuth` 등을 따른다; 스택은 `startIsolatedMode3Stack({ walletEnv: { MODE3_WALLET_SECRETS: 'passkey' }, walletHost: 'localhost', ciaEnv: { CIA_ISSUE_AUTH: 'code' }, autoRelay: true })`):
  - `설정 카드: 패스키 만들기 → credential 저장, 탭이 열린다` — 스텁 컨텍스트에서 zk 스냅 화면 → "패스키 만들기" → `/wallet/passkey/state` 의 `passkey.credentialId` 존재, MetaMask 연결 카드 숨김.
  - `127.0.0.1 로 열면 패스키를 부르지 않고 안내만` — `http://127.0.0.1:<walletPort>/` → `passkey_wrong_origin` 문구, `__webauthnCalls.get === 0 && create === 0`.
  - `zkID 가입 → zkONE 로그인, 팝업 하나에 패스키 한 번` — 가입 팝업·로그인 팝업 각각에서 `__webauthnCalls.get === 1`; 서비스에 "로그인 성공".
  - `PRF 없는 인증기는 거절` — `buildWebAuthnStub({ prf: false })` 컨텍스트에서 만들기 → `passkey_prf_unsupported` 문구, credential 저장 안 됨.
  - `다른 패스키는 passkey_mismatch` — 등록된 상태에서 다른 `secretHex` 의 스텁 컨텍스트로 zkONE 로그인 팝업 → 스텁이 다른 credential ID 를 돌려줌 → `passkey_mismatch` 문구, 서비스에 로그인 안 됨(R-E). 스텁은 `allowCredentials` 를 무시하고 자기 credential 을 돌려준다.
  - `실제 Chrome WebAuthn(CDP 가상 인증기)` — 스텁 없는 새 컨텍스트의 zk 스냅 화면 탭에 `WebAuthn.addVirtualAuthenticator({ protocol:'ctap2', ctap2Version:'ctap2_1', transport:'internal', hasResidentKey:true, hasUserVerification:true, isUserVerified:true, automaticPresenceSimulation:true, hasPrf:true })` → 만들기 성공 → 페이지에서 `Mode3Passkey.derivePrf({credentialId})` 두 번 같은 `s_u`; `hasPrf:false` 인증기로 바꾸면 `passkey_prf_unsupported`. (이 케이스는 credential 을 저장한 뒤 `DELETE /wallet/passkey/credential` 로 되돌린다.)
- [ ] **Step 2:** `node tests/test_mode3_passkey_browser.mjs` → FAIL(설정 카드에 패스키 버튼 없음).
- [ ] **Step 3: 구현**
  - `passkey_store.js`: 위 Produces.
  - `wallet.html`: `<script src="/common/passkey_store.js">` 추가. `const PASSKEY = () => cfg.secrets === 'passkey'`. `invokeSnap(method, params)`(:541)는 passkey 면 `passkeyStore.call(method, params)` 로. `ensureConnected`(:495)·팝업의 `connect`(:1093)는 passkey 면 MetaMask 없이 `true`. `applyGate`(:302)·`refreshSetup`(:1834)는 passkey 면 "credentialId 없음 = 설정 필요" 로 보고, 설정 카드에 "패스키 만들기"·"이미 있는 패스키 쓰기" 두 버튼(백업 행·불러오기 행은 숨김). `init`(:2412)에서 passkey 면 `applySnapMode()`(등록 안내 등 공통 부분) + 스냅 전용 요소(스냅 버전 줄·스냅 업데이트 버튼·MetaMask 상태) 숨김, 모드 표시 문구 키 `wallet_mode_passkey`. 오리진이 `localhost` 가 아니면 카드·탭 대신 `passkey_wrong_origin` 안내와 `http://localhost:<port>` 링크만.
  - 팝업(`processAuthorize`, :1091): passkey 면 요청 처리 전체를 `passkeyStore.withSalt(async () => …)` 로 감싸 패스키 한 번. `restoreSnapIfEmpty`(:769)는 passkey 면 `null` 을 돌려준다(R-D). 진입 조건 `cfg.secrets !== 'snap'`(:889, :1283) → `cfg.secrets === 'file'` 일 때만 거절.
  - `rp.html`: `:344`(배지 — `rp_wallet_passkey`), `:792`(팝업 경로), `:985`(출금 허용)에서 `'passkey'` 를 `'snap'` 과 같게.
  - `strings.js`: 새 문구 키(`wallet_mode_passkey`, `wallet_setup_passkey_new_btn`, `wallet_setup_passkey_existing_btn`, `rp_wallet_passkey`, `rp_wallet_passkey_note`)를 ko·en 으로.
- [ ] **Step 4:** 새 브라우저 테스트 전부 ok. 회귀 `node tests/test_mode3_browser.mjs`(스냅 모드 54건) 통과, `node tests/test_mode3_demo_strings.js` 통과.
- [ ] **Step 5: Commit**(승인 뒤) — `feat(mode3): 패스키 모드 3 — zk 스냅 화면 설정·승인 팝업·서비스 팝업 경로`

---

### Task 4: 세션 복구 카드·내 계정·보내기·데모 리셋

**Files:**
- Modify: `mode3/wallet.html`, `mode3/rp.html`, `mode3/common/strings.js`
- Test: `tests/test_mode3_passkey_browser.mjs`(케이스 추가)

**Interfaces:**
- Consumes: Task 2 `hasWitness`·`session_restore_required`·`/wallet/session/witness`·`DELETE /wallet/passkey/credential`; Task 3 `passkeyStore.withSalt`, `derivePrf`.
- Produces(화면 id — 테스트가 잡는다): `#restoreCard`, `#restoreList`(세션마다 `li[data-rs]`), `#restoreBtn`, `#restoreVerdict`(세션별 결과 `li[data-rs] .verdict`), `#showSaltBtn`, `#passkeyDisconnectBtn`.

- [ ] **Step 1: 실패하는 테스트**(같은 파일에 추가):
  - `에이전트 재시작 → 서비스는 복구 안내 → zk 스냅 화면 세션 복구 → 재검증 성공` — Task 3 의 로그인 뒤 `stack.restartWallet()` → zkONE 의 재검증(또는 출금)에 `session_restore_required` 문구와 zk 스냅 화면 링크 → zk 스냅 화면 `#restoreCard` 보임, 세션 1개 → `#restoreBtn` → `__webauthnCalls.get` 이 1 늘고 세션 결과 성공 → `#restoreCard` 숨김 → zkONE 재검증 "재검증 성공".
  - `복구는 세션별 결과` — zkTWO 에도 로그인한 뒤 재시작, 한 세션의 증인 거절을 `page.route('**/wallet/session/witness', …)` 로 그 `r_s` 만 409 `user_cred_mismatch` 로 바꿔 → 한 세션 성공, 한 세션 사유 표시.
  - `salt 보기는 패스키 한 번, 저장소에 s_u 가 없다` — "내 계정" → `#showSaltBtn` → salt 표시 → `localStorage`·`sessionStorage` 전체 값과 에이전트 상태 파일에 그 10진 문자열이 없다.
  - `보내기 탭은 에이전트 릴레이어로` — 로그인한 세션으로 소액 보내기 → "전송 성공".
  - `데모 리셋 뒤 같은 패스키로 다시 가입하면 같은 PPID` — 리셋 전 PPID 기록 → `/attr/dist/reset.json` epoch 변경(스택 헬퍼에 같은 방식이 있으면 그것) → 재가입·재로그인 → 같은 PPID, `passkey.credentialId` 그대로.
  - `연결 끊기는 등록이 없을 때만` — 등록 있음 → `#passkeyDisconnectBtn` 비활성(또는 409 문구), 리셋 뒤 → 성공, 설정 카드가 다시 보인다.
- [ ] **Step 2:** 새 케이스 FAIL(`#restoreCard` 없음).
- [ ] **Step 3: 구현**
  - `wallet.html` 세션 복구 카드(passkey 모드만, "서비스" 탭 위 — `#sessionsCard`(:159) 앞): `/wallet/status` 의 `hasWitness === false` 세션 목록(서비스 이름·오리진·에이전트 허용) → `#restoreBtn` → `passkeyStore.withSalt` 안에서 `/wallet/passkey/state` 로 증인 조립(`{ uid, s_u, attrs, userCred }`) → 세션마다 `/wallet/session/witness { r_s, witness, allowAgent: 세션.allowAgent }` → 세션별 결과(성공 / 사유 사전). 진입·`visibilitychange` 때 다시 읽는다.
  - "내 계정": passkey 면 salt 행은 가림 + `#showSaltBtn`(어댑터 `showSalt`), `#passkeyDisconnectBtn`(등록 있으면 비활성 + 안내), 스냅 전용 행(스냅 버전·백업 다시 만들기) 숨김.
  - 보내기(:2286): passkey 면 `sendTxViaRelayer()`(R-B). 증인 없음이면 `session_restore_required` 문구.
  - 데모 리셋(`checkDemoReset`·`snapResetNow`, :2354·:2375): passkey 면 MetaMask·스냅 없이 에이전트 리셋만, credentialId 유지.
  - `rp.html`: 재검증·요청·출금 응답의 `session_restore_required` → 사유 사전 안내 + `walletCfg.walletOrigin` 링크, 세션은 지우지 않는다.
  - `strings.js`: 카드·버튼 문구 키(ko·en).
- [ ] **Step 4:** `node tests/test_mode3_passkey_browser.mjs` 전부 ok. 회귀 `node tests/test_mode3_browser.mjs`, `node tests/test_mode3_demo_strings.js`.
- [ ] **Step 5: Commit**(승인 뒤) — `feat(mode3): 패스키 모드 4 — zk 스냅 화면 세션 복구, salt 보기, 보내기, 데모 리셋·연결 끊기`

---

### Task 5: 실행 스크립트·문서

**Files:**
- Modify: `scripts/demo_web_reset.sh`, `scripts/demo_split_start.sh`, `docs/MODE3_DEMO.md`

**Interfaces:**
- Consumes: Task 2 의 기동 조건(passkey 는 `localhost` 오리진).

- [ ] **Step 1:** `demo_web_reset.sh`(:23-25)·`demo_split_start.sh`(:39-41, :100, :103, :159, :176, :190, :228)의 `WALLET_MODE` 분기에 `passkey` 를 더한다: 에이전트를 `MODE3_WALLET_SECRETS=passkey MODE3_WALLET_PUBLIC_ORIGIN=http://localhost:5100` 로, 스냅 서버(:8082)·스냅 번들 검사는 건너뛰고, `CIA_ISSUE_AUTH` 기본·상태 파일 백업·`reset.json` 은 snap 과 같게. 한 머신 스크립트(`demo_web_reset.sh`)는 끝에 "서비스·IdP 페이지는 127.0.0.1 주소로 여세요(spec §2)" 를 출력한다. 사용법 주석에 한 줄.
- [ ] **Step 2:** `bash -n scripts/demo_web_reset.sh && bash -n scripts/demo_split_start.sh` → 출력 없음. `WALLET_MODE=bogus bash scripts/demo_split_start.sh` → 허용값 안내에 `passkey` 가 있고 종료 1(포트·VM 을 건드리기 전에 끝나는지 줄 순서로 확인한 뒤에만 실행).
- [ ] **Step 3:** `docs/MODE3_DEMO.md` 의 "MetaMask / 스냅 경로" 절(:887) 뒤에 "패스키 경로(`MODE3_WALLET_SECRETS=passkey`, 2026-11-17)" 절: 기동, 설정 카드, 팝업마다 패스키 한 번, 세션 복구 카드, `localhost` 전용과 한 머신 데모의 `127.0.0.1` 규칙, 사유 10개 표, 미검증(실제 Google 비밀번호 관리자 PRF). "테스트" 절(:1523)에 새 테스트 3개.
- [ ] **Step 4:** `node tests/test_mode3_demo_strings.js` 통과(문서의 사유 코드 검사).
- [ ] **Step 5: Commit**(승인 뒤) — `docs(mode3): 패스키 모드 실행 스크립트·런북`

---

## 마지막 검증(전 Task 뒤)

- `bash scripts/run_tests.sh unit`, `snap`, `contract`, `chain`, `browser` — 체인 쓰는 그룹은 하나씩. 결과를 성공/실패와 핵심 오류만 보고.
- 전체 리뷰는 Opus 리뷰어(메모리 규칙).
