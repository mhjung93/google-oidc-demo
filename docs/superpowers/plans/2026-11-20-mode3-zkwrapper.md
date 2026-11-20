# Mode 3 zkWrapper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** passkey-web 분리 데모에서 zkIdP(4100)를 없애고, 5100 의 zkWrapper 서버가 Google ID 토큰을 받아 세션 토큰에 서명하게 한다 — 발급에 π_IdP 가 없고, 증명은 브라우저가 만드는 π_RP 하나다.

**Architecture:** 발급 엔진(상태·등록부·폐기 트리·체인 게시·서비스 등록·개봉)은 `cia.js` 의 것을 그대로 쓰고, 래퍼 방식은 깃발 `CIA_WRAPPER=1` 뒤에만 더한다(깃발이 꺼져 있으면 지금과 같다). 새 진입점 `mode3_zkwrapper.js` 가 깃발을 켜고 사용자 페이지·번들·회로 파일을 같은 프로세스에서 낸다. 브라우저는 Google 을 다녀온 뒤 패스키로 salt 를 한 번 만들어 발급 요청과 π_RP 를 만든다. 토큰은 1회용 요청 키(pk_e)에 묶는다.

**Tech Stack:** Node 22(ESM)·express, snarkjs(Groth16 — `pi_cred` 회로 그대로), WebCrypto ECDSA P-256(요청 키), jose(Google 토큰 검증 — 기존 `lib/mode3_oidc.js`), esbuild(사용자 앱 번들), Playwright(브라우저 테스트).

**Spec:** `docs/superpowers/specs/2026-11-20-mode3-zkwrapper-design.md`

## Global Constraints

- 대상은 passkey-web 뿐이다. 스냅·에이전트·web 모드의 동작과 테스트는 바뀌지 않는다 — `CIA_WRAPPER` 가 없으면 `cia.js` 의 모든 경로가 지금과 같은 응답을 낸다.
- `circuits/`·`build/`·`contracts/` 를 고치지 않는다. `npm run zk:*` 를 돌리지 않는다. 새 npm 의존성을 넣지 않는다.
- salt 는 어디에도 저장하지 않는다(IndexedDB·localStorage·sessionStorage·서버). Google 을 다녀오는 동안 브라우저에 두는 것은 공개값과 **꺼낼 수 없는** 요청 키뿐이다.
- 브라우저가 zkWrapper 서버에 보내는 어떤 요청에도 서비스의 arid·오리진·팩토리 주소·PPID 가 들어가지 않는다. 체인 읽기는 zkWrapper 서버를 거치지 않는다(스펙 §5).
- 계정은 `uid = uidOf('google', sub)`(기존 `lib/mode3_oidc_nonce.js`). 계정당 auid 는 첫 발급 때 고정하고, 등록부 리프는 고정된 값으로 만든다. "한 auid 는 한 계정"(R11)은 유지한다.
- 발급의 부수효과를 막는 서버 대조(스펙 §3·§10): auid_s 는 전체에서 한 번만 · 본 적 있는 Cf_u 는 다른 계정에서 거절 · 토큰 nonce 1회 소비 · C_u 교체는 계정당 10분에 1번 · C_u·C_s 부분군 점 검사 유지.
- zkWrapper 의 Google 클라이언트 ID 는 **전용**이다 — 서비스의 Google 로그인과 같은 값이면 기동을 거부한다(`MODE3_RP_GOOGLE_CLIENT_ID_DENY` 로 받은 값과 대조; 스크립트가 넘긴다). 중계 화면은 래퍼의 귀환을 지갑 오리진으로만 넘긴다. `prompt=none` 을 쓰지 않는다.
- 서명하는 본문에는 늘 목적(`issue`·`revoke_session`·`revoke_account`)과 서버 주소가 들어간다.
- 비밀(키·토큰·관리자 비밀번호)을 코드·로그·응답에 넣지 않는다. 상태·키 파일(`cia_state.json`·`cia_keys.json`)을 읽거나 지우는 테스트를 쓰지 않는다 — 테스트는 격리 인스턴스(`tests/helpers/isolated_cia.mjs`)만 쓴다.
- 주석은 줄 끝이나 윗줄에만. 고친 `.js`·`.mjs` 는 `node --check`, HTML 인라인 스크립트는 `vm.Script` 로 문법 확인. 새 테스트는 `scripts/run_tests.sh` 의 맞는 그룹에 넣는다.
- 화면 문구: 발급자의 이름은 "zkWrapper", 증명의 이름은 "π_RP", salt 는 "저장하지 않고 필요할 때마다 같은 값으로 다시 만든다".

## Review Focus

1. **가로챈·받아 낸 Google 토큰**: 토큰만 가진 쪽(요청 키 없음)이 발급·폐기하거나 남의 계정에 자기 auid 를 고정하지 못한다. 같은 토큰을 두 번 쓰지 못한다. 서비스와 같은 클라이언트 ID 로는 뜨지 않는다 — Task 1·2 의 테스트.
2. **한 계정 여러 PPID · 개봉 오염**: 같은 Google 계정이 두 번째 auid 로 발급받지 못한다. 남의 auid_s 로 온 발급은 거절되고 기록에 남지 않는다. 같은 Cf_u 를 두 계정이 등록하지 못한다 — Task 2 `고정된 auid 와 다르면 409`·`다른 계정의 auid_s 면 409`·`본 적 있는 Cf_u 면 409`.
3. **깃발이 꺼진 `cia.js`**: 기존 모드의 응답이 한 글자도 달라지지 않는다 — Task 2 뒤 체인 그룹 전체(39개) 통과가 완료 조건.
4. **서비스 식별자 누출**: 로그인 한 번 동안 브라우저가 zkWrapper 오리진으로 보낸 모든 요청의 주소·본문에 arid·서비스 오리진·팩토리 주소·PPID 가 없다 — Task 5 의 브라우저 테스트가 요청을 전부 모아 검사한다.
5. **Google 을 다녀오는 길의 끊김**: 요청 키가 사라졌거나(창을 닫았다 다시 연 경우) 10분이 지났거나 state 가 다르면 토큰을 쓰지 않고 처음부터 다시 한다 — Task 4 `takeWrapperReturn` 단위 테스트.

---

### Task 1: 요청 결속 — 토큰 nonce 와 요청 서명(`lib/mode3_wrapper_auth.js`)

**Files:**
- Create: `lib/mode3_wrapper_auth.js`
- Test: `tests/test_mode3_wrapper_auth.mjs`(unit)
- Modify: `scripts/run_tests.sh`(UNIT 에 추가)

**Interfaces:**
- Produces(Node·브라우저 공용 — WebCrypto `globalThis.crypto.subtle` 만 쓴다):
  - `WRAPPER_PREFIX = 'wrap:'`
  - `async wrapperNonce(pkE: JsonWebKey) -> string` — `'wrap:' + hex(SHA-256(x || y))`(x·y 는 base64url 을 푼 32바이트씩)
  - `issueDigest(body: object, aud: string) -> Uint8Array` — `'zkwrapper|issue|' + aud`(aud = 서버의 공개 주소) 뒤에 정해진 순서의 필드(`auid`, `auid_s`, `arid_s`, `C_u_pt.x`, `C_u_pt.y`, `C_s_pt.x`, `C_s_pt.y`, `chainid`, `allowAgent`, `max_height`)를 `|` 로 이은 UTF-8
  - `revokeDigest({ scope: 'session' | 'account', Cf_s?: string }, aud: string) -> Uint8Array` — `'zkwrapper|revoke_session|…'`·`'zkwrapper|revoke_account|…'`
  - `async signDigest(privateKey, digestBytes) -> string`, `async verifyDigest(pkE, digestBytes, sig) -> boolean` — `signIssue`·`verifyIssue` 는 이 둘을 `issueDigest` 와 묶은 것
  - `async signIssue(privateKey: CryptoKey, body) -> string`(base64url, ECDSA P-256/SHA-256, IEEE P1363 64바이트)
  - `async verifyIssue(pkE: JsonWebKey, body, sig: string) -> boolean` — 형식이 틀리면 false(던지지 않는다)
  - `isWrapperNonce(s) -> boolean`

- [ ] **Step 1: 실패하는 테스트를 쓴다** — `tests/test_mode3_wrapper_auth.mjs`:
  - `wrapperNonce: 같은 키면 같은 값, 다른 키면 다른 값, 'wrap:' + hex 64자`
  - `signIssue/verifyIssue: 맞는 키·본문이면 true`
  - `verifyIssue: 본문의 한 필드(auid_s·arid_s·C_s_pt.y·max_height 각각)를 바꾸면 false`
  - `verifyIssue: 다른 키의 서명·잘린 서명·빈 문자열·JWK 가 P-256 이 아니면 false`
  - `issueDigest: 필드가 빠지면 던진다(reason 'malformed')` · `aud 가 다르면 다른 값` · `revokeDigest 와 issueDigest 는 같은 필드로도 겹치지 않는다(목적이 다르다)`
- [ ] **Step 2: 돌려서 실패를 본다** — `node tests/test_mode3_wrapper_auth.mjs` → `does not provide an export named …`
- [ ] **Step 3: 구현한다.**
- [ ] **Step 4: 통과를 본다** — 5건 `ok`.
- [ ] **Step 5: 커밋** — `feat(mode3): zkWrapper 요청 결속 — 토큰 nonce = H(pk_e), 요청 서명`

### Task 2: 발급 서버의 래퍼 방식(`cia.js`, 깃발 `CIA_WRAPPER=1`)

**Files:**
- Modify: `cia.js`(깃발, `/cia/issue` 의 래퍼 분기, `/cia/revoke` 세션 폐기의 토큰 인증, `/cia/public_keys`, 계정·비밀번호 경로 차단), `tests/helpers/isolated_cia.mjs`(옵션 `wrapper: true` → env)
- Test: `tests/test_cia_wrapper.mjs`(chain)
- Modify: `scripts/run_tests.sh`(CHAIN 에 추가)

**Interfaces:**
- Consumes: Task 1 의 `wrapperNonce`·`verifyIssue`·`WRAPPER_PREFIX`; 기존 `oidcUid(idToken, prefix)`, `registerAccount`, `registryLeaf`, `compressPoint`.
- Produces:
  - `GET /cia/public_keys` 에 `wrapper: true`, `oidc.authorizeUrl`, `oidc.redirectUri`(env `MODE3_OIDC_AUTHORIZE_URL`·`MODE3_OIDC_REDIRECT_URI`) — 깃발이 꺼져 있으면 지금과 같다.
  - `POST /cia/issue`(래퍼 방식) 본문: `{ id_token, pk_e, sig, auid, auid_s, arid_s, C_u_pt, C_s_pt, chainid, allowAgent, max_height }` — `uid`·`n`·`tag`·`proof_idp`·`registration` 이 없다. 응답은 지금의 발급 응답 + `uid`, `slot`, `email`(토큰에 있으면).
  - 사유: `wrapper_nonce_mismatch` 400 · `wrapper_bad_signature` 400 · `wrapper_token_used` 409 · `auid_pinned` 409 · `auid_taken` 409(기존 R11) · `auid_s_taken` 409 · `cf_u_taken` 409 · `cred_change_too_soon` 429 · `wrapper_mode` 403(계정·비밀번호·등록·슬롯·증명 로그인·일반 OIDC 경로) · 기존 `oidc_*`·`account_disabled`.
  - 기동 검사: `CIA_WRAPPER=1` 인데 `MODE3_OIDC_CLIENT_ID` 가 없거나 `MODE3_RP_GOOGLE_CLIENT_ID_DENY`(쉼표 목록)에 든 값이면 메시지를 내고 종료한다.
  - 개봉(`uidOfAuidS`): 일치하는 계정이 둘 이상이면 uid 를 내지 않고 `ambiguous` 로 답한다.
  - `POST /cia/revoke`(scope=session, 래퍼 방식): `{ id_token, pk_e, sig, Cf_s }` — 토큰 nonce = `wrapperNonce(pk_e)`, `sig` 는 `revokeDigest({ scope:'session', Cf_s }, aud)` 에 대한 것, 그 계정의 세션일 때만. 계정 폐기(`/cia/account/self_revoke`)도 같은 모양(`scope:'account'`).

- [ ] **Step 1: 실패하는 테스트를 쓴다** — `tests/test_cia_wrapper.mjs`(격리 IdP `wrapper: true` + 발급자 스텁):
  - `public_keys: wrapper:true, oidc.authorizeUrl·redirectUri`
  - `첫 발급: 계정이 생기고(auid 고정·슬롯 배정) 토큰이 나온다 — 응답의 서명이 (auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent) 에 대한 것`(기존 `tests/helpers/mode3_flow.mjs` 의 검증 도우미 재사용)
  - `그 토큰으로 π_RP 가 만들어지고 서비스 검증(lib/mode3_rp.js verifyLogin)을 통과한다` — π_IdP 없이 끝까지
  - `두 번째 발급: 같은 auid 면 200, 다른 auid 면 409 auid_pinned — 등록부는 그대로`
  - `nonce 가 다른 pk_e 의 것이면 400 wrapper_nonce_mismatch, 서명이 없거나 다른 키면 400 wrapper_bad_signature — 계정이 생기지 않는다`
  - `본문을 바꾼 재전송(같은 토큰·같은 pk_e, auid_s 만 바꿈)은 서명이 맞지 않아 거절`
  - `같은 auid 를 다른 Google 계정이 내면 409 auid_taken(R11 유지)`
  - `다른 계정의 발급 기록에 있는 auid_s 로 온 발급은 409 auid_s_taken — 그 계정의 기록에 남지 않고, 개봉은 원래 계정을 가리킨다` · `같은 계정의 같은 auid_s 재시도는 받는다`
  - `다른 계정이 이미 낸 Cf_u 는 409 cf_u_taken`
  - `같은 토큰을 두 번 쓰면 두 번째는 409 wrapper_token_used` · `C_u 를 10분 안에 두 번 바꾸면 429 cred_change_too_soon(같은 C_u 의 재발급은 된다)`
  - `부분군에 없는 점(C_u·C_s)은 400`
  - `기동 검사: 서비스와 같은 클라이언트 ID 면 뜨지 않는다`
  - `틀린 auid(그 salt 의 것이 아님)로 받은 토큰으로는 π_RP 를 만들 수 없다`(증명 생성이 던진다)
  - `세션 폐기: 그 계정의 토큰 + 그 Cf_s 에 대한 서명이면 폐기된다 — 다른 계정의 토큰, 다른 Cf_s 에 대한 서명, 발급용 서명의 재사용은 거절`
  - `막힌 경로: /cia/signup·/cia/user/login·/cia/register·/cia/slot·/cia/user/login_challenge·/oidc/authorize 가 403 wrapper_mode`
  - `개봉: 서비스가 낸 로그인 증명의 auid_s 로 발급 기록에서 그 Google 계정의 uid 를 찾는다`(기존 개봉 테스트의 흐름을 래퍼 발급으로)
- [ ] **Step 2: 돌려서 실패를 본다.**
- [ ] **Step 3: 구현한다.** `/cia/issue` 는 `WRAPPER` 일 때 맨 앞에서 갈라 `issueWrapper(req, res)` 로 보낸다(기존 본문은 건드리지 않는다). 점의 부분군 검사(`isValidPoint`)·필드 범위·체인 생존·`cred_revoked`·등록부 갱신·서명·발급 기록은 기존 발급과 같은 함수를 부른다 — 그 뒤쪽(인증 다음)을 함수로 뽑아 두 길이 함께 쓴다.
- [ ] **Step 4: 통과를 본다** — 새 파일 전부 `ok`, 그리고 **체인 그룹 전체**(`bash scripts/run_tests.sh chain`, :8545 필요) 통과(Review Focus 3).
- [ ] **Step 5: 커밋** — `feat(mode3): 발급 서버의 래퍼 방식 — Google 토큰으로 발급, π_IdP 없음(CIA_WRAPPER)`

### Task 3: 브라우저 코어 — 래퍼 로그인(`mode3/user/core/user_core.js`)

**Files:**
- Modify: `mode3/user/core/user_core.js`, `lib/mode3_wallet.js`(발급 요청의 재료를 π_IdP 없이 만드는 `buildWrapperIssueBody`)
- Test: `tests/test_mode3_user_core_wrapper.mjs`(chain — 격리 IdP `wrapper: true`·RP·패스키 대역)
- Modify: `scripts/run_tests.sh`

**Interfaces:**
- Consumes: Task 1(`wrapperNonce`·`signIssue`), Task 2 의 `/cia/issue`.
- Produces(코어 — `config.wrapper === true` 일 때만 쓰인다):
  - `async wrapperBegin() -> R(200, { pkE: JsonWebKey, googleNonce: string })` — 요청 키 쌍을 만들고(추출 불가, `kv 'wrapperKey'` 에 `{ privateKey: CryptoKey, pkE, at }`), 이전 것은 덮는다. salt 를 묻지 않는다.
  - `async wrapperLogin(body, { idToken, verifiedOrigin, serviceName, policy }) -> R(200, 지금의 login 응답)` — 패스키 → salt → 발급 요청(π_IdP 없음, `signIssue`) → `/cia/issue` → (처음이면 게시 대기) → π_RP. 끝나면 `kv 'wrapperKey'` 를 지운다. 등록이 없으면 응답의 `uid`·`slot` 으로 로컬 등록을 만든다(속성은 `DEFAULT_PROFILE` 또는 속성 도구 기록).
  - 사유: `wrapper_key_missing` 409(요청 키가 없다 — 처음부터 다시) · 서버 사유는 그대로 전달.
  - `lib/mode3_wallet.js`: `async buildWrapperIssueBody({ uid, s_u, blind_u, attrs, arid, r_rp, r_s, session, chainid, allowAgent, max_height }) -> { body, C_u_pt, C_s_pt, Cf_u, Cf_s, auid_s, arid_s }` — `buildIssueRequest` 에서 증명 부분을 뺀 것.
- 로그인 플로우 기록(`loginFlow`)의 단계: `passkey`, `sync`, `session_key`, `issue`, `publish_wait`, `prove_session`, `sign`, `check_service` + 새 `google`(창이 넘겨 준 걸린 시간). `prove_idp` 는 없다.

- [ ] **Step 1: 실패하는 테스트를 쓴다:**
  - `wrapperBegin: 패스키를 묻지 않는다(derive 0회), googleNonce 는 'wrap:'…`
  - `wrapperLogin(처음): derive 1회, 계정·로컬 등록이 생기고 서비스 검증 통과 — 요청에 proof_idp·tag·n 이 없다`(격리 IdP 가 받은 본문을 대역 fetch 로 본다)
  - `wrapperLogin(두 번째): derive 1회, 같은 PPID`
  - `다른 패스키(다른 salt)로 같은 Google 계정: 409 auid_pinned, 로컬 등록이 생기지 않는다`
  - `wrapperBegin 없이 wrapperLogin: 409 wrapper_key_missing`
  - `끝난 뒤 kv 에 wrapperKey·salt 가 없다`
  - `loginFlow 기록에 prove_idp 가 없고 google·passkey·issue·prove_session 이 있다`
- [ ] **Step 2~4:** 실패 확인 → 구현 → 통과.
- [ ] **Step 5: 커밋** — `feat(mode3): 브라우저 코어의 래퍼 로그인 — Google 토큰·요청 키·π_RP`

### Task 4: 승인 창 — Google 을 다녀오는 로그인(`mode3/user/popup.js`·`idp_return.js`)

**Files:**
- Modify: `mode3/user/popup.js`, `mode3/user/idp_return.js`, `mode3/user/user.js`(코어에 `wrapper` 설정 전달), `mode3/common/strings.js`
- Test: `tests/test_mode3_user_idp_return.mjs`(unit — 추가), `tests/test_mode3_user_wrapper_browser.mjs`(browser)
- Modify: `scripts/run_tests.sh`

**Interfaces:**
- Consumes: Task 3 의 `wrapperBegin`·`wrapperLogin`; 기존 `googleSignupUrl`(`prompt=select_account` 고정 — `prompt=none` 은 쓰지 않는다, 스펙 §10 C2)을 `googleAuthUrl` 이름으로도 내보낸다.
- Produces(`idp_return.js`): `WRAPPER_PENDING_KEY = 'mode3.wrapper.pending'`, `saveWrapperPending(storage, { state, at, req, origin })`, `takeWrapperReturn({ hash, storage, now }) -> null | { pend, idToken, error }` — `takeGoogleReturn` 과 같은 규칙(state·10분·1회용).
- 승인 창의 흐름(`mode3-authorize`, 래퍼 방식): 서비스 인증서 확인 → `wrapperBegin` → 대기분 저장 → Google(계정 선택) → 돌아옴 → `wrapperLogin` → 서비스에 결과. 진행 줄(`#authStatus`)에 단계가 보인다.
- 패스키가 없으면 지금의 가입 창처럼 "패스키 만들기" 버튼 하나(만든 값은 그 로그인에 바로 쓴다).

- [ ] **Step 1: 실패하는 테스트를 쓴다:**
  - (unit) `takeWrapperReturn: state 불일치·10분 초과·저장분 없음은 pend:null, 맞으면 1회용` · `googleAuthUrl: prompt 는 늘 select_account`
  - (browser) `빈 브라우저에서 서비스 "zk 로그인" → 패스키 만들기 한 번 → Google(대역) → 로그인 성공 — zkIdP 인증 창(/login)으로 가지 않고, 발급 서버의 계정 표에 Google 계정이 생긴다`
  - (browser) `두 번째 로그인: 패스키 1회, Google 계정 선택을 한 번 거친다`
  - (browser) `zkTWO 로그인: PPID 가 zkONE 과 다르고 조건 증명이 통과한다`
  - (browser) `Google 에서 돌아온 조각을 다른 창에 붙여도(state 불일치) 발급되지 않는다`
  - (browser) `저장소에 salt·ID 토큰이 남지 않는다(localStorage·sessionStorage·IndexedDB 의 값 전부 검사)`
- [ ] **Step 2~4:** 실패 확인 → 구현 → 통과. 그리고 `tests/test_mode3_user_passkey_web.mjs`·`_proof.mjs`·`_signup.mjs`(기존 방식, 깃발 없음)가 그대로 통과.
- [ ] **Step 5: 커밋** — `feat(mode3): 승인 창의 래퍼 로그인 — Google 을 다녀와 패스키 한 번`

### Task 5: 체인 읽기를 서버 밖으로 · zkWrapper 서버 진입점

**Files:**
- Create: `mode3_zkwrapper.js`(진입점), `lib/mode3_user_app_routes.js`(`mode3_user_static.js` 의 페이지·번들·회로·설정 경로를 `mountUserApp(app, opts)` 로)
- Modify: `mode3_user_static.js`(`mountUserApp` 을 쓰도록 — 응답은 그대로), `cia.js`(깃발이 켜져 있으면 `mountUserApp(app, …)`), `mode3/user/core/chain.js`(계정 주소를 브라우저에서 계산 — `accountAddressOf` 가 체인을 부르지 않는다), `mode3/user/user.js`(RPC 주소를 설정의 `chainRpcUrl`·`revRpcUrl` 로)
- Test: `tests/test_mode3_zkwrapper_server.mjs`(chain), `tests/test_mode3_user_wrapper_browser.mjs`(추가 사례)

**Interfaces:**
- Produces: `mountUserApp(app, { secrets, walletOrigin, ciaUrl, rpOrigins, chainRpcUrl, revRpcUrl, explorerUrl, csp })`; `/user/config` 에 `wrapper: true`, `chainRpcUrl`, `revRpcUrl`(브라우저가 직접 부를 체인 노드 주소 — 래퍼 방식에서는 `/rpc/app`·`/rpc/rev` 경로가 없다).
- 서비스 페이지(`mode3/rp.html`)는 래퍼 방식에서 지갑 서버의 `/wallet/config`·`/mode3/health` 를 브라우저에서 부르지 않는다(`Origin` 헤더로 서비스가 샌다 — 스펙 §5). `/google-relay` 는 래퍼의 귀환(`state` 가 지갑 오리진)을 지갑 창으로만 넘기고, 서비스의 귀환은 서비스용 클라이언트 ID 의 것만 넘긴다.
- `mode3_zkwrapper.js`: env `MODE3_ZKWRAPPER_PORT`(기본 5100)·`MODE3_CHAIN_RPC_BROWSER`·`MODE3_REV_RPC_BROWSER` 를 읽고 `CIA_WRAPPER=1`·`CIA_PORT` 를 정한 뒤 `cia.js` 를 띄운다.
- `chain.accountAddressOf(factoryAddress, PPID)` — 팩토리의 초기화 코드 해시와 PPID 로 CREATE2 주소를 계산(컨트랙트 `PPIDWalletFactory.computeAddress` 와 같은 식). 초기화 코드 해시는 서비스가 인증서와 함께 알려 준 값이 아니라 **서비스 정보(`/api/mode3/rp_info`)의 `walletInitCodeHash`** 로 받는다 → `mode3_rp.js` 에 그 필드를 더한다.

- [ ] **Step 1: 실패하는 테스트를 쓴다:**
  - `zkWrapper 서버: 한 포트에서 / (홈)·/dist·/zk·/user/config·/cia/public_keys·/cia/issue 가 모두 난다, /rpc/app 은 404`
  - `accountAddressOf: 컨트랙트의 computeAddress 와 같은 주소(체인에 물어 대조) — 호출 중 RPC 요청 0건`
  - (browser) `로그인·출금 한 번 동안 zkWrapper 오리진으로 간 모든 요청의 주소·본문에 서비스의 arid·오리진·팩토리 주소·PPID·계정 주소가 없다`(Review Focus 4)
  - (browser) `체인 읽기는 설정의 chainRpcUrl 로 간다` · `서비스 페이지에서 zkWrapper 오리진으로 가는 요청은 승인 창을 여는 것뿐이다(fetch 0건)`
- [ ] **Step 2~4:** 실패 확인 → 구현 → 통과. `tests/test_mode3_user_static*.mjs` 가 그대로 통과.
- [ ] **Step 5: 커밋** — `feat(mode3): zkWrapper 서버 진입점 · 체인 읽기는 서버를 거치지 않는다`

### Task 6: 홈페이지 · 화면 정리

**Files:**
- Modify: `mode3/user/index.html`·`ui.js`(홈: 사용자용 세 단계·운영자용 세 단계·전체 플로우 링크, 그 아래 지금의 카드), `mode3/common/flow.html`·`flow_page.js`(③ 에서 π_IdP 를 빼고 Google 토큰으로 — 아랫줄이 "Google → zkWrapper → 서비스" 가 된다), `mode3/common/strings.js`(zkIdP → zkWrapper, 인증 창·가입 문구 제거), `mode3/rp.html`(버튼 "zk 로그인"), `mode3/cia_rp.html`·`cia_admin.html`(상단 바의 이름·`/user` 링크 제거)
- Test: `tests/test_mode3_user_wrapper_browser.mjs`(추가)

- [ ] **Step 1: 실패하는 테스트를 쓴다:** `홈에 사용자용·운영자용 안내가 있고 링크가 맞다` · `래퍼 방식의 화면 어디에도 "zkIdP"·"인증 창"·"π_IdP"·"비밀번호" 가 없다(홈·승인 창·서비스·운영자·관리자)` · `전체 플로우 한 장: 아랫줄에 Google 이 있고 π_IdP 가 없다 — 실제 값이 채워진다`
- [ ] **Step 2~4:** 실패 확인 → 구현 → 통과. `tests/test_mode3_demo_strings.js` 통과.
- [ ] **Step 5: 커밋** — `feat(mode3): zkWrapper 홈페이지와 화면 문구`

### Task 7: 분리 데모 스크립트 · 문서

**Files:**
- Modify: `scripts/demo_split_start.sh`(새 모드 `WALLET_MODE=zkwrapper`: zkIdP 를 띄우지 않고 `mode3_zkwrapper.js` 를 띄운다 — 먼저 **발표 PC**(`https://wallet.zkd.test:5100`, 지금 자리)에서. 서비스의 `MODE3_CIA_URL` 은 그 주소), `tests/test_demo_split_passkey_web.mjs`(정적 검사 추가), `docs/MODE3_DEMO_SCRIPT.md`, `docs/MODE3_DEMO.md`
- 스펙 §8-2 의 "VM 에 띄우기" 는 이 계획에 넣지 않는다 — `/etc/hosts`·인증서 변경이 필요해 사용자 작업이 선행한다. 스크립트에 `ZKWRAPPER_HOST` 자리만 둔다.

- [ ] **Step 1:** 정적 검사 테스트(스크립트가 `zkwrapper` 모드에서 `cia.js` 를 VM 에 띄우지 않는다, 서비스 env 의 발급자 주소가 지갑 오리진이다, 래퍼 전용 클라이언트 ID `ZKWRAPPER_GOOGLE_CLIENT_ID` 가 없으면 멈추고 서비스의 ID 를 `MODE3_RP_GOOGLE_CLIENT_ID_DENY` 로 넘긴다).
- [ ] **Step 2~4:** 구현 → `bash -n` → 테스트 통과.
- [ ] **Step 5:** 문서 고치고 커밋 — `feat(mode3): 분리 데모의 zkwrapper 모드 · 시연 문서`

재배포(실제 VM)는 사용자 요청이 있을 때만 한다 — 이 계획의 범위 밖.
