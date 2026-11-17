# Mode 3 — 패스키 모드: salt 를 패스키 PRF 로 매번 유도한다, 스냅 모드 옆 세 번째 비밀 공급 모드 (설계, 2026-11-17)

- 상태: **초안 — 사용자 검토 대기.** 방향은 사용자 승인(2026-11-16~17 대화): 방법 A(PRF 로 salt 를 직접 유도, 백업 파일 없음), 모양 2(salt 를 어디에도
  저장하지 않고 팝업마다 다시 유도), **스냅 모드는 남겨 두고 새 모드로 추가**, 세션 복구는 로그인과 분리 — **패스키 모드에만**, **zk 스냅 화면에서 한 번에**,
  `blind_u`·동의 기록은 **에이전트 파일에 그대로**, 에이전트 파일을 잃었을 때 계정 되찾기는 **이번 범위 밖**, **에이전트 하나에 패스키 계정 하나**.
  설계 1부(구조)·2부(흐름) 사용자 승인(2026-11-17).
- 용어: **salt** 는 코드의 `s_u` 다. **패스키 모드** 는 `MODE3_WALLET_SECRETS=passkey` 로 띄운 에이전트와 그 화면이다. **증인 모드** 는 snap·passkey 를 함께 부르는 말이다
  (요청마다 증인을 받고, 세션 증인은 메모리에만 둔다).
- 배경: 스냅 모드는 salt 를 MetaMask 스냅에 두고, 사용자가 암호화 백업 파일(파일 + 비밀번호)로 지킨다(스펙 `2026-11-13-mode3-snap-random-salt-backup-design.md`).
  패스키 모드는 MetaMask 와 백업 파일을 모두 뺀다 — salt 는 **패스키(WebAuthn PRF 확장)에서 그때그때 유도**하고, 패스키의 동기화(Google 비밀번호 관리자·iCloud 키체인)가
  백업 역할을 한다. 회로·컨트랙트·IdP 는 salt 값만 보고 출처를 모르므로 바뀌지 않는다.
- 2026-10-21(복구 코드)에는 패스키 PRF 를 "지원 불균일, 나중에 얹을 수 있다" 로 미뤘다. 이번에 다시 꺼낸다.
- 비범위: 회로·zkey·컨트랙트(재빌드 없음), IdP(`cia.js`), 스냅(`snap-mode3` — 그대로), 스냅 모드의 동작(세션 복구 포함 — 그대로), 파일 모드·웹 모드,
  Mode 1·Mode 2. §9 의 후속.

## 0. 실험 결과(2026-11-16, 스크래치 — 버렸다)

| 확인 | 결과 |
|---|---|
| Chrome 154 + CDP 가상 인증기(`hasPrf: true`), `http://localhost:5180` | 생성 시 `prf.enabled: true`, 생성 시 PRF 출력 있음. 같은 입력으로 두 번 계산 → 같은 32바이트. 새로 고친 뒤(allowCredentials 없이) 다시 계산 → 같은 값. |
| 이 머신(Ubuntu 20.04)의 실제 인증기 | 블루투스 어댑터 없음(휴대폰 QR 연동 불가), USB 보안 키 없음. 남은 후보는 **Google 비밀번호 관리자 패스키** 하나 — **미확인**(사용자 수동 확인 대기). |

실제 인증기에서 PRF 가 나오지 않으면 이 머신에서는 시연할 수 없다(§8 미검증 위험). 구현은 가상 인증기로 테스트한다.

## 1. 결정

| # | 결정 | 이유·대가 |
|---|---|---|
| P1 | 에이전트에 세 번째 모드 **`MODE3_WALLET_SECRETS=passkey`** 를 더한다. snap·file 은 그대로다. | 사용자 결정(스냅 모드 유지). |
| P2 | **salt = 패스키 PRF 에서 유도**: `s_u = BigInt(SHA-256(utf8("zkd-passkey-s_u-v1") ‖ prf.first)) >> 6n` (256 → 250비트). 0 이면 `passkey_bad_salt`(확률 2^−250). PRF 입력(`eval.first`)은 `utf8("zkd-s_u-v1")` 로 고정한다. | 지금 salt 범위 [1, 2^250−1](`SCALAR_MAX`, `isSalt`)에 맞춘다. 도메인 문자열로 다른 용도의 PRF 출력과 섞이지 않게 한다. 버전 문자열을 바꾸면 salt 가 바뀌므로 **바꾸지 않는다**. |
| P3 | salt 는 **어디에도 저장하지 않는다** — 에이전트 파일·브라우저 저장소 모두. 팝업·화면이 한 번의 작업(팝업 하나, 버튼 하나) 동안만 메모리에 들고 버린다. | 사용자 결정(모양 2). 에이전트가 받는 증인의 s_u 는 지금 스냅 모드처럼 세션 증인으로 메모리에만 있다. |
| P4 | **`blind_u`(C_u 전체)와 동의 기록은 에이전트 파일에 둔다.** | 사용자 결정. `blind_u` 가 없으면 세션 복구가 `user_cred_mismatch` 로 막힌다. 파일이 새도 s_u(250비트 무작위 상당) 없이는 증명을 만들 수 없다. |
| P5 | **에이전트 하나에 패스키 하나.** 설정 때 credential ID(공개값)를 에이전트 파일에 적고, 이후 요청은 `allowCredentials` 로 그 패스키만 지정한다. 다른 패스키는 auid 대조로 거절한다(`passkey_mismatch`). | 사용자 결정. 다른 계정 시연은 "패스키 연결 끊기"(§4.6) 뒤 다시 설정. |
| P6 | 패스키 모드는 **`localhost` 에서만** 동작한다. 에이전트의 지갑 오리진 기본값을 `http://localhost:<PORT>` 로 하고, `MODE3_WALLET_PUBLIC_ORIGIN` 의 호스트가 IP 이면 기동을 거부한다. 화면은 `127.0.0.1` 로 열리면 `passkey_wrong_origin` 안내만 띄운다. | WebAuthn 은 IP 주소를 RP ID 로 받지 않는다. 스냅 모드의 기본값(`http://127.0.0.1:<PORT>`)은 그대로. |
| P7 | 화면 쪽은 **스냅 RPC 모양을 흉내 내는 어댑터**(`mode3/common/passkey_store.js`)로 구현한다. zk 스냅 화면·팝업의 `invokeSnap(method, params)` 진입점이 모드를 보고 스냅 또는 어댑터로 보낸다. | 로그인·가입·출금 흐름 코드를 스냅 모드와 한 벌로 유지한다(설계 1부 방법 A). |
| P8 | 스냅이 띄우던 확인 창(릴레이 출금 받는 주소·금액, 자기 폐기 비밀번호, 등록 초기화 확인)은 **화면 자체 확인 상자**가 대신한다. | 패스키 모드에는 스냅 창이 없다. |
| P9 | **세션 복구는 로그인과 분리한다(패스키 모드만).** 증인이 없는 세션의 재검증·출금은 `needs_consent` 대신 **`session_restore_required`**(409)를 돌려준다. 서비스는 안내와 zk 스냅 화면 링크만 보인다. zk 스냅 화면의 **세션 복구 카드**가 패스키 한 번으로 증인 없는 세션 전부를 채운다. | 사용자 결정. 지금 스냅 모드는 `needs_consent` → "로그아웃 뒤 다시 로그인" 안내다(`strings.js` `needs_consent`) — 서비스는 재승인 팝업(`reauth`)을 열지 않는다. 그 동작은 그대로 둔다. |
| P10 | 에이전트 파일을 잃었을 때 패스키로 계정을 되찾는 기능은 **넣지 않는다**(§9). | 사용자 결정. 스냅 모드에도 이 방향의 복구는 없다(있는 것은 "스냅만 비었을 때" `restoreSnapIfEmpty`). |

## 2. 보안 메모

- **RP ID 는 호스트 단위이고 포트를 가리지 않는다.** `localhost` 의 어느 포트 페이지든 사용자가 패스키를 누르면 같은 PRF 입력으로 같은 salt 를 얻는다.
  스냅은 호출 오리진을 `:5100` 으로 검사했지만(`WALLET_ORIGINS`) 패스키는 그 검사를 할 수 없다. 그래서:
  - 분리 데모(서비스가 VM `.11`/`.12`)에서는 서비스 페이지가 `localhost` 가 아니므로 해당 없다.
  - 한 머신 데모에서는 **서비스·IdP 페이지를 `127.0.0.1` 로 연다**(IP 오리진에서는 WebAuthn 자체가 안 된다). 실행 스크립트와 `docs/MODE3_DEMO.md` 에 적는다.
  - 실제 배포라면 지갑 전용 도메인(그 도메인의 페이지만 패스키를 부른다)이 필요하다 — 스펙·논문에 한 줄로 적는다.
- **패스키 보관자:** 동기화 패스키는 Google·Apple 이 보관한다(둘 다 종단간 암호화라고 밝힌다 — 근거 미검토). Google 래퍼 계정에서는 IdP 와 패스키 보관자가 같은 회사다.
  논문의 위협 모델 문장에서 이 가정을 짚는다.
- **사용자 확인:** 패스키 요청은 `userVerification: 'required'` 로 한다(PIN·생체). 팝업 하나에 한 번이다(P3).
- 에이전트 새 라우트(§3.2)는 지금 `/wallet/secrets/salt` 처럼 `Sec-Fetch-Site` 가 있으면 `same-origin` 만 받는다. `blind_u` 를 싣기 때문이다.

## 3. 에이전트 (`mode3_wallet_agent.js`, `lib/mode3_secret_source.js`)

### 3.1 모드
- `SECRETS` 허용값에 `'passkey'` 를 더한다. 지금의 `SECRETS === 'snap'` 분기(19곳)를 **증인 모드** 판정(`SECRETS !== 'file'`)으로 바꾸되, 스냅에만 해당하는 곳
  (`snapId`·`snapVersion` 응답, 스냅 설치 관련)은 `'snap'` 그대로 둔다. 어느 쪽인지는 분기마다 구현 계획에서 나눈다.
- `/wallet/config` 응답의 `secrets` 는 `'passkey'`, `snapId` 는 `null`.
- 지갑 오리진: P6.

### 3.2 저장(파일)
- `state.passkey = { credentialId, createdAt } | null` — credentialId 는 base64url.
- `registration.userCred` 는 **`blind_u` 까지** 저장한다(passkey 모드의 `stripSecrets` 변형 — snap 모드는 지금처럼 `Cf_u`·`issuedAt` 만). s_u 는 저장하지 않는다(P3).
- `state.consents = { [rpOrigin]: { arid, allowAgent, grantedAt } }` — 스냅 상태의 `consents` 와 같은 모양.
- 새 라우트(지갑 오리진, same-origin 만):
  - `GET /wallet/passkey/state` → `{ passkey, registration(공개 + userCred 전체), consents }`. 어댑터의 `getPublicInfo`·`getStoredState`·증인 조립이 쓴다.
  - `PUT /wallet/passkey/credential` `{ credentialId }` → 저장. 이미 있고 다르면 409 `passkey_already_set`(연결 끊기 뒤에만 바꾼다).
  - `DELETE /wallet/passkey/credential` → 연결 끊기(§4.6). 등록이 있으면 409 `registered`(데모 리셋 먼저).
  - `POST /wallet/passkey/consent` `{ origin, arid, allowAgent }` → 동의 기록(어댑터의 `consentLogin` 이 부른다).
- C_u 저장: 스냅 모드는 페이지가 응답의 `userCredIssued` 를 스냅의 `updateUserCred` 로 넘긴다. 패스키 모드는 **에이전트가 발급 때 직접 저장**한다
  (`userCredIssued` 를 받는 쪽이 에이전트 자신). 속성 변경(`/wallet/profile` 의 `changed`)은 지금처럼 `userCred = null`.

### 3.3 세션 증인·복구
- 증인 없는 세션: `secretSourceFor` 가 snap 모드에서 던지는 `needs_consent` 를 passkey 모드에서는 **`session_restore_required`** 로 던진다(재검증·`/wallet/request`·`/wallet/tx/prepare` 등 같은 경로).
- `/wallet/session/witness` 를 passkey 모드에서도 받는다(지금은 snap 만). 검사(allowAgent 일치, `Cf_u` 일치, `validateWitness` 의 auid 대조)는 그대로다.
- `/wallet/status` 의 세션 항목에 **`hasWitness: boolean`** 을 더한다(모든 모드 — file 모드는 늘 true).

## 4. 화면

### 4.1 어댑터 (`mode3/common/passkey_store.js`, 새 파일)
- `derive()`: `navigator.credentials.get({ publicKey: { rpId: 'localhost', allowCredentials: [credentialId], userVerification: 'required', extensions: { prf: { eval: { first } } } } })`
  → P2 로 s_u. 작업 하나 동안 캐시(`withSalt(fn)` — fn 이 끝나면 버린다).
- 스냅 RPC 대응:

| 스냅 RPC | 패스키 어댑터 |
|---|---|
| `getPublicInfo` | `/wallet/passkey/state` 로 같은 모양을 만든다. `hasSalt`·`backedUp` = credentialId 가 있는지. |
| `getStoredState` | 같은 라우트. `salt` 칸은 비워 두고, 화면의 "salt 보기"(§4.2)가 따로 채운다. |
| `initSalt` / `importSalt` | §4.2 설정 카드의 "패스키 만들기" / "이미 있는 패스키 쓰기". |
| `confirmBackup` / `exportSaltForBackup` | 없음(패스키 모드는 백업 파일이 없다). |
| `prepareRegister`, `getSalt`, `showSalt` | `derive()` → `{ s_u }`. |
| `consentLogin` | `derive()` + 에이전트 상태로 증인 `{ uid, s_u, attrs, userCred }` 조립 → `/wallet/passkey/consent` 기록 → 증인. |
| `consentDisclosure` | `relay: true` 면 화면 확인 상자(서비스·공개 속성·받는 주소·금액 — 스냅 창과 같은 줄). 아니면 `{ ok: true }`. |
| `storeRegistration`, `updateUserCred`, `syncAttrs` | 에이전트가 이미 가졌다(§3.2) — `{ ok: true }`. |
| `selfRevoke` | 화면 비밀번호 상자 → `{ uid, pwd }` / `{ denied: true }`. |
| `consentRevokeSession` | `{ ok: true }`. |
| `reset` | 화면 확인 상자 → `{ ok: true }` / `{ denied: true }`(에이전트 리셋은 지금 화면 흐름이 부른다). |

- 오류는 사유 문자열로 던진다(§5). `NotAllowedError` → `passkey_cancelled`, `prf.results` 없음 → `passkey_prf_unsupported`.

### 4.2 zk 스냅 화면 (`mode3/wallet.html`)
- passkey 모드에서는 MetaMask 연결 단계·스냅 설치·스냅 업데이트 버튼을 숨긴다. 상단 모드 표시는 "패스키".
- **설정 카드**(credentialId 가 없을 때):
  - "패스키 만들기": `create`(rp `{ id: 'localhost', name: 'zk 스냅' }`, user id 무작위 16바이트, `residentKey: 'required'`, `userVerification: 'required'`,
    `prf: { eval: { first } }`) → `prf.enabled` 가 아니면 `passkey_prf_unsupported` → `derive()` 한 번(생성 때 PRF 값이 있으면 두 값 대조, 다르면 `passkey_unstable`)
    → `PUT /wallet/passkey/credential`. 백업 확인(R6·R7)의 자리다.
  - "이미 있는 패스키 쓰기": `allowCredentials` 없이 `get` → 고른 credential 로 s_u → 에이전트에 등록이 있으면 auid 대조(다르면 `passkey_mismatch`) → 저장.
- **세션 복구 카드**(passkey 모드, `hasWitness: false` 인 세션이 있을 때만): 세션마다 서비스 이름·오리진·에이전트 허용 여부. "세션 복구" → `derive()` 한 번 →
  세션마다 `/wallet/session/witness { r_s, witness, allowAgent: 세션 값 }` → 세션별 결과(성공 / 사유). 화면 진입·탭 복귀(visibilitychange) 때 다시 읽는다.
- "내 계정" 탭: salt 행은 가림 + "salt 보기"(패스키 한 번). "패스키 연결 끊기"(§4.6).
- `127.0.0.1:5100` 으로 열리면: 카드 대신 `passkey_wrong_origin` 안내와 `http://localhost:5100` 링크.

### 4.3 승인 팝업 (같은 페이지의 팝업 경로)
- 로그인·가입·출금 흐름은 그대로 — `invokeSnap` 이 어댑터로 간다. 팝업 하나에 패스키 한 번(`withSalt`).
- 팝업 진입 조건의 `cfg.secrets !== 'snap'` 거절(`not_snap_mode`)은 증인 모드 판정으로 바꾼다.
- `restoreSnapIfEmpty` 는 passkey 모드에서 건너뛴다(어댑터의 "등록 있음"은 에이전트 그 자체다).

### 4.4 서비스 페이지 (`mode3/rp.html`)
- `walletCfg.secrets === 'snap'` 세 곳: 팝업 경로·출금 허용은 `'passkey'` 도 같게. 지갑 표시 배지에 `rp_wallet_passkey`.
- `session_restore_required` 를 받으면 사유 사전의 안내 + zk 스냅 화면 링크(`walletOrigin`). 세션은 지우지 않는다(복구 뒤 그대로 쓴다).

### 4.5 속성 도구 (`mode3/attr.html`)
- 바뀌지 않는다 — salt 는 사용자가 붙여 넣는다(zk 스냅 화면 "salt 보기" 에서 복사).

### 4.6 데모 리셋·연결 끊기
- 데모 리셋(`/attr/dist/reset.json` epoch, `checkDemoReset`): 에이전트의 등록·`userCred`·동의 기록·세션을 지운다. **credentialId 는 남긴다** — 다시 가입하면 같은 salt·auid·PPID.
- "패스키 연결 끊기": 등록이 없을 때만. credentialId 를 지워 다른 패스키로 설정할 수 있게 한다. 비밀번호 관리자의 패스키는 지우지 않는다(사용자가 직접).

## 5. 사유 사전 (`mode3/common/strings.js`)

| 사유 | 언제 | where |
|---|---|---|
| `passkey_wrong_origin` | `127.0.0.1:5100` 으로 열었다 | wallet |
| `passkey_unsupported` | `PublicKeyCredential` 없음·보안 컨텍스트 아님 | wallet |
| `passkey_prf_unsupported` | 고른 인증기가 PRF 를 주지 않는다 | wallet |
| `passkey_unstable` | 생성 때와 계산 때 PRF 값이 다르다 | wallet |
| `passkey_cancelled` | 사용자가 패스키 창을 닫았다·시간 초과 | wallet |
| `passkey_mismatch` | 고른 패스키의 auid 가 이 에이전트 등록과 다르다 | wallet |
| `passkey_setup_required` | credentialId 가 없다 | wallet |
| `passkey_already_set` | 다른 패스키가 이미 연결돼 있다 | wallet |
| `passkey_bad_salt` | 유도값이 0(사실상 없음) | wallet |
| `session_restore_required` | 증인 없는 세션(에이전트 재시작) | rp·wallet |

문구는 기존 사전 형식(`{ where, ko: { title, cause, action }, en }`)을 따른다. 사유 사전 전체 검사 테스트에 들어간다.

## 6. 실행 스크립트·문서
- `scripts/demo_web_reset.sh`, `scripts/demo_split_start.sh`: `WALLET_MODE=passkey` — 에이전트를 `MODE3_WALLET_SECRETS=passkey`,
  `MODE3_WALLET_PUBLIC_ORIGIN=http://localhost:<PORT>` 로 띄우고 스냅 서버(:8082)는 띄우지 않는다. 한 머신 모드에서는 서비스·IdP 주소를 `127.0.0.1` 로 안내한다(§2).
- `docs/MODE3_DEMO.md`: 패스키 모드 절(설정·세션 복구·제약). `docs/MODE3_DEMO_SCRIPT.md` 는 스냅 모드 기준 그대로 — 패스키 모드 시연 순서는 실제 인증기 확인(§8) 뒤 따로.

## 7. 테스트
- 단위(`unit` 그룹): P2 유도 — 고정 PRF 바이트 → 고정 s_u, 결과가 [1, 2^250) 안, 버전 문자열이 바뀌면 값이 바뀐다.
- 에이전트(`tests/test_mode3_wallet_agent.mjs`, passkey 모드 스택):
  - `/wallet/login` 이 증인을 요구한다(`witness_required`), 상태 파일에 s_u 가 없다(로그인 뒤 파일 문자열 검사), `userCred.blind_u` 는 있다.
  - credential 라우트: 저장·다른 값 409·등록 있을 때 삭제 409·cross-site 403.
  - 에이전트 재시작 → 재검증이 409 `session_restore_required`, `hasWitness: false` → `/wallet/session/witness` → 재검증 통과.
  - IP 오리진으로 passkey 모드 기동 거부.
- 브라우저(새 파일 `tests/test_mode3_passkey_browser.mjs`, `browser` 그룹): CDP 가상 인증기(`hasPrf: true`), 지갑 호스트 `localhost`.
  - 패스키 만들기 → zkID 가입 → zkONE 로그인(패스키 한 번) → 에이전트 재시작 → zkONE 재검증에 복구 안내 → zk 스냅 화면 세션 복구 → 재검증 통과.
  - `127.0.0.1:5100` 안내, 다른 패스키(두 번째 가상 인증기) `passkey_mismatch`, PRF 없는 인증기(`hasPrf: false`) `passkey_prf_unsupported`, 데모 리셋 뒤 같은 PPID.
  - 상태 파일과 `localStorage`·`sessionStorage` 에 s_u 문자열이 없다.
- 회귀: 기존 `unit`·`snap`·`contract`·`chain`·`browser`(스냅 모드 54건)·에이전트 테스트가 그대로 통과.

## 8. 미검증 위험
- **실제 인증기(Google 비밀번호 관리자 패스키, 이 머신의 Chrome)에서 PRF 가 나오는지 확인하지 않았다.** 안 나오면 이 머신에서는 시연할 수 없고(블루투스·보안 키 없음),
  다른 기기나 USB 보안 키가 필요하다.
- Google 비밀번호 관리자가 `localhost` RP ID 의 패스키를 저장·동기화하는지 확인하지 않았다.
- 분리 데모에서 시연자 PC 의 `localhost:5100` 이 지갑이라는 점은 스냅 모드와 같다 — VM 쪽 변경은 없다고 보지만 스크립트에서 확인한다.

## 9. 후속(이 스펙 밖)
- 에이전트 파일을 잃었을 때 계정 되찾기(zkID 로그인 + 패스키 → IdP 슬롯과 auid 대조로 등록 재구성).
- 에이전트 하나에 패스키 여러 개(스펙 초안 `2026-11-16-mode3-agent-per-snap-state-design.md` 와 함께 판단).
- 스냅 모드의 세션 복구 분리.
- 실제 배포용 지갑 전용 도메인.
- 패스키 모드 시연 순서(`docs/MODE3_DEMO_SCRIPT.md`)와 덱·논문 반영.

## 10. 계정 복구(2026-11-17 추가 — 사용자 승인)

§9 의 "에이전트 파일을 잃었을 때 계정 되찾기" 를 이번 범위로 당긴다. 결정(사용자): 패스키 모드만, zk 스냅 화면의 **"계정 복구"**(서비스 로그인과 분리),
본인 확인은 **IdP 인증 창 재사용**(비밀번호는 IdP 에만), 속성은 **복구 카드에서 입력**(IdP 는 속성을 보관하지 않는다). 리뷰 I-1(속성 도구 기록의 평문 salt)은 예외로 둔다(사용자 결정).

| # | 결정 | 이유·대가 |
|---|---|---|
| P11 | 복구 카드는 **패스키가 연결돼 있고 에이전트에 등록이 없을 때** zk 스냅 화면에 보인다(연결이 없으면 설정 카드의 "이미 있는 패스키 쓰기" 가 먼저). | 파일을 잃었거나 다른 PC — 연결과 복구를 한 흐름으로 묶지 않아 각 단계의 실패가 분명하다. |
| P12 | 카드: 스키마 속성 칸(기본값 채움) + "계정 복구". 누르면 패스키 한 번 → auid 를 계산해 보인다(사용자가 복사 — 11-09 규칙대로 인증 창에 미리 채우지 않는다). | auid 는 인증 창의 등록 코드에 묶인다(cia.js `/cia/auth/code` purpose=register). |
| P13 | "인증 창으로" 를 누르면 `sessionStorage` 의 기존 대기 키(`PENDING_KEY`)에 `{ req: { type: 'mode3-recover', profile }, origin: location.origin, nonce, at }` 를 남기고 IdP `/login?purpose=register&return=1` 로 간다. **salt 는 남기지 않는다.** | IdP 인증 창은 늘 `${wallet}/?authorize=1&idp_code…&idp_uid…&idp_auid…` 로 돌아온다 — IdP 는 바꾸지 않는다. |
| P14 | 돌아온 페이지(`takeIdpReturn`)가 `req.type === 'mode3-recover'` 면: 패스키 한 번(페이지가 새로 떠 salt 가 없다) → 계산한 auid 가 돌아온 `idp_auid` 와 같은지 → `/wallet/register { uid, code, s_u, profile }` → 결과를 `sessionStorage` 의 `mode3_recover_result` 에 남기고 `/` 로 돌아간다. zk 스냅 화면이 그 결과를 복구 카드 자리에 한 번 보인다. | 복구 한 번에 패스키 두 번(auid 표시, 돌아온 뒤). |
| P15 | 에이전트 `/wallet/register` 응답에 IdP 의 `restored: true` 를 그대로 싣는다. 화면은 `restored` 면 "계정을 되찾았습니다(같은 슬롯)", 아니면 "새로 등록했습니다". | IdP `registerAccount` 는 같은 계정·같은 auid 면 슬롯을 새로 잡지 않고 돌려준다 — 같은 PPID. |

오류: `register_auid_mismatch`(돌아온 auid ≠ 이 패스키의 auid, 또는 IdP 가 코드의 auid 와 대조해 거절), `already_registered`(그 zkID 계정에 다른 auid — "이 패스키의 계정이 아닙니다" 로 안내),
`account_disabled`(폐기된 계정), 패스키 사유(§5). 대기 저장분이 없거나 nonce 가 어긋나면 지금처럼 `wallet_auth_resume_failed`.

테스트: 에이전트 — `/wallet/register` 가 같은 auid 재등록에 `restored: true`. 브라우저 — 에이전트 상태 파일을 비워(파일 분실 흉내) 재시작 → "이미 있는 패스키 쓰기" → 복구 카드 → 인증 창 → `restored` 문구,
같은 슬롯 → 서비스 로그인 → 같은 PPID; 인증 창에 다른 auid 를 넣으면 `register_auid_mismatch` 이고 등록되지 않는다; `sessionStorage`·`localStorage` 에 salt 가 없다(속성 도구 기록 키 제외).

## 11. salt 10분 보관(2026-11-17 추가 — 사용자 결정 (b) 10분)

| # | 결정 | 이유·대가 |
|---|---|---|
| P16 | 화면이 패스키로 만든 salt 를 스냅 에이전트 **메모리에만** 10분(`MODE3_PASSKEY_HOLD_SECONDS`, 기본 600, 0 이면 끔) 맡긴다 — `POST /wallet/passkey/hold { s_u }`(등록이 있고 auid 가 맞을 때만, 아니면 409 `not_registered`·`passkey_mismatch`), `GET /wallet/passkey/held`(없으면 404 `passkey_not_held`). 시간은 맡긴 때부터 센다(늘리지 않는다). 재시작·스냅 초기화·패스키 연결 끊기로 지운다. 파일에는 쓰지 않는다. | 로그인마다 패스키를 묻는 번거로움(사용자 지적). 대가: 그 10분 동안은 `localhost:5100` 화면이 사용자 확인 없이 salt 를 쓴다(스냅 모드의 11-05 확인 창 제거와 같은 수준). 같은 PC 의 다른 브라우저 프로필도 같은 에이전트면 함께 쓴다. 로그인한 세션의 증인에는 원래도 s_u 가 메모리에 있다. |

화면 어댑터는 salt 가 필요할 때 먼저 보관분을 보고, 없으면 패스키 → 맡긴다(실패는 무시). 첫 등록·계정 복구는 등록 전이라 지금처럼 패스키를 묻는다.
