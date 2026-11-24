# zkWrapper 패스키 분실 복구(salt 봉투) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 패스키₁ 을 잃어도 미리 만든 백업(백업 패스키·복구 코드)으로 같은 salt 를 되찾아 auid·PPID·서비스 계정 주소를 그대로 쓰게 한다.

**Architecture:** salt 는 바꾸지 않는다. 같은 salt 를 다른 열쇠로 잠근 사본(봉투, AES-GCM)을 zkWrapper 서버에 Google 계정별 암호문으로 둔다. 새 기기에서 발급이 `auid_pinned` 로 거절되면 그 응답에 봉투 목록과 auid 대조값(해시)이 오고, 브라우저가 백업으로 연 뒤 대조하고, 이 기기의 패스키로 새 봉투를 만들어 **같은 토큰**으로 발급을 다시 요청한다(요청 키의 서명이 새 본문을 덮는다). 회로·zkey·컨트랙트는 바뀌지 않는다.

**Tech Stack:** WebCrypto(AES-GCM 256, HKDF-SHA256, SHA-256, ECDSA P-256 요청 키), WebAuthn PRF, Node 22, Playwright(가짜 인증기).

**Spec:** `docs/superpowers/specs/2026-11-24-mode3-zkwrapper-home-and-account-recovery-design.md` 3부(§3.1~3.6)·§6 Q5~Q7. 1·2부는 `c076682`·`5d579d4` 에서 끝났다.

**검토:** 2026-11-24 Opus 독립 검토 "고친 뒤 구현 가능" — Important I1~I8 과 Minor 일부를 이 판에 반영했다(각 자리에 `[I#]`·`[m#]` 표시).

## Global Constraints

- zkWrapper 만(`config.wrapper === true`, 서버는 `WRAPPER` 분기 안). passkey-web·스냅·에이전트·web 의 동작·화면은 그대로.
- 패스키₁ 의 salt 유도는 바꾸지 않는다: `s_u = SHA-256("zkd-passkey-s_u-v1" ‖ PRF("zkd-s_u-v1")) >> 6`(`mode3/common/passkey_store.js` `saltFromPrf`). 지금 사용자의 PPID 가 바뀌면 안 된다.
- 봉투 = `AES-GCM-256(K, utf8(s_u 10진), AAD = utf8("zkd-env-v1|" + uid + "|" + id + "|" + kind + "|" + (credentialId ?? "-")))` [m4], IV 12바이트 무작위, `ct = b64url(IV ‖ 암호문+태그)`.
- 열쇠: 백업 패스키·기기 `K = HKDF-SHA256(ikm = PRF(입력 "zkd-s_u-v1") 32바이트, salt = 빈 값, info = "zkd-env-key-v1")`, 복구 코드 `K = HKDF-SHA256(ikm = 코드 16바이트, salt = 빈 값, info = "zkd-env-code-v1")`. 열쇠는 추출 불가 CryptoKey 로만 다룬다.
- 복구 코드 = 무작위 16바이트를 Crockford base32 26자 + 검사 문자 1자(26자 값의 합 mod 32) [m8], 4자씩 `-` 로 끊어 보인다. 입력은 대소문자·`-`·공백을 무시하고 `I/L→1`, `O→0`. 검사 문자가 틀리면 봉투를 열기 전에 `recovery_code_typo`. 26번째 자리의 남는 2비트는 0 이어야 한다.
- 무결성 [I1]: 서버는 auid 를 내주지 않는다. 409 `auid_pinned` 는 `auidCheck = SHA-256 16진(utf8("zkd-auid-check-v1|" + uid + "|" + auid))` 만 준다. 브라우저는 연 salt 로 같은 값을 계산해 대조하고 다르면 `recover_auid_mismatch`(발급을 보내지 않는다). 정직한 서버를 전제로 한 검사다 — 서버가 옛 봉투와 옛 대조값을 함께 주는 것은 막지 못한다 [m5].
- 서버는 암호문·kind·credentialId·id·createdAt 만 가진다. salt·PRF·코드·열쇠는 서버로 가지 않고 브라우저 저장소에 평문으로 남지 않는다. 409 본문(봉투·대조값)은 로그(`log(errText…)`·응답의 `cia` 칸)에 싣지 않는다 [m9].
- 봉투 종류 [I3]: `passkey`(백업 패스키)·`code`(복구 코드) = **백업**, 계정당 5. `device`(복구한 기기의 패스키) = 따로 10, 같은 credentialId 면 바꿔 넣고, 차면 가장 오래된 `device` 를 밀어낸다. 백업 한도가 찬 것이 복구를 막지 않는다.
- 폐기(disabled) 계정에는 더하지 않는다. 계정 폐기 때는 남기고(§6 Q6, R11), 관리자 삭제 때 계정과 함께 사라진다.
- 서명 결속: 봉투 추가·삭제는 1회용 요청 키에 묶인 Google 토큰 + `envelopeDigest` 서명. 발급에 실린 봉투는 `issueDigest` 가 덮는다 — **서명하는 글에는 `ct` 자체를 넣는다**(b64url ≤ 256자라 `|` 가 없다; WebCrypto 에 동기 SHA-256 이 없어서) [I6]. 봉투가 없으면 지금 글과 바이트까지 같다.
- 토큰 소비는 검사 뒤 [m1]: 봉투 경로는 `wrapperAuth(..., { consume: false })` 로 확인하고, 한도·중복 검사를 지난 뒤 동기로 `consumeWrapperNonce`.
- 패스키 묻는 횟수(복구 한 번): 이 기기에 패스키가 있으면 1(첫 시도) + 백업 패스키 1, 새로 만들면 create 1 + 확인 get 1(`createPasskey` 의 재계산) + 백업 1 = 3 [I5]. 복구 코드면 백업 몫이 0. 첫 시도에 고른 패스키가 바로 백업 패스키면 다시 묻지 않는다 [I4].
- 백업 패스키를 만들 때 `excludeCredentials = [패스키₁, 이미 있는 봉투들의 credentialId]` — 같은 인증기(같은 GPM)에 백업이 생기지 않게 [I7]. 화면에 "다른 기기·보안 키에 만드세요, 동기화되는 패스키 권장, 백업은 안전한 곳에" [m11].
- 복구는 요청 키 수명(`WRAPPER_KEY_MAX_MS` = 10분, Google 왕복 포함) 안에 끝나야 한다 [m2].
- 문구는 `ko`·`en` 과 래퍼 화면 규칙(`strings.js wrapperText`)을 따른다. T4 회귀 검사가 새 문구도 본다.
- 새 의존성·회로 재빌드 없음. 상태 파일 버전 14 그대로. 새 테스트는 `scripts/run_tests.sh` 의 기존 그룹에 넣는다.

## Review Focus

1. 복구 코드 한 글자 틀림 → 검사 문자로 `recovery_code_typo`(봉투를 열기 전), 고쳐 넣으면 된다. 검사 문자까지 맞는데 다른 코드 → `envelope_open_failed`. 토큰은 아직 쓰이지 않았다.
2. 복구 중 백업 패스키 창을 취소 → `passkey_cancelled`, 요청 키가 남아 같은 화면에서 다시 시도(10분 안).
3. 서버가 다른 계정의 봉투를 준다 → AAD 의 uid 가 달라 `envelope_open_failed`, 발급을 보내지 않는다.
4. 복구한 기기의 다음 로그인 → 패스키 1회로 로컬 봉투를 열어 같은 PPID. 서버에서 그 기기 봉투를 지워도 로컬 사본으로는 계속 된다 — 화면에 "지워도 이미 복구한 기기는 끊기지 않습니다" [m6].
5. 소비 뒤 `cred_revoked` 로 코어가 같은 본문을 다시 보낸다 → 이미 더한 같은 봉투는 그대로 받아들여(멱등) 두 번째가 성공한다 [I2].

---

## 파일 구조

| 파일 | 맡는 일 |
|---|---|
| `lib/mode3_salt_envelope.js`(새) | 봉투 암복호·HKDF 열쇠·복구 코드·봉투 모양 검사·`auidCheck`. 브라우저 번들과 Node(서버·테스트)가 함께 쓴다(WebCrypto 만). |
| `lib/mode3_wrapper_auth.js` | `envelopeDigest`, `issueDigest` 의 선택 칸 `envelope`. |
| `lib/mode3_cia_state.js` | `migrateCiaState` 가 `accounts[uid].envelopes` 모양을 검사(틀린 항목은 버리고 notes) [m7]. |
| `cia.js`(`WRAPPER` 분기만) | 봉투 저장·`POST /cia/wrapper/envelope`(add·remove)·`auid_pinned` 응답·발급에 실린 봉투. |
| `mode3/common/passkey_store.js` | `derivePrf`·`createPasskey` 가 `envKey` 도 돌려준다, `createPasskey({ excludeCredentialIds })`. |
| `mode3/user/core/user_core.js` | 봉투 경유 salt, 복구 메모, 봉투 추가·삭제·복구 op, `login → issueSession → signIssue` 의 `envelope` 칸. |
| `mode3/user/popup.js`·`idp_return.js` | 귀로 목적 "봉투 추가·삭제", 새 패스키의 `envKey` 넘기기, `auid_pinned` 복구 화면. |
| `mode3/user/ui.js`·`index.html`·`mode3/common/strings.js` | `/user` "백업" 카드, 복구 코드 보이기·다시 입력, 문구·사유. |
| `tests/helpers/webauthn_stub.js` | 인증기 여럿·`excludeCredentials`·맞지 않는 `allowCredentials` 거절 [m3]. 기존 호출은 그대로. |

## 결정(스펙과 다른 점)

- **상태 파일 버전은 14 그대로**(검토 확인: `auidSLog` 와 같은 선례). `envelopes` 는 없어도 되는 칸이다.
- **복구는 같은 토큰으로 다시 발급한다**(검토 확인: `auid_pinned` 는 소비 전, 소비는 `finishIssue` 에서만). 스펙 §3.3-5 의 두 번째 Google 왕복을 줄인다.
- **복구한 기기는 자기 봉투 사본을 IndexedDB 에 둔다**(검토 확인: 열쇠는 그 기기 PRF 에서만). 서버에도 `device` 봉투로 둔다(같은 기기의 저장소가 지워져도 그 패스키로 다시 복구).
- **auid 대신 대조 해시**를 내준다 [I1] — 스펙 §3.3-2 를 바꾼다.

---

### Task 1: 봉투 라이브러리

**Files:** Create `lib/mode3_salt_envelope.js` · Test `tests/test_mode3_salt_envelope.mjs`(unit 그룹)

**Interfaces — Produces:**
- `BACKUP_LIMIT = 5`, `DEVICE_LIMIT = 10`, `ENV_KINDS = ['passkey', 'code', 'device']`
- `async envKeyFromPrf(prf: Uint8Array(32)) -> CryptoKey`, `async envKeyFromCode(code: string) -> CryptoKey`(형식 `recovery_code_format`, 검사 문자 `recovery_code_typo`)
- `newRecoveryCode() -> string`, `parseRecoveryCode(s) -> Uint8Array(16)`
- `newEnvelopeId() -> string`(16진 32자)
- `async sealSalt({ key, s_u, uid, id, kind, credentialId }) -> ct`, `async openSalt({ key, ct, uid, id, kind, credentialId }) -> s_u`(실패 `envelope_open_failed`)
- `isEnvelope(e) -> boolean` — `{ id: 16진32, kind ∈ ENV_KINDS, credentialId: b64url ≤1024 (code 면 null, 나머지는 필수), ct: b64url ≤256 }`
- `async auidCheckOf(uid: string, auid: string) -> string`(SHA-256 16진)

- [ ] **Step 1: 실패하는 테스트** — 왕복이 같은 s_u; uid·id·kind·credentialId 중 하나라도 바꾸면 `envelope_open_failed`; ct 한 바이트 → 같음; 다른 PRF → 같음; 코드: `parseRecoveryCode(newRecoveryCode())` 16바이트, 소문자·공백·`-`·`I/L/O` 정규화, 한 글자 바꾸면 `recovery_code_typo`, 길이 틀림·다른 문자 `recovery_code_format`; 틀린(검사 문자까지 맞춘) 코드로 열면 `envelope_open_failed`; `isEnvelope` 의 경계(ct 257자 false, code+credentialId false, device credentialId 없음 false); `auidCheckOf` 가 고정 입력에 고정 값(테스트에 적는다).
- [ ] **Step 2:** `node tests/test_mode3_salt_envelope.mjs` — Expected: 모듈 없음으로 FAIL.
- [ ] **Step 3:** 구현(`globalThis.crypto.subtle` 만). Crockford 표 `0123456789ABCDEFGHJKMNPQRSTVWXYZ`.
- [ ] **Step 4:** 같은 명령 통과, `scripts/run_tests.sh` unit 목록에 더하고 `bash scripts/run_tests.sh unit` 통과.
- [ ] **Step 5: Commit** `feat(mode3): salt 봉투 라이브러리(AES-GCM·HKDF·복구 코드·auid 대조값)`

### Task 2: 서버 — 봉투 저장·결속·`auid_pinned` 응답

**Files:** Modify `lib/mode3_wrapper_auth.js`, `lib/mode3_cia_state.js`, `cia.js` · Test `tests/test_mode3_wrapper_auth.mjs`, `tests/test_cia_wrapper.mjs`, `tests/test_mode3_cia_state.js`

**Interfaces:**
- Consumes: Task 1 `isEnvelope`·`BACKUP_LIMIT`·`DEVICE_LIMIT`·`auidCheckOf`.
- Produces:
  - `envelopeDigest({ op: 'add'|'remove', envelope?, id? }, aud)` — 글 `zkwrapper|envelope|<aud>|add|<id>|<kind>|<credentialId 또는 ->|<ct>` / `…|remove|<id>` [I6].
  - `issueDigest(body, aud)` — `body.envelope` 가 있으면 끝에 `|envelope|<id>|<kind>|<credentialId>|<ct>`. 없으면 지금과 같은 바이트.
  - `POST /cia/wrapper/envelope { id_token, pk_e, sig, op, envelope? , id? }` → 200 `{ envelopes: [{ id, kind, credentialId, createdAt }] }`(암호문 빼고). add 는 `kind ∈ {passkey, code}` 만(`device` 는 발급으로만). 사유: `envelope_bad` 400, `envelope_limit` 409, `envelope_exists` 409(같은 id 또는 같은 credentialId), `envelope_unknown` 404, `account_disabled` 403, `unknown account` 404. 검사 뒤 소비 [m1]. `op:'list'` 는 두지 않는다 — 화면 목록은 add·remove 응답과 로컬 메타로 [m10].
  - 발급 409 `auid_pinned` 본문 `{ reason, auidCheck, envelopes: [{ id, kind, credentialId, ct }] }` — auid 는 싣지 않는다 [I1]. 경합 경로(`registerAccount` 의 "already registered")도 같은 본문.
  - 발급 본문의 선택 칸 `envelope`(`kind: 'device'` 만 받는다): **서명 직전의 마지막 동기 구간(`finishIssue` 의 persist 앞)** 에서 더한다 [I2]. 같은 id·credentialId·ct 면 이미 있는 것으로 받아들이고(멱등), 같은 credentialId 의 다른 봉투면 바꿔 넣고, `device` 한도면 가장 오래된 `device` 를 민다 [I3]. 형식이 틀리면 소비 전에 400.
  - `migrateCiaState`: `envelopes` 가 배열이 아니거나 `isEnvelope` 를 못 지나는 항목은 버리고 notes [m7].

- [ ] **Step 1: 실패하는 테스트**
  - digest: 봉투 없는 `issueDigest` 가 지금 바이트와 같다(지금 코드로 계산한 16진을 테스트에 적는다), 봉투가 있으면 다르다, `envelopeDigest` 칸에 `|` 면 던진다.
  - 경로: 등록된 계정 add(passkey) → 200, 목록에 ct 없음; 같은 토큰 두 번째 → `wrapper_token_used`; 백업 6번째 → `envelope_limit`, 이때 토큰은 아직 쓸 수 있다(같은 토큰으로 remove 가 된다); 같은 credentialId → `envelope_exists`; add 에 `kind:'device'` → `envelope_bad`.
  - 발급: 다른 auid → 409, 본문에 `auid` 칸이 **없고** `auidCheck === auidCheckOf(uid, 계정 auid)`, `envelopes[0].ct` 있음. 같은 토큰·같은 요청 키로 맞는 auid + `envelope(device)` → 200, 계정 봉투 +1. 서명 없이 `envelope` 만 바꾸면 `wrapper_bad_signature`.
  - 멱등 [I2]: 같은 `envelope` 를 실은 발급이 `cred_revoked` 재시도로 두 번 와도(두 번째 토큰은 새 토큰) 봉투는 하나.
  - 한도 [I3]: 백업 5개가 찬 계정에서 `device` 봉투를 실은 복구 발급이 된다. `device` 11번째면 가장 오래된 것이 밀린다.
  - 폐기 계정 add → `account_disabled`. 관리자 삭제 뒤 새 등록에는 봉투가 없다. 상태 파일에 모양이 틀린 봉투 → 기동 때 버려지고 notes.
  - 래퍼가 아닌 서버에서 `/cia/wrapper/envelope` → 404.
- [ ] **Step 2:** `node tests/test_mode3_wrapper_auth.mjs`, `node tests/test_cia_wrapper.mjs`(:8545) — Expected: 새 사례 FAIL.
- [ ] **Step 3:** 구현.
- [ ] **Step 4:** 같은 명령 + `node tests/test_cia_wrapper_race.mjs` + 상태 테스트 — Expected: 통과.
- [ ] **Step 5: Commit** `feat(mode3): zkWrapper 서버 — salt 봉투 저장·결속·auid_pinned 대조값`

### Task 3: 패스키 열쇠와 가짜 인증기

**Files:** Modify `mode3/common/passkey_store.js`, `tests/helpers/webauthn_stub.js` · Test `tests/test_mode3_passkey_salt.mjs`

**Interfaces:**
- Produces:
  - `derivePrf(...)`·`createPasskey(...)` 반환에 `envKey`(추출 불가 AES-GCM CryptoKey, 식은 Task 1 `envKeyFromPrf` 와 같다 — 전역 스크립트라 import 못 하므로 같은 식을 둔다).
  - `createPasskey({ ..., excludeCredentialIds = [] })` — WebAuthn `excludeCredentials` 로 넘긴다 [I7]. 인증기가 거절하면(`InvalidStateError`) `passkey_already_registered`.
  - 가짜 인증기 `buildWebAuthnStub({ secretHex, extraSecrets = [] })`: credential 마다 secret(credId = SHA-256(secret)[0..16]). `create` 는 `window.__webauthnCreateIndex`(없으면 0)번 secret, 그 credId 가 `excludeCredentials` 에 있으면 `InvalidStateError`. `get` 은 `allowCredentials` 가 있으면 맞는 secret 으로, **맞는 것이 없으면 `NotAllowedError`** [m3]; `allowCredentials` 가 없으면 0번. `extraSecrets` 가 없으면 지금과 같다.
- [ ] **Step 1: 실패하는 테스트** — 같은 PRF 바이트에서 `passkey_store` 의 `envKey` 로 seal 한 봉투를 Task 1 `envKeyFromPrf` 로 연다. 기존 salt 기대값은 그대로.
- [ ] **Step 2:** `node tests/test_mode3_passkey_salt.mjs` — FAIL.
- [ ] **Step 3:** 구현(`importKey('raw', prf, 'HKDF')` → `deriveKey({ name:'HKDF', hash:'SHA-256', salt: 빈 값, info: utf8('zkd-env-key-v1') }, …, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt'])`).
- [ ] **Step 4:** 같은 명령 + zkWrapper 브라우저 테스트 한 번(가짜 인증기 기본 동작이 그대로) — 통과.
- [ ] **Step 5: Commit** `feat(mode3): 패스키 봉투 열쇠(envKey)·excludeCredentials·가짜 인증기 여러 credential`

### Task 4: 코어 — 봉투 경유 salt·추가·삭제·복구

**Files:** Modify `mode3/user/core/user_core.js` · Test `tests/test_mode3_user_core_wrapper.mjs`(`browser()` 도우미의 가짜 `passkey` 가 credential 여럿·`envKey`·`excludeCredentialIds` 를 흉내 낸다)

**Interfaces:**
- Consumes: Task 1~3.
- Produces:
  - kv `passkey = { credentialId, info, via?: 'envelope', envelope?: { id, ct } }`(via 없으면 직접).
  - `saltNow()` — `via === 'envelope'` 면 derive 의 `envKey` 로 `openSalt({ …, kind: 'device', credentialId })` → auid 대조. 그 밖은 지금과 같다.
  - **복구 메모** [I5]: 모듈 변수 `recoverMemo = { credentialId, envKey, at }` — `withSalt` 범위를 넘어 남는다. 채우는 곳: `saltNow` 의 derive(그 결과의 `envKey`), `wrapperLogin({ ..., salt, envKey })`(새로 만든 패스키 — 승인 창이 `createPasskey` 의 `envKey` 를 넘긴다). 수명 = 요청 키 수명(`WRAPPER_KEY_MAX_MS`), `wrapperBegin`·복구 성공·실패 확정 때 지운다.
  - `wrapperLogin` 이 409 `auid_pinned` 를 받으면 `R(409, { reason: 'auid_pinned', recover: { envelopes: [{ id, kind, credentialId }] } })` — 암호문·대조값은 코어 메모(`recoverOffer = { auidCheck, envelopes, uid, at }`)에만 두고 응답·로그에 싣지 않는다 [m9]. 요청 키를 지우지 않는다(`keepKey`). 방금 만든 로컬 등록은 지금처럼 되돌린다.
  - `wrapperLoginRecover(body, { idToken, verifiedOrigin, serviceName, policy, envelopeId, code = null })`:
    1. 봉투를 고른다. `recoverMemo.credentialId` 가 어떤 봉투의 credentialId 와 같으면 [I4] 그 `envKey` 로 바로 연다(다시 묻지 않는다, 새 봉투도 만들지 않는다 — 그 봉투를 로컬 사본으로 쓴다). 아니면 패스키 봉투는 `passkey.derive({ credentialId: 봉투의 credentialId })`(돌아온 credentialId 가 다르면 `envelope_credential_mismatch`), 코드 봉투는 `envKeyFromCode(code)`.
    2. `openSalt` → `auidCheckOf(uid, auidOf(s_u))` ≠ `recoverOffer.auidCheck` 면 `recover_auid_mismatch`(발급 없음).
    3. [I8] `wrapperLocalRegister({ uid, provider, s_u })` → `saltMemo = s_u` → (I4 가 아니면) `recoverMemo.envKey` 로 `device` 봉투 seal → `login(body, { wrapper: { ..., envelope } })` — `envelope` 는 `login → issueSession → 발급 본문·signIssue` 까지 실어 보낸다.
    4. 성공: kv `passkey = { credentialId: recoverMemo.credentialId, info, via: 'envelope', envelope: { id, ct } }`, 메모 지움. 실패: 로컬 등록 되돌림(지금 `created && pendingIdp` 규칙), 요청 키는 남긴다(10분 안 재시도 — [m2]).
  - `wrapperEnvelopeAdd({ idToken, kind: 'passkey'|'code', code? })` → 200 `{ envelopes }`. salt 는 `saltNow`(1회). passkey: `passkey.create({ excludeCredentialIds: [연결된 credentialId, ...봉투 credentialId] })` 의 `envKey`. code: 받은 코드(저장하지 않는다). 코어는 지금 `passkey.create` 를 부르지 않지만 `user.js` 가 넘기는 `passkey` 에 이미 있다.
  - `wrapperEnvelopeRemove({ idToken, id })` → 200 `{ envelopes }`. kv `envelopes`(목록 메타, 암호문 없음)를 응답으로 갱신.
- [ ] **Step 1: 실패하는 테스트**(credential: 기기 A `cA`, 백업 `cB`, 새 기기 C `cC`, D `cD`)
  - A 로그인 → `wrapperEnvelopeAdd(passkey)` → 목록 1(그때 create 의 exclude 에 `cA` 가 있다) → `wrapperEnvelopeAdd(code)` → 목록 2. `b.dump()` 에 s_u·코드 문자열 없음.
  - C 로 같은 계정 로그인 → 409, `recover.envelopes.length === 2`, 응답 JSON 에 `ct`·`auidCheck` 문자열이 없다, kv `wrapperKey` 남음.
  - C `wrapperLoginRecover(패스키 봉투)` → derive 1회(`cB`) → 200, PPID = A 의 PPID, kv `passkey.via === 'envelope'`. C 의 다음 `wrapperLogin` → derive 1회, 같은 PPID.
  - 새로 만든 패스키 경로 [I5]: E 가 `salt`·`envKey` 를 넘긴 `wrapperLogin` → 409 → 코드 복구 → 200(derive 0회 추가).
  - 첫 시도가 백업 credential [I4]: F 가 `cB` 로 로그인 → 409 → `wrapperLoginRecover(패스키 봉투)` → derive 추가 0회, 200, 서버 봉투 수 그대로.
  - D 틀린 코드 → `recovery_code_typo` 또는 `envelope_open_failed`, `/cia/issue` 두 번째 요청 없음; 맞는 코드 → 200.
  - 봉투 바꿔치기(fetch 스파이가 409 본문의 봉투를 다른 계정 것으로) → `envelope_open_failed`, 발급 없음.
  - 백업 패스키 창 취소 → `passkey_cancelled`, `wrapperKey` 남음, 다시 시도하면 200 [m2].
- [ ] **Step 2:** `node tests/test_mode3_user_core_wrapper.mjs`(:8545) — FAIL.
- [ ] **Step 3:** 구현.
- [ ] **Step 4:** 같은 명령 + `node tests/test_mode3_zkwrapper_server.mjs` — 통과.
- [ ] **Step 5: Commit** `feat(mode3): 코어 — 봉투 경유 salt·백업 추가·삭제·auid_pinned 복구`

### Task 5: 화면 — 백업 카드·복구 화면·문구

**Files:** Modify `mode3/user/index.html`, `ui.js`, `popup.js`, `idp_return.js`, `mode3/common/strings.js`, `docs/MODE3_DEMO_SCRIPT.md` · Test `tests/test_mode3_user_wrapper_browser.mjs`, `tests/test_mode3_demo_strings.js`

**Interfaces:**
- Consumes: Task 4 ops.
- Produces:
  - `/user` "백업" 카드 `#backupCard`(등록돼 있을 때만): `#backupList`(종류·만든 시각·"지우기"), `#backupPasskeyBtn`, `#backupCodeBtn`, 안내 "다른 기기·보안 키에, 동기화되는 패스키 권장, 백업은 안전한 곳에 — 지워도 이미 복구한 기기는 끊기지 않습니다" [m6·m11]. 두 버튼: 확인 창 → Google(같은 계정만) → 귀로.
  - 귀로 목적 `mode3-envelope-add`(kind)·`mode3-envelope-remove`(id), 결과 키 `WRAP_BACKUP_RESULT_KEY`. 복구 코드는 **귀로 화면에서** 만들어 보이고 다시 입력받는다(가기 전에 만들지 않는다 — sessionStorage 에 남지 않게). 백업 패스키는 귀로 화면의 `#authBackupCreateBtn` 클릭 한 번에 WebAuthn 한 번(사용자 동작이 필요한 브라우저 대비 [m11]).
  - 승인 창: 새 패스키를 만들면 `createPasskey` 의 `envKey` 를 `wrapperLogin` 에 넘긴다 [I5]. 409 `auid_pinned` + 봉투가 있으면 복구 화면 — 봉투마다 버튼("백업 패스키로 복구" / "복구 코드로 복구" → `#authRecoverCode`), 실패하면 그 자리에서 다시. 봉투가 없으면 지금 문구.
  - 사유(ko·en, 래퍼 규칙): `envelope_bad`·`envelope_limit`·`envelope_exists`·`envelope_unknown`·`envelope_open_failed`·`envelope_credential_mismatch`·`recover_auid_mismatch`·`recovery_code_format`·`recovery_code_typo`·`passkey_already_registered`.
  - 시연 대본: 백업·복구 장면, 한계(서버가 봉투를 숨기면 막지 못한다, 정직한 서버 전제의 대조 [m5], 복구한 기기는 속성 기록이 없어 다음 발급이 빈 속성의 C_u — 속성 도구를 다시 쓴다 [m11]).
- [ ] **Step 1: 실패하는 테스트**(가짜 인증기 `extraSecrets` = 백업 secret)
  - A: `/user` → 백업 패스키 더하기 → Google(A) → 귀로 버튼 → 목록 1. 복구 코드 만들기 → 귀로에서 코드 표시·다시 입력 → 목록 2. 저장소에 코드·salt 평문 없음.
  - 새 컨텍스트 C(다른 secret + 백업 secret): zkONE → "zkWrapper 로 로그인" → 패스키 만들기 → 복구 화면 → "백업 패스키로 복구" → 로그인 성공, PPID = A, 패스키 횟수 create 1 + get 2.
  - 새 컨텍스트 D: 코드 한 글자 틀림 → "한 글자가 틀렸습니다"(typo), 고치면 성공.
  - A: "지우기" → Google → 목록 1.
- [ ] **Step 2:** `node tests/test_mode3_user_wrapper_browser.mjs`(:8545, Chrome) — FAIL.
- [ ] **Step 3:** 구현.
- [ ] **Step 4:** 같은 명령, `node tests/test_mode3_demo_strings.js`, zkWrapper 테스트 7개, `bash scripts/run_tests.sh unit` — 통과.
- [ ] **Step 5: Commit** `feat(mode3): zkWrapper 백업 카드·패스키 분실 복구 화면`

---

## 검증 순서

1. Task 1·3 단위 → Task 2 서버 → Task 4 코어 → Task 5 브라우저.
2. 끝나면 Opus 전체 검토(이번 검토의 I1~I8 이 실제로 고쳐졌는지 포함).
3. 사람 확인: 실제 GPM 패스키 + 보안 키(또는 두 번째 Chrome 프로필)로 백업 → 패스키₁ 없이 복구 → 같은 계정 주소.
