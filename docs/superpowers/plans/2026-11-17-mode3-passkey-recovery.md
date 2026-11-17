# Mode 3 패스키 모드 — 계정 복구 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 패스키 모드에서 에이전트 파일을 잃었을 때 zk 스냅 화면의 "계정 복구"로 같은 zkID 등록(같은 슬롯·PPID)을 되찾는다 — 서비스 로그인·속성 도구 기록 없이.

**Architecture:** 화면이 패스키로 auid 를 보여 주고, 기존 IdP 인증 창(등록 모드)을 다녀온 뒤 다시 패스키로 salt 를 만들어 `/wallet/register` 를 부른다. IdP 의 기존 `restored` 경로(같은 계정·같은 auid → 기존 슬롯)를 그대로 쓰고, 에이전트는 그 표시를 응답에 싣는다. IdP 는 바꾸지 않는다.

**Tech Stack:** 이전 계획과 같다(Node 22·Express·전역 스크립트 HTML·WebAuthn PRF·Playwright).

**Spec:** `docs/superpowers/specs/2026-11-17-mode3-passkey-mode-design.md` §10 (P11~P15)

## Global Constraints

- 이전 계획(`docs/superpowers/plans/2026-11-17-mode3-passkey-mode.md`)의 Global Constraints 를 그대로 따른다(커밋은 승인 뒤, 회로·IdP·스냅 불변, salt 저장 금지, localhost 전용, 체인 테스트 동시 실행 금지).
- IdP(`cia.js`, `mode3/cia_login.html`)는 바꾸지 않는다 — 인증 창은 늘 `/?authorize=1&idp_nonce&idp_code&idp_purpose=register&idp_uid&idp_auid` 로 돌아온다.
- sessionStorage 대기 키는 기존 `PENDING_KEY` 를 쓰고, 복구 요청은 `{ type: 'mode3-recover', profile }`. 결과 키는 `mode3_recover_result`. salt 는 두 키 어디에도 넣지 않는다.
- 패스키 모드가 아니면 복구 카드도 `mode3-recover` 처리도 없다(스냅·파일 모드 동작 불변).

## Review Focus

1. **돌아왔는데 등록이 이미 있음**(다른 탭이 먼저 복구): `/wallet/register` 409 `already_registered` 를 그대로 보이고 아무것도 바꾸지 않는다.
2. **IdP 를 다녀오는 동안 다른 패스키를 고름**(스텁은 allowCredentials 를 무시하지만 실제 브라우저에서는 연결된 패스키만 나온다): 계산한 auid ≠ `idp_auid` 면 `register_auid_mismatch` 로 멈춘다.
3. **복구 결과 키가 남음**: 결과를 한 번 보이면 `mode3_recover_result` 를 지운다(새로 고쳐도 다시 안 뜬다).
4. **속성 입력 오류**: 스키마에 없는 값이면 에이전트 400 `bad_attr` 를 사유 사전 문구로.
5. **salt 가 저장소에 남음**: 복구 전후 `sessionStorage`·`localStorage`(속성 도구 기록 키 제외)·상태 파일에 s_u 가 없다.

---

### Task 1: 에이전트가 `restored` 를 넘긴다

**Files:** Modify `mode3_wallet_agent.js`(`/wallet/register` 201 응답). Test `tests/test_mode3_wallet_passkey.mjs`.

**Interfaces:** Produces — `/wallet/register` 201 본문에 IdP 가 `restored: true` 를 주면 `restored: true`(아니면 키 없음).

- [ ] **Step 1: 실패하는 테스트** — `같은 auid 로 다시 등록하면 restored: true, 같은 slot` : 기존 케이스 순서에서 데모 리셋(등록 비움) 뒤, IdP 인증 창 API `POST /cia/auth/code { id: '12345', pwd: 'password123', auid, purpose: 'register' }` 로 코드를 받아 `/wallet/register { uid, code, s_u: S_U }` → 201, `restored === true`, `slot` 이 처음 등록과 같다.
- [ ] **Step 2:** `node tests/test_mode3_wallet_passkey.mjs` → 새 케이스 FAIL(`restored` 없음).
- [ ] **Step 3:** 201 응답에 `...(r.body.restored ? { restored: true } : {})`.
- [ ] **Step 4:** 같은 명령 → 전부 ok.

### Task 2: zk 스냅 화면의 계정 복구

**Files:** Modify `mode3/wallet.html`, `mode3/common/strings.js`. Test `tests/test_mode3_passkey_browser.mjs`.

**Interfaces:**
- Consumes: Task 1 의 `restored`; 기존 `goIdpAuth`·`takeIdpReturn`·`PENDING_KEY`·`passkeyStore`·`loadAttrBundle()`/`Mode3Attr.auidOf({ s_u })`·`/wallet/attr_schema`.
- Produces(테스트가 잡는 id): `#recoverCard`, `#recoverAttrs`(속성 입력들, `data-slot` = 스키마 슬롯 이름), `#recoverAuidBtn`(패스키 → auid 표시), `#recoverAuid`(auid 텍스트), `#recoverGoBtn`(인증 창으로), `#recoverVerdict`.

- [ ] **Step 1: 실패하는 테스트**(같은 파일 끝, 연결 끊기 케이스 뒤 — 그 케이스가 등록·연결을 모두 비운다):
  - `에이전트 파일을 잃어도 계정 복구로 같은 슬롯·같은 PPID` — 상태 파일을 `{}` 로 덮고 `stack.restartWallet()` → zk 스냅 화면 새로 고침 → 설정 카드 "이미 있는 패스키 쓰기" → `#recoverCard` 보임 → `#recoverAuidBtn` → `#recoverAuid` 가 `AUID_A` → `#recoverGoBtn` → IdP 인증 창(`atIdpLogin`)에 pk-user·비밀번호·`AUID_A` → 돌아와 `/` 에서 `#recoverVerdict` 에 "계정을 되찾았습니다" → `/wallet/status` 등록·slot 이 복구 전 기록과 같다 → 서비스 로그인(`loginAgain`) → PPID 집합 크기 1. 복구 동안 패스키 계산 2번(`hits.get`). `sessionStorage` 에 `mode3_recover_result` 없음, 저장소에 SALT_A 없음.
  - `인증 창에 다른 auid 를 넣으면 등록되지 않는다` — 다시 상태 파일 비우고 → 이미 있는 패스키 쓰기 → 복구 → 인증 창에 다른 auid(예: `AUID_A` 의 끝자리를 바꾼 값) → IdP 가 409(다른 auid)로 인증 창에서 막거나, 돌아오면 `register_auid_mismatch` — 어느 쪽이든 `/wallet/status` 미등록.
- [ ] **Step 2:** 실행 → 새 케이스 FAIL(`#recoverCard` 없음).
- [ ] **Step 3: 구현**
  - 복구 카드 HTML(`#setupCard` 아래, 탭과 함께 보이는 카드 — `data-panel` 없이 직접 hidden 제어). 보이는 조건: `PASSKEY() && !IS_AUTHORIZE && 연결됨 && !lastStatus?.registered`.
  - 속성 칸: `/wallet/attr_schema` 의 슬롯 중 `unused`·예비 슬롯(`isSpareSlot`) 제외, 기본값은 에이전트 기본(1990·KR — 스키마 이름이 같을 때).
  - `#recoverAuidBtn`: `passkeyStore.call('getSalt')` → `Mode3Attr.auidOf` → `#recoverAuid`(salt 는 버린다).
  - `#recoverGoBtn`: `goIdpAuth({ type: 'mode3-recover', profile }, location.origin, { purpose: 'register' })`.
  - `takeIdpReturn` 뒤 분기(`back.req?.type === 'mode3-recover'`): `passkeyStore.withSalt` 안에서 getSalt → auid 대조(`back.auid`) → `postJson('/wallet/register', { uid: back.uid, code: back.code, s_u, profile })` → `sessionStorage.setItem('mode3_recover_result', JSON.stringify({ ok, restored, reason }))` → `location.replace('/')`. 실패도 같은 키로.
  - `init` 끝: 결과 키가 있으면 `#recoverVerdict`(또는 등록 뒤라면 `#setupNotice`)에 보이고 키를 지운다.
  - 문구 키: 카드 제목·설명·버튼, `wallet_recover_done_restored`("계정을 되찾았습니다(같은 슬롯)"), `wallet_recover_done_new`("새로 등록했습니다"), `wallet_recover_failed`.
- [ ] **Step 4:** `node tests/test_mode3_passkey_browser.mjs` 전부 ok, `node tests/test_mode3_demo_strings.js` all ok.

### Task 3: 문서

**Files:** Modify `docs/MODE3_DEMO.md`(패스키 절에 "계정 복구" 한 항목, 오류 표에 복구 경로 사유).

- [ ] **Step 1:** 패스키 절에 계정 복구 흐름(P11~P15) 요약, 미검증 그대로.
- [ ] **Step 2:** `node tests/test_mode3_demo_strings.js` all ok.

## 마지막 검증

`bash scripts/run_tests.sh unit`, `node tests/test_mode3_wallet_passkey.mjs`, `node tests/test_mode3_passkey_browser.mjs`, 스냅 모드 회귀 `node tests/test_mode3_browser.mjs`(wallet.html 공통 경로를 건드리므로). 최종 리뷰는 Opus.
