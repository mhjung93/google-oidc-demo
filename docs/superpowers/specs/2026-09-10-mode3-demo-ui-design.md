# Mode 3 — 데모 UI 연동 설계

**상태: 설계 확정. 구현 전.**
작성 2026-09-10. 단계 (a) 오프체인 전 구간(`7d7e456`)이 테스트로 고정된 뒤, 그 위에 시연
가능한 UI를 올리는 설계다. 2026-09-10 설계 대화에서 정해진 내용을 옮긴다.

**상위 문서:** `2026-09-09-mode3-cia-revocation-design.md` (이하 "설계"). 이 문서는 설계의
프로토콜·파라미터를 바꾸지 않는다. 바뀌는 것은 "누가 어느 프로세스에서 어느 버튼으로
그 프로토콜을 돌리는가"뿐이다.

---

## 1. 결정 사항 (설계 대화 요약)

| 질문 | 결정 | 이유 |
|---|---|---|
| 지갑 로직을 어디서 돌리나 | **Node 지갑 에이전트 프로세스** (`mode3_wallet_agent.js`, :5100). 브라우저 내 증명은 별도 후속 | `lib/mode3_wallet.js`가 Node 전용(`fs`로 wasm·zkey 11.7MB 읽음). Mode 2의 `wallet_agent.js` 패턴과 같아 데모 구조가 일관되고, `tests/test_mode3_e2e.mjs`의 조립 코드를 거의 그대로 옮길 수 있다. 설계 §8.3의 브라우저 증명 시간(3~5배)은 이 단계에서 실측되지 않는다 |
| RP를 어디에 두나 | **별도 서버** `mode3_rp.js` (:3100) | `server.js`(:3000)는 Mode 1/2 전용으로 그대로. 단계 (a)에서 지켜온 "Mode 2 파일 무변경"을 유지하고 실행 중인 데모 스택과 충돌하지 않는다 |
| 페이지 구성 | **지갑 페이지(:5100) + RP 로그인 페이지(:3100)**, 브라우저가 두 오리진을 직접 호출 | Mode 2의 relay/popup 경로는 데모 목적에 과하다 |
| 폐기·복구 조작 | **CIA 관리자 패널** (`:4100/admin`) | e2e가 보여주는 핵심(폐기 → 게시 → 거절 → 복구 → PPID 유지)이 시연의 요점이다. curl로 하면 시연이 끊긴다 |

---

## 2. 구성 요소와 포트

| 프로세스 | 포트 | 파일 | 역할 |
|---|---|---|---|
| hardhat 노드 | :8545 | (사용자 프로세스) | `RevocationLog` |
| CIA | :4100 | `cia.js` (기존) + `/admin` 라우트 1개 | 등록·발급·폐기·게시 + 관리자 패널 |
| 지갑 에이전트 | :5100 | `mode3_wallet_agent.js` (신규) | 지갑 상태·트리 동기화·증명 생성, 지갑 페이지 |
| RP | :3100 | `mode3_rp.js` (신규) | challenge 발급·로그인 검증, 로그인 페이지 |

정적 페이지 셋은 `mode3/` 디렉터리에 둔다: `wallet.html`, `rp.html`, `cia_admin.html`.
프레임워크 없는 vanilla JS, 스타일은 `index.html`과 같은 수준(시연용). 각 서버는
`server.js`처럼 **허용 목록 `sendFile`**만 하고 `express.static`으로 루트를 서빙하지
않는다(2026-09-04 개인키 노출 사고의 교훈, `server.js`의 `PUBLIC_STATIC_FILES` 주석 참조).

**Mode 2 파일은 손대지 않는다.** `cia.js`는 Mode 3 파일이다.

---

## 3. 지갑 에이전트 `mode3_wallet_agent.js`

`lib/mode3_wallet.js`를 그대로 쓴다. 새 암호학 코드는 없다.

### 3.1 상태

`mode3_wallet_state.json` (저장소 루트, 0600, `.gitignore`, `lib/mode3_state.js`의
`writeJsonAtomic`). 데모용이므로 비밀이 평문으로 들어간다.

```
{
  uid, s_u, r_u, cm_u: {x, y}, sk_u,                 // 등록 (§6.1). 한 번
  credentials: {
    [arid]: { credential: {C, max_height, sigma, pk_CIA}, blind, sessionPrivKey, pk_i }
  }
}
```

credential은 **arid별로** 보관한다 — 설계 §4.1에서 `arid`가 `C` 안에 들어가므로 RP마다
별개의 credential이다. 세션키(secp256k1)는 credential과 1:1이다(`pk_i`가 `C`에 박혀 있다).

`ProofCache`(root, 세션 주소)는 메모리에만 둔다. 재시작하면 π를 다시 만들면 된다.

### 3.2 API (JSON, `127.0.0.1` 바인드)

**`GET /wallet/status`** — 페이지 표시용. 등록 여부·uid, arid별 credential(만료 높이,
세션 주소, 발급 시각), 체인 head, 마지막 동기화 root, 캐시된 π의 root. 비밀은 내보내지
않는다.

**`POST /wallet/register {uid, pwd}`** — `createRegistration()` → CIA `POST /cia/register`
→ 응답의 `sk_u`와 함께 저장. 이미 등록돼 있으면 409.

**`POST /wallet/login {arid, challenge, skipSync?}`** — **RP 페이지 오리진에서 호출된다.**
CORS는 이 경로에 RP 오리진(`MODE3_RP_ORIGIN`, 기본 `http://127.0.0.1:3100`)만 연다.

1. `skipSync`가 아니면 `syncRevocationTree(provider, logAddress)`. root 불일치나 RPC
   다운이면 503 `{reason:'chain_unavailable'}`.
2. 그 arid의 credential이 **없거나**, **만료**(`head > max_height`)거나, **리프가 트리에
   있으면**(폐기됨) → **자동 발급**: 새 세션키 + `buildIssueRequest` → CIA `POST /cia/issue`.
   CIA 403이면 403 `{reason:'account_disabled'}`, 그 밖의 CIA 오류는 502.
   응답에 `issued:true`를 실어 페이지가 "새 credential 발급"을 표시한다.
3. `ProofCache.get(root, 세션 주소)` 히트면 재사용, 아니면 `buildCredentialProof` 후 캐시.
4. `signChallenge(세션 지갑, challenge)`.
5. 반환 `{proof, publicSignals, sig, pk_i, root, issued}`.

`skipSync`면 1·2를 건너뛰고 **마지막으로 캐시된 π를 그대로** 서명해 돌려준다. 캐시가
비어 있으면 409 `{reason:'no_cached_proof'}`. 이것은 RP에서 `stale_root` 거절을 시연하기
위한 스위치이고, 설계 §8.2(N=1)·§8.4(π 재사용)를 눈으로 보여준다.

**응답에 `uid`를 절대 넣지 않는다.** RP는 PPID만 본다(설계 §2.3, Mode 2의 uid/salt 경계와
같은 원칙).

### 3.3 왜 "발급" 버튼이 따로 없나

설계 §6.2는 "발급 (세션마다)"다. 로그인이 곧 세션이므로 발급은 로그인 안에서 필요할 때
일어나는 것이 설계와 일치한다. 폐기 → 복구 → 재로그인 시나리오가 이 자동 발급 하나로
`tests/test_mode3_e2e.mjs`와 동일하게 재현된다. 별도 버튼은 YAGNI.

### 3.4 설정

| env | 기본 | 뜻 |
|---|---|---|
| `MODE3_WALLET_PORT` | 5100 | |
| `MODE3_WALLET_STATE_FILE` | `./mode3_wallet_state.json` | 격리 테스트가 임시 경로를 넣는다 |
| `MODE3_CIA_URL` | `http://127.0.0.1:4100` | |
| `MODE3_RP_ORIGIN` | `http://127.0.0.1:3100` | CORS 허용 오리진 |
| `CIA_LOG_ADDRESS` | (필수) | `RevocationLog` 주소. RP·CIA와 같은 값 |
| `CIA_RPC_URL` | `http://127.0.0.1:8545` | |

---

## 4. RP `mode3_rp.js`

`createRpVerifier()` 하나로 검증한다. 설계 §6.3의 7단계는 전부 `lib/mode3_rp.js` 안에
있고 여기서는 challenge 관리와 HTTP만 붙인다.

### 4.1 `pk_CIA` 고정

설계 §5에서 `pk_CIA` 대조는 **유일한 위조 방어선**이고 "설정에 박힌 키"여야 한다.
`MODE3_PK_CIA_X`/`MODE3_PK_CIA_Y` env가 있으면 그것을 쓴다. 없으면 **기동 시 CIA
`GET /cia/public_keys`에서 한 번 받아 로그에 찍고 프로세스 수명 동안 고정**한다(TOFU).
후자는 데모 단축이며 `docs/MODE3_DEMO.md`에 "운영이라면 env로 박는다"고 명시한다.
기동 후에는 CIA에 다시 묻지 않는다(설계 §9.9 — CIA는 조회 경로에 있어서는 안 된다).

### 4.2 API

**`GET /`** → `mode3/rp.html`.

**`GET /api/mode3/rp_info`** → `{arid, logAddress, walletAgentOrigin}`. 페이지가 지갑
에이전트 주소와 arid를 안다.

**`POST /api/mode3/challenge`** → `{challenge, expiresAt}`. 32바이트 무작위 hex. 메모리
`Map`에 **2분 TTL, 1회용**. 만료된 항목은 발급 때마다 걷어낸다.

**`POST /api/mode3/login {challenge, proof, publicSignals, sig}`**
1. challenge가 발급된 적 없거나, 만료됐거나, 이미 쓰였으면 401 `{ok:false, reason:'bad_challenge'}`.
   검증기 호출 **전에** 소비 표시한다(실패해도 재사용 불가).
2. `verifyLogin(...)` → 성공 `{ok:true, PPID, pk_i}`, 실패 `{ok:false, reason}` (검증기의
   reason 그대로: `chain_unavailable`, `stale_root`, `expired`, `untrusted_cia`, `wrong_arid`,
   `bad_proof`, `bad_signature`, `malformed`).
3. 성공은 메모리 목록 `logins[]`(PPID, 시각, root)에만 기록한다. **쿠키·세션 없음** —
   데모의 요점은 검증 결과다. `GET /api/mode3/logins`로 페이지가 목록을 본다.

### 4.3 설정

| env | 기본 | 뜻 |
|---|---|---|
| `MODE3_RP_PORT` | 3100 | |
| `MODE3_RP_ARID` | `22222222222222222222` | e2e와 같은 값. 스칼라 < 2²⁵⁰ |
| `MODE3_PK_CIA_X`, `MODE3_PK_CIA_Y` | (없으면 TOFU) | §4.1 |
| `MODE3_CIA_URL` | `http://127.0.0.1:4100` | TOFU 때만 |
| `MODE3_WALLET_AGENT_ORIGIN` | `http://127.0.0.1:5100` | 페이지에 알려줄 값 |
| `CIA_LOG_ADDRESS` | (필수) | |
| `CIA_RPC_URL` | `http://127.0.0.1:8545` | |

---

## 5. CIA 관리자 패널

`cia.js`에 **`GET /admin` → `mode3/cia_admin.html` `sendFile` 한 라우트만** 추가한다.
페이지는 secret을 입력받아 `X-CIA-Admin-Secret` 헤더로만 쓰고 저장하지 않는다
(`localStorage`도 안 쓴다). 버튼:

| 버튼 | 호출 (전부 기존 API) |
|---|---|
| 상태 보기 | `GET /cia/state` |
| 계정 폐기 | `POST /cia/revoke {uid, scope:'account'}` |
| 게시 | `POST /cia/publish` |
| 복구 | `POST /cia/account/set_disabled {uid, disabled:false}` |

새 API는 없다. 같은 오리진이라 CORS도 없다.

`cia.js`에 `import 'dotenv/config'`를 추가해 `custom_idp.js`·`server.js`·`wallet_agent.js`와
같이 `.env`를 읽게 한다. 격리 하네스(`tests/helpers/isolated_cia.mjs`)는 env를 명시적으로
넘기고 dotenv는 이미 있는 값을 덮지 않으므로 테스트에 영향이 없다. (`.env`에
`CIA_TTL_BLOCKS`처럼 하네스가 넘기지 않는 값이 있으면 격리 CIA도 그 값을 보게 되는데,
현재 `.env`에는 `CIA_*`가 없다는 전제이며 `MODE3_DEMO.md`에 적어 둔다.)

---

## 6. 브라우저 흐름과 시연 각본

RP 페이지의 `[Mode 3 로그인]`:

```
→ RP  GET  /api/mode3/rp_info            (arid, walletAgentOrigin)
→ RP  POST /api/mode3/challenge          (challenge)
→ 지갑 POST :5100/wallet/login {arid, challenge, skipSync}     ← CORS
→ RP  POST /api/mode3/login {challenge, proof, publicSignals, sig}
→ 표시: PPID 또는 reason, 단계별 소요 시간(동기화·발급·증명·검증)
```

체크박스 `동기화 생략(캐시된 π 재사용)` = `skipSync`.

**시연 각본** (e2e `tests/test_mode3_e2e.mjs`의 7단계와 같다):

| # | 조작 | 기대 |
|---|---|---|
| 1 | 지갑 페이지: 등록 (`12345` / `password123`) | 201, 지갑 상태에 uid 표시 |
| 2 | RP 페이지: 로그인 | `issued:true`, PPID 표시 |
| 3 | RP: 로그인 (다시) | 캐시된 π 재사용(증명 시간 ≈ 0), 같은 PPID |
| 4 | 관리자 패널: 계정 폐기 → 게시 | epoch +1 |
| 5 | RP: 생략 체크 → 로그인 | `stale_root` |
| 6 | RP: 생략 해제 → 로그인 | 지갑이 폐기를 감지해 재발급 시도 → `account_disabled` |
| 7 | 관리자 패널: 복구 | `disabled:false` |
| 8 | RP: 로그인 | `issued:true`, **PPID가 2와 동일** (설계 §6.6) |

---

## 7. 오류 처리와 경계

- 지갑 에이전트·RP 모두 `127.0.0.1`에 바인드한다. CORS는 지갑의 `/wallet/login`에 RP
  오리진만. 지갑 페이지·상태 API는 같은 오리진에서만.
- RPC 다운: 지갑 503 `chain_unavailable`; RP는 검증기의 fail-closed(설계 §8.5) 그대로 —
  10분 안의 캐시된 뷰만 인정.
- 지갑 에이전트는 사용자 한 명(데모)이다. 동시 요청은 직렬화하지 않는다 — 상태 파일은
  원자적으로 쓰이므로 깨지지는 않고, 마지막 쓰기가 이긴다.
- **재시연 메모.** `cia_state.json` 삭제는 Mode 2의 `idp_state.json`과 같은 이유로 금지 —
  체인의 `RevocationLog.root`와 어긋나 `syncRevocationTree`가 전원을 막는다. 재시연은
  "hardhat 재시작 → `deploy_mode3_log.cjs` 재배포 → `.env`의 `CIA_LOG_ADDRESS` 갱신 →
  `cia_state.json`·`mode3_wallet_state.json` 삭제 → CIA·지갑·RP 재시작"을 **한 세트로만**
  한다. `docs/MODE3_DEMO.md`에 적는다.

---

## 8. 테스트 (chain 그룹)

- `tests/helpers/isolated_mode3_stack.mjs` — 격리 CIA(기존 `isolated_cia.mjs`) + 지갑
  에이전트 + RP를 임시 포트·임시 상태 파일로 띄우고 내린다. 지갑 에이전트에는 CIA URL과
  RP 오리진을, RP에는 CIA URL(TOFU)과 지갑 오리진을 env로 넘긴다. `stop()`이 세 프로세스와
  임시 디렉터리를 정리한다.
- `tests/test_mode3_demo_stack.mjs` — HTTP만으로 §6 각본 8단계 전체. 음성:
  challenge 미발급·재사용·만료(짧은 TTL을 env로 주입) 거절, `skipSync` → `stale_root`,
  캐시 없는 `skipSync` → 409, `/wallet/login` 응답에 `uid` 키 부재, `Access-Control-Allow-Origin`이
  RP 오리진에만 붙고 다른 `Origin`에는 없음.
- 브라우저 페이지는 자동화하지 않는다. 실제 스택에서 수동 스모크(playwright로 한 번 확인).
- `scripts/run_tests.sh`의 CHAIN에 등록한다.

---

## 9. 파일

**신규:** `mode3_wallet_agent.js`, `mode3_rp.js`, `mode3/wallet.html`, `mode3/rp.html`,
`mode3/cia_admin.html`, `tests/helpers/isolated_mode3_stack.mjs`,
`tests/test_mode3_demo_stack.mjs`, `docs/MODE3_DEMO.md`

**수정:** `cia.js`(`/admin` 라우트 + dotenv), `.gitignore`(`mode3_wallet_state.json`),
`scripts/run_tests.sh`(CHAIN), `scripts/deploy_mode3_log.cjs`(배포하면서 CIA 주소에 ETH를 넣는다 —
CIA가 `publishRoot` tx를 자기 키로 보내므로 가스비가 필요한데, 격리 하네스와 달리 실제 데모에는
그 단계가 없었다)

**손대지 않음:** `server.js`, `client.js`, `wallet_agent.js`, `custom_idp.js`, `index.html`,
`lib/mode3_*.js`, `contracts/`, `circuits/`, `build/`

---

## 10. 이 문서가 다루지 않는 것

- 브라우저 내 증명(설계 §8.3의 브라우저 T 실측) — 별도 후속
- RP 세션·쿠키·로그아웃 — 데모 범위 밖
- 관리자 패널의 인증 강화 — secret 헤더 그대로
- Poseidon 전환(설계 §12 보류)
