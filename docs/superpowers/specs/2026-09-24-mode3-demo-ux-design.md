# Mode 3 데모 UX 개선 (1차) — 공통 안내 레이어·시각 정비·용어·오류 번역

2026-09-24. Mode 3 데모 페이지 네 개(`mode3/wallet.html` 586줄, `rp.html` 353줄, `cia_admin.html` 188줄,
`cia_account.html` 53줄)는 스타일 없는 "개발자 콘솔" 형태다 — 버튼·fieldset·원문 로그가 나열되고 문구가
내부 용어(`PPID`, `stale_root`, "정확히 공개(체크된 슬롯)") 그대로다. 이 문서는 세 청중(발표 청중, 개발자·연구자,
혼자 체험하는 사용자)을 위해 페이지를 다시 짜는 1차 범위를 정한다.

## 0. 결정 사항 (설계 대화 요약)

| 질문 | 결정 |
|---|---|
| 1순위 청중 | 셋 전부 — 비개발자 발표, 개발자 검증, 일반 사용자 혼자 체험 |
| 화면 구성 | **당사자별 페이지 분리 유지 + 공통 안내 레이어**(대시보드 통합 안 함 — "한 페이지가 셋을 다 본다"는 인상이 프라이버시 주장과 어긋난다) |
| 프런트 기술 | **순수 HTML/JS, 빌드 없음, 새 의존성 없음.** 공통 파일은 `mode3/common/`에 두고 세 서버가 서빙 |
| 1차 범위 | ① 시각·레이아웃 ② 단계 안내 바 ③ 용어 개편 + 전문가 보기 토글 ④ 오류 사유의 쉬운 말 번역 |
| 2차로 미룸 | 스택 상태 패널(프로세스·root 나이·하트비트), 혼자 체험 모드(버튼 잠금·튜토리얼), Snap 자체 UI, Mode 2 페이지 |
| 언어 | **한국어 + 영어 토글**(기본 한국어). 문구 사전 하나에 두 언어 |
| 테스트 계약 | `tests/test_mode3_browser.mjs` 는 **수정 없이** 통과해야 한다 — 요소 id 와 한국어 판정 문구 유지 |

## 1. 구조 — 공통 레이어와 서빙

### 1.1 새 파일 `mode3/common/`

| 파일 | 책임 |
|---|---|
| `demo.css` | 색·간격 변수, 카드·배지·버튼·표·진행 표시줄·토스트·스피너, `.expert` 숨김 규칙, 1열/2열 반응형 |
| `strings.js` | 문구 사전. `window.DemoStrings = { ko: {...}, en: {...}, expert: {...}, reasons: {...}, steps: [...] }` |
| `demo.js` | `window.Demo` — 언어·전문가 토글(+`localStorage`), 안내 바 렌더, 결과 카드·오류 번역, 공통 `Demo.call()` |

세 파일 모두 전역 스크립트다(모듈 아님 — 페이지가 `file://` 이 아니라 각 서버에서 열리지만 기존 페이지가 전역 스크립트 방식이라 맞춘다).

### 1.2 서버 변경(세 줄)

`cia.js`, `mode3_rp.js`, `mode3_wallet_agent.js` 각각에
`app.use('/common', express.static(path.join(__dirname, 'mode3', 'common')))` 한 줄. 그 밖의 서버 변경은 §1.3 의 `ciaUrl` 응답 필드 추가(서비스 `rp_info`, 지갑 `/wallet/status`)뿐이다 — 검증·발급·폐기 로직은 건드리지 않는다.
지갑 에이전트의 `/common` 은 기존 정적 응답과 같은 CORS 정책(열지 않음)을 따른다 — 같은 오리진 페이지만 읽는다.

### 1.3 페이지 공통 골격

```html
<link rel="stylesheet" href="/common/demo.css">
<script src="/common/strings.js"></script>
<script src="/common/demo.js"></script>
<body data-page="wallet|rp|admin|account">
  <header id="demoBar"></header>          <!-- Demo.guide() 가 그린다 -->
  <main class="cards"> …카드들… </main>
</body>
```

- `Demo.init({ page })` 가 `#demoBar` 에 진행 표시줄·언어·전문가 토글을 그리고, `data-i18n="key"` 속성이 있는 요소의 텍스트를 사전으로 채운다. 언어를 바꾸면 같은 함수가 다시 돈다.
- 다른 당사자 페이지 링크: 서비스 페이지는 `rp_info.walletAgentOrigin`(지갑)과 `rp_info.ciaUrl`(AA, **응답에 필드 하나 추가** — 값은 기존 `CIA_URL` 설정, 로직 변경 아님)으로 링크한다. 지갑 페이지는 `/wallet/status` 에 같은 방식으로 추가하는 `ciaUrl` 로 AA 계정·관리자 페이지에 링크한다. 관리자·계정 페이지는 서로만 링크한다(서비스·지갑 주소를 모른다). 그 밖의 **새 API 는 만들지 않는다** — 값이 없으면 링크를 숨긴다.

### 1.4 browser 테스트 계약

테스트가 붙잡는 id 는 그대로 둔다: 지갑 `#connectBtn #mmStatus #snapPanel #fileRegFields #uid #pwd #registerBtn #registerResult #refreshBtn #status #sessionActions #sessionLog #txSession #txTo #txData #dk0 #discLo0 #discHi0 #setSlot #txBtn #txVerdict #txLog #forgedBtn`,
서비스 `#walletMode #allowAgent #loginBtn #verdict #log #sessionId #revalidateBtn #skipSync #requestBtn #sessionVerdict #sessionLog`.
판정 문구('로그인 성공', '등록됨', '전송 성공', '재검증 성공', '재승인 불가', '팝업이 차단됐다', '지갑 비밀=snap', `user_denied`, `factory_constants_unavailable`)는 사전의 한국어 값이 되고 기본 언어가 한국어이므로 테스트는 그대로다. 원문 로그 요소를 `.expert` 로 숨겨도 `textContent` 는 남는다. `window.__snapOnRpcRequest` 주입도 그대로.

## 2. 안내 바와 단계 모델

### 2.1 전역 7단계

| # | 키 | 단계 | 어디서 | 완료 신호(페이지가 자기 것만 판단) |
|---|---|---|---|---|
| 1 | approve | 서비스 승인 | AA 관리자 | 서비스: `rp_info.status === 'approved'`; 관리자: 대기 서비스 0 |
| 2 | register | 지갑 등록 | 지갑 | 지갑: `status.registration` 존재 |
| 3 | login | 로그인 | 서비스 | 서비스: 세션 `r_s` 존재; 지갑: `status.sessions` 비어 있지 않음 |
| 4 | use | 이용 | 서비스·지갑 | 서비스: 재검증 또는 요청 성공 1회; 지갑: 트랜잭션 성공 1회 |
| 5 | disclose | 공개·조건 | 지갑·서비스 | 지갑: mask≠0 또는 set 트랜잭션 성공; 서비스: `require` 로그인 성공 |
| 6 | revoke | 폐기·복구 | 지갑·계정·관리자 | 지갑: 세션 폐기 1회; 관리자: 계정 폐기 또는 게시 1회 |
| 7 | open | 승인 개봉 | 서비스·관리자 | 서비스: 개봉 결과 수신; 관리자: 개봉 승인 1회 |

- 완료 판단은 **세션 중 메모리**(페이지 변수)와 서버 상태 조회로만 한다. 페이지 간 공유 저장소·새 API 는 없다. 다른 당사자에서 끝나는 단계는 "다른 창에서 진행 중" 상태로 표시한다.
- 4~7단계는 순서를 강제하지 않는다. 안내 바는 "권장 다음 단계"를 제안할 뿐 버튼을 잠그지 않는다(잠금은 2차 체험 모드).

### 2.2 `Demo.guide()`

```js
Demo.guide({ done: ['approve','register'], current: 'login', hint: 'login_hint_rp' /* 사전 키 */, links: { rp: url, wallet: url, admin: url } })
```

각 페이지의 `refresh()`(또는 상태를 다시 읽는 함수) 끝에서 한 번 부른다. 렌더 내용: 진행 표시줄(1~7, 완료·현재·미완·다른 창), 현재 단계 한 줄 설명, "다음: [당사자]에서 [조작]" 문장, 그 당사자 페이지로 가는 링크 버튼, 오른쪽에 언어 토글·전문가 보기 토글.

### 2.3 카드 머리 설명

각 카드는 제목 아래 한 줄 설명(`data-i18n`)을 갖는다. 예 — 로그인 카드: "지갑이 신원 기관의 서명과 영지식 증명으로 이 서비스 전용 주소를 만듭니다. 신원 기관은 어느 서비스인지 모릅니다." 전문가 보기에서는 그 아래 `.expert` 줄에 원래 기호와 값이 펼쳐진다.

## 3. 용어·전문가 보기·오류 번역

### 3.1 두 층의 표기

사전 항목은 `{ ko, en, expert? }`. `expert` 는 원래 기호(선택). 대표 대응:

| 내부 용어 | ko | en | expert |
|---|---|---|---|
| PPID | 이 서비스에서의 내 주소 | My address at this service | `PPID = Poseidon(uid, s_u, chainid, arid)` |
| AA/CIA | 신원 기관 | Identity authority | `pk_CIA` |
| r_s / 세션 | 로그인 세션 | Login session | `r_s`, `pk_i`, `max_height` |
| root / RCL | 폐기 목록 버전 | Revocation list version | root, epoch, 나이(블록) |
| π_rp | 영지식 증명 | Zero-knowledge proof | 증명 ms, 캐시 히트 |
| disc_mask/lo/hi, set | 공개할 속성 조건 | Attribute conditions to reveal | mask·lo·hi·set_sel·set_root |
| C_u / C_s | 내 자격증명 / 세션 표 | My credential / session ticket | `Cf_u`, `Cf_s` |
| 태그 / 개봉 | 추적용 봉인 | Sealed trace | `c1`, `c2`, `pk_trace` |
| allowAgent | AI 에이전트 허용 | Allow AI agent | `allowAgent ∈ {0,1}` |
| 속성 a₀..a₃ | 출생연도·국가·등급·예비 | Birth year·Country·Tier·Spare | `attrs[0..3]`, 64비트 |

### 3.2 전문가 보기

`<html data-expert="1">` 이면 `.expert` 요소가 보인다(기본 숨김). 토글은 `localStorage` 에 기억한다. 결과 카드는 항상 "한 줄 요약 + 접힌 '자세히'(원본 JSON)" 구조이고, 전문가 보기에서는 '자세히'가 펼쳐진 채 뜬다. 기존 원문 로그(`#log`, `#sessionLog`, `#txLog`, `#out`, `#openLog`, `#authLog`)는 남기고 `.expert` 로 감싼다.

### 3.3 오류 사유 사전

`DemoStrings.reasons[code] = { ko: {title, cause, action}, en: {...}, where }`. 대상 코드(현재 `docs/MODE3_DEMO.md` 에 문서화된 것 전부):

| 어디 | 코드 |
|---|---|
| 서비스 | `stale_root`, `root_too_old`, `revalidate_required`, `predicate_unmet`, `factory_constants_unavailable`, `registration_pending`, `bad_signature`, `bad_rp_cert`, `bad_proof`, `expired`, `malformed` |
| 지갑 에이전트 | `revoked`, `revoked_session`, `account_disabled`, `needs_consent`, `bad_rp_cert`, `bad_factory`(하위 `no_code`, `factory_code_mismatch`, `verifier_code_mismatch`), `allow_agent_mismatch`, `no_session`, `not_registered`, `cia_unavailable`, `witness_required`, `internal` |
| 지갑 페이지(승인 팝업) | `user_denied`, `snap_unavailable`, `wallet_error`, 팝업 차단 |
| AA | `unknown_session`, `no_user_cred`, `unknown account`, `admin secret required` |

예: `stale_root` → 제목 "폐기 목록이 오래됐습니다", 원인 "지갑이 최신 폐기 목록으로 증명하지 않았습니다", 조치 "'동기화 생략'을 끄고 다시 재검증하세요". 사전에 없는 코드는 코드 그대로 + '자세히'로 떨어진다(숨기지 않는다). 구현자는 각 코드의 실제 발생 조건을 `docs/MODE3_DEMO.md` 사유 표와 해당 소스에서 확인해 문구를 쓴다 — 추측으로 쓰지 않는다.

### 3.4 결과 카드

- 성공: 초록 배지 + 판정 문구(테스트 needle 유지) + 한 줄 요약. 예: "로그인 성공 — 새 세션. 이 서비스에서의 내 주소는 이전과 같습니다."
- 실패: 빨간 배지 + 제목·원인·조치 3줄 + '자세히'.
- 진행 중: 스피너 + "증명 생성 중(약 1초)" 같은 예상 시간 문구(사전 키).

## 4. 페이지별 구성

### 4.1 지갑 `wallet.html`

안내 바 → 카드 순서:
1. **내 신원** — 등록 상태 배지, 속성 4칸 읽기 전용(이름은 3.1 표), "신원 기관에서 다시 받기"(기존 `#attrsBtn`). file 모드 등록 폼(`#fileRegFields`)은 미등록일 때만 펼쳐진다.
2. **로그인 세션** — 세션마다 서비스명(arid 대신 `rp_info` 가 있으면 이름, 없으면 origin)·주소 요약·만료 블록·AI 에이전트 여부·"이 세션 끝내기(폐기)"(V8 `/wallet/session/revoke`, snap 모드는 `consentRevokeSession` 선행). 전문가: `r_s`, `Cf_s`, `pk_i`.
3. **트랜잭션 보내기** — 세션 선택·받는 주소·값·데이터. 접힌 "공개할 조건" 패널: 슬롯 체크·범위·집합·"나이 ≥" 프리셋(기존 id 유지). 결과 카드 `#txVerdict`.
4. **MetaMask·Snap** — snap 모드에서만 보임(`#snapPanel`). 연결·상태·자기 폐기·초기화(파괴적).

승인 팝업 뷰(`#authorizeView`)는 독립 카드: 서비스명·origin·요청 조건(허용 국가·최소 나이·AI 에이전트)을 문장으로, "허용/거절" 두 버튼. 단계·로그(`#authStep`, `#authLog`)는 `.expert`.

### 4.2 서비스 `rp.html`

1. **서비스 상태** — 승인 대기/활성 배지, 정책(허용 국가·최소 나이)을 문장으로, 지갑 모드 배지(`#walletMode`).
2. **로그인** — AI 에이전트 허용(`#allowAgent`)·조건 요구(`#requirePred`) 체크, "로그인"(`#loginBtn`) → 결과 카드 `#verdict`.
3. **내 세션** — 세션 요약, "재검증"(`#revalidateBtn`)·"세션 요청"(`#requestBtn`) → `#sessionVerdict`; "동기화 생략"(`#skipSync`)은 `.expert`.
4. **로그인 기록** — 표(주소 요약·시각·공개 조건·AI 에이전트), 행마다 "개봉 요청".
5. **승인 개봉** — 요청·상태 조회·해시로 개봉, 결과 카드(`#openLog` 는 `.expert`).

### 4.3 관리자 `cia_admin.html`

1. 시크릿 입력(세션 동안 기억).
2. 상단 배지: 승인 대기 서비스 n, 개봉 요청 n(로드 시와 새로고침 때 갱신).
3. 계정 표 — 속성 편집·폐기·복구·세션 목록/폐기(V8).
4. 서비스 표 — 승인.
5. 개봉 요청 표 — 승인/거절·결과.
6. 폐기 목록 카드 — root·epoch·pending 수·"게시".
원문 `#out` 은 `.expert`.

### 4.4 계정 `cia_account.html`

한 카드 "내 계정 폐기"(uid·pwd·결과). 안내 바는 6단계로 연결.

### 4.5 공통 규칙

- 파괴적 버튼(폐기·초기화·게시)은 빨간 외곽선 + `confirm` 한 번.
- 모든 fetch 는 `Demo.call(label, () => fetch…)` 를 거쳐 진행 중 스피너·오류 카드를 자동으로 그린다. 기존 페이지의 fetch 헬퍼를 감싸는 방식이고 요청·응답 형식은 바꾸지 않는다.
- 반응형: 창 폭 ≤ 900px 1열, 그 외 2열.
- 접근성 최소: 버튼은 `<button>`, 배지 색에 텍스트 동반, 포커스 링 유지.

## 5. 오류 처리와 경계

- 사전 로드 실패(`/common` 404): 페이지는 기존 텍스트로 동작해야 한다 — `data-i18n` 요소는 HTML 안에 한국어 기본 텍스트를 가진다.
- 언어 전환은 페이지 재요청 없이 DOM 텍스트만 바꾼다. 서버 응답의 문자열(예: 판정 원문)은 번역하지 않고 사유 코드만 번역한다.
- 전문가 보기 토글은 요소를 숨길 뿐 제거하지 않는다(테스트·디버그 계약).

## 6. 테스트

| 그룹 | 파일 | 내용 |
|---|---|---|
| unit | `tests/test_mode3_demo_strings.js`(신규) | 사전의 모든 `reasons` 코드에 ko·en 둘 다 있는지; 판정 문구 키 값이 browser 테스트 needle 목록과 일치하는지(needle 목록을 테스트 안에 상수로 둔다); `steps` 가 7개이고 키가 고유한지 |
| browser | `tests/test_mode3_browser.mjs`(무수정) | 통과해야 한다 |
| chain | `tests/test_mode3_demo_stack.mjs`(무수정) | 통과해야 한다 |
| 수동 | 각본 `docs/MODE3_DEMO.md` | 네 페이지를 한국어·영어·전문가 보기로 한 번씩 스크린샷(Playwright 스크립트 `scripts/screenshot_mode3.mjs` 신규, 결과는 `results/mode3_ux_20260924/`) |

## 7. 파일

| 파일 | 변경 |
|---|---|
| `mode3/common/demo.css`, `strings.js`, `demo.js` | 신규 |
| `mode3/wallet.html`, `rp.html`, `cia_admin.html`, `cia_account.html` | 마크업 재구성·`data-i18n`·`Demo.*` 호출. id 유지 |
| `cia.js`, `mode3_rp.js`, `mode3_wallet_agent.js` | `/common` 정적 서빙 한 줄씩; `rp_info`·`/wallet/status` 응답에 `ciaUrl` 필드 추가 |
| `tests/test_mode3_demo_strings.js`, `scripts/screenshot_mode3.mjs` | 신규; `scripts/run_tests.sh` unit 그룹 등록 |
| `docs/MODE3_DEMO.md` | 각본의 버튼 이름을 새 문구로, 언어·전문가 토글 설명 |

## 8. 이 문서가 다루지 않는 것

스택 상태 패널, 체험 모드(버튼 잠금·튜토리얼), Snap 자체 UI, Mode 2 페이지, 서버 API 변경, 새 의존성·빌드, 접근성 감사, 다크 모드.
