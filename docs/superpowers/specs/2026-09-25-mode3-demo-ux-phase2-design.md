# Mode 3 데모 UX 개선 (2차) — 스택 상태 패널·혼자 체험 모드

2026-09-25. 1차(`docs/superpowers/specs/2026-09-24-mode3-demo-ux-design.md`, 구현 완료 f7a09de)가 미룬 두 항목을 공통 레이어
`mode3/common/` 위에 얹는다. 1차가 만든 안내 바·사전·결과 카드·전문가 보기는 그대로 두고, (1) 세 서버와 체인이 살아 있는지를
어느 페이지에서나 한눈에 보는 **상태 패널**, (2) 켜면 단계 순서대로만 진행되도록 버튼을 잠그고 말풍선으로 다음 클릭을 가리키는
**체험 모드**를 더한다.

## 0. 결정 사항 (설계 대화 요약)

| 질문 | 결정 |
|---|---|
| 체험 모드 강도 | **잠금 + 안내 오버레이**. 체험 모드를 켰을 때만 잠기고 기본은 꺼짐(1차의 자유로운 시연 순서 유지). 상단 바에서 언제든 끔 |
| 상태를 어디서 얻나 | **접근 A**: 서버마다 민감정보 없는 `GET /mode3/health` 하나, CORS 는 이미 아는 상대 오리진만. 별도 허브 프로세스(B)·자기 서버만 보기(C)는 기각 |
| 페이지 간 진행 상태 | 공유 저장소 없음. **서버 사실(health)** + 페이지 메모리(1차 `progress`)로만 판정 |
| 잠금 범위 | 앞 3단계(승인→등록→로그인)만. 4~7단계는 1차대로 순서 강제 없음. 관리자 페이지는 잠그지 않음 |
| 테스트 계약 | `tests/test_mode3_browser.mjs`·`tests/test_mode3_demo_stack.mjs` 무수정 통과(체험 모드 기본 꺼짐, 기존 id·요청 불변) |

## 1. 상태 엔드포인트와 CORS

### 1.1 `GET /mode3/health` — 세 서버 공통

인증 없음, `Cache-Control: no-store`, **민감정보 없음**(uid·PPID·시크릿·개인키·pk 값·세션 식별자 없음). 응답:

```json
{ "role": "aa" | "rp" | "wallet", "ok": true, "now": "<ISO>", "chain": { "id": "31337", "head": "812" } | null, ...역할별 }
```

역할별 추가 필드(값은 전부 문자열·불리언·정수):

| 역할 | 필드 |
|---|---|
| **aa** (`cia.js`) | `root`(앞 12자리 + `…`), `epoch`, `lastPublishedBlock`, `rootAge`(= head − lastPublishedBlock, 체인 없으면 `null`), `heartbeatBlocks`, `pendingLeaves`, `pendingRps`, `pendingOpenings`, `accounts`(수), `walletOrigin`(§1.2 의 env 값), `rpOrigins`(승인된 서비스 origin 배열) |
| **rp** (`mode3_rp.js`) | `status`(`pending`|`approved`), `active`(검증기 준비 여부 = `verifier != null`), `inactiveReason`(없으면 `null`), `maxRootAge`(EFFECTIVE 값), `rootAge`(서비스가 마지막으로 본 값, 모르면 `null`), `sessions`(수), `predicates: { countries: n, minAge }`, `walletAgentOrigin`, `ciaUrl` |
| **wallet** (`mode3_wallet_agent.js`) | `secrets`(`file`|`snap`), `registered`, `hasCred`(활성 사용자 자격증명 있음), `sessions`(수), `ciaReachable`(최근 5초 안에 CIA `/cia/public_keys` 가 200 이었나 — health 호출 때 짧은 타임아웃으로 확인), `rpOrigin`, `ciaUrl` |

조립은 `lib/mode3_health.js` 의 순수 함수로 한다(`buildAaHealth(view)`, `buildRpHealth(view)`, `buildWalletHealth(view)` — 서버가 읽은 값을 넣으면 응답 객체를 돌려준다). `rootAge` 계산과 "민감 필드 없음"은 단위 테스트가 이 함수들로 검사한다.

### 1.2 CORS 허용 오리진

각 서버가 **이미 아는 상대 오리진**만 허용한다. 허용 밖 오리진에는 CORS 헤더를 붙이지 않는다(브라우저가 막고, 같은 오리진 호출은 늘 된다). 단순 GET 이라 preflight 가 없으므로 `cors` 패키지 없이 라우트 안에서 `Origin` 헤더가 허용 목록에 있을 때만 `Access-Control-Allow-Origin: <origin>` + `Vary: Origin` 을 직접 붙인다(`cia.js`·`mode3_rp.js` 는 `cors` 를 import 하지 않는다; 지갑도 같은 방식으로 통일). 허용 목록 판정은 `lib/mode3_health.js` 의 `allowOrigin(origin, list)` 로 두어 단위 테스트한다.

| 서버 | 허용 |
|---|---|
| 서비스 | `WALLET_ORIGIN`(`MODE3_WALLET_AGENT_ORIGIN`), `CIA_URL`(`MODE3_CIA_URL`) |
| 지갑 | `RP_ORIGIN`(`MODE3_RP_ORIGIN`), `CIA_URL` |
| AA | 승인된 서비스들의 `origin`(`state.rps`, 승인 시점에 갱신되므로 콜백이 매번 읽는다) + **새 env `MODE3_WALLET_AGENT_ORIGIN`**(기본 `http://127.0.0.1:5100`) |

`tests/helpers/isolated_mode3_stack.mjs` 는 CIA 를 띄울 때 `MODE3_WALLET_AGENT_ORIGIN` 을 지갑 오리진으로 넘긴다(헬퍼 한 줄 추가). 그 외 세 오리진은 이미 서로 전달되고 있다.

### 1.3 실패 표현

서버가 죽었으면 fetch 가 실패한다 → 패널 "응답 없음". 체인이 죽었으면 `chain: null`. 각 health 요청은 **2초 타임아웃**(`AbortController`)이라 한쪽이 느려도 다른 쪽 표시를 막지 않는다.

## 2. 상태 패널

### 2.1 표시

- 상단 안내 바 오른쪽(언어·전문가 토글 옆)에 **상태 점 4개**: 신원 기관 · 서비스 · 지갑 · 체인. 색: 초록(정상), 노랑(주의), 빨강(응답 없음·막힘), 회색(모름/아직 안 읽음). 점에는 텍스트 라벨이 붙는다(색만으로 구분하지 않음, 1차 §4.5).
- 점을 누르면 바 아래로 패널이 펼쳐지고 밖을 누르면 닫힌다. 패널은 역할별 한 줄 요약 + 주의·빨강일 때 원인·조치(1차 `reasons` 재사용: `root_too_old`, `factory_constants_unavailable`, `registration_pending`, `cia_unavailable`) + 전문가 보기에서 원본 JSON.
- 네 페이지가 같은 모양이다. `Demo.stack()` 이 그리고 `Demo.guide()` 는 1차 그대로.

### 2.2 판정 규칙 (점 색과 패널 문구가 같은 규칙)

| 대상 | 빨강 | 노랑 | 초록 | 회색 |
|---|---|---|---|---|
| 응답 없음 | fetch 실패·타임아웃 — "응답 없음: 프로세스가 떠 있는지 확인" | | | 아직 안 읽음 |
| 체인 | 세 서버 모두 `chain: null` — "체인 없음(hardhat)" | | 하나라도 `chain` 을 주면, head 표시 | |
| AA | `rootAge ≥ maxRootAge`(서비스가 준 값; 서비스가 없으면 AA 의 `heartbeatBlocks·2` 를 임시 상한으로) — "게시가 멈춤 → 전원 root_too_old" | `rootAge ≥ maxRootAge/2`, 또는 `heartbeatBlocks ≥ maxRootAge`, 또는 `pendingLeaves > 0`("게시 대기 n") | 그 외 | |
| 서비스 | `active = false` — "검증기 준비 안 됨" (`inactiveReason` 의 사전 문구) | `status = pending` — "승인 대기" | approved & active | |
| 지갑 | | `ciaReachable = false` — "신원 기관에 못 닿음" | 등록됨 | 미등록 — "미등록" |

### 2.3 폴링과 주소

- 5초 간격. 탭이 숨겨지면 멈추고(`visibilitychange`) 다시 보이면 즉시 한 번 읽는다. 실패는 콘솔에 남기지 않고 점 색으로만 표현한다.
- 상대 서버 주소: 서비스 페이지는 `rp_info` 의 `walletAgentOrigin`·`ciaUrl`; 지갑 페이지는 `/wallet/status` 의 `ciaUrl` 과 지갑 health 의 `rpOrigin`; AA 페이지(관리자·계정)는 AA health 의 `walletOrigin` 과 `rpOrigins[0]`(여럿이면 첫 승인 서비스 — 패널에 "서비스 n개 중 첫 번째" 표기). 1차 안내 바의 링크(`go_rp` 등)도 이 값으로 채운다.
- 호출: `Demo.stack({ self: 'rp'|'wallet'|'aa', urls: { aa, rp, wallet } })` 를 각 페이지의 `init` 에서 한 번. 주소를 나중에 알게 되면(`rp_info` 로드 뒤) 다시 불러 갱신한다. `Demo.stack.last` 에 마지막 응답 묶음이 남아 체험 모드가 읽는다.

## 3. 체험 모드

### 3.1 켜기·끄기·전파

- 상단 바 스위치 "체험 모드". `localStorage` `mode3.tour`(`'1'`|없음), 기본 꺼짐.
- 오리진마다 저장소가 다르므로 켜져 있으면 안내 바의 다른 당사자 링크에 `?tour=1` 을 붙인다. 페이지는 로드 시 `?tour=1` 을 보면 자기 저장소에 켜고, 주소창에서 쿼리를 지운다(`history.replaceState`). `?tour=0` 은 끈다.
- 끄면 즉시 잠금·오버레이가 사라지고 버튼은 원래 활성 규칙으로 돌아간다.
- 승인 팝업(`?authorize=1`)에는 체험 모드를 표시하지 않는다(1차 M4 와 같은 이유).

### 3.2 단계 판정 (서버 사실 + 페이지 메모리)

| 단계 | 판정 근거 |
|---|---|
| 1 승인 | `rp.status === 'approved'` (health) |
| 2 등록 | `wallet.registered` (health) |
| 3 로그인 | `wallet.sessions > 0` 또는 `rp.sessions > 0` (health) |
| 4 이용 | 페이지 메모리 `progress.used`(서비스: 재검증·요청 성공, 지갑: 트랜잭션 성공) |
| 5 공개·조건 | 페이지 메모리 `progress.disclosed` |
| 6 폐기·복구 | `aa.pendingLeaves > 0` 또는 이번 세션 중 `aa.epoch` 증가 관측 |
| 7 개봉 | 서비스: 개봉 결과 수신(메모리); 관리자: `aa.pendingOpenings` 가 1 이상에서 0 으로 관측 |

health 가 아직 없거나 응답 없음이면 **잠그지 않는다**(막히는 것보다 열려 있는 편이 안전). 1차 `renderGuide()` 의 `done/current` 계산은 이 판정과 합쳐 `Demo.tour.evaluate()` 한 곳에서 한다 — 페이지는 `progress` 만 넘긴다.

### 3.3 잠금 규칙 (체험 모드일 때만)

| 페이지 | 잠기는 조작 | 풀리는 조건 | 잠금 사유(사전 키) |
|---|---|---|---|
| 서비스 | 로그인 `#loginBtn` | `wallet.registered` | `tour_lock_login`: "먼저 지갑에서 등록하세요" |
| 서비스 | 재검증·세션 요청 | 세션 있음(기존 규칙 그대로) | (기존) |
| 지갑 | 등록 `#registerBtn` | `rp.status === 'approved'` | `tour_lock_register`: "먼저 관리자가 서비스를 승인해야 합니다" |
| 지갑 | 트랜잭션 `#txBtn` | 세션 있음(기존 규칙 그대로) | (기존) |
| 관리자·계정 | 없음 | — | 운영자는 잠그지 않음 |

- 등록: 페이지가 `Demo.tour.lock('loginBtn', 'wallet_registered')` 처럼 **버튼 id 와 조건 키**를 넘긴다. 조건 키는 `Demo.tour` 가 §3.2 표로 해석한다.
- 잠긴 버튼은 `disabled` + 옆에 사유 배지(`.tour-lock`). 버튼 id·이벤트 핸들러는 그대로. 체험 모드가 꺼지면 `disabled` 를 페이지의 원래 규칙에 되돌린다(페이지가 `Demo.tour.lock` 에 `else` 규칙 함수를 함께 넘긴다: `{ id, cond, otherwise: () => boolean }`).

### 3.4 오버레이(말풍선)

- 현재 단계의 대상 요소 옆에 말풍선 하나: 제목·한 줄 설명·"다음 단계로" 링크(대상이 다른 당사자면 그 페이지 링크, `?tour=1` 포함). 대상 요소 id 는 사전 `steps[k].target[page]`(예: login → rp:`loginBtn`, register → wallet:`registerBtn`, approve → admin:`rpsBtn`)로 둔다. 이 페이지에 대상이 없으면 안내 바 아래에 "지금은 [당사자] 창에서 진행 중" 카드.
- 위치는 `getBoundingClientRect` 로 잡고 스크롤·리사이즈·안내 바 재렌더에 다시 계산한다. 다른 요소를 가리거나 클릭을 막지 않는다(말풍선 자체만 `pointer-events: auto`).
- 7단계가 모두 done 이면 말풍선 대신 "체험 완료" 카드와 "처음부터 다시: 관리자에서 계정 복구 → 서비스에서 재로그인" 안내.
- 좁은 창(≤ 900px)에서는 말풍선을 대상 요소 아래 전폭으로 둔다.

### 3.5 문구

전부 사전: `ui.tour_on/off`, `ui.tour_lock_*`, `ui.tour_elsewhere`, `ui.tour_done_*`, 단계별 `steps[k].tour: { ko: {title, body}, en: {...} }`, 상태 패널 `ui.stack_*`. 사전 단위 테스트가 7단계 × (title·body) 와 잠금 사유 2개, 상태 패널 키의 ko·en 존재를 검사한다.

## 4. 테스트

| 그룹 | 파일 | 내용 |
|---|---|---|
| unit | `tests/test_mode3_demo_strings.js`(확장) | `steps[k].tour`·`target`, `tour_*`, `stack_*` 키 ko·en |
| unit | `tests/test_mode3_health_shape.js`(신규) | `lib/mode3_health.js` 세 조립 함수: 역할별 필드 존재, 민감 필드 부재(`uid PPID secret sk_u pk_u pk_CIA arid r_s` 키가 어느 깊이에도 없음), `rootAge` 계산·체인 없음 `null`, `root` 축약 |
| chain | `tests/test_mode3_health.mjs`(신규, `run_tests.sh` CHAIN) | 격리 스택에서 세 `/mode3/health` 실제 응답 형태; `Origin` 헤더를 허용 오리진으로 보내면 `Access-Control-Allow-Origin` 이 있고 다른 오리진이면 없음; AA 는 서비스 승인 전후로 허용 목록이 바뀜; `Cache-Control: no-store` |
| chain | `tests/test_mode3_demo_stack.mjs`(무수정) | 통과 |
| browser | `tests/test_mode3_browser.mjs`(무수정) | 통과(체험 모드 기본 꺼짐) |
| browser | `tests/test_mode3_tour.mjs`(신규, `run_tests.sh` BROWSER) | file 모드: 서비스를 `?tour=1` 로 열면 `#loginBtn` 이 disabled 이고 `.tour-lock` 배지가 있다 → 지갑에서 등록 → 서비스가 다음 폴링 뒤 잠금을 풀고 말풍선이 `#loginBtn` 을 가리킨다 → 로그인 성공 → 말풍선이 4단계로 이동; 상태 점 셋이 초록; 격리 CIA 프로세스를 죽이면 AA 점이 빨강("응답 없음")·지갑 점이 노랑 |
| 수동 | `scripts/screenshot_mode3.mjs`(확장) | `--tour` 로 체험 모드 화면(서비스 잠김·지갑 말풍선·상태 패널 펼침) 3~4장 추가, `results/mode3_ux_20260925/` |

## 5. 파일

| 파일 | 변경 |
|---|---|
| `lib/mode3_health.js` | 신규 — 역할별 health 객체 조립(순수), `rootAge`, `shortRoot` |
| `cia.js`, `mode3_rp.js`, `mode3_wallet_agent.js` | `GET /mode3/health` + 허용 오리진 CORS 블록; AA 에 `MODE3_WALLET_AGENT_ORIGIN` env; 지갑의 `ciaReachable` 확인 |
| `tests/helpers/isolated_mode3_stack.mjs` | CIA 에 `MODE3_WALLET_AGENT_ORIGIN` 전달 |
| `mode3/common/demo.js` | `Demo.stack()`(폴링·점·패널), `Demo.tour`(스위치·evaluate·lock·오버레이) |
| `mode3/common/demo.css` | 상태 점·패널·말풍선·`.tour-lock` |
| `mode3/common/strings.js` | `stack_*`, `tour_*`, `steps[k].tour/target` |
| 네 페이지 | `Demo.stack(...)` 호출, `Demo.tour.lock(...)` 등록, `?tour=` 처리, `renderGuide` 를 `Demo.tour.evaluate` 로 위임 |
| `docs/MODE3_DEMO.md` | 상태 패널·체험 모드·env 설명, 각본에 "체험 모드로 한 번에" 절 |
| `scripts/screenshot_mode3.mjs`, `results/mode3_ux_20260925/` | `--tour` |

## 6. 이 문서가 다루지 않는 것

Snap 팝업 창의 오버레이, 관리자 페이지 잠금, 모바일 실기기, Mode 2 페이지, 서버 API 의 기존 라우트 변경, 새 의존성·빌드, 상태 이력(그래프), 알림(소리·데스크톱).
