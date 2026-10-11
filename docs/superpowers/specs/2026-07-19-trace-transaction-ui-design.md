# Mode 2 후속 작업: RP 페이지에 트랜잭션 추적(B2) UI 추가

## 상태

사용자 승인 완료(2026-07-19), `trace` 브랜치에서 진행. 아직 구현 안 됨.

## 배경

B2(트랜잭션 추적)는 `server.js`의 `POST /api/mode2/trace_transaction`(`{pk_i, max_height}` → `custom_idp.js`의 `/idp/lookup_uid_by_r_token`에 위임해서 `{uid}` 반환)로 백엔드는 이미 구현/테스트돼 있지만, 이걸 브라우저에서 시연할 UI가 전혀 없다(`index.html`/`client.js`에 관련 요소 없음, `grep` 확인 완료). 2026-07-17 미팅 항목 4(데모 준비)의 일부로, "추적하는 동작도 데모로 보여야 한다"는 요구에 따라 UI를 추가한다.

## 범위

**포함:**
- `index.html`: `#mode2SSOSection` 안, 기존 "Send PPID Transaction" 버튼 블록(`#submitPPIDTransaction`/`#ppidTxResult`) 바로 아래에 새 블록 추가 — `pk_i`/`max_height` 입력 필드 2개, "Trace Transaction" 버튼, 결과 표시 영역. **주의**: RP-UI 플랜 때 겪었던 버그(버튼을 `display:none`인 `#ssoStepButtons` 디버그 패널 안에 둬서 실제로는 안 보였던 문제)를 반복하지 않도록, 반드시 `#rpFeVisibleFlow`/트랜잭션 버튼과 같은 레벨(형제 요소)에 둔다 — `#ssoStepButtons` 안에 넣지 않는다.
- `client.js`: 새 버튼 클릭 리스너 추가. `POST /api/mode2/trace_transaction`을 `{pk_i, max_height}`로 호출하고 결과(`uid`) 또는 에러를 표시. 입력 필드는 Step 8에서 이미 확보된 `ssoMetadata.signingPublicKey`(pk_i)와 `ssoMetadata.maxHeight`로 기본값을 채워서(수정 가능) 편집증적인 수동 조회 없이도 "방금 보낸 트랜잭션을 그대로 추적"하는 데모 흐름이 되게 한다.

**명시적으로 범위 밖:**
- `server.js`/`custom_idp.js`의 추적 로직 자체 — 이미 구현/테스트됨, 변경 없음.
- 별도 "RP 조사관" 페이지나 인증/승인 절차 — 사용자가 명시적으로 "그냥 RP 페이지에 버튼으로" 요청, 이번 스코프 아님.
- B2 설계 문서(`docs/superpowers/specs/2026-07-16-*`, `docs/superpowers/plans/2026-07-16-*` 등 B2 관련)에 이미 명시된 "권한/승인 게이트 없음" 결정 — 그대로 유지, 이번 작업에서 추가하지 않음.

## 핵심 설계 결정

**왜 새 페이지/섹션이 아니라 기존 RP 페이지에 버튼만 추가하는가?**
사용자가 명시적으로 단순화를 요청함("그냥 rp 페이지에 버튼으로 줘"). 데모 목적상 "로그인 → 트랜잭션 제출 → 추적"을 하나의 연속된 화면 흐름으로 보여주는 게 더 직관적이다.

**왜 `pk_i`/`max_height`를 자동으로 채우는가?**
이 값들은 Step 8에서 이미 지갑이 생성해서 `ssoMetadata`에 들어있는 값과 동일하다(트랜잭션 제출에도 같은 값을 씀). 데모에서 "방금 보낸 그 트랜잭션을 추적해보자"는 흐름을 그대로 보여주려면 자동 채움이 자연스럽다. 수동 조회(다른 세션의 값을 넣어보는 것)도 막지 않기 위해 입력 필드는 수정 가능하게 둔다.

## 아키텍처

```
[PPID 트랜잭션 제출 후, client.js]
  "Trace Transaction" 버튼 표시, pk_i/max_height 입력 필드에
  ssoMetadata.signingPublicKey / ssoMetadata.maxHeight로 기본값 채움

[버튼 클릭]
  client.js: POST /api/mode2/trace_transaction
    body: { pk_i: <입력값>, max_height: <입력값> }

  server.js (기존, 변경 없음):
    1. sessionLog에서 (pk_i, max_height)로 r_token 재계산해 일치하는 세션 탐색
    2. 매칭되면 custom_idp.js의 POST /idp/lookup_uid_by_r_token 호출
    3. { uid } 응답

  client.js: 결과 영역에 uid 표시, 매칭 실패/에러 시 에러 메시지 표시
```

## 테스트 및 검증

- `node --check client.js`로 구문 검사.
- 라이브 검증(서버 재시작 불필요 — 기존 백엔드 그대로 사용): 로그인 → 트랜잭션 제출 → 추적 버튼 클릭 → `uid`가 정확히 표시되는지 확인. 매칭 안 되는 임의의 `pk_i`/`max_height`를 넣었을 때 에러 메시지가 뜨는지도 확인.
