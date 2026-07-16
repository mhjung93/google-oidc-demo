# Mode 2 후속 작업: Snap Home Page 트랜잭션 제출 UI

## 상태

**폐기됨(2026-07-16, 같은 날 대화 안에서).** 설계 검증 중 "Snap은 `eth_sendTransaction`을
직접 호출할 수 없다(`endowment:ethereum-provider`는 read 전용)"는 기술적 제약이
확인되어, Snap Home Page 경로 자체가 성립하지 않는다는 게 드러났다. 이후 논의를 거쳐
"RP FE가 트랜잭션 생성을 트리거하는 게 오히려 자연스럽다"(OpenSea 비교 참고 —
`to`/`value`/`data`는 애초에 RP 자신의 서비스 내용이라 RP가 아는 게 문제되지 않고, 이
프로토콜이 숨기는 건 `uid`이지 "트랜잭션이 일어났다"는 사실 자체가 아니다)는 결론에
도달해 이 문서는 폐기하고, 훨씬 단순한
`docs/superpowers/specs/2026-07-16-rp-transaction-submission-ui-design.md`로
대체되었다. 이 문서는 "Snap이 왜 안 되는지"에 대한 실제 검증 기록으로서만 남겨둔다.

~~사용자 승인 완료(2026-07-16), `trace` 브랜치에서 진행. 아직 구현 안 됨.~~

## 배경

B1(`docs/superpowers/specs/2026-07-15-ppid-transaction-submission-design.md`)이 `wallet_agent.js`의 `/submitTransaction` 엔드포인트를 만들었지만, 이걸 실제로 호출해서 온체인에 보내는 UI는 아직 없다 — B1/B2 검증 때는 개발자가 curl/스크립트로 직접 호출했다.

이 스펙은 그 UI를 추가한다. 처음에는 "Step 15 완료 후 RP 페이지(`client.js`)에 버튼 하나"로 논의를 시작했지만, 사용자가 "RP FE랑 트랜잭션 제출은 전혀 관련 없는거잖아"라고 지적하면서 방향이 바뀌었다 — RP 페이지는 이 트랜잭션 제출 과정에 어떤 식으로도 관여하면 안 된다. 그래서 트리거 자체를 MetaMask Snap의 자체 화면(Home Page)으로 옮기기로 했다.

## 범위

**포함:**
- `wallet_agent.js`: Step 12(`/verifyIdPAuthToken`) 성공 시 `business`/`rpNonce`/`idpToken`을 `wallet_state.json`에 영속화(기존 `sk_i` 영속화와 같은 패턴). "대기 중인 세션이 있는가" 조회용 엔드포인트 추가. `/submitTransaction`이 이 값들을 요청 본문 대신 저장된 상태에서 읽도록 계약 변경(B1의 기존 코드 수정)
- Snap(`snap/`): `@metamask/snaps-sdk`/`@metamask/snaps-cli`를 JSX 지원 버전으로 업그레이드. `onHomePage` + `onUserInput` 핸들러 추가. 버튼 클릭 시 `/submitTransaction` 호출 → `eth_sendTransaction`으로 실제 전송 → 결과를 같은 화면에 표시

**명시적으로 범위 밖:**
- `client.js`(RP 페이지) 변경 — 이 기능은 RP 페이지와 완전히 무관해야 한다는 게 설계의 핵심 전제
- B2 추적 기능(`/api/mode2/trace_transaction`) 호출 UI — 이번 스펙은 "보내기"만, "추적"은 별도
- 기존 Snap 다이얼로그(Step 7/Step 12 표시 등, `onRpcRequest`)의 재작성 — 그대로 유지
- `circuits/pi_pk_i.circom`, `contracts/PPIDWallet.sol`, `contracts/PPIDWalletFactory.sol` 수정

## 핵심 설계 결정과 기각된 대안들

**왜 RP 페이지에 트리거 버튼을 두는 방식을 기각했는가?**
처음 제안한 "RP 페이지에 작은 버튼 → `wallet_invokeSnap` 호출 → Snap 다이얼로그가 뜸" 방식은 실제로 동작은 하지만(MetaMask 확장 프로그램은 `wallet_invokeSnap` 호출 시 자동으로 팝업을 띄운다), RP 페이지가 트리거 역할이라도 하게 된다. 사용자는 "트랜잭션 제출은 RP FE랑 전혀 관련 없다"는 원칙을 분명히 했다 — Mode 2 전체 설계가 RP가 사용자 지갑의 동작에 대해 필요 이상으로 알거나 관여하지 못하게 하는 게 목적이므로, 이 원칙에 맞춰 RP 페이지 관여를 완전히 제거하기로 했다.

**왜 정적 Home Page(정보만 표시) + RP 페이지 버튼 절충안을 기각했는가?**
사용자가 "전체 범위(JSX 의존성 추가 포함)로 진행"을 명시적으로 선택했다. 절충안은 새 의존성이 필요 없다는 장점이 있었지만, 결국 RP 페이지가 트리거 역할을 한다는 점에서 위 원칙을 못 지킨다.

**왜 Home Page의 클릭 가능한 버튼에 JSX(`@metamask/snaps-sdk/jsx`)가 필요한가?**
현재 Snap 코드는 `panel()`/`text()`/`heading()` 같은 구버전 빌더 함수만 쓰는데(`snap/src/index.js`), 이 API는 정적 콘텐츠 표시만 가능하고 클릭 이벤트에 반응하는 인터랙티브 컴포넌트(`Button`)를 지원하지 않는다. MetaMask 공식 문서(context7로 확인) 기준, 인터랙티브 UI(`snap_createInterface` + `Button` + `onUserInput`)는 JSX 컴포넌트 체계에서만 제공되고, 여기엔 `@metamask/snaps-sdk` `^6.1.1`+, `@metamask/snaps-cli` `^6.2.1`+(현재 `^4.0.1`)가 필요하다. 이건 앱 코드 몇 줄이 아니라 Snap의 의존성/빌드 체계 자체를 바꾸는 작업이며, 기존에 잘 동작하는 Snap 기능(Step 7/Step 12 다이얼로그)이 업그레이드 이후 깨지지 않는지 재검증이 필요하다.

**왜 `wallet_agent.js`가 `business`/`rpNonce`/`idpToken`까지 영속화해야 하는가?**
Home Page는 MetaMask 확장 프로그램에서 사용자가 이 Snap을 직접 열 때 뜨는 화면이라, RP 페이지의 JS 컨텍스트(그 안에 있는 `business`/`idpToken` 등 세션 데이터)에 전혀 접근할 수 없다. `wallet_agent.js`가 로그인 완료 시점의 이 값들을 스스로 들고 있어야, Home Page의 버튼 클릭만으로 `/submitTransaction`을 호출할 수 있다. 이미 `sk_i`를 이 패턴(로그인 이후에도 살아있는 상태, `wallet_state.json`)으로 영속화하기로 한 결정(B1)의 자연스러운 연장이다.

**왜 "대기 중인 세션 하나"만 다루는가(여러 세션 큐잉 안 함)?**
`sk_i`와 동일하게, `wallet_agent.js`는 한 번에 하나의 "현재" 로그인 세션만 추적한다(다음 로그인이 오면 덮어씀). 이건 지갑 프로세스 하나당 활성 세션 하나라는 기존 모델과 일치하고, 큐/여러 대기 트랜잭션을 관리하는 건 이 스펙 범위를 넘는 복잡도다.

## 아키텍처

```
[로그인 완료 시점, wallet_agent.js의 Step 12(/verifyIdPAuthToken) 성공 직후]
  wallet_agent.js: sk_i처럼 business/rpNonce/idpToken도 wallet_state.json에 영속화
  (B1의 /submitTransaction 계약 변경: 더 이상 요청 본문으로 이 값들을 안 받고,
   자체 저장된 값을 읽음)

[사용자가 MetaMask 확장 프로그램에서 이 Snap을 직접 열 때, RP 페이지와 무관]
  Snap의 onHomePage: wallet_agent.js에 "제출 대기 중인 세션이 있나?" 조회
    -> 있으면 인터랙티브 인터페이스(Box + Button)를 snap_createInterface로 만들어 표시
    -> 없으면 "대기 중인 트랜잭션 없음" 정적 표시

[사용자가 Home Page 안의 버튼 클릭]
  Snap의 onUserInput(ButtonClickEvent):
    1. wallet_agent.js의 /submitTransaction 호출(더 이상 body 없이, 저장된 세션으로)
       -> 증명+서명 생성 + PPIDWallet 주소 조회 + execute() calldata ABI 인코딩까지
          wallet_agent.js가 전부 끝내고 { to, data } 형태로 응답 (Snap은 ABI를 모름)
    2. ethereum.request({method:'eth_sendTransaction', params:[{to, data}]})로 그대로 전송
       -> MetaMask 표준 트랜잭션 서명 팝업이 별도로 뜸(항상 나오는 표준 동작)
    3. snap_updateInterface로 같은 화면에 결과(tx hash) 표시
```

## 컴포넌트

### `wallet_agent.js` (수정)
- `/verifyIdPAuthToken`(Step 12) 성공 시, `getOrCreateSessionKey()`와 같은 패턴으로 `business`/`rpNonce`/`idpToken`을 `wallet_state.json`에 새 필드(예: `mode2PendingSubmission`)로 저장. 다음 로그인이 성공하면 이 필드를 덮어쓴다(단일 "현재 세션" 모델).
- **신규 설정**: `PPID_WALLET_FACTORY_ADDRESS` 환경변수(배포된 `PPIDWalletFactory`의 주소) — 지금은 이 정보를 아는 컴포넌트가 전혀 없다(B1 검증 때는 임시 스크립트가 수동으로 배포/전달했다). `MODE2_ETH_RPC_URL`과 같은 위치(환경변수)에서 읽는다.
- `/submitTransaction`: 기존에 요청 본문으로 받던 `business`/`rpNonce`/`idpToken`을 이제 `mode2PendingSubmission`에서 읽도록 변경. (`to`/`value`/`data`/`currentNonce`는 여전히 호출자가 지정 — Snap이 이 값을 채워서 보낸다.) 응답 형태를 바꿔서, Snap이 `PPIDWallet.execute(...)`의 ABI를 몰라도 되게 한다: `payload`/`sig`/`proofA/B/C`/`pk_i`/`pk_IdP_x`/`pk_IdP_y`/`max_height`를 그대로 노출하는 대신(또는 그에 더해), **`wallet_agent.js`가 자체적으로 `PPID_WALLET_FACTORY_ADDRESS`의 `computeAddress(ppid)`를 RPC 조회하고 `execute(...)` calldata까지 ABI 인코딩해서, `{ to: walletAddress, data: encodedCalldata }` 형태로 응답에 포함**시킨다(이미 `wallet_agent.js`에 있는 `ethers` 의존성 재사용). Snap은 이 `{to, data}`를 그대로 `eth_sendTransaction`에 넘기기만 하면 된다 — ABI 인코딩 로직을 Snap 샌드박스 안에 새로 들여올 필요가 없다(SES 제약 하에서 위험을 하나 더 줄이는 선택).
- 신규 `GET /pendingSubmission`: 저장된 `mode2PendingSubmission`이 있으면 그 요약(예: `walletAddress`, `auid_i` 등 사람이 읽을 수 있는 최소 정보)을 반환, 없으면 `{ pending: false }`.

### `snap/package.json`, `snap/tsconfig.json`(또는 해당 설정), `snap/snap.manifest.json` (수정)
- `@metamask/snaps-sdk` `^6.1.1`+, `@metamask/snaps-cli` `^6.2.1`+로 업그레이드, `@types/react`/`@types/react-dom` `18.2.4`(캐럿 없이) 추가
- TS/빌드 설정에 JSX 컴파일 옵션(`"jsx": "react-jsx"`, `"jsxImportSource": "@metamask/snaps-sdk"`) 추가, `include`에 `**/*.tsx` 추가
- manifest에 `endowment:page-home` 권한 추가

### `snap/src/index.js` (수정)
- 신규 `onHomePage` export: `wallet_agent.js`의 `GET /pendingSubmission`을 호출해서, 대기 중인 세션이 있으면 `snap_createInterface`로 `Box`+`Button`(예: `name="submit-tx"`)을 만들어 인터페이스 ID를 반환, 없으면 정적 `panel`/`text`로 "대기 중인 트랜잭션 없음" 표시.
- 신규 `onUserInput` export: `ButtonClickEvent`이고 `name === 'submit-tx'`이면, `wallet_agent.js`의 `POST /submitTransaction`을 호출(본문 없음 또는 `to`/`value`/`data` 최소 정보만) → 응답으로 받은 **`{ to, data }`**(이미 ABI 인코딩까지 끝난 상태)를 그대로 `ethereum.request({method:'eth_sendTransaction', params:[{to, data}]})`에 전달 → 성공하면 `snap_updateInterface`로 같은 인터페이스에 결과(tx hash) 갱신. Snap은 `PPIDWallet`의 ABI/`execute()` 시그니처를 전혀 몰라도 된다.
- 기존 `onRpcRequest`(Step 7/Step 12 다이얼로그 등)는 그대로 유지, 손대지 않음.

## 데이터 흐름

아키텍처 섹션에 이미 명시.

## 에러 처리

- `onHomePage`가 `wallet_agent.js`에 연결 실패(프로세스 안 떠 있음 등)하면, Home Page에 "지갑 에이전트에 연결할 수 없음" 정적 메시지 표시(버튼 없이).
- `onUserInput`에서 `/submitTransaction` 호출이 실패하면(`mode2PendingSubmission` 없음, 증명 생성 실패 등), `snap_updateInterface`로 같은 화면에 에러 메시지 표시(버튼은 다시 누를 수 있게 유지하거나, 실패 원인에 따라 "다시 로그인하세요" 안내).
- `eth_sendTransaction`이 사용자에 의해 거부(reject)되면, 인터페이스에 "사용자가 거부함" 표시.

## 테스트 계획

- Snap 업그레이드 후, 기존 기능(Step 7 팝업, Step 12 검증 결과 다이얼로그)이 여전히 정상 동작하는지 회귀 확인
- `wallet_agent.js`가 로그인 완료 후 `mode2PendingSubmission`을 올바르게 저장/덮어쓰는지 확인
- `GET /pendingSubmission`이 세션 유무에 따라 올바른 응답을 주는지 확인
- Home Page에서 버튼 클릭 → 실제 온체인 `execute()` 성공까지 라이브 확인(로컬 Hardhat 노드 + 배포된 `PPIDWallet`/`PPIDWalletFactory` 대상)
- 버튼 클릭 후 `eth_sendTransaction`을 사용자가 거부하는 경우의 에러 표시 확인

## 후속 작업 (이 스펙 범위 밖)

- B2 추적(`trace_transaction`) 호출을 위한 별도 UI(Home Page의 또 다른 섹션이 될 수도 있음)
- 여러 개의 대기 중인 세션을 큐로 관리하는 기능(지금은 "현재 세션 하나"만 지원)
- `client.js`(RP 페이지)에 "제출 완료 여부"를 보여주는 어떤 형태의 표시 — 이번 설계 원칙(RP 페이지는 관여 안 함)에 따라 이것도 신중하게 검토 필요
