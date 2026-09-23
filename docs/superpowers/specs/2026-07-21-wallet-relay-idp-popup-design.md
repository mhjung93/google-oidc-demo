# Mode 2 후속 작업: 지갑 중계를 통한 IdP 팝업의 RP origin 은닉

## 상태

사용자 승인 완료(2026-07-21), 아직 구현 안 됨.

## 배경

`idp/login_popup.js`는 IdP 자신의 origin에서 실행되는 코드인데, 지금 구조에서는 RP가 이 팝업을 직접 열고
직접 `postMessage`를 주고받기 때문에, 다음 두 지점에서 RP origin을 그대로 알게 된다.

- `idp/login_popup.js:10`: `const tentativeRpOrigin = new URLSearchParams(location.hash.slice(1)).get('rp');`
- `idp/login_popup.js:70`: `rpOrigin = event.origin;`

논문(PairCT)의 "IdP-side RP hiding"(Definition 1 / Property 3)은 IdP 서버가 HTTP 요청만으로 RP를 식별하지
못한다는 뜻이었다. 하지만 IdP가 honest-but-curious라서 "자기가 서빙하는 페이지 스크립트를 관찰할 수 있다"는
모델까지 확장하면, 이 두 줄이 있는 한 IdP는 RP origin을 그냥 알 수 있다. 사용자는 이걸 "IdP 서버가 HTTP
요청만으로는 RP를 식별 못 한다"로 논문 주장을 좁히는 대신, 실제로 RP origin이 IdP 쪽 코드에 안 보이도록
지갑(`wallet_agent.js`)을 중계자로 끼워 넣는 쪽을 선택했다.

## 핵심 설계 결정

**왜 `idp/login_popup.js`를 안 바꿔도 되는가?**
이 코드는 이미 "자신을 연 창(opener)의 origin"만 신뢰하도록 짜여 있다(`#rp=` 잠정값 → 첫 메시지의
`event.origin`으로 확정). IdP 팝업을 RP가 아니라 지갑의 relay가 열도록만 바꾸면, `idp/login_popup.js`는
코드 변경 없이 그대로 지갑 origin(`http://127.0.0.1:5001`)을 opener로 인식한다. RP origin은 IdP 쪽 코드
어디에도 등장하지 않게 된다.

**왜 보이는 팝업이 아니라 숨겨진 iframe인가?**
사용자가 "안 보이는 iframe으로" 선택했다. `wallet_agent.js`가 relay 페이지를 정적으로 서빙하고, RP 페이지가
그걸 숨겨진 `<iframe>`으로 임베드한다. 그 iframe 안의 JS(=지갑 origin에서 실행)가 IdP 팝업을
`window.open()`으로 직접 연다 — 그래서 그 팝업의 `window.opener`가 지갑 origin이 된다. 팝업 창 개수가 늘지
않아 UX가 오늘과 동일하다.

**왜 iframe 임베드를 `wallet_agent.js`의 기존 `RP_ORIGIN` 설정으로 제한하는가?**
`wallet_agent.js`는 이미 단일 신뢰 RP origin 개념을 갖고 있다(`wallet_agent.js:18`,
`app.use(cors({ origin: RP_ORIGIN }))`). relay 페이지도 이 기존 경계를 그대로 따른다: 응답에
`Content-Security-Policy: frame-ancestors ${RP_ORIGIN}` 헤더를 붙여서 다른 origin이 이 relay를 임베드하는
것 자체를 브라우저가 막게 하고, relay JS 안에서도 부모로부터 온 첫 메시지의 `event.origin`이 `RP_ORIGIN`과
일치하는지 재확인한다(오늘 `idp/login_popup.js`가 하는 것과 동일한 이중 확인 패턴).

**왜 팝업 닫힘 감지를 유지하는가?**
사용자가 "유지"를 선택했다. RP 페이지가 이제 IdP 팝업을 직접 들고 있지 않으므로(relay iframe만 들고 있음),
relay가 자신이 연 IdP 팝업의 `.closed` 상태를 주기적으로 확인하다가 닫히면 새 메시지 타입(예:
`IDP_POPUP_CLOSED`)으로 부모(RP)에게 알린다. 오늘의 재시도 버튼 UX를 그대로 유지하기 위함이다.

## 범위

**포함:**
- 새 디렉터리 `wallet/`에 `relay.html`/`relay.js` 추가 — `idp/login_popup.html`/`.js`와 같은 역할의 정적
  파일 쌍. `#rp=` 잠정값 → `event.origin` 확정 → IdP 팝업 오픈 → 양방향 메시지 중계(`RP_SEND_ZKP`,
  `IDP_READY_FOR_ZKP`, `IDP_SSO_SUCCESS`) → 팝업 닫힘 감지 후 `IDP_POPUP_CLOSED` 전달.
- `wallet_agent.js`: `idp/`를 서빙하는 `custom_idp.js`의 기존 패턴(`express.static` + `sendFile` 라우트)을
  그대로 따라 `wallet/`을 정적으로 서빙. relay 라우트 응답에 `frame-ancestors ${RP_ORIGIN}` CSP 헤더 추가.
- `client.js`: `window.open(IDP_ORIGIN + '/login_popup#rp=...')` 직접 호출을 제거하고, 숨겨진 iframe
  생성으로 교체. `idpPopupWindow.postMessage(...)` → `relayIframe.contentWindow.postMessage(...)`.
  `event.origin === IDP_ORIGIN` 체크 → `event.origin === WALLET_AGENT_ORIGIN`. `IDP_POPUP_CLOSED` 메시지를
  받으면 오늘의 `idpPopupWindow.closed` 감지와 동일하게 재시도 버튼을 보여줌.

**명시적으로 범위 밖:**
- `idp/login_popup.js`, `idp/login_popup.html`, `custom_idp.js` — 변경 없음.
- `contracts/*`, `circuits/*`, `wallet_agent.js`의 Step 8/트랜잭션 로직 자체 — 변경 없음(이번 작업은 순수
  postMessage 중계 배선 문제).
- 정확한 메시지 이름/시퀀스의 세부 코드는 이 스펙이 아니라 다음 단계인 구현 계획(writing-plans)에서 확정한다
  — 이 스펙은 아키텍처와 신뢰 경계(누가 무엇을 누구에게 보여줄 수 있는지)만 고정한다.
- 논문(PairCT) 문서의 Definition 1 / Property 3 관련 문구 조정 — 이 구현이 끝나고 실제로 IdP 쪽 코드가 RP
  origin을 못 보게 된 뒤, 별도 작업으로 처리한다.

## 테스트 및 검증

- `node --check wallet_agent.js`, `node --check client.js` 구문 검사.
- 라이브 검증(컨트롤러가 직접 실행, 사용자 확인하며 진행):
  1. 로그인 흐름을 처음부터 끝까지 진행해서, 오늘과 동일하게 IdP 팝업에 로그인 폼이 뜨고 동의 후 로그인이
     완료되는지 확인.
  2. 브라우저 개발자 도구에서 IdP 팝업 창의 콘솔/네트워크를 확인해서, `idp/login_popup.js`가 아는 opener
     origin이 RP origin(`http://127.0.0.1:3000`)이 아니라 지갑 origin(`http://127.0.0.1:5001`)인지 확인.
  3. IdP 팝업을 로그인 중간에 직접 닫아서, 오늘과 동일하게 재시도 버튼이 뜨는지 확인.
  4. RP 외의 origin에서 relay iframe을 직접 열었을 때(예: 다른 포트로 접속해서 `<iframe src="http://127.0.0.1:5001/relay">` 삽입) 브라우저가 CSP로 막는지 확인.

## Self-Review

- **플레이스홀더 검사**: 없음.
- **범위 일관성**: "포함" 목록(relay 정적 파일, wallet_agent.js 서빙, client.js 배선)이 "핵심 설계 결정"
  네 가지와 1:1로 대응됨.
- **모순 검사**: `idp/login_popup.js`를 "변경 없음"이라고 배경·범위 양쪽에서 일관되게 명시함.
