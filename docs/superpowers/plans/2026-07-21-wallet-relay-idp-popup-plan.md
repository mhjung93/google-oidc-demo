# Wallet Relay for IdP Popup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** RP 페이지가 IdP 로그인 팝업을 더 이상 직접 열거나 메시지를 주고받지 않고, 지갑(`wallet_agent.js`)이 서빙하는 숨겨진 relay iframe을 거치게 해서 `idp/login_popup.js`(IdP origin에서 실행되는 코드)가 RP origin을 알 수 없게 만든다.

**Architecture:** 새 정적 페이지 쌍(`wallet/relay.html`/`relay.js`)을 `wallet_agent.js`가 서빙한다. RP 페이지(`client.js`)는 이 relay를 숨겨진 `<iframe>`으로 임베드하고, 오늘 IdP 팝업과 직접 주고받던 메시지(`RP_SEND_ZKP`, `IDP_READY_FOR_ZKP`, `IDP_SSO_SUCCESS`)를 relay와 주고받는다. relay는 자신이 직접 IdP 팝업을 열고 그 팝업과 오늘의 client.js와 동일한 프로토콜로 통신하면서 양쪽을 중계한다. `idp/login_popup.js`는 "자신을 연 창의 origin만 신뢰"하는 기존 로직 그대로이므로 전혀 수정하지 않는다.

**Tech Stack:** 순정 브라우저 API(iframe, postMessage, window.open)만 사용, 새 의존성 없음. `wallet_agent.js`는 이미 있는 `express.static`/`path`/`__dirname` 패턴을 재사용한다.

## Global Constraints

- `idp/login_popup.js`, `idp/login_popup.html`, `custom_idp.js` — 변경하지 않는다.
- `contracts/*`, `circuits/*`, `wallet_agent.js`의 Step 8/트랜잭션 로직(`/generateStep8Proofs`, `/submitTransaction` 등) — 변경하지 않는다.
- relay 정적 파일 라우트는 `wallet_agent.js`의 기존 `X-Wallet-Agent-Token` 검사 미들웨어(`wallet_agent.js:353-360`)보다 **앞**에 둬야 한다 — iframe의 `src` 요청은 브라우저가 커스텀 헤더를 못 실어 보내므로, 그 미들웨어를 거치면 항상 401이 난다.
- relay HTML 응답에는 `Content-Security-Policy: frame-ancestors ${RP_ORIGIN}` 헤더를 붙여서, 설정된 RP_ORIGIN 외의 페이지가 이 relay를 iframe으로 못 담게 막는다(`wallet_agent.js`가 이미 갖고 있는 `RP_ORIGIN` 상수를 그대로 재사용).
- 새 메시지 타입은 `IDP_POPUP_CLOSED` 하나만 추가한다. 기존 `RP_SEND_ZKP`/`IDP_READY_FOR_ZKP`/`IDP_SSO_SUCCESS`는 이름과 payload 구조를 그대로 재사용한다(다만 relay가 두 홉으로 중계).

---

### Task 1: `wallet/relay.html`/`relay.js` 작성 + `wallet_agent.js`에서 서빙

**Files:**
- Create: `wallet/relay.html`
- Create: `wallet/relay.js`
- Modify: `wallet_agent.js:351-352`(정적 서빙 라우트 삽입 위치, `app.use(express.json());` 바로 뒤, 토큰 검사 미들웨어 바로 앞)

**Interfaces:**
- Produces: `GET /relay` (relay.html, `frame-ancestors ${RP_ORIGIN}` CSP 헤더 포함), `GET /wallet/relay.js` (정적 서빙).
- Produces (relay.js가 부모 프레임과 주고받는 postMessage 프로토콜, Task 2가 그대로 소비): 부모→relay `{type:'RP_SEND_ZKP', zkp: <currentSSOProof 객체>}`, relay→부모 `{type:'IDP_READY_FOR_ZKP'}` / `{type:'IDP_POPUP_CLOSED'}` / `{type:'IDP_SSO_SUCCESS', idpToken, r_i}`(IdP 팝업이 보낸 payload를 그대로 전달).

- [ ] **Step 1: `wallet/relay.html` 작성**

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Wallet Relay</title>
</head>
<body>
  <script type="module" src="/wallet/relay.js"></script>
</body>
</html>
```

- [ ] **Step 2: `wallet/relay.js` 작성**

```js
// RP 페이지가 숨겨진 iframe으로 이 페이지를 임베드한다. 이 스크립트는 지갑
// origin(wallet_agent.js)에서 실행되면서, RP 페이지와 실제 IdP 로그인 팝업
// 사이에서 메시지를 중계한다 — 그래서 idp/login_popup.js는 자신을 연 창(opener)
// 으로 RP가 아니라 이 relay(지갑 origin)를 보게 되고, RP origin을 알 방법이
// 없어진다. idp/login_popup.js는 변경하지 않는다.

const IDP_ORIGIN = 'http://127.0.0.1:4000';

// RP 페이지(부모)가 이 iframe의 src에 URL 프래그먼트(#rp=...)로 자기 origin을
// 알려준다. 프래그먼트는 서버로 전송되지 않지만 문자열이라 위조될 수 있으므로
// "잠정값"으로만 쓰고, 첫 메시지가 도착하면 그 메시지의 event.origin(브라우저
// 보장, 위조 불가능)과 일치하는지 반드시 확인한 뒤에만 rpOrigin으로 확정한다 —
// idp/login_popup.js가 오늘 하는 것과 동일한 패턴을 한 홉 앞으로 옮긴 것뿐이다.
const tentativeRpOrigin = new URLSearchParams(location.hash.slice(1)).get('rp');
let rpOrigin = null;

let idpPopupWindow = null;
let idpPopupReady = false;
let pendingZKP = null;
let successRelayed = false;
let closedWatchTimer = null;

if (window.parent !== window && tentativeRpOrigin) {
  window.parent.postMessage({ type: 'IDP_READY_FOR_ZKP' }, tentativeRpOrigin);
}

function openOrReuseIdPPopup() {
  if (idpPopupWindow && !idpPopupWindow.closed) return;
  idpPopupReady = false;
  successRelayed = false;
  const popupName = `IdPLogin-${crypto.randomUUID()}`;
  idpPopupWindow = window.open(
    `${IDP_ORIGIN}/login_popup#rp=${encodeURIComponent(window.location.origin)}`,
    popupName,
    'width=500,height=600',
  );
  if (idpPopupWindow) startPopupClosedWatch();
}

function trySendProofToIdP() {
  if (!pendingZKP || !idpPopupWindow || idpPopupWindow.closed || !idpPopupReady) return;
  idpPopupWindow.postMessage({ type: 'RP_SEND_ZKP', zkp: pendingZKP }, IDP_ORIGIN);
}

function startPopupClosedWatch() {
  if (closedWatchTimer) clearInterval(closedWatchTimer);
  closedWatchTimer = setInterval(() => {
    if (!idpPopupWindow || idpPopupWindow.closed) {
      clearInterval(closedWatchTimer);
      closedWatchTimer = null;
      if (!successRelayed && rpOrigin) {
        window.parent.postMessage({ type: 'IDP_POPUP_CLOSED' }, rpOrigin);
      }
    }
  }, 500);
}

window.addEventListener('message', (event) => {
  if (event.source === window.parent) {
    if (rpOrigin === null) {
      if (event.origin !== tentativeRpOrigin) return;
      rpOrigin = event.origin;
    }
    if (event.origin !== rpOrigin) return;
    if (event.data.type === 'RP_SEND_ZKP') {
      pendingZKP = event.data.zkp;
      openOrReuseIdPPopup();
      trySendProofToIdP();
    }
    return;
  }

  if (idpPopupWindow && event.source === idpPopupWindow) {
    if (event.origin !== IDP_ORIGIN) return;
    if (event.data.type === 'IDP_READY_FOR_ZKP') {
      idpPopupReady = true;
      trySendProofToIdP();
    }
    if (event.data.type === 'IDP_SSO_SUCCESS') {
      successRelayed = true;
      if (rpOrigin) {
        window.parent.postMessage(event.data, rpOrigin);
      }
    }
  }
});
```

- [ ] **Step 3: `wallet_agent.js`에 정적 서빙 라우트 추가**

`wallet_agent.js`에서 다음 두 줄(351-352행)을 찾는다:

```js
app.use(express.json());

app.use((req, res, next) => {
```

다음으로 교체한다(정적 라우트 2개를 토큰 검사 미들웨어보다 앞에 삽입):

```js
app.use(express.json());

// RP 페이지가 숨겨진 iframe으로 이 정적 relay 페이지를 임베드한다(설계 문서:
// docs/superpowers/specs/2026-07-21-wallet-relay-idp-popup-design.md). iframe의
// src 요청은 브라우저가 커스텀 헤더를 못 실어 보내므로, 아래 두 라우트는 반드시
// X-Wallet-Agent-Token 검사 미들웨어보다 앞에 둔다. frame-ancestors CSP로 이
// relay를 설정된 RP_ORIGIN 외의 페이지가 iframe으로 못 담게 막는다.
app.get('/relay', (req, res) => {
  res.setHeader('Content-Security-Policy', `frame-ancestors ${RP_ORIGIN}`);
  res.sendFile(path.join(__dirname, 'wallet', 'relay.html'));
});
app.use('/wallet', express.static(path.join(__dirname, 'wallet')));

app.use((req, res, next) => {
```

- [ ] **Step 4: 구문 검사**

Run: `node --check wallet_agent.js && echo OK`
Expected: `OK`

- [ ] **Step 5: 정적 라우트가 토큰 없이 응답하는지 확인 (컨트롤러 직접 실행)**

`wallet_agent.js`가 이미 떠 있다면(재시작 필요 여부는 사용자에게 먼저 확인), 다음으로 확인한다:

```bash
curl -sI http://127.0.0.1:5001/relay | head -5
curl -sI http://127.0.0.1:5001/wallet/relay.js | head -5
```

Expected: 둘 다 `200`이고(`X-Wallet-Agent-Token` 헤더 없이 curl했는데도 401이 아님), `/relay` 응답에
`content-security-policy: frame-ancestors http://127.0.0.1:3000` 헤더가 보임.

- [ ] **Step 6: 커밋**

```bash
git add wallet/relay.html wallet/relay.js wallet_agent.js
git commit -m "feat(mode2): serve a wallet-hosted relay page for the IdP login popup

idp/login_popup.js trusts whatever origin opened it, and RP currently
opens that popup directly - so IdP-origin code learns the RP's origin
via the #rp= fragment and the confirming event.origin. Adds wallet/relay.html
+ relay.js, served by wallet_agent.js ahead of its X-Wallet-Agent-Token
check (iframe src requests can't carry custom headers), scoped to the
configured RP_ORIGIN via a frame-ancestors CSP header. The relay will
become the thing that actually opens the IdP popup (Task 2), so
idp/login_popup.js sees the wallet's origin as its opener instead of the
RP's - no change needed there. Not yet wired into client.js."
```

---

### Task 2: `client.js`가 relay iframe을 쓰도록 배선 + 라이브 검증

**Files:**
- Modify: `client.js:89-90`(상태 변수), `client.js:163-202`(popup 준비/전송 함수), `client.js:344-358`(`openIdPLoginPopup`), `client.js:360-385`(메시지 리스너)

**Interfaces:**
- Consumes: Task 1의 `GET /relay`(iframe src로 로드) 및 postMessage 프로토콜(`RP_SEND_ZKP`/`IDP_READY_FOR_ZKP`/`IDP_POPUP_CLOSED`/`IDP_SSO_SUCCESS`).

- [ ] **Step 1: 상태 변수 교체**

`client.js`에서 다음 줄(89-90행)을 찾는다:

```js
  let idpPopupWindow = null;
  let idpPopupReady = false;
```

다음으로 교체한다:

```js
  let relayIframe = null;
  let relayReady = false;
```

- [ ] **Step 2: `postProofToIdPPopup`/`prepareIdPLoginPopup`을 relay 기반으로 교체**

`client.js`에서 다음 블록(163-202행)을 찾는다:

```js
  function postProofToIdPPopup() {
    if (!currentSSOProof || !idpPopupWindow || idpPopupWindow.closed || !idpPopupReady) return false;
    idpPopupWindow.postMessage({ type: 'RP_SEND_ZKP', zkp: currentSSOProof }, IDP_ORIGIN);
    return true;
  }

  function clearIdPOnlyProofMaterial() {
    if (!currentSSOProof) return;
    delete currentSSOProof.zkpProof;
    delete currentSSOProof.zkpPublicSignals;
    delete currentSSOProof.pi_i;
    if (currentSSOProof.walletSubmission) {
      delete currentSSOProof.walletSubmission.pi_i;
    }
  }

  function prepareIdPLoginPopup() {
    idpPopupReady = false;
    // RP origin을 URL 프래그먼트(#rp=...)로 실어 보낸다 — 프래그먼트는 브라우저가
    // 실제 HTTP 요청에는 절대 포함시키지 않으므로(항상 클라이언트에만 남음)
    // custom_idp.js 서버는 이 값을 볼 수 없다. 다만 이 값 자체는 그냥 문자열이라
    // login_popup.js는 이걸 "잠정값"으로만 쓰고, 실제 메시지가 오면 그 메시지의
    // event.origin(브라우저 보장, 위조 불가능)과 일치하는지 반드시 재확인한 뒤에만
    // 신뢰한다 — 그래서 반복 전송(RP_HELLO) 없이도 하드코딩 문제와 타이밍 레이스를
    // 동시에 피할 수 있다.
    // 창 이름을 고정값(예: 'IdPLogin')으로 두면, 같은 브라우징 컨텍스트 그룹 안에서
    // 미리 실행되는 악성 스크립트가 그 이름을 선점해 핸들을 쥐고 있다가 로그인 도중
    // 창을 다른 곳으로 재이동시키거나 강제로 닫아버릴 수 있다. 매번 예측 불가능한
    // 이름을 쓰면 이 선점 자체가 불가능해진다.
    const popupName = `IdPLogin-${crypto.randomUUID()}`;
    idpPopupWindow = window.open(
      `${IDP_ORIGIN}/login_popup#rp=${encodeURIComponent(window.location.origin)}`,
      popupName,
      'width=500,height=600',
    );
    if (!idpPopupWindow) {
      return false;
    }
    return true;
  }
```

다음으로 교체한다:

```js
  function postProofToRelay() {
    if (!currentSSOProof || !relayIframe || !relayReady) return false;
    relayIframe.contentWindow.postMessage({ type: 'RP_SEND_ZKP', zkp: currentSSOProof }, WALLET_AGENT_ORIGIN);
    return true;
  }

  function clearIdPOnlyProofMaterial() {
    if (!currentSSOProof) return;
    delete currentSSOProof.zkpProof;
    delete currentSSOProof.zkpPublicSignals;
    delete currentSSOProof.pi_i;
    if (currentSSOProof.walletSubmission) {
      delete currentSSOProof.walletSubmission.pi_i;
    }
  }

  function prepareWalletRelay() {
    if (relayIframe) return true;
    relayReady = false;
    // RP는 이제 IdP 팝업을 직접 열지 않는다 — 지갑(wallet_agent.js)이 서빙하는
    // 숨겨진 relay iframe을 열고, 그 iframe 안의 스크립트(지갑 origin에서 실행)가
    // 실제 IdP 팝업을 대신 연다. 그래서 idp/login_popup.js가 보는 opener origin은
    // RP가 아니라 지갑이 되고, IdP는 RP origin을 알 방법이 없어진다. 이 iframe은
    // 한 번만 만들고 재사용한다 — 재시도 시에는 relay가 자기 안의 IdP 팝업만 새로
    // 연다(wallet/relay.js의 openOrReuseIdPPopup 참고).
    relayIframe = document.createElement('iframe');
    relayIframe.style.display = 'none';
    relayIframe.src = `${WALLET_AGENT_ORIGIN}/relay#rp=${encodeURIComponent(window.location.origin)}`;
    document.body.appendChild(relayIframe);
    return true;
  }
```

- [ ] **Step 3: `openIdPLoginPopup` 갱신**

`client.js`에서 다음 블록(344-358행)을 찾는다:

```js
  function openIdPLoginPopup() {
    const start = now();
    try {
      if (!currentSSOProof) throw new Error('Generate ZKP first');
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 9. Wallet sends auid_i, arid_i, r_token, and pi_i to IdP published endpoint ${formatMs(start)}:\n${IDP_SSO_ENDPOINT}`;
      if (!idpPopupWindow || idpPopupWindow.closed) {
        if (!prepareIdPLoginPopup()) throw new Error('Popup blocked. Use the Step 9 button to retry.');
      }
      if (!postProofToIdPPopup()) {
        return;
      }
    } catch (err) {
      mode2Status.innerText = `Step 9 Error: ${err.message}`;
    }
  }
```

다음으로 교체한다:

```js
  function openIdPLoginPopup() {
    const start = now();
    try {
      if (!currentSSOProof) throw new Error('Generate ZKP first');
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 9. Wallet sends auid_i, arid_i, r_token, and pi_i to IdP published endpoint ${formatMs(start)}:\n${IDP_SSO_ENDPOINT}`;
      if (!prepareWalletRelay()) throw new Error('Failed to set up wallet relay. Use the Step 9 button to retry.');
      if (!postProofToRelay()) {
        return;
      }
    } catch (err) {
      mode2Status.innerText = `Step 9 Error: ${err.message}`;
    }
  }
```

- [ ] **Step 4: 메시지 리스너를 relay 기준으로 교체**

`client.js`에서 다음 블록(360-385행)을 찾는다:

```js
  // Listen for message from IdP Popup
  window.addEventListener('message', (event) => {
    if (event.origin !== IDP_ORIGIN) return;

    if (event.data.type === 'IDP_READY_FOR_ZKP') {
      console.log('[RP FE] IdP Popup ready signal received.');
      idpPopupWindow = event.source;
      idpPopupReady = true;
      postProofToIdPPopup();
    }
    
    if (event.data.type === 'IDP_SSO_SUCCESS') {
      if (event.data.r_i !== mode2SessionNonce) {
        console.warn('[Mode 2] r_i mismatch on IdP success message:', {
          expected: mode2SessionNonce,
          received: event.data.r_i
        });
        return;
      }
      currentIdPToken = event.data.idpToken;
      clearIdPOnlyProofMaterial();
      document.getElementById('step15NotifyWallet').disabled = false;
      document.getElementById('step25RPFEVerifyFail').disabled = false;
      runWalletStep11And12();
    }
  });
```

다음으로 교체한다:

```js
  // Listen for messages from the wallet relay iframe (never directly from the IdP popup anymore)
  window.addEventListener('message', (event) => {
    if (event.origin !== WALLET_AGENT_ORIGIN) return;

    if (event.data.type === 'IDP_READY_FOR_ZKP') {
      console.log('[RP FE] Wallet relay ready signal received.');
      relayReady = true;
      postProofToRelay();
    }

    if (event.data.type === 'IDP_POPUP_CLOSED') {
      console.warn('[Mode 2] IdP login popup was closed before completing SSO.');
      mode2Status.innerText = 'IdP login popup closed. Use the Step 9 button to retry.';
    }

    if (event.data.type === 'IDP_SSO_SUCCESS') {
      if (event.data.r_i !== mode2SessionNonce) {
        console.warn('[Mode 2] r_i mismatch on IdP success message:', {
          expected: mode2SessionNonce,
          received: event.data.r_i
        });
        return;
      }
      currentIdPToken = event.data.idpToken;
      clearIdPOnlyProofMaterial();
      document.getElementById('step15NotifyWallet').disabled = false;
      document.getElementById('step25RPFEVerifyFail').disabled = false;
      runWalletStep11And12();
    }
  });
```

- [ ] **Step 5: 구문 검사**

Run: `node --check client.js && echo OK`
Expected: `OK`

- [ ] **Step 6: 라이브 검증 (컨트롤러가 직접 실행, 서브에이전트에 위임하지 않음)**

실제 사용자 브라우저를 다루는 작업이라 매 단계 사용자 확인이 필요하다. `client.js`는 정적 파일이라 브라우저
새로고침만 하면 반영된다(서버 재시작 불필요). `wallet_agent.js`는 Task 1에서 이미 재시작했는지 확인한다.

브라우저에서 사용자에게 다음을 요청:
1. 로그인(Step 1-15)을 처음부터 끝까지 진행해서, 오늘과 동일하게 IdP 팝업에 로그인 폼이 뜨고 동의 후 로그인이
   완료되는지 확인 요청.
2. IdP 팝업 창에서 개발자 도구를 열어 `window.opener.location.origin` 또는 콘솔에서 opener 관련 값을
   확인해서(또는 Step 1에서 이미 로그로 남는 `tentativeRpOrigin`/`rpOrigin` 값을 `console.log`로 임시 확인),
   `http://127.0.0.1:3000`이 아니라 `http://127.0.0.1:5001`로 나오는지 확인 요청.
3. Step 9 버튼을 누른 뒤 뜬 IdP 팝업을 로그인 중간에 직접 닫아서, "IdP login popup closed. Use the Step 9
   button to retry." 메시지가 뜨는지, 이어서 Step 9를 다시 눌렀을 때 새 IdP 팝업이 뜨고 정상적으로 로그인이
   이어지는지 확인 요청.

테스트가 끝나면 포트를 정리할지 사용자에게 확인한다.

- [ ] **Step 7: 커밋**

```bash
git add client.js
git commit -m "feat(mode2): route the IdP login popup through the wallet relay

client.js used to open idp/login_popup.js directly and exchange
RP_SEND_ZKP/IDP_READY_FOR_ZKP/IDP_SSO_SUCCESS with it by postMessage,
which handed the IdP-origin popup script the RP's real origin (via the
#rp= fragment and the confirming event.origin). Now client.js embeds
the wallet_agent.js-served relay (Task 1) as a hidden iframe and
exchanges the same message types with it instead; the relay is the one
that actually opens the IdP popup, so idp/login_popup.js's opener is
the wallet's origin, not the RP's. Adds IDP_POPUP_CLOSED handling to
keep today's retry UX. idp/login_popup.js is untouched. Confirmed live:
full login flow still works, IdP popup no longer resolves the RP's
origin, and the retry-after-close path works."
```

## Self-Review

- **스펙 커버리지**: 스펙의 "포함" 목록(relay 정적 파일 쌍, `wallet_agent.js` 서빙 + CSP, `client.js` 배선,
  팝업 닫힘 감지) 전부 Task 1/2에 매핑됨. "범위 밖"(`idp/login_popup.js` 등)은 어느 Task에서도 건드리지 않음.
- **플레이스홀더 검사**: 없음.
- **타입/이름 일관성**: `relayIframe`/`relayReady`/`postProofToRelay`/`prepareWalletRelay`(client.js)와
  `wallet/relay.js`가 실제로 보내고 받는 메시지 타입(`RP_SEND_ZKP`/`IDP_READY_FOR_ZKP`/`IDP_POPUP_CLOSED`/
  `IDP_SSO_SUCCESS`)이 두 Task에서 동일하게 쓰임. `WALLET_AGENT_ORIGIN`은 client.js에 이미 있는 기존 상수를
  재사용(새로 정의하지 않음).
