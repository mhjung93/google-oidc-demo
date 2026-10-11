# RP FE가 IdP Authorize 요청을 여는 구조로 재설계 — 설계 문서

## 1. 배경

직전 서브프로젝트(`2026-07-31-rp-fe-statement-verification-design.md`)에서 완성한 로그인 흐름은 `wallet_agent.js`가 `POST /par` 호출, 시스템 브라우저 오픈(`open()`), loopback 콜백 수신을 전부 혼자 담당했다. 이 구조에 대해 "브라우저를 여는 주체가 RP FE가 아니라 백그라운드 Node 프로세스라는 게 이상하다"는 지적이 있었고, 확인 결과 애초에 참고했던 PPT(`260731_meeting_MHJ.pptx`) 원안도 "Wallet은 콜백용 포트만 알려주고, 실제로 IdP authorize endpoint를 여는 건 RP FE"인 구조였다(p.2, p.5).

이번 서브프로젝트는 그 부분만 정정한다: **IdP에 ZKP 증명을 담아 보내는 `/par` 호출과 콜백 수신은 그대로 Wallet이 하되, "브라우저를 IdP authorize URL로 보내는" 그 한 단계만 RP FE로 옮긴다.** `custom_idp.js`는 전혀 안 바뀐다(누가 `/authorize`를 열든 상관하지 않는 엔드포인트이므로).

## 2. 목표 / 비목표

**목표**
- `client.js`(RP FE)가 IdP의 `/authorize` 엔드포인트로 브라우저를 여는 주체가 된다.
- `wallet_agent.js`는 `/par` 호출(ZKP 증명 포함)과 loopback 콜백 수신을 그대로 유지하되, 브라우저를 직접 여는 코드(`open()`)는 제거한다.
- `auid`를 포함한 ZKP 증명 데이터(`zkpProof`, `zkpPublicSignals`)는 이번에도 RP FE에 노출되지 않는다 — RP FE가 받는 건 의미 없는 참조값인 `request_uri`뿐이다.
- 브라우저를 여는 시점이 사용자 클릭에서 여러 `await`만큼 떨어져 있어도 팝업 차단에 걸리지 않게 한다.

**비목표**
- `custom_idp.js` 변경 — 없음. `/par`/`/authorize`/`/token` 어느 것도 "누가 브라우저를 여는지" 신경 쓰지 않는다.
- `POST /par`의 요청 바디, `POST /token`의 흐름, loopback 콜백 서버 구조 — 안 바뀜.
- `2026-07-31` 서브프로젝트에서 다룬 `verify_statement`, `submitPPIDTransaction`, 옛 팝업/relay 정리 — 이미 완료, 이번 범위 아님.

## 3. `wallet_agent.js` 변경

### 3.1 `startLoopbackLogin()` — 브라우저를 열지 않고 `request_uri`만 저장

`wallet_agent.js:691-702`(현재 `job.status = 'awaiting_browser_login';`부터 함수 끝까지)을 아래로 교체한다:

```javascript
  job.status = 'awaiting_browser_login';
  job.requestUri = parBody.request_uri;
  console.log(`[WalletAgent][loopback] job ${jobId} pushed to IdP, request_uri=${parBody.request_uri}, redirect_uri=${redirectUri}`);
  // 브라우저를 여는 건 이제 RP FE의 몫이다 — RP FE가 사용자 클릭 시점에 미리
  // 열어둔 빈 창을 이 request_uri로 이동시킨다(팝업 차단 회피, 설계 문서 §4
  // 참고). Wallet은 IdP에 ZKP 증명을 담아 /par만 보내고, 그 결과인 request_uri
  // (그 자체로는 아무 정보도 없는 참조값)만 RP FE에 넘겨준다.
}
```

`wallet_agent.js:10`의 `import open from 'open';`도 제거한다(다른 곳에서 안 쓰임 — `open(`은 파일 전체에서 이 한 곳뿐이었다).

### 3.2 `GET /loginStatus` — `awaiting_browser_login`에 `requestUri` 포함

`wallet_agent.js:581-594`를 아래로 교체한다:

```javascript
app.get('/loginStatus', (req, res) => {
  pruneExpiredJobs();
  const { jobId } = req.query ?? {};
  const job = loginJobs.get(jobId);
  if (!job) return res.status(404).json({ error: 'Unknown or expired jobId' });

  if (job.status === 'done') {
    return res.json({ status: 'done', ...job.result });
  }
  if (job.status === 'failed') {
    return res.json({ status: 'failed', error: job.error });
  }
  if (job.status === 'awaiting_browser_login') {
    return res.json({ status: 'awaiting_browser_login', requestUri: job.requestUri });
  }
  res.json({ status: job.status });
});
```

## 4. `client.js` 변경

### 4.1 상수 추가

`client.js:146`(기존 `const IDP_ORIGIN = 'http://127.0.0.1:4000';`) 바로 아래에 추가:

```javascript
  const PAIRCT_CLIENT_ID = 'pairct-wallet';
```

(`IDP_ORIGIN`은 이미 존재한다 — 이전 서브프로젝트의 최종 리뷰에서 죽은 코드로 남겨뒀던 것을 이번에 다시 쓰게 된다.)

### 4.2 클릭 핸들러 — 첫 줄에서 빈 창 열기

`client.js:24`(`mode2SSOLoginButton?.addEventListener('click', async () => {`) 바로 다음 줄, **`mode2SSOSection.style.display` 대입보다도 먼저**, 어떤 `await`도 실행되기 전에 삽입:

```javascript
    let authWindowRef = null;
    try {
      authWindowRef = window.open('', '_blank');
      authWindowRef?.document.write('<p style="font-family: system-ui;">IdP 로그인 페이지를 준비하는 중입니다&hellip;</p>');
    } catch (err) {
      authWindowRef = null;
    }
```

이 시점(핸들러의 첫 동기 구문)에만 팝업 차단이 사용자 제스처를 인식한다 — `connectSnap()`, `rp_credential_nonce` fetch 등 이후에 나오는 `await`들 뒤에서 새로 `window.open()`을 부르면 대부분 브라우저가 막는다. 미리 열어둔 창은 나중에 `.location.href`만 바꾸는 거라 그 시점엔 차단 대상이 아니다.

`client.js:74`의 `await runDelegatedLogin();`을 `await runDelegatedLogin(authWindowRef);`로 바꾼다.

### 4.3 `runDelegatedLogin(authWindowRef)` — 파라미터 추가 + 콜백 시점에 창 이동

`client.js:153`의 함수 시그니처를 `async function runDelegatedLogin(authWindowRef) {`로 바꾸고, 함수 본문 맨 앞(`mode2Status.innerText = 'Login job starting...';` 다음 줄)에 이전 시도의 폴백 링크를 지우는 한 줄을 추가:

```javascript
    document.getElementById('authWindowFallback')?.replaceChildren();
```

`client.js:178-179`(`let snapConfirmSent = false;` / `const POLL_INTERVAL_MS = 1000;`) 사이에 새 가드 변수를 추가:

```javascript
    let snapConfirmSent = false;
    let browserNavigated = false;
    const POLL_INTERVAL_MS = 1000;
```

`client.js:217-219`의 `awaiting_browser_login` 케이스를 아래로 교체:

```javascript
            case 'awaiting_browser_login':
              if (!browserNavigated) {
                browserNavigated = true;
                navigateToIdP(authWindowRef, data.requestUri);
              }
              mode2Status.innerText = '시스템 브라우저에서 IdP 로그인을 진행해주세요.';
              return;
```

`runDelegatedLogin` 함수 뒤(예: `runRpVerifyStatement` 정의 앞)에 두 개의 새 함수를 추가:

```javascript
  function navigateToIdP(authWindowRef, requestUri) {
    const authorizeUrl = `${IDP_ORIGIN}/authorize?client_id=${PAIRCT_CLIENT_ID}&request_uri=${encodeURIComponent(requestUri)}`;
    if (authWindowRef && !authWindowRef.closed) {
      try {
        authWindowRef.location.href = authorizeUrl;
        return;
      } catch (err) {
        console.warn('[Mode 2] Failed to navigate pre-opened auth window:', err.message);
      }
    }
    showManualAuthorizeLink(authorizeUrl);
  }

  function showManualAuthorizeLink(authorizeUrl) {
    const container = document.getElementById('authWindowFallback');
    if (!container) return;
    container.replaceChildren();
    const link = document.createElement('a');
    link.href = authorizeUrl;
    link.target = '_blank';
    link.rel = 'noopener';
    link.textContent = '여기를 클릭해서 IdP 로그인 페이지 열기';
    container.appendChild(link);
  }
```

`showManualAuthorizeLink`가 `innerHTML`이 아니라 `createElement`/`textContent`로 링크를 만드는 건, 이 코드베이스가 이미 `setSelectMessage`(신뢰할 수 없는 문자열을 마크업으로 해석시키지 않기 위해 `textContent`만 씀) 같은 곳에서 따르는 관례를 그대로 따른 것이다.

### 4.4 `index.html` — 폴백 링크를 담을 요소 추가

`index.html`의 `<p id="mode2Status" ...>` 바로 다음 줄에 추가:

```html
    <p id="authWindowFallback" style="font-size: 0.85em; margin-top: 6px;"></p>
```

## 5. 보안 노트

- **RP FE origin이 IdP에 노출되지 않는다.** `index.html`에 이미 `<meta name="referrer" content="same-origin" />`가 있어서, 다른 origin(IdP, 4000번 포트)으로 가는 요청엔 애초에 Referer 헤더가 안 실린다. 이번 변경으로 새로 생기는 위험이 아니다.
- **`client_id='pairct-wallet'`는 RP를 특정하지 않는 공유 고정값이다.** PPT p.17의 "vs. ZKP" 비교표가 명시하듯("공통 wallet client id (CPP-wallet)"), 실제 RP 신원(`rid`)은 이 client_id가 아니라 ZKP(hidden rid, `arid_i = rid·rp_nonce`)로 검증된다. RP FE가 이 상수를 아는 것 자체는 어떤 정보도 추가로 노출하지 않는다.
- **`auid`/`zkpProof`/`zkpPublicSignals`는 여전히 RP FE에 절대 안 간다.** `/par` 호출은 이번에도 Wallet이 직접 IdP에 보내고(`wallet_agent.js:667`), RP FE는 그 결과인 `request_uri`(그 자체로는 아무 의미 없는 참조 문자열)만 받는다.
- **`noopener`를 쓰지 않는다.** 창을 나중에 이동시켜야 해서 참조(`authWindowRef`)를 계속 들고 있어야 하기 때문이다. 이 때문에 이론적으로 IdP 쪽 페이지가 `window.opener.location`을 다른 곳으로 돌리는 tabnabbing이 가능해지지만, 이 프로젝트는 IdP를 honest-but-curious로 가정하고 있어(PPT p.20) 이미 위협 모델 범위 밖이다 — 새로 막을 필요는 없다.

## 6. 테스트 계획

- `tests/test_wallet_login_loopback.js`(기존)에 검증 추가: `approved: true`로 `awaiting_browser_login`에 도달했을 때, 응답에 `requestUri` 필드가 문자열로 존재하는지 확인하는 케이스를 추가한다(지금은 `status`만 확인함).
- `open` 패키지 제거로 인해, 테스트 환경에 실제 브라우저가 없어도 더는 `open()`이 실행 자체를 시도하지 않는다 — 기존에 `open()` 실패를 견디던 try/catch가 통째로 사라지므로 회귀 확인이 필요하다(같은 테스트 파일로 커버됨).
- `client.js`는 이번에도 자동 브라우저 테스트 대상이 아니다. 수동 확인 항목: (1) "Delegated Login" 클릭 시 빈 창이 즉시 뜨는지, (2) Snap 승인 후 그 창이 IdP 로그인 페이지로 자동 전환되는지(추가 클릭 없이), (3) 브라우저 팝업 차단을 강하게 설정한 상태에서도 폴백 링크(`#authWindowFallback`)가 뜨는지, (4) 로그인 완주 후 "Send PPID Transaction"까지 정상 동작하는지.

## 7. 정리 대상

- `package.json`의 `open` 의존성 — `wallet_agent.js`가 더 이상 안 쓰므로 제거 후보. `npm uninstall open` 실행 여부는 구현 단계에서 다른 곳(스크립트 등)에서 쓰지 않는지 확인 후 결정한다.
