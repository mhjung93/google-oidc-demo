# RP FE가 IdP Authorize 요청을 여는 구조로 재설계 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** IdP의 `/authorize` 엔드포인트로 브라우저를 여는 주체를 `wallet_agent.js`(Node `open()`)에서 `client.js`(RP FE, `window.open()`)로 옮기되, ZKP 증명(`auid` 포함)은 여전히 RP FE에 노출되지 않게 한다.

**Architecture:** `wallet_agent.js`는 `/par` 호출(ZKP 증명 포함)과 loopback 콜백 수신을 그대로 유지하고, 그 결과인 의미 없는 참조값 `request_uri`만 `/loginStatus` 응답에 실어 RP FE에 넘긴다. `client.js`는 사용자가 로그인 버튼을 클릭한 바로 그 순간(어떤 `await`보다 먼저) 빈 브라우저 창을 미리 열어두고, 나중에 `request_uri`를 받으면 그 창의 `location.href`만 바꿔치기해서 팝업 차단을 피한다. `custom_idp.js`는 전혀 안 바뀐다.

**Tech Stack:** Node.js/Express(`wallet_agent.js`), 바닐라 브라우저 JS(`client.js`), 표준 `window.open()`/`Window.location`.

## Global Constraints

- `request_uri`는 그 자체로 아무 정보도 담지 않는 참조 문자열이다. RP FE는 `zkpProof`, `zkpPublicSignals`(따라서 `auid`도)를 이번에도 절대 받지 않는다 — `/par` 호출은 계속 `wallet_agent.js`가 IdP에 직접 보낸다.
- `window.open('', '_blank')`는 클릭 핸들러의 **첫 동기 구문**(어떤 `await`보다 먼저)에서 호출해야 한다. 그 뒤에 나오는 `await`들 이후에 새로 `window.open()`을 부르면 팝업 차단에 걸린다.
- 사용자에게 보여주는 폴백 링크는 `innerHTML`이 아니라 `document.createElement`/`textContent`로 만든다 — 이 코드베이스의 기존 관례(`setSelectMessage`)를 따른다.
- `client_id` 상수는 `PAIRCT_CLIENT_ID = 'pairct-wallet'` — RP를 특정하지 않는 공유 고정값이라 RP FE가 알아도 안전하다(PPT p.17 "공통 wallet client id" 확인됨).
- `custom_idp.js`는 이번 계획에서 수정하지 않는다.
- `noopener`는 의도적으로 안 쓴다(창을 나중에 이동시키기 위해 참조가 필요) — 이론상 tabnabbing 가능성은 IdP를 honest-but-curious로 가정하는 기존 위협 모델 범위 밖이라 새로 방어하지 않는다.
- 새로 추가하는 코드 주석은 한글로, "왜"가 비자명한 경우에만 작성한다.
- 각 태스크는 해당 태스크가 손댄 파일만 `git add`해서 커밋한다.

---

### Task 1: `wallet_agent.js` — 브라우저를 열지 않고 `request_uri`만 노출

**Files:**
- Modify: `wallet_agent.js:10` (import 제거), `wallet_agent.js:581-594` (`/loginStatus`), `wallet_agent.js:691-702` (`startLoopbackLogin` 끝부분)
- Test: `tests/test_wallet_login_loopback.js` (기존 파일에 케이스 추가)

**Interfaces:**
- Consumes: 없음(기존 `/par`/loopback 로직 재사용, 변경 없음).
- Produces: `GET /loginStatus`가 `awaiting_browser_login` 상태일 때 `{status:'awaiting_browser_login', requestUri: string}`을 반환(지금은 `{status:'awaiting_browser_login'}`만 반환). Task 2가 이 `requestUri` 필드를 소비한다.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_wallet_login_loopback.js`를 연다. 기존 `main()` 함수 안의 아래 블록:

```javascript
  console.log('-- approved: true reaches awaiting_browser_login (/par succeeded) --');
  const approvedJobId = await startJobToApproval(token);
  const approveRes = await fetch(`${WALLET}/confirmLoginResult`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
    body: JSON.stringify({ jobId: approvedJobId, approved: true }),
  });
  if (approveRes.status !== 200) throw new Error(`FAIL: expected 200, got ${approveRes.status}`);
  const afterApproval = await pollUntil(
    token, approvedJobId,
    (s) => s.status === 'awaiting_browser_login' || s.status === 'failed',
    10000,
  );
  if (afterApproval.status !== 'awaiting_browser_login') {
    throw new Error(`FAIL: expected awaiting_browser_login, got ${afterApproval.status} (${afterApproval.error ?? ''})`);
  }
  console.log('PASS: job reached awaiting_browser_login — /par succeeded, loopback listener is open and waiting');
```

바로 다음 줄(`await testConcurrentJobsDoNotCorruptSessionKeys(token);` 이전)에 아래 검증을 추가한다:

```javascript
  if (typeof afterApproval.requestUri !== 'string' || afterApproval.requestUri.length === 0) {
    throw new Error(`FAIL: expected non-empty string requestUri, got ${JSON.stringify(afterApproval.requestUri)}`);
  }
  console.log('PASS: /loginStatus exposes a non-empty requestUri once /par succeeds');
```

- [ ] **Step 2: 서버 3개(custom_idp.js:4000, server.js:3000, wallet_agent.js:5001)를 실행한 채 테스트를 돌려서 실패를 확인**

Run: `node tests/test_wallet_login_loopback.js`
Expected: `FAIL: expected non-empty string requestUri, got undefined`로 실패 (아직 `requestUri` 필드가 없으므로).

- [ ] **Step 3: `wallet_agent.js:10`의 `import open from 'open';` 삭제**

파일 상단의 `import open from 'open';` 줄을 지운다(파일 전체에서 `open(`을 부르는 곳은 이 삭제 대상 코드 한 곳뿐이다 — Step 5에서 그 호출도 지운다).

- [ ] **Step 4: `GET /loginStatus`에 `requestUri` 노출 추가**

`wallet_agent.js:581-594`(`app.get('/loginStatus', (req, res) => { ... });` 전체)를 아래로 교체한다:

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

- [ ] **Step 5: `startLoopbackLogin()`에서 브라우저 오픈 제거, `job.requestUri` 저장**

`wallet_agent.js:691-702`(기존 `job.status = 'awaiting_browser_login';`부터 함수를 닫는 `}`까지)를 아래로 교체한다:

```javascript
  job.status = 'awaiting_browser_login';
  job.requestUri = parBody.request_uri;
  console.log(`[WalletAgent][loopback] job ${jobId} pushed to IdP, request_uri=${parBody.request_uri}, redirect_uri=${redirectUri}`);
  // 브라우저를 여는 건 이제 RP FE의 몫이다 — RP FE가 사용자 클릭 시점에 미리
  // 열어둔 빈 창을 이 request_uri로 이동시킨다(팝업 차단 회피). Wallet은 IdP에
  // ZKP 증명을 담아 /par만 보내고, 그 결과인 request_uri(그 자체로는 아무
  // 의미 없는 참조값)만 RP FE에 넘겨준다.
}
```

- [ ] **Step 6: wallet_agent.js 재시작 후 테스트 통과 확인**

Run: `node tests/test_wallet_login_loopback.js`
Expected: `ALL WALLET LOOPBACK TESTS PASSED (manual browser completion not covered — see design spec)` (새 `requestUri` PASS 줄 포함)

- [ ] **Step 7: 커밋**

```bash
git add wallet_agent.js tests/test_wallet_login_loopback.js
git commit -m "feat(mode2): stop opening the browser in wallet_agent.js, expose request_uri instead"
```

---

### Task 2: `client.js` + `index.html` — RP FE가 미리 연 창을 IdP authorize URL로 이동

**Files:**
- Modify: `client.js:24` (클릭 핸들러 시작부), `client.js:74` (`runDelegatedLogin` 호출부), `client.js:146` 부근(상수), `client.js:153` (`runDelegatedLogin` 시그니처+본문), `client.js:178-179` (가드 변수), `client.js:217-219` (`awaiting_browser_login` 케이스), `runDelegatedLogin` 뒤에 새 함수 2개 추가
- Modify: `index.html` (`mode2Status` 다음 줄에 폴백 링크 컨테이너 추가)

**Interfaces:**
- Consumes: Task 1이 만든 `GET /loginStatus`의 `awaiting_browser_login` 응답 `{status:'awaiting_browser_login', requestUri: string}`.
- Produces: 이 태스크가 마지막 코드 소비자다. 이후 태스크 없음.

- [ ] **Step 1: 상수 추가**

`client.js:146`(`const IDP_ORIGIN = 'http://127.0.0.1:4000';`) 바로 다음 줄에 삽입:

```javascript
  const PAIRCT_CLIENT_ID = 'pairct-wallet';
```

- [ ] **Step 2: 클릭 핸들러 첫 줄에서 빈 창 열기**

`client.js:24`의 `mode2SSOLoginButton?.addEventListener('click', async () => {` 바로 다음 줄에, 기존 코드(`if (mode2SSOSection) mode2SSOSection.style.display = 'block';`)보다 먼저 삽입:

```javascript
    let authWindowRef = null;
    try {
      authWindowRef = window.open('', '_blank');
      authWindowRef?.document.write('<p style="font-family: system-ui;">IdP 로그인 페이지를 준비하는 중입니다&hellip;</p>');
    } catch (err) {
      authWindowRef = null;
    }

```

- [ ] **Step 3: `runDelegatedLogin` 호출부와 시그니처 수정**

`client.js:74`의 `await runDelegatedLogin();`을 `await runDelegatedLogin(authWindowRef);`로 바꾼다.

`client.js:153`의 `async function runDelegatedLogin() {`를 `async function runDelegatedLogin(authWindowRef) {`로 바꾼다.

그 함수 본문의 두 번째 줄(`mode2Status.innerText = 'Login job starting...';` 다음)에 삽입:

```javascript
    document.getElementById('authWindowFallback')?.replaceChildren();
```

- [ ] **Step 4: 가드 변수 추가**

`client.js:178`(`let snapConfirmSent = false;`) 다음 줄, `const POLL_INTERVAL_MS = 1000;` 이전에 삽입:

```javascript
    let browserNavigated = false;
```

- [ ] **Step 5: `awaiting_browser_login` 케이스에서 창 이동 트리거**

`client.js:217-219`를 아래로 교체한다:

```javascript
            case 'awaiting_browser_login':
              if (!browserNavigated) {
                browserNavigated = true;
                navigateToIdP(authWindowRef, data.requestUri);
              }
              mode2Status.innerText = '시스템 브라우저에서 IdP 로그인을 진행해주세요.';
              return;
```

- [ ] **Step 6: `navigateToIdP`/`showManualAuthorizeLink` 함수 추가**

`runDelegatedLogin` 함수 정의가 끝나는 `}` 바로 다음(즉 `runRpVerifyStatement` 정의 앞)에 삽입:

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

- [ ] **Step 7: `index.html`에 폴백 링크 컨테이너 추가**

`index.html`에서 `<p id="mode2Status" ...></p>` 줄을 찾아 바로 다음 줄에 삽입:

```html
    <p id="authWindowFallback" style="font-size: 0.85em; margin-top: 6px;"></p>
```

- [ ] **Step 8: 문법 검사**

Run: `node --check client.js`
Expected: 출력 없이 종료(문법 오류 없음).

- [ ] **Step 9: 수동 브라우저 테스트**

`node server.js`(3000), `node custom_idp.js`(4000), `node wallet_agent.js`(5001)를 띄우고(이미 떠 있다면 재시작 불필요 — Task 1에서 `wallet_agent.js`는 재시작했어야 함), `index.html`을 MetaMask+Snap이 연결된 브라우저로 연다.

1. **골든 패스**: "Delegated Login" 클릭 → 그 즉시 새 빈 창(로딩 문구)이 뜨는지 확인 → Snap `confirmLogin` 승인 → **추가 클릭 없이** 그 창이 자동으로 IdP 로그인 페이지로 바뀌는지 확인 → `testuser`/`password123`으로 로그인 후 동의 → 탭이 "Login complete" 메시지로 바뀌면 원래 페이지에서 "로그인 성공" + "Send PPID Transaction" 버튼 활성화까지 확인.
2. **팝업 차단 시나리오**: 브라우저의 팝업 차단을 강하게 설정(또는 시크릿 모드 등 팝업이 막히는 환경)한 뒤 같은 과정을 반복 — 빈 창 열기 자체가 막혔을 때 `#authWindowFallback`에 "여기를 클릭해서 IdP 로그인 페이지 열기" 링크가 뜨는지, 그 링크를 눌러 수동으로 진행해도 로그인이 완주되는지 확인.

CLAUDE.md 규칙대로, 이 수동 테스트를 위해 새로 띄운 프로세스는 테스트가 끝나면 포트(3000/4000/5001)를 정리한다.

- [ ] **Step 10: 커밋**

```bash
git add client.js index.html
git commit -m "feat(mode2): open the IdP authorize URL from client.js instead of wallet_agent.js"
```

---

## 정리 대상 (선택)

`package.json`에서 `open` 의존성이 다른 곳에 안 쓰이면 제거를 고려한다(구현 단계에서 `grep -rn "from 'open'" --include=*.js .`로 확인 후 필요하면 `npm uninstall open` — 두 태스크 어느 쪽에도 필수는 아니므로, Task 1 완료 후 여유가 있으면 같이 처리해도 되고 별도로 남겨도 된다).
