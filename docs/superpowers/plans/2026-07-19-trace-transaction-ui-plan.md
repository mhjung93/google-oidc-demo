# Trace Transaction UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** RP 페이지(`index.html`/`client.js`)에 B2 트랜잭션 추적(`POST /api/mode2/trace_transaction`, 이미 구현된 백엔드) 기능을 시연할 수 있는 버튼과 입력 필드를 추가한다.

**Architecture:** 기존 "Send PPID Transaction" 버튼 바로 아래에 `pk_i`/`max_height` 입력 필드와 "Trace Transaction" 버튼을 추가한다. Step 15 완료 시점에 두 입력 필드를 `ssoMetadata`의 기존 값으로 자동 채우고, 버튼 클릭 시 기존 백엔드 엔드포인트를 호출해 결과를 표시한다. 백엔드는 전혀 건드리지 않는다.

**Tech Stack:** 순수 HTML/vanilla JS, `fetch` — 새 의존성 없음.

## Global Constraints

- 새 버튼/입력 필드는 반드시 `#ssoStepButtons`(`display:none`인 디버그 패널) **밖**에 둔다 — `#rpFeVisibleFlow`/`#submitPPIDTransaction`과 같은 레벨(형제 요소)이어야 실제로 보인다. (과거 RP-UI 플랜에서 이 실수로 버튼이 안 보였던 적이 있음.)
- `server.js`/`custom_idp.js`의 추적 로직은 전혀 수정하지 않는다 — 이미 구현/테스트된 백엔드를 그대로 재사용한다.
- 별도 페이지, 별도 섹션, 인증/승인 게이트는 추가하지 않는다.

---

### Task 1: 추적 UI 추가

**Files:**
- Modify: `index.html:18-26`
- Modify: `client.js:456-507`(핸들러 추가), `client.js:740-742`(자동 채움 추가)

**Interfaces:**
- Consumes: 기존 `POST /api/mode2/trace_transaction`(body `{pk_i, max_height}`, 응답 `{uid}` 또는 `{error}`), 기존 `ssoMetadata.signingPublicKey`/`ssoMetadata.maxHeight`(Step 8에서 이미 채워짐).
- Produces: 없음(이 기능을 소비하는 후속 태스크 없음).

- [ ] **Step 1: `index.html`에 입력 필드/버튼 추가**

`index.html`에서 다음 블록(18-26행)을 찾는다:

```html
    <div id="mode2SSOSection" style="display: none;">
      <div id="rpFeVisibleFlow" style="margin-top: 12px; padding: 10px; border: 1px solid #c8e6c9; background: #f1f8e9; font-size: 0.9em;">
        <strong>RP FE Flow</strong>
        <pre id="rpFeVisibleFlowLog" style="margin: 6px 0 0; white-space: pre-wrap;"></pre>
      </div>
      <div style="margin-top: 12px;">
        <button id="submitPPIDTransaction" style="background: #e1f5fe;" disabled>Send PPID Transaction</button>
        <p id="ppidTxResult" style="font-size: 0.85em; color: #333; white-space: pre-wrap;"></p>
      </div>
```

이 블록 바로 다음(원래 27행이던 `<div id="ssoStepButtons"...` 앞)에 새 블록을 삽입해서 다음과 같이 만든다:

```html
    <div id="mode2SSOSection" style="display: none;">
      <div id="rpFeVisibleFlow" style="margin-top: 12px; padding: 10px; border: 1px solid #c8e6c9; background: #f1f8e9; font-size: 0.9em;">
        <strong>RP FE Flow</strong>
        <pre id="rpFeVisibleFlowLog" style="margin: 6px 0 0; white-space: pre-wrap;"></pre>
      </div>
      <div style="margin-top: 12px;">
        <button id="submitPPIDTransaction" style="background: #e1f5fe;" disabled>Send PPID Transaction</button>
        <p id="ppidTxResult" style="font-size: 0.85em; color: #333; white-space: pre-wrap;"></p>
      </div>
      <div style="margin-top: 12px;">
        <label for="traceInputPkI">pk_i: </label>
        <input id="traceInputPkI" type="text" size="46" style="font-family: monospace;" />
        <br />
        <label for="traceInputMaxHeight">max_height: </label>
        <input id="traceInputMaxHeight" type="text" size="20" style="font-family: monospace;" />
        <br />
        <button id="traceTransaction" style="background: #fff3e0; margin-top: 6px;">Trace Transaction</button>
        <p id="traceResult" style="font-size: 0.85em; color: #333; white-space: pre-wrap;"></p>
      </div>
```

(`#ssoStepButtons`로 시작하는 그다음 블록은 그대로 둔다 — 손대지 않는다.)

- [ ] **Step 2: `client.js`에 추적 버튼 클릭 핸들러 추가**

`client.js`에서 `submitPPIDTransaction` 클릭 핸들러(456-507행)의 닫는 `});` 바로 다음에 새 핸들러를 추가한다:

```js
  document.getElementById('traceTransaction')?.addEventListener('click', async () => {
    const resultEl = document.getElementById('traceResult');
    resultEl.innerText = 'Tracing...';
    try {
      const pkI = document.getElementById('traceInputPkI').value;
      const maxHeight = document.getElementById('traceInputMaxHeight').value;
      if (!pkI) throw new Error('pk_i is required');
      if (!maxHeight) throw new Error('max_height is required');

      const traceRes = await fetch('/api/mode2/trace_transaction', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pk_i: pkI, max_height: maxHeight }),
      });
      const traceResult = await traceRes.json();
      if (!traceRes.ok) throw new Error(traceResult.error || 'trace_transaction failed');

      resultEl.innerText = `Traced uid: ${traceResult.uid}`;
    } catch (err) {
      resultEl.innerText = `Error: ${err.message}`;
    }
  });
```

- [ ] **Step 3: Step 15 완료 시점에 입력 필드 자동 채움**

`client.js`의 `runRPFeStep15()` 안, 다음 블록(약 740-742행)을 찾는다:

```js
    const submitButton = document.getElementById('submitPPIDTransaction');
    if (submitButton) submitButton.disabled = false;
  }
```

다음으로 교체:

```js
    const submitButton = document.getElementById('submitPPIDTransaction');
    if (submitButton) submitButton.disabled = false;
    const tracePkIInput = document.getElementById('traceInputPkI');
    const traceMaxHeightInput = document.getElementById('traceInputMaxHeight');
    if (tracePkIInput) tracePkIInput.value = ssoMetadata.signingPublicKey ?? '';
    if (traceMaxHeightInput) traceMaxHeightInput.value = ssoMetadata.maxHeight ?? '';
  }
```

- [ ] **Step 4: 구문 검사**

Run: `node --check client.js && echo OK`
Expected: `OK`

- [ ] **Step 5: 커밋**

```bash
git add index.html client.js
git commit -m "feat(mode2): add trace-transaction UI to the RP page

Wires the existing POST /api/mode2/trace_transaction endpoint (B2,
already implemented and tested) to a button on the RP page so it can
be demonstrated live. pk_i/max_height inputs are pre-filled from the
session's own Step 8 values (editable) so the default flow traces the
transaction just submitted. Placed as a sibling of the existing
transaction button, not inside the hidden #ssoStepButtons debug
panel."
```

---

### Task 2: 라이브 검증

이 태스크는 컨트롤러가 직접 실행한다(서브에이전트에 위임하지 않음) — 실제 사용자 브라우저를 다루는 작업이라 매 단계 사용자 확인이 필요하다. 백엔드를 전혀 안 건드렸으므로 서버 재시작은 필요 없다(이미 떠 있는 서버를 그대로 쓴다).

**Files:** 없음.

- [ ] **Step 1: 사용자에게 라이브 테스트 요청**

브라우저에서 새로고침 후: 로그인(Step 1-15) → "Send PPID Transaction" 클릭 → "Trace Transaction" 버튼이 `pk_i`/`max_height`가 채워진 채로 나타나는지 확인 → 클릭해서 정확한 `uid`가 표시되는지 확인. 그다음 `pk_i`나 `max_height`를 임의의 값으로 바꿔서 다시 클릭해 에러 메시지가 정상적으로 뜨는지도 확인 요청.

- [ ] **Step 2: 포트 정리 여부 확인**

라이브 테스트가 끝나면 계속 띄워져 있던 포트(3000/4000/5001, 그리고 8545)를 정리할지 사용자에게 확인한다.

## Self-Review

- **스펙 커버리지**: 스펙의 "포함" 목록(입력 필드+버튼, 클릭 핸들러, 자동 채움) 모두 Task 1에 매핑됨. "범위 밖"(백엔드 변경, 별도 페이지/인증 게이트)은 어느 태스크에서도 건드리지 않음 — Global Constraints에 명시.
- **플레이스홀더 검사**: 없음.
- **타입/이름 일관성**: `traceInputPkI`/`traceInputMaxHeight`/`traceTransaction`/`traceResult` id가 Step 1(HTML)과 Step 2/3(JS)에서 정확히 일치.
