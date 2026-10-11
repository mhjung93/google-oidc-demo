# PPIDWallet Sponsored (Paymaster) Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** RP 백엔드(`server.js`)가 로컬 Hardhat 노드의 unlock된 계정으로 PPIDWallet 트랜잭션을 대신 전송(gas sponsorship)할 수 있게 하고, RP 데모 페이지에 그 경로를 시연하는 버튼을 추가한다.

**Architecture:** `contracts/PPIDWallet.sol`은 `msg.sender`를 검사하지 않으므로 컨트랙트 변경 없이, `server.js`에 새 relay 엔드포인트만 추가한다. 이 엔드포인트는 실제 전송 전에 `eth_call`로 dry-run해서 잘못되거나 만료된 payload에 실제 gas를 쓰지 않도록 막고, 통과한 것만 로컬 Hardhat 기본 unlock 계정으로 `eth_sendTransaction`한다. `client.js`/`index.html`은 기존 MetaMask 버튼 옆에 새 버튼을 추가해서 같은 `wallet_agent.js` 응답을 이 엔드포인트로 대신 보낸다.

**Tech Stack:** 기존 Express(`server.js`)와 순정 `fetch`(JSON-RPC) 그대로 재사용. 새 의존성 없음, 새 private key 관리 없음(Hardhat 로컬 노드의 unlock 계정을 그대로 씀).

## Global Constraints

- `wallet_agent.js`, `contracts/PPIDWallet.sol`, `contracts/PPIDWalletFactory.sol`, `circuits/pi_pk_i.circom` — 전부 변경하지 않는다.
- 새 relayer용 private key를 도입하지 않는다 — 로컬 Hardhat 노드가 이미 unlock/펀딩해둔 계정(`eth_accounts`)만 쓴다.
- 실제 전송(`eth_sendTransaction`) 전에 반드시 `eth_call`로 dry-run해서, 실패할 트랜잭션에 실제 gas를 쓰지 않는다.
- relayer 남용 방지(rate limiting), gas 상환 메커니즘, 실체인용 private-key relayer는 이번 스코프에 포함하지 않는다 — 스펙(`docs/superpowers/specs/2026-07-20-ppidwallet-sponsored-execution-design.md`)의 "명시적으로 범위 밖" 목록 그대로.

---

### Task 1: `server.js`에 relay 엔드포인트 추가

**Files:**
- Modify: `server.js:209`(새 헬퍼 함수 2개 삽입 위치, `getRpcChainId()` 함수 바로 뒤), `server.js:754`(새 라우트 삽입 위치, `/api/mode2/trace_transaction` 라우트의 닫는 `});` 바로 뒤, `const server = app.listen(...)` 바로 앞)

**Interfaces:**
- Produces: `POST /api/mode2/relay_transaction` — 요청 본문 `{ deploy?: { to: string, data: string }, to: string, data: string }`, 성공 시 `200 { txHash: string }`, 실패 시 `400 { error: string }`.
- Produces (내부 헬퍼, Task 2에서는 안 씀): `rpcCall(method, params)` — 임의의 JSON-RPC 결과(문자열/배열/객체/null) 전부를 그대로 반환. `waitForReceipt(txHash)` — 영수증이 나올 때까지 1초 간격으로 폴링.

- [ ] **Step 1: `server.js`에 `rpcCall`/`waitForReceipt` 헬퍼 추가**

`server.js`에서 `getRpcChainId()` 함수(약 187-209행)의 닫는 `}` 바로 뒤에 다음을 추가한다:

```js

// wallet_agent.js의 rpcCall과 같은 패턴이지만, eth_accounts(배열)/eth_getTransactionReceipt(객체 또는
// null)처럼 문자열이 아닌 결과도 다뤄야 해서 결과 타입을 강제하지 않는다.
async function rpcCall(method, params = []) {
  const response = await fetch(MODE2_ETH_RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });

  if (!response.ok) {
    throw new Error(`${method} RPC failed with status ${response.status}`);
  }

  const data = await response.json();
  if (data.error) {
    throw new Error(data.error.message || `${method} RPC returned an error`);
  }
  return data.result;
}

async function waitForReceipt(txHash) {
  let receipt = null;
  while (!receipt) {
    receipt = await rpcCall('eth_getTransactionReceipt', [txHash]);
    if (!receipt) await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  return receipt;
}

// deploy/execute 공통: 실제 전송 전에 eth_call로 dry-run해서 revert할 payload에 실제 gas를
// 쓰지 않도록 막은 뒤, 통과하면 로컬 Hardhat의 기본 unlock 계정으로 전송하고 영수증을 기다린다.
async function relaySingleCall(from, { to, data }) {
  await rpcCall('eth_call', [{ from, to, data }, 'latest']);
  const txHash = await rpcCall('eth_sendTransaction', [{ from, to, data }]);
  await waitForReceipt(txHash);
  return txHash;
}
```

- [ ] **Step 2: `POST /api/mode2/relay_transaction` 라우트 추가**

`server.js`에서 `/api/mode2/trace_transaction` 라우트의 닫는 `});`(약 754행) 바로 뒤, `const server = app.listen(...)`(약 756행) 바로 앞에 다음을 추가한다:

```js

app.post('/api/mode2/relay_transaction', async (req, res) => {
  const { deploy, to, data } = req.body ?? {};
  if (!to) return res.status(400).json({ error: 'to is required' });
  if (!data) return res.status(400).json({ error: 'data is required' });
  if (deploy && (!deploy.to || !deploy.data)) {
    return res.status(400).json({ error: 'deploy.to and deploy.data are required when deploy is present' });
  }

  try {
    const accounts = await rpcCall('eth_accounts', []);
    const from = accounts?.[0];
    if (!from) throw new Error('No unlocked account available from RPC node');

    if (deploy) {
      await relaySingleCall(from, deploy);
    }
    const txHash = await relaySingleCall(from, { to, data });

    res.json({ txHash });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
```

- [ ] **Step 3: 구문 검사**

Run: `node --check server.js && echo OK`
Expected: `OK`

- [ ] **Step 4: 로컬 Hardhat 노드 대상 스모크 테스트 (컨트롤러 직접 실행)**

이 단계는 실제 로그인 흐름 없이도 `eth_accounts`/dry-run 거부 경로만 확인하는 것이라 컨트롤러가 직접 실행한다.
사용자에게 로컬 Hardhat 노드(`http://127.0.0.1:8545`)와 `server.js`가 이미 떠 있는지 확인부터 받는다. 떠 있으면:

```bash
curl -s -X POST http://localhost:3000/api/mode2/relay_transaction \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x000000000000000000000000000000000000dEaD","data":"0x12345678"}'
```

Expected: `400`과 함께 `{"error": "..."}` — 존재하지 않는 함수 셀렉터(`0x12345678`)를 대상 주소로 호출하려 하므로
`eth_call` dry-run 단계에서 거부된다(EOA 주소라 코드가 없어 실제로는 call 자체는 성공할 수도 있음 — 이 경우
`서버가 실제로 eth_sendTransaction까지 진행하는지`를 `curl -v`로 확인하고, 진행됐다면 Step 2의 대상 주소를
`PPIDWalletFactory`가 배포된 실제 PPIDWallet 미배포 주소로 바꿔서 재시도해서 `BadSignature`류의 revert로
거부되는지 확인한다). 실제 서명·증명은 Task 2의 라이브 검증에서 정상 경로로 확인한다.

- [ ] **Step 5: 커밋**

```bash
git add server.js
git commit -m "feat(mode2): add sponsored-execution relay endpoint for PPIDWallet

PPIDWallet.execute() never checks msg.sender - authorization is entirely
signature + pi_pk_i proof based - so a third party can already submit a
user's payload safely. Adds POST /api/mode2/relay_transaction, which
dry-runs via eth_call before spending real gas and then sends from the
local Hardhat node's unlocked default account, so client.js can offer a
gas-sponsored path alongside the existing MetaMask one. No contract,
wallet_agent.js, or circuit changes."
```

---

### Task 2: `client.js`/`index.html`에 "Send via Sponsor" 버튼 추가 + 라이브 검증

**Files:**
- Modify: `index.html:24-25`(새 버튼/결과 표시 영역 삽입), `client.js:456-507`(새 클릭 핸들러 삽입 위치, 기존 `submitPPIDTransaction` 핸들러 바로 뒤), `client.js:763-764`(새 버튼도 같이 활성화)

**Interfaces:**
- Consumes: Task 1의 `POST /api/mode2/relay_transaction` (`{ deploy?, to, data }` → `{ txHash }`), `wallet_agent.js`의 기존 `POST http://127.0.0.1:5001/submitTransaction`.

- [ ] **Step 1: `index.html`에 버튼과 결과 표시 영역 추가**

`index.html`에서 다음 줄(24-25행)을 찾는다:

```html
        <button id="submitPPIDTransaction" style="background: #e1f5fe;" disabled>Send PPID Transaction</button>
        <p id="ppidTxResult" style="font-size: 0.85em; color: #333; white-space: pre-wrap;"></p>
```

바로 뒤에 다음을 추가한다:

```html
        <button id="sponsorPPIDTransaction" style="background: #e1f5fe; margin-top: 6px;" disabled>Send via Sponsor</button>
        <p id="sponsorTxResult" style="font-size: 0.85em; color: #333; white-space: pre-wrap;"></p>
```

- [ ] **Step 2: `client.js`에 클릭 핸들러 추가**

`client.js`에서 `submitPPIDTransaction` 클릭 핸들러의 닫는 `});`(약 507행, `document.getElementById('traceTransaction')...` 바로 앞)
뒤에 다음을 추가한다:

```js

  document.getElementById('sponsorPPIDTransaction')?.addEventListener('click', async () => {
    const resultEl = document.getElementById('sponsorTxResult');
    resultEl.innerText = 'Preparing transaction...';
    try {
      const tokenRes = await fetch('/api/mode2/wallet_agent_token');
      if (!tokenRes.ok) throw new Error('Failed to obtain wallet agent token');
      const { token } = await tokenRes.json();

      const submitRes = await fetch('http://127.0.0.1:5001/submitTransaction', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
        body: JSON.stringify({
          to: '0x000000000000000000000000000000000000dEaD',
          value: '0',
          data: '0x',
          business: currentSSOProof?.business,
          rpNonce: ssoMetadata.rpNonce,
          idpToken: walletReceivedIdPToken,
        }),
      });
      const submission = await submitRes.json();
      if (!submitRes.ok) throw new Error(submission.error || 'submitTransaction failed');

      resultEl.innerText = 'Relaying via sponsor...';
      const relayRes = await fetch('/api/mode2/relay_transaction', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deploy: submission.deploy,
          to: submission.to,
          data: submission.data,
        }),
      });
      const relayResult = await relayRes.json();
      if (!relayRes.ok) throw new Error(relayResult.error || 'relay_transaction failed');

      resultEl.innerText = `Transaction sent (sponsored): ${relayResult.txHash}`;
    } catch (err) {
      resultEl.innerText = `Error: ${err.message}`;
    }
  });
```

- [ ] **Step 3: 로그인 완료 시 새 버튼도 같이 활성화**

`client.js`에서 다음 줄(약 763-764행)을 찾는다:

```js
    const submitButton = document.getElementById('submitPPIDTransaction');
    if (submitButton) submitButton.disabled = false;
```

바로 뒤에 다음을 추가한다:

```js
    const sponsorButton = document.getElementById('sponsorPPIDTransaction');
    if (sponsorButton) sponsorButton.disabled = false;
```

- [ ] **Step 4: 구문 검사**

Run: `node --check client.js && echo OK`
Expected: `OK`
(`index.html`은 JS가 아니므로 별도 구문 검사 불필요 — Step 5 라이브 검증에서 브라우저가 파싱 여부를 바로 드러냄.)

- [ ] **Step 5: 라이브 검증 (컨트롤러가 직접 실행, 서브에이전트에 위임하지 않음)**

실제 사용자 브라우저를 다루는 작업이라 매 단계 사용자 확인이 필요하다.

먼저 사용자에게 서버 재시작 필요 여부를 확인한다 — `server.js`/`client.js`/`index.html` 변경이므로 `server.js`
재시작이 필요하다(`wallet_agent.js`는 안 건드렸으므로 재시작 불필요, 컨트랙트/회로도 안 바꿨으므로 factory
재배포 불필요).

승인받으면:
```bash
pid=$(lsof -ti :3000 -sTCP:LISTEN); [ -n "$pid" ] && kill $pid
sleep 1
lsof -i :3000 -sTCP:LISTEN | tail -n +2
```
Expected: 빈 출력. 그 뒤 기존과 같은 방식으로 `server.js` 재시작.

브라우저에서 사용자에게 다음을 요청:
1. 로그인(Step 1-15) 완료 후 "Send via Sponsor" 버튼 클릭.
2. 첫 로그인(PPIDWallet 미배포 상태)이면 "Preparing transaction..." → "Relaying via sponsor..." 순서로
   메시지가 바뀌면서 최종적으로 `Transaction sent (sponsored): 0x...`가 뜨는지 확인 요청.
3. MetaMask 팝업이 전혀 뜨지 않는지(= 실제로 서버가 대신 보냈다는 증거) 확인 요청.
4. 이어서 "Send PPID Transaction"(MetaMask 경로)도 눌러서, 두 경로를 번갈아 써도 두 번째 트랜잭션이 정상
   성공하는지(= nonce가 서로 꼬이지 않는지) 확인 요청.

테스트가 끝나면 포트를 정리할지 사용자에게 확인한다.

## Self-Review

- **스펙 커버리지**: 스펙의 "포함" 목록(`server.js` relay 엔드포인트 + dry-run, `client.js`/`index.html` 버튼)이
  Task 1/Task 2에 각각 매핑됨. "범위 밖"(private-key relayer, gas 상환, rate limiting, 논문 문구 수정)은 어느
  Task에서도 건드리지 않음.
- **플레이스홀더 검사**: 없음.
- **타입/이름 일관성**: `rpcCall`/`waitForReceipt`/`relaySingleCall`(Task 1)과 `/api/mode2/relay_transaction`의
  요청/응답 모양(Task 2가 그대로 소비)이 두 Task에서 동일하게 쓰임.
