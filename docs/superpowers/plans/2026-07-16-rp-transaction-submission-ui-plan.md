# RP 페이지 트랜잭션 제출 UI 구현 계획

> **에이전트 작업자용:** 이 계획을 Task 단위로 실행하려면 superpowers:subagent-driven-development(추천) 또는 superpowers:executing-plans를 사용하세요. 각 단계는 체크박스(`- [ ]`) 문법으로 추적됩니다.

**목표:** Mode 2 로그인(Step 15) 완료 후, RP 페이지(`client.js`)에서 실제로 PPID 트랜잭션을 만들어 MetaMask로 온체인에 제출할 수 있게 한다.

**아키텍처:** `wallet_agent.js`의 `/submitTransaction`이 `PPIDWallet` 주소/현재 nonce를 RPC로 직접 조회하고 `execute()`(및 필요 시 배포) calldata까지 ABI 인코딩해서 반환하도록 바꾸고, `client.js`는 그 결과를 그대로 `window.ethereum.request({method:'eth_sendTransaction', ...})`에 넘기기만 한다.

**기술 스택:** `ethers`(이미 `wallet_agent.js`에 있음, `Interface`로 ABI 인코딩/디코딩), MetaMask `window.ethereum`(EIP-1193, 이미 `client.js`가 씀), 새 의존성 없음.

## 전역 제약사항

- `client.js`는 `PPIDWallet`/`PPIDWalletFactory`의 ABI를 몰라도 되게 한다 — 인코딩은 전부 `wallet_agent.js`가 한다.
- 받는 사람/금액은 데모용 고정값을 쓴다(사용자 입력 폼 없음).
- `circuits/pi_pk_i.circom`, `contracts/PPIDWallet.sol`, `contracts/PPIDWalletFactory.sol`, Snap(`snap/`)은 이 계획에서 수정하지 않는다.
- `PPIDWallet`이 아직 배포 안 됐을 수 있다 — `/submitTransaction`은 배포 필요 여부를 판단해서 응답에 포함시켜야 한다.
- 모든 필드 원소는 10진수 문자열로 주고받는다(hex 아님) — 기존 프로젝트 컨벤션.

---

## Task 1: `wallet_agent.js` — `/submitTransaction`을 ready-to-send calldata 반환으로 변경

**파일:**
- 수정: `wallet_agent.js`(import, 전역 설정, `/submitTransaction` 핸들러 전체)

**인터페이스:**
- 소비: 기존 `rpcCall()`, `getOrCreateSessionKey()`, `valueToField()`, `getIdpPublicKeys()`, `ensureEdDSA()`/`poseidon` — 전부 수정 없이 그대로 재사용
- 산출물: `POST /submitTransaction` 응답 형태 변경 — `{ deploy: {to, data} | null, to: string, data: string }` (기존 `payload`/`sig`/`proofA/B/C`/`pk_i`/`pk_IdP_x`/`pk_IdP_y`/`max_height` 필드는 응답에서 제거)
- 요청 본문 변경: `currentNonce` 필드 제거(더 이상 필요 없음 — 서버가 RPC로 직접 조회)

- [ ] **Step 1: import에 `Interface` 추가**

Find (`wallet_agent.js:11`):

```js
import { keccak256, AbiCoder } from 'ethers';
```

Replace with:

```js
import { keccak256, AbiCoder, Interface } from 'ethers';
```

- [ ] **Step 2: `PPID_WALLET_FACTORY_ADDRESS` 설정 + ABI Interface 전역 선언 추가**

Find (`wallet_agent.js:20`):

```js
const MODE2_ETH_RPC_URL = process.env.MODE2_ETH_RPC_URL || process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';
```

Replace with:

```js
const MODE2_ETH_RPC_URL = process.env.MODE2_ETH_RPC_URL || process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';
// B1 트랜잭션 제출(post-login) 대상 PPIDWalletFactory 주소. 지금까지는 이 정보를 아는
// 컴포넌트가 없었다(검증 스크립트가 임시로 수동 배포/전달했음) — 실제 온체인 제출을
// 하려면 이 값이 반드시 필요하다.
const PPID_WALLET_FACTORY_ADDRESS = process.env.PPID_WALLET_FACTORY_ADDRESS;

const PPID_WALLET_FACTORY_ABI = [
  'function computeAddress(uint256 ppid) view returns (address)',
  'function deploy(uint256 ppid) returns (address)',
];
const PPID_WALLET_ABI = [
  'function execute((address to, uint256 value, bytes data, uint256 nonce) payload, bytes sig, uint[2] proofA, uint[2][2] proofB, uint[2] proofC, uint256 pk_i, uint256 pk_IdP_x, uint256 pk_IdP_y, uint256 max_height) returns (bool ok)',
  'function nonce() view returns (uint256)',
];
const factoryInterface = new Interface(PPID_WALLET_FACTORY_ABI);
const walletInterface = new Interface(PPID_WALLET_ABI);
```

- [ ] **Step 3: `/submitTransaction` 핸들러 전체 교체**

Find (`wallet_agent.js:456-549`, 정확한 시작/끝 줄은 현재 파일에서 재확인 — `app.post('/submitTransaction', ...)`부터 그 라우트의 닫는 `});`까지 전체):

```js
app.post('/submitTransaction', async (req, res) => {
  const start = cursor();
  try {
    const { to, value, data, currentNonce, business, rpNonce } = req.body ?? {};
    if (!to) throw new Error('to is required');
    if (value === undefined) throw new Error('value is required');
    if (currentNonce === undefined) throw new Error('currentNonce is required');
    if (!business?.arid_i || !business?.auid_i) throw new Error('business.arid_i/auid_i are required');
    if (business?.PPID === undefined && business?.ppid === undefined) throw new Error('business.PPID/ppid is required');
    if (!rpNonce) throw new Error('rpNonce is required');

    await ensureEdDSA();
    if (!poseidon) throw new Error('Poseidon not initialized yet');

    const idpPublicKeys = await getIdpPublicKeys();
    const pkIdPRaw = idpPublicKeys?.pk_IdP;
    if (!pkIdPRaw || pkIdPRaw.length !== 2) throw new Error('IdP EdDSA public key not available');

    const idpTokenSig = req.body?.idpToken?.signature;
    if (!idpTokenSig?.R8 || !idpTokenSig?.S) throw new Error('idpToken.signature is required');

    const { sk_i, pk_i } = getOrCreateSessionKey();

    const payloadData = data ?? '0x';
    const payload = { to, value: value.toString(), data: payloadData, nonce: currentNonce.toString() };

    const payloadHash = keccak256(
      AbiCoder.defaultAbiCoder().encode(
        ['address', 'uint256', 'bytes', 'uint256'],
        [payload.to, payload.value, payload.data, payload.nonce],
      ),
    );
    const sigRaw = secp256k1.sign(payloadHash.slice(2), sk_i);
    const sig =
      '0x' +
      sigRaw.r.toString(16).padStart(64, '0') +
      sigRaw.s.toString(16).padStart(64, '0') +
      (27 + sigRaw.recovery).toString(16).padStart(2, '0');

    const rp_nonce = valueToField(rpNonce);
    const arid_i = valueToField(business.arid_i);
    const auid_i = valueToField(business.auid_i);
    const r_token = valueToField(business.r_token ?? business.tokenNonce);
    const chain_id = valueToField(business.chain_id ?? business.chainId);
    const maxHeightField = valueToField(business.maxHeight ?? business.max_height);

    const pkIdP_x = BigInt(pkIdPRaw[0]);
    const pkIdP_y = BigInt(pkIdPRaw[1]);

    const circuitInput = {
      rp_nonce: rp_nonce.toString(),
      arid_i: arid_i.toString(),
      auid_i: auid_i.toString(),
      r_token: r_token.toString(),
      chain_id: chain_id.toString(),
      S: idpTokenSig.S,
      R8x: idpTokenSig.R8[0],
      R8y: idpTokenSig.R8[1],
      pk_i: pk_i.toString(),
      pk_IdP_x: pkIdP_x.toString(),
      pk_IdP_y: pkIdP_y.toString(),
      PPID: valueToField(business.PPID ?? business.ppid).toString(),
      max_height: maxHeightField.toString(),
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      'build/mode2/pi_pk_i_js/pi_pk_i.wasm',
      'build/mode2/pi_pk_i_final.zkey',
    );
    const calldata = JSON.parse(`[${await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)}]`);
    const [proofA, proofB, proofC] = calldata;

    console.log(`[WalletAgent][submitTransaction] proof generated ${ms(start)}`);
    res.json({
      payload,
      sig,
      proofA,
      proofB,
      proofC,
      pk_i: pk_i.toString(),
      pk_IdP_x: pkIdP_x.toString(),
      pk_IdP_y: pkIdP_y.toString(),
      max_height: maxHeightField.toString(),
    });
  } catch (err) {
    console.error(`[WalletAgent][submitTransaction] error: ${err.message} ${ms(start)}`);
    res.status(400).json({ error: err.message });
  }
});
```

Replace with:

```js
app.post('/submitTransaction', async (req, res) => {
  const start = cursor();
  try {
    const { to, value, data, business, rpNonce } = req.body ?? {};
    if (!to) throw new Error('to is required');
    if (value === undefined) throw new Error('value is required');
    if (!business?.arid_i || !business?.auid_i) throw new Error('business.arid_i/auid_i are required');
    if (business?.PPID === undefined && business?.ppid === undefined) throw new Error('business.PPID/ppid is required');
    if (!rpNonce) throw new Error('rpNonce is required');
    if (!PPID_WALLET_FACTORY_ADDRESS) throw new Error('PPID_WALLET_FACTORY_ADDRESS not configured');

    await ensureEdDSA();
    if (!poseidon) throw new Error('Poseidon not initialized yet');

    const idpPublicKeys = await getIdpPublicKeys();
    const pkIdPRaw = idpPublicKeys?.pk_IdP;
    if (!pkIdPRaw || pkIdPRaw.length !== 2) throw new Error('IdP EdDSA public key not available');

    const idpTokenSig = req.body?.idpToken?.signature;
    if (!idpTokenSig?.R8 || !idpTokenSig?.S) throw new Error('idpToken.signature is required');

    const { sk_i, pk_i } = getOrCreateSessionKey();

    const ppidField = valueToField(business.PPID ?? business.ppid);

    // 대상 PPIDWallet의 CREATE2 주소를 factory에 직접 조회한다 — client.js는
    // 이 주소를 몰라도 된다.
    const computeAddressCalldata = factoryInterface.encodeFunctionData('computeAddress', [ppidField]);
    const computeAddressResult = await rpcCall('eth_call', [
      { to: PPID_WALLET_FACTORY_ADDRESS, data: computeAddressCalldata },
      'latest',
    ]);
    const [walletAddress] = factoryInterface.decodeFunctionResult('computeAddress', computeAddressResult);

    // PPIDWallet은 CREATE2로 지연 배포되므로, 아직 배포 안 됐을 수 있다(코드 없음).
    // 배포 안 됐으면 nonce는 0으로 간주하고, 응답에 배포 트랜잭션도 같이 실어보낸다 —
    // wallet_agent.js는 가스비를 낼 서명 키가 없어서(sk_i는 payload 서명 전용) 배포도
    // execute()와 마찬가지로 브라우저의 MetaMask가 보내야 한다.
    const walletCode = await rpcCall('eth_getCode', [walletAddress, 'latest']);
    const isDeployed = Boolean(walletCode) && walletCode !== '0x';

    let currentNonce = 0n;
    if (isDeployed) {
      const nonceCalldata = walletInterface.encodeFunctionData('nonce', []);
      const nonceResult = await rpcCall('eth_call', [{ to: walletAddress, data: nonceCalldata }, 'latest']);
      [currentNonce] = walletInterface.decodeFunctionResult('nonce', nonceResult);
    }

    const payloadData = data ?? '0x';
    const payload = { to, value: value.toString(), data: payloadData, nonce: currentNonce.toString() };

    const payloadHash = keccak256(
      AbiCoder.defaultAbiCoder().encode(
        ['address', 'uint256', 'bytes', 'uint256'],
        [payload.to, payload.value, payload.data, payload.nonce],
      ),
    );
    const sigRaw = secp256k1.sign(payloadHash.slice(2), sk_i);
    const sig =
      '0x' +
      sigRaw.r.toString(16).padStart(64, '0') +
      sigRaw.s.toString(16).padStart(64, '0') +
      (27 + sigRaw.recovery).toString(16).padStart(2, '0');

    const rp_nonce = valueToField(rpNonce);
    const arid_i = valueToField(business.arid_i);
    const auid_i = valueToField(business.auid_i);
    const r_token = valueToField(business.r_token ?? business.tokenNonce);
    const chain_id = valueToField(business.chain_id ?? business.chainId);
    const maxHeightField = valueToField(business.maxHeight ?? business.max_height);

    const pkIdP_x = BigInt(pkIdPRaw[0]);
    const pkIdP_y = BigInt(pkIdPRaw[1]);

    const circuitInput = {
      rp_nonce: rp_nonce.toString(),
      arid_i: arid_i.toString(),
      auid_i: auid_i.toString(),
      r_token: r_token.toString(),
      chain_id: chain_id.toString(),
      S: idpTokenSig.S,
      R8x: idpTokenSig.R8[0],
      R8y: idpTokenSig.R8[1],
      pk_i: pk_i.toString(),
      pk_IdP_x: pkIdP_x.toString(),
      pk_IdP_y: pkIdP_y.toString(),
      PPID: ppidField.toString(),
      max_height: maxHeightField.toString(),
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      'build/mode2/pi_pk_i_js/pi_pk_i.wasm',
      'build/mode2/pi_pk_i_final.zkey',
    );
    const calldata = JSON.parse(`[${await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)}]`);
    const [proofA, proofB, proofC] = calldata;

    const executeCalldata = walletInterface.encodeFunctionData('execute', [
      { to: payload.to, value: payload.value, data: payload.data, nonce: payload.nonce },
      sig,
      proofA,
      proofB,
      proofC,
      pk_i.toString(),
      pkIdP_x.toString(),
      pkIdP_y.toString(),
      maxHeightField.toString(),
    ]);

    const deploy = isDeployed
      ? null
      : {
          to: PPID_WALLET_FACTORY_ADDRESS,
          data: factoryInterface.encodeFunctionData('deploy', [ppidField]),
        };

    console.log(`[WalletAgent][submitTransaction] proof + calldata generated ${ms(start)}`);
    res.json({ deploy, to: walletAddress, data: executeCalldata });
  } catch (err) {
    console.error(`[WalletAgent][submitTransaction] error: ${err.message} ${ms(start)}`);
    res.status(400).json({ error: err.message });
  }
});
```

- [ ] **Step 4: 문법 검사**

Run: `node --check wallet_agent.js`
Expected: 에러 없음.

- [ ] **Step 5: 모듈 로드 확인**

Run: `PPID_WALLET_FACTORY_ADDRESS=0x0000000000000000000000000000000000000001 node -e "import('./wallet_agent.js')" 2>&1 | head -20`
Expected: Poseidon/EdDSA 초기화 로그 후 포트 5001에서 리슨 시작, 참조 에러 없음. (RPC 호출을 실제로 하는 부분은 이 스텝에서 검증 안 됨 — Task 3의 라이브 검증에서 확인.)

- [ ] **Step 6: 커밋**

```bash
git add wallet_agent.js
git commit -m "feat(mode2): /submitTransaction resolves wallet address/nonce via RPC, returns ready-to-send calldata"
```

---

## Task 2: `client.js` + `index.html` — "트랜잭션 보내기" 버튼

**파일:**
- 수정: `index.html`(버튼/결과 표시 엘리먼트 추가)
- 수정: `client.js`(버튼 활성화, 클릭 핸들러 추가)

**인터페이스:**
- 소비: Task 1의 `POST /submitTransaction` — 응답 `{ deploy: {to, data} | null, to: string, data: string }`
- 기존 `ssoMetadata.rpNonce`, `currentSSOProof.business`, `walletReceivedIdPToken`(이미 Step 8~12에서 채워짐), `/api/mode2/wallet_agent_token`(기존 토큰 발급 엔드포인트) 재사용

- [ ] **Step 1: `index.html`에 버튼/결과 영역 추가**

Find (`index.html`, `step15NotifyWallet` 버튼이 있는 블록 — 정확한 줄은 현재 파일에서 재확인):

```html
        <div style="margin-bottom: 5px;">
          <button id="step15NotifyWallet" style="background: #fffde7;" disabled>Step 11. Send IdP Token to Wallet</button>
        </div>
        <div style="margin-bottom: 5px;">
          <button id="step3CompleteRP" disabled>Step 12. Wallet: Verify IdP Auth Token</button>
        </div>
```

Replace with:

```html
        <div style="margin-bottom: 5px;">
          <button id="step15NotifyWallet" style="background: #fffde7;" disabled>Step 11. Send IdP Token to Wallet</button>
        </div>
        <div style="margin-bottom: 5px;">
          <button id="step3CompleteRP" disabled>Step 12. Wallet: Verify IdP Auth Token</button>
        </div>
        <div style="margin-bottom: 5px;">
          <button id="submitPPIDTransaction" style="background: #e1f5fe;" disabled>Send PPID Transaction</button>
        </div>
        <p id="ppidTxResult" style="font-size: 0.85em; color: #333; white-space: pre-wrap;"></p>
```

- [ ] **Step 2: 버튼 클릭 핸들러 등록**

Find (`client.js:443` 부근, `step15NotifyWallet`의 기존 리스너 등록 — 정확한 줄은 현재 파일에서 재확인):

```js
  document.getElementById('step15NotifyWallet')?.addEventListener('click', async () => {
```

바로 앞에(같은 스코프, `APP_MODE === 2` 블록 안) 다음을 추가:

```js
  document.getElementById('submitPPIDTransaction')?.addEventListener('click', async () => {
    const resultEl = document.getElementById('ppidTxResult');
    resultEl.innerText = 'Preparing transaction...';
    try {
      const tokenRes = await fetch('/api/mode2/wallet_agent_token');
      if (!tokenRes.ok) throw new Error('Failed to obtain wallet agent token');
      const { token } = await tokenRes.json();

      const submitRes = await fetch('http://127.0.0.1:5001/submitTransaction', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
        body: JSON.stringify({
          // 데모 고정값: 받는 사람/금액을 입력받는 폼은 이 기능 범위 밖.
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

      const [from] = await window.ethereum.request({ method: 'eth_requestAccounts' });

      if (submission.deploy) {
        resultEl.innerText = 'Deploying PPIDWallet (first use)...';
        const deployTxHash = await window.ethereum.request({
          method: 'eth_sendTransaction',
          params: [{ from, to: submission.deploy.to, data: submission.deploy.data }],
        });
        let receipt = null;
        while (!receipt) {
          receipt = await window.ethereum.request({
            method: 'eth_getTransactionReceipt',
            params: [deployTxHash],
          });
          if (!receipt) await new Promise((resolve) => setTimeout(resolve, 1000));
        }
      }

      resultEl.innerText = 'Sending transaction...';
      const executeTxHash = await window.ethereum.request({
        method: 'eth_sendTransaction',
        params: [{ from, to: submission.to, data: submission.data }],
      });
      resultEl.innerText = `Transaction sent: ${executeTxHash}`;
    } catch (err) {
      resultEl.innerText = `Error: ${err.message}`;
    }
  });

  document.getElementById('step15NotifyWallet')?.addEventListener('click', async () => {
```

- [ ] **Step 3: Step 15 완료 시 버튼 활성화**

Find (`client.js`, `runRPFeStep15()` 함수 끝부분 — 정확한 줄은 현재 파일에서 재확인):

```js
    appendRpFeVisibleFlow(`Measured total excluding confirmation waits: ${formatDurationMs(sumMeasuredDurations(measuredDurations))}`);
    appendRpFeVisibleFlow(`  Step 8: ${formatDurationMs(measuredDurations.step8)}`);
    appendRpFeVisibleFlow(`  Step 12: ${formatDurationMs(measuredDurations.step12)}`);
    appendRpFeVisibleFlow(`  Step 14: ${formatDurationMs(measuredDurations.step14)}`);
    appendRpFeVisibleFlow(`  Step 15: ${formatDurationMs(measuredDurations.step15)}`);
  }
```

Replace with:

```js
    appendRpFeVisibleFlow(`Measured total excluding confirmation waits: ${formatDurationMs(sumMeasuredDurations(measuredDurations))}`);
    appendRpFeVisibleFlow(`  Step 8: ${formatDurationMs(measuredDurations.step8)}`);
    appendRpFeVisibleFlow(`  Step 12: ${formatDurationMs(measuredDurations.step12)}`);
    appendRpFeVisibleFlow(`  Step 14: ${formatDurationMs(measuredDurations.step14)}`);
    appendRpFeVisibleFlow(`  Step 15: ${formatDurationMs(measuredDurations.step15)}`);
    const submitButton = document.getElementById('submitPPIDTransaction');
    if (submitButton) submitButton.disabled = false;
  }
```

- [ ] **Step 4: 문법 확인 (브라우저 스크립트라 `node --check` 대신 정적 확인)**

Run: `node --check client.js`
Expected: 에러 없음(브라우저 전용 API인 `window`/`document`가 있어도 `node --check`는 문법만 확인하므로 통과해야 함).

- [ ] **Step 5: 커밋**

```bash
git add index.html client.js
git commit -m "feat(mode2): add RP-page button to submit PPID transaction via MetaMask"
```

---

## Task 3: 엔드투엔드 라이브 검증

**파일:** 없음(검증만, 코드 변경 없음)

**중요:** 이 Task는 실제 브라우저 + MetaMask 확장 프로그램 조작이 필요해서 curl/스크립트로 자동화할 수 없다. 사용자의 직접 참여가 필요하다(EdDSA 마이그레이션 때의 Task 7, Snap 관련 이전 검증들과 동일한 성격).

- [ ] **Step 1: 환경 준비**

로컬 Hardhat 노드(`npx hardhat node`, 포트 8545) 기동. `PiPkIVerifier`/`PPIDWalletFactory` 배포(B1 Task 6이 이미 검증한 배포 절차 재사용) 후, 그 factory 주소를 기록.

`custom_idp.js`, `wallet_agent.js`(`PPID_WALLET_FACTORY_ADDRESS=<위에서 배포한 주소>` 환경변수와 함께), `server.js` 기동.

MetaMask 확장 프로그램에 Hardhat 로컬 네트워크(`http://127.0.0.1:8545`, chainId 1337 또는 31337)를 추가하고, Hardhat이 기본 제공하는 테스트 계정 중 하나(자금 있음)를 개인키로 임포트해서 연결.

- [ ] **Step 2: 로그인 + 트랜잭션 제출**

브라우저에서 `http://127.0.0.1:3000` 접속, Mode 2 로그인(Step 1~15) 진행. Step 15 완료 후 "Send PPID Transaction" 버튼이 활성화되는지 확인. 클릭 → MetaMask 승인 팝업(배포 필요하면 2번, 아니면 1번) → 승인 → 결과 텍스트에 tx hash 표시되는지 확인.

- [ ] **Step 3: 온체인 확인**

Hardhat 노드 로그 또는 `eth_getTransactionReceipt`로 트랜잭션이 성공(`status: 1`)했는지 확인. `0x000000000000000000000000000000000000dEaD` 주소의 잔액이 그대로(0 ETH 전송이므로)인지, `PPIDWallet`의 `nonce()`가 1 증가했는지 확인.

- [ ] **Step 4: 재사용 거부 확인**

같은 버튼을 다시 클릭(같은 세션, 새로 로그인 안 함) — `/submitTransaction`이 새 `nonce`로 다시 증명을 만들 것이므로 정상적으로 두 번째 트랜잭션도 성공해야 한다(nonce가 매번 새로 조회되므로 재사용 문제 없음). 이를 통해 nonce 자동 조회가 실제로 매번 최신값을 읽는지 확인.

- [ ] **Step 5: MetaMask 거부 케이스 확인**

버튼을 다시 클릭하고 MetaMask 승인 팝업에서 "거부(Reject)" 선택 → 결과 텍스트에 에러 메시지가 표시되고 페이지가 멈추거나 깨지지 않는지 확인.

- [ ] **Step 6: 정리**

기동한 프로세스(Hardhat 노드, `custom_idp.js`, `wallet_agent.js`, `server.js`) 종료, 포트 3000/4000/5001/8545 비어있는지 확인.

- [ ] **Step 7: ledger 갱신**

`.superpowers/sdd/progress.md`에 Task 3 결과 기록.
