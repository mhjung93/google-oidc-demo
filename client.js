const snapId = 'local:http://localhost:8081';

// Mode handling
const APP_MODE = window.APP_MODE || 1;
console.log(`[CLIENT] Running in Mode ${APP_MODE}`);

// Update UI with current mode
const modeDisplay = document.getElementById('modeDisplay');
if (modeDisplay) modeDisplay.innerText = APP_MODE;
const appTitle = document.getElementById('appTitle');
if (appTitle) appTitle.style.visibility = 'visible';

// --- Mode 2: Custom IdP Logic ---
if (APP_MODE === 2) {
  const mode2Section = document.getElementById('mode2Section');
  if (mode2Section) mode2Section.style.display = 'block';
  const snapSection = document.getElementById('snapSection');
  if (snapSection) snapSection.style.display = 'none';
  
  const mode2Status = document.getElementById('mode2Status');
  const mode2SSOLoginButton = document.getElementById('mode2SSOLoginButton');
  const mode2SSOSection = document.getElementById('mode2SSOSection');

  mode2SSOLoginButton?.addEventListener('click', async () => {
    let authWindowRef = null;
    const authWindowState = { navigated: false };
    try {
      authWindowRef = window.open('', '_blank');
      authWindowRef?.document.write('<p style="font-family: system-ui;">IdP 로그인 페이지를 준비하는 중입니다&hellip;</p>');
    } catch (err) {
      authWindowRef = null;
    }

    if (mode2SSOSection) mode2SSOSection.style.display = 'block';
    mode2SSOLoginButton.disabled = true;
    mode2Status.innerText = 'Preparing Snap connection...';

    try {
      if (!window.ethereum) throw new Error('MetaMask not found');
      await connectSnap();
      mode2Status.innerText = 'Step 2: Initializing wallet-side module...';
      // 사용자가 Snap 연결 팝업에서 실제로 클릭할 때까지 걸리는 시간은
      // 측정에서 제외하고, 승인 이후부터만 잰다. EOA account/address는
      // 선택하거나 공개하지 않는다; RP account continuity는 PPID로 처리한다.
      const start = now();
      mode2SessionNonce = createSessionNonce();

      const display = document.getElementById('ssoIntermediateDisplay');
      display.innerText = `Step 1. Delegated Login started ${formatMs(start)}.`;
      display.innerText += `\n\nStep 2. Initialize wallet-side module ${formatMs(start)}:\nSnap connected; no EOA account/address selected.`;
      display.innerText += `\n\nStep 3. RP FE session nonce created ${formatMs(start)}:\nsessionNonce: ${previewValue(mode2SessionNonce)}`;
      display.innerText += `\n\nStep 4. RP credential and RP nonce request sent ${formatMs(start)}.`;

      const requestBody = {
        sessionNonce: mode2SessionNonce,
        r_i: mode2SessionNonce,
        requestedAt: new Date().toISOString()
      };

      const res = await fetch('/api/mode2/rp_credential_nonce', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      });
      const data = await res.json();

      if (!res.ok || !data.success) {
        throw new Error(data.error || 'RP credential request failed');
      }

      ssoMetadata.rpCredential = data.rpCredential;
      ssoMetadata.sessionNonce = data.sessionNonce;
      ssoMetadata.r_i = data.r_i || data.sessionNonce;
      ssoMetadata.rpNonce = data.rpNonce;
      const sessionNonceCheck = data.sessionNonce === mode2SessionNonce;
      display.innerText += `\n\nStep 6. RP credential and nonce received ${formatMs(start)}:\nrpNonce: ${previewValue(data.rpNonce)}`;
      display.innerText += `\n\nStep 7. RP FE sends values to Wallet ${formatMs(start)}:\nrid: ${previewValue(data.rpCredential?.rid)}\nsignature: ${previewValue(data.rpCredential?.signature)}\nsessionNonce: ${previewValue(data.sessionNonce)}\nsessionNonce check: ${sessionNonceCheck}\nrpNonce: ${previewValue(data.rpNonce)}`;
      appendRpFeVisibleFlow(`Step 7. RP FE -> Wallet ${formatMs(start)}`);
      appendRpFeVisibleFlow(`  rid: ${previewValue(data.rpCredential?.rid)}`);
      appendRpFeVisibleFlow(`  r_i check: ${sessionNonceCheck ? 'PASS' : 'FAIL'}`);
      appendRpFeVisibleFlow(`  rpNonce: ${previewValue(data.rpNonce)}`);
      mode2Status.innerText = `Step 7 Complete ${formatMs(start)}. Values passed to wallet context.`;
      await runDelegatedLogin(authWindowRef, authWindowState);
    } catch (err) {
      if (!authWindowState.navigated) authWindowRef?.close();
      mode2SSOLoginButton.disabled = false;
      mode2Status.innerText = `Delegated Login Error: ${err.message}`;
    }
  });

  let mode2SessionNonce = null;
  let ssoMetadata = {
    userAddress: null,
    rid: null,
    rpNonceField: null,
    arid_i: null,
    auid: null,
    auid_i: null,
    pi_i: null,
    pi_PPID: null,
    step12Verified: false
  };

  // --- Timing Helpers ---
  function now() { return performance.now(); }
  function formatMs(start) { return `(${(now() - start).toFixed(0)} ms)`; }
  function formatDurationMs(durationMs) {
    if (durationMs == null || !Number.isFinite(Number(durationMs))) return 'n/a';
    return durationMs > 0 && durationMs < 1 ? '<1 ms' : `${Math.round(durationMs)} ms`;
  }
  function sumMeasuredDurations(durations) {
    return Object.values(durations)
      .filter((value) => value != null && Number.isFinite(Number(value)))
      .reduce((sum, value) => sum + Number(value), 0);
  }
  const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  function createSessionNonce() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return '0x' + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  }

  function valueToField(value) {
    if (typeof value === 'bigint') return value % FIELD_PRIME;
    if (typeof value === 'number') return BigInt(value) % FIELD_PRIME;
    const str = String(value);
    if (str.startsWith('0x')) return BigInt(str) % FIELD_PRIME;
    if (/^[0-9]+$/.test(str)) return BigInt(str) % FIELD_PRIME;
    const bytes = new TextEncoder().encode(str);
    const hex = bytesToHex(bytes);
    return BigInt(`0x${hex || '0'}`) % FIELD_PRIME;
  }

  function appendWalletLog(line) {
    if (!Array.isArray(ssoMetadata.walletLog)) ssoMetadata.walletLog = [];
    ssoMetadata.walletLog.push(line);
    console.log('[Wallet Step 8]', line);
  }

  function previewValue(value, maxChars = 48) {
    if (value === undefined || value === null) return 'n/a';
    const str = typeof value === 'string' ? value : JSON.stringify(value);
    return str.length > maxChars ? `${str.slice(0, maxChars)}...` : str;
  }

  function appendRpFeVisibleFlow(line) {
    const log = document.getElementById('rpFeVisibleFlowLog');
    if (!log) return;
    log.innerText += `${line}\n`;
  }

  const IDP_ORIGIN = 'http://127.0.0.1:4000';
  const PAIRCT_CLIENT_ID = 'pairct-wallet';
  const IDP_SSO_ENDPOINT = `${IDP_ORIGIN}/sso_with_credentials`;
  // Step 8 (PPID/arid_i/auid_i, signing key, pi_i/pi_PPID) runs in a local-only
  // Node process (wallet_agent.js), not in this RP page's JS context — see
  // wallet_agent.js for why (MetaMask Snap's SES sandbox can't run snarkjs/circomlibjs).
  const WALLET_AGENT_ORIGIN = 'http://127.0.0.1:5001';

  async function runDelegatedLogin(authWindowRef, authWindowState) {
    const start = now();
    mode2Status.innerText = 'Login job starting...';
    document.getElementById('authWindowFallback')?.replaceChildren();
    ssoMetadata.rid = BigInt(ssoMetadata.rpCredential.rid);
    ssoMetadata.rpNonceField = valueToField(ssoMetadata.rpNonce);

    const tokenRes = await fetch('/api/mode2/wallet_agent_token');
    if (!tokenRes.ok) throw new Error('Could not fetch wallet agent token. Is wallet_agent.js running?');
    const { token: walletAgentToken } = await tokenRes.json();

    const startRes = await fetch(`${WALLET_AGENT_ORIGIN}/startLogin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': walletAgentToken },
      body: JSON.stringify({
        rpCredential: ssoMetadata.rpCredential,
        r_i: ssoMetadata.r_i,
        rpNonce: ssoMetadata.rpNonce,
      }),
    });
    if (startRes.status !== 202) {
      const errData = await startRes.json().catch(() => ({}));
      throw new Error(errData.error || `/startLogin failed (${startRes.status})`);
    }
    const { jobId } = await startRes.json();

    let snapConfirmSent = false;
    let browserNavigated = false;
    const POLL_INTERVAL_MS = 1000;

    await new Promise((resolve, reject) => {
      const timer = setInterval(async () => {
        try {
          const statusRes = await fetch(`${WALLET_AGENT_ORIGIN}/loginStatus?jobId=${encodeURIComponent(jobId)}`);
          if (!statusRes.ok) {
            clearInterval(timer);
            reject(new Error(`/loginStatus failed (${statusRes.status})`));
            return;
          }
          const data = await statusRes.json();

          switch (data.status) {
            case 'generating_proof':
              mode2Status.innerText = `Step 8: 지갑이 증명을 생성하는 중입니다... ${formatMs(start)}`;
              return;

            case 'awaiting_wallet_approval':
              mode2Status.innerText = 'Snap에서 로그인 승인을 기다리는 중입니다...';
              if (snapConfirmSent) return;
              snapConfirmSent = true;
              try {
                const snapResult = await window.ethereum.request({
                  method: 'wallet_invokeSnap',
                  params: { snapId, request: { method: 'confirmLogin', params: {} } },
                });
                await fetch(`${WALLET_AGENT_ORIGIN}/confirmLoginResult`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ jobId, approved: Boolean(snapResult?.approved) }),
                });
              } catch (err) {
                snapConfirmSent = false; // Snap 호출/보고 자체가 실패하면 다음 tick에 재시도
                console.warn('[Mode 2] Snap confirmLogin failed:', err.message);
              }
              return;

            case 'awaiting_browser_login':
              if (!browserNavigated) {
                browserNavigated = true;
                navigateToIdP(authWindowRef, data.requestUri, authWindowState);
              }
              mode2Status.innerText = '시스템 브라우저에서 IdP 로그인을 진행해주세요.';
              return;

            case 'exchanging_token':
              mode2Status.innerText = '인증 코드를 토큰으로 교환하는 중입니다...';
              return;

            case 'done':
              clearInterval(timer);
              ssoMetadata.ppid = BigInt(data.ppid);
              ssoMetadata.arid_i = BigInt(data.arid_i);
              ssoMetadata.auid_i = BigInt(data.auid_i);
              ssoMetadata.pkI = data.pk_i;
              ssoMetadata.signingPublicKey = data.publicKeyHex;
              ssoMetadata.pi_PPID = data.pi_PPID;
              ssoMetadata.statement = data.statement;
              ssoMetadata.idpToken = data.idpToken;
              resolve();
              return;

            case 'denied':
              clearInterval(timer);
              reject(new Error('로그인이 거부되었습니다.'));
              return;

            case 'failed':
              clearInterval(timer);
              reject(new Error(data.error || '로그인에 실패했습니다.'));
              return;
          }
        } catch (err) {
          clearInterval(timer);
          reject(err);
        }
      }, POLL_INTERVAL_MS);
    });

    mode2Status.innerText = '로그인 완료. 결과를 검증하는 중입니다...';
    await runRpVerifyStatement(start);
  }

  function navigateToIdP(authWindowRef, requestUri, authWindowState) {
    const authorizeUrl = `${IDP_ORIGIN}/authorize?client_id=${PAIRCT_CLIENT_ID}&request_uri=${encodeURIComponent(requestUri)}`;
    if (authWindowRef && !authWindowRef.closed) {
      try {
        authWindowRef.location.href = authorizeUrl;
        authWindowState.navigated = true;
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

  async function runRpVerifyStatement(start) {
    const statement = ssoMetadata.statement;

    const ppidPublicSignals = ssoMetadata.pi_PPID?.publicSignals;
    const ridFromProof = ppidPublicSignals?.[0] != null ? BigInt(ppidPublicSignals[0]) : null;
    const ppidFromProof = ppidPublicSignals?.[1] != null ? BigInt(ppidPublicSignals[1]) : null;

    let piPpidOk = false;
    if (ssoMetadata.pi_PPID?.proof && Array.isArray(ppidPublicSignals) && ppidPublicSignals.length === 2) {
      try {
        const vkey = await getPiPpidVkey();
        piPpidOk = await snarkjs.groth16.verify(vkey, ppidPublicSignals, ssoMetadata.pi_PPID.proof);
      } catch (err) {
        console.warn('[Mode 2] pi_PPID ZKP verify error:', err.message);
      }
    }

    let ppidOk = false;
    let auidBindingOk = false;
    if (ridFromProof !== null && ppidFromProof !== null && ssoMetadata.rpNonceField != null) {
      ppidOk = String(ridFromProof) === String(ssoMetadata.rid);
      const recomputedAuidI = (ppidFromProof * ssoMetadata.rpNonceField) % FIELD_PRIME;
      auidBindingOk = String(statement?.auid_i) === String(recomputedAuidI);
    }

    const localChecksOk = auidBindingOk && ppidOk && piPpidOk;
    let rpBackendOk = false;
    let rpBackendMessage = localChecksOk ? 'not checked' : 'skipped because local checks failed';
    if (localChecksOk) {
      const res = await fetch('/api/mode2/verify_statement', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ statement, ppid: ssoMetadata.ppid.toString() }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        rpBackendOk = true;
        rpBackendMessage = 'PASS';
      } else {
        rpBackendMessage = data.error || 'RP backend verification failed';
      }
    }

    appendRpFeVisibleFlow('');
    appendRpFeVisibleFlow(`Statement 검증 ${formatMs(start)}`);
    appendRpFeVisibleFlow(`  auid_i / rp_nonce binding: ${auidBindingOk ? 'PASS' : 'FAIL'}`);
    appendRpFeVisibleFlow(`  rid binding: ${ppidOk ? 'PASS' : 'FAIL'}`);
    appendRpFeVisibleFlow(`  pi_PPID ZKP verification: ${piPpidOk ? 'PASS' : 'FAIL'}`);
    appendRpFeVisibleFlow(`  RP backend statement verification: ${rpBackendOk ? 'PASS' : 'FAIL'} (${rpBackendMessage})`);

    if (!localChecksOk || !rpBackendOk) {
      mode2Status.innerText = `로그인 검증 실패: ${rpBackendMessage}`;
      throw new Error(rpBackendMessage);
    }

    mode2Status.innerText = `로그인 성공 ${formatMs(start)}.`;
    const submitButton = document.getElementById('submitPPIDTransaction');
    if (submitButton) submitButton.disabled = false;
    const tracePkIInput = document.getElementById('traceInputPkI');
    const traceMaxHeightInput = document.getElementById('traceInputMaxHeight');
    if (tracePkIInput) tracePkIInput.value = ssoMetadata.pkI ?? '';
    if (traceMaxHeightInput) traceMaxHeightInput.value = statement?.max_height ?? '';
  }


  // pk_i/max_height는 이미 execute() calldata에 평문으로 들어가는 공개 온체인 값이라
  // (누구나 체인을 보면 알 수 있음), wallet_agent.js가 이 PPID의 PPIDWallet 앞으로
  // 온 execute() 호출들을 체인에서 직접 긁어와 돌려준다 — 서버의 private
  // sessionLog는 안 건드린다. 사용자가 드롭다운에서 고른 항목의 값만 추적 입력창에
  // 채워진다.
  // innerHTML 대신 textContent로만 옵션을 채운다 — err.message 등 신뢰할 수 없는
  // 문자열이 그대로 마크업으로 해석되는 걸 막기 위함.
  function setSelectMessage(select, text) {
    select.replaceChildren();
    const option = document.createElement('option');
    option.value = '';
    option.textContent = text;
    select.appendChild(option);
  }

  async function loadTransactionHistory() {
    const select = document.getElementById('traceHistorySelect');
    if (!select || !ssoMetadata.ppid) return;
    setSelectMessage(select, 'Loading...');
    try {
      const tokenRes = await fetch('/api/mode2/wallet_agent_token');
      if (!tokenRes.ok) throw new Error('Failed to obtain wallet agent token');
      const { token } = await tokenRes.json();

      const historyRes = await fetch('http://127.0.0.1:5001/transactionHistory', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Wallet-Agent-Token': token },
      });
      const result = await historyRes.json();
      if (!historyRes.ok) throw new Error(result.error || 'transactionHistory failed');

      if (!result.history || result.history.length === 0) {
        setSelectMessage(select, 'No transactions found yet');
        return;
      }
      select.replaceChildren();
      for (const entry of result.history) {
        const option = document.createElement('option');
        option.value = entry.txHash;
        option.textContent = `Block ${entry.blockNumber} - ${entry.txHash.slice(0, 10)}...`;
        option.dataset.pkI = entry.pk_i;
        option.dataset.maxHeight = entry.max_height;
        option.dataset.to = entry.to;
        select.appendChild(option);
      }
      select.dispatchEvent(new Event('change'));
    } catch (err) {
      setSelectMessage(select, `Error: ${err.message}`);
    }
  }

  document.getElementById('refreshTraceHistory')?.addEventListener('click', () => {
    loadTransactionHistory();
  });

  document.getElementById('traceHistorySelect')?.addEventListener('change', () => {
    const select = document.getElementById('traceHistorySelect');
    const selected = select.options[select.selectedIndex];
    const tracePkIInput = document.getElementById('traceInputPkI');
    const traceMaxHeightInput = document.getElementById('traceInputMaxHeight');
    const traceToInput = document.getElementById('traceInputTo');
    if (selected?.dataset.pkI && tracePkIInput) tracePkIInput.value = selected.dataset.pkI;
    if (selected?.dataset.maxHeight && traceMaxHeightInput) traceMaxHeightInput.value = selected.dataset.maxHeight;
    if (selected?.dataset.to && traceToInput) traceToInput.value = selected.dataset.to;
  });

  document.getElementById('submitPPIDTransaction')?.addEventListener('click', async () => {
    const resultEl = document.getElementById('ppidTxResult');
    resultEl.innerText = 'Preparing transaction...';
    const traceSection = document.getElementById('traceSection');
    if (traceSection) traceSection.style.display = 'block';
    loadTransactionHistory();
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
          business: {
            arid_i: ssoMetadata.arid_i.toString(),
            auid_i: ssoMetadata.auid_i.toString(),
            ppid: ssoMetadata.ppid.toString(),
            r_token: ssoMetadata.statement.r_token,
            chain_id: ssoMetadata.statement.chain_id,
            maxHeight: ssoMetadata.statement.max_height,
          },
          rpNonce: ssoMetadata.rpNonce,
          idpToken: ssoMetadata.idpToken,
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
      resultEl.innerText = `Transaction sent: ${executeTxHash}. Waiting for confirmation...`;
      // eth_sendTransaction만으로는 트랜잭션이 아직 블록에 안 올라갔을 수 있다 —
      // 여기서 바로 loadTransactionHistory()를 부르면(체인을 스캔해서 찾는 방식이라)
      // 아직 안 보일 수 있으므로, deploy 트랜잭션과 동일하게 영수증을 기다린 뒤에 갱신한다.
      let executeReceipt = null;
      while (!executeReceipt) {
        executeReceipt = await window.ethereum.request({
          method: 'eth_getTransactionReceipt',
          params: [executeTxHash],
        });
        if (!executeReceipt) await new Promise((resolve) => setTimeout(resolve, 1000));
      }
      resultEl.innerText = `Transaction sent: ${executeTxHash}`;
      loadTransactionHistory();
    } catch (err) {
      resultEl.innerText = `Error: ${err.message}`;
    }
  });

  document.getElementById('traceTransaction')?.addEventListener('click', async () => {
    const resultEl = document.getElementById('traceResult');
    resultEl.innerText = 'Tracing...';
    try {
      const to = document.getElementById('traceInputTo').value;
      if (!to) throw new Error('to (wallet address) is required');

      const traceRes = await fetch('/api/mode2/trace_transaction', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to }),
      });
      const traceResult = await traceRes.json();
      if (!traceRes.ok) throw new Error(traceResult.error || 'trace_transaction failed');

      const t = traceResult.timings ?? {};
      resultEl.innerText = `Traced uid: ${traceResult.uid} (username: ${traceResult.username ?? 'unknown'})\n` +
        `  auid_i lookup: ${t.auidILookupMs ?? 'n/a'} ms\n` +
        `  IdP lookup: ${t.idpLookupMs ?? 'n/a'} ms\n` +
        `  Total: ${t.totalMs ?? 'n/a'} ms`;
    } catch (err) {
      resultEl.innerText = `Error: ${err.message}`;
    }
  });

  let piPpidVkeyPromise = null;
  function getPiPpidVkey() {
    if (!piPpidVkeyPromise) {
      piPpidVkeyPromise = fetch('/build/mode2/pi_ppid_vkey.json').then((r) => r.json());
    }
    return piPpidVkeyPromise;
  }

  } // End APP_MODE === 2 block.

  // Dynamic import for ethers.js
  let ethers;

try {
  const ethersModule = await import(
    'https://cdn.jsdelivr.net/npm/ethers@6.16.0/dist/ethers.min.js'
  );
  ethers = ethersModule.ethers; // { ethers } named export
  console.log('ethers.js loaded successfully', ethers.version);
} catch (e) {
  console.error('Failed to load ethers.js module', e);
  throw e;
}


// ------------------------------
// Receipt polling helpers
// ------------------------------
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForReceipt(txHash, {
  pollIntervalMs = 1200,
  maxAttempts = 60,
  onTick = null,
} = {}) {
  if (!txHash || typeof txHash !== 'string') {
    throw new Error('waitForReceipt: txHash must be a string');
  }
  for (let i = 0; i < maxAttempts; i++) {
    const receipt = await window.ethereum.request({
      method: 'eth_getTransactionReceipt',
      params: [txHash],
    });
    if (onTick) onTick({ attempt: i + 1, receipt });
    if (receipt) return receipt;
    await sleep(pollIntervalMs);
  }
  throw new Error(`Transaction not mined after ${maxAttempts} attempts`);
}


// ------------------------------
// Wallet/Snap Connect & State
// ------------------------------
async function getSnaps() {
  return await window.ethereum.request({ method: 'wallet_getSnaps' });
}

async function isSnapConnected() {
  if (isSnapConnectedCache) return true; // Return cached status
  try {
    const snaps = await getSnaps();
    const isConnected = Object.keys(snaps).includes(snapId);
    isSnapConnectedCache = isConnected; // Update cache
    return isConnected;
  } catch (err) {
    console.warn('Failed to check snap connection status:', err);
    return false;
  }
}

async function connectSnap() {
  await window.ethereum.request({
    method: 'wallet_requestSnaps',
    params: { [snapId]: {} },
  });
  console.log('Snap connected successfully');
  isSnapConnectedCache = true;
}

// ------------------------------
// Logging
// ------------------------------
const statusP = document.getElementById('statusP');
function setStatus(msg) {
  if (statusP) statusP.innerText = msg;
  console.log('[STATUS]', msg);
}

function logRpcError(title, err) {
  console.error(title, err);
  const msg = err?.message || JSON.stringify(err);
  setStatus(`${title} ${msg}`);
}


// ------------------------------
// UI Elements & Listeners
// ------------------------------
const connectButton = document.getElementById('connectButton');
const helloButton = document.getElementById('helloButton');
const spendButton = document.getElementById('spendButton');
const sendProofButton = document.getElementById('sendProofButton');
const deployAndCallButton = document.getElementById('deployAndCallButton');
const sendT1withALButton = document.getElementById('sendT1withALButton');

const toAddressInput = document.getElementById('toAddress');      // input id="toAddress"
const proofUrlInput = document.getElementById('proofUrl'); // (optional) input id="proofUrl"

let accounts = [];
let isSnapConnectedCache = false; // Add this line

// Initial status check
(async () => {
  if (typeof window.ethereum === 'undefined') {
    setStatus('MetaMask not detected. Please install MetaMask.');
    if (connectButton) connectButton.disabled = true;
    return;
  }

  const connected = await isSnapConnected();
  if (connected) {
    updateUiAfterConnect();
  }
})();

function updateUiAfterConnect() {
  if (connectButton) connectButton.disabled = true;
  if (helloButton) helloButton.disabled = false;
  if (spendButton) spendButton.disabled = false;
  if (sendProofButton) sendProofButton.disabled = false;
  if (deployAndCallButton) deployAndCallButton.disabled = false;
  if (sendT1withALButton) sendT1withALButton.disabled = false;
  setStatus('Snap connected! Ready to test.');
}

// Connect Snap
connectButton?.addEventListener('click', async () => {
  try {
    await connectSnap();
    updateUiAfterConnect();
  } catch (err) {
    logRpcError('Connect error:', err);
  }
});

// 1) Say Hello (Simple RPC)
helloButton?.addEventListener('click', async () => {
  try {
    const result = await window.ethereum.request({
      method: 'wallet_invokeSnap',
      params: {
        snapId,
        request: { method: 'hello' },
      },
    });
    setStatus(`Snap result: ${result}`);
  } catch (err) {
    logRpcError('Hello error:', err);
  }
});

// 2) Spend (Standard Tx)
spendButton?.addEventListener('click', async () => {
  try {
    const target = toAddressInput?.value?.trim() || '0x0000000000000000000000000000000000000000';
    const txHash = await window.ethereum.request({
      method: 'eth_sendTransaction',
      params: [{
        from: (await window.ethereum.request({ method: 'eth_accounts' }))[0],
        to: target,
        value: '0x0', // 0 ETH
      }],
    });
    setStatus(`Tx sent: ${txHash}. Waiting for receipt...`);
    await waitForReceipt(txHash);
    setStatus(`Tx mined OK: ${txHash}`);
  } catch (err) {
    logRpcError('Spend error:', err);
  }
});

// JSON Loader
async function loadJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to load ${url}: ${res.statusText}`);
  return await res.json();
}

// Helper to get chainId and nonce for Snap
async function getTxContext(address) {
  const chainId = await window.ethereum.request({ method: 'eth_chainId' });
  const nonce = await window.ethereum.request({
    method: 'eth_getTransactionCount',
    params: [address, 'latest'],
  });
  return { chainId, nonce };
}

// 3) Send ZK Proof (Integrated with Snap)
sendProofButton?.addEventListener('click', async () => {
  try {
    setStatus('Preparing ZKP transaction...');

    const from = (await window.ethereum.request({ method: 'eth_accounts' }))[0];
    const txContext = await getTxContext(from);

    // 1. Fetch user data (sub, etc.) from RP server
    const res_user = await fetch('/api/id_token');
    if (!res_user.ok) {
      const errText = await res_user.text();
      throw new Error(`Failed to fetch user data: ${res_user.statusText} - ${errText}`);
    }
    const { claims } = await res_user.json();
    const sub = claims.sub;

    // 2. Encrypt sub for Auditor via RP server
    const res_encrypt = await fetch('/api/encrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plaintext: sub }),
    });
    if (!res_encrypt.ok) throw new Error(`Encryption failed: ${res_encrypt.statusText} - ${await res_encrypt.text()}`);
    const { ciphertext } = await res_encrypt.json();

    // 3. Load Proof from build/
    const proof = await loadJson(proofUrlInput?.value?.trim() || '/build/proof.json');
    const publicSignals = await loadJson('/build/public.json');
    const pseudonym_pk = {
      Ax: publicSignals[0],
      Ay: publicSignals[1],
    };

    // 4. Invoke Snap to wrap into transaction
    const target = toAddressInput?.value?.trim() || '0x0000000000000000000000000000000000000001';
    const resp = await window.ethereum.request({
      method: 'wallet_invokeSnap',
      params: {
        snapId,
        request: {
          method: 'zkp',
          params: {
            proof,
            publicSignals,
            ciphertext,
            attachMode: 'full',
            baseTx: {
              to: target,
              value: '0x0',
              gas: '0x50000',
            },
            txContext,
          },
        },
      },
    });

    if (!resp.tx) throw new Error('Snap did not return a transaction object.');
    
    // 5. Send transaction
    setStatus(`Submitting ZKP tx...`);
    const txHash = await window.ethereum.request({
      method: 'eth_sendTransaction',
      params: [resp.tx],
    });

    setStatus(`Proof tx sent: ${txHash}`);

    // Display summary of sent data
    const summary = `
      ZK Proof Transaction Sent!
      ------------------------------------
      Tx Hash: ${txHash}

      Encrypted 'sub' (Original Plaintext):
      ${sub}

      Pseudonym Public Key (Ax, Ay) from ZKP:
      Ax: ${pseudonym_pk.Ax}
      Ay: ${pseudonym_pk.Ay}

      Ciphertext (Hex, Encrypted 'sub' for Auditor):
      ${ciphertext}

      ZKP attachment (in accessList):
      mode: ${resp.attachment?.mode ?? 'n/a'}
      carrier: ${resp.attachment?.carrier ?? 'n/a'}
      payloadHash: ${resp.attachment?.payloadHash ?? 'n/a'}
    `;
    setStatus(summary);

  } catch (err) {
    logRpcError('SendProof error:', err);
    setStatus(`SendProof error: ${err?.message ?? err}`);
  }
});

// 4) Deploy, Call & Send ZKP
// This tests: 
// 1. Contract Deployment
// 2. Preparing a Function Call (calldata)
// 3. Wrapping both calldata + ZKP into one tx via Snap
deployAndCallButton?.addEventListener('click', async () => {
  try {
    setStatus('Step 1/4: Deploying Greeter contract...');
    
    // 1. Load Artifact
    const artifact = await loadJson('/artifacts/contracts/Greeter.sol/Greeter.json');
    const from = (await window.ethereum.request({ method: 'eth_accounts' }))[0];

    // 2. Deploy
    const deployTxHash = await window.ethereum.request({
      method: 'eth_sendTransaction',
      params: [{
        from,
        data: artifact.bytecode,
      }],
    });
    
    setStatus(`Deploy sent: ${deployTxHash}. Waiting...`);
    const deployReceipt = await waitForReceipt(deployTxHash);
    const contractAddress = deployReceipt.contractAddress;
    setStatus(`Greeter deployed at: ${contractAddress}`);

    // 3. Prepare 'setGreeting' call
    setStatus('Step 2/4: Preparing function call...');
    const iface = new ethers.Interface(artifact.abi);
    const greetingMsg = `Hello from ${from.slice(0,6)} at ${new Date().toLocaleTimeString()}`;
    const callData = iface.encodeFunctionData('setGreeting', [greetingMsg]);

    // 4. Prepare ZKP data (same as sendProofButton)
    setStatus('Step 3/4: Fetching ZKP data...');
    const res_user = await fetch('/api/id_token');
    const { claims } = await res_user.json();
    const sub = claims.sub;

    const res_encrypt = await fetch('/api/encrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plaintext: sub }),
    });
    const { ciphertext } = await res_encrypt.json();

    const proof = await loadJson('/build/proof.json');
    const publicSignals = await loadJson('/build/public.json');

    // 5. Wrap into single tx via Snap
    setStatus('Step 4/4: Wrapping into ZKP tx via Snap...');
    const txContext = await getTxContext(from);
    const resp = await window.ethereum.request({
      method: 'wallet_invokeSnap',
      params: {
        snapId,
        request: {
          method: 'zkp',
          params: {
            proof,
            publicSignals,
            ciphertext,
            attachMode: 'full',
            baseTx: {
              to: contractAddress,
              data: callData,
              value: '0x0',
              gas: '0x60000',
            },
            txContext,
          },
        },
      },
    });

    // 6. Send final bundled tx
    const txHash = await window.ethereum.request({
      method: 'eth_sendTransaction',
      params: [resp.tx],
    });

    setStatus(`Final bundled tx sent: ${txHash}`);
    const r = await waitForReceipt(txHash);
    if (r.status === 1 || r.status === '0x1') {
      setStatus(`✅ Final Tx Mined OK: ${txHash}`);
    } else {
      setStatus(`❌ Final Tx Mined but failed (status=${r.status}): ${txHash}`);
    }

  } catch (err) {
    logRpcError('Deploy/Call error:', err);
    setStatus(`Deploy/Call error: ${err?.message ?? err}`);
  }
});

// 5) Send T1 with AccessList (Pure ZKP attachment check)
sendT1withALButton?.addEventListener('click', async () => {
  try {
    setStatus('Preparing T1 AccessList transaction...');

    // 1. Get user and encrypted data
    const res_user = await fetch('/api/id_token');
    const { claims } = await res_user.json();
    const sub = claims.sub;

    const res_encrypt = await fetch('/api/encrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plaintext: sub }),
    });
    const { ciphertext } = await res_encrypt.json();

    // 2. Get Proof
    const proof = await loadJson('/build/proof.json');
    const publicSignals = await loadJson('/build/public.json');

    // 3. Invoke Snap with type 2 target
    const from = (await window.ethereum.request({ method: 'eth_accounts' }))[0];
    const txContext = await getTxContext(from);
    const resp = await window.ethereum.request({
      method: 'wallet_invokeSnap',
      params: {
        snapId,
        request: {
          method: 'zkp',
          params: {
            proof,
            publicSignals,
            ciphertext,
            attachMode: 'full',
            baseTx: {
              to: '0x0000000000000000000000000000000000000001',
              value: '0x0',
              gas: '0x50000',
            },
            txContext,
          },
        },
      },
    });

    // Basic validation of snap output
    if (!resp.tx || !resp.tx.to || !resp.tx.type || !resp.tx.gas) {
      throw new Error('Snap returned tx missing required fields (to/type/gas).');
    }
    if (!Array.isArray(resp.tx.accessList)) {
      throw new Error('Snap returned tx missing accessList array.');
    }

    // 4. Send
    const txHash = await window.ethereum.request({
      method: 'eth_sendTransaction',
      params: [resp.tx],
    });

    setStatus(`T1 AccessList tx sent: ${txHash}`);
    const r = await waitForReceipt(txHash);
    if (r.status === 1 || r.status === '0x1') {
      setStatus(`✅ T1 AccessList Mined OK: ${txHash}`);
    } else {
      setStatus(`❌ T1 AccessList failed: ${txHash}`);
    }
  } catch (err) {
    logRpcError('T1 AL error:', err);
    setStatus(`T1 AL error: ${err?.message ?? err}`);
  }
});
