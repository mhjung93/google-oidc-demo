const snapId = 'local:http://localhost:8081';

// Mode handling
const APP_MODE = window.APP_MODE || 1;
console.log(`[CLIENT] Running in Mode ${APP_MODE}`);

// Import circomlibjs Poseidon via esm.sh CDN (Handles dependencies automatically)
let buildPoseidon;
try {
  const module = await import('https://esm.sh/circomlibjs@0.1.7');
  buildPoseidon = module.buildPoseidon;
  console.log('circomlibjs Poseidon loaded successfully via esm.sh');
} catch (err) {
  console.error('Failed to load circomlibjs via esm.sh:', err);
}

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
    if (mode2SSOSection) mode2SSOSection.style.display = 'block';
    mode2SSOLoginButton.disabled = true;
    mode2Status.innerText = 'Preparing Snap connection...';

    try {
      if (!window.ethereum) throw new Error('MetaMask not found');
      await connectSnap();
      prepareIdPLoginPopup();
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
      await runWalletStep7();
    } catch (err) {
      mode2SSOLoginButton.disabled = false;
      mode2Status.innerText = `Delegated Login Error: ${err.message}`;
    }
  });

  let currentSSOProof = null;
  let currentIdPToken = null; 
  let walletReceivedIdPToken = null;
  let step11Completed = false;
  let step13Completed = false;
  let step14Result = null;
  const measuredDurations = {};
  let idpPopupWindow = null;
  let idpPopupReady = false;
  let mode2SessionNonce = null;
  let ssoMetadata = {
    userAddress: null,
    uid: '12345',
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

  async function getOrCreateWalletSalt() {
    const result = await window.ethereum.request({
      method: 'wallet_invokeSnap',
      params: {
        snapId,
        request: {
          method: 'getOrCreateWalletSalt',
        },
      },
    });

    if (!result?.salt || typeof result.salt !== 'string') {
      throw new Error('Wallet salt is missing');
    }
    return result.salt;
  }

  const IDP_ORIGIN = 'http://127.0.0.1:4000';
  const IDP_SSO_ENDPOINT = `${IDP_ORIGIN}/sso_with_credentials`;

  function postProofToIdPPopup() {
    if (!currentSSOProof || !idpPopupWindow || idpPopupWindow.closed || !idpPopupReady) return false;
    idpPopupWindow.postMessage({ type: 'RP_SEND_ZKP', zkp: currentSSOProof }, IDP_ORIGIN);
    return true;
  }

  function prepareIdPLoginPopup() {
    idpPopupReady = false;
    idpPopupWindow = window.open(`${IDP_ORIGIN}/login_popup`, 'IdPLogin', 'width=500,height=600');
    if (!idpPopupWindow) {
      return false;
    }
    return true;
  }

  async function getCurrentHeightForValidation() {
    try {
      const blockHex = await window.ethereum.request({ method: 'eth_blockNumber' });
      return { value: BigInt(blockHex), source: 'eth_blockNumber' };
    } catch (err) {
      return {
        value: BigInt(Math.floor(Date.now() / 1000)),
        source: 'time-fallback',
        error: err.message
      };
    }
  }

  async function showWalletProcessSummary() {
    if (!window.ethereum || !Array.isArray(ssoMetadata.walletLog)) return;
    try {
      await window.ethereum.request({
        method: 'wallet_invokeSnap',
        params: {
          snapId,
          request: {
            method: 'walletProcessSummary',
            params: { lines: ssoMetadata.walletLog },
          },
        },
      });
    } catch (err) {
      console.warn('[Mode 2] Failed to show wallet processing in Snap:', err.message);
      mode2Status.innerText += ` Snap dialog skipped: ${err.message}`;
    }
  }

  async function createSigningKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
    const publicKeyHex = `0x${bytesToHex(publicKeyRaw)}`;
    return {
      keyPair,
      publicKeyHex,
      publicKeyField: valueToField(publicKeyHex),
    };
  }

  async function getMaxHeight() {
    try {
      const blockHex = await window.ethereum.request({ method: 'eth_blockNumber' });
      const currentBlock = BigInt(blockHex);
      return {
        currentBlock,
        maxHeight: currentBlock + 300n, // 1 hour at 12 seconds per block.
        source: 'eth_blockNumber',
      };
    } catch (err) {
      console.warn('[Mode 2] eth_blockNumber failed. Using time-based max_height fallback:', err.message);
      return {
        currentBlock: null,
        maxHeight: BigInt(Math.floor(Date.now() / 1000) + 3600),
        source: 'time-fallback',
        error: err.message,
      };
    }
  }

  async function runWalletStep7() {
    const start = now();
    let segmentStart = start;
    const step8Breakdown = [];
    const markStep8 = (label) => {
      const t = now();
      const durationMs = t - segmentStart;
      step8Breakdown.push({ label, durationMs });
      segmentStart = t;
      return durationMs;
    };
    appendWalletLog(`Step 8. Wallet started ${formatMs(start)}.`);
    mode2Status.innerText = 'Step 8: Wallet is generating PPID, keys, token nonce, and ZKP...';

    try {
      if (!buildPoseidon) throw new Error('circomlibjs (buildPoseidon) not found.');
      const poseidon = await buildPoseidon();
      const poseidonF = poseidon.F;
      markStep8('Poseidon init');

      const uidField = valueToField(ssoMetadata.uid);
      const walletSalt = await getOrCreateWalletSalt();
      const saltField = valueToField(walletSalt);
      // rid: IdP가 RP 등록 시 발급한 숫자 스칼라, 회로에서는 private input.
      const rid = BigInt(ssoMetadata.rpCredential.rid);
      ssoMetadata.rid = rid;

      const ppid = (uidField * rid * saltField) % FIELD_PRIME;
      ssoMetadata.ppid = ppid;
      appendWalletLog(`✓ PPID generated: ${ppid.toString().slice(0, 32)}...`);
      appendWalletLog('  formula: uid * rid * salt');
      appendWalletLog('  salt source: Snap-managed wallet secret');

      // rp_nonce (RP 서버가 발급한 값)가 블라인딩 스칼라 역할을 겸한다 — 별도의
      // 지갑 생성 r_RP는 더 이상 쓰지 않는다. 회로에서는 private input으로 숨겨진다.
      const rpNonceField = valueToField(ssoMetadata.rpNonce);
      ssoMetadata.rpNonceField = rpNonceField;

      const arid_i = (rid * rpNonceField) % FIELD_PRIME;
      ssoMetadata.arid_i = arid_i;
      appendWalletLog(`✓ arid_i generated: ${arid_i.toString().slice(0, 32)}...`);

      const auid_i = (ppid * rpNonceField) % FIELD_PRIME;
      ssoMetadata.auid_i = auid_i;
      appendWalletLog(`✓ auid_i generated: ${auid_i.toString().slice(0, 32)}...`);
      markStep8('PPID/arid_i/auid_i calculation');

      const signing = await createSigningKeyPair();
      ssoMetadata.signingKeyPair = signing.keyPair;
      ssoMetadata.signingPublicKey = signing.publicKeyHex;
      appendWalletLog(`✓ signing key pair generated. publicKey: ${signing.publicKeyHex.slice(0, 34)}...`);
      markStep8('Signing key pair generation');

      const heightInfo = await getMaxHeight();
      const maxHeight = heightInfo.maxHeight;
      ssoMetadata.currentBlock = heightInfo.currentBlock?.toString() ?? 'unavailable';
      ssoMetadata.maxHeight = maxHeight.toString();
      appendWalletLog(`✓ current block number: ${ssoMetadata.currentBlock}`);
      appendWalletLog(`✓ max_height set for 1 hour validity: ${ssoMetadata.maxHeight}`);
      appendWalletLog(`  height source: ${heightInfo.source}`);
      markStep8('Block height/max_height lookup');

      const maxHeightField = valueToField(maxHeight);
      const tokenNonce = poseidonF.toObject(poseidon([
        signing.publicKeyField,
        maxHeightField,
        rpNonceField,
      ]));
      ssoMetadata.tokenNonce = tokenNonce;
      appendWalletLog(`✓ token nonce generated with Poseidon2(pk, max_height, RP nonce): ${tokenNonce.toString().slice(0, 32)}...`);
      markStep8('Token nonce generation');

      const inputs = {
        rp_nonce: rpNonceField.toString(),
        salt: saltField.toString(),
        rid: rid.toString(),
        pk_i: signing.publicKeyField.toString(),
        uid: uidField.toString(),
        arid_i: arid_i.toString(),
        auid_i: auid_i.toString(),
        max_height: maxHeightField.toString(),
        token_nonce: tokenNonce.toString()
      };

      appendWalletLog('• generating ZKP pi_i...');
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        inputs,
        "/build/mode2/pi_arid_i_js/pi_arid_i.wasm",
        "/build/mode2/pi_arid_i_final.zkey"
      );
      ssoMetadata.pi_i = proof;
      markStep8('pi_i proof generation');

      appendWalletLog('• generating ZKP pi_PPID (proves rid was used in PPID; uid and salt stay hidden in pi_PPID)...');
      const ppidInputs = {
        uid: uidField.toString(),
        salt: saltField.toString(),
        rid: rid.toString(),
        ppid: ppid.toString()
      };
      const { proof: ppidProof, publicSignals: ppidPublicSignals } = await snarkjs.groth16.fullProve(
        ppidInputs,
        "/build/mode2/pi_ppid_js/pi_ppid.wasm",
        "/build/mode2/pi_ppid_final.zkey"
      );
      markStep8('pi_PPID proof generation');
      ssoMetadata.pi_PPID = {
        type: 'pi_PPID',
        proof: ppidProof,
        publicSignals: ppidPublicSignals, // [rid, ppid], per circuit's public [rid, ppid]
        r_token: tokenNonce.toString(),
        generatedAt: new Date().toISOString()
      };
      appendWalletLog(`✓ pi_PPID ZKP generated for PPID: ${ppid.toString().slice(0, 32)}...`);

      currentSSOProof = {
        zkpProof: proof,
        zkpPublicSignals: publicSignals,
        pi_i: proof,
        pi_PPID: ssoMetadata.pi_PPID,
        r_i: ssoMetadata.r_i,
        walletSubmission: {
          endpoint: IDP_SSO_ENDPOINT,
          auid_i: auid_i.toString(),
          arid_i: arid_i.toString(),
          r_token: tokenNonce.toString(),
          pi_i: proof,
          r_i: ssoMetadata.r_i
        },
        business: {
          uid: ssoMetadata.uid,
          arid_i: arid_i.toString(),
          auid_i: auid_i.toString(),
          r_i: ssoMetadata.r_i,
          r_token: tokenNonce.toString(),
          tokenNonce: tokenNonce.toString(),
          maxHeight: maxHeight.toString()
        }
      };

      ssoMetadata.step8DurationMs = now() - start;
      measuredDurations.step8 = ssoMetadata.step8DurationMs;
      ssoMetadata.step8Breakdown = step8Breakdown;
      appendWalletLog('Step 8 timing breakdown:');
      for (const item of step8Breakdown) {
        appendWalletLog(`  ${item.label}: ${Math.round(item.durationMs)} ms`);
      }
      appendWalletLog(`✓ pi_i generated ${formatMs(start)}. publicSignals[0]: ${publicSignals[0]}`);
      const breakdownText = step8Breakdown
        .map((item) => `  - ${item.label}: ${Math.round(item.durationMs)} ms`)
        .join('\n');
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 8. Wallet generated PPID, arid_i, auid_i, signing key pair, r_token, pi_i, and pi_PPID ${formatMs(start)}.\nStep 8 timing breakdown:\n${breakdownText}`;
      document.getElementById('step2SubmitToIdP').disabled = false;
      // Disabled for demo flow; keep showWalletProcessSummary() available for later.
      // await showWalletProcessSummary();
      openIdPLoginPopup();
    } catch (err) {
      appendWalletLog(`✗ Step 8 error: ${err.message}`);
      mode2Status.innerText = `Step 8 Error: ${err.message}`;
      // Disabled for demo flow; keep showWalletProcessSummary() available for later.
      // await showWalletProcessSummary();
    }
  }

  // Global helper for the popup to get current ZKP
  window.getPendingZKP = () => currentSSOProof;

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

  // Listen for message from IdP Popup
  window.addEventListener('message', (event) => {
    if (event.origin !== 'http://127.0.0.1:4000') return;

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
      document.getElementById('step25RPFEVerify').disabled = false;
      document.getElementById('step25RPFEVerifyFail').disabled = false;
      runStep10VerifyAndContinue();
    }
  });

  document.getElementById('step25RPFEVerifyFail')?.addEventListener('click', () => {
    if (!currentIdPToken || !currentIdPToken.signature) return;
    mode2Status.innerText = 'SIMULATING ERROR: Tampering with IdP PS Signature...';
    
    currentIdPToken.signature.sigma1 = 'f' + currentIdPToken.signature.sigma1.slice(1);
    document.getElementById('step15NotifyWallet').disabled = true;
    document.getElementById('step3CompleteRP').disabled = true;

    console.warn('[Mode 2] IdP PS Signature tampered. RP Backend will reject this.');
    document.getElementById('ssoIntermediateDisplay').innerText += `\n\n[FAIL TEST] PS Signature tampered! Submit now to see RP BE rejection.`;
    mode2Status.innerText = 'Tampering complete. Now click Step 10 to see it FAIL.';
  });

  document.getElementById('step2SubmitToIdP')?.addEventListener('click', async () => {
    openIdPLoginPopup();
  });
document.getElementById('step25RPFEVerify')?.addEventListener('click', async () => {
  await runStep10VerifyAndContinue();
});

async function runStep10VerifyAndContinue() {
  const start = now();
  mode2Status.innerText = 'Step 10: Verifying IdP Token and RP audience on Backend...';
  document.getElementById('step15NotifyWallet').disabled = true;
  document.getElementById('step3CompleteRP').disabled = true;

  try {
    if (!currentIdPToken) throw new Error('No IdP Token to verify');
    if (!currentSSOProof) throw new Error('No Wallet proof context found');

    // RP backend verifies only the IdP token signature and RP audience binding.
    // pi_i stays with the IdP; its public UID signal is not sent to the RP.
    const requestBody = {
      idpToken: {
        arid_i: currentIdPToken.arid_i,
        auid_i: currentIdPToken.auid_i,
        r_token: currentIdPToken.r_token,
        max_height: currentIdPToken.max_height,
        signature_prime: currentIdPToken.signature,
      }
    };

    console.log('[Mode 2] Sending RP Backend Verify Request:', {
      idpToken: {
        arid_i: previewValue(requestBody.idpToken.arid_i),
        auid_i: previewValue(requestBody.idpToken.auid_i),
        r_token: previewValue(requestBody.idpToken.r_token),
        max_height: requestBody.idpToken.max_height
      }
    });

    const res = await fetch('/api/mode2/sso_success', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody)
    });

      
      let data;
      const contentType = res.headers.get("content-type");
      if (contentType && contentType.indexOf("application/json") !== -1) {
        data = await res.json();
      } else {
        const text = await res.text();
        throw new Error(`Server Error: ${text.slice(0, 100)}...`);
      }

      console.log('[Mode 2] Server response received:', data);

      if (data.success) {
        console.log('[Mode 2] Step 10 SUCCESS. IdP token and RP audience verified. Activating Step 11 button...');
        
        const display = document.getElementById('ssoIntermediateDisplay');
        if (display) {
          display.style.color = '#2e7d32'; // 초록색
          display.innerText += `\n\n✅ Step 10. SUCCESS ${formatMs(start)}: IdP token signature and RP audience accepted by RP Backend.`;
        }
        
        document.getElementById('step15NotifyWallet').disabled = false;
        await runWalletStep11And12();
      } else {
        throw new Error(data.error || 'Verification failed at server');
      }
    } catch (err) {
      console.error('[Mode 2] Step 10 FAILED:', err.message);
      
      const display = document.getElementById('ssoIntermediateDisplay');
      if (display) {
        display.style.backgroundColor = '#ffebee'; // 옅은 빨간색 배경
        display.style.color = '#c62828'; // 짙은 빨간색 글씨
        display.innerText += `\n\n❌ Step 10. FAILED: ${err.message}\n[SECURITY ALERT] Unauthorized Access Attempt Blocked.`;
      }

      mode2Status.innerHTML = `<b style="color: red;">🚨 Step 10 ERROR: ${err.message}</b>`;
      
      // 다음 단계 버튼들 철저히 차단
      document.getElementById('step15NotifyWallet').disabled = true;
      document.getElementById('step3CompleteRP').disabled = true;
      
      window.alert(`🚨 Security Breach Blocked!\n\nReason: ${err.message}\n\nThe system has detected tampered data and halted the process.`);
    }
  }

  document.getElementById('step15NotifyWallet')?.addEventListener('click', async () => {
    await runWalletStep11And12();
  });

  document.getElementById('step3CompleteRP')?.addEventListener('click', async () => {
    await runWalletStep12();
  });

  async function runWalletStep11And12() {
    const start = now();
    try {
      if (!currentIdPToken) throw new Error('No IdP Token to send to Wallet');
      walletReceivedIdPToken = currentIdPToken;
      step11Completed = true;
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 11. IdP token sent to Wallet ${formatMs(start)}.`;
      document.getElementById('step3CompleteRP').disabled = false;
      // Step 12와 Step 13(→14→15)이 각각 snap_dialog를 띄우는데, MetaMask는 스냅 origin당
      // 다이얼로그를 하나만 허용하므로 동시에 실행하면 충돌한다. Step 12를 먼저 끝내고 진행한다.
      const step12Ok = await runWalletStep12().catch((err) => {
        console.warn('[Mode 2] Step 12 skipped or failed:', err.message);
        return false;
      });
      if (!step12Ok) {
        mode2Status.innerText = 'Step 12 failed. Wallet verification did not accept the IdP auth token.';
        return;
      }
      runWalletStep13();
    } catch (err) {
      console.warn('[Mode 2] Step 11 Error:', err.message);
      runWalletStep13();
    }
  }

  async function runWalletStep12() {
    const start = now();

    try {
      if (!step11Completed) throw new Error('Step 11 must complete before Step 12');
      if (!walletReceivedIdPToken) throw new Error('Wallet has no IdP auth token');

      const psPublicKeys = await fetch(`${IDP_ORIGIN}/ps_public_keys`).then((r) => r.json());
      const verification = await window.ethereum.request({
        method: 'wallet_invokeSnap',
        params: {
          snapId,
          request: {
            method: 'verifyIdPAuthToken',
            params: {
              idpToken: walletReceivedIdPToken,
              psPublicKeys,
              walletSubmission: currentSSOProof?.walletSubmission,
              business: currentSSOProof?.business
            },
          },
        },
      });

      ssoMetadata.step12DurationMs = verification?.durationMs ?? null;
      measuredDurations.step12 = verification?.durationMs ?? null;
      const elapsedText = verification?.durationMs != null
        ? `(${Math.round(verification.durationMs)} ms, excluding Snap confirmation)`
        : formatMs(start);
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 12. Wallet verified IdP auth token (PS signature): ${verification?.success ? 'PASS' : 'FAIL'} ${elapsedText}.`;
      ssoMetadata.step12Verified = Boolean(verification?.success);
      if (!ssoMetadata.step12Verified) {
        throw new Error(verification?.message || 'Wallet rejected IdP auth token');
      }
      return true;
    } catch (err) {
      console.warn('[Mode 2] Step 12 Error:', err.message);
      ssoMetadata.step12Verified = false;
      return false;
    }
  }

  function runWalletStep13() {
    const start = now();
    if (step13Completed) return;
    if (!walletReceivedIdPToken) {
      console.warn('[Mode 2] Step 13 Error: Wallet has no IdP auth token');
      return;
    }
    if (!ssoMetadata.step12Verified) {
      console.warn('[Mode 2] Step 13 blocked: Wallet did not verify IdP auth token');
      return;
    }
    if (!ssoMetadata.ppid || !ssoMetadata.pi_PPID) {
      console.warn('[Mode 2] Step 13 Error: Wallet has no PPID or pi_PPID');
      return;
    }

    appendRpFeVisibleFlow('');
    appendRpFeVisibleFlow(`Step 13. Wallet -> RP FE ${formatMs(start)}`);
    appendRpFeVisibleFlow(`  r_i check: ${ssoMetadata.r_i === mode2SessionNonce ? 'PASS' : 'FAIL'}`);
    appendRpFeVisibleFlow(`  auth token.uid: ${previewValue(walletReceivedIdPToken.uid)}`);
    appendRpFeVisibleFlow(`  auth token.rid: ${previewValue(walletReceivedIdPToken.rid)}`);
    appendRpFeVisibleFlow(`  auth token.max_height: ${previewValue(walletReceivedIdPToken.max_height)}`);
    appendRpFeVisibleFlow(`  auth token.r_token: ${previewValue(walletReceivedIdPToken.r_token)}`);
    appendRpFeVisibleFlow(`  auth token.signature: ${previewValue(walletReceivedIdPToken.signature?.sigma1, 36)}`);
    appendRpFeVisibleFlow(`  PPID: ${previewValue(ssoMetadata.ppid.toString())}`);
    appendRpFeVisibleFlow(`  pi_PPID: ${previewValue(ssoMetadata.pi_PPID)}`);
    step13Completed = true;
    runRPFeStep14().catch((err) => console.warn('[Mode 2] Step 14 failed:', err.message));
  }

  let piPpidVkeyPromise = null;
  function getPiPpidVkey() {
    if (!piPpidVkeyPromise) {
      piPpidVkeyPromise = fetch('/build/mode2/pi_ppid_vkey.json').then((r) => r.json());
    }
    return piPpidVkeyPromise;
  }

  async function runRPFeStep14() {
    const start = now();
    const token = walletReceivedIdPToken;
    const heightInfo = await getCurrentHeightForValidation();
    const maxHeight = token?.max_height != null ? BigInt(token.max_height) : null;
    const heightOk = maxHeight != null && heightInfo.value <= maxHeight;

    // pi_PPID is now a real Groth16 proof (circuits/pi_ppid.circom): it attests that
    // ppid = uid * rid * salt for some hidden uid/salt, with rid and ppid public.
    // Verify the proof itself, then read rid/ppid from its public signals (never
    // trust a plaintext claim) to check they bind to this RP and this IdP session.
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
      auidBindingOk = String(token?.auid_i) === String(recomputedAuidI);
    }

    appendRpFeVisibleFlow('');
    appendRpFeVisibleFlow(`Step 14. RP FE verifies Wallet submission ${formatMs(start)}`);
    appendRpFeVisibleFlow('  IdP PS signature: already verified by RP backend at Step 10 (verifyPS_Hybrid)');
    appendRpFeVisibleFlow(`  max_height: ${heightOk ? 'PASS' : 'FAIL'} (current: ${heightInfo.value.toString()}, max: ${previewValue(token?.max_height)}, source: ${heightInfo.source})`);
    appendRpFeVisibleFlow(`  auid_i / rp_nonce binding: ${auidBindingOk ? 'PASS' : 'FAIL'}`);
    appendRpFeVisibleFlow(`  rid binding: ${ppidOk ? 'PASS' : 'FAIL'}`);
    appendRpFeVisibleFlow(`  pi_PPID ZKP verification: ${piPpidOk ? 'PASS' : 'FAIL'}`);

    step14Result = {
      success: heightOk && auidBindingOk && ppidOk && piPpidOk,
      ppid: ppidFromProof != null ? ppidFromProof.toString() : null,
      r_i: ssoMetadata.r_i,
      r_i_check: ssoMetadata.r_i === mode2SessionNonce,
      step8DurationMs: ssoMetadata.step8DurationMs ?? null,
      step12DurationMs: ssoMetadata.step12DurationMs ?? null,
      checks: {
        expireOk: heightOk,
        heightOk,
        auidBindingOk,
        ppidOk,
        piPpidOk
      }
    };
    measuredDurations.step14 = now() - start;
    step14Result.step14DurationMs = measuredDurations.step14;

    if (!heightOk || !auidBindingOk || !ppidOk || !piPpidOk) {
      console.warn('[Mode 2] Step 14 demo verification failed:', {
        heightOk,
        auidBindingOk,
        ppidOk,
        piPpidOk
      });
    }

    runRPFeStep15().catch((err) => console.warn('[Mode 2] Step 15 failed:', err.message));
  }

  async function runRPFeStep15() {
    const start = now();
    if (!step14Result) throw new Error('Step 14 result is missing');

    const result = await window.ethereum.request({
      method: 'wallet_invokeSnap',
      params: {
        snapId,
        request: {
          method: 'rpAuthResult',
          params: {
            result: step14Result
          },
        },
      },
    });

    const measuredMs = result?.durationMs;
    measuredDurations.step15 = measuredMs ?? null;
    const measuredText = measuredMs != null
      ? `${formatDurationMs(measuredMs)} excluding Snap confirmation`
      : formatMs(start);
    appendRpFeVisibleFlow(`Step 15. Wallet notified ${measuredText}`);
    appendRpFeVisibleFlow(`Measured total excluding confirmation waits: ${formatDurationMs(sumMeasuredDurations(measuredDurations))}`);
    appendRpFeVisibleFlow(`  Step 8: ${formatDurationMs(measuredDurations.step8)}`);
    appendRpFeVisibleFlow(`  Step 12: ${formatDurationMs(measuredDurations.step12)}`);
    appendRpFeVisibleFlow(`  Step 14: ${formatDurationMs(measuredDurations.step14)}`);
    appendRpFeVisibleFlow(`  Step 15: ${formatDurationMs(measuredDurations.step15)}`);
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
