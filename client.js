const snapId = 'local:http://localhost:8081';

// Mode handling
const APP_MODE = window.APP_MODE || 1;
console.log(`[CLIENT] Running in Mode ${APP_MODE}`);

// Import circomlibjs (BabyJubJub) via esm.sh CDN (Handles dependencies automatically)
let buildBabyjub;
let buildPoseidon;
try {
  const module = await import('https://esm.sh/circomlibjs@0.1.7');
  buildBabyjub = module.buildBabyjub;
  buildPoseidon = module.buildPoseidon;
  console.log('circomlibjs (BabyJubJub) loaded successfully via esm.sh');
} catch (err) {
  console.error('Failed to load circomlibjs via esm.sh:', err);
}

// Update UI with current mode
const modeDisplay = document.getElementById('modeDisplay');
if (modeDisplay) modeDisplay.innerText = APP_MODE;

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
    const start = now();
    if (mode2SSOSection) mode2SSOSection.style.display = 'block';
    mode2SSOLoginButton.disabled = true;
    mode2Status.innerText = 'Preparing Snap connection...';

    try {
      if (!window.ethereum) throw new Error('MetaMask not found');
      await connectSnap();
      prepareIdPLoginPopup();
      mode2Status.innerText = 'Step 2: Connecting wallet...';
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
      ssoMetadata.userAddress = accounts[0];
      mode2SessionNonce = createSessionNonce();

      const display = document.getElementById('ssoIntermediateDisplay');
      display.innerText = `Step 1. Delegated Login started.`;
      display.innerText += `\n\nStep 2. Connect Wallet:\nAddress: ${ssoMetadata.userAddress}`;
      display.innerText += `\n\nStep 3. RP FE session nonce created:\nsessionNonce: ${mode2SessionNonce}`;
      display.innerText += `\n\nStep 4. RP credential and RP nonce request sent.`;

      const requestBody = {
        walletAddress: ssoMetadata.userAddress,
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
      display.innerText += `\n\nStep 6. RP credential and nonce received ${formatMs(start)}:\nrpNonce: ${data.rpNonce}`;
      display.innerText += `\n\nStep 7. RP FE sends values to Wallet:\nclientId: ${data.rpCredential?.clientId}\nsignature: ${data.rpCredential?.signature}\nsessionNonce: ${data.sessionNonce}\nsessionNonce check: ${sessionNonceCheck}\nrpNonce: ${data.rpNonce}`;
      appendRpFeVisibleFlow('Step 7. RP FE -> Wallet');
      appendRpFeVisibleFlow(`  clientId: ${previewValue(data.rpCredential?.clientId)}`);
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
  let idpPopupWindow = null;
  let idpPopupReady = false;
  let mode2SessionNonce = null;
  let ssoMetadata = {
    userAddress: null,
    uid: 'user-unique-id-999', 
    rid: null,               
    r_RP: null,
    arid_i: null,
    auid: null,
    auid_i: null,
    pi_i: null,
    pi_PPID: null,
    pi_uid: null,
    salt_fixed: 'wallet-fixed-salt-888' 
  };

  // --- Timing Helpers ---
  function now() { return performance.now(); }
  function formatMs(start) { return `(${(now() - start).toFixed(0)} ms)`; }
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

  let babyJub = null;
  let F = null;

  // Initialize BabyJubJub (must be called before EC operations)
  async function initBabyJub() {
    if (babyJub) return;
    
    if (buildBabyjub) {
      babyJub = await buildBabyjub();
    } else if (window.circomlibjs && window.circomlibjs.buildBabyjub) {
      babyJub = await window.circomlibjs.buildBabyjub();
    } else {
      throw new Error('circomlibjs (buildBabyjub) not found. Please ensure internet access.');
    }
    
    F = babyJub.F;
    console.log('[Mode 2] BabyJubJub initialized successfully');
  }

  async function runWalletStep7() {
    const start = now();
    appendWalletLog('Step 8. Wallet started.');
    mode2Status.innerText = 'Step 8: Wallet is generating PPID, keys, token nonce, and ZKP...';

    try {
      await initBabyJub();
      if (!buildPoseidon) throw new Error('circomlibjs (buildPoseidon) not found.');
      const poseidon = await buildPoseidon();
      const poseidonF = poseidon.F;

      const uid = '12345';
      const walletSalt = ssoMetadata.salt_fixed;
      const ridPoint = babyJub.Base8;
      ssoMetadata.rid = { x: F.toObject(ridPoint[0]), y: F.toObject(ridPoint[1]) };

      const ppid = (
        valueToField(uid) *
        valueToField(ssoMetadata.rid.x) *
        valueToField(walletSalt)
      ) % FIELD_PRIME;
      ssoMetadata.ppid = ppid;
      appendWalletLog(`✓ PPID generated: ${ppid.toString().slice(0, 32)}...`);
      appendWalletLog('  formula: uid * rid * salt');
      appendWalletLog('  salt source: wallet internal value');

      const r_RP_bytes = ethers.randomBytes(31);
      ssoMetadata.r_RP = BigInt(ethers.hexlify(r_RP_bytes));
      const arid_i_point = babyJub.mulPointEscalar(ridPoint, ssoMetadata.r_RP);
      ssoMetadata.arid_i = { x: F.toObject(arid_i_point[0]), y: F.toObject(arid_i_point[1]) };
      appendWalletLog(`✓ arid_i generated: ${ssoMetadata.arid_i.x.toString().slice(0, 32)}...`);

      const auidPoint = babyJub.mulPointEscalar(babyJub.Base8, ppid);
      ssoMetadata.auid = { x: F.toObject(auidPoint[0]), y: F.toObject(auidPoint[1]) };
      const auid_i_point = babyJub.mulPointEscalar(auidPoint, ssoMetadata.r_RP);
      ssoMetadata.auid_i = { x: F.toObject(auid_i_point[0]), y: F.toObject(auid_i_point[1]) };
      appendWalletLog(`✓ auid_i generated: ${ssoMetadata.auid_i.x.toString().slice(0, 32)}...`);

      const signing = await createSigningKeyPair();
      ssoMetadata.signingKeyPair = signing.keyPair;
      ssoMetadata.signingPublicKey = signing.publicKeyHex;
      appendWalletLog(`✓ signing key pair generated. publicKey: ${signing.publicKeyHex.slice(0, 34)}...`);

      const heightInfo = await getMaxHeight();
      const maxHeight = heightInfo.maxHeight;
      ssoMetadata.currentBlock = heightInfo.currentBlock?.toString() ?? 'unavailable';
      ssoMetadata.maxHeight = maxHeight.toString();
      appendWalletLog(`✓ current block number: ${ssoMetadata.currentBlock}`);
      appendWalletLog(`✓ max_height set for 1 hour validity: ${ssoMetadata.maxHeight}`);
      appendWalletLog(`  height source: ${heightInfo.source}`);

      const tokenNonce = poseidonF.toObject(poseidon([
        signing.publicKeyField,
        valueToField(maxHeight),
        valueToField(ssoMetadata.rpNonce),
      ]));
      ssoMetadata.tokenNonce = tokenNonce;
      appendWalletLog(`✓ token nonce generated with Poseidon2(pk, max_height, RP nonce): ${tokenNonce.toString().slice(0, 32)}...`);

      const inputs = {
        r_RP: ssoMetadata.r_RP.toString(),
        rid_x: ssoMetadata.rid.x.toString(),
        rid_y: ssoMetadata.rid.y.toString(),
        auid_x: ssoMetadata.auid.x.toString(),
        auid_y: ssoMetadata.auid.y.toString(),
        arid_i_x: ssoMetadata.arid_i.x.toString(),
        arid_i_y: ssoMetadata.arid_i.y.toString(),
        auid_i_x: ssoMetadata.auid_i.x.toString(),
        auid_i_y: ssoMetadata.auid_i.y.toString()
      };

      appendWalletLog('• generating ZKP pi_i...');
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        inputs,
        "/build/mode2/pi_arid_i_js/pi_arid_i.wasm",
        "/build/mode2/pi_arid_i_final.zkey"
      );
      ssoMetadata.pi_i = proof;
      ssoMetadata.pi_PPID = {
        type: 'pi_PPID',
        ppid: ppid.toString(),
        auid: ssoMetadata.auid.x.toString(),
        r_token: tokenNonce.toString(),
        generatedAt: new Date().toISOString()
      };
      appendWalletLog(`✓ pi_PPID generated for PPID: ${ppid.toString().slice(0, 32)}...`);

      currentSSOProof = {
        zkpProof: proof,
        zkpPublicSignals: publicSignals,
        pi_i: proof,
        pi_PPID: ssoMetadata.pi_PPID,
        r_i: ssoMetadata.r_i,
        walletSubmission: {
          endpoint: IDP_SSO_ENDPOINT,
          auid_i: ssoMetadata.auid_i.x.toString(),
          arid_i: ssoMetadata.arid_i.x.toString(),
          r_token: tokenNonce.toString(),
          pi_i: proof,
          r_i: ssoMetadata.r_i
        },
        business: {
          sub: 'pending',
          ppid: ppid.toString(),
          arid_i: ssoMetadata.arid_i.x.toString(),
          auid_i: ssoMetadata.auid_i.x.toString(),
          r_i: ssoMetadata.r_i,
          r_token: tokenNonce.toString(),
          tokenNonce: tokenNonce.toString(),
          maxHeight: maxHeight.toString(),
          r_RP: ssoMetadata.r_RP.toString()
        }
      };

      appendWalletLog(`✓ pi_i generated ${formatMs(start)}. publicSignals[0]: ${publicSignals[0]}`);
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 8. Wallet generated PPID, arid_i, auid_i, signing key pair, r_token, pi_i, and pi_PPID ${formatMs(start)}.`;
      document.getElementById('step2SubmitToIdP').disabled = false;
      document.getElementById('step1GenerateZKPFail').disabled = false;
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

  document.getElementById('step0PrepMetadata')?.addEventListener('click', async () => {
    const start = now();
    mode2Status.innerText = 'Step 7: RP FE Calculating REAL arid_i (EC Mul)...';
    try {
      await initBabyJub();
      const res = await fetch('/api/mode2/rp_info');
      const rpInfo = await res.json();
      
      // 진짜 BabyJubJub 연산을 시작합니다.
      // 1. rid (Base Point로 가정)
      const rid_point = babyJub.Base8; 
      ssoMetadata.rid = { x: F.toObject(rid_point[0]), y: F.toObject(rid_point[1]) };

      // 2. r_RP (랜덤 스칼라)
      const r_RP_bytes = ethers.randomBytes(31); // 253비트 미만으로 안전하게 생성
      ssoMetadata.r_RP = BigInt(ethers.hexlify(r_RP_bytes));

      // 3. arid_i = rid * r_RP (진짜 타원곡선 곱셈!)
      const arid_i_point = babyJub.mulPointEscalar(rid_point, ssoMetadata.r_RP);
      ssoMetadata.arid_i = { x: F.toObject(arid_i_point[0]), y: F.toObject(arid_i_point[1]) };

      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 7. REAL EC Calculation Done:\narid_i.x: ${ssoMetadata.arid_i.x.toString().slice(0,20)}...`;
      
      document.getElementById('mode2WalletProofs').disabled = false;
      mode2Status.innerText = `Step 7 Complete ${formatMs(start)}. arid_i (EC Point) calculated.`;
    } catch (err) {
      mode2Status.innerText = `Step 7 Error: ${err.message}`;
    }
  });

  document.getElementById('mode2WalletProofs')?.addEventListener('click', async () => {
    const start = now();
    mode2Status.innerText = 'Step 8-9: Wallet Calculating REAL auid...';
    try {
      await initBabyJub();
      // auid도 진짜 타원곡선 점으로 생성 (데모용으로 Base8 * 12345n)
      const auid_point = babyJub.mulPointEscalar(babyJub.Base8, 12345n);
      ssoMetadata.auid = { x: F.toObject(auid_point[0]), y: F.toObject(auid_point[1]) };

      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 8-9. REAL EC Calculation Done:\nauid.x: ${ssoMetadata.auid.x.toString().slice(0,20)}...`;
      
      document.getElementById('step07RPFECalcAuidi').disabled = false;
      mode2Status.innerText = `Step 8-9 Complete ${formatMs(start)}. auid (EC Point) ready.`;
    } catch (err) {
      mode2Status.innerText = `Step 8-9 Error: ${err.message}`;
    }
  });

  document.getElementById('step07RPFECalcAuidi')?.addEventListener('click', async () => {
    const start = now();
    mode2Status.innerText = 'Step 10: RP FE Calculating REAL auid_i (EC Mul)...';
    try {
      await initBabyJub();
      const auid_point = [F.e(ssoMetadata.auid.x), F.e(ssoMetadata.auid.y)];
      
      // auid_i = auid * r_RP
      const auid_i_point = babyJub.mulPointEscalar(auid_point, ssoMetadata.r_RP);
      ssoMetadata.auid_i = { x: F.toObject(auid_i_point[0]), y: F.toObject(auid_i_point[1]) };

      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 10. REAL EC Calculation Done:\nauid_i.x: ${ssoMetadata.auid_i.x.toString().slice(0,20)}...`;
      
      document.getElementById('step1GenerateZKP').disabled = false;
      mode2Status.innerText = `Step 10 Complete ${formatMs(start)}. auid_i (EC Point) ready.`;
    } catch (err) {
      mode2Status.innerText = `Step 10 Error: ${err.message}`;
    }
  });

  document.getElementById('step1GenerateZKP')?.addEventListener('click', async () => {
    const start = now();
    mode2Status.innerText = 'Step 11: Generating HEAVY ZK Proof (pi_i)...';
    try {
      // pi_i 회로를 위한 진짜 입력값들
      const inputs = {
        r_RP: ssoMetadata.r_RP.toString(),
        rid_x: ssoMetadata.rid.x.toString(),
        rid_y: ssoMetadata.rid.y.toString(),
        auid_x: ssoMetadata.auid.x.toString(),
        auid_y: ssoMetadata.auid.y.toString(),
        arid_i_x: ssoMetadata.arid_i.x.toString(),
        arid_i_y: ssoMetadata.arid_i.y.toString(),
        auid_i_x: ssoMetadata.auid_i.x.toString(),
        auid_i_y: ssoMetadata.auid_i.y.toString()
      };

      console.log('[Mode 2] Proving HEAVY circuit pi_i (2x EC Mul)...');
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        inputs,
        "/build/mode2/pi_arid_i_js/pi_arid_i.wasm",
        "/build/mode2/pi_arid_i_final.zkey"
      );

      currentSSOProof = {
        zkpProof: proof,
        zkpPublicSignals: publicSignals,
        business: {
          sub: 'pending',
          arid_i: ssoMetadata.arid_i.x.toString(), // 데모용 식별자로 사용
          auid_i: ssoMetadata.auid_i.x.toString(),
          r_RP: ssoMetadata.r_RP.toString()
        }
      };
      
      ssoMetadata.pi_i = proof;
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 11. HEAVY ZKP (pi_i) Generated ${formatMs(start)}! (25k+ constraints)`;
      
      document.getElementById('step2SubmitToIdP').disabled = false;
      document.getElementById('step1GenerateZKPFail').disabled = false;
      mode2Status.innerText = `Step 11 Complete ${formatMs(start)}. Heavy ZKP ready.`;
    } catch (err) {
      mode2Status.innerText = `Step 11 Error: ${err.message}`;
    }
  });

  document.getElementById('step1GenerateZKPFail')?.addEventListener('click', async () => {
    mode2Status.innerText = 'SIMULATING ERROR: Tampering with Public Signals...';
    if (!currentSSOProof) return;
    
    // 증명은 그대로지만, 공개 신호 중 하나를 조작하여 검증 실패 유도
    if (currentSSOProof.zkpPublicSignals && currentSSOProof.zkpPublicSignals.length > 0) {
      currentSSOProof.zkpPublicSignals[0] = "9999999999"; 
    }
    
    document.getElementById('step15NotifyWallet').disabled = true;
    document.getElementById('step3CompleteRP').disabled = true;

    console.warn('[Mode 2] ZKP Public Signals Tampered. IdP will reject this.');
    document.getElementById('ssoIntermediateDisplay').innerText += `\n\n[FAIL TEST] Public Signals tampered! Submit now to see IdP rejection.`;
    mode2Status.innerText = 'Tampering complete. Now click Step 9 to see it FAIL.';
  });

  // Global helper for the popup to get current ZKP
  window.getPendingZKP = () => currentSSOProof;

  function openIdPLoginPopup() {
    const start = now();
    try {
      if (!currentSSOProof) throw new Error('Generate ZKP first');
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 9. Wallet sends auid_i, arid_i, r_token, and pi_i to IdP published endpoint:\n${IDP_SSO_ENDPOINT}`;
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
  mode2Status.innerText = 'Step 10: Verifying pi_i and IdP Token on Backend...';
  document.getElementById('step15NotifyWallet').disabled = true;
  document.getElementById('step3CompleteRP').disabled = true;

  try {
    if (!currentIdPToken) throw new Error('No IdP Token to verify');
    if (!currentSSOProof) throw new Error('No ZKP Proof found');

    // 서버가 기대하는 하이브리드 검증용 데이터 구조
    const requestBody = {
      idpToken: {
        ...currentIdPToken,
        signature_prime: currentIdPToken.signature, // 이름 통일
        rid: ssoMetadata.rid.x.toString(),
        exp: currentIdPToken.exp
      },
      zkpProof: currentSSOProof.zkpProof,
      zkpPublicSignals: {
        // pi_i 회로의 결과값 중 arid_i의 X, Y 좌표를 모두 추출합니다.
        P_commitment_x: currentSSOProof.zkpPublicSignals[4], // arid_i_x
        P_commitment_y: currentSSOProof.zkpPublicSignals[5]  // arid_i_y
      }

    };

    console.log('[Mode 2] Sending Hybrid Verify Request:', requestBody);

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
        console.log('[Mode 2] Step 10 SUCCESS. pi_i and IdP token verified. Activating Step 11 button...');
        
        const display = document.getElementById('ssoIntermediateDisplay');
        if (display) {
          display.style.color = '#2e7d32'; // 초록색
          display.innerText += `\n\n✅ Step 10. SUCCESS: pi_i verified and IdP token accepted by RP Backend.`;
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
      runWalletStep13();
      runWalletStep12().catch((err) => console.warn('[Mode 2] Step 12 skipped or failed:', err.message));
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
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 12. Wallet accepted IdP auth token without verification ${formatMs(start)}.`;
    } catch (err) {
      console.warn('[Mode 2] Step 12 Error:', err.message);
    }
  }

  function runWalletStep13() {
    if (step13Completed) return;
    if (!walletReceivedIdPToken) {
      console.warn('[Mode 2] Step 13 Error: Wallet has no IdP auth token');
      return;
    }
    if (!ssoMetadata.ppid || !ssoMetadata.pi_PPID) {
      console.warn('[Mode 2] Step 13 Error: Wallet has no PPID or pi_PPID');
      return;
    }

    appendRpFeVisibleFlow('');
    appendRpFeVisibleFlow('Step 13. Wallet -> RP FE');
    appendRpFeVisibleFlow(`  r_i check: ${ssoMetadata.r_i === mode2SessionNonce ? 'PASS' : 'FAIL'}`);
    appendRpFeVisibleFlow(`  auth token.sub: ${previewValue(walletReceivedIdPToken.sub)}`);
    appendRpFeVisibleFlow(`  auth token.exp: ${previewValue(walletReceivedIdPToken.exp)}`);
    appendRpFeVisibleFlow(`  auth token.signature: ${previewValue(walletReceivedIdPToken.signature?.sigma1, 36)}`);
    appendRpFeVisibleFlow(`  PPID: ${previewValue(ssoMetadata.ppid.toString())}`);
    appendRpFeVisibleFlow(`  pi_PPID: ${previewValue(ssoMetadata.pi_PPID)}`);
    step13Completed = true;
    runRPFeStep14();
  }

  function runRPFeStep14() {
    const token = walletReceivedIdPToken;
    const nowSec = Math.floor(Date.now() / 1000);
    const exp = Number(token?.exp ?? 0);
    const expireOk = Number.isFinite(exp) && exp > nowSec;
    const auidBindingOk = String(token?.auid_i) === String(ssoMetadata.auid_i?.x);
    const ppidOk = String(ssoMetadata.pi_PPID?.ppid) === String(ssoMetadata.ppid);
    const piPpidOk =
      ssoMetadata.pi_PPID?.type === 'pi_PPID' &&
      String(ssoMetadata.pi_PPID?.auid) === String(ssoMetadata.auid?.x) &&
      String(ssoMetadata.pi_PPID?.r_token) === String(ssoMetadata.tokenNonce);

    appendRpFeVisibleFlow('');
    appendRpFeVisibleFlow('Step 14. RP FE verifies Wallet submission');
    appendRpFeVisibleFlow('  IdP signature with public key: deferred in demo');
    appendRpFeVisibleFlow(`  expire time: ${expireOk ? 'PASS' : 'FAIL'} (exp: ${previewValue(token?.exp)})`);
    appendRpFeVisibleFlow(`  auid_i / r_RP binding: ${auidBindingOk ? 'PASS' : 'FAIL'}`);
    appendRpFeVisibleFlow(`  PPID binding: ${ppidOk ? 'PASS' : 'FAIL'}`);
    appendRpFeVisibleFlow(`  pi_PPID verification: ${piPpidOk ? 'PASS' : 'FAIL'}`);

    step14Result = {
      success: expireOk && auidBindingOk && ppidOk && piPpidOk,
      ppid: ssoMetadata.ppid?.toString(),
      r_i: ssoMetadata.r_i,
      r_i_check: ssoMetadata.r_i === mode2SessionNonce,
      checks: {
        expireOk,
        auidBindingOk,
        ppidOk,
        piPpidOk
      }
    };

    if (!expireOk || !auidBindingOk || !ppidOk || !piPpidOk) {
      console.warn('[Mode 2] Step 14 demo verification failed:', {
        expireOk,
        auidBindingOk,
        ppidOk,
        piPpidOk
      });
    }

    runRPFeStep15().catch((err) => console.warn('[Mode 2] Step 15 failed:', err.message));
  }

  async function runRPFeStep15() {
    if (!step14Result) throw new Error('Step 14 result is missing');

    await window.ethereum.request({
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
  }

  // --- Light ZKP (Poseidon Only) Flow ---

  document.getElementById('step0PrepMetadataLight')?.addEventListener('click', async () => {
    const start = now();
    mode2Status.innerText = 'Step 7 (Light): RP FE Preparing Nonce (No EC)...';
    try {
      ssoMetadata.r_RP = ethers.hexlify(ethers.randomBytes(16)); // 단순 랜덤 문자열
      ssoMetadata.arid_i = { light: `arid_light_${Math.random().toString(36).substring(7)}` };

      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 7 (Light). Raw value used (No EC).`;
      document.getElementById('mode2WalletProofsLight').disabled = false;
      mode2Status.innerText = `Step 7 (Light) Complete ${formatMs(start)}. No 타원곡선.`;
    } catch (err) {
      mode2Status.innerText = `Step 7 (Light) Error: ${err.message}`;
    }
  });

  document.getElementById('mode2WalletProofsLight')?.addEventListener('click', async () => {
    const start = now();
    mode2Status.innerText = 'Step 8-9 (Light): Wallet Preparing ID (No EC)...';
    try {
      ssoMetadata.auid = { light: `auid_light_999` };
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 8-9 (Light). Raw value used.`;
      document.getElementById('step07RPFECalcAuidiLight').disabled = false;
      mode2Status.innerText = `Step 8-9 (Light) Complete ${formatMs(start)}.`;
    } catch (err) {
      mode2Status.innerText = `Step 8-9 (Light) Error: ${err.message}`;
    }
  });

  document.getElementById('step07RPFECalcAuidiLight')?.addEventListener('click', async () => {
    const start = now();
    mode2Status.innerText = 'Step 10 (Light): RP FE Linking ID (No EC)...';
    try {
      ssoMetadata.auid_i = { light: `auid_i_light_comb` };
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 10 (Light). Linking done without EC.`;
      document.getElementById('step1GenerateZKPLight').disabled = false;
      mode2Status.innerText = `Step 10 (Light) Complete ${formatMs(start)}.`;
    } catch (err) {
      mode2Status.innerText = `Step 10 (Light) Error: ${err.message}`;
    }
  });

  document.getElementById('step1GenerateZKPLight')?.addEventListener('click', async () => {
    const start = now();
    mode2Status.innerText = 'Step 11 (Light): Generating FAST ZK Proof (pi_PPID)...';
    try {
      const psTokenStr = localStorage.getItem('mode2_ps_token');
      if (!psTokenStr) throw new Error('No PS Token found.');
      const psToken = JSON.parse(psTokenStr);
      
      // 타원곡선이 없는 매우 가벼운 Poseidon 회로 입력
      const inputs = {
        uid: "12345", // 실제로는 psToken.sub 등을 사용해야 함
        rid: "67890",
        salt: "111222",
        auid: "12329717125881324656859002801361718611351997041186147611354292512100725906895"
      };

      console.log('[Mode 2] Proving LIGHT circuit pi_PPID (Poseidon Only, with Public UID)...');
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        inputs,
        "/build/mode2/pi_auid_js/pi_auid.wasm",
        "/build/mode2/pi_auid_final.zkey"
      );

      currentSSOProof = {
        zkpProof: proof,
        zkpPublicSignals: publicSignals,
        pi_PPID: proof,
        business: {
          sub: psToken.sub,
          arid_i: "light_mode",
          auid_i: "light_mode",
          r_RP: "light_mode"
        },
        isLight: true // 서버에게 라이트 모드임을 알림
      };
      ssoMetadata.pi_PPID = proof;
      
      document.getElementById('ssoIntermediateDisplay').innerText += `\n\nStep 11 (Light). FAST ZKP Generated ${formatMs(start)}! (~200 constraints)`;
      document.getElementById('step2SubmitToIdP').disabled = false;
      mode2Status.innerText = `Step 11 (Light) Complete ${formatMs(start)}. 압도적인 속도!`;
    } catch (err) {
      mode2Status.innerText = `Step 16-17 Error: ${err.message}`;
    }
    });
    } // <--- 이 부분이 APP_MODE === 2 블록을 닫는 지점입니다.

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
