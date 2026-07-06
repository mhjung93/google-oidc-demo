// client.js (dApp)
// - Connect: requests accounts + requests snap permission for THIS origin (localhost:3000)
// - Hello: invokes snap hello
// - Spend: example tx from dApp (kept simple)
// - Send ZK Proof: invokes snap -> receives {tx} -> dApp sends eth_sendTransaction

const snapId = 'local:http://localhost:8081';

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
  throw new Error(`Timed out waiting for receipt: ${txHash}`);
}

function hexToInt(hex) {
  if (hex == null) return null;
  if (typeof hex === 'number') return hex;
  if (typeof hex !== 'string') return null;
  if (!hex.startsWith('0x')) return null;
  return parseInt(hex, 16);
}

function summarizeReceipt(receipt) {
  const status = receipt?.status;
  const blockNumber = receipt?.blockNumber;
  const gasUsed = receipt?.gasUsed;
  const effectiveGasPrice = receipt?.effectiveGasPrice;
  return {
    status,
    blockNumber,
    gasUsed,
    effectiveGasPrice,
    transactionHash: receipt?.transactionHash,
  };
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
  throw new Error(`Timed out waiting for receipt: ${txHash}`);
}

function hexToInt(hex) {
  if (hex == null) return null;
  if (typeof hex === 'number') return hex;
  if (typeof hex !== 'string') return null;
  if (!hex.startsWith('0x')) return null;
  return parseInt(hex, 16);
}

function summarizeReceipt(receipt) {
  const status = receipt?.status;
  const blockNumber = receipt?.blockNumber;
  const gasUsed = receipt?.gasUsed;
  const effectiveGasPrice = receipt?.effectiveGasPrice;
  return {
    status,
    blockNumber,
    gasUsed,
    effectiveGasPrice,
    transactionHash: receipt?.transactionHash,
  };
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
  throw new Error(`Timed out waiting for receipt: ${txHash}`);
}

function hexToInt(hex) {
  if (hex == null) return null;
  if (typeof hex === 'number') return hex;
  if (typeof hex !== 'string') return null;
  if (!hex.startsWith('0x')) return null;
  return parseInt(hex, 16);
}

function summarizeReceipt(receipt) {
  const status = receipt?.status;
  const blockNumber = receipt?.blockNumber;
  const gasUsed = receipt?.gasUsed;
  const effectiveGasPrice = receipt?.effectiveGasPrice;
  return {
    status,
    blockNumber,
    gasUsed,
    effectiveGasPrice,
    transactionHash: receipt?.transactionHash,
  };
}

// ---- DOM helpers (IDs must match your index.html) ----
const connectButton = document.getElementById('connectButton');
const helloButton = document.getElementById('helloButton');
const spendButton = document.getElementById('spendButton');
const sendProofButton = document.getElementById('sendProofButton');
const statusP = document.getElementById('statusP');

const toInput = document.getElementById('toAddress');      // input id="toAddress"
const proofUrlInput = document.getElementById('proofUrl'); // (optional) input id="proofUrl"

let accounts = [];
let isSnapConnectedCache = false; // Add this line

async function isSnapConnected() {
  if (!window.ethereum) return false;
  if (isSnapConnectedCache) return true; // Use cache to avoid repeated calls

  try {
    const snaps = await window.ethereum.request({ method: 'wallet_getSnaps' });
    const isConnected = Object.keys(snaps).includes(snapId);
    isSnapConnectedCache = isConnected; // Update cache
    return isConnected;
  } catch (err) {
    console.warn('Failed to check snap connection status:', err);
    return false;
  }
}

async function getExternalReceiverAddress(accounts) {
    // 1) If you have an input box, prefer it when filled
    const input = document.getElementById('toAddress');
    if (input && input.value.trim()) {
      return input.value.trim();
    }
  
    // 2) Else load the receiver address generated by run_all.sh
    try {
      const r = await fetch('/build/receiver.json');
      if (r.ok) {
        const j = await r.json();
        if (j && typeof j.to === 'string' && j.to.startsWith('0x')) {
          return j.to;
        }
      }
    } catch (e) {
      // ignore
    }
  
    // 3) Fallback (must NOT be a MetaMask internal account)
    return '0x1000000000000000000000000000000000000001';
  }
  
  function assertNotInternal(to, accounts) {
    const lower = (s) => (s || '').toLowerCase();
    if (accounts.some((a) => lower(a) === lower(to))) {
      throw new Error(
        'Destination is a MetaMask internal account. Pick an address NOT in your wallet for data-carrying tx.'
      );
    }
  }
  
function logRpcError(prefix, err) {
  const msg = err?.data?.originalError?.message || err?.message || err;
  console.error(prefix, msg, err);
}
function logRpcError(prefix, err) {
  const msg = err?.data?.originalError?.message || err?.message || err;
  console.error(prefix, msg, err);
}
function logRpcError(prefix, err) {
  const msg = err?.data?.originalError?.message || err?.message || err;
  console.error(prefix, msg, err);
}

function setStatus(msg) {
  if (statusP) statusP.innerText = msg;
  console.log(msg);
}

function requireEthereum() {
  if (!window.ethereum) {
    throw new Error('MetaMask not found. Please use MetaMask Flask for Snaps.');
  }
}

async function requestSnapPermission() {
  requireEthereum();
  if (!(await isSnapConnected())) { // Only request if not already connected
    await window.ethereum.request({
      method: 'wallet_requestSnaps',
      params: { [snapId]: {} },
    });
    isSnapConnectedCache = true; // Update cache after successful request
  }
}

async function invokeSnap(request) {
  // 권한이 없으면 invoke가 막히므로 항상 보장
  await requestSnapPermission();

  return await window.ethereum.request({
    method: 'wallet_invokeSnap',
    params: { snapId, request },
  });
}

async function loadJson(defaultUrl, optionalUrl) {
  const candidates = [];
  if (optionalUrl) {
    candidates.push(optionalUrl);
  }
  candidates.push(defaultUrl);

  for (const url of candidates) {
    try {
      const res = await fetch(url, { cache: 'no-store' });
      if (res.ok) {
        console.log(`Successfully loaded JSON from ${url}`);
        return await res.json();
      }
    } catch (e) {
      // try next
    }
  }
  throw new Error(`Cannot find or load JSON. Tried: ${candidates.join(', ')}`);
}

function getToAddress() {
  const to = (toInput && toInput.value.trim()) || '';
  if (!to) {
    throw new Error('Missing destination address. Fill #toAddress input.');
  }
  return to;
}

// ---- UI init ----
if (helloButton) helloButton.disabled = true;
if (spendButton) spendButton.disabled = true;
if (sendProofButton) sendProofButton.disabled = true;

// ---- Connect ----
connectButton?.addEventListener('click', async () => {
  try {
    requireEthereum();

    accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    if (!accounts?.length) throw new Error('No accounts returned');

    // ✅ 핵심: 이 origin(3000)에 snap 권한 부여/설치
    await requestSnapPermission();

    // ✅ toAddress 자동 채우기: 2번째 계정이 있으면 그걸, 없으면 자기 자신
    if (toInput && !toInput.value.trim()) {
        //toInput.value = accounts[1] ?? accounts[0];
        toInput.value = await getExternalReceiverAddress(accounts);
    }
  
    setStatus(`Connected: ${accounts[0]}`);
    if (helloButton) helloButton.disabled = false;
    if (spendButton) spendButton.disabled = false;
    if (sendProofButton) sendProofButton.disabled = false;
  } catch (err) {
    console.error(err);
    setStatus(`Connect error: ${err?.message ?? err}`);
  }
});

// ---- Hello ----
helloButton?.addEventListener('click', async () => {
  try {
    const resp = await invokeSnap({ method: 'hello' });
    console.log('hello resp:', resp);
    setStatus(`hello done (resp=${JSON.stringify(resp)})`);
  } catch (err) {
    console.error(err);
    setStatus(`hello error: ${err?.message ?? err}`);
  }
});

// ---- Spend (example) ----
spendButton?.addEventListener('click', async () => {
  try {
    requireEthereum();
    if (!accounts?.length) throw new Error('Connect first');

    const to = getToAddress();

    // 아주 단순한 tx 예시 (value=0)
    const txHash = await window.ethereum.request({
      method: 'eth_sendTransaction',
      params: [
        {
          from: accounts[0],
          to,
          value: '0x0',
        },
      ],
    });

    setStatus(`Spend tx sent: ${txHash}`);
  } catch (err) {
    console.error(err);
    setStatus(`Spend error: ${err?.message ?? err}`);
  }
});

// ---- Send ZK Proof ----
sendProofButton?.addEventListener('click', async () => {
  try {
    setStatus('Starting ZK Proof process...');
    requireEthereum();
    if (!accounts?.length) throw new Error('Connect first');

    // 1. Fetch ZK proof and public signals
    setStatus('Loading proof and public signals...');
    const proof = await loadJson('/build/proof.json', proofUrlInput.value.trim());
    const publicSignals = await loadJson('/build/public.json');
    
    const pseudonym_pk = {
      Ax: publicSignals[0],
      Ay: publicSignals[1],
    };
    console.log('Proof and public key loaded:', { proof, pseudonym_pk });

    // 2. Fetch 'sub' claim from server-side session
    setStatus('Fetching user data (sub)...');
    const res_user = await fetch('/api/id_token');
    if (!res_user.ok) {
      const resp = await res_user.text();
      throw new Error(`Failed to fetch user data: ${res_user.statusText} - ${resp}`);
    }
    const { claims } = await res_user.json();
    if (!claims?.sub) {
      throw new Error('"sub" claim not found in user data.');
    }
    const sub = claims.sub;
    console.log('User "sub" claim fetched:', sub);

    // 3. Encrypt the 'sub' claim for the auditor
    setStatus('Encrypting user data for auditor...');
    const res_encrypt = await fetch('/api/encrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plaintext: sub }),
    });
    if (!res_encrypt.ok) {
      const resp = await res_encrypt.text();
      throw new Error(`Encryption failed: ${res_encrypt.statusText} - ${resp}`);
    }
    const { ciphertext } = await res_encrypt.json();
    console.log('Encrypted ciphertext for "sub":', ciphertext);

    // 4. Build base transaction (original intent) + txContext, then invoke Snap
    setStatus('Building base transaction + invoking Snap...');
    const to = await getExternalReceiverAddress(accounts);
    assertNotInternal(to, accounts);

    // Base tx: keep to/value/data exactly as intended.
    // In this demo, we keep it as a simple transfer (value=0, data=0x).
    // You can replace (value/data) with any contract call calldata you want.
    const baseTx = {
      to,
      value: '0x0',
      data: '0x',
    };

    // Collect context for binding + reproducibility
    const [chainId, nonce] = await Promise.all([
      window.ethereum.request({ method: 'eth_chainId' }),
      window.ethereum.request({
        method: 'eth_getTransactionCount',
        params: [accounts[0], 'pending'],
      }),
    ]);
    console.log('txContext from provider:', { chainId, nonce });
    if (chainId == null || nonce == null) {
      throw new Error(`Failed to fetch txContext. chainId=${chainId}, nonce=${nonce}`);
    }

    // Estimate gas for the base tx (Snap will add accessList delta + margin).
    const gas = await window.ethereum.request({
      method: 'eth_estimateGas',
      params: [
        {
          from: accounts[0],
          ...baseTx,
        },
      ],
    });
    baseTx.gas = gas;

    const resp = await invokeSnap({
      method: 'sendZkProof',
      params: {
        proof,
        publicSignals,
        ciphertext,
        baseTx,
        txContext: { chainId, nonce },

        // 'full' stores the payload bytes in accessList (expensive but actually “attaches”).
        // 'hash-only' stores only keccak256(payloadBytes) in accessList (cheap, but not full payload).
        attachMode: 'full',

        // Snap-side extra margin to avoid OOG due to accessList intrinsic cost
        marginGas: '20000',
      },
    });

    console.log('sendZkProof resp:', resp);

    if (!resp?.ok) {
      setStatus(`User rejected or snap failed: ${resp?.reason ?? 'unknown'}`);
      return;
    }

    // Basic sanity checks for the returned Type-2 tx object
    if (!resp?.tx || typeof resp.tx !== 'object') {
      throw new Error('Snap returned ok=true but no tx object.');
    }
    if (!resp.tx.to || !resp.tx.type || !resp.tx.gas) {
      throw new Error('Snap returned tx missing required fields (to/type/gas).');
    }
    if (!Array.isArray(resp.tx.accessList)) {
      throw new Error('Snap returned tx missing accessList array.');
    }

    // 5. Send the transaction from dApp
    setStatus('Sending transaction...');
    const txParams = {
      from: accounts[0],
      ...resp.tx,
    };
    console.log('Sending transaction object to MetaMask:', txParams);
    const txHash = await window.ethereum.request({
      method: 'eth_sendTransaction',
      params: [txParams],
    });

    setStatus(`Proof tx sent: ${txHash}`);

    // 6) Poll for receipt and show final execution result
    setStatus(`Waiting for receipt: ${txHash}`);
    console.log('Waiting for receipt:', txHash);

    const receipt = await waitForReceipt(txHash, {
      pollIntervalMs: 1200,
      maxAttempts: 60,
      onTick: ({ attempt, receipt }) => {
        if (!receipt && attempt % 5 === 0) {
          console.log(`receipt pending... (attempt ${attempt})`);
        }
      },
    });

    const r = summarizeReceipt(receipt);
    console.log('Receipt:', receipt);
    console.log('Receipt summary:', r);

    const ok = (r.status || '').toLowerCase() === '0x1';
    if (ok) {
      const bn = hexToInt(r.blockNumber);
      setStatus(`✅ Mined OK (block ${bn ?? r.blockNumber}): ${txHash}`);
    } else {
      // status can be 0x0 for revert; on local chains it can also be missing
      const bn = hexToInt(r.blockNumber);
      setStatus(`❌ Mined but failed (status=${r.status}) block ${bn ?? r.blockNumber}: ${txHash}`);

      // Optional: best-effort revert reason (may fail depending on node/client)
      try {
        const tx = await window.ethereum.request({ method: 'eth_getTransactionByHash', params: [txHash] });
        // eth_call at the same block to extract revert reason (if available)
        await window.ethereum.request({
          method: 'eth_call',
          params: [{ from: tx.from, to: tx.to, data: tx.input, value: tx.value }, r.blockNumber],
        });
      } catch (e) {
        // Many clients won't return a readable reason; keep it quiet but log details
        console.log('Best-effort revert reason lookup failed:', e?.data?.originalError?.message || e?.message || e);
      }
    }

  } catch (err) {
    logRpcError('SendProof error:', err);
    setStatus(`SendProof error: ${err?.message ?? err}`);
  }
});

