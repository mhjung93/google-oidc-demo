let pendingZKP = null;

const RP_ORIGIN = 'http://127.0.0.1:3000';
const statusEl = document.getElementById('status');
const loginButton = document.getElementById('loginBtn');
const loginSection = document.getElementById('loginSection');
const consentSection = document.getElementById('consentSection');
const allowConsentButton = document.getElementById('allowConsentBtn');
const denyConsentButton = document.getElementById('denyConsentBtn');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const retryButton = document.getElementById('retryLoginBtn');
let pendingIdPToken = null;
let pendingUsername = null;

function setStatus(message) {
  if (statusEl) statusEl.innerText = message;
}

// 다른 계정으로 로그인했을 때(예: Step 8 증명의 uid와 실제 로그인한 계정이
// 달라서 동의 단계에서 Identity Mismatch로 거부되는 경우) 팝업이 로그인 폼도
// 없이 막혀버리지 않도록, 로그인 폼으로 되돌아갈 수 있는 재시도 버튼을 보여준다.
function showRetry() {
  if (retryButton) retryButton.style.display = 'inline-block';
}

function resetToLogin() {
  if (consentSection) consentSection.style.display = 'none';
  if (loginSection) loginSection.style.display = 'block';
  if (loginButton) loginButton.disabled = false;
  if (passwordInput) passwordInput.value = '';
  if (retryButton) retryButton.style.display = 'none';
  setStatus('Enter credentials and try again.');
}

function zkpSignalsWithoutUid() {
  return Array.isArray(pendingZKP?.zkpPublicSignals)
    ? pendingZKP.zkpPublicSignals.slice(1)
    : pendingZKP?.zkpPublicSignals;
}

if (window.opener && loginButton) {
  loginButton.disabled = true;
  if (loginSection) loginSection.style.display = 'none';
  setStatus('Waiting for Wallet submission...');
}

if (window.opener) {
  window.opener.postMessage({ type: 'IDP_READY_FOR_ZKP' }, RP_ORIGIN);
}

window.addEventListener('message', (event) => {
  if (event.origin !== RP_ORIGIN) return;
  if (event.data.type === 'RP_SEND_ZKP') {
    pendingZKP = event.data.zkp;
    pendingUsername = pendingZKP.username;
    if (usernameInput) usernameInput.value = pendingUsername || '';
    if (loginButton) loginButton.disabled = false;
    if (loginSection) loginSection.style.display = 'block';
    setStatus('Wallet submission received. Enter password to continue.');
  }
});

async function doLogin() {
  const username = usernameInput.value;
  const password = passwordInput.value;
  pendingUsername = username;

  setStatus('Verifying...');

  try {
    const endpoint = pendingZKP ? '/sso_with_credentials' : '/login';
    const payload = pendingZKP
      ? {
          username,
          password,
          zkpProof: pendingZKP.zkpProof,
          zkpPublicSignals: zkpSignalsWithoutUid(),
          business: pendingZKP.business,
          isLight: pendingZKP.isLight,
          walletSubmission: pendingZKP.walletSubmission,
          pi_i: pendingZKP.pi_i,
        }
      : { username, password };

    if (pendingZKP) {
      setStatus(`Submitting Wallet data to IdP published endpoint: ${endpoint}`);
    }

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();

    if (data.success && pendingZKP) {
      if (loginSection) loginSection.style.display = 'none';
      if (consentSection) consentSection.style.display = 'block';
      setStatus('Login verified. Waiting for consent.');
      return;
    }

    if (data.success) {
      sessionStorage.setItem('custom_idp_auth_token', JSON.stringify(data.authToken));
      window.location.href = '/idp/profile.html';
      return;
    }

    setStatus(`Error: ${data.error}`);
    showRetry();
  } catch (err) {
    setStatus(`Login Failed: ${err.message}`);
    showRetry();
  }
}

async function submitConsent(allowed) {
  if (!pendingZKP) return;

  setStatus(`Consent ${allowed ? 'allowed' : 'denied'}. Reporting to IdP...`);

  try {
    const res = await fetch('/consent_result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: pendingUsername,
        allowed,
        walletSubmission: pendingZKP.walletSubmission,
        business: pendingZKP.business,
        zkpProof: pendingZKP.zkpProof,
        zkpPublicSignals: zkpSignalsWithoutUid(),
        isLight: pendingZKP.isLight,
        pi_i: pendingZKP.pi_i,
      }),
    });
    const data = await res.json();

    if (allowed && data.success && data.idpToken) {
      pendingIdPToken = data.idpToken;
      window.opener.postMessage({
        type: 'IDP_SSO_SUCCESS',
        idpToken: pendingIdPToken,
        r_i: pendingZKP.r_i || pendingZKP.walletSubmission?.r_i || pendingZKP.business?.r_i,
      }, RP_ORIGIN);
      window.close();
      return;
    }

    setStatus(`Consent failed: ${data.error || 'SSO was not completed.'}`);
    showRetry();
  } catch (err) {
    setStatus(`Consent report failed: ${err.message}`);
    showRetry();
  }
}

loginButton?.addEventListener('click', doLogin);
allowConsentButton?.addEventListener('click', () => submitConsent(true));
denyConsentButton?.addEventListener('click', () => submitConsent(false));
retryButton?.addEventListener('click', resetToLogin);
