let pendingZKP = null;

const RP_ORIGIN = 'http://127.0.0.1:3000';
const statusEl = document.getElementById('status');
const loginButton = document.getElementById('loginBtn');
const loginSection = document.getElementById('loginSection');
const consentSection = document.getElementById('consentSection');
const allowConsentButton = document.getElementById('allowConsentBtn');
const denyConsentButton = document.getElementById('denyConsentBtn');
let pendingIdPToken = null;
let pendingUsername = null;

function setStatus(message) {
  if (statusEl) statusEl.innerText = message;
}

if (window.opener && loginButton) {
  loginButton.disabled = true;
  setStatus('Waiting for Wallet submission...');
}

if (window.opener) {
  window.opener.postMessage({ type: 'IDP_READY_FOR_ZKP' }, RP_ORIGIN);
}

window.addEventListener('message', (event) => {
  if (event.origin !== RP_ORIGIN) return;
  if (event.data.type === 'RP_SEND_ZKP') {
    pendingZKP = event.data.zkp;
    if (loginButton) loginButton.disabled = false;
    setStatus('Wallet submission received. Please log in.');
  }
});

async function doLogin() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  pendingUsername = username;

  setStatus('Verifying...');

  try {
    const endpoint = pendingZKP ? '/sso_with_credentials' : '/login';
    const payload = pendingZKP
      ? { username, password, ...pendingZKP }
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
  } catch (err) {
    setStatus(`Login Failed: ${err.message}`);
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
        zkpPublicSignals: pendingZKP.zkpPublicSignals,
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
  } catch (err) {
    setStatus(`Consent report failed: ${err.message}`);
  }
}

loginButton?.addEventListener('click', doLogin);
allowConsentButton?.addEventListener('click', () => submitConsent(true));
denyConsentButton?.addEventListener('click', () => submitConsent(false));
