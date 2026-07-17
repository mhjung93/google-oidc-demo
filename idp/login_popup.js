let pendingZKP = null;

// RP origin은 하드코딩하지 않는다. 팝업을 연 쪽(client.js)이 URL 프래그먼트
// (#rp=...)로 자기 origin을 알려주지만, 프래그먼트는 서버에 절대 전송되지 않는
// 대신(브라우저가 HTTP 요청에서 항상 잘라냄) 그 값 자체는 그냥 문자열이라
// 위조될 수 있다 — 그래서 이걸 "잠정값"으로만 쓴다. 실제로 메시지가 도착하면
// 그 메시지의 event.origin(브라우저가 보장하는, 위조 불가능한 진짜 발신
// origin)이 이 잠정값과 일치하는지 반드시 확인한 뒤에만 rpOrigin으로
// "확정"한다 — 확정 전까지는 아무 민감한 데이터도 안 보내고 안 받는다.
const tentativeRpOrigin = new URLSearchParams(location.hash.slice(1)).get('rp');
let rpOrigin = null; // event.origin으로 확인되기 전까지는 null
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
    ? pendingZKP.zkpPublicSignals
    : pendingZKP?.zkpPublicSignals;
}

if (window.opener && loginButton) {
  loginButton.disabled = true;
  if (loginSection) loginSection.style.display = 'none';
  setStatus('Waiting for Wallet submission...');
}

// URL 프래그먼트의 잠정값으로 곧바로 "준비됨" 신호를 보낸다 — 반복 전송(RP_HELLO)
// 없이, 로드되자마자 한 번만. 이 메시지엔 민감한 데이터가 없어서, 잠정값이
// 틀려도(또는 악의적으로 조작돼도) 기껏해야 이 빈 신호 하나가 엉뚱한 곳에
// 갈 뿐이다 — 실제 데이터는 아래 리스너에서 event.origin으로 재확인한 뒤에만 오간다.
if (window.opener && tentativeRpOrigin) {
  window.opener.postMessage({ type: 'IDP_READY_FOR_ZKP' }, tentativeRpOrigin);
}

window.addEventListener('message', (event) => {
  if (rpOrigin === null) {
    // 최초 메시지의 event.origin(브라우저 보장, 위조 불가능)이 프래그먼트가
    // 주장한 값과 실제로 일치할 때만 그 origin을 확정해서 신뢰하기 시작한다.
    // 일치하지 않으면 무시한다 — 프래그먼트가 틀렸거나 다른 origin이 끼어든 것.
    if (event.origin !== tentativeRpOrigin) return;
    rpOrigin = event.origin;
  }
  if (event.origin !== rpOrigin) return;
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
      }, rpOrigin);
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
