const requestUri = new URLSearchParams(location.search).get('request_uri');
const statusEl = document.getElementById('status');
const loginSection = document.getElementById('loginSection');
const consentSection = document.getElementById('consentSection');

document.getElementById('loginBtn').addEventListener('click', async () => {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  statusEl.innerText = 'Verifying...';
  try {
    const res = await fetch('/authorize/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request_uri: requestUri, username, password }),
    });
    const data = await res.json();
    if (!data.success) {
      statusEl.innerText = `Error: ${data.error}`;
      return;
    }
    loginSection.style.display = 'none';
    consentSection.style.display = 'block';
  } catch (err) {
    statusEl.innerText = `Error: ${err.message}`;
  }
});

async function submitConsent(allowed) {
  const res = await fetch('/authorize/consent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_uri: requestUri, allowed }),
  });
  const data = await res.json();
  if (data.redirectTo) {
    window.location.href = data.redirectTo;
  } else {
    statusEl.innerText = `Error: ${data.error_description || data.error}`;
  }
}

document.getElementById('allowBtn').addEventListener('click', () => submitConsent(true));
document.getElementById('denyBtn').addEventListener('click', () => submitConsent(false));
