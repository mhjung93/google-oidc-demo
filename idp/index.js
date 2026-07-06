const statusEl = document.getElementById('status');
const registerRpButton = document.getElementById('registerRpButton');
const userLoginButton = document.getElementById('userLoginButton');

const RP_REGISTER_ENDPOINT = 'http://127.0.0.1:3000/api/mode2/register';

function setStatus(value) {
  if (typeof value === 'string') {
    statusEl.innerText = value;
    return;
  }
  statusEl.innerText = JSON.stringify(value, null, 2);
}

registerRpButton?.addEventListener('click', async () => {
  setStatus('Requesting RP Backend registration...');

  try {
    const res = await fetch(RP_REGISTER_ENDPOINT, { method: 'POST' });
    const data = await res.json();

    if (!res.ok) {
      setStatus(`RP registration failed: ${data.error || res.statusText}`);
      return;
    }

    setStatus('RP registration requested successfully. Check the RP Backend terminal for details.');
  } catch (err) {
    setStatus(`RP registration failed: ${err.message}`);
  }
});

userLoginButton?.addEventListener('click', () => {
  window.location.href = '/login_popup';
});
