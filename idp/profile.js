const tokenStr = sessionStorage.getItem('custom_idp_auth_token');
const logoutButton = document.getElementById('logoutButton');

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.innerText = value || '-';
}

if (!tokenStr) {
  setText('sub', 'Not logged in');
} else {
  try {
    const token = JSON.parse(tokenStr);
    setText('sub', token.sub);
    setText('issuer', token.issuer);
    setText('sigma1', token.signature?.sigma1);
    setText('sigma2', token.signature?.sigma2);
  } catch (err) {
    setText('sub', `Invalid login data: ${err.message}`);
  }
}

logoutButton?.addEventListener('click', () => {
  sessionStorage.removeItem('custom_idp_auth_token');
  window.location.href = '/idp';
});
