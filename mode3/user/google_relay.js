// mode3/user/google_relay.js — Google 로그인 중계(2026-11-19, google_relay.html). 서비스(zkONE·zkTWO)가 Google 의 암묵 흐름(response_type=id_token)으로 보낸 브라우저가
// 여기로 돌아온다: 주소의 조각(#)에 id_token·state(또는 error)가 있다. state 의 앞부분이 그 로그인을 시작한 서비스의 오리진(base64url)이다 —
// 이 서버가 아는 서비스 오리진(/user/config 의 rpOrigins)일 때만 그 서비스의 첫 화면으로 조각째 넘긴다(지갑 오리진이면 지갑 창으로 — 아래 2026-11-20). 토큰은 여기서 검증하지 않는다(서비스가 한다) —
// 서비스는 자기가 낸 nonce 와 자기 브라우저에 남겨 둔 state 가 맞을 때만 받는다. 저장·기록·전송(네트워크)은 하지 않는다.
(async () => {
  const say = (t) => { document.getElementById('msg').textContent = t; };
  const frag = new URLSearchParams(location.hash.slice(1)), query = new URLSearchParams(location.search);
  const state = frag.get('state') ?? query.get('state') ?? '';
  history.replaceState(null, '', location.pathname);   // 토큰이 주소창·히스토리에 남지 않게
  let target = null;
  try { target = atob(state.split('.')[0].replace(/-/g, '+').replace(/_/g, '/')); } catch { target = null; }
  let allowed = [], walletOrigin = null;
  try { const cfg = await (await fetch('/user/config', { cache: 'no-store' })).json(); allowed = cfg.rpOrigins ?? []; walletOrigin = typeof cfg.walletOrigin === 'string' ? cfg.walletOrigin : null; } catch { allowed = []; }
  // 2026-11-20(스펙 passkey-google-signup G8): zkIdP 가입의 Google 확인은 지갑 창이 시작한다 — state 가 지갑 오리진이면 그 창(/?authorize=1)으로 돌려보낸다.
  // 받는 쪽(지갑 창)은 자기 sessionStorage 에 남겨 둔 state 와 맞을 때만 토큰을 쓴다(서비스와 같은 규칙).
  const toWallet = Boolean(target) && walletOrigin !== null && target === walletOrigin;
  if (!target || (!toWallet && !allowed.includes(target))) return say('돌아갈 서비스를 알 수 없습니다 — 서비스 페이지에서 다시 로그인하세요.');
  const out = new URLSearchParams({ google_back: '1', state });
  const token = frag.get('id_token');
  if (token) out.set('id_token', token); else out.set('error', frag.get('error') ?? query.get('error') ?? 'no_token');
  location.replace(toWallet ? `${target}/?authorize=1#${out}` : `${target}/#${out}`);
})();
