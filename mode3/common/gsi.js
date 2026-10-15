// mode3/common/gsi.js — Google Identity Services(GIS) 로더(스펙 2026-10-16 D5). classic script: 사용자 페이지(번들)와 계정 페이지(인라인 스크립트)가 같은 사본을 쓴다.
// 테스트는 window.google.accounts.id 를 먼저 심어 두고(addInitScript) 이 로더가 스크립트 주입을 건너뛰게 한다.
(function () {
  const GSI_SRC = 'https://accounts.google.com/gsi/client';
  let loading = null;
  /** Google 은 127.0.0.1 오리진을 승인 목록에 받지 않는다(D6) — localhost 로 열었을 때만 버튼을 그린다. */
  const originOk = () => location.hostname === 'localhost';
  /** window.google.accounts.id 를 돌려준다. 이미 있으면(스텁·재호출) 그대로, 없으면 스크립트를 한 번만 주입한다. 실패/8초 → Error{ reason:'gsi_unavailable' }. */
  function load({ timeoutMs = 8000 } = {}) {
    if (window.google?.accounts?.id) return Promise.resolve(window.google.accounts.id);
    if (loading) return loading;
    loading = new Promise((resolve, reject) => {
      const fail = (why) => { loading = null; reject(Object.assign(new Error(`GIS 스크립트를 불러오지 못했다: ${why}`), { reason: 'gsi_unavailable' })); };
      const s = document.createElement('script');
      s.src = GSI_SRC; s.async = true; s.defer = true;
      const timer = setTimeout(() => fail('timeout'), timeoutMs);
      s.onload = () => { clearTimeout(timer); window.google?.accounts?.id ? resolve(window.google.accounts.id) : fail('no google.accounts.id'); };
      s.onerror = () => { clearTimeout(timer); fail('error'); };
      document.head.appendChild(s);
    });
    return loading;
  }
  /** 버튼을 el 안에 그린다. 토큰(JWT 문자열)은 onToken 으로. nonce 는 호출마다 새로 넣는다(initialize 는 전역이라 마지막 호출이 이긴다 — 한 화면에 버튼 하나만 살아 있게 쓴다). */
  async function render({ el, clientId, nonce, onToken, text = 'signin_with', theme = 'outline', size = 'large' }) {
    const id = await load();
    id.initialize({ client_id: clientId, nonce, callback: (resp) => onToken(resp?.credential ?? null), auto_select: false, cancel_on_tap_outside: true, use_fedcm_for_prompt: false });
    el.replaceChildren();
    id.renderButton(el, { type: 'standard', theme, size, text, shape: 'rectangular', logo_alignment: 'left' });
  }
  window.Mode3Gsi = { originOk, load, render, GSI_SRC };
})();
