// RP 페이지가 숨겨진 iframe으로 이 페이지를 임베드한다. 이 스크립트는 지갑
// origin(wallet_agent.js)에서 실행되면서, RP 페이지와 실제 IdP 로그인 팝업
// 사이에서 메시지를 중계한다 — 그래서 idp/login_popup.js는 자신을 연 창(opener)
// 으로 RP가 아니라 이 relay(지갑 origin)를 보게 되고, RP origin을 알 방법이
// 없어진다. idp/login_popup.js는 변경하지 않는다.

const IDP_ORIGIN = 'http://127.0.0.1:4000';

// RP 페이지(부모)가 이 iframe의 src에 URL 프래그먼트(#rp=...)로 자기 origin을
// 알려준다. 프래그먼트는 서버로 전송되지 않지만 문자열이라 위조될 수 있으므로
// "잠정값"으로만 쓰고, 첫 메시지가 도착하면 그 메시지의 event.origin(브라우저
// 보장, 위조 불가능)과 일치하는지 반드시 확인한 뒤에만 rpOrigin으로 확정한다 —
// idp/login_popup.js가 오늘 하는 것과 동일한 패턴을 한 홉 앞으로 옮긴 것뿐이다.
const tentativeRpOrigin = new URLSearchParams(location.hash.slice(1)).get('rp');
let rpOrigin = null;

let idpPopupWindow = null;
let idpPopupReady = false;
let pendingZKP = null;
let successRelayed = false;
let closedWatchTimer = null;

if (window.parent !== window && tentativeRpOrigin) {
  window.parent.postMessage({ type: 'IDP_READY_FOR_ZKP' }, tentativeRpOrigin);
}

function openOrReuseIdPPopup() {
  if (idpPopupWindow && !idpPopupWindow.closed) return;
  idpPopupReady = false;
  successRelayed = false;
  const popupName = `IdPLogin-${crypto.randomUUID()}`;
  idpPopupWindow = window.open(
    `${IDP_ORIGIN}/login_popup#rp=${encodeURIComponent(window.location.origin)}`,
    popupName,
    'width=500,height=600',
  );
  if (idpPopupWindow) startPopupClosedWatch();
}

function trySendProofToIdP() {
  if (!pendingZKP || !idpPopupWindow || idpPopupWindow.closed || !idpPopupReady) return;
  idpPopupWindow.postMessage({ type: 'RP_SEND_ZKP', zkp: pendingZKP }, IDP_ORIGIN);
}

function startPopupClosedWatch() {
  if (closedWatchTimer) clearInterval(closedWatchTimer);
  closedWatchTimer = setInterval(() => {
    if (!idpPopupWindow || idpPopupWindow.closed) {
      clearInterval(closedWatchTimer);
      closedWatchTimer = null;
      if (!successRelayed && rpOrigin) {
        window.parent.postMessage({ type: 'IDP_POPUP_CLOSED' }, rpOrigin);
      }
    }
  }, 500);
}

window.addEventListener('message', (event) => {
  if (event.source === window.parent) {
    if (rpOrigin === null) {
      if (event.origin !== tentativeRpOrigin) return;
      rpOrigin = event.origin;
    }
    if (event.origin !== rpOrigin) return;
    if (event.data.type === 'RP_SEND_ZKP') {
      pendingZKP = event.data.zkp;
      openOrReuseIdPPopup();
      trySendProofToIdP();
    }
    return;
  }

  if (idpPopupWindow && event.source === idpPopupWindow) {
    if (event.origin !== IDP_ORIGIN) return;
    if (event.data.type === 'IDP_READY_FOR_ZKP') {
      idpPopupReady = true;
      trySendProofToIdP();
    }
    if (event.data.type === 'IDP_SSO_SUCCESS') {
      successRelayed = true;
      if (rpOrigin) {
        window.parent.postMessage(event.data, rpOrigin);
      }
      // idp/login_popup.js도 성공 후 스스로 window.close()를 호출하지만, nested
      // cross-origin iframe에서 연 창이라 브라우저가 그 self-close를 막는 경우가
      // 있다. relay는 이 창을 실제로 window.open()한 opener라서 cross-origin이어도
      // .close() 호출이 항상 허용되므로, 여기서도 한 번 더 닫아준다.
      if (idpPopupWindow && !idpPopupWindow.closed) {
        idpPopupWindow.close();
      }
    }
  }
});
