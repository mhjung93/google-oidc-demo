// mode3/user/user.js — 브라우저 전용 사용자 페이지의 엔트리(스펙 2026-10-15 §4.2, 번들 → /dist/user.js).
// 설정(/user/config) → 저장소(IndexedDB) → 체인 provider → 증명 워커 → 코어 → 화면(ui.js) 또는 승인 팝업(popup.js).
// 같은 index.html 을 쿼리로 가른다(?authorize=1 이면 팝업) — 에이전트 페이지(mode3/wallet.html)와 같은 규칙.
import { ethers } from 'ethers';
import { createUserCore } from './core/user_core.js';
import { openIdbKv } from './core/kv_idb.js';
import { createProver } from './prover_client.js';
import { $, mountUi, publicMeta, textKit, setPresence } from './ui.js';
import { runPopup, failPopup } from './popup.js';

const IS_AUTHORIZE = new URLSearchParams(location.search).get('authorize') === '1';
// 뷰 전환은 설정을 기다리지 않는다 — 쿼리만 보면 알 수 있다(팝업에 사용자 화면이 비치지 않게 가장 먼저).
if (IS_AUTHORIZE) { $('mainView').hidden = true; $('authorizeView').hidden = false; }

// /common 이 뜨지 않아도(404) 페이지는 HTML 의 한국어 기본 텍스트로 계속 돌아간다(설계 §5, wallet.html 과 같은 대체물).
const Demo = window.Demo ?? {
  lang: 'ko', expert: false,
  t(k, vars = {}) { const e = window.DemoStrings?.ui?.[k]; let s = e ? e.ko : k; for (const [n, v] of Object.entries(vars)) s = s.split(`{${n}}`).join(String(v)); return s; },
  term: (n) => window.DemoStrings?.terms?.[n]?.ko ?? n,
  reason: (code) => window.DemoStrings?.reasons?.[code]?.ko ?? null,
  init() { /* 안내 바 없음 */ }, guide() { /* 안내 바 없음 */ }, setLang() {}, setExpert() {},
  verdict(el, args) {
    const { ok, title, summary, reason, detail, pending } = typeof args === 'function' ? args() : args;
    el.className = `verdict ${pending ? 'pending' : ok ? 'ok' : 'bad'}`;
    const d = detail === undefined ? null : (typeof detail === 'string' ? detail : JSON.stringify(detail));
    el.textContent = [window.DemoStrings?.verdicts?.[title]?.ko ?? title, summary, reason, d].filter(Boolean).join(' — ');
  },
  confirmDanger: (k) => window.confirm(window.DemoStrings?.ui?.[k]?.ko ?? k),
};

/** 시작하지 못하는 오류(설정·저장소) — 사유 카드를 보이고 멈춘다. 팝업이면 첫 요청에 실패를 돌려주고 닫는다. */
function fatal(reason, detail) {
  const { setVerdict } = textKit(Demo);
  if (IS_AUTHORIZE) {
    $('authTitle').textContent = Demo.reason(reason)?.title ?? reason;
    $('authStep').textContent = detail;
    failPopup({ reason, detail });
    return;
  }
  setVerdict($('registerResult'), false, 'error_title', { reason, detail });   // 버튼은 그대로 활성(2026-10-16) — 다시 눌러 재시도할 수 있다
}

async function main() {
  // 승인 팝업에는 체험 모드·안내 바를 두지 않는다(설계 2026-09-25 §3.1 — 할 일이 하나뿐인 좁은 창이다).
  Demo.init({ page: 'wallet', tour: !IS_AUTHORIZE });
  if (IS_AUTHORIZE) $('demoBar').hidden = true;
  let config;
  try {
    const r = await fetch('/user/config');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    config = await r.json();
  } catch (e) { return fatal('internal', `/user/config: ${e.message}`); }
  if (config.wrapper === true) setPresence(false);   // zkWrapper 서버에는 존재 신호(세션·서비스 수)를 보내지 않는다
  Demo.setWalletKind?.(config.wrapper === true ? 'zkwrapper' : config.secrets);   // 2026-11-18: passkey-web 이면 화면에서 "스냅" 을 뺀다 — 아래에서 문구를 그리기 전에 맞춘다
  // 2026-10-21: 브라우저에 저장소 영속을 요청한다 — iOS 의 7일 삭제·Chrome 의 용량 정리 대상에서 빠진다(새 기기 이전은 복구 코드로). 거절·미지원은 무시.
  if (!IS_AUTHORIZE) { try { navigator.storage?.persist?.()?.catch?.(() => {}); } catch { /* 미지원 */ } }
  let kv;
  try { kv = await openIdbKv(); }
  catch (e) { return fatal(e?.reason ?? 'storage_unavailable', e?.message ?? String(e)); }
  // passkey-web(2026-11-17 계획 R-5): 체인 RPC 는 같은 오리진 프록시(/rpc/app·/rpc/rev) — 상대 경로라 절대 주소로 푼다(ethers 는 http(s) 주소만 받는다).
  const absUrl = (u) => (typeof u === 'string' && u.startsWith('/') ? new URL(u, location.origin).href : u);
  const rpcUrl = absUrl(config.rpcUrl), revRpcUrl = absUrl(config.revRpcUrl);
  const provider = new ethers.JsonRpcProvider(rpcUrl, undefined, { cacheTimeout: -1 });
  // 캐노니컬 로그가 다른 체인에 있으면(두 체인 구성, V10) 그 RPC 로 따로 읽는다.
  const canonProvider = revRpcUrl && revRpcUrl !== rpcUrl ? new ethers.JsonRpcProvider(revRpcUrl, undefined, { cacheTimeout: -1 }) : provider;
  // passkey-web(스펙 W3, 계획 R-2): salt 는 패스키 PRF — RP ID 는 설정의 사용자 오리진 호스트(페이지 호스트가 다르면 passkey_store 가 passkey_wrong_origin).
  let passkey = null;
  if (config.secrets === 'passkey-web') {
    const rpId = new URL(config.walletOrigin).hostname;
    const P = () => {
      if (!window.Mode3Passkey) throw Object.assign(new Error('/common/passkey_store.js 를 읽지 못했다'), { reason: 'passkey_unsupported' });
      return window.Mode3Passkey;
    };
    // 패스키 이름(2026-11-25 사용자 요청): zkWrapper 는 계정 이름·표시 이름 모두 'zkWrapper', passkey-web 은 예전 그대로
    const pkNames = config.wrapper === true ? { rpName: 'zkWrapper', userName: 'zkWrapper' } : { rpName: 'zk 지갑' };
    passkey = { derive: (o) => P().derivePrf({ ...o, rpId }), create: (o) => P().createPasskey({ ...o, rpId, ...pkNames }) };
  }
  // 워커 진행률은 화면이 듣는 이벤트로 넘긴다(화면이 아직 없을 때 온 것은 버려진다 — 다음 청크가 다시 온다).
  const prover = createProver({ onProgress: (p) => window.dispatchEvent(new CustomEvent('mode3-zk-progress', { detail: p })) });
  // 코어의 로그는 처리되지 않은 오류의 stack 뿐이다(비밀은 실리지 않는다 — 같은 메시지가 응답의 detail 로도 나간다).
  const core = createUserCore({ kv, config, provider, canonProvider, fullProve: prover.fullProve, log: (m) => console.warn(m), passkey });
  const meta = publicMeta(kv);
  // 데모 세대(2026-10-21, 사용자 결정 "3번"): 리셋 스크립트가 /user/config.demoGeneration 을 올린다. 기억한 번호와 다르면 이 브라우저의 옛 등록·세션을
  // 스스로 지운다 — 리셋마다 "모두 지우기"를 누르지 않게. **데모 전용**: 서버 설정값 하나로 브라우저의 비밀이 지워지는 셈이라 실제 배포에서는 켜면 안 된다
  // (설정이 없으면 아무것도 하지 않는다). 번호를 처음 보는 브라우저는 지우지 않고 기억만 한다(옛 등록은 사람이 한 번 지운다).
  let demoReset = false;
  if (config.demoGeneration) {
    try {
      const seen = await kv.get('demoGeneration');
      // 2026-11-18(사용자 요청): 리셋 때는 패스키 연결도 끊는다(passkey-web) — 새 데모는 패스키 설정부터 다시 한다. 패스키 자체는 인증기(Google 비밀번호 관리자 등)에 남는다.
      if (seen && seen !== config.demoGeneration) { await core.wipe({ keepPasskey: false }); demoReset = true; }
      await kv.set('demoGeneration', config.demoGeneration);
    } catch { /* 저장소 오류면 그대로 진행 — 수동 "모두 지우기"가 남아 있다 */ }
  }
  if (IS_AUTHORIZE) return runPopup({ core, config, Demo, meta, passkey });
  // 상태 패널(설계 2026-09-25 §2) — 에이전트 페이지의 syncStack 자리. 신원 기관·첫 RP 주소는 설정이 안다.
  // 래퍼 방식에서는 상태 패널을 걸지 않는다 — 지갑 서버가 발급 서버와 한 몸이라 따로 볼 상대가 없고, 서비스의 상태를 이 페이지가 물을 까닭도 없다.
  if (config.wrapper !== true) Demo.stack?.({ self: 'wallet', urls: { aa: config.ciaUrl, rp: config.rpOrigins?.[0] } });
  return mountUi({ core, prover, config, Demo, meta, demoReset, passkey });
}
main().catch((e) => { console.error(e); fatal('internal', e?.message ?? String(e)); });
