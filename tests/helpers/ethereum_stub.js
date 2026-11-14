// 브라우저 테스트용 window.ethereum 스텁 — MetaMask Flask 없이 지갑 페이지·승인 팝업을 그대로 돌리기 위한 것이다
// (스펙 2026-09-22 metamask-snap §7). page.addInitScript 로 문서 스크립트보다 먼저 주입한다.
//
// Task 5 Ruling 5: wallet_invokeSnap 은 시뮬레이터가 아니라 **진짜 Snap**(snap-mode3/src/index.js)의 onRpcRequest 로
// 간다. Snap 소스는 ESM 이라 addInitScript 의 고전 스크립트에 그대로 못 넣으므로, import 두 줄만 바꿔
// (1) @metamask/snaps-sdk 는 panel/text/heading/divider 네 개짜리 껍데기로, (2) ./crypto.js 는 같은 파일을 앞에 이어 붙여
// 해결한다. 나머지 본문(오리진 검사·상태 모양·대화상자 문구·증인 조립)은 소스 그대로 돌아간다.
//
// Snap 전역(`snap`)과 MetaMask 의 체인 호출은 페이지 밖(Node 하네스)으로 넘긴다:
//   - snap_manageState → window.__snapState(op, newState)   MetaMask 의 암호화 저장소는 페이지가 아니라 확장에 있다.
//     지갑 페이지와 승인 팝업은 서로 다른 JS 컨텍스트라, 페이지 안 객체로 두면 팝업이 등록을 못 본다.
//   - snap_dialog       → window.__snapDialog(params)       하네스가 답을 주고 무엇을 보여 줬는지도 검사한다.
//   - eth_sendTransaction / eth_getTransactionReceipt → window.__sendTx / window.__getReceipt (hardhat 계정이 실제 전송)
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const SRC_DIR = fileURLToPath(new URL('../../snap-mode3/src/', import.meta.url));
/** 저장소의 스냅 번들 버전(snap-mode3/snap.manifest.json) — 에이전트의 /wallet/config.snapVersion 과 같은 값이다. */
export const SNAP_MANIFEST_VERSION = JSON.parse(fs.readFileSync(fileURLToPath(new URL('../../snap-mode3/snap.manifest.json', import.meta.url)), 'utf8')).version;

// snap-mode3/src/index.js 의 WALLET_ORIGINS 상수(번들에 굳어 있어 env 로 못 바꾼다). 격리 스택의 지갑 포트는
// 매번 다르므로, MetaMask 역할인 이 스텁이 Snap 에 알려 주는 오리진은 이 고정값을 쓴다.
export const SNAP_WALLET_ORIGIN = 'http://127.0.0.1:5100';
// 2026-11-13(스냅 0.5.0, 스펙 random-salt): snap_getEntropy 대역은 없다 — 스냅은 salt 를 스스로 무작위로 만든다(crypto.getRandomValues). 정해진 salt 가 필요한 테스트는
// 저장 상태(__snapState)에 { version: 2, salt: { s_u, backedUp: true, … } } 를 미리 넣거나 importSalt 를 부른다.

/** `export ` 접두사만 떼어 고전 스크립트에 넣을 수 있게 한다. */
function stripExports(src) {
  const out = src.replace(/^export (const|function|async function) /gm, '$1 ');
  if (/^export /m.test(out)) throw new Error('ethereum_stub: 처리하지 못한 export 가 남았다');
  return out;
}

/** snap-mode3/src/index.js 를 고전 스크립트용으로 바꾼다. 치환이 하나라도 안 맞으면 조용히 넘어가지 않고 던진다. */
function snapModuleSource() {
  const crypto = stripExports(fs.readFileSync(`${SRC_DIR}crypto.js`, 'utf8'));
  let index = fs.readFileSync(`${SRC_DIR}index.js`, 'utf8');
  const sdkImport = /^import \* as sdkNamespace from '@metamask\/snaps-sdk';$/m;
  // 리뷰 2026-10-13 U2: index.js 가 crypto.js 에서 ATTR_MAX 도 가져오게 되면서 import 목록이 늘었다 — 이름 목록은
  // 가리지 않고 crypto.js 에서 가져오는 import 문 한 줄이라는 구조만 본다.
  const cryptoImport = /^import \{ [\w, ]+ \} from '\.\/crypto\.js';$/m;
  if (!sdkImport.test(index)) throw new Error('ethereum_stub: snap-mode3/src/index.js 의 snaps-sdk import 를 못 찾았다');
  if (!cryptoImport.test(index)) throw new Error('ethereum_stub: snap-mode3/src/index.js 의 crypto.js import 를 못 찾았다');
  index = index.replace(sdkImport, 'const sdkNamespace = __SDK_SHIM__;').replace(cryptoImport, '');
  if (!/^export const onRpcRequest = /m.test(index)) throw new Error('ethereum_stub: onRpcRequest export 를 못 찾았다');
  index = index.replace(/^export const onRpcRequest = /m, 'const onRpcRequest = ');
  return `${crypto}\n${index}\nwindow.__snapOnRpcRequest = onRpcRequest;\n`;
}

/**
 * addInitScript 에 넣을 스크립트를 만든다.
 * @param {{snapId: string, account: string, chainId: string, srp?: string}} opts
 */
export function buildInitScript({ snapId, account, chainId }) {
  return `(() => {
  const SNAP_ID = ${JSON.stringify(snapId)};
  const ACCOUNT = ${JSON.stringify(account)};
  const CHAIN_ID = ${JSON.stringify('0x' + BigInt(chainId).toString(16))};
  const SNAP_ORIGIN = ${JSON.stringify(SNAP_WALLET_ORIGIN)};
  const SNAP_VERSION = ${JSON.stringify(SNAP_MANIFEST_VERSION)};

  // @metamask/snaps-sdk 의 UI 빌더 — Snap 은 모양만 만들고 표시는 MetaMask 가 한다. 하네스가 문구를 검사할 수 있게 그대로 담는다.
  const __SDK_SHIM__ = {
    panel: (children) => ({ type: 'panel', children }),
    text: (value) => ({ type: 'text', value }),
    heading: (value) => ({ type: 'heading', value }),
    divider: () => ({ type: 'divider' }),
  };

  // MetaMask 의 Snap 실행 환경이 주는 전역.
  window.snap = {
    request: async ({ method, params }) => {
      if (method === 'snap_manageState') {
        const op = params && params.operation;
        if (op === 'get') return window.__snapState('get', null);
        if (op === 'update') return window.__snapState('update', params.newState);
        if (op === 'clear') return window.__snapState('clear', null);
        throw new Error('ethereum_stub: 모르는 snap_manageState operation ' + op);
      }
      if (method === 'snap_dialog') return window.__snapDialog(params);
      throw new Error('ethereum_stub: 모르는 snap method ' + method);
    },
  };

${snapModuleSource().split('\n').map((l) => (l ? '  ' + l : l)).join('\n')}

  // 설치된 스냅의 버전(2026-11-14): 기본은 저장소의 매니페스트 버전. 옛 스냅을 흉내 내려면 sessionStorage.__snapStubVersion 에 버전을 둔다(새로 고쳐도 남는다) —
  // wallet_requestSnaps(설치·업데이트)가 그것을 지워 지금 버전이 설치된 것으로 만든다. 부른 메서드는 window.__ethCalls 에 쌓는다(계정을 요청하지 않는지 테스트가 본다).
  const stubVersion = () => { try { return sessionStorage.getItem('__snapStubVersion') || SNAP_VERSION; } catch { return SNAP_VERSION; } };
  const snaps = () => ({ [SNAP_ID]: { id: SNAP_ID, version: stubVersion(), enabled: true, blocked: false } });
  // 스냅은 오리진마다 한 번 허용받는다(2026-11-14): wallet_requestSnaps 전에는 wallet_getSnaps 가 빈 객체다 — 화면이 처음에는 "MetaMask 연결" 카드를 보이고,
  // 허용 뒤에는 새로 고쳐도 창 없이 다시 잇는 것을 그대로 본다. 허용 표시는 그 오리진의 localStorage 에 둔다(스냅 화면과 승인 팝업·속성 도구가 같은 오리진이다).
  const installed = () => { try { return localStorage.getItem('__snapStubInstalled') === '1'; } catch { return true; } };
  window.__ethCalls = [];
  window.ethereum = {
    isMetaMask: true,
    request: async ({ method, params }) => {
      window.__ethCalls.push(method);
      switch (method) {
        case 'eth_requestAccounts':
        case 'eth_accounts':
          return [ACCOUNT];
        case 'eth_chainId':
          return CHAIN_ID;
        case 'wallet_requestSnaps':
          try { sessionStorage.removeItem('__snapStubVersion'); localStorage.setItem('__snapStubInstalled', '1'); } catch { /* 저장소 없음 */ }
          return snaps();
        case 'wallet_getSnaps':
          return installed() ? snaps() : {};
        case 'wallet_invokeSnap': {
          const { snapId, request } = params || {};
          if (snapId !== SNAP_ID) throw new Error('ethereum_stub: 모르는 snapId ' + snapId);
          // 테스트 전용 훅(2026-11-12 리뷰 M-3): 옛 스냅(0.1.0)은 getSalt 를 모른다 — 실제 스냅의 default 분기와 같은 오류.
          if (window.__snapOutdated && request && request.method === 'getSalt') throw new Error('method_not_found: getSalt');
          // MetaMask 가 부르는 자리 — origin 은 확장이 정한다. 페이지가 고를 수 없으므로 여기서 준다.
          return window.__snapOnRpcRequest({ origin: SNAP_ORIGIN, request });
        }
        case 'eth_sendTransaction':
          return window.__sendTx((params || [])[0]);
        case 'eth_getTransactionReceipt':
          return window.__getReceipt((params || [])[0]);
        default:
          throw new Error('ethereum_stub: 모르는 method ' + method);
      }
    },
    on: () => {},
    removeListener: () => {},
  };
})();
`;
}
