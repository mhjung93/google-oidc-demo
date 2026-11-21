// lib/mode3_zkwrapper_env.js — zkWrapper 서버 진입점(mode3_zkwrapper.js)이 cia.js 를 부르기 전에 세우는 환경 값(스펙 2026-11-20 zkwrapper §1·§4).
// 따로 둔 까닭: 진입점은 불러오는 순간 서버가 뜨므로, 기본값을 시험할 수 있게 순수 함수로 뺐다(2026-11-21, 최종 검토 M-5).
import path from 'node:path';

/** env(지금 환경)를 보고 더할 값을 돌려준다 — 이미 있는 값은 덮지 않는다(CIA_WRAPPER·CIA_USER_APP 은 늘 1).
 *  상태·열쇠 파일의 기본값은 root/.local/zkwrapper/ — 저장소 루트의 cia_state.json·cia_keys.json(한 머신 데모의 zkIdP)과 겹치지 않게(M-5). */
export function zkwrapperEnv(env, root) {
  const dir = path.join(root, '.local', 'zkwrapper');
  return {
    CIA_WRAPPER: '1',
    CIA_USER_APP: '1',
    CIA_PORT: env.CIA_PORT || env.MODE3_ZKWRAPPER_PORT || '5100',
    MODE3_WALLET_KIND: env.MODE3_WALLET_KIND || 'zkwrapper',   // 화면 문구 — 지갑은 브라우저의 zk 클라이언트이고, 별도 IdP 가 없다(/mode3/health 의 walletKind)
    CIA_STATE_FILE: env.CIA_STATE_FILE || path.join(dir, 'cia_state.json'),
    CIA_KEYS_FILE: env.CIA_KEYS_FILE || path.join(dir, 'cia_keys.json'),
  };
}
