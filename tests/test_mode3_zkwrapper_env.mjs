// tests/test_mode3_zkwrapper_env.mjs — zkWrapper 진입점의 환경 기본값(lib/mode3_zkwrapper_env.js). 외부 의존 없음. (unit)
import assert from 'node:assert/strict';
import path from 'node:path';
import { zkwrapperEnv } from '../lib/mode3_zkwrapper_env.js';

let fails = 0; const t = (n, f) => { try { f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.message); } };
const ROOT = '/repo';
t('기본값: 깃발 둘, 포트 5100, 지갑 종류 zkwrapper, 상태·열쇠는 .local/zkwrapper/(저장소 루트의 cia_state.json·cia_keys.json 이 아니다 — M-5)', () => {
  const e = zkwrapperEnv({}, ROOT);
  assert.equal(e.CIA_WRAPPER, '1'); assert.equal(e.CIA_USER_APP, '1'); assert.equal(e.CIA_PORT, '5100'); assert.equal(e.MODE3_WALLET_KIND, 'zkwrapper');
  assert.equal(e.CIA_STATE_FILE, path.join(ROOT, '.local', 'zkwrapper', 'cia_state.json'));
  assert.equal(e.CIA_KEYS_FILE, path.join(ROOT, '.local', 'zkwrapper', 'cia_keys.json'));
});
t('준 값은 덮지 않는다 — CIA_PORT 가 MODE3_ZKWRAPPER_PORT 보다 먼저', () => {
  const e = zkwrapperEnv({ CIA_PORT: '7001', MODE3_ZKWRAPPER_PORT: '7002', MODE3_WALLET_KIND: 'x', CIA_STATE_FILE: '/s.json', CIA_KEYS_FILE: '/k.json' }, ROOT);
  assert.equal(e.CIA_PORT, '7001'); assert.equal(e.MODE3_WALLET_KIND, 'x'); assert.equal(e.CIA_STATE_FILE, '/s.json'); assert.equal(e.CIA_KEYS_FILE, '/k.json');
  assert.equal(zkwrapperEnv({ MODE3_ZKWRAPPER_PORT: '7002' }, ROOT).CIA_PORT, '7002');
});
console.log(fails ? `\n${fails} 실패` : '\n모두 통과');
process.exit(fails ? 1 : 0);
