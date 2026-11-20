// scripts/demo_split_start.sh 의 WALLET_MODE=zkwrapper 정적 검사(2026-11-20 계획 zkwrapper Task 7). 분리 데모는 실제 VM·ssh 로만 돌아서 스크립트를 실행하지 않고 줄을 읽어 확인한다.
// 실행은 "래퍼 사전 검사가 내림·ssh 보다 먼저" 단언이 통과했을 때만, 그 사전 검사에서 끝나는 경우로 한정한다(라이브 데모를 건드리지 않는다).
//   node tests/test_demo_split_zkwrapper.mjs   (unit)
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const SCRIPT = new URL('../scripts/demo_split_start.sh', import.meta.url).pathname;
const src = fs.readFileSync(SCRIPT, 'utf8');
const lines = src.split('\n');
let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }
const idx = (re, from = 0) => lines.findIndex((l, i) => i >= from && re.test(l));
/** i 번째 줄을 감싼 가장 가까운 ZW 분기 — 'then'(ZW=1 쪽) / 'else'(ZW≠1 쪽) / null. 한 줄 짜리 "[ \"$ZW\" = 1 ] || …" 도 'else' 로 본다. */
function zwBranch(i) {
  if (/\[ "\$ZW" = 1 \] \|\|/.test(lines[i]) || /\[ "\$ZW" != 1 \] &&/.test(lines[i])) return 'else';
  if (/\[ "\$ZW" = 1 \] &&/.test(lines[i])) return 'then';
  let depth = 0;
  for (let k = i - 1; k >= 0; k--) {
    const l = lines[k].trim();
    if (/^fi\b/.test(l)) depth++;
    else if (/^if\b.*; then$/.test(l)) { if (depth === 0) return /^if \[ "\$ZW" = 1 \]; then$/.test(l) ? 'then' : /^if \[ "\$ZW" != 1 \]; then$/.test(l) ? 'else' : null; depth--; }
    else if (depth === 0 && l === 'else') { for (let m = k - 1, d = 0; m >= 0; m--) { const x = lines[m].trim(); if (/^fi\b/.test(x)) d++; else if (/^if\b.*; then$/.test(x)) { if (d === 0) return /^if \[ "\$ZW" = 1 \]; then$/.test(x) ? 'else' : null; d--; } } return null; }
  }
  return null;
}
const sh = (script, env = {}) => spawnSync('bash', ['-c', script], { encoding: 'utf8', env: { PATH: process.env.PATH, ...env } }).stdout.trim();

t('bash -n 문법', () => { const r = spawnSync('bash', ['-n', SCRIPT], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); });
t('zkwrapper 는 passkey-web 의 화면·인증서·hosts 규칙에 ZW 표시를 더한 모드다 — case 줄보다 먼저 바꾼다', () => {
  const m = idx(/^ZW=0; \[ "\$WALLET_MODE" = zkwrapper \] && \{ ZW=1; WALLET_MODE=passkey-web; \}/), c = idx(/^case "\$WALLET_MODE" in/);
  assert.ok(m >= 0, '모드 바꾸기 줄 없음'); assert.ok(m < c, 'case 줄보다 먼저여야 한다');
  assert.equal(sh(`WALLET_MODE=zkwrapper; ${lines[m]}; echo "$ZW $WALLET_MODE"`), '1 passkey-web');
  assert.equal(sh(`WALLET_MODE=passkey-web; ${lines[m]}; echo "$ZW $WALLET_MODE"`), '0 passkey-web');
});
t('일반 OIDC(비교용)는 zkwrapper 에서 늘 끈다 — zkWrapper 에는 /oidc 가 없다', () => {
  const l = idx(/^\[ "\$ZW" = 1 \] && PLAIN_OIDC=0/), p = idx(/^PLAIN_OIDC="\$\{PLAIN_OIDC:-/); assert.ok(l > p, 'PLAIN_OIDC 기본값 뒤에 있어야 한다');
});
t('IdP VM 에 cia.js 를 띄우지 않는다(열쇠 확인·역할 파일·기동 모두 ZW≠1 쪽)', () => {
  const starts = lines.map((l, i) => [l, i]).filter(([l]) => /on "\$IDP" "cd ~\/zkd-demo && \{ CIA_STATE_FILE=|start_remote "\$IDP" cia\.js|put_env "\$IDP"/.test(l));
  assert.ok(starts.length >= 3, `IdP 기동 관련 줄 ${starts.length}개`);
  for (const [l, i] of starts) assert.equal(zwBranch(i), 'else', `${i + 1}: ${l.trim().slice(0, 90)}`);
});
t('zkWrapper 는 이 PC 에서 mode3_zkwrapper.js 로 뜬다 — 전용 클라이언트 ID·서비스 ID 거부 목록·브라우저용 체인 주소·전용 상태 폴더', () => {
  const i = idx(/node mode3_zkwrapper\.js/); assert.ok(i >= 0, '기동 줄 없음');
  const head = [...lines.slice(0, i)].reverse().find((l) => /^(if|elif) .*; then$/.test(l.trim()));
  assert.equal(head?.trim(), 'elif [ "$WALLET_MODE" = passkey-web ] && [ "$ZW" = 1 ]; then', '기동 줄은 zkwrapper 분기 안에 있어야 한다');
  const blk = lines.slice(Math.max(0, i - 8), i + 1).join('\n');
  for (const s of ['MODE3_OIDC_CLIENT_ID="$ZKWRAPPER_GOOGLE_CLIENT_ID"', 'MODE3_RP_GOOGLE_CLIENT_ID_DENY="$ZW_DENY"', 'MODE3_OIDC_REDIRECT_URI="$GOOGLE_RELAY"', 'CIA_PUBLIC_URL="$WALLET_ORIGIN"',
    'MODE3_CHAIN_RPC_BROWSER="http://127.0.0.1:$APP_PORT"', 'MODE3_REV_RPC_BROWSER="http://127.0.0.1:$REV_PORT"', 'CIA_STATE_FILE="$ZW_DIR/cia_state.json"', 'CIA_KEYS_FILE="$ZW_DIR/cia_keys.json"',
    'MODE3_ZKWRAPPER_PORT=$USER_PORT', 'MODE3_BIND_HOST=0.0.0.0', 'MODE3_TLS_CERT="$TLS_OUT/zkwrapper.crt"', 'DOTENV_CONFIG_PATH="$LOGS/empty.env"']) assert.ok(blk.includes(s), s);
  assert.equal(sh(`ZW=1; ${lines[idx(/^ZW_DIR=/)].replace(/\s#\s.*$/, '')}; echo "$ZW_DIR"`), '.local/zkwrapper', '라이브 IdP 의 cia_keys.json(저장소 루트)과 섞이지 않는 폴더');
});
t('서비스는 발급자를 zkWrapper 로 안다 — 서버끼리는 이 PC 의 IP, 브라우저는 지갑 오리진, 지갑 종류 zkwrapper', () => {
  const d = idx(/^CIA_SRV=/); assert.ok(d >= 0, 'CIA_SRV 정의 없음');
  assert.equal(sh(`SCHEME=https IDP=10.0.0.10 IDP_PORT=4100 HOST=10.0.0.128 USER_PORT=5100 ZW=1; ${lines[d]}; echo "$CIA_SRV"`), 'https://10.0.0.128:5100');
  assert.equal(sh(`SCHEME=https IDP=10.0.0.10 IDP_PORT=4100 HOST=10.0.0.128 USER_PORT=5100 ZW=0; ${lines[d]}; echo "$CIA_SRV"`), 'https://10.0.0.10:4100');
  assert.equal((src.match(/"MODE3_CIA_URL=\$CIA_SRV"/g) ?? []).length, 2, '두 서비스 모두');
  const u = idx(/^\[ "\$ZW" = 1 \] && IDP_UI="\$WALLET_ORIGIN"/); assert.ok(u > idx(/^  RP1_UI="https:\/\/zkone/), '이름 주소를 정한 뒤 IdP 화면 주소를 지갑 오리진으로');
  const k = idx(/^WALLET_KIND_OUT=/); assert.ok(k >= 0 && /MODE3_WALLET_KIND=\$WALLET_KIND_OUT/.test(src), '지갑 종류 전달 없음');
  assert.equal(sh(`WALLET_MODE=passkey-web ZW=1; ${lines[k].replace(/\s#\s.*$/, '')}; echo "$WALLET_KIND_OUT"`), 'zkwrapper'); assert.equal(sh(`WALLET_MODE=passkey-web ZW=0; ${lines[k].replace(/\s#\s.*$/, '')}; echo "$WALLET_KIND_OUT"`), 'passkey-web');
  for (const re of [/rps_json\(\) \{ curl[^\n]*"\$CIA_SRV\/cia\/rps"/, /-X POST -H "\$HDR" "\$CIA_SRV\/cia\/rps\/\$arid\/approve"/]) assert.match(src, re);
});
t('zkWrapper 인증서는 따로 — 지갑 이름·127.0.0.1·이 PC 의 IP(서비스 VM 이 부른다). 지갑 인증서 줄은 그대로', () => {
  const l = lines.find((x) => /zkd_issue_cert[^\n]* zkwrapper wallet\.zkd\.test/.test(x)); assert.ok(l, '발급 줄 없음');
  assert.match(l, /zkwrapper wallet\.zkd\.test 127\.0\.0\.1 "\$HOST"/);
  assert.match(src, /zkd_issue_cert "\$ZKD_CA_DIR" "\$TLS_OUT" wallet wallet\.zkd\.test 127\.0\.0\.1 \\\n/);
});
t('정지 — 5100 의 zkWrapper 도 passkey-web(·zkwrapper) 일 때 내린다', () => {
  assert.match(src, /passkey-web \] && STOP_EXTRA="5100:mode3_user_static\.js 5100:mode3_zkwrapper\.js"/);
});
const zwBlocked = lines.map((l, i) => [l, i]).filter(([l]) => /BLOCKED/.test(l) && /ZKWRAPPER_GOOGLE_CLIENT_ID/.test(l)).map(([, i]) => i);
// 맨 앞에서 실행되는 첫 내림·ssh — 함수 정의 안의 줄(들여 쓴 on …)은 부를 때만 돈다
const firstStop = lines.findIndex((l) => /^stop_remote; stop_local/.test(l)), firstOn = lines.findIndex((l) => /^on "\$/.test(l));
let orderOk = false;
t('사전 검사 — 래퍼 전용 클라이언트 ID 가 없거나 서비스의 것과 같으면 BLOCKED(값은 출력하지 않는다), 내림·ssh 보다 먼저', () => {
  assert.equal(zwBlocked.length, 2, `BLOCKED 줄 ${zwBlocked.length}개`);
  for (const i of zwBlocked) { assert.ok(i < firstStop && i < firstOn, `${i + 1} 이 내림(${firstStop + 1})·ssh(${firstOn + 1}) 보다 뒤`); assert.match(lines[i], /exit 1/); assert.doesNotMatch(lines[i], /echo[^;]*\$ZKWRAPPER_GOOGLE_CLIENT_ID/); }
  orderOk = true;
});
if (!orderOk) console.log('SKIP - 순서 단언이 실패해 스크립트를 실행하지 않는다(라이브 데모 보호)');
else {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsz-'));
  // 방어용 env — 라이브 VM 에 닿지 않게 문서용 주소(192.0.2.0/24)와 없는 ssh 사용자. .env 를 읽지 않게 cwd 는 빈 폴더가 아니라 저장소지만 스크립트가 cd 한다 — 클라이언트 ID 는 env 로만 준다.
  const baseEnv = { PATH: process.env.PATH, HOME: process.env.HOME, DEMO_LOG_DIR: path.join(tmp, 'logs'), SPLIT_SSH_USER: 'nobody', WALLET_MODE: 'zkwrapper',
    SPLIT_HOST_IP: '192.0.2.1', SPLIT_IDP_IP: '192.0.2.10', SPLIT_RP1_IP: '192.0.2.11', SPLIT_RP2_IP: '192.0.2.12', ZKD_CA_DIR: path.join(tmp, 'noca') };
  const run = (env) => spawnSync('bash', [SCRIPT], { encoding: 'utf8', env: { ...baseEnv, ...env }, timeout: 20000, cwd: tmp });
  t('실행 — ZKWRAPPER_GOOGLE_CLIENT_ID 가 없으면 BLOCKED, 종료 1, SPLIT_START 없음', () => {
    const r = run({}); assert.equal(r.status, 1, r.stdout + r.stderr); assert.match(r.stdout, /BLOCKED[^\n]*ZKWRAPPER_GOOGLE_CLIENT_ID/); assert.doesNotMatch(r.stdout, /SPLIT_START|stop /);
  });
  t('실행 — 서비스와 같은 클라이언트 ID 면 BLOCKED, 값은 출력하지 않는다', () => {
    const r = run({ ZKWRAPPER_GOOGLE_CLIENT_ID: 'same-client-123', RP2_GOOGLE_CLIENT_ID: 'same-client-123' });
    assert.equal(r.status, 1, r.stdout + r.stderr); assert.match(r.stdout, /BLOCKED[^\n]*ZKWRAPPER_GOOGLE_CLIENT_ID/); assert.doesNotMatch(r.stdout + r.stderr, /same-client-123/); assert.doesNotMatch(r.stdout, /SPLIT_START/);
  });
  t('실행 — 셸의 MODE3_OIDC_CLIENT_ID(서비스에 공유로 가는 ID)와 같아도 BLOCKED(최종 검토 I-2 b)', () => {
    const r = run({ ZKWRAPPER_GOOGLE_CLIENT_ID: 'shared-777', MODE3_OIDC_CLIENT_ID: 'shared-777' });
    assert.equal(r.status, 1, r.stdout + r.stderr); assert.match(r.stdout, /BLOCKED[^\n]*ZKWRAPPER_GOOGLE_CLIENT_ID/); assert.doesNotMatch(r.stdout + r.stderr, /shared-777/);
  });
  t('실행 — 전용 ID 가 있으면 래퍼 검사를 지나 다음 사전 검사(데모 CA)에서 멈춘다', () => {
    const r = run({ ZKWRAPPER_GOOGLE_CLIENT_ID: 'wrap-client-1', RP1_GOOGLE_CLIENT_ID: 'svc-1', RP2_GOOGLE_CLIENT_ID: 'svc-2' });
    assert.equal(r.status, 1, r.stdout + r.stderr); assert.match(r.stdout, /BLOCKED: 먼저 bash scripts\/zkd_tls_setup\.sh/); assert.doesNotMatch(r.stdout + r.stderr, /wrap-client-1|svc-1|svc-2/);
  });
  fs.rmSync(tmp, { recursive: true, force: true });
}
console.log(fails ? `\n${fails} FAILED` : '\nall ok');
process.exit(fails ? 1 : 0);
