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
    // if [ "$ZW" = 1 ] … elif …: elif 갈래는 ZW 가 아닌 쪽이다(2026-11-21)
    else if (depth === 0 && /^elif\b.*; then$/.test(l)) { for (let m = k - 1, d = 0; m >= 0; m--) { const x = lines[m].trim(); if (/^fi\b/.test(x)) d++; else if (/^if\b.*; then$/.test(x)) { if (d === 0) return /^if \[ "\$ZW" = 1 \]; then$/.test(x) ? 'else' : null; d--; } } return null; }
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
t('zkWrapper 인증서는 따로 — zkwrapper 이름·127.0.0.1·이 PC 의 IP(서비스 VM 이 부른다). 지갑 인증서 줄은 그대로', () => {
  const l = lines.find((x) => /zkd_issue_cert[^\n]* zkwrapper zkwrapper\.zkd\.test/.test(x)); assert.ok(l, '발급 줄 없음');
  assert.match(l, /zkwrapper zkwrapper\.zkd\.test 127\.0\.0\.1 "\$HOST"/);
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
// 최종 검토 M-4(2026-11-21): zkwrapper 모드는 IdP VM 을 쓰지 않는다 — 그 VM 에 닿는 줄(ssh·인증서·상태 백업·동기화·주소 확인)은 모두 ZW 가 아닐 때만 돈다.
t('zkwrapper 모드는 IdP VM 에 닿지 않는다 — "$IDP" 를 부르는 줄은 모두 ZW 가 아닌 갈래(또는 같은 줄의 [ "$ZW" = 1 ] || )에 있다', () => {
  const touch = lines.map((l, i) => [l, i]).filter(([l]) => !/^\s*#/.test(l) && /(on|deploy_tls) "\$IDP"|"\$IDP" "\$RP1"|"\$IDP=idp\.zkd\.test"|idp idp\.zkd\.test|"\$U@\$IDP"/.test(l));
  assert.ok(touch.length >= 6, `찾은 줄이 너무 적다: ${touch.length}`);
  // IdP 터널(if [ "$SPLIT_IDP_TUNNEL" != 0 ])은 passkey-web 이 0 으로 끈다 — zkwrapper 는 passkey-web 으로 바뀐 뒤라 그 갈래에 들어가지 않는다
  const inTunnel = (i) => { for (let k = i - 1; k >= 0; k--) { const x = lines[k].trim(); if (/^fi\b/.test(x)) return false; if (/^if\b.*; then$/.test(x)) return x === 'if [ "$SPLIT_IDP_TUNNEL" != 0 ]; then'; } return false; };
  const off = idx(/SCHEME=https; SPLIT_IDP_TUNNEL=0;/), zw = idx(/^ZW=0; \[ "\$WALLET_MODE" = zkwrapper \]/); assert.ok(off > zw && zw >= 0, 'zkwrapper 를 passkey-web 으로 바꾼 뒤에 터널을 끈다');
  for (const [l, i] of touch) if (!inTunnel(i)) assert.equal(zwBranch(i), 'else', `${i + 1}: ${l.trim().slice(0, 100)}`);
});
t('zkwrapper 모드의 안내문은 /user(래퍼에서는 403)를 가리키지 않는다', () => {
  const bad = lines.map((l, i) => [l, i]).filter(([l]) => /^\s*echo .*\/user\b/.test(l) && !/\/user\/config/.test(l));
  for (const [l, i] of bad) assert.equal(zwBranch(i), 'else', `${i + 1}: ${l.trim().slice(0, 100)}`);
  const pend = idx(/echo "RP 등록 \$N 건 — 인증서 대기/); assert.ok(pend >= 0); assert.ok(lines[pend].includes('$IDP_PAGE/rp'), '운영자 화면은 사람이 여는 주소(IDP_PAGE — zkwrapper 면 zkWrapper 서버)로');
});
t('zkWrapper 기동에 폐기 게시 간격(CIA_REVOKE_PUBLISH_AFTER_BLOCKS)이 넘어간다 — 보통 방식과 같은 기본값 3', () => {
  const i = idx(/node mode3_zkwrapper\.js/); const blk = lines.slice(Math.max(0, i - 8), i + 1).join('\n');
  assert.ok(blk.includes('CIA_REVOKE_PUBLISH_AFTER_BLOCKS="${REVOKE_PUBLISH_AFTER:-3}"'), blk);
});
// 2026-11-21(실제 기동 셀프 피드백): zkwrapper 로 띄웠더니 "공유 ID 를 IdP 에 넘긴다"·"zkIdP 패스키 가입: on" 이 찍혔다 — IdP 가 없는 모드다.
// 공유 ID 는 전용 ID 가 없는 서비스로만 간다. 그 구간(oidc_client_id ~ 패스키 가입 줄)을 잘라 가짜 .env 가 있는 임시 폴더에서 돌린다.
t('zkwrapper 모드의 Google 안내 — IdP 를 말하지 않고, 공유 ID 경고는 그것을 받는 서비스 이름을 댄다', () => {
  const a = idx(/^oidc_client_id\(\) \{/), b = idx(/zkIdP 패스키 가입\(Google 이메일\)/);
  assert.ok(a >= 0 && b > a, '구간을 못 찾았다');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zw-oidc-'));
  try {
    fs.writeFileSync(path.join(dir, '.env'), 'GOOGLE_CLIENT_ID=test-shared-id\n');
    const body = lines.slice(a, b + 1).join('\n');
    const run = (env) => spawnSync('bash', ['-c', body], { cwd: dir, encoding: 'utf8', env: { PATH: process.env.PATH, USER_PORT: '5100', WALLET_MODE: 'passkey-web', ...env } }).stdout;
    const zw = run({ ZW: '1' });
    assert.equal(/IdP 에 넘긴다|zkIdP 패스키 가입|OIDC\(Google\)/.test(zw), false, zw);
    assert.match(zw, /서비스\(zkONE·zkTWO\)에 넘긴다/, zw);
    assert.match(run({ ZW: '1', RP2_GOOGLE_CLIENT_ID: 'rp2-id' }), /서비스\(zkONE\)에 넘긴다/);
    assert.equal(/공유 클라이언트 ID/.test(run({ ZW: '1', RP1_GOOGLE_CLIENT_ID: 'rp1-id', RP2_GOOGLE_CLIENT_ID: 'rp2-id' })), false, '두 서비스 모두 전용 ID 면 공유 ID 를 받는 곳이 없다');
    assert.equal(/test-shared-id/.test(zw), false, '값은 출력하지 않는다');
    assert.equal(/\.env 의 GOOGLE_CLIENT_ID/.test(run({ ZW: '1', MODE3_OIDC_CLIENT_ID: 'shell-id' })), false, '셸이 ID 를 주면 .env 를 쓰지 않는다');
    const plain = run({ ZW: '0' });
    assert.match(plain, /OIDC\(Google\): on/); assert.match(plain, /IdP 에 넘긴다/); assert.match(plain, /zkIdP 패스키 가입\(Google 이메일\): off/, '공유 ID 하나뿐이면 서비스와 같은 ID 라 패스키 가입은 꺼진다(C2, 2026-11-22)');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
// C2(2026-11-22): 보통 passkey-web 에서도 zkIdP 가 서비스와 같은 Google ID 로 패스키 가입을 열면 악의적 서비스가 피해자 Google 계정의 zkIdP 계정을 선점한다.
// 스크립트는 서비스가 받는 ID 목록을 zkIdP 에 넘기고(MODE3_RP_GOOGLE_CLIENT_ID_DENY — cia.js 가 그 ID 면 가입을 닫는다), 안내 줄도 그 판단과 같게 찍는다.
t('보통 passkey-web: 서비스 ID 목록을 zkIdP 에 넘기고, 같은 ID 면 패스키 가입 off 와 이유를 찍는다 — 값은 출력하지 않는다', () => {
  const a = idx(/^oidc_client_id\(\) \{/), b = idx(/zkIdP 패스키 가입\(Google 이메일\)/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zw-oidc-'));
  try {
    fs.writeFileSync(path.join(dir, '.env'), 'GOOGLE_CLIENT_ID=test-shared-id\n');
    const body = lines.slice(a, b + 1).join('\n');
    const run = (env) => { const r = spawnSync('bash', ['-c', `${body}\necho "@@DENY=$IDP_DENY_LINE"`], { cwd: dir, encoding: 'utf8', env: { PATH: process.env.PATH, USER_PORT: '5100', WALLET_MODE: 'passkey-web', ZW: '0', ...env } }).stdout; const [out, deny] = r.split('@@DENY='); return { out, deny: deny.trim() }; };
    let r = run({});
    assert.match(r.out, /zkIdP 패스키 가입\(Google 이메일\): off \(서비스와 같은 Google 클라이언트 ID/, r.out);
    assert.equal(r.deny, 'MODE3_RP_GOOGLE_CLIENT_ID_DENY=test-shared-id');
    assert.equal(/test-shared-id/.test(r.out), false, '값은 출력하지 않는다');
    r = run({ RP1_GOOGLE_CLIENT_ID: 'rp1-id', RP2_GOOGLE_CLIENT_ID: 'rp2-id' });
    assert.match(r.out, /zkIdP 패스키 가입\(Google 이메일\): on/, '두 서비스가 전용 ID 면 zkIdP 의 공유 ID 는 서비스와 겹치지 않는다');
    assert.equal(r.deny, 'MODE3_RP_GOOGLE_CLIENT_ID_DENY=rp1-id,rp2-id');
    r = run({ RP2_GOOGLE_CLIENT_ID: 'rp2-id' });
    assert.match(r.out, /: off \(서비스와 같은/, 'zkONE 이 zkIdP 와 같은 공유 ID 를 받는다');
    assert.equal(r.deny, 'MODE3_RP_GOOGLE_CLIENT_ID_DENY=rp2-id,test-shared-id');
    r = run({ ZW: '1' });
    assert.equal(r.deny, '', 'zkwrapper 에는 IdP 가 없다 — 이 줄을 만들지 않는다');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// 2026-11-22(11-18 리뷰 3번): 기동 때 VM 시계를 재서 30초(CLOCK_SKEW_WARN_SECONDS)를 넘게 어긋나면 경고한다 — ssh(on)는 가짜로 바꿔 돌린다.
t('VM 시계가 어긋나면 기동 때 경고한다 — 어긋나지 않으면 조용하고, zkwrapper 에는 IdP VM 이 없다', () => {
  const a = idx(/^CLOCK_VMS=\(/), b = idx(/^done; unset _vm_t _here_t _skew CLOCK_VMS/);
  assert.ok(a >= 0 && b > a, '구간을 못 찾았다');
  const body = lines.slice(a, b + 1).join('\n');
  const run = (offsets, env = {}) => spawnSync('bash', ['-c', `on() { case "$1" in ${Object.entries(offsets).map(([h, o]) => `${h}) echo $(( $(date +%s) + (${o}) ));;`).join(' ')} *) return 1;; esac; }\n${body}`],
    { encoding: 'utf8', env: { PATH: process.env.PATH, IDP: 'vm-idp', RP1: 'vm-rp1', RP2: 'vm-rp2', ZW: '0', ...env } }).stdout;
  let out = run({ 'vm-idp': 0, 'vm-rp1': 1, 'vm-rp2': -2 });
  assert.equal(out.trim(), '', out);
  out = run({ 'vm-idp': 0, 'vm-rp1': 400, 'vm-rp2': -90 });
  assert.match(out, /VM vm-rp1 의 시계가 이 PC 와 40[0-9]초 어긋난다/, out); assert.match(out, /VM vm-rp2 의 시계가 이 PC 와 9[0-9]초 어긋난다/, out);
  assert.equal(/vm-idp/.test(out), false, out);
  out = run({ 'vm-rp1': 0, 'vm-rp2': 0 }, { ZW: '1' });
  assert.equal(out.trim(), '', 'zkwrapper 는 IdP VM 을 재지 않는다: ' + out);
  out = run({ 'vm-rp1': 0, 'vm-rp2': 0 });
  assert.match(out, /VM vm-idp 의 시계를 읽지 못했다/, out);
});

// 2026-11-23(사용자 요청): 서비스의 "옛 증명으로 보내기(시연)" — 분리 데모는 기본으로 켜고(RELAY_DEMO_REVERT=0 이면 끔), 두 서비스가 같은 COMMON 으로 받는다.
t('서비스 공통 환경변수에 옛 증명 시연 스위치(MODE3_RELAY_DEMO_REVERT, 기본 1)', () => {
  const common = src.match(/\nCOMMON="([^"]*)"/); assert.ok(common, 'COMMON 정의를 찾지 못했다');
  assert.match(common[1], /^MODE3_RELAY_DEMO_REVERT=\$\{RELAY_DEMO_REVERT:-1\}$/m);
  assert.match(src, /^#.*RELAY_DEMO_REVERT=0 bash scripts\/demo_split_start\.sh/m, '사용법 주석이 없다');
});

t('zkwrapper 의 이름은 zkwrapper.zkd.test — 주소·hosts 확인·인증서. passkey-web 은 wallet.zkd.test 그대로(2026-11-25)', () => {
  const w = idx(/^\[ "\$ZW" = 1 \] && WALLET_ORIGIN=/), u = idx(/^\[ "\$ZW" = 1 \] && IDP_UI="\$WALLET_ORIGIN"/), b = idx(/^  WALLET_ORIGIN="https:\/\/wallet\.zkd\.test:/);
  assert.ok(b >= 0 && b < w && w < u, `순서: ${b} ${w} ${u}`);
  const origin = (zw) => sh(`USER_PORT=5100 ZW=${zw} WALLET_ORIGIN=https://wallet.zkd.test:5100; ${lines[w]}; echo "$WALLET_ORIGIN"`);
  assert.equal(origin(1), 'https://zkwrapper.zkd.test:5100'); assert.equal(origin(0), 'https://wallet.zkd.test:5100');
  const p = lines.find((l) => /PAIRS=\(/.test(l));
  const pairs = (zw) => sh(`ZW=${zw} IDP=10.0.0.10 RP1=10.0.0.11 RP2=10.0.0.12; ${p}; echo "\${PAIRS[*]}"`);
  assert.equal(pairs(1), '127.0.0.1=zkwrapper.zkd.test 10.0.0.11=zkone.zkd.test 10.0.0.12=zktwo.zkd.test'); assert.ok(pairs(0).startsWith('127.0.0.1=wallet.zkd.test 10.0.0.10=idp.zkd.test'));
  assert.ok(src.includes('"$TLS_OUT" zkwrapper zkwrapper.zkd.test 127.0.0.1 "$HOST"'), '인증서 이름');
  assert.ok(/zkd_hosts_render \/etc\/hosts .*"127\.0\.0\.1=zkwrapper\.zkd\.test"/.test(fs.readFileSync(new URL('../scripts/zkd_tls_setup.sh', import.meta.url), 'utf8')), 'setup 의 hosts 목록');
});
t('폐기 체인 Blockscout(:4001) — 체인을 새로 만든 뒤 초기화하고(BLOCKSCOUT_RCL=0 이면 안 함) 실패해도 계속한다; 덮어쓰기는 폐기 체인만 가리킨다(2026-11-25)', () => {
  const i = idx(/bash scripts\/blockscout_rcl\.sh reset/), c = idx(/^start_chain \$REV_PORT/); assert.ok(c >= 0 && i > c, `순서: ${c} ${i}`);
  assert.ok(/BLOCKSCOUT_RCL:-1\}" != 0/.test(lines[i - 1]) && /BLOCKSCOUT_RESET:-1\}" != 0/.test(lines[i - 1]), lines[i - 1]); assert.ok(/WARN Blockscout\(RCL\)/.test(lines[i]) && !/exit/.test(lines[i]), lines[i]);
  const o = fs.readFileSync(new URL('../scripts/blockscout_rcl.compose.yml', import.meta.url), 'utf8').split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');
  assert.ok(!/8547|31339|:4000/.test(o), '응용 체인을 가리킨다'); assert.ok(o.includes('127.0.0.1:4001:80') && (o.match(/8548/g) ?? []).length >= 4 && o.includes('31340')); assert.ok(!/SECRET|PASSWORD|DATABASE_URL|external:|container_name/.test(o));
});
t('폐기 체인 Blockscout — 다른 스택과 볼륨·네트워크 이름을 나눠 쓰면 지우지도 띄우지도 않는다(가짜 docker)', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'zkd-bs-')); fs.mkdirSync(path.join(d, 'scripts')); fs.mkdirSync(path.join(d, 'bin')); fs.mkdirSync(path.join(d, '.local/blockscout'), { recursive: true }); fs.writeFileSync(path.join(d, '.local/blockscout/compose.yml'), '');
  for (const f of ['blockscout_rcl.sh', 'blockscout_rcl.compose.yml']) fs.copyFileSync(new URL(`../scripts/${f}`, import.meta.url), path.join(d, 'scripts', f));
  fs.writeFileSync(path.join(d, 'bin/docker'), '#!/bin/bash\necho "$@" >> "$CALLS"\nfor a in "$@"; do [ "$a" = config ] && { cat "$CFG"; exit "${CFG_EXIT:-0}"; }; done\nexit 0\n', { mode: 0o755 });
  const run = (cmd, cfg, env = {}) => { const calls = path.join(d, 'calls'); fs.rmSync(calls, { force: true }); fs.writeFileSync(path.join(d, 'cfg'), cfg); const r = spawnSync('bash', [path.join(d, 'scripts/blockscout_rcl.sh'), cmd], { encoding: 'utf8', env: { PATH: `${path.join(d, 'bin')}:${process.env.PATH}`, CALLS: calls, CFG: path.join(d, 'cfg'), ...env } }); return { code: r.status, out: r.stdout + r.stderr, calls: fs.existsSync(calls) ? fs.readFileSync(calls, 'utf8') : '' }; };
  const good = 'services:\n  db: {}\nnetworks:\n  default:\n    name: zkid-blockscout-rcl_default\nvolumes:\n  db-data:\n    name: zkid-blockscout-rcl_db-data\n';
  try {
    const ok = run('reset', good); assert.equal(ok.code, 0, ok.out); assert.match(ok.calls, /-p zkid-blockscout-rcl .* down -v/); const up = ok.calls.split('\n').find((l) => / up -d /.test(l)); assert.ok(up.includes('proxy-rcl') && !/ proxy( |$)/.test(up), `바탕 proxy(:4000)를 띄운다: ${up}`);
    for (const [name, cfg, env] of [['응용 체인 볼륨', good.replace('zkid-blockscout-rcl_db-data', 'zkid-blockscout_db-data')], ['external', `${good}    external: true\n`], ['고정 컨테이너 이름', `${good}    container_name: x\n`], ['이름 없음', 'services: {}\n'], ['설정 풀기 실패', good, { CFG_EXIT: '1' }]])
      for (const cmd of ['reset', 'down', 'up']) { const r = run(cmd, cfg, env); assert.notEqual(r.code, 0, `${name} ${cmd}`); assert.ok(!/ down | up -d/.test(r.calls), `${name} ${cmd}: ${r.calls}`); }
    const same = run('reset', good, { BLOCKSCOUT_RCL_PROJECT: 'zkid-blockscout' }); assert.notEqual(same.code, 0); assert.equal(same.calls, '', '프로젝트 이름이 같은데 docker 를 불렀다');
    fs.rmSync(path.join(d, '.local'), { recursive: true }); const none = run('reset', good); assert.equal(none.code, 0); assert.equal(none.calls, '');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});
t('속성 도구의 리셋 표시(reset.json)는 래퍼면 walletKind zkwrapper — 도구가 이 값으로 화면 모드를 다시 정한다(2026-11-25)', () => {
  const i = idx(/^if \[ "\$AGENT_MODE" = 1 \] \|\| \[ "\$WALLET_MODE" = passkey-web \]; then mkdir -p mode3\/attr\/dist/); assert.ok(i >= 0, 'reset.json 쓰는 줄 없음');
  const kind = lines[i].match(/"\$TS" ("\$\(.*?\)")/)?.[1]; assert.ok(kind, lines[i].slice(0, 200));
  assert.equal(sh(`WALLET_MODE=passkey-web ZW=1; echo ${kind}`), 'zkwrapper');
  assert.equal(sh(`WALLET_MODE=passkey-web ZW=0; echo ${kind}`), 'passkey-web');
});

console.log(fails ? `\n${fails} FAILED` : '\nall ok');
process.exit(fails ? 1 : 0);
