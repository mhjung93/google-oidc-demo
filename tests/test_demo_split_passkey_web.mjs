// scripts/demo_split_start.sh 의 WALLET_MODE=passkey-web 정적 검사(2026-11-17). 분리 데모는 실제 VM·ssh 로만 돌아서 스크립트를 실행하지 않고 줄을 읽어 확인한다.
// 실행은 "사전 검사가 먼저" 순서 단언이 통과했을 때만, 내림·ssh 에 닿기 전에 끝나는 두 경우(잘못된 모드·CA 없음)로 한정한다.
// 이 테스트는 사용자의 라이브 데모를 건드리면 안 된다 — 그래서 순서 단언이 실패하면 스크립트를 아예 부르지 않는다.
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

// 함수 정의 줄·본문과 주석을 뺀 "실행되는" 줄 번호(0부터)
function execLines() {
  const out = [];
  let inFunc = false;
  lines.forEach((ln, i) => {
    if (inFunc) { if (/^\}/.test(ln)) inFunc = false; return; }
    if (/^\s*#/.test(ln)) return;
    if (/^[A-Za-z_0-9]+\(\) \{/.test(ln)) { if (!/\}\s*$/.test(ln)) inFunc = true; return; }
    out.push(i);
  });
  return out;
}
const EXEC = execLines();
const STOP_BRANCH = /"\$\{1:-\}" = "stop"/; // 인자 stop 일 때만 도는 분기 — 이 테스트는 인자 없이 부른다
// 줄 끝 주석(공백 # 공백…)은 빼고 본다 — 설명에 stop_local 같은 이름이 나온다.
const code = (i) => lines[i].replace(/\s#\s.*$/, '');
const firstExec = (re) => EXEC.find((i) => re.test(code(i)) && !STOP_BRANCH.test(lines[i]));

t('bash -n 문법', () => {
  const r = spawnSync('bash', ['-n', SCRIPT], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
});

t('허용값 — case 줄과 오류 문구에 passkey-web', () => {
  const caseLine = lines.find((l) => /^case "\$WALLET_MODE" in/.test(l));
  assert.ok(caseLine, 'case 줄 없음');
  assert.match(caseLine, /passkey-web\)\s*USER_PORT=5100/);
  assert.match(caseLine, /echo "WALLET_MODE 는 web·snap·passkey·passkey-web 중 하나/);
});

t('passkey-web 값 — 터널 끔·https 이름·AGENT_MODE=0', () => {
  assert.match(src, /AGENT_MODE=\$\(\[ "\$WALLET_MODE" = web \] \|\| \[ "\$WALLET_MODE" = passkey-web \]/);
  const blk = src.slice(src.indexOf('if [ "$WALLET_MODE" = passkey-web ]; then\n  SCHEME=https'));
  assert.ok(blk.length > 0 && src.includes('SCHEME=https'), 'passkey-web 값 블록 없음');
  for (const s of ['SPLIT_IDP_TUNNEL=0', 'SPLIT_RP_TUNNEL=0', 'WALLET_ORIGIN="https://wallet.zkd.test:$USER_PORT"', 'IDP_UI="https://idp.zkd.test:$IDP_PORT"',
    'RP1_UI="https://zkone.zkd.test:$RP1_PORT"', 'RP2_UI="https://zktwo.zkd.test:$RP2_PORT"']) assert.ok(blk.includes(s), s);
});

t('사전 검사 — ca.crt·ca.key·hosts 를 보고 BLOCKED 로 종료', () => {
  const i = lines.findIndex((l) => /BLOCKED/.test(l) && /zkd_tls_setup\.sh/.test(l));
  assert.ok(i >= 0, 'BLOCKED 줄 없음');
  const ctx = lines.slice(Math.max(0, i - 2), i + 1).join('\n');
  assert.match(ctx, /ca\.crt/);
  assert.match(ctx, /ca\.key/);
  assert.match(ctx, /getent hosts wallet\.zkd\.test/);
  assert.match(lines[i], /exit 1/);
});

let orderOk = false;
t('사전 검사가 먼저 — BLOCKED 줄 < 첫 stop_remote/stop_local 호출 < 첫 on/ssh/pkill/docker 호출', () => {
  const blocked = lines.findIndex((l) => /BLOCKED/.test(l) && /zkd_tls_setup\.sh/.test(l));
  assert.ok(blocked >= 0, 'BLOCKED 줄 없음');
  const stopCall = firstExec(/\b(stop_remote|stop_local)\b/);
  const remote = firstExec(/\b(ssh|pkill|docker|scp|rsync)\b|(^|[\s;&|({])on "/);
  assert.ok(stopCall !== undefined && remote !== undefined, '기준 줄을 못 찾음');
  assert.ok(blocked < stopCall, `BLOCKED(${blocked + 1}) < stop 호출(${stopCall + 1})`);
  assert.ok(blocked < remote, `BLOCKED(${blocked + 1}) < 원격 호출(${remote + 1})`);
  const start = lines.findIndex((l) => /^echo "SPLIT_START/.test(l));
  assert.ok(blocked < start, 'BLOCKED 가 SPLIT_START 보다 앞');
  orderOk = true;
});

t('개인키를 출력하지 않는다', () => {
  // 주석·scp·chmod 줄은 키 "파일 이름"만 다루므로 뺀다. cat/echo/printf 와 .key 가 한 줄에 있으면 안 된다.
  const bad = lines.map((l, i) => [l, i]).filter(([l]) => !/^\s*#/.test(l) && !/\b(scp|chmod)\b/.test(l) && /(cat|echo|printf)[^\n]*\.key\b/.test(l));
  assert.deepEqual(bad.map(([l, i]) => `${i + 1}: ${l.trim().slice(0, 80)}`), []);
});

t('번들·인증서·VM 배포 줄', () => {
  assert.match(src, /node scripts\/build_user_app\.mjs/);
  assert.match(src, /node scripts\/build_attr_tool\.mjs/);
  assert.match(src, /zkd_issue_cert[^\n]* wallet wallet\.zkd\.test 127\.0\.0\.1 "\$HOST"/);
  for (const [short, dns] of [['idp', 'idp'], ['zkone', 'zkone'], ['zktwo', 'zktwo']]) assert.match(src, new RegExp(`zkd_issue_cert[^\\n]* ${short} ${dns}\\.zkd\\.test`), short);
  assert.match(src, /mkdir -p -m 700 ~\/zkd-demo\/tls/);
  assert.match(src, /MODE3_TLS_CERT=\$1\/zkd-demo\/tls\/\$2\.crt/);
  assert.match(src, /NODE_EXTRA_CA_CERTS=\$1\/zkd-demo\/tls\/ca\.crt/);
  assert.match(src, /MODE3_WALLET_SECRETS=passkey-web/);
  assert.match(src, /"MODE3_CIA_URL=\$SCHEME:\/\/\$IDP:\$IDP_PORT"/);
  assert.match(src, /CIA_PUBLIC_URL=\$SCHEME:\/\/\$IDP:\$IDP_PORT/);
  assert.match(src, /--cacert/);
});

t('기존 모드 보존 — stop_local 의 5100 정적 서버 항목은 passkey-web 일 때만', () => {
  assert.match(src, /passkey-web \] && STOP_EXTRA="5100:mode3_user_static\.js"/);
  assert.match(src, /for spec in "\$APP_PORT:chain\.config\.cjs"[^\n]*"5200:mode3_user_static\.js"/);
});

if (!orderOk) {
  console.log('SKIP - 순서 단언이 실패해 스크립트를 실행하지 않는다(라이브 데모 보호)');
} else {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsp-'));
  const baseEnv = { PATH: process.env.PATH, HOME: process.env.HOME, DEMO_LOG_DIR: path.join(tmp, 'logs') };
  const run = (env) => spawnSync('bash', [SCRIPT], { encoding: 'utf8', env: { ...baseEnv, ...env }, timeout: 20000, cwd: tmp });
  t('실행 — 잘못된 WALLET_MODE 는 종료 1, 문구에 passkey-web', () => {
    const r = run({ WALLET_MODE: 'bogus' });
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /passkey-web/);
    assert.doesNotMatch(r.stdout, /SPLIT_START/);
  });
  t('실행 — passkey-web + 빈 ZKD_CA_DIR 는 BLOCKED, 종료 1, SPLIT_START 이후 없음', () => {
    const ca = fs.mkdtempSync(path.join(tmp, 'ca-'));
    const r = run({ WALLET_MODE: 'passkey-web', ZKD_CA_DIR: ca });
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /BLOCKED/);
    assert.match(r.stdout, /zkd_tls_setup\.sh/);
    assert.doesNotMatch(r.stdout, /SPLIT_START|stop |ABORT|chain /);
  });
  fs.rmSync(tmp, { recursive: true, force: true });
}

console.log(fails ? `\n${fails} FAILED` : '\nall ok');
process.exit(fails ? 1 : 0);
