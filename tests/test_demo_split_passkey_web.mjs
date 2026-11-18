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

const blockedIdx = () => lines.map((l, i) => [l, i]).filter(([l]) => /BLOCKED/.test(l) && !/번들 빌드|snap-mode3/.test(l)).map(([, i]) => i);
t('사전 검사 — CA 파일·VM 주소(IPv4)·CA 이름 제약 망·hosts 를 보고 BLOCKED 로 종료(hosts 검사가 마지막)', () => {
  const b = blockedIdx();
  assert.equal(b.length, 5, `BLOCKED 줄 ${b.length}개`);
  const [caLine, ipLine, netLine, hostsLine, staleLine] = b;
  assert.match(lines[ipLine], /IPv4/);
  const ctx = (i) => lines.slice(Math.max(0, i - 2), i + 1).join('\n');
  assert.match(ctx(caLine), /ca\.crt/); assert.match(ctx(caLine), /ca\.key/); assert.match(lines[caLine], /zkd_tls_setup\.sh/);
  assert.match(lines.slice(caLine, netLine + 1).join('\n'), /openssl x509 -noout -text/);
  assert.match(lines.slice(caLine, netLine + 1).join('\n'), /255\\\.255\\\.255\\\.0/);
  assert.match(lines[netLine], /ZKD_DEMO_NET/);
  assert.match(ctx(hostsLine), /getent hosts/);
  assert.match(lines[hostsLine], /zkd_tls_setup\.sh/);
  assert.match(lines[staleLine], /블록 밖의 옛/);
  assert.match(src, /"127\.0\.0\.1=wallet\.zkd\.test" "\$IDP=idp\.zkd\.test" "\$RP1=zkone\.zkd\.test" "\$RP2=zktwo\.zkd\.test"/);
  for (const i of b) assert.match(lines[i], /exit 1/);
});

t('지갑 인증서 SAN 은 이름과 127.0.0.1 뿐 — $HOST 없음', () => {
  const l = lines.find((x) => /zkd_issue_cert[^\n]* wallet wallet\.zkd\.test/.test(x));
  assert.ok(l, '지갑 발급 줄 없음');
  assert.ok(!/\$HOST|\$\{HOST/.test(l), l.trim());
  assert.match(l, /wallet wallet\.zkd\.test 127\.0\.0\.1( \\)?\s*$/);
});

let orderOk = false;
t('사전 검사가 먼저 — 모든 BLOCKED 줄 < 첫 stop_remote/stop_local 호출 < 첫 on/ssh/pkill/docker 호출', () => {
  const b = blockedIdx();
  assert.ok(b.length >= 4, 'BLOCKED 줄 없음');
  const stopCall = firstExec(/\b(stop_remote|stop_local)\b/);
  const remote = firstExec(/\b(ssh|pkill|docker|scp|rsync)\b|(^|[\s;&|({])on "/);
  assert.ok(stopCall !== undefined && remote !== undefined, '기준 줄을 못 찾음');
  const last = Math.max(...b);
  assert.ok(last < stopCall, `BLOCKED(${last + 1}) < stop 호출(${stopCall + 1})`);
  assert.ok(last < remote, `BLOCKED(${last + 1}) < 원격 호출(${remote + 1})`);
  const start = lines.findIndex((l) => /^echo "SPLIT_START/.test(l));
  assert.ok(last < start, 'BLOCKED 가 SPLIT_START 보다 앞');
  orderOk = true;
});

t('개인키를 출력하지 않는다', () => {
  // 주석·scp·chmod 줄은 키 "파일 이름"만 다루므로 뺀다. cat/echo/printf 와 .key 가 한 줄에 있으면 안 된다.
  const bad = lines.map((l, i) => [l, i]).filter(([l]) => !/^\s*#/.test(l) && !/\b(scp|chmod)\b/.test(l) && /(cat|echo|printf)[^\n]*\.key\b/.test(l));
  assert.deepEqual(bad.map(([l, i]) => `${i + 1}: ${l.trim().slice(0, 80)}`), []);
});

// 2026-11-18(사용자 요청): IdP·서비스 페이지가 passkey-web 에서 "스냅" 을 빼고 그리려면 지갑 모드를 알아야 한다 — 공통 환경변수로 넘긴다.
t('IdP·서비스 공통 환경변수에 지갑 모드(MODE3_WALLET_KIND)', () => {
  const common = src.match(/\nCOMMON="([^"]*)"/);
  assert.ok(common, 'COMMON 정의를 찾지 못했다');
  assert.match(common[1], /^MODE3_WALLET_KIND=\$WALLET_MODE$/m);
  // 속성 도구는 상태 조회를 부르지 않는다 — 리셋 표시 파일에 함께 싣는다.
  assert.match(src, /printf '\{"epoch":"%s","walletKind":"%s"\}\\n' "\$TS" "\$WALLET_MODE" > mode3\/attr\/dist\/reset\.json/);
});
t('번들·인증서·VM 배포 줄', () => {
  assert.match(src, /node scripts\/build_user_app\.mjs/);
  assert.match(src, /node scripts\/build_attr_tool\.mjs/);
  for (const [short, dns] of [['idp', 'idp'], ['zkone', 'zkone'], ['zktwo', 'zktwo']]) assert.match(src, new RegExp(`zkd_issue_cert[^\\n]* ${short} ${dns}\\.zkd\\.test`), short);
  assert.match(src, /mkdir -p -m 700 ~\/zkd-demo\/tls/);
  assert.match(src, /MODE3_TLS_CERT=\$1\/zkd-demo\/tls\/\$2\.crt/);
  assert.match(src, /NODE_EXTRA_CA_CERTS=\$1\/zkd-demo\/tls\/ca\.crt/);
  assert.match(src, /MODE3_WALLET_SECRETS=passkey-web/);
  assert.match(src, /"MODE3_CIA_URL=\$SCHEME:\/\/\$IDP:\$IDP_PORT"/);
  assert.match(src, /CIA_PUBLIC_URL=\$SCHEME:\/\/\$IDP:\$IDP_PORT/);
  assert.match(src, /--cacert/);
});

t('정적 서버에 TTL·높이 격자를 넘긴다, scp 는 타임아웃·BatchMode', () => {
  const l = lines.find((x) => /MODE3_WALLET_SECRETS=passkey-web/.test(x));
  assert.match(l, /MODE3_TTL_BLOCKS="\$\{TTL_BLOCKS:-5\}"/);
  assert.match(src, /passkey-web[^\n]*\n[^\n]*MODE3_HEIGHT_GRID="\$\{HEIGHT_GRID:-5\}"/);
  assert.match(src, /scp -q -o BatchMode=yes -o ConnectTimeout=5/);
  assert.match(src, /chmod 700 ~\/zkd-demo\/tls/);
});

t('기존 모드 보존 — stop_local 의 5100 정적 서버 항목은 passkey-web 일 때만', () => {
  assert.match(src, /passkey-web \] && STOP_EXTRA="5100:mode3_user_static\.js"/);
  assert.match(src, /for spec in "\$APP_PORT:chain\.config\.cjs"[^\n]*"5200:mode3_user_static\.js"/);
});

if (!orderOk) {
  console.log('SKIP - 순서 단언이 실패해 스크립트를 실행하지 않는다(라이브 데모 보호)');
} else {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsp-'));
  // 방어용 env — 나중에 순서가 깨져도 라이브 VM(.10/.11/.12)에 닿지 않게 문서용 주소(192.0.2.0/24)와 없는 ssh 사용자를 쓴다.
  const baseEnv = { PATH: process.env.PATH, HOME: process.env.HOME, DEMO_LOG_DIR: path.join(tmp, 'logs'), SPLIT_SSH_USER: 'nobody',
    SPLIT_HOST_IP: '192.0.2.1', SPLIT_IDP_IP: '192.0.2.10', SPLIT_RP1_IP: '192.0.2.11', SPLIT_RP2_IP: '192.0.2.12' };
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
  t('실행 — VM 주소가 CA 이름 제약 망 밖이면 BLOCKED, 종료 1, SPLIT_START 이후 없음', () => {
    const ca = fs.mkdtempSync(path.join(tmp, 'ca-net-'));
    const mk = spawnSync('bash', ['-c', 'source scripts/zkd_tls_lib.sh; zkd_ca_create "$1" 10.9.8.0', 'x', ca], { encoding: 'utf8', cwd: new URL('..', import.meta.url).pathname });
    assert.equal(mk.status, 0, mk.stderr);
    const r = run({ WALLET_MODE: 'passkey-web', ZKD_CA_DIR: ca });
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /BLOCKED[^\n]*이름 제약 망/);
    assert.match(r.stdout, /\(10\.9\.8\.0\/24\)/, 'CA 망 파싱이 비면(없음) fail-closed 만 확인될 뿐 비교는 검증되지 않는다');
    assert.match(r.stdout, /ZKD_DEMO_NET/);
    assert.doesNotMatch(r.stdout, /SPLIT_START|stop |ABORT|chain /);
  });
  t('실행 — SPLIT_*_IP 가 IPv4 가 아니면 BLOCKED, 종료 1', () => {
    const ca = fs.mkdtempSync(path.join(tmp, 'ca-ip-'));
    const mk = spawnSync('bash', ['-c', 'source scripts/zkd_tls_lib.sh; zkd_ca_create "$1" 192.0.2.0', 'x', ca], { encoding: 'utf8', cwd: new URL('..', import.meta.url).pathname });
    assert.equal(mk.status, 0, mk.stderr);
    const r = run({ WALLET_MODE: 'passkey-web', ZKD_CA_DIR: ca, SPLIT_IDP_IP: '192.0.2.x' });
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /BLOCKED[^\n]*IPv4/);
    assert.doesNotMatch(r.stdout, /SPLIT_START|stop |ABORT|chain /);
  });
  t('실행 — CA 망은 맞아도 hosts 이름이 현재 주소와 다르면 BLOCKED, 종료 1', () => {
    // 문서용 망(192.0.2.0/24)이라 개발 PC 의 실제 /etc/hosts(.226 망)와는 반드시 어긋난다 — 이름 하나에서 멈춘다
    const ca = fs.mkdtempSync(path.join(tmp, 'ca-hosts-'));
    const mk = spawnSync('bash', ['-c', 'source scripts/zkd_tls_lib.sh; zkd_ca_create "$1" 192.0.2.0', 'x', ca], { encoding: 'utf8', cwd: new URL('..', import.meta.url).pathname });
    assert.equal(mk.status, 0, mk.stderr);
    // 개발 PC 의 hosts 가 우연히 192.0.2.x 로 풀면 사전검사를 다 통과해 라이브 로컬 데모를 내린다(stop_local) —
    // 그래서 getent 를 항상 빈 결과로 가짜로 바꿔, 실제 hosts 와 무관하게 wallet 검사에서 반드시 멈추게 한다.
    const fake = fs.mkdtempSync(path.join(tmp, 'fakegetent-'));
    fs.writeFileSync(path.join(fake, 'getent'), '#!/bin/sh\nexit 2\n', { mode: 0o755 });
    const r = run({ WALLET_MODE: 'passkey-web', ZKD_CA_DIR: ca, PATH: `${fake}:${process.env.PATH}` });
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /BLOCKED[^\n]*wallet\.zkd\.test/);
    assert.doesNotMatch(r.stdout, /SPLIT_START|stop |ABORT|chain /);
  });
  fs.rmSync(tmp, { recursive: true, force: true });
}

console.log(fails ? `\n${fails} FAILED` : '\nall ok');
process.exit(fails ? 1 : 0);
