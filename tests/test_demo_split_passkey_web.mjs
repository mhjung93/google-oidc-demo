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

// zkwrapper 의 래퍼 전용 클라이언트 ID 사전 검사(2026-11-20)는 tests/test_demo_split_zkwrapper.mjs 가 따로 본다 — 여기서는 passkey-web 공통의 다섯 개만 센다
const blockedIdx = () => lines.map((l, i) => [l, i]).filter(([l]) => /BLOCKED/.test(l) && !/번들 빌드|snap-mode3|ZKWRAPPER_GOOGLE_CLIENT_ID/.test(l)).map(([, i]) => i);
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
  // 2026-11-20: zkwrapper 는 모드를 passkey-web 으로 두고 ZW 표시로 가르므로, 넘기는 값은 그 표시를 보고 zkwrapper 로 고친다(그 밖은 지금처럼 $WALLET_MODE)
  assert.match(common[1], /^MODE3_WALLET_KIND=\$WALLET_KIND_OUT$/m); assert.match(src, /^WALLET_KIND_OUT="\$WALLET_MODE"; \[ "\$ZW" = 1 \] && WALLET_KIND_OUT=zkwrapper/m);
  // 속성 도구는 상태 조회를 부르지 않는다 — 리셋 표시 파일에 함께 싣는다.
  assert.match(src, /printf '\{"epoch":"%s","walletKind":"%s"\}\\n' "\$TS" "\$\(\[ "\$ZW" = 1 \] && echo zkwrapper \|\| echo "\$WALLET_MODE"\)" > mode3\/attr\/dist\/reset\.json/);   // 2026-11-25: 래퍼면 zkwrapper, 그 밖은 WALLET_MODE 그대로
});
// 2026-11-18(스펙 2026-11-18-blockscout-auto-verify): Blockscout 초기화는 화면에 보이는 스택(compose 프로젝트 zkid-blockscout)에 걸고, 자동 검증 감시자를 띄우고 내린다.
// 2026-11-19(스펙 passkey-proof-login L1): passkey-web 의 발급 정책 기본값은 key — 등록된 지갑은 인증 창 없이 패스키 증명으로 로그인한다. 에이전트 모드(snap·passkey)는 code 그대로.
t('발급 정책 기본값 — 에이전트 모드만 code, passkey-web·web 은 key(ISSUE_AUTH 로 덮을 수 있다)', () => {
  const ln = lines.find((l) => l.includes('CIA_ISSUE_AUTH=${ISSUE_AUTH:-'));
  assert.ok(ln, 'CIA_ISSUE_AUTH 기본값 줄을 찾지 못했다');
  const expr = ln.match(/CIA_ISSUE_AUTH=\$\{ISSUE_AUTH:-(\$\([^)]*\))\}/);
  assert.ok(expr, 'CIA_ISSUE_AUTH=${ISSUE_AUTH:-$(…)} 모양이 아니다');
  const policy = (agentMode, walletMode) => spawnSync('bash', ['-c', `AGENT_MODE=${agentMode} WALLET_MODE=${walletMode}; echo ${expr[1]}`], { encoding: 'utf8' }).stdout.trim();
  assert.equal(policy(0, 'passkey-web'), 'key');
  assert.equal(policy(0, 'web'), 'key');
  assert.equal(policy(1, 'snap'), 'code');
  assert.equal(policy(1, 'passkey'), 'code');
});
// 2026-11-19(스펙 oidc-comparison C1·C7): 일반 OIDC(비교용)는 passkey-web 에서만 기본으로 켜고, IdP·서비스에 같은 값을 넘긴다.
t('일반 OIDC(비교용) — passkey-web 에서만 기본 켬, IdP(CIA_PLAIN_OIDC)·서비스(MODE3_RP_ZKOIDC)에 같은 값', () => {
  const ln = lines.find((l) => /^PLAIN_OIDC="\$\{PLAIN_OIDC:-/.test(l));
  assert.ok(ln, 'PLAIN_OIDC 기본값 줄을 찾지 못했다');
  const expr = ln.match(/^PLAIN_OIDC="\$\{PLAIN_OIDC:-(\$\([^)]*\))\}"/);
  assert.ok(expr, 'PLAIN_OIDC="${PLAIN_OIDC:-$(…)}" 모양이 아니다');
  // 2026-11-20: Google 클라이언트 ID 가 있으면(GOOGLE_ID_SET=1 — 서비스의 Google 로그인이 켜진다) 일반 OIDC 장면은 Google 로 보이므로 기본으로 끈다
  const on = (walletMode, google = 0) => spawnSync('bash', ['-c', `WALLET_MODE=${walletMode}; GOOGLE_ID_SET=${google}; echo ${expr[1]}`], { encoding: 'utf8' }).stdout.trim();
  assert.equal(on('passkey-web'), '1'); assert.equal(on('snap'), '0'); assert.equal(on('web'), '0'); assert.equal(on('passkey'), '0');
  assert.equal(on('passkey-web', 1), '0', 'Google 이 있으면 기본으로 끈다'); assert.equal(on('snap', 1), '0');
  const gi = lines.findIndex((l) => l.startsWith('GOOGLE_ID_SET=0')), pi = lines.findIndex((l) => l.startsWith('PLAIN_OIDC="${PLAIN_OIDC:-'));
  assert.ok(gi >= 0 && gi < pi, 'GOOGLE_ID_SET 은 PLAIN_OIDC 기본값보다 먼저 정한다');
  const gl = lines[gi + 1];
  const google = (env, dotenv) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'zkd-gid-')); try { if (dotenv !== null) fs.writeFileSync(path.join(d, '.env'), dotenv); return spawnSync('bash', ['-c', `GOOGLE_ID_SET=0; ${gl}; echo $GOOGLE_ID_SET`], { encoding: 'utf8', cwd: d, env: { PATH: process.env.PATH, ...env } }).stdout.trim(); } finally { fs.rmSync(d, { recursive: true, force: true }); } };
  assert.equal(google({}, null), '0'); assert.equal(google({}, 'OTHER=1\nGOOGLE_CLIENT_ID=\n'), '0', '빈 값은 없는 것');
  assert.equal(google({}, 'GOOGLE_CLIENT_ID=abc\n'), '1'); assert.equal(google({ MODE3_OIDC_CLIENT_ID: 'x' }, null), '1'); assert.equal(google({ RP1_GOOGLE_CLIENT_ID: 'x' }, null), '1');
  assert.equal(google({ OIDC: '0' }, 'GOOGLE_CLIENT_ID=abc\n'), '0', 'OIDC=0 이면 .env 의 ID 를 쓰지 않는다'); assert.equal(google({ OIDC: '0', RP2_GOOGLE_CLIENT_ID: 'x' }, null), '1');
  assert.ok(lines.includes('CIA_PLAIN_OIDC=$PLAIN_OIDC') && lines.includes('MODE3_RP_ZKOIDC=$PLAIN_OIDC'), '공통 환경변수에 두 값이 없다');
});
t('Blockscout — 초기화는 프로젝트 이름을 주고(B1), 감시자는 pid 파일로 띄우고 내린다(B10)', () => {
  assert.match(src, /^BS_PROJECT="\$\{BLOCKSCOUT_PROJECT:-zkid-blockscout\}"$/m);
  const compose = lines.filter((l) => /docker compose/.test(l) && !/^\s*#/.test(l));
  assert.ok(compose.length >= 1, 'docker compose 줄 없음');
  for (const l of compose) assert.equal((l.match(/docker compose/g) ?? []).length, (l.match(/docker compose -p "\$BS_PROJECT"/g) ?? []).length, `프로젝트 이름 없는 docker compose: ${l.trim().slice(0, 80)}`);
  assert.match(src, /down -v/); assert.match(src, /up -d/);
  // 띄우기: BLOCKSCOUT_VERIFY=0 이면 띄우지 않는다. pid 를 $LOGS/blockscout_verify.pid 에 적는다.
  assert.match(src, /\$\{BLOCKSCOUT_VERIFY:-1\}" != 0/);
  assert.match(src, /setsid nohup node scripts\/blockscout_verify_watch\.mjs > "\$LOGS\/blockscout_verify\.log" 2>&1 < \/dev\/null &\s*\n?\s*echo \$! > "\$BS_VERIFY_PID"/);
  // 내리기: 감시자는 포트를 듣지 않아 stop_local 의 포트 목록으로는 못 찾는다 — pid 파일의 pid 를 명령줄을 확인한 뒤에만 내린다.
  const stopWatch = src.match(/\nstop_verify_watch\(\) \{[\s\S]*?\n\}/);
  assert.ok(stopWatch, 'stop_verify_watch 함수 없음');
  assert.match(stopWatch[0], /\/proc\/\$pid\/cmdline/); assert.match(stopWatch[0], /grep -qF -- "blockscout_verify_watch\.mjs"/); assert.match(stopWatch[0], /rm -f "\$BS_VERIFY_PID"/);
  // 2026-11-18(증명 기록의 거래 링크): Blockscout 가 있으면 정적 서버(web·passkey-web)에 탐색기 주소를 넘긴다.
  assert.match(src, /^BS_EXPLORER=\$\(\[ -f "\$BS_DIR\/compose\.yml" \] && echo "\$\{BLOCKSCOUT_URL:-http:\/\/127\.0\.0\.1:4000\}"\)$/m);
  assert.equal((src.match(/MODE3_EXPLORER_URL="\$BS_EXPLORER"/g) ?? []).length, 3, '사용자 앱 기동 세 곳(web·passkey-web 정적 서버, zkwrapper 의 zkWrapper — 2026-11-20)');
  const stopLocal = src.match(/\nstop_local\(\) \{[\s\S]*?\n\}/);
  assert.match(stopLocal[0], /stop_verify_watch/, 'stop_local 이 감시자를 함께 내린다');
});
t('번들·인증서·VM 배포 줄', () => {
  assert.match(src, /node scripts\/build_user_app\.mjs/);
  assert.match(src, /node scripts\/build_attr_tool\.mjs/);
  for (const [short, dns] of [['idp', 'idp'], ['zkone', 'zkone'], ['zktwo', 'zktwo']]) assert.match(src, new RegExp(`zkd_issue_cert[^\\n]* ${short} ${dns}\\.zkd\\.test`), short);
  assert.match(src, /mkdir -p -m 700 ~\/zkd-demo\/tls/);
  assert.match(src, /MODE3_TLS_CERT=\$1\/zkd-demo\/tls\/\$2\.crt/);
  assert.match(src, /NODE_EXTRA_CA_CERTS=\$1\/zkd-demo\/tls\/ca\.crt/);
  assert.match(src, /MODE3_WALLET_SECRETS=passkey-web/);
  // 2026-11-20: 서비스의 발급자 주소는 CIA_SRV 로 — 기본은 지금처럼 IdP VM, zkwrapper 면 이 PC 의 zkWrapper(tests/test_demo_split_zkwrapper.mjs)
  assert.match(src, /^CIA_SRV="\$SCHEME:\/\/\$IDP:\$IDP_PORT"; /m); assert.equal((src.match(/"MODE3_CIA_URL=\$CIA_SRV"/g) ?? []).length, 2);
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
  assert.match(src, /passkey-web \] && STOP_EXTRA="5100:mode3_user_static\.js( 5100:mode3_zkwrapper\.js)?"/);   // 2026-11-20: zkwrapper(ZW)의 zkWrapper 도 같은 자리
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
