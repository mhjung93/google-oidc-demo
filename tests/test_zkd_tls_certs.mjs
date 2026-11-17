// passkey-web 8: 데모 CA(이름 제약)·서버 인증서·hosts 블록 렌더러(scripts/zkd_tls_lib.sh) 단위 테스트.
// 임시 디렉터리에서만 돈다 — /etc/hosts·~/.pki/nssdb·.local/zkd-ca 는 건드리지 않고, zkd_tls_setup.sh 는 실행하지 않는다(문법만 확인).
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, symlinkSync, rmSync, statSync, readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import assert from 'node:assert/strict';

const ROOT = resolve(new URL('..', import.meta.url).pathname);
const LIB = join(ROOT, 'scripts/zkd_tls_lib.sh');
for (const bin of ['openssl', 'bash']) {
  if (spawnSync(bin, [bin === 'openssl' ? 'version' : '--version']).error) {
    console.error(`BLOCKED: ${bin} 이 없다`); process.exit(1);
  }
}

const tmp = mkdtempSync(join(tmpdir(), 'zkd-tls-test-'));
const outputs = [];
function sh(script, cwd = ROOT, env = process.env) {
  const r = spawnSync('bash', ['-c', `set -u; source "${LIB}"; ${script}`], { cwd, encoding: 'utf8', env });
  outputs.push(r.stdout, r.stderr);
  return r;
}
const ssl = (...a) => spawnSync('openssl', a, { encoding: 'utf8' });
let n = 0;
function t(name, fn) { fn(); n++; console.log('ok -', name); }

try {
  const ca = join(tmp, 'ca'), out = join(tmp, 'out');
  const NET = '192.168.226.0';

  t('CA: 이름 제약·CA 표시·키 600', () => {
    const r = sh(`zkd_ca_create "${ca}" ${NET}`);
    assert.equal(r.status, 0, r.stderr);
    const txt = ssl('x509', '-noout', '-text', '-in', join(ca, 'ca.crt')).stdout;
    for (const s of ['CA:TRUE', 'X509v3 Name Constraints: critical', 'DNS:zkd.test',
      'IP:127.0.0.0/255.0.0.0', 'IP:192.168.226.0/255.255.255.0']) assert.ok(txt.includes(s), `없음: ${s}`);
    assert.equal(statSync(join(ca, 'ca.key')).mode & 0o777, 0o600);
  });

  t('서버 인증서: SAN·EKU·30일·검증', () => {
    const r = sh(`zkd_issue_cert "${ca}" "${out}" wallet wallet.zkd.test 127.0.0.1`);
    assert.equal(r.status, 0, r.stderr);
    const crt = join(out, 'wallet.crt');
    const txt = ssl('x509', '-noout', '-text', '-in', crt).stdout;
    for (const s of ['DNS:wallet.zkd.test', 'IP Address:127.0.0.1', 'TLS Web Server Authentication']) assert.ok(txt.includes(s), `없음: ${s}`);
    const d = ssl('x509', '-noout', '-startdate', '-enddate', '-in', crt).stdout;
    const nb = Date.parse(d.match(/notBefore=(.*)/)[1]), na = Date.parse(d.match(/notAfter=(.*)/)[1]);
    assert.ok((na - nb) / 86400000 <= 31, '유효기간 31일 초과');
    assert.equal(statSync(join(out, 'wallet.key')).mode & 0o777, 0o600);
    const v = ssl('verify', '-CAfile', join(ca, 'ca.crt'), crt);
    assert.match(v.stdout, /OK/, v.stdout + v.stderr);
  });

  t('이름 제약이 막는다', () => {
    const r = sh(`zkd_issue_cert "${ca}" "${out}" evil evil.example.com 10.0.0.1`);
    assert.equal(r.status, 0, r.stderr);
    const v = ssl('verify', '-CAfile', join(ca, 'ca.crt'), join(out, 'evil.crt'));
    assert.notEqual(v.status, 0);
    assert.match(v.stdout + v.stderr, /permitted subtree violation|name constraints/i);
  });

  t('재사용', () => {
    const before = readFileSync(join(ca, 'ca.crt'));
    assert.equal(sh(`zkd_ca_create "${ca}" ${NET}`).status, 0);
    assert.ok(before.equals(readFileSync(join(ca, 'ca.crt'))));
    const mm = sh(`zkd_ca_create "${ca}" 10.1.2.0`);
    assert.equal(mm.status, 2);
    assert.ok(mm.stderr.startsWith('BLOCKED:'), mm.stderr);
    const fp = sh(`zkd_ca_fingerprint "${ca}"`);
    assert.equal(fp.status, 0);
    assert.match(fp.stdout.trim(), /([0-9A-F]{2}:){31}[0-9A-F]{2}/i);
  });

  t('재사용: ca.key 권한이 600 이 아니면 600 으로 고친다', () => {
    chmodSync(join(ca, 'ca.key'), 0o644);
    const r = sh(`zkd_ca_create "${ca}" ${NET}`);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(statSync(join(ca, 'ca.key')).mode & 0o777, 0o600);
    assert.ok(r.stderr.includes('[고침]'), r.stderr);
  });

  t('IPv4 검사·망 비교(숫자)', () => {
    const ok = (c) => assert.equal(sh(c).status, 0, c);
    const no = (c) => assert.notEqual(sh(c).status, 0, c);
    ok('zkd_ip_valid 192.168.226.10'); no('zkd_ip_valid 192.168.226.256'); no('zkd_ip_valid idp.example'); no('zkd_ip_valid 1.2.3');
    ok('zkd_ip_in_net24 192.168.226.10 192.168.226.0');
    ok('zkd_ip_in_net24 192.168.226.10 192.168.226.0'); ok('zkd_ip_in_net24 192.168.226.1 192.168.226.0');   // 앞 세 칸을 숫자로 비교(선행 0 은 10 진수)
    no('zkd_ip_in_net24 192.168.227.10 192.168.226.0'); no('zkd_ip_in_net24 idp.example 192.168.226.0');
  });

  t('realpath 가 없으면 BLOCKED 로 멈춘다', () => {
    // PATH 에서 realpath 만 뺀 디렉터리(심볼릭 링크 모음) — git 은 남긴다
    const bin = join(tmp, 'norealpath'); mkdirSync(bin);
    for (const c of ['bash', 'git', 'dirname', 'mkdir', 'chmod', 'openssl', 'rm', 'mktemp', 'cat', 'stat', 'awk', 'sed']) {
      const p = spawnSync('bash', ['-c', `command -v ${c}`], { encoding: 'utf8' }).stdout.trim();
      if (p) symlinkSync(p, join(bin, c));
    }
    const r = sh(`zkd_ca_dir_check "${join(tmp, 'x')}"`, ROOT, { ...process.env, PATH: bin });
    assert.equal(r.status, 2, r.stderr);
    assert.ok(r.stderr.startsWith('BLOCKED:') && r.stderr.includes('realpath'), r.stderr);
  });

  t('hosts 블록', () => {
    const hosts = join(tmp, 'hosts');
    writeFileSync(hosts, '127.0.0.1 localhost\n# 사용자 줄\n');
    const args = (ip) => `127.0.0.1=wallet.zkd.test ${ip}=idp.zkd.test`;
    const a = sh(`zkd_hosts_render "${hosts}" ${args('192.168.226.10')}`).stdout;
    writeFileSync(hosts, a);
    const b = sh(`zkd_hosts_render "${hosts}" ${args('192.168.226.10')}`).stdout;
    assert.equal(a, b, '두 번 렌더가 같아야 한다');
    assert.equal(a.split('# >>> zkd-demo (scripts/zkd_tls_setup.sh) >>>').length - 1, 1);
    assert.ok(a.startsWith('127.0.0.1 localhost\n# 사용자 줄\n'));
    assert.ok(a.includes('192.168.226.10 idp.zkd.test'));
    const c = sh(`zkd_hosts_render "${hosts}" ${args('192.168.226.99')}`).stdout;
    assert.ok(c.includes('192.168.226.99 idp.zkd.test') && !c.includes('192.168.226.10 idp'));
    assert.ok(c.startsWith('127.0.0.1 localhost\n# 사용자 줄\n'));
    assert.equal(c.split('# <<< zkd-demo <<<').length - 1, 1);
  });

  t('hosts: 끝 표시 없으면 거부', () => {
    const hosts = join(tmp, 'hosts_bad');
    writeFileSync(hosts, 'a\n# >>> zkd-demo (scripts/zkd_tls_setup.sh) >>>\n1.2.3.4 x\nuser-line\n');
    const r = sh(`zkd_hosts_render "${hosts}" 127.0.0.1=wallet.zkd.test`);
    assert.notEqual(r.status, 0);
    assert.equal(r.stdout, '');
    assert.ok(r.stderr.startsWith('BLOCKED:'));
  });

  t('hosts: 짝 없는 끝 표시는 일반 줄로 남기지 않는다', () => {
    const hosts = join(tmp, 'hosts_orphan');
    writeFileSync(hosts, 'a\n# <<< zkd-demo <<<\nb\n');
    const r = sh(`zkd_hosts_render "${hosts}" 127.0.0.1=wallet.zkd.test`);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.split('# <<< zkd-demo <<<').length - 1, 1, r.stdout);
    assert.ok(r.stdout.startsWith('a\nb\n'), r.stdout);
  });

  t('hosts: 블록 밖 *.zkd.test 는 WARN(막지 않음), 블록 안·주석·없으면 조용', () => {
    const hosts = join(tmp, 'hosts_stale');
    writeFileSync(hosts, '127.0.0.1 localhost\n10.0.0.5 idp.zkd.test\n# 1.1.1.1 old.zkd.test\n# >>> zkd-demo (scripts/zkd_tls_setup.sh) >>>\n192.168.226.10 idp.zkd.test\n# <<< zkd-demo <<<\n');
    const w = sh(`zkd_hosts_stale_warn "${hosts}"`);
    assert.equal(w.status, 0);
    assert.ok(w.stderr.startsWith('WARN:') && w.stderr.includes('10.0.0.5 idp.zkd.test'), w.stderr);
    assert.ok(!w.stderr.includes('192.168.226.10') && !w.stderr.includes('old.zkd.test'), w.stderr);
    writeFileSync(hosts, '127.0.0.1 localhost\n# >>> zkd-demo (scripts/zkd_tls_setup.sh) >>>\n192.168.226.10 idp.zkd.test\n# <<< zkd-demo <<<\n');
    const q = sh(`zkd_hosts_stale_warn "${hosts}"`);
    assert.notEqual(q.status, 0); assert.equal(q.stderr, '');
  });

  t('hosts: 두 번째 awk 실패를 전파한다', () => {
    // 첫 awk(끝 표시 검사)는 통과시키고 두 번째(블록 밖 줄 출력)만 실패시키는 가짜 awk — 실패하면 블록만 남은 출력이 /etc/hosts 를 덮을 수 있다
    const hosts = join(tmp, 'hosts_prop');
    writeFileSync(hosts, '127.0.0.1 localhost\n');
    const bin = join(tmp, 'fakebin'); mkdirSync(bin);
    const realAwk = spawnSync('bash', ['-c', 'command -v awk'], { encoding: 'utf8' }).stdout.trim();
    const cnt = join(tmp, 'awk_count');
    writeFileSync(join(bin, 'awk'), `#!/usr/bin/env bash\nn=$(( $(cat "${cnt}" 2>/dev/null || echo 0) + 1 )); echo $n > "${cnt}"\n[ $n -ge 2 ] && exit 1\nexec "${realAwk}" "$@"\n`);
    chmodSync(join(bin, 'awk'), 0o755);
    const r = sh(`PATH="${bin}:$PATH" zkd_hosts_render "${hosts}" 127.0.0.1=wallet.zkd.test`);
    assert.notEqual(r.status, 0, '두 번째 awk 실패가 0 으로 끝났다');
  });

  t('hosts: 원래 줄 보존 검사(zkd_hosts_check)', () => {
    const hosts = join(tmp, 'hosts_chk');
    writeFileSync(hosts, '127.0.0.1 localhost\n# 사용자 줄\n# >>> zkd-demo (scripts/zkd_tls_setup.sh) >>>\n1.2.3.4 idp.zkd.test\n# <<< zkd-demo <<<\n::1 ip6-localhost\n');
    const good = join(tmp, 'hosts_chk_good');
    const rr = sh(`zkd_hosts_render "${hosts}" 127.0.0.1=wallet.zkd.test > "${good}"`);
    assert.equal(rr.status, 0, rr.stderr);
    assert.equal(sh(`zkd_hosts_check "${hosts}" "${good}"`).status, 0);
    const blockOnly = join(tmp, 'hosts_chk_bad');
    writeFileSync(blockOnly, '# >>> zkd-demo (scripts/zkd_tls_setup.sh) >>>\n127.0.0.1 wallet.zkd.test\n# <<< zkd-demo <<<\n');
    const bad = sh(`zkd_hosts_check "${hosts}" "${blockOnly}"`);
    assert.notEqual(bad.status, 0);
    assert.ok(bad.stderr.startsWith('BLOCKED:'), bad.stderr);
    writeFileSync(blockOnly, '127.0.0.1 localhost\n# >>> zkd-demo (scripts/zkd_tls_setup.sh) >>>\n# <<< zkd-demo <<<\n');
    assert.notEqual(sh(`zkd_hosts_check "${hosts}" "${blockOnly}"`).status, 0, '줄 하나가 빠졌는데 통과했다');
  });

  const hasGit = !spawnSync('git', ['--version']).error;
  // 사용자·시스템 git 설정(전역 excludesFile 등)과 TMPDIR 이 git 작업 트리 안인 경우에 판정이 흔들리지 않게 한다
  const gitEnv = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', XDG_CONFIG_HOME: join(tmp, 'xdg'), HOME: join(tmp, 'home') };  // git 2.25 는 GIT_CONFIG_GLOBAL 을 몰라 HOME 도 비운다
  const tmpInGit = hasGit && spawnSync('git', ['-C', tmp, 'rev-parse', '--is-inside-work-tree'], { encoding: 'utf8', env: gitEnv }).stdout.trim() === 'true';
  t('CA 위치: 저장소 안이면 .gitignore 에 걸려야 한다', () => {
    if (!hasGit) { console.log('  (git 없음 — 건너뜀)'); return; }
    if (tmpInGit) { console.log(`  (임시 디렉터리 ${tmp} 가 git 작업 트리 안이라 건너뜀 — TMPDIR 을 저장소 밖으로)`); return; }
    const repo = join(tmp, 'repo'); mkdirSync(repo);
    const g = spawnSync('git', ['-c', 'core.excludesFile=/dev/null', 'init', '-q', repo], { encoding: 'utf8', env: gitEnv });
    assert.equal(g.status, 0, g.stderr);
    const shg = (c, cwd) => sh(c, cwd, gitEnv);
    const caIn = join(repo, '.local/zkd-ca');
    const blocked = shg(`zkd_ca_create "${caIn}" ${NET}`, repo);
    assert.equal(blocked.status, 2, blocked.stderr);
    assert.ok(blocked.stderr.startsWith('BLOCKED:') && blocked.stderr.includes('.gitignore'), blocked.stderr);
    assert.ok(!existsSync(join(caIn, 'ca.key')), '거부했는데 키를 만들었다');
    // 상대 경로(setup 의 기본값 .local/zkd-ca)도 같은 판정
    assert.equal(shg(`zkd_ca_create .local/zkd-ca ${NET}`, repo).status, 2);
    writeFileSync(join(repo, '.gitignore'), '.local/\n');
    const ok = shg(`zkd_ca_create .local/zkd-ca ${NET}`, repo);
    assert.equal(ok.status, 0, ok.stderr);
    assert.ok(existsSync(join(caIn, 'ca.key')));
    // 저장소 밖(임시 디렉터리)은 검사하지 않는다 — 위 'CA:' 케이스가 그 경로다
    assert.equal(shg(`zkd_ca_dir_check "${join(tmp, 'outside-ca')}"`, ROOT).status, 0);
  });

  t('리프: 키 식별자 포함', () => {
    const txt = ssl('x509', '-noout', '-text', '-in', join(out, 'wallet.crt')).stdout;
    assert.ok(txt.includes('Subject Key Identifier') && txt.includes('Authority Key Identifier'));
  });

  t('개인키를 출력하지 않는다', () => {
    for (const o of outputs) assert.ok(!o.includes('PRIVATE KEY'));
  });

  t('zkd_tls_setup.sh 문법', () => {
    const r = spawnSync('bash', ['-n', join(ROOT, 'scripts/zkd_tls_setup.sh')], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    // 순서: CA 위치 검사 → hosts 렌더 → 줄 보존 검사 → sudo install (실행하지 않고 줄 순서만 본다)
    const src = readFileSync(join(ROOT, 'scripts/zkd_tls_setup.sh'), 'utf8');
    const at = (s) => { const i = src.indexOf(s); assert.ok(i >= 0, `없음: ${s}`); return i; };
    assert.ok(at('zkd_ca_dir_check "$CA_DIR" || exit 2') < at('sudo apt-get'));
    assert.ok(at('zkd_hosts_render /etc/hosts') < at('zkd_hosts_check /etc/hosts "$new_hosts"'));
    assert.ok(at('zkd_hosts_check /etc/hosts "$new_hosts"') < at('sudo install -m 644'));
  });

  console.log(`${n} passed`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
