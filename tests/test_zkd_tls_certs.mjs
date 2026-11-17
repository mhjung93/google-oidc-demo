// passkey-web 8: 데모 CA(이름 제약)·서버 인증서·hosts 블록 렌더러(scripts/zkd_tls_lib.sh) 단위 테스트.
// 임시 디렉터리에서만 돈다 — /etc/hosts·~/.pki/nssdb·.local/zkd-ca 는 건드리지 않고, zkd_tls_setup.sh 는 실행하지 않는다(문법만 확인).
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, statSync, readFileSync, writeFileSync } from 'node:fs';
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
function sh(script) {
  const r = spawnSync('bash', ['-c', `set -u; source "${LIB}"; ${script}`], { cwd: ROOT, encoding: 'utf8' });
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
    assert.equal(sh(`zkd_ca_create "${ca}" 10.1.2.0`).status, 2);
    const fp = sh(`zkd_ca_fingerprint "${ca}"`);
    assert.equal(fp.status, 0);
    assert.match(fp.stdout.trim(), /([0-9A-F]{2}:){31}[0-9A-F]{2}/i);
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

  t('개인키를 출력하지 않는다', () => {
    for (const o of outputs) assert.ok(!o.includes('PRIVATE KEY'));
  });

  t('zkd_tls_setup.sh 문법', () => {
    const r = spawnSync('bash', ['-n', join(ROOT, 'scripts/zkd_tls_setup.sh')], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
  });

  console.log(`${n}/7 passed`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
