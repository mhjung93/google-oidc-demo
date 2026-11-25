// 서비스 보관 계정의 시드·주소(lib/mode3_rp_custody.js, 스펙 2026-11-25-mode3-rp-custody-address). 외부 의존 없음.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { openCustody, custodySeedFileOf, CustodyError } from '../lib/mode3_rp_custody.js';

let fails = 0;
const t = (name, fn) => { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } };
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-'));
const f = (n) => path.join(dir, n);
// KAT: BIP32(HMAC-SHA512)를 따로 계산해 맞춰 본 값(2026-11-25) — [지문, ids[0], ids[1]]
const KAT = ['0x84e567225005473faF42022D6a8a068955914e25', '0xAA4508C142FF7AA629aeCfCaf99d55DAEb78be31', '0xCeE80AeE6281c8Bb1A98142b2b15A30852c8955F'];
const ids = ['acct_0123456789abcdef', 'acct_fedcba9876543210'];
// 던지는 오류의 문구·스택 어디에도 시드가 없다
const refuses = (fn, re, secret) => { let e = null; try { fn(); } catch (x) { e = x; } assert.ok(e instanceof CustodyError, `던지지 않았다: ${e}`); assert.match(e.message, re); if (secret) assert.ok(!`${e.message}${e.stack}${e.cause ?? ''}`.includes(secret), '오류에 시드가 있다'); };

t('시드 파일 이름은 계정 파일에서 — 서비스마다 다르다', () => {
  assert.equal(custodySeedFileOf('/x/mode3_rp_accounts.json'), '/x/mode3_rp_custody_seed.json');
  assert.equal(custodySeedFileOf('/x/mode3_rp_zkthree_accounts.json'), '/x/mode3_rp_zkthree_custody_seed.json');
  assert.equal(custodySeedFileOf('/x/mode3_a_accounts.json'), '/x/mode3_a_custody_seed.json');
  assert.notEqual(custodySeedFileOf('/x/other.json'), '/x/other.json');
});
t('처음 열면 만든다: 0600, 다시 열면 덮지 않고 같은 주소·지문 — 계정마다 다르고 서비스마다 다르다', () => {
  const a = openCustody({ file: f('a.json') }); const raw = fs.readFileSync(f('a.json'), 'utf8');
  assert.equal(fs.statSync(f('a.json')).mode & 0o777, 0o600);
  const again = openCustody({ file: f('a.json'), expect: a.fingerprint });
  assert.equal(fs.readFileSync(f('a.json'), 'utf8'), raw); assert.equal(again.fingerprint, a.fingerprint);
  for (const id of ids) { assert.match(a.addressOf(id), /^0x[0-9a-fA-F]{40}$/); assert.equal(again.addressOf(id), a.addressOf(id)); }
  assert.notEqual(a.addressOf(ids[0]), a.addressOf(ids[1])); assert.notEqual(a.addressOf(ids[0]), a.fingerprint);
  const b = openCustody({ file: f('b.json') }); assert.notEqual(b.addressOf(ids[0]), a.addressOf(ids[0])); assert.notEqual(b.fingerprint, a.fingerprint);
});
t('서명자의 주소가 보이는 주소와 같고, 돌려주는 것에 시드·개인 키가 없다', () => {
  const a = openCustody({ file: f('a.json') });
  assert.equal(a.signerOf(ids[0], null).address, a.addressOf(ids[0]));
  assert.deepEqual(Object.keys(a).sort(), ['addressOf', 'fingerprint', 'signerOf']); assert.ok(!JSON.stringify(a).includes(JSON.parse(fs.readFileSync(f('a.json'), 'utf8')).seed));
});
t('유도 고정값(KAT, 테스트 전용 시드) — 경로 규칙이 바뀌면 실패한다', () => {
  fs.writeFileSync(f('kat.json'), JSON.stringify({ version: 1, seed: '00'.repeat(31) + '01' }), { mode: 0o600 });
  const k = openCustody({ file: f('kat.json') });
  assert.deepEqual([k.fingerprint, k.addressOf(ids[0]), k.addressOf(ids[1])], KAT);
});
t('시드를 잃었거나 바뀌었으면 기동을 막는다 — 새로 만들지 않는다', () => {
  const a = openCustody({ file: f('a.json') });
  refuses(() => openCustody({ file: f('lost.json'), expect: a.fingerprint }), /시드 파일이 없다/); assert.ok(!fs.existsSync(f('lost.json')), '새로 만들었다');
  const bs = JSON.parse(fs.readFileSync(f('b.json'), 'utf8')).seed; refuses(() => openCustody({ file: f('b.json'), expect: a.fingerprint }), /지문과 다르다/, bs);
});
t('망가진 파일·넓은 권한·디렉터리면 막는다 — 오류 문구에 내용이 없다', () => {
  const secret = 'ab'.repeat(32);
  for (const [n, body] of [['bad1.json', `{"version":1,"seed":"${secret}",}`], ['bad2.json', `{"version":2,"seed":"${secret}"}`], ['bad3.json', `{"version":1,"seed":"${secret}00"}`], ['bad4.json', secret], ['bad5.json', '']]) { fs.writeFileSync(f(n), body, { mode: 0o600 }); refuses(() => openCustody({ file: f(n) }), /모양이 틀리다/, secret); assert.equal(fs.readFileSync(f(n), 'utf8'), body, '파일을 바꿨다'); }
  fs.writeFileSync(f('wide.json'), `{"version":1,"seed":"${secret}"}`, { mode: 0o600 }); fs.chmodSync(f('wide.json'), 0o644); refuses(() => openCustody({ file: f('wide.json') }), /권한/, secret);
  fs.mkdirSync(f('d.json')); refuses(() => openCustody({ file: f('d.json') }), /일반 파일/);
  const a = openCustody({ file: f('a.json') }); for (const id of ['', null, undefined, 5]) refuses(() => a.addressOf(id), /계정 id/);
});
t('공개 저장소에 올라가지 않는다 — .gitignore(시드와 백업본)', () => {
  for (const n of ['mode3_rp_custody_seed.json', 'mode3_rp_zkthree_custody_seed.json', 'mode3_rp2_custody_seed.json', 'mode3_rp_custody_seed.json.bak-20261125-1200', 'mode3_rp_custody_seed.json.tmp']) execFileSync('git', ['check-ignore', '-q', n], { cwd: new URL('..', import.meta.url).pathname });
});
fs.rmSync(dir, { recursive: true, force: true });
if (fails) { console.log(`\n${fails} FAIL`); process.exit(1); } else console.log('\nall ok');
