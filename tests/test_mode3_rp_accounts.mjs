// tests/test_mode3_rp_accounts.mjs — RP 계정 저장소(lib/mode3_rp_accounts.js, 스펙 2026-11-10 §2) 단위. 외부 의존 없음. (unit)
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openAccountStore, migrateAccounts, AccountError, METHODS } from '../lib/mode3_rp_accounts.js';

let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); } }
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rp-accounts-'));
let n = 0;
const fresh = () => { const file = path.join(dir, `a${++n}.json`); let i = 0; return { file, store: openAccountStore({ file, now: () => '2026-11-10T00:00:00.000Z', newId: () => `acct_${n}_${++i}` }) }; };
const rejectsWith = (fn, status, reason) => assert.throws(fn, (e) => e instanceof AccountError && e.status === status && e.reason === reason);

await t('METHODS 는 zkid·google·naver', () => assert.deepEqual([...METHODS], ['zkid', 'google', 'naver']));
await t('loginOrCreate: 처음 보는 수단이면 그 칸만 채운 새 계정, 두 번째는 같은 계정', () => {
  const { store } = fresh();
  const a = store.loginOrCreate('google', { sub: 'g1' });
  assert.equal(a.created, true);
  assert.deepEqual(store.loginOrCreate('google', { sub: 'g1' }), { id: a.id, created: false });
  const acc = store.get(a.id);
  assert.equal(acc.google.sub, 'g1'); assert.equal(acc.zkid, null); assert.equal(acc.naver, null);
  assert.equal(store.findBy('google', { sub: 'g1' }), a.id); assert.equal(store.findBy('naver', { sub: 'g1' }), null, '수단마다 색인이 따로');
});
await t('link: 빈 칸에 붙인다; 다른 계정의 값이면 409 method_linked_elsewhere; 칸이 차 있으면 409 method_already_linked; 같은 값은 그대로', () => {
  const { store } = fresh();
  const A = store.loginOrCreate('zkid', { PPID: '111' }).id, B = store.loginOrCreate('google', { sub: 'g2' }).id;
  store.link(A, 'naver', { sub: 'n1' });
  assert.equal(store.findBy('naver', { sub: 'n1' }), A);
  rejectsWith(() => store.link(B, 'naver', { sub: 'n1' }), 409, 'method_linked_elsewhere');
  rejectsWith(() => store.link(B, 'zkid', { PPID: '111' }), 409, 'method_linked_elsewhere');
  rejectsWith(() => store.link(A, 'naver', { sub: 'n9' }), 409, 'method_already_linked');
  assert.equal(store.link(A, 'naver', { sub: 'n1' }).naver.sub, 'n1', '같은 값 재연결은 오류가 아니다');
  rejectsWith(() => store.link('acct_none', 'google', { sub: 'x' }), 404, 'no_account');
  rejectsWith(() => store.link(A, 'email', { sub: 'x' }), 400, 'bad_method');
  rejectsWith(() => store.link(A, 'google', { sub: '' }), 400, 'bad_sub');
});
await t('unlink: 마지막 수단은 409 last_method, 없는 칸은 409 not_linked; 풀면 색인도 지워져 다른 계정이 쓸 수 있다', () => {
  const { store } = fresh();
  const A = store.loginOrCreate('google', { sub: 'g3' }).id;
  rejectsWith(() => store.unlink(A, 'google'), 409, 'last_method');
  rejectsWith(() => store.unlink(A, 'naver'), 409, 'not_linked');
  store.link(A, 'naver', { sub: 'n3' });
  store.unlink(A, 'google');
  assert.equal(store.findBy('google', { sub: 'g3' }), null);
  const B = store.loginOrCreate('google', { sub: 'g3' });
  assert.equal(B.created, true, '풀린 Google 로 로그인하면 새 계정');
});
await t('view 는 sub 을 싣지 않는다', () => {
  const { store } = fresh();
  const A = store.loginOrCreate('google', { sub: 'secret-sub' }).id;
  store.link(A, 'zkid', { PPID: '222' });
  const v = store.view(A);
  assert.equal(v.account, A); assert.equal(v.methods.zkid.PPID, '222'); assert.ok(v.methods.google.linkedAt);
  assert.equal(JSON.stringify(v).includes('secret-sub'), false);
});
await t('pinAttrCommit: 처음 고정은 changed false, 다른 값이면 true + 기록, null 이면 그대로', () => {
  const { store } = fresh();
  const A = store.loginOrCreate('zkid', { PPID: '333' }).id;
  assert.deepEqual(store.pinAttrCommit(A, null), { attrCommit: null, changed: false });
  assert.deepEqual(store.pinAttrCommit(A, '5'), { attrCommit: '5', changed: false });
  assert.deepEqual(store.pinAttrCommit(A, '5'), { attrCommit: '5', changed: false });
  assert.deepEqual(store.pinAttrCommit(A, '6'), { attrCommit: '6', changed: true });
  assert.equal(store.get(A).attrHistory.at(-1).attrCommit, '5');
});
await t('장부: addKrw·addCustody 는 bigint, 음수가 되면 400 이고 바뀌지 않는다', () => {
  const { store } = fresh();
  const A = store.loginOrCreate('google', { sub: 'g4' }).id;
  assert.equal(store.addKrw(A, 1_000_000n), 1_000_000n);
  rejectsWith(() => store.addKrw(A, -2_000_000n), 400, 'insufficient_krw');
  assert.equal(store.krw(A), 1_000_000n);
  assert.equal(store.addCustody(A, 10n ** 17n), 10n ** 17n);
  rejectsWith(() => store.addCustody(A, -(10n ** 18n)), 400, 'insufficient_custody');
  assert.equal(store.custody(A), 10n ** 17n);
});
await t('파일: 다시 열어도 계정·색인·장부가 남는다(version 2, 권한 600)', () => {
  const { file, store } = fresh();
  const A = store.loginOrCreate('naver', { sub: 'n5' }).id;
  store.addKrw(A, 7n); store.addCustody(A, 9n);
  const again = openAccountStore({ file });
  assert.equal(again.findBy('naver', { sub: 'n5' }), A); assert.equal(again.krw(A), 7n); assert.equal(again.custody(A), 9n);
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).version, 2);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});
await t('version 1(byPPID → 속성 커밋먼트)은 PPID 계정으로 옮기고 파일을 version 2 로 다시 쓴다', () => {
  const file = path.join(dir, 'v1.json');
  fs.writeFileSync(file, JSON.stringify({ version: 1, byPPID: { '444': { attrCommit: '9', since: '2026-11-09T01:00:00.000Z', updatedAt: '2026-11-09T02:00:00.000Z', history: [] } } }));
  const store = openAccountStore({ file, newId: () => 'acct_v1' });
  assert.equal(store.findBy('zkid', { PPID: '444' }), 'acct_v1');
  assert.equal(store.get('acct_v1').attrCommit, '9');
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).version, 2);
});
await t('모르는 모양의 파일이면 연다고 덮어쓰지 않고 오류', () => {
  assert.throws(() => migrateAccounts({ version: 7 }, { now: 'x', newId: () => 'y' }), /모양을 모른다/);
});

fs.rmSync(dir, { recursive: true, force: true });
if (failed) { console.error(`${failed} failed`); process.exit(1); }
console.log('all passed');
