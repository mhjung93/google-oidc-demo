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
// 2026-11-11(사용자 결정): RP 는 사용자 속성 커밋먼트(C_attr)를 받지도 고정하지도 않는다 — RP 마다 같은 값이라 두 RP 가 맞대면 같은 사람임을 안다.
await t('속성 커밋먼트: 고정 API 가 없고, 새 계정·view 에 attr 필드가 없다', () => {
  const { store } = fresh();
  const A = store.loginOrCreate('zkid', { PPID: '333' }).id;
  assert.equal(store.pinAttrCommit, undefined);
  for (const k of ['attrCommit', 'attrSince', 'attrUpdatedAt', 'attrHistory']) { assert.equal(k in store.get(A), false, k); assert.equal(k in store.view(A), false, k); }
});
await t('옛 파일에 남은 속성 커밋먼트(version 2 의 attr 필드)는 열 때 지우고 다시 쓴다', () => {
  const file = path.join(dir, 'v2attr.json');
  fs.writeFileSync(file, JSON.stringify({ version: 2, accounts: { acct_x: { id: 'acct_x', createdAt: 't', zkid: { PPID: '555', linkedAt: 't' }, google: null, naver: null, attrCommit: '9', attrSince: 't', attrUpdatedAt: 't', attrHistory: [{ attrCommit: '8', until: 't' }] } }, byPPID: { 555: 'acct_x' }, byGoogle: {}, byNaver: {}, krw: {}, custodyEth: {} }));
  const store = openAccountStore({ file });
  assert.equal(store.findBy('zkid', { PPID: '555' }), 'acct_x');
  assert.equal('attrCommit' in store.get('acct_x'), false);
  assert.equal(fs.readFileSync(file, 'utf8').includes('attrCommit'), false, '파일에서도 지워졌다');
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
await t('version 1(byPPID → 속성 커밋먼트)은 PPID 계정만 옮기고(커밋먼트는 버린다) 파일을 version 2 로 다시 쓴다', () => {
  const file = path.join(dir, 'v1.json');
  fs.writeFileSync(file, JSON.stringify({ version: 1, byPPID: { '444': { attrCommit: '9', since: '2026-11-09T01:00:00.000Z', updatedAt: '2026-11-09T02:00:00.000Z', history: [] } } }));
  const store = openAccountStore({ file, newId: () => 'acct_v1' });
  assert.equal(store.findBy('zkid', { PPID: '444' }), 'acct_v1');
  assert.equal('attrCommit' in store.get('acct_v1'), false, '옛 커밋먼트는 옮기지 않는다(2026-11-11)');
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).version, 2);
});
await t('모르는 모양의 파일이면 연다고 덮어쓰지 않고 오류', () => {
  assert.throws(() => migrateAccounts({ version: 7 }, { now: 'x', newId: () => 'y' }), /모양을 모른다/);
});

fs.rmSync(dir, { recursive: true, force: true });
if (failed) { console.error(`${failed} failed`); process.exit(1); }
console.log('all passed');
