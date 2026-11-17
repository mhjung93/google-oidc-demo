// passkey-web 승인 팝업의 IdP 인증 창 왕복(mode3/user/idp_return.js, 계획 Task 6) — DOM 전역은 인자로 받으므로 Node 에서 돈다.
//   node tests/test_mode3_user_idp_return.mjs   (unit)
import assert from 'node:assert/strict';
import { PENDING_KEY, PENDING_MAX_AGE_MS, RECOVER_RESULT_KEY, idpAuthUrl, savePending, takeIdpReturn, readAttrRecord } from '../mode3/user/idp_return.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.stack ?? e.message); } }

/** sessionStorage·localStorage 대역 — Map 래퍼(getItem 은 없으면 null). */
function fakeStorage(init = {}) {
  const m = new Map(Object.entries(init));
  return { m, getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => { m.set(k, String(v)); }, removeItem: (k) => { m.delete(k); } };
}
const REQ = { type: 'mode3-authorize', arid: '11', origin: 'http://rp.example', cert_s: '22', pk_trace: ['1', '2'], r_s: '33', r_rp: '44', serviceName: 'zkONE' };
const NOW = 1_800_000_000_000;
const pendingWith = (over = {}) => { const s = fakeStorage(); savePending(s, { req: REQ, origin: 'http://rp.example', nonce: 'n1', at: NOW, ...over }); return s; };

await t('상수: 대기 키·10분·복구 결과 키', () => {
  assert.equal(PENDING_KEY, 'mode3.authorize.pending');
  assert.equal(PENDING_MAX_AGE_MS, 600_000);
  assert.equal(RECOVER_RESULT_KEY, 'mode3_recover_result');
});

await t('idpAuthUrl: /login 에 nonce·wallet·return=1, 기본은 purpose 없음, register 면 purpose=register', () => {
  const u = new URL(idpAuthUrl({ ciaUrl: 'http://idp.example:4100', walletOrigin: 'http://localhost:5100', nonce: 'abc' }));
  assert.equal(u.origin + u.pathname, 'http://idp.example:4100/login');
  assert.equal(u.searchParams.get('nonce'), 'abc');
  assert.equal(u.searchParams.get('wallet'), 'http://localhost:5100');
  assert.equal(u.searchParams.get('return'), '1');
  assert.equal(u.searchParams.has('purpose'), false);
  assert.deepEqual([...u.searchParams.keys()].sort(), ['nonce', 'return', 'wallet']);
  const r = new URL(idpAuthUrl({ ciaUrl: 'http://idp.example:4100', walletOrigin: 'http://localhost:5100', nonce: 'abc', purpose: 'register' }));
  assert.equal(r.searchParams.get('purpose'), 'register');
  assert.deepEqual([...r.searchParams.keys()].sort(), ['nonce', 'purpose', 'return', 'wallet']);
});

await t('savePending: 대기 키에 { req, origin, nonce, at } — salt(s_u) 키는 없다', () => {
  const s = pendingWith();
  const raw = s.getItem(PENDING_KEY);
  assert.deepEqual(JSON.parse(raw), { req: REQ, origin: 'http://rp.example', nonce: 'n1', at: NOW });
  assert.equal(raw.includes('s_u'), false);
  const rec = fakeStorage(); savePending(rec, { req: { type: 'mode3-recover', profile: { birthYear: '1990', country: 'KR' } }, origin: 'http://localhost:5100', nonce: 'n2', at: NOW });
  assert.equal(rec.getItem(PENDING_KEY).includes('s_u'), false, '복구 대기분에도 salt 가 없다');
});

await t('takeIdpReturn: 쿼리가 없으면 null 이고 저장분은 그대로', () => {
  const s = pendingWith();
  assert.equal(takeIdpReturn({ search: '?authorize=1', storage: s, now: NOW }), null);
  assert.equal(takeIdpReturn({ search: '', storage: s, now: NOW }), null);
  assert.ok(s.getItem(PENDING_KEY), '돌아온 길이 아니면 저장분을 건드리지 않는다');
});

await t('takeIdpReturn: nonce 불일치 → { req: null } 이고 저장분은 지워진다', () => {
  const s = pendingWith();
  assert.deepEqual(takeIdpReturn({ search: '?authorize=1&idp_nonce=bad&idp_code=c1', storage: s, now: NOW }), { req: null });
  assert.equal(s.getItem(PENDING_KEY), null);
});

await t('takeIdpReturn: 저장분 없음·코드 없음·깨진 JSON → { req: null }', () => {
  assert.deepEqual(takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1', storage: fakeStorage(), now: NOW }), { req: null });
  assert.deepEqual(takeIdpReturn({ search: '?authorize=1&idp_nonce=n1', storage: pendingWith(), now: NOW }), { req: null });
  const broken = fakeStorage({ [PENDING_KEY]: '{not json' });
  assert.deepEqual(takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1', storage: broken, now: NOW }), { req: null });
  assert.equal(broken.getItem(PENDING_KEY), null);
});

await t('takeIdpReturn: at 이 10분 1ms 전 → { req: null }, 딱 10분이면 받는다', () => {
  assert.deepEqual(takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1', storage: pendingWith({ at: NOW - PENDING_MAX_AGE_MS - 1 }), now: NOW }), { req: null });
  const ok = takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1', storage: pendingWith({ at: NOW - PENDING_MAX_AGE_MS }), now: NOW });
  assert.deepEqual(ok.req, REQ);
});

await t('takeIdpReturn: 정상 발급 → { req, origin, code, purpose:issue, uid:null, auid:null } 이고 저장분은 지워진다', () => {
  const s = pendingWith();
  const back = takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1&idp_uid=7&idp_auid=8', storage: s, now: NOW });
  assert.deepEqual(back, { req: REQ, origin: 'http://rp.example', code: 'c1', purpose: 'issue', uid: null, auid: null });
  assert.equal(s.getItem(PENDING_KEY), null);
});

await t('takeIdpReturn: register 인데 uid 가 비숫자 → { req: null }', () => {
  assert.deepEqual(takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1&idp_purpose=register&idp_uid=abc', storage: pendingWith(), now: NOW }), { req: null });
  assert.deepEqual(takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1&idp_purpose=register', storage: pendingWith(), now: NOW }), { req: null });
});

await t('takeIdpReturn: 정상 register → uid·auid, auid 가 비숫자면 auid:null', () => {
  const a = takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1&idp_purpose=register&idp_uid=123&idp_auid=456', storage: pendingWith(), now: NOW });
  assert.deepEqual(a, { req: REQ, origin: 'http://rp.example', code: 'c1', purpose: 'register', uid: '123', auid: '456' });
  const b = takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1&idp_purpose=register&idp_uid=123&idp_auid=0x1', storage: pendingWith(), now: NOW });
  assert.equal(b.uid, '123'); assert.equal(b.auid, null);
});

// ---- readAttrRecord ----
const S_OK = (12345678901234567890n).toString();
const recordStorage = (rec, extra = {}) => fakeStorage({ mode3_attr_tool_v1: JSON.stringify(rec), ...extra });
const resetFetch = (epoch) => async (url) => {
  assert.equal(url, '/attr/dist/reset.json');
  return epoch === null ? { ok: false, json: async () => ({}) } : { ok: true, json: async () => ({ epoch }) };
};
const noFetch = async () => { throw new Error('없음'); };

await t('readAttrRecord: epoch 가 바뀌면 기록을 지우고 null, 새 epoch 를 기억한다', async () => {
  const ls = recordStorage({ version: 5, s_u: S_OK, profile: { birthYear: '1990' } }, { mode3_attr_tool_reset: 'e1' });
  assert.equal(await readAttrRecord({ fetch: resetFetch('e2'), localStorage: ls }), null);
  assert.equal(ls.getItem('mode3_attr_tool_v1'), null);
  assert.equal(ls.getItem('mode3_attr_tool_reset'), 'e2');
});

await t('readAttrRecord: 같은 epoch·reset.json 없음·fetch 실패면 기록을 그대로 읽는다', async () => {
  const rec = { version: 5, s_u: S_OK, profile: { birthYear: '1990', country: 'KR' } };
  assert.deepEqual(await readAttrRecord({ fetch: resetFetch('e1'), localStorage: recordStorage(rec, { mode3_attr_tool_reset: 'e1' }) }), { s_u: S_OK, profile: rec.profile });
  assert.deepEqual(await readAttrRecord({ fetch: resetFetch(null), localStorage: recordStorage(rec) }), { s_u: S_OK, profile: rec.profile });
  assert.deepEqual(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage(rec) }), { s_u: S_OK, profile: rec.profile });
});

await t('readAttrRecord: version 3 → null, version 4 는 받는다', async () => {
  assert.equal(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage({ version: 3, s_u: S_OK }) }), null);
  assert.deepEqual(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage({ version: 4, s_u: S_OK, uid: '9' }) }), { s_u: S_OK, profile: null });
});

await t("readAttrRecord: s_u '0'·2^250·비숫자 → null", async () => {
  for (const s_u of ['0', (1n << 250n).toString(), '12a', 12345])
    assert.equal(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage({ version: 5, s_u }) }), null, String(s_u));
  assert.deepEqual(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage({ version: 5, s_u: ((1n << 250n) - 1n).toString() }) }), { s_u: ((1n << 250n) - 1n).toString(), profile: null });
});

await t('readAttrRecord: 기록 없음·깨진 JSON → null, profile 이 배열이면 profile:null', async () => {
  assert.equal(await readAttrRecord({ fetch: noFetch, localStorage: fakeStorage() }), null);
  assert.equal(await readAttrRecord({ fetch: noFetch, localStorage: fakeStorage({ mode3_attr_tool_v1: '{x' }) }), null);
  assert.deepEqual(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage({ version: 5, s_u: S_OK, profile: ['a'] }) }), { s_u: S_OK, profile: null });
});

console.log(fails ? `\n${fails} failed` : '\nall passed');
process.exit(fails ? 1 : 0);
