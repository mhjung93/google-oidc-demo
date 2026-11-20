// passkey-web 승인 팝업의 IdP 인증 창 왕복(mode3/user/idp_return.js, 계획 Task 6) — DOM 전역은 인자로 받으므로 Node 에서 돈다.
//   node tests/test_mode3_user_idp_return.mjs   (unit)
import assert from 'node:assert/strict';
import { PENDING_KEY, PENDING_MAX_AGE_MS, RECOVER_RESULT_KEY, idpAuthUrl, savePending, takeIdpReturn, readAttrRecord, SIGNUP_PENDING_KEY, googleSignupUrl, saveSignupPending, takeGoogleReturn, WRAPPER_PENDING_KEY, googleAuthUrl, saveWrapperPending, takeWrapperReturn } from '../mode3/user/idp_return.js';

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

// 2026-11-17(미뤄 둔 Minor C, Task 6): 대기 저장분이 갈 때의 목적(purpose)을 기억하고, 돌아온 목적이 다르면 이어받지 않는다(nonce 와 함께 묶는다).
// 목적을 남기지 않은 옛 대기분은 지금처럼 받는다.
await t('savePending: purpose 를 주면 함께 남긴다', () => {
  const s = fakeStorage(); savePending(s, { req: REQ, origin: 'http://rp.example', nonce: 'n1', at: NOW, purpose: 'register' });
  assert.deepEqual(JSON.parse(s.getItem(PENDING_KEY)), { req: REQ, origin: 'http://rp.example', nonce: 'n1', at: NOW, purpose: 'register' });
});
await t('takeIdpReturn: 돌아온 purpose 가 대기분의 purpose 와 다르면 { req: null } 이고 저장분은 지워진다', () => {
  const reg = pendingWith({ purpose: 'register' });
  assert.deepEqual(takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1', storage: reg, now: NOW }), { req: null }, '등록으로 갔는데 발급 코드');
  assert.equal(reg.getItem(PENDING_KEY), null);
  assert.deepEqual(takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1&idp_purpose=register&idp_uid=123', storage: pendingWith({ purpose: 'issue' }), now: NOW }), { req: null }, '발급으로 갔는데 등록 코드');
  assert.equal(takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1&idp_purpose=register&idp_uid=123&idp_auid=4', storage: pendingWith({ purpose: 'register' }), now: NOW }).purpose, 'register');
  assert.equal(takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1', storage: pendingWith({ purpose: 'issue' }), now: NOW }).purpose, 'issue');
  assert.equal(takeIdpReturn({ search: '?authorize=1&idp_nonce=n1&idp_code=c1', storage: pendingWith(), now: NOW }).purpose, 'issue', '목적 없는 옛 대기분');
});

await t('readAttrRecord: epoch 가 바뀌면 기록을 지우고 null, 새 epoch 를 기억한다', async () => {
  const ls = recordStorage({ version: 5, s_u: S_OK, profile: { birthYear: '1990' } }, { mode3_attr_tool_reset: 'e1' });
  assert.equal(await readAttrRecord({ fetch: resetFetch('e2'), localStorage: ls }), null);
  assert.equal(ls.getItem('mode3_attr_tool_v1'), null);
  assert.equal(ls.getItem('mode3_attr_tool_reset'), 'e2');
});

await t('readAttrRecord: 같은 epoch·reset.json 없음·fetch 실패면 기록을 그대로 읽는다', async () => {
  const rec = { version: 5, s_u: S_OK, profile: { birthYear: '1990', country: 'KR' } };
  assert.deepEqual(await readAttrRecord({ fetch: resetFetch('e1'), localStorage: recordStorage(rec, { mode3_attr_tool_reset: 'e1' }) }), { auid: null, s_u: S_OK, profile: rec.profile });
  assert.deepEqual(await readAttrRecord({ fetch: resetFetch(null), localStorage: recordStorage(rec) }), { auid: null, s_u: S_OK, profile: rec.profile });
  assert.deepEqual(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage(rec) }), { auid: null, s_u: S_OK, profile: rec.profile });
});

await t('readAttrRecord: version 3 → null, version 4 는 받는다', async () => {
  assert.equal(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage({ version: 3, s_u: S_OK }) }), null);
  assert.deepEqual(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage({ version: 4, s_u: S_OK, uid: '9' }) }), { auid: null, s_u: S_OK, profile: null });
});

await t("readAttrRecord: s_u '0'·2^250·비숫자 → null", async () => {
  for (const s_u of ['0', (1n << 250n).toString(), '12a', 12345])
    assert.equal(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage({ version: 5, s_u }) }), null, String(s_u));
  assert.deepEqual(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage({ version: 5, s_u: ((1n << 250n) - 1n).toString() }) }), { auid: null, s_u: ((1n << 250n) - 1n).toString(), profile: null });
});

await t('readAttrRecord: 기록 없음·깨진 JSON → null, profile 이 배열이면 profile:null', async () => {
  assert.equal(await readAttrRecord({ fetch: noFetch, localStorage: fakeStorage() }), null);
  assert.equal(await readAttrRecord({ fetch: noFetch, localStorage: fakeStorage({ mode3_attr_tool_v1: '{x' }) }), null);
  assert.deepEqual(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage({ version: 5, s_u: S_OK, profile: ['a'] }) }), { auid: null, s_u: S_OK, profile: null });
});

// 2026-11-20(사용자 결정): 속성 도구는 기록에 salt 를 두지 않는다(version 6) — 그 salt 의 auid(공개값)만 있다
await t('readAttrRecord: version 6 은 { auid, s_u:null, profile } — auid 가 숫자가 아니거나 salt 가 섞여 있으면 null', async () => {
  const rec = { version: 6, auid: '0042', profile: { birthYear: '1990', country: 'KR' } };
  assert.deepEqual(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage(rec) }), { auid: '42', s_u: null, profile: rec.profile }, '정규 10진으로');
  assert.equal(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage({ version: 6, auid: 'x1', profile: {} }) }), null);
  assert.equal(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage({ version: 6, profile: {} }) }), null);
  assert.equal(await readAttrRecord({ fetch: noFetch, localStorage: recordStorage({ version: 6, auid: '42', s_u: S_OK, profile: {} }) }), null, 'version 6 기록에 salt 가 있으면 도구가 쓴 것이 아니다');
});

// ---- 패스키 가입의 Google 왕복(스펙 2026-11-20 passkey-google-signup §2) ----
const SIGNUP = { idpOrigin: 'https://idp.example', loginNonce: '77', uid: '100003', reg: { auid: '5', n: '6', tag: '7' }, login: { uid: '100003', nonce: '77' } };
await t('googleSignupUrl: 암묵 흐름(id_token)·openid email·계정 고르기, state 는 "지갑 오리진(base64url).난수"', async () => {
  const { url, state } = googleSignupUrl({ authorizeUrl: 'https://accounts.example/auth', clientId: 'cid-1', redirectUri: 'https://127.0.0.1:5100/google-relay', nonce: 'reg:abc', walletOrigin: 'https://wallet.example:5100', rand: 'aabbcc' });
  const u = new URL(url);
  assert.equal(u.origin + u.pathname, 'https://accounts.example/auth');
  assert.deepEqual(Object.fromEntries(u.searchParams), { client_id: 'cid-1', response_type: 'id_token', scope: 'openid email', redirect_uri: 'https://127.0.0.1:5100/google-relay', nonce: 'reg:abc', state, prompt: 'select_account' });
  const [o, r] = state.split('.');
  assert.equal(Buffer.from(o, 'base64url').toString(), 'https://wallet.example:5100'); assert.equal(r, 'aabbcc');
  assert.doesNotMatch(o, /[+/=]/, 'base64url 이어야 중계 화면이 푼다');
});
await t('takeGoogleReturn: Google 에서 돌아온 길이 아니면 null — 저장분을 건드리지 않는다', async () => {
  const st = fakeStorage(); saveSignupPending(st, { ...SIGNUP, state: 's1', at: 1000 });
  assert.equal(takeGoogleReturn({ hash: '', storage: st, now: 2000 }), null);
  assert.equal(takeGoogleReturn({ hash: '#other=1', storage: st, now: 2000 }), null);
  assert.ok(st.getItem(SIGNUP_PENDING_KEY));
});
await t('takeGoogleReturn: state 가 맞으면 저장분과 토큰을 돌려주고 저장분을 지운다(1회용)', async () => {
  const st = fakeStorage(); saveSignupPending(st, { ...SIGNUP, state: 's1', at: 1000 });
  const back = takeGoogleReturn({ hash: '#google_back=1&state=s1&id_token=T.O.K', storage: st, now: 2000 });
  assert.deepEqual(back, { pend: { ...SIGNUP, state: 's1', at: 1000 }, idToken: 'T.O.K', error: null });
  assert.equal(st.getItem(SIGNUP_PENDING_KEY), null);
  assert.deepEqual(takeGoogleReturn({ hash: '#google_back=1&state=s1&id_token=T.O.K', storage: st, now: 2000 }), { pend: null, idToken: null, error: null }, '두 번째는 이어받지 못한다');
});
await t('takeGoogleReturn: state 불일치·10분 초과·저장분 없음은 pend:null(토큰도 내주지 않는다), Google 의 오류는 error 로', async () => {
  let st = fakeStorage(); saveSignupPending(st, { ...SIGNUP, state: 's1', at: 1000 });
  assert.deepEqual(takeGoogleReturn({ hash: '#google_back=1&state=other&id_token=T', storage: st, now: 2000 }), { pend: null, idToken: null, error: null });
  assert.equal(st.getItem(SIGNUP_PENDING_KEY), null, '어긋나도 지운다');
  st = fakeStorage(); saveSignupPending(st, { ...SIGNUP, state: 's1', at: 1000 });
  assert.deepEqual(takeGoogleReturn({ hash: '#google_back=1&state=s1&id_token=T', storage: st, now: 1000 + PENDING_MAX_AGE_MS + 1 }), { pend: null, idToken: null, error: null });
  assert.deepEqual(takeGoogleReturn({ hash: '#google_back=1&state=s1&id_token=T', storage: fakeStorage(), now: 2000 }), { pend: null, idToken: null, error: null });
  st = fakeStorage({ [SIGNUP_PENDING_KEY]: '{깨진' });
  assert.deepEqual(takeGoogleReturn({ hash: '#google_back=1&state=s1&id_token=T', storage: st, now: 2000 }), { pend: null, idToken: null, error: null });
  st = fakeStorage(); saveSignupPending(st, { ...SIGNUP, state: 's1', at: 1000 });
  const denied = takeGoogleReturn({ hash: '#google_back=1&state=s1&error=access_denied', storage: st, now: 2000 });
  assert.equal(denied.idToken, null); assert.equal(denied.error, 'access_denied'); assert.equal(denied.pend.uid, '100003');
});

// ---- 래퍼 로그인의 Google 왕복(스펙 2026-11-20 zkwrapper §2.2, 계획 Task 4) ----
await t('googleAuthUrl: prompt 는 늘 select_account — prompt=none 으로 조용히 토큰을 받는 주소를 만들지 않는다', async () => {
  for (const extra of [{}, { prompt: 'none' }, { prompt: 'consent' }]) {
    const { url, state } = googleAuthUrl({ authorizeUrl: 'https://accounts.example/auth', clientId: 'wrap-1', redirectUri: 'https://127.0.0.1:5100/google-relay', nonce: 'wrap:' + 'ab'.repeat(32), walletOrigin: 'https://wallet.zkd.test:5100', rand: 'r1', ...extra });
    const q = new URL(url).searchParams;
    assert.equal(q.get('prompt'), 'select_account'); assert.equal(q.get('response_type'), 'id_token'); assert.equal(q.get('nonce'), 'wrap:' + 'ab'.repeat(32)); assert.equal(q.get('state'), state);
  }
});
await t('saveWrapperPending·takeWrapperReturn: state 가 맞으면 요청·오리진·토큰을 돌려주고 저장분을 지운다(1회용) — 저장분에는 공개값뿐', async () => {
  const st = fakeStorage();
  saveWrapperPending(st, { state: 's1', at: 1000, req: REQ, origin: 'http://rp.example', secret: 'x' });
  assert.deepEqual(JSON.parse(st.m.get(WRAPPER_PENDING_KEY)), { state: 's1', at: 1000, req: REQ, origin: 'http://rp.example' }, '정해진 칸만 남긴다');
  assert.equal(takeWrapperReturn({ hash: '#other=1', storage: st, now: 2000 }), null); assert.ok(st.m.has(WRAPPER_PENDING_KEY), '돌아온 길이 아니면 저장분을 건드리지 않는다');
  const back = takeWrapperReturn({ hash: '#google_back=1&state=s1&id_token=T.O.K', storage: st, now: 2000 });
  assert.deepEqual(back.pend.req, REQ); assert.equal(back.pend.origin, 'http://rp.example'); assert.equal(back.pend.at, 1000); assert.equal(back.idToken, 'T.O.K'); assert.equal(back.error, null);
  assert.equal(st.m.has(WRAPPER_PENDING_KEY), false);
  assert.deepEqual(takeWrapperReturn({ hash: '#google_back=1&state=s1&id_token=T.O.K', storage: st, now: 2000 }), { pend: null, idToken: null, error: null }, '두 번째는 이어받지 못한다');
});
await t('takeWrapperReturn: state 불일치·10분 초과·저장분 없음·요청 없는 저장분은 pend:null(토큰도 내주지 않는다), Google 의 오류는 error 로', async () => {
  const none = { pend: null, idToken: null, error: null };
  let st = fakeStorage(); saveWrapperPending(st, { state: 's1', at: 1000, req: REQ, origin: 'http://rp.example' });
  assert.deepEqual(takeWrapperReturn({ hash: '#google_back=1&state=OTHER&id_token=T.O.K', storage: st, now: 2000 }), none); assert.equal(st.m.has(WRAPPER_PENDING_KEY), false, '어긋나도 저장분은 지운다');
  st = fakeStorage(); saveWrapperPending(st, { state: 's1', at: 1000, req: REQ, origin: 'http://rp.example' });
  assert.deepEqual(takeWrapperReturn({ hash: '#google_back=1&state=s1&id_token=T.O.K', storage: st, now: 1000 + PENDING_MAX_AGE_MS + 1 }), none);
  assert.deepEqual(takeWrapperReturn({ hash: '#google_back=1&state=s1&id_token=T.O.K', storage: fakeStorage(), now: 2000 }), none);
  st = fakeStorage({ [WRAPPER_PENDING_KEY]: JSON.stringify({ state: 's1', at: 1000, origin: 'http://rp.example' }) });
  assert.deepEqual(takeWrapperReturn({ hash: '#google_back=1&state=s1&id_token=T.O.K', storage: st, now: 2000 }), none);
  // 가입용 저장분(다른 열쇠)은 래퍼 귀환이 이어받지 않는다
  st = fakeStorage(); saveSignupPending(st, { state: 's1', at: 1000, idpOrigin: 'http://idp.example', uid: '1' });
  assert.deepEqual(takeWrapperReturn({ hash: '#google_back=1&state=s1&id_token=T.O.K', storage: st, now: 2000 }), none);
  st = fakeStorage(); saveWrapperPending(st, { state: 's1', at: 1000, req: REQ, origin: 'http://rp.example' });
  const denied = takeWrapperReturn({ hash: '#google_back=1&state=s1&error=access_denied', storage: st, now: 2000 });
  assert.equal(denied.idToken, null); assert.equal(denied.error, 'access_denied'); assert.deepEqual(denied.pend.req, REQ);
});

console.log(fails ? `\n${fails} failed` : '\nall passed');
process.exit(fails ? 1 : 0);
