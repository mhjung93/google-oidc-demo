// tests/test_mode3_wrapper_auth.mjs — zkWrapper 의 요청 결속(lib/mode3_wrapper_auth.js, 스펙 2026-11-20 zkwrapper §2.2·§3). 외부 의존 없음(unit).
// Google ID 토큰은 1회용 요청 키 pk_e 에 묶이고(nonce = "wrap:" + H(pk_e)), 발급·폐기 요청의 본문에는 pk_e 의 서명이 붙는다 — 토큰만 가진 쪽은 아무것도 못 한다.
import assert from 'node:assert/strict';
import { WRAPPER_PREFIX, generateRequestKey, wrapperNonce, isWrapperNonce, issueDigest, revokeDigest, signDigest, verifyDigest, signIssue, verifyIssue } from '../lib/mode3_wrapper_auth.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.stack ?? e.message); } }
const AUD = 'https://wallet.example:5100';
const BODY = { auid: '11', auid_s: '22', arid_s: '33', C_u_pt: { x: '44', y: '55' }, C_s_pt: { x: '66', y: '77' }, chainid: '31337', allowAgent: '0', max_height: '400' };
const clone = (o) => JSON.parse(JSON.stringify(o));

await t("generateRequestKey: 개인키는 꺼낼 수 없고(extractable:false) 공개키는 P-256 JWK", async () => {
  const k = await generateRequestKey();
  assert.equal(k.privateKey.extractable, false); assert.equal(k.privateKey.type, 'private');
  assert.equal(k.pkE.kty, 'EC'); assert.equal(k.pkE.crv, 'P-256'); assert.equal(typeof k.pkE.x, 'string'); assert.equal(typeof k.pkE.y, 'string'); assert.equal('d' in k.pkE, false, '공개키에 개인 성분이 없다');
});
await t("wrapperNonce: 같은 키면 같은 값, 다른 키면 다른 값, 'wrap:' + hex 64자", async () => {
  const a = await generateRequestKey(), b = await generateRequestKey();
  const na = await wrapperNonce(a.pkE);
  assert.equal(WRAPPER_PREFIX, 'wrap:'); assert.match(na, /^wrap:[0-9a-f]{64}$/);
  assert.equal(await wrapperNonce(clone(a.pkE)), na); assert.notEqual(await wrapperNonce(b.pkE), na);
  assert.equal(isWrapperNonce(na), true);
  for (const bad of ['issue:' + 'a'.repeat(64), 'wrap:xyz', 'wrap:' + 'a'.repeat(63), '', null, 5]) assert.equal(isWrapperNonce(bad), false, String(bad));
  for (const badKey of [null, {}, { kty: 'EC', crv: 'P-384', x: a.pkE.x, y: a.pkE.y }, { kty: 'EC', crv: 'P-256', x: 'AA', y: a.pkE.y }]) await assert.rejects(wrapperNonce(badKey), (e) => e.reason === 'malformed');
});
await t('signIssue/verifyIssue: 맞는 키·본문·서버 주소면 true', async () => {
  const k = await generateRequestKey();
  const sig = await signIssue(k.privateKey, BODY, AUD);
  assert.match(sig, /^[A-Za-z0-9_-]{86}$/, '64바이트 서명의 base64url');
  assert.equal(await verifyIssue(k.pkE, clone(BODY), sig, AUD), true);
});
await t('verifyIssue: 본문의 필드 하나를 바꾸거나 서버 주소가 다르면 false', async () => {
  const k = await generateRequestKey(); const sig = await signIssue(k.privateKey, BODY, AUD);
  for (const [path, v] of [['auid', '12'], ['auid_s', '23'], ['arid_s', '34'], ['C_u_pt.x', '45'], ['C_s_pt.y', '78'], ['chainid', '31338'], ['allowAgent', '1'], ['max_height', '401']]) {
    const b = clone(BODY); const ks = path.split('.'); if (ks.length === 2) b[ks[0]][ks[1]] = v; else b[path] = v;
    assert.equal(await verifyIssue(k.pkE, b, sig, AUD), false, path);
  }
  assert.equal(await verifyIssue(k.pkE, BODY, sig, 'https://other.example'), false, '다른 서버');
});
await t('verifyIssue: 다른 키의 서명·잘린 서명·빈 문자열·P-256 이 아닌 키·필드가 빠진 본문이면 false(던지지 않는다)', async () => {
  const k = await generateRequestKey(), other = await generateRequestKey(); const sig = await signIssue(k.privateKey, BODY, AUD);
  assert.equal(await verifyIssue(other.pkE, BODY, sig, AUD), false);
  for (const s of [sig.slice(0, -4), '', 'x', null, 12, sig + 'AA']) assert.equal(await verifyIssue(k.pkE, BODY, s, AUD), false, String(s));
  for (const key of [null, {}, { ...k.pkE, crv: 'P-384' }, { ...k.pkE, x: 'AA' }]) assert.equal(await verifyIssue(key, BODY, sig, AUD), false);
  const short = clone(BODY); delete short.arid_s; assert.equal(await verifyIssue(k.pkE, short, sig, AUD), false);
});
await t("issueDigest: 필드가 빠지거나 문자열이 아니면 던진다(reason 'malformed'), 서버 주소가 다르면 다른 값", async () => {
  for (const drop of ['auid', 'auid_s', 'arid_s', 'C_u_pt', 'C_s_pt', 'chainid', 'allowAgent', 'max_height']) { const b = clone(BODY); delete b[drop]; assert.throws(() => issueDigest(b, AUD), (e) => e.reason === 'malformed', drop); }
  assert.throws(() => issueDigest({ ...clone(BODY), auid: 11 }, AUD), (e) => e.reason === 'malformed', '숫자는 받지 않는다');
  assert.throws(() => issueDigest({ ...clone(BODY), auid_s: '2|2' }, AUD), (e) => e.reason === 'malformed', '구분자가 든 값');
  assert.throws(() => issueDigest(BODY, ''), (e) => e.reason === 'malformed');
  assert.notDeepEqual(issueDigest(BODY, AUD), issueDigest(BODY, 'https://other.example'));
  assert.ok(new TextDecoder().decode(issueDigest(BODY, AUD)).startsWith(`zkwrapper|issue|${AUD}|`));
});
await t('revokeDigest: 목적이 본문에 들어가 발급 서명과 겹치지 않는다 — 세션 폐기는 Cf_s 가 필요하다', async () => {
  const k = await generateRequestKey();
  const ds = revokeDigest({ scope: 'session', Cf_s: '999' }, AUD), da = revokeDigest({ scope: 'account' }, AUD);
  assert.ok(new TextDecoder().decode(ds).startsWith(`zkwrapper|revoke_session|${AUD}|`)); assert.ok(new TextDecoder().decode(da).startsWith(`zkwrapper|revoke_account|${AUD}`));
  assert.notDeepEqual(ds, da); assert.notDeepEqual(ds, revokeDigest({ scope: 'session', Cf_s: '998' }, AUD));
  for (const bad of [{ scope: 'session' }, { scope: 'session', Cf_s: 9 }, { scope: 'other' }, {}, null]) assert.throws(() => revokeDigest(bad, AUD), (e) => e.reason === 'malformed');
  const sig = await signDigest(k.privateKey, ds);
  assert.equal(await verifyDigest(k.pkE, ds, sig), true); assert.equal(await verifyDigest(k.pkE, da, sig), false, '세션 폐기 서명은 계정 폐기에 못 쓴다');
  assert.equal(await verifyDigest(k.pkE, issueDigest(BODY, AUD), sig), false, '폐기 서명은 발급에 못 쓴다');
  const isig = await signIssue(k.privateKey, BODY, AUD); assert.equal(await verifyDigest(k.pkE, ds, isig), false, '발급 서명은 폐기에 못 쓴다');
});
console.log(fails ? `\n${fails} failed` : '\nall passed');
process.exit(fails ? 1 : 0);
