// 패스키 모드 RP ID 인자(passkey-web R-2). 전역 스크립트라 vm 으로 window·location·navigator 를 흉내 낸다.
//   node tests/test_mode3_passkey_rpid.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

globalThis.window = {};
vm.runInThisContext(fs.readFileSync(new URL('../mode3/common/passkey_store.js', import.meta.url), 'utf8'));
const P = globalThis.window.Mode3Passkey;

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

// 케이스마다 갈아 끼우는 브라우저 전역. 호출 인자를 calls 에 기록한다.
function setup(hostname) {
  const calls = { get: [], create: [] };
  const prf = new Uint8Array(32).fill(7);
  const ext = () => ({ prf: { enabled: true, results: { first: prf } } });
  const cred = { rawId: new Uint8Array(16).fill(1), getClientExtensionResults: ext };
  globalThis.window = { PublicKeyCredential: function () {}, isSecureContext: true };
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { credentials: {
    get: async ({ publicKey }) => { calls.get.push(publicKey); return cred; },
    create: async ({ publicKey }) => { calls.create.push(publicKey); return cred; },
  } } });
  globalThis.location = { hostname };
  globalThis.PublicKeyCredential = globalThis.window.PublicKeyCredential;
  globalThis.isSecureContext = true;
  return calls;
}
const wrongOrigin = (e) => e.reason === 'passkey_wrong_origin';
const j = (o) => JSON.stringify(o);

await t('기본은 localhost', async () => {
  const c = setup('localhost');
  await P.derivePrf({ credentialId: 'AA' });
  assert.equal(c.get[0].rpId, 'localhost');
});
await t('rpId 를 따른다', async () => {
  const c = setup('wallet.zkd.test');
  await P.derivePrf({ credentialId: 'AA', rpId: 'wallet.zkd.test' });
  assert.equal(c.get[0].rpId, 'wallet.zkd.test');
});
await t('다른 이름 페이지는 거절', async () => {
  const c = setup('idp.zkd.test');
  await assert.rejects(P.derivePrf({ credentialId: 'AA', rpId: 'wallet.zkd.test' }), wrongOrigin);
  assert.equal(c.get.length, 0);
});
await t('에이전트 경로 불변', async () => {
  const c = setup('wallet.zkd.test');
  await assert.rejects(P.derivePrf({ credentialId: 'AA' }), wrongOrigin);
  assert.equal(c.get.length, 0);
});
await t('IP 거절', async () => {
  const c = setup('192.168.226.128');
  await assert.rejects(P.derivePrf({ credentialId: 'AA', rpId: '192.168.226.128' }), wrongOrigin);
  assert.equal(c.get.length, 0);
});
// 2026-11-17(미뤄 둔 Minor): 문자열이 아닌 rpId 는 TypeError 대신 사유가 붙은 오류; IP 거절 문구는 무엇이 틀렸는지(IP 는 RP ID 가 될 수 없다) 말한다.
await t('문자열이 아닌 rpId 는 사유가 붙은 오류(WebAuthn 을 부르지 않는다)', async () => {
  for (const rpId of [null, 42, {}, '']) {
    const c = setup('wallet.zkd.test');
    await assert.rejects(P.derivePrf({ credentialId: 'AA', rpId }), wrongOrigin, String(rpId));
    await assert.rejects(P.createPasskey({ rpId }), wrongOrigin, String(rpId));
    assert.equal(c.get.length + c.create.length, 0);
  }
});
await t('IP 거절 문구는 IP 가 RP ID 가 될 수 없다고 말하고 이름으로 열라고 한다', async () => {
  for (const ip of ['192.168.226.128', '::1']) {
    setup(ip);
    await assert.rejects(P.derivePrf({ credentialId: 'AA', rpId: ip }), (e) => wrongOrigin(e) && /IP 주소/.test(e.message) && /RP ID 가 될 수 없/.test(e.message) && /이름/.test(e.message) && !/에서만 쓴다/.test(e.message));
  }
});
await t('만들기', async () => {
  const c = setup('wallet.zkd.test');
  await P.createPasskey({ rpId: 'wallet.zkd.test', rpName: 'zk 지갑' });
  assert.deepEqual(c.create[0].rp, { id: 'wallet.zkd.test', name: 'zk 지갑' });
  assert.equal(c.get[0].rpId, 'wallet.zkd.test');
});

// 2026-11-17(미뤄 둔 Minor C): IPv6 RP ID, createPasskey() 기본 rp, 다른 호스트의 createPasskey(만들기 0번), 포트를 붙인 이름의 안내.
await t('IPv6 RP ID(괄호·괄호 없음·링크 로컬)는 IP 로 거절, WebAuthn 0번', async () => {
  for (const ip of ['::1', '[::1]', 'fe80::1', '2001:db8::5', '::ffff:127.0.0.1']) {
    const c = setup(ip);
    await assert.rejects(P.derivePrf({ credentialId: 'AA', rpId: ip }), (e) => wrongOrigin(e) && /IP 주소/.test(e.message), ip);
    await assert.rejects(P.createPasskey({ rpId: ip }), (e) => wrongOrigin(e) && /IP 주소/.test(e.message), ip);
    assert.equal(c.get.length + c.create.length, 0, ip);
  }
});
await t('포트를 붙인 이름(localhost:5100)은 IP 가 아니라 "포트를 빼고 이름만" 이라고 말한다', async () => {
  for (const [rpId, name] of [['localhost:5100', 'localhost'], ['wallet.zkd.test:5100', 'wallet.zkd.test']]) {
    const c = setup(name);
    await assert.rejects(P.derivePrf({ credentialId: 'AA', rpId }), (e) => wrongOrigin(e) && !/IP 주소/.test(e.message) && /포트/.test(e.message) && e.message.includes(`(${name})`), rpId);
    assert.equal(c.get.length, 0);
  }
});
// 2026-11-17(Minor C 수정 1): 숫자 호스트 + 포트('1:2')·줄인 IPv4('127.1', '1')는 이름이 아니라 IP 다 — WHATWG URL 은 마지막 라벨이 숫자인 호스트를 IPv4 로 읽는다.
await t('숫자 호스트(1:2·127.1·1·0x7f.1:5100)는 포트 안내가 아니라 IP 로 거절', async () => {
  for (const rpId of ['1:2', '127.1', '1', '0x7f.1:5100', '127.0.0.1:5100']) {
    const c = setup('localhost');
    await assert.rejects(P.derivePrf({ credentialId: 'AA', rpId }), (e) => wrongOrigin(e) && /IP 주소/.test(e.message) && !/포트/.test(e.message), rpId);
    assert.equal(c.get.length, 0, rpId);
  }
});
await t('createPasskey() 기본: rp = { id: localhost, name: zk 스냅 }, 확인 get 도 localhost', async () => {
  const c = setup('localhost');
  const r = await P.createPasskey();
  assert.deepEqual(c.create[0].rp, { id: 'localhost', name: 'zk 스냅' });
  assert.equal(c.create[0].user.displayName, 'zk 스냅');
  assert.equal(c.get.length, 1); assert.equal(c.get[0].rpId, 'localhost');
  assert.match(r.s_u, /^[1-9][0-9]*$/);
});
await t('다른 호스트의 createPasskey 는 거절하고 만들지 않는다(create 0번)', async () => {
  for (const [host, opts] of [['idp.zkd.test', { rpId: 'wallet.zkd.test' }], ['wallet.zkd.test', {}], ['zkd.test', { rpId: 'wallet.zkd.test' }]]) {
    const c = setup(host);
    await assert.rejects(P.createPasskey(opts), wrongOrigin, `${host} ${j(opts)}`);
    assert.equal(c.create.length + c.get.length, 0, host);
  }
});

if (fails) { console.log(`\n${fails} 실패`); process.exit(1); }
console.log('\n전부 통과');
