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

if (fails) { console.log(`\n${fails} 실패`); process.exit(1); }
console.log('\n전부 통과');
