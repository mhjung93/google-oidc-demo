// tests/test_mode3_vault_hold.mjs — 금고의 10분 passkey salt 보관(passkey-web). (unit)  node tests/test_mode3_vault_hold.mjs
import assert from 'node:assert/strict';
import { createVault, PASSKEY_HOLD_MS } from '../mode3/user/core/vault.js';
import { createMemKv } from '../mode3/user/core/kv_mem.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

const S = '123456789012345678901234567890123456789';
const MIN = 60_000;
let tm = 1_000_000;
const now = () => tm;
async function fresh(opts = {}) { tm = 1_000_000; const kv = createMemKv(); const vault = createVault(kv, { now, ...opts }); await vault.setup(null); return { kv, vault }; }

await t('상수: 10분', () => assert.equal(PASSKEY_HOLD_MS, 10 * MIN));
// 평문 부재 검사(2026-11-17 미뤄 둔 Minor C): 상자(box) 직렬화 모양에 기대지 않고 kv 의 날 레코드를 전부 훑는다 — 문자열·바이트 배열(ArrayBuffer·TypedArray)을
// 재귀로 모아 salt 의 10진·16진(값·10진 문자열의 UTF-8)·base64(같은 둘)·날 바이트(값의 big-endian·10진 문자열의 UTF-8)를 찾는다. CryptoKey 는 내용을 꺼낼 수 없어 건너뛴다.
const bytesOf = (v) => (v instanceof ArrayBuffer ? new Uint8Array(v) : ArrayBuffer.isView(v) ? new Uint8Array(v.buffer, v.byteOffset, v.byteLength) : null);
function rawParts(v, out = { strings: [], blobs: [] }, seen = new Set()) {
  if (v === null || v === undefined) return out;
  if (typeof v === 'string') { out.strings.push(v); return out; }
  if (typeof v === 'number' || typeof v === 'bigint' || typeof v === 'boolean') { out.strings.push(String(v)); return out; }
  const b = bytesOf(v); if (b) { out.blobs.push(b); return out; }
  if (typeof v !== 'object' || seen.has(v) || (globalThis.CryptoKey && v instanceof CryptoKey)) return out;
  seen.add(v);
  for (const k of Object.keys(v)) { out.strings.push(k); rawParts(v[k], out, seen); }
  return out;
}
function saltForms(dec) {
  const n = BigInt(dec); let hex = n.toString(16); if (hex.length % 2) hex = '0' + hex;
  const be = Buffer.from(hex, 'hex'), utf = Buffer.from(dec, 'utf8');
  return { strings: [dec, hex, utf.toString('hex'), be.toString('base64').replace(/=+$/, ''), utf.toString('base64').replace(/=+$/, '')], blobs: [be, utf] };
}
// 문자열 안의 16진·base64(url) 처럼 보이는 토막은 바이트로 풀어 함께 본다(2026-11-17 Minor C 수정 1) — base64(JSON{…s_u…}) 처럼 salt 가 인코딩 경계와
// 어긋난 자리에 있어도 잡는다. 토막 앞에 다른 글자가 붙었을 수 있어 시작 위치를 몇 칸(16진 2, base64 4) 옮겨 가며 푼다.
function decodedBlobs(str) {
  const out = [];
  for (const m of str.matchAll(/[0-9a-fA-F]{8,}/g)) for (let o = 0; o < 2; o++) { const h = m[0].slice(o); out.push(Buffer.from(h.slice(0, h.length - (h.length % 2)), 'hex')); }
  for (const m of str.matchAll(/[A-Za-z0-9+/_-]{8,}={0,2}/g)) for (let o = 0; o < 4; o++) out.push(Buffer.from(m[0].slice(o).replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  return out;
}
async function plaintextIn(kv, dec) {
  const parts = { strings: [], blobs: [] };
  for (const k of await kv.keys()) rawParts(await kv.get(k), parts);
  const f = saltForms(dec);
  const hay = parts.strings.join('\n').toLowerCase();
  for (const x of f.strings) if (hay.includes(x.toLowerCase())) return `문자열 형태 ${x}`;
  const hexAscii = Buffer.from(f.strings[1], 'utf8');   // 값의 16진을 글자로 담은 바이트(풀어낸 JSON 안의 "0x…" 등)
  const blobs = [...parts.blobs.map((b) => Buffer.from(b)), ...parts.strings.flatMap(decodedBlobs)];
  for (const b of blobs) for (const x of [...f.blobs, hexAscii]) if (b.includes(x) || b.toString('latin1').toLowerCase().includes(x.toString('latin1').toLowerCase())) return `바이트 형태 ${x.toString('hex')}`;
  return null;
}
await t('평문 검사 자체: 어디에 어떤 모양으로 숨겨도 찾는다(대조군)', async () => {
  const hex = BigInt(S).toString(16).padStart(Math.ceil(BigInt(S).toString(16).length / 2) * 2, '0');
  // base64(JSON)·16진(JSON) 회귀 대조군: salt 가 인코딩 경계와 어긋난 자리에 있도록 앞에 길이가 다른 필드를 둔다. 다른 글자 뒤에 붙은 토막도 넣는다.
  const enc = (o, how) => Buffer.from(JSON.stringify(o)).toString(how);
  const jsonPlants = [];
  for (const pad of ['', 'a', 'ab', 'abc']) {
    jsonPlants.push({ b64: enc({ pad, s_u: S }, 'base64') }, { b64u: enc({ pad, s_u: S }, 'base64url') }, { hx: enc({ pad, s_u: S }, 'hex') }, { mixed: `box:${enc({ pad, s_u: S }, 'base64')}` }, { hexval: enc({ pad, v: '0x' + hex }, 'base64') });
  }
  for (const planted of [{ a: { b: [S] } }, { x: new TextEncoder().encode(S) }, { y: Uint8Array.from(Buffer.from(hex, 'hex')).buffer }, { z: Buffer.from(S).toString('base64') }, { w: hex.toUpperCase() }, ...jsonPlants]) {
    const kv = createMemKv(); await kv.set('k', planted);
    assert.ok(await plaintextIn(kv, S), `못 찾음: ${JSON.stringify(planted).slice(0, 80)}`);
  }
  assert.equal(await plaintextIn(createMemKv(), S), null);
});
await t('보관·읽기: 읽힌다, kv 날 레코드 어디에도 salt 평문(10진·16진·base64·바이트)이 없다', async () => {
  const { kv, vault } = await fresh();
  assert.equal(await vault.holdSalt(S), true);
  assert.equal(await vault.heldSalt(), S);
  assert.equal(await vault.heldUntil(), tm + PASSKEY_HOLD_MS);
  assert.equal(await plaintextIn(kv, S), null);
});
// 2026-11-17(미뤄 둔 Minor C): salt 와 만료를 한 번의 복호로 함께 — heldSalt()·heldUntil() 을 따로 부르면 그 사이에 만료·덮어쓰기가 끼어 서로 다른 보관분을 볼 수 있다.
await t('held(): 한 번에 { s_u, until }, 없으면 null', async () => {
  const { vault } = await fresh();
  assert.equal(await vault.held(), null);
  await vault.holdSalt(S);
  assert.deepEqual(await vault.held(), { s_u: S, until: tm + PASSKEY_HOLD_MS });
  tm += PASSKEY_HOLD_MS + 1;
  assert.equal(await vault.held(), null);
});
await t('만료: null 이고 kv 키가 지워진다', async () => {
  const { kv, vault } = await fresh();
  await vault.holdSalt(S); tm += PASSKEY_HOLD_MS + 1;
  assert.equal(await vault.heldSalt(), null);
  assert.equal(await kv.get('passkeyHold'), undefined);
});
await t('늘리지 않음: 읽어도 until 이 그대로', async () => {
  const { vault } = await fresh();
  await vault.holdSalt(S); tm += 9 * MIN;
  assert.equal(await vault.heldSalt(), S);
  tm += MIN + 1;
  assert.equal(await vault.heldSalt(), null);
});
await t('다른 탭: 같은 kv 의 두 번째 금고가 읽는다', async () => {
  const { kv, vault } = await fresh();
  await vault.holdSalt(S);
  assert.equal(await createVault(kv, { now }).heldSalt(), S);
});
await t('끔: holdMs 0 이면 false, kv 에 키 없음', async () => {
  const { kv, vault } = await fresh({ holdMs: 0 });
  assert.equal(await vault.holdSalt(S), false);
  assert.equal(await kv.get('passkeyHold'), undefined);
});
await t('지우기: clearHold 뒤 null', async () => {
  const { vault } = await fresh();
  await vault.holdSalt(S); await vault.clearHold();
  assert.equal(await vault.heldSalt(), null); assert.equal(await vault.heldUntil(), null);
});
await t('덮어쓰기: 새 until', async () => {
  const { vault } = await fresh();
  await vault.holdSalt(S); tm += 5 * MIN; await vault.holdSalt('42');
  assert.equal(await vault.heldSalt(), '42'); assert.equal(await vault.heldUntil(), tm + PASSKEY_HOLD_MS);
});
await t('바깥 until 조작: 안쪽과 달라 null, 키 삭제', async () => {
  const { kv, vault } = await fresh();
  await vault.holdSalt(S);
  const h = await kv.get('passkeyHold'); await kv.set('passkeyHold', { ...h, until: h.until + 10 * MIN });
  assert.equal(await vault.heldSalt(), null);
  assert.equal(await kv.get('passkeyHold'), undefined);
});
await t('잠김: 금고 없으면 holdSalt locked, heldSalt null', async () => {
  const vault = createVault(createMemKv(), { now });
  await assert.rejects(vault.holdSalt(S), (e) => e.reason === 'locked');
  assert.equal(await vault.heldSalt(), null); assert.equal(await vault.heldUntil(), null);
});
await t('형식: 0·abc·2^250 이상은 reject', async () => {
  const { vault } = await fresh();
  for (const bad of ['0', 'abc', '', (2n ** 250n).toString(), 5, null]) await assert.rejects(vault.holdSalt(bad), `거부돼야 함: ${bad}`);
});
// 2026-11-17(미뤄 둔 Minor C): 정규 10진만 — 앞자리 0·부호·공백이 붙은 같은 값은 사유(passkey_bad_salt)가 붙은 오류로 거절하고 보관하지 않는다.
await t('형식: 비정규 10진(007·+7·공백)은 passkey_bad_salt, 보관하지 않는다', async () => {
  const { kv, vault } = await fresh();
  for (const bad of ['007', '0' + S, '+7', ' 7', '7 ', '7\n', '1e3', '0x10']) {
    await assert.rejects(vault.holdSalt(bad), (e) => e.reason === 'passkey_bad_salt', `거부돼야 함: ${JSON.stringify(bad)}`);
  }
  assert.equal(await kv.get('passkeyHold'), undefined);
  assert.equal(await vault.holdSalt('7'), true);
});
process.exit(fails ? 1 : 0);
