// tests/test_browser_sha256.js — 순수 JS SHA-256 과 node:crypto shim 이 Node 의 crypto 와 같은 값을 낸다. (unit)  node tests/test_browser_sha256.js
import assert from 'node:assert/strict';
import { createHash as nodeCreateHash, randomBytes as nodeRandomBytes } from 'node:crypto';
import { sha256, sha256Hex, utf8Bytes } from '../lib/browser/sha256.js';
import { createHash, randomBytes } from '../lib/browser/node_crypto.js';

let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

t('표준 벡터: 빈 입력·abc·448비트 경계·2블록', () => {
  assert.equal(sha256Hex(new Uint8Array(0)), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256Hex(utf8Bytes('abc')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256Hex(utf8Bytes('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')), '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  assert.equal(sha256Hex(utf8Bytes('a'.repeat(1000))), nodeCreateHash('sha256').update('a'.repeat(1000)).digest('hex'));
});
t('임의 길이 0..300 바이트 200개가 node:crypto 와 같다', () => {
  for (let i = 0; i < 200; i++) {
    const n = Math.floor(Math.random() * 301);
    const b = new Uint8Array(nodeRandomBytes(n));
    assert.equal(sha256Hex(b), nodeCreateHash('sha256').update(b).digest('hex'), `len=${n}`);
  }
});
t('createHash shim: 문자열(utf8)·hex 문자열·Uint8Array·체이닝·digest()/digest(hex) 가 node 와 같다', () => {
  const s = '한글 origin http://127.0.0.1:3100';
  assert.equal(createHash('sha256').update(s, 'utf8').digest('hex'), nodeCreateHash('sha256').update(s, 'utf8').digest('hex'));
  assert.equal(createHash('sha256').update(s).digest('hex'), nodeCreateHash('sha256').update(s).digest('hex'));
  assert.equal(createHash('sha256').update('deadbeef', 'hex').digest('hex'), nodeCreateHash('sha256').update('deadbeef', 'hex').digest('hex'));
  assert.equal(createHash('sha256').update('ab').update(new Uint8Array([1, 2])).digest('hex'), nodeCreateHash('sha256').update('ab').update(new Uint8Array([1, 2])).digest('hex'));
  const d = createHash('sha256').update('x').digest();
  assert.ok(Buffer.isBuffer(d) && d.length === 32);
  assert.throws(() => createHash('md5'), /sha256/);
});
t('randomBytes shim: 길이·Buffer·toString(hex)·연속 호출이 다르다', () => {
  const a = randomBytes(32), b = randomBytes(32);
  assert.ok(Buffer.isBuffer(a) && a.length === 32);
  assert.match(a.toString('hex'), /^[0-9a-f]{64}$/);
  assert.notEqual(a.toString('hex'), b.toString('hex'));
  assert.equal(randomBytes(0).length, 0);
});
t('originToField·loadSchema 와 같은 입력에서 shim 과 node 가 같다(encodeProfile 경로 동등성)', async () => {
  const { canonicalJson, DEFAULT_ATTR_SCHEMA } = await import('../lib/mode3_attr_schema.js');
  const cj = canonicalJson(DEFAULT_ATTR_SCHEMA);
  assert.equal(createHash('sha256').update(cj).digest('hex'), nodeCreateHash('sha256').update(cj).digest('hex'));
  for (const o of ['http://127.0.0.1:3100', 'https://rp.example.com', 'http://localhost:3101']) assert.equal(createHash('sha256').update(o, 'utf8').digest('hex'), nodeCreateHash('sha256').update(o, 'utf8').digest('hex'));
});
process.exit(fails ? 1 : 0);
