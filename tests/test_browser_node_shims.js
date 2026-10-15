// tests/test_browser_node_shims.js — lib/browser/node_path.js·node_url.js·node_fs.js 가 브라우저에서 'node:path'·'node:url'·'node:fs' 자리를 메우는 값을 낸다. (unit)  node tests/test_browser_node_shims.js
import assert from 'node:assert/strict';
import { join, dirname, basename } from '../lib/browser/node_path.js';
import { fileURLToPath } from '../lib/browser/node_url.js';
import { existsSync, readFileSync } from '../lib/browser/node_fs.js';

let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

t('join: http:// 베이스의 프로토콜 "//" 를 보존한 채 나머지 경로를 붙인다(mode3_wallet.js 류가 import.meta.url 로 만드는 기본 자산 경로와 같은 모양)', () => {
  const base = fileURLToPath(new URL('..', 'http://127.0.0.1:5199/dist/user.js'));
  assert.equal(join(base, 'build', 'mode3', 'pi_cred_js', 'pi_cred.wasm'), 'http://127.0.0.1:5199/build/mode3/pi_cred_js/pi_cred.wasm');
});
t('join: 일반 경로의 중복 슬래시를 하나로 줄인다', () => {
  assert.equal(join('a', 'b/', '/c'), 'a/b/c');
  assert.equal(join('/x//y', 'z'), '/x/y/z');
});
t('dirname·basename', () => {
  assert.equal(dirname('/a/b/c.js'), '/a/b');
  assert.equal(dirname('c.js'), '.');
  assert.equal(basename('/a/b/c.js'), 'c.js');
});
t('fileURLToPath: URL 을 문자열로 그대로 받는다(번들 URL 문자열용)', () => {
  assert.equal(fileURLToPath(new URL('..', 'http://h/dist/user.js')), 'http://h/');
});
t('node_fs shim: existsSync 는 항상 false, readFileSync 는 "브라우저" 를 담은 오류로 죽는다(조용히 빈 값을 주지 않는다)', () => {
  assert.equal(existsSync('x'), false);
  assert.throws(() => readFileSync('x'), /브라우저/);
});
process.exit(fails ? 1 : 0);
