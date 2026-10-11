// 집합 트리(V7 spec §2) — 회로·지갑·RP 가 공유하는 정의. node tests/test_mode3_set_tree.mjs
import assert from 'node:assert/strict';
import { buildPoseidon } from 'circomlibjs';
import { normalizeMembers, setRoot, setPath, SET_DEPTH, SET_SIZE, SET_PAD, NO_SET } from '../lib/mode3_set_tree.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

await t('상수: 깊이 8, 리프 256, 패딩 2^64, NO_SET 은 sel 0·root 0·path 0×8', () => {
  assert.equal(SET_DEPTH, 8); assert.equal(SET_SIZE, 256); assert.equal(SET_PAD, 1n << 64n);
  assert.deepEqual({ ...NO_SET, path: [...NO_SET.path] }, { sel: 0n, root: 0n, index: 0, path: Array(8).fill(0n) });
});

await t('normalizeMembers: 정렬·중복 제거, 문자열·숫자·bigint 혼용 허용', () => {
  assert.deepEqual(normalizeMembers(['840', 410, 392n, '410']), [392n, 410n, 840n]);
});

await t('normalizeMembers: 빈 배열·배열 아님·비정수·음수·≥2^64·257개(중복 제거 후) 는 bad_disclosure', () => {
  for (const bad of [[], 'x', null, ['abc'], [-1], [(1n << 64n).toString()], Array.from({ length: 257 }, (_, i) => i)]) {
    assert.throws(() => normalizeMembers(bad), (e) => e.reason === 'bad_disclosure', `허용되면 안 됨: ${JSON.stringify(bad)?.slice(0, 40)}`);
  }
  assert.equal(normalizeMembers(Array.from({ length: 300 }, (_, i) => i % 256)).length, 256);   // 중복 제거 뒤 256 이면 허용
});

await t('setRoot: 순서·중복과 무관하게 같은 root, 원소가 다르면 다른 root', async () => {
  const a = await setRoot([410, 392, 840, 276, 250]);
  const b = await setRoot(['250', '276', '392', '410', '840', '410']);
  assert.equal(a, b);
  assert.notEqual(a, await setRoot([410, 392, 840, 276]));
});

await t('setRoot: 손으로 계산한 깊이 8 트리(리프 = 값, 빈 자리 = 2^64, Poseidon(2))와 같다', async () => {
  const poseidon = await buildPoseidon();
  const H = (x, y) => poseidon.F.toObject(poseidon([x, y]));
  let layer = Array.from({ length: 256 }, (_, i) => (i < 3 ? [7n, 9n, 11n][i] : SET_PAD));
  for (let d = 0; d < 8; d++) { const n = []; for (let i = 0; i < layer.length; i += 2) n.push(H(layer[i], layer[i + 1])); layer = n; }
  assert.equal(await setRoot([11, 7, 9]), layer[0]);
});

await t('setPath: 경로로 root 를 재구성할 수 있고 index 는 정렬 뒤 위치', async () => {
  const members = [410, 392, 840, 276, 250];
  const { index, path, root } = await setPath(members, 410);
  assert.equal(index, 3);   // 정렬 [250, 276, 392, 410, 840]
  assert.equal(path.length, 8);
  const poseidon = await buildPoseidon();
  const H = (x, y) => poseidon.F.toObject(poseidon([x, y]));
  let cur = 410n, idx = index;
  for (let i = 0; i < 8; i++) { cur = (idx & 1) ? H(path[i], cur) : H(cur, path[i]); idx >>= 1; }
  assert.equal(cur, root);
  assert.equal(root, await setRoot(members));
});

await t('setPath: 없는 값은 disclosure_unsatisfiable, 형식 오류는 bad_disclosure', async () => {
  await assert.rejects(() => setPath([410, 392], 840), (e) => e.reason === 'disclosure_unsatisfiable');
  await assert.rejects(() => setPath([], 840), (e) => e.reason === 'bad_disclosure');
});

if (failed) { console.error(`${failed} failed`); process.exit(1); }
console.log('all passed');
