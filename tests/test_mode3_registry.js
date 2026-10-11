// 등록부 슬롯 트리(스펙 2026-10-01 §3.1). (unit 그룹)  node tests/test_mode3_registry.js
import assert from 'node:assert/strict';
import { buildPoseidon } from 'circomlibjs';
import { REG_DEPTH, registryLeaf, createRegistryTree, computeRoot } from '../lib/mode3_registry.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

await t('빈 트리 root = 영해시 체인, 깊이 20', async () => {
  const ps = await buildPoseidon(); const H = (a, b) => ps.F.toObject(ps([a, b]));
  let z = 0n; for (let i = 0; i < 20; i++) z = H(z, z);
  const tree = await createRegistryTree();
  assert.equal(tree.depth, REG_DEPTH); assert.equal(REG_DEPTH, 20);
  assert.equal(tree.root(), z);
});
await t('registryLeaf = Poseidon(cm.x, cm.y, Cf_u); 문자열 입력도 같다', async () => {
  const ps = await buildPoseidon();
  const a = await registryLeaf({ x: 11n, y: 22n }, 33n);
  assert.equal(a, ps.F.toObject(ps([11n, 22n, 33n])));
  assert.equal(await registryLeaf({ x: '11', y: '22' }, '33'), a);
});
await t('set/leafAt/path: 경로로 root 가 재계산되고, 덮어쓰기·0 으로 비우기가 된다', async () => {
  const tree = await createRegistryTree();
  tree.set(0, 101n); tree.set(5, 505n); tree.set(1023, 7n);
  assert.equal(tree.leafAt(5), 505n); assert.equal(tree.leafAt(6), 0n);
  const { pathElements, pathIndices } = tree.path(5);
  assert.equal(pathElements.length, 20); assert.equal(pathIndices.length, 20);
  assert.deepEqual(pathIndices.slice(0, 4), [1, 0, 1, 0]);   // 5 = 0b101
  assert.equal(await computeRoot(505n, pathElements, pathIndices), tree.root());
  const before = tree.root();
  tree.set(5, 506n); assert.notEqual(tree.root(), before);
  assert.equal(await computeRoot(506n, tree.path(5).pathElements, tree.path(5).pathIndices), tree.root());
  tree.set(5, 0n); tree.set(1023, 0n); tree.set(0, 0n);
  const empty = await createRegistryTree();
  assert.equal(tree.root(), empty.root(), '전부 비우면 빈 트리 root');
  assert.deepEqual(empty.entries(), []);
});
await t('entries 는 0 이 아닌 (index, leaf) 를 index 순으로', async () => {
  const tree = await createRegistryTree();
  tree.set(9, 1n); tree.set(2, 2n); tree.set(9, 0n); tree.set(4, 4n);
  assert.deepEqual(tree.entries(), [[2, 2n], [4, 4n]]);
});
await t('범위 밖 index·음수 리프는 throw', async () => {
  const tree = await createRegistryTree(4);
  assert.throws(() => tree.set(16, 1n), /index/); assert.throws(() => tree.set(-1, 1n), /index/);
  assert.throws(() => tree.set(1, -1n), /leaf/);
});
await t('depth 32: index ≥ 2^31 도 경로·root 가 맞는다 (32비트 비트연산 회귀)', async () => {
  const tree = await createRegistryTree(32);
  const hi = 2 ** 31, top = 2 ** 32 - 1;
  tree.set(hi, 999n); tree.set(top, 7n); tree.set(5, 505n);
  for (const [i, leaf] of [[hi, 999n], [top, 7n], [5, 505n]]) {
    const { pathElements, pathIndices } = tree.path(i);
    assert.equal(pathElements.length, 32);
    assert.equal(await computeRoot(leaf, pathElements, pathIndices), tree.root(), `index ${i}`);
  }
  assert.deepEqual(tree.entries(), [[5, 505n], [hi, 999n], [top, 7n]]);
  assert.throws(() => tree.set(2 ** 32, 1n), /index/);
});
process.exit(fails ? 1 : 0);
