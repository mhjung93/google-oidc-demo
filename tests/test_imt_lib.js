import assert from 'node:assert/strict';
import { createIMT, leafValue, TAG_SESSION, TAG_ACCOUNT } from '../lib/imt.js';

async function main() {
  const tree = await createIMT(20);

  // 빈 트리: 무엇이든 비멤버
  const w0 = await tree.getNonMembershipWitness(12345n);
  assert.ok(w0.root, 'empty tree must still produce a root');

  const a = await leafValue(TAG_ACCOUNT, 777n);
  const s = await leafValue(TAG_SESSION, 777n);
  assert.notEqual(a.toString(), s.toString(), 'domain tags must separate identical raw values');

  await tree.insert(a);
  const rootAfter = tree.getRoot();
  assert.notEqual(rootAfter.toString(), w0.root, 'insert must change the root');

  // 삽입한 값은 더 이상 비멤버가 아니다
  await assert.rejects(
    () => tree.getNonMembershipWitness(a),
    /is a member/,
  );

  // 삽입하지 않은 값은 여전히 비멤버이고 witness가 나온다
  const w1 = await tree.getNonMembershipWitness(s);
  assert.equal(w1.pathElements.length, 20);
  assert.equal(w1.pathIndices.length, 20);
  assert.equal(w1.root, rootAfter.toString());

  // 라이브러리가 만든 witness가 실제 회로를 통과해야 한다
  const fs = await import('node:fs');
  const wc = await import('/tmp/imt_measure/test_imt_only_js/witness_calculator.js');
  const wasmBuffer = fs.default.readFileSync('/tmp/imt_measure/test_imt_only_js/test_imt_only.wasm');
  const calc = await wc.default(wasmBuffer);
  await calc.calculateWitness({ ...w1, target: s.toString() }, true);
  console.log('OK: library witness verifies against the circuit');

  console.log('PASS: IMT library inserts, changes root, and produces non-membership witnesses.');
}

main();
