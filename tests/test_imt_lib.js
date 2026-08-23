// 이 테스트는 측정 전용 래퍼 회로를 필요로 한다. 없으면 아래로 재생성한다:
//   printf 'pragma circom 2.0.0;\ninclude "lib/imt_nonmembership.circom";\ncomponent main {public [root]} = IMTNonMembership(20);\n' > /tmp/test_imt_only.circom
//   circom /tmp/test_imt_only.circom --r1cs --wasm -o /tmp/imt_measure -l circuits -l circuits/lib -l node_modules/circomlib/circuits
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

  // 회귀 테스트 1 (Critical 1): 아무것도 넣지 않은 새 트리도 회로를 통과하는
  // witness를 내야 한다. anchor(0) 리프가 없던 예전 구현은 build()가 리터럴
  // 0을 리프로 취급했지만, getNonMembershipWitness()는 별도 분기에서
  // lowValue/lowNextValue를 '0'/'0'으로 반환해 Poseidon(0,0) != 0 이 되어
  // 회로의 root === cur[depth] 단언에서 실패했다.
  {
    const freshTree = await createIMT(20);
    const freshWitness = await freshTree.getNonMembershipWitness(999n);
    await calc.calculateWitness({ ...freshWitness, target: '999' }, true);
    console.log('OK: empty tree witness round-trips through the circuit');
  }

  // 회귀 테스트 2 (Critical 2): 이미 값이 들어간 트리에서, 저장된 모든 값보다
  // 작은 target을 요청해도 witness를 낼 수 있어야 한다. anchor(0)가 항상
  // lowValue 후보로 남아 있으므로 lowIdx === -1 로 빠지지 않는다.
  {
    const belowMinTree = await createIMT(20);
    await belowMinTree.insert(500n);
    await belowMinTree.insert(1000n);
    const belowMinWitness = await belowMinTree.getNonMembershipWitness(100n);
    assert.equal(belowMinWitness.lowValue, '0', 'the anchor leaf must serve as the low bound');
    await calc.calculateWitness({ ...belowMinWitness, target: '100' }, true);
    console.log('OK: below-minimum target witness round-trips through the circuit');
  }

  // 회귀 테스트 3 (Important 3): 마스킹되지 않은 원시 Poseidon 다이제스트
  // (>= 2^252)는 회로의 Num2Bits(252) range-check를 깨므로 insert() 단계에서
  // 거부되어야 한다.
  {
    const unmaskedTree = await createIMT(20);
    await assert.rejects(
      () => unmaskedTree.insert(1n << 252n),
      /outside/,
      'insert() must reject values >= 2^252',
    );
    console.log('OK: insert() rejects an unmasked value >= 2^252');
  }

  // 회귀 테스트 4 (Critical 4): 음수는 insert() 단계에서 거부되어야 한다.
  // 음수를 허용하면 트리의 anchor(0)을 대체해서 회로 증명이 불가능해진다.
  {
    const negativeTree = await createIMT(20);
    await assert.rejects(
      () => negativeTree.insert(-5n),
      /outside/,
      'insert() must reject negative values',
    );
    console.log('OK: insert() rejects negative values');
  }

  // 회귀 테스트 5 (Critical 5): 원시 Poseidon 다이제스트(비트 252 이상 설정)를
  // getNonMembershipWitness()에 넘기면 회로와 같은 마스킹을 거쳐서
  // witness가 회로를 통과해야 한다.
  {
    const rawTargetTree = await createIMT(20);
    const masked1 = 500n;
    const masked2 = 1000n;
    await rawTargetTree.insert(masked1);
    await rawTargetTree.insert(masked2);

    // 두 값 사이에 있고 비트 252 이상이 설정된 target
    const unmaskedTarget = 600n + (1n << 252n);
    const witness = await rawTargetTree.getNonMembershipWitness(unmaskedTarget);

    // 회로에 원시(마스킹되지 않은) 값을 넘기면 회로가 내부에서 마스킹해서 처리
    await calc.calculateWitness({ ...witness, target: unmaskedTarget.toString() }, true);
    console.log('OK: raw unmasked target round-trips through the circuit');
  }

  console.log('PASS: IMT library inserts, changes root, and produces non-membership witnesses.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
