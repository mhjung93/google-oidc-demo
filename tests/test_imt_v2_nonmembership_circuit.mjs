// lib/imt_v2.js가 만든 witness를 정석 IMT 회로가 실제로 받아들이는지 확인한다.
//   node tests/test_imt_v2_nonmembership_circuit.mjs
//
// zkey는 필요 없다. circom으로 --r1cs --wasm만 만들고 witness 계산까지만 한다.
// 필요한 컴파일은 이 스크립트가 스스로 수행하며, 경로는 전부 저장소 기준
// 상대 경로다(기존 tests/test_imt_nonmembership_circuit.mjs 는 /tmp를 하드코딩해
// clean checkout에서 돌지 않는다 — 그 전철을 밟지 않는다).
//
// 산출물은 build/imt_v2/ 에 만든다. build/ 전체가 .gitignore 대상이고,
// 이 디렉터리는 이번 작업으로 새로 생기므로 기존 산출물을 덮어쓰지 않는다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { createIMTv2, buildIMTv2, leafValue, TAG_SESSION } from '../lib/imt_v2.js';

const DEPTH = 20;
const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'imt_v2');
const CIRCUIT_NAME = 'imt_v2_only';
const WRAPPER = path.join(OUT_DIR, `${CIRCUIT_NAME}.circom`);
const WASM = path.join(OUT_DIR, `${CIRCUIT_NAME}_js`, `${CIRCUIT_NAME}.wasm`);
const WTNS = path.join(OUT_DIR, 'scratch.wtns');

// 측정/테스트 전용 main 래퍼. circuits/lib/imt_nonmembership_v2.circom 을 그대로
// 인스턴스화할 뿐이라 저장소에 두지 않고 여기서 생성한다.
const WRAPPER_SRC = `pragma circom 2.0.0;
include "lib/imt_nonmembership_v2.circom";
component main {public [root]} = IMTNonMembershipV2(${DEPTH});
`;

function compileIfNeeded() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const stale = !fs.existsSync(WASM)
    || !fs.existsSync(WRAPPER)
    || fs.readFileSync(WRAPPER, 'utf8') !== WRAPPER_SRC
    || fs.statSync(WASM).mtimeMs
       < fs.statSync(path.join(ROOT_DIR, 'circuits', 'lib', 'imt_nonmembership_v2.circom')).mtimeMs;
  if (!stale) {
    console.log(`OK: reusing ${path.relative(ROOT_DIR, WASM)}`);
    return;
  }
  fs.writeFileSync(WRAPPER, WRAPPER_SRC);
  console.log('… compiling circuits/lib/imt_nonmembership_v2.circom (--r1cs --wasm, no zkey)');
  const out = execFileSync(
    'circom',
    [
      WRAPPER, '--r1cs', '--wasm', '-o', OUT_DIR,
      '-l', path.join(ROOT_DIR, 'circuits'),
      '-l', path.join(ROOT_DIR, 'circuits', 'lib'),
      '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits'),
    ],
    { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const constraints = /non-linear constraints:\s*(\d+)/.exec(out);
  console.log(`OK: compiled, ${constraints ? constraints[1] : '?'} non-linear constraints`);
}

async function accepts(input) {
  await snarkjs.wtns.calculate(input, WASM, WTNS);
}

async function rejects(input, label) {
  let threw = false;
  try {
    await snarkjs.wtns.calculate(input, WASM, WTNS);
  } catch {
    threw = true;
  }
  if (!threw) {
    console.error(`FAIL: ${label} was accepted by the circuit`);
    process.exit(1);
  }
}

// 라이브러리와 독립적으로 경로/root를 계산하는 헬퍼. 빈 슬롯을 low 리프로
// 위장하는 공격을 재현하려면 "리프가 없는 위치"의 경로도 만들 수 있어야 한다.
function makeHelpers(poseidon, depth) {
  const F = poseidon.F;
  const H2 = (a, b) => F.toObject(poseidon([a, b]));
  const H3 = (a, b, c) => F.toObject(poseidon([a, b, c]));
  const zeros = [0n];
  for (let k = 1; k <= depth; k++) zeros.push(H2(zeros[k - 1], zeros[k - 1]));

  function node(leaves, level, idx) {
    if (idx * 2 ** level >= leaves.length) return zeros[level];
    if (level === 0) {
      const l = leaves[idx];
      return H3(l.value, BigInt(l.nextIndex), l.nextValue);
    }
    return H2(node(leaves, level - 1, idx * 2), node(leaves, level - 1, idx * 2 + 1));
  }

  function pathFor(leaves, leafIdx) {
    const pathElements = [];
    const pathIndices = [];
    let idx = leafIdx;
    for (let k = 0; k < depth; k++) {
      const isRight = idx % 2 === 1;
      pathElements.push(node(leaves, k, isRight ? idx - 1 : idx + 1).toString());
      pathIndices.push(isRight ? '1' : '0');
      idx = Math.floor(idx / 2);
    }
    return { pathElements, pathIndices };
  }

  return { H3, zeros, root: (leaves) => node(leaves, depth, 0), pathFor };
}

async function main() {
  compileIfNeeded();
  const poseidon = await buildPoseidon();
  const helpers = makeHelpers(poseidon, DEPTH);

  // =====================================================================
  // 긍정 케이스 — 라이브러리 witness가 그대로 통과해야 한다.
  // =====================================================================

  // 1) 빈 트리 (anchor만 있는 상태)
  {
    const tree = await createIMTv2(DEPTH);
    const w = await tree.getNonMembershipWitness(999n);
    await accepts({ ...w, target: '999' });
    console.log('OK: empty-tree witness verifies (anchor leaf as the low bound)');
  }

  // 2) 정렬 순서와 물리 순서가 어긋난 트리. low 리프가 물리적으로 마지막이
  //    아니어도 경로가 맞아야 한다 — v2의 핵심이 여기다.
  {
    const tree = await buildIMTv2(DEPTH, [500n, 100n, 900n, 300n, 700n]);
    for (const t of [50n, 200n, 400n, 600n, 800n, 100000n]) {
      const w = await tree.getNonMembershipWitness(t);
      await accepts({ ...w, target: t.toString() });
    }
    console.log('OK: witnesses verify when the physical layout differs from the sorted order');

    // 라이브러리가 낸 경로가 독립 계산과 일치하는지도 확인한다
    const leaves = tree.getLeaves();
    assert.equal(tree.getRoot().toString(), helpers.root(leaves).toString());
    const w = await tree.getNonMembershipWitness(400n);
    const lowIdx = leaves.findIndex((l) => l.value === 300n);
    const ref = helpers.pathFor(leaves, lowIdx);
    assert.deepEqual(w.pathElements, ref.pathElements);
    assert.deepEqual(w.pathIndices, ref.pathIndices);
    console.log('OK: library-produced Merkle path matches an independent computation');
  }

  // 3) 실제 리프 값(도메인 태그 + 252비트 마스킹)으로 만든 트리
  {
    const tree = await createIMTv2(DEPTH);
    tree.getRoot(); // 증분 경로를 강제한다
    const revoked = [];
    for (let i = 0; i < 40; i++) {
      const v = await leafValue(TAG_SESSION, BigInt(1000 + i));
      revoked.push(v);
      await tree.insert(v);
    }
    const alive = await leafValue(TAG_SESSION, 424242n);
    const w = await tree.getNonMembershipWitness(alive);
    await accepts({ ...w, target: alive.toString() });
    console.log('OK: incrementally-built tree of 40 masked leaf values verifies');

    // 원시(마스킹되지 않은) target도 회로가 내부에서 마스킹해 처리한다
    const raw = alive + (1n << 252n);
    const wRaw = await tree.getNonMembershipWitness(raw);
    await accepts({ ...wRaw, target: raw.toString() });
    console.log('OK: an unmasked target (>= 2^252) round-trips through the circuit');

    // =====================================================================
    // 부정 케이스
    // =====================================================================

    // 4) 폐기된 값: 라이브러리는 witness를 거부하고, 손으로 predecessor 리프를
    //    골라 제시해도 회로가 거부해야 한다.
    const victim = revoked[17];
    await assert.rejects(() => tree.getNonMembershipWitness(victim), /is a member/);
    const leaves = tree.getLeaves();
    const predIdx = leaves.findIndex((l) => l.nextValue === victim);
    assert.notEqual(predIdx, -1, 'the revoked value must have a predecessor on the list');
    const pred = leaves[predIdx];
    const predPath = helpers.pathFor(leaves, predIdx);
    await rejects({
      target: victim.toString(),
      lowValue: pred.value.toString(),
      lowNextIndex: pred.nextIndex.toString(),
      lowNextValue: pred.nextValue.toString(),
      ...predPath,
      root: tree.getRoot().toString(),
    }, 'a revoked value presented with its true predecessor leaf');
    console.log('OK: a revoked value is rejected (target == lowNextValue fails the strict upper bound)');

    // 5) 구간을 넓히려고 lowNextValue를 조작하면 리프 해시가 달라져 경로가 깨진다
    await rejects({
      target: victim.toString(),
      lowValue: pred.value.toString(),
      lowNextIndex: pred.nextIndex.toString(),
      lowNextValue: (victim + 1n).toString(), // 구간을 넓혀 victim을 삼키려는 시도
      ...predPath,
      root: tree.getRoot().toString(),
    }, 'a tampered lowNextValue');
    console.log('OK: tampering with lowNextValue breaks the Merkle path');

    // 6) lowNextIndex만 조작해도 리프 해시가 달라져 거부된다.
    //    (값 필드는 전부 정직하고 부수 필드 하나만 틀린 경우 — 회로가 이 필드를
    //     리프 해시에 넣기 때문에 조용히 통과하지 않는다)
    const honest = await tree.getNonMembershipWitness(alive);
    await rejects(
      { ...honest, lowNextIndex: (Number(honest.lowNextIndex) + 1).toString(), target: alive.toString() },
      'a tampered lowNextIndex',
    );
    console.log('OK: tampering with lowNextIndex alone is rejected (it is bound into the leaf hash)');

    // 7) 경로 원소 조작
    const badPath = [...honest.pathElements];
    badPath[3] = (BigInt(badPath[3]) + 1n).toString();
    await rejects({ ...honest, pathElements: badPath, target: alive.toString() }, 'a tampered path element');
    console.log('OK: tampering with a path element is rejected');

    // 8) 빈 슬롯을 anchor 모양의 리프로 위장하는 공격.
    //    빈 슬롯의 리프 해시를 (0,0,0)의 Poseidon으로 뒀다면, 그 슬롯을 low
    //    리프로 제시해 lowValue=0 / lowNextValue=0(sentinel)로 **모든** 값의
    //    비멤버십을 통과시킬 수 있다(설계 문서 3.2절). lib/imt_v2.js는 빈 리프를
    //    리터럴 0으로 두므로 이 공격이 root 검증에서 걸려야 한다.
    const emptySlot = leaves.length; // 아직 안 쓴 첫 물리 슬롯
    const emptyPath = helpers.pathFor(leaves, emptySlot);
    await rejects({
      target: victim.toString(),
      lowValue: '0',
      lowNextIndex: '0',
      lowNextValue: '0',
      ...emptyPath,
      root: tree.getRoot().toString(),
    }, 'an unused slot disguised as an anchor-shaped (0,0,0) leaf');
    console.log('OK: an unused slot cannot be presented as a (0,0,0) leaf (empty leaves hash to literal 0)');
    assert.notEqual(helpers.H3(0n, 0n, 0n).toString(), '0', 'Poseidon(0,0,0) must differ from the empty-leaf hash 0');
  }

  // =====================================================================
  // 9) 왜 remove()가 없는가 — 언링크의 비건전성을 회로 수준에서 재현한다.
  //    이건 "실패해야 할 것이 실패한다"가 아니라 "언링크를 허용하면 거짓
  //    증명이 통과한다"를 보이는 데모다(설계 문서 3.2절, 검증 계획 8.4).
  // =====================================================================
  {
    // 정상 트리: 10, 30 삽입
    //   [ (0,1,10), (10,2,30), (30,0,0) ]
    // 여기서 30을 "언링크"한다 — 리프 2는 트리에 남지만 리스트에서 빠진다:
    //   [ (0,1,10), (10,0,0), (30,0,0)  <- 낡은 리프 ]
    // 그 뒤 40을 삽입하면 predecessor는 10이므로:
    //   [ (0,1,10), (10,3,40), (30,0,0), (40,0,0) ]
    // 이제 낡은 리프 2 = (30, 0, 0)을 low로 제시하면 30 < 40 이고
    // lowNextValue == 0(sentinel)이라 상한 검사가 생략되어, **폐기된 40에 대한
    // 거짓 비멤버십 증명**이 통과한다.
    const unlinked = [
      { value: 0n, nextIndex: 1, nextValue: 10n },
      { value: 10n, nextIndex: 3, nextValue: 40n },
      { value: 30n, nextIndex: 0, nextValue: 0n }, // 언링크된 낡은 리프
      { value: 40n, nextIndex: 0, nextValue: 0n },
    ];
    const root = helpers.root(unlinked).toString();
    const stalePath = helpers.pathFor(unlinked, 2);
    await accepts({
      target: '40',
      lowValue: '30',
      lowNextIndex: '0',
      lowNextValue: '0',
      ...stalePath,
      root,
    });
    console.log('OK: DEMONSTRATED — an unlinked stale leaf proves false non-membership of a revoked value');
    console.log('    (this is exactly why lib/imt_v2.js has no remove(); recovery goes through rebaseline())');
  }

  console.log('PASS: proper IMT (v2) witnesses verify against the Poseidon(3) circuit; tampered ones do not.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
