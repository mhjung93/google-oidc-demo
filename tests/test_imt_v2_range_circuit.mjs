// lib/imt_v2.js의 getRangeNonMembershipWitness()가 만든 witness를 IMTRangeNonMembershipV2 회로가
// 실제로 받아들이는지 확인한다(2026-10-22 세션 폐기 상한, 설계 §3).
//   node tests/test_imt_v2_range_circuit.mjs
//
// 하네스는 tests/test_imt_v2_nonmembership_circuit.mjs:20-70을 그대로 복사해 가젯 이름만 바꿨다.
// zkey는 필요 없다. circom으로 --r1cs --wasm만 만들고 witness 계산까지만 한다.
//
// 산출물은 build/imt_v2/ 에 만든다(기존 imt_v2_only 산출물과 공존한다).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';
import { createIMTv2 } from '../lib/imt_v2.js';

const DEPTH = 20;
const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'imt_v2');
const CIRCUIT_NAME = 'imt_v2_range_only';
const WRAPPER = path.join(OUT_DIR, `${CIRCUIT_NAME}.circom`);
const WASM = path.join(OUT_DIR, `${CIRCUIT_NAME}_js`, `${CIRCUIT_NAME}.wasm`);
const WTNS = path.join(OUT_DIR, 'scratch_range.wtns');

// 측정/테스트 전용 main 래퍼. circuits/lib/imt_range_nonmembership_v2.circom 을 그대로
// 인스턴스화할 뿐이라 저장소에 두지 않고 여기서 생성한다.
const WRAPPER_SRC = `pragma circom 2.0.0;
include "lib/imt_range_nonmembership_v2.circom";
component main {public [root, lo, hi]} = IMTRangeNonMembershipV2(${DEPTH});
`;

function compileIfNeeded() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const stale = !fs.existsSync(WASM)
    || !fs.existsSync(WRAPPER)
    || fs.readFileSync(WRAPPER, 'utf8') !== WRAPPER_SRC
    || fs.statSync(WASM).mtimeMs
       < fs.statSync(path.join(ROOT_DIR, 'circuits', 'lib', 'imt_range_nonmembership_v2.circom')).mtimeMs;
  if (!stale) {
    console.log(`OK: reusing ${path.relative(ROOT_DIR, WASM)}`);
    return;
  }
  fs.writeFileSync(WRAPPER, WRAPPER_SRC);
  console.log('… compiling circuits/lib/imt_range_nonmembership_v2.circom (--r1cs --wasm, no zkey)');
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

async function main() {
  compileIfNeeded();

  // 트리: 값 100·200 삽입. 구간 [101,199] → 통과(low=100, next=200).
  const tree = await createIMTv2(DEPTH);
  await tree.insert(100n);
  await tree.insert(200n);
  const w = (lo, hi) => tree.getRangeNonMembershipWitness(lo, hi).then((x) => ({ ...x, lo: String(lo), hi: String(hi) }));

  await accepts(await w(101n, 199n));
  console.log('OK: [101, 199] 구간에 리프가 없다 (low=100, next=200)');

  // [100,150] → 실패(100 이 구간 안: low 는 anchor 0 이고 next=100 ≤ hi).
  // 여기서는 같은 증인에서 lo 만 100으로 낮춰 lowValue(100) < lo(100) 조건을 깨는 형태로 재현한다.
  await rejects({ ...(await w(101n, 199n)), hi: '200' }, 'hi 를 next(200) 까지 늘리면 실패');
  console.log('OK: hi 를 200으로 늘리면 거부된다 (lowNextValue(200) <= hi)');

  await rejects({ ...(await w(101n, 199n)), lo: '100' }, 'lo 를 low.value(100) 까지 내리면 실패');
  console.log('OK: lo 를 100으로 내리면 거부된다 (lowValue(100) < lo 실패)');

  // [201, 2^252-1] → 통과(low=200, next=0 끝).
  await accepts(await w(201n, (1n << 252n) - 1n));
  console.log('OK: [201, 2^252-1] 구간에 리프가 없다 (low=200, next=0 끝)');

  // [150,200] → 라이브러리가 이미 멤버십 충돌로 막는다(next=200 <= hi).
  await assert.rejects(() => tree.getRangeNonMembershipWitness(150n, 200n), /is a member/);
  console.log('OK: [150, 200] 구간은 라이브러리가 "is a member" 로 막는다');

  console.log('PASS: IMTRangeNonMembershipV2 구간 비멤버십 가젯이 witness 를 올바르게 검증한다.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
