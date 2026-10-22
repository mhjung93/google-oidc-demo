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
  } catch (err) {
    // witness calculator 가 stderr 로 내는 `ERROR: 4 …` 줄은 이 경로에서 어쩔 수 없다. 다만 메시지가
    // 회로의 assert 실패(`=== `제약)가 아닌 다른 이유(예: 타입 오류)로 던진 거라면 그대로 다시 던져
    // "뭐든 던지면 통과"가 되지 않게 한다.
    if (!/Assert Failed/.test(err.message)) throw err;
    threw = true;
    console.log(`   (예상된 실패: ${label})`);
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

  await rejects({ ...(await w(101n, 199n)), hi: '200' }, 'hi 를 next(200) 까지 늘리면 실패');
  console.log('OK: hi 를 200으로 늘리면 거부된다 (lowNextValue(200) <= hi)');

  // [100,150] → 실패(100 이 구간 안: low 는 anchor 0 이고 next=100 ≤ hi).
  // 여기서는 같은 증인에서 lo 만 100으로 낮춰 lowValue(100) < lo(100) 조건을 깨는 형태로 재현한다.
  await rejects({ ...(await w(101n, 199n)), lo: '100' }, 'lo 를 low.value(100) 까지 내리면 실패');
  console.log('OK: lo 를 100으로 내리면 거부된다 (lowValue(100) < lo 실패)');

  // [201, 2^252-1] → 통과(low=200, next=0 끝).
  await accepts(await w(201n, (1n << 252n) - 1n));
  console.log('OK: [201, 2^252-1] 구간에 리프가 없다 (low=200, next=0 끝)');

  // [150,200] → 라이브러리가 이미 멤버십 충돌로 막는다(next=200 <= hi).
  await assert.rejects(() => tree.getRangeNonMembershipWitness(150n, 200n), /is a member/);
  console.log('OK: [150, 200] 구간은 라이브러리가 "is a member" 로 막는다');

  // ---- 경계 케이스 ----

  // 1) lo = hi (counter=0 에 해당): 트리에 없는 한 점 구간 → 통과.
  await accepts(await w(150n, 150n));
  console.log('OK: lo == hi(150) — counter=0 인 한 점 구간도 통과한다');

  // 2) hi = 2^252 → Num2Bits(252) 범위 검사에서 거부된다(hi 는 [0, 2^252) 안이어야 한다).
  await rejects({ ...(await w(201n, (1n << 252n) - 1n)), hi: (1n << 252n).toString() }, 'hi 를 2^252 로 올리면 범위 검사에서 실패');
  console.log('OK: hi = 2^252 는 Num2Bits(252) 범위 검사로 거부된다');

  // 3) sentinel 위조: 마지막이 아닌 리프(low=100, lowNextValue=200)를 low 로 쓰는 정상 증인에서
  //    lowNextValue 만 '0'(sentinel)으로 바꾼다 — 리프 해시가 바뀌어 Merkle 경로가 root 와 어긋난다.
  //    "lowNextValue==0 은 진짜 꼬리에서만 통과한다"의 직접 증거.
  await rejects({ ...(await w(101n, 199n)), lowNextValue: '0' }, 'lowNextValue 를 0 으로 위조하면 실패');
  console.log('OK: 마지막이 아닌 리프의 lowNextValue 를 0 으로 위조하면 거부된다 (리프 해시 불일치)');

  // 4) anchor(값 0)를 low 로 쓰는 구간: 가장 작은 실제 리프(100)보다 작은 [1, 99] → 통과.
  await accepts(await w(1n, 99n));
  console.log('OK: [1, 99] 구간은 anchor(0)를 low 로 써서 통과한다');

  console.log('PASS: IMTRangeNonMembershipV2 구간 비멤버십 가젯이 witness 를 올바르게 검증한다.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
