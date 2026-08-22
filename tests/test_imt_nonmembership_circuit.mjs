import { buildPoseidon } from 'circomlibjs';
import fs from 'fs';

const DEPTH = 20;

// 테스트용 최소 IMT: 리프 2개짜리 트리를 손으로 만든다.
async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const H = (a, b) => F.toObject(poseidon([a, b]));

  // 리프: (10, 20) — 값 10이고 다음 값이 20. 따라서 10 < x < 20 인 x는 트리에 없다.
  const lowValue = 10n;
  const lowNextValue = 20n;
  const leaf = H(lowValue, lowNextValue);

  // 깊이 20 경로를 전부 0으로 채워 root를 계산한다.
  const pathElements = [];
  const pathIndices = [];
  let cur = leaf;
  for (let i = 0; i < DEPTH; i++) {
    pathElements.push(0n);
    pathIndices.push(0);
    cur = H(cur, 0n);
  }
  const root = cur;

  const wc = await import('/tmp/imt_measure/test_imt_only_js/witness_calculator.js');
  const wasmBuffer = await fs.promises.readFile('/tmp/imt_measure/test_imt_only_js/test_imt_only.wasm');
  const calc = await wc.default(wasmBuffer);

  const base = {
    lowValue: lowValue.toString(),
    lowNextValue: lowNextValue.toString(),
    pathElements: pathElements.map(String),
    pathIndices: pathIndices.map(String),
    root: root.toString(),
  };

  // 1) 15는 10과 20 사이 -> 비멤버십 증명 성공
  await calc.calculateWitness({ ...base, target: '15' }, true);
  console.log('OK: 15 is provably absent');

  // 2) 10은 리프 값 자체 -> lowValue < target 위반으로 실패해야 함
  let rejected = false;
  try {
    await calc.calculateWitness({ ...base, target: '10' }, true);
  } catch { rejected = true; }
  if (!rejected) { console.error('FAIL: target == lowValue was accepted'); process.exit(1); }
  console.log('OK: target == lowValue rejected');

  // 3) 25는 구간 밖 -> target < lowNextValue 위반으로 실패해야 함
  rejected = false;
  try {
    await calc.calculateWitness({ ...base, target: '25' }, true);
  } catch { rejected = true; }
  if (!rejected) { console.error('FAIL: out-of-range target was accepted'); process.exit(1); }
  console.log('OK: out-of-range target rejected');

  // 4) lowNextValue == 0 (가장 큰 리프) 이면 상한 검사를 건너뛴다
  const sentinelLeaf = H(100n, 0n);
  let sc = sentinelLeaf;
  for (let i = 0; i < DEPTH; i++) sc = H(sc, 0n);
  await calc.calculateWitness({
    target: '99999',
    lowValue: '100',
    lowNextValue: '0',
    pathElements: pathElements.map(String),
    pathIndices: pathIndices.map(String),
    root: sc.toString(),
  }, true);
  console.log('OK: sentinel leaf allows arbitrarily large target');

  console.log('PASS: IMT non-membership circuit enforces low < target < next.');
}

main();
