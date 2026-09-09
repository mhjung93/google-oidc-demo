// Mode 3 커밋 스킴 두 판의 바인딩 검증과 제약 수 비교.
//   node tests/test_mode3_commit_scheme.mjs
//
// zkey는 만들지 않는다. circom --r1cs --wasm 으로 제약 수를 읽고 witness 계산까지만 한다.
// 산출물은 build/mode3/commit/ 에 만든다 (build/ 전체가 .gitignore 대상).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildPoseidon } from 'circomlibjs';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'mode3', 'commit');

const VARIANTS = {
  poseidon: `pragma circom 2.0.0;
include "lib/mode3_commit.circom";
component main = CommitPoseidon();
`,
  pedersen: `pragma circom 2.0.0;
include "lib/mode3_commit.circom";
component main = CommitPedersen();
`,
};

// 제약 수를 세려면 컴파일해야 한다. circom은 컴파일 요약에 비선형 제약 수를 찍는다.
function compile(name, src) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const wrapper = path.join(OUT_DIR, `${name}.circom`);
  fs.writeFileSync(wrapper, src);
  const out = execFileSync(
    'circom',
    [
      wrapper, '--r1cs', '--wasm', '-o', OUT_DIR,
      '-l', path.join(ROOT_DIR, 'circuits'),
      '-l', path.join(ROOT_DIR, 'circuits', 'lib'),
      '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits'),
    ],
    { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const m = /non-linear constraints:\s*(\d+)/.exec(out);
  assert.ok(m, `제약 수를 읽지 못했다:\n${out}`);
  return Number(m[1]);
}

async function witness(name, input) {
  // circom이 만드는 witness_calculator.js는 CommonJS인데, 저장소 package.json이
  // "type": "module"이라 .js로 그냥 import()하면 ESM으로 오인돼 깨진다. 기존
  // scripts/build_mode2_circuits.sh와 같은 방식으로 .cjs로 복사해 우회한다.
  const jsDir = path.join(OUT_DIR, `${name}_js`);
  const cjsPath = path.join(jsDir, 'witness_calculator.cjs');
  if (!fs.existsSync(cjsPath)) {
    fs.copyFileSync(path.join(jsDir, 'witness_calculator.js'), cjsPath);
  }
  const wc = await import(cjsPath).then((m) => m.default);
  const wasm = fs.readFileSync(path.join(jsDir, `${name}.wasm`));
  const calc = await wc(wasm);
  return calc.calculateWitness(input, true);
}

const INPUT = {
  uid: '11111111111111111111',
  arid: '22222222222222222222',
  s_u: '33333333333333333333',
  blind: '44444444444444444444',
  pk_i: '1234567890123456789012345678901234567890', // 160비트 주소 범위
};

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const counts = {};

for (const [name, src] of Object.entries(VARIANTS)) {
  await t(`${name}: 컴파일되고 witness가 계산된다`, async () => {
    counts[name] = compile(name, src);
    const w = await witness(name, INPUT);
    assert.ok(w.length > 0);
  });
}

await t('Poseidon 판은 같은 입력에 같은 C를 준다', async () => {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const expected = F.toObject(poseidon([
    BigInt(INPUT.uid), BigInt(INPUT.arid), BigInt(INPUT.s_u),
    BigInt(INPUT.blind), BigInt(INPUT.pk_i),
  ]));
  const w = await witness('poseidon', INPUT);
  // main 컴포넌트의 출력은 witness[1] 부터 놓인다 (witness[0]은 상수 1).
  assert.equal(w[1].toString(), expected.toString(),
    '회로가 계산한 C가 circomlibjs Poseidon과 달라서는 안 된다');
});

await t('blind 하나만 바꿔도 C가 바뀐다 (hiding의 전제)', async () => {
  const a = await witness('poseidon', INPUT);
  const b = await witness('poseidon', { ...INPUT, blind: '55555555555555555555' });
  assert.notEqual(a[1].toString(), b[1].toString());
});

console.log('');
console.log('## 커밋 스킴 제약 수');
console.log('');
console.log('| 판 | 비선형 제약 |');
console.log('|---|--:|');
for (const [k, v] of Object.entries(counts)) {
  console.log(`| ${k} | ${v.toLocaleString()} |`);
}
console.log('');
console.log(`차이: ${Math.abs(counts.pedersen - counts.poseidon).toLocaleString()} ` +
            `(Pedersen이 Poseidon의 ${(counts.pedersen / counts.poseidon).toFixed(1)}배)`);

process.exit(failed === 0 ? 0 : 1);
