// pi_cred 회로의 zkey 생성과 증명·검증 시간 실측.
//   node scripts/bench_pi_cred.mjs <ptau 파일 경로>
//
// 산출물은 전부 build/mode3/ 아래에 만든다. Mode 2 산출물(build/mode2/)을
// 건드리지 않으며 npm run zk:key 를 쓰지 않는다.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import * as snarkjs from 'snarkjs';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'mode3');
const PTAU = process.argv[2];
if (!PTAU || !fs.existsSync(PTAU)) {
  console.error('사용법: node scripts/bench_pi_cred.mjs <ptau 파일 경로>');
  process.exit(2);
}

const R1CS = path.join(OUT_DIR, 'pi_cred.r1cs');
const ZKEY0 = path.join(OUT_DIR, 'pi_cred_0000.zkey');
const ZKEY = path.join(OUT_DIR, 'pi_cred_final.zkey');
const VKEY = path.join(OUT_DIR, 'pi_cred_vkey.json');
const WASM = path.join(OUT_DIR, 'pi_cred_js', 'pi_cred.wasm');

function sh(args) {
  execFileSync('npx', args, { cwd: ROOT_DIR, stdio: 'inherit' });
}

if (!fs.existsSync(ZKEY)) {
  console.log('… zkey 생성 (수 분 걸릴 수 있음)');
  sh(['snarkjs', 'groth16', 'setup', R1CS, PTAU, ZKEY0]);
  sh(['snarkjs', 'zkey', 'contribute', ZKEY0, ZKEY, '--name=mode3', '-v', '-e=mode3-bench']);
  sh(['snarkjs', 'zkey', 'export', 'verificationkey', ZKEY, VKEY]);
}

// 입력은 테스트가 쓰는 것과 같은 방식으로 만든다.
const { buildValidInput } = await import('../tests/helpers/mode3_fixture.mjs');
const { input } = await buildValidInput();

const N = 10;
const proveMs = [];
const verifyMs = [];
let proof, publicSignals;

for (let i = 0; i < N; i++) {
  const t0 = performance.now();
  ({ proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY));
  proveMs.push(performance.now() - t0);

  const vkey = JSON.parse(fs.readFileSync(VKEY, 'utf8'));
  const t1 = performance.now();
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  verifyMs.push(performance.now() - t1);
  if (!ok) throw new Error('검증 실패');
}

const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
console.log('');
console.log('## pi_cred 실측');
console.log('');
console.log(`| 항목 | 값 |`);
console.log(`|---|--:|`);
console.log(`| 증명 시간 (중앙값, ${N}회) | ${med(proveMs).toFixed(1)} ms |`);
console.log(`| 검증 시간 (중앙값, ${N}회) | ${med(verifyMs).toFixed(1)} ms |`);
console.log(`| zkey 크기 | ${(fs.statSync(ZKEY).size / 1e6).toFixed(1)} MB |`);
console.log(`| 공개 입력 수 | ${publicSignals.length} |`);
process.exit(0);
