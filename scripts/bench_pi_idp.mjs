// pi_idp 회로의 증명·검증 시간 실측(스펙 2026-10-12 §8). zkey 는 scripts/build_mode3_circuit.sh 가 만든 것을 쓴다(없으면 안내 후 종료).
//   node scripts/bench_pi_idp.mjs
import fs from 'node:fs';
import * as snarkjs from 'snarkjs';
import { IDP_WASM_PATH, IDP_ZKEY_PATH, IDP_VKEY_PATH } from '../lib/mode3_idp_proof.js';
import { buildIdpInput } from '../tests/helpers/mode3_idp_fixture.mjs';

for (const f of [IDP_WASM_PATH, IDP_ZKEY_PATH, IDP_VKEY_PATH]) if (!fs.existsSync(f)) { console.error(`${f} 가 없다 — bash scripts/build_mode3_circuit.sh pot21_final.ptau`); process.exit(2); }
const { input } = await buildIdpInput();
const vkey = JSON.parse(fs.readFileSync(IDP_VKEY_PATH, 'utf8'));
const N = 10, proveMs = [], verifyMs = [];
let publicSignals;
for (let i = 0; i < N; i++) {
  const t0 = performance.now();
  const out = await snarkjs.groth16.fullProve(input, IDP_WASM_PATH, IDP_ZKEY_PATH);
  proveMs.push(performance.now() - t0);
  const t1 = performance.now();
  const ok = await snarkjs.groth16.verify(vkey, out.publicSignals, out.proof);
  verifyMs.push(performance.now() - t1);
  if (!ok) throw new Error('검증 실패');
  publicSignals = out.publicSignals;
}
const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
console.log('\n## pi_idp 실측\n\n| 항목 | 값 |\n|---|--:|');
console.log(`| 증명 시간 (중앙값, ${N}회) | ${med(proveMs).toFixed(1)} ms |`);
console.log(`| 검증 시간 (중앙값, ${N}회) | ${med(verifyMs).toFixed(1)} ms |`);
console.log(`| zkey 크기 | ${(fs.statSync(IDP_ZKEY_PATH).size / 1e6).toFixed(1)} MB |`);
console.log(`| 공개 입력 수 | ${publicSignals.length} |`);
