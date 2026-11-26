// pi_trace 회로(스펙 2026-11-26 ppid-account-trace §4.2)의 witness·증명 — 양성·음성·공개 입력 순서·제약 수. (circuit 그룹)
//   node tests/test_pi_trace_witness.mjs
// 컴파일은 build/mode3/witness_test/ 에만 한다(배포용 산출물은 건드리지 않는다). 배포용 zkey·vkey(build/mode3/pi_trace_*)가 있으면 증명도 만들어 검증한다 — 없으면 그 사례는 건너뛴다고 적는다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';
import { dealAuditorKey, traceWitness, TRACE_PUB_INDEX, partialDecryptTrace, combineTrace } from '../lib/mode3_trace_record.js';
import { randomScalar, auidOf } from '../lib/mode3_credential.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'mode3', 'witness_test');
const NAME = 'pi_trace';
function compile() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const out = execFileSync('circom', [path.join(ROOT_DIR, 'circuits', `${NAME}.circom`), '--r1cs', '--wasm', '--sym', '-o', OUT_DIR,
    '-l', path.join(ROOT_DIR, 'circuits'), '-l', path.join(ROOT_DIR, 'circuits', 'lib'), '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits')], { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  return { constraints: Number(/non-linear constraints:\s*(\d+)/.exec(out)?.[1] ?? 0), pub: Number(/public inputs:\s*(\d+)/.exec(out)?.[1] ?? -1), priv: Number(/private inputs:\s*(\d+)/.exec(out)?.[1] ?? -1) };
}
let calc = null;
async function witness(input) {
  if (!calc) {
    const jsDir = path.join(OUT_DIR, `${NAME}_js`), cjs = path.join(jsDir, 'witness_calculator.cjs');
    if (!fs.existsSync(cjs)) fs.copyFileSync(path.join(jsDir, 'witness_calculator.js'), cjs);
    calc = await (await import(cjs)).default(fs.readFileSync(path.join(jsDir, `${NAME}.wasm`)));
  }
  return calc.calculateWitness(input, true);
}
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

const info = compile();
const key = await dealAuditorKey(), s_u = randomScalar(), arid = 777n, chainid = 31337n;
const w = await traceWitness({ s_u, arid, chainid, pk_aud: key.pk });
const bump = (v) => (BigInt(v) + 1n).toString();

await t('컴파일: 공개 입력 8개·비공개 2개, 제약 수가 수천 개 안이다', () => {
  assert.equal(info.pub, 8); assert.equal(info.priv, 2); assert.ok(info.constraints > 2000 && info.constraints < 8000, `${info.constraints}`);
  console.log(`     비선형 제약 ${info.constraints.toLocaleString()}개`);
});
await t('양성: 정상 입력의 witness 가 계산되고, 공개 입력이 정해진 순서로 나온다', async () => {
  const wt = await witness(w.input);
  assert.deepEqual(Array.from(wt.slice(1, 1 + TRACE_PUB_INDEX.COUNT)).map(String), w.publicSignals);
});
for (const [name, field] of [['PPID', 'PPID'], ['arid', 'arid'], ['chainid', 'chainid'], ['pk_aud_x', 'pk_aud_x'], ['c1_x', 'c1_x'], ['c1_y', 'c1_y'], ['c2(다른 auid)', 'c2'], ['s_u(다른 사람의 salt)', 's_u'], ['rho', 'rho']]) {
  await t(`음성: ${name} 를 바꾸면 witness 가 만들어지지 않는다`, async () => { await assert.rejects(() => witness({ ...w.input, [field]: bump(w.input[field]) })); });
}
await t('음성: 남의 auid 를 암호화한 암호문은 이 PPID 의 기록이 될 수 없다', async () => {
  const other = await traceWitness({ s_u: randomScalar(), arid, chainid, pk_aud: key.pk, rho: BigInt(w.input.rho) });
  await assert.rejects(() => witness({ ...w.input, c2: other.input.c2 }));
});
await t('음성: rho = 0 은 거절한다(c1 이 항등원이면 암호문이 평문을 가리지 못한다)', async () => {
  // rho = 0 이면 c1 = 항등원(0, 1), K = 항등원 — 그 값들로 식을 맞춰도 rho ≠ 0 제약에서 걸려야 한다
  const { buildPoseidon } = await import('circomlibjs'); const ps = await buildPoseidon();
  const c2zero = ((await auidOf({ s_u })) + ps.F.toObject(ps([0n, 1n]))) % ps.F.p;
  await assert.rejects(() => witness({ ...w.input, rho: '0', c1_x: '0', c1_y: '1', c2: c2zero.toString() }));
});
const zkey = path.join(ROOT_DIR, 'build', 'mode3', `${NAME}_final.zkey`), vkeyPath = path.join(ROOT_DIR, 'build', 'mode3', `${NAME}_vkey.json`), wasm = path.join(ROOT_DIR, 'build', 'mode3', `${NAME}_js`, `${NAME}.wasm`);
if (fs.existsSync(zkey) && fs.existsSync(vkeyPath) && fs.existsSync(wasm)) {
  await t('배포용 키로 증명이 만들어지고 검증된다 — 공개 입력을 하나 바꾸면 검증이 실패하고, 그 암호문은 두 조각으로 그 auid 로 열린다', async () => {
    const vkey = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
    const t0 = Date.now(), { proof, publicSignals } = await snarkjs.groth16.fullProve(w.input, wasm, zkey);
    console.log(`     증명 ${Date.now() - t0} ms`);
    assert.deepEqual(publicSignals, w.publicSignals); assert.equal(vkey.nPublic, 8);
    assert.equal(await snarkjs.groth16.verify(vkey, publicSignals, proof), true);
    for (const i of [TRACE_PUB_INDEX.PPID, TRACE_PUB_INDEX.C2, TRACE_PUB_INDEX.PK_AUD_Y]) { const p = [...publicSignals]; p[i] = bump(p[i]); assert.equal(await snarkjs.groth16.verify(vkey, p, proof), false, `공개 입력 ${i}`); }
    const pa = await partialDecryptTrace(key.shares[1], w.c1), pb = await partialDecryptTrace(key.shares[2], w.c1);
    assert.equal(await combineTrace(w.c2, pa, pb), await auidOf({ s_u }));
  });
} else console.log('skip 배포용 키(build/mode3/pi_trace_*)가 없어 증명 사례는 돌리지 않았다 — bash scripts/build_mode3_circuit.sh pi_trace');
console.log(failed ? `\n${failed} FAILED` : '\nall ok');
process.exit(failed ? 1 : 0);
