// pi_idp 회로(V11 §4)의 witness 계산 — 양성·음성·공개 입력 순서·제약 수. (circuit 그룹)
//   node tests/test_pi_idp_witness.mjs
// zkey 는 만들지 않는다(Task 4 의 build_mode3_circuit.sh). build/mode3/witness_test/ 에만 컴파일한다 — 배포용 산출물은 건드리지 않는다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildIdpInput } from './helpers/mode3_idp_fixture.mjs';
import { PK_I_MAX, MAX_HEIGHT_MAX } from '../lib/mode3_credential.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'mode3', 'witness_test');
const NAME = 'pi_idp';

function compile() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const out = execFileSync('circom', [
    path.join(ROOT_DIR, 'circuits', `${NAME}.circom`), '--r1cs', '--wasm', '--sym', '-o', OUT_DIR,
    '-l', path.join(ROOT_DIR, 'circuits'), '-l', path.join(ROOT_DIR, 'circuits', 'lib'), '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits'),
  ], { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const m = /non-linear constraints:\s*(\d+)/.exec(out);
  console.log(`OK: 컴파일됨, 비선형 제약 ${m ? Number(m[1]).toLocaleString() : '?'}개`);
  return m ? Number(m[1]) : 0;
}
let calc = null;
async function witness(input) {
  if (!calc) {
    const jsDir = path.join(OUT_DIR, `${NAME}_js`);
    const cjsPath = path.join(jsDir, 'witness_calculator.cjs');
    if (!fs.existsSync(cjsPath)) fs.copyFileSync(path.join(jsDir, 'witness_calculator.js'), cjsPath);   // tests/test_pi_cred_witness.mjs 와 같은 CJS 우회
    const wc = await import(cjsPath).then((m) => m.default);
    calc = await wc(fs.readFileSync(path.join(jsDir, `${NAME}.wasm`)));
  }
  return calc.calculateWitness(input, true);
}
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

const constraints = compile();
const fx = await buildIdpInput();
const valid = fx.input;
const bump = (v) => (BigInt(v) + 1n).toString();

await t('양성: 정상 입력의 witness 가 계산된다', async () => { assert.ok((await witness(valid)).length > 0); });
await t('공개 입력 순서 = [uid, auid, auid_s, C_u_x, C_u_y, C_s_x, C_s_y, max_height] (witness 1..8, .sym)', async () => {
  const sym = fs.readFileSync(path.join(OUT_DIR, `${NAME}.sym`), 'utf8');
  const byIndex = new Map();
  for (const line of sym.split('\n')) { const f = line.split(','); if (f.length < 4) continue; const idx = Number(f[1]); if (idx >= 1 && idx <= 8 && /^main\.[^.]+$/.test(f[3]) && !byIndex.has(idx)) byIndex.set(idx, f[3].slice(5)); }
  assert.deepEqual(Array.from({ length: 8 }, (_, i) => byIndex.get(i + 1)), ['uid', 'auid', 'auid_s', 'C_u_x', 'C_u_y', 'C_s_x', 'C_s_y', 'max_height']);
  const w = await witness(valid);
  assert.equal(BigInt(w[2]).toString(), valid.auid); assert.equal(BigInt(w[8]).toString(), valid.max_height);
});
await t('D15: 속성 값은 자유 — 다른 attrs 로 만든 C_u 도 통과한다(IdP 는 값을 보지 않는다)', async () => {
  const other = await buildIdpInput({ attrs: [1n, 2n, 3n, 4n, 5n, 6n] });
  assert.ok((await witness(other.input)).length > 0);
});
await t('음성: s_u 를 바꾸면 거부 (C_u·auid 둘 다 어긋난다)', async () => { await assert.rejects(() => witness({ ...valid, s_u: bump(valid.s_u) }), /Assert Failed/); });
await t('음성: auid 를 바꾸면 거부 — IdP 가 DB 값을 넣으므로 다른 salt 의 지갑은 통과하지 못한다', async () => { await assert.rejects(() => witness({ ...valid, auid: bump(valid.auid) }), /Assert Failed/); });
await t('음성: auid_s 를 바꾸면 거부; arid 를 바꾸면 auid_s 가 어긋나 거부', async () => {
  await assert.rejects(() => witness({ ...valid, auid_s: bump(valid.auid_s) }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, arid: bump(valid.arid) }), /Assert Failed/);
});
await t('음성: r_rp 를 바꾸면 거부 (auid_s 와 C_s 가 같은 r_rp 에 묶인다)', async () => { await assert.rejects(() => witness({ ...valid, r_rp: bump(valid.r_rp) }), /Assert Failed/); });
await t('음성: pk_i·r_s·max_height 를 바꾸면 C_s 가 어긋나 거부', async () => {
  await assert.rejects(() => witness({ ...valid, pk_i: bump(valid.pk_i) }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, r_s: bump(valid.r_s) }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, max_height: bump(valid.max_height) }), /Assert Failed/);
});
await t('음성: 범위 — attr ≥ 2^64, pk_i ≥ 2^160, max_height ≥ 2^64 는 거부', async () => {
  await assert.rejects(() => witness({ ...valid, attrs: [(1n << 64n).toString(), '410', '2', '0', '0', '0'] }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, pk_i: PK_I_MAX.toString() }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, max_height: MAX_HEIGHT_MAX.toString() }), /Assert Failed/);
});
await t('양성: 같은 r_rp 로 다른 세션키·만료의 C_s 를 만들면(픽스처 재생성) 통과한다', async () => {
  const other = await buildIdpInput({ pk_i: 0x9999n, maxHeight: 42n, r_s: 777n });
  assert.ok((await witness(other.input)).length > 0);
});

console.log('');
console.log(`## pi_idp 비선형 제약: ${constraints.toLocaleString()} (스펙 §4 추정 약 13,000)`);
process.exit(failed === 0 ? 0 : 1);
