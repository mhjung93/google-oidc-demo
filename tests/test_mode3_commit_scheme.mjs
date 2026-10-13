// Mode 3 커밋 회로 둘(CommitUser·CommitSessionV11)이 JS 와 일치하는지와 제약 수. (circuit 그룹)
//   node tests/test_mode3_commit_scheme.mjs
// zkey 는 만들지 않는다. 산출물은 build/mode3/commit/ 에 만든다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildBabyjub } from 'circomlibjs';
import { userCommit, sessionCommit, SCALAR_MAX, PK_I_MAX, PEDERSEN_GENERATORS } from '../lib/mode3_credential.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'mode3', 'commit');
const SRC = {
  user: `pragma circom 2.0.0;\ninclude "lib/mode3_commit.circom";\ncomponent main = CommitUser();`,
  session: `pragma circom 2.0.0;\ninclude "lib/mode3_commit.circom";\ncomponent main = CommitSessionV11();`,
};
function compile(name, src) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const wrapper = path.join(OUT_DIR, `${name}.circom`);
  fs.writeFileSync(wrapper, src);
  const out = execFileSync('circom', [wrapper, '--r1cs', '--wasm', '-o', OUT_DIR, '-l', path.join(ROOT_DIR, 'circuits'), '-l', path.join(ROOT_DIR, 'circuits', 'lib'), '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits')], { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const m = /non-linear constraints:\s*(\d+)/.exec(out);
  assert.ok(m, `제약 수를 읽지 못했다:\n${out}`);
  return Number(m[1]);
}
async function witness(name, input) {
  const jsDir = path.join(OUT_DIR, `${name}_js`);
  const cjsPath = path.join(jsDir, 'witness_calculator.cjs');
  if (!fs.existsSync(cjsPath)) fs.copyFileSync(path.join(jsDir, 'witness_calculator.js'), cjsPath);
  const wc = await import(cjsPath).then((m) => m.default);
  const calc = await wc(fs.readFileSync(path.join(jsDir, `${name}.wasm`)));
  return calc.calculateWitness(input, true);
}
const USER_INPUT = { uid: '11111111111111111111', s_u: '33333333333333333333', blind_u: '44444444444444444444', attrs: ['19', '410', '0', '0', '0', '0'] };
const SESSION_INPUT = { pk_i: '1234567890123456789012345678901234567890', max_height: '1789000000', r_s: '13131313131313131313', r_rp: '12121212121212121212' };
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }
const counts = {};

await t('CommitUser 회로의 (Cx, Cy) 가 JS userCommit 과 일치한다', async () => {
  counts.user = compile('user', SRC.user);
  const w = await witness('user', USER_INPUT);
  const { Cx, Cy } = await userCommit({ uid: BigInt(USER_INPUT.uid), s_u: BigInt(USER_INPUT.s_u), blind_u: BigInt(USER_INPUT.blind_u), attrs: USER_INPUT.attrs.map(BigInt) });
  assert.equal(BigInt(w[1]), Cx, 'Cx 불일치 — 생성원 순서나 스칼라 인코딩이 어긋났다'); assert.equal(BigInt(w[2]), Cy, 'Cy 불일치');
});
await t('CommitSessionV11 회로의 (Cx, Cy) 가 JS sessionCommit({pk_i, max_height, r_s, r_rp}) 과 일치한다', async () => {
  counts.session = compile('session', SRC.session);
  const w = await witness('session', SESSION_INPUT);
  const { Cx, Cy } = await sessionCommit({ pk_i: BigInt(SESSION_INPUT.pk_i), max_height: BigInt(SESSION_INPUT.max_height), r_s: BigInt(SESSION_INPUT.r_s), r_rp: BigInt(SESSION_INPUT.r_rp) });
  assert.equal(BigInt(w[1]), Cx); assert.equal(BigInt(w[2]), Cy);
});
await t('생성원 13개가 곡선 위·소수 부분군 안에 있다', async () => {
  const bj = await buildBabyjub();
  assert.equal(Object.keys(PEDERSEN_GENERATORS).length, 13, 'uid, arid, s_u, pk_i, attr0..5, blind, exp, rs');
  for (const [name, g] of Object.entries(PEDERSEN_GENERATORS)) { const P = [bj.F.e(g[0]), bj.F.e(g[1])]; assert.ok(bj.inCurve(P), `${name} 곡선`); assert.ok(bj.inSubgroup(P), `${name} 부분군 — binding 논증이 깨진다`); }
});
await t('JS 가 상한을 거부한다 (s_u·r_s 2^250, pk_i 2^160)', async () => {
  await assert.rejects(() => userCommit({ uid: 1n, s_u: SCALAR_MAX, blind_u: 4n }), /2\^250/);
  await assert.rejects(() => sessionCommit({ pk_i: 5n, max_height: 1n, r_s: SCALAR_MAX, r_rp: 2n }), /2\^250/);
  await assert.rejects(() => sessionCommit({ pk_i: PK_I_MAX, max_height: 1n, r_s: 1n, r_rp: 2n }), /2\^160/);
});
await t('회로도 상한을 거부한다 (s_u 2^250, pk_i 2^160, max_height 2^64)', async () => {
  await assert.rejects(() => witness('user', { ...USER_INPUT, s_u: SCALAR_MAX.toString() }), /Assert Failed/);
  await assert.rejects(() => witness('session', { ...SESSION_INPUT, pk_i: PK_I_MAX.toString() }), /Assert Failed/);
  await assert.rejects(() => witness('session', { ...SESSION_INPUT, max_height: (1n << 64n).toString() }), /Assert Failed/);
});
await t('attr·blind 하나만 바꿔도 C_u 가 바뀐다; max_height·r_s·r_rp 하나만 바꿔도 C_s 가 바뀐다', async () => {
  const a = await witness('user', USER_INPUT);
  assert.notEqual(a[1].toString(), (await witness('user', { ...USER_INPUT, attrs: ['20', '410', '0', '0', '0', '0'] }))[1].toString());
  assert.notEqual(a[1].toString(), (await witness('user', { ...USER_INPUT, blind_u: '66666666666666666666' }))[1].toString());
  const s = await witness('session', SESSION_INPUT);
  for (const [k, v] of [['max_height', '1789000001'], ['r_s', '1'], ['r_rp', '1']]) assert.notEqual(s[1].toString(), (await witness('session', { ...SESSION_INPUT, [k]: v }))[1].toString(), k);
});
await t('attrs 를 생략한 JS userCommit 은 전부 0 과 같다', async () => {
  assert.equal((await userCommit({ uid: 1n, s_u: 3n, blind_u: 4n, attrs: [0n, 0n, 0n, 0n, 0n, 0n] })).Cf, (await userCommit({ uid: 1n, s_u: 3n, blind_u: 4n })).Cf);
});
console.log('\n## 커밋 회로 제약 수\n\n| 회로 | 비선형 제약 |\n|---|--:|');
for (const [k, v] of Object.entries(counts)) console.log(`| ${k} | ${v.toLocaleString()} |`);
process.exit(failed === 0 ? 0 : 1);
