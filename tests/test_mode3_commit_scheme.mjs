// Mode 3 커밋 회로 둘(CommitUser·CommitSession)이 JS 와 일치하는지와 제약 수.
//   node tests/test_mode3_commit_scheme.mjs
//
// zkey는 만들지 않는다. circom --r1cs --wasm 으로 제약 수를 읽고 witness 계산까지만 한다.
// 산출물은 build/mode3/commit/ 에 만든다 (build/ 전체가 .gitignore 대상).
// V4 단일 커밋 판과 Poseidon 판의 제약 수 비교는 2026-09-21 에 그 회로들과 함께 지웠다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildBabyjub } from 'circomlibjs';
import { userCommit, sessionCommit, SCALAR_MAX, PEDERSEN_GENERATORS } from '../lib/mode3_credential.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'mode3', 'commit');

// V5(2026-09-21) 커밋 둘.
const SRC = {
  user: `pragma circom 2.0.0;
include "lib/mode3_commit.circom";
component main = CommitUser();`,
  session: `pragma circom 2.0.0;
include "lib/mode3_commit.circom";
component main = CommitSession();`,
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

const USER_INPUT = { uid: '11111111111111111111', s_u: '33333333333333333333', blind_u: '44444444444444444444', attrs: ['19', '410', '0', '0'] };   // 예: 나이·국가코드, 빈 슬롯은 0
const SESSION_INPUT = { arid: '22222222222222222222', pk_i: '1234567890123456789012345678901234567890', blind_s: '55555555555555555555' };   // pk_i 는 160비트 주소 범위

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const counts = {};

await t('CommitUser 회로의 (Cx, Cy) 가 JS userCommit 과 일치한다', async () => {
  counts.user = compile('user', SRC.user);
  const w = await witness('user', USER_INPUT);
  // main 출력은 witness[1], witness[2] (Cx, Cy). witness[0] 은 상수 1.
  const { Cx, Cy } = await userCommit({ uid: BigInt(USER_INPUT.uid), s_u: BigInt(USER_INPUT.s_u), blind_u: BigInt(USER_INPUT.blind_u), attrs: USER_INPUT.attrs.map(BigInt) });
  assert.equal(BigInt(w[1]), Cx, 'Cx 불일치 — 생성원 순서나 스칼라 인코딩이 어긋났다');
  assert.equal(BigInt(w[2]), Cy, 'Cy 불일치');
});

await t('CommitSession 회로의 (Cx, Cy) 가 JS sessionCommit 과 일치한다', async () => {
  counts.session = compile('session', SRC.session);
  const w = await witness('session', SESSION_INPUT);
  const { Cx, Cy } = await sessionCommit({ arid: BigInt(SESSION_INPUT.arid), pk_i: BigInt(SESSION_INPUT.pk_i), blind_s: BigInt(SESSION_INPUT.blind_s) });
  assert.equal(BigInt(w[1]), Cx); assert.equal(BigInt(w[2]), Cy);
});

await t('생성원 9개가 곡선 위·소수 부분군 안에 있다', async () => {
  const bj = await buildBabyjub();
  assert.equal(Object.keys(PEDERSEN_GENERATORS).length, 9, 'uid, arid, s_u, pk_i, attr0..3, blind');
  for (const [name, g] of Object.entries(PEDERSEN_GENERATORS)) {
    const P = [bj.F.e(g[0]), bj.F.e(g[1])];
    assert.ok(bj.inCurve(P), `${name} 가 곡선 위에 없다`);
    assert.ok(bj.inSubgroup(P), `${name} 가 소수 부분군 밖이다 — binding 논증이 깨진다`);
  }
});

await t('스칼라가 2^250 이상이면 JS 가 거부한다 (회로의 Num2Bits(250) 과 같은 상한)', async () => {
  await assert.rejects(() => userCommit({ uid: 1n, s_u: SCALAR_MAX, blind_u: 4n }), /2\^250/);
  await assert.rejects(() => sessionCommit({ arid: 2n, pk_i: 5n, blind_s: SCALAR_MAX }), /2\^250/);
});

await t('회로도 2^250 이상 스칼라를 거부한다', async () => {
  await assert.rejects(() => witness('user', { ...USER_INPUT, s_u: SCALAR_MAX.toString() }), /Assert Failed/);
  await assert.rejects(() => witness('session', { ...SESSION_INPUT, pk_i: SCALAR_MAX.toString() }), /Assert Failed/);
});

await t('attr 하나만 바꿔도 C_u 가 바뀐다 (속성이 커밋에 실린다); blind 하나만 바꿔도 바뀐다 (hiding 의 전제)', async () => {
  const a = await witness('user', USER_INPUT);
  const b = await witness('user', { ...USER_INPUT, attrs: ['20', '410', '0', '0'] });
  const c = await witness('user', { ...USER_INPUT, blind_u: '66666666666666666666' });
  assert.notEqual(a[1].toString(), b[1].toString());
  assert.notEqual(a[1].toString(), c[1].toString());
});

await t('attrs 를 생략한 JS userCommit 은 전부 0 과 같다', async () => {
  const withZero = await userCommit({ uid: 1n, s_u: 3n, blind_u: 4n, attrs: [0n, 0n, 0n, 0n] });
  const omitted = await userCommit({ uid: 1n, s_u: 3n, blind_u: 4n });
  assert.equal(withZero.Cf, omitted.Cf);
});

console.log('');
console.log('## 커밋 회로 제약 수');
console.log('');
console.log('| 회로 | 비선형 제약 |');
console.log('|---|--:|');
for (const [k, v] of Object.entries(counts)) console.log(`| ${k} | ${v.toLocaleString()} |`);

process.exit(failed === 0 ? 0 : 1);
