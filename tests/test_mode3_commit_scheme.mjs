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
import { buildPoseidon, buildBabyjub } from 'circomlibjs';
import { credCommit, SCALAR_MAX, PEDERSEN_GENERATORS, DOMAIN_MODE3_CRED, DOMAIN_MODE3_CRED_V2 } from '../lib/mode3_credential.js';

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
  attrs: ['19', '410', '0', '0'],                   // 예: 나이·국가코드, 빈 슬롯은 0
};
// CommitPoseidon 은 attrs 입력이 없다 — circom witness calculator 는 정의되지 않은
// 입력 신호가 섞이면 거부한다("Too many values for input signal attrs"). Poseidon 판
// 호출에는 이 값을 쓴다.
const { attrs: _unusedAttrs, ...POSEIDON_INPUT } = INPUT;

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const counts = {};

for (const [name, src] of Object.entries(VARIANTS)) {
  await t(`${name}: 컴파일되고 witness가 계산된다`, async () => {
    counts[name] = compile(name, src);
    const w = await witness(name, name === 'poseidon' ? POSEIDON_INPUT : INPUT);
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
  const w = await witness('poseidon', POSEIDON_INPUT);
  // main 컴포넌트의 출력은 witness[1] 부터 놓인다 (witness[0]은 상수 1).
  assert.equal(w[1].toString(), expected.toString(),
    '회로가 계산한 C가 circomlibjs Poseidon과 달라서는 안 된다');
});

await t('blind 하나만 바꿔도 C가 바뀐다 (hiding의 전제)', async () => {
  const a = await witness('poseidon', POSEIDON_INPUT);
  const b = await witness('poseidon', { ...POSEIDON_INPUT, blind: '55555555555555555555' });
  assert.notEqual(a[1].toString(), b[1].toString());
});

await t('Pedersen 판: 회로의 (Cx, Cy) 가 JS credCommit 과 일치한다', async () => {
  const w = await witness('pedersen', INPUT);
  // main 출력은 witness[1], witness[2] (Cx, Cy)
  const { Cx, Cy } = await credCommit({
    uid: BigInt(INPUT.uid), arid: BigInt(INPUT.arid), s_u: BigInt(INPUT.s_u),
    blind: BigInt(INPUT.blind), pk_i: BigInt(INPUT.pk_i),
    attrs: INPUT.attrs.map(BigInt),
  });
  assert.equal(w[1].toString(), Cx.toString(), 'Cx 불일치 — 생성원 순서나 스칼라 인코딩이 어긋났다');
  assert.equal(w[2].toString(), Cy.toString(), 'Cy 불일치');
});

await t('Pedersen 판: 생성원 9개가 곡선 위·소수 부분군 안에 있다', async () => {
  const bj = await buildBabyjub();
  assert.equal(Object.keys(PEDERSEN_GENERATORS).length, 9, 'uid, arid, s_u, pk_i, attr0..3, blind');
  for (const [name, g] of Object.entries(PEDERSEN_GENERATORS)) {
    const P = [bj.F.e(g[0]), bj.F.e(g[1])];
    assert.ok(bj.inCurve(P), `${name} 가 곡선 위에 없다`);
    assert.ok(bj.inSubgroup(P), `${name} 가 소수 부분군 밖이다 — binding 논증이 깨진다`);
  }
});

await t('Pedersen 판: 스칼라가 2^250 이상이면 JS 가 거부한다 (회로의 Num2Bits(250) 과 같은 상한)', async () => {
  await assert.rejects(
    () => credCommit({ uid: 1n, arid: 2n, s_u: SCALAR_MAX, blind: 4n, pk_i: 5n }),
    /2\^250/,
  );
});

await t('Pedersen 판: 회로도 2^250 이상 스칼라를 거부한다', async () => {
  await assert.rejects(
    () => witness('pedersen', { ...INPUT, s_u: SCALAR_MAX.toString() }),
    /Assert Failed/,
  );
});

await t('Pedersen 판: attr 하나만 바꿔도 C 가 바뀐다 (속성이 커밋에 실린다)', async () => {
  const a = await witness('pedersen', INPUT);
  const b = await witness('pedersen', { ...INPUT, attrs: ['20', '410', '0', '0'] });
  assert.notEqual(a[1].toString(), b[1].toString());
});

await t('Pedersen 판: attrs 를 생략한 JS credCommit 은 전부 0 과 같다', async () => {
  const withZero = await credCommit({ uid: 1n, arid: 2n, s_u: 3n, blind: 4n, pk_i: 5n, attrs: [0n, 0n, 0n, 0n] });
  const omitted = await credCommit({ uid: 1n, arid: 2n, s_u: 3n, blind: 4n, pk_i: 5n });
  assert.equal(withZero.Cf, omitted.Cf);
});

await t('DOMAIN_MODE3_CRED_V2 는 "MODE3CREDV2" 빅엔디언이고 옛 태그와 다르다', () => {
  assert.equal(DOMAIN_MODE3_CRED_V2, BigInt('0x' + Buffer.from('MODE3CREDV2').toString('hex')));
  assert.notEqual(DOMAIN_MODE3_CRED_V2, DOMAIN_MODE3_CRED);
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
