// pi_cred 회로의 witness 계산. 양성 2건(정상 witness + JS/회로 리프 일치) + 음성 4건.
//   node tests/test_pi_cred_witness.mjs
//
// zkey는 만들지 않는다 (Task 4에서 별도 승인 후). 여기서는 회로가 올바른 입력을
// 받아들이고 잘못된 입력을 거부하는지만 본다 — 그게 건전성의 핵심이다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { credLeaf, createRevocationTree, MODE3_TREE_DEPTH } from '../lib/mode3_revocation.js';
import { buildValidInput } from './helpers/mode3_fixture.mjs';
import { ppid } from '../lib/mode3_credential.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
// build/mode3 바로 아래가 아니라 하위 디렉터리에 컴파일한다 — 지갑이 증명에 쓰는 build/mode3/pi_cred_js/pi_cred.wasm
// 은 pi_cred_final.zkey 와 짝이라, 회로를 고친 뒤 npm test 가 wasm 만 갈아치우면 데모 로그인이 전부 bad_proof 가 된다.
const OUT_DIR = path.join(ROOT_DIR, 'build', 'mode3', 'witness_test');
const NAME = 'pi_cred';

function compile() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const out = execFileSync(
    'circom',
    [
      path.join(ROOT_DIR, 'circuits', `${NAME}.circom`),
      '--r1cs', '--wasm', '--sym', '-o', OUT_DIR,
      '-l', path.join(ROOT_DIR, 'circuits'),
      '-l', path.join(ROOT_DIR, 'circuits', 'lib'),
      '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits'),
    ],
    { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const m = /non-linear constraints:\s*(\d+)/.exec(out);
  console.log(`OK: 컴파일됨, 비선형 제약 ${m ? Number(m[1]).toLocaleString() : '?'}개`);
  return m ? Number(m[1]) : 0;
}

let calc = null;
async function witness(input) {
  if (!calc) {
    // circom이 만드는 witness_calculator.js는 CommonJS인데, 저장소 package.json이
    // "type": "module"이라 .js로 그냥 import()하면 ESM으로 오인돼 깨진다. .cjs로
    // 복사해 우회한다 (tests/test_mode3_commit_scheme.mjs와 같은 패턴). 이미
    // 있으면(다른 실행에서 만든 것) 재사용한다.
    const jsDir = path.join(OUT_DIR, `${NAME}_js`);
    const cjsPath = path.join(jsDir, 'witness_calculator.cjs');
    if (!fs.existsSync(cjsPath)) {
      fs.copyFileSync(path.join(jsDir, 'witness_calculator.js'), cjsPath);
    }
    const wc = await import(cjsPath).then((m) => m.default);
    calc = await wc(fs.readFileSync(path.join(jsDir, `${NAME}.wasm`)));
  }
  return calc.calculateWitness(input, true);
}

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const constraints = compile();
const { input: valid, C: validC } = await buildValidInput();

await t('양성: 정상 credential의 witness가 계산된다', async () => {
  const w = await witness(valid);
  assert.ok(w.length > 0);
  assert.equal(valid.pathElements.length, MODE3_TREE_DEPTH);
});

await t('PPID 는 chainid 를 덮는다 — 같은 uid·s_u·arid 라도 체인이 다르면 가명이 다르고, 옛 가명은 거부된다', async () => {
  // 체인 간 unlinkability(발표 자료 6장의 H(ID, salt, chain, rid)). chainid 는 서명 메시지에도 들어가므로
  // 서명을 다시 만들지 않고는 chainid 만 바꿔 통과시킬 수 없다 — 여기서는 JS 유도값이 체인마다 다름과,
  // 다른 체인용 PPID 를 그대로 내면 회로가 거부함을 본다.
  const a = await ppid({ uid: BigInt(valid.uid), arid: BigInt(valid.arid), s_u: BigInt(valid.s_u), chainid: BigInt(valid.chainid) });
  const b = await ppid({ uid: BigInt(valid.uid), arid: BigInt(valid.arid), s_u: BigInt(valid.s_u), chainid: BigInt(valid.chainid) + 1n });
  assert.equal(a.toString(), valid.PPID, 'JS ppid 가 픽스처의 PPID 와 같아야 한다');
  assert.notEqual(a, b);
  await assert.rejects(() => witness({ ...valid, PPID: b.toString() }), /Assert Failed/);
});

await t('음성: PPID가 다르면 거부된다', async () => {
  await assert.rejects(
    () => witness({ ...valid, PPID: (BigInt(valid.PPID) + 1n).toString() }),
    /Assert Failed/,
  );
});

await t('음성: exptime 을 바꾸면 거부된다 (서명이 exptime 을 덮는다)', async () => {
  await assert.rejects(() => witness({ ...valid, exptime: (BigInt(valid.exptime) + 1n).toString() }), /Assert Failed/);
});

await t('음성: chainid 를 바꾸면 거부된다 (서명이 chainid 를 덮는다)', async () => {
  await assert.rejects(() => witness({ ...valid, chainid: '1' }), /Assert Failed/);
});

await t('음성: nonce 를 바꾸면 거부된다 (서명이 nonce 를 덮는다)', async () => {
  await assert.rejects(() => witness({ ...valid, nonce: (BigInt(valid.nonce) + 1n).toString() }), /Assert Failed/);
});

await t('음성: attr 하나를 바꾸면 거부된다 (C 가 달라져 서명이 안 맞는다)', async () => {
  const attrs = [...valid.attrs]; attrs[0] = '20';
  await assert.rejects(() => witness({ ...valid, attrs }), /Assert Failed/);
});

await t('음성: pk_i를 바꾸면 거부된다 (C 바인딩이 깨진다)', async () => {
  await assert.rejects(
    () => witness({ ...valid, pk_i: (BigInt(valid.pk_i) + 1n).toString() }),
    /Assert Failed/,
  );
});

await t('음성: 폐기 전에 만든 witness는 폐기 후 root에서 거부된다 (낡은 증명)', async () => {
  // 회로 수준의 폐기 검증이다. 라이브러리가 폐기된 리프의 witness 생성을 거부하는
  // 것은 Task 1 테스트가 이미 확인했다 — 여기서 볼 것은 **회로가** 낡은 증명을
  // 거부하는가다.
  //
  // 폐기된 사용자가 증명을 제시할 수 있는 유일한 길은 폐기 **전**에 만든 witness를
  // 그대로 내는 것이다. 회로는 revRoot에 묶여 있으므로, 옛 witness + 새 root 조합은
  // 경로 검증에서 걸려야 한다. 컨트랙트가 최신 root만 받으므로(N=1) 이것이 폐기가
  // 실제로 작동하는 지점이다.
  const tree = await createRevocationTree();
  await tree.insert(await credLeaf(999n));    // valid 을 만들 때와 같은 상태
  await tree.insert(await credLeaf(validC));  // 내 credential 폐기 → root 변경
  await assert.rejects(
    () => witness({ ...valid, revRoot: tree.getRoot().toString() }),
    /Assert Failed/,
    '폐기 후 root에 대해 옛 witness가 통과하면 폐기가 무의미하다',
  );
});

await t('JS credLeaf 와 회로의 리프 계산이 일치한다', async () => {
  // 회로가 폐기 트리에 넣는 리프(main.leafHasher.out)와 lib/mode3_revocation.js의
  // credLeaf()가 같은 값을 내야 한다 — 어긋나면 CIA가 트리에 넣는 리프와 회로가
  // 검증하는 리프가 달라져 폐기가 조용히 무력화된다.
  const symPath = path.join(OUT_DIR, `${NAME}.sym`);
  const sym = fs.readFileSync(symPath, 'utf8');
  const line = sym.split('\n').find((l) => l.split(',')[3] === 'main.leafHasher.out');
  assert.ok(line, 'pi_cred.sym에서 main.leafHasher.out 시그널을 찾지 못했다');
  const witnessIdx = Number(line.split(',')[1]);
  const w = await witness(valid);
  const circuitLeaf = BigInt(w[witnessIdx]) & ((1n << 252n) - 1n);
  assert.equal(circuitLeaf, await credLeaf(validC));
});

console.log('');
console.log(`## pi_cred 비선형 제약: ${constraints.toLocaleString()}`);
console.log(`   (참고 — Mode 2 pi_pk_i_v3: 13,905)`);

process.exit(failed === 0 ? 0 : 1);
