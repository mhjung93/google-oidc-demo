// pi_cred 회로의 witness 계산. 양성 1건 + 음성 4건.
//   node tests/test_pi_cred_witness.mjs
//
// zkey는 만들지 않는다 (Task 4에서 별도 승인 후). 여기서는 회로가 올바른 입력을
// 받아들이고 잘못된 입력을 거부하는지만 본다 — 그게 건전성의 핵심이다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildPoseidon, buildEddsa } from 'circomlibjs';
import { credLeaf, createRevocationTree, MODE3_TREE_DEPTH } from '../lib/mode3_revocation.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'mode3');
const NAME = 'pi_cred';
const DOMAIN_MODE3_CRED = 1426111059989523219780n;

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

// --- 정상 입력 하나를 만든다 -------------------------------------------------
async function buildValidInput() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const eddsa = await buildEddsa();

  const uid   = 11111111111111111111n;
  const arid  = 22222222222222222222n;
  const s_u   = 33333333333333333333n;
  const blind = 44444444444444444444n;
  const pk_i  = 0x1234567890123456789012345678901234567890n; // 160비트
  const max_height = 1000n;

  const C = F.toObject(poseidon([uid, arid, s_u, blind, pk_i]));
  const PPID = F.toObject(poseidon([uid, arid, s_u]));
  const msg = F.toObject(poseidon([DOMAIN_MODE3_CRED, C, max_height]));

  // CIA 서명키. 테스트 고정값이며 실제 키가 아니다.
  const prv = Buffer.from('0001020304050607080900010203040506070809000102030405060708090001', 'hex');
  const pub = eddsa.prv2pub(prv);
  const sig = eddsa.signPoseidon(prv, F.e(msg));

  // 폐기 트리에 남의 폐기를 하나 넣어 둔다 — 내 비멤버십은 여전히 성립해야 한다.
  const tree = await createRevocationTree();
  await tree.insert(await credLeaf(999n));
  const w = await tree.getNonMembershipWitness(await credLeaf(C));

  return {
    uid: uid.toString(),
    s_u: s_u.toString(),
    blind: blind.toString(),
    S: sig.S.toString(),
    R8x: F.toObject(sig.R8[0]).toString(),
    R8y: F.toObject(sig.R8[1]).toString(),
    lowValue: w.lowValue.toString(),
    lowNextIndex: w.lowNextIndex.toString(),
    lowNextValue: w.lowNextValue.toString(),
    pathElements: w.pathElements.map(String),
    pathIndices: w.pathIndices.map(String),
    PPID: PPID.toString(),
    arid: arid.toString(),
    pk_i: pk_i.toString(),
    max_height: max_height.toString(),
    revRoot: tree.getRoot().toString(),
    pk_CIA_x: F.toObject(pub[0]).toString(),
    pk_CIA_y: F.toObject(pub[1]).toString(),
  };
}

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const constraints = compile();
const valid = await buildValidInput();

await t('양성: 정상 credential의 witness가 계산된다', async () => {
  const w = await witness(valid);
  assert.ok(w.length > 0);
});

await t('음성: PPID가 다르면 거부된다', async () => {
  await assert.rejects(
    () => witness({ ...valid, PPID: (BigInt(valid.PPID) + 1n).toString() }),
    /Assert Failed|Error/,
  );
});

await t('음성: 서명이 다른 max_height에 대한 것이면 거부된다', async () => {
  await assert.rejects(
    () => witness({ ...valid, max_height: (BigInt(valid.max_height) + 1n).toString() }),
    /Assert Failed|Error/,
  );
});

await t('음성: pk_i를 바꾸면 거부된다 (C 바인딩이 깨진다)', async () => {
  await assert.rejects(
    () => witness({ ...valid, pk_i: (BigInt(valid.pk_i) + 1n).toString() }),
    /Assert Failed|Error/,
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
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const C = F.toObject(poseidon([
    11111111111111111111n, 22222222222222222222n, 33333333333333333333n,
    44444444444444444444n, 0x1234567890123456789012345678901234567890n,
  ]));
  const tree = await createRevocationTree();
  await tree.insert(await credLeaf(999n));   // valid 을 만들 때와 같은 상태
  await tree.insert(await credLeaf(C));       // 내 credential 폐기 → root 변경
  await assert.rejects(
    () => witness({ ...valid, revRoot: tree.getRoot().toString() }),
    /Assert Failed|Error/,
    '폐기 후 root에 대해 옛 witness가 통과하면 폐기가 무의미하다',
  );
});

console.log('');
console.log(`## pi_cred 비선형 제약: ${constraints.toLocaleString()}`);
console.log(`   (참고 — Mode 2 pi_pk_i_v3: 13,905)`);

process.exit(failed === 0 ? 0 : 1);
