// 배포용 pi_cred 산출물(build/mode3)이 지금의 회로 소스(circuits/pi_cred.circom)에서 나온 것인가. (circuit 그룹)
//   node tests/test_mode3_artifacts.mjs
//
// 2026-09-25 리뷰 E-3: 회로를 고쳐도 `bash scripts/build_mode3_circuit.sh` 를 안 돌리면 zkey·vkey·wasm 은 옛
// 회로의 것으로 남는다. 그런데 테스트는 대부분 **배포용 산출물**로 증명을 만들어 검증하므로 전부 초록색이다 —
// 회로 소스와 산출물이 갈라진 사실을 아무도 못 본다. 여기서 둘을 잇는다.
//
// tests/test_pi_cred_witness.mjs 가 build/mode3/witness_test/ 에 회로를 새로 컴파일한다(배포용 산출물은
// 건드리지 않는다 — 그 파일 17-18행 참고). 그 결과물을 재사용하고, 없거나 회로 소스보다 오래됐으면
// 여기서 같은 방식으로 컴파일한다(단독 실행도 되게).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const BUILD_DIR = path.join(ROOT_DIR, 'build', 'mode3');
const OUT_DIR = path.join(BUILD_DIR, 'witness_test');
const CIRCUITS_DIR = path.join(ROOT_DIR, 'circuits');
const NAME = 'pi_cred';
const REBUILD = '회로를 고치고 `bash scripts/build_mode3_circuit.sh` 를 안 돌렸다 — build/mode3 의 zkey·vkey·wasm 이 옛 회로의 것이다';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

/** circuits/ 아래 .circom 중 가장 최근 수정 시각. 이보다 오래된 컴파일 결과는 낡은 것으로 본다. */
function newestCircuitMtime(dir = CIRCUITS_DIR) {
  let newest = 0;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) newest = Math.max(newest, newestCircuitMtime(p));
    else if (e.name.endsWith('.circom')) newest = Math.max(newest, fs.statSync(p).mtimeMs);
  }
  return newest;
}

/** tests/test_pi_cred_witness.mjs 와 같은 circom 호출. 산출물은 witness_test/ 에만 쓴다. */
function compileFresh() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  execFileSync(
    'circom',
    [
      path.join(CIRCUITS_DIR, `${NAME}.circom`),
      '--r1cs', '--wasm', '--sym', '-o', OUT_DIR,
      '-l', CIRCUITS_DIR,
      '-l', path.join(CIRCUITS_DIR, 'lib'),
      '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits'),
    ],
    { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
}

/**
 * .r1cs 헤더(섹션 타입 1)를 직접 읽는다. 형식: "r1cs" + version(u32) + nSections(u32),
 * 이어서 [type(u32), size(u64), data] 반복. 헤더 데이터는 n8(u32) + prime(n8) +
 * nWires(u32) + nPubOut(u32) + nPubIn(u32) + nPrvIn(u32) + nLabels(u64) + nConstraints(u32).
 * snarkjs 의 nPublic = nPubOut + nPubIn 이다.
 */
function r1csHeader(file) {
  const b = fs.readFileSync(file);
  assert.equal(b.toString('ascii', 0, 4), 'r1cs', `${file} 가 r1cs 가 아니다`);
  const nSections = b.readUInt32LE(8);
  let off = 12;
  for (let i = 0; i < nSections; i++) {
    const type = b.readUInt32LE(off);
    const size = Number(b.readBigUInt64LE(off + 4));
    const data = off + 12;
    if (type === 1) {
      const n8 = b.readUInt32LE(data);
      const p = data + 4 + n8;
      const nPubOut = b.readUInt32LE(p + 4), nPubIn = b.readUInt32LE(p + 8);
      return { nWires: b.readUInt32LE(p), nPubOut, nPubIn, nPrvIn: b.readUInt32LE(p + 12), nPublic: nPubOut + nPubIn, nConstraints: b.readUInt32LE(p + 24) };
    }
    off = data + size;
  }
  throw new Error(`${file} 에 r1cs 헤더 섹션이 없다`);
}

/** .sym 의 witness 인덱스 → 시그널 이름. 공개 입력은 1..nPublic 이다(0 은 상수 1). */
function publicSignalNames(symFile, nPublic) {
  const byIndex = new Map();
  for (const line of fs.readFileSync(symFile, 'utf8').split('\n')) {
    const f = line.split(',');
    if (f.length < 4) continue;
    const idx = Number(f[1]);
    if (!Number.isInteger(idx) || idx < 1 || idx > nPublic) continue;
    if (!/^main\.[^.]+$/.test(f[3])) continue;   // main 의 직속 시그널만(하위 컴포넌트 제외)
    if (!byIndex.has(idx)) byIndex.set(idx, f[3].slice('main.'.length));
  }
  return Array.from({ length: nPublic }, (_, i) => byIndex.get(i + 1) ?? null);
}

// 회로가 정한 공개 입력 순서. contracts/Mode3Wallet.sol(pub[3]·pub[5]·pub[11..13]·pub[14..24]),
// lib/mode3_rp.js(구조분해), lib/mode3_onchain.js(statementDigestFields), cia.js(개봉)가 이 자리를 번호로 읽는다.
const CANONICAL_PUBLIC_INPUTS = [
  'PPID', 'arid', 'pk_i', 'max_height', 'chainid', 'allowAgent', 'revRoot',
  'pk_CIA_x', 'pk_CIA_y', 'pk_trace_x', 'pk_trace_y',
  'tag_c1_x', 'tag_c1_y', 'tag_c2',
  'disc_mask', 'disc_lo[0]', 'disc_lo[1]', 'disc_lo[2]', 'disc_lo[3]',
  'disc_hi[0]', 'disc_hi[1]', 'disc_hi[2]', 'disc_hi[3]',
  'set_sel', 'set_root',
];

const VKEY_FILE = path.join(BUILD_DIR, `${NAME}_vkey.json`);
const DEPLOYED_R1CS = path.join(BUILD_DIR, `${NAME}.r1cs`);
const FRESH_R1CS = path.join(OUT_DIR, `${NAME}.r1cs`);
const FRESH_SYM = path.join(OUT_DIR, `${NAME}.sym`);

assert.ok(fs.existsSync(VKEY_FILE), `배포용 vkey 가 없다: ${VKEY_FILE} — bash scripts/build_mode3_circuit.sh`);

if (!fs.existsSync(FRESH_R1CS) || !fs.existsSync(FRESH_SYM) || fs.statSync(FRESH_R1CS).mtimeMs < newestCircuitMtime()) {
  console.log('   (회로를 새로 컴파일한다 — witness_test/ 가 없거나 소스보다 오래됐다)');
  compileFresh();
}

const fresh = r1csHeader(FRESH_R1CS);
const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, 'utf8'));

await t('E-3: 회로 소스의 공개 입력 수가 배포용 vkey 의 nPublic 과 같다', () => {
  assert.equal(
    fresh.nPublic, vkey.nPublic,
    `회로는 공개 입력 ${fresh.nPublic}개인데 배포용 vkey 는 ${vkey.nPublic}개다 — ${REBUILD}`,
  );
  // vkey 의 IC 는 공개 입력마다 하나 + 상수항 하나다. 둘이 어긋나면 vkey 자체가 깨진 것이다.
  assert.equal(vkey.IC.length, vkey.nPublic + 1, `vkey.IC 길이(${vkey.IC.length}) 가 nPublic + 1 이 아니다`);
});

await t('E-3: 배포용 .r1cs 도 같은 회로에서 나왔다(공개·비공개 입력 수)', () => {
  assert.ok(fs.existsSync(DEPLOYED_R1CS), `배포용 r1cs 가 없다: ${DEPLOYED_R1CS} — ${REBUILD}`);
  const dep = r1csHeader(DEPLOYED_R1CS);
  // 제약·wire 수는 컴파일러 판에 따라 달라질 수 있어 비교하지 않는다. 입력 수는 소스가 정한다.
  assert.equal(dep.nPublic, fresh.nPublic, `배포용 r1cs 의 공개 입력 ${dep.nPublic}개 ≠ 소스 ${fresh.nPublic}개 — ${REBUILD}`);
  assert.equal(dep.nPrvIn, fresh.nPrvIn, `배포용 r1cs 의 비공개 입력 ${dep.nPrvIn}개 ≠ 소스 ${fresh.nPrvIn}개 — ${REBUILD}`);
});

await t('E-3: 공개 입력의 이름·순서가 컨트랙트·검증기가 번호로 읽는 그 순서다', () => {
  // 개수만 보면 두 입력을 맞바꾸는 변경을 못 잡는다 — 그때 pub[3](만료)·pub[5](에이전트 허용)를 읽는
  // 컨트랙트와 서비스가 조용히 다른 값을 보게 된다.
  const names = publicSignalNames(FRESH_SYM, fresh.nPublic);
  assert.deepEqual(names, CANONICAL_PUBLIC_INPUTS, `공개 입력 순서가 바뀌었다 — 바꾸려면 contracts/Mode3Wallet.sol·lib/mode3_rp.js·lib/mode3_onchain.js·cia.js 의 인덱스를 함께 고쳐야 한다`);
});

await t('E-3: 배포용 증명자 산출물(zkey·wasm)이 제자리에 있다', () => {
  for (const f of [path.join(BUILD_DIR, `${NAME}_final.zkey`), path.join(BUILD_DIR, `${NAME}_js`, `${NAME}.wasm`)]) {
    assert.ok(fs.existsSync(f), `${f} 가 없다 — bash scripts/build_mode3_circuit.sh`);
  }
});

console.log('');
console.log(`## pi_cred 공개 입력 ${fresh.nPublic}개 / 비공개 입력 ${fresh.nPrvIn}개 / 비선형 제약 ${fresh.nConstraints.toLocaleString()}개(소스)`);

process.exit(failed === 0 ? 0 : 1);
