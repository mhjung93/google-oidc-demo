// 배포용 산출물(build/mode3)이 지금의 회로 소스에서 나온 것인가 — pi_cred(V11, 공개 33)·pi_idp(공개 8). (circuit 그룹)
//   node tests/test_mode3_artifacts.mjs
// 2026-09-25 리뷰 E-3: 회로를 고쳐도 `bash scripts/build_mode3_circuit.sh` 를 안 돌리면 zkey·vkey·wasm 은 옛 회로의 것으로 남는데,
// 테스트는 대부분 배포용 산출물로 증명을 만들어 검증하므로 전부 초록색이다. 여기서 둘을 잇는다.
// 컴파일 결과는 tests/test_pi_cred_witness.mjs·test_pi_idp_witness.mjs 가 build/mode3/witness_test/ 에 둔 것을 재사용하고, 없거나 소스보다 오래됐으면 여기서 컴파일한다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { PUB_INDEX } from '../lib/mode3_onchain.js';
import { IDP_PUB_INDEX } from '../lib/mode3_idp_proof.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const BUILD_DIR = path.join(ROOT_DIR, 'build', 'mode3');
const OUT_DIR = path.join(BUILD_DIR, 'witness_test');
const CIRCUITS_DIR = path.join(ROOT_DIR, 'circuits');
const REBUILD = '회로를 고치고 `bash scripts/build_mode3_circuit.sh` 를 안 돌렸다 — build/mode3 의 zkey·vkey·wasm 이 옛 회로의 것이다';

let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

function newestCircuitMtime(dir = CIRCUITS_DIR) {
  let newest = 0;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) newest = Math.max(newest, newestCircuitMtime(p));
    else if (e.name.endsWith('.circom')) newest = Math.max(newest, fs.statSync(p).mtimeMs);
  }
  return newest;
}
function compileFresh(name) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  execFileSync('circom', [path.join(CIRCUITS_DIR, `${name}.circom`), '--r1cs', '--wasm', '--sym', '-o', OUT_DIR, '-l', CIRCUITS_DIR, '-l', path.join(CIRCUITS_DIR, 'lib'), '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits')], { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}
/** .r1cs 헤더(섹션 타입 1): n8·prime·nWires·nPubOut·nPubIn·nPrvIn·nLabels·nConstraints. snarkjs 의 nPublic = nPubOut + nPubIn. */
function r1csHeader(file) {
  const b = fs.readFileSync(file);
  assert.equal(b.toString('ascii', 0, 4), 'r1cs', `${file} 가 r1cs 가 아니다`);
  const nSections = b.readUInt32LE(8);
  let off = 12;
  for (let i = 0; i < nSections; i++) {
    const type = b.readUInt32LE(off), size = Number(b.readBigUInt64LE(off + 4)), data = off + 12;
    if (type === 1) {
      const n8 = b.readUInt32LE(data), p = data + 4 + n8;
      const nPubOut = b.readUInt32LE(p + 4), nPubIn = b.readUInt32LE(p + 8);
      return { nWires: b.readUInt32LE(p), nPubOut, nPubIn, nPrvIn: b.readUInt32LE(p + 12), nPublic: nPubOut + nPubIn, nConstraints: b.readUInt32LE(p + 24) };
    }
    off = data + size;
  }
  throw new Error(`${file} 에 r1cs 헤더 섹션이 없다`);
}
/** .sym 의 witness 인덱스 → 시그널 이름. 공개 입력은 1..nPublic(0 은 상수 1). main 의 직속 시그널만. */
function publicSignalNames(symFile, nPublic) {
  const byIndex = new Map();
  for (const line of fs.readFileSync(symFile, 'utf8').split('\n')) {
    const f = line.split(',');
    if (f.length < 4) continue;
    const idx = Number(f[1]);
    if (!Number.isInteger(idx) || idx < 1 || idx > nPublic || !/^main\.[^.]+$/.test(f[3])) continue;
    if (!byIndex.has(idx)) byIndex.set(idx, f[3].slice('main.'.length));
  }
  return Array.from({ length: nPublic }, (_, i) => byIndex.get(i + 1) ?? null);
}

// 회로가 정한 공개 입력 순서. contracts/Mode3Wallet.sol(pub[3]·pub[5]·pub[12..14]·pub[15..29]), lib/mode3_rp.js(구조분해·[30..32]),
// lib/mode3_onchain.js(PUB_INDEX), cia.js(개봉)가 이 자리를 번호로 읽는다.
const CIRCUITS = {
  pi_cred: {
    publicInputs: [
      'PPID', 'arid', 'pk_i', 'max_height', 'chainid', 'allowAgent', 'revRoot', 'regRoot',
      'pk_CIA_x', 'pk_CIA_y', 'pk_trace_x', 'pk_trace_y', 'tag_c1_x', 'tag_c1_y', 'tag_c2',
      'disc_mask', 'disc_lo[0]', 'disc_lo[1]', 'disc_lo[2]', 'disc_lo[3]', 'disc_lo[4]', 'disc_lo[5]',
      'disc_hi[0]', 'disc_hi[1]', 'disc_hi[2]', 'disc_hi[3]', 'disc_hi[4]', 'disc_hi[5]',
      'set_sel', 'set_root', 'auid_s', 'arid_s', 'r_s', 'counter',
    ],
    indexNote: 'contracts/Mode3Wallet.sol·lib/mode3_rp.js·lib/mode3_onchain.js·cia.js',
  },
  // lib/mode3_idp_proof.js IDP_PUB_INDEX·cia.js 의 공개 입력 조립 순서
  pi_idp: { publicInputs: ['uid', 'auid', 'auid_s', 'C_u_x', 'C_u_y', 'C_s_x', 'C_s_y', 'max_height'], indexNote: 'lib/mode3_idp_proof.js·cia.js' },
};

for (const [name, spec] of Object.entries(CIRCUITS)) {
  const VKEY_FILE = path.join(BUILD_DIR, `${name}_vkey.json`);
  const DEPLOYED_R1CS = path.join(BUILD_DIR, `${name}.r1cs`);
  const FRESH_R1CS = path.join(OUT_DIR, `${name}.r1cs`);
  const FRESH_SYM = path.join(OUT_DIR, `${name}.sym`);
  if (!fs.existsSync(VKEY_FILE)) { await t(`E-3 ${name}: 배포용 vkey 가 있다`, () => { throw new Error(`배포용 vkey 가 없다: ${VKEY_FILE} — bash scripts/build_mode3_circuit.sh`); }); continue; }
  if (!fs.existsSync(FRESH_R1CS) || !fs.existsSync(FRESH_SYM) || fs.statSync(FRESH_R1CS).mtimeMs < newestCircuitMtime()) {
    console.log(`   (${name} 를 새로 컴파일한다 — witness_test/ 가 없거나 소스보다 오래됐다)`);
    compileFresh(name);
  }
  const fresh = r1csHeader(FRESH_R1CS);
  const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, 'utf8'));

  await t(`E-3 ${name}: 회로 소스의 공개 입력 수(${spec.publicInputs.length})가 배포용 vkey 의 nPublic 과 같다`, () => {
    assert.equal(fresh.nPublic, spec.publicInputs.length, `회로 소스의 공개 입력이 ${fresh.nPublic}개 — 계획의 계약(${spec.publicInputs.length})과 다르다`);
    assert.equal(fresh.nPublic, vkey.nPublic, `회로는 공개 입력 ${fresh.nPublic}개인데 배포용 vkey 는 ${vkey.nPublic}개다 — ${REBUILD}`);
    assert.equal(vkey.IC.length, vkey.nPublic + 1, `vkey.IC 길이(${vkey.IC.length}) 가 nPublic + 1 이 아니다`);
  });
  await t(`E-3 ${name}: 배포용 .r1cs 도 같은 회로에서 나왔다(공개·비공개 입력 수)`, () => {
    assert.ok(fs.existsSync(DEPLOYED_R1CS), `배포용 r1cs 가 없다: ${DEPLOYED_R1CS} — ${REBUILD}`);
    const dep = r1csHeader(DEPLOYED_R1CS);
    assert.equal(dep.nPublic, fresh.nPublic, `배포용 r1cs 의 공개 입력 ${dep.nPublic}개 ≠ 소스 ${fresh.nPublic}개 — ${REBUILD}`);
    assert.equal(dep.nPrvIn, fresh.nPrvIn, `배포용 r1cs 의 비공개 입력 ${dep.nPrvIn}개 ≠ 소스 ${fresh.nPrvIn}개 — ${REBUILD}`);
  });
  await t(`E-3 ${name}: 공개 입력의 이름·순서가 ${spec.indexNote} 가 번호로 읽는 그 순서다`, () => {
    assert.deepEqual(publicSignalNames(FRESH_SYM, fresh.nPublic), spec.publicInputs, '공개 입력 순서가 바뀌었다 — 바꾸려면 그 파일들의 인덱스를 함께 고쳐야 한다');
  });
  await t(`E-3 ${name}: 배포용 증명자 산출물(zkey·wasm)이 제자리에 있다`, () => {
    for (const f of [path.join(BUILD_DIR, `${name}_final.zkey`), path.join(BUILD_DIR, `${name}_js`, `${name}.wasm`)]) assert.ok(fs.existsSync(f), `${f} 가 없다 — bash scripts/build_mode3_circuit.sh`);
  });
  console.log(`## ${name} 공개 입력 ${fresh.nPublic}개 / 비공개 입력 ${fresh.nPrvIn}개 / 비선형 제약 ${fresh.nConstraints.toLocaleString()}개(소스)`);
}

// M5(최종 리뷰): PUB_INDEX(lib/mode3_onchain.js)·IDP_PUB_INDEX(lib/mode3_idp_proof.js) — 다른 파일이 공개 입력을 번호로 읽는
// 색인표 — 가 위에서 이미 .sym 과 대조해 확인한 CIRCUITS.*.publicInputs(실제 회로 순서)와 맞는지를 색인 하나하나 검사한다.
// 둘 중 하나만 바뀌면 조용히 틀린 자리를 읽으므로, 이 대조가 lib/mode3_idp_proof.js:16 의 주석("tests/test_mode3_artifacts.mjs
// 가 .sym 과 대조한다")을 실제로 만든다.
await t('E-3 PUB_INDEX.COUNT 는 pi_cred 공개 입력 수와 같다', () => {
  assert.equal(PUB_INDEX.COUNT, CIRCUITS.pi_cred.publicInputs.length);
});
await t('E-3 IDP_PUB_INDEX.COUNT 는 pi_idp 공개 입력 수와 같다', () => {
  assert.equal(IDP_PUB_INDEX.COUNT, CIRCUITS.pi_idp.publicInputs.length);
});
await t('E-3 PUB_INDEX 의 색인이 pi_cred 회로의 실제 공개 입력 이름을 정확히 가리킨다', () => {
  const names = CIRCUITS.pi_cred.publicInputs;
  // DISC_LO·DISC_HI 는 6워드 배열의 시작 색인이라 그 자리의 이름은 [0] 슬롯이다.
  const expect = {
    PPID: 'PPID', ARID: 'arid', PK_I: 'pk_i', MAX_HEIGHT: 'max_height', CHAINID: 'chainid', ALLOW_AGENT: 'allowAgent',
    REV_ROOT: 'revRoot', REG_ROOT: 'regRoot', PK_CIA_X: 'pk_CIA_x', PK_CIA_Y: 'pk_CIA_y',
    PK_TRACE_X: 'pk_trace_x', PK_TRACE_Y: 'pk_trace_y', TAG_C1_X: 'tag_c1_x', TAG_C1_Y: 'tag_c1_y', TAG_C2: 'tag_c2',
    DISC_MASK: 'disc_mask', DISC_LO: 'disc_lo[0]', DISC_HI: 'disc_hi[0]', SET_SEL: 'set_sel', SET_ROOT: 'set_root',
    AUID_S: 'auid_s', ARID_S: 'arid_s', R_S: 'r_s',
  };
  for (const [key, name] of Object.entries(expect)) assert.equal(names[PUB_INDEX[key]], name, `PUB_INDEX.${key} → pub[${PUB_INDEX[key]}]`);
});
await t('E-3 IDP_PUB_INDEX 의 색인이 pi_idp 회로의 실제 공개 입력 이름을 정확히 가리킨다', () => {
  const names = CIRCUITS.pi_idp.publicInputs;
  const expect = { UID: 'uid', AUID: 'auid', AUID_S: 'auid_s', C_U_X: 'C_u_x', C_U_Y: 'C_u_y', C_S_X: 'C_s_x', C_S_Y: 'C_s_y', MAX_HEIGHT: 'max_height' };
  for (const [key, name] of Object.entries(expect)) assert.equal(names[IDP_PUB_INDEX[key]], name, `IDP_PUB_INDEX.${key} → pub[${IDP_PUB_INDEX[key]}]`);
});
process.exit(failed === 0 ? 0 : 1);
