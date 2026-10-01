// pi_cred 회로(V9)의 witness 계산. 양성·음성 45건 — 정상 witness, JS/회로 리프 일치, 태그 개봉, 잘못된 입력 거부.
//   node tests/test_pi_cred_witness.mjs
//
// zkey는 만들지 않는다 (Task 4에서 별도 승인 후). 여기서는 회로가 올바른 입력을
// 받아들이고 잘못된 입력을 거부하는지만 본다 — 그게 건전성의 핵심이다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sessionLeaf, MODE3_TREE_DEPTH } from '../lib/mode3_revocation.js';
import { registryLeaf } from '../lib/mode3_registry.js';
import { buildValidInput } from './helpers/mode3_fixture.mjs';
import { ppid } from '../lib/mode3_credential.js';
import { partialDecrypt, combineDecrypt, resolveTagPlaintext } from '../lib/mode3_trace.js';

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
const { input: valid, shares, tag, arid: validArid } = await buildValidInput();

await t('양성: 정상 credential의 witness가 계산된다', async () => {
  const w = await witness(valid);
  assert.ok(w.length > 0);
  assert.equal(valid.s_pathElements.length, MODE3_TREE_DEPTH);
  assert.equal(valid.reg_pathElements.length, 20);
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

await t('음성: max_height 를 바꾸면 거부된다 (서명이 max_height 를 덮는다)', async () => {
  await assert.rejects(() => witness({ ...valid, max_height: (BigInt(valid.max_height) + 1n).toString() }), /Assert Failed/);
});

await t('음성: chainid 를 바꾸면 거부된다 (서명이 chainid 를 덮는다)', async () => {
  await assert.rejects(() => witness({ ...valid, chainid: '1' }), /Assert Failed/);
});

await t('음성: allowAgent 를 뒤집으면 거부된다 (서명이 allowAgent 를 덮는다), 2 는 불리언 제약에서 거부된다', async () => {
  await assert.rejects(() => witness({ ...valid, allowAgent: '1' }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, allowAgent: '2' }), /Assert Failed/);
});

await t('양성: allowAgent = 1 로 서명한 자격증명은 통과한다', async () => {
  const { input } = await buildValidInput({ allowAgent: 1n });
  const w = await witness(input);
  assert.ok(w.length > 0);
});

await t('음성: attr 하나를 바꾸면 거부된다 (C 가 달라져 서명이 안 맞는다)', async () => {
  const attrs = [...valid.attrs]; attrs[0] = '20';
  await assert.rejects(() => witness({ ...valid, attrs }), /Assert Failed/);
});

await t('음성: pk_i를 바꾸면 거부된다 (C_s 바인딩이 깨진다 — 서명이 Cf_s 를 덮는다)', async () => {
  await assert.rejects(
    () => witness({ ...valid, pk_i: (BigInt(valid.pk_i) + 1n).toString() }),
    /Assert Failed/,
  );
});

await t('V5 음성: blind_u 를 바꾸면 거부된다 (C_u 가 달라져 서명·리프가 안 맞는다)', async () => {
  await assert.rejects(() => witness({ ...valid, blind_u: (BigInt(valid.blind_u) + 1n).toString() }), /Assert Failed/);
});
await t('V5 음성: blind_s 를 바꾸면 거부된다 (C_s 가 달라져 서명이 안 맞는다)', async () => {
  await assert.rejects(() => witness({ ...valid, blind_s: (BigInt(valid.blind_s) + 1n).toString() }), /Assert Failed/);
});
await t('V5 음성: r = 0 은 회로가 거부한다 (2026-09-21 결정 — IsZero 제약)', async () => {
  await assert.rejects(() => witness({ ...valid, r: '0' }), /Assert Failed/);
});

await t('⑤ 양성: 회로가 받아들인 태그는 두 조각으로 uid 로 열린다 (JS encryptTag 와 회로 계산이 일치)', async () => {
  await witness(valid);   // 공개 입력 tag_* 가 회로 계산과 같아야 통과한다
  const D_svc = await partialDecrypt(shares.svc.x, tag.c1);
  const D_aa = await partialDecrypt(shares.aa.x, tag.c1);
  const h = await combineDecrypt(tag.c2, D_svc, D_aa);
  assert.equal(h, tag.h, '복호 결과는 Poseidon(uid, arid)');
  assert.equal(await resolveTagPlaintext(h, validArid, ['1', valid.uid]), valid.uid);
});

await t('⑤ 음성: c2 를 바꾸면 거부된다 (평문이 커밋 안의 uid·공개 입력 arid 의 Poseidon 과 다르다)', async () => {
  await assert.rejects(() => witness({ ...valid, tag_c2: (BigInt(valid.tag_c2) + 1n).toString() }), /Assert Failed/);
});

await t('⑤ 음성: pk_trace 를 바꾸면 거부된다 (다른 키로 만든 태그는 이 키의 태그가 아니다)', async () => {
  // c1 은 r 만의 함수라 그대로이고 K 가 달라져 c2 가 안 맞는다.
  await assert.rejects(() => witness({ ...valid, pk_trace_x: shares.svc.X.x.toString(), pk_trace_y: shares.svc.X.y.toString() }), /Assert Failed/);
});

await t('⑤ 음성: c1 을 바꾸면 거부된다 (c1 = r·B8 를 회로가 계산한다)', async () => {
  await assert.rejects(() => witness({ ...valid, tag_c1_x: shares.svc.X.x.toString(), tag_c1_y: shares.svc.X.y.toString() }), /Assert Failed/);
});

await t('⑤ 음성: r 을 바꾸면 거부된다 (c1·c2 둘 다 어긋난다)', async () => {
  await assert.rejects(() => witness({ ...valid, r: (BigInt(valid.r) + 1n).toString() }), /Assert Failed/);
});

await t('V6 양성: mask = 0 이면 lo·hi 가 0 이어도 통과 (로그인 문장)', async () => {
  const fx = await buildValidInput();
  assert.equal(fx.input.disc_mask, '0');
  await witness(fx.input);
});
await t('V6 양성: 슬롯 0 구간 [0, 2007], 슬롯 1 등식 410 — 통과', async () => {
  const fx = await buildValidInput({ disclosure: { mask: 0b0011n, lo: [0n, 410n, 0n, 0n, 0n, 0n], hi: [2007n, 410n, 0n, 0n, 0n, 0n] } });
  await witness(fx.input);
});
await t('V6 음성: 구간 밖(a₀ = 1990 ∉ [0, 1980]) 은 거부', async () => {
  const fx = await buildValidInput({ disclosure: { mask: 0b0001n, lo: [0n, 0n, 0n, 0n, 0n, 0n], hi: [1980n, 0n, 0n, 0n, 0n, 0n] } });
  await assert.rejects(() => witness(fx.input), /Assert Failed/);
});
await t('V6 음성: 등식 불일치(a₁ = 410, lo = hi = 840) 는 거부', async () => {
  const fx = await buildValidInput({ disclosure: { mask: 0b0010n, lo: [0n, 840n, 0n, 0n, 0n, 0n], hi: [0n, 840n, 0n, 0n, 0n, 0n] } });
  await assert.rejects(() => witness(fx.input), /Assert Failed/);
});
await t('V6 양성: 공개하지 않는 슬롯의 lo·hi 는 무시된다 (mask 비트 0 인 슬롯 2 에 불가능한 구간)', async () => {
  const fx = await buildValidInput({ disclosure: { mask: 0b0001n, lo: [0n, 0n, 999n, 0n, 0n, 0n], hi: [2007n, 0n, 5n, 0n, 0n, 0n] } });
  await witness(fx.input);
});
await t('V6 음성: mask ≥ 64, lo ≥ 2^64, attr ≥ 2^64 는 거부', async () => {
  const ok = await buildValidInput({ disclosure: { mask: 0b0001n, lo: [0n, 0n, 0n, 0n, 0n, 0n], hi: [2007n, 0n, 0n, 0n, 0n, 0n] } });
  await assert.rejects(() => witness({ ...ok.input, disc_mask: '64' }), /Assert Failed/);
  await assert.rejects(() => witness({ ...ok.input, disc_lo: [(1n << 64n).toString(), '0', '0', '0', '0', '0'] }), /Assert Failed/);
  const big = await buildValidInput();
  await assert.rejects(() => witness({ ...big.input, attrs: [(1n << 64n).toString(), '410', '2', '0', '0', '0'] }), /Assert Failed/);   // C_u 가 달라져 서명도 깨지지만 Num2Bits(64) 가 먼저 막는다
});

const COUNTRIES = [410, 392, 840, 276, 250];
await t('V7 양성: set_sel = 0, set_root = 0 (집합 술어 없음) — 기존 입력 그대로 통과, 공개 입력에 set_sel·set_root 가 있다', async () => {
  const fx = await buildValidInput();
  assert.equal(fx.input.set_sel, '0'); assert.equal(fx.input.set_root, '0');
  await witness(fx.input);
});
await t('V7 양성: 국가(a₁ = 410) ∈ {410,392,840,276,250} — set_sel = 2 통과', async () => {
  const fx = await buildValidInput({ set: { slot: 1, members: COUNTRIES } });
  assert.equal(fx.input.set_sel, '2');
  await witness(fx.input);
});
await t('V7 양성: 범위 + 집합 동시(슬롯 0 범위, 슬롯 1 집합)', async () => {
  const fx = await buildValidInput({ disclosure: { mask: 0b0001n, lo: [0n, 0n, 0n, 0n, 0n, 0n], hi: [2007n, 0n, 0n, 0n, 0n, 0n] }, set: { slot: 1, members: COUNTRIES } });
  await witness(fx.input);
});
await t('V7 음성: root 를 바꾸면 거부', async () => {
  const fx = await buildValidInput({ set: { slot: 1, members: COUNTRIES } });
  await assert.rejects(() => witness({ ...fx.input, set_root: (BigInt(fx.input.set_root) + 1n).toString() }), /Assert Failed/);
});
await t('V7 음성: 다른 슬롯을 가리키면(set_sel = 1, a₀ = 1990 ∉ S) 거부', async () => {
  const fx = await buildValidInput({ set: { slot: 1, members: COUNTRIES } });
  await assert.rejects(() => witness({ ...fx.input, set_sel: '1' }), /Assert Failed/);
});
await t('V7 음성: 경로 index 를 바꾸면 거부', async () => {
  const fx = await buildValidInput({ set: { slot: 1, members: COUNTRIES } });
  await assert.rejects(() => witness({ ...fx.input, set_index: String((Number(fx.input.set_index) + 1) % 256) }), /Assert Failed/);
});
await t('V7 음성: set_sel = 0 인데 set_root ≠ 0 은 거부(검증자가 무시하는 값에 쓰레기를 실을 수 없다)', async () => {
  const fx = await buildValidInput();
  await assert.rejects(() => witness({ ...fx.input, set_root: '1' }), /Assert Failed/);
});
await t('V7 음성: set_sel = 7 은 거부', async () => {
  const fx = await buildValidInput({ set: { slot: 1, members: COUNTRIES } });
  await assert.rejects(() => witness({ ...fx.input, set_sel: '7' }), /Assert Failed/);
});
await t('V7 양성: set_sel = 0 이면 set_index·set_path 는 무시된다', async () => {
  const fx = await buildValidInput();
  await witness({ ...fx.input, set_index: '77', set_path: Array(8).fill('123456789') });
});
await t('V7: 패딩 리프(2^64)는 어떤 속성으로도 못 맞춘다 — 속성이 64비트라 2^64 자체가 거부된다', async () => {
  // 집합에 원소 하나만 두면 index 1..255 는 전부 패딩. 속성 값을 2^64 로 바꿔 패딩 자리에 맞추려 해도 C_u 의 Num2Bits(64) 가 먼저 막는다.
  const fx = await buildValidInput({ set: { slot: 3, members: [0] } });   // a₃ = 0 ∈ {0}
  await witness(fx.input);
  await assert.rejects(() => witness({ ...fx.input, attrs: ['1990', '410', '2', (1n << 64n).toString(), '0', '0'], set_index: '1' }), /Assert Failed/);
});

await t('V8 양성: 남의 세션 폐기 리프가 있어도 내 세션 비멤버십은 성립', async () => {
  const fx = await buildValidInput({ revokedSessions: [777n, 778n] });
  await witness(fx.input);
});
await t('V8 음성: 내 세션 리프 Poseidon(5, Cf_s) 가 트리에 있으면 거부 — 사용자 리프는 그대로', async () => {
  const fx = await buildValidInput();
  await fx.tree.insert(await sessionLeaf(fx.Cf_s));
  await assert.rejects(() => witness({ ...fx.input, revRoot: fx.tree.getRoot().toString() }), /Assert Failed/);
});

await t('V9 양성: 등록부 슬롯 번호는 임의 — 마지막 슬롯(2^20 - 1)에 내 리프가 있어도 통과', async () => {
  const fx = await buildValidInput({ registrySlot: 2 ** 20 - 1 });   // 마지막 슬롯
  await witness(fx.input);
});
await t('V9 음성: r_u 가 다르면 cm_u 가 달라 등록부 포함이 깨진다', async () => {
  await assert.rejects(() => witness({ ...valid, r_u: (BigInt(valid.r_u) + 1n).toString() }), /Assert Failed/);
});
await t('V9 음성: 슬롯이 비어 있으면(리프 0) 거부 — 게시 전 자격증명', async () => {
  const fx = await buildValidInput({ registryLeafOverride: 0n });
  await assert.rejects(() => witness(fx.input), /Assert Failed/);
});
await t('V9 음성: 은퇴(슬롯을 0으로 되돌림) 뒤의 실제 root 에 옛 경로를 내밀면 거부', async () => {
  const fx = await buildValidInput();
  fx.registry.set(fx.slot, 0n);
  await assert.rejects(() => witness({ ...fx.input, regRoot: fx.registry.root().toString() }), /Assert Failed/);
});
await t('V9 음성: 슬롯이 다른 자격증명(C′)으로 바뀌면 거부 — 관리자 바꿔치기 시연의 회로 쪽', async () => {
  const fx = await buildValidInput({ registryLeafOverride: 424242n });
  await assert.rejects(() => witness(fx.input), /Assert Failed/);
});
await t('V9 음성: 경로를 바꾸면 거부, regRoot 를 바꾸면 거부', async () => {
  const els = [...valid.reg_pathElements]; els[0] = (BigInt(els[0]) + 1n).toString();
  await assert.rejects(() => witness({ ...valid, reg_pathElements: els }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, regRoot: (BigInt(valid.regRoot) + 1n).toString() }), /Assert Failed/);
});
await t('V9 음성: reg_pathIndices 가 불리언이 아니면(2) 거부, 비트를 뒤집어도(0↔1) 거부', async () => {
  const nonBool = [...valid.reg_pathIndices]; nonBool[0] = '2';
  await assert.rejects(() => witness({ ...valid, reg_pathIndices: nonBool }), /Assert Failed/);
  const flipped = [...valid.reg_pathIndices]; flipped[0] = flipped[0] === '0' ? '1' : '0';
  await assert.rejects(() => witness({ ...valid, reg_pathIndices: flipped }), /Assert Failed/);
});
await t('V9 음성: salt(s_u) 를 바꾸면 PPID·C_u·등록부가 모두 어긋난다(지갑 시연 "prove" 경로)', async () => {
  await assert.rejects(() => witness({ ...valid, s_u: (BigInt(valid.s_u) + 1n).toString() }), /Assert Failed/);
});
await t('V9: JS registryLeaf 와 회로의 리프 계산이 일치한다 (main.inc.leaf)', async () => {
  // main.regLeaf.out 자체는 circom 최적화가 inc.leaf 와 같은 와이어로 합쳐 witness 색인을 -1(별도 저장 없음)로
  // 지운다 — producer.out 을 <== 로 바로 다른 신호에 넘기는 자리는 전부 이 패턴이다(main.sLeaf.out·main.cfu.out 도 -1).
  // 소비자 쪽 main.inc.leaf 가 실제 색인을 쥐고 있고 inc.leaf === regLeaf.out 제약으로 값이 같으므로 여기서 비교한다.
  const sym = fs.readFileSync(path.join(OUT_DIR, `${NAME}.sym`), 'utf8');
  const line = sym.split('\n').find((l) => l.split(',')[3] === 'main.inc.leaf');
  assert.ok(line, 'pi_cred.sym 에서 main.inc.leaf 를 찾지 못했다');
  const idx = Number(line.split(',')[1]);
  const w = await witness(valid);
  const fx = await buildValidInput();
  assert.equal(BigInt(w[idx]), await registryLeaf(fx.cm_u, fx.Cf_u));
});
await t('V9 양성: 6번째 슬롯 범위·집합 — attrs[5] = 0 ∈ [0, 0], set_sel = 6', async () => {
  const fx = await buildValidInput({ disclosure: { mask: 0b100000n, lo: [0n, 0n, 0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n, 0n, 0n] }, set: { slot: 5, members: [0, 1, 2] } });
  assert.equal(fx.input.set_sel, '6');
  await witness(fx.input);
});

console.log('');
console.log(`## pi_cred 비선형 제약: ${constraints.toLocaleString()}`);
console.log(`   (참고 — Mode 2 pi_pk_i_v3: 13,905)`);
console.log('   (V3 2026-09-16: 25,505)');
console.log('   (V8 2026-09-24: 37,130)');

process.exit(failed === 0 ? 0 : 1);
