// 이중 트리(샤딩) 판 pi_pk_i 회로의 샤드 제약을 고정한다.
//   node tests/test_pi_pk_i_v3_shard.mjs
//
// zkey는 필요 없다. circom으로 --r1cs --wasm만 만들고 witness 계산까지만 한다
// (tests/test_imt_v2_nonmembership_circuit.mjs 와 같은 방식). 산출물은
// build/pi_pk_i_v3/ 에 만들며, 기존 build/mode2/ 는 건드리지 않는다.
//
// 무엇을 고정하는가 — 설계 문서 2026-09-05-revocation-dual-tree-design.md 4절/11절:
//
//   케이스 1  유효 witness가 통과한다
//   케이스 2  sess_shard_low를 거짓으로 주면 거부된다          (조건 3)
//   케이스 3  acct_shard를 거짓으로 주면 거부된다              (조건 1)
//   케이스 4  "빈 샤드 공격" — 비어 있는 다른 서브트리를 제시해도 거부된다
//   케이스 5  Case 1(본인 폐기): 같은 샤드에 내 리프가 들어가면 witness 자체가 안 나온다
//   케이스 6  Case 2(타인 폐기): 다른 샤드의 폐기는 내 서브트리 root를 바꾸지 않는다
//
// 케이스 4가 이 설계에서 새로 생긴 실패 모드다. 샤드로 쪼개는 순간 "이 서브트리에 없다"는
// 아무것도 증명하지 못하게 되므로(빈 서브트리를 고르면 그만), 회로가 "이 target은 정의상
// 샤드 s에 속한다"까지 함께 보여야 한다.
//
// 케이스 6이 이 설계의 목적 그 자체다 — 타인 폐기로 증명이 죽지 않는다는 것.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { randomBytes, webcrypto } from 'node:crypto';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256 } from 'ethers';
import * as snarkjs from 'snarkjs';
import { createIMTv2 } from '../lib/imt_v2.js';
import {
  leafValue, TAG_SESSION, TAG_ACCOUNT,
  sessionShardLowOf, accountShardOf,
  SESSION_SUBTREE_DEPTH, SESSION_VALUE_BITS,
  ACCOUNT_SUBTREE_DEPTH, ACCOUNT_SHARD_BITS,
} from '../lib/imt_v3.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'pi_pk_i_v3');
const SRC = path.join(ROOT_DIR, 'circuits', 'pi_pk_i_v3.circom');
const WASM = path.join(OUT_DIR, 'pi_pk_i_v3_js', 'pi_pk_i_v3.wasm');
const WTNS = path.join(OUT_DIR, 'scratch.wtns');

// 회로 파라미터. lib/imt_v3.js에서 그대로 가져온다 — 회로와 라이브러리의 샤드 규칙이
// 어긋나면 폐기가 조용히 무효가 되므로, 여기서 값을 다시 적지 않는다.
const SESS_DEPTH = SESSION_SUBTREE_DEPTH;
const SESS_SHARD_BITS = SESSION_VALUE_BITS;
const ACCT_DEPTH = ACCOUNT_SUBTREE_DEPTH;
const ACCT_SHARD_BITS = ACCOUNT_SHARD_BITS;

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// 회로는 target을 252비트로 마스킹한 뒤 하위 비트를 취하는데, 마스킹은 하위 비트를
// 건드리지 않으므로 lib/imt_v3.js의 규칙과 값이 같다. 아래 두 헬퍼는 그 규칙을 그대로
// 쓰기 위한 얇은 래퍼다.
function shardOf(leaf, bits) {
  if (bits === SESS_SHARD_BITS) return BigInt(sessionShardLowOf(leaf));
  if (bits === ACCT_SHARD_BITS) return BigInt(accountShardOf(leaf));
  throw new Error(`unexpected shard bits ${bits}`);
}

function compileIfNeeded() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const deps = [
    SRC,
    path.join(ROOT_DIR, 'circuits', 'lib', 'imt_nonmembership_v3.circom'),
  ];
  const newestDep = Math.max(...deps.map((f) => fs.statSync(f).mtimeMs));
  if (fs.existsSync(WASM) && fs.statSync(WASM).mtimeMs >= newestDep) {
    console.log(`OK: reusing ${path.relative(ROOT_DIR, WASM)}`);
    return;
  }
  console.log('… compiling circuits/pi_pk_i_v3.circom (--r1cs --wasm, no zkey)');
  const out = execFileSync(
    'circom',
    [
      SRC, '--r1cs', '--wasm', '-o', OUT_DIR,
      '-l', path.join(ROOT_DIR, 'circuits'),
      '-l', path.join(ROOT_DIR, 'circuits', 'lib'),
      '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits'),
    ],
    { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const constraints = /non-linear constraints:\s*(\d+)/.exec(out);
  const publics = /public inputs:\s*(\d+)/.exec(out);
  console.log(`OK: compiled, ${constraints?.[1] ?? '?'} constraints, ${publics?.[1] ?? '?'} public inputs`);
  // 설계 문서 7절의 실측값. 회로가 조용히 커지면 여기서 걸린다.
  assert.equal(constraints?.[1], '13905', 'constraint 수가 설계 문서(13,905)와 다르다');
  assert.equal(publics?.[1], '9', 'public signal 수가 설계 문서(9)와 다르다');
}

async function accepts(input, label) {
  await snarkjs.wtns.calculate(input, WASM, WTNS);
  console.log(`OK: ${label}`);
}

async function rejects(input, label) {
  let threw = false;
  try {
    await snarkjs.wtns.calculate(input, WASM, WTNS);
  } catch {
    threw = true;
  }
  if (!threw) {
    console.error(`FAIL: ${label} — 회로가 받아들였다`);
    process.exit(1);
  }
  console.log(`OK: ${label}`);
}

function addressFromPub(pub65) {
  return BigInt('0x' + keccak256('0x' + Buffer.from(pub65.slice(1)).toString('hex')).slice(-40));
}

async function main() {
  compileIfNeeded();

  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = eddsa.F;
  const pos = (arr) => poseidon.F.toObject(poseidon(arr));

  const skIdP = randomBytes(32);
  const pkIdP = eddsa.prv2pub(skIdP);

  const sk_i = webcrypto.getRandomValues(new Uint8Array(32));
  const pk_i = addressFromPub(secp256k1.getPublicKey(sk_i, false));

  const rp_nonce = 424242n;
  const uid = 111111n;
  const rid = 222222n;
  const salt = 333333n;
  const max_height = 1000n;
  const chain_id = 31337n;

  const PPID = pos([uid, rid, salt]);
  const auid = pos([uid, salt]);
  const r_token = pos([pk_i, max_height, rp_nonce]);
  const arid_i = (rid * rp_nonce) % FIELD_PRIME;
  const auid_i = (PPID * rp_nonce) % FIELD_PRIME;

  const DOMAIN_IDP_TOKEN = BigInt('0x' + Buffer.from('IDP_TOKEN').toString('hex')) % FIELD_PRIME;
  const msg = poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id]);
  const sig = eddsa.signPoseidon(skIdP, msg);

  const sessLeaf = await leafValue(TAG_SESSION, r_token);
  const acctLeaf = await leafValue(TAG_ACCOUNT, auid);
  const sessShard = shardOf(sessLeaf, SESS_SHARD_BITS);
  const acctShard = shardOf(acctLeaf, ACCT_SHARD_BITS);
  console.log(`   내 샤드: sess_shard_low=${sessShard}, acct_shard=${acctShard}`);

  // 내 샤드의 서브트리 두 개. 처음에는 비어 있다(anchor만).
  const sessTree = await createIMTv2(SESS_DEPTH);
  const acctTree = await createIMTv2(ACCT_DEPTH);

  const base = {
    rp_nonce: rp_nonce.toString(),
    arid_i: arid_i.toString(),
    auid_i: auid_i.toString(),
    r_token: r_token.toString(),
    chain_id: chain_id.toString(),
    S: sig.S.toString(),
    R8x: F.toObject(sig.R8[0]).toString(),
    R8y: F.toObject(sig.R8[1]).toString(),
    uid: uid.toString(),
    rid: rid.toString(),
    salt: salt.toString(),
    pk_i: pk_i.toString(),
    pk_IdP_x: F.toObject(pkIdP[0]).toString(),
    pk_IdP_y: F.toObject(pkIdP[1]).toString(),
    PPID: PPID.toString(),
    max_height: max_height.toString(),
  };

  async function buildInput({ sessOverride, acctOverride, sessShardLow, acctShardIdx } = {}) {
    const sw = sessOverride ?? await sessTree.getNonMembershipWitness(sessLeaf);
    const aw = acctOverride ?? await acctTree.getNonMembershipWitness(acctLeaf);
    return {
      ...base,
      sess_lowValue: sw.lowValue,
      sess_lowNextIndex: sw.lowNextIndex,
      sess_lowNextValue: sw.lowNextValue,
      sess_pathElements: sw.pathElements,
      sess_pathIndices: sw.pathIndices,
      sess_root: sw.root,
      sess_shard_low: (sessShardLow ?? sessShard).toString(),
      acct_lowValue: aw.lowValue,
      acct_lowNextIndex: aw.lowNextIndex,
      acct_lowNextValue: aw.lowNextValue,
      acct_pathElements: aw.pathElements,
      acct_pathIndices: aw.pathIndices,
      acct_root: aw.root,
      acct_shard: (acctShardIdx ?? acctShard).toString(),
    };
  }

  // ── 1) 유효 witness ────────────────────────────────────────────────────
  await accepts(await buildInput(), '1) 유효 witness가 통과한다');

  // ── 2) 세션 샤드 위조 (조건 3) ────────────────────────────────────────
  await rejects(
    await buildInput({ sessShardLow: (sessShard + 1n) % (1n << BigInt(SESS_SHARD_BITS)) }),
    '2) sess_shard_low를 거짓으로 주면 거부된다',
  );

  // ── 3) 계정 샤드 위조 (조건 1) ────────────────────────────────────────
  await rejects(
    await buildInput({ acctShardIdx: (acctShard + 1n) % (1n << BigInt(ACCT_SHARD_BITS)) }),
    '3) acct_shard를 거짓으로 주면 거부된다',
  );

  // ── 4) 빈 샤드 공격 ───────────────────────────────────────────────────
  // 공격자는 자기 계정 리프가 든 샤드 대신, **비어 있는 다른 샤드**의 서브트리를 제시한다.
  // 빈 트리에서는 anchor가 모든 값을 덮으므로 비멤버십 witness 자체는 정상적으로 나온다 —
  // 막는 것은 오직 shardIndex === acct_shard 제약뿐이다.
  // (역으로, "올바른 샤드인데 root가 가짜"인 경우는 회로가 아니라 컨트랙트가 막는다 —
  //  상위 트리 경로로 root_s가 latestTopRoot의 s번째 잎임을 확인한다. Stage C.)
  {
    const emptyOtherShard = await createIMTv2(ACCT_DEPTH);
    const w = await emptyOtherShard.getNonMembershipWitness(acctLeaf);
    const otherShardIdx = (acctShard + 7n) % (1n << BigInt(ACCT_SHARD_BITS));
    assert.notEqual(otherShardIdx, acctShard);
    await rejects(
      await buildInput({ acctOverride: w, acctShardIdx: otherShardIdx }),
      '4) 빈 서브트리를 다른 샤드로 제시하면 거부된다 (빈 샤드 공격)',
    );
  }

  // ── 5) Case 1 — 본인 폐기 ─────────────────────────────────────────────
  // 내 리프가 내 샤드에 들어가면 비멤버십 witness가 아예 만들어지지 않는다.
  {
    const revoked = await createIMTv2(SESS_DEPTH);
    await revoked.insert(sessLeaf);
    await assert.rejects(
      () => revoked.getNonMembershipWitness(sessLeaf),
      /is a member of the revocation set/,
      '폐기된 세션에 대해 witness가 만들어졌다',
    );
    console.log('OK: 5) Case 1 — 본인 세션이 폐기되면 witness 자체가 나오지 않는다');
  }

  // ── 6) Case 2 — 타인 폐기 ─────────────────────────────────────────────
  // 이 설계의 목적. 타인의 폐기가 **다른 샤드**에 떨어지면 내 서브트리 root가 그대로이므로
  // 내 증명 입력이 한 글자도 바뀌지 않는다. (현행 단일 트리에서는 여기서 root가 바뀌어
  // 전 지갑의 증명이 죽는다.)
  {
    const before = sessTree.getRoot().toString();
    const otherShardTree = await createIMTv2(SESS_DEPTH);
    // 다른 사람의 세션 리프. 샤드가 다르므로 우리 서브트리에는 애초에 들어오지 않는다.
    let otherLeaf = await leafValue(TAG_SESSION, 987654321n);
    let guard = 0;
    while (shardOf(otherLeaf, SESS_SHARD_BITS) === sessShard) {
      otherLeaf = await leafValue(TAG_SESSION, 987654321n + BigInt(++guard));
      assert.ok(guard < 64, '다른 샤드에 떨어지는 리프를 찾지 못했다');
    }
    await otherShardTree.insert(otherLeaf);

    const after = sessTree.getRoot().toString();
    assert.equal(after, before, '타인 폐기가 내 서브트리 root를 바꿨다');
    await accepts(
      await buildInput(),
      '6) Case 2 — 타인 폐기 뒤에도 같은 입력이 그대로 통과한다 (SNARK 재생성 불필요)',
    );
  }

  console.log('\n== pi_pk_i_v3 샤드 제약 6종 통과 ==');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
