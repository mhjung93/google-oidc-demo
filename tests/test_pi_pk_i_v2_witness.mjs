// circuits/pi_pk_i.circom(정석 IMT v2 배선판)이 실제 지갑이 만들 witness 형태를
// 그대로 받아들이는지, zkey 생성 **전에** witness 계산만으로 확인한다.
//   node tests/test_pi_pk_i_v2_witness.mjs
//
// tests/test_imt_v2_nonmembership_circuit.mjs가 IMTNonMembershipV2 템플릿 단독을
// 검증한 것과 같은 방식(circom --r1cs --wasm + snarkjs.wtns.calculate)을 pi_pk_i
// 전체에 적용한다. zkey는 필요 없다 — 여기서 문제가 나오면 값비싼 zkey 생성 전에
// 고치는 게 훨씬 싸다(브리프 작업 1/검증 1).
//
// 산출물은 build/pi_pk_i_v2test/에 만든다. build/ 전체가 .gitignore 대상이고 이
// 디렉터리는 새로 생기므로 커밋된 build/mode2 산출물을 덮어쓰지 않는다.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import { buildPoseidon, buildEddsa } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { createIMTv2, buildIMTv2, leafValue, TAG_SESSION, TAG_ACCOUNT } from '../lib/imt_v2.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'pi_pk_i_v2test');
const SRC = path.join(ROOT_DIR, 'circuits', 'pi_pk_i.circom');
const WASM = path.join(OUT_DIR, 'pi_pk_i_js', 'pi_pk_i.wasm');
const WTNS = path.join(OUT_DIR, 'scratch.wtns');

// 회로가 하드코딩한 var DOMAIN_IDP_TOKEN 과 반드시 같아야 서명이 검증된다.
const DOMAIN_IDP_TOKEN = 1351534856589225444686n;
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function compileIfNeeded() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const stale = !fs.existsSync(WASM)
    || fs.statSync(WASM).mtimeMs < fs.statSync(SRC).mtimeMs
    || fs.statSync(WASM).mtimeMs
       < fs.statSync(path.join(ROOT_DIR, 'circuits', 'lib', 'imt_nonmembership_v2.circom')).mtimeMs;
  if (!stale) {
    console.log(`OK: reusing ${path.relative(ROOT_DIR, WASM)}`);
    return;
  }
  console.log('… compiling circuits/pi_pk_i.circom (--r1cs --wasm, no zkey)');
  const out = execFileSync(
    'circom',
    [SRC, '--r1cs', '--wasm', '-o', OUT_DIR, '-l', path.join(ROOT_DIR, 'circuits')],
    { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const nl = /non-linear constraints:\s*(\d+)/.exec(out);
  console.log(`OK: compiled, ${nl ? nl[1] : '?'} non-linear constraints`);
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
    console.error(`FAIL: ${label} was accepted by the circuit`);
    process.exit(1);
  }
  console.log(`OK: ${label} (rejected)`);
}

// 실제 지갑(wallet_agent.js buildWarmupPiPkIInput / submitTransaction)이 만드는
// circuitInput 모양 그대로를 v2 트리로 구성한다. sess/acct 모두 lowNextIndex 포함.
async function buildWalletInput({ poseidon, eddsa, tree }) {
  const F = eddsa.F;
  const sk = webcrypto.getRandomValues(new Uint8Array(32));
  const pk = eddsa.prv2pub(sk);

  const rp_nonce = 424242n;
  const uid = 111111n;
  const rid = 222222n;
  const salt = 333333n;
  const pk_i = 987654321n;
  const max_height = 1000n;
  const chain_id = 1337n;

  const PPID = poseidon.F.toObject(poseidon([uid, rid, salt]));
  const arid_i = (rid * rp_nonce) % FIELD_PRIME;
  const auid_i = (PPID * rp_nonce) % FIELD_PRIME;
  const r_token = poseidon.F.toObject(poseidon([pk_i, max_height, rp_nonce]));
  const auid = poseidon.F.toObject(poseidon([uid, salt]));

  const msg = poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id]);
  const sig = eddsa.signPoseidon(sk, msg);

  const sessTarget = await leafValue(TAG_SESSION, r_token.toString());
  const acctTarget = await leafValue(TAG_ACCOUNT, auid.toString());
  const sess = await tree.getNonMembershipWitness(sessTarget);
  const acct = await tree.getNonMembershipWitness(acctTarget);

  return {
    input: {
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
      sess_lowValue: sess.lowValue,
      sess_lowNextIndex: sess.lowNextIndex,
      sess_lowNextValue: sess.lowNextValue,
      sess_pathElements: sess.pathElements,
      sess_pathIndices: sess.pathIndices,
      acct_lowValue: acct.lowValue,
      acct_lowNextIndex: acct.lowNextIndex,
      acct_lowNextValue: acct.lowNextValue,
      acct_pathElements: acct.pathElements,
      acct_pathIndices: acct.pathIndices,
      pk_i: pk_i.toString(),
      pk_IdP_x: F.toObject(pk[0]).toString(),
      pk_IdP_y: F.toObject(pk[1]).toString(),
      PPID: PPID.toString(),
      max_height: max_height.toString(),
      revocationRoot: sess.root,
    },
    meta: { r_token, auid },
  };
}

async function main() {
  compileIfNeeded();
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();

  // 1) 빈(anchor만) v2 트리 — 두 target 모두 자명한 비멤버.
  {
    const tree = await createIMTv2(20);
    const { input } = await buildWalletInput({ poseidon, eddsa, tree });
    await accepts(input, 'empty v2 tree: full pi_pk_i witness verifies');
  }

  // 2) 정렬 순서 ≠ 물리 순서인 v2 트리(임의 arrival 순서로 폐기 삽입).
  //    v2의 핵심(low 리프가 물리적으로 마지막이 아니어도 됨)을 pi_pk_i 전체에서 확인.
  {
    const revoked = [];
    for (const seed of [50, 900, 300, 700, 100, 800, 200, 600, 400]) {
      revoked.push(await leafValue(TAG_SESSION, BigInt(seed)));
    }
    const tree = await buildIMTv2(20, revoked);
    const { input } = await buildWalletInput({ poseidon, eddsa, tree });
    await accepts(input, 'unsorted-arrival v2 tree: full pi_pk_i witness verifies');
  }

  // 3) 폐기된 세션 target으로는 witness 자체가 못 만들어져야 한다(라이브러리가 거부).
  //    회로 배선이 아니라 소비 규약 확인 — 폐기된 값은 증명 경로에 들어오지 못한다.
  {
    const tree = await createIMTv2(20);
    const victim = await leafValue(TAG_SESSION, 555n);
    await tree.insert(victim);
    let threw = false;
    try { await tree.getNonMembershipWitness(victim); } catch { threw = true; }
    if (!threw) { console.error('FAIL: revoked target produced a non-membership witness'); process.exit(1); }
    console.log('OK: a revoked session target cannot produce a non-membership witness');
  }

  // 4) lowNextIndex를 조작하면(다른 필드는 정직) 리프 해시가 달라져 회로가 거부한다.
  {
    const tree = await buildIMTv2(20, [
      await leafValue(TAG_SESSION, 10n),
      await leafValue(TAG_SESSION, 20n),
      await leafValue(TAG_SESSION, 30n),
    ]);
    const { input } = await buildWalletInput({ poseidon, eddsa, tree });
    const tampered = { ...input, sess_lowNextIndex: (BigInt(input.sess_lowNextIndex) + 1n).toString() };
    await rejects(tampered, 'tampered sess_lowNextIndex breaks the Merkle path');
  }

  console.log('\nPASS: pi_pk_i.circom (v2) accepts real wallet-shaped witnesses; tampered ones fail.');
}

main().catch((err) => { console.error(err); process.exit(1); });
