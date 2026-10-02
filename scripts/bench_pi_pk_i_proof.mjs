// 현재 pi_pk_i 회로의 증명 생성 시간을 실측해 results/에 남긴다.
//   node scripts/bench_pi_pk_i_proof.mjs [runs]      (기본 10회)
//
// 왜 필요한가. results/mode2_zkp_benchmark_10runs.csv는 **4,820 constraint 시절**
// 회로의 값이다(pi_pk_i 295~740 ms). 그 뒤 폐기 비멤버십이 들어가고(19,091) pk_i
// 160비트 제약까지 붙어(19,251) 회로가 4배 커졌는데, 발표 자료가 옛 수치를
// "우리 실측"으로 인용하고 있었다(2026-09-04 슬라이드 리뷰). 라벨과 실제를 맞춘다.
//
// test/PPIDWallet.test.mjs의 buildValidCallData와 같은 방식으로 입력을 만든다.
import fs from 'node:fs';
import { randomBytes, webcrypto } from 'node:crypto';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256 } from 'ethers';
import * as snarkjs from 'snarkjs';
import { createIMTv2, leafValue, TAG_SESSION, TAG_ACCOUNT } from '../lib/imt_v2.js';

const RUNS = Number(process.argv[2]) || 10;
const WASM = 'build/mode2/pi_pk_i_js/pi_pk_i.wasm';
const ZKEY = 'build/mode2/pi_pk_i_final.zkey';
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function addressFromPub(pub65) {
  return BigInt('0x' + keccak256('0x' + Buffer.from(pub65.slice(1)).toString('hex')).slice(-40));
}

async function buildInput() {
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

  const tree = await createIMTv2(20);
  const sessWitness = await tree.getNonMembershipWitness(await leafValue(TAG_SESSION, r_token));
  const acctWitness = await tree.getNonMembershipWitness(await leafValue(TAG_ACCOUNT, auid));

  return {
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
    sess_lowValue: sessWitness.lowValue,
    sess_lowNextIndex: sessWitness.lowNextIndex,
    sess_lowNextValue: sessWitness.lowNextValue,
    sess_pathElements: sessWitness.pathElements,
    sess_pathIndices: sessWitness.pathIndices,
    acct_lowValue: acctWitness.lowValue,
    acct_lowNextIndex: acctWitness.lowNextIndex,
    acct_lowNextValue: acctWitness.lowNextValue,
    acct_pathElements: acctWitness.pathElements,
    acct_pathIndices: acctWitness.pathIndices,
    pk_i: pk_i.toString(),
    pk_IdP_x: F.toObject(pkIdP[0]).toString(),
    pk_IdP_y: F.toObject(pkIdP[1]).toString(),
    PPID: PPID.toString(),
    max_height: max_height.toString(),
    revocationRoot: sessWitness.root,
  };
}

const input = await buildInput();
const rows = [];
console.log(`pi_pk_i 증명 생성 ${RUNS}회 측정 (wasm=${WASM})`);
for (let i = 1; i <= RUNS; i++) {
  const t0 = process.hrtime.bigint();
  const { proof } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  rows.push({ run: i, ms, bytes: JSON.stringify(proof).length });
  console.log(`  run ${i}: ${ms.toFixed(1)} ms`);
}

// 1회차는 WASM 초기화·JIT 웜업이 섞여 있어 따로 본다(wallet_agent.js가 워밍업을 두는 이유).
const warm = rows.slice(1).map((r) => r.ms);
const mean = warm.reduce((a, b) => a + b, 0) / warm.length;
const sd = Math.sqrt(warm.reduce((a, b) => a + (b - mean) ** 2, 0) / warm.length);
console.log(`\ncold(1회차): ${rows[0].ms.toFixed(1)} ms`);
console.log(`warm 평균: ${mean.toFixed(1)} ms (±${sd.toFixed(1)}, n=${warm.length})`);

const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
const out = `results/mode2_pi_pk_i_proof_${stamp}.csv`;
fs.writeFileSync(
  out,
  'circuit,run,duration_ms,proof_json_bytes\n' +
    rows.map((r) => `pi_pk_i,${r.run},${r.ms.toFixed(1)},${r.bytes}`).join('\n') +
    '\n',
);
console.log(`\nwrote ${out}`);
