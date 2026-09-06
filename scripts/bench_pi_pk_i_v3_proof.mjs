// 이중 트리(v3) 회로의 증명 생성 시간을 실측해 results/에 남긴다.
//   node scripts/bench_pi_pk_i_v3_proof.mjs [runs]      (기본 10회)
//
// 설계 문서(2026-09-05-revocation-dual-tree-design.md) 7절이 "약 546 ms"를 constraint 비
// 환산치로 적어두고 있었다. 그 자리를 실측으로 대체하기 위한 스크립트다.
// scripts/bench_pi_pk_i_proof.mjs와 같은 방식이되 입력이 v3 형식(샤드별 서브트리)이다.
import fs from 'node:fs';
import { randomBytes, webcrypto } from 'node:crypto';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256 } from 'ethers';
import * as snarkjs from 'snarkjs';
import {
  createSessionForest, createAccountForest,
  sessionShardLowOf, accountShardOf,
  leafValue, TAG_SESSION, TAG_ACCOUNT,
} from '../lib/imt_v3.js';

const RUNS = Number(process.argv[2]) || 10;
const WASM = 'build/mode2_v3/pi_pk_i_v3_js/pi_pk_i_v3.wasm';
const ZKEY = 'build/mode2_v3/pi_pk_i_v3_final.zkey';
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function buildInput() {
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = eddsa.F;
  const pos = (a) => poseidon.F.toObject(poseidon(a));

  const skIdP = randomBytes(32);
  const pkIdP = eddsa.prv2pub(skIdP);
  const sk_i = webcrypto.getRandomValues(new Uint8Array(32));
  const pk_i = BigInt('0x' + keccak256('0x' + Buffer.from(secp256k1.getPublicKey(sk_i, false).slice(1)).toString('hex')).slice(-40));

  const rp_nonce = 424242n, uid = 111111n, rid = 222222n, salt = 333333n;
  const max_height = 1000n, chain_id = 31337n;
  const PPID = pos([uid, rid, salt]);
  const auid = pos([uid, salt]);
  const r_token = pos([pk_i, max_height, rp_nonce]);
  const arid_i = (rid * rp_nonce) % FIELD_PRIME;
  const auid_i = (PPID * rp_nonce) % FIELD_PRIME;
  const DOMAIN = BigInt('0x' + Buffer.from('IDP_TOKEN').toString('hex')) % FIELD_PRIME;
  const sig = eddsa.signPoseidon(skIdP, poseidon([DOMAIN, arid_i, auid_i, r_token, max_height, chain_id]));

  const sessLeaf = await leafValue(TAG_SESSION, r_token);
  const acctLeaf = await leafValue(TAG_ACCOUNT, auid);
  const sess = await createSessionForest();
  const acct = await createAccountForest();
  const sw = await sess.getNonMembershipWitness(sessLeaf, { maxHeight: max_height });
  const aw = await acct.getNonMembershipWitness(acctLeaf);

  return {
    rp_nonce: rp_nonce.toString(), arid_i: arid_i.toString(), auid_i: auid_i.toString(),
    r_token: r_token.toString(), chain_id: chain_id.toString(),
    S: sig.S.toString(), R8x: F.toObject(sig.R8[0]).toString(), R8y: F.toObject(sig.R8[1]).toString(),
    uid: uid.toString(), rid: rid.toString(), salt: salt.toString(),
    sess_lowValue: sw.lowValue, sess_lowNextIndex: sw.lowNextIndex, sess_lowNextValue: sw.lowNextValue,
    sess_pathElements: sw.pathElements, sess_pathIndices: sw.pathIndices,
    acct_lowValue: aw.lowValue, acct_lowNextIndex: aw.lowNextIndex, acct_lowNextValue: aw.lowNextValue,
    acct_pathElements: aw.pathElements, acct_pathIndices: aw.pathIndices,
    pk_i: pk_i.toString(), pk_IdP_x: F.toObject(pkIdP[0]).toString(), pk_IdP_y: F.toObject(pkIdP[1]).toString(),
    PPID: PPID.toString(), max_height: max_height.toString(),
    sess_root: sw.root, sess_shard_low: String(sessionShardLowOf(sessLeaf)),
    acct_root: aw.root, acct_shard: String(accountShardOf(acctLeaf)),
  };
}

const input = await buildInput();
const rows = [];
console.log(`pi_pk_i_v3 증명 생성 ${RUNS}회 측정 (wasm=${WASM})`);
for (let i = 1; i <= RUNS; i++) {
  const t0 = process.hrtime.bigint();
  const { proof } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  rows.push({ run: i, ms, bytes: JSON.stringify(proof).length });
  console.log(`  run ${i}: ${ms.toFixed(1)} ms`);
}
// 1회차는 WASM 초기화·JIT 웜업이 섞여 있어 따로 본다(v2 벤치와 같은 규칙).
const warm = rows.slice(1).map((r) => r.ms);
const mean = warm.reduce((a, b) => a + b, 0) / warm.length;
const sd = Math.sqrt(warm.reduce((a, b) => a + (b - mean) ** 2, 0) / warm.length);
console.log(`\ncold(1회차): ${rows[0].ms.toFixed(1)} ms`);
console.log(`warm 평균: ${mean.toFixed(1)} ms (±${sd.toFixed(1)}, n=${warm.length})`);

const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
const out = `results/mode2_pi_pk_i_v3_proof_${stamp}.csv`;
fs.writeFileSync(out, 'circuit,run,duration_ms,proof_json_bytes\n' +
  rows.map((r) => `pi_pk_i_v3,${r.run},${r.ms.toFixed(1)},${r.bytes}`).join('\n') + '\n');
console.log(`\nwrote ${out}`);

// snarkjs가 워커 스레드를 남겨 프로세스가 안 끝나는 경우가 있어 명시적으로 종료한다.
process.exit(0);
