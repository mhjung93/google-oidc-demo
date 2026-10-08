// Mode 2의 세 회로를 **한 번에** 돌려 per-run 합까지 내는 벤치.
//   node scripts/bench_mode2_zkp_all.mjs [runs]      (기본 10회)
//
// 왜 필요한가. 논문 초안은 "세 회로 지속시간을 run별로 더한 값"의 평균·중앙값·범위를
// 보고했는데(final46: 525.50 ms, median 472, range 423-755), 그 수치는 회로마다 따로
// 돌린 CSV에서 나온 것이 아니라 **한 실행 안에서 세 회로를 순차로 돌린 run**에서만
// 나올 수 있다. pi_pk_i가 폐기 이중 트리 판으로 바뀌면서(4,820 -> 13,905 constraints)
// 그 수치가 낡았고, 회로별 평균만으로는 run 수준 분포를 복원할 수 없다.
// 이 스크립트가 그 분포를 다시 만든다.
//
// 세 회로에 **같은 크레덴셜**을 먹인다. 실제 로그인 한 번이 만드는 증명 셋과 같은
// 구성이어야 합이 의미를 갖기 때문이다.
//   pi_ppid   — PPID = Poseidon(uid, rid, salt)
//   pi_arid_i — 발급 단계. RP_REG 크레덴셜(EdDSA-Poseidon) 검증 + arid_i/auid_i/token_nonce/auid
//   pi_pk_i   — 온체인 제출 단계(v3 이중 트리). 위의 IdP 토큰 서명 + 폐기 비멤버십 2건
//
// 산출물은 results/mode2_zkp_all_<날짜>.csv. build/는 읽기만 한다.
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
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const CIRCUITS = [
  { name: 'pi_ppid', wasm: 'build/mode2/pi_ppid_js/pi_ppid.wasm', zkey: 'build/mode2/pi_ppid_final.zkey' },
  { name: 'pi_arid_i', wasm: 'build/mode2/pi_arid_i_js/pi_arid_i.wasm', zkey: 'build/mode2/pi_arid_i_final.zkey' },
  { name: 'pi_pk_i', wasm: 'build/mode2_v3/pi_pk_i_v3_js/pi_pk_i_v3.wasm', zkey: 'build/mode2_v3/pi_pk_i_v3_final.zkey' },
];

/** wallet_agent.js / custom_idp.js의 valueToField와 같은 규칙. */
function valueToField(value) {
  if (typeof value === 'bigint') return value % FIELD_PRIME;
  const str = String(value);
  if (/^[0-9]+$/.test(str)) return BigInt(str) % FIELD_PRIME;
  const hex = Buffer.from(str, 'utf8').toString('hex');
  return BigInt(`0x${hex || '0'}`) % FIELD_PRIME;
}

async function buildInputs() {
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = eddsa.F;
  const pos = (a) => poseidon.F.toObject(poseidon(a));

  // IdP 키 (RP_REG 크레덴셜과 IdP 토큰 둘 다 이 키로 서명한다 — 실제 흐름과 같다)
  const skIdP = randomBytes(32);
  const pkIdP = eddsa.prv2pub(skIdP);
  const pk_IdP_x = F.toObject(pkIdP[0]);
  const pk_IdP_y = F.toObject(pkIdP[1]);

  const sk_i = webcrypto.getRandomValues(new Uint8Array(32));
  const pub65 = secp256k1.getPublicKey(sk_i, false);
  const pk_i = BigInt('0x' + keccak256('0x' + Buffer.from(pub65.slice(1)).toString('hex')).slice(-40));

  const uid = 12345n;
  const rid = valueToField('demo-rid-0001');
  const salt = valueToField('demo-salt-0001');
  const rp_nonce = valueToField('demo-rp-nonce-0001');
  const origin = valueToField('http://127.0.0.1:3000');
  const max_height = 1000n;
  const chain_id = 31337n;

  const PPID = pos([uid, rid, salt]);
  const auid = pos([uid, salt]);
  const arid_i = (rid * rp_nonce) % FIELD_PRIME;
  const auid_i = (PPID * rp_nonce) % FIELD_PRIME;
  const r_token = pos([pk_i, max_height, rp_nonce]);

  // RP 등록 크레덴셜 (pi_arid_i가 회로 안에서 검증한다)
  const DOMAIN_RP_REG = valueToField('RP_REG');
  const rpRegSig = eddsa.signPoseidon(skIdP, poseidon([DOMAIN_RP_REG, rid, origin]));

  // IdP 토큰 (pi_pk_i가 회로 안에서 검증한다)
  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const tokenSig = eddsa.signPoseidon(
    skIdP, poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id]),
  );

  // 폐기 witness (빈 포레스트 — anchor가 모든 값을 덮으므로 벤치에 충분하다)
  const sessLeaf = await leafValue(TAG_SESSION, r_token);
  const acctLeaf = await leafValue(TAG_ACCOUNT, auid);
  const sess = await createSessionForest();
  const acct = await createAccountForest();
  const sw = await sess.getNonMembershipWitness(sessLeaf, { maxHeight: max_height });
  const aw = await acct.getNonMembershipWitness(acctLeaf);

  return {
    pi_ppid: {
      uid: uid.toString(), salt: salt.toString(),
      rid: rid.toString(), ppid: PPID.toString(),
    },
    pi_arid_i: {
      rp_nonce: rp_nonce.toString(), salt: salt.toString(), rid: rid.toString(),
      pk_i: pk_i.toString(), origin: origin.toString(),
      rp_reg_S: rpRegSig.S.toString(),
      rp_reg_R8x: F.toObject(rpRegSig.R8[0]).toString(),
      rp_reg_R8y: F.toObject(rpRegSig.R8[1]).toString(),
      uid: uid.toString(), arid_i: arid_i.toString(), auid_i: auid_i.toString(),
      max_height: max_height.toString(), token_nonce: r_token.toString(), auid: auid.toString(),
      pk_IdP_x: pk_IdP_x.toString(), pk_IdP_y: pk_IdP_y.toString(),
    },
    pi_pk_i: {
      rp_nonce: rp_nonce.toString(), arid_i: arid_i.toString(), auid_i: auid_i.toString(),
      r_token: r_token.toString(), chain_id: chain_id.toString(),
      S: tokenSig.S.toString(),
      R8x: F.toObject(tokenSig.R8[0]).toString(), R8y: F.toObject(tokenSig.R8[1]).toString(),
      uid: uid.toString(), rid: rid.toString(), salt: salt.toString(),
      sess_lowValue: sw.lowValue, sess_lowNextIndex: sw.lowNextIndex, sess_lowNextValue: sw.lowNextValue,
      sess_pathElements: sw.pathElements, sess_pathIndices: sw.pathIndices,
      acct_lowValue: aw.lowValue, acct_lowNextIndex: aw.lowNextIndex, acct_lowNextValue: aw.lowNextValue,
      acct_pathElements: aw.pathElements, acct_pathIndices: aw.pathIndices,
      pk_i: pk_i.toString(), pk_IdP_x: pk_IdP_x.toString(), pk_IdP_y: pk_IdP_y.toString(),
      PPID: PPID.toString(), max_height: max_height.toString(),
      sess_root: sw.root, sess_shard_low: String(sessionShardLowOf(sessLeaf)),
      acct_root: aw.root, acct_shard: String(accountShardOf(acctLeaf)),
    },
  };
}

function stats(xs) {
  const sorted = [...xs].sort((a, b) => a - b);
  const mean = xs.reduce((a, b) => a + b, 0) / xs.length;
  const sd = Math.sqrt(xs.reduce((a, b) => a + (b - mean) ** 2, 0) / xs.length);
  const mid = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
  return { mean, sd, median, min: sorted[0], max: sorted[sorted.length - 1] };
}
const f1 = (x) => x.toFixed(1);

const inputs = await buildInputs();
const rows = [];
const perRunSum = [];
const vkeys = Object.fromEntries(CIRCUITS.map((c) => [c.name, JSON.parse(fs.readFileSync(c.zkey.replace(/_final\.zkey$/, '_vkey.json'), 'utf8'))]));

console.log(`Mode 2 세 회로 ${RUNS}회 측정 (같은 크레덴셜, run마다 순차 실행)`);
for (let run = 1; run <= RUNS; run++) {
  let sum = 0;
  const parts = [];
  for (const c of CIRCUITS) {
    const t0 = process.hrtime.bigint();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs[c.name], c.wasm, c.zkey);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    // 검증 시간도 같이 잰다(2026-09-18 추가 — 열만 늘고 기존 열은 그대로).
    const v0 = process.hrtime.bigint();
    const ok = await snarkjs.groth16.verify(vkeys[c.name], publicSignals, proof);
    const verifyMs = Number(process.hrtime.bigint() - v0) / 1e6;
    if (!ok) throw new Error(`${c.name}: 검증 실패`);
    rows.push({ circuit: c.name, run, ms, verifyMs, bytes: JSON.stringify(proof).length, publics: publicSignals.length });
    parts.push(`${c.name} ${f1(ms)}`);
    sum += ms;
  }
  perRunSum.push({ run, ms: sum });
  console.log(`  run ${run}: ${parts.join(' | ')} => 합 ${f1(sum)} ms`);
}

// 1회차는 WASM 초기화·JIT 웜업이 섞여 있어 따로 본다(기존 벤치들과 같은 규칙).
console.log('\n=== warm (1회차 제외) ===');
for (const c of CIRCUITS) {
  const s = stats(rows.filter((r) => r.circuit === c.name && r.run > 1).map((r) => r.ms));
  const v = stats(rows.filter((r) => r.circuit === c.name && r.run > 1).map((r) => r.verifyMs));
  const r0 = rows.find((r) => r.circuit === c.name);
  console.log(`  ${c.name.padEnd(10)} 평균 ${f1(s.mean)} ms (SD ${f1(s.sd)}), 중앙값 ${f1(s.median)}, 범위 ${f1(s.min)}-${f1(s.max)} | verify 중앙값 ${f1(v.median)} ms | 증명 ${r0.bytes} B, 공개 입력 ${r0.publics}`);
}
const S = stats(perRunSum.filter((r) => r.run > 1).map((r) => r.ms));
console.log(`  ${'per-run 합'.padEnd(10)} 평균 ${f1(S.mean)} ms (SD ${f1(S.sd)}), 중앙값 ${f1(S.median)}, 범위 ${f1(S.min)}-${f1(S.max)}`);
console.log(`\ncold(1회차) 합: ${f1(perRunSum[0].ms)} ms`);

const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
const out = `results/mode2_zkp_all_${stamp}.csv`;
fs.writeFileSync(
  out,
  '# Mode 2 세 회로를 한 실행 안에서 순차로 돌린 결과. pi_pk_i는 폐기 이중 트리(v3) 판이다.\n' +
    '# per-run 합은 run별로 세 회로 시간을 더한 값이다(회로별 평균의 합이 아니다).\n' +
    'circuit,run,duration_ms,proof_json_bytes,verify_ms,public_inputs\n' +
    rows.map((r) => `${r.circuit},${r.run},${f1(r.ms)},${r.bytes},${f1(r.verifyMs)},${r.publics}`).join('\n') + '\n' +
    perRunSum.map((r) => `sum_of_three,${r.run},${f1(r.ms)},,,`).join('\n') + '\n',
);
console.log(`\nwrote ${out}`);

// snarkjs가 워커 스레드를 남겨 프로세스가 안 끝나는 경우가 있어 명시적으로 종료한다.
process.exit(0);
