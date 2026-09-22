// 저장소의 ZKP 전체 목록 실측 — Mode 2 v4 삽입 전이 회로, (레거시) pi_uid, Mode 3 π_u(시그마, 사용자 자격증명)·pi_cred(Groth16 V5).
// 2026-09-21 부터 세션 발급(/cia/issue)에는 ZKP 가 없다 — π_u 는 사용자 자격증명 발급(/cia/user_cred) 때만 한 번.
//   node scripts/bench_zkp_inventory.mjs [N]        (기본 N=10; build/ 는 읽기만 한다)
//
// Mode 2 의 pi_ppid·pi_arid_i·pi_pk_i(v3) 는 scripts/bench_mode2_zkp_all.mjs 가 잰다(같은 크레덴셜을 세 회로에 먹여야
// per-run 합이 의미가 있어서 거기 둔다). Mode 1 bind_key_to_idtoken 은 실제 Google ID 토큰이 있어야 증명이 되므로
// 여기서는 제약 수만 보고한다(r1cs info).
//
// Groth16 은 witness 생성(WASM)과 증명(zkey MSM)을 나눠 재고, 검증 시간·증명 JSON 크기·vkey 크기도 함께 낸다.
// 첫 회는 WASM 초기화가 섞이므로 중앙값을 쓰고, 최소–최대를 같이 적는다.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import { createSessionForest, createAccountForest, leafValue, TAG_SESSION, TAG_ACCOUNT } from '../lib/imt_v3.js';
import { buildInsertInput, circuitFor } from '../lib/transition_proof.js';
import { randomScalar } from '../lib/mode3_credential.js';
import { registrationCommit, proveUserCred, verifyUserCred, serializeUserCredProof } from '../lib/mode3_issuance.js';
import { buildValidInput } from '../tests/helpers/mode3_fixture.mjs';

const N = Number(process.argv[2] || 10);
const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
const fmt = (a) => `${med(a).toFixed(1)} (${Math.min(...a).toFixed(1)}–${Math.max(...a).toFixed(1)})`;
const now = () => Number(process.hrtime.bigint()) / 1e6;

/** Groth16 한 회로: witness → prove → verify 를 N회. */
async function benchGroth16(name, input, wasm, zkey, vkeyPath) {
  const vkey = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
  const W = [], P = [], V = [];
  let proof, publicSignals, wtnsBytes = 0;
  const wtnsPath = path.join(os.tmpdir(), `zkp_inventory_${process.pid}_${name}.wtns`);
  for (let i = 0; i < N; i++) {
    const t0 = now();
    await snarkjs.wtns.calculate(input, wasm, wtnsPath);
    const t1 = now();
    ({ proof, publicSignals } = await snarkjs.groth16.prove(zkey, wtnsPath));
    const t2 = now();
    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    const t3 = now();
    if (!ok) throw new Error(`${name}: 검증 실패`);
    W.push(t1 - t0); P.push(t2 - t1); V.push(t3 - t2);
  }
  wtnsBytes = fs.statSync(wtnsPath).size; fs.unlinkSync(wtnsPath);
  return {
    name, witnessMs: fmt(W), proveMs: fmt(P), fullMs: fmt(W.map((w, i) => w + P[i])), verifyMs: fmt(V),
    proofBytes: JSON.stringify(proof).length, publics: publicSignals.length,
    zkeyBytes: fs.statSync(zkey).size, vkeyBytes: fs.statSync(vkeyPath).size, wasmBytes: fs.statSync(wasm).size, wtnsBytes,
  };
}

const rows = [];

// ---- Mode 3 π_u: 사용자 자격증명 시그마 프로토콜(회로·셋업 없음). 공개 (uid, C_u_pt, cm_u) ----
{
  const uid = 12345n, s_u = randomScalar(), r_u = randomScalar();
  const attrs = [1990n, 410n, 2n, 0n];   // 데모 testuser 와 같은 값(스펙 2026-09-22 §3.1)
  const cm_u = await registrationCommit(s_u, r_u);
  const P = [], V = []; let out;
  for (let i = 0; i < N; i++) {
    const blind_u = randomScalar();
    const t0 = now();
    out = await proveUserCred({ uid, s_u, blind_u, r_u, attrs });
    const t1 = now();
    const ok = await verifyUserCred({ uid, attrs, C_u_pt: out.C_u_pt, cm_u, proof: out.proof });
    const t2 = now();
    if (!ok) throw new Error('π_u 검증 실패');
    P.push(t1 - t0); V.push(t2 - t1);
  }
  rows.push({ name: 'π_u V2 (Σ, Mode 3 사용자 자격증명, 속성 공개)', witnessMs: '-', proveMs: fmt(P), fullMs: fmt(P), verifyMs: fmt(V),
    proofBytes: JSON.stringify(serializeUserCredProof(out.proof)).length, publics: 7, zkeyBytes: 0, vkeyBytes: 0, wasmBytes: 0, wtnsBytes: 0 });
}

// ---- Mode 3 pi_cred (Groth16, V6 — 선택 공개, disc_mask=0) ----
{
  const { input } = await buildValidInput();
  rows.push(await benchGroth16('pi_cred (Mode 3 V6)', input, 'build/mode3/pi_cred_js/pi_cred.wasm', 'build/mode3/pi_cred_final.zkey', 'build/mode3/pi_cred_vkey.json'));
}

// ---- Mode 2 v4 삽입 전이: 세션 층(깊이 8, K=4) / 계정 층(깊이 10, K=4) — 배치 1건과 4건 ----
{
  const sess = await createSessionForest();
  const acct = await createAccountForest();
  const mk = async (forest, tag, k, meta) => {
    const ts = [];
    let shard = null;
    while (ts.length < k) {   // 같은 샤드로 떨어지는 리프만 모아 root 사슬을 잇는다
      const leaf = (await leafValue(tag, randomScalar())).toString();
      const r = await forest.insertWithTranscript(leaf, meta);
      if (r === null) continue;
      if (shard === null) shard = r.shard;
      if (r.shard === shard) ts.push(r.transcript);
    }
    return ts;
  };
  for (const [layer, forest, tag, meta] of [['session', sess, TAG_SESSION, { maxHeight: 1000n }], ['account', acct, TAG_ACCOUNT, undefined]]) {
    const c = circuitFor(layer);
    for (const k of [1, 4]) {
      const ts = await mk(forest, tag, k, meta);
      const input = buildInsertInput(ts, c.depth);
      rows.push(await benchGroth16(`${layer === 'session' ? 'pi_ins_sess' : 'pi_ins_acct'} (Mode 2 v4, ${k}건)`, input, c.wasm, c.zkey, c.vkey));
    }
  }
}

// ---- Mode 2 pi_uid (레거시 — 현재 흐름에서 안 쓰임) ----
{
  const poseidon = await buildPoseidon();
  const uid = 12345n, secret = randomScalar();
  const commitment = poseidon.F.toObject(poseidon([uid, secret])).toString();
  rows.push(await benchGroth16('pi_uid (Mode 2, 레거시)', { uid: uid.toString(), secret: secret.toString(), commitment },
    'build/mode2/pi_uid_js/pi_uid.wasm', 'build/mode2/pi_uid_final.zkey', 'build/mode2/pi_uid_vkey.json'));
}

console.log(`\n## ZKP 실측 (N=${N}, ms 중앙값 (최소–최대), AMD Ryzen 9 5950X, Node ${process.version}, snarkjs)\n`);
console.log('| 증명 | witness | prove | witness+prove | verify | 증명 크기(JSON B) | 공개 입력 | zkey(B) | vkey(B) | wasm(B) |');
console.log('|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|');
for (const r of rows) console.log(`| ${r.name} | ${r.witnessMs} | ${r.proveMs} | ${r.fullMs} | ${r.verifyMs} | ${r.proofBytes} | ${r.publics} | ${r.zkeyBytes || '-'} | ${r.vkeyBytes || '-'} | ${r.wasmBytes || '-'} |`);
process.exit(0);
