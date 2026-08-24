import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { randomBytes } from 'crypto';
import fs from 'fs';
import { createIMT, leafValue, TAG_SESSION, TAG_ACCOUNT } from '../lib/imt.js';

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function main() {
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = eddsa.F;
  const pos = (arr) => poseidon.F.toObject(poseidon(arr));

  const sk = randomBytes(32);
  const pk = eddsa.prv2pub(sk);

  const uid = 12345n, rid = 999n, salt = 777n;
  const rp_nonce = 31337n, pk_i = 4242n, max_height = 1000n, chain_id = 1337n;

  const PPID = pos([uid, rid, salt]);
  const auid = pos([uid, salt]);
  const arid_i = (rid * rp_nonce) % P;
  const auid_i = (PPID * rp_nonce) % P;
  const r_token = pos([pk_i, max_height, rp_nonce]);

  const DOMAIN = 1351534856589225444686n;
  const sig = eddsa.signPoseidon(sk, poseidon([DOMAIN, arid_i, auid_i, r_token, max_height, chain_id]));

  // 폐기 트리: 무관한 항목 하나만 넣어 둔다
  const tree = await createIMT(20);
  await tree.insert(await leafValue(TAG_ACCOUNT, 555n));

  const sessTarget = await leafValue(TAG_SESSION, r_token);
  const acctTarget = await leafValue(TAG_ACCOUNT, auid);
  const sw = await tree.getNonMembershipWitness(sessTarget);
  const aw = await tree.getNonMembershipWitness(acctTarget);

  const input = {
    rp_nonce: rp_nonce.toString(), arid_i: arid_i.toString(), auid_i: auid_i.toString(),
    r_token: r_token.toString(), chain_id: chain_id.toString(),
    S: sig.S.toString(),
    R8x: F.toObject(sig.R8[0]).toString(), R8y: F.toObject(sig.R8[1]).toString(),
    uid: uid.toString(), rid: rid.toString(), salt: salt.toString(),
    sess_lowValue: sw.lowValue, sess_lowNextValue: sw.lowNextValue,
    sess_pathElements: sw.pathElements, sess_pathIndices: sw.pathIndices,
    acct_lowValue: aw.lowValue, acct_lowNextValue: aw.lowNextValue,
    acct_pathElements: aw.pathElements, acct_pathIndices: aw.pathIndices,
    pk_i: pk_i.toString(), pk_IdP_x: F.toObject(pk[0]).toString(), pk_IdP_y: F.toObject(pk[1]).toString(),
    PPID: PPID.toString(), max_height: max_height.toString(), revocationRoot: sw.root,
  };

  const wc = await import('../build/mode2/pi_pk_i_js/witness_calculator.cjs');
  const wasmBuffer = fs.readFileSync('build/mode2/pi_pk_i_js/pi_pk_i.wasm');
  const calc = await wc.default(wasmBuffer);

  await calc.calculateWitness(input, true);
  console.log('OK: unrevoked session and account produce a valid witness');

  // PPID를 다른 값으로 바꾸면 바인딩 제약에 걸려야 한다
  let rejected = false;
  try {
    await calc.calculateWitness({ ...input, PPID: (PPID + 1n).toString() }, true);
  } catch { rejected = true; }
  if (!rejected) { console.error('FAIL: mismatched PPID was accepted'); process.exit(1); }
  console.log('OK: PPID not derived from uid/rid/salt is rejected');

  // 이 계정을 실제로 폐기하면 witness 자체를 만들 수 없어야 한다
  await tree.insert(acctTarget);
  let witnessRefused = false;
  try {
    await tree.getNonMembershipWitness(acctTarget);
  } catch (e) {
    witnessRefused = /is a member/.test(e.message);
  }
  if (!witnessRefused) { console.error('FAIL: revoked account still produced a witness'); process.exit(1); }
  console.log('OK: revoked account cannot obtain a non-membership witness');

  // 이 세션을 실제로 폐기하면 witness 자체를 만들 수 없어야 한다
  await tree.insert(sessTarget);
  let sessionWitnessRefused = false;
  try {
    await tree.getNonMembershipWitness(sessTarget);
  } catch (e) {
    sessionWitnessRefused = /is a member/.test(e.message);
  }
  if (!sessionWitnessRefused) { console.error('FAIL: revoked session still produced a witness'); process.exit(1); }
  console.log('OK: revoked session cannot obtain a non-membership witness');

  console.log('PASS: pi_pk_i enforces account binding and revocation non-membership.');
}

main();
