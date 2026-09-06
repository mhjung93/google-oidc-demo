// 실제 zkey로 만든 진짜 증명이 온체인 v3 경로를 통과하는지 본다 (E단계 왕복 검증).
//   npx hardhat test test/PPIDWalletV3Proof.test.mjs
//
// test/PPIDWalletV3.test.mjs가 mock verifier로 "컨트랙트가 책임지는 부분"만 봤다면,
// 여기는 회로-zkey-verifier-컨트랙트를 한 줄로 꿴다. 산출물은 build/mode2_v3/ 이고
// 기존 build/mode2/ 와 배포된 컨트랙트는 건드리지 않는다.
import hre from "hardhat";
import { expect } from "chai";
import { randomBytes, webcrypto } from "crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256, concat, getBytes } from "ethers";
import { buildEddsa, buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";
import {
  createSessionForest, createAccountForest, computeTopPath, combineTopRoots,
  rootToBytes32, sessionShardOf, sessionShardLowOf, accountShardOf,
  leafValue, TAG_SESSION, TAG_ACCOUNT,
} from "../lib/imt_v3.js";

const WASM = "build/mode2_v3/pi_pk_i_v3_js/pi_pk_i_v3.wasm";
const ZKEY = "build/mode2_v3/pi_pk_i_v3_final.zkey";
const VKEY = "build/mode2_v3/pi_pk_i_v3_vkey.json";
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const GRACE = 3;
const V3_VERIFIER = "contracts/PiPkIV3Verifier.sol:Groth16Verifier";

describe("PPIDWalletV3 — 진짜 증명 왕복", function () {
  this.timeout(600000);

  it("회로 -> zkey -> verifier -> execute 가 한 줄로 통과하고, 타인 폐기에 증명이 살아남는다", async function () {
    const [deployer] = await hre.ethers.getSigners();
    const eddsa = await buildEddsa();
    const poseidon = await buildPoseidon();
    const F = eddsa.F;
    const pos = (a) => poseidon.F.toObject(poseidon(a));

    const skIdP = randomBytes(32);
    const pkIdP = eddsa.prv2pub(skIdP);
    const pk_IdP_x = F.toObject(pkIdP[0]);
    const pk_IdP_y = F.toObject(pkIdP[1]);

    const sk_i = webcrypto.getRandomValues(new Uint8Array(32));
    const pub65 = secp256k1.getPublicKey(sk_i, false);
    const pk_i = BigInt("0x" + keccak256("0x" + Buffer.from(pub65.slice(1)).toString("hex")).slice(-40));

    const rp_nonce = 424242n, uid = 111111n, rid = 222222n, salt = 333333n;
    const chain_id = (await hre.ethers.provider.getNetwork()).chainId;
    const maxHeight = BigInt(await hre.ethers.provider.getBlockNumber()) + 500n;

    const PPID = pos([uid, rid, salt]);
    const auid = pos([uid, salt]);
    const r_token = pos([pk_i, maxHeight, rp_nonce]);
    const arid_i = (rid * rp_nonce) % FIELD_PRIME;
    const auid_i = (PPID * rp_nonce) % FIELD_PRIME;
    const DOMAIN = BigInt("0x" + Buffer.from("IDP_TOKEN").toString("hex")) % FIELD_PRIME;
    const sig = eddsa.signPoseidon(skIdP, poseidon([DOMAIN, arid_i, auid_i, r_token, maxHeight, chain_id]));

    const sessLeaf = await leafValue(TAG_SESSION, r_token);
    const acctLeaf = await leafValue(TAG_ACCOUNT, auid);
    const sessShard = sessionShardOf(sessLeaf, maxHeight);
    const acctShard = accountShardOf(acctLeaf);

    const sess = await createSessionForest();
    const acct = await createAccountForest();

    async function witness() {
      const sw = await sess.getNonMembershipWitness(sessLeaf, { maxHeight });
      const aw = await acct.getNonMembershipWitness(acctLeaf);
      return { sw, aw };
    }
    const { sw, aw } = await witness();

    const input = {
      rp_nonce: rp_nonce.toString(), arid_i: arid_i.toString(), auid_i: auid_i.toString(),
      r_token: r_token.toString(), chain_id: chain_id.toString(),
      S: sig.S.toString(), R8x: F.toObject(sig.R8[0]).toString(), R8y: F.toObject(sig.R8[1]).toString(),
      uid: uid.toString(), rid: rid.toString(), salt: salt.toString(),
      sess_lowValue: sw.lowValue, sess_lowNextIndex: sw.lowNextIndex, sess_lowNextValue: sw.lowNextValue,
      sess_pathElements: sw.pathElements, sess_pathIndices: sw.pathIndices,
      acct_lowValue: aw.lowValue, acct_lowNextIndex: aw.lowNextIndex, acct_lowNextValue: aw.lowNextValue,
      acct_pathElements: aw.pathElements, acct_pathIndices: aw.pathIndices,
      pk_i: pk_i.toString(), pk_IdP_x: pk_IdP_x.toString(), pk_IdP_y: pk_IdP_y.toString(),
      PPID: PPID.toString(), max_height: maxHeight.toString(),
      sess_root: sw.root, sess_shard_low: String(sessionShardLowOf(sessLeaf)),
      acct_root: aw.root, acct_shard: String(acctShard),
    };

    const t0 = Date.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const proveMs = Date.now() - t0;
    const vkey = JSON.parse((await import("fs")).readFileSync(VKEY, "utf8"));
    expect(await snarkjs.groth16.verify(vkey, publicSignals, proof)).to.equal(true);
    console.log(`      증명 생성 ${proveMs} ms, public signals ${publicSignals.length}개`);

    // public signal 순서가 회로 선언과 같은지 확인한다
    expect(publicSignals[0]).to.equal(pk_i.toString());
    expect(publicSignals[4]).to.equal(maxHeight.toString());
    expect(publicSignals[6]).to.equal(String(sessionShardLowOf(sessLeaf)));
    expect(publicSignals[8]).to.equal(String(acctShard));

    const pA = [proof.pi_a[0], proof.pi_a[1]];
    const pB = [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]];
    const pC = [proof.pi_c[0], proof.pi_c[1]];

    // ── 온체인 ────────────────────────────────────────────────────────────
    const verifier = await (await hre.ethers.getContractFactory(V3_VERIFIER)).deploy();
    expect(await verifier.verifyProof(pA, pB, pC, publicSignals)).to.equal(true);

    const registry = await (await hre.ethers.getContractFactory("RevocationRegistryV3"))
      .deploy(deployer.address, GRACE);
    const factory = await (await hre.ethers.getContractFactory("PPIDWalletFactoryV3"))
      .deploy(verifier.target, pk_IdP_x, pk_IdP_y, registry.target);
    await (await factory.deploy(PPID)).wait();
    const wallet = await hre.ethers.getContractAt("PPIDWalletV3", await factory.computeAddress(PPID));

    function buildRev() {
      return {
        sessRoot: rootToBytes32(sess.getSubtreeRoot(sessShard)),
        sessShardLow: sessionShardLowOf(sessLeaf),
        sessSiblings: computeTopPath(sess.getSubtreeRoots(), sessShard),
        acctRoot: rootToBytes32(acct.getSubtreeRoot(acctShard)),
        acctShard,
        acctSiblings: computeTopPath(acct.getSubtreeRoots(), acctShard),
      };
    }
    const publish = async () =>
      (await registry.pushRoot(combineTopRoots(sess.getTopRoot(), acct.getTopRoot()))).wait();

    async function exec(rev) {
      const payload = { to: deployer.address, value: 0n, data: "0x", nonce: await wallet.nonce() };
      const hash = getBytes(hre.ethers.keccak256(hre.ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "address", "address", "uint256", "bytes", "uint256"],
        [chain_id, wallet.target, payload.to, payload.value, payload.data, payload.nonce])));
      const s = secp256k1.sign(hash, sk_i);
      const sigBytes = concat([
        "0x" + s.r.toString(16).padStart(64, "0"),
        "0x" + s.s.toString(16).padStart(64, "0"),
        "0x" + (27 + s.recovery).toString(16).padStart(2, "0"),
      ]);
      return wallet.execute(payload, sigBytes, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, rev);
    }

    await publish();
    const rc = await (await exec(buildRev())).wait();
    expect(await wallet.nonce()).to.equal(1n);
    console.log(`      execute 가스 ${rc.gasUsed} (첫 호출, nonce 0->1 cold SSTORE 포함)`);

    // ── Case 2 — 타인 폐기. 증명은 그대로, 상위 형제만 갱신한다 ────────────
    const before = buildRev();
    await acct.insert(await leafValue(TAG_ACCOUNT, 987654321987n));
    await sess.insert(await leafValue(TAG_SESSION, 555000111n), { maxHeight: maxHeight + 7n });
    await publish();
    const after = buildRev();

    expect(after.sessRoot).to.equal(before.sessRoot);
    expect(after.acctRoot).to.equal(before.acctRoot);
    // 같은 증명(pA/pB/pC)을 그대로 재사용한다 — 재생성이 없다는 것이 이 설계의 목적이다
    await expect(exec(after)).to.emit(wallet, "Executed");
    expect(await wallet.nonce()).to.equal(2n);
    console.log("      Case 2: 증명 재생성 없이 두 번째 execute 통과");
  });
});
