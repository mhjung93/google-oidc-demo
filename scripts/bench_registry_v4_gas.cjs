// RevocationRegistryV4의 게시 가스 실측 (설계 문서 13.2절).
//   npx hardhat run scripts/bench_registry_v4_gas.cjs --network localhost
//
// 무엇을 재는가. 13.2절은 전이 증명의 비용을 "배치당 Groth16 1회, 약 25만 gas"로
// **추정**해 두었다. 실제로 재서 그 추정을 대체한다. 함께 재는 것:
//   - V3의 pushRoot(bytes32) — 검증이 전혀 없던 기준선
//   - V4의 pushUpdates([Insert])  — 증명 1건 + 상위 경로 접기
//   - V4의 pushUpdates([Insert x2]) — 증명이 선형으로 붙는지 확인
//   - V4의 pushUpdates([SessionReset]) — 증명이 없는 전이(컨트랙트가 스스로 검증)
//
// 마지막 항목이 설계의 요점이다: 세션 층 회수는 링 주기(512)가 크레덴셜 최대 수명(332)보다
// 크다는 사실만으로 검증되므로 증명이 붙지 않는다.
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

const MAX_CREDENTIAL_SPAN = 332;
const GRACE_BLOCKS = 3;
const KIND_INSERT = 0;
const KIND_SESSION_RESET = 1;
const NO_PROOF = { a: [0, 0], b: [[0, 0], [0, 0]], c: [0, 0] };

function assertPersistentNetwork() {
  if (hre.network.name === "hardhat") {
    throw new Error(
      "--network localhost 없이 실행되었습니다. 임시 인프로세스 체인에서는 측정이 사라집니다:\n" +
      "  npx hardhat run scripts/bench_registry_v4_gas.cjs --network localhost"
    );
  }
}

async function main() {
  assertPersistentNetwork();
  const v3 = await import("../lib/imt_v3.js");
  const { proveInsertTransition } = await import("../lib/transition_proof.js");
  const {
    createSessionForest, createAccountForest, rootToBytes32,
    leafValue, TAG_SESSION, TAG_ACCOUNT, SESSION_RING,
  } = v3;

  const [idp] = await hre.ethers.getSigners();
  const sess = await createSessionForest();
  const acct = await createAccountForest();

  const SessV = await hre.ethers.getContractFactory("contracts/pi_ins_sess_verifier.sol:Groth16Verifier");
  const sessV = await (await SessV.deploy()).waitForDeployment();
  const AcctV = await hre.ethers.getContractFactory("contracts/pi_ins_acct_verifier.sol:Groth16Verifier");
  const acctV = await (await AcctV.deploy()).waitForDeployment();

  const RegV4 = await hre.ethers.getContractFactory("RevocationRegistryV4");
  const reg = await (await RegV4.deploy(
    idp.address, GRACE_BLOCKS, MAX_CREDENTIAL_SPAN, rootToBytes32(sess.emptyRoot),
    await sessV.getAddress(), await acctV.getAddress(),
    rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()),
  )).waitForDeployment();

  // 기준선: 검증이 전혀 없던 V3.
  const RegV3 = await hre.ethers.getContractFactory("RevocationRegistryV3");
  const reg3 = await (await RegV3.deploy(idp.address, GRACE_BLOCKS)).waitForDeployment();

  const rows = [];
  const gasOf = async (txp) => Number((await (await txp).wait()).gasUsed);

  rows.push({
    what: "V3 pushRoot(bytes32)", gas: await gasOf(reg3.pushRoot(rootToBytes32(12345n))),
    note: "검증 없음 — 기준선",
  });

  async function acctUpdate(raw) {
    const leaf = (await leafValue(TAG_ACCOUNT, raw)).toString();
    const { shard, transcript } = await acct.insertWithTranscript(leaf);
    const proved = await proveInsertTransition("account", [transcript]);
    return {
      kind: KIND_INSERT, account: true, shard,
      oldSubRoot: rootToBytes32(proved.oldRoot),
      newSubRoot: rootToBytes32(proved.newRoot),
      siblings: acct.topPathFor(shard),
      ...proved.calldata,
    };
  }

  const u1 = await acctUpdate(4001n);
  rows.push({
    what: "V4 pushUpdates([Insert])", gas: await gasOf(reg.pushUpdates([u1])),
    note: "Groth16 1회 + 상위 경로(깊이 8) 2회 접기",
  });

  // 서로 다른 샤드 두 건.
  let a = null, b = null;
  for (let i = 0n; i < 60n && (a === null || b === null); i++) {
    const leaf = (await leafValue(TAG_ACCOUNT, 5000n + i)).toString();
    const sh = acct.shardFor(leaf);
    if (a === null) a = { raw: 5000n + i, sh };
    else if (sh !== a.sh) b = { raw: 5000n + i, sh };
  }
  const u2 = await acctUpdate(a.raw);
  const u3 = await acctUpdate(b.raw);
  rows.push({
    what: "V4 pushUpdates([Insert x2])", gas: await gasOf(reg.pushUpdates([u2, u3])),
    note: "증명 2회 — 선형 증가분 확인용",
  });

  // 세션 리셋 — 증명이 없다. 리셋 창이 열릴 때까지 블록을 진행시킨다.
  const sLeaf = (await leafValue(TAG_SESSION, 777n)).toString();
  const maxHeight = 1000n;
  await sess.insert(sLeaf, { maxHeight });
  const sShard = sess.shardFor(sLeaf, { maxHeight });
  // 포레스트가 바뀌었으므로 레지스트리의 세션 top과 어긋난다 — 리셋만 재려는 것이므로
  // 레지스트리를 이 상태로 새로 띄운다.
  const reg2 = await (await RegV4.deploy(
    idp.address, GRACE_BLOCKS, MAX_CREDENTIAL_SPAN, rootToBytes32(sess.emptyRoot),
    await sessV.getAddress(), await acctV.getAddress(),
    rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()),
  )).waitForDeployment();

  // 필요한 블록 수를 한 번에 계산해 한 번에 채굴한다. 한 블록씩 RPC로 돌면
  // 최악 512회 왕복이라 눈에 띄게 느리다.
  const k = BigInt(Math.floor(sShard / 8));
  {
    const B = BigInt(await hre.ethers.provider.getBlockNumber());
    const want = BigInt(MAX_CREDENTIAL_SPAN + 10);       // 목표 d
    const n = ((k - B - want) % SESSION_RING + SESSION_RING) % SESSION_RING;
    if (n > 0n) await hre.network.provider.send("hardhat_mine", ["0x" + n.toString(16)]);
  }
  const reset = {
    kind: KIND_SESSION_RESET, account: false, shard: sShard,
    oldSubRoot: rootToBytes32(sess.getSubtreeRoot(sShard)),
    newSubRoot: rootToBytes32(sess.emptyRoot),
    siblings: sess.topPathFor(sShard),
    ...NO_PROOF,
  };
  rows.push({
    what: "V4 pushUpdates([SessionReset])", gas: await gasOf(reg2.pushUpdates([reset])),
    note: "증명 없음 — block.number만으로 검증(깊이 12 경로)",
  });

  console.log("");
  console.log("## 폐기 root 게시 가스 — V3(검증 없음) vs V4(전이 검증)");
  console.log("");
  console.log("| 조작 | gas | 비고 |");
  console.log("|:--|---:|:--|");
  for (const r of rows) console.log(`| ${r.what} | ${r.gas.toLocaleString()} | ${r.note} |`);
  const base = rows[0].gas;
  const ins1 = rows[1].gas;
  const ins2 = rows[2].gas;
  console.log("");
  console.log(`증명 1건이 붙는 비용: ${(ins1 - base).toLocaleString()} gas (V3 기준선 대비)`);
  console.log(`증명 2건째의 한계 비용: ${(ins2 - ins1).toLocaleString()} gas`);
  console.log(`세션 리셋은 증명이 없어 ${(ins1 - rows[3].gas).toLocaleString()} gas 싸다`);

  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const out = path.join(__dirname, "..", "results", `mode2_registry_v4_gas_${stamp}.csv`);
  fs.writeFileSync(out,
    "# RevocationRegistryV4 게시 가스 실측. V3는 검증이 전혀 없던 기준선이다.\n" +
    "# 설계 문서 13.2절의 '배치당 약 25만 gas' 추정을 대체한다.\n" +
    "operation,gas,note\n" +
    rows.map((r) => `"${r.what}",${r.gas},"${r.note}"`).join("\n") + "\n");
  console.log(`\nwrote ${path.relative(process.cwd(), out)}`);
}

// snarkjs가 워커 스레드를 남겨 프로세스가 스스로 끝나지 않는다(다른 벤치들과 같은 처리).
main()
  .then(() => process.exit(0))
  .catch((e) => { console.error(e); process.exit(1); });
