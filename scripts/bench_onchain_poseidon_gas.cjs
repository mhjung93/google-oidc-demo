// 온체인 Poseidon 해시 가스를 실측한다.
//   npx hardhat run scripts/bench_onchain_poseidon_gas.cjs --network localhost
//
// 왜 재는가. 설계 문서 12절이 "컨트랙트가 폐기 트리를 직접 유지하는" 대안을 평가하면서
// 온체인 Poseidon을 "수만 gas 규모, 폐기 1건당 약 100만 gas"로 **추정**해 두었다. 채택한
// 설계(상위 트리를 keccak으로 빼는 쪽)는 Poseidon을 온체인에서 쓰지 않으므로 직접
// 영향은 없지만, 그 대안을 왜 버렸는지가 추정에만 기대고 있었다. 유일하게 남은 추정치라
// 닫아 둔다.
//
// circomlibjs가 EVM 어셈블리로 된 Poseidon 컨트랙트를 생성해 준다(회로와 같은 상수).
// keccak과 나란히 재서 "밖으로 뺀 만큼이 왜 이득인가"를 수치로 남긴다.
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

function assertPersistentNetwork() {
  if (hre.network.name === "hardhat") {
    throw new Error(
      '--network localhost 없이 실행되었습니다. 임시 인프로세스 체인에서는 측정이 사라집니다:\n' +
      '  npx hardhat run scripts/bench_onchain_poseidon_gas.cjs --network localhost'
    );
  }
}

// 가스를 재려면 view가 아니라 트랜잭션이어야 한다. 생성된 Poseidon 컨트랙트를 호출하고
// 결과를 버리는 얇은 프로브를 둔다 — 호출 오버헤드(약 700 gas)는 양쪽에서 동일하다.
const PROBE_SRC = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
interface IPoseidon2 { function poseidon(uint256[2] calldata) external pure returns (uint256); }
contract HashGasProbe {
    uint256 public sink;
    function poseidonOnce(address p, uint256 a, uint256 b) external {
        sink = IPoseidon2(p).poseidon([a, b]);
    }
    function keccakOnce(bytes32 a, bytes32 b) external {
        sink = uint256(keccak256(abi.encodePacked(a, b)));
    }
    function noop() external { sink = sink; }
}
`;

async function main() {
  assertPersistentNetwork();
  const { poseidonContract } = await import("circomlibjs");
  const [signer] = await hre.ethers.getSigners();

  // 1) Poseidon(2) 컨트랙트 배포
  const abi = poseidonContract.generateABI(2);
  const bytecode = poseidonContract.createCode(2);
  const PoseidonFactory = new hre.ethers.ContractFactory(abi, bytecode, signer);
  const poseidon = await PoseidonFactory.deploy();
  await poseidon.waitForDeployment();
  const poseidonAddr = await poseidon.getAddress();
  const poseidonCode = await hre.ethers.provider.getCode(poseidonAddr);
  console.log(`Poseidon(2) 배포: ${poseidonAddr} (코드 ${(poseidonCode.length - 2) / 2} bytes)`);

  // 2) 프로브 컨트랙트를 즉석에서 컴파일해 배포
  // 프로브를 contracts/ 아래에 잠시 쓴다. 실패해도 남지 않도록 finally에서 지운다 —
  // 남으면 이후 모든 hardhat compile이 그 파일을 함께 컴파일하고, 추적되지 않는 .sol이
  // 작업트리에 떠다니게 된다.
  const srcDir = path.join(__dirname, "..", "contracts", "test");
  const probePath = path.join(srcDir, "HashGasProbe.sol");
  if (fs.existsSync(probePath)) {
    throw new Error(`${probePath}가 이미 있습니다. 이전 실행이 비정상 종료했을 수 있으니 확인 후 지우고 다시 실행하세요.`);
  }
  fs.writeFileSync(probePath, PROBE_SRC.trimStart());
  let probe;
  try {
    await hre.run("compile", { quiet: true });
    const Probe = await hre.ethers.getContractFactory("HashGasProbe");
    probe = await Probe.deploy();
    await probe.waitForDeployment();
  } finally {
    fs.rmSync(probePath, { force: true });
    // 소스가 사라진 아티팩트가 남으면 다음 컴파일에서 혼란스럽다(추적 대상은 아니다).
    fs.rmSync(path.join(__dirname, "..", "artifacts", "contracts", "test", "HashGasProbe.sol"),
              { recursive: true, force: true });
  }

  // 3) 측정. 첫 호출은 sink의 cold SSTORE(20k)를 포함하므로 워밍 후 잰다.
  const warm = async (fn) => { await (await fn()).wait(); };
  await warm(() => probe.noop());
  const gasOf = async (fn) => Number((await (await fn()).wait()).gasUsed);

  const noop = await gasOf(() => probe.noop());
  const pos = await gasOf(() => probe.poseidonOnce(poseidonAddr, 12345n, 67890n));
  const kec = await gasOf(() => probe.keccakOnce(hre.ethers.id("a"), hre.ethers.id("b")));

  const posNet = pos - noop;
  const kecNet = kec - noop;
  console.log(`\n기준선(noop, 트랜잭션+warm SSTORE): ${noop}`);
  console.log(`Poseidon(2) 1회: ${pos}  (순수 해시 ${posNet})`);
  console.log(`keccak256 1회 : ${kec}  (순수 해시 ${kecNet})`);
  console.log(`비율: Poseidon / keccak = ${(posNet / kecNet).toFixed(1)}배`);

  // 4) 설계 문서 12절이 추정한 "삽입 1건당 Poseidon 약 40회"를 이 값으로 환산
  const perInsert = posNet * 40;
  console.log(`\n깊이 20 IMT 삽입 1건(Poseidon 약 40회) 환산: 약 ${perInsert.toLocaleString()} gas`);
  console.log(`(참고) 현재 execute 전체: 330,079 gas`);

  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const out = path.join(__dirname, "..", "results", `mode2_onchain_hash_gas_${stamp}.csv`);
  fs.writeFileSync(out,
    "# 온체인 해시 가스 실측. circomlibjs poseidonContract(2)를 배포해 keccak과 나란히 쟀다.\n" +
    "# net_gas는 트랜잭션 기준선(noop)을 뺀 값이다. 설계 문서 12절의 추정치를 대체한다.\n" +
    "measurement,gas,note\n" +
    `noop_baseline,${noop},"트랜잭션 + warm SSTORE"\n` +
    `poseidon2_total,${pos},"프로브 -> Poseidon(2) 외부 호출 포함"\n` +
    `poseidon2_net,${posNet},"기준선 제외"\n` +
    `keccak256_total,${kec},\n` +
    `keccak256_net,${kecNet},"기준선 제외"\n` +
    `poseidon_over_keccak,${(posNet / kecNet).toFixed(1)},"배수"\n` +
    `imt_insert_estimate,${perInsert},"Poseidon 40회 환산 (깊이 20 삽입 1건)"\n`);
  console.log(`\nwrote ${path.relative(process.cwd(), out)}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
