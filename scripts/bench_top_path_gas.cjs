// 상위 트리 경로 한 단계의 온체인 비용 실측.
//   npx hardhat run scripts/bench_top_path_gas.cjs --network localhost
//
// 왜 재는가. 계정 층 샤드 수를 늘리면(256 -> 1024 -> 4096 ...) 상위 트리가 깊어지고,
// 그 깊이는 **모든 execute()가 매번** 접어 올린다. "샤드를 늘리자"는 판단이 이 단가에
// 달려 있는데 지금까지 추정치뿐이었다.
//
// 단가에는 두 가지가 섞여 있고 둘 다 재야 한다:
//   (1) 계산  — keccak256(a‖b) 한 번 + 방향 분기
//   (2) calldata — 형제 32바이트가 하나 더 붙는다. non-zero 바이트는 16 gas/byte라
//                  이쪽이 오히려 더 크다.
// 그래서 view 호출이 아니라 **트랜잭션**으로 재고, 형제 배열 길이만 바꿔 차분을 본다.
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

function assertPersistentNetwork() {
  if (hre.network.name === "hardhat") {
    throw new Error(
      "--network localhost 없이 실행되었습니다. 임시 인프로세스 체인에서는 측정이 사라집니다:\n" +
      "  npx hardhat run scripts/bench_top_path_gas.cjs --network localhost"
    );
  }
}

// PPIDWalletV3._climbAcct / RevocationRegistryV4._climb 과 **같은 계산**이어야 한다.
// 샤드 인덱스의 비트가 곧 좌우 방향인 것까지 동일하게 옮긴다.
const PROBE_SRC = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract TopPathGasProbe {
    bytes32 public sink;
    function climb(bytes32 leaf, uint256 index, bytes32[] calldata siblings) external {
        bytes32 node = leaf;
        uint256 idx = index;
        for (uint256 i = 0; i < siblings.length; i++) {
            node = (idx & 1) == 0
                ? keccak256(abi.encodePacked(node, siblings[i]))
                : keccak256(abi.encodePacked(siblings[i], node));
            idx >>= 1;
        }
        sink = node;
    }
    function noop() external { sink = sink; }
}
`;

async function main() {
  assertPersistentNetwork();
  const [signer] = await hre.ethers.getSigners();

  // 프로브를 contracts/ 아래에 잠시 쓴다. 실패해도 남지 않도록 finally에서 지운다 —
  // 남으면 이후 모든 compile이 그 파일을 함께 컴파일한다.
  const probePath = path.join(__dirname, "..", "contracts", "test", "TopPathGasProbe.sol");
  if (fs.existsSync(probePath)) {
    throw new Error(`${probePath}가 이미 있습니다. 이전 실행이 비정상 종료했을 수 있으니 확인 후 지우고 다시 실행하세요.`);
  }
  fs.mkdirSync(path.dirname(probePath), { recursive: true });
  fs.writeFileSync(probePath, PROBE_SRC.trimStart());
  let probe;
  try {
    await hre.run("compile", { quiet: true });
    const P = await hre.ethers.getContractFactory("TopPathGasProbe");
    probe = await (await P.deploy()).waitForDeployment();
  } finally {
    fs.rmSync(probePath, { force: true });
    fs.rmSync(path.join(__dirname, "..", "artifacts", "contracts", "test", "TopPathGasProbe.sol"),
              { recursive: true, force: true });
  }

  const warm = async (fn) => { await (await fn()).wait(); };
  const gasOf = async (fn) => Number((await (await fn()).wait()).gasUsed);

  // 형제는 전부 non-zero로 채운다. 0으로 채우면 calldata가 4 gas/byte로 계산돼
  // 실제(빈 서브트리 root도 non-zero다)보다 싸게 나온다.
  const sib = (n) => Array.from({ length: n }, (_, i) =>
    hre.ethers.keccak256(hre.ethers.toUtf8Bytes(`sibling-${i}`)));
  const leaf = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("leaf"));

  // sink를 **비0 값으로** 먼저 채운다. 이걸 안 하면 첫 측정만 SSTORE 0->비0(20,000 gas)를
  // 물어 기준선이 오염된다(처음에 그렇게 재서 깊이 0이 깊이 8보다 비싸게 나왔다).
  await warm(() => probe.noop());

  const depths = [0, 8, 10, 12, 14];
  const rows = [];
  // 워밍 호출 한 번(측정에 넣지 않는다) — 이후 모든 호출은 SSTORE 비0->비0만 낸다.
  await warm(() => probe.climb(leaf, 0, sib(1)));
  for (const d of depths) {
    const gas = await gasOf(() => probe.climb(leaf, 0b101010101010, sib(d)));
    rows.push({ depth: d, gas });
  }

  const base = rows.find((r) => r.depth === 0).gas;
  console.log("");
  console.log("## 상위 트리 경로 깊이별 온체인 비용 (계산 + calldata)");
  console.log("");
  console.log("| 깊이 | 샤드 수 | gas | 기준선 대비 | 단계당 |");
  console.log("|--:|--:|--:|--:|--:|");
  for (const r of rows) {
    const perLevel = r.depth === 0 ? "—" : ((r.gas - base) / r.depth).toFixed(0);
    const shards = r.depth === 0 ? "—" : (2 ** r.depth).toLocaleString();
    console.log(`| ${r.depth} | ${shards} | ${r.gas.toLocaleString()} | +${(r.gas - base).toLocaleString()} | ${perLevel} |`);
  }

  const g = (d) => rows.find((r) => r.depth === d).gas;
  const perLevel = (g(12) - g(8)) / 4;
  console.log("");
  console.log(`깊이 8 -> 12 (계정 샤드 256 -> 4,096): +${(g(12) - g(8)).toLocaleString()} gas ` +
              `(단계당 ${perLevel.toFixed(0)})`);
  console.log("이 값은 **execute() 한 번마다** 붙는다. 현재 execute()는 약 332,000 gas다.");
  console.log(`즉 증가율 약 ${(100 * (g(12) - g(8)) / 332000).toFixed(2)}%.`);

  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const out = path.join(__dirname, "..", "results", `mode2_top_path_gas_${stamp}.csv`);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out,
    "# 상위 트리 경로 깊이별 온체인 비용. 계산(keccak)과 calldata(형제 32바이트)를 모두 포함한다.\n" +
    "# 형제는 non-zero로 채웠다(0으로 채우면 calldata가 4 gas/byte로 계산돼 싸게 나온다).\n" +
    "depth,shards,gas,delta_vs_depth0\n" +
    rows.map((r) => `${r.depth},${r.depth === 0 ? 0 : 2 ** r.depth},${r.gas},${r.gas - base}`).join("\n") + "\n");
  console.log(`\nwrote ${path.relative(process.cwd(), out)}`);
}

main()
  .then(() => process.exit(0))
  .catch((e) => { console.error(e); process.exit(1); });
