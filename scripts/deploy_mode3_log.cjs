// Mode 3 로그 V2(폐기 root + 등록부 root) 컨트랙트 배포.
//   CIA_ETH_ADDRESS=0x... npx hardhat run scripts/deploy_mode3_log.cjs --network localhost
//
// 주소는 출력만 한다. .env 에 CIA_LOG_ADDRESS 로 옮기는 것은 사람이 한다.
const hre = require("hardhat");

async function main() {
  if (hre.network.name === "hardhat") {
    throw new Error("--network localhost 없이 실행되었습니다. 임시 인프로세스 체인에 배포하면 사라집니다.");
  }
  const raw = process.env.CIA_ETH_ADDRESS;
  if (!raw) throw new Error("CIA_ETH_ADDRESS 가 없습니다. cia.js 를 한 번 띄워 GET /cia/public_keys 의 ethAddress 를 쓰세요.");
  const cia = hre.ethers.getAddress(raw.trim());
  const { createRevocationTree } = await import("../lib/mode3_revocation.js");
  const { createRegistryTree } = await import("../lib/mode3_registry.js");
  const emptyRoot = hre.ethers.zeroPadValue(hre.ethers.toBeHex((await createRevocationTree()).getRoot()), 32);
  const emptyReg = hre.ethers.zeroPadValue(hre.ethers.toBeHex((await createRegistryTree()).root()), 32);
  // CIA 는 publish tx 를 자기 키로 보낸다 — hardhat 기본 계정에서 가스비를 채워 준다.
  const [funder] = await hre.ethers.getSigners();
  const bal = await hre.ethers.provider.getBalance(cia);
  if (bal < hre.ethers.parseEther("0.5")) {
    await (await funder.sendTransaction({ to: cia, value: hre.ethers.parseEther("1") })).wait();
    console.log(`funded ${cia} with 1 ETH`);
  }
  const F = await hre.ethers.getContractFactory("Mode3Log");
  const log = await F.deploy(cia, emptyRoot, emptyReg);
  await log.waitForDeployment();
  console.log(`Mode3Log: ${await log.getAddress()}`);
  console.log(`  cia=${cia}  emptyRoot=${emptyRoot}  emptyReg=${emptyReg}`);
  console.log(`\n.env 에 추가:\n  CIA_LOG_ADDRESS=${await log.getAddress()}`);
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
