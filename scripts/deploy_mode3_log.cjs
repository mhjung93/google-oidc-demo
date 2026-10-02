// Mode 3 캐노니컬 로그(Mode3Log) + 거울(Mode3Mirror) 배포.
//   CIA_ETH_ADDRESS=0x... npx hardhat run scripts/deploy_mode3_log.cjs --network localhost
//
// V10(2026-10-02 설계 §5): 서비스(RP)·지갑·계정 컨트랙트는 자기 체인의 거울만 읽고, CIA 가 캐노니컬 로그의 게시를 거울로
// 중계한다. 기본 흐름은 한 네트워크에 로그와 그 로그를 가리키는 거울을 함께 배포한다(체인 하나 데모).
// 폐기 체인을 별도 노드로 둘 때(docs/MODE3_DEMO.md "폐기 체인을 별도 노드로")는 두 번 돌린다 — 폐기 체인에서 한 번(로그 +
// 같은 체인 거울, 거울은 안 써도 무해), 앱 체인에서 MODE3_CANONICAL_LOG_ADDRESS·MODE3_CANONICAL_CHAIN_ID 를 주어 한 번
// (거울만, 남의 체인의 캐노니컬을 가리킨다).
//
// 주소는 출력만 한다. .env 에 옮기는 것은 사람이 한다.
const hre = require("hardhat");

async function main() {
  if (hre.network.name === "hardhat") {
    throw new Error("--network localhost 없이 실행되었습니다. 임시 인프로세스 체인에 배포하면 사라집니다.");
  }
  const raw = process.env.CIA_ETH_ADDRESS;
  if (!raw) throw new Error("CIA_ETH_ADDRESS 가 없습니다. cia.js 를 한 번 띄워 GET /cia/public_keys 의 ethAddress 를 쓰세요.");
  const cia = hre.ethers.getAddress(raw.trim());
  // 거울만 배포하는 모드: 둘 다 있거나 둘 다 없어야 한다(하나만 있으면 엉뚱한 체인을 가리키는 거울이 생긴다).
  const foreignLog = (process.env.MODE3_CANONICAL_LOG_ADDRESS || "").trim();
  const foreignChain = (process.env.MODE3_CANONICAL_CHAIN_ID || "").trim();
  if (Boolean(foreignLog) !== Boolean(foreignChain)) {
    throw new Error("MODE3_CANONICAL_LOG_ADDRESS 와 MODE3_CANONICAL_CHAIN_ID 는 함께 줘야 합니다(거울만 배포).");
  }
  const { createRevocationTree } = await import("../lib/mode3_revocation.js");
  const { createRegistryTree } = await import("../lib/mode3_registry.js");
  const emptyRoot = hre.ethers.zeroPadValue(hre.ethers.toBeHex((await createRevocationTree()).getRoot()), 32);
  const emptyReg = hre.ethers.zeroPadValue(hre.ethers.toBeHex((await createRegistryTree()).root()), 32);
  // CIA 는 게시·거울 중계 tx 를 자기 키로 보낸다 — hardhat 기본 계정에서 가스비를 채워 준다(이 네트워크 몫).
  const [funder] = await hre.ethers.getSigners();
  const bal = await hre.ethers.provider.getBalance(cia);
  if (bal < hre.ethers.parseEther("0.5")) {
    await (await funder.sendTransaction({ to: cia, value: hre.ethers.parseEther("1") })).wait();
    console.log(`funded ${cia} with 1 ETH`);
  }
  const chainId = (await hre.ethers.provider.getNetwork()).chainId;

  let logAddress, canonicalChainId;
  if (foreignLog) {
    logAddress = hre.ethers.getAddress(foreignLog);
    canonicalChainId = BigInt(foreignChain);
    if (canonicalChainId === chainId) throw new Error(`MODE3_CANONICAL_CHAIN_ID(${canonicalChainId}) 가 이 네트워크와 같습니다 — 같은 체인이면 변수 없이 로그와 거울을 함께 배포하세요.`);
    console.log(`캐노니컬(외부): chainId=${canonicalChainId}  Mode3Log=${logAddress}`);
  } else {
    const F = await hre.ethers.getContractFactory("Mode3Log");
    const log = await F.deploy(cia, emptyRoot, emptyReg);
    await log.waitForDeployment();
    logAddress = await log.getAddress();
    canonicalChainId = chainId;
    console.log(`Mode3Log: ${logAddress}  (chainId=${chainId})`);
  }
  const M = await hre.ethers.getContractFactory("Mode3Mirror");
  const mirror = await M.deploy(cia, canonicalChainId, logAddress, emptyRoot, emptyReg);
  await mirror.waitForDeployment();
  const mirrorAddress = await mirror.getAddress();
  console.log(`Mode3Mirror: ${mirrorAddress}  (chainId=${chainId}, canonicalChainId=${canonicalChainId})`);
  console.log(`  cia=${cia}  emptyRoot=${emptyRoot}  emptyReg=${emptyReg}`);
  console.log(`\n.env 에 추가:`);
  if (!foreignLog) console.log(`  CIA_LOG_ADDRESS=${logAddress}`);
  console.log(`  MODE3_MIRROR_ADDRESS=${mirrorAddress}`);
  console.log(`  CIA_MIRRORS=${chainId}=${mirrorAddress}`);
  console.log(`\n주의: CIA_CHAIN_RPCS 에 ${chainId}=<이 네트워크의 RPC URL> 항목이 있어야 cia.js 가 기동합니다(거울 중계·세션 발급용).`);
  if (foreignLog) console.log(`      CIA_RPC_URL·CIA_LOG_ADDRESS 는 캐노니컬(chainId=${canonicalChainId}) 쪽 값 그대로 둡니다.`);
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
