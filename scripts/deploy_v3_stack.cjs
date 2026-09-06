const hre = require("hardhat");
const { getIdPSigner, fetchIdPTopRootV3 } = require("./revocation_idp.cjs");

// 이중 트리(v3) 스택 배포 — verifier + RevocationRegistryV3 + PPIDWalletFactoryV3.
//   REDEPLOY_CONFIRM=yes npx hardhat run scripts/deploy_v3_stack.cjs --network localhost
//
// scripts/redeploy_ppid_factory.cjs(v2)와 같은 구조이고, 다른 점은 셋이다.
//   1) verifier가 public signal 9개짜리 PiPkIV3Verifier다
//   2) 레지스트리가 유예 창(graceBlocks)을 받는다
//   3) 부트스트랩 root가 /idp/revocation_state_v3 의 topRoot다 — 이미 bytes32라
//      필드 원소 변환을 거치지 않는다
//
// 전제: IdP가 **v3를 지원하는 코드로** 떠 있어야 한다. 아니면 여기서 명확히 멈춘다.
function assertPersistentNetwork() {
  if (hre.network.name === "hardhat") {
    throw new Error(
      '이 스크립트는 --network localhost 없이 실행되었습니다. defaultNetwork가 "hardhat"이라 ' +
      '배포 결과가 명령 종료와 함께 사라지는 임시 인프로세스 체인에 올라갑니다.\n' +
      '  npx hardhat run scripts/deploy_v3_stack.cjs --network localhost'
    );
  }
}

const GRACE_ENV = "REVOCATION_GRACE_BLOCKS";

async function main() {
  assertPersistentNetwork();
  const idpBaseUrl = process.env.CUSTOM_IDP_BASE_URL || "http://127.0.0.1:4000";

  const graceRaw = process.env[GRACE_ENV] ?? "3";
  const grace = Number(graceRaw);
  if (!Number.isInteger(grace) || grace < 1 || grace > 6) {
    throw new Error(`${GRACE_ENV}는 1~6 사이 정수여야 합니다(레지스트리 링 8칸 기준). 받은 값: ${graceRaw}`);
  }

  const res = await fetch(`${idpBaseUrl}/ps_public_keys`);
  if (!res.ok) throw new Error(`Failed to fetch pk_IdP from ${idpBaseUrl}/ps_public_keys: ${res.status}`);
  const { pk_IdP } = await res.json();
  const [pk_IdP_x, pk_IdP_y] = pk_IdP;

  const idpSigner = await getIdPSigner(hre);
  console.log("RevocationRegistryV3 onlyIdP address:", idpSigner.address);
  console.log("graceBlocks:", grace);

  // 배포를 시작하기 전에 IdP가 v3를 서빙하는지 먼저 확인한다. 갓 배포된 레지스트리는
  // latestRoot == 0이라 그 상태로 두면 모든 execute가 막히므로, 부트스트랩 root를
  // 못 가져오는 상황이면 아예 시작하지 않는 편이 낫다.
  const initialRoot = await fetchIdPTopRootV3(idpBaseUrl);

  if (process.env.REDEPLOY_CONFIRM !== "yes") {
    throw new Error(
      "\n" + "!".repeat(70) + "\n" +
      "v3 스택(verifier·registry·factory)을 새로 배포합니다. 되돌릴 수 없습니다:\n" +
      "  1) CREATE2 지갑 주소가 전부 바뀝니다 — 옛 주소의 잔액은 그대로 남습니다.\n" +
      "  2) 실행 중인 sweep 데몬과 wallet_agent.js는 옛 주소를 계속 씁니다.\n" +
      "     배포 후 반드시 새 주소로 둘 다 재기동하십시오.\n" +
      "진행하려면 REDEPLOY_CONFIRM=yes 를 설정하고 다시 실행하십시오.\n" +
      "!".repeat(70)
    );
  }

  const Verifier = await hre.ethers.getContractFactory("contracts/PiPkIV3Verifier.sol:Groth16Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  console.log("PiPkIV3Verifier deployed at:", verifierAddress);

  const Registry = await hre.ethers.getContractFactory("RevocationRegistryV3");
  const registry = await Registry.deploy(idpSigner.address, grace);
  await registry.waitForDeployment();
  const registryAddress = await registry.getAddress();
  console.log("RevocationRegistryV3 deployed at:", registryAddress);

  // 배포 트랜잭션 사이에 폐기가 게시됐을 수 있으므로 게시 직전에 다시 읽는다
  // (v2 스크립트와 같은 이유 — 낡은 root를 부트스트랩하면 전원이 막힌다).
  const freshRoot = await fetchIdPTopRootV3(idpBaseUrl);
  if (freshRoot !== initialRoot) {
    console.log(`[deploy_v3] 배포 중 IdP topRoot가 바뀌었다: ${initialRoot} -> ${freshRoot}`);
  }
  await (await registry.connect(idpSigner).pushRoot(freshRoot)).wait();
  console.log("Bootstrapped v3 top root:", freshRoot);

  const Factory = await hre.ethers.getContractFactory("PPIDWalletFactoryV3");
  const factory = await Factory.deploy(verifierAddress, pk_IdP_x, pk_IdP_y, registryAddress);
  await factory.waitForDeployment();
  const factoryAddress = await factory.getAddress();
  console.log("PPIDWalletFactoryV3 deployed at:", factoryAddress);

  console.log(
    `\nSet these before restarting wallet_agent.js / the sweep daemon:\n` +
    `PPID_WALLET_FACTORY_ADDRESS=${factoryAddress}\n` +
    `REVOCATION_REGISTRY_ADDRESS=${registryAddress}\n` +
    `REVOCATION_TREE_VERSION=v3`,
  );
}

main().catch((err) => { console.error(err); process.exit(1); });
