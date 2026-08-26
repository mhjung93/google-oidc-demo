const hre = require("hardhat");
const { getIdPSigner, fetchIdPRoot, rootToBytes32 } = require("./revocation_idp.cjs");

// hardhat.config.cjs에 networks 블록이 없어 defaultNetwork가 "hardhat"이다.
// 이 스크립트를 --network 없이 실행하면(예: `node scripts/redeploy_ppid_factory.cjs`)
// 명령이 끝나는 즉시 사라지는 인프로세스 임시 체인에 배포되고, 출력된 주소는
// 존재하지 않는 컨트랙트를 가리키게 된다. 8545에 떠 있는 영속 체인에 배포하려면
// 반드시 `npx hardhat run scripts/redeploy_ppid_factory.cjs --network localhost`로 실행한다.
function assertPersistentNetwork() {
  if (hre.network.name === "hardhat") {
    throw new Error(
      '이 스크립트는 --network localhost 없이 실행되었습니다. ' +
      'defaultNetwork가 "hardhat"이라 배포 결과가 명령 종료와 함께 사라지는 ' +
      '임시 인프로세스 체인에 올라갑니다. 다음처럼 실행하세요:\n' +
      '  npx hardhat run scripts/redeploy_ppid_factory.cjs --network localhost'
    );
  }
}

async function main() {
  assertPersistentNetwork();
  const idpBaseUrl = process.env.CUSTOM_IDP_BASE_URL || "http://127.0.0.1:4000";
  const res = await fetch(`${idpBaseUrl}/ps_public_keys`);
  if (!res.ok) {
    throw new Error(`Failed to fetch pk_IdP from ${idpBaseUrl}/ps_public_keys: ${res.status}`);
  }
  const { pk_IdP } = await res.json();
  const [pk_IdP_x, pk_IdP_y] = pk_IdP;

  // RevocationRegistry의 onlyIdP 주소는 REVOCATION_IDP_ADDRESS로 명시적으로 받는다.
  // 예전에는 배포 스크립트를 실행한 계정을 그대로 썼는데, 그러면 폐기 권한이 우연히
  // 배포자에게 붙고 운영자는 그 사실조차 모른다. 미설정이면 여기서 중단된다.
  const idpSigner = await getIdPSigner(hre);
  const idpAddress = idpSigner.address;
  console.log("RevocationRegistry onlyIdP address:", idpAddress);

  // 부트스트랩 root를 배포 직후 게시해야 하므로, 배포를 시작하기 전에 IdP가 살아있는지
  // 먼저 확인한다. filled == 0이면 isRecentRoot가 항상 false라 재배포 직후 시스템이
  // 완전히 동작 불능이 되므로, 여기서 조용히 넘어가면 안 된다.
  const initialRoot = await fetchIdPRoot(idpBaseUrl);

  const Verifier = await hre.ethers.getContractFactory("PiPkIVerifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  console.log("PiPkIVerifier deployed at:", verifierAddress);

  const Registry = await hre.ethers.getContractFactory("RevocationRegistry");
  const registry = await Registry.deploy(idpAddress);
  await registry.waitForDeployment();
  const registryAddress = await registry.getAddress();
  console.log("RevocationRegistry deployed at", registryAddress);

  // 갓 배포된 레지스트리는 비어 있고(filled == 0), 그 상태에서는 isRecentRoot가
  // 무조건 false라 모든 execute()가 StaleRevocationRoot로 revert한다. 재배포 직후
  // 시스템이 100% 동작 불능이 되지 않도록 IdP의 현재 root를 즉시 게시한다.
  const initialRootHex = rootToBytes32(hre, initialRoot);
  const bootstrapTx = await registry.connect(idpSigner).pushRoot(initialRootHex);
  await bootstrapTx.wait();
  console.log("Bootstrapped revocation root:", initialRootHex);

  const Factory = await hre.ethers.getContractFactory("PPIDWalletFactory");
  const factory = await Factory.deploy(verifierAddress, pk_IdP_x, pk_IdP_y, registryAddress);
  await factory.waitForDeployment();
  const factoryAddress = await factory.getAddress();
  console.log("PPIDWalletFactory deployed at:", factoryAddress);
  // wallet_agent.js는 증명 전에 자기 root가 실제로 게시됐는지 레지스트리에 직접
  // 물어보므로 두 주소가 모두 필요하다.
  console.log(
    `\nSet these before starting wallet_agent.js:\n` +
    `PPID_WALLET_FACTORY_ADDRESS=${factoryAddress}\n` +
    `REVOCATION_REGISTRY_ADDRESS=${registryAddress}`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
