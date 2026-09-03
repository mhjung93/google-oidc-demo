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
  // 먼저 확인한다. latestRoot == 0(게시 전)이면 isCurrentRoot가 항상 false라 재배포
  // 직후 시스템이 완전히 동작 불능이 되므로, 여기서 조용히 넘어가면 안 된다.
  const initialRoot = await fetchIdPRoot(idpBaseUrl);

  // 이 스크립트는 되돌릴 수 없는 일을 한다. 실행 전에 무엇이 깨지는지 분명히 알린다
  // (2026-09-04 리뷰).
  //
  //  - registry를 새로 배포하면 **실행 중인 sweep 데몬과 wallet_agent는 옛 주소를
  //    계속 쓴다.** 데몬은 A에, 지갑은 B에 붙은 상태가 되어 첫 폐기 게시 순간부터
  //    전원의 execute()가 StaleRevocationRoot로 막힌다. 반드시 둘 다 새 주소로
  //    재기동해야 한다.
  //  - verifier/registry가 바뀌면 factory의 불변값이 바뀌므로 **CREATE2 지갑 주소가
  //    전부 달라진다.** 옛 주소에 남은 잔액은 그 주소로만 접근 가능하다.
  //
  // REDEPLOY_CONFIRM=yes 가 없으면 여기서 멈춘다.
  if (process.env.REDEPLOY_CONFIRM !== "yes") {
    throw new Error(
      "\n" + "!".repeat(70) + "\n" +
      "이 스크립트는 verifier·registry·factory를 새로 배포합니다. 되돌릴 수 없습니다:\n" +
      "  1) CREATE2 지갑 주소가 전부 바뀝니다 — 옛 주소의 잔액은 그대로 남습니다.\n" +
      "  2) 실행 중인 revocation_sweep 데몬과 wallet_agent.js는 옛 registry 주소를\n" +
      "     계속 씁니다. 배포 후 반드시 새 주소로 둘 다 재기동하십시오. 그러지 않으면\n" +
      "     첫 폐기 게시부터 전원의 트랜잭션이 StaleRevocationRoot로 막힙니다.\n" +
      "진행하려면 REDEPLOY_CONFIRM=yes 를 설정하고 다시 실행하십시오.\n" +
      "!".repeat(70)
    );
  }

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

  // 갓 배포된 레지스트리는 latestRoot == 0이고, 그 상태에서는 isCurrentRoot가
  // 무조건 false라 모든 execute()가 StaleRevocationRoot로 revert한다. 재배포 직후
  // 시스템이 100% 동작 불능이 되지 않도록 IdP의 현재 root를 즉시 게시한다.
  // 위에서 읽은 initialRoot는 배포 트랜잭션 3건 **이전** 값이라, 그 사이 폐기가
  // 게시됐으면 낡았다. 낡은 root를 부트스트랩하면 지갑들이 만드는 증명의 root와
  // 어긋나 전원이 막힌다 — 게시 직전에 다시 읽는다(위 조회는 "IdP가 살아있는가"
  // 확인용으로 남겨 둔다).
  const freshRoot = await fetchIdPRoot(idpBaseUrl);
  if (String(freshRoot) !== String(initialRoot)) {
    console.log(`[redeploy] 배포 중 IdP root가 바뀌었다: ${initialRoot} -> ${freshRoot} (새 값으로 부트스트랩)`);
  }
  const initialRootHex = rootToBytes32(hre, freshRoot);
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
