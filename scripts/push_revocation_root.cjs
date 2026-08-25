const hre = require("hardhat");

// hardhat.config.cjs에 networks 블록이 없어 defaultNetwork가 "hardhat"이다.
// 이 스크립트를 --network 없이 실행하면(예: `node scripts/push_revocation_root.cjs`)
// 명령이 끝나는 즉시 사라지는 인프로세스 임시 체인에 트랜잭션을 보내게 되어,
// 실제 8545 체인의 RevocationRegistry에는 root가 반영되지 않는다. 영속 체인에
// 게시하려면 반드시 `npx hardhat run scripts/push_revocation_root.cjs --network localhost`로 실행한다.
function assertPersistentNetwork() {
  if (hre.network.name === "hardhat") {
    throw new Error(
      '이 스크립트는 --network localhost 없이 실행되었습니다. ' +
      'defaultNetwork가 "hardhat"이라 트랜잭션이 명령 종료와 함께 사라지는 ' +
      '임시 인프로세스 체인에 들어갑니다. 다음처럼 실행하세요:\n' +
      '  npx hardhat run scripts/push_revocation_root.cjs --network localhost'
    );
  }
}

// IdP의 현재 폐기 root를 읽어 RevocationRegistry에 게시한다.
// IdP에 개인키를 두지 않기 위해 오퍼레이터가 실행하는 별도 단계로 분리했다.
async function main() {
  assertPersistentNetwork();
  const idpBaseUrl = process.env.CUSTOM_IDP_BASE_URL || "http://127.0.0.1:4000";
  const registryAddress = process.env.REVOCATION_REGISTRY_ADDRESS;
  if (!registryAddress) throw new Error("REVOCATION_REGISTRY_ADDRESS is required");

  const res = await fetch(`${idpBaseUrl}/idp/revocation_state`);
  if (!res.ok) throw new Error(`revocation_state failed: ${res.status}`);
  const { root } = await res.json();

  // 회로의 root는 필드 요소(10진 문자열)이고 컨트랙트는 bytes32를 받는다.
  const rootHex = hre.ethers.zeroPadValue(hre.ethers.toBeHex(BigInt(root)), 32);

  const registry = await hre.ethers.getContractAt("RevocationRegistry", registryAddress);
  if (await registry.isRecentRoot(rootHex)) {
    console.log("Root already published, nothing to do:", rootHex);
    return;
  }
  const tx = await registry.pushRoot(rootHex);
  await tx.wait();
  console.log("Pushed revocation root:", rootHex);
}

main().catch((e) => { console.error(e); process.exit(1); });
