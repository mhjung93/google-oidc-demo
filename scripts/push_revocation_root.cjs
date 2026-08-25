const hre = require("hardhat");
const { getIdPSigner, fetchIdPRoot, rootToBytes32 } = require("./revocation_idp.cjs");

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

  const root = await fetchIdPRoot(idpBaseUrl);
  const rootHex = rootToBytes32(hre, root);

  // onlyIdP 주소는 REVOCATION_IDP_ADDRESS로 명시한다 — 배포 스크립트와 같은 값을
  // 써야 pushRoot가 NotIdP로 revert하지 않는다.
  const idpSigner = await getIdPSigner(hre);
  const registry = await hre.ethers.getContractAt("RevocationRegistry", registryAddress, idpSigner);

  // 중복 게시 가드는 두지 않는다. 레지스트리가 블록 기반 만료(GRACE_BLOCKS)를 쓰게
  // 되면서, 같은 root의 재게시는 "아무것도 안 하는 중복"이 아니라 신선도를 갱신하는
  // 정당한 주기적 갱신(heartbeat)이 됐다. 가드를 두면 폐기가 드문 환경에서 root가
  // 갱신되지 못한 채 만료돼 정상 사용자가 전부 막힌다.
  const tx = await registry.pushRoot(rootHex);
  await tx.wait();
  console.log("Pushed revocation root:", rootHex);
}

main().catch((e) => { console.error(e); process.exit(1); });
