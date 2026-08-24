const hre = require("hardhat");

// IdP의 현재 폐기 root를 읽어 RevocationRegistry에 게시한다.
// IdP에 개인키를 두지 않기 위해 오퍼레이터가 실행하는 별도 단계로 분리했다.
async function main() {
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
