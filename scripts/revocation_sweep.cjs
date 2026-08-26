const hre = require("hardhat");
const { getIdPSigner, rootToBytes32 } = require("./revocation_idp.cjs");

// hardhat.config.cjs에 networks 블록이 없어 defaultNetwork가 "hardhat"이다.
// push_revocation_root.cjs와 같은 이유로, --network 없이 실행하면 명령 종료와
// 함께 사라지는 임시 인프로세스 체인에 프루닝 root를 게시하게 되어 실제 8545
// 체인의 RevocationRegistry에는 반영되지 않는다.
function assertPersistentNetwork() {
  if (hre.network.name === "hardhat") {
    throw new Error(
      '이 스크립트는 --network localhost 없이 실행되었습니다. ' +
      'defaultNetwork가 "hardhat"이라 트랜잭션이 명령 종료와 함께 사라지는 ' +
      '임시 인프로세스 체인에 들어갑니다. 다음처럼 실행하세요:\n' +
      '  npx hardhat run scripts/revocation_sweep.cjs --network localhost'
    );
  }
}

// IdP에 만료된 폐기 리프를 정리(prune)시키고, 그 결과 root를 즉시 온체인에
// 게시한다. IdP가 자체 타이머로만 prune하고 게시는 별도 주기로 돈다면, 그
// 사이에 IdP root와 게시된 root가 어긋나는 창이 생겨 지갑의 witness가 게시된
// root와 맞지 않게 된다. prune과 게시를 한 트랜잭션성 동작으로 묶어 그 창을
// 없앤다.
async function main() {
  assertPersistentNetwork();
  const idpBaseUrl = process.env.CUSTOM_IDP_BASE_URL || "http://127.0.0.1:4000";
  const registryAddress = process.env.REVOCATION_REGISTRY_ADDRESS;
  if (!registryAddress) throw new Error("REVOCATION_REGISTRY_ADDRESS is required");

  const adminSecret = process.env.IDP_ADMIN_SECRET;
  if (!adminSecret) {
    throw new Error(
      "IDP_ADMIN_SECRET is required (must match the value custom_idp.js was started with) " +
      "— POST /idp/sweep is an admin-only endpoint."
    );
  }

  let res;
  try {
    res = await fetch(`${idpBaseUrl}/idp/sweep`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-IdP-Admin-Secret": adminSecret },
    });
  } catch (err) {
    throw new Error(`IdP(${idpBaseUrl})에 연결할 수 없어 sweep을 요청하지 못했습니다: ${err.message}`);
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`/idp/sweep failed (${idpBaseUrl}): ${res.status} ${body}`);
  }
  const { root, removed, remaining } = await res.json();
  if (root === undefined || root === null) {
    throw new Error(`/idp/sweep 응답에 root가 없습니다 (${idpBaseUrl})`);
  }
  console.log(`Swept IdP revocation tree: removed=${removed}, remaining=${remaining}`);

  const rootHex = rootToBytes32(hre, String(root));

  // onlyIdP 주소는 REVOCATION_IDP_ADDRESS로 명시한다 — 배포 스크립트/
  // push_revocation_root.cjs와 같은 값을 써야 pushRoot가 NotIdP로 revert하지 않는다.
  const idpSigner = await getIdPSigner(hre);
  const registry = await hre.ethers.getContractAt("RevocationRegistry", registryAddress, idpSigner);

  // push_revocation_root.cjs와 동일하게 중복 게시 가드는 두지 않는다(dd75591에서
  // 의도적으로 제거됨). 제거된 리프가 0개여도(heartbeat) 이 root를 다시 push해서
  // pushedAt을 갱신해야 RevocationRegistry의 GRACE_BLOCKS 만료로 정상 사용자가
  // 막히는 일을 막는다.
  const tx = await registry.pushRoot(rootHex);
  await tx.wait();
  console.log("Pushed revocation root:", rootHex);
}

main().catch((e) => { console.error(e); process.exit(1); });
