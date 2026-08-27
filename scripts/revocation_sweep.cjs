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

async function callIdPAdmin(idpBaseUrl, adminSecret, pathname, body) {
  let res;
  try {
    res = await fetch(`${idpBaseUrl}${pathname}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-IdP-Admin-Secret": adminSecret },
      body: JSON.stringify(body ?? {}),
    });
  } catch (err) {
    throw new Error(`IdP(${idpBaseUrl})에 연결할 수 없어 ${pathname}을 호출하지 못했습니다: ${err.message}`);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${pathname} failed (${idpBaseUrl}): ${res.status} ${text}`);
  }
  return res.json();
}

// 폐기 게시 주기(batch publish). IdP에 대기 중인 폐기를 반영하고 만료된 리프를
// 정리한 다음 그 root를 온체인에 게시한다.
//
// 순서가 핵심이다: prepare(계산만) -> pushRoot(온체인 확정) -> commit(IdP 전진).
// IdP를 먼저 전진시키면 push가 실패했을 때 '게시되지 않은 root'를 지갑이 받아가
// 정상 사용자 전원의 execute()가 StaleRevocationRoot로 막힌다. push가 확정된
// 뒤에만 commit하므로 그 창이 존재하지 않는다.
async function main() {
  assertPersistentNetwork();
  const idpBaseUrl = process.env.CUSTOM_IDP_BASE_URL || "http://127.0.0.1:4000";
  const registryAddress = process.env.REVOCATION_REGISTRY_ADDRESS;
  if (!registryAddress) throw new Error("REVOCATION_REGISTRY_ADDRESS is required");

  const adminSecret = process.env.IDP_ADMIN_SECRET;
  if (!adminSecret) {
    throw new Error(
      "IDP_ADMIN_SECRET is required (must match the value custom_idp.js was started with) " +
      "— POST /idp/publish/prepare and /idp/publish/commit are admin-only endpoints."
    );
  }

  // 1) prepare — 다음 게시 후보 root를 계산만 한다. IdP 게시 상태는 그대로다.
  const prepared = await callIdPAdmin(idpBaseUrl, adminSecret, "/idp/publish/prepare");
  const expectedRoot = prepared.expectedRoot;
  if (expectedRoot === undefined || expectedRoot === null) {
    throw new Error(`/idp/publish/prepare 응답에 expectedRoot가 없습니다 (${idpBaseUrl})`);
  }
  console.log(
    `1/3 prepare: added=${prepared.added}, removed=${prepared.removed}, ` +
    `leaves=${prepared.leafCount}, pending=${prepared.pendingCount}`
  );
  console.log(`    currentRoot=${prepared.currentRoot}`);
  console.log(`    expectedRoot=${expectedRoot}`);

  // 2) pushRoot — 온체인에 게시하고 영수증까지 기다린다.
  const rootHex = rootToBytes32(hre, String(expectedRoot));

  // onlyIdP 주소는 REVOCATION_IDP_ADDRESS로 명시한다 — 배포 스크립트/
  // push_revocation_root.cjs와 같은 값을 써야 pushRoot가 NotIdP로 revert하지 않는다.
  const idpSigner = await getIdPSigner(hre);
  const registry = await hre.ethers.getContractAt("RevocationRegistry", registryAddress, idpSigner);

  // push_revocation_root.cjs와 동일하게 중복 게시 가드는 두지 않는다(dd75591에서
  // 의도적으로 제거됨). 추가·제거가 0건이어도(heartbeat) 이 root를 다시 push해서
  // pushedAt을 갱신해야 RevocationRegistry의 GRACE_BLOCKS 만료로 정상 사용자가
  // 막히는 일을 막는다.
  const tx = await registry.pushRoot(rootHex);
  const receipt = await tx.wait();
  console.log(`2/3 pushRoot: ${rootHex} (block ${receipt.blockNumber}, tx ${receipt.hash})`);

  // 3) commit — push가 확정된 뒤에만 IdP를 전진시킨다.
  const committed = await callIdPAdmin(idpBaseUrl, adminSecret, "/idp/publish/commit", {
    root: String(expectedRoot),
  });
  console.log(
    `3/3 commit: published root=${committed.root}, leaves=${committed.leafCount}, ` +
    `pending=${committed.pendingCount}`
  );

  if (String(committed.root) !== String(expectedRoot)) {
    throw new Error(
      `commit이 반영한 root(${committed.root})가 게시한 root(${expectedRoot})와 다릅니다. ` +
      `IdP 상태와 온체인 root가 어긋났습니다.`
    );
  }
  console.log("Published revocation root:", rootHex);
}

main().catch((e) => { console.error(e); process.exit(1); });
