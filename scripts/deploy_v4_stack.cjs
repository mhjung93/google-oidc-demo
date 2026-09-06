// V4 스택 배포 — 전이 검증 레지스트리로 전환한다 (설계 문서 13.2절).
//
//   REDEPLOY_CONFIRM=yes npx hardhat run scripts/deploy_v4_stack.cjs --network localhost
//
// V3 스택과 무엇이 다른가.
//   - RevocationRegistryV3 -> RevocationRegistryV4. root를 받지 않고 유도한다.
//   - 전이 검증자 둘(pi_ins_sess / pi_ins_acct)이 새로 배포된다.
//   - **회로와 지갑 컨트랙트는 그대로다.** PPIDWalletV3는 레지스트리에서
//     isAcceptableRoot(bytes32) 하나만 쓰는데 V4도 같은 서명을 제공하므로 드롭인이다.
//     그래서 PiPkIV3Verifier와 PPIDWalletV3 코드는 손대지 않고, factory만 새 레지스트리
//     주소로 다시 배포한다.
//
// 되돌릴 수 없는 것: factory의 불변값이 바뀌므로 **CREATE2 지갑 주소가 전부 달라진다.**
// 옛 주소에 남은 잔액은 그 주소로만 접근 가능하다.
//
// 부트스트랩: 레지스트리 생성자에 지금 IdP의 두 층 상위 root를 새긴다. 이후로는 여기서
// 출발해 검증된 전이만 쌓이므로, 신뢰가 필요한 지점이 이 한 번으로 국한된다.
const hre = require("hardhat");
const { getIdPSigner } = require("./revocation_idp.cjs");

// custom_idp.js의 CREDENTIAL_LIFETIME_BLOCKS + MAX_HEIGHT_SLACK_BLOCKS.
// 세션 샤드 리셋을 컨트랙트가 스스로 검증하는 근거값이라 반드시 IdP와 같아야 한다.
const MAX_CREDENTIAL_SPAN = Number(process.env.MAX_CREDENTIAL_SPAN || 332);
const GRACE_BLOCKS = Number(process.env.REVOCATION_GRACE_BLOCKS || 3);

function assertPersistentNetwork() {
  if (hre.network.name === "hardhat") {
    throw new Error(
      "--network localhost 없이 실행되었습니다. 임시 인프로세스 체인에 배포됩니다:\n" +
      "  REDEPLOY_CONFIRM=yes npx hardhat run scripts/deploy_v4_stack.cjs --network localhost"
    );
  }
}

async function main() {
  assertPersistentNetwork();
  const idpBaseUrl = process.env.CUSTOM_IDP_BASE_URL || "http://127.0.0.1:4000";
  const { rootToBytes32, createSessionForest } = await import("../lib/imt_v3.js");

  const idpSigner = await getIdPSigner(hre);
  console.log("RevocationRegistryV4 onlyIdP address:", idpSigner.address);
  console.log("graceBlocks:", GRACE_BLOCKS, "/ maxCredentialSpan:", MAX_CREDENTIAL_SPAN);

  // 배포를 시작하기 전에 IdP가 살아있는지 확인한다. 부트스트랩 root를 생성자에 넣어야
  // 하므로, 여기서 실패하면 아무것도 배포하지 않은 채 끝나는 것이 낫다.
  const res = await fetch(`${idpBaseUrl}/idp/revocation_state_v3`);
  if (!res.ok) throw new Error(`revocation_state_v3 failed (${idpBaseUrl}): ${res.status}`);
  const before = await res.json();
  console.log("IdP 부트스트랩 상태:", before.topRoot);

  if (process.env.REDEPLOY_CONFIRM !== "yes") {
    throw new Error(
      "\n" + "!".repeat(70) + "\n" +
      "이 스크립트는 레지스트리와 factory를 새로 배포합니다. 되돌릴 수 없습니다:\n" +
      "  1) CREATE2 지갑 주소가 전부 바뀝니다 — 옛 주소의 잔액은 그대로 남습니다.\n" +
      "  2) 실행 중인 revocation_sweep 데몬과 wallet_agent.js는 옛 주소를 계속 씁니다.\n" +
      "     배포 후 반드시 새 주소로 둘 다 재기동하십시오.\n" +
      "진행하려면 REDEPLOY_CONFIRM=yes 를 설정하고 다시 실행하십시오.\n" +
      "!".repeat(70)
    );
  }

  const SessV = await hre.ethers.getContractFactory("contracts/pi_ins_sess_verifier.sol:Groth16Verifier");
  const sessV = await (await SessV.deploy()).waitForDeployment();
  console.log("pi_ins_sess verifier:", await sessV.getAddress());

  const AcctV = await hre.ethers.getContractFactory("contracts/pi_ins_acct_verifier.sol:Groth16Verifier");
  const acctV = await (await AcctV.deploy()).waitForDeployment();
  console.log("pi_ins_acct verifier:", await acctV.getAddress());

  // 빈 세션 서브트리 root — 리셋의 목적지다. 라이브러리에서 직접 얻어 IdP와 어긋날 수 없게 한다.
  const emptySessionSubRoot = rootToBytes32((await createSessionForest()).emptyRoot);

  // 배포 트랜잭션이 오가는 사이 IdP 상태가 바뀔 수 있다. 생성자에 넣기 직전에 다시 읽는다 —
  // 낡은 root로 부트스트랩하면 지갑이 만드는 witness와 어긋나 전원이 막힌다.
  const fresh = await (await fetch(`${idpBaseUrl}/idp/revocation_state_v3`)).json();
  if (fresh.topRoot !== before.topRoot) {
    console.log(`[deploy_v4] 배포 중 IdP root가 바뀌었다: ${before.topRoot} -> ${fresh.topRoot}`);
  }

  const RegV4 = await hre.ethers.getContractFactory("RevocationRegistryV4");
  const registry = await (await RegV4.deploy(
    idpSigner.address,
    GRACE_BLOCKS,
    MAX_CREDENTIAL_SPAN,
    emptySessionSubRoot,
    await sessV.getAddress(),
    await acctV.getAddress(),
    fresh.sessionTopRoot,
    fresh.accountTopRoot,
  )).waitForDeployment();
  const registryAddress = await registry.getAddress();
  console.log("RevocationRegistryV4 deployed at:", registryAddress);

  // 생성자가 부트스트랩 root를 새겼는지 확인한다.
  const latest = await registry.latestRoot();
  if (String(latest).toLowerCase() !== String(fresh.topRoot).toLowerCase()) {
    throw new Error(`부트스트랩 실패: 컨트랙트 ${latest} != IdP ${fresh.topRoot}`);
  }
  console.log("Bootstrapped root:", latest);

  // 회로는 바뀌지 않았다. 그래도 verifier를 새로 배포한다 — 주소를 어디서도 들고 있지
  // 않아 재사용하려면 운영자가 손으로 넘겨야 하는데, 배포 비용이 그 실수 위험보다 싸다
  // (deploy_v3_stack.cjs와 같은 방침).
  const Verifier = await hre.ethers.getContractFactory("contracts/PiPkIV3Verifier.sol:Groth16Verifier");
  const verifier = await (await Verifier.deploy()).waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  console.log("PiPkIV3Verifier deployed at:", verifierAddress);

  // factory에 새길 신뢰 IdP 키는 IdP에서 직접 읽는다. 손으로 넘기면 어긋날 수 있다.
  const keysRes = await fetch(`${idpBaseUrl}/ps_public_keys`);
  if (!keysRes.ok) {
    throw new Error(`Failed to fetch pk_IdP from ${idpBaseUrl}/ps_public_keys: ${keysRes.status}`);
  }
  const { pk_IdP } = await keysRes.json();
  const [pk_IdP_x, pk_IdP_y] = pk_IdP;

  const Factory = await hre.ethers.getContractFactory("PPIDWalletFactoryV3");
  const factory = await (await Factory.deploy(
    verifierAddress, pk_IdP_x, pk_IdP_y, registryAddress,
  )).waitForDeployment();
  console.log("PPIDWalletFactoryV3 (V4 registry) deployed at:", await factory.getAddress());

  console.log("");
  console.log("=== .env 에 반영할 값 ===");
  console.log(`REVOCATION_REGISTRY_ADDRESS=${registryAddress}`);
  console.log(`PPID_WALLET_FACTORY_ADDRESS=${await factory.getAddress()}`);
  console.log("");
  console.log("이후: wallet_agent.js 를 새 factory 주소로 재기동하십시오.");
}

main()
  .then(() => process.exit(0))
  .catch((e) => { console.error(e); process.exit(1); });
