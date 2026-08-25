const hre = require("hardhat");

async function main() {
  const idpBaseUrl = process.env.CUSTOM_IDP_BASE_URL || "http://127.0.0.1:4000";
  const res = await fetch(`${idpBaseUrl}/ps_public_keys`);
  if (!res.ok) {
    throw new Error(`Failed to fetch pk_IdP from ${idpBaseUrl}/ps_public_keys: ${res.status}`);
  }
  const { pk_IdP } = await res.json();
  const [pk_IdP_x, pk_IdP_y] = pk_IdP;

  // push_revocation_root.cjs는 명시적 signer 없이 기본 signer로 pushRoot()를 호출하므로,
  // RevocationRegistry의 onlyIdP는 그 기본 signer(=이 스크립트의 배포자) 주소를 알아야 한다.
  const [deployer] = await hre.ethers.getSigners();
  const idpAddress = deployer.address;

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

  const Factory = await hre.ethers.getContractFactory("PPIDWalletFactory");
  const factory = await Factory.deploy(verifierAddress, pk_IdP_x, pk_IdP_y, registryAddress);
  await factory.waitForDeployment();
  const factoryAddress = await factory.getAddress();
  console.log("PPIDWalletFactory deployed at:", factoryAddress);
  console.log(`\nSet this before starting wallet_agent.js:\nPPID_WALLET_FACTORY_ADDRESS=${factoryAddress}`);
  console.log('PPID_WALLET_FACTORY_ADDRESS=', factoryAddress);
  console.log('REVOCATION_REGISTRY_ADDRESS=', registryAddress);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
