const hre = require("hardhat");

async function main() {
  const idpBaseUrl = process.env.CUSTOM_IDP_BASE_URL || "http://127.0.0.1:4000";
  const res = await fetch(`${idpBaseUrl}/ps_public_keys`);
  if (!res.ok) {
    throw new Error(`Failed to fetch pk_IdP from ${idpBaseUrl}/ps_public_keys: ${res.status}`);
  }
  const { pk_IdP } = await res.json();
  const [pk_IdP_x, pk_IdP_y] = pk_IdP;

  const Verifier = await hre.ethers.getContractFactory("PiPkIVerifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  console.log("PiPkIVerifier deployed at:", verifierAddress);

  const Factory = await hre.ethers.getContractFactory("PPIDWalletFactory");
  const factory = await Factory.deploy(verifierAddress, pk_IdP_x, pk_IdP_y);
  await factory.waitForDeployment();
  const factoryAddress = await factory.getAddress();
  console.log("PPIDWalletFactory deployed at:", factoryAddress);
  console.log(`\nSet this before starting wallet_agent.js:\nPPID_WALLET_FACTORY_ADDRESS=${factoryAddress}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
