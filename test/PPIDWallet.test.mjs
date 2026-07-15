import hre from "hardhat";
import { expect } from "chai";
import { buildEddsa, buildPoseidon } from "circomlibjs";
import { randomBytes } from "crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256, concat, getBytes } from "ethers";
import * as snarkjs from "snarkjs";

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
function valueToField(value) {
  if (typeof value === "bigint") return value % FIELD_PRIME;
  if (typeof value === "number") return BigInt(value) % FIELD_PRIME;
  const str = String(value);
  if (str.startsWith("0x")) return BigInt(str) % FIELD_PRIME;
  if (/^[0-9]+$/.test(str)) return BigInt(str) % FIELD_PRIME;
  const bytes = new TextEncoder().encode(str);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return BigInt(`0x${hex || "0"}`) % FIELD_PRIME;
}
function ethAddressFromSecp256k1Pubkey(pubKeyUncompressed65) {
  const xy = pubKeyUncompressed65.slice(1);
  return "0x" + keccak256(xy).slice(-40);
}

describe("PPIDWallet", function () {
  this.timeout(120000);

  async function buildValidCallData({ maxHeight = 999_999_999n, chainId } = {}) {
    const eddsa = await buildEddsa();
    const poseidon = await buildPoseidon();
    const F = eddsa.F;

    const sk_IdP = randomBytes(32);
    const pk_IdP = eddsa.prv2pub(sk_IdP);
    const pk_IdP_x = F.toObject(pk_IdP[0]);
    const pk_IdP_y = F.toObject(pk_IdP[1]);

    const sk_i = secp256k1.utils.randomPrivateKey();
    const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
    const pk_i = BigInt(ethAddressFromSecp256k1Pubkey(pubUncompressed));

    const rp_nonce = valueToField("rp-nonce-test");
    const rid = valueToField("rid-test");
    const uid = valueToField("12345");
    const salt = valueToField("salt-test");
    const resolvedChainId = chainId ?? valueToField((await hre.ethers.provider.getNetwork()).chainId.toString());

    const PPID = (uid * rid * salt) % FIELD_PRIME;
    const arid_i = (rid * rp_nonce) % FIELD_PRIME;
    const auid_i = (PPID * rp_nonce) % FIELD_PRIME;
    const r_token = poseidon.F.toObject(poseidon([pk_i, maxHeight, rp_nonce]));

    const DOMAIN_IDP_TOKEN = valueToField("IDP_TOKEN");
    const msg = poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, maxHeight, resolvedChainId]);
    const sigma_i = eddsa.signPoseidon(sk_IdP, msg);

    const circuitInput = {
      rp_nonce: rp_nonce.toString(),
      arid_i: arid_i.toString(),
      auid_i: auid_i.toString(),
      r_token: r_token.toString(),
      chain_id: resolvedChainId.toString(),
      S: sigma_i.S.toString(),
      R8x: F.toObject(sigma_i.R8[0]).toString(),
      R8y: F.toObject(sigma_i.R8[1]).toString(),
      pk_i: pk_i.toString(),
      pk_IdP_x: pk_IdP_x.toString(),
      pk_IdP_y: pk_IdP_y.toString(),
      PPID: PPID.toString(),
      max_height: maxHeight.toString(),
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      "build/mode2/pi_pk_i_js/pi_pk_i.wasm",
      "build/mode2/pi_pk_i_final.zkey",
    );
    const calldata = JSON.parse("[" + (await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)) + "]");
    const [pA, pB, pC] = calldata;

    function signPayload(payload) {
      const payloadHash = getBytes(
        hre.ethers.keccak256(
          hre.ethers.AbiCoder.defaultAbiCoder().encode(
            ["address", "uint256", "bytes", "uint256"],
            [payload.to, payload.value, payload.data, payload.nonce],
          ),
        ),
      );
      const sig = secp256k1.sign(payloadHash, sk_i);
      return concat([
        "0x" + sig.r.toString(16).padStart(64, "0"),
        "0x" + sig.s.toString(16).padStart(64, "0"),
        "0x" + (27 + sig.recovery).toString(16).padStart(2, "0"),
      ]);
    }

    return { pk_IdP_x, pk_IdP_y, pk_i, PPID, maxHeight, pA, pB, pC, signPayload, sk_i };
  }

  async function deployFixture() {
    const [deployer] = await hre.ethers.getSigners();
    const { pk_IdP_x, pk_IdP_y, pk_i, PPID, maxHeight, pA, pB, pC, signPayload } = await buildValidCallData();

    const Verifier = await hre.ethers.getContractFactory("PiPkIVerifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const Factory = await hre.ethers.getContractFactory("PPIDWalletFactory");
    const factory = await Factory.deploy(await verifier.getAddress(), pk_IdP_x, pk_IdP_y);
    await factory.waitForDeployment();

    const walletAddr = await factory.computeAddress(PPID);
    await deployer.sendTransaction({ to: walletAddr, value: hre.ethers.parseEther("1.0") });
    await (await factory.deploy(PPID)).wait();
    const wallet = await hre.ethers.getContractAt("PPIDWallet", walletAddr);

    return { deployer, factory, wallet, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, pA, pB, pC, signPayload };
  }

  it("counterfactual address receives funds before deployment", async function () {
    const [deployer] = await hre.ethers.getSigners();
    const { pk_IdP_x, pk_IdP_y, PPID } = await buildValidCallData();
    const Verifier = await hre.ethers.getContractFactory("PiPkIVerifier");
    const verifier = await Verifier.deploy();
    const Factory = await hre.ethers.getContractFactory("PPIDWalletFactory");
    const factory = await Factory.deploy(await verifier.getAddress(), pk_IdP_x, pk_IdP_y);
    const addr = await factory.computeAddress(PPID);
    await deployer.sendTransaction({ to: addr, value: hre.ethers.parseEther("0.5") });
    expect(await hre.ethers.provider.getBalance(addr)).to.equal(hre.ethers.parseEther("0.5"));
    expect(await hre.ethers.provider.getCode(addr)).to.equal("0x");
  });

  it("executes a valid payload and transfers value", async function () {
    const { wallet, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, pA, pB, pC, signPayload } = await deployFixture();
    const recipient = hre.ethers.Wallet.createRandom().address;
    const value = hre.ethers.parseEther("0.1");
    const payload = { to: recipient, value, data: "0x", nonce: await wallet.nonce() };
    const sig = signPayload(payload);

    await expect(wallet.execute(payload, sig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight))
      .to.not.be.reverted;
    expect(await hre.ethers.provider.getBalance(recipient)).to.equal(value);
    expect(await wallet.nonce()).to.equal(1);
  });

  it("rejects nonce reuse (replay)", async function () {
    const { wallet, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, pA, pB, pC, signPayload } = await deployFixture();
    const payload = { to: hre.ethers.Wallet.createRandom().address, value: 0, data: "0x", nonce: await wallet.nonce() };
    const sig = signPayload(payload);
    await (await wallet.execute(payload, sig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight)).wait();

    await expect(
      wallet.execute(payload, sig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight),
    ).to.be.revertedWithCustomError(wallet, "NonceMismatch");
  });

  it("rejects a tampered signature", async function () {
    const { wallet, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, pA, pB, pC, signPayload } = await deployFixture();
    const payload = { to: hre.ethers.Wallet.createRandom().address, value: 0, data: "0x", nonce: await wallet.nonce() };
    const sig = signPayload(payload);
    const tamperedSig = sig.slice(0, -2) + "00"; // flip last byte
    await expect(
      wallet.execute(payload, tamperedSig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight),
    ).to.be.reverted; // ecrecover on a mangled sig either returns address(0) or a wrong address -> BadSignature
  });

  it("rejects an untrusted pk_IdP", async function () {
    const { wallet, pk_i, maxHeight, pA, pB, pC, signPayload } = await deployFixture();
    const payload = { to: hre.ethers.Wallet.createRandom().address, value: 0, data: "0x", nonce: await wallet.nonce() };
    const sig = signPayload(payload);
    await expect(
      wallet.execute(payload, sig, pA, pB, pC, pk_i, 1n, 2n, maxHeight),
    ).to.be.revertedWithCustomError(wallet, "UntrustedIdP");
  });

  it("rejects an expired max_height", async function () {
    const [deployer] = await hre.ethers.getSigners();
    const currentBlock = BigInt(await hre.ethers.provider.getBlockNumber());
    const { pk_IdP_x, pk_IdP_y, pk_i, PPID, maxHeight, pA, pB, pC, signPayload } =
      await buildValidCallData({ maxHeight: currentBlock }); // already expired by the time we submit

    const Verifier = await hre.ethers.getContractFactory("PiPkIVerifier");
    const verifier = await Verifier.deploy();
    const Factory = await hre.ethers.getContractFactory("PPIDWalletFactory");
    const factory = await Factory.deploy(await verifier.getAddress(), pk_IdP_x, pk_IdP_y);
    const walletAddr = await factory.computeAddress(PPID);
    await (await factory.deploy(PPID)).wait();
    const wallet = await hre.ethers.getContractAt("PPIDWallet", walletAddr);

    const payload = { to: deployer.address, value: 0, data: "0x", nonce: await wallet.nonce() };
    const sig = signPayload(payload);
    await expect(
      wallet.execute(payload, sig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight),
    ).to.be.revertedWithCustomError(wallet, "Expired");
  });

  it("increments nonce even when the inner call fails", async function () {
    const { wallet, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, pA, pB, pC, signPayload } = await deployFixture();
    // send more value than the wallet holds -> inner call fails, execute() itself should not revert
    const tooMuch = hre.ethers.parseEther("1000");
    const payload = { to: hre.ethers.Wallet.createRandom().address, value: tooMuch, data: "0x", nonce: await wallet.nonce() };
    const sig = signPayload(payload);
    const tx = await wallet.execute(payload, sig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight);
    const receipt = await tx.wait();
    // execute() returns `ok`; the call itself doesn't revert. Confirm nonce advanced anyway.
    expect(await wallet.nonce()).to.equal(1);
  });
});
