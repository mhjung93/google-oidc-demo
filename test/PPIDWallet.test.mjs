import hre from "hardhat";
import { expect } from "chai";
import { buildEddsa, buildPoseidon } from "circomlibjs";
import { randomBytes } from "crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256, concat, getBytes } from "ethers";
import * as snarkjs from "snarkjs";
import { leafValue, TAG_SESSION, TAG_ACCOUNT } from "../lib/imt.js";
import { createIMTv2 } from "../lib/imt_v2.js";

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

  async function buildValidCallData({ maxHeight = 999_999_999n, chainId, pkIOverride } = {}) {
    const eddsa = await buildEddsa();
    const poseidon = await buildPoseidon();
    const F = eddsa.F;
    const pos = (arr) => poseidon.F.toObject(poseidon(arr));

    const sk_IdP = randomBytes(32);
    const pk_IdP = eddsa.prv2pub(sk_IdP);
    const pk_IdP_x = F.toObject(pk_IdP[0]);
    const pk_IdP_y = F.toObject(pk_IdP[1]);

    const sk_i = secp256k1.utils.randomPrivateKey();
    const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
    // pkIOverride는 "회로가 pk_i를 제약하지 않는다"는 사실을 재현하기 위한 테스트 전용 경로다.
    const pk_i = pkIOverride !== undefined ? pkIOverride : BigInt(ethAddressFromSecp256k1Pubkey(pubUncompressed));

    const rp_nonce = valueToField("rp-nonce-test");
    const rid = valueToField("rid-test");
    const uid = valueToField("12345");
    const salt = valueToField("salt-test");
    const resolvedChainId = chainId ?? valueToField((await hre.ethers.provider.getNetwork()).chainId.toString());

    // PPID/auid는 pi_pk_i.circom의 계정 바인딩 제약(PPID === Poseidon(uid, rid,
    // salt), auid === Poseidon(uid, salt))과 동일한 방식으로 계산해야 한다.
    const PPID = pos([uid, rid, salt]);
    const auid = pos([uid, salt]);
    const arid_i = (rid * rp_nonce) % FIELD_PRIME;
    const auid_i = (PPID * rp_nonce) % FIELD_PRIME;
    const r_token = poseidon.F.toObject(poseidon([pk_i, maxHeight, rp_nonce]));

    const DOMAIN_IDP_TOKEN = valueToField("IDP_TOKEN");
    const msg = poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, maxHeight, resolvedChainId]);
    const sigma_i = eddsa.signPoseidon(sk_IdP, msg);

    // 폐기 트리는 비어 있다(anchor만 존재) — 세션/계정 모두 미폐기 상태의
    // 비멤버십 witness를 만든다. lib/imt_v2.js가 circuits/lib/imt_nonmembership_v2.circom과
    // 같은 리프/해시 규약(Poseidon(3), lowNextIndex 포함)을 쓴다.
    const tree = await createIMTv2(20);
    const sessTarget = await leafValue(TAG_SESSION, r_token);
    const acctTarget = await leafValue(TAG_ACCOUNT, auid);
    const sessWitness = await tree.getNonMembershipWitness(sessTarget);
    const acctWitness = await tree.getNonMembershipWitness(acctTarget);
    const revocationRoot = hre.ethers.zeroPadValue(hre.ethers.toBeHex(BigInt(sessWitness.root)), 32);

    const circuitInput = {
      rp_nonce: rp_nonce.toString(),
      arid_i: arid_i.toString(),
      auid_i: auid_i.toString(),
      r_token: r_token.toString(),
      chain_id: resolvedChainId.toString(),
      S: sigma_i.S.toString(),
      R8x: F.toObject(sigma_i.R8[0]).toString(),
      R8y: F.toObject(sigma_i.R8[1]).toString(),
      uid: uid.toString(),
      rid: rid.toString(),
      salt: salt.toString(),
      sess_lowValue: sessWitness.lowValue,
      sess_lowNextIndex: sessWitness.lowNextIndex,
      sess_lowNextValue: sessWitness.lowNextValue,
      sess_pathElements: sessWitness.pathElements,
      sess_pathIndices: sessWitness.pathIndices,
      acct_lowValue: acctWitness.lowValue,
      acct_lowNextIndex: acctWitness.lowNextIndex,
      acct_lowNextValue: acctWitness.lowNextValue,
      acct_pathElements: acctWitness.pathElements,
      acct_pathIndices: acctWitness.pathIndices,
      pk_i: pk_i.toString(),
      pk_IdP_x: pk_IdP_x.toString(),
      pk_IdP_y: pk_IdP_y.toString(),
      PPID: PPID.toString(),
      max_height: maxHeight.toString(),
      revocationRoot: sessWitness.root,
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      "build/mode2/pi_pk_i_js/pi_pk_i.wasm",
      "build/mode2/pi_pk_i_final.zkey",
    );
    const calldata = JSON.parse("[" + (await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)) + "]");
    const [pA, pB, pC] = calldata;

    // 서명은 체인과 지갑에 묶인다. 도메인 분리가 없으면 같은 배포가 두 체인에 있을 때
    // (CREATE2라 주소가 같다) 한쪽의 execute 트랜잭션을 다른 쪽에 그대로 재제출할 수 있다.
    function signPayload(payload, walletAddress, chainId) {
      if (!walletAddress) throw new Error("signPayload: walletAddress required (domain separation)");
      const payloadHash = getBytes(
        hre.ethers.keccak256(
          hre.ethers.AbiCoder.defaultAbiCoder().encode(
            ["uint256", "address", "address", "uint256", "bytes", "uint256"],
            [chainId, walletAddress, payload.to, payload.value, payload.data, payload.nonce],
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

    return { pk_IdP_x, pk_IdP_y, pk_i, PPID, maxHeight, pA, pB, pC, signPayload, sk_i, revocationRoot };
  }

  async function deployFixture() {
    const [deployer] = await hre.ethers.getSigners();
    const { pk_IdP_x, pk_IdP_y, pk_i, PPID, maxHeight, pA, pB, pC, signPayload, revocationRoot } =
      await buildValidCallData();

    const Registry = await hre.ethers.getContractFactory("RevocationRegistry");
    const registry = await Registry.deploy(deployer.address);
    await registry.waitForDeployment();
    await (await registry.pushRoot(revocationRoot)).wait();

    const Verifier = await hre.ethers.getContractFactory("PiPkIVerifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const Factory = await hre.ethers.getContractFactory("PPIDWalletFactory");
    const factory = await Factory.deploy(await verifier.getAddress(), pk_IdP_x, pk_IdP_y, await registry.getAddress());
    await factory.waitForDeployment();

    const walletAddr = await factory.computeAddress(PPID);
    await deployer.sendTransaction({ to: walletAddr, value: hre.ethers.parseEther("1.0") });
    await (await factory.deploy(PPID)).wait();
    const wallet = await hre.ethers.getContractAt("PPIDWallet", walletAddr);

    return { deployer, factory, registry, wallet, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, pA, pB, pC, signPayload, revocationRoot };
  }

  it("counterfactual address receives funds before deployment", async function () {
    const [deployer] = await hre.ethers.getSigners();
    const { pk_IdP_x, pk_IdP_y, PPID } = await buildValidCallData();
    const Registry = await hre.ethers.getContractFactory("RevocationRegistry");
    const registry = await Registry.deploy(deployer.address);
    const Verifier = await hre.ethers.getContractFactory("PiPkIVerifier");
    const verifier = await Verifier.deploy();
    const Factory = await hre.ethers.getContractFactory("PPIDWalletFactory");
    const factory = await Factory.deploy(await verifier.getAddress(), pk_IdP_x, pk_IdP_y, await registry.getAddress());
    const addr = await factory.computeAddress(PPID);
    await deployer.sendTransaction({ to: addr, value: hre.ethers.parseEther("0.5") });
    expect(await hre.ethers.provider.getBalance(addr)).to.equal(hre.ethers.parseEther("0.5"));
    expect(await hre.ethers.provider.getCode(addr)).to.equal("0x");
  });

  it("executes a valid payload and transfers value", async function () {
    const { wallet, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, pA, pB, pC, signPayload, revocationRoot } = await deployFixture();
    const recipient = hre.ethers.Wallet.createRandom().address;
    const value = hre.ethers.parseEther("0.1");
    const payload = { to: recipient, value, data: "0x", nonce: await wallet.nonce() };
    const sig = signPayload(payload, wallet.target, (await hre.ethers.provider.getNetwork()).chainId);

    await expect(wallet.execute(payload, sig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, revocationRoot))
      .to.not.be.reverted;
    expect(await hre.ethers.provider.getBalance(recipient)).to.equal(value);
    expect(await wallet.nonce()).to.equal(1);
  });

  it("rejects nonce reuse (replay)", async function () {
    const { wallet, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, pA, pB, pC, signPayload, revocationRoot } = await deployFixture();
    const payload = { to: hre.ethers.Wallet.createRandom().address, value: 0, data: "0x", nonce: await wallet.nonce() };
    const sig = signPayload(payload, wallet.target, (await hre.ethers.provider.getNetwork()).chainId);
    await (await wallet.execute(payload, sig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, revocationRoot)).wait();

    await expect(
      wallet.execute(payload, sig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, revocationRoot),
    ).to.be.revertedWithCustomError(wallet, "NonceMismatch");
  });

  it("rejects a tampered signature", async function () {
    const { wallet, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, pA, pB, pC, signPayload, revocationRoot } = await deployFixture();
    const payload = { to: hre.ethers.Wallet.createRandom().address, value: 0, data: "0x", nonce: await wallet.nonce() };
    const sig = signPayload(payload, wallet.target, (await hre.ethers.provider.getNetwork()).chainId);
    // 서명 본문(r)의 한 자리를 바꾼다. 예전에는 마지막 바이트(v)를 "00"으로 바꿨는데,
    // 그러면 실제로 검증되는 것은 "잘못된 서명을 거부한다"가 아니라 "잘못된 v를 거부한다"
    // 였다(ecrecover는 v가 27/28이 아니면 그냥 0을 돌려준다). 같은 패턴이
    // tests/test_par_endpoint.js에서는 실행의 절반에서 단언을 무력화하고 있었다.
    const flipped = sig[10] === "0" ? "1" : "0";
    const tamperedSig = sig.slice(0, 10) + flipped + sig.slice(11);
    expect(tamperedSig).to.not.equal(sig);
    await expect(
      wallet.execute(payload, tamperedSig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, revocationRoot),
    ).to.be.reverted; // ecrecover on a mangled sig either returns address(0) or a wrong address -> BadSignature
  });

  it("rejects a signature that is not bound to this chain and wallet", async function () {
    const { wallet, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, pA, pB, pC, revocationRoot } = await deployFixture();
    const payload = { to: hre.ethers.Wallet.createRandom().address, value: 0, data: "0x", nonce: await wallet.nonce() };

    // 도메인 분리 이전 형식(체인·지갑 없이 payload 필드만)으로 서명한다. 이 형식이
    // 통과하면 같은 배포가 있는 다른 체인/다른 지갑에 그대로 재제출할 수 있다.
    const legacyHash = getBytes(
      hre.ethers.keccak256(
        hre.ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "uint256", "bytes", "uint256"],
          [payload.to, payload.value, payload.data, payload.nonce],
        ),
      ),
    );
    const { sk_i } = await buildValidCallData(); // 서명 키만 필요하다(이 증명은 안 쓴다)
    const raw = secp256k1.sign(legacyHash, sk_i);
    const legacySig = concat([
      "0x" + raw.r.toString(16).padStart(64, "0"),
      "0x" + raw.s.toString(16).padStart(64, "0"),
      "0x" + (27 + raw.recovery).toString(16).padStart(2, "0"),
    ]);

    await expect(
      wallet.execute(payload, legacySig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, revocationRoot),
    ).to.be.revertedWithCustomError(wallet, "BadSignature");
  });

  it("rejects pk_i = 0 instead of letting ecrecover's address(0) pass the signature check", async function () {
    // 회로는 pk_i != 0을 제약하지 않고, IdP는 pk_i를 볼 수 없다(pi_arid_i에서 private).
    // 그래서 pk_i = 0인 크레덴셜이 실제로 발급될 수 있다. 그 경우 잘못된 v를 넣은
    // 서명에 대해 ecrecover가 address(0)을 반환하고, address(uint160(0))과 같아져
    // 서명 검사가 공허하게 통과한다 — 그 지갑은 누구나 임의 payload로 실행할 수 있다.
    const [deployer] = await hre.ethers.getSigners();
    const zero = await buildValidCallData({ pkIOverride: 0n });

    const Registry = await hre.ethers.getContractFactory("RevocationRegistry");
    const registry = await Registry.deploy(deployer.address);
    await registry.waitForDeployment();
    await (await registry.pushRoot(zero.revocationRoot)).wait();
    const Verifier = await hre.ethers.getContractFactory("PiPkIVerifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();
    const Factory = await hre.ethers.getContractFactory("PPIDWalletFactory");
    const factory = await Factory.deploy(
      await verifier.getAddress(), zero.pk_IdP_x, zero.pk_IdP_y, await registry.getAddress(),
    );
    await factory.waitForDeployment();
    const walletAddr = await factory.computeAddress(zero.PPID);
    await deployer.sendTransaction({ to: walletAddr, value: hre.ethers.parseEther("1.0") });
    await (await factory.deploy(zero.PPID)).wait();
    const zeroWallet = await hre.ethers.getContractAt("PPIDWallet", walletAddr);

    const payload = { to: hre.ethers.Wallet.createRandom().address, value: 0, data: "0x", nonce: await zeroWallet.nonce() };
    // v = 0 은 유효하지 않아 ecrecover가 address(0)을 돌려준다.
    const garbageSig = "0x" + "11".repeat(64) + "00";

    await expect(
      zeroWallet.execute(
        payload, garbageSig, zero.pA, zero.pB, zero.pC, 0n,
        zero.pk_IdP_x, zero.pk_IdP_y, zero.maxHeight, zero.revocationRoot,
      ),
    ).to.be.revertedWithCustomError(zeroWallet, "BadSignature");
  });

  it("emits Executed with success=false when the inner call fails", async function () {
    // ok는 top-level 트랜잭션 반환값이라 영수증에 없다. 이벤트가 없으면 잔액보다 큰
    // value를 보낸 트랜잭션이 status=1로 채굴되고 nonce만 소모된 채 자금은 안 움직이는데
    // 사용자도 RP도 알 수 없다.
    const { wallet, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, pA, pB, pC, signPayload, revocationRoot } = await deployFixture();
    const tooMuch = hre.ethers.parseEther("1000"); // 지갑 잔액(1 ETH)보다 크다
    const payload = { to: hre.ethers.Wallet.createRandom().address, value: tooMuch, data: "0x", nonce: await wallet.nonce() };
    const sig = signPayload(payload, wallet.target, (await hre.ethers.provider.getNetwork()).chainId);

    await expect(wallet.execute(payload, sig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, revocationRoot))
      .to.emit(wallet, "Executed")
      .withArgs(payload.nonce, payload.to, tooMuch, false);
  });

  it("rejects an untrusted pk_IdP", async function () {
    const { wallet, pk_i, maxHeight, pA, pB, pC, signPayload, revocationRoot } = await deployFixture();
    const payload = { to: hre.ethers.Wallet.createRandom().address, value: 0, data: "0x", nonce: await wallet.nonce() };
    const sig = signPayload(payload, wallet.target, (await hre.ethers.provider.getNetwork()).chainId);
    await expect(
      wallet.execute(payload, sig, pA, pB, pC, pk_i, 1n, 2n, maxHeight, revocationRoot),
    ).to.be.revertedWithCustomError(wallet, "UntrustedIdP");
  });

  it("rejects an expired max_height", async function () {
    const [deployer] = await hre.ethers.getSigners();
    const currentBlock = BigInt(await hre.ethers.provider.getBlockNumber());
    const { pk_IdP_x, pk_IdP_y, pk_i, PPID, maxHeight, pA, pB, pC, signPayload, revocationRoot } =
      await buildValidCallData({ maxHeight: currentBlock }); // already expired by the time we submit

    const Registry = await hre.ethers.getContractFactory("RevocationRegistry");
    const registry = await Registry.deploy(deployer.address);
    await (await registry.pushRoot(revocationRoot)).wait();

    const Verifier = await hre.ethers.getContractFactory("PiPkIVerifier");
    const verifier = await Verifier.deploy();
    const Factory = await hre.ethers.getContractFactory("PPIDWalletFactory");
    const factory = await Factory.deploy(await verifier.getAddress(), pk_IdP_x, pk_IdP_y, await registry.getAddress());
    const walletAddr = await factory.computeAddress(PPID);
    await (await factory.deploy(PPID)).wait();
    const wallet = await hre.ethers.getContractAt("PPIDWallet", walletAddr);

    const payload = { to: deployer.address, value: 0, data: "0x", nonce: await wallet.nonce() };
    const sig = signPayload(payload, wallet.target, (await hre.ethers.provider.getNetwork()).chainId);
    await expect(
      wallet.execute(payload, sig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, revocationRoot),
    ).to.be.revertedWithCustomError(wallet, "Expired");
  });

  it("increments nonce even when the inner call fails", async function () {
    const { wallet, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, pA, pB, pC, signPayload, revocationRoot } = await deployFixture();
    // send more value than the wallet holds -> inner call fails, execute() itself should not revert
    const tooMuch = hre.ethers.parseEther("1000");
    const payload = { to: hre.ethers.Wallet.createRandom().address, value: tooMuch, data: "0x", nonce: await wallet.nonce() };
    const sig = signPayload(payload, wallet.target, (await hre.ethers.provider.getNetwork()).chainId);
    const tx = await wallet.execute(payload, sig, pA, pB, pC, pk_i, pk_IdP_x, pk_IdP_y, maxHeight, revocationRoot);
    const receipt = await tx.wait();
    // execute() returns `ok`; the call itself doesn't revert. Confirm nonce advanced anyway.
    expect(await wallet.nonce()).to.equal(1);
  });
});
