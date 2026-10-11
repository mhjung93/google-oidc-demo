# PPID 기반 트랜잭션 제출(B1) 구현 계획

> **에이전트 작업자용:** 이 계획을 Task 단위로 실행하려면 superpowers:subagent-driven-development(추천) 또는 superpowers:executing-plans를 사용하세요. 각 단계는 체크박스(`- [ ]`) 문법으로 추적됩니다.

**목표:** wallet이 로그인(Step 1~15) 완료 후, `PPID`를 논리적 주체로 하는 블록체인 트랜잭션을 실제 온체인 강제 검증(zk 증명 + 서명)을 거쳐 제출할 수 있게 한다.

**아키텍처:** 새 `pi_pk_i` zk 회로(BabyJubJub/EdDSA-Poseidon) + `CREATE2` 기반 PPID별 지갑 컨트랙트(secp256k1 `ecrecover`로 payload 서명 검증) + `wallet_agent.js`의 새 엔드포인트.

**기술 스택:** circom 2.1.6, snarkjs 0.7.5, Solidity 0.8.24 + Hardhat, `@noble/curves/secp256k1`, ethers v6.

## 전역 제약사항

- `RP_REG` 서명(`custom_idp.js`의 `/register_rp`, `psSign`)은 절대 건드리지 않는다.
- `circuits/pi_arid_i.circom`, `circuits/pi_ppid.circom`은 수정하지 않는다.
- 모든 필드 원소는 JSON에서 10진수 문자열로 표현한다(hex, raw circomlibjs 내부 표현 금지).
- 이 계획의 모든 회로/컨트랙트 코드는 계획 작성 중 실제로 컴파일하고, 유효한 값과 조작된 값
  둘 다로 witness/트랜잭션 실행까지 검증을 마쳤다 — Task 1, 3의 코드는 전부 이미 검증된
  코드를 그대로 옮긴 것이다.
- `pk_i`는 이제 "공개키 블롭을 해시로 뭉갠 값"이 아니라 **secp256k1 공개키에서 뽑은
  이더리움 주소**(`uint256`으로 캐스팅된 20바이트 주소)다 — 온체인 `ecrecover` 결과와 별도
  변환 없이 직접 비교하기 위함.
- `sk_i`(세션 서명 개인키)는 Step 8 생성 시점에 버려지지 않고 `wallet_state.json`에
  저장된다(기존 `mode2WalletSalt`와 동일한 패턴) — 로그인 이후의 트랜잭션 제출 단계에서
  같은 키로 payload에 서명해야 하기 때문.

---

## Task 1: `circuits/pi_pk_i.circom` 회로

**파일:**
- 생성: `circuits/pi_pk_i.circom`
- 수정: `scripts/build_mode2_circuits.sh`
- 생성: `tests/test_pi_pk_i.mjs`

**인터페이스:**
- 산출물: `build/mode2/pi_pk_i_js/pi_pk_i.wasm`, `build/mode2/pi_pk_i_final.zkey`,
  `build/mode2/pi_pk_i_vkey.json`
- Public input 순서: `[pk_i, pk_IdP_x, pk_IdP_y, PPID, max_height]` (Task 2/3에서 이 순서
  그대로 Solidity verifier의 `uint[5] _pubSignals`로 소비됨)

- [ ] **Step 1: 회로 작성**

```circom
pragma circom 2.0.0;

include "lib/eddsaposeidon.circom";
include "lib/poseidon.circom";

template PiPkI() {
    // Private inputs
    signal input rp_nonce;
    signal input arid_i;
    signal input auid_i;
    signal input r_token;
    signal input chain_id;
    signal input S;
    signal input R8x;
    signal input R8y;

    // Public inputs
    signal input pk_i;
    signal input pk_IdP_x;
    signal input pk_IdP_y;
    signal input PPID;
    signal input max_height;

    // DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN'), precomputed in JS (same value
    // custom_idp.js/server.js/wallet_agent.js already use for auth token signing/verifying).
    var DOMAIN_IDP_TOKEN = 1351534856589225444686;

    // auid_i = PPID * rp_nonce
    auid_i === PPID * rp_nonce;

    // r_token = Poseidon(pk_i, max_height, rp_nonce)  (same formula as the existing
    // Step 8 tokenNonce computation)
    component tokenNonceHasher = Poseidon(3);
    tokenNonceHasher.inputs[0] <== pk_i;
    tokenNonceHasher.inputs[1] <== max_height;
    tokenNonceHasher.inputs[2] <== rp_nonce;
    r_token === tokenNonceHasher.out;

    // msg = Poseidon([DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id])
    // (same 6-field construction custom_idp.js uses to sign the auth token)
    component msgHasher = Poseidon(6);
    msgHasher.inputs[0] <== DOMAIN_IDP_TOKEN;
    msgHasher.inputs[1] <== arid_i;
    msgHasher.inputs[2] <== auid_i;
    msgHasher.inputs[3] <== r_token;
    msgHasher.inputs[4] <== max_height;
    msgHasher.inputs[5] <== chain_id;

    // SigVerify(pk_IdP, sigma_i) == True
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== pk_IdP_x;
    sigVerifier.Ay <== pk_IdP_y;
    sigVerifier.S <== S;
    sigVerifier.R8x <== R8x;
    sigVerifier.R8y <== R8y;
    sigVerifier.M <== msgHasher.out;
}

component main {public [pk_i, pk_IdP_x, pk_IdP_y, PPID, max_height]} = PiPkI();
```

- [ ] **Step 2: `scripts/build_mode2_circuits.sh`에 빌드 단계 추가**

Find (현재 파일 끝부분):

```bash
compile_circuit "pi_arid_i"
compile_circuit "pi_ppid"

echo "🎉 All Mode 2 circuits compiled successfully in $BUILD_DIR"
```

Replace with:

```bash
compile_circuit "pi_arid_i"
compile_circuit "pi_ppid"
compile_circuit "pi_pk_i"

# pi_pk_i는 온체인에서도 검증해야 하므로, Solidity verifier도 같이 export한다
# (pi_arid_i/pi_ppid는 오프체인 검증만 하므로 이 단계가 필요 없음).
echo "▶ Exporting Solidity verifier for pi_pk_i..."
npx snarkjs zkey export solidityverifier "$BUILD_DIR/pi_pk_i_final.zkey" "contracts/PiPkIVerifier.sol"
sed -i 's/contract Groth16Verifier/contract PiPkIVerifier/' "contracts/PiPkIVerifier.sol"

echo "🎉 All Mode 2 circuits compiled successfully in $BUILD_DIR"
```

- [ ] **Step 3: 실제로 빌드 스크립트 실행**

Run: `bash scripts/build_mode2_circuits.sh`
Expected: `build/mode2/pi_pk_i_*` 파일들과 `contracts/PiPkIVerifier.sol`이 생성됨. 콘솔에
`✅ pi_pk_i build complete.`와 `🎉 All Mode 2 circuits compiled successfully`가 출력됨.

- [ ] **Step 4: 회로 검증 테스트 작성**

```js
// tests/test_pi_pk_i.mjs
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { randomBytes } from 'crypto';

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function valueToField(value) {
  if (typeof value === 'bigint') return value % FIELD_PRIME;
  if (typeof value === 'number') return BigInt(value) % FIELD_PRIME;
  const str = String(value);
  if (str.startsWith('0x')) return BigInt(str) % FIELD_PRIME;
  if (/^[0-9]+$/.test(str)) return BigInt(str) % FIELD_PRIME;
  const bytes = new TextEncoder().encode(str);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return BigInt(`0x${hex || '0'}`) % FIELD_PRIME;
}

async function test() {
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = eddsa.F;

  const sk_IdP = randomBytes(32);
  const pk_IdP = eddsa.prv2pub(sk_IdP);

  const rp_nonce = valueToField('rp-nonce-test');
  const rid = valueToField('rid-test');
  const uid = valueToField('12345');
  const salt = valueToField('salt-test');
  const pk_i = valueToField('0x04deadbeef1234567890abcdef');
  const max_height = valueToField('1000');
  const chain_id = valueToField('1337');

  const PPID = (uid * rid * salt) % FIELD_PRIME;
  const arid_i = (rid * rp_nonce) % FIELD_PRIME;
  const auid_i = (PPID * rp_nonce) % FIELD_PRIME;
  const r_token = poseidon.F.toObject(poseidon([pk_i, max_height, rp_nonce]));

  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const msgFields = [DOMAIN_IDP_TOKEN, arid_i, auid_i, r_token, max_height, chain_id];
  const msg = poseidon(msgFields);
  const sig = eddsa.signPoseidon(sk_IdP, msg);

  const input = {
    rp_nonce: rp_nonce.toString(),
    arid_i: arid_i.toString(),
    auid_i: auid_i.toString(),
    r_token: r_token.toString(),
    chain_id: chain_id.toString(),
    S: sig.S.toString(),
    R8x: F.toObject(sig.R8[0]).toString(),
    R8y: F.toObject(sig.R8[1]).toString(),
    pk_i: pk_i.toString(),
    pk_IdP_x: F.toObject(pk_IdP[0]).toString(),
    pk_IdP_y: F.toObject(pk_IdP[1]).toString(),
    PPID: PPID.toString(),
    max_height: max_height.toString(),
  };

  const wc = await import('../build/mode2/pi_pk_i_js/witness_calculator.js');
  const fs = await import('fs');
  const wasmBuffer = await fs.promises.readFile('build/mode2/pi_pk_i_js/pi_pk_i.wasm');
  const witnessCalculator = await wc.default(wasmBuffer);

  // 1. 유효한 값 -> witness 계산 성공해야 함
  await witnessCalculator.calculateWitness(input, true);
  console.log('✅ Valid witness computed successfully.');

  // 2. auid_i 조작 -> witness 계산 실패해야 함 (constraint 위반)
  const tamperedInput = { ...input, auid_i: (auid_i + 1n).toString() };
  try {
    await witnessCalculator.calculateWitness(tamperedInput, true);
    console.error('FAIL: tampered auid_i was accepted');
    process.exit(1);
  } catch (err) {
    console.log('✅ Tampered auid_i correctly rejected:', err.message);
  }

  console.log('pi_pk_i circuit test: ALL CHECKS PASSED');
}

test();
```

Note: `witness_calculator.js` (not `.cjs`) is the raw output of `circom --wasm` before any
ESM-compat renaming — `pi_arid_i_js`/`pi_ppid_js` get renamed to `.cjs` by
`build_mode2_circuits.sh`'s existing patch step, and `pi_pk_i_js` will too (Step 2's
`compile_circuit "pi_pk_i"` call goes through the same patching code). Adjust the import
filename to `witness_calculator.cjs` if that's what's actually on disk after Step 3 — verify
with `ls build/mode2/pi_pk_i_js/` before finalizing this file.

- [ ] **Step 5: 테스트 실행**

Run: `node tests/test_pi_pk_i.mjs`
Expected: `pi_pk_i circuit test: ALL CHECKS PASSED`, exit code 0.

- [ ] **Step 6: 커밋**

```bash
git add circuits/pi_pk_i.circom scripts/build_mode2_circuits.sh tests/test_pi_pk_i.mjs \
  build/mode2/pi_pk_i_js build/mode2/pi_pk_i.r1cs build/mode2/pi_pk_i.sym \
  build/mode2/pi_pk_i_0000.zkey build/mode2/pi_pk_i_final.zkey build/mode2/pi_pk_i_vkey.json \
  contracts/PiPkIVerifier.sol
git commit -m "feat(mode2): add pi_pk_i circuit for post-login transaction submission"
```

(빌드 산출물(`build/mode2/pi_pk_i_*`, `contracts/PiPkIVerifier.sol`)을 커밋하는 건 기존
`pi_arid_i`/`pi_ppid` 산출물이 이미 저장소에 커밋돼 있는 것과 같은 관례를 따르는 것 —
`git status`로 기존 `build/mode2/pi_arid_i_*` 등이 이미 추적 중인지 먼저 확인.)

---

## Task 2: `contracts/PPIDWallet.sol` + `contracts/PPIDWalletFactory.sol`

**파일:**
- 생성: `contracts/PPIDWallet.sol`
- 생성: `contracts/PPIDWalletFactory.sol`

**인터페이스:**
- 소비: Task 1의 `contracts/PiPkIVerifier.sol` (`PiPkIVerifier.verifyProof(uint[2], uint[2][2], uint[2], uint[5])`)
- 제공: `PPIDWalletFactory.deploy(uint256 ppid) returns (address)`,
  `PPIDWalletFactory.computeAddress(uint256 ppid) view returns (address)`,
  `PPIDWallet.execute(Payload, bytes sig, uint[2] pA, uint[2][2] pB, uint[2] pC, uint256 pk_i, uint256 pk_IdP_x, uint256 pk_IdP_y, uint256 max_height) returns (bool)`

- [ ] **Step 1: `PPIDWallet.sol` 작성**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./PiPkIVerifier.sol";

contract PPIDWallet {
    uint256 public immutable ppid;
    PiPkIVerifier public immutable verifier;
    uint256 public immutable trustedPkIdPX;
    uint256 public immutable trustedPkIdPY;
    uint256 public nonce;

    struct Payload {
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
    }

    error NonceMismatch(uint256 expected, uint256 got);
    error BadSignature();
    error UntrustedIdP();
    error InvalidProof();
    error Expired(uint256 currentBlock, uint256 maxHeight);

    constructor(uint256 _ppid, address _verifier, uint256 _pkIdPX, uint256 _pkIdPY) {
        ppid = _ppid;
        verifier = PiPkIVerifier(_verifier);
        trustedPkIdPX = _pkIdPX;
        trustedPkIdPY = _pkIdPY;
    }

    function execute(
        Payload calldata payload,
        bytes calldata sig,
        uint[2] calldata proofA,
        uint[2][2] calldata proofB,
        uint[2] calldata proofC,
        uint256 pk_i,
        uint256 pk_IdP_x,
        uint256 pk_IdP_y,
        uint256 max_height
    ) external returns (bool ok) {
        if (payload.nonce != nonce) revert NonceMismatch(nonce, payload.nonce);

        bytes32 payloadHash = keccak256(abi.encode(payload.to, payload.value, payload.data, payload.nonce));
        address recovered = recoverSigner(payloadHash, sig);
        // pk_i is the Ethereum address derived from the secp256k1 session public key
        // (not a hash of the raw pubkey bytes), so it compares directly against
        // ecrecover's output with no extra derivation needed.
        if (recovered != address(uint160(pk_i))) revert BadSignature();

        if (pk_IdP_x != trustedPkIdPX || pk_IdP_y != trustedPkIdPY) revert UntrustedIdP();

        uint[5] memory pubSignals = [pk_i, pk_IdP_x, pk_IdP_y, ppid, max_height];
        if (!verifier.verifyProof(proofA, proofB, proofC, pubSignals)) revert InvalidProof();

        if (block.number > max_height) revert Expired(block.number, max_height);

        // 검증 통과 후 실행 결과와 무관하게 nonce를 증가시킨다 — 실행이 실패해도
        // 서명된 payload를 나중에 다시 재생(replay)하지 못하게 막기 위함
        // (Gnosis Safe 등 기존 스마트컨트랙트 지갑 관례와 동일).
        nonce += 1;

        (ok, ) = payload.to.call{value: payload.value}(payload.data);
    }

    function recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        return ecrecover(hash, v, r, s);
    }

    receive() external payable {}
}
```

- [ ] **Step 2: `PPIDWalletFactory.sol` 작성**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./PPIDWallet.sol";

contract PPIDWalletFactory {
    address public immutable verifier;
    uint256 public immutable trustedPkIdPX;
    uint256 public immutable trustedPkIdPY;

    constructor(address _verifier, uint256 _pkIdPX, uint256 _pkIdPY) {
        verifier = _verifier;
        trustedPkIdPX = _pkIdPX;
        trustedPkIdPY = _pkIdPY;
    }

    function computeAddress(uint256 ppid) public view returns (address) {
        bytes32 salt = bytes32(ppid);
        bytes memory bytecode = abi.encodePacked(
            type(PPIDWallet).creationCode,
            abi.encode(ppid, verifier, trustedPkIdPX, trustedPkIdPY)
        );
        return address(uint160(uint256(keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(bytecode))
        ))));
    }

    function deploy(uint256 ppid) external returns (address wallet) {
        wallet = computeAddress(ppid);
        if (wallet.code.length > 0) return wallet;
        bytes32 salt = bytes32(ppid);
        PPIDWallet deployed = new PPIDWallet{salt: salt}(ppid, verifier, trustedPkIdPX, trustedPkIdPY);
        require(address(deployed) == wallet, "CREATE2 address mismatch");
        return address(deployed);
    }
}
```

- [ ] **Step 3: 컴파일 확인**

Run: `npx hardhat compile`
Expected: `Compiled N Solidity files successfully` — 에러 없음.

- [ ] **Step 4: 커밋**

```bash
git add contracts/PPIDWallet.sol contracts/PPIDWalletFactory.sol
git commit -m "feat(mode2): add PPIDWallet/PPIDWalletFactory contracts (CREATE2, secp256k1 ecrecover + pi_pk_i verification)"
```

---

## Task 3: Hardhat 통합 테스트

**파일:**
- 생성: `test/PPIDWallet.test.mjs`

**인터페이스:**
- 소비: Task 1/2의 회로 산출물과 컨트랙트

- [ ] **Step 1: 테스트 작성**

```js
// test/PPIDWallet.test.mjs
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
```

- [ ] **Step 2: 테스트 실행**

Run: `npx hardhat test test/PPIDWallet.test.mjs`
Expected: 7개 테스트 전부 통과. (증명 생성이 케이스마다 있어서 몇 분 걸릴 수 있음 — 정상.)

- [ ] **Step 3: 커밋**

```bash
git add test/PPIDWallet.test.mjs
git commit -m "test(mode2): add Hardhat test suite for PPIDWallet/PPIDWalletFactory"
```

---

## Task 4: `wallet_agent.js` — Step 8 세션 키를 secp256k1로 전환

**파일:**
- 수정: `wallet_agent.js:1-9`(import), `wallet_agent.js:190-217`(state 함수들), `wallet_agent.js:283-292`(키 생성부)

**인터페이스:**
- 소비: `@noble/curves/secp256k1`, `ethers`의 `keccak256`(이미 프로젝트 의존성)
- 산출: `getOrCreateSessionKey()` — `{ sk_i: Uint8Array, pk_i: bigint, address: string }` 반환,
  `wallet_state.json`에 `mode2SessionKey`(hex) 필드로 영속화
- Task 5가 `getOrCreateSessionKey()`를 재사용함

- [ ] **Step 1: import 추가**

Find (`wallet_agent.js:1-9`):

```js
import express from 'express';
import cors from 'cors';
import * as snarkjs from 'snarkjs';
import { buildPoseidon, buildEddsa } from 'circomlibjs';
import mcl from 'mcl-wasm';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { webcrypto } from 'crypto';
```

Replace with:

```js
import express from 'express';
import cors from 'cors';
import * as snarkjs from 'snarkjs';
import { buildPoseidon, buildEddsa } from 'circomlibjs';
import mcl from 'mcl-wasm';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { webcrypto } from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256 } from 'ethers';
```

- [ ] **Step 2: 세션 키 생성/영속화 함수 추가**

`getOrCreateWalletSalt()` 함수(`wallet_agent.js:208-217`) 바로 뒤에 추가:

```js
// pk_i의 이더리움 주소 계산 — 65바이트(0x04 prefix) 비압축 공개키에서 프리픽스를 떼고
// keccak256(X||Y)의 마지막 20바이트를 취한다. 표준 이더리움 주소 유도 공식.
function ethAddressFromSecp256k1Pubkey(pubKeyUncompressed65) {
  const xy = pubKeyUncompressed65.slice(1);
  const hash = keccak256(xy);
  return '0x' + hash.slice(-40);
}

// 세션 서명키(pk_i/sk_i): P-256 대신 secp256k1을 쓴다 — 이유는 PPIDWallet 컨트랙트가
// payload 서명을 회로 밖에서 ecrecover로 직접 검증하기 때문(온체인 ecrecover는
// secp256k1 전용). WebCrypto의 SubtleCrypto는 secp256k1을 지원하지 않으므로
// @noble/curves를 쓴다. 로그인 시점(Step 8)에 한 번 생성해서 state 파일에 저장해두고,
// 이후 트랜잭션 제출 단계(다른 HTTP 요청)에서 같은 키를 재사용한다 — 그전엔 이 키가
// 요청 하나 처리 후 버려졌었는데, payload 서명을 나중에 또 해야 하므로 영속화가
// 필요해졌다.
function getOrCreateSessionKey() {
  const state = readState();
  if (!state.mode2SessionKey) {
    const sk_i = secp256k1.utils.randomPrivateKey();
    state.mode2SessionKey = bytesToHex(sk_i);
    writeState(state);
  }
  const sk_i = Uint8Array.from(Buffer.from(state.mode2SessionKey, 'hex'));
  const pubUncompressed = secp256k1.getPublicKey(sk_i, false);
  const address = ethAddressFromSecp256k1Pubkey(pubUncompressed);
  return { sk_i, pk_i: BigInt(address), address, publicKeyHex: `0x${bytesToHex(pubUncompressed)}` };
}
```

- [ ] **Step 3: `/generateStep8Proofs`의 키 생성부 교체**

Find (`wallet_agent.js:283-292`):

```js
    // 세션 서명키는 이 프로세스 안에서만 생성하고, pk_i(공개 필드값)만 내보낸다.
    const signingKeyPair = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const publicKeyRaw = new Uint8Array(await subtle.exportKey('raw', signingKeyPair.publicKey));
    const publicKeyHex = `0x${bytesToHex(publicKeyRaw)}`;
    const pkField = valueToField(publicKeyHex);
    console.log(`[WalletAgent][Step 8] signing key pair generated. publicKey: ${preview(publicKeyHex, 34)} ${ms(start)}`);
```

Replace with:

```js
    // 세션 서명키: secp256k1, wallet_state.json에 영속화됨 (getOrCreateSessionKey 참고).
    // pk_i는 이제 공개키 블롭의 해시가 아니라 그 공개키의 이더리움 주소 자체다.
    const { pk_i: pkField, publicKeyHex } = getOrCreateSessionKey();
    console.log(`[WalletAgent][Step 8] session key ready. address(pk_i): ${preview(publicKeyHex, 34)} ${ms(start)}`);
```

(`pkField`는 이후 코드에서 그대로 `tokenNonce`/`aridInputs.pk_i` 계산에 쓰이므로, 변수명은
바꾸지 않고 값의 출처만 바뀐다.)

- [ ] **Step 4: 문법 검사 + 회귀 확인**

Run: `node --check wallet_agent.js`
Expected: 에러 없음.

Run: `node -e "import('./wallet_agent.js')" 2>&1 | head -20` — 모듈 로드 시 즉시 에러 나는지만
빠르게 확인(포트 바인딩까지는 안 가도 import 단계 문법/참조 오류는 여기서 드러남). 실제
동작 확인은 Task 6의 엔드투엔드 테스트에서.

- [ ] **Step 5: 커밋**

```bash
git add wallet_agent.js
git commit -m "feat(mode2): switch Step 8 session key from P-256 to secp256k1, persist sk_i"
```

---

## Task 5: `wallet_agent.js` — `POST /submitTransaction` 엔드포인트

**파일:**
- 수정: `wallet_agent.js` (import 추가, 새 라우트 추가)

**인터페이스:**
- 소비: Task 1의 `build/mode2/pi_pk_i_js/pi_pk_i.wasm` + `pi_pk_i_final.zkey`, Task 4의
  `getOrCreateSessionKey()`
- 요청 본문: `{ to, value, data, currentNonce, business: {arid_i, auid_i, r_token, chain_id}, rpNonce }`
  (`business`는 Step 8 응답에 이미 있던 필드들을 클라이언트가 그대로 되돌려 보내는 것 —
  `rpNonce`도 마찬가지로 클라이언트가 이미 갖고 있음)
- 응답: `{ payload, sig, proofA, proofB, proofC, pk_i, pk_IdP_x, pk_IdP_y, max_height }` —
  브라우저가 이 값을 그대로 `PPIDWallet.execute(...)` 트랜잭션 인자로 씀

- [ ] **Step 1: import 추가**

Find (Task 4에서 이미 추가한 import 블록):

```js
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256 } from 'ethers';
```

Replace with:

```js
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256, AbiCoder } from 'ethers';
```

- [ ] **Step 2: 엔드포인트 추가**

`/verifyIdPAuthToken` 라우트(기존 코드, 계획 문서
`docs/superpowers/plans/2026-07-14-eddsa-poseidon-auth-token-migration.md`의 Task 5에서
추가됨) 바로 뒤에 추가:

```js
app.post('/submitTransaction', async (req, res) => {
  const start = cursor();
  try {
    const { to, value, data, currentNonce, business, rpNonce } = req.body ?? {};
    if (!to) throw new Error('to is required');
    if (value === undefined) throw new Error('value is required');
    if (currentNonce === undefined) throw new Error('currentNonce is required');
    if (!business?.arid_i || !business?.auid_i) throw new Error('business.arid_i/auid_i are required');
    if (!rpNonce) throw new Error('rpNonce is required');

    await ensureEdDSA();
    if (!poseidon) throw new Error('Poseidon not initialized yet');

    const idpPublicKeys = await getIdpPublicKeys();
    const pkIdPRaw = idpPublicKeys?.pk_IdP;
    if (!pkIdPRaw || pkIdPRaw.length !== 2) throw new Error('IdP EdDSA public key not available');

    const { sk_i, pk_i } = getOrCreateSessionKey();

    const payloadData = data ?? '0x';
    const payload = { to, value: value.toString(), data: payloadData, nonce: currentNonce.toString() };

    // payloadHash는 PPIDWallet.execute()의 keccak256(abi.encode(to, value, data, nonce))와
    // 정확히 같은 방식으로 계산해야 한다 — 여기서 안 맞으면 컨트랙트의 ecrecover 결과가
    // 다른 주소로 나와서 항상 BadSignature로 거부된다.
    const payloadHash = keccak256(
      AbiCoder.defaultAbiCoder().encode(
        ['address', 'uint256', 'bytes', 'uint256'],
        [payload.to, payload.value, payload.data, payload.nonce],
      ),
    );
    const sigRaw = secp256k1.sign(payloadHash.slice(2), sk_i);
    const sig =
      '0x' +
      sigRaw.r.toString(16).padStart(64, '0') +
      sigRaw.s.toString(16).padStart(64, '0') +
      (27 + sigRaw.recovery).toString(16).padStart(2, '0');

    const rp_nonce = valueToField(rpNonce);
    const arid_i = valueToField(business.arid_i);
    const auid_i = valueToField(business.auid_i);
    const r_token = valueToField(business.r_token ?? business.tokenNonce);
    const chain_id = valueToField(business.chain_id ?? business.chainId);
    const maxHeightField = valueToField(business.maxHeight ?? business.max_height);

    const pkIdP_x = BigInt(pkIdPRaw[0]);
    const pkIdP_y = BigInt(pkIdPRaw[1]);

    // sigma_i (the auth token's own EdDSA-Poseidon signature) must come from the request
    // body too — the client already has it as walletReceivedIdPToken.signature.{R8,S}.
    const idpTokenSig = req.body?.idpToken?.signature;
    if (!idpTokenSig?.R8 || !idpTokenSig?.S) throw new Error('idpToken.signature is required');

    const circuitInput = {
      rp_nonce: rp_nonce.toString(),
      arid_i: arid_i.toString(),
      auid_i: auid_i.toString(),
      r_token: r_token.toString(),
      chain_id: chain_id.toString(),
      S: idpTokenSig.S,
      R8x: idpTokenSig.R8[0],
      R8y: idpTokenSig.R8[1],
      pk_i: pk_i.toString(),
      pk_IdP_x: pkIdP_x.toString(),
      pk_IdP_y: pkIdP_y.toString(),
      PPID: valueToField(business.PPID ?? business.ppid).toString(),
      max_height: maxHeightField.toString(),
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      'build/mode2/pi_pk_i_js/pi_pk_i.wasm',
      'build/mode2/pi_pk_i_final.zkey',
    );
    const calldata = JSON.parse(`[${await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)}]`);
    const [proofA, proofB, proofC] = calldata;

    console.log(`[WalletAgent][submitTransaction] proof generated ${ms(start)}`);
    res.json({
      payload,
      sig,
      proofA,
      proofB,
      proofC,
      pk_i: pk_i.toString(),
      pk_IdP_x: pkIdP_x.toString(),
      pk_IdP_y: pkIdP_y.toString(),
      max_height: maxHeightField.toString(),
    });
  } catch (err) {
    console.error(`[WalletAgent][submitTransaction] error: ${err.message} ${ms(start)}`);
    res.status(400).json({ error: err.message });
  }
});
```

**중요:** 이 Step의 `circuitInput` 필드 채우기 순서(먼저 빈 문자열로 뒀다가 나중에
`idpTokenSig`에서 채우는 부분)는 가독성을 위해 이렇게 썼지만, `S`/`R8x`/`R8y`를 못 채우고
`snarkjs.groth16.fullProve`가 빈 문자열로 호출되면 이상한 에러가 날 수 있다 — 구현 시
`idpTokenSig` 체크를 `circuitInput` 조립보다 먼저 하도록 순서를 바꾸는 게 더 안전하다.
이건 계획 작성 중 발견한, 구현 시 반드시 고쳐야 할 순서 문제로 남겨둔다.

- [ ] **Step 3: 문법 검사**

Run: `node --check wallet_agent.js`
Expected: 에러 없음.

- [ ] **Step 4: 커밋**

```bash
git add wallet_agent.js
git commit -m "feat(mode2): add wallet_agent.js /submitTransaction endpoint (pi_pk_i proof + payload signature generation)"
```

---

## Task 6: 엔드투엔드 스모크 테스트

**파일:** 없음(검증만, 코드 변경 없음)

- [ ] **Step 1: 로컬 Hardhat 노드 기동**

```bash
npx hardhat node
```
(별도 터미널에서 계속 띄워둠, 포트 8545)

- [ ] **Step 2: `PiPkIVerifier`/`PPIDWalletFactory` 배포**

간단한 배포 스크립트(`scripts/deploy_ppid_factory.mjs`, 이 Task에서 임시로 작성해도 되고
Task 2에 정식 배포 스크립트로 포함시켜도 됨)로 로컬 노드에 두 컨트랙트를 배포하고, IdP의
현재 `pk_IdP`(`GET http://127.0.0.1:4000/ps_public_keys`의 `pk_IdP` 필드)를 생성자 인자로
넘긴다. 배포된 factory 주소를 기록해둔다.

- [ ] **Step 3: 전체 Mode 2 로그인(Step 1~15) 실제 실행**

`custom_idp.js`, `wallet_agent.js`, `server.js`(`MODE2_ETH_RPC_URL=http://127.0.0.1:8545`로
설정)를 띄우고, 브라우저에서 로그인 끝까지 진행(EdDSA-Poseidon 마이그레이션 때 확인한
방식과 동일).

- [ ] **Step 4: 트랜잭션 제출**

로그인 완료 후, `client.js`에 새 버튼/호출을 아직 안 만들었으므로 브라우저 개발자
콘솔에서 직접 `fetch('http://127.0.0.1:5001/submitTransaction', {...})`를 호출해서(Step 2
배포 정보와 실제 로그인 결과값을 담아) 응답을 받고, 그 응답으로 factory를 통해 배포된
`PPIDWallet.execute(...)`를 (예: Hardhat console이나 ethers 스크립트로) 직접 호출한다.
트랜잭션이 성공하고, 지정한 수신자가 실제로 값을 받았는지 확인한다.

- [ ] **Step 5: 조작 케이스 확인**

`sig`를 한 바이트 조작해서 다시 제출 → revert 확인. 같은 `nonce`로 두 번 제출 → 두 번째는
`NonceMismatch`로 revert 확인.

- [ ] **Step 6: 정리**

`npx hardhat node`, `custom_idp.js`, `wallet_agent.js`, `server.js` 프로세스 종료, 포트
3000/4000/5001/8545 비어있는지 확인.

- [ ] **Step 7: ledger 갱신**

`.superpowers/sdd/progress.md`에 Task 6 결과 기록.

---

## 후속 작업 (이 계획 범위 밖)

- `client.js`에 실제 "트랜잭션 보내기" UI/버튼 추가 (지금은 Task 6에서 개발자 콘솔로
  수동 호출) — 이건 이 계획이 다루는 백엔드/컨트랙트 인프라가 다 검증된 뒤, 별도로
  가볍게 추가할 수 있는 프론트엔드 작업.
- B2(추적) — 완전히 별도의 브레인스토밍 사이클.
