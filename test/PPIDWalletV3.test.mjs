// 폐기 트리 이중 구조(v3)의 온체인 몫을 고정한다.
//   npx hardhat test test/PPIDWalletV3.test.mjs
//
// 설계: docs/superpowers/specs/2026-09-05-revocation-dual-tree-design.md 6·8절
//
// 진짜 PiPkIV3Verifier는 새 zkey가 있어야 만들 수 있으므로(E단계), 여기서는
// MockPiPkIV3Verifier로 증명 검증을 떼어내고 **컨트랙트가 책임지는 부분**만 본다:
// 상위 트리 검증, 세션 만료 축 자체 계산(조건 2), 샤드 범위, 유예 창.
//
// 회로가 책임지는 부분(샤드 인덱스가 리프에서 나왔는가)은 tests/test_pi_pk_i_v3_shard.mjs가
// 이미 고정했다. 둘이 합쳐져야 샤드가 확정된다.
import hre from "hardhat";
import { expect } from "chai";
import { randomBytes } from "crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256, concat, getBytes } from "ethers";
import {
  createSessionForest,
  createAccountForest,
  computeTopPath,
  combineTopRoots,
  rootToBytes32,
  sessionShardOf,
  sessionShardLowOf,
  accountShardOf,
  leafValue,
  TAG_SESSION,
  TAG_ACCOUNT,
  ACCOUNT_SHARD_COUNT,
} from "../lib/imt_v3.js";

const GRACE = 3;

function ethAddressFromSecp256k1Pubkey(pub65) {
  return "0x" + keccak256(pub65.slice(1)).slice(-40);
}

describe("PPIDWalletV3 — 이중 트리 폐기", function () {
  this.timeout(180000);

  async function fixture() {
    const [deployer] = await hre.ethers.getSigners();

    const verifier = await (await hre.ethers.getContractFactory("MockPiPkIV3Verifier")).deploy();
    const registry = await (await hre.ethers.getContractFactory("RevocationRegistryV3"))
      .deploy(deployer.address, GRACE);

    // 세션 키
    const sk_i = randomBytes(32);
    const pk_i = BigInt(ethAddressFromSecp256k1Pubkey(secp256k1.getPublicKey(sk_i, false)));

    // 이 테스트는 회로를 돌리지 않으므로 PPID/pk_IdP는 임의의 상수로 둔다.
    const PPID = 12345678901234567890n;
    const pk_IdP_x = 111n;
    const pk_IdP_y = 222n;

    const factory = await (await hre.ethers.getContractFactory("PPIDWalletFactoryV3"))
      .deploy(verifier.target, pk_IdP_x, pk_IdP_y, registry.target);
    await (await factory.deploy(PPID)).wait();
    const wallet = await hre.ethers.getContractAt("PPIDWalletV3", await factory.computeAddress(PPID));

    // 크레덴셜 만료. 실제 흐름과 같이 현재 블록보다 뒤에 둔다.
    const maxHeight = BigInt(await hre.ethers.provider.getBlockNumber()) + 500n;

    // 폐기 포레스트 두 개 (IdP 쪽 상태)
    const sess = await createSessionForest();
    const acct = await createAccountForest();

    // 내 리프
    const rToken = 987654321n;
    const auid = 55555n;
    const sessLeaf = await leafValue(TAG_SESSION, rToken);
    const acctLeaf = await leafValue(TAG_ACCOUNT, auid);

    function signPayload(payload, walletAddress, chainId) {
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

    // 지갑이 만드는 witness: 서브트리 root + 샤드 인덱스 + 상위 형제.
    function buildWitness({ sessRootOverride, sessSiblingsOverride, sessShardLowOverride, acctShardOverride } = {}) {
      const sessShard = sessionShardOf(sessLeaf, maxHeight);
      const acctShard = accountShardOf(acctLeaf);
      return {
        sessRoot: sessRootOverride ?? rootToBytes32(sess.getSubtreeRoot(sessShard)),
        sessShardLow: sessShardLowOverride ?? sessionShardLowOf(sessLeaf),
        sessSiblings: sessSiblingsOverride ?? computeTopPath(sess.getSubtreeRoots(), sessShard),
        acctRoot: rootToBytes32(acct.getSubtreeRoot(acctShard)),
        acctShard: acctShardOverride ?? acctShard,
        acctSiblings: computeTopPath(acct.getSubtreeRoots(), acctShard),
      };
    }

    function currentCombinedRoot() {
      return combineTopRoots(sess.getTopRoot(), acct.getTopRoot());
    }

    async function publish() {
      await (await registry.pushRoot(currentCombinedRoot())).wait();
    }

    const P = [0n, 0n];
    const PB = [[0n, 0n], [0n, 0n]];

    async function callExecute(overrides = {}) {
      const payload = {
        to: deployer.address,
        value: 0n,
        data: "0x",
        nonce: await wallet.nonce(),
        ...(overrides.payload ?? {}),
      };
      const chainId = (await hre.ethers.provider.getNetwork()).chainId;
      const sig = signPayload(payload, wallet.target, chainId);
      return wallet.execute(
        payload, sig, P, PB, P,
        pk_i, pk_IdP_x, pk_IdP_y, maxHeight,
        overrides.witness ?? buildWitness(),
      );
    }

    return {
      deployer, verifier, registry, wallet, factory,
      sess, acct, sessLeaf, acctLeaf, maxHeight, pk_i, PPID,
      buildWitness, currentCombinedRoot, publish, callExecute,
    };
  }

  // ── 레지스트리 ────────────────────────────────────────────────────────
  it("root 0은 게시할 수 없다", async function () {
    const { registry } = await fixture();
    await expect(registry.pushRoot(hre.ethers.ZeroHash)).to.be.revertedWithCustomError(registry, "EmptyRoot");
    expect(await registry.isAcceptableRoot(hre.ethers.ZeroHash)).to.equal(false);
  });

  it("IdP가 아니면 게시할 수 없다", async function () {
    const { registry } = await fixture();
    const [, other] = await hre.ethers.getSigners();
    await expect(registry.connect(other).pushRoot("0x" + "11".repeat(32)))
      .to.be.revertedWithCustomError(registry, "NotIdP");
  });

  it("유예 창이 링보다 크면 배포를 거부한다", async function () {
    const [deployer] = await hre.ethers.getSigners();
    const F = await hre.ethers.getContractFactory("RevocationRegistryV3");
    await expect(F.deploy(deployer.address, 0)).to.be.revertedWithCustomError(F, "GraceOutOfRange");
    await expect(F.deploy(deployer.address, 7)).to.be.revertedWithCustomError(F, "GraceOutOfRange");
  });

  // ── 정상 경로 ─────────────────────────────────────────────────────────
  it("게시된 상위 root로 execute가 통과한다", async function () {
    const { publish, callExecute, wallet } = await fixture();
    await publish();
    await expect(callExecute()).to.emit(wallet, "Executed");
    expect(await wallet.nonce()).to.equal(1n);
  });

  it("컨트랙트가 회로에 넘기는 public signal이 기대값과 같다", async function () {
    const { publish, callExecute, verifier, wallet, buildWitness, pk_i, PPID, maxHeight } = await fixture();
    await publish();
    const w = buildWitness();
    // circuits/pi_pk_i_v3.circom 의 main 선언 순서 그대로
    const expected = [
      pk_i, 111n, 222n, PPID, maxHeight,
      BigInt(w.sessRoot), BigInt(w.sessShardLow), BigInt(w.acctRoot), BigInt(w.acctShard),
    ];
    await (await verifier.setExpectedInput(expected)).wait();
    await expect(callExecute()).to.emit(wallet, "Executed");

    // 한 자리라도 다르면 통과하지 못한다 — 대조가 실제로 걸린다는 확인
    const wrong = [...expected];
    wrong[6] = wrong[6] === 0n ? 1n : 0n; // sess_shard_low
    await (await verifier.setExpectedInput(wrong)).wait();
    await expect(callExecute()).to.be.revertedWithCustomError(wallet, "InvalidProof");
  });

  it("게시되지 않은 root면 StaleRevocationRoot로 막힌다", async function () {
    const { callExecute, wallet } = await fixture();
    await expect(callExecute()).to.be.revertedWithCustomError(wallet, "StaleRevocationRoot");
  });

  // ── 조건 2 — 만료 축은 컨트랙트가 직접 계산한다 ───────────────────────
  it("호출자가 다른 만료 칸의 상위 경로를 제시해도 통하지 않는다", async function () {
    const { publish, callExecute, wallet, sess, sessLeaf, maxHeight, buildWitness } = await fixture();

    // 먼저 다른 만료 칸에 남의 폐기를 하나 넣는다. 이게 없으면 상위 트리의 모든 리프가
    // 같은 값(빈 서브트리 상수)이라 어느 샤드의 경로든 형제가 전부 동일해져서, 이 테스트가
    // 공허해진다 — 잘못된 경로를 제시해도 우연히 같은 root가 나온다.
    await sess.insert(await leafValue(TAG_SESSION, 31337n), { maxHeight: maxHeight + 1n });
    await publish();

    // 공격자는 max_height가 다른 칸의 경로를 만들어 낸다. 컨트랙트는 sessShard를
    // max_height % 512로 스스로 계산하므로 이 경로로는 top root가 나오지 않는다.
    const wrongShard = sessionShardOf(sessLeaf, maxHeight + 1n);
    const w = buildWitness({
      sessSiblingsOverride: computeTopPath(sess.getSubtreeRoots(), wrongShard),
    });
    await expect(callExecute({ witness: w })).to.be.revertedWithCustomError(wallet, "StaleRevocationRoot");

    // 대조군: 올바른 경로면 통과한다 (위 실패가 경로 때문이지 다른 이유가 아님을 확인)
    await expect(callExecute()).to.emit(wallet, "Executed");
  });

  it("샤드 인덱스가 범위를 벗어나면 거부한다", async function () {
    const { publish, callExecute, wallet, buildWitness } = await fixture();
    await publish();
    await expect(callExecute({ witness: buildWitness({ sessShardLowOverride: 8 }) }))
      .to.be.revertedWithCustomError(wallet, "ShardOutOfRange");
    // 하드코딩하지 않는다 — 계정 샤드 수가 바뀌면 이 값도 따라와야 한다(256 -> 4096).
    await expect(callExecute({ witness: buildWitness({ acctShardOverride: ACCOUNT_SHARD_COUNT }) }))
      .to.be.revertedWithCustomError(wallet, "ShardOutOfRange");
  });

  // ── Case 1 / Case 2 ───────────────────────────────────────────────────
  it("Case 1 — 내 세션이 폐기되면 유예 창이 지난 뒤 통과하지 못한다", async function () {
    const { publish, callExecute, wallet, verifier, sess, sessLeaf, maxHeight, buildWitness } = await fixture();
    await publish();
    const stale = buildWitness();

    await sess.insert(sessLeaf, { maxHeight });
    await publish();

    // 유예 창 안에서는 옛 root가 아직 유효하다. 이게 설계상 폐기 효력 지연이며,
    // graceBlocks로 고정된다(설계 문서 6절) — 인플라이트 트랜잭션을 보호하는 대가다.
    await expect(callExecute({ witness: stale })).to.emit(wallet, "Executed");

    // 창을 넘기면 막힌다. 새 witness를 만들려 해도 내 리프가 서브트리에 있어
    // 비멤버십 witness 자체가 나오지 않는다(회로 쪽 Case 1).
    for (let i = 0; i < GRACE + 1; i++) await hre.ethers.provider.send("evm_mine", []);
    await expect(callExecute({ witness: stale })).to.be.revertedWithCustomError(wallet, "StaleRevocationRoot");

    // 여기서 역할이 갈린다. 최신 상태로 새 witness를 만들면 상위 트리는 맞아떨어지므로
    // **컨트랙트는 통과시킨다** — 내 리프가 서브트리 안에 있는지는 컨트랙트가 볼 수 없다.
    // 그걸 막는 것은 회로다: 폐기된 리프에 대해서는 비멤버십 witness 자체가 만들어지지
    // 않는다(tests/test_pi_pk_i_v3_shard.mjs 케이스 5, tests/test_imt_v3_lib.js 3).
    // mock verifier로 "유효한 증명이 존재하지 않는" 상황을 흉내 내면 InvalidProof다.
    const current = buildWitness();
    await (await verifier.setResult(false)).wait();
    await expect(callExecute({ witness: current })).to.be.revertedWithCustomError(wallet, "InvalidProof");
  });

  it("Case 2 — 타인 폐기 뒤에도 같은 서브트리 root로 통과한다 (상위 형제만 갱신)", async function () {
    const { publish, callExecute, wallet, sess, sessLeaf, maxHeight, buildWitness } = await fixture();
    await publish();
    const before = buildWitness();

    // 남의 세션 폐기 — 만료가 달라 다른 샤드에 떨어진다.
    const otherLeaf = await leafValue(TAG_SESSION, 424242n);
    await sess.insert(otherLeaf, { maxHeight: maxHeight + 5n });
    await publish();

    const after = buildWitness();
    // SNARK가 보는 값(서브트리 root와 샤드 인덱스)은 한 글자도 바뀌지 않았다.
    expect(after.sessRoot).to.equal(before.sessRoot);
    expect(after.acctRoot).to.equal(before.acctRoot);
    expect(after.sessShardLow).to.equal(before.sessShardLow);
    // 바뀐 것은 상위 형제뿐이다.
    expect(after.sessSiblings).to.not.deep.equal(before.sessSiblings);

    await expect(callExecute({ witness: after })).to.emit(wallet, "Executed");
  });

  // ── 유예 창 ───────────────────────────────────────────────────────────
  it("밀려난 root가 유예 창 안에서는 통과하고 넘으면 거부된다", async function () {
    const { publish, callExecute, wallet, registry, sess, maxHeight, buildWitness, currentCombinedRoot } =
      await fixture();
    await publish();
    const oldWitness = buildWitness();
    const oldRoot = currentCombinedRoot();

    // 남의 폐기로 top root가 바뀐다 → 옛 root는 "밀려난" 상태가 된다.
    await sess.insert(await leafValue(TAG_SESSION, 777777n), { maxHeight: maxHeight + 9n });
    await publish();
    expect(await registry.latestRoot()).to.not.equal(oldRoot);
    expect(await registry.isAcceptableRoot(oldRoot)).to.equal(true);

    // 유예 창 안이면 옛 witness도 아직 통과한다 (인플라이트 트랜잭션 보호)
    await expect(callExecute({ witness: oldWitness })).to.emit(wallet, "Executed");

    // GRACE 블록을 넘기면 거부된다
    for (let i = 0; i < GRACE + 1; i++) await hre.ethers.provider.send("evm_mine", []);
    expect(await registry.isAcceptableRoot(oldRoot)).to.equal(false);
    await expect(callExecute({ witness: oldWitness })).to.be.revertedWithCustomError(wallet, "StaleRevocationRoot");
  });

  it("같은 root 재게시(heartbeat)는 유예 창을 소모하지 않는다", async function () {
    const { publish, registry, currentCombinedRoot } = await fixture();
    await publish();
    const root = currentCombinedRoot();

    // heartbeat를 여러 번, 유예 창보다 오래 반복해도 최신 root는 계속 유효해야 한다.
    for (let i = 0; i < GRACE + 3; i++) await publish();
    expect(await registry.latestRoot()).to.equal(root);
    expect(await registry.isAcceptableRoot(root)).to.equal(true);
  });
});
