// RevocationRegistryV4 — root를 받지 않고 **유도하는** 레지스트리 (설계 문서 13.2절).
//
// 전제: build/mode2_v4/의 wasm/zkey (회로 컴파일 + 신뢰 설정이 끝나 있어야 한다).
//       증명 생성이 들어가므로 다른 컨트랙트 테스트보다 느리다.
import hre from 'hardhat';
import { expect } from 'chai';
import {
  createSessionForest,
  createAccountForest,
  combineTopRoots,
  rootToBytes32,
  leafValue,
  TAG_SESSION,
  TAG_ACCOUNT,
  SESSION_RING,
} from '../lib/imt_v3.js';
import { proveInsertTransition } from '../lib/transition_proof.js';

const { ethers } = hre;

// custom_idp.js의 CREDENTIAL_LIFETIME_BLOCKS + MAX_HEIGHT_SLACK_BLOCKS.
const MAX_CREDENTIAL_SPAN = 332;
const GRACE_BLOCKS = 3;
const KIND_INSERT = 0;
const KIND_SESSION_RESET = 1;
const KIND_ACCOUNT_REBASELINE = 2;

describe('RevocationRegistryV4', function () {
  this.timeout(600000);

  /** 빈 업데이트의 증명 자리(리셋처럼 증명이 필요 없는 경우). */
  const NO_PROOF = { a: [0, 0], b: [[0, 0], [0, 0]], c: [0, 0] };

  async function deploy(sessionTop, accountTop) {
    const [idp, other] = await ethers.getSigners();
    const SessV = await ethers.getContractFactory('contracts/pi_ins_sess_verifier.sol:Groth16Verifier');
    const sessV = await SessV.deploy();
    const AcctV = await ethers.getContractFactory('contracts/pi_ins_acct_verifier.sol:Groth16Verifier');
    const acctV = await AcctV.deploy();

    const emptySess = rootToBytes32((await createSessionForest()).emptyRoot);

    const F = await ethers.getContractFactory('RevocationRegistryV4');
    const reg = await F.deploy(
      idp.address,
      GRACE_BLOCKS,
      MAX_CREDENTIAL_SPAN,
      emptySess,
      await sessV.getAddress(),
      await acctV.getAddress(),
      sessionTop,
      accountTop,
    );
    return { reg, idp, other, emptySess };
  }

  /** 계정 층에 값 하나를 넣고, 그 전이의 업데이트 서술자를 만든다. */
  async function accountInsertUpdate(forest, rawValue) {
    const leaf = (await leafValue(TAG_ACCOUNT, rawValue)).toString();
    const before = forest.getSubtreeRoot(forest.shardFor(leaf));
    const { shard, transcript } = await forest.insertWithTranscript(leaf);
    const proved = await proveInsertTransition('account', [transcript]);
    expect(proved.oldRoot).to.equal(before);
    return {
      kind: KIND_INSERT,
      account: true,
      shard,
      oldSubRoot: rootToBytes32(proved.oldRoot),
      newSubRoot: rootToBytes32(proved.newRoot),
      // 형제 경로는 **삽입 후** 상태에서 뽑아도 같다 — 바뀐 것은 이 샤드의 리프뿐이라
      // 그 형제들은 그대로다. 컨트랙트도 같은 경로로 old와 new를 모두 접는다.
      siblings: forest.topPathFor(shard),
      ...proved.calldata,
    };
  }

  it('생성자가 부트스트랩 root를 새기고, 그 값이 곧 유효 root다', async function () {
    const sess = await createSessionForest();
    const acct = await createAccountForest();
    const sTop = rootToBytes32(sess.getTopRoot());
    const aTop = rootToBytes32(acct.getTopRoot());
    const { reg } = await deploy(sTop, aTop);

    expect(await reg.sessionTop()).to.equal(sTop);
    expect(await reg.accountTop()).to.equal(aTop);
    expect(await reg.latestRoot()).to.equal(combineTopRoots(sess.getTopRoot(), acct.getTopRoot()));
    expect(await reg.isAcceptableRoot(await reg.latestRoot())).to.equal(true);
  });

  it('증명된 삽입 전이를 적용하고, 유도한 root가 오프체인 포레스트와 일치한다', async function () {
    const sess = await createSessionForest();
    const acct = await createAccountForest();
    const { reg } = await deploy(rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()));

    const u = await accountInsertUpdate(acct, 5150n);
    await (await reg.pushUpdates([u])).wait();

    // 핵심: 컨트랙트가 계산한 root가 IdP가 독립적으로 계산한 root와 같다.
    const expected = combineTopRoots(sess.getTopRoot(), acct.getTopRoot());
    expect(await reg.latestRoot()).to.equal(expected);
    expect(await reg.accountTop()).to.equal(rootToBytes32(acct.getTopRoot()));
    expect(await reg.isAcceptableRoot(expected)).to.equal(true);
  });

  it('한 번에 여러 전이를 순차로 접는다 (다른 샤드 2건)', async function () {
    const sess = await createSessionForest();
    const acct = await createAccountForest();
    const { reg } = await deploy(rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()));

    // 서로 다른 샤드로 가는 값 두 개를 찾는다.
    let a = null;
    let b = null;
    for (let i = 0n; i < 40n && (a === null || b === null); i++) {
      const leaf = (await leafValue(TAG_ACCOUNT, 7000n + i)).toString();
      const sh = acct.shardFor(leaf);
      if (a === null) a = { raw: 7000n + i, sh };
      else if (sh !== a.sh) b = { raw: 7000n + i, sh };
    }
    expect(b, '서로 다른 샤드를 가진 값 두 개를 찾지 못했다').to.not.equal(null);

    const u1 = await accountInsertUpdate(acct, a.raw);
    const u2 = await accountInsertUpdate(acct, b.raw);
    await (await reg.pushUpdates([u1, u2])).wait();

    expect(await reg.latestRoot()).to.equal(combineTopRoots(sess.getTopRoot(), acct.getTopRoot()));
  });

  it('oldSubRoot가 현재 내용이 아니면 거부한다 — 롤백과 낡은 제출이 여기서 막힌다', async function () {
    const sess = await createSessionForest();
    const acct = await createAccountForest();
    const { reg } = await deploy(rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()));

    const u = await accountInsertUpdate(acct, 6060n);
    await (await reg.pushUpdates([u])).wait();

    // 같은 업데이트를 다시 제출한다 = 그 샤드를 삽입 이전 상태로 되돌리려는 시도.
    // oldSubRoot가 더 이상 현재 내용이 아니므로 거부돼야 한다.
    await expect(reg.pushUpdates([u])).to.be.revertedWithCustomError(reg, 'SubtreeMismatch');
  });

  it('증명이 유효하지 않으면 거부한다', async function () {
    const sess = await createSessionForest();
    const acct = await createAccountForest();
    const { reg } = await deploy(rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()));

    const u = await accountInsertUpdate(acct, 8080n);
    // newSubRoot만 바꾼다 — 공개 신호가 달라지므로 증명이 맞지 않는다.
    const tampered = { ...u, newSubRoot: rootToBytes32(BigInt(u.newSubRoot) ^ 1n) };
    await expect(reg.pushUpdates([tampered])).to.be.revertedWithCustomError(reg, 'InvalidTransitionProof');
  });

  it('IdP가 아니면 거부한다', async function () {
    const sess = await createSessionForest();
    const acct = await createAccountForest();
    const { reg, other } = await deploy(rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()));
    const u = await accountInsertUpdate(acct, 9090n);
    await expect(reg.connect(other).pushUpdates([u])).to.be.revertedWithCustomError(reg, 'NotIdP');
  });

  describe('세션 샤드 리셋 — 컨트랙트가 block.number만으로 검증한다', function () {
    /** 지금 블록에서 리셋이 허용되는/안 되는 샤드를 각각 하나씩 고른다. */
    async function pickShards(reg) {
      const B = BigInt(await ethers.provider.getBlockNumber());
      const ring = Number(SESSION_RING);
      const span = MAX_CREDENTIAL_SPAN;
      const bMod = Number(B % SESSION_RING);
      // d = (k - B) mod ring. d > span 이면 리셋 가능.
      const kOk = (bMod + span + 10) % ring;      // d = span + 10 > span
      const kBad = (bMod + 1) % ring;             // d = 1 <= span
      return { okShard: kOk * 8, badShard: kBad * 8 };
    }

    it('만료 창 밖의 샤드는 리셋을 거부한다', async function () {
      const sess = await createSessionForest();
      const acct = await createAccountForest();
      const { reg, emptySess } = await deploy(
        rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()),
      );
      const { badShard } = await pickShards(reg);
      expect(await reg.sessionShardResettable(badShard)).to.equal(false);

      const u = {
        kind: KIND_SESSION_RESET, account: false, shard: badShard,
        oldSubRoot: rootToBytes32(sess.getSubtreeRoot(badShard)),
        newSubRoot: emptySess,
        siblings: sess.topPathFor(badShard),
        ...NO_PROOF,
      };
      await expect(reg.pushUpdates([u])).to.be.revertedWithCustomError(reg, 'SessionShardNotExpired');
    });

    it('만료 창 안의 샤드는 증명 없이 리셋된다', async function () {
      const sess = await createSessionForest();
      const acct = await createAccountForest();

      // 리셋이 의미를 가지려면 그 샤드에 리프가 있어야 한다. 아무 세션 리프나 넣고
      // 그 샤드가 창 안에 오도록 블록을 진행시킨다.
      const leaf = (await leafValue(TAG_SESSION, 4242n)).toString();
      const maxHeight = 1000n;
      await sess.insert(leaf, { maxHeight });
      const shard = sess.shardFor(leaf, { maxHeight });

      const { reg, emptySess } = await deploy(
        rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()),
      );
      expect(await reg.sessionTop()).to.equal(rootToBytes32(sess.getTopRoot()));

      // d = (k - B) mod 512 가 span보다 커질 때까지 블록을 진행시킨다.
      const k = BigInt(Math.floor(shard / 8));
      for (let i = 0; i < Number(SESSION_RING) + 1; i++) {
        const B = BigInt(await ethers.provider.getBlockNumber());
        const d = Number((k + SESSION_RING - (B % SESSION_RING)) % SESSION_RING);
        if (d > MAX_CREDENTIAL_SPAN) break;
        await hre.network.provider.send('hardhat_mine', ['0x1']);
      }
      expect(await reg.sessionShardResettable(shard)).to.equal(true);

      const u = {
        kind: KIND_SESSION_RESET, account: false, shard,
        oldSubRoot: rootToBytes32(sess.getSubtreeRoot(shard)),
        newSubRoot: emptySess,
        siblings: sess.topPathFor(shard),
        ...NO_PROOF,
      };
      await (await reg.pushUpdates([u])).wait();

      // 오프체인도 같은 리셋을 하면 root가 일치해야 한다.
      sess.resetShard(shard);
      expect(await reg.latestRoot()).to.equal(combineTopRoots(sess.getTopRoot(), acct.getTopRoot()));
    });

    it('리셋의 목적지가 빈 서브트리 root가 아니면 거부한다', async function () {
      const sess = await createSessionForest();
      const acct = await createAccountForest();
      const { reg } = await deploy(rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()));
      const { okShard } = await pickShards(reg);

      const u = {
        kind: KIND_SESSION_RESET, account: false, shard: okShard,
        oldSubRoot: rootToBytes32(sess.getSubtreeRoot(okShard)),
        newSubRoot: rootToBytes32(12345n),
        siblings: sess.topPathFor(okShard),
        ...NO_PROOF,
      };
      await expect(reg.pushUpdates([u])).to.be.revertedWithCustomError(reg, 'ResetMustGoToEmptyRoot');
    });

    it('계정 층에는 리셋을 허용하지 않는다', async function () {
      const sess = await createSessionForest();
      const acct = await createAccountForest();
      const { reg, emptySess } = await deploy(
        rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()),
      );
      const u = {
        kind: KIND_SESSION_RESET, account: true, shard: 0,
        oldSubRoot: rootToBytes32(acct.getSubtreeRoot(0)),
        newSubRoot: emptySess,
        siblings: acct.topPathFor(0),
        ...NO_PROOF,
      };
      await expect(reg.pushUpdates([u])).to.be.revertedWithCustomError(reg, 'ResetNotAllowedOnAccountLayer');
    });
  });

  it('계정 층 재기준화는 증명 없이 되지만 별도 이벤트로 남는다 (잔여 신뢰)', async function () {
    const sess = await createSessionForest();
    const acct = await createAccountForest();
    const { reg } = await deploy(rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()));

    const u = await accountInsertUpdate(acct, 3030n);
    await (await reg.pushUpdates([u])).wait();

    // 그 샤드를 빈 상태로 되돌린다(만료 회수의 극단적인 경우).
    const shard = u.shard;
    const oldSub = rootToBytes32(acct.getSubtreeRoot(shard));
    const siblings = acct.topPathFor(shard);
    const emptyAcct = rootToBytes32(acct.emptyRoot);

    const rb = {
      kind: KIND_ACCOUNT_REBASELINE, account: true, shard,
      oldSubRoot: oldSub, newSubRoot: emptyAcct, siblings,
      ...NO_PROOF,
    };
    await expect(reg.pushUpdates([rb])).to.emit(reg, 'UntrustedAccountRebaseline');

    acct.resetShard(shard);
    expect(await reg.latestRoot()).to.equal(combineTopRoots(sess.getTopRoot(), acct.getTopRoot()));
  });

  it('세션 층에는 계정 재기준화를 허용하지 않는다', async function () {
    const sess = await createSessionForest();
    const acct = await createAccountForest();
    const { reg } = await deploy(rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()));
    const u = {
      kind: KIND_ACCOUNT_REBASELINE, account: false, shard: 0,
      oldSubRoot: rootToBytes32(sess.getSubtreeRoot(0)),
      newSubRoot: rootToBytes32(sess.emptyRoot),
      siblings: sess.topPathFor(0),
      ...NO_PROOF,
    };
    await expect(reg.pushUpdates([u])).to.be.revertedWithCustomError(reg, 'RebaselineOnlyOnAccountLayer');
  });

  it('유예 창: 밀려난 root도 graceBlocks 동안은 받아준다', async function () {
    const sess = await createSessionForest();
    const acct = await createAccountForest();
    const { reg } = await deploy(rootToBytes32(sess.getTopRoot()), rootToBytes32(acct.getTopRoot()));
    const before = await reg.latestRoot();

    const u = await accountInsertUpdate(acct, 1212n);
    await (await reg.pushUpdates([u])).wait();

    expect(await reg.isAcceptableRoot(before)).to.equal(true);
    await hre.network.provider.send('hardhat_mine', ['0x' + (GRACE_BLOCKS + 1).toString(16)]);
    expect(await reg.isAcceptableRoot(before)).to.equal(false);
  });
});
