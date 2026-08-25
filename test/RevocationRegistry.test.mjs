import hre from 'hardhat';
import { expect } from 'chai';

const { ethers } = hre;

// 블록을 n개 진행시킨다. isRecentRoot는 block.number 기준으로 만료를 판정하므로
// 만료 경계를 실제로 넘겨보려면 체인을 앞으로 밀어야 한다.
async function mine(n) {
  await hre.network.provider.send('hardhat_mine', [`0x${n.toString(16)}`]);
}

async function blockNumber() {
  return await hre.ethers.provider.getBlockNumber();
}

describe('RevocationRegistry', function () {
  const R = (n) => ethers.zeroPadValue(ethers.toBeHex(n), 32);

  async function deploy() {
    const [idp, other] = await ethers.getSigners();
    const F = await ethers.getContractFactory('RevocationRegistry');
    const reg = await F.deploy(idp.address);
    return { reg, idp, other };
  }

  it('accepts a root from the IdP and reports it as recent', async function () {
    const { reg } = await deploy();
    await reg.pushRoot(R(1));
    expect(await reg.isRecentRoot(R(1))).to.equal(true);
    expect(await reg.latestRoot()).to.equal(R(1));
  });

  it('rejects pushRoot from a non-IdP caller', async function () {
    const { reg, other } = await deploy();
    await expect(reg.connect(other).pushRoot(R(1))).to.be.revertedWithCustomError(reg, 'NotIdP');
  });

  it('keeps the most recent K roots and evicts older ones', async function () {
    const { reg } = await deploy();
    for (let i = 1; i <= 8; i++) await reg.pushRoot(R(i));
    expect(await reg.isRecentRoot(R(1))).to.equal(true);
    await reg.pushRoot(R(9));
    expect(await reg.isRecentRoot(R(1))).to.equal(false, 'oldest root must be evicted');
    expect(await reg.isRecentRoot(R(9))).to.equal(true);
    expect(await reg.isRecentRoot(R(2))).to.equal(true);
  });

  it('reports an unknown root as not recent', async function () {
    const { reg } = await deploy();
    await reg.pushRoot(R(1));
    expect(await reg.isRecentRoot(R(42))).to.equal(false);
  });

  it('exposes how many slots are filled', async function () {
    const { reg } = await deploy();
    expect(await reg.filled()).to.equal(0n);
    await reg.pushRoot(R(1));
    expect(await reg.filled()).to.equal(1n);
    for (let i = 2; i <= 10; i++) await reg.pushRoot(R(i));
    expect(await reg.filled()).to.equal(await reg.K(), 'filled saturates at K');
  });

  it('treats every root as stale while no root has been published', async function () {
    const { reg } = await deploy();
    expect(await reg.filled()).to.equal(0n);
    expect(await reg.isRecentRoot(R(1))).to.equal(false);
  });

  // C2의 핵심: 슬롯 축출(K)이 아니라 블록 경과(GRACE_BLOCKS)가 만료를 결정한다.
  it('keeps a root valid up to GRACE_BLOCKS and expires it right after', async function () {
    const { reg } = await deploy();
    await reg.pushRoot(R(1));
    const pushedAt = await blockNumber();
    const grace = Number(await reg.GRACE_BLOCKS());

    // block.number - pushedAt == GRACE_BLOCKS 인 시점까지는 유효하다.
    await mine(grace - (await blockNumber()) + pushedAt);
    expect(await blockNumber()).to.equal(pushedAt + grace);
    expect(await reg.isRecentRoot(R(1))).to.equal(true, 'root must still be valid at exactly GRACE_BLOCKS');

    // 한 블록만 더 지나면 만료된다. 슬롯은 그대로 남아 있는데도(축출 아님) 무효다.
    await mine(1);
    expect(await reg.isRecentRoot(R(1))).to.equal(false, 'root must expire one block past GRACE_BLOCKS');
    expect(await reg.filled()).to.equal(1n, 'the slot is still occupied — expiry is time-based, not eviction');
    expect(await reg.latestRoot()).to.equal(R(1));
  });

  // 같은 root를 다시 게시하면 신선도가 갱신돼야 한다(주기적 heartbeat 경로).
  // 이때 옛 슬롯이 순회에서 먼저 걸리므로, 첫 일치에서 멈추면 만료가 실제보다
  // 일찍 걸려 정상 사용자가 막힌다 — 가장 최근 게시 시각으로 판정해야 한다.
  it('refreshes freshness when the same root is republished, even from an older slot', async function () {
    const { reg } = await deploy();
    await reg.pushRoot(R(1));
    const firstPush = await blockNumber();
    const grace = Number(await reg.GRACE_BLOCKS());

    await mine(grace - 10);
    await reg.pushRoot(R(1)); // 두 번째 슬롯에 같은 root를 다시 기록
    const secondPush = await blockNumber();
    expect(await reg.filled()).to.equal(2n, 'republishing occupies another slot');

    // 첫 게시 기준이면 이미 만료됐을 시점인데, 재게시 덕분에 여전히 유효해야 한다.
    await mine(20);
    expect(await blockNumber()).to.be.greaterThan(firstPush + grace);
    expect(await reg.isRecentRoot(R(1))).to.equal(
      true,
      'the newest push must decide freshness, not the first matching (older) slot',
    );

    // 재게시 기준으로도 GRACE_BLOCKS가 지나면 결국 만료된다.
    await mine(grace - (await blockNumber()) + secondPush + 1);
    expect(await reg.isRecentRoot(R(1))).to.equal(false);
  });

  // 위 테스트는 옛 사본이 낮은 인덱스, 새 사본이 높은 인덱스인 경우만 다룬다.
  // 그 순서라면 "첫 일치에서 멈추는" 오구현(first match wins)만 잡아낸다.
  // 여기서는 순환 버퍼가 한 바퀴 돈 뒤 새 사본이 오히려 낮은 인덱스에 쓰이는
  // 경우를 만든다 — 슬롯 인덱스 순서와 게시 시각 순서가 어긋나므로, "마지막으로
  // 순회에서 만난 슬롯"을 기준으로 삼는 오구현(last match wins)도 이걸로 잡힌다.
  // 올바른 구현은 인덱스 순서와 무관하게 pushedAt이 가장 큰(가장 최근) 사본을
  // 기준으로 신선도를 판정해야 한다.
  it('refreshes freshness when the newer copy of a republished root lands at a lower slot index after wraparound', async function () {
    const { reg } = await deploy();
    const K = Number(await reg.K());
    // 아래 슬롯 인덱스 배치(idx6 옛 사본 / idx2 새 사본)는 K=8을 가정하므로 못 박아둔다.
    expect(K).to.equal(8, 'this test hardcodes slot indices assuming K == 8');
    const grace = Number(await reg.GRACE_BLOCKS());
    const ROOT = R(1);

    // idx0..idx5: 채움용 필러
    for (let i = 0; i < 6; i++) await reg.pushRoot(R(300 + i));
    // idx6: 옛 사본 (인덱스가 높다)
    await reg.pushRoot(ROOT);
    const oldPushedAt = await blockNumber();
    // idx7: 필러 (여기서 head가 7 -> 0으로 wrap된다)
    await reg.pushRoot(R(310));
    // idx0, idx1: 필러 (wrap 이후 옛 슬롯을 덮어씀)
    await reg.pushRoot(R(311));
    await reg.pushRoot(R(312));
    // idx2: 새 사본 — 옛 사본(idx6)보다 인덱스가 낮다
    await reg.pushRoot(ROOT);
    const newPushedAt = await blockNumber();

    expect(await reg.filled()).to.equal(await reg.K());
    expect(newPushedAt).to.be.greaterThan(oldPushedAt);

    // 옛 사본 기준으로는 이미 만료됐지만 새 사본 기준으로는 아직 유효한 구간으로 이동.
    await mine(grace - (await blockNumber()) + oldPushedAt);
    await mine(1);
    expect(await blockNumber() - oldPushedAt).to.be.greaterThan(grace, 'old copy must already be past its grace window');
    expect(await blockNumber() - newPushedAt).to.be.at.most(grace, 'new copy must still be within its grace window');
    expect(await reg.isRecentRoot(ROOT)).to.equal(
      true,
      'the newer (lower-index) copy must decide freshness even though the older (higher-index) copy already expired',
    );

    // 새 사본 기준으로도 GRACE_BLOCKS가 지나면 결국 만료된다.
    await mine(grace - (await blockNumber()) + newPushedAt + 1);
    expect(await reg.isRecentRoot(ROOT)).to.equal(false);
  });
});
