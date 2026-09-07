// V4 게시 한 사이클을 끝에서 끝까지 — 격리 IdP + 실제로 배포한 RevocationRegistryV4.
//   node tests/test_publish_v4_cycle.mjs
//
// 전제: hardhat 노드(:8545), build/mode2_v4/의 wasm/zkey, artifacts/(npx hardhat compile).
//
// 무엇을 고정하는가. sweep이 하는 일을 그대로 한다:
//   prepare -> commit(전이 서술자 수집) -> 증명 붙이기 -> pushUpdates
// 그리고 **컨트랙트가 유도한 root가 IdP가 독립적으로 계산한 root와 같은지**를 본다.
// 이 한 줄이 13.2 전체가 성립하는지를 말해준다 — 체인이 IdP의 주장을 받아 적은 것이 아니라
// 스스로 계산했는데 같은 값이 나왔다는 뜻이기 때문이다.
//
// 함께 확인하는 것:
//   · 삽입·세션 리셋·계정 회수가 한 스트림으로 순서대로 적용된다
//   · 같은 회차를 다시 올리면 SubtreeMismatch로 막힌다(롤백 불가)
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { startIsolatedIdP } from './helpers/isolated_idp.mjs';
import { buildContractUpdates } from '../lib/transition_proof.js';
import { createSessionForest, rootToBytes32 } from '../lib/imt_v3.js';

const RPC = process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';
// hardhat 노드의 **마지막** 기본 계정(#9). 이 테스트가 배포자이자 IdP다.
// 계정 #0은 wallet_agent.js가 스폰서 트랜잭션에 쓰고 있어 nonce가 충돌한다.
const DEPLOYER_KEY = '0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6';
const MAX_CREDENTIAL_SPAN = 332;
const GRACE_BLOCKS = 3;

function artifact(sol, name) {
  const p = `artifacts/contracts/${sol}/${name}.json`;
  if (!fs.existsSync(p)) {
    throw new Error(`${p} 가 없습니다. 먼저 npx hardhat compile 을 실행하세요.`);
  }
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

async function deployRegistry(wallet, sessionTop, accountTop) {
  const deploy = async (sol, name, args = []) => {
    const a = artifact(sol, name);
    const f = new ethers.ContractFactory(a.abi, a.bytecode, wallet);
    const c = await f.deploy(...args);
    await c.waitForDeployment();
    return c;
  };
  const sessV = await deploy('pi_ins_sess_verifier.sol', 'Groth16Verifier');
  const acctV = await deploy('pi_ins_acct_verifier.sol', 'Groth16Verifier');
  const emptySess = rootToBytes32((await createSessionForest()).emptyRoot);
  return deploy('RevocationRegistryV4.sol', 'RevocationRegistryV4', [
    await wallet.getAddress(),
    GRACE_BLOCKS,
    MAX_CREDENTIAL_SPAN,
    emptySess,
    await sessV.getAddress(),
    await acctV.getAddress(),
    sessionTop,
    accountTop,
  ]);
}

/** prepare -> commit만. push하지 않는다(일부 테스트가 실제로 이렇게 쓴다). */
async function commitOnly(idp) {
  const prepared = await idp.post('/idp/publish/prepare');
  assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
  const committed = await idp.post('/idp/publish/commit', { roundToken: prepared.body.roundToken });
  assert.equal(committed.status, 200, JSON.stringify(committed.body));
  return committed.body;
}

/** sweep이 하는 한 사이클: prepare -> commit -> pushUpdates -> ack. */
async function publishCycle(idp, registry) {
  const committed = await commitOnly(idp);

  const descriptors = committed.updates ?? [];
  if (descriptors.length === 0) return { committed, updates: [], pushed: false };

  const updates = await buildContractUpdates(descriptors);
  const rc = await (await registry.pushUpdates(updates)).wait();
  const acked = await idp.post('/idp/publish/ack', { count: updates.length });
  assert.equal(acked.status, 200, JSON.stringify(acked.body));
  assert.equal(acked.body.pending, 0, '백로그가 비지 않았다');
  return { committed, updates, pushed: true, gasUsed: rc.gasUsed };
}


const uniqueValue = () => `${Date.now()}${Math.floor(Math.random() * 1e6)}`;

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC);
  // NonceManager로 감싼다. 맨 Wallet은 nonce를 provider에 매번 물어보는데, 자동 채굴
  // 노드에서 연속 배포를 하면 그 조회가 낡은 값을 돌려줘 "nonce too low"가 난다.
  const wallet = new ethers.NonceManager(new ethers.Wallet(DEPLOYER_KEY, provider));
  const deployerAddress = await wallet.getAddress();

  const idp = await startIsolatedIdP();
  try {
    // 배포 시점의 IdP 상태를 생성자에 새긴다(부트스트랩).
    const boot = (await idp.get('/idp/revocation_state_v3')).body;
    const registry = await deployRegistry(wallet, boot.sessionTopRoot, boot.accountTopRoot);
    assert.equal(await registry.latestRoot(), boot.topRoot, '부트스트랩 root가 어긋났다');
    console.log('OK: 1) 부트스트랩 — 배포 시점 IdP 상태가 생성자에 새겨졌다');

    // ── 2) 계정 폐기 한 건을 게시한다 ─────────────────────────────────────
    const v1 = uniqueValue();
    assert.equal((await idp.post('/idp/revoke', { type: 'account', value: v1 })).status, 200);
    const r1 = await publishCycle(idp, registry);
    assert.ok(r1.pushed, '전이가 없었다 — 폐기가 반영되지 않았다');
    assert.equal(r1.updates.length, 1, `전이 1건이어야 한다 (실제 ${r1.updates.length})`);
    assert.equal(r1.updates[0].kind, 0, 'insert 여야 한다');

    // 이 한 줄이 요점이다: 체인이 스스로 계산한 root가 IdP의 root와 같다.
    const onchain = await registry.latestRoot();
    assert.equal(
      String(onchain).toLowerCase(), String(r1.committed.root).toLowerCase(),
      '컨트랙트가 유도한 root가 IdP가 계산한 root와 다르다',
    );
    assert.equal(await registry.isAcceptableRoot(onchain), true);
    console.log(`OK: 2) 삽입 전이를 증명과 함께 올렸고, 유도된 root가 IdP와 일치한다 (gas ${r1.gasUsed})`);

    // ── 3) 여러 건을 한 회차에 — 순서대로 접힌다 ──────────────────────────
    const many = [uniqueValue(), uniqueValue(), uniqueValue()];
    for (const v of many) {
      assert.equal((await idp.post('/idp/revoke', { type: 'account', value: v })).status, 200);
    }
    const r2 = await publishCycle(idp, registry);
    assert.equal(r2.updates.length, many.length, '전이 건수가 폐기 건수와 다르다');
    assert.equal(
      String(await registry.latestRoot()).toLowerCase(),
      String(r2.committed.root).toLowerCase(),
      '여러 전이를 접은 결과가 IdP와 다르다',
    );
    console.log(`OK: 3) 한 회차 ${many.length}건이 순서대로 접히고 root가 일치한다 (gas ${r2.gasUsed})`);

    // ── 4) 롤백 불가 — 같은 회차를 다시 올리면 막힌다 ─────────────────────
    // staticCall(eth_call)로 본다. 트랜잭션으로 보내면 노드가 돌려주는 에러를 ethers가
    // 항상 디코딩하지는 못하는데("unknown custom error"), eth_call은 revert 데이터를
    // 그대로 돌려줘 커스텀 에러 이름까지 나온다. 컨트랙트 로직은 동일하게 탄다.
    let replayErr = null;
    try {
      await registry.pushUpdates.staticCall(r1.updates);
    } catch (err) {
      replayErr = err;
    }
    assert.ok(replayErr, '지난 회차를 다시 올렸는데 통과했다 — 롤백이 가능하다');
    assert.equal(
      replayErr.revert?.name, 'SubtreeMismatch',
      `롤백이 SubtreeMismatch가 아닌 이유로 막혔다: ` +
        `${replayErr.revert?.name ?? replayErr.shortMessage ?? replayErr.message}`,
    );
    console.log('OK: 4) 지난 회차 재제출은 SubtreeMismatch로 막힌다 (롤백 불가)');

    // ── 5) 바뀐 것이 없으면 트랜잭션을 만들지 않는다 ──────────────────────
    const r3 = await publishCycle(idp, registry);
    assert.equal(r3.pushed, false, '바뀐 것이 없는데 전이를 올렸다');
    assert.equal(
      String(await registry.latestRoot()).toLowerCase(),
      String(r3.committed.root).toLowerCase(),
      'no-op 회차인데 체인과 IdP의 root가 어긋났다',
    );
    console.log('OK: 5) 바뀐 서브트리가 없는 회차는 트랜잭션을 만들지 않는다');

    // ── 6) 만료 회수도 같은 스트림으로 올라간다 ───────────────────────────
    // 계정 리프가 만료되도록 블록을 진행시킨 뒤 한 회차 돈다.
    await provider.send('hardhat_mine', [`0x${(MAX_CREDENTIAL_SPAN + 1).toString(16)}`]);
    const r4 = await publishCycle(idp, registry);
    assert.ok(r4.pushed, '만료 회수가 전이로 올라가지 않았다');
    assert.ok(
      r4.updates.some((u) => u.kind === 2),
      `계정 회수(kind=2)가 없다: ${JSON.stringify(r4.updates.map((u) => u.kind))}`,
    );
    assert.equal(
      String(await registry.latestRoot()).toLowerCase(),
      String(r4.committed.root).toLowerCase(),
      '회수를 접은 결과가 IdP와 다르다',
    );
    console.log(`OK: 6) 만료 회수가 같은 스트림으로 올라가고 root가 일치한다 (gas ${r4.gasUsed})`);

    // ── 7) push 없이 커밋한 회차도 다음 사이클이 수습한다 ────────────────
    //
    // 이것이 2026-09-07 전환 중 실제로 시스템을 갈라놓은 경로다. 전이를 회차 버퍼로 두고
    // 응답에 실을 때 비웠더니, 커밋했지만 push하지 않은 회차의 전이가 사라졌다. 그러면
    // 다음 사이클의 전이는 체인의 옛 상태와 맞지 않아 거부되고, **V4에는 root를 직접 미는
    // 경로가 없어 영영 따라잡을 수 없다** — 레지스트리를 다시 배포하는 것 말고 방법이 없었다.
    // 그래서 전이는 push가 확인될 때까지 남는 백로그가 됐다.
    {
      const skipped = uniqueValue();
      assert.equal((await idp.post('/idp/revoke', { type: 'account', value: skipped })).status, 200);
      const c = await commitOnly(idp);                    // 커밋만, push 없음
      assert.ok(c.updates.length > 0, '커밋했는데 전이가 없다');
      const rootBefore = await registry.latestRoot();
      assert.notEqual(
        String(rootBefore).toLowerCase(), String(c.root).toLowerCase(),
        '전제가 깨졌다: push하지 않았는데 체인이 이미 따라와 있다',
      );

      // 다음 사이클은 백로그(지난 회차 + 이번 회차)를 통째로 올려 체인을 따라잡혀야 한다.
      const another = uniqueValue();
      assert.equal((await idp.post('/idp/revoke', { type: 'account', value: another })).status, 200);
      const r = await publishCycle(idp, registry);
      assert.ok(r.pushed);
      assert.ok(
        r.updates.length >= 2,
        `백로그가 누락됐다: 전이 ${r.updates.length}건 (지난 회차분이 빠졌다)`,
      );
      assert.equal(
        String(await registry.latestRoot()).toLowerCase(),
        String(r.committed.root).toLowerCase(),
        '백로그를 올렸는데도 체인이 IdP를 따라잡지 못했다',
      );
      console.log('OK: 7) push 없이 커밋한 회차도 다음 사이클이 백로그로 수습한다');
    }

    console.log('\n== V4 게시 사이클 7종 통과 ==');
  } finally {
    await idp.stop();
  }
}

main().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
