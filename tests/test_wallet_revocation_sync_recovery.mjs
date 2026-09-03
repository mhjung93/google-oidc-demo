// 지갑의 폐기 트리 동기화 **실패·복구** 경로 단위 테스트.
//   node tests/test_wallet_revocation_sync_recovery.mjs
//
// 살아있는 IdP도 관리자 시크릿도 필요 없다 — globalThis.fetch를 가짜 IdP로 갈아끼워
// syncRevocationTreeV2()를 격리 실행한다. 기존 테스트(test_imt_v2_wiring.js)는 동기화가
// **성공하는** 경로만 보므로, 아래 두 상황은 어느 테스트도 덮지 않는다:
//
//   1) IdP가 어긋난 상태를 서빙했을 때 지갑이 다음 호출에서 스스로 복구하는가.
//      복구하지 못하면 모듈 캐시가 오염된 채 남아 /submitTransaction이 영구히 실패하고,
//      지갑을 손으로 재시작하는 것 말고는 방법이 없다.
//   2) 동기화가 겹쳤을 때 한쪽이 다른 쪽을 깨뜨리지 않는가.
//      깨지면 아무 잘못 없는 사용자의 트랜잭션이 실패한다.
import assert from 'node:assert/strict';
import { buildIMTv2 } from '../lib/imt_v2.js';
import { syncRevocationTreeV2, _resetRevocationTreeV2ForTest } from '../wallet_agent.js';

const DEPTH = 20; // wallet_agent.js의 REVOCATION_TREE_DEPTH_V2와 같아야 한다

// custom_idp.js의 v2LeafToStr와 같은 직렬화(리프는 문자열로 나간다).
const strLeaf = (l) => ({
  value: l.value.toString(),
  nextIndex: l.nextIndex.toString(),
  nextValue: l.nextValue.toString(),
});

// --- 가짜 IdP -------------------------------------------------------------
// 상태를 테스트가 직접 갈아끼운다. 응답 형태는 custom_idp.js의
// GET /idp/revocation_state_v2와 동일하게 맞춘다.
const idp = { tree: null, seq: 0, epoch: 0, incrementalHandler: null };

async function setIdpState(values, { seq, epoch }) {
  idp.tree = await buildIMTv2(DEPTH, values.map((v) => BigInt(v)));
  idp.seq = seq;
  idp.epoch = epoch;
}

const idpRoot = () => idp.tree.getRoot().toString();
const fullBody = () => ({
  epoch: idp.epoch,
  seq: idp.seq,
  root: idpRoot(),
  leaves: idp.tree.getLeaves().map(strLeaf),
});
const json = (body) => ({ ok: true, status: 200, json: async () => body });

globalThis.fetch = async (url) => {
  const u = new URL(String(url));
  if (u.searchParams.get('since') === null) return json(fullBody());
  if (idp.incrementalHandler) return idp.incrementalHandler(u);
  // 기본 증분 응답: 뒤처진 구간이 없다(현재 상태 그대로).
  return json({ epoch: idp.epoch, seq: idp.seq, root: idpRoot(), mutations: [] });
};

// --- 1. IdP가 뒤로 돌아갔을 때 다음 호출이 스스로 복구하는가 ----------------
// 시나리오: IdP가 커밋을 디스크에 저장하지 못한 채 재시작해, 같은 epoch에서 더 낮은
// seq와 옛 root를 서빙한다. 지갑의 since는 그 seq보다 크므로 IdP는 "적용할 변경 없음"을
// 돌려주고, 지갑의 로컬 root는 IdP root와 어긋난다.
{
  _resetRevocationTreeV2ForTest();
  idp.incrementalHandler = null;
  await setIdpState([11n, 22n, 33n], { seq: 6, epoch: 1 });

  const first = await syncRevocationTreeV2();
  assert.equal(first.mode, 'full', '첫 동기화는 전체 조회여야 한다');
  assert.equal(first.root, idpRoot());
  console.log('OK: 첫 동기화가 전체 조회로 IdP root와 일치한다');

  // IdP가 커밋 이전 상태로 되돌아갔다.
  await setIdpState([11n, 22n], { seq: 4, epoch: 1 });
  await assert.rejects(
    syncRevocationTreeV2(),
    /root/,
    '어긋난 root는 조용히 넘어가지 않고 드러나야 한다',
  );
  console.log('OK: root 불일치가 드러난다');

  // 핵심: 다음 호출은 오염된 캐시를 버리고 전체 재조회로 복구해야 한다.
  const recovered = await syncRevocationTreeV2();
  assert.equal(recovered.mode, 'full', '불일치 이후에는 전체 재조회로 폴백해야 한다');
  assert.equal(recovered.root, idpRoot(), '복구된 트리는 IdP root와 일치해야 한다');
  console.log('OK: 불일치 다음 호출이 전체 재조회로 스스로 복구한다');
}

// --- 2. 동기화는 겹쳐 실행되지 않아야 한다 ----------------------------------
// 동기화는 모듈 전역(트리·epoch·lastSeq)을 갈아끼운다. 두 호출이 겹치면 한쪽이 트리를
// 바꾼 뒤 다른 쪽이 자기 **옛** 응답의 root와 대조하게 돼, 아무 잘못이 없는데도
// "root 불일치"로 실패한다 — 그 사용자의 트랜잭션이 그냥 실패한다.
//
// 결과가 아니라 그 결과를 낳는 조건을 직접 단언한다: **미결 요청이 동시에 2개가 되면
// 안 된다.** 결과로 단언하려면 "B가 끝난 뒤 A가 재개되는" 인터리빙을 강제해야 하는데,
// 그건 직렬화가 들어가는 순간 교착이라 테스트로 성립하지 않는다.
{
  _resetRevocationTreeV2ForTest();
  idp.incrementalHandler = null;
  await setIdpState([11n, 22n, 33n], { seq: 6, epoch: 1 });
  await syncRevocationTreeV2(); // 트리 확보(이후 호출은 증분 분기로 들어간다)

  let outstanding = 0;
  let maxOutstanding = 0;
  idp.incrementalHandler = async () => {
    outstanding += 1;
    maxOutstanding = Math.max(maxOutstanding, outstanding);
    // 응답이 즉시 돌아오지 않는 실제 네트워크를 흉내낸다(겹칠 틈을 준다).
    await new Promise((r) => setTimeout(r, 10));
    outstanding -= 1;
    return json({ epoch: idp.epoch, seq: idp.seq, root: idpRoot(), mutations: [] });
  };

  const results = await Promise.all([syncRevocationTreeV2(), syncRevocationTreeV2()]);
  assert.equal(maxOutstanding, 1, '동기화 요청이 동시에 두 개 떠 있으면 안 된다(직렬화되어야 한다)');
  for (const r of results) {
    assert.equal(r.root, idpRoot(), '겹친 동기화 결과가 모두 IdP root와 일치해야 한다');
  }
  console.log('OK: 겹친 동기화가 직렬화되어 서로를 깨뜨리지 않는다');
}

console.log('PASS: 지갑이 어긋난 폐기 상태와 겹친 동기화에서 스스로 복구한다.');
