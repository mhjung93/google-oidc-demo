// 삽입 전이 회로(13.2절)의 건전성·완전성 검사.
//   node tests/test_insert_transition_circuit.mjs
//
// 전제: build/mode2_v4/의 wasm/zkey. 없으면 회로 컴파일 + 신뢰 설정이 먼저다.
//
// 무엇을 고정하는가.
//   완전성 — 라이브러리가 실제로 한 삽입은 증명이 만들어지고 검증된다.
//   건전성 — 다음이 **전부 실패**해야 한다:
//     · newRoot를 다른 값으로 바꾼 증명
//     · 다른 서브트리의 root에서 출발했다고 주장하는 증명
//     · 순서 조건을 어긴 삽입(low가 실제 predecessor가 아님)
//     · 이미 찬 슬롯에 쓰려는 삽입
//     · newValue = 0 (anchor/빈 슬롯 표식)
//
// 건전성 쪽은 "증명이 안 만들어진다"로 확인한다. 회로 제약이 걸리면 witness 생성 자체가
// 실패하기 때문이다 — 잘못된 증명이 **만들어진 뒤 검증에서 걸리는** 것이 아니라 애초에
// 만들어지지 않는다는 것이 더 강한 성질이다.
import assert from 'node:assert/strict';
import { createIMTv2 } from '../lib/imt_v2.js';
import { leafValue, TAG_ACCOUNT, ACCOUNT_SUBTREE_DEPTH } from '../lib/imt_v3.js';
import {
  proveInsertTransition,
  verifyInsertTransition,
  buildInsertInput,
  circuitFor,
  INSERT_BATCH_K,
} from '../lib/transition_proof.js';
import * as snarkjs from 'snarkjs';

const LAYER = 'account';
const DEPTH = ACCOUNT_SUBTREE_DEPTH;

/** 회로 입력 하나로 witness가 만들어지는가. 실패하면 이유를 문자열로 돌려준다. */
async function tryProve(input) {
  const c = circuitFor(LAYER);
  try {
    await snarkjs.groth16.fullProve(input, c.wasm, c.zkey);
    return null;
  } catch (err) {
    return String(err.message ?? err);
  }
}

async function main() {
  const vals = [];
  for (let i = 0; i < 6; i++) vals.push((await leafValue(TAG_ACCOUNT, 900000n + BigInt(i))).toString());

  // ── 1) 완전성 — 실제 삽입 2건이 증명되고 검증된다 ─────────────────────
  const tree = await createIMTv2(DEPTH);
  const t0 = await tree.insertWithTranscript(vals[0]);
  const t1 = await tree.insertWithTranscript(vals[1]);
  assert.ok(t0 && t1, '전이 기록이 나오지 않았다');
  assert.equal(t1.oldRoot, t0.newRoot, '기록이 이어지지 않는다');
  assert.equal(t1.newRoot, tree.getRoot().toString(), '기록의 최종 root가 트리 root와 다르다');

  const r = await proveInsertTransition(LAYER, [t0, t1]);
  assert.ok(await verifyInsertTransition(LAYER, r.proof, r.publicSignals), '증명 검증 실패');
  assert.deepEqual(
    r.publicSignals.map(String),
    [t0.oldRoot, t1.newRoot],
    '공개 신호가 [oldRoot, newRoot] 순서가 아니다 — 컨트랙트가 반대로 읽는다',
  );
  console.log('OK: 1) 실제 삽입 2건의 전이가 증명되고, 공개 신호는 [oldRoot, newRoot]다');

  // ── 2) 패딩 — 1건만 넣어도 K개 자리를 채워 통과한다 ───────────────────
  const tree2 = await createIMTv2(DEPTH);
  const s0 = await tree2.insertWithTranscript(vals[2]);
  const r2 = await proveInsertTransition(LAYER, [s0]);
  assert.ok(await verifyInsertTransition(LAYER, r2.proof, r2.publicSignals));
  assert.equal(r2.publicSignals[1], s0.newRoot);
  console.log(`OK: 2) 삽입 1건도 K=${INSERT_BATCH_K} 회로에서 패딩으로 통과한다`);

  // ── 3) 건전성 — newRoot를 바꾸면 witness가 만들어지지 않는다 ──────────
  {
    const input = buildInsertInput([t0, t1], DEPTH);
    input.newRoot = (BigInt(input.newRoot) + 1n).toString();
    const err = await tryProve(input);
    assert.ok(err, 'newRoot를 바꿨는데 증명이 만들어졌다');
    console.log('OK: 3) newRoot 위조는 witness 생성에서 막힌다');
  }

  // ── 4) 건전성 — oldRoot를 바꾸면 막힌다 (다른 서브트리에서 출발 주장) ──
  {
    const input = buildInsertInput([t0, t1], DEPTH);
    input.oldRoot = (BigInt(input.oldRoot) + 1n).toString();
    const err = await tryProve(input);
    assert.ok(err, 'oldRoot를 바꿨는데 증명이 만들어졌다');
    console.log('OK: 4) oldRoot 위조는 witness 생성에서 막힌다');
  }

  // ── 5) 건전성 — 순서 조건 위반 ────────────────────────────────────────
  // low 리프가 **트리의 멤버이면서도 predecessor가 아닌** 경우를 만든다. 멤버십만
  // 검사하고 순서를 안 보면 통과해 버리는데, 그러면 연결 리스트에 구멍이 생겨 그 구간에
  // 거짓 비멤버십이 만들어진다. 멤버십 제약에 먼저 걸려 버리면 순서 제약이 있는지
  // 확인한 것이 아니므로, low 리프를 **실재하는 다른 리프**로 바꿔치기한다.
  {
    const sorted = [vals[3], vals[4], vals[5]]
      .map(BigInt).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).map(String);
    const [A, M, B] = sorted;   // A < M < B

    // 상태 S = {A, B}. 두 트리를 같은 상태로 만들어 서로의 기록을 섞을 수 있게 한다.
    const tA = await createIMTv2(DEPTH);
    await tA.insert(A);
    await tA.insert(B);
    const tB = await createIMTv2(DEPTH);
    await tB.insert(A);
    await tB.insert(B);
    assert.equal(tA.getRoot().toString(), tB.getRoot().toString(), '두 트리가 같은 상태가 아니다');

    // (i) B보다 큰 값을 넣는 기록 -> low가 B다. 여기서 B의 리프와 경로를 얻는다.
    const bigger = (BigInt(B) + 1n).toString();
    const viaB = await tA.insertWithTranscript(bigger);
    assert.equal(viaB.lowValue, B, 'low가 B가 아니다 — 테스트 전제가 깨졌다');

    // (ii) M을 넣는 진짜 기록 -> low는 A다.
    const real = await tB.insertWithTranscript(M);
    assert.equal(real.lowValue, A, 'low가 A가 아니다 — 테스트 전제가 깨졌다');

    // (iii) M의 low를 B로 바꿔치기한다. B는 실재하는 멤버라 멤버십 검사는 통과하고,
    //       lowValue(B) > newValue(M)이라 순서 검사에서 걸려야 한다.
    const input = buildInsertInput([real], DEPTH);
    input.lowValue[0] = viaB.lowValue;
    input.lowNextIndex[0] = viaB.lowNextIndex;
    input.lowNextValue[0] = viaB.lowNextValue;
    input.lowPathIndices[0] = viaB.lowPathIndices;
    input.lowSiblings[0] = viaB.lowSiblings;

    const err = await tryProve(input);
    assert.ok(err, 'low가 predecessor가 아닌데 증명이 만들어졌다');
    assert.match(err, /line: 12[0-9]|line: 13[0-9]/,
      `순서 제약이 아니라 다른 제약에서 걸렸다 — 순서 제약을 검사한 것이 아니다: ${err}`);
    console.log('OK: 5) 멤버이지만 predecessor가 아닌 low는 순서 제약에서 막힌다');
  }

  // ── 6) 건전성 — 이미 찬 슬롯에 쓰려는 삽입 ────────────────────────────
  // newIndex를 이미 쓰인 슬롯으로 바꾸면 "그 슬롯이 비어 있다"는 4단계가 깨진다.
  // 막지 못하면 기존 리프를 덮어써서 폐기를 지울 수 있다.
  {
    const input = buildInsertInput([t0, t1], DEPTH);
    input.newIndex[1] = '1';                       // 이미 t0가 쓴 슬롯
    input.newPathIndices[1] = input.newPathIndices[1].map((_, i) => (i === 0 ? '1' : '0'));
    const err = await tryProve(input);
    assert.ok(err, '이미 찬 슬롯에 쓰는데 증명이 만들어졌다');
    console.log('OK: 6) 이미 찬 슬롯에 쓰려는 삽입은 막힌다');
  }

  // ── 7) 건전성 — newValue = 0 ──────────────────────────────────────────
  // 0은 anchor 값이자 빈 슬롯 표식이다. 리프로 들어가면 anchor와 모양이 같아져
  // 모든 target을 통과시키는 low 리프가 생긴다.
  {
    const input = buildInsertInput([t0], DEPTH);
    input.newValue[0] = '0';
    const err = await tryProve(input);
    assert.ok(err, 'newValue=0인데 증명이 만들어졌다');
    console.log('OK: 7) newValue = 0 은 막힌다');
  }

  // ── 8) 건전성 — active를 꺼도 root는 못 건너뛴다 ──────────────────────
  // 꺼진 단계는 root를 그대로 통과시킬 뿐이므로, 전부 끄면 oldRoot == newRoot여야 한다.
  // 즉 "아무것도 안 하고 root만 바꾸기"가 되지 않는다.
  {
    const input = buildInsertInput([t0, t1], DEPTH);
    for (let i = 0; i < INSERT_BATCH_K; i++) input.active[i] = '0';
    const err = await tryProve(input);
    assert.ok(err, '전 단계를 껐는데 oldRoot != newRoot 전이가 증명됐다');
    console.log('OK: 8) 단계를 끄면 root가 그대로여야 한다 — 빈 전이로 root를 바꿀 수 없다');
  }

  console.log('\n== 삽입 전이 회로 8종 통과 ==');
}

main().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
