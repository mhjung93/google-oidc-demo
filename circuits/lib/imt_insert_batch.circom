pragma circom 2.0.0;

include "poseidon.circom";
include "comparators.circom";
include "mux1.circom";
include "bitify.circom";

// 깊이 d 서브트리에 K건까지 삽입한 **전이의 정당성** 증명 (설계 문서 13.2절).
//
// 무엇을 증명하는가. "oldRoot에서 시작해 유효한 IMT 삽입을 K건(패딩 포함) 적용하면
// newRoot가 나온다." 공개 신호는 oldRoot와 newRoot 둘뿐이다.
//
// 왜 필요한가. RevocationRegistryV3까지는 컨트랙트가 게시된 root가 실제 트리와 맞는지
// 전혀 검증하지 않았다 — 레지스트리 키가 폐기 무결성의 단일 신뢰점이었다. 키를 쥔 쪽은
// (1) 옛 root를 다시 올려 그동안의 폐기를 통째로 되돌리거나, (2) 아무도 witness를 만들 수
// 없는 쓰레기 root를 올려 전원을 막거나, (3) 특정 폐기만 빠뜨린 root를 올릴 수 있었다.
//
// 이 회로가 (1)과 (3)을 막는다. 삽입은 **리프를 더하기만** 하므로, 전이가 이 회로로
// 증명되면 폐기 집합은 줄어들 수 없다. (2)는 컨트랙트 쪽에서 막는다 — 새 root를 받지 않고
// 현재 root에서 유도하기 때문이다. **막을 수 없는 것은 애초에 제출되지 않은 폐기의 누락**
// 이다. 체인은 무엇이 폐기돼야 하는지 모른다(설계 문서 12절과 논문 §IV-G에 명시).
//
// == 삽입 한 건의 의미 ==
// lib/imt_v2.js / lib/imt_v3.js의 insert()와 정확히 같아야 한다:
//   1. low 리프 (lowValue, lowNextIndex, lowNextValue)가 현재 트리에 있다
//   2. lowValue < newValue 이고, (lowNextValue == 0 이거나 newValue < lowNextValue)
//   3. low 리프를 (lowValue, newIndex, newValue)로 갱신한다
//   4. 그 중간 트리에서 newIndex 슬롯이 **비어 있다**(리프 리터럴 0)
//   5. 그 자리에 (newValue, lowNextIndex, lowNextValue)를 쓴다
//
// 4번의 "빈 슬롯 = 리터럴 0"은 라이브러리와 같은 관례다(lib/imt_v2.js의 zeros[0] = 0n).
// 빈 슬롯을 Poseidon(0,0,0)으로 두지 않은 이유도 거기 적혀 있다.
//
// == 왜 newIndex가 append 위치인지 검사하지 않는가 ==
// 검사할 필요가 없다. 비멤버십의 건전성은 anchor에서 시작하는 **연결 리스트가 값 구간을
// 빠짐없이 덮는가**에 달려 있고, 그것은 위 1~5로 보존된다. 물리 인덱스를 어디에 쓰든
// (빈 슬롯이기만 하면) 리스트는 여전히 정합적이다. 인덱스 선택이 바꾸는 것은 root뿐인데,
// root는 바로 이 증명의 결론이므로 자유도가 남지 않는다.
//
// == 패딩 ==
// 한 회차에 실제로 삽입되는 건수는 매번 다른데 회로는 고정 크기다. 그래서 active[i]로
// 단계를 끄고, 꺼진 단계의 모든 제약을 active로 곱해 무력화한다. 꺼진 단계는 root를
// 그대로 통과시킨다. 입력은 전부 0으로 채우면 된다.
template IMTInsertBatch(depth, K) {
    assert(depth >= 1);
    assert(K >= 1);

    signal input oldRoot;
    signal input newRoot;

    signal input active[K];
    signal input newValue[K];
    signal input lowValue[K];
    signal input lowNextIndex[K];
    signal input lowNextValue[K];
    signal input lowPathIndices[K][depth];
    signal input lowSiblings[K][depth];
    signal input newIndex[K];
    signal input newPathIndices[K][depth];
    signal input newSiblings[K][depth];

    signal roots[K + 1];
    roots[0] <== oldRoot;

    component lowLeafOld[K];
    component lowLeafNew[K];
    component newLeaf[K];
    component lowClimbOld[K];
    component lowClimbNew[K];
    component emptyClimb[K];
    component newClimb[K];
    component rangeNew[K];
    component rangeLow[K];
    component rangeNext[K];
    component ltLow[K];
    component ltHigh[K];
    component isLast[K];
    component pickHigh[K];
    component pickRoot[K];
    component isZeroNew[K];

    signal midRoot[K];

    for (var s = 0; s < K; s++) {
        active[s] * (1 - active[s]) === 0;

        // ── 1) low 리프가 현재 트리에 있다 ───────────────────────────────
        lowLeafOld[s] = Poseidon(3);
        lowLeafOld[s].inputs[0] <== lowValue[s];
        lowLeafOld[s].inputs[1] <== lowNextIndex[s];
        lowLeafOld[s].inputs[2] <== lowNextValue[s];

        lowClimbOld[s] = MerkleClimb(depth);
        lowClimbOld[s].leaf <== lowLeafOld[s].out;
        for (var i = 0; i < depth; i++) {
            lowClimbOld[s].pathIndices[i] <== lowPathIndices[s][i];
            lowClimbOld[s].siblings[i] <== lowSiblings[s][i];
        }
        // 꺼진 단계에서는 검사하지 않는다.
        active[s] * (lowClimbOld[s].root - roots[s]) === 0;

        // ── 2) 순서 조건 ─────────────────────────────────────────────────
        // 모든 리프 값은 lib/imt.js의 leafValue()가 하위 252비트로 정규화한 값이다.
        // 비교 전에 그 범위를 실제로 강제한다(비멤버십 회로와 같은 관례).
        rangeNew[s] = Num2Bits(252);
        rangeNew[s].in <== newValue[s];
        rangeLow[s] = Num2Bits(252);
        rangeLow[s].in <== lowValue[s];
        rangeNext[s] = Num2Bits(252);
        rangeNext[s].in <== lowNextValue[s];

        // newValue != 0 — 0은 anchor이자 빈 슬롯 표식이라 폐기 값이 될 수 없다.
        isZeroNew[s] = IsZero();
        isZeroNew[s].in <== newValue[s];
        active[s] * isZeroNew[s].out === 0;

        ltLow[s] = LessThan(252);
        ltLow[s].in[0] <== lowValue[s];
        ltLow[s].in[1] <== newValue[s];
        active[s] * (1 - ltLow[s].out) === 0;

        isLast[s] = IsZero();
        isLast[s].in <== lowNextValue[s];
        ltHigh[s] = LessThan(252);
        ltHigh[s].in[0] <== newValue[s];
        ltHigh[s].in[1] <== lowNextValue[s];
        pickHigh[s] = Mux1();
        pickHigh[s].c[0] <== ltHigh[s].out;
        pickHigh[s].c[1] <== 1;            // lowNextValue == 0 이면 상한이 없다
        pickHigh[s].s <== isLast[s].out;
        active[s] * (1 - pickHigh[s].out) === 0;

        // ── 3) low 리프를 갱신한 중간 트리 ───────────────────────────────
        // newIndex가 실제로 아래 새 리프의 경로 비트와 같은 값인지 묶는다. 안 묶으면
        // low 리프의 포인터가 새 리프의 실제 위치와 어긋난 채 통과한다.
        // 비트의 boolean 제약은 MerkleClimb이 건다.
        var accIdx = 0;
        for (var i = 0; i < depth; i++) {
            accIdx += newPathIndices[s][i] * (1 << i);
        }
        active[s] * (newIndex[s] - accIdx) === 0;

        lowLeafNew[s] = Poseidon(3);
        lowLeafNew[s].inputs[0] <== lowValue[s];
        lowLeafNew[s].inputs[1] <== newIndex[s];
        lowLeafNew[s].inputs[2] <== newValue[s];

        lowClimbNew[s] = MerkleClimb(depth);
        lowClimbNew[s].leaf <== lowLeafNew[s].out;
        for (var i = 0; i < depth; i++) {
            lowClimbNew[s].pathIndices[i] <== lowPathIndices[s][i];
            lowClimbNew[s].siblings[i] <== lowSiblings[s][i];
        }
        midRoot[s] <== lowClimbNew[s].root;

        // ── 4) 그 중간 트리에서 newIndex 슬롯이 비어 있다 ────────────────
        emptyClimb[s] = MerkleClimb(depth);
        emptyClimb[s].leaf <== 0;
        for (var i = 0; i < depth; i++) {
            emptyClimb[s].pathIndices[i] <== newPathIndices[s][i];
            emptyClimb[s].siblings[i] <== newSiblings[s][i];
        }
        active[s] * (emptyClimb[s].root - midRoot[s]) === 0;

        // ── 5) 그 자리에 새 리프를 쓴다 ──────────────────────────────────
        newLeaf[s] = Poseidon(3);
        newLeaf[s].inputs[0] <== newValue[s];
        newLeaf[s].inputs[1] <== lowNextIndex[s];
        newLeaf[s].inputs[2] <== lowNextValue[s];

        newClimb[s] = MerkleClimb(depth);
        newClimb[s].leaf <== newLeaf[s].out;
        for (var i = 0; i < depth; i++) {
            newClimb[s].pathIndices[i] <== newPathIndices[s][i];
            newClimb[s].siblings[i] <== newSiblings[s][i];
        }

        // 꺼진 단계는 root를 그대로 통과시킨다.
        pickRoot[s] = Mux1();
        pickRoot[s].c[0] <== roots[s];
        pickRoot[s].c[1] <== newClimb[s].root;
        pickRoot[s].s <== active[s];
        roots[s + 1] <== pickRoot[s].out;
    }

    newRoot === roots[K];
}

// 리프 하나와 경로로 root를 계산한다. 방향 비트는 호출자가 제약한다.
template MerkleClimb(depth) {
    signal input leaf;
    signal input pathIndices[depth];
    signal input siblings[depth];
    signal output root;

    component h[depth];
    component muxL[depth];
    component muxR[depth];
    signal cur[depth + 1];
    cur[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // 방향 비트가 boolean이 아니면 Mux1이 실제 Merkle 경로가 아닌 값을 낸다.
        // circomlib의 Mux1은 s를 boolean으로 제약하지 않으므로 여기서 건다.
        pathIndices[i] * (1 - pathIndices[i]) === 0;
        muxL[i] = Mux1();
        muxL[i].c[0] <== cur[i];
        muxL[i].c[1] <== siblings[i];
        muxL[i].s <== pathIndices[i];
        muxR[i] = Mux1();
        muxR[i].c[0] <== siblings[i];
        muxR[i].c[1] <== cur[i];
        muxR[i].s <== pathIndices[i];
        h[i] = Poseidon(2);
        h[i].inputs[0] <== muxL[i].out;
        h[i].inputs[1] <== muxR[i].out;
        cur[i + 1] <== h[i].out;
    }
    root <== cur[depth];
}
