// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IMode3Roots.sol";

/// @title Mode 3 root 이력 + 세션별 counter — 캐노니컬 Mode3Log 와 거울 Mode3Mirror 의 공통 베이스
///   (설계 2026-10-25 root 유효 창 §2). 둘이 같은 코드를 공유해야 검증자(Mode3Wallet)가 어느 쪽을 읽어도 같은 답을 얻는다.
/// @notice 최신 root 외에 "대체된 블록" 을 최근 ROOT_HISTORY 개까지 기억한다. isAcceptable*Root(root, G) 는 최신이거나
///   대체된 지 G 블록 이내인 root 만 참이다. sessionBoundOf[pk_i] 는 IdP 가 게시 페이로드에 실어 보낸 세션별 허용
///   거래 수 c 를 **c + 1** 로 저장한다(0 = 미설정; Mode3Wallet.sessionBound 와 같은 인코딩. uint32 c 가 2^32−1 일 때
///   +1 이 넘치지 않게 uint256 으로 둔다).
abstract contract Mode3RootHistory is IMode3Roots {
    uint256 public constant ROOT_HISTORY = 16;

    bytes32 public revRoot;
    bytes32 public regRoot;
    uint64 public epoch;
    uint64 public lastPublishedBlock;

    /// @dev root → 그 root 가 대체된 블록 높이. 최신 root 와 이력 밖으로 밀린 root 는 0.
    mapping(bytes32 => uint64) public revSupersededAt;
    mapping(bytes32 => uint64) public regSupersededAt;
    bytes32[ROOT_HISTORY] private revHist;
    bytes32[ROOT_HISTORY] private regHist;
    uint256 private revPos;
    uint256 private regPos;

    /// @notice 세션키별 공개 상한: 저장값 = c + 1 (0 = 없음). 낮추기만 된다.
    mapping(uint256 => uint256) public sessionBoundOf;

    event SessionBoundPublished(uint256 indexed pk_i, uint32 bound, uint64 epoch);
    error LengthMismatch();

    constructor(bytes32 emptyRevRoot, bytes32 emptyRegRoot) {
        revRoot = emptyRevRoot;
        regRoot = emptyRegRoot;
        lastPublishedBlock = uint64(block.number);
    }

    function isAcceptableRevRoot(bytes32 root, uint64 window) public view returns (bool) {
        if (root == revRoot) return true;
        uint64 at = revSupersededAt[root];
        return at != 0 && block.number <= uint256(at) + uint256(window);
    }

    function isAcceptableRegRoot(bytes32 root, uint64 window) public view returns (bool) {
        if (root == regRoot) return true;
        uint64 at = regSupersededAt[root];
        return at != 0 && block.number <= uint256(at) + uint256(window);
    }

    /// @dev 링 버퍼에 옛 root 를 넣고 밀려난 root 의 기록을 지운다. 같은 root 가 다시 대체되면(등록부가 옛 값으로 돌아온 뒤
    ///   또 바뀜) 시각을 덮어쓴다 — 먼저 들어간 항목이 밀려날 때 새 기록까지 지워 liveness 만 조금 깎인다(안전과 무관).
    function _supersede(bytes32[ROOT_HISTORY] storage hist, uint256 pos, mapping(bytes32 => uint64) storage at, bytes32 old) private returns (uint256) {
        bytes32 evicted = hist[pos];
        if (evicted != bytes32(0)) delete at[evicted];
        hist[pos] = old;
        at[old] = uint64(block.number);
        return (pos + 1) % ROOT_HISTORY;
    }

    /// @dev 두 root·epoch·게시 블록을 갱신한다. 값이 바뀐 root 만 이력에 넣는다(하트비트 재게시는 이력을 건드리지 않는다).
    function _setRoots(bytes32 newRev, bytes32 newReg, uint64 newEpoch) internal {
        if (newRev != revRoot) revPos = _supersede(revHist, revPos, revSupersededAt, revRoot);
        if (newReg != regRoot) regPos = _supersede(regHist, regPos, regSupersededAt, regRoot);
        revRoot = newRev;
        regRoot = newReg;
        epoch = newEpoch;
        lastPublishedBlock = uint64(block.number);
    }

    /// @dev 세션별 상한 적용 — 낮추기만, 아니면 조용히 무시(게시 전체가 막히지 않게). 같은 pk_i 가 여러 번 실리면
    ///   순서대로 적용돼 최솟값이 남는다.
    function _applyBounds(uint256[] calldata boundKeys, uint32[] calldata boundValues, uint64 newEpoch) internal {
        if (boundKeys.length != boundValues.length) revert LengthMismatch();
        for (uint256 i = 0; i < boundKeys.length; i++) {
            uint256 cur = sessionBoundOf[boundKeys[i]];
            uint256 next = uint256(boundValues[i]) + 1;
            if (cur == 0 || next < cur) {
                sessionBoundOf[boundKeys[i]] = next;
                emit SessionBoundPublished(boundKeys[i], boundValues[i], newEpoch);
            }
        }
    }
}
