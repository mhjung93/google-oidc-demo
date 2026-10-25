// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
/// @title 검증자가 읽는 폐기 상태 — 캐노니컬 Mode3Log(폐기 체인)와 Mode3Mirror(응용 체인)가 같은 모양으로 낸다(V10 설계 §2).
interface IMode3Roots {
    function revRoot() external view returns (bytes32);
    function regRoot() external view returns (bytes32);
    function epoch() external view returns (uint64);
    function lastPublishedBlock() external view returns (uint64);
    /// @notice 2026-10-25 root 유효 창: root 가 최신이거나 대체된 지 window 블록 이내인가.
    function isAcceptableRevRoot(bytes32 root, uint64 window) external view returns (bool);
    function isAcceptableRegRoot(bytes32 root, uint64 window) external view returns (bool);
    /// @notice 거울에 공개된 세션별 상한(저장값 c + 1, 0 = 없음).
    function sessionBoundOf(uint256 pk_i) external view returns (uint256);
}
