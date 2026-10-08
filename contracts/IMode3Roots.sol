// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
/// @title 검증자가 읽는 폐기 상태 — 캐노니컬 Mode3Log(폐기 체인)와 Mode3Mirror(응용 체인)가 같은 모양으로 낸다(V10 설계 §2).
interface IMode3Roots {
    function revRoot() external view returns (bytes32);
    function regRoot() external view returns (bytes32);
    function epoch() external view returns (uint64);
    function lastPublishedBlock() external view returns (uint64);
}
