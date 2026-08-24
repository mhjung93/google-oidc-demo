// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice 폐기 트리 root의 순환 버퍼. IdP만 갱신할 수 있고,
///         최근 K개 root를 유효한 것으로 인정한다(grace window).
///
///         K개를 허용하는 이유: root가 바뀔 때마다 모든 지갑이 재증명해야 하면
///         세션당 1회 증명이라는 이점이 사라진다. 대신 폐기 반영이 최대
///         K번의 갱신만큼 늦어진다.
contract RevocationRegistry {
    uint256 public constant K = 8;

    address public immutable idp;
    bytes32[K] private roots;
    uint256 private head;      // 다음에 쓸 슬롯
    uint256 private filled;    // 채워진 슬롯 수 (K에서 포화)

    error NotIdP();

    event RootPushed(bytes32 indexed root, uint256 index);

    constructor(address _idp) {
        idp = _idp;
    }

    modifier onlyIdP() {
        if (msg.sender != idp) revert NotIdP();
        _;
    }

    function pushRoot(bytes32 newRoot) external onlyIdP {
        roots[head] = newRoot;
        emit RootPushed(newRoot, head);
        head = (head + 1) % K;
        if (filled < K) filled += 1;
    }

    /// @notice root가 최근 K개 안에 있는가.
    /// @dev K가 상수 8이므로 선형 탐색이 매핑보다 싸다(축출 시 매핑 정리 비용이 없음).
    function isRecentRoot(bytes32 root) external view returns (bool) {
        for (uint256 i = 0; i < filled; i++) {
            if (roots[i] == root) return true;
        }
        return false;
    }

    function latestRoot() external view returns (bytes32) {
        if (filled == 0) return bytes32(0);
        return roots[(head + K - 1) % K];
    }
}
