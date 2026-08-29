// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice 폐기 트리 root의 최신값 하나만 보관한다. IdP만 갱신할 수 있다.
///
///         배칭(폐기는 대기열에 쌓이고 주기적으로 게시)이 도입된 뒤로, heartbeat가
///         같은 root를 재게시할 때는 값이 바뀌지 않아 무효화가 없다. root가 실제로
///         바뀌는 것은 폐기가 게시될 때뿐이므로, grace window나 K개 순환 버퍼 없이
///         "최신 root만 유효"로도 폐기가 자연 만료(max_height)보다 먼저 효력을 갖는다.
///         그 대가로 root가 바뀌는 순간과 겹치는 인플라이트 트랜잭션은 revert된다
///         (docs/ .superpowers/sdd/drop-grace-brief.md 참고).
contract RevocationRegistry {
    address public immutable idp;
    bytes32 public latestRoot;

    error NotIdP();

    event RootPushed(bytes32 indexed root);

    constructor(address _idp) {
        idp = _idp;
    }

    modifier onlyIdP() {
        if (msg.sender != idp) revert NotIdP();
        _;
    }

    /// @notice 같은 root를 다시 게시해도 해롭지 않다(무의미한 heartbeat) — latestRoot가
    ///         이미 그 값이면 값 자체는 바뀌지 않는다.
    function pushRoot(bytes32 newRoot) external onlyIdP {
        latestRoot = newRoot;
        emit RootPushed(newRoot);
    }

    /// @notice root가 지금 유효한 최신 root인가.
    /// @dev latestRoot == 0은 "아직 아무 root도 게시되지 않음"(부트스트랩 전)을
    ///      뜻하므로, root가 0으로 전달돼도 latestRoot가 0인 동안은 통과시키지 않는다.
    function isCurrentRoot(bytes32 root) external view returns (bool) {
        if (latestRoot == bytes32(0)) return false;
        return root == latestRoot;
    }
}
