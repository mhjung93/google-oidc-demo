// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice 폐기 트리 root의 순환 버퍼. IdP만 갱신할 수 있고,
///         최근 K개 슬롯 중 아직 만료되지 않은 root를 유효한 것으로 인정한다(grace window).
///
///         K개를 허용하는 이유: root가 바뀔 때마다 모든 지갑이 재증명해야 하면
///         세션당 1회 증명이라는 이점이 사라진다. K는 "캐시 여유"일 뿐이고,
///         실제 보안 경계는 아래 GRACE_BLOCKS(신선도 정책)가 담당한다.
///
///         K만으로 신선도를 정하면 폐기가 드문 환경에서 옛 root가 사실상
///         영원히 유효해진다(슬롯을 밀어내려면 서로 다른 폐기 이벤트가 K건
///         필요하므로). 그러면 폐기된 크레덴셜이 max_height 자연 만료까지
///         살아남아 폐기 기능이 아무 것도 앞당기지 못한다. 그래서 슬롯 수와
///         신선도를 분리해 블록 기반 만료를 따로 강제한다.
contract RevocationRegistry {
    uint256 public constant K = 8;

    /// @notice root가 게시된 뒤 유효한 것으로 인정되는 블록 수.
    /// @dev 200블록 × 12초 = 40분. max_height 창(300블록 = 1시간)보다 엄격히 짧아야
    ///      폐기가 자연 만료보다 먼저 효력을 갖는다. spec §5.4의 K×T 상한을 코드가
    ///      실제로 강제하는 형태.
    uint256 public constant GRACE_BLOCKS = 200;

    struct Entry {
        bytes32 root;
        uint64 pushedAt; // 게시된 블록 번호
    }

    address public immutable idp;
    Entry[K] private entries;
    uint256 private head; // 다음에 쓸 슬롯
    /// @notice 채워진 슬롯 수 (K에서 포화). 지갑이 윈도우 상태를 조회할 수 있도록 공개한다.
    uint256 public filled;

    error NotIdP();

    event RootPushed(bytes32 indexed root, uint256 index);

    constructor(address _idp) {
        idp = _idp;
    }

    modifier onlyIdP() {
        if (msg.sender != idp) revert NotIdP();
        _;
    }

    /// @notice 같은 root를 다시 게시하는 것은 정상 동작이다 — 신선도(pushedAt)를
    ///         갱신하는 주기적 heartbeat 경로가 된다.
    function pushRoot(bytes32 newRoot) external onlyIdP {
        entries[head] = Entry({root: newRoot, pushedAt: uint64(block.number)});
        emit RootPushed(newRoot, head);
        head = (head + 1) % K;
        if (filled < K) filled += 1;
    }

    /// @notice root가 윈도우 안에 있고 아직 만료되지 않았는가.
    /// @dev K가 상수 8이므로 선형 탐색이 매핑보다 싸다(축출 시 매핑 정리 비용이 없음).
    ///      같은 root가 여러 슬롯에 들어갈 수 있으므로(주기적 재게시) 첫 일치에서
    ///      멈추면 안 된다 — 그 슬롯이 가장 오래된 것일 수 있고, 그러면 만료가
    ///      실제보다 일찍 걸려 정상 사용자가 막힌다. 끝까지 순회하며 가장 최근
    ///      게시 시각을 기준으로 판정한다.
    function isRecentRoot(bytes32 root) external view returns (bool) {
        bool found = false;
        uint64 newestPushedAt = 0;
        for (uint256 i = 0; i < filled; i++) {
            if (entries[i].root == root) {
                if (!found || entries[i].pushedAt > newestPushedAt) {
                    newestPushedAt = entries[i].pushedAt;
                    found = true;
                }
            }
        }
        if (!found) return false;
        return block.number - uint256(newestPushedAt) <= GRACE_BLOCKS;
    }

    function latestRoot() external view returns (bytes32) {
        if (filled == 0) return bytes32(0);
        return entries[(head + K - 1) % K].root;
    }
}
