// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice 폐기 트리 이중 구조(v3)의 상위 root를 보관한다. IdP만 갱신할 수 있다.
///
///         설계: docs/superpowers/specs/2026-09-05-revocation-dual-tree-design.md 6절
///
///         RevocationRegistry(v1)와의 차이는 **블록 단위 유예 창** 하나다.
///
///         v1은 "최신 root만 유효"였다. 배칭(수 분 주기) 덕에 root가 드물게 바뀌어서
///         유예 없이도 인플라이트 트랜잭션이 거의 걸리지 않았기 때문이다(43ca1bc가
///         grace window와 K-슬롯 링을 제거한 근거). 그런데 샤딩으로 게시 주기를 블록
///         단위까지 줄이면 그 전제가 깨진다 — 상위 root는 아무 폐기에나 바뀌므로 제출과
///         채굴 사이에 바뀌는 일이 흔해진다.
///
///         그래서 유예를 되살리되 **root 개수가 아니라 블록 수로** 잰다. 개수로 재면
///         변경이 드문 구간에서 옛 root가 오래 살아남아 폐기 지연이 폐기 빈도에 의존하게
///         된다. 블록 수로 재면 폐기 지연이 graceBlocks로 **고정**된다.
contract RevocationRegistryV3 {
    address public immutable idp;

    /// @notice 밀려난 root를 몇 블록 더 받아줄지. 그대로 폐기 효력 지연이 된다.
    uint256 public immutable graceBlocks;

    bytes32 public latestRoot;
    uint64 public latestRootBlock;

    /// @dev 최신에서 밀려난 root와 밀려난 블록. 블록당 최대 1회 게시를 전제로 하면
    ///      유예 창 안에 있을 수 있는 root는 graceBlocks개뿐이므로 링 8칸이면 넉넉하다.
    ///      한 블록에 여러 번 게시하면 아직 창 안에 있는 root가 일찍 밀려날 수 있는데,
    ///      그 방향은 "받아주던 것을 안 받아줌"이라 안전하다(fail-closed).
    uint256 private constant RING = 8;
    struct Superseded {
        bytes32 root;
        uint64 supersededAt;
    }
    Superseded[RING] private ring;
    uint256 private ringHead;

    error NotIdP();
    /// @notice root 0은 "미게시" 표식이라 게시 대상이 될 수 없다.
    error EmptyRoot();
    error GraceOutOfRange(uint256 graceBlocks);

    /// @param heartbeat 값이 바뀌지 않은 재게시였는지. 유예 창에 영향이 없다.
    event RootPushed(bytes32 indexed root, bool heartbeat);

    constructor(address _idp, uint256 _graceBlocks) {
        // 링보다 크면 유예 창 안의 root가 링에서 밀려나 조용히 거부되기 시작한다.
        if (_graceBlocks == 0 || _graceBlocks > RING - 2) revert GraceOutOfRange(_graceBlocks);
        idp = _idp;
        graceBlocks = _graceBlocks;
    }

    modifier onlyIdP() {
        if (msg.sender != idp) revert NotIdP();
        _;
    }

    /// @notice 새 상위 root를 게시한다. 같은 값을 다시 밀면 아무것도 바뀌지 않는다.
    /// @dev 같은 root의 재게시(heartbeat)를 유예 링에 넣지 않는 것이 중요하다. 넣으면
    ///      아직 최신인 root가 "밀려난 것"으로 기록돼 graceBlocks 뒤에 스스로 만료된다.
    function pushRoot(bytes32 newRoot) external onlyIdP {
        if (newRoot == bytes32(0)) revert EmptyRoot();
        if (newRoot == latestRoot) {
            emit RootPushed(newRoot, true);
            return;
        }
        if (latestRoot != bytes32(0)) {
            ring[ringHead] = Superseded({ root: latestRoot, supersededAt: uint64(block.number) });
            ringHead = (ringHead + 1) % RING;
        }
        latestRoot = newRoot;
        latestRootBlock = uint64(block.number);
        emit RootPushed(newRoot, false);
    }

    /// @notice 이 root로 지금 증명을 제출할 수 있는가.
    /// @dev 최신이면 무조건 통과하고(가장 흔한 경로라 SLOAD 한 번에 끝난다), 아니면
    ///      유예 링을 훑는다. root 0은 "미게시" 표식이자 링의 초기값이므로 언제나 거부한다.
    function isAcceptableRoot(bytes32 root) public view returns (bool) {
        if (root == bytes32(0)) return false;
        if (root == latestRoot) return true;
        for (uint256 i = 0; i < RING; i++) {
            Superseded storage e = ring[i];
            if (e.root == root && block.number <= uint256(e.supersededAt) + graceBlocks) {
                return true;
            }
        }
        return false;
    }

    /// @notice 운영 진단용 — 유예 링의 현재 내용.
    function graceEntries() external view returns (bytes32[RING] memory roots, uint64[RING] memory blocks_) {
        for (uint256 i = 0; i < RING; i++) {
            roots[i] = ring[i].root;
            blocks_[i] = ring[i].supersededAt;
        }
    }
}
