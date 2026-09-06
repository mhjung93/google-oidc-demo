// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IInsertTransitionVerifier {
    function verifyProof(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[2] calldata input
    ) external view returns (bool);
}

/// @notice 폐기 트리 상위 root를 보관하되, **새 root를 받지 않고 유도한다**.
///
///         설계: docs/superpowers/specs/2026-09-05-revocation-dual-tree-design.md 13.2절
///
///         == V3와 무엇이 다른가 ==
///         V3의 `pushRoot(bytes32)`는 IdP가 준 값을 그대로 저장했다. 그래서 레지스트리 키가
///         폐기 무결성의 단일 신뢰점이었고, 키를 쥔 쪽은 셋을 할 수 있었다:
///           (1) 롤백    — 옛 root를 다시 올려 그동안의 폐기를 통째로 되돌린다
///           (2) 쓰레기  — 아무도 witness를 만들 수 없는 root를 올려 전원을 막는다
///           (3) 선택 누락 — 특정 폐기만 빠뜨린 root를 올린다
///
///         V4는 root를 **받지 않는다.** 현재 상위 root에서 시작해, 검증된 서브트리 전이만
///         접어 올려 새 root를 계산한다. 그 결과:
///           (1) 롤백 불가   — 모든 전이는 현재 상태를 출발점으로 검증된다
///           (2) 쓰레기 불가 — 새 root는 계산 결과이지 입력이 아니다
///           (3) 삽입 전이는 ZK로 증명되므로 **폐기 집합은 줄어들 수 없다**
///
///         남는 것은 **애초에 제출되지 않은 폐기의 누락**이다. 체인은 무엇이 폐기돼야
///         하는지 모르므로 이것은 원리상 막을 수 없다(논문 §IV-G에도 명시).
///         그리고 아래 pushAccountRebaseline 하나가 증명되지 않는 조작으로 남는다.
///
///         == 전이의 종류 ==
///         Insert       — 서브트리에 리프를 K건까지 더한다. pi_ins_sess/pi_ins_acct 회로가
///                        (oldSubRoot -> newSubRoot)를 증명한다. 더하기만 하므로 안전 방향이다.
///         SessionReset — 세션 샤드를 통째로 비운다. **증명이 필요 없다** — 아래 참고.
///
///         == 세션 리셋을 컨트랙트가 스스로 검증할 수 있는 이유 ==
///         세션 샤드 인덱스는 s = (max_height mod 512) * 8 + (리프 하위 3비트)다. 즉 샤드
///         s에 들어가는 크레덴셜은 전부 max_height ≡ k (mod 512), k = s / 8 이다.
///         한편 IdP는 max_height <= 발급블록 + maxCredentialSpan(= 수명 300 + 여유 32 = 332)
///         만 발급한다.
///
///         현재 블록을 B라 하고 d = (k - B) mod 512 라 하자. d > 332 이면:
///           - k 잔여류이면서 B 이상인 가장 작은 값은 B + d > B + 332 이다.
///           - 이미 발급된 어떤 크레덴셜도 max_height <= 발급블록 + 332 <= B + 332 이므로
///             B + d 이상일 수 없다.
///           - 따라서 이 샤드의 발급된 모든 크레덴셜은 max_height < B, 즉 **전부 만료**다.
///         링 주기 512가 최대 수명 332보다 크기 때문에 성립한다. 샤드마다 매 주기
///         512 - 332 = 180블록의 리셋 창이 열린다.
///
///         이 성질이 없었다면 리셋도 ZK로 증명해야 했고, 그러려면 서브트리의 모든 리프
///         만료를 증명에 담아야 했다(깊이 8 = 리프 256개).
contract RevocationRegistryV4 {
    // ── 트리 형상. lib/imt_v3.js·PPIDWalletV3.sol과 반드시 같아야 한다 ──────
    uint256 private constant SESSION_RING = 512;
    uint256 private constant SESSION_VALUE_SPAN = 8;
    uint256 private constant SESSION_SHARD_COUNT = SESSION_RING * SESSION_VALUE_SPAN; // 4096
    uint256 private constant SESSION_TOP_DEPTH = 12;                                  // log2(4096)
    uint256 private constant ACCOUNT_SHARD_COUNT = 256;
    uint256 private constant ACCOUNT_TOP_DEPTH = 8;                                   // log2(256)

    address public immutable idp;
    uint256 public immutable graceBlocks;
    /// @notice IdP가 발급을 허용하는 max_height 상한 폭(수명 + 여유). 리셋 판정의 근거다.
    uint256 public immutable maxCredentialSpan;
    /// @notice 빈 서브트리의 root(필드 원소를 bytes32로). 리셋의 목적지다.
    bytes32 public immutable emptySessionSubRoot;

    IInsertTransitionVerifier public immutable sessVerifier;
    IInsertTransitionVerifier public immutable acctVerifier;

    /// @notice 두 층의 상위 root. 전이를 층별로 접어 올리므로 따로 들고 있어야 한다.
    bytes32 public sessionTop;
    bytes32 public accountTop;

    bytes32 public latestRoot;
    uint64 public latestRootBlock;

    /// @dev V3와 같은 블록 단위 유예 링. 근거는 V3 주석 참고.
    uint256 private constant RING = 8;
    struct Superseded {
        bytes32 root;
        uint64 supersededAt;
    }
    Superseded[RING] private ring;
    uint256 private ringHead;

    enum Kind {
        Insert,
        SessionReset
    }

    struct Update {
        Kind kind;
        /// @dev false = 세션 층, true = 계정 층
        bool account;
        uint16 shard;
        bytes32 oldSubRoot;
        bytes32 newSubRoot;
        /// @dev 상위 트리에서 이 샤드까지의 형제 경로. 길이는 층 깊이와 같아야 한다.
        bytes32[] siblings;
        uint[2] a;
        uint[2][2] b;
        uint[2] c;
    }

    error NotIdP();
    error EmptyRoot();
    error GraceOutOfRange(uint256 graceBlocks);
    error NoUpdates();
    error ShardOutOfRange(uint256 shard, uint256 bound);
    error BadSiblingsLength(uint256 got, uint256 want);
    /// @notice oldSubRoot가 그 샤드의 현재 내용이 아니다 — 롤백이거나 낡은 제출이다.
    error SubtreeMismatch(uint16 shard, bool account);
    error InvalidTransitionProof(uint16 shard, bool account);
    error ResetNotAllowedOnAccountLayer();
    error ResetMustGoToEmptyRoot();
    /// @notice 이 샤드에는 아직 만료되지 않았을 수 있는 크레덴셜이 있다.
    error SessionShardNotExpired(uint16 shard, uint256 distance);

    event RootPushed(bytes32 indexed root, bool heartbeat);
    event SubtreeUpdated(bool indexed account, uint16 indexed shard, bytes32 oldSubRoot, bytes32 newSubRoot, Kind kind);
    /// @notice **증명되지 않은** 계정 층 회수. 유일하게 폐기 집합을 줄일 수 있는 조작이다.
    event UntrustedAccountRebaseline(uint16 indexed shard, bytes32 oldSubRoot, bytes32 newSubRoot);

    constructor(
        address _idp,
        uint256 _graceBlocks,
        uint256 _maxCredentialSpan,
        bytes32 _emptySessionSubRoot,
        address _sessVerifier,
        address _acctVerifier,
        bytes32 _sessionTop,
        bytes32 _accountTop
    ) {
        if (_graceBlocks == 0 || _graceBlocks > RING - 2) revert GraceOutOfRange(_graceBlocks);
        // 리셋 판정이 성립하려면 링 주기가 최대 수명보다 커야 한다. 같거나 작으면
        // d > span 인 샤드가 없어 리셋 창이 아예 열리지 않는다(또는 잘못 열린다).
        require(_maxCredentialSpan < SESSION_RING, "span must be < ring");
        idp = _idp;
        graceBlocks = _graceBlocks;
        maxCredentialSpan = _maxCredentialSpan;
        emptySessionSubRoot = _emptySessionSubRoot;
        sessVerifier = IInsertTransitionVerifier(_sessVerifier);
        acctVerifier = IInsertTransitionVerifier(_acctVerifier);

        // 부트스트랩 상태는 신뢰 입력이다 — 배포 시점의 IdP 상태를 그대로 새긴다.
        // 이후로는 여기서 출발해 검증된 전이만 쌓이므로, 신뢰가 필요한 지점이 배포
        // 한 번으로 국한된다.
        sessionTop = _sessionTop;
        accountTop = _accountTop;
        bytes32 root = keccak256(abi.encodePacked(_sessionTop, _accountTop));
        if (root == bytes32(0)) revert EmptyRoot();
        latestRoot = root;
        latestRootBlock = uint64(block.number);
        emit RootPushed(root, false);
    }

    modifier onlyIdP() {
        if (msg.sender != idp) revert NotIdP();
        _;
    }

    /// @notice 검증된 전이들을 적용하고 새 상위 root를 **유도해** 게시한다.
    /// @dev 같은 샤드를 여러 번 갱신해도 된다 — 순차로 접으므로 앞 전이의 결과가 뒤
    ///      전이의 출발점이 된다. K를 넘는 삽입은 이렇게 나눠 넣는다.
    function pushUpdates(Update[] calldata ups) external onlyIdP {
        if (ups.length == 0) revert NoUpdates();

        bytes32 sTop = sessionTop;
        bytes32 aTop = accountTop;

        for (uint256 i = 0; i < ups.length; i++) {
            Update calldata u = ups[i];
            _checkShape(u);

            bytes32 layerTop = u.account ? aTop : sTop;
            // 1) oldSubRoot가 정말 그 샤드의 현재 내용인가. 이 검사가 롤백과 낡은 제출을
            //    한꺼번에 막는다 — 출발점이 현재 상태로 고정되기 때문이다.
            if (_climb(u.oldSubRoot, u.shard, u.siblings) != layerTop) {
                revert SubtreeMismatch(u.shard, u.account);
            }

            // 2) 전이 자체가 정당한가
            if (u.kind == Kind.SessionReset) {
                if (u.account) revert ResetNotAllowedOnAccountLayer();
                if (u.newSubRoot != emptySessionSubRoot) revert ResetMustGoToEmptyRoot();
                _requireSessionShardExpired(u.shard);
            } else {
                IInsertTransitionVerifier v = u.account ? acctVerifier : sessVerifier;
                uint[2] memory signals = [uint256(u.oldSubRoot), uint256(u.newSubRoot)];
                if (!v.verifyProof(u.a, u.b, u.c, signals)) {
                    revert InvalidTransitionProof(u.shard, u.account);
                }
            }

            // 3) 같은 형제 경로로 접어 올린다. 리프 하나만 바뀌었으므로 형제는 그대로다.
            bytes32 nextTop = _climb(u.newSubRoot, u.shard, u.siblings);
            if (u.account) aTop = nextTop;
            else sTop = nextTop;

            emit SubtreeUpdated(u.account, u.shard, u.oldSubRoot, u.newSubRoot, u.kind);
        }

        sessionTop = sTop;
        accountTop = aTop;
        _publish(keccak256(abi.encodePacked(sTop, aTop)));
    }

    /// @notice 계정 층 샤드의 만료 회수. **증명되지 않는다.**
    ///
    /// @dev 왜 증명할 수 없는가. 계정 폐기 리프의 만료는 접수 시점 + 수명이고, 그 값은
    ///      리프(Poseidon(TAG_ACCOUNT, auid))에 들어 있지 않다. 세션 층처럼 만료를 샤드
    ///      인덱스에 담을 수도 없다 — 지갑은 자기 auid만 알지 그 폐기가 언제 접수됐는지
    ///      모르므로, 만료로 샤딩하면 조회할 샤드를 특정할 수 없다.
    ///
    ///      그래서 이것 하나가 잔여 신뢰로 남는다. 키를 쥔 쪽이 이 경로로 살아있는 계정
    ///      폐기를 떨어뜨릴 수 있다. 별도 이벤트로 남겨 외부에서 감사할 수 있게 한다.
    ///      제거하려면 "새 리프 집합이 옛 집합의 부분집합"을 증명하는 회로가 필요하다
    ///      (설계 문서 13.2절의 남은 과제).
    ///
    ///      이 경로도 oldSubRoot 검사는 그대로 받는다. 즉 **다른 샤드는 건드릴 수 없고**,
    ///      이 샤드의 롤백 이외의 임의 조작도 할 수 없다.
    function pushAccountRebaseline(
        uint16 shard,
        bytes32 oldSubRoot,
        bytes32 newSubRoot,
        bytes32[] calldata siblings
    ) external onlyIdP {
        if (shard >= ACCOUNT_SHARD_COUNT) revert ShardOutOfRange(shard, ACCOUNT_SHARD_COUNT);
        if (siblings.length != ACCOUNT_TOP_DEPTH) revert BadSiblingsLength(siblings.length, ACCOUNT_TOP_DEPTH);
        if (_climb(oldSubRoot, shard, siblings) != accountTop) revert SubtreeMismatch(shard, true);

        bytes32 nextTop = _climb(newSubRoot, shard, siblings);
        accountTop = nextTop;
        emit UntrustedAccountRebaseline(shard, oldSubRoot, newSubRoot);
        _publish(keccak256(abi.encodePacked(sessionTop, nextTop)));
    }

    // ── 조회 (V3와 동일한 계약) ────────────────────────────────────────────

    /// @notice 이 root로 지금 증명을 제출할 수 있는가.
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

    function graceEntries() external view returns (bytes32[RING] memory roots, uint64[RING] memory blocks_) {
        for (uint256 i = 0; i < RING; i++) {
            roots[i] = ring[i].root;
            blocks_[i] = ring[i].supersededAt;
        }
    }

    /// @notice 지금 이 세션 샤드를 리셋할 수 있는가(운영 진단용).
    function sessionShardResettable(uint16 shard) external view returns (bool) {
        if (shard >= SESSION_SHARD_COUNT) return false;
        return _sessionShardDistance(shard) > maxCredentialSpan;
    }

    // ── 내부 ───────────────────────────────────────────────────────────────

    function _checkShape(Update calldata u) private pure {
        if (u.account) {
            if (u.shard >= ACCOUNT_SHARD_COUNT) revert ShardOutOfRange(u.shard, ACCOUNT_SHARD_COUNT);
            if (u.siblings.length != ACCOUNT_TOP_DEPTH) {
                revert BadSiblingsLength(u.siblings.length, ACCOUNT_TOP_DEPTH);
            }
        } else {
            if (u.shard >= SESSION_SHARD_COUNT) revert ShardOutOfRange(u.shard, SESSION_SHARD_COUNT);
            if (u.siblings.length != SESSION_TOP_DEPTH) {
                revert BadSiblingsLength(u.siblings.length, SESSION_TOP_DEPTH);
            }
        }
    }

    /// @dev 샤드 s의 만료 잔여류 거리 d = (k - block.number) mod 512, k = s / 8.
    function _sessionShardDistance(uint16 shard) private view returns (uint256) {
        uint256 k = uint256(shard) / SESSION_VALUE_SPAN;
        return (k + SESSION_RING - (block.number % SESSION_RING)) % SESSION_RING;
    }

    function _requireSessionShardExpired(uint16 shard) private view {
        uint256 d = _sessionShardDistance(shard);
        if (d <= maxCredentialSpan) revert SessionShardNotExpired(shard, d);
    }

    /// @dev 샤드 인덱스의 비트가 곧 좌우 방향이다(PPIDWalletV3._climb과 같은 규칙).
    ///      방향을 따로 받지 않는 것이 중요하다 — 받으면 증명자가 다른 위치의 서브트리를
    ///      자기 샤드인 척 접어 올릴 수 있다.
    function _climb(bytes32 leaf, uint256 index, bytes32[] calldata siblings)
        private
        pure
        returns (bytes32)
    {
        bytes32 node = leaf;
        uint256 idx = index;
        for (uint256 i = 0; i < siblings.length; i++) {
            node = (idx & 1) == 0
                ? keccak256(abi.encodePacked(node, siblings[i]))
                : keccak256(abi.encodePacked(siblings[i], node));
            idx >>= 1;
        }
        return node;
    }

    function _publish(bytes32 newRoot) private {
        if (newRoot == bytes32(0)) revert EmptyRoot();
        if (newRoot == latestRoot) {
            emit RootPushed(newRoot, true);
            return;
        }
        ring[ringHead] = Superseded({ root: latestRoot, supersededAt: uint64(block.number) });
        ringHead = (ringHead + 1) % RING;
        latestRoot = newRoot;
        latestRootBlock = uint64(block.number);
        emit RootPushed(newRoot, false);
    }
}
