// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./RevocationRegistryV3.sol";

/// @notice pi_pk_i v3 검증기 인터페이스. public signal 9개다(현행은 6개).
///         순서는 circuits/pi_pk_i_v3.circom 의 main 선언 순서를 그대로 따른다.
interface IPiPkIV3Verifier {
    function verifyProof(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[9] calldata input
    ) external view returns (bool);
}

/// @notice 폐기 트리 이중 구조(v3) 판 PPIDWallet. PPIDWallet.sol과 나란히 둔다.
///
///         설계: docs/superpowers/specs/2026-09-05-revocation-dual-tree-design.md 8절
///
///         현행과의 차이는 폐기 검사 하나다.
///           현행: revocationRoot 하나를 받아 registry.isCurrentRoot로 대조
///           v3  : 세션·계정 각각의 서브트리 root와 샤드 인덱스를 받아, 상위 트리를
///                 keccak으로 직접 올라가 하나의 root로 합친 뒤 대조
///
///         왜 컨트랙트가 상위 트리를 검증하는가. 상위 트리를 회로 안에 두면 아무 폐기에나
///         SNARK가 무효화되어 샤딩의 의미가 사라진다. 밖으로 빼면 SNARK는 자기 서브트리
///         root에만 묶이고, 다른 샤드의 폐기에는 상위 형제(평범한 calldata)만 갱신하면
///         된다. 상위 트리는 회로에 안 들어가므로 SNARK 친화적일 필요가 없어 keccak을 쓴다.
contract PPIDWalletV3 {
    uint256 public immutable ppid;
    IPiPkIV3Verifier public immutable verifier;
    uint256 public immutable trustedPkIdPX;
    uint256 public immutable trustedPkIdPY;
    RevocationRegistryV3 public immutable registry;
    uint256 public nonce;

    // 샤딩 파라미터. lib/imt_v3.js 및 circuits/pi_pk_i_v3.circom 과 반드시 일치해야 한다.
    uint256 private constant SESSION_RING = 512;        // max_height mod 512
    uint256 private constant SESSION_VALUE_SPAN = 8;    // 2^3, 값 축
    uint256 private constant SESSION_TOP_DEPTH = 12;    // log2(512 * 8)
    uint256 private constant ACCOUNT_SHARD_COUNT = 4096;
    uint256 private constant ACCOUNT_TOP_DEPTH = 12;    // log2(4096)

    struct Payload {
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
    }

    /// @notice 폐기 비멤버십의 온체인 몫. 회로가 서브트리 안을 증명하고, 이 값들이
    ///         그 서브트리를 상위 트리에 붙인다.
    struct RevocationWitness {
        bytes32 sessRoot;
        uint256 sessShardLow;                        // 값 축. 회로가 고정한다(조건 3)
        bytes32[SESSION_TOP_DEPTH] sessSiblings;
        bytes32 acctRoot;
        uint256 acctShard;                           // 회로가 고정한다(조건 1)
        bytes32[ACCOUNT_TOP_DEPTH] acctSiblings;
    }

    error NonceMismatch(uint256 expected, uint256 got);
    error BadSignature();
    error UntrustedIdP();
    error InvalidProof();
    error Expired(uint256 currentBlock, uint256 maxHeight);
    error StaleRevocationRoot(bytes32 root);
    error ShardOutOfRange(uint256 shard, uint256 bound);

    event Executed(uint256 indexed nonceUsed, address indexed to, uint256 value, bool success);

    constructor(
        uint256 _ppid,
        address _verifier,
        uint256 _pkIdPX,
        uint256 _pkIdPY,
        address _registry
    ) {
        ppid = _ppid;
        verifier = IPiPkIV3Verifier(_verifier);
        trustedPkIdPX = _pkIdPX;
        trustedPkIdPY = _pkIdPY;
        registry = RevocationRegistryV3(_registry);
    }

    function execute(
        Payload calldata payload,
        bytes calldata sig,
        uint[2] calldata proofA,
        uint[2][2] calldata proofB,
        uint[2] calldata proofC,
        uint256 pk_i,
        uint256 pk_IdP_x,
        uint256 pk_IdP_y,
        uint256 max_height,
        RevocationWitness calldata rev
    ) external returns (bool ok) {
        if (payload.nonce != nonce) revert NonceMismatch(nonce, payload.nonce);

        // 서명은 이 체인과 이 지갑에 묶인다 (PPIDWallet.sol의 도메인 분리와 동일).
        bytes32 payloadHash = keccak256(
            abi.encode(block.chainid, address(this), payload.to, payload.value, payload.data, payload.nonce)
        );
        address recovered = recoverSigner(payloadHash, sig);
        if (recovered == address(0)) revert BadSignature();
        if (recovered != address(uint160(pk_i))) revert BadSignature();

        if (pk_IdP_x != trustedPkIdPX || pk_IdP_y != trustedPkIdPY) revert UntrustedIdP();

        _checkRevocationAndProof(proofA, proofB, proofC, pk_i, pk_IdP_x, pk_IdP_y, max_height, rev);

        if (block.number > max_height) revert Expired(block.number, max_height);

        nonce += 1;

        (ok, ) = payload.to.call{value: payload.value}(payload.data);
        emit Executed(payload.nonce, payload.to, payload.value, ok);
    }

    /// @dev execute()의 스택 한도를 넘지 않도록 폐기·증명 검증을 분리한다.
    function _checkRevocationAndProof(
        uint[2] calldata proofA,
        uint[2][2] calldata proofB,
        uint[2] calldata proofC,
        uint256 pk_i,
        uint256 pk_IdP_x,
        uint256 pk_IdP_y,
        uint256 max_height,
        RevocationWitness calldata rev
    ) internal view {
        // 상위 트리 검증이 증명 검증보다 싸므로 먼저 본다.
        bytes32 combined = _combinedTopRoot(max_height, rev);
        if (!registry.isAcceptableRoot(combined)) revert StaleRevocationRoot(combined);

        uint[9] memory pubSignals = [
            pk_i,
            pk_IdP_x,
            pk_IdP_y,
            ppid,
            max_height,
            uint256(rev.sessRoot),
            rev.sessShardLow,
            uint256(rev.acctRoot),
            rev.acctShard
        ];
        if (!verifier.verifyProof(proofA, proofB, proofC, pubSignals)) revert InvalidProof();
    }

    /// @dev 두 층의 상위 root를 각각 올라간 뒤 하나로 합친다. 레지스트리는 이 합친 값
    ///      하나만 들고 있으므로, 두 층이 한 트랜잭션 안에서 **같은 시점의 상태에** 묶인다
    ///      — 한쪽만 낡은 채로 통과하는 경로가 없다. lib/imt_v3.js의 combineTopRoots()와
    ///      같은 계산이어야 한다.
    function _combinedTopRoot(uint256 max_height, RevocationWitness calldata rev)
        internal
        pure
        returns (bytes32)
    {
        // 조건 2 — 세션 샤드의 만료 축은 **컨트랙트가 직접 계산한다.** 호출자가 준 값을
        // 쓰면 증명자가 비어 있는 만료 칸을 골라 폐기를 통째로 우회한다. max_height는
        // 이미 public signal이고 아래 만료 검사에도 쓰이므로 새로 실을 것이 없다.
        if (rev.sessShardLow >= SESSION_VALUE_SPAN) {
            revert ShardOutOfRange(rev.sessShardLow, SESSION_VALUE_SPAN);
        }
        if (rev.acctShard >= ACCOUNT_SHARD_COUNT) {
            revert ShardOutOfRange(rev.acctShard, ACCOUNT_SHARD_COUNT);
        }
        uint256 sessShard = (max_height % SESSION_RING) * SESSION_VALUE_SPAN + rev.sessShardLow;

        bytes32 sessTop = _climb(rev.sessRoot, sessShard, rev.sessSiblings);
        bytes32 acctTop = _climbAcct(rev.acctRoot, rev.acctShard, rev.acctSiblings);
        return keccak256(abi.encodePacked(sessTop, acctTop));
    }

    /// @dev 샤드 인덱스의 비트가 곧 좌우 방향이다. 방향을 따로 받지 않는 것이 중요하다 —
    ///      받으면 위 조건 2의 "컨트랙트가 직접 계산한다"가 무의미해진다.
    function _climb(bytes32 leaf, uint256 index, bytes32[SESSION_TOP_DEPTH] calldata siblings)
        private
        pure
        returns (bytes32 node)
    {
        node = leaf;
        uint256 idx = index;
        for (uint256 i = 0; i < SESSION_TOP_DEPTH; i++) {
            node = (idx & 1) == 0
                ? keccak256(abi.encodePacked(node, siblings[i]))
                : keccak256(abi.encodePacked(siblings[i], node));
            idx >>= 1;
        }
    }

    function _climbAcct(bytes32 leaf, uint256 index, bytes32[ACCOUNT_TOP_DEPTH] calldata siblings)
        private
        pure
        returns (bytes32 node)
    {
        node = leaf;
        uint256 idx = index;
        for (uint256 i = 0; i < ACCOUNT_TOP_DEPTH; i++) {
            node = (idx & 1) == 0
                ? keccak256(abi.encodePacked(node, siblings[i]))
                : keccak256(abi.encodePacked(siblings[i], node));
            idx >>= 1;
        }
    }

    function recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        return ecrecover(hash, v, r, s);
    }

    receive() external payable {}
}
