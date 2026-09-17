// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./PiCredVerifier.sol";
import "./RevocationLog.sol";

/// @title Mode 3 PPID 계정 — 설계 2026-09-18 §5.3
/// @notice PPIDWallet(Mode 2)과 같은 구조다. 다른 점: 검증자가 pi_cred(공개 입력 14개), 폐기 근거가 RevocationLog(root + 게시 블록),
///   성명의 arid·pk_CIA·pk_trace 를 immutable 로 고정한다(서비스 검증기 lib/mode3_rp.js 의 d 단계와 같다), 트레이스 태그와
///   allowAgent 를 이벤트로 남긴다. 검사 순서는 싼 것부터다(§5.3).
contract Mode3Wallet {
    uint256 public immutable ppid;
    uint256 public immutable arid;
    uint256 public immutable pkCIAX;
    uint256 public immutable pkCIAY;
    uint256 public immutable pkTraceX;
    uint256 public immutable pkTraceY;
    PiCredVerifier public immutable verifier;
    RevocationLog public immutable log;
    uint64 public immutable maxRootAge;   // 블록. root 가 이보다 오래됐으면 CIA 가 죽었거나 withholding 이다 — fail-closed
    uint256 public nonce;

    struct Payload {
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
    }

    error NonceMismatch(uint256 expected, uint256 got);
    error BadSignature();
    error WrongWallet();
    error UntrustedKeys();
    error BadAllowAgent();
    error StaleRevocationRoot(bytes32 root);
    error RootTooOld(uint256 lastPublished, uint256 current);
    error Expired(uint256 currentBlock, uint256 maxHeight);
    error InvalidProof();

    /// @dev 내부 호출의 성공 여부는 영수증에 남지 않으므로 이벤트로 낸다(PPIDWallet 과 같은 이유).
    event Executed(uint256 indexed nonceUsed, address indexed to, uint256 value, bool success);
    /// @dev 서비스가 개봉 재료를 체인에서 바로 읽을 수 있게 태그·플래그를 남긴다. calldata 에도 있지만 이벤트가 조회하기 쉽다.
    event Mode3Auth(uint256 indexed nonceUsed, uint256 pk_i, uint256 maxHeight, uint256 allowAgent,
                    uint256 tagC1X, uint256 tagC1Y, uint256 tagC2);

    constructor(
        uint256 _ppid, uint256 _arid,
        uint256 _pkCIAX, uint256 _pkCIAY, uint256 _pkTraceX, uint256 _pkTraceY,
        address _verifier, address _log, uint64 _maxRootAge
    ) {
        ppid = _ppid; arid = _arid;
        pkCIAX = _pkCIAX; pkCIAY = _pkCIAY; pkTraceX = _pkTraceX; pkTraceY = _pkTraceY;
        verifier = PiCredVerifier(_verifier);
        log = RevocationLog(_log);
        maxRootAge = _maxRootAge;
    }

    /// @param pub 공개 입력 14개(circuits/pi_cred.circom 의 순서):
    ///   [0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot
    ///   [7] pk_CIA_x [8] pk_CIA_y [9] pk_trace_x [10] pk_trace_y [11] tag_c1_x [12] tag_c1_y [13] tag_c2
    function execute(
        Payload calldata payload,
        bytes calldata sig,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[14] calldata pub
    ) external returns (bool ok) {
        if (payload.nonce != nonce) revert NonceMismatch(nonce, payload.nonce);

        // 서명은 이 체인과 이 지갑에 묶인다(PPIDWallet 과 같은 도메인 분리). 같은 팩토리를 두 체인에 배포해도
        // PPID 가 chainid 를 포함해 주소가 다르지만, 서명까지 묶어 두는 편이 싸고 안전하다.
        bytes32 payloadHash = keccak256(
            abi.encode(block.chainid, address(this), payload.to, payload.value, payload.data, payload.nonce)
        );
        address recovered = _recover(payloadHash, sig);
        // ecrecover 는 잘못된 서명에 address(0) 을 돌려준다. 회로는 pk_i < 2^160 만 제약하므로 pk_i = 0 인
        // 성명이 있을 수 있고, 그때 비교가 공허하게 통과하지 않도록 0 을 먼저 거른다.
        if (recovered == address(0)) revert BadSignature();
        if (recovered != address(uint160(pub[2]))) revert BadSignature();

        _checkStatement(pub);
        if (!verifier.verifyProof(a, b, c, pub)) revert InvalidProof();

        // 검증 통과 후 실행 결과와 무관하게 nonce 를 올린다 — 실패한 payload 의 재생을 막는다.
        nonce += 1;
        (ok, ) = payload.to.call{value: payload.value}(payload.data);
        // 이벤트는 내부 호출 뒤에 낸다 — 호출 앞으로 옮기지 말 것(JS 는 발신 주소로도 거르지만 순서도 지킨다).
        emit Executed(payload.nonce, payload.to, payload.value, ok);
        emit Mode3Auth(payload.nonce, pub[2], pub[3], pub[5], pub[11], pub[12], pub[13]);
    }

    /// @dev 성명의 공개 입력을 이 지갑의 고정값·체인 상태와 대조한다. 순서는 설계 §5.3 의 3~8.
    function _checkStatement(uint[14] calldata pub) internal view {
        if (pub[0] != ppid || pub[1] != arid || pub[4] != block.chainid) revert WrongWallet();
        if (pub[7] != pkCIAX || pub[8] != pkCIAY || pub[9] != pkTraceX || pub[10] != pkTraceY) revert UntrustedKeys();
        if (pub[5] > 1) revert BadAllowAgent();
        bytes32 root = bytes32(pub[6]);
        if (root != log.root()) revert StaleRevocationRoot(root);          // N=1: 최신 root 만
        uint256 last = log.lastPublishedBlock();
        if (block.number - last > maxRootAge) revert RootTooOld(last, block.number);
        if (block.number > pub[3]) revert Expired(block.number, pub[3]);
    }

    /// @dev RevocationLog 와 같은 기준으로 서명 가변성을 막는다: s 의 상위 절반과 v ∉ {27,28} 을 거절한다.
    ///   안 그러면 릴레이어가 mempool 의 execute 를 가로채 s → n-s, v 를 뒤집어 같은 payload 를
    ///   다른 트랜잭션 해시로 먼저 올릴 수 있고, 원본은 nonce 가 이미 올라 NonceMismatch 로 실패한다 —
    ///   §6.2 의 해시 기반 개봉 장부가 어긋난다.
    function _recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert BadSignature();
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert BadSignature();
        if (v != 27 && v != 28) revert BadSignature();
        return ecrecover(hash, v, r, s);
    }

    receive() external payable {}
}
