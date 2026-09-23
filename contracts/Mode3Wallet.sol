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
    uint64 public immutable maxLifetime;  // 블록. 지갑이 정한 max_height 의 상한(설계 §3.2 갱신) — 없으면 만료 없는 성명이 된다
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
    error BadTag();
    error StaleRevocationRoot(bytes32 root);
    error RootTooOld(uint256 lastPublished, uint256 current);
    error Expired(uint256 currentBlock, uint256 maxHeight);
    error TooFarExpiry(uint256 currentBlock, uint256 maxHeight);
    error InvalidProof();
    error BadDisclosure();

    /// @dev 내부 호출의 성공 여부는 영수증에 남지 않으므로 이벤트로 낸다(PPIDWallet 과 같은 이유).
    event Executed(uint256 indexed nonceUsed, address indexed to, uint256 value, bool success);
    /// @dev 서비스가 개봉 재료를 체인에서 바로 읽을 수 있게 태그·플래그를 남긴다. calldata 에도 있지만 이벤트가 조회하기 쉽다.
    event Mode3Auth(uint256 indexed nonceUsed, uint256 pk_i, uint256 maxHeight, uint256 allowAgent,
                    uint256 tagC1X, uint256 tagC1Y, uint256 tagC2);
    /// @notice 공개한 속성 구간(2026-09-22 선택 공개 §5.1) + V7 집합 소속(2026-09-23 §4.2). 대상 컨트랙트가 읽은 값과 같은 것을 이벤트로 남긴다.
    event Disclosure(uint256 indexed nonceUsed, uint256 mask, uint256[4] lo, uint256[4] hi, uint256 setSel, uint256 setRoot);

    constructor(
        uint256 _ppid, uint256 _arid,
        uint256 _pkCIAX, uint256 _pkCIAY, uint256 _pkTraceX, uint256 _pkTraceY,
        address _verifier, address _log, uint64 _maxRootAge, uint64 _maxLifetime
    ) {
        ppid = _ppid; arid = _arid;
        pkCIAX = _pkCIAX; pkCIAY = _pkCIAY; pkTraceX = _pkTraceX; pkTraceY = _pkTraceY;
        verifier = PiCredVerifier(_verifier);
        log = RevocationLog(_log);
        maxRootAge = _maxRootAge;
        maxLifetime = _maxLifetime;
    }

    /// @param pub 공개 입력 25개(circuits/pi_cred.circom 의 순서):
    ///   [0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot
    ///   [7] pk_CIA_x [8] pk_CIA_y [9] pk_trace_x [10] pk_trace_y [11] tag_c1_x [12] tag_c1_y [13] tag_c2
    ///   [14] disc_mask [15..18] disc_lo [19..22] disc_hi [23] set_sel [24] set_root
    function execute(
        Payload calldata payload,
        bytes calldata sig,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[25] calldata pub
    ) external returns (bool ok) {
        if (payload.nonce != nonce) revert NonceMismatch(nonce, payload.nonce);

        // 서명은 이 체인과 이 지갑에 묶인다(PPIDWallet 과 같은 도메인 분리). 같은 팩토리를 두 체인에 배포해도
        // PPID 가 chainid 를 포함해 주소가 다르지만, 서명까지 묶어 두는 편이 싸고 안전하다.
        // 다이제스트가 공개 값 9워드 전부를 덮는다 — 같은 세션키·같은 mask 의 π 가 둘(예: 어떤 대상엔 정확한
        // 값 공개, 다른 대상엔 구간 공개) 있어도 릴레이어가 lo/hi 를 바꿔 끼우지 못한다(§5.1).
        bytes32 payloadHash = keccak256(
            abi.encode(
                block.chainid, address(this), payload.to, payload.value, payload.data, payload.nonce,
                pub[14], [pub[15], pub[16], pub[17], pub[18]], [pub[19], pub[20], pub[21], pub[22]], pub[23], pub[24]
            )
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
        // 꼬리 11워드(352바이트: mask, lo[4], hi[4], set_sel, set_root)는 값과 무관하게 항상 붙인다(전부 0 일 수도 있다).
        // payload.data 는 사용자가 임의로 채우는 필드라, 조건부로만 붙이면 사용자가 캐시된 빈 π 를 재사용하면서
        // payload.data 끝에 스스로 위조한 꼬리를 덧붙여 대상이 그것을 읽게 만들 수 있다(2026-09-22 최종 리뷰
        // Critical, PoC 로 재현). 항상 붙이면 calldata 끝 352바이트는 반드시 이번 실행에서 검증된 π 의 공개 입력이므로
        // payload.data 안의 위조 꼬리는 그 앞에 묻혀 대상이 읽지 못한다. 대상은 calldatasize 끝에서 읽는다(ERC-2771 방식).
        // Solidity ABI 디코더는 남는 calldata 를 무시하므로 함수 호출 대상과는 호환된다.
        // 예외 하나(2026-09-22 사용자 결정, V7 에서 set_sel 도 포함): payload.data 가 비어 있고 mask = 0, set_sel = 0 이면
        // 꼬리를 붙이지 않는다. 그래야 receive() 만 있는 컨트랙트(다른 Mode3Wallet·PPIDWallet 등)로의 단순 송금이 revert 하지
        // 않는다(receive 는 msg.data 가 비어야 실행된다). 이 예외는 위조 방어를 약화시키지 않는다: 위조 꼬리는 payload.data
        // 안에 있어야 하므로 data 가 비어 있지 않고 → 꼬리가 붙어 위조분이 묻히며, data 가 비어 있으면 셀렉터가 없어 어떤
        // 함수도 꼬리를 읽을 수 없다.
        bytes memory data = (payload.data.length == 0 && pub[14] == 0 && pub[23] == 0)
            ? payload.data
            : abi.encodePacked(payload.data, pub[14], pub[15], pub[16], pub[17], pub[18], pub[19], pub[20], pub[21], pub[22], pub[23], pub[24]);
        (ok, ) = payload.to.call{value: payload.value}(data);
        // 이벤트는 내부 호출 뒤에 낸다 — 호출 앞으로 옮기지 말 것(JS 는 발신 주소로도 거르지만 순서도 지킨다).
        emit Executed(payload.nonce, payload.to, payload.value, ok);
        emit Mode3Auth(payload.nonce, pub[2], pub[3], pub[5], pub[11], pub[12], pub[13]);
        if (pub[14] != 0 || pub[23] != 0) {
            emit Disclosure(payload.nonce, pub[14], [pub[15], pub[16], pub[17], pub[18]], [pub[19], pub[20], pub[21], pub[22]], pub[23], pub[24]);
        }
    }

    /// @dev 성명의 공개 입력을 이 지갑의 고정값·체인 상태와 대조한다. 순서는 설계 §5.3 의 3~8.
    function _checkStatement(uint[25] calldata pub) internal view {
        if (pub[0] != ppid || pub[1] != arid || pub[4] != block.chainid) revert WrongWallet();
        if (pub[7] != pkCIAX || pub[8] != pkCIAY || pub[9] != pkTraceX || pub[10] != pkTraceY) revert UntrustedKeys();
        if (pub[5] > 1) revert BadAllowAgent();
        if (pub[11] == 0 && pub[12] == 1) revert BadTag();   // r = 0 — c1 이 항등원이면 태그가 평문을 그대로 드러낸다(오프체인 검증기 lib/mode3_rp.js 의 bad_tag 와 같은 규칙)
        if (pub[14] >= 16) revert BadDisclosure();   // ⑤′ mask 는 4비트. 회로도 막지만 이벤트·꼬리에 남는 값이라 한 번 더
        // V7: set_sel ∈ {0..4}, sel = 0 이면 root = 0 — 회로도 막지만 꼬리·이벤트·다이제스트에 남는 값이라 한 번 더
        if (pub[23] > 4 || (pub[23] == 0 && pub[24] != 0)) revert BadDisclosure();
        bytes32 root = bytes32(pub[6]);
        if (root != log.root()) revert StaleRevocationRoot(root);          // N=1: 최신 root 만
        uint256 last = log.lastPublishedBlock();
        if (block.number - last > maxRootAge) revert RootTooOld(last, block.number);
        if (block.number > pub[3]) revert Expired(block.number, pub[3]);
        // 만료는 지갑이 정하므로 상한을 여기서 강제한다: 성명은 [max_height − maxLifetime, max_height] 창에서만 쓰인다.
        if (pub[3] > block.number + maxLifetime) revert TooFarExpiry(block.number, pub[3]);
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
