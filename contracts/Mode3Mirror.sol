// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "./IMode3Roots.sol";
/// @title Mode 3 거울(V10 설계 §2·§3·§5) — 응용 체인에서 폐기 체인의 캐노니컬 Mode3Log 의 (revRoot, regRoot, epoch) 를 받아 적는다.
/// @notice 신뢰 근거는 IdP 서명뿐이다(결정 1-A). 다이제스트는 캐노니컬 Mode3Log.digestFor 와 바이트 단위로 같다 — 리프·슬롯 배열 대신
///   그 세 해시를 받으므로 같은 서명이 양쪽에 유효하다. 이 체인의 검증자(Mode3Wallet, RP)는 이 값만 본다.
contract Mode3Mirror is IMode3Roots {
    bytes32 public constant DOMAIN = keccak256("MODE3_LOG_V3");
    address public immutable cia;
    uint256 public immutable canonicalChainId;
    address public immutable canonicalLog;
    bytes32 public revRoot;
    bytes32 public regRoot;
    uint64 public epoch;
    uint64 public lastPublishedBlock;
    event Mirrored(uint64 indexed epoch, bytes32 revRoot, bytes32 regRoot);
    error EpochNotIncreasing(uint64 got, uint64 have);
    error BadSignature();
    constructor(address cia_, uint256 canonicalChainId_, address canonicalLog_, bytes32 emptyRevRoot, bytes32 emptyRegRoot) {
        cia = cia_; canonicalChainId = canonicalChainId_; canonicalLog = canonicalLog_;
        revRoot = emptyRevRoot; regRoot = emptyRegRoot; lastPublishedBlock = uint64(block.number);
    }
    /// @dev 캐노니컬 Mode3Log.digestFor 와 바이트 단위로 같다 — block.chainid/address(this) 대신 생성자로 받은
    ///   canonicalChainId/canonicalLog 를 넣는다(같은 서명이 양쪽에서 유효해야 하므로).
    function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32 hLeaves, bytes32 hIdx, bytes32 hSlots) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN, canonicalChainId, canonicalLog, newRev, newReg, newEpoch, hLeaves, hIdx, hSlots));
    }
    /// @notice 제출자는 아무나(릴레이어) — 신뢰 근거는 CIA 서명뿐이다. 캐노니컬과 달리 리프·슬롯 배열 전체가 아니라
    ///   그 세 해시만 받으므로 calldata 가 작다. epoch 은 건너뛸 수 있다(거울은 뒤처질 수 있다, V10 §3).
    function publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32 hLeaves, bytes32 hIdx, bytes32 hSlots, bytes calldata sig) external {
        if (newEpoch <= epoch) revert EpochNotIncreasing(newEpoch, epoch);
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digestFor(newRev, newReg, newEpoch, hLeaves, hIdx, hSlots)));
        if (_recover(ethDigest, sig) != cia) revert BadSignature();
        revRoot = newRev; regRoot = newReg; epoch = newEpoch; lastPublishedBlock = uint64(block.number);
        emit Mirrored(newEpoch, newRev, newReg);
    }
    /// @dev Mode3Log._recover 와 같은 본문(low-s, v∈{27,28}) — 서명 규칙을 양쪽이 바이트 단위로 공유한다.
    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert BadSignature();
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert BadSignature();
        if (v != 27 && v != 28) revert BadSignature();
        address a = ecrecover(digest, v, r, s);
        if (a == address(0)) revert BadSignature();
        return a;
    }
}
