// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "./Mode3RootHistory.sol";
/// @title Mode 3 거울(V10 설계 §2·§3·§5) — 응용 체인에서 폐기 체인의 캐노니컬 Mode3Log 의 (revRoot, regRoot, epoch) 를 받아 적는다.
/// @notice 신뢰 근거는 IdP 서명뿐이다(결정 1-A). 다이제스트는 캐노니컬 Mode3Log.digestFor 와 바이트 단위로 같다 — 리프·슬롯 배열 대신
///   그 세 해시를 받으므로 같은 서명이 양쪽에 유효하다. 이 체인의 검증자(Mode3Wallet, RP)는 이 값만 본다.
contract Mode3Mirror is Mode3RootHistory {
    bytes32 public constant DOMAIN = keccak256("MODE3_LOG_V4");
    address public immutable cia;
    uint256 public immutable canonicalChainId;
    address public immutable canonicalLog;
    event Mirrored(uint64 indexed epoch, bytes32 revRoot, bytes32 regRoot);
    error EpochNotIncreasing(uint64 got, uint64 have);
    error BadSignature();
    constructor(address cia_, uint256 canonicalChainId_, address canonicalLog_, bytes32 emptyRevRoot, bytes32 emptyRegRoot) Mode3RootHistory(emptyRevRoot, emptyRegRoot) {
        cia = cia_; canonicalChainId = canonicalChainId_; canonicalLog = canonicalLog_;
    }
    /// @dev 캐노니컬 Mode3Log.digestFor 와 바이트 단위로 같다 — block.chainid/address(this) 대신 생성자로 받은
    ///   canonicalChainId/canonicalLog 를 넣는다. 2026-10-25: bound 두 배열의 해시가 뒤에 붙는다.
    function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32 hLeaves, bytes32 hIdx, bytes32 hSlots, bytes32 hBoundKeys, bytes32 hBoundValues) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN, canonicalChainId, canonicalLog, newRev, newReg, newEpoch, hLeaves, hIdx, hSlots, hBoundKeys, hBoundValues));
    }
    /// @notice 제출자는 아무나(릴레이어) — 신뢰 근거는 CIA 서명뿐이다. 리프·슬롯은 해시 세 개로 받지만 bound 는 저장해야 하므로
    ///   배열 그대로 받는다(2026-10-25 §2.2). epoch 은 건너뛸 수 있다(거울은 뒤처질 수 있다, V10 §3) — 건너뛴 게시의 bound 는
    ///   IdP 가 다음 게시에 다시 실어 보낸다(같은 값·올리기는 _applyBounds 가 무시한다).
    function publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32 hLeaves, bytes32 hIdx, bytes32 hSlots, uint256[] calldata boundKeys, uint32[] calldata boundValues, bytes calldata sig) external {
        if (newEpoch <= epoch) revert EpochNotIncreasing(newEpoch, epoch);
        bytes32 inner = digestFor(newRev, newReg, newEpoch, hLeaves, hIdx, hSlots, keccak256(abi.encodePacked(boundKeys)), keccak256(abi.encodePacked(boundValues)));
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        if (_recover(ethDigest, sig) != cia) revert BadSignature();
        _applyBounds(boundKeys, boundValues, newEpoch);
        _setRoots(newRev, newReg, newEpoch);
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
