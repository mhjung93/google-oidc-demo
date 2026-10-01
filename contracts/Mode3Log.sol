// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Mode 3 로그 V2 — 폐기 트리 root 와 사용자 자격증명 등록부 root 를 한 트랜잭션에 게시한다(설계 2026-10-01 §4).
/// @notice RevocationLog(V1)과 같은 서명 규칙(EIP-191, CIA 키, low-s)·epoch 증가 규칙. 두 root 가 같은 블록에 게시되므로
///   root 나이(lastPublishedBlock)는 하나다. 지갑은 Revoked 이벤트로 폐기 트리를, SlotUpdated 이벤트로 등록부를 복원한다.
contract Mode3Log {
    bytes32 public constant DOMAIN = keccak256("MODE3_LOG_V2");

    address public immutable cia;
    bytes32 public revRoot;
    bytes32 public regRoot;
    uint64 public epoch;
    uint64 public lastPublishedBlock;

    event Revoked(uint64 indexed epoch, bytes32 root, bytes32[] leaves);
    event SlotUpdated(uint64 indexed epoch, uint32 index, bytes32 leaf);

    error EpochNotIncreasing(uint64 got, uint64 have);
    error BadSignature();
    error LengthMismatch();

    constructor(address cia_, bytes32 emptyRevRoot, bytes32 emptyRegRoot) {
        cia = cia_;
        revRoot = emptyRevRoot;
        regRoot = emptyRegRoot;
        lastPublishedBlock = uint64(block.number);
    }

    /// @dev EIP-191 을 적용하기 전의 내부 digest. lib/mode3_log.js publicationDigestV2 와 바이트 단위로 같다.
    function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] calldata revLeaves, uint32[] calldata slotIdx, bytes32[] calldata slotLeaves)
        public view returns (bytes32)
    {
        return keccak256(abi.encode(
            DOMAIN, address(this), newRev, newReg, newEpoch,
            keccak256(abi.encodePacked(revLeaves)), keccak256(abi.encodePacked(slotIdx)), keccak256(abi.encodePacked(slotLeaves))
        ));
    }

    function publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] calldata revLeaves, uint32[] calldata slotIdx, bytes32[] calldata slotLeaves, bytes calldata sig)
        external
    {
        if (newEpoch <= epoch) revert EpochNotIncreasing(newEpoch, epoch);
        if (slotIdx.length != slotLeaves.length) revert LengthMismatch();
        bytes32 inner = digestFor(newRev, newReg, newEpoch, revLeaves, slotIdx, slotLeaves);
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        if (_recover(ethDigest, sig) != cia) revert BadSignature();
        revRoot = newRev;
        regRoot = newReg;
        epoch = newEpoch;
        lastPublishedBlock = uint64(block.number);
        emit Revoked(newEpoch, newRev, revLeaves);
        for (uint256 i = 0; i < slotIdx.length; i++) emit SlotUpdated(newEpoch, slotIdx[i], slotLeaves[i]);
    }

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
