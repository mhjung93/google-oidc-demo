// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IMode3Roots.sol";

/// @title Mode 3 로그 V3 — 폐기 트리 root 와 사용자 자격증명 등록부 root 를 한 트랜잭션에 게시한다(설계 2026-10-01 §4,
///   V10 폐기 전용 체인 설계 §2 의 chainid 바인딩).
/// @notice RevocationLog(V1)과 같은 서명 규칙(EIP-191, CIA 키, low-s)·epoch 증가 규칙. 두 root 가 같은 블록에 게시되므로
///   root 나이(lastPublishedBlock)는 하나다. 지갑은 Revoked 이벤트로 폐기 트리를, SlotUpdated 이벤트로 등록부를 복원한다.
///   IMode3Roots 를 구현해 검증자(Mode3Wallet)가 캐노니컬 로그와 거울(Mode3Mirror)을 같은 타입으로 읽는다.
contract Mode3Log is IMode3Roots {
    bytes32 public constant DOMAIN = keccak256("MODE3_LOG_V3");

    address public immutable cia;
    bytes32 public revRoot;
    bytes32 public regRoot;
    uint64 public epoch;
    uint64 public lastPublishedBlock;

    // 폐기 접수증 대기열 (V10 §4): 사용자(또는 누구든)가 IdP 서명 접수증을 올리면 pending 에 적히고, 다음
    // publish 는 그 슬롯을 0(폐기)으로 실어야만 통과한다. 통과한 슬롯은 isRetired 에 영구히 남아 다시는
    // 0 이 아닌 값을 받지 않는다 — IdP가 영원히 publish 를 미뤄도 사용자 쪽에서 강제할 수 있어야 하므로.
    bytes32 public constant D_RECEIPT = keccak256("MODE3_REVOKE_RECEIPT_V1");
    mapping(uint32 => bool) public pending;
    uint32[] private pendingList;
    mapping(uint32 => bool) public isRetired;

    event Revoked(uint64 indexed epoch, bytes32 root, bytes32[] leaves);
    event SlotUpdated(uint64 indexed epoch, uint32 index, bytes32 leaf);
    event RevocationRequested(uint32 indexed slot, uint64 epochAtRequest);
    event SlotRetired(uint32 indexed slot, uint64 epoch);

    error EpochNotIncreasing(uint64 got, uint64 have);
    error BadSignature();
    error LengthMismatch();
    error PendingRevocationNotApplied(uint32 slot);
    /// @dev 이벤트 SlotRetired 와 이름이 겹쳐 error SlotRetired 로 못 쓴다(같은 식별자를 이벤트·에러 둘 다로
    ///   선언 불가) — 이벤트 쪽을 기존 이름으로 두고 에러만 SlotIsRetired 로 구분한다(2026-10-02 결정).
    error SlotIsRetired(uint32 slot);

    constructor(address cia_, bytes32 emptyRevRoot, bytes32 emptyRegRoot) {
        cia = cia_;
        revRoot = emptyRevRoot;
        regRoot = emptyRegRoot;
        lastPublishedBlock = uint64(block.number);
    }

    /// @dev EIP-191 을 적용하기 전의 내부 digest. lib/mode3_log.js publicationDigestV3 와 바이트 단위로 같다.
    /// @dev V3: address(this) 앞에 block.chainid — 같은 서명이 거울(Mode3Mirror)에서도 유효해야 하므로 거울은 이 둘을
    ///   생성자로 받아 같은 값을 넣는다.
    function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] calldata revLeaves, uint32[] calldata slotIdx, bytes32[] calldata slotLeaves)
        public view returns (bytes32)
    {
        return keccak256(abi.encode(
            DOMAIN, block.chainid, address(this), newRev, newReg, newEpoch,
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

        _enforceRevocationQueue(slotIdx, slotLeaves, newEpoch);

        revRoot = newRev;
        regRoot = newReg;
        epoch = newEpoch;
        lastPublishedBlock = uint64(block.number);
        emit Revoked(newEpoch, newRev, revLeaves);
        for (uint256 i = 0; i < slotIdx.length; i++) emit SlotUpdated(newEpoch, slotIdx[i], slotLeaves[i]);
    }

    /// @dev publish() 본문의 로컬 변수가 많아 EVM 스택 한도(stack too deep)에 걸려 별도 함수로 뺐다. 은퇴된
    ///   슬롯은 영구히 0 이 아닌 값을 받지 못하고(0 으로 다시 쓰는 건 멱등이라 허용), pending 에 있는 슬롯은
    ///   이번 publish 가 0 으로 실어야 통과한다 — 아니면 거절해 IdP 가 접수증을 무시하고 지나가지 못하게 한다.
    ///   안쪽 루프는 pendingList.length × slotIdx.length 로 중첩되지만 두 배열 다 소규모(폐기 대기 슬롯 수)
    ///   범위라 프로토타입 단계에서는 허용한다(2026-10-02).
    function _enforceRevocationQueue(uint32[] calldata slotIdx, bytes32[] calldata slotLeaves, uint64 newEpoch) internal {
        for (uint256 i = 0; i < slotIdx.length; i++) {
            if (isRetired[slotIdx[i]] && slotLeaves[i] != bytes32(0)) revert SlotIsRetired(slotIdx[i]);
        }
        uint256 n = pendingList.length;
        for (uint256 p = 0; p < n; p++) {
            uint32 s = pendingList[p];
            bool applied = false;
            for (uint256 i = 0; i < slotIdx.length; i++) {
                if (slotIdx[i] == s && slotLeaves[i] == bytes32(0)) { applied = true; break; }
            }
            if (!applied) revert PendingRevocationNotApplied(s);
            pending[s] = false;
            isRetired[s] = true;
            emit SlotRetired(s, newEpoch);
        }
        delete pendingList;
    }

    function pendingSlots() external view returns (uint32[] memory) { return pendingList; }

    function receiptDigestFor(uint32 slot, uint64 epochAtRequest, uint64 requestedAt) public view returns (bytes32) {
        return keccak256(abi.encode(D_RECEIPT, block.chainid, address(this), slot, epochAtRequest, requestedAt));
    }

    /// @notice 사용자(또는 누구든)가 IdP 가 서명한 폐기 접수증을 올린다(V10 §4). 다음 publish 는 이 슬롯을 0 으로 실어야 한다.
    ///   이미 pending 이거나 이미 은퇴된 슬롯이면 조용히 아무 일도 하지 않는다(IdP가 지연 중에 재전송해도 안전).
    function requestRevocation(uint32 slot, uint64 epochAtRequest, uint64 requestedAt, bytes calldata sig) external {
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", receiptDigestFor(slot, epochAtRequest, requestedAt)));
        if (_recover(ethDigest, sig) != cia) revert BadSignature();
        if (pending[slot] || isRetired[slot]) return;
        pending[slot] = true;
        pendingList.push(slot);
        emit RevocationRequested(slot, epochAtRequest);
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
