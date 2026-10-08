// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Mode 3 폐기 체인 — CIA 서명 root + 리프 calldata
/// @notice 설계 §6.5, §7.2. 상태는 root 와 epoch 둘뿐이고 리프는 이벤트(calldata)로만 남긴다.
///   누구든 이벤트를 재생해 트리를 재구성할 수 있고(데이터 가용성), 재구성한 root 가 여기
///   저장된 root 와 다르면 그 자리에서 들통난다(사후 감사). 삽입을 온체인에서 검증하지 않는
///   이유는 CIA 를 신뢰하기로 했기 때문이다(§2.1) — 검증은 신뢰가 없을 때 필요한 것이다.
///
///   제출은 무허가다. 권한은 서명에 있으므로 릴레이어를 신뢰할 필요가 없다. 그래서 서명이
///   **리프 배열까지** 덮어야 한다 — 안 그러면 릴레이어가 서명된 root 에 엉뚱한 리프를 붙여
///   calldata 를 오염시키고, 지갑이 잘못된 트리를 재구성해 전원이 root 불일치로 막힌다.
///
///   digest 는 **이 컨트랙트 주소**를 덮는다(2026-09-11). 같은 CIA 키로 로그를 재배포하면 옛 로그의
///   공개 calldata (root, epoch, leaves, sig) 를 새 로그에 그대로 재생해 root 를 옛 트리로 바꿀 수
///   있었다 — 운영 절차가 재배포 시 CIA 이더 키를 유지하므로 "키 하나당 로그 하나" 전제는 실제로
///   지켜지지 않았다. chainid 는 여전히 넣지 않는다(설계 §6.5: 한 번 서명해 여러 체인에 뿌리는
///   여지). 다중 체인에 같은 서명을 쓰려면 CREATE2 로 주소를 맞추면 된다.
///
///   2026-09-18: lastPublishedBlock 추가. 같은 root 를 새 epoch 로 재게시하는 하트비트가 이 값을 갱신한다 — 컨트랙트 조건(epoch 증가)은 그대로다.
contract RevocationLog {
    bytes32 public constant DOMAIN = keccak256("MODE3_REVOCATION_ROOT_V1");

    address public immutable cia;
    bytes32 public root;
    uint64 public epoch;
    uint64 public lastPublishedBlock;   // publishRoot 가 성공한 마지막 블록. 지갑 컨트랙트가 root 의 나이를 잰다(2026-09-18 §5.1)

    event Revoked(uint64 indexed epoch, bytes32 root, bytes32[] leaves);

    error EpochNotIncreasing(uint64 got, uint64 have);
    error BadSignature();

    constructor(address cia_, bytes32 emptyRoot) {
        cia = cia_;
        root = emptyRoot;
        lastPublishedBlock = uint64(block.number);
    }

    /// @dev EIP-191 personal_sign 을 적용하기 **전의** 내부 digest. ethers 의
    ///   wallet.signMessage(getBytes(digestFor(...))) 가 이 컨트랙트가 기대하는 서명을 만든다.
    function digestFor(bytes32 newRoot, uint64 newEpoch, bytes32[] calldata leaves)
        public view returns (bytes32)
    {
        return keccak256(abi.encode(DOMAIN, address(this), newRoot, newEpoch, keccak256(abi.encodePacked(leaves))));
    }

    function publishRoot(bytes32 newRoot, uint64 newEpoch, bytes32[] calldata leaves, bytes calldata sig)
        external
    {
        if (newEpoch <= epoch) revert EpochNotIncreasing(newEpoch, epoch);
        bytes32 inner = digestFor(newRoot, newEpoch, leaves);
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        if (_recover(ethDigest, sig) != cia) revert BadSignature();
        root = newRoot;
        epoch = newEpoch;
        lastPublishedBlock = uint64(block.number);
        emit Revoked(newEpoch, newRoot, leaves);
    }

    /// @dev OpenZeppelin 없이 ecrecover. s 의 상위 절반과 v ∉ {27,28} 을 거절해 가변성을 막는다.
    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert BadSignature();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert BadSignature();
        if (v != 27 && v != 28) revert BadSignature();
        address a = ecrecover(digest, v, r, s);
        if (a == address(0)) revert BadSignature();
        return a;
    }
}
