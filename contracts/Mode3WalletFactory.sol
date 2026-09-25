// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Mode3Wallet.sol";

/// @title Mode 3 PPID 계정 팩토리 — 설계 2026-09-18 §5.4. 서비스마다 하나(arid·pk_trace 가 박힌다).
/// @notice 주소 = CREATE2(salt = PPID). PPID 가 chainid 를 포함하므로 같은 팩토리를 다른 체인에 배포해도 계정은 체인마다 다르다.
contract Mode3WalletFactory {
    address public immutable verifier;
    uint256 public immutable arid;
    uint256 public immutable pkCIAX;
    uint256 public immutable pkCIAY;
    uint256 public immutable pkTraceX;
    uint256 public immutable pkTraceY;
    address public immutable log;
    uint64 public immutable maxRootAge;
    uint64 public immutable maxLifetime;

    /// @notice 이 팩토리가 배포한 지갑. 대상 컨트랙트(AttrGate)가 msg.sender 를 확인하는 데 쓴다 — 꼬리 11워드는 π 를 검증한 지갑만 붙일 수 있다.
    mapping(address => bool) public isWallet;

    constructor(
        address _verifier, uint256 _arid,
        uint256 _pkCIAX, uint256 _pkCIAY, uint256 _pkTraceX, uint256 _pkTraceY,
        address _log, uint64 _maxRootAge, uint64 _maxLifetime
    ) {
        verifier = _verifier; arid = _arid;
        pkCIAX = _pkCIAX; pkCIAY = _pkCIAY; pkTraceX = _pkTraceX; pkTraceY = _pkTraceY;
        log = _log; maxRootAge = _maxRootAge; maxLifetime = _maxLifetime;
    }

    function _initCode(uint256 ppid) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(Mode3Wallet).creationCode,
            abi.encode(ppid, arid, pkCIAX, pkCIAY, pkTraceX, pkTraceY, verifier, log, maxRootAge, maxLifetime)
        );
    }

    function computeAddress(uint256 ppid) public view returns (address) {
        return address(uint160(uint256(keccak256(
            abi.encodePacked(bytes1(0xff), address(this), bytes32(ppid), keccak256(_initCode(ppid)))
        ))));
    }

    function deploy(uint256 ppid) external returns (address wallet) {
        wallet = computeAddress(ppid);
        if (wallet.code.length > 0) { isWallet[wallet] = true; return wallet; }   // 다른 경로로 이미 있어도 이 팩토리 코드로 만든 주소다
        Mode3Wallet deployed = new Mode3Wallet{salt: bytes32(ppid)}(
            ppid, arid, pkCIAX, pkCIAY, pkTraceX, pkTraceY, verifier, log, maxRootAge, maxLifetime
        );
        require(address(deployed) == wallet, "CREATE2 address mismatch");
        isWallet[wallet] = true;
    }
}
