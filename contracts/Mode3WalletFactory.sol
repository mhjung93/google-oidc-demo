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

    constructor(
        address _verifier, uint256 _arid,
        uint256 _pkCIAX, uint256 _pkCIAY, uint256 _pkTraceX, uint256 _pkTraceY,
        address _log, uint64 _maxRootAge
    ) {
        verifier = _verifier; arid = _arid;
        pkCIAX = _pkCIAX; pkCIAY = _pkCIAY; pkTraceX = _pkTraceX; pkTraceY = _pkTraceY;
        log = _log; maxRootAge = _maxRootAge;
    }

    function _initCode(uint256 ppid) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(Mode3Wallet).creationCode,
            abi.encode(ppid, arid, pkCIAX, pkCIAY, pkTraceX, pkTraceY, verifier, log, maxRootAge)
        );
    }

    function computeAddress(uint256 ppid) public view returns (address) {
        return address(uint160(uint256(keccak256(
            abi.encodePacked(bytes1(0xff), address(this), bytes32(ppid), keccak256(_initCode(ppid)))
        ))));
    }

    function deploy(uint256 ppid) external returns (address wallet) {
        wallet = computeAddress(ppid);
        if (wallet.code.length > 0) return wallet;
        Mode3Wallet deployed = new Mode3Wallet{salt: bytes32(ppid)}(
            ppid, arid, pkCIAX, pkCIAY, pkTraceX, pkTraceY, verifier, log, maxRootAge
        );
        require(address(deployed) == wallet, "CREATE2 address mismatch");
    }
}
