// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./PPIDWallet.sol";

contract PPIDWalletFactory {
    address public immutable verifier;
    uint256 public immutable trustedPkIdPX;
    uint256 public immutable trustedPkIdPY;

    constructor(address _verifier, uint256 _pkIdPX, uint256 _pkIdPY) {
        verifier = _verifier;
        trustedPkIdPX = _pkIdPX;
        trustedPkIdPY = _pkIdPY;
    }

    function computeAddress(uint256 ppid) public view returns (address) {
        bytes32 salt = bytes32(ppid);
        bytes memory bytecode = abi.encodePacked(
            type(PPIDWallet).creationCode,
            abi.encode(ppid, verifier, trustedPkIdPX, trustedPkIdPY)
        );
        return address(uint160(uint256(keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(bytecode))
        ))));
    }

    function deploy(uint256 ppid) external returns (address wallet) {
        wallet = computeAddress(ppid);
        if (wallet.code.length > 0) return wallet;
        bytes32 salt = bytes32(ppid);
        PPIDWallet deployed = new PPIDWallet{salt: salt}(ppid, verifier, trustedPkIdPX, trustedPkIdPY);
        require(address(deployed) == wallet, "CREATE2 address mismatch");
        return address(deployed);
    }
}
