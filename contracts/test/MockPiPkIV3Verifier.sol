// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice 테스트 전용. 진짜 PiPkIV3Verifier는 새 zkey가 있어야 만들 수 있으므로(E단계),
///         C단계에서는 폐기·상위 트리·유예 창만 떼어 보기 위해 쓴다.
///
/// @dev 반드시 view여야 한다. 실제 Groth16 verifier가 view이고 PPIDWalletV3가 그 인터페이스로
///      staticcall하기 때문이다 — 스토리지를 쓰는 mock을 끼우면 호출 자체가 revert한다.
///
///      그래서 "컨트랙트가 회로에 무엇을 넘겼는가"는 기록이 아니라 **대조**로 검증한다.
///      테스트가 기대하는 public signal 9개를 미리 등록해 두면, 실제로 넘어온 값이 그와
///      다를 때 false를 돌려주므로 지갑이 InvalidProof로 revert한다.
contract MockPiPkIV3Verifier {
    bool public result = true;
    bytes32 public expectedInputHash; // 0이면 아무 입력이나 통과

    function setResult(bool r) external {
        result = r;
    }

    function setExpectedInput(uint[9] calldata input) external {
        expectedInputHash = keccak256(abi.encode(input));
    }

    function clearExpectedInput() external {
        expectedInputHash = bytes32(0);
    }

    function verifyProof(
        uint[2] calldata,
        uint[2][2] calldata,
        uint[2] calldata,
        uint[9] calldata input
    ) external view returns (bool) {
        if (expectedInputHash != bytes32(0) && keccak256(abi.encode(input)) != expectedInputHash) {
            return false;
        }
        return result;
    }
}
