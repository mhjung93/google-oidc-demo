// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title 테스트 전용 — "무엇이든 통과시키는" 검증자. 지갑의 참조 코드 대조(lib/mode3_onchain.js verifyReferenceCode)가
///   이런 검증자를 가리키는 팩토리를 거절하는지 확인하는 데만 쓴다. 데모 스택은 절대 배포하지 않는다.
contract AcceptAllPiCredVerifier {
    function verifyProof(uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[25] calldata) public pure returns (bool) {
        return true;
    }
}
