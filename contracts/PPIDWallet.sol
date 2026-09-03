// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./PiPkIVerifier.sol";
import "./RevocationRegistry.sol";

contract PPIDWallet {
    uint256 public immutable ppid;
    PiPkIVerifier public immutable verifier;
    uint256 public immutable trustedPkIdPX;
    uint256 public immutable trustedPkIdPY;
    RevocationRegistry public immutable registry;
    uint256 public nonce;

    struct Payload {
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
    }

    error NonceMismatch(uint256 expected, uint256 got);
    error BadSignature();
    error UntrustedIdP();
    error InvalidProof();
    error Expired(uint256 currentBlock, uint256 maxHeight);
    error StaleRevocationRoot(bytes32 root);

    constructor(
        uint256 _ppid,
        address _verifier,
        uint256 _pkIdPX,
        uint256 _pkIdPY,
        address _registry
    ) {
        ppid = _ppid;
        verifier = PiPkIVerifier(_verifier);
        trustedPkIdPX = _pkIdPX;
        trustedPkIdPY = _pkIdPY;
        registry = RevocationRegistry(_registry);
    }

    function execute(
        Payload calldata payload,
        bytes calldata sig,
        uint[2] calldata proofA,
        uint[2][2] calldata proofB,
        uint[2] calldata proofC,
        uint256 pk_i,
        uint256 pk_IdP_x,
        uint256 pk_IdP_y,
        uint256 max_height,
        bytes32 revocationRoot
    ) external returns (bool ok) {
        if (payload.nonce != nonce) revert NonceMismatch(nonce, payload.nonce);

        // 서명은 이 체인과 이 지갑에 묶인다. 도메인 분리가 없으면 서명이 (그리고 함께
        // calldata에 실리는 증명이) 그대로 이식된다: 같은 factory/registry가 두 체인에
        // 배포되면 CREATE2라 지갑 주소가 같으므로, 한쪽의 execute 트랜잭션을 다른 쪽의
        // 같은 nonce에 재제출해 지갑을 비울 수 있다(2026-09-04 리뷰).
        bytes32 payloadHash = keccak256(
            abi.encode(block.chainid, address(this), payload.to, payload.value, payload.data, payload.nonce)
        );
        address recovered = recoverSigner(payloadHash, sig);
        // ecrecover는 서명이 잘못됐을 때 revert하지 않고 address(0)을 돌려준다. 그런데
        // 회로는 pk_i != 0을 제약하지 않고 IdP는 pk_i를 볼 수 없어(pi_arid_i에서 private)
        // pk_i = 0인 크레덴셜이 실제로 발급될 수 있다. 그 경우 address(uint160(0)) ==
        // address(0)이라 아래 비교가 공허하게 통과해, 그 지갑은 아무 서명으로나 열린다.
        if (recovered == address(0)) revert BadSignature();
        // pk_i is the Ethereum address derived from the secp256k1 session public key
        // (not a hash of the raw pubkey bytes), so it compares directly against
        // ecrecover's output with no extra derivation needed.
        if (recovered != address(uint160(pk_i))) revert BadSignature();

        if (pk_IdP_x != trustedPkIdPX || pk_IdP_y != trustedPkIdPY) revert UntrustedIdP();

        _checkRevocationAndProof(proofA, proofB, proofC, pk_i, pk_IdP_x, pk_IdP_y, max_height, revocationRoot);

        if (block.number > max_height) revert Expired(block.number, max_height);

        // 검증 통과 후 실행 결과와 무관하게 nonce를 증가시킨다 — 실행이 실패해도
        // 서명된 payload를 나중에 다시 재생(replay)하지 못하게 막기 위함
        // (Gnosis Safe 등 기존 스마트컨트랙트 지갑 관례와 동일).
        nonce += 1;

        (ok, ) = payload.to.call{value: payload.value}(payload.data);
    }

    // execute()의 로컬 변수/파라미터 수가 EVM 스택 한도(16 slot)를 넘어서서
    // "stack too deep"이 나므로, 증명 검증 관련 부분을 별도 함수로 분리한다.
    function _checkRevocationAndProof(
        uint[2] calldata proofA,
        uint[2][2] calldata proofB,
        uint[2] calldata proofC,
        uint256 pk_i,
        uint256 pk_IdP_x,
        uint256 pk_IdP_y,
        uint256 max_height,
        bytes32 revocationRoot
    ) internal view {
        // 폐기 root가 현재 최신 root인지 먼저 본다 — 증명 검증보다 싸다.
        if (!registry.isCurrentRoot(revocationRoot)) revert StaleRevocationRoot(revocationRoot);

        uint[6] memory pubSignals = [
            pk_i, pk_IdP_x, pk_IdP_y, ppid, max_height, uint256(revocationRoot)
        ];
        if (!verifier.verifyProof(proofA, proofB, proofC, pubSignals)) revert InvalidProof();
    }

    function recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        return ecrecover(hash, v, r, s);
    }

    receive() external payable {}
}
