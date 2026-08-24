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

        bytes32 payloadHash = keccak256(abi.encode(payload.to, payload.value, payload.data, payload.nonce));
        address recovered = recoverSigner(payloadHash, sig);
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
        // 폐기 root가 grace window 안인지 먼저 본다 — 증명 검증보다 싸다.
        if (!registry.isRecentRoot(revocationRoot)) revert StaleRevocationRoot(revocationRoot);

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
