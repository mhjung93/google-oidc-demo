// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Mode3WalletFactory.sol";

/// @title 데모 대상 — 공개된 속성 구간으로 문을 연다 (선택 공개 설계 2026-09-22 §5.3)
/// @notice Mode3Wallet.execute 가 π 검증 뒤 호출 데이터 꼬리에 붙인 (mask, lo[4], hi[4]) 를 읽는다. 이 꼬리는 mask 값과
///   무관하게 항상 붙는다(mask = 0 이면 전부 0) — 그래야 payload.data 안에 사용자가 넣은 위조 꼬리가 그 앞에 묻힌다
///   (2026-09-22 최종 리뷰 Critical). 꼬리는 팩토리가 배포한 지갑만 붙일 수 있으므로 msg.sender 를 팩토리로 확인한다.
///   정책: 국가(a₁) = countryEq, 출생연도(a₀) ≤ birthYearMax.
contract AttrGate {
    Mode3WalletFactory public immutable factory;
    uint64 public immutable countryEq;
    uint64 public immutable birthYearMax;
    mapping(address => bool) public claimed;

    event Claimed(address indexed wallet, uint64 birthYearHi, uint64 country);

    uint256 private constant TAIL = 9 * 32;

    constructor(address _factory, uint64 _countryEq, uint64 _birthYearMax) {
        factory = Mode3WalletFactory(_factory); countryEq = _countryEq; birthYearMax = _birthYearMax;
    }

    /// @dev calldata 끝 288바이트 = mask, lo[0..3], hi[0..3] (각 32바이트 워드).
    function _disclosure() internal pure returns (uint256 mask, uint256[4] memory lo, uint256[4] memory hi) {
        require(msg.data.length >= 4 + TAIL, "no disclosure");
        uint256 base = msg.data.length - TAIL;
        assembly {
            mask := calldataload(base)
        }
        for (uint256 k = 0; k < 4; k++) {
            uint256 l; uint256 h;
            uint256 pl = base + 32 * (1 + k); uint256 ph = base + 32 * (5 + k);
            assembly { l := calldataload(pl) h := calldataload(ph) }
            lo[k] = l; hi[k] = h;
        }
    }

    function claim() external {
        require(factory.isWallet(msg.sender), "not a mode3 wallet");
        require(!claimed[msg.sender], "already claimed");
        (uint256 mask, uint256[4] memory lo, uint256[4] memory hi) = _disclosure();
        require(mask & 0x3 == 0x3, "need slot0,1");
        require(lo[1] == countryEq && hi[1] == countryEq, "country");
        require(hi[0] <= birthYearMax, "age");
        claimed[msg.sender] = true;
        emit Claimed(msg.sender, uint64(hi[0]), uint64(lo[1]));
    }
}
