// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Mode3WalletFactory.sol";

/// @title 데모 대상 v2 — 집합 소속 + 시각 상대 술어 (설계 2026-09-23-mode3-predicates-design.md §4.2)
/// @notice Mode3Wallet.execute 가 π 검증 뒤 호출 데이터 꼬리에 붙인 (mask, lo[4], hi[4], set_sel, set_root) 11워드를 읽는다.
///   꼬리는 mask·sel 값과 무관하게 항상 붙는다(둘 다 0 이면 전부 0) — 그래야 payload.data 안의 위조 꼬리가 그 앞에 묻힌다
///   (2026-09-22 최종 리뷰 Critical). 예외는 payload.data 가 비고 mask = 0, set_sel = 0 인 단순 송금뿐(셀렉터가 없어 아무도 못 읽는다).
///   정책: 국가(a₁) ∈ S(allowedCountriesRoot), 올해(block.timestamp, UTC) − 출생연도(a₀) ≥ minAge. 나이는 연 단위다.
///   "올해" 를 체인 시계로 계산하므로 증명자가 시각을 고를 수 없다 — 회로는 그대로다(범위 술어 hi[0] 만 쓴다).
contract AttrGate {
    Mode3WalletFactory public immutable factory;
    uint256 public immutable allowedCountriesRoot;   // lib/mode3_set_tree.js setRoot(허용 국가) — 원소는 서비스가 게시한다
    uint64 public immutable minAge;
    mapping(address => bool) public claimed;

    event Claimed(address indexed wallet, uint64 birthYearHi, uint256 setRoot);

    uint256 private constant TAIL = 11 * 32;

    constructor(address _factory, uint256 _allowedCountriesRoot, uint64 _minAge) {
        factory = Mode3WalletFactory(_factory); allowedCountriesRoot = _allowedCountriesRoot; minAge = _minAge;
    }

    /// @dev calldata 끝 352바이트 = mask, lo[0..3], hi[0..3], set_sel, set_root (각 32바이트 워드).
    function _disclosure() internal pure returns (uint256 mask, uint256[4] memory lo, uint256[4] memory hi, uint256 setSel, uint256 setRoot) {
        require(msg.data.length >= 4 + TAIL, "no disclosure");
        uint256 base = msg.data.length - TAIL;
        assembly { mask := calldataload(base) }
        for (uint256 k = 0; k < 4; k++) {
            uint256 l; uint256 h;
            uint256 pl = base + 32 * (1 + k); uint256 ph = base + 32 * (5 + k);
            assembly { l := calldataload(pl) h := calldataload(ph) }
            lo[k] = l; hi[k] = h;
        }
        uint256 ps = base + 32 * 9; uint256 pr = base + 32 * 10;
        assembly { setSel := calldataload(ps) setRoot := calldataload(pr) }
    }

    /// @notice UNIX 초 → 그레고리력 연도(UTC). Howard Hinnant 의 civil_from_days — 윤년 규칙(4·100·400) 포함.
    function yearOf(uint256 ts) public pure returns (uint256) {
        uint256 z = ts / 86400 + 719468;
        uint256 era = z / 146097;
        uint256 doe = z - era * 146097;                                   // [0, 146096]
        uint256 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        uint256 y = yoe + era * 400;
        uint256 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);             // [0, 365]
        uint256 mp = (5 * doy + 2) / 153;                                  // [0, 11], 0 = 3월
        return y + (mp < 10 ? 0 : 1);                                      // 1·2월(mp 10·11)은 다음 해
    }

    function claim() external {
        require(factory.isWallet(msg.sender), "not a mode3 wallet");
        require(!claimed[msg.sender], "already claimed");
        (uint256 mask, , uint256[4] memory hi, uint256 setSel, uint256 setRoot) = _disclosure();
        require(mask & 0x1 == 0x1, "need slot0");
        require(setSel == 2 && setRoot == allowedCountriesRoot, "country");
        require(hi[0] + minAge <= yearOf(block.timestamp), "age");
        claimed[msg.sender] = true;
        emit Claimed(msg.sender, uint64(hi[0]), setRoot);
    }
}
