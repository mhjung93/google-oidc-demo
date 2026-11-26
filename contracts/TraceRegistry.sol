// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "./TraceVerifier.sol";
/// @title Mode 3 추적 기록 등록부(스펙 2026-11-26 ppid-account-trace §4.3·§5) — 응용 체인마다 하나.
/// @notice PPID 마다 한 번, 감사자 키 pk_aud 로 잠근 auid(c1, c2)를 남긴다. 올바름은 π_trace 가 보증한다("이 암호문은 이 PPID 의 주인의 auid 다").
///   개봉은 누군가 requestOpen 거래를 내야 시작된다 — 그 이벤트(OpenRequested)를 사용자 화면이 받아 알린다. 감사자는 이 이벤트를 본 뒤에만
///   자기 조각으로 부분 복호를 내고(체인 밖), 냈다는 표시만 noteShare 로 남긴다. 조각·평문은 체인에 올리지 않는다.
///   알림의 보장은 감사자 셋 중 둘 이상이 "체인의 요청 없이는 조각을 쓰지 않는다" 를 지킬 때다 — 컨트랙트는 그것을 강제하지 못한다(체인 밖의 복호를 볼 수 없다).
contract TraceRegistry {
    struct Record { uint256 arid; uint256 c1x; uint256 c1y; uint256 c2; uint64 registeredAt; }
    struct Request { uint256 ppid; address requester; bytes32 reasonHash; uint64 requestedAt; uint8 shareBits; }

    TraceVerifier public immutable verifier;
    uint256 public immutable pkAudX;
    uint256 public immutable pkAudY;
    /// 감사자마다 하나 — noteShare 를 낼 수 있는 주소. 순서가 조각의 index(1..3)다.
    address[3] public auditors;

    mapping(uint256 => Record) private records;
    Request[] private requests;

    event TraceRegistered(uint256 indexed ppid, uint256 indexed arid);
    event OpenRequested(uint256 indexed id, uint256 indexed ppid, address indexed requester, bytes32 reasonHash);
    event ShareSubmitted(uint256 indexed id, uint8 indexed auditorIndex, bytes32 shareHash);

    error AlreadyRegistered(uint256 ppid);
    error InvalidProof();
    error NotRegistered(uint256 ppid);
    error UnknownRequest(uint256 id);
    error NotAuditor();
    error AlreadySubmitted(uint256 id, uint8 auditorIndex);
    error BadAuditors();

    constructor(TraceVerifier _verifier, uint256 _pkAudX, uint256 _pkAudY, address[3] memory _auditors) {
        // 주소가 비었거나 겹치면 "셋 중 둘" 이 실제로는 그보다 적은 사람이 된다
        if (_auditors[0] == address(0) || _auditors[1] == address(0) || _auditors[2] == address(0)
            || _auditors[0] == _auditors[1] || _auditors[0] == _auditors[2] || _auditors[1] == _auditors[2]) revert BadAuditors();
        verifier = _verifier;
        pkAudX = _pkAudX;
        pkAudY = _pkAudY;
        auditors = _auditors;
    }

    /// @notice PPID 의 추적 기록을 남긴다. 제출자는 아무나(서비스의 릴레이) — 증명이 PPID·암호문에 묶여 있어 남이 다시 내도 같은 기록이다.
    /// @dev 공개 입력은 이 컨트랙트가 조립한다: arid 는 제출값, chainid 는 이 체인, pk_aud 는 고정값. 순서는 circuits/pi_trace.circom 의 main 과 같다.
    function register(uint256 ppid, uint256 arid, uint256 c1x, uint256 c1y, uint256 c2, uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c) external {
        if (records[ppid].registeredAt != 0) revert AlreadyRegistered(ppid);
        uint[8] memory pub = [ppid, arid, block.chainid, pkAudX, pkAudY, c1x, c1y, c2];
        if (!verifier.verifyProof(a, b, c, pub)) revert InvalidProof();
        records[ppid] = Record({ arid: arid, c1x: c1x, c1y: c1y, c2: c2, registeredAt: uint64(block.number) });
        emit TraceRegistered(ppid, arid);
    }

    function has(uint256 ppid) external view returns (bool) { return records[ppid].registeredAt != 0; }

    function recordOf(uint256 ppid) external view returns (uint256 arid, uint256 c1x, uint256 c1y, uint256 c2, uint64 registeredAt) {
        Record storage r = records[ppid];
        if (r.registeredAt == 0) revert NotRegistered(ppid);
        return (r.arid, r.c1x, r.c1y, r.c2, r.registeredAt);
    }

    /// @notice 개봉을 요청한다 — 이 거래의 이벤트가 사용자에게 가는 알림이다. 요청자는 아무나다: 누가 요청했는지(msg.sender)와 사유의 해시가 남고,
    ///   받아들일지는 감사자들이 체인 밖에서 정한다(서비스에는 체인 위의 신원이 없어 여기서 가르지 않는다).
    function requestOpen(uint256 ppid, bytes32 reasonHash) external returns (uint256 id) {
        if (records[ppid].registeredAt == 0) revert NotRegistered(ppid);
        id = requests.length;
        requests.push(Request({ ppid: ppid, requester: msg.sender, reasonHash: reasonHash, requestedAt: uint64(block.number), shareBits: 0 }));
        emit OpenRequested(id, ppid, msg.sender, reasonHash);
    }

    /// @notice 감사자가 그 요청에 부분 복호를 냈다는 표시(조각의 해시). 감사자마다 요청당 한 번.
    function noteShare(uint256 id, bytes32 shareHash) external {
        if (id >= requests.length) revert UnknownRequest(id);
        uint8 idx = 0;
        for (uint8 i = 0; i < 3; i++) if (auditors[i] == msg.sender) idx = i + 1;
        if (idx == 0) revert NotAuditor();
        Request storage q = requests[id];
        uint8 bit = uint8(1) << (idx - 1);
        if (q.shareBits & bit != 0) revert AlreadySubmitted(id, idx);
        q.shareBits |= bit;
        emit ShareSubmitted(id, idx, shareHash);
    }

    function requestCount() external view returns (uint256) { return requests.length; }

    function requestOf(uint256 id) external view returns (uint256 ppid, address requester, bytes32 reasonHash, uint64 requestedAt, uint8 shareBits) {
        if (id >= requests.length) revert UnknownRequest(id);
        Request storage q = requests[id];
        return (q.ppid, q.requester, q.reasonHash, q.requestedAt, q.shareBits);
    }
}
