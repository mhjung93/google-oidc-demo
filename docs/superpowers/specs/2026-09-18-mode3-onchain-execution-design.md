# Mode 3 — 온체인 실행 설계: PPID 계정, max_height, allowAgent, 트레이스 태그 V2

**상태: 설계 확정. 구현 전.**
작성 2026-09-18. 2026-09-17~18 설계 대화에서 정해진 내용을 옮긴다. 출발점은 `documents/260917_OVERALL.pptx`(이하 "덱")
20·22·23·25·27장이다. 덱과 현재 구현이 충돌하는 여섯 항목(만료 기준, salt 일관성, 트랜잭션 모델, 세션키 위치, 챌린지 명칭,
태그 평문)에 대해 결정을 내렸고, 덱대로 가지 **않는** 항목은 §9 에 이유를 적었다.

기반 문서: `2026-09-16-mode3-authorized-opening-design.md`(이하 "개봉 설계"), `2026-09-15-mode3-session-statement-design.md`
(이하 "세션 설계"), `2026-09-14-mode3-attribute-credential-design.md`(이하 "속성 설계"), `2026-09-09-mode3-cia-revocation-design.md`
(이하 "기반 설계"), `2026-07-20-ppidwallet-sponsored-execution-design.md`(이하 "후원 실행 설계").
이 문서는 **세션 설계 §4(인증 요구의 필드)·§5(발급)·§6(공개 입력)·§7(세션 안 요청)**, **속성 설계 §3(서명 메시지)·§6(만료)**,
**개봉 설계 §4.1(태그 평문)·§6(개봉 메시지·중복 판정)**, **기반 설계 §9.11(온체인 검증 기각)** 을 대체한다.
커밋 `C_pt`·`cm_u`·π_issue·가명 `PPID`·폐기 트리·리프·자기 폐기·서비스 등록 승인·`cert_s` V2 는 바뀌지 않는다.

---

## 1. 무엇이 달라지는가

| | 지금(개봉 설계까지) | 이 문서 | 근거 |
|---|---|---|---|
| 트랜잭션 모델 | PPID 는 오프체인 "이름". 서비스가 π 를 오프체인에서 검증 | **PPID 는 온체인 계정 주소**(CREATE2). 트랜잭션마다 π 를 첨부하고 컨트랙트가 매번 검증. 오프체인 로그인도 유지 | 덱 25장. 기반 설계 §9.11 의 기각을 되돌린다(§9.1) |
| 만료 기준 | `exptime`(Unix 초) | **`max_height`**(블록 높이). 그리드로 양자화 | 덱 20·23·25장 |
| 챌린지 `r_s` | CIA 서명 메시지와 공개 입력에 포함 | **CIA 서명·공개 입력에서 제거.** 서비스 로그인의 신선도는 `σ = Sign(sk_i, r_s)` 만으로. 온체인 재생 방지는 지갑 `nonce` | 온체인 공개 입력은 AA 가 본다(§2). 덱의 `nonce` 는 지갑 트랜잭션 카운터로 해석 |
| `H(C)` | 회로 안(비공개) | 그대로 **비공개** | 공개하면 AA 가 발급 기록과 대조해 uid↔트랜잭션을 잇는다(§2) |
| 세션키 `pk_i` | 커밋 안 | 그대로 **커밋 안** | 같은 이유(§2). 덱은 커밋 밖 |
| salt 일관성 | 등록 커밋 `cm_u` + π_issue | 그대로 | 덱의 auid 대조와 보안상 동등, 구현·논문 완료(§9.3) |
| 트레이스 태그 평문 | `uid` | **`Poseidon(uid, arid)`**. 개봉 시 CIA 가 등록부로 역조회 | 덱 25장 `H(uid, ·)` |
| `allowAgent` | 없음(논문 V-H 에 "미구현") | **발급 요청 → CIA 서명 → 공개 입력 → 온체인 이벤트·개봉 결과** | 덱 22장 |
| 폐기 root 신선도(온체인) | — | `RevocationLog` 가 마지막 게시 블록을 기록, 지갑 컨트랙트가 `MAX_ROOT_AGE` 안인지 검사. CIA 하트비트 게시 | 기반 설계 §9.11 "최소 조건은 하트비트" |
| 공개 입력 | 14개 `[PPID, arid, pk_i, exptime, chainid, r_s, revRoot, pk_CIA, pk_trace, tag]` | 14개 **`[PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, pk_CIA_x, pk_CIA_y, pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2]`** | 개수 동일 — 검증자 인터페이스 크기 불변 |

**목적.** 덱의 시스템 모델(사용자 트랜잭션의 sender 가 PPID 이고 트랜잭션에 트레이스 태그와 ZKP 가 붙는다)을 코드로 만든다.
그 과정에서 온체인 공개가 AA 비연결성을 깨지 않도록 공개 입력을 다시 고른다.

---

## 2. 위협 모형에 추가되는 것: 공개 입력은 AA 도 본다

오프체인 모델에서 트랜스크립트(π 와 공개 입력)는 서비스만 봤다. 온체인 모델에서는 **체인에 올라간 모든 값을 AA 가 읽을 수 있다.**
따라서 AA 가 발급 때 본 값과 결정적으로 이어지는 값은 공개 입력에 둘 수 없다.

| AA 가 발급 때 아는 값 | 공개 입력에 두면 | 결정 |
|---|---|---|
| `uid`, `C`(=`Poseidon(C_pt)`), `C_pt` | `H(C)` 를 공개하면 발급 기록 `issued[uid]` 와 즉시 대조 | `C` 는 회로 안 비회원 증명에만 쓴다(지금과 같음) |
| `r_s`(세션 설계) | 발급 기록과 즉시 대조 | 서명·공개 입력에서 제거 |
| `chainid` | 체인 하나에 수만 사용자 — 연결 가치 없음 | 공개 |
| `allowAgent` | 1비트 | 공개 |
| `max_height` | 정확한 발급 블록을 드러내면 시각 상관으로 좁혀진다 | **그리드 양자화**(§3.2): 같은 창에서 발급된 자격증명은 같은 값. 양자화는 지갑이 한다(2026-09-18 갱신) |
| 발급 시각 자체 | AA 로그 | 양자화 창 안의 사용자들 사이 k-익명. 창이 넓을수록 익명성↑, 만료 정밀도↓ |

AA 가 서명하는 값은 `(C, max_height, chainid, allowAgent)` 뿐이다. 이 중 공개되는 것은 뒤의 셋이고, 셋 다 저엔트로피다.
**한계**: 사용자가 매우 적은 데모·초기 배포에서는 양자화 창 안에 사용자가 한 명일 수 있어 AA 가 시각으로 특정할 수 있다.
이는 오프체인 모델에는 없던 새 노출이며 §8 과 논문 한계에 적는다.

서비스·릴레이어·체인 관찰자에 대한 가정은 세션 설계·개봉 설계 그대로다. 릴레이어(§5.3)는 데모에서 hardhat 언락 계정이며
트랜잭션 내용을 전부 본다 — 실제 배포의 번들러/페이마스터와 같은 위치다.

---

## 3. 자격증명 V4 와 회로

### 3.1 CIA 서명 메시지

```
m = Poseidon(DOMAIN_MODE3_CRED_V4, C, max_height, chainid, allowAgent)
σ_CIA = EdDSA-Poseidon(sk_CIA, m)
DOMAIN_MODE3_CRED_V4 = 93461614427473393731524148   // ASCII "MODE3CREDV4" 빅엔디언
```

`r_s` 가 빠지고 `exptime` 자리에 `max_height`, 끝에 `allowAgent ∈ {0, 1}` 이 들어간다. Poseidon 인자 수는 5 로 같다.

### 3.2 `max_height`

**(2026-09-18 갱신 — 지갑이 정하고 CIA 는 그대로 서명한다.)** 첫 판은 CIA 가 요청의 `chainid` 체인 헤드를 읽어 양자화까지
해 주었다. 그러면 자격증명의 수명 정책이 발급자(CIA)에 묶이고, CIA 가 체인마다 "지금 몇 블록인가"를 알아야 하는 역할이 생긴다.
zkLogin 의 `max_epoch` 처럼 **만료는 사용자(지갑)가 정하고, 발급자는 그 값을 서명에 묶기만 하며, 상한은 검증자가 강제**한다.

```
지갑:   max_height = ceil((head + MODE3_TTL_BLOCKS) / MODE3_HEIGHT_GRID) × MODE3_HEIGHT_GRID    (head 는 지갑의 체인 뷰)
CIA:    max_height < 2^64 만 검사하고 그대로 서명(§3.1 메시지). 계산도 양자화도 하지 않는다.
검증자: head ≤ max_height ≤ head + L      L = MODE3_MAX_LIFETIME_BLOCKS (기본 400)
```

기본값 `MODE3_TTL_BLOCKS = 300`, `MODE3_HEIGHT_GRID = 100`(지갑 env). 유효 기간은 TTL 이상 TTL+GRID 미만이고, 검증자의
상한 `L` 은 `TTL + GRID` 이상이어야 정상 발급이 통과한다(기본 400 = 300 + 100). 상한이 없으면 지갑이 `2^64 − 1` 을 넣어
영구 자격증명을 만들 수 있으므로 상한은 검증자에게 필수다: 컨트랙트는 `block.number ≤ pub[3] ≤ block.number + maxLifetime`
(`maxLifetime` 은 팩토리 생성자 인자 → 계정 주소에 새겨진다), 서비스는 `view.head ≤ max_height ≤ view.head + L`.
양자화(§2 의 k-익명)는 이제 지갑의 책임이다 — 지갑이 그리드를 지키지 않으면 자기 발급 시각을 정확히 드러내는 것이므로
손해는 본인에게만 간다. CIA 는 `chainid` 허용 목록과 체인 생존 확인(헤드 조회 성공)은 그대로 한다(§4.2).

### 3.3 발급 요청 서명 `sig_u`

```
issueRequestMessage(C_pt, chainid, allowAgent, max_height) = Poseidon(DOMAIN_MODE3_ISSUEREQ_V3, C_pt.x, C_pt.y, chainid, allowAgent, max_height)
DOMAIN_MODE3_ISSUEREQ_V3 = 401414577397388343646241740924474931   // ASCII "MODE3ISSUEREQV3"
```

지금 메시지 `Poseidon(C_pt.x, C_pt.y, chainid, r_s)` 에는 도메인이 없었다. 인자 구조가 바뀌므로 도메인을 넣어 옛 서명과 갈라 둔다.
(2026-09-18 갱신: 지갑이 `max_height` 를 정하므로 서명이 그 값도 덮는다 — 안 덮으면 중간자가 요청의 만료를 바꿔 CIA 서명을
받을 수 있다. 도메인 V2 → V3.)

**요청 재생.** `r_s` 가 빠지면 같은 발급 요청을 제3자가 다시 보낼 수 있다. 얻는 것은 같은 `C_pt` 에 묶인 자격증명 하나인데,
그것을 쓰려면 `sk_i`(커밋 안 `pk_i` 의 비밀키)와 커밋 증인이 필요하므로 재생자는 아무것도 못 한다. CIA 쪽 부작용은
`issued[uid]` 에 같은 `C` 의 항목이 하나 더 생기는 것뿐이고, 폐기 리프는 `Poseidon(TAG, C)` 로 같으므로 트리에 중복 삽입되지
않는다(CIA 가 리프 중복을 걸러야 한다 — §4.3). 따라서 재생 방지 장치를 두지 않는다.

### 3.4 트레이스 태그 V2

```
r ← [1, 2^250)   (0 제외 — 개봉 설계 §4.1 그대로)
c1 = r·B8
K  = r·pk_trace
h  = Poseidon(uid, arid)
c2 = h + Poseidon(K.x, K.y)   (mod p)
```

개봉 설계 §4.1 의 `c2 = uid + Poseidon(K)` 에서 평문만 `h` 로 바뀐다. 회로는 `h` 를 커밋 안의 `uid` 와 공개 입력 `arid` 로
직접 계산해 조건 ⑤ 에 넣는다(Poseidon(2) 하나 추가). 복호 결과가 `uid` 원문이 아니라 서비스별 값이므로, 개봉 결과가
새더라도 `uid` 는 CIA 등록부 없이는 드러나지 않는다. CIA 는 등록부의 `uid` 마다 `Poseidon(uid, arid)` 를 계산해 역조회한다(§6.2).

### 3.5 회로 `pi_cred` V4

공개 입력 14개, 순서는 회로가 정한다:

```
[PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot,
 pk_CIA_x, pk_CIA_y, pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2]
```

조건:
1. `C_pt = Commit(uid, arid, s_u, pk_i, attrs[0..3]; blind)`, `Cf = Poseidon(Cx, Cy)` — 변경 없음
2. `EdDSA-Poseidon.Verify(pk_CIA, σ_CIA, Poseidon(DOMAIN_MODE3_CRED_V4, Cf, max_height, chainid, allowAgent))`
3. `PPID = Poseidon(uid, s_u, chainid, arid)` — 변경 없음
4. `Poseidon(TAG_MODE3_CRED, Cf) ∉ Tree(revRoot)` — 변경 없음(리프·경로 모두 비공개)
5. `tag_c1 = r·B8`, `tag_c2 = Poseidon(uid, arid) + Poseidon((r·pk_trace).x, (r·pk_trace).y)`
6. `allowAgent × (allowAgent − 1) = 0`
7. `pk_i < 2^160`, `max_height < 2^64` (범위 검사. `r_s` 범위 검사는 사라진다)

제약 수는 지금(25,505)에서 Poseidon(2) 하나(≈240)만큼 는다. zkey·vkey·검증자 컨트랙트는 재생성한다(§7).

---

## 4. CIA (`cia.js`)

### 4.1 발급 `POST /cia/issue`

요청 `{uid, C_pt, proof, sig_u, chainid, allowAgent, max_height}`. `allowAgent` 는 `"0"`/`"1"` 문자열(다른 값은 400).
`max_height` 는 10진 문자열, `< 2^64`(아니면 400) — 값은 그대로 서명한다(§3.2).
검사 순서: 형식 → disabled → `chainid` 허용·체인 생존 확인(§4.2) → `sig_u` → π_issue → 서명·기록.
응답 `{C, max_height, chainid, allowAgent, sig: {R8, S}}`. `exptime`·`r_s` 는 응답에서 사라진다.

### 4.2 체인 헤드

```
CIA_CHAIN_RPCS = "31337=http://127.0.0.1:8545,11155111=https://…"    # chainid=url 쉼표 목록
```

허용 체인 = 이 맵의 키. 맵이 비어 있으면 지금처럼 CIA 자신의 provider(`CIA_RPC_URL`) 의 `chainId` 하나만 허용하고 그 provider 로
헤드를 읽는다. `CIA_CHAIN_IDS` 는 없앤다(맵의 키가 그 역할). 헤드 조회 실패는 503 `chain head unavailable`.
발급 때의 헤드 조회는 이제 **생존 확인**이다(값은 안 쓴다 — §3.2 갱신). 만료 정리(§4.3)는 헤드 값을 그대로 쓴다.
provider 는 chainid 별로 하나씩 만들어 재사용한다.

### 4.3 발급 기록과 만료 정리

`issued[uid] = [{ leaf, C, max_height, chainid }]`. 같은 `leaf` 가 이미 있으면 `max_height` 만 큰 쪽으로 갱신한다(§3.3 재생).
만료 정리는 **chainid 별** 로, 그 체인의 헤드를 읽었을 때 `max_height + CIA_REVOKE_SKEW_BLOCKS < head` 인 항목을 지운다.
기본 `CIA_REVOKE_SKEW_BLOCKS = 50`(옛 `REVOKE_SKEW_SECONDS` 의 블록판). 헤드를 못 읽으면 그 체인 항목은 지우지 않는다 —
폐기 때 죽은 리프를 더 넣는 쪽이 산 리프를 빠뜨리는 쪽보다 낫다. 폐기(`/cia/revoke`)·자기 폐기 직전에도 정리를 한 번 돈다.

### 4.4 상태 v5 이행

`STATE_VERSION = 5`. v4 파일은 기동 시 이행한다: `issued` 를 **비운다**(v4 항목은 V3 서명 자격증명이며 새 회로·컨트랙트·서비스
검증기 어디서도 검증되지 않으므로 폐기 대상이 아니다), `openings` 의 각 항목에 `resolved: null` 을 추가, 그 외(`accounts`, `rps`,
`revoked`, `pending`, `epoch`)는 그대로. v3 이하는 지금 규칙대로 v4 를 거쳐 온다. `CIA_TTL_SECONDS`·`REVOKE_SKEW_SECONDS` 환경변수는
읽지 않고, 설정돼 있으면 기동 로그에 "무시" 경고를 남긴다.

### 4.5 하트비트 게시

`CIA_HEARTBEAT_BLOCKS`(기본 50) 마다 폐기 체인의 헤드를 보고, 마지막 게시 블록에서 그만큼 지났고 pending 이 비어 있으면 같은
`root` 를 **새 epoch** 로 `publishRoot(root, epoch+1, [], sig)` 한다. `RevocationLog.publishRoot` 는 이미 epoch 증가만 요구하므로
컨트랙트 쪽 조건은 그대로다. pending 이 있으면 하트비트 대신 정식 게시를 한다(지금의 `/cia/publish` 와 같은 경로를 타이머가 호출).
`CIA_HEARTBEAT_BLOCKS = 0` 이면 끈다(테스트용). 하트비트도 가스를 쓴다 — 데모 측정치는 §8.

`/cia/public_keys` 응답에 `chainIds` 를 싣는다(`ttlSeconds` 제거. `ttlBlocks, heightGrid` 도 2026-09-18 갱신으로 제거 — 만료는 지갑 몫).

---

## 5. 컨트랙트

### 5.1 `RevocationLog` — `lastPublishedBlock`

```solidity
uint64 public lastPublishedBlock;   // publishRoot 가 성공할 때마다 block.number
```

`publishRoot` 끝에 `lastPublishedBlock = uint64(block.number);`. 생성자에서도 `block.number` 로 초기화한다(배포 직후 첫 게시 전에도
지갑이 막히지 않게). `DOMAIN`·digest·서명 규칙은 그대로다. 재배포가 필요하다(§7.3).

### 5.2 `PiCredVerifier.sol`

`npx snarkjs zkey export solidityverifier build/mode3/pi_cred_final.zkey contracts/PiCredVerifier.sol` 로 생성. 컨트랙트 이름을
`PiCredVerifier` 로 바꾼다(snarkjs 기본 `Groth16Verifier`). `verifyProof(uint[2], uint[2][2], uint[2], uint[14]) view returns (bool)`.

### 5.3 `Mode3Wallet.sol`

```solidity
contract Mode3Wallet {
    uint256 public immutable ppid;
    uint256 public immutable arid;
    uint256 public immutable pkCIAX;  uint256 public immutable pkCIAY;
    uint256 public immutable pkTraceX; uint256 public immutable pkTraceY;
    PiCredVerifier public immutable verifier;
    RevocationLog public immutable log;
    uint64  public immutable maxRootAge;   // 블록
    uint64  public immutable maxLifetime;  // 블록 — 지갑이 정한 max_height 의 상한 L (§3.2 갱신)
    uint256 public nonce;

    struct Payload { address to; uint256 value; bytes data; uint256 nonce; }

    event Executed(uint256 indexed nonceUsed, address indexed to, uint256 value, bool success);
    event Mode3Auth(uint256 indexed nonceUsed, uint256 pk_i, uint256 maxHeight, uint256 allowAgent,
                    uint256 tagC1X, uint256 tagC1Y, uint256 tagC2);

    error NonceMismatch(uint256 expected, uint256 got);
    error BadSignature();
    error WrongWallet();        // PPID·arid·chainid 불일치
    error UntrustedKeys();      // pk_CIA·pk_trace 불일치
    error BadAllowAgent();
    error StaleRevocationRoot(bytes32 root);
    error RootTooOld(uint256 lastPublished, uint256 current);
    error Expired(uint256 currentBlock, uint256 maxHeight);
    error TooFarExpiry(uint256 currentBlock, uint256 maxHeight);
    error InvalidProof();

    function execute(Payload calldata payload, bytes calldata sig,
                     uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c,
                     uint[14] calldata pub) external returns (bool ok);
    receive() external payable {}
}
```

`execute` 검사 순서(싼 것부터, 실패 시 revert):
1. `payload.nonce == nonce`
2. `ecrecover(keccak256(abi.encode(block.chainid, address(this), to, value, data, nonce)), sig)` 가 `address(0)` 이 아니고
   `address(uint160(pub[2]))` 와 같다 — `PPIDWallet` 과 같은 도메인 분리(체인·지갑 주소). 서명은 EIP-191 없이 raw digest 위
   (`PPIDWallet` 과 동일. ethers `wallet.signingKey.sign(digest)`).
3. `pub[0] == ppid && pub[1] == arid && pub[4] == block.chainid` — 아니면 `WrongWallet`
4. `pub[7..10] == (pkCIAX, pkCIAY, pkTraceX, pkTraceY)` — 아니면 `UntrustedKeys`
5. `pub[5] <= 1` — 아니면 `BadAllowAgent`(회로도 막지만 이벤트 값의 의미를 위해 한 번 더)
5'. `pub[11..12] ≠ (0, 1)` — 아니면 `BadTag`(오프체인 검증기의 `bad_tag` 와 같은 규칙; 회로는 `r ≠ 0` 을 강제하지 않는다)
6. `bytes32(pub[6]) == log.root()` — 아니면 `StaleRevocationRoot`(N=1. 세션 설계 §8.2 와 같은 규칙)
7. `block.number - log.lastPublishedBlock() <= maxRootAge` — 아니면 `RootTooOld`
8. `block.number <= pub[3]` — 아니면 `Expired`
8'. `pub[3] <= block.number + maxLifetime` — 아니면 `TooFarExpiry`(§3.2 갱신: 지갑이 정한 만료의 상한)
9. `verifier.verifyProof(a, b, c, pub)` — 아니면 `InvalidProof`
10. `nonce += 1`, `(ok,) = to.call{value}(data)`, `emit Executed`, `emit Mode3Auth(nonceUsed, pub[2], pub[3], pub[5], pub[11], pub[12], pub[13])`

실행 실패에도 revert 하지 않고 nonce 를 소모한다(`PPIDWallet` 과 같은 이유). 스택 한도 때문에 3~9 는 내부 함수
`_checkAuth(pub)`/`_checkProof(a,b,c,pub)` 로 나눈다.

### 5.4 `Mode3WalletFactory.sol`

```solidity
constructor(address verifier, uint256 arid, uint256 pkCIAX, uint256 pkCIAY,
            uint256 pkTraceX, uint256 pkTraceY, address log, uint64 maxRootAge, uint64 maxLifetime)
function computeAddress(uint256 ppid) public view returns (address)   // CREATE2, salt = bytes32(ppid)
function deploy(uint256 ppid) external returns (address)             // 이미 있으면 그 주소
```

`PPIDWalletFactory` 와 같은 구조. **서비스마다 팩토리 하나**(arid·pk_trace 가 생성자에 박힌다). 같은 서비스가 다른 체인에 같은
팩토리를 배포하면 PPID 는 `chainid` 를 포함하므로 지갑 주소는 체인마다 다르다 — 의도된 것이다(체인별 계정).

---

## 6. 서비스와 지갑

### 6.1 서비스(`mode3_rp.js`) — 팩토리 배포와 로그인

- 등록이 `approved` 가 되면(폴링 결과 포함) `MODE3_RP_FACTORY_ADDRESS` 가 없고 등록 파일에 `factoryAddress` 도 없을 때
  `Mode3WalletFactory` 를 배포하고 등록 파일에 저장한다. 배포자·가스는 `provider.getSigner(0)`(hardhat 언락 계정, 후원 실행 설계와
  같은 방식, 개인키 없음). 생성자 인자는 `/cia/public_keys` 의 `pk_CIA`·`logAddress`, 등록의 `arid`·`pk_trace`, `PiCredVerifier`
  주소(`MODE3_VERIFIER_ADDRESS`, 없으면 서비스가 함께 배포), `MODE3_MAX_ROOT_AGE`(기본 100), `MODE3_MAX_LIFETIME_BLOCKS`(기본 400 — §3.2 갱신).
  아티팩트는 `artifacts/contracts/*.sol/*.json` 에서 읽는다(`npx hardhat compile` 전제). 서명·배포 코드는 `lib/mode3_onchain.js` 에 둔다.
- `GET /api/mode3/rp_info` 와 `POST /api/mode3/challenge` 응답에 `factoryAddress` 를 싣는다. 지갑은 이 값을 서비스 주장으로
  받아들인다(서비스가 자기 dApp 의 계정 규칙을 정한다). `cert_s` 는 바꾸지 않는다.
- `verifyLogin`: 공개 입력 V4 파싱. 검사 b(root 일치)·f(σ 가 `r_s` 위)·g(세션 생성)는 그대로, c(만료)는 `view.head ≤ max_height`, c'(상한)은 `max_height ≤ view.head + MODE3_MAX_LIFETIME_BLOCKS`(아니면 `bad_expiry`),
  e(키·arid 일치)에 `allowAgent ≤ 1` 추가. 세션과 로그인 로그에 `max_height, allowAgent` 를 기록(`exptime`·`r_s` 필드는 σ 검증용
  `r_s` 만 남는다). `verifySessionRequest` 는 그대로(`${r_s}:${body}`).
- 재검증(`/api/mode3/revalidate`)은 그대로: root 가 바뀌면 새 π. `max_height` 가 지나면 세션 종료(`expired`).

### 6.2 개봉 요청 — 로그인 기록 또는 트랜잭션 해시

`POST /api/mode3/open` 은 `{loginId}` 또는 `{txHash}` 를 받는다. `txHash` 면 `provider.getTransaction` 으로 calldata 를 읽어
`Mode3Wallet.execute` 의 ABI 로 디코드해 `(a, b, c, pub)` 을 꺼내고, 영수증의 `Mode3Auth` 이벤트로 성공한 실행인지 확인한다.
그 뒤는 개봉 설계 §6 과 같다: `D_svc = x_svc·c1`, 서명, `/cia/open/request`.

서명 메시지(개봉 설계 §6 대체):

```
mode3-open:${arid}:${PPID}:${c1.x}:${c1.y}:${D_svc.x}:${D_svc.y}:${ts}
```

`r_s` 대신 `c1` 이 요청을 특정한다(온체인 트랜잭션에는 `r_s` 가 없다). CIA 의 중복 판정 키는 `(arid, c1.x, c1.y)` 로, pending·approved
가 있으면 409(failed·denied 는 재요청 허용 — 개봉 설계 판정 그대로).

CIA 의 검사 순서: 서비스 승인 상태 → ts 신선도 → 서명 → `wrong_arid` → `untrusted_cia` → `wrong_trace_key` → `chainid` 허용 →
`allowAgent ≤ 1` → `D_svc` 부분군 → Groth16 → 중복. 운영자 승인 시 `K = D_svc + x_AA·c1`, `h = c2 − Poseidon(K)`, 등록부의
각 `uid` 로 `Poseidon(uid, arid)` 를 계산(arid 별 캐시)해 `h` 와 같은 `uid` 를 찾는다. 결과:

```
{ status: 'approved', uid, allowAgent, max_height, chainid, PPID }     // 찾았을 때
{ status: 'approved', uid: null, resolved: false, ... }               // 등록부에 없음(계정 삭제 등)
```

`GET /cia/open/:id` 응답과 결과 서명 메시지 `mode3-open-result:${id}:${ts}` 는 그대로. 서비스 페이지는 `allowAgent` 를
"AI agent 허용됨/허용 안 됨" 으로 표시한다(덱 22장의 용도).

### 6.3 지갑(`mode3_wallet_agent.js`)

- 발급 요청에 `allowAgent`(로그인 폼 체크박스, 기본 0)와 지갑이 정한 `max_height`(§3.2: `MODE3_TTL_BLOCKS`·`MODE3_HEIGHT_GRID`,
  헤드는 지갑의 체인 뷰). 자격증명 저장 형식 `{C, max_height, chainid, allowAgent, sig}`.
  `buildCredentialProof` 는 `Poseidon(uid, arid)` 평문으로 태그를 만들고 V4 공개 입력을 낸다.
- 로그인 흐름은 세션 설계 §5 그대로되, 단계 (1) 에서 서비스가 준 `factoryAddress` 를 세션에 보관하고, 단계 (2) 발급 요청에
  `r_s` 대신 `allowAgent` 와 `max_height` 를 보낸다. `r_s` 는 (4) 의 σ 에만 쓴다.
- 새 API `POST /wallet/tx { arid, to, value, data }` (`data` 는 hex, 기본 `0x`):
  1. 세션(`arid`)이 살아 있어야 한다(`head ≤ max_height`). 아니면 409 `session_expired`.
  2. `wallet = factory.computeAddress(PPID)`. 코드가 없으면 `factory.deploy(PPID)` 를 릴레이어로 보낸다.
  3. `nonce = wallet.nonce()`. `digest = keccak256(abi.encode(chainid, wallet, to, value, data, nonce))`, `sig = sk_i.sign(digest)`.
  4. π: 세션의 마지막 π 가 있고 그 `revRoot` 가 `log.root()` 와 같으면 재사용, 아니면 새 root 로 다시 증명(세션 재검증과 같은 경로).
  5. 릴레이어 `provider.getSigner(0)` 으로 `wallet.execute(payload, sig, a, b, c, pub)` 제출. 응답
     `{ txHash, wallet, nonce, status, ok, gasUsed }`(`ok` 는 `Executed` 이벤트).
  실패 사유(revert 이름)는 그대로 돌려준다. 릴레이어는 `MODE3_RELAYER_INDEX`(기본 0) 번 언락 계정.
- 지갑 페이지에 "트랜잭션 보내기" 폼(대상·값). 데모 각본에 "지갑 배포 → 트랜잭션 → 서비스가 해시로 개봉" 을 추가한다.
- 지갑에 이더가 없으면 `value > 0` 실행은 `ok = false` 로 채굴된다(`PPIDWallet` 과 같음). 데모 각본은 먼저 릴레이어가 지갑 주소에
  소액을 보내는 단계를 둔다(`POST /wallet/tx` 의 응답에 `wallet` 주소가 있으므로 사용자가 hardhat 계정에서 송금).

---

## 7. 빌드·테스트·배포

### 7.1 빌드 순서

1. `bash scripts/build_mode3_circuit.sh` → `build/mode3/pi_cred_final.zkey`, `pi_cred_vkey.json`(`nPublic == 14`).
2. `npx snarkjs zkey export solidityverifier build/mode3/pi_cred_final.zkey contracts/PiCredVerifier.sol` + 이름 치환.
3. `npx hardhat compile`.
4. `tests/helpers/mode3_fixture.mjs`(`buildValidInput`)를 V4 입력으로 갱신 — 회로·컨트랙트 테스트가 이 헬퍼로 증명을 만든다.

### 7.2 테스트(그룹은 `scripts/run_tests.sh`)

- `unit`: `test_mode3_issuance.js`(V4 메시지·`issueRequestMessage` V2·`allowAgent` 범위), `test_mode3_trace.js`(평문 `Poseidon(uid,arid)`,
  복호 후 역조회), `test_mode3_opening.js`(메시지 형식, `(arid, c1)` 중복), 상태 v4→v5 이행 테스트(신규 `test_mode3_state_migration.js`).
- `circuit`: `test_pi_cred_witness.mjs` — 공개 입력 14개 순서, `allowAgent = 2` 로 witness 실패, `r_s` 부재.
- `contract`(신규 `test/Mode3Wallet.test.mjs`, hardhat 인프로세스): 픽스처 증명으로 정상 실행·`Mode3Auth` 이벤트, nonce 불일치,
  잘못된 서명, `pk_i = 0`, 다른 arid 팩토리, stale root, `RootTooOld`(블록 진행 후), `Expired`, `TooFarExpiry`, `allowAgent = 2`, 다른 chainid 재생
  (chainid 를 바꾼 인프로세스 체인), `value` 초과 시 `ok = false` + nonce 소모. `RevocationLog.lastPublishedBlock` 갱신.
- `chain`: `test_mode3_e2e.mjs` 에 격리 CIA·서비스로 "발급(allowAgent=1) → 로그인 → 팩토리 배포 → 지갑 배포 → tx 2회(π 재사용) →
  root 게시 → tx 실패(stale) → 재증명 → tx 성공 → 해시로 개봉 → uid·allowAgent 확인 → 하트비트 후 `RootTooOld` 회복" 추가.
  `test_mode3_wallet_agent.mjs`·`test_mode3_rp.mjs` 를 V4 필드로 갱신.

### 7.3 배포·운영

- `scripts/deploy_mode3_log.cjs` 로 `RevocationLog` 재배포 → `CIA_LOG_ADDRESS` 갱신. CIA 상태의 `epoch` 는 새 로그의 0 보다 커야
  하므로 그대로 이어 쓴다(EpochNotIncreasing 은 `<=` 만 막는다).
- `PiCredVerifier`·팩토리는 서비스가 기동 시 배포한다(§6.1). 운영 절차는 `docs/MODE3_DEMO.md` 에 적는다.
- 사용자 프로세스(:8545, :4100, :5100, :3100)는 재시작 시점을 사용자와 정한다.

---

## 8. 알려진 한계와 비용

- **트랜잭션마다 검증 가스.** Groth16 검증 ~200k + 공개 입력 14개 + 이벤트. 실측(`Mode3Wallet.test.mjs`, 2026-09-18 max_height
  지갑 결정 판): `Mode3Wallet.execute()` gas 387,905(값 전송 + 새 수신 계정, 배포 제외; `TooFarExpiry` 검사 추가로 +223).
  회로 실측: 비선형 제약 25,560(V3 는 25,505) — 증명 857 ms 중앙값 / 검증 14.4 ms / zkey 15,459,179 bytes(`bench_pi_cred.mjs`).
  세션 안 재사용은 증명 생성 시간만 아끼고 검증 가스는 못 아낀다(사용자 결정 2026-09-17: 덱 25장 문면).
  격리 스택 실측(`scripts/bench_mode3_onchain.mjs`, N=10 중앙값, 원본 `results/mode3_onchain_bench_20260918.md`):

  | 항목 | 값 |
  |---|--:|
  | 로그인 전체 왕복(발급 + 증명, 지갑 HTTP) | 1,394 ms (sync 31 / CIA 발급 422 / 증명 898) |
  | 서비스 `verifyLogin` | 39 ms (재검증 캐시 π 왕복 33 ms) |
  | `/wallet/tx` 왕복(캐시 π, 서명 + 제출 + 채굴) | 157 ms |
  | `execute` gas — 값 0·EOA 호출, 캐시 π | 339,341 (첫 tx 356,441: nonce 0→1 저장) |
  | 계정 배포(`factory.deploy`, CREATE2) | 713,542 |
  | `PiCredVerifier` / `Mode3WalletFactory` 배포 | 648,683 / 1,269,466 |
  | `RevocationLog` 게시(리프 10) / 하트비트(리프 0) | 50,968 / 40,261 |
- **stale root 실패.** root 게시와 같은 블록 창에 채굴된 트랜잭션은 `StaleRevocationRoot` 로 revert 하고 가스가 소각된다.
  지갑은 재증명 후 재제출한다(§6.3 4). 기반 설계 §9.11 의 "절반 fail-closed" 가 그대로 남는다.
- **withholding.** 컨트랙트는 체인 헤드로 root 의 나이를 알 수 없다. 하트비트(§4.5)와 `MAX_ROOT_AGE`(§5.3) 로 노출을 "무한" 에서
  `MAX_ROOT_AGE` 블록으로 줄인다. CIA 가 죽으면 그 뒤 모든 지갑이 `RootTooOld` 로 멈춘다 — 가용성과 안전성의 교환이며 의도된 것이다.
- **AA 의 시각 상관**(§2). 양자화 창 안 사용자 수가 익명 집합이다. 양자화는 지갑이 하므로(§3.2 갱신) 지갑 구현이 그리드를
  무시하면 그 사용자만 익명 집합에서 빠진다.
- **만료 상한 `L` 은 정책 상수다.** 팩토리 생성자에 새겨지므로 바꾸면 PPID 계정 주소가 전부 바뀐다(`MAX_ROOT_AGE` 와 같음). 서비스의
  `MODE3_MAX_LIFETIME_BLOCKS` 와 지갑의 `TTL + GRID` 가 어긋나면(L < TTL + GRID) 정상 발급도 `bad_expiry`·`TooFarExpiry` 로 막힌다.
- **릴레이어**(§2)는 데모용 언락 계정이다. 실제 배포는 ERC-4337 번들러 등으로 바꿔야 하며 이 문서 범위 밖이다.
- **서비스가 팩토리를 정한다.** 지갑은 `factoryAddress` 의 온체인 값(arid·pk_CIA·pk_trace·로그 주소)을 인증서·고정값과 대조한다(2026-09-18 점검 3 반영; 그전 판은 검증하지 않았고 "같은 π 규칙을 따른다"는 논거는 틀렸다 — 팩토리는 임의 코드다). 검증자 컨트랙트 주소는 대조하지 못하므로 남는 위험은 다음과 같다: 지갑은 `factoryAddress` 를 그 밖의 점에서는 검증하지 않는다. 악의적 서비스가 엉뚱한 팩토리를 주면 사용자는 다른
  주소로 트랜잭션을 보내지만, 그 지갑도 같은 π 규칙(arid·pk_trace 가 생성자 인자)을 따르지 않으면 실행이 안 되고, 따르면 결국
  그 서비스의 계정이다. 사용자 손해는 가스뿐이다(릴레이어 부담).
- 데모의 지갑 에이전트는 로컬 프로세스이고 사용자 확인 대화상자가 없다 — 지갑 페이지의 버튼이 곧 확인이다. 실제 배포에서는
  트랜잭션마다 지갑 UI 확인이 필요하다.
- 회로에 `r ≠ 0` 제약을 넣는 것은 다음 zkey 재생성 때다. 지금은 컨트랙트의 `BadTag`(§5.3) 만으로 막는다.
- 팩토리의 `pk_CIA` 와 `RevocationLog.cia`(이더 주소) 사이에 온체인 연결이 없다 — 잘못된 로그를 가리키도록 배포해도
  컨트랙트가 감지하지 못한다(배포 절차 가정).
- **allowAgent 동의의 출처.** 플래그는 서비스 로그인 페이지의 체크박스에서 와 지갑을 거쳐 AA 가 서명한다. 악의적 서비스가 사용자 없이 "허용"을 주장할 수 있으므로 부인 방지는 없다(2026-09-18 점검 5). 지갑 UI 에서 동의를 받는 것이 후속.
- **개봉 API 무인증(데모).** 서비스의 `POST /api/mode3/open`·`GET /api/mode3/open/:id` 는 인증이 없다. 개봉의 실제 게이트는 CIA 의 서비스 서명 검증과 운영자 승인이다(2026-09-18 점검 4).

---

## 9. 덱과 다르게 한 것과 이유

1. **온체인 복귀와 기반 설계 §9.11.** §9.11 은 2026-09-10 에 온체인 검증을 기각했다(withholding 60분 vs 10분, 절반 fail-closed,
   ~250k gas). 2026-09-17 사용자 결정으로 덱대로 되돌리되, §9.11 이 "되돌리려면 최소 조건" 으로 적은 하트비트를 넣는다. §9.11 에는
   이 문서로 대체됐다는 한 줄을 추가한다.
2. **`nonce`·`H(C)` 공개(덱 25장) 를 따르지 않는다.** §2 의 이유. 덱의 `nonce` 는 지갑 트랜잭션 카운터로 읽는다.
3. **auid 대조(덱 20장) 대신 `cm_u` 유지.** 둘 다 사용자당 값 하나를 AA 가 저장하고 발급마다 증명·대조하므로 보안상 동등하다.
   구현·테스트·논문 V-B 가 이미 `cm_u` 다.
4. **`pk_i` 를 커밋 밖 AA 속성으로 두지 않는다(덱 12장).** §2 의 이유.
5. **태그 평문의 두 번째 인자는 `arid`.** 덱은 비어 있다. `salt` 면 AA 가 역조회를 못 하고, 상수면 `uid` 와 다를 바 없다.
6. **세션 등록형 온체인 검증(첫 tx 에서만 π)** 은 사용자가 기각했다(트랜잭션마다 첨부).

---

## 10. 구현 범위

바뀌는 파일: `circuits/pi_cred.circom`, `circuits/lib/mode3_trace_tag.circom`, `lib/mode3_credential.js`, `lib/mode3_issuance.js`,
`lib/mode3_trace.js`, `lib/mode3_opening.js`, `lib/mode3_wallet.js`, `lib/mode3_rp.js`, `cia.js`, `mode3_wallet_agent.js`, `mode3_rp.js`,
`mode3/wallet.html`·`mode3/rp.html`·`mode3/cia_admin.html`, `contracts/RevocationLog.sol`, `scripts/build_mode3_circuit.sh`(검증자 export 추가),
`scripts/run_tests.sh`, 관련 테스트·픽스처, `docs/MODE3_DEMO.md`, 기반 설계 §9.11 추기.
새 파일: `contracts/PiCredVerifier.sol`(생성), `contracts/Mode3Wallet.sol`, `contracts/Mode3WalletFactory.sol`,
`lib/mode3_onchain.js`(팩토리 배포·지갑 주소·execute 인코딩·calldata 디코드 — 서비스와 지갑이 공유. 테스트 헬퍼 `tests/helpers/mode3_chain.mjs` 와는 별개), `test/Mode3Wallet.test.mjs`,
`tests/test_mode3_state_migration.js`.
바뀌지 않는 것: Mode 1·Mode 2 전부(`PPIDWallet*`, `RevocationRegistry*`, `wallet_agent.js`, `server.js`, `custom_idp.js`), 등록·`cm_u`·
π_issue·`cert_s` V2·서비스 등록 승인·폐기 트리·자기 폐기.

---

## 11. 논문·발표에 되돌아갈 것

- Fig. 1·Table 2·V-C/V-D/V-E/VI: `exptime → max_height`, `r_s` 는 σ 에만, 공개 입력 V4, 태그 평문, `allowAgent` 구현됨(V-H 의
  "미구현" 삭제), 온체인 실행 절 신설(§5 컨트랙트, 가스 실측), VII 한계에 §2·§8.
- 논문 한계에 "지갑 UI 확인" 항목을 추가한다(§8).
- 덱 25장의 `nonce`·`H(C)` 공개 입력은 §2 의 이유로 논문에서 다르게 적어야 한다 — 발표 자료도 맞출 것.
