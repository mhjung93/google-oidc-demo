# Mode 3 — 속성 선택 공개(selective disclosure) 설계: AA 보증 속성 + π_rp 공개 술어 + 온체인 전달

**상태: 초안. 사용자 검토 대기.**
작성 2026-09-22.

기반 문서: `2026-09-21-mode3-two-tier-credential-design.md`(이하 "이중 구조"), `2026-09-14-mode3-attribute-credential-design.md`(속성
슬롯), `2026-09-18-mode3-onchain-execution-design.md`(온체인 실행). 이 문서는 이중 구조의 **§3.1(C_u 의 속성 의미), §3.5(π_u)**,
속성 설계의 **§2(CIA 는 속성 값을 모른다)**, 온체인 실행의 **§5.3(execute 검사)** 를 바꾼다. 나머지(C_s, σ_AA, 폐기 리프, 태그,
PPID, 서비스 로그인 절차)는 그대로다.

---

## 1. 무엇이 달라지는가

| | 지금 (V5) | 이 문서 (V6) |
|---|---|---|
| 속성 a₀..a₃ 의 출처 | 사용자가 지갑에서 입력, AA 는 값을 모름 | **AA 계정 기록**. 등록 때 AA 가 지갑에 내려주고, π_u 검증에서 AA 값과 같음을 강제 |
| π_u 가 증명하는 것 | C_u 의 uid 가 인증된 uid, s_u 가 cm_u 의 s_u | + **속성이 AA 기록과 같다** (AA 가 uid·G_UID + Σa_k·G_ATTR 을 빼고 나머지만 PoK) |
| 속성 값 범위 | [0, 2^250) | **[0, 2^64)** — 정수 속성. 회로 Num2Bits(64) |
| π_rp 공개 입력 | 14개 | **23개** = 14 + `disc_mask` + `disc_lo[4]` + `disc_hi[4]` |
| π_rp 가 추가로 증명하는 것 | — | mask 비트 k 가 1 이면 `disc_lo[k] ≤ a_k ≤ disc_hi[k]` (등식 공개는 lo = hi) |
| `Mode3Wallet.execute` | `uint[14]` | `uint[23]`; mask ≠ 0 이면 공개 값 9워드를 호출 데이터 뒤에 붙여 대상에 전달, `Disclosure` 이벤트 |
| 대상 컨트랙트 | 없음 | 데모 `AttrGate` — 팩토리 지갑에서 온 호출의 꼬리 9워드를 읽어 정책(예: 국가 = 410, 출생연도 ≤ 2007) 검사 |
| 지갑 `/wallet/tx` | to, value, data | + `disclose`(슬롯별 lo/hi 또는 null). mask ≠ 0 이면 캐시 대신 새 π |
| 지갑 `/wallet/attrs` | 사용자가 속성 변경 | **삭제**. 속성은 AA 관리자가 바꾸고(`/cia/accounts/:uid/attrs`), 지갑은 다음 발급 때 다시 받는다 |
| G5 (attribute privacy) | AA 가 속성 **값**을 모른다 | AA 가 속성의 **사용처**를 모른다(어느 서비스·트랜잭션에서 공개됐는지). 값은 AA 가 안다 |

**목적.** 트랜잭션(또는 로그인)에 "C_u 의 속성이 이 술어를 만족한다"를 붙이고, 체인이 π 검증으로 그것을 확인한 뒤 대상
컨트랙트가 공개 값에 따라 동작하게 한다. 공개 값은 AA 가 보증한 것이어야 의미가 있으므로 속성 출처를 AA 로 옮긴다.

**비용 요약.** 회로 제약 +≈1.3k(범위 8개 + 속성 64비트), 공개 입력 +9 → 온체인 검증 gas +≈60k, 증명 시간 변화 없음. 공개하는
트랜잭션은 새 증명이 필요하다(≈0.9 s). zkey·검증자·팩토리 재배포 → PPID 계정 주소 전부 변경.

---

## 2. 가정과 신뢰 (이중 구조 §2 에 더하는 것)

- **AA 는 속성의 권위 있는 출처다.** AA 는 IdP 이므로 uid 의 프로필(출생연도, 국가 등)을 이미 안다. 속성은 AA 계정 기록
  `accounts[uid].attrs` 에 있고 관리자만 바꾼다. 사용자는 값을 고르지 못한다. 이것이 속성 설계 §2 의 "CIA 는 값을 모른다"를
  뒤집는 유일한 변경이며, 대가는 §7 에 적는다.
- **π_u 가 속성을 묶는다.** AA 는 C_u 에서 자기가 아는 uid·G_UID + Σa_k·G_ATTR 을 빼고 남은 s_u·G_SU + blind_u·H 에 대한
  PoK 만 받는다. 지갑이 다른 a_k 로 C_u 를 만들면 PoK 가 성립하지 않는다(Pedersen binding). 따라서 σ_AA 가 Cf_u 를 덮는 것으로
  "C_u 의 속성 = AA 기록"이 보증된다.
- **공개는 사용자가 고른다.** 어떤 슬롯을 어떤 구간으로 공개할지는 지갑이 트랜잭션마다 정한다. AA·서비스·체인은 공개하지 않은
  슬롯에 대해 hiding·ZK 로 아무것도 얻지 못한다.
- **공개 값은 영구 공개다.** 트랜잭션의 공개 입력은 체인에 남고 PPID 계정·서비스(arid)에 묶인다. 정확한 값 공개(lo = hi)보다
  구간 공개가 익명 집합을 넓힌다.
- **대상 컨트랙트는 지갑 컨트랙트 코드를 신뢰한다.** 공개 값은 π 를 검증한 `Mode3Wallet` 만 붙일 수 있으므로, 대상은 `msg.sender`
  가 신뢰하는 팩토리가 배포한 지갑인지 확인해야 한다(§5.3).
- honest-but-curious AA·서비스, 지갑 신뢰, 능동적 AA 부정(위조 root)은 그대로다.

---

## 3. 속성 출처: AA 계정 기록

### 3.1 데모 계정과 슬롯 의미

```
슬롯   뜻                 예 (testuser / alice)
a₀     출생연도            1990 / 2005
a₁     국가 코드(ISO 3166 numeric)   410 / 840
a₂     등급(level)         2 / 1
a₃     예비                0 / 0
```

`cia.js` 의 `DEMO_ACCOUNTS` 에 `attrs: ['1990', '410', '2', '0']` 식으로 둔다. 모든 값은 `[0, 2^64)`(§4.1). 실제 배포에서는
IdP 의 프로필 저장소가 이 자리다.

### 3.2 AA 상태 v7

`accounts[uid]` 에 `attrs: [4개 10진 문자열]` 을 더한다. v6 → v7 마이그레이션: 기존 계정은 `DEMO_ACCOUNTS` 의 값(없으면 0 네 개)을
채우고, **활성 자격증명은 전부 물린다**(`retireActiveCred`, 리프는 다음 게시 대기). 이유: 기존 C_u 의 속성은 사용자가 고른 값이라
보증되지 않는다. 지갑은 다음 세션 발급에서 `no_user_cred` 를 받고 기존 재시도 경로(이중 구조 §6.2 3단계)로 새 C_u 를 받는다.

### 3.3 지갑이 속성을 받는 경로

- **`POST /cia/register` 응답**에 `attrs` 를 싣는다. 지갑은 `registration.attrs` 에 저장한다(지갑 상태 v7 — 형식은 같고 의미만
  "AA 가 준 값"으로 바뀐다). 지갑 페이지의 속성 입력 4칸은 **읽기 전용 표시**가 된다.
- **`POST /cia/attrs`** `{ uid, sig_u }` → `{ attrs }`. 요청 서명 = `Sign(sk_u, Poseidon(DOMAIN_MODE3_ATTRSREQ, uid, nonce))`,
  `nonce` 는 지갑이 뽑는 난수(요청 본문에 실음). AA 는 신선도를 검사하지 않는다 — 응답은 자기 속성뿐이라 재생의 이득이 없다(데모).
  `DOMAIN_MODE3_ATTRSREQ` = ASCII "MODE3ATTRSREQ" 빅엔디언.
- **관리자 변경** `POST /cia/accounts/:uid/attrs` (requireAdmin) `{ attrs }` → 기록 갱신 + 활성 자격증명 물림(리프 대기) → 200
  `{ attrs, inserted }`. 관리자 페이지(`mode3/cia_admin.html`)에 계정별 속성 편집 칸을 둔다.
- **지갑의 재동기화.** `/cia/user_cred` 가 400 `bad_proof` 를 돌려주면(지갑의 attrs 가 AA 기록과 다를 때 π_u 가 깨진다) 지갑은
  `/cia/attrs` 로 값을 다시 받아 **한 번** 재시도한다. 이것으로 `/wallet/attrs` 는 필요 없어지고 삭제한다. 지갑 페이지의
  "속성 변경" 버튼은 "AA 에서 속성 다시 받기"로 바뀐다(`POST /wallet/attrs/sync` — 값을 받아 저장만 하고 재발급은 다음 로그인이).

### 3.4 π_u 개정 (이중 구조 §3.5 대체)

```
공개:   uid, a₀..a₃ (AA 기록), C_u, cm_u
증인:   s_u, blind_u, r_u
관계:   C_u − uid·G_UID − Σa_k·G_ATTR[k] = s_u·G_SU + blind_u·H   ∧   cm_u = s_u·G_SU + r_u·H

증명:   T1 = k_su·G_SU + k_blind·H,  T2 = k_su·G_SU + k_ru·H
        c  = Poseidon(DOMAIN_MODE3_USERCRED_V2, uid, a₀, a₁, a₂, a₃, C_u.x, C_u.y, cm_u.x, cm_u.y, T1.x, T1.y, T2.x, T2.y) & MASK_250
        z_su = k_su + c·s_u,  z_blind = k_blind + c·blind_u,  z_ru = k_ru + c·r_u   (mod ℓ)
검증:   점 4개 부분군 검사, z < ℓ, c 재계산,
        Y1 = C_u − uid·G_UID − Σa_k·G_ATTR[k]
        z_su·G_SU + z_blind·H == T1 + c·Y1
        z_su·G_SU + z_ru·H    == T2 + c·cm_u
```

- `z_attr[4]` 가 사라지고 `T1` 의 항이 둘로 준다. 증명 스칼라곱 9 → 5, 검증 9 → 11(Σa_k·G_ATTR 4개가 검증 쪽으로 옮겨 간다).
  실측은 §8 에서 다시 잰다.
- `DOMAIN_MODE3_USERCRED_V2` = ASCII "MODE3USERCRED2" 빅엔디언. 옛 도메인의 증명은 통과하지 않는다.
- `proveUserCred({ uid, s_u, blind_u, r_u, attrs })` 시그니처는 그대로(attrs 는 이제 AA 가 준 값). `verifyUserCred({ uid, attrs, C_u_pt,
  cm_u, proof })` 에 `attrs` 가 더해진다 — AA 는 **자기 기록의 attrs** 를 넣는다. 요청 본문의 attrs 는 받지 않는다.
- 스칼라 검사: `uid < 2^250`(기존), `a_k < 2^64`(§4.1).

---

## 4. 회로 V6 (π_rp)

### 4.1 속성 64비트

`CommitUser` 의 `attrs[k]` 에 `Num2Bits(64)` 를 쓴다(스칼라곱은 64비트 EscalarMulFix). JS `normalizeAttrs` 상한도 `2^64` 로
바꾼다(`ATTR_MAX = 1n << 64n`). 이유: 범위 술어의 `LessEqThan(64)` 가 입력이 64비트임을 전제하고, 정수 속성에 64비트면 충분하다.
부수 효과로 CommitUser 제약이 약 3.7k 준다.

### 4.2 공개 술어

```
signal input disc_mask;        // 공개 입력 [14]. 비트 k = 슬롯 k 공개 여부. 0 ≤ mask < 16
signal input disc_lo[4];       // [15..18]
signal input disc_hi[4];       // [19..22]

component mb = Num2Bits(4);  mb.in <== disc_mask;
for k in 0..3:
    component lo = Num2Bits(64); lo.in <== disc_lo[k];      // 범위 검사 — 공개 입력도 64비트여야 비교기가 성립
    component hi = Num2Bits(64); hi.in <== disc_hi[k];
    component ge = LessEqThan(64); ge.in[0] <== disc_lo[k]; ge.in[1] <== attrs[k];
    component le = LessEqThan(64); le.in[0] <== attrs[k];   le.in[1] <== disc_hi[k];
    signal okk; okk <== ge.out * le.out;
    mb.out[k] * (1 - okk) === 0;                            // 공개하는 슬롯만 강제
```

- 등식 공개 = `lo = hi = 값`. 공개하지 않는 슬롯은 지갑이 `lo = hi = 0` 으로 채운다(회로는 무시, 검증자는 대조하지 않음).
- 로그인·재검증 증명은 `mask = 0` 으로 만든다 — 지금과 같은 문장이다.
- 제약: Num2Bits(64)×8 + LessEqThan(64)×8 + 소량 ≈ 1.1k. 속성 64비트 절감을 빼면 V5 대비 순증 ≈ −2.5k(줄어든다).

### 4.3 공개 입력 순서 (불변 목록 갱신)

```
[0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot
[7] pk_CIA_x [8] pk_CIA_y [9] pk_trace_x [10] pk_trace_y [11] tag_c1_x [12] tag_c1_y [13] tag_c2
[14] disc_mask [15..18] disc_lo[0..3] [19..22] disc_hi[0..3]
```

앞 14개는 V5 와 같다. 의존처: `lib/mode3_wallet.js`(입력 조립), `lib/mode3_rp.js`(길이 23, [14..22] 파싱), `cia.js` 개봉(태그
인덱스 그대로), `contracts/Mode3Wallet.sol`(`uint[23]`), `contracts/PiCredVerifier.sol`(재생성), `tests/helpers/mode3_fixture.mjs`.

---

## 5. 온체인

### 5.1 `Mode3Wallet.execute` (온체인 실행 §5.3 갱신)

```solidity
function execute(Payload calldata payload, bytes calldata sig,
                 uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[23] calldata pub)
```

검사 순서는 §5.3 의 ①~⑧ 그대로에 하나가 더해진다: ⑤′ `pub[14] < 16`. Groth16 검증 뒤:

```solidity
nonce += 1;
bytes memory data = payload.data;
if (pub[14] != 0) {
    // 꼬리 9워드: mask, lo[4], hi[4]. 대상은 calldatasize 끝에서 288바이트를 읽는다(ERC-2771 과 같은 방식).
    data = abi.encodePacked(payload.data, pub[14], pub[15], pub[16], pub[17], pub[18], pub[19], pub[20], pub[21], pub[22]);
}
(ok, ) = payload.to.call{value: payload.value}(data);
emit Executed(...); emit Mode3Auth(...);
if (pub[14] != 0) emit Disclosure(payload.nonce, pub[14], [pub[15..18]], [pub[19..22]]);
```

- 세션키 서명 `σ` 의 다이제스트는 지금처럼 `(chainid, wallet, to, value, data, nonce)` 를 덮는다 — 공개 값은 π 의 공개 입력으로
  묶이고, 어느 π 를 붙일지는 릴레이어가 바꿀 수 없다(π 는 pk_i 에 묶이고 σ 는 sk_i 만 만든다). 다만 **같은 세션키의 서로 다른 π
  두 개**(mask 0 과 mask ≠ 0)가 동시에 있으면 릴레이어가 하나를 골라 붙일 수 있다 → 지갑은 트랜잭션마다 σ 다이제스트에 `disc_mask`
  를 포함해 `(…, nonce, disc_mask)` 로 서명하고 컨트랙트도 같은 다이제스트를 검사한다. 이러면 릴레이어는 사용자가 정한 mask 의 π
  만 쓸 수 있다.
- 꼬리 9워드를 항상 붙이지 않고 mask ≠ 0 일 때만 붙이는 이유: 기존 대상(꼬리를 모르는 컨트랙트)과의 호환. Solidity ABI 디코더는
  남는 calldata 를 무시한다.
- 저장소를 쓰지 않는다(트랜지언트 저장 대신 calldata 꼬리) — 추가 gas 는 calldata 288바이트(≈4.6k) + 이벤트뿐.

### 5.2 `Mode3WalletFactory`

`mapping(address => bool) public isWallet` 을 두고 `deploy(ppid)` 가 기록한다. 대상 컨트랙트가 `msg.sender` 를 확인하는 데 쓴다.
(CREATE2 라 `computeAddress(ppid)` 로도 확인할 수 있지만 대상은 ppid 를 모른다.)

### 5.3 데모 대상 `AttrGate`

```solidity
contract AttrGate {
    Mode3WalletFactory public immutable factory;
    uint64 public immutable countryEq;      // a₁ == 410
    uint64 public immutable birthYearMax;   // a₀ ≤ 2007  (성인)
    mapping(address => bool) public claimed;
    event Claimed(address wallet, uint64 birthYearHi, uint64 country);

    function claim() external {
        require(factory.isWallet(msg.sender), "not a mode3 wallet");
        (uint256 mask, uint256[4] memory lo, uint256[4] memory hi) = _disclosure();   // calldatasize 끝 288바이트
        require(mask & 0x3 == 0x3, "need slot0,1");
        require(lo[1] == countryEq && hi[1] == countryEq, "country");
        require(hi[0] <= birthYearMax, "age");
        claimed[msg.sender] = true;
        emit Claimed(msg.sender, uint64(hi[0]), uint64(lo[1]));
    }
}
```

`_disclosure()` 는 `msg.data.length >= 4 + 288` 을 확인하고 끝 9워드를 읽는다. 지갑 컨트랙트 외에는 `isWallet` 로 걸러지므로
임의 EOA 가 꼬리를 흉내 내도 통과하지 못한다. 서비스가 기동 때 팩토리 다음에 배포하고 주소를 `rp_info` 에 싣는다(`attrGateAddress`).

---

## 6. 지갑·서비스

### 6.1 `/wallet/tx`

```
{ r_s, to, value?, data?, disclose?: [ {lo, hi} | null, ×4 ] }
```

- `disclose` 가 없거나 전부 null 이면 mask = 0, 캐시된 π 재사용(지금과 같다).
- 하나라도 있으면 mask 를 만들고 `buildCredentialProof(…, disclosure)` 로 **새 π** 를 만든다. 캐시 키는 `(root, r_s, mask, lo, hi)`.
  같은 공개로 두 번째 트랜잭션은 캐시를 쓴다.
- lo ≤ hi, 둘 다 < 2^64, 그리고 `lo ≤ a_k ≤ hi` 를 지갑이 먼저 검사한다(안 맞으면 400 `disclosure_unsatisfiable` — 증명이 어차피
  안 만들어진다).
- 지갑 페이지 트랜잭션 폼에 슬롯별 체크박스 + lo/hi 입력, "정확히 공개" 버튼(lo = hi = 내 값)을 둔다. 대상 주소 기본값은
  `rp_info.attrGateAddress`, data 기본값은 `claim()` 셀렉터.

### 6.2 로그인 (`lib/mode3_rp.js`)

- `publicSignals.length === 23`. `[14] < 16` 검사(`bad_disclosure`). 로그인 정책은 없다 — 서비스는 `[14..22]` 를 세션에 기록만
  한다(`session.disclosure`). 로그인 때 공개하는 기능은 열어 두되 데모 서비스는 요구하지 않는다.
- 개봉·기록 경로는 태그 인덱스 [11..13] 그대로.

### 6.3 데모 시나리오 (`docs/MODE3_DEMO.md` 추가)

1. testuser 등록 → 속성 [1990, 410, 2, 0] 이 AA 에서 내려온다(입력 칸 읽기 전용).
2. 로그인(mask 0) → 트랜잭션 폼에서 슬롯 0 을 `[0, 2007]`, 슬롯 1 을 `[410, 410]` 으로 공개 → `AttrGate.claim()` → `Claimed` 이벤트.
3. alice(2005, 840) 로 같은 시도 → `claim` 이 `country` 로 revert(Executed success=false, nonce 소모).
4. 슬롯 0 을 `[0, 1980]` 으로 공개 시도 → 지갑이 `disclosure_unsatisfiable` (1990 ∉ [0,1980]).
5. 관리자가 testuser 의 a₂ 를 3 으로 변경 → 활성 C_u 물림 → 다음 로그인에서 지갑이 `bad_proof`/`no_user_cred` → `/cia/attrs` 재동기화 →
   새 C_u → 로그인 성공, PPID 동일.

---

## 7. 프라이버시 분석 (변한 것만)

- **G5 재정의.** "AA 가 속성 값을 모른다" → "AA 가 속성이 어디에 쓰이는지 모른다". AA 는 값을 알지만 로그인·트랜잭션 뷰에서 공개
  입력 [14..22] 를 보더라도 그것이 누구 것인지는 §2 의 G4 게임 그대로다. 단 아래 항목이 익명 집합을 줄인다.
- **공개 값에 의한 익명 집합 축소(G4′ 약화).** 온체인 공개 입력은 AA 도 읽는다. AA 는 모든 사용자의 속성을 알므로, 공개된 술어를
  만족하는 사용자 집합 ∩ (chainid, allowAgent, max_height 창) 이 새 익명 집합이다. 정확한 값 공개(출생연도 = 1990, 국가 = 410)는
  집합을 크게 줄이고, 구간 공개는 덜 줄인다. 형식 문서 정리 3 의 1/n 에서 n 이 "술어를 만족하는 창 안 사용자 수"로 바뀐다.
  논문 한계에 적는다.
- **서비스 측.** 서비스는 공개된 값을 PPID 에 영구히 붙인다. 이는 사용자가 고른 공개이므로 정의상 누설이 아니다. 공개하지 않은
  슬롯은 Groth16 ZK 로 숨는다.
- **바뀌지 않는 것.** Cross-RP unlinkability(G3): 두 서비스에 같은 값을 공개하면 그 값으로 묶일 수 있다 — 사용자가 고른 공개의
  당연한 결과이며 PPID 자체는 여전히 독립이다. 조건부 추적(G10)·폐기(G8·G9)·세션 바인딩(G7)은 영향 없음.

---

## 8. 실측할 것

`scripts/bench_zkp_inventory.mjs`·`scripts/bench_mode3_onchain.mjs` 에 추가: 회로 V6 제약·증명·검증, π_u V2 증명·검증, mask = 0
로그인, mask ≠ 0 트랜잭션(새 π 포함) 왕복, `execute` gas(mask 0 / mask ≠ 0 + AttrGate.claim), 공개 입력 23개 검증자 gas 차이.
결과는 `results/mode3_disclosure_bench_YYYYMMDD.md`.

**2026-09-22 실측** (N=10, 중앙값(최소–최대), AMD Ryzen 9 5950X, Node v22.20.0 — 전체는 `results/mode3_disclosure_bench_20260922.md`):

| 항목 | V5 (2026-09-21) | V6 (이번 실측) |
|---|--:|--:|
| pi_cred(π_rp) R1CS 제약 | 26,601 | **25,369** |
| pi_cred 공개 입력 | 14 | **23** |
| pi_cred witness+prove | 859.6 (840.3–1,280.3) ms | **809.0 (798.6–1,209.9) ms** |
| pi_cred verify | 11.5 (10.5–16.6) ms | **10.7 (7.1–12.6) ms** |
| π_u prove | 121.9 (120.1–333.8) ms | **79.7 (79.1–295.0) ms** (V2) |
| π_u verify | 140.5 (138.2–144.4) ms | **98.7 (97.5–100.2) ms** |
| 로그인 전체 왕복 | 1,073 ms | **1,054 (1,023–4,710) ms** |
| /wallet/tx 왕복, mask=0(캐시 π) | — | **151 (149–154) ms** |
| /wallet/tx 왕복, mask=3(새 π + `AttrGate.claim`) | — | **1,000 (979–1,043) ms** |
| `execute` gas, 캐시 π (mask=0) | 339,321 | **402,079 (402,035–402,091)** |
| `execute` gas, 첫 tx | 356,453 | **419,135** |
| `execute` gas, mask=3(새 π) + `AttrGate.claim` | — | **444,973 (444,881–444,997)** |

검증자 gas 차이(공개 입력 14 → 23): mask=0 캐시 π 기준 +62,758 gas. 컨트랙트 단위 테스트(mask=0, 450,675 − 387,961, π 바이트
잡음으로 실행마다 수십 gas 차이)에서도 +62,714 gas 로 거의 같은 증가폭이 나온다. mask=3(선택 공개 + `AttrGate.claim`) 오버헤드는
mask=0 대비 +42,894 gas.
회로 제약은 V5 → V6 에서 오히려 줄었다(선택 공개 검사가 늘었지만 다른 부분이 더 줄어든 순효과 — 항목별 분해는 안 함, §11).

---

## 9. 테스트

- unit: `test_mode3_issuance.js` — π_u V2 양성, attrs 가 하나라도 다르면 실패, 옛 도메인 실패; `test_mode3_credential_v5.js` — attrs
  2^64 상한.
- circuit: `test_pi_cred_witness.mjs` — mask 0, 등식 공개, 구간 공개, 구간 밖(증인 실패), lo > 2^64(실패), mask ≥ 16(실패).
- contract: `test/mode3_wallet.test.mjs` — `uint[23]`, mask ≠ 0 꼬리 전달, `Disclosure` 이벤트, σ 다이제스트에 mask 포함, `AttrGate`
  양성·국가 불일치·나이 불일치·EOA 직접 호출 거절.
- chain: `test_cia_register_issue.mjs` — register 응답 attrs, `/cia/attrs`, 관리자 속성 변경 → 활성 C_u 물림; `test_mode3_wallet_agent.mjs`
  — `bad_proof` → 재동기화 → 성공, `disclosure_unsatisfiable`; `test_mode3_e2e.mjs`·`test_mode3_demo_stack.mjs` — §6.3 시나리오.
- 모두 `scripts/run_tests.sh` 의 해당 그룹에 넣는다.

---

## 10. 구현 범위와 순서 (계획 문서의 뼈대)

1. `lib/mode3_credential.js`·`circuits/lib/mode3_commit.circom`: 속성 64비트. `lib/mode3_issuance.js`: π_u V2. 테스트.
2. `circuits/pi_cred.circom` V6 공개 술어, `bash scripts/build_mode3_circuit.sh`, 픽스처, 증인 테스트.
3. `Mode3Wallet.sol`(`uint[23]`, 꼬리 전달, mask 다이제스트, 이벤트), `Mode3WalletFactory.isWallet`, `AttrGate.sol`, 컨트랙트 테스트.
4. `cia.js` 상태 v7(attrs, 마이그레이션 시 활성 C_u 물림), register 응답 attrs, `/cia/attrs`, 관리자 속성 변경, 관리자 페이지.
5. `lib/mode3_wallet.js`(`buildCredentialProof` disclosure, 캐시 키), `mode3_wallet_agent.js`(register attrs 저장, `/wallet/tx` disclose,
   `bad_proof` 재동기화, `/wallet/attrs` 삭제·`/wallet/attrs/sync`), 지갑 페이지.
6. `lib/mode3_rp.js`·`mode3_rp.js`(23개, `AttrGate` 배포·`rp_info`), 서비스 페이지.
7. 문서(`docs/MODE3_DEMO.md` 재배포 절차 + 시나리오), 벤치, 실측 기록, 스펙 §11 후속 목록.

**재배포 절차(데모):** `npx hardhat compile` → mode3 상태 파일에서 `verifierAddress`·`factoryAddress` 삭제(RP 기동 시 재배포, 주소 변경)
→ CIA 상태 v7 자동 마이그레이션(활성 C_u 물림 → 다음 게시에 리프) → 지갑은 다음 로그인에서 자동 재발급. `RevocationLog` 는 그대로.

---

## 11. 결정된 것 / 열린 것

- 결정(2026-09-22, 사용자): 속성 출처 = AA, 공개 형태 = 등식 + 구간(구간 하나로 통일, 등식은 lo = hi).
- 열린 것: (a) 로그인 때 서비스가 공개를 요구하는 정책(지금은 기록만 하고 강제하지 않는다 — `[14] < 16` 형식 검사뿐, mask 값 자체를
  요구하는 로직은 없다). (b) 속성 슬롯 의미·데모 값. (c) 관리자 속성 변경 시 옛 리프 게시 여부 — 이중 구조의 "속성 변경 시각 상관"
  결정(보류 중)과 같은 항목이며, **지금 코드의 실제 동작은 "게시한다"**(관리자가 속성을 바꾸면 옛 활성 C_u 리프가 pending 에 들어가
  다음 게시에 나간다, §3.2·`docs/MODE3_DEMO.md` "시각 상관에 주의") — 세 번째 선택지로 "지갑이 revoked 를 만나면 세션을 버리지 않고
  같은 세션키로 재발급 뒤 재검증"(서비스에는 보통 재검증으로 보임)을 추가한다. 이 셋 중 어느 쪽으로 굳힐지는 미결정.
- **논문(`documents/` PairCT 원고) 반영 항목(2026-09-22, T7 시점 미착수):**
  - V-B(속성 출처): "사용자가 지갑에 입력" → "AA 계정 기록, 관리자만 변경"으로 서술 수정.
  - Table 2·3: π_rp 제약(26,601 → 25,369), 공개 입력(14 → 23), π_u 시간(121.9/140.5 → 79.7/98.7 ms, V2), `execute` gas(339,321/356,453
    → 402,079/419,135, mask=0 기준) 로 갱신. mask≠0(선택 공개) 행은 새로 추가해야 한다(V5 표에는 없던 개념). 원 수치는
    `results/mode3_disclosure_bench_20260922.md` §1·§3.
  - IX(한계): "공개 값에 의한 익명 집합 축소" 항목 추가 — 본 스펙 §7 의 G4′ 약화(AA 가 술어를 만족하는 사용자 집합을 알 수 있다)를
    그대로 옮긴다. 정확한 값 공개(등식)는 구간 공개보다 집합을 더 줄인다는 점을 명시.
